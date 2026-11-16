//! Os PDBs públicos: os nomes públicos (S_PUB32) de um PDB em RVAs do PE e
//! o cache local (`build/symbols/<nome>.pdb`), preenchido pelo servidor
//! público de símbolos (`<servidor>/<nome>/<GUID><idade>/<nome>`).
//!
//! O download usa o `curl` desta máquina (o do Windows 10 já vem no
//! sistema), como o `cargo xtask nt-types` faz com o PDB do ntoskrnl, e
//! roda numa thread: o depurador segue com os exports e troca os nomes
//! quando o arquivo chega.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use super::msf::Msf;
use super::pe::{guid_text, PeImage};

/// O servidor público de símbolos da Microsoft.
pub const DEFAULT_SERVER: &str = "https://msdl.microsoft.com/download/symbols";

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn c_string(bytes: &[u8], at: usize) -> Option<String> {
    let tail = bytes.get(at..)?;
    let end = tail.iter().position(|&byte| byte == 0)?;
    Some(String::from_utf8_lossy(&tail[..end]).into_owned())
}

/// Os nomes públicos (S_PUB32) de um PDB, em RVA pelas seções do PE.
/// `None` se o PDB não é o que o RSDS do PE cita.
pub fn publics(pdb: &Path, image: &PeImage) -> Option<Vec<(u32, String)>> {
    let msf = Msf::parse(std::fs::read(pdb).ok()?).ok()?;
    let (guid, age, _) = image.rsds()?;
    if msf.identity().ok()? != (guid, age) {
        return None;
    }
    let dbi = msf.stream(3).ok()?;
    let records = msf.stream(u16_at(&dbi, 20)? as usize).ok()?;
    Some(public_records(&records, &image.sections.iter().map(|section| section.address).collect::<Vec<_>>()))
}

/// Os S_PUB32 de um stream de símbolos: (seção, offset) vira RVA.
pub fn public_records(records: &[u8], sections: &[u32]) -> Vec<(u32, String)> {
    let mut publics = Vec::new();
    let mut at = 0;
    while at + 4 <= records.len() {
        let Some(length) = u16_at(records, at).map(usize::from) else { break };
        let kind = u16_at(records, at + 2).unwrap_or(0);
        // S_PUB32: flags, offset, segmento, nome.
        if kind == 0x110E {
            if let (Some(offset), Some(segment), Some(name)) = (u32_at(records, at + 8), u16_at(records, at + 12), c_string(records, at + 14)) {
                if let Some(&address) = (segment as usize).checked_sub(1).and_then(|index| sections.get(index)) {
                    publics.push((address + offset, undecorate(&name)));
                }
            }
        }
        if length < 2 {
            break;
        }
        at += 2 + length;
    }
    publics
}

/// O nome legível de um público do C++ (`?Nome@Classe@@...` vira
/// `Classe::Nome`); os do C ficam como estão.
pub fn undecorate(name: &str) -> String {
    let Some(body) = name.strip_prefix('?') else { return name.to_string() };
    if body.starts_with('?') || body.starts_with('$') {
        return name.to_string();
    }
    let Some(end) = body.find("@@") else { return name.to_string() };
    let mut parts: Vec<&str> = body[..end].split('@').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() || parts.iter().any(|part| part.chars().any(|character| !(character.is_ascii_alphanumeric() || character == '_'))) {
        return name.to_string();
    }
    parts.reverse();
    parts.join("::")
}

/// Baixa um PDB do servidor de símbolos para `destination` (pelo arquivo
/// `.part`, renomeado no fim).
pub fn download(server: &str, name: &str, guid: &str, age: u32, destination: &Path) -> Result<(), String> {
    let url = format!("{}/{name}/{guid}{age:X}/{name}", server.trim_end_matches('/'));
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    let partial = destination.with_extension("pdb.part");
    let status = Command::new("curl")
        .args(["--fail", "--location", "--silent", "--show-error", "--user-agent", "symbol-client/1.0", "--output"])
        .arg(&partial)
        .arg(&url)
        .status()
        .map_err(|error| format!("curl: {error}"))?;
    if !status.success() {
        let _ = std::fs::remove_file(&partial);
        return Err(format!("download do PDB falhou ({status}): {url}"));
    }
    std::fs::rename(&partial, destination).map_err(|error| format!("{}: {error}", destination.display()))
}

/// O estado do PDB de um módulo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fetch {
    Downloading,
    Failed(String),
}

/// O cache de PDBs e os downloads em andamento.
#[derive(Clone)]
pub struct SymbolStore {
    pub directory: PathBuf,
    pub server: String,
    pub download: bool,
    fetches: Arc<Mutex<HashMap<String, Fetch>>>,
}

impl SymbolStore {
    /// O cache em `<raiz>/build/symbols` (ou `OPENNT_SYMBOLS`); downloads
    /// ligados, menos com `OPENNT_SYMBOL_DOWNLOAD=0`.
    pub fn new(root: &Path) -> Self {
        let directory = std::env::var_os("OPENNT_SYMBOLS").map(PathBuf::from).unwrap_or_else(|| root.join("build").join("symbols"));
        let server = std::env::var("OPENNT_SYMBOL_SERVER").unwrap_or_else(|_| DEFAULT_SERVER.to_string());
        let download = std::env::var("OPENNT_SYMBOL_DOWNLOAD").map_or(true, |value| value != "0");
        Self { directory, server, download, fetches: Arc::new(Mutex::new(HashMap::new())) }
    }

    /// Um cache sem downloads (os testes).
    pub fn offline(directory: PathBuf) -> Self {
        Self { directory, server: DEFAULT_SERVER.into(), download: false, fetches: Arc::new(Mutex::new(HashMap::new())) }
    }

    pub fn path(&self, pdb_name: &str) -> PathBuf {
        self.directory.join(super::symbols::base_name(pdb_name))
    }

    /// O estado do download de um PDB, se houve um.
    pub fn fetch_state(&self, pdb_name: &str) -> Option<Fetch> {
        self.fetches.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(&pdb_name.to_ascii_lowercase()).cloned()
    }

    /// O PDB citado pelo RSDS, se está no cache com a identidade certa; senão
    /// começa o download (uma vez por nome e identidade) e devolve `None`.
    pub fn request(&self, image: &PeImage) -> Option<PathBuf> {
        let (guid, age, pdb_name) = image.rsds()?;
        let path = self.path(&pdb_name);
        if path.is_file() && identity(&path) == Some((guid, age)) {
            return Some(path);
        }
        if !self.download {
            return None;
        }
        let key = pdb_name.to_ascii_lowercase();
        {
            let mut fetches = self.fetches.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if fetches.contains_key(&key) {
                return None;
            }
            fetches.insert(key.clone(), Fetch::Downloading);
        }
        let fetches = Arc::clone(&self.fetches);
        let server = self.server.clone();
        let name = super::symbols::base_name(&pdb_name).to_string();
        let guid = guid_text(&guid);
        std::thread::spawn(move || {
            let result = download(&server, &name, &guid, age, &path);
            let mut fetches = fetches.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            match result {
                Ok(()) => {
                    fetches.remove(&key);
                }
                Err(error) => {
                    fetches.insert(key, Fetch::Failed(error));
                }
            }
        });
        None
    }

    /// Algum download ainda roda.
    pub fn busy(&self) -> bool {
        self.fetches.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).values().any(|fetch| *fetch == Fetch::Downloading)
    }
}

/// GUID e idade de um PDB no disco.
pub fn identity(path: &Path) -> Option<([u8; 16], u32)> {
    // Só o começo do arquivo não basta (o diretório pode estar no fim).
    Msf::parse(std::fs::read(path).ok()?).ok()?.identity().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = ((body.len() + 2) as u16).to_le_bytes().to_vec();
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    #[test]
    fn reads_public_symbols() {
        let mut publics = Vec::new();
        // S_PUB32: flags, offset 0x1a3, segmento 1, nome.
        let mut body = 2u32.to_le_bytes().to_vec();
        body.extend_from_slice(&0x1a3u32.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(b"NtfsCommonCreate\0\0");
        publics.extend(record(0x110E, &body));
        // Um registro que não é público.
        publics.extend(record(0x1125, &[0; 8]));
        let mut body = 0u32.to_le_bytes().to_vec();
        body.extend_from_slice(&0x10u32.to_le_bytes());
        body.extend_from_slice(&2u16.to_le_bytes());
        body.extend_from_slice(b"?Lock@CVolume@@QEAAXXZ\0");
        publics.extend(record(0x110E, &body));
        let list = public_records(&publics, &[0x1000, 0x5000]);
        assert_eq!(list, vec![(0x11a3, "NtfsCommonCreate".to_string()), (0x5010, "CVolume::Lock".to_string())]);
    }

    #[test]
    fn undecorates_simple_names() {
        assert_eq!(undecorate("NtfsFsdCreate"), "NtfsFsdCreate");
        assert_eq!(undecorate("?Start@Worker@Acpi@@QEAAJXZ"), "Acpi::Worker::Start");
        assert_eq!(undecorate("??0CVolume@@QEAA@XZ"), "??0CVolume@@QEAA@XZ");
    }
}
