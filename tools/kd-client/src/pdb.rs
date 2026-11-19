//! Os PDBs: os símbolos de um PDB em RVAs do PE e o cache local de PDBs,
//! preenchido pelo servidor público de símbolos
//! (`<servidor>/<nome>/<GUID><idade>/<nome>`).
//!
//! Do PDB saem os nomes públicos (S_PUB32; função pelas flags ou pela seção
//! de código), os dados globais e estáticos (S_GDATA32/S_LDATA32) e, quando
//! o PDB não foi despido, os procedimentos dos módulos (com o tamanho) e as
//! linhas (as subseções C13 com os nomes do stream `/names`). Os PDBs
//! públicos da Microsoft só trazem os públicos.
//!
//! O cache tem uma ou mais pastas (`OPENNT_SYMBOLS`, separadas por `;`; a
//! primeira recebe os downloads; `build/symbols` sem a variável). Em cada
//! pasta valem três formas, sempre conferidas pelo GUID e pela idade:
//! `<nome>/<GUID><idade>/<nome>` (a do servidor, onde os downloads ficam),
//! `<nome>.<GUID><idade>.pdb` e `<nome>` sozinho (o `ntkrnlmp.pdb` do
//! `cargo xtask nt-types`). Assim duas versões do mesmo PDB convivem.
//!
//! O download usa o `curl` desta máquina (o do Windows 10 já vem no
//! sistema), como o `cargo xtask nt-types`, numa fila com poucos downloads
//! ao mesmo tempo. Um pedido comum vai para o fim da fila e o depurador
//! segue (o módulo recarrega quando o arquivo chega); um pedido com pressa
//! (`fetch_now`: uma busca por nome, a pilha) passa para a frente e espera.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use super::msf::{identity_of_file, Msf};
use super::pe::{guid_text, PeImage};

/// O servidor público de símbolos da Microsoft.
pub const DEFAULT_SERVER: &str = "https://msdl.microsoft.com/download/symbols";

/// Downloads ao mesmo tempo.
const WORKERS: usize = 4;
/// Os downloads a mais que um pedido com pressa pode abrir quando todos
/// estão ocupados.
const URGENT_WORKERS: usize = 2;
/// Quanto um pedido com pressa espera o PDB sem `OPENNT_SYMBOL_WAIT`.
const DEFAULT_WAIT: Duration = Duration::from_secs(120);

const S_END: u16 = 0x0006;
const S_THUNK32: u16 = 0x1102;
const S_BLOCK32: u16 = 0x1103;
const S_WITH32: u16 = 0x1104;
const S_LDATA32: u16 = 0x110C;
const S_GDATA32: u16 = 0x110D;
const S_PUB32: u16 = 0x110E;
const S_LPROC32: u16 = 0x110F;
const S_GPROC32: u16 = 0x1110;
const S_SEPCODE: u16 = 0x1132;
const S_LPROC32_ID: u16 = 0x1146;
const S_GPROC32_ID: u16 = 0x1147;
const S_INLINESITE: u16 = 0x114D;
const S_INLINESITE_END: u16 = 0x114E;
const S_PROC_ID_END: u16 = 0x114F;

const DEBUG_S_LINES: u32 = 0xF2;
const DEBUG_S_FILECHKSMS: u32 = 0xF4;

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

// ---- identidade -------------------------------------------------------------

/// A identidade de um PDB: o nome do arquivo e o GUID e a idade que o RSDS
/// do PE cita.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PdbId {
    pub name: String,
    pub guid: [u8; 16],
    pub age: u32,
}

impl PdbId {
    pub fn new(name: &str, guid: [u8; 16], age: u32) -> Self {
        Self { name: super::symbols::base_name(name).to_string(), guid, age }
    }

    /// A identidade que o RSDS de uma imagem cita.
    pub fn of_image(image: &PeImage) -> Option<Self> {
        let (guid, age, name) = image.rsds()?;
        let id = Self::new(&name, guid, age);
        (!id.name.is_empty()).then_some(id)
    }

    /// `<GUID><idade>` como no caminho do servidor.
    pub fn signature(&self) -> String {
        format!("{}{:X}", guid_text(&self.guid), self.age)
    }

    /// A chave da fila de downloads (sem diferença de caixa no nome).
    fn key(&self) -> String {
        format!("{}/{}", self.name.to_ascii_lowercase(), self.signature())
    }

    /// Os caminhos aceitos numa pasta do cache, na ordem de busca.
    pub fn candidates(&self, directory: &Path) -> [PathBuf; 3] {
        let signature = self.signature();
        [directory.join(&self.name).join(&signature).join(&self.name), directory.join(format!("{}.{signature}.pdb", self.name)), directory.join(&self.name)]
    }
}

// ---- símbolos ---------------------------------------------------------------

/// Uma seção do PE para os símbolos do PDB: o RVA e se é de código.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PdbSection {
    pub address: u32,
    pub code: bool,
}

impl PdbSection {
    /// As seções de uma imagem (código: IMAGE_SCN_CNT_CODE ou
    /// IMAGE_SCN_MEM_EXECUTE).
    pub fn of_image(image: &PeImage) -> Vec<PdbSection> {
        image.sections.iter().map(|section| PdbSection { address: section.address, code: section.characteristics & (0x20 | 0x2000_0000) != 0 }).collect()
    }
}

/// Um símbolo do PDB em RVA (tamanho 0 = desconhecido).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdbSymbol {
    pub rva: u32,
    pub size: u32,
    pub name: String,
    pub function: bool,
}

/// Uma linha de código: o RVA onde começa, o número e o índice do arquivo.
/// A linha 0 marca o fim de um trecho (ou código sem linha).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineEntry {
    pub rva: u32,
    pub line: u32,
    pub file: u32,
}

/// As linhas de um PDB, em ordem de RVA.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LineTable {
    pub files: Vec<String>,
    pub entries: Vec<LineEntry>,
}

impl LineTable {
    /// O arquivo e a linha do código em `rva`.
    pub fn at(&self, rva: u32) -> Option<(&str, u32)> {
        let index = self.entries.partition_point(|entry| entry.rva <= rva).checked_sub(1)?;
        let entry = self.entries[index];
        (entry.line != 0).then(|| (self.files.get(entry.file as usize).map_or("?", String::as_str), entry.line))
    }
}

/// O que um PDB dá a um módulo.
#[derive(Clone, Debug, Default)]
pub struct PdbData {
    pub symbols: Vec<PdbSymbol>,
    pub lines: Option<LineTable>,
    /// O PDB tem os procedimentos dos módulos (não foi despido).
    pub private: bool,
}

/// (seção, offset) do PDB em RVA.
fn rva_of(sections: &[PdbSection], segment: u16, offset: u32) -> Option<u32> {
    sections.get((segment as usize).checked_sub(1)?)?.address.checked_add(offset)
}

/// Os registros (tipo, registro inteiro com o comprimento) de um stream de
/// símbolos.
fn records(bytes: &[u8]) -> impl Iterator<Item = (u16, &[u8])> + '_ {
    let mut at = 0usize;
    std::iter::from_fn(move || {
        let length = u16_at(bytes, at)? as usize;
        if length < 2 {
            return None;
        }
        let record = bytes.get(at..at + 2 + length)?;
        at += 2 + length;
        Some((u16_at(record, 2)?, record))
    })
}

/// S_GDATA32/S_LDATA32: tipo, offset, segmento, nome.
fn data_record(record: &[u8], sections: &[PdbSection]) -> Option<PdbSymbol> {
    let (offset, segment, name) = (u32_at(record, 8)?, u16_at(record, 12)?, c_string(record, 14)?);
    Some(PdbSymbol { rva: rva_of(sections, segment, offset)?, size: 0, name, function: false })
}

/// Os símbolos do stream de registros globais: os públicos (S_PUB32: flags,
/// offset, segmento, nome; função pelos bits de código e de função das
/// flags ou pela seção de código) e os dados globais e estáticos.
pub fn public_records(stream: &[u8], sections: &[PdbSection]) -> Vec<PdbSymbol> {
    let mut symbols = Vec::new();
    for (kind, record) in records(stream) {
        match kind {
            S_PUB32 => {
                let (Some(flags), Some(offset), Some(segment), Some(name)) = (u32_at(record, 4), u32_at(record, 8), u16_at(record, 12), c_string(record, 14)) else { continue };
                let Some(rva) = rva_of(sections, segment, offset) else { continue };
                let code = (segment as usize).checked_sub(1).and_then(|index| sections.get(index)).is_some_and(|section| section.code);
                symbols.push(PdbSymbol { rva, size: 0, name: undecorate(&name), function: flags & 3 != 0 || code });
            }
            S_GDATA32 | S_LDATA32 => symbols.extend(data_record(record, sections)),
            _ => {}
        }
    }
    symbols
}

/// Os procedimentos (com o tamanho do código) e os dados do nível de cima do
/// stream de símbolos de um módulo (sem a assinatura do começo). Os dados de
/// dentro de um procedimento (estáticos locais) ficam de fora.
pub fn module_records(stream: &[u8], sections: &[PdbSection]) -> Vec<PdbSymbol> {
    let mut symbols = Vec::new();
    let mut depth = 0usize;
    for (kind, record) in records(stream) {
        match kind {
            S_GPROC32 | S_LPROC32 | S_GPROC32_ID | S_LPROC32_ID => {
                // pai, fim, próximo, tamanho, início e fim do depurável, tipo,
                // offset, segmento, flags, nome.
                if depth == 0 {
                    if let (Some(size), Some(offset), Some(segment), Some(name)) = (u32_at(record, 16), u32_at(record, 32), u16_at(record, 36), c_string(record, 39)) {
                        if let Some(rva) = rva_of(sections, segment, offset) {
                            symbols.push(PdbSymbol { rva, size, name, function: true });
                        }
                    }
                }
                depth += 1;
            }
            S_BLOCK32 | S_THUNK32 | S_WITH32 | S_SEPCODE | S_INLINESITE => depth += 1,
            S_END | S_PROC_ID_END | S_INLINESITE_END => depth = depth.saturating_sub(1),
            S_GDATA32 | S_LDATA32 if depth == 0 => symbols.extend(data_record(record, sections)),
            _ => {}
        }
    }
    symbols
}

/// Um módulo do DBI: o stream de símbolos dele e os tamanhos das partes.
struct ModuleInfo {
    stream: u16,
    symbol_bytes: u32,
    c11_bytes: u32,
    c13_bytes: u32,
}

/// Os módulos do substream de módulos do DBI (logo depois do cabeçalho de
/// 64 bytes): o registro fixo, o nome do módulo e o do objeto, alinhados
/// em 4.
fn module_infos(dbi: &[u8]) -> Vec<ModuleInfo> {
    let mut modules = Vec::new();
    let Some(size) = u32_at(dbi, 24) else { return modules };
    let Some(substream) = dbi.get(64..64 + size as usize) else { return modules };
    let mut at = 0;
    while at + 64 <= substream.len() {
        modules.push(ModuleInfo {
            stream: u16_at(substream, at + 34).unwrap_or(0xFFFF),
            symbol_bytes: u32_at(substream, at + 36).unwrap_or(0),
            c11_bytes: u32_at(substream, at + 40).unwrap_or(0),
            c13_bytes: u32_at(substream, at + 44).unwrap_or(0),
        });
        let mut cursor = at + 64;
        for _ in 0..2 {
            match substream.get(cursor..).and_then(|tail| tail.iter().position(|&byte| byte == 0)) {
                Some(end) => cursor += end + 1,
                None => return modules,
            }
        }
        at = (cursor + 3) & !3;
    }
    modules
}

/// O buffer de nomes do stream `/names`, achado pelo mapa de streams
/// nomeados do stream de informação (o comprimento e os nomes, depois a
/// tabela: tamanho, capacidade, os bits de presentes e de apagados e um par
/// nome/stream por presente).
fn names_buffer(msf: &Msf) -> Option<Vec<u8>> {
    let info = msf.stream(1).ok()?;
    let length = u32_at(&info, 28)? as usize;
    let strings = info.get(32..32 + length)?;
    let mut at = 32 + length;
    let size = u32_at(&info, at)? as usize;
    at += 8;
    let present = u32_at(&info, at)? as usize;
    at += 4 + 4 * present;
    let deleted = u32_at(&info, at)? as usize;
    at += 4 + 4 * deleted;
    for index in 0..size.min(4096) {
        let (key, value) = (u32_at(&info, at + 8 * index)?, u32_at(&info, at + 8 * index + 4)?);
        if c_string(strings, key as usize).as_deref() == Some("/names") {
            let stream = msf.stream(value as usize).ok()?;
            if u32_at(&stream, 0)? != 0xEFFE_EFFE {
                return None;
            }
            let bytes = u32_at(&stream, 8)? as usize;
            return stream.get(12..(12 + bytes).min(stream.len())).map(<[u8]>::to_vec);
        }
    }
    None
}

/// As linhas de todos os módulos, os arquivos sem repetição.
#[derive(Default)]
struct LineBuilder {
    table: LineTable,
    files: HashMap<String, u32>,
}

impl LineBuilder {
    /// As subseções C13 de um módulo: as de linhas (o trecho e os blocos por
    /// arquivo) com os arquivos da subseção de checksums.
    fn add_module(&mut self, c13: &[u8], sections: &[PdbSection], names: Option<&[u8]>) {
        let mut subsections = Vec::new();
        let mut at = 0;
        while at + 8 <= c13.len() {
            let (Some(kind), Some(length)) = (u32_at(c13, at), u32_at(c13, at + 4)) else { break };
            let Some(data) = c13.get(at + 8..at + 8 + length as usize) else { break };
            subsections.push((kind, data));
            at = (at + 8 + length as usize + 3) & !3;
        }
        let checksums = subsections.iter().find(|(kind, _)| *kind == DEBUG_S_FILECHKSMS).map(|(_, data)| *data);
        for (_, data) in subsections.iter().filter(|(kind, _)| *kind == DEBUG_S_LINES) {
            // offset, segmento, flags, tamanho do trecho.
            let (Some(offset), Some(segment), Some(code_size)) = (u32_at(data, 0), u16_at(data, 4), u32_at(data, 8)) else { continue };
            let Some(start) = rva_of(sections, segment, offset) else { continue };
            let mut at = 12;
            while at + 12 <= data.len() {
                // arquivo, quantas linhas, tamanho do bloco (com as colunas).
                let (Some(file_id), Some(count), Some(block_size)) = (u32_at(data, at), u32_at(data, at + 4), u32_at(data, at + 8)) else { break };
                let file = self.file_index(checksums, file_id, names);
                for line in 0..count.min(0x10_0000) as usize {
                    let entry = at + 12 + 8 * line;
                    let (Some(delta), Some(bits)) = (u32_at(data, entry), u32_at(data, entry + 4)) else { break };
                    // 0xFEEFEE e 0xF00F00: código que o compilador marca sem linha.
                    let number = match bits & 0x00FF_FFFF {
                        0xFEEFEE | 0xF00F00 => 0,
                        number => number,
                    };
                    self.table.entries.push(LineEntry { rva: start.wrapping_add(delta), line: number, file });
                }
                if (block_size as usize) < 12 {
                    break;
                }
                at += block_size as usize;
            }
            self.table.entries.push(LineEntry { rva: start.wrapping_add(code_size), line: 0, file: 0 });
        }
    }

    fn file_index(&mut self, checksums: Option<&[u8]>, file_id: u32, names: Option<&[u8]>) -> u32 {
        let name = checksums.and_then(|data| u32_at(data, file_id as usize)).and_then(|offset| names.and_then(|names| c_string(names, offset as usize))).unwrap_or_else(|| format!("arquivo#{file_id}"));
        if let Some(&index) = self.files.get(&name) {
            return index;
        }
        let index = self.table.files.len() as u32;
        self.table.files.push(name.clone());
        self.files.insert(name, index);
        index
    }

    fn finish(mut self) -> Option<LineTable> {
        if self.table.entries.iter().all(|entry| entry.line == 0) {
            return None;
        }
        // No mesmo RVA, a linha real fica depois do fim do trecho anterior.
        self.table.entries.sort_by_key(|entry| (entry.rva, entry.line != 0));
        Some(self.table)
    }
}

/// Os símbolos e as linhas de um PDB, se ele é o da identidade pedida.
pub fn load(pdb: &Path, id: &PdbId, sections: &[PdbSection]) -> Option<PdbData> {
    let msf = Msf::parse(std::fs::read(pdb).ok()?).ok()?;
    if msf.identity().ok()? != (id.guid, id.age) {
        return None;
    }
    let dbi = msf.stream(3).ok()?;
    let mut data = PdbData::default();
    if let Some(index) = u16_at(&dbi, 20).filter(|&index| index != 0xFFFF) {
        if let Ok(stream) = msf.stream(index as usize) {
            data.symbols = public_records(&stream, sections);
        }
    }
    let names = names_buffer(&msf);
    let mut lines = LineBuilder::default();
    for module in module_infos(&dbi) {
        if module.stream == 0xFFFF || module.stream as usize >= msf.stream_count() {
            continue;
        }
        let Ok(stream) = msf.stream(module.stream as usize) else { continue };
        let symbol_end = (module.symbol_bytes as usize).min(stream.len());
        if symbol_end > 4 {
            let found = module_records(&stream[4..symbol_end], sections);
            data.private |= found.iter().any(|symbol| symbol.function);
            data.symbols.extend(found);
        }
        let c13_start = symbol_end.saturating_add(module.c11_bytes as usize);
        let c13_end = c13_start.saturating_add(module.c13_bytes as usize).min(stream.len());
        if c13_start < c13_end {
            lines.add_module(&stream[c13_start..c13_end], sections, names.as_deref());
        }
    }
    data.lines = lines.finish();
    Some(data)
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

// ---- download ---------------------------------------------------------------

/// Baixa um PDB do servidor de símbolos para `destination` (pelo arquivo
/// `.part`, renomeado no fim).
pub fn download(server: &str, name: &str, guid: &str, age: u32, destination: &Path) -> Result<(), String> {
    let url = format!("{}/{name}/{guid}{age:X}/{name}", server.trim_end_matches('/'));
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    let partial = destination.with_extension("pdb.part");
    let mut attempt = 0;
    loop {
        attempt += 1;
        // Sem prazo, um curl travado deixaria o PDB "baixando" para sempre.
        let status = Command::new("curl")
            .args(["--fail", "--location", "--silent", "--show-error", "--connect-timeout", "30", "--max-time", "1800", "--retry", "2", "--user-agent", "symbol-client/1.0", "--output"])
            .arg(&partial)
            .arg(&url)
            .status()
            .map_err(|error| format!("curl: {error}"))?;
        if status.success() {
            break;
        }
        let _ = std::fs::remove_file(&partial);
        // O `--retry` do curl não repete uma conexão cortada no TLS (35) nem
        // uma resposta interrompida; com vários downloads ao mesmo tempo o
        // servidor às vezes corta uma delas.
        if attempt >= DOWNLOAD_ATTEMPTS || !status.code().is_some_and(transient_curl_error) {
            return Err(format!("download do PDB falhou ({status}): {url}"));
        }
        std::thread::sleep(std::time::Duration::from_millis(500 * attempt as u64));
    }
    std::fs::rename(&partial, destination).map_err(|error| format!("{}: {error}", destination.display()))
}

/// Tentativas de um download que falha por um erro de rede passageiro.
const DOWNLOAD_ATTEMPTS: u32 = 4;

/// Saídas do curl que valem uma nova tentativa: resolução de nome, conexão,
/// prazo, TLS, resposta vazia e erros de envio e recepção (o 22, um HTTP 404
/// do servidor, não muda tentando de novo).
fn transient_curl_error(code: i32) -> bool {
    matches!(code, 6 | 7 | 18 | 28 | 35 | 52 | 55 | 56)
}

/// Baixa o PDB (se o destino já não é ele) e confere a identidade do
/// arquivo que chegou.
fn fetch(server: &str, id: &PdbId, destination: &Path) -> Result<(), String> {
    if identity_of_file(destination).ok() == Some((id.guid, id.age)) {
        return Ok(());
    }
    download(server, &id.name, &guid_text(&id.guid), id.age, destination)?;
    match identity_of_file(destination) {
        Ok(found) if found == (id.guid, id.age) => Ok(()),
        Ok(_) => {
            let _ = std::fs::remove_file(destination);
            Err(format!("{}: o servidor mandou um PDB de outra identidade", id.name))
        }
        Err(error) => {
            let _ = std::fs::remove_file(destination);
            Err(error)
        }
    }
}

/// O estado do download de um PDB.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fetch {
    /// Na fila ou baixando.
    Downloading,
    Failed(String),
}

struct Job {
    id: PdbId,
    destination: PathBuf,
}

#[derive(Default)]
struct Queue {
    states: HashMap<String, Fetch>,
    waiting: VecDeque<Job>,
    workers: usize,
    /// Os PDBs que chegaram nesta sessão.
    arrived: HashSet<String>,
    /// Os pedidos com pressa que já esperaram uma vez.
    waited: HashSet<String>,
    /// Downloads terminados (com sucesso ou não).
    finished: u64,
}

#[derive(Default)]
struct Shared {
    queue: Mutex<Queue>,
    changed: Condvar,
}

/// O cache de PDBs e a fila de downloads (as cópias dividem a fila).
#[derive(Clone)]
pub struct SymbolStore {
    /// A pasta dos downloads (a primeira do caminho).
    pub directory: PathBuf,
    /// As outras pastas consultadas, na ordem.
    pub search: Vec<PathBuf>,
    pub server: String,
    pub download: bool,
    /// Quanto um pedido com pressa espera o PDB (zero: não espera).
    pub wait: Duration,
    shared: Arc<Shared>,
}

impl SymbolStore {
    /// As pastas de `OPENNT_SYMBOLS` (separadas por `;`; sem a variável,
    /// `<raiz>/build/symbols`); downloads ligados, menos com
    /// `OPENNT_SYMBOL_DOWNLOAD=0`; a espera de `OPENNT_SYMBOL_WAIT`
    /// (segundos).
    pub fn new(root: &Path) -> Self {
        let mut directories: Vec<PathBuf> = std::env::var_os("OPENNT_SYMBOLS").map(|value| std::env::split_paths(&value).filter(|path| !path.as_os_str().is_empty()).collect()).unwrap_or_default();
        if directories.is_empty() {
            directories.push(root.join("build").join("symbols"));
        }
        let directory = directories.remove(0);
        let server = std::env::var("OPENNT_SYMBOL_SERVER").unwrap_or_else(|_| DEFAULT_SERVER.to_string());
        let download = std::env::var("OPENNT_SYMBOL_DOWNLOAD").map_or(true, |value| value != "0");
        let wait = std::env::var("OPENNT_SYMBOL_WAIT").ok().and_then(|text| text.trim().parse::<u64>().ok()).map_or(DEFAULT_WAIT, Duration::from_secs);
        Self { directory, search: directories, server, download, wait, shared: Arc::default() }
    }

    /// Um cache sem downloads (os testes).
    pub fn offline(directory: PathBuf) -> Self {
        Self { directory, search: Vec::new(), server: DEFAULT_SERVER.into(), download: false, wait: Duration::ZERO, shared: Arc::default() }
    }

    fn lock(&self) -> MutexGuard<'_, Queue> {
        self.shared.queue.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// As pastas do cache, a dos downloads primeiro.
    pub fn directories(&self) -> impl Iterator<Item = &PathBuf> {
        std::iter::once(&self.directory).chain(self.search.iter())
    }

    /// `<pasta dos downloads>/<nome>`: o lugar sem a assinatura.
    pub fn path(&self, pdb_name: &str) -> PathBuf {
        self.directory.join(super::symbols::base_name(pdb_name))
    }

    /// Onde o download de um PDB fica (a forma do servidor).
    pub fn download_path(&self, id: &PdbId) -> PathBuf {
        let [server_layout, _, _] = id.candidates(&self.directory);
        server_layout
    }

    /// O PDB com a identidade, em alguma pasta e forma do cache.
    pub fn find(&self, id: &PdbId) -> Option<PathBuf> {
        self.directories().flat_map(|directory| id.candidates(directory)).find(|path| path.is_file() && identity_of_file(path).ok() == Some((id.guid, id.age)))
    }

    /// O PDB no cache; senão o download entra no fim da fila (uma vez por
    /// identidade) e volta `None`.
    pub fn request(&self, id: &PdbId) -> Option<PathBuf> {
        if let Some(path) = self.find(id) {
            return Some(path);
        }
        self.enqueue(id, false);
        None
    }

    /// Põe o download na fila; com pressa, na frente (e com um download a
    /// mais se todos estão ocupados). `false` quando não há download (o
    /// cache sem downloads ou um que já falhou).
    pub fn enqueue(&self, id: &PdbId, urgent: bool) -> bool {
        if !self.download {
            return false;
        }
        let key = id.key();
        let mut queue = self.lock();
        let state = queue.states.get(&key).cloned();
        match state {
            Some(Fetch::Failed(_)) => return false,
            Some(Fetch::Downloading) => {
                if urgent {
                    if let Some(position) = queue.waiting.iter().position(|job| job.id == *id) {
                        if let Some(job) = queue.waiting.remove(position) {
                            queue.waiting.push_front(job);
                        }
                        self.spawn_if_needed(&mut queue, true);
                    }
                }
                return true;
            }
            None => {}
        }
        queue.states.insert(key, Fetch::Downloading);
        let job = Job { id: id.clone(), destination: self.download_path(id) };
        if urgent {
            queue.waiting.push_front(job);
        } else {
            queue.waiting.push_back(job);
        }
        self.spawn_if_needed(&mut queue, urgent);
        true
    }

    fn spawn_if_needed(&self, queue: &mut Queue, urgent: bool) {
        let limit = if urgent { WORKERS + URGENT_WORKERS } else { WORKERS };
        if queue.workers >= limit || queue.waiting.is_empty() {
            return;
        }
        queue.workers += 1;
        let shared = Arc::clone(&self.shared);
        let server = self.server.clone();
        std::thread::spawn(move || loop {
            let job = {
                let mut queue = shared.queue.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                match queue.waiting.pop_front() {
                    Some(job) => job,
                    None => {
                        queue.workers -= 1;
                        return;
                    }
                }
            };
            let result = fetch(&server, &job.id, &job.destination);
            let key = job.id.key();
            let mut queue = shared.queue.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            match result {
                Ok(()) => {
                    queue.states.remove(&key);
                    queue.arrived.insert(key);
                }
                Err(error) => {
                    queue.states.insert(key, Fetch::Failed(error));
                }
            }
            queue.finished += 1;
            drop(queue);
            shared.changed.notify_all();
        });
    }

    /// O PDB já: no cache, ou o download passa para a frente da fila e a
    /// chamada espera até `timeout`. A espera vale uma vez por identidade:
    /// depois dela (chegando ou não) o download segue no fundo e o módulo
    /// recarrega quando o arquivo chegar.
    pub fn fetch_now(&self, id: &PdbId, timeout: Duration) -> Option<PathBuf> {
        if let Some(path) = self.find(id) {
            return Some(path);
        }
        if !self.enqueue(id, true) {
            return None;
        }
        let key = id.key();
        let deadline = Instant::now() + timeout;
        let mut queue = self.lock();
        if timeout.is_zero() || !queue.waited.insert(key.clone()) {
            return None;
        }
        while queue.states.get(&key) == Some(&Fetch::Downloading) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            queue = self.shared.changed.wait_timeout(queue, remaining).map(|(guard, _)| guard).unwrap_or_else(|poisoned| poisoned.into_inner().0);
        }
        let arrived = queue.arrived.contains(&key);
        drop(queue);
        if arrived {
            self.find(id)
        } else {
            None
        }
    }

    /// Espera todos os downloads da fila até `timeout`; `true` se nenhum
    /// ficou pendente.
    pub fn wait_all(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut queue = self.lock();
        loop {
            if !queue.states.values().any(|fetch| *fetch == Fetch::Downloading) {
                return true;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            queue = self.shared.changed.wait_timeout(queue, remaining).map(|(guard, _)| guard).unwrap_or_else(|poisoned| poisoned.into_inner().0);
        }
    }

    /// O estado do download de um PDB, se houve um e não terminou bem.
    pub fn state(&self, id: &PdbId) -> Option<Fetch> {
        self.lock().states.get(&id.key()).cloned()
    }

    /// O PDB chegou nesta sessão.
    pub fn arrived(&self, id: &PdbId) -> bool {
        self.lock().arrived.contains(&id.key())
    }

    /// Esquece as falhas (e as esperas já feitas): o próximo pedido tenta de
    /// novo. Devolve quantas falhas havia.
    pub fn forget_failures(&self) -> usize {
        let mut queue = self.lock();
        let before = queue.states.len();
        queue.states.retain(|_, fetch| *fetch == Fetch::Downloading);
        queue.waited.clear();
        before - queue.states.len()
    }

    /// Quantos downloads estão na fila ou em andamento.
    pub fn pending_count(&self) -> usize {
        self.lock().states.values().filter(|fetch| **fetch == Fetch::Downloading).count()
    }

    /// Algum download ainda roda.
    pub fn busy(&self) -> bool {
        self.pending_count() > 0
    }

    /// Downloads terminados desde o começo (quem guarda o número sabe se
    /// algo chegou).
    pub fn finished(&self) -> u64 {
        self.lock().finished
    }
}

/// GUID e idade de um PDB no disco.
pub fn identity(path: &Path) -> Option<([u8; 16], u32)> {
    identity_of_file(path).ok()
}

#[cfg(test)]
mod tests {
    use super::super::msf::tests::{identity_streams, tiny_msf};
    use super::*;

    fn record(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = ((body.len() + 2) as u16).to_le_bytes().to_vec();
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    fn sections() -> Vec<PdbSection> {
        vec![PdbSection { address: 0x1000, code: true }, PdbSection { address: 0x5000, code: false }]
    }

    fn public(flags: u32, offset: u32, segment: u16, name: &str) -> Vec<u8> {
        let mut body = flags.to_le_bytes().to_vec();
        body.extend_from_slice(&offset.to_le_bytes());
        body.extend_from_slice(&segment.to_le_bytes());
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        record(S_PUB32, &body)
    }

    fn data(kind: u16, offset: u32, segment: u16, name: &str) -> Vec<u8> {
        let mut body = 0x74u32.to_le_bytes().to_vec();
        body.extend_from_slice(&offset.to_le_bytes());
        body.extend_from_slice(&segment.to_le_bytes());
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        record(kind, &body)
    }

    fn procedure(size: u32, offset: u32, segment: u16, name: &str) -> Vec<u8> {
        let mut body = vec![0u8; 12];
        body.extend_from_slice(&size.to_le_bytes());
        body.extend_from_slice(&[0u8; 12]);
        body.extend_from_slice(&offset.to_le_bytes());
        body.extend_from_slice(&segment.to_le_bytes());
        body.push(0);
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        record(S_GPROC32, &body)
    }

    #[test]
    fn reads_public_symbols() {
        let mut stream = public(2, 0x1a3, 1, "NtfsCommonCreate");
        // Um registro que não é público nem dado.
        stream.extend(record(0x1125, &[0; 8]));
        stream.extend(public(0, 0x10, 2, "?Lock@CVolume@@QEAAXXZ"));
        stream.extend(data(S_GDATA32, 0x20, 2, "NtfsData"));
        // Um público sem flags numa seção de código ainda é função.
        stream.extend(public(0, 0x300, 1, "SemFlags"));
        let list = public_records(&stream, &sections());
        assert_eq!(
            list,
            vec![
                PdbSymbol { rva: 0x11a3, size: 0, name: "NtfsCommonCreate".into(), function: true },
                PdbSymbol { rva: 0x5010, size: 0, name: "CVolume::Lock".into(), function: false },
                PdbSymbol { rva: 0x5020, size: 0, name: "NtfsData".into(), function: false },
                PdbSymbol { rva: 0x1300, size: 0, name: "SemFlags".into(), function: true },
            ]
        );
        // Um segmento fora da tabela de seções fica de fora.
        assert!(public_records(&public(2, 0, 9, "Fora"), &sections()).is_empty());
    }

    #[test]
    fn module_procedures_skip_nested_data() {
        let mut stream = procedure(0x40, 0x10, 1, "Privada");
        stream.extend(data(S_LDATA32, 0x30, 2, "estatica_local"));
        stream.extend(record(S_END, &[]));
        stream.extend(data(S_LDATA32, 0x8, 2, "Global"));
        let list = module_records(&stream, &sections());
        assert_eq!(list, vec![PdbSymbol { rva: 0x1010, size: 0x40, name: "Privada".into(), function: true }, PdbSymbol { rva: 0x5008, size: 0, name: "Global".into(), function: false }]);
    }

    #[test]
    fn undecorates_simple_names() {
        assert_eq!(undecorate("NtfsFsdCreate"), "NtfsFsdCreate");
        assert_eq!(undecorate("?Start@Worker@Acpi@@QEAAJXZ"), "Acpi::Worker::Start");
        assert_eq!(undecorate("??0CVolume@@QEAA@XZ"), "??0CVolume@@QEAA@XZ");
    }

    #[test]
    fn retries_only_network_failures() {
        // Conexão cortada no TLS e recepção interrompida: nova tentativa.
        assert!(transient_curl_error(35));
        assert!(transient_curl_error(56));
        // HTTP 404 (--fail) e argumentos errados: não adianta repetir.
        assert!(!transient_curl_error(22));
        assert!(!transient_curl_error(2));
    }

    /// Um PDB inteiro: informação com `/names`, DBI com um módulo, os
    /// registros globais, o `/names` e o stream do módulo com um
    /// procedimento e as linhas dele.
    fn full_pdb(guid: [u8; 16], age: u32) -> Vec<u8> {
        let (mut info, mut dbi) = identity_streams(guid, age);
        // Mapa de streams nomeados: "/names" -> stream 5.
        info.extend_from_slice(&7u32.to_le_bytes());
        info.extend_from_slice(b"/names\0");
        for value in [1u32, 1, 1, 1, 0, 0, 5] {
            info.extend_from_slice(&value.to_le_bytes());
        }
        // DBI: registros globais no stream 4, um módulo com o stream 6.
        dbi[20..22].copy_from_slice(&4u16.to_le_bytes());
        let mut module_symbols = 4u32.to_le_bytes().to_vec();
        module_symbols.extend(procedure(0x40, 0x10, 1, "Privada"));
        module_symbols.extend(record(S_END, &[]));
        let mut c13 = Vec::new();
        // Checksums: o arquivo no nome 0 do /names, sem checksum.
        c13.extend_from_slice(&DEBUG_S_FILECHKSMS.to_le_bytes());
        c13.extend_from_slice(&8u32.to_le_bytes());
        c13.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        // Linhas: o trecho em 1:0x10 de 0x40 bytes, um bloco com duas linhas.
        let mut lines = 0x10u32.to_le_bytes().to_vec();
        lines.extend_from_slice(&1u16.to_le_bytes());
        lines.extend_from_slice(&0u16.to_le_bytes());
        lines.extend_from_slice(&0x40u32.to_le_bytes());
        for value in [0u32, 2, 28, 0, 10 | 0x8000_0000, 0x20, 12 | 0x8000_0000] {
            lines.extend_from_slice(&value.to_le_bytes());
        }
        c13.extend_from_slice(&DEBUG_S_LINES.to_le_bytes());
        c13.extend_from_slice(&(lines.len() as u32).to_le_bytes());
        c13.extend(lines);
        let mut module_info = vec![0u8; 64];
        module_info[34..36].copy_from_slice(&6u16.to_le_bytes());
        module_info[36..40].copy_from_slice(&(module_symbols.len() as u32).to_le_bytes());
        module_info[44..48].copy_from_slice(&(c13.len() as u32).to_le_bytes());
        module_info.extend_from_slice(b"mod\0obj\0");
        dbi[24..28].copy_from_slice(&(module_info.len() as u32).to_le_bytes());
        dbi.extend(module_info);
        let mut module_stream = module_symbols;
        module_stream.extend(c13);
        let globals = public(2, 0x10, 1, "Privada");
        let mut names = 0xEFFE_EFFEu32.to_le_bytes().to_vec();
        names.extend_from_slice(&1u32.to_le_bytes());
        names.extend_from_slice(&4u32.to_le_bytes());
        names.extend_from_slice(b"a.c\0");
        tiny_msf(&[Vec::new(), info, Vec::new(), dbi, globals, names, module_stream])
    }

    fn scratch(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!("kd-pdb-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn loads_private_symbols_and_lines() {
        let guid = [3u8; 16];
        let directory = scratch("full");
        let path = directory.join("full.pdb");
        std::fs::write(&path, full_pdb(guid, 2)).unwrap();
        let id = PdbId::new("full.pdb", guid, 2);
        let data = load(&path, &id, &sections()).unwrap();
        assert!(data.private);
        assert!(data.symbols.contains(&PdbSymbol { rva: 0x1010, size: 0, name: "Privada".into(), function: true }));
        assert!(data.symbols.contains(&PdbSymbol { rva: 0x1010, size: 0x40, name: "Privada".into(), function: true }));
        let lines = data.lines.unwrap();
        assert_eq!(lines.at(0x1010), Some(("a.c", 10)));
        assert_eq!(lines.at(0x102f), Some(("a.c", 10)));
        assert_eq!(lines.at(0x1030), Some(("a.c", 12)));
        assert_eq!(lines.at(0x1050), None);
        assert_eq!(lines.at(0x100f), None);
        // Outra identidade: nada.
        assert!(load(&path, &PdbId::new("full.pdb", guid, 3), &sections()).is_none());
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn cache_layouts_and_identity() {
        let guid = [5u8; 16];
        let id = PdbId::new(r"d:\obj\amd64\teste.pdb", guid, 1);
        assert_eq!(id.name, "teste.pdb");
        assert_eq!(id.signature(), format!("{}1", "05".repeat(16)));
        let first = scratch("first");
        let second = scratch("second");
        let (info, dbi) = identity_streams(guid, 1);
        let pdb = tiny_msf(&[Vec::new(), info, Vec::new(), dbi]);
        let (other_info, other_dbi) = identity_streams([6u8; 16], 1);
        // Na primeira pasta, o nome sozinho com outra identidade; na segunda,
        // o nome com a assinatura.
        std::fs::write(first.join("teste.pdb"), tiny_msf(&[Vec::new(), other_info, Vec::new(), other_dbi])).unwrap();
        let signed = second.join(format!("teste.pdb.{}.pdb", id.signature()));
        std::fs::write(&signed, &pdb).unwrap();
        let mut store = SymbolStore::offline(first.clone());
        assert_eq!(store.find(&id), None);
        store.search.push(second.clone());
        assert_eq!(store.find(&id), Some(signed));
        assert_eq!(store.download_path(&id), first.join("teste.pdb").join(id.signature()).join("teste.pdb"));
        // Sem downloads: nada entra na fila e a espera volta na hora.
        assert!(!store.enqueue(&PdbId::new("falta.pdb", guid, 1), true));
        assert_eq!(store.fetch_now(&PdbId::new("falta.pdb", guid, 1), Duration::from_secs(5)), None);
        assert!(!store.busy());
        assert!(store.wait_all(Duration::ZERO));
        let _ = std::fs::remove_dir_all(&first);
        let _ = std::fs::remove_dir_all(&second);
    }
}
