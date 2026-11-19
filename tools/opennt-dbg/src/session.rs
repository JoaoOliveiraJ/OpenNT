//! Sessões com nome: os breakpoints (no texto do `.bpsave`, o mesmo do
//! `breakpoints.txt` que volta sozinho no attach), as expressões
//! observadas, a expressão da memória e como abrir o alvo (as opções do
//! `xtask`, o diretório de build, o QEMU sem janela ou o endereço de um
//! QEMU de fora). Ficam em `<build>/opennt-dbg/sessoes/<nome>.json` ou no
//! caminho dado (`--session=ARQ`, o menu Sessão).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A versão do formato (um arquivo mais novo é recusado com a explicação).
pub const VERSION: u32 = 1;

/// O arquivo de uma sessão (os campos que faltam ficam vazios).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionFile {
    pub version: u32,
    /// Os breakpoints em texto (`Client::breakpoint_specs`, o `.bpsave`):
    /// tipo, ligado, tamanho, contagem, expressão e condição por linha.
    pub breakpoints: String,
    /// As expressões da janela Observação.
    pub watches: Vec<String>,
    /// A expressão do painel Memória.
    pub memory: String,
    /// As opções do `xtask` da abertura (`--initial-process=smss ...`).
    pub xtask: Vec<String>,
    /// O `--build-dir` (vazio: `build`).
    pub build_dir: String,
    pub headless: bool,
    /// O endereço de um QEMU de fora (vazio: o depurador abre o OpenNT).
    pub connect: String,
}

impl SessionFile {
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|error| format!("sessao: {error}"))
    }

    pub fn from_json(text: &str) -> Result<SessionFile, String> {
        let session: SessionFile = serde_json::from_str(text).map_err(|error| format!("sessao invalida: {error}"))?;
        if session.version > VERSION {
            return Err(format!("sessao da versao {} (este opennt-dbg le ate a versao {VERSION})", session.version));
        }
        Ok(session)
    }

    pub fn load(path: &Path) -> Result<SessionFile, String> {
        let text = std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
        SessionFile::from_json(&text).map_err(|error| format!("{}: {error}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
        }
        std::fs::write(path, self.to_json()?).map_err(|error| format!("{}: {error}", path.display()))
    }

    /// Quantos breakpoints o texto tem (linhas que não são comentário).
    pub fn breakpoint_count(&self) -> usize {
        self.breakpoints.lines().filter(|line| !line.trim().is_empty() && !line.starts_with('#')).count()
    }
}

/// A pasta das sessões com nome de um diretório de build.
pub fn directory(build: &Path) -> PathBuf {
    build.join("opennt-dbg").join("sessoes")
}

/// O arquivo de uma sessão pelo que foi digitado: um nome simples vira
/// `<pasta>/<nome>.json`; um caminho (com `/`, `\` ou `.json`) fica como
/// está, relativo à raiz do repositório.
pub fn path_for(root: &Path, directory: &Path, name: &str) -> Result<PathBuf, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("nome da sessao vazio".into());
    }
    if name.contains('/') || name.contains('\\') || name.ends_with(".json") {
        let path = PathBuf::from(name);
        return Ok(if path.is_absolute() { path } else { root.join(path) });
    }
    if let Some(bad) = name.chars().find(|character| matches!(character, ':' | '*' | '?' | '"' | '<' | '>' | '|')) {
        return Err(format!("{name}: o Windows nao aceita {bad:?} em nome de arquivo"));
    }
    Ok(directory.join(format!("{name}.json")))
}

/// As sessões salvas numa pasta: (nome sem extensão, caminho), em ordem.
pub fn list(directory: &Path) -> Vec<(String, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(directory) else { return Vec::new() };
    let mut found: Vec<(String, PathBuf)> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("json")))
        .filter_map(|path| Some((path.file_stem()?.to_string_lossy().into_owned(), path)))
        .collect();
    found.sort();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trip() {
        let session = SessionFile {
            version: VERSION,
            breakpoints: "software\t1\t1\t0\tnt!NtCreateFile\t\nmodulo\t1\t1\t0\tntfs.sys\t\n# comentario\n".into(),
            watches: vec!["@rcx".into(), "(_IRP*)@rdx".into()],
            memory: "@rsp".into(),
            xtask: vec!["--initial-process=smss".into(), "--display=basic".into()],
            build_dir: "build/logon".into(),
            headless: false,
            connect: String::new(),
        };
        let text = session.to_json().unwrap();
        assert_eq!(SessionFile::from_json(&text), Ok(session.clone()));
        assert_eq!(session.breakpoint_count(), 2);
    }

    #[test]
    fn old_and_new_files() {
        // Um arquivo com menos campos abre com o resto vazio.
        let session = SessionFile::from_json("{\"version\": 1, \"watches\": [\"@rax\"]}").unwrap();
        assert_eq!(session.watches, vec!["@rax".to_string()]);
        assert!(session.breakpoints.is_empty());
        assert!(SessionFile::from_json("{\"version\": 99}").unwrap_err().contains("versao 99"));
        assert!(SessionFile::from_json("nao e json").is_err());
    }

    #[test]
    fn session_paths() {
        let root = Path::new("raiz");
        let folder = directory(Path::new("raiz/build"));
        assert_eq!(folder, PathBuf::from("raiz/build").join("opennt-dbg").join("sessoes"));
        assert_eq!(path_for(root, &folder, " logon "), Ok(folder.join("logon.json")));
        assert_eq!(path_for(root, &folder, "docs/sessao.json"), Ok(root.join("docs/sessao.json")));
        assert_eq!(path_for(root, &folder, "outra.json"), Ok(root.join("outra.json")));
        assert!(path_for(root, &folder, "").is_err());
        assert!(path_for(root, &folder, "a:b").is_err());
    }
}
