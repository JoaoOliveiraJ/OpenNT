//! Os nomes e os textos dos códigos de erro do Windows: NTSTATUS, HRESULT e
//! os erros do Win32, para a desmontagem (o imediato `0xC0000034` vira
//! `STATUS_OBJECT_NAME_NOT_FOUND`), a caixa de informação e o LastError da
//! TEB.
//!
//! - Os nomes saem dos cabeçalhos públicos do SDK do Windows instalado
//!   nesta máquina (`shared\ntstatus.h` e `shared\winerror.h` em
//!   `Windows Kits\10\Include\<versão>`; `OPENNT_SDK_INCLUDE` aponta outra
//!   pasta `shared`). Sem o SDK, valem a tabela curta do
//!   `kd_client::ntstatus` e a lista curta daqui.
//! - O texto de cada código sai das tabelas de mensagens (RT_MESSAGETABLE)
//!   dos binários reais: o `ntdll.dll` para os NTSTATUS e o `KernelBase.dll`
//!   para os erros do Win32 e os HRESULT, pelo `.mui` do idioma em
//!   `System32\<idioma>\`.
//!
//! Tudo é lido uma vez, na primeira consulta.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use kd_client::pe::PeImage;

/// RT_MESSAGETABLE.
const RT_MESSAGETABLE: u32 = 11;

/// A forma de um `#define` dos cabeçalhos.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Form {
    /// `((NTSTATUS)0xC0000034L)`.
    NtStatus,
    /// `_HRESULT_TYPEDEF_(0x80004005L)` ou `((HRESULT)0L)`.
    HResult,
    /// Um número solto; `decimal_long` diz se é decimal com o sufixo `L`
    /// (a forma dos erros do Win32 no `winerror.h`).
    Plain { decimal_long: bool },
}

/// Os nomes e os textos carregados.
#[derive(Default)]
pub struct Codes {
    ntstatus: HashMap<u32, String>,
    hresult: HashMap<u32, String>,
    win32: HashMap<u32, String>,
    /// A tabela de mensagens do ntdll (NTSTATUS).
    ntstatus_text: HashMap<u32, String>,
    /// A tabela de mensagens do sistema (Win32 e HRESULT).
    system_text: HashMap<u32, String>,
    /// De onde vieram (para a barra de estado e os testes).
    pub source: String,
}

/// Um número de cabeçalho C: `0x...`, decimal, com sufixos `L`/`U`.
fn number_literal(text: &str) -> Option<(u32, bool)> {
    let trimmed = text.trim();
    let long = trimmed.ends_with(|character: char| character == 'L' || character == 'l');
    let digits = trimmed.trim_end_matches(|character: char| matches!(character, 'L' | 'l' | 'U' | 'u'));
    if let Some(hex) = digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        let value = u64::from_str_radix(hex, 16).ok()?;
        return u32::try_from(value).ok().map(|value| (value, false));
    }
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let value: u64 = digits.parse().ok()?;
    u32::try_from(value).ok().map(|value| (value, long))
}

/// Uma linha `#define NOME valor` com valor numérico.
fn define(line: &str) -> Option<(&str, u32, Form)> {
    let rest = line.trim_start().strip_prefix("#define")?;
    if !rest.starts_with(|character: char| character == ' ' || character == '\t') {
        return None;
    }
    let rest = rest.trim_start();
    let end = rest.find(char::is_whitespace)?;
    let name = &rest[..end];
    if name.contains('(') {
        return None;
    }
    let mut value = rest[end..].trim();
    for marker in ["//", "/*"] {
        if let Some(cut) = value.find(marker) {
            value = value[..cut].trim();
        }
    }
    let wrapped = |prefix: &str| value.strip_prefix(prefix).and_then(|inner| inner.strip_suffix(')'));
    if let Some(inner) = wrapped("((NTSTATUS)") {
        return number_literal(inner).map(|(number, _)| (name, number, Form::NtStatus));
    }
    if let Some(inner) = wrapped("_HRESULT_TYPEDEF_(").or_else(|| wrapped("((HRESULT)")) {
        return number_literal(inner).map(|(number, _)| (name, number, Form::HResult));
    }
    number_literal(value).map(|(number, decimal_long)| (name, number, Form::Plain { decimal_long }))
}

impl Codes {
    /// Os nomes do `ntstatus.h` (texto inteiro).
    fn load_ntstatus(&mut self, text: &str) {
        for line in text.lines() {
            if let Some((name, value, Form::NtStatus)) = define(line) {
                self.ntstatus.entry(value).or_insert_with(|| name.to_string());
            }
        }
        // STATUS_WAIT_0 vem antes no cabeçalho, mas o 0 é STATUS_SUCCESS.
        if self.ntstatus.contains_key(&0) {
            self.ntstatus.insert(0, "STATUS_SUCCESS".into());
        }
    }

    /// Os nomes do `winerror.h`: os HRESULT pelo molde e os erros do Win32
    /// (decimais com `L`). Um nome definido duas vezes (os ramos `#if` do
    /// cabeçalho) fica com a primeira definição, a do Windows.
    fn load_winerror(&mut self, text: &str) {
        let mut seen: HashSet<&str> = HashSet::new();
        for line in text.lines() {
            let Some((name, value, form)) = define(line) else { continue };
            if !seen.insert(name) {
                continue;
            }
            match form {
                Form::HResult => {
                    self.hresult.entry(value).or_insert_with(|| name.to_string());
                }
                Form::Plain { decimal_long: true } if !name.starts_with("FACILITY_") && !name.starts_with("SEVERITY_") => {
                    // O primeiro nome ERROR_ ganha de um apelido anterior.
                    let replace = match self.win32.get(&value) {
                        None => true,
                        Some(current) => !current.starts_with("ERROR_") && name.starts_with("ERROR_"),
                    };
                    if replace {
                        self.win32.insert(value, name.to_string());
                    }
                }
                _ => {}
            }
        }
        if self.hresult.contains_key(&0) {
            self.hresult.insert(0, "S_OK".into());
        }
        if self.hresult.contains_key(&1) {
            self.hresult.insert(1, "S_FALSE".into());
        }
    }

    /// As listas curtas, quando o SDK não está nesta máquina.
    fn load_builtin(&mut self) {
        for &(value, name) in BUILTIN_WIN32 {
            self.win32.entry(value).or_insert_with(|| name.to_string());
        }
        for &(value, name) in BUILTIN_HRESULT {
            self.hresult.entry(value).or_insert_with(|| name.to_string());
        }
    }

    /// Carrega tudo o que achar nesta máquina.
    fn load() -> Codes {
        let mut codes = Codes::default();
        let mut sources = Vec::new();
        match sdk_shared() {
            Some(folder) => {
                if let Ok(text) = std::fs::read_to_string(folder.join("ntstatus.h")) {
                    codes.load_ntstatus(&text);
                }
                if let Ok(bytes) = std::fs::read(folder.join("winerror.h")) {
                    codes.load_winerror(&String::from_utf8_lossy(&bytes));
                }
                sources.push(format!("nomes de {}", folder.display()));
            }
            None => sources.push("nomes: lista curta (SDK do Windows ausente)".into()),
        }
        codes.load_builtin();
        let system = system_root().join("System32");
        if let Some(path) = localized(&system, "ntdll.dll") {
            codes.ntstatus_text = message_table(&path);
            sources.push(format!("textos de {}", path.display()));
        }
        if let Some(path) = localized(&system, "KernelBase.dll") {
            codes.system_text = message_table(&path);
            sources.push(format!("textos de {}", path.display()));
        }
        codes.source = sources.join("; ");
        codes
    }

    /// O nome de um NTSTATUS.
    pub fn ntstatus(&self, value: u32) -> Option<&str> {
        self.ntstatus.get(&value).map(String::as_str).or_else(|| kd_client::ntstatus::name(value))
    }

    /// O nome de um erro do Win32.
    pub fn win32(&self, value: u32) -> Option<&str> {
        self.win32.get(&value).map(String::as_str)
    }

    /// O nome de um HRESULT: o do cabeçalho ou a forma composta
    /// `HRESULT_FROM_WIN32(ERROR_X)` / `HRESULT_FROM_NT(STATUS_X)`.
    pub fn hresult(&self, value: u32) -> Option<String> {
        if let Some(name) = self.hresult.get(&value) {
            return Some(name.clone());
        }
        // HRESULT_FROM_WIN32: severidade 1, facilidade 7 (0x8007xxxx).
        if value & 0xFFFF_0000 == 0x8007_0000 {
            return self.win32(value & 0xFFFF).map(|name| format!("HRESULT_FROM_WIN32({name})"));
        }
        // HRESULT_FROM_NT: o bit N (0x10000000) sobre o NTSTATUS.
        if value & 0x1000_0000 != 0 && value >> 31 != 0 {
            return self.ntstatus(value & !0x1000_0000).map(|name| format!("HRESULT_FROM_NT({name})"));
        }
        None
    }

    /// O texto da tabela de mensagens de um NTSTATUS.
    pub fn ntstatus_text(&self, value: u32) -> Option<&str> {
        self.ntstatus_text.get(&value).map(String::as_str)
    }

    /// O texto da tabela de mensagens do sistema (Win32 ou HRESULT).
    pub fn system_text(&self, value: u32) -> Option<&str> {
        self.system_text.get(&value).map(String::as_str)
    }

    /// O nome curto para um imediato da desmontagem: só valores com
    /// severidade ou facilidade (a partir de 0x40000000, onde um número
    /// comum quase nunca cai) que têm nome. NTSTATUS primeiro (é o código
    /// do kernel e da ntdll), depois HRESULT.
    pub fn immediate(&self, value: u64) -> Option<String> {
        let high = value >> 32;
        if high != 0 && high != 0xFFFF_FFFF {
            return None;
        }
        let low = value as u32;
        if high == 0xFFFF_FFFF && low >> 31 == 0 {
            return None;
        }
        if low < 0x4000_0000 || low == 0xFFFF_FFFF {
            return None;
        }
        self.ntstatus(low).map(str::to_string).or_else(|| self.hresult(low))
    }

    /// Todas as leituras de um valor de 32 bits, com o texto da tabela de
    /// mensagens quando houver (a caixa de informação).
    pub fn explain(&self, value: u32) -> Vec<String> {
        let mut lines = Vec::new();
        let text = |found: Option<&str>| found.map(|text| format!(": {text}")).unwrap_or_default();
        if let Some(name) = self.ntstatus(value) {
            lines.push(format!("{value:#010x} NTSTATUS {name}{}", text(self.ntstatus_text(value))));
        }
        if let Some(name) = self.hresult(value) {
            lines.push(format!("{value:#010x} HRESULT {name}{}", text(self.system_text(value).or_else(|| self.system_text(value & 0xFFFF).filter(|_| value & 0xFFFF_0000 == 0x8007_0000)))));
        }
        if value < 0x1_0000 {
            if let Some(name) = self.win32(value) {
                lines.push(format!("{value} Win32 {name}{}", text(self.system_text(value))));
            }
        }
        lines
    }

    /// `STATUS_X (0xc0000034)` ou só o número.
    pub fn describe_ntstatus(&self, value: u32) -> String {
        match self.ntstatus(value) {
            Some(name) => format!("{name} ({value:#010x})"),
            None => format!("{value:#010x}"),
        }
    }

    /// `ERROR_X (2)` ou só o número.
    pub fn describe_win32(&self, value: u32) -> String {
        match self.win32(value) {
            Some(name) => format!("{name} ({value})"),
            None => format!("{value}"),
        }
    }
}

/// Os nomes e textos (carregados na primeira chamada).
pub fn codes() -> &'static Codes {
    static CODES: OnceLock<Codes> = OnceLock::new();
    CODES.get_or_init(Codes::load)
}

fn system_root() -> PathBuf {
    std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

/// A pasta `shared` do SDK com o `ntstatus.h` (a versão mais nova).
fn sdk_shared() -> Option<PathBuf> {
    if let Some(folder) = std::env::var_os("OPENNT_SDK_INCLUDE").map(PathBuf::from) {
        if folder.join("ntstatus.h").is_file() {
            return Some(folder);
        }
    }
    let mut roots = Vec::new();
    if let Some(sdk) = std::env::var_os("WindowsSdkDir") {
        roots.push(PathBuf::from(sdk).join("Include"));
    }
    for variable in ["ProgramFiles(x86)", "ProgramFiles"] {
        if let Some(folder) = std::env::var_os(variable) {
            roots.push(PathBuf::from(folder).join("Windows Kits").join("10").join("Include"));
        }
    }
    roots.push(PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10\Include"));
    for root in roots {
        let Ok(entries) = std::fs::read_dir(&root) else { continue };
        let mut versions: Vec<PathBuf> = entries.filter_map(Result::ok).map(|entry| entry.path().join("shared")).filter(|folder| folder.join("ntstatus.h").is_file()).collect();
        versions.sort();
        if let Some(newest) = versions.pop() {
            return Some(newest);
        }
    }
    None
}

/// O `.mui` de um binário do sistema (en-US, pt-BR ou o primeiro idioma
/// que tiver), senão o próprio binário.
fn localized(system: &Path, file: &str) -> Option<PathBuf> {
    let mui = format!("{file}.mui");
    for language in ["en-US", "pt-BR"] {
        let path = system.join(language).join(&mui);
        if path.is_file() {
            return Some(path);
        }
    }
    if let Ok(entries) = std::fs::read_dir(system) {
        for entry in entries.filter_map(Result::ok) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.len() == 5 && name.as_bytes()[2] == b'-' {
                let path = entry.path().join(&mui);
                if path.is_file() {
                    return Some(path);
                }
            }
        }
    }
    let path = system.join(file);
    path.is_file().then_some(path)
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    bytes.get(at..at + 2).map(|slice| u16::from_le_bytes([slice[0], slice[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    bytes.get(at..at + 4).map(|slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// A entrada de um diretório de recursos (deslocamento `directory` nos
/// bytes) com o id pedido, ou a primeira com `None`: o deslocamento do
/// filho e se ele é outro diretório.
fn resource_entry(bytes: &[u8], root: usize, directory: usize, id: Option<u32>) -> Option<(usize, bool)> {
    let named = u16_at(bytes, directory + 12)? as usize;
    let ids = u16_at(bytes, directory + 14)? as usize;
    for index in 0..(named + ids).min(4096) {
        let at = directory + 16 + 8 * index;
        let name = u32_at(bytes, at)?;
        let offset = u32_at(bytes, at + 4)?;
        if let Some(wanted) = id {
            if name & 0x8000_0000 != 0 || name != wanted {
                continue;
            }
        }
        return Some((root + (offset & 0x7FFF_FFFF) as usize, offset & 0x8000_0000 != 0));
    }
    None
}

/// A tabela de mensagens de um PE (o primeiro nome e o primeiro idioma do
/// tipo RT_MESSAGETABLE): id → texto.
fn message_table(path: &Path) -> HashMap<u32, String> {
    let Some(image) = std::fs::read(path).ok().and_then(PeImage::parse) else { return HashMap::new() };
    message_table_of(&image)
}

fn message_table_of(image: &PeImage) -> HashMap<u32, String> {
    let empty = HashMap::new();
    let Some((rva, _)) = image.directory(2).filter(|&(rva, size)| rva != 0 && size != 0) else { return empty };
    let Some(root) = image.offset(rva) else { return empty };
    let bytes = &image.bytes;
    let Some((names, true)) = resource_entry(bytes, root, root, Some(RT_MESSAGETABLE)) else { return empty };
    let Some((languages, true)) = resource_entry(bytes, root, names, None) else { return empty };
    let Some((leaf, false)) = resource_entry(bytes, root, languages, None) else { return empty };
    // IMAGE_RESOURCE_DATA_ENTRY: RVA dos dados e tamanho.
    let (Some(data_rva), Some(size)) = (u32_at(bytes, leaf), u32_at(bytes, leaf + 4)) else { return empty };
    match image.bytes_at(data_rva, size as usize) {
        Some(data) => parse_messages(data),
        None => empty,
    }
}

/// MESSAGE_RESOURCE_DATA: os blocos (id baixo, id alto, deslocamento) e as
/// entradas (tamanho, flags, texto ANSI ou UTF-16).
fn parse_messages(data: &[u8]) -> HashMap<u32, String> {
    let mut table = HashMap::new();
    let Some(blocks) = u32_at(data, 0) else { return table };
    for block in 0..(blocks as usize).min(8192) {
        let at = 4 + 12 * block;
        let (Some(low), Some(high), Some(start)) = (u32_at(data, at), u32_at(data, at + 4), u32_at(data, at + 8)) else { break };
        if high < low || high - low > 0x1_0000 {
            continue;
        }
        let mut entry = start as usize;
        for id in low..=high {
            let (Some(length), Some(flags)) = (u16_at(data, entry), u16_at(data, entry + 2)) else { break };
            let length = length as usize;
            if length < 4 {
                break;
            }
            let raw = data.get(entry + 4..entry + length).unwrap_or(&[]);
            let text = if flags & 1 != 0 {
                let units: Vec<u16> = raw.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
                String::from_utf16_lossy(&units)
            } else {
                raw.iter().take_while(|&&byte| byte != 0).map(|&byte| byte as char).collect()
            };
            table.insert(id, clean_message(&text));
            entry += length;
        }
    }
    table
}

/// O texto numa linha: sem as quebras e sem os espaços das pontas.
fn clean_message(text: &str) -> String {
    text.split(|character: char| character == '\r' || character == '\n').map(str::trim).filter(|part| !part.is_empty()).collect::<Vec<_>>().join(" ")
}

/// Os erros do Win32 mais comuns (valores públicos do `winerror.h`).
const BUILTIN_WIN32: &[(u32, &str)] = &[
    (0, "ERROR_SUCCESS"),
    (1, "ERROR_INVALID_FUNCTION"),
    (2, "ERROR_FILE_NOT_FOUND"),
    (3, "ERROR_PATH_NOT_FOUND"),
    (5, "ERROR_ACCESS_DENIED"),
    (6, "ERROR_INVALID_HANDLE"),
    (8, "ERROR_NOT_ENOUGH_MEMORY"),
    (13, "ERROR_INVALID_DATA"),
    (14, "ERROR_OUTOFMEMORY"),
    (18, "ERROR_NO_MORE_FILES"),
    (31, "ERROR_GEN_FAILURE"),
    (32, "ERROR_SHARING_VIOLATION"),
    (50, "ERROR_NOT_SUPPORTED"),
    (87, "ERROR_INVALID_PARAMETER"),
    (120, "ERROR_CALL_NOT_IMPLEMENTED"),
    (122, "ERROR_INSUFFICIENT_BUFFER"),
    (126, "ERROR_MOD_NOT_FOUND"),
    (127, "ERROR_PROC_NOT_FOUND"),
    (183, "ERROR_ALREADY_EXISTS"),
    (203, "ERROR_ENVVAR_NOT_FOUND"),
    (234, "ERROR_MORE_DATA"),
    (258, "WAIT_TIMEOUT"),
    (259, "ERROR_NO_MORE_ITEMS"),
    (997, "ERROR_IO_PENDING"),
    (1004, "ERROR_INVALID_FLAGS"),
    (1008, "ERROR_NO_TOKEN"),
    (1060, "ERROR_SERVICE_DOES_NOT_EXIST"),
    (1168, "ERROR_NOT_FOUND"),
    (1312, "ERROR_NO_SUCH_LOGON_SESSION"),
    (1314, "ERROR_PRIVILEGE_NOT_HELD"),
    (1400, "ERROR_INVALID_WINDOW_HANDLE"),
    (1407, "ERROR_CANNOT_FIND_WND_CLASS"),
    (1410, "ERROR_CLASS_ALREADY_EXISTS"),
    (1722, "RPC_S_SERVER_UNAVAILABLE"),
    (1726, "RPC_S_CALL_FAILED"),
];

/// Os HRESULT mais comuns (valores públicos do `winerror.h`).
const BUILTIN_HRESULT: &[(u32, &str)] = &[
    (0x0000_0000, "S_OK"),
    (0x0000_0001, "S_FALSE"),
    (0x8000_4001, "E_NOTIMPL"),
    (0x8000_4002, "E_NOINTERFACE"),
    (0x8000_4003, "E_POINTER"),
    (0x8000_4004, "E_ABORT"),
    (0x8000_4005, "E_FAIL"),
    (0x8000_FFFF, "E_UNEXPECTED"),
    (0x8001_0105, "RPC_E_SERVERFAULT"),
    (0x8001_0106, "RPC_E_CHANGED_MODE"),
    (0x8001_0108, "RPC_E_DISCONNECTED"),
    (0x8004_0110, "CLASS_E_NOAGGREGATION"),
    (0x8004_0154, "REGDB_E_CLASSNOTREG"),
    (0x8004_01F0, "CO_E_NOTINITIALIZED"),
    (0x8007_0005, "E_ACCESSDENIED"),
    (0x8007_0006, "E_HANDLE"),
    (0x8007_000E, "E_OUTOFMEMORY"),
    (0x8007_0057, "E_INVALIDARG"),
    (0x8000_000A, "E_PENDING"),
    (0x8000_000B, "E_BOUNDS"),
    (0x8000_0013, "RO_E_CLOSED"),
    (0x887A_0001, "DXGI_ERROR_INVALID_CALL"),
    (0x887A_0002, "DXGI_ERROR_NOT_FOUND"),
    (0x887A_0004, "DXGI_ERROR_UNSUPPORTED"),
    (0x887A_0005, "DXGI_ERROR_DEVICE_REMOVED"),
    (0x887A_0007, "DXGI_ERROR_DEVICE_RESET"),
];

#[cfg(test)]
mod tests {
    use super::*;

    const NTSTATUS_H: &str = "
#define STATUS_WAIT_0                           ((NTSTATUS)0x00000000L) // winnt
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)    // ntsubauth
#define STATUS_PENDING                   ((NTSTATUS)0x00000103L)    // winnt
#define STATUS_OBJECT_NAME_NOT_FOUND     ((NTSTATUS)0xC0000034L)
#define STATUS_SEVERITY_ERROR            0x3
#define FACILITY_RPC_RUNTIME             0x2
";

    const WINERROR_H: &str = "
#define FACILITY_WIN32                   7
#define ERROR_SUCCESS                    0L
#define NO_ERROR 0L                                                 // dderror
#define ERROR_FILE_NOT_FOUND             2L
#define ERROR_INSUFFICIENT_BUFFER        122L    // dderror
#define E_NOTIMPL                        _HRESULT_TYPEDEF_(0x80004001L)
#define E_FAIL                           _HRESULT_TYPEDEF_(0x80004005L)
#define E_NOTIMPL                        _HRESULT_TYPEDEF_(0x80000001L)
#define S_OK                                   ((HRESULT)0L)
#define DXGI_ERROR_INVALID_CALL          _HRESULT_TYPEDEF_(0x887A0001L)
#define MAKE_HRESULT(sev,fac,code) ((HRESULT)(((unsigned long)(sev)<<31)))
";

    fn sample() -> Codes {
        let mut codes = Codes::default();
        codes.load_ntstatus(NTSTATUS_H);
        codes.load_winerror(WINERROR_H);
        codes
    }

    #[test]
    fn parses_header_defines() {
        assert_eq!(define("#define STATUS_PENDING ((NTSTATUS)0x00000103L) // x"), Some(("STATUS_PENDING", 0x103, Form::NtStatus)));
        assert_eq!(define("#define E_FAIL _HRESULT_TYPEDEF_(0x80004005L)"), Some(("E_FAIL", 0x8000_4005, Form::HResult)));
        assert_eq!(define("#define ERROR_FILE_NOT_FOUND 2L"), Some(("ERROR_FILE_NOT_FOUND", 2, Form::Plain { decimal_long: true })));
        assert_eq!(define("#define FACILITY_WIN32 7"), Some(("FACILITY_WIN32", 7, Form::Plain { decimal_long: false })));
        assert_eq!(define("#define MAKE_HRESULT(sev,fac,code) (x)"), None);
        assert_eq!(define("#define WIN32_LEAN"), None);
        assert_eq!(define("#defineX 1"), None);
    }

    #[test]
    fn names_codes() {
        let codes = sample();
        assert_eq!(codes.ntstatus(0), Some("STATUS_SUCCESS"));
        assert_eq!(codes.ntstatus(0xC000_0034), Some("STATUS_OBJECT_NAME_NOT_FOUND"));
        assert_eq!(codes.win32(0), Some("ERROR_SUCCESS"));
        assert_eq!(codes.win32(122), Some("ERROR_INSUFFICIENT_BUFFER"));
        assert_eq!(codes.win32(7), None);
        // A segunda definição de E_NOTIMPL (outro ramo do #if) não vale.
        assert_eq!(codes.hresult(0x8000_4001).as_deref(), Some("E_NOTIMPL"));
        assert_eq!(codes.hresult(0x8000_0001), None);
        assert_eq!(codes.hresult(0).as_deref(), Some("S_OK"));
        assert_eq!(codes.hresult(0x8007_007A).as_deref(), Some("HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)"));
        assert_eq!(codes.hresult(0xD000_0034).as_deref(), Some("HRESULT_FROM_NT(STATUS_OBJECT_NAME_NOT_FOUND)"));
        assert_eq!(codes.describe_win32(2), "ERROR_FILE_NOT_FOUND (2)");
        assert_eq!(codes.describe_ntstatus(0xC000_0034), "STATUS_OBJECT_NAME_NOT_FOUND (0xc0000034)");
    }

    #[test]
    fn names_immediates() {
        let codes = sample();
        assert_eq!(codes.immediate(0xC000_0034).as_deref(), Some("STATUS_OBJECT_NAME_NOT_FOUND"));
        // O mesmo valor estendido com sinal (mov rax, imm32).
        assert_eq!(codes.immediate(0xFFFF_FFFF_C000_0034).as_deref(), Some("STATUS_OBJECT_NAME_NOT_FOUND"));
        assert_eq!(codes.immediate(0x887A_0001).as_deref(), Some("DXGI_ERROR_INVALID_CALL"));
        // Números pequenos, máscaras e ponteiros ficam sem nome.
        assert_eq!(codes.immediate(0x103), None);
        assert_eq!(codes.immediate(0xFFFF_FFFF), None);
        assert_eq!(codes.immediate(0xFFFF_F800_C000_0034), None);
        assert_eq!(codes.immediate(0xFFFF_FFFF_4000_0000), None);
    }

    #[test]
    fn explains_values() {
        let mut codes = sample();
        codes.ntstatus_text.insert(0xC000_0034, "Object Name not found.".into());
        codes.system_text.insert(122, "The data area passed to a system call is too small.".into());
        let lines = codes.explain(0xC000_0034);
        assert_eq!(lines, vec!["0xc0000034 NTSTATUS STATUS_OBJECT_NAME_NOT_FOUND: Object Name not found.".to_string()]);
        let lines = codes.explain(0x8007_007A);
        assert_eq!(lines, vec!["0x8007007a HRESULT HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER): The data area passed to a system call is too small.".to_string()]);
        let lines = codes.explain(122);
        assert_eq!(lines, vec!["122 Win32 ERROR_INSUFFICIENT_BUFFER: The data area passed to a system call is too small.".to_string()]);
    }

    #[test]
    fn parses_message_tables() {
        // Um bloco com os ids 5 e 6: um texto ANSI e um UTF-16.
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&5u32.to_le_bytes());
        data.extend_from_slice(&6u32.to_le_bytes());
        data.extend_from_slice(&16u32.to_le_bytes());
        let ansi = b"Acesso negado.\r\n\0\0";
        data.extend_from_slice(&((ansi.len() + 4) as u16).to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(ansi);
        let wide: Vec<u8> = "{Nao achado}\r\nO nome nao existe.\0".encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
        data.extend_from_slice(&((wide.len() + 4) as u16).to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&wide);
        let table = parse_messages(&data);
        assert_eq!(table.get(&5).map(String::as_str), Some("Acesso negado."));
        assert_eq!(table.get(&6).map(String::as_str), Some("{Nao achado} O nome nao existe."));
    }

    #[test]
    fn walks_resource_directories() {
        // Raiz em 0: um tipo (11) que leva ao diretório em 0x20, que leva
        // ao de idiomas em 0x40, que leva à entrada de dados em 0x60.
        let mut bytes = vec![0u8; 0x80];
        bytes[14..16].copy_from_slice(&1u16.to_le_bytes());
        bytes[16..20].copy_from_slice(&11u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&(0x8000_0000u32 | 0x20).to_le_bytes());
        bytes[0x20 + 14..0x20 + 16].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x30..0x34].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x34..0x38].copy_from_slice(&(0x8000_0000u32 | 0x40).to_le_bytes());
        bytes[0x40 + 14..0x40 + 16].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x50..0x54].copy_from_slice(&0x409u32.to_le_bytes());
        bytes[0x54..0x58].copy_from_slice(&0x60u32.to_le_bytes());
        assert_eq!(resource_entry(&bytes, 0, 0, Some(11)), Some((0x20, true)));
        assert_eq!(resource_entry(&bytes, 0, 0, Some(3)), None);
        assert_eq!(resource_entry(&bytes, 0, 0x20, None), Some((0x40, true)));
        assert_eq!(resource_entry(&bytes, 0, 0x40, None), Some((0x60, false)));
    }
}
