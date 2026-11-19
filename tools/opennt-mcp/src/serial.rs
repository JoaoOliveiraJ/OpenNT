//! O log da COM1 (o `serial.log` do build) visto pelas ferramentas: o
//! resumo de um log inteiro (marcadores `*_OK`, processos criados, as
//! quedas de processo e do kernel, o bugcheck, a presença do WdLog do
//! dxgkrnl, as falhas mais repetidas e as últimas linhas) e a espera de um
//! texto com a máquina rodando, lendo só o que o log ganhou.
//!
//! Os formatos são os que o kernel do OpenNT escreve: `[init] X (pid N)
//! criou Y (pid M) ...`, os blocos `[crash]` (processo de usuário),
//! `[kcrash]` (parada no KeBugCheck), `[bugcheck] codigo de parada: NOME`,
//! `*** STOP`, e as linhas `KERNEL_BUGCHECK_SECONDARY_RECORD`/`_BYTES` dos
//! dados secundários do bugcheck (o WdLog do dxgkrnl vem por elas).

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

/// O GUID dos dados secundários do dxgkrnl (WdDxgkSecondaryDataGUID
/// {270A33FD-3DA6-460D-BA89-3C1BAE21E39B}) como ele aparece nas linhas
/// `KERNEL_BUGCHECK_SECONDARY_RECORD` (os bytes do GUID em hexadecimal).
pub const WDLOG_GUID: &str = "fd330a27a63d0d46ba893c1bae21e39b";

/// Maior trecho lido de um log para o resumo (os logs do boot passam de
/// alguns MB).
pub const MAX_READ: u64 = 64 << 20;

/// Lê o log a partir de `offset` (até `MAX_READ` bytes).
pub fn read_from(path: &Path, offset: u64) -> Result<Vec<u8>, String> {
    let mut file = std::fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    file.seek(SeekFrom::Start(offset)).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_READ).read_to_end(&mut bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(bytes)
}

/// O tamanho do log agora (0 se ainda não existe).
pub fn size(path: &Path) -> u64 {
    std::fs::metadata(path).map_or(0, |metadata| metadata.len())
}

/// O fim de um texto com no máximo `max` bytes (num limite de caractere).
pub fn tail_text(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut start = text.len() - max;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    &text[start..]
}

fn position(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// A linha inteira em volta de `at` (sem a quebra, no máximo 400 caracteres).
fn line_around(bytes: &[u8], at: usize) -> String {
    let start = bytes[..at].iter().rposition(|&byte| byte == b'\n').map_or(0, |index| index + 1);
    let end = bytes[at..].iter().position(|&byte| byte == b'\n').map_or(bytes.len(), |index| at + index);
    let text = String::from_utf8_lossy(&bytes[start..end]).trim_end().to_string();
    text.chars().take(400).collect()
}

/// Um texto achado no log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub marker: String,
    /// A linha do texto.
    pub line: String,
    /// O byte logo depois do texto (a próxima busca começa ali).
    pub offset: u64,
}

/// A espera de textos num log que cresce: cada `poll` lê só o que chegou
/// desde a anterior (com uma sobra do tamanho do maior texto, para achar um
/// texto partido entre duas leituras).
pub struct Watch {
    path: PathBuf,
    checked: u64,
    /// Nada antes daqui conta (o começo pedido, ou o fim do último achado).
    floor: u64,
}

impl Watch {
    /// Procura a partir de `from` (0 = o log inteiro).
    pub fn new(path: PathBuf, from: u64) -> Watch {
        Watch { path, checked: from, floor: from }
    }

    /// Até onde o log já foi lido.
    pub fn checked(&self) -> u64 {
        self.checked
    }

    /// O primeiro dos textos que aparece no que o log ganhou.
    pub fn poll(&mut self, markers: &[String]) -> Option<Found> {
        let total = size(&self.path);
        if total < self.checked {
            // O log recomeçou (outro boot no mesmo build).
            self.checked = 0;
            self.floor = 0;
        }
        if total == self.checked {
            return None;
        }
        let longest = markers.iter().map(String::len).max().unwrap_or(0) as u64;
        let search_from = self.checked.saturating_sub(longest.saturating_sub(1)).max(self.floor);
        // Um pouco antes, para a linha inteira do texto achado.
        let read_start = search_from.saturating_sub(4096);
        let bytes = read_from(&self.path, read_start).ok()?;
        let skip = ((search_from - read_start) as usize).min(bytes.len());
        let mut best: Option<(usize, &String)> = None;
        for marker in markers.iter().filter(|marker| !marker.is_empty()) {
            if let Some(index) = position(&bytes[skip..], marker.as_bytes()) {
                let at = skip + index;
                if best.is_none_or(|(current, _)| at < current) {
                    best = Some((at, marker));
                }
            }
        }
        self.checked = read_start + bytes.len() as u64;
        let (at, marker) = best?;
        let offset = read_start + (at + marker.len()) as u64;
        self.checked = offset;
        self.floor = offset;
        Some(Found { marker: marker.clone(), line: line_around(&bytes, at), offset })
    }
}

/// Um token começando com dígito vira `#` (os PIDs, endereços e códigos
/// mudam de uma linha para outra; o padrão da falha não).
pub fn normalize(line: &str) -> String {
    let mut output = String::with_capacity(line.len());
    let mut characters = line.chars().peekable();
    let mut previous_word = false;
    while let Some(character) = characters.next() {
        if character.is_ascii_digit() && !previous_word {
            while characters.peek().is_some_and(|next| next.is_ascii_hexdigit() || *next == 'x' || *next == '`') {
                characters.next();
            }
            output.push('#');
            previous_word = false;
            continue;
        }
        previous_word = character.is_ascii_alphanumeric() || character == '_';
        output.push(character);
    }
    output.chars().take(160).collect()
}

/// A linha fala de falha (as palavras do log do kernel e os NTSTATUS de
/// erro).
fn is_failure(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    const WORDS: [&str; 10] = ["falh", "fail", "erro", "excec", "exception", "denied", "negad", "not found", "nao encontrad", "invalid"];
    if WORDS.iter().any(|word| lower.contains(word)) {
        return true;
    }
    // 0xc0000034, ffffffffc0000034, 0xd0000409: um NTSTATUS de erro.
    let bytes = lower.as_bytes();
    let mut index = 0;
    while let Some(found) = lower[index..].find(['c', 'd']) {
        let at = index + found;
        let digits = &bytes[at..bytes.len().min(at + 8)];
        let after = bytes.get(at + 8).copied();
        let before = at.checked_sub(1).map(|before| bytes[before]);
        let starts = before.is_none_or(|byte| byte == b'x' || byte == b'f' || !byte.is_ascii_alphanumeric());
        if starts && digits.len() == 8 && digits[1] == b'0' && digits.iter().all(u8::is_ascii_hexdigit) && after.is_none_or(|byte| !byte.is_ascii_hexdigit()) {
            return true;
        }
        index = at + 1;
    }
    false
}

/// O marcador de uma linha: a primeira palavra em maiúsculas terminada em
/// `_OK` (`SMSS_CSRSS_OK`, `PAGEFILE_OK \??\D:\...`).
fn marker_of(line: &str) -> Option<&str> {
    let word = line.split_whitespace().next()?;
    let valid = word.len() > 3 && word.ends_with("_OK") && word.chars().next().is_some_and(|character| character.is_ascii_uppercase()) && word.chars().all(|character| character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_');
    valid.then_some(word)
}

/// A etiqueta `[tag]` do começo da linha.
fn tag_of(line: &str) -> Option<&str> {
    let rest = line.strip_prefix('[')?;
    let end = rest.find(']')?;
    let tag = &rest[..end];
    (!tag.is_empty() && tag.len() <= 24 && !tag.contains(' ')).then_some(tag)
}

/// `[init] winlogon.exe (pid 196) criou dwm.exe (pid 500) por ...`.
fn process_created(line: &str) -> Option<Value> {
    let rest = line.strip_prefix("[init] ")?;
    let (parent, child) = rest.split_once(" criou ")?;
    let split = |text: &str| -> Option<(String, u64)> {
        let (name, tail) = text.split_once(" (pid ")?;
        let pid: String = tail.chars().take_while(char::is_ascii_digit).collect();
        Some((name.trim().to_string(), pid.parse().ok()?))
    };
    let (parent, parent_pid) = split(parent)?;
    let (name, pid) = split(child)?;
    Some(json!({"name": name, "pid": pid, "parent": parent, "parent_pid": parent_pid}))
}

/// Os blocos de linhas seguidas com o mesmo prefixo (`[crash]`,
/// `[kcrash]`): a primeira linha e as seguintes (até `detail` delas).
fn blocks(lines: &[&str], prefix: &str, detail: usize, limit: usize) -> Vec<Value> {
    let mut output = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if !lines[index].starts_with(prefix) {
            index += 1;
            continue;
        }
        let first = index;
        while index < lines.len() && lines[index].starts_with(prefix) {
            index += 1;
        }
        let body: Vec<String> = lines[first + 1..index].iter().take(detail).map(|line| line[prefix.len()..].trim().to_string()).collect();
        output.push(json!({"line": first + 1, "header": lines[first][prefix.len()..].trim(), "details": body, "more": (index - first - 1).saturating_sub(detail)}));
    }
    // As últimas valem mais (a queda que encerrou o boot).
    let skip = output.len().saturating_sub(limit);
    output.split_off(skip)
}

/// O que interessa numa queda: os blocos `[crash]` e `[kcrash]`, o código
/// de parada do bugcheck, as linhas de `*** STOP` e a presença do WdLog.
pub fn crash_report(text: &str) -> Value {
    let lines: Vec<&str> = text.lines().collect();
    let stop_code = lines.iter().rev().find_map(|line| line.strip_prefix("[bugcheck] codigo de parada:")).map(|code| code.trim().to_string());
    let bugcheck: Vec<String> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| (line.starts_with("[bugcheck]") && !line.contains("callback (motivo")) || line.contains("*** STOP"))
        .map(|(index, line)| format!("{}: {}", index + 1, line.chars().take(300).collect::<String>()))
        .collect();
    let skip = bugcheck.len().saturating_sub(16);
    json!({
        "user_crashes": blocks(&lines, "[crash]", 12, 8),
        "kernel_crashes": blocks(&lines, "[kcrash]", 12, 4),
        "bugcheck": {"stop_code": stop_code, "lines": bugcheck[skip..]},
        "wdlog": wdlog_presence(text),
    })
}

/// Se o log tem o WdLog do dxgkrnl (os dados secundários do bugcheck com o
/// GUID dele): quantos registros e pedaços de bytes. A decodificação dos
/// anéis é da análise do opennt-kd.
pub fn wdlog_presence(text: &str) -> Value {
    let mut records = 0usize;
    let mut chunks = 0usize;
    let mut in_wdlog = false;
    for line in text.lines() {
        if line.starts_with("KERNEL_BUGCHECK_SECONDARY_RECORD") {
            in_wdlog = line.contains(WDLOG_GUID);
            if in_wdlog {
                records += 1;
            }
        } else if in_wdlog && line.starts_with("KERNEL_BUGCHECK_SECONDARY_BYTES") {
            chunks += 1;
        }
    }
    json!({"present": records > 0, "records": records, "chunks": chunks})
}

/// As opções do resumo.
#[derive(Clone, Debug)]
pub struct SummaryOptions {
    /// Últimas linhas.
    pub tail: usize,
    /// Linhas com este texto (vazio = nenhuma).
    pub grep: String,
    pub grep_limit: usize,
    /// Padrões de falha no máximo.
    pub failures: usize,
}

impl Default for SummaryOptions {
    fn default() -> Self {
        SummaryOptions { tail: 20, grep: String::new(), grep_limit: 50, failures: 15 }
    }
}

/// O resumo de um log (ou de um trecho dele).
pub fn summarize(text: &str, options: &SummaryOptions) -> Value {
    let lines: Vec<&str> = text.lines().collect();
    let mut markers: Vec<(String, usize, usize)> = Vec::new();
    let mut processes = Vec::new();
    let mut tags: HashMap<&str, usize> = HashMap::new();
    let mut failures: HashMap<String, (usize, usize, String)> = HashMap::new();
    let mut xtask = Vec::new();
    let mut grep = Vec::new();
    let mut grep_total = 0usize;
    let wanted = options.grep.to_ascii_lowercase();
    for (index, line) in lines.iter().enumerate() {
        let number = index + 1;
        if let Some(marker) = marker_of(line) {
            match markers.iter_mut().find(|(name, _, _)| name == marker) {
                Some(entry) => entry.2 += 1,
                None => markers.push((marker.to_string(), number, 1)),
            }
        }
        if let Some(created) = process_created(line) {
            processes.push(created);
        }
        if let Some(tag) = tag_of(line) {
            *tags.entry(tag).or_default() += 1;
            if tag == "xtask" && xtask.len() < 20 {
                xtask.push(format!("{number}: {}", line.chars().take(300).collect::<String>()));
            }
        }
        if is_failure(line) {
            let entry = failures.entry(normalize(line)).or_insert((0, number, String::new()));
            entry.0 += 1;
            if entry.2.is_empty() {
                entry.2 = line.chars().take(300).collect();
            }
        }
        if !wanted.is_empty() && line.to_ascii_lowercase().contains(&wanted) {
            grep_total += 1;
            if grep.len() < options.grep_limit {
                grep.push(format!("{number}: {}", line.chars().take(400).collect::<String>()));
            }
        }
    }
    let mut tag_list: Vec<(&str, usize)> = tags.into_iter().collect();
    tag_list.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let mut failure_list: Vec<(String, (usize, usize, String))> = failures.into_iter().collect();
    failure_list.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.1 .1.cmp(&b.1 .1)));
    let tail_start = lines.len().saturating_sub(options.tail);
    let mut value = json!({
        "bytes": text.len(),
        "lines": lines.len(),
        "markers": markers.iter().map(|(name, line, count)| json!({"marker": name, "line": line, "count": count})).collect::<Vec<_>>(),
        "last_marker": markers.iter().max_by_key(|(_, line, _)| *line).map(|(name, _, _)| name.clone()),
        "processes": processes,
        "crash": crash_report(text),
        "failures": failure_list.iter().take(options.failures).map(|(pattern, (count, line, example))| json!({"count": count, "first_line": line, "pattern": pattern, "example": example})).collect::<Vec<_>>(),
        "tags": tag_list.iter().take(15).map(|(tag, count)| json!({"tag": tag, "count": count})).collect::<Vec<_>>(),
        "xtask": xtask,
        "tail": lines[tail_start..].iter().enumerate().map(|(index, line)| format!("{}: {}", tail_start + index + 1, line.chars().take(400).collect::<String>())).collect::<Vec<_>>(),
    });
    if !wanted.is_empty() {
        value["grep"] = json!({"text": options.grep, "matches": grep_total, "lines": grep});
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "HELLO_KERNEL_OK\n\
[xtask] relogio de acordo com o hospedeiro\n\
SMSS_CSRSS_OK\n\
[init] smss.exe (pid 84) criou csrss.exe (pid 92) por NtCreateUserProcess\n\
[init] winlogon.exe (pid 196) criou dwm.exe (pid 500) por NtCreateUserProcess\n\
[pnp] devnode ACPI\\PNP0A06\\0 estado Failed problema 0x1c servico -\n\
[pnp] devnode ACPI\\PNP0A06\\1 estado Failed problema 0x1c servico -\n\
[usermode] NtOpenKey falhou 0xc0000034\n\
PAGEFILE_OK \\??\\D:\\pagefile.sys\n\
PAGEFILE_OK \\??\\C:\\swapfile.sys\n\
[crash] LogonUI.exe 492:536: NtRaiseHardError 0xd0000409\n\
[crash]   excecao 0xc0000409\n\
[crash]   pilha da chamada (rsp 0x3b4dd18): ntdll.dll+0xa02b4 (ZwRaiseHardError+0x14)\n\
[kcrash] parada dentro de KeBugCheck, chamada de win32kbase.sys+0xf99cb\n\
[bugcheck] codigo de parada: WIN32K_CRITICAL_FAILURE\n\
[bugcheck] callback (motivo 2) de wpprecorder.sys: rotina 0xfffff80100853480\n\
KERNEL_BUGCHECK_SECONDARY_RECORD {\"record\":\"fd330a27a63d0d46ba893c1bae21e39b\"}\n\
KERNEL_BUGCHECK_SECONDARY_BYTES {\"offset\":0}\n\
KERNEL_BUGCHECK_SECONDARY_BYTES {\"offset\":512}\n\
[bugcheck] reiniciando (AutoReboot)\n";

    #[test]
    fn summarizes_a_boot_log() {
        let summary = summarize(LOG, &SummaryOptions { tail: 2, grep: "dwm".into(), ..SummaryOptions::default() });
        assert_eq!(summary["lines"], 20);
        assert_eq!(summary["markers"][0]["marker"], "HELLO_KERNEL_OK");
        assert_eq!(summary["markers"][2]["marker"], "PAGEFILE_OK");
        assert_eq!(summary["markers"][2]["count"], 2);
        assert_eq!(summary["last_marker"], "PAGEFILE_OK");
        assert_eq!(summary["processes"][1]["name"], "dwm.exe");
        assert_eq!(summary["processes"][1]["parent_pid"], 196);
        let crash = &summary["crash"];
        assert_eq!(crash["user_crashes"][0]["header"], "LogonUI.exe 492:536: NtRaiseHardError 0xd0000409");
        assert_eq!(crash["user_crashes"][0]["details"].as_array().unwrap().len(), 2);
        assert_eq!(crash["kernel_crashes"][0]["line"], 14);
        assert_eq!(crash["bugcheck"]["stop_code"], "WIN32K_CRITICAL_FAILURE");
        assert_eq!(crash["bugcheck"]["lines"].as_array().unwrap().len(), 2);
        assert_eq!(crash["wdlog"], json!({"present": true, "records": 1, "chunks": 2}));
        // As duas linhas do devnode viram um padrão só.
        let failures = summary["failures"].as_array().unwrap();
        assert_eq!(failures[0]["count"], 2, "{failures:?}");
        assert!(failures[0]["pattern"].as_str().unwrap().contains("estado Failed problema #"));
        assert!(failures.iter().any(|failure| failure["example"].as_str().unwrap().contains("0xc0000034")));
        assert_eq!(summary["tags"][0]["tag"], "bugcheck");
        assert_eq!(summary["tail"].as_array().unwrap().len(), 2);
        assert_eq!(summary["grep"]["matches"], 1);
    }

    #[test]
    fn normalizes_and_classifies_lines() {
        assert_eq!(normalize("tid=68 start=0x18004d110 pid 84"), "tid=# start=# pid #");
        assert_eq!(normalize("win32kbase.sys+0xf99cb"), "win32kbase.sys+#");
        assert!(is_failure("[zw] status ffffffffc0000034"));
        assert!(is_failure("p=0xc000000d"));
        assert!(!is_failure("[mm] PFN: 352256 frames"));
        assert!(!is_failure("base=0xfffff80100000000"));
        assert_eq!(marker_of("PAGEFILE_OK \\??\\D:"), Some("PAGEFILE_OK"));
        assert_eq!(marker_of("[init] OK"), None);
        assert_eq!(tag_of("[file-io] x"), Some("file-io"));
        assert_eq!(tail_text("ação", 3), "ão");
    }

    #[test]
    fn watches_a_growing_log() {
        let directory = std::env::temp_dir().join(format!("opennt-mcp-serial-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&directory);
        let path = directory.join("serial.log");
        std::fs::write(&path, "linha 1\n").unwrap();
        let mut watch = Watch::new(path.clone(), 0);
        let markers = vec!["criou dwm".to_string(), "NUNCA".to_string()];
        assert_eq!(watch.poll(&markers), None);
        assert_eq!(watch.checked(), 8);
        std::fs::write(&path, "linha 1\n[init] winlogon.exe (pid 196) cri").unwrap();
        assert_eq!(watch.poll(&markers), None);
        // O texto partido entre duas leituras ainda é achado.
        std::fs::write(&path, "linha 1\n[init] winlogon.exe (pid 196) criou dwm.exe (pid 500)\nresto\n").unwrap();
        let found = watch.poll(&markers).expect("achado");
        assert_eq!(found.marker, "criou dwm");
        assert_eq!(found.line, "[init] winlogon.exe (pid 196) criou dwm.exe (pid 500)");
        assert_eq!(found.offset, 8 + "[init] winlogon.exe (pid 196) criou dwm".len() as u64);
        assert_eq!(watch.poll(&markers), None);
        let _ = std::fs::remove_dir_all(&directory);
    }
}
