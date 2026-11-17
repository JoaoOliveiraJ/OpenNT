//! Os exploradores do estado vivo do alvo (`kernel/src/ntos/kd/explore.rs`):
//! as respostas de `monitor reg`, `monitor objdir` e `monitor fs` em
//! estruturas, os nomes dos tipos REG_* e o texto de um valor do Registro.
//! Os campos de cada linha vêm separados por tabulação; a última linha de
//! uma página incompleta é `mais: N`.

/// Uma chave do Registro (o cabeçalho do `reg keys`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyInfo {
    pub path: String,
    pub subkeys: usize,
    pub values: usize,
    /// LastWriteTime (100 ns desde 1601).
    pub last_write: u64,
    pub volatile: bool,
    pub link: bool,
    /// O arquivo da hive (vazio: só em memória).
    pub hive: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubKey {
    pub name: String,
    pub subkeys: usize,
    pub values: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryValue {
    pub name: String,
    pub kind: u32,
    /// O tamanho inteiro (os dados podem vir cortados).
    pub size: usize,
    pub data: Vec<u8>,
}

impl RegistryValue {
    pub fn kind_name(&self) -> &'static str {
        kind_name(self.kind)
    }

    /// O valor em texto, pelo tipo.
    pub fn display(&self) -> String {
        format_value(self.kind, &self.data, self.size)
    }
}

/// Um objeto de um diretório do namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectEntry {
    pub name: String,
    pub kind: String,
    /// O corpo nativo (o objeto do NT), quando há.
    pub body: u64,
    pub children: usize,
    /// O destino de um link, ou o arquivo por trás.
    pub target: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectDirectory {
    pub path: String,
    pub kind: String,
    pub body: u64,
    pub count: usize,
    pub entries: Vec<ObjectEntry>,
}

/// Um arquivo ou uma pasta do volume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    pub name: String,
    pub directory: bool,
    pub size: u64,
    pub attributes: u32,
    /// LastWriteTime (100 ns desde 1601).
    pub modified: u64,
}

pub fn kind_name(kind: u32) -> &'static str {
    match kind {
        0 => "REG_NONE",
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        7 => "REG_MULTI_SZ",
        8 => "REG_RESOURCE_LIST",
        9 => "REG_FULL_RESOURCE_DESCRIPTOR",
        10 => "REG_RESOURCE_REQUIREMENTS_LIST",
        11 => "REG_QWORD",
        _ => "REG_?",
    }
}

fn utf16(data: &[u8]) -> String {
    let units: Vec<u16> = data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    String::from_utf16_lossy(&units)
}

/// O texto de um valor pelo tipo (`size` é o tamanho inteiro).
pub fn format_value(kind: u32, data: &[u8], size: usize) -> String {
    let cut = if data.len() < size { " ..." } else { "" };
    match kind {
        1 | 2 | 6 => format!("\"{}\"{cut}", utf16(data).trim_end_matches('\0')),
        7 => {
            let text = utf16(data);
            let parts: Vec<String> = text.split('\0').filter(|part| !part.is_empty()).map(|part| format!("\"{part}\"")).collect();
            format!("{}{cut}", parts.join(" "))
        }
        4 if data.len() >= 4 => {
            let value = u32::from_le_bytes(data[..4].try_into().unwrap_or([0; 4]));
            format!("{value:#010x} ({value})")
        }
        5 if data.len() >= 4 => {
            let value = u32::from_be_bytes(data[..4].try_into().unwrap_or([0; 4]));
            format!("{value:#010x} ({value})")
        }
        11 if data.len() >= 8 => {
            let value = u64::from_le_bytes(data[..8].try_into().unwrap_or([0; 8]));
            format!("{value:#018x} ({value})")
        }
        _ => {
            let shown: Vec<String> = data.iter().take(48).map(|byte| format!("{byte:02x}")).collect();
            format!("{}{}", shown.join(" "), if data.len() > 48 || data.len() < size { " ..." } else { "" })
        }
    }
}

fn hex_bytes(text: &str) -> Vec<u8> {
    super::rsp::unhex(text.trim())
}

fn number(text: &str) -> u64 {
    let text = text.trim();
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).unwrap_or(0),
        None => text.parse().unwrap_or(0),
    }
}

/// O índice da próxima página (`mais: N`).
pub fn more(text: &str) -> Option<usize> {
    text.lines().find_map(|line| line.strip_prefix("mais: ").and_then(|next| next.trim().parse().ok()))
}

/// O erro de uma resposta sem as linhas esperadas (a primeira linha).
pub fn error_of(text: &str, expected: &str) -> Option<String> {
    let first = text.lines().next().unwrap_or("").trim();
    (!first.starts_with(expected)).then(|| if first.is_empty() { "resposta vazia do alvo".to_string() } else { first.to_string() })
}

/// Uma página do `reg keys`: o cabeçalho e as subchaves.
pub fn parse_keys(text: &str) -> Result<(KeyInfo, Vec<SubKey>), String> {
    if let Some(error) = error_of(text, "chave\t") {
        return Err(error);
    }
    let mut info = KeyInfo::default();
    let mut keys = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        match fields.first().copied() {
            Some("chave") if fields.len() >= 8 => {
                info = KeyInfo { path: fields[1].to_string(), subkeys: number(fields[2]) as usize, values: number(fields[3]) as usize, last_write: number(fields[4]), volatile: fields[5] == "1", link: fields[6] == "1", hive: fields[7].to_string() };
            }
            Some("k") if fields.len() >= 4 => keys.push(SubKey { name: fields[1].to_string(), subkeys: number(fields[2]) as usize, values: number(fields[3]) as usize }),
            _ => {}
        }
    }
    Ok((info, keys))
}

/// Uma página do `reg values`.
pub fn parse_values(text: &str) -> Result<Vec<RegistryValue>, String> {
    let mut values = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.first() == Some(&"v") && fields.len() >= 5 {
            values.push(RegistryValue { name: fields[1].to_string(), kind: number(fields[2]) as u32, size: number(fields[3]) as usize, data: hex_bytes(fields[4]) });
        } else if !line.starts_with("mais: ") && !line.trim().is_empty() && values.is_empty() {
            return Err(line.trim().to_string());
        }
    }
    Ok(values)
}

/// O `reg value`: o valor, o deslocamento dos dados e os dados.
pub fn parse_value(text: &str) -> Result<(RegistryValue, usize), String> {
    if let Some(error) = error_of(text, "valor\t") {
        return Err(error);
    }
    let line = text.lines().next().unwrap_or("");
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.len() < 6 {
        return Err(format!("resposta inesperada: {line}"));
    }
    Ok((RegistryValue { name: fields[1].to_string(), kind: number(fields[2]) as u32, size: number(fields[3]) as usize, data: hex_bytes(fields[5]) }, number(fields[4]) as usize))
}

/// Uma página do `objdir`.
pub fn parse_object_directory(text: &str) -> Result<ObjectDirectory, String> {
    if let Some(error) = error_of(text, "diretorio\t") {
        return Err(error);
    }
    let mut directory = ObjectDirectory::default();
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        match fields.first().copied() {
            Some("diretorio") if fields.len() >= 5 => {
                directory.path = fields[1].to_string();
                directory.kind = fields[2].to_string();
                directory.body = number(fields[3]);
                directory.count = number(fields[4]) as usize;
            }
            Some("o") if fields.len() >= 5 => directory.entries.push(ObjectEntry { name: fields[1].to_string(), kind: fields[2].to_string(), body: number(fields[3]), children: number(fields[4]) as usize, target: fields.get(5).unwrap_or(&"").to_string() }),
            _ => {}
        }
    }
    Ok(directory)
}

/// Uma página do `fs ls`: a pasta, o total e as entradas.
pub fn parse_files(text: &str) -> Result<(String, usize, Vec<FileEntry>), String> {
    if let Some(error) = error_of(text, "pasta\t") {
        return Err(error);
    }
    let mut path = String::new();
    let mut count = 0;
    let mut entries = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        match fields.first().copied() {
            Some("pasta") if fields.len() >= 3 => {
                path = fields[1].to_string();
                count = number(fields[2]) as usize;
            }
            Some("f") if fields.len() >= 6 => entries.push(FileEntry { name: fields[1].to_string(), directory: fields[2] == "1", size: number(fields[3]), attributes: number(fields[4]) as u32, modified: number(fields[5]) }),
            _ => {}
        }
    }
    Ok((path, count, entries))
}

/// O `fs read`: o tamanho do arquivo, o deslocamento e os bytes.
pub fn parse_file_data(text: &str) -> Result<(u64, u64, Vec<u8>), String> {
    if let Some(error) = error_of(text, "dados\t") {
        return Err(error);
    }
    let line = text.lines().next().unwrap_or("");
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.len() < 5 {
        return Err(format!("resposta inesperada: {line}"));
    }
    Ok((number(fields[2]), number(fields[3]), hex_bytes(fields[4])))
}

/// Uma data do NT (100 ns desde 1601) em texto UTC `AAAA-MM-DD HH:MM:SS`.
pub fn nt_time(value: u64) -> String {
    if value == 0 {
        return "-".to_string();
    }
    let seconds = value / 10_000_000;
    let days = seconds / 86_400;
    let rest = seconds % 86_400;
    // Dias desde 1601-01-01 para a data civil (o algoritmo de dias civis,
    // a partir de 1970).
    let unix_days = days as i64 - 134_774;
    let z = unix_days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}", rest / 3600, rest % 3600 / 60, rest % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_pages() {
        let keys = "chave\t\\REGISTRY\\MACHINE\\SYSTEM\\Select\t0\t4\t0x1d9a0b0c0d0e0f0\t0\t0\t\\SystemRoot\\System32\\Config\\SYSTEM\nk\tFilho\t2\t3\nmais: 1\n";
        let (info, subkeys) = parse_keys(keys).expect("chave");
        assert_eq!(info.values, 4);
        assert_eq!(info.hive, "\\SystemRoot\\System32\\Config\\SYSTEM");
        assert_eq!(subkeys, vec![SubKey { name: "Filho".into(), subkeys: 2, values: 3 }]);
        assert_eq!(more(keys), Some(1));
        assert!(parse_keys("\\x: chave nao encontrada\n").is_err());
        let values = parse_values("v\tCurrent\t4\t4\t01000000\nv\tNome\t1\t8\t4f004b000000\n").expect("valores");
        assert_eq!(values[0].kind_name(), "REG_DWORD");
        assert_eq!(values[0].display(), "0x00000001 (1)");
        assert_eq!(values[1].display(), "\"OK\" ...");
        let (value, offset) = parse_value("valor\tCurrent\t4\t4\t0\t01000000\n").expect("valor");
        assert_eq!((value.size, offset, value.data.clone()), (4, 0, vec![1, 0, 0, 0]));
        assert_eq!(format_value(7, &"a\0b\0\0".encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>(), 10), "\"a\" \"b\"");
    }

    #[test]
    fn objects_and_files() {
        let text = "diretorio\t\\Device\tDirectory\t0xffff800000001000\t2\no\tNull\tDevice\t0xffff800000002000\t0\t\no\tHarddiskVolume1\tSymbolicLink\t0x0\t0\t\\Device\\Harddisk0\\Partition1\n";
        let directory = parse_object_directory(text).expect("diretorio");
        assert_eq!(directory.count, 2);
        assert_eq!(directory.entries[0].body, 0xffff_8000_0000_2000);
        assert_eq!(directory.entries[1].target, "\\Device\\Harddisk0\\Partition1");
        let (path, count, files) = parse_files("pasta\t/Windows\t2\nf\tSystem32\t1\t0\t0x10\t0x0\nf\twin.ini\t0\t92\t0x20\t0x1d9a0b0c0d0e0f0\n").expect("pasta");
        assert_eq!((path.as_str(), count), ("/Windows", 2));
        assert!(files[0].directory && !files[1].directory);
        assert_eq!(files[1].size, 92);
        let (size, offset, bytes) = parse_file_data("dados\t/win.ini\t92\t0\t5b666f6e74735d\n").expect("dados");
        assert_eq!((size, offset), (92, 0));
        assert_eq!(bytes, b"[fonts]");
    }

    #[test]
    fn nt_dates() {
        // 2020-01-01 00:00:00 UTC.
        assert_eq!(nt_time(132_223_104_000_000_000), "2020-01-01 00:00:00");
        assert_eq!(nt_time(0), "-");
    }
}
