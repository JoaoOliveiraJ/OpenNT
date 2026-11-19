//! As linhas do log da serial (COM1) que a análise de uma parada lê: os
//! começos de boot, as imagens de kernel carregadas (`[pe] base=`) e os
//! dados secundários do bugcheck (`KERNEL_BUGCHECK_SECONDARY_RECORD` e
//! `KERNEL_BUGCHECK_SECONDARY_BYTES`, que o `publish_secondary_data` do
//! kernel imprime em blocos de 128 bytes).

use std::ops::Range;

/// O pedaço da linha que abre um boot (`[OpenNT] kernel 64-bit vivo`, às
/// vezes com lixo do BIOS antes).
pub const BOOT_MARKER: &str = "kernel 64-bit vivo";

/// O maior registro de dados secundários aceito (o MaximumAllowed do kernel
/// é bem menor; o limite só evita alocar por um número corrompido).
const MAXIMUM_RECORD: u64 = 0x10_0000;

/// As linhas do texto da serial, sem `\r` e sem bytes nulos.
pub fn split(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = text.split('\n').map(|line| line.trim_end_matches('\r').replace('\0', "")).collect();
    if lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    lines
}

/// O começo do boot que contém a linha `index`: a última linha de abertura
/// de boot até ela (0 sem nenhuma).
pub fn boot_start(lines: &[String], index: usize) -> usize {
    if lines.is_empty() {
        return 0;
    }
    let last = index.min(lines.len() - 1);
    lines[..=last].iter().rposition(|line| line.contains(BOOT_MARKER)).unwrap_or(0)
}

/// O fim do boot que contém a linha `index`: a próxima abertura de boot
/// depois dela (ou o fim do log).
pub fn boot_end(lines: &[String], index: usize) -> usize {
    let first = (index + 1).min(lines.len());
    lines[first..].iter().position(|line| line.contains(BOOT_MARKER)).map_or(lines.len(), |offset| first + offset)
}

/// Um número em hexadecimal, com ou sem `0x`.
pub fn hex(text: &str) -> Option<u64> {
    let text = text.trim();
    let digits = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text);
    if digits.is_empty() || digits.len() > 16 {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

/// Um endereço da metade de sistema (bit 47 ligado, forma canônica).
pub fn system_address(address: u64) -> bool {
    address >> 47 == 0x1_FFFF
}

/// Uma imagem de kernel carregada, como o log a mostra.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedImage {
    /// O nome do arquivo (`dxgkrnl.sys`); vazio quando o log não o diz.
    pub name: String,
    /// O caminho como o log o escreve (ou só o nome).
    pub path: String,
    pub base: u64,
    pub size: u64,
    /// A linha `[pe] base=` (índice a partir de 0).
    pub line: usize,
}

impl LoadedImage {
    pub fn contains(&self, address: u64) -> bool {
        address >= self.base && address - self.base < self.size
    }
}

/// O nome de arquivo de imagem no fim de um caminho (`atapi.sys`), se o
/// caminho termina num `.sys`, `.dll` ou `.exe`.
pub fn image_name(path: &str) -> Option<&str> {
    let name = path.trim().rsplit(['\\', '/']).next()?;
    let (stem, extension) = name.rsplit_once('.')?;
    let valid = !stem.is_empty() && stem.chars().all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.'));
    (valid && ["sys", "dll", "exe"].contains(&extension.to_ascii_lowercase().as_str())).then_some(name)
}

/// O caminho de uma linha que anuncia a imagem carregada logo depois: o
/// serviço (`[services] atapi -> \SystemRoot\...\atapi.sys`), a leitura do
/// NTFS (`[ntoskrnl] /dxgkrnl.sys via NTFS (...)`), a validação da CI
/// (`[ci-loader] validating ... bytes=`, `CI_KERNEL_IMAGE_RESULT name=...`)
/// ou o import que ainda não estava carregado (`[pe] imports de X`). Os API
/// sets (`api-...`, `ext-...`) não são imagens.
fn announced_path(line: &str) -> Option<&str> {
    let path = if let Some(rest) = line.strip_prefix("[services] ") {
        rest.split_once(" -> ")?.1
    } else if let Some(rest) = line.strip_prefix("[ntoskrnl] ") {
        rest.split_once(" via NTFS")?.0
    } else if let Some(rest) = line.strip_prefix("[ci-loader] validating ") {
        rest.split_once(" bytes=")?.0
    } else if let Some(rest) = line.strip_prefix("CI_KERNEL_IMAGE_RESULT name=") {
        rest.split_once(" status=")?.0
    } else if let Some(rest) = line.strip_prefix("[pe] imports de ") {
        let lower = rest.trim().to_ascii_lowercase();
        if lower.starts_with("api-") || lower.starts_with("ext-") {
            return None;
        }
        rest
    } else {
        return None;
    };
    image_name(path).map(|_| path.trim())
}

/// `chave=valor` numa linha: o valor até o próximo espaço.
fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("{name}=");
    let start = line.find(&key)? + key.len();
    line[start..].split_whitespace().next()
}

/// As imagens de kernel carregadas nas linhas de `range`, na ordem do log.
///
/// O nome vem da última linha que anunciou uma imagem antes do `[pe] base=`
/// ([`announced_path`]); a HAL, que o log nomeia depois (`[boot] hal.dll
/// carregado`), recebe o nome por essa linha. A imagem do próprio kernel
/// vem do `[mm] kernel PE registrado`. Uma imagem que cobre a faixa de uma
/// anterior (descarregada) a substitui, e uma abertura de boot zera a lista.
pub fn loaded_images(lines: &[String], range: Range<usize>) -> Vec<LoadedImage> {
    let mut images: Vec<LoadedImage> = Vec::new();
    let mut pending: Option<String> = None;
    let mut unnamed: Option<usize> = None;
    for index in range.start..range.end.min(lines.len()) {
        let line = lines[index].as_str();
        if line.contains(BOOT_MARKER) {
            images.clear();
            pending = None;
            unnamed = None;
            continue;
        }
        if let Some(rest) = line.strip_prefix("[pe] base=") {
            let base = rest.split_whitespace().next().and_then(hex);
            let size = field(rest, "imagem").and_then(|text| text.parse::<u64>().ok());
            let path = pending.take().unwrap_or_default();
            unnamed = None;
            if let (Some(base), Some(size)) = (base, size) {
                if system_address(base) && size > 0 {
                    images.retain(|other| other.base >= base.saturating_add(size) || base >= other.base.saturating_add(other.size));
                    let name = image_name(&path).unwrap_or("").to_string();
                    if name.is_empty() {
                        unnamed = Some(images.len());
                    }
                    images.push(LoadedImage { name, path, base, size, line: index });
                }
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("[mm] kernel PE registrado: ") {
            if let (Some(base), Some(size)) = (field(rest, "base").and_then(hex), field(rest, "size").and_then(hex)) {
                images.push(LoadedImage { name: "ntoskrnl.exe".into(), path: "ntoskrnl.exe".into(), base, size, line: index });
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("[boot] ") {
            let mut words = rest.split_whitespace();
            if let (Some(name), Some(verb)) = (words.next(), words.next()) {
                let name = name.trim_end_matches([';', ',']);
                if verb.starts_with("carregado") && image_name(name).is_some() {
                    if let Some(position) = unnamed.take() {
                        images[position].name = name.to_string();
                        images[position].path = name.to_string();
                    }
                }
            }
            continue;
        }
        if let Some(path) = announced_path(line) {
            pending = Some(path.to_string());
        }
    }
    images
}

/// A imagem que contém o endereço (a carregada por último, se mais de uma).
pub fn image_at(images: &[LoadedImage], address: u64) -> Option<&LoadedImage> {
    images.iter().rev().find(|image| image.contains(address))
}

/// A imagem pelo nome do arquivo, sem diferença de caixa.
pub fn image_named<'a>(images: &'a [LoadedImage], name: &str) -> Option<&'a LoadedImage> {
    images.iter().rev().find(|image| image.name.eq_ignore_ascii_case(name))
}

/// O texto de um campo `"nome":"valor"` de uma linha JSON do kernel.
pub fn json_text<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("\"{name}\":\"");
    let start = line.find(&key)? + key.len();
    let length = line[start..].find('"')?;
    Some(&line[start..start + length])
}

/// O número de um campo `"nome":123` de uma linha JSON do kernel.
pub fn json_number(line: &str, name: &str) -> Option<u64> {
    let key = format!("\"{name}\":");
    let start = line.find(&key)? + key.len();
    let digits: String = line[start..].chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Bytes de um texto hexadecimal de tamanho par.
pub fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len()).step_by(2).map(|at| u8::from_str_radix(&text[at..at + 2], 16).ok()).collect()
}

/// Um registro de dados secundários do bugcheck (o que um callback de
/// motivo KbCallbackSecondaryDumpData entregou), remontado dos blocos.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecondaryRecord {
    /// A linha `KERNEL_BUGCHECK_SECONDARY_RECORD`.
    pub line: usize,
    /// O endereço do registro, como o log o escreve (`0xfffff801001c4128`).
    pub record: String,
    /// Os bytes do GUID na ordem da memória (`guidBytes`).
    pub guid: Vec<u8>,
    /// Os bytes; um bloco que falta no log fica zerado.
    pub bytes: Vec<u8>,
    /// Quantos blocos de bytes chegaram.
    pub chunks: usize,
}

/// Os registros de dados secundários nas linhas de `range`, na ordem.
pub fn secondary_records(lines: &[String], range: Range<usize>) -> Vec<SecondaryRecord> {
    let mut records: Vec<SecondaryRecord> = Vec::new();
    for index in range.start..range.end.min(lines.len()) {
        let line = lines[index].as_str();
        if let Some(body) = line.strip_prefix("KERNEL_BUGCHECK_SECONDARY_RECORD ") {
            let (Some(record), Some(length)) = (json_text(body, "record"), json_number(body, "length")) else { continue };
            let guid = json_text(body, "guidBytes").and_then(hex_bytes).unwrap_or_default();
            records.push(SecondaryRecord { line: index, record: record.to_string(), guid, bytes: vec![0; length.min(MAXIMUM_RECORD) as usize], chunks: 0 });
        } else if let Some(body) = line.strip_prefix("KERNEL_BUGCHECK_SECONDARY_BYTES ") {
            let (Some(record), Some(offset), Some(bytes)) = (json_text(body, "record"), json_number(body, "offset"), json_text(body, "bytes").and_then(hex_bytes)) else { continue };
            let Some(target) = records.iter_mut().rev().find(|candidate| candidate.record == record) else { continue };
            let Ok(offset) = usize::try_from(offset) else { continue };
            if offset >= target.bytes.len() {
                continue;
            }
            let end = (offset + bytes.len()).min(target.bytes.len());
            target.bytes[offset..end].copy_from_slice(&bytes[..end - offset]);
            target.chunks += 1;
        }
    }
    records
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &str) -> Vec<String> {
        split(text)
    }

    #[test]
    fn splits_and_finds_boots() {
        let log = lines("lixo\r\nBEAPKGL6[OpenNT] kernel 64-bit vivo (BIOS)\r\na\0b\n[OpenNT] kernel 64-bit vivo\nc\n");
        assert_eq!(log, vec!["lixo", "BEAPKGL6[OpenNT] kernel 64-bit vivo (BIOS)", "ab", "[OpenNT] kernel 64-bit vivo", "c"]);
        assert_eq!(boot_start(&log, 2), 1);
        assert_eq!(boot_start(&log, 4), 3);
        assert_eq!(boot_start(&log, 0), 0);
        assert_eq!(boot_end(&log, 2), 3);
        assert_eq!(boot_end(&log, 3), 5);
        assert_eq!(boot_start(&[], 3), 0);
    }

    #[test]
    fn names_images_by_the_line_that_announced_them() {
        let log = lines(
            "[mm] kernel PE registrado: base=0xfffff80040000000 size=0x11fd000\n\
             [pe] base=0xfffff80100000000 (fisico 0x8632000) imagem=24576 bytes, 4 secoes\n\
             [boot] hal.dll carregado (0 exports, 91 encaminhamentos)\n\
             [services] atapi -> \\SystemRoot\\System32\\Drivers\\atapi.sys\n\
             [pe] base=0xfffff80100010000 (fisico 0x891a000) imagem=53248 bytes, 9 secoes\n\
             [pe] imports de ataport.SYS\n\
             [pe] base=0xfffff80100020000 (fisico 0x8927000) imagem=245760 bytes, 11 secoes\n\
             [pe] imports de HAL.dll\n\
             [pe] imports de ext-ms-win-ntos-werkernel-l1-1-0.dll\n\
             [ntoskrnl] /Windows/System32/DriverStore/FileRepository/x/BasicDisplay.sys via NTFS (68608 bytes, streaming/DMA)\n\
             [pe] base=0xfffff80100a30000 (fisico 0x95c6000) imagem=90112 bytes, 10 secoes\n\
             [ci-loader] validating \\Device\\KernelVolume1\\win32kfull.sys bytes=3809792\n\
             [pe] base=0xfffff92040380000 (fisico 0xc4b9000) imagem=3883008 bytes, 12 secoes\n\
             [pe] base=0x180000000 (fisico 0x1000) imagem=8192 bytes, 2 secoes\n",
        );
        let images = loaded_images(&log, 0..log.len());
        let names: Vec<&str> = images.iter().map(|image| image.name.as_str()).collect();
        assert_eq!(names, ["ntoskrnl.exe", "hal.dll", "atapi.sys", "ataport.SYS", "BasicDisplay.sys", "win32kfull.sys"]);
        assert_eq!(images[4].path, "/Windows/System32/DriverStore/FileRepository/x/BasicDisplay.sys");
        assert_eq!((images[4].base, images[4].size, images[4].line), (0xfffff80100a30000, 90112, 10));
        assert_eq!(image_at(&images, 0xfffff80100a3eb75).map(|image| image.name.as_str()), Some("BasicDisplay.sys"));
        assert_eq!(image_at(&images, 0xfffff80040047afc).map(|image| image.name.as_str()), Some("ntoskrnl.exe"));
        assert!(image_at(&images, 0xfffff80100a30000 + 90112).is_none());
        assert_eq!(image_named(&images, "WIN32KFULL.SYS").map(|image| image.base), Some(0xfffff92040380000));
    }

    #[test]
    fn a_new_image_over_an_old_range_replaces_it_and_a_boot_clears_the_list() {
        let log = lines(
            "[services] a -> \\SystemRoot\\a.sys\n\
             [pe] base=0xfffff80100010000 (fisico 0x1) imagem=8192 bytes, 2 secoes\n\
             [services] b -> \\SystemRoot\\b.sys\n\
             [pe] base=0xfffff80100011000 (fisico 0x2) imagem=4096 bytes, 2 secoes\n",
        );
        let images = loaded_images(&log, 0..log.len());
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].name, "b.sys");
        let log = lines("[services] a -> \\SystemRoot\\a.sys\n[pe] base=0xfffff80100010000 (fisico 0x1) imagem=8192 bytes, 2 secoes\n[OpenNT] kernel 64-bit vivo\n");
        assert!(loaded_images(&log, 0..log.len()).is_empty());
    }

    #[test]
    fn reassembles_secondary_records_from_the_chunks() {
        let log = lines(
            "KERNEL_BUGCHECK_SECONDARY_RECORD {\"record\":\"0xffffa000002fce20\",\"guidBytes\":\"8848c854d1011e4cbed6282c98241303\",\"length\":6}\n\
             KERNEL_BUGCHECK_SECONDARY_RECORD {\"record\":\"0xfffff801001c4128\",\"guidBytes\":\"fd330a27a63d0d46ba893c1bae21e39b\",\"length\":260}\n\
             KERNEL_BUGCHECK_SECONDARY_BYTES {\"record\":\"0xffffa000002fce20\",\"offset\":0,\"bytes\":\"010203040506\"}\n\
             KERNEL_BUGCHECK_SECONDARY_BYTES {\"record\":\"0xfffff801001c4128\",\"offset\":256,\"bytes\":\"aabbccdd\"}\n\
             KERNEL_BUGCHECK_SECONDARY_BYTES {\"record\":\"0xfffff801001c4128\",\"offset\":0,\"bytes\":\"11\"}\n\
             KERNEL_BUGCHECK_SECONDARY_BYTES {\"record\":\"0xfffff801001c4128\",\"offset\":512,\"bytes\":\"ff\"}\n\
             KERNEL_BUGCHECK_SECONDARY_BYTES {\"record\":\"0xfffff801001c4128\",\"offset\":128,\"bytes\":\"abc",
        );
        let records = secondary_records(&log, 0..log.len());
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].bytes, [1, 2, 3, 4, 5, 6]);
        assert_eq!(records[1].guid[..4], [0xfd, 0x33, 0x0a, 0x27]);
        assert_eq!(records[1].bytes.len(), 260);
        assert_eq!(records[1].bytes[0], 0x11);
        assert_eq!(records[1].bytes[256..], [0xaa, 0xbb, 0xcc, 0xdd]);
        // O bloco fora do registro e o bloco cortado não entram.
        assert_eq!(records[1].chunks, 2);
        assert_eq!(records[1].line, 1);
    }

    #[test]
    fn small_parsers() {
        assert_eq!(hex("0x1f"), Some(0x1f));
        assert_eq!(hex("fffff92040469655"), Some(0xfffff92040469655));
        assert_eq!(hex("0x"), None);
        assert_eq!(image_name(r"\Device\KernelVolume1\cdd.dll"), Some("cdd.dll"));
        assert_eq!(image_name("/dxgkrnl.sys"), Some("dxgkrnl.sys"));
        assert_eq!(image_name("arquivo.txt"), None);
        assert_eq!(json_number("{\"offset\":128,\"x\":1}", "offset"), Some(128));
        assert_eq!(json_text("{\"record\":\"0x10\"}", "record"), Some("0x10"));
        assert_eq!(hex_bytes("0aFF"), Some(vec![0x0a, 0xff]));
        assert_eq!(hex_bytes("0a0"), None);
        assert!(system_address(0xfffff80100000000));
        assert!(!system_address(0x180000000));
    }
}
