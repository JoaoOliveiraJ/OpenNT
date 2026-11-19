//! O monitor HMP do QEMU (o `--monitor-port` que o `xtask debug` abre): os
//! snapshots da máquina (`savevm`, `loadvm`, `delvm`, `info snapshots`) e
//! o estado do record/replay (`info replay`). Cada comando abre a conexão,
//! espera o prompt `(qemu)`, manda a linha e lê até o próximo prompt.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// Lê até o prompt `(qemu) ` (ou o prazo).
fn read_prompt(stream: &mut TcpStream, deadline: Instant) -> String {
    let mut text = Vec::new();
    let mut chunk = [0u8; 4096];
    while Instant::now() < deadline {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                text.extend_from_slice(&chunk[..count]);
                if text.ends_with(b"(qemu) ") {
                    break;
                }
            }
            Err(_) => {}
        }
    }
    String::from_utf8_lossy(&text).into_owned()
}

/// Tira os ecos e as sequências de terminal do HMP.
fn clean(text: &str, command: &str) -> String {
    let mut output = String::new();
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\u{1b}' {
            // ESC [ ... letra
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&next) = chars.peek() {
                    chars.next();
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        if character != '\r' {
            output.push(character);
        }
    }
    output
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with("(qemu)") && line != command.trim() && !line.ends_with(command.trim()) && !line.starts_with("QEMU ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Um comando no monitor em `address`; devolve a saída sem o eco.
pub fn command(address: &str, line: &str, timeout: Duration) -> Result<String, String> {
    let mut stream = TcpStream::connect(address).map_err(|error| format!("monitor do QEMU em {address}: {error}"))?;
    stream.set_read_timeout(Some(Duration::from_millis(100))).ok();
    read_prompt(&mut stream, Instant::now() + Duration::from_secs(3));
    stream.write_all(format!("{line}\n").as_bytes()).map_err(|error| format!("monitor do QEMU: {error}"))?;
    let reply = read_prompt(&mut stream, Instant::now() + timeout);
    Ok(clean(&reply, line))
}

/// Um snapshot da máquina (`info snapshots`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub id: String,
    pub tag: String,
    /// O tamanho do estado da máquina, em texto (`12.3 MiB`).
    pub vm_size: String,
    pub date: String,
    pub vm_clock: String,
    pub icount: String,
}

/// A tabela do `info snapshots`.
pub fn parse_snapshots(text: &str) -> Vec<Snapshot> {
    let mut snapshots = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // ID TAG TAMANHO UNIDADE DATA HORA RELOGIO [ICOUNT]
        if fields.len() < 7 || fields[0] == "ID" || !fields[0].chars().all(|character| character.is_ascii_digit() || character == '-') {
            continue;
        }
        let (size, rest) = if fields[3].chars().all(|character| character.is_ascii_alphabetic()) { (format!("{} {}", fields[2], fields[3]), &fields[4..]) } else { (fields[2].to_string(), &fields[3..]) };
        if rest.len() < 3 {
            continue;
        }
        snapshots.push(Snapshot { id: fields[0].to_string(), tag: fields[1].to_string(), vm_size: size, date: format!("{} {}", rest[0], rest[1]), vm_clock: rest[2].to_string(), icount: rest.get(3).unwrap_or(&"").to_string() });
    }
    snapshots
}

/// Um nome de snapshot aceito (letras, dígitos, `-`, `_`, `.`).
pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.chars().all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
}

/// Uma saída do HMP que é erro (o `savevm` e o `loadvm` só respondem em
/// caso de erro).
pub fn error_text(output: &str) -> Option<String> {
    let lower = output.to_ascii_lowercase();
    (lower.contains("error") || lower.contains("erro") || lower.contains("could not") || lower.contains("not supported") || lower.contains("does not support") || lower.contains("unknown command")).then(|| output.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_table() {
        let text = "List of snapshots present on all disks:\nID        TAG               VM SIZE                DATE     VM CLOCK     ICOUNT\n--        antes             12.3 MiB 2026-11-17 10:00:00  00:01:02.345\n--        depois           100 KiB 2026-11-17 10:05:00  00:02:00.000      123456\n";
        let snapshots = parse_snapshots(text);
        assert_eq!(snapshots.len(), 2, "{snapshots:?}");
        assert_eq!(snapshots[0].tag, "antes");
        assert_eq!(snapshots[0].vm_size, "12.3 MiB");
        assert_eq!(snapshots[0].date, "2026-11-17 10:00:00");
        assert_eq!(snapshots[1].icount, "123456");
        assert!(valid_name("passo-1"));
        assert!(!valid_name("com espaco"));
        assert!(error_text("Error: Device 'ide0-hd0' is writable but does not support snapshots").is_some());
        assert!(error_text("").is_none());
        assert_eq!(clean("savevm x\r\n\u{1b}[K(qemu) ", "savevm x"), "");
    }
}
