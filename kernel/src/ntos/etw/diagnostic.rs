//! Diagnóstico na serial dos eventos ETW de alguns provedores. Só imprime:
//! o convidado vê a mesma coisa com ou sem ele.
//!
//! - Service Control Manager ({555908d1-a6d7-4695-8e1e-26931d2012f4}, o
//!   provedor do services.exe): cada evento que alguma sessão aceita (no
//!   boot da cadeia, a EventLog-System do autologger, que habilita o
//!   provedor como num Windows recém-instalado) sai como
//!   `[scm] evento <Id> <dados>`. Os eventos 7000-7045 do services.exe são
//!   clássicos (o ScLogEvent grava pelo EvtIntReportEventAndSourceAsync da
//!   ntdll, descritor com Id 0): o Id sai do EventID do evento e os dados são
//!   as cadeias de inserção. Num evento de manifesto, um segmento por campo:
//!   os UTF-16 terminados em NUL como texto, os de 4 e 8 bytes em
//!   hexadecimal (os códigos de erro), os outros UTF-16 entre colchetes e o
//!   resto pelo tamanho. Os ids que contam: 7000 (o serviço não iniciou, com
//!   o erro), 7001 (dependência), 7009 e 7011 (prazos), 7022 (travado
//!   iniciando), 7023 e 7024 (terminou com erro), 7031 e 7034 (terminou
//!   inesperadamente), 7036 (entrou no estado), 7038 e 7041 (logon da
//!   conta), 7043 e 7045.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::provider_state::Event;
use crate::rtl::SpinLock;

/// {555908d1-a6d7-4695-8e1e-26931d2012f4}.
const SERVICE_CONTROL_MANAGER: [u8; 16] = [0xD1, 0x08, 0x59, 0x55, 0xD7, 0xA6, 0x95, 0x46, 0x8E, 0x1E, 0x26, 0x93, 0x1D, 0x20, 0x12, 0xF4];

/// A última linha `[scm]` (sem o prefixo), para os autotestes.
static LAST_SCM: SpinLock<Option<String>> = SpinLock::new(None);

/// Um evento que alguma sessão aceitou (`provider_state::deliver`).
pub fn observe(event: &Event) {
    if event.provider == SERVICE_CONTROL_MANAGER {
        service_control_manager(event);
    }
}

fn service_control_manager(event: &Event) {
    let id = u16::from_le_bytes([event.descriptor[0], event.descriptor[1]]);
    let classic = if id == 0 { classic(event) } else { None };
    let line = classic.unwrap_or_else(|| {
        let mut line = format!("evento {id}");
        for (index, segment) in event.data.iter().enumerate() {
            line.push_str(if index == 0 { " " } else { " / " });
            line.push_str(&describe(segment));
        }
        line
    });
    crate::debug_print!("[scm] {}", line);
    *LAST_SCM.lock() = Some(line);
}

/// O evento clássico pelo ETW, como o EvtIntReportEventWorker da ntdll o
/// grava (o ScLogEvent do services.exe chega a ele pelo
/// EvtIntReportEventAndSourceAsync): o descritor com Id 0 e os campos
/// TimeStamp (8 bytes, a hora do sistema), EventID (4, os qualificadores
/// no alto), o tamanho do nome da fonte em caracteres com o NUL (2), o
/// nome, o tamanho do SID (2), o SID quando o tamanho não é zero,
/// NumStrings (2), as cadeias com o NUL, DataSize (4) e os dados. A linha
/// leva o id sem os qualificadores e as cadeias de inserção (`%%N` é uma
/// mensagem do sistema, o erro N).
fn classic(event: &Event) -> Option<String> {
    let data = &event.data;
    if data.len() < 6 || data[0].len() != 8 || data[1].len() != 4 {
        return None;
    }
    let word = |segment: &[u8]| (segment.len() == 2).then(|| u16::from_le_bytes([segment[0], segment[1]]));
    let event_id = u32::from_le_bytes([data[1][0], data[1][1], data[1][2], data[1][3]]);
    word(&data[2])?;
    let sid_length = word(data.get(4)?)?;
    let count_index = if sid_length != 0 { 6 } else { 5 };
    let count = word(data.get(count_index)?)? as usize;
    let first = count_index + 1;
    let strings: Vec<String> = data.get(first..first + count)?.iter().map(|segment| unicode(segment)).collect();
    Some(format!("evento {} {}", event_id & 0xFFFF, strings.join(" / ")))
}

/// Uma cadeia UTF-16 até o NUL (uma cadeia de inserção do evento clássico).
fn unicode(segment: &[u8]) -> String {
    let units: Vec<u16> = segment.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
    String::from_utf16_lossy(&units)
}

/// A última linha `[scm]` impressa.
pub fn last_scm_line() -> Option<String> {
    LAST_SCM.lock().clone()
}

fn units(segment: &[u8]) -> Option<Vec<u16>> {
    (segment.len() >= 2 && segment.len() % 2 == 0).then(|| segment.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect())
}

/// Texto UTF-16 de pelo menos dois caracteres, sem NUL nem controle.
fn text(units: &[u16]) -> Option<String> {
    if units.len() < 2 || units.contains(&0) {
        return None;
    }
    let text = String::from_utf16(units).ok()?;
    (!text.chars().any(char::is_control)).then_some(text)
}

/// Um campo do evento: o UnicodeString terminado em NUL como texto, os
/// inteiros de 4 e 8 bytes em hexadecimal, um binário em UTF-16 entre
/// colchetes e o resto pelo tamanho.
fn describe(segment: &[u8]) -> String {
    let decoded = units(segment);
    if let Some((&0, body)) = decoded.as_deref().and_then(<[u16]>::split_last) {
        if let Some(text) = text(body) {
            return text;
        }
    }
    match segment.len() {
        4 => return format!("{:#x}", u32::from_le_bytes([segment[0], segment[1], segment[2], segment[3]])),
        8 => return format!("{:#x}", u64::from_le_bytes(segment.try_into().unwrap_or([0; 8]))),
        _ => {}
    }
    match decoded.as_deref().and_then(text) {
        Some(text) => format!("[{text}]"),
        None => format!("<{} bytes>", segment.len()),
    }
}
