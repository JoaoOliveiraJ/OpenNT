//! Os autologgers do Registro: as sessões de `Control\WMI\Autologger` que o
//! kernel inicia no boot, como o EtwpInitializeAutoLoggers do ntoskrnl 19041
//! (rva 0x795d64, chamado pelo EtwInitializeSiloState na fase 1).
//!
//! - EtwpEnumerateAutologgerPath (0x7960d4): cada subchave é uma sessão, com
//!   o nome da subchave como LoggerName.
//! - EtwStartAutoLogger (0x796344): Start diferente de zero inicia a sessão;
//!   BufferSize, MinimumBuffers, MaximumBuffers, MaxFileSize, LogFileMode,
//!   FlushTimer, ClockType e Guid montam o WMI_LOGGER_INFORMATION (sem Guid,
//!   ou com um texto que o RtlGUIDFromString recusa,
//!   STATUS_INVALID_PARAMETER) e o resultado vai para o valor Status da
//!   chave (RtlNtStatusToDosError). Uma chave com Start zero não ganha
//!   Status. O OpenNT não grava o arquivo da sessão (FileName) nem o
//!   RtBackup das sessões de tempo real: os buffers ficam na memória
//!   (`logger`).
//! - EtwpEnableKeyProviders/EtwpEnableAutoLoggerProvider (0x797e78): cada
//!   subchave da sessão com o GUID de um provedor no nome e Enabled
//!   diferente de zero é habilitada com EnableLevel, MatchAnyKeyword (o
//!   EnableFlags quando o MatchAnyKeyword é zero), MatchAllKeyword e
//!   EnableProperty, e o Status dela fica zero.
//!
//! Assim, no boot da cadeia, a sessão EventLog-System habilita o provedor do
//! Service Control Manager antes de o services.exe registrá-lo, e os
//! eventos dele chegam à sessão como num Windows recém-instalado.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::logger::{self, SessionSettings};
use crate::ntos::cm::registry;

/// `Control\WMI\Autologger` do conjunto de controle corrente.
pub const AUTOLOGGER_PATH: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\WMI\\Autologger";

const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_DWORD: u32 = 4;
const REG_QWORD: u32 = 11;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// EtwpInitializeAutoLoggers: as sessões do Registro, uma vez no boot.
pub fn initialize() {
    let started = start_all(AUTOLOGGER_PATH);
    if started != 0 {
        crate::debug_print!("[etw] autologgers do Registro iniciados: {}", started);
    }
}

/// EtwpEnumerateAutologgerPath: as sessões das subchaves de `path`;
/// devolve quantas começaram.
pub fn start_all(path: &str) -> usize {
    registry::list_keys(path).iter().filter(|name| start(path, name).is_ok()).count()
}

fn dword(key: &str, name: &str) -> Option<u32> {
    let value = registry::read_value_by_path(key, name)?;
    (value.value_type == REG_DWORD && value.data.len() >= 4).then(|| u32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]]))
}

/// Um REG_QWORD (ou um REG_DWORD, estendido).
fn qword(key: &str, name: &str) -> Option<u64> {
    let value = registry::read_value_by_path(key, name)?;
    match value.value_type {
        REG_QWORD if value.data.len() >= 8 => Some(u64::from_le_bytes(value.data[0..8].try_into().unwrap())),
        REG_DWORD if value.data.len() >= 4 => Some(u32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]]) as u64),
        _ => None,
    }
}

/// Um REG_SZ ou REG_EXPAND_SZ, até o primeiro NUL.
fn string(key: &str, name: &str) -> Option<String> {
    let value = registry::read_value_by_path(key, name)?;
    if value.value_type != REG_SZ && value.value_type != REG_EXPAND_SZ {
        return None;
    }
    let units: Vec<u16> = value.data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
    Some(String::from_utf16_lossy(&units))
}

/// O valor Status (REG_DWORD) que o RtlWriteRegistryValue grava na chave.
fn write_status(key: &str, status: u32) {
    if let Some(node) = registry::node_by_path(key) {
        registry::set_node_value(node, key, "Status", REG_DWORD, status.to_le_bytes().to_vec());
    }
}

/// EtwStartAutoLogger da sessão `name` de `path`: Ok(LoggerId) ou o
/// status (Err(0) para Start zero, sem Status gravado).
pub fn start(path: &str, name: &str) -> Result<u16, u32> {
    let key = format!("{path}\\{name}");
    if dword(&key, "Start").unwrap_or(0) == 0 {
        return Err(0);
    }
    let result = start_session(&key, name);
    let status = result.err().unwrap_or(0);
    write_status(&key, crate::ntos::rtl::error::status_to_dos_error(status));
    let logger_id = result?;
    for provider in registry::list_keys(&key) {
        enable_provider(&key, &provider, logger_id);
    }
    Ok(logger_id)
}

fn start_session(key: &str, name: &str) -> Result<u16, u32> {
    let guid = string(key, "Guid").and_then(|text| crate::ntos::em::database::guid_from_text(&text)).ok_or(STATUS_INVALID_PARAMETER)?;
    let value = |name: &str| dword(key, name).unwrap_or(0);
    logger::start_session(&SessionSettings {
        name,
        guid,
        clock: value("ClockType"),
        buffer_size: value("BufferSize"),
        minimum_buffers: value("MinimumBuffers"),
        maximum_buffers: value("MaximumBuffers"),
        maximum_file_size: value("MaxFileSize"),
        log_file_mode: value("LogFileMode"),
        flush_timer: value("FlushTimer"),
    })
}

/// EtwpEnableAutoLoggerProvider: a subchave `name` (o GUID do provedor) da
/// sessão em `key`.
fn enable_provider(key: &str, name: &str, logger_id: u16) {
    let provider_key = format!("{key}\\{name}");
    if dword(&provider_key, "Enabled").unwrap_or(0) == 0 {
        return;
    }
    let Some(guid) = crate::ntos::em::database::guid_from_text(name) else { return };
    let level = dword(&provider_key, "EnableLevel").unwrap_or(0) as u8;
    let property = dword(&provider_key, "EnableProperty").unwrap_or(0);
    let any_keyword = match qword(&provider_key, "MatchAnyKeyword").unwrap_or(0) {
        0 => dword(&provider_key, "EnableFlags").unwrap_or(0) as u64,
        keyword => keyword,
    };
    let all_keyword = qword(&provider_key, "MatchAllKeyword").unwrap_or(0);
    if matches!(logger::enable_provider_options(logger_id, guid, level, any_keyword, all_keyword, property), Ok(0)) {
        write_status(&provider_key, 0);
    }
}
