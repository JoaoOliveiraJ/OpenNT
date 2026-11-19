//! Os códigos de erro do Windows decodificados: NTSTATUS, HRESULT e erros
//! do Win32 (`GetLastError`). Os valores e os nomes são os dos cabeçalhos
//! públicos do SDK (`ntstatus.h`, `winerror.h`); os nomes de NTSTATUS vêm
//! da tabela do `opennt-kd` (`opennt_kd::ntstatus`), a mesma do monitor de
//! APIs.
//!
//! Um número sozinho é ambíguo (`0x80070005` é HRESULT; `0xC0000022` é
//! NTSTATUS; `87` é um erro do Win32), então o resultado traz cada leitura
//! que faz sentido e um resumo (`best`) com a mais provável.

use opennt_kd::ntstatus;
use serde_json::{json, Map, Value};

/// Facilidades do NTSTATUS (bits 16-27).
const NT_FACILITIES: &[(u32, &str)] = &[
    (0x1, "FACILITY_DEBUGGER"),
    (0x2, "FACILITY_RPC_RUNTIME"),
    (0x3, "FACILITY_RPC_STUBS"),
    (0x4, "FACILITY_IO_ERROR_CODE"),
    (0x7, "FACILITY_NTWIN32"),
    (0xA, "FACILITY_TERMINAL_SERVER"),
    (0x13, "FACILITY_CLUSTER_ERROR_CODE"),
    (0x14, "FACILITY_ACPI_ERROR_CODE"),
    (0x15, "FACILITY_SXS_ERROR_CODE"),
    (0x19, "FACILITY_TRANSACTION"),
    (0x1B, "FACILITY_VIDEO"),
    (0x1C, "FACILITY_FILTER_MANAGER"),
    (0x1D, "FACILITY_MONITOR"),
    (0x1E, "FACILITY_GRAPHICS_KERNEL"),
    (0x20, "FACILITY_DRIVER_FRAMEWORK"),
    (0x35, "FACILITY_HYPERVISOR"),
    (0x3E, "FACILITY_WIN32K_NTUSER"),
    (0x3F, "FACILITY_WIN32K_NTGDI"),
    (0xE9, "FACILITY_SYSTEM_INTEGRITY"),
];

/// Facilidades do HRESULT (bits 16-27 sem o bit N).
const HRESULT_FACILITIES: &[(u32, &str)] = &[
    (0x0, "FACILITY_NULL"),
    (0x1, "FACILITY_RPC"),
    (0x2, "FACILITY_DISPATCH"),
    (0x3, "FACILITY_STORAGE"),
    (0x4, "FACILITY_ITF"),
    (0x7, "FACILITY_WIN32"),
    (0x8, "FACILITY_WINDOWS"),
    (0x9, "FACILITY_SECURITY"),
    (0xA, "FACILITY_CONTROL"),
    (0xB, "FACILITY_CERT"),
    (0xC, "FACILITY_INTERNET"),
    (0xD, "FACILITY_MEDIASERVER"),
    (0xE, "FACILITY_MSMQ"),
    (0xF, "FACILITY_SETUPAPI"),
    (0x10, "FACILITY_SCARD"),
    (0x11, "FACILITY_COMPLUS"),
    (0x13, "FACILITY_URT"),
    (0x17, "FACILITY_SXS"),
    (0x19, "FACILITY_HTTP"),
    (0x1A, "FACILITY_USERMODE_COMMONLOG"),
    (0x1F, "FACILITY_USERMODE_FILTER_MANAGER"),
    (0x20, "FACILITY_BACKGROUNDCOPY"),
    (0x21, "FACILITY_CONFIGURATION"),
    (0x24, "FACILITY_WINDOWSUPDATE"),
    (0x25, "FACILITY_DIRECTORYSERVICE"),
    (0x26, "FACILITY_GRAPHICS"),
    (0x27, "FACILITY_SHELL"),
    (0x28, "FACILITY_TPM_SERVICES"),
    (0x29, "FACILITY_TPM_SOFTWARE"),
    (0x31, "FACILITY_FVE"),
    (0x32, "FACILITY_FWP"),
    (0x33, "FACILITY_WINRM"),
    (0x34, "FACILITY_NDIS"),
    (0x35, "FACILITY_USERMODE_HYPERVISOR"),
    (0x36, "FACILITY_CMI"),
    (0x50, "FACILITY_WINDOWS_DEFENDER"),
    (0x879, "FACILITY_DIRECT3D10"),
    (0x87A, "FACILITY_DXGI"),
    (0x87B, "FACILITY_DXGI_DDI"),
    (0x87C, "FACILITY_DIRECT3D11"),
    (0x898, "FACILITY_WINCODEC_DWRITE_DWM"),
    (0x899, "FACILITY_D2D"),
];

/// HRESULTs com nome próprio (os de `HRESULT_FROM_WIN32` saem pelo nome do
/// erro do Win32).
const HRESULT_NAMES: &[(u32, &str)] = &[
    (0x0000_0000, "S_OK"),
    (0x0000_0001, "S_FALSE"),
    (0x8000_000A, "E_PENDING"),
    (0x8000_000B, "E_BOUNDS"),
    (0x8000_000C, "E_CHANGED_STATE"),
    (0x8000_000D, "E_ILLEGAL_STATE_CHANGE"),
    (0x8000_000E, "E_ILLEGAL_METHOD_CALL"),
    (0x8000_0013, "RO_E_CLOSED"),
    (0x8000_4001, "E_NOTIMPL"),
    (0x8000_4002, "E_NOINTERFACE"),
    (0x8000_4003, "E_POINTER"),
    (0x8000_4004, "E_ABORT"),
    (0x8000_4005, "E_FAIL"),
    (0x8000_FFFF, "E_UNEXPECTED"),
    (0x8001_0105, "RPC_E_SERVERFAULT"),
    (0x8001_0106, "RPC_E_CHANGED_MODE"),
    (0x8001_0108, "RPC_E_DISCONNECTED"),
    (0x8001_010E, "RPC_E_WRONG_THREAD"),
    (0x8004_0110, "CLASS_E_NOAGGREGATION"),
    (0x8004_0111, "CLASS_E_CLASSNOTAVAILABLE"),
    (0x8004_0150, "REGDB_E_READREGDB"),
    (0x8004_0154, "REGDB_E_CLASSNOTREG"),
    (0x8004_0155, "REGDB_E_IIDNOTREG"),
    (0x8004_01F0, "CO_E_NOTINITIALIZED"),
    (0x8004_01F1, "CO_E_ALREADYINITIALIZED"),
    (0x8007_0005, "E_ACCESSDENIED"),
    (0x8007_0006, "E_HANDLE"),
    (0x8007_000E, "E_OUTOFMEMORY"),
    (0x8007_0057, "E_INVALIDARG"),
    (0x8008_0005, "CO_E_SERVER_EXEC_FAILURE"),
    (0x887A_0001, "DXGI_ERROR_INVALID_CALL"),
    (0x887A_0002, "DXGI_ERROR_NOT_FOUND"),
    (0x887A_0003, "DXGI_ERROR_MORE_DATA"),
    (0x887A_0004, "DXGI_ERROR_UNSUPPORTED"),
    (0x887A_0005, "DXGI_ERROR_DEVICE_REMOVED"),
    (0x887A_0006, "DXGI_ERROR_DEVICE_HUNG"),
    (0x887A_0007, "DXGI_ERROR_DEVICE_RESET"),
    (0x887A_000A, "DXGI_ERROR_WAS_STILL_DRAWING"),
    (0x887A_0020, "DXGI_ERROR_DRIVER_INTERNAL_ERROR"),
    (0x887A_0022, "DXGI_ERROR_NOT_CURRENTLY_AVAILABLE"),
    (0x8899_000C, "D2DERR_RECREATE_TARGET"),
];

/// Erros do Win32 (decimais, como no `winerror.h`).
const WIN32_NAMES: &[(u32, &str)] = &[
    (0, "ERROR_SUCCESS"),
    (1, "ERROR_INVALID_FUNCTION"),
    (2, "ERROR_FILE_NOT_FOUND"),
    (3, "ERROR_PATH_NOT_FOUND"),
    (4, "ERROR_TOO_MANY_OPEN_FILES"),
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
    (109, "ERROR_BROKEN_PIPE"),
    (120, "ERROR_CALL_NOT_IMPLEMENTED"),
    (122, "ERROR_INSUFFICIENT_BUFFER"),
    (123, "ERROR_INVALID_NAME"),
    (126, "ERROR_MOD_NOT_FOUND"),
    (127, "ERROR_PROC_NOT_FOUND"),
    (161, "ERROR_BAD_PATHNAME"),
    (183, "ERROR_ALREADY_EXISTS"),
    (193, "ERROR_BAD_EXE_FORMAT"),
    (203, "ERROR_ENVVAR_NOT_FOUND"),
    (231, "ERROR_PIPE_BUSY"),
    (232, "ERROR_NO_DATA"),
    (233, "ERROR_PIPE_NOT_CONNECTED"),
    (234, "ERROR_MORE_DATA"),
    (258, "WAIT_TIMEOUT"),
    (259, "ERROR_NO_MORE_ITEMS"),
    (299, "ERROR_PARTIAL_COPY"),
    (487, "ERROR_INVALID_ADDRESS"),
    (535, "ERROR_PIPE_CONNECTED"),
    (997, "ERROR_IO_PENDING"),
    (998, "ERROR_NOACCESS"),
    (1008, "ERROR_NO_TOKEN"),
    (1009, "ERROR_BADDB"),
    (1010, "ERROR_BADKEY"),
    (1011, "ERROR_CANTOPEN"),
    (1012, "ERROR_CANTREAD"),
    (1013, "ERROR_CANTWRITE"),
    (1015, "ERROR_REGISTRY_CORRUPT"),
    (1053, "ERROR_SERVICE_REQUEST_TIMEOUT"),
    (1056, "ERROR_SERVICE_ALREADY_RUNNING"),
    (1058, "ERROR_SERVICE_DISABLED"),
    (1060, "ERROR_SERVICE_DOES_NOT_EXIST"),
    (1062, "ERROR_SERVICE_NOT_ACTIVE"),
    (1114, "ERROR_DLL_INIT_FAILED"),
    (1168, "ERROR_NOT_FOUND"),
    (1312, "ERROR_NO_SUCH_LOGON_SESSION"),
    (1314, "ERROR_PRIVILEGE_NOT_HELD"),
    (1326, "ERROR_LOGON_FAILURE"),
    (1332, "ERROR_NONE_MAPPED"),
    (1400, "ERROR_INVALID_WINDOW_HANDLE"),
    (1401, "ERROR_INVALID_MENU_HANDLE"),
    (1402, "ERROR_INVALID_CURSOR_HANDLE"),
    (1407, "ERROR_CANNOT_FIND_WND_CLASS"),
    (1410, "ERROR_CLASS_ALREADY_EXISTS"),
    (1411, "ERROR_CLASS_DOES_NOT_EXIST"),
    (1412, "ERROR_CLASS_HAS_WINDOWS"),
    (1413, "ERROR_INVALID_INDEX"),
    (1444, "ERROR_INVALID_THREAD_ID"),
    (1460, "ERROR_TIMEOUT"),
    (1702, "RPC_S_INVALID_BINDING"),
    (1717, "RPC_S_UNKNOWN_IF"),
    (1722, "RPC_S_SERVER_UNAVAILABLE"),
    (1723, "RPC_S_SERVER_TOO_BUSY"),
    (1726, "RPC_S_CALL_FAILED"),
    (1727, "RPC_S_CALL_FAILED_DNE"),
    (1753, "EPT_S_NOT_REGISTERED"),
    (4317, "ERROR_INVALID_OPERATION"),
    (5023, "ERROR_INVALID_STATE"),
];

fn find(table: &[(u32, &'static str)], value: u32) -> Option<&'static str> {
    table.iter().find(|(code, _)| *code == value).map(|(_, name)| *name)
}

/// O nome de um erro do Win32, se conhecido.
pub fn win32_name(code: u32) -> Option<&'static str> {
    find(WIN32_NAMES, code)
}

/// O nome de um HRESULT, se conhecido.
pub fn hresult_name(value: u32) -> Option<&'static str> {
    find(HRESULT_NAMES, value)
}

fn facility_text(table: &[(u32, &'static str)], facility: u32) -> String {
    match find(table, facility) {
        Some(name) => format!("{facility:#x} {name}"),
        None => format!("{facility:#x}"),
    }
}

fn severity_name(severity: u32) -> &'static str {
    match severity {
        0 => "sucesso",
        1 => "informativo",
        2 => "aviso",
        _ => "erro",
    }
}

/// Lê um código: `0x80070005`, `C0000034` (hexadecimal com letras), `87`
/// (só dígitos: decimal), `-1073741790` (decimal negativo, um NTSTATUS
/// impresso como inteiro com sinal) ou 64 bits com o sinal estendido
/// (`0xffffffffc0000034`).
pub fn parse_code(text: &str) -> Result<u32, String> {
    let cleaned = text.trim().replace(['`', '_'], "");
    if let Some(negative) = cleaned.strip_prefix('-') {
        let number: i64 = negative.trim().parse().map_err(|_| format!("{text}: numero invalido"))?;
        return Ok((-number) as i32 as u32);
    }
    let lower = cleaned.to_ascii_lowercase();
    let parsed = if let Some(digits) = lower.strip_prefix("0x") {
        u64::from_str_radix(digits, 16)
    } else if !lower.is_empty() && lower.chars().all(|character| character.is_ascii_digit()) {
        lower.parse::<u64>()
    } else {
        u64::from_str_radix(lower.trim_end_matches('h'), 16)
    };
    let value = parsed.map_err(|_| format!("{text}: codigo invalido (0x..., hexadecimal ou decimal)"))?;
    if value > u32::MAX as u64 && value >> 32 != 0xFFFF_FFFF {
        return Err(format!("{text}: maior que 32 bits"));
    }
    Ok(value as u32)
}

/// As leituras de um código e o resumo.
pub fn decode(value: u32) -> Value {
    let mut result = Map::new();
    result.insert("value".into(), json!(format!("{value:#010x}")));
    let mut best: Option<String> = None;
    if value < 0x1_0000 {
        // Pequeno: erro do Win32 (ou um NTSTATUS de sucesso, como
        // STATUS_PENDING = 0x103).
        let win32 = win32_name(value);
        result.insert("win32".into(), json!({"code": value, "name": win32}));
        if let Some(name) = hresult_name(value) {
            best = Some(format!("{name} (HRESULT)"));
        }
        if let Some(name) = win32 {
            best.get_or_insert_with(|| format!("{name} ({value}, erro do Win32)"));
        }
        if let Some(name) = ntstatus::name(value) {
            result.insert("ntstatus".into(), json!({"name": name}));
            best.get_or_insert_with(|| format!("{name} (NTSTATUS)"));
        }
    } else {
        let severity = value >> 30;
        let n_bit = value & 0x1000_0000 != 0;
        let without_n = value & !0x1000_0000;
        let nt_facility = (value >> 16) & 0xFFF;
        let nt_name = ntstatus::name(value).or_else(|| if n_bit { ntstatus::name(without_n) } else { None });
        let mut nt = json!({
            "severity": severity_name(severity),
            "customer": value & 0x2000_0000 != 0,
            "facility": facility_text(NT_FACILITIES, nt_facility),
            "code": format!("{:#x}", value & 0xFFFF),
            "name": nt_name,
        });
        if n_bit && ntstatus::name(value).is_none() {
            nt["note"] = json!(format!("com o bit 0x10000000 (HRESULT_FROM_NT, ou HARDERROR_OVERRIDE_ERRORMODE no NtRaiseHardError): {}", ntstatus::describe(without_n)));
        }
        let mut nt_win32 = None;
        if nt_facility == 7 && severity == 3 {
            let code = value & 0xFFFF;
            nt["win32"] = json!({"code": code, "name": win32_name(code)});
            nt_win32 = win32_name(code).map(|name| format!("NTSTATUS_FROM_WIN32({name} = {code})"));
        }
        result.insert("ntstatus".into(), nt);
        if value & 0x8000_0000 != 0 {
            let mut hresult = Map::new();
            let name = hresult_name(value);
            hresult.insert("name".into(), json!(name));
            if n_bit {
                // HRESULT_FROM_NT: o NTSTATUS com o bit N.
                hresult.insert("from_nt".into(), json!(ntstatus::describe(without_n)));
                if let Some(name) = name {
                    best = Some(format!("{name} (HRESULT)"));
                } else if let Some(status) = ntstatus::name(without_n) {
                    best = Some(format!("HRESULT_FROM_NT({status})"));
                }
            } else {
                let facility = (value >> 16) & 0xFFF;
                let code = value & 0xFFFF;
                hresult.insert("facility".into(), json!(facility_text(HRESULT_FACILITIES, facility)));
                hresult.insert("code".into(), json!(format!("{code:#x}")));
                if let Some(name) = name {
                    best = Some(format!("{name} (HRESULT)"));
                }
                if facility == 7 {
                    hresult.insert("win32".into(), json!({"code": code, "name": win32_name(code)}));
                    if let Some(win32) = win32_name(code) {
                        best.get_or_insert_with(|| format!("HRESULT_FROM_WIN32({win32} = {code})"));
                    } else {
                        best.get_or_insert_with(|| format!("HRESULT_FROM_WIN32({code})"));
                    }
                }
            }
            result.insert("hresult".into(), Value::Object(hresult));
        }
        if let Some(name) = nt_name {
            best.get_or_insert_with(|| format!("{name} (NTSTATUS)"));
        }
        if let Some(text) = nt_win32 {
            best.get_or_insert(text);
        }
        if best.is_none() {
            best = Some(if value & 0x8000_0000 != 0 {
                format!("desconhecido: NTSTATUS de {} da facilidade {:#x}, ou HRESULT da facilidade {:#x}, codigo {:#x}", severity_name(severity), nt_facility, (value >> 16) & 0xFFF, value & 0xFFFF)
            } else {
                format!("desconhecido: NTSTATUS {} da facilidade {:#x}, codigo {:#x}", severity_name(severity), nt_facility, value & 0xFFFF)
            });
        }
    }
    result.insert("best".into(), json!(best.unwrap_or_else(|| format!("{value:#x}: sem nome conhecido"))));
    Value::Object(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_codes() {
        assert_eq!(parse_code("0x80070578"), Ok(0x8007_0578));
        assert_eq!(parse_code("C0000034"), Ok(0xC000_0034));
        assert_eq!(parse_code("87"), Ok(87));
        assert_eq!(parse_code("-1073741790"), Ok(0xC000_0022));
        assert_eq!(parse_code("0xffffffffc0000034"), Ok(0xC000_0034));
        assert_eq!(parse_code("0xfffff800`00000000").map_err(|error| error.contains("32 bits")), Err(true));
        assert!(parse_code("xyz").is_err());
        assert!(parse_code("").is_err());
    }

    #[test]
    fn decodes_hresults_ntstatus_and_win32() {
        // HRESULT_FROM_WIN32(ERROR_INVALID_WINDOW_HANDLE): a falha do dwm.
        let value = decode(0x8007_0578);
        assert_eq!(value["best"], "HRESULT_FROM_WIN32(ERROR_INVALID_WINDOW_HANDLE = 1400)");
        assert_eq!(value["hresult"]["facility"], "0x7 FACILITY_WIN32");
        assert_eq!(value["hresult"]["win32"]["code"], 1400);
        let value = decode(0xC000_0034);
        assert_eq!(value["best"], "STATUS_OBJECT_NAME_NOT_FOUND (NTSTATUS)");
        assert_eq!(value["ntstatus"]["severity"], "erro");
        // O fail fast do LogonUI pelo NtRaiseHardError.
        let value = decode(0xD000_0409);
        assert_eq!(value["best"], "HRESULT_FROM_NT(STATUS_STACK_BUFFER_OVERRUN)");
        assert!(value["ntstatus"]["note"].as_str().unwrap().contains("STATUS_STACK_BUFFER_OVERRUN"));
        assert_eq!(decode(87)["best"], "ERROR_INVALID_PARAMETER (87, erro do Win32)");
        assert_eq!(decode(0x8000_4002)["best"], "E_NOINTERFACE (HRESULT)");
        assert_eq!(decode(0x887A_0005)["hresult"]["facility"], "0x87a FACILITY_DXGI");
        assert_eq!(decode(0)["best"], "S_OK (HRESULT)");
        // STATUS_PENDING também é ERROR_NO_MORE_ITEMS em decimal (259).
        let value = decode(0x103);
        assert_eq!(value["ntstatus"]["name"], "STATUS_PENDING");
        assert_eq!(value["win32"]["name"], "ERROR_NO_MORE_ITEMS");
        assert!(decode(0xC0AB_1234)["best"].as_str().unwrap().starts_with("desconhecido"));
    }
}
