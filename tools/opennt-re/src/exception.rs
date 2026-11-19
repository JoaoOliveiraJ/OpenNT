//! As exceções de usuário em palavras: o EXCEPTION_RECORD (o código com o
//! nome, as flags, o endereço e o sentido dos parâmetros dos códigos
//! comuns), as exceções guardadas do WinRT (STATUS_STOWED_EXCEPTION, com o
//! HRESULT, a pilha ou o texto de cada STOWED_EXCEPTION_INFORMATION), o
//! código do `__fastfail`, o tipo lançado de uma exceção do C++ (pela
//! ThrowInfo da imagem) e onde achar o registro numa parada (a entrada do
//! RaiseFailFastException, do KiUserExceptionDispatcher, do
//! UnhandledExceptionFilter...).
//!
//! Layouts do x64 (os do winnt.h público):
//! - EXCEPTION_RECORD: código em 0, flags em 4, registro encadeado em 8,
//!   endereço em 0x10, número de parâmetros em 0x18, parâmetros em 0x20 (15
//!   no máximo);
//! - EXCEPTION_POINTERS: o registro em 0 e o CONTEXT em 8;
//! - STOWED_EXCEPTION_INFORMATION_V2: tamanho em 0, assinatura em 4 ('SE01'
//!   ou 'SE02'), HRESULT em 8, a forma (2 bits) e a thread (30 bits) em 0xC,
//!   o endereço da exceção (forma 1) ou o texto (forma 2) em 0x10, o tamanho
//!   da palavra da pilha em 0x18, as palavras em 0x1C, a pilha em 0x20, o
//!   tipo do aninhado em 0x28 e o aninhado em 0x30 (só na V2);
//! - o frame do KiUserExceptionDispatcher: CONTEXT no RSP, CONTEXT_EX em
//!   0x4D0 e o EXCEPTION_RECORD em RSP + 0x4F0 (o mesmo que o kernel do
//!   OpenNT monta em `ps/user/exceptions.rs`);
//! - a ThrowInfo do C++ (x64, por RVA): o vetor de tipos capturáveis em
//!   0xC; o vetor com a contagem em 0 e o primeiro tipo em 4; o tipo com o
//!   TypeDescriptor em 4; o nome decorado em TypeDescriptor + 0x10.
//!
//! A leitura é por `ReadMemory` e os símbolos entram depois
//! (`Report::symbolize`): o backend lê com o cliente e nomeia com os
//! símbolos dele.

use opennt_kd::ntstatus;
use opennt_kd::unwind::ReadMemory;

/// O EXCEPTION_RECORD no frame do KiUserExceptionDispatcher (RSP + 0x4F0).
pub const DISPATCHER_RECORD: u64 = 0x4F0;
const MAX_PARAMETERS: usize = 15;
/// Até onde seguir registros encadeados e exceções aninhadas.
const MAX_DEPTH: usize = 4;

pub const STATUS_BREAKPOINT: u32 = 0x8000_0003;
pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const STATUS_IN_PAGE_ERROR: u32 = 0xC000_0006;
pub const STATUS_STOWED_EXCEPTION: u32 = 0xC000_027B;
pub const STATUS_HEAP_CORRUPTION: u32 = 0xC000_0374;
pub const STATUS_STACK_BUFFER_OVERRUN: u32 = 0xC000_0409;
pub const STATUS_ASSERTION_FAILURE: u32 = 0xC000_0420;
pub const STATUS_FAIL_FAST_EXCEPTION: u32 = 0xC000_0602;
/// A exceção do C++ (`throw`): 0xE0 + 'msc'.
pub const CPP_EXCEPTION: u32 = 0xE06D_7363;
/// O fail-fast do dwmcore (MilFailFastForHR): o HRESULT no parâmetro 0.
pub const MIL_FAIL_FAST: u32 = 0xE046_4645;

const STOWED_V1: u32 = 0x5345_3031; // 'SE01'
const STOWED_V2: u32 = 0x5345_3032; // 'SE02'
const NESTED_WIN32: u32 = 0x5733_3245; // 'W32E'
const NESTED_STOWED: u32 = 0x5354_4F57; // 'STOW'

/// Os códigos de exceção que o ntstatus do opennt-kd não nomeia (ou que
/// têm um sentido próprio aqui).
const CODES: &[(u32, &str)] = &[
    (0x4001_0006, "DBG_PRINTEXCEPTION_C"),
    (0x4001_000A, "DBG_PRINTEXCEPTION_WIDE_C"),
    (0x406D_1388, "MS_VC_EXCEPTION (nome de thread)"),
    (0x8000_0001, "STATUS_GUARD_PAGE_VIOLATION"),
    (0x8000_0002, "STATUS_DATATYPE_MISALIGNMENT"),
    (0x8000_0003, "STATUS_BREAKPOINT"),
    (0x8000_0004, "STATUS_SINGLE_STEP"),
    (0x8000_0029, "STATUS_UNWIND_CONSOLIDATE"),
    (0xC000_0005, "STATUS_ACCESS_VIOLATION"),
    (0xC000_0006, "STATUS_IN_PAGE_ERROR"),
    (0xC000_0008, "STATUS_INVALID_HANDLE"),
    (0xC000_001D, "STATUS_ILLEGAL_INSTRUCTION"),
    (0xC000_0025, "STATUS_NONCONTINUABLE_EXCEPTION"),
    (0xC000_0026, "STATUS_INVALID_DISPOSITION"),
    (0xC000_0028, "STATUS_BAD_STACK"),
    (0xC000_008C, "STATUS_ARRAY_BOUNDS_EXCEEDED"),
    (0xC000_008D, "STATUS_FLOAT_DENORMAL_OPERAND"),
    (0xC000_008E, "STATUS_FLOAT_DIVIDE_BY_ZERO"),
    (0xC000_008F, "STATUS_FLOAT_INEXACT_RESULT"),
    (0xC000_0090, "STATUS_FLOAT_INVALID_OPERATION"),
    (0xC000_0091, "STATUS_FLOAT_OVERFLOW"),
    (0xC000_0092, "STATUS_FLOAT_STACK_CHECK"),
    (0xC000_0093, "STATUS_FLOAT_UNDERFLOW"),
    (0xC000_0094, "STATUS_INTEGER_DIVIDE_BY_ZERO"),
    (0xC000_0095, "STATUS_INTEGER_OVERFLOW"),
    (0xC000_0096, "STATUS_PRIVILEGED_INSTRUCTION"),
    (0xC000_00FD, "STATUS_STACK_OVERFLOW"),
    (0xC000_0135, "STATUS_DLL_NOT_FOUND"),
    (0xC000_0139, "STATUS_ENTRYPOINT_NOT_FOUND"),
    (0xC000_0142, "STATUS_DLL_INIT_FAILED"),
    (0xC000_0194, "STATUS_POSSIBLE_DEADLOCK"),
    (0xC000_027B, "STATUS_STOWED_EXCEPTION"),
    (0xC000_0374, "STATUS_HEAP_CORRUPTION"),
    (0xC000_0409, "STATUS_STACK_BUFFER_OVERRUN"),
    (0xC000_041D, "STATUS_FATAL_USER_CALLBACK_EXCEPTION"),
    (0xC000_0420, "STATUS_ASSERTION_FAILURE"),
    (0xC000_0602, "STATUS_FAIL_FAST_EXCEPTION"),
    (0xE06D_7363, "exceção do C++"),
    (0xE046_4645, "fail-fast do MIL (dwmcore)"),
];

/// HRESULTs comuns na cadeia do logon (COM, WinRT, XAML, DXGI, D2D).
const HRESULTS: &[(u32, &str)] = &[
    (0x0000_0000, "S_OK"),
    (0x0000_0001, "S_FALSE"),
    (0x8000_000B, "E_BOUNDS"),
    (0x8000_000C, "E_CHANGED_STATE"),
    (0x8000_000E, "E_ILLEGAL_METHOD_CALL"),
    (0x8000_0013, "RO_E_CLOSED"),
    (0x8000_0018, "E_ILLEGAL_DELEGATE_ASSIGNMENT"),
    (0x8000_4001, "E_NOTIMPL"),
    (0x8000_4002, "E_NOINTERFACE"),
    (0x8000_4003, "E_POINTER"),
    (0x8000_4004, "E_ABORT"),
    (0x8000_4005, "E_FAIL"),
    (0x8000_FFFF, "E_UNEXPECTED"),
    (0x8001_0106, "RPC_E_CHANGED_MODE"),
    (0x8001_0108, "RPC_E_DISCONNECTED"),
    (0x8001_010E, "RPC_E_WRONG_THREAD"),
    (0x8004_0111, "CLASS_E_CLASSNOTAVAILABLE"),
    (0x8004_0154, "REGDB_E_CLASSNOTREG"),
    (0x8004_01F0, "CO_E_NOTINITIALIZED"),
    (0x8007_0005, "E_ACCESSDENIED"),
    (0x8007_0006, "E_HANDLE"),
    (0x8007_000E, "E_OUTOFMEMORY"),
    (0x8007_0057, "E_INVALIDARG"),
    (0x802B_000A, "E_XAMLPARSEFAILED"),
    (0x887A_0001, "DXGI_ERROR_INVALID_CALL"),
    (0x887A_0004, "DXGI_ERROR_UNSUPPORTED"),
    (0x887A_0005, "DXGI_ERROR_DEVICE_REMOVED"),
    (0x887A_0006, "DXGI_ERROR_DEVICE_HUNG"),
    (0x887A_0007, "DXGI_ERROR_DEVICE_RESET"),
    (0x887A_0020, "DXGI_ERROR_DRIVER_INTERNAL_ERROR"),
    (0x8899_000C, "D2DERR_RECREATE_TARGET"),
];

/// Os erros do Win32 mais vistos dentro de um HRESULT_FROM_WIN32.
const WIN32: &[(u32, &str)] = &[
    (2, "ERROR_FILE_NOT_FOUND"),
    (3, "ERROR_PATH_NOT_FOUND"),
    (5, "ERROR_ACCESS_DENIED"),
    (6, "ERROR_INVALID_HANDLE"),
    (8, "ERROR_NOT_ENOUGH_MEMORY"),
    (31, "ERROR_GEN_FAILURE"),
    (50, "ERROR_NOT_SUPPORTED"),
    (87, "ERROR_INVALID_PARAMETER"),
    (122, "ERROR_INSUFFICIENT_BUFFER"),
    (126, "ERROR_MOD_NOT_FOUND"),
    (127, "ERROR_PROC_NOT_FOUND"),
    (170, "ERROR_BUSY"),
    (259, "ERROR_NO_MORE_ITEMS"),
    (998, "ERROR_NOACCESS"),
    (1008, "ERROR_NO_TOKEN"),
    (1168, "ERROR_NOT_FOUND"),
    (1400, "ERROR_INVALID_WINDOW_HANDLE"),
    (1450, "ERROR_NO_SYSTEM_RESOURCES"),
    (1722, "RPC_S_SERVER_UNAVAILABLE"),
];

/// Os códigos do `__fastfail` (FAST_FAIL_* do winnt.h).
const FAST_FAIL: &[(u64, &str)] = &[
    (0, "FAST_FAIL_LEGACY_GS_VIOLATION"),
    (1, "FAST_FAIL_VTGUARD_CHECK_FAILURE"),
    (2, "FAST_FAIL_STACK_COOKIE_CHECK_FAILURE"),
    (3, "FAST_FAIL_CORRUPT_LIST_ENTRY"),
    (4, "FAST_FAIL_INCORRECT_STACK"),
    (5, "FAST_FAIL_INVALID_ARG"),
    (6, "FAST_FAIL_GS_COOKIE_INIT"),
    (7, "FAST_FAIL_FATAL_APP_EXIT"),
    (8, "FAST_FAIL_RANGE_CHECK_FAILURE"),
    (9, "FAST_FAIL_UNSAFE_REGISTRY_ACCESS"),
    (10, "FAST_FAIL_GUARD_ICALL_CHECK_FAILURE"),
    (11, "FAST_FAIL_GUARD_WRITE_CHECK_FAILURE"),
    (12, "FAST_FAIL_INVALID_FIBER_SWITCH"),
    (13, "FAST_FAIL_INVALID_SET_OF_CONTEXT"),
    (14, "FAST_FAIL_INVALID_REFERENCE_COUNT"),
    (18, "FAST_FAIL_INVALID_JUMP_BUFFER"),
    (19, "FAST_FAIL_MRDATA_MODIFIED"),
    (20, "FAST_FAIL_CERTIFICATION_FAILURE"),
    (21, "FAST_FAIL_INVALID_EXCEPTION_CHAIN"),
    (22, "FAST_FAIL_CRYPTO_LIBRARY"),
    (23, "FAST_FAIL_INVALID_CALL_IN_DLL_CALLOUT"),
    (24, "FAST_FAIL_INVALID_IMAGE_BASE"),
    (25, "FAST_FAIL_DLOAD_PROTECTION_FAILURE"),
    (26, "FAST_FAIL_UNSAFE_EXTENSION_CALL"),
    (27, "FAST_FAIL_DEPRECATED_SERVICE_INVOKED"),
    (28, "FAST_FAIL_INVALID_BUFFER_ACCESS"),
    (29, "FAST_FAIL_INVALID_BALANCED_TREE"),
    (30, "FAST_FAIL_INVALID_NEXT_THREAD"),
    (31, "FAST_FAIL_GUARD_ICALL_CHECK_SUPPRESSED"),
    (32, "FAST_FAIL_APCS_DISABLED"),
    (33, "FAST_FAIL_INVALID_IDLE_STATE"),
    (34, "FAST_FAIL_MRDATA_PROTECTION_FAILURE"),
    (35, "FAST_FAIL_UNEXPECTED_HEAP_EXCEPTION"),
    (36, "FAST_FAIL_INVALID_LOCK_STATE"),
    (37, "FAST_FAIL_GUARD_JUMPTABLE"),
    (38, "FAST_FAIL_INVALID_LONGJUMP_TARGET"),
    (39, "FAST_FAIL_INVALID_DISPATCH_CONTEXT"),
    (40, "FAST_FAIL_INVALID_THREAD"),
    (41, "FAST_FAIL_INVALID_SYSCALL_NUMBER"),
    (42, "FAST_FAIL_INVALID_FILE_OPERATION"),
    (43, "FAST_FAIL_LPAC_ACCESS_DENIED"),
    (44, "FAST_FAIL_GUARD_SS_FAILURE"),
    (45, "FAST_FAIL_LOADER_CONTINUITY_FAILURE"),
    (46, "FAST_FAIL_GUARD_EXPORT_SUPPRESSION_FAILURE"),
    (47, "FAST_FAIL_INVALID_CONTROL_STACK"),
    (48, "FAST_FAIL_SET_CONTEXT_DENIED"),
    (49, "FAST_FAIL_INVALID_IAT"),
    (50, "FAST_FAIL_HEAP_METADATA_CORRUPTION"),
    (51, "FAST_FAIL_PAYLOAD_RESTRICTION_VIOLATION"),
    (52, "FAST_FAIL_LOW_LABEL_ACCESS_DENIED"),
    (53, "FAST_FAIL_ENCLAVE_CALL_FAILURE"),
    (54, "FAST_FAIL_UNHANDLED_LSS_EXCEPTON"),
    (55, "FAST_FAIL_ADMINLESS_ACCESS_DENIED"),
    (56, "FAST_FAIL_UNEXPECTED_CALL"),
    (57, "FAST_FAIL_CONTROL_INVALID_RETURN_ADDRESS"),
    (58, "FAST_FAIL_UNEXPECTED_HOST_BEHAVIOR"),
    (59, "FAST_FAIL_FLAGS_CORRUPTION"),
    (60, "FAST_FAIL_VEH_CORRUPTION"),
    (61, "FAST_FAIL_ETW_CORRUPTION"),
    (62, "FAST_FAIL_RIO_ABORT"),
    (63, "FAST_FAIL_INVALID_PFN"),
];

/// O nome de um código de exceção (o valor em hexadecimal se não houver).
pub fn code_name(code: u32) -> String {
    if let Some((_, name)) = CODES.iter().find(|(value, _)| *value == code) {
        return name.to_string();
    }
    if let Some(name) = ntstatus::name(code) {
        return name.to_string();
    }
    if let Some((_, name)) = HRESULTS.iter().find(|(value, _)| *value == code) {
        return name.to_string();
    }
    format!("{code:#010x}")
}

/// O código com o nome e o valor.
pub fn describe_code(code: u32) -> String {
    let name = code_name(code);
    if name.starts_with("0x") {
        name
    } else {
        format!("{name} ({code:#010x})")
    }
}

/// Um HRESULT em palavras: o nome conhecido, o erro do Win32 de dentro de
/// um HRESULT_FROM_WIN32 ou o NTSTATUS de um HRESULT_FROM_NT.
pub fn hresult_name(hr: u32) -> String {
    if let Some((_, name)) = HRESULTS.iter().find(|(value, _)| *value == hr) {
        return format!("{name} ({hr:#010x})");
    }
    if hr & 0xFFFF_0000 == 0x8007_0000 {
        let code = hr & 0xFFFF;
        return match WIN32.iter().find(|(value, _)| *value == code) {
            Some((_, name)) => format!("HRESULT_FROM_WIN32({name}) ({hr:#010x})"),
            None => format!("HRESULT_FROM_WIN32({code}) ({hr:#010x})"),
        };
    }
    if hr & 0x1000_0000 != 0 && hr >> 30 != 0 {
        return format!("HRESULT_FROM_NT({}) ({hr:#010x})", ntstatus::describe(hr & !0x1000_0000));
    }
    if let Some(name) = ntstatus::name(hr) {
        return format!("{name} ({hr:#010x})");
    }
    format!("{hr:#010x}")
}

/// O nome de um código do `__fastfail`.
pub fn fast_fail_name(code: u64) -> Option<&'static str> {
    FAST_FAIL.iter().find(|(value, _)| *value == code).map(|(_, name)| *name)
}

/// As flags de um EXCEPTION_RECORD com os nomes.
pub fn flags_text(flags: u32) -> String {
    const NAMES: [(u32, &str); 8] = [(0x1, "NONCONTINUABLE"), (0x2, "UNWINDING"), (0x4, "EXIT_UNWIND"), (0x8, "STACK_INVALID"), (0x10, "NESTED_CALL"), (0x20, "TARGET_UNWIND"), (0x40, "COLLIDED_UNWIND"), (0x80, "SOFTWARE_ORIGINATE")];
    let names: Vec<&str> = NAMES.iter().filter(|(bit, _)| flags & bit != 0).map(|(_, name)| *name).collect();
    if names.is_empty() {
        format!("{flags:#x}")
    } else {
        format!("{flags:#x} ({})", names.join(" | "))
    }
}

/// Os quatro caracteres de uma constante como 'SE02' ou 'W32E'.
pub fn fourcc(value: u32) -> String {
    let bytes = value.to_be_bytes();
    if bytes.iter().all(|byte| byte.is_ascii_graphic()) {
        bytes.iter().map(|&byte| byte as char).collect()
    } else {
        format!("{value:#010x}")
    }
}

/// O nome legível de um tipo do C++ decorado no TypeDescriptor
/// (`.?AVhresult_error@winrt@@` vira `winrt::hresult_error`); os nomes com
/// templates ou de tipos simples ficam como estão.
pub fn undecorate_type(name: &str) -> String {
    let Some(body) = name.strip_prefix(".?AV").or_else(|| name.strip_prefix(".?AU")) else { return name.to_string() };
    let Some(body) = body.strip_suffix("@@") else { return name.to_string() };
    if body.contains('?') || body.contains('$') {
        return name.to_string();
    }
    let mut parts: Vec<&str> = body.split('@').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() {
        return name.to_string();
    }
    parts.reverse();
    parts.join("::")
}

fn access_text(kind: u64) -> &'static str {
    match kind {
        0 => "leitura",
        1 => "escrita",
        8 => "execução (DEP)",
        _ => "acesso",
    }
}

fn fail_fast_flags(flags: u64) -> String {
    let mut names = Vec::new();
    if flags & 1 != 0 {
        names.push("FAIL_FAST_GENERATE_EXCEPTION_ADDRESS");
    }
    if flags & 2 != 0 {
        names.push("FAIL_FAST_NO_HARD_ERROR_DLG");
    }
    if names.is_empty() {
        String::new()
    } else {
        format!(" ({})", names.join(" | "))
    }
}

// ---- leitura -----------------------------------------------------------------

fn read_exact(memory: &mut dyn ReadMemory, address: u64, length: usize) -> Result<Vec<u8>, String> {
    let bytes = memory.read(address, length)?;
    if bytes.len() < length {
        return Err(format!("{address:#x}: so {} de {length} bytes legiveis", bytes.len()));
    }
    Ok(bytes)
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    bytes.get(offset..offset + 4).and_then(|slice| slice.try_into().ok()).map_or(0, u32::from_le_bytes)
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    bytes.get(offset..offset + 8).and_then(|slice| slice.try_into().ok()).map_or(0, u64::from_le_bytes)
}

fn read_qword(memory: &mut dyn ReadMemory, address: u64) -> Result<u64, String> {
    read_exact(memory, address, 8).map(|bytes| u64_at(&bytes, 0))
}

/// Uma cadeia UTF-16 terminada em NUL (até `limit` caracteres).
fn read_wide_text(memory: &mut dyn ReadMemory, address: u64, limit: usize) -> Option<String> {
    let mut units: Vec<u16> = Vec::new();
    let mut at = address;
    let mut first = true;
    while units.len() < limit {
        let chunk = match memory.read(at, 0x100) {
            Ok(chunk) => chunk,
            Err(_) if first => return None,
            Err(_) => break,
        };
        first = false;
        if chunk.len() < 2 {
            break;
        }
        for pair in chunk.chunks_exact(2) {
            let unit = u16::from_le_bytes([pair[0], pair[1]]);
            if unit == 0 {
                return Some(String::from_utf16_lossy(&units));
            }
            units.push(unit);
        }
        at += (chunk.len() & !1) as u64;
    }
    Some(String::from_utf16_lossy(&units))
}

// ---- as vistas -----------------------------------------------------------------

/// Um EXCEPTION_RECORD lido e explicado.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordView {
    /// Onde o registro está (0 = montado dos argumentos de uma chamada).
    pub address: u64,
    pub code: u32,
    pub flags: u32,
    pub exception_address: u64,
    /// O símbolo do endereço da exceção (depois, com os símbolos).
    pub symbol: String,
    pub parameters: Vec<u64>,
    /// O que a exceção é, numa linha.
    pub summary: String,
    /// O sentido dos parâmetros conhecidos: (rótulo, valor).
    pub details: Vec<(String, String)>,
    /// As exceções guardadas do WinRT (STATUS_STOWED_EXCEPTION).
    pub stowed: Vec<StowedView>,
    /// O tipo lançado de uma exceção do C++.
    pub thrown_type: Option<String>,
    /// O registro encadeado (ExceptionRecord) e onde ele estava.
    pub chained_address: u64,
    pub chained: Option<Box<RecordView>>,
    /// O que não deu para ler.
    pub notes: Vec<String>,
}

/// Uma STOWED_EXCEPTION_INFORMATION (V1 ou V2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StowedView {
    pub address: u64,
    pub size: u32,
    /// `SE01` ou `SE02`.
    pub signature: String,
    pub result: u32,
    /// 1: endereço e pilha; 2: texto.
    pub form: u32,
    pub thread: u32,
    /// O endereço da exceção e o símbolo dele (forma 1).
    pub exception_address: (u64, String),
    /// A pilha guardada, com os símbolos (forma 1).
    pub stack: Vec<(u64, String)>,
    /// O texto do erro (forma 2).
    pub text: Option<String>,
    pub nested_type: u32,
    pub nested_address: u64,
    pub nested: Option<Nested>,
    pub error: Option<String>,
}

/// A exceção aninhada numa STOWED_EXCEPTION_INFORMATION_V2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Nested {
    /// 'STOW': outra STOWED_EXCEPTION_INFORMATION.
    Stowed(Box<StowedView>),
    /// 'W32E': um EXCEPTION_RECORD do Win32.
    Record(Box<RecordView>),
}

impl RecordView {
    /// Os símbolos dos endereços (o da exceção, os das pilhas guardadas e
    /// os dos registros encadeados).
    pub fn symbolize(&mut self, describe: &dyn Fn(u64) -> String) {
        if self.exception_address != 0 {
            self.symbol = describe(self.exception_address);
        }
        for stowed in &mut self.stowed {
            stowed.symbolize(describe);
        }
        if let Some(chained) = &mut self.chained {
            chained.symbolize(describe);
        }
    }
}

impl StowedView {
    pub fn symbolize(&mut self, describe: &dyn Fn(u64) -> String) {
        if self.exception_address.0 != 0 {
            self.exception_address.1 = describe(self.exception_address.0);
        }
        for (address, name) in &mut self.stack {
            *name = describe(*address);
        }
        match &mut self.nested {
            Some(Nested::Stowed(inner)) => inner.symbolize(describe),
            Some(Nested::Record(inner)) => inner.symbolize(describe),
            None => {}
        }
    }
}

/// Lê um EXCEPTION_RECORD (e os encadeados) e explica o código.
pub fn read_record(memory: &mut dyn ReadMemory, address: u64, depth: usize) -> Result<RecordView, String> {
    let bytes = read_exact(memory, address, 0x20)?;
    let count = u32_at(&bytes, 0x18) as usize;
    let mut view = RecordView { address, code: u32_at(&bytes, 0), flags: u32_at(&bytes, 4), exception_address: u64_at(&bytes, 0x10), chained_address: u64_at(&bytes, 8), ..Default::default() };
    if count > MAX_PARAMETERS {
        view.notes.push(format!("NumberParameters {count} (mais de 15): so os 15 primeiros"));
    }
    let shown = count.min(MAX_PARAMETERS);
    if shown > 0 {
        match read_exact(memory, address + 0x20, shown * 8) {
            Ok(parameters) => view.parameters = (0..shown).map(|index| u64_at(&parameters, index * 8)).collect(),
            Err(error) => view.notes.push(format!("parametros ilegiveis: {error}")),
        }
    }
    explain(memory, &mut view, depth);
    if view.chained_address != 0 {
        if depth >= MAX_DEPTH {
            view.notes.push(format!("registro encadeado em {:#x} (fundo demais)", view.chained_address));
        } else {
            match read_record(memory, view.chained_address, depth + 1) {
                Ok(inner) => view.chained = Some(Box::new(inner)),
                Err(error) => view.notes.push(format!("registro encadeado em {:#x}: {error}", view.chained_address)),
            }
        }
    }
    Ok(view)
}

/// Um registro montado sem ler a memória do registro (os argumentos do
/// RaiseException, o int 0x29 de um `__fastfail`).
pub fn synthetic(memory: &mut dyn ReadMemory, code: u32, flags: u32, address: u64, parameters: Vec<u64>, note: &str) -> RecordView {
    let mut view = RecordView { code, flags, exception_address: address, parameters, ..Default::default() };
    if !note.is_empty() {
        view.notes.push(note.to_string());
    }
    explain(memory, &mut view, 0);
    view
}

/// Os argumentos do RaiseException(código, flags, número, ponteiro), com
/// o endereço de retorno como endereço da exceção.
pub fn from_arguments(memory: &mut dyn ReadMemory, code: u32, flags: u32, count: u64, arguments: u64, caller: u64) -> RecordView {
    let shown = (count as usize).min(MAX_PARAMETERS);
    let mut note = "montado dos argumentos do RaiseException (o registro ainda não existe)".to_string();
    let parameters = if shown > 0 && arguments != 0 {
        match read_exact(memory, arguments, shown * 8) {
            Ok(bytes) => (0..shown).map(|index| u64_at(&bytes, index * 8)).collect(),
            Err(error) => {
                note.push_str(&format!("; argumentos ilegiveis: {error}"));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    synthetic(memory, code, flags, caller, parameters, &note)
}

/// O resumo e o sentido dos parâmetros pelo código.
fn explain(memory: &mut dyn ReadMemory, view: &mut RecordView, depth: usize) {
    let parameters = view.parameters.clone();
    let get = |index: usize| parameters.get(index).copied();
    match view.code {
        STATUS_ACCESS_VIOLATION | STATUS_IN_PAGE_ERROR => {
            let what = if view.code == STATUS_ACCESS_VIOLATION { "violação de acesso" } else { "erro de página (E/S)" };
            match (get(0), get(1)) {
                (Some(kind), Some(target)) => {
                    let null = if target < 0x10000 { " (perto do ponteiro nulo)" } else { "" };
                    view.summary = format!("{what}: {} em {target:#x}{null}", access_text(kind));
                    view.details.push(("tipo de acesso".into(), format!("{kind} ({})", access_text(kind))));
                    view.details.push(("endereço acessado".into(), format!("{target:#x}")));
                    if view.code == STATUS_IN_PAGE_ERROR {
                        if let Some(status) = get(2) {
                            view.details.push(("status da E/S".into(), ntstatus::describe(status as u32)));
                        }
                    }
                }
                _ => view.summary = what.to_string(),
            }
        }
        STATUS_STACK_BUFFER_OVERRUN => match get(0) {
            Some(code) => {
                let name = fast_fail_name(code).unwrap_or("código desconhecido");
                view.summary = format!("__fastfail({code}): {name}");
                view.details.push(("código do __fastfail".into(), format!("{code} ({name})")));
            }
            None => view.summary = "estouro do cookie de pilha (/GS)".into(),
        },
        STATUS_STOWED_EXCEPTION => {
            let (array, count) = (get(0).unwrap_or(0), get(1).unwrap_or(0));
            view.summary = format!("{count} exceção(ões) guardada(s) do WinRT");
            view.details.push(("vetor das STOWED_EXCEPTION_INFORMATION".into(), format!("{array:#x}")));
            view.details.push(("quantas".into(), count.to_string()));
            if array != 0 && count > 0 {
                let count = (count as usize).min(32);
                match read_exact(memory, array, count * 8) {
                    Ok(bytes) => {
                        for index in 0..count {
                            let pointer = u64_at(&bytes, index * 8);
                            view.stowed.push(read_stowed(memory, pointer, depth));
                        }
                    }
                    Err(error) => view.notes.push(format!("vetor das exceções guardadas: {error}")),
                }
            }
        }
        STATUS_FAIL_FAST_EXCEPTION => view.summary = "fail-fast sem registro do chamador (RaiseFailFastException com pExceptionRecord nulo)".into(),
        CPP_EXCEPTION => {
            view.summary = "exceção do C++ (throw)".into();
            if let Some(magic) = get(0) {
                view.details.push(("versão (magic)".into(), format!("{magic:#x}")));
            }
            if let Some(object) = get(1) {
                view.details.push(("objeto lançado".into(), format!("{object:#x}")));
            }
            if let (Some(info), Some(base)) = (get(2), get(3)) {
                view.details.push(("ThrowInfo".into(), format!("{info:#x} (imagem {base:#x})")));
                view.thrown_type = cpp_type_name(memory, info, base);
                if let Some(name) = &view.thrown_type {
                    view.summary = format!("exceção do C++: {name}");
                }
            }
        }
        MIL_FAIL_FAST => match get(0) {
            Some(hr) => {
                view.summary = format!("fail-fast do MIL: {}", hresult_name(hr as u32));
                view.details.push(("HRESULT".into(), hresult_name(hr as u32)));
            }
            None => view.summary = "fail-fast do MIL (dwmcore MilFailFastForHR)".into(),
        },
        STATUS_HEAP_CORRUPTION => view.summary = "corrupção do heap (RtlReportCriticalFailure)".into(),
        STATUS_ASSERTION_FAILURE => view.summary = "falha de asserção (int 0x2C)".into(),
        STATUS_BREAKPOINT => view.summary = "int 3 no código".into(),
        code => view.summary = code_name(code),
    }
}

/// Lê uma STOWED_EXCEPTION_INFORMATION (V1 ou V2) e a aninhada.
pub fn read_stowed(memory: &mut dyn ReadMemory, address: u64, depth: usize) -> StowedView {
    let mut view = StowedView { address, ..Default::default() };
    if address == 0 {
        view.error = Some("ponteiro nulo no vetor".into());
        return view;
    }
    let bytes = match read_exact(memory, address, 0x28) {
        Ok(bytes) => bytes,
        Err(error) => {
            view.error = Some(error);
            return view;
        }
    };
    view.size = u32_at(&bytes, 0);
    let signature = u32_at(&bytes, 4);
    view.signature = fourcc(signature);
    if signature != STOWED_V1 && signature != STOWED_V2 {
        view.error = Some(format!("assinatura {} desconhecida (esperado SE01 ou SE02)", view.signature));
        return view;
    }
    view.result = u32_at(&bytes, 8);
    let packed = u32_at(&bytes, 0xC);
    view.form = packed & 3;
    view.thread = packed >> 2;
    match view.form {
        1 => {
            view.exception_address = (u64_at(&bytes, 0x10), String::new());
            let word = u32_at(&bytes, 0x18) as usize;
            let words = (u32_at(&bytes, 0x1C) as usize).min(64);
            let stack = u64_at(&bytes, 0x20);
            if stack != 0 && words > 0 && (word == 4 || word == 8) {
                match read_exact(memory, stack, words * word) {
                    Ok(raw) => view.stack = (0..words).map(|index| (if word == 8 { u64_at(&raw, index * 8) } else { u32_at(&raw, index * 4) as u64 }, String::new())).collect(),
                    Err(error) => view.error = Some(format!("pilha guardada: {error}")),
                }
            }
        }
        2 => {
            let text = u64_at(&bytes, 0x10);
            if text != 0 {
                view.text = read_wide_text(memory, text, 1024);
            }
        }
        _ => {}
    }
    if signature == STOWED_V2 && view.size >= 0x38 {
        match read_exact(memory, address + 0x28, 0x10) {
            Ok(tail) => {
                view.nested_type = u32_at(&tail, 0);
                view.nested_address = u64_at(&tail, 8);
            }
            Err(error) => view.error = Some(format!("aninhada: {error}")),
        }
        if view.nested_address != 0 && depth < MAX_DEPTH {
            view.nested = match view.nested_type {
                NESTED_STOWED => Some(Nested::Stowed(Box::new(read_stowed(memory, view.nested_address, depth + 1)))),
                NESTED_WIN32 => read_record(memory, view.nested_address, depth + 1).ok().map(|record| Nested::Record(Box::new(record))),
                _ => None,
            };
        }
    }
    view
}

/// O tipo lançado de uma exceção do C++ (o primeiro tipo capturável da
/// ThrowInfo, o mais derivado).
pub fn cpp_type_name(memory: &mut dyn ReadMemory, throw_info: u64, image_base: u64) -> Option<String> {
    if throw_info == 0 || image_base == 0 {
        return None;
    }
    let info = read_exact(memory, throw_info, 0x10).ok()?;
    let array = u32_at(&info, 0xC) as u64;
    if array == 0 {
        return None;
    }
    let header = read_exact(memory, image_base + array, 8).ok()?;
    let count = u32_at(&header, 0);
    if count == 0 || count > 64 {
        return None;
    }
    let catchable = u32_at(&header, 4) as u64;
    let entry = read_exact(memory, image_base + catchable, 8).ok()?;
    let descriptor = u32_at(&entry, 4) as u64;
    let name = memory.read(image_base + descriptor + 0x10, 256).ok()?;
    let end = name.iter().position(|&byte| byte == 0).unwrap_or(name.len());
    let raw = String::from_utf8_lossy(&name[..end]).into_owned();
    if raw.is_empty() {
        None
    } else {
        Some(undecorate_type(&raw))
    }
}

// ---- onde o registro está numa parada ------------------------------------------

/// Onde um ponteiro está na entrada de uma função.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    /// Num registrador (o primeiro argumento é o RCX).
    Register(&'static str),
    /// Um EXCEPTION_POINTERS no registrador: o registro em [r] e o CONTEXT
    /// em [r + 8].
    Pointers(&'static str),
    /// Na pilha: RSP + deslocamento.
    Stack(u64),
    /// Montado dos argumentos do RaiseException.
    RaiseArguments,
}

/// Uma função na entrada da qual o registro de exceção é conhecido.
#[derive(Clone, Copy, Debug)]
pub struct Locator {
    pub symbol: &'static str,
    pub record: Place,
    pub context: Option<Place>,
    pub what: &'static str,
}

impl Locator {
    /// O módulo do símbolo (`KERNELBASE`, `ntdll`).
    pub fn module(&self) -> &'static str {
        self.symbol.split('!').next().unwrap_or("")
    }
}

/// As entradas conhecidas (ntdll e KERNELBASE do 19041).
pub const LOCATORS: &[Locator] = &[
    Locator { symbol: "KERNELBASE!RaiseFailFastException", record: Place::Register("rcx"), context: Some(Place::Register("rdx")), what: "fail-fast (RaiseFailFastException)" },
    Locator { symbol: "ntdll!KiUserExceptionDispatcher", record: Place::Stack(DISPATCHER_RECORD), context: Some(Place::Stack(0)), what: "exceção entregue ao processo (KiUserExceptionDispatcher)" },
    Locator { symbol: "ntdll!RtlDispatchException", record: Place::Register("rcx"), context: Some(Place::Register("rdx")), what: "despacho da exceção (RtlDispatchException)" },
    Locator { symbol: "ntdll!RtlRaiseException", record: Place::Register("rcx"), context: None, what: "exceção lançada por software (RtlRaiseException)" },
    Locator { symbol: "ntdll!NtRaiseException", record: Place::Register("rcx"), context: Some(Place::Register("rdx")), what: "exceção levada ao kernel (NtRaiseException)" },
    Locator { symbol: "ntdll!RtlReportException", record: Place::Register("rcx"), context: Some(Place::Register("rdx")), what: "relatório da exceção (RtlReportException)" },
    Locator { symbol: "KERNELBASE!UnhandledExceptionFilter", record: Place::Pointers("rcx"), context: Some(Place::Pointers("rcx")), what: "exceção não tratada (UnhandledExceptionFilter)" },
    Locator { symbol: "ntdll!RtlUnhandledExceptionFilter2", record: Place::Pointers("rcx"), context: Some(Place::Pointers("rcx")), what: "exceção não tratada (RtlUnhandledExceptionFilter2)" },
    Locator { symbol: "KERNELBASE!RaiseException", record: Place::RaiseArguments, context: None, what: "RaiseException (antes de o registro existir)" },
];

/// O endereço de um ponteiro na entrada (`context`: o CONTEXT de um
/// EXCEPTION_POINTERS, no lugar do registro).
fn resolve(place: Place, registers: &dyn Fn(&str) -> Option<u64>, memory: &mut dyn ReadMemory, context: bool) -> Result<u64, String> {
    match place {
        Place::Register(name) => registers(name).ok_or_else(|| format!("sem o registrador {name}")),
        Place::Pointers(name) => {
            let pointers = registers(name).ok_or_else(|| format!("sem o registrador {name}"))?;
            if pointers == 0 {
                return Err(format!("{name} = 0 (EXCEPTION_POINTERS nulo)"));
            }
            read_qword(memory, pointers + if context { 8 } else { 0 })
        }
        Place::Stack(offset) => registers("rsp").map(|rsp| rsp + offset).ok_or_else(|| "sem o RSP".to_string()),
        Place::RaiseArguments => Err("montado dos argumentos".into()),
    }
}

/// A exceção de uma parada (ou a pedida na aba).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// Como o registro foi achado.
    pub how: String,
    pub record: Result<RecordView, String>,
    /// O CONTEXT do ponto da exceção, quando conhecido.
    pub context: Option<u64>,
    /// A pilha desenrolada do CONTEXT (endereço, símbolo), do backend.
    pub context_stack: Vec<(u64, String)>,
    /// Outras linhas (os flags do RaiseFailFastException, os operandos da
    /// instrução numa parada de primeira chance).
    pub notes: Vec<String>,
    /// Achado sozinho pela parada (senão, pedido na aba).
    pub automatic: bool,
    /// Parada de primeira chance do anel 3, antes da entrega: o registro
    /// ainda não existe.
    pub first_chance: bool,
}

impl Report {
    pub fn new(how: String) -> Report {
        Report { how, record: Err("sem registro".into()), context: None, context_stack: Vec::new(), notes: Vec::new(), automatic: false, first_chance: false }
    }

    pub fn symbolize(&mut self, describe: &dyn Fn(u64) -> String) {
        if let Ok(record) = &mut self.record {
            record.symbolize(describe);
        }
    }
}

/// A exceção de uma parada na entrada de uma das funções de `LOCATORS`.
pub fn report_at(locator: &Locator, registers: &dyn Fn(&str) -> Option<u64>, memory: &mut dyn ReadMemory) -> Report {
    let mut report = Report::new(format!("parada na entrada de {}: {}", locator.symbol, locator.what));
    report.automatic = true;
    let fail_fast = locator.symbol.ends_with("RaiseFailFastException");
    let caller = registers("rsp").and_then(|rsp| read_qword(memory, rsp).ok()).unwrap_or(0);
    report.record = match locator.record {
        Place::RaiseArguments => {
            let get = |name: &str| registers(name).unwrap_or(0);
            let (code, flags, count, arguments) = (get("rcx") as u32, get("rdx") as u32, get("r8"), get("r9"));
            Ok(from_arguments(memory, code, flags, count, arguments, caller))
        }
        place => match resolve(place, registers, memory, false) {
            Ok(0) if fail_fast => Ok(synthetic(memory, STATUS_FAIL_FAST_EXCEPTION, 1, caller, Vec::new(), "pExceptionRecord nulo: o endereço é o retorno da chamada")),
            Ok(0) => Err("o ponteiro do registro é nulo".into()),
            Ok(address) => read_record(memory, address, 0),
            Err(error) => Err(error),
        },
    };
    report.context = locator.context.and_then(|place| resolve(place, registers, memory, true).ok()).filter(|&address| address != 0);
    if fail_fast {
        if let Some(flags) = registers("r8") {
            report.notes.push(format!("dwFlags = {flags:#x}{}", fail_fast_flags(flags)));
        }
    }
    report
}

/// Um registro (ou EXCEPTION_POINTERS) num endereço pedido.
pub fn report_from_address(memory: &mut dyn ReadMemory, address: u64, pointers: bool, how: &str) -> Report {
    let mut report = Report::new(how.to_string());
    if pointers {
        let record = read_qword(memory, address);
        let context = read_qword(memory, address + 8);
        report.record = match record {
            Ok(0) => Err("ExceptionRecord nulo".into()),
            Ok(record) => read_record(memory, record, 0),
            Err(error) => Err(error),
        };
        report.context = context.ok().filter(|&context| context != 0);
    } else {
        report.record = read_record(memory, address, 0);
    }
    report
}

/// Uma parada de primeira chance do anel 3 (`monitor uex on`), antes da
/// entrega: o registro ainda não existe. Um `int 0x29` (`__fastfail`) logo
/// antes do RIP dá o código pelo RCX.
pub fn first_chance(memory: &mut dyn ReadMemory, signal: u8, rip: u64, rcx: u64) -> Report {
    let mut report = Report::new("exceção de primeira chance do anel 3 (uex), antes da entrega ao processo".into());
    report.automatic = true;
    report.first_chance = true;
    let before = memory.read(rip.wrapping_sub(2), 2).unwrap_or_default();
    if signal == 6 && before == [0xCD_u8, 0x29] {
        report.record = Ok(synthetic(memory, STATUS_STACK_BUFFER_OVERRUN, 1, rip.wrapping_sub(2), vec![rcx], "montado do int 0x29 (__fastfail): o código vai no RCX"));
        return report;
    }
    let what = match signal {
        4 => "instrução inválida (#UD)",
        6 => "exceção sem sinal próprio (int 0x29, int 0x2C ou outro vetor)",
        8 => "erro aritmético (#DE, x87 ou SIMD)",
        11 => "falta de página ou de proteção (#PF, #GP, #SS, #AC)",
        _ => "exceção",
    };
    report.record = Err(format!("sinal {signal}: {what}. O EXCEPTION_RECORD é montado na entrega; continue até o ntdll!KiUserExceptionDispatcher para ler o registro."));
    report
}

// ---- os breakpoints prontos ----------------------------------------------------

/// Um breakpoint de um conjunto pronto.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PresetBreakpoint {
    pub expression: &'static str,
    pub condition: &'static str,
    /// Com log e sem condição, o breakpoint só registra.
    pub log: &'static str,
    pub name: &'static str,
}

/// Os conjuntos prontos de breakpoints de exceção (no processo escolhido).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preset {
    FailFast,
    Unhandled,
    Dispatcher,
    ErrorExit,
    RoErrors,
}

const PRESET_FAIL_FAST: &[PresetBreakpoint] = &[PresetBreakpoint { expression: "KERNELBASE!RaiseFailFastException", condition: "", log: "", name: "fail-fast" }];
const PRESET_UNHANDLED: &[PresetBreakpoint] = &[PresetBreakpoint { expression: "KERNELBASE!UnhandledExceptionFilter", condition: "", log: "", name: "exceção não tratada" }];
const PRESET_DISPATCHER: &[PresetBreakpoint] = &[PresetBreakpoint { expression: "ntdll!KiUserExceptionDispatcher", condition: "", log: "", name: "exceção entregue" }];
const PRESET_ERROR_EXIT: &[PresetBreakpoint] = &[PresetBreakpoint { expression: "ntdll!NtTerminateProcess", condition: "(@rdx & 0xffffffff) != 0", log: "", name: "saída com erro" }];
const PRESET_RO_ERRORS: &[PresetBreakpoint] = &[
    PresetBreakpoint { expression: "combase!RoOriginateError", condition: "", log: "RoOriginateError hr={@rcx} de {poi(@rsp):s}", name: "RoOriginateError" },
    PresetBreakpoint { expression: "combase!RoOriginateErrorW", condition: "", log: "RoOriginateErrorW hr={@rcx} de {poi(@rsp):s}", name: "RoOriginateErrorW" },
    PresetBreakpoint { expression: "combase!RoTransformError", condition: "", log: "RoTransformError {@rcx} -> {@rdx} de {poi(@rsp):s}", name: "RoTransformError" },
];

impl Preset {
    pub const ALL: [Preset; 5] = [Preset::FailFast, Preset::Unhandled, Preset::Dispatcher, Preset::ErrorExit, Preset::RoErrors];

    pub fn label(self) -> &'static str {
        match self {
            Preset::FailFast => "fail-fast",
            Preset::Unhandled => "exceção não tratada",
            Preset::Dispatcher => "toda exceção entregue",
            Preset::ErrorExit => "saída com erro",
            Preset::RoErrors => "erros do WinRT (só registra)",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            Preset::FailFast => "KERNELBASE!RaiseFailFastException: o registro (com as exceções guardadas do WinRT) é lido na parada",
            Preset::Unhandled => "KERNELBASE!UnhandledExceptionFilter: a exceção que ninguém tratou",
            Preset::Dispatcher => "ntdll!KiUserExceptionDispatcher: toda exceção entregue ao processo (inclui as do C++ que serão tratadas)",
            Preset::ErrorExit => "ntdll!NtTerminateProcess com status diferente de zero",
            Preset::RoErrors => "combase!RoOriginateError(W) e RoTransformError: uma linha de log por erro, sem parar",
        }
    }

    pub fn breakpoints(self) -> &'static [PresetBreakpoint] {
        match self {
            Preset::FailFast => PRESET_FAIL_FAST,
            Preset::Unhandled => PRESET_UNHANDLED,
            Preset::Dispatcher => PRESET_DISPATCHER,
            Preset::ErrorExit => PRESET_ERROR_EXIT,
            Preset::RoErrors => PRESET_RO_ERRORS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct Memory(HashMap<u64, u8>);

    impl Memory {
        fn put(&mut self, address: u64, bytes: &[u8]) {
            for (index, byte) in bytes.iter().enumerate() {
                self.0.insert(address + index as u64, *byte);
            }
        }

        fn put_u32(&mut self, address: u64, value: u32) {
            self.put(address, &value.to_le_bytes());
        }

        fn put_u64(&mut self, address: u64, value: u64) {
            self.put(address, &value.to_le_bytes());
        }

        fn record(&mut self, address: u64, code: u32, at: u64, chained: u64, parameters: &[u64]) {
            self.put_u32(address, code);
            self.put_u32(address + 4, 0);
            self.put_u64(address + 8, chained);
            self.put_u64(address + 0x10, at);
            self.put_u32(address + 0x18, parameters.len() as u32);
            self.put_u32(address + 0x1C, 0);
            for (index, parameter) in parameters.iter().enumerate() {
                self.put_u64(address + 0x20 + index as u64 * 8, *parameter);
            }
        }

        fn wide(&mut self, address: u64, text: &str) {
            let mut bytes: Vec<u8> = text.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
            bytes.extend_from_slice(&[0, 0]);
            self.put(address, &bytes);
        }
    }

    impl ReadMemory for Memory {
        fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
            let mut bytes = Vec::new();
            for offset in 0..length as u64 {
                match self.0.get(&(address + offset)) {
                    Some(byte) => bytes.push(*byte),
                    None => break,
                }
            }
            if bytes.is_empty() && length > 0 {
                return Err(format!("{address:#x} ilegivel"));
            }
            Ok(bytes)
        }
    }

    fn registers<'a>(values: &'a [(&'static str, u64)]) -> impl Fn(&str) -> Option<u64> + 'a {
        move |name: &str| values.iter().find(|(register, _)| *register == name).map(|(_, value)| *value)
    }

    #[test]
    fn access_violation() {
        let mut memory = Memory::default();
        memory.record(0x1000, STATUS_ACCESS_VIOLATION, 0x7ff6_0000_1234, 0, &[1, 0x10]);
        let mut record = read_record(&mut memory, 0x1000, 0).unwrap();
        assert_eq!(record.code, STATUS_ACCESS_VIOLATION);
        assert_eq!(record.parameters, vec![1, 0x10]);
        assert!(record.summary.contains("escrita em 0x10"), "{}", record.summary);
        assert!(record.summary.contains("nulo"), "{}", record.summary);
        record.symbolize(&|address| format!("mod+{address:#x}"));
        assert_eq!(record.symbol, "mod+0x7ff600001234");
        assert_eq!(describe_code(record.code), "STATUS_ACCESS_VIOLATION (0xc0000005)");
    }

    #[test]
    fn stowed_exceptions() {
        let mut memory = Memory::default();
        memory.record(0x1000, STATUS_STOWED_EXCEPTION, 0x7ff0_0000, 0, &[0x3000, 2]);
        memory.put_u64(0x3000, 0x4000);
        memory.put_u64(0x3008, 0x5000);
        // A primeira: forma 1 (endereço e pilha), thread 0x21c.
        memory.put_u32(0x4000, 0x38);
        memory.put_u32(0x4004, 0x5345_3032);
        memory.put_u32(0x4008, 0x802B_000A);
        memory.put_u32(0x400C, 1 | (0x21c << 2));
        memory.put_u64(0x4010, 0x7ff0_0010);
        memory.put_u32(0x4018, 8);
        memory.put_u32(0x401C, 2);
        memory.put_u64(0x4020, 0x6000);
        memory.put_u64(0x4028, 0);
        memory.put_u64(0x4030, 0);
        memory.put_u64(0x6000, 0x7ff0_0100);
        memory.put_u64(0x6008, 0x7ff0_0200);
        // A segunda: forma 2 (texto), com uma aninhada do tipo STOW.
        memory.put_u32(0x5000, 0x38);
        memory.put_u32(0x5004, 0x5345_3032);
        memory.put_u32(0x5008, 0x8004_0154);
        memory.put_u32(0x500C, 2 | (0x21c << 2));
        memory.put_u64(0x5010, 0x7000);
        memory.put(0x5018, &[0; 0x10]);
        memory.put_u32(0x5028, 0x5354_4F57);
        // O preenchimento entre NestedExceptionType e NestedException.
        memory.put_u32(0x502C, 0);
        memory.put_u64(0x5030, 0x8000);
        memory.wide(0x7000, "classe nao registrada");
        memory.put_u32(0x8000, 0x38);
        memory.put_u32(0x8004, 0x5345_3032);
        memory.put_u32(0x8008, 0x8007_0490);
        memory.put_u32(0x800C, 0);
        memory.put(0x8010, &[0; 0x28]);
        let mut record = read_record(&mut memory, 0x1000, 0).unwrap();
        assert_eq!(record.stowed.len(), 2, "{record:?}");
        let first = &record.stowed[0];
        assert_eq!(first.signature, "SE02");
        assert_eq!(first.result, 0x802B_000A);
        assert_eq!(first.thread, 0x21c);
        assert_eq!(first.form, 1);
        assert_eq!(first.stack.iter().map(|(address, _)| *address).collect::<Vec<_>>(), vec![0x7ff0_0100, 0x7ff0_0200]);
        let second = &record.stowed[1];
        assert_eq!(second.text.as_deref(), Some("classe nao registrada"));
        assert_eq!(fourcc(second.nested_type), "STOW");
        match &second.nested {
            Some(Nested::Stowed(inner)) => assert_eq!(inner.result, 0x8007_0490),
            other => panic!("{other:?}"),
        }
        record.symbolize(&|address| format!("x+{address:#x}"));
        assert_eq!(record.stowed[0].exception_address.1, "x+0x7ff00010");
        assert_eq!(record.stowed[0].stack[1].1, "x+0x7ff00200");
        assert!(hresult_name(0x8004_0154).starts_with("REGDB_E_CLASSNOTREG"));
        assert!(hresult_name(0x802B_000A).starts_with("E_XAMLPARSEFAILED"));
    }

    #[test]
    fn fast_fail_and_names() {
        let mut memory = Memory::default();
        memory.record(0x1000, STATUS_STACK_BUFFER_OVERRUN, 0x7ff0_0000, 0, &[7]);
        let record = read_record(&mut memory, 0x1000, 0).unwrap();
        assert!(record.summary.contains("FAST_FAIL_FATAL_APP_EXIT"), "{}", record.summary);
        assert_eq!(fast_fail_name(10), Some("FAST_FAIL_GUARD_ICALL_CHECK_FAILURE"));
        assert_eq!(fast_fail_name(15), None);
        assert!(hresult_name(0x8007_0490).contains("ERROR_NOT_FOUND"));
        assert!(hresult_name(0x8007_1234).contains("HRESULT_FROM_WIN32(4660)"));
        let nt = hresult_name(0xD000_0005);
        assert!(nt.contains("HRESULT_FROM_NT") && nt.contains("STATUS_ACCESS_VIOLATION"), "{nt}");
        assert_eq!(code_name(STATUS_STOWED_EXCEPTION), "STATUS_STOWED_EXCEPTION");
        assert_eq!(code_name(0x1234_5678), "0x12345678");
        assert_eq!(fourcc(0x5345_3032), "SE02");
        assert_eq!(fourcc(0x0102_0304), "0x01020304");
        assert_eq!(flags_text(1), "0x1 (NONCONTINUABLE)");
        assert_eq!(flags_text(0), "0x0");
    }

    #[test]
    fn cpp_exception_type() {
        let mut memory = Memory::default();
        let base = 0x1_4000_0000u64;
        memory.record(0x1000, CPP_EXCEPTION, base + 0x1234, 0, &[0x1993_0520, 0x9000, base + 0x10000, base]);
        memory.put(base + 0x10000, &[0; 0xC]);
        memory.put_u32(base + 0x1000C, 0x20000);
        memory.put_u32(base + 0x20000, 1);
        memory.put_u32(base + 0x20004, 0x20100);
        memory.put_u32(base + 0x20100, 0);
        memory.put_u32(base + 0x20104, 0x30000);
        memory.put(base + 0x30000, &[0; 0x10]);
        memory.put(base + 0x30010, b".?AVhresult_error@winrt@@\0");
        let record = read_record(&mut memory, 0x1000, 0).unwrap();
        assert_eq!(record.thrown_type.as_deref(), Some("winrt::hresult_error"));
        assert!(record.summary.contains("winrt::hresult_error"));
        assert_eq!(undecorate_type(".?AUFailureInfo@wil@@"), "wil::FailureInfo");
        assert_eq!(undecorate_type(".?AV?$vector@H@std@@"), ".?AV?$vector@H@std@@");
        assert_eq!(undecorate_type(".H"), ".H");
    }

    #[test]
    fn chained_record() {
        let mut memory = Memory::default();
        memory.record(0x1000, STATUS_FAIL_FAST_EXCEPTION, 0x7ff0_0000, 0x2000, &[]);
        memory.record(0x2000, STATUS_ACCESS_VIOLATION, 0x7ff0_0040, 0, &[0, 0x1234_0000]);
        let record = read_record(&mut memory, 0x1000, 0).unwrap();
        assert_eq!(record.chained_address, 0x2000);
        let chained = record.chained.as_ref().expect("encadeado");
        assert!(chained.summary.contains("leitura em 0x12340000"), "{}", chained.summary);
    }

    #[test]
    fn locators() {
        let mut memory = Memory::default();
        // KiUserExceptionDispatcher: o registro em RSP + 0x4F0.
        memory.record(0x9000 + DISPATCHER_RECORD, STATUS_ACCESS_VIOLATION, 0x7ff0_0000, 0, &[8, 0x7ff0_0000]);
        memory.put_u64(0x9000, 0);
        let dispatcher = LOCATORS.iter().find(|locator| locator.symbol.ends_with("KiUserExceptionDispatcher")).unwrap();
        assert_eq!(dispatcher.module(), "ntdll");
        let values = [("rsp", 0x9000u64)];
        let report = report_at(dispatcher, &registers(&values), &mut memory);
        assert!(report.automatic);
        assert_eq!(report.context, Some(0x9000));
        assert!(report.record.as_ref().unwrap().summary.contains("execução"));
        // UnhandledExceptionFilter: um EXCEPTION_POINTERS no RCX.
        memory.record(0x1000, 0xC000_0094, 0x7ff0_0010, 0, &[]);
        memory.put_u64(0xA000, 0x1000);
        memory.put_u64(0xA008, 0xB000);
        let unhandled = LOCATORS.iter().find(|locator| locator.symbol.ends_with("UnhandledExceptionFilter")).unwrap();
        let values = [("rcx", 0xA000u64), ("rsp", 0x9000)];
        let report = report_at(unhandled, &registers(&values), &mut memory);
        assert_eq!(report.record.as_ref().unwrap().code, 0xC000_0094);
        assert_eq!(report.context, Some(0xB000));
        // RaiseFailFastException sem registro: o código próprio e o retorno.
        memory.put_u64(0xC000, 0x7ff0_0abc);
        let fail_fast = LOCATORS.iter().find(|locator| locator.symbol.ends_with("RaiseFailFastException")).unwrap();
        let values = [("rcx", 0u64), ("rdx", 0), ("r8", 2), ("rsp", 0xC000)];
        let report = report_at(fail_fast, &registers(&values), &mut memory);
        let record = report.record.as_ref().unwrap();
        assert_eq!(record.code, STATUS_FAIL_FAST_EXCEPTION);
        assert_eq!(record.exception_address, 0x7ff0_0abc);
        assert!(report.notes.iter().any(|note| note.contains("FAIL_FAST_NO_HARD_ERROR_DLG")));
        // RaiseException: montado dos argumentos.
        memory.put_u64(0xD000, 0x1993_0520);
        let raise = LOCATORS.iter().find(|locator| locator.symbol.ends_with("!RaiseException")).unwrap();
        let values = [("rcx", CPP_EXCEPTION as u64), ("rdx", 1), ("r8", 1), ("r9", 0xD000), ("rsp", 0xC000)];
        let report = report_at(raise, &registers(&values), &mut memory);
        let record = report.record.as_ref().unwrap();
        assert_eq!((record.code, record.parameters.clone(), record.exception_address), (CPP_EXCEPTION, vec![0x1993_0520], 0x7ff0_0abc));
    }

    #[test]
    fn manual_and_first_chance() {
        let mut memory = Memory::default();
        memory.record(0x1000, STATUS_HEAP_CORRUPTION, 0x7ff0_0000, 0, &[]);
        memory.put_u64(0x2000, 0x1000);
        memory.put_u64(0x2008, 0x3000);
        let report = report_from_address(&mut memory, 0x2000, true, "pedido");
        assert_eq!(report.record.as_ref().unwrap().code, STATUS_HEAP_CORRUPTION);
        assert_eq!(report.context, Some(0x3000));
        assert!(report_from_address(&mut memory, 0x5555, false, "pedido").record.is_err());
        // Um int 0x29 logo antes do RIP: o __fastfail com o código no RCX.
        memory.put(0x7ff0_1000, &[0xCD, 0x29]);
        let report = first_chance(&mut memory, 6, 0x7ff0_1002, 5);
        assert!(report.first_chance);
        let record = report.record.as_ref().unwrap();
        assert_eq!(record.exception_address, 0x7ff0_1000);
        assert!(record.summary.contains("FAST_FAIL_INVALID_ARG"), "{}", record.summary);
        let report = first_chance(&mut memory, 11, 0x7ff0_2000, 0);
        assert!(report.record.as_ref().unwrap_err().contains("KiUserExceptionDispatcher"));
    }

    #[test]
    fn presets() {
        for preset in Preset::ALL {
            assert!(!preset.breakpoints().is_empty());
            assert!(preset.breakpoints().iter().all(|breakpoint| breakpoint.expression.contains('!')));
        }
        // Os que só registram não têm condição de parada.
        assert!(Preset::RoErrors.breakpoints().iter().all(|breakpoint| !breakpoint.log.is_empty() && breakpoint.condition.is_empty()));
    }
}
