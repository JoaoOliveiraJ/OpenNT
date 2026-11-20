//! O desligamento do Executive (ExShutdownSystem).
//!
//! Como no ntoskrnl 19041 (ExShutdownSystem rva 0x9b2c98):
//! - fase 0: o ExpRecordShutdownTime (rva 0x5b247c) grava o instante do
//!   desligamento (o SystemTime da KUSER_SHARED_DATA, 0xFFFFF78000000014) no
//!   valor `ShutdownTime` (REG_BINARY de 8 bytes) de
//!   `\Registry\Machine\System\CurrentControlSet\Control\Windows`, aberta
//!   com ZwOpenKey(0x2001F, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), e
//!   descarrega a chave (ZwFlushKey); sem a chave nada é gravado. Depois
//!   ExpTooLateForErrors e ExpShuttingDown ficam ligados e as chaves que o
//!   Ex mantém abertas são fechadas;
//! - fase 1: o ExSwapinWorkerThreads, só com o bit 1 do PopShutdownCleanly
//!   (`po::shutdown::clean_shutdown_flags`, zero no boot comum); as pilhas
//!   das threads de trabalho do OpenNT nunca saem da memória, então não há
//!   o que trazer de volta;
//! - fase 2: nada.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{ObjectAttributes, UnicodeString};
use crate::ntos::init::exports::invoke_handler;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

/// A chave e o valor do ExpRecordShutdownTime.
pub const WINDOWS_KEY: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Windows";
pub const SHUTDOWN_TIME_VALUE: &str = "ShutdownTime";
/// KUSER_SHARED_DATA.SystemTime.
const SYSTEM_TIME: u64 = 0xFFFF_F780_0000_0014;
/// KEY_READ | KEY_SET_VALUE | KEY_CREATE_SUB_KEY (o 0x2001F do NT).
const KEY_ACCESS: u64 = 0x2_001F;
const REG_BINARY: u64 = 3;
/// OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE.
const ATTRIBUTES: u32 = 0x240;

/// ExpShuttingDown e ExpTooLateForErrors.
static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);
static TOO_LATE_FOR_ERRORS: AtomicBool = AtomicBool::new(false);

/// Os argumentos do ExpRecordShutdownTime (bloco privado; os textos vêm
/// depois dele).
#[repr(C)]
struct Request {
    attributes: ObjectAttributes,
    key_name: UnicodeString,
    value_name: UnicodeString,
    handle: Field<u64>,
    time: Field<u64>,
}

// SAFETY: #[repr(C)] só de células e estruturas do NT.
unsafe impl NtStruct for Request {}

fn init_unicode(string: &UnicodeString, buffer: u64, text: &str) {
    let units = text.encode_utf16().count() as u16;
    guest_strings::write_wide_string(buffer, text);
    string.length.set(units * 2);
    string.maximum_length.set(units * 2 + 2);
    string.buffer.set(buffer);
}

/// ExpRecordShutdownTime: o SystemTime corrente em `ShutdownTime`. Devolve o
/// instante gravado, ou None se a chave não abre.
pub fn record_shutdown_time() -> Result<Option<u64>, KernelError> {
    let key_text = (WINDOWS_KEY.len() as u64 + 1) * 2;
    let block = guest::alloc_bytes(Request::SIZE + key_text + (SHUTDOWN_TIME_VALUE.len() as u64 + 1) * 2);
    if block == 0 {
        return Ok(None);
    }
    // SAFETY: bloco zerado recém-alocado; os textos vêm logo depois dele.
    let request = unsafe { Request::at(block) };
    init_unicode(&request.key_name, block + Request::SIZE, WINDOWS_KEY);
    init_unicode(&request.value_name, block + Request::SIZE + key_text, SHUTDOWN_TIME_VALUE);
    request.attributes.length.set(ObjectAttributes::SIZE as u32);
    request.attributes.object_name.set(request.key_name.address());
    request.attributes.attributes.set(ATTRIBUTES);
    let time = guest::read64(SYSTEM_TIME);
    request.time.set(time);
    // As chamadas Zw entram com PreviousMode = KernelMode, como pelo
    // KiServiceInternal: o desligamento da cadeia roda na thread do wininit,
    // dentro do NtShutdownSystem de modo usuário.
    let result = crate::ntos::ps::previous_mode::with_kernel(|| -> Result<Option<u64>, KernelError> {
        let opened = invoke_handler("ZwOpenKey", &[request.handle.address(), KEY_ACCESS, request.attributes.address()])? as u32;
        if opened & 0x8000_0000 != 0 {
            return Ok(None);
        }
        let key = request.handle.get();
        let set = invoke_handler("ZwSetValueKey", &[key, request.value_name.address(), 0, REG_BINARY, request.time.address(), 8])? as u32;
        invoke_handler("ZwFlushKey", &[key])?;
        invoke_handler("ZwClose", &[key])?;
        Ok((set & 0x8000_0000 == 0).then_some(time))
    })
    .and_then(|result| result);
    guest::free_bytes(block);
    result
}

/// ExShutdownSystem(Phase).
pub fn shutdown_system(phase: u32) -> Result<(), KernelError> {
    if phase == 0 {
        match record_shutdown_time()? {
            Some(time) => debug_print!("[ex] ShutdownTime gravado: {:#x}", time),
            None => debug_print!("[ex] ShutdownTime: chave Control\\Windows indisponivel"),
        }
        TOO_LATE_FOR_ERRORS.store(true, Ordering::Release);
        SHUTTING_DOWN.store(true, Ordering::Release);
    } else if phase == 1 && crate::ntos::po::shutdown::clean_shutdown_flags() & 2 != 0 {
        debug_print!("[ex] desligamento: ExSwapinWorkerThreads (pilhas sempre residentes)");
    }
    Ok(())
}

/// ExpShuttingDown: o desligamento passou da fase 0 do Executive.
pub fn shutting_down() -> bool {
    SHUTTING_DOWN.load(Ordering::Acquire)
}

/// ExpTooLateForErrors: o desligamento não aceita mais pop-ups de erro.
pub fn too_late_for_errors() -> bool {
    TOO_LATE_FOR_ERRORS.load(Ordering::Acquire)
}
