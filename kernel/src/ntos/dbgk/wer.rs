//! Dumps de kernel ao vivo do Windows Error Reporting (DbgkWer*).
//!
//! DbgkWerCaptureLiveKernelDump(ComponentName, BugCheckCode, P1..P4,
//! SecondaryDataCallback, SecondaryDataContext, Flags) monta o contexto do
//! relatório e o entrega ao WerLiveKernelCreateReport do contrato
//! ext-ms-win-ntos-werkernel; o código de bugcheck, os parâmetros e as flags
//! só preenchem esse contexto. O OpenNT não tem host para o contrato (o
//! werkernel.sys não carrega): o import do ntoskrnl fica no stub padrão da
//! extensão ausente, que devolve STATUS_NOT_SUPPORTED. A sequência é a do
//! ntoskrnl 19041:
//!
//! 1. IRQL acima de PASSIVE_LEVEL: STATUS_INVALID_LEVEL.
//! 2. `CrashControl\FullLiveKernelReports\FullLiveReportsMax` REG_DWORD igual
//!    a zero: STATUS_CONTENT_BLOCKED.
//! 3. Região crítica; outra captura em curso (DbgkpBusy): STATUS_RETRY.
//! 4. Nome do componente nulo ou sem terminador nos 16 caracteres do
//!    contexto (RtlStringCchLengthW): STATUS_INVALID_PARAMETER.
//! 5. WerLiveKernelCreateReport: STATUS_NOT_SUPPORTED, registrado como erro.
//!
//! O DbgkpWerInitialized do Windows é ligado incondicionalmente na fase 1 do
//! Dbgk, então o caminho "antes da inicialização" (STATUS_DEVICE_NOT_READY)
//! não existe depois do boot.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::ntos::cm::registry;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::ke::{critical_region, irql};
use crate::rtl::KernelError;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_INVALID_LEVEL: u32 = 0xC000_0148;
const STATUS_RETRY: u32 = 0xC000_022D;
const STATUS_CONTENT_BLOCKED: u32 = 0xC000_0804;

const REG_DWORD: u32 = 4;
const FULL_LIVE_KERNEL_REPORTS: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\CrashControl\\FullLiveKernelReports";
/// Caracteres do nome do componente no contexto do relatório, com o NUL.
const COMPONENT_NAME_CHARACTERS: u64 = 16;

/// DbgkpBusy: uma captura por vez.
static BUSY: AtomicBool = AtomicBool::new(false);

/// DbgkpWerIsFullLiveDumpDisabled: FullLiveReportsMax REG_DWORD de quatro
/// bytes igual a zero.
fn full_live_dump_disabled() -> bool {
    registry::read_value_by_path(FULL_LIVE_KERNEL_REPORTS, "FullLiveReportsMax").is_some_and(|value| value.value_type == REG_DWORD && value.data == [0; 4])
}

/// RtlStringCchLengthW(ComponentName, 16): o NUL precisa estar entre os 16
/// primeiros caracteres.
fn component_name_fits(component_name: u64) -> bool {
    // SAFETY: PCWSTR de kernel do chamador, lido até o NUL como no Windows.
    component_name != 0 && (0..COMPONENT_NAME_CHARACTERS).any(|index| unsafe { Field::<u16>::at(component_name + index * 2) }.get() == 0)
}

/// O relatório com a captura já reservada.
fn create_report(component_name: u64) -> u32 {
    if !component_name_fits(component_name) {
        return STATUS_INVALID_PARAMETER;
    }
    debug_print!("DBGK: DbgkWerCaptureLiveKernelDump: WerLiveKernelCreateReport failed, status 0x{:x}.", STATUS_NOT_SUPPORTED);
    STATUS_NOT_SUPPORTED
}

/// DbgkWerCaptureLiveKernelDump: o NTSTATUS da captura.
pub fn capture_live_kernel_dump(component_name: u64) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        debug_print!("DBGK: DbgkWerCaptureLiveKernelDump: called at IRQL > PASSIVE_LEVEL");
        return Ok(STATUS_INVALID_LEVEL);
    }
    if full_live_dump_disabled() {
        debug_print!("DBGK: Full Live Kernel Dumps are disabled. Failing request.");
        return Ok(STATUS_CONTENT_BLOCKED);
    }
    critical_region::with_critical(|| {
        if BUSY.swap(true, Ordering::SeqCst) {
            return Ok(STATUS_RETRY);
        }
        let status = create_report(component_name);
        BUSY.store(false, Ordering::SeqCst);
        Ok(status)
    })
}
