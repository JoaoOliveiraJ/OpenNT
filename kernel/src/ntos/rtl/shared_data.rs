//! Estado global do sistema que o Rtl lê e grava, como no ntoskrnl 19041:
//! RtlQueryElevationFlags (KUSER_SHARED_DATA.SharedDataFlags),
//! RtlSetActiveConsoleId e RtlSetConsoleSessionForegroundProcessId (na
//! KUSER_SHARED_DATA, ou no SILO_USER_SHARED_DATA do silo de servidor da
//! thread), RtlGetCurrentServiceSessionId (ServiceSessionId do silo) e
//! RtlGetNtGlobalFlags (NtGlobalFlag).
//!
//! NtGlobalFlag: o NT o carrega do valor GlobalFlag do Session Manager no
//! boot; o OpenNT não lê esse valor, e a célula começa em 0, o padrão de uma
//! instalação.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::ntos::inc::field::Field;
use crate::ntos::mm::shared_user_data;
use crate::ntos::ps::silo::query as silo;
use crate::rtl::KernelError;

static NT_GLOBAL_FLAG: AtomicU32 = AtomicU32::new(0);

/// NtGlobalFlag (RtlGetNtGlobalFlags).
pub fn nt_global_flag() -> u32 {
    NT_GLOBAL_FLAG.load(Ordering::Relaxed)
}

/// Troca NtGlobalFlag e devolve o anterior.
pub fn set_nt_global_flag(value: u32) -> u32 {
    NT_GLOBAL_FLAG.swap(value, Ordering::SeqCst)
}

/// RtlQueryElevationFlags(Flags): DbgElevationEnabled -> 1, DbgVirtEnabled
/// -> 2, DbgInstallerDetectEnabled -> 4; sempre STATUS_SUCCESS.
pub fn query_elevation_flags(output: &Field<u32>) -> u32 {
    output.set(0);
    let Some(shared) = shared_user_data::data() else { return 0 };
    let mut flags = 0;
    if shared.dbg_elevation_enabled() != 0 {
        flags |= 1;
    }
    if shared.dbg_virt_enabled() != 0 {
        flags |= 2;
    }
    if shared.dbg_installer_detect_enabled() != 0 {
        flags |= 4;
    }
    output.set(flags);
    0
}

/// RtlSetActiveConsoleId(ConsoleId).
pub fn set_active_console_id(console: u32) -> Result<(), KernelError> {
    match silo::user_shared_data(silo::current_server_silo()) {
        Some(data) => data.active_console_id.set(console),
        None => shared_user_data::data().ok_or_else(|| KernelError::new("KUSER_SHARED_DATA ausente"))?.active_console_id.set(console),
    }
    Ok(())
}

/// RtlSetConsoleSessionForegroundProcessId(ProcessId).
pub fn set_console_session_foreground_process_id(process: u64) -> Result<(), KernelError> {
    match silo::user_shared_data(silo::current_server_silo()) {
        Some(data) => data.console_session_foreground_process_id.set(process as i64),
        None => shared_user_data::data().ok_or_else(|| KernelError::new("KUSER_SHARED_DATA ausente"))?.console_session_foreground_process_id.set(process as i64),
    }
    Ok(())
}

/// RtlGetCurrentServiceSessionId: a sessão de serviço do silo de servidor
/// da thread corrente (fora do contexto de uma thread, o do host, 0).
pub fn current_service_session_id() -> u32 {
    silo::service_session_id(silo::current_server_silo())
}
