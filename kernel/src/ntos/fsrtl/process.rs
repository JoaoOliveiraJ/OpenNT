//! Consultas de processo usadas por file systems — FsRtlIs32BitProcess
//! (0x88bc00) e FsRtlGetCurrentProcessLoaderList (0x88bbd0) do ntoskrnl
//! 19045.
//!
//! * 32 bits: EPROCESS.WoW64Process não nulo e EWOW64PROCESS.Machine igual a
//!   IMAGE_FILE_MACHINE_I386 (0x14C) ou IMAGE_FILE_MACHINE_ARMNT (0x1C4).
//! * Lista do loader: KTHREAD.ApcState.Process -> EPROCESS.Peb -> PEB.Ldr ->
//!   &PEB_LDR_DATA.InLoadOrderModuleList. O PEB é memória de modo usuário do
//!   processo corrente: a leitura de `Ldr` é sondada (o NT a faz sem sonda e
//!   uma falha vira exceção do chamador; aqui vira STATUS_ACCESS_VIOLATION).

use core::mem::offset_of;

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Eprocess, Ethread, Ewow64process, Peb, PebLdrData};
use crate::ntos::ps::process;
use crate::rtl::KernelError;

const IMAGE_FILE_MACHINE_I386: u16 = 0x14C;
const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x1C4;

/// FsRtlIs32BitProcess(Process) -> BOOLEAN.
pub fn is_32bit_process(process_object: &Eprocess) -> bool {
    let wow64 = process_object.wo_w64_process.get();
    if wow64 == 0 {
        return false;
    }
    // SAFETY: EWOW64PROCESS do processo (pool do kernel).
    matches!(unsafe { Ewow64process::at(wow64) }.machine.get(), IMAGE_FILE_MACHINE_I386 | IMAGE_FILE_MACHINE_ARMNT)
}

/// FsRtlGetCurrentProcessLoaderList() -> PLIST_ENTRY.
pub fn current_process_loader_list() -> Result<u64, KernelError> {
    // SAFETY: a thread corrente e o processo ao qual ela está anexada.
    let thread = unsafe { Ethread::at(process::get_current_thread()) };
    let attached = unsafe { Eprocess::at(thread.tcb.apc_state.process.get()) };
    let ldr = Peb::try_at(attached.peb.get())?.ldr.probe_get()?;
    // Só o endereço do campo (o NT não lê a lista aqui).
    Ok(ldr.wrapping_add(offset_of!(PebLdrData, in_load_order_module_list) as u64))
}
