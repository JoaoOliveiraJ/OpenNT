//! ProcessInstrumentationCallback x64 versão 0.
//!
//! O retorno de syscall transfere o controle no anel 3, com o PC anterior
//! em R10 e o resultado original em RAX; o callback cuida da contabilidade
//! no TEB e da recursão. O campo do bloco de execução da CPU é consumido
//! pela HAL de modo usuário.

use super::{state, syscalls_core};
use crate::hal::amd64::usermode;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{Eprocess, NtStruct, ProcessInstrumentationCallbackInformation};
use crate::ntos::ps::process;

/// Só o processo corrente.
fn set_information(process: u64, input: u64, length: u64) -> Result<u32, KernelError> {
    if process != u64::MAX {
        return Ok(0xC000_0008);
    }
    if length != 16 && length != 8 {
        return Ok(0xC000_0004);
    }
    if !state::probe_user_read(input, length) {
        return Ok(0xC000_0005);
    }
    // PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION (versão 0) ou o PVOID
    // da forma antiga de 8 bytes.
    let callback = if length == 16 {
        let information = state::user_struct::<ProcessInstrumentationCallbackInformation>(input).and_then(|information| Ok((information.version.probe_get()?, information.reserved.probe_get()?, information.callback.probe_get()?)));
        match information {
            Ok((0, 0, callback)) => callback,
            Ok(_) => return Ok(0xC000_000D),
            Err(error) => return Ok(error.status),
        }
    } else {
        match guest::try_read::<u64>(input) {
            Ok(callback) => callback,
            Err(error) => return Ok(error.status),
        }
    };
    if callback != 0 && !state::probe_user_read(callback, 1) {
        return Ok(0xC000_0005);
    }
    // KPROCESS.InstrumentationCallback do processo corrente; o bloco de
    // execução da CPU guarda a cópia que a HAL lê no retorno de syscall.
    // SAFETY: o EPROCESS do processo corrente.
    unsafe { Eprocess::at(process::get_current_process()) }.pcb.instrumentation_callback.set(callback);
    let process_id = state::current_process_id();
    usermode::block().instrumentation.set(callback);
    crate::debug_print!("[instrumentation] pid={} callback=0x{:x}", process_id, callback);
    Ok(0)
}

/// O callback do processo encerrado sai do bloco de execução da CPU (o
/// KPROCESS some com ele).
pub fn release_process() {
    usermode::block().instrumentation.set(0);
}

pub fn init() {
    syscalls_core::set_instrumentation_setter(set_information);
}
