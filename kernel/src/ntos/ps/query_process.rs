//! Consulta de informações de processo em modo kernel
//! (ZwQueryInformationProcess).
//!
//! ProcessImageInformation (37) vem de `image_information`;
//! ProcessBasicInformation (0) é montado do EPROCESS achado pelo pid do
//! handle. As demais classes devolvem STATUS_INVALID_PARAMETER.

use super::{image_information, process};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{Eprocess, ProcessBasicInformation};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;

/// ZwQueryInformationProcess: ProcessImageInformation (37) e
/// ProcessBasicInformation (0). Devolve o NTSTATUS.
pub fn query_information(handle: u64, class: u32, output: u64, length: u32, returned: u64) -> Result<u32, KernelError> {
    if class == 37 {
        return image_information::query(handle, output, length, returned, 0, None);
    }
    if class != 0 {
        return Ok(0xC000_000D);
    }
    if (length as u64) < ProcessBasicInformation::SIZE {
        if returned != 0 {
            // SAFETY: PULONG ReturnLength do chamador de kernel.
            unsafe { Field::<u32>::at(returned) }.set(ProcessBasicInformation::SIZE as u32);
        }
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    let pid = process::process_id_from_handle(handle);
    let Some(target) = process::list_active_processes().into_iter().find(|entry| entry.pid == pid) else { return Ok(STATUS_INVALID_HANDLE) };
    // Zera o buffer inteiro (o preenchimento também) antes dos campos.
    guest::write_bytes(output, &[0; ProcessBasicInformation::SIZE as usize]);
    // SAFETY: PROCESS_BASIC_INFORMATION do chamador de kernel (tamanho conferido).
    let information = unsafe { ProcessBasicInformation::at(output) };
    information.exit_status.set(0x103);
    // SAFETY: EPROCESS achado na lista de processos ativos.
    information.peb_base_address.set(unsafe { Eprocess::at(target.address) }.peb.get());
    information.affinity_mask.set(1);
    information.base_priority.set(8);
    information.unique_process_id.set(pid);
    information.inherited_from_unique_process_id.set(4);
    if returned != 0 {
        // SAFETY: PULONG ReturnLength do chamador de kernel.
        unsafe { Field::<u32>::at(returned) }.set(ProcessBasicInformation::SIZE as u32);
    }
    Ok(0)
}
