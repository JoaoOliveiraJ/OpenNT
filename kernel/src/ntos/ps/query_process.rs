//! Consulta de informações de processo em modo kernel
//! (ZwQueryInformationProcess).
//!
//! ProcessImageInformation (37) vem de `image_information`;
//! ProcessBasicInformation (0) é montado do EPROCESS achado pelo pid do
//! handle. As demais classes devolvem STATUS_INVALID_PARAMETER.

use super::{image_information, process};
use crate::ntos::inc::nt_abi::eprocess;
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
    if length < 0x30 {
        if returned != 0 {
            guest::write32(returned, 0x30);
        }
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    let pid = process::process_id_from_handle(handle);
    let Some(target) = process::list_active_processes().into_iter().find(|entry| entry.pid == pid) else { return Ok(STATUS_INVALID_HANDLE) };
    guest::write32(output, 0x103);
    guest::write32(output + 4, 0);
    guest::write64(output + 8, guest::read64(target.address + eprocess::PEB));
    guest::write64(output + 0x10, 1);
    guest::write32(output + 0x18, 8);
    guest::write32(output + 0x1C, 0);
    guest::write64(output + 0x20, pid);
    guest::write64(output + 0x28, 4);
    if returned != 0 {
        guest::write32(returned, 0x30);
    }
    Ok(0)
}
