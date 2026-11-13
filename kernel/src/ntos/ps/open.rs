//! Abertura de processo e de thread em KernelMode (ZwOpenProcess e
//! ZwOpenThread), como o NtOpenProcess/NtOpenThread do NT.
//!
//! O objeto vem pelo CLIENT_ID (PsLookup*, com a thread conferida contra o
//! processo pedido) ou pelo nome (ObOpenObjectByName); nunca os dois nem
//! nenhum. O resultado é o valor nativo de retorno: o NTSTATUS estendido ou,
//! na abertura pelo nome, o que o ObOpenObjectByName devolveu.

use crate::ntos::inc::nt_abi::kthread;
use crate::ntos::init::exports::{invoke_handler, signed_status};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{object_types, open_pointer};
use crate::rtl::KernelError;

const STATUS_INVALID_PARAMETER_MIX: u32 = 0xC000_0030;
const STATUS_INVALID_CID: u32 = 0xC000_000B;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// ZwOpenProcess(handle*, access, oa, clientId*).
pub fn open_process(output: u64, access: u32, attributes: u64, client_id: u64) -> Result<u64, KernelError> {
    open(output, access, attributes, client_id, false)
}

/// ZwOpenThread(handle*, access, oa, clientId*).
pub fn open_thread(output: u64, access: u32, attributes: u64, client_id: u64) -> Result<u64, KernelError> {
    open(output, access, attributes, client_id, true)
}

fn open(output: u64, access: u32, attributes: u64, client_id: u64, thread: bool) -> Result<u64, KernelError> {
    // OBJECT_ATTRIBUTES: ObjectName @0x10, Attributes @0x18.
    let (name, flags) = if attributes != 0 { (guest::read64(attributes + 0x10), guest::read32(attributes + 0x18)) } else { (0, 0) };
    let object_type = if thread { object_types::thread_type().pointer } else { object_types::process_type().pointer };
    if (name != 0) == (client_id != 0) {
        return Ok(signed_status(STATUS_INVALID_PARAMETER_MIX));
    }
    if name != 0 {
        return invoke_handler("ObOpenObjectByName", &[attributes, object_type, 0, 0, access as u64, 0, output]);
    }
    let (process_id, thread_id) = (guest::read64(client_id), guest::read64(client_id + 8));
    let slot = guest::alloc_bytes(8);
    if slot == 0 {
        return Ok(signed_status(STATUS_INSUFFICIENT_RESOURCES));
    }
    let lookup = if thread { invoke_handler("PsLookupThreadByThreadId", &[thread_id, slot]) } else { invoke_handler("PsLookupProcessByProcessId", &[process_id, slot]) };
    let object = guest::read64(slot);
    guest::free_bytes(slot);
    let status = lookup? as u32;
    if status != 0 {
        return Ok(signed_status(status));
    }
    if thread && process_id != 0 && guest::read64(object + kthread::CID_UNIQUE_PROCESS) != process_id {
        invoke_handler("ObfDereferenceObject", &[object])?;
        return Ok(signed_status(STATUS_INVALID_CID));
    }
    let opened = open_pointer::open(object, flags, 0, access, object_type, 0, output);
    invoke_handler("ObfDereferenceObject", &[object])?;
    Ok(signed_status(opened?))
}
