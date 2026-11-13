//! Objeto evento do Executive: a célula de ExEventObjectType e a abertura
//! de eventos nomeados em modo kernel (ZwOpenEvent).
//!
//! A IAT recebe o endereço da célula, que aponta para o OBJECT_TYPE do
//! evento; a abertura procura o nó "Event" no namespace e publica o handle
//! pelo núcleo de handles de kernel do I/O (`io/file/zw`).

use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::nt_abi::object_attributes;
use crate::ntos::init::exports::signed_status;
use crate::ntos::io::file::zw as zw_files;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;

/// Célula de ExEventObjectType: a IAT recebe o endereço da célula, que
/// aponta para o OBJECT_TYPE do evento.
static EVENT_OBJECT_TYPE: AtomicU64 = AtomicU64::new(0);

/// Endereço da célula de ExEventObjectType, criada na primeira consulta.
pub fn event_object_type() -> u64 {
    let current = EVENT_OBJECT_TYPE.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }
    let type_structure = guest::alloc_bytes(0x40);
    let cell = guest::alloc_bytes(8);
    guest::write64(cell, type_structure);
    match EVENT_OBJECT_TYPE.compare_exchange(0, cell, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => cell,
        Err(existing) => {
            guest::free_bytes(cell);
            guest::free_bytes(type_structure);
            existing
        }
    }
}

fn object_name(attributes: u64) -> alloc::string::String {
    guest_strings::read_unicode_string(guest::read64(attributes + object_attributes::OBJECT_NAME))
}

/// ZwOpenEvent: evento nomeado do namespace. Devolve o valor nativo do
/// export: o nome inexistente sai como NTSTATUS estendido com sinal e o
/// status da abertura sai estendido com zeros.
pub fn open(output: u64, access: u32, attributes: u64) -> Result<u64, KernelError> {
    let node = object_manager::lookup(&object_name(attributes)).filter(|&node| object_manager::node(node).is_some_and(|node| node.type_name == "Event"));
    let Some(node) = node else { return Ok(signed_status(STATUS_OBJECT_NAME_NOT_FOUND)) };
    Ok(zw_files::open_kernel_object(output, node, access, attributes)? as u64)
}
