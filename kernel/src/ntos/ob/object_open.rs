//! Abertura de objetos por nome — ObOpenObjectByName, como o `obopen.c` do
//! NT (a abertura por ponteiro é `open_pointer`).
//!
//! O nome dos OBJECT_ATTRIBUTES resolve no namespace; callbacks do Ex,
//! seções e drivers abrem o handle pelo próprio dono, e o restante recebe um
//! handle do Object Manager. Devolve o valor de retorno do export, com o
//! NTSTATUS já estendido para 64 bits do jeito que o export o entrega.

use crate::ntos::ex::callbacks as executive_callbacks;
use crate::ntos::inc::nt_abi::object_attributes;
use crate::ntos::init::exports::signed_status;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::ob::object_reference::{native_pointer_of_node, reference_device, type_differs};
use crate::ntos::ob::object_types;
use crate::ntos::ob::objects::{driver as driver_objects, section as section_objects};
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

const NAME_NOT_FOUND: u32 = 0xC000_0034;
const TYPE_MISMATCH: u32 = 0xC000_0024;
const ACCESS_DENIED: u32 = 0xC000_0022;

/// Abre um callback do Ex pelos atributos já capturados.
fn open_callback(captured_node: NodeId, flags: u32, object_type: u64, access: u32, mode: u8, output: u64) -> Result<u64, KernelError> {
    if type_differs(object_type, object_types::callback_type().pointer) {
        return Ok(signed_status(TYPE_MISMATCH));
    }
    let target = object_manager::node(captured_node).and_then(|node| node.data).map_or(0, |data| data.native_pointer);
    match executive_callbacks::open_handle(target, access, flags, mode != 0)? {
        Ok(handle) => {
            guest::write64(output, handle);
            Ok(0)
        }
        Err(status) => Ok(status as u64),
    }
}

/// ObOpenObjectByName (7 argumentos): handle do Object Manager para o
/// objeto nomeado em `attributes_pointer` (OBJECT_ATTRIBUTES).
pub fn open_by_name(attributes_pointer: u64, object_type: u64, mode: u8, access: u32, output: u64) -> Result<u64, KernelError> {
    if let Ok(captured) = executive_callbacks::attributes(attributes_pointer) {
        if let Some(node) = captured.node.filter(|&node| object_manager::node(node).is_some_and(|node| node.type_name == "Callback")) {
            return open_callback(node, captured.flags, object_type, access, mode, output);
        }
    }
    let name = guest_strings::read_unicode_string(guest::read64(attributes_pointer + object_attributes::OBJECT_NAME));
    let node = object_manager::lookup(&name);
    let pointer = native_pointer_of_node(node);
    if pointer == 0 {
        return Ok(signed_status(NAME_NOT_FOUND));
    }
    if executive_callbacks::exists(pointer) {
        let captured = match executive_callbacks::attributes(attributes_pointer) {
            Ok(captured) => captured,
            Err(status) => return Ok(status as u64),
        };
        let Some(node) = captured.node else { return Ok(signed_status(NAME_NOT_FOUND)) };
        if object_manager::node(node).is_none_or(|node| node.type_name != "Callback") {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        return open_callback(node, captured.flags, object_type, access, mode, output);
    }
    let attributes = guest::read32(attributes_pointer + object_attributes::ATTRIBUTES);
    if section_objects::is_section(pointer) {
        if type_differs(object_type, object_types::section_type().pointer) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        if section_objects::access(access).is_none() {
            return Ok(signed_status(ACCESS_DENIED));
        }
        let handle = section_objects::open_handle(pointer, access, attributes)?;
        if handle == 0 {
            return Ok(signed_status(NAME_NOT_FOUND));
        }
        guest::write64(output, handle);
        return Ok(0);
    }
    if driver_objects::is_driver(pointer) {
        if type_differs(object_type, object_types::driver_type().pointer) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        if driver_objects::access(access).is_none() {
            return Ok(signed_status(ACCESS_DENIED));
        }
        let handle = driver_objects::open_handle(pointer, access, attributes)?;
        if handle == 0 {
            return Ok(signed_status(NAME_NOT_FOUND));
        }
        guest::write64(output, handle);
        return Ok(0);
    }
    reference_device(pointer)?;
    let handle = object_manager::open(&name)?;
    guest::write64(output, handle as u64);
    Ok(0)
}
