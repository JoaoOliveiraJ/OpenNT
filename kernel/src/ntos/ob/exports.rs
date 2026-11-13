//! Exports Ob* do ntoskrnl — `system32/win32/ntoskrnl/ob.js`.
//!
//! Referências e aberturas pelo dono real de cada corpo (namespace,
//! despachante, callbacks do Ex, contextos de silo, tokens, seções, drivers,
//! arquivos, processos, threads e dispositivos), por nome, handle ou
//! ponteiro, além do nome do objeto e do descritor de segurança. Os handles
//! de modo usuário (tokens e seções da tabela de usuário) entram com o estado
//! de modo usuário (fase 7).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;

use crate::ntos::init::exports::{signed_status, Call, Group};
use crate::ntos::io::file::zw as zw_files;
use crate::ntos::ex::callbacks as executive_callbacks;
use crate::ntos::io::io_manager;
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::ob::objects::{device as device_objects, dispatcher as dispatcher_objects, driver as driver_objects, file as file_objects, namespace as namespace_objects, section as section_objects};
use crate::ntos::ob::{object_types, open_pointer, reference_trace};
use crate::ntos::ps::{kernel_threads, process};
use crate::ntos::ps::silo::contexts as silo_contexts;
use crate::ntos::se::token::{handles as token_handles, tokens};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::ntos::inc::nt_abi::{device_object, object_attributes};

const NAME_NOT_FOUND: u32 = 0xC000_0034;
const TYPE_MISMATCH: u32 = 0xC000_0024;
const ACCESS_DENIED: u32 = 0xC000_0022;
const INVALID_HANDLE: u32 = 0xC000_0008;

/// Descritor escrito por ObSetSecurityObjectByPointer, por objeto.
static SECURITY_DESCRIPTORS: SpinLock<BTreeMap<u64, u64>> = SpinLock::new(BTreeMap::new());

pub fn security_descriptor(object: u64) -> Option<u64> {
    SECURITY_DESCRIPTORS.lock().get(&object).copied()
}

/// Retém o dispositivo pelo dono que o conhece ou pelo contador nativo LONG.
fn reference_device(pointer: u64) -> Result<u64, KernelError> {
    if let Some(count) = device_objects::reference(pointer)? {
        return Ok(count as u64);
    }
    let address = pointer + device_object::REFERENCE_COUNT;
    let value = (guest::read32(address) as i32).wrapping_add(1);
    guest::write32(address, value as u32);
    Ok(value as i64 as u64)
}

fn dereference_device(pointer: u64) -> Result<u64, KernelError> {
    if let Some(count) = device_objects::dereference(pointer)? {
        return Ok(count as u64);
    }
    let address = pointer + device_object::REFERENCE_COUNT;
    let value = (guest::read32(address) as i32).wrapping_sub(1);
    guest::write32(address, value as u32);
    Ok(value as i64 as u64)
}

/// Corpo nativo de um objeto nomeado (Device, Driver, Section, Callback).
fn native_pointer_of_node(node: Option<NodeId>) -> u64 {
    let Some(snapshot) = node.and_then(object_manager::node) else { return 0 };
    let data = snapshot.data.unwrap_or_default();
    match snapshot.type_name.as_str() {
        "Device" => io_manager::device(snapshot.id).map(|entry| if entry.stack_top != 0 { entry.stack_top } else { entry.native_device }).unwrap_or(data.native_pointer),
        "Driver" | "Section" | "Callback" => data.native_pointer,
        _ => 0,
    }
}

/// Caminho completo pelo corpo nativo (\Device, \Driver e \KernelObjects).
fn find_path_by_native_pointer(pointer: u64) -> Option<String> {
    for root in ["\\Device", "\\Driver", "\\KernelObjects"] {
        let Some(children) = object_manager::lookup(root).and_then(object_manager::node).and_then(|node| node.children) else { continue };
        for &child in children.values() {
            let Some(node) = object_manager::node(child) else { continue };
            let Some(data) = node.data.as_ref() else { continue };
            if native_pointer_of_node(Some(child)) == pointer || (node.type_name == "Event" && data.native_pointer == pointer) {
                return Some(format!("{root}\\{}", node.name));
            }
        }
    }
    None
}

/// Tipo de um corpo do namespace, do despachante ou de contexto de silo.
fn described_type(pointer: u64) -> u64 {
    open_pointer::describe(pointer).map_or(0, |described| described.object_type.pointer)
}

fn require_owner(pointer: u64, allow_legacy_device: bool, name: &str) -> Result<(), KernelError> {
    if !allow_legacy_device && !device_objects::is_device(pointer) && open_pointer::describe(pointer).is_none() {
        return Err(KernelError::new(format!("{name}: invalid native object {pointer:#x}")));
    }
    Ok(())
}

/// Retém pelo dono existente; o histórico observa a tentativa antes.
pub fn reference_with_tag(pointer: u64, tag: u32, allow_legacy_device: bool) -> Result<u64, KernelError> {
    reference_trace::record(pointer, tag, 1);
    require_owner(pointer, allow_legacy_device, "ObfReferenceObjectWithTag")?;
    if namespace_objects::get(pointer).is_some() {
        return namespace_objects::reference(pointer);
    }
    if dispatcher_objects::get(pointer).is_some() {
        return Ok(dispatcher_objects::reference(pointer)? as u64);
    }
    if let Some(count) = executive_callbacks::reference(pointer) {
        return Ok(count as u64);
    }
    if let Some(count) = silo_contexts::reference(pointer)? {
        return Ok(count);
    }
    if let Some(count) = tokens::reference(pointer) {
        return Ok(count);
    }
    if let Some(count) = section_objects::reference(pointer) {
        return Ok(count as u64);
    }
    if let Some(count) = driver_objects::reference(pointer) {
        return Ok(count as u64);
    }
    if let Some(count) = file_objects::reference(pointer)? {
        return Ok(count as u64);
    }
    if let Some(count) = process::reference(pointer) {
        return Ok(count as u64);
    }
    if kernel_threads::reference(pointer) {
        return Ok(process::thread_reference_count(pointer).unwrap_or(0) as u64);
    }
    if let Some(count) = process::reference_thread(pointer) {
        return Ok(count as u64);
    }
    reference_device(pointer)
}

/// Solta uma referência pelo dono real; a tag só altera o histórico.
pub fn dereference_with_tag(pointer: u64, tag: u32, allow_legacy_device: bool) -> Result<u64, KernelError> {
    reference_trace::record(pointer, tag, -1);
    require_owner(pointer, allow_legacy_device, "ObfDereferenceObjectWithTag")?;
    if namespace_objects::get(pointer).is_some() {
        return namespace_objects::dereference(pointer);
    }
    if dispatcher_objects::get(pointer).is_some() {
        return Ok(dispatcher_objects::dereference(pointer)? as u64);
    }
    if let Some(count) = executive_callbacks::dereference(pointer)? {
        return Ok(count as u64);
    }
    if let Some(count) = silo_contexts::dereference(pointer)? {
        return Ok(count);
    }
    if let Some(count) = tokens::dereference(pointer) {
        return Ok(count);
    }
    if let Some(count) = section_objects::dereference(pointer)? {
        return Ok(count as u64);
    }
    if let Some(count) = driver_objects::dereference(pointer)? {
        return Ok(count as u64);
    }
    if let Some(count) = file_objects::dereference(pointer)? {
        return Ok(count as u64);
    }
    if let Some(count) = process::dereference(pointer)? {
        return Ok(count as u64);
    }
    if let Some(count) = kernel_threads::dereference(pointer)? {
        return Ok(count as u64);
    }
    if let Some(count) = process::dereference_thread(pointer)? {
        return Ok(count as u64);
    }
    dereference_device(pointer)
}

fn reference_object(call: &Call) -> Result<u64, KernelError> {
    reference_with_tag(call.arg(1), reference_trace::DEFAULT_TAG, true)
}
fn dereference_object(call: &Call) -> Result<u64, KernelError> {
    dereference_with_tag(call.arg(1), reference_trace::DEFAULT_TAG, true)
}

fn type_differs(requested: u64, expected: u64) -> bool {
    requested != 0 && requested != expected
}

fn write_information(information: u64, attributes: u32, access: u32) {
    if information != 0 {
        guest::write32(information, attributes);
        guest::write32(information + 4, access);
    }
}

/// ObReferenceObjectByName (8 argumentos, com PACCESS_STATE opcional).
fn reference_object_by_name(call: &Call) -> Result<u64, KernelError> {
    let (attributes, access, object_type, mode, output) = (call.arg(2) as u32, call.arg(4) as u32, call.arg(5), call.arg(6) as u8, call.arg(8));
    let name = guest_strings::read_unicode_string(call.arg(1));
    let node = object_manager::lookup(&name);
    let pointer = native_pointer_of_node(node);
    if pointer == 0 {
        return Ok(signed_status(NAME_NOT_FOUND));
    }
    if executive_callbacks::exists(pointer) {
        let actual = object_manager::resolve_from(&name, 0, attributes & 0x40 != 0, false, object_manager::ROOT).0;
        let Some(actual) = actual.and_then(object_manager::node) else { return Ok(signed_status(NAME_NOT_FOUND)) };
        if actual.type_name != "Callback" || type_differs(object_type, object_types::callback_type().pointer) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        let target = actual.data.map_or(0, |data| data.native_pointer);
        if let Err(status) = executive_callbacks::access(target, access, mode != 0 || attributes & 0x400 != 0) {
            return Ok(status as u64);
        }
        executive_callbacks::reference(target);
        guest::write64(output, target);
        return Ok(0);
    }
    if section_objects::is_section(pointer) {
        if type_differs(object_type, object_types::section_type().pointer) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        if section_objects::access(access).is_none() {
            return Ok(signed_status(ACCESS_DENIED));
        }
        section_objects::reference(pointer);
        guest::write64(output, pointer);
        return Ok(0);
    }
    if driver_objects::is_driver(pointer) {
        if type_differs(object_type, object_types::driver_type().pointer) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        if driver_objects::access(access).is_none() {
            return Ok(signed_status(ACCESS_DENIED));
        }
        driver_objects::reference(pointer);
        guest::write64(output, pointer);
        return Ok(0);
    }
    reference_device(pointer)?;
    if let Some(node) = node {
        object_manager::update_node(node, |node| node.refs += 1);
    }
    guest::write64(output, pointer);
    Ok(0)
}

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
/// objeto nomeado.
fn open_object_by_name(call: &Call) -> Result<u64, KernelError> {
    let (attributes_pointer, object_type, mode, access, output) = (call.arg(1), call.arg(2), call.arg(3) as u8, call.arg(5) as u32, call.arg(7));
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

/// ObReferenceObjectByHandle(handle, access, type, mode, out, info).
pub(crate) fn reference_object_by_handle(call: &Call) -> Result<u64, KernelError> {
    let (handle, access, object_type, mode, output, information) = (call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u8, call.arg(5), call.arg(6));
    if let Some(status) = open_pointer::reference_handle(handle, access, object_type, mode, output, information)? {
        return Ok(status as u64);
    }
    if let Some(callback) = executive_callbacks::resolve_handle(handle, mode != 0) {
        if type_differs(object_type, object_types::callback_type().pointer) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        let granted = callback.access.unwrap_or(0);
        if mode != 0 && access & !granted != 0 {
            return Ok(signed_status(ACCESS_DENIED));
        }
        executive_callbacks::reference(callback.native_pointer);
        guest::write64(output, callback.native_pointer);
        write_information(information, callback.attributes, granted);
        return Ok(0);
    }
    // Tokens de handles nativos (os de usuário entram com a fase 7).
    let token = if mode != 0 { None } else { token_handles::resolve_native(handle) };
    if let Some(entry) = token.filter(|entry| entry.native_pointer != 0) {
        if type_differs(object_type, object_types::token_type().pointer) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        let granted = entry.access.unwrap_or(0);
        if mode != 0 && access & !granted != 0 {
            return Ok(signed_status(ACCESS_DENIED));
        }
        tokens::retain(entry.native_pointer)?;
        guest::write64(output, entry.native_pointer);
        write_information(information, entry.attributes, granted);
        return Ok(0);
    }
    let signed = handle as i64;
    // -2 é a thread corrente; o tipo é validado antes do acesso.
    if signed == -2 {
        let thread_type = object_types::thread_type();
        if type_differs(object_type, thread_type.pointer) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        if mode != 0 && access & !thread_type.valid_access != 0 {
            return Ok(signed_status(ACCESS_DENIED));
        }
        let thread = process::get_current_thread();
        if process::reference_thread(thread).is_none() {
            return Ok(signed_status(INVALID_HANDLE));
        }
        guest::write64(output, thread);
        write_information(information, 0, thread_type.valid_access);
        return Ok(0);
    }
    if signed < 0 && signed != -1 {
        return Ok(signed_status(INVALID_HANDLE));
    }
    let handle32 = handle as u32;
    let node = object_manager::get_object(handle32);
    let snapshot = node.and_then(object_manager::node);
    let type_name = snapshot.as_ref().map_or("", |node| node.type_name.as_str());
    let data = snapshot.as_ref().and_then(|node| node.data.clone()).unwrap_or_default();
    if type_name == "Section" {
        let pointer = data.native_pointer;
        if !section_objects::is_section(pointer) {
            return Ok(signed_status(INVALID_HANDLE));
        }
        let section_type = object_types::section_type();
        if type_differs(object_type, section_type.pointer) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        let granted = data.access.unwrap_or(section_type.valid_access);
        if mode != 0 && access & !granted != 0 {
            return Ok(signed_status(ACCESS_DENIED));
        }
        section_objects::reference(pointer);
        guest::write64(output, pointer);
        write_information(information, data.attributes, granted);
        return Ok(0);
    }
    if type_name == "Driver" {
        let pointer = native_pointer_of_node(node);
        if !driver_objects::is_driver(pointer) {
            return Ok(signed_status(INVALID_HANDLE));
        }
        let driver_type = object_types::driver_type();
        if type_differs(object_type, driver_type.pointer) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        let granted = data.access.unwrap_or(driver_type.valid_access);
        if mode != 0 && access & !granted != 0 {
            return Ok(signed_status(ACCESS_DENIED));
        }
        driver_objects::reference(pointer);
        guest::write64(output, pointer);
        write_information(information, data.attributes, granted);
        return Ok(0);
    }
    let pseudo_process = signed == -1;
    if pseudo_process || type_name == "Process" {
        let pointer = if pseudo_process { process::get_current_process() } else { data.native_pointer };
        if !process::is_process(pointer) {
            return Ok(signed_status(INVALID_HANDLE));
        }
        let process_type = object_types::process_type();
        if type_differs(object_type, process_type.pointer) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        let granted = if pseudo_process { process_type.valid_access } else { data.access.unwrap_or(0) };
        if mode != 0 && access & !granted != 0 {
            return Ok(signed_status(ACCESS_DENIED));
        }
        process::reference(pointer);
        guest::write64(output, pointer);
        write_information(information, 0, granted);
        return Ok(0);
    }
    if type_name == "Thread" {
        if type_differs(object_type, object_types::thread_type().pointer) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        let granted = data.access.unwrap_or(0);
        if mode != 0 && access & !granted != 0 {
            return Ok(signed_status(ACCESS_DENIED));
        }
        kernel_threads::reference(data.native_pointer);
        guest::write64(output, data.native_pointer);
        write_information(information, 0, granted);
        return Ok(0);
    }
    let mut pointer = native_pointer_of_node(node);
    // Eventos nomeados: o corpo é o KEVENT do convidado.
    if pointer == 0 && type_name == "Event" {
        pointer = data.native_pointer;
    }
    // Handles de arquivo do zw: o corpo é o FILE_OBJECT nativo.
    if pointer == 0 {
        pointer = zw_files::file_object_of_handle(handle32 as u64);
    }
    if pointer == 0 {
        return Ok(signed_status(INVALID_HANDLE));
    }
    if let Some((kind, _, _)) = dispatcher_objects::get(pointer) {
        let record = zw_files::handle_access_record(handle32);
        let Some((kernel_handle, owner, attributes, granted)) = record else { return Ok(INVALID_HANDLE as u64) };
        if (mode != 0 && kernel_handle) || (!kernel_handle && owner != process::get_current_process()) {
            return Ok(INVALID_HANDLE as u64);
        }
        if type_differs(object_type, object_types::by_name(&kind).map_or(0, |found| found.pointer)) {
            return Ok(TYPE_MISMATCH as u64);
        }
        if mode != 0 && access & !granted != 0 {
            return Ok(ACCESS_DENIED as u64);
        }
        dispatcher_objects::reference(pointer)?;
        guest::write64(output, pointer);
        write_information(information, attributes, granted);
        return Ok(0);
    }
    if file_objects::is_file(pointer) {
        if type_differs(object_type, object_types::file_type().pointer) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        let granted = zw_files::file_access_of_handle(handle32 as u64);
        if mode != 0 && access & !granted != 0 {
            return Ok(signed_status(ACCESS_DENIED));
        }
        file_objects::reference(pointer)?;
        guest::write64(output, pointer);
        write_information(information, 0, granted);
        return Ok(0);
    }
    reference_device(pointer)?;
    if let Some(node) = node {
        object_manager::update_node(node, |node| node.refs += 1);
    }
    guest::write64(output, pointer);
    Ok(0)
}

/// ObReferenceObjectByPointer(object, access, type, mode): em modo usuário
/// o tipo pedido precisa ser o do objeto.
fn reference_object_by_pointer(call: &Call) -> Result<u64, KernelError> {
    let (pointer, object_type, mode) = (call.arg(1), call.arg(3), call.arg(4) as u8);
    if pointer == 0 {
        return Ok(signed_status(0xC000_000D));
    }
    let mismatch = |expected: u64| mode != 0 && (object_type == 0 || object_type != expected);
    if namespace_objects::get(pointer).is_some() || dispatcher_objects::get(pointer).is_some() {
        if mismatch(described_type(pointer)) {
            return Ok(TYPE_MISMATCH as u64);
        }
        if namespace_objects::get(pointer).is_some() {
            namespace_objects::reference(pointer)?;
        } else {
            dispatcher_objects::reference(pointer)?;
        }
        return Ok(0);
    }
    if executive_callbacks::exists(pointer) {
        if mismatch(object_types::callback_type().pointer) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        executive_callbacks::reference(pointer);
        return Ok(0);
    }
    if silo_contexts::exists(pointer) {
        if mismatch(described_type(pointer)) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        silo_contexts::reference(pointer)?;
        return Ok(0);
    }
    if tokens::get(pointer).is_some() {
        if mismatch(object_types::token_type().pointer) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        tokens::retain(pointer)?;
        return Ok(0);
    }
    if section_objects::is_section(pointer) {
        if mismatch(object_types::section_type().pointer) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        section_objects::reference(pointer);
        return Ok(0);
    }
    if driver_objects::is_driver(pointer) {
        if mismatch(object_types::driver_type().pointer) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        driver_objects::reference(pointer);
        return Ok(0);
    }
    if file_objects::is_file(pointer) {
        if mismatch(object_types::file_type().pointer) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        file_objects::reference(pointer)?;
        return Ok(0);
    }
    if process::is_process(pointer) {
        if mismatch(object_types::process_type().pointer) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        process::reference(pointer);
        return Ok(0);
    }
    if process::is_thread(pointer) {
        if mismatch(object_types::thread_type().pointer) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        if !kernel_threads::reference(pointer) {
            process::reference_thread(pointer);
        }
        return Ok(0);
    }
    if kernel_threads::reference(pointer) {
        return Ok(0);
    }
    reference_device(pointer)?;
    Ok(0)
}

fn write_wide(address: u64, text: &str) {
    guest_strings::write_wide_string(address, text);
}

/// ObQueryNameString: o caminho completo do objeto (callbacks pelo nome
/// próprio, com o UNICODE_STRING montado no buffer).
fn query_name_string(call: &Call) -> Result<u64, KernelError> {
    let (pointer, output, size, returned) = (call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4));
    if executive_callbacks::exists(pointer) {
        let name = executive_callbacks::name(pointer);
        let units = name.as_ref().map_or(0, |name| name.encode_utf16().count() as u32);
        let needed = 16 + if name.is_some() { units * 2 + 2 } else { 0 };
        if returned != 0 {
            guest::write32(returned, needed);
        }
        if size < needed {
            return Ok(signed_status(0xC000_0004));
        }
        for offset in 0..16 {
            guest::write8(output + offset, 0);
        }
        if let Some(name) = name {
            guest::write16(output, units as u16 * 2);
            guest::write16(output + 2, units as u16 * 2 + 2);
            guest::write64(output + 8, output + 16);
            write_wide(output + 16, &name);
        }
        return Ok(0);
    }
    let Some(path) = find_path_by_native_pointer(pointer) else {
        if returned != 0 {
            guest::write32(returned, 0);
        }
        return Ok(signed_status(0xC000_000D));
    };
    let units = path.encode_utf16().count() as u32;
    let needed = units * 2 + 2;
    if returned != 0 {
        guest::write32(returned, needed);
    }
    if size < needed {
        return Ok(signed_status(0xC000_0004));
    }
    write_wide(guest::read64(output + 8), &path);
    guest::write16(output, units as u16 * 2);
    guest::write16(output + 2, units as u16 * 2 + 2);
    Ok(0)
}

/// Sem device maps por LUID (sem sessões de logon).
fn is_dos_device_locally_mapped(_: &Call) -> Result<u64, KernelError> {
    Ok(0)
}

/// ObSetSecurityObjectByPointer: o descritor fica na tabela lateral (o
/// slot do OBJECT_HEADER no NT).
fn set_security_object_by_pointer(call: &Call) -> Result<u64, KernelError> {
    if call.arg(1) == 0 {
        return Ok(signed_status(INVALID_HANDLE));
    }
    SECURITY_DESCRIPTORS.lock().insert(call.arg(1), call.arg(2));
    Ok(0)
}

pub static GROUP: Group = Group {
    name: "ob",
    names: &["ObReferenceObject", "ObDereferenceObject", "ObfReferenceObject", "ObfDereferenceObject", "ObReferenceObjectByName", "ObOpenObjectByName", "ObReferenceObjectByHandle", "ObReferenceObjectByPointer", "ObQueryNameString", "ObIsDosDeviceLocallyMapped", "ObSetSecurityObjectByPointer"],
    handlers: &[reference_object, dereference_object, reference_object, dereference_object, reference_object_by_name, open_object_by_name, reference_object_by_handle, reference_object_by_pointer, query_name_string, is_dos_device_locally_mapped, set_security_object_by_pointer],
    data_exports: &[],
};

pub mod find_handle {
    //! ObFindHandleForObject — `ntos/ob/find-handle` (o resolvedor entrega o corpo
    //! nativo; o trampolim usa a busca do kernel).

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::ob::find_handle;
    use crate::rtl::KernelError;

    fn find(call: &Call) -> Result<u64, KernelError> {
        find_handle::find(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5))
    }

    pub static GROUP: Group = Group { name: "find-handle", names: &["ObFindHandleForObject"], handlers: &[find], data_exports: &[] };
}

pub mod get_object_type {
    //! ObGetObjectType — `system32/win32/ntoskrnl/get-object-type.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ob::get_object_type;

    fn ob_get_object_type(call: &Call) -> Result<u64, KernelError> {
        get_object_type::get(call.arg(1))
    }

    pub static GROUP: Group = Group {
        name: "get-object-type",
        names: &["ObGetObjectType"],
        handlers: &[ob_get_object_type],
        data_exports: &[],
    };
}

pub mod object_callbacks {
    //! ObRegisterCallbacks/ObUnRegisterCallbacks — `system32/win32/ntoskrnl/object-callbacks.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ob::callbacks;

    fn register_callbacks(call: &Call) -> Result<u64, KernelError> {
        Ok(callbacks::register(call.arg(1), call.arg(2))? as u64)
    }

    fn unregister_callbacks(call: &Call) -> Result<u64, KernelError> {
        Ok(callbacks::unregister(call.arg(1))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "object-callbacks",
        names: &["ObRegisterCallbacks", "ObUnRegisterCallbacks"],
        handlers: &[register_callbacks, unregister_callbacks],
        data_exports: &[],
    };
}

pub mod open_pointer_exports {
    //! ObOpenObjectByPointer — `system32/win32/ntoskrnl/open-pointer.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ob::open_pointer;

    fn open_object_by_pointer(call: &Call) -> Result<u64, KernelError> {
        Ok(open_pointer::open(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5), call.arg(6) as u8, call.arg(7))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "open-pointer",
        names: &["ObOpenObjectByPointer"],
        handlers: &[open_object_by_pointer],
        data_exports: &[],
    };
}

pub mod tagged_dereference {
    //! ObfDereferenceObjectWithTag — a desreferência com tag do grupo `ob`; falha
    //! interna interrompe o sistema.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::init::exports::fatal_unless_transfer;
    use crate::ntos::ob::exports as ob;
    use crate::rtl::KernelError;

    fn dereference_with_tag(call: &Call) -> Result<u64, KernelError> {
        fatal_unless_transfer("tagged-dereference", ob::dereference_with_tag(call.arg(1), call.arg(2) as u32, false))
    }

    pub static GROUP: Group = Group { name: "tagged-dereference", names: &["ObfDereferenceObjectWithTag"], handlers: &[dereference_with_tag], data_exports: &[] };
}

pub mod tagged_reference {
    //! ObfReferenceObjectWithTag — a referência com tag do grupo `ob`; falha
    //! interna interrompe o sistema.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::init::exports::fatal_unless_transfer;
    use crate::ntos::ob::exports as ob;
    use crate::rtl::KernelError;

    fn reference_with_tag(call: &Call) -> Result<u64, KernelError> {
        fatal_unless_transfer("tagged-reference", ob::reference_with_tag(call.arg(1), call.arg(2) as u32, false))
    }

    pub static GROUP: Group = Group { name: "tagged-reference", names: &["ObfReferenceObjectWithTag"], handlers: &[reference_with_tag], data_exports: &[] };
}

pub mod close {
    //! NtClose — `system32/win32/ntoskrnl/close.js`.
    //!
    //! Fecha com o modo anterior da thread.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ob::close;

    fn nt_close(call: &Call) -> Result<u64, KernelError> {
        Ok(close::close(call.arg(1), None)? as u64)
    }

    pub static GROUP: Group = Group {
        name: "close",
        names: &["NtClose"],
        handlers: &[nt_close],
        data_exports: &[],
    };
}

pub mod query_object {
    //! ZwQueryObject — `win32/ntoskrnl/query-object.js`: a consulta de objetos
    //! dos provedores reais.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::ob::query_object;
    use crate::rtl::KernelError;

    fn query(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(query_object::query(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5))?))
    }

    pub static GROUP: Group = Group { name: "query-object", names: &["ZwQueryObject"], handlers: &[query], data_exports: &[] };
}

pub mod query_security {
    //! ZwQuerySecurityObject — `ntos/ob/query-security`; falha interna interrompe
    //! o sistema.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::ntos::ob::query_security;
    use crate::rtl::KernelError;

    fn query(call: &Call) -> Result<u64, KernelError> {
        fatal_unless_transfer("query-security", query_security::query(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5))).map(|status| status as u64)
    }

    pub static GROUP: Group = Group { name: "query-security", names: &["ZwQuerySecurityObject"], handlers: &[query], data_exports: &[] };
}

pub mod ob_object_lifecycle {
    use alloc::collections::BTreeMap;
    use alloc::string::String;

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::inc::nt_abi::object_attributes;
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::mm::kernel_data;
    use crate::ntos::ob::exports::{reference_object_by_handle, security_descriptor};
    use crate::ntos::ob::object_manager::{self, ObjectData};
    use crate::ntos::ob::{close, handle_ids, object_access, object_types, open_pointer, reference_trace};
    use crate::ntos::ps::process;
    use crate::ntos::rtl::guest_strings;
    use crate::rtl::{KernelError, SpinLock};

    const STATUS_SUCCESS: u32 = 0;
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
    const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
    const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
    const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;

    const OBJ_KERNEL_HANDLE: u32 = 0x200;
    const DUPLICATE_CLOSE_SOURCE: u32 = 0x0000_0001;
    const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;
    const KERNEL_HANDLE_MASK: u64 = 0xFFFF_FFFF_8000_0000;

    /// Create-info captured by ObCreateObject, consumed by ObInsertObject or
    /// freed by ObDeleteCapturedInsertInfo. Keyed by the object body pointer.
    #[derive(Clone)]
    struct Captured {
        type_pointer: u64,
        type_name: String,
        name: Option<String>,
        attributes: u32,
    }

    /// One published dxgkrnl object handle (the body plus its granted access).
    #[derive(Clone)]
    struct DxHandle {
        body: u64,
        type_pointer: u64,
        type_name: String,
        access: u32,
        attributes: u32,
        owner: u64,
        kernel: bool,
    }

    static CAPTURED: SpinLock<BTreeMap<u64, Captured>> = SpinLock::new(BTreeMap::new());
    static HANDLES: SpinLock<BTreeMap<u64, DxHandle>> = SpinLock::new(BTreeMap::new());

    fn kernel_handle(id: u32) -> u64 {
        KERNEL_HANDLE_MASK | id as u64
    }

    fn is_kernel_value(handle: u64) -> bool {
        handle & KERNEL_HANDLE_MASK == KERNEL_HANDLE_MASK && !(-6..=-1).contains(&(handle as i64))
    }

    /// ObjectType of a dxgkrnl body still in CAPTURED or already in HANDLES.
    fn dx_type(body: u64) -> Option<object_types::ObjectType> {
        if let Some(cap) = CAPTURED.lock().get(&body) {
            return object_types::find(cap.type_pointer);
        }
        let pointer = HANDLES.lock().values().find(|entry| entry.body == body).map(|entry| entry.type_pointer)?;
        object_types::find(pointer)
    }

    // --- ObCreateObjectType ---------------------------------------------------
    // NTSTATUS ObCreateObjectType(PUNICODE_STRING Name,
    //   POBJECT_TYPE_INITIALIZER Init, PSECURITY_DESCRIPTOR Sd, POBJECT_TYPE *Type)
    //
    // Faithful wrapper over object_types::define (the public form of the private
    // create()). The INITIALIZER mirrors the 0xD8 body window: Length/flags in
    // the first dword, GENERIC_MAPPING at +0x0C, ValidAccessMask at +0x1C.
    fn create_object_type(call: &Call) -> Result<u64, KernelError> {
        let (name_ptr, init, out) = (call.arg(1), call.arg(2), call.arg(4));
        if init == 0 || name_ptr == 0 {
            return Ok(signed_status(STATUS_INVALID_PARAMETER));
        }
        let name = guest_strings::read_unicode_string(name_ptr);
        if name.is_empty() {
            return Ok(signed_status(STATUS_INVALID_PARAMETER));
        }
        let header = guest::read32(init);
        let flags = (header >> 16) as u16;
        let mapping = [
            guest::read32(init + 0x0C),
            guest::read32(init + 0x10),
            guest::read32(init + 0x14),
            guest::read32(init + 0x18),
        ];
        let valid = guest::read32(init + 0x1C);
        match object_types::define(&name, mapping, valid, flags) {
            Ok(info) => {
                if out != 0 {
                    guest::write64(out, info.pointer);
                }
                Ok(signed_status(STATUS_SUCCESS))
            }
            Err(_) => Ok(signed_status(STATUS_OBJECT_NAME_COLLISION)),
        }
    }

    // --- ObCreateObject -------------------------------------------------------
    // NTSTATUS ObCreateObject(KPROCESSOR_MODE ProbeMode, POBJECT_TYPE Type,
    //   POBJECT_ATTRIBUTES Attr, KPROCESSOR_MODE OwnerMode, PVOID Reserved,
    //   ULONG BodySize, ULONG PagedCharge, ULONG NonPagedCharge, PVOID *Object)
    //
    // Allocates the object body, counts it on its type, and captures the
    // OBJECT_ATTRIBUTES for a later ObInsertObject (RVA 0x7022d0 ->
    // ObpAllocateObject stashes the captured create-info in the header).
    fn create_object(call: &Call) -> Result<u64, KernelError> {
        let (type_ptr, attr, body_size, out) = (call.arg(2), call.arg(3), call.arg(6) as u32, call.arg(9));
        let Some(object_type) = object_types::find(type_ptr) else {
            return Ok(signed_status(STATUS_INVALID_PARAMETER));
        };
        let body = guest::alloc_bytes(body_size.max(1) as u64);
        if body == 0 {
            return Ok(signed_status(STATUS_INSUFFICIENT_RESOURCES));
        }
        let (name, attributes) = if attr != 0 {
            let name_us = guest::read64(attr + object_attributes::OBJECT_NAME);
            let name = (name_us != 0).then(|| guest_strings::read_unicode_string(name_us)).filter(|name| !name.is_empty());
            (name, guest::read32(attr + object_attributes::ATTRIBUTES))
        } else {
            (None, 0)
        };
        // Count the new object on its type (ObpAllocateObject bumps TotalNumberOfObjects).
        let _ = object_types::account(&object_type.name, 1, 0);
        CAPTURED.lock().insert(body, Captured { type_pointer: type_ptr, type_name: object_type.name, name, attributes });
        if out != 0 {
            guest::write64(out, body);
        }
        Ok(signed_status(STATUS_SUCCESS))
    }

    // --- ObInsertObject -------------------------------------------------------
    // NTSTATUS ObInsertObject(PVOID Object, PACCESS_STATE AccessState,
    //   ACCESS_MASK DesiredAccess, ULONG Bias, PVOID *NewObject, PHANDLE Handle)
    //
    // Consumes the ObCreateObject create-info, inserts a named body into the
    // namespace (best-effort, so the name is visible), and opens a handle in the
    // current (or System, for OBJ_KERNEL_HANDLE) table.
    fn insert_object(call: &Call) -> Result<u64, KernelError> {
        let (object, desired, new_object_out, handle_out) = (call.arg(1), call.arg(3) as u32, call.arg(5), call.arg(6));
        let Some(cap) = CAPTURED.lock().remove(&object) else {
            return Ok(signed_status(STATUS_INVALID_PARAMETER));
        };
        let kernel = cap.attributes & OBJ_KERNEL_HANDLE != 0;

        // Best-effort namespace insertion for a fully-qualified name (\Dir\Leaf).
        if let Some(name) = cap.name.as_deref() {
            let trimmed = name.strip_prefix('\\').unwrap_or(name);
            let (parent, leaf) = trimmed.rsplit_once('\\').unwrap_or(("", trimmed));
            if !leaf.is_empty() {
                let parent_path = alloc::format!("\\{parent}");
                let _ = object_manager::create_object(&parent_path, leaf, &cap.type_name, Some(ObjectData::pointer(object)));
            }
        }

        let id = handle_ids::allocate(4)?;
        let handle = if kernel { kernel_handle(id) } else { id as u64 };
        let owner = if kernel { process::get_system_process() } else { process::get_current_process() };
        // Count the handle on the type (ObpIncrementHandleCount).
        let _ = object_types::account(&cap.type_name, 0, 1);
        HANDLES.lock().insert(handle, DxHandle { body: object, type_pointer: cap.type_pointer, type_name: cap.type_name, access: desired, attributes: cap.attributes & 7, owner, kernel });
        if new_object_out != 0 {
            guest::write64(new_object_out, object);
        }
        if handle_out != 0 {
            guest::write64(handle_out, handle);
        }
        Ok(signed_status(STATUS_SUCCESS))
    }

    // --- ObDeleteCapturedInsertInfo -------------------------------------------
    // VOID ObDeleteCapturedInsertInfo(PVOID Object): frees the captured
    // create-info when a created object is NOT inserted; undoes the object count.
    fn delete_captured_insert_info(call: &Call) -> Result<u64, KernelError> {
        if let Some(cap) = CAPTURED.lock().remove(&call.arg(1)) {
            let _ = object_types::account(&cap.type_name, -1, 0);
        }
        Ok(0)
    }

    // --- ObReferenceObjectByHandleWithTag -------------------------------------
    // NTSTATUS ObReferenceObjectByHandleWithTag(HANDLE, ACCESS_MASK, POBJECT_TYPE,
    //   KPROCESSOR_MODE, ULONG Tag, PVOID *Object, POBJECT_HANDLE_INFORMATION)
    //
    // The tag is diagnostic only. dxgkrnl objects resolve through HANDLES; every
    // other handle forwards to the existing ObReferenceObjectByHandle core (the
    // real export merely shuffles the tag arg and calls the shared routine).
    /// O handle está na tabela de quem chama? Handles de kernel ficam na tabela
    /// do System e valem em qualquer contexto; um handle de usuário só existe
    /// na tabela do processo dono — como no NT, outro processo não o enxerga
    /// (e recebe STATUS_INVALID_HANDLE pelo caminho comum do Object Manager).
    fn visible(entry: &DxHandle) -> bool {
        entry.kernel || entry.owner == process::get_current_process()
    }

    fn reference_object_by_handle_with_tag(call: &Call) -> Result<u64, KernelError> {
        let (handle, access, object_type, mode, tag, out, info) =
            (call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u8, call.arg(5) as u32, call.arg(6), call.arg(7));
        if let Some(entry) = HANDLES.lock().get(&handle).cloned().filter(visible) {
            if object_type != 0 && object_type != entry.type_pointer {
                return Ok(signed_status(STATUS_OBJECT_TYPE_MISMATCH));
            }
            if mode != 0 && access & !entry.access != 0 {
                return Ok(signed_status(STATUS_ACCESS_DENIED));
            }
            reference_trace::record(entry.body, tag, 1);
            let _ = object_types::account(&entry.type_name, 1, 0);
            guest::write64(out, entry.body);
            if info != 0 {
                guest::write32(info, entry.attributes);
                guest::write32(info + 4, entry.access);
            }
            return Ok(signed_status(STATUS_SUCCESS));
        }
        // ObReferenceObjectByHandle(handle, access, type, mode, out, info).
        let forwarded = Call {
            args: [handle, access as u64, object_type, mode as u64, out, info, 0, 0, 0, 0, 0, 0, 0, 0],
            return_address: call.return_address,
            frame: call.frame,
            context: call.context,
        };
        reference_object_by_handle(&forwarded)
    }

    // --- ObCheckObjectAccess --------------------------------------------------
    // BOOLEAN ObCheckObjectAccess(PVOID Object, PSECURITY_SUBJECT_CONTEXT,
    //   BOOLEAN LockHeld, KPROCESSOR_MODE Mode, PACCESS_MASK GrantedAccess,
    //   PNTSTATUS Status). GrantedAccess is in/out (desired on entry, granted
    //   on exit). Wraps object_access::check against the type generic-mapping.
    fn check_object_access(call: &Call) -> Result<u64, KernelError> {
        let (object, mode, granted_out, status_out) = (call.arg(1), call.arg(4) as u8, call.arg(5), call.arg(6));
        let desired = if granted_out != 0 { guest::read32(granted_out) } else { 0 };
        let (object_type, policy) = if let Some(described) = open_pointer::describe(object) {
            (described.object_type.clone(), described.owner.security(object))
        } else if let Some(object_type) = object_types::bound(object).or_else(|| dx_type(object)) {
            (object_type, object_access::capture(None))
        } else {
            if status_out != 0 {
                guest::write32(status_out, STATUS_INVALID_HANDLE);
            }
            return Ok(0);
        };
        match object_access::check(&policy, object_access::subject(), desired, &object_type, mode == 0) {
            Ok(granted) => {
                if granted_out != 0 {
                    guest::write32(granted_out, granted);
                }
                if status_out != 0 {
                    guest::write32(status_out, STATUS_SUCCESS);
                }
                Ok(1)
            }
            Err(status) => {
                if granted_out != 0 {
                    guest::write32(granted_out, 0);
                }
                if status_out != 0 {
                    guest::write32(status_out, status);
                }
                Ok(0)
            }
        }
    }

    // --- ObGetObjectSecurity --------------------------------------------------
    // NTSTATUS ObGetObjectSecurity(PVOID Object, PSECURITY_DESCRIPTOR *Sd,
    //   PBOOLEAN MemoryAllocated). Returns the side-table SD; nothing is
    //   allocated, so MemoryAllocated is FALSE (pairs with ObReleaseObjectSecurity).
    fn get_object_security(call: &Call) -> Result<u64, KernelError> {
        let (object, sd_out, allocated_out) = (call.arg(1), call.arg(2), call.arg(3));
        let sd = security_descriptor(object).unwrap_or(0);
        if sd_out != 0 {
            guest::write64(sd_out, sd);
        }
        if allocated_out != 0 {
            guest::write8(allocated_out, 0);
        }
        Ok(signed_status(STATUS_SUCCESS))
    }

    // --- ObReleaseObjectSecurity ----------------------------------------------
    // VOID ObReleaseObjectSecurity(PSECURITY_DESCRIPTOR Sd, BOOLEAN MemoryAllocated).
    fn release_object_security(call: &Call) -> Result<u64, KernelError> {
        let (sd, allocated) = (call.arg(1), call.arg(2) & 0xFF != 0);
        if allocated && sd != 0 {
            guest::free_bytes(sd);
        }
        Ok(0)
    }

    // --- ObDuplicateObject ----------------------------------------------------
    // NTSTATUS ObDuplicateObject(PEPROCESS Source, HANDLE SourceHandle,
    //   PEPROCESS Target, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess,
    //   ULONG HandleAttributes, ULONG Options, KPROCESSOR_MODE Mode)
    //
    // Minimal cross-process path over the dxgkrnl handle table: resolve the
    // source body, publish a new handle owned by Target, honor
    // DUPLICATE_SAME_ACCESS / DUPLICATE_CLOSE_SOURCE. Standard (Object-Manager)
    // handles are not duplicated here — see LIMITATIONS.
    fn duplicate_object(call: &Call) -> Result<u64, KernelError> {
        let (source_handle, target_process, target_handle_out, desired, handle_attributes, options) =
            (call.arg(2), call.arg(3), call.arg(4), call.arg(5) as u32, call.arg(6) as u32, call.arg(7) as u32);
        let Some(entry) = HANDLES.lock().get(&source_handle).cloned().filter(visible) else {
            return Ok(signed_status(STATUS_INVALID_HANDLE));
        };
        let access = if options & DUPLICATE_SAME_ACCESS != 0 { entry.access } else { desired };
        let kernel = handle_attributes & OBJ_KERNEL_HANDLE != 0 || entry.kernel;
        let id = handle_ids::allocate(4)?;
        let handle = if kernel { kernel_handle(id) } else { id as u64 };
        let owner = if kernel {
            process::get_system_process()
        } else if target_process != 0 {
            target_process
        } else {
            process::get_current_process()
        };
        let _ = object_types::account(&entry.type_name, 0, 1);
        HANDLES.lock().insert(handle, DxHandle { body: entry.body, type_pointer: entry.type_pointer, type_name: entry.type_name.clone(), access, attributes: handle_attributes & 7, owner, kernel });
        if options & DUPLICATE_CLOSE_SOURCE != 0 {
            if let Some(source) = HANDLES.lock().remove(&source_handle) {
                let _ = object_types::account(&source.type_name, 0, -1);
            }
        }
        if target_handle_out != 0 {
            guest::write64(target_handle_out, handle);
        }
        Ok(signed_status(STATUS_SUCCESS))
    }

    // --- ObIsKernelHandle -----------------------------------------------------
    // BOOLEAN ObIsKernelHandle(HANDLE Handle): the kernel-handle bit is set and
    // the handle is not a pseudo-handle (-1..-6).
    fn is_kernel_handle(call: &Call) -> Result<u64, KernelError> {
        Ok(is_kernel_value(call.arg(1)) as u64)
    }

    // --- ObCloseHandle --------------------------------------------------------
    // NTSTATUS ObCloseHandle(HANDLE Handle, KPROCESSOR_MODE Mode): same path as
    // NtClose with an explicit mode. dxgkrnl handles leave the local table;
    // everything else delegates to close::close.
    fn close_handle(call: &Call) -> Result<u64, KernelError> {
        let (handle, mode) = (call.arg(1), call.arg(2) as u8);
        // Só fecha um handle da tabela de quem chama; o de outro processo segue
        // para o close comum, que o recusa.
        let removed = {
            let mut handles = HANDLES.lock();
            match handles.get(&handle) {
                Some(entry) if visible(entry) => handles.remove(&handle),
                _ => None,
            }
        };
        if let Some(entry) = removed {
            let _ = object_types::account(&entry.type_name, 0, -1);
            return Ok(signed_status(STATUS_SUCCESS));
        }
        Ok(signed_status(close::close(handle, Some(mode))?))
    }

    // --- object-type pointer DATA exports (heap-populated kdata cells) ---------
    fn io_device_object_type() -> u64 {
        kernel_data::address("IoDeviceObjectType").unwrap_or_else(|error| panic!("IoDeviceObjectType: {error}"))
    }
    fn ex_semaphore_object_type() -> u64 {
        kernel_data::address("ExSemaphoreObjectType").unwrap_or_else(|error| panic!("ExSemaphoreObjectType: {error}"))
    }
    fn lpc_port_object_type() -> u64 {
        kernel_data::address("LpcPortObjectType").unwrap_or_else(|error| panic!("LpcPortObjectType: {error}"))
    }

    pub static GROUP: Group = Group {
        name: "ob-object-lifecycle",
        names: &[
            "ObCreateObjectType",
            "ObCreateObject",
            "ObInsertObject",
            "ObDeleteCapturedInsertInfo",
            "ObReferenceObjectByHandleWithTag",
            "ObCheckObjectAccess",
            "ObGetObjectSecurity",
            "ObReleaseObjectSecurity",
            "ObDuplicateObject",
            "ObIsKernelHandle",
            "ObCloseHandle",
        ],
        handlers: &[
            create_object_type,
            create_object,
            insert_object,
            delete_captured_insert_info,
            reference_object_by_handle_with_tag,
            check_object_access,
            get_object_security,
            release_object_security,
            duplicate_object,
            is_kernel_handle,
            close_handle,
        ],
        data_exports: &[
            ("IoDeviceObjectType", io_device_object_type),
            ("ExSemaphoreObjectType", ex_semaphore_object_type),
            ("LpcPortObjectType", lpc_port_object_type),
        ],
    };
}

// =============================================================================
