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
