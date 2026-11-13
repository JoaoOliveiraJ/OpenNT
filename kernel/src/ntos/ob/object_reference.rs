//! Referências a objetos — ObReferenceObject/ObDereferenceObject (com e sem
//! tag), ObReferenceObjectByName, ObReferenceObjectByHandle(WithTag) e
//! ObReferenceObjectByPointer.
//!
//! Retém e solta pelo dono real de cada corpo (namespace, despachante,
//! callbacks do Ex, contextos de silo, tokens, seções, drivers, arquivos,
//! processos, threads e dispositivos), por nome, handle ou ponteiro. Os
//! handles de modo usuário (tokens e seções da tabela de usuário) entram com
//! o estado de modo usuário (fase 7).
//!
//! As rotinas `reference_by_*` devolvem o valor de retorno do export, com o
//! NTSTATUS já estendido para 64 bits do jeito que o export o entrega.

use alloc::format;
use core::sync::atomic::Ordering;

use crate::ntos::ex::callbacks as executive_callbacks;
use crate::ntos::inc::types::{DeviceObject, Field, NtStruct, ObjectHandleInformation};
use crate::ntos::init::exports::signed_status;
use crate::ntos::io::file::zw as zw_files;
use crate::ntos::io::io_manager;
use crate::ntos::ob::handles::inserted;
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::ob::objects::{device as device_objects, dispatcher as dispatcher_objects, driver as driver_objects, file as file_objects, namespace as namespace_objects, section as section_objects};
use crate::ntos::ob::{object_types, open_pointer, reference_trace};
use crate::ntos::ps::silo::contexts as silo_contexts;
use crate::ntos::ps::{kernel_threads, process};
use crate::ntos::rtl::guest_strings;
use crate::ntos::se::token::{handles as token_handles, tokens};
use crate::rtl::KernelError;

const NAME_NOT_FOUND: u32 = 0xC000_0034;
const TYPE_MISMATCH: u32 = 0xC000_0024;
const ACCESS_DENIED: u32 = 0xC000_0022;
const INVALID_HANDLE: u32 = 0xC000_0008;

/// Saída escalar (`PVOID*`, `PHANDLE`, `PULONG`...) de um chamador de kernel.
fn out<T: Copy>(address: u64) -> &'static Field<T> {
    // SAFETY: ponteiro de saída fornecido por um chamador de kernel.
    unsafe { Field::<T>::at(address) }
}

/// Retém o dispositivo pelo dono que o conhece ou pelo contador nativo LONG
/// (InterlockedIncrement: devolve o valor novo).
///
/// O OpenNT não monta OBJECT_HEADER antes dos corpos: um ponteiro que
/// nenhum dono reconhece cai no DEVICE_OBJECT.ReferenceCount, que no NT é a
/// contagem de E/S do dispositivo — não o PointerCount do cabeçalho.
pub(crate) fn reference_device(pointer: u64) -> Result<u64, KernelError> {
    if let Some(count) = device_objects::reference(pointer)? {
        return Ok(count as u64);
    }
    // SAFETY: dispositivo legado fora do registro dos donos.
    let count = &unsafe { DeviceObject::at(pointer) }.reference_count;
    let value = count.atomic().fetch_add(1, Ordering::SeqCst).wrapping_add(1);
    Ok(value as i64 as u64)
}

/// InterlockedDecrement do contador nativo; devolve o valor novo.
fn dereference_device(pointer: u64) -> Result<u64, KernelError> {
    if let Some(count) = device_objects::dereference(pointer)? {
        return Ok(count as u64);
    }
    // SAFETY: dispositivo legado fora do registro dos donos.
    let count = &unsafe { DeviceObject::at(pointer) }.reference_count;
    let value = count.atomic().fetch_sub(1, Ordering::SeqCst).wrapping_sub(1);
    Ok(value as i64 as u64)
}

/// Corpo nativo de um objeto nomeado (Device, Driver, Section, Callback).
pub(crate) fn native_pointer_of_node(node: Option<NodeId>) -> u64 {
    let Some(snapshot) = node.and_then(object_manager::node) else { return 0 };
    let data = snapshot.data.unwrap_or_default();
    match snapshot.type_name.as_str() {
        "Device" => io_manager::device(snapshot.id).map(|entry| if entry.stack_top != 0 { entry.stack_top } else { entry.native_device }).unwrap_or(data.native_pointer),
        "Driver" | "Section" | "Callback" => data.native_pointer,
        _ => 0,
    }
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

pub(crate) fn type_differs(requested: u64, expected: u64) -> bool {
    requested != 0 && requested != expected
}

fn write_information(information: u64, attributes: u32, access: u32) {
    if information != 0 {
        // SAFETY: POBJECT_HANDLE_INFORMATION de um chamador de kernel.
        let information = unsafe { ObjectHandleInformation::at(information) };
        information.handle_attributes.set(attributes);
        information.granted_access.set(access);
    }
}

/// ObReferenceObjectByName (8 argumentos, com PACCESS_STATE opcional): o
/// nome é o UNICODE_STRING em `name`.
pub fn reference_by_name(name: u64, attributes: u32, access: u32, object_type: u64, mode: u8, output: u64) -> Result<u64, KernelError> {
    let name = guest_strings::read_unicode_string(name);
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
        out::<u64>(output).set(target);
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
        out::<u64>(output).set(pointer);
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
        out::<u64>(output).set(pointer);
        return Ok(0);
    }
    reference_device(pointer)?;
    if let Some(node) = node {
        object_manager::update_node(node, |node| node.refs += 1);
    }
    out::<u64>(output).set(pointer);
    Ok(0)
}

/// ObReferenceObjectByHandle(handle, access, type, mode, out, info).
pub fn reference_by_handle(handle: u64, access: u32, object_type: u64, mode: u8, output: u64, information: u64) -> Result<u64, KernelError> {
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
        out::<u64>(output).set(callback.native_pointer);
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
        out::<u64>(output).set(entry.native_pointer);
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
        out::<u64>(output).set(thread);
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
        out::<u64>(output).set(pointer);
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
        out::<u64>(output).set(pointer);
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
        out::<u64>(output).set(pointer);
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
        out::<u64>(output).set(data.native_pointer);
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
        out::<u64>(output).set(pointer);
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
        out::<u64>(output).set(pointer);
        write_information(information, 0, granted);
        return Ok(0);
    }
    reference_device(pointer)?;
    if let Some(node) = node {
        object_manager::update_node(node, |node| node.refs += 1);
    }
    out::<u64>(output).set(pointer);
    Ok(0)
}

/// ObReferenceObjectByHandleWithTag(handle, access, type, mode, tag, out,
/// info): a tag só alimenta o histórico. Os handles de objetos inseridos por
/// ObInsertObject resolvem na tabela deles; os demais seguem pelo núcleo de
/// ObReferenceObjectByHandle (o export real só reordena a tag e chama a
/// rotina compartilhada).
pub fn reference_by_handle_with_tag(handle: u64, access: u32, object_type: u64, mode: u8, tag: u32, output: u64, information: u64) -> Result<u64, KernelError> {
    if let Some(status) = inserted::reference(handle, access, object_type, mode, tag, output, information) {
        return Ok(signed_status(status));
    }
    reference_by_handle(handle, access, object_type, mode, output, information)
}

/// ObReferenceObjectByPointer(object, access, type, mode): em modo usuário
/// o tipo pedido precisa ser o do objeto.
pub fn reference_by_pointer(pointer: u64, object_type: u64, mode: u8) -> Result<u64, KernelError> {
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
