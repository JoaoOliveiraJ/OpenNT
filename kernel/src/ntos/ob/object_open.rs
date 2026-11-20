//! Abertura de objetos por nome — ObOpenObjectByName (a abertura por
//! ponteiro é `open_pointer`).
//!
//! O nome dos OBJECT_ATTRIBUTES resolve no namespace; callbacks do Ex,
//! seções e drivers abrem o handle pelo próprio dono, e o restante recebe um
//! handle do Object Manager. Devolve o valor de retorno do export, com o
//! NTSTATUS já estendido para 64 bits do jeito que o export o entrega.
//!
//! Como no ObpLookupObjectName, quando a busca chega a um objeto que não é
//! diretório e cujo tipo tem ParseProcedure (o RootDirectory ou um prefixo
//! do caminho absoluto), o resto do nome vai à rotina do tipo: a
//! WindowStation do win32k cria e abre as Desktops assim (o
//! ExpWin32ParseProcedure, `ex/win32.rs`). A rotina recebe o nome completo e
//! o restante numa cópia do kernel terminada em NUL (o ParseWindowStation
//! anda sobre o Buffer e tira a barra inicial do restante no lugar), o
//! ACCESS_STATE de quem chama ou um local (SeCreateAccessState com o
//! mapeamento do tipo pedido), o ParseContext e o SecurityQualityOfService
//! dos atributos; o objeto que ela devolve, referenciado, recebe o handle
//! (ObpCreateHandle com ObOpenHandle) e a referência da busca é solta.

use crate::ntos::ex::callbacks as executive_callbacks;
use crate::ntos::inc::types::{Field, NtStruct, ObjectAttributes, UnicodeString};
use crate::ntos::init::exports::signed_status;
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::ob::object_reference::{native_pointer_of_node, reference_device, type_differs};
use crate::ntos::ob::object_header;
use crate::ntos::ob::object_types;
use crate::ntos::ob::objects::{driver as driver_objects, section as section_objects};
use crate::ntos::mm::guest_memory as guest;
use alloc::string::String;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

const NAME_NOT_FOUND: u32 = 0xC000_0034;
const TYPE_MISMATCH: u32 = 0xC000_0024;
const ACCESS_DENIED: u32 = 0xC000_0022;
const ACCESS_VIOLATION: u32 = 0xC000_0005;
const INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// Saída escalar (`PVOID*`, `PHANDLE`, `PULONG`...) de um chamador de kernel.
fn out<T: Copy>(address: u64) -> &'static Field<T> {
    // SAFETY: ponteiro de saída fornecido por um chamador de kernel.
    unsafe { Field::<T>::at(address) }
}

/// Abre um callback do Ex pelos atributos já capturados.
fn open_callback(captured_node: NodeId, flags: u32, object_type: u64, access: u32, mode: u8, output: u64) -> Result<u64, KernelError> {
    if type_differs(object_type, object_types::callback_type().pointer) {
        return Ok(signed_status(TYPE_MISMATCH));
    }
    let target = object_manager::node(captured_node).and_then(|node| node.data).map_or(0, |data| data.native_pointer);
    match executive_callbacks::open_handle(target, access, flags, mode != 0)? {
        Ok(handle) => {
            out::<u64>(output).set(handle);
            Ok(0)
        }
        Err(status) => Ok(status as u64),
    }
}

/// O objeto do handle `root`, de qualquer tabela, referenciado no modo de
/// quem chama.
fn reference_root(root: u64, mode: u8) -> Option<u64> {
    let slot = guest::alloc_bytes(8);
    let status = crate::ntos::ob::object_reference::reference_by_handle(root, 0, 0, mode, slot, 0).ok()? as u32;
    let pointer = guest::read64(slot);
    guest::free_bytes(slot);
    (status & 0x8000_0000 == 0 && pointer != 0).then_some(pointer)
}

/// A ParseProcedure do tipo de um objeto com OBJECT_HEADER que não é
/// diretório (0 = sem rotina).
fn parse_routine(object: u64) -> u64 {
    if object == 0 || !object_header::is_object(object) {
        return 0;
    }
    let Some(object_type) = object_header::object_type(object) else { return 0 };
    if object_type == object_types::directory_type().pointer {
        return 0;
    }
    object_types::type_object(object_type).map_or(0, |info| info.type_info.parse_procedure.get())
}

/// O objeto de parse e o índice (em unidades UTF-16) do restante do nome:
/// o RootDirectory com ParseProcedure (o nome todo é o restante) ou, num
/// caminho absoluto que o namespace não resolve inteiro, o prefixo mais
/// longo que resolve, se ele for um objeto com ParseProcedure (o restante
/// começa na barra). O objeto volta referenciado.
fn parse_target(root: u64, units: &[u16], mode: u8) -> Option<(u64, usize)> {
    if root != 0 {
        let object = reference_root(root, mode)?;
        if parse_routine(object) == 0 {
            let _ = crate::ntos::ob::object_reference::dereference_with_tag(object, crate::ntos::ob::reference_trace::DEFAULT_TAG, false);
            return None;
        }
        return Some((object, 0));
    }
    if units.first() != Some(&(b'\\' as u16)) || object_manager::lookup(&String::from_utf16_lossy(units)).is_some() {
        return None;
    }
    let cut = (1..units.len()).rev().find(|&index| units[index] == b'\\' as u16 && object_manager::lookup(&String::from_utf16_lossy(&units[..index])).is_some())?;
    let object = native_pointer_of_node(object_manager::lookup(&String::from_utf16_lossy(&units[..cut])));
    if parse_routine(object) == 0 {
        return None;
    }
    object_header::reference(object, 1);
    Some((object, cut))
}

/// O caminho da ParseProcedure do ObOpenObjectByName; `None` quando o nome
/// não chega a um objeto com a rotina (segue a busca do namespace).
fn open_through_parse(attributes_pointer: u64, object_type: u64, mode: u8, access_state: u64, access: u32, parse_context: u64, output: u64) -> Result<Option<u64>, KernelError> {
    use crate::ntos::inc::types::{AccessState, AuxAccessData, UnicodeString};
    // SAFETY: OBJECT_ATTRIBUTES de um chamador de kernel (ObOpenObjectByName).
    let attributes = unsafe { ObjectAttributes::at(attributes_pointer) };
    let name_pointer = attributes.object_name.get();
    let units = if name_pointer != 0 { guest_strings::try_read_unicode_units(name_pointer).unwrap_or_default() } else { alloc::vec::Vec::new() };
    let Some((parse_object, start)) = parse_target(attributes.root_directory.get(), &units, mode) else { return Ok(None) };
    let flags = attributes.attributes.get();
    let qos = attributes.security_quality_of_service.get();
    // O nome completo e o restante numa cópia do kernel terminada em NUL.
    let bytes = units.len() as u64 * 2;
    let buffer = guest::alloc_bytes(bytes + 2);
    let strings = guest::alloc_bytes(UnicodeString::SIZE * 2);
    let object_cell = guest::alloc_bytes(8);
    let mut text: alloc::vec::Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    text.extend_from_slice(&[0, 0]);
    guest::write_bytes(buffer, &text);
    let (complete, remaining) = (strings, strings + UnicodeString::SIZE);
    guest_strings::write_string_fields(complete, bytes as u16, bytes as u16 + 2, buffer);
    let rest = bytes - start as u64 * 2;
    guest_strings::write_string_fields(remaining, rest as u16, rest as u16 + 2, buffer + start as u64 * 2);
    guest::write64(object_cell, 0);
    // O ACCESS_STATE de quem chama, ou um local com o mapeamento do tipo.
    let mut local = None;
    let state = if access_state != 0 {
        access_state
    } else {
        let (state, aux) = (guest::alloc_bytes(AccessState::SIZE), guest::alloc_bytes(AuxAccessData::SIZE));
        let mapping = object_types::type_object(object_type).map(|info| &info.type_info.generic_mapping);
        // SAFETY: blocos recém-alocados do tamanho dos tipos.
        let created = unsafe { crate::ntos::se::access_state::create(crate::ntos::ps::process::get_current_thread(), crate::ntos::ps::process::get_current_process(), AccessState::at(state), AuxAccessData::at(aux), access, mapping) };
        local = Some((state, aux, matches!(created, Ok(0))));
        state
    };
    let parse_type = object_header::object_type(parse_object).unwrap_or(0);
    let status = crate::ntos::ob::type_procedures::parse(parse_type, parse_object, object_type, state, mode, flags, complete, remaining, parse_context, qos, object_cell).unwrap_or(NAME_NOT_FOUND);
    let _ = crate::ntos::ob::object_reference::dereference_with_tag(parse_object, crate::ntos::ob::reference_trace::DEFAULT_TAG, false);
    let found = guest::read64(object_cell);
    let result = if status & 0x8000_0000 != 0 {
        status
    } else if found == 0 {
        NAME_NOT_FOUND
    } else {
        let opened = if type_differs(object_type, object_header::object_type(found).unwrap_or(0)) { Ok(TYPE_MISMATCH) } else { crate::ntos::ob::open_pointer::open(found, flags, state, access, object_type, mode, output) };
        let _ = crate::ntos::ob::object_reference::dereference_with_tag(found, crate::ntos::ob::reference_trace::DEFAULT_TAG, false);
        match opened? {
            0 => {
                observe_parsed(parse_object, &units[start..], found);
                status
            }
            failure => failure,
        }
    };
    if let Some((state, aux, created)) = local {
        if created {
            // SAFETY: o ACCESS_STATE criado acima.
            let _ = crate::ntos::se::access_state::delete(unsafe { AccessState::at(state) });
        }
        guest::free_bytes(state);
        guest::free_bytes(aux);
    }
    for block in [buffer, strings, object_cell] {
        guest::free_bytes(block);
    }
    Ok(Some(signed_status(result)))
}

/// Observação do boot do smss: uma Desktop aberta pela ParseProcedure de
/// uma WindowStation vai a `initial_process::desktop_opened` com o nome da
/// WindowStation (o componente final do NameInfo) e o da Desktop.
fn observe_parsed(parse_object: u64, remaining: &[u16], found: u64) {
    use crate::ntos::inc::types::ObjectHeaderNameInfo;
    if !crate::ntos::init::boot_config::smss_boot() || object_header::object_type(found) != Some(crate::ntos::mm::kernel_data::read("ExDesktopObjectType")) {
        return;
    }
    let info = object_header::name_info(parse_object);
    if info == 0 {
        return;
    }
    // SAFETY: o NameInfo do cabeçalho da WindowStation.
    let station = guest_strings::try_read_unicode_string(unsafe { ObjectHeaderNameInfo::at(info) }.name.address()).unwrap_or_default();
    let desktop = String::from_utf16_lossy(remaining);
    crate::ntos::init::initial_process::desktop_opened(station.rsplit('\\').next().unwrap_or(""), desktop.trim_start_matches('\\'));
}

/// OBJECT_ATTRIBUTES de modo usuário copiados para o kernel (o caminho
/// inteiro, sem RootDirectory): o OA, o UNICODE_STRING e o texto num bloco,
/// que o chamador libera. Os NtOpen* de modo usuário passam este bloco ao
/// ObOpenObjectByName.
pub fn capture_user_attributes(attributes: u64) -> Result<u64, u32> {
    use crate::ntos::ps::user::registry::{parse_user_object_attributes, user_object_attributes};
    let Some(parsed) = parse_user_object_attributes(attributes) else { return Err(ACCESS_VIOLATION) };
    let flags = user_object_attributes(attributes).map_err(|error| if error.status != 0 { error.status } else { ACCESS_VIOLATION })?;
    let wide: alloc::vec::Vec<u8> = parsed.path.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let block = guest::alloc_bytes(ObjectAttributes::SIZE + UnicodeString::SIZE + wide.len() as u64 + 2);
    if block == 0 {
        return Err(INSUFFICIENT_RESOURCES);
    }
    let name = block + ObjectAttributes::SIZE;
    let text = name + UnicodeString::SIZE;
    guest::write_bytes(block, &[0u8; (ObjectAttributes::SIZE + UnicodeString::SIZE) as usize]);
    guest::write_bytes(text, &wide);
    // SAFETY: o bloco recém-alocado do kernel, do tamanho dos dois tipos.
    let (object, string) = unsafe { (ObjectAttributes::at(block), UnicodeString::at(name)) };
    string.length.set(wide.len() as u16);
    string.maximum_length.set(wide.len() as u16);
    string.buffer.set(text);
    object.length.set(ObjectAttributes::SIZE as u32);
    object.object_name.set(name);
    object.attributes.set(flags);
    Ok(block)
}

/// ObOpenObjectByName sem ACCESS_STATE nem ParseContext.
pub fn open_by_name(attributes_pointer: u64, object_type: u64, mode: u8, access: u32, output: u64) -> Result<u64, KernelError> {
    open_by_name_ex(attributes_pointer, object_type, mode, 0, access, 0, output)
}

/// ObOpenObjectByName (7 argumentos): handle para o objeto nomeado em
/// `attributes_pointer` (OBJECT_ATTRIBUTES).
pub fn open_by_name_ex(attributes_pointer: u64, object_type: u64, mode: u8, access_state: u64, access: u32, parse_context: u64, output: u64) -> Result<u64, KernelError> {
    if let Some(result) = open_through_parse(attributes_pointer, object_type, mode, access_state, access, parse_context, output)? {
        return Ok(result);
    }
    if let Ok(captured) = executive_callbacks::attributes(attributes_pointer) {
        if let Some(node) = captured.node.filter(|&node| object_manager::node(node).is_some_and(|node| node.type_name == "Callback")) {
            return open_callback(node, captured.flags, object_type, access, mode, output);
        }
    }
    // SAFETY: OBJECT_ATTRIBUTES de um chamador de kernel (ObOpenObjectByName).
    let attributes = unsafe { ObjectAttributes::at(attributes_pointer) };
    let name = guest_strings::read_unicode_string(attributes.object_name.get());
    let node = object_manager::lookup(&name);
    let pointer = native_pointer_of_node(node);
    if pointer == 0 {
        // Um diretório do namespace (sem corpo com OBJECT_HEADER aqui)
        // aberto com outro tipo é STATUS_OBJECT_TYPE_MISMATCH, como o nome
        // achado com outro tipo no NT, não um nome ausente.
        let directory = node.and_then(object_manager::node).is_some_and(|snapshot| snapshot.type_name == "Directory");
        if directory && type_differs(object_type, object_types::directory_type().pointer) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
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
    let attributes = attributes.attributes.get();
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
        out::<u64>(output).set(handle);
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
        out::<u64>(output).set(handle);
        return Ok(0);
    }
    // Um objeto com OBJECT_HEADER abre pelo ObOpenObjectByPointer (ObOpenHandle).
    if crate::ntos::ob::object_header::is_object(pointer) {
        if type_differs(object_type, crate::ntos::ob::object_header::object_type(pointer).unwrap_or(0)) {
            return Ok(signed_status(TYPE_MISMATCH));
        }
        return Ok(signed_status(crate::ntos::ob::open_pointer::open(pointer, attributes, 0, access, object_type, mode, output)?));
    }
    reference_device(pointer)?;
    let handle = object_manager::open(&name)?;
    out::<u64>(output).set(handle as u64);
    Ok(0)
}
