//! Handles anexados a mensagens.
//!
//! Captura referências de objetos antes de entregar a mensagem; consultar
//! um índice duplica o objeto na tabela do dono da porta consultada.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::alpc::message::buffer as message_buffer;
use crate::ntos::alpc::message::identity::Retained;
use crate::ntos::ke::critical_region;
use crate::ntos::ob::callbacks::{self, Outcome, PerformOptions};
use crate::ntos::ob::object_types::ObjectType;
use crate::ntos::ob::open_pointer::{self, Described};
use crate::ntos::ob::objects::port::Port;
use crate::ntos::ob::{handle_table, object_access, object_manager};
use crate::ntos::ob::handles::process as process_handles;
use crate::ntos::ps::process;
use crate::ntos::ps::user::state;
use crate::ntos::se::token::handles as token_handles;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::alpc::message::buffer::read_field;
use crate::ntos::inc::types::{AlpcHandleAttr, AlpcHandleAttr32, AlpcMessageAttributes, NtStruct};
use core::mem::offset_of;

/// O código ALPC do tipo Token (`type_code`).
const TOKEN_TYPE: u32 = 0x200;

/// Códigos ALPC são máscaras por espécie, não índices dinâmicos de OBJECT_TYPE.
fn type_code(name: &str) -> Option<u32> {
    Some(match name {
        "File" => 1,
        "Thread" => 4,
        "Semaphore" => 8,
        "Event" => 0x10,
        "Process" => 0x20,
        "Mutant" => 0x40,
        "Section" => 0x80,
        "Key" => 0x100,
        "Token" => 0x200,
        "Composition" => 0x400,
        "Job" => 0x800,
        _ => return None,
    })
}

/// PspThreadOpen/PspProcessOpen concedem os direitos limitados implicados
/// por operações mais amplas; o valor publicado reflete essa normalização.
fn implied_access(object_type: &ObjectType, mut access: u32) -> u32 {
    if object_type.name == "Thread" {
        if access & 0x40 != 0 {
            access |= 0x800;
        }
        if access & 0x20 != 0 {
            access |= 0x400;
        }
        if access & 2 != 0 {
            access |= 0x1000;
        }
    } else if object_type.name == "Process" {
        if access & 0x400 != 0 || access & 0x28 == 0x28 {
            access |= 0x1000;
        }
        if access & 0x200 != 0 {
            access |= 0x2000;
        }
    }
    access
}

struct Descriptor {
    flags: u32,
    handle: u64,
    access: u32,
}

/// Objeto capturado com a retenção do corpo e do processo de origem.
pub struct Entry {
    pub item: Described,
    pub source_process: u64,
    pub access: u32,
    pub object_type: u32,
    pub attributes: u32,
}

fn failure(outcome: Outcome) -> Result<u32, KernelError> {
    match outcome.error {
        Some(error) if outcome.status == 0 => Err(error),
        _ => Ok(outcome.status),
    }
}

fn capture_entry(descriptor: &Descriptor, mode: u8) -> Result<Result<Entry, u32>, KernelError> {
    let handle = descriptor.handle;
    let pseudo = matches!(handle as i64, -1 | -2);
    let kernel_handle = handle & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000;
    let source_process = if mode != 0 { process::get_current_process() } else { process::get_system_process() };
    if !pseudo && mode != 0 && kernel_handle {
        return Ok(Err(0xC000_0008));
    }
    if !pseudo && !kernel_handle && handle > 0x7FFF_FFFF {
        return Ok(Err(0xC000_0008));
    }
    if descriptor.flags & 0x1_0000 == 0 && descriptor.access & 0x0CE0_0000 != 0 {
        return Ok(Err(0xC000_0022));
    }
    critical_region::enter_critical()?;
    let found = (|| -> Result<Result<Option<(Described, u32, u32)>, u32>, KernelError> {
        if pseudo {
            let pointer = if handle as i64 == -1 { process::get_current_process() } else { process::get_current_thread() };
            let Some(item) = open_pointer::describe(pointer) else { return Err(KernelError::new("ALPC pseudo-handle has no object owner")) };
            item.reference();
            let access = item.object_type.valid_access;
            return Ok(Ok(Some((item, access, 0))));
        }
        let table = process_handles::reference(source_process)?;
        if table == 0 {
            return Ok(Err(0xC000_010A));
        }
        let index = (handle & 0x7FFF_FFFC) as u32;
        let outcome = (|| {
            if process_handles::get(source_process) != Some(table) {
                return Err(KernelError::new("ALPC source table mismatch"));
            }
            handle_table::with_entry(table, index, |row| {
                let native = object_manager::handle_record(index);
                let matches = native.as_ref().is_some_and(|native| native.node == row.identity);
                if matches && native.as_ref().is_some_and(|native| native.options.kernel_handle != kernel_handle) {
                    return Ok(None);
                }
                if !matches && kernel_handle {
                    return Ok(None);
                }
                let item = open_pointer::describe(row.pointer).or_else(|| if row.native_body != 0 { open_pointer::describe(row.native_body) } else { None });
                let Some(item) = item else { return Err(KernelError::new("ALPC captured handle has no object owner")) };
                item.reference();
                Ok(Some((item, row.access, row.attributes)))
            })
        })();
        let _ = process_handles::release(source_process);
        Ok(Ok(outcome?.flatten()))
    })();
    let _ = critical_region::leave_critical();
    let (item, source_access, source_attributes) = match found? {
        Err(status) => return Ok(Err(status)),
        Ok(None) => return Ok(Err(0xC000_0008)),
        Ok(Some(found)) => found,
    };
    let mut retained = false;
    let result = (|| -> Result<Result<Entry, u32>, KernelError> {
        let Some(object_type) = type_code(&item.object_type.name) else { return Ok(Err(0xC000_0022)) };
        let desired = if descriptor.flags & 0x1_0000 != 0 { source_access } else { object_access::map_generic_access(descriptor.access, &item.object_type) & (item.object_type.valid_access | 0x0100_0000) };
        if desired & !source_access != 0 {
            return Ok(Err(0xC000_0022));
        }
        let options = PerformOptions { operation: 2, enforce: mode != 0, kernel_handle: mode == 0, source_process, target_process: source_process };
        let item_type = item.object_type.clone();
        let outcome = callbacks::perform(&item, desired, &options, &mut |granted| Outcome { status: 0, granted: Some(implied_access(&item_type, granted)), value: 0, error: None })?;
        if outcome.status != 0 {
            return failure(outcome).map(Err);
        }
        process::reference(source_process);
        retained = true;
        // Conserva a herança do handle capturado; INHERIT do
        // atributo não cria esse bit no objeto de origem.
        Ok(Ok(Entry { item: item.clone(), source_process, access: outcome.granted.unwrap_or(desired), object_type, attributes: source_attributes & 2 }))
    })();
    if !retained {
        item.dereference();
    }
    result
}

fn release_entries(entries: &mut Vec<Entry>) {
    for entry in entries.drain(..) {
        entry.item.dereference();
        let _ = process::dereference(entry.source_process);
    }
}

/// Entradas retidas pela mensagem; `release` devolve cada retenção uma vez.
pub struct HandleData {
    pub entries: SpinLock<Vec<Entry>>,
    released: SpinLock<bool>,
}

impl Retained for HandleData {
    fn release(&self) {
        let mut released = self.released.lock();
        if *released {
            return;
        }
        *released = true;
        drop(released);
        release_entries(&mut self.entries.lock());
    }
}

/// O formato simples ocupa 24 bytes; a forma indireta tem 2..512 entradas
/// compactas de 16 bytes com handles ULONG, como a captura original.
pub fn capture(address: u64, mode: u8) -> Result<Result<Arc<HandleData>, u32>, KernelError> {
    match capture_descriptors(address, mode) {
        Ok(descriptors) => capture_entries(&descriptors, mode),
        Err(status) => Ok(Err(status)),
    }
}

/// O atributo de handles de uma resposta (`alpc/server.rs`), capturado
/// como o de um pedido: uma recusa da captura (um NTSTATUS) recusa o envio.
/// Diferença do 19041: um objeto que a captura não descreve (a chave do Cm,
/// sem dono no `open_pointer`) não recusa a resposta, que sai sem os
/// handles, como antes de as respostas levarem handles; o 19041 duplicaria
/// a chave no cliente.
pub fn capture_reply(address: u64, mode: u8) -> Result<Option<Arc<HandleData>>, u32> {
    match capture(address, mode) {
        Ok(Ok(handles)) => Ok(Some(handles)),
        Ok(Err(status)) => Err(status),
        Err(error) => {
            crate::debug_print!("[alpc] resposta do pid {} sem o atributo de handles: {}", process::get_current_process_id(), error);
            Ok(None)
        }
    }
}

/// Lê ALPC_HANDLE_ATTR (forma simples ou vetor de ALPC_HANDLE_ATTR32) do
/// buffer do chamador, com sonda em cada campo.
fn capture_descriptors(address: u64, mode: u8) -> Result<Vec<Descriptor>, u32> {
    if !message_buffer::accessible(address, AlpcHandleAttr::SIZE, mode, false) {
        return Err(0xC000_0005);
    }
    let flags = read_field::<u32>(address, offset_of!(AlpcHandleAttr, flags))?;
    if flags & !0xF_0000 != 0 {
        return Err(0xC000_000D);
    }
    let mut descriptors = Vec::new();
    if flags & 0x4_0000 != 0 {
        let count = read_field::<u32>(address, offset_of!(AlpcHandleAttr, object_type))? as u64;
        if count > 512 {
            return Err(0xC000_0722);
        }
        if count <= 1 {
            return Err(0xC000_000D);
        }
        // HandleAttrArray sobrepõe Handle na forma indireta.
        let array = read_field::<u64>(address, offset_of!(AlpcHandleAttr, handle))?;
        if mode != 0 && array & 3 != 0 {
            return Err(0x8000_0002);
        }
        if !message_buffer::accessible(array, count * AlpcHandleAttr32::SIZE, mode, false) {
            return Err(0xC000_0005);
        }
        for index in 0..count {
            let element = array + index * AlpcHandleAttr32::SIZE;
            let element_flags = read_field::<u32>(element, offset_of!(AlpcHandleAttr32, flags))?;
            if element_flags & !0xB_0000 != 0 {
                return Err(0xC000_000D);
            }
            let handle = read_field::<u32>(element, offset_of!(AlpcHandleAttr32, handle))? as u64;
            let access = read_field::<u32>(element, offset_of!(AlpcHandleAttr32, desired_access))?;
            descriptors.push(Descriptor { flags: element_flags, handle, access });
        }
    } else {
        let handle = read_field::<u64>(address, offset_of!(AlpcHandleAttr, handle))?;
        let access = read_field::<u32>(address, offset_of!(AlpcHandleAttr, desired_access))?;
        descriptors.push(Descriptor { flags, handle, access });
    }
    Ok(descriptors)
}

/// Captura as entradas dos descritores lidos; uma falha solta as anteriores.
fn capture_entries(descriptors: &[Descriptor], mode: u8) -> Result<Result<Arc<HandleData>, u32>, KernelError> {
    let mut entries = Vec::new();
    for descriptor in descriptors {
        match capture_entry(descriptor, mode) {
            Ok(Ok(entry)) => entries.push(entry),
            Ok(Err(status)) => {
                release_entries(&mut entries);
                return Ok(Err(status));
            }
            Err(error) => {
                release_entries(&mut entries);
                return Err(error);
            }
        }
    }
    Ok(Ok(Arc::new(HandleData { entries: SpinLock::new(entries), released: SpinLock::new(false) })))
}

/// ALPC_PORFLG_ALLOW_DUP_OBJECT e ALPC_PORFLG_ALLOW_MULTIHANDLE_ATTRIBUTE.
const ALLOW_DUP_OBJECT: u32 = 0x8_0000;
const ALLOW_MULTIHANDLE_ATTRIBUTE: u32 = 0x200_0000;
/// ALPC_HANDLEFLG_INDIRECT: os handles se pedem um a um pela classe 3.
const HANDLE_INDIRECT: u32 = 0x4_0000;

/// O ALPC_HANDLE_ATTR que a recepção publica.
pub enum Exposed {
    /// Nada: a porta não aceita handles (sem ALLOW_DUP_OBJECT), a mensagem
    /// leva mais de um sem ALLOW_MULTIHANDLE_ATTRIBUTE ou a duplicação
    /// falhou; os handles saem com a mensagem.
    Nothing,
    /// {Flags INDIRECT, Handle 0, ObjectType = o número de handles}: os
    /// handles ficam com a mensagem, e quem recebeu pede cada um pela
    /// classe 3.
    Indirect([u8; 24]),
    /// O único handle, já duplicado no dono da porta, com o tipo e o acesso
    /// concedido; a mensagem não guarda mais os handles.
    Duplicated([u8; 24]),
}

/// AlpcpExposeHandleAttribute: o ALPC_HANDLE_ATTR de recepção pelas regras
/// da porta `port` (a que recebe, ou a de comunicação ligada ao cliente
/// quando o servidor recebe pela porta de conexão).
pub fn expose(handles: &HandleData, port: &Arc<Port>, mode: u8) -> Exposed {
    let flags = port.with(|state| state.port_flags);
    if flags & ALLOW_DUP_OBJECT == 0 {
        return Exposed::Nothing;
    }
    let entries = handles.entries.lock();
    let mut bytes = [0u8; 24];
    let put32 = |bytes: &mut [u8; 24], offset: usize, value: u32| bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    if flags & ALLOW_MULTIHANDLE_ATTRIBUTE != 0 {
        put32(&mut bytes, offset_of!(AlpcHandleAttr, flags), HANDLE_INDIRECT);
        put32(&mut bytes, offset_of!(AlpcHandleAttr, object_type), entries.len() as u32);
        return Exposed::Indirect(bytes);
    }
    if entries.len() != 1 {
        return Exposed::Nothing;
    }
    let Some(duplicated) = duplicate(&entries[0], port, mode).ok().and_then(Result::ok) else { return Exposed::Nothing };
    // HANDLE de 64 bits: o de kernel (bit 31) estende o sinal.
    let handle = offset_of!(AlpcHandleAttr, handle);
    bytes[handle..handle + 8].copy_from_slice(&(duplicated.handle as i32 as u64).to_le_bytes());
    put32(&mut bytes, offset_of!(AlpcHandleAttr, object_type), duplicated.object_type);
    put32(&mut bytes, offset_of!(AlpcHandleAttr, desired_access), duplicated.granted);
    Exposed::Duplicated(bytes)
}

/// ALPC_MESSAGE_HANDLE_ATTRIBUTE.
const HANDLE_ATTRIBUTE: u32 = 0x1000_0000;

/// A recepção de uma mensagem com handles (o AlpcpExposeAttributes de quem
/// recebe): com o ALPC_MESSAGE_HANDLE_ATTRIBUTE alocado em `attributes`, o
/// ALPC_HANDLE_ATTR de [`expose`] pelas regras de `port` e o bit no
/// ValidAttributes. Devolve os handles quando eles ficam com a mensagem (a
/// forma indireta, que quem recebeu pede um a um pela classe 3); nos outros
/// casos eles saem aqui. Uma exposição sem atributo não falha a recepção; só
/// a escrita no buffer de atributos falha.
pub fn deliver(handles: Arc<HandleData>, port: &Arc<Port>, attributes: u64, mode: u8) -> Result<Option<Arc<HandleData>>, u32> {
    let allocated = attributes != 0 && state::user_struct::<AlpcMessageAttributes>(attributes).and_then(|header| header.allocated_attributes.probe_get()).is_ok_and(|allocated| allocated & HANDLE_ATTRIBUTE != 0);
    let (bytes, retained) = match allocated.then(|| expose(&handles, port, mode)) {
        Some(Exposed::Indirect(bytes)) => (bytes, true),
        Some(Exposed::Duplicated(bytes)) => (bytes, false),
        Some(Exposed::Nothing) | None => {
            handles.release();
            return Ok(None);
        }
    };
    let published = (|| -> Result<(), u32> {
        let at = crate::ntos::ps::user::alpc::attribute_address(attributes, HANDLE_ATTRIBUTE);
        if !message_buffer::writable(at, AlpcHandleAttr::SIZE, mode) {
            return Err(0xC000_0005);
        }
        message_buffer::write_block(at, &bytes)?;
        let header = state::user_struct::<AlpcMessageAttributes>(attributes).map_err(|error| error.status)?;
        let valid = header.valid_attributes.probe_get().map_err(|error| error.status)?;
        header.valid_attributes.probe_set(valid | HANDLE_ATTRIBUTE).map_err(|error| error.status)
    })();
    match published {
        Ok(()) if retained => Ok(Some(handles)),
        Ok(()) => {
            handles.release();
            Ok(None)
        }
        Err(status) => {
            handles.release();
            Err(status)
        }
    }
}

/// Handle duplicado na tabela do dono da porta.
pub struct Duplicated {
    pub granted: u32,
    pub handle: u32,
    pub object_type: u32,
}

/// Publica uma nova entrada com retenção própria: nenhum handle do emissor
/// é devolvido como se pertencesse ao receptor, mesmo no mesmo processo.
pub fn duplicate(entry: &Entry, port: &Arc<Port>, mode: u8) -> Result<Result<Duplicated, u32>, KernelError> {
    if port.with(|state| state.duplicate_object_types) & entry.object_type == 0 {
        return Ok(Err(0xC000_0024));
    }
    let target = port.process_pointer;
    let table = process_handles::reference(target)?;
    if table == 0 {
        return Ok(Err(0xC000_010A));
    }
    let item = entry.item.clone();
    item.reference();
    process::reference(entry.source_process);
    let kernel_handle = target == process::get_system_process();
    let options = PerformOptions { operation: 2, enforce: mode != 0, kernel_handle, source_process: entry.source_process, target_process: target };
    let attributes = entry.attributes | if kernel_handle { 0x200 } else { 0 };
    let mut published: Option<Duplicated> = None;
    let outcome = callbacks::perform(&item, entry.access, &options, &mut |granted| {
        let granted = implied_access(&item.object_type, granted);
        // O token entra como os handles de token do destino (a tabela de
        // usuário, onde o NtQueryInformationToken os procura); os outros
        // tipos, como linha do Object Manager.
        let inserted = if entry.object_type == TOKEN_TYPE { token_handles::insert_for(item.pointer, granted, attributes, target).map(|handle| handle as u32) } else { open_pointer::insert(&item, granted, attributes, target) };
        match inserted {
            Ok(handle) => {
                published = Some(Duplicated { granted, handle: handle | if kernel_handle { 0x8000_0000 } else { 0 }, object_type: entry.object_type });
                Outcome { status: 0, granted: Some(granted), value: handle, error: None }
            }
            Err(error) => Outcome { status: if error.status != 0 { error.status } else { 0xC000_0001 }, granted: None, value: 0, error: (error.status == 0).then_some(error) },
        }
    });
    item.dereference();
    let _ = process::dereference(entry.source_process);
    let _ = process_handles::release(target);
    let outcome = outcome?;
    if outcome.status != 0 {
        return failure(outcome).map(Err);
    }
    // O token da resposta do UMLogonUser do UserManager ao winlogon
    // (`initial_process::token_handle_received`).
    if entry.object_type == TOKEN_TYPE {
        crate::ntos::init::initial_process::token_handle_received(entry.source_process, target, entry.item.pointer);
    }
    published.map(Ok).ok_or_else(|| KernelError::new("ALPC duplicated handle was not published"))
}
