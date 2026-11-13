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
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

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
                if matches && native.as_ref().is_some_and(|native| (native.attributes & 0x200 != 0) != kernel_handle) {
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
        // O original conserva a herança do handle capturado; INHERIT do
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
    if !message_buffer::accessible(address, 24, mode, false) {
        return Ok(Err(0xC000_0005));
    }
    let flags = guest::read32(address);
    if flags & !0xF_0000 != 0 {
        return Ok(Err(0xC000_000D));
    }
    let mut descriptors = Vec::new();
    if flags & 0x4_0000 != 0 {
        let count = guest::read32(address + 16) as u64;
        if count > 512 {
            return Ok(Err(0xC000_0722));
        }
        if count <= 1 {
            return Ok(Err(0xC000_000D));
        }
        let array = guest::read64(address + 8);
        if mode != 0 && array & 3 != 0 {
            return Ok(Err(0x8000_0002));
        }
        if !message_buffer::accessible(array, count * 16, mode, false) {
            return Ok(Err(0xC000_0005));
        }
        for index in 0..count {
            let element = array + index * 16;
            let element_flags = guest::read32(element);
            if element_flags & !0xB_0000 != 0 {
                return Ok(Err(0xC000_000D));
            }
            descriptors.push(Descriptor { flags: element_flags, handle: guest::read32(element + 4) as u64, access: guest::read32(element + 12) });
        }
    } else {
        descriptors.push(Descriptor { flags, handle: guest::read64(address + 8), access: guest::read32(address + 20) });
    }
    let mut entries = Vec::new();
    for descriptor in &descriptors {
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
        match open_pointer::insert(&item, granted, attributes, target) {
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
    published.map(Ok).ok_or_else(|| KernelError::new("ALPC duplicated handle was not published"))
}
