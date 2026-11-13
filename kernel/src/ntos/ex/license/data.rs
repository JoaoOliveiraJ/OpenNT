//! Busca e cópia dos valores de ProductPolicy.
//!
//! O serviço superior valida o contexto e o cache; aqui ficam os acessos
//! observados no helper nativo.

use alloc::vec::Vec;

use super::layout::{self, context_at, descriptor_at, entry_at, ulong_at, unicode_at, Descriptor, PolicyEntry, RAW_ENTRY};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::mm::guest_memory as guest;

const STATUS_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

/// Entrada comparável pela busca binária.
pub trait Entry {
    fn prepare(&mut self) {}
    fn characters(&mut self) -> u32;
    fn character(&self, index: u32) -> u16;
}

/// Relê a UNICODE_STRING a cada comparação e só percorre o prefixo
/// necessário.
fn compare_name(name: u64, entry: &mut impl Entry) -> i32 {
    let buffer = unicode_at(name).buffer.get();
    entry.prepare();
    let name_characters = (unicode_at(name).length.get() >> 1) as u32;
    let entry_characters = entry.characters();
    for character in 0..name_characters.min(entry_characters) {
        let supplied = guest::read16(buffer + character as u64 * 2) as i32;
        let stored = entry.character(character) as i32;
        if supplied != stored {
            return supplied - stored;
        }
    }
    name_characters as i32 - entry_characters as i32
}

/// Busca binária: meio inferior quando a quantidade é par.
fn search<E: Entry>(count: u32, name: u64, mut get_entry: impl FnMut(u32) -> E) -> Option<E> {
    let mut first = 0u32;
    let mut remaining = count;
    while remaining != 0 {
        let half = remaining >> 1;
        let left = if remaining & 1 != 0 { half } else { half - 1 };
        let index = first + left;
        let mut entry = get_entry(index);
        let comparison = compare_name(name, &mut entry);
        if comparison == 0 {
            return Some(entry);
        }
        if comparison < 0 {
            remaining = left;
        } else {
            first = index + 1;
            remaining = half;
        }
    }
    None
}


/// Descritor nativo de 16 bytes: kind 2 aponta para a entrada do blob; os
/// demais para uma UNICODE_STRING.
struct NativeEntry {
    descriptor: u64,
    pointer: u64,
    text: u64,
}

impl Entry for NativeEntry {
    fn prepare(&mut self) {
        self.pointer = descriptor_at(self.descriptor).entry.get();
    }
    fn characters(&mut self) -> u32 {
        if descriptor_at(self.descriptor).kind.get() == RAW_ENTRY {
            self.text = self.pointer + PolicyEntry::SIZE;
            (entry_at(self.pointer).name_size.get() >> 1) as u32
        } else {
            let name = unicode_at(self.pointer);
            self.text = name.buffer.get();
            (name.length.get() >> 1) as u32
        }
    }
    fn character(&self, index: u32) -> u16 {
        guest::read16(self.text + index as u64 * 2)
    }
}

/// Consulta pelo índice nativo do contexto. As saídas podem apontar para os
/// metadados: tamanho e deslocamento são relidos depois das escritas.
pub fn query_native_index(context: u64, name: u64, type_pointer: u64, buffer: u64, capacity: u32, length_pointer: u64) -> u32 {
    let count = context_at(context).descriptor_count.get();
    let Some(entry) = search(count, name, |index| NativeEntry { descriptor: context_at(context).descriptor_array() + index as u64 * Descriptor::SIZE, pointer: 0, text: 0 }) else { return STATUS_NOT_FOUND };
    let pointer = descriptor_at(entry.descriptor).entry.get();
    ulong_at(length_pointer).set(entry_at(pointer).data_size.get() as u32);
    if type_pointer != 0 {
        ulong_at(type_pointer).set(entry_at(pointer).data_type.get() as u32);
    }
    let length = entry_at(pointer).data_size.get() as u32;
    if length > capacity {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if buffer != 0 {
        let name_bytes = entry_at(pointer).name_size.get() as u64;
        layout::move_bytes(buffer, pointer + PolicyEntry::SIZE + name_bytes, length);
    }
    0
}

/// Valor do cache do boot (cópia própria dos bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedEntry {
    pub name: Vec<u16>,
    pub value_type: u32,
    pub data: Vec<u8>,
}

/// Cache do boot: status da carga e entradas ordenadas.
#[derive(Clone, Debug, Default)]
pub struct OwnedValues {
    pub status: u32,
    pub entries: Vec<OwnedEntry>,
}

struct OwnedRef<'a>(&'a OwnedEntry);

impl Entry for OwnedRef<'_> {
    fn characters(&mut self) -> u32 {
        self.0.name.len() as u32
    }
    fn character(&self, index: u32) -> u16 {
        self.0.name[index as usize]
    }
}

/// Mesmo nome contado e mesma ordem das saídas, sobre o cache do boot.
pub fn query_owned(values: &OwnedValues, name: u64, type_pointer: u64, buffer: u64, capacity: u32, length_pointer: u64) -> u32 {
    if values.status != 0 {
        return values.status;
    }
    let Some(OwnedRef(entry)) = search(values.entries.len() as u32, name, |index| OwnedRef(&values.entries[index as usize])) else { return STATUS_NOT_FOUND };
    ulong_at(length_pointer).set(entry.data.len() as u32);
    if type_pointer != 0 {
        ulong_at(type_pointer).set(entry.value_type);
    }
    if entry.data.len() as u64 > capacity as u64 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if buffer != 0 {
        guest::write_bytes(buffer, &entry.data);
    }
    0
}
