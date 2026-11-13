//! Busca e cópia dos valores de ProductPolicy.
//!
//! O serviço superior valida o contexto e o cache; aqui ficam os acessos
//! observados no helper nativo.

use alloc::vec::Vec;

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
    let buffer = guest::read64(name + 8);
    entry.prepare();
    let name_characters = (guest::read16(name) >> 1) as u32;
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

/// memmove; comprimento zero não toca o buffer de dados.
fn move_bytes(destination: u64, source: u64, length: u32) {
    if destination > source && destination < source + length as u64 {
        for index in (0..length as u64).rev() {
            guest::write8(destination + index, guest::read8(source + index));
        }
    } else {
        for index in 0..length as u64 {
            guest::write8(destination + index, guest::read8(source + index));
        }
    }
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
        self.pointer = guest::read64(self.descriptor + 8);
    }
    fn characters(&mut self) -> u32 {
        let raw = guest::read8(self.descriptor) == 2;
        self.text = if raw { self.pointer + 16 } else { guest::read64(self.pointer + 8) };
        (guest::read16(self.pointer + if raw { 2 } else { 0 }) >> 1) as u32
    }
    fn character(&self, index: u32) -> u16 {
        guest::read16(self.text + index as u64 * 2)
    }
}

/// Consulta pelo índice nativo do contexto. As saídas podem apontar para os
/// metadados: tamanho e deslocamento são relidos depois das escritas.
pub fn query_native_index(context: u64, name: u64, type_pointer: u64, buffer: u64, capacity: u32, length_pointer: u64) -> u32 {
    let count = guest::read32(context + 0xB6E8);
    let Some(entry) = search(count, name, |index| NativeEntry { descriptor: context + 0x18 + index as u64 * 16, pointer: 0, text: 0 }) else { return STATUS_NOT_FOUND };
    let pointer = guest::read64(entry.descriptor + 8);
    guest::write32(length_pointer, guest::read16(pointer + 6) as u32);
    if type_pointer != 0 {
        guest::write32(type_pointer, guest::read16(pointer + 4) as u32);
    }
    let length = guest::read16(pointer + 6) as u32;
    if length > capacity {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if buffer != 0 {
        let name_bytes = guest::read16(pointer + 2) as u64;
        move_bytes(buffer, pointer + 16 + name_bytes, length);
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
    guest::write32(length_pointer, entry.data.len() as u32);
    if type_pointer != 0 {
        guest::write32(type_pointer, entry.value_type);
    }
    if entry.data.len() as u64 > capacity as u64 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if buffer != 0 {
        guest::write_bytes(buffer, &entry.data);
    }
    0
}
