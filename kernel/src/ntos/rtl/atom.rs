//! Tabelas de átomos do Rtl (RtlCreateAtomTable[Ex], RtlDestroyAtomTable,
//! RtlAddAtomToAtomTable[Ex], RtlLookupAtomInAtomTable,
//! RtlDeleteAtomFromAtomTable, RtlPinAtomInAtomTable,
//! RtlQueryAtomInAtomTable e RtlGetIntegerAtom), como no ntoskrnl 19041.
//!
//! A tabela é a `_RTL_ATOM_TABLE` real em pool paginado (tag 'AtmT'), com a
//! assinatura 'Atom', a contagem de referências, o push lock que serializa
//! cada operação (dentro de uma região crítica) e os baldes de hash; cada
//! nome é uma `_RTL_ATOM_TABLE_ENTRY` (tag 'AtmA') encadeada no seu balde.
//! Como o RtlpAllocateAtom, cada bloco tem 16 bytes de cabeçalho antes da
//! estrutura (bloco de cota e tamanho); o OpenNT não cobra a cota de pool
//! compartilhada, então o bloco de cota fica nulo.
//!
//! Átomos inteiros vão de 1 a 0xBFFF e não entram na tabela. Um átomo de
//! string é 0xC000 | índice, onde o índice é o do handle que o
//! RtlpInsertStringAtom cria para a entrada na tabela de handles da tabela
//! (handle / 4, de 1 a 0x3FFF). O índice mora aqui num registro por tabela
//! (`ExHandleTable` fica nulo): índices novos crescem a partir de 1 e um
//! índice liberado volta primeiro (a lista livre LIFO da tabela de handles).
//!
//! Nomes: até 255 caracteres; o hash soma 3c + c/2 de cada caractere em
//! maiúscula (NLS_UPCASE) e a comparação é a `_wcsicmp` do kernel (só
//! A-Z/a-z se equivalem). Referências: cada Add de um nome existente soma
//! uma; em 0xFFFF a entrada fica fixada, como um RtlPinAtomInAtomTable.
//! Uma entrada fixada não sai com Delete (STATUS_WAS_LOCKED).
//!
//! LowBox: o NT guarda referências por AppContainer quando o token efetivo
//! tem número LowBox; o OpenNT não atribui números LowBox (não há
//! NtCreateLowBoxToken), então a referência é sempre a da própria entrada.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::ntos::ex::{pool_allocation, push_lock};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::extra_rtl::{RtlAtomTable, RtlAtomTableEntry};
use crate::ntos::ke::critical_region;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::unicode_case;
use crate::rtl::{KernelError, SpinLock};

const STATUS_SUCCESS: u32 = 0;
const STATUS_WAS_LOCKED: u32 = 0x4000_0019;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_INTEGER_OVERFLOW: u32 = 0xC000_0095;

/// 'Atom', a assinatura de uma tabela viva.
const SIGNATURE: u32 = 0x6D6F_7441;
/// 'AtmT' e 'AtmA': as tags da tabela e das entradas.
const TABLE_TAG: u32 = 0x546D_7441;
const ENTRY_TAG: u32 = 0x416D_7441;
/// Baldes quando o chamador pede 0 ou 1.
const DEFAULT_BUCKETS: u32 = 37;
/// MAXINTATOM: o primeiro átomo de string.
const MAXIMUM_INTEGER_ATOM: u16 = 0xC000;
/// Maior índice de handle que ainda cabe num átomo.
const MAXIMUM_INDEX: u16 = 0x3FFF;
const MAXIMUM_NAME_LENGTH: usize = 0xFF;
/// RTL_ATOM_TABLE_REFERENCE.Flags: a entrada está fixada.
const REFERENCE_PINNED: u16 = 1;
/// Do Flags do RtlAddAtomToAtomTableEx só este bit vai para a referência.
const ADD_FLAGS_KEPT: u32 = 2;
/// Cabeçalho do RtlpAllocateAtom antes da estrutura.
const ALLOCATION_HEADER: u64 = 0x10;

/// Índices de handle de uma tabela: índice -> entrada.
struct Handles {
    entries: BTreeMap<u16, u64>,
    free: Vec<u16>,
    next: u16,
}

static HANDLES: SpinLock<BTreeMap<u64, Handles>> = SpinLock::new(BTreeMap::new());

fn table_at(table: u64) -> &'static RtlAtomTable {
    // SAFETY: PVOID AtomTableHandle do chamador de kernel; a assinatura é
    // conferida antes de qualquer outro campo.
    unsafe { RtlAtomTable::at(table) }
}

fn entry_at(entry: u64) -> &'static RtlAtomTableEntry {
    // SAFETY: entrada alocada por `allocate_entry` e viva enquanto está no
    // balde e no registro de índices.
    unsafe { RtlAtomTableEntry::at(entry) }
}

fn bucket_slot(table: u64, index: u32) -> &'static Field<u64> {
    // SAFETY: os baldes seguem o cabeçalho, `number_of_buckets` células
    // dentro da alocação da tabela.
    unsafe { Field::<u64>::at(table_at(table).buckets[0].address() + index as u64 * 8) }
}

fn link_at(slot: u64) -> &'static Field<u64> {
    // SAFETY: um balde ou o HashLink (+0) de uma entrada viva.
    unsafe { Field::<u64>::at(slot) }
}

/// RtlpAllocateAtom: pool paginado com o cabeçalho de cota.
fn allocate_atom(size: u64, tag: u32) -> u64 {
    let Some(total) = size.checked_add(ALLOCATION_HEADER) else { return 0 };
    let block = pool_allocation::allocate_tagged(1, total, tag).unwrap_or(0);
    if block == 0 {
        return 0;
    }
    guest::write64(block, 0);
    guest::write64(block + 8, total);
    block + ALLOCATION_HEADER
}

/// RtlpFreeAtom.
fn free_atom(pointer: u64) {
    let _ = pool_allocation::free(pointer - ALLOCATION_HEADER, 0);
}

/// RtlpLockAtomTable: tabela nula ou sem a assinatura = FALSE.
fn lock(table: u64) -> Result<bool, KernelError> {
    if table == 0 || table_at(table).signature.get() != SIGNATURE {
        return Ok(false);
    }
    critical_region::enter_critical()?;
    push_lock::acquire_exclusive(table_at(table).push_lock.value.address(), 0)?;
    Ok(true)
}

/// RtlpUnlockAtomTable.
fn unlock(table: u64) -> Result<(), KernelError> {
    push_lock::release_exclusive(table_at(table).push_lock.value.address(), 0)?;
    critical_region::leave_critical()
}

/// Corpo sob o lock da tabela; sem lock, STATUS_INVALID_PARAMETER.
fn locked(table: u64, body: impl FnOnce() -> Result<u32, KernelError>) -> Result<u32, KernelError> {
    if !lock(table)? {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let result = body();
    unlock(table)?;
    result
}

/// O valor de RtlGetIntegerAtom: MAKEINTATOM abaixo de 0xC000 (0 vira
/// 0xC000) ou "#<dígitos decimais>" (o valor do RtlUnicodeStringToInteger;
/// fora de 1..=0xC000 vira 0xC000).
fn integer_value(name: u64) -> Option<u16> {
    if name & !0xFFFF == 0 {
        let value = name as u16;
        if value >= MAXIMUM_INTEGER_ATOM {
            return None;
        }
        return Some(if value == 0 { MAXIMUM_INTEGER_ATOM } else { value });
    }
    if guest::read16(name) != b'#' as u16 {
        return None;
    }
    let mut cursor = name + 2;
    let mut value = 0u32;
    let mut digits = 0;
    loop {
        let unit = guest::read16(cursor);
        if unit == 0 {
            break;
        }
        if !(b'0' as u16..=b'9' as u16).contains(&unit) {
            return None;
        }
        value = value.wrapping_mul(10).wrapping_add((unit - b'0' as u16) as u32);
        digits += 1;
        cursor += 2;
    }
    // RtlUnicodeStringToInteger recusa a string vazia.
    if digits == 0 {
        return None;
    }
    Some(if value.wrapping_sub(1) > 0xBFFF { MAXIMUM_INTEGER_ATOM } else { value as u16 })
}

/// RtlGetIntegerAtom(AtomName, IntegerAtom).
pub fn integer_atom(name: u64, output: Option<&Field<u16>>) -> bool {
    let Some(value) = integer_value(name) else { return false };
    if let Some(output) = output {
        output.set(value);
    }
    true
}

/// RtlCreateAtomTableEx(NumberOfBuckets, Flags, AtomTableHandle): um
/// *AtomTableHandle já preenchido não é tocado.
pub fn create_table(buckets: u32, flags: u32, handle: &Field<u64>) -> u32 {
    if handle.get() != 0 {
        return STATUS_SUCCESS;
    }
    let buckets = if buckets > 1 { buckets } else { DEFAULT_BUCKETS };
    // O tamanho do original: 0x30 * (baldes - 1) + 0x28.
    let Some(size) = 0x30u64.checked_mul(buckets as u64 - 1).and_then(|size| size.checked_add(0x28)) else {
        return STATUS_INTEGER_OVERFLOW;
    };
    let table = allocate_atom(size, TABLE_TAG);
    if table == 0 {
        return STATUS_NO_MEMORY;
    }
    guest::write_bytes(table, &alloc::vec![0u8; size as usize]);
    let header = table_at(table);
    header.number_of_buckets.set(buckets);
    HANDLES.lock().insert(table, Handles { entries: BTreeMap::new(), free: Vec::new(), next: 1 });
    push_lock::initialize(header.push_lock.value.address());
    header.signature.set(SIGNATURE);
    header.reference_count.set(1);
    header.flags.set(flags);
    handle.set(table);
    STATUS_SUCCESS
}

/// Entrada do índice `index` (RtlpAtomMapAtomToHandleEntry).
fn map_index(table: u64, index: u16) -> u64 {
    HANDLES.lock().get(&table).and_then(|handles| handles.entries.get(&index).copied()).unwrap_or(0)
}

/// RtlpInsertStringAtom: índice novo (o liberado mais recente primeiro);
/// índice além de 0x3FFF é devolvido e a inserção falha.
fn insert_index(table: u64, entry: u64) -> bool {
    let mut registry = HANDLES.lock();
    let Some(handles) = registry.get_mut(&table) else { return false };
    let index = match handles.free.pop() {
        Some(index) => index,
        None => {
            let index = handles.next;
            if index > MAXIMUM_INDEX {
                return false;
            }
            handles.next += 1;
            index
        }
    };
    handles.entries.insert(index, entry);
    let entry = entry_at(entry);
    entry.handle_index.set(index);
    entry.atom.set(MAXIMUM_INTEGER_ATOM | index);
    true
}

/// RtlpFreeHandleForAtom.
fn free_index(table: u64, index: u16) {
    if let Some(handles) = HANDLES.lock().get_mut(&table) {
        if handles.entries.remove(&index).is_some() {
            handles.free.push(index);
        }
    }
}

/// Caracteres do nome até o NUL.
fn read_name(name: u64) -> Vec<u16> {
    let mut units = Vec::new();
    loop {
        let unit = guest::read16(name + units.len() as u64 * 2);
        if unit == 0 {
            return units;
        }
        units.push(unit);
    }
}

fn hash(units: &[u16]) -> u32 {
    units.iter().fold(0u32, |sum, &unit| {
        let upper = unicode_case::nls_upcase(unit) as u32;
        sum.wrapping_add(3 * upper + (upper >> 1))
    })
}

/// A `_wcsicmp` do kernel: só A-Z viram minúsculas.
fn equal_ignoring_ascii_case(left: &[u16], right: &[u16]) -> bool {
    let fold = |unit: u16| if (b'A' as u16..=b'Z' as u16).contains(&unit) { unit + 0x20 } else { unit };
    left.len() == right.len() && left.iter().zip(right).all(|(&a, &b)| fold(a) == fold(b))
}

fn entry_name(entry: u64) -> Vec<u16> {
    let length = entry_at(entry).name_length.get() as usize;
    let base = entry_at(entry).name[0].address();
    (0..length).map(|index| guest::read16(base + index as u64 * 2)).collect()
}

/// O que o RtlpHashStringToAtom acha para um nome de string.
struct Search {
    /// Célula que aponta para a entrada achada, ou a última do balde (onde
    /// uma entrada nova é encadeada); 0 para nome longo demais.
    slot: u64,
    entry: u64,
}

fn search(table: u64, units: &[u16]) -> Search {
    if units.len() > MAXIMUM_NAME_LENGTH {
        return Search { slot: 0, entry: 0 };
    }
    let index = hash(units) % table_at(table).number_of_buckets.get();
    let mut slot = bucket_slot(table, index).address();
    let mut entry = link_at(slot).get();
    while entry != 0 {
        if entry_at(entry).name_length.get() as usize == units.len() && equal_ignoring_ascii_case(&entry_name(entry), units) {
            break;
        }
        slot = entry;
        entry = entry_at(entry).hash_link.get();
    }
    Search { slot, entry }
}

/// RtlpReferenceAtom sobre a referência da própria entrada.
fn reference(entry: u64) {
    let reference = &entry_at(entry).reference;
    let count = reference.reference_count.get();
    if count == 0xFFFF {
        reference.flags.set(reference.flags.get() | REFERENCE_PINNED);
    } else {
        reference.reference_count.set(count + 1);
    }
}

/// RtlpAllocateAtomTableEntry + cópia do nome.
fn allocate_entry(units: &[u16], flags: u32) -> u64 {
    let bytes = units.len() as u64 * 2;
    let entry = allocate_atom(bytes + 0x2C, ENTRY_TAG);
    if entry == 0 {
        return 0;
    }
    let fields = entry_at(entry);
    fields.hash_link.set(0);
    fields.reference.reference_count.set(1);
    fields.reference.flags.set((flags & ADD_FLAGS_KEPT) as u16);
    let list = fields.reference.low_box_list.flink.address();
    fields.reference.low_box_list.flink.set(list);
    fields.reference.low_box_list.blink.set(list);
    fields.reference.low_box_id.set(0);
    let mut name: Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    name.extend_from_slice(&[0, 0]);
    guest::write_bytes(fields.name[0].address(), &name);
    fields.name_length.set(units.len() as u8);
    entry
}

/// RtlAddAtomToAtomTableEx(AtomTable, AtomName, Atom, Flags).
pub fn add(table: u64, name: u64, atom: Option<&Field<u16>>, flags: u32) -> Result<u32, KernelError> {
    locked(table, || {
        if let Some(value) = integer_value(name) {
            let (status, result) = if value < MAXIMUM_INTEGER_ATOM { (STATUS_SUCCESS, value) } else { (STATUS_INVALID_PARAMETER, 0) };
            if let Some(atom) = atom {
                atom.set(result);
            }
            return Ok(status);
        }
        let units = read_name(name);
        if units.is_empty() {
            return Ok(STATUS_OBJECT_NAME_INVALID);
        }
        let found = search(table, &units);
        if found.entry != 0 {
            reference(found.entry);
            if let Some(atom) = atom {
                atom.set(entry_at(found.entry).atom.get());
            }
            return Ok(STATUS_SUCCESS);
        }
        if found.slot == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let entry = allocate_entry(&units, flags);
        if entry == 0 {
            return Ok(STATUS_NO_MEMORY);
        }
        if !insert_index(table, entry) {
            free_atom(entry);
            return Ok(STATUS_NO_MEMORY);
        }
        link_at(found.slot).set(entry);
        if let Some(atom) = atom {
            atom.set(entry_at(entry).atom.get());
        }
        Ok(STATUS_SUCCESS)
    })
}

/// RtlLookupAtomInAtomTable(AtomTable, AtomName, Atom): não soma referência.
pub fn lookup(table: u64, name: u64, atom: Option<&Field<u16>>) -> Result<u32, KernelError> {
    locked(table, || {
        if let Some(value) = integer_value(name) {
            let (status, result) = if value < MAXIMUM_INTEGER_ATOM { (STATUS_SUCCESS, value) } else { (STATUS_INVALID_PARAMETER, 0) };
            if let Some(atom) = atom {
                atom.set(result);
            }
            return Ok(status);
        }
        let units = read_name(name);
        if units.is_empty() {
            return Ok(STATUS_OBJECT_NAME_INVALID);
        }
        let found = search(table, &units);
        if found.entry == 0 {
            return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        if map_index(table, entry_at(found.entry).handle_index.get()) == 0 {
            return Ok(STATUS_INVALID_HANDLE);
        }
        if let Some(atom) = atom {
            atom.set(entry_at(found.entry).atom.get());
        }
        Ok(STATUS_SUCCESS)
    })
}

/// A entrada viva do átomo de string `atom` (índice e átomo conferem).
fn string_entry(table: u64, atom: u16) -> u64 {
    let entry = map_index(table, atom & MAXIMUM_INDEX);
    if entry != 0 && entry_at(entry).atom.get() == atom { entry } else { 0 }
}

/// RtlpFreeAllAtom: tira a entrada do balde, devolve o índice e a memória.
fn free_entry(table: u64, entry: u64) {
    let found = search(table, &entry_name(entry));
    if found.entry != entry {
        return;
    }
    link_at(found.slot).set(entry_at(entry).hash_link.get());
    free_index(table, entry_at(entry).handle_index.get());
    free_atom(entry);
}

/// RtlDeleteAtomFromAtomTable(AtomTable, Atom).
pub fn delete(table: u64, atom: u16) -> Result<u32, KernelError> {
    locked(table, || {
        if atom < MAXIMUM_INTEGER_ATOM {
            return Ok(if atom != 0 { STATUS_SUCCESS } else { STATUS_INVALID_HANDLE });
        }
        let entry = string_entry(table, atom);
        if entry == 0 {
            return Ok(STATUS_INVALID_HANDLE);
        }
        let reference = &entry_at(entry).reference;
        if reference.flags.get() & REFERENCE_PINNED != 0 {
            return Ok(STATUS_WAS_LOCKED);
        }
        // RtlpDereferenceAtom: a última referência libera a entrada.
        let count = reference.reference_count.get().wrapping_sub(1);
        reference.reference_count.set(count);
        if count == 0 {
            free_entry(table, entry);
        }
        Ok(STATUS_SUCCESS)
    })
}

/// RtlPinAtomInAtomTable(AtomTable, Atom).
pub fn pin(table: u64, atom: u16) -> Result<u32, KernelError> {
    locked(table, || {
        if atom < MAXIMUM_INTEGER_ATOM {
            return Ok(if atom != 0 { STATUS_SUCCESS } else { STATUS_INVALID_HANDLE });
        }
        let entry = string_entry(table, atom);
        if entry == 0 {
            return Ok(STATUS_INVALID_HANDLE);
        }
        let reference = &entry_at(entry).reference;
        reference.flags.set(reference.flags.get() | REFERENCE_PINNED);
        Ok(STATUS_SUCCESS)
    })
}

/// Saídas opcionais do RtlQueryAtomInAtomTable.
pub struct QueryOutputs<'a> {
    pub reference_count: Option<&'a Field<u32>>,
    pub pin_count: Option<&'a Field<u32>>,
    pub name: u64,
    pub name_length: Option<&'a Field<u32>>,
}

/// Cópia do nome com a regra do original: o que não cabe é truncado a
/// (capacidade - 2) bytes com sucesso; capacidade menor que 2 (ou nada a
/// copiar depois do corte) = STATUS_BUFFER_TOO_SMALL.
fn copy_name(units: &[u16], buffer: u64, length: &Field<u32>, report_needed: bool) -> u32 {
    let mut bytes = units.len() as u32 * 2;
    let capacity = length.get();
    if bytes >= capacity {
        if capacity < 2 {
            if report_needed {
                length.set(bytes);
            }
            return STATUS_BUFFER_TOO_SMALL;
        }
        bytes = capacity - 2;
    }
    if bytes == 0 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let mut payload: Vec<u8> = units[..bytes as usize / 2].iter().flat_map(|unit| unit.to_le_bytes()).collect();
    payload.extend_from_slice(&[0, 0]);
    guest::write_bytes(buffer, &payload);
    length.set(bytes);
    STATUS_SUCCESS
}

/// RtlQueryAtomInAtomTable(AtomTable, Atom, RefCount, PinCount, AtomName,
/// AtomNameLength): PinCount recebe o Flags da referência (bit 0 = fixado);
/// um átomo inteiro conta 1 e 1 e se chama "#<valor>".
pub fn query(table: u64, atom: u16, outputs: &QueryOutputs) -> Result<u32, KernelError> {
    locked(table, || {
        if atom < MAXIMUM_INTEGER_ATOM {
            if atom == 0 {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            if let Some(count) = outputs.reference_count {
                count.set(1);
            }
            if let Some(pins) = outputs.pin_count {
                pins.set(1);
            }
            let (Some(length), true) = (outputs.name_length, outputs.name != 0) else { return Ok(STATUS_SUCCESS) };
            let text: Vec<u16> = alloc::format!("#{atom}").encode_utf16().collect();
            return Ok(copy_name(&text, outputs.name, length, false));
        }
        let entry = string_entry(table, atom);
        if entry == 0 {
            return Ok(STATUS_INVALID_HANDLE);
        }
        let reference = &entry_at(entry).reference;
        if let Some(count) = outputs.reference_count {
            count.set(reference.reference_count.get() as u32);
        }
        if let Some(pins) = outputs.pin_count {
            pins.set(reference.flags.get() as u32);
        }
        let (Some(length), true) = (outputs.name_length, outputs.name != 0) else { return Ok(STATUS_SUCCESS) };
        Ok(copy_name(&entry_name(entry), outputs.name, length, true))
    })
}

/// RtlDestroyAtomTable(AtomTable): só a última referência destrói; as
/// entradas saem sem passar por Delete (fixadas ou não).
pub fn destroy_table(table: u64) -> Result<u32, KernelError> {
    let remaining = table_at(table).reference_count.atomic().fetch_sub(1, core::sync::atomic::Ordering::SeqCst).wrapping_sub(1);
    if remaining != 0 {
        return Ok(STATUS_SUCCESS);
    }
    if !lock(table)? {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    for index in 0..table_at(table).number_of_buckets.get() {
        let slot = bucket_slot(table, index);
        let mut entry = slot.get();
        slot.set(0);
        while entry != 0 {
            let next = entry_at(entry).hash_link.get();
            entry_at(entry).hash_link.set(0);
            free_atom(entry);
            entry = next;
        }
    }
    table_at(table).signature.set(0);
    unlock(table)?;
    HANDLES.lock().remove(&table);
    guest::write_bytes(table, &[0u8; 0x28]);
    free_atom(table);
    Ok(STATUS_SUCCESS)
}
