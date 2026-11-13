//! Descritores OBJECT_TYPE do gerenciador de objetos — `ntos/ob/object-types.js`.
//!
//! Layout do PDB: corpo de 0xD8 bytes, TypeInfo em +0x40 com tamanho 0x78.
//! Ponteiros exportados, verificações de tipo e contadores usam a mesma
//! identidade (o ponteiro do corpo).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::inc::status::STATUS_INSUFFICIENT_RESOURCES;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

/// Identidade pública de um tipo (cópia barata).
#[derive(Clone, Debug)]
pub struct ObjectType {
    pub name: String,
    pub pointer: u64,
    pub mapping: [u32; 4],
    pub valid_access: u32,
}

struct TypeRecord {
    info: ObjectType,
    objects: u32,
    handles: u32,
    peak_objects: u32,
    peak_handles: u32,
}

struct Types {
    by_name: BTreeMap<String, TypeRecord>,
    order: Vec<String>,
    by_body: BTreeMap<u64, String>,
    next_index: u8,
}

static TYPES: SpinLock<Types> =
    SpinLock::new(Types { by_name: BTreeMap::new(), order: Vec::new(), by_body: BTreeMap::new(), next_index: 2 });

fn publish_counts(record: &TypeRecord) {
    for (offset, value) in [(0x2C, record.objects), (0x30, record.handles), (0x34, record.peak_objects), (0x38, record.peak_handles)] {
        guest::write32(record.info.pointer + offset, value);
    }
}

fn apply(record: &mut TypeRecord, objects: i64, handles: i64) -> Result<(), KernelError> {
    if record.objects as i64 + objects < 0 || record.handles as i64 + handles < 0 {
        return Err(KernelError::new(alloc::format!("object type count underflow: {}", record.info.name)));
    }
    record.objects = (record.objects as i64 + objects) as u32;
    record.handles = (record.handles as i64 + handles) as u32;
    record.peak_objects = record.peak_objects.max(record.objects);
    record.peak_handles = record.peak_handles.max(record.handles);
    publish_counts(record);
    Ok(())
}

/// Aloca o tipo e seu nome UTF-16, grava mapeamento genérico, máscara
/// válida e a lista de callbacks. O metatipo conta os descritores criados.
fn create(name: &str, mapping: [u32; 4], valid_access: u32, flags: u16) -> Result<ObjectType, KernelError> {
    let mut types = TYPES.lock();
    if types.by_name.contains_key(name) {
        return Err(KernelError::new(alloc::format!("duplicate object type: {name}")));
    }
    let units: Vec<u16> = name.encode_utf16().collect();
    let pointer = guest::alloc_bytes(0xD8);
    let name_buffer = guest::alloc_bytes((units.len() as u64 + 1) * 2);
    if pointer == 0 || name_buffer == 0 {
        if pointer != 0 {
            guest::free_bytes(pointer);
        }
        if name_buffer != 0 {
            guest::free_bytes(name_buffer);
        }
        return Err(KernelError::with_status("object type allocation failed", STATUS_INSUFFICIENT_RESOURCES));
    }
    guest::write64(pointer, pointer);
    guest::write64(pointer + 8, pointer);
    guest::write16(pointer + 0x10, (units.len() * 2) as u16);
    guest::write16(pointer + 0x12, ((units.len() + 1) * 2) as u16);
    guest::write64(pointer + 0x18, name_buffer);
    for (index, &unit) in units.iter().enumerate() {
        guest::write16(name_buffer + index as u64 * 2, unit);
    }
    let index = types.next_index;
    types.next_index = types.next_index.wrapping_add(1);
    guest::write8(pointer + 0x28, index);
    guest::write16(pointer + 0x40, 0x78);
    guest::write16(pointer + 0x42, flags);
    for (position, value) in mapping.iter().enumerate() {
        guest::write32(pointer + 0x4C + position as u64 * 4, *value);
    }
    guest::write32(pointer + 0x5C, valid_access);
    guest::write64(pointer + 0xC8, pointer + 0xC8);
    guest::write64(pointer + 0xD0, pointer + 0xC8);
    let info = ObjectType { name: String::from(name), pointer, mapping, valid_access };
    types.by_name.insert(
        String::from(name),
        TypeRecord { info: info.clone(), objects: 0, handles: 0, peak_objects: 0, peak_handles: 0 },
    );
    types.order.push(String::from(name));
    let size = types.by_name.len() as i64;
    if let Some(meta) = types.by_name.get_mut("Type") {
        apply(meta, if name == "Type" { size } else { 1 }, 0)?;
    }
    Ok(info)
}

fn get_or_create(name: &str, mapping: [u32; 4], valid_access: u32, flags: u16) -> ObjectType {
    if let Some(record) = TYPES.lock().by_name.get(name) {
        return record.info.clone();
    }
    create(name, mapping, valid_access, flags).unwrap_or_else(|error| panic!("{error}"))
}

/// PspProcessMapping; flags: só objetos sem nome, contagem de handles e callbacks.
pub fn process_type() -> ObjectType {
    get_or_create("Process", [0x20410, 0x20BEA, 0x121001, 0x1FFFFF], 0x1FFFFF, 0x52)
}

pub fn thread_type() -> ObjectType {
    get_or_create("Thread", [0x20048, 0x20437, 0x121800, 0x1FFFFF], 0x1FFFFF, 0x52)
}

pub fn driver_type() -> ObjectType {
    get_or_create("Driver", [0x120089, 0x120116, 0x1200A0, 0x1F01FF], 0x1F01FF, 0x11)
}

pub fn file_type() -> ObjectType {
    get_or_create("File", [0x120089, 0x120116, 0x1200A0, 0x1F01FF], 0x1F01FF, 0x11)
}

pub fn section_type() -> ObjectType {
    get_or_create("Section", [0x20005, 0x20002, 0x20008, 0xF001F], 0x1F001F, 0x10)
}

pub fn token_type() -> ObjectType {
    get_or_create("Token", [0x2001A, 0x201E0, 0x20005, 0xF01FF], 0x1F01FF, 0x12)
}

pub fn callback_type() -> ObjectType {
    get_or_create("Callback", [0x20000, 0x20001, 0x120000, 0x1F0001], 0x1F0001, 0)
}

/// Cria um tipo de objeto arbitrário — a forma pública do `create`, usada por
/// ObCreateObjectType quando um driver registra tipos próprios.
pub fn define(name: &str, mapping: [u32; 4], valid_access: u32, flags: u16) -> Result<ObjectType, KernelError> {
    create(name, mapping, valid_access, flags)
}

pub fn device_type() -> ObjectType {
    get_or_create("Device", [0x120089, 0x120116, 0x1200A0, 0x1F01FF], 0x1F01FF, 0)
}

pub fn event_type() -> ObjectType {
    get_or_create("Event", [0x20001, 0x20002, 0x120000, 0x1F0003], 0x1F0003, 0)
}

pub fn meta_type() -> ObjectType {
    get_or_create("Type", [0x20000, 0x20000, 0x20000, 0xF0001], 0x1F0001, 0)
}

pub fn directory_type() -> ObjectType {
    get_or_create("Directory", [0x20003, 0x2000C, 0x20003, 0xF000F], 0xF000F, 8)
}

pub fn symbolic_link_type() -> ObjectType {
    get_or_create("SymbolicLink", [0x20001, 0x20000, 0x20001, 0xF0001], 0xFFFFF, 0)
}

pub fn key_type() -> ObjectType {
    get_or_create("Key", [0x20019, 0x20006, 0x20039, 0xF003F], 0x1F003F, 8)
}

/// Nome do runtime de usuário -> tipo nativo; `None` se ainda não suportado.
pub fn user_type(kind: &str) -> Option<ObjectType> {
    let name = match kind {
        "completion" => String::from("IoCompletion"),
        "waitpacket" => String::from("WaitCompletionPacket"),
        "workerfactory" => String::from("TpWorkerFactory"),
        "alpc" | "port" => String::from("ALPC Port"),
        "symlink" => String::from("SymbolicLink"),
        "device" => String::from("File"),
        _ => {
            let mut characters = kind.chars();
            match characters.next() {
                Some(first) => first.to_uppercase().chain(characters).collect(),
                None => String::new(),
            }
        }
    };
    if let Some(record) = TYPES.lock().by_name.get(&name) {
        return Some(record.info.clone());
    }
    let (mapping, valid, flags) = match name.as_str() {
        "Mutant" => ([0x20001, 0x20000, 0x120000, 0x1F0001], 0x1F0001, 0),
        "Semaphore" | "Timer" | "IoCompletion" => ([0x20001, 0x20002, 0x120000, 0x1F0003], 0x1F0003, 0),
        "Partition" => ([0x20001, 0x20002, 0x120001, 0x1F0003], 0x1F0003, 8),
        "WaitCompletionPacket" => ([0x20001, 0x20001, 0x20001, 0xF0001], 0x1F0001, 0),
        "TpWorkerFactory" => ([0x20008, 0x20004, 0x20003, 0xF00FF], 0xF00FF, 0),
        "ALPC Port" => ([0x20001, 0x10001, 0, 0x1F0001], 0x1F0001, 0x10),
        _ => return None,
    };
    create(&name, mapping, valid, flags).ok()
}

/// Tipo paginável ou não paginável dos contextos de silo, com PoolType em
/// OBJECT_TYPE_INITIALIZER (+0x24, isto é, +0x64 no corpo).
pub fn silo_context_type(paged: bool) -> ObjectType {
    let name = if paged { "PsSiloContextPaged" } else { "PsSiloContextNonPaged" };
    if let Some(record) = TYPES.lock().by_name.get(name) {
        return record.info.clone();
    }
    let info = create(name, [0x20000, 0x20000, 0x20000, 0xF0000], 0x1F0000, 2).unwrap_or_else(|error| panic!("{error}"));
    guest::write32(info.pointer + 0x64, if paged { 1 } else { 0x200 });
    info
}

/// Aplica deltas de objetos e handles, recusando contagens negativas.
pub fn account(name: &str, objects: i64, handles: i64) -> Result<(), KernelError> {
    let mut types = TYPES.lock();
    let record = types.by_name.get_mut(name).ok_or_else(|| KernelError::new(alloc::format!("unknown object type: {name}")))?;
    apply(record, objects, handles)
}

/// Associa um corpo vivo ao tipo e o contabiliza uma vez.
pub fn bind_native(pointer: u64, type_name: &str) -> Result<(), KernelError> {
    if pointer == 0 {
        return Err(KernelError::new("native object body is NULL"));
    }
    {
        let mut types = TYPES.lock();
        match types.by_body.get(&pointer) {
            Some(previous) if previous != type_name => return Err(KernelError::new("native object type changed")),
            Some(_) => return Ok(()),
            None => {
                types.by_body.insert(pointer, String::from(type_name));
            }
        }
    }
    account(type_name, 1, 0)
}

pub fn unbind_native(pointer: u64) {
    let name = TYPES.lock().by_body.remove(&pointer);
    if let Some(name) = name {
        let _ = account(&name, -1, 0);
    }
}

/// (objetos, handles, pico de objetos, pico de handles) do tipo.
pub fn statistics(name: &str) -> Option<(u32, u32, u32, u32)> {
    TYPES.lock().by_name.get(name).map(|record| (record.objects, record.handles, record.peak_objects, record.peak_handles))
}

/// Eleva os picos com os de um subsistema que conta por conta própria.
pub fn raise_peaks(name: &str, peak_objects: u32, peak_handles: u32) {
    let mut types = TYPES.lock();
    if let Some(record) = types.by_name.get_mut(name) {
        record.peak_objects = record.peak_objects.max(peak_objects);
        record.peak_handles = record.peak_handles.max(peak_handles);
        guest::write32(record.info.pointer + 0x34, record.peak_objects);
        guest::write32(record.info.pointer + 0x38, record.peak_handles);
    }
}

pub fn bound(pointer: u64) -> Option<ObjectType> {
    let types = TYPES.lock();
    let name = types.by_body.get(&pointer)?;
    types.by_name.get(name).map(|record| record.info.clone())
}

pub fn find(pointer: u64) -> Option<ObjectType> {
    TYPES.lock().by_name.values().find(|record| record.info.pointer == pointer).map(|record| record.info.clone())
}

pub fn by_name(name: &str) -> Option<ObjectType> {
    TYPES.lock().by_name.get(name).map(|record| record.info.clone())
}

/// Tipos na ordem de criação.
pub fn all() -> Vec<ObjectType> {
    let types = TYPES.lock();
    types.order.iter().filter_map(|name| types.by_name.get(name)).map(|record| record.info.clone()).collect()
}

/// (objetos, handles, pico de objetos, pico de handles).
pub fn counts(name: &str) -> Option<(u32, u32, u32, u32)> {
    TYPES
        .lock()
        .by_name
        .get(name)
        .map(|record| (record.objects, record.handles, record.peak_objects, record.peak_handles))
}
