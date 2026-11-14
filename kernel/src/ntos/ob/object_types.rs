//! Descritores OBJECT_TYPE do gerenciador de objetos.
//!
//! Corpo `_OBJECT_TYPE` com o TypeInfo (`_OBJECT_TYPE_INITIALIZER`) embutido.
//! Ponteiros exportados, verificações de tipo e contadores usam a mesma
//! identidade (o ponteiro do corpo). ObCreateObjectType e as células
//! exportadas com ponteiros de tipo também moram aqui.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::ntos::inc::status::STATUS_INSUFFICIENT_RESOURCES;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::inc::types::{self as nt, NtStruct, ObjectTypeInitializer, PoolType};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_data;
use crate::ntos::rtl::guest_strings;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;

/// Key (tag de pool) do tipo Type: 'ObjT'.
const TYPE_TYPE_KEY: u32 = 0x546A_624F;

/// ObTypeIndexTable: o OBJECT_TYPE de cada índice. O 0 fica vazio, o 1 é o
/// MmBadPointer (o tipo de um cabeçalho já liberado) e o 2 é o tipo Type;
/// os demais recebem o primeiro índice livre a partir de 3.
static TYPE_INDEX_TABLE: [AtomicU64; 256] = [const { AtomicU64::new(0) }; 256];

/// ObHeaderCookie: o byte aleatório que o ObInitSystem sorteia no boot
/// (ExGenRandom; aqui o TSC) e que embaralha o TypeIndex de cada
/// OBJECT_HEADER. O bit 0x100 marca o valor já sorteado.
static HEADER_COOKIE: AtomicU32 = AtomicU32::new(0);

/// O ObHeaderCookie, sorteado uma vez antes do primeiro cabeçalho.
pub fn header_cookie() -> u8 {
    let current = HEADER_COOKIE.load(Ordering::Acquire);
    if current & 0x100 != 0 {
        return current as u8;
    }
    let drawn = 0x100 | (crate::hal::cpu::rdtsc() as u32 & 0xFF);
    match HEADER_COOKIE.compare_exchange(0, drawn, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => drawn as u8,
        Err(winner) => winner as u8,
    }
}

/// ObTypeIndexTable[index] (o índice 1 é a célula MmBadPointer, que o
/// ObInitSystem copia para ali).
pub fn type_at_index(index: u8) -> u64 {
    if index == 1 {
        return kernel_data::read("MmBadPointer");
    }
    TYPE_INDEX_TABLE[index as usize].load(Ordering::Acquire)
}

/// A tag de pool de um tipo (OBJECT_TYPE.Key), como o ObCreateObjectTypeEx
/// a monta: os quatro primeiros caracteres ANSI do nome, completados com
/// espaços; 'ObjT' para o próprio tipo Type.
fn pool_key(name: &str) -> u32 {
    if name == "Type" {
        return TYPE_TYPE_KEY;
    }
    let mut bytes = [b' '; 4];
    for (slot, character) in bytes.iter_mut().zip(name.chars()) {
        *slot = if character.is_ascii() { character as u8 } else { b'?' };
    }
    u32::from_le_bytes(bytes)
}

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

/// O `_OBJECT_TYPE` publicado de um tipo registrado.
fn native(pointer: u64) -> &'static nt::ObjectType {
    // SAFETY: corpos alocados por `create`, nunca liberados depois de publicados.
    unsafe { nt::ObjectType::at(pointer) }
}

/// Espelha as contagens (a fonte é o registro, sob TYPES) no OBJECT_TYPE.
fn publish_counts(record: &TypeRecord) {
    let body = native(record.info.pointer);
    body.total_number_of_objects.set(record.objects);
    body.total_number_of_handles.set(record.handles);
    body.high_water_number_of_objects.set(record.peak_objects);
    body.high_water_number_of_handles.set(record.peak_handles);
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
    // O tipo Type é o primeiro (índice 2), como no ObInitSystem.
    if name != "Type" && !TYPES.lock().by_name.contains_key("Type") {
        meta_type();
    }
    let mut types = TYPES.lock();
    if types.by_name.contains_key(name) {
        return Err(KernelError::new(alloc::format!("duplicate object type: {name}")));
    }
    if types.next_index == 0 {
        return Err(KernelError::with_status("object type index table is full", STATUS_INSUFFICIENT_RESOURCES));
    }
    let units: Vec<u16> = name.encode_utf16().collect();
    let pointer = guest::alloc_bytes(nt::ObjectType::SIZE);
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
    let body = native(pointer);
    body.type_list.flink.set(body.type_list.address());
    body.type_list.blink.set(body.type_list.address());
    body.name.length.set((units.len() * 2) as u16);
    body.name.maximum_length.set(((units.len() + 1) * 2) as u16);
    body.name.buffer.set(name_buffer);
    let text: Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    guest::write_bytes(name_buffer, &text);
    let index = types.next_index;
    types.next_index = types.next_index.wrapping_add(1);
    body.index.set(index);
    body.key.set(pool_key(name));
    TYPE_INDEX_TABLE[index as usize].store(pointer, Ordering::Release);
    let info = &body.type_info;
    info.length.set(ObjectTypeInitializer::SIZE as u16);
    info.object_type_flags.set(flags);
    let generic = &info.generic_mapping;
    generic.generic_read.set(mapping[0]);
    generic.generic_write.set(mapping[1]);
    generic.generic_execute.set(mapping[2]);
    generic.generic_all.set(mapping[3]);
    info.valid_access_mask.set(valid_access);
    body.callback_list.flink.set(body.callback_list.address());
    body.callback_list.blink.set(body.callback_list.address());
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

/// O OBJECT_TYPE_INITIALIZER com que o executive cria um tipo no boot
/// (os campos que o OpenNT guarda no TypeInfo).
pub struct TypeTemplate {
    pub name: &'static str,
    pub mapping: [u32; 4],
    pub valid_access: u32,
    pub flags: u16,
    pub object_type_code: u32,
    pub invalid_attributes: u32,
    pub pool_type: u32,
    pub paged_charge: u32,
    pub non_paged_charge: u32,
}

/// O tipo do modelo, criado na primeira chamada (as seguintes devolvem o
/// mesmo; um tipo criado antes sob demanda com o mesmo nome é completado)
/// com o TypeInfo preenchido como o ObCreateObjectType do NT.
pub fn ensure(template: &TypeTemplate) -> ObjectType {
    let existing = TYPES.lock().by_name.get(template.name).map(|record| record.info.clone());
    let info = match existing {
        Some(info) => info,
        None => create(template.name, template.mapping, template.valid_access, template.flags).unwrap_or_else(|error| panic!("{error}")),
    };
    let type_info = &native(info.pointer).type_info;
    type_info.object_type_code.set(template.object_type_code);
    type_info.invalid_attributes.set(template.invalid_attributes);
    type_info.pool_type.set(PoolType(template.pool_type as i32));
    type_info.default_paged_pool_charge.set(template.paged_charge);
    type_info.default_non_paged_pool_charge.set(template.non_paged_charge);
    info
}

/// O OBJECT_TYPE publicado de um tipo registrado (`None` para outro
/// ponteiro).
pub fn type_object(pointer: u64) -> Option<&'static nt::ObjectType> {
    find(pointer).map(|info| native(info.pointer))
}

/// ObpDefaultObject: o cabeçalho de despacho sempre sinalizado que os tipos
/// com UseDefaultObject publicam em DefaultObject.
fn default_object() -> u64 {
    static DEFAULT_OBJECT: AtomicU64 = AtomicU64::new(0);
    let current = DEFAULT_OBJECT.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }
    let event = guest::alloc_bytes(nt::Kevent::SIZE);
    crate::ntos::ke::dispatcher::initialize_event(event, 0, true);
    match DEFAULT_OBJECT.compare_exchange(0, event, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => event,
        Err(winner) => {
            guest::free_bytes(event);
            winner
        }
    }
}

/// OBJ_VALID_ATTRIBUTES mais OBJ_KERNEL_EXCLUSIVE (0x10000): o complemento
/// de 0xFFFEE00D, a máscara que o ObCreateObjectTypeEx aplica a
/// InvalidAttributes.
const VALID_OBJECT_ATTRIBUTES: u32 = !0xFFFE_E00D;
/// O que o ObCreateObjectTypeEx soma à cobrança padrão do pool do tipo:
/// 0x58 bytes, mais 0x10 com MaintainHandleCount.
const HEADER_CHARGE: u32 = 0x58;
const HANDLE_INFO_CHARGE: u32 = 0x10;
/// SYNCHRONIZE, que um tipo com UseDefaultObject passa a aceitar.
const SYNCHRONIZE: u32 = 0x10_0000;

// --- ObCreateObjectTypeEx -------------------------------------------------
// NTSTATUS ObCreateObjectTypeEx(PUNICODE_STRING TypeName,
//   POBJECT_TYPE_INITIALIZER Init, PSECURITY_DESCRIPTOR Sd,
//   PVOID DefaultObject, POBJECT_TYPE *ObjectType); ObCreateObjectType é o
// mesmo com DefaultObject NULL.
//
// Como no ntoskrnl 19041 (rva 0x7906a0): o nome não vazio, de tamanho par e
// sem barra invertida (STATUS_OBJECT_NAME_INVALID); o inicializador com Length 0x78,
// InvalidAttributes dentro dos atributos válidos, só UseExtendedParameters no
// segundo byte de flags, MaintainHandleCount só com Open ou Close procedure e,
// sem UseDefaultObject, PoolType NonPagedPool ou NonPagedPoolNx (o NT trata
// a violação com DbgPrintEx e int3; aqui é STATUS_INVALID_PARAMETER); nome
// repetido é STATUS_OBJECT_NAME_COLLISION. O TypeInfo é a cópia inteira do
// inicializador (procedimentos inclusive); a cobrança padrão do pool do tipo
// ganha 0x58 (mais 0x10 com MaintainHandleCount); com UseDefaultObject o ValidAccessMask ganha
// SYNCHRONIZE e DefaultObject aponta o ObpDefaultObject, senão é o
// DefaultObject pedido. Key é a tag de pool do nome e Index o índice livre
// da ObTypeIndexTable.
pub fn create_type_ex(name_pointer: u64, init: u64, default_object_offset: u64, out: u64) -> u32 {
    if name_pointer == 0 || init == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: UNICODE_STRING e OBJECT_TYPE_INITIALIZER de um chamador de kernel.
    let name_string = unsafe { nt::UnicodeString::at(name_pointer) };
    let length = name_string.length.get();
    // SAFETY: idem.
    let initializer = unsafe { ObjectTypeInitializer::at(init) };
    let flags = initializer.object_type_flags.get();
    let pool_type = initializer.pool_type.get().0 as u32;
    let maintain_handle_count = flags & 0x10 != 0;
    let use_default_object = flags & 0x4 != 0;
    if length == 0
        || length & 1 != 0
        || initializer.invalid_attributes.get() & !VALID_OBJECT_ATTRIBUTES != 0
        || initializer.length.get() != ObjectTypeInitializer::SIZE as u16
        || initializer.bitfield_3.get() >= 2
        || (maintain_handle_count && initializer.open_procedure.get() == 0 && initializer.close_procedure.get() == 0)
        || (!use_default_object && pool_type & !0x200 != 0 && default_object_offset & 1 == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    let name = guest_strings::read_unicode_string(name_pointer);
    if name.contains('\\') {
        return STATUS_OBJECT_NAME_INVALID;
    }
    let generic = &initializer.generic_mapping;
    let mapping = [generic.generic_read.get(), generic.generic_write.get(), generic.generic_execute.get(), generic.generic_all.get()];
    let Ok(info) = create(&name, mapping, initializer.valid_access_mask.get(), flags) else {
        return STATUS_OBJECT_NAME_COLLISION;
    };
    let body = native(info.pointer);
    guest::write_bytes(body.type_info.address(), &guest::read_bytes(init, ObjectTypeInitializer::SIZE as usize));
    let type_info = &body.type_info;
    let charge = HEADER_CHARGE + if maintain_handle_count { HANDLE_INFO_CHARGE } else { 0 };
    if pool_type & 1 != 0 {
        type_info.default_paged_pool_charge.set(type_info.default_paged_pool_charge.get().wrapping_add(charge));
    } else {
        type_info.default_non_paged_pool_charge.set(type_info.default_non_paged_pool_charge.get().wrapping_add(charge));
    }
    let mut valid = type_info.valid_access_mask.get();
    if use_default_object {
        valid |= SYNCHRONIZE;
        type_info.valid_access_mask.set(valid);
        body.default_object.set(default_object());
    } else {
        body.default_object.set(default_object_offset);
    }
    if let Some(record) = TYPES.lock().by_name.get_mut(&name) {
        record.info.valid_access = valid;
    }
    if out != 0 {
        // SAFETY: POBJECT_TYPE* de saída do mesmo chamador.
        unsafe { nt::Field::<u64>::at(out) }.set(info.pointer);
    }
    STATUS_SUCCESS
}

/// Célula de dados exportada com o ponteiro de um tipo (IoDeviceObjectType,
/// ExSemaphoreObjectType, LpcPortObjectType), preenchida no heap.
pub fn exported_cell(name: &str) -> u64 {
    kernel_data::address(name).unwrap_or_else(|error| panic!("{name}: {error}"))
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

/// Tipo paginável ou não paginável dos contextos de silo, com o PoolType
/// do OBJECT_TYPE_INITIALIZER (TypeInfo.PoolType).
pub fn silo_context_type(paged: bool) -> ObjectType {
    let name = if paged { "PsSiloContextPaged" } else { "PsSiloContextNonPaged" };
    if let Some(record) = TYPES.lock().by_name.get(name) {
        return record.info.clone();
    }
    let info = create(name, [0x20000, 0x20000, 0x20000, 0xF0000], 0x1F0000, 2).unwrap_or_else(|error| panic!("{error}"));
    native(info.pointer).type_info.pool_type.set(if paged { PoolType::PAGED_POOL } else { PoolType::NON_PAGED_POOL_NX });
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
        let body = native(record.info.pointer);
        body.high_water_number_of_objects.set(record.peak_objects);
        body.high_water_number_of_handles.set(record.peak_handles);
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
