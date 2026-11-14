//! O OBJECT_HEADER do NT na frente dos corpos criados pelo ObCreateObject —
//! o ObpAllocateObject e o ObpFreeObject do ntoskrnl 19041 — e a vida
//! desses objetos pelo cabeçalho: PointerCount (ObfReferenceObject,
//! ObfDereferenceObject e a remoção adiada do ObpDeferObjectDeletion),
//! HandleCount com a contagem por processo do HandleInfo (o
//! ObpIncrementHandleCountEx e o ObpDecrementHandleCount), a cobrança de
//! cota e o nome do NameInfo.
//!
//! Uma alocação, do endereço baixo para o alto: o preenchimento de
//! alinhamento dos tipos CacheAligned (InfoMask 0x80, com o
//! OBJECT_HEADER_PADDING_INFO nos 4 bytes antes do resto), EXTENDED (0x40),
//! AUDIT (0x20), PROCESS (0x10), QUOTA (0x08), HANDLE (0x04), NAME (0x02),
//! CREATOR (0x01), o `_OBJECT_HEADER` (0x30 bytes) e o corpo. O cabeçalho
//! opcional de bit `b` fica em `Header - ObpInfoMaskToOffset[InfoMask &
//! (2b - 1)]`. O TypeIndex do cabeçalho é `Type->Index ^ ObHeaderCookie ^
//! (byte 1 do endereço do cabeçalho)`, decodificado pela ObTypeIndexTable.
//! O bloco vem do pool do tipo (TypeInfo.PoolType, zerado, tag = Key).
//!
//! Os objetos de outros donos do OpenNT (processos, threads, arquivos,
//! dispositivos, drivers, seções, tokens, chaves, eventos e o namespace)
//! ainda não têm cabeçalho: o registro `LIVE` distingue os corpos com
//! cabeçalho, e só eles são lidos aqui.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::types::extra_ob_header::{ObjectCreateInformation, ObjectHandleCountDatabase, ObjectHandleCountEntry, ObjectHeaderCreatorInfo, ObjectHeaderHandleInfo, ObjectHeaderPaddingInfo, ObjectHeaderProcessInfo, ObjectHeaderQuotaInfo};
use crate::ntos::inc::types::{Eprocess, Field, NtStruct, ObjectHeader, ObjectHeaderNameInfo, ObjectType as NativeObjectType};
use crate::ntos::ke::{bugcheck, critical_region};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_pool::PoolQuota;
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::ob::object_types;
use crate::ntos::ob::type_procedures::{self, SecurityOperation};
use crate::ntos::ps::{pool_quota, process};
use crate::ntos::se::descriptor;
use crate::rtl::SpinLock;

pub const INFO_CREATOR: u8 = 0x01;
pub const INFO_NAME: u8 = 0x02;
pub const INFO_HANDLE: u8 = 0x04;
pub const INFO_QUOTA: u8 = 0x08;
pub const INFO_PROCESS: u8 = 0x10;
pub const INFO_AUDIT: u8 = 0x20;
pub const INFO_EXTENDED: u8 = 0x40;
pub const INFO_PADDING: u8 = 0x80;

/// Tamanho de cada cabeçalho opcional, do bit 0x01 ao 0x80.
const INFO_SIZES: [u8; 8] = [0x20, 0x20, 0x10, 0x20, 0x10, 0x10, 0x10, 0x4];

const fn info_mask_to_offset() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut mask = 0;
    while mask < 256 {
        let mut total = 0u8;
        let mut bit = 0;
        while bit < 8 {
            if mask & (1 << bit) != 0 {
                total += INFO_SIZES[bit];
            }
            bit += 1;
        }
        table[mask] = total;
        mask += 1;
    }
    table
}

/// ObpInfoMaskToOffset, como o ObpInitInfoBlockOffsets a preenche.
pub static INFO_MASK_TO_OFFSET: [u8; 256] = info_mask_to_offset();

/// O corpo começa em OBJECT_HEADER + 0x30 (`Body`).
pub const BODY_OFFSET: u64 = core::mem::offset_of!(ObjectHeader, body) as u64;

// OBJECT_HEADER.Flags.
pub const FLAG_NEW_OBJECT: u8 = ObjectHeader::NEW_OBJECT_MASK;
pub const FLAG_KERNEL_OBJECT: u8 = ObjectHeader::KERNEL_OBJECT_MASK;
pub const FLAG_KERNEL_ONLY_ACCESS: u8 = ObjectHeader::KERNEL_ONLY_ACCESS_MASK;
pub const FLAG_EXCLUSIVE_OBJECT: u8 = ObjectHeader::EXCLUSIVE_OBJECT_MASK;
pub const FLAG_PERMANENT_OBJECT: u8 = ObjectHeader::PERMANENT_OBJECT_MASK;
pub const FLAG_SINGLE_HANDLE_ENTRY: u8 = ObjectHeader::SINGLE_HANDLE_ENTRY_MASK;
pub const FLAG_DELETED_INLINE: u8 = ObjectHeader::DELETED_INLINE_MASK;

// OBJECT_TYPE_INITIALIZER.ObjectTypeFlags (byte baixo).
const TYPE_UNNAMED_OBJECTS_ONLY: u8 = 0x02;
const TYPE_MAINTAIN_HANDLE_COUNT: u8 = 0x10;
const TYPE_MAINTAIN_TYPE_LIST: u8 = 0x20;
const TYPE_CACHE_ALIGNED: u8 = 0x80;

// OBJECT_ATTRIBUTES.Attributes.
const OBJ_INHERIT: u32 = 0x2;
const OBJ_PERMANENT: u32 = 0x10;
const OBJ_EXCLUSIVE: u32 = 0x20;
const OBJ_FORCE_ACCESS_CHECK: u32 = 0x400;
/// O bit interno que marca o objeto KernelOnlyAccess (OwnerMode KernelMode).
const OBJ_KERNEL_ONLY_ACCESS: u32 = 0x1_0000;

const PAGED_POOL: u32 = 1;
/// POOL_ZERO_ALLOCATION: o ObpAllocateObject pede o bloco zerado.
const POOL_ZERO_ALLOCATION: u32 = 0x400;
/// Tag do ObpFreeObject para um cabeçalho sem tipo: 'ObjT'.
const FALLBACK_POOL_TAG: u32 = 0x546A_624F;
/// Tag do texto do nome capturado: 'ObNm'.
pub const NAME_BUFFER_TAG: u32 = 0x6D4E_624F;
/// Tag do OBJECT_CREATE_INFORMATION: 'ObCi'.
pub const CREATE_INFO_TAG: u32 = 0x6943_624F;
/// Tag dos blocos de contagem de handles por processo: 'ObHd'.
const HANDLE_DATABASE_TAG: u32 = 0x6448_624F;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_QUOTA_EXCEEDED: u32 = 0xC000_0044;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// REFERENCE_BY_POINTER.
const BUGCHECK_REFERENCE_BY_POINTER: u32 = 0x18;
/// O ObpRemoveObjectRoutine num objeto de tipo: KeBugCheckEx(0xF4, ...).
const BUGCHECK_TYPE_OBJECT_DELETE: u32 = 0xF4;

/// Estado do OpenNT por objeto com cabeçalho: o nó do namespace do nome
/// inserido e as cobranças de cota confirmadas (o NT as devolve pelo bloco
/// de cota do processo).
#[derive(Default)]
struct Record {
    node: Option<NodeId>,
    quota: Vec<PoolQuota>,
}

/// Cabeçalhos vivos (o endereço do OBJECT_HEADER).
static LIVE: SpinLock<BTreeMap<u64, Record>> = SpinLock::new(BTreeMap::new());

/// O lock do banco de contagens por processo (o push lock do cabeçalho no
/// NT); nunca é mantido durante uma rotina de tipo.
static HANDLE_COUNTS: SpinLock<()> = SpinLock::new(());

/// O OBJECT_HEADER em `header`.
fn header_at(header: u64) -> &'static ObjectHeader {
    // SAFETY: cabeçalho vivo do registro (alocado por `allocate`).
    unsafe { ObjectHeader::at(header) }
}

fn native_type(pointer: u64) -> &'static NativeObjectType {
    // SAFETY: OBJECT_TYPE registrado (o ObTypeIndexTable só guarda tipos vivos).
    unsafe { NativeObjectType::at(pointer) }
}

/// O cabeçalho de `body`, se o corpo foi criado com cabeçalho.
pub fn header_of(body: u64) -> Option<u64> {
    let header = body.checked_sub(BODY_OFFSET)?;
    LIVE.lock().contains_key(&header).then_some(header)
}

/// O corpo tem o OBJECT_HEADER do NT.
pub fn is_object(body: u64) -> bool {
    header_of(body).is_some()
}

/// O OBJECT_HEADER de um corpo com cabeçalho.
pub fn header(body: u64) -> Option<&'static ObjectHeader> {
    header_of(body).map(header_at)
}

/// O endereço do cabeçalho opcional `bit` de `header`, ou 0 se ausente.
pub fn info(header: u64, bit: u8) -> u64 {
    let mask = header_at(header).info_mask.get();
    if mask & bit == 0 {
        return 0;
    }
    header - INFO_MASK_TO_OFFSET[(mask & (bit | (bit - 1))) as usize] as u64
}

/// O OBJECT_TYPE pelo TypeIndex do cabeçalho (o ObGetObjectType).
pub fn type_of_header(header: u64) -> u64 {
    let index = header_at(header).type_index.get() ^ object_types::header_cookie() ^ (header >> 8) as u8;
    object_types::type_at_index(index)
}

/// O OBJECT_TYPE de um corpo com cabeçalho.
pub fn object_type(body: u64) -> Option<u64> {
    header_of(body).map(type_of_header)
}

/// O registro público do tipo de um corpo com cabeçalho.
pub fn object_type_info(body: u64) -> Option<object_types::ObjectType> {
    object_type(body).and_then(object_types::find)
}

/// O OBJECT_HEADER_NAME_INFO de um corpo com cabeçalho (o ObQueryNameInfo),
/// ou 0.
pub fn name_info(body: u64) -> u64 {
    header_of(body).map_or(0, |header| info(header, INFO_NAME))
}

fn type_flags(object_type: u64) -> u8 {
    native_type(object_type).type_info.bitfield_2.get()
}

/// O tipo de pool do OpenNT para o PoolType de um tipo: sem pool de sessão
/// (bit 0x20), o pool global equivalente; o paginável já é NX.
fn pool_type_of(object_type: u64) -> u32 {
    let pool = native_type(object_type).type_info.pool_type.get().0 as u32 & !0x20;
    if pool & 1 != 0 {
        pool & !0x200
    } else {
        pool
    }
}

/// O processo corrente é o System ou o ocioso (o OpenNT não tem EPROCESS
/// ocioso): o ObpAllocateObject não reserva QuotaInfo para eles.
fn system_context() -> bool {
    let system = process::get_system_process();
    system == 0 || process::get_current_process() == system
}

// --- ObpAllocateObject ------------------------------------------------------
// NTSTATUS ObpAllocateObject(POBJECT_CREATE_INFORMATION CreateInfo,
//   KPROCESSOR_MODE OwnerMode, POBJECT_TYPE Type, PUNICODE_STRING Name,
//   ULONG BodySize, POBJECT_HEADER *Header, ...)
//
// Como no ntoskrnl 19041 (rva 0x64c950): ProcessInfo com OBJ_EXCLUSIVE;
// AuditInfo só quando o SeAuditHeaderRequired pede (arquivos com auditoria
// ligada; o OpenNT não tem política de auditoria); QuotaInfo fora do System
// com as cobranças do CreateInfo; HandleInfo com MaintainHandleCount (a
// entrada única, Flags 0x41); NameInfo com o nome capturado (Directory NULL;
// um tipo UnnamedObjectsOnly recusa com STATUS_OBJECT_NAME_INVALID);
// CreatorInfo com MaintainTypeList (o processo criador, a lista vazia);
// preenchimento até 64 bytes nos tipos CacheAligned. PointerCount 1,
// HandleCount 0, Flags NewObject (+ KernelObject com OwnerMode KernelMode, +
// KernelOnlyAccess com o bit 0x10000, + PermanentObject com OBJ_PERMANENT, +
// ExclusiveObject com OBJ_EXCLUSIVE), ObjectCreateInfo = CreateInfo e o
// TotalNumberOfObjects do tipo contado.
pub fn allocate(create_info: u64, owner_mode: u8, object_type: u64, name: (u16, u16, u64), body_size: u32) -> Result<u64, u32> {
    let (name_length, name_maximum, name_buffer) = name;
    // SAFETY: OBJECT_CREATE_INFORMATION capturado pelo chamador (memória do kernel).
    let create = unsafe { ObjectCreateInformation::at(create_info) };
    let attributes = create.attributes.get();
    let flags = type_flags(object_type);
    let mut mask = 0u8;
    if attributes & OBJ_EXCLUSIVE != 0 {
        mask |= INFO_PROCESS;
    }
    if !system_context() {
        mask |= INFO_QUOTA;
    }
    if flags & TYPE_MAINTAIN_HANDLE_COUNT != 0 {
        mask |= INFO_HANDLE;
    }
    if name_length != 0 {
        if flags & TYPE_UNNAMED_OBJECTS_ONLY != 0 {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        mask |= INFO_NAME;
    }
    if flags & TYPE_MAINTAIN_TYPE_LIST != 0 {
        mask |= INFO_CREATOR;
    }
    let reserve = if flags & TYPE_CACHE_ALIGNED != 0 { 0x30u32 } else { 0 };
    let headers = INFO_MASK_TO_OFFSET[mask as usize] as u32 + BODY_OFFSET as u32;
    let fixed = headers + reserve;
    let Some(total) = fixed.checked_add(body_size) else { return Err(STATUS_INVALID_PARAMETER) };
    let key = native_type(object_type).key.get();
    let base = pool_allocation::allocate_tagged(pool_type_of(object_type) | POOL_ZERO_ALLOCATION, total as u64, key).unwrap_or(0);
    if base == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let mut cursor = base;
    if reserve != 0 {
        let padding = (cursor + headers as u64).wrapping_neg() & 0x3F;
        if padding != 0 {
            cursor += padding;
            mask |= INFO_PADDING;
            // SAFETY: os 4 bytes antes do resto dos cabeçalhos, dentro do bloco.
            unsafe { ObjectHeaderPaddingInfo::at(cursor - 4) }.padding_amount.set(padding as u32);
        }
    }
    if mask & INFO_PROCESS != 0 {
        // SAFETY: cabeçalho opcional dentro do bloco recém-alocado.
        unsafe { ObjectHeaderProcessInfo::at(cursor) }.exclusive_process.set(0);
        cursor += ObjectHeaderProcessInfo::SIZE;
    }
    if mask & INFO_QUOTA != 0 {
        // SAFETY: idem.
        let quota = unsafe { ObjectHeaderQuotaInfo::at(cursor) };
        quota.paged_pool_charge.set(create.paged_pool_charge.get());
        quota.non_paged_pool_charge.set(create.non_paged_pool_charge.get());
        quota.security_descriptor_charge.set(create.security_descriptor_charge.get());
        quota.security_descriptor_quota_block.set(0);
        cursor += ObjectHeaderQuotaInfo::SIZE;
    }
    if mask & INFO_HANDLE != 0 {
        // SAFETY: idem.
        let handle_info = unsafe { ObjectHeaderHandleInfo::at(cursor) };
        handle_info.single_entry.process.set(0);
        handle_info.single_entry.bitfield_8.set(0);
        cursor += ObjectHeaderHandleInfo::SIZE;
    }
    if mask & INFO_NAME != 0 {
        // SAFETY: idem.
        let name_info = unsafe { ObjectHeaderNameInfo::at(cursor) };
        name_info.directory.set(0);
        name_info.name.length.set(name_length);
        name_info.name.maximum_length.set(name_maximum);
        name_info.name.buffer.set(name_buffer);
        name_info.reference_count.set(0);
        cursor += ObjectHeaderNameInfo::SIZE;
    }
    if mask & INFO_CREATOR != 0 {
        // SAFETY: idem.
        let creator = unsafe { ObjectHeaderCreatorInfo::at(cursor) };
        creator.creator_back_trace_index.set(0);
        // SAFETY: o EPROCESS corrente.
        creator.creator_unique_process.set(unsafe { Eprocess::at(process::get_current_process()) }.unique_process_id.get());
        creator.type_list.flink.set(creator.type_list.address());
        creator.type_list.blink.set(creator.type_list.address());
        cursor += ObjectHeaderCreatorInfo::SIZE;
    }
    let header = header_at(cursor);
    header.info_mask.set(mask);
    header.trace_flags.set(0);
    let mut header_flags = FLAG_NEW_OBJECT;
    if flags & TYPE_MAINTAIN_HANDLE_COUNT != 0 {
        header_flags |= FLAG_SINGLE_HANDLE_ENTRY;
    }
    header.handle_count.set(0);
    header.pointer_count.set(1);
    header.lock.value.set(0);
    let index = native_type(object_type).index.get();
    header.type_index.set(index ^ object_types::header_cookie() ^ (cursor >> 8) as u8);
    if owner_mode == 0 {
        header_flags |= FLAG_KERNEL_OBJECT;
        if attributes & OBJ_KERNEL_ONLY_ACCESS != 0 {
            header_flags |= FLAG_KERNEL_ONLY_ACCESS;
        }
    }
    if attributes & OBJ_PERMANENT != 0 {
        header_flags |= FLAG_PERMANENT_OBJECT;
    }
    if attributes & OBJ_EXCLUSIVE != 0 {
        header_flags |= FLAG_EXCLUSIVE_OBJECT;
    }
    header.flags.set(header_flags);
    header.object_create_info.set(create_info);
    header.security_descriptor.set(0);
    LIVE.lock().insert(cursor, Record::default());
    if let Some(info) = object_types::find(object_type) {
        let _ = object_types::account(&info.name, 1, 0);
    }
    Ok(cursor)
}

/// Libera o OBJECT_CREATE_INFORMATION capturado (o descritor capturado
/// junto) — o fim do ObpFreeObjectCreateInformation.
pub fn free_create_info(create_info: u64) {
    if create_info == 0 {
        return;
    }
    // SAFETY: OBJECT_CREATE_INFORMATION capturado por `object_create::capture`.
    let create = unsafe { ObjectCreateInformation::at(create_info) };
    let descriptor = create.security_descriptor.get();
    if descriptor != 0 {
        descriptor::release_captured(descriptor);
        create.security_descriptor.set(0);
    }
    let _ = pool_allocation::free(create_info, CREATE_INFO_TAG as u64);
}

// --- ObpFreeObject ----------------------------------------------------------
// Como no ntoskrnl 19041 (rva 0x63dc40): tira o CreatorInfo da lista do
// tipo, desconta o TotalNumberOfObjects, libera a informação de criação
// ainda presa (NewObject) ou devolve a cota cobrada (QuotaBlockCharged), o
// banco de contagens por processo, o texto do nome, marca o TypeIndex com o
// índice 1 e devolve o bloco ao pool com a tag do tipo.
pub fn free(header: u64) {
    let record = LIVE.lock().remove(&header).unwrap_or_default();
    let object = header_at(header);
    let mask = object.info_mask.get();
    let object_type = type_of_header(header);
    let type_info = object_types::find(object_type);
    let creator = info(header, INFO_CREATOR);
    if creator != 0 {
        unlink_creator(object_type, creator);
    }
    if let Some(type_info) = &type_info {
        let _ = object_types::account(&type_info.name, -1, 0);
    }
    let flags = object.flags.get();
    if flags & FLAG_NEW_OBJECT != 0 {
        free_create_info(object.object_create_info.get());
    } else {
        for quota in record.quota {
            (quota.release)(quota.process_pointer, quota.paged, quota.bytes);
        }
    }
    object.object_create_info.set(0);
    let handle_info = info(header, INFO_HANDLE);
    if handle_info != 0 && flags & FLAG_SINGLE_HANDLE_ENTRY == 0 {
        // SAFETY: HandleInfo do cabeçalho; sem SingleHandleEntry o primeiro
        // QWORD é o banco de contagens.
        let database = unsafe { Field::<u64>::at(handle_info) }.get();
        if database != 0 {
            let _ = pool_allocation::free(database, HANDLE_DATABASE_TAG as u64);
        }
    }
    let name = info(header, INFO_NAME);
    if name != 0 {
        // SAFETY: NameInfo do cabeçalho.
        let name_info = unsafe { ObjectHeaderNameInfo::at(name) };
        let buffer = name_info.name.buffer.get();
        if buffer != 0 {
            let _ = pool_allocation::free(buffer, NAME_BUFFER_TAG as u64);
            name_info.name.buffer.set(0);
        }
    }
    let base = header - INFO_MASK_TO_OFFSET[mask as usize] as u64;
    let base = if mask & INFO_PADDING != 0 {
        // SAFETY: o OBJECT_HEADER_PADDING_INFO do bloco.
        base + 4 - unsafe { ObjectHeaderPaddingInfo::at(base) }.padding_amount.get() as u64
    } else {
        base
    };
    object.type_index.set(object_types::header_cookie() ^ (header >> 8) as u8 ^ 1);
    let tag = if object_type != 0 && type_info.is_some() { native_type(object_type).key.get() } else { FALLBACK_POOL_TAG };
    let _ = pool_allocation::free(base, tag as u64);
}

/// O CreatorInfo entra na TypeList do tipo no primeiro handle (ObCreateHandle).
fn link_creator(object_type: u64, creator: u64) {
    let _guard = HANDLE_COUNTS.lock();
    // SAFETY: CreatorInfo do cabeçalho e o OBJECT_TYPE vivo.
    let entry = unsafe { ObjectHeaderCreatorInfo::at(creator) };
    if entry.type_list.flink.get() != entry.type_list.address() {
        return;
    }
    let head = &native_type(object_type).type_list;
    let last = head.blink.get();
    entry.type_list.flink.set(head.address());
    entry.type_list.blink.set(last);
    // SAFETY: o último elemento da lista (LIST_ENTRY viva).
    unsafe { crate::ntos::inc::types::ListEntry::at(last) }.flink.set(entry.type_list.address());
    head.blink.set(entry.type_list.address());
}

fn unlink_creator(object_type: u64, creator: u64) {
    let _guard = HANDLE_COUNTS.lock();
    // SAFETY: CreatorInfo do cabeçalho.
    let entry = unsafe { ObjectHeaderCreatorInfo::at(creator) };
    let (next, previous) = (entry.type_list.flink.get(), entry.type_list.blink.get());
    if next == entry.type_list.address() || object_type == 0 {
        return;
    }
    // SAFETY: vizinhos vivos da lista do tipo.
    unsafe { crate::ntos::inc::types::ListEntry::at(previous) }.flink.set(next);
    // SAFETY: idem.
    unsafe { crate::ntos::inc::types::ListEntry::at(next) }.blink.set(previous);
    entry.type_list.flink.set(entry.type_list.address());
    entry.type_list.blink.set(entry.type_list.address());
}

// --- ObfReferenceObject / ObfDereferenceObject --------------------------------

/// PointerCount += `count` (o ObfReferenceObject soma 1). Um objeto que
/// estava em zero é KeBugCheckEx(REFERENCE_BY_POINTER, 0, Object, 0x10,
/// PointerCount). Devolve o valor novo.
pub fn reference(body: u64, count: i64) -> i64 {
    let header = body - BODY_OFFSET;
    let value = header_at(header).pointer_count.atomic().fetch_add(count, Ordering::SeqCst) + count;
    if value <= count {
        bugcheck::bug_check_ex(BUGCHECK_REFERENCE_BY_POINTER, 0, body, 0x10, value as u64);
    }
    value
}

/// ObReferenceObjectSafe: soma 1 só a um PointerCount ainda positivo (um
/// objeto que já chegou a zero está saindo).
pub fn reference_safe(body: u64) -> bool {
    let count = header_at(body - BODY_OFFSET).pointer_count.atomic();
    let mut current = count.load(Ordering::SeqCst);
    while current > 0 {
        match count.compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return true,
            Err(seen) => current = seen,
        }
    }
    false
}

/// ObfDereferenceObjectWithTag (`defer` = ObDereferenceObjectDeferDelete):
/// PointerCount -= 1; no zero, com handles ainda abertos é
/// KeBugCheckEx(REFERENCE_BY_POINTER, Type, Object, 1, HandleCount) e
/// abaixo de zero (…, 0, Object, 2, PointerCount). O objeto sai na hora em
/// PASSIVE_LEVEL sem região guardada; senão (ou com `defer`) a remoção vai
/// para a fila do ObpDeferObjectDeletion. Devolve o valor novo.
pub fn dereference(body: u64, defer: bool) -> i64 {
    let header = body - BODY_OFFSET;
    let object = header_at(header);
    let value = object.pointer_count.atomic().fetch_sub(1, Ordering::SeqCst) - 1;
    if value > 0 {
        return value;
    }
    let handles = object.handle_count.get();
    if handles != 0 {
        bugcheck::bug_check_ex(BUGCHECK_REFERENCE_BY_POINTER, type_of_header(header), body, 1, handles as u64);
    }
    if value < 0 {
        bugcheck::bug_check_ex(BUGCHECK_REFERENCE_BY_POINTER, 0, body, 2, value as u64);
    }
    if defer || critical_region::all_disabled() {
        defer_deletion(header);
    } else {
        remove_object(header, false);
    }
    value
}

// --- ObpDeferObjectDeletion ---------------------------------------------------
// A lista ObpRemoveObjectList encadeia os cabeçalhos por NextToFree (o
// QWORD do HandleCount, zero nesse ponto); o valor 1 marca o trabalhador
// rodando. Quem empilha na lista vazia enfileira o work item
// ObpRemoveObjectWorkItem (o NT passa por um DPC acima de DISPATCH_LEVEL; a
// fila de work items do OpenNT aceita qualquer IRQL). O trabalhador
// (ObpProcessRemoveObjectQueue) troca a lista por 1, remove cada objeto em
// PASSIVE_LEVEL e só devolve a lista a 0 quando nada mais chegou.

static REMOVE_LIST: AtomicU64 = AtomicU64::new(0);
static REMOVE_WORK_ITEM: AtomicU64 = AtomicU64::new(0);

fn remove_work_item() -> u64 {
    let current = REMOVE_WORK_ITEM.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }
    let item = guest::alloc_bytes(crate::ntos::io::work_items::work_item_size());
    match REMOVE_WORK_ITEM.compare_exchange(0, item, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => item,
        Err(winner) => {
            guest::free_bytes(item);
            winner
        }
    }
}

fn defer_deletion(header: u64) {
    let next_to_free = &header_at(header).next_to_free;
    let mut previous = REMOVE_LIST.load(Ordering::Acquire);
    loop {
        next_to_free.set(previous);
        match REMOVE_LIST.compare_exchange(previous, header, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(current) => previous = current,
        }
    }
    if previous == 0 {
        crate::ntos::io::work_items::queue_kernel_work_item(remove_work_item(), process_remove_queue, 0, None);
    }
}

/// ObpProcessRemoveObjectQueue (rva 0x663df0), sem a parte do PatchGuard.
fn process_remove_queue(_device: u64, _context: u64) {
    loop {
        let mut header = REMOVE_LIST.swap(1, Ordering::AcqRel);
        while header != 0 && header != 1 {
            let next = header_at(header).next_to_free.get();
            remove_object(header, true);
            header = next;
        }
        if REMOVE_LIST.compare_exchange(1, 0, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            return;
        }
    }
}

/// Objetos na fila da remoção adiada (para os autotestes).
pub fn deferred_pending() -> bool {
    REMOVE_LIST.load(Ordering::Acquire) > 1
}

// --- ObpRemoveObjectRoutine ---------------------------------------------------
// Como no ntoskrnl 19041 (rva 0x63db60): um objeto de tipo nunca é removido
// (KeBugCheckEx 0xF4); com descritor no cabeçalho, o SecurityProcedure
// recebe DeleteSecurityDescriptor; a DeleteProcedure do tipo roda (fora do
// trabalhador, com DeletedInline no cabeçalho) e o bloco volta pelo
// ObpFreeObject.
fn remove_object(header: u64, on_worker: bool) {
    let object_type = type_of_header(header);
    let body = header + BODY_OFFSET;
    if object_types::find(object_type).is_some_and(|info| info.name == "Type") {
        bugcheck::bug_check_ex(BUGCHECK_TYPE_OBJECT_DELETE, object_type, body, 0, 0);
    }
    if let Some(node) = LIVE.lock().get_mut(&header).and_then(|record| record.node.take()) {
        object_manager::remove_named(node);
    }
    let object = header_at(header);
    if object.security_descriptor.get() != 0 {
        type_procedures::security(object_type, body, SecurityOperation::Delete, 0, 0, 0, object.security_descriptor.address(), 0, 0);
    }
    if native_type(object_type).type_info.delete_procedure.get() != 0 {
        if !on_worker {
            object.flags.set(object.flags.get() | FLAG_DELETED_INLINE);
        }
        type_procedures::delete(object_type, body);
    }
    free(header);
}

// --- Contagem de handles --------------------------------------------------------

/// Razões do OB_OPEN_REASON.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum OpenReason {
    Create = 0,
    Open = 1,
    Duplicate = 2,
    Inherit = 3,
}

/// Uma abertura de handle: a razão, o modo de acesso, o processo dono da
/// tabela, o acesso concedido (que a OpenProcedure pode ajustar) e os
/// atributos do handle.
#[derive(Clone, Copy, Debug)]
pub struct HandleOpen {
    pub reason: OpenReason,
    pub access_mode: u8,
    pub process: u64,
    pub granted: u32,
    pub attributes: u32,
}

fn handle_entry(handle_info: u64) -> &'static ObjectHandleCountEntry {
    // SAFETY: a entrada única do HandleInfo ou uma entrada do banco.
    unsafe { ObjectHandleCountEntry::at(handle_info) }
}

/// As entradas do banco de contagens por processo.
fn database_entries(database: u64) -> &'static [ObjectHandleCountEntry] {
    // SAFETY: banco alocado por `grow_database`, com CountEntries entradas.
    let count = unsafe { ObjectHandleCountDatabase::at(database) }.count_entries.get() as usize;
    // SAFETY: idem.
    unsafe { ObjectHandleCountEntry::array_at(database + core::mem::offset_of!(ObjectHandleCountDatabase, handle_count_entries) as u64, count) }
}

/// O ObpInsertHandleCount: um banco no pool paginável com duas entradas
/// (a entrada única copiada) ou com quatro a mais que o anterior; o
/// cabeçalho deixa de ser SingleHandleEntry.
fn grow_database(object: &ObjectHeader, handle_info: u64) -> Option<u64> {
    let single = object.flags.get() & FLAG_SINGLE_HANDLE_ENTRY != 0;
    // SAFETY: o primeiro QWORD do HandleInfo.
    let slot = unsafe { Field::<u64>::at(handle_info) };
    let old: Vec<(u64, u32)> = if single {
        let entry = handle_entry(handle_info);
        alloc::vec![(entry.process.get(), entry.bitfield_8.get())]
    } else {
        database_entries(slot.get()).iter().map(|entry| (entry.process.get(), entry.bitfield_8.get())).collect()
    };
    let count = if single { 2 } else { old.len() + 4 };
    let size = core::mem::offset_of!(ObjectHandleCountDatabase, handle_count_entries) as u64 + count as u64 * ObjectHandleCountEntry::SIZE;
    let database = pool_allocation::allocate_tagged(PAGED_POOL | POOL_ZERO_ALLOCATION, size, HANDLE_DATABASE_TAG).unwrap_or(0);
    if database == 0 {
        return None;
    }
    // SAFETY: bloco recém-alocado.
    unsafe { ObjectHandleCountDatabase::at(database) }.count_entries.set(count as u32);
    for (entry, (owner, counts)) in database_entries(database).iter().zip(old) {
        entry.process.set(owner);
        entry.bitfield_8.set(counts);
    }
    if !single {
        let _ = pool_allocation::free(slot.get(), HANDLE_DATABASE_TAG as u64);
    }
    slot.set(database);
    object.flags.set(object.flags.get() & !FLAG_SINGLE_HANDLE_ENTRY);
    Some(database)
}

/// O ObpLockHandleDataBaseEntry: a entrada de `owner` (criada se preciso)
/// com LockCount + 1; devolve a entrada e HandleCount + LockCount.
fn lock_handle_entry(object: &ObjectHeader, handle_info: u64, owner: u64) -> Option<(u64, u32)> {
    let lock = |entry: &ObjectHandleCountEntry| {
        entry.bitfield_8.set(entry.bitfield_8.get().wrapping_add(1 << 24));
        (entry.address(), entry.handle_count() + entry.lock_count())
    };
    if object.flags.get() & FLAG_SINGLE_HANDLE_ENTRY != 0 {
        let entry = handle_entry(handle_info);
        if entry.process.get() == 0 {
            entry.process.set(owner);
            entry.bitfield_8.set(0);
            return Some(lock(entry));
        }
        if entry.process.get() == owner {
            return Some(lock(entry));
        }
        grow_database(object, handle_info)?;
    }
    // SAFETY: o primeiro QWORD do HandleInfo é o banco.
    let database = unsafe { Field::<u64>::at(handle_info) }.get();
    if let Some(entry) = database_entries(database).iter().find(|entry| entry.process.get() == owner) {
        return Some(lock(entry));
    }
    let free_entry = match database_entries(database).iter().find(|entry| entry.process.get() == 0) {
        Some(entry) => entry,
        None => {
            let database = grow_database(object, handle_info)?;
            database_entries(database).iter().find(|entry| entry.process.get() == 0)?
        }
    };
    free_entry.process.set(owner);
    free_entry.bitfield_8.set(0);
    Some(lock(free_entry))
}

/// Desfaz o LockCount; com `opened`, o handle passa a contar. Uma entrada
/// sem handles nem travas fica livre.
fn unlock_handle_entry(entry: u64, opened: bool) {
    let entry = handle_entry(entry);
    let mut counts = entry.bitfield_8.get().wrapping_sub(1 << 24);
    if opened {
        counts = (counts & !ObjectHandleCountEntry::HANDLE_COUNT_MASK) | ((counts + 1) & ObjectHandleCountEntry::HANDLE_COUNT_MASK);
    }
    entry.bitfield_8.set(counts);
    if counts == 0 {
        entry.process.set(0);
    }
}

/// A entrada de `owner` no HandleInfo, se houver.
fn find_handle_entry(object: &ObjectHeader, handle_info: u64, owner: u64) -> Option<u64> {
    if object.flags.get() & FLAG_SINGLE_HANDLE_ENTRY != 0 {
        let entry = handle_entry(handle_info);
        return (entry.process.get() == owner).then(|| entry.address());
    }
    // SAFETY: o primeiro QWORD do HandleInfo é o banco.
    let database = unsafe { Field::<u64>::at(handle_info) }.get();
    database_entries(database).iter().find(|entry| entry.process.get() == owner).map(|entry| entry.address())
}

/// Cobrança de cota de um objeto ainda NewObject (a parte do
/// ObpIncrementHandleCountEx e o ObpChargeQuotaForObject): as cobranças do
/// QuotaInfo (ou as padrão do tipo) mais a do descritor, no processo; o
/// System não é cobrado. QuotaBlockCharged recebe o EPROCESS.QuotaBlock ou
/// 1 (o OpenNT não monta blocos de cota: a contagem vai para o
/// ProcessQuotaUsage do EPROCESS e volta pelo registro do objeto).
fn charge_quota(header: u64, owner: u64, descriptor_charge: u32) -> Result<(), u32> {
    let object = header_at(header);
    let quota_info = info(header, INFO_QUOTA);
    let object_type = native_type(type_of_header(header));
    let (paged, non_paged, descriptor) = if quota_info != 0 {
        // SAFETY: QuotaInfo do cabeçalho.
        let quota = unsafe { ObjectHeaderQuotaInfo::at(quota_info) };
        (quota.paged_pool_charge.get(), quota.non_paged_pool_charge.get(), quota.security_descriptor_charge.get().max(descriptor_charge))
    } else {
        (object_type.type_info.default_paged_pool_charge.get(), object_type.type_info.default_non_paged_pool_charge.get(), descriptor_charge)
    };
    let mut tokens = Vec::new();
    if owner != process::get_system_process() {
        for (pool_paged, bytes) in [(true, paged), (false, non_paged), (true, descriptor)] {
            if bytes == 0 {
                continue;
            }
            match pool_quota::charge(owner, pool_paged, bytes as u64) {
                Ok(Ok(Some(token))) => tokens.push(token),
                Ok(Ok(None)) => {}
                _ => {
                    for token in tokens {
                        (token.release)(token.process_pointer, token.paged, token.bytes);
                    }
                    return Err(STATUS_QUOTA_EXCEEDED);
                }
            }
        }
    }
    // SAFETY: o EPROCESS dono (vivo durante a cobrança).
    let block = if owner != 0 { unsafe { Eprocess::at(owner) }.quota_block.get() } else { 0 };
    object.quota_block_charged.set(if block != 0 { block } else { 1 });
    if let Some(record) = LIVE.lock().get_mut(&header) {
        record.quota.extend(tokens);
    }
    Ok(())
}

/// ObpChargeQuotaForObject de um objeto inserido sem handle: limpa
/// NewObject e cobra a cota no processo corrente.
pub fn charge_quota_for_object(body: u64, descriptor_charge: u32) -> Result<(), u32> {
    let header = body - BODY_OFFSET;
    let object = header_at(header);
    if object.flags.get() & FLAG_NEW_OBJECT == 0 {
        return Ok(());
    }
    object.flags.set(object.flags.get() & !FLAG_NEW_OBJECT);
    charge_quota(header, process::get_current_process(), descriptor_charge)
}

// --- ObpIncrementHandleCountEx --------------------------------------------------
// Como no ntoskrnl 19041 (rva 0x643680), sob o lock do cabeçalho: um objeto
// NewObject perde a marca e paga a cota; OBJ_EXCLUSIVE só vale num objeto
// exclusivo não herdável (STATUS_INVALID_PARAMETER) e prende o
// ExclusiveProcess (outro processo, ou handles já abertos sem ele, dão
// STATUS_ACCESS_DENIED); um objeto exclusivo preso não abre sem
// OBJ_EXCLUSIVE; KernelOnlyAccess recusa UserMode (ou OBJ_FORCE_ACCESS_CHECK);
// com MaintainHandleCount a entrada do processo é travada. HandleCount
// sobe; o primeiro handle de criação liga o CreatorInfo na lista do tipo; o
// TotalNumberOfHandles do tipo é contado.
pub fn increment_handle_count(body: u64, open: &mut HandleOpen, descriptor_charge: u32) -> Result<(), u32> {
    let header = body - BODY_OFFSET;
    let object = header_at(header);
    let object_type = type_of_header(header);
    let type_flags = type_flags(object_type);
    let access_mode = if open.attributes & OBJ_FORCE_ACCESS_CHECK != 0 { 1 } else { open.access_mode };
    let (new_object, handle_entry) = {
        let _guard = HANDLE_COUNTS.lock();
        let flags = object.flags.get();
        let new_object = flags & FLAG_NEW_OBJECT != 0;
        let exclusive_object = flags & FLAG_EXCLUSIVE_OBJECT != 0;
        let process_info = info(header, INFO_PROCESS);
        // SAFETY: ProcessInfo do cabeçalho (presente nos objetos exclusivos).
        let exclusive = (process_info != 0).then(|| unsafe { ObjectHeaderProcessInfo::at(process_info) });
        if open.attributes & OBJ_EXCLUSIVE != 0 {
            if !exclusive_object || open.attributes & OBJ_INHERIT != 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let holder = exclusive.map_or(0, |info| info.exclusive_process.get());
            if (holder == 0 && object.handle_count.get() != 0) || (holder != 0 && holder != open.process) {
                return Err(STATUS_ACCESS_DENIED);
            }
            if let Some(info) = exclusive {
                info.exclusive_process.set(open.process);
            }
        } else if exclusive_object && exclusive.is_some_and(|info| info.exclusive_process.get() != 0) {
            return Err(STATUS_ACCESS_DENIED);
        }
        if access_mode != 0 && flags & FLAG_KERNEL_ONLY_ACCESS != 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        let handle_entry = if type_flags & TYPE_MAINTAIN_HANDLE_COUNT != 0 {
            let handle_info = info(header, INFO_HANDLE);
            match lock_handle_entry(object, handle_info, open.process) {
                Some(found) => Some(found),
                None => return Err(STATUS_INSUFFICIENT_RESOURCES),
            }
        } else {
            None
        };
        if new_object {
            object.flags.set(object.flags.get() & !FLAG_NEW_OBJECT);
        }
        object.handle_count.atomic().fetch_add(1, Ordering::SeqCst);
        (new_object, handle_entry)
    };
    if new_object {
        if let Err(status) = charge_quota(header, open.process, descriptor_charge) {
            undo_increment(header, handle_entry.map(|(entry, _)| entry));
            return Err(status);
        }
    }
    // A OpenProcedure com o HandleCount já contado e a entrada do processo
    // travada (HandleCount + LockCount); uma falha desfaz a abertura sem
    // CloseProcedure e passa pelo ObpDeleteNameCheck.
    if let Err(status) = type_procedures::open(object_type, body, open, handle_entry.map_or(0, |(_, count)| count)) {
        undo_increment(header, handle_entry.map(|(entry, _)| entry));
        delete_name_check(body);
        return Err(status);
    }
    if let Some((entry, _)) = handle_entry {
        let _guard = HANDLE_COUNTS.lock();
        unlock_handle_entry(entry, true);
    }
    if open.reason == OpenReason::Create {
        let creator = info(header, INFO_CREATOR);
        if creator != 0 {
            link_creator(object_type, creator);
        }
    }
    if let Some(info) = object_types::find(object_type) {
        let _ = object_types::account(&info.name, 0, 1);
    }
    Ok(())
}

fn undo_increment(header: u64, entry: Option<u64>) {
    let _guard = HANDLE_COUNTS.lock();
    if let Some(entry) = entry {
        unlock_handle_entry(entry, false);
    }
    header_at(header).handle_count.atomic().fetch_sub(1, Ordering::SeqCst);
}

// --- ObpDecrementHandleCount ------------------------------------------------------
// Como no ntoskrnl 19041 (rva 0x6f6c04): HandleCount desce (o último solta o
// ExclusiveProcess), a entrada do processo perde um handle; o último handle
// de um objeto temporário tira o nome do namespace (ObpDeleteNameCheck); o
// TotalNumberOfHandles do tipo desce. Devolve (contagem do processo,
// contagem do sistema), as anteriores ao fechamento.
pub fn decrement_handle_count(body: u64, owner: u64) -> (u32, u64) {
    let header = body - BODY_OFFSET;
    let object = header_at(header);
    let object_type = type_of_header(header);
    let (process_count, system_count) = {
        let _guard = HANDLE_COUNTS.lock();
        let system_count = object.handle_count.atomic().fetch_sub(1, Ordering::SeqCst) as u64;
        if system_count == 1 && object.flags.get() & FLAG_EXCLUSIVE_OBJECT != 0 {
            let process_info = info(header, INFO_PROCESS);
            if process_info != 0 {
                // SAFETY: ProcessInfo do cabeçalho.
                unsafe { ObjectHeaderProcessInfo::at(process_info) }.exclusive_process.set(0);
            }
        }
        let mut process_count = 0;
        if type_flags(object_type) & TYPE_MAINTAIN_HANDLE_COUNT != 0 {
            let handle_info = info(header, INFO_HANDLE);
            if let Some(entry) = find_handle_entry(object, handle_info, owner) {
                let entry = handle_entry(entry);
                process_count = entry.handle_count();
                entry.set_handle_count(process_count.saturating_sub(1));
                if entry.bitfield_8.get() == 0 {
                    entry.process.set(0);
                }
            }
        }
        (process_count, system_count)
    };
    type_procedures::close(object_type, owner, body, process_count, system_count);
    if system_count == 1 {
        delete_name_check(body);
    }
    if let Some(info) = object_types::find(object_type) {
        let _ = object_types::account(&info.name, 0, -1);
    }
    (process_count, system_count)
}

/// Contagem de handles de `owner` no objeto (0 sem MaintainHandleCount).
pub fn process_handle_count(body: u64, owner: u64) -> u32 {
    let header = body - BODY_OFFSET;
    let object = header_at(header);
    if type_flags(type_of_header(header)) & TYPE_MAINTAIN_HANDLE_COUNT == 0 {
        return 0;
    }
    let _guard = HANDLE_COUNTS.lock();
    find_handle_entry(object, info(header, INFO_HANDLE), owner).map_or(0, |entry| handle_entry(entry).handle_count())
}

// --- Nome no namespace ------------------------------------------------------------

/// O nome inserido pelo ObInsertObject: o nó do namespace, que retém uma
/// referência do objeto (a entrada de diretório do NT), e o NameInfo com o
/// diretório e só o componente final — como o ObpLookupObjectName, num
/// buffer novo do pool paginável ('ObNm', Length = MaximumLength), liberando
/// o nome capturado.
pub fn attach_name(body: u64, node: NodeId, directory: u64, component: &str) {
    let header = body - BODY_OFFSET;
    reference(body, 1);
    let name = info(header, INFO_NAME);
    if name != 0 {
        // SAFETY: NameInfo do cabeçalho.
        let name_info = unsafe { ObjectHeaderNameInfo::at(name) };
        let text: Vec<u8> = component.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
        let buffer = pool_allocation::allocate_tagged(PAGED_POOL, text.len().max(1) as u64, NAME_BUFFER_TAG).unwrap_or(0);
        if buffer != 0 {
            guest::write_bytes(buffer, &text);
            let old = name_info.name.buffer.get();
            if old != 0 {
                let _ = pool_allocation::free(old, NAME_BUFFER_TAG as u64);
            }
            name_info.name.length.set(text.len() as u16);
            name_info.name.maximum_length.set(text.len() as u16);
            name_info.name.buffer.set(buffer);
        }
        name_info.directory.set(directory);
    }
    if let Some(record) = LIVE.lock().get_mut(&header) {
        record.node = Some(node);
    }
}

/// O nó do namespace do nome inserido, se houver.
pub fn name_node(body: u64) -> Option<NodeId> {
    let header = header_of(body)?;
    LIVE.lock().get(&header).and_then(|record| record.node)
}

/// ObpDeleteNameCheck: um objeto não permanente sem handles sai do
/// namespace; o NameInfo perde o diretório e a entrada solta a referência
/// que tinha do objeto (ObpDeleteDirectoryEntry).
pub fn delete_name_check(body: u64) {
    let header = body - BODY_OFFSET;
    let object = header_at(header);
    if object.flags.get() & FLAG_PERMANENT_OBJECT != 0 || object.handle_count.get() != 0 {
        return;
    }
    let Some(node) = LIVE.lock().get_mut(&header).and_then(|record| record.node.take()) else { return };
    object_manager::remove_named(node);
    let name = info(header, INFO_NAME);
    if name != 0 {
        // SAFETY: NameInfo do cabeçalho.
        unsafe { ObjectHeaderNameInfo::at(name) }.directory.set(0);
    }
    dereference(body, false);
}

/// Tira o nome do namespace sem olhar permanência nem handles (o
/// ObpDeleteDirectoryEntry da falha de uma inserção com nome).
pub fn detach_name(body: u64) {
    let header = body - BODY_OFFSET;
    let Some(node) = LIVE.lock().get_mut(&header).and_then(|record| record.node.take()) else { return };
    object_manager::remove_named(node);
    let name = info(header, INFO_NAME);
    if name != 0 {
        // SAFETY: NameInfo do cabeçalho.
        unsafe { ObjectHeaderNameInfo::at(name) }.directory.set(0);
    }
    dereference(body, false);
}

/// ObMakeTemporaryObject de um objeto com cabeçalho: tira PermanentObject e
/// passa pelo ObpDeleteNameCheck.
pub fn make_temporary(body: u64) {
    let object = header_at(body - BODY_OFFSET);
    object.flags.set(object.flags.get() & !FLAG_PERMANENT_OBJECT);
    delete_name_check(body);
}

/// Contagens do cabeçalho: (PointerCount, HandleCount).
pub fn counts(body: u64) -> (i64, i64) {
    let object = header_at(body - BODY_OFFSET);
    (object.pointer_count.get(), object.handle_count.get())
}

/// O nome do NameInfo (só o componente final).
pub fn name(body: u64) -> Option<alloc::string::String> {
    let name = name_info(body);
    (name != 0).then(|| crate::ntos::rtl::guest_strings::read_unicode_string(name + core::mem::offset_of!(ObjectHeaderNameInfo, name) as u64))
}
