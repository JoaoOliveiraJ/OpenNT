//! Contextos de filtro do FsRtl — por stream (cabeçalho avançado do FCB),
//! por arquivo (FileContextSupportPointer) e por FILE_OBJECT (extensão), com
//! os mesmos locks e a mesma regra de correspondência do ntoskrnl 10.0.19045.
//!
//! * Por stream (InsertPerStreamContext 0x2ffc10, LookupPerStreamContextInternal
//!   0x2ca690, RemovePerStreamContext 0x4f1180) sobre `FsrtlAdvancedFcbHeader`
//!   (`inc::types::extra_fsrtl`): Flags2 bit 2 = SUPPORTS_FILTER_CONTEXTS;
//!   Version >= 1 usa o push lock (em região crítica), Version 0 o FAST_MUTEX.
//! * Por arquivo (InsertPerFileContext 0x318d00, LookupPerFileContext
//!   0x31d9f0, RemovePerFileContext 0x4f1080): `*PerFileContextPointer` ganha
//!   sob demanda um [`PerFileBlock`] (NonPagedPoolNx, 'FSfc'), publicado com
//!   compare-exchange.
//! * Por FILE_OBJECT (InsertPerFileObjectContext 0x2fb1e0, Lookup 0x2eec90,
//!   Remove 0x2fb0f0): `FileObject.file_object_extension`
//!   (`IopFileObjectExtension`, NonPagedPoolNx 'Io  ',
//!   IopAllocateFileObjectExtension 0x22bb40); FoExtPerTypeExtension[3]
//!   guarda um [`PerFileObjectBlock`] (NonPagedPoolNx, 'FOCX').
//!
//! Registros: FSRTL_PER_STREAM_CONTEXT / PER_FILE_CONTEXT /
//! PER_FILEOBJECT_CONTEXT. Correspondência: InstanceId != NULL -> OwnerId E
//! InstanceId; senão OwnerId != NULL -> OwnerId; senão a primeira entrada.
//! Inserção = InsertHeadList. LIST_ENTRY corrompida é o fast-fail do NT
//! (`int 0x29`, FAST_FAIL_CORRUPT_LIST_ENTRY): bugcheck 0x139 código 3.
//! Limitação (sinalizada): a destruição de FILE_OBJECT do OpenNT não libera a
//! extensão nem o bloco 'FOCX' (o IopDeleteFile do NT libera).
//!
//! Motor estável: `insert_per_stream_context`, `lookup_per_stream_context`,
//! `remove_per_stream_context`, `insert_per_file_context`,
//! `lookup_per_file_context`, `remove_per_file_context`,
//! `insert_per_file_object_context`, `lookup_per_file_object_context`,
//! `remove_per_file_object_context`, `file_object_extension`. (Os anexos
//! `fsrtl-file-context-teardown` e `fsrtl-volume-support` acrescentam
//! `teardown_per_file_contexts` e `teardown_per_stream_contexts`.)

use core::sync::atomic::Ordering;

use crate::ntos::ex::{pool_allocation, push_lock};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::extra_fsrtl::{FsrtlAdvancedFcbHeader, FsrtlPerFileContext, FsrtlPerFileobjectContext, FsrtlPerStreamContext};
use crate::ntos::inc::types::{FileObject, IopFileObjectExtension, ListEntry};
use crate::ntos::ke::{bugcheck, critical_region, fast_mutex};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// Offsets do cabeçalho avançado, derivados do tipo, para o anexo
/// `fsrtl-volume-support` (ainda no modelo antigo) que os usa por nome.
pub const FCB_VERSION: u64 = core::mem::offset_of!(FsrtlAdvancedFcbHeader, bitfield_7) as u64;
pub const FCB_FAST_MUTEX: u64 = core::mem::offset_of!(FsrtlAdvancedFcbHeader, fast_mutex) as u64;
pub const FCB_FILTER_CONTEXTS: u64 = core::mem::offset_of!(FsrtlAdvancedFcbHeader, filter_contexts) as u64;
pub const FCB_PUSH_LOCK: u64 = core::mem::offset_of!(FsrtlAdvancedFcbHeader, push_lock) as u64;

const FSRTL_FLAG2_SUPPORTS_FILTER_CONTEXTS: u8 = 0x02;
const TAG_FSFC: u32 = 0x6366_5346; // 'FSfc'
const TAG_FOCX: u32 = 0x5843_4F46; // 'FOCX'
const TAG_IO: u32 = 0x2020_6F49; // 'Io  '
const NON_PAGED_POOL_NX: u32 = 0x200;
/// FoExtPerTypeExtension[3]: o contexto de filtro do FILE_OBJECT (+0x20).
const FILTER_CONTEXT_EXTENSION_SLOT: usize = 3;
/// KERNEL_SECURITY_CHECK_FAILURE / FAST_FAIL_CORRUPT_LIST_ENTRY.
const KERNEL_SECURITY_CHECK_FAILURE: u32 = 0x139;
const FAST_FAIL_CORRUPT_LIST_ENTRY: u64 = 3;

/// Bloco por arquivo do FsRtl ('FSfc', 0x20): EX_PUSH_LOCK + lista.
#[repr(C)]
struct PerFileBlock {
    push_lock: Field<u64>,
    list: ListEntry,
    reserved: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for PerFileBlock {}

/// Bloco por FILE_OBJECT do FsRtl ('FOCX', 0x18): EX_PUSH_LOCK + lista.
#[repr(C)]
struct PerFileObjectBlock {
    push_lock: Field<u64>,
    list: ListEntry,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for PerFileObjectBlock {}

const _: () = {
    assert!(core::mem::size_of::<PerFileBlock>() == 0x20);
    assert!(core::mem::offset_of!(PerFileBlock, list) == 0x8);
    assert!(core::mem::size_of::<PerFileObjectBlock>() == 0x18);
    assert!(core::mem::offset_of!(PerFileObjectBlock, list) == 0x8);
};

/// Registro de contexto: Links em +0, OwnerId e InstanceId.
trait ContextRecord: NtStruct + 'static {
    fn ids(&self) -> (u64, u64);
}

impl ContextRecord for FsrtlPerStreamContext {
    fn ids(&self) -> (u64, u64) {
        (self.owner_id.get(), self.instance_id.get())
    }
}

impl ContextRecord for FsrtlPerFileContext {
    fn ids(&self) -> (u64, u64) {
        (self.owner_id.get(), self.instance_id.get())
    }
}

impl ContextRecord for FsrtlPerFileobjectContext {
    fn ids(&self) -> (u64, u64) {
        (self.owner_id.get(), self.instance_id.get())
    }
}

fn entry_at(address: u64) -> &'static ListEntry {
    // SAFETY: elos de uma lista viva do FsRtl.
    unsafe { ListEntry::at(address) }
}

fn corrupt_list() -> ! {
    bugcheck::bug_check_ex(KERNEL_SECURITY_CHECK_FAILURE, FAST_FAIL_CORRUPT_LIST_ENTRY, 0, 0, 0)
}

/// InsertHeadList com a checagem de integridade do NT.
fn insert_head(head: &ListEntry, entry: &ListEntry) {
    let first = entry_at(head.flink.get());
    if first.blink.get() != head.address() {
        corrupt_list();
    }
    entry.flink.set(first.address());
    entry.blink.set(head.address());
    first.blink.set(entry.address());
    head.flink.set(entry.address());
}

/// RemoveEntryList com a checagem de integridade do NT.
fn unlink(entry: &ListEntry) {
    let (next, previous) = (entry_at(entry.flink.get()), entry_at(entry.blink.get()));
    if next.blink.get() != entry.address() || previous.flink.get() != entry.address() {
        corrupt_list();
    }
    previous.flink.set(next.address());
    next.blink.set(previous.address());
}

/// Regra de correspondência comum (0 = nenhum).
fn find<T: ContextRecord>(head: &ListEntry, owner: u64, instance: u64) -> u64 {
    let mut entry = head.flink.get();
    while entry != head.address() {
        // SAFETY: cada elo da lista é o Links (+0) de um registro do tipo.
        let (entry_owner, entry_instance) = unsafe { T::at(entry) }.ids();
        let hit = if instance != 0 {
            entry_owner == owner && entry_instance == instance
        } else {
            owner == 0 || entry_owner == owner
        };
        if hit {
            return entry;
        }
        entry = entry_at(entry).flink.get();
    }
    0
}

fn find_and_unlink<T: ContextRecord>(head: &ListEntry, owner: u64, instance: u64) -> u64 {
    let entry = find::<T>(head, owner, instance);
    if entry != 0 {
        unlink(entry_at(entry));
    }
    entry
}

/// Push lock em região crítica (KeEnterCriticalRegion + ExAcquirePushLock*Ex).
fn with_push_lock<T>(lock: &Field<u64>, shared: bool, body: impl FnOnce() -> T) -> Result<T, KernelError> {
    critical_region::enter_critical()?;
    if shared {
        push_lock::acquire_shared(lock.address(), 0)?;
    } else {
        push_lock::acquire_exclusive(lock.address(), 0)?;
    }
    let result = body();
    if shared {
        push_lock::release_shared(lock.address(), 0)?;
    } else {
        push_lock::release_exclusive(lock.address(), 0)?;
    }
    critical_region::leave_critical()?;
    Ok(result)
}

/// Lock do cabeçalho avançado: push lock (Version >= 1) ou o FAST_MUTEX
/// apontado (Version 0).
fn with_header_lock<T>(header: &FsrtlAdvancedFcbHeader, shared: bool, body: impl FnOnce() -> T) -> Result<T, KernelError> {
    if header.version() >= 1 {
        return with_push_lock(&header.push_lock.value, shared, body);
    }
    let mutex = header.fast_mutex.get();
    fast_mutex::acquire(mutex)?;
    let result = body();
    fast_mutex::release(mutex)?;
    Ok(result)
}

fn supports_filter_contexts(header: Option<&FsrtlAdvancedFcbHeader>) -> Option<&FsrtlAdvancedFcbHeader> {
    header.filter(|header| header.flags2.get() & FSRTL_FLAG2_SUPPORTS_FILTER_CONTEXTS != 0)
}

/// Bloco zerado de `size` bytes do pool, ou 0.
fn allocate_zeroed(size: u64, tag: u32) -> Result<u64, KernelError> {
    let block = pool_allocation::allocate_tagged(NON_PAGED_POOL_NX, size, tag)?;
    if block != 0 {
        guest::write_bytes(block, &alloc::vec![0u8; size as usize]);
    }
    Ok(block)
}

fn initialize_list_head(head: &ListEntry) {
    head.flink.set(head.address());
    head.blink.set(head.address());
}

/// Publica `fresh` em `cell` se ela estiver vazia; senão libera `fresh` e
/// devolve o bloco que venceu a corrida.
fn publish(cell: &Field<u64>, fresh: u64) -> Result<u64, KernelError> {
    match cell.atomic().compare_exchange(0, fresh, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(_) => Ok(fresh),
        Err(winner) => {
            pool_allocation::free(fresh, 0)?;
            Ok(winner)
        }
    }
}

fn is_empty(head: &ListEntry) -> bool {
    head.flink.get() == head.address()
}

// ---- por stream ----------------------------------------------------------------

/// FsRtlInsertPerStreamContext(AdvancedHeader, Ptr) -> NTSTATUS.
pub fn insert_per_stream_context(header: Option<&FsrtlAdvancedFcbHeader>, context: &FsrtlPerStreamContext) -> Result<u32, KernelError> {
    let Some(header) = supports_filter_contexts(header) else { return Ok(STATUS_INVALID_DEVICE_REQUEST) };
    with_header_lock(header, false, || insert_head(&header.filter_contexts, &context.links))?;
    Ok(STATUS_SUCCESS)
}

/// FsRtlLookupPerStreamContextInternal(AdvancedHeader, OwnerId, InstanceId).
pub fn lookup_per_stream_context(header: &FsrtlAdvancedFcbHeader, owner: u64, instance: u64) -> Result<u64, KernelError> {
    with_header_lock(header, true, || find::<FsrtlPerStreamContext>(&header.filter_contexts, owner, instance))
}

/// FsRtlRemovePerStreamContext(AdvancedHeader, OwnerId, InstanceId).
pub fn remove_per_stream_context(header: Option<&FsrtlAdvancedFcbHeader>, owner: u64, instance: u64) -> Result<u64, KernelError> {
    let Some(header) = supports_filter_contexts(header) else { return Ok(0) };
    with_header_lock(header, false, || find_and_unlink::<FsrtlPerStreamContext>(&header.filter_contexts, owner, instance))
}

// ---- por arquivo ------------------------------------------------------------------

fn per_file_block(pointer: &Field<u64>) -> Option<&'static PerFileBlock> {
    let block = pointer.get();
    // SAFETY: o PerFileContextPointer só recebe blocos criados aqui.
    let block = (block != 0).then(|| unsafe { PerFileBlock::at(block) })?;
    (!is_empty(&block.list)).then_some(block)
}

/// FsRtlInsertPerFileContext(PerFileContextPointer, Ptr) -> NTSTATUS.
pub fn insert_per_file_context(pointer: Option<&Field<u64>>, context: &FsrtlPerFileContext) -> Result<u32, KernelError> {
    let Some(pointer) = pointer else { return Ok(STATUS_INVALID_DEVICE_REQUEST) };
    let mut block = pointer.get();
    if block == 0 {
        let fresh = allocate_zeroed(PerFileBlock::SIZE, TAG_FSFC)?;
        if fresh == 0 {
            return Ok(STATUS_INSUFFICIENT_RESOURCES);
        }
        // SAFETY: bloco recém-alocado do tamanho certo.
        initialize_list_head(&unsafe { PerFileBlock::at(fresh) }.list);
        block = publish(pointer, fresh)?;
    }
    // SAFETY: bloco publicado em PerFileContextPointer.
    let block = unsafe { PerFileBlock::at(block) };
    with_push_lock(&block.push_lock, false, || insert_head(&block.list, &context.links))?;
    Ok(STATUS_SUCCESS)
}

/// FsRtlLookupPerFileContext(PerFileContextPointer, OwnerId, InstanceId).
pub fn lookup_per_file_context(pointer: &Field<u64>, owner: u64, instance: u64) -> Result<u64, KernelError> {
    let Some(block) = per_file_block(pointer) else { return Ok(0) };
    with_push_lock(&block.push_lock, true, || find::<FsrtlPerFileContext>(&block.list, owner, instance))
}

/// FsRtlRemovePerFileContext(PerFileContextPointer, OwnerId, InstanceId).
pub fn remove_per_file_context(pointer: &Field<u64>, owner: u64, instance: u64) -> Result<u64, KernelError> {
    let Some(block) = per_file_block(pointer) else { return Ok(0) };
    with_push_lock(&block.push_lock, false, || find_and_unlink::<FsrtlPerFileContext>(&block.list, owner, instance))
}

// ---- por FILE_OBJECT ------------------------------------------------------------

/// IopAllocateFileObjectExtension / IoGetFileObjectFilterContext: a extensão
/// do FILE_OBJECT, criada sob demanda quando `allocate` (None se ausente ou
/// sem memória).
pub fn file_object_extension(file_object: &FileObject, allocate: bool) -> Result<Option<&'static IopFileObjectExtension>, KernelError> {
    let mut extension = file_object.file_object_extension.get();
    if extension == 0 {
        if !allocate {
            return Ok(None);
        }
        let fresh = allocate_zeroed(IopFileObjectExtension::SIZE, TAG_IO)?;
        if fresh == 0 {
            return Ok(None);
        }
        extension = publish(&file_object.file_object_extension, fresh)?;
    }
    // SAFETY: a extensão de um FILE_OBJECT vivo.
    Ok(Some(unsafe { IopFileObjectExtension::at(extension) }))
}

fn per_file_object_block(file_object: &FileObject) -> Result<Option<&'static PerFileObjectBlock>, KernelError> {
    let Some(extension) = file_object_extension(file_object, false)? else { return Ok(None) };
    let block = extension.fo_ext_per_type_extension[FILTER_CONTEXT_EXTENSION_SLOT].get();
    // SAFETY: o slot só recebe blocos criados aqui.
    Ok((block != 0).then(|| unsafe { PerFileObjectBlock::at(block) }))
}

/// FsRtlInsertPerFileObjectContext(FileObject, Ptr) -> NTSTATUS.
pub fn insert_per_file_object_context(file_object: Option<&FileObject>, context: &FsrtlPerFileobjectContext) -> Result<u32, KernelError> {
    let Some(file_object) = file_object else { return Ok(STATUS_INVALID_PARAMETER) };
    let Some(extension) = file_object_extension(file_object, true)? else { return Ok(STATUS_INSUFFICIENT_RESOURCES) };
    let slot = &extension.fo_ext_per_type_extension[FILTER_CONTEXT_EXTENSION_SLOT];
    let mut block = slot.get();
    if block == 0 {
        let fresh = allocate_zeroed(PerFileObjectBlock::SIZE, TAG_FOCX)?;
        if fresh == 0 {
            return Ok(STATUS_INSUFFICIENT_RESOURCES);
        }
        // SAFETY: bloco recém-alocado do tamanho certo.
        initialize_list_head(&unsafe { PerFileObjectBlock::at(fresh) }.list);
        // IoChangeFileObjectFilterContext(.., TRUE): publica só se vazio.
        block = publish(slot, fresh)?;
    }
    // SAFETY: bloco publicado no slot da extensão.
    let block = unsafe { PerFileObjectBlock::at(block) };
    with_push_lock(&block.push_lock, false, || insert_head(&block.list, &context.links))?;
    Ok(STATUS_SUCCESS)
}

/// FsRtlLookupPerFileObjectContext(FileObject, OwnerId, InstanceId).
pub fn lookup_per_file_object_context(file_object: Option<&FileObject>, owner: u64, instance: u64) -> Result<u64, KernelError> {
    let Some(file_object) = file_object else { return Ok(0) };
    let Some(block) = per_file_object_block(file_object)? else { return Ok(0) };
    with_push_lock(&block.push_lock, true, || find::<FsrtlPerFileobjectContext>(&block.list, owner, instance))
}

/// FsRtlRemovePerFileObjectContext(FileObject, OwnerId, InstanceId).
pub fn remove_per_file_object_context(file_object: Option<&FileObject>, owner: u64, instance: u64) -> Result<u64, KernelError> {
    let Some(file_object) = file_object else { return Ok(0) };
    let Some(block) = per_file_object_block(file_object)? else { return Ok(0) };
    with_push_lock(&block.push_lock, false, || find_and_unlink::<FsrtlPerFileobjectContext>(&block.list, owner, instance))
}

// ---- FsRtlTeardownPerFileContexts (anexo do grupo fsrtl-file-context-teardown) ----
//
// Anexado a `fsrtl/filter_context.rs` (grupo irmão fsrtl-filter-contexts) e
// escrito sobre os itens privados dele: `PerFileBlock` (o bloco 'FSfc' de
// 0x20: EX_PUSH_LOCK + LIST_ENTRY de FSRTL_PER_FILE_CONTEXT), `entry_at`,
// `unlink` (RemoveEntryList com a checagem de integridade, que faz o
// bugcheck KERNEL_SECURITY_CHECK_FAILURE/FAST_FAIL_CORRUPT_LIST_ENTRY como o
// `int 0x29` do NT), `is_empty`, `TAG_FSFC` e os `use` do arquivo
// (Ordering, Field, NtStruct, FsrtlPerFileContext, critical_region,
// push_lock, pool_allocation, KernelError). Sem `use` novo.
//
// FsRtlTeardownPerFileContexts (RVA 0x67b590, ntoskrnl 19045): toma o bloco
// por arquivo com `xchg [PerFileContextPointer], 0`; com a lista não vazia,
// em região crítica e push lock exclusivo, retira um contexto por vez, solta
// o lock e a região, chama FreeCallback(Context) e readquire; no fim libera
// o bloco (ExFreePoolWithTag 'FSfc').

/// FsRtlTeardownPerFileContexts(PerFileContextPointer) -> VOID.
pub fn teardown_per_file_contexts(per_file_context_pointer: &Field<u64>) -> Result<(), KernelError> {
    let address = per_file_context_pointer.atomic().swap(0, Ordering::SeqCst);
    if address == 0 {
        return Ok(());
    }
    // SAFETY: bloco publicado por FsRtlInsertPerFileContext.
    let block = unsafe { PerFileBlock::at(address) };
    let lock = block.push_lock.address();
    if !is_empty(&block.list) {
        critical_region::enter_critical()?;
        push_lock::acquire_exclusive(lock, 0)?;
        while !is_empty(&block.list) {
            let entry = entry_at(block.list.flink.get());
            unlink(entry);
            push_lock::release_exclusive(lock, 0)?;
            critical_region::leave_critical()?;
            // SAFETY: cada elo da lista é o Links (+0) de um FSRTL_PER_FILE_CONTEXT.
            let context = unsafe { FsrtlPerFileContext::at(entry.address()) };
            crate::hal::amd64::native_call::call(context.free_callback.get(), &[context.address()]);
            critical_region::enter_critical()?;
            push_lock::acquire_exclusive(lock, 0)?;
        }
        push_lock::release_exclusive(lock, 0)?;
        critical_region::leave_critical()?;
    }
    pool_allocation::free(address, TAG_FSFC as u64)
}

// ---- FsRtlTeardownPerStreamContexts (fsrtl-volume-support) --------------------------
//
// ntoskrnl 10.0.19045, RVA 0x668240: lista FilterContexts vazia -> nada. Senão,
// sob a trava do cabeçalho (Version >= 1: push lock numa região crítica; senão
// a FAST_MUTEX apontada), retira a primeira entrada (RemoveEntryList com a
// checagem de integridade), solta a trava, chama
// FSRTL_PER_STREAM_CONTEXT.FreeCallback com a própria entrada e retoma, até
// esvaziar. Usa os itens privados deste módulo: `with_header_lock`,
// `is_empty`, `entry_at`, `unlink` e os `use` do arquivo.

/// FsRtlTeardownPerStreamContexts(AdvancedHeader).
pub fn teardown_per_stream_contexts(header: &FsrtlAdvancedFcbHeader) -> Result<(), KernelError> {
    let head = &header.filter_contexts;
    if is_empty(head) {
        return Ok(());
    }
    loop {
        let entry = with_header_lock(header, false, || {
            if is_empty(head) {
                return 0;
            }
            let entry = entry_at(head.flink.get());
            unlink(entry);
            entry.address()
        })?;
        if entry == 0 {
            return Ok(());
        }
        // SAFETY: cada elo de FilterContexts é o Links (+0) de um FSRTL_PER_STREAM_CONTEXT.
        let context = unsafe { FsrtlPerStreamContext::at(entry) };
        crate::hal::amd64::native_call::call(context.free_callback.get(), &[entry]);
    }
}
