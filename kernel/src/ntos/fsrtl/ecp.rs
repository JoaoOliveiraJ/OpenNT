//! Extra Create Parameters (ECP) do FsRtl — listas e entradas no pool com o
//! layout exato do ntoskrnl 10.0.19045, procura por GUID, flags de
//! reconhecimento e acoplamento ao IRP de create.
//!
//! * `EcpList` (`inc::types::extra_fsrtl`, PDB `_ECP_LIST`): Signature
//!   'EcpL', Flags (2 = bloco de pool/quota, 4 = bloco de lookaside, 8 =
//!   dentro de um IRP), EcpList.
//! * [`EcpHeader`] (privado do FsRtl, 0x48) precede o contexto P devolvido
//!   ao chamador: 'EcpH', ListEntry, EcpType, CleanupCallback, Flags (2
//!   alocada, 4 consultada/colidida, 8 reconhecida, 0x10 do modo usuário,
//!   0x20 do FltMgr, 0x40 não paginada), TotalSize = contexto + 0x48,
//!   lookaside dona, contexto do FltMgr.
//!
//! RVAs: AllocateExtraCreateParameterList 0x60d350, FreeExtraCreateParameterList
//! 0x60cd80, AllocateExtraCreateParameter 0x6bd480, FreeExtraCreateParameter
//! 0x60ce40, Insert 0x60d2e0, Find 0x651070, Remove 0x651100, GetNext
//! 0x69fae0, AcknowledgeEcp 0x67db70, IsEcpAcknowledged 0x679570,
//! IsEcpFromUserMode 0x680890, PrepareToReuseEcp 0x77d0c0, GetEcpListFromIrp
//! 0x650610, SetEcpListIntoIrp 0x66f890, Init/DeleteExtraCreateParameter
//! LookasideList 0x7cb6d0 / 0x88a550, AllocateExtraCreateParameterFrom
//! LookasideList 0x662410.
//!
//! Divergências (sinalizadas): a lista sem quota do NT sai de uma lookaside
//! paginada privada (Flags = 6); aqui é um bloco de PagedPool com Flags = 2
//! (o valor do caminho com quota do NT), liberado com ExFreePool como aquele
//! caminho. O ramo de liberação do FltMgr (flag 0x20) não é alcançável:
//! nenhum alocador do OpenNT liga essa flag. LIST_ENTRY corrompida é o
//! fast-fail do NT: bugcheck 0x139 código 3.
//!
//! Motor estável: `allocate_list`, `free_list`, `allocate`, `free`, `insert`,
//! `find`, `remove`, `get_next`, `acknowledge`, `is_acknowledged`,
//! `is_from_user_mode`, `prepare_to_reuse`, `get_list_from_irp`,
//! `set_list_into_irp`, `init_lookaside`, `delete_lookaside`,
//! `allocate_from_lookaside`, `header_of`.

use core::sync::atomic::Ordering;

use crate::hal::amd64::native_call;
use crate::ntos::ex::{lookaside, pool_allocation, pool_quota};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::extra_fsrtl::EcpList;
use crate::ntos::inc::types::{GeneralLookaside, Guid, Irp, ListEntry};
use crate::ntos::ke::bugcheck;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_INTEGER_OVERFLOW: u32 = 0xC000_0095;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
pub const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
pub const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
pub const STATUS_NOT_FOUND: u32 = 0xC000_0225;

const ECP_LIST_SIGNATURE: u32 = 0x4C70_6345; // 'EcpL'
const ECP_HEADER_SIGNATURE: u32 = 0x4870_6345; // 'EcpH'
const TAG_FSEL: u32 = 0x6C65_5346; // 'FSel'
const LIST_FLAG_POOL: u32 = 0x02;
const LIST_FLAG_IN_IRP: u32 = 0x08;
// Flags da entrada.
const ECP_ALLOCATED: u32 = 0x02;
const ECP_LOOKED_UP: u32 = 0x04;
const ECP_ACKNOWLEDGED: u32 = 0x08;
const ECP_FROM_USER_MODE: u32 = 0x10;
const ECP_NONPAGED: u32 = 0x40;
// Flags públicos de alocação.
const ALLOCATE_FLAG_CHARGE_QUOTA: u32 = 0x01;
const ALLOCATE_FLAG_NONPAGED_POOL: u32 = 0x02;
/// IRP.Flags: IRP_CREATE_OPERATION (o NT testa o bit de sinal do byte baixo).
const IRP_CREATE_OPERATION: u32 = 0x80;
// POOL_TYPE.
const PAGED_POOL: u32 = 1;
const NON_PAGED_POOL_NX: u32 = 0x200;
const POOL_QUOTA_FAIL_INSTEAD_OF_RAISE: u32 = 8;
/// KERNEL_SECURITY_CHECK_FAILURE / FAST_FAIL_CORRUPT_LIST_ENTRY.
const KERNEL_SECURITY_CHECK_FAILURE: u32 = 0x139;
const FAST_FAIL_CORRUPT_LIST_ENTRY: u64 = 3;

/// Cabeçalho de uma entrada ECP (privado do FsRtl, derivado da desmontagem
/// de FsRtlAllocateExtraCreateParameter 0x6bd480).
#[repr(C)]
pub struct EcpHeader {
    pub signature: Field<u32>,
    _reserved_4: Field<u32>,
    pub list_entry: ListEntry,
    pub ecp_type: Guid,
    /// -> `fn` (PFSRTL_EXTRA_CREATE_PARAMETER_CLEANUP_CALLBACK)
    pub cleanup_callback: Field<u64>,
    pub flags: Field<u32>,
    pub total_size: Field<u32>,
    /// -> lookaside dona (NULL = pool)
    pub lookaside: Field<u64>,
    /// -> contexto do FltMgr (ECPs com a flag 0x20)
    pub flt_context: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for EcpHeader {}

const _: () = {
    assert!(core::mem::size_of::<EcpHeader>() == 0x48);
    assert!(core::mem::offset_of!(EcpHeader, list_entry) == 0x08);
    assert!(core::mem::offset_of!(EcpHeader, ecp_type) == 0x18);
    assert!(core::mem::offset_of!(EcpHeader, cleanup_callback) == 0x28);
    assert!(core::mem::offset_of!(EcpHeader, flags) == 0x30);
    assert!(core::mem::offset_of!(EcpHeader, total_size) == 0x34);
    assert!(core::mem::offset_of!(EcpHeader, lookaside) == 0x38);
    assert!(core::mem::offset_of!(EcpHeader, flt_context) == 0x40);
};

/// O cabeçalho de um contexto ECP (P - 0x48).
pub fn header_of(context: u64) -> &'static EcpHeader {
    // SAFETY: todo contexto ECP é precedido pelo seu cabeçalho.
    unsafe { EcpHeader::at(context - EcpHeader::SIZE) }
}

fn header_of_link(link: u64) -> &'static EcpHeader {
    // SAFETY: os elos da lista são o ListEntry (+8) de um cabeçalho ECP.
    unsafe { EcpHeader::at(link - core::mem::offset_of!(EcpHeader, list_entry) as u64) }
}

fn context_of(header: &EcpHeader) -> u64 {
    header.address() + EcpHeader::SIZE
}

fn context_size(header: &EcpHeader) -> u32 {
    header.total_size.get().wrapping_sub(EcpHeader::SIZE as u32)
}

fn entry_at(address: u64) -> &'static ListEntry {
    // SAFETY: elos de uma lista ECP viva.
    unsafe { ListEntry::at(address) }
}

fn corrupt_list() -> ! {
    bugcheck::bug_check_ex(KERNEL_SECURITY_CHECK_FAILURE, FAST_FAIL_CORRUPT_LIST_ENTRY, 0, 0, 0)
}

fn guid_bytes(guid: &Guid) -> alloc::vec::Vec<u8> {
    guest::read_bytes(guid.address(), Guid::SIZE as usize)
}

/// Primeira entrada da lista com o GUID pedido.
fn find_header(list: &EcpList, ecp_type: &Guid) -> Option<&'static EcpHeader> {
    let wanted = guid_bytes(ecp_type);
    let head = &list.ecp_list;
    let mut link = head.flink.get();
    while link != head.address() {
        let header = header_of_link(link);
        if guid_bytes(&header.ecp_type) == wanted {
            return Some(header);
        }
        link = entry_at(link).flink.get();
    }
    None
}

/// RemoveEntryList com a checagem do NT; zera os elos da entrada.
fn unlink(entry: &ListEntry) {
    let (next, previous) = (entry_at(entry.flink.get()), entry_at(entry.blink.get()));
    if next.blink.get() != entry.address() || previous.flink.get() != entry.address() {
        corrupt_list();
    }
    previous.flink.set(next.address());
    next.blink.set(previous.address());
    entry.flink.set(0);
    entry.blink.set(0);
}

fn write_header(header: &EcpHeader, ecp_type: &Guid, cleanup: u64, flags: u32, total: u32, owner: u64) {
    header.signature.set(ECP_HEADER_SIGNATURE);
    header._reserved_4.set(0);
    header.list_entry.flink.set(0);
    header.list_entry.blink.set(0);
    guest::write_bytes(header.ecp_type.address(), &guid_bytes(ecp_type));
    header.cleanup_callback.set(cleanup);
    header.flags.set(flags);
    header.total_size.set(total);
    header.lookaside.set(owner);
    header.flt_context.set(0);
}

/// FsRtlAllocateExtraCreateParameterList(Flags, EcpList*).
pub fn allocate_list(flags: u32, list_out: &Field<u64>) -> Result<u32, KernelError> {
    list_out.set(0);
    let address = if flags & ALLOCATE_FLAG_CHARGE_QUOTA != 0 {
        pool_quota::allocate(PAGED_POOL | POOL_QUOTA_FAIL_INSTEAD_OF_RAISE, EcpList::SIZE, TAG_FSEL)?
    } else {
        pool_allocation::allocate_tagged(PAGED_POOL, EcpList::SIZE, TAG_FSEL)?
    };
    if address == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    // SAFETY: bloco recém-alocado do tamanho de _ECP_LIST.
    let list = unsafe { EcpList::at(address) };
    list.signature.set(ECP_LIST_SIGNATURE);
    list.flags.set(LIST_FLAG_POOL);
    list.ecp_list.flink.set(list.ecp_list.address());
    list.ecp_list.blink.set(list.ecp_list.address());
    list_out.set(address);
    Ok(STATUS_SUCCESS)
}

/// FsRtlInitializeExtraCreateParameterList(EcpList): uma _ECP_LIST que o
/// chamador alocou ('EcpL', Flags 0, lista vazia); NULL é
/// STATUS_INVALID_PARAMETER.
pub fn initialize_list(list: u64) -> u32 {
    if list == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: a _ECP_LIST do chamador de kernel.
    let list = unsafe { EcpList::at(list) };
    list.flags.set(0);
    list.ecp_list.blink.set(list.ecp_list.address());
    list.ecp_list.flink.set(list.ecp_list.address());
    list.signature.set(ECP_LIST_SIGNATURE);
    STATUS_SUCCESS
}

/// FsRtlInitializeExtraCreateParameter(Ecp, EcpFlags, CleanupCallback,
/// TotalSize, EcpType, ListAllocatedFrom): o cabeçalho de uma ECP que o
/// chamador alocou — 'EcpH' com o dword seguinte zerado, fora de lista, o
/// GUID, a rotina de limpeza, as flags e o tamanho dados, a lookaside de
/// origem e sem contexto do FltMgr.
pub fn initialize(header: &EcpHeader, flags: u32, cleanup_callback: u64, total_size: u32, ecp_type: &Guid, list_allocated_from: u64) {
    header.signature.set(ECP_HEADER_SIGNATURE);
    header._reserved_4.set(0);
    header.list_entry.blink.set(0);
    header.list_entry.flink.set(0);
    guest::write_bytes(header.ecp_type.address(), &guest::read_bytes(ecp_type.address(), Guid::SIZE as usize));
    header.cleanup_callback.set(cleanup_callback);
    header.flags.set(flags);
    header.total_size.set(total_size);
    header.lookaside.set(list_allocated_from);
    header.flt_context.set(0);
}

/// FsRtlFreeExtraCreateParameter(EcpContext): CleanupCallback(P, &EcpType)
/// e devolve o bloco à lookaside dona ou ao pool.
pub fn free(context: u64) -> Result<(), KernelError> {
    let header = header_of(context);
    let cleanup = header.cleanup_callback.get();
    if cleanup != 0 {
        native_call::call(cleanup, &[context, header.ecp_type.address()]);
    }
    let owner = header.lookaside.get();
    if owner == 0 {
        pool_allocation::free(header.address(), 0)
    } else {
        lookaside::free(owner, header.address())
    }
}

/// FsRtlFreeExtraCreateParameterList(EcpList): cada entrada (com cleanup) e a lista.
pub fn free_list(list: &EcpList) -> Result<(), KernelError> {
    let head = &list.ecp_list;
    loop {
        let link = head.flink.get();
        if link == head.address() {
            break;
        }
        unlink(entry_at(link));
        free(context_of(header_of_link(link)))?;
    }
    pool_allocation::free(list.address(), 0)
}

/// FsRtlAllocateExtraCreateParameter(EcpType, SizeOfContext, Flags,
/// CleanupCallback, PoolTag, EcpContext*).
pub fn allocate(ecp_type: &Guid, size: u32, flags: u32, cleanup: u64, tag: u32, context_out: &Field<u64>) -> Result<u32, KernelError> {
    context_out.set(0);
    let total = size.wrapping_add(EcpHeader::SIZE as u32);
    if total < EcpHeader::SIZE as u32 {
        return Ok(STATUS_INTEGER_OVERFLOW);
    }
    let nonpaged = flags & ALLOCATE_FLAG_NONPAGED_POOL != 0;
    let entry_flags = ECP_ALLOCATED | if nonpaged { ECP_NONPAGED } else { 0 };
    let pool_type = if nonpaged { NON_PAGED_POOL_NX } else { PAGED_POOL };
    let address = if flags & ALLOCATE_FLAG_CHARGE_QUOTA != 0 {
        pool_quota::allocate(pool_type | POOL_QUOTA_FAIL_INSTEAD_OF_RAISE, total as u64, tag)?
    } else {
        pool_allocation::allocate_tagged(pool_type, total as u64, tag)?
    };
    if address == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    // SAFETY: bloco recém-alocado de cabeçalho + contexto.
    let header = unsafe { EcpHeader::at(address) };
    write_header(header, ecp_type, cleanup, entry_flags, total, 0);
    context_out.set(context_of(header));
    Ok(STATUS_SUCCESS)
}

/// FsRtlInsertExtraCreateParameter(EcpList, EcpContext): GUID repetido marca
/// a entrada existente (flag 4) e devolve STATUS_INVALID_PARAMETER; senão
/// insere no fim (InsertTailList com a checagem do NT).
pub fn insert(list: &EcpList, context: u64) -> u32 {
    let header = header_of(context);
    if let Some(existing) = find_header(list, &header.ecp_type) {
        existing.flags.atomic().fetch_or(ECP_LOOKED_UP, Ordering::SeqCst);
        return STATUS_INVALID_PARAMETER;
    }
    let head = &list.ecp_list;
    let tail = entry_at(head.blink.get());
    if tail.flink.get() != head.address() {
        corrupt_list();
    }
    let entry = &header.list_entry;
    entry.flink.set(head.address());
    entry.blink.set(tail.address());
    tail.flink.set(entry.address());
    head.blink.set(entry.address());
    STATUS_SUCCESS
}

/// FsRtlFindExtraCreateParameter(EcpList, EcpType, EcpContext*, EcpContextSize*).
pub fn find(list: &EcpList, ecp_type: &Guid, context_out: Option<&Field<u64>>, size_out: Option<&Field<u32>>) -> u32 {
    if let Some(out) = context_out {
        out.set(0);
    }
    if let Some(out) = size_out {
        out.set(0);
    }
    let Some(header) = find_header(list, ecp_type) else { return STATUS_NOT_FOUND };
    header.flags.atomic().fetch_or(ECP_LOOKED_UP, Ordering::SeqCst);
    if let Some(out) = context_out {
        out.set(context_of(header));
    }
    if let Some(out) = size_out {
        out.set(context_size(header));
    }
    STATUS_SUCCESS
}

/// FsRtlRemoveExtraCreateParameter(EcpList, EcpType, EcpContext*, EcpContextSize*).
pub fn remove(list: &EcpList, ecp_type: &Guid, context_out: &Field<u64>, size_out: Option<&Field<u32>>) -> u32 {
    context_out.set(0);
    let Some(header) = find_header(list, ecp_type) else { return STATUS_NOT_FOUND };
    header.flags.atomic().fetch_or(ECP_LOOKED_UP, Ordering::SeqCst);
    unlink(&header.list_entry);
    context_out.set(context_of(header));
    if let Some(out) = size_out {
        out.set(context_size(header));
    }
    STATUS_SUCCESS
}

/// FsRtlGetNextExtraCreateParameter(EcpList, CurrentEcpContext, NextEcpType*,
/// NextEcpContext*, NextEcpContextSize*): no fim zera as saídas e devolve
/// STATUS_NOT_FOUND.
pub fn get_next(list: &EcpList, current: u64, type_out: Option<&Guid>, context_out: Option<&Field<u64>>, size_out: Option<&Field<u32>>) -> u32 {
    let head = &list.ecp_list;
    let next = if current == 0 { head.flink.get() } else { header_of(current).list_entry.flink.get() };
    if next == head.address() || next == core::mem::offset_of!(EcpHeader, list_entry) as u64 {
        if let Some(out) = context_out {
            out.set(0);
        }
        if let Some(out) = size_out {
            out.set(0);
        }
        if let Some(out) = type_out {
            guest::write_bytes(out.address(), &[0u8; 16]);
        }
        return STATUS_NOT_FOUND;
    }
    let header = header_of_link(next);
    if let Some(out) = context_out {
        out.set(context_of(header));
    }
    if let Some(out) = size_out {
        out.set(context_size(header));
    }
    if let Some(out) = type_out {
        guest::write_bytes(out.address(), &guid_bytes(&header.ecp_type));
    }
    STATUS_SUCCESS
}

/// FsRtlAcknowledgeEcp: Flags |= 8.
pub fn acknowledge(context: u64) {
    header_of(context).flags.atomic().fetch_or(ECP_ACKNOWLEDGED, Ordering::SeqCst);
}

/// FsRtlIsEcpAcknowledged: bit 3.
pub fn is_acknowledged(context: u64) -> bool {
    header_of(context).flags.get() & ECP_ACKNOWLEDGED != 0
}

/// FsRtlIsEcpFromUserMode: bit 4.
pub fn is_from_user_mode(context: u64) -> bool {
    header_of(context).flags.get() & ECP_FROM_USER_MODE != 0
}

/// FsRtlPrepareToReuseEcp: Flags &= ~8.
pub fn prepare_to_reuse(context: u64) {
    header_of(context).flags.atomic().fetch_and(!ECP_ACKNOWLEDGED, Ordering::SeqCst);
}

/// FsRtlGetEcpListFromIrp(Irp, EcpList*): só IRPs de create; a lista mora em
/// Irp->UserBuffer nesses IRPs.
pub fn get_list_from_irp(irp: &Irp, list_out: &Field<u64>) -> u32 {
    if irp.flags.get() & IRP_CREATE_OPERATION == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    list_out.set(irp.user_buffer.get());
    STATUS_SUCCESS
}

/// FsRtlSetEcpListIntoIrp(Irp, EcpList): create sem lista anterior; marca a
/// lista (Flags |= 8).
pub fn set_list_into_irp(irp: &Irp, list: &EcpList) -> u32 {
    if irp.flags.get() & IRP_CREATE_OPERATION == 0 {
        return STATUS_INVALID_PARAMETER_1;
    }
    if irp.user_buffer.get() != 0 {
        return STATUS_INVALID_PARAMETER_2;
    }
    irp.user_buffer.set(list.address());
    list.flags.atomic().fetch_or(LIST_FLAG_IN_IRP, Ordering::SeqCst);
    STATUS_SUCCESS
}

/// FsRtlInitExtraCreateParameterLookasideList(Lookaside, Flags, Size, Tag):
/// blocos de Size + 0x48; NONPAGED -> NPagedLookaside(NX), senão paginada.
pub fn init_lookaside(list: u64, flags: u32, size: u64, tag: u32) -> Result<(), KernelError> {
    let block = size.wrapping_add(EcpHeader::SIZE);
    if flags & ALLOCATE_FLAG_NONPAGED_POOL != 0 {
        lookaside::initialize(list, 0, 0, NON_PAGED_POOL_NX, block, tag, false)
    } else {
        lookaside::initialize(list, 0, 0, 0, block, tag, true)
    }
}

/// FsRtlDeleteExtraCreateParameterLookasideList(Lookaside, Flags).
pub fn delete_lookaside(list: u64) -> Result<(), KernelError> {
    lookaside::delete(list)
}

/// FsRtlAllocateExtraCreateParameterFromLookasideList(EcpType, SizeOfContext,
/// Flags, CleanupCallback, LookasideList, EcpContext*): contexto maior que o
/// bloco cai em `allocate` com a tag da lookaside.
pub fn allocate_from_lookaside(ecp_type: &Guid, size: u32, flags: u32, cleanup: u64, list: &GeneralLookaside, context_out: &Field<u64>) -> Result<u32, KernelError> {
    let total = size.wrapping_add(EcpHeader::SIZE as u32);
    if total > list.size.get() {
        return allocate(ecp_type, size, flags, cleanup, list.tag.get(), context_out);
    }
    let entry_flags = if flags & ALLOCATE_FLAG_NONPAGED_POOL != 0 { ECP_ALLOCATED | ECP_NONPAGED } else { ECP_ALLOCATED };
    let address = lookaside::allocate(list.address())?;
    if address == 0 {
        context_out.set(0);
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    // SAFETY: bloco da lookaside, do tamanho cabeçalho + contexto.
    let header = unsafe { EcpHeader::at(address) };
    write_header(header, ecp_type, cleanup, entry_flags, total, list.address());
    context_out.set(context_of(header));
    Ok(STATUS_SUCCESS)
}
