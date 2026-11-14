//! ERESOURCE x64.
//!
//! ERESOURCE ocupa 0x68 bytes, OWNER_ENTRY 0x10 e o bloco circular de espera
//! 0x30 (layout e transferência de posse conferidos com o PE/PDB nativo).
//! Posse, recursão e filas ficam no convidado, sob o SpinLock do recurso.

use core::sync::atomic::Ordering;

use super::list_entry;
use crate::hal::cpu;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{Eresource, Kevent, Kthread, ListEntry, OwnerEntry};
use crate::ntos::ke::{critical_region, dispatcher, irql};
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

pub const STRUCT_SIZE: u64 = <Eresource as NtStruct>::SIZE;
/// Flag.ResourceOwnedExclusive.
const EXCLUSIVE_OWNER_FLAG: u16 = 0x80;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// Bloco de espera publicado em SharedWaiters/ExclusiveWaiters: vínculo
/// circular, thread aguardando e o evento cujo SignalState marca a posse
/// concedida.
#[repr(C)]
struct WaitBlock {
    wait_list: ListEntry,
    /// -> `_KTHREAD`
    thread: Field<u64>,
    event: Kevent,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for WaitBlock {}

const _: () = {
    assert!(core::mem::size_of::<WaitBlock>() == 0x30);
    assert!(core::mem::offset_of!(WaitBlock, thread) == 0x10);
    assert!(core::mem::offset_of!(WaitBlock, event) == 0x18);
};

/// Cabeça global dos recursos (ExpSystemResourcesList) e a palavra do lock.
#[repr(C)]
struct ResourceList {
    head: ListEntry,
    lock: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for ResourceList {}

const _: () = assert!(core::mem::size_of::<ResourceList>() == 0x18);

/// Modo de aquisição de cada export.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Exclusive,
    Shared,
    /// ExAcquireSharedStarveExclusive.
    Starve,
    /// ExAcquireSharedWaitForExclusive.
    WaitExclusive,
}

/// Endereço da cabeça global; 0 = ainda não alocada.
static RESOURCE_LIST: SpinLock<u64> = SpinLock::new(0);

fn resource_at(resource: u64) -> &'static Eresource {
    // SAFETY: os exports recebem um PERESOURCE do chamador.
    unsafe { Eresource::at(resource) }
}

fn current_thread() -> Result<u64, KernelError> {
    match process::get_current_thread() {
        0 => Err(KernelError::new("ERESOURCE requires a current KTHREAD")),
        thread => Ok(thread),
    }
}

fn require_irql(maximum: u8) -> Result<(), KernelError> {
    if irql::get_irql() > maximum {
        return Err(KernelError::new("ERESOURCE used above its permitted IRQL"));
    }
    Ok(())
}

/// Eleva a DISPATCH_LEVEL, adquire a palavra do lock e executa `action`.
fn with_lock<T>(lock: &Field<u64>, action: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
    require_irql(2)?;
    let previous = irql::get_irql();
    if previous < 2 {
        irql::raise_irql(2);
    }
    while lock.atomic().compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
        cpu::pause();
    }
    let result = action();
    lock.atomic().store(0, Ordering::Release);
    if previous < 2 {
        irql::lower_irql(previous as u64);
    }
    result
}

fn clear(pointer: u64, length: u64) {
    guest::write_bytes(pointer, &alloc::vec![0u8; length as usize]);
}

fn remove_entry(entry: &ListEntry) -> Result<u64, KernelError> {
    let next = list_entry::remove(entry).ok_or_else(|| KernelError::new("corrupt ERESOURCE list"))?;
    list_entry::initialize(entry);
    Ok(next)
}

/// ExInitializeResourceLite: liga o corpo à lista global (alocada na
/// primeira inicialização).
pub fn initialize(resource: u64) -> Result<u32, KernelError> {
    require_irql(2)?;
    let list = {
        let mut list = RESOURCE_LIST.lock();
        if *list == 0 {
            let allocation = guest::alloc_bytes(ResourceList::SIZE);
            if allocation == 0 {
                return Ok(STATUS_INSUFFICIENT_RESOURCES);
            }
            clear(allocation, ResourceList::SIZE);
            // SAFETY: alocação nova do tamanho da cabeça.
            list_entry::initialize(&unsafe { ResourceList::at(allocation) }.head);
            *list = allocation;
        }
        // SAFETY: a cabeça global vive até o fim.
        unsafe { ResourceList::at(*list) }
    };
    clear(resource, STRUCT_SIZE);
    let body = resource_at(resource);
    with_lock(&list.lock, || {
        list_entry::insert_tail(&list.head, &body.system_resources_list);
        Ok(())
    })?;
    Ok(0)
}

fn has_owners_or_waiters(resource: &Eresource) -> bool {
    resource.active_entries.get() != 0 || resource.number_of_shared_waiters.get() != 0 || resource.number_of_exclusive_waiters.get() != 0
}

/// Vetor de OWNER_ENTRY apontado por OwnerTable; a entrada 0 é o cabeçalho
/// cujo TableSize é a capacidade.
fn owner_table(resource: &Eresource) -> Option<&'static [OwnerEntry]> {
    let table = resource.owner_table.get();
    if table == 0 {
        return None;
    }
    // SAFETY: OwnerTable aponta para TableSize entradas alocadas por nós.
    let header = unsafe { OwnerEntry::at(table) };
    Some(unsafe { OwnerEntry::array_at(table, header.table_size.get().max(1) as usize) })
}

/// ExReinitializeResourceLite: exige recurso ocioso; conserva a tabela, os
/// vínculos globais e o SpinLock.
pub fn reinitialize(resource: u64) -> Result<u32, KernelError> {
    require_irql(2)?;
    let body = resource_at(resource);
    with_lock(&body.spin_lock, || {
        if has_owners_or_waiters(body) {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        if let Some(table) = owner_table(body) {
            let capacity = table[0].table_size.get();
            clear(table[0].address(), capacity as u64 * OwnerEntry::SIZE);
            table[0].table_size.set(capacity);
        }
        // ActiveCount..Reserved2: tudo menos os vínculos, Address e SpinLock.
        let start = body.active_count.address();
        clear(start, body.address.address() - start);
        Ok(0)
    })
}

/// ExDeleteResourceLite.
pub fn delete(resource: u64) -> Result<u32, KernelError> {
    require_irql(2)?;
    let body = resource_at(resource);
    with_lock(&body.spin_lock, || {
        if has_owners_or_waiters(body) {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let list = *RESOURCE_LIST.lock();
        if list == 0 {
            return Err(KernelError::new("ERESOURCE was not initialized"));
        }
        // SAFETY: a cabeça global vive até o fim.
        let list = unsafe { ResourceList::at(list) };
        with_lock(&list.lock, || remove_entry(&body.system_resources_list))?;
        let table = body.owner_table.get();
        if table != 0 {
            guest::free_bytes(table);
        }
        body.owner_table.set(0);
        Ok(0)
    })
}

/// Entrada embutida e depois a tabela extra; `None` = sem posse nem reserva.
fn find_owner(resource: &'static Eresource, thread: u64) -> Option<&'static OwnerEntry> {
    if resource.owner_entry.owner_thread.get() == thread {
        return Some(&resource.owner_entry);
    }
    owner_table(resource).and_then(|table| table.iter().skip(1).find(|entry| entry.owner_thread.get() == thread))
}

/// Entrada livre; `table_only` evita a embutida. Tabela cheia é ampliada
/// (3 entradas, depois o dobro) com a primeira entrada como cabeçalho.
fn reserve_owner(resource: &'static Eresource, table_only: bool) -> Result<&'static OwnerEntry, KernelError> {
    if !table_only && resource.owner_entry.owner_thread.get() == 0 {
        return Ok(&resource.owner_entry);
    }
    let table = owner_table(resource);
    let capacity = table.map_or(0, |table| table[0].table_size.get() as u64);
    if let Some(entry) = table.and_then(|table| table.iter().skip(1).find(|entry| entry.owner_thread.get() == 0)) {
        return Ok(entry);
    }
    let next_capacity = if capacity != 0 { capacity * 2 } else { 3 };
    let new_table = guest::alloc_bytes(next_capacity * OwnerEntry::SIZE);
    if new_table == 0 {
        return Err(KernelError::new("ERESOURCE owner table allocation failed"));
    }
    clear(new_table, next_capacity * OwnerEntry::SIZE);
    // SAFETY: alocação nova de `next_capacity` entradas.
    let entries = unsafe { OwnerEntry::array_at(new_table, next_capacity as usize) };
    if let Some(table) = table {
        for (target, source) in entries.iter().zip(table) {
            target.owner_thread.set(source.owner_thread.get());
            target.table_size.set(source.table_size.get());
        }
    }
    entries[0].table_size.set(next_capacity as u32);
    let old = resource.owner_table.get();
    resource.owner_table.set(new_table);
    if old != 0 {
        guest::free_bytes(old);
    }
    Ok(&entries[capacity.max(1) as usize])
}

/// Os 29 bits de recursão (OwnerCount) da palavra de controle da entrada.
fn recursion(entry: &OwnerEntry) -> u32 {
    entry.table_size.get() >> OwnerEntry::OWNER_COUNT_SHIFT
}

/// Dono e recursão; os três bits baixos de flags voltam a zero quando o
/// dono muda.
fn set_owner(entry: &OwnerEntry, thread: u64, depth: u32) -> Result<(), KernelError> {
    if depth > 0x1FFF_FFFF {
        return Err(KernelError::new("ERESOURCE recursion overflow"));
    }
    let flags = if thread != 0 && entry.owner_thread.get() == thread { entry.table_size.get() & !OwnerEntry::OWNER_COUNT_MASK } else { 0 };
    entry.owner_thread.set(thread);
    entry.table_size.set(depth << OwnerEntry::OWNER_COUNT_SHIFT | flags);
    Ok(())
}

fn set_owner_count(resource: &Eresource, count: u32) {
    resource.active_entries.set(count);
    resource.active_count.set((count != 0) as i16);
}

fn set_exclusive(resource: &Eresource, exclusive: bool) {
    let flags = resource.flag.get();
    resource.flag.set(if exclusive { flags | EXCLUSIVE_OWNER_FLAG } else { flags & !EXCLUSIVE_OWNER_FLAG });
}

fn is_exclusive(resource: &Eresource) -> bool {
    resource.flag.get() & EXCLUSIVE_OWNER_FLAG != 0
}

fn waiter_fields(resource: &Eresource, shared: bool) -> (&Field<u64>, &Field<u32>) {
    if shared {
        (&resource.shared_waiters, &resource.number_of_shared_waiters)
    } else {
        (&resource.exclusive_waiters, &resource.number_of_exclusive_waiters)
    }
}

fn enqueue_waiter(resource: &Eresource, block: &WaitBlock, shared: bool) {
    let (field, count) = waiter_fields(resource, shared);
    let head = field.get();
    if head != 0 {
        list_entry::insert_tail(list_entry::at(head), &block.wait_list);
    } else {
        list_entry::initialize(&block.wait_list);
        field.set(block.address());
    }
    count.set(count.get() + 1);
    resource.contention_count.set(resource.contention_count.get().wrapping_add(1));
}

fn dequeue_waiter(resource: &Eresource, shared: bool) -> Result<Option<&'static WaitBlock>, KernelError> {
    let (field, count) = waiter_fields(resource, shared);
    let head = field.get();
    if head == 0 {
        return Ok(None);
    }
    let next = remove_entry(list_entry::at(head))?;
    field.set(if next == head { 0 } else { next });
    count.set(count.get() - 1);
    // SAFETY: a fila só contém blocos de espera publicados por `poll`.
    Ok(Some(unsafe { WaitBlock::at(head) }))
}

/// Transfere a posse aos leitores aguardando e marca seus blocos concluídos.
fn wake_shared(resource: &'static Eresource) -> Result<(), KernelError> {
    set_exclusive(resource, false);
    while let Some(block) = dequeue_waiter(resource, true)? {
        let thread = block.thread.get();
        // WaitForExclusive pode conservar uma aquisição antiga.
        if find_owner(resource, thread).is_none() {
            set_owner(reserve_owner(resource, false)?, thread, 1)?;
        }
        set_owner_count(resource, resource.active_entries.get() + 1);
        block.event.header.signal_state.set(1);
    }
    Ok(())
}

/// Entrega a posse exclusiva ao primeiro escritor da fila.
fn wake_exclusive(resource: &Eresource) -> Result<(), KernelError> {
    let Some(block) = dequeue_waiter(resource, false)? else { return Ok(()) };
    set_exclusive(resource, true);
    set_owner_count(resource, 1);
    set_owner(&resource.owner_entry, block.thread.get(), 1)?;
    block.event.header.signal_state.set(1);
    Ok(())
}

/// Aquisição suspensível.
pub struct Request {
    resource: u64,
    thread: u64,
    mode: Mode,
    wait: bool,
    critical: bool,
    block: u64,
    result: Option<u64>,
}

/// Captura thread, modo e política de espera; `enter_critical` também entra
/// na região crítica e força a espera.
pub fn begin(resource: u64, mode: Mode, wait: bool, enter_critical: bool) -> Result<Request, KernelError> {
    require_irql(1)?;
    let thread = current_thread()?;
    if enter_critical {
        critical_region::enter_critical()?;
    }
    Ok(Request { resource, thread, mode, wait: enter_critical || wait, critical: enter_critical, block: 0, result: None })
}

impl Request {
    /// `Some(resultado)` quando concluída; `None` enquanto aguarda.
    pub fn poll(&mut self) -> Result<Option<u64>, KernelError> {
        if let Some(result) = self.result {
            return Ok(Some(result));
        }
        let resource = resource_at(self.resource);
        let thread = self.thread;
        let mode = self.mode;
        let outcome = with_lock(&resource.spin_lock, || -> Result<Option<u64>, KernelError> {
            if self.block != 0 {
                // SAFETY: bloco alocado e publicado por esta requisição.
                if unsafe { WaitBlock::at(self.block) }.event.header.signal_state.get() == 0 {
                    return Ok(None);
                }
                guest::free_bytes(self.block);
                self.block = 0;
                return Ok(Some(1));
            }
            let active = resource.active_entries.get();
            let exclusive = is_exclusive(resource);
            // Uma entrada existente permite recursão; WaitForExclusive ainda
            // respeita escritores aguardando.
            let owned = find_owner(resource, thread);
            let exclusive_waiters = resource.number_of_exclusive_waiters.get();
            if active == 0 {
                let entry = if mode == Mode::Exclusive { &resource.owner_entry } else { reserve_owner(resource, false)? };
                set_owner(entry, thread, 1)?;
                set_owner_count(resource, 1);
                set_exclusive(resource, mode == Mode::Exclusive);
                return Ok(Some(1));
            }
            if let Some(owned) = owned {
                if (exclusive && resource.owner_entry.owner_thread.get() == thread) || (mode != Mode::Exclusive && (mode != Mode::WaitExclusive || exclusive_waiters == 0)) {
                    set_owner(owned, thread, recursion(owned) + 1)?;
                    return Ok(Some(1));
                }
            }
            if mode != Mode::Exclusive && !exclusive && (mode == Mode::Starve || exclusive_waiters == 0) {
                set_owner(reserve_owner(resource, false)?, thread, 1)?;
                set_owner_count(resource, active + 1);
                return Ok(Some(1));
            }
            if !self.wait {
                return Ok(Some(0));
            }
            let allocation = guest::alloc_bytes(WaitBlock::SIZE);
            if allocation == 0 {
                return Err(KernelError::new("ERESOURCE wait block allocation failed"));
            }
            clear(allocation, WaitBlock::SIZE);
            // SAFETY: alocação nova do tamanho do bloco.
            let block = unsafe { WaitBlock::at(allocation) };
            block.thread.set(thread);
            // Evento de sincronização (Type 1, Size 6); SignalState é o
            // indicador de posse concedida.
            block.event.header.lock.set(0x0006_0001);
            list_entry::initialize(&block.event.header.wait_list_head);
            if mode != Mode::Exclusive && owned.is_none() {
                if let Err(error) = reserve_owner(resource, true).and_then(|entry| set_owner(entry, thread, 1)) {
                    guest::free_bytes(allocation);
                    return Err(error);
                }
            }
            enqueue_waiter(resource, block, mode != Mode::Exclusive);
            self.block = allocation;
            Ok(None)
        });
        let result = match outcome {
            Ok(result) => result,
            Err(error) => {
                // Só desfaz a região crítica sem espera publicada pendente.
                if self.critical && self.block == 0 {
                    self.critical = false;
                    critical_region::leave_critical()?;
                }
                return Err(error);
            }
        };
        let Some(value) = result else { return Ok(None) };
        // Os helpers combinados devolvem KTHREAD.Win32Thread.
        // SAFETY: a thread corrente é um KTHREAD vivo.
        let value = if self.critical { unsafe { Kthread::at(thread) }.win32_thread.get() } else { value };
        self.result = Some(value);
        Ok(Some(value))
    }
}

/// Numa syscall a thread bloqueia até a posse; fora dela o dispatcher avança
/// entre consultas.
fn acquire(resource: u64, mode: Mode, wait: bool, enter_critical: bool) -> Result<u64, KernelError> {
    let mut request = begin(resource, mode, wait, enter_critical)?;
    crate::ntos::ke::context_switch::acquire_until(|| request.poll(), dispatcher::pump_kernel)
}

pub fn acquire_exclusive(resource: u64, wait: bool) -> Result<u64, KernelError> {
    acquire(resource, Mode::Exclusive, wait, false)
}

pub fn acquire_shared(resource: u64, wait: bool) -> Result<u64, KernelError> {
    acquire(resource, Mode::Shared, wait, false)
}

pub fn acquire_shared_starve_exclusive(resource: u64, wait: bool) -> Result<u64, KernelError> {
    acquire(resource, Mode::Starve, wait, false)
}

pub fn acquire_shared_wait_for_exclusive(resource: u64, wait: bool) -> Result<u64, KernelError> {
    acquire(resource, Mode::WaitExclusive, wait, false)
}

pub fn enter_exclusive(resource: u64) -> Result<u64, KernelError> {
    acquire(resource, Mode::Exclusive, true, true)
}

pub fn enter_shared(resource: u64) -> Result<u64, KernelError> {
    acquire(resource, Mode::Shared, true, true)
}

/// ExReleaseResourceForThreadLite: a última recursão entrega o recurso a
/// leitores ou escritores conforme a fila e o modo anterior.
pub fn release_for_thread(resource: u64, thread: u64) -> Result<(), KernelError> {
    require_irql(2)?;
    let resource = resource_at(resource);
    let mut referenced = 0u64;
    with_lock(&resource.spin_lock, || {
        let Some(entry) = find_owner(resource, thread).filter(|entry| recursion(entry) != 0) else {
            return Err(KernelError::new("ERESOURCE released by a non-owner"));
        };
        let remaining = recursion(entry) - 1;
        if remaining != 0 {
            return set_owner(entry, thread, remaining);
        }
        let exclusive = is_exclusive(resource);
        // OwnerReferenced: a última liberação solta a referência da thread
        // (o ObDereferenceObjectDeferDelete de ExpRelease*ResourceForThreadLite).
        if entry.owner_referenced() != 0 {
            referenced = thread & !3;
        }
        set_owner(entry, 0, 0)?;
        set_owner_count(resource, resource.active_entries.get() - 1);
        if exclusive {
            set_exclusive(resource, false);
            if resource.number_of_shared_waiters.get() != 0 { wake_shared(resource) } else { wake_exclusive(resource) }
        } else if resource.active_entries.get() == 0 {
            if resource.number_of_exclusive_waiters.get() != 0 { wake_exclusive(resource) } else { wake_shared(resource) }
        } else {
            Ok(())
        }
    })?;
    if referenced != 0 {
        crate::ntos::ob::object_reference::dereference_with_tag(referenced, THREAD_REFERENCE_TAG, false)?;
    }
    Ok(())
}

pub fn release(resource: u64) -> Result<(), KernelError> {
    release_for_thread(resource, current_thread()?)
}

/// ExReleaseResourceAndLeaveCriticalRegion.
pub fn release_and_leave(resource: u64) -> Result<(), KernelError> {
    release(resource)?;
    critical_region::leave_critical()
}

/// ExIsResourceAcquiredSharedLite: recursão da thread corrente.
pub fn is_acquired_shared(resource: u64) -> Result<u32, KernelError> {
    require_irql(2)?;
    let thread = current_thread()?;
    let resource = resource_at(resource);
    with_lock(&resource.spin_lock, || Ok(find_owner(resource, thread).map_or(0, recursion)))
}

/// ExIsResourceAcquiredExclusiveLite.
pub fn is_acquired_exclusive(resource: u64) -> Result<bool, KernelError> {
    require_irql(2)?;
    let thread = current_thread()?;
    let resource = resource_at(resource);
    with_lock(&resource.spin_lock, || Ok(is_exclusive(resource) && resource.owner_entry.owner_thread.get() == thread))
}

/// ExConvertExclusiveToSharedLite: abre o recurso aos leitores aguardando.
pub fn convert_exclusive_to_shared(resource: u64) -> Result<(), KernelError> {
    require_irql(1)?;
    let thread = current_thread()?;
    let resource = resource_at(resource);
    with_lock(&resource.spin_lock, || {
        if !is_exclusive(resource) || resource.owner_entry.owner_thread.get() != thread {
            return Err(KernelError::new("ERESOURCE conversion requires exclusive ownership"));
        }
        wake_shared(resource)
    })
}

pub fn shared_waiters(resource: u64) -> u32 {
    resource_at(resource).number_of_shared_waiters.get()
}

pub fn exclusive_waiters(resource: u64) -> u32 {
    resource_at(resource).number_of_exclusive_waiters.get()
}

// ---- Transferência de posse: ExSetResourceOwnerPointer(Ex) --------------------
//
// Comportamento conferido contra o ntoskrnl 10.0.19045:
//   ExSetResourceOwnerPointerEx(R, P, F) 0x2dcac0 / ExSetResourceOwnerPointer(R, P)
//   0x5b53e0 (= ...Ex com F = 0): ReservedLowFlags bit 0 (recurso "fast") ->
//   KeBugCheckEx(0x1C6, 0xE, R, 0, 0); senão ExpSetResourceOwnerPointerEx 0x2dcae0,
//   sob o spin lock do recurso:
//   - exclusivo: (ExpResourceEnforcesOwnershipTransfer é FALSE: a global
//     ExpResourceEnforceOwnerTransfer vale 0) a entrada embutida passa a P;
//   - compartilhado: acha a entrada de P e a da thread corrente (sem a da
//     corrente: KeBugCheckEx(0xE3, R, thread, OwnerTable, 4)). Se P já tem
//     entrada, as contagens se somam nela e a da corrente é liberada
//     (ActiveEntries - 1); senão a entrada da corrente passa a P.
//   - F & FLAG_OWNER_POINTER_IS_THREAD: P & ~3 tem de ser a thread corrente
//     (senão KeBugCheckEx(0x132, R, OwnerTable, thread, P)); a thread ganha uma
//     referência (ObfReferenceObjectWithTag 'Dflt') e a entrada o bit
//     OwnerReferenced, que a liberação final desfaz (ObDereferenceObjectDeferDelete).
//   Os bits IoPriorityBoosted/IoQoSPriorityBoosted que o NT repassa
//   (PsBoostThreadIoEx/PsBoostThreadIoQoS) nunca são ligados pelo ERESOURCE do
//   OpenNT, que não dá boost de E/S; não há o que repassar.

/// FLAG_OWNER_POINTER_IS_THREAD.
pub const OWNER_POINTER_IS_THREAD: u32 = 1;
/// ReservedLowFlags bit 0: recurso "fast" (ExInitializeResourceFast...).
const FAST_RESOURCE: u8 = 1;
/// 'Dflt': a tag da referência da thread dona.
pub const THREAD_REFERENCE_TAG: u32 = 0x746C_6644;

/// ExSetResourceOwnerPointerEx(Resource, OwnerPointer, Flags); ExSetResourceOwnerPointer
/// é esta com Flags = 0.
pub fn set_owner_pointer(resource: u64, owner_pointer: u64, flags: u32) -> Result<(), KernelError> {
    let body = resource_at(resource);
    if body.reserved_low_flags.get() & FAST_RESOURCE != 0 {
        crate::ntos::ke::bugcheck::bug_check_ex(0x1C6, 0xE, resource, 0, 0);
    }
    let thread = current_thread()?;
    let is_thread = flags & OWNER_POINTER_IS_THREAD != 0;
    let validate = || {
        if owner_pointer & !3 != thread {
            crate::ntos::ke::bugcheck::bug_check_ex(0x132, resource, body.owner_table.get(), thread, owner_pointer);
        }
    };
    let reference = with_lock(&body.spin_lock, || -> Result<bool, KernelError> {
        if is_exclusive(body) {
            let entry = &body.owner_entry;
            if is_thread {
                validate();
                entry.set_owner_referenced(1);
            }
            entry.owner_thread.set(owner_pointer);
            return Ok(is_thread);
        }
        let target = find_owner(body, owner_pointer);
        let Some(current) = find_owner(body, thread) else {
            crate::ntos::ke::bugcheck::bug_check_ex(0xE3, resource, thread, body.owner_table.get(), 4);
        };
        let Some(target) = target else {
            if is_thread {
                validate();
                current.set_owner_referenced(1);
            }
            current.owner_thread.set(owner_pointer);
            return Ok(is_thread);
        };
        let mut referenced = false;
        if is_thread {
            validate();
            if target.owner_referenced() == 0 {
                target.set_owner_referenced(1);
                referenced = true;
            }
        }
        // OwnerCount somado na entrada de P (que mantém os seus bits baixos); a
        // da corrente fica livre com os bits baixos que tinha, como no NT.
        target.set_owner_count(target.owner_count().wrapping_add(current.owner_count()));
        current.set_owner_count(0);
        current.owner_thread.set(0);
        set_owner_count(body, body.active_entries.get().wrapping_sub(1));
        Ok(referenced)
    })?;
    if reference {
        crate::ntos::ob::object_reference::reference_with_tag(thread, THREAD_REFERENCE_TAG, false)?;
    }
    Ok(())
}

// ---- ERESOURCE com região de prioridade -----------------------------------
//
// (append de `ex-resource-priority` ao ex/resource.rs.)
//
// No ntoskrnl 19041: ExEnterPriorityRegionAndAcquireResource{Shared,Exclusive}
// = PsBoostThreadIoEx(thread, FALSE, 0, 0) + KeEnterCriticalRegion +
// ExAcquireResource{Shared,Exclusive}Lite(Wait=TRUE), devolvendo
// KTHREAD.Win32Thread; ExReleaseResourceAndLeavePriorityRegion =
// ExReleaseResourceLite + PsBoostThreadIoEx(thread, TRUE, 0, 0) +
// KeLeaveCriticalRegionThread. O impulso de E/S é o `ps::io_boost`
// (ETHREAD.IoBoostCount, o mesmo de PsEnter/LeavePriorityRegion).

/// O ETHREAD corrente, alvo do PsBoostThreadIoEx.
fn boost_thread() -> Result<&'static crate::ntos::inc::types::Ethread, KernelError> {
    // SAFETY: Prcb.CurrentThread é o ETHREAD vivo em execução.
    Ok(unsafe { crate::ntos::inc::types::Ethread::at(current_thread()?) })
}

/// ExEnterPriorityRegionAndAcquireResourceShared: KTHREAD.Win32Thread.
pub fn enter_priority_region_shared(resource: u64) -> Result<u64, KernelError> {
    crate::ntos::ps::io_boost::enter_priority_region(boost_thread()?);
    enter_shared(resource)
}

/// ExEnterPriorityRegionAndAcquireResourceExclusive: KTHREAD.Win32Thread.
pub fn enter_priority_region_exclusive(resource: u64) -> Result<u64, KernelError> {
    crate::ntos::ps::io_boost::enter_priority_region(boost_thread()?);
    enter_exclusive(resource)
}

/// ExReleaseResourceAndLeavePriorityRegion: libera, desfaz o impulso e sai
/// da região crítica, nessa ordem.
pub fn release_and_leave_priority_region(resource: u64) -> Result<(), KernelError> {
    release(resource)?;
    crate::ntos::ps::io_boost::leave_priority_region(boost_thread()?);
    critical_region::leave_critical()
}
