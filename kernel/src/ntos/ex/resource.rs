//! ERESOURCE x64 — `system32/ntos/ex/resource.js`.
//!
//! ERESOURCE ocupa 0x68 bytes, OWNER_ENTRY 0x10 e o bloco circular de espera
//! 0x30 (layout e transferência de posse conferidos com o PE/PDB nativo).
//! Posse, recursão e filas ficam no convidado, sob o SpinLock do recurso.

use crate::hal::cpu;
use crate::ntos::ke::{critical_region, dispatcher, irql};
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

pub const STRUCT_SIZE: u64 = 0x68;
const OWNER_TABLE: u64 = 0x10;
const ACTIVE_COUNT: u64 = 0x18;
const FLAGS: u64 = 0x1A;
const SHARED_WAITERS: u64 = 0x20;
const EXCLUSIVE_WAITERS: u64 = 0x28;
const INLINE_OWNER: u64 = 0x30;
const OWNER_COUNT: u64 = 0x40;
const CONTENTION_COUNT: u64 = 0x44;
const SHARED_WAITER_COUNT: u64 = 0x48;
const EXCLUSIVE_WAITER_COUNT: u64 = 0x4C;
const SPIN_LOCK: u64 = 0x60;
const EXCLUSIVE_OWNER_FLAG: u16 = 0x80;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

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

/// Cabeça global (16 bytes) seguida da palavra de lock; 0 = ainda não alocada.
static RESOURCE_LIST: SpinLock<u64> = SpinLock::new(0);

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
fn with_lock<T>(lock: u64, action: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
    require_irql(2)?;
    let previous = irql::get_irql();
    if previous < 2 {
        irql::raise_irql(2);
    }
    while guest::compare_exchange64(lock, 0, 1)? != 0 {
        cpu::pause();
    }
    let result = action();
    let _ = guest::compare_exchange64(lock, 1, 0);
    if previous < 2 {
        irql::lower_irql(previous as u64);
    }
    result
}

fn clear(pointer: u64, length: u64) {
    for offset in (0..length).step_by(8) {
        guest::write64(pointer + offset, 0);
    }
}

fn insert_tail(head: u64, entry: u64) {
    let last = guest::read64(head + 8);
    guest::write64(entry, head);
    guest::write64(entry + 8, last);
    guest::write64(last, entry);
    guest::write64(head + 8, entry);
}

fn remove_entry(entry: u64) -> Result<u64, KernelError> {
    let next = guest::read64(entry);
    let previous = guest::read64(entry + 8);
    if guest::read64(next + 8) != entry || guest::read64(previous) != entry {
        return Err(KernelError::new("corrupt ERESOURCE list"));
    }
    guest::write64(previous, next);
    guest::write64(next + 8, previous);
    guest::write64(entry, entry);
    guest::write64(entry + 8, entry);
    Ok(next)
}

/// ExInitializeResourceLite: liga o corpo à lista global (alocada na
/// primeira inicialização).
pub fn initialize(resource: u64) -> Result<u32, KernelError> {
    require_irql(2)?;
    let list = {
        let mut list = RESOURCE_LIST.lock();
        if *list == 0 {
            let allocation = guest::alloc_bytes(24);
            if allocation == 0 {
                return Ok(STATUS_INSUFFICIENT_RESOURCES);
            }
            clear(allocation, 24);
            guest::write64(allocation, allocation);
            guest::write64(allocation + 8, allocation);
            *list = allocation;
        }
        *list
    };
    clear(resource, STRUCT_SIZE);
    with_lock(list + 16, || {
        insert_tail(list, resource);
        Ok(())
    })?;
    Ok(0)
}

fn has_owners_or_waiters(resource: u64) -> bool {
    guest::read32(resource + OWNER_COUNT) != 0 || guest::read32(resource + SHARED_WAITER_COUNT) != 0 || guest::read32(resource + EXCLUSIVE_WAITER_COUNT) != 0
}

/// ExReinitializeResourceLite: exige recurso ocioso; conserva a tabela, os
/// vínculos globais e o SpinLock.
pub fn reinitialize(resource: u64) -> Result<u32, KernelError> {
    require_irql(2)?;
    with_lock(resource + SPIN_LOCK, || {
        if has_owners_or_waiters(resource) {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let table = guest::read64(resource + OWNER_TABLE);
        if table != 0 {
            let capacity = guest::read32(table + 8);
            clear(table, capacity as u64 * 16);
            guest::write32(table + 8, capacity);
        }
        clear(resource + ACTIVE_COUNT, 0x40);
        Ok(0)
    })
}

/// ExDeleteResourceLite.
pub fn delete(resource: u64) -> Result<u32, KernelError> {
    require_irql(2)?;
    with_lock(resource + SPIN_LOCK, || {
        if has_owners_or_waiters(resource) {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let list = *RESOURCE_LIST.lock();
        if list == 0 {
            return Err(KernelError::new("ERESOURCE was not initialized"));
        }
        with_lock(list + 16, || remove_entry(resource))?;
        let table = guest::read64(resource + OWNER_TABLE);
        if table != 0 {
            guest::free_bytes(table);
        }
        guest::write64(resource + OWNER_TABLE, 0);
        Ok(0)
    })
}

/// Entrada embutida e depois a tabela extra; 0 = sem posse nem reserva.
fn find_owner(resource: u64, thread: u64) -> u64 {
    if guest::read64(resource + INLINE_OWNER) == thread {
        return resource + INLINE_OWNER;
    }
    let table = guest::read64(resource + OWNER_TABLE);
    if table != 0 {
        for index in 1..guest::read32(table + 8) as u64 {
            let entry = table + index * 16;
            if guest::read64(entry) == thread {
                return entry;
            }
        }
    }
    0
}

/// Entrada livre; `table_only` evita a embutida. Tabela cheia é ampliada
/// (3 entradas, depois o dobro) com a primeira entrada como cabeçalho.
fn reserve_owner(resource: u64, table_only: bool) -> Result<u64, KernelError> {
    if !table_only && guest::read64(resource + INLINE_OWNER) == 0 {
        return Ok(resource + INLINE_OWNER);
    }
    let table = guest::read64(resource + OWNER_TABLE);
    let capacity = if table != 0 { guest::read32(table + 8) as u64 } else { 0 };
    for index in 1..capacity {
        let entry = table + index * 16;
        if guest::read64(entry) == 0 {
            return Ok(entry);
        }
    }
    let next_capacity = if capacity != 0 { capacity * 2 } else { 3 };
    let new_table = guest::alloc_bytes(next_capacity * 16);
    if new_table == 0 {
        return Err(KernelError::new("ERESOURCE owner table allocation failed"));
    }
    clear(new_table, next_capacity * 16);
    for offset in (0..capacity * 16).step_by(8) {
        guest::write64(new_table + offset, guest::read64(table + offset));
    }
    guest::write32(new_table + 8, next_capacity as u32);
    guest::write64(resource + OWNER_TABLE, new_table);
    if table != 0 {
        guest::free_bytes(table);
    }
    Ok(new_table + capacity.max(1) * 16)
}

/// Os 29 bits de recursão da palavra de controle da entrada.
fn recursion(entry: u64) -> u32 {
    guest::read32(entry + 8) >> 3
}

fn set_owner(entry: u64, thread: u64, depth: u32) -> Result<(), KernelError> {
    if depth > 0x1FFF_FFFF {
        return Err(KernelError::new("ERESOURCE recursion overflow"));
    }
    guest::write64(entry, thread);
    guest::write32(entry + 8, depth * 8);
    Ok(())
}

fn set_owner_count(resource: u64, count: u32) {
    guest::write32(resource + OWNER_COUNT, count);
    guest::write16(resource + ACTIVE_COUNT, (count != 0) as u16);
}

fn set_exclusive(resource: u64, exclusive: bool) {
    let flags = guest::read16(resource + FLAGS);
    guest::write16(resource + FLAGS, if exclusive { flags | EXCLUSIVE_OWNER_FLAG } else { flags & !EXCLUSIVE_OWNER_FLAG });
}

fn is_exclusive(resource: u64) -> bool {
    guest::read16(resource + FLAGS) & EXCLUSIVE_OWNER_FLAG != 0
}

fn enqueue_waiter(resource: u64, block: u64, shared: bool) {
    let field = resource + if shared { SHARED_WAITERS } else { EXCLUSIVE_WAITERS };
    let head = guest::read64(field);
    if head != 0 {
        insert_tail(head, block);
    } else {
        guest::write64(block, block);
        guest::write64(block + 8, block);
        guest::write64(field, block);
    }
    let count = resource + if shared { SHARED_WAITER_COUNT } else { EXCLUSIVE_WAITER_COUNT };
    guest::write32(count, guest::read32(count) + 1);
    guest::write32(resource + CONTENTION_COUNT, guest::read32(resource + CONTENTION_COUNT).wrapping_add(1));
}

fn dequeue_waiter(resource: u64, shared: bool) -> Result<u64, KernelError> {
    let field = resource + if shared { SHARED_WAITERS } else { EXCLUSIVE_WAITERS };
    let head = guest::read64(field);
    if head == 0 {
        return Ok(0);
    }
    let next = remove_entry(head)?;
    guest::write64(field, if next == head { 0 } else { next });
    let count = resource + if shared { SHARED_WAITER_COUNT } else { EXCLUSIVE_WAITER_COUNT };
    guest::write32(count, guest::read32(count) - 1);
    Ok(head)
}

/// Transfere a posse aos leitores aguardando e marca seus blocos concluídos.
fn wake_shared(resource: u64) -> Result<(), KernelError> {
    set_exclusive(resource, false);
    loop {
        let block = dequeue_waiter(resource, true)?;
        if block == 0 {
            return Ok(());
        }
        let thread = guest::read64(block + 0x10);
        // WaitForExclusive pode conservar uma aquisição antiga.
        if find_owner(resource, thread) == 0 {
            set_owner(reserve_owner(resource, false)?, thread, 1)?;
        }
        set_owner_count(resource, guest::read32(resource + OWNER_COUNT) + 1);
        guest::write32(block + 0x1C, 1);
    }
}

/// Entrega a posse exclusiva ao primeiro escritor da fila.
fn wake_exclusive(resource: u64) -> Result<(), KernelError> {
    let block = dequeue_waiter(resource, false)?;
    if block == 0 {
        return Ok(());
    }
    set_exclusive(resource, true);
    set_owner_count(resource, 1);
    set_owner(resource + INLINE_OWNER, guest::read64(block + 0x10), 1)?;
    guest::write32(block + 0x1C, 1);
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
        let resource = self.resource;
        let thread = self.thread;
        let mode = self.mode;
        let outcome = with_lock(resource + SPIN_LOCK, || -> Result<Option<u64>, KernelError> {
            if self.block != 0 {
                if guest::read32(self.block + 0x1C) == 0 {
                    return Ok(None);
                }
                guest::free_bytes(self.block);
                self.block = 0;
                return Ok(Some(1));
            }
            let active = guest::read32(resource + OWNER_COUNT);
            let exclusive = is_exclusive(resource);
            // Uma entrada existente permite recursão; WaitForExclusive ainda
            // respeita escritores aguardando.
            let owned = find_owner(resource, thread);
            let exclusive_waiters = guest::read32(resource + EXCLUSIVE_WAITER_COUNT);
            if active == 0 {
                let entry = if mode == Mode::Exclusive { resource + INLINE_OWNER } else { reserve_owner(resource, false)? };
                set_owner(entry, thread, 1)?;
                set_owner_count(resource, 1);
                set_exclusive(resource, mode == Mode::Exclusive);
                return Ok(Some(1));
            }
            if owned != 0 && ((exclusive && guest::read64(resource + INLINE_OWNER) == thread) || (mode != Mode::Exclusive && (mode != Mode::WaitExclusive || exclusive_waiters == 0))) {
                set_owner(owned, thread, recursion(owned) + 1)?;
                return Ok(Some(1));
            }
            if mode != Mode::Exclusive && !exclusive && (mode == Mode::Starve || exclusive_waiters == 0) {
                set_owner(reserve_owner(resource, false)?, thread, 1)?;
                set_owner_count(resource, active + 1);
                return Ok(Some(1));
            }
            if !self.wait {
                return Ok(Some(0));
            }
            let block = guest::alloc_bytes(0x30);
            if block == 0 {
                return Err(KernelError::new("ERESOURCE wait block allocation failed"));
            }
            clear(block, 0x30);
            guest::write64(block + 0x10, thread);
            // Tipo e tamanho; +0x1C é o indicador de posse concedida.
            guest::write32(block + 0x18, 0x60001);
            guest::write64(block + 0x20, block + 0x20);
            guest::write64(block + 0x28, block + 0x20);
            if mode != Mode::Exclusive && owned == 0 {
                if let Err(error) = reserve_owner(resource, true).and_then(|entry| set_owner(entry, thread, 1)) {
                    guest::free_bytes(block);
                    return Err(error);
                }
            }
            enqueue_waiter(resource, block, mode != Mode::Exclusive);
            self.block = block;
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
        // Os helpers combinados devolvem KTHREAD.Win32Thread (+0x1C8).
        let value = if self.critical { guest::read64(thread + 0x1C8) } else { value };
        self.result = Some(value);
        Ok(Some(value))
    }
}

fn acquire(resource: u64, mode: Mode, wait: bool, enter_critical: bool) -> Result<u64, KernelError> {
    let mut request = begin(resource, mode, wait, enter_critical)?;
    loop {
        if let Some(result) = request.poll()? {
            return Ok(result);
        }
        dispatcher::pump_kernel();
    }
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
    with_lock(resource + SPIN_LOCK, || {
        let entry = find_owner(resource, thread);
        if entry == 0 || recursion(entry) == 0 {
            return Err(KernelError::new("ERESOURCE released by a non-owner"));
        }
        let remaining = recursion(entry) - 1;
        if remaining != 0 {
            return set_owner(entry, thread, remaining);
        }
        let exclusive = is_exclusive(resource);
        set_owner(entry, 0, 0)?;
        set_owner_count(resource, guest::read32(resource + OWNER_COUNT) - 1);
        if exclusive {
            set_exclusive(resource, false);
            if guest::read32(resource + SHARED_WAITER_COUNT) != 0 { wake_shared(resource) } else { wake_exclusive(resource) }
        } else if guest::read32(resource + OWNER_COUNT) == 0 {
            if guest::read32(resource + EXCLUSIVE_WAITER_COUNT) != 0 { wake_exclusive(resource) } else { wake_shared(resource) }
        } else {
            Ok(())
        }
    })
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
    with_lock(resource + SPIN_LOCK, || {
        let entry = find_owner(resource, thread);
        Ok(if entry != 0 { recursion(entry) } else { 0 })
    })
}

/// ExIsResourceAcquiredExclusiveLite.
pub fn is_acquired_exclusive(resource: u64) -> Result<bool, KernelError> {
    require_irql(2)?;
    let thread = current_thread()?;
    with_lock(resource + SPIN_LOCK, || Ok(is_exclusive(resource) && guest::read64(resource + INLINE_OWNER) == thread))
}

/// ExConvertExclusiveToSharedLite: abre o recurso aos leitores aguardando.
pub fn convert_exclusive_to_shared(resource: u64) -> Result<(), KernelError> {
    require_irql(1)?;
    let thread = current_thread()?;
    with_lock(resource + SPIN_LOCK, || {
        if !is_exclusive(resource) || guest::read64(resource + INLINE_OWNER) != thread {
            return Err(KernelError::new("ERESOURCE conversion requires exclusive ownership"));
        }
        wake_shared(resource)
    })
}

pub fn shared_waiters(resource: u64) -> u32 {
    guest::read32(resource + SHARED_WAITER_COUNT)
}

pub fn exclusive_waiters(resource: u64) -> u32 {
    guest::read32(resource + EXCLUSIVE_WAITER_COUNT)
}
