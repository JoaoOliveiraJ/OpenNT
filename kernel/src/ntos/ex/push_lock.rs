//! EX_PUSH_LOCK.
//!
//! A palavra nativa e blocos de espera de 0x40 bytes no convidado. Cada
//! aguardante possui sua alocação até ser desligado e retomar. Os caminhos
//! rápidos inline dos drivers observam os mesmos bits e ligações.

use crate::ntos::ke::{dispatcher, irql};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const LOCKED: u64 = 1;
const HAS_WAITERS: u64 = 2;
const WAKE_IN_PROGRESS: u64 = 4;
const MULTIPLE_SHARED_OWNERS: u64 = 8;
const SHARED_REFERENCE_INCREMENT: u64 = 16;
const ALIGNED_POINTER_MASK: u64 = !15;

const NEXT_BLOCK: u64 = 0x18;
const LAST_BLOCK: u64 = 0x20;
const PREVIOUS_BLOCK: u64 = 0x28;
const SHARED_COUNT: u64 = 0x30;
const BLOCK_FLAGS: u64 = 0x34;

fn cas64(pointer: u64, expected: u64, replacement: u64) -> u64 {
    guest::compare_exchange64(pointer, expected, replacement).unwrap_or_else(|error| panic!("{error}"))
}

fn cas32(pointer: u64, expected: u32, replacement: u32) -> u32 {
    guest::compare_exchange32(pointer, expected, replacement).unwrap_or_else(|error| panic!("{error}"))
}

fn read_atomic(pointer: u64) -> u64 {
    cas64(pointer, 0, 0)
}

fn update_atomic(pointer: u64, transform: impl Fn(u64) -> u64) -> u64 {
    let mut expected = read_atomic(pointer);
    loop {
        let observed = cas64(pointer, expected, transform(expected));
        if observed == expected {
            return expected;
        }
        expected = observed;
    }
}

fn store_atomic(pointer: u64, value: u64) {
    update_atomic(pointer, |_| value);
}

fn update_atomic32(pointer: u64, transform: impl Fn(u32) -> u32) -> u32 {
    let mut expected = guest::read32(pointer);
    loop {
        let observed = cas32(pointer, expected, transform(expected));
        if observed == expected {
            return expected;
        }
        expected = observed;
    }
}

fn validate(flags: u32, maximum_irql: u8) -> Result<(), KernelError> {
    if flags & !3 != 0 {
        return Err(KernelError::new("invalid EX_PUSH_LOCK flags"));
    }
    if irql::get_irql() > maximum_irql {
        return Err(KernelError::new("EX_PUSH_LOCK used above its permitted IRQL"));
    }
    Ok(())
}

/// Segue as ligações até o aguardante mais antigo e completa os vínculos de
/// retorno e o atalho da cabeça.
fn find_oldest_waiter(head: u64) -> u64 {
    let mut cursor = head;
    let mut last = read_atomic(cursor + LAST_BLOCK);
    while last == 0 {
        let newer = cursor;
        cursor = read_atomic(cursor + NEXT_BLOCK);
        store_atomic(cursor + PREVIOUS_BLOCK, newer);
        last = read_atomic(cursor + LAST_BLOCK);
    }
    if cursor != head {
        store_atomic(head + LAST_BLOCK, last);
    }
    last
}

/// Sinaliza o evento só quando o aguardante já saiu da fase de espera ativa.
fn signal_chain(mut block: u64) {
    while block != 0 {
        let next = read_atomic(block + PREVIOUS_BLOCK);
        if update_atomic32(block + BLOCK_FLAGS, |flags| flags & !2) & 2 == 0 {
            dispatcher::set_event(block);
        }
        block = next;
    }
}

fn wake(pointer: u64, mut value: u64) {
    loop {
        if value & LOCKED != 0 {
            let observed = cas64(pointer, value, value & !WAKE_IN_PROGRESS);
            if observed == value {
                return;
            }
            value = observed;
            continue;
        }
        let head = value & ALIGNED_POINTER_MASK;
        let last = find_oldest_waiter(head);
        let newer = read_atomic(last + PREVIOUS_BLOCK);
        // O escritor mais antigo acorda sozinho.
        if guest::read32(last + BLOCK_FLAGS) & 1 != 0 && newer != 0 {
            store_atomic(head + LAST_BLOCK, newer);
            store_atomic(last + PREVIOUS_BLOCK, 0);
            update_atomic(pointer, |current| current & !WAKE_IN_PROGRESS);
            signal_chain(last);
            return;
        }
        let observed = cas64(pointer, value, 0);
        if observed == value {
            signal_chain(last);
            return;
        }
        value = observed;
    }
}

fn update_waiter_links(pointer: u64, mut value: u64) {
    loop {
        if value & LOCKED == 0 {
            wake(pointer, value);
            return;
        }
        find_oldest_waiter(value & ALIGNED_POINTER_MASK);
        let observed = cas64(pointer, value, value & !WAKE_IN_PROGRESS);
        if observed == value {
            return;
        }
        value = observed;
    }
}

/// Aquisição sem bloco de espera.
fn try_acquire(pointer: u64, shared: bool) -> bool {
    let mut value = read_atomic(pointer);
    loop {
        if value & LOCKED != 0 && (!shared || value & HAS_WAITERS != 0 || value & ALIGNED_POINTER_MASK == 0) {
            return false;
        }
        let next = (value | LOCKED) + if shared && value & HAS_WAITERS == 0 { SHARED_REFERENCE_INCREMENT } else { 0 };
        let observed = cas64(pointer, value, next);
        if observed == value {
            return true;
        }
        value = observed;
    }
}

/// Estado suspensível de uma aquisição.
pub struct PushLockRequest {
    pointer: u64,
    shared: bool,
    allocation: u64,
    queued: bool,
    parked: bool,
}

pub fn begin(pointer: u64, shared: bool, flags: u32) -> Result<PushLockRequest, KernelError> {
    validate(flags, 1)?;
    Ok(PushLockRequest { pointer, shared, allocation: 0, queued: false, parked: false })
}

impl PushLockRequest {
    /// `Some(())` quando adquirido; `None` enquanto espera. Publica o próprio
    /// bloco sem perder uma liberação concorrente.
    pub fn poll(&mut self) -> Result<Option<()>, KernelError> {
        if self.queued {
            if !self.parked {
                self.parked = update_atomic32(self.allocation + BLOCK_FLAGS, |flags| flags & !2) & 2 != 0;
            }
            if self.parked && dispatcher::try_wait_objects(&[self.allocation], 1).is_none() {
                return Ok(None);
            }
            self.queued = false;
            self.parked = false;
        }
        loop {
            if try_acquire(self.pointer, self.shared) {
                if self.allocation != 0 {
                    guest::free_bytes(self.allocation);
                }
                self.allocation = 0;
                return Ok(Some(()));
            }
            if self.allocation == 0 {
                self.allocation = guest::alloc_bytes(0x40);
                if self.allocation == 0 {
                    return Err(KernelError::new("EX_PUSH_LOCK wait block allocation failed"));
                }
            }
            let block = self.allocation;
            // Uma liberação entre as duas leituras exige nova tentativa.
            let value = read_atomic(self.pointer);
            if value & LOCKED == 0 || (self.shared && value & HAS_WAITERS == 0 && value & ALIGNED_POINTER_MASK != 0) {
                continue;
            }
            dispatcher::initialize_event(block, 1, false);
            guest::write32(block + BLOCK_FLAGS, if self.shared { 2 } else { 3 });
            store_atomic(block + PREVIOUS_BLOCK, 0);
            store_atomic(block + 0x38, 0);
            let next = if value & HAS_WAITERS != 0 {
                store_atomic(block + NEXT_BLOCK, value & ALIGNED_POINTER_MASK);
                store_atomic(block + LAST_BLOCK, 0);
                guest::write32(block + SHARED_COUNT, 0xFFFF_FFFF);
                block | LOCKED | HAS_WAITERS | WAKE_IN_PROGRESS | (value & MULTIPLE_SHARED_OWNERS)
            } else {
                store_atomic(block + NEXT_BLOCK, 0);
                store_atomic(block + LAST_BLOCK, block);
                let owners = (value >> 4) as u32;
                guest::write32(block + SHARED_COUNT, if owners != 0 { owners } else { 0xFFFF_FFFE });
                block | LOCKED | HAS_WAITERS | if owners > 1 { MULTIPLE_SHARED_OWNERS } else { 0 }
            };
            if cas64(self.pointer, value, next) != value {
                continue;
            }
            self.queued = true;
            if value & HAS_WAITERS != 0 && value & WAKE_IN_PROGRESS == 0 {
                update_waiter_links(self.pointer, next);
            }
            self.parked = update_atomic32(block + BLOCK_FLAGS, |flags| flags & !2) & 2 != 0;
            if self.parked && dispatcher::try_wait_objects(&[block], 1).is_none() {
                return Ok(None);
            }
            self.queued = false;
            self.parked = false;
        }
    }
}

fn acquire(pointer: u64, shared: bool, flags: u32) -> Result<(), KernelError> {
    let mut request = begin(pointer, shared, flags)?;
    while request.poll()?.is_none() {
        dispatcher::pump_kernel();
    }
    Ok(())
}

/// O último leitor acompanha a contagem do bloco antigo e assume o despertar.
fn release_core(pointer: u64, shared: bool) {
    let mut value = read_atomic(pointer);
    if shared && value & HAS_WAITERS == 0 {
        loop {
            let next = if value & ALIGNED_POINTER_MASK == SHARED_REFERENCE_INCREMENT { 0 } else { value - SHARED_REFERENCE_INCREMENT };
            let observed = cas64(pointer, value, next);
            if observed == value {
                return;
            }
            value = observed;
            if value & HAS_WAITERS != 0 {
                break;
            }
        }
    }
    let mut decrement = 1;
    if shared && value & MULTIPLE_SHARED_OWNERS != 0 {
        let last = find_oldest_waiter(value & ALIGNED_POINTER_MASK);
        let before = update_atomic32(last + SHARED_COUNT, |count| count.wrapping_sub(1));
        if (before as i32) - 1 > 0 {
            return;
        }
        decrement += MULTIPLE_SHARED_OWNERS;
    }
    loop {
        let should_wake = value & (HAS_WAITERS | WAKE_IN_PROGRESS) == HAS_WAITERS;
        let next = value - decrement + if should_wake { WAKE_IN_PROGRESS } else { 0 };
        let observed = cas64(pointer, value, next);
        if observed == value {
            if should_wake {
                wake(pointer, next);
            }
            return;
        }
        value = observed;
    }
}

pub fn initialize(pointer: u64) {
    store_atomic(pointer, 0);
}

pub fn acquire_exclusive(pointer: u64, flags: u32) -> Result<(), KernelError> {
    acquire(pointer, false, flags)
}

pub fn acquire_shared(pointer: u64, flags: u32) -> Result<(), KernelError> {
    acquire(pointer, true, flags)
}

pub fn release_exclusive(pointer: u64, flags: u32) -> Result<(), KernelError> {
    validate(flags, 2)?;
    release_core(pointer, false);
    Ok(())
}

pub fn release_shared(pointer: u64, flags: u32) -> Result<(), KernelError> {
    validate(flags, 2)?;
    release_core(pointer, true);
    Ok(())
}

/// Infere o modo pela palavra nativa (export genérico).
pub fn release_any(pointer: u64, flags: u32) -> Result<(), KernelError> {
    validate(flags, 2)?;
    let value = read_atomic(pointer);
    release_core(pointer, value & HAS_WAITERS != 0 || value >= SHARED_REFERENCE_INCREMENT);
    Ok(())
}

/// Exclusivo simples -> um leitor, pela mesma operação atômica nativa.
pub fn convert_exclusive_to_shared(pointer: u64) {
    cas64(pointer, 1, 17);
}

pub fn try_exclusive(pointer: u64, flags: u32) -> Result<bool, KernelError> {
    validate(flags, 1)?;
    Ok(try_acquire(pointer, false))
}

pub fn try_shared(pointer: u64, flags: u32) -> Result<bool, KernelError> {
    validate(flags, 2)?;
    Ok(try_acquire(pointer, true))
}
