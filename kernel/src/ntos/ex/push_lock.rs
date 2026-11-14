//! EX_PUSH_LOCK.
//!
//! A palavra nativa e blocos de espera de 0x40 bytes no convidado. Cada
//! aguardante possui sua alocação até ser desligado e retomar. Os caminhos
//! rápidos inline dos drivers observam os mesmos bits e ligações.

use core::sync::atomic::{AtomicU64, Ordering::SeqCst};

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{ExPushLock, Kevent};
use crate::ntos::ke::{dispatcher, irql};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const LOCKED: u64 = 1;
const HAS_WAITERS: u64 = 2;
const WAKE_IN_PROGRESS: u64 = 4;
const MULTIPLE_SHARED_OWNERS: u64 = 8;
const SHARED_REFERENCE_INCREMENT: u64 = 16;
const ALIGNED_POINTER_MASK: u64 = !15;

/// Bloco de espera do push lock (layout nativo, 0x40 bytes): o evento de
/// despertar, os vínculos da cadeia, a contagem de leitores do bloco mais
/// antigo e as flags (bit 0 = escritor, bit 1 = espera ativa).
#[repr(C)]
pub(super) struct WaitBlock {
    pub(super) wake_event: Kevent,
    /// -> bloco mais antigo seguinte da cadeia.
    pub(super) next: Field<u64>,
    /// -> bloco mais antigo (atalho na cabeça).
    pub(super) last: Field<u64>,
    /// -> bloco mais novo (vínculo de retorno).
    pub(super) previous: Field<u64>,
    pub(super) share_count: Field<u32>,
    pub(super) flags: Field<u32>,
    spare: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for WaitBlock {}

const _: () = {
    assert!(core::mem::size_of::<WaitBlock>() == 0x40);
    assert!(core::mem::offset_of!(WaitBlock, next) == 0x18);
    assert!(core::mem::offset_of!(WaitBlock, last) == 0x20);
    assert!(core::mem::offset_of!(WaitBlock, previous) == 0x28);
    assert!(core::mem::offset_of!(WaitBlock, share_count) == 0x30);
    assert!(core::mem::offset_of!(WaitBlock, flags) == 0x34);
};

/// O bloco de espera em `address` (vínculo lido da palavra ou da cadeia).
pub(super) fn wait_block(address: u64) -> &'static WaitBlock {
    // SAFETY: a palavra e a cadeia só guardam blocos de espera publicados.
    unsafe { WaitBlock::at(address) }
}

/// A palavra Value do EX_PUSH_LOCK do chamador.
fn word(pointer: u64) -> &'static AtomicU64 {
    // SAFETY: os exports recebem um PEX_PUSH_LOCK do chamador.
    unsafe { ExPushLock::at(pointer) }.value.atomic()
}

/// LOCK CMPXCHG: devolve o valor observado.
fn cas(cell: &AtomicU64, expected: u64, replacement: u64) -> u64 {
    match cell.compare_exchange(expected, replacement, SeqCst, SeqCst) {
        Ok(value) | Err(value) => value,
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
    let mut cursor = wait_block(head);
    let mut last = cursor.last.atomic().load(SeqCst);
    while last == 0 {
        let newer = cursor.address();
        cursor = wait_block(cursor.next.atomic().load(SeqCst));
        cursor.previous.atomic().store(newer, SeqCst);
        last = cursor.last.atomic().load(SeqCst);
    }
    if cursor.address() != head {
        wait_block(head).last.atomic().store(last, SeqCst);
    }
    last
}

/// Sinaliza o evento só quando o aguardante já saiu da fase de espera ativa.
fn signal_chain(mut block: u64) {
    while block != 0 {
        let waiter = wait_block(block);
        let next = waiter.previous.atomic().load(SeqCst);
        if waiter.flags.atomic().fetch_and(!2, SeqCst) & 2 == 0 {
            dispatcher::set_event(waiter.wake_event.address());
        }
        block = next;
    }
}

fn wake(word: &AtomicU64, mut value: u64) {
    loop {
        if value & LOCKED != 0 {
            let observed = cas(word, value, value & !WAKE_IN_PROGRESS);
            if observed == value {
                return;
            }
            value = observed;
            continue;
        }
        let head = value & ALIGNED_POINTER_MASK;
        let last = find_oldest_waiter(head);
        let oldest = wait_block(last);
        let newer = oldest.previous.atomic().load(SeqCst);
        // O escritor mais antigo acorda sozinho.
        if oldest.flags.get() & 1 != 0 && newer != 0 {
            wait_block(head).last.atomic().store(newer, SeqCst);
            oldest.previous.atomic().store(0, SeqCst);
            word.fetch_and(!WAKE_IN_PROGRESS, SeqCst);
            signal_chain(last);
            return;
        }
        let observed = cas(word, value, 0);
        if observed == value {
            signal_chain(last);
            return;
        }
        value = observed;
    }
}

fn update_waiter_links(word: &AtomicU64, mut value: u64) {
    loop {
        if value & LOCKED == 0 {
            wake(word, value);
            return;
        }
        find_oldest_waiter(value & ALIGNED_POINTER_MASK);
        let observed = cas(word, value, value & !WAKE_IN_PROGRESS);
        if observed == value {
            return;
        }
        value = observed;
    }
}

/// Aquisição sem bloco de espera.
fn try_acquire(word: &AtomicU64, shared: bool) -> bool {
    let mut value = word.load(SeqCst);
    loop {
        if value & LOCKED != 0 && (!shared || value & HAS_WAITERS != 0 || value & ALIGNED_POINTER_MASK == 0) {
            return false;
        }
        let next = (value | LOCKED) + if shared && value & HAS_WAITERS == 0 { SHARED_REFERENCE_INCREMENT } else { 0 };
        let observed = cas(word, value, next);
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
        let word = word(self.pointer);
        if self.queued {
            if !self.parked {
                self.parked = wait_block(self.allocation).flags.atomic().fetch_and(!2, SeqCst) & 2 != 0;
            }
            if self.parked && dispatcher::try_wait_objects(&[self.allocation], 1).is_none() {
                return Ok(None);
            }
            self.queued = false;
            self.parked = false;
        }
        loop {
            if try_acquire(word, self.shared) {
                if self.allocation != 0 {
                    guest::free_bytes(self.allocation);
                }
                self.allocation = 0;
                return Ok(Some(()));
            }
            if self.allocation == 0 {
                self.allocation = guest::alloc_bytes(WaitBlock::SIZE);
                if self.allocation == 0 {
                    return Err(KernelError::new("EX_PUSH_LOCK wait block allocation failed"));
                }
            }
            let block = wait_block(self.allocation);
            // Uma liberação entre as duas leituras exige nova tentativa.
            let value = word.load(SeqCst);
            if value & LOCKED == 0 || (self.shared && value & HAS_WAITERS == 0 && value & ALIGNED_POINTER_MASK != 0) {
                continue;
            }
            dispatcher::initialize_event(block.wake_event.address(), 1, false);
            block.flags.set(if self.shared { 2 } else { 3 });
            block.previous.atomic().store(0, SeqCst);
            block.spare.atomic().store(0, SeqCst);
            let next = if value & HAS_WAITERS != 0 {
                block.next.atomic().store(value & ALIGNED_POINTER_MASK, SeqCst);
                block.last.atomic().store(0, SeqCst);
                block.share_count.set(0xFFFF_FFFF);
                block.address() | LOCKED | HAS_WAITERS | WAKE_IN_PROGRESS | (value & MULTIPLE_SHARED_OWNERS)
            } else {
                block.next.atomic().store(0, SeqCst);
                block.last.atomic().store(block.address(), SeqCst);
                let owners = (value >> 4) as u32;
                block.share_count.set(if owners != 0 { owners } else { 0xFFFF_FFFE });
                block.address() | LOCKED | HAS_WAITERS | if owners > 1 { MULTIPLE_SHARED_OWNERS } else { 0 }
            };
            if cas(word, value, next) != value {
                continue;
            }
            self.queued = true;
            if value & HAS_WAITERS != 0 && value & WAKE_IN_PROGRESS == 0 {
                update_waiter_links(word, next);
            }
            self.parked = block.flags.atomic().fetch_and(!2, SeqCst) & 2 != 0;
            if self.parked && dispatcher::try_wait_objects(&[block.address()], 1).is_none() {
                return Ok(None);
            }
            self.queued = false;
            self.parked = false;
        }
    }
}

/// Numa syscall a thread bloqueia até a posse; fora dela o dispatcher avança
/// entre consultas.
fn acquire(pointer: u64, shared: bool, flags: u32) -> Result<(), KernelError> {
    let mut request = begin(pointer, shared, flags)?;
    crate::ntos::ke::context_switch::acquire_until(|| request.poll(), dispatcher::pump_kernel).map(|_| ())
}

/// O último leitor acompanha a contagem do bloco antigo e assume o despertar.
fn release_core(word: &AtomicU64, shared: bool) {
    let mut value = word.load(SeqCst);
    if shared && value & HAS_WAITERS == 0 {
        loop {
            let next = if value & ALIGNED_POINTER_MASK == SHARED_REFERENCE_INCREMENT { 0 } else { value - SHARED_REFERENCE_INCREMENT };
            let observed = cas(word, value, next);
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
        let before = wait_block(last).share_count.atomic().fetch_sub(1, SeqCst);
        if (before as i32) - 1 > 0 {
            return;
        }
        decrement += MULTIPLE_SHARED_OWNERS;
    }
    loop {
        let should_wake = value & (HAS_WAITERS | WAKE_IN_PROGRESS) == HAS_WAITERS;
        let next = value - decrement + if should_wake { WAKE_IN_PROGRESS } else { 0 };
        let observed = cas(word, value, next);
        if observed == value {
            if should_wake {
                wake(word, next);
            }
            return;
        }
        value = observed;
    }
}

pub fn initialize(pointer: u64) {
    word(pointer).store(0, SeqCst);
}

pub fn acquire_exclusive(pointer: u64, flags: u32) -> Result<(), KernelError> {
    acquire(pointer, false, flags)
}

pub fn acquire_shared(pointer: u64, flags: u32) -> Result<(), KernelError> {
    acquire(pointer, true, flags)
}

pub fn release_exclusive(pointer: u64, flags: u32) -> Result<(), KernelError> {
    validate(flags, 2)?;
    release_core(word(pointer), false);
    Ok(())
}

pub fn release_shared(pointer: u64, flags: u32) -> Result<(), KernelError> {
    validate(flags, 2)?;
    release_core(word(pointer), true);
    Ok(())
}

/// Infere o modo pela palavra nativa (export genérico).
pub fn release_any(pointer: u64, flags: u32) -> Result<(), KernelError> {
    validate(flags, 2)?;
    let word = word(pointer);
    let value = word.load(SeqCst);
    release_core(word, value & HAS_WAITERS != 0 || value >= SHARED_REFERENCE_INCREMENT);
    Ok(())
}

/// Exclusivo simples -> um leitor, pela mesma operação atômica nativa.
pub fn convert_exclusive_to_shared(pointer: u64) {
    cas(word(pointer), 1, 17);
}

/// ExTryConvertPushLockSharedToExclusiveEx(PushLock, Flags): flags além de
/// 3 param o sistema (bugcheck 0x152, Flags, PushLock); senão um LOCK
/// CMPXCHG de "um leitor" (LOCKED | um incremento compartilhado) para
/// "exclusivo". Com outro leitor, aguardantes ou um escritor, nada muda.
pub fn try_convert_shared_to_exclusive(pointer: u64, flags: u32) -> bool {
    if flags & !3 != 0 {
        crate::ntos::ke::bugcheck::bug_check_ex(0x152, flags as u64, pointer, 0, 0);
    }
    let single_reader = LOCKED | SHARED_REFERENCE_INCREMENT;
    cas(word(pointer), single_reader, LOCKED) == single_reader
}

pub fn try_exclusive(pointer: u64, flags: u32) -> Result<bool, KernelError> {
    validate(flags, 1)?;
    Ok(try_acquire(word(pointer), false))
}

pub fn try_shared(pointer: u64, flags: u32) -> Result<bool, KernelError> {
    validate(flags, 2)?;
    Ok(try_acquire(word(pointer), true))
}

// ---- EX_PUSH_LOCK_CACHE_AWARE --------------------------------------------------
//
// Derivado do ntoskrnl 10.0.19045:
//   ExAllocateCacheAwarePushLock(Flags)        RVA 0x3c8090
//     tabela = ExAllocatePoolWithTag(Flags&1 ? NonPagedPoolNx : PagedPool, 0x100, 'Plcp')
//     KeNumberNodes == 1 (um nó no OpenNT) -> um bloco de 0x1000 ('Plcl'):
//     slot i = bloco + i*0x80 (EX_PUSH_LOCK_CACHE_AWARE_PADDED): Lock = 0,
//     Single = 1, ParentLock = tabela; tabela.Locks[i] = slot. Falha -> NULL.
//   ExAcquireCacheAwarePushLockExclusive       RVA 0x273160 -> ExfAcquire...ExclusiveEx
//     0x2731b0: trava Locks[0..32] exclusivos, em ordem.
//   ExReleaseCacheAwarePushLockExclusive       RVA 0x271a50: solta Locks[0..32].
//   ExAcquireCacheAwarePushLockSharedEx(L, F)  RVA 0x2caae0: F & ~3 -> bugcheck 0x152;
//     trava compartilhado Locks[Prcb.Number & 0x1f] e DEVOLVE esse slot.
//   ExReleaseCacheAwarePushLockSharedEx(P, F)  RVA 0x2caca0: solta o slot P.
// O KeAbPreAcquire/KeAbPostRelease (AutoBoost) não existe no OpenNT.

use crate::ntos::inc::types::extra_fs_fat::{ExPushLockCacheAware, ExPushLockCacheAwarePadded};
use crate::ntos::inc::types::Kpcr;

pub const CACHE_AWARE_SLOT_COUNT: usize = 32;
const CACHE_AWARE_TAG_TABLE: u32 = 0x7063_6C50; // 'Plcp'
const CACHE_AWARE_TAG_BLOCK: u32 = 0x6C63_6C50; // 'Plcl'

/// EX_PUSH_LOCK flags inválidos: KeBugCheckEx(0x152, Flags, Lock, 0, 0).
fn cache_aware_check_flags(lock: u64, flags: u32) {
    if flags & !3 != 0 {
        crate::ntos::ke::bugcheck::bug_check_ex(0x152, flags as u64, lock, 0, 0);
    }
}

/// ExAllocateCacheAwarePushLock: devolve a tabela (PEX_PUSH_LOCK_CACHE_AWARE) ou 0.
pub fn allocate_cache_aware(flags: u32) -> Result<u64, KernelError> {
    let pool_type = if flags & 1 != 0 { 0x200 } else { 1 }; // NonPagedPoolNx : PagedPool
    let table_bytes = ExPushLockCacheAware::SIZE;
    let slot_bytes = ExPushLockCacheAwarePadded::SIZE;
    let address = crate::ntos::ex::pool_allocation::allocate_tagged(pool_type, table_bytes, CACHE_AWARE_TAG_TABLE)?;
    if address == 0 {
        return Ok(0);
    }
    guest::write_bytes(address, &[0u8; ExPushLockCacheAware::SIZE as usize]);
    let block = crate::ntos::ex::pool_allocation::allocate_tagged(pool_type, slot_bytes * CACHE_AWARE_SLOT_COUNT as u64, CACHE_AWARE_TAG_BLOCK)?;
    if block == 0 {
        crate::ntos::mm::kernel_pool::free(address, Some(CACHE_AWARE_TAG_TABLE))?;
        return Ok(0);
    }
    guest::write_bytes(block, &alloc::vec![0u8; (slot_bytes * CACHE_AWARE_SLOT_COUNT as u64) as usize]);
    // SAFETY: a tabela e o bloco acabaram de ser alocados com esses tamanhos.
    let table = unsafe { ExPushLockCacheAware::at(address) };
    let slots = unsafe { ExPushLockCacheAwarePadded::array_at(block, CACHE_AWARE_SLOT_COUNT) };
    for (cell, slot) in table.locks.iter().zip(slots) {
        slot.lock.value.set(0);
        slot.single.set(1);
        slot.parent_lock.set(address);
        cell.set(slot.address());
    }
    Ok(address)
}

/// ExAcquireCacheAwarePushLockExclusive: todos os slots, em ordem.
pub fn acquire_cache_aware_exclusive(table: &ExPushLockCacheAware) -> Result<(), KernelError> {
    for cell in &table.locks {
        acquire_exclusive(cell.get(), 0)?;
    }
    Ok(())
}

/// ExReleaseCacheAwarePushLockExclusive.
pub fn release_cache_aware_exclusive(table: &ExPushLockCacheAware) -> Result<(), KernelError> {
    for cell in &table.locks {
        release_exclusive(cell.get(), 0)?;
    }
    Ok(())
}

/// ExAcquireCacheAwarePushLockSharedEx: o slot da CPU (Prcb.Number & 31).
pub fn acquire_cache_aware_shared(table: &ExPushLockCacheAware, flags: u32) -> Result<u64, KernelError> {
    cache_aware_check_flags(table.address(), flags);
    // SAFETY: a KPCR da CPU corrente fica mapeada desde o boot.
    let processor = unsafe { Kpcr::at(crate::ntos::ke::pcr::get_pcr_address()) }.prcb.number.get() as usize;
    let lock = table.locks[processor & (CACHE_AWARE_SLOT_COUNT - 1)].get();
    acquire_shared(lock, flags)?;
    Ok(lock)
}

/// ExReleaseCacheAwarePushLockSharedEx: o slot devolvido pela aquisição.
pub fn release_cache_aware_shared(lock: u64, flags: u32) -> Result<(), KernelError> {
    cache_aware_check_flags(lock, flags);
    release_shared(lock, flags)
}
