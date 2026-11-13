//! EX_RUNDOWN_REF.
//!
//! Referências deslocadas um bit, ou um ponteiro de espera marcado no bit
//! zero. O descritor por CPU ocupa 0x18 bytes (RunRefs, PoolToFree,
//! RunRefSize, Number). Saldos individuais podem ser negativos quando uma
//! thread migra entre aquisição e liberação.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering::SeqCst};

use crate::hal::cpu;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{ExRundownRef, ExRundownRefCacheAware, Kevent, Kpcr};
use crate::ntos::ke::{dispatcher, irql, pcr, smp};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

/// Bloco de espera publicado na palavra (marcado no bit 0): o saldo de
/// referências, o evento do encerramento e a flag de espera ativa (bit 0).
#[repr(C)]
struct WaitBlock {
    count: Field<u64>,
    wake_event: Kevent,
    flags: Field<u32>,
    _pad: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for WaitBlock {}

const _: () = {
    assert!(core::mem::size_of::<WaitBlock>() == 0x28);
    assert!(core::mem::offset_of!(WaitBlock, wake_event) == 0x8);
    assert!(core::mem::offset_of!(WaitBlock, flags) == 0x20);
};

/// Marcador de PoolToFree: o buffer pertence ao chamador.
const CALLER_OWNED: u64 = 0xBADCA11;

fn require_irql(maximum: u8) -> Result<(), KernelError> {
    if irql::get_irql() > maximum {
        return Err(KernelError::new("rundown IRQL too high"));
    }
    Ok(())
}

/// A palavra Count de um EX_RUNDOWN_REF (simples ou slot por CPU).
fn word(pointer: u64) -> &'static AtomicU64 {
    // SAFETY: os exports recebem um PEX_RUNDOWN_REF; os slots vêm de RunRefs.
    unsafe { ExRundownRef::at(pointer) }.count.atomic()
}

fn wait_block(address: u64) -> &'static WaitBlock {
    // SAFETY: a palavra só publica blocos alocados por `allocate_wait_block`.
    unsafe { WaitBlock::at(address) }
}

fn cache_aware(pointer: u64) -> &'static ExRundownRefCacheAware {
    // SAFETY: os exports recebem um PEX_RUNDOWN_REF_CACHE_AWARE.
    unsafe { ExRundownRefCacheAware::at(pointer) }
}

fn cas(cell: &AtomicU64, expected: u64, replacement: u64) -> u64 {
    match cell.compare_exchange(expected, replacement, SeqCst, SeqCst) {
        Ok(value) | Err(value) => value,
    }
}

/// ExAcquireRundownProtectionEx: só enquanto o bit de encerramento está livre.
pub fn acquire_ex(pointer: u64, count: u32) -> Result<bool, KernelError> {
    require_irql(2)?;
    let delta = count.wrapping_mul(2) as u64;
    let word = word(pointer);
    let mut expected = word.load(SeqCst);
    while expected & 1 == 0 {
        let observed = cas(word, expected, expected.wrapping_add(delta));
        if observed == expected {
            return Ok(true);
        }
        expected = observed;
    }
    Ok(false)
}

/// ExReleaseRundownProtectionEx: na palavra ativa ou no bloco publicado; a
/// última referência sinaliza o evento do bloco.
pub fn release_ex(pointer: u64, count: u32) -> Result<(), KernelError> {
    require_irql(2)?;
    let delta = count.wrapping_mul(2) as u64;
    let word = word(pointer);
    let mut expected = word.load(SeqCst);
    loop {
        if expected & 1 != 0 {
            if expected == 1 {
                return Err(KernelError::new("release after rundown completed"));
            }
            let block = wait_block(expected & !1);
            let previous = block.count.atomic().fetch_sub(count as u64, SeqCst);
            if previous == count as u64 {
                // LOCK BTR do caminho lento: encerra a espera ativa ou, se já
                // terminou, acorda o evento.
                let previous_flags = block.flags.atomic().fetch_and(!1, SeqCst);
                if previous_flags & 1 == 0 {
                    dispatcher::set_event(block.wake_event.address());
                }
            }
            return Ok(());
        }
        let observed = cas(word, expected, expected.wrapping_sub(delta));
        if observed == expected {
            return Ok(());
        }
        expected = observed;
    }
}

pub fn acquire(pointer: u64) -> Result<bool, KernelError> {
    acquire_ex(pointer, 1)
}

pub fn release(pointer: u64) -> Result<(), KernelError> {
    release_ex(pointer, 1)
}

fn allocate_wait_block() -> Result<&'static WaitBlock, KernelError> {
    let allocation = guest::alloc_bytes(WaitBlock::SIZE);
    if allocation == 0 {
        return Err(KernelError::new("rundown wait block allocation failed"));
    }
    let block = wait_block(allocation);
    block.count.set(0);
    dispatcher::initialize_event(block.wake_event.address(), 1, false);
    block.flags.set(0);
    block._pad.set(0);
    Ok(block)
}

/// Encerramento em andamento (simples ou por CPU).
pub struct RundownRequest {
    slots: Vec<u64>,
    block: u64,
    done: bool,
    observer: u64,
}

impl RundownRequest {
    fn finish(&mut self) {
        for &slot in &self.slots {
            word(slot).swap(1, SeqCst);
        }
        if self.block != 0 {
            guest::free_bytes(self.block);
        }
        self.block = 0;
        self.done = true;
    }

    /// `true` quando o encerramento terminou. Só o dono acessa e libera o
    /// bloco; observadores acompanham a palavra publicada.
    pub fn poll(&mut self) -> bool {
        if self.done {
            return true;
        }
        if self.observer != 0 {
            if self.slots.iter().any(|&slot| word(slot).load(SeqCst) == self.observer) {
                return false;
            }
            self.done = true;
            return true;
        }
        if dispatcher::try_wait_objects(&[wait_block(self.block).wake_event.address()], 1).is_none() {
            return false;
        }
        self.finish();
        true
    }
}

/// Inicia o encerramento. Uma única operação possui o bloco de espera.
pub fn begin(pointer: u64, cache_aware: bool) -> Result<RundownRequest, KernelError> {
    require_irql(1)?;
    let slots = if cache_aware { cache_reference_slots(pointer)? } else { alloc::vec![pointer] };
    let mut request = RundownRequest { slots, block: 0, done: false, observer: 0 };
    let first = word(request.slots[0]);
    if !cache_aware {
        let mut value = cas(first, 0, 1);
        if value <= 1 {
            request.done = true;
            return Ok(request);
        }
        if value & 1 != 0 {
            request.observer = value;
            return Ok(request);
        }
        let block = allocate_wait_block()?;
        loop {
            block.count.set(value >> 1);
            let observed = cas(first, value, block.address() | 1);
            if observed == value {
                request.block = block.address();
                break;
            }
            value = observed;
            if value & 1 != 0 {
                guest::free_bytes(block.address());
                request.observer = if value > 1 { value } else { 0 };
                request.done = value == 1;
                return Ok(request);
            }
        }
        // A última referência saiu antes da publicação: conclui agora.
        if value == 0 {
            request.finish();
        }
        return Ok(request);
    }
    // O slot zero arbitra quem publica o bloco do encerramento por CPU.
    let current = first.load(SeqCst);
    if current & 1 != 0 {
        request.observer = if current > 1 { current } else { 0 };
        request.done = current == 1;
        return Ok(request);
    }
    let block = allocate_wait_block()?;
    let mut value = current;
    loop {
        let observed = cas(first, value, block.address() | 1);
        if observed == value {
            break;
        }
        value = observed;
        if value & 1 != 0 {
            guest::free_bytes(block.address());
            request.observer = if value > 1 { value } else { 0 };
            request.done = value == 1;
            return Ok(request);
        }
    }
    // Agrega os saldos anteriores de todos os slots como inteiro com sinal.
    let mut total = value;
    for &slot in &request.slots[1..] {
        total = total.wrapping_add(word(slot).swap(block.address() | 1, SeqCst));
    }
    let total = (total as i64) >> 1;
    request.block = block.address();
    let previous = block.count.atomic().fetch_add(total as u64, SeqCst) as i64;
    if previous + total == 0 {
        request.finish();
    }
    Ok(request)
}

/// ExWaitForRundownProtectionRelease: avança o dispatcher entre consultas.
pub fn wait_ex(pointer: u64, cache_aware: bool) -> Result<(), KernelError> {
    let mut request = begin(pointer, cache_aware)?;
    while !request.poll() {
        dispatcher::pump_kernel();
    }
    Ok(())
}

pub fn wait(pointer: u64) -> Result<(), KernelError> {
    wait_ex(pointer, false)
}

/// Linha de cache de CPUID, mínimo de 64 bytes.
fn cache_line_alignment() -> u32 {
    (((cpu::cpuid(1)[1] >> 8) & 255) * 8).max(64)
}

/// KeGetCurrentProcessorNumberEx: KPCR->Prcb.Number.
fn current_processor_number() -> u32 {
    // SAFETY: o KPCR da CPU corrente.
    unsafe { Kpcr::at(pcr::get_pcr_address()) }.prcb.number.get()
}

fn cache_reference_slots(pointer: u64) -> Result<Vec<u64>, KernelError> {
    let descriptor = cache_aware(pointer);
    let base = descriptor.run_refs.get();
    let stride = descriptor.run_ref_size.get();
    let count = descriptor.number.get();
    if base == 0 || stride < 8 || stride & 7 != 0 || count == 0 {
        return Err(KernelError::new("invalid cache-aware rundown descriptor"));
    }
    Ok((0..count as u64).map(|index| base + index * stride as u64).collect())
}

fn current_cache_slot(pointer: u64) -> Result<u64, KernelError> {
    let descriptor = cache_aware(pointer);
    let count = descriptor.number.get();
    if count == 0 {
        return Err(KernelError::new("uninitialized cache-aware rundown"));
    }
    Ok(descriptor.run_refs.get() + ((current_processor_number() % count) * descriptor.run_ref_size.get()) as u64)
}

/// ExSizeOfRundownProtectionCacheAware.
pub fn size_cache() -> u64 {
    let count = smp::online_cpu_count() as u64;
    let header = ExRundownRefCacheAware::SIZE;
    if count == 1 { header + ExRundownRef::SIZE } else { header + (count + 1) * cache_line_alignment() as u64 }
}

fn clear_slots(array: u64, stride: u64, count: u64) {
    for index in 0..count {
        word(array + index * stride).store(0, SeqCst);
    }
}

/// ExInitializeRundownProtectionCacheAware: o marcador 0xBADCA11 impede
/// liberar pelo pool um buffer que pertence ao chamador.
pub fn initialize_cache(pointer: u64, buffer_length: u32) -> Result<(), KernelError> {
    require_irql(2)?;
    let header = ExRundownRefCacheAware::SIZE;
    let capacity = buffer_length.wrapping_sub(header as u32);
    let single = capacity == ExRundownRef::SIZE as u32;
    let stride = if single { ExRundownRef::SIZE as u32 } else { cache_line_alignment() };
    let count = if single { 1 } else { (capacity / stride) as i64 - 1 };
    if count < 1 {
        return Err(KernelError::new("cache-aware rundown buffer is too small"));
    }
    let array = if single { pointer + header } else { (pointer + header + stride as u64 - 1) & !(stride as u64 - 1) };
    let descriptor = cache_aware(pointer);
    descriptor.run_refs.set(array);
    descriptor.pool_to_free.set(CALLER_OWNED);
    descriptor.run_ref_size.set(stride);
    descriptor.number.set(count as u32);
    clear_slots(array, stride as u64, count as u64);
    Ok(())
}

/// ExAllocateCacheAwareRundownProtection (tipo e tag de pool ignorados).
pub fn allocate_cache(_pool_type: u32, _pool_tag: u32) -> Result<u64, KernelError> {
    require_irql(2)?;
    let pointer = guest::alloc_bytes(ExRundownRefCacheAware::SIZE);
    if pointer == 0 {
        return Ok(0);
    }
    let count = smp::online_cpu_count() as u64;
    let stride = if count == 1 { ExRundownRef::SIZE } else { cache_line_alignment() as u64 };
    let allocation = guest::alloc_bytes(count * stride + if count == 1 { 0 } else { stride - 1 });
    if allocation == 0 {
        guest::free_bytes(pointer);
        return Ok(0);
    }
    let array = (allocation + stride - 1) & !(stride - 1);
    let descriptor = cache_aware(pointer);
    descriptor.run_refs.set(array);
    descriptor.pool_to_free.set(allocation);
    descriptor.run_ref_size.set(stride as u32);
    descriptor.number.set(count as u32);
    clear_slots(array, stride, count);
    Ok(pointer)
}

pub fn free_cache(pointer: u64) -> Result<(), KernelError> {
    require_irql(2)?;
    let allocation = cache_aware(pointer).pool_to_free.get();
    if allocation == CALLER_OWNED {
        return Err(KernelError::new("caller-owned cache-aware rundown cannot be pool-freed"));
    }
    guest::free_bytes(allocation);
    guest::free_bytes(pointer);
    Ok(())
}

fn set(pointer: u64, value: u64) -> Result<(), KernelError> {
    require_irql(2)?;
    word(pointer).swap(value, SeqCst);
    Ok(())
}

pub fn initialize(pointer: u64) -> Result<(), KernelError> {
    set(pointer, 0)
}

pub fn reinitialize(pointer: u64) -> Result<(), KernelError> {
    set(pointer, 0)
}

pub fn completed(pointer: u64) -> Result<(), KernelError> {
    set(pointer, 1)
}

fn set_cache(pointer: u64, value: u64) -> Result<(), KernelError> {
    require_irql(2)?;
    for slot in cache_reference_slots(pointer)? {
        word(slot).swap(value, SeqCst);
    }
    Ok(())
}

pub fn acquire_cache(pointer: u64, count: u32) -> Result<bool, KernelError> {
    acquire_ex(current_cache_slot(pointer)?, count)
}

pub fn release_cache(pointer: u64, count: u32) -> Result<(), KernelError> {
    release_ex(current_cache_slot(pointer)?, count)
}

pub fn wait_cache(pointer: u64) -> Result<(), KernelError> {
    wait_ex(pointer, true)
}

pub fn reinitialize_cache(pointer: u64) -> Result<(), KernelError> {
    set_cache(pointer, 0)
}

pub fn completed_cache(pointer: u64) -> Result<(), KernelError> {
    set_cache(pointer, 1)
}
