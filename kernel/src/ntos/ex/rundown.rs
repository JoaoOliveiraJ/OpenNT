//! EX_RUNDOWN_REF.
//!
//! Referências deslocadas um bit, ou um ponteiro de espera marcado no bit
//! zero. O descritor por CPU ocupa 0x18 bytes (RunRefs, PoolToFree,
//! RunRefSize, Number). Saldos individuais podem ser negativos quando uma
//! thread migra entre aquisição e liberação.

use alloc::vec::Vec;

use crate::hal::cpu;
use crate::ntos::ke::{dispatcher, irql, pcr, smp};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

fn require_irql(maximum: u8) -> Result<(), KernelError> {
    if irql::get_irql() > maximum {
        return Err(KernelError::new("rundown IRQL too high"));
    }
    Ok(())
}

fn cas64(pointer: u64, expected: u64, replacement: u64) -> u64 {
    guest::compare_exchange64(pointer, expected, replacement).unwrap_or_else(|error| panic!("{error}"))
}

fn read_atomic(pointer: u64) -> u64 {
    cas64(pointer, 0, 0)
}

fn exchange(pointer: u64, next: u64) -> u64 {
    let mut expected = read_atomic(pointer);
    loop {
        let observed = cas64(pointer, expected, next);
        if observed == expected {
            return expected;
        }
        expected = observed;
    }
}

fn add(pointer: u64, delta: u64) -> u64 {
    let mut expected = read_atomic(pointer);
    loop {
        let observed = cas64(pointer, expected, expected.wrapping_add(delta));
        if observed == expected {
            return expected;
        }
        expected = observed;
    }
}

/// ExAcquireRundownProtectionEx: só enquanto o bit de encerramento está livre.
pub fn acquire_ex(pointer: u64, count: u32) -> Result<bool, KernelError> {
    require_irql(2)?;
    let delta = count.wrapping_mul(2) as u64;
    let mut expected = read_atomic(pointer);
    while expected & 1 == 0 {
        let observed = cas64(pointer, expected, expected.wrapping_add(delta));
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
    let mut expected = read_atomic(pointer);
    loop {
        if expected & 1 != 0 {
            if expected == 1 {
                return Err(KernelError::new("release after rundown completed"));
            }
            let block = expected & !1;
            let previous = add(block, (count as u64).wrapping_neg());
            if previous == count as u64 {
                // LOCK BTR do caminho lento: encerra a espera ativa (bit 0 de
                // +0x20) ou, se já terminou, acorda o evento.
                let flags = block + 0x20;
                let mut previous_flags = guest::read32(flags);
                loop {
                    let observed = guest::compare_exchange32(flags, previous_flags, previous_flags & !1)?;
                    if observed == previous_flags {
                        break;
                    }
                    previous_flags = observed;
                }
                if previous_flags & 1 == 0 {
                    dispatcher::set_event(block + 8);
                }
            }
            return Ok(());
        }
        let observed = cas64(pointer, expected, expected.wrapping_sub(delta));
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

fn allocate_wait_block() -> Result<u64, KernelError> {
    let block = guest::alloc_bytes(0x28);
    if block == 0 {
        return Err(KernelError::new("rundown wait block allocation failed"));
    }
    guest::write64(block, 0);
    dispatcher::initialize_event(block + 8, 1, false);
    guest::write64(block + 0x20, 0);
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
            exchange(slot, 1);
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
            if self.slots.iter().any(|&slot| read_atomic(slot) == self.observer) {
                return false;
            }
            self.done = true;
            return true;
        }
        if dispatcher::try_wait_objects(&[self.block + 8], 1).is_none() {
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
    if !cache_aware {
        let mut value = cas64(request.slots[0], 0, 1);
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
            guest::write64(block, value >> 1);
            let observed = cas64(request.slots[0], value, block | 1);
            if observed == value {
                request.block = block;
                break;
            }
            value = observed;
            if value & 1 != 0 {
                guest::free_bytes(block);
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
    let first = read_atomic(request.slots[0]);
    if first & 1 != 0 {
        request.observer = if first > 1 { first } else { 0 };
        request.done = first == 1;
        return Ok(request);
    }
    let block = allocate_wait_block()?;
    let mut value = first;
    loop {
        let observed = cas64(request.slots[0], value, block | 1);
        if observed == value {
            break;
        }
        value = observed;
        if value & 1 != 0 {
            guest::free_bytes(block);
            request.observer = if value > 1 { value } else { 0 };
            request.done = value == 1;
            return Ok(request);
        }
    }
    // Agrega os saldos anteriores de todos os slots como inteiro com sinal.
    let mut total = value;
    for &slot in &request.slots[1..] {
        total = total.wrapping_add(exchange(slot, block | 1));
    }
    let total = (total as i64) >> 1;
    request.block = block;
    let previous = add(block, total as u64) as i64;
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

fn current_processor_number() -> u32 {
    guest::read32(pcr::get_pcr_address() + 0x1A4)
}

fn cache_reference_slots(pointer: u64) -> Result<Vec<u64>, KernelError> {
    let base = guest::read64(pointer);
    let stride = guest::read32(pointer + 0x10);
    let count = guest::read32(pointer + 0x14);
    if base == 0 || stride < 8 || stride & 7 != 0 || count == 0 {
        return Err(KernelError::new("invalid cache-aware rundown descriptor"));
    }
    Ok((0..count as u64).map(|index| base + index * stride as u64).collect())
}

fn current_cache_slot(pointer: u64) -> Result<u64, KernelError> {
    let count = guest::read32(pointer + 0x14);
    if count == 0 {
        return Err(KernelError::new("uninitialized cache-aware rundown"));
    }
    Ok(guest::read64(pointer) + ((current_processor_number() % count) * guest::read32(pointer + 0x10)) as u64)
}

/// ExSizeOfRundownProtectionCacheAware.
pub fn size_cache() -> u64 {
    let count = smp::online_cpu_count() as u64;
    if count == 1 { 32 } else { 24 + (count + 1) * cache_line_alignment() as u64 }
}

/// ExInitializeRundownProtectionCacheAware: o marcador 0xBADCA11 impede
/// liberar pelo pool um buffer que pertence ao chamador.
pub fn initialize_cache(pointer: u64, buffer_length: u32) -> Result<(), KernelError> {
    require_irql(2)?;
    let capacity = buffer_length.wrapping_sub(24);
    let stride = if capacity == 8 { 8 } else { cache_line_alignment() };
    let count = if capacity == 8 { 1 } else { (capacity / stride) as i64 - 1 };
    if count < 1 {
        return Err(KernelError::new("cache-aware rundown buffer is too small"));
    }
    let array = if capacity == 8 { pointer + 24 } else { (pointer + 24 + stride as u64 - 1) & !(stride as u64 - 1) };
    guest::write64(pointer, array);
    guest::write64(pointer + 8, 0xBADCA11);
    guest::write32(pointer + 0x10, stride);
    guest::write32(pointer + 0x14, count as u32);
    for index in 0..count as u64 {
        guest::write64(array + index * stride as u64, 0);
    }
    Ok(())
}

/// ExAllocateCacheAwareRundownProtection (tipo e tag de pool ignorados).
pub fn allocate_cache(_pool_type: u32, _pool_tag: u32) -> Result<u64, KernelError> {
    require_irql(2)?;
    let pointer = guest::alloc_bytes(24);
    if pointer == 0 {
        return Ok(0);
    }
    let count = smp::online_cpu_count() as u64;
    let stride = if count == 1 { 8 } else { cache_line_alignment() as u64 };
    let allocation = guest::alloc_bytes(count * stride + if count == 1 { 0 } else { stride - 1 });
    if allocation == 0 {
        guest::free_bytes(pointer);
        return Ok(0);
    }
    let array = (allocation + stride - 1) & !(stride - 1);
    guest::write64(pointer, array);
    guest::write64(pointer + 8, allocation);
    guest::write32(pointer + 0x10, stride as u32);
    guest::write32(pointer + 0x14, count as u32);
    for index in 0..count {
        guest::write64(array + index * stride, 0);
    }
    Ok(pointer)
}

pub fn free_cache(pointer: u64) -> Result<(), KernelError> {
    require_irql(2)?;
    let allocation = guest::read64(pointer + 8);
    if allocation == 0xBADCA11 {
        return Err(KernelError::new("caller-owned cache-aware rundown cannot be pool-freed"));
    }
    guest::free_bytes(allocation);
    guest::free_bytes(pointer);
    Ok(())
}

fn set(pointer: u64, value: u64) -> Result<(), KernelError> {
    require_irql(2)?;
    exchange(pointer, value);
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
        exchange(slot, value);
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
