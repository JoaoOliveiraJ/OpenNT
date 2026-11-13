//! Alocação de pool com prioridade pela ABI NT — `system32/ntos/ex/pool-allocation.js`.
//!
//! O provedor de memória mantém armazenamento, paginação e propriedade;
//! pedidos inválidos provocam bugcheck 0xC2 e a falha com RAISE levanta
//! STATUS_INSUFFICIENT_RESOURCES. Também as variantes ExAllocatePool2/Zero/
//! Uninitialized e a liberação (ExFreePool*), que encaminha ao pool dono.

use crate::ntos::ke::{bugcheck, irql};
use crate::ntos::mm::data_pool;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::rtl::KernelError;

const RAISE_ON_ALLOCATION_FAILURE: u32 = 0x10;
const COLD_ALLOCATION: u32 = 0x100;
/// POOL_ZERO_ALLOCATION (ExAllocatePoolZero); o VGK pede 0x600.
const ZERO_ALLOCATION: u32 = 0x400;

/// Registra o motivo e chama KeBugCheckEx(0xC2, 0x99, tipo, bytes, tag).
fn reject(message: &str, pool_type: u32, bytes: u64, tag: u32) -> ! {
    debug_print!("[pool] {}", message);
    bugcheck::bug_check_ex(0xC2, 0x99, pool_type as u64, bytes, tag as u64)
}

/// Valida tipo, tag, prioridade e IRQL e pede memória ao pool. `layout`
/// (prefixo, sufixo, alinhamento) substitui as opções derivadas do tipo.
pub fn allocate_storage(pool_type: u32, bytes: u64, tag: u32, priority: u32, layout: Option<(u64, u64, u64)>) -> u64 {
    let base = pool_type & !(RAISE_ON_ALLOCATION_FAILURE | COLD_ALLOCATION | ZERO_ALLOCATION);
    // Tipos reservados, de sessão e MustSucceed não são pools comuns.
    if ![0, 1, 4, 5, 512, 516].contains(&base) {
        reject("unsupported or reserved POOL_TYPE", pool_type, bytes, tag);
    }
    if tag == 0 {
        reject("pool tag must be nonzero", pool_type, bytes, tag);
    }
    if ![0, 8, 9, 16, 24, 25, 32, 40, 41].contains(&priority) {
        reject("invalid pool priority", pool_type, bytes, tag);
    }
    let pageable = base & 1 != 0;
    if irql::get_irql() > if pageable { 1 } else { 2 } {
        reject("pool allocation at invalid IRQL", pool_type, bytes, tag);
    }
    let (prefix_bytes, suffix_bytes, alignment) = layout.unwrap_or((0, 0, if base & 4 != 0 { 64 } else { 16 }));
    let options = AllocateOptions {
        paged: pageable,
        nx: pageable || base & 512 != 0,
        alignment,
        tag,
        priority,
        zero: pool_type & ZERO_ALLOCATION != 0,
        cold: pool_type & COLD_ALLOCATION != 0,
        prefix_bytes,
        suffix_bytes,
    };
    match kernel_pool::allocate(bytes, options) {
        Ok(pointer) => pointer,
        Err(error) => reject(&alloc::format!("pool invariant failure: {error}"), pool_type, bytes, tag),
    }
}

/// ExAllocatePoolWithTagPriority: RAISE transforma a falta em exceção.
pub fn allocate_priority(pool_type: u32, bytes: u64, tag: u32, priority: u32) -> Result<u64, KernelError> {
    let pointer = allocate_storage(pool_type, bytes, tag, priority, None);
    if pointer != 0 || pool_type & RAISE_ON_ALLOCATION_FAILURE == 0 {
        return Ok(pointer);
    }
    Err(KernelError::with_status("pool allocation raised STATUS_INSUFFICIENT_RESOURCES", 0xC000_009A))
}

/// ExAllocatePoolWithTag: o alocador interno direto (prioridade 32).
pub fn allocate_tagged(pool_type: u32, bytes: u64, tag: u32) -> Result<u64, KernelError> {
    allocate_priority(pool_type, bytes, tag, 32)
}

/// ExAllocatePool2/ExAllocatePoolZero: POOL_FLAGS só escolhe paginado/não
/// paginado; o pool do convidado é único e a memória sai zerada.
pub fn allocate_zeroed(bytes: u64) -> u64 {
    guest::alloc_bytes(bytes)
}

/// ExAllocatePoolUninitialized: o mesmo pool, sem zerar.
pub fn allocate_uninitialized(bytes: u64) -> u64 {
    guest::alloc_raw(bytes)
}

/// ExFreePool/ExFreePoolWithTag/ExFreePool2. Encaminha ao alocador dono:
/// endereços baixos são da arena; a tag opcional só é conferida pelo pool
/// que guarda o metadado.
pub fn free(pointer: u64, tag: u64) -> Result<(), KernelError> {
    if pointer < 0xFFFF_0000_0000_0000 {
        guest::free_bytes(pointer);
    } else if data_pool::owns(pointer) {
        data_pool::free(pointer)?;
    } else if kernel_pool::owns(pointer) {
        kernel_pool::free(pointer, if tag == 0 { None } else { Some(tag as u32) })?;
    } else {
        guest::free_bytes(pointer);
    }
    Ok(())
}
