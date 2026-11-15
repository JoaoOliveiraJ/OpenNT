//! ExAllocatePoolWithQuotaTag.
//!
//! Armazenamento real, cobrança por processo e falhas distintas de memória
//! e de quota. Nunca devolve um bloco sem cobrar seu dono.

use super::pool_allocation;
use crate::ntos::mm::{kernel_pool, session, session_pool};
use crate::ntos::ps::{pool_quota, process};
use crate::rtl::KernelError;

const FAIL_INSTEAD_OF_RAISE: u32 = 8;
const RAISE_ON_ALLOCATION_FAILURE: u32 = 16;
/// Limite do caminho de pequenos blocos de ExAllocatePoolWithTag.
const MAXIMUM_SMALL_ALLOCATION: u64 = 4064;

/// Exceção levantada por RtlRaiseStatus (o despacho de exceções chega na
/// fase 6; até lá o status viaja como erro).
fn raise(status: u32) -> Result<u64, KernelError> {
    Err(KernelError::with_status("ExAllocatePoolWithQuotaTag raised", status))
}

pub fn allocate(pool_type: u32, bytes: u64, tag: u32) -> Result<u64, KernelError> {
    let owner = process::get_current_process();
    let charged = owner != process::get_system_process() && bytes <= MAXIMUM_SMALL_ALLOCATION;
    // Cabeçalho e alinhamento consomem memória real, devolvida no mesmo
    // free; perto do fim da página o NT retira o alinhamento de cache.
    let cache_aligned = pool_type & 4 != 0 && bytes.saturating_add(80) <= MAXIMUM_SMALL_ALLOCATION;
    let layout = charged.then(|| if cache_aligned { (64, 16, 64) } else { (16, 0, 16) });
    let pointer = pool_allocation::allocate_storage(pool_type & !FAIL_INSTEAD_OF_RAISE, bytes, tag, 16, layout);
    if pointer == 0 {
        // O RAISE da alocação subjacente prevalece mesmo quando a variante
        // com quota permitiria NULL; a falha de quota usa só o flag 8.
        if pool_type & FAIL_INSTEAD_OF_RAISE == 0 || pool_type & RAISE_ON_ALLOCATION_FAILURE != 0 {
            return raise(0xC000_009A);
        }
        return Ok(0);
    }
    if !charged {
        return Ok(pointer);
    }
    // PagedPoolSession sai do heap da sessão corrente: a cobrança é pelos
    // bytes que o bloco reserva lá e volta com o free dele.
    let session_block = session_pool::is_paged_session_type(pool_type);
    let rounded = if session_block { session_pool::block(session::current(), pointer).map_or(0, |(size, _)| size) } else { kernel_pool::info(pointer).map_or(0, |info| info.rounded) };
    match pool_quota::charge(owner, pool_type & 1 != 0, rounded)? {
        Err(status) => {
            if session_block {
                let _ = session_pool::free_paged(pointer);
            } else {
                kernel_pool::free(pointer, Some(tag))?;
            }
            if pool_type & FAIL_INSTEAD_OF_RAISE == 0 {
                return raise(status);
            }
            Ok(0)
        }
        Ok(quota) => {
            if let Some(quota) = quota {
                if session_block {
                    session_pool::attach_quota(pointer, quota)?;
                } else {
                    kernel_pool::attach_quota(pointer, quota)?;
                }
            }
            Ok(pointer)
        }
    }
}
