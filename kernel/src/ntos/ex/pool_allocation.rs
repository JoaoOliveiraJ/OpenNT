//! Alocação de pool com prioridade pela ABI NT.
//!
//! O provedor de memória mantém armazenamento, paginação e propriedade;
//! pedidos inválidos provocam bugcheck 0xC2 e a falha com RAISE levanta
//! STATUS_INSUFFICIENT_RESOURCES. Também as variantes ExAllocatePool2/Zero/
//! Uninitialized e a liberação (ExFreePool*), que encaminha ao pool dono.
//!
//! Execução, como no Windows 10 19041: o NonPagedPool (tipo 0, o
//! NonPagedPoolExecute) e o NonPagedPoolCacheAligned (4), e o
//! ExAllocatePool2 com POOL_FLAG_NON_PAGED_EXECUTE, saem de regiões
//! executáveis do pool executivo (`kernel_pool`, que não mistura páginas
//! executáveis e NX); o NonPagedPoolNx (0x200), o NonPagedPoolNxCacheAligned
//! (0x204), o PagedPool e o resto ficam sem execução, no pool executivo NX
//! ou na arena da janela do heap.

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

/// POOL_FLAGS do ExAllocatePool2 (wdm.h).
const POOL_FLAG_UNINITIALIZED: u64 = 0x2;
const POOL_FLAG_CACHE_ALIGNED: u64 = 0x8;
const POOL_FLAG_RAISE_ON_FAILURE: u64 = 0x20;
const POOL_FLAG_NON_PAGED_EXECUTE: u64 = 0x80;

/// O tipo (sem os modificadores de RAISE, frio e zero) é de pool não
/// paginado executável: NonPagedPool/NonPagedPoolExecute (0) ou
/// NonPagedPoolCacheAligned (4).
pub fn executable_pool_type(pool_type: u32) -> bool {
    matches!(pool_type & !(RAISE_ON_ALLOCATION_FAILURE | COLD_ALLOCATION | ZERO_ALLOCATION), 0 | 4)
}

/// ExAllocatePool2(Flags, NumberOfBytes, Tag). Com POOL_FLAG_NON_PAGED_EXECUTE
/// o bloco sai de uma região executável do pool executivo (zerado, salvo
/// POOL_FLAG_UNINITIALIZED; alinhado à linha de cache com
/// POOL_FLAG_CACHE_ALIGNED); a falta com POOL_FLAG_RAISE_ON_FAILURE levanta
/// STATUS_INSUFFICIENT_RESOURCES. Os outros pedidos (POOL_FLAG_NON_PAGED, o
/// NX, e POOL_FLAG_PAGED) saem zerados da arena, que não executa.
pub fn allocate_pool2(flags: u64, bytes: u64, tag: u32) -> Result<u64, KernelError> {
    if flags & POOL_FLAG_NON_PAGED_EXECUTE == 0 {
        return Ok(guest::alloc_bytes(bytes));
    }
    let options = AllocateOptions {
        paged: false,
        nx: false,
        alignment: if flags & POOL_FLAG_CACHE_ALIGNED != 0 { 64 } else { 16 },
        tag,
        priority: 32,
        zero: flags & POOL_FLAG_UNINITIALIZED == 0,
        ..AllocateOptions::default()
    };
    let pointer = kernel_pool::allocate(bytes, options)?;
    if pointer == 0 && flags & POOL_FLAG_RAISE_ON_FAILURE != 0 {
        return Err(KernelError::with_status("ExAllocatePool2 raised STATUS_INSUFFICIENT_RESOURCES", 0xC000_009A));
    }
    Ok(pointer)
}

/// ExAllocatePoolZero/ExAllocatePoolUninitialized(PoolType, NumberOfBytes,
/// Tag): os tipos executáveis passam pelo ExAllocatePoolWithTag (com
/// POOL_ZERO_ALLOCATION quando `zero`), numa região executável do pool
/// executivo; os NX e os paginados saem da arena, zerada quando `zero`.
pub fn allocate_typed(pool_type: u32, bytes: u64, tag: u32, zero: bool) -> Result<u64, KernelError> {
    if executable_pool_type(pool_type) {
        let typed = if zero { pool_type | ZERO_ALLOCATION } else { pool_type & !ZERO_ALLOCATION };
        return allocate_tagged(typed, bytes, tag);
    }
    Ok(if zero { guest::alloc_bytes(bytes) } else { guest::alloc_raw(bytes) })
}

/// ExFreePool/ExFreePoolWithTag/ExFreePool2. Encaminha ao alocador dono
/// pela faixa de cada um (a arena na janela do heap, o pool de dados e o pool
/// executivo); a tag opcional só é conferida pelo pool que guarda o
/// metadado.
pub fn free(pointer: u64, tag: u64) -> Result<(), KernelError> {
    if guest::in_arena(pointer) {
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

// ---- tamanho de um bloco de pool ------------------------------------------
//
// (append de `ex-pool-block-size` ao ex/pool_allocation.rs; usa o
// `kernel_pool` já importado pelo arquivo, sem linhas `use` novas.)
//
// ExQueryPoolBlockSize no ntoskrnl 19041 (fora do special pool): bloco
// alinhado à página (big pool) devolve PAGE_SIZE com QuotaCharged = FALSE;
// senão o POOL_HEADER em Block-0x10 dá BlockSize*16 - 0x10 (o tamanho útil
// de 16 em 16 bytes) e QuotaCharged = (ExpGetBilledProcess != NULL). O pool
// do OpenNT não tem POOL_HEADER: as mesmas grandezas saem do registro da
// alocação. Pedidos acima de 0xFF0 bytes (o que o NT serve do big pool)
// devolvem PAGE_SIZE; os menores, round_up(bytes, 16). Blocos fora do
// `kernel_pool` (arena do convidado) não têm registro: 0 e FALSE.

const POOL_PAGE_SIZE: u64 = 0x1000;
/// PAGE_SIZE - sizeof(POOL_HEADER): acima disso o NT usa o big pool.
const SMALL_POOL_LIMIT: u64 = 0xFF0;
/// Granularidade do POOL_HEADER.BlockSize.
const POOL_GRANULARITY: u64 = 16;

/// ExQueryPoolBlockSize: (tamanho, QuotaCharged).
pub fn query_block_size(block: u64) -> (u64, bool) {
    match kernel_pool::info(block) {
        Some(info) if info.bytes > SMALL_POOL_LIMIT => (POOL_PAGE_SIZE, false),
        Some(info) => (info.bytes.max(1).next_multiple_of(POOL_GRANULARITY), info.quota_owner != 0),
        None => (0, false),
    }
}

/// ExQueryPoolBlockSize com a saída do BOOLEAN de cota (o Windows a exige;
/// NULL aqui só não é gravado).
pub fn query_block_size_with_quota(block: u64, quota_charged: Option<&crate::ntos::inc::field::Field<u8>>) -> u64 {
    let (size, charged) = query_block_size(block);
    if let Some(quota_charged) = quota_charged {
        quota_charged.set(charged as u8);
    }
    size
}

/// ExAllocatePool(PoolType, NumberOfBytes) (ntoskrnl 19041 rva 0x32bff0): o
/// ExAllocatePoolWithTag com a tag 'None' (0x656E6F4E).
pub fn allocate_untagged(pool_type: u32, bytes: u64) -> Result<u64, KernelError> {
    allocate_tagged(pool_type, bytes, 0x656E_6F4E)
}
