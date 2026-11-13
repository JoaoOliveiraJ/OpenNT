//! Serviços de memória virtual de um processo alvo, em KernelMode
//! (ZwAllocateVirtualMemory(Ex), ZwFreeVirtualMemory, ZwProtectVirtualMemory).
//!
//! O processo alvo vem do handle (o pseudo-handle é o processo corrente,
//! inclusive anexado) e é retido durante a operação; o processo de usuário
//! ativo usa os VADs do runtime, os demais as regiões privadas do próprio
//! espaço (`ps::user::memory::Space`). Cada serviço devolve o NTSTATUS.

use crate::ntos::ke::irql;
use crate::ntos::mm::query_virtual;
use crate::ntos::ps::process;
use crate::ntos::ps::user::memory::{self, Space};
use crate::rtl::KernelError;

const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;
const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
const STATUS_INVALID_PARAMETER_5: u32 = 0xC000_00F3;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RESET: u32 = 0x8_0000;
const MEM_TOP_DOWN: u32 = 0x10_0000;
const MEM_WRITE_WATCH: u32 = 0x20_0000;
const MEM_PHYSICAL: u32 = 0x40_0000;
const MEM_RESET_UNDO: u32 = 0x100_0000;
const MEM_LARGE_PAGES: u32 = 0x2000_0000;

/// Executa `body` no espaço do processo do handle, com o processo retido.
fn with_target(handle: u64, body: impl FnOnce(Space) -> Result<u32, KernelError>) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("Zw*VirtualMemory requires PASSIVE_LEVEL"));
    }
    let pointer = match query_virtual::target(handle) {
        Ok((pointer, _)) => pointer,
        Err(status) => return Ok(status),
    };
    let Some(terminated) = process::with_record(pointer, |record| record.terminated) else { return Ok(STATUS_INVALID_HANDLE) };
    if terminated {
        return Ok(STATUS_PROCESS_IS_TERMINATING);
    }
    if process::reference(pointer).is_none() {
        return Ok(STATUS_INVALID_HANDLE);
    }
    let result = body(Space::of(pointer));
    process::dereference(pointer)?;
    result
}

/// ZeroBits: até 53 é a quantidade de bits altos zerados; acima disso é
/// uma máscara do endereço mais alto. 0 = limite padrão do espaço.
fn highest_from_zero_bits(zero_bits: u64) -> Result<u64, u32> {
    match zero_bits {
        0 => Ok(0),
        1..=53 => Ok(u64::MAX >> zero_bits),
        mask if mask >= 0x1_0000 => Ok(u64::MAX >> mask.leading_zeros()),
        _ => Err(STATUS_INVALID_PARAMETER_3),
    }
}

/// Tipos de alocação: COMMIT/RESERVE/TOP_DOWN vão ao alocador; RESET só
/// valida (o conteúdo pode ser preservado); os demais não existem aqui.
fn checked_type(allocation_type: u32) -> Result<u32, u32> {
    let known = MEM_COMMIT | MEM_RESERVE | MEM_RESET | MEM_TOP_DOWN | MEM_WRITE_WATCH | MEM_PHYSICAL | MEM_RESET_UNDO | MEM_LARGE_PAGES;
    if allocation_type & !known != 0 || allocation_type & (MEM_COMMIT | MEM_RESERVE | MEM_RESET | MEM_RESET_UNDO) == 0 {
        return Err(STATUS_INVALID_PARAMETER_5);
    }
    if allocation_type & MEM_LARGE_PAGES != 0 {
        return Err(STATUS_PRIVILEGE_NOT_HELD);
    }
    if allocation_type & (MEM_WRITE_WATCH | MEM_PHYSICAL | MEM_RESET_UNDO) != 0 {
        return Err(STATUS_NOT_SUPPORTED);
    }
    Ok(allocation_type)
}

/// MEM_RESET: a faixa precisa estar inteira numa região comitada.
fn reset(space: Space, base_pointer: u64, size_pointer: u64) -> Result<u32, KernelError> {
    memory::validate_committed(space, base_pointer, size_pointer)
}

/// ZwAllocateVirtualMemory.
pub fn allocate(process_handle: u64, base_pointer: u64, zero_bits: u64, size_pointer: u64, allocation_type: u32, protect: u32) -> Result<u32, KernelError> {
    let highest = match highest_from_zero_bits(zero_bits) {
        Ok(highest) => highest,
        Err(status) => return Ok(status),
    };
    let allocation_type = match checked_type(allocation_type) {
        Ok(value) => value,
        Err(status) => return Ok(status),
    };
    with_target(process_handle, |space| {
        if allocation_type & MEM_RESET != 0 {
            return reset(space, base_pointer, size_pointer);
        }
        memory::allocate_in(space, base_pointer, size_pointer, allocation_type & (MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN), protect, 0, highest, 0x1_0000)
    })
}

/// ZwAllocateVirtualMemoryEx.
pub fn allocate_ex(process_handle: u64, base_pointer: u64, size_pointer: u64, allocation_type: u32, protect: u32, parameters: u64, count: u32) -> Result<u32, KernelError> {
    let allocation_type = match checked_type(allocation_type) {
        Ok(value) => value,
        Err(status) => return Ok(status),
    };
    with_target(process_handle, |space| {
        if allocation_type & MEM_RESET != 0 {
            return reset(space, base_pointer, size_pointer);
        }
        memory::allocate_ex_in(space, base_pointer, size_pointer, allocation_type & (MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN), protect, parameters, count as u64)
    })
}

/// ZwFreeVirtualMemory.
pub fn free(process_handle: u64, base_pointer: u64, size_pointer: u64, free_type: u32) -> Result<u32, KernelError> {
    with_target(process_handle, |space| memory::free_in(space, base_pointer, size_pointer, free_type))
}

/// ZwProtectVirtualMemory.
pub fn protect(process_handle: u64, base_pointer: u64, size_pointer: u64, new_protect: u32, old_pointer: u64) -> Result<u32, KernelError> {
    with_target(process_handle, |space| memory::protect_in(space, base_pointer, size_pointer, new_protect, old_pointer, false))
}
