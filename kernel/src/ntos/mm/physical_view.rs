//! Vistas físicas giratórias de usuário (MmRotatePhysicalView).
//!
//! MmRotatePhysicalView(VirtualAddress, NumberOfBytes, NewMdl, Direction,
//! CopyFunction, Context) troca as páginas de uma faixa de um VAD de vista
//! física giratória (VadType = VadRotatePhysical, criado pelo
//! NtAllocateVirtualMemory com MEM_PHYSICAL | MEM_ROTATE) entre memória
//! comum e o framebuffer. A ordem de validação é a do ntoskrnl 19041:
//! VirtualAddress fora do alinhamento de página = STATUS_INVALID_PARAMETER_1;
//! tamanho desalinhado, zero ou que estoura = STATUS_INVALID_PARAMETER_2;
//! Direction >= MmMaximumRotateDirection (4) = STATUS_INVALID_PARAMETER_3;
//! depois o VAD do processo corrente (MiObtainReferencedVadEx): sem VAD,
//! STATUS_ACCESS_VIOLATION; um VAD que não é de vista giratória ou que não
//! cobre a faixa, STATUS_CONFLICTING_ADDRESSES. *NumberOfBytes recebe a
//! quantidade girada (0 em toda falha).
//!
//! O OpenNT não cria VADs de vista giratória (o NtAllocateVirtualMemory não
//! aceita MEM_ROTATE), então toda faixa válida termina numa das duas recusas
//! do VAD.

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::ps::user::memory;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
/// MmMaximumRotateDirection.
const MAXIMUM_ROTATE_DIRECTION: u32 = 4;

fn validate(virtual_address: u64, size: u64, direction: u32) -> u32 {
    if virtual_address & 0xFFF != 0 {
        return STATUS_INVALID_PARAMETER_1;
    }
    if size & 0xFFF != 0 || virtual_address.wrapping_add(size).wrapping_sub(1) <= virtual_address {
        return STATUS_INVALID_PARAMETER_2;
    }
    if direction >= MAXIMUM_ROTATE_DIRECTION {
        return STATUS_INVALID_PARAMETER_3;
    }
    // Nenhum VAD do OpenNT é de vista giratória.
    match memory::Space::current().find(virtual_address) {
        None => STATUS_ACCESS_VIOLATION,
        Some(_) => STATUS_CONFLICTING_ADDRESSES,
    }
}

/// MmRotatePhysicalView: devolve o NTSTATUS e grava *NumberOfBytes.
pub fn rotate_physical_view(virtual_address: u64, number_of_bytes: u64, _new_mdl: u64, direction: u32, _copy_function: u64, _context: u64) -> u32 {
    // SAFETY: PSIZE_T NumberOfBytes de um chamador de modo kernel.
    let bytes = unsafe { Field::<u64>::at(number_of_bytes) };
    let status = validate(virtual_address, bytes.get(), direction);
    bytes.set(0);
    status
}
