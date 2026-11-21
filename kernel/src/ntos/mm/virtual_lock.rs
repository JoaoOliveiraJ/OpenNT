//! A trava de páginas virtuais de um processo: NtLockVirtualMemory e
//! NtUnlockVirtualMemory (com o ZwUnlockVirtualMemory de modo kernel).
//!
//! Como no ntoskrnl 19041 (NtLockVirtualMemory 0x339070, NtUnlockVirtualMemory
//! 0x2ae5c0, ambos sobre o MiLockUnlockCommon 0x67db7c):
//! - MapType só com MAP_PROCESS (1) e/ou MAP_SYSTEM (2), e pelo menos um;
//!   BaseAddress acima de MM_HIGHEST_USER_ADDRESS, faixa além de
//!   MM_USER_PROBE_ADDRESS ou tamanho zero: STATUS_INVALID_PARAMETER;
//! - o processo do handle com PROCESS_VM_OPERATION; o MAP_SYSTEM pede o
//!   SeLockMemoryPrivilege a quem vem de UserMode
//!   (STATUS_PRIVILEGE_NOT_HELD);
//! - a faixa vai às páginas inteiras que a cobrem, e BaseAddress e
//!   RegionSize voltam com elas.
//!
//! A trava: cada página precisa estar comitada numa alocação privada
//! (reservada ou fora dos VADs: STATUS_ACCESS_VIOLATION, o ERROR_NOACCESS do
//! VirtualLock); as que estão fora do working set voltam a ele, as de zero
//! sob demanda ganham o frame (`mm/page_fault`, a falta de cada página do
//! MiLockPages), e o corte do working set (`mm/working_set`) não leva mais
//! as travadas ao arquivo de paginação. Com todas as páginas já travadas no
//! mesmo tipo, a resposta é
//! STATUS_WAS_LOCKED. A destrava pede cada página travado no tipo
//! (STATUS_NOT_LOCKED senão, sem mudar nada). O decommit e a liberação da
//! região levam as travas junto. As vistas de seção não passam pelo corte
//! do working set do OpenNT: a trava delas fica recusada
//! (STATUS_NOT_SUPPORTED, com registro).

use crate::ntos::mm::memory_map;
use crate::ntos::mm::page_fault;
use crate::ntos::ps::user::memory::{PrivateRegion, Space};
use crate::ntos::ps::user::state::Region;

pub const MAP_PROCESS: u32 = 1;
pub const MAP_SYSTEM: u32 = 2;
const MAP_TYPE_MASK: u32 = MAP_PROCESS | MAP_SYSTEM;
const PAGE: u64 = 0x1000;

const STATUS_WAS_LOCKED: u32 = 0x4000_0019;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_LOCKED: u32 = 0xC000_002A;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;

fn private(region: &Region) -> Option<&PrivateRegion> {
    region.as_any().downcast_ref::<PrivateRegion>()
}

/// As validações de parâmetros do MiLockUnlockCommon: a faixa de páginas
/// `[first, end)` ou o NTSTATUS.
pub fn validate(map_type: u32, base: u64, size: u64) -> Result<(u64, u64), u32> {
    if map_type & !MAP_TYPE_MASK != 0 || map_type & MAP_TYPE_MASK == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if base > memory_map::HIGHEST_USER_ADDRESS || memory_map::USER_PROBE_ADDRESS - base < size || size == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let first = base & !(PAGE - 1);
    let end = (base + size).div_ceil(PAGE) * PAGE;
    Ok((first, end))
}

/// As páginas `[first, end)` em regiões privadas do espaço: a região e os
/// índices de cada pedaço, ou o NTSTATUS de uma página sem alocação privada.
fn private_runs(space: Space, first: u64, end: u64) -> Result<alloc::vec::Vec<(Region, u64, u64)>, u32> {
    let mut runs = alloc::vec::Vec::new();
    let mut va = first;
    while va < end {
        let Some(region) = space.find(va) else { return Err(STATUS_ACCESS_VIOLATION) };
        let Some(owner) = private(&region) else {
            crate::debug_print!("[mm] NtLockVirtualMemory: {:#x} numa vista de secao sem suporte", va);
            return Err(STATUS_NOT_SUPPORTED);
        };
        let run_end = end.min(owner.base + owner.size);
        let (first_index, end_index) = ((va - owner.base) / PAGE, (run_end - owner.base) / PAGE);
        runs.push((region.clone(), first_index, end_index));
        va = run_end;
    }
    Ok(runs)
}

/// MiLockVirtualMemory sobre a faixa já validada: trava as páginas no tipo
/// `map_type`. Devolve o NTSTATUS.
pub fn lock(space: Space, first: u64, end: u64, map_type: u32) -> u32 {
    let runs = match private_runs(space, first, end) {
        Ok(runs) => runs,
        Err(status) => return status,
    };
    // Todas as páginas comitadas antes de travar qualquer uma.
    for (region, first_index, end_index) in &runs {
        let Some(owner) = private(region) else { return STATUS_ACCESS_VIOLATION };
        let state = owner.state.lock();
        if (*first_index..*end_index).any(|index| !state.committed_pages.contains(&index)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    let mut newly = false;
    for (region, first_index, end_index) in &runs {
        let Some(owner) = private(region) else { continue };
        let _hold = owner.hold();
        let status = page_fault::make_present(space.root(), owner, *first_index, *end_index);
        if status != 0 {
            return status;
        }
        let mut state = owner.state.lock();
        for index in *first_index..*end_index {
            let entry = state.locked.entry(index).or_insert(0);
            newly |= *entry & map_type as u8 != map_type as u8;
            *entry |= map_type as u8;
        }
    }
    if newly { 0 } else { STATUS_WAS_LOCKED }
}

/// MiUnlockVirtualMemory sobre a faixa já validada: cada página precisa
/// estar travada no tipo; senão STATUS_NOT_LOCKED sem destravar nada.
pub fn unlock(space: Space, first: u64, end: u64, map_type: u32) -> u32 {
    let runs = match private_runs(space, first, end) {
        Ok(runs) => runs,
        Err(STATUS_NOT_SUPPORTED) | Err(STATUS_ACCESS_VIOLATION) => return STATUS_NOT_LOCKED,
        Err(status) => return status,
    };
    for (region, first_index, end_index) in &runs {
        let Some(owner) = private(region) else { return STATUS_NOT_LOCKED };
        let state = owner.state.lock();
        if (*first_index..*end_index).any(|index| state.locked.get(&index).is_none_or(|bits| *bits & map_type as u8 != map_type as u8)) {
            return STATUS_NOT_LOCKED;
        }
    }
    for (region, first_index, end_index) in &runs {
        let Some(owner) = private(region) else { continue };
        let mut state = owner.state.lock();
        for index in *first_index..*end_index {
            if let Some(bits) = state.locked.get_mut(&index) {
                *bits &= !(map_type as u8);
                if *bits == 0 {
                    state.locked.remove(&index);
                }
            }
        }
    }
    0
}
