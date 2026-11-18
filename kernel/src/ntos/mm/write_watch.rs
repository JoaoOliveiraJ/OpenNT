//! Write watch das alocações privadas (MEM_WRITE_WATCH) e os serviços
//! NtGetWriteWatch e NtResetWriteWatch, como no ntoskrnl 19041
//! (NtGetWriteWatch 0x2acce0, NtResetWriteWatch 0x63a770).
//!
//! MEM_WRITE_WATCH só vale numa reserva (o MiValidateAllocationType recusa
//! o resto com STATUS_INVALID_PARAMETER) e marca a alocação privada
//! (`PrivateRegion::allocation_type`, o VadFlags.WriteWatch). Uma página
//! foi escrita quando o bit Dirty da PTE válida está ligado ou quando o
//! bitmap de write watch da região (`PrivateMut::written`) a guarda: o bit
//! Dirty passa ao bitmap sempre que a PTE válida é reescrita
//! (NtProtectVirtualMemory) ou sai do working set (o corte), o
//! MiCaptureWriteWatchDirtyBit desses caminhos. O decommit não passa nada ao
//! bitmap, como no NT. As PTEs de usuário do OpenNT já nascem graváveis,
//! então o bit Dirty do hardware é o marcador (no NT x64 a PTE começa sem o
//! bit de escrita do hardware e a primeira escrita liga os dois, o 0x42 que
//! o NtGetWriteWatch testa). Limpar uma página (o MiMakePteClean e o
//! MiMoveDirtyBitsToPfns) apaga o bit Dirty da PTE e o do bitmap e invalida
//! a cópia da página no arquivo de paginação, que deixou de valer.
//!
//! Diferença declarada: uma escrita que o kernel faz pelo mapa direto (a
//! cópia do NtWriteVirtualMemory para outro processo) não liga o bit Dirty
//! da PTE de usuário e não aparece no write watch.

use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::memory_map as map;
use crate::ntos::mm::{paging, paging_file};
use crate::ntos::ps::user::memory::{self, PrivateMut, PrivateRegion, Space};
use crate::ntos::ps::user::state;
use crate::rtl::KernelError;

/// MEM_WRITE_WATCH.
pub const MEM_WRITE_WATCH: u32 = 0x20_0000;
const MEM_RESERVE: u32 = 0x2000;
/// WRITE_WATCH_FLAG_RESET.
const WRITE_WATCH_FLAG_RESET: u32 = 1;
const PAGE: u64 = 0x1000;
const PTE_VALID: u64 = 0x1;
const PTE_DIRTY: u64 = 0x40;
const PROCESS_VM_OPERATION: u32 = 0x8;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;
const STATUS_INVALID_PARAMETER_5: u32 = 0xC000_00F3;

/// MEM_WRITE_WATCH só com MEM_RESERVE (o MiValidateAllocationType).
pub fn valid_allocation_type(allocation_type: u32) -> bool {
    allocation_type & MEM_WRITE_WATCH == 0 || allocation_type & MEM_RESERVE != 0
}

/// A alocação privada guarda as escritas (MEM_WRITE_WATCH na reserva).
pub fn watched(owner: &PrivateRegion) -> bool {
    owner.allocation_type & MEM_WRITE_WATCH != 0
}

fn dirty(pte: u64) -> bool {
    pte & (PTE_VALID | PTE_DIRTY) == PTE_VALID | PTE_DIRTY
}

/// MiCaptureWriteWatchDirtyBit: antes de a PTE `pte` da página `index` ser
/// reescrita ou sair do working set, o bit Dirty dela passa ao bitmap da
/// região. Sem MEM_WRITE_WATCH, nada.
pub fn capture(owner: &PrivateRegion, state: &mut PrivateMut, index: u64, pte: u64) {
    if watched(owner) && dirty(pte) {
        state.written.insert(index);
    }
}

/// A página foi escrita desde a última limpeza.
fn written(root: u64, state: &PrivateMut, index: u64, va: u64) -> bool {
    state.written.contains(&index) || paging::read_leaf_in(root, va).is_some_and(dirty)
}

/// MiMakePteClean / MiMoveDirtyBitsToPfns de uma página: o bitmap e o bit
/// Dirty da PTE válida (a VA é invalidada na raiz carregada) saem, e a cópia
/// no arquivo de paginação deixa de valer.
fn clean(root: u64, state: &mut PrivateMut, index: u64, va: u64) {
    state.written.remove(&index);
    let Some(pte) = paging::read_leaf_in(root, va).filter(|&pte| dirty(pte)) else { return };
    paging::write_leaf_in(root, va, pte & !PTE_DIRTY);
    if let Some(slot) = state.clean.remove(&index) {
        paging_file::release(slot);
    }
}

/// A alocação MEM_WRITE_WATCH do espaço que contém `[base, last]`; sem VAD,
/// sem write watch ou passando do fim dele, STATUS_INVALID_PARAMETER_1.
fn watched_region(space: Space, base: u64, last: u64, body: impl FnOnce(&PrivateRegion) -> Result<u32, KernelError>) -> Result<u32, KernelError> {
    let Some(region) = space.find(base) else { return Ok(STATUS_INVALID_PARAMETER_1) };
    match region.as_any().downcast_ref::<PrivateRegion>() {
        Some(owner) if watched(owner) && last <= owner.base + owner.size - 1 => body(owner),
        _ => Ok(STATUS_INVALID_PARAMETER_1),
    }
}

/// NtGetWriteWatch(ProcessHandle, Flags, BaseAddress, RegionSize,
/// UserAddressArray, EntriesInUserAddressArray*, Granularity*) de modo
/// usuário: Flags só com WRITE_WATCH_FLAG_RESET (senão
/// STATUS_INVALID_PARAMETER_2); BaseAddress até MmHighestUserAddress
/// (PARAMETER_3) e a faixa até MmUserProbeAddress (PARAMETER_4); o contador
/// sondado e entre 1 e 2^61 - 1 (PARAMETER_5); o vetor sondado com
/// alinhamento 8 e o ULONG da granularidade; o processo do handle com
/// PROCESS_VM_OPERATION; RegionSize zero é PARAMETER_4 e a faixa tem de
/// estar numa alocação MEM_WRITE_WATCH (PARAMETER_1). As páginas escritas
/// saem em ordem crescente até encher o vetor (com WRITE_WATCH_FLAG_RESET,
/// cada uma devolvida volta a limpa); no sucesso, o vetor, o contador e a
/// granularidade (4 KB) são gravados.
pub fn nt_get_write_watch(process: u64, flags: u64, base: u64, size: u64, rsp: u64) -> Result<u32, KernelError> {
    let flags = flags as u32;
    if flags & !WRITE_WATCH_FLAG_RESET != 0 {
        return Ok(STATUS_INVALID_PARAMETER_2);
    }
    let (array, entries, granularity) = (state::stack_arg(rsp, 5), state::stack_arg(rsp, 6), state::stack_arg(rsp, 7));
    if base > map::HIGHEST_USER_ADDRESS {
        return Ok(STATUS_INVALID_PARAMETER_3);
    }
    if map::USER_PROBE_ADDRESS - base < size {
        return Ok(STATUS_INVALID_PARAMETER_4);
    }
    state::guarded(|| {
        if !state::probe_user_write(entries, 8) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        let limit = guest::try_read::<u64>(entries)?;
        if limit == 0 || limit > 0x1FFF_FFFF_FFFF_FFFF {
            return Ok(STATUS_INVALID_PARAMETER_5);
        }
        if array & 7 != 0 {
            return Ok(STATUS_DATATYPE_MISALIGNMENT);
        }
        if !state::probe_user_write(array, limit * 8) || !state::probe_user_write(granularity, 4) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        let mut pages: Vec<u64> = Vec::new();
        let status = memory::with_process_handle(process, PROCESS_VM_OPERATION, |target| {
            let last = base.wrapping_sub(1).wrapping_add(size);
            if base > last {
                return Ok(STATUS_INVALID_PARAMETER_4);
            }
            let space = Space::of(target);
            watched_region(space, base, last, |owner| {
                pages = collect(space.root(), owner, base, last, limit, flags & WRITE_WATCH_FLAG_RESET != 0);
                Ok(0)
            })
        })?;
        if status != 0 {
            return Ok(status);
        }
        let bytes: Vec<u8> = pages.iter().flat_map(|page| page.to_le_bytes()).collect();
        guest::try_write_bytes(array, &bytes)?;
        guest::try_write::<u64>(entries, pages.len() as u64)?;
        guest::try_write::<u32>(granularity, PAGE as u32)?;
        Ok(0)
    })
}

/// As páginas escritas de `[base, last]` em ordem crescente, no máximo
/// `limit`; com `reset`, cada uma devolvida volta a limpa (as seguintes ao
/// vetor cheio ficam como estão).
fn collect(root: u64, owner: &PrivateRegion, base: u64, last: u64, limit: u64, reset: bool) -> Vec<u64> {
    let mut pages = Vec::new();
    let mut state = owner.state.lock();
    let (first, final_index) = ((base - owner.base) / PAGE, (last - owner.base) / PAGE);
    // Só páginas comitadas ou já no bitmap podem ter sido escritas.
    let mut candidates: Vec<u64> = state.committed_pages.range(first..=final_index).chain(state.written.range(first..=final_index)).copied().collect();
    candidates.sort_unstable();
    candidates.dedup();
    for index in candidates {
        if pages.len() as u64 >= limit {
            break;
        }
        let va = owner.base + index * PAGE;
        if !written(root, &state, index, va) {
            continue;
        }
        pages.push(va);
        if reset {
            clean(root, &mut state, index, va);
        }
    }
    pages
}

/// NtResetWriteWatch(ProcessHandle, BaseAddress, RegionSize): BaseAddress
/// até MmHighestUserAddress (STATUS_INVALID_PARAMETER_2), a faixa não vazia
/// até MmUserProbeAddress (PARAMETER_3), o processo do handle com
/// PROCESS_VM_OPERATION e a faixa numa alocação MEM_WRITE_WATCH
/// (PARAMETER_1); toda página da faixa volta a limpa.
pub fn nt_reset_write_watch(process: u64, base: u64, size: u64) -> Result<u32, KernelError> {
    if base > map::HIGHEST_USER_ADDRESS {
        return Ok(STATUS_INVALID_PARAMETER_2);
    }
    if map::USER_PROBE_ADDRESS - base < size || size == 0 {
        return Ok(STATUS_INVALID_PARAMETER_3);
    }
    memory::with_process_handle(process, PROCESS_VM_OPERATION, |target| {
        let space = Space::of(target);
        let last = base + size - 1;
        watched_region(space, base, last, |owner| {
            let root = space.root();
            let mut state = owner.state.lock();
            let (first, final_index) = ((base - owner.base) / PAGE, (last - owner.base) / PAGE);
            let candidates: Vec<u64> = state.committed_pages.range(first..=final_index).chain(state.written.range(first..=final_index)).copied().collect();
            for index in candidates {
                clean(root, &mut state, index, owner.base + index * PAGE);
            }
            Ok(0)
        })
    })
}
