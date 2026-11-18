//! Páginas de guarda (PAGE_GUARD) das alocações privadas e o crescimento da
//! pilha de usuário, como no ntoskrnl 19041 (o MiAccessCheck e o
//! MiCheckForUserStackOverflow que o MiUserFault chama).
//!
//! Uma página privada com PAGE_GUARD (NtAllocateVirtualMemory ou
//! NtProtectVirtualMemory) fica comitada, com o frame, e a PTE ausente; a
//! proteção completa fica na região (`PrivateMut::page_protects`), que o
//! NtQueryVirtualMemory devolve. O primeiro acesso que a proteção base
//! admite tira a guarda (uma escrita numa página sem escrita, ou uma
//! execução numa página NX, é STATUS_ACCESS_VIOLATION e a guarda fica, como
//! no MiAccessCheck): a PTE volta válida com a proteção base, e o
//! MiCheckForUserStackOverflow decide o resultado:
//!
//! - fora da pilha da thread (TEB DeallocationStack..StackBase), com a
//!   thread anexada a outro processo ou sem TEB: STATUS_GUARD_PAGE_VIOLATION,
//!   entregue ao modo usuário como exceção com o tipo de acesso e o endereço;
//! - na pilha: a guarda desce. A garantia é o GuaranteedStackBytes da TEB
//!   arredondado à página, mais uma página quando não é zero, e no mínimo
//!   3 páginas; as páginas logo abaixo da página da falta são comitadas
//!   PAGE_READWRITE|PAGE_GUARD (o ZwAllocateVirtualMemory do 19041), o
//!   StackLimit da TEB vai para a página da falta e o acesso repete
//!   (STATUS_PAGE_FAULT_GUARD_PAGE);
//! - sem espaço acima do DeallocationStack, com o commit recusado ou com o
//!   FLG_DISABLE_STACK_EXTENSION do NtGlobalFlag da PEB: o que sobra fica
//!   PAGE_READWRITE (ZwProtectVirtualMemory), o StackLimit desce até lá e o
//!   resultado é STATUS_STACK_OVERFLOW.
//!
//! O acesso chega aqui pela falta de página de usuário (`ps/user/exceptions`)
//! e pelas sondas do kernel sobre memória de usuário
//! (`ps/user/state::probe_user_access`, o toque do kernel numa página de
//! guarda: a pilha cresce e a sonda segue; fora dela a guarda sai e a sonda
//! falha). Com um spin lock retido, ou acima de APC_LEVEL, a página fica
//! como está. As pilhas que o
//! OpenNT monta são comitadas inteiras; a guarda aparece nas pilhas que o
//! próprio processo monta (o RtlCreateUserStack das fibras, o
//! SetThreadStackGuarantee).

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Kthread, Peb, Teb};
use crate::ntos::ke::{irql, process_attachment};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::memory_map as map;
use crate::ntos::mm::paging::{self, MapOptions};
use crate::ntos::ps::process;
use crate::ntos::ps::user::memory::{self, PrivateRegion, Space, PAGE_GUARD};
use crate::ntos::ps::user::state;
use crate::rtl::{sync, KernelError};

/// O acesso repete: a pilha cresceu.
pub const STATUS_PAGE_FAULT_GUARD_PAGE: u32 = 0x0000_0113;
pub const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x8000_0001;
pub const STATUS_STACK_OVERFLOW: u32 = 0xC000_00FD;
const PAGE: u64 = 0x1000;
const MEM_COMMIT: u32 = 0x1000;
const PAGE_READWRITE: u32 = 0x04;
/// A garantia mínima de pilha (3 páginas).
const MINIMUM_GUARANTEE: u64 = 0x3000;
/// FLG_DISABLE_STACK_EXTENSION.
const FLG_DISABLE_STACK_EXTENSION: u32 = 0x1_0000;

/// O tipo de acesso da falta.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Access {
    Read,
    Write,
    Execute,
}

/// Acesso a `address` no processo corrente: `None` se a página não é de
/// guarda de uma alocação privada (ou se a proteção base recusa o acesso
/// antes); senão a guarda sai e volta STATUS_PAGE_FAULT_GUARD_PAGE (a pilha
/// cresceu: o acesso repete), STATUS_GUARD_PAGE_VIOLATION ou
/// STATUS_STACK_OVERFLOW.
pub fn touch(address: u64, access: Access) -> Option<u32> {
    if !(map::LOWEST_USER_ADDRESS..map::USER_ADDRESS_LIMIT).contains(&address) || sync::spin_locks_held() != 0 || irql::get_irql() > irql::APC_LEVEL {
        return None;
    }
    let space = Space::current();
    let region = space.find(address)?;
    let owner = region.as_any().downcast_ref::<PrivateRegion>()?;
    if !clear_guard(space.root(), owner, (address - owner.base) / PAGE, access) {
        return None;
    }
    Some(check_user_stack_overflow(address))
}

/// MiAccessCheck da página `index`: com PAGE_GUARD e o acesso admitido pela
/// proteção base, a PTE volta válida com ela e a guarda sai da proteção
/// registrada.
fn clear_guard(root: u64, owner: &PrivateRegion, index: u64, access: Access) -> bool {
    let mut state = owner.state.lock();
    if !state.committed_pages.contains(&index) {
        return false;
    }
    let protect = state.page_protects.get(&index).copied().filter(|&protect| protect != 0).unwrap_or(owner.protect);
    if protect & PAGE_GUARD == 0 {
        return false;
    }
    let writable = protect & (0x04 | 0x08 | 0x40 | 0x80) != 0;
    let executable = protect & 0xF0 != 0;
    if (access == Access::Write && !writable) || (access == Access::Execute && !executable) {
        return false;
    }
    let Some(&frame) = state.frames.get(&index) else { return false };
    let base = protect & !PAGE_GUARD;
    if !paging::map_page_in(root, owner.base + index * PAGE, frame, memory::private_pte(base), MapOptions { nx: base & 0xF0 == 0, ..MapOptions::default() }) {
        return false;
    }
    state.page_protects.insert(index, base);
    state.protected_frames.insert(index, frame);
    true
}

/// Os campos da pilha na TEB: StackBase, DeallocationStack e
/// GuaranteedStackBytes.
fn stack_fields(teb: u64) -> Result<(u64, u64, u32), KernelError> {
    let block = state::user_struct::<Teb>(teb)?;
    Ok((block.nt_tib.stack_base.probe_get()?, block.deallocation_stack.probe_get()?, block.guaranteed_stack_bytes.probe_get()?))
}

/// MiCheckForUserStackOverflow(FaultingAddress) depois da guarda tirada.
fn check_user_stack_overflow(address: u64) -> u32 {
    if process_attachment::is_attached() {
        return STATUS_GUARD_PAGE_VIOLATION;
    }
    // SAFETY: a KTHREAD corrente.
    let teb = unsafe { Kthread::at(process::get_current_thread()) }.teb.get();
    if teb == 0 {
        return STATUS_GUARD_PAGE_VIOLATION;
    }
    let Ok((stack_base, deallocation, guaranteed)) = stack_fields(teb) else { return STATUS_GUARD_PAGE_VIOLATION };
    let deallocation = deallocation & !(PAGE - 1);
    let mut guarantee = (guaranteed as u64 + PAGE - 1) & !(PAGE - 1);
    if guarantee != 0 {
        guarantee += PAGE;
    }
    let guarantee = guarantee.max(MINIMUM_GUARANTEE);
    if address >= stack_base || address < deallocation {
        return STATUS_GUARD_PAGE_VIOLATION;
    }
    let guard = (address & !(PAGE - 1)).wrapping_sub(guarantee);
    let (status, limit) = if guard <= deallocation {
        (STATUS_STACK_OVERFLOW, make_read_write(deallocation + PAGE, guarantee))
    } else {
        match commit_guard(guard, guarantee) {
            Some((base, size)) => (STATUS_PAGE_FAULT_GUARD_PAGE, base + size),
            None => (STATUS_STACK_OVERFLOW, make_read_write(guard + PAGE, guarantee - PAGE)),
        }
    };
    let written = state::user_struct::<Teb>(teb).and_then(|block| block.nt_tib.stack_limit.probe_set(limit));
    if written.is_err() {
        return STATUS_GUARD_PAGE_VIOLATION;
    }
    status
}

/// O NtGlobalFlag da PEB do processo corrente proíbe o crescimento da pilha.
fn stack_extension_disabled() -> bool {
    let peb = state::current_peb();
    peb != 0 && state::user_struct::<Peb>(peb).and_then(|block| block.nt_global_flag.probe_get()).is_ok_and(|flags| flags & FLG_DISABLE_STACK_EXTENSION != 0)
}

/// Dois SIZE_T de kernel para os serviços de memória do processo corrente
/// (base e tamanho, como o ZwAllocateVirtualMemory e o
/// ZwProtectVirtualMemory recebem) e um ULONG para a proteção anterior.
fn with_cells<R>(base: u64, size: u64, body: impl FnOnce(u64) -> R) -> Option<R> {
    let cells = guest::alloc_bytes(0x18);
    if cells == 0 {
        return None;
    }
    guest::write64(cells, base);
    guest::write64(cells + 8, size);
    let result = body(cells);
    guest::free_bytes(cells);
    Some(result)
}

/// ZwAllocateVirtualMemory(NtCurrentProcess, &guard, 0, &guarantee,
/// MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD): a base e o tamanho comitados,
/// ou `None` se o commit falhou (ou o crescimento da pilha está desligado).
fn commit_guard(base: u64, size: u64) -> Option<(u64, u64)> {
    if stack_extension_disabled() {
        return None;
    }
    with_cells(base, size, |cells| {
        let status = memory::allocate_in(Space::current(), cells, cells + 8, MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD, 0, 0, map::ALLOCATION_GRANULARITY);
        status.ok().filter(|&status| status & 0x8000_0000 == 0).map(|_| (guest::read64(cells), guest::read64(cells + 8)))
    })
    .flatten()
}

/// ZwProtectVirtualMemory(NtCurrentProcess, &base, &size, PAGE_READWRITE,
/// &old), resultado ignorado: devolve a base depois da chamada (o StackLimit
/// novo).
fn make_read_write(base: u64, size: u64) -> u64 {
    with_cells(base, size, |cells| {
        let _ = memory::protect_in(Space::current(), cells, cells + 8, PAGE_READWRITE, cells + 0x10, false);
        guest::read64(cells)
    })
    .unwrap_or(base)
}
