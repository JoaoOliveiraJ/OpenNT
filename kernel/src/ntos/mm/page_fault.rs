//! A falta de zero sob demanda das alocações privadas: o
//! MiResolveDemandZeroFault (rva 0x20fb10) e o MiResolvePrivateZeroFault
//! (0x2100e0) que o MiUserFault do ntoskrnl 19041 chama, pelo MiZeroFault
//! (0x2cf5f0) ou pelo MiDispatchFault (0x20eec0), para uma página privada
//! comitada que ainda não tem página física.
//!
//! - Commit: o NtAllocateVirtualMemory e o commit sobre reserva de uma
//!   alocação paginável (`PrivateRegion::pageable`) cobram o commit do
//!   processo e do sistema e só marcam as páginas comitadas, com a proteção
//!   (`PrivateMut::committed_pages`, `page_protects`): nenhum frame e a PTE
//!   zero, como o VAD com MemCommit do 19041 (o MiZeroFault confere o commit
//!   pelo VAD). As regiões residentes que o kernel monta para o processo
//!   (pilha da primeira thread, PEB, TEB e parâmetros) continuam com frames
//!   no commit.
//! - Falta: uma página comitada sem frame e fora do working set
//!   (`PrivateMut::demand_zero`) recebe um frame zerado na primeira vez que é
//!   tocada, pelo código de usuário (a falta do anel 3), pelo kernel (a falta
//!   do anel 0 de um acesso confiável) ou por uma sonda (`guest_memory`, o
//!   `__try { ProbeFor*; *p }` do NT). Como o MiAccessCheck, a proteção
//!   decide antes: PAGE_NOACCESS, a escrita numa página sem escrita e a
//!   execução numa página sem execução não materializam (o acesso dá
//!   STATUS_ACCESS_VIOLATION); a página de guarda é do `guard_page`, que tira
//!   a guarda e materializa a página pelo [`materialize`]. O frame vem do PFN
//!   antes de a região ser travada; com a região travada a página é
//!   conferida de novo (outra CPU pode tê-la materializado, liberado ou
//!   protegido no meio), zerada e mapeada com a PTE da proteção, sem
//!   execução fora das proteções executáveis (MiCompletePrivateZeroFault,
//!   0x210810). Conta no PageFaultCount do
//!   processo (EPROCESS.Vm.Instance) e nos contadores da
//!   SystemPerformanceInformation (PageFaultCount e DemandZeroCount).
//! - O NtLockVirtualMemory materializa as páginas antes de travá-las
//!   ([`make_present`], o MiLockPages faz a falta de cada uma); o
//!   NtProtectVirtualMemory só troca a proteção registrada de uma página sem
//!   frame, como o MiProtectVirtualMemory reescreve a PTE de zero sob
//!   demanda.
//!
//! Spin locks: no NT uma falta com spin lock retido é um bugcheck, e nenhum
//! caminho do kernel toca memória de usuário paginável assim. No OpenNT os
//! SpinLock do Rust guardam estado de módulos inteiros, e um serviço pode
//! tocar um buffer de usuário (ainda não tocado) com um deles retido. A
//! falta de zero sob demanda não espera E/S nem memória, então é atendida
//! também nesse caso, desde que as travas do caminho (a lista de processos,
//! o VAD e a região) estejam livres: cada uma é tentada por um tempo curto
//! (outra CPU pode estar com ela por um instante) e o frame vem só da lista
//! livre, sem recuperação. Com uma delas tomada (talvez pelo próprio
//! chamador), a falta é recusada: a sonda devolve STATUS_ACCESS_VIOLATION e
//! o acesso confiável vai ao diagnóstico da falta do anel 0. A recusa é o
//! que no 19041 seria o bugcheck: um defeito de quem tocou a página com o
//! spin lock retido, corrigido nele (materializar ou sondar a faixa antes de
//! travar). Ela é contada (a linha `[mm] frames por dono` e a `[mm]
//! memoria` mostram o total) e sai na serial com o marcador
//! `*** ZERO SOB DEMANDA RECUSADO`, uma falha para o test-boot; a sonda que a
//! sofreu registra a linha de quem a chamou.

use core::sync::atomic::{AtomicU64, Ordering};

use super::page_residency::{self, FaultResult, Provider};
use super::paging::{self, MapOptions};
use super::{memory_map as map, pfn, working_set};
use crate::hal::physical;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::Eprocess;
use crate::ntos::ps::process;
use crate::ntos::ps::user::memory::{self, PrivateMut, PrivateRegion, Space, PAGE_GUARD};
use crate::rtl::sync::{self, SpinLockGuard};
use crate::rtl::{KernelError, SpinLock};

const PAGE: u64 = map::PAGE_SIZE;
/// Tentativas de cada trava do caminho com spin locks retidos.
const LOCK_ATTEMPTS: u32 = 1 << 16;

/// As faltas de zero sob demanda atendidas (o DemandZeroCount).
static DEMAND_ZERO_FAULTS: AtomicU64 = AtomicU64::new(0);
/// As recusadas com spin locks retidos.
static REFUSED: AtomicU64 = AtomicU64::new(0);

/// O acesso da falta.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Access {
    Read,
    Write,
    Execute,
}

/// O resultado de uma falta de zero sob demanda.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// A página não é de zero sob demanda (ou a proteção recusa o acesso).
    NotDemandZero,
    /// A página tem frame agora (ou já tinha: outra CPU chegou antes).
    Resolved,
    /// Com spin locks retidos: uma trava do caminho continuou tomada, ou não
    /// havia frame na lista livre (um defeito de quem tocou a página).
    Refused,
    /// Sem spin lock retido, o PFN não deu frame nem com a recuperação.
    NoMemory,
}

/// As faltas de zero sob demanda atendidas desde o boot.
pub fn demand_zero_faults() -> u64 {
    DEMAND_ZERO_FAULTS.load(Ordering::Relaxed)
}

/// As faltas de zero sob demanda recusadas com spin locks retidos.
pub fn refused_faults() -> u64 {
    REFUSED.load(Ordering::Relaxed)
}

/// Registra o provedor de residência (no init do Mm, antes de qualquer
/// processo).
pub fn init() {
    let provider = Provider { fault, resolve, reclaim: |_| Ok(0), prepare: || Ok(()), resolve_range: Some((map::LOWEST_USER_ADDRESS, map::USER_ADDRESS_LIMIT)) };
    if let Err(error) = page_residency::register("demand zero", provider) {
        crate::debug_print!("[mm] provedor de zero sob demanda: {}", error);
    }
}

/// A proteção corrente da página.
fn protection_of(owner: &PrivateRegion, state: &PrivateMut, index: u64) -> u32 {
    state.page_protects.get(&index).copied().filter(|&protect| protect != 0).unwrap_or(owner.protect)
}

/// O MiAccessCheck de uma página privada: a proteção admite o acesso sem
/// guarda.
fn admits(protect: u32, access: Access) -> bool {
    if protect & 0xFF == 0x01 || protect & 0xFF == 0 || protect & PAGE_GUARD != 0 {
        return false;
    }
    match access {
        Access::Read => true,
        Access::Write => protect & (0x04 | 0x08 | 0x40 | 0x80) != 0,
        Access::Execute => protect & 0xF0 != 0,
    }
}

/// A trava da região: direta sem spin lock retido; senão tentada por um
/// tempo curto.
fn lock_region(owner: &PrivateRegion, locked: bool) -> Option<SpinLockGuard<'_, PrivateMut>> {
    if !locked {
        return Some(owner.state.lock());
    }
    (0..LOCK_ATTEMPTS).find_map(|_| {
        let guard = owner.state.try_lock();
        if guard.is_none() {
            core::hint::spin_loop();
        }
        guard
    })
}

/// A thread de um autoteste que provoca recusas de propósito
/// ([`capture_refusals`]) e quantas ela teve: as dela não contam como
/// defeito nem vão à serial.
static CAPTURE: SpinLock<Option<(u64, u64)>> = SpinLock::new(None);

/// Roda `body` contando à parte as recusas da thread corrente (o autoteste
/// da recusa com a trava da própria região retida); devolve o resultado e
/// quantas houve. As das outras threads continuam defeitos.
pub fn capture_refusals<R>(body: impl FnOnce() -> R) -> (R, u64) {
    let outer = CAPTURE.lock().replace((process::get_current_thread(), 0));
    let result = body();
    let captured = core::mem::replace(&mut *CAPTURE.lock(), outer).map_or(0, |(_, count)| count);
    (result, captured)
}

/// Uma falta recusada com spin locks retidos: no 19041 seria o bugcheck
/// IRQL_NOT_LESS_OR_EQUAL, então é um defeito de quem tocou a página com o
/// spin lock retido (o caminho tem de materializar ou sondar a faixa antes
/// de travar, como o MmProbeAndLockPages). Conta e sai na serial com o
/// marcador `*** ZERO SOB DEMANDA RECUSADO`, que o test-boot trata como
/// falha.
fn refuse(address: u64) -> Outcome {
    let thread = process::get_current_thread();
    {
        let mut capture = CAPTURE.lock();
        if let Some((_, count)) = capture.as_mut().filter(|(owner, _)| *owner == thread) {
            *count += 1;
            return Outcome::Refused;
        }
    }
    let count = REFUSED.fetch_add(1, Ordering::Relaxed) + 1;
    // As primeiras e depois uma a cada 64: o diagnóstico não inunda a serial.
    if count <= 16 || count % 64 == 0 {
        crate::debug_print!("*** ZERO SOB DEMANDA RECUSADO com spin lock: VA {:#x}, {} spin locks na CPU, processo {:#x}, thread {:#x} ({} recusas)", address, sync::spin_locks_held(), process::get_current_process(), thread, count);
    }
    Outcome::Refused
}

/// A falta de zero sob demanda de `address` no processo corrente (o
/// anexado, quando há attach).
pub fn resolve_current(address: u64, access: Access) -> Outcome {
    let locked = sync::spin_locks_held() != 0;
    let space = Space::current();
    let region = if locked {
        match space.try_find(address, LOCK_ATTEMPTS) {
            Ok(region) => region,
            Err(()) => return refuse(address),
        }
    } else {
        space.find(address)
    };
    let Some(region) = region else { return Outcome::NotDemandZero };
    let Some(owner) = region.as_any().downcast_ref::<PrivateRegion>() else { return Outcome::NotDemandZero };
    let outcome = zero_fault(space.root(), owner, (address - owner.base) / PAGE, Some(access), locked);
    if outcome == Outcome::Refused {
        return refuse(address);
    }
    outcome
}

/// MiResolvePrivateZeroFault da página `index` da região na raiz `root`:
/// com `access`, só se a proteção o admite; sem ele (a guarda que sai, a
/// trava de páginas), com a proteção que a página tiver.
fn zero_fault(root: u64, owner: &PrivateRegion, index: u64, access: Option<Access>, locked: bool) -> Outcome {
    let protect = {
        let Some(state) = lock_region(owner, locked) else { return Outcome::Refused };
        // Uma página que já tem frame (a de guarda, a PAGE_NOACCESS, a que o
        // corte levou à transição) não é desta falta: é da guarda ou do
        // working set. Dizer que foi resolvida repetiria a falta para sempre.
        if !state.demand_zero(index) {
            return Outcome::NotDemandZero;
        }
        protection_of(owner, &state, index)
    };
    if access.is_some_and(|access| !admits(protect, access)) {
        return Outcome::NotDemandZero;
    }
    // O frame antes da trava da região; com spin locks retidos, só da lista
    // livre (a recuperação de memória grava páginas e trava regiões).
    let frame = if locked { pfn::try_alloc_page_for(pfn::FrameUse::PrivatePageable) } else { pfn::alloc_page_for(pfn::FrameUse::PrivatePageable) };
    if frame == 0 {
        crate::debug_print!("[mm] zero sob demanda em {:#x} sem frame livre", owner.base + index * PAGE);
        return if locked { Outcome::Refused } else { Outcome::NoMemory };
    }
    physical::zero(frame, PAGE as usize);
    let Some(mut state) = lock_region(owner, locked) else {
        pfn::free_page(frame);
        return Outcome::Refused;
    };
    if !state.demand_zero(index) {
        let present = state.frames.contains_key(&index);
        drop(state);
        pfn::free_page(frame);
        return if present { Outcome::Resolved } else { Outcome::NotDemandZero };
    }
    // A proteção pode ter mudado entre as duas travas: vale a de agora.
    let protect = protection_of(owner, &state, index);
    if !paging::map_page_in(root, owner.base + index * PAGE, frame, memory::private_pte(protect), MapOptions { nx: protect & 0xF0 == 0, ..MapOptions::default() }) {
        drop(state);
        pfn::free_page(frame);
        return Outcome::NoMemory;
    }
    state.frames.insert(index, frame);
    drop(state);
    count_fault();
    Outcome::Resolved
}

/// Os contadores de uma falta de zero sob demanda atendida.
fn count_fault() {
    DEMAND_ZERO_FAULTS.fetch_add(1, Ordering::Relaxed);
    working_set::COUNTERS.page_faults.fetch_add(1, Ordering::Relaxed);
    let current = process::get_current_process();
    if current != 0 {
        // SAFETY: o EPROCESS corrente, vivo enquanto a thread roda nele.
        unsafe { Eprocess::at(current) }.vm.instance.page_fault_count.atomic().fetch_add(1, Ordering::Relaxed);
    }
}

/// Materializa a página `index` (comitada e sem frame) com a proteção que
/// ela tiver: a guarda que sai (`guard_page`). `false` se a página não é de
/// zero sob demanda ou não pôde ganhar frame.
pub fn materialize(root: u64, owner: &PrivateRegion, index: u64) -> bool {
    zero_fault(root, owner, index, None, sync::spin_locks_held() != 0) == Outcome::Resolved
}

/// As páginas `[first, end)` da região ficam presentes: as que o corte do
/// working set levou voltam (`working_set::make_resident`) e as de zero sob
/// demanda ganham frame, como o MiLockPages faz a falta de cada página. O
/// NTSTATUS da primeira que falhar.
pub fn make_present(root: u64, owner: &PrivateRegion, first: u64, end: u64) -> u32 {
    let status = working_set::make_resident(root, owner, first, end);
    if status != 0 {
        return status;
    }
    for index in first..end {
        if matches!(zero_fault(root, owner, index, None, sync::spin_locks_held() != 0), Outcome::Refused | Outcome::NoMemory) {
            return 0xC000_009A;
        }
    }
    0
}

/// A falta de página (anel 3 e anel 0) numa VA de usuário não presente.
fn fault(address: u64, error: u32) -> FaultResult {
    if error & 1 != 0 || !(map::LOWEST_USER_ADDRESS..map::USER_ADDRESS_LIMIT).contains(&address) {
        return FaultResult::NotMine;
    }
    let access = if error & 0x10 != 0 { Access::Execute } else if error & 2 != 0 { Access::Write } else { Access::Read };
    match resolve_current(address, access) {
        Outcome::Resolved => FaultResult::Resolved,
        Outcome::NotDemandZero | Outcome::Refused | Outcome::NoMemory => FaultResult::NotMine,
    }
}

/// A sonda de `guest_memory` antes de olhar as PTEs: uma página de zero sob
/// demanda ganha frame (o toque do `__try` do NT). Uma página presente não
/// passa pelo VAD.
fn resolve(address: u64) -> Result<Option<u64>, KernelError> {
    let page = address & !(PAGE - 1);
    if paging::query_page(page, false).is_some() {
        return Ok(None);
    }
    match resolve_current(page, Access::Read) {
        Outcome::Resolved => Ok(Some(paging::translate(page))),
        Outcome::NotDemandZero | Outcome::Refused | Outcome::NoMemory => Ok(None),
    }
}
