//! Zero sob demanda das alocações privadas (`mm/page_fault`), num processo
//! parado com espaço próprio, no fim da fase 7:
//!
//! - O commit de 1 MB (MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE) cobra 256
//!   páginas do commit do processo e não dá frame a nenhuma: as 256 ficam
//!   comitadas na região, sem frame, com a PTE zero, e o
//!   NtQueryVirtualMemory as descreve MEM_COMMIT.
//! - Anexado ao processo, a leitura sondada de 3 páginas devolve zeros e dá
//!   um frame a cada uma (faltas de zero sob demanda +3, PageFaultCount do
//!   processo +3, working set +3); a escrita confiável numa quarta (a falta
//!   do anel 0) também, e o valor fica.
//! - PAGE_READONLY: a leitura dá zero e a escrita sondada é
//!   STATUS_ACCESS_VIOLATION; PAGE_NOACCESS: a sonda falha e nada ganha
//!   frame.
//! - O NtProtectVirtualMemory numa faixa não tocada troca só a proteção
//!   registrada (sem frame); a falta depois dá a página com a proteção nova
//!   (PAGE_READONLY: sem escrita na PTE).
//! - O NtLockVirtualMemory numa faixa não tocada dá frame a cada página.
//! - A guarda sem frame (PAGE_READWRITE|PAGE_GUARD): o primeiro toque,
//!   anexado e fora de pilha, é STATUS_GUARD_PAGE_VIOLATION e tira a guarda
//!   dando o frame zerado; o segundo lê zero.
//! - Spin locks: com um spin lock de outro estado retido, a sonda e o acesso
//!   confiável a uma página não tocada são atendidos (o caso que o kernel do
//!   OpenNT tem e o NT não); com a trava da própria região retida, a sonda
//!   devolve STATUS_ACCESS_VIOLATION, a recusa é contada (na conta do
//!   autoteste, `page_fault::capture_refusals`, fora da de defeitos, que
//!   fica como estava) e a CPU não trava; solta a trava, a mesma sonda é
//!   atendida.
//! - O decommit de páginas não tocadas devolve o commit delas.

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::Eprocess;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::process_address_space as address_space;
use crate::ntos::mm::{page_fault, paging, process_usage, query_virtual, virtual_lock};
use crate::ntos::ps::create;
use crate::ntos::ps::process_context;
use crate::ntos::ps::user::memory::{self, PrivateRegion, Space};
use crate::ntos::ps::user::process::{self as user_process, RunOptions};
use crate::rtl::SpinLock;

type Assert = fn(bool, &str);

const PAGE: u64 = 0x1000;
const PAGES: u64 = 256;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_DECOMMIT: u32 = 0x4000;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_GUARD: u32 = 0x100;
const MAP_PROCESS: u32 = 1;

/// Um estado qualquer guardado por spin lock, alheio ao Mm.
static UNRELATED: SpinLock<u64> = SpinLock::new(0);

/// As células de kernel dos serviços (base, tamanho, proteção anterior), numa
/// região do processo corrente.
struct Cells {
    address: u64,
}

impl Cells {
    fn new() -> Option<Self> {
        memory::map_user_region(PAGE).ok().map(|address| Self { address })
    }

    fn set(&self, base: u64, size: u64) {
        guest::write64(self.address, base);
        guest::write64(self.address + 8, size);
    }

    fn base(&self) -> u64 {
        guest::read64(self.address)
    }
}

impl Drop for Cells {
    fn drop(&mut self) {
        if let Some(region) = memory::find_region(self.address) {
            memory::release_private_region(&region);
        }
    }
}

/// A região privada nova do processo, de `pages` páginas comitadas com
/// `protect`: (base, região).
fn allocate(space: Space, cells: &Cells, pages: u64, protect: u32) -> Option<(u64, crate::ntos::ps::user::state::Region)> {
    cells.set(0, pages * PAGE);
    if memory::allocate_in(space, cells.address, cells.address + 8, MEM_RESERVE | MEM_COMMIT, protect, 0, 0, 0x1_0000).ok()? != 0 {
        return None;
    }
    let base = cells.base();
    space.find(base).map(|region| (base, region))
}

fn owner(region: &crate::ntos::ps::user::state::Region) -> &PrivateRegion {
    region.as_any().downcast_ref::<PrivateRegion>().expect("regiao privada")
}

fn frames(owner: &PrivateRegion) -> usize {
    owner.state.lock().frames.len()
}

fn pte(root: u64, va: u64) -> u64 {
    paging::read_leaf_in(root, va).unwrap_or(0)
}

pub fn run(assert: Assert) {
    let Some(image) = crate::ntos::test::paging_file::parked_image() else {
        assert(false, "zero sob demanda: numero do NtTerminateProcess");
        return;
    };
    let request = user_process::windows_process_request(create::ImageOrigin::Bytes(image), "zerado.exe", "C:\\zerado.exe", &RunOptions::default());
    let Ok(child) = create::create_user_process(&request) else {
        assert(false, "zero sob demanda: processo de teste parado");
        return;
    };
    let process = child.process_pointer;
    let space = Space::of(process);
    let root = address_space::root_of(process).unwrap_or(0);
    let Some(cells) = Cells::new() else {
        assert(false, "zero sob demanda: memoria do teste");
        return;
    };
    // SAFETY: o EPROCESS do processo de teste, retido pelo `child`.
    let eprocess = unsafe { Eprocess::at(process) };
    let commit_before = eprocess.commit_charge.get();
    let Some((base, region)) = allocate(space, &cells, PAGES, PAGE_READWRITE) else {
        assert(false, "zero sob demanda: commit de 1 MB no processo de teste");
        return;
    };
    let private = owner(&region);
    let committed = private.state.lock().committed_pages.len() as u64;
    let untouched = frames(private) == 0 && (0..PAGES).all(|page| pte(root, base + page * PAGE) == 0);
    let described = query_virtual::describe_address(process, base + 7 * PAGE).state == MEM_COMMIT;
    assert(root != 0 && committed == PAGES && untouched && described && eprocess.commit_charge.get() == commit_before + PAGES, "zero sob demanda: o commit cobra 256 paginas e nao da frame a nenhuma (PTE zero, MEM_COMMIT)");

    // Os primeiros toques: três leituras sondadas e uma escrita confiável.
    let faults = page_fault::demand_zero_faults();
    let process_faults = eprocess.vm.instance.page_fault_count.get();
    let working_set = process_usage::query_working_set(process).current;
    let touched = process_context::with_process(process, || {
        let zeros = [0, 5, 200].iter().all(|&page| guest::try_read::<u64>(base + page * PAGE + 0x80).is_ok_and(|value| value == 0));
        guest::write64(base + 9 * PAGE + 8, 0x5EED);
        zeros && guest::try_read::<u64>(base + 9 * PAGE + 8).is_ok_and(|value| value == 0x5EED)
    })
    .unwrap_or(false);
    let materialized = frames(private) == 4 && [0, 5, 9, 200].iter().all(|&page| pte(root, base + page * PAGE) & 1 != 0) && pte(root, base + PAGE) == 0;
    let counted = page_fault::demand_zero_faults() >= faults + 4 && eprocess.vm.instance.page_fault_count.get() >= process_faults + 4 && process_usage::query_working_set(process).current == working_set + 4 * PAGE;
    assert(touched && materialized && counted, "zero sob demanda: o primeiro toque (sonda ou acesso confiavel) da o frame zerado, conta a falta e entra no working set");

    // A proteção de cada página.
    let Some((readonly, readonly_region)) = allocate(space, &cells, 2, PAGE_READONLY) else {
        assert(false, "zero sob demanda: commit PAGE_READONLY");
        return;
    };
    let Some((noaccess, noaccess_region)) = allocate(space, &cells, 1, PAGE_NOACCESS) else {
        assert(false, "zero sob demanda: commit PAGE_NOACCESS");
        return;
    };
    let protections = process_context::with_process(process, || {
        let read = guest::try_read::<u64>(readonly).is_ok_and(|value| value == 0);
        let write = guest::try_write::<u64>(readonly + PAGE, 1).is_err();
        let none = guest::try_read::<u64>(noaccess).is_err();
        read && write && none
    })
    .unwrap_or(false);
    let readonly_pte = pte(root, readonly);
    assert(protections && readonly_pte & 1 != 0 && readonly_pte & 2 == 0 && frames(owner(&noaccess_region)) == 0, "zero sob demanda: PAGE_READONLY le zero e recusa a escrita; PAGE_NOACCESS nao materializa");

    // NtProtectVirtualMemory e NtLockVirtualMemory em faixas não tocadas.
    cells.set(base + 16 * PAGE, 4 * PAGE);
    let protected = memory::protect_in(space, cells.address, cells.address + 8, PAGE_READONLY, cells.address + 0x10, false).unwrap_or(1) == 0;
    let recorded = (16..20).all(|page| private.state.lock().demand_zero(page) && private.state.lock().page_protects.get(&page) == Some(&PAGE_READONLY));
    let reread = process_context::with_process(process, || guest::try_read::<u64>(base + 17 * PAGE).is_ok_and(|value| value == 0) && guest::try_write::<u64>(base + 17 * PAGE, 1).is_err()).unwrap_or(false);
    assert(protected && guest::read32(cells.address + 0x10) == PAGE_READWRITE && recorded && reread && pte(root, base + 17 * PAGE) & 3 == 1, "zero sob demanda: NtProtectVirtualMemory sem frame troca so a protecao, e a falta depois a respeita");
    let locked = virtual_lock::lock(space, base + 32 * PAGE, base + 40 * PAGE, MAP_PROCESS) == 0;
    assert(locked && (32..40).all(|page| private.state.lock().frames.contains_key(&page) && pte(root, base + page * PAGE) & 1 != 0), "zero sob demanda: NtLockVirtualMemory da frame as paginas nao tocadas antes de trava-las");
    // Uma página com frame e a PTE ausente (tocada e depois PAGE_NOACCESS)
    // não é de zero sob demanda: a falta dela não é resolvida aqui (senão o
    // acesso repetiria a falta para sempre).
    cells.set(base + 5 * PAGE, PAGE);
    let hidden = memory::protect_in(space, cells.address, cells.address + 8, PAGE_NOACCESS, cells.address + 0x10, false).unwrap_or(1) == 0;
    let claimed = process_context::with_process(process, || page_fault::resolve_current(base + 5 * PAGE, page_fault::Access::Read)).unwrap_or(page_fault::Outcome::Resolved);
    assert(hidden && pte(root, base + 5 * PAGE) & 1 == 0 && private.state.lock().frames.contains_key(&5) && claimed == page_fault::Outcome::NotDemandZero, "zero sob demanda: a pagina com frame e PTE ausente (PAGE_NOACCESS) nao e resolvida como zero sob demanda");

    // A guarda sem frame.
    let Some((guard, guard_region)) = allocate(space, &cells, 1, PAGE_READWRITE | PAGE_GUARD) else {
        assert(false, "zero sob demanda: commit PAGE_GUARD");
        return;
    };
    let unguarded = frames(owner(&guard_region)) == 0;
    let (first, second) = process_context::with_process(process, || (guest::try_read::<u64>(guard).is_err(), guest::try_read::<u64>(guard).is_ok_and(|value| value == 0))).unwrap_or((false, false));
    let cleared = owner(&guard_region).state.lock().page_protects.get(&0) == Some(&PAGE_READWRITE) && frames(owner(&guard_region)) == 1;
    assert(unguarded && first && second && cleared, "zero sob demanda: a guarda sem frame falta uma vez, perde a guarda e ganha o frame zerado");

    // Com spin locks retidos.
    let refused = page_fault::refused_faults();
    let under_lock = process_context::with_process(process, || {
        let _unrelated = UNRELATED.lock();
        let probed = guest::try_read::<u64>(base + 50 * PAGE).is_ok_and(|value| value == 0);
        guest::write64(base + 51 * PAGE, 0xD15C);
        probed && guest::try_read::<u64>(base + 51 * PAGE).is_ok_and(|value| value == 0xD15C)
    })
    .unwrap_or(false);
    assert(under_lock && page_fault::refused_faults() == refused && pte(root, base + 50 * PAGE) & 1 != 0 && pte(root, base + 51 * PAGE) & 1 != 0, "zero sob demanda: com um spin lock alheio retido, a sonda e o acesso confiavel sao atendidos");
    // A recusa provocada de propósito fica na conta do autoteste, fora da
    // conta de defeitos (e da serial, onde o test-boot a leria como falha).
    let ((blocked, retried), captured) = page_fault::capture_refusals(|| {
        process_context::with_process(process, || {
            let blocked = {
                let _region = private.state.lock();
                guest::try_read::<u64>(base + 60 * PAGE).is_err()
            };
            (blocked, guest::try_read::<u64>(base + 60 * PAGE).is_ok_and(|value| value == 0))
        })
        .unwrap_or((false, false))
    });
    assert(blocked && retried && captured == 1 && page_fault::refused_faults() == refused, "zero sob demanda: com a trava da propria regiao retida a sonda e recusada e contada; solta a trava, e atendida");

    // O decommit das páginas não tocadas devolve o commit delas.
    let before = eprocess.commit_charge.get();
    cells.set(base + 100 * PAGE, 50 * PAGE);
    let decommitted = memory::free_in(space, cells.address, cells.address + 8, MEM_DECOMMIT).unwrap_or(1) == 0;
    assert(decommitted && eprocess.commit_charge.get() == before - 50 && (100..150).all(|page| !private.state.lock().committed_pages.contains(&page)), "zero sob demanda: o decommit de paginas nao tocadas devolve o commit");
    drop((readonly_region, noaccess_region, guard_region, region));
    drop(cells);
    drop(child);
}
