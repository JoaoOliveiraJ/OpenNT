//! A thread corrente é por processador (`ke/pcr.rs`, `ps/process.rs`):
//! KPRCB.CurrentThread da KPCR de cada CPU, lida por gs:[188h]
//! (KeGetCurrentThread, PsGetCurrentThread) e gravada só pela troca de
//! thread que roda naquela CPU.
//!
//! Cada CPU online (o BSP e cada AP, por um job) troca a própria thread
//! corrente para uma KTHREAD de um processo de kernel só dela e espera numa
//! barreira até todas terem trocado; com todas ao mesmo tempo nas suas
//! threads, cada uma lê gs:[188h], a thread corrente, o processo corrente e
//! o TID e espera na segunda barreira antes de restaurar. Cada CPU vê a
//! própria thread e o próprio processo; o export PsGetCurrentThread,
//! chamado pelo trampolim no BSP no meio da janela, devolve a do BSP. No fim
//! a KPCR de cada AP volta à thread que tinha (nenhuma) e a do BSP à dele.
//! Com uma célula global, todas veriam a última thread gravada.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::hal::cpu;
use crate::ntos::inc::types::{Ethread, Kpcr, NtStruct};
use crate::ntos::ke::{clock, pcr, smp};
use crate::ntos::mm::memory_map as map;
use crate::ntos::ps::{cid, process};

type Assert = fn(bool, &str);

/// Prazo de cada barreira.
const BARRIER_TIMEOUT_MS: u64 = 5_000;
/// Campos lidos por cada CPU: gs:[188h], a thread corrente, o processo
/// corrente e o TID.
const FIELDS: usize = 4;

static THREADS: [AtomicU64; map::MAX_CPUS] = [const { AtomicU64::new(0) }; map::MAX_CPUS];
static SEEN: [[AtomicU64; FIELDS]; map::MAX_CPUS] = [const { [const { AtomicU64::new(0) }; FIELDS] }; map::MAX_CPUS];
static PARTICIPANTS: AtomicU32 = AtomicU32::new(0);
static ENTERED: AtomicU32 = AtomicU32::new(0);
static READ: AtomicU32 = AtomicU32::new(0);
/// O PsGetCurrentThread do trampolim, chamado pelo BSP dentro da janela.
static EXPORT_SEEN: AtomicU64 = AtomicU64::new(0);

fn gs_current_thread() -> u64 {
    let thread: u64;
    // SAFETY: leitura de um campo da KPCR desta CPU.
    unsafe { core::arch::asm!("mov {}, gs:[{}]", out(reg) thread, const pcr::layout::PRCB_CURRENT_THREAD, options(nostack, readonly, preserves_flags)) };
    thread
}

/// Espera todas as CPUs passarem por `counter`, com prazo.
fn barrier(counter: &AtomicU32) -> bool {
    let deadline = clock::uptime_ms() + BARRIER_TIMEOUT_MS;
    while counter.load(Ordering::SeqCst) < PARTICIPANTS.load(Ordering::SeqCst) {
        if clock::uptime_ms() >= deadline {
            return false;
        }
        cpu::pause();
    }
    true
}

/// A vez de uma CPU: troca a thread corrente desta CPU para a da posição
/// `index`, lê o que vê com todas trocadas e restaura a anterior.
fn take_turn(index: usize, read_export: bool) -> bool {
    let previous = process::get_current_thread();
    process::set_current_thread(THREADS[index].load(Ordering::SeqCst));
    ENTERED.fetch_add(1, Ordering::SeqCst);
    let entered = barrier(&ENTERED);
    let seen = &SEEN[index];
    seen[0].store(gs_current_thread(), Ordering::SeqCst);
    seen[1].store(process::get_current_thread(), Ordering::SeqCst);
    seen[2].store(process::get_current_process(), Ordering::SeqCst);
    seen[3].store(process::get_current_thread_id(), Ordering::SeqCst);
    if read_export {
        EXPORT_SEEN.store(crate::ntos::test::phase6::call_export("PsGetCurrentThread", &[]).unwrap_or(0), Ordering::SeqCst);
    }
    READ.fetch_add(1, Ordering::SeqCst);
    let read = barrier(&READ);
    process::set_current_thread(previous);
    entered && read
}

/// Job de AP: a vez da CPU de posição `index`; 1 com as barreiras cumpridas.
extern "win64" fn ap_turn(index: u64, _: u64, _: u64, _: u64) -> u64 {
    take_turn(index as usize, false) as u64
}

pub fn run(assert: Assert) {
    let cpus = (1 + smp::ap_slot_count()).min(map::MAX_CPUS);
    if smp::discovered_cpu_count() > 1 {
        assert(cpus > 1, "thread corrente: algum AP online");
    }
    let mut owned = Vec::new();
    for index in 0..cpus {
        let name = alloc::format!("cpu-thread-{index}");
        let Ok(owner) = process::create_process(cid::ALLOCATE, &name, 0, None) else { break };
        match process::create_kernel_thread(owner, cid::ALLOCATE, false, 0, None) {
            Ok(thread) => {
                THREADS[index].store(thread, Ordering::SeqCst);
                owned.push((owner, thread));
            }
            Err(_) => {
                let _ = process::terminate_process(owner, 0);
                break;
            }
        }
    }
    if owned.len() != cpus {
        assert(false, "thread corrente: um processo de kernel e uma thread por CPU");
    } else {
        for seen in SEEN.iter().take(cpus) {
            seen.iter().for_each(|field| field.store(0, Ordering::SeqCst));
        }
        PARTICIPANTS.store(cpus as u32, Ordering::SeqCst);
        ENTERED.store(0, Ordering::SeqCst);
        READ.store(0, Ordering::SeqCst);
        EXPORT_SEEN.store(0, Ordering::SeqCst);
        let bsp_before = process::get_current_thread();
        let routine = ap_turn as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64;
        let mut slots = Vec::new();
        for index in 1..cpus {
            let Some(slot) = smp::ap_slot(index - 1) else { break };
            if smp::start_job(slot, routine, [index as u64, 0, 0, 0]).is_ok_and(|started| started) {
                slots.push(slot);
            }
        }
        assert(slots.len() == cpus - 1, "thread corrente: job em cada AP");
        let flags = cpu::save_and_disable_interrupts();
        let bsp_turn = take_turn(0, true);
        cpu::restore_interrupts(flags);
        let ap_turns = slots.iter().all(|&slot| smp::wait_job(slot, BARRIER_TIMEOUT_MS * 3).is_ok_and(|result| result == 1));
        assert(bsp_turn && ap_turns, "thread corrente: todas as CPUs nas proprias threads ao mesmo tempo (barreiras cumpridas)");
        let mut own = true;
        for (index, &(owner, thread)) in owned.iter().enumerate() {
            // SAFETY: ETHREAD criada pelo teste e retida até o fim dele.
            let tid = unsafe { Ethread::at(thread) }.cid.unique_thread.get();
            let seen: Vec<u64> = SEEN[index].iter().map(|field| field.load(Ordering::SeqCst)).collect();
            if seen != [thread, thread, owner, tid] {
                debug_print!("[thread-corrente] CPU {} viu {:x?}, esperado [{:#x}, {:#x}, {:#x}, {:#x}]", index, seen, thread, thread, owner, tid);
                own = false;
            }
        }
        assert(own, "thread corrente: cada CPU ve em gs:[188h] a propria thread, e dela o proprio processo e TID");
        assert(EXPORT_SEEN.load(Ordering::SeqCst) == owned[0].1, "thread corrente: PsGetCurrentThread no BSP devolve a do BSP com os APs nas deles");
        let restored = (1..cpus).all(|number| {
            // SAFETY: a KPCR de um AP online fica mapeada por toda a vida do sistema.
            unsafe { Kpcr::at(map::PCR_VIRTUAL_BASE + number as u64 * pcr::layout::SIZE) }.prcb.current_thread.get() == 0
        });
        assert(restored && process::get_current_thread() == bsp_before && pcr::current().prcb.current_thread.get() == bsp_before, "thread corrente: cada CPU volta a propria thread anterior");
    }
    for (owner, thread) in owned {
        let _ = process::terminate_process(owner, 0);
        let _ = process::release_thread(thread);
    }
    THREADS.iter().for_each(|thread| thread.store(0, Ordering::SeqCst));
}
