//! A espera de um SharedLock disputado (`rtl::sync`, `ps/scheduler.rs`) num
//! AP: o AP roda trabalhos sem thread corrente e gira, sem rodar o
//! escalonador nele. Com o tick do contexto de boot no AP, a espera vencia os
//! timers lá, aprontava threads e despachava processos ao mesmo tempo que o
//! BSP, na pilha do trabalho: um timer que vence enquanto o BSP segura a
//! trava com as interrupções desligadas, e o AP a espera, continua não
//! sinalizado até o BSP voltar.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::cpu;
use crate::ntos::ke::{clock, smp, timer};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::sync::SharedLock;

type Assert = fn(bool, &str);

/// NotificationTimer (o tipo 8 do Header).
const NOTIFICATION_TIMER: u32 = 8;

static LOCK: SharedLock = SharedLock::new();
/// 1 depois que o trabalho do AP obteve a posse compartilhada.
static ACQUIRED: AtomicU64 = AtomicU64::new(0);

/// Job de AP: a posse compartilhada da trava (esperando o dono exclusivo).
extern "win64" fn acquire_shared(_: u64, _: u64, _: u64, _: u64) -> u64 {
    let guard = LOCK.acquire_shared();
    ACQUIRED.store(1, Ordering::SeqCst);
    drop(guard);
    1
}

pub fn run(assert: Assert) {
    let Some(slot) = smp::ap_slot(0) else { return };
    let ktimer = guest::alloc_bytes(0x40);
    if ktimer == 0 {
        assert(false, "disputa: memoria do KTIMER");
        return;
    }
    timer::initialize_timer(ktimer, NOTIFICATION_TIMER);
    ACQUIRED.store(0, Ordering::SeqCst);
    let routine = acquire_shared as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64;
    let exclusive = LOCK.acquire_exclusive();
    // Sem interrupções no BSP, só a espera do AP poderia vencer o timer.
    let flags = cpu::save_and_disable_interrupts();
    let started = smp::start_job(slot, routine, [0; 4]).is_ok_and(|started| started);
    timer::set_timer(ktimer, -10_000, 0, 0);
    clock::spin_ms(30);
    let expired_on_ap = timer::read_state(ktimer) != 0;
    let waited = ACQUIRED.load(Ordering::SeqCst) == 0;
    cpu::restore_interrupts(flags);
    drop(exclusive);
    let finished = started && smp::wait_job(slot, 10_000).is_ok_and(|result| result == 1) && ACQUIRED.load(Ordering::SeqCst) == 1;
    timer::cancel_timer(ktimer);
    guest::free_bytes(ktimer);
    assert(started && waited && finished, "disputa: o trabalho do AP espera a posse exclusiva do BSP e a obtem depois da liberacao");
    assert(!expired_on_ap, "disputa: a espera de um SharedLock num AP gira, sem rodar o escalonador nele (nenhum timer vence fora do processador de boot)");
}
