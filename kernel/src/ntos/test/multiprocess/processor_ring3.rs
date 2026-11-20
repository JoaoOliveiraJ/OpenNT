//! O anel 3 nos APs (`ke/smp.rs::start_scheduling`,
//! `hal/amd64/usermode.rs::processor_user_mode_init`): cada AP armado tem a
//! GDT, a TSS, a IDT, os MSRs de syscall e o timer local dele, como o
//! KiInitializeProcessor do 19041 dá a cada processador, e fica no laço
//! ocioso com as interrupções ligadas, atendendo os trabalhos da mailbox.
//!
//! - as tabelas: num trabalho em cada AP, o GDTR é a KPCR.GdtBase dele e
//!   difere do de toda outra CPU, o TR é a TSS de 0x38, a TSS (KPCR.TssBase)
//!   tem no RSP0 a pilha reserva e na IST1 a pilha da falta dupla que o AP
//!   recebeu, o IDTR é a KPCR.IdtBase (a página copiada) e difere do do BSP, o
//!   vetor 8 da IDT dele usa a IST1, o LSTAR, o STAR e o SFMASK são os do
//!   BSP, o EFER.SCE está ligado e o CR4 é o do BSP;
//! - o timer local: os tiques do AP (vetor 0x41, contados na KPCR dele)
//!   andam, e o relógio global do BSP continua só no 0x40;
//! - o anel 3 cru no CPU 1: um programa faz uma syscall de teste, que devolve
//!   o número do processador que a atende, e sai pelo código de saída do
//!   bloco da CPU;
//! - a retomada em outra CPU: uma syscall bloqueia no BSP (o quadro de troca
//!   na pilha de kernel da thread) e é retomada no CPU 1, com a KPCR.UserRsp
//!   do BSP envenenada depois do bloqueio. A volta do serviço vai ao anel 3
//!   pela KPCR da CPU que a retoma (o stub relê o RBX depois do serviço): o
//!   programa segue do ponto certo, com a pilha certa, e grava que bloqueou
//!   no processador 0 e voltou no 1.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

use crate::hal::amd64::usermode;
use crate::hal::cpu;
use crate::nano::interrupts;
use crate::ntos::ex::service_table;
use crate::ntos::inc::types::{Ethread, Kthread, NtStruct};
use crate::ntos::ke::{pcr, smp};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_stack;
use crate::ntos::ps::{cid, process};
use crate::ntos::ps::user::{memory, state};

type Assert = fn(bool, &str);

/// Os serviços de teste, índices 0-2 da tabela 1.
const PROCESSOR_SERVICE: u32 = 0x1000;
const EXIT_SERVICE: u32 = 0x1001;
const MIGRATE_SERVICE: u32 = 0x1002;
const SERVICES: usize = 3;
/// Os MSRs comparados.
const MSR_EFER: u32 = 0xC000_0080;
const MSR_STAR: u32 = 0xC000_0081;
const MSR_LSTAR: u32 = 0xC000_0082;
const MSR_SFMASK: u32 = 0xC000_0084;
/// Deslocamentos da TSS de 64 bits.
const TSS_RSP0: u64 = 4;
const TSS_IST1: u64 = 0x24;
/// O seletor da TSS na GDT de cada CPU.
const SELECTOR_TSS: u64 = 0x38;
/// A KPCR.UserRsp envenenada do BSP: uma VA de usuário sem página.
const POISON_USER_RSP: u64 = 0x7FFF_0000_1000;

static SERVICE_TABLE: [AtomicU32; SERVICES] = [const { AtomicU32::new(0) }; SERVICES];
static SERVICE_ARGUMENTS: [AtomicU8; SERVICES] = [const { AtomicU8::new(0) }; SERVICES];

/// O que o trabalho de tabelas leu num processador.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Tables {
    number: u64,
    gdtr: u64,
    gdt_base: u64,
    tr: u64,
    tss_base: u64,
    rsp0: u64,
    ist1: u64,
    idtr: u64,
    idt_base: u64,
    double_fault_ist: u64,
    lstar: u64,
    star: u64,
    sfmask: u64,
    efer: u64,
    cr4: u64,
}

const TABLE_FIELDS: usize = 15;
/// As tabelas lidas por cada AP (pelo número do processador).
static TABLES: [[AtomicU64; TABLE_FIELDS]; 16] = [const { [const { AtomicU64::new(0) }; TABLE_FIELDS] }; 16];

fn read_tables() -> Tables {
    #[repr(C, packed)]
    struct Register {
        limit: u16,
        base: u64,
    }
    let mut gdtr = Register { limit: 0, base: 0 };
    let mut idtr = Register { limit: 0, base: 0 };
    let tr: u16;
    // SAFETY: leituras dos registradores de tabela desta CPU.
    unsafe {
        core::arch::asm!("sgdt [{}]", in(reg) &mut gdtr, options(nostack));
        core::arch::asm!("sidt [{}]", in(reg) &mut idtr, options(nostack));
        core::arch::asm!("str {0:x}", out(reg) tr, options(nostack, nomem));
    }
    let kpcr = pcr::current();
    let tss = kpcr.tss_base.get();
    let idt = idtr.base;
    Tables {
        number: kpcr.prcb.number.get() as u64,
        gdtr: gdtr.base,
        gdt_base: kpcr.gdt_base.get(),
        tr: tr as u64,
        tss_base: tss,
        rsp0: if tss != 0 { guest::read64(tss + TSS_RSP0) } else { 0 },
        ist1: if tss != 0 { guest::read64(tss + TSS_IST1) } else { 0 },
        idtr: idt,
        idt_base: kpcr.idt_base.get(),
        double_fault_ist: guest::read8(idt + 8 * 16 + 4) as u64 & 7,
        lstar: cpu::read_msr(MSR_LSTAR),
        star: cpu::read_msr(MSR_STAR),
        sfmask: cpu::read_msr(MSR_SFMASK),
        efer: cpu::read_msr(MSR_EFER),
        cr4: cpu::read_cr4(),
    }
}

/// Trabalho de AP: as tabelas desta CPU em TABLES[número].
extern "win64" fn tables_job(_: u64, _: u64, _: u64, _: u64) -> u64 {
    let tables = read_tables();
    let values = [tables.number, tables.gdtr, tables.gdt_base, tables.tr, tables.tss_base, tables.rsp0, tables.ist1, tables.idtr, tables.idt_base, tables.double_fault_ist, tables.lstar, tables.star, tables.sfmask, tables.efer, tables.cr4];
    let slot = &TABLES[(tables.number as usize).min(15)];
    for (cell, value) in slot.iter().zip(values) {
        cell.store(value, Ordering::SeqCst);
    }
    1
}

fn tables_of(number: usize) -> Tables {
    let value = |index: usize| TABLES[number][index].load(Ordering::SeqCst);
    Tables {
        number: value(0),
        gdtr: value(1),
        gdt_base: value(2),
        tr: value(3),
        tss_base: value(4),
        rsp0: value(5),
        ist1: value(6),
        idtr: value(7),
        idt_base: value(8),
        double_fault_ist: value(9),
        lstar: value(10),
        star: value(11),
        sfmask: value(12),
        efer: value(13),
        cr4: value(14),
    }
}

/// Trabalho de AP: os tiques do timer local desta CPU.
extern "win64" fn ticks_job(_: u64, _: u64, _: u64, _: u64) -> u64 {
    interrupts::processor_tick_count() as u64
}

/// O número do processador que atende a syscall.
extern "win64" fn processor_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    pcr::current().prcb.number.get() as u64
}

/// A saída do anel 3 cru: o código vai ao bloco da CPU e o intervalo acaba
/// (o caminho do NtTerminateProcess do próprio processo).
extern "win64" fn exit_service(code: u64, _: u64, _: u64, _: u64) -> u64 {
    usermode::block().exit_code.set(code as u32);
    state::TERMINATE_MAGIC as u64
}

/// A thread da retomada (KTHREAD), lida pelo serviço que bloqueia.
static MIGRATING: AtomicU64 = AtomicU64::new(0);

/// Bloqueia o serviço (`usermode::block_in_service`: o quadro de troca em
/// KTHREAD.KernelStack, e o estado por CPU do serviço levado na pilha da
/// thread) e volta quando outra CPU o retoma. Devolve o número do
/// processador do bloqueio (byte 1) e o da volta (byte 0).
extern "win64" fn migrate_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    let before = pcr::current().prcb.number.get() as u64;
    // SAFETY: a KTHREAD da thread corrente, viva durante o teste.
    let kthread = unsafe { Kthread::at(MIGRATING.load(Ordering::SeqCst)) };
    usermode::block_in_service(&kthread.kernel_stack);
    let after = pcr::current().prcb.number.get() as u64;
    (before << 8) | after
}

/// `mov eax, serviço; mov r10, rcx; syscall; mov [rsp+10h], rax;
/// mov ecx, código; mov r10, rcx; mov eax, saída; syscall; jmp $`.
fn program(service: u32, code: u32) -> alloc::vec::Vec<u8> {
    let mut program = alloc::vec![0xB8];
    program.extend_from_slice(&service.to_le_bytes());
    program.extend_from_slice(&[0x49, 0x89, 0xCA, 0x0F, 0x05, 0x48, 0x89, 0x44, 0x24, 0x10, 0xB9]);
    program.extend_from_slice(&code.to_le_bytes());
    program.extend_from_slice(&[0x49, 0x89, 0xCA, 0xB8]);
    program.extend_from_slice(&EXIT_SERVICE.to_le_bytes());
    program.extend_from_slice(&[0x0F, 0x05, 0xEB, 0xFE]);
    program
}

/// O ambiente do anel 3 cru: código e pilha de usuário no processo
/// corrente e a thread (GUI, com pilha de kernel própria) que os roda.
struct RawRing3 {
    code: u64,
    stack: u64,
    thread: u64,
}

impl RawRing3 {
    fn stack_top(&self) -> u64 {
        self.stack + 0x4000 - 0x28
    }
}

/// O anel 3 cru da thread do ambiente, nesta CPU: a thread corrente é ela
/// (a raiz do processo dela) durante o intervalo. Devolve o código de saída
/// e o tipo da saída.
fn run_raw(raw: &RawRing3) -> (u64, u32) {
    let previous = process::get_current_thread();
    process::set_current_thread(raw.thread);
    let saved_exit = usermode::block().exit_code.get();
    let exited = usermode::exec_user_mode(raw.code, raw.stack_top(), 0, 0, 0, 0);
    let kind = usermode::block().exit_kind.get();
    usermode::block().exit_code.set(saved_exit);
    process::set_current_thread(previous);
    (exited, kind)
}

/// Trabalho de AP: o anel 3 cru do ambiente (o ponteiro em `raw`).
extern "win64" fn raw_job(raw: u64, _: u64, _: u64, _: u64) -> u64 {
    // SAFETY: o ambiente do teste, vivo até o trabalho acabar.
    let raw = unsafe { &*(raw as *const RawRing3) };
    run_raw(raw).0
}

/// Trabalho de AP: retoma o serviço bloqueado da thread do ambiente (o
/// quadro de troca em `saved`) nesta CPU e devolve o código de saída do
/// intervalo.
extern "win64" fn resume_job(raw: u64, saved: u64, _: u64, _: u64) -> u64 {
    // SAFETY: o ambiente do teste, vivo até o trabalho acabar.
    let raw = unsafe { &*(raw as *const RawRing3) };
    let previous = process::get_current_thread();
    process::set_current_thread(raw.thread);
    let saved_exit = usermode::block().exit_code.get();
    let result = usermode::resume_kernel_context(saved, 0) as u64;
    usermode::block().exit_code.set(saved_exit);
    process::set_current_thread(previous);
    result
}

fn tables(assert: Assert) {
    let bsp = read_tables();
    let mut all = alloc::vec![bsp];
    let mut ran = true;
    for index in 0..smp::ap_slot_count() {
        let Some(slot) = smp::ap_slot(index) else { continue };
        ran &= matches!(smp::run_on_ap(slot, tables_job as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64, [0; 4]), Ok(1));
        all.push(tables_of(index + 1));
    }
    let aps = &all[1..];
    let own = aps.iter().enumerate().all(|(index, ap)| {
        let resources = smp::ap_slot(index).and_then(smp::scheduling_resources);
        ap.number == index as u64 + 1
            && resources.is_some_and(|(fallback, double_fault, idt_frame)| ap.rsp0 == fallback && ap.ist1 == double_fault && ap.idtr == crate::hal::physical::to_virtual(idt_frame))
            && ap.gdtr == ap.gdt_base
            && ap.gdt_base == crate::ntos::mm::memory_map::PCR_VIRTUAL_BASE + ap.number * pcr::layout::SIZE + pcr::layout::PROCESSOR_GDT
            && ap.tr == SELECTOR_TSS
            && ap.tss_base == ap.gdt_base + (pcr::layout::PROCESSOR_TSS - pcr::layout::PROCESSOR_GDT)
            && ap.rsp0 != 0
            && ap.ist1 != 0
            && ap.idtr == ap.idt_base
            && ap.idtr != bsp.idtr
            && ap.double_fault_ist == 1
    });
    let distinct = all.iter().enumerate().all(|(index, first)| all[index + 1..].iter().all(|second| first.gdtr != second.gdtr && first.tss_base != second.tss_base && first.rsp0 != second.rsp0 && first.ist1 != second.ist1));
    let same_msrs = aps.iter().all(|ap| ap.lstar == bsp.lstar && ap.star == bsp.star && ap.sfmask == bsp.sfmask && ap.efer & 1 != 0 && ap.cr4 == bsp.cr4);
    if !(own && distinct && same_msrs) {
        crate::debug_print!("[anel3-ap] tabelas: {:x?}", all);
    }
    assert(ran && own, "anel3-ap: cada AP armado tem a GDT e a TSS na reserva da KPCR (GdtBase, TssBase, TR 0x38, RSP0 e IST1) e a IDT propria (IdtBase, vetor 8 na IST1)");
    assert(distinct, "anel3-ap: a GDT, a TSS e as pilhas da TSS de cada CPU sao distintas");
    assert(same_msrs, "anel3-ap: o LSTAR, o STAR, o SFMASK e o CR4 dos APs sao os do BSP, com o EFER.SCE ligado");
}

fn local_timer(assert: Assert) {
    let Some(slot) = smp::ap_slot(0) else { return };
    let job = ticks_job as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64;
    let (global, local_vector) = (interrupts::tick_count(), interrupts::irq_count(interrupts::VECTOR_LAPIC_TIMER_AP));
    let first = smp::run_on_ap(slot, job, [0; 4]);
    // Quatro tiques do BSP.
    let start = interrupts::tick_count();
    let deadline = crate::ntos::ke::clock::uptime_ms() + 2_000;
    while interrupts::tick_count().wrapping_sub(start) < 4 && crate::ntos::ke::clock::uptime_ms() < deadline {
        core::hint::spin_loop();
    }
    let second = smp::run_on_ap(slot, job, [0; 4]);
    let advanced = matches!((first, second), (Ok(first), Ok(second)) if second > first);
    let counted = interrupts::irq_count(interrupts::VECTOR_LAPIC_TIMER_AP) != local_vector && interrupts::tick_count() != global && interrupts::processor_tick_count() == interrupts::tick_count();
    assert(advanced && counted, "anel3-ap: o timer local do AP (vetor 0x41) conta os tiques dele na KPCR, e o relogio global do BSP segue so no 0x40");
}

fn raw_on_application_processor(assert: Assert, raw: &RawRing3) {
    let Some(slot) = smp::ap_slot(0) else { return };
    guest::write_bytes(raw.code, &program(PROCESSOR_SERVICE, 7));
    guest::write64(raw.stack_top() + 0x10, u64::MAX);
    let exited = smp::run_on_ap(slot, raw_job as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64, [raw as *const RawRing3 as u64, 0, 0, 0]);
    let seen = guest::read64(raw.stack_top() + 0x10);
    let exited = exited.ok();
    if exited != Some(7) || seen != 1 {
        crate::debug_print!("[anel3-ap] anel 3 cru no CPU 1: saida {:?}, processador visto {:#x}", exited, seen);
    }
    assert(exited == Some(7) && seen == 1 && !usermode::executing(), "anel3-ap: o anel 3 cru roda no CPU 1: a syscall de teste e atendida nele e o programa sai pelo bloco da CPU, sem execucao de usuario no BSP");
}

fn resume_elsewhere(assert: Assert, raw: &RawRing3) {
    let Some(slot) = smp::ap_slot(0) else { return };
    guest::write_bytes(raw.code, &program(MIGRATE_SERVICE, 9));
    guest::write64(raw.stack_top() + 0x10, u64::MAX);
    MIGRATING.store(raw.thread, Ordering::SeqCst);
    // SAFETY: a KTHREAD da thread do ambiente, retida pelo teste.
    let kthread = unsafe { Kthread::at(raw.thread) };
    let (_, kind) = run_raw(raw);
    let saved = kthread.kernel_stack.get();
    let blocked = kind == crate::hal::amd64::context_switch::EXIT_BLOCKED && saved > kthread.stack_limit.get() && saved < kthread.initial_stack.get();
    // A pilha do usuário que o BSP guardou não serve à volta em outra CPU.
    let original = pcr::current().user_rsp.get();
    pcr::current().user_rsp.set(POISON_USER_RSP);
    let resumed = if blocked { smp::run_on_ap(slot, resume_job as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64, [raw as *const RawRing3 as u64, saved, 0, 0]) } else { Ok(u64::MAX) };
    let resumed = resumed.ok();
    pcr::current().user_rsp.set(original);
    kthread.kernel_stack.set(kthread.initial_stack.get());
    let seen = guest::read64(raw.stack_top() + 0x10);
    if resumed != Some(9) || seen != 0x0001 {
        crate::debug_print!("[anel3-ap] retomada no CPU 1: bloqueio={} (tipo {}), saida {:?}, visto {:#x}", blocked, kind, resumed, seen);
    }
    assert(blocked && resumed == Some(9) && seen == 0x0001, "anel3-ap: a syscall que bloqueou no BSP e foi retomada no CPU 1 volta ao anel 3 pela KPCR do CPU 1 (pilha e ponto certos), e o programa sai la");
}

pub fn run(assert: Assert) {
    if smp::ap_slot_count() == 0 {
        return;
    }
    if !usermode::ready() {
        assert(false, "anel3-ap: anel 3 do BSP armado");
        return;
    }
    let armed = (0..smp::ap_slot_count()).filter_map(smp::ap_slot).all(|slot| smp::start_scheduling(slot).is_ok() && smp::is_scheduling(slot));
    assert(armed, "anel3-ap: todo AP online arma o anel 3 e fica no laco ocioso com as interrupcoes ligadas");
    if !armed {
        return;
    }
    tables(assert);
    local_timer(assert);
    let Ok(saved_shadow) = service_table::shadow_second_table() else {
        assert(false, "anel3-ap: descritores de servico publicados");
        return;
    };
    let table = SERVICE_TABLE.as_ptr() as u64;
    let routines: [extern "win64" fn(u64, u64, u64, u64) -> u64; SERVICES] = [processor_service, exit_service, migrate_service];
    let mut encoded = true;
    for (slot, routine) in SERVICE_TABLE.iter().zip(routines) {
        match service_table::encode_entry(table, routine as usize as u64, 0) {
            Ok(entry) => slot.store(entry, Ordering::Release),
            Err(_) => encoded = false,
        }
    }
    let scratch = guest::alloc_bytes(16);
    let allocate = |size: u64, protect: u32| {
        guest::write64(scratch, 0);
        guest::write64(scratch + 8, size);
        let status = memory::do_user_allocate(scratch, scratch + 8, 0x3000, protect, 0x10000, 0x7FFF_FFFF_0000, 0x10000).unwrap_or(1);
        if status == 0 { guest::read64(scratch) } else { 0 }
    };
    let (code, stack) = (allocate(0x1000, 0x40), allocate(0x4000, 4));
    let thread = kernel_stack::create(false).and_then(|stack| process::create_kernel_thread(process::get_current_process(), cid::ALLOCATE, true, 1, Some(stack)));
    match (&thread, encoded && code != 0 && stack != 0 && service_table::publish_shadow_second_table(table, SERVICES as u32, SERVICE_ARGUMENTS.as_ptr() as u64).is_ok()) {
        (Ok(thread), true) => {
            // A thread GUI busca no Shadow, cuja tabela 1 é a de teste.
            // SAFETY: a ETHREAD acabou de ser criada e é retida até o fim.
            let tcb = &unsafe { Ethread::at(*thread) }.tcb;
            tcb.set_gui_thread(1);
            let raw = RawRing3 { code, stack, thread: *thread };
            raw_on_application_processor(assert, &raw);
            resume_elsewhere(assert, &raw);
            tcb.set_gui_thread(0);
        }
        _ => assert(false, "anel3-ap: thread, memoria de usuario e tabela 1 de teste"),
    }
    let _ = service_table::restore_shadow_second_table(saved_shadow);
    for slot in &SERVICE_TABLE {
        slot.store(0, Ordering::Release);
    }
    if let Ok(thread) = thread {
        let _ = process::release_thread(thread);
    }
    guest::free_bytes(scratch);
    for base in [code, stack] {
        if let Some(region) = memory::find_region(base).filter(|_| base != 0) {
            memory::release_private_region(&region);
        }
    }
}
