//! Autotestes do depurador pedidos pelo host (`monitor kdtest`), para os
//! roteiros do teste `kd` (`xtask/scripts/kd-parada.txt`).
//!
//! Os pedidos ficam armados e rodam no próximo tique do relógio do BSP no
//! anel 0, com as interrupções desligadas (o tique entra no depurador pelo
//! pedido em `opennt_kd_tick_request`, mesmo sem byte na porta):
//! - `nmi [ms]`: o BSP gira com as interrupções desligadas e manda uma NMI
//!   a si mesmo depois de 50 ms. O pedido de parada do host (0x03) não
//!   seria visto ali (o tique não vem); a NMI para a máquina dentro do giro;
//! - `cli <ms>`: o mesmo giro sem a NMI própria, para o host mandar a dele
//!   (o `nmi` do monitor do QEMU);
//! - `excecao <código> <1|2>`: uma exceção de usuário sintética passa pelo
//!   filtro (`monitor sx`) e pela parada como uma de verdade;
//! - `hlt`: um `int 3` fixo seguido de `hlt`, para o passo sobre o `hlt`
//!   com o IF mascarado;
//! - `passo-falta`: um `int 3` fixo seguido de uma leitura de 3 bytes num
//!   endereço fora da forma canônica: o passo dá #GP sem tratador, que vira
//!   uma parada nova; o host pula a leitura mudando o RIP e continua.
//!
//! Dois rodam na hora, dentro do comando, e só funcionam porque a sessão
//! tem o ponto de recuperação (`kd::recovery`):
//! - `falta`: uma leitura fora da forma canônica (#GP sem tratador);
//! - `bugcheck`: KeBugCheckEx(MANUALLY_INITIATED_CRASH).
//!
//! Um roda num AP, para as paradas fora do BSP (o teste `kd-smp2`):
//! - `ap [n]`: depois de a máquina seguir, uma worker do kernel (o work item
//!   reservado no boot com o depurador, como o do `monitor kill`) põe um
//!   trabalho na caixa do primeiro AP com o anel 3 armado
//!   (`smp::start_job`); o AP executa, no laço ocioso dele, um `int 3` fixo
//!   (a parada é do AP: o BSP fica congelado) e chama `ap_target` `n`
//!   vezes, onde o roteiro arma breakpoints de software e de hardware.

use core::arch::global_asm;
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use super::packet::Payload;
use super::{exception_filter, stop, user_debug};
use crate::hal::cpu;
use crate::ntos::io::work_items;
use crate::ntos::ke::{clock, smp};

global_asm!(
    r#"
.pushsection .text.kd, "ax", @progbits
# `int 3` fixo e `hlt`: o passo sobre o `hlt` (com o IF mascarado) nao pode
# dormir.
.global opennt_kd_test_halt
opennt_kd_test_halt:
    int3
    hlt
    ret
# `int 3` fixo e uma leitura fora da forma canonica (`mov rax, [rax]`, 3
# bytes): a #GP no meio do passo vira uma parada nova.
.global opennt_kd_test_step_fault
opennt_kd_test_step_fault:
    movabs rax, 0x8000000000000000
    int3
    mov rax, qword ptr [rax]
    ret
# `int 3` fixo do trabalho do AP (`ap`): a parada do AP, com o RIP depois
# dele.
.global opennt_kd_test_processor_break
opennt_kd_test_processor_break:
    int3
    ret
.popsection
"#
);

extern "sysv64" {
    fn opennt_kd_test_halt();
    fn opennt_kd_test_step_fault() -> u64;
    fn opennt_kd_test_processor_break();
}

const TEST_NONE: u8 = 0;
const TEST_NMI: u8 = 1;
const TEST_CLI: u8 = 2;
const TEST_EXCEPTION: u8 = 3;
const TEST_HALT: u8 = 4;
const TEST_STEP_FAULT: u8 = 5;

static TEST_KIND: AtomicU8 = AtomicU8::new(TEST_NONE);
/// Milissegundos do giro, ou o código da exceção.
static TEST_ARGUMENT: AtomicU64 = AtomicU64::new(0);
static TEST_CHANCE: AtomicU8 = AtomicU8::new(0);

/// Um endereço fora da forma canônica: a leitura dá #GP.
const NONCANONICAL: u64 = 0x8000_0000_0000_0000;
/// MANUALLY_INITIATED_CRASH, o código do despejo pedido.
const MANUALLY_INITIATED_CRASH: u32 = 0xE2;

const USAGE: &str = "uso: kdtest nmi [ms] | cli <ms> | excecao <codigo> <1|2> | hlt | passo-falta | falta | bugcheck | ap [n]\n";

/// O work item do trabalho do AP (0 antes do [`initialize`]).
static AP_WORK_ITEM: AtomicU64 = AtomicU64::new(0);
/// As chamadas de `ap_target` pedidas pelo `ap` (0 = nenhum pedido).
static AP_REQUEST: AtomicU64 = AtomicU64::new(0);

/// Com o depurador ligado (`--kd`), reserva o work item do `ap` e o põe na
/// fila, à espera de um pedido (como o do `monitor kill`). Chamada uma vez
/// no boot, depois do pool.
pub fn initialize() {
    if !stop::active() || AP_WORK_ITEM.load(Ordering::Acquire) != 0 {
        return;
    }
    let item = crate::ntos::mm::guest_memory::alloc_bytes(work_items::work_item_size());
    if item == 0 {
        crate::debug_print!("[kd] work item do kdtest ap nao reservado: o autoteste fica desligado");
        return;
    }
    AP_WORK_ITEM.store(item, Ordering::Release);
    work_items::queue_kernel_work_item(item, post_processor_job, 0, Some(processor_job_requested));
}

fn processor_job_requested() -> bool {
    AP_REQUEST.load(Ordering::Acquire) != 0
}

/// A rotina do work item, a PASSIVE_LEVEL numa worker do BSP: o trabalho vai
/// à caixa do primeiro AP com o anel 3 armado, sem esperar a conclusão (a
/// máquina para no meio dele), e o item volta à fila.
fn post_processor_job(_device: u64, _context: u64) {
    let count = AP_REQUEST.load(Ordering::Acquire);
    let slot = (0..smp::ap_slot_count()).find_map(|index| smp::ap_slot(index).filter(|&slot| smp::is_scheduling(slot)));
    match slot {
        Some(slot) => match smp::start_job(slot, processor_job as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64, [count, 0, 0, 0]) {
            Ok(true) => crate::debug_print!("[kd] kdtest ap: trabalho na caixa do AP slot {} ({} chamadas)", slot, count),
            Ok(false) => crate::debug_print!("[kd] kdtest ap: a caixa do AP slot {} esta ocupada", slot),
            Err(error) => crate::debug_print!("[kd] kdtest ap: {}", error),
        },
        None => crate::debug_print!("[kd] kdtest ap: nenhum AP com o anel 3 armado (--user-smp)"),
    }
    AP_REQUEST.store(0, Ordering::Release);
    work_items::queue_kernel_work_item(AP_WORK_ITEM.load(Ordering::Acquire), post_processor_job, 0, Some(processor_job_requested));
}

/// O trabalho no AP (o laço ocioso dele, no anel 0): o `int 3` fixo e as
/// chamadas de [`ap_target`].
extern "win64" fn processor_job(count: u64, _: u64, _: u64, _: u64) -> u64 {
    // SAFETY: `int3; ret`, reconhecido pela entrada do vetor 3 do AP (a IDT
    // inteira, copiada do BSP no armar do anel 3).
    unsafe { opennt_kd_test_processor_break() };
    (0..count).fold(0, |total, index| total + ap_target(index))
}

/// O ponto dos breakpoints do roteiro no trabalho do AP.
#[inline(never)]
pub fn ap_target(index: u64) -> u64 {
    core::hint::black_box(index + 1)
}

fn arm(kind: u8, argument: u64, chance: u8, what: &str, out: &mut Payload) {
    TEST_ARGUMENT.store(argument, Ordering::Relaxed);
    TEST_CHANCE.store(chance, Ordering::Relaxed);
    TEST_KIND.store(kind, Ordering::Release);
    stop::request_tick(stop::TICK_TEST);
    let _ = writeln!(out, "autoteste armado: {} (roda no proximo tique do relogio no anel 0, depois de continuar)", what);
}

/// `kdtest ...`.
pub fn command(line: &str, out: &mut Payload) {
    let mut words = line.split_whitespace();
    let verb = words.next().unwrap_or("");
    let first = words.next();
    let second = words.next();
    let milliseconds = |word: Option<&str>, default: u64| word.and_then(|word| word.parse::<u64>().ok()).unwrap_or(default).clamp(100, 60_000);
    match verb {
        "nmi" => arm(TEST_NMI, milliseconds(first, 5_000), 0, "giro com as interrupcoes desligadas e NMI propria", out),
        "cli" => arm(TEST_CLI, milliseconds(first, 10_000), 0, "giro com as interrupcoes desligadas (mande a NMI)", out),
        "excecao" => {
            let (Some(code), Some(chance)) = (first.and_then(exception_filter::parse_code), second.and_then(|word| word.parse::<u8>().ok()).filter(|&chance| chance == 1 || chance == 2)) else {
                out.push_str(USAGE);
                return;
            };
            arm(TEST_EXCEPTION, code as u64, chance, "excecao de usuario sintetica", out);
        }
        "hlt" => arm(TEST_HALT, 0, 0, "int 3 e hlt", out),
        "passo-falta" => arm(TEST_STEP_FAULT, 0, 0, "int 3 e leitura fora da forma canonica", out),
        "falta" => {
            // SAFETY: proposital: a #GP sem tratador volta pelo ponto de
            // recuperação da sessão, e o comando é abandonado.
            let value = unsafe { core::ptr::read_volatile(NONCANONICAL as *const u64) };
            let _ = writeln!(out, "a leitura voltou {:#x}: o ponto de recuperacao nao agiu", value);
        }
        "bugcheck" => crate::ntos::ke::bugcheck::bug_check_ex(MANUALLY_INITIATED_CRASH, 0x4B44_5445_5354, 0, 0, 0),
        "ap" => {
            if AP_WORK_ITEM.load(Ordering::Acquire) == 0 {
                out.push_str("o work item do kdtest ap nao foi reservado\n");
                return;
            }
            let count = first.and_then(|word| word.parse::<u64>().ok()).unwrap_or(1).clamp(1, 16);
            AP_REQUEST.store(count, Ordering::Release);
            let _ = writeln!(out, "autoteste armado: trabalho num AP com int 3 e {} chamadas de ap_target (roda numa worker depois de continuar)", count);
        }
        _ => out.push_str(USAGE),
    }
}

/// O autoteste armado, no tique do relógio do BSP no anel 0
/// (`stop::poll`, com a máquina rodando e as interrupções desligadas).
pub fn run_armed() {
    let argument = TEST_ARGUMENT.load(Ordering::Relaxed);
    let chance = TEST_CHANCE.load(Ordering::Relaxed);
    let kind = TEST_KIND.swap(TEST_NONE, Ordering::AcqRel);
    // O host que pediu se desligou: as paradas do teste esperariam por um
    // host para sempre.
    if !super::session::attached() {
        return;
    }
    match kind {
        TEST_NMI => spin_with_interrupts_off(argument, true),
        TEST_CLI => spin_with_interrupts_off(argument, false),
        TEST_EXCEPTION => user_debug::self_test_exception(argument as u32, chance),
        // SAFETY: `int3; hlt; ret`, sem pilha nem registradores além do RIP.
        TEST_HALT => unsafe { opennt_kd_test_halt() },
        TEST_STEP_FAULT => {
            // SAFETY: a leitura só roda se o host continuar sem pular a
            // instrução; aí a #GP segue o diagnóstico, como pedido.
            let _ = unsafe { opennt_kd_test_step_fault() };
        }
        _ => {}
    }
}

/// O BSP gira `milliseconds` com as interrupções desligadas; com
/// `self_nmi`, manda uma NMI a si mesmo depois de 50 ms.
#[inline(never)]
fn spin_with_interrupts_off(milliseconds: u64, self_nmi: bool) {
    let flags = cpu::save_and_disable_interrupts();
    let start = clock::uptime_ms();
    let mut sent = !self_nmi;
    loop {
        let elapsed = clock::uptime_ms().saturating_sub(start);
        if elapsed >= milliseconds {
            break;
        }
        if !sent && elapsed >= 50 {
            sent = true;
            stop::send_self_nmi();
        }
        core::hint::spin_loop();
    }
    cpu::restore_interrupts(flags);
}
