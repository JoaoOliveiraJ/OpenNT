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

use core::arch::global_asm;
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use super::packet::Payload;
use super::{exception_filter, stop, user_debug};
use crate::hal::cpu;
use crate::ntos::ke::clock;

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
.popsection
"#
);

extern "sysv64" {
    fn opennt_kd_test_halt();
    fn opennt_kd_test_step_fault() -> u64;
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

const USAGE: &str = "uso: kdtest nmi [ms] | cli <ms> | excecao <codigo> <1|2> | hlt | passo-falta | falta | bugcheck\n";

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
