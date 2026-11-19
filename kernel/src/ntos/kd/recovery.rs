//! Ponto de recuperação da sessão: uma falta, um KeBugCheckEx ou um pânico
//! dentro de um comando do host não derrubam o depurador.
//!
//! A sessão (`kd::session`) roda cada pacote do host com o ponto armado
//! (`run`). As consultas do OpenNT tocam estruturas do kernel com a máquina
//! parada; um ponteiro estragado nelas vira falta de proteção ou de página
//! sem tratador, um KeBugCheckEx ou um pânico do Rust. Antes, a falta caía
//! no diagnóstico fatal (`rs_kernel_exception`) com a máquina parada no meio
//! de um pacote, e o host esperava a resposta para sempre. Com o ponto
//! armado no processador da falta, o diagnóstico, o KeBugCheckEx e o pânico
//! chamam `recover`: a pilha volta ao ponto (os registradores preservados,
//! como um `longjmp`), o comando é abandonado, a sessão manda ao host o que
//! aconteceu e espera o próximo pacote. O código abandonado não roda os
//! destrutores: memória do comando fica perdida e uma trava tomada por ele
//! fica tomada (a mensagem conta as travas presas). Nada disso é pior que a
//! máquina parada sem sessão.
//!
//! Só um processador é dono da parada por vez, então há um único ponto; um
//! comando que já roda com o ponto armado não o rearma.

use core::arch::global_asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

global_asm!(
    r#"
.pushsection .text.kd, "ax", @progbits
# opennt_kd_try(rotina, argumento, ponto): guarda RBX, RBP, R12-R15, o RSP
# depois do retorno e o endereço de retorno no ponto e chama
# rotina(argumento); devolve 1 quando a rotina volta. opennt_kd_recover(ponto)
# restaura o ponto e volta ao chamador do opennt_kd_try com 0.
.global opennt_kd_try
opennt_kd_try:
    mov [rdx], rbx
    mov [rdx + 8], rbp
    mov [rdx + 16], r12
    mov [rdx + 24], r13
    mov [rdx + 32], r14
    mov [rdx + 40], r15
    lea rax, [rsp + 8]
    mov [rdx + 48], rax
    mov rax, [rsp]
    mov [rdx + 56], rax
    sub rsp, 8
    mov rax, rdi
    mov rdi, rsi
    call rax
    add rsp, 8
    mov eax, 1
    ret
.global opennt_kd_recover
opennt_kd_recover:
    mov rbx, [rdi]
    mov rbp, [rdi + 8]
    mov r12, [rdi + 16]
    mov r13, [rdi + 24]
    mov r14, [rdi + 32]
    mov r15, [rdi + 40]
    mov rsp, [rdi + 48]
    cld
    xor eax, eax
    jmp qword ptr [rdi + 56]
.popsection
"#
);

/// RBX, RBP, R12-R15, RSP e RIP do ponto.
#[repr(C)]
struct JumpBuffer([u64; 8]);

struct Point(UnsafeCell<JumpBuffer>);

// SAFETY: só o dono da parada usa o ponto, e há um dono por vez.
unsafe impl Sync for Point {}

static POINT: Point = Point(UnsafeCell::new(JumpBuffer([0; 8])));

extern "sysv64" {
    fn opennt_kd_try(routine: extern "sysv64" fn(u64), argument: u64, point: *mut JumpBuffer) -> u32;
    fn opennt_kd_recover(point: *const JumpBuffer) -> !;
}

/// Processador com o ponto armado + 1 (0 = nenhum).
static ARMED: AtomicU32 = AtomicU32::new(0);
/// Travas do kernel do processador ao armar (as presas pelo comando
/// abandonado são a diferença).
static LOCKS_BEFORE: AtomicU32 = AtomicU32::new(0);

/// O que interrompeu o último comando abandonado.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Event {
    /// Falta sem tratador: vetor, RIP, código de erro e CR2.
    Fault { vector: u8, rip: u64, error: u64, address: u64 },
    /// KeBugCheckEx: código e parâmetros.
    BugCheck { code: u32, parameters: [u64; 4] },
    /// Pânico do Rust.
    Panic,
}

const EVENT_NONE: u8 = 0;
const EVENT_FAULT: u8 = 1;
const EVENT_BUGCHECK: u8 = 2;
const EVENT_PANIC: u8 = 3;

static EVENT_KIND: AtomicU8 = AtomicU8::new(EVENT_NONE);
static EVENT_DATA: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];
/// Comandos abandonados desde o boot (para o `monitor nmi`).
static RECOVERED: AtomicU32 = AtomicU32::new(0);

fn locks_held() -> u32 {
    crate::rtl::sync::spin_locks_held() + crate::rtl::sync::shared_locks_held()
}

/// Roda `routine(argument)` no processador `number` com o ponto armado.
/// `false` quando uma falta, um KeBugCheckEx ou um pânico a interromperam
/// (`last_event` diz qual).
pub fn run(number: usize, routine: extern "sysv64" fn(u64), argument: u64) -> bool {
    if ARMED.compare_exchange(0, number as u32 + 1, Ordering::AcqRel, Ordering::Acquire).is_err() {
        // Já armado (não deveria acontecer: a sessão não se aninha).
        routine(argument);
        return true;
    }
    LOCKS_BEFORE.store(locks_held(), Ordering::Relaxed);
    let interrupts = crate::hal::cpu::interrupts_enabled();
    // SAFETY: o ponto é deste processador enquanto ARMED o aponta; a rotina
    // é `extern "sysv64"` e o argumento é dela.
    let completed = unsafe { opennt_kd_try(routine, argument, POINT.0.get()) } != 0;
    ARMED.store(0, Ordering::Release);
    // A falta entrou por um portão de interrupção (IF desligado): o IF de
    // quem armou volta.
    if !completed && interrupts {
        crate::hal::cpu::enable_interrupts();
    }
    completed
}

/// O ponto está armado no processador `number` (a falta é de um comando).
pub fn armed_here(number: usize) -> bool {
    ARMED.load(Ordering::Acquire) == number as u32 + 1
}

/// Volta ao ponto armado, abandonando o comando. Só para quem conferiu
/// `armed_here` no processador corrente.
pub fn recover(event: Event) -> ! {
    let (kind, data) = match event {
        Event::Fault { vector, rip, error, address } => (EVENT_FAULT, [vector as u64, rip, error, address, 0]),
        Event::BugCheck { code, parameters } => (EVENT_BUGCHECK, [code as u64, parameters[0], parameters[1], parameters[2], parameters[3]]),
        Event::Panic => (EVENT_PANIC, [0; 5]),
    };
    for (cell, value) in EVENT_DATA.iter().zip(data) {
        cell.store(value, Ordering::Relaxed);
    }
    EVENT_KIND.store(kind, Ordering::Release);
    RECOVERED.fetch_add(1, Ordering::Relaxed);
    // SAFETY: o ponto foi gravado pelo `opennt_kd_try` deste processador,
    // cujo quadro ainda está na pilha (a falta veio de dentro da rotina).
    unsafe { opennt_kd_recover(POINT.0.get()) }
}

/// O que interrompeu o último comando abandonado.
pub fn last_event() -> Option<Event> {
    let data: [u64; 5] = core::array::from_fn(|index| EVENT_DATA[index].load(Ordering::Relaxed));
    match EVENT_KIND.load(Ordering::Acquire) {
        EVENT_FAULT => Some(Event::Fault { vector: data[0] as u8, rip: data[1], error: data[2], address: data[3] }),
        EVENT_BUGCHECK => Some(Event::BugCheck { code: data[0] as u32, parameters: [data[1], data[2], data[3], data[4]] }),
        EVENT_PANIC => Some(Event::Panic),
        _ => None,
    }
}

/// Travas que o último comando abandonado deixou tomadas.
pub fn locks_left() -> u32 {
    locks_held().saturating_sub(LOCKS_BEFORE.load(Ordering::Relaxed))
}

/// Comandos abandonados desde o boot.
pub fn recovered() -> u32 {
    RECOVERED.load(Ordering::Relaxed)
}

/// A linha que o host recebe sobre o comando abandonado.
pub fn describe(out: &mut super::packet::Payload) {
    use core::fmt::Write;
    match last_event() {
        Some(Event::Fault { vector, rip, error, address }) => {
            let _ = write!(out, "falta dentro do depurador: vetor {:#x} em RIP={:#x} (erro {:#x}, CR2 {:#x}); comando abandonado", vector, rip, error, address);
        }
        Some(Event::BugCheck { code, parameters }) => {
            let _ = write!(out, "bugcheck {:#010x} ({:#x}, {:#x}, {:#x}, {:#x}) dentro do depurador: comando abandonado, o bugcheck nao segue", code, parameters[0], parameters[1], parameters[2], parameters[3]);
        }
        Some(Event::Panic) => out.push_str("panico dentro do depurador: comando abandonado"),
        None => out.push_str("comando abandonado"),
    }
    let left = locks_left();
    if left != 0 {
        let _ = write!(out, "; {} trava(s) do kernel ficaram tomadas pelo comando", left);
    }
    out.push(b'\n');
}
