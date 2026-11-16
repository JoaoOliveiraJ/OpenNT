//! Paradas do depurador do kernel vindas do modo usuário.
//!
//! O despacho de primeira chance de uma exceção do anel 3
//! (`ps/user/exceptions.rs`) chama `exception` antes de entregar a exceção
//! ao processo, com o CONTEXT salvo da thread (o RIP já no `int3` de um
//! vetor 3). Com um host anexado:
//!
//! - `int 3` num breakpoint do depurador gravado pela raiz deste processo
//!   (`kd::breakpoints`): a máquina para com os registradores da thread de
//!   usuário. O `int 3` de outro processo que mapeia o mesmo quadro de
//!   código passa sem parar: o byte original volta por um passo da thread
//!   (TF) e o 0xCC volta depois dele;
//! - o passo (`s`) e a saída de um breakpoint num `c` usam o TF no CONTEXT
//!   da thread: o #DB do passo volta por aqui e é reconhecido pelo CONTEXT
//!   (a identidade da thread);
//! - com `monitor uex on`, qualquer outra exceção do anel 3 também para (a
//!   primeira chance). Ao continuar, um `int 3` que não é do depurador é
//!   pulado (o RIP + 1 do KdpTrap) e as outras exceções seguem ao processo,
//!   a menos que o host tenha mudado o RIP.
//!
//! Na parada, o host vê um quadro de trap montado do CONTEXT (CS 0x33, a
//! TEB como base de GS, x87/SSE do FltSave) e o espaço de endereços é o do
//! processo. O quadro volta ao CONTEXT na saída.

use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::breakpoints::{self, HitOwner};
use super::packet::Payload;
use super::stop::{self, Kind, UserResume};
use crate::hal::amd64::irqstubs::TrapFrame;
use crate::hal::cpu;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::Context;

const TRAP_FLAG: u32 = 1 << 8;
const USER_CODE: u64 = 0x33;
const USER_DATA: u64 = 0x2B;
const VECTOR_DEBUG: u32 = 1;
const VECTOR_BREAKPOINT: u32 = 3;
const VECTOR_DEBUG_SERVICE: u32 = 0x2D;

/// O CONTEXT da thread que dá um passo do depurador (0 = nenhuma).
static STEP_CONTEXT: AtomicU64 = AtomicU64::new(0);
/// O breakpoint suspenso pelo passo (0 = nenhum).
static STEP_OVER: AtomicU64 = AtomicU64::new(0);
/// O passo só sai de um breakpoint: no fim, a thread segue sem parar.
static STEP_SILENT: AtomicBool = AtomicBool::new(false);
/// Parar em toda exceção de primeira chance do anel 3 (`monitor uex`).
static BREAK_ON_EXCEPTIONS: AtomicBool = AtomicBool::new(false);
/// Paradas e passagens (para o `monitor uex`).
static STOPS: AtomicU64 = AtomicU64::new(0);
static FOREIGN_HITS: AtomicU64 = AtomicU64::new(0);

/// Sinal do GDB para o vetor de uma exceção de usuário.
fn signal(vector: u32) -> u8 {
    match vector {
        0 | 16 | 19 => stop::SIGFPE,
        6 => stop::SIGILL,
        10..=14 | 17 => stop::SIGSEGV,
        1 | 3 => stop::SIGTRAP,
        _ => stop::SIGABRT,
    }
}

/// O `int 3`/#DB/falta do anel 3 com o CONTEXT da thread (`teb` = a TEB
/// dela). Devolve se o depurador tratou a exceção: a thread segue do
/// CONTEXT, sem entrega ao processo.
pub fn exception(context: &Context, vector: u32, teb: u64) -> bool {
    if vector == VECTOR_DEBUG_SERVICE {
        return false;
    }
    let rip = context.rip.get();
    // O passo do depurador terminou (também depois de o host se desligar:
    // o #DB do TF que o depurador ligou não vai ao processo).
    if vector == VECTOR_DEBUG && STEP_CONTEXT.load(Ordering::Acquire) == context.address() {
        STEP_CONTEXT.store(0, Ordering::Release);
        context.e_flags.set(context.e_flags.get() & !TRAP_FLAG);
        let over = STEP_OVER.swap(0, Ordering::AcqRel);
        if over != 0 {
            breakpoints::restore(over);
        }
        if STEP_SILENT.load(Ordering::Acquire) || !stop::active() || !super::session::attached() {
            return true;
        }
        return stop_here(context, teb, stop::SIGTRAP, Kind::Signal, false);
    }
    if !stop::active() || !super::session::attached() {
        return false;
    }
    if vector == VECTOR_BREAKPOINT {
        match breakpoints::classify_user_hit(rip, cpu::read_cr3()) {
            HitOwner::Mine => return stop_here(context, teb, stop::SIGTRAP, Kind::SoftwareBreak, false),
            HitOwner::Foreign => {
                FOREIGN_HITS.fetch_add(1, Ordering::Relaxed);
                breakpoints::suspend(rip);
                begin_step(context, rip, true);
                return true;
            }
            HitOwner::None => {}
        }
    }
    if BREAK_ON_EXCEPTIONS.load(Ordering::Acquire) {
        return stop_here(context, teb, signal(vector), Kind::Signal, vector == VECTOR_BREAKPOINT);
    }
    false
}

/// Liga o TF da thread para uma instrução; `over` é o breakpoint suspenso.
fn begin_step(context: &Context, over: u64, silent: bool) {
    STEP_OVER.store(over, Ordering::Release);
    STEP_SILENT.store(silent, Ordering::Release);
    STEP_CONTEXT.store(context.address(), Ordering::Release);
    context.e_flags.set(context.e_flags.get() | TRAP_FLAG);
}

/// O quadro de trap que o host vê, montado do CONTEXT.
fn frame_of(context: &Context) -> TrapFrame {
    TrapFrame {
        r15: context.r15.get(),
        r14: context.r14.get(),
        r13: context.r13.get(),
        r12: context.r12.get(),
        rbp: context.rbp.get(),
        rbx: context.rbx.get(),
        r11: context.r11.get(),
        r10: context.r10.get(),
        r9: context.r9.get(),
        r8: context.r8.get(),
        rdi: context.rdi.get(),
        rsi: context.rsi.get(),
        rdx: context.rdx.get(),
        rcx: context.rcx.get(),
        rax: context.rax.get(),
        vector: 0,
        hardware: [context.rip.get(), USER_CODE, context.e_flags.get() as u64, context.rsp.get(), USER_DATA, 0],
    }
}

/// O quadro (com as mudanças do host) de volta ao CONTEXT.
fn store_frame(context: &Context, frame: &TrapFrame) {
    context.r15.set(frame.r15);
    context.r14.set(frame.r14);
    context.r13.set(frame.r13);
    context.r12.set(frame.r12);
    context.rbp.set(frame.rbp);
    context.rbx.set(frame.rbx);
    context.r11.set(frame.r11);
    context.r10.set(frame.r10);
    context.r9.set(frame.r9);
    context.r8.set(frame.r8);
    context.rdi.set(frame.rdi);
    context.rsi.set(frame.rsi);
    context.rdx.set(frame.rdx);
    context.rcx.set(frame.rcx);
    context.rax.set(frame.rax);
    context.rip.set(frame.hardware[0]);
    // Só os bits que o anel 3 pode mudar (TF fica com o passo).
    let flags = (context.e_flags.get() & !0x0CD5) | (frame.hardware[2] as u32 & 0x0CD5);
    context.e_flags.set(flags);
    context.rsp.set(frame.hardware[3]);
}

/// A parada com o CONTEXT da thread. `skip_int3`: a exceção é um `int 3`
/// que não é do depurador (ao continuar, o RIP pula o byte).
fn stop_here(context: &Context, teb: u64, signal: u8, kind: Kind, skip_int3: bool) -> bool {
    let mut frame = frame_of(context);
    let fx = context.flt_save.address();
    let before = context.rip.get();
    STOPS.fetch_add(1, Ordering::Relaxed);
    let flags = cpu::save_and_disable_interrupts();
    let resume = stop::enter_user(&mut frame as *mut TrapFrame as u64, fx, signal, kind, 0, teb);
    cpu::restore_interrupts(flags);
    store_frame(context, &frame);
    let rip = context.rip.get();
    match resume {
        None => false,
        Some(UserResume::Step) => {
            let over = if breakpoints::inserted_at(rip) && breakpoints::suspend(rip) { rip } else { 0 };
            begin_step(context, over, false);
            true
        }
        Some(UserResume::Continue { pass }) => {
            if breakpoints::inserted_at(rip) {
                // A instrução original executa num passo; o 0xCC volta depois.
                breakpoints::suspend(rip);
                begin_step(context, rip, true);
                return true;
            }
            if kind == Kind::SoftwareBreak || rip != before {
                return true;
            }
            if skip_int3 && !pass {
                context.rip.set(rip + 1);
                return true;
            }
            // Outra exceção (ou `C sig`): segue ao processo.
            false
        }
    }
}

/// `uex [on|off]`: parar ou não nas exceções de primeira chance do anel 3.
pub fn command(argument: &str, out: &mut Payload) {
    match argument.trim() {
        "on" | "1" => BREAK_ON_EXCEPTIONS.store(true, Ordering::Release),
        "off" | "0" => BREAK_ON_EXCEPTIONS.store(false, Ordering::Release),
        _ => {}
    }
    let _ = writeln!(
        out,
        "excecoes do anel 3: {} (paradas {}, int 3 de outros processos passados {})",
        if BREAK_ON_EXCEPTIONS.load(Ordering::Acquire) { "param na primeira chance" } else { "so os breakpoints do depurador" },
        STOPS.load(Ordering::Relaxed),
        FOREIGN_HITS.load(Ordering::Relaxed)
    );
}

/// O host se desligou: um passo pendente termina sem parar.
pub fn reset() {
    STEP_SILENT.store(true, Ordering::Release);
    BREAK_ON_EXCEPTIONS.store(false, Ordering::Release);
}
