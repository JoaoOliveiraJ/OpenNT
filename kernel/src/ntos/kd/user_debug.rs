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
//! - #DB de um comparador de hardware de usuário do depurador
//!   (`kd::user_hardware`, o DR6 do CONTEXT) na thread de um processo com a
//!   mesma raiz: a máquina para; continuar de um comparador de execução
//!   desliga o comparador por um passo da thread;
//! - #PF com o bit RSVD numa página com breakpoint de memória
//!   (`kd::page_breakpoints`): a página volta ao normal, a máquina para se
//!   o tipo de acesso bate, e a instrução executa num passo antes de o bit
//!   voltar.
//!
//! Na parada, o host vê um quadro de trap montado do CONTEXT (CS 0x33, a
//! TEB como base de GS, x87/SSE do FltSave) e o espaço de endereços é o do
//! processo. Os registradores de depuração que ele lê são os do CONTEXT. O
//! quadro volta ao CONTEXT na saída.

use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::breakpoints::{self, HitOwner, Watch};
use super::packet::Payload;
use super::stop::{self, Kind, UserResume};
use super::{page_breakpoints, user_hardware};
use crate::hal::amd64::irqstubs::TrapFrame;
use crate::hal::cpu;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::Context;

const TRAP_FLAG: u32 = 1 << 8;
const USER_CODE: u64 = 0x33;
const USER_DATA: u64 = 0x2B;
const VECTOR_DEBUG: u32 = 1;
const VECTOR_BREAKPOINT: u32 = 3;
const VECTOR_PAGE_FAULT: u32 = 14;
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
/// O CONTEXT da thread parada agora (0 = nenhuma parada de usuário).
static CURRENT_CONTEXT: AtomicU64 = AtomicU64::new(0);
/// O comparador de usuário desligado pelo passo (índice + 1; 0 = nenhum).
static STEP_HARDWARE: AtomicU64 = AtomicU64::new(0);
/// A página de breakpoint de memória a rearmar depois do passo (página |
/// 1; 0 = nenhuma) e a raiz dela.
static STEP_PAGE: AtomicU64 = AtomicU64::new(0);
static STEP_PAGE_ROOT: AtomicU64 = AtomicU64::new(0);

/// O CONTEXT da thread de usuário da parada corrente, se a parada é do
/// anel 3 (os registradores de depuração que o host lê).
pub fn current_context() -> Option<u64> {
    match CURRENT_CONTEXT.load(Ordering::Acquire) {
        0 => None,
        address => Some(address),
    }
}

/// O fim do passo: o comparador e a página voltam.
fn finish_step_extras(context: &Context) {
    let hardware = STEP_HARDWARE.swap(0, Ordering::AcqRel);
    if hardware != 0 {
        user_hardware::set_enabled_in_context(context, hardware as usize - 1, true);
    }
    let page = STEP_PAGE.swap(0, Ordering::AcqRel);
    if page != 0 {
        page_breakpoints::rearm(STEP_PAGE_ROOT.load(Ordering::Acquire), page & !1);
    }
}

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
        finish_step_extras(context);
        if STEP_SILENT.load(Ordering::Acquire) || !stop::active() || !super::session::attached() {
            return true;
        }
        return stop_here(context, teb, stop::SIGTRAP, Kind::Signal, false);
    }
    if !stop::active() || !super::session::attached() {
        return false;
    }
    let root = cpu::read_cr3();
    // Um comparador de hardware de usuário do depurador.
    if vector == VECTOR_DEBUG && user_hardware::any() {
        if let Some((index, watch, address)) = user_hardware::hit(context, root) {
            let kind = if watch == Watch::Execute { Kind::HardwareBreak } else { Kind::Watch(watch) };
            if watch == Watch::Execute {
                // A instrução de novo dispararia: o comparador sai por um
                // passo (religado no fim dele).
                STEP_HARDWARE.store(index as u64 + 1, Ordering::Release);
                user_hardware::set_enabled_in_context(context, index, false);
            }
            return stop_with_data(context, teb, stop::SIGTRAP, kind, address);
        }
    }
    // Uma página com breakpoint de memória (o #PF com o bit reservado).
    if vector == VECTOR_PAGE_FAULT && page_breakpoints::any() {
        let block = crate::hal::amd64::usermode::block();
        let (cr2, error) = (block.fault_cr2.get(), block.error_code.get() as u32);
        if let Some((matches, page)) = page_breakpoints::fault(root, cr2, error) {
            STEP_PAGE_ROOT.store(root, Ordering::Release);
            STEP_PAGE.store(page | 1, Ordering::Release);
            if !matches {
                // Outro tipo de acesso: a instrução executa num passo com a
                // página normal, sem parar.
                begin_step(context, 0, true);
                return true;
            }
            let watch = if error & 2 != 0 {
                Watch::Write
            } else if error & 0x10 != 0 {
                Watch::Execute
            } else {
                Watch::Access
            };
            return stop_with_data(context, teb, stop::SIGTRAP, Kind::Memory(watch), cr2);
        }
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
    stop_inner(context, teb, signal, kind, 0, skip_int3)
}

/// A parada com um dado na resposta (o endereço vigiado).
fn stop_with_data(context: &Context, teb: u64, signal: u8, kind: Kind, data: u64) -> bool {
    stop_inner(context, teb, signal, kind, data, false)
}

fn stop_inner(context: &Context, teb: u64, signal: u8, kind: Kind, data: u64, skip_int3: bool) -> bool {
    let mut frame = frame_of(context);
    let fx = context.flt_save.address();
    let before = context.rip.get();
    STOPS.fetch_add(1, Ordering::Relaxed);
    let flags = cpu::save_and_disable_interrupts();
    CURRENT_CONTEXT.store(context.address(), Ordering::Release);
    let resume = stop::enter_user(&mut frame as *mut TrapFrame as u64, fx, signal, kind, data, teb);
    CURRENT_CONTEXT.store(0, Ordering::Release);
    cpu::restore_interrupts(flags);
    store_frame(context, &frame);
    let rip = context.rip.get();
    let debugger_kind = matches!(kind, Kind::HardwareBreak | Kind::Watch(_) | Kind::Memory(_));
    match resume {
        None => {
            // Sem a parada (depurador desligado no caminho): o comparador e
            // a página voltam já.
            finish_step_extras(context);
            debugger_kind
        }
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
            if STEP_HARDWARE.load(Ordering::Acquire) != 0 || STEP_PAGE.load(Ordering::Acquire) != 0 {
                // O comparador desligado ou a página normal valem por uma
                // instrução.
                begin_step(context, 0, true);
                return true;
            }
            if kind == Kind::SoftwareBreak || debugger_kind || rip != before {
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
