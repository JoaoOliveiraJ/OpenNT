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
//!   (a identidade da thread), numa tabela com um passo pendente por thread
//!   (outra thread pode sair de outro breakpoint antes de o #DB desta
//!   chegar); o #DB de um passo do depurador nunca vai ao processo, nem
//!   quando o passo para a máquina (o `s`) e o host continua depois. Um passo
//!   pedido numa parada do anel 0 que segue para o anel 3 (o `iretq` de
//!   volta, ou uma NMI que interrompeu o anel 3) também para aqui, pelo
//!   CONTEXT do intervalo (`arm_step_from_kernel`). O TF do passo não sai da
//!   thread: o `pushfq` passo a passo empilha o RFLAGS sem ele, e uma exceção
//!   da própria instrução (ou uma APC de usuário) que desvia o CONTEXT antes
//!   do #DB desfaz o passo antes da cópia do CONTEXT para a pilha de usuário;
//! - as outras exceções passam pelo filtro por código (`kd::exception_filter`,
//!   `monitor sx`): `monitor uex on` é o FLG_STOP_ON_EXCEPTION do KdpReport
//!   do 19041, e a tabela vale por cima dele. Ao continuar, um `int 3` que
//!   não é do depurador é pulado (o RIP + 1 do KdpTrap) e as outras exceções
//!   seguem ao processo, a menos que o host tenha mudado o RIP;
//! - a primeira chance de uma exceção levantada pelo NtRaiseException (o
//!   RaiseException da kernelbase, as exceções do C++ e do RPC) passa pelo
//!   mesmo filtro antes da entrega (`raised`);
//! - a segunda chance (`second_chance`): o NtRaiseException com
//!   FirstChance FALSE, a exceção que não pôde ser entregue e o `__fastfail`
//!   (int 0x29, que o KiFastFailDispatch do 19041 leva direto à segunda
//!   chance). É o ponto do DbgkForwardException(SecondChance), com o
//!   depurador do kernel no papel da porta de depuração; para quando a
//!   tabela pede. O fim do processo pelo NtTerminateProcess com um código
//!   da tabela também para (`terminating`): o RaiseFailFastException sem o
//!   serviço do WER termina assim, com o código (0xC0000602, ou o
//!   0xC000027B da exceção guardada do WinRT). Essas paradas são só para
//!   ver: continuar deixa o processo terminar, e o passo é recusado;
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
//! quadro volta ao CONTEXT na saída. A última exceção relatada fica no
//! `monitor exr` (o registro, o código do fast fail e as exceções guardadas
//! de um 0xC000027B).

use core::cell::UnsafeCell;
use core::fmt::Write;
use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

use super::breakpoints::{self, HitOwner, Watch};
use super::exception_filter;
use super::packet::Payload;
use super::stop::{self, Kind, UserException, UserResume};
use super::{memory, page_breakpoints, process_context, user_hardware};
use crate::hal::amd64::irqstubs::TrapFrame;
use crate::hal::cpu;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Context, ExceptionRecord};

const TRAP_FLAG: u32 = 1 << 8;
const USER_CODE: u64 = 0x33;
const USER_DATA: u64 = 0x2B;
const VECTOR_DEBUG: u32 = 1;
const VECTOR_BREAKPOINT: u32 = 3;
const VECTOR_PAGE_FAULT: u32 = 14;
const VECTOR_DEBUG_SERVICE: u32 = 0x2D;
/// EXCEPTION_NONCONTINUABLE.
const NONCONTINUABLE: u32 = 1;
const RECORD_SIZE: usize = size_of::<ExceptionRecord>();

/// Um passo do depurador numa thread de usuário: o TF está ligado no
/// CONTEXT dela e o #DB que ele dá é do depurador, nunca do processo.
/// Cada thread tem o seu: entre o `iretq` com o TF e a instrução, o tique
/// pode trocar de thread, e outra thread pode passar por cima de outro
/// breakpoint antes de o #DB desta chegar (um único passo global perdia o
/// primeiro, e o STATUS_SINGLE_STEP ia ao processo).
struct PendingStep {
    /// O CONTEXT da thread (0 = vaga livre).
    context: AtomicU64,
    /// O breakpoint suspenso pelo passo (0 = nenhum).
    over: AtomicU64,
    /// O passo só sai de um breakpoint: no fim, a thread segue sem parar.
    silent: AtomicBool,
    /// A instrução do passo é um `pushfq`: o RFLAGS empilhado leva o TF do
    /// passo, que sai da pilha no fim dele.
    pushf: AtomicBool,
}

/// O fim de um passo pendente (`take_step`).
#[derive(Clone, Copy)]
struct TakenStep {
    over: u64,
    silent: bool,
    pushf: bool,
}

/// Passos pendentes no máximo (threads entre o `iretq` com o TF e o #DB).
const STEP_SLOTS: usize = 128;

static STEPS: [PendingStep; STEP_SLOTS] = [const { PendingStep { context: AtomicU64::new(0), over: AtomicU64::new(0), silent: AtomicBool::new(false), pushf: AtomicBool::new(false) } }; STEP_SLOTS];
/// Passos que não acharam vaga (a tabela cheia).
static STEP_OVERFLOWS: AtomicU64 = AtomicU64::new(0);
/// Passos desfeitos porque a exceção da própria instrução (ou uma APC) foi
/// ao processo antes do #DB.
static STEPS_ABANDONED: AtomicU64 = AtomicU64::new(0);

/// Registra o passo da thread do CONTEXT `context` (a vaga dela, ou uma
/// livre). Sem vaga, devolve `false`: o TF não deve ser ligado.
fn push_step(context: u64, over: u64, silent: bool, pushf: bool) -> bool {
    let slot = STEPS.iter().find(|slot| slot.context.load(Ordering::Acquire) == context).or_else(|| STEPS.iter().find(|slot| slot.context.compare_exchange(0, context, Ordering::AcqRel, Ordering::Acquire).is_ok()));
    let Some(slot) = slot else {
        STEP_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
        return false;
    };
    slot.over.store(over, Ordering::Release);
    slot.silent.store(silent, Ordering::Release);
    slot.pushf.store(pushf, Ordering::Release);
    true
}

/// Tira o passo pendente da thread do CONTEXT `context`, ou `None` se o #DB
/// não é de um passo do depurador.
fn take_step(context: u64) -> Option<TakenStep> {
    let slot = STEPS.iter().find(|slot| slot.context.load(Ordering::Acquire) == context)?;
    let found = TakenStep { over: slot.over.swap(0, Ordering::AcqRel), silent: slot.silent.load(Ordering::Acquire), pushf: slot.pushf.load(Ordering::Acquire) };
    slot.context.store(0, Ordering::Release);
    Some(found)
}

/// A instrução em `rip` (no espaço do processador, com os bytes originais
/// por baixo dos breakpoints) é um `pushfq`, com prefixos.
fn is_pushf(rip: u64) -> bool {
    let cr3 = cpu::read_cr3();
    let mut bytes = [0u8; 8];
    let length = memory::read(cr3, rip, &mut bytes);
    breakpoints::mask_read(cr3, rip, &mut bytes[..length]);
    bytes[..length].iter().find(|&&byte| !matches!(byte, 0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67 | 0xF2 | 0xF3 | 0x40..=0x4F)) == Some(&0x9C)
}

/// O passo terminou num `pushfq`: o RFLAGS no topo da pilha de usuário sai
/// sem o TF (um `popfq` depois o religaria e o #DB iria ao processo como
/// STATUS_SINGLE_STEP, como no começo do RtlCaptureContext do ntdll).
fn clear_pushed_trap_flag(context: &Context) {
    let (cr3, rsp) = (cpu::read_cr3(), context.rsp.get());
    if let Some(pushed) = memory::read_u64(cr3, rsp) {
        memory::write_u64(cr3, rsp, pushed & !(TRAP_FLAG as u64));
    }
}

/// A thread sai da instrução do passo sem o #DB dele: a exceção da própria
/// instrução vai ao processo, ou uma APC de usuário desvia o CONTEXT. O
/// passo acaba aqui: o TF sai do CONTEXT (o despachante copia o CONTEXT para
/// a pilha de usuário, e um NtContinue mais tarde religaria o TF fora do
/// depurador) e o breakpoint suspenso volta (a instrução repetida depois do
/// tratador bate nele de novo).
fn abandon_step(context: &Context) {
    let Some(step) = take_step(context.address()) else { return };
    context.e_flags.set(context.e_flags.get() & !TRAP_FLAG);
    if step.over != 0 {
        breakpoints::restore(step.over);
    }
    finish_step_extras(context);
    STEPS_ABANDONED.fetch_add(1, Ordering::Relaxed);
}

/// O CONTEXT da thread vai ser desviado para um despachante do ntdll (a
/// entrega de uma APC de usuário): um passo do depurador armado nele acaba
/// antes (`abandon_step`).
pub fn context_redirected(context: &Context) {
    if pending_steps() != 0 {
        abandon_step(context);
    }
}

/// O depurador armou um passo para a thread do CONTEXT `context`: a volta
/// dela ao anel 3 passa pelo CONTEXT (o TF do passo).
pub fn step_armed(context: u64) -> bool {
    context != 0 && STEPS.iter().any(|slot| slot.context.load(Ordering::Acquire) == context)
}

/// Passos pendentes agora (o `monitor uex`).
fn pending_steps() -> usize {
    STEPS.iter().filter(|slot| slot.context.load(Ordering::Acquire) != 0).count()
}
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

/// A última exceção relatada ao host (o `monitor exr`).
struct LastException {
    code: AtomicU32,
    flags: AtomicU32,
    address: AtomicU64,
    count: AtomicU32,
    information: [AtomicU64; 15],
    /// 0 = nenhuma, 1 = primeira chance, 2 = segunda chance.
    chance: AtomicU8,
    termination: AtomicBool,
    process: AtomicU64,
    process_id: AtomicU64,
    thread_id: AtomicU64,
}

static LAST: LastException = LastException {
    code: AtomicU32::new(0),
    flags: AtomicU32::new(0),
    address: AtomicU64::new(0),
    count: AtomicU32::new(0),
    information: [const { AtomicU64::new(0) }; 15],
    chance: AtomicU8::new(0),
    termination: AtomicBool::new(false),
    process: AtomicU64::new(0),
    process_id: AtomicU64::new(0),
    thread_id: AtomicU64::new(0),
};

/// O CONTEXT de mentira do autoteste `kdtest excecao`.
#[repr(C, align(16))]
struct TestContext(UnsafeCell<[u8; size_of::<Context>()]>);

// SAFETY: só o autoteste usa o bloco, no tique do relógio do BSP.
unsafe impl Sync for TestContext {}

static TEST_CONTEXT: TestContext = TestContext(UnsafeCell::new([0; size_of::<Context>()]));
/// RIP e RSP do CONTEXT de mentira: metade de usuário, sem memória por trás.
const TEST_RIP: u64 = 0x7FFE_0000_1000;
const TEST_RSP: u64 = 0x7FFE_0000_8000;

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

/// Sinal do GDB para o código de uma exceção (as levantadas por software,
/// a segunda chance e o fim do processo).
fn signal_for_code(code: u32) -> u8 {
    match code {
        0xC000_0005 | 0xC000_0006 | 0x8000_0001 | 0x8000_0002 | 0xC000_00FD => stop::SIGSEGV,
        0xC000_001D | 0xC000_0096 => stop::SIGILL,
        0xC000_008C..=0xC000_0095 => stop::SIGFPE,
        0x8000_0003 | 0x8000_0004 => stop::SIGTRAP,
        exception_filter::STATUS_STACK_BUFFER_OVERRUN | exception_filter::STATUS_FAIL_FAST_EXCEPTION | exception_filter::STATUS_STOWED_EXCEPTION | 0xC000_0374 | 0xC000_0420 => stop::SIGABRT,
        _ => stop::SIGTRAP,
    }
}

fn record_u32(record: &[u8], offset: usize) -> u32 {
    record.get(offset..offset + 4).map_or(0, |bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn record_u64(record: &[u8], offset: usize) -> u64 {
    record.get(offset..offset + 8).and_then(|bytes| bytes.try_into().ok()).map_or(0, u64::from_le_bytes)
}

fn record_code(record: &[u8]) -> u32 {
    record_u32(record, offset_of!(ExceptionRecord, exception_code))
}

/// A exceção relatada vai ao `monitor exr`.
fn note(record: &[u8], chance: u8, termination: bool) {
    LAST.code.store(record_code(record), Ordering::Relaxed);
    LAST.flags.store(record_u32(record, offset_of!(ExceptionRecord, exception_flags)), Ordering::Relaxed);
    LAST.address.store(record_u64(record, offset_of!(ExceptionRecord, exception_address)), Ordering::Relaxed);
    let count = record_u32(record, offset_of!(ExceptionRecord, number_parameters)).min(15);
    LAST.count.store(count, Ordering::Relaxed);
    let information = offset_of!(ExceptionRecord, exception_information);
    for (index, cell) in LAST.information.iter().enumerate() {
        cell.store(if (index as u32) < count { record_u64(record, information + index * 8) } else { 0 }, Ordering::Relaxed);
    }
    LAST.termination.store(termination, Ordering::Relaxed);
    LAST.process.store(crate::ntos::ps::process::get_current_process(), Ordering::Relaxed);
    LAST.process_id.store(crate::ntos::ps::process::get_current_process_id(), Ordering::Relaxed);
    LAST.thread_id.store(crate::ntos::ps::process::get_current_thread_id(), Ordering::Relaxed);
    LAST.chance.store(chance, Ordering::Release);
}

/// O `int 3`/#DB/falta do anel 3 com o CONTEXT da thread (`teb` = a TEB
/// dela) e o registro montado pelo despacho. Devolve se o depurador tratou
/// a exceção: a thread segue do CONTEXT, sem entrega ao processo.
pub fn exception(context: &Context, vector: u32, teb: u64, record: &[u8]) -> bool {
    if vector == VECTOR_DEBUG_SERVICE {
        return false;
    }
    // O passo do depurador terminou (também depois de o host se desligar:
    // o #DB do TF que o depurador ligou não vai ao processo).
    if vector == VECTOR_DEBUG {
        if let Some(step) = take_step(context.address()) {
            context.e_flags.set(context.e_flags.get() & !TRAP_FLAG);
            if step.pushf {
                clear_pushed_trap_flag(context);
            }
            if step.over != 0 {
                breakpoints::restore(step.over);
            }
            finish_step_extras(context);
            // Também depois de o host se desligar: o passo termina sem parar.
            if silent_end(step) {
                return true;
            }
            return stop_after_step(context, teb);
        }
    }
    let handled = dispatch(context, vector, teb, record);
    if !handled {
        // A exceção vai ao processo: um passo armado nesta thread não chega
        // ao #DB (a instrução faltou antes de terminar).
        abandon_step(context);
    }
    handled
}

/// O passo termina sem parar: a saída de um breakpoint, ou o host já não
/// está lá.
fn silent_end(step: TakenStep) -> bool {
    step.silent || !stop::active() || !super::session::attached()
}

/// O resto do `exception`, depois do passo do depurador.
fn dispatch(context: &Context, vector: u32, teb: u64, record: &[u8]) -> bool {
    let rip = context.rip.get();
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
    let code = record_code(record);
    let stops = exception_filter::first_chance(code, BREAK_ON_EXCEPTIONS.load(Ordering::Acquire));
    exception_filter::count(code, stops);
    if stops {
        note(record, 1, false);
        let exception = UserException { code, chance: 1, termination: false };
        return stop_inner(context, teb, signal(vector), Kind::Signal, 0, vector == VECTOR_BREAKPOINT, false, Some(exception));
    }
    false
}

/// A primeira chance de uma exceção levantada pelo NtRaiseException, antes
/// da entrega ao processo. Devolve se o depurador tratou a exceção (o host
/// mudou o RIP ou pediu um passo): a thread segue do CONTEXT, sem entrega.
pub fn raised(context: &Context, teb: u64, record: &[u8]) -> bool {
    if !stop::active() || !super::session::attached() {
        return false;
    }
    let code = record_code(record);
    let stops = exception_filter::first_chance(code, BREAK_ON_EXCEPTIONS.load(Ordering::Acquire));
    exception_filter::count(code, stops);
    if !stops {
        return false;
    }
    note(record, 1, false);
    let exception = UserException { code, chance: 1, termination: false };
    stop_inner(context, teb, signal_for_code(code), Kind::Signal, 0, false, false, Some(exception))
}

/// A segunda chance de uma exceção do anel 3 (o DbgkForwardException com
/// SecondChance): o processo termina com o código depois dela, qualquer que
/// seja a resposta do host.
pub fn second_chance(context: &Context, teb: u64, record: &[u8]) {
    observe(context, teb, record, false);
}

/// O NtTerminateProcess do próprio processo com `code`, com a thread na
/// chamada (`context`, o CONTEXT da syscall; 0 sem ele): para quando a
/// tabela pede a segunda chance do código.
pub fn terminating(context: u64, teb: u64, code: u32) {
    if context == 0 || code == 0 || !stop::active() || !super::session::attached() || !exception_filter::second_chance(code) {
        return;
    }
    // SAFETY: o CONTEXT da thread viva que chamou (memória do kernel).
    let context = unsafe { Context::at(context) };
    let mut record = [0u8; RECORD_SIZE];
    record[offset_of!(ExceptionRecord, exception_code)..][..4].copy_from_slice(&code.to_le_bytes());
    record[offset_of!(ExceptionRecord, exception_flags)..][..4].copy_from_slice(&NONCONTINUABLE.to_le_bytes());
    record[offset_of!(ExceptionRecord, exception_address)..][..8].copy_from_slice(&context.rip.get().to_le_bytes());
    observe(context, teb, &record, true);
}

/// A parada só para ver (segunda chance ou fim do processo): o quadro do
/// CONTEXT, sem passo nem saída de breakpoint, e o CONTEXT intocado.
fn observe(context: &Context, teb: u64, record: &[u8], termination: bool) {
    if !stop::active() || !super::session::attached() {
        return;
    }
    let code = record_code(record);
    let stops = exception_filter::second_chance(code);
    exception_filter::count(code, stops);
    if !stops {
        return;
    }
    note(record, 2, termination);
    let mut frame = frame_of(context);
    let fx = context.flt_save.address();
    STOPS.fetch_add(1, Ordering::Relaxed);
    let flags = cpu::save_and_disable_interrupts();
    CURRENT_CONTEXT.store(context.address(), Ordering::Release);
    let exception = UserException { code, chance: 2, termination };
    let _ = stop::enter_user(&mut frame as *mut TrapFrame as u64, fx, signal_for_code(code), Kind::Signal, 0, teb, Some(exception));
    CURRENT_CONTEXT.store(0, Ordering::Release);
    cpu::restore_interrupts(flags);
}

/// O passo pedido numa parada do anel 0 segue no anel 3 (o TF já está no
/// quadro que volta ao usuário): o #DB que ele dá na thread do intervalo
/// (o CONTEXT `context`) para a máquina aqui.
pub fn arm_step_from_kernel(context: u64) {
    push_step(context, 0, false, false);
}

/// Liga o TF da thread para uma instrução; `over` é o breakpoint suspenso.
/// Sem vaga na tabela de passos, o TF não liga: o breakpoint suspenso volta
/// já (a instrução original não executa por baixo dele; a thread bate nele
/// de novo, o que é melhor que um #DB entregue ao processo).
fn begin_step(context: &Context, over: u64, silent: bool) {
    if !push_step(context.address(), over, silent, is_pushf(context.rip.get())) {
        if over != 0 {
            breakpoints::restore(over);
        }
        return;
    }
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
    stop_inner(context, teb, signal, kind, 0, skip_int3, false, None)
}

/// A parada no fim de um passo do depurador (`s` numa parada de usuário, ou
/// o passo de uma parada do anel 0 que seguiu para o anel 3). O #DB é do
/// depurador: continuar não o entrega ao processo (o KdpTrap do 19041
/// consome o STATUS_SINGLE_STEP de um passo do kd), só um `C sig` explícito.
fn stop_after_step(context: &Context, teb: u64) -> bool {
    stop_inner(context, teb, stop::SIGTRAP, Kind::Signal, 0, false, true, None)
}

/// A parada com um dado na resposta (o endereço vigiado).
fn stop_with_data(context: &Context, teb: u64, signal: u8, kind: Kind, data: u64) -> bool {
    stop_inner(context, teb, signal, kind, data, false, false, None)
}

/// `owned`: a exceção da parada é do depurador (o #DB de um passo dele) e
/// não vai ao processo ao continuar.
#[allow(clippy::too_many_arguments)]
fn stop_inner(context: &Context, teb: u64, signal: u8, kind: Kind, data: u64, skip_int3: bool, owned: bool, exception: Option<UserException>) -> bool {
    let mut frame = frame_of(context);
    let fx = context.flt_save.address();
    let before = context.rip.get();
    STOPS.fetch_add(1, Ordering::Relaxed);
    let flags = cpu::save_and_disable_interrupts();
    CURRENT_CONTEXT.store(context.address(), Ordering::Release);
    let resume = stop::enter_user(&mut frame as *mut TrapFrame as u64, fx, signal, kind, data, teb, exception);
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
            debugger_kind || owned
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
            if owned {
                return !pass;
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

/// O autoteste `kdtest excecao`: uma exceção de usuário sintética passa
/// pelo filtro e pela parada como uma de verdade (primeira chance pelo
/// caminho do NtRaiseException, segunda chance pelo da segunda chance), com
/// um CONTEXT de mentira. Roda no tique do relógio do BSP.
pub fn self_test_exception(code: u32, chance: u8) {
    // SAFETY: o bloco estático alinhado do tamanho do CONTEXT, só deste
    // autoteste.
    let context = unsafe {
        (*TEST_CONTEXT.0.get()).fill(0);
        Context::at(TEST_CONTEXT.0.get() as u64)
    };
    context.rip.set(TEST_RIP);
    context.rsp.set(TEST_RSP);
    context.e_flags.set(0x202);
    let mut record = [0u8; RECORD_SIZE];
    record[offset_of!(ExceptionRecord, exception_code)..][..4].copy_from_slice(&code.to_le_bytes());
    record[offset_of!(ExceptionRecord, exception_address)..][..8].copy_from_slice(&TEST_RIP.to_le_bytes());
    if chance >= 2 {
        record[offset_of!(ExceptionRecord, exception_flags)..][..4].copy_from_slice(&NONCONTINUABLE.to_le_bytes());
        second_chance(context, 0, &record);
    } else {
        // Um passo pedido aqui ficaria armado no CONTEXT de mentira: desfeito.
        let _ = raised(context, 0, &record);
        let _ = take_step(context.address());
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
        "excecoes do anel 3: {} (paradas {}, int 3 de outros processos passados {}, passos pendentes {}, passos sem vaga {}, passos desfeitos por excecao ou APC {}; por codigo: monitor sx)",
        if BREAK_ON_EXCEPTIONS.load(Ordering::Acquire) { "param na primeira chance" } else { "so os breakpoints do depurador" },
        STOPS.load(Ordering::Relaxed),
        FOREIGN_HITS.load(Ordering::Relaxed),
        pending_steps(),
        STEP_OVERFLOWS.load(Ordering::Relaxed),
        STEPS_ABANDONED.load(Ordering::Relaxed)
    );
}

/// Os códigos do `__fastfail` (FAST_FAIL_* do winnt.h) mais comuns.
fn fast_fail_name(code: u64) -> Option<&'static str> {
    Some(match code {
        0 => "FAST_FAIL_LEGACY_GS_VIOLATION",
        1 => "FAST_FAIL_VTGUARD_CHECK_FAILURE",
        2 => "FAST_FAIL_STACK_COOKIE_CHECK_FAILURE",
        3 => "FAST_FAIL_CORRUPT_LIST_ENTRY",
        4 => "FAST_FAIL_INCORRECT_STACK",
        5 => "FAST_FAIL_INVALID_ARG",
        6 => "FAST_FAIL_GS_COOKIE_INIT",
        7 => "FAST_FAIL_FATAL_APP_EXIT",
        8 => "FAST_FAIL_RANGE_CHECK_FAILURE",
        9 => "FAST_FAIL_UNSAFE_REGISTRY_ACCESS",
        10 => "FAST_FAIL_GUARD_ICALL_CHECK_FAILURE",
        11 => "FAST_FAIL_GUARD_WRITE_CHECK_FAILURE",
        12 => "FAST_FAIL_INVALID_FIBER_SWITCH",
        13 => "FAST_FAIL_INVALID_SET_OF_CONTEXT",
        14 => "FAST_FAIL_INVALID_REFERENCE_COUNT",
        18 => "FAST_FAIL_INVALID_JUMP_BUFFER",
        19 => "FAST_FAIL_MRDATA_MODIFIED",
        20 => "FAST_FAIL_CERTIFICATION_FAILURE",
        21 => "FAST_FAIL_INVALID_EXCEPTION_CHAIN",
        22 => "FAST_FAIL_CRYPTO_LIBRARY",
        23 => "FAST_FAIL_INVALID_CALL_IN_DLL_CALLOUT",
        _ => return None,
    })
}

/// STOWED_EXCEPTION_INFORMATION_V1/V2 (winnt.h): cabeçalho (Size,
/// Signature 'SE01'/'SE02'), ResultCode, ExceptionForm:2 | ThreadId:30 e
/// ExceptionAddress, StackTraceWordSize, StackTraceWords e StackTrace (forma
/// 1) ou ErrorText (forma 2).
const STOWED_V1: u32 = 0x5345_3031;
const STOWED_V2: u32 = 0x5345_3032;

/// As exceções guardadas de um 0xC000027B: ExceptionInformation[0] aponta o
/// vetor de ponteiros e [1] é a quantidade.
fn stowed_exceptions(root: u64, array: u64, count: u64, out: &mut Payload) {
    for index in 0..count.min(8) {
        let Some(entry) = memory::read_u64(root, array.wrapping_add(index * 8)).filter(|&entry| entry != 0) else {
            let _ = writeln!(out, "    [{}] ponteiro ilegivel", index);
            continue;
        };
        let signature = memory::read_u32(root, entry + 4).unwrap_or(0);
        if signature != STOWED_V1 && signature != STOWED_V2 {
            let _ = writeln!(out, "    [{}] {:#x}: assinatura {:#x} desconhecida", index, entry, signature);
            continue;
        }
        let result = memory::read_u32(root, entry + 8).unwrap_or(0);
        let form = memory::read_u32(root, entry + 0xC).unwrap_or(0);
        let _ = write!(out, "    [{}] {:#x} ResultCode {:#010x} thread {:#x}", index, entry, result, form >> 2);
        match form & 3 {
            1 => {
                let address = memory::read_u64(root, entry + 0x10).unwrap_or(0);
                let words = memory::read_u32(root, entry + 0x1C).unwrap_or(0);
                let trace = memory::read_u64(root, entry + 0x20).unwrap_or(0);
                let _ = writeln!(out, " endereco {:#x}, pilha de {} palavras em {:#x}", address, words, trace);
            }
            2 => {
                let text = memory::read_u64(root, entry + 0x10).unwrap_or(0);
                out.push_str(" texto \"");
                for character in 0..80u64 {
                    let Some(unit) = memory::read_u16(root, text.wrapping_add(character * 2)).filter(|&unit| unit != 0) else { break };
                    out.push(if (0x20..0x7F).contains(&unit) { unit as u8 } else { b'?' });
                }
                out.push_str("\"\n");
            }
            other => {
                let _ = writeln!(out, " forma {}", other);
            }
        }
    }
}

/// `exr`: a última exceção do anel 3 relatada ao host.
pub fn exr_command(owner: usize, out: &mut Payload) {
    let chance = LAST.chance.load(Ordering::Acquire);
    if chance == 0 {
        out.push_str("nenhuma excecao do anel 3 relatada\n");
        return;
    }
    let code = LAST.code.load(Ordering::Relaxed);
    let what = if LAST.termination.load(Ordering::Relaxed) {
        "fim do processo com o codigo (NtTerminateProcess)"
    } else if chance == 1 {
        "primeira chance"
    } else {
        "segunda chance"
    };
    let _ = writeln!(out, "excecao do anel 3, {}: {:#010x} {}", what, code, exception_filter::name(code).unwrap_or(""));
    let cr3 = stop::address_space(owner);
    let process = LAST.process.load(Ordering::Relaxed);
    let mut name = [0u8; 16];
    let length = if process != 0 { super::monitor::process_name(cr3, process, &mut name) } else { 0 };
    let _ = write!(out, "  processo {:#x} pid {:#x} tid {:#x} ", process, LAST.process_id.load(Ordering::Relaxed), LAST.thread_id.load(Ordering::Relaxed));
    super::monitor::push_name(out, &name[..length]);
    out.push(b'\n');
    let flags = LAST.flags.load(Ordering::Relaxed);
    let _ = writeln!(out, "  flags {:#x}{} endereco {:#x}", flags, if flags & NONCONTINUABLE != 0 { " (nao continuavel)" } else { "" }, LAST.address.load(Ordering::Relaxed));
    let count = LAST.count.load(Ordering::Relaxed) as usize;
    let information: [u64; 15] = core::array::from_fn(|index| LAST.information[index].load(Ordering::Relaxed));
    if count != 0 {
        let _ = write!(out, "  parametros ({}):", count);
        for value in &information[..count] {
            let _ = write!(out, " {:#x}", value);
        }
        out.push(b'\n');
    }
    match code {
        exception_filter::STATUS_STACK_BUFFER_OVERRUN if count >= 1 => {
            let _ = writeln!(out, "  codigo do fast fail {} {}", information[0], fast_fail_name(information[0]).unwrap_or(""));
        }
        0xC000_0005 | 0xC000_0006 if count >= 2 => {
            let access = match information[0] {
                0 => "leitura",
                1 => "escrita",
                8 => "execucao",
                _ => "acesso",
            };
            let _ = writeln!(out, "  {} em {:#x}", access, information[1]);
        }
        exception_filter::STATUS_STOWED_EXCEPTION if count >= 2 => {
            let _ = writeln!(out, "  {} excecao(oes) guardada(s) em {:#x}:", information[1], information[0]);
            let root = process_context::root_of(cr3, process).unwrap_or(cr3);
            stowed_exceptions(root, information[0], information[1], out);
        }
        _ => {}
    }
}

/// O host se desligou: um passo pendente termina sem parar, e o filtro por
/// código volta ao padrão.
pub fn reset() {
    BREAK_ON_EXCEPTIONS.store(false, Ordering::Release);
    exception_filter::clear();
}
