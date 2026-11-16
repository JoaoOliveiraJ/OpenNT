//! Parada da máquina no depurador do kernel (o papel do KdpTrap, do
//! KdEnterDebugger/KdExitDebugger e do KeFreezeExecution/KeThawExecution).
//!
//! Entradas, todas com o quadro completo do trap (`TrapFrame`) e a área
//! FXSAVE64 montados pelos trampolins (`hal::amd64::irqstubs`):
//! - `int 3` (vetor 3) no anel 0: breakpoint do depurador (o RIP volta para
//!   o 0xCC), `int 3` fixo no código (DbgBreakPoint, o RIP fica depois
//!   dele) e as paradas pedidas pelo próprio kernel (pedido de parada na
//!   inicialização, bugcheck, pânico);
//! - #DB (vetor 1): fim de um passo (DR6.BS) ou comparador de hardware
//!   (DR6.B0-B3);
//! - o tique do relógio do LAPIC no anel 0, quando o LSR da porta tem um
//!   byte: o 0x03 do host (ou o começo de um pacote de um host que acabou de
//!   se conectar) para a máquina, como o KdPollBreakIn do relógio do NT;
//! - NMI (vetor 2) com congelamento pedido: o processador fica parado;
//! - a exceção de kernel sem tratador (`rs_kernel_exception`), antes do
//!   diagnóstico fatal.
//!
//! O primeiro processador a entrar vira o dono da parada; os outros recebem
//! NMI pelo código de IPI do Ke (`smp::send_nmi_to_application_processors`)
//! e ficam presos (`park`) até o degelo, com o quadro publicado para o host
//! ler e alterar. Um passo (`s`) mantém os outros congelados e roda só a
//! instrução do dono, com as interrupções mascaradas durante o passo (o
//! IF original volta depois, e um `pushfq` passo a passo grava o IF
//! original na pilha). Continuar de um breakpoint de software dá antes um
//! passo com o byte original de volta.
//!
//! O KdDisableDebugger desliga as entradas (KdpDebugRoutineSelect 0: o
//! `int 3` volta ao despacho comum de exceções), e o KdEnableDebugger as
//! religa.

use core::arch::global_asm;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};

use super::breakpoints::{self, Watch};
use super::registers::View;
use super::{memory, session, transport};
use crate::hal::amd64::irqstubs::TrapFrame;
use crate::hal::cpu;
use crate::ntos::ke::{clock, pcr, smp};
use crate::ntos::mm::memory_map::MAX_CPUS;

pub const REASON_DEBUG: u32 = 1;
pub const REASON_NMI: u32 = 2;
pub const REASON_BREAKPOINT: u32 = 3;
pub const REASON_POLL: u32 = 0x40;

pub const SIGINT: u8 = 2;
pub const SIGILL: u8 = 4;
pub const SIGTRAP: u8 = 5;
pub const SIGABRT: u8 = 6;
pub const SIGFPE: u8 = 8;
pub const SIGSEGV: u8 = 11;

const TRAP_FLAG: u64 = 1 << 8;
const INTERRUPT_FLAG: u64 = 1 << 9;
const RESUME_FLAG: u64 = 1 << 16;
const DR6_SINGLE_STEP: u64 = 1 << 14;
/// Prazo do congelamento e do degelo (o do shootdown de TLB do Ke).
const FREEZE_TIMEOUT_MS: u64 = 5_000;

/// Vetores 1-3 do anel 0 vão ao depurador (lido pelos trampolins).
#[export_name = "opennt_kd_trap_active"]
static TRAP_ACTIVE: AtomicU8 = AtomicU8::new(0);
/// Porta do LSR consultada no tique do relógio (0 = sem consulta).
#[export_name = "opennt_kd_poll_port"]
static POLL_PORT: AtomicU16 = AtomicU16::new(0);
/// Congelamento pedido: a NMI prende o processador (lido pela NMI dos APs).
#[export_name = "opennt_kd_freeze_active"]
static FREEZE: AtomicU8 = AtomicU8::new(0);

/// Dono da parada: número do processador + 1 (0 = máquina rodando).
static OWNER: AtomicU32 = AtomicU32::new(0);

/// Estado de um processador parado.
struct Processor {
    frame: AtomicU64,
    error_code: AtomicBool,
    fx: AtomicU64,
    frozen: AtomicBool,
    pcr: AtomicU64,
    cr3: AtomicU64,
    /// O CR8 (IRQL) do processador parado, como o KSPECIAL_REGISTERS.Cr8.
    irql: AtomicU8,
    locks: AtomicU32,
    segments: AtomicU64,
    fs_base: AtomicU64,
    gs_base: AtomicU64,
}

impl Processor {
    const fn new() -> Self {
        Self {
            frame: AtomicU64::new(0),
            error_code: AtomicBool::new(false),
            fx: AtomicU64::new(0),
            frozen: AtomicBool::new(false),
            pcr: AtomicU64::new(0),
            cr3: AtomicU64::new(0),
            irql: AtomicU8::new(0),
            locks: AtomicU32::new(0),
            segments: AtomicU64::new(0),
            fs_base: AtomicU64::new(0),
            gs_base: AtomicU64::new(0),
        }
    }
}

static PROCESSORS: [Processor; MAX_CPUS] = [const { Processor::new() }; MAX_CPUS];

/// Passo em andamento: processador + 1 (0 = nenhum).
static STEP_PROCESSOR: AtomicU32 = AtomicU32::new(0);
static STEP_INTERRUPT_FLAG: AtomicU64 = AtomicU64::new(0);
static STEP_INSTRUCTION: AtomicU8 = AtomicU8::new(0);
/// Breakpoint suspenso pelo passo (0 = nenhum).
static STEP_OVER: AtomicU64 = AtomicU64::new(0);
/// O passo é a saída de um breakpoint num `c`: no fim, continua.
static STEP_THEN_CONTINUE: AtomicBool = AtomicBool::new(false);

/// Motivo da última parada (a resposta do `?`).
static STOP_SIGNAL: AtomicU8 = AtomicU8::new(SIGTRAP);
static STOP_KIND: AtomicU8 = AtomicU8::new(0);
static STOP_DATA: AtomicU64 = AtomicU64::new(0);
static STOP_PROCESSOR: AtomicU32 = AtomicU32::new(0);

/// Código e parâmetros do bugcheck que parou a máquina.
static BUGCHECK: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];

/// Instrução executada por um passo, para acertar o IF depois dele.
const INSTRUCTION_OTHER: u8 = 0;
const INSTRUCTION_PUSHF: u8 = 1;
const INSTRUCTION_SETS_IF: u8 = 2;

/// Classe da parada.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Signal,
    SoftwareBreak,
    HardwareBreak,
    Watch(Watch),
}

impl Kind {
    fn code(self) -> u8 {
        match self {
            Kind::Signal => 0,
            Kind::SoftwareBreak => 1,
            Kind::HardwareBreak => 2,
            Kind::Watch(Watch::Write) => 3,
            Kind::Watch(_) => 4,
        }
    }

    fn from_code(code: u8) -> Self {
        match code {
            1 => Kind::SoftwareBreak,
            2 => Kind::HardwareBreak,
            3 => Kind::Watch(Watch::Write),
            4 => Kind::Watch(Watch::Access),
            _ => Kind::Signal,
        }
    }
}

/// Como a máquina sai da parada (decidido pelo host).
pub enum Resume {
    /// Continua; `pass` devolve a exceção ao despacho comum (o `C sig` do
    /// GDB, o "não tratada" do KD).
    Continue { pass: bool },
    /// Uma instrução no dono.
    Step,
}

global_asm!(
    r#"
.pushsection .text.kd, "ax", @progbits
# Paradas pedidas pelo próprio kernel: um `int 3` cujo endereço o
# depurador reconhece.
.global opennt_kd_break_in
opennt_kd_break_in:
    int3
    ret
.global opennt_kd_bugcheck_break
opennt_kd_bugcheck_break:
    int3
    ret
.global opennt_kd_panic_break
opennt_kd_panic_break:
    int3
    ret
# DbgBreakPointWithStatus: o status no RCX, como no NT.
.global opennt_kd_break_with_status
opennt_kd_break_with_status:
    mov rcx, rdi
    int3
    ret
.popsection
"#
);

extern "sysv64" {
    fn opennt_kd_break_in();
    fn opennt_kd_bugcheck_break();
    fn opennt_kd_panic_break();
    fn opennt_kd_break_with_status(status: u64);
}

fn helper_address(function: unsafe extern "sysv64" fn()) -> u64 {
    function as usize as u64
}

/// Liga as entradas do depurador com o LSR da porta `line_status_port`.
pub fn activate(line_status_port: u16) {
    POLL_PORT.store(line_status_port, Ordering::Release);
    TRAP_ACTIVE.store(1, Ordering::Release);
}

/// KdpDebugRoutineSelect: liga ou desliga as entradas (KdEnable/KdDisable).
pub fn set_routine(enabled: bool) {
    if enabled {
        POLL_PORT.store(transport::line_status_port(), Ordering::Release);
        TRAP_ACTIVE.store(1, Ordering::Release);
    } else {
        TRAP_ACTIVE.store(0, Ordering::Release);
        POLL_PORT.store(0, Ordering::Release);
    }
}

/// As entradas do depurador estão ligadas.
pub fn active() -> bool {
    TRAP_ACTIVE.load(Ordering::Acquire) != 0
}

/// A máquina está parada no depurador.
pub fn stopped() -> bool {
    OWNER.load(Ordering::Acquire) != 0
}

/// Número do processador corrente (0 antes da KPCR).
pub fn current_processor() -> usize {
    if pcr::get_pcr_address() == 0 {
        return 0;
    }
    (pcr::current().prcb.number.get() as usize).min(MAX_CPUS - 1)
}

/// Dono da parada, se houver.
pub fn owner() -> Option<usize> {
    match OWNER.load(Ordering::Acquire) {
        0 => None,
        value => Some(value as usize - 1),
    }
}

/// Processadores visíveis ao host: o dono e os congelados.
pub fn processor_stopped(number: usize) -> bool {
    number < MAX_CPUS && (owner() == Some(number) || PROCESSORS[number].frozen.load(Ordering::Acquire))
}

/// Estado de registradores do processador `number`, se parado.
pub fn view(number: usize) -> Option<View> {
    if !processor_stopped(number) {
        return None;
    }
    let record = &PROCESSORS[number];
    let segments = record.segments.load(Ordering::Relaxed);
    Some(View {
        frame: record.frame.load(Ordering::Acquire),
        error_code: record.error_code.load(Ordering::Relaxed),
        fx: record.fx.load(Ordering::Relaxed),
        segments: [segments as u16, (segments >> 16) as u16, (segments >> 32) as u16, (segments >> 48) as u16],
        fs_base: record.fs_base.load(Ordering::Relaxed),
        gs_base: record.gs_base.load(Ordering::Relaxed),
    })
}

/// CR3 do processador parado `number` (o espaço de endereços dos acessos
/// do host).
pub fn address_space(number: usize) -> u64 {
    PROCESSORS[number.min(MAX_CPUS - 1)].cr3.load(Ordering::Relaxed)
}

/// IRQL (CR8) do processador parado `number`.
pub fn processor_irql(number: usize) -> u8 {
    PROCESSORS[number.min(MAX_CPUS - 1)].irql.load(Ordering::Relaxed)
}

/// KPCR do processador parado `number`.
pub fn processor_control_region(number: usize) -> u64 {
    PROCESSORS[number.min(MAX_CPUS - 1)].pcr.load(Ordering::Relaxed)
}

/// Algum processador parado tinha trava do kernel (SpinLock ou
/// SharedLock): consultas que usam as estruturas do Rust não podem rodar.
pub fn locks_held() -> bool {
    (0..MAX_CPUS).any(|number| processor_stopped(number) && PROCESSORS[number].locks.load(Ordering::Relaxed) != 0)
}

/// Motivo da última parada: sinal, classe, dado (endereço vigiado) e
/// processador.
pub fn stop_reason() -> (u8, Kind, u64, usize) {
    (
        STOP_SIGNAL.load(Ordering::Acquire),
        Kind::from_code(STOP_KIND.load(Ordering::Acquire)),
        STOP_DATA.load(Ordering::Acquire),
        STOP_PROCESSOR.load(Ordering::Acquire) as usize,
    )
}

/// Código e parâmetros do bugcheck que parou a máquina (0 se nenhum).
pub fn bug_check_data() -> [u64; 5] {
    core::array::from_fn(|index| BUGCHECK[index].load(Ordering::Acquire))
}

fn read_segments() -> u64 {
    let (ds, es, fs, gs): (u16, u16, u16, u16);
    // SAFETY: leitura dos seletores do processador corrente.
    unsafe {
        core::arch::asm!("mov {:x}, ds", out(reg) ds, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov {:x}, es", out(reg) es, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov {:x}, fs", out(reg) fs, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov {:x}, gs", out(reg) gs, options(nomem, nostack, preserves_flags));
    }
    ds as u64 | (es as u64) << 16 | (fs as u64) << 32 | (gs as u64) << 48
}

/// Publica o estado do processador corrente parado com `frame`.
fn capture(number: usize, frame: u64, fx: u64, error_code: bool) {
    let record = &PROCESSORS[number];
    record.error_code.store(error_code, Ordering::Relaxed);
    record.fx.store(fx, Ordering::Relaxed);
    record.pcr.store(if pcr::get_pcr_address() != 0 { pcr::current_address() } else { 0 }, Ordering::Relaxed);
    record.cr3.store(cpu::read_cr3(), Ordering::Relaxed);
    record.irql.store(crate::ntos::ke::irql::get_irql(), Ordering::Relaxed);
    record.locks.store(crate::rtl::sync::spin_locks_held() + crate::rtl::sync::shared_locks_held(), Ordering::Relaxed);
    record.segments.store(read_segments(), Ordering::Relaxed);
    record.fs_base.store(cpu::read_msr(0xC000_0100), Ordering::Relaxed);
    record.gs_base.store(cpu::read_msr(0xC000_0101), Ordering::Relaxed);
    record.frame.store(frame, Ordering::Release);
}

/// Prende o processador corrente até o degelo (KiFreezeTargetExecution).
fn park(number: usize, frame: u64, fx: u64, error_code: bool) {
    capture(number, frame, fx, error_code);
    PROCESSORS[number].frozen.store(true, Ordering::Release);
    while FREEZE.load(Ordering::Acquire) != 0 {
        core::hint::spin_loop();
    }
    PROCESSORS[number].frozen.store(false, Ordering::Release);
}

/// Congela os outros processadores (KeFreezeExecution): NMI a cada AP
/// online e espera de cada um preso.
fn freeze_others(number: usize) {
    if FREEZE.swap(1, Ordering::AcqRel) != 0 {
        return;
    }
    let sent = smp::send_nmi_to_application_processors() as usize;
    let deadline = clock::uptime_ms() + FREEZE_TIMEOUT_MS;
    loop {
        let frozen = (0..MAX_CPUS).filter(|&other| other != number && PROCESSORS[other].frozen.load(Ordering::Acquire)).count();
        if frozen >= sent {
            break;
        }
        if clock::uptime_ms() >= deadline {
            debug_print!("[kd] {} de {} processadores congelados no prazo", frozen, sent);
            break;
        }
        core::hint::spin_loop();
    }
}

/// Degela os outros (KeThawExecution) e espera cada um sair da prisão: a
/// próxima NMI de congelamento não pode encontrá-lo ainda lá dentro.
fn thaw_others(number: usize) {
    FREEZE.store(0, Ordering::Release);
    let deadline = clock::uptime_ms() + FREEZE_TIMEOUT_MS;
    while (0..MAX_CPUS).any(|other| other != number && PROCESSORS[other].frozen.load(Ordering::Acquire)) {
        if clock::uptime_ms() >= deadline {
            break;
        }
        core::hint::spin_loop();
    }
}

fn record_stop(number: usize, signal: u8, kind: Kind, data: u64) {
    STOP_SIGNAL.store(signal, Ordering::Release);
    STOP_KIND.store(kind.code(), Ordering::Release);
    STOP_DATA.store(data, Ordering::Release);
    STOP_PROCESSOR.store(number as u32, Ordering::Release);
}

/// Classe da instrução em `rip` para o acerto do IF depois do passo.
fn classify_instruction(cr3: u64, rip: u64) -> u8 {
    let mut bytes = [0u8; 8];
    let length = memory::read(cr3, rip, &mut bytes);
    for &byte in &bytes[..length] {
        match byte {
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67 | 0xF2 | 0xF3 | 0x40..=0x4F => continue,
            0x9C => return INSTRUCTION_PUSHF,
            0x9D | 0xFA | 0xFB | 0xCF => return INSTRUCTION_SETS_IF,
            _ => return INSTRUCTION_OTHER,
        }
    }
    INSTRUCTION_OTHER
}

/// Prepara um passo no dono: TF ligado, IF mascarado (o original fica
/// guardado) e RF sobre um comparador de execução.
fn prepare_step(number: usize, view: &View, over: u64, then_continue: bool) {
    let flags = view.rflags();
    STEP_INTERRUPT_FLAG.store(flags & INTERRUPT_FLAG, Ordering::Relaxed);
    STEP_INSTRUCTION.store(classify_instruction(address_space(number), view.rip()), Ordering::Relaxed);
    STEP_OVER.store(over, Ordering::Relaxed);
    STEP_THEN_CONTINUE.store(then_continue, Ordering::Relaxed);
    STEP_PROCESSOR.store(number as u32 + 1, Ordering::Release);
    let resume = if breakpoints::hardware_execute_at(view.rip()) { RESUME_FLAG } else { 0 };
    view.set_rflags((flags | TRAP_FLAG | resume) & !INTERRUPT_FLAG);
    breakpoints::load_into_processor();
}

/// Fim do passo: TF desligado, IF de volta e o breakpoint suspenso
/// recolocado. Devolve se o passo era a saída de um `c`.
fn finish_step(number: usize, view: &View) -> bool {
    STEP_PROCESSOR.store(0, Ordering::Release);
    let original = STEP_INTERRUPT_FLAG.load(Ordering::Relaxed);
    let instruction = STEP_INSTRUCTION.load(Ordering::Relaxed);
    let mut flags = view.rflags() & !TRAP_FLAG;
    if instruction != INSTRUCTION_SETS_IF {
        flags = (flags & !INTERRUPT_FLAG) | original;
    }
    view.set_rflags(flags);
    if instruction == INSTRUCTION_PUSHF {
        let cr3 = address_space(number);
        let rsp = view.rsp();
        if let Some(pushed) = memory::read_u64(cr3, rsp) {
            memory::write_u64(cr3, rsp, (pushed & !(TRAP_FLAG | INTERRUPT_FLAG)) | original);
        }
    }
    let over = STEP_OVER.swap(0, Ordering::AcqRel);
    if over != 0 {
        breakpoints::restore(over);
    }
    STEP_THEN_CONTINUE.swap(false, Ordering::AcqRel)
}

/// Sai da parada continuando: RF sobre um comparador de execução,
/// registradores de depuração carregados, degelo e fim da posse.
fn continue_execution(number: usize, view: &View) {
    if breakpoints::hardware_execute_at(view.rip()) {
        view.set_rflags(view.rflags() | RESUME_FLAG);
    }
    breakpoints::load_into_processor();
    thaw_others(number);
    transport::unlock();
    OWNER.store(0, Ordering::Release);
}

/// Resultado para o trampolim: 1 = volta com o quadro, 0 = segue o caminho
/// comum da exceção.
const HANDLED: u32 = 1;
const DECLINED: u32 = 0;

/// A parada: posse, congelamento, sessão com o host e a saída. `None`
/// quando outro processador já estava no depurador: este ficou congelado
/// até o degelo, e quem chamou faz o trap se repetir.
fn enter(number: usize, frame: u64, fx: u64, error_code: bool, signal: u8, kind: Kind, data: u64) -> Option<u32> {
    let me = number as u32 + 1;
    if OWNER.load(Ordering::Acquire) != me && OWNER.compare_exchange(0, me, Ordering::AcqRel, Ordering::Acquire).is_err() {
        park(number, frame, fx, error_code);
        return None;
    }
    capture(number, frame, fx, error_code);
    breakpoints::disarm_processor();
    transport::seize(number);
    freeze_others(number);
    record_stop(number, signal, kind, data);
    let view = view(number).unwrap_or_default();
    Some(match session::run(number) {
        Resume::Step => {
            // Um passo sobre um breakpoint executa a instrução original.
            let rip = view.rip();
            let over = if breakpoints::inserted_at(rip) && breakpoints::suspend(rip) { rip } else { 0 };
            prepare_step(number, &view, over, false);
            HANDLED
        }
        Resume::Continue { pass } => {
            let rip = view.rip();
            if breakpoints::inserted_at(rip) {
                breakpoints::suspend(rip);
                prepare_step(number, &view, rip, true);
                return Some(HANDLED);
            }
            continue_execution(number, &view);
            if pass { DECLINED } else { HANDLED }
        }
    })
}

/// Entrada dos trampolins (vetores 1, 2 e 3 do anel 0 e o tique do relógio
/// com byte na porta).
#[no_mangle]
extern "sysv64" fn rs_kd_trap(frame: *mut TrapFrame, fx: u64, reason: u32) -> u32 {
    if !active() {
        return DECLINED;
    }
    let number = current_processor();
    let me = number as u32 + 1;
    let frame = frame as u64;
    let view = View { frame, error_code: false, fx, ..View::default() };
    let stepping = STEP_PROCESSOR.load(Ordering::Acquire) == me;
    // Um trap dentro do próprio depurador não é do depurador.
    if OWNER.load(Ordering::Acquire) == me && !stepping {
        return DECLINED;
    }
    match reason {
        REASON_NMI => {
            if FREEZE.load(Ordering::Acquire) != 0 && OWNER.load(Ordering::Acquire) != me {
                park(number, frame, fx, false);
                HANDLED
            } else {
                DECLINED
            }
        }
        REASON_POLL => {
            if OWNER.load(Ordering::Acquire) != 0 || !transport::try_lock(number) {
                return HANDLED;
            }
            let Some(byte) = transport::read() else {
                transport::unlock();
                return HANDLED;
            };
            match byte {
                0x03 => session::set_host_waiting(),
                b'$' => transport::unread(byte),
                _ => {
                    // Confirmação atrasada ou ruído: a máquina segue.
                    transport::unlock();
                    return HANDLED;
                }
            }
            transport::unlock();
            enter(number, frame, fx, false, SIGINT, Kind::Signal, 0).unwrap_or(HANDLED)
        }
        REASON_DEBUG => {
            let status: u64;
            // SAFETY: DR6 do processador corrente; os bits são limpos aqui.
            unsafe {
                core::arch::asm!("mov {}, dr6", out(reg) status, options(nomem, nostack));
                core::arch::asm!("mov dr6, {}", in(reg) 0xFFFF_0FF0u64, options(nomem, nostack));
            }
            if stepping && status & DR6_SINGLE_STEP != 0 {
                if finish_step(number, &view) {
                    continue_execution(number, &view);
                    return HANDLED;
                }
                return enter(number, frame, fx, false, SIGTRAP, Kind::Signal, 0).unwrap_or(HANDLED);
            }
            if let Some(index) = (0..4).find(|index| status & (1 << index) != 0) {
                if let Some((watch, address, _)) = breakpoints::hardware_slot(index) {
                    let kind = if watch == Watch::Execute { Kind::HardwareBreak } else { Kind::Watch(watch) };
                    return enter(number, frame, fx, false, SIGTRAP, kind, address).unwrap_or(HANDLED);
                }
            }
            DECLINED
        }
        REASON_BREAKPOINT => {
            if stepping {
                // O passo executou um `int 3`.
                finish_step(number, &view);
            }
            let address = view.rip().wrapping_sub(1);
            let cr3 = cpu::read_cr3();
            // Congelado durante a entrada: o `int 3` executa de novo no degelo.
            let repeat = || {
                view.set_rip(address);
                HANDLED
            };
            if address == helper_address(opennt_kd_break_in) {
                // Pedido de parada encontrado pelo próprio kernel.
                if transport::byte_pending() {
                    match transport::read() {
                        Some(0x03) => session::set_host_waiting(),
                        Some(byte) if byte == b'$' => transport::unread(byte),
                        _ => {}
                    }
                }
                return enter(number, frame, fx, false, SIGINT, Kind::Signal, 0).unwrap_or_else(repeat);
            }
            if address == helper_address(opennt_kd_bugcheck_break) || address == helper_address(opennt_kd_panic_break) {
                return enter(number, frame, fx, false, SIGABRT, Kind::Signal, 0).unwrap_or_else(repeat);
            }
            if breakpoints::inserted_at(address) {
                view.set_rip(address);
                return enter(number, frame, fx, false, SIGTRAP, Kind::SoftwareBreak, 0).unwrap_or(HANDLED);
            }
            if memory::read_u8(cr3, address) != Some(0xCC) {
                // O breakpoint saiu enquanto este processador entrava: a
                // instrução original executa.
                view.set_rip(address);
                return HANDLED;
            }
            // `int 3` fixo no código (DbgBreakPoint): o RIP fica depois dele.
            enter(number, frame, fx, false, SIGTRAP, Kind::Signal, 0).unwrap_or_else(repeat)
        }
        _ => DECLINED,
    }
}

/// NMI de congelamento nos APs (o portão de NMI da IDT deles).
#[no_mangle]
extern "sysv64" fn rs_kd_freeze_processor(frame: *mut TrapFrame) {
    let number = current_processor();
    if FREEZE.load(Ordering::Acquire) != 0 && OWNER.load(Ordering::Acquire) != number as u32 + 1 {
        park(number, frame as u64, 0, false);
    }
}

/// Sinal do GDB para o vetor de uma exceção de kernel.
fn exception_signal(vector: u64) -> u8 {
    match vector {
        0 | 16 | 19 => SIGFPE,
        6 => SIGILL,
        10..=14 | 17 => SIGSEGV,
        1 | 3 => SIGTRAP,
        _ => SIGABRT,
    }
}

/// Exceção de kernel sem tratador, antes do diagnóstico fatal: o host vê a
/// máquina parada na instrução que faltou. Ao continuar, o diagnóstico
/// segue (a exceção não tem para onde voltar).
pub fn fatal_exception(frame: &TrapFrame) {
    if !active() {
        return;
    }
    let number = current_processor();
    let me = number as u32 + 1;
    if OWNER.load(Ordering::Acquire) == me {
        return;
    }
    // Espera o dono atual sair, se outro processador estiver no depurador.
    while OWNER.load(Ordering::Acquire) != 0 {
        core::hint::spin_loop();
    }
    let vector = frame.vector & 0xFF;
    let error_code = crate::hal::amd64::irqstubs::has_error_code(vector as u8);
    let address = frame as *const TrapFrame as u64;
    debug_print!("[kd] excecao de kernel (vetor {:#x}) parada no depurador", vector);
    let _ = enter(number, address, 0, error_code, exception_signal(vector), Kind::Signal, 0);
    // Sem continuação possível: os outros processadores voltam a rodar e o
    // diagnóstico segue.
}

/// Parada pedida pelo kernel (um pedido do host já na porta na
/// inicialização ou um 0x03 lido no meio de uma impressão).
pub fn break_in_now() {
    if active() && !stopped() {
        // SAFETY: `int 3; ret` reconhecido pela entrada do vetor 3.
        unsafe { opennt_kd_break_in() };
    }
}

/// KeBugCheckEx com o depurador ativo: para antes da tela de STOP, como o
/// KeBugCheck2 com KdDebuggerEnabled (o bugcheck fica no `monitor
/// bugcheck`).
pub fn bug_check(code: u32, parameters: [u64; 4]) {
    if !active() || stopped() {
        return;
    }
    BUGCHECK[0].store(code as u64, Ordering::Release);
    for (cell, value) in BUGCHECK[1..].iter().zip(parameters) {
        cell.store(value, Ordering::Release);
    }
    debug_print!("[kd] bugcheck {:#010x} parado no depurador", code);
    session::announce_fatal(code, parameters);
    // SAFETY: `int 3; ret` reconhecido pela entrada do vetor 3.
    unsafe { opennt_kd_bugcheck_break() };
}

/// O KiSendFreeze do KeBugCheckEx: os outros processadores ficam presos
/// pela NMI de congelamento (com o quadro publicado, como numa parada do
/// depurador) até um degelo; devolve quantos estão presos.
pub fn freeze_for_bug_check() -> usize {
    let number = current_processor();
    freeze_others(number);
    (0..MAX_CPUS).filter(|&other| other != number && PROCESSORS[other].frozen.load(Ordering::Acquire)).count()
}

/// O KiSendThawExecution do KeBugCheckEx antes do reinício.
pub fn thaw_after_bug_check() {
    thaw_others(current_processor());
}

/// Pânico do kernel com o depurador ativo: para antes de travar a CPU.
pub fn panic_stop() {
    if active() && !stopped() {
        // SAFETY: `int 3; ret` reconhecido pela entrada do vetor 3.
        unsafe { opennt_kd_panic_break() };
    }
}

/// DbgBreakPointWithStatus com o depurador ativo: `int 3` com o status no
/// RCX; o host continua depois dele.
pub fn break_with_status(status: u32) {
    // SAFETY: `mov rcx, rdi; int 3; ret`.
    unsafe { opennt_kd_break_with_status(status as u64) };
}
