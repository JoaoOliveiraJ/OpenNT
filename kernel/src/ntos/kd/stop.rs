//! Parada da máquina no depurador do kernel (o papel do KdpTrap, do
//! KdEnterDebugger/KdExitDebugger, do KiProcessNMI e do
//! KeFreezeExecution/KeThawExecution).
//!
//! Entradas, todas com o quadro completo do trap (`TrapFrame`) e a área
//! FXSAVE64 montados pelos trampolins (`hal::amd64::irqstubs`):
//! - `int 3` (vetor 3) no anel 0: breakpoint do depurador (o RIP volta para
//!   o 0xCC), `int 3` fixo no código (DbgBreakPoint, o RIP fica depois
//!   dele) e as paradas pedidas pelo próprio kernel (pedido de parada na
//!   inicialização, bugcheck, pânico, carga de imagem do filtro do host);
//! - #DB (vetor 1): fim de um passo (DR6.BS) ou comparador de hardware
//!   (DR6.B0-B3);
//! - o tique do relógio do LAPIC no anel 0, quando o LSR da porta tem um
//!   byte: o 0x03 do host (ou o começo de um pacote de um host que acabou de
//!   se conectar) para a máquina, como o KdPollBreakIn do relógio do NT; o
//!   mesmo tique atende uma NMI adiada e os autotestes (`kd::self_test`);
//! - NMI (vetor 2) no BSP, de qualquer anel: o congelamento pedido prende o
//!   processador; senão é um pedido de parada (o `nmi` do monitor do QEMU,
//!   ou um AP que precisa parar). É a parada que funciona com as
//!   interrupções desligadas, quando o tique do relógio não vem;
//! - a exceção de kernel sem tratador (`rs_kernel_exception`), antes do
//!   diagnóstico fatal.
//!
//! O processador que recebe a exceção relata a parada (o KdpReport do
//! 19041): vira o dono (o KiFreezeOwner do KeFreezeExecution) e congela os
//! outros, o BSP inclusive quando o dono é um AP. O congelamento segue o
//! KiSendFreeze (0x51e0c0) e o KiFreezeTargetExecution (0x51dda0): cada
//! processador online passa de 0 a 5 (TARGET_PENDING) no KPRCB.IpiFrozen e
//! recebe a NMI; na NMI, o alvo que se acha pendente
//! (KiCheckForFreezeExecution) publica o quadro, passa a 2 (TARGET_FROZEN) e
//! fica preso (`park`) até o dono gravar 3 (TARGET_THAW) no degelo; então
//! carrega os registradores de depuração do kernel (o
//! KiRestoreProcessorControlState) e volta a 0. O dono fica em 4
//! (FREEZE_OWNER) e espera cada alvo chegar a 2, mandando a NMI de novo a
//! quem ainda está pendente (sob o WHPX a NMI pode se perder, como no
//! shootdown de TLB do Ke), com prazo (o KiFreezeTimeout). Um passo (`s`)
//! mantém os outros congelados e roda só a instrução do dono, com as
//! interrupções mascaradas durante o passo (o IF original volta depois, e um
//! `pushfq` passo a passo grava o IF original na pilha). Continuar de um
//! breakpoint de software dá antes um passo com o byte original de volta.
//!
//! A NMI segue o KiProcessNMI do 19041 (0x5129b0): primeiro o congelamento
//! (KiCheckForFreezeExecution), depois a marca de NMI em andamento do
//! processador (KiNmiInProgress) e a KiNMILock tomada sem esperar, com o
//! congelamento conferido enquanto outro processador a tem. No lugar do
//! HalHandleNMI (o relatório do WHEA e o bugcheck), a NMI com o depurador
//! ligado é a parada pedida pelo host, e continuar volta ao código
//! interrompido. A NMI que chega no anel 0 com o GS do usuário (numa
//! fronteira de SYSCALL ou de IRETQ, talvez ainda na pilha do usuário):
//! com o congelamento pedido, o alvo fica preso ali mesmo, no asm
//! (`opennt_kd_freeze_boundary`), sem tocar no GS nem crescer a pilha;
//! sem ele, o pedido de parada é atendido no próximo tique do relógio no
//! anel 0. Os APs com o anel 3 armado (`--user-smp`) têm a IDT inteira e
//! param sozinhos como o BSP; os outros APs só têm o portão da NMI: um
//! bugcheck, um pânico ou um pedido de parada neles é pedido ao BSP por
//! NMI, e a parada mostra o AP (`thread:` do AP).
//!
//! Com a máquina num estado ruim, a sessão sobrevive: um comando do host que
//! falta, chama KeBugCheckEx ou entra em pânico é abandonado
//! (`kd::recovery`); o `int 3` de um breakpoint do host atingido por um
//! comando executa o byte original; o passo sobre `hlt` (que dormiria com o
//! IF mascarado) pula a instrução; o passo sobre o `iretq` (ou o `swapgs`
//! que o precede) de volta ao anel 3 segue no anel 3 e para na thread de
//! usuário (`kd::user_debug`); uma falta sem tratador no meio de um passo
//! vira uma parada nova em vez do diagnóstico fatal.
//!
//! O KdDisableDebugger desliga as entradas (KdpDebugRoutineSelect 0: o
//! `int 3` volta ao despacho comum de exceções), e o KdEnableDebugger as
//! religa.

use core::arch::global_asm;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};

use super::breakpoints::{self, Watch};
use super::packet::Payload;
use super::registers::View;
use super::{memory, recovery, session, trace, transport, user_debug};
use crate::hal::amd64::irqstubs::TrapFrame;
use crate::hal::{cpu, lapic};
use crate::ntos::inc::types::{Kprcb, NtStruct};
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
/// Intervalo entre as NMIs de congelamento repetidas a um alvo que ainda
/// está pendente (o NMI_RESEND_MS do shootdown de TLB do Ke).
const FREEZE_RESEND_MS: u64 = 20;
/// Por quanto tempo depois do degelo uma NMI repetida pode chegar ao alvo
/// que já tinha ficado preso pela primeira.
const STRAY_GRACE_MS: u64 = 1_000;
/// IA32_KERNEL_GS_BASE: com a KPCR no GS, o GS do usuário (a TEB).
const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// KPRCB.IpiFrozen (KeFreezeExecution 0x51d630, KiSendFreeze 0x51e0c0,
/// KiFreezeTargetExecution 0x51dda0 e KiSendThawExecution 0x51e190).
const FROZEN_RUNNING: u32 = 0;
const FROZEN_TARGET: u32 = 2;
const FROZEN_THAW: u32 = 3;
const FROZEN_OWNER: u32 = 4;
const FROZEN_PENDING: u32 = 5;

/// Vetores 1-3 do anel 0 vão ao depurador (lido pelos trampolins).
#[export_name = "opennt_kd_trap_active"]
static TRAP_ACTIVE: AtomicU8 = AtomicU8::new(0);
/// Porta do LSR consultada no tique do relógio (0 = sem consulta).
#[export_name = "opennt_kd_poll_port"]
static POLL_PORT: AtomicU16 = AtomicU16::new(0);
/// Congelamento pedido: a NMI prende o processador (lido pela NMI dos APs).
#[export_name = "opennt_kd_freeze_active"]
static FREEZE: AtomicU8 = AtomicU8::new(0);
/// O quadro completo e o CR3 de cada processador preso numa fronteira com o
/// GS do usuário (`opennt_kd_freeze_boundary`; 0 = nenhum).
#[export_name = "opennt_kd_boundary_frame"]
static BOUNDARY_FRAME: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
#[export_name = "opennt_kd_boundary_cr3"]
static BOUNDARY_CR3: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
/// NMIs de congelamento repetidas a cada alvo no congelamento corrente.
static RESENT: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
/// NMIs de congelamento que ainda podem chegar a cada processador depois do
/// degelo (as repetidas, e a de um alvo que não chegou a ficar preso) e o
/// prazo delas: a que chega é consumida, e não vira pedido de parada.
static STRAY: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
static STRAY_UNTIL: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
/// Entrada pedida para o próximo tique do relógio no anel 0, mesmo sem byte
/// na porta (lido e gravado pelos trampolins): `TICK_NMI` é a NMI que chegou
/// numa fronteira com o GS do usuário, `TICK_TEST` um autoteste.
#[export_name = "opennt_kd_tick_request"]
static TICK_REQUEST: AtomicU8 = AtomicU8::new(0);
pub const TICK_NMI: u8 = 1;
pub const TICK_TEST: u8 = 2;

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
    /// A impressão do conjunto de comparadores do depurador carregado nos
    /// registradores de depuração do processador (`hardware_signature`).
    loaded_hardware: AtomicU64,
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
            loaded_hardware: AtomicU64::new(0),
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
/// A exceção de usuário da parada corrente: código, chance (0 = nenhuma) e
/// se é o fim do processo com o código.
static STOP_EXCEPTION_CODE: AtomicU32 = AtomicU32::new(0);
static STOP_EXCEPTION_CHANCE: AtomicU8 = AtomicU8::new(0);
static STOP_TERMINATION: AtomicBool = AtomicBool::new(false);
/// Paradas desde o boot (um AP que pediu parada sabe que ela aconteceu).
static STOP_SEQUENCE: AtomicU32 = AtomicU32::new(0);
/// O processador relatado na próxima parada (número + 1; 0 = o dono): o AP
/// que pediu a parada ao BSP.
static REPORT_PROCESSOR: AtomicU32 = AtomicU32::new(0);

/// Código e parâmetros do bugcheck que parou a máquina.
static BUGCHECK: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];

/// KiNMILock: um processador por vez trata o pedido de parada da NMI
/// (número + 1; 0 = livre).
static NMI_LOCK: AtomicU32 = AtomicU32::new(0);
/// KiNmiInProgress: a NMI do processador está sendo tratada.
static NMI_ACTIVE: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];
/// Contadores do `monitor nmi`: NMIs que entraram no depurador por
/// processador, paradas pedidas pelo host, NMIs adiadas para o tique e NMIs
/// que chegaram com a máquina já parada.
static NMI_RECEIVED: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
static NMI_BREAKS: AtomicU32 = AtomicU32::new(0);
static NMI_DEFERRED: AtomicU32 = AtomicU32::new(0);
static NMI_IGNORED: AtomicU32 = AtomicU32::new(0);
/// Pedido de parada de um AP ao BSP: (sinal << 8) | (número + 1).
static AP_REQUEST: AtomicU32 = AtomicU32::new(0);
/// APIC id do BSP (o alvo da NMI de um pedido de AP; acima de 0xFF = sem).
static BSP_APIC_ID: AtomicU32 = AtomicU32::new(u32::MAX);

/// Breakpoints que um comando do host atingiu (o byte original executou) e
/// que voltam no fim da sessão.
static SESSION_SUSPENDED: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];

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
    /// Breakpoint de memória por página (`kd::page_breakpoints`): o dado da
    /// parada é o endereço acessado.
    Memory(Watch),
    /// Carga de imagem pedida pelo filtro do host (`kd::events`): os
    /// argumentos do evento estão nos registradores do processador.
    Library,
    /// Pedido de parada por NMI (o `nmi:` da resposta).
    Nmi,
}

impl Kind {
    fn code(self) -> u8 {
        match self {
            Kind::Signal => 0,
            Kind::SoftwareBreak => 1,
            Kind::HardwareBreak => 2,
            Kind::Watch(Watch::Write) => 3,
            Kind::Watch(_) => 4,
            Kind::Memory(Watch::Write) => 5,
            Kind::Memory(Watch::Execute) => 6,
            Kind::Memory(Watch::Access) => 7,
            Kind::Library => 8,
            Kind::Nmi => 9,
        }
    }

    fn from_code(code: u8) -> Self {
        match code {
            1 => Kind::SoftwareBreak,
            2 => Kind::HardwareBreak,
            3 => Kind::Watch(Watch::Write),
            4 => Kind::Watch(Watch::Access),
            5 => Kind::Memory(Watch::Write),
            6 => Kind::Memory(Watch::Execute),
            7 => Kind::Memory(Watch::Access),
            8 => Kind::Library,
            9 => Kind::Nmi,
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
# Carga de imagem que o filtro do host pediu (`kd::events`): os argumentos
# do evento ficam nos registradores (RDI base, RSI tamanho, RDX PID, RCX
# nome, R8 tamanho do nome, R9 sistema).
.global opennt_kd_load_break
opennt_kd_load_break:
    int3
    ret
.popsection
"#
);

global_asm!(
    r#"
.pushsection .text.kd, "ax", @progbits
# O KiFreezeTargetExecution numa fronteira: a NMI chegou no anel 0 com o GS
# do usuario (logo depois do SYSCALL, antes da troca de pilha, ou entre o
# SWAPGS e o IRETQ da volta), talvez ainda na pilha do usuario. Sem tocar no
# GS nem crescer a pilha: a KPCR vem do IA32_KERNEL_GS_BASE, o quadro
# completo (RDI, o TrapFrame na pilha interrompida) e o CR3 ficam publicados,
# e o processador pendente (KPRCB.IpiFrozen 5) passa a 2 e espera aqui ate o
# degelo. Usa RAX, RCX, RDX e RSI (ja salvos no quadro).
.global opennt_kd_freeze_boundary
opennt_kd_freeze_boundary:
    mov ecx, 0xC0000102
    rdmsr
    shl rdx, 32
    or rdx, rax
    # Sem KPCR no KernelGSbase (um AP que ainda parte): nada a fazer.
    test rdx, rdx
    jns opennt_kd_boundary_done
    mov esi, dword ptr [rdx + {number}]
    cmp esi, {max_cpus}
    jae opennt_kd_boundary_done
    lea rax, [rip + opennt_kd_boundary_cr3]
    mov rcx, cr3
    mov qword ptr [rax + rsi*8], rcx
    lea rax, [rip + opennt_kd_boundary_frame]
    mov qword ptr [rax + rsi*8], rdi
    mov eax, {pending}
    mov ecx, {target}
    lock cmpxchg dword ptr [rdx + {ipi_frozen}], ecx
    jne opennt_kd_boundary_unpublish
opennt_kd_boundary_wait:
    pause
    cmp byte ptr [rip + opennt_kd_freeze_active], 0
    je opennt_kd_boundary_thawed
    cmp dword ptr [rdx + {ipi_frozen}], {target}
    je opennt_kd_boundary_wait
opennt_kd_boundary_thawed:
    mov dword ptr [rdx + {ipi_frozen}], {running}
opennt_kd_boundary_unpublish:
    lea rax, [rip + opennt_kd_boundary_frame]
    mov qword ptr [rax + rsi*8], 0
opennt_kd_boundary_done:
    ret
.popsection
"#,
    number = const crate::ntos::ke::pcr::layout::PRCB_NUMBER,
    ipi_frozen = const crate::ntos::ke::pcr::layout::PRCB_IPI_FROZEN,
    max_cpus = const MAX_CPUS,
    pending = const FROZEN_PENDING,
    target = const FROZEN_TARGET,
    running = const FROZEN_RUNNING,
);

extern "sysv64" {
    fn opennt_kd_break_in();
    fn opennt_kd_bugcheck_break();
    fn opennt_kd_panic_break();
    fn opennt_kd_break_with_status(status: u64);
    fn opennt_kd_load_break(base: u64, size: u64, process_id: u64, name: u64, name_length: u64, system: u64);
}

fn helper_address(function: unsafe extern "sysv64" fn()) -> u64 {
    function as usize as u64
}

/// Liga as entradas do depurador com o LSR da porta `line_status_port`.
/// Roda no BSP (a fase 0): o APIC id dele é o alvo dos pedidos dos APs.
pub fn activate(line_status_port: u16) {
    BSP_APIC_ID.store(lapic::read(0x20) >> 24, Ordering::Release);
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

/// Processadores visíveis ao host: o dono e os congelados (também os presos
/// numa fronteira).
pub fn processor_stopped(number: usize) -> bool {
    number < MAX_CPUS && (owner() == Some(number) || PROCESSORS[number].frozen.load(Ordering::Acquire) || boundary_frame(number) != 0)
}

/// O quadro do processador preso numa fronteira com o GS do usuário (0 se
/// não está).
fn boundary_frame(number: usize) -> u64 {
    let frame = BOUNDARY_FRAME[number].load(Ordering::Acquire);
    if frame != 0 && ipi_frozen_of(number) == FROZEN_TARGET {
        frame
    } else {
        0
    }
}

/// Estado de registradores do processador `number`, se parado.
pub fn view(number: usize) -> Option<View> {
    if !processor_stopped(number) {
        return None;
    }
    if owner() != Some(number) && !PROCESSORS[number].frozen.load(Ordering::Acquire) {
        // Preso numa fronteira: o quadro completo, sem a área FXSAVE; o GS
        // ainda é o do usuário, e os seletores, os dele.
        return Some(View { frame: boundary_frame(number), error_code: false, fx: 0, segments: [0x2B, 0x2B, 0x53, 0x2B], fs_base: 0, gs_base: 0 });
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
    let number = number.min(MAX_CPUS - 1);
    if boundary_only(number) {
        return BOUNDARY_CR3[number].load(Ordering::Acquire);
    }
    PROCESSORS[number].cr3.load(Ordering::Relaxed)
}

/// O processador está preso só numa fronteira (sem o estado da `capture`).
fn boundary_only(number: usize) -> bool {
    owner() != Some(number) && !PROCESSORS[number].frozen.load(Ordering::Acquire) && boundary_frame(number) != 0
}

/// IRQL (CR8) do processador parado `number` (numa fronteira de serviço,
/// PASSIVE_LEVEL).
pub fn processor_irql(number: usize) -> u8 {
    let number = number.min(MAX_CPUS - 1);
    if boundary_only(number) {
        return 0;
    }
    PROCESSORS[number].irql.load(Ordering::Relaxed)
}

/// KPCR do processador parado `number`.
pub fn processor_control_region(number: usize) -> u64 {
    let number = number.min(MAX_CPUS - 1);
    match PROCESSORS[number].pcr.load(Ordering::Relaxed) {
        0 if boundary_only(number) => kpcr_of(number),
        address => address,
    }
}

/// O processador `number` está online (o BSP sempre; os APs pelo número
/// que o Ke deu a cada um, sem trava).
fn online(number: usize) -> bool {
    number == 0 || (number < MAX_CPUS && smp::processor_apic_id(number).is_some())
}

/// A KPCR do processador online `number` (a reserva fixa dele), ou 0.
fn kpcr_of(number: usize) -> u64 {
    if !online(number) || pcr::get_pcr_address() == 0 {
        return 0;
    }
    pcr::prcb_address(number as u32) - pcr::layout::PRCB
}

/// A KPRCB do processador online `number`.
fn prcb_of(number: usize) -> Option<&'static Kprcb> {
    if !online(number) || pcr::get_pcr_address() == 0 {
        return None;
    }
    // SAFETY: a KPRCB de cada processador online fica mapeada por toda a
    // vida do sistema.
    Some(unsafe { Kprcb::at(pcr::prcb_address(number as u32)) })
}

/// KPRCB.IpiFrozen do processador `number` (0 fora dos online).
fn ipi_frozen_of(number: usize) -> u32 {
    prcb_of(number).map_or(FROZEN_RUNNING, |prcb| prcb.ipi_frozen.atomic().load(Ordering::Acquire))
}

/// Algum processador parado tinha trava do kernel (SpinLock ou
/// SharedLock): consultas que usam as estruturas do Rust não podem rodar.
pub fn locks_held() -> bool {
    // Numa fronteira de serviço nenhuma trava está tomada.
    (0..MAX_CPUS).any(|number| processor_stopped(number) && !boundary_only(number) && PROCESSORS[number].locks.load(Ordering::Relaxed) != 0)
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

/// A exceção de usuário relatada numa parada (`exception:código;chance:n;`
/// na resposta, mais `term:` no fim do processo com o código).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UserException {
    pub code: u32,
    /// 1 = primeira chance, 2 = segunda chance (ou fim do processo).
    pub chance: u8,
    pub termination: bool,
}

/// A exceção de usuário da parada corrente, se a parada é de uma.
pub fn stop_exception() -> Option<UserException> {
    match STOP_EXCEPTION_CHANCE.load(Ordering::Acquire) {
        0 => None,
        chance => Some(UserException { code: STOP_EXCEPTION_CODE.load(Ordering::Acquire), chance, termination: STOP_TERMINATION.load(Ordering::Acquire) }),
    }
}

/// O passo vale na parada corrente: não numa parada pedida por um AP (o
/// passo roda só no dono) nem numa segunda chance (o processo termina).
pub fn step_allowed() -> bool {
    let (_, _, _, number) = stop_reason();
    owner() == Some(number) && stop_exception().map_or(true, |exception| exception.chance == 1)
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

/// Os seletores e o GS do anel 3 (DS, ES e GS 0x2B, FS 0x53; a base de GS
/// é a TEB, no KernelGSbase enquanto a KPCR está no GS).
fn publish_user_segments(number: usize, user_gs_base: u64) {
    PROCESSORS[number].segments.store(0x2B | 0x2B << 16 | 0x53 << 32 | 0x2B << 48, Ordering::Relaxed);
    PROCESSORS[number].gs_base.store(user_gs_base, Ordering::Relaxed);
}

/// KPRCB.IpiFrozen do processador corrente.
fn set_own_ipi_frozen(value: u32) {
    if pcr::get_pcr_address() != 0 {
        pcr::current().prcb.ipi_frozen.atomic().store(value, Ordering::Release);
    }
}

fn own_ipi_frozen() -> u32 {
    if pcr::get_pcr_address() == 0 {
        return FROZEN_RUNNING;
    }
    pcr::current().prcb.ipi_frozen.atomic().load(Ordering::Acquire)
}

/// A impressão do conjunto de comparadores do depurador (0 sem nenhum).
fn hardware_signature() -> u64 {
    if !breakpoints::any_hardware() {
        return 0;
    }
    (0..4).fold(breakpoints::dr7(), |signature, index| signature.rotate_left(17) ^ breakpoints::hardware_slot(index).map_or(0, |(_, address, length)| address ^ length << 60))
}

/// Os comparadores do depurador nos registradores de depuração do
/// processador corrente (e na KPRCB dele), com a impressão do conjunto.
fn load_debug_registers(number: usize) {
    breakpoints::load_into_processor();
    PROCESSORS[number].loaded_hardware.store(hardware_signature(), Ordering::Release);
}

fn read_dr7() -> u64 {
    let value: u64;
    // SAFETY: DR7 do processador corrente, em anel 0.
    unsafe { core::arch::asm!("mov {}, dr7", out(reg) value, options(nomem, nostack, preserves_flags)) };
    value
}

fn write_dr7(value: u64) {
    // SAFETY: DR7 do processador corrente, em anel 0.
    unsafe { core::arch::asm!("mov dr7, {}", in(reg) value, options(nomem, nostack, preserves_flags)) };
}

/// O KiFreezeTargetExecution: o processador corrente publica o quadro,
/// passa a TARGET_FROZEN e fica preso até o degelo (TARGET_THAW, gravado
/// pelo dono, ou o fim de um congelamento que não o viu chegar). No degelo
/// o TLB sai (as PTEs mudaram na parada: breakpoint de memória) e, se o host
/// mudou os comparadores na parada, os registradores de depuração voltam
/// com os do depurador (o KiRestoreProcessorControlState carrega o
/// KernelDr0-7 da KPRCB.ProcessorState de cada processador): um breakpoint
/// de hardware armado numa parada vale em todos os processadores com a IDT
/// inteira. Sem mudança, o DR7 de antes volta (a NMI pode chegar com o banco
/// do usuário já carregado, logo antes do `swapgs` da volta ao anel 3). Do
/// anel 3, os trampolins já trocaram o banco de depuração pelo do kernel e
/// o devolvem depois, com o do kernel guardado.
fn park(number: usize, frame: u64, fx: u64, error_code: bool) {
    // Uma vigia de dados não dispara dentro da prisão.
    let saved_dr7 = read_dr7();
    breakpoints::disarm_processor();
    capture(number, frame, fx, error_code);
    // A NMI que chegou no código do usuário: os seletores e o GS dele (no
    // KernelGSbase enquanto a KPCR está no GS).
    if (View { frame, error_code, ..View::default() }).cs() & 3 == 3 {
        publish_user_segments(number, cpu::read_msr(MSR_KERNEL_GS_BASE));
    }
    set_own_ipi_frozen(FROZEN_TARGET);
    PROCESSORS[number].frozen.store(true, Ordering::Release);
    while own_ipi_frozen() == FROZEN_TARGET && FREEZE.load(Ordering::Acquire) != 0 {
        core::hint::spin_loop();
    }
    super::page_breakpoints::after_thaw();
    // Um AP sem a IDT inteira não tem o portão do #DB: os comparadores do
    // depurador não vão a ele (um disparo ali seria falta tripla).
    if has_debug_vectors() && PROCESSORS[number].loaded_hardware.load(Ordering::Acquire) != hardware_signature() {
        load_debug_registers(number);
    } else {
        write_dr7(saved_dr7);
    }
    set_own_ipi_frozen(FROZEN_RUNNING);
    PROCESSORS[number].frozen.store(false, Ordering::Release);
}

/// O KiCheckForFreezeExecution da NMI (e do tique do relógio): com o
/// congelamento pedido por outro dono, o processador fica preso (um que já
/// estava preso, por conta própria na entrada, só volta à prisão). Sem
/// congelamento, uma NMI repetida de um congelamento que já acabou é
/// consumida. Devolve se a NMI era do congelamento.
fn check_for_freeze(number: usize, frame: u64, fx: u64) -> bool {
    let me = number as u32 + 1;
    if FREEZE.load(Ordering::Acquire) != 0 {
        if OWNER.load(Ordering::Acquire) == me {
            return false;
        }
        if !PROCESSORS[number].frozen.load(Ordering::Acquire) {
            park(number, frame, fx, false);
        }
        return true;
    }
    if consume_stray(number) {
        NMI_IGNORED.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    false
}

/// Uma NMI de congelamento que chegou depois do degelo (a repetida a um
/// alvo que já estava preso, ou a de um alvo que não chegou a tempo),
/// dentro do prazo dela.
fn consume_stray(number: usize) -> bool {
    let cell = &STRAY[number];
    let mut current = cell.load(Ordering::Acquire);
    while current != 0 {
        match cell.compare_exchange(current, current - 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                if clock::uptime_ms() < STRAY_UNTIL[number].load(Ordering::Acquire) {
                    return true;
                }
                cell.store(0, Ordering::Release);
                return false;
            }
            Err(value) => current = value,
        }
    }
    false
}

/// A NMI de congelamento ao processador `number`.
fn send_freeze_nmi(number: usize) {
    let target = match smp::processor_apic_id(number) {
        Some(identifier) => identifier,
        None if number == 0 => BSP_APIC_ID.load(Ordering::Acquire),
        None => return,
    };
    if target <= 0xFF {
        send_nmi_to(target);
    }
}

/// Os alvos de um congelamento pedido por `number`: cada outro processador
/// online. Sem o depurador ligado (o KeBugCheckEx sem host), a NMI do BSP
/// não vai ao congelamento: só os APs são alvos.
fn freeze_targets(number: usize) -> u32 {
    (0..MAX_CPUS).filter(|&other| other != number && online(other) && (other != 0 || active())).fold(0, |mask, other| mask | 1 << other)
}

/// O KeFreezeExecution: o processador corrente é o dono (FREEZE_OWNER) e
/// congela os outros. O KiSendFreeze: cada alvo passa de RUNNING a
/// TARGET_PENDING no KPRCB.IpiFrozen (o que já se prendeu sozinho na
/// entrada, em TARGET_FROZEN, conta como congelado) e recebe a NMI. A espera
/// vai até cada alvo chegar a TARGET_FROZEN, com prazo (o KiFreezeTimeout);
/// a quem ainda está pendente a NMI vai de novo a cada FREEZE_RESEND_MS.
fn freeze_others(number: usize) {
    if FREEZE.swap(1, Ordering::AcqRel) != 0 {
        return;
    }
    let targets = freeze_targets(number);
    for other in (0..MAX_CPUS).filter(|&other| targets & 1 << other != 0) {
        RESENT[other].store(0, Ordering::Release);
        let Some(prcb) = prcb_of(other) else { continue };
        let cell = prcb.ipi_frozen.atomic();
        match cell.compare_exchange(FROZEN_RUNNING, FROZEN_PENDING, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => send_freeze_nmi(other),
            Err(FROZEN_TARGET) => {}
            Err(_) => {
                // Ainda saindo da prisão do congelamento anterior.
                cell.store(FROZEN_PENDING, Ordering::Release);
                send_freeze_nmi(other);
            }
        }
    }
    let start = clock::uptime_ms();
    let mut last_send = start;
    loop {
        let waiting = (0..MAX_CPUS).filter(|&other| targets & 1 << other != 0 && ipi_frozen_of(other) != FROZEN_TARGET).fold(0u32, |mask, other| mask | 1 << other);
        if waiting == 0 {
            break;
        }
        let now = clock::uptime_ms();
        if now >= start + FREEZE_TIMEOUT_MS {
            debug_print!("[kd] processadores {:#x} sem congelar no prazo (alvos {:#x})", waiting, targets);
            break;
        }
        if now >= last_send + FREEZE_RESEND_MS {
            last_send = now;
            for other in (0..MAX_CPUS).filter(|&other| waiting & 1 << other != 0) {
                let Some(prcb) = prcb_of(other) else { continue };
                let cell = prcb.ipi_frozen.atomic();
                let state = cell.load(Ordering::Acquire);
                // Um alvo que saiu da prisão anterior depois de marcado
                // (e se gravou RUNNING) fica pendente de novo.
                if state != FROZEN_PENDING && cell.compare_exchange(state, FROZEN_PENDING, Ordering::AcqRel, Ordering::Acquire).is_err() {
                    continue;
                }
                RESENT[other].fetch_add(1, Ordering::AcqRel);
                send_freeze_nmi(other);
            }
        }
        core::hint::spin_loop();
    }
}

/// O KeThawExecution e o KiSendThawExecution: cada alvo preso passa a
/// TARGET_THAW, e o que não chegou a ficar preso volta a RUNNING; o dono
/// espera cada um sair da prisão (a próxima NMI de congelamento não pode
/// encontrá-lo ainda lá dentro). As NMIs repetidas, e a de um alvo que não
/// chegou, ainda podem chegar depois: ficam contadas para a NMI do BSP não
/// as tomar por um pedido de parada.
fn thaw_others(number: usize) {
    let now = clock::uptime_ms();
    for other in (0..MAX_CPUS).filter(|&other| other != number) {
        let mut stray = RESENT[other].swap(0, Ordering::AcqRel);
        if let Some(prcb) = prcb_of(other) {
            let cell = prcb.ipi_frozen.atomic();
            if cell.compare_exchange(FROZEN_TARGET, FROZEN_THAW, Ordering::AcqRel, Ordering::Acquire).is_err() && cell.compare_exchange(FROZEN_PENDING, FROZEN_RUNNING, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                stray += 1;
            }
        }
        if stray != 0 {
            STRAY_UNTIL[other].store(now + STRAY_GRACE_MS, Ordering::Release);
            STRAY[other].fetch_add(stray, Ordering::AcqRel);
        }
    }
    FREEZE.store(0, Ordering::Release);
    let deadline = clock::uptime_ms() + FREEZE_TIMEOUT_MS;
    while (0..MAX_CPUS).any(|other| other != number && (PROCESSORS[other].frozen.load(Ordering::Acquire) || BOUNDARY_FRAME[other].load(Ordering::Acquire) != 0)) {
        if clock::uptime_ms() >= deadline {
            break;
        }
        core::hint::spin_loop();
    }
}

fn record_stop(number: usize, signal: u8, kind: Kind, data: u64) {
    let reported = match REPORT_PROCESSOR.swap(0, Ordering::AcqRel) {
        0 => number,
        value => {
            let other = value as usize - 1;
            if processor_stopped(other) {
                other
            } else {
                number
            }
        }
    };
    STOP_SIGNAL.store(signal, Ordering::Release);
    STOP_KIND.store(kind.code(), Ordering::Release);
    STOP_DATA.store(data, Ordering::Release);
    STOP_PROCESSOR.store(reported as u32, Ordering::Release);
    STOP_EXCEPTION_CHANCE.store(0, Ordering::Release);
    STOP_TERMINATION.store(false, Ordering::Release);
    STOP_SEQUENCE.fetch_add(1, Ordering::AcqRel);
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

/// O que um passo na instrução do RIP encontraria.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StepHazard {
    None,
    /// `hlt` (com os prefixos, deste tamanho): com o IF mascarado do passo,
    /// a CPU dormiria até uma NMI.
    Halt(u64),
    /// `iretq`, ou `swapgs` seguido de `iretq`, de volta ao anel 3: o #DB do
    /// passo chegaria pelo anel 3, fora do depurador do kernel.
    ReturnToUser,
}

/// O quadro do IRETQ em `rsp` volta ao anel 3.
fn iret_target_is_user(cr3: u64, rsp: u64) -> bool {
    memory::read_u64(cr3, rsp.wrapping_add(8)).is_some_and(|cs| cs & 3 == 3)
}

fn step_hazard(number: usize, view: &View) -> StepHazard {
    let cr3 = address_space(number);
    let rip = view.rip();
    let mut bytes = [0u8; 16];
    let length = memory::read(cr3, rip, &mut bytes);
    breakpoints::mask_read(cr3, rip, &mut bytes[..length]);
    let bytes = &bytes[..length];
    let prefixes = bytes.iter().take_while(|&&byte| matches!(byte, 0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67 | 0xF2 | 0xF3 | 0x40..=0x4F)).count();
    match &bytes[prefixes..] {
        [0xF4, ..] => StepHazard::Halt(prefixes as u64 + 1),
        [0xCF, ..] if iret_target_is_user(cr3, view.rsp()) => StepHazard::ReturnToUser,
        [0x0F, 0x01, 0xF8, 0x48, 0xCF, ..] if prefixes == 0 && iret_target_is_user(cr3, view.rsp()) => StepHazard::ReturnToUser,
        _ => StepHazard::None,
    }
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
    load_debug_registers(number);
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
    load_debug_registers(number);
    thaw_others(number);
    transport::unlock();
    set_own_ipi_frozen(FROZEN_RUNNING);
    OWNER.store(0, Ordering::Release);
}

/// Resultado para o trampolim: 1 = volta com o quadro, 0 = segue o caminho
/// comum da exceção.
const HANDLED: u32 = 1;
const DECLINED: u32 = 0;

/// O passo pedido pelo host segue no anel 3: TF no RFLAGS do quadro do
/// IRETQ que vai rodar (`flags_address`, pela raiz `cr3`; 0 = o RFLAGS do
/// próprio quadro da parada) e a parada vem pelo #DB do anel 3 da thread do
/// intervalo (`kd::user_debug`). `false` sem CONTEXT do intervalo (o anel 3
/// cru dos autotestes): o passo não é possível.
fn step_into_user(view: &View, cr3: u64, flags_address: u64) -> bool {
    let context = crate::hal::amd64::usermode::block().context.get();
    if context == 0 {
        return false;
    }
    if flags_address == 0 {
        view.set_rflags(view.rflags() | TRAP_FLAG);
    } else {
        let Some(flags) = memory::read_u64(cr3, flags_address) else { return false };
        if !memory::write_u64(cr3, flags_address, flags | TRAP_FLAG) {
            return false;
        }
    }
    user_debug::arm_step_from_kernel(context);
    true
}

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
    // Uma NMI que interrompeu o anel 3: o quadro é o do usuário, com os
    // seletores e o GS dele.
    let user_frame = View { frame, error_code, ..View::default() }.cs() & 3 == 3;
    if user_frame {
        publish_user_segments(number, cpu::read_msr(MSR_KERNEL_GS_BASE));
    }
    set_own_ipi_frozen(FROZEN_OWNER);
    breakpoints::disarm_processor();
    transport::seize(number);
    freeze_others(number);
    // Outra parada no meio de um rastro encerra o rastro.
    trace::abandon();
    record_stop(number, signal, kind, data);
    let view = view(number).unwrap_or_default();
    loop {
        let resume = session::run(number);
        if user_frame {
            // O rastro passo a passo é do anel 0; o passo no anel 3 usa o TF
            // do quadro e para pelo #DB do anel 3 da thread.
            trace::disarm();
            if matches!(resume, Resume::Step) && !step_into_user(&view, 0, 0) {
                debug_print!("[kd] passo no anel 3 sem o CONTEXT do intervalo: a parada se repete");
                record_stop(number, SIGTRAP, Kind::Signal, 0);
                continue;
            }
            continue_execution(number, &view);
            return Some(HANDLED);
        }
        // Continuar com um rastro armado começa os passos do rastro.
        if matches!(resume, Resume::Continue { .. }) && trace::armed() {
            let rip = view.rip();
            let over = if breakpoints::inserted_at(rip) && breakpoints::suspend(rip) { rip } else { 0 };
            if trace::begin(number, &view) {
                prepare_step(number, &view, over, false);
                return Some(HANDLED);
            }
            if over != 0 {
                breakpoints::restore(over);
            }
            // O lote terminou sem passo: o host recebe a parada de novo.
            record_stop(number, SIGTRAP, Kind::Signal, 0);
            continue;
        }
        match resume {
            Resume::Step => match step_hazard(number, &view) {
                StepHazard::Halt(length) => {
                    // O passo pula o `hlt` sem executá-lo: nada muda além do
                    // RIP, e a parada se repete depois dele.
                    view.set_rip(view.rip().wrapping_add(length));
                    record_stop(number, SIGTRAP, Kind::Signal, 0);
                    continue;
                }
                StepHazard::ReturnToUser => {
                    // O TF vai ao RFLAGS que o IRETQ carrega (RSP + 16 no
                    // quadro dele): a instrução de usuário roda e para.
                    if !step_into_user(&view, address_space(number), view.rsp().wrapping_add(16)) {
                        debug_print!("[kd] passo para o anel 3 sem o CONTEXT do intervalo: a parada se repete");
                        record_stop(number, SIGTRAP, Kind::Signal, 0);
                        continue;
                    }
                    continue_execution(number, &view);
                    return Some(HANDLED);
                }
                StepHazard::None => {
                    // Um passo sobre um breakpoint executa a instrução original.
                    let rip = view.rip();
                    let over = if breakpoints::inserted_at(rip) && breakpoints::suspend(rip) { rip } else { 0 };
                    prepare_step(number, &view, over, false);
                    return Some(HANDLED);
                }
            },
            Resume::Continue { pass } => {
                let rip = view.rip();
                if breakpoints::inserted_at(rip) {
                    breakpoints::suspend(rip);
                    prepare_step(number, &view, rip, true);
                    return Some(HANDLED);
                }
                continue_execution(number, &view);
                return Some(if pass { DECLINED } else { HANDLED });
            }
        }
    }
}

/// Como uma parada do modo usuário sai (decidido pelo host).
pub enum UserResume {
    /// Continua; `pass` devolve a exceção ao processo.
    Continue { pass: bool },
    /// Uma instrução da thread de usuário (o TF no CONTEXT dela).
    Step,
}

/// Parada pedida pelo despacho de uma exceção do anel 3 (`kd::user_debug`),
/// com interrupções desligadas por quem chama. `frame` é um quadro de trap
/// montado do CONTEXT da thread (o host lê e grava nele) e `fx` a área
/// FltSave do CONTEXT. A posse, o congelamento e a sessão são os de uma
/// parada do anel 0; o passo e a saída de um breakpoint ficam com quem
/// chamou, pelo TF da thread. `exception` é a exceção relatada ao host.
/// `None` com o depurador desligado.
pub fn enter_user(frame: u64, fx: u64, signal: u8, kind: Kind, data: u64, user_gs_base: u64, exception: Option<UserException>) -> Option<UserResume> {
    if !active() {
        return None;
    }
    let number = current_processor();
    let me = number as u32 + 1;
    if OWNER.load(Ordering::Acquire) == me {
        return None;
    }
    // Outro processador no depurador: este fica congelado pela NMI dele e
    // entra depois do degelo.
    while OWNER.compare_exchange(0, me, Ordering::AcqRel, Ordering::Acquire).is_err() {
        core::hint::spin_loop();
    }
    capture(number, frame, fx, false);
    publish_user_segments(number, user_gs_base);
    set_own_ipi_frozen(FROZEN_OWNER);
    breakpoints::disarm_processor();
    transport::seize(number);
    freeze_others(number);
    trace::abandon();
    record_stop(number, signal, kind, data);
    if let Some(exception) = exception {
        STOP_EXCEPTION_CODE.store(exception.code, Ordering::Release);
        STOP_TERMINATION.store(exception.termination, Ordering::Release);
        STOP_EXCEPTION_CHANCE.store(exception.chance, Ordering::Release);
    }
    let resume = session::run(number);
    // O rastro passo a passo é do anel 0: armado aqui, fica desfeito.
    trace::disarm();
    let view = view(number).unwrap_or_default();
    continue_execution(number, &view);
    Some(match resume {
        Resume::Step => UserResume::Step,
        Resume::Continue { pass } => UserResume::Continue { pass },
    })
}

/// O breakpoint em `address` volta ao byte original até o fim da sessão: um
/// comando do host (que roda código do kernel) o atingiu.
fn suspend_for_session(address: u64) -> bool {
    let Some(slot) = SESSION_SUSPENDED.iter().find(|slot| slot.load(Ordering::Acquire) == 0) else { return false };
    if !breakpoints::suspend(address) {
        return false;
    }
    slot.store(address, Ordering::Release);
    true
}

/// Os breakpoints suspensos por comandos do host voltam (a sessão acabou).
pub fn restore_session_breakpoints() {
    for slot in SESSION_SUSPENDED.iter() {
        let address = slot.swap(0, Ordering::AcqRel);
        if address != 0 {
            breakpoints::restore(address);
        }
    }
}

/// Entrada dos trampolins (vetores 1, 2 e 3 do anel 0, a NMI de qualquer
/// anel no BSP e o tique do relógio com byte na porta ou pedido).
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
    if reason == REASON_NMI {
        return nmi(number, frame, fx, stepping);
    }
    // Um trap dentro do próprio depurador não é do depurador. O `int 3` de
    // um breakpoint do host que um comando atingiu executa o byte original;
    // outro trap segue o caminho comum e, sem tratador, o ponto de
    // recuperação abandona o comando (`kd::recovery`).
    if OWNER.load(Ordering::Acquire) == me && !stepping {
        if reason == REASON_BREAKPOINT && recovery::armed_here(number) {
            let address = view.rip().wrapping_sub(1);
            if breakpoints::inserted_at(address) && suspend_for_session(address) {
                view.set_rip(address);
                return HANDLED;
            }
        }
        return DECLINED;
    }
    match reason {
        REASON_POLL => poll(number, frame, fx),
        REASON_DEBUG => {
            let status: u64;
            // SAFETY: DR6 do processador corrente; os bits são limpos aqui.
            unsafe {
                core::arch::asm!("mov {}, dr6", out(reg) status, options(nomem, nostack));
                core::arch::asm!("mov dr6, {}", in(reg) 0xFFFF_0FF0u64, options(nomem, nostack));
            }
            super::extended_state::set_entry_dr6(status);
            if stepping && status & DR6_SINGLE_STEP != 0 {
                if trace::active() {
                    // Um passo do rastro: grava e segue sem voltar ao host.
                    finish_step(number, &view);
                    return match trace::after_step(&view) {
                        trace::Next::Continue => {
                            prepare_step(number, &view, 0, false);
                            HANDLED
                        }
                        trace::Next::Stop(kind) => enter(number, frame, fx, false, SIGTRAP, kind, 0).unwrap_or(HANDLED),
                    };
                }
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
                trace::abandon();
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
            let load_break: unsafe extern "sysv64" fn(u64, u64, u64, u64, u64, u64) = opennt_kd_load_break;
            if address == load_break as usize as u64 {
                // Carga de imagem do filtro: o RIP fica depois do `int 3`.
                return enter(number, frame, fx, false, SIGTRAP, Kind::Library, 0).unwrap_or_else(repeat);
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

/// O tique do relógio no anel 0 com byte na porta, NMI adiada ou autoteste.
fn poll(number: usize, frame: u64, fx: u64) -> u32 {
    let request = TICK_REQUEST.swap(0, Ordering::AcqRel);
    if OWNER.load(Ordering::Acquire) != 0 {
        // Outro processador é o dono e este não ficou preso (a NMI de
        // congelamento se perdeu): o KiCheckForFreezeExecution do tique.
        if FREEZE.load(Ordering::Acquire) != 0 {
            check_for_freeze(number, frame, fx);
        }
        // A máquina está num passo, ou parada por outro: o pedido fica para
        // depois.
        if request != 0 {
            TICK_REQUEST.fetch_or(request, Ordering::AcqRel);
        }
        return HANDLED;
    }
    if request & TICK_NMI != 0 {
        if request & !TICK_NMI != 0 {
            TICK_REQUEST.fetch_or(request & !TICK_NMI, Ordering::AcqRel);
        }
        // Uma NMI repetida de um congelamento que já acabou, chegada numa
        // fronteira, não é pedido de parada.
        if consume_stray(number) {
            NMI_IGNORED.fetch_add(1, Ordering::Relaxed);
            return HANDLED;
        }
        // A NMI que chegou numa fronteira com o GS do usuário.
        NMI_DEFERRED.fetch_add(1, Ordering::Relaxed);
        return nmi_break(number, frame, fx);
    }
    if request & TICK_TEST != 0 {
        super::self_test::run_armed();
        return HANDLED;
    }
    if !transport::try_lock(number) {
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

/// A NMI no BSP (o KxNmiInterrupt/KiProcessNMI do 19041). Sempre volta ao
/// código interrompido: a NMI não é exceção.
fn nmi(number: usize, frame: u64, fx: u64, stepping: bool) -> u32 {
    let me = number as u32 + 1;
    NMI_RECEIVED[number].fetch_add(1, Ordering::Relaxed);
    // KiCheckForFreezeExecution: o congelamento pedido por outro dono prende
    // o processador; uma NMI repetida de um congelamento que já acabou é
    // consumida.
    if check_for_freeze(number, frame, fx) {
        return HANDLED;
    }
    // A máquina já está parada aqui (uma segunda NMI do host na sessão ou no
    // meio de um passo): nada a fazer.
    if OWNER.load(Ordering::Acquire) == me || stepping {
        NMI_IGNORED.fetch_add(1, Ordering::Relaxed);
        return HANDLED;
    }
    // KiNmiInProgress: uma NMI aninhada na NMI deste processador.
    if NMI_ACTIVE[number].swap(true, Ordering::AcqRel) {
        NMI_IGNORED.fetch_add(1, Ordering::Relaxed);
        return HANDLED;
    }
    let result = nmi_break(number, frame, fx);
    NMI_ACTIVE[number].store(false, Ordering::Release);
    result
}

/// A parada pedida por NMI: o pedido de um AP, se houver, ou o do host.
fn nmi_break(number: usize, frame: u64, fx: u64) -> u32 {
    let me = number as u32 + 1;
    // KiNMILock, tomada sem esperar: enquanto outro processador a tem, este
    // confere o congelamento (o laço do KiProcessNMI).
    while NMI_LOCK.compare_exchange(0, me, Ordering::AcqRel, Ordering::Acquire).is_err() {
        if FREEZE.load(Ordering::Acquire) != 0 && check_for_freeze(number, frame, fx) {
            return HANDLED;
        }
        core::hint::spin_loop();
    }
    let request = AP_REQUEST.load(Ordering::Acquire);
    if request != 0 {
        let signal = (request >> 8) as u8;
        // A parada mostra o AP que pediu (preso pela NMI do congelamento).
        REPORT_PROCESSOR.store(request & 0xFF, Ordering::Release);
        if signal == SIGINT {
            session::set_host_waiting();
        }
        if enter(number, frame, fx, false, signal, Kind::Signal, 0).is_some() {
            let _ = AP_REQUEST.compare_exchange(request, 0, Ordering::AcqRel, Ordering::Acquire);
        } else {
            REPORT_PROCESSOR.store(0, Ordering::Release);
        }
    } else {
        NMI_BREAKS.fetch_add(1, Ordering::Relaxed);
        // O host que mandou a NMI espera a resposta de parada.
        session::set_host_waiting();
        let _ = enter(number, frame, fx, false, SIGINT, Kind::Nmi, 0);
    }
    NMI_LOCK.store(0, Ordering::Release);
    HANDLED
}

/// NMI de congelamento nos APs (o portão de NMI da IDT deles), com o
/// congelamento ativo e o GS do kernel: o quadro completo e a área FXSAVE64
/// da entrada (`hal::amd64::aptrampoline`). O dono da parada recebe a NMI
/// de um shootdown de TLB por aqui também, e só a atende.
#[no_mangle]
extern "sysv64" fn rs_kd_freeze_processor(frame: *mut TrapFrame, fx: u64) {
    let number = current_processor();
    NMI_RECEIVED[number].fetch_add(1, Ordering::Relaxed);
    if FREEZE.load(Ordering::Acquire) != 0 {
        check_for_freeze(number, frame as u64, fx);
    }
}

/// NMI ao processador do APIC id `target` pelo ICR do LAPIC (modo NMI,
/// nível ligado, o 0x4400 do código de IPI do Ke), sem as travas do Ke: quem
/// chama pode ser o dono delas.
fn send_nmi_to(target: u32) {
    const COMMAND_LOW: u32 = 0x300;
    const COMMAND_HIGH: u32 = 0x310;
    const DELIVERY_PENDING: u32 = 1 << 12;
    const NMI_COMMAND: u32 = 0x4400;
    let idle = || {
        let deadline = clock::uptime_ms() + 100;
        while lapic::read(COMMAND_LOW) & DELIVERY_PENDING != 0 && clock::uptime_ms() < deadline {
            core::hint::spin_loop();
        }
    };
    let flags = cpu::save_and_disable_interrupts();
    idle();
    lapic::write(COMMAND_HIGH, target << 24);
    lapic::write(COMMAND_LOW, NMI_COMMAND);
    idle();
    cpu::restore_interrupts(flags);
}

/// NMI ao próprio processador (o autoteste da parada por NMI).
pub fn send_self_nmi() {
    send_nmi_to(lapic::read(0x20) >> 24);
}

/// Pede a entrada no próximo tique do relógio no anel 0 (`TICK_TEST`).
pub fn request_tick(bits: u8) {
    TICK_REQUEST.fetch_or(bits, Ordering::AcqRel);
}

/// O processador corrente tem a IDT inteira: o BSP e os APs com o anel 3
/// armado (`smp::start_scheduling` copia a IDT do BSP), em que o `int 3` e
/// o #DB chegam ao depurador pelos trampolins. Os outros APs só têm os
/// portões 0-2 (o da NMI): um `int 3` ali seria falta tripla.
fn has_debug_vectors() -> bool {
    #[repr(C, packed)]
    struct TableRegister {
        limit: u16,
        base: u64,
    }
    let mut register = TableRegister { limit: 0, base: 0 };
    // SAFETY: `sidt` grava os 10 bytes do IDTR no registro local.
    unsafe { core::arch::asm!("sidt [{}]", in(reg) &mut register as *mut TableRegister, options(nostack, preserves_flags)) };
    let limit = register.limit;
    limit as usize >= 4 * 16 - 1
}

/// Um AP sem a IDT inteira não tem `int 3`: a parada é pedida ao BSP por
/// NMI, e este processador fica preso com os outros até o degelo. Sem
/// resposta do BSP no prazo, segue sem parar.
fn request_stop_from_application_processor(number: usize, signal: u8) {
    let target = BSP_APIC_ID.load(Ordering::Acquire);
    if target > 0xFF || number + 1 > 0xFF {
        return;
    }
    let request = (signal as u32) << 8 | (number as u32 + 1);
    if AP_REQUEST.compare_exchange(0, request, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return;
    }
    let sequence = STOP_SEQUENCE.load(Ordering::Acquire);
    send_nmi_to(target);
    let deadline = clock::uptime_ms() + FREEZE_TIMEOUT_MS;
    while AP_REQUEST.load(Ordering::Acquire) == request && STOP_SEQUENCE.load(Ordering::Acquire) == sequence {
        if clock::uptime_ms() >= deadline {
            debug_print!("[kd] o BSP nao atendeu o pedido de parada do processador {}", number);
            break;
        }
        core::hint::spin_loop();
    }
    let _ = AP_REQUEST.compare_exchange(request, 0, Ordering::AcqRel, Ordering::Acquire);
    while OWNER.load(Ordering::Acquire) != 0 {
        core::hint::spin_loop();
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
/// máquina parada na instrução que faltou. Devolve se a execução volta ao
/// quadro: o host mudou o RIP (pulou a instrução) ou pediu um passo (a
/// instrução repete e, faltando de novo, para de novo). Continuar sem mudar
/// o RIP segue o diagnóstico (a falta não tem para onde voltar). A falta
/// dupla e o machine check nunca voltam. Uma falta dentro de um comando do
/// host abandona o comando (`kd::recovery`); uma falta no meio de um passo
/// encerra o passo e vira uma parada nova.
pub fn fatal_exception(frame: *mut TrapFrame) -> bool {
    if !active() {
        return false;
    }
    let number = current_processor();
    let me = number as u32 + 1;
    let address = frame as u64;
    // SAFETY: o quadro vivo do trampolim da exceção.
    let (vector, first_word) = unsafe { ((*frame).vector & 0xFF, (*frame).hardware[0]) };
    let error_code = crate::hal::amd64::irqstubs::has_error_code(vector as u8);
    let view = View { frame: address, error_code, ..View::default() };
    if recovery::armed_here(number) {
        recovery::recover(recovery::Event::Fault { vector: vector as u8, rip: view.rip(), error: if error_code { first_word } else { 0 }, address: cpu::read_cr2() });
    }
    if OWNER.load(Ordering::Acquire) == me {
        if STEP_PROCESSOR.load(Ordering::Acquire) != me {
            return false;
        }
        // A instrução do passo (ou do rastro) faltou sem tratador.
        finish_step(number, &view);
        trace::abandon();
    } else {
        // Espera o dono atual sair, se outro processador estiver no depurador.
        while OWNER.load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }
    }
    debug_print!("[kd] excecao de kernel (vetor {:#x}) parada no depurador", vector);
    let before = view.rip();
    if enter(number, address, 0, error_code, exception_signal(vector), Kind::Signal, 0).is_none() {
        return false;
    }
    let stepping = STEP_PROCESSOR.load(Ordering::Acquire) == me;
    if matches!(vector, 8 | 18) {
        if stepping {
            finish_step(number, &view);
            continue_execution(number, &view);
        }
        return false;
    }
    stepping || view.rip() != before
}

/// Parada pedida pelo kernel (um pedido do host já na porta na
/// inicialização ou um 0x03 lido no meio de uma impressão).
pub fn break_in_now() {
    if !active() || stopped() {
        return;
    }
    let number = current_processor();
    if number != 0 && !has_debug_vectors() {
        request_stop_from_application_processor(number, SIGINT);
        return;
    }
    // SAFETY: `int 3; ret` reconhecido pela entrada do vetor 3.
    unsafe { opennt_kd_break_in() };
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
    let number = current_processor();
    if number != 0 && !has_debug_vectors() {
        request_stop_from_application_processor(number, SIGABRT);
        return;
    }
    // SAFETY: `int 3; ret` reconhecido pela entrada do vetor 3.
    unsafe { opennt_kd_bugcheck_break() };
}

/// KeBugCheckEx chamado de dentro de um comando do host (que tocou o kernel
/// com a máquina parada): o comando é abandonado e a sessão segue; o
/// bugcheck não acontece. Fora disso, nada.
pub fn bug_check_in_debugger(code: u32, parameters: [u64; 4]) {
    if active() && recovery::armed_here(current_processor()) {
        recovery::recover(recovery::Event::BugCheck { code, parameters });
    }
}

/// O KiSendFreeze do KeBugCheckEx: os outros processadores ficam presos
/// pela NMI de congelamento (com o quadro publicado, como numa parada do
/// depurador) até um degelo; devolve quantos estão presos.
pub fn freeze_for_bug_check() -> usize {
    let number = current_processor();
    freeze_others(number);
    (0..MAX_CPUS).filter(|&other| other != number && ipi_frozen_of(other) == FROZEN_TARGET).count()
}

/// O KiSendThawExecution do KeBugCheckEx antes do reinício.
pub fn thaw_after_bug_check() {
    thaw_others(current_processor());
}

/// Pânico do kernel com o depurador ativo: para antes de travar a CPU. O
/// pânico de um comando do host abandona só o comando.
pub fn panic_stop() {
    if !active() {
        return;
    }
    let number = current_processor();
    if recovery::armed_here(number) {
        recovery::recover(recovery::Event::Panic);
    }
    if stopped() {
        return;
    }
    if number != 0 && !has_debug_vectors() {
        request_stop_from_application_processor(number, SIGABRT);
        return;
    }
    // SAFETY: `int 3; ret` reconhecido pela entrada do vetor 3.
    unsafe { opennt_kd_panic_break() };
}

/// Carga de imagem que casou com o filtro do host (`kd::events`): para a
/// máquina com os argumentos do evento nos registradores (a resposta de
/// parada os leva em `load:`).
pub fn load_break(base: u64, size: u64, process_id: u64, name: u64, name_length: u64, system: u64) {
    if active() {
        // SAFETY: `int 3; ret` reconhecido pela entrada do vetor 3; os
        // argumentos só ficam nos registradores.
        unsafe { opennt_kd_load_break(base, size, process_id, name, name_length, system) };
    }
}

/// DbgBreakPointWithStatus com o depurador ativo: `int 3` com o status no
/// RCX; o host continua depois dele. Num AP, a parada pedida ao BSP.
pub fn break_with_status(status: u32) {
    let number = current_processor();
    if number != 0 && !has_debug_vectors() {
        if !stopped() {
            request_stop_from_application_processor(number, SIGTRAP);
        }
        return;
    }
    // SAFETY: `mov rcx, rdi; int 3; ret`.
    unsafe { opennt_kd_break_with_status(status as u64) };
}

/// `monitor nmi`: a parada por NMI e o estado de congelamento de cada
/// processador.
pub fn describe_nmi(out: &mut Payload) {
    let _ = writeln!(
        out,
        "NMI: paradas pedidas por NMI {} adiadas para o tique {} ignoradas com a maquina parada {}; comandos abandonados {}",
        NMI_BREAKS.load(Ordering::Relaxed),
        NMI_DEFERRED.load(Ordering::Relaxed),
        NMI_IGNORED.load(Ordering::Relaxed),
        recovery::recovered()
    );
    for number in (0..MAX_CPUS).filter(|&number| online(number)) {
        let received = NMI_RECEIVED[number].load(Ordering::Relaxed);
        let state = if owner() == Some(number) {
            "dono da parada"
        } else if PROCESSORS[number].frozen.load(Ordering::Acquire) {
            "congelado"
        } else if boundary_frame(number) != 0 {
            "congelado numa fronteira com o GS do usuario"
        } else {
            "rodando"
        };
        let _ = writeln!(out, "CPU {}: {} (KPRCB.IpiFrozen {}), NMIs recebidas {}", number, state, ipi_frozen_of(number), received);
    }
}
