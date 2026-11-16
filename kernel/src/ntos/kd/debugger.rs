//! O depurador do kernel visto pelos drivers: KdDebuggerEnabled,
//! KdDebuggerNotPresent, KUSER_SHARED_DATA.KdDebuggerEnabled e as rotinas
//! que os consultam ou mudam, com a lógica do ntoskrnl 19041.
//!
//! Sem `--kd` o boot é o de um Windows sem /DEBUG: KdPitchDebugger, e
//! KdEnableDebugger, KdDisableDebugger e KdChangeOption devolvem
//! STATUS_DEBUGGER_INACTIVE (o teste do KdPitchDebugger vem antes de tudo
//! nas três), KdRefreshDebuggerNotPresent devolve TRUE e KdDebuggerEnabled
//! fica FALSE. Com `--kd=comN` o depurador do OpenNT (`kd::stop`) está
//! ligado, como o KdInitSystem com o transporte iniciado: KdDebuggerEnabled
//! = TRUE, o bit 0 do KUSER_SHARED_DATA.KdDebuggerEnabled e
//! KdComPortInUse com a porta do transporte; o
//! KdDebuggerNotPresent continua TRUE até um host trocar pacotes, quando
//! cai para FALSE com o bit 1 (presente) ligado, como o transporte faz
//! quando o host responde; o host se desligando desfaz os dois.
//!
//! - KdDisableDebugger (KdDisableDebuggerWithLock): KdBlockEnable recusa
//!   com STATUS_ACCESS_DENIED; sob a KdDebuggerLock em DISPATCH_LEVEL, o
//!   primeiro desligamento (KdDisableCount 0) guarda KdPreviouslyEnabled e,
//!   com o depurador ligado, recusa com STATUS_ACCESS_DENIED se algum
//!   processador tem registrador de depuração do kernel habilitado
//!   (KdpAllowDisable: KPRCB.ProcessorState.SpecialRegisters.KernelDr7),
//!   tira os breakpoints da memória, zera o KUSER_SHARED_DATA.KdDebuggerEnabled,
//!   desliga a rotina de depuração, liga KdDebuggerNotPresent, desliga
//!   KdDebuggerEnabled e põe o transporte em D3; a contagem sobe sempre.
//! - KdEnableDebugger: KdBlockEnable recusa; sem desligamento pendente,
//!   STATUS_INVALID_PARAMETER; a contagem desce e, chegando a 0 com
//!   KdPreviouslyEnabled, o transporte volta a D0, a rotina e
//!   KdDebuggerEnabled voltam, o KUSER_SHARED_DATA.KdDebuggerEnabled vale 1
//!   e os breakpoints voltam à memória.
//! - KdChangeOption(Option, InBufferBytes, InBuffer, OutBufferBytes,
//!   OutBuffer, OutBufferNeeded): só KD_OPTION_SET_BLOCK_ENABLE (0); outra
//!   opção é STATUS_INVALID_INFO_CLASS; InBufferBytes != 1, OutBufferBytes
//!   != 0 ou OutBuffer não nulo, STATUS_INVALID_PARAMETER; KdBlockEnable com
//!   o bit 7 trava em STATUS_ACCESS_DENIED; senão KdBlockEnable = *InBuffer.
//!   *OutBufferNeeded = 0 no sucesso e na opção inválida.
//! - KdRefreshDebuggerNotPresent: depurador desligado, TRUE; ligado, o
//!   KdDebuggerNotPresent da sessão corrente.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

use super::{breakpoints, power, stop};
use crate::hal::amd64::{native_call, private_entries};
use crate::hal::volatile;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::mm::{kernel_address, kernel_data, shared_user_data};
use crate::rtl::KernelError;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_DEBUGGER_INACTIVE: u32 = 0xC000_0354;
/// KD_OPTION_SET_BLOCK_ENABLE.
const OPTION_SET_BLOCK_ENABLE: u32 = 0;
/// KUSER_SHARED_DATA.KdDebuggerEnabled: bit 0 ligado, bit 1 presente.
const SHARED_ENABLED: u8 = 1;
const SHARED_PRESENT: u8 = 2;
/// PowerDeviceD0/D3 com o bit de forçar (0x40000000) do KdPowerTransitionEx.
const POWER_D0_FORCED: u32 = 0x4000_0001;
const POWER_D3_FORCED: u32 = 0x4000_0004;

/// KdPitchDebugger: o boot não pediu depurador.
static PITCH: AtomicBool = AtomicBool::new(true);
/// KdDisableCount.
static DISABLE_COUNT: AtomicU32 = AtomicU32::new(0);
/// KdPreviouslyEnabled.
static PREVIOUSLY_ENABLED: AtomicBool = AtomicBool::new(false);
/// KdBlockEnable.
static BLOCK_ENABLE: AtomicU8 = AtomicU8::new(0);
/// Células KdDebuggerEnabled e KdDebuggerNotPresent, guardadas na
/// inicialização: a sessão as grava com a máquina parada, sem consultar a
/// tabela de dados.
static ENABLED_CELL: AtomicU64 = AtomicU64::new(0);
static NOT_PRESENT_CELL: AtomicU64 = AtomicU64::new(0);

/// O boot pediu o depurador (KdPitchDebugger FALSE).
pub fn pitched() -> bool {
    PITCH.load(Ordering::Acquire)
}

fn set_enabled(value: bool) {
    let cell = ENABLED_CELL.load(Ordering::Acquire);
    if cell != 0 {
        volatile::write8(cell, value as u8);
    }
}

/// KdDebuggerEnabled.
pub fn enabled() -> bool {
    let cell = ENABLED_CELL.load(Ordering::Acquire);
    cell != 0 && volatile::read8(cell) != 0
}

fn set_not_present(value: bool) {
    let cell = NOT_PRESENT_CELL.load(Ordering::Acquire);
    if cell != 0 {
        volatile::write8(cell, value as u8);
    }
}

fn not_present() -> bool {
    let cell = NOT_PRESENT_CELL.load(Ordering::Acquire);
    cell == 0 || volatile::read8(cell) != 0
}

fn shared_flags(update: impl FnOnce(u8) -> u8) {
    if let Some(shared) = shared_user_data::data() {
        shared.kd_debugger_enabled.set(update(shared.kd_debugger_enabled.get()));
    }
}

/// O depurador do OpenNT foi iniciado no boot (o KdInitSystem com o
/// transporte pronto) na UART em `port`: KdComPortInUse passa a apontar a
/// porta, como o transporte serial do NT grava ao iniciar (quem enumera as
/// portas seriais deixa a do depurador de fora).
pub fn enable_at_boot(port: u16) -> Result<(), KernelError> {
    ENABLED_CELL.store(kernel_data::address("KdDebuggerEnabled")?, Ordering::Release);
    NOT_PRESENT_CELL.store(kernel_data::address("KdDebuggerNotPresent")?, Ordering::Release);
    volatile::write64(kernel_data::address("KdComPortInUse")?, port as u64);
    PITCH.store(false, Ordering::Release);
    set_enabled(true);
    shared_flags(|_| SHARED_ENABLED);
    Ok(())
}

/// Um host passou a trocar pacotes (`true`) ou se desligou (`false`).
pub fn set_debugger_present(present: bool) {
    set_not_present(!present);
    shared_flags(|flags| if present { flags | SHARED_PRESENT } else { flags & !SHARED_PRESENT });
}

/// KdEnableDebugger.
pub fn enable_debugger() -> u32 {
    if pitched() {
        return STATUS_DEBUGGER_INACTIVE;
    }
    if BLOCK_ENABLE.load(Ordering::Acquire) != 0 {
        return STATUS_ACCESS_DENIED;
    }
    power::with_debugger_lock(|| {
        let count = DISABLE_COUNT.load(Ordering::Acquire);
        if count == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        DISABLE_COUNT.store(count - 1, Ordering::Release);
        if count == 1 && PREVIOUSLY_ENABLED.load(Ordering::Acquire) {
            power::power_transition(POWER_D0_FORCED, false);
            stop::set_routine(true);
            set_enabled(true);
            shared_flags(|_| SHARED_ENABLED);
            breakpoints::restore_all();
        }
        STATUS_SUCCESS
    })
}

/// KdDisableDebugger.
pub fn disable_debugger() -> u32 {
    if pitched() {
        return STATUS_DEBUGGER_INACTIVE;
    }
    if BLOCK_ENABLE.load(Ordering::Acquire) != 0 {
        return STATUS_ACCESS_DENIED;
    }
    power::with_debugger_lock(|| {
        if DISABLE_COUNT.load(Ordering::Acquire) == 0 {
            let was_enabled = enabled();
            PREVIOUSLY_ENABLED.store(was_enabled, Ordering::Release);
            if was_enabled {
                // KdpAllowDisable: um registrador de depuração do kernel
                // habilitado impede o desligamento.
                if breakpoints::any_hardware() {
                    return STATUS_ACCESS_DENIED;
                }
                breakpoints::suspend_all();
                shared_flags(|_| 0);
                stop::set_routine(false);
                set_not_present(true);
                set_enabled(false);
                power::power_transition(POWER_D3_FORCED, false);
            }
        }
        DISABLE_COUNT.fetch_add(1, Ordering::AcqRel);
        STATUS_SUCCESS
    })
}

/// KdRefreshDebuggerNotPresent.
pub fn refresh_debugger_not_present() -> u64 {
    if pitched() || !enabled() {
        return 1;
    }
    not_present() as u64
}

/// KdChangeOption.
pub fn change_option(option: u32, in_buffer_bytes: u32, in_buffer: u64, out_buffer_bytes: u32, out_buffer: u64, out_buffer_needed: u64) -> u32 {
    if pitched() {
        return STATUS_DEBUGGER_INACTIVE;
    }
    let status = if option != OPTION_SET_BLOCK_ENABLE {
        STATUS_INVALID_INFO_CLASS
    } else {
        if in_buffer_bytes != 1 || out_buffer_bytes != 0 || out_buffer != 0 {
            return STATUS_INVALID_PARAMETER;
        }
        if BLOCK_ENABLE.load(Ordering::Acquire) & 0x80 != 0 {
            return STATUS_ACCESS_DENIED;
        }
        // SAFETY: o BOOLEAN de entrada do chamador de kernel.
        BLOCK_ENABLE.store(unsafe { Field::<u8>::at(in_buffer) }.get(), Ordering::Release);
        STATUS_SUCCESS
    };
    if out_buffer_needed != 0 {
        // SAFETY: o PULONG de saída do chamador de kernel.
        unsafe { Field::<u32>::at(out_buffer_needed) }.set(0);
    }
    status
}

/// KdPollBreakIn: o host pediu parada? Como no ntoskrnl 19041, com
/// KdPitchDebugger (sem depurador no boot) ou KdDebuggerEnabled desligado é
/// FALSE (o OpenNT não tem o registro de eventos do KD); senão, com as
/// interrupções mascaradas e a trava do transporte tomada sem esperar (o
/// KxTryToAcquireSpinLock(KdDebuggerLock)), pergunta ao transporte se há
/// pedido do host (o KdReceivePacket(PACKET_TYPE_KD_POLL_BREAKIN)) e o
/// resultado vale só com KdDebuggerEnabled. No transporte do OpenNT o pedido
/// é qualquer byte do host na porta (o 0x03 ou o começo de um pacote); o
/// byte fica na porta para a consulta do tique do relógio, que para a
/// máquina (o papel do KdpControlCPressed). Com a máquina parada ou com a
/// trava ocupada a resposta é FALSE.
pub fn poll_break_in() -> bool {
    if pitched() || !enabled() {
        return false;
    }
    let flags = crate::hal::cpu::save_and_disable_interrupts();
    let mut requested = false;
    if !stop::stopped() && super::transport::try_lock(stop::current_processor()) {
        requested = super::transport::byte_pending();
        super::transport::unlock();
    }
    requested &= enabled();
    crate::hal::cpu::restore_interrupts(flags);
    requested
}

/// DbgBreakPointWithStatus: com o depurador ligado, `int 3` com o status
/// no RCX e o host decide; sem ele, um INT 3 não tratado vira
/// KMODE_EXCEPTION_NOT_HANDLED.
pub fn break_point_with_status(status: u32) -> Result<u64, KernelError> {
    if stop::active() {
        stop::break_with_status(status);
        return Ok(0);
    }
    debug_print!("[kd] DbgBreakPointWithStatus status={:#x} sem debugger — KMODE_EXCEPTION_NOT_HANDLED", status);
    crate::hal::cpu::halt_forever()
}

/// Estado para o `monitor kd`.
pub fn describe(out: &mut super::packet::Payload) {
    use core::fmt::Write;
    let shared = shared_user_data::data().map_or(0, |shared| shared.kd_debugger_enabled.get());
    let _ = writeln!(
        out,
        "KdPitchDebugger={} KdDebuggerEnabled={} KdDebuggerNotPresent={} SharedUserData.KdDebuggerEnabled={:#x} KdDisableCount={} KdBlockEnable={} porta={:#x}",
        pitched() as u8,
        enabled() as u8,
        not_present() as u8,
        shared,
        DISABLE_COUNT.load(Ordering::Acquire),
        BLOCK_ENABLE.load(Ordering::Acquire),
        super::transport::base()
    );
}

fn data_address(name: &str) -> u64 {
    kernel_data::address(name).unwrap_or_else(|error| panic!("{name}: {error}"))
}

/// Célula do export de dados KdDebuggerEnabled.
pub fn debugger_enabled_address() -> u64 {
    data_address("KdDebuggerEnabled")
}

/// Célula do export de dados KdDebuggerNotPresent.
pub fn debugger_not_present_address() -> u64 {
    data_address("KdDebuggerNotPresent")
}

/// Célula do export de dados KdEnteredDebugger.
pub fn entered_debugger_address() -> u64 {
    data_address("KdEnteredDebugger")
}

/// Célula do export de dados KdComPortInUse (PUCHAR, nulo sem depurador por
/// serial).
pub fn com_port_in_use_address() -> u64 {
    data_address("KdComPortInUse")
}

/// Célula do export de dados KdHvComPortInUse (PUCHAR, nulo sem depurador do
/// hipervisor por serial).
pub fn hv_com_port_in_use_address() -> u64 {
    data_address("KdHvComPortInUse")
}

/// DbgBreakPoint: o corpo nativo é o do ntoskrnl 19041 (`int 3; ret`). Com o
/// depurador ligado, o `int 3` para a máquina; sem ele, a exceção
/// STATUS_BREAKPOINT segue pelo despacho de exceções de kernel: um handler
/// do chamador a trata; sem handler, KMODE_EXCEPTION_NOT_HANDLED.
pub fn break_point() -> Result<(), KernelError> {
    let entry = private_entries::entry("dbg_break_point").ok_or_else(|| KernelError::new("DbgBreakPoint native body is missing"))?;
    let address = kernel_address::image_address(entry)?;
    native_call::call(address, &[]);
    Ok(())
}

/// DbgPrompt(Prompt, Response, Length): os três argumentos vão ao corpo
/// nativo; devolve o resultado de 32 bits.
pub fn prompt(prompt: u64, response: u64, length: u64) -> Result<u32, KernelError> {
    let entry = private_entries::entry("dbg_prompt").ok_or_else(|| KernelError::new("DbgPrompt native body is missing"))?;
    let address = kernel_address::image_address(entry)?;
    Ok(native_call::call(address, &[prompt, response, length]) as u32)
}
