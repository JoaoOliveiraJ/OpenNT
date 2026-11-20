//! Desligamento do sistema: NtShutdownSystem, NtSetSystemPowerState das
//! ações de desligamento, o PopGracefulShutdown e o PopShutdownSystem.
//!
//! Como no ntoskrnl 19041:
//! - NtShutdownSystem(Action) (rva 0x5b2800) traduz a ação e chama o
//!   NtSetSystemPowerState(SystemAction, PowerSystemSleeping3, Flags =
//!   POWER_ACTION_CRITICAL | POWER_ACTION_DISABLE_WAKES |
//!   POWER_ACTION_OVERRIDE_APPS): ShutdownNoReboot (0) = PowerActionShutdown,
//!   ShutdownReboot (1) = PowerActionShutdownReset, ShutdownPowerOff (2) =
//!   PowerActionShutdownOff. A ação 3 (reinício para recuperação) exige o
//!   SeShutdownPrivilege de quem chama do modo usuário e vai ao
//!   ExRebootSystemForRecovery, que não volta; outra ação dá
//!   STATUS_INVALID_PARAMETER.
//! - NtSetSystemPowerState (PopTransitionSystemPowerStateEx, rva 0x9918d8):
//!   LightestSystemState fora de 1..6, SystemAction fora de 1..7 ou Flags com
//!   bits de 0x0CFFFFC0 = STATUS_INVALID_PARAMETER; do modo usuário exige o
//!   SeShutdownPrivilege habilitado (STATUS_PRIVILEGE_NOT_HELD) e entra de
//!   novo pelo ZwSetSystemPowerState. Uma ação de desligamento lê a política
//!   `DontPowerOffAfterShutdown` (PopReadShutdownPolicy, só para
//!   PowerActionShutdown) e faz o desligamento ordenado; as de suspensão e
//!   hibernação dão STATUS_NOT_SUPPORTED: o OpenNT não suspende o sistema.
//! - PopGracefulShutdown (rva 0x9b10a0), na ordem do original: só com o
//!   PopShutdownCleanly diferente de zero (0x9b110b; o `PoCleanShutdownFlags`
//!   de `Session Manager\Kernel` pelo CmControlVector, 0 no boot comum), o
//!   PsShutdownSystem, o PopShutdownEvent sinalizado e as threads do
//!   PoRequestShutdownEvent esperadas; CmShutdownSystem(0);
//!   ExShutdownSystem(0) (o ShutdownTime); IoShutdownSystem(0) (PnpShutdownDevices e o IRP_MJ_SHUTDOWN dos
//!   IoRegisterShutdownNotification); CmShutdownSystem(1) (todas as hives no
//!   disco); ExShutdownSystem(1); MmShutdownSystem(0) (as páginas alteradas
//!   das vistas de arquivo); IoShutdownSystem(1) (os file systems, que
//!   descarregam os volumes e passam a recusar escritas, e a fila de última
//!   chance); CcWaitForCurrentLazyWriterActivity; ExShutdownSystem(2) e o
//!   PopShutdownSystem. Passos de componentes que o OpenNT não tem
//!   (TmShutdownSystem, ObShutdownSystem e PsWaitForAllProcesses só com
//!   PopShutdownCleanly, EtwShutdown, os IRPs de energia S5 aos
//!   dispositivos, o MmShutdownSystem(2)) ficam de fora.
//! - PopShutdownSystem (rva 0x9b2764): PowerActionShutdown com a política
//!   DontPowerOffAfterShutdown = 1 mostra que é seguro desligar e para o
//!   processador (PopShutdownHandler); sem ela, e em PowerActionShutdownOff,
//!   o tratador PowerStateShutdownOff (nenhum registrado: o OpenNT não
//!   registra os tratadores do ZwPowerInformation) e o
//!   HalReturnToFirmware(HalPowerDownRoutine); PowerActionShutdownReset, o
//!   HalReturnToFirmware(HalRebootRoutine).
//!
//! A serial marca as etapas: `SHUTDOWN_NOTIFIED` depois do IRP_MJ_SHUTDOWN
//! de todas as filas, `FLUSHED` depois do Cache Manager, e o HAL imprime
//! `POWER_OFF` ou `REBOOT` antes da escrita final.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::hal::firmware_return::{self, Routine};
use crate::ntos::cc::lazy_writer;
use crate::ntos::cm::{lazy_flush, registry};
use crate::ntos::ex::shutdown as executive;
use crate::ntos::inc::types::{Kevent, NtStruct};
use crate::ntos::io::shutdown as io_shutdown;
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_access;
use crate::ntos::po::{system_state, transition_checkpoint};
use crate::ntos::ps::previous_mode;
use crate::ntos::ps::user::state;
use crate::ntos::se::token::tokens;
use crate::rtl::KernelError;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
/// SE_SHUTDOWN_PRIVILEGE e SE_PRIVILEGE_ENABLED.
const SE_SHUTDOWN_PRIVILEGE: u64 = 19;
const SE_PRIVILEGE_ENABLED: u32 = 2;

/// POWER_ACTION das ações de desligamento.
pub const POWER_ACTION_SHUTDOWN: u32 = 4;
pub const POWER_ACTION_SHUTDOWN_RESET: u32 = 5;
pub const POWER_ACTION_SHUTDOWN_OFF: u32 = 6;
/// PowerSystemSleeping3 e as flags que o NtShutdownSystem passa.
const POWER_SYSTEM_SLEEPING3: u32 = 4;
const SHUTDOWN_FLAGS: u32 = 0xC000_0004;

/// A política `DontPowerOffAfterShutdown` e onde ela mora.
const POLICY_KEY: &str = "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows NT";
const POLICY_VALUE: &str = "DontPowerOffAfterShutdown";
const REG_DWORD: u32 = 4;

/// A entrada do CmControlVector do PopShutdownCleanly.
const KERNEL_KEY: &str = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel";
const CLEAN_SHUTDOWN_VALUE: &str = "PoCleanShutdownFlags";

/// PopShutdownPowerOffPolicy.
static POWER_OFF_POLICY: AtomicBool = AtomicBool::new(false);
/// PopShutdownCleanly: 0 na imagem do ntoskrnl.
static CLEAN_SHUTDOWN_FLAGS: AtomicU32 = AtomicU32::new(0);
/// Um desligamento ordenado já começou (só o primeiro segue).
static SHUTDOWN_STARTED: AtomicBool = AtomicBool::new(false);

/// Ação pedida ao NtShutdownSystem, já traduzida.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    /// NtSetSystemPowerState com a POWER_ACTION.
    PowerAction(u32),
    /// ExRebootSystemForRecovery.
    RebootForRecovery,
}

/// SHUTDOWN_ACTION -> pedido; `None` = STATUS_INVALID_PARAMETER.
pub fn translate(action: u32) -> Option<Request> {
    Some(match action {
        0 => Request::PowerAction(POWER_ACTION_SHUTDOWN),
        1 => Request::PowerAction(POWER_ACTION_SHUTDOWN_RESET),
        2 => Request::PowerAction(POWER_ACTION_SHUTDOWN_OFF),
        3 => Request::RebootForRecovery,
        _ => return None,
    })
}

/// SeSinglePrivilegeCheck(SeShutdownPrivilege, PreviousMode): o modo kernel
/// passa; o usuário precisa do privilégio habilitado no token.
pub fn holds_shutdown_privilege(mode: u8) -> bool {
    mode == 0 || object_access::subject().and_then(|token| tokens::with(token, |token| token.privileges.iter().any(|privilege| privilege.id == SE_SHUTDOWN_PRIVILEGE && privilege.attributes & SE_PRIVILEGE_ENABLED != 0))).unwrap_or(false)
}

/// As validações do PopTransitionSystemPowerStateEx (sem o privilégio).
pub fn validate_power_state(action: u32, lightest_state: u32, flags: u32) -> u32 {
    if lightest_state.wrapping_sub(1) > 5 || action.wrapping_sub(1) > 6 || flags & 0x0CFF_FFC0 != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    0
}

/// PopReadShutdownPolicy: DontPowerOffAfterShutdown REG_DWORD de primeiro
/// byte 1 liga a política; sem a chave, o valor ou com outro tipo, ela fica
/// como estava.
pub fn read_shutdown_policy() {
    if let Some(value) = registry::read_value_by_path(POLICY_KEY, POLICY_VALUE).filter(|value| value.value_type == REG_DWORD) {
        POWER_OFF_POLICY.store(value.data.first() == Some(&1), Ordering::SeqCst);
    }
}

/// A política DontPowerOffAfterShutdown em vigor.
pub fn power_off_policy() -> bool {
    POWER_OFF_POLICY.load(Ordering::SeqCst)
}

/// A entrada `Session Manager\Kernel\PoCleanShutdownFlags` do CmControlVector
/// (o CmpGetSystemControlValues logo depois da carga da SYSTEM): até
/// BufferLength (4, o ULONG do PopShutdownCleanly) bytes do valor, de
/// qualquer tipo, sobre o 0 da imagem.
pub fn initialize_control_values() {
    let mut bytes = [0u8; 4];
    if let Some(value) = registry::read_value_by_path(KERNEL_KEY, CLEAN_SHUTDOWN_VALUE) {
        let length = value.data.len().min(4);
        bytes[..length].copy_from_slice(&value.data[..length]);
    }
    CLEAN_SHUTDOWN_FLAGS.store(u32::from_le_bytes(bytes), Ordering::Release);
}

/// O PopShutdownCleanly capturado no boot.
pub fn clean_shutdown_flags() -> u32 {
    CLEAN_SHUTDOWN_FLAGS.load(Ordering::Acquire)
}

/// O começo do PopGracefulShutdown (0x9b110b): só com o PopShutdownCleanly
/// diferente de zero o PopShutdownEvent é sinalizado e as threads do
/// PoRequestShutdownEvent são esperadas (sem prazo); no boot comum nada
/// disso acontece, a lista continua aberta e o evento, desligado. Devolve
/// quantas threads foram esperadas.
pub fn shutdown_event_step() -> usize {
    let flags = clean_shutdown_flags();
    if flags == 0 {
        return 0;
    }
    // O PsShutdownSystem e o PsWaitForAllProcesses que acompanham o valor
    // não existem no OpenNT.
    debug_print!("[po] PoCleanShutdownFlags={:#x}: threads do PoRequestShutdownEvent esperadas (sem PsShutdownSystem)", flags);
    step("PopShutdownEvent", system_state::notify_shutdown_waiters()).unwrap_or(0)
}

/// NtSetSystemPowerState(SystemAction, LightestSystemState, Flags): só
/// volta em falha.
pub fn set_system_power_state(action: u32, lightest_state: u32, flags: u32) -> Result<u32, KernelError> {
    let status = validate_power_state(action, lightest_state, flags);
    if status != 0 {
        return Ok(status);
    }
    if !holds_shutdown_privilege(previous_mode::get()?) {
        return Ok(STATUS_PRIVILEGE_NOT_HELD);
    }
    if action < POWER_ACTION_SHUTDOWN {
        return Ok(STATUS_NOT_SUPPORTED);
    }
    if action == POWER_ACTION_SHUTDOWN {
        read_shutdown_policy();
    }
    match action {
        POWER_ACTION_SHUTDOWN | POWER_ACTION_SHUTDOWN_RESET | POWER_ACTION_SHUTDOWN_OFF => graceful_shutdown(action),
        // PowerActionWarmEject: sem dispositivo de ejeção no OpenNT.
        _ => Ok(STATUS_NOT_SUPPORTED),
    }
}

/// NtShutdownSystem(Action): só volta em falha.
pub fn shutdown_system(action: u32) -> Result<u32, KernelError> {
    match translate(action) {
        None => Ok(STATUS_INVALID_PARAMETER),
        Some(Request::RebootForRecovery) => {
            if !holds_shutdown_privilege(previous_mode::get()?) {
                return Ok(STATUS_PRIVILEGE_NOT_HELD);
            }
            // ExRebootSystemForRecovery: o reinício sem a sequência ordenada.
            firmware_return::return_to_firmware(Routine::Reboot)
        }
        Some(Request::PowerAction(power_action)) => set_system_power_state(power_action, POWER_SYSTEM_SLEEPING3, SHUTDOWN_FLAGS),
    }
}

fn step<T>(name: &str, result: Result<T, KernelError>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            debug_print!("[po] desligamento: {} falhou: {}", name, error);
            None
        }
    }
}

/// O PopTransitionLock que um segundo pedido espera: um KEVENT de
/// notificação que nunca é sinalizado (o primeiro pedido desliga a máquina
/// sem soltá-lo).
static TRANSITION_LOCK: AtomicU64 = AtomicU64::new(0);

fn transition_lock() -> u64 {
    let current = TRANSITION_LOCK.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }
    let event = guest::alloc_bytes(Kevent::SIZE);
    if event == 0 {
        return 0;
    }
    dispatcher::initialize_event(event, 0, false);
    match TRANSITION_LOCK.compare_exchange(0, event, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => event,
        Err(existing) => {
            guest::free_bytes(event);
            existing
        }
    }
}

/// Um segundo pedido de desligamento: no 19041 ele para no
/// PopAcquireTransitionLock (rva 0x991abe) até a máquina desligar. A espera
/// é de KernelMode, sem prazo e sem alerta; a CPU de quem pediu segue
/// atendendo DPCs, timers e as outras threads.
pub fn wait_behind_running_shutdown() -> ! {
    let event = transition_lock();
    loop {
        if event == 0 {
            // Sem memória para o evento: nada a esperar além da parada.
            crate::hal::cpu::halt_forever();
        }
        dispatcher::wait_for_single_object(event, 0, 0, false);
    }
}

/// PopGracefulShutdown(Action): a sequência ordenada e o PopShutdownSystem.
fn graceful_shutdown(action: u32) -> ! {
    if SHUTDOWN_STARTED.swap(true, Ordering::SeqCst) {
        wait_behind_running_shutdown();
    }
    debug_print!("[po] desligamento ordenado: acao {}", action);
    transition_checkpoint::record(10, 1);
    let waited = shutdown_event_step();
    // CmShutdownSystem(0): sem transações do Registro no OpenNT.
    step("ExShutdownSystem(0)", executive::shutdown_system(0));
    step("IoShutdownSystem(0)", io_shutdown::shutdown_system(0));
    let hives = lazy_flush::shutdown();
    step("ExShutdownSystem(1)", executive::shutdown_system(1));
    // MmShutdownSystem(0): as vistas de arquivo no disco antes de os file
    // systems fecharem os volumes.
    crate::ntos::mm::shutdown::shutdown_system(0);
    transition_checkpoint::record(10, 2);
    step("IoShutdownSystem(1)", io_shutdown::shutdown_system(1));
    let (devices, file_systems, last_chance) = io_shutdown::delivered();
    debug_print!("SHUTDOWN_NOTIFIED threads={} dispositivos={} file_systems={} ultima_chance={}", waited, devices, file_systems, last_chance);
    let lazy = lazy_writer::wait_for_current_lazy_writer_activity();
    let committed = crate::drivers::storage::ata_volume::committed_sectors();
    debug_print!("FLUSHED hives={:#x} cache={:#x} setores_do_volume={}", hives, lazy, committed);
    step("ExShutdownSystem(2)", executive::shutdown_system(2));
    shutdown_system_final(action)
}

/// PopShutdownSystem(Action).
fn shutdown_system_final(action: u32) -> ! {
    match action {
        POWER_ACTION_SHUTDOWN_RESET => firmware_return::return_to_firmware(Routine::Reboot),
        POWER_ACTION_SHUTDOWN if power_off_policy() => {
            // PopShutdownHandler: a tela de que é seguro desligar e a parada.
            crate::drivers::console::print("E seguro desligar o computador.");
            debug_print!("[po] DontPowerOffAfterShutdown: seguro desligar; processador parado");
            crate::hal::cpu::halt_forever()
        }
        _ => firmware_return::return_to_firmware(Routine::PowerDown),
    }
}

// ---- serviços de modo usuário ----------------------------------------------

fn nt_shutdown_system(action: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    shutdown_system(action as u32)
}

fn nt_set_system_power_state(action: u64, lightest_state: u64, flags: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    set_system_power_state(action as u32, lightest_state as u32, flags as u32)
}

/// Os handlers dos serviços NtShutdownSystem e NtSetSystemPowerState.
pub fn register_user_services() {
    state::register_handler("NtShutdownSystem", nt_shutdown_system);
    state::register_handler("NtSetSystemPowerState", nt_set_system_power_state);
}
