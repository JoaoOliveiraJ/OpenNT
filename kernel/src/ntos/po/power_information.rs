//! NtPowerInformation (ntoskrnl 19041, rva 0x6f04e0), de modo kernel
//! (ZwPowerInformation) e de modo usuário.
//!
//! O nível 94 vai ao gravador black box do kernel; o 41 (SessionPowerInit)
//! e o 63 (SessionPowerCleanup) são o início e o fim da energia de uma
//! sessão, que o win32k pede no DriverEntry e na limpeza. Os níveis 4
//! (SystemPowerCapabilities), 5 (SystemBatteryState), 29
//! (SystemVideoState, o estado da tela do console), 58
//! (PowerSettingNotificationName), 59 (GetPowerSettingValue), 66
//! (PlatformInformation) e 75 (PlatformRole) têm o mesmo corpo nos dois
//! modos (`level_answer`), como o 42 (SessionDisplayState, o aviso de tela
//! do win32k), o 61 (SessionRITState) e o 62 (SessionConnectNotification),
//! a entrada e a conexão da sessão (`po/user_presence.rs`), que o modo
//! usuário não alcança, e o 87 (PowerInformationInternal): o
//! NtPowerInformation de modo kernel passa pelo mesmo
//! PopPowerInformationInternal (0x6f1b04), sem captura, e os tipos internos
//! só de kernel (o SessionPowerState, o SetWatchdog e o InputControllerState
//! do win32kbase) recusam o modo usuário. Os demais níveis de modo kernel
//! devolvem STATUS_INVALID_PARAMETER.
//!
//! Só de modo usuário: LastWakeTime e LastSleepTime (14 e 15, o
//! PopAction.WakeTime/SleepTime, zero num sistema que nunca dormiu),
//! SystemExecutionState (16, `po/power_request.rs`),
//! SystemMonitorHiberBootPowerOff (28, que exige um contexto administrador:
//! o PopHiberBootForceMonitorOff ligado e o PoPowerOffMonitor,
//! `po/win32_callout.rs`; o PopSuspendResumePdc não tem PDC no OpenNT), os
//! pedidos de energia (43 PowerRequestCreate, 44 PowerRequestAction e 72
//! PlmPowerRequestCreate), SessionLockState (64: o
//! PopSessionWinlogonNotification, cujo status o NT descarta),
//! SystemHiberbootState (65, o Hiberboot das capacidades filtradas, que o
//! OpenNT não tem), UpdateBlackBoxRecorder (94, `po/black_box.rs`) e
//! SessionAllowExternalDmaDevices (95: o ExNotifyCallback do
//! PipCslCallbackObject, sem registrados no OpenNT).

use alloc::vec::Vec;
use core::sync::atomic::AtomicU8;

use crate::ntos::inc::types::{NtStruct, SystemPowerCapabilities};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::po::{black_box, boot_status, display_state, power_request, power_setting, user_presence, watchdog};
use crate::rtl::KernelError;

const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// POWER_INFORMATION_LEVEL SystemPowerCapabilities e SystemBatteryState.
const SYSTEM_POWER_CAPABILITIES: u32 = 4;
const SYSTEM_BATTERY_STATE: u32 = 5;
/// POWER_INFORMATION_LEVEL PowerSettingNotificationName e
/// GetPowerSettingValue.
const POWER_SETTING_NOTIFICATION_NAME: u32 = 58;
const GET_POWER_SETTING_VALUE: u32 = 59;
/// POWER_INFORMATION_LEVEL PlatformInformation.
const PLATFORM_INFORMATION: u32 = 66;

/// POWER_INFORMATION_LEVEL LastWakeTime, LastSleepTime,
/// SystemExecutionState e SystemMonitorHiberBootPowerOff.
const LAST_WAKE_TIME: u32 = 14;
const LAST_SLEEP_TIME: u32 = 15;
const SYSTEM_EXECUTION_STATE: u32 = 16;
const SYSTEM_MONITOR_HIBER_BOOT_POWER_OFF: u32 = 28;
/// POWER_INFORMATION_LEVEL PowerRequestCreate, PowerRequestAction e
/// PlmPowerRequestCreate.
const POWER_REQUEST_CREATE: u32 = 43;
const POWER_REQUEST_ACTION: u32 = 44;
const PLM_POWER_REQUEST_CREATE: u32 = 72;
/// POWER_INFORMATION_LEVEL SessionLockState, SystemHiberbootState,
/// UpdateBlackBoxRecorder e SessionAllowExternalDmaDevices.
const SESSION_LOCK_STATE: u32 = 64;
const SYSTEM_HIBERBOOT_STATE: u32 = 65;
const UPDATE_BLACK_BOX_RECORDER: u32 = 94;
const SESSION_ALLOW_EXTERNAL_DMA_DEVICES: u32 = 95;
/// Os níveis que pedem um contexto administrador (PspIsContextAdmin) ao
/// modo usuário.
const ADMIN_LEVELS: [u32; 4] = [28, 45, 50, 78];
/// O deslocamento do Hiberboot no SYSTEM_POWER_CAPABILITIES.
const HIBERBOOT_OFFSET: usize = 0x12;

/// POWER_INFORMATION_LEVEL SessionPowerInit e SessionPowerCleanup.
const SESSION_POWER_INIT: u32 = 41;
const SESSION_POWER_CLEANUP: u32 = 63;

/// PopNoMoreInput e PopHiberBootForceMonitorOff: os BOOLEANs do Po cujos
/// endereços o SessionPowerInit entrega ao win32k (que os lê e grava).
static NO_MORE_INPUT: AtomicU8 = AtomicU8::new(0);
static HIBER_BOOT_FORCE_MONITOR_OFF: AtomicU8 = AtomicU8::new(0);
/// PopLidOpened: começa TRUE (o valor da imagem do ntoskrnl) e só muda com
/// uma tampa, que um desktop não tem.
const LID_OPENED: u8 = 1;

/// SessionPowerInit (NtPowerInformation 19041, 0x6f123a): sem entrada, a
/// saída de exatamente 0x40 bytes (senão STATUS_INVALID_PARAMETER) com os
/// endereços de PopNoMoreInput e PopHiberBootForceMonitorOff, os valores de
/// PopPowerSettingValues da sessão, o economizador de energia (PopEsState),
/// a tampa (PopLidOpened) e o TTM (TtmpEnabled; ligado, o NT também chama o
/// TtmInitCurrentSession). Os callbacks internos do Po que gravam o
/// PopPowerSettingValues (PopInitialSettingCallbacks) não são registrados,
/// então os valores de configuração ficam no zero de antes de qualquer
/// esquema, como o PopPowerSettingValues (.data sem inicializador) no boot,
/// e o economizador fica desligado.
fn session_power_init(input: u64, output: u64, output_length: u32) -> u32 {
    use crate::ntos::inc::types::extra_ps_user::PowerSessionInit;
    if input != 0 || output == 0 || output_length as u64 != PowerSessionInit::SIZE {
        return STATUS_INVALID_PARAMETER;
    }
    guest::write_bytes(output, &[0u8; 0x40]);
    // SAFETY: a saída do chamador (Zw, KernelMode) com os 0x40 bytes conferidos.
    let information = unsafe { PowerSessionInit::at(output) };
    information.no_more_input.set(NO_MORE_INPUT.as_ptr() as u64);
    information.hiber_boot_force_monitor_off.set(HIBER_BOOT_FORCE_MONITOR_OFF.as_ptr() as u64);
    information.lid_opened.set(LID_OPENED);
    information.ttm_enabled.set(crate::ntos::ttm::device::enabled() as u8);
    0
}

/// POWER_INFORMATION_LEVEL SystemVideoState e SessionDisplayState (o estado
/// da tela, `po/display_state.rs`).
const SYSTEM_VIDEO_STATE: u32 = 29;
const SESSION_DISPLAY_STATE: u32 = 42;
/// POWER_INFORMATION_LEVEL SessionRITState e SessionConnectNotification (a
/// entrada e a conexão da sessão, `po/user_presence.rs`).
const SESSION_RIT_STATE: u32 = 61;
const SESSION_CONNECT_NOTIFICATION: u32 = 62;

/// SessionPowerCleanup (0x6f17c4): sem entrada nem saída; o
/// PopFreeSessionState da sessão corrente. O OpenNT não guarda estado de
/// energia por sessão.
fn session_power_cleanup(input: u64, output: u64) -> u32 {
    if input != 0 || output != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    0
}

/// ZwPowerInformation (PreviousMode KernelMode): sem sondas nem captura; os
/// níveis de `level_answer` passam pelo mesmo fim comum do modo usuário.
/// Devolve o NTSTATUS.
pub fn query(level: u32, input: u64, input_length: u32, output: u64, output_length: u32) -> Result<u32, KernelError> {
    if level == 94 {
        return black_box::update_from_kernel(input, input_length, output, output_length);
    }
    if level == SESSION_POWER_INIT {
        return Ok(session_power_init(input, output, output_length));
    }
    if level == SESSION_POWER_CLEANUP {
        return Ok(session_power_cleanup(input, output));
    }
    if !matches!(level, SYSTEM_POWER_CAPABILITIES | SYSTEM_BATTERY_STATE | SYSTEM_VIDEO_STATE | SESSION_DISPLAY_STATE | POWER_SETTING_NOTIFICATION_NAME | GET_POWER_SETTING_VALUE | PLATFORM_INFORMATION | PLATFORM_ROLE | SESSION_RIT_STATE | SESSION_CONNECT_NOTIFICATION | POWER_INFORMATION_INTERNAL) {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let input_length = if input == 0 { 0 } else { input_length };
    let input = if input_length == 0 { 0 } else { input };
    let output_length = if output == 0 { 0 } else { output_length };
    let output = if output_length == 0 { 0 } else { output };
    let captured = if input != 0 { guest::read_bytes(input, input_length.min(MAXIMUM_CAPTURE) as usize) } else { Vec::new() };
    let data = match level_answer(level, &captured, output_length, false)? {
        Answer::Data(data) => data,
        Answer::Status(status) => return Ok(status),
    };
    if output == 0 {
        return Ok(0);
    }
    if (output_length as usize) < data.len() {
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    guest::write_bytes(output, &data);
    Ok(0)
}

// NtPowerInformation de modo usuário (ntoskrnl 19041, rva 0x6f04e0).
//
// - Um nível acima de 0x5F dá STATUS_INVALID_PARAMETER.
// - Um ponteiro NULL zera o comprimento dele, e um comprimento zero anula o
//   ponteiro.
// - Os níveis só de kernel dão STATUS_ACCESS_DENIED a um chamador de modo
//   usuário (as máscaras 0x30200C0 e 0x209E02E385CA1E1F do 19041).
// - Sem entrada, a saída é sondada para escrita com alinhamento 1. Com
//   entrada, os níveis fora da lista sem privilégio pedem o
//   SeShutdownPrivilege (o SeCreatePagefilePrivilege no nível 10); depois a
//   entrada é sondada e capturada e a saída sondada.
// - O nível monta o resultado num buffer do kernel; o fim comum copia esse
//   resultado para a saída (STATUS_BUFFER_TOO_SMALL se ela for menor). Sem
//   saída, o resultado é descartado com sucesso.

const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const MAXIMUM_LEVEL: u32 = 0x5F;
/// Os níveis que o NtPowerInformation recusa ao modo usuário.
const KERNEL_ONLY_LEVELS: [u32; 33] = [6, 7, 17, 24, 25, 30, 31, 32, 33, 34, 39, 40, 41, 42, 47, 49, 52, 53, 54, 56, 61, 62, 63, 67, 68, 69, 71, 79, 80, 81, 82, 85, 91];
/// Os níveis que aceitam entrada de modo usuário sem privilégio.
const NO_PRIVILEGE_LEVELS: [u32; 28] = [2, 3, 11, 37, 38, 43, 44, 45, 46, 48, 55, 57, 58, 59, 60, 64, 66, 72, 73, 75, 86, 87, 88, 90, 92, 93, 94, 95];
/// Com entrada, o SystemReserveHiberFile (10) pede o
/// SeCreatePagefilePrivilege; os outros níveis fora da lista acima, o
/// SeShutdownPrivilege.
const RESERVE_HIBER_FILE: u32 = 10;
const SE_CREATE_PAGEFILE_PRIVILEGE: u64 = 15;
const SE_SHUTDOWN_PRIVILEGE: u64 = 19;
/// POWER_INFORMATION_LEVEL PlatformRole e PowerInformationInternal.
const PLATFORM_ROLE: u32 = 75;
const POWER_INFORMATION_INTERNAL: u32 = 87;
/// POWER_INFORMATION_LEVEL_INTERNAL PowerInternalUserAbsencePredictionCapability.
const USER_ABSENCE_PREDICTION_CAPABILITY: u32 = 4;
/// POWER_INFORMATION_LEVEL_INTERNAL PowerInternalSessionPowerState,
/// PowerInternalSetWatchdog e PowerInternalInputControllerState.
const SESSION_POWER_STATE: u32 = 0x13;
const SET_WATCHDOG: u32 = 0x15;
const INPUT_CONTROLLER_STATE: u32 = 0x1C;
/// Os tipos internos que o PopPowerInformationInternal (0x6f1c77..0x6f1ca5)
/// recusa a um chamador de modo usuário com STATUS_ACCESS_DENIED: 0x24,
/// 0x41, a máscara 0x8E00030014B80105 dos tipos até 0x3F e 0x43.
const KERNEL_ONLY_INTERNAL_TYPES: [u32; 18] = [0, 2, 8, 19, 20, 21, 23, 26, 28, 36, 40, 41, 57, 58, 59, 63, 65, 67];
/// O comprimento da entrada do PowerInternalInputControllerState
/// ({POWER_INFORMATION_INTERNAL_HEADER, ULONG State}).
const INPUT_CONTROLLER_STATE_INPUT: usize = 0xC;
/// POWER_PLATFORM_ROLE PlatformRoleDesktop.
const PLATFORM_ROLE_DESKTOP: u32 = 1;
/// O maior pedaço de entrada que o OpenNT captura (os níveis suportados
/// leem no máximo 0x18 bytes).
const MAXIMUM_CAPTURE: u32 = 0x1000;

/// PopPlatformAoAc: FALSE numa plataforma sem Modern Standby.
pub(crate) fn platform_aoac() -> u8 {
    0
}

/// PopCapturePlatformRole: o PopPlatformRole, ou, antes de definido,
/// PlatformRoleMobile com bateria (PopCB.BatteryCount) e PlatformRoleDesktop
/// sem. O OpenNT não tem bateria.
fn platform_role() -> u32 {
    PLATFORM_ROLE_DESKTOP
}

/// Um bloco de kernel zerado de `size` bytes preenchido por `fill`, como
/// bytes.
fn build(size: u64, fill: impl FnOnce(u64)) -> Vec<u8> {
    let block = guest::alloc_bytes(size);
    if block == 0 {
        return Vec::new();
    }
    guest::write_bytes(block, &alloc::vec![0u8; size as usize]);
    fill(block);
    let bytes = guest::read_bytes(block, size as usize);
    guest::free_bytes(block);
    bytes
}

/// SystemPowerCapabilities (0x6f0ca4): o PopFilterCapabilities sobre o
/// PopCapabilities, com o FullWake (PopFullWake & 1) e o DiskSpinDown
/// (PopDisksRegisteredForIdle) atualizados. O PopCapabilities começa zerado
/// e só os eventos de plataforma o preenchem: o OpenNT tem o botão de
/// energia fixo do FADT e o ShutdownOff da HAL (S5), sem handlers de S1 a S4,
/// sem botão de sono, tampa, UPS, zona térmica, hiberfil ou bateria.
fn capabilities() -> Vec<u8> {
    build(SystemPowerCapabilities::SIZE, |block| {
        // SAFETY: o bloco zerado de 0x4c bytes acima.
        let capabilities = unsafe { SystemPowerCapabilities::at(block) };
        capabilities.power_button_present.set(1);
        capabilities.system_s5.set(1);
        capabilities.full_wake.set((crate::ntos::po::system_state::full_wake() & 1) as u8);
        capabilities.ao_ac.set(platform_aoac());
        capabilities.disk_spin_down.set(crate::ntos::po::idle::disks_registered() as u8);
    })
}

/// SystemBatteryState (0x6f0979): o PopCurrentPowerState, a cópia do estado
/// composto que o PopBatteryInit deixa sem bateria (AcOnLine = TRUE, o resto
/// zerado).
fn battery_state() -> Vec<u8> {
    use crate::ntos::inc::types::extra_ps_user::SystemBatteryState;
    build(SystemBatteryState::SIZE, |block| {
        // SAFETY: o bloco zerado de 0x20 bytes acima.
        unsafe { SystemBatteryState::at(block) }.ac_on_line.set(1);
    })
}

/// O GUID de 16 bytes no começo de uma entrada capturada.
fn guid_of(input: &[u8]) -> [u8; 16] {
    let mut value = [0u8; 16];
    value.copy_from_slice(&input[..16]);
    value
}

/// O resultado de um nível: os bytes que o fim comum copia para a saída.
enum Answer {
    Data(Vec<u8>),
    Status(u32),
}

/// O corpo de cada nível sobre a entrada capturada (`input` vazio = NULL), o
/// comprimento da saída (0 = sem saída) e o PreviousMode (`user`).
fn level_answer(level: u32, input: &[u8], output_length: u32, user: bool) -> Result<Answer, KernelError> {
    let has_output = output_length != 0;
    Ok(match level {
        // SystemPowerCapabilities, SystemBatteryState, SystemVideoState,
        // PlatformInformation e PlatformRole: sem entrada, com saída. O
        // SystemVideoState (0x6f0f45) são os 4 bytes do
        // PopConsoleDisplayState.
        SYSTEM_POWER_CAPABILITIES | SYSTEM_BATTERY_STATE | SYSTEM_VIDEO_STATE | PLATFORM_INFORMATION | PLATFORM_ROLE => {
            if !input.is_empty() || !has_output {
                return Ok(Answer::Status(STATUS_INVALID_PARAMETER));
            }
            Answer::Data(match level {
                SYSTEM_POWER_CAPABILITIES => capabilities(),
                SYSTEM_BATTERY_STATE => battery_state(),
                SYSTEM_VIDEO_STATE => display_state::console_display_state().to_le_bytes().to_vec(),
                PLATFORM_INFORMATION => alloc::vec![platform_aoac()],
                _ => platform_role().to_le_bytes().to_vec(),
            })
        }
        // SessionDisplayState (0x6f0fb9; o modo usuário é recusado antes):
        // entrada de exatamente 0x10 bytes e nenhuma saída.
        SESSION_DISPLAY_STATE => {
            if input.len() != display_state::SESSION_DISPLAY_STATE_INPUT || has_output {
                return Ok(Answer::Status(STATUS_INVALID_PARAMETER));
            }
            display_state::session_display_state(input)?;
            Answer::Data(Vec::new())
        }
        // SessionRITState (0x6f0ee4) e SessionConnectNotification (0x6f1108),
        // só de modo kernel: entrada de exatamente 8 e 2 bytes e saída de
        // exatamente 8 ({InputTimeout, DisplayTimeout} em segundos), da
        // sessão de quem chama (PsGetProcessSessionIdEx).
        SESSION_RIT_STATE | SESSION_CONNECT_NOTIFICATION => {
            let expected = if level == SESSION_RIT_STATE { user_presence::SESSION_RIT_STATE_INPUT } else { user_presence::SESSION_CONNECT_INPUT };
            if input.len() != expected || output_length != 8 {
                return Ok(Answer::Status(STATUS_INVALID_PARAMETER));
            }
            let session = crate::ntos::mm::session::session_id_ex(crate::ntos::ps::process::get_current_process());
            Answer::Data(if level == SESSION_RIT_STATE { user_presence::session_input_change(session, input) } else { user_presence::session_connection_change(session, input) })
        }
        // PowerSettingNotificationName (0x6f0bed): com saída de exatamente 8
        // bytes (o WNF_STATE_NAME) e entrada, se houver, de exatamente 0x14
        // ({GUID, ULONG Session}).
        POWER_SETTING_NOTIFICATION_NAME => {
            if !has_output {
                return Ok(Answer::Status(STATUS_INVALID_PARAMETER));
            }
            if (!input.is_empty() && input.len() != 0x14) || output_length != 8 {
                return Ok(Answer::Status(STATUS_BUFFER_TOO_SMALL));
            }
            let request = (!input.is_empty()).then(|| (guid_of(input), u32::from_le_bytes([input[16], input[17], input[18], input[19]])));
            match power_setting::notification_name(request)? {
                Ok(name) => Answer::Data(name.to_le_bytes().to_vec()),
                Err(status) => Answer::Status(status),
            }
        }
        // GetPowerSettingValue (0x6f0d0b): entrada e saída obrigatórias; a
        // entrada é exatamente um GUID e a saída tem pelo menos 4 bytes.
        GET_POWER_SETTING_VALUE => {
            if input.is_empty() || !has_output {
                return Ok(Answer::Status(STATUS_INVALID_PARAMETER));
            }
            if input.len() != 0x10 || output_length < 4 {
                return Ok(Answer::Status(STATUS_BUFFER_TOO_SMALL));
            }
            match power_setting::setting_value(&guid_of(input), output_length) {
                Ok(data) => Answer::Data(data),
                Err(status) => Answer::Status(status),
            }
        }
        // PowerInformationInternal: o POWER_INFORMATION_INTERNAL_HEADER
        // {InternalType, Version} de pelo menos 8 bytes; os tipos 0x44 a
        // 0xFFF e de 0x100B em diante são inválidos.
        POWER_INFORMATION_INTERNAL => {
            if input.len() < 8 {
                return Ok(Answer::Status(STATUS_INVALID_PARAMETER));
            }
            let internal = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
            if (0x44..=0xFFF).contains(&internal) || internal as i32 >= 0x100B {
                return Ok(Answer::Status(STATUS_INVALID_PARAMETER));
            }
            if user && KERNEL_ONLY_INTERNAL_TYPES.contains(&internal) {
                return Ok(Answer::Status(STATUS_ACCESS_DENIED));
            }
            match internal {
                // PopPowerInformationInternal: sem saída é
                // STATUS_BUFFER_TOO_SMALL; senão um BOOLEAN, FALSE fora de uma
                // plataforma AoAc.
                USER_ABSENCE_PREDICTION_CAPABILITY => {
                    if !has_output {
                        return Ok(Answer::Status(STATUS_BUFFER_TOO_SMALL));
                    }
                    Answer::Data(alloc::vec![platform_aoac()])
                }
                // SessionPowerState (0x81ce97): entrada de exatamente 0x14
                // bytes e nenhuma saída (`po/display_state.rs`).
                SESSION_POWER_STATE => {
                    if input.len() != display_state::SESSION_POWER_STATE_INPUT || has_output {
                        return Ok(Answer::Status(STATUS_INVALID_PARAMETER));
                    }
                    display_state::session_power_state(input)?;
                    Answer::Data(Vec::new())
                }
                // SetWatchdog (0x6f1c02): o watchdog de energia
                // (`po/watchdog.rs`), sobre uma cópia de kernel da entrada.
                SET_WATCHDOG => {
                    if input.len() < watchdog::SET_WATCHDOG_INPUT {
                        return Ok(Answer::Status(STATUS_BUFFER_TOO_SMALL));
                    }
                    let block = guest::alloc_bytes(input.len() as u64);
                    if block == 0 {
                        return Ok(Answer::Status(STATUS_INSUFFICIENT_RESOURCES));
                    }
                    guest::write_bytes(block, input);
                    let result = watchdog::set_watchdog_request(block, input.len(), has_output);
                    guest::free_bytes(block);
                    match result {
                        Ok(data) => Answer::Data(data),
                        Err(status) => Answer::Status(status),
                    }
                }
                // InputControllerState (0x81d055): entrada de exatamente 0xC
                // bytes; o ULONG de +8 vai a
                // GUID_ADAPTIVE_INPUT_CONTROLLER_STATE
                // (PopSetPowerSettingValueAcDc). A saída não é olhada.
                INPUT_CONTROLLER_STATE => {
                    if input.len() != INPUT_CONTROLLER_STATE_INPUT {
                        return Ok(Answer::Status(STATUS_INVALID_PARAMETER));
                    }
                    power_setting::set_value_ac_dc(&power_setting::GUID_ADAPTIVE_INPUT_CONTROLLER_STATE, &input[8..12]);
                    Answer::Data(Vec::new())
                }
                // BootStatGet e BootStatSet: o boot status data
                // (`po/boot_status.rs`).
                boot_status::BOOT_STAT_GET | boot_status::BOOT_STAT_SET => match boot_status::request(internal, input, has_output)? {
                    Ok(data) => Answer::Data(data),
                    Err(status) => Answer::Status(status),
                },
                // TransitionCheckpoint (`po/transition_checkpoint.rs`).
                crate::ntos::po::transition_checkpoint::TRANSITION_CHECKPOINT => Answer::Status(crate::ntos::po::transition_checkpoint::request(input, has_output)),
                _ => {
                    crate::debug_print!("[po] NtPowerInformation de modo usuario: PowerInformationInternal tipo {:#x} sem suporte", internal);
                    Answer::Status(STATUS_NOT_IMPLEMENTED)
                }
            }
        }
        // LastWakeTime e LastSleepTime (0x6f13cc e 0x6f145a): sem entrada,
        // com saída; os 8 bytes de PopAction.WakeTime/SleepTime, que só uma
        // transição de sono grava.
        LAST_WAKE_TIME | LAST_SLEEP_TIME => {
            if !input.is_empty() || !has_output {
                return Ok(Answer::Status(STATUS_INVALID_PARAMETER));
            }
            Answer::Data(0u64.to_le_bytes().to_vec())
        }
        // SystemExecutionState (0x6f0ba0): sem entrada, com saída; o ULONG
        // dos pedidos de sistema e de tela ligados.
        SYSTEM_EXECUTION_STATE => {
            if !input.is_empty() || !has_output {
                return Ok(Answer::Status(STATUS_INVALID_PARAMETER));
            }
            Answer::Data(power_request::system_execution_state().to_le_bytes().to_vec())
        }
        // SystemMonitorHiberBootPowerOff (0x6f1838): sem conferir entrada nem
        // saída; o status do PoPowerOffMonitor volta direto.
        SYSTEM_MONITOR_HIBER_BOOT_POWER_OFF => {
            HIBER_BOOT_FORCE_MONITOR_OFF.store(1, core::sync::atomic::Ordering::SeqCst);
            Answer::Status(super::win32_callout::power_off_monitor())
        }
        // PowerRequestCreate e PlmPowerRequestCreate (0x6f0d47): entrada de
        // exatamente 0x28 bytes e saída de exatamente 8 (senão
        // STATUS_BUFFER_TOO_SMALL); o handle do pedido.
        POWER_REQUEST_CREATE | PLM_POWER_REQUEST_CREATE => {
            if input.is_empty() || !has_output {
                return Ok(Answer::Status(STATUS_INVALID_PARAMETER));
            }
            if input.len() != super::reason_context::CONTEXT_SIZE || output_length != 8 {
                return Ok(Answer::Status(STATUS_BUFFER_TOO_SMALL));
            }
            match power_request::create_info(input, level == PLM_POWER_REQUEST_CREATE) {
                Ok(handle) => Answer::Data(handle.to_le_bytes().to_vec()),
                Err(status) => Answer::Status(status),
            }
        }
        // PowerRequestAction (0x6f0c6d): entrada de exatamente 0x18 bytes
        // (senão STATUS_BUFFER_TOO_SMALL) e nenhuma saída.
        POWER_REQUEST_ACTION => {
            if input.is_empty() || has_output {
                return Ok(Answer::Status(STATUS_INVALID_PARAMETER));
            }
            if input.len() != 0x18 {
                return Ok(Answer::Status(STATUS_BUFFER_TOO_SMALL));
            }
            Answer::Status(power_request::action_info(input)?)
        }
        // SessionLockState (0x6f14fc): entrada de exatamente 8 bytes e
        // nenhuma saída; o status do PopSessionWinlogonNotification é
        // descartado.
        SESSION_LOCK_STATE => {
            if input.len() != 8 || has_output {
                return Ok(Answer::Status(STATUS_INVALID_PARAMETER));
            }
            Answer::Data(Vec::new())
        }
        // SystemHiberbootState (0x6f15f6): sem entrada, com saída; o
        // BOOLEAN Hiberboot das capacidades filtradas (com ele, a política
        // do registro).
        SYSTEM_HIBERBOOT_STATE => {
            if !input.is_empty() || !has_output {
                return Ok(Answer::Status(STATUS_INVALID_PARAMETER));
            }
            Answer::Data(alloc::vec![capabilities().get(HIBERBOOT_OFFSET).copied().unwrap_or(0)])
        }
        // UpdateBlackBoxRecorder de modo usuário (0x6f0b5c): entrada de
        // exatamente 0x20 bytes (senão STATUS_BUFFER_TOO_SMALL) e nenhuma
        // saída.
        UPDATE_BLACK_BOX_RECORDER => {
            if input.is_empty() || has_output {
                return Ok(Answer::Status(STATUS_INVALID_PARAMETER));
            }
            Answer::Status(black_box::update_from_user(input)?)
        }
        // SessionAllowExternalDmaDevices (0x6f10d6): entrada de exatamente 1
        // byte e nenhuma saída; o ExNotifyCallback do PipCslCallbackObject.
        SESSION_ALLOW_EXTERNAL_DMA_DEVICES => {
            if input.len() != 1 || has_output {
                return Ok(Answer::Status(STATUS_INVALID_PARAMETER));
            }
            Answer::Data(Vec::new())
        }
        _ => {
            crate::debug_print!("[po] NtPowerInformation de modo usuario: nivel {} sem suporte", level);
            Answer::Status(STATUS_NOT_IMPLEMENTED)
        }
    })
}

/// NtPowerInformation(InformationLevel, InputBuffer, InputBufferLength,
/// OutputBuffer, OutputBufferLength) com PreviousMode UserMode.
pub fn query_user(level: u32, input: u64, input_length: u32, output: u64, output_length: u32) -> Result<u32, KernelError> {
    use crate::ntos::ps::user_probe;
    if level > MAXIMUM_LEVEL {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let input_length = if input == 0 { 0 } else { input_length };
    let input = if input_length == 0 { 0 } else { input };
    let output_length = if output == 0 { 0 } else { output_length };
    let output = if output_length == 0 { 0 } else { output };
    if KERNEL_ONLY_LEVELS.contains(&level) {
        return Ok(STATUS_ACCESS_DENIED);
    }
    if ADMIN_LEVELS.contains(&level) && !crate::ntos::ps::security::is_context_admin() {
        return Ok(STATUS_ACCESS_DENIED);
    }
    let captured = if input != 0 {
        if !NO_PRIVILEGE_LEVELS.contains(&level) {
            let privilege = if level == RESERVE_HIBER_FILE { SE_CREATE_PAGEFILE_PRIVILEGE } else { SE_SHUTDOWN_PRIVILEGE };
            if !crate::ntos::se::privilege::single_privilege_check(privilege, 1) {
                return Ok(STATUS_PRIVILEGE_NOT_HELD);
            }
        }
        if !user_probe::probe_user_read(input, input_length as u64) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        match guest::try_read_bytes(input, input_length.min(MAXIMUM_CAPTURE) as usize) {
            Ok(bytes) => bytes,
            Err(error) => return Ok(error.status),
        }
    } else {
        Vec::new()
    };
    if output != 0 && !user_probe::probe_user_write(output, output_length as u64) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let data = match level_answer(level, &captured, output_length, true)? {
        Answer::Data(data) => data,
        Answer::Status(status) => return Ok(status),
    };
    if output == 0 {
        return Ok(0);
    }
    if (output_length as usize) < data.len() {
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    match guest::try_write_bytes(output, &data) {
        Ok(()) => Ok(0),
        Err(error) => Ok(error.status),
    }
}

fn nt_power_information(level: u64, input: u64, input_length: u64, output: u64, rsp: u64) -> Result<u32, KernelError> {
    query_user(level as u32, input, input_length as u32, output, crate::ntos::ps::user::state::stack_arg32(rsp, 5))
}

/// NtSetThreadExecutionState(EsFlags, PreviousFlags*): o pedido legado da
/// thread (`po/power_request.rs`).
fn nt_set_thread_execution_state(flags: u64, previous_flags: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    power_request::set_thread_execution_state(flags as u32, previous_flags)
}

/// Os handlers dos serviços NtPowerInformation e NtSetThreadExecutionState
/// de modo usuário.
pub fn register_user_services() {
    crate::ntos::ps::user::state::register_handler("NtPowerInformation", nt_power_information);
    crate::ntos::ps::user::state::register_handler("NtSetThreadExecutionState", nt_set_thread_execution_state);
}

/// PoEnergyEstimationEnabled: o estimador de energia (E3) do Po não existe
/// no OpenNT, então FALSE, o valor do export e o BOOLEAN da
/// SystemEnergyEstimationConfigInformation (158).
pub fn energy_estimation_enabled() -> bool {
    false
}

/// PoSetProcessEnergyTrackingState (ntoskrnl 19041, rva 0x69b020) sobre o
/// PROCESS_ENERGY_TRACKING_STATE capturado: sem o contexto de energia do
/// processo (EPROCESS.EnergyContext) é STATUS_NOT_SUPPORTED antes de olhar o
/// estado. Só o estimador de energia cria esse contexto, e o OpenNT não tem
/// o estimador: todo processo fica sem ele.
pub fn set_process_energy_tracking_state(_process: u64, _state: &[u8]) -> u32 {
    0xC000_00BB
}
