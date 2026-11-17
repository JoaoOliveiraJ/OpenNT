//! Informações de energia em modo kernel (ZwPowerInformation).
//!
//! O nível 94 vai ao gravador black box do kernel; o nível 4 descreve um
//! desktop (SYSTEM_POWER_CAPABILITIES sem bateria, AC ligado); o 66
//! (PlatformInformation) devolve o POWER_PLATFORM_INFORMATION; o 41
//! (SessionPowerInit) e o 63 (SessionPowerCleanup) são o início e o fim da
//! energia de uma sessão, que o win32k pede no DriverEntry e na limpeza, e o
//! 29 (SystemVideoState) devolve o estado da tela do console. Os demais
//! níveis devolvem STATUS_INVALID_PARAMETER.

use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use crate::ntos::inc::types::{NtStruct, SystemPowerCapabilities};
use crate::ntos::po::black_box;
use crate::rtl::KernelError;

const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// POWER_INFORMATION_LEVEL PlatformInformation.
const PLATFORM_INFORMATION: u32 = 66;

/// PlatformInformation: sem entrada e com saída, POWER_PLATFORM_INFORMATION
/// { BOOLEAN AoAc } com o PopPlatformAoAc, FALSE numa plataforma sem
/// Modern Standby (o padrão do 19041 e o desta máquina).
fn platform_information(input: u64, output: u64, output_length: u32) -> u32 {
    if input != 0 || output_length == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: o BOOLEAN de saída do chamador (Zw, KernelMode).
    unsafe { crate::ntos::inc::field::Field::<u8>::at(output) }.set(0);
    0
}

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
/// TtmInitCurrentSession). O OpenNT não aplica esquemas de energia (não há
/// `Control\Power\User\PowerSchemes` nem o serviço de modo usuário que os
/// publica), então os valores de configuração ficam no zero de antes de
/// qualquer esquema, como o PopPowerSettingValues (.data sem inicializador)
/// no boot, e o economizador fica desligado.
fn session_power_init(input: u64, output: u64, output_length: u32) -> u32 {
    use crate::ntos::inc::types::extra_ps_user::PowerSessionInit;
    if input != 0 || output == 0 || output_length as u64 != PowerSessionInit::SIZE {
        return STATUS_INVALID_PARAMETER;
    }
    crate::ntos::mm::guest_memory::write_bytes(output, &[0u8; 0x40]);
    // SAFETY: a saída do chamador (Zw, KernelMode) com os 0x40 bytes conferidos.
    let information = unsafe { PowerSessionInit::at(output) };
    information.no_more_input.set(NO_MORE_INPUT.as_ptr() as u64);
    information.hiber_boot_force_monitor_off.set(HIBER_BOOT_FORCE_MONITOR_OFF.as_ptr() as u64);
    information.lid_opened.set(LID_OPENED);
    information.ttm_enabled.set(crate::ntos::ttm::device::enabled() as u8);
    0
}

/// POWER_INFORMATION_LEVEL SystemVideoState.
const SYSTEM_VIDEO_STATE: u32 = 29;

/// PopConsoleDisplayState (MONITOR_DISPLAY_STATE): só o
/// PopUpdateConsoleDisplayState o grava, quando a sessão informa o estado da
/// tela (SessionDisplayState); até lá fica no zero do boot
/// (PowerMonitorOff), o .data sem inicializador do ntoskrnl.
static CONSOLE_DISPLAY_STATE: AtomicU32 = AtomicU32::new(0);

/// SystemVideoState (0x6f0f45): sem entrada, uma saída de pelo menos 4
/// bytes (senão STATUS_BUFFER_TOO_SMALL) com o PopConsoleDisplayState.
fn system_video_state(input: u64, output: u64, output_length: u32) -> u32 {
    if input != 0 || output == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if output_length < 4 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    // SAFETY: a saída do chamador (Zw, KernelMode) com os 4 bytes conferidos.
    unsafe { crate::ntos::inc::field::Field::<u32>::at(output) }.set(CONSOLE_DISPLAY_STATE.load(Ordering::Acquire));
    0
}

/// SessionPowerCleanup (0x6f17c4): sem entrada nem saída; o
/// PopFreeSessionState da sessão corrente. O OpenNT não guarda estado de
/// energia por sessão.
fn session_power_cleanup(input: u64, output: u64) -> u32 {
    if input != 0 || output != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    0
}

/// ZwPowerInformation: 94 = black box do kernel; 4 = SystemPowerCapabilities
/// de desktop (sem bateria, AC ligado). Devolve o NTSTATUS.
pub fn query(level: u32, input: u64, input_length: u32, output: u64, output_length: u32) -> Result<u32, KernelError> {
    if level == 94 {
        return black_box::update_from_kernel(input, input_length, output, output_length);
    }
    if level == PLATFORM_INFORMATION {
        return Ok(platform_information(input, output, output_length));
    }
    if level == SESSION_POWER_INIT {
        return Ok(session_power_init(input, output, output_length));
    }
    if level == SESSION_POWER_CLEANUP {
        return Ok(session_power_cleanup(input, output));
    }
    if level == SYSTEM_VIDEO_STATE {
        return Ok(system_video_state(input, output, output_length));
    }
    if level != 4 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if output_length < 0x40 {
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    // SAFETY: buffer SYSTEM_POWER_CAPABILITIES do chamador (Zw, KernelMode).
    let capabilities = unsafe { SystemPowerCapabilities::at(output) };
    capabilities.power_button_present.set(1);
    capabilities.sleep_button_present.set(1);
    capabilities.lid_present.set(0);
    capabilities.system_s1.set(1);
    capabilities.system_s5.set(1);
    capabilities.ups_present.set(1);
    Ok(0)
}

// NtPowerInformation de modo usuário (ntoskrnl 19041, rva 0x6f04e0).
//
// - Um nível acima de 0x5F dá STATUS_INVALID_PARAMETER.
// - Um ponteiro NULL zera o comprimento dele, e um comprimento zero anula o
//   ponteiro.
// - Os níveis só de kernel dão STATUS_ACCESS_DENIED a um chamador de modo
//   usuário (as máscaras 0x30200C0 e 0x209E02E385CA1E1F do 19041).
// - A saída é sondada para escrita com alinhamento 1 e a entrada é capturada.
// - O nível monta o resultado num buffer do kernel; o fim comum copia esse
//   resultado para a saída (STATUS_BUFFER_TOO_SMALL se ela for menor). Sem
//   saída, o resultado é descartado com sucesso.

const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const MAXIMUM_LEVEL: u32 = 0x5F;
/// Os níveis que o NtPowerInformation recusa ao modo usuário.
const KERNEL_ONLY_LEVELS: [u32; 33] = [6, 7, 17, 24, 25, 30, 31, 32, 33, 34, 39, 40, 41, 42, 47, 49, 52, 53, 54, 56, 61, 62, 63, 67, 68, 69, 71, 79, 80, 81, 82, 85, 91];
/// POWER_INFORMATION_LEVEL PlatformRole e PowerInformationInternal.
const PLATFORM_ROLE: u32 = 75;
const POWER_INFORMATION_INTERNAL: u32 = 87;
/// POWER_INFORMATION_LEVEL_INTERNAL PowerInternalUserAbsencePredictionCapability.
const USER_ABSENCE_PREDICTION_CAPABILITY: u32 = 4;
/// POWER_PLATFORM_ROLE PlatformRoleDesktop.
const PLATFORM_ROLE_DESKTOP: u32 = 1;
/// O maior pedaço de entrada que o OpenNT captura (o maior nível suportado
/// lê 8 bytes).
const MAXIMUM_CAPTURE: u32 = 0x1000;

/// PopPlatformAoAc: FALSE numa plataforma sem Modern Standby.
fn platform_aoac() -> u8 {
    0
}

/// PopCapturePlatformRole: o PopPlatformRole, ou, antes de definido,
/// PlatformRoleMobile com bateria (PopCB.BatteryCount) e PlatformRoleDesktop
/// sem. O OpenNT não tem bateria.
fn platform_role() -> u32 {
    PLATFORM_ROLE_DESKTOP
}

/// O resultado de um nível: os bytes que o fim comum copia para a saída.
enum Answer {
    Data(alloc::vec::Vec<u8>),
    Status(u32),
}

/// O corpo de cada nível sobre a entrada capturada (`input` vazio = NULL) e
/// a presença da saída.
fn user_level(level: u32, input: &[u8], has_output: bool) -> Answer {
    match level {
        // PlatformInformation e PlatformRole: sem entrada, com saída.
        PLATFORM_INFORMATION | PLATFORM_ROLE => {
            if !input.is_empty() || !has_output {
                return Answer::Status(STATUS_INVALID_PARAMETER);
            }
            if level == PLATFORM_INFORMATION {
                Answer::Data(alloc::vec![platform_aoac()])
            } else {
                Answer::Data(platform_role().to_le_bytes().to_vec())
            }
        }
        // PowerInformationInternal: o POWER_INFORMATION_INTERNAL_HEADER
        // {InternalType, Version} de pelo menos 8 bytes; os tipos 0x44 a
        // 0xFFF e de 0x100B em diante são inválidos.
        POWER_INFORMATION_INTERNAL => {
            if input.len() < 8 {
                return Answer::Status(STATUS_INVALID_PARAMETER);
            }
            let internal = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
            if (0x44..=0xFFF).contains(&internal) || internal as i32 >= 0x100B {
                return Answer::Status(STATUS_INVALID_PARAMETER);
            }
            match internal {
                // PopPowerInformationInternal: sem saída é
                // STATUS_BUFFER_TOO_SMALL; senão um BOOLEAN, FALSE fora de uma
                // plataforma AoAc.
                USER_ABSENCE_PREDICTION_CAPABILITY => {
                    if !has_output {
                        return Answer::Status(STATUS_BUFFER_TOO_SMALL);
                    }
                    Answer::Data(alloc::vec![platform_aoac()])
                }
                _ => {
                    crate::debug_print!("[po] NtPowerInformation de modo usuario: PowerInformationInternal tipo {:#x} sem suporte", internal);
                    Answer::Status(STATUS_NOT_IMPLEMENTED)
                }
            }
        }
        _ => {
            crate::debug_print!("[po] NtPowerInformation de modo usuario: nivel {} sem suporte", level);
            Answer::Status(STATUS_NOT_IMPLEMENTED)
        }
    }
}

/// NtPowerInformation(InformationLevel, InputBuffer, InputBufferLength,
/// OutputBuffer, OutputBufferLength) com PreviousMode UserMode.
pub fn query_user(level: u32, input: u64, input_length: u32, output: u64, output_length: u32) -> u32 {
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::ps::user_probe;
    if level > MAXIMUM_LEVEL {
        return STATUS_INVALID_PARAMETER;
    }
    let input_length = if input == 0 { 0 } else { input_length };
    let input = if input_length == 0 { 0 } else { input };
    let output_length = if output == 0 { 0 } else { output_length };
    let output = if output_length == 0 { 0 } else { output };
    if KERNEL_ONLY_LEVELS.contains(&level) {
        return STATUS_ACCESS_DENIED;
    }
    if output != 0 && !user_probe::probe_user_write(output, output_length as u64) {
        return STATUS_ACCESS_VIOLATION;
    }
    let captured = if input != 0 {
        if !user_probe::probe_user_read(input, input_length as u64) {
            return STATUS_ACCESS_VIOLATION;
        }
        match guest::try_read_bytes(input, input_length.min(MAXIMUM_CAPTURE) as usize) {
            Ok(bytes) => bytes,
            Err(error) => return error.status,
        }
    } else {
        alloc::vec::Vec::new()
    };
    let data = match user_level(level, &captured, output != 0) {
        Answer::Data(data) => data,
        Answer::Status(status) => return status,
    };
    if output == 0 {
        return 0;
    }
    if (output_length as usize) < data.len() {
        return STATUS_BUFFER_TOO_SMALL;
    }
    match guest::try_write_bytes(output, &data) {
        Ok(()) => 0,
        Err(error) => error.status,
    }
}

fn nt_power_information(level: u64, input: u64, input_length: u64, output: u64, rsp: u64) -> Result<u32, KernelError> {
    Ok(query_user(level as u32, input, input_length as u32, output, crate::ntos::ps::user::state::stack_arg32(rsp, 5)))
}

/// O handler do serviço NtPowerInformation de modo usuário.
pub fn register_user_services() {
    crate::ntos::ps::user::state::register_handler("NtPowerInformation", nt_power_information);
}
