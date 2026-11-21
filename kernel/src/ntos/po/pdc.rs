//! O Power Dependency Coordinator (o pdc.sys real, driver de boot da
//! instalação) visto pelo Po (ntoskrnl 19041): o registro do PDC pelo
//! ZwPowerInformation nível 67 e as 20 rotinas PdcPo* que o kernel devolve a
//! ele.
//!
//! - NtPowerInformation 67 (só de modo kernel, 0x6f1069): entrada não nula
//!   de exatamente 0xB8 bytes e saída nula ou de exatamente 0xA0 bytes,
//!   senão STATUS_INVALID_PARAMETER. O PopPdcInvocation (0x773604) lê o
//!   ULONG inicial: 0 é o PopPdcRegister; 1 chama o PoPdcCallbacks+0x20 (o
//!   PdcRegisterKernelClient do pdc.sys) com {entrada+0x10, entrada+8}, ou
//!   STATUS_NOT_IMPLEMENTED antes do registro; outro valor é
//!   STATUS_INVALID_PARAMETER. O próprio pdc.sys registra os clientes de
//!   tarefa e de porta dele pelo tipo 1.
//! - PopPdcRegister(Entrada, Saída) (0x7d1130): sem saída,
//!   STATUS_INVALID_PARAMETER. Sob a trava da política zera o
//!   PopModernStandbyTransitionInfo (o OpenNT não tem a transição de Modern
//!   Standby), copia os 0xB0 bytes depois do tipo (22 ponteiros do pdc.sys)
//!   para o PoPdcCallbacks e grava na saída as 20 rotinas abaixo, na ordem
//!   da tabela do 19041.
//!
//! As rotinas (o PDC as chama pelos ponteiros da saída; aqui cada uma é um
//! stub de `hal/amd64/routine_stubs.rs`):
//!
//! - 0 PdcPoResiliencyClient(Tipo, Engajado, Arg): o tipo 1 é o
//!   PopPdcIdleResiliencyCallback (Arg, Engajado): o PopPdcIdleResiliency e
//!   GUID_PDC_IDLE_RESILIENCY_ENGAGED (AC e DC); os tipos 2 e 3 gravam o
//!   PopPdcIoCoalescing quando o PopDeepIoCoalescingEnabled é zero (tipo 2)
//!   ou não (tipo 3); o OpenNT não tem coalescência profunda de E/S, então
//!   só o tipo 2 grava. O PopCheckResiliencyScenarios e a contabilidade do
//!   connected standby (CPU não ativada, fases de IR dos dispositivos, vigia
//!   de DRIPS, alta performance adiada, wake por ociosidade, DRIPS
//!   dirigido) não existem no OpenNT. Devolve 0.
//! - 1 PdcPoLowPower(Epoch): GUID_LOW_POWER_EPOCH = Epoch (AC e DC); 0.
//! - 2 PdcPoSetPowerAction: o PopExecutePowerAction, que o OpenNT não tem
//!   (`po/power_action.rs`): nenhuma transição acontece e a linha `[po]`
//!   registra o pedido.
//! - 3 PdcPoReportButton(Botões, Presente): para cada bit (1 energia, 2
//!   sono, 4 tampa), o byte do PopCapabilities passa a Presente quando muda
//!   e o PopResetCurrentPolicies refaz as políticas; o OpenNT não tem o
//!   motor de políticas de energia, então a linha `[po]` registra a troca.
//! - 4 PdcPoReportLidState(Aberta): sem a errata da tampa, o PopLidOpened
//!   muda; tampa fechada numa plataforma AoAc forçaria a troca de sessão do
//!   agregador (o OpenNT não é AoAc). GUID_LIDSWITCH_STATE_CHANGE = Aberta
//!   (AC e DC).
//! - 5 PdcPoRecordButton(): o PopBsdPowerTransition (o SystemTime da
//!   KUSER_SHARED_DATA) e o PopBsdHandleRequest(1), que grava a transição de
//!   energia no bootstat.dat; o OpenNT guarda o instante e não grava a
//!   transição no arquivo (lacuna).
//! - 6 PdcPoVerifyActionPolicy(Política): o PopVerifyPowerActionPolicy
//!   sobre as capacidades filtradas (`verify_action_policy`).
//! - 7 PdcPoVerifyPowerState(Estado, Pedido): o PopVerifySystemPowerState
//!   (`verify_system_power_state`).
//! - 8 PopBlockSessionSwitch(Bloquear, Sessão*) e 9 PopControlMonitor:
//!   `po/win32_callout.rs`.
//! - 10 PopNotifyCsStateExited: agenda o trabalhador do agregador de energia
//!   e o rastro PDC_PHASES_EXITED; o OpenNT não tem o agregador.
//! - 11 PdcPoCurrentPdcPhase(Fase, Engajado, Arg): grava o
//!   PopBsdCurrentCsPhase; as fases 1, 2, 7 e 8 vão ao vigia da fase ociosa,
//!   ao estado ocioso do connected standby, à contabilidade de consumo e ao
//!   agregador, que o OpenNT não tem; a 6 é o
//!   PopPowerAggregatorNotifyPdcSleepTransition, que com o agregador fora
//!   dos estados 1 e 4 devolve STATUS_INVALID_PARAMETER. As outras, 0.
//! - 12 PdcPoIdleScanEnabled: 0 com o PopIdleScanInterval acima de zero
//!   (0xFFFFFFFF na imagem, sem escritores), senão STATUS_UNSUCCESSFUL.
//! - 13, 14 e 15 PdcPoPpmRegisterProfiles, PdcPoPpmApplyProfile e
//!   PdcPoPpmResetProfile: os perfis de desempenho do PPM
//!   (`po/processor_power.rs`): o registro guarda os perfis como o
//!   PpmRegisterProfiles, a aplicação troca o perfil corrente; a política de
//!   desempenho que os usaria não existe no OpenNT. O PdcPpmInitialize do
//!   pdc.sys registra os perfis de `Power\Profile` e falha o DriverEntry se o
//!   registro falha.
//! - 16 PdcPoNetworkResiliency(Engajado): o PopNetResiliencyEngaged e o
//!   PopNetGracePeriodState; a contabilidade de DS e o temporizador de
//!   avaliação não existem no OpenNT.
//! - 17 PpmQueryDripsResidency: sem PpmPlatformStates (o OpenNT não tem
//!   estados de plataforma), ~0.
//! - 18 PdcPoSleepStudyHelperSetPhaseActive(Fase): as fases 1 a 5 e 9
//!   ativam coleções de bloqueadores do Sleep Study, que o OpenNT não tem.
//! - 19 PdcPoPowerRequestBlockingCallback(Começou): o log de pedidos de
//!   energia e o cronômetro ExecutionRequiredStopWatchCollection, que o
//!   OpenNT não tem.
//!
//! As rotinas que dependem de maquinário ausente não fingem o efeito: cada
//! uma registra uma linha `[po]` na primeira chamada.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

use crate::hal::amd64::native_call;
use crate::hal::amd64::routine_stubs::{self, Routine};
use crate::ntos::init::exports::Call;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::po::{power_information, power_setting, processor_power, win32_callout};
use crate::rtl::{KernelError, SpinLock};

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;

/// A entrada do nível 67: {ULONG Tipo; 22 ponteiros}.
pub const INVOCATION_SIZE: u32 = 0xB8;
/// A saída do registro: as 20 rotinas do kernel.
pub const ROUTINE_TABLE_SIZE: u32 = 0xA0;
/// Os ponteiros do pdc.sys guardados no PoPdcCallbacks.
const CALLBACK_COUNT: usize = 22;
/// PoPdcCallbacks+0x20: o PdcRegisterKernelClient do pdc.sys.
const REGISTER_KERNEL_CLIENT: usize = 4;

/// Os tipos do PopPdcInvocation.
const INVOCATION_REGISTER: u32 = 0;
const INVOCATION_KERNEL_CLIENT: u32 = 1;

/// PoPdcCallbacks.
static CALLBACKS: SpinLock<[u64; CALLBACK_COUNT]> = SpinLock::new([0; CALLBACK_COUNT]);

/// PopBsdCurrentCsPhase.
static CURRENT_CS_PHASE: AtomicU32 = AtomicU32::new(0);
/// PopPdcIdleResiliency e PopPdcIoCoalescing.
static IDLE_RESILIENCY: AtomicU8 = AtomicU8::new(0);
static IO_COALESCING: AtomicU8 = AtomicU8::new(0);
/// PopNetResiliencyEngaged e PopNetGracePeriodState.
static NET_RESILIENCY_ENGAGED: AtomicU8 = AtomicU8::new(0);
static NET_GRACE_PERIOD_STATE: AtomicU32 = AtomicU32::new(0);
/// PopBsdPowerTransition.
static BSD_POWER_TRANSITION: AtomicU64 = AtomicU64::new(0);
/// PopDeepIoCoalescingEnabled: zero (sem coalescência profunda de E/S).
const DEEP_IO_COALESCING_ENABLED: u32 = 0;
/// PopIdleScanInterval: o valor da imagem, sem escritores no 19041.
const IDLE_SCAN_INTERVAL: u32 = 0xFFFF_FFFF;
/// PopPromoteHibernateToShutdown: zero.
const PROMOTE_HIBERNATE_TO_SHUTDOWN: u32 = 0;

/// GUID_LOW_POWER_EPOCH {e1233993-eaa4-470f-9de7-a351c1b6fb71}.
const GUID_LOW_POWER_EPOCH: [u8; 16] = [0x93, 0x39, 0x23, 0xE1, 0xA4, 0xEA, 0x0F, 0x47, 0x9D, 0xE7, 0xA3, 0x51, 0xC1, 0xB6, 0xFB, 0x71];
/// GUID_LIDSWITCH_STATE_CHANGE {ba3e0f4d-b817-4094-a2d1-d56379e6a0f3}.
const GUID_LIDSWITCH_STATE_CHANGE: [u8; 16] = [0x4D, 0x0F, 0x3E, 0xBA, 0x17, 0xB8, 0x94, 0x40, 0xA2, 0xD1, 0xD5, 0x63, 0x79, 0xE6, 0xA0, 0xF3];
/// GUID_PDC_IDLE_RESILIENCY_ENGAGED {307bcc77-e09b-43ce-8d97-46756ffb04a7}.
const GUID_PDC_IDLE_RESILIENCY_ENGAGED: [u8; 16] = [0x77, 0xCC, 0x7B, 0x30, 0x9B, 0xE0, 0xCE, 0x43, 0x8D, 0x97, 0x46, 0x75, 0x6F, 0xFB, 0x04, 0xA7];

/// As rotinas devolvidas ao PDC, na ordem da tabela do PopPdcRegister.
pub const ROUTINES: &[Routine] = &[
    Routine { name: "PdcPoResiliencyClient", handler: resiliency_client },
    Routine { name: "PdcPoLowPower", handler: low_power },
    Routine { name: "PdcPoSetPowerAction", handler: set_power_action },
    Routine { name: "PdcPoReportButton", handler: report_button },
    Routine { name: "PdcPoReportLidState", handler: report_lid_state },
    Routine { name: "PdcPoRecordButton", handler: record_button },
    Routine { name: "PdcPoVerifyActionPolicy", handler: verify_action_policy_routine },
    Routine { name: "PdcPoVerifyPowerState", handler: verify_power_state_routine },
    Routine { name: "PopBlockSessionSwitch", handler: block_session_switch },
    Routine { name: "PopControlMonitor", handler: control_monitor },
    Routine { name: "PopNotifyCsStateExited", handler: notify_cs_state_exited },
    Routine { name: "PdcPoCurrentPdcPhase", handler: current_pdc_phase },
    Routine { name: "PdcPoIdleScanEnabled", handler: idle_scan_enabled },
    Routine { name: "PdcPoPpmRegisterProfiles", handler: ppm_register_profiles },
    Routine { name: "PdcPoPpmApplyProfile", handler: ppm_apply_profile },
    Routine { name: "PdcPoPpmResetProfile", handler: ppm_reset_profile },
    Routine { name: "PdcPoNetworkResiliency", handler: network_resiliency },
    Routine { name: "PpmQueryDripsResidency", handler: query_drips_residency },
    Routine { name: "PdcPoSleepStudyHelperSetPhaseActive", handler: sleep_study_set_phase_active },
    Routine { name: "PdcPoPowerRequestBlockingCallback", handler: power_request_blocking },
];

/// Uma linha `[po]` por rotina que pede maquinário ausente, na primeira
/// chamada.
fn note_absent(flag: &AtomicBool, what: &str) {
    if !flag.swap(true, Ordering::Relaxed) {
        crate::debug_print!("[po] PDC: {} (o OpenNT nao tem esse maquinario)", what);
    }
}

/// NtPowerInformation 67 de modo kernel: as validações do NtPowerInformation
/// e o PopPdcInvocation. Os ponteiros nulos e os comprimentos zero já vêm
/// normalizados pelo chamador.
pub fn invocation(input: u64, input_length: u32, output: u64, output_length: u32) -> u32 {
    if input == 0 || input_length != INVOCATION_SIZE || (output != 0 && output_length != ROUTINE_TABLE_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }
    match guest::read32(input) {
        INVOCATION_REGISTER => register(input, output),
        INVOCATION_KERNEL_CLIENT => {
            let client = CALLBACKS.lock()[REGISTER_KERNEL_CLIENT];
            if client == 0 {
                return STATUS_NOT_IMPLEMENTED;
            }
            native_call::call(client, &[guest::read64(input + 0x10), guest::read64(input + 8)]) as u32
        }
        _ => STATUS_INVALID_PARAMETER,
    }
}

/// PopPdcRegister(Entrada, Saída).
fn register(input: u64, output: u64) -> u32 {
    if output == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let mut routines = [0u64; ROUTINES.len()];
    for (slot, routine) in ROUTINES.iter().enumerate() {
        match routine_stubs::address(routine.name) {
            Ok(address) => routines[slot] = address,
            Err(_) => return STATUS_NOT_IMPLEMENTED,
        }
    }
    {
        let mut callbacks = CALLBACKS.lock();
        for (index, callback) in callbacks.iter_mut().enumerate() {
            *callback = guest::read64(input + 8 + index as u64 * 8);
        }
    }
    for (slot, address) in routines.iter().enumerate() {
        guest::write64(output + slot as u64 * 8, *address);
    }
    crate::debug_print!("[po] PDC registrado: PoPdcCallbacks com {} rotinas do pdc.sys, {} rotinas do kernel devolvidas", CALLBACK_COUNT, ROUTINES.len());
    0
}

/// O ponteiro `index` do PoPdcCallbacks (0 antes do registro).
pub fn callback(index: usize) -> u64 {
    CALLBACKS.lock().get(index).copied().unwrap_or(0)
}

/// O PDC já se registrou.
pub fn registered() -> bool {
    callback(REGISTER_KERNEL_CLIENT) != 0
}

/// Desfaz o registro: o autoteste do nível 67 registra um PDC sintético
/// quando o pdc.sys não está carregado e o apaga no fim.
pub fn clear_registration() {
    *CALLBACKS.lock() = [0; CALLBACK_COUNT];
}

fn resiliency_client(call: &Call) -> Result<u64, KernelError> {
    static ABSENT: AtomicBool = AtomicBool::new(false);
    let engaged = call.arg(2) as u8;
    match call.arg(1) as u32 {
        1 => {
            // PopPdcIdleResiliencyCallback(Arg, Engajado).
            IDLE_RESILIENCY.store(engaged, Ordering::SeqCst);
            power_setting::set_value_ac_dc(&GUID_PDC_IDLE_RESILIENCY_ENGAGED, &(engaged as u32).to_le_bytes());
            note_absent(&ABSENT, "resiliencia ociosa sem cenarios de resiliencia nem contabilidade do connected standby");
        }
        2 if DEEP_IO_COALESCING_ENABLED == 0 => {
            IO_COALESCING.store(engaged, Ordering::SeqCst);
            note_absent(&ABSENT, "coalescencia de E/S sem cenarios de resiliencia");
        }
        3 if DEEP_IO_COALESCING_ENABLED != 0 => IO_COALESCING.store(engaged, Ordering::SeqCst),
        _ => {}
    }
    Ok(0)
}

fn low_power(call: &Call) -> Result<u64, KernelError> {
    power_setting::set_value_ac_dc(&GUID_LOW_POWER_EPOCH, &((call.arg(1) as u8) as u32).to_le_bytes());
    Ok(0)
}

fn set_power_action(call: &Call) -> Result<u64, KernelError> {
    crate::debug_print!("[po] PDC: acao de energia {} (estado {}, flags {:#x}) sem o PopExecutePowerAction", call.arg(1) as u32, call.arg(2) as u32, call.arg(3) as u32);
    Ok(0)
}

fn report_button(call: &Call) -> Result<u64, KernelError> {
    let buttons = call.arg(1) as u32;
    let present = call.arg(2) as u8 != 0;
    for bit in 0..3 {
        if buttons & (1 << bit) != 0 && power_information::set_button_present(bit, present) {
            crate::debug_print!("[po] PDC: botao {} {} sem o PopResetCurrentPolicies", bit, if present { "presente" } else { "ausente" });
        }
    }
    Ok(0)
}

fn report_lid_state(call: &Call) -> Result<u64, KernelError> {
    let open = call.arg(1) as u8;
    power_information::set_lid_opened(open);
    power_setting::set_value_ac_dc(&GUID_LIDSWITCH_STATE_CHANGE, &((open != 0) as u32).to_le_bytes());
    Ok(0)
}

fn record_button(_call: &Call) -> Result<u64, KernelError> {
    static ABSENT: AtomicBool = AtomicBool::new(false);
    BSD_POWER_TRANSITION.store(crate::ntos::ke::clock::shared_system_time() as u64, Ordering::SeqCst);
    note_absent(&ABSENT, "transicao de energia sem o registro no bootstat.dat");
    Ok(0)
}

/// SYSTEM_POWER_CAPABILITIES: os bytes das capacidades filtradas.
const CAP_SYSTEM_S1: usize = 3;
const CAP_SYSTEM_S2: usize = 4;
const CAP_SYSTEM_S3: usize = 5;
const CAP_SYSTEM_S5: usize = 7;
const CAP_AOAC: usize = 0x14;

/// PopIsHibernateSupported e PopIsHiberbootSupported: o OpenNT não hiberna.
fn hibernate_supported() -> bool {
    false
}

/// POWER_ACTION.
const ACTION_NONE: u32 = 0;
const ACTION_RESERVED: u32 = 1;
const ACTION_SLEEP: u32 = 2;
const ACTION_HIBERNATE: u32 = 3;
const ACTION_SHUTDOWN: u32 = 4;
const ACTION_SHUTDOWN_OFF: u32 = 6;
const ACTION_DISPLAY_OFF: u32 = 8;

/// PopVerifyPowerActionPolicy(Política*): a POWER_ACTION_POLICY
/// {Action, Flags, EventCode} ajustada às capacidades. Devolve TRUE quando a
/// ação caiu para PowerActionNone por falta de estado de sono.
pub fn verify_action_policy(policy: u64) -> u8 {
    if policy == 0 {
        return 0;
    }
    let mut flags = guest::read32(policy + 4);
    if flags & 0x0CFF_FFC0 != 0 {
        return 0;
    }
    if flags & 0x8000_0000 != 0 {
        flags = (flags & !3) | 4;
        guest::write32(policy + 4, flags);
    }
    let capabilities = power_information::filtered_capabilities();
    let present = |offset: usize| capabilities.get(offset).copied().unwrap_or(0) != 0;
    let sleep_states = [CAP_SYSTEM_S1, CAP_SYSTEM_S2, CAP_SYSTEM_S3].iter().filter(|&&offset| present(offset)).count();
    let hibernate = hibernate_supported();
    let mut downgraded = 0u8;
    let mut action = guest::read32(policy);
    loop {
        let original = action;
        let mut next = action;
        if action == ACTION_RESERVED {
            guest::write32(policy, ACTION_SLEEP);
            action = ACTION_SLEEP;
            next = ACTION_SLEEP;
        }
        match action {
            ACTION_SLEEP => {
                if sleep_states == 0 {
                    if hibernate {
                        guest::write32(policy, ACTION_HIBERNATE);
                        next = ACTION_HIBERNATE;
                    } else {
                        guest::write32(policy, ACTION_NONE);
                        downgraded = 1;
                        next = ACTION_NONE;
                    }
                }
            }
            ACTION_HIBERNATE if !hibernate => {
                if PROMOTE_HIBERNATE_TO_SHUTDOWN != 0 {
                    guest::write32(policy, ACTION_SHUTDOWN);
                    next = ACTION_SHUTDOWN;
                } else if sleep_states == 0 {
                    guest::write32(policy, ACTION_NONE);
                    downgraded = 1;
                    next = ACTION_NONE;
                } else {
                    guest::write32(policy, ACTION_SLEEP);
                    next = ACTION_SLEEP;
                }
            }
            ACTION_SHUTDOWN_OFF if !present(CAP_SYSTEM_S5) => {
                guest::write32(policy, ACTION_SHUTDOWN);
                next = ACTION_SHUTDOWN;
            }
            ACTION_DISPLAY_OFF if present(CAP_AOAC) => {
                guest::write32(policy, ACTION_SLEEP);
                next = ACTION_SLEEP;
            }
            _ => {}
        }
        if next == original {
            return downgraded;
        }
        action = next;
    }
}

fn verify_action_policy_routine(call: &Call) -> Result<u64, KernelError> {
    Ok(verify_action_policy(call.arg(1)) as u64)
}

/// SYSTEM_POWER_STATE.
const STATE_WORKING: i32 = 1;
const STATE_S1: i32 = 2;
const STATE_S2: i32 = 3;
const STATE_S3: i32 = 4;
const STATE_S4: i32 = 5;

/// PopVerifySystemPowerState(Estado*, Pedido): o estado de sono baixado até
/// um que as capacidades tenham (S4 sem hibernação vira S3, S3 sem S3 vira
/// S2, e assim até PowerSystemWorking); com Pedido 1 ou 2 o caminho sobe
/// de S1 em diante, e sem nenhum estado o resultado é PowerSystemWorking.
pub fn verify_system_power_state(state: u64, request: i32) {
    if state == 0 {
        return;
    }
    let capabilities = power_information::filtered_capabilities();
    let present = |offset: usize| capabilities.get(offset).copied().unwrap_or(0) != 0;
    let mut value = guest::read32(state) as i32;
    if value > -1 && !(STATE_S1..=STATE_S4).contains(&value) {
        return;
    }
    let result = (|| {
        // `allow_hibernate` é o AL do 19041: cai a zero quando a descida
        // chega a PowerSystemWorking com Pedido 1 e vira subida.
        let mut allow_hibernate = true;
        if request < 0 {
            return value;
        }
        if request > 1 && request != 2 {
            return value;
        }
        if request <= 1 {
            // A descida: S4 → S3 → S2 → S1 → PowerSystemWorking.
            if value == STATE_S4 {
                if hibernate_supported() {
                    return value;
                }
                value = STATE_S3;
            }
            if value == STATE_S3 {
                if present(CAP_SYSTEM_S3) {
                    return value;
                }
                value = STATE_S2;
            }
            if value == STATE_S2 {
                if present(CAP_SYSTEM_S2) {
                    return value;
                }
                value = STATE_S1;
            }
            if value == STATE_S1 {
                if present(CAP_SYSTEM_S1) {
                    return value;
                }
                value = STATE_WORKING;
            }
            if value != STATE_WORKING || request != STATE_WORKING {
                return value;
            }
            allow_hibernate = false;
            value = STATE_S1;
        }
        // A subida (Pedido 2, ou a volta da descida): S1 → S2 → S3 → S4.
        if value == STATE_S1 {
            if present(CAP_SYSTEM_S1) {
                return value;
            }
            value = STATE_S2;
        }
        if value == STATE_S2 {
            if present(CAP_SYSTEM_S2) {
                return value;
            }
            value = STATE_S3;
        }
        if value == STATE_S3 {
            if present(CAP_SYSTEM_S3) {
                return value;
            }
            value = STATE_S4;
        }
        if value != STATE_S4 {
            return value;
        }
        if allow_hibernate && hibernate_supported() {
            return value;
        }
        STATE_WORKING
    })();
    guest::write32(state, result as u32);
}

fn verify_power_state_routine(call: &Call) -> Result<u64, KernelError> {
    verify_system_power_state(call.arg(1), call.arg(2) as u32 as i32);
    Ok(0)
}

fn block_session_switch(call: &Call) -> Result<u64, KernelError> {
    Ok(win32_callout::block_session_switch(call.arg(1) as u8 != 0, call.arg(2)) as u64)
}

fn control_monitor(call: &Call) -> Result<u64, KernelError> {
    Ok(win32_callout::control_monitor(call.arg(1), call.arg(2) as u32) as u64)
}

fn notify_cs_state_exited(_call: &Call) -> Result<u64, KernelError> {
    static ABSENT: AtomicBool = AtomicBool::new(false);
    note_absent(&ABSENT, "saida das fases do connected standby sem o agregador de energia");
    Ok(0)
}

fn current_pdc_phase(call: &Call) -> Result<u64, KernelError> {
    static ABSENT: AtomicBool = AtomicBool::new(false);
    let phase = call.arg(1) as u32;
    CURRENT_CS_PHASE.store(phase, Ordering::SeqCst);
    match phase {
        6 => {
            note_absent(&ABSENT, "transicao de sono do PDC sem o agregador de energia");
            Ok(STATUS_INVALID_PARAMETER as u64)
        }
        1 | 2 | 7 | 8 => {
            note_absent(&ABSENT, "fase do PDC sem o vigia da fase ociosa nem a contabilidade do connected standby");
            Ok(0)
        }
        _ => Ok(0),
    }
}

fn idle_scan_enabled(_call: &Call) -> Result<u64, KernelError> {
    Ok(if IDLE_SCAN_INTERVAL > 0 { 0 } else { STATUS_UNSUCCESSFUL as u64 })
}

fn ppm_register_profiles(call: &Call) -> Result<u64, KernelError> {
    Ok(processor_power::register_profiles(call.arg(1) as u8 as u32, call.arg(2)) as u64)
}

fn ppm_apply_profile(call: &Call) -> Result<u64, KernelError> {
    static ABSENT: AtomicBool = AtomicBool::new(false);
    processor_power::apply_profile(call.arg(1));
    note_absent(&ABSENT, "perfil do PPM aplicado sem a reavaliacao da politica de desempenho do processador");
    Ok(0)
}

fn ppm_reset_profile(_call: &Call) -> Result<u64, KernelError> {
    static ABSENT: AtomicBool = AtomicBool::new(false);
    if processor_power::profile_status() & 2 == 0 {
        note_absent(&ABSENT, "perfil do PPM habilitado ou desabilitado sem a politica de desempenho do processador");
    }
    Ok(0)
}

fn network_resiliency(call: &Call) -> Result<u64, KernelError> {
    static ABSENT: AtomicBool = AtomicBool::new(false);
    let engaged = call.arg(1) as u8 != 0;
    NET_RESILIENCY_ENGAGED.store(engaged as u8, Ordering::SeqCst);
    NET_GRACE_PERIOD_STATE.store(engaged as u32, Ordering::SeqCst);
    note_absent(&ABSENT, "resiliencia de rede sem a contabilidade de DS nem o temporizador de avaliacao");
    Ok(0)
}

fn query_drips_residency(_call: &Call) -> Result<u64, KernelError> {
    Ok(u64::MAX)
}

fn sleep_study_set_phase_active(call: &Call) -> Result<u64, KernelError> {
    static ABSENT: AtomicBool = AtomicBool::new(false);
    if matches!(call.arg(1) as u32, 1..=5 | 9) {
        note_absent(&ABSENT, "fase do Sleep Study sem as colecoes de bloqueadores");
    }
    Ok(0)
}

fn power_request_blocking(_call: &Call) -> Result<u64, KernelError> {
    static ABSENT: AtomicBool = AtomicBool::new(false);
    note_absent(&ABSENT, "bloqueio de pedidos de energia sem o cronometro ExecutionRequiredStopWatchCollection");
    Ok(0)
}
