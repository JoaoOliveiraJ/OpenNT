//! KeStackAttachProcess/KeUnstackDetachProcess — `system32/ntos/ke/process-attachment.js`.
//!
//! Anexação da thread corrente com KAPC_STATE x64 de 48 bytes. O MM atual
//! compartilha uma PML4 entre processos: a identidade APC e as filas mudam
//! de verdade, mas não há um espaço de endereços independente.

use alloc::collections::BTreeMap;

use super::{apc, irql, pcr};
use crate::hal::cpu;
use crate::ntos::mm::memory_map;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{eprocess, kthread};

/// Campos privados conferidos no PDB e nas instruções do kernel 19041.
const APC_STATE_INDEX: u64 = 0x24A;
const SAVED_APC_STATE: u64 = 0x258;
const PROCESS_FLAGS: u64 = 0x278;
const PROCESS_STACK_COUNT: u64 = 0x348;
const PROCESS_ACTIVE_PROCESSORS: u64 = 0x178;

/// Dados da anexação guardados junto do quadro salvo pelas APCs.
#[derive(Clone, Copy)]
struct Frame {
    caller_state: u64,
    saved_state: u64,
    previous_index: u8,
    target_process: u64,
}

static FRAMES: SpinLock<BTreeMap<(u64, usize), Frame>> = SpinLock::new(BTreeMap::new());

/// KeAttachProcess salva o ambiente no KTHREAD.SavedApcState embutido e usa
/// um pequeno bloco-marcador separado como "caller_state" do núcleo de
/// anexação (o núcleo exige que marcador e estado salvo sejam buffers
/// distintos no primeiro attach). thread → bloco-marcador, consumido por
/// KeDetachProcess.
static LEGACY_ATTACH: SpinLock<BTreeMap<u64, u64>> = SpinLock::new(BTreeMap::new());

/// IRQL abaixo de DISPATCH_LEVEL; uso inválido não vira sucesso.
fn require_attach_level() -> Result<(), KernelError> {
    if irql::get_irql() >= 2 {
        return Err(KernelError::new("process attachment requires IRQL below DISPATCH_LEVEL"));
    }
    Ok(())
}

/// Recusa uma raiz que o MM atual não sabe selecionar.
fn require_supported_address_space(process: u64) -> Result<(), KernelError> {
    if guest::read64(process + eprocess::DIRECTORY_TABLE_BASE) != memory_map::PML4_PHYS {
        return Err(KernelError::new("process attachment requires an address space managed by the shared-PML4 MM"));
    }
    Ok(())
}

/// StackCount: estado nos três bits baixos e a quantidade de pilhas nos
/// demais; atualização atômica.
fn change_stack_count(process: u64, difference: i64) -> Result<(), KernelError> {
    let address = process + PROCESS_STACK_COUNT;
    loop {
        let previous = guest::read32(address);
        let next = previous as i64 + difference;
        if previous & 7 != 0 || !(0..=0xFFFF_FFFF).contains(&next) {
            return Err(KernelError::new("invalid resident process stack count"));
        }
        if guest::compare_exchange32(address, previous, next as u32)? == previous {
            return Ok(());
        }
    }
}

/// Publica a CPU (grupo e número da PRCB) na afinidade ativa do destino e a
/// retira da origem, recarregando a raiz compartilhada.
fn publish_address_space(previous_process: u64, next_process: u64) -> Result<(), KernelError> {
    let region = pcr::get_pcr_address();
    let group = guest::read8(region + 0x250) as u64;
    let number = guest::read8(region + 0x251) as u64;
    let affinity_offset = PROCESS_ACTIVE_PROCESSORS + group * 8;
    let bit = 1u64 << number;
    for (process, active) in [(next_process, true), (previous_process, false)] {
        let address = process + affinity_offset;
        loop {
            let previous = guest::read64(address);
            let next = if active { previous | bit } else { previous & !bit };
            if guest::compare_exchange64(address, previous, next)? == previous {
                break;
            }
        }
        if active {
            cpu::reload_cr3();
        }
    }
    Ok(())
}

/// Liberação da retenção do processo anexado (chamada pelas APCs).
fn release_target(process: u64) {
    if let Err(error) = change_stack_count(process, -8) {
        debug_print!("[attach] {}", error);
    }
    let _ = process::dereference(process);
}

/// Salva só o marcador 1 quando já estamos no destino. Na primeira troca o
/// ambiente anterior vai para KTHREAD.SavedApcState; nas demais, para o
/// bloco do chamador.
pub fn attach(target_process: u64, caller_state: u64) -> Result<u32, KernelError> {
    require_attach_level()?;
    let thread = process::get_current_thread();
    let current_state = thread + kthread::APC_STATE;
    let previous_process = guest::read64(current_state + 0x20);
    if pcr::get_dpc_request_summary() & 0x10001 != 0 || guest::read32(target_process + PROCESS_FLAGS) & 0x400 != 0 {
        return Err(KernelError::new("invalid process attach attempt (native bugcheck 0x5)"));
    }
    if previous_process == target_process {
        guest::write64(caller_state + 0x20, 1);
        return Ok(0);
    }
    require_supported_address_space(previous_process)?;
    require_supported_address_space(target_process)?;
    let previous_index = guest::read8(thread + APC_STATE_INDEX);
    let saved_state = if previous_index != 0 { caller_state } else { thread + SAVED_APC_STATE };
    let count = guest::read32(target_process + PROCESS_STACK_COUNT);
    if count & 7 != 0 || count > 0xFFFF_FFF7 {
        return Err(KernelError::new("invalid resident process stack count"));
    }
    // A referência mantém o processo vivo durante callbacks e término concorrente.
    if process::reference(target_process).is_none() {
        return Err(KernelError::new("process attachment target is not a managed process"));
    }
    let mut failure = None;
    let mut transition = |_: u64| {
        let step = (|| -> Result<(), KernelError> {
            change_stack_count(target_process, 8)?;
            for offset in [0u64, 0x10] {
                guest::write64(current_state + offset, current_state + offset);
                guest::write64(current_state + offset + 8, current_state + offset);
            }
            guest::write16(current_state + 0x28, 0);
            guest::write8(current_state + 0x2A, 0);
            guest::write64(current_state + 0x20, target_process);
            guest::write8(thread + APC_STATE_INDEX, 1);
            publish_address_space(previous_process, target_process)?;
            if previous_index == 0 {
                guest::write64(caller_state + 0x20, 0);
            }
            Ok(())
        })();
        if let Err(error) = step {
            failure = Some(error);
        }
    };
    let depth = apc::begin_attachment(thread, Some(saved_state), Some(&mut transition))?;
    if let Some(error) = failure {
        return Err(error);
    }
    FRAMES.lock().insert((thread, depth), Frame { caller_state, saved_state, previous_index, target_process });
    apc::set_attachment_release(thread, (release_target, target_process));
    Ok(0)
}

/// Restaura a última anexação sem mudar o processo dono da ETHREAD/CID; as
/// APCs do ambiente original voltam à fila certa.
pub fn detach(caller_state: u64) -> Result<u32, KernelError> {
    require_attach_level()?;
    let marker = guest::read64(caller_state + 0x20);
    if marker == 1 {
        return Ok(0);
    }
    let thread = process::get_current_thread();
    let current_state = thread + kthread::APC_STATE;
    let saved_state = if marker == 0 { thread + SAVED_APC_STATE } else { caller_state };
    let depth = apc::current_attachment(thread);
    let frame = depth.and_then(|depth| FRAMES.lock().get(&(thread, depth)).copied());
    let (Some(depth), Some(frame)) = (depth, frame) else { return Err(KernelError::new("unbalanced process attachment")) };
    if frame.caller_state != caller_state || frame.saved_state != saved_state || guest::read8(thread + APC_STATE_INDEX) == 0 {
        return Err(KernelError::new("unbalanced process attachment"));
    }
    // A drenagem cooperativa só executa APCs permitidas; uma fila pendente
    // impede o retorno (nenhum trabalho é descartado).
    apc::deliver_all_queued()?;
    if guest::read8(current_state + 0x28) & 1 != 0 || guest::read64(current_state) != current_state || guest::read64(current_state + 0x10) != current_state + 0x10 {
        return Err(KernelError::new("detaching process with active or pending APCs"));
    }
    let restored_process = guest::read64(saved_state + 0x20);
    require_supported_address_space(restored_process)?;
    let mut failure = None;
    let mut transition = || {
        if frame.previous_index == 0 {
            guest::write64(saved_state + 0x20, 0);
        }
        guest::write8(thread + APC_STATE_INDEX, frame.previous_index);
        if let Err(error) = publish_address_space(frame.target_process, restored_process) {
            failure = Some(error);
        }
    };
    apc::end_attachment(thread, depth, Some(&mut transition))?;
    FRAMES.lock().remove(&(thread, depth));
    failure.map_or(Ok(0), Err)
}

/// KeAttachProcess(PKPROCESS): forma legada da anexação. Encaminha ao mesmo
/// núcleo de KeStackAttachProcess; no primeiro attach o estado anterior vai
/// para o KTHREAD.SavedApcState embutido (previous_index == 0), exatamente
/// como o KiAttachProcess. O bloco-marcador fica guardado para o detach.
pub fn attach_legacy(target_process: u64) -> Result<(), KernelError> {
    let thread = process::get_current_thread();
    let marker = guest::alloc_bytes(0x30);
    guest::write64(marker + 0x20, 0);
    match attach(target_process, marker) {
        Ok(_) => {
            if let Some(previous) = LEGACY_ATTACH.lock().insert(thread, marker) {
                guest::free_bytes(previous);
            }
            Ok(())
        }
        Err(error) => {
            guest::free_bytes(marker);
            Err(error)
        }
    }
}

/// KeDetachProcess(void): desfaz a anexação legada da thread corrente.
pub fn detach_legacy() -> Result<(), KernelError> {
    let thread = process::get_current_thread();
    let marker = LEGACY_ATTACH.lock().remove(&thread);
    if let Some(marker) = marker {
        let result = detach(marker);
        guest::free_bytes(marker);
        result?;
    }
    Ok(())
}

/// KeIsAttachedProcess(void): TRUE se a thread corrente está anexada
/// (ApcStateIndex != 0, isto é, o KAPC_STATE foi trocado).
pub fn is_attached() -> bool {
    let thread = process::get_current_thread();
    guest::read8(thread + APC_STATE_INDEX) != 0
}
