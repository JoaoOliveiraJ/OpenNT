//! KeStackAttachProcess/KeUnstackDetachProcess.
//!
//! Anexação da thread corrente com KAPC_STATE x64 de 48 bytes. O MM atual
//! compartilha uma PML4 entre processos: a identidade APC e as filas mudam
//! de verdade, mas não há um espaço de endereços independente.

use alloc::collections::BTreeMap;
use core::sync::atomic::Ordering;

use super::{apc, irql, pcr};
use crate::hal::cpu;
use crate::ntos::mm::memory_map;
use crate::ntos::ps::process;
use crate::ntos::inc::types::{KapcState, Kpcr, Kprocess, Kthread, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::{KernelError, SpinLock};

fn kprocess(process: u64) -> &'static Kprocess {
    // SAFETY: processos geridos pelo Ps (referenciados durante a anexação).
    unsafe { Kprocess::at(process) }
}

fn kthread(thread: u64) -> &'static Kthread {
    // SAFETY: a thread corrente.
    unsafe { Kthread::at(thread) }
}

fn apc_state(state: u64) -> &'static KapcState {
    // SAFETY: KTHREAD.ApcState/SavedApcState ou o PRKAPC_STATE do chamador.
    unsafe { KapcState::at(state) }
}

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
    if kprocess(process).directory_table_base.get() != memory_map::PML4_PHYS {
        return Err(KernelError::new("process attachment requires an address space managed by the shared-PML4 MM"));
    }
    Ok(())
}

/// StackCount: estado nos três bits baixos e a quantidade de pilhas nos
/// demais; atualização atômica.
fn change_stack_count(process: u64, difference: i64) -> Result<(), KernelError> {
    let count = kprocess(process).stack_count.value.atomic();
    let mut previous = count.load(Ordering::SeqCst) as u32;
    loop {
        let next = previous as i64 + difference;
        if previous & 7 != 0 || !(0..=0xFFFF_FFFF).contains(&next) {
            return Err(KernelError::new("invalid resident process stack count"));
        }
        match count.compare_exchange(previous as i32, next as u32 as i32, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return Ok(()),
            Err(observed) => previous = observed as u32,
        }
    }
}

/// Publica a CPU (grupo e número da PRCB) na afinidade ativa do destino e a
/// retira da origem, recarregando a raiz compartilhada.
fn publish_address_space(previous_process: u64, next_process: u64) -> Result<(), KernelError> {
    // SAFETY: a KPCR está mapeada desde `pcr::init`.
    let prcb = &unsafe { Kpcr::at(pcr::get_pcr_address()) }.prcb;
    let group = prcb.group.get() as usize;
    let bit = 1u64 << prcb.group_index.get();
    for (process, active) in [(next_process, true), (previous_process, false)] {
        // KPROCESS.ActiveProcessors.Bitmap[grupo]: LOCK OR / LOCK AND.
        let mask = kprocess(process).active_processors.bitmap[group].atomic();
        if active {
            mask.fetch_or(bit, Ordering::SeqCst);
        } else {
            mask.fetch_and(!bit, Ordering::SeqCst);
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
    let current = kthread(thread);
    let current_state = &current.apc_state;
    let previous_process = current_state.process.get();
    if pcr::get_dpc_request_summary() & 0x10001 != 0 || kprocess(target_process).va_space_deleted() != 0 {
        return Err(KernelError::new("invalid process attach attempt (native bugcheck 0x5)"));
    }
    if previous_process == target_process {
        apc_state(caller_state).process.set(1);
        return Ok(0);
    }
    require_supported_address_space(previous_process)?;
    require_supported_address_space(target_process)?;
    let previous_index = current.apc_state_index.get();
    let saved_state = if previous_index != 0 { caller_state } else { current.saved_apc_state.address() };
    let count = kprocess(target_process).stack_count.value.get() as u32;
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
            for head in &current_state.apc_list_head {
                head.flink.set(head.address());
                head.blink.set(head.address());
            }
            current_state.in_progress_flags.set(0);
            current_state.kernel_apc_pending.set(0);
            current_state.user_apc_pending_all.set(0);
            current_state.process.set(target_process);
            current.apc_state_index.set(1);
            publish_address_space(previous_process, target_process)?;
            if previous_index == 0 {
                apc_state(caller_state).process.set(0);
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
    let marker = apc_state(caller_state).process.get();
    if marker == 1 {
        return Ok(0);
    }
    let thread = process::get_current_thread();
    let current = kthread(thread);
    let current_state = &current.apc_state;
    let saved_state = if marker == 0 { current.saved_apc_state.address() } else { caller_state };
    let depth = apc::current_attachment(thread);
    let frame = depth.and_then(|depth| FRAMES.lock().get(&(thread, depth)).copied());
    let (Some(depth), Some(frame)) = (depth, frame) else { return Err(KernelError::new("unbalanced process attachment")) };
    if frame.caller_state != caller_state || frame.saved_state != saved_state || current.apc_state_index.get() == 0 {
        return Err(KernelError::new("unbalanced process attachment"));
    }
    // A drenagem cooperativa só executa APCs permitidas; uma fila pendente
    // impede o retorno (nenhum trabalho é descartado).
    apc::deliver_all_queued()?;
    let [kernel_head, user_head] = &current_state.apc_list_head;
    if current_state.in_progress_flags.get() & 1 != 0 || kernel_head.flink.get() != kernel_head.address() || user_head.flink.get() != user_head.address() {
        return Err(KernelError::new("detaching process with active or pending APCs"));
    }
    let restored_process = apc_state(saved_state).process.get();
    require_supported_address_space(restored_process)?;
    let mut failure = None;
    let mut transition = || {
        if frame.previous_index == 0 {
            apc_state(saved_state).process.set(0);
        }
        current.apc_state_index.set(frame.previous_index);
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
    let marker = guest::alloc_bytes(KapcState::SIZE);
    apc_state(marker).process.set(0);
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
    kthread(thread).apc_state_index.get() != 0
}
