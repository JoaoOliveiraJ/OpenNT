//! Acessores do EPROCESS: os PsGetProcess*, PsIsProtectedProcess[Light],
//! PsIsSystemProcess e as consultas WOW64.
//!
//! Leem os campos do layout 19041 que o OpenNT mantém, pelo endereço do
//! objeto dado; uma referência válida mantém o objeto consultável depois da
//! saída. Não referenciam nem substituem o processo pelo corrente, salvo nas
//! variantes `current_*` (o processo corrente é o anexado, como o
//! PsGetCurrentProcess).

use super::process;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{Eprocess, Ethread, Ewow64process, Kpcr};
use crate::ntos::ke::pcr;
use crate::rtl::KernelError;

/// O PEPROCESS recebido (o chamador garante um processo vivo ou retido).
fn eprocess(process: u64) -> &'static Eprocess {
    // SAFETY: os exports recebem um PEPROCESS válido, como no NT.
    unsafe { Eprocess::at(process) }
}

/// PsGetProcessId: EPROCESS.UniqueProcessId.
pub fn id(process: u64) -> u64 {
    eprocess(process).unique_process_id.get()
}

/// PsGetProcessCreateTimeQuadPart: EPROCESS.CreateTime, separado do
/// RundownProtect (+0x458).
pub fn create_time(process: u64) -> u64 {
    eprocess(process).create_time.quad_part.get() as u64
}

/// PsGetProcessExitStatus.
pub fn exit_status(process: u64) -> u32 {
    eprocess(process).exit_status.get() as u32
}

/// PsGetProcessExitProcessCalled: bit 2 de Flags.
pub fn exit_process_called(process: u64) -> u32 {
    eprocess(process).process_exiting()
}

/// LARGE_INTEGER PsGetProcessExitTime(VOID): o ExitTime do processo corrente.
pub fn current_exit_time() -> u64 {
    eprocess(process::get_current_process()).exit_time.quad_part.get() as u64
}

/// PsGetProcessPeb.
pub fn peb(process: u64) -> u64 {
    eprocess(process).peb.get()
}

/// PsGetProcessImageFileName: o endereço do campo ImageFileName.
pub fn image_file_name(process: u64) -> u64 {
    eprocess(process).image_file_name[0].address()
}

/// PsGetProcessSectionBaseAddress.
pub fn section_base_address(process: u64) -> u64 {
    eprocess(process).section_base_address.get()
}

/// PsGetProcessProtection: PS_PROTECTION completo (Type, Audit e Signer);
/// os testes de tipo usam só os três bits baixos.
pub fn protection(process: u64) -> u8 {
    eprocess(process).protection.level.get()
}

/// PsIsProtectedProcess: qualquer tipo de proteção.
pub fn is_protected(process: u64) -> bool {
    protection(process) & 7 != 0
}

/// PsIsProtectedProcessLight: tipo PsProtectedTypeProtectedLight (1).
pub fn is_protected_light(process: u64) -> bool {
    protection(process) & 7 == 1
}

/// PsGetProcessSignatureLevel: escreve o nível da seção (se houver saída)
/// antes de ler o da imagem, preservando o resultado quando a saída aponta
/// para um dos campos.
pub fn signature_level(process: u64, section_signature_level: u64) -> u8 {
    let process = eprocess(process);
    if section_signature_level != 0 {
        // SAFETY: PSE_SIGNING_LEVEL de saída do chamador de kernel.
        let output = unsafe { Field::<u8>::at(section_signature_level) };
        output.set(process.section_signature_level.get());
    }
    process.signature_level.get()
}

/// PsGetProcessWin32Process.
pub fn win32_process(process: u64) -> u64 {
    eprocess(process).win32_process.get()
}

/// PsGetCurrentProcessWin32Process.
pub fn current_win32_process() -> u64 {
    win32_process(process::get_current_process())
}

/// PsGetProcessWow64Process: PEB do EWOW64PROCESS; sem ele o processo não
/// tem ambiente WOW64.
pub fn wow64_process(process: u64) -> u64 {
    let wow64_process = eprocess(process).wo_w64_process.get();
    if wow64_process == 0 {
        0
    } else {
        // SAFETY: EPROCESS.WoW64Process aponta para o EWOW64PROCESS do processo.
        unsafe { Ewow64process::at(wow64_process) }.peb.get()
    }
}

/// PsGetCurrentProcessWow64Process: processo da thread atual pela região
/// de controle do processador.
pub fn current_wow64_process() -> Result<u64, KernelError> {
    let region = pcr::get_pcr_address();
    if region == 0 {
        return Err(KernelError::new("current WOW64 query requires an initialized KPCR"));
    }
    // SAFETY: a KPCR inicializada do processador corrente.
    let thread = unsafe { Kpcr::at(region) }.prcb.current_thread.get();
    // SAFETY: Prcb.CurrentThread é o ETHREAD em execução.
    Ok(wow64_process(unsafe { Ethread::at(thread) }.tcb.apc_state.process.get()))
}

/// PsGetProcessInheritedFromUniqueProcessId.
pub fn inherited_from_unique_process_id(process: u64) -> u64 {
    eprocess(process).inherited_from_unique_process_id.get()
}

/// PsGetProcessJob.
pub fn job(process: u64) -> u64 {
    eprocess(process).job.get()
}

/// PsGetProcessSequenceNumber.
pub fn sequence_number(process: u64) -> u64 {
    eprocess(process).sequence_number.get()
}

/// PsGetProcessPriorityClass.
pub fn priority_class(process: u64) -> u8 {
    eprocess(process).priority_class.get()
}

/// PsGetProcessWin32WindowStation.
pub fn win32_window_station(process: u64) -> u64 {
    eprocess(process).win32_window_station.get()
}

/// PsGetProcessSecurityPort.
pub fn security_port(process: u64) -> u64 {
    eprocess(process).security_port.get()
}

/// PsGetProcessDxgProcess.
pub fn dxg_process(process: u64) -> u64 {
    eprocess(process).dxg_process.get()
}

/// PsIsSystemProcess: Flags3.SystemProcess.
pub fn is_system_process(process: u64) -> bool {
    eprocess(process).system_process() != 0
}

// ---- ps-process-info: máquina WOW64 e start key (ntoskrnl 19041) ----------

/// IMAGE_FILE_MACHINE_AMD64: a máquina de um processo sem WOW64.
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

/// PsWow64GetProcessMachine (0x6c14c0): EWOW64PROCESS.Machine, ou AMD64 sem
/// EWOW64PROCESS (ou com Machine zero).
pub fn wow64_machine(process: u64) -> u16 {
    let wow64_process = eprocess(process).wo_w64_process.get();
    if wow64_process != 0 {
        // SAFETY: o EWOW64PROCESS vive enquanto o EPROCESS dono vive.
        let machine = unsafe { Ewow64process::at(wow64_process) }.machine.get();
        if machine != 0 {
            return machine;
        }
    }
    IMAGE_FILE_MACHINE_AMD64
}

/// PsGetProcessStartKey (0x25ed50): (KUSER_SHARED_DATA.BootId << 48) |
/// SequenceNumber — o ULONG do BootId é estendido a 64 bits antes do
/// deslocamento.
pub fn start_key(process: u64) -> u64 {
    // SAFETY: KUSER_SHARED_DATA é mapeado pelo Mm no boot e nunca sai.
    let shared = unsafe { crate::ntos::inc::types::KuserSharedData::at(crate::ntos::mm::shared_user_data::SHARED_USER_DATA_VA) };
    ((shared.boot_id.get() as u64) << 48) | eprocess(process).sequence_number.get()
}

// ---- ps-priority: classe de prioridade (ntoskrnl 19041) --------------------

/// PsSetProcessPriorityClass (0x581460): grava o byte cru de
/// EPROCESS.PriorityClass (o par de `priority_class`).
pub fn set_priority_class(process: u64, priority_class: u8) {
    eprocess(process).priority_class.set(priority_class);
}

/// PspPriorityTable: a prioridade base de cada PROCESS_PRIORITY_CLASS
/// (Unknown, Idle, Normal, High, RealTime, BelowNormal, AboveNormal).
const PRIORITY_TABLE: [i8; 7] = [8, 4, 8, 13, 24, 6, 10];
/// PSPROCESSPRIORITYMODE.
const PRIORITY_FOREGROUND: u32 = 1;
const PRIORITY_SPINNING: u32 = 2;
/// A prioridade de memória de um processo em primeiro plano.
const MEMORY_PRIORITY_FOREGROUND: u8 = 2;

/// PsSetProcessPriorityByClass(Process, PriorityMode): o
/// PspComputeQuantumAndPriority — a prioridade base vem da PspPriorityTable
/// pela classe do processo e vai para KPROCESS.BasePriority; fora do modo
/// Spinning, a prioridade de memória (EPROCESS.Vm, MMSUPPORT_FLAGS) fica em
/// 2 no primeiro plano e 0 no fundo, como o MmSetMemoryPriorityProcess. O
/// OpenNT não tem quantum por processo nem a fila de pedidos de primeiro
/// plano do NT: o efeito é o da prioridade.
pub fn set_priority_by_class(process: u64, mode: u32) {
    let object = eprocess(process);
    if mode != PRIORITY_SPINNING {
        let memory = if mode == PRIORITY_FOREGROUND { MEMORY_PRIORITY_FOREGROUND } else { 0 };
        object.vm.instance.flags.memory_priority.set(memory);
    }
    let class = object.priority_class.get() as usize;
    object.pcb.base_priority.set(PRIORITY_TABLE.get(class).copied().unwrap_or(PRIORITY_TABLE[2]));
}

// ---- Contadores de disco do processo (ps-disk-counters) -----------------------------
//
// ntoskrnl 10.0.19045: PsIsDiskCountersEnabled 0x3ca4b0 = (PsDisableDiskCounters
// == 0), e o global vale 0 na imagem; PsUpdateDiskCounters 0x30f3d0:
// EPROCESS.DiskCounters (PROCESS_DISK_COUNTERS) nulo -> nada; senão lock xadd
// de BytesRead, BytesWritten, ReadOperationCount, WriteOperationCount e
// FlushOperationCount, só os não nulos. O EPROCESS do OpenNT não aloca o
// bloco DiskCounters (o NT o cria no PspAllocateProcess), então hoje a
// atualização não encontra destino, como o NT para um processo sem o bloco.

/// PsDisableDiskCounters (o OpenNT não oferece a chave que o liga).
pub fn disk_counters_enabled() -> bool {
    true
}

fn add_counter(counter: &Field<u64>, delta: u64) {
    if delta != 0 {
        counter.atomic().fetch_add(delta, core::sync::atomic::Ordering::SeqCst);
    }
}

/// PsUpdateDiskCounters(Process, BytesRead, BytesWritten, ReadOperationCount,
/// WriteOperationCount, FlushOperationCount).
pub fn update_disk_counters(process: &Eprocess, bytes_read: u64, bytes_written: u64, reads: u32, writes: u32, flushes: u32) {
    let address = process.disk_counters.get();
    if address == 0 {
        return;
    }
    // SAFETY: EPROCESS.DiskCounters não nulo aponta para o PROCESS_DISK_COUNTERS do processo.
    let counters = unsafe { crate::ntos::inc::types::ProcessDiskCounters::at(address) };
    add_counter(&counters.bytes_read, bytes_read);
    add_counter(&counters.bytes_written, bytes_written);
    add_counter(&counters.read_operation_count, reads as u64);
    add_counter(&counters.write_operation_count, writes as u64);
    add_counter(&counters.flush_operation_count, flushes as u64);
}
