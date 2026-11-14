//! Acessores do objeto job (EJOB), como a parte de consulta dos jobs do Ps
//! do NT: lock, classe de restrições de UI, sessão e job raiz comum a dois
//! processos. Conferido contra o ntoskrnl 19041 (PsGetJobLock 0x32cf40,
//! PsGetJobUIRestrictionsClass 0x329c10, PsGetJobSessionId 0x2017c0,
//! PsGetProcessCommonJob 0x36c530).
//!
//! O OpenNT não cria jobs (EPROCESS.Job fica NULL): os chamadores só chegam
//! aqui com corpos que eles mesmos obtiveram; nada é fabricado. O tipo de
//! objeto Job existe desde o boot, publicado em PsJobType, como o
//! PspInitPhase0 o cria: PspJobMapping {0x20004, 0x2000B, 0x120000,
//! 0x1F003F}, ValidAccessMask 0x1F003F, SecurityRequired, ObjectTypeCode
//! 0x800, NonPagedPoolNx com 0x640 de cobrança não paginável.

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Ejob, Eprocess};
use crate::ntos::mm::kernel_data;
use crate::ntos::ob::object_types::{self, TypeTemplate};

/// O OBJECT_TYPE_INITIALIZER do tipo Job.
const JOB_TYPE: TypeTemplate = TypeTemplate {
    name: "Job",
    mapping: [0x2_0004, 0x2_000B, 0x12_0000, 0x1F_003F],
    valid_access: 0x1F_003F,
    flags: 0x08,
    object_type_code: 0x800,
    invalid_attributes: 0,
    pool_type: 0x200,
    paged_charge: 0,
    non_paged_charge: 0x640,
};

/// Cria o tipo Job (uma vez) e publica PsJobType.
pub fn initialize_type() {
    kernel_data::write("PsJobType", object_types::ensure(&JOB_TYPE).pointer);
}

/// PsGetJobSessionId: os marcadores -2/-1 (acima de 0xFFFFFFFD) saem -1.
const LAST_VALID_SESSION_ID: u32 = 0xFFFF_FFFD;

/// PsGetJobLock: o endereço do ERESOURCE embutido (EJOB.JobLock).
pub fn lock(job: &Ejob) -> u64 {
    job.job_lock.address()
}

/// PsGetJobUIRestrictionsClass.
pub fn ui_restrictions_class(job: &Ejob) -> u32 {
    job.ui_restrictions_class.get()
}

/// PsGetJobSessionId: valores acima de 0xFFFFFFFD saem como (ULONG)-1
/// (cmp eax,-3; cmova).
pub fn session_id(job: &Ejob) -> u32 {
    let session = job.session_id.get();
    if session > LAST_VALID_SESSION_ID { u32::MAX } else { session }
}

/// PsGetProcessCommonJob(Process1, Process2): o RootJob comum aos jobs dos
/// dois processos, ou NULL se algum não tem job ou as raízes diferem.
pub fn process_common_job(first: &Eprocess, second: &Eprocess) -> u64 {
    let (first_job, second_job) = (first.job.get(), second.job.get());
    if first_job == 0 || second_job == 0 {
        return 0;
    }
    // SAFETY: EPROCESS.Job de um processo vivo aponta para um EJOB vivo.
    let (first_job, second_job) = unsafe { (Ejob::at(first_job), Ejob::at(second_job)) };
    let root = first_job.root_job.get();
    if root == second_job.root_job.get() { root } else { 0 }
}

/// ZwQueryInformationJobObject(JobHandle, JobObjectInformationClass,
/// JobObjectInformation, Length, ReturnLength*): sem handle, o job do
/// processo corrente — fora de um job, como no NT, só as classes 0x1F e
/// 0x27 seguem e as demais dão STATUS_ACCESS_DENIED; com handle, o objeto
/// precisa ser um Job (JOB_OBJECT_QUERY). O OpenNT não cria jobs: um handle
/// válido de outro tipo dá STATUS_OBJECT_TYPE_MISMATCH, um inexistente
/// STATUS_INVALID_HANDLE, e as classes de silo sem job, que o NT responde
/// pelo silo hospedeiro, STATUS_NOT_SUPPORTED.
pub fn query_information_job_object(handle: u64, class: u32) -> u32 {
    const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
    const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
    if handle == 0 {
        // SAFETY: o EPROCESS corrente.
        let job = unsafe { Eprocess::at(crate::ntos::ps::process::get_current_process()) }.job.get();
        if job == 0 {
            return if class.wrapping_sub(0x1F) & !8 == 0 { STATUS_NOT_SUPPORTED } else { STATUS_ACCESS_DENIED };
        }
        return STATUS_NOT_SUPPORTED;
    }
    let known = matches!(crate::ntos::ob::open_pointer::resolve(handle, false), Some(Ok(_))) || crate::ntos::ps::user::state::get_user_handle(handle).is_some() || crate::ntos::io::file::zw::file_object_of_handle(handle) != 0;
    if known { STATUS_OBJECT_TYPE_MISMATCH } else { STATUS_INVALID_HANDLE }
}

// ---- PsGetEffectiveContainerId --------------------------------------------------
//
// Como o PsGetEffectiveContainerId do ntoskrnl 19041 (rva 0x30e400): Level
// (inteiro com sinal) a partir de 5 é STATUS_INVALID_PARAMETER_1 e Thread
// nula STATUS_INVALID_PARAMETER_2; a saída (o GUID do contêiner e um ULONG
// de flags, 0x14 bytes) é zerada antes. Numa DPC (KPRCB.DpcRequestSummary &
// 0x10001) a thread corrente não é examinada. A thread de trabalho em nome
// de outra (ETHREAD.WorkOnBehalfThread, PsGetWorkOnBehalfThread) troca a
// thread examinada e liga o bit 0 das flags. Do job do processo dela
// (EPROCESS.Job): nível 0 e 4 o ContainerId do próprio job; 2 o do
// EffectiveNetIoRateLimitJob; 3 o do EffectiveHeapAttributionJob; os demais
// nenhum. Sem job, o GUID fica zerado; o resultado é sempre sucesso.

const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;

/// Saída do PsGetEffectiveContainerId: o GUID e as flags.
#[repr(C)]
pub struct EffectiveContainerId {
    pub container_id: crate::ntos::inc::types::Guid,
    pub flags: crate::ntos::inc::field::Field<u32>,
}

// SAFETY: #[repr(C)] só de células e de estruturas do NT.
unsafe impl NtStruct for EffectiveContainerId {}

const _: () = assert!(core::mem::size_of::<EffectiveContainerId>() == 0x14);

/// O job de onde vem o GUID do nível pedido.
fn container_job(job: &Ejob, level: i32) -> u64 {
    match level {
        0 | 4 => job.address(),
        2 => job.effective_net_io_rate_limit_job.get(),
        3 => job.effective_heap_attribution_job.get(),
        _ => 0,
    }
}

/// PsGetEffectiveContainerId(Level, Thread, ContainerId*): devolve o
/// NTSTATUS. `output` é do chamador de modo kernel.
pub fn effective_container_id(level: i32, thread: u64, output: u64) -> Result<u32, crate::rtl::KernelError> {
    use crate::ntos::inc::types::Ethread;
    use crate::ntos::ps::process;
    if level >= 5 {
        return Ok(STATUS_INVALID_PARAMETER_1);
    }
    if thread == 0 {
        return Ok(STATUS_INVALID_PARAMETER_2);
    }
    crate::ntos::mm::guest_memory::write_bytes(output, &[0; 0x14]);
    // SAFETY: a saída do chamador, do tamanho da estrutura.
    let result = unsafe { EffectiveContainerId::at(output) };
    let current = process::get_current_thread();
    if crate::ntos::ke::pcr::current().prcb.dpc_request_summary.get() & 0x10001 != 0 && thread == current {
        return Ok(0);
    }
    // PsGetWorkOnBehalfThread: a thread em nome de quem esta trabalha, retida.
    // SAFETY: a ETHREAD viva do chamador.
    let on_behalf = unsafe { Ethread::at(thread) }.work_on_behalf_thread.get();
    let referenced = on_behalf != 0 && thread != current && process::reference_thread(on_behalf).is_some();
    let examined = if referenced {
        result.flags.set(result.flags.get() | 1);
        on_behalf
    } else {
        thread
    };
    // SAFETY: a thread examinada (viva ou retida) e o processo dela.
    let job = unsafe { Eprocess::at(Ethread::at(examined).tcb.process.get()) }.job.get();
    if job != 0 {
        // SAFETY: EPROCESS.Job de um processo vivo aponta para um EJOB vivo.
        let source = container_job(unsafe { Ejob::at(job) }, level);
        if source != 0 {
            // SAFETY: os jobs efetivos do EJOB também são EJOBs vivos.
            let guid = &unsafe { Ejob::at(source) }.container_id;
            let bytes = crate::ntos::mm::guest_memory::read_bytes(guid.address(), 16);
            crate::ntos::mm::guest_memory::write_bytes(result.container_id.address(), &bytes);
        }
    }
    if referenced {
        process::dereference_thread(on_behalf)?;
    }
    Ok(0)
}
