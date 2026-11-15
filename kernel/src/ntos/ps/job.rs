//! O objeto job (EJOB) do Ps, como no ntoskrnl 19041.
//!
//! - Este arquivo: o tipo Job, os acessores dos drivers (PsGetJobLock
//!   0x32cf40, PsGetJobUIRestrictionsClass 0x329c10, PsGetJobSessionId
//!   0x2017c0, PsGetProcessCommonJob 0x36c530, PsGetEffectiveContainerId) e
//!   o que as partes do assunto dividem: a trava dos jobs, os nomes dos bits
//!   e as notificações para a porta de conclusão (PspSendJobNotification).
//! - `object`: NtCreateJobObject, NtOpenJobObject, a lista PspJobList, os ids
//!   únicos e as rotinas do tipo (PspJobClose, PspJobDelete).
//! - `membership`: a atribuição de um processo (PsAssignProcessToJobObject,
//!   com a hierarquia de jobs aninhados do Windows 8), a herança na criação
//!   (PspImplicitAssignProcessToJob, PS_ATTRIBUTE_JOB_LIST, breakaway), a
//!   saída e a deleção de um processo membro, NtTerminateJobObject e
//!   NtIsProcessInJob.
//! - `limits`: os limites efetivos de um job aninhado, o teto de commit de
//!   cada processo e o commit do job (PspChangeJobMemoryUsageByProcess).
//! - `information`: NtQueryInformationJobObject e NtSetInformationJobObject.
//!
//! O tipo de objeto Job nasce no boot, publicado em PsJobType, como o
//! PspInitPhase0 o cria: PspJobMapping {0x20004, 0x2000B, 0x120000,
//! 0x1F003F}, ValidAccessMask 0x1F003F, SecurityRequired, ObjectTypeCode
//! 0x800, NonPagedPoolNx com 0x640 de cobrança não paginável, CloseProcedure
//! PspJobClose e DeleteProcedure PspJobDelete.
//!
//! As travas do NT (o ERESOURCE de cada job, a do job raiz, a da atribuição
//! e o push lock dos limites de memória) são aqui uma trava só, [`JOBS`]: os
//! contadores, as listas de processos e de filhos, os limites e a porta
//! mudam só com ela. Ela nunca atravessa uma chamada que volte ao assunto
//! (término de processo, soltura de referência, envio à porta): o que sai
//! dela vai para um [`Outbox`] e é entregue depois.

pub mod information;
pub mod limits;
pub mod membership;
pub mod object;

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Ejob, Eprocess};
use crate::ntos::init::exports::private_routines;
use crate::ntos::mm::kernel_data;
use crate::ntos::ob::object_types::{self, TypeTemplate};
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::ob::{object_header, object_reference, reference_trace};
use crate::rtl::SpinLock;

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

/// A trava dos jobs (o papel do JobLock de cada EJOB, da trava do job raiz,
/// da PspJobAssignmentLock e do MemoryLimitsLock).
pub(crate) static JOBS: SpinLock<()> = SpinLock::new(());

// ---- NTSTATUS ------------------------------------------------------------------
pub(crate) const STATUS_SUCCESS: u32 = 0;
pub(crate) const STATUS_PROCESS_NOT_IN_JOB: u32 = 0x123;
pub(crate) const STATUS_PROCESS_IN_JOB: u32 = 0x124;
pub(crate) const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
pub(crate) const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub(crate) const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub(crate) const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub(crate) const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub(crate) const STATUS_QUOTA_EXCEEDED: u32 = 0xC000_0044;
pub(crate) const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
pub(crate) const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
pub(crate) const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;
pub(crate) const STATUS_RETRY: u32 = 0xC000_022D;

// ---- Direitos (JOB_OBJECT_*) -----------------------------------------------------
pub(crate) const JOB_OBJECT_ASSIGN_PROCESS: u32 = 0x1;
pub(crate) const JOB_OBJECT_SET_ATTRIBUTES: u32 = 0x2;
pub(crate) const JOB_OBJECT_QUERY: u32 = 0x4;
pub(crate) const JOB_OBJECT_TERMINATE: u32 = 0x8;
pub(crate) const JOB_OBJECT_SET_SECURITY_ATTRIBUTES: u32 = 0x10;

// ---- EJOB.LimitFlags (JOB_OBJECT_LIMIT_*) ----------------------------------------
pub(crate) mod limit {
    pub const WORKINGSET: u32 = 0x1;
    pub const PROCESS_TIME: u32 = 0x2;
    pub const JOB_TIME: u32 = 0x4;
    pub const ACTIVE_PROCESS: u32 = 0x8;
    pub const AFFINITY: u32 = 0x10;
    pub const PRIORITY_CLASS: u32 = 0x20;
    pub const PRESERVE_JOB_TIME: u32 = 0x40;
    pub const SCHEDULING_CLASS: u32 = 0x80;
    pub const PROCESS_MEMORY: u32 = 0x100;
    pub const JOB_MEMORY: u32 = 0x200;
    pub const BREAKAWAY_OK: u32 = 0x800;
    pub const SILENT_BREAKAWAY_OK: u32 = 0x1000;
    pub const KILL_ON_JOB_CLOSE: u32 = 0x2000;
    pub const SUBSET_AFFINITY: u32 = 0x4000;
    /// O limite interno do commit total (EJOB.JobTotalMemoryLimit).
    pub const JOB_TOTAL_MEMORY: u32 = 0x20_0000;
}

// ---- EJOB.JobFlags ---------------------------------------------------------------
pub(crate) mod flags {
    pub const CLOSE_DONE: u32 = 1 << 0;
    pub const UI_LIMITS: u32 = 1 << 4;
    pub const TERMINATING: u32 = 1 << 7;
    pub const EMPTY_JOB_NOTIFIED: u32 = 1 << 21;
    pub const NET_RATE_CONTROL_ACTIVE: u32 = 1 << 25;
    pub const DISALLOW_NEW_PROCESSES: u32 = 1 << 29;
    pub const SILO: u32 = 1 << 30;
    /// Os bits que um job aninhado herda do pai (PspEstablishJobHierarchy):
    /// WakeNotificationEnabled, TimersVirtualized, NoWakeChargePolicyDecided
    /// e DropNoWakeCharges.
    pub const INHERITED: u32 = 0x0184_1000;
}

/// JOBS_FLAGS2.ParentLocked.
pub(crate) const PARENT_LOCKED: u32 = 1;

// ---- JOB_OBJECT_MSG_* ------------------------------------------------------------
pub(crate) mod message {
    pub const ACTIVE_PROCESS_LIMIT: u32 = 3;
    pub const ACTIVE_PROCESS_ZERO: u32 = 4;
    pub const NEW_PROCESS: u32 = 6;
    pub const EXIT_PROCESS: u32 = 7;
    pub const ABNORMAL_EXIT_PROCESS: u32 = 8;
    pub const PROCESS_MEMORY_LIMIT: u32 = 9;
    pub const JOB_MEMORY_LIMIT: u32 = 10;
}

/// O EJOB de um corpo vivo.
pub(crate) fn ejob(job: u64) -> &'static Ejob {
    // SAFETY: só corpos de job retidos por quem chama chegam aqui.
    unsafe { Ejob::at(job) }
}

/// O EPROCESS de um corpo vivo.
pub(crate) fn eprocess(process: u64) -> &'static Eprocess {
    // SAFETY: só EPROCESS retidos por quem chama chegam aqui.
    unsafe { Eprocess::at(process) }
}

/// O OBJECT_TYPE Job (PsJobType).
pub(crate) fn job_type() -> u64 {
    match kernel_data::read("PsJobType") {
        0 => object_types::ensure(&JOB_TYPE).pointer,
        pointer => pointer,
    }
}

/// Cria o tipo Job (uma vez), publica PsJobType e liga as rotinas do tipo.
pub fn initialize_type() {
    let pointer = object_types::ensure(&JOB_TYPE).pointer;
    kernel_data::write("PsJobType", pointer);
    crate::ntos::ps::process::register_process_exit_routine(membership::process_exit_notify);
    if let Some(info) = object_types::type_object(pointer) {
        info.type_info.close_procedure.set(private_routines::address("PspJobClose"));
        info.type_info.delete_procedure.set(private_routines::address("PspJobDelete"));
    }
}

/// ObfReferenceObjectWithTag sobre um job.
pub(crate) fn reference_job(job: u64) {
    let _ = object_reference::reference_with_tag(job, reference_trace::DEFAULT_TAG, false);
}

/// ObDereferenceObjectDeferDelete: a última referência de um job solta fora
/// de qualquer trava do assunto.
pub(crate) fn dereference_job(job: u64) {
    let _ = object_reference::dereference_defer_delete(job, reference_trace::DEFAULT_TAG);
}

/// As notificações e as solturas que saem de dentro da [`JOBS`], entregues
/// por [`Outbox::deliver`] depois de soltá-la.
#[derive(Default)]
pub(crate) struct Outbox {
    /// (job, porta, chave, mensagem, contexto, quota): job e porta retidos.
    notifications: Vec<(u64, u64, u64, u32, u64, bool)>,
    /// Referências de job a soltar.
    jobs: Vec<u64>,
}

impl Outbox {
    /// PspSendJobNotification(Job, Message, Context, Quota): o pacote vai
    /// para a porta associada (CompletionKey, ApcContext = Context, Status 0,
    /// Information = a mensagem); CompletionCount sobe a cada pacote
    /// entregue. Chamado com a [`JOBS`].
    pub(crate) fn notify(&mut self, job: &Ejob, message: u32, context: u64, quota: bool) {
        let port = job.completion_port.get();
        if port == 0 {
            return;
        }
        if dispatcher_objects::reference(port).is_err() {
            return;
        }
        object_header::reference(job.address(), 1);
        self.notifications.push((job.address(), port, job.completion_key.get(), message, context, quota));
    }

    /// A notificação se o filtro do job deixa passar a mensagem (`bit`: o
    /// bit de CompletionFilter que o NT testa para ela).
    pub(crate) fn notify_filtered(&mut self, job: &Ejob, bit: u32, message: u32, context: u64, quota: bool) {
        if job.completion_port.get() != 0 && job.completion_filter.get() & (1 << bit) != 0 {
            self.notify(job, message, context, quota);
        }
    }

    /// Uma referência de job para soltar depois.
    pub(crate) fn release_job(&mut self, job: u64) {
        self.jobs.push(job);
    }

    /// Entrega tudo, já fora da [`JOBS`].
    pub(crate) fn deliver(self) {
        for (job, port, key, message, context, quota) in self.notifications {
            if matches!(crate::ntos::io::completion::set::post(port, key, context, 0, message as u64, quota as u64, 0), Ok(0)) {
                ejob(job).completion_count.atomic().fetch_add(1, Ordering::SeqCst);
            }
            let _ = dispatcher_objects::dereference(port);
            object_header::dereference(job, true);
        }
        for job in self.jobs {
            dereference_job(job);
        }
    }
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
    let root = ejob(first_job).root_job.get();
    if root == ejob(second_job).root_job.get() { root } else { 0 }
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
