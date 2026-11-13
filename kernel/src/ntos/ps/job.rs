//! Acessores do objeto job (EJOB), como a parte de consulta do `ps\psjob.c`
//! do NT: lock, classe de restrições de UI, sessão e job raiz comum a dois
//! processos. Transcrito do ntoskrnl 19041 (PsGetJobLock 0x32cf40,
//! PsGetJobUIRestrictionsClass 0x329c10, PsGetJobSessionId 0x2017c0,
//! PsGetProcessCommonJob 0x36c530).
//!
//! O OpenNT não cria jobs (EPROCESS.Job fica NULL): os chamadores só chegam
//! aqui com corpos que eles mesmos obtiveram; nada é fabricado.

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Ejob, Eprocess};

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
