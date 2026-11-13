//! Conjuntos de propriedades de thread e de job — ntoskrnl 19041
//! PsSetThreadProperty 0x2efc70, PsGetThreadProperty 0x2efe20,
//! PsSetJobProperty 0x5813f0, PsGetJobProperty 0x2f0020 e os internos
//! PspValidateThread 0x2efcb0, PspInsertProperty 0x2efd30,
//! PspRemoveProperty 0x2efb98, PspFindPropertySetEntry 0x2f01a8,
//! PspGetJobProperty 0x2f0084.
//!
//! No NT o conjunto é um _PS_PROPERTY_SET embutido no objeto (ETHREAD+0x5C8,
//! EJOB+0x500: LIST_ENTRY + KSPIN_LOCK) com entradas de pool 'PsPp'
//! {LIST_ENTRY, Key, Value}. O valor é sempre um objeto do Ob: a inserção o
//! referencia com a tag 'PsPr', a remoção solta essa referência, e a leitura
//! devolve o objeto com uma referência nova que o chamador libera. O OpenNT
//! guarda o conjunto numa tabela lateral indexada pelo corpo dono, sob um
//! spin lock, com a mesma semântica (chave única, inserção na cabeça).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::ntos::inc::types::{Ejob, Eprocess, Ethread, Kpcr, Kprcb, NtStruct};
use crate::ntos::ke::{irql, pcr};
use crate::ntos::ob::{get_object_type, object_types};
use crate::ntos::ps::process;
use crate::rtl::SpinLock;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
/// Tag da referência que a entrada mantém no valor ('PsPr').
const PROPERTY_REFERENCE_TAG: u32 = 0x7250_7350;
/// ETHREAD.Silo == -3: a thread herda o job do processo.
const THREAD_SILO_INHERIT: u64 = (-3i64) as u64;
/// PsGetThreadProperty: bit 0 = não consultar o job; os demais são inválidos.
const THREAD_PROPERTY_NO_JOB_FALLBACK: u32 = 1;

/// Conjunto por corpo dono: (Key, Value), a entrada mais nova primeiro.
static SETS: SpinLock<BTreeMap<u64, Vec<(u64, u64)>>> = SpinLock::new(BTreeMap::new());

fn reference(object: u64) {
    let _ = crate::ntos::ob::object_reference::reference_with_tag(object, PROPERTY_REFERENCE_TAG, true);
}

fn dereference(object: u64) {
    let _ = crate::ntos::ob::object_reference::dereference_with_tag(object, PROPERTY_REFERENCE_TAG, true);
}

/// PspInsertProperty: chave repetida = STATUS_OBJECT_NAME_COLLISION; a
/// entrada nova entra na cabeça e referencia o valor.
fn insert(owner: u64, key: u64, value: u64) -> u32 {
    let mut sets = SETS.lock();
    let set = sets.entry(owner).or_default();
    if set.iter().any(|&(existing, _)| existing == key) {
        return STATUS_OBJECT_NAME_COLLISION;
    }
    set.insert(0, (key, value));
    drop(sets);
    reference(value);
    0
}

/// PspRemoveProperty: retira a entrada (se houver) e solta a referência do
/// valor; sempre STATUS_SUCCESS.
fn remove(owner: u64, key: u64) -> u32 {
    let removed = {
        let mut sets = SETS.lock();
        let Some(set) = sets.get_mut(&owner) else { return 0 };
        let removed = set.iter().position(|&(existing, _)| existing == key).map(|index| set.remove(index).1);
        if set.is_empty() {
            sets.remove(&owner);
        }
        removed
    };
    if let Some(value) = removed {
        dereference(value);
    }
    0
}

/// PspFindPropertySetEntry + referência ao valor encontrado.
fn find_referenced(owner: u64, key: u64) -> Option<u64> {
    let value = SETS.lock().get(&owner).and_then(|set| set.iter().find(|&&(existing, _)| existing == key).map(|&(_, value)| value))?;
    reference(value);
    Some(value)
}

fn object_type_is(body: u64, object_type: Option<u64>) -> bool {
    object_type.is_some_and(|expected| get_object_type::get(body).ok() == Some(expected))
}

fn is_thread(body: u64) -> bool {
    object_type_is(body, Some(object_types::thread_type().pointer))
}

/// O OpenNT só tem tipo Job quando algum job foi criado; sem tipo, nenhum
/// corpo é job.
fn is_job(body: u64) -> bool {
    object_type_is(body, object_types::by_name("Job").map(|object_type| object_type.pointer))
}

fn below_dispatch() -> bool {
    irql::get_irql() < irql::DISPATCH_LEVEL
}

/// KPRCB.IdleThread do processador corrente (KPCR.CurrentPrcb).
fn current_idle_thread() -> u64 {
    // SAFETY: a KPCR está mapeada desde `pcr::init` e CurrentPrcb aponta para
    // a KPRCB embutida nela.
    unsafe { Kprcb::at(Kpcr::at(pcr::get_pcr_address()).current_prcb.get()) }.idle_thread.get()
}

/// PspValidateThread: a thread ociosa e a thread corrente dentro de uma DPC
/// (DpcRequestSummary & 0x10001) não têm conjunto (STATUS_NOT_SUPPORTED);
/// abaixo de DISPATCH_LEVEL o corpo precisa ser do tipo Thread.
fn validate_thread(thread: u64) -> u32 {
    if thread == current_idle_thread() {
        return STATUS_NOT_SUPPORTED;
    }
    if below_dispatch() && !is_thread(thread) {
        return STATUS_INVALID_PARAMETER;
    }
    if thread == process::get_current_thread() && pcr::get_dpc_request_summary() & 0x10001 != 0 {
        return STATUS_NOT_SUPPORTED;
    }
    0
}

/// PsSetThreadProperty(Thread, Key, Value): Value NULL remove a chave.
pub fn set_thread_property(thread: u64, key: u64, value: u64) -> u32 {
    let status = validate_thread(thread);
    if status != 0 {
        return status;
    }
    if value == 0 {
        remove(thread, key)
    } else {
        insert(thread, key, value)
    }
}

/// PsSetJobProperty(Job, Key, Value): abaixo de DISPATCH_LEVEL o corpo
/// precisa ser do tipo Job.
pub fn set_job_property(job: u64, key: u64, value: u64) -> u32 {
    if below_dispatch() && !is_job(job) {
        return STATUS_INVALID_PARAMETER;
    }
    if value == 0 {
        remove(job, key)
    } else {
        insert(job, key, value)
    }
}

/// PspGetJobProperty: procura no job e sobe pela cadeia de ParentJob.
fn job_property_in_chain(mut job: u64, key: u64) -> u64 {
    while job != 0 {
        if let Some(value) = find_referenced(job, key) {
            return value;
        }
        // SAFETY: só corpos de job chegam aqui (PsGetJobProperty valida o
        // tipo abaixo de DISPATCH_LEVEL; ParentJob encadeia EJOBs vivos).
        job = unsafe { Ejob::at(job) }.parent_job.get();
    }
    0
}

/// PsGetJobProperty(Job, Key): objeto referenciado ou NULL.
pub fn get_job_property(job: u64, key: u64) -> u64 {
    if below_dispatch() && !is_job(job) {
        return 0;
    }
    job_property_in_chain(job, key)
}

/// PsGetThreadProperty(Thread, Key, Flags): objeto referenciado ou NULL.
/// Sem a chave na thread e sem o bit 0 de Flags, consulta o job efetivo
/// (ETHREAD.Silo, ou EPROCESS.Job quando Silo == -3).
pub fn get_thread_property(thread: u64, key: u64, flags: u32) -> u64 {
    if flags & !THREAD_PROPERTY_NO_JOB_FALLBACK != 0 || validate_thread(thread) != 0 {
        return 0;
    }
    if let Some(value) = find_referenced(thread, key) {
        return value;
    }
    if flags & THREAD_PROPERTY_NO_JOB_FALLBACK != 0 {
        return 0;
    }
    // SAFETY: validate_thread aceitou o corpo como ETHREAD vivo.
    let ethread = unsafe { Ethread::at(thread) };
    let mut job = ethread.silo.get();
    if job == THREAD_SILO_INHERIT {
        // SAFETY: KTHREAD.Process aponta para o EPROCESS dono, vivo.
        job = unsafe { Eprocess::at(ethread.tcb.process.get()) }.job.get();
    }
    if job == 0 {
        0
    } else {
        get_job_property(job, key)
    }
}

/// Limpeza do conjunto quando o dono é destruído (o NT esvazia o
/// _PS_PROPERTY_SET na deleção do ETHREAD/EJOB).
pub fn clear(owner: u64) {
    let removed = SETS.lock().remove(&owner).unwrap_or_default();
    for (_, value) in removed {
        dereference(value);
    }
}
