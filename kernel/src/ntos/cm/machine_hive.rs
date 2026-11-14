//! Notificações de carga das hives de máquina
//! (CmRegisterMachineHiveLoadedNotification e
//! CmUnregisterMachineHiveLoadedNotification).
//!
//! Como no ntoskrnl 19041 (CmRegisterMachineHiveLoadedNotification rva
//! 0x799bd0, CmUnregisterMachineHiveLoadedNotification 0x86a010,
//! CmpMachineHiveLoadedWorkItem 0x7cb7b0, CmpNotifyMachineHiveLoaded
//! 0x3b7820): as sete hives de CmpMachineHiveList têm o ponto de montagem
//! `\REGISTRY\` + MACHINE\ ou USER\ + nome (HARDWARE, SECURITY, SOFTWARE,
//! SYSTEM, USER\.DEFAULT, SAM, OSDATA, comparados sem caixa). O registro
//! (0x28 bytes, 'CM92', PagedPool) entra na lista da hive; com a hive já
//! carregada, o work item dela (DelayedWorkQueue) é enfileirado. O work item
//! tira cada registro da lista e chama Callback(Context) uma vez, fora da
//! trava; a remoção espera um callback em curso e tira o registro da lista
//! se ele ainda não foi chamado.
//!
//! No OpenNT as hives de máquina são subárvores do registro em memória: uma
//! hive está carregada quando a chave do ponto de montagem existe. A
//! criação posterior dessa chave (observada pelo `registry::watch`) faz o
//! papel do CmpNotifyMachineHiveLoaded.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::cm::registry;
use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{ListEntry, UnicodeString};
use crate::ntos::io::work_items;
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::hal::amd64::native_call;
use crate::rtl::{KernelError, SpinLock};

const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_003A;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;

/// 'CM92', a tag dos registros e dos work items.
const CALLBACK_TAG: u32 = 0x3239_4D43;
const PAGED_POOL: u32 = 1;

/// Pontos de montagem de CmpMachineHiveList, na ordem do índice.
const MOUNT_POINTS: [&str; 7] = [
    "\\REGISTRY\\MACHINE\\HARDWARE",
    "\\REGISTRY\\MACHINE\\SECURITY",
    "\\REGISTRY\\MACHINE\\SOFTWARE",
    "\\REGISTRY\\MACHINE\\SYSTEM",
    "\\REGISTRY\\USER\\.DEFAULT",
    "\\REGISTRY\\MACHINE\\SAM",
    "\\REGISTRY\\MACHINE\\OSDATA",
];

/// O registro de notificação (0x28 bytes), devolvido como handle.
#[repr(C)]
pub struct MachineHiveCallback {
    pub list_entry: ListEntry,
    pub callback: Field<u64>,
    pub context: Field<u64>,
    pub hive_index: Field<u32>,
    /// O callback está rodando.
    pub active: Field<u8>,
    /// Ainda na lista da hive (não chamado).
    pub in_list: Field<u8>,
    /// A remoção espera o callback em curso.
    pub unregistering: Field<u8>,
    _spare: Field<u8>,
}

// SAFETY: #[repr(C)] só de células e de estruturas do NT.
unsafe impl NtStruct for MachineHiveCallback {}

const _: () = {
    assert!(core::mem::size_of::<MachineHiveCallback>() == 0x28);
    assert!(core::mem::offset_of!(MachineHiveCallback, callback) == 0x10);
    assert!(core::mem::offset_of!(MachineHiveCallback, hive_index) == 0x20);
    assert!(core::mem::offset_of!(MachineHiveCallback, active) == 0x24);
    assert!(core::mem::offset_of!(MachineHiveCallback, unregistering) == 0x26);
};

/// Estado de uma entrada de CmpMachineHiveList.
struct MachineHive {
    /// A lista de registros ainda não chamados (o LIST_ENTRY +0x98).
    pending: Vec<u64>,
    /// O work item da hive (+0xa8), alocado no primeiro uso.
    work_item: u64,
    /// Execuções pedidas do work item (+0xb0).
    requests: u32,
    /// A hive está carregada (estado +0x74 == 1).
    loaded: bool,
    /// Observador da criação do ponto de montagem.
    watch: u64,
}

static HIVES: SpinLock<[MachineHive; 7]> = SpinLock::new([const { MachineHive { pending: Vec::new(), work_item: 0, requests: 0, loaded: false, watch: 0 } }; 7]);

fn callback_at(registration: u64) -> &'static MachineHiveCallback {
    // SAFETY: só registros alocados por `register`, vivos até a remoção.
    unsafe { MachineHiveCallback::at(registration) }
}

/// CmpFindMachineHiveByMountPoint: o índice do ponto de montagem.
fn find_hive(mount_point: &str) -> Option<usize> {
    MOUNT_POINTS.iter().position(|candidate| candidate.eq_ignore_ascii_case(mount_point))
}

fn is_loaded(index: usize) -> bool {
    registry::node_by_path(MOUNT_POINTS[index]).is_some()
}

/// CmpNotifyMachineHiveLoaded: pede uma execução do work item da hive.
fn request_work_item(hive: &mut MachineHive, index: usize) {
    if hive.work_item == 0 {
        hive.work_item = guest::alloc_bytes(work_items::work_item_size());
        work_items::create_work_item(0, hive.work_item);
    }
    hive.requests += 1;
    if hive.requests == 1 {
        work_items::queue_kernel_work_item(hive.work_item, machine_hive_loaded_work_item, index as u64, None);
    }
}

/// CmpMachineHiveLoadedWorkItem: chama cada registro pendente uma vez.
fn machine_hive_loaded_work_item(_device: u64, index: u64) {
    let index = index as usize;
    loop {
        let next = {
            let mut hives = HIVES.lock();
            let hive = &mut hives[index];
            if hive.pending.is_empty() {
                hive.requests = hive.requests.saturating_sub(1);
                if hive.requests == 0 {
                    return;
                }
                continue;
            }
            let registration = hive.pending.remove(0);
            let body = callback_at(registration);
            body.active.set(1);
            body.in_list.set(0);
            registration
        };
        let body = callback_at(next);
        native_call::call(body.callback.get(), &[body.context.get()]);
        let _hives = HIVES.lock();
        body.active.set(0);
    }
}

/// A criação do ponto de montagem carrega a hive (uma vez).
fn observe_mount_point(index: usize) {
    if !is_loaded(index) {
        return;
    }
    let watch = {
        let mut hives = HIVES.lock();
        let hive = &mut hives[index];
        if hive.loaded {
            return;
        }
        hive.loaded = true;
        if !hive.pending.is_empty() {
            request_work_item(hive, index);
        }
        core::mem::take(&mut hive.watch)
    };
    if watch != 0 {
        registry::unwatch(watch);
    }
}

/// CmRegisterMachineHiveLoadedNotification(Callback, Context, MountPoint,
/// Handle*): devolve o NTSTATUS. `mount_point` e `handle` são do chamador
/// de modo kernel.
pub fn register(callback: u64, context: u64, mount_point: u64, handle: u64) -> Result<u32, KernelError> {
    if callback == 0 {
        return Ok(STATUS_INVALID_PARAMETER_1);
    }
    if mount_point == 0 {
        return Ok(STATUS_INVALID_PARAMETER_3);
    }
    if handle == 0 {
        return Ok(STATUS_INVALID_PARAMETER_4);
    }
    // SAFETY: o PCUNICODE_STRING do chamador de modo kernel.
    let name = guest_strings::read_unicode_string(unsafe { UnicodeString::at(mount_point) }.address());
    let Some(index) = find_hive(&name) else { return Ok(STATUS_OBJECT_NAME_NOT_FOUND) };
    let registration = pool_allocation::allocate_tagged(PAGED_POOL, MachineHiveCallback::SIZE, CALLBACK_TAG).unwrap_or(0);
    if registration == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    let body = callback_at(registration);
    body.list_entry.flink.set(0);
    body.list_entry.blink.set(0);
    body.callback.set(callback);
    body.context.set(context);
    body.hive_index.set(index as u32);
    body.active.set(0);
    body.unregistering.set(0);
    body._spare.set(0);
    let loaded = is_loaded(index);
    let watch_needed = {
        let mut hives = HIVES.lock();
        let hive = &mut hives[index];
        hive.pending.push(registration);
        body.in_list.set(1);
        hive.loaded |= loaded;
        if hive.loaded {
            request_work_item(hive, index);
        }
        !hive.loaded && hive.watch == 0
    };
    if watch_needed {
        let identifier = registry::watch(MOUNT_POINTS[index], Arc::new(move |_| observe_mount_point(index)));
        let mut hives = HIVES.lock();
        if hives[index].watch == 0 && !hives[index].loaded {
            hives[index].watch = identifier;
        } else {
            drop(hives);
            registry::unwatch(identifier);
        }
    }
    // SAFETY: o PVOID* Handle do chamador de modo kernel.
    unsafe { Field::<u64>::at(handle) }.set(registration);
    Ok(0)
}

/// CmUnregisterMachineHiveLoadedNotification(Handle): espera o callback em
/// curso, tira da lista um registro ainda não chamado e o libera. Handle
/// nulo não faz nada.
pub fn unregister(registration: u64) -> Result<(), KernelError> {
    if registration == 0 {
        return Ok(());
    }
    let body = callback_at(registration);
    let index = body.hive_index.get() as usize;
    loop {
        {
            let mut hives = HIVES.lock();
            if body.active.get() == 0 {
                if body.in_list.get() != 0 {
                    hives[index].pending.retain(|&candidate| candidate != registration);
                    body.in_list.set(0);
                }
                break;
            }
            body.unregistering.set(1);
        }
        // KeWaitForSingleObject(CmpMachineHiveCallbackEvent): o work item
        // avança no pump até o callback em curso voltar.
        dispatcher::pump_kernel();
    }
    pool_allocation::free(registration, 0)
}
