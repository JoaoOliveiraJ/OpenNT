//! Afinidade das threads (KeSetSystemAffinityThread e família).
//!
//! O código dos drivers roda no processador de boot; a afinidade pedida é
//! validada contra os processadores ativos da MADT e guardada por thread
//! (afinidade de usuário, afinidade de sistema e processador ideal). Um
//! conjunto sem nenhum processador ativo para o sistema com
//! INVALID_AFFINITY_SET, como o NT.

use alloc::collections::BTreeMap;

use super::{bugcheck, processor_group, smp};
use crate::ntos::inc::types::{GroupAffinity, NtStruct};
use crate::ntos::ps::process;
use crate::rtl::SpinLock;

/// INVALID_AFFINITY_SET.
const INVALID_AFFINITY_SET: u64 = 0x3;

#[derive(Clone, Copy)]
struct ThreadAffinity {
    user: u64,
    system: Option<u64>,
    ideal: u8,
}

static AFFINITIES: SpinLock<BTreeMap<u64, ThreadAffinity>> = SpinLock::new(BTreeMap::new());

fn thread_affinity(thread: u64) -> ThreadAffinity {
    AFFINITIES.lock().get(&thread).copied().unwrap_or(ThreadAffinity { user: processor_group::active_mask(), system: None, ideal: 0 })
}

fn update_affinity<T>(thread: u64, change: impl FnOnce(&mut ThreadAffinity) -> T) -> T {
    let mut affinity = thread_affinity(thread);
    let result = change(&mut affinity);
    AFFINITIES.lock().insert(thread, affinity);
    result
}

/// Só processadores ativos; um conjunto sem nenhum é INVALID_AFFINITY_SET.
fn validated_affinity(affinity: u64) -> u64 {
    let mask = affinity & processor_group::active_mask();
    if mask == 0 {
        bugcheck::bug_check_ex(INVALID_AFFINITY_SET as u32, affinity, processor_group::active_mask(), 0, 0);
    }
    mask
}

fn current_thread() -> u64 {
    process::get_current_thread()
}

/// KeSetSystemAffinityThread.
pub fn set_system_affinity_thread(affinity: u64) {
    let mask = validated_affinity(affinity);
    update_affinity(current_thread(), |state| state.system = Some(mask));
}

/// KeSetSystemAffinityThreadEx: devolve a afinidade de sistema anterior (0
/// sem afinidade de sistema).
pub fn set_system_affinity_thread_ex(affinity: u64) -> u64 {
    let mask = validated_affinity(affinity);
    update_affinity(current_thread(), |state| state.system.replace(mask).unwrap_or(0))
}

/// KeRevertToUserAffinityThread.
pub fn revert_to_user_affinity_thread() {
    update_affinity(current_thread(), |state| state.system = None);
}

/// KeRevertToUserAffinityThreadEx: afinidade 0 volta à de usuário; outra
/// vira a afinidade de sistema.
pub fn revert_to_user_affinity_thread_ex(affinity: u64) {
    let system = if affinity == 0 { None } else { Some(validated_affinity(affinity)) };
    update_affinity(current_thread(), |state| state.system = system);
}

/// KeSetSystemGroupAffinityThread: a anterior vai para PreviousAffinity
/// (opcional) com Mask 0 quando a thread não estava em afinidade de
/// sistema; só o grupo 0 existe.
pub fn set_system_group_affinity_thread(requested: u64, previous: u64) {
    // SAFETY: PGROUP_AFFINITY Affinity do driver.
    let requested = unsafe { GroupAffinity::at(requested) };
    let (mask, group) = (requested.mask.get(), requested.group.get());
    if group != 0 {
        bugcheck::bug_check_ex(INVALID_AFFINITY_SET as u32, mask, group as u64, 0, 0);
    }
    let mask = validated_affinity(mask);
    let before = update_affinity(current_thread(), |state| state.system.replace(mask));
    if previous != 0 {
        processor_group::write_group_affinity(previous, before.unwrap_or(0));
    }
}

/// KeRevertToUserGroupAffinityThread: Mask 0 volta à afinidade de usuário.
pub fn revert_to_user_group_affinity_thread(previous_affinity: u64) {
    // SAFETY: PGROUP_AFFINITY PreviousAffinity do driver.
    let mask = unsafe { GroupAffinity::at(previous_affinity) }.mask.get();
    let system = if mask == 0 { None } else { Some(validated_affinity(mask)) };
    update_affinity(current_thread(), |state| state.system = system);
}

/// KeSetAffinityThread: troca a afinidade de usuário e devolve a anterior.
pub fn set_affinity_thread(thread: u64, affinity: u64) -> u64 {
    let mask = validated_affinity(affinity);
    update_affinity(thread, |state| core::mem::replace(&mut state.user, mask))
}

/// KeSetIdealProcessorThread: devolve o processador ideal anterior; um
/// processador inexistente é ignorado.
pub fn set_ideal_processor_thread(thread: u64, processor: u8) -> u8 {
    let valid = (processor as usize) < smp::online_cpu_count();
    update_affinity(thread, |state| {
        let previous = state.ideal;
        if valid {
            state.ideal = processor;
        }
        previous
    })
}
