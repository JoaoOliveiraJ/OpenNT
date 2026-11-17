//! O uso de memória de um processo: o MmQueryWorkingSetInformation e o
//! tamanho virtual (EPROCESS.VirtualSize) que o NtQueryInformationProcess
//! do ntoskrnl 19041 lê para ProcessQuotaLimits e ProcessVmCounters.
//!
//! - MmQueryWorkingSetInformation (rva 0x25bfb0), sob a trava do working set
//!   do processo: PeakWorkingSetSize (Vm+0xa0), WorkingSetLeafSize (+0x78),
//!   WorkingSetLeafPrivateSize (+0x80), MinimumWorkingSetSize (+0x70) e
//!   MaximumWorkingSetSize (+0x98), todos em páginas, devolvidos em bytes; as
//!   flags levam 1 com o MaximumWorkingSetHard e 4 com o
//!   MinimumWorkingSetHard (Vm.Flags).
//! - O working set do OpenNT é o que está mapeado na raiz do processo: as
//!   páginas residentes das regiões privadas (os frames fora do corte do
//!   working set, `mm/working_set`) e as páginas das vistas e imagens com
//!   PTE válida na raiz dele. O privado é a parte das regiões privadas.
//! - O tamanho virtual é a soma das regiões do VAD (alocações privadas,
//!   vistas e imagens), reservadas ou não, como o VirtualSize do NT.
//! - Os picos (Vm.PeakWorkingSetSize e EPROCESS.PeakVirtualSize) sobem a
//!   cada amostra: o Mm do OpenNT não os acompanha a cada mudança do VAD.
//! - O MiInitializeWorkingSetList do NT grava no processo novo os limites
//!   padrão do working set (MmMinimumWorkingSetSize e
//!   MmMaximumWorkingSetSize, 50 e 345 páginas); enquanto o EPROCESS do
//!   OpenNT tiver os campos zerados, valem esses padrões.

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::Eprocess;
use crate::ntos::mm::paging;
use crate::ntos::ps::user::memory::{PrivateRegion, Space};

const PAGE: u64 = 0x1000;
/// MmMinimumWorkingSetSize e MmMaximumWorkingSetSize padrão, em páginas.
const DEFAULT_MINIMUM_WORKING_SET: u64 = 50;
const DEFAULT_MAXIMUM_WORKING_SET: u64 = 345;
/// Flags do MmQueryWorkingSetInformation.
pub const WORKING_SET_MAXIMUM_HARD: u32 = 1;
pub const WORKING_SET_MINIMUM_HARD: u32 = 4;

/// As saídas do MmQueryWorkingSetInformation, em bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WorkingSetInformation {
    pub peak: u64,
    pub current: u64,
    pub private: u64,
    pub minimum: u64,
    pub maximum: u64,
    pub flags: u32,
}

fn eprocess(process: u64) -> &'static Eprocess {
    // SAFETY: EPROCESS retido pelo chamador (handle referenciado ou o corrente).
    unsafe { Eprocess::at(process) }
}

/// (páginas no working set, das quais privadas) do VAD do processo.
fn resident_pages(process: u64) -> (u64, u64) {
    let space = Space::of(process);
    let root = space.root();
    let (mut resident, mut private) = (0u64, 0u64);
    for region in space.regions().iter().chain(space.images().iter()) {
        if let Some(owner) = region.as_any().downcast_ref::<PrivateRegion>() {
            let state = owner.state.lock();
            let count = state.frames.keys().filter(|index| !state.paging.contains_key(index)).count() as u64;
            resident += count;
            private += count;
            continue;
        }
        let base = region.base();
        let mapped = |index: u64| root != 0 && paging::translate_in(root, base + index * PAGE) != 0;
        resident += match region.committed_pages() {
            Some(pages) => pages.into_iter().filter(|&index| mapped(index)).count() as u64,
            None => (0..region.size() / PAGE).filter(|&index| mapped(index)).count() as u64,
        };
    }
    (resident, private)
}

/// MmQueryWorkingSetInformation do processo.
pub fn query_working_set(process: u64) -> WorkingSetInformation {
    let (resident, private) = resident_pages(process);
    let vm = &eprocess(process).vm.instance;
    let peak = vm.peak_working_set_size.atomic().fetch_max(resident, core::sync::atomic::Ordering::AcqRel).max(resident);
    let minimum = match vm.minimum_working_set_size.get() {
        0 => DEFAULT_MINIMUM_WORKING_SET,
        pages => pages,
    };
    let maximum = match vm.maximum_working_set_size.get() {
        0 => DEFAULT_MAXIMUM_WORKING_SET,
        pages => pages,
    };
    let mut flags = 0;
    if vm.flags.maximum_working_set_hard() != 0 {
        flags |= WORKING_SET_MAXIMUM_HARD;
    }
    if vm.flags.minimum_working_set_hard() != 0 {
        flags |= WORKING_SET_MINIMUM_HARD;
    }
    WorkingSetInformation { peak: peak * PAGE, current: resident * PAGE, private: private * PAGE, minimum: minimum * PAGE, maximum: maximum * PAGE, flags }
}

/// (PeakVirtualSize, VirtualSize) do processo, em bytes.
pub fn virtual_size(process: u64) -> (u64, u64) {
    let space = Space::of(process);
    let size: u64 = space.regions().iter().chain(space.images().iter()).map(|region| region.size()).sum();
    let peak = eprocess(process).peak_virtual_size.atomic().fetch_max(size, core::sync::atomic::Ordering::AcqRel).max(size);
    (peak, size)
}
