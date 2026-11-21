//! O uso de memória de um processo: o working set e o tamanho virtual que o
//! ntoskrnl 19041 guarda no EPROCESS e que três consultas leem.
//!
//! - MmQueryWorkingSetInformation (rva 0x25bfb0), sob a trava do working set
//!   do processo: PeakWorkingSetSize (Vm+0xa0), WorkingSetLeafSize (+0x78),
//!   WorkingSetLeafPrivateSize (+0x80), MinimumWorkingSetSize (+0x70) e
//!   MaximumWorkingSetSize (+0x98), todos em páginas, devolvidos em bytes; as
//!   flags levam 1 com o MaximumWorkingSetHard e 4 com o
//!   MinimumWorkingSetHard (Vm.Flags). É o que o NtQueryInformationProcess
//!   usa para ProcessQuotaLimits e ProcessVmCounters.
//! - O ExpCopyProcessInfo (rva 0x618e80) da lista de processos do
//!   NtQuerySystemInformation lê os mesmos campos direto do EPROCESS:
//!   PeakWorkingSetSize, WorkingSetLeafSize, WorkingSetLeafPrivateSize,
//!   PageFaultCount, HardFaultCount, VirtualSize e PeakVirtualSize.
//! - No NT o Mm mantém esses campos a cada página que entra ou sai do
//!   working set e a cada mudança do VAD. O OpenNT os recalcula em
//!   [`refresh`], que as duas consultas chamam antes de ler: o working set é
//!   o que está mapeado na raiz do processo (as páginas residentes das
//!   regiões privadas, os frames fora do corte do working set,
//!   `mm/working_set`, e as páginas das vistas e imagens com PTE válida na
//!   raiz dele); o privado é a parte das regiões privadas. O OpenNT não
//!   conta as tabelas de páginas no working set, então WorkingSetSize e
//!   WorkingSetPrivateSize recebem os mesmos valores das folhas. O tamanho
//!   virtual é a soma das regiões do VAD (alocações privadas, vistas e
//!   imagens), reservadas ou não, como o VirtualSize do NT. Os picos sobem a
//!   cada amostra.
//! - O MiInitializeWorkingSetList do NT grava no processo novo os limites
//!   padrão do working set (MmMinimumWorkingSetSize e
//!   MmMaximumWorkingSetSize, 50 e 345 páginas); enquanto o EPROCESS do
//!   OpenNT tiver os campos zerados, valem esses padrões.

use core::sync::atomic::Ordering;

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
    // SAFETY: EPROCESS retido pelo chamador (handle referenciado, o corrente
    // ou o da lista de processos ativos sob referência).
    unsafe { Eprocess::at(process) }
}

/// (páginas no working set, das quais privadas, bytes de VA) do VAD do
/// processo.
fn sample(process: u64) -> (u64, u64, u64) {
    let space = Space::of(process);
    let root = space.root();
    let (mut resident, mut private, mut virtual_size) = (0u64, 0u64, 0u64);
    for region in space.regions().iter().chain(space.images().iter()) {
        virtual_size += region.size();
        if let Some(owner) = region.as_any().downcast_ref::<PrivateRegion>() {
            let state = owner.state.lock();
            let count = state.frames.keys().filter(|index| !state.paging.contains_key(index)).count() as u64;
            resident += count;
            private += count;
        } else if root != 0 {
            resident += paging::count_present_in(root, region.base(), region.size());
        }
    }
    (resident, private, virtual_size)
}

/// Recalcula no EPROCESS o working set (Vm.WorkingSetLeafSize,
/// WorkingSetLeafPrivateSize, WorkingSetSize, WorkingSetPrivateSize e o pico
/// PeakWorkingSetSize, em páginas) e o tamanho virtual (VirtualSize e
/// PeakVirtualSize, em bytes) a partir do VAD.
pub fn refresh(process: u64) {
    let (resident, private, virtual_size) = sample(process);
    let object = eprocess(process);
    let vm = &object.vm.instance;
    vm.working_set_leaf_size.set(resident);
    vm.working_set_leaf_private_size.set(private);
    vm.working_set_size.set(resident);
    vm.working_set_private_size.set(private);
    vm.peak_working_set_size.atomic().fetch_max(resident, Ordering::AcqRel);
    object.virtual_size.set(virtual_size);
    object.peak_virtual_size.atomic().fetch_max(virtual_size, Ordering::AcqRel);
}

/// MmQueryWorkingSetInformation do processo (depois de [`refresh`]).
pub fn query_working_set(process: u64) -> WorkingSetInformation {
    refresh(process);
    let vm = &eprocess(process).vm.instance;
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
    WorkingSetInformation {
        peak: vm.peak_working_set_size.get() * PAGE,
        current: vm.working_set_leaf_size.get() * PAGE,
        private: vm.working_set_leaf_private_size.get() * PAGE,
        minimum: minimum * PAGE,
        maximum: maximum * PAGE,
        flags,
    }
}

/// (PeakVirtualSize, VirtualSize) do processo, em bytes, como o último
/// [`refresh`] (ou [`query_working_set`]) os deixou.
pub fn virtual_size(process: u64) -> (u64, u64) {
    let object = eprocess(process);
    (object.peak_virtual_size.get(), object.virtual_size.get())
}
