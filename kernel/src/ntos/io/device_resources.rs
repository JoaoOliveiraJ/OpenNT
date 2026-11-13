//! CM_RESOURCE_LIST de cada PDO.
//!
//! Registro (ponteiro do PDO -> lista) para APIs que derivam a configuração
//! de hardware do dispositivo: o IoConnectInterruptEx LINE_BASED acha a IRQ
//! aqui (o que o NT resolve pelo devnode e pelos árbitros de recurso).

use alloc::collections::BTreeMap;

use crate::ntos::inc::types::{CmPartialResourceDescriptor, CmResourceList, NtStruct};
use crate::rtl::SpinLock;

const CM_RESOURCE_TYPE_INTERRUPT: u8 = 2;

/// PDO -> CM_RESOURCE_LIST (ponteiros inteiros de 64 bits).
struct Registry {
    resources: BTreeMap<u64, u64>,
    /// Interrupções já consumidas por conexões LINE_BASED (o ataport conecta
    /// uma por canal IDE, na ordem declarada pelo bus).
    consumed: BTreeMap<u64, u32>,
}

static REGISTRY: SpinLock<Registry> = SpinLock::new(Registry { resources: BTreeMap::new(), consumed: BTreeMap::new() });

pub fn register_device_resources(device: u64, resource_list: u64) {
    REGISTRY.lock().resources.insert(device, resource_list);
}

pub fn lookup_resource_list(device: u64) -> u64 {
    REGISTRY.lock().resources.get(&device).copied().unwrap_or(0)
}

/// Interrupção LINE_BASED: nível, vetor e flags do descritor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interrupt {
    pub level: u32,
    pub vector: u32,
    pub flags: u16,
}

/// Consome o próximo descritor INTERRUPT da lista do PDO.
pub fn consume_next_interrupt(device: u64) -> Option<Interrupt> {
    let list = lookup_resource_list(device);
    if list == 0 {
        return None;
    }
    // List[0].PartialResourceList (a lista do PDO tem um descritor completo).
    // SAFETY: CM_RESOURCE_LIST registrada para o PDO, viva enquanto ele existir.
    let partial = &unsafe { CmResourceList::at(list) }.list[0].partial_resource_list;
    let count = partial.count.get();
    let first = partial.partial_descriptors[0].address();
    let consumed = REGISTRY.lock().consumed.get(&device).copied().unwrap_or(0);
    let mut interrupt_index = 0;
    for index in 0..count as u64 {
        // SAFETY: descritores consecutivos (#pragma pack(4)) da lista parcial.
        let descriptor = unsafe { CmPartialResourceDescriptor::at(first + index * CmPartialResourceDescriptor::SIZE) };
        if descriptor.type_.get() != CM_RESOURCE_TYPE_INTERRUPT {
            continue;
        }
        let current = interrupt_index;
        interrupt_index += 1;
        if current != consumed {
            continue;
        }
        REGISTRY.lock().consumed.insert(device, consumed + 1);
        let interrupt = &descriptor.u.interrupt;
        return Some(Interrupt { level: interrupt.level.get() as u32, vector: interrupt.vector.get(), flags: descriptor.flags.get() });
    }
    None
}
