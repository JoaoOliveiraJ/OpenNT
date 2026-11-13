//! CM_RESOURCE_LIST de cada PDO.
//!
//! Registro (ponteiro do PDO -> lista) para APIs que derivam a configuração
//! de hardware do dispositivo: o IoConnectInterruptEx LINE_BASED acha a IRQ
//! aqui (o que o NT resolve pelo devnode e pelos árbitros de recurso). As
//! chaves são os 32 bits baixos do ponteiro, como no original.

use alloc::collections::BTreeMap;

use crate::rtl::SpinLock;
use crate::ntos::mm::guest_memory as guest;

const PARTIAL_DESCRIPTOR_SIZE: u64 = 20;
const CM_RESOURCE_TYPE_INTERRUPT: u8 = 2;

struct Registry {
    resources: BTreeMap<u32, u32>,
    /// Interrupções já consumidas por conexões LINE_BASED (o ataport conecta
    /// uma por canal IDE, na ordem declarada pelo bus).
    consumed: BTreeMap<u32, u32>,
}

static REGISTRY: SpinLock<Registry> = SpinLock::new(Registry { resources: BTreeMap::new(), consumed: BTreeMap::new() });

pub fn register_device_resources(device: u64, resource_list: u64) {
    REGISTRY.lock().resources.insert(device as u32, resource_list as u32);
}

pub fn lookup_resource_list(device: u64) -> u64 {
    REGISTRY.lock().resources.get(&(device as u32)).copied().unwrap_or(0) as u64
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
    let count = guest::read32(list + 16);
    let consumed = REGISTRY.lock().consumed.get(&(device as u32)).copied().unwrap_or(0);
    let mut interrupt_index = 0;
    for index in 0..count as u64 {
        let descriptor = list + 20 + index * PARTIAL_DESCRIPTOR_SIZE;
        if guest::read8(descriptor) != CM_RESOURCE_TYPE_INTERRUPT {
            continue;
        }
        let current = interrupt_index;
        interrupt_index += 1;
        if current != consumed {
            continue;
        }
        REGISTRY.lock().consumed.insert(device as u32, consumed + 1);
        return Some(Interrupt { level: guest::read32(descriptor + 4), vector: guest::read32(descriptor + 8), flags: guest::read16(descriptor + 2) });
    }
    None
}
