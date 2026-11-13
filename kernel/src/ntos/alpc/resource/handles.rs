//! Tabela de recursos ALPC.
//!
//! Seções, contextos e reservas ocupam a mesma tabela da comunicação: o
//! listener tem a sua; os endpoints cliente/servidor compartilham a da
//! comunicação. A referência usa os 32 bits baixos sem remover tags.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use crate::ntos::alpc::port_sections::SectionRecord;
use crate::ntos::alpc::resource::reserves::Reserve;
use crate::ntos::alpc::security_contexts::ContextRecord;
use crate::ntos::ob::objects::port::{Port, Role};
use crate::rtl::SpinLock;

#[derive(Clone)]
pub enum Resource {
    Section(Arc<SectionRecord>),
    Security(Arc<ContextRecord>),
    Reserve(Arc<Reserve>),
}

pub type ResourceTable = Arc<SpinLock<BTreeMap<u32, Resource>>>;

pub fn new_table() -> ResourceTable {
    Arc::new(SpinLock::new(BTreeMap::new()))
}

/// Estado compartilhado pelos endpoints de uma comunicação.
pub struct Communication {
    pub resources: ResourceTable,
}

impl Default for Communication {
    fn default() -> Self {
        Communication { resources: new_table() }
    }
}

pub fn table_for(port: &Arc<Port>) -> ResourceTable {
    if port.with(|state| state.role == Role::Listener) {
        return port.own_resources.clone();
    }
    port.with(|state| state.communication.get_or_insert_with(|| Arc::new(Communication::default())).resources.clone())
}

pub fn available(table: &ResourceTable) -> Option<u32> {
    let table = table.lock();
    let mut handle: u64 = 0x10;
    while table.contains_key(&(handle as u32)) && handle <= 0xFFFF_FFFF {
        handle += 1;
    }
    (handle <= 0xFFFF_FFFF).then_some(handle as u32)
}

pub fn find(port: &Arc<Port>, handle: u64) -> Option<Resource> {
    let index = handle as u32;
    let table = if port.with(|state| state.role == Role::Listener) { Some(port.own_resources.clone()) } else { port.with(|state| state.communication.as_ref().map(|communication| communication.resources.clone())) };
    table.and_then(|table| table.lock().get(&index).cloned())
}
