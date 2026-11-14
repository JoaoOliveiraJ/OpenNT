//! Referências a processo e seção por handle.
//!
//! Resolve na tabela do chamador antes de anexar a qualquer alvo: o
//! pseudo-handle do processo corrente, handles abertos por ponteiro, handles
//! de usuário do processo em execução e handles do Object Manager.

use alloc::sync::Arc;

use crate::ntos::ob::open_pointer::{self, Described};
use crate::ntos::ob::object_manager;
use crate::ntos::ob::objects::section as section_objects;
use crate::ntos::ps::process;
use crate::ntos::ps::user::sections::{self, Section};
use crate::ntos::ps::user::state;
use crate::rtl::KernelError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Process,
    Section,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Process => "Process",
            Kind::Section => "Section",
        }
    }
}

enum Release {
    Process(u64),
    Section(u64),
    Item(Described),
}

/// Corpo referenciado; `release` solta pelo mesmo dono.
pub struct Reference {
    pub pointer: u64,
    pub section: Option<Arc<Section>>,
    release: Release,
}

impl Reference {
    pub fn release(self) -> Result<(), KernelError> {
        match self.release {
            Release::Process(pointer) => process::dereference(pointer).map(|_| ()),
            Release::Section(pointer) => section_objects::dereference(pointer).map(|_| ()),
            Release::Item(item) => {
                item.dereference();
                Ok(())
            }
        }
    }

    /// Processo terminado ou saindo (PROCESS_IS_TERMINATING).
    pub fn process_terminating(&self) -> bool {
        process::with_record(self.pointer, |record| record.terminated || record.exiting).unwrap_or(false)
    }
}

fn process_reference(pointer: u64) -> Result<Reference, u32> {
    if pointer == 0 || process::reference(pointer).is_none() {
        return Err(0xC000_0008);
    }
    Ok(Reference { pointer, section: None, release: Release::Process(pointer) })
}

pub fn reference(handle: u64, kind: Kind, desired: u32, mode: u8) -> Result<Reference, u32> {
    if handle == u64::MAX {
        if kind != Kind::Process {
            return Err(0xC000_0024);
        }
        return process_reference(process::get_current_process());
    }
    if handle == u64::MAX - 1 {
        return Err(0xC000_0024);
    }
    if let Some(opened) = open_pointer::resolve(handle, mode != 0) {
        let opened = opened?;
        if opened.item.object_type.name != kind.name() {
            return Err(0xC000_0024);
        }
        if mode != 0 && desired & !opened.access != 0 {
            return Err(0xC000_0022);
        }
        opened.item.reference();
        let pointer = opened.item.pointer;
        let section = if kind == Kind::Section { sections::by_pointer(pointer) } else { None };
        return Ok(Reference { pointer, section, release: Release::Item(opened.item) });
    }
    if handle > 0x7FFF_FFFF {
        return Err(0xC000_0008);
    }
    // A referência de SECTION aceita as tags NT dos dois bits baixos.
    let handle = handle & !3;
    let current = process::get_current_process();
    let user = if state::is_user_process(current) { state::get_user_handle(handle) } else { None };
    let node = if user.is_none() { object_manager::get_object(handle as u32).and_then(object_manager::node) } else { None };
    let (kind_name, owner, access, data) = match (&user, &node) {
        (Some(entry), _) => (alloc::string::String::from(entry.kind()), entry.object.owner_process(), entry.access(), entry.object.callback_data()),
        (None, Some(node)) => {
            let data = node.data.clone().unwrap_or_default();
            (node.type_name.to_lowercase(), data.owner_process, data.access.unwrap_or(0), data)
        }
        (None, None) => return Err(0xC000_0008),
    };
    if kind_name != kind.name().to_lowercase() {
        return Err(0xC000_0024);
    }
    if owner.is_some_and(|owner| owner != current) {
        return Err(0xC000_0008);
    }
    if mode != 0 && desired & !access != 0 {
        return Err(0xC000_0022);
    }
    if kind == Kind::Section {
        let section = match &user {
            Some(entry) => entry.object.section(),
            None => sections::by_pointer(data.native_pointer),
        };
        let pointer = section.as_ref().map_or(data.native_pointer, |section| section.pointer());
        if section_objects::reference(pointer).is_none() {
            return Err(0xC000_0008);
        }
        return Ok(Reference { pointer, section, release: Release::Section(pointer) });
    }
    let pointer = if data.native_pointer != 0 { data.native_pointer } else { data.process_id.and_then(|pid| process::list_active_processes().into_iter().find(|entry| entry.pid == pid)).map_or(0, |entry| entry.address) };
    process_reference(pointer)
}
