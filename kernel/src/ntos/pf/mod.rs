//! O prefetcher (Pf): os eventos `\KernelObjects` que o PfInitializeSuperfetch
//! cria no Phase1InitializationDiscard.
//!
//! Cada evento sai do PfpCreateEvent (ntoskrnl 19041 rva 0x7c0530):
//! ZwCreateEvent(EVENT_ALL_ACCESS, OBJ_PERMANENT | OBJ_OPENIF |
//! OBJ_KERNEL_HANDLE, não sinalizado) com um descritor só com DACL,
//! Administrators e SYSTEM com EVENT_ALL_ACCESS; o Pf guarda uma
//! referência e fecha o handle. Na ordem do PfInitializeSuperfetch:
//!
//! - `SuperfetchParametersChanged` (PfpParametersInitialize), de
//!   sincronização;
//! - `SuperfetchScenarioNotify` (PfpScenCtxStart), de notificação;
//! - `PrefetchTracesReady` (PfSnInitializePrefetcher), de sincronização.
//!
//! O `SuperfetchTracesReady` não é do boot: o PfTStart o cria quando o
//! serviço SysMain liga o rastreamento pelo NtSetSystemInformation
//! (SystemSuperfetchInformation), que o OpenNT não implementa.

pub mod prefetcher_information;

use alloc::vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager;
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::se::model::{sid, Ace, SecurityPolicy};
use crate::rtl::KernelError;

const EVENT_ALL_ACCESS: u32 = 0x1F_0003;
const NOTIFICATION_EVENT: u32 = 0;
const SYNCHRONIZATION_EVENT: u32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 4;

/// Os eventos do boot, na ordem do PfInitializeSuperfetch, com o
/// EVENT_TYPE que cada chamador passa ao PfpCreateEvent.
const BOOT_EVENTS: [(&str, u32); 3] = [
    ("\\KernelObjects\\SuperfetchParametersChanged", SYNCHRONIZATION_EVENT),
    ("\\KernelObjects\\SuperfetchScenarioNotify", NOTIFICATION_EVENT),
    ("\\KernelObjects\\PrefetchTracesReady", SYNCHRONIZATION_EVENT),
];

/// PfpCreateEvent: o evento com o descritor do Pf (OBJ_OPENIF: um nome que
/// já existe é aceito).
fn create_event(name: &str, event_type: u32) -> Result<(), KernelError> {
    if object_manager::lookup(name).is_some() {
        return Ok(());
    }
    let explicit = SecurityPolicy { dacl: Some(vec![Ace::allow(sid(5, &[32, 544]), EVENT_ALL_ACCESS), Ace::allow(sid(5, &[18]), EVENT_ALL_ACCESS)]), ..SecurityPolicy::default() };
    let bytes = crate::ntos::se::object_security::encode(&explicit, DACL_SECURITY_INFORMATION);
    let descriptor = guest::alloc_bytes(bytes.len() as u64);
    if descriptor == 0 {
        return Err(KernelError::with_status("PfpCreateEvent: sem memoria", 0xC000_009A));
    }
    guest::write_bytes(descriptor, &bytes);
    let parent = object_manager::lookup("\\KernelObjects");
    let assigned = crate::ntos::ob::object_security::assign_new(&crate::ntos::ob::object_types::event_type(), parent, descriptor, false);
    guest::free_bytes(descriptor);
    let policy = assigned.map_err(|status| KernelError::with_status("PfpCreateEvent: SeAssignSecurity", status))?;
    let event = crate::ntos::ps::user::events::create_kernel_event(name, event_type, false)?;
    dispatcher_objects::set_security(event.pointer, policy);
    Ok(())
}

/// PfInitializeSuperfetch (rva 0xa6a76c): os eventos do boot.
pub fn initialize() -> Result<(), KernelError> {
    for (name, event_type) in BOOT_EVENTS {
        create_event(name, event_type)?;
    }
    Ok(())
}
