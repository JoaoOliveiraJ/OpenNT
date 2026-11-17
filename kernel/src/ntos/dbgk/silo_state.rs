//! O estado de silo do Dbgk na fase 1 (o DbgkpInitializePhase1SiloState do
//! silo hospedeiro, chamado pelo DbgkpInitializePhase1).
//!
//! O DbgkpCreateNotificationEvent cria o evento de notificação
//! `\KernelObjects\SystemErrorPortReady`, não sinalizado, por um
//! ZwCreateEvent de modo kernel (EVENT_ALL_ACCESS, OBJ_PERMANENT |
//! OBJ_KERNEL_HANDLE) com um descritor só com DACL, nesta ordem:
//!
//! - SeLocalSid, SeAllAppPackagesSid e o SID da capability
//!   `lpacInstrumentation` (o RtlDeriveCapabilitySidsFromName): 0x120001
//!   (SYNCHRONIZE | READ_CONTROL | EVENT_QUERY_STATE);
//! - SeLocalSystemSid: EVENT_ALL_ACCESS (0x1F0003);
//! - SeWorldSid: 0x120001.
//!
//! O silo guarda uma referência ao evento (EVENT_MODIFY_STATE) e fecha o
//! handle. O evento é sinalizado quando a porta de erros do WER é
//! registrada (DbgkRegisterErrorPort); o winsrvext.dll do csrss o abre.

use alloc::vec;
use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager;
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::se::capability::identifiers;
use crate::ntos::se::model::{sid, Ace, SecurityPolicy};
use crate::rtl::KernelError;

pub const SYSTEM_ERROR_PORT_READY: &str = "\\KernelObjects\\SystemErrorPortReady";

const QUERY_AND_SYNCHRONIZE: u32 = 0x12_0001;
const EVENT_ALL_ACCESS: u32 = 0x1F_0003;
const NOTIFICATION_EVENT: u32 = 0;
const DACL_SECURITY_INFORMATION: u32 = 4;

/// A DACL do DbgkpCreateNotificationEvent, na ordem das ACEs.
pub fn notification_dacl() -> Vec<Ace> {
    vec![
        Ace::allow(sid(2, &[0]), QUERY_AND_SYNCHRONIZE),
        Ace::allow(sid(15, &[2, 1]), QUERY_AND_SYNCHRONIZE),
        Ace::allow(identifiers::capability_sid("lpacInstrumentation"), QUERY_AND_SYNCHRONIZE),
        Ace::allow(sid(5, &[18]), EVENT_ALL_ACCESS),
        Ace::allow(sid(1, &[0]), QUERY_AND_SYNCHRONIZE),
    ]
}

/// DbgkpInitializePhase1SiloState do silo hospedeiro: cria o evento uma vez.
/// O descritor do objeto sai do SeAssignSecurity do ObInsertObject: a DACL
/// explícita e o dono e o grupo do token do System.
pub fn initialize_phase1() -> Result<(), KernelError> {
    if object_manager::lookup(SYSTEM_ERROR_PORT_READY).is_some() {
        return Ok(());
    }
    let explicit = SecurityPolicy { dacl: Some(notification_dacl()), ..SecurityPolicy::default() };
    let bytes = crate::ntos::se::object_security::encode(&explicit, DACL_SECURITY_INFORMATION);
    let descriptor = guest::alloc_bytes(bytes.len() as u64);
    if descriptor == 0 {
        return Err(KernelError::with_status("SystemErrorPortReady: sem memoria", 0xC000_009A));
    }
    guest::write_bytes(descriptor, &bytes);
    let parent = object_manager::lookup("\\KernelObjects");
    let assigned = crate::ntos::ob::object_security::assign_new(&crate::ntos::ob::object_types::event_type(), parent, descriptor, false);
    guest::free_bytes(descriptor);
    let policy = assigned.map_err(|status| KernelError::with_status("SystemErrorPortReady: SeAssignSecurity", status))?;
    let event = crate::ntos::ps::user::events::create_kernel_event(SYSTEM_ERROR_PORT_READY, NOTIFICATION_EVENT, false)?;
    dispatcher_objects::set_security(event.pointer, policy);
    Ok(())
}
