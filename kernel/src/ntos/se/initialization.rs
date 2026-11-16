//! A parte do SepInitializationPhase1 do ntoskrnl 19041 (rva 0x79d6c8) que o
//! LSA usa: o diretório permanente `\Security` e, nele, o evento de
//! notificação permanente `LSA_AUTHENTICATION_INITIALIZED`, não sinalizado.
//! O lsass.exe abre o evento ao iniciar (e sai com STATUS_INVALID_HANDLE sem
//! ele) e o sinaliza quando a autenticação fica pronta.
//!
//! Lacuna: os descritores do NT (a DACL do diretório, com SYSTEM
//! DIRECTORY_ALL_ACCESS, Administrators 0x20003 e World DIRECTORY_TRAVERSE, e o
//! SePublicDefaultSd no evento) ficam com o descritor padrão do Object
//! Manager do OpenNT.

use crate::ntos::ob::object_manager;
use crate::rtl::KernelError;

const SECURITY_DIRECTORY: &str = "\\Security";
const LSA_AUTHENTICATION_INITIALIZED: &str = "\\Security\\LSA_AUTHENTICATION_INITIALIZED";
/// NotificationEvent.
const NOTIFICATION_EVENT: u32 = 0;

/// O diretório `\Security` e o evento `LSA_AUTHENTICATION_INITIALIZED`.
pub fn initialize_phase1() -> Result<(), KernelError> {
    if object_manager::lookup(LSA_AUTHENTICATION_INITIALIZED).is_some() {
        return Ok(());
    }
    object_manager::create_directory(SECURITY_DIRECTORY)?;
    crate::ntos::ps::user::events::create_kernel_event(LSA_AUTHENTICATION_INITIALIZED, NOTIFICATION_EVENT, false)?;
    Ok(())
}
