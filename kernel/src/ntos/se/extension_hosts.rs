//! Hosts de extensão do Se: a tabela de autorização (SepAuthExtensionHost,
//! id 2), que o ksecdd.sys preenche, e a de BCrypt (SepBCryptExtensionHost,
//! id 3), que o cng.sys preenche, ambas por ExRegisterExtension.
//!
//! Como o SepInitializeAuthorizationCallbacks (ntoskrnl 19041 rva 0xa47e64),
//! chamado na fase 1 antes dos drivers de boot: autorização = id 2, versão
//! 1, 6 funções, PagedPool (1); BCrypt = id 3, versão 1, 0x24 funções,
//! NonPagedPoolNx (0x200); nenhum dos dois tem tabela do host nem rotina de
//! notificação. Um registro que falha deixa a célula do host zerada.

use core::sync::atomic::{AtomicU64, Ordering::SeqCst};

use crate::ntos::ex::extension_host::{self, HostParameters};
use crate::rtl::KernelError;

/// SepAuthExtensionHost.
static AUTHORIZATION_HOST: AtomicU64 = AtomicU64::new(0);
/// SepBCryptExtensionHost.
static BCRYPT_HOST: AtomicU64 = AtomicU64::new(0);

const AUTHORIZATION: HostParameters = HostParameters { extension_id: 2, extension_version: 1, function_count: 6, pool_type: 1, host_table: 0, notification_routine: 0, notification_context: 0 };
const BCRYPT: HostParameters = HostParameters { extension_id: 3, extension_version: 1, function_count: 0x24, pool_type: 0x200, host_table: 0, notification_routine: 0, notification_context: 0 };

/// SepInitializeAuthorizationCallbacks.
pub fn initialize_authorization_callbacks() -> Result<(), KernelError> {
    AUTHORIZATION_HOST.store(extension_host::register_host(&AUTHORIZATION)?.unwrap_or(0), SeqCst);
    BCRYPT_HOST.store(extension_host::register_host(&BCRYPT)?.unwrap_or(0), SeqCst);
    Ok(())
}

/// O host da tabela de autorização (0 sem registro).
pub fn authorization_host() -> u64 {
    AUTHORIZATION_HOST.load(SeqCst)
}

/// O host da tabela de BCrypt (0 sem registro).
pub fn bcrypt_host() -> u64 {
    BCRYPT_HOST.load(SeqCst)
}

/// LsaFreeReturnBuffer(Buffer) (ntoskrnl 19041 rva 0x666530): a terceira
/// função da tabela de autorização, sob o rundown do host, devolve o status
/// dela; sem extensão registrada, STATUS_NOT_IMPLEMENTED.
pub fn free_return_buffer(buffer: u64) -> Result<u32, KernelError> {
    const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
    let host = authorization_host();
    let table = extension_host::get_extension_table(host)?;
    if table == 0 {
        return Ok(STATUS_NOT_IMPLEMENTED);
    }
    let routine = crate::ntos::mm::guest_memory::read64(table + 0x10);
    let status = crate::hal::amd64::native_call::call(routine, &[buffer]) as u32;
    extension_host::release_extension_table(host)?;
    Ok(status)
}
