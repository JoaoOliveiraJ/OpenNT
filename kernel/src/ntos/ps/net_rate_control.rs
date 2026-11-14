//! Host de extensão do controle de taxa de rede por job
//! (PspNetRateControlExtensionHost, id 4), que a pilha TCP/IP preenche com
//! ExRegisterExtension (o proxy de QoS do tcpip.sys).
//!
//! Como o PspInitializeNetRateControl (ntoskrnl 19041 rva 0xa47e04), na fase
//! 1: id 4, versão 1, uma função, PagedPool (1), sem tabela do host nem
//! rotina de notificação.

use core::sync::atomic::{AtomicU64, Ordering::SeqCst};

use crate::ntos::ex::extension_host::{self, HostParameters};
use crate::rtl::KernelError;

/// PspNetRateControlExtensionHost.
static HOST: AtomicU64 = AtomicU64::new(0);

const NET_RATE_CONTROL: HostParameters = HostParameters { extension_id: 4, extension_version: 1, function_count: 1, pool_type: 1, host_table: 0, notification_routine: 0, notification_context: 0 };

/// PspInitializeNetRateControl.
pub fn initialize() -> Result<(), KernelError> {
    HOST.store(extension_host::register_host(&NET_RATE_CONTROL)?.unwrap_or(0), SeqCst);
    Ok(())
}

/// O host do controle de taxa de rede (0 sem registro).
pub fn host() -> u64 {
    HOST.load(SeqCst)
}
