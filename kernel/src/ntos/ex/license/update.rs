//! ExUpdateLicenseData (ntoskrnl 19041, 0x6a6780): com o provedor
//! alternativo de g_kernelCallbacks (+0x190) registrado, a chamada vai para
//! ele; senão para o SLUpdateLicenseDataInternal do contexto de licença do
//! server silo corrente (ESERVERSILO_GLOBALS->ExpLicenseState, o do
//! hospedeiro fora de silos). O OpenNT não registra o provedor alternativo;
//! a publicação mora em `boot.rs::update`.

use crate::ntos::ex::license::{boot, values};
use crate::rtl::KernelError;

/// ExUpdateLicenseData(Size, Buffer) -> NTSTATUS.
pub fn update_license_data(size: u32, buffer: u64) -> Result<u32, KernelError> {
    boot::update(values::current_context()?, buffer, size)
}
