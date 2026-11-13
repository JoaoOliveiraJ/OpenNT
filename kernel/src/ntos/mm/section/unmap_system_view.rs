//! MmUnmapViewInSystemSpace.
//!
//! Remove vistas globais reais de seção; não usa o contrato de handles do
//! ZwUnmapViewOfSection. Endereço sem vista = bugcheck 0xD7
//! (DRIVER_UNMAPPING_INVALID_VIEW) com os parâmetros documentados.

use crate::ntos::ke::{bugcheck, irql};
use crate::ntos::ps::user::sections;
use crate::rtl::KernelError;

pub fn unmap(address: u64) -> Result<u32, KernelError> {
    if irql::get_irql() > 1 {
        return Err(KernelError::new("system view removal above APC_LEVEL"));
    }
    let Some(view) = sections::system_views().into_iter().find(|candidate| address >= candidate.base && address < candidate.base + candidate.size) else {
        bugcheck::bug_check_ex(0xD7, address, 1, 0, 0)
    };
    sections::unmap(&view, None)?;
    Ok(0)
}
