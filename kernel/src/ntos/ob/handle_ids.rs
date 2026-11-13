//! Espaço único de identificadores de handle.
//!
//! Handles de kernel e de usuário compartilham o espaço; registro, arquivos e
//! namespace mantêm seus próprios descritores sem reutilizar o identificador.

use crate::ntos::inc::status::STATUS_INSUFFICIENT_RESOURCES;
use crate::rtl::{KernelError, SpinLock};

/// O zero é inválido; o primeiro identificador disponível é quatro.
static NEXT: SpinLock<u32> = SpinLock::new(4);

/// Reserva um identificador alinhado em quatro bytes, respeitando o piso e os
/// slots nativos reservados (o primeiro de cada folha, inclusive 0x400).
pub fn allocate(minimum: u32) -> Result<u32, KernelError> {
    if minimum < 4 || minimum & 3 != 0 {
        return Err(KernelError::new("invalid handle allocation floor"));
    }
    let mut next = NEXT.lock();
    *next = (*next).max(minimum);
    if *next & 0x3FF == 0 {
        *next += 4;
    }
    if *next > 0x7FFF_FFFC {
        return Err(KernelError::with_status("handle ID space exhausted", STATUS_INSUFFICIENT_RESOURCES));
    }
    let handle = *next;
    *next += 4;
    Ok(handle)
}
