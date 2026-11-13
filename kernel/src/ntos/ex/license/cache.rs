//! Preparação e consulta do contexto de ProductPolicy — `system32/ntos/ex/license-cache.js`.
//!
//! O dono conserva os blobs vivos até destruir o contexto e o registro de
//! estado.

use crate::ntos::ex::license::{data as license_data, index as license_index, state as license_state};
use crate::ntos::ex::push_lock;
use crate::ntos::ke::critical_region;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

pub const DESCRIPTOR_CAPACITY: u32 = 0xB6D;
const STATUS_DATA_ERROR: u32 = 0xC000_003E;
const STATUS_NAME_NOT_FOUND: u32 = 0xC000_0034;

/// Corpo crítico sob o EX_PUSH_LOCK do contexto (+0xB6F8).
fn locked<T>(context: u64, exclusive: bool, operation: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
    let lock = context + 0xB6F8;
    critical_region::enter_critical()?;
    let acquired = if exclusive { push_lock::acquire_exclusive(lock, 0) } else { push_lock::acquire_shared(lock, 0) };
    let result = match acquired {
        Ok(()) => {
            let result = operation();
            let released = if exclusive { push_lock::release_exclusive(lock, 0) } else { push_lock::release_shared(lock, 0) };
            released.and(result)
        }
        Err(error) => Err(error),
    };
    let left = critical_region::leave_critical();
    let result = result?;
    left?;
    Ok(result)
}

/// Decisão inicial sob leitura e revalidação sob posse exclusiva. O
/// consumidor de telemetria de corrupção é chamado fora do lock.
pub fn prepare(context: u64, notify_corruption: Option<fn(u64)>) -> Result<u32, KernelError> {
    let current = locked(context, false, || {
        if guest::read8(context + 0xB790) != 0 {
            return Ok(Some(STATUS_DATA_ERROR));
        }
        if guest::read8(context + 0xB6EC) != 0 {
            return Ok(Some(if guest::read32(context + 0xB6E8) != 0 { 0 } else { STATUS_NAME_NOT_FOUND }));
        }
        Ok(None)
    })?;
    if let Some(status) = current {
        return Ok(status);
    }
    let mut newly_corrupt = false;
    let status = locked(context, true, || {
        // Outra thread pode ter terminado a montagem: o original devolve zero.
        if guest::read8(context + 0xB6EC) == 1 {
            return Ok(0);
        }
        let mut blob = guest::read64(context);
        if blob != 0 {
            let header = license_index::validate_header(context);
            if header & 0x8000_0000 != 0 {
                return Ok(header);
            }
        } else {
            blob = guest::read64(context + 0xB6F0);
        }
        if blob != 0 {
            if guest::read32(blob + 12) & 1 != 0 {
                license_state::set_context_state(context, 2)?;
            }
            let mut result = 0;
            if guest::read32(context + 0xB6E8) == 0 {
                result = license_index::build(blob, 1, context + 24, DESCRIPTOR_CAPACITY, context + 0xB6E8);
            }
            if result & 0x8000_0000 == 0 {
                let count = guest::read32(context + 0xB6E8);
                if count != 0 {
                    license_index::sort(context + 24, count);
                }
                guest::write8(context + 0xB6EC, 1);
                return Ok(if count != 0 { 0 } else { STATUS_NAME_NOT_FOUND });
            }
            if result != 0xC000_0023 {
                return Ok(result);
            }
        }
        guest::write8(context + 0xB790, 1);
        newly_corrupt = true;
        Ok(STATUS_DATA_ERROR)
    })?;
    if newly_corrupt {
        if let Some(notify) = notify_corruption {
            notify(context);
        }
    }
    Ok(status)
}

/// RVA 0x3B7A0C: não inicializa o cache nem consulta o flag de corrupção.
pub fn query(context: u64, name: u64, type_pointer: u64, buffer: u64, capacity: u32, length_pointer: u64) -> Result<u32, KernelError> {
    locked(context, false, || {
        if guest::read8(context + 0xB6EC) == 1 && guest::read32(context + 0xB6E8) == 0 {
            return Ok(STATUS_NAME_NOT_FOUND);
        }
        let mut blob = guest::read64(context);
        if blob == 0 {
            blob = guest::read64(context + 0xB6F0);
        }
        if blob == 0 {
            return Ok(STATUS_DATA_ERROR);
        }
        let size = guest::read32(blob);
        if size == 24 {
            return Ok(STATUS_NAME_NOT_FOUND);
        }
        if size < 24 {
            return Ok(STATUS_DATA_ERROR);
        }
        Ok(license_data::query_native_index(context, name, type_pointer, buffer, capacity, length_pointer))
    })
}
