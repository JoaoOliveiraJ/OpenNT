//! Preparação e consulta do contexto de ProductPolicy.
//!
//! O dono conserva os blobs vivos até destruir o contexto e o registro de
//! estado.

use crate::ntos::ex::license::{data as license_data, index as license_index, state as license_state};
use crate::ntos::ex::push_lock;
use crate::ntos::ke::critical_region;
use crate::rtl::KernelError;
use super::layout::{self, context_at, header_at};
use crate::ntos::inc::field::NtStruct;

pub const DESCRIPTOR_CAPACITY: u32 = layout::DESCRIPTOR_CAPACITY as u32;
const STATUS_DATA_ERROR: u32 = 0xC000_003E;
const STATUS_NAME_NOT_FOUND: u32 = 0xC000_0034;

/// Corpo crítico sob o EX_PUSH_LOCK de política do contexto.
fn locked<T>(context: u64, exclusive: bool, operation: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
    let lock = context_at(context).policy_lock.address();
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
        if context_at(context).corrupt.get() != 0 {
            return Ok(Some(STATUS_DATA_ERROR));
        }
        if context_at(context).index_built.get() != 0 {
            return Ok(Some(if context_at(context).descriptor_count.get() != 0 { 0 } else { STATUS_NAME_NOT_FOUND }));
        }
        Ok(None)
    })?;
    if let Some(status) = current {
        return Ok(status);
    }
    let mut newly_corrupt = false;
    let status = locked(context, true, || {
        // Outra thread pode ter terminado a montagem: devolve zero.
        if context_at(context).index_built.get() == 1 {
            return Ok(0);
        }
        let mut blob = context_at(context).primary.get();
        if blob != 0 {
            let header = license_index::validate_header(context);
            if header & 0x8000_0000 != 0 {
                return Ok(header);
            }
        } else {
            blob = context_at(context).view.get();
        }
        if blob != 0 {
            if header_at(blob).flags.get() & 1 != 0 {
                license_state::set_context_state(context, 2)?;
            }
            let mut result = 0;
            if context_at(context).descriptor_count.get() == 0 {
                result = license_index::build(blob, 1, context_at(context).descriptor_array(), DESCRIPTOR_CAPACITY, context_at(context).descriptor_count.address());
            }
            if result & 0x8000_0000 == 0 {
                let count = context_at(context).descriptor_count.get();
                if count != 0 {
                    license_index::sort(context_at(context).descriptor_array(), count);
                }
                context_at(context).index_built.set(1);
                return Ok(if count != 0 { 0 } else { STATUS_NAME_NOT_FOUND });
            }
            if result != 0xC000_0023 {
                return Ok(result);
            }
        }
        context_at(context).corrupt.set(1);
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
        if context_at(context).index_built.get() == 1 && context_at(context).descriptor_count.get() == 0 {
            return Ok(STATUS_NAME_NOT_FOUND);
        }
        let mut blob = context_at(context).primary.get();
        if blob == 0 {
            blob = context_at(context).view.get();
        }
        if blob == 0 {
            return Ok(STATUS_DATA_ERROR);
        }
        let size = header_at(blob).total_size.get();
        if size == 24 {
            return Ok(STATUS_NAME_NOT_FOUND);
        }
        if size < 24 {
            return Ok(STATUS_DATA_ERROR);
        }
        Ok(license_data::query_native_index(context, name, type_pointer, buffer, capacity, length_pointer))
    })
}
