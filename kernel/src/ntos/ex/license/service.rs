//! Serviço de consulta de licenças.
//!
//! A ordem de preparação, callbacks e busca vem de
//! SLQueryLicenseValueInternal; nenhum erro do cache ativa um produto.

use alloc::vec::Vec;

use crate::ntos::ex::license::special::{self, Providers};
use crate::ntos::ex::license::{cache as license_cache, registry as license_registry};
use crate::ntos::ex::{pool_allocation, push_lock};
use crate::ntos::ke::critical_region;
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const FRAME_TAG: u32 = 0x7351_734C;
const VALUE_TAG: u32 = 0x2053_4C53;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_DATA_ERROR: u32 = 0xC000_003E;
const STATUS_INTERNAL_ERROR: u32 = 0xC000_00E5;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Callback {
    SessionIdentifier,
    GenuineBefore,
    State,
    RemainingTime,
    LocalHardwareIdentifier,
    ContextValue,
    ProductPfn,
    ProductContentId,
    Expiration,
    AddonPolicy,
    DeviceIdentifier,
    DeviceLocked,
}

/// Nomes contados e sensíveis a caixa; o último campo indica o lock externo
/// exigido pelo callback anterior.
const RESERVED_NAMES: [(&str, Callback, bool); 14] = [
    ("Kernel-Session-Machine-Identifier", Callback::SessionIdentifier, true),
    ("Security-SPP-GenuineLocalStatus", Callback::GenuineBefore, true),
    ("Security-SPP-Reserved-TBLState", Callback::State, true),
    ("Security-SPP-Reserved-TBLRemainingTime", Callback::RemainingTime, true),
    ("Security-SPP-Reserved-LocalHardwareId", Callback::LocalHardwareIdentifier, false),
    ("9882750d-0aa7-4801-bb9b-90ae56b7c2ab", Callback::ContextValue, true),
    ("Kernel-OsProduct-PFN", Callback::ProductPfn, false),
    ("Kernel-OsProduct-ContentId", Callback::ProductContentId, false),
    ("Kernel-ExpirationDate", Callback::Expiration, false),
    ("ConsumeAddonPolicySet", Callback::AddonPolicy, true),
    ("FDE6DEB3-F790-48FF-8F27-43461944FD3E", Callback::DeviceIdentifier, false),
    ("CE163B38-1AEC-47AF-854D-FC90ABD6951C", Callback::DeviceLocked, false),
    ("Microsoft-Reserved-24C26ACC-DE62-4303-88AD-6CD4F1447F18", Callback::DeviceLocked, false),
    ("BF319B54-49B5-412B-8CC8-FC2C003D31AF", Callback::DeviceLocked, false),
];

/// Exclusões do provedor adicional (comparação terminada em NUL, só A..Z).
const ADDON_EXCLUSIONS: [&str; 7] = [
    "Security-SPP-GenuineLocalStatus",
    "Security-SPP-Action-StateData",
    "Security-SPP-LastWindowsActivationHResult",
    "Security-SPP-LastWindowsActivationTime",
    "Kernel-ExpirationDate",
    "SMR-HostManaged-Enabled",
    "TerminalServices-RemoteConnectionManager-AllowAppServerMode",
];

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

fn move_bytes(destination: u64, source: u64, size: u32) {
    let backwards = destination > source && destination < source + size as u64;
    for index in 0..size as u64 {
        let offset = if backwards { size as u64 - index - 1 } else { index };
        guest::write8(destination + offset, guest::read8(source + offset));
    }
}

fn write_name(descriptor: u64, name: &str) {
    let units: Vec<u16> = name.encode_utf16().collect();
    guest::write16(descriptor, units.len() as u16 * 2);
    guest::write16(descriptor + 2, (units.len() as u16 + 1) * 2);
    guest::write64(descriptor + 8, descriptor + 16);
    for (index, unit) in units.iter().chain(core::iter::once(&0)).enumerate() {
        guest::write16(descriptor + 16 + index as u64 * 2, *unit);
    }
}

/// Decodifica todos os WCHARs antes de comparar cada entrada de tamanho
/// igual (as falhas de um nome em página não mapeada são observáveis).
fn find_reserved(name: u64) -> Option<(Callback, bool)> {
    let length = guest::read16(name);
    for (text, callback, needs_lock) in RESERVED_NAMES {
        if length as usize != text.encode_utf16().count() * 2 {
            continue;
        }
        let pointer = guest::read64(name + 8);
        let captured: Vec<u16> = (0..length as u64 / 2).map(|index| guest::read16(pointer + index * 2)).collect();
        if captured.iter().copied().eq(text.encode_utf16()) {
            return Some((callback, needs_lock));
        }
    }
    None
}

fn equals_counted(name: u64, text: &str) -> bool {
    let units: Vec<u16> = text.encode_utf16().collect();
    if guest::read16(name) as usize != units.len() * 2 {
        return false;
    }
    let buffer = guest::read64(name + 8);
    units.iter().enumerate().all(|(index, &unit)| guest::read16(buffer + index as u64 * 2) == unit)
}

fn excluded_addon_name(buffer: u64) -> bool {
    let fold = |value: u16| if (65..=90).contains(&value) { value + 32 } else { value };
    for text in ADDON_EXCLUSIONS {
        let expected: Vec<u16> = text.encode_utf16().collect();
        let mut index = 0usize;
        loop {
            let current = fold(guest::read16(buffer + index as u64 * 2));
            let wanted = fold(expected.get(index).copied().unwrap_or(0));
            if current != wanted {
                break;
            }
            if current == 0 {
                return true;
            }
            index += 1;
        }
    }
    false
}

/// RVA 0x94DEA8: cache de Clip-SubscriptionPFN (130 bytes no contexto).
/// Devolve (status, buffer próprio ou zero).
pub fn capture_subscription(context: u64, frame: u64) -> Result<(u32, u64), KernelError> {
    let mut allocated = 0u64;
    // `transferred` acompanha a posse do buffer: só é devolvido ao chamador
    // quando a captura chega ao fim.
    let mut transferred = false;
    let result = (|| -> Result<u32, KernelError> {
        let mut status = 0u32;
        if guest::read8(context + 0xB708) == 0 {
            write_name(frame + 16, "Clip-SubscriptionPFN");
            guest::write32(frame + 8, 0);
            status = license_cache::query(context, frame + 16, 0, 0, 0, frame + 8)?;
            let mut capacity = 0u32;
            if status == STATUS_BUFFER_TOO_SMALL {
                capacity = guest::read32(frame + 8);
                allocated = pool_allocation::allocate_tagged(1, capacity as u64, VALUE_TAG).unwrap_or(0);
                if allocated == 0 || capacity > 0x82 {
                    return Ok(STATUS_INTERNAL_ERROR);
                }
                status = license_cache::query(context, frame + 16, 0, allocated, capacity, frame + 8)?;
            }
            locked(context, true, || {
                if guest::read8(context + 0xB708) != 0 {
                    return Ok(());
                }
                if status & 0x8000_0000 == 0 {
                    move_bytes(context + 0xB70A, allocated, capacity);
                }
                if status & 0x8000_0000 == 0 || status == STATUS_NAME_NOT_FOUND {
                    guest::write8(context + 0xB708, 1);
                }
                Ok(())
            })?;
        } else {
            locked(context, false, || {
                if guest::read8(context + 0xB708) == 0 {
                    return Ok(());
                }
                allocated = pool_allocation::allocate_tagged(1, 0x82, VALUE_TAG).unwrap_or(0);
                if allocated == 0 {
                    status = STATUS_INTERNAL_ERROR;
                    return Ok(());
                }
                move_bytes(allocated, context + 0xB70A, 0x82);
                Ok(())
            })?;
        }
        transferred = true;
        Ok(status)
    })();
    if !transferred && allocated != 0 {
        let _ = kernel_pool::free(allocated, None);
        allocated = 0;
    }
    result.map(|status| (status, allocated))
}

/// Recursão de GenuineLocalStatus com uma UNICODE_STRING própria.
pub fn query_by_name(context: u64, name: &str, type_pointer: u64, buffer: u64, capacity: u32, length: u64, providers: &Providers) -> Result<u32, KernelError> {
    let units = name.encode_utf16().count() as u64;
    let Ok(frame) = kernel_pool::allocate(16 + (units + 1) * 2, AllocateOptions { zero: true, paged: true, tag: FRAME_TAG, ..Default::default() }) else { return Ok(STATUS_NO_MEMORY) };
    write_name(frame, name);
    let result = query(context, frame, type_pointer, buffer, capacity, length, providers);
    let _ = kernel_pool::free(frame, Some(FRAME_TAG));
    result
}

fn invoke(callback: Callback, context: u64, type_pointer: u64, buffer: u64, capacity: u32, length: u64, handled: u64, providers: &Providers) -> Result<u32, KernelError> {
    Ok(match callback {
        Callback::SessionIdentifier => special::query_session_identifier(context, type_pointer, buffer, capacity, length, handled),
        Callback::GenuineBefore => special::query_genuine_before(context, type_pointer, buffer, capacity, length, handled)?,
        Callback::State => special::query_state(context, type_pointer, buffer, capacity, length, handled)?,
        Callback::RemainingTime => special::query_remaining_time(context, type_pointer, buffer, capacity, length, handled)?,
        Callback::LocalHardwareIdentifier => special::query_local_hardware_identifier(),
        Callback::ContextValue => special::query_context_value(context, type_pointer, buffer, capacity, length, handled),
        Callback::ProductPfn => license_registry::query_product_pfn(type_pointer, buffer, capacity, length, handled)?,
        Callback::ProductContentId => license_registry::query_product_content_id(type_pointer, buffer, capacity, length, handled)?,
        Callback::Expiration => special::query_expiration(type_pointer, buffer, capacity, length, handled, providers.query_expiration),
        Callback::AddonPolicy => special::query_addon_policy(context, type_pointer, buffer, capacity, length, handled)?,
        Callback::DeviceIdentifier => license_registry::query_device_identifier(type_pointer, buffer, capacity, length, handled)?,
        Callback::DeviceLocked => license_registry::query_device_locked(type_pointer, buffer, capacity, length, handled)?,
    })
}

/// SLQueryLicenseValueInternal com o contexto já selecionado pelo silo.
/// Respostas dos provedores opcionais são usadas diretamente, nunca
/// substituídas por sucesso fixo.
pub fn query(context: u64, name: u64, type_pointer: u64, buffer: u64, capacity: u32, length: u64, providers: &Providers) -> Result<u32, KernelError> {
    if name == 0 || length == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if guest::read64(name + 8) == 0 || guest::read16(name) < 2 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let Ok(frame) = kernel_pool::allocate(96, AllocateOptions { zero: true, paged: true, tag: FRAME_TAG, ..Default::default() }) else { return Ok(STATUS_NO_MEMORY) };
    let mut copied_name = 0u64;
    let mut subscription = 0u64;
    let result = (|| -> Result<u32, KernelError> {
        let initialization = license_cache::prepare(context, providers.notify_corruption)?;
        let mut status = 0;
        if let Some((callback, needs_lock)) = find_reserved(name) {
            let call = || invoke(callback, context, type_pointer, buffer, capacity, length, frame, providers);
            status = if needs_lock { locked(context, false, call)? } else { call()? };
        }
        if guest::read8(frame) != 0 {
            if status & 0x8000_0000 == 0 && guest::read32(length) > capacity {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            return Ok(status);
        }
        if initialization & 0x8000_0000 != 0 {
            return Ok(initialization);
        }
        write_name(frame + 16, "ConsumeAddonPolicySet");
        status = license_cache::query(context, frame + 16, 0, frame + 4, 4, frame + 8)?;
        let mut query_cache = true;
        if let Some(addon) = providers.query_addon_policy.filter(|_| guest::read32(frame + 4) != 0 && !equals_counted(name, "Clip-SubscriptionPFN")) {
            let name_bytes = guest::read16(name) as u32 + 2;
            copied_name = pool_allocation::allocate_tagged(1, name_bytes as u64, VALUE_TAG).unwrap_or(0);
            if copied_name == 0 {
                return Ok(STATUS_NO_MEMORY);
            }
            guest::write_bytes(copied_name, &alloc::vec![0u8; name_bytes as usize]);
            move_bytes(copied_name, guest::read64(name + 8), guest::read16(name) as u32);
            if !excluded_addon_name(copied_name) {
                // O status do helper não é testado: NULL também é argumento.
                subscription = capture_subscription(context, frame)?.1;
                let addon_status = addon(subscription, 0, 0, 0, copied_name, name_bytes, buffer, capacity, length, type_pointer, 0);
                if addon_status & 0x8000_0000 == 0 || addon_status == STATUS_BUFFER_TOO_SMALL {
                    status = if capacity != 0 { addon_status } else { STATUS_BUFFER_TOO_SMALL };
                    query_cache = false;
                }
            }
        }
        if query_cache {
            status = license_cache::query(context, name, type_pointer, buffer, capacity, length)?;
            if status == STATUS_DATA_ERROR {
                locked(context, true, || {
                    guest::write8(context + 0xB790, 1);
                    Ok(())
                })?;
            }
        }
        // O nome é procurado de novo: saídas sobrepostas podem tê-lo mudado.
        if find_reserved(name).is_some_and(|(callback, _)| callback == Callback::GenuineBefore) && (status & 0x8000_0000 == 0 || status == STATUS_NAME_NOT_FOUND || status == STATUS_NOT_FOUND) {
            let recurse = |text: &str, result_type: u64, result_buffer: u64, result_capacity: u32, result_length: u64| query_by_name(context, text, result_type, result_buffer, result_capacity, result_length, providers);
            let after = special::query_genuine_after(context, type_pointer, buffer, capacity, length, frame, &recurse, providers)?;
            if guest::read8(frame) != 0 {
                status = after;
            }
        }
        Ok(status)
    })();
    if subscription != 0 {
        let _ = kernel_pool::free(subscription, None);
    }
    if copied_name != 0 {
        let _ = kernel_pool::free(copied_name, None);
    }
    let _ = kernel_pool::free(frame, Some(FRAME_TAG));
    result
}

/// Entrada Nt em KernelMode: argumentos ausentes e capacidade excessiva têm
/// erros distintos; o contexto do silo só é selecionado depois das guardas.
pub fn query_kernel(context: impl FnOnce() -> u64, name: u64, type_pointer: u64, buffer: u64, capacity: u32, length: u64, providers: &Providers) -> Result<u32, KernelError> {
    if name == 0 || length == 0 || (buffer == 0 && capacity != 0) {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if capacity > 0x80_0000 {
        return Ok(STATUS_NO_MEMORY);
    }
    let context = context();
    if let Some(query_license) = providers.query_license {
        return Ok(query_license(context, name, type_pointer, buffer, capacity, length));
    }
    query(context, name, type_pointer, buffer, capacity, length, providers)
}
