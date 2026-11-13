//! Tratamentos especiais de SLQueryLicenseValueInternal.
//!
//! Os valores vêm do contexto, do relógio, da hive ou de um provedor
//! registrado. Os padrões são ramos medidos no kernel original, não uma
//! indicação de produto ativado.

use crate::ntos::ex::license::registry::{self as license_registry, ValueName};
use crate::ntos::ex::license::{cache as license_cache, state as license_state};
use crate::ntos::ex::{pool_allocation, push_lock};
use crate::ntos::ke::clock;
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use super::layout::{self, byte_at, context_at, ulong_at};
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const FRAME_TAG: u32 = 0x7353_6C54;
const VALUE_TAG: u32 = 0x2053_4C53;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;

/// Moldura de pool do GenuineLocalStatus posterior: o DWORD de
/// IgnoreDeferredActivation, a saída da ativação adiada, os tamanhos
/// devolvidos, o indicador "tratado" e as flags da verificação.
#[repr(C)]
struct GenuineFrame {
    ignore_deferred: Field<u32>,
    deferred_activation: Field<u32>,
    value_length: Field<u32>,
    policy_size: Field<u32>,
    handled: Field<u8>,
    _pad_11: Reserved<0xF>,
    verify_flags: Field<u8>,
    _pad_21: Reserved<0x1F>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for GenuineFrame {}

const _: () = {
    assert!(core::mem::size_of::<GenuineFrame>() == 64);
    assert!(core::mem::offset_of!(GenuineFrame, handled) == 16);
    assert!(core::mem::offset_of!(GenuineFrame, verify_flags) == 32);
};
const STATUS_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

/// Provedores opcionais registrados pelo dono do contexto.
#[derive(Clone, Copy, Default)]
pub struct Providers {
    pub notify_corruption: Option<fn(u64)>,
    /// (status, FILETIME) da data de expiração.
    pub query_expiration: Option<fn() -> (u32, u64)>,
    #[allow(clippy::type_complexity)]
    pub query_addon_policy: Option<fn(u64, u64, u64, u64, u64, u32, u64, u32, u64, u64, u64) -> u32>,
    pub query_deferred_activation: Option<fn(u64) -> u32>,
    pub verify_product_policy: Option<fn(u32, u64, u64, u64, u32, u32, u64) -> u32>,
    pub query_license: Option<fn(u64, u64, u64, u64, u32, u64) -> u32>,
}

/// Helper 0x94D3DC: tamanho antes do teste de capacidade; Type opcional.
pub fn write_dword(type_pointer: u64, buffer: u64, capacity: u32, length: u64, value: u32) -> u32 {
    ulong_at(length).set(4);
    if capacity < 4 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if type_pointer != 0 {
        ulong_at(type_pointer).set(4);
    }
    if buffer != 0 {
        guest::write_bytes(buffer, &value.to_le_bytes());
    }
    0
}

pub fn query_session_identifier(context: u64, type_pointer: u64, buffer: u64, capacity: u32, length: u64, handled: u64) -> u32 {
    byte_at(handled).set(1);
    ulong_at(length).set(16);
    if capacity < 16 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if type_pointer != 0 {
        ulong_at(type_pointer).set(3);
    }
    if buffer != 0 {
        // A carga SSE original captura os 16 bytes antes de gravar.
        let bytes = guest::read_bytes(context_at(context).session_identifier.as_ptr() as u64, 16);
        guest::write_bytes(buffer, &bytes);
    }
    0
}

pub fn query_context_value(context: u64, type_pointer: u64, buffer: u64, capacity: u32, length: u64, handled: u64) -> u32 {
    byte_at(handled).set(1);
    write_dword(type_pointer, buffer, capacity, length, context_at(context).context_value.get())
}

/// Registro inicial observado: estado 4 e flag 1, demais campos zerados.
fn initial_state() -> [u8; 48] {
    let mut bytes = [0u8; 48];
    bytes[8] = 4;
    bytes[40] = 1;
    bytes
}

pub fn read_local_state(context: u64) -> Result<u32, KernelError> {
    if context_at(context).view.get() == 0 {
        return Ok(context_at(context).local_state.get());
    }
    if let Some(record) = license_state::snapshot(context)? {
        return Ok(u32::from_le_bytes([record[8], record[9], record[10], record[11]]));
    }
    // A preparação do registro ausente relê o blob e a contagem.
    let blob = context_at(context).view.get();
    let _ = context_at(context).descriptor_count.get();
    if blob != 0 {
        license_state::update_snapshot(context, &initial_state(), 0xFFFF_FFFF, 0)?;
    }
    Ok(4)
}

fn query_local_state(value: u32, context: u64, type_pointer: u64, buffer: u64, capacity: u32, length: u64, handled: u64) -> Result<u32, KernelError> {
    let state = read_local_state(context)?;
    byte_at(handled).set((state != 0) as u8);
    if state == 0 {
        return Ok(STATUS_NAME_NOT_FOUND);
    }
    Ok(write_dword(type_pointer, buffer, capacity, length, value))
}

pub fn query_state(context: u64, type_pointer: u64, buffer: u64, capacity: u32, length: u64, handled: u64) -> Result<u32, KernelError> {
    query_local_state(4, context, type_pointer, buffer, capacity, length, handled)
}

pub fn query_remaining_time(context: u64, type_pointer: u64, buffer: u64, capacity: u32, length: u64, handled: u64) -> Result<u32, KernelError> {
    query_local_state(0, context, type_pointer, buffer, capacity, length, handled)
}

/// 0x725F70 é literalmente MOV EAX,C00000BB; RET (não escreve handled).
pub fn query_local_hardware_identifier() -> u32 {
    STATUS_NOT_SUPPORTED
}

fn has_record(context: u64, exclusive: bool) -> Result<bool, KernelError> {
    let lock = context_at(context).state_lock.address();
    if exclusive {
        push_lock::acquire_exclusive(lock, 0)?;
    } else {
        push_lock::acquire_shared(lock, 0)?;
    }
    let present = context_at(context).state_carrier.get() != 0;
    if exclusive {
        push_lock::release_exclusive(lock, 0)?;
    } else {
        push_lock::release_shared(lock, 0)?;
    }
    Ok(present)
}

/// Milissegundos desde o boot, a unidade dos prazos.
fn elapsed_milliseconds() -> i64 {
    clock::uptime_ms() as i64
}

fn refresh_genuine_state(context: u64) -> Result<(), KernelError> {
    let mut refresh = !has_record(context, false)?;
    if !refresh {
        let previous = license_state::snapshot(context)?;
        let last_check = previous.map_or(0, |bytes| i64::from_le_bytes(bytes[16..24].try_into().unwrap_or([0; 8])));
        if last_check == 0 {
            refresh = true;
        } else {
            let interval = context_at(context).refresh_interval.get().min(900_000) as i64;
            let deadline = last_check.wrapping_add(interval);
            refresh = deadline < last_check || deadline <= elapsed_milliseconds();
        }
    }
    if !refresh || context_at(context).primary.get() != 0 || context_at(context).view.get() == 0 {
        return Ok(());
    }
    if !has_record(context, true)? {
        license_state::set_context_state(context, 5)?;
        return Ok(());
    }
    let blob = context_at(context).view.get();
    let _ = context_at(context).descriptor_count.get();
    if blob == 0 {
        return Ok(());
    }
    let Some(previous) = license_state::snapshot(context)? else { return Ok(()) };
    let mut current = initial_state();
    let mask = if u64::from_le_bytes(previous[0..8].try_into().unwrap_or([0; 8])) == 0 { 4 } else { 6 };
    current[16..24].copy_from_slice(&(elapsed_milliseconds() as u64).to_le_bytes());
    license_state::update_snapshot(context, &current, mask, 0)?;
    Ok(())
}

pub fn query_genuine_before(context: u64, type_pointer: u64, buffer: u64, capacity: u32, length: u64, handled: u64) -> Result<u32, KernelError> {
    if context_at(context).primary.get() == 0 && context_at(context).view.get() != 0 {
        refresh_genuine_state(context)?;
    }
    if context_at(context).primary.get() != 0 && elapsed_milliseconds() / 1000 > 10800 {
        license_state::set_context_state(context, 2)?;
        license_state::update_snapshot(context, &[0u8; 48], 32, 0)?;
    }
    query_local_state(0, context, type_pointer, buffer, capacity, length, handled)
}

/// FILETIME em seis campos de 16 bits (RtlpTimeToTimeFields com divisão
/// assinada); os quatro bytes finais ficam zerados.
pub fn expiration_bytes(file_time: u64) -> [u8; 16] {
    let milliseconds = file_time as i64 / 10_000;
    let whole_days = milliseconds / 86_400_000;
    let days = whole_days as u32 as i64;
    let second_of_day = (milliseconds.wrapping_sub(whole_days * 86_400_000) as u32 / 1000) as i64;
    let shifted = days - 134_774 + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era = (day_of_era - day_of_era.div_euclid(1460) + day_of_era.div_euclid(36_524) - day_of_era.div_euclid(146_096)).div_euclid(365);
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era.div_euclid(4) - year_of_era.div_euclid(100));
    let march_month = (5 * day_of_year + 2).div_euclid(153);
    let day = day_of_year - (153 * march_month + 2).div_euclid(5) + 1;
    let month = march_month + if march_month < 10 { 3 } else { -9 };
    let fields = [year + if month <= 2 { 1 } else { 0 }, month, day, second_of_day / 3600, (second_of_day / 60) % 60, second_of_day % 60];
    let mut bytes = [0u8; 16];
    for (index, value) in fields.iter().enumerate() {
        bytes[index * 2..index * 2 + 2].copy_from_slice(&(*value as u16).to_le_bytes());
    }
    bytes
}

/// Sem callback, 0x7D38C0 fornece FILETIME zero (sem data configurada).
pub fn query_expiration(type_pointer: u64, buffer: u64, capacity: u32, length: u64, handled: u64, provider: Option<fn() -> (u32, u64)>) -> u32 {
    ulong_at(length).set(16);
    if capacity < 16 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if type_pointer != 0 {
        ulong_at(type_pointer).set(3);
    }
    let (status, value) = provider.map_or((0, 0), |provider| provider());
    if status & 0x8000_0000 != 0 {
        return status;
    }
    guest::write_bytes(buffer, &expiration_bytes(value));
    byte_at(handled).set(1);
    status
}


pub fn query_addon_policy(context: u64, type_pointer: u64, buffer: u64, capacity: u32, length: u64, handled: u64) -> Result<u32, KernelError> {
    byte_at(handled).set(1);
    let Ok(frame) = kernel_pool::allocate(64, AllocateOptions { zero: true, paged: true, tag: FRAME_TAG, ..Default::default() }) else { return Ok(STATUS_NO_MEMORY) };
    layout::write_inline_name(frame, "ConsumeAddonPolicySet");
    let result = license_cache::query(context, frame, type_pointer, buffer, capacity, length);
    let _ = kernel_pool::free(frame, Some(FRAME_TAG));
    result
}

/// Callback posterior de GenuineLocalStatus: só substitui o resultado se
/// escrever handled; sem provedor devolve NOT_SUPPORTED com handled=0.
#[allow(clippy::too_many_arguments)]
pub fn query_genuine_after(context: u64, type_pointer: u64, buffer: u64, capacity: u32, length: u64, handled: u64, query_license: &dyn Fn(&str, u64, u64, u32, u64) -> Result<u32, KernelError>, providers: &Providers) -> Result<u32, KernelError> {
    byte_at(handled).set(0);
    if context_at(context).primary.get() != 0 {
        let status = write_dword(type_pointer, buffer, capacity, length, 2);
        byte_at(handled).set(1);
        return Ok(status);
    }
    if buffer != 0 {
        // Valor anterior no buffer de dados do chamador (largura pela capacidade).
        let width = match capacity {
            1 => 1,
            2 => 2,
            _ => 4,
        };
        let mut bytes = [0u8; 4];
        bytes[..width].copy_from_slice(&guest::read_bytes(buffer, width));
        let value = u32::from_le_bytes(bytes);
        if value == 1 {
            return Ok(0);
        }
    }
    let Ok(frame) = kernel_pool::allocate(GenuineFrame::SIZE, AllocateOptions { zero: true, paged: true, tag: FRAME_TAG, ..Default::default() }) else { return Ok(STATUS_NO_MEMORY) };
    // SAFETY: alocação nova do tamanho da moldura.
    let genuine = unsafe { GenuineFrame::at(frame) };
    let mut policy = 0u64;
    let result = (|| -> Result<u32, KernelError> {
        genuine.value_length.set(4);
        let status = query_license("Security-SPP-IgnoreDeferredActivation", 0, genuine.ignore_deferred.address(), 4, genuine.value_length.address())?;
        if status & 0x8000_0000 == 0 && genuine.ignore_deferred.get() == 1 {
            return Ok(status);
        }
        let Some(deferred) = providers.query_deferred_activation else { return Ok(STATUS_NOT_SUPPORTED) };
        let status = deferred(genuine.deferred_activation.address());
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        let Some(verify) = providers.verify_product_policy else { return Ok(STATUS_NOT_SUPPORTED) };
        let mut status = license_registry::query(ValueName::Text("ProductPolicy"), 0, 0, 0, genuine.policy_size.address(), genuine.handled.address())?;
        if status == STATUS_BUFFER_TOO_SMALL {
            let size = genuine.policy_size.get();
            policy = pool_allocation::allocate_tagged(1, size as u64, VALUE_TAG).unwrap_or(0);
            if policy == 0 {
                return Ok(STATUS_NO_MEMORY);
            }
            status = license_registry::query(ValueName::Text("ProductPolicy"), 0, policy, size, genuine.policy_size.address(), genuine.handled.address())?;
        }
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        let mut status = verify(3, policy, 0, 0, 0, 0, genuine.verify_flags.address());
        if (status & 0x8000_0000 == 0 && genuine.verify_flags.get() & 0x40 != 0) || status == 0xC000_0272 {
            status = 0;
        }
        if status & 0x8000_0000 != 0 || genuine.deferred_activation.get() != 0 {
            return Ok(status);
        }
        let status = write_dword(type_pointer, buffer, capacity, length, 2);
        byte_at(handled).set(1);
        Ok(status)
    })();
    if policy != 0 {
        let _ = kernel_pool::free(policy, None);
    }
    let _ = kernel_pool::free(frame, Some(FRAME_TAG));
    result
}
