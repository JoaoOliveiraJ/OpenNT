//! Registro privado de estado do licenciamento.
//!
//! Corpo de 48 bytes e portador no pool do contexto; um identificador opaco
//! liga o portador ao registro próprio, sem aceitar ponteiros forjados.

use alloc::collections::BTreeMap;

use super::layout::context_at;
use crate::ntos::ex::{pool_allocation, push_lock};
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::mm::kernel_pool;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const ALLOCATION_TAG: u32 = 0x2053_4C53;

/// Registro de estado (48 bytes); a origem de `update` tem o mesmo layout.
#[repr(C)]
struct StateRecord {
    primary_value: Field<u64>,
    state: Field<u32>,
    _pad_c: Reserved<0x4>,
    last_check: Field<u64>,
    reserved: Field<u64>,
    grace_seconds: Field<u64>,
    active: Field<u8>,
    _pad_29: Reserved<0x7>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for StateRecord {}

const _: () = {
    assert!(core::mem::size_of::<StateRecord>() == 48);
    assert!(core::mem::offset_of!(StateRecord, last_check) == 16);
    assert!(core::mem::offset_of!(StateRecord, grace_seconds) == 32);
    assert!(core::mem::offset_of!(StateRecord, active) == 40);
};

fn record_at(address: u64) -> &'static StateRecord {
    // SAFETY: registros alocados aqui ou a origem de 48 bytes do chamador.
    unsafe { StateRecord::at(address) }
}

/// O campo do registro selecionado pelo bit da máscara.
fn load(record: &StateRecord, bit: u32) -> u64 {
    match bit {
        1 => record.primary_value.get(),
        2 => record.state.get() as u64,
        4 => record.last_check.get(),
        8 => record.reserved.get(),
        16 => record.grace_seconds.get(),
        _ => record.active.get() as u64,
    }
}

fn store(record: &StateRecord, bit: u32, value: u64) {
    match bit {
        1 => record.primary_value.set(value),
        2 => record.state.set(value as u32),
        4 => record.last_check.set(value),
        8 => record.reserved.set(value),
        16 => record.grace_seconds.set(value),
        _ => record.active.set(value as u8),
    }
}

/// O identificador guardado no portador de 8 bytes.
fn carrier_at(carrier: u64) -> &'static Field<u64> {
    // SAFETY: portadores alocados por `update_fields`.
    unsafe { Field::<u64>::at(carrier) }
}

struct Records {
    by_carrier: BTreeMap<u64, (u64, u64)>,
    next_identifier: u64,
}

static RECORDS: SpinLock<Records> = SpinLock::new(Records { by_carrier: BTreeMap::new(), next_identifier: 1 });

/// Só portadores publicados por este provedor têm armazenamento.
fn resolve(carrier: u64) -> Result<u64, KernelError> {
    let identifier = carrier_at(carrier).get();
    match RECORDS.lock().by_carrier.get(&carrier) {
        Some(&(owned, data)) if owned == identifier => Ok(data),
        _ => Err(KernelError::new("ProductPolicy state carrier is not owned or was corrupted")),
    }
}

/// (bit, largura, offset) dos campos do registro.
const FIELDS: [(u32, u8, u64); 6] = [(1, 64, 0), (2, 32, 8), (4, 64, 16), (8, 64, 24), (16, 64, 32), (32, 8, 40)];

fn update_fields(context: u64, mask: u32, flags: u8, source: impl Fn(u32, u8, u64) -> u64) -> Result<u32, KernelError> {
    if flags & 1 == 0 && context_at(context).view.get() == 0 {
        return Ok(0);
    }
    let lock = context_at(context).state_lock.address();
    push_lock::acquire_exclusive(lock, 0)?;
    let result = (|| -> Result<u32, KernelError> {
        let carrier = context_at(context).state_carrier.get();
        let data = if carrier != 0 {
            resolve(carrier)?
        } else {
            let Ok(data) = pool_allocation::allocate_tagged(1, StateRecord::SIZE, ALLOCATION_TAG) else { return Ok(0xC000_0017) };
            let Ok(carrier) = pool_allocation::allocate_tagged(1, 8, ALLOCATION_TAG) else {
                let _ = kernel_pool::free(data, None);
                return Ok(0xC000_0017);
            };
            let record = record_at(data);
            record.primary_value.set(0);
            record.last_check.set(0);
            record.reserved.set(0);
            record.grace_seconds.set(0);
            record.state.set(4);
            record.active.set(1);
            let identifier = {
                let mut records = RECORDS.lock();
                let identifier = records.next_identifier;
                records.next_identifier += 1;
                records.by_carrier.insert(carrier, (identifier, data));
                identifier
            };
            carrier_at(carrier).set(identifier);
            context_at(context).state_carrier.set(carrier);
            data
        };
        // A ordem das máscaras mantém leituras tardias se a entrada sobrepuser
        // o registro; campos não selecionados não são tocados.
        let record = record_at(data);
        for (bit, width, offset) in FIELDS {
            if mask & bit != 0 {
                store(record, bit, source(bit, width, offset));
            }
        }
        Ok(0)
    })();
    push_lock::release_exclusive(lock, 0)?;
    result
}

/// A entrada obrigatória é validada antes de examinar o blob secundário.
pub fn update(context: u64, source: u64, mask: u32, flags: u8) -> Result<u32, KernelError> {
    if source == 0 {
        return Ok(0xC000_000D);
    }
    let source = record_at(source);
    update_fields(context, mask, flags, |bit, _, _| load(source, bit))
}

/// Helper 0x5B2FA4: publica o DWORD do contexto mesmo se faltar pool para o
/// registro opcional.
pub fn set_context_state(context: u64, value: u32) -> Result<u32, KernelError> {
    context_at(context).local_state.set(value);
    update_fields(context, 2, 0, |_, _, _| value as u64)
}

/// Copia os 48 bytes em três blocos de 16.
pub fn query(context: u64, output: u64) -> Result<u32, KernelError> {
    if output == 0 {
        return Ok(0xC000_000D);
    }
    let lock = context_at(context).state_lock.address();
    push_lock::acquire_shared(lock, 0)?;
    let result = (|| {
        let carrier = context_at(context).state_carrier.get();
        if carrier == 0 {
            return Ok(0xC000_0225);
        }
        let data = resolve(carrier)?;
        for block in [0u64, 16, 32] {
            let bytes = guest::read_bytes(data + block, 16);
            guest::write_bytes(output + block, &bytes);
        }
        Ok(0)
    })();
    push_lock::release_shared(lock, 0)?;
    result
}

/// Chamado pelo dono ao destruir o contexto.
pub fn release(context: u64) -> Result<(), KernelError> {
    let lock = context_at(context).state_lock.address();
    push_lock::acquire_exclusive(lock, 0)?;
    let result = (|| {
        let carrier = context_at(context).state_carrier.get();
        if carrier == 0 {
            return Ok(());
        }
        let data = resolve(carrier)?;
        context_at(context).state_carrier.set(0);
        RECORDS.lock().by_carrier.remove(&carrier);
        let _ = kernel_pool::free(data, None);
        let _ = kernel_pool::free(carrier, None);
        Ok(())
    })();
    push_lock::release_exclusive(lock, 0)?;
    result
}

/// Cópia dos 48 bytes, sem ponteiro ao pool depois de soltar o lock.
pub fn snapshot(context: u64) -> Result<Option<[u8; 48]>, KernelError> {
    let lock = context_at(context).state_lock.address();
    push_lock::acquire_shared(lock, 0)?;
    let result = (|| {
        let carrier = context_at(context).state_carrier.get();
        if carrier == 0 {
            return Ok(None);
        }
        let data = resolve(carrier)?;
        let mut bytes = [0u8; 48];
        bytes.copy_from_slice(&guest::read_bytes(data, 48));
        Ok(Some(bytes))
    })();
    push_lock::release_shared(lock, 0)?;
    result
}

/// Mesmas máscaras e alocações, com a origem pertencente à chamada.
pub fn update_snapshot(context: u64, bytes: &[u8; 48], mask: u32, flags: u8) -> Result<u32, KernelError> {
    update_fields(context, mask, flags, |_, width, offset| {
        let offset = offset as usize;
        match width {
            64 => u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap_or([0; 8])),
            32 => u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap_or([0; 4])) as u64,
            _ => bytes[offset] as u64,
        }
    })
}
