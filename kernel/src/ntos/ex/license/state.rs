//! Registro privado de estado do licenciamento.
//!
//! Corpo de 48 bytes e portador no pool do contexto; um identificador opaco
//! liga o portador ao registro próprio, sem aceitar ponteiros forjados.

use alloc::collections::BTreeMap;

use crate::ntos::ex::{pool_allocation, push_lock};
use crate::ntos::mm::kernel_pool;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const ALLOCATION_TAG: u32 = 0x2053_4C53;

struct Records {
    by_carrier: BTreeMap<u64, (u64, u64)>,
    next_identifier: u64,
}

static RECORDS: SpinLock<Records> = SpinLock::new(Records { by_carrier: BTreeMap::new(), next_identifier: 1 });

/// Só portadores publicados por este provedor têm armazenamento.
fn resolve(carrier: u64) -> Result<u64, KernelError> {
    let identifier = guest::read64(carrier);
    match RECORDS.lock().by_carrier.get(&carrier) {
        Some(&(owned, data)) if owned == identifier => Ok(data),
        _ => Err(KernelError::new("ProductPolicy state carrier is not owned or was corrupted")),
    }
}

/// (bit, largura, offset) dos campos do registro.
const FIELDS: [(u32, u8, u64); 6] = [(1, 64, 0), (2, 32, 8), (4, 64, 16), (8, 64, 24), (16, 64, 32), (32, 8, 40)];

fn update_fields(context: u64, mask: u32, flags: u8, source: impl Fn(u8, u64) -> u64) -> Result<u32, KernelError> {
    if flags & 1 == 0 && guest::read64(context + 0xB6F0) == 0 {
        return Ok(0);
    }
    let lock = context + 0xB7B0;
    push_lock::acquire_exclusive(lock, 0)?;
    let result = (|| -> Result<u32, KernelError> {
        let carrier = guest::read64(context + 0xB7A8);
        let data = if carrier != 0 {
            resolve(carrier)?
        } else {
            let Ok(data) = pool_allocation::allocate_tagged(1, 48, ALLOCATION_TAG) else { return Ok(0xC000_0017) };
            let Ok(carrier) = pool_allocation::allocate_tagged(1, 8, ALLOCATION_TAG) else {
                let _ = kernel_pool::free(data, None);
                return Ok(0xC000_0017);
            };
            for offset in [0u64, 16, 24, 32] {
                guest::write64(data + offset, 0);
            }
            guest::write32(data + 8, 4);
            guest::write8(data + 40, 1);
            let identifier = {
                let mut records = RECORDS.lock();
                let identifier = records.next_identifier;
                records.next_identifier += 1;
                records.by_carrier.insert(carrier, (identifier, data));
                identifier
            };
            guest::write64(carrier, identifier);
            guest::write64(context + 0xB7A8, carrier);
            data
        };
        // A ordem das máscaras mantém leituras tardias se a entrada sobrepuser
        // o registro; campos não selecionados não são tocados.
        for (bit, width, offset) in FIELDS {
            if mask & bit != 0 {
                let value = source(width, offset);
                match width {
                    64 => guest::write64(data + offset, value),
                    32 => guest::write32(data + offset, value as u32),
                    _ => guest::write8(data + offset, value as u8),
                }
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
    update_fields(context, mask, flags, |width, offset| match width {
        64 => guest::read64(source + offset),
        32 => guest::read32(source + offset) as u64,
        _ => guest::read8(source + offset) as u64,
    })
}

/// Helper 0x5B2FA4: publica o DWORD do contexto mesmo se faltar pool para o
/// registro opcional.
pub fn set_context_state(context: u64, value: u32) -> Result<u32, KernelError> {
    guest::write32(context + 0xB78C, value);
    update_fields(context, 2, 0, |_, _| value as u64)
}

/// Copia os 48 bytes em três blocos de 16, como o original.
pub fn query(context: u64, output: u64) -> Result<u32, KernelError> {
    if output == 0 {
        return Ok(0xC000_000D);
    }
    let lock = context + 0xB7B0;
    push_lock::acquire_shared(lock, 0)?;
    let result = (|| {
        let carrier = guest::read64(context + 0xB7A8);
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
    let lock = context + 0xB7B0;
    push_lock::acquire_exclusive(lock, 0)?;
    let result = (|| {
        let carrier = guest::read64(context + 0xB7A8);
        if carrier == 0 {
            return Ok(());
        }
        let data = resolve(carrier)?;
        guest::write64(context + 0xB7A8, 0);
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
    let lock = context + 0xB7B0;
    push_lock::acquire_shared(lock, 0)?;
    let result = (|| {
        let carrier = guest::read64(context + 0xB7A8);
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
    update_fields(context, mask, flags, |width, offset| {
        let offset = offset as usize;
        match width {
            64 => u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap_or([0; 8])),
            32 => u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap_or([0; 4])) as u64,
            _ => bytes[offset] as u64,
        }
    })
}
