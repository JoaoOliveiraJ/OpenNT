//! Células de segurança de uma hive ('sk', o cmse do NT).
//!
//! Cada descritor distinto da hive mora numa célula 'sk' com o descritor
//! auto-relativo e a contagem de chaves que o usam; as células formam uma
//! lista circular (Flink/Blink). Como no ntoskrnl 19041: a chave nova
//! reaproveita uma célula com o mesmo descritor
//! (CmpFindMatchingDescriptorCell) ou ganha uma célula nova, inserida logo
//! depois da célula do pai; a da raiz da hive aponta para si mesma
//! (CmpInsertSecurityCellList, rva 0x69e850). Quando a contagem chega a
//! zero a célula sai da lista e é liberada (CmpRemoveSecurityCellList).

use alloc::vec::Vec;

use crate::ntos::inc::types::CmKeySecurity;
use crate::ntos::inc::types::NtStruct;
use crate::ntos::se::inherit_descriptor::Captured;

use super::storage::{Storage, HCELL_NIL, STATUS_REGISTRY_CORRUPT};

/// 'sk'.
pub const SK: u16 = 0x6b73;

fn security_at(address: u64) -> &'static CmKeySecurity {
    // SAFETY: dados de uma célula 'sk' alocada (conferida pelo chamador).
    unsafe { CmKeySecurity::at(address) }
}

fn sk(storage: &Storage, cell: u32) -> Option<&'static CmKeySecurity> {
    let address = storage.cell(cell, 0x14)?;
    let security = security_at(address);
    (security.signature.get() == SK).then_some(security)
}

fn align4(length: usize) -> usize {
    (length + 3) & !3
}

/// SECURITY_DESCRIPTOR_RELATIVE com SACL, DACL, owner e group, nessa ordem.
pub fn self_relative(descriptor: &Captured) -> Vec<u8> {
    let mut bytes = alloc::vec![0u8; 20];
    bytes[0] = 1;
    // Componente presente sem ACL (offset 0) é a ACL NULL.
    let control = descriptor.control | 0x8000;
    let place = |bytes: &mut Vec<u8>, field: usize, component: &[u8]| {
        let offset = bytes.len() as u32;
        bytes[field..field + 4].copy_from_slice(&offset.to_le_bytes());
        bytes.extend_from_slice(component);
        bytes.resize(align4(bytes.len()), 0);
    };
    if let Some(sacl) = descriptor.sacl.as_ref().filter(|_| descriptor.control & 0x10 != 0) {
        place(&mut bytes, 12, sacl);
    }
    if let Some(dacl) = descriptor.dacl.as_ref().filter(|_| descriptor.control & 4 != 0) {
        place(&mut bytes, 16, dacl);
    }
    if !descriptor.owner.is_empty() {
        place(&mut bytes, 4, &descriptor.owner);
    }
    if !descriptor.group.is_empty() {
        place(&mut bytes, 8, &descriptor.group);
    }
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    bytes
}

/// Componentes de um descritor auto-relativo. Um componente fora dos
/// limites torna a hive corrompida.
pub fn parse_self_relative(bytes: &[u8]) -> Result<Captured, u32> {
    if bytes.len() < 20 || bytes[0] != 1 {
        return Err(STATUS_REGISTRY_CORRUPT);
    }
    let u16_at = |offset: usize| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    let u32_at = |offset: usize| u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]]) as usize;
    let control = u16_at(2);
    let sid = |field: usize| -> Result<Vec<u8>, u32> {
        let offset = u32_at(field);
        if offset == 0 {
            return Ok(Vec::new());
        }
        let count = *bytes.get(offset + 1).ok_or(STATUS_REGISTRY_CORRUPT)? as usize;
        bytes.get(offset..offset + 8 + 4 * count).map(<[u8]>::to_vec).ok_or(STATUS_REGISTRY_CORRUPT)
    };
    let acl = |field: usize, present: bool| -> Result<Option<Vec<u8>>, u32> {
        let offset = u32_at(field);
        if !present || offset == 0 {
            return Ok(None);
        }
        let size = bytes.get(offset + 2..offset + 4).map(|size| u16::from_le_bytes([size[0], size[1]]) as usize).ok_or(STATUS_REGISTRY_CORRUPT)?;
        bytes.get(offset..offset + size).map(|acl| Some(acl.to_vec())).ok_or(STATUS_REGISTRY_CORRUPT)
    };
    Ok(Captured { control: control & 0x7FFF, owner: sid(4)?, group: sid(8)?, sacl: acl(12, control & 0x10 != 0)?, dacl: acl(16, control & 4 != 0)? })
}

/// O descritor de uma célula 'sk'.
pub fn read(storage: &Storage, cell: u32) -> Result<Captured, u32> {
    let security = sk(storage, cell).ok_or(STATUS_REGISTRY_CORRUPT)?;
    let length = security.descriptor_length.get();
    let bytes = storage.read_cell(cell, 0x14 + length).ok_or(STATUS_REGISTRY_CORRUPT)?;
    parse_self_relative(&bytes[0x14..])
}

/// Célula da lista com exatamente esses bytes de descritor.
fn find_matching(storage: &Storage, start: u32, descriptor: &[u8]) -> Option<u32> {
    let mut cell = start;
    for _ in 0..0x10000 {
        let security = sk(storage, cell)?;
        if security.descriptor_length.get() as usize == descriptor.len() && storage.read_cell(cell, 0x14 + descriptor.len() as u32).is_some_and(|bytes| bytes[0x14..] == *descriptor) {
            return Some(cell);
        }
        cell = security.flink.get();
        if cell == start {
            return None;
        }
    }
    None
}

/// CmpAssignSecurityDescriptor: a célula 'sk' para uma chave, com a
/// contagem já incrementada. `anchor` é a célula do pai (nil para a raiz).
pub fn assign(storage: &mut Storage, anchor: u32, root_security: u32, descriptor: &Captured) -> Option<u32> {
    let bytes = self_relative(descriptor);
    if root_security != HCELL_NIL {
        if let Some(cell) = find_matching(storage, root_security, &bytes) {
            let security = sk(storage, cell)?;
            security.reference_count.set(security.reference_count.get() + 1);
            storage.mark_cell_dirty(cell);
            return Some(cell);
        }
    }
    let cell = storage.allocate(0x14 + bytes.len() as u32)?;
    storage.write_cell(cell, 0x14, &bytes);
    let security = security_at(storage.cell(cell, 0x14)?);
    security.signature.set(SK);
    security.reference_count.set(1);
    security.descriptor_length.set(bytes.len() as u32);
    match anchor {
        HCELL_NIL => {
            security.flink.set(cell);
            security.blink.set(cell);
        }
        anchor => {
            let previous = sk(storage, anchor)?;
            let next_cell = previous.flink.get();
            let next = sk(storage, next_cell)?;
            security.flink.set(next_cell);
            security.blink.set(anchor);
            previous.flink.set(cell);
            next.blink.set(cell);
            storage.mark_cell_dirty(anchor);
            storage.mark_cell_dirty(next_cell);
        }
    }
    storage.mark_cell_dirty(cell);
    Some(cell)
}

/// Solta uma referência; a última tira a célula da lista e a libera.
pub fn release(storage: &mut Storage, cell: u32) {
    let Some(security) = sk(storage, cell) else { return };
    let count = security.reference_count.get();
    if count > 1 {
        security.reference_count.set(count - 1);
        storage.mark_cell_dirty(cell);
        return;
    }
    let (previous, next) = (security.blink.get(), security.flink.get());
    if previous != cell {
        if let (Some(previous_sk), Some(next_sk)) = (sk(storage, previous), sk(storage, next)) {
            previous_sk.flink.set(next);
            next_sk.blink.set(previous);
            storage.mark_cell_dirty(previous);
            storage.mark_cell_dirty(next);
        }
    }
    storage.free(cell);
}

/// Contagem de referências de uma célula (para os testes e a verificação).
pub fn reference_count(storage: &Storage, cell: u32) -> Option<u32> {
    sk(storage, cell).map(|security| security.reference_count.get())
}
