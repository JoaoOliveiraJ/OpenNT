//! Consultas ACPI da HAL nativa.
//!
//! Devolvem cópias pertencentes ao boot na arena de convidados. As
//! assinaturas são DWORDs little-endian do cabeçalho ACPI.

use alloc::collections::BTreeMap;
use alloc::string::String;

use super::acpi::{self, AcpiTable};
use crate::rtl::SpinLock;
use crate::ntos::mm::guest_memory as guest;

/// endereço de firmware -> (cópia nativa, tamanho)
static CACHE: SpinLock<BTreeMap<u64, (u64, u64)>> = SpinLock::new(BTreeMap::new());

fn signature_text(signature: u32) -> String {
    (0..4).map(|index| ((signature >> (8 * index)) & 255) as u8 as char).collect()
}

/// HalpAcpiGetCachedTable usa strncmp, limitado a 6 e 8 bytes.
fn matches(pointer: u64, bytes: &[u8], offset: usize, size: usize) -> bool {
    if pointer == 0 {
        return true;
    }
    for index in 0..size {
        let byte = guest::read8(pointer.wrapping_add(index as u64));
        if byte != bytes[offset + index] {
            return false;
        }
        if byte == 0 {
            break;
        }
    }
    true
}

fn current_copy(pointer: u64, size: u64, table: &AcpiTable) -> bool {
    size == table.length && (0..table.length).all(|index| guest::read8(pointer + index) == table.bytes[index as usize])
}

/// O kernel revalida a SLIC contra o firmware; as demais ficam em cache
/// durante o boot. Cópias antigas continuam válidas para os chamadores.
fn copy(table: &AcpiTable) -> u64 {
    if let Some(&(pointer, size)) = CACHE.lock().get(&table.address) {
        if table.signature != "SLIC" || current_copy(pointer, size, table) {
            return pointer;
        }
    }
    let pointer = guest::alloc_bytes(table.length);
    if pointer == 0 {
        return 0;
    }
    guest::write_bytes(pointer, &table.bytes);
    CACHE.lock().insert(table.address, (pointer, table.length));
    pointer
}

pub fn get_cached_table(signature: u32, oem_id: u64, oem_table_id: u64) -> u64 {
    let name = signature_text(signature);
    let count = acpi::enumerate().iter().filter(|table| table.signature == name).count();
    for instance in 0..count {
        let Some(table) = acpi::get_table(&name, instance, name == "SLIC") else { continue };
        if !matches(oem_id, &table.bytes, 10, 6) || !matches(oem_table_id, &table.bytes, 16, 8) {
            continue;
        }
        return copy(&table);
    }
    0
}

/// Inicializado o catálogo, o LoaderBlock não é usado (HalpAcpiTableCacheInit).
pub fn get_table_ex(_loader_block: u64, signature: u32, oem_id: u64, oem_table_id: u64) -> u64 {
    get_cached_table(signature, oem_id, oem_table_id)
}

pub fn get_table_phase0(loader_block: u64, signature: u32) -> u64 {
    get_table_ex(loader_block, signature, 0, 0)
}
