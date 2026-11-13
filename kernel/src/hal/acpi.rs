//! Descoberta das tabelas de firmware no boot BIOS.
//!
//! ACPI 6.6, seção 5.2: RSDP, RSDT/XSDT, cabeçalho SDT e links do FADT.
//! Checksums e tamanhos são conferidos antes de a HAL/SMP consumir uma tabela.

use alloc::string::String;
use alloc::vec::Vec;

use crate::hal::physical;
use crate::rtl::{KernelError, SpinLock};

const PHYSICAL_LIMIT: u64 = crate::ntos::mm::memory_map::PHYSICAL_MEMORY_LIMIT; // fim do mapa direto
const MAX_TABLE_SIZE: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct AcpiTable {
    pub address: u64,
    pub signature: String,
    pub length: u64,
    pub revision: u8,
    pub oem_id: Option<String>,
    pub oem_table_id: Option<String>,
    pub bytes: Vec<u8>,
}

struct Catalog {
    tables: Option<Vec<AcpiTable>>,
    root_pointer: u64,
}

static CATALOG: SpinLock<Catalog> = SpinLock::new(Catalog { tables: None, root_pointer: 0 });

fn in_range(address: u64, size: u64) -> bool {
    address > 0 && size > 0 && address.checked_add(size).is_some_and(|end| end <= PHYSICAL_LIMIT)
}

fn read(address: u64, size: u64) -> Result<Vec<u8>, KernelError> {
    if !in_range(address, size) {
        return Err(KernelError::new("ACPI physical range is not mapped"));
    }
    Ok(physical::read_bytes(address, size as usize))
}

fn text(bytes: &[u8], start: usize, size: usize) -> String {
    bytes[start..start + size].iter().map(|&byte| byte as char).collect()
}

fn checksum(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |sum, &byte| sum.wrapping_add(byte)) == 0
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

/// Ponteiro de 64 bits do firmware, nunca truncado para outro endereço baixo.
fn address64(bytes: &[u8], offset: usize) -> Result<u64, KernelError> {
    let address = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    if address >= PHYSICAL_LIMIT {
        return Err(KernelError::new("ACPI address above the direct map"));
    }
    Ok(address)
}

struct Root {
    address: u64,
    rsdt: u64,
    xsdt: u64,
}

fn rsdp_at(address: u64) -> Result<Option<Root>, KernelError> {
    if !in_range(address, 20) {
        return Ok(None);
    }
    let first = read(address, 20)?;
    if text(&first, 0, 8) != "RSD PTR " || !checksum(&first) {
        return Ok(None);
    }
    if first[15] < 2 {
        return Ok(Some(Root { address, rsdt: u32_at(&first, 16) as u64, xsdt: 0 }));
    }
    if !in_range(address, 36) {
        return Ok(None);
    }
    let header = read(address, 36)?;
    let size = u32_at(&header, 20) as u64;
    if !(36..=4096).contains(&size) || !in_range(address, size) || !checksum(&read(address, size)?) {
        return Ok(None);
    }
    Ok(Some(Root { address, rsdt: u32_at(&header, 16) as u64, xsdt: address64(&header, 24)? }))
}

fn find_root() -> Result<Option<Root>, KernelError> {
    let ebda = (physical::read8(0x40E) as u64 + physical::read8(0x40F) as u64 * 256) * 16;
    let mut regions = Vec::new();
    if ebda >= 0x400 && ebda + 1024 <= 0xA0000 {
        regions.push((ebda, ebda + 1024));
    }
    regions.push((0xE0000, 0x100000));
    for (start, end) in regions {
        let mut address = start;
        while address + 20 <= end {
            if let Some(root) = rsdp_at(address)? {
                return Ok(Some(root));
            }
            address += 16;
        }
    }
    Ok(None)
}

fn table_at(address: u64, expected: Option<&str>) -> Result<AcpiTable, KernelError> {
    let first = read(address, 8)?;
    let signature = text(&first, 0, 4);
    if let Some(expected) = expected {
        if signature != expected {
            return Err(KernelError::new(alloc::format!("ACPI signature mismatch: {expected}")));
        }
    }
    let size = u32_at(&first, 4) as u64;
    let facs = signature == "FACS";
    if size < if facs { 64 } else { 36 } || size > MAX_TABLE_SIZE {
        return Err(KernelError::new("ACPI invalid table length"));
    }
    let bytes = read(address, size)?;
    if !facs && !checksum(&bytes) {
        return Err(KernelError::new(alloc::format!("ACPI checksum mismatch: {signature}")));
    }
    Ok(AcpiTable {
        address,
        revision: if facs { bytes[32] } else { bytes[8] },
        oem_id: (!facs).then(|| text(&bytes, 10, 6)),
        oem_table_id: (!facs).then(|| text(&bytes, 16, 8)),
        signature,
        length: size,
        bytes,
    })
}

pub fn init() {
    let mut catalog = CATALOG.lock();
    if catalog.tables.is_some() {
        return;
    }
    let mut tables: Vec<AcpiTable> = Vec::new();
    let mut seen: Vec<u64> = Vec::new();
    let mut add = |address: u64, expected: Option<&str>, tables: &mut Vec<AcpiTable>| -> Option<usize> {
        if address == 0 || seen.contains(&address) {
            return None;
        }
        seen.push(address);
        match table_at(address, expected) {
            Ok(table) => {
                tables.push(table);
                Some(tables.len() - 1)
            }
            Err(error) => {
                debug_print!("[acpi] table rejected: {}", error);
                None
            }
        }
    };
    let root = match find_root() {
        Ok(Some(root)) => root,
        Ok(None) => {
            catalog.tables = Some(Vec::new());
            debug_print!("[acpi] no valid BIOS RSDP");
            return;
        }
        Err(error) => {
            debug_print!("[acpi] root rejected: {}", error);
            catalog.tables = Some(Vec::new());
            debug_print!("[acpi] no valid BIOS RSDP");
            return;
        }
    };
    catalog.root_pointer = root.address;
    let (root_address, root_signature) = if root.xsdt != 0 { (root.xsdt, "XSDT") } else { (root.rsdt, "RSDT") };
    let Some(root_index) = add(root_address, Some(root_signature), &mut tables) else {
        catalog.tables = Some(Vec::new());
        return;
    };
    let stride = if root.xsdt != 0 { 8 } else { 4 };
    let root_table = tables[root_index].clone();
    if (root_table.length - 36) % stride != 0 {
        debug_print!("[acpi] invalid root table entry stride");
        catalog.tables = Some(Vec::new());
        return;
    }
    let mut offset = 36;
    while offset < root_table.length as usize {
        let entry = if stride == 8 { address64(&root_table.bytes, offset) } else { Ok(u32_at(&root_table.bytes, offset) as u64) };
        match entry {
            Ok(address) => {
                add(address, None, &mut tables);
            }
            Err(error) => debug_print!("[acpi] root entry rejected: {}", error),
        }
        offset += stride as usize;
    }
    if let Some(fadt) = tables.iter().find(|table| table.signature == "FACP").cloned() {
        for (signature, legacy, extended) in [("DSDT", 40usize, 140usize), ("FACS", 36, 132)] {
            let mut address = if fadt.length as usize >= extended + 8 {
                match address64(&fadt.bytes, extended) {
                    Ok(address) => address,
                    Err(error) => {
                        debug_print!("[acpi] FADT link rejected: {}", error);
                        continue;
                    }
                }
            } else {
                0
            };
            if address == 0 && fadt.length as usize >= legacy + 4 {
                address = u32_at(&fadt.bytes, legacy) as u64;
            }
            add(address, Some(signature), &mut tables);
        }
    }
    let names: Vec<&str> = tables.iter().map(|table| table.signature.as_str()).collect();
    debug_print!("[acpi] {}: {}", root_table.signature, names.join(","));
    catalog.tables = Some(tables);
}

/// Cópia de uma tabela validada. FACS é estado compartilhado do firmware:
/// seus bytes são relidos a cada consulta; `refresh` revalida a tabela.
pub fn get_table(signature: &str, instance: usize, refresh: bool) -> Option<AcpiTable> {
    init();
    if signature.len() != 4 {
        return None;
    }
    let table = CATALOG.lock().tables.as_ref()?.iter().filter(|item| item.signature == signature).nth(instance)?.clone();
    if refresh {
        return match table_at(table.address, Some(signature)) {
            Ok(table) => Some(table),
            Err(error) => {
                debug_print!("[acpi] refresh rejected: {}", error);
                None
            }
        };
    }
    if table.signature == "FACS" {
        let bytes = read(table.address, table.length).ok()?;
        return Some(AcpiTable { bytes, ..table });
    }
    Some(table)
}

/// Catálogo sem os bytes.
pub fn enumerate() -> Vec<AcpiTable> {
    init();
    CATALOG
        .lock()
        .tables
        .as_ref()
        .map(|tables| tables.iter().map(|table| AcpiTable { bytes: Vec::new(), ..table.clone() }).collect())
        .unwrap_or_default()
}

pub fn rsdp_address() -> u64 {
    init();
    CATALOG.lock().root_pointer
}
