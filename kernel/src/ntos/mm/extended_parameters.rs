//! Os parâmetros estendidos (MEM_EXTENDED_PARAMETER) dos serviços Ex do Mm,
//! capturados como no ntoskrnl 19041.
//!
//! - MiCaptureAllocateMapExtendedParameters (0x5f9738), o do
//!   NtMapViewOfSectionEx e do NtAllocateUserPhysicalPagesEx: nenhum
//!   parâmetro com o ponteiro não nulo, ou o ponteiro nulo com parâmetros, é
//!   STATUS_INVALID_PARAMETER; em UserMode o vetor é sondado para escrita
//!   (ProbeForWrite, alinhado a 8). Cada entrada tem o tipo nos 8 bits
//!   baixos e o resto do cabeçalho zero, um tipo de 1 a 5 que o serviço
//!   aceita e que não se repete. AddressRequirements (1) aponta um
//!   MEM_ADDRESS_REQUIREMENTS (alinhado a 8 e sondado em UserMode) que é
//!   copiado; NumaNode (2) cabe em 32 bits (o bit 63 é a marca de nó
//!   obrigatório) e não é 0xFFFFFFFF, guardado como nó + 1; PartitionHandle
//!   (3) não é nulo; UserPhysicalHandle (4) é guardado; AttributeFlags (5)
//!   não passa de 0x3F.
//! - MiCaptureSectionCreateExtendedParameters (0x654dec), o do
//!   NtCreateSectionEx: as mesmas regras de vetor, com os tipos de seção
//!   UserPhysicalFlags (1, valor 0 ou 1) e NumaNode (2, guardado como nó + 1).

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user_probe;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
/// O MmUserProbeAddress do 19041.
const USER_PROBE_ADDRESS: u64 = 0x7FFF_FFFF_0000;
/// Tamanho de um MEM_EXTENDED_PARAMETER e de um MEM_ADDRESS_REQUIREMENTS.
const PARAMETER_SIZE: u64 = 0x10;
const REQUIREMENTS_SIZE: u64 = 0x18;

/// MEM_EXTENDED_PARAMETER_TYPE.
pub const ADDRESS_REQUIREMENTS: u32 = 1;
pub const NUMA_NODE: u32 = 2;
pub const PARTITION_HANDLE: u32 = 3;
pub const USER_PHYSICAL_HANDLE: u32 = 4;
pub const ATTRIBUTE_FLAGS: u32 = 5;
/// MEM_SECTION_EXTENDED_PARAMETER_TYPE.
pub const SECTION_USER_PHYSICAL_FLAGS: u32 = 1;
pub const SECTION_NUMA_NODE: u32 = 2;

/// O que o MiCaptureAllocateMapExtendedParameters guarda.
#[derive(Clone, Copy, Default, Debug)]
pub struct AllocateMap {
    /// MEM_ADDRESS_REQUIREMENTS (zeros sem o parâmetro).
    pub lowest: u64,
    pub highest: u64,
    pub alignment: u64,
    pub partition: u64,
    /// O nó pedido + 1 (0 sem o parâmetro) e a marca de nó obrigatório.
    pub numa_node_plus_one: u32,
    pub numa_strict: bool,
    pub user_physical_handle: u64,
    pub has_user_physical_handle: bool,
    pub attribute_flags: u64,
    /// Os tipos presentes (bit = 1 << tipo).
    pub present: u32,
}

/// O que o MiCaptureSectionCreateExtendedParameters guarda.
#[derive(Clone, Copy, Default, Debug)]
pub struct SectionCreate {
    pub user_physical_flags: Option<u32>,
    /// O nó pedido + 1 (0 sem o parâmetro).
    pub numa_node_plus_one: u32,
    pub present: u32,
}

/// As regras comuns do vetor: o ponteiro conforme a contagem e, em
/// UserMode, o ProbeForWrite alinhado a 8.
fn check_vector(parameters: u64, count: u32, user: bool) -> Result<bool, u32> {
    if count == 0 {
        return if parameters != 0 { Err(STATUS_INVALID_PARAMETER) } else { Ok(false) };
    }
    if parameters == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if user {
        if parameters & 7 != 0 {
            return Err(STATUS_DATATYPE_MISALIGNMENT);
        }
        if !user_probe::probe_user_write(parameters, count as u64 * PARAMETER_SIZE) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
    }
    Ok(true)
}

/// Cabeçalho e valor de uma entrada (lidos sondados), com o tipo dos 8
/// bits baixos; o resto do cabeçalho tem de ser zero.
fn entry(parameters: u64, index: u32, user: bool) -> Result<(u32, u64), u32> {
    let address = parameters + index as u64 * PARAMETER_SIZE;
    let read = |at: u64| if user { guest::try_read::<u64>(at).map_err(|error| error.status) } else { Ok(guest::read64(at)) };
    let header = read(address)?;
    if header >= 0x100 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok((header as u32, read(address + 8)?))
}

/// O NumaNode: cabe em 32 bits depois da marca do bit 63, e não é
/// 0xFFFFFFFF; devolve (nó + 1, obrigatório).
fn numa_node(value: u64, strict_allowed: bool) -> Result<(u32, bool), u32> {
    let (node, strict) = if value > u32::MAX as u64 && strict_allowed && value >> 63 != 0 { (value & !(1 << 63), true) } else { (value, false) };
    if node >= u32::MAX as u64 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok((node as u32 + 1, strict))
}

/// MiCaptureAllocateMapExtendedParameters(Parameters, Count, PreviousMode,
/// AllowedTypes (bit = 1 << tipo)).
pub fn capture_allocate_map(parameters: u64, count: u32, user: bool, allowed: u32) -> Result<AllocateMap, u32> {
    let mut captured = AllocateMap::default();
    if !check_vector(parameters, count, user)? {
        return Ok(captured);
    }
    for index in 0..count {
        let (kind, value) = entry(parameters, index, user)?;
        if !(ADDRESS_REQUIREMENTS..=ATTRIBUTE_FLAGS).contains(&kind) || allowed & (1 << kind) == 0 || captured.present & (1 << kind) != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        captured.present |= 1 << kind;
        match kind {
            ADDRESS_REQUIREMENTS => {
                if user {
                    if value & 7 != 0 {
                        return Err(STATUS_DATATYPE_MISALIGNMENT);
                    }
                    if value.checked_add(REQUIREMENTS_SIZE).is_none_or(|end| end > USER_PROBE_ADDRESS) {
                        return Err(STATUS_ACCESS_VIOLATION);
                    }
                }
                let read = |at: u64| if user { guest::try_read::<u64>(at).map_err(|error| error.status) } else { Ok(guest::read64(at)) };
                captured.lowest = read(value)?;
                captured.highest = read(value + 8)?;
                captured.alignment = read(value + 0x10)?;
            }
            NUMA_NODE => (captured.numa_node_plus_one, captured.numa_strict) = numa_node(value, true)?,
            PARTITION_HANDLE => {
                if value == 0 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                captured.partition = value;
            }
            USER_PHYSICAL_HANDLE => {
                captured.user_physical_handle = value;
                captured.has_user_physical_handle = true;
            }
            _ => {
                if value & !0x3F != 0 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                captured.attribute_flags = value;
            }
        }
    }
    Ok(captured)
}

/// MiCaptureSectionCreateExtendedParameters(Parameters, Count, PreviousMode).
pub fn capture_section_create(parameters: u64, count: u32, user: bool) -> Result<SectionCreate, u32> {
    let mut captured = SectionCreate::default();
    if !check_vector(parameters, count, user)? {
        return Ok(captured);
    }
    for index in 0..count {
        let (kind, value) = entry(parameters, index, user)?;
        if !(SECTION_USER_PHYSICAL_FLAGS..=SECTION_NUMA_NODE).contains(&kind) || captured.present & (1 << kind) != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        captured.present |= 1 << kind;
        if kind == SECTION_USER_PHYSICAL_FLAGS {
            if value & !1 != 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            captured.user_physical_flags = Some(value as u32);
        } else {
            captured.numa_node_plus_one = numa_node(value, false)?.0;
        }
    }
    Ok(captured)
}
