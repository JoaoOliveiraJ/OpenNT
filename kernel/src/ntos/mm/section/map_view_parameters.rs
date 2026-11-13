//! Validação nativa (19041) dos parâmetros de vista.
//!
//! Medida antes de o MM original alocar VADs ou tabelas de páginas; não faz
//! busca de objeto nem alocação. A aritmética usa u128, para que somas acima
//! de 2^64 sejam comparadas sem truncar.

const INVALID: u32 = 0xC000_000D;
const PROTECTION: u32 = 0xC000_0045;
const VIEW: u32 = 0xC000_001F;
const U64: u128 = u64::MAX as u128;
const LIMIT: u128 = 0x7FFF_FFFF_0000;
const ACCESS: [u32; 8] = [4, 4, 8, 12, 2, 4, 10, 12];
const COMPATIBILITY: [u32; 8] = [1, 11, 17, 187, 15, 11, 255, 187];

fn base_mask(value: u32) -> Option<i32> {
    Some(match value {
        1 => 24,
        2 => 1,
        4 => 4,
        8 => 5,
        0x10 => 2,
        0x20 => 3,
        0x40 => 6,
        0x80 => 7,
        _ => return None,
    })
}

/// Máscara interna de uma proteção Win32 (GUARD, NOCACHE e WRITECOMBINE
/// inclusos); -1 para combinações inválidas.
pub fn protection(value: u32) -> i32 {
    let Some(mut mask) = base_mask(value & 255) else { return -1 };
    if value >= 0x800 {
        return -1;
    }
    if value & 0x100 != 0 {
        if mask == 24 || value & 0x600 != 0 {
            return -1;
        }
        mask |= 16;
    }
    if value & 0x200 != 0 {
        if mask == 24 || value & 0x400 != 0 {
            return -1;
        }
        mask |= 8;
    }
    if value & 0x400 != 0 {
        if mask == 24 || mask & 2 != 0 {
            return -1;
        }
        mask |= 24;
    }
    mask
}

/// ZeroBits normalizado, máscara e acesso exigido.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    pub zero: u32,
    pub mask: i32,
    pub access: u32,
}

/// ZeroBits abaixo de 32 conta bits altos; acima, é uma máscara (zeros à
/// esquerda); mais de 53 é inválido. Depois, a proteção sem o bit de
/// enclave.
pub fn prefix(zero_bits: u64, protect: u32) -> Result<Prefix, u32> {
    let zero = match zero_bits {
        0 => 0,
        bits if bits < 32 => bits as u32 + 32,
        bits => bits.leading_zeros(),
    };
    if zero > 53 {
        return Err(INVALID);
    }
    let mask = protection(protect & !0x4000_0000);
    if mask < 0 {
        return Err(PROTECTION);
    }
    Ok(Prefix { zero, mask, access: ACCESS[(mask & 7) as usize] })
}

/// Base e tamanho capturados abaixo do limite de usuário e do ZeroBits.
pub fn captured(base: u64, size: u64, zero: u32) -> u32 {
    let (base, size) = (base as u128, size as u128);
    if base >= LIMIT || size > LIMIT - base || base + size > U64 >> zero {
        INVALID
    } else {
        0
    }
}

/// Atributos da seção que a validação consulta.
#[derive(Clone, Copy, Debug, Default)]
pub struct SectionTraits {
    pub is_image: bool,
    pub size: u64,
    pub page_protect: u32,
    pub cache_flags: u32,
}

/// Parâmetros de NtMapViewOfSection(Ex); `numa_nodes` 0 = um nó.
#[derive(Clone, Copy, Debug, Default)]
pub struct MapInput {
    pub zero: u64,
    pub protect: u32,
    pub base: u64,
    pub size: u64,
    pub offset: u64,
    pub allocation: u32,
    pub inherit: u32,
    pub numa_nodes: u32,
    pub commit: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct View {
    pub base: u64,
    pub size: u64,
    pub offset: u64,
    pub upper: u64,
    pub alignment: u64,
    pub protect: u32,
    pub allocation: u32,
    pub inherit: u32,
    pub commit: u64,
    pub preferred_node_plus_one: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decoded {
    View(View),
    Status(u32),
    /// Fronteira de privilégio que o chamador resolve (imagem com páginas
    /// grandes exige SeLockMemoryPrivilege).
    Boundary(&'static str),
}

/// A ordem de verificações do MM nativo: captura, nó NUMA, alinhamento,
/// herança, flags de alocação, proteção contra a da seção, extensão, limite
/// superior, commit, reserva e flags de cache.
pub fn decode(section: &SectionTraits, input: &MapInput, decoded: Option<Prefix>) -> Decoded {
    let decoded = match decoded {
        Some(decoded) => decoded,
        None => match prefix(input.zero, input.protect) {
            Ok(decoded) => decoded,
            Err(status) => return Decoded::Status(status),
        },
    };
    let (mut base, mut size, mut offset) = (input.base as u128, input.size as u128, input.offset as u128);
    let capture_status = captured(input.base, input.size, decoded.zero);
    if capture_status != 0 {
        return Decoded::Status(capture_status);
    }
    let mut allocation = input.allocation;
    let mut protect = input.protect;
    let inherit = input.inherit;
    if allocation & 127 > input.numa_nodes.max(1) {
        return Decoded::Status(INVALID);
    }
    allocation &= !127;
    let alignment: u128 = if !section.is_image && allocation & 0x2000_0000 != 0 { 0x20_0000 } else { 0x1_0000 };
    let mut upper = LIMIT - 1;
    if (base == 0 || section.is_image) && decoded.zero != 0 {
        upper = upper.min(U64 >> decoded.zero);
    }
    if inherit != 1 && inherit != 2 {
        return Decoded::Status(INVALID);
    }
    if (base | offset) & 0xFFFF != 0 {
        return Decoded::Status(0xC000_0220);
    }
    if allocation & 0x9F2B_DFFF != 0 || allocation & 0x4000_0000 != 0 {
        return Decoded::Status(INVALID);
    }
    if protect & 0x4000_0000 != 0 {
        if protect & 0xF0 == 0 {
            return Decoded::Status(INVALID);
        }
        protect &= !0x4000_0000;
    }
    if section.is_image {
        if allocation & 0x2000 != 0 {
            return Decoded::Status(INVALID);
        }
        if allocation & 0x2000_0000 != 0 {
            return Decoded::Boundary("lock_pages_privilege_check");
        }
    } else {
        let maximum = (protection(section.page_protect) & 7) as usize;
        let allowed = COMPATIBILITY[maximum] | 0x700;
        if protect & !allowed != 0 {
            return Decoded::Status(0xC000_004E);
        }
        if allocation & 0x84_0000 != 0 {
            return Decoded::Status(INVALID);
        }
    }
    let section_size = section.size as u128;
    let reserve = allocation & 0x2000 != 0;
    if size + offset > U64 || (size + offset > section_size && !reserve) {
        return Decoded::Status(VIEW);
    }
    if size == 0 {
        size = section_size.wrapping_sub(offset) & U64;
    }
    let offset_delta = offset & (alignment - 1);
    offset -= offset_delta;
    if !section.is_image {
        size += offset_delta;
    }
    if size == 0 || size > 0x7FFF_FFFF_FFFF_FFFF {
        return Decoded::Status(VIEW);
    }
    base &= !(alignment - 1);
    let unrounded = size;
    size = (size + 4095) & !4095;
    if size > U64 {
        return Decoded::Status(VIEW);
    }
    if base > upper {
        return Decoded::Status(INVALID);
    }
    if upper - base + 1 < size {
        return Decoded::Status(if base != 0 { 0xC000_0018 } else { 0xC000_0017 });
    }
    if input.commit as u128 > unrounded && !reserve {
        return Decoded::Status(INVALID);
    }
    if unrounded > section_size && !reserve {
        return Decoded::Status(VIEW);
    }
    if reserve && section.page_protect & 0x44 == 0 {
        return Decoded::Status(0xC000_004E);
    }
    if allocation & 0x80_0000 != 0 && (!section.is_image || allocation & 0x2000_0000 != 0) {
        return Decoded::Status(INVALID);
    }
    let cache = section.cache_flags;
    if cache & 0x8000 != 0 {
        protect = (protect | 0x200) & !0x400;
    }
    if cache & 0x4000 != 0 {
        protect = (protect | 0x400) & !0x200;
    }
    if protection(protect) < 0 {
        return Decoded::Status(PROTECTION);
    }
    Decoded::View(View {
        base: base as u64,
        size: size as u64,
        offset: offset as u64,
        upper: upper as u64,
        alignment: alignment as u64,
        protect,
        allocation,
        inherit,
        commit: input.commit,
        preferred_node_plus_one: input.allocation & 127,
    })
}
