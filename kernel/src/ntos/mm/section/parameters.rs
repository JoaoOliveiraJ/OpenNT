//! Decodificação dos argumentos de criação de seção.
//!
//! Devolver uma requisição só valida parâmetros; criação, referências de
//! arquivo, commit e publicação do handle pertencem ao gerenciador de seções.

const INVALID: u32 = 0xC000_000D;
const ATTRIBUTES: u32 = 0xC000_00F4;
const PROTECTION: u32 = 0xC000_0045;

/// Máscara de proteção do Mm para cada PAGE_* base.
fn mask_of(base: u32) -> Option<u32> {
    match base {
        2 => Some(1),
        4 => Some(4),
        8 => Some(5),
        0x10 => Some(2),
        0x20 => Some(3),
        0x40 => Some(6),
        0x80 => Some(7),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub flags: u32,
    pub attributes: u32,
    pub page_protect: u32,
    pub protection_mask: u32,
    pub size: u64,
    pub file_handle: u64,
    pub preferred_node_plus_one: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decoded {
    Status(u32),
    /// Handles de partição exigem a busca no Ob antes da proteção.
    Partition { partition_handle: u64, allocation: u32, protect: u32, size: u64, preferred_node_plus_one: u32 },
    Request(Request),
}

pub fn decode(allocation: u32, protect: u32, size: u64, file_handle: u64, numa_nodes: u32, kernel_object: bool) -> Decoded {
    let preferred = allocation & 127;
    let mut attributes = allocation & !127;
    let mut protect = protect;
    let mut flags = 0u32;
    let image_selector = attributes & 0x0210_0000;
    // Nt/Zw validam os atributos de syscall antes do construtor comum;
    // MmCreateSection entra direto (atributos zero chegam à seção reservada).
    if !kernel_object && (attributes & 0x0300_0000 == 0x0300_0000 || attributes & 0x2083_FFFF != 0 || attributes & 0x0F10_0000 == 0) {
        return Decoded::Status(ATTRIBUTES);
    }
    if !kernel_object && attributes & 0x0310_0000 != 0 && attributes & if image_selector != 0 { 0xCC04_0000 } else { 0xCC44_0000 } != 0 {
        return Decoded::Status(ATTRIBUTES);
    }
    if !kernel_object && (attributes & 0x0C00_0000 == 0x0C00_0000 || attributes & 0x8008_0000 == 0x8008_0000) {
        return Decoded::Status(ATTRIBUTES);
    }
    if !kernel_object && protect & 0x701 != 0 {
        return Decoded::Status(PROTECTION);
    }
    if attributes & 0x0110_0000 == 0x0110_0000 {
        flags |= 0x200;
        attributes &= !0x0010_0000;
    }
    if attributes & 0x0010_0000 != 0 {
        if attributes & 0x0020_0000 != 0 {
            attributes &= !0x0020_0000;
            flags |= 0x40;
        }
        flags |= 0x20;
        attributes &= !0x0010_0000;
        if attributes & 0x0040_0000 != 0 {
            attributes &= !0x0040_0000;
            flags |= 0x100;
        }
        attributes |= 0x0100_0000;
    } else if attributes & 0x0200_0000 != 0 {
        flags |= 0x10;
        if attributes & 0x0040_0000 != 0 {
            attributes &= !0x0040_0000;
            flags |= 0x100;
        }
        attributes = (attributes & !0x0200_0000) | 0x0100_0000;
    }
    if attributes & 0x0004_0000 != 0 {
        if file_handle == 0 {
            return Decoded::Status(INVALID);
        }
        return Decoded::Partition { partition_handle: file_handle, allocation, protect, size, preferred_node_plus_one: preferred };
    }
    if attributes & 0x0100_0000 != 0 {
        if attributes & 0x1000_0000 != 0 {
            if protect != 2 {
                return Decoded::Status(PROTECTION);
            }
            attributes &= !0x1000_0000;
        } else {
            flags |= 0x400;
        }
    } else if attributes & 0x1000_0000 != 0 {
        protect |= 0x200;
    } else if attributes & 0x4000_0000 != 0 {
        protect |= 0x400;
    }
    let base = protect & 255;
    let mask = if kernel_object && base == 1 { Some(24) } else { mask_of(base) };
    let modifiers = protect & 0x700;
    let Some(mask) = mask else { return Decoded::Status(PROTECTION) };
    if protect & !if kernel_object { 0x7FF } else { 0x6FF } != 0
        || (modifiers != 0 && modifiers != 0x100 && modifiers != 0x200 && modifiers != 0x400)
        || (base == 1 && modifiers != 0)
        || (protect & 0x400 != 0 && base & 0xF0 != 0)
    {
        return Decoded::Status(PROTECTION);
    }
    if preferred > numa_nodes {
        return Decoded::Status(INVALID);
    }
    let modifier_mask = if protect & 0x200 != 0 { 8 } else if protect & 0x400 != 0 { 24 } else if protect & 0x100 != 0 { 16 } else { 0 };
    Decoded::Request(Request { flags, attributes, page_protect: protect, protection_mask: mask | modifier_mask, size, file_handle, preferred_node_plus_one: preferred })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PagefileSize {
    pub pages: u64,
    pub rounded_size: u64,
    pub committed: bool,
    pub large: bool,
}

/// Tamanho de uma seção de pagefile. O dono verifica SeLockMemoryPrivilege
/// antes da validação de páginas grandes; nada é alocado aqui.
pub fn pagefile_size(request: &Request) -> Result<PagefileSize, u32> {
    if request.attributes & 0x0100_0000 != 0 {
        return Err(0xC000_0020);
    }
    let large = request.attributes & 0x8000_0000 != 0;
    let committed = request.attributes & 0x0800_0000 != 0;
    if large && !committed {
        return Err(ATTRIBUTES);
    }
    if request.size == 0 {
        return Err(0xC000_00F2);
    }
    if request.size > if committed { 0xFFF_FF00_0000 } else { 0xFFFF_FFFF_FFFF_F000 } {
        return Err(0xC000_0040);
    }
    let pages = request.size.div_ceil(4096);
    if (request.attributes & 0x8_0000 != 0 && pages & 15 != 0) || (large && pages & 511 != 0) {
        return Err(0xC000_00F2);
    }
    Ok(PagefileSize { pages, rounded_size: pages * 4096, committed, large })
}

/// Acesso exigido ao arquivo; MiCreateFileSection recusa estes atributos
/// antes de referenciar o handle.
pub fn file_request(request: &Request) -> Result<u32, u32> {
    if request.attributes & 0x8008_0000 != 0 {
        return Err(ATTRIBUTES);
    }
    Ok([0, 1, 0x20, 0x21, 3, 1, 0x23, 0x21][(request.protection_mask & 7) as usize])
}
