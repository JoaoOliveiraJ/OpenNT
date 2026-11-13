//! Conversão de proteção Win32 (PAGE_*) para a máscara de proteção do Mm — o
//! MiMakeProtectionMask do `protect.c` do NT.
//!
//! Máscara MM: bits 0..2 = acesso (1 READONLY, 2 EXECUTE, 3 EXECUTE_READ,
//! 4 READWRITE, 5 WRITECOPY, 6 EXECUTE_READWRITE, 7 EXECUTE_WRITECOPY; 0x18 é
//! NOACCESS), 0x08 = NOCACHE, 0x10 = GUARD, 0x18 sobre um acesso =
//! WRITECOMBINE. As duas tabelas são as do ntoskrnl 19041 (RVA 0x18198 para o
//! nibble baixo, 0x18188 para o alto), conferidas contra o binário.

/// PAGE_NOACCESS..PAGE_WRITECOPY (nibble baixo).
const LOW_NIBBLE: [u8; 16] = [0x00, 0x18, 0x01, 0xFF, 0x04, 0xFF, 0xFF, 0xFF, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
/// PAGE_EXECUTE..PAGE_EXECUTE_WRITECOPY (nibble alto).
const HIGH_NIBBLE: [u8; 16] = [0x00, 0x02, 0x03, 0xFF, 0x06, 0xFF, 0xFF, 0xFF, 0x07, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

pub const PAGE_GUARD: u32 = 0x100;
pub const PAGE_NOCACHE: u32 = 0x200;
pub const PAGE_WRITECOMBINE: u32 = 0x400;
/// Bits de cache da máscara (`mask >> 3`: 0 cacheado, 1 não cacheado,
/// 2 guarda, 3 write-combine).
pub const MASK_NOCACHE: u32 = 0x08;
pub const MASK_GUARD: u32 = 0x10;
pub const MASK_WRITECOMBINE: u32 = 0x18;

/// MiMakeProtectionMask; `None` é o 0xFFFFFFFF (proteção inválida) do original.
pub fn make_mask(protect: u32) -> Option<u32> {
    if protect >= 0x800 {
        return None;
    }
    let low = protect & 0xF;
    let mask = if low != 0 {
        if protect & 0xF0 != 0 {
            return None;
        }
        LOW_NIBBLE[low as usize]
    } else {
        let high = (protect >> 4) & 0xF;
        if high == 0 {
            return None;
        }
        HIGH_NIBBLE[high as usize]
    };
    if mask == 0xFF {
        return None;
    }
    let mut mask = mask as u32;
    if protect & (PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE) == 0 {
        return Some(mask);
    }
    if protect & PAGE_GUARD != 0 {
        if mask == MASK_WRITECOMBINE || protect & (PAGE_NOCACHE | PAGE_WRITECOMBINE) != 0 {
            return None;
        }
        mask |= MASK_GUARD;
    }
    if protect & PAGE_NOCACHE != 0 {
        if mask == MASK_WRITECOMBINE || protect & PAGE_WRITECOMBINE != 0 {
            return None;
        }
        return Some(mask | MASK_NOCACHE);
    }
    if protect & PAGE_WRITECOMBINE != 0 {
        if mask == MASK_WRITECOMBINE || mask & 2 != 0 {
            return None;
        }
        return Some(mask | MASK_WRITECOMBINE);
    }
    Some(mask)
}
