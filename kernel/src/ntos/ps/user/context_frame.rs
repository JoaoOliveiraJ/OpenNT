//! Escritas reais num CONTEXT de usuário salvo — `system32/ntos/ps/user/context-frame.js`.
//!
//! Quando o frame da syscall ainda está vivo, a HAL copia estas faixas
//! brutas depois de salvar o resultado da syscall; não escolhe grupos de
//! registradores nem saneia valores.

use alloc::vec::Vec;

use crate::hal::amd64::usermode;
use crate::ntos::ps::context::registers::INTEGER;

/// Faixas preparadas para um CONTEXT salvo.
pub struct Prepared {
    context: u64,
    ranges: Vec<(u32, u32)>,
}

impl Prepared {
    /// `true` quando o frame vivo da syscall reterá as faixas.
    pub fn retain(&self) -> bool {
        !self.ranges.is_empty() && usermode::retain_user_context_ranges(self.context, &self.ranges)
    }
}

pub fn prepare(context: u64, flags: u32) -> Prepared {
    let selected = |bit: u32| flags & (0x10_0000 | bit) == 0x10_0000 | bit;
    let mut ranges = Vec::new();
    if selected(1) {
        ranges.extend([(0x38, 2), (0x42, 6), (0x98, 8), (0xF8, 8)]);
    }
    if selected(2) {
        ranges.extend(INTEGER.iter().map(|&offset| (offset as u32, 8)));
    }
    if selected(8) {
        ranges.extend([(0x34, 4), (0x100, 0x1A0)]);
    }
    if selected(0x10) {
        ranges.push((0x48, 48));
    }
    Prepared { context, ranges }
}

pub fn retain(context: u64, flags: u32) -> bool {
    prepare(context, flags).retain()
}
