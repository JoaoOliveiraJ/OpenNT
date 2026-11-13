//! Posse da entrada de PspSetContextThreadInternal — `system32/ntos/ps/thread-context-input.js`.
//!
//! KernelMode conserva o buffer real do chamador; UserMode captura só os
//! campos selecionados. Não enfileira APC nem informa conclusão.

use crate::ntos::ps::context::registers::{self, INTEGER, SIZE};
use crate::ntos::mm::memory_map::USER_ADDRESS_LIMIT;
use crate::ntos::mm::{page_residency, paging};
use crate::ntos::ps::user::state;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const AV: u32 = 0xC000_0005;
const MISALIGNED: u32 = 0x8000_0002;
const NO_MEMORY: u32 = 0xC000_009A;

/// Uma página comprometida não residente pode ser trazida em PASSIVE/APC;
/// páginas alheias ao CONTEXT não são tocadas.
fn readable(pointer: u64, length: u64) -> bool {
    if pointer.checked_add(length).is_none_or(|end| end > USER_ADDRESS_LIMIT) {
        return false;
    }
    if state::probe_user_read(pointer, length) {
        return true;
    }
    let last = (pointer + length - 1) & !0xFFF;
    let mut page = pointer & !0xFFF;
    while page <= last {
        let flags = paging::access_flags(page);
        let present_user = paging::PAGE_PRESENT | paging::PAGE_USER;
        if flags & present_user != present_user && (flags & paging::PAGE_PRESENT != 0 || !page_residency::fault(page, 4)) {
            return false;
        }
        page += 0x1000;
    }
    state::probe_user_read(pointer, length)
}

fn ranges(flags: u32) -> alloc::vec::Vec<(u64, u64)> {
    let mut selected = alloc::vec::Vec::new();
    if flags & 1 != 0 {
        selected.extend([(0xF8, 8), (0x98, 8), (0x38, 2), (0x42, 2), (0x44, 4)]);
    }
    if flags & 2 != 0 {
        selected.extend(INTEGER.iter().map(|&offset| (offset, 8)));
    }
    if flags & 4 != 0 {
        selected.push((0x3A, 8));
    }
    if flags & 8 != 0 {
        selected.extend([(0x34, 4), (0x100, 0x1A0)]);
    }
    if flags & 0x10 != 0 {
        selected.extend([(0x48, 48), (0x4B0, 32)]);
    }
    selected
}

/// CONTEXT capturado: a fonte (buffer do chamador ou cópia própria).
pub struct Captured {
    pub source: u64,
    pub flags: u32,
    owned: bool,
}

impl Captured {
    pub fn release(&mut self) {
        if self.owned {
            self.owned = false;
            guest::free_bytes(self.source);
        }
    }
}

pub fn capture(pointer: u64, mode: u8) -> Result<Result<Captured, u32>, KernelError> {
    let flag_address = pointer.wrapping_add(0x30);
    if mode != 0 && !readable(flag_address.min(USER_ADDRESS_LIMIT), 4) {
        return Ok(Err(AV));
    }
    // O original lê as flags antes do alinhamento, da extensão total e do
    // acesso aos campos selecionados; falhas de kernel não viram status.
    let flags = guest::read32(flag_address);
    let (status, flags) = registers::validate(flags, mode, false);
    if status != 0 {
        return Ok(Err(status));
    }
    if mode == 0 {
        return Ok(Ok(Captured { source: pointer, flags, owned: false }));
    }
    if pointer & 15 != 0 {
        return Ok(Err(MISALIGNED));
    }
    if pointer.checked_add(SIZE).is_none_or(|end| end > USER_ADDRESS_LIMIT) {
        return Ok(Err(AV));
    }
    for (offset, length) in ranges(flags) {
        if !readable(pointer + offset, length) {
            return Ok(Err(AV));
        }
    }
    let storage = guest::alloc_aligned(SIZE, 16, false);
    if storage == 0 {
        return Ok(Err(NO_MEMORY));
    }
    let mut captured = Captured { source: storage, flags, owned: true };
    if let Err(error) = registers::capture_registers(storage, pointer, flags) {
        captured.release();
        return Err(error);
    }
    Ok(Ok(captured))
}
