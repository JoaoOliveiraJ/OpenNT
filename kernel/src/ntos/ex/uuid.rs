//! Geração de UUIDs do Executive (ExUuidCreate): versão 4 com variante DCE,
//! a partir de um gerador xorshift32 semeado no TSC.

use crate::hal::cpu;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

/// Gerador xorshift32 semeado no TSC (ExUuidCreate).
static IDENTIFIER_STATE: SpinLock<u32> = SpinLock::new(0);

fn next_random32() -> u32 {
    let mut state = IDENTIFIER_STATE.lock();
    if *state == 0 {
        *state = match (cpu::rdtsc() as u32) ^ 0x9E37_79B9 {
            0 => 0x2545_F491,
            seed => seed,
        };
    }
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    *state
}

/// Duas saídas do gerador; os 64 bits saem exatos, sem arredondar os bits
/// baixos.
fn next_random64() -> u64 {
    let low = next_random32() as u64;
    low | (next_random32() as u64) << 32
}

/// UUID versão 4 com variante DCE.
pub fn create(pointer: u64) {
    let low = next_random64();
    let high = next_random64();
    guest::write64(pointer, low);
    guest::write64(pointer + 8, high);
    guest::write8(pointer + 6, (guest::read8(pointer + 6) & 0x0F) | 0x40);
    guest::write8(pointer + 8, (guest::read8(pointer + 8) & 0x3F) | 0x80);
}
