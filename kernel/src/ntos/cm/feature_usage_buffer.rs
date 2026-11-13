//! Banco nativo de relatos de uso — `system32/ntos/cm/feature-usage-buffer.js`.
//!
//! 64 relatos; produtores reservam primeiro a contagem e depois um bit, e o
//! consumidor só drena um banco fora de uso pelos produtores. Layout de
//! 0x310 bytes: ocupação +0, descartes +4, bitmap +8 e 64 slots de 12 bytes
//! a partir de +0x10 (tentativas + relato de 8 bytes).

use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

pub const SIZE: u64 = 0x310;
pub const CAPACITY: u32 = 64;
const INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const NOT_FOUND: u32 = 0xC000_0225;

/// Soma por compare-exchange e devolve o valor anterior.
fn add_atomic_count(pointer: u64, delta: u32) -> Result<u32, KernelError> {
    loop {
        let previous = guest::read32(pointer);
        if guest::compare_exchange32(pointer, previous, previous.wrapping_add(delta))? == previous {
            return Ok(previous);
        }
    }
}

/// Reserva capacidade e um slot livre antes de ler o relato; banco cheio
/// conta um descarte sem tocar o ponteiro de entrada.
pub fn enqueue(buffer: u64, report: u64) -> Result<u32, KernelError> {
    let reserved = loop {
        let reserved = guest::read32(buffer);
        if reserved == CAPACITY {
            add_atomic_count(buffer + 4, 1)?;
            return Ok(INSUFFICIENT_RESOURCES);
        }
        if guest::compare_exchange32(buffer, reserved, reserved + 1)? == reserved {
            break reserved;
        }
    };
    loop {
        let occupied = guest::read64_single(buffer + 8);
        let Some(slot) = (0..CAPACITY).map(|offset| (reserved + offset) % CAPACITY).find(|&slot| occupied & (1u64 << slot) == 0) else {
            return Err(KernelError::new("feature-usage bitmap/count ownership corrupted"));
        };
        // O bit reserva o slot com exclusividade depois da contagem.
        if guest::compare_exchange64(buffer + 8, occupied, occupied | 1u64 << slot)? != occupied {
            continue;
        }
        guest::write64(buffer + 0x14 + slot as u64 * 12, guest::read64_single(report));
        return Ok(0);
    }
}

/// Percorre o bitmap de um banco exclusivo, entrega os relatos elegíveis e
/// atualiza tentativas; devolve quantos relatos ficaram retidos.
pub fn drain(buffer: u64, mut send: impl FnMut(u64) -> u32, retry_previous: bool) -> u32 {
    let mut retained = 0;
    for slot in 0..CAPACITY as u64 {
        let mask = 1u64 << slot;
        if guest::read64(buffer + 8) & mask == 0 {
            continue;
        }
        let slot_pointer = buffer + 0x10 + slot * 12;
        let previous = guest::read32(slot_pointer);
        if previous != 0 && !retry_previous {
            continue;
        }
        let status = send(slot_pointer + 4);
        let attempts = previous.wrapping_add(1);
        guest::write32(slot_pointer, attempts);
        // Direção medida na referência: falha diferente de NOT_FOUND com ao
        // menos cinco tentativas mantém o slot.
        if status & 0x8000_0000 != 0 && status != NOT_FOUND && attempts >= 5 {
            retained += 1;
            continue;
        }
        guest::write64(slot_pointer, 0);
        guest::write32(slot_pointer + 8, 0);
        guest::write64(buffer + 8, guest::read64(buffer + 8) & !mask);
        guest::write32(buffer, guest::read32(buffer) - 1);
    }
    retained
}

pub fn count(buffer: u64) -> u32 {
    guest::read32(buffer)
}

pub fn dropped(buffer: u64) -> u32 {
    guest::read32(buffer + 4)
}
