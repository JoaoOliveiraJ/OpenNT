//! Banco nativo de relatos de uso.
//!
//! 64 relatos; produtores reservam primeiro a contagem e depois um bit, e o
//! consumidor só drena um banco fora de uso pelos produtores. Layout de
//! 0x310 bytes ([`UsageBank`]): ocupação +0, descartes +4, bitmap +8 e 64
//! slots de 12 bytes a partir de +0x10 (tentativas + relato de 8 bytes).
//! Contagens e bitmap são compartilhados entre CPUs: só operações atômicas.

use core::sync::atomic::Ordering;

use crate::ntos::inc::types::{Field, NtStruct, RtlFeatureUsageReport};
use crate::rtl::KernelError;

pub const CAPACITY: u32 = 64;
const INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const NOT_FOUND: u32 = 0xC000_0225;

/// Slot do banco: tentativas de entrega e o relato copiado.
#[repr(C)]
struct UsageSlot {
    attempts: Field<u32>,
    report: RtlFeatureUsageReport,
}

/// Banco de relatos (layout do OpenNT, modelado no banco nativo).
#[repr(C)]
struct UsageBank {
    /// Ocupação reservada pelos produtores.
    reserved: Field<u32>,
    /// Relatos descartados com o banco cheio.
    dropped: Field<u32>,
    /// Bitmap dos slots ocupados.
    occupied: Field<u64>,
    slots: [UsageSlot; CAPACITY as usize],
}

// SAFETY: #[repr(C)] só de células e estruturas do NT.
unsafe impl NtStruct for UsageSlot {}
unsafe impl NtStruct for UsageBank {}

const _: () = {
    assert!(core::mem::size_of::<UsageSlot>() == 12);
    assert!(core::mem::offset_of!(UsageBank, occupied) == 8);
    assert!(core::mem::offset_of!(UsageBank, slots) == 0x10);
    assert!(core::mem::size_of::<UsageBank>() == 0x310);
};

pub const SIZE: u64 = core::mem::size_of::<UsageBank>() as u64;

fn bank(buffer: u64) -> &'static UsageBank {
    // SAFETY: bloco de SIZE bytes reservado pelo provedor de relatos.
    unsafe { UsageBank::at(buffer) }
}

/// Reserva capacidade e um slot livre antes de ler o relato; banco cheio
/// conta um descarte sem tocar o ponteiro de entrada.
pub fn enqueue(buffer: u64, report: u64) -> Result<u32, KernelError> {
    let bank = bank(buffer);
    let Ok(reserved) = bank.reserved.atomic().try_update(Ordering::SeqCst, Ordering::SeqCst, |reserved| (reserved != CAPACITY).then_some(reserved + 1)) else {
        bank.dropped.atomic().fetch_add(1, Ordering::SeqCst);
        return Ok(INSUFFICIENT_RESOURCES);
    };
    let bitmap = bank.occupied.atomic();
    loop {
        let occupied = bitmap.load(Ordering::SeqCst);
        let Some(slot) = (0..CAPACITY).map(|offset| (reserved + offset) % CAPACITY).find(|&slot| occupied & (1u64 << slot) == 0) else {
            return Err(KernelError::new("feature-usage bitmap/count ownership corrupted"));
        };
        // O bit reserva o slot com exclusividade depois da contagem.
        if bitmap.compare_exchange(occupied, occupied | 1u64 << slot, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            continue;
        }
        // SAFETY: RTL_FEATURE_USAGE_REPORT do chamador de RtlNotifyFeatureUsage.
        let source = unsafe { RtlFeatureUsageReport::at(report) };
        let target = &bank.slots[slot as usize].report;
        target.feature_id.set(source.feature_id.get());
        target.reporting_kind.set(source.reporting_kind.get());
        target.reporting_options.set(source.reporting_options.get());
        return Ok(0);
    }
}

/// Percorre o bitmap de um banco exclusivo, entrega os relatos elegíveis e
/// atualiza tentativas; devolve quantos relatos ficaram retidos.
pub fn drain(buffer: u64, mut send: impl FnMut(u64) -> u32, retry_previous: bool) -> u32 {
    let bank = bank(buffer);
    let mut retained = 0;
    for (index, slot) in bank.slots.iter().enumerate() {
        let mask = 1u64 << index;
        if bank.occupied.atomic().load(Ordering::SeqCst) & mask == 0 {
            continue;
        }
        let previous = slot.attempts.get();
        if previous != 0 && !retry_previous {
            continue;
        }
        let status = send(slot.report.address());
        let attempts = previous.wrapping_add(1);
        slot.attempts.set(attempts);
        // Direção medida na referência: falha diferente de NOT_FOUND com ao
        // menos cinco tentativas mantém o slot.
        if status & 0x8000_0000 != 0 && status != NOT_FOUND && attempts >= 5 {
            retained += 1;
            continue;
        }
        slot.attempts.set(0);
        slot.report.feature_id.set(0);
        slot.report.reporting_kind.set(0);
        slot.report.reporting_options.set(0);
        // Bitmap e contagem também são tocados pelos produtores (CAS).
        bank.occupied.atomic().fetch_and(!mask, Ordering::SeqCst);
        bank.reserved.atomic().fetch_sub(1, Ordering::SeqCst);
    }
    retained
}

pub fn count(buffer: u64) -> u32 {
    bank(buffer).reserved.atomic().load(Ordering::SeqCst)
}

pub fn dropped(buffer: u64) -> u32 {
    bank(buffer).dropped.atomic().load(Ordering::SeqCst)
}
