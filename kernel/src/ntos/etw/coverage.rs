//! Cobertura de telemetria: EtwTelemetryCoverageReport (ntoskrnl 19041).
//!
//! Um driver marca a passagem por um ponto de cobertura
//! (TELEMETRY_COVERAGE_POINT: Name, Hash, LastCoveredRound, Flags). Em IRQL
//! abaixo de DISPATCH_LEVEL e com o ponto habilitado (Flags bit 0 limpo), o
//! ponto entra no registro de cobertura da rodada corrente, uma vez por
//! rodada (LastCoveredRound recebe a rodada); acima disso, ou desabilitado,
//! nada é registrado. Devolve STATUS_SUCCESS. O OpenNT não envia a
//! cobertura a nenhum consumidor: o registro fica no kernel.

use alloc::collections::BTreeMap;
use alloc::string::String;

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::ke::irql;
use crate::ntos::rtl::guest_strings;
use crate::rtl::SpinLock;

/// TELEMETRY_COVERAGE_POINT.
#[repr(C)]
pub struct TelemetryCoveragePoint {
    pub name: Field<u64>,
    pub hash: Field<u32>,
    pub last_covered_round: Field<u32>,
    pub flags: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for TelemetryCoveragePoint {}

const _: () = assert!(core::mem::offset_of!(TelemetryCoveragePoint, flags) == 0x10);

/// O ponto está desabilitado.
const COVERAGE_POINT_DISABLED: u32 = 1;
/// A rodada de coleta corrente (uma só: não há consumidor que a avance).
const CURRENT_ROUND: u32 = 1;

/// Hash -> nome dos pontos cobertos na rodada.
static COVERED: SpinLock<BTreeMap<u32, String>> = SpinLock::new(BTreeMap::new());

/// EtwTelemetryCoverageReport(CoveragePoint).
pub fn report(point: &TelemetryCoveragePoint) -> u32 {
    if irql::get_irql() >= irql::DISPATCH_LEVEL || point.flags.get() & COVERAGE_POINT_DISABLED != 0 {
        return 0;
    }
    if point.last_covered_round.get() == CURRENT_ROUND {
        return 0;
    }
    let name = point.name.get();
    let text = if name != 0 { guest_strings::read_wide_string(name) } else { String::new() };
    COVERED.lock().insert(point.hash.get(), text);
    point.last_covered_round.set(CURRENT_ROUND);
    0
}

/// O nome registrado para o hash, se o ponto foi coberto.
pub fn covered(hash: u32) -> Option<String> {
    COVERED.lock().get(&hash).cloned()
}
