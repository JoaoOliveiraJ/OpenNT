//! Épocas do relógio de parede: milissegundos Unix e o tempo do NT.

/// Milissegundos entre 1601-01-01 e 1970-01-01 (época do NT vs. Unix).
pub const UNIX_TO_NT_EPOCH_MILLISECONDS: u64 = 11_644_473_600_000;

/// Converte milissegundos Unix em unidades de 100 ns desde 1601 (formato
/// de tempo do Windows).
pub fn unix_milliseconds_to_nt_time(milliseconds: u64) -> u64 {
    (milliseconds + UNIX_TO_NT_EPOCH_MILLISECONDS) * 10_000
}

/// O tempo do NT (100 ns desde 1601) em milissegundos Unix (zero antes de
/// 1970).
pub fn nt_time_to_unix_milliseconds(time: u64) -> u64 {
    (time / 10_000).saturating_sub(UNIX_TO_NT_EPOCH_MILLISECONDS)
}
