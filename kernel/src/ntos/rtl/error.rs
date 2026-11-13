//! Tradução de NTSTATUS para códigos de erro Win32 —
//! RtlNtStatusToDosError e RtlNtStatusToDosErrorNoTeb.
//!
//! Subconjunto da tabela real usado pelos drivers; sem mapeamento =
//! ERROR_MR_MID_NOT_FOUND (317).

/// RtlNtStatusToDosError: a tabela real (subconjunto usado por drivers);
/// sem mapeamento = ERROR_MR_MID_NOT_FOUND (317).
pub fn status_to_dos_error(status: u32) -> u32 {
    match status {
        0x0000_0000 => 0,
        0x8000_0005 => 234,
        0xC000_0001 => 31,
        0xC000_0002 => 1,
        0xC000_0004 => 24,
        0xC000_0005 => 998,
        0xC000_0008 => 6,
        0xC000_000D => 87,
        0xC000_0017 => 8,
        0xC000_0022 => 5,
        0xC000_0023 => 122,
        0xC000_0034 => 2,
        0xC000_0035 => 183,
        0xC000_003A => 3,
        0xC000_0043 => 32,
        0xC000_009A => 8,
        0xC000_009D => 1167,
        0xC000_00A5 => 31,
        0xC000_00BB => 50,
        0xC000_0185 => 1117,
        0xC000_0225 => 1168,
        _ => 317,
    }
}
