//! `CurrentControlSet\Control\TimeZoneInformation`: o fuso de uma instalação
//! nova configurada no UTC: todos os vieses 0, sem datas de troca, os nomes
//! MUI do tzres.dll para o UTC (-932 e -931), a chave do fuso "UTC",
//! DynamicDaylightTimeDisabled 0 e o ActiveTimeBias 0 que o boot usa para
//! ler o relógio da CMOS.
//!
//! Dados puros, como as outras tabelas de `cm/seed.rs`: o `xtask` também os
//! inclui, para pôr no relógio da máquina virtual a hora deste fuso (o que
//! um PC com o Windows guarda no RTC).

use alloc::vec::Vec;

use super::seed::{SeedKey, REG_DWORD, REG_SZ};

const REG_BINARY: u32 = 3;

/// Bias (UTC − local, em minutos).
pub const BIAS: i32 = 0;
pub const STANDARD_BIAS: i32 = 0;
pub const DAYLIGHT_BIAS: i32 = 0;
/// ActiveTimeBias: o viés em vigor quando a hive foi gravada.
pub const ACTIVE_TIME_BIAS: i32 = 0;
pub const STANDARD_NAME: &str = "@tzres.dll,-932";
pub const DAYLIGHT_NAME: &str = "@tzres.dll,-931";
pub const TIME_ZONE_KEY_NAME: &str = "UTC";
/// StandardStart e DaylightStart (TIME_FIELDS de 16 bytes): sem troca.
pub const STANDARD_START: [u8; 16] = [0; 16];
pub const DAYLIGHT_START: [u8; 16] = [0; 16];

/// A chave, na ordem dos valores da instalação.
pub fn seed_keys() -> Vec<SeedKey> {
    let mut key = SeedKey::new("CurrentControlSet\\Control\\TimeZoneInformation");
    key.dword("Bias", BIAS as u32)
        .value("DaylightBias", REG_DWORD, (DAYLIGHT_BIAS as u32).to_le_bytes().to_vec())
        .text("DaylightName", REG_SZ, DAYLIGHT_NAME)
        .value("DaylightStart", REG_BINARY, DAYLIGHT_START.to_vec())
        .dword("StandardBias", STANDARD_BIAS as u32)
        .text("StandardName", REG_SZ, STANDARD_NAME)
        .value("StandardStart", REG_BINARY, STANDARD_START.to_vec())
        .text("TimeZoneKeyName", REG_SZ, TIME_ZONE_KEY_NAME)
        .dword("DynamicDaylightTimeDisabled", 0)
        .dword("ActiveTimeBias", ACTIVE_TIME_BIAS as u32);
    alloc::vec![key]
}
