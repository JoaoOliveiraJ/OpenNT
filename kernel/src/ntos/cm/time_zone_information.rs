//! `CurrentControlSet\Control\TimeZoneInformation`: o fuso desta máquina,
//! com os valores da instalação (E. South America Standard Time, UTC−3 sem
//! horário de verão): Bias 180, StandardBias 0, DaylightBias −60, as datas
//! de troca zeradas (sem troca), os nomes MUI do tzres.dll, a chave do fuso,
//! DynamicDaylightTimeDisabled 0 e o ActiveTimeBias 180 que o boot usa para
//! ler o relógio da CMOS, que guarda a hora local.
//!
//! Dados puros, como as outras tabelas de `cm/seed.rs`: o `xtask` também os
//! inclui, para pôr no relógio da máquina virtual a hora local deste fuso
//! (o que um PC com o Windows guarda no RTC).

use alloc::vec::Vec;

use super::seed::{SeedKey, REG_DWORD, REG_SZ};

const REG_BINARY: u32 = 3;

/// Bias (UTC − local, em minutos).
pub const BIAS: i32 = 180;
pub const STANDARD_BIAS: i32 = 0;
pub const DAYLIGHT_BIAS: i32 = -60;
/// ActiveTimeBias: o viés em vigor quando a hive foi gravada.
pub const ACTIVE_TIME_BIAS: i32 = 180;
pub const STANDARD_NAME: &str = "@tzres.dll,-42";
pub const DAYLIGHT_NAME: &str = "@tzres.dll,-41";
pub const TIME_ZONE_KEY_NAME: &str = "E. South America Standard Time";
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
