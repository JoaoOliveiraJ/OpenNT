//! Chaves de controle do PnP e do Errata Manager na hive SYSTEM, as da
//! instalação do Windows desta máquina:
//! - `Control\PnP` (PollBootPartitionTimeout) e `Control\PnP\Pci\CardList`,
//!   a lista de pontes de host que o PciAddDevice do pci.sys abre (a chave
//!   precisa existir para o AddDevice do barramento raiz); cada valor
//!   REG_BINARY tem 16 bytes: o 1 da versão, o fabricante e o dispositivo
//!   PCI e oito zeros;
//! - `Control\Errata\Dynamic`, vazia, que a fase 1 do EmInitSystem abre e
//!   enumera.
//! Dados puros, incluídos também pelo `xtask`.

use alloc::vec::Vec;

use super::seed::SeedKey;

/// REG_BINARY.
const REG_BINARY: u32 = 3;

/// `Control\PnP\Pci\CardList`: (nome, fabricante, dispositivo).
const CARD_LIST: &[(&str, u16, u16)] = &[
    ("Ali", 0x10B9, 0x1521),
    ("Intel 82439HX", 0x8086, 0x1250),
    ("Intel 82439TX", 0x8086, 0x7100),
    ("Intel 82441FX", 0x8086, 0x1237),
    ("Intel 82443BX1", 0x8086, 0x7190),
    ("Intel 82443BX2", 0x8086, 0x7192),
    ("Intel 82443GX", 0x8086, 0x71A0),
    ("Intel 82443LX/EX", 0x8086, 0x7180),
    ("Toshiba", 0x1179, 0x0601),
    ("VIA Tech1", 0x1106, 0x0501),
    ("VIA Tech2", 0x1106, 0x0691),
];

pub fn seed_keys() -> Vec<SeedKey> {
    let mut keys = Vec::new();
    let mut key = SeedKey::new("CurrentControlSet\\Control\\PnP");
    key.dword("PollBootPartitionTimeout", 30000);
    keys.push(key);
    let mut key = SeedKey::new("CurrentControlSet\\Control\\PnP\\Pci\\CardList");
    for &(name, vendor, device) in CARD_LIST {
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&vendor.to_le_bytes());
        data.extend_from_slice(&device.to_le_bytes());
        data.extend_from_slice(&[0; 8]);
        key.value(name, REG_BINARY, data);
    }
    keys.push(key);
    keys.push(SeedKey::new("CurrentControlSet\\Control\\Errata\\Dynamic"));
    keys
}
