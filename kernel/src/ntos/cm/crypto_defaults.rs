//! CSPs instalados (`SOFTWARE\Microsoft\Cryptography\Defaults`).
//!
//! Registra o RSAENH presente no disco; nomes, tipos e caminho da DLL
//! correspondem ao catálogo usado pelos binários. Não cria chaves nem
//! recipientes criptográficos.
//!
//! Dados puros da hive SOFTWARE (veja `cm/seed.rs`): o `xtask` grava estas
//! chaves no arquivo da hive e o kernel só as semeia em memória quando o
//! arquivo falta.

use alloc::format;
use alloc::vec::Vec;

use super::seed::{SeedKey, REG_SZ};

const DEFAULTS: &str = "Microsoft\\Cryptography\\Defaults";

/// (nome do provedor, tipo).
const PROVIDERS: &[(&str, u32)] = &[
    ("Microsoft Base Cryptographic Provider v1.0", 1),
    ("Microsoft Enhanced Cryptographic Provider v1.0", 1),
    ("Microsoft Strong Cryptographic Provider", 1),
    ("Microsoft RSA SChannel Cryptographic Provider", 12),
    ("Microsoft Enhanced RSA and AES Cryptographic Provider", 24),
];

/// (tipo, provedor padrão, descrição do tipo).
const PROVIDER_TYPES: &[(u32, &str, &str)] = &[
    (1, "Microsoft Strong Cryptographic Provider", "RSA Full (Signature and Key Exchange)"),
    (12, "Microsoft RSA SChannel Cryptographic Provider", "RSA SChannel"),
    (24, "Microsoft Enhanced RSA and AES Cryptographic Provider", "RSA Full and AES"),
];

/// As chaves `Provider\<nome>` e `Provider Types\Type NNN`.
pub fn seed_keys() -> Vec<SeedKey> {
    let mut keys = Vec::new();
    for &(name, provider_type) in PROVIDERS {
        let mut key = SeedKey::new(&format!("{DEFAULTS}\\Provider\\{name}"));
        key.text("Image Path", REG_SZ, "%SystemRoot%\\system32\\rsaenh.dll").dword("Type", provider_type).dword("SigInFile", 0);
        keys.push(key);
    }
    for &(provider_type, name, description) in PROVIDER_TYPES {
        let mut key = SeedKey::new(&format!("{DEFAULTS}\\Provider Types\\Type {provider_type:03}"));
        key.text("Name", REG_SZ, name).text("TypeName", REG_SZ, description);
        keys.push(key);
    }
    keys
}
