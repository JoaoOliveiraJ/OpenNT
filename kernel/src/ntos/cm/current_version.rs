//! As pastas de programas da instalação
//! (`SOFTWARE\Microsoft\Windows\CurrentVersion`).
//!
//! O DriverEntry do luafv.sys abre esta chave (GetStaticEntryRoots) e lê
//! ProgramFilesDir e ProgramFilesDir (x86) para montar as raízes protegidas
//! da virtualização de arquivos; sem a chave ele falha com o status do
//! ZwOpenKey (STATUS_OBJECT_NAME_NOT_FOUND). Os valores são os desta
//! instalação do Windows 10 19041.
//!
//! Dados puros da hive SOFTWARE (veja `cm/seed.rs`): o `xtask` grava estas
//! chaves no arquivo da hive e o kernel só as semeia em memória quando o
//! arquivo falta.

use alloc::vec::Vec;

use super::seed::{SeedKey, REG_EXPAND_SZ, REG_SZ};

const CURRENT_VERSION: &str = "Microsoft\\Windows\\CurrentVersion";

/// (valor, tipo, dado).
const VALUES: &[(&str, u32, &str)] = &[
    ("ProgramFilesDir", REG_SZ, "C:\\Program Files"),
    ("CommonFilesDir", REG_SZ, "C:\\Program Files\\Common Files"),
    ("ProgramFilesDir (x86)", REG_SZ, "C:\\Program Files (x86)"),
    ("CommonFilesDir (x86)", REG_SZ, "C:\\Program Files (x86)\\Common Files"),
    ("CommonW6432Dir", REG_SZ, "C:\\Program Files\\Common Files"),
    ("DevicePath", REG_EXPAND_SZ, "%SystemRoot%\\inf"),
    ("MediaPathUnexpanded", REG_EXPAND_SZ, "%SystemRoot%\\Media"),
    ("ProgramFilesPath", REG_EXPAND_SZ, "%ProgramFiles%"),
    ("ProgramW6432Dir", REG_SZ, "C:\\Program Files"),
];

/// A chave `CurrentVersion` com as pastas.
pub fn seed_keys() -> Vec<SeedKey> {
    let mut key = SeedKey::new(CURRENT_VERSION);
    for &(name, value_type, data) in VALUES {
        key.text(name, value_type, data);
    }
    alloc::vec![key]
}
