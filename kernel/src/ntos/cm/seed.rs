//! O conteúdo estático da hive SYSTEM: as chaves e valores que vêm de
//! tabelas fixas (as chaves de serviço dos drivers que o boot instala, os
//! parâmetros e as classes de dispositivo, e a configuração do Session
//! Manager no boot do processo inicial real).
//!
//! É uma fonte só para dois consumidores: o `xtask`, que grava com estas
//! chaves o arquivo `\SystemRoot\System32\config\SYSTEM` do volume, e o
//! kernel, que carrega esse arquivo no boot e só semeia as mesmas chaves em
//! memória quando o arquivo não existe (`cm/hive_list.rs`). Por isso este
//! arquivo e as tabelas que ele reúne (`cm/session_manager.rs`,
//! `cm/service/boot_services.rs` e `cm/service/inbox_drivers.rs`) são
//! dados puros: não usam nada do kernel e o `xtask` os inclui por `#[path]`
//! na mesma árvore de módulos (`cm`, `cm::service`).
//!
//! Os caminhos são relativos à raiz da hive SYSTEM
//! (`\Registry\Machine\System`) e os dados já vêm codificados como o
//! Registro os guarda (UTF-16LE com NUL, DWORD little-endian, REG_MULTI_SZ
//! com o NUL final extra).

use alloc::string::String;
use alloc::vec::Vec;

pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;

/// Uma chave da hive com os valores (nome, tipo, dados) na ordem de criação.
pub struct SeedKey {
    pub path: String,
    pub values: Vec<(String, u32, Vec<u8>)>,
}

impl SeedKey {
    pub fn new(path: &str) -> SeedKey {
        SeedKey { path: String::from(path), values: Vec::new() }
    }

    pub fn value(&mut self, name: &str, value_type: u32, data: Vec<u8>) -> &mut SeedKey {
        self.values.push((String::from(name), value_type, data));
        self
    }

    pub fn text(&mut self, name: &str, value_type: u32, text: &str) -> &mut SeedKey {
        self.value(name, value_type, wide(text))
    }

    pub fn dword(&mut self, name: &str, value: u32) -> &mut SeedKey {
        self.value(name, REG_DWORD, value.to_le_bytes().to_vec())
    }

    pub fn strings(&mut self, name: &str, strings: &[&str]) -> &mut SeedKey {
        self.value(name, REG_MULTI_SZ, multi(strings))
    }
}

/// UTF-16LE com NUL.
pub fn wide(text: &str) -> Vec<u8> {
    text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

/// REG_MULTI_SZ: cada texto com NUL e o NUL final.
pub fn multi(strings: &[&str]) -> Vec<u8> {
    let mut data: Vec<u8> = strings.iter().flat_map(|text| wide(text)).collect();
    data.extend_from_slice(&[0, 0]);
    data
}

/// As chaves estáticas da hive SYSTEM, na ordem em que o boot as cria.
/// `smss_boot`: o boot do processo inicial real (`--initial-process=smss`).
pub fn system_keys(smss_boot: bool) -> Vec<SeedKey> {
    let mut keys = super::service::boot_services::driver_keys();
    keys.extend(super::service::inbox_drivers::seed_keys());
    keys.extend(super::service::boot_services::parameter_keys());
    if smss_boot {
        keys.extend(super::session_manager::seed_keys());
    }
    keys
}
