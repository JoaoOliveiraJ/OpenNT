//! CSPs instalados — `system32/ntos/cm/crypto-defaults.js`.
//!
//! Registra o RSAENH presente no disco; nomes, tipos e caminho da DLL
//! correspondem ao catálogo usado pelos binários. Não cria chaves nem
//! recipientes criptográficos.

use core::sync::atomic::{AtomicBool, Ordering};

use super::registry;
use crate::rtl::KernelError;

static INITIALIZED: AtomicBool = AtomicBool::new(false);

const DEFAULTS_PATH: &str = "\\Registry\\Machine\\Software\\Microsoft\\Cryptography\\Defaults";

enum Data<'a> {
    Text(&'a str),
    Number(u32),
}

fn write_missing_values(relative: &str, defaults: &[(&str, u32, Data)]) -> Result<(), KernelError> {
    let handle = registry::open_or_create(&(alloc::string::String::from(DEFAULTS_PATH) + relative), None)?;
    for (name, value_type, data) in defaults {
        if registry::get_value(handle, name).is_none() {
            let bytes = match data {
                Data::Text(text) => registry::encode_wide(text),
                Data::Number(value) => value.to_le_bytes().to_vec(),
            };
            registry::set_value(handle, name, *value_type, bytes);
        }
    }
    registry::close_handle(handle);
    Ok(())
}

/// Publica provedores e tipos ausentes; marca a inicialização só depois de
/// completar as inscrições.
pub fn initialize() -> Result<(), KernelError> {
    if INITIALIZED.load(Ordering::Acquire) {
        return Ok(());
    }
    for (name, provider_type) in [
        ("Microsoft Base Cryptographic Provider v1.0", 1),
        ("Microsoft Enhanced Cryptographic Provider v1.0", 1),
        ("Microsoft Strong Cryptographic Provider", 1),
        ("Microsoft RSA SChannel Cryptographic Provider", 12),
        ("Microsoft Enhanced RSA and AES Cryptographic Provider", 24),
    ] {
        write_missing_values(&(alloc::string::String::from("\\Provider\\") + name), &[("Image Path", 1, Data::Text("%SystemRoot%\\system32\\rsaenh.dll")), ("Type", 4, Data::Number(provider_type)), ("SigInFile", 4, Data::Number(0))])?;
    }
    for (provider_type, name, description) in [
        (1, "Microsoft Strong Cryptographic Provider", "RSA Full (Signature and Key Exchange)"),
        (12, "Microsoft RSA SChannel Cryptographic Provider", "RSA SChannel"),
        (24, "Microsoft Enhanced RSA and AES Cryptographic Provider", "RSA Full and AES"),
    ] {
        write_missing_values(&alloc::format!("\\Provider Types\\Type {provider_type:03}"), &[("Name", 1, Data::Text(name)), ("TypeName", 1, Data::Text(description))])?;
    }
    INITIALIZED.store(true, Ordering::Release);
    Ok(())
}
