//! Catálogo CNG no registro.
//!
//! Publica os provedores criptográficos instalados (nomes, imagens e
//! algoritmos de `primitive_provider`); não executa algoritmos nem cria
//! material de chave.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use super::primitive_provider::PROVIDERS;
use super::registry;
use crate::rtl::KernelError;

static INITIALIZED: AtomicBool = AtomicBool::new(false);

const ROOT: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Cryptography";
const PROVIDER_NAME: &str = "Microsoft Primitive Provider";

enum Data<'a> {
    Number(u32),
    Text(&'a str),
    Multi(&'a [&'a str]),
}

/// REG_DWORD, REG_SZ ou REG_MULTI_SZ (dois nulos finais).
fn encode(data: &Data) -> (u32, Vec<u8>) {
    let text: String = match data {
        Data::Number(value) => return (4, value.to_le_bytes().to_vec()),
        Data::Text(text) => String::from(*text) + "\0",
        Data::Multi(items) => items.join("\0") + "\0\0",
    };
    let value_type = if matches!(data, Data::Multi(_)) { 7 } else { 1 };
    (value_type, text.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect())
}

fn write_missing_values(relative: &str, defaults: &[(&str, Data)]) -> Result<(), KernelError> {
    let handle = registry::open_or_create(&(String::from(ROOT) + relative), None)?;
    for (name, data) in defaults {
        if registry::get_value(handle, name).is_some() {
            continue;
        }
        let (value_type, bytes) = encode(data);
        registry::set_value(handle, name, value_type, bytes);
    }
    registry::close_handle(handle);
    Ok(())
}

/// Instala só valores ausentes, uma vez por boot; os contextos padrão
/// locais são publicados para a modalidade de usuário.
pub fn initialize() -> Result<(), KernelError> {
    if INITIALIZED.load(Ordering::Acquire) {
        return Ok(());
    }
    write_missing_values("\\Configuration\\Domain", &[])?;
    write_missing_values("\\Configuration\\Local\\Default", &[("Flags", Data::Number(0))])?;
    for mode in PROVIDERS {
        let mode_path = alloc::format!("\\Providers\\{PROVIDER_NAME}\\{}", mode.mode);
        write_missing_values(&mode_path, &[("Image", Data::Text(mode.image))])?;
        for interface in mode.interfaces {
            write_missing_values(&alloc::format!("{mode_path}\\{}", interface.id), &[("", Data::Text(interface.name)), ("Flags", Data::Number(interface.flags)), ("Functions", Data::Multi(interface.functions))])?;
            // Só algoritmos do provedor de usuário entram nos contextos locais.
            if mode.mode != "UM" {
                continue;
            }
            let context = alloc::format!("\\Configuration\\Local\\Default\\{}", interface.id);
            write_missing_values(&context, &[("", Data::Text(interface.name)), ("Functions", Data::Multi(interface.functions))])?;
            for algorithm in interface.functions {
                write_missing_values(&alloc::format!("{context}\\{algorithm}"), &[("Flags", Data::Number(0)), ("Providers", Data::Multi(&[PROVIDER_NAME]))])?;
            }
        }
    }
    INITIALIZED.store(true, Ordering::Release);
    Ok(())
}
