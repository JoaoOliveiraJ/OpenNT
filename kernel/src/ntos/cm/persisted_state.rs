//! RtlGetPersistedStateLocation — `system32/ntos/cm/persisted-state.js`.
//!
//! Consulta o mapa de redirecionamento da hive. Chave de origem ausente usa o
//! caminho padrão do chamador; valor ausente numa chave existente é erro.

use alloc::string::String;
use alloc::vec::Vec;

use super::registry;
use crate::ntos::{mm::guest_memory as guest, rtl::guest_strings};

pub const ROOT: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\StateSeparation\\RedirectionMap\\";

/// Tipo 0 = chave, 1 = arquivo. Valida REG_SZ, informa o tamanho em bytes
/// com o NUL e só copia quando a saída comporta o texto inteiro.
pub fn query(source_name: u64, custom_value_name: u64, default_path: u64, location_type: u32, output: u64, capacity: u32, required_length: u64) -> u32 {
    if location_type > 1 {
        return 0xC000_00F1;
    }
    if source_name == 0 {
        return 0xC000_000D;
    }
    let source = guest_strings::read_wide_string(source_name);
    let key_path = String::from(ROOT) + if location_type == 0 { "Keys\\" } else { "Files\\" } + &source;
    let handle = registry::open(&key_path).unwrap_or(0);
    let mut bytes: Vec<u8>;
    if handle != 0 {
        let name = if custom_value_name != 0 { guest_strings::read_wide_string(custom_value_name) } else { String::new() };
        let configured = registry::get_value(handle, &name);
        registry::close_handle(handle);
        let Some(configured) = configured else { return 0xC000_0034 };
        if configured.value_type != 1 {
            return 0xC000_0024;
        }
        bytes = configured.data;
        // Bytes que não formam unidades UTF-16 são recusados; valores sem
        // terminador recebem dois bytes nulos.
        if bytes.len() % 2 != 0 {
            return 0xC000_000D;
        }
        if bytes.is_empty() || bytes[bytes.len() - 1] != 0 || bytes[bytes.len() - 2] != 0 {
            bytes.extend_from_slice(&[0, 0]);
        }
    } else {
        if default_path == 0 {
            return 0xC000_0034;
        }
        bytes = registry::encode_wide(&guest_strings::read_wide_string(default_path));
    }
    if required_length != 0 {
        guest::write32(required_length, bytes.len() as u32);
    }
    // Capacidade insuficiente: BUFFER_OVERFLOW sem cópia parcial.
    if (capacity as usize) < bytes.len() {
        return 0x8000_0005;
    }
    if output == 0 {
        return 0xC000_000D;
    }
    guest::write_bytes(output, &bytes);
    0
}
