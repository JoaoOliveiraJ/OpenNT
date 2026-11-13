//! GUIDs do Rtl — RtlStringFromGUID (texto alocado) e RtlGenerateClass5Guid
//! (UUID v5 por SHA-1, RFC 4122).
//!
//! GUID nativo: Data1/Data2/Data3 little-endian seguidos dos 8 bytes de
//! Data4. O texto canônico é "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}".

use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::{guest_strings, sha1};

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// RtlStringFromGUID: "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" alocado.
pub fn string_from_guid(guid: u64, output: u64) {
    let mut text = alloc::format!("{{{:08X}-{:04X}-{:04X}-", guest::read32(guid), guest::read16(guid + 4), guest::read16(guid + 6));
    for index in 0..2 {
        text.push_str(&alloc::format!("{:02X}", guest::read8(guid + 8 + index)));
    }
    text.push('-');
    for index in 2..8 {
        text.push_str(&alloc::format!("{:02X}", guest::read8(guid + 8 + index)));
    }
    text.push('}');
    let length = text.len() as u64 * 2;
    let buffer = guest::alloc_bytes(length + 2);
    guest_strings::write_wide_string(buffer, &text);
    guest::write16(output, length as u16);
    guest::write16(output + 2, length as u16 + 2);
    guest::write64(output + 8, buffer);
}

/// RtlGenerateClass5Guid(GUID Namespace, const UCHAR* Name, Len, GUID* Out):
/// UUID v5 (SHA-1, RFC 4122). O GUID por valor (>8 bytes) chega por ponteiro.
/// Devolve o NTSTATUS.
pub fn generate_class5(namespace: u64, name: u64, name_length: usize, output: u64) -> u32 {
    if namespace == 0 || output == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let ns = guest::read_bytes(namespace, 16);
    // Namespace em ordem de rede (big-endian) nos campos Data1/2/3.
    let mut message = Vec::with_capacity(16 + name_length);
    message.extend_from_slice(&[ns[3], ns[2], ns[1], ns[0], ns[5], ns[4], ns[7], ns[6]]);
    message.extend_from_slice(&ns[8..16]);
    if name_length > 0 {
        message.extend_from_slice(&guest::read_bytes(name, name_length));
    }
    let digest = sha1::hash_bytes(&message);
    let mut g = [0u8; 16];
    g.copy_from_slice(&digest[0..16]);
    g[6] = (g[6] & 0x0F) | 0x50; // versão 5
    g[8] = (g[8] & 0x3F) | 0x80; // variante RFC 4122
    // Converte de volta ao layout nativo do GUID (Data1/2/3 little-endian).
    let out = [g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]];
    guest::write_bytes(output, &out);
    0
}
