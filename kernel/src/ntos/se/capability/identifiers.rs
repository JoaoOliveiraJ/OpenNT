//! Derivação dos SIDs de capability — `system32/ntos/se/capability-identifiers.js`.
//!
//! Interna a RtlCapabilityCheck: os SIDs vêm do nome completo em maiúsculas
//! NLS (SHA-256), sem consultar nem alterar o token.

use crate::ntos::rtl::{sha256, unicode_case};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

/// A posição é a subautoridade dos 12 nomes legados do Windows; o SID de
/// grupo continua sendo por hash mesmo para eles.
const LEGACY_CAPABILITY_NAMES: [&str; 12] = [
    "INTERNETCLIENT",
    "INTERNETCLIENTSERVER",
    "PRIVATENETWORKCLIENTSERVER",
    "PICTURESLIBRARY",
    "VIDEOSLIBRARY",
    "MUSICLIBRARY",
    "DOCUMENTSLIBRARY",
    "ENTERPRISEAUTHENTICATION",
    "SHAREDUSERCERTIFICATES",
    "REMOVABLESTORAGE",
    "APPOINTMENTS",
    "CONTACTS",
];

/// Ordem de publicação do cabeçalho nativo (vale com buffers sobrepostos).
fn initialize_identifier(pointer: u64, sub_authority_count: u8, authority: u8) {
    guest::write8(pointer + 1, sub_authority_count);
    guest::write8(pointer, 1);
    guest::write32(pointer + 2, 0);
    guest::write16(pointer + 6, (authority as u16) << 8);
}

/// Recebe um UNICODE_STRING e buffers de 44 (grupo) e 48 (capability)
/// bytes. Falha de alocação mantém as saídas zeradas, como no kernel.
pub fn derive(name: u64, group: u64, capability: u64) -> Result<u32, KernelError> {
    if name == 0 || group == 0 || capability == 0 {
        // O original executa INT 29h (FAST_FAIL_INVALID_ARG).
        return Err(KernelError::with_status("Capability SID derivation: null required pointer", 0xC000_0409));
    }
    // A saída de capability é zerada primeiro.
    guest::write_bytes(capability, &[0; 48]);
    guest::write_bytes(group, &[0; 44]);
    let length = guest::read16(name) as u64;
    // O heap do convidado recusa tamanho zero; um byte representa a posse.
    let uppercase = guest::alloc_raw(length.max(1));
    if uppercase == 0 {
        return Ok(0xC000_0017);
    }
    let result = (|| -> Result<(), KernelError> {
        let source = guest::read64(name + 8);
        let mut text = alloc::string::String::new();
        // RtlUpcaseUnicodeString converte WCHARs inteiros; com comprimento
        // ímpar o byte final do pool também entra no hash.
        for index in 0..length / 2 {
            let unit = guest::read16(source + index * 2);
            let upper = if (0x61..=0x7A).contains(&unit) {
                unit - 0x20
            } else if unit >= 0xC0 {
                unicode_case::upcase_char(unit)?
            } else {
                unit
            };
            guest::write16(uppercase + index * 2, upper);
            text.push(char::from_u32(upper as u32).unwrap_or('\u{FFFD}'));
        }
        let bytes = guest::read_bytes(uppercase, length as usize);
        let digest = sha256::hash_bytes(&bytes);
        let legacy = if length & 1 != 0 { None } else { LEGACY_CAPABILITY_NAMES.iter().position(|&legacy| legacy == text) };
        initialize_identifier(group, 9, 5);
        guest::write32(group + 8, 32);
        guest::write_bytes(group + 12, &digest);
        if let Some(index) = legacy {
            initialize_identifier(capability, 2, 15);
            guest::write32(capability + 8, 3);
            guest::write32(capability + 12, index as u32 + 1);
        }
        // No caminho por hash o texto é liberado antes de publicar o SID.
        guest::free_bytes(uppercase);
        if legacy.is_none() {
            initialize_identifier(capability, 10, 15);
            guest::write32(capability + 8, 3);
            guest::write32(capability + 12, 1024);
            guest::write_bytes(capability + 16, &digest);
        }
        Ok(())
    })();
    if result.is_err() {
        guest::free_bytes(uppercase);
    }
    result.map(|_| 0)
}
