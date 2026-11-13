//! Derivação dos SIDs de capability.
//!
//! Interna a RtlCapabilityCheck: os SIDs vêm do nome completo em maiúsculas
//! NLS (SHA-256), sem consultar nem alterar o token.

use crate::ntos::rtl::{sha256, unicode_case};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{NtStruct, UnicodeString};
use crate::ntos::se::sid;

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
    let identifier = sid::at(pointer);
    identifier.sub_authority_count.set(sub_authority_count);
    identifier.revision.set(1);
    for (index, byte) in identifier.identifier_authority.value.iter().enumerate() {
        byte.set(if index == 5 { authority } else { 0 });
    }
}

/// Recebe um UNICODE_STRING e buffers de 44 (grupo) e 48 (capability)
/// bytes. Falha de alocação mantém as saídas zeradas, como no kernel.
pub fn derive(name: u64, group: u64, capability: u64) -> Result<u32, KernelError> {
    if name == 0 || group == 0 || capability == 0 {
        // O kernel de referência executa INT 29h (FAST_FAIL_INVALID_ARG).
        return Err(KernelError::with_status("Capability SID derivation: null required pointer", 0xC000_0409));
    }
    // A saída de capability é zerada primeiro.
    guest::write_bytes(capability, &[0; 48]);
    guest::write_bytes(group, &[0; 44]);
    // SAFETY: PCUNICODE_STRING do chamador de RtlCapabilityCheck.
    let name = unsafe { UnicodeString::at(name) };
    let length = name.length.get() as u64;
    // O heap do convidado recusa tamanho zero; um byte representa a posse.
    let uppercase = guest::alloc_raw(length.max(1));
    if uppercase == 0 {
        return Ok(0xC000_0017);
    }
    let result = (|| -> Result<(), KernelError> {
        let source = guest::read_bytes(name.buffer.get(), (length / 2 * 2) as usize);
        let mut text = alloc::string::String::new();
        let mut upcased = alloc::vec::Vec::with_capacity(source.len());
        // RtlUpcaseUnicodeString converte WCHARs inteiros; com comprimento
        // ímpar o byte final do pool também entra no hash.
        for pair in source.chunks_exact(2) {
            let unit = u16::from_le_bytes([pair[0], pair[1]]);
            let upper = if (0x61..=0x7A).contains(&unit) {
                unit - 0x20
            } else if unit >= 0xC0 {
                unicode_case::upcase_char(unit)?
            } else {
                unit
            };
            upcased.extend_from_slice(&upper.to_le_bytes());
            text.push(char::from_u32(upper as u32).unwrap_or('\u{FFFD}'));
        }
        guest::write_bytes(uppercase, &upcased);
        let bytes = guest::read_bytes(uppercase, length as usize);
        let digest = sha256::hash_bytes(&bytes);
        let legacy = if length & 1 != 0 { None } else { LEGACY_CAPABILITY_NAMES.iter().position(|&legacy| legacy == text) };
        initialize_identifier(group, 9, 5);
        let group_authorities = sid::sub_authorities(sid::at(group), 9);
        group_authorities[0].set(32);
        // SubAuthority[1..9] = SHA-256 do nome.
        guest::write_bytes(group_authorities[1].address(), &digest);
        if let Some(index) = legacy {
            initialize_identifier(capability, 2, 15);
            let authorities = sid::sub_authorities(sid::at(capability), 2);
            authorities[0].set(3);
            authorities[1].set(index as u32 + 1);
        }
        // No caminho por hash o texto é liberado antes de publicar o SID.
        guest::free_bytes(uppercase);
        if legacy.is_none() {
            initialize_identifier(capability, 10, 15);
            let authorities = sid::sub_authorities(sid::at(capability), 10);
            authorities[0].set(3);
            authorities[1].set(1024);
            // SubAuthority[2..10] = SHA-256 do nome.
            guest::write_bytes(authorities[2].address(), &digest);
        }
        Ok(())
    })();
    if result.is_err() {
        guest::free_bytes(uppercase);
    }
    result.map(|_| 0)
}
