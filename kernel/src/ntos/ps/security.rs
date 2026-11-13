//! Segurança do Process Manager: o token primário de cada EPROCESS
//! (PsReferencePrimaryToken/PsDereferencePrimaryToken), as consultas de
//! atributos de segurança do token (SeQuerySecurityAttributesToken,
//! PsQueryProcessAttributesByToken) e as células SeTokenObjectType/SeExports.
//!
//! Usam os tokens e as referências mantidos pelo kernel; o gerenciador de
//! processos fornece o token primário de cada EPROCESS e o serializador de
//! atributos calcula o layout nativo da resposta.

use alloc::string::String;
use alloc::vec::Vec;

use super::process;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::UnicodeString;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_data;
use crate::ntos::se::security_attributes::{self, OutputWriter};
use crate::ntos::se::token::tokens::{self, Token};
use crate::rtl::KernelError;

/// Token do kernel; o nome da operação identifica o erro de uso.
fn owned_token(pointer: u64, operation: &str) -> Result<Token, KernelError> {
    tokens::get(pointer).ok_or_else(|| KernelError::new(alloc::format!("{operation}: invalid token")))
}

struct GuestWriter {
    base: u64,
}

impl OutputWriter for GuestWriter {
    // O serializador escolhe os offsets do layout nativo; cada escrita é um MOV.
    fn u8(&mut self, offset: u64, value: u8) {
        guest::write(self.base + offset, value);
    }
    fn u16(&mut self, offset: u64, value: u16) {
        guest::write(self.base + offset, value);
    }
    fn u32(&mut self, offset: u64, value: u32) {
        guest::write(self.base + offset, value);
    }
    fn u64(&mut self, offset: u64, value: u64) {
        guest::write(self.base + offset, value);
    }
}

/// SeQuerySecurityAttributesToken: filtra os atributos do token e os copia
/// para o buffer no layout nativo. Também usado por consumidores internos.
pub fn query_attributes(token_pointer: u64, names_pointer: u64, name_count: u32, output: u64, output_length: u32, returned_length: u64) -> Result<u32, KernelError> {
    if (output != 0) != (output_length != 0) {
        return Ok(0xC000_000D);
    }
    let token = owned_token(token_pointer, "SeQuerySecurityAttributesToken")?;
    // SAFETY: PULONG ReturnLength do chamador de kernel.
    let returned_length = unsafe { Field::<u32>::at(returned_length) };
    returned_length.set(0);
    // A seleção começa com todos; os filtros só valem para a lista não vazia.
    let all = &token.security_attributes;
    let mut selected = all.clone();
    if !all.is_empty() && names_pointer != 0 {
        // Valida todos os UNICODE_STRING antes de ler os nomes.
        let mut descriptors = Vec::new();
        let mut odd_length = false;
        // SAFETY: UNICODE_STRING Attributes[NumberOfAttributes] do chamador de kernel.
        for descriptor in unsafe { UnicodeString::array_at(names_pointer, name_count as usize) } {
            let length = descriptor.length.get();
            let maximum = descriptor.maximum_length.get();
            let text = descriptor.buffer.get();
            if length == 0 || maximum == 0 || length > maximum || text == 0 {
                return Ok(0xC000_000D);
            }
            descriptors.push((text, length));
            if length & 1 != 0 {
                odd_length = true;
            }
        }
        // Só pares completos de bytes viram unidades UTF-16.
        let names: Vec<String> = descriptors
            .iter()
            .map(|&(text, length)| {
                let bytes = guest::read_bytes(text, (length as usize / 2) * 2);
                let units: Vec<u16> = bytes.chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]])).collect();
                String::from_utf16_lossy(&units)
            })
            .collect();
        // Os nomes dos tokens têm comprimento par: um filtro ímpar não casa.
        let filtered = if odd_length { None } else { security_attributes::select(all, Some(&names))? };
        match filtered {
            Some(attributes) => selected = attributes,
            None => return Ok(0xC000_0225),
        }
    } else if !all.is_empty() && name_count != 0 {
        return Err(KernelError::new("SeQuerySecurityAttributesToken: null filter array"));
    }
    // Mede antes de escrever: buffer curto recebe só o tamanho necessário.
    let size = match security_attributes::measure(&selected) {
        Ok(size) => size,
        Err(status) => return Ok(status),
    };
    if (output_length as u64) < size {
        returned_length.set(size as u32);
        return Ok(0xC000_0023);
    }
    // Lista não vazia zera o buffer todo; a vazia toca só o cabeçalho.
    let clear = if all.is_empty() { 16 } else { output_length as u64 };
    guest::write_bytes(output, &alloc::vec![0; clear as usize]);
    let status = security_attributes::copy_out(&selected, output, output_length as u64, &mut GuestWriter { base: output }, !all.is_empty());
    returned_length.set(size as u32);
    Ok(status)
}

/// PsQueryProcessAttributesByToken: presença dos atributos de aplicativo do
/// sistema e de identidade de pacote, independente de flags e valores (nada
/// é deduzido do nome).
pub fn process_attributes(token_pointer: u64, system_application: u64, package_identity: u64) -> Result<u64, KernelError> {
    if system_application == 0 && package_identity == 0 {
        return Ok(0);
    }
    let token = owned_token(token_pointer, "PsQueryProcessAttributesByToken")?;
    let present = |name: &str| -> Result<u8, KernelError> { Ok(security_attributes::select(&token.security_attributes, Some(&[String::from(name)]))?.is_some() as u8) };
    if system_application != 0 {
        // SAFETY: PBOOLEAN de saída do chamador de kernel.
        unsafe { Field::<u8>::at(system_application) }.set(present("WIN://SYSAPPID")?);
    }
    if package_identity != 0 {
        // SAFETY: PBOOLEAN de saída do chamador de kernel.
        unsafe { Field::<u8>::at(package_identity) }.set(present("WIN://PKG")?);
    }
    Ok(0)
}

/// PsReferencePrimaryToken: retém o token primário antes de entregar seu
/// endereço.
pub fn reference_primary_token(process: u64) -> Result<u64, KernelError> {
    let token = process::get_primary_token(process).ok_or_else(|| KernelError::new("PsReferencePrimaryToken: invalid process"))?;
    tokens::retain(token)?;
    Ok(token)
}

/// PsDereferencePrimaryToken: devolve exatamente uma referência adquirida
/// pelo chamador.
pub fn dereference_primary_token(token: u64) -> Result<(), KernelError> {
    if tokens::get(token).is_none() {
        return Err(KernelError::new("PsDereferencePrimaryToken: invalid token"));
    }
    tokens::release(token)?;
    Ok(())
}

/// Célula exportada SeTokenObjectType: o valor é o endereço da célula, não
/// uma cópia.
pub fn token_object_type_cell() -> u64 {
    kernel_data::address("SeTokenObjectType").unwrap_or_else(|error| panic!("SeTokenObjectType: {error}"))
}

/// Célula exportada SeExports.
pub fn exports_cell() -> u64 {
    kernel_data::address("SeExports").unwrap_or_else(|error| panic!("SeExports: {error}"))
}
