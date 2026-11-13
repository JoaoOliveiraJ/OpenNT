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
    fn u8(&mut self, offset: u64, value: u8) {
        guest::write8(self.base + offset, value);
    }
    fn u16(&mut self, offset: u64, value: u16) {
        guest::write16(self.base + offset, value);
    }
    fn u32(&mut self, offset: u64, value: u32) {
        guest::write32(self.base + offset, value);
    }
    fn u64(&mut self, offset: u64, value: u64) {
        guest::write64(self.base + offset, value);
    }
}

/// SeQuerySecurityAttributesToken: filtra os atributos do token e os copia
/// para o buffer no layout nativo. Também usado por consumidores internos.
pub fn query_attributes(token_pointer: u64, names_pointer: u64, name_count: u32, output: u64, output_length: u32, returned_length: u64) -> Result<u32, KernelError> {
    if (output != 0) != (output_length != 0) {
        return Ok(0xC000_000D);
    }
    let token = owned_token(token_pointer, "SeQuerySecurityAttributesToken")?;
    guest::write32(returned_length, 0);
    // A seleção começa com todos; os filtros só valem para a lista não vazia.
    let all = &token.security_attributes;
    let mut selected = all.clone();
    if !all.is_empty() && names_pointer != 0 {
        // Valida todos os UNICODE_STRING antes de ler os nomes.
        let mut descriptors = Vec::new();
        let mut odd_length = false;
        for index in 0..name_count as u64 {
            let descriptor = names_pointer + index * 16;
            let length = guest::read16(descriptor);
            let maximum = guest::read16(descriptor + 2);
            let text = guest::read64(descriptor + 8);
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
                let units: Vec<u16> = (0..length as u64 / 2).map(|unit| guest::read16(text + unit * 2)).collect();
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
        guest::write32(returned_length, size as u32);
        return Ok(0xC000_0023);
    }
    // Lista não vazia zera o buffer todo; a vazia toca só o cabeçalho.
    let clear = if all.is_empty() { 16 } else { output_length as u64 };
    for offset in 0..clear {
        guest::write8(output + offset, 0);
    }
    let status = security_attributes::copy_out(&selected, output, output_length as u64, &mut GuestWriter { base: output }, !all.is_empty());
    guest::write32(returned_length, size as u32);
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
        guest::write8(system_application, present("WIN://SYSAPPID")?);
    }
    if package_identity != 0 {
        guest::write8(package_identity, present("WIN://PKG")?);
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
