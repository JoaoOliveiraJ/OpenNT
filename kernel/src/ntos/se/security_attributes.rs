//! Atributos de segurança de tokens.
//!
//! TOKEN_SECURITY_ATTRIBUTE_V1 usa UNICODE_STRING com tamanho explícito. A
//! identidade de pacote fica ausente para processos que não pertencem a um.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::ntos::rtl::unicode_case;
use crate::rtl::KernelError;

const SUPPORTED_TYPES: [u16; 7] = [1, 2, 3, 4, 5, 6, 0x10];

#[derive(Clone, Debug, PartialEq)]
pub enum AttributeValue {
    /// Tipos 1 (INT64), 2 (UINT64) e 6 (BOOLEAN).
    Integer(u64),
    /// Tipo 3 (STRING).
    Text(String),
    /// Tipo 4 (FQBN).
    Fqbn { version: u64, name: String },
    /// Tipos 5 (SID) e 0x10 (OCTET_STRING).
    Bytes(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct SecurityAttribute {
    pub name: String,
    pub kind: u16,
    pub flags: u32,
    pub values: Vec<AttributeValue>,
}

/// Copia nomes, flags e valores; na herança, a flag 1 (não herdar) elimina.
pub fn clone(attributes: &[SecurityAttribute], inherit: bool) -> Vec<SecurityAttribute> {
    attributes.iter().filter(|attribute| !inherit || attribute.flags & 1 == 0).cloned().collect()
}

fn equal_names(left: &str, right: &str) -> Result<bool, KernelError> {
    let left: Vec<u16> = left.encode_utf16().collect();
    let right: Vec<u16> = right.encode_utf16().collect();
    if left.len() != right.len() {
        return Ok(false);
    }
    for (&a, &b) in left.iter().zip(right.iter()) {
        if a != b && unicode_case::upcase_char(a)? != unicode_case::upcase_char(b)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Seleciona na ordem pedida (tabela NLS); um nome ausente invalida tudo.
/// Nomes repetidos preservam entradas repetidas.
pub fn select(attributes: &[SecurityAttribute], names: Option<&[String]>) -> Result<Option<Vec<SecurityAttribute>>, KernelError> {
    let Some(names) = names else { return Ok(Some(attributes.to_vec())) };
    let mut result = Vec::new();
    for name in names {
        let mut found = None;
        for attribute in attributes {
            if equal_names(&attribute.name, name)? {
                found = Some(attribute.clone());
                break;
            }
        }
        match found {
            Some(attribute) => result.push(attribute),
            None => return Ok(None),
        }
    }
    Ok(Some(result))
}

/// Destino das escritas do layout (deslocamentos relativos à base).
pub trait OutputWriter {
    fn u8(&mut self, offset: u64, value: u8);
    fn u16(&mut self, offset: u64, value: u16);
    fn u32(&mut self, offset: u64, value: u32);
    fn u64(&mut self, offset: u64, value: u64);
}

struct Layout<'a> {
    base: u64,
    size: u64,
    limit: u64,
    writer: Option<&'a mut dyn OutputWriter>,
}

impl Layout<'_> {
    /// O cálculo com base zero alinha offsets; a cópia alinha endereços.
    fn reserve(&mut self, length: u64, alignment: u64) -> Result<u64, u32> {
        let remainder = self.base % alignment;
        let aligned = (self.size + remainder).div_ceil(alignment) * alignment - remainder;
        let end = aligned.checked_add(length).ok_or(0xC000_0095u32)?;
        if end > self.limit {
            return Err(0x8000_0005);
        }
        self.size = end;
        Ok(aligned)
    }

    fn counted_string(&mut self, descriptor: u64, text: &str, alignment: u64) -> Result<(), u32> {
        let units: Vec<u16> = text.encode_utf16().collect();
        if units.len() > 32767 {
            return Err(0xC000_000D);
        }
        let length = units.len() as u64 * 2;
        let offset = self.reserve(length, alignment)?;
        let base = self.base;
        if let Some(writer) = self.writer.as_mut() {
            writer.u16(descriptor, length as u16);
            writer.u16(descriptor + 2, length as u16);
            writer.u64(descriptor + 8, base + offset);
            for (index, &unit) in units.iter().enumerate() {
                writer.u16(offset + index as u64 * 2, unit);
            }
        }
        Ok(())
    }
}

/// Calcula e, com `writer`, grava o layout. Strings têm MaximumLength igual a
/// Length, sem NUL; arrays vazios preservam o ponteiro alinhado.
fn layout_attributes(
    attributes: &[SecurityAttribute],
    base: u64,
    writer: Option<&mut dyn OutputWriter>,
    limit: u64,
    array_present: bool,
) -> Result<u64, u32> {
    let mut layout = Layout { base, size: 16 + attributes.len() as u64 * 40, limit, writer };
    if layout.size > limit {
        return Err(0x8000_0005);
    }
    if let Some(writer) = layout.writer.as_mut() {
        writer.u32(0, 1);
        writer.u32(4, attributes.len() as u32);
        writer.u64(8, if array_present { base + 16 } else { 0 });
    }
    for (index, attribute) in attributes.iter().enumerate() {
        let at = 16 + index as u64 * 40;
        if let Some(writer) = layout.writer.as_mut() {
            writer.u16(at + 16, attribute.kind);
            writer.u32(at + 20, attribute.flags);
            writer.u32(at + 24, attribute.values.len() as u32);
        }
        layout.counted_string(at, &attribute.name, 2)?;
        if !SUPPORTED_TYPES.contains(&attribute.kind) {
            return Err(0xC000_000D);
        }
        let stride = match attribute.kind {
            4 => 24,
            3 | 5 | 0x10 => 16,
            _ => 8,
        };
        let array = layout.reserve(stride * attribute.values.len() as u64, 8)?;
        let base = layout.base;
        if let Some(writer) = layout.writer.as_mut() {
            writer.u64(at + 32, base + array);
        }
        for (value_index, value) in attribute.values.iter().enumerate() {
            let value_at = array + value_index as u64 * stride;
            match (attribute.kind, value) {
                (1 | 2 | 6, AttributeValue::Integer(number)) => {
                    if let Some(writer) = layout.writer.as_mut() {
                        writer.u64(value_at, *number);
                    }
                }
                (3, AttributeValue::Text(text)) => layout.counted_string(value_at, text, 1)?,
                (4, AttributeValue::Fqbn { version, name }) => {
                    // O nome inteiro é validado antes de escrever a versão.
                    layout.counted_string(value_at + 8, name, 1)?;
                    if let Some(writer) = layout.writer.as_mut() {
                        writer.u64(value_at, *version);
                    }
                }
                (5 | 0x10, AttributeValue::Bytes(bytes)) => {
                    let payload = layout.reserve(bytes.len() as u64, 1)?;
                    let base = layout.base;
                    if let Some(writer) = layout.writer.as_mut() {
                        writer.u64(value_at, base + payload);
                        writer.u32(value_at + 8, bytes.len() as u32);
                        for (offset, &byte) in bytes.iter().enumerate() {
                            writer.u8(payload + offset as u64, byte);
                        }
                    }
                }
                _ => return Err(0xC000_000D),
            }
        }
    }
    Ok(layout.size)
}

/// Tamanho sem produzir bytes; erros de contrato devolvem o NTSTATUS.
pub fn measure(attributes: &[SecurityAttribute]) -> Result<u64, u32> {
    layout_attributes(attributes, 0, None, u64::MAX, !attributes.is_empty())
}

/// Escreve pelo `writer` e invalida o cabeçalho numa falha de contrato
/// quando a capacidade comporta seus 16 bytes.
pub fn copy_out(attributes: &[SecurityAttribute], base: u64, length: u64, writer: &mut dyn OutputWriter, array_present: bool) -> u32 {
    match layout_attributes(attributes, base, Some(&mut *writer), length, array_present) {
        Ok(_) => 0,
        Err(status) => {
            if length >= 16 {
                for offset in 0..16 {
                    writer.u8(offset, 0);
                }
            }
            status
        }
    }
}

struct BufferWriter<'a>(&'a mut [u8]);

impl OutputWriter for BufferWriter<'_> {
    fn u8(&mut self, offset: u64, value: u8) {
        self.0[offset as usize] = value;
    }
    fn u16(&mut self, offset: u64, value: u16) {
        self.0[offset as usize..offset as usize + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn u32(&mut self, offset: u64, value: u32) {
        self.0[offset as usize..offset as usize + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn u64(&mut self, offset: u64, value: u64) {
        self.0[offset as usize..offset as usize + 8].copy_from_slice(&value.to_le_bytes());
    }
}

/// Os mesmos bytes num buffer, com ponteiros relativos à base do convidado.
pub fn encode(attributes: &[SecurityAttribute], base: u64) -> Result<Vec<u8>, u32> {
    let present = !attributes.is_empty();
    let size = layout_attributes(attributes, base, None, u64::MAX, present)?;
    let mut bytes = vec![0u8; size as usize];
    layout_attributes(attributes, base, Some(&mut BufferWriter(&mut bytes)), u64::MAX, present)?;
    Ok(bytes)
}
