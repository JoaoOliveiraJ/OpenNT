//! Atributos de segurança de tokens.
//!
//! TOKEN_SECURITY_ATTRIBUTE_V1 usa UNICODE_STRING com tamanho explícito. A
//! identidade de pacote fica ausente para processos que não pertencem a um.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::offset_of;

use crate::ntos::inc::types::{AuthzbasepSecurityAttributesInformation, Field, NtStruct, UnicodeString};
use crate::ntos::inc::types::extra_obpsse::{AuthzbasepSecurityAttribute, AuthzbasepSecurityAttributeValue};
use crate::ntos::mm::guest_memory as guest;
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

/// Nomes iguais sem caixa (a tabela de maiúsculas do NLS).
pub fn equal_names(left: &str, right: &str) -> Result<bool, KernelError> {
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

/// Um UNICODE_STRING do chamador (Length, MaximumLength e Buffer em +8),
/// lido com sonda.
fn capture_unicode(address: u64) -> Result<String, u32> {
    let length = guest::try_read::<u16>(address).map_err(|_| 0xC000_0005u32)? as usize;
    let buffer = guest::try_read::<u64>(address + 8).map_err(|_| 0xC000_0005u32)?;
    if length % 2 != 0 || (length != 0 && buffer == 0) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let bytes = guest::try_read_bytes(buffer, length).map_err(|_| 0xC000_0005u32)?;
    let units: Vec<u16> = bytes.chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]])).collect();
    Ok(String::from_utf16_lossy(&units))
}

/// Captura um TOKEN_SECURITY_ATTRIBUTES_INFORMATION (versão 1: Version,
/// AttributeCount e o vetor TOKEN_SECURITY_ATTRIBUTE_V1 de 40 bytes em +8),
/// como o SepCaptureTokenSecurityAttributesInformation: nome, tipo, flags e
/// os valores de cada atributo. Versão diferente de 1, tipo desconhecido ou
/// atributo sem valores dão STATUS_INVALID_PARAMETER; uma página inacessível,
/// STATUS_ACCESS_VIOLATION.
pub fn capture_information(address: u64) -> Result<Vec<SecurityAttribute>, u32> {
    let read16 = |at: u64| guest::try_read::<u16>(at).map_err(|_| 0xC000_0005u32);
    let read32 = |at: u64| guest::try_read::<u32>(at).map_err(|_| 0xC000_0005u32);
    let read64 = |at: u64| guest::try_read::<u64>(at).map_err(|_| 0xC000_0005u32);
    if read16(address)? != 1 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let count = read32(address + 4)? as u64;
    let array = read64(address + 8)?;
    if count != 0 && array == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut attributes = Vec::with_capacity(count as usize);
    for index in 0..count {
        let entry = array + index * 40;
        let name = capture_unicode(entry)?;
        let kind = read16(entry + 16)?;
        let flags = read32(entry + 20)?;
        let value_count = read32(entry + 24)? as u64;
        let values_address = read64(entry + 32)?;
        if !SUPPORTED_TYPES.contains(&kind) || value_count == 0 || values_address == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut values = Vec::with_capacity(value_count as usize);
        for value in 0..value_count {
            values.push(match kind {
                1 | 2 | 6 => AttributeValue::Integer(read64(values_address + value * 8)?),
                3 => AttributeValue::Text(capture_unicode(values_address + value * 16)?),
                4 => AttributeValue::Fqbn { version: read64(values_address + value * 24)?, name: capture_unicode(values_address + value * 24 + 8)? },
                _ => {
                    let at = values_address + value * 16;
                    let (pointer, length) = (read64(at)?, read32(at + 8)? as usize);
                    AttributeValue::Bytes(if length == 0 { Vec::new() } else { guest::try_read_bytes(pointer, length).map_err(|_| 0xC000_0005u32)? })
                }
            });
        }
        attributes.push(SecurityAttribute { name, kind, flags, values });
    }
    Ok(attributes)
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

// ---- Formato interno do token -------------------------------------------------
//
// O TOKEN_ACCESS_INFORMATION carrega o conjunto no formato interno do token,
// como o AuthzBasepCopyoutInternalSecurityAttributes do ntoskrnl 19041: o
// AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION (contagem, lista de atributos,
// contagem e lista de trabalho), um AuthzbasepSecurityAttribute por
// atributo e, depois de todos eles, por atributo, o nome (alinhado a 2) e os
// valores (AuthzbasepSecurityAttributeValue, alinhados a 8) seguidos dos
// dados de strings, SIDs e octetos. As listas são LIST_ENTRY com endereços
// absolutos.

const INTERNAL_HEADER: u64 = AuthzbasepSecurityAttributesInformation::SIZE;
const INTERNAL_ATTRIBUTE: u64 = AuthzbasepSecurityAttribute::SIZE;
const INTERNAL_VALUE: u64 = AuthzbasepSecurityAttributeValue::SIZE;
const STATUS_INTEGER_OVERFLOW: u32 = 0xC000_0095;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

const HEADER_COUNT: u64 = offset_of!(AuthzbasepSecurityAttributesInformation, security_attribute_count) as u64;
const HEADER_LIST: u64 = offset_of!(AuthzbasepSecurityAttributesInformation, security_attributes_list) as u64;
const HEADER_WORKING_LIST: u64 = offset_of!(AuthzbasepSecurityAttributesInformation, working_security_attributes_list) as u64;
const ATTRIBUTE_NAME: u64 = offset_of!(AuthzbasepSecurityAttribute, name) as u64;
const ATTRIBUTE_TYPE: u64 = offset_of!(AuthzbasepSecurityAttribute, value_type) as u64;
const ATTRIBUTE_FLAGS: u64 = offset_of!(AuthzbasepSecurityAttribute, flags) as u64;
const ATTRIBUTE_VALUE_COUNT: u64 = offset_of!(AuthzbasepSecurityAttribute, value_count) as u64;
const ATTRIBUTE_VALUES: u64 = offset_of!(AuthzbasepSecurityAttribute, values) as u64;
const ATTRIBUTE_LIST_60: u64 = offset_of!(AuthzbasepSecurityAttribute, list_60) as u64;
const VALUE_DATA: u64 = offset_of!(AuthzbasepSecurityAttributeValue, value) as u64;
const VALUE_NAME: u64 = offset_of!(AuthzbasepSecurityAttributeValue, name) as u64;

fn utf16_bytes(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Bytes que o valor deixa depois do vetor de valores do atributo.
fn internal_value_data(kind: u16, value: &AttributeValue) -> Result<Vec<u8>, u32> {
    match (kind, value) {
        (1 | 2 | 6, AttributeValue::Integer(_)) => Ok(Vec::new()),
        (3, AttributeValue::Text(text)) | (4, AttributeValue::Fqbn { name: text, .. }) => Ok(utf16_bytes(text)),
        (5 | 0x10, AttributeValue::Bytes(bytes)) => Ok(bytes.clone()),
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

/// Tamanho do formato interno, em ULONG como o
/// AuthzBasepGetInternalSecurityAttributesCopyoutBufferSize.
pub fn internal_size(attributes: &[SecurityAttribute]) -> Result<u32, u32> {
    let add = |size: u32, more: u64| u32::try_from(size as u64 + more).map_err(|_| STATUS_INTEGER_OVERFLOW);
    let mut size = add(0, INTERNAL_HEADER + attributes.len() as u64 * INTERNAL_ATTRIBUTE)?;
    for attribute in attributes {
        size = add(size, 1)? & !1;
        size = add(size, attribute.name.encode_utf16().count() as u64 * 2)?;
        size = add(size, 7)? & !7;
        size = add(size, attribute.values.len() as u64 * INTERNAL_VALUE)?;
        for value in &attribute.values {
            size = add(size, internal_value_data(attribute.kind, value)?.len() as u64)?;
        }
    }
    Ok(size)
}

/// Imagem do formato interno com ponteiros absolutos a partir de `base`.
struct InternalImage {
    bytes: Vec<u8>,
    base: u64,
}

impl InternalImage {
    fn put(&mut self, offset: u64, value: &[u8]) {
        self.bytes[offset as usize..offset as usize + value.len()].copy_from_slice(value);
    }
    fn get64(&self, offset: u64) -> u64 {
        let mut word = [0u8; 8];
        word.copy_from_slice(&self.bytes[offset as usize..offset as usize + 8]);
        u64::from_le_bytes(word)
    }
    fn empty_list(&mut self, head: u64) {
        let address = self.base + head;
        self.put(head, &address.to_le_bytes());
        self.put(head + 8, &address.to_le_bytes());
    }
    /// InsertTailList(head, entry).
    fn insert_tail(&mut self, head: u64, entry: u64) {
        let last = self.get64(head + 8);
        let (head_address, entry_address) = (self.base + head, self.base + entry);
        self.put(entry, &head_address.to_le_bytes());
        self.put(entry + 8, &last.to_le_bytes());
        self.put(last - self.base, &entry_address.to_le_bytes());
        self.put(head + 8, &entry_address.to_le_bytes());
    }
    /// UNICODE_STRING com MaximumLength igual a Length, sem NUL.
    fn counted(&mut self, descriptor: u64, length: usize, buffer: u64) {
        self.put(descriptor + offset_of!(UnicodeString, length) as u64, &(length as u16).to_le_bytes());
        self.put(descriptor + offset_of!(UnicodeString, maximum_length) as u64, &(length as u16).to_le_bytes());
        self.put(descriptor + offset_of!(UnicodeString, buffer) as u64, &(self.base + buffer).to_le_bytes());
    }
}

/// O conjunto no formato interno, montado para o endereço `base`.
pub fn encode_internal(attributes: &[SecurityAttribute], base: u64) -> Result<Vec<u8>, u32> {
    let size = internal_size(attributes)? as usize;
    let mut image = InternalImage { bytes: vec![0u8; size], base };
    image.empty_list(HEADER_LIST);
    image.empty_list(HEADER_WORKING_LIST);
    let mut cursor = INTERNAL_HEADER + attributes.len() as u64 * INTERNAL_ATTRIBUTE;
    for (index, attribute) in attributes.iter().enumerate() {
        let record = INTERNAL_HEADER + index as u64 * INTERNAL_ATTRIBUTE;
        image.insert_tail(HEADER_LIST, record);
        image.put(HEADER_COUNT, &(index as u32 + 1).to_le_bytes());
        image.put(record + ATTRIBUTE_TYPE, &attribute.kind.to_le_bytes());
        image.put(record + ATTRIBUTE_FLAGS, &attribute.flags.to_le_bytes());
        image.empty_list(record + ATTRIBUTE_VALUES);
        image.empty_list(record + ATTRIBUTE_LIST_60);
        cursor = (cursor + 1) & !1;
        let name = utf16_bytes(&attribute.name);
        image.counted(record + ATTRIBUTE_NAME, name.len(), cursor);
        image.put(cursor, &name);
        cursor += name.len() as u64;
        let values = (cursor + 7) & !7;
        let mut data = values + attribute.values.len() as u64 * INTERNAL_VALUE;
        for (value_index, value) in attribute.values.iter().enumerate() {
            let entry = values + value_index as u64 * INTERNAL_VALUE;
            let payload = internal_value_data(attribute.kind, value)?;
            match value {
                AttributeValue::Integer(number) => image.put(entry + VALUE_DATA, &number.to_le_bytes()),
                AttributeValue::Text(_) => image.counted(entry + VALUE_DATA, payload.len(), data),
                AttributeValue::Fqbn { version, .. } => {
                    image.put(entry + VALUE_DATA, &version.to_le_bytes());
                    image.counted(entry + VALUE_NAME, payload.len(), data);
                }
                AttributeValue::Bytes(_) => {
                    image.put(entry + VALUE_DATA, &(base + data).to_le_bytes());
                    image.put(entry + VALUE_NAME, &(payload.len() as u32).to_le_bytes());
                }
            }
            image.put(data, &payload);
            data += payload.len() as u64;
            image.insert_tail(record + ATTRIBUTE_VALUES, entry);
            image.put(record + ATTRIBUTE_VALUE_COUNT, &(value_index as u32 + 1).to_le_bytes());
        }
        cursor = data;
    }
    Ok(image.bytes)
}

/// Texto de uma UNICODE_STRING do formato interno (unidades inteiras).
fn counted_text(descriptor: &UnicodeString) -> String {
    let units: Vec<u16> = guest::read_bytes(descriptor.buffer.get(), descriptor.length.get() as usize & !1).chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]])).collect();
    String::from_utf16_lossy(&units)
}

/// Os atributos de um conjunto no formato interno (o
/// TOKEN_ACCESS_INFORMATION.SecurityAttributes), pelas listas.
pub fn decode_internal(address: u64) -> Result<Vec<SecurityAttribute>, u32> {
    if address == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // SAFETY: o conjunto interno do TOKEN_ACCESS_INFORMATION do chamador.
    let header = unsafe { AuthzbasepSecurityAttributesInformation::at(address) };
    let head = header.security_attributes_list.address();
    let mut attributes = Vec::new();
    let mut link = header.security_attributes_list.flink.get();
    while link != head {
        // SAFETY: elo da lista de atributos, no início do registro.
        let record = unsafe { AuthzbasepSecurityAttribute::at(link) };
        let kind = record.value_type.get();
        let mut values = Vec::new();
        let values_head = record.values.address();
        let mut value_link = record.values.flink.get();
        while value_link != values_head {
            // SAFETY: elo da lista de valores, no início do valor.
            let value = unsafe { AuthzbasepSecurityAttributeValue::at(value_link) };
            values.push(match kind {
                1 | 2 | 6 => AttributeValue::Integer(value.value.get()),
                // SAFETY: a UNICODE_STRING do STRING começa em `value`.
                3 => AttributeValue::Text(counted_text(unsafe { UnicodeString::at(value.value.address()) })),
                4 => AttributeValue::Fqbn { version: value.value.get(), name: counted_text(&value.name) },
                5 | 0x10 => {
                    // SAFETY: o ULONG do tamanho ocupa o início de `name`.
                    let length = unsafe { Field::<u32>::at(value.name.address()) }.get();
                    AttributeValue::Bytes(guest::read_bytes(value.value.get(), length as usize))
                }
                _ => return Err(STATUS_INVALID_PARAMETER),
            });
            value_link = value.list_link.flink.get();
        }
        attributes.push(SecurityAttribute { name: counted_text(&record.name), kind, flags: record.flags.get(), values });
        link = record.list_link.flink.get();
    }
    Ok(attributes)
}
