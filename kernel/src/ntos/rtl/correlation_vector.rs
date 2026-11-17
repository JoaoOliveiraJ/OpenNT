//! Vetores de correlação (CORRELATION_VECTOR) do Rtl — ntoskrnl 19041:
//! RtlInitializeCorrelationVector 0x916160, RtlIncrementCorrelationVector
//! 0x916070, RtlExtendCorrelationVector 0x916020 e
//! RtlValidateCorrelationVector 0x9161e0.
//!
//! O texto é "<base>.<n>[.<n>...]": a base é o GUID em base64 (os 16
//! primeiros caracteres na versão 1, os 22 na versão 2) e cada componente é
//! um decimal de 1 a 10 dígitos que não passa de "2147483647" (comparação
//! de texto). O buffer útil tem 0x41 bytes na versão 1 e 0x81 na versão 2
//! (RtlpGetCorrelationVectorBufferLength); outra versão não tem buffer.
//! O incremento lê e reescreve o último componente com "%d" (um int de 32
//! bits: 2147483647 + 1 vira "-2147483648", como no original).

use alloc::format;
use alloc::vec::Vec;

use crate::ntos::inc::types::CorrelationVector;

const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// Alfabeto do RtlpBase64Encode (a tabela de 64 bytes da .rdata).
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// O maior componente aceito pela validação.
const COMPONENT_LIMIT: &[u8; 10] = b"2147483647";
/// Caracteres da base: o GUID inteiro em base64 tem 22.
const V1_BASE: usize = 16;
const V2_BASE: usize = 22;

fn byte(vector: &CorrelationVector, index: usize) -> u8 {
    vector.vector[index].get()
}

/// RtlpGetCorrelationVectorBufferLength: 0x41, 0x81 ou -1.
fn buffer_length(vector: &CorrelationVector) -> i32 {
    match vector.version.get() {
        1 => 0x41,
        2 => 0x81,
        _ => -1,
    }
}

fn is_base64(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'+' || c == b'/'
}

/// RtlpGetLastContiguosBase64Position: o índice do último caractere da
/// sequência inicial de caracteres base64, ou -1.
fn last_base64_position(vector: &CorrelationVector) -> i32 {
    let length = buffer_length(vector);
    let mut last = -1;
    let mut index = 0;
    while index < length && byte(vector, index as usize) != 0 && is_base64(byte(vector, index as usize)) {
        last = index;
        index += 1;
    }
    last
}

/// RtlpGetCorrelationVectorEndPosition: o índice do NUL, ou -1 se não há NUL
/// dentro do buffer.
fn end_position(vector: &CorrelationVector) -> i32 {
    let length = buffer_length(vector);
    let mut count = 0;
    while count < length && byte(vector, count as usize) != 0 {
        count += 1;
    }
    if length > count { count } else { -1 }
}

/// RtlpGetCorrelationVectorLastDotPosition: o índice do último '.' antes do
/// NUL, ou -1.
fn last_dot_position(vector: &CorrelationVector) -> i32 {
    let length = buffer_length(vector);
    let mut dot = -1;
    let mut index = 0;
    while index < length {
        let c = byte(vector, index as usize);
        if c == 0 {
            break;
        }
        if c == b'.' {
            dot = index;
        }
        index += 1;
    }
    dot
}

/// RtlInitializeCorrelationVector(CorrelationVector, Version, Guid): versão
/// (o byte baixo) fora de 1..2 ou Guid NULL = STATUS_INVALID_PARAMETER sem
/// tocar no vetor. Senão zera os 129 bytes do texto, grava a versão, o GUID
/// em base64 com "==" e NUL (24 caracteres) e põe ".0" e NUL logo depois da
/// base da versão; o resto da codificação fica depois desse NUL.
pub fn initialize(vector: &CorrelationVector, version: u32, guid: u64) -> u32 {
    let version = version as u8;
    if version.wrapping_sub(1) > 1 || guid == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    for cell in &vector.vector {
        cell.set(0);
    }
    vector.version.set(version);
    let bytes = crate::ntos::mm::guest_memory::read_bytes(guid, 16);
    let mut text: Vec<u8> = Vec::with_capacity(25);
    for chunk in bytes[..15].chunks(3) {
        text.push(BASE64[(chunk[0] >> 2) as usize]);
        text.push(BASE64[(((chunk[0] & 3) << 4) | (chunk[1] >> 4)) as usize]);
        text.push(BASE64[(((chunk[1] & 0xF) << 2) | (chunk[2] >> 6)) as usize]);
        text.push(BASE64[(chunk[2] & 0x3F) as usize]);
    }
    text.push(BASE64[(bytes[15] >> 2) as usize]);
    text.push(BASE64[((bytes[15] & 3) << 4) as usize]);
    text.extend_from_slice(b"==\0");
    for (cell, &value) in vector.vector.iter().zip(&text) {
        cell.set(value);
    }
    let base = if version == 1 { V1_BASE } else { V2_BASE };
    vector.vector[base].set(b'.');
    vector.vector[base + 1].set(b'0');
    vector.vector[base + 2].set(0);
    0
}

/// RtlValidateCorrelationVector(Vector): NULL, versão sem buffer, texto sem
/// NUL no buffer, base de tamanho errado para a versão ou componentes fora
/// da forma ".<1 a 10 dígitos>" (com 10 dígitos, até "2147483647") =
/// STATUS_INVALID_PARAMETER.
pub fn validate(vector: Option<&CorrelationVector>) -> u32 {
    let Some(vector) = vector else { return STATUS_INVALID_PARAMETER };
    if buffer_length(vector) < 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let base = last_base64_position(vector);
    let end = end_position(vector);
    if end < 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let expected = (if vector.version.get() == 1 { V1_BASE } else { V2_BASE }) as i32 - 1;
    if base != expected {
        return STATUS_INVALID_PARAMETER;
    }
    let (end, mut index) = (end as usize, (base + 1) as usize);
    if byte(vector, index) != b'.' {
        return STATUS_INVALID_PARAMETER;
    }
    while index < end {
        if byte(vector, index) != b'.' {
            return STATUS_INVALID_PARAMETER;
        }
        index += 1;
        let start = index;
        if index >= end {
            return STATUS_INVALID_PARAMETER;
        }
        while index < end && byte(vector, index).is_ascii_digit() {
            index += 1;
        }
        let digits: Vec<u8> = (start..index).map(|position| byte(vector, position)).collect();
        if digits.is_empty() || digits.len() > COMPONENT_LIMIT.len() || (digits.len() == COMPONENT_LIMIT.len() && digits.as_slice() > COMPONENT_LIMIT.as_slice()) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    0
}

/// RtlIncrementCorrelationVector(CorrelationVector): valida (o erro volta
/// como está), lê o último componente com "%d", soma 1 e o reescreve no
/// lugar; o texto novo (com o NUL) precisa caber antes do fim do buffer
/// (`n < buffer - ponto - 2`), senão STATUS_BUFFER_OVERFLOW sem mudar nada.
pub fn increment(vector: &CorrelationVector) -> u32 {
    let length = buffer_length(vector);
    let status = validate(Some(vector));
    if status != 0 {
        return status;
    }
    let dot = last_dot_position(vector);
    if dot < 0 {
        return STATUS_BUFFER_OVERFLOW;
    }
    let first = dot as usize + 1;
    let mut value = 0i32;
    let mut index = first;
    while byte(vector, index).is_ascii_digit() {
        value = value.wrapping_mul(10).wrapping_add((byte(vector, index) - b'0') as i32);
        index += 1;
    }
    let text = format!("{}", value.wrapping_add(1));
    if text.len() as i32 >= length - dot - 2 {
        return STATUS_BUFFER_OVERFLOW;
    }
    for (offset, &c) in text.as_bytes().iter().chain(core::iter::once(&0)).enumerate() {
        vector.vector[first + offset].set(c);
    }
    status
}

/// RtlExtendCorrelationVector(CorrelationVector): sem validar, acrescenta
/// ".0" e NUL no fim do texto; sem NUL no buffer (ou versão sem buffer) ou
/// sem espaço (fim >= buffer - 3) = STATUS_BUFFER_OVERFLOW.
pub fn extend(vector: &CorrelationVector) -> u32 {
    let end = end_position(vector);
    if end < 0 || end >= buffer_length(vector) - 3 {
        return STATUS_BUFFER_OVERFLOW;
    }
    let end = end as usize;
    vector.vector[end].set(b'.');
    vector.vector[end + 1].set(b'0');
    vector.vector[end + 2].set(0);
    0
}
