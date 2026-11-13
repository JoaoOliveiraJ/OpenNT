//! UTF-8 <-> UTF-16 sobre buffers contados (RtlUTF8ToUnicodeN / RtlUnicodeToUTF8N).
//!
//! Sem terminador; zeros internos são dados; comprimentos em bytes. A ordem
//! de consumo e os resultados parciais seguem as rotinas NT.

use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const SOME_NOT_MAPPED: u32 = 0x107;
const BUFFER_TOO_SMALL: u32 = 0xC000_0023;

pub fn utf8_to_unicode(destination: u64, capacity: u32, output_length: u64, source: u64, source_length: u32) -> Result<u32, KernelError> {
    if source == 0 {
        return Ok(0xC000_00F2);
    }
    if destination == 0 && output_length == 0 {
        return Ok(0xC000_000D);
    }
    let mut offset = 0u32;
    let mut written = 0u32;
    let mut status = 0;
    let emit = |unit: u16, written: &mut u32| -> Result<bool, KernelError> {
        if destination != 0 {
            if *written + 2 > capacity {
                return Ok(false);
            }
            guest::try_write16(destination + *written as u64, unit)?;
        }
        *written += 2;
        Ok(true)
    };
    while offset < source_length {
        let lead = guest::try_read8(source + offset as u64)?;
        offset += 1;
        let mut code_point = lead as u32;
        let mut continuation = 0;
        let mut invalid = false;
        match lead {
            0xC2..=0xDF => {
                code_point = (lead & 31) as u32;
                continuation = 1;
            }
            0xE0..=0xEF => {
                code_point = (lead & 15) as u32;
                continuation = 2;
            }
            0xF0..=0xF4 => {
                code_point = (lead & 7) as u32;
                continuation = 3;
            }
            0x80.. => invalid = true,
            _ => {}
        }
        let mut index = 0;
        while index < continuation && !invalid {
            if offset == source_length {
                invalid = true;
                break;
            }
            let byte = guest::try_read8(source + offset as u64)?;
            if byte & 0xC0 != 0x80 {
                invalid = true;
                break;
            }
            // O segundo byte é consumido antes de rejeitar codificação longa,
            // substitutos ou valores fora do Unicode.
            offset += 1;
            code_point = code_point * 64 + (byte & 63) as u32;
            if index == 0
                && ((continuation == 2 && (code_point < 0x20 || (0x360..=0x37F).contains(&code_point)))
                    || (continuation == 3 && !(0x10..=0x10F).contains(&code_point)))
            {
                invalid = true;
            }
            index += 1;
        }
        if invalid {
            code_point = 0xFFFD;
            status = SOME_NOT_MAPPED;
        }
        // Pode gravar só o substituto alto se houver espaço para um WCHAR.
        if code_point >= 0x10000 {
            let value = code_point - 0x10000;
            if !emit(0xD800 | (value >> 10) as u16, &mut written)? || !emit(0xDC00 | (value & 1023) as u16, &mut written)? {
                status = BUFFER_TOO_SMALL;
                break;
            }
        } else if !emit(code_point as u16, &mut written)? {
            status = BUFFER_TOO_SMALL;
            break;
        }
    }
    if output_length != 0 {
        guest::try_write32(output_length, written)?;
    }
    Ok(status)
}

/// Combina pares substitutos válidos e substitui unidades soltas. Nunca
/// publica sequências UTF-8 incompletas.
pub fn unicode_to_utf8(destination: u64, capacity: u32, output_length: u64, source: u64, source_length: u32) -> Result<u32, KernelError> {
    if source == 0 {
        return Ok(0xC000_00F2);
    }
    if destination == 0 && output_length == 0 {
        return Ok(0xC000_000D);
    }
    // A escrita rejeita tamanho ímpar antes de tocar as saídas.
    if destination != 0 && source_length & 1 != 0 {
        return Ok(0xC000_00F3);
    }
    let count = source_length / 2;
    let mut index = 0u32;
    let mut written = 0u32;
    let mut status = 0;
    while index < count {
        let mut code_point = guest::try_read16(source + index as u64 * 2)? as u32;
        index += 1;
        if (0xD800..=0xDBFF).contains(&code_point) {
            let low = if index < count { guest::try_read16(source + index as u64 * 2)? as u32 } else { 0 };
            if (0xDC00..=0xDFFF).contains(&low) {
                code_point = 0x10000 + (code_point - 0xD800) * 1024 + low - 0xDC00;
                index += 1;
            } else {
                code_point = 0xFFFD;
                status = SOME_NOT_MAPPED;
            }
        } else if (0xDC00..=0xDFFF).contains(&code_point) {
            code_point = 0xFFFD;
            status = SOME_NOT_MAPPED;
        }
        let encoded = if code_point < 0x80 { 1 } else if code_point < 0x800 { 2 } else if code_point < 0x10000 { 3 } else { 4 };
        if destination != 0 {
            if written + encoded > capacity {
                status = BUFFER_TOO_SMALL;
                break;
            }
            let first = match encoded {
                1 => code_point,
                2 => 0xC0 | (code_point >> 6),
                3 => 0xE0 | (code_point >> 12),
                _ => 0xF0 | (code_point >> 18),
            };
            guest::try_write8(destination + written as u64, first as u8)?;
            for continuation in 1..encoded {
                let shift = 6 * (encoded - continuation - 1);
                guest::try_write8(destination + (written + continuation) as u64, (0x80 | ((code_point >> shift) & 63)) as u8)?;
            }
        }
        written += encoded;
    }
    // Escrever o tamanho incondicionalmente com um ponteiro nulo aqui
    // gravaria no endereço físico zero, então só se escreve quando há saída.
    if output_length != 0 {
        guest::try_write32(output_length, written)?;
    }
    Ok(status)
}
