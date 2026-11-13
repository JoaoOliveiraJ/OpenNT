//! XPRESS LZ77 simples (COMPRESSION_FORMAT_XPRESS, MS-XCA 2.3/2.4).
//!
//! Fluxo: palavras de flags de 32 bits (bit 31 primeiro; 0 = literal, 1 =
//! match) seguidas dos seus tokens; match = USHORT `((offset - 1) << 3) | L`,
//! com `L = 7` estendido por meio byte compartilhado, depois um byte e por fim
//! USHORT/ULONG de comprimento.
//!
//! - `decompress` transcreve `RtlDecompressBufferXpressLz` (ntoskrnl 19045,
//!   conferido contra o ntdll): menos de 5 bytes de entrada, literal sem entrada
//!   ou sem saída, match que aponta antes do início ou passa do fim da saída e
//!   recarga de flags sem 4 bytes dão STATUS_BAD_COMPRESSION_BUFFER; a entrada
//!   esgotada num bit de match termina com sucesso (com 1 byte sobrando, só se a
//!   saída estiver cheia). O tamanho de saída precisa ser o exato.
//! - `compress` tem o contrato do `RtlCompressBufferXpressLzStandard`
//!   (CompressedSize < 0x40 ou UncompressedSize < 8 → STATUS_BUFFER_TOO_SMALL;
//!   saída que não cabe → STATUS_BUFFER_TOO_SMALL; sem STATUS_BUFFER_ALL_ZEROS),
//!   mas usa o parser guloso `parse` (hash de 3 bytes, cadeia de 16): o fluxo é
//!   válido e decodifica igual no NT, sem ser byte-idêntico ao da Microsoft.
//!   Não usa o workspace do chamador.

use alloc::vec;
use alloc::vec::Vec;

use super::{GuestWindow, STATUS_BAD_COMPRESSION_BUFFER, STATUS_BUFFER_TOO_SMALL};
use crate::ntos::inc::types::Field;
use crate::ntos::mm::guest_memory as guest;

const HASH_BITS: u32 = 12;
const CHAIN_DEPTH: u32 = 16;
const MAX_OFFSET: usize = 8192;

/// Token do parser LZ77: literal ou (offset, comprimento >= 3).
#[derive(Clone, Copy)]
pub(super) enum Token {
    Literal(u8),
    Match { offset: usize, length: usize },
}

fn hash3(data: &[u8], at: usize) -> usize {
    (((data[at] as usize) << 8) ^ ((data[at + 1] as usize) << 4) ^ data[at + 2] as usize) & ((1 << HASH_BITS) - 1)
}

/// Parser guloso determinístico sobre `data[start..end]`: cabeças de hash de
/// 3 bytes, cadeia `previous` de profundidade 16, offsets até `max_offset`.
pub(super) fn parse(data: &[u8], start: usize, end: usize, max_offset: usize) -> Vec<Token> {
    let mut head = vec![usize::MAX; 1 << HASH_BITS];
    let mut previous = vec![usize::MAX; end - start];
    let mut tokens = Vec::new();
    let insert = |head: &mut [usize], previous: &mut [usize], at: usize| {
        let key = hash3(data, at);
        previous[at - start] = head[key];
        head[key] = at;
    };
    let mut position = start;
    while position < end {
        let (mut best_length, mut best_offset) = (0usize, 0usize);
        if position + 3 <= end {
            let mut candidate = head[hash3(data, position)];
            let mut depth = 0;
            while candidate != usize::MAX && candidate >= start && depth < CHAIN_DEPTH {
                let offset = position - candidate;
                if offset > max_offset {
                    break;
                }
                let mut length = 0;
                while position + length < end && data[candidate + length] == data[position + length] {
                    length += 1;
                }
                if length > best_length {
                    best_length = length;
                    best_offset = offset;
                }
                candidate = previous[candidate - start];
                depth += 1;
            }
            insert(&mut head, &mut previous, position);
        }
        if best_length >= 3 {
            tokens.push(Token::Match { offset: best_offset, length: best_length });
            let stop = (position + best_length).min(end.saturating_sub(2));
            for at in position + 1..stop {
                insert(&mut head, &mut previous, at);
            }
            position += best_length;
        } else {
            tokens.push(Token::Literal(data[position]));
            position += 1;
        }
    }
    tokens
}

/// RtlCompressBufferXpressLz (engines standard e maximum).
pub fn compress(uncompressed: u64, uncompressed_size: u32, compressed: u64, compressed_size: u32, final_size_out: &Field<u32>) -> u32 {
    if compressed_size < 0x40 || uncompressed_size < 8 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let input = guest::read_bytes(uncompressed, uncompressed_size as usize);
    let Some(output) = encode(&input, compressed_size as usize) else {
        return STATUS_BUFFER_TOO_SMALL;
    };
    guest::write_bytes(compressed, &output);
    final_size_out.set(output.len() as u32);
    0
}

fn encode(input: &[u8], capacity: usize) -> Option<Vec<u8>> {
    let mut out = vec![0u8; 4];
    let (mut flag_position, mut flags, mut count) = (0usize, 0u32, 0u32);
    let mut nibble: Option<usize> = None;
    for token in parse(input, 0, input.len(), MAX_OFFSET) {
        match token {
            Token::Literal(byte) => {
                out.push(byte);
                flags <<= 1;
            }
            Token::Match { offset, length } => {
                let mut extra = length - 3;
                out.extend_from_slice(&((((offset - 1) << 3) | extra.min(7)) as u16).to_le_bytes());
                if extra >= 7 {
                    extra -= 7;
                    match nibble.take() {
                        None => {
                            nibble = Some(out.len());
                            out.push(extra.min(15) as u8);
                        }
                        Some(at) => out[at] |= (extra.min(15) as u8) << 4,
                    }
                    if extra >= 15 {
                        extra -= 15;
                        if extra < 255 {
                            out.push(extra as u8);
                        } else {
                            out.push(255);
                            if length - 3 <= 0xFFFF {
                                out.extend_from_slice(&((length - 3) as u16).to_le_bytes());
                            } else {
                                out.extend_from_slice(&0u16.to_le_bytes());
                                out.extend_from_slice(&((length - 3) as u32).to_le_bytes());
                            }
                        }
                    }
                }
                flags = (flags << 1) | 1;
            }
        }
        count += 1;
        if count == 32 {
            out[flag_position..flag_position + 4].copy_from_slice(&flags.to_le_bytes());
            flag_position = out.len();
            out.extend_from_slice(&[0; 4]);
            flags = 0;
            count = 0;
        }
        if out.len() > capacity {
            return None;
        }
    }
    // Bits restantes = 1: o decodificador termina no primeiro "match" sem entrada.
    let padded = if count == 0 { u32::MAX } else { (flags << (32 - count)) | ((1u32 << (32 - count)) - 1) };
    out[flag_position..flag_position + 4].copy_from_slice(&padded.to_le_bytes());
    if out.len() > capacity {
        return None;
    }
    Some(out)
}

/// RtlDecompressBufferXpressLz(Uncompressed, Size, Compressed, CompressedSize,
/// .., *FinalUncompressedSize). A saída parcial fica no buffer em caso de erro.
pub fn decompress(uncompressed: u64, size: u32, compressed: u64, compressed_size: u32, final_size_out: &Field<u32>) -> u32 {
    if compressed_size < 5 {
        return STATUS_BAD_COMPRESSION_BUFFER;
    }
    let input = guest::read_bytes(compressed, compressed_size as usize);
    let mut output = GuestWindow::read(uncompressed, size as usize);
    let result = decode(&input, &mut output, size as usize);
    output.flush();
    match result {
        Ok(produced) => {
            final_size_out.set(produced as u32);
            0
        }
        Err(status) => status,
    }
}

fn decode(input: &[u8], output: &mut GuestWindow, out_end: usize) -> Result<usize, u32> {
    let end = input.len();
    let read16 = |at: usize| u16::from_le_bytes([input[at], input[at + 1]]) as usize;
    let read32 = |at: usize| u32::from_le_bytes([input[at], input[at + 1], input[at + 2], input[at + 3]]) as usize;
    let mut flags = read32(0) as u32;
    let mut at = 4usize;
    let mut bits = 32u32;
    let mut nibble: Option<usize> = None;
    let mut out = 0usize;
    loop {
        if bits == 0 {
            if at + 4 > end {
                return Err(STATUS_BAD_COMPRESSION_BUFFER);
            }
            flags = read32(at) as u32;
            at += 4;
            bits = 32;
        }
        let is_match = flags & 0x8000_0000 != 0;
        flags <<= 1;
        bits -= 1;
        if !is_match {
            if at >= end || out >= out_end {
                return Err(STATUS_BAD_COMPRESSION_BUFFER);
            }
            output.put(out, input[at]);
            out += 1;
            at += 1;
            continue;
        }
        if at == end {
            return Ok(out);
        }
        if at + 1 >= end {
            return if out < out_end { Err(STATUS_BAD_COMPRESSION_BUFFER) } else { Ok(out) };
        }
        let token = read16(at);
        at += 2;
        let mut length = token & 7;
        let offset = (token >> 3) + 1;
        if length == 7 {
            length = match nibble.take() {
                None => {
                    if at >= end {
                        return Err(STATUS_BAD_COMPRESSION_BUFFER);
                    }
                    nibble = Some(at);
                    at += 1;
                    (input[at - 1] & 0xF) as usize
                }
                Some(saved) => (input[saved] >> 4) as usize,
            };
            if length == 15 {
                if at >= end {
                    return Err(STATUS_BAD_COMPRESSION_BUFFER);
                }
                length = input[at] as usize;
                at += 1;
                if length == 255 {
                    if at + 2 > end {
                        return Err(STATUS_BAD_COMPRESSION_BUFFER);
                    }
                    length = read16(at);
                    at += 2;
                    if length == 0 {
                        if at + 4 > end {
                            return Err(STATUS_BAD_COMPRESSION_BUFFER);
                        }
                        length = read32(at);
                        at += 4;
                    }
                    if length < 0x16 {
                        return Err(STATUS_BAD_COMPRESSION_BUFFER);
                    }
                    length -= 0x16;
                }
                length += 15;
            }
            length += 7;
        }
        length += 3;
        if offset > out || out + length > out_end {
            return Err(STATUS_BAD_COMPRESSION_BUFFER);
        }
        for _ in 0..length {
            let byte = output.bytes[out - offset];
            output.put(out, byte);
            out += 1;
        }
    }
}
