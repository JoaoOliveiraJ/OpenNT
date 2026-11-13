//! XPRESS Huffman (COMPRESSION_FORMAT_XPRESS_HUFF, MS-XCA 2.1/2.2).
//!
//! Cada bloco de 65536 bytes de saída começa com 256 bytes de comprimentos de
//! código (4 bits por símbolo, 512 símbolos: 0..255 literais, 256..511 matches
//! `256 + min(len - 3, 15) + 16 * floor(log2(offset))`), seguidos de um fluxo de
//! bits em palavras de 16 bits (MSB primeiro) intercalado com os bytes extras
//! de comprimento.
//!
//! - `decompress` transcreve `RtlDecompressBufferXpressHuff` e
//!   `XpressBuildHuffmanDecodingTable` (ntoskrnl 19045, conferido contra o
//!   ntdll em entradas válidas e corrompidas): a tabela é montada literalmente no
//!   workspace do chamador (alinhado a 8; 1024 entradas primárias de 10 bits em
//!   +0x420 e a árvore dos códigos longos em +0xC20), com as mesmas regras de
//!   aceitação — códigos atribuídos do maior comprimento para o menor a partir do
//!   topo, um código mais curto sobrescrevendo prefixos já atribuídos, rejeição
//!   quando o espaço de códigos esgota com símbolos restantes, e o caso especial
//!   de um único símbolo de comprimento 1. Bloco com menos de 0x104 bytes de
//!   entrada termina com sucesso só se a saída estiver completa; símbolo 256 com
//!   a entrada esgotada e a saída completa também termina.
//! - `compress` tem o contrato do `RtlCompressBufferXpressHuffStandard`
//!   (CompressedSize < 0x12C → STATUS_BUFFER_TOO_SMALL; saída que não cabe →
//!   STATUS_BUFFER_TOO_SMALL) e gera blocos MS-XCA válidos com códigos de Huffman
//!   completos limitados a 15 bits, sem ser byte-idêntico ao da Microsoft.
//!   Não usa o workspace do chamador.

use alloc::collections::BinaryHeap;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Reverse;

use super::xpress::{parse, Token};
use super::{GuestWindow, STATUS_BAD_COMPRESSION_BUFFER, STATUS_BUFFER_TOO_SMALL};
use crate::ntos::inc::types::Field;
use crate::ntos::mm::guest_memory as guest;

const SYMBOLS: usize = 512;
const BLOCK: usize = 0x1_0000;
const MAX_CODE_LENGTH: u32 = 15;
/// Palavras do workspace usadas pela tabela: próximos (0..511), cabeças por
/// comprimento (+0x400), primária (+0x420) e árvore (+0xC20, índices até 0x400).
const HEAD: usize = 0x200;
const PRIMARY: usize = 0x210;
const TREE: usize = 0x610;
const TABLE_WORDS: usize = TREE + 0x401;
const END_OF_LIST: u16 = 0x200;

fn s16(value: i32) -> i32 {
    value as i16 as i32
}

/// Escreve uma palavra da tabela; índice fora do workspace = tabela inválida.
fn store(words: &mut [u16], index: i64, value: i32) -> bool {
    if index < 0 || index as usize >= words.len() {
        return false;
    }
    words[index as usize] = value as u16;
    true
}

/// Comportamento conferido contra o XpressBuildHuffmanDecodingTable do ntoskrnl.
fn build_table(words: &mut [u16], lengths: &[u8]) -> bool {
    for length in 0..16 {
        words[HEAD + length] = END_OF_LIST;
    }
    for (index, &byte) in lengths.iter().enumerate().take(256) {
        let (low, high) = ((byte & 0xF) as usize, (byte >> 4) as usize);
        if low != 0 {
            words[2 * index] = words[HEAD + low];
            words[HEAD + low] = (2 * index) as u16;
        }
        if high != 0 {
            words[2 * index + 1] = words[HEAD + high];
            words[HEAD + high] = (2 * index + 1) as u16;
        }
    }
    // Códigos de 15 a 11 bits: folhas e nós internos na árvore, de cima para baixo.
    let mut node = -1024i32;
    let mut slot = 0x400i64;
    let mut length = 15usize;
    let mut pair = node + 1;
    loop {
        if pair < node {
            let count = ((((node - pair) & 0xFFFF) - 1) & 0xFFFF) >> 1;
            let count = (count + 1) & 0xFFFF;
            let mut index = slot;
            slot -= count as i64;
            loop {
                if !store(words, TREE as i64 + index, pair) {
                    return false;
                }
                index -= 1;
                pair = s16(pair + 2);
                if pair >= node {
                    break;
                }
            }
        }
        if pair == node {
            return false;
        }
        pair = s16(node + 1);
        let mut symbol = words[HEAD + length];
        while symbol != END_OF_LIST {
            if !store(words, TREE as i64 + slot, ((symbol as i32) << 4) + length as i32) {
                return false;
            }
            slot -= 1;
            symbol = words[symbol as usize];
        }
        length -= 1;
        node = s16(-(slot as i32));
        if length <= 10 {
            break;
        }
    }
    // Prefixos de 10 bits que levam à árvore.
    let mut code = 0x3FFi64;
    if pair < node {
        let count = (((((node - pair) & 0xFFFF) - 1) & 0xFFFF) >> 1) + 1;
        code -= count as i64;
        let mut index = 0x3FFi64;
        loop {
            if !store(words, PRIMARY as i64 + index, pair) {
                return false;
            }
            index -= 1;
            pair = s16(pair + 2);
            if pair >= node {
                break;
            }
        }
        if pair == node {
            return false;
        }
    } else if pair == node {
        return false;
    }
    // Códigos de 10 a 1 bit direto na primária, do topo do espaço para baixo.
    let mut exhausted = false;
    let mut entry = 0i32;
    for length in (1..=10usize).rev() {
        let mut symbol = words[HEAD + length];
        while symbol != END_OF_LIST {
            entry = (((symbol as i32) << 4) + length as i32) & 0xFFFF;
            if exhausted {
                return false;
            }
            let shift = 10 - length as u32;
            if code < 0 || (code + 1) << shift > 0x400 {
                return false;
            }
            let start = (code << shift) as usize;
            for offset in 0..1usize << shift {
                words[PRIMARY + start + offset] = entry as u16;
            }
            if code == 0 {
                exhausted = true;
            } else {
                code -= 1;
            }
            symbol = words[symbol as usize];
        }
        code >>= 1;
    }
    if exhausted {
        return true;
    }
    // Só um símbolo de comprimento 1: toda entrada decodifica nele.
    if (2..16).any(|length| words[HEAD + length] != END_OF_LIST) || words[HEAD + 1] == END_OF_LIST {
        return false;
    }
    for index in 0..512 {
        words[PRIMARY + index] = entry as u16;
    }
    true
}

/// RtlDecompressBufferXpressHuff(Uncompressed, Size, Compressed,
/// CompressedSize, .., *FinalUncompressedSize, WorkSpace).
pub fn decompress(uncompressed: u64, size: u32, compressed: u64, compressed_size: u32, final_size_out: &Field<u32>, work_space: u64) -> u32 {
    let input = if compressed_size == 0 { Vec::new() } else { guest::read_bytes(compressed, compressed_size as usize) };
    let table = (work_space + 7) & !7;
    let mut words: Vec<u16> = guest::read_bytes(table, TABLE_WORDS * 2).chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    let mut output = GuestWindow::read(uncompressed, size as usize);
    let result = decode(&input, &mut output, size as usize, &mut words);
    output.flush();
    let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    guest::write_bytes(table, &bytes);
    match result {
        Ok(produced) => {
            final_size_out.set(produced as u32);
            0
        }
        Err(status) => status,
    }
}

/// Leitor de bits: 32 bits na janela, `extra` = bits além dos 16 garantidos.
struct Bits<'a> {
    input: &'a [u8],
    at: usize,
    window: u32,
    extra: i32,
}

impl Bits<'_> {
    fn word(&self, at: usize) -> u32 {
        u16::from_le_bytes([self.input[at], self.input[at + 1]]) as u32
    }

    /// Consome `count` bits; recarrega 16 quando `extra` fica negativo.
    fn consume(&mut self, count: u32) -> Result<(), u32> {
        self.window = if count >= 32 { 0 } else { self.window << count };
        self.extra -= count as i32;
        self.refill()
    }

    fn refill(&mut self) -> Result<(), u32> {
        if self.extra < 0 {
            if self.at + 2 > self.input.len() {
                return Err(STATUS_BAD_COMPRESSION_BUFFER);
            }
            self.window = self.window.wrapping_add(self.word(self.at) << (-self.extra) as u32);
            self.at += 2;
            self.extra += 16;
        }
        Ok(())
    }
}

fn decode(input: &[u8], output: &mut GuestWindow, out_end: usize, words: &mut [u16]) -> Result<usize, u32> {
    let end = input.len();
    let mut at = 0usize;
    let mut out = 0usize;
    loop {
        if end - at < 0x104 {
            return if out == out_end { Ok(out) } else { Err(STATUS_BAD_COMPRESSION_BUFFER) };
        }
        if !build_table(words, &input[at..at + 256]) {
            return Err(STATUS_BAD_COMPRESSION_BUFFER);
        }
        at += 256;
        let window = (u16::from_le_bytes([input[at], input[at + 1]]) as u32) << 16 | u16::from_le_bytes([input[at + 2], input[at + 3]]) as u32;
        let mut bits = Bits { input, at: at + 4, window, extra: 16 };
        let block_end = (out + BLOCK).min(out_end);
        while out < block_end {
            let mut entry = s16(words[PRIMARY + (bits.window >> 22) as usize] as i32);
            if entry > 0 {
                bits.window <<= entry & 0xF;
                bits.extra -= entry & 0xF;
            } else {
                bits.window <<= 10;
                bits.extra -= 10;
                loop {
                    let bit = (bits.window >> 31) as i32;
                    bits.extra -= 1;
                    bits.window <<= 1;
                    let index = TREE as i64 + s16(bit - entry) as i64;
                    if index < 0 || index as usize >= words.len() {
                        return Err(STATUS_BAD_COMPRESSION_BUFFER);
                    }
                    entry = s16(words[index as usize] as i32);
                    if entry > 0 {
                        break;
                    }
                }
            }
            bits.refill()?;
            let symbol = (entry >> 4) as usize;
            if symbol < 256 {
                output.put(out, symbol as u8);
                out += 1;
                continue;
            }
            if symbol == 256 && bits.at >= end && out == out_end {
                return Ok(out);
            }
            let class = symbol - 256;
            let offset_bits = (class >> 4) as u32;
            let mut length = class & 15;
            if length == 15 {
                if bits.at >= end {
                    return Err(STATUS_BAD_COMPRESSION_BUFFER);
                }
                length = input[bits.at] as usize;
                bits.at += 1;
                if length == 255 {
                    if bits.at + 2 > end {
                        return Err(STATUS_BAD_COMPRESSION_BUFFER);
                    }
                    length = bits.word(bits.at) as usize;
                    bits.at += 2;
                    if length == 0 {
                        if bits.at + 4 > end {
                            return Err(STATUS_BAD_COMPRESSION_BUFFER);
                        }
                        length = u32::from_le_bytes([input[bits.at], input[bits.at + 1], input[bits.at + 2], input[bits.at + 3]]) as usize;
                        bits.at += 4;
                    }
                    if length < 15 {
                        return Err(STATUS_BAD_COMPRESSION_BUFFER);
                    }
                    length -= 15;
                }
                length += 15;
            }
            let high = if offset_bits == 0 { 0 } else { (bits.window >> (32 - offset_bits)) as usize };
            let offset = high + (1usize << offset_bits);
            length += 3;
            bits.consume(offset_bits)?;
            if offset > out || out + length > out_end {
                return Err(STATUS_BAD_COMPRESSION_BUFFER);
            }
            for _ in 0..length {
                let byte = output.bytes[out - offset];
                output.put(out, byte);
                out += 1;
            }
        }
        at = bits.at;
    }
}

/// RtlCompressBufferXpressHuff (engines standard e maximum).
pub fn compress(uncompressed: u64, uncompressed_size: u32, compressed: u64, compressed_size: u32, final_size_out: &Field<u32>) -> u32 {
    if compressed_size < 0x12C {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let input = if uncompressed_size == 0 { Vec::new() } else { guest::read_bytes(uncompressed, uncompressed_size as usize) };
    let Some(output) = encode(&input, compressed_size as usize) else {
        return STATUS_BUFFER_TOO_SMALL;
    };
    guest::write_bytes(compressed, &output);
    final_size_out.set(output.len() as u32);
    0
}

fn match_symbol(offset: usize, length: usize) -> usize {
    let offset_bits = usize::BITS - 1 - offset.leading_zeros();
    256 + (length - 3).min(15) + 16 * offset_bits as usize
}

/// Comprimentos de Huffman (fusões por heap, inteiro) limitados a 15 bits e
/// ajustados para Kraft exato; menos de dois símbolos ganham um parceiro.
fn code_lengths(frequency: &[u64]) -> Vec<u32> {
    let symbols: Vec<usize> = (0..SYMBOLS).filter(|&symbol| frequency[symbol] != 0).collect();
    let mut lengths = vec![0u32; SYMBOLS];
    if symbols.len() < 2 {
        let mut pair = symbols.clone();
        for filler in [0usize, 1] {
            if pair.len() < 2 && !pair.contains(&filler) {
                pair.push(filler);
            }
        }
        for symbol in pair {
            lengths[symbol] = 1;
        }
        return lengths;
    }
    let mut heap: BinaryHeap<Reverse<(u64, usize)>> = symbols.iter().map(|&symbol| Reverse((frequency[symbol], symbol))).collect();
    let mut parent = vec![usize::MAX; SYMBOLS * 2];
    let mut next = SYMBOLS;
    while heap.len() > 1 {
        let Reverse((first_weight, first)) = heap.pop().unwrap_or(Reverse((0, 0)));
        let Reverse((second_weight, second)) = heap.pop().unwrap_or(Reverse((0, 0)));
        parent[first] = next;
        parent[second] = next;
        heap.push(Reverse((first_weight + second_weight, next)));
        next += 1;
    }
    for &symbol in &symbols {
        let (mut depth, mut node) = (0u32, symbol);
        while parent[node] != usize::MAX {
            node = parent[node];
            depth += 1;
        }
        lengths[symbol] = depth.min(MAX_CODE_LENGTH);
    }
    let full = 1u64 << MAX_CODE_LENGTH;
    let mut total: u64 = symbols.iter().map(|&symbol| 1u64 << (MAX_CODE_LENGTH - lengths[symbol])).sum();
    let mut order = symbols.clone();
    order.sort_by_key(|&symbol| (frequency[symbol], symbol));
    while total > full {
        if let Some(&symbol) = order.iter().find(|&&symbol| lengths[symbol] < MAX_CODE_LENGTH) {
            total -= 1u64 << (MAX_CODE_LENGTH - lengths[symbol] - 1);
            lengths[symbol] += 1;
        }
    }
    while total < full {
        let longest = symbols.iter().map(|&symbol| lengths[symbol]).max().unwrap_or(1);
        if let Some(&symbol) = order.iter().rev().find(|&&symbol| lengths[symbol] == longest) {
            total += 1u64 << (MAX_CODE_LENGTH - lengths[symbol]);
            lengths[symbol] -= 1;
        }
    }
    lengths
}

/// Códigos canônicos (comprimento crescente, símbolo crescente) — iguais aos
/// que o decodificador do NT atribui para um código completo.
fn canonical_codes(lengths: &[u32]) -> Vec<u32> {
    let mut codes = vec![0u32; SYMBOLS];
    let mut code = 0u32;
    for length in 1..=MAX_CODE_LENGTH {
        for symbol in 0..SYMBOLS {
            if lengths[symbol] == length {
                codes[symbol] = code;
                code += 1;
            }
        }
        code <<= 1;
    }
    codes
}

/// Palavras de 16 bits reservadas na ordem em que o decodificador as busca:
/// duas no início do bloco e uma nova sempre que os bits passam de 16 * k.
struct BitWriter {
    words: Vec<usize>,
    accumulator: u64,
    pending: u32,
    total: u64,
    flushed: usize,
}

impl BitWriter {
    fn new(out: &mut Vec<u8>) -> Self {
        let words = vec![out.len(), out.len() + 2];
        out.extend_from_slice(&[0; 4]);
        BitWriter { words, accumulator: 0, pending: 0, total: 0, flushed: 0 }
    }

    fn put(&mut self, out: &mut Vec<u8>, value: u32, count: u32) {
        self.accumulator = (self.accumulator << count) | value as u64;
        self.pending += count;
        self.total += count as u64;
        while self.pending >= 16 {
            self.pending -= 16;
            let word = ((self.accumulator >> self.pending) & 0xFFFF) as u16;
            let at = self.words[self.flushed];
            out[at..at + 2].copy_from_slice(&word.to_le_bytes());
            self.flushed += 1;
            self.accumulator &= (1u64 << self.pending) - 1;
        }
        while self.total > 16 * (self.words.len() as u64 - 1) {
            self.words.push(out.len());
            out.extend_from_slice(&[0; 2]);
        }
    }

    fn finish(&self, out: &mut [u8]) {
        if self.pending != 0 {
            let word = ((self.accumulator << (16 - self.pending)) & 0xFFFF) as u16;
            let at = self.words[self.flushed];
            out[at..at + 2].copy_from_slice(&word.to_le_bytes());
        }
    }
}

fn encode(input: &[u8], capacity: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut position = 0usize;
    loop {
        let block_end = (position + BLOCK).min(input.len());
        let tokens = parse(input, position, block_end, 0xFFFF);
        let mut frequency = vec![0u64; SYMBOLS];
        for token in &tokens {
            match *token {
                Token::Literal(byte) => frequency[byte as usize] += 1,
                Token::Match { offset, length } => frequency[match_symbol(offset, length)] += 1,
            }
        }
        let lengths = code_lengths(&frequency);
        let codes = canonical_codes(&lengths);
        for index in 0..256 {
            out.push((lengths[2 * index] | lengths[2 * index + 1] << 4) as u8);
        }
        let mut writer = BitWriter::new(&mut out);
        for token in &tokens {
            match *token {
                Token::Literal(byte) => writer.put(&mut out, codes[byte as usize], lengths[byte as usize]),
                Token::Match { offset, length } => {
                    let symbol = match_symbol(offset, length);
                    writer.put(&mut out, codes[symbol], lengths[symbol]);
                    if length - 3 >= 15 {
                        if length - 18 < 255 {
                            out.push((length - 18) as u8);
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
                    let offset_bits = usize::BITS - 1 - offset.leading_zeros();
                    writer.put(&mut out, (offset - (1 << offset_bits)) as u32, offset_bits);
                }
            }
            if out.len() > capacity {
                return None;
            }
        }
        writer.finish(&mut out);
        if out.len() > capacity {
            return None;
        }
        position = block_end;
        if position >= input.len() {
            return Some(out);
        }
    }
}
