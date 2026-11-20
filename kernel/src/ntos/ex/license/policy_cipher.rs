//! A cifra dos blobs do SystemPolicyInformation (classe 134) no ntoskrnl
//! 19041: blocos de 64 bits (duas palavras de 32 bits em big-endian) num
//! encadeamento de Feistel com 16 rodadas duplas da tabela de funções de
//! rodada (rva 0xd2d510, 31 entradas) e um bloco fixo de rodadas inline
//! chaveado pelas quatro palavras de 16 bits da chave de 8 bytes.
//!
//! Os 0xA0 bytes de parâmetros dizem, para cada meia-rodada `i` (0..32),
//! qual função usar (o byte 0x80 + i; 0x1F ou mais pula a meia-rodada) e os
//! três bytes de parâmetro dela (os bytes 4·i, 4·i + 1 e 4·i + 2).
//!
//! - O pedido é decifrado pelo despachante (0x5fe795..0x5fec4e): rodadas
//!   inline do pedido e depois a tabela de trás para a frente.
//! - A resposta é cifrada com os parâmetros e a chave que vieram no pedido
//!   (0x6006ca..0x600bdd): a tabela de frente para trás e depois as rodadas
//!   inline da resposta, que não são o inverso das do pedido (cada lado tem
//!   o seu par de cifras).
//! - O encadeamento é o mesmo nos dois sentidos: cada bloco entra misturado
//!   ao bloco anterior do outro lado (o texto cifrado anterior na
//!   decifração, o claro anterior na cifração) e sai misturado ao bloco
//!   anterior do mesmo lado. O começo é o par (0, 0) de claro e
//!   (0, 0xFFFFFFFF) de cifrado.
//! - Os `tamanho % 8` bytes iniciais, quando existem, saem de um fluxo de
//!   chave (a tabela de trás para a frente sobre (0, 0xFFFFFFFF)) e são o
//!   primeiro elo do encadeamento.
//!
//! O conferidor de integridade é o XOR de todos os bytes do claro, guardado
//! como u64 depois do texto cifrado.

use alloc::vec::Vec;

/// Bytes de parâmetros de rodada do blob.
pub const PARAMETERS_SIZE: usize = 0xA0;
/// Bytes da chave do blob.
pub const KEY_SIZE: usize = 8;
/// O índice de função que pula a meia-rodada.
const SKIP: u8 = 0x1F;
/// Primeiro elo do encadeamento no lado cifrado (o claro começa em zero).
const INITIAL_CIPHER: (u32, u32) = (0, 0xFFFF_FFFF);

pub type Parameters = [u8; PARAMETERS_SIZE];
pub type Key = [u8; KEY_SIZE];

/// A palavra de 16 bits `index & 3` da chave.
fn key_word(key: &Key, index: u64) -> u32 {
    let at = 2 * (index & 3) as usize;
    u16::from_le_bytes([key[at], key[at + 1]]) as u32
}

/// A palavra de 32 bits `index & 1` da chave.
fn key_dword(key: &Key, index: u64) -> u32 {
    let at = 4 * (index & 1) as usize;
    u32::from_le_bytes([key[at], key[at + 1], key[at + 2], key[at + 3]])
}

/// O segundo índice de palavra das funções 0..11 e 24..26:
/// `(b + 1 + b / 3 + (índice & 3)) & 3`.
fn second_word(byte: u8, slot: u64) -> u64 {
    (byte as u64 + 1 + byte as u64 / 3 + slot) & 3
}

/// A função de rodada `function` da tabela 0xd2d510 com o índice da
/// meia-rodada, os três bytes de parâmetro e o valor da outra metade (o
/// quarto byte que o despachante passa não é lido por nenhuma).
fn round(function: u8, index: u64, b0: u8, b1: u8, b2: u8, key: &Key, value: u32) -> u32 {
    let slot = index & 3;
    let word = key_word(key, slot);
    let dword = key_dword(key, (index >> 1).wrapping_sub(1));
    match function {
        // 0x6761d0, 0x666290, 0x665550, 0x674680, 0x9639e0, 0x668150.
        0..=5 => {
            let other = key_word(key, second_word(b0, slot));
            let shift = (b1 % 15 + 1) as u32;
            let product = if function == 1 { word.wrapping_mul(value.wrapping_sub(other)) } else { (other ^ value).wrapping_mul(word) };
            match function {
                0 => product.wrapping_add(value >> shift),
                1 => product.wrapping_sub(value >> shift),
                2 => product ^ (value >> shift),
                3 => product.wrapping_add(value.rotate_right(shift)),
                4 => product.wrapping_sub(value.rotate_right(shift)),
                _ => product ^ value.rotate_right(shift),
            }
        }
        // 0x66a290, 0x680070, 0x66f790, 0x663ab0, 0x6777a0, 0x663c80.
        6..=11 => {
            let rotation = (b1 % 7 + 1) as u32;
            let other = key_word(key, second_word(b0, slot));
            let mixed = match function {
                7 => dword ^ value,
                8 => value.wrapping_sub(other),
                _ => other ^ value,
            };
            let product = mixed.rotate_left(rotation).wrapping_mul(word);
            let shifted = value >> (b2 % 15 + 1);
            let rotated = value.rotate_right((b2 % 31 + 1) as u32);
            match function {
                6 => product.wrapping_add(shifted),
                7 => product.wrapping_sub(shifted),
                8 => product ^ shifted,
                9 => product.wrapping_add(rotated),
                10 => product.wrapping_sub(rotated),
                _ => product ^ rotated,
            }
        }
        // 0x66c480 .. 0x66f8f0 (a 23 é a mesma rotina da 18, 0x677b10).
        12..=23 => {
            let mixed = match function {
                12 | 15 => dword.wrapping_add(value),
                13 | 16 | 19 => dword.wrapping_sub(value),
                14 | 17 | 20 => dword ^ value,
                _ => value.wrapping_sub(dword),
            };
            let product = mixed.rotate_right((b1 % 31 + 1) as u32).wrapping_mul(word);
            let rotated = value.rotate_right((b2 % 31 + 1) as u32);
            match function {
                12 | 13 | 14 | 21 => product.wrapping_add(rotated),
                15 | 16 | 17 | 22 => product.wrapping_sub(rotated),
                _ => product ^ rotated,
            }
        }
        // 0x665fa0, 0x665f30, 0x6680e0: o deslocamento sai de b0 e o
        // segundo índice de palavra, de b1.
        24..=26 => {
            let other = key_word(key, second_word(b1, slot));
            let shift = (b0 % 15 + 1) as u32;
            let mixed = match function {
                24 => (!value).rotate_right(shift).wrapping_add(word),
                25 => value.rotate_right(shift).wrapping_sub(word),
                _ => value.rotate_right(shift) ^ word,
            };
            mixed.wrapping_mul(other)
        }
        // 0x66c450, 0x676d30: as duas palavras de 32 bits pelo bit 0.
        27 => key_dword(key, (index & 1).wrapping_sub(1)).wrapping_sub(key_dword(key, index & 1) ^ value),
        28 => key_dword(key, (index & 1).wrapping_sub(1)) ^ key_dword(key, index & 1) ^ value,
        // 0x66c3f0, 0x66c420.
        29 => value.wrapping_sub(word) ^ dword,
        _ => value.wrapping_sub(dword).wrapping_sub(word),
    }
}

/// A meia-rodada `index` (0..32): função do byte 0x80 + índice e os bytes
/// de parâmetro 4·índice .. 4·índice + 2.
fn half_round(parameters: &Parameters, key: &Key, index: usize, value: u32) -> Option<u32> {
    let function = parameters[0x80 + index];
    if function >= SKIP {
        return None;
    }
    let base = 4 * index;
    Some(round(function, index as u64, parameters[base], parameters[base + 1], parameters[base + 2], key, value))
}

/// As 16 rodadas duplas de trás para a frente (a decifração e o fluxo de
/// chave dos bytes iniciais): R ^= F(2i + 1, L), L ^= F(2i, R), i = 15..0.
fn table_backward(mut left: u32, mut right: u32, parameters: &Parameters, key: &Key) -> (u32, u32) {
    for pair in (0..16).rev() {
        if let Some(value) = half_round(parameters, key, 2 * pair + 1, left) {
            right ^= value;
        }
        if let Some(value) = half_round(parameters, key, 2 * pair, right) {
            left ^= value;
        }
    }
    (left, right)
}

/// As 16 rodadas duplas de frente para trás (a cifração da resposta).
fn table_forward(mut left: u32, mut right: u32, parameters: &Parameters, key: &Key) -> (u32, u32) {
    for pair in 0..16 {
        if let Some(value) = half_round(parameters, key, 2 * pair, right) {
            left ^= value;
        }
        if let Some(value) = half_round(parameters, key, 2 * pair + 1, left) {
            right ^= value;
        }
    }
    (left, right)
}

/// As rodadas inline da decifração do pedido (0x5fe9dd..0x5feb24).
fn inline_request(mut left: u32, mut right: u32, key: &Key) -> (u32, u32) {
    let (k0, k1, k2, k3) = (key_word(key, 0), key_word(key, 1), key_word(key, 2), key_word(key, 3));
    let (low, high) = (key_dword(key, 0), key_dword(key, 1));
    right ^= high ^ low ^ left;
    left ^= (right ^ k1).wrapping_mul(k2) ^ (right >> 8);
    right ^= high.wrapping_sub(left).rotate_right(11).wrapping_mul(k1).wrapping_sub(left.rotate_right(12));
    left ^= (high ^ right).rotate_left(8).wrapping_mul(k0).wrapping_sub(right.rotate_left(2));
    right ^= left.wrapping_sub(low).rotate_right(4).wrapping_mul(k3) ^ left.rotate_right(9);
    left ^= low.wrapping_sub(right).rotate_right(10).wrapping_mul(k2).wrapping_add(right.rotate_right(4));
    right ^= (left ^ k3).rotate_left(4).wrapping_mul(k1).wrapping_sub(left.rotate_right(16));
    left ^= (right ^ k1).wrapping_mul(k0).wrapping_sub(right.rotate_right(7));
    right ^= left.wrapping_sub(low).wrapping_sub(k3);
    left ^= low.wrapping_sub(right).rotate_right(9).wrapping_mul(k2) ^ right.rotate_right(11);
    right ^= left.wrapping_sub(k2).wrapping_mul(k1).wrapping_sub(left >> 13);
    left ^= right.wrapping_sub(k2).rotate_left(3).wrapping_mul(k0) ^ (right >> 15);
    (left, right)
}

/// As rodadas inline da cifração da resposta (0x600a62..0x600b85).
fn inline_reply(mut left: u32, mut right: u32, key: &Key) -> (u32, u32) {
    let (k0, k1, k2, k3) = (key_word(key, 0), key_word(key, 1), key_word(key, 2), key_word(key, 3));
    let (low, high) = (key_dword(key, 0), key_dword(key, 1));
    left ^= (!right).rotate_right(5).wrapping_add(k0).wrapping_mul(k3);
    right ^= (k3 ^ left).wrapping_mul(k1) ^ (left >> 10);
    left ^= (low ^ right).rotate_right(12).wrapping_mul(k2) ^ right.rotate_right(10);
    right ^= left.wrapping_sub(low).rotate_right(14).wrapping_mul(k3).wrapping_sub(left.rotate_left(8));
    left ^= high.wrapping_add(right).rotate_right(15).wrapping_mul(k0).wrapping_add(right.rotate_left(2));
    right ^= left.rotate_right(6) ^ (k2 ^ left).wrapping_mul(k1);
    left ^= high.wrapping_sub(low ^ right);
    right ^= (k1 ^ left).rotate_left(6).wrapping_mul(k3).wrapping_sub(left.rotate_left(2));
    left ^= right.wrapping_sub(k2).wrapping_mul(k0).wrapping_sub(right >> 13);
    right ^= high.wrapping_add(left).rotate_right(9).wrapping_mul(k1).wrapping_sub(left.rotate_left(2));
    left ^= right.wrapping_sub(low).rotate_left(5).wrapping_mul(k2).wrapping_add(right.rotate_left(10));
    right ^= left ^ low ^ high;
    (left, right)
}

/// Os até quatro bytes em big-endian, alinhados à esquerda.
fn word_be(bytes: &[u8]) -> u32 {
    let mut word = [0u8; 4];
    word[..bytes.len()].copy_from_slice(bytes);
    u32::from_be_bytes(word)
}

/// Só os `bytes` bytes mais altos da palavra (os que existem no bloco).
fn keep_high(word: u32, bytes: usize) -> u32 {
    match bytes {
        0 => 0,
        1..=3 => word >> (32 - 8 * bytes) << (32 - 8 * bytes),
        _ => word,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// O pedido, com as rodadas inline do pedido.
    Request,
    /// A resposta, com as rodadas inline da resposta.
    Reply,
}

fn crypt(data: &[u8], parameters: &Parameters, key: &Key, direction: Direction) -> Vec<u8> {
    let head = data.len() % 8;
    let mut output = Vec::with_capacity(data.len());
    // Elos do encadeamento: o claro e o cifrado anteriores.
    let (mut previous_plain, mut previous_cipher) = ((0u32, 0u32), INITIAL_CIPHER);
    if head != 0 {
        let stream = table_backward(INITIAL_CIPHER.0, INITIAL_CIPHER.1, parameters, key);
        let input = (word_be(&data[..head.min(4)]), if head > 4 { word_be(&data[4..head]) } else { 0 });
        let produced = (stream.0 ^ input.0, stream.1 ^ input.1);
        let mut bytes = [0u8; 8];
        bytes[..4].copy_from_slice(&produced.0.to_be_bytes());
        bytes[4..].copy_from_slice(&produced.1.to_be_bytes());
        output.extend_from_slice(&bytes[..head]);
        let kept = (keep_high(produced.0, head.min(4)), keep_high(produced.1, head.saturating_sub(4)));
        (previous_plain, previous_cipher) = match direction {
            Direction::Request => (kept, input),
            Direction::Reply => (input, kept),
        };
    }
    for block in data[head..].chunks_exact(8) {
        let input = (word_be(&block[..4]), word_be(&block[4..]));
        let produced = match direction {
            Direction::Request => {
                let (left, right) = inline_request(input.0 ^ previous_plain.0, input.1 ^ previous_plain.1, key);
                let (left, right) = table_backward(left, right, parameters, key);
                let plain = (left ^ previous_cipher.0, right ^ previous_cipher.1);
                (previous_plain, previous_cipher) = (plain, input);
                plain
            }
            Direction::Reply => {
                let (left, right) = table_forward(input.0 ^ previous_cipher.0, input.1 ^ previous_cipher.1, parameters, key);
                let (left, right) = inline_reply(left, right, key);
                let cipher = (left ^ previous_plain.0, right ^ previous_plain.1);
                (previous_plain, previous_cipher) = (input, cipher);
                cipher
            }
        };
        output.extend_from_slice(&produced.0.to_be_bytes());
        output.extend_from_slice(&produced.1.to_be_bytes());
    }
    output
}

/// Decifra os dados de um pedido (sem o conferidor final).
pub fn decrypt_request(data: &[u8], parameters: &Parameters, key: &Key) -> Vec<u8> {
    crypt(data, parameters, key, Direction::Request)
}

/// Cifra o claro de uma resposta com os parâmetros e a chave do pedido.
pub fn encrypt_reply(plain: &[u8], parameters: &Parameters, key: &Key) -> Vec<u8> {
    crypt(plain, parameters, key, Direction::Reply)
}

/// O conferidor: o XOR de todos os bytes do claro.
pub fn checksum(plain: &[u8]) -> u8 {
    plain.iter().fold(0, |sum, byte| sum ^ byte)
}
