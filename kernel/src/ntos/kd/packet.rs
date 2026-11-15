//! Enquadramento do protocolo serial remoto do GDB (RSP): `$dados#cs`, com a
//! soma dos bytes módulo 256 em dois dígitos hexadecimais, confirmação `+`
//! (ou `-` para repetir) até o host pedir o modo sem confirmação
//! (`QStartNoAckMode`), e o byte 0x03 avulso como pedido de parada.
//!
//! Nada aqui aloca: o depurador roda com os outros processadores congelados
//! e com o processador parado onde quer que estivesse, inclusive com a trava
//! do heap tomada. Os buffers são estáticos e só o dono da parada os usa.

use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

use super::transport;

/// Maior pacote aceito, anunciado no `PacketSize` do qSupported.
pub const PACKET_SIZE: usize = 0x1000;
/// Prazo de uma confirmação antes de repetir o pacote.
const ACK_TIMEOUT_MS: u64 = 2000;
const ACK_RETRIES: u32 = 5;

/// O host pediu o modo sem confirmação.
static NO_ACK: AtomicBool = AtomicBool::new(false);
/// Um 0x03 chegou enquanto se esperava uma confirmação.
static INTERRUPT_SEEN: AtomicBool = AtomicBool::new(false);

pub fn set_no_ack(value: bool) {
    NO_ACK.store(value, Ordering::Release);
}

pub fn no_ack() -> bool {
    NO_ACK.load(Ordering::Acquire)
}

/// Consome a marca de 0x03 visto durante uma espera de confirmação.
pub fn take_interrupt() -> bool {
    INTERRUPT_SEEN.swap(false, Ordering::AcqRel)
}

/// Texto de um pacote em construção sobre um buffer fixo; o que não cabe é
/// descartado e marcado em `overflow`.
pub struct Payload<'a> {
    buffer: &'a mut [u8],
    length: usize,
    pub overflow: bool,
}

impl<'a> Payload<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, length: 0, overflow: false }
    }

    pub fn push(&mut self, byte: u8) {
        if self.length < self.buffer.len() {
            self.buffer[self.length] = byte;
            self.length += 1;
        } else {
            self.overflow = true;
        }
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.push(byte);
        }
    }

    pub fn push_str(&mut self, text: &str) {
        self.push_bytes(text.as_bytes());
    }

    /// Um byte em dois dígitos hexadecimais minúsculos.
    pub fn push_hex_byte(&mut self, byte: u8) {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        self.push(DIGITS[(byte >> 4) as usize]);
        self.push(DIGITS[(byte & 15) as usize]);
    }

    /// Bytes em hexadecimal, na ordem da memória.
    pub fn push_hex(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.push_hex_byte(byte);
        }
    }

    /// Um número em hexadecimal sem zeros à esquerda (o formato dos números
    /// do protocolo).
    pub fn push_number(&mut self, value: u64) {
        let _ = fmt::Write::write_fmt(self, format_args!("{:x}", value));
    }

    /// Texto codificado em hexadecimal (a saída de `O` e do `qRcmd`).
    pub fn push_hex_text(&mut self, text: &[u8]) {
        self.push_hex(text);
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..self.length]
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn clear(&mut self) {
        self.length = 0;
        self.overflow = false;
    }
}

impl fmt::Write for Payload<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.push_str(text);
        Ok(())
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Dois dígitos hexadecimais em um byte.
pub fn hex_byte(high: u8, low: u8) -> Option<u8> {
    Some(hex_digit(high)? << 4 | hex_digit(low)?)
}

/// Um número hexadecimal do protocolo (sem prefixo).
pub fn parse_number(text: &[u8]) -> Option<u64> {
    if text.is_empty() || text.len() > 16 {
        return None;
    }
    let mut value = 0u64;
    for &byte in text {
        value = value << 4 | hex_digit(byte)? as u64;
    }
    Some(value)
}

/// Decodifica hexadecimal em `output`; devolve quantos bytes.
pub fn decode_hex(text: &[u8], output: &mut [u8]) -> Option<usize> {
    if text.len() % 2 != 0 || text.len() / 2 > output.len() {
        return None;
    }
    for (index, pair) in text.chunks_exact(2).enumerate() {
        output[index] = hex_byte(pair[0], pair[1])?;
    }
    Some(text.len() / 2)
}

/// Desfaz o escape dos dados binários do `X` (`}` seguido do byte XOR 0x20)
/// no próprio buffer; devolve o comprimento.
pub fn unescape_binary(data: &mut [u8]) -> usize {
    let mut read = 0;
    let mut write = 0;
    while read < data.len() {
        let mut byte = data[read];
        read += 1;
        if byte == b'}' && read < data.len() {
            byte = data[read] ^ 0x20;
            read += 1;
        }
        data[write] = byte;
        write += 1;
    }
    write
}

fn checksum(payload: &[u8]) -> u8 {
    payload.iter().fold(0u8, |sum, &byte| sum.wrapping_add(byte))
}

fn transmit(payload: &[u8]) {
    transport::write(b'$');
    transport::write_all(payload);
    transport::write(b'#');
    let sum = checksum(payload);
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    transport::write(DIGITS[(sum >> 4) as usize]);
    transport::write(DIGITS[(sum & 15) as usize]);
}

/// Envia um pacote e, no modo com confirmação, espera o `+` (repete no `-`
/// ou no prazo). `false` se o host não confirmou.
pub fn send(payload: &[u8]) -> bool {
    for _ in 0..ACK_RETRIES {
        transmit(payload);
        if no_ack() {
            return true;
        }
        loop {
            match transport::read_timeout(ACK_TIMEOUT_MS) {
                Some(b'+') => return true,
                Some(b'-') | None => break,
                Some(0x03) => INTERRUPT_SEEN.store(true, Ordering::Release),
                Some(_) => {}
            }
        }
    }
    false
}

/// Envia um pacote sem esperar além de uma confirmação curta (a saída de
/// `O` com a máquina rodando): um host que não confirma não segura o
/// DbgPrint de quem imprimiu.
pub fn send_unreliable(payload: &[u8]) {
    transmit(payload);
    if no_ack() {
        return;
    }
    loop {
        match transport::read_timeout(200) {
            Some(b'+') | Some(b'-') | None => return,
            Some(0x03) => INTERRUPT_SEEN.store(true, Ordering::Release),
            Some(_) => {}
        }
    }
}

/// O que chegou do host com a máquina parada.
pub enum Received {
    /// Um pacote válido, já confirmado, com este comprimento em `buffer`.
    Packet(usize),
    /// O 0x03 avulso (pedido de parada).
    Interrupt,
}

/// Espera o próximo pacote. Pacotes com soma errada recebem `-` e são
/// descartados; confirmações avulsas são ignoradas.
pub fn receive(buffer: &mut [u8]) -> Received {
    loop {
        match transport::read_blocking() {
            0x03 => return Received::Interrupt,
            b'$' => {}
            _ => continue,
        }
        let mut length = 0;
        let mut sum = 0u8;
        let mut overflow = false;
        loop {
            let byte = transport::read_blocking();
            if byte == b'#' {
                break;
            }
            if byte == b'$' {
                // Um pacote novo começou no meio do anterior: vale o novo.
                length = 0;
                sum = 0;
                overflow = false;
                continue;
            }
            sum = sum.wrapping_add(byte);
            if length < buffer.len() {
                buffer[length] = byte;
                length += 1;
            } else {
                overflow = true;
            }
        }
        let high = transport::read_blocking();
        let low = transport::read_blocking();
        let valid = hex_byte(high, low) == Some(sum) && !overflow;
        if !no_ack() {
            transport::write(if valid { b'+' } else { b'-' });
        }
        if valid {
            return Received::Packet(length);
        }
    }
}
