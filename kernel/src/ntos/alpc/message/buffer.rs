//! Captura e entrega de buffers ALPC x64 — `system32/ntos/alpc/message-buffer.js`.
//!
//! Compartilhadas pelos caminhos Nt e Zw. A capacidade declarada não é a
//! extensão sondada: só os bytes efetivos são acessados.

use alloc::vec::Vec;

use crate::ntos::mm::{page_residency, paging};
use crate::ntos::ps::user::state;
use crate::ntos::mm::guest_memory as guest;

pub const HEADER_SIZE: u64 = 40;
const ACCESS_VIOLATION: u32 = 0xC000_0005;
const USER_PROBE_LIMIT: u64 = 0x7FFF_FFFF_0000;

/// UserMode sonda a faixa de usuário; KernelMode exige páginas presentes
/// (com falha de residência resolvida) e endereço canônico.
pub fn accessible(address: u64, length: u64, access_mode: u8, writing: bool) -> bool {
    if access_mode != 0 {
        return address < USER_PROBE_LIMIT && if writing { state::probe_user_write(address, length) } else { state::probe_user_read(address, length) };
    }
    let Some(end) = address.checked_add(length) else { return false };
    if address == 0 || (address < 0xFFFF_8000_0000_0000 && end > 0x8000_0000_0000) {
        return false;
    }
    let required = if writing { 3 } else { 1 };
    let mut page = address & !0xFFF;
    while page < end {
        let flags = paging::access_flags(page);
        if flags & required != required && (!page_residency::fault(page, (if writing { 2 } else { 0 }) | (flags & 1) as u32) || paging::access_flags(page) & required != required) {
            return false;
        }
        page += 0x1000;
    }
    true
}

pub fn writable(address: u64, length: u64, access_mode: u8) -> bool {
    accessible(address, length, access_mode, true)
}

/// PORT_MESSAGE x64 capturado (cabeçalho e dados).
pub struct Captured {
    pub header: [u8; 40],
    pub data: Vec<u8>,
}

/// Tamanhos inconsistentes precedem PORT_MESSAGE_TOO_LONG; o remetente
/// não é alterado.
pub fn capture_message(input: u64, maximum_length: u32, access_mode: u8) -> Result<Captured, u32> {
    if !accessible(input, HEADER_SIZE, access_mode, false) {
        return Err(ACCESS_VIOLATION);
    }
    let mut header = [0u8; 40];
    for (index, byte) in header.iter_mut().enumerate() {
        *byte = guest::read8(input + index as u64);
    }
    let data_length = u16::from_le_bytes([header[0], header[1]]) as u64;
    let total_length = u16::from_le_bytes([header[2], header[3]]) as u64;
    if total_length != HEADER_SIZE + data_length || u16::from_le_bytes([header[6], header[7]]) != 0 {
        return Err(0xC000_000D);
    }
    if total_length > maximum_length as u64 {
        return Err(0xC000_002F);
    }
    if !accessible(input + 40, data_length, access_mode, false) {
        return Err(ACCESS_VIOLATION);
    }
    let data = (0..data_length).map(|index| guest::read8(input + 40 + index)).collect();
    Ok(Captured { header, data })
}

/// O cabeçalho de recepção exige alinhamento ULONG em UserMode.
pub fn probe_header(output: u64, access_mode: u8) -> u32 {
    if access_mode == 0 {
        return 0;
    }
    if output & 3 != 0 {
        return 0x8000_0002;
    }
    if writable(output, HEADER_SIZE, access_mode) { 0 } else { ACCESS_VIOLATION }
}

/// Buffer de recepção: o SIZE_T é capturado uma vez; sem ponteiro de
/// comprimento a capacidade é ilimitada.
#[derive(Clone, Copy)]
pub struct Buffer {
    pub output: u64,
    pub length_address: u64,
    pub capacity: u64,
    pub access_mode: u8,
}

pub fn capture_length(output: u64, length_address: u64, access_mode: u8) -> Result<Buffer, u32> {
    if length_address != 0 && !writable(length_address, 8, access_mode) {
        return Err(ACCESS_VIOLATION);
    }
    Ok(Buffer { output, length_address, capacity: if length_address != 0 { guest::read64(length_address) } else { u64::MAX }, access_mode })
}

/// BUFFER_TOO_SMALL informa o tamanho e deixa a mensagem na fila; a entrega
/// síncrona escreve o comprimento depois dos bytes.
pub fn deliver(buffer: &Buffer, message: &[u8], synchronous: bool) -> u32 {
    let required = message.len() as u64;
    if buffer.capacity < required {
        if buffer.length_address != 0 {
            if !writable(buffer.length_address, 8, buffer.access_mode) {
                return ACCESS_VIOLATION;
            }
            guest::write64(buffer.length_address, required);
        }
        return 0xC000_0023;
    }
    if !writable(buffer.output, required, buffer.access_mode) {
        return ACCESS_VIOLATION;
    }
    guest::write_bytes(buffer.output, message);
    if synchronous && buffer.length_address != 0 {
        if !writable(buffer.length_address, 8, buffer.access_mode) {
            return ACCESS_VIOLATION;
        }
        guest::write64(buffer.length_address, required);
    }
    0
}
