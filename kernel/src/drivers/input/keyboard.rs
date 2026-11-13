//! Driver de teclado PS/2 — `system32/drivers/input/keyboard.js`.
//!
//! Lê a porta 0x60 quando 0x64 sinaliza dado. Scancodes do set 1 -> ASCII.
//! O teclado do sistema é o i8042prt.sys + kbdclass.sys da Microsoft (veja
//! `keyboard_stack`), que reutilizam o `decode` daqui; sem esses binários no
//! volume, o kernel usa este driver: o ring buffer alimentado pela IRQ1 (ou
//! polling, sem IRQs).

use core::sync::atomic::{AtomicBool, Ordering};

use crate::hal::port;
use crate::nano::interrupts;

const PORT_STATUS: u16 = 0x64;
const PORT_DATA: u16 = 0x60;

/// Set 1, make codes (índice = scancode). `\0` = sem mapa.
const NORMAL: [char; 58] = [
    '\0', '\0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\u{8}', '\t', //
    'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n', '\0', 'a', 's', //
    'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', '\0', '\\', 'z', 'x', 'c', 'v', //
    'b', 'n', 'm', ',', '.', '/', '\0', '*', '\0', ' ',
];

const SHIFTED: [char; 58] = [
    '\0', '\0', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '\u{8}', '\t', //
    'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n', '\0', 'A', 'S', //
    'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~', '\0', '|', 'Z', 'X', 'C', 'V', //
    'B', 'N', 'M', '<', '>', '?', '\0', '*', '\0', ' ',
];

const SCANCODE_LEFT_SHIFT: u8 = 0x2A;
const SCANCODE_RIGHT_SHIFT: u8 = 0x36;

static SHIFT: AtomicBool = AtomicBool::new(false);

/// Decodifica um scancode; devolve o caractere, ou `None` (tecla sem mapa
/// ou modificador).
pub fn decode(scancode: u8) -> Option<char> {
    if scancode & 0x80 != 0 {
        // break code (soltou)
        let make = scancode & 0x7F;
        if make == SCANCODE_LEFT_SHIFT || make == SCANCODE_RIGHT_SHIFT {
            SHIFT.store(false, Ordering::Relaxed);
        }
        return None;
    }
    if scancode == SCANCODE_LEFT_SHIFT || scancode == SCANCODE_RIGHT_SHIFT {
        SHIFT.store(true, Ordering::Relaxed);
        return None;
    }
    if scancode == 0xE0 {
        // estendido: descarta o próximo
        if port::read8(PORT_STATUS) & 1 != 0 {
            port::read8(PORT_DATA);
        }
        return None;
    }
    let table = if SHIFT.load(Ordering::Relaxed) { &SHIFTED } else { &NORMAL };
    match table.get(scancode as usize) {
        Some(&character) if character != '\0' => Some(character),
        _ => None,
    }
}

/// Não bloqueante: caractere ou `None` se não há tecla.
/// Com IRQs: lê do ring buffer alimentado pela IRQ1 (`nano::interrupts`).
/// Sem IRQs: polling direto da porta 0x60.
pub fn poll_key() -> Option<char> {
    if interrupts::is_available() {
        return decode(interrupts::poll_scancode()?);
    }
    if port::read8(PORT_STATUS) & 1 == 0 {
        return None;
    }
    decode(port::read8(PORT_DATA))
}

/// Bloqueante.
pub fn read_key() -> char {
    loop {
        if let Some(key) = poll_key() {
            return key;
        }
        core::hint::spin_loop();
    }
}
