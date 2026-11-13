//! Serial COM1 (canal de depuração), transcrita de `hal/core/host.c`.
//!
//! Cada lote respeita a capacidade detectada da FIFO do 16550A e é enviado
//! com interrupções desligadas, para que outro escritor não consuma as
//! posições entre a consulta de THRE e os OUTs.

use core::sync::atomic::{AtomicUsize, Ordering};

use super::{cpu, port};

const COM1: u16 = 0x3F8;
static FIFO_SIZE: AtomicUsize = AtomicUsize::new(1);

pub fn init() {
    port::write8(COM1 + 1, 0x00);
    port::write8(COM1 + 3, 0x80);
    port::write8(COM1, 0x03);
    port::write8(COM1 + 1, 0x00);
    port::write8(COM1 + 3, 0x03);
    port::write8(COM1 + 2, 0xC7);
    port::write8(COM1 + 4, 0x0B);
    // O 16550A expõe os dois bits de FIFO; UARTs antigas escrevem um byte por vez.
    let size = if port::read8(COM1 + 2) & 0xC0 == 0xC0 { 16 } else { 1 };
    FIFO_SIZE.store(size, Ordering::Relaxed);
}

fn send(bytes: &[u8]) {
    let flags = cpu::save_and_disable_interrupts();
    while port::read8(COM1 + 5) & 0x20 == 0 {
        core::hint::spin_loop();
    }
    for &byte in bytes {
        port::write8(COM1, byte);
    }
    cpu::restore_interrupts(flags);
}

/// Escreve bytes, convertendo `\n` em `\r\n`.
pub fn write(text: &[u8]) {
    let fifo_size = FIFO_SIZE.load(Ordering::Relaxed).clamp(1, 16);
    let mut batch = [0u8; 16];
    let mut used = 0;
    for &byte in text {
        if byte == b'\n' {
            batch[used] = b'\r';
            used += 1;
            if used == fifo_size {
                send(&batch[..used]);
                used = 0;
            }
        }
        batch[used] = byte;
        used += 1;
        if used == fifo_size {
            send(&batch[..used]);
            used = 0;
        }
    }
    if used > 0 {
        send(&batch[..used]);
    }
}

pub fn puts(text: &str) {
    write(text.as_bytes());
}
