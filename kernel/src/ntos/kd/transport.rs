//! Transporte serial do depurador do kernel: uma UART 16550 por E/S
//! programada, sem interrupção (o papel do transporte serial do KD).
//!
//! A COM1 é o log do kernel; o depurador fica numa das outras portas ISA
//! (`--kd=com2`, `com3` ou `com4`). A porta trabalha a 115200 8N1 com a FIFO
//! no estado em que o firmware a deixou: ligar ou desligar a FIFO descarta o
//! que já chegou, e um pedido de parada enviado pelo host antes do boot
//! precisa sobreviver até a primeira consulta. Sem OUT2 no MCR a UART não
//! pede IRQ: toda leitura é por consulta do LSR, inclusive a do pedido de
//! parada, que o tique do relógio faz (como o KdPollBreakIn do NT).
//!
//! Quem escreve fora da parada (o DbgPrint repassado ao host) toma a trava
//! do transporte; o dono da parada a ignora quando o dono dela está
//! congelado, porque um processador parado no meio de um pacote não volta a
//! tocar a porta antes do degelo.

use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};

use crate::hal::{cpu, port};
use crate::ntos::ke::clock;

const RECEIVE_TRANSMIT: u16 = 0;
const INTERRUPT_ENABLE: u16 = 1;
const LINE_CONTROL: u16 = 3;
const MODEM_CONTROL: u16 = 4;
const LINE_STATUS: u16 = 5;
const SCRATCH: u16 = 7;
const LINE_STATUS_DATA_READY: u8 = 0x01;
const LINE_STATUS_TRANSMIT_EMPTY: u8 = 0x20;

/// Base da UART do depurador (0 = sem transporte).
static BASE: AtomicU16 = AtomicU16::new(0);
/// Dono da trava do transporte: número do processador + 1 (0 = livre).
static LOCK_OWNER: AtomicU32 = AtomicU32::new(0);
/// Byte devolvido à entrada (0x100 | byte; 0 = nenhum): o tique do relógio
/// lê o primeiro byte de um pacote para decidir parar, e a sessão o relê.
static PUSHBACK: AtomicU16 = AtomicU16::new(0);

/// Base de E/S das portas que o depurador aceita. A COM1 é o log do kernel.
pub fn port_base(name: &str) -> Option<u16> {
    match name {
        "com2" => Some(0x2F8),
        "com3" => Some(0x3E8),
        "com4" => Some(0x2E8),
        _ => None,
    }
}

/// Programa a UART em `base`; `false` se não há porta ali (o registrador de
/// rascunho não guarda o valor escrito).
pub fn initialize(base: u16) -> bool {
    port::write8(base + SCRATCH, 0x5A);
    if port::read8(base + SCRATCH) != 0x5A {
        return false;
    }
    port::write8(base + INTERRUPT_ENABLE, 0);
    port::write8(base + LINE_CONTROL, 0x80);
    port::write8(base + RECEIVE_TRANSMIT, 1);
    port::write8(base + INTERRUPT_ENABLE, 0);
    port::write8(base + LINE_CONTROL, 0x03);
    port::write8(base + MODEM_CONTROL, 0x03);
    BASE.store(base, Ordering::Release);
    true
}

/// Base da porta (0 sem depurador).
pub fn base() -> u16 {
    BASE.load(Ordering::Acquire)
}

/// Porta do LSR, consultada pelo tique do relógio.
pub fn line_status_port() -> u16 {
    base() + LINE_STATUS
}

/// Há um byte esperando no receptor.
pub fn byte_pending() -> bool {
    let base = base();
    PUSHBACK.load(Ordering::Acquire) != 0 || (base != 0 && port::read8(base + LINE_STATUS) & LINE_STATUS_DATA_READY != 0)
}

/// O próximo byte recebido, se houver.
pub fn read() -> Option<u8> {
    let pushed = PUSHBACK.swap(0, Ordering::AcqRel);
    if pushed != 0 {
        return Some(pushed as u8);
    }
    if !byte_pending() {
        return None;
    }
    Some(port::read8(base() + RECEIVE_TRANSMIT))
}

/// Devolve um byte lido à entrada.
pub fn unread(byte: u8) {
    PUSHBACK.store(0x100 | byte as u16, Ordering::Release);
}

/// Espera o próximo byte sem prazo (a máquina está parada no depurador).
pub fn read_blocking() -> u8 {
    loop {
        if let Some(byte) = read() {
            return byte;
        }
        cpu::pause();
    }
}

/// Espera o próximo byte por até `milliseconds`.
pub fn read_timeout(milliseconds: u64) -> Option<u8> {
    let deadline = clock::uptime_ms() + milliseconds;
    loop {
        if let Some(byte) = read() {
            return Some(byte);
        }
        if clock::uptime_ms() >= deadline {
            return None;
        }
        cpu::pause();
    }
}

/// Envia um byte quando o transmissor esvazia.
pub fn write(byte: u8) {
    let base = base();
    if base == 0 {
        return;
    }
    while port::read8(base + LINE_STATUS) & LINE_STATUS_TRANSMIT_EMPTY == 0 {
        cpu::pause();
    }
    port::write8(base + RECEIVE_TRANSMIT, byte);
}

pub fn write_all(bytes: &[u8]) {
    for &byte in bytes {
        write(byte);
    }
}

/// Toma a trava do transporte para o processador `cpu`, esperando.
pub fn lock(cpu: usize) {
    let me = cpu as u32 + 1;
    while LOCK_OWNER.compare_exchange_weak(0, me, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
}

/// Tenta tomar a trava sem esperar.
pub fn try_lock(cpu: usize) -> bool {
    LOCK_OWNER.compare_exchange(0, cpu as u32 + 1, Ordering::Acquire, Ordering::Relaxed).is_ok()
}

pub fn unlock() {
    LOCK_OWNER.store(0, Ordering::Release);
}

/// Dono corrente da trava (número do processador), se houver.
pub fn lock_owner() -> Option<usize> {
    match LOCK_OWNER.load(Ordering::Acquire) {
        0 => None,
        owner => Some(owner as usize - 1),
    }
}

/// O dono da parada assume a porta: a trava passa a ele, mesmo que o dono
/// anterior esteja congelado no meio de um pacote.
pub fn seize(cpu: usize) {
    LOCK_OWNER.store(cpu as u32 + 1, Ordering::Release);
}
