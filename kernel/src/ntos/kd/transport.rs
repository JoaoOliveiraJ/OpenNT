//! Transporte serial do depurador do kernel: uma UART 16550 por E/S
//! programada, sem interrupção (o papel do transporte serial do KD).
//!
//! A COM1 é o log do kernel; o depurador fica numa das outras portas ISA
//! (`--kd=com2`, `com3` ou `com4`). A porta trabalha a 115200 8N1. No boot a
//! FIFO fica no estado em que o firmware a deixou: ligar ou desligar a FIFO
//! descarta o que já chegou, e um pedido de parada enviado pelo host antes
//! do boot precisa sobreviver até a primeira consulta. A sessão liga a FIFO
//! (`enable_fifo`) depois do primeiro pacote recebido, quando o host espera
//! a resposta e não manda nada; o byte que estiver no receptor fica no
//! `PUSHBACK`. Com a FIFO o transmissor aceita 16 bytes a cada THRE, que
//! saem num `rep outsb` (`Sender`: cerca de 9 µs por byte no WHPX contra
//! 42 µs de um LSR e um OUT por byte), e o receptor guarda até 14 bytes
//! antes de o emulador parar de entregar (sem a FIFO, o QEMU entrega um
//! byte por volta do laço principal).
//!
//! Sem OUT2 no MCR a UART não pede IRQ: toda leitura é por consulta do LSR,
//! inclusive a do pedido de parada, que o tique do relógio faz (como o
//! KdPollBreakIn do NT). O custo parado é uma leitura do LSR por tique de
//! 10 ms em cada processador no anel 0 (100 por segundo por processador):
//! uma IRQ da UART pouparia só isso e exigiria rotear a IRQ 3/4 pelo IOAPIC
//! que o acpi.sys programa, por isso a consulta fica.
//!
//! Quem escreve fora da parada (o DbgPrint repassado ao host) toma a trava
//! do transporte; o dono da parada a ignora quando o dono dela está
//! congelado, porque um processador parado no meio de um pacote não volta a
//! tocar a porta antes do degelo.

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};

use crate::hal::{cpu, port};
use crate::ntos::ke::clock;

const RECEIVE_TRANSMIT: u16 = 0;
const INTERRUPT_ENABLE: u16 = 1;
/// Escrita: FCR; leitura: IIR.
const FIFO_CONTROL: u16 = 2;
const INTERRUPT_IDENTIFICATION: u16 = 2;
const LINE_CONTROL: u16 = 3;
const MODEM_CONTROL: u16 = 4;
const LINE_STATUS: u16 = 5;
const SCRATCH: u16 = 7;
const LINE_STATUS_DATA_READY: u8 = 0x01;
const LINE_STATUS_TRANSMIT_EMPTY: u8 = 0x20;
/// TEMT: o registrador de deslocamento também esvaziou.
const LINE_STATUS_TRANSMITTER_IDLE: u8 = 0x40;
/// FCR: FIFO ligada, as duas FIFOs limpas e o gatilho do receptor em 14
/// bytes (o emulador entrega até 14 bytes de uma vez).
const FIFO_ENABLE_CLEAR_TRIGGER_14: u8 = 0xC7;
/// IIR bits 6-7: as FIFOs funcionam (16550A).
const IIR_FIFOS_ENABLED: u8 = 0xC0;
/// Bytes que o transmissor aceita depois do THRE com a FIFO ligada.
const TRANSMIT_FIFO_DEPTH: usize = 16;

/// Base da UART do depurador (0 = sem transporte).
static BASE: AtomicU16 = AtomicU16::new(0);
/// As FIFOs do 16550A estão ligadas (pelo IIR na inicialização ou pelo
/// `enable_fifo`): o `Sender` manda lotes de 16.
static FIFO: AtomicBool = AtomicBool::new(false);
/// O `enable_fifo` já programou o FCR (FIFO e gatilho de 14 bytes).
static FIFO_CONFIGURED: AtomicBool = AtomicBool::new(false);
/// Dono da trava do transporte: número do processador + 1 (0 = livre).
static LOCK_OWNER: AtomicU32 = AtomicU32::new(0);
/// Byte devolvido à entrada (0x100 | byte; 0 = nenhum): o tique do relógio
/// lê o primeiro byte de um pacote para decidir parar, e a sessão o relê.
static PUSHBACK: AtomicU16 = AtomicU16::new(0);

/// Base de E/S das portas que o depurador aceita. A COM1 é o log do kernel.
pub fn port_base(name: &str) -> Option<u16> {
    [("com2", 0x2F8), ("com3", 0x3E8), ("com4", 0x2E8)].into_iter().find(|(port, _)| port.eq_ignore_ascii_case(name)).map(|(_, base)| base)
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
    // A FIFO fica como está (o firmware, ou a sessão antes de uma volta a
    // D0); o IIR diz se ela funciona, e desligada a sessão a liga de novo.
    let fifo = port::read8(base + INTERRUPT_IDENTIFICATION) & IIR_FIFOS_ENABLED == IIR_FIFOS_ENABLED;
    FIFO.store(fifo, Ordering::Release);
    if !fifo {
        FIFO_CONFIGURED.store(false, Ordering::Release);
    }
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

/// Liga as FIFOs do 16550A com o gatilho de 14 bytes (ver o comentário do
/// módulo), uma vez. Só pode ser chamada quando o host não está mandando
/// nada: entre a leitura do byte pendente e a escrita do FCR, um byte novo
/// seria descartado. Mais de um byte pendente (um não cabe no `PUSHBACK`)
/// adia a troca para a próxima vez. Uma UART sem FIFO (8250/16450) continua
/// byte a byte.
pub fn enable_fifo() -> bool {
    if FIFO_CONFIGURED.load(Ordering::Acquire) {
        return FIFO.load(Ordering::Acquire);
    }
    let base = base();
    if base == 0 {
        return false;
    }
    // A limpeza da FIFO de transmissão descartaria o `+` que acabou de ir.
    while port::read8(base + LINE_STATUS) & LINE_STATUS_TRANSMITTER_IDLE == 0 {
        cpu::pause();
    }
    if port::read8(base + LINE_STATUS) & LINE_STATUS_DATA_READY != 0 {
        if PUSHBACK.load(Ordering::Acquire) != 0 {
            return false;
        }
        unread(port::read8(base + RECEIVE_TRANSMIT));
        if port::read8(base + LINE_STATUS) & LINE_STATUS_DATA_READY != 0 {
            return false;
        }
    }
    port::write8(base + FIFO_CONTROL, FIFO_ENABLE_CLEAR_TRIGGER_14);
    let enabled = port::read8(base + INTERRUPT_IDENTIFICATION) & IIR_FIFOS_ENABLED == IIR_FIFOS_ENABLED;
    if !enabled {
        port::write8(base + FIFO_CONTROL, 0);
    }
    FIFO.store(enabled, Ordering::Release);
    FIFO_CONFIGURED.store(true, Ordering::Release);
    enabled
}

/// As FIFOs estão ligadas.
pub fn fifo_enabled() -> bool {
    FIFO.load(Ordering::Acquire)
}

/// Envio em lotes, como a COM1 (`hal::serial`): com a FIFO ligada, até 16
/// bytes esperam o THRE uma vez e saem num `rep outsb`. No WHPX cada OUT é
/// uma saída para o QEMU (21 µs medidos na COM1) e o `rep outsb` sai uma
/// vez por lote (7,8 µs por byte): um byte custava uma leitura do LSR e um
/// OUT (cerca de 42 µs), um lote de 16 custa cerca de 146 µs (9 µs por
/// byte). Sem a FIFO, um byte por THRE. O que sobra no lote sai no `flush`
/// (ou quando o `Sender` acaba).
pub struct Sender {
    base: u16,
    depth: usize,
    batch: [u8; TRANSMIT_FIFO_DEPTH],
    used: usize,
}

impl Sender {
    pub fn new() -> Self {
        Self { base: base(), depth: if fifo_enabled() { TRANSMIT_FIFO_DEPTH } else { 1 }, batch: [0; TRANSMIT_FIFO_DEPTH], used: 0 }
    }

    pub fn put(&mut self, byte: u8) {
        if self.base == 0 {
            return;
        }
        self.batch[self.used] = byte;
        self.used += 1;
        if self.used >= self.depth {
            self.flush();
        }
    }

    pub fn put_all(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.put(byte);
        }
    }

    /// Manda o lote: espera o THRE (a FIFO de transmissão vazia) e escreve
    /// tudo numa instrução.
    pub fn flush(&mut self) {
        if self.used == 0 || self.base == 0 {
            self.used = 0;
            return;
        }
        while port::read8(self.base + LINE_STATUS) & LINE_STATUS_TRANSMIT_EMPTY == 0 {
            cpu::pause();
        }
        // SAFETY: lê `used` bytes do lote (DF é zero: a ABI no código Rust e
        // o `cld` dos trampolins) e os escreve na porta de dados da UART;
        // com o THRE ligado a FIFO tem espaço para `depth` bytes.
        unsafe {
            core::arch::asm!(
                "rep outsb",
                in("dx") self.base + RECEIVE_TRANSMIT,
                inout("rsi") self.batch.as_ptr() => _,
                inout("rcx") self.used => _,
                options(nostack, preserves_flags, readonly),
            );
        }
        self.used = 0;
    }
}

impl Default for Sender {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Envia um byte quando o transmissor esvazia.
pub fn write(byte: u8) {
    Sender::new().put(byte);
}

pub fn write_all(bytes: &[u8]) {
    Sender::new().put_all(bytes);
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
