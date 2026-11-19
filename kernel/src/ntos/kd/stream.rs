//! Fluxo de registros para o host: o monitor de APIs (`api_monitor`) e o
//! rastreador de IRPs (`irp_trace`) gravam registros curtos num anel e o
//! host os recebe em lotes.
//!
//! O anel tem `SLOTS` posições de `SLOT_SIZE` bytes, reservadas no boot com
//! `--kd` (`reserve`, fora da imagem do kernel). Cada registro ganha um
//! número de sequência (`NEXT`); a posição é o número módulo `SLOTS`. Quem
//! grava zera o selo da posição, copia o registro e grava o selo com o
//! número + 1 (`COMMIT`). Quem lê confere o selo antes e depois da cópia:
//! um registro sobrescrito no meio da leitura é descartado. Nada aqui toma
//! trava do kernel nem aloca depois da reserva.
//!
//! Entrega:
//! - com a máquina rodando e o host pedindo (`stream on`), o próprio
//!   gravador manda os registros pendentes ao host num pacote `O` quando o
//!   lote passa de `BATCH` registros ou de `FLUSH_MS` milissegundos, só se a
//!   trava do transporte estiver livre (senão fica para o próximo);
//! - com a máquina parada, o host lê por `qOpenNTStream:SEQ` a partir do
//!   número que ainda não tem (a leitura não muda o estado: um pedido
//!   repetido devolve o mesmo).
//!
//! O conteúdo do `O` começa com o marcador `\0OSTR` e a versão; um GDB
//! comum mostraria bytes estranhos, por isso a entrega assíncrona só liga a
//! pedido. O formato dos registros é o de `tools/opennt-kd/src/stream.rs`:
//!
//! ```text
//! cabeçalho: tamanho u16 | tipo u8 | CPU u8 | flags u32 | sequência u64 | hora u64 (100 ns)
//! ```

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};

use super::packet::{self, Payload};
use super::{session, stop, transport};
use crate::hal::cpu;
use crate::ntos::ke::clock;

pub const SLOT_SIZE: usize = 384;
pub const SLOTS: usize = 1024;
pub const HEADER_SIZE: usize = 24;
/// O marcador do conteúdo de um `O` com registros.
pub const MARKER: &[u8; 5] = b"\0OSTR";
const VERSION: u8 = 1;
/// Registros por lote assíncrono.
const BATCH: u64 = 24;
const FLUSH_MS: u64 = 25;
/// Bytes de registros por pacote `O` (dois dígitos por byte).
const PACKET_BYTES: usize = 1700;
/// Pacotes por descarga (o resto fica para a próxima).
const PACKETS_PER_FLUSH: usize = 3;

pub const KIND_API: u8 = 1;
pub const KIND_IRP_ALLOCATE: u8 = 0x10;
pub const KIND_IRP_CALL: u8 = 0x11;
pub const KIND_IRP_RETURN: u8 = 0x12;
pub const KIND_IRP_COMPLETE: u8 = 0x13;
pub const KIND_IRP_ROUTINE: u8 = 0x14;
pub const KIND_IRP_FREE: u8 = 0x15;

static BUFFER: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static COMMIT: AtomicPtr<AtomicU64> = AtomicPtr::new(core::ptr::null_mut());
/// O próximo número de sequência.
static NEXT: AtomicU64 = AtomicU64::new(0);
/// O primeiro número ainda não mandado pela entrega assíncrona.
static SENT: AtomicU64 = AtomicU64::new(0);
/// Registros perdidos (anel cheio antes da entrega, ou registro grande demais).
static DROPPED: AtomicU64 = AtomicU64::new(0);
static LAST_FLUSH_MS: AtomicU64 = AtomicU64::new(0);
static FLUSHING: AtomicBool = AtomicBool::new(false);
/// O host pediu a entrega assíncrona (`stream on`).
static ASYNC: AtomicBool = AtomicBool::new(false);

/// Reserva o anel (o `kd::initialize` com o depurador ligado).
pub fn reserve() {
    if !BUFFER.load(Ordering::Acquire).is_null() {
        return;
    }
    let buffer: &'static mut [u8] = Box::leak(vec![0u8; SLOTS * SLOT_SIZE].into_boxed_slice());
    let commit: &'static mut [AtomicU64] = Box::leak((0..SLOTS).map(|_| AtomicU64::new(0)).collect::<Vec<_>>().into_boxed_slice());
    COMMIT.store(commit.as_mut_ptr(), Ordering::Release);
    BUFFER.store(buffer.as_mut_ptr(), Ordering::Release);
}

pub fn available() -> bool {
    !BUFFER.load(Ordering::Acquire).is_null()
}

fn commit_cell(slot: usize) -> &'static AtomicU64 {
    // SAFETY: `SLOTS` selos vivos para sempre (`reserve`), chamado só com o
    // anel reservado.
    unsafe { &*COMMIT.load(Ordering::Acquire).add(slot) }
}

fn slot_pointer(slot: usize) -> *mut u8 {
    // SAFETY: `slot < SLOTS` dentro do anel reservado.
    unsafe { BUFFER.load(Ordering::Acquire).add(slot * SLOT_SIZE) }
}

/// A hora dos registros: 100 ns desde o boot (o QPC a 10 MHz).
pub fn now() -> u64 {
    clock::uptime_100ns()
}

/// Um registro em montagem (na pilha de quem grava).
pub struct Record {
    bytes: [u8; SLOT_SIZE],
    length: usize,
}

impl Record {
    /// Começa um registro do tipo, com a hora dada.
    pub fn new(kind: u8, flags: u32, time: u64) -> Self {
        let mut record = Record { bytes: [0; SLOT_SIZE], length: HEADER_SIZE };
        record.bytes[2] = kind;
        record.bytes[3] = stop::current_processor() as u8;
        record.bytes[4..8].copy_from_slice(&flags.to_le_bytes());
        record.bytes[16..24].copy_from_slice(&time.to_le_bytes());
        record
    }

    pub fn set_flags(&mut self, flags: u32) {
        self.bytes[4..8].copy_from_slice(&flags.to_le_bytes());
    }

    pub fn flags(&self) -> u32 {
        u32::from_le_bytes([self.bytes[4], self.bytes[5], self.bytes[6], self.bytes[7]])
    }

    /// Espaço livre no registro.
    pub fn room(&self) -> usize {
        SLOT_SIZE - self.length
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == HEADER_SIZE
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() > self.room() {
            return false;
        }
        self.bytes[self.length..self.length + bytes.len()].copy_from_slice(bytes);
        self.length += bytes.len();
        true
    }

    pub fn push_u8(&mut self, value: u8) -> bool {
        self.push_bytes(&[value])
    }

    pub fn push_u16(&mut self, value: u16) -> bool {
        self.push_bytes(&value.to_le_bytes())
    }

    pub fn push_u32(&mut self, value: u32) -> bool {
        self.push_bytes(&value.to_le_bytes())
    }

    pub fn push_u64(&mut self, value: u64) -> bool {
        self.push_bytes(&value.to_le_bytes())
    }

    /// Grava um `u16` já reservado no deslocamento.
    pub fn patch_u16(&mut self, offset: usize, value: u16) {
        self.bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
}

/// Grava o registro no anel e, com a entrega assíncrona ligada, manda o
/// lote quando ele enche ou envelhece.
pub fn commit(mut record: Record) {
    if !available() {
        return;
    }
    let length = record.length;
    record.bytes[0..2].copy_from_slice(&(length as u16).to_le_bytes());
    let flags = cpu::save_and_disable_interrupts();
    let sequence = NEXT.fetch_add(1, Ordering::AcqRel);
    record.bytes[8..16].copy_from_slice(&sequence.to_le_bytes());
    let slot = (sequence % SLOTS as u64) as usize;
    let cell = commit_cell(slot);
    cell.store(0, Ordering::Release);
    // SAFETY: a posição é deste gravador até o selo (ver o comentário do
    // módulo); `length <= SLOT_SIZE`.
    unsafe { core::ptr::copy_nonoverlapping(record.bytes.as_ptr(), slot_pointer(slot), length) };
    cell.store(sequence + 1, Ordering::Release);
    cpu::restore_interrupts(flags);
    if ASYNC.load(Ordering::Relaxed) {
        let pending = sequence + 1 - SENT.load(Ordering::Relaxed).min(sequence + 1);
        let now_ms = clock::uptime_ms();
        if pending >= BATCH || now_ms.saturating_sub(LAST_FLUSH_MS.load(Ordering::Relaxed)) >= FLUSH_MS {
            flush();
        }
    }
}

/// O que a cópia de um registro deu.
enum Copy {
    /// Copiado, com o tamanho.
    Done(usize),
    /// Reservado e ainda não selado: o gravador está no meio.
    Pending,
    /// Sobrescrito por um registro mais novo (ou ilegível).
    Lost,
}

/// Copia o registro `sequence` para `output`.
fn copy_record(sequence: u64, output: &mut [u8]) -> Copy {
    let slot = (sequence % SLOTS as u64) as usize;
    let cell = commit_cell(slot);
    let seal = cell.load(Ordering::Acquire);
    if seal != sequence + 1 {
        return if seal < sequence + 1 { Copy::Pending } else { Copy::Lost };
    }
    let pointer = slot_pointer(slot);
    // SAFETY: a posição tem `SLOT_SIZE` bytes; o selo conferido de novo
    // depois da cópia descarta uma sobrescrita no meio.
    let length = unsafe { u16::from_le_bytes([pointer.read_volatile(), pointer.add(1).read_volatile()]) } as usize;
    if !(HEADER_SIZE..=SLOT_SIZE).contains(&length) {
        return Copy::Lost;
    }
    if length > output.len() {
        return Copy::Done(0);
    }
    for (index, byte) in output[..length].iter_mut().enumerate() {
        // SAFETY: dentro da posição.
        *byte = unsafe { pointer.add(index).read_volatile() };
    }
    if cell.load(Ordering::Acquire) != sequence + 1 {
        return Copy::Lost;
    }
    Copy::Done(length)
}

/// O mais antigo ainda no anel.
fn oldest() -> u64 {
    NEXT.load(Ordering::Acquire).saturating_sub(SLOTS as u64)
}

/// Manda os registros pendentes ao host em pacotes `O` (só com a máquina
/// rodando, o host anexado e a trava do transporte livre).
fn flush() {
    if !session::attached() || stop::stopped() || !stop::active() {
        return;
    }
    if FLUSHING.compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        return;
    }
    let processor = stop::current_processor();
    let flags = cpu::save_and_disable_interrupts();
    if !transport::try_lock(processor) {
        cpu::restore_interrupts(flags);
        FLUSHING.store(false, Ordering::Release);
        return;
    }
    LAST_FLUSH_MS.store(clock::uptime_ms(), Ordering::Relaxed);
    let mut chunk = [0u8; PACKET_BYTES + 16];
    let mut encoded = [0u8; 2 * (PACKET_BYTES + 16) + 8];
    for _ in 0..PACKETS_PER_FLUSH {
        let mut sequence = SENT.load(Ordering::Acquire).max(oldest());
        let end = NEXT.load(Ordering::Acquire);
        if sequence >= end {
            break;
        }
        chunk[..MARKER.len()].copy_from_slice(MARKER);
        chunk[MARKER.len()] = VERSION;
        let mut length = MARKER.len() + 1;
        while sequence < end {
            match copy_record(sequence, &mut chunk[length..PACKET_BYTES]) {
                // O pacote encheu, ou o gravador está no meio: o resto espera.
                Copy::Done(0) | Copy::Pending => break,
                Copy::Done(copied) => length += copied,
                Copy::Lost => {
                    DROPPED.fetch_add(1, Ordering::Relaxed);
                }
            }
            sequence += 1;
        }
        SENT.store(sequence, Ordering::Release);
        if length == MARKER.len() + 1 {
            break;
        }
        let mut payload = Payload::new(&mut encoded);
        payload.push(b'O');
        payload.push_hex(&chunk[..length]);
        packet::send_unreliable(payload.as_bytes());
    }
    transport::unlock();
    cpu::restore_interrupts(flags);
    FLUSHING.store(false, Ordering::Release);
    if packet::take_interrupt() {
        stop::break_in_now();
    }
}

/// O `qOpenNTStream:SEQ` (máquina parada): cabeçalho (próximo, mais
/// antigo, perdidos, flags) e os registros a partir de SEQ que couberem.
pub fn read(from: u64, output: &mut [u8]) -> usize {
    if output.len() < 32 || !available() {
        return 0;
    }
    let next = NEXT.load(Ordering::Acquire);
    let oldest = oldest();
    let mut sequence = from.max(oldest);
    output[0..8].copy_from_slice(&next.to_le_bytes());
    output[8..16].copy_from_slice(&oldest.to_le_bytes());
    output[16..24].copy_from_slice(&DROPPED.load(Ordering::Relaxed).to_le_bytes());
    let flags = (super::api_monitor::enabled() as u32) | (super::irp_trace::enabled() as u32) << 1 | (ASYNC.load(Ordering::Relaxed) as u32) << 2;
    output[24..28].copy_from_slice(&flags.to_le_bytes());
    let mut length = 32;
    while sequence < next {
        match copy_record(sequence, &mut output[length..]) {
            Copy::Done(0) | Copy::Pending => break,
            Copy::Done(copied) => length += copied,
            Copy::Lost => {}
        }
        sequence += 1;
    }
    // O que o host já leu parado não volta pela entrega assíncrona.
    if SENT.load(Ordering::Acquire) < sequence {
        SENT.store(sequence, Ordering::Release);
    }
    length
}

/// O `stream` do monitor.
pub fn command(line: &str, out: &mut Payload) {
    match line.split_whitespace().next().unwrap_or("status") {
        "on" => {
            ASYNC.store(true, Ordering::Release);
            out.push_str("fluxo: entrega com a maquina rodando ligada\n");
        }
        "off" => {
            ASYNC.store(false, Ordering::Release);
            out.push_str("fluxo: entrega com a maquina rodando desligada\n");
        }
        "clear" => {
            SENT.store(NEXT.load(Ordering::Acquire), Ordering::Release);
            out.push_str("fluxo: pendentes descartados\n");
        }
        _ => status(out),
    }
}

pub fn status(out: &mut Payload) {
    if !available() {
        out.push_str("fluxo: sem o anel (boot sem --kd)\n");
        return;
    }
    let _ = writeln!(
        out,
        "fluxo: proximo {} enviado {} perdidos {} anel {}x{} entrega {}",
        NEXT.load(Ordering::Acquire),
        SENT.load(Ordering::Acquire),
        DROPPED.load(Ordering::Relaxed),
        SLOTS,
        SLOT_SIZE,
        if ASYNC.load(Ordering::Relaxed) { "ligada" } else { "desligada" }
    );
}
