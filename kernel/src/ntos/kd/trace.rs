//! Rastro de instruções dentro do convidado: o dono da parada executa passo
//! a passo (TF) sem voltar ao host a cada instrução e grava registros
//! compactos num buffer; o host lê o buffer em lotes (`qOpenNTTrace`).
//!
//! O host arma o rastro pelo `qRcmd` (`trace start count=N [until=END]
//! [ret] [depth=D] [skip=INI-FIM]... [enter=INI-FIM] [leave=INI-FIM]
//! [watch=END:TAM]`) e continua (`c`): cada #DB do passo vem para
//! `after_step`, que grava o registro e decide se dá mais um passo ou se a
//! máquina para (no fim pedido, num breakpoint, antes de uma instrução que
//! não pode ser rastreada ou com o buffer cheio, quando o host lê o lote e
//! pede `trace resume`). Os outros processadores ficam congelados o tempo
//! todo e as interrupções ficam mascaradas durante cada passo, como no `s`.
//!
//! O formato (cabeçalho de 32 bytes e os registros) é o de
//! `tools/kd-client/src/trace.rs`:
//!
//! ```text
//! cabeçalho: "OTRC" | versão u8 | CPU u8 | motivo u8 | flags u8 |
//!            registros u32 | bytes u32 | passos u64 | reservado u64
//! registro:  flags u8 | máscara u32 | RIP u64 | profundidade i16 |
//!            [thread u64] [vigia u64] [pulados u32] | valores u64 por bit da máscara
//! ```
//!
//! O buffer é reservado no boot com `--kd` (`reserve`, fora da imagem do
//! kernel); depois disso nada aqui aloca nem toma trava: só o processador
//! da parada mexe no estado.

use alloc::boxed::Box;
use alloc::vec;
use core::cell::UnsafeCell;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use super::packet::Payload;
use super::registers::View;
use super::{breakpoints, memory, stop};
use crate::hal::cpu;
use crate::ntos::ke::pcr;

const BUFFER_SIZE: usize = 0x40000;
const HEADER_SIZE: usize = 32;
const REGISTERS: usize = 17;
const FULL_MASK: u32 = (1 << REGISTERS) - 1;
/// O maior registro: flags, máscara, RIP, profundidade, thread, vigia,
/// pulados e os 17 registradores.
const MAX_RECORD: usize = 1 + 4 + 8 + 2 + 8 + 8 + 4 + REGISTERS * 8;
const MAX_RANGES: usize = 4;

const FLAG_THREAD: u8 = 4;
const FLAG_WATCH: u8 = 8;
const FLAG_SKIPPED: u8 = 16;

pub const CLASS_OTHER: u8 = 0;
pub const CLASS_CALL: u8 = 1;
pub const CLASS_RETURN: u8 = 2;
/// iretq, sysret, syscall, hlt, int: o passo sairia do anel 0 ou travaria.
pub const CLASS_UNSAFE: u8 = 3;

pub const REASON_RUNNING: u8 = 0;
pub const REASON_COUNT: u8 = 1;
pub const REASON_ADDRESS: u8 = 2;
pub const REASON_RETURN: u8 = 3;
pub const REASON_ENTERED: u8 = 4;
pub const REASON_LEFT: u8 = 5;
pub const REASON_BUFFER_FULL: u8 = 6;
pub const REASON_UNSAFE: u8 = 7;
pub const REASON_BREAKPOINT: u8 = 8;
pub const REASON_INTERRUPTED: u8 = 9;

const REASON_TEXT: [&str; 10] = ["em andamento", "numero de instrucoes", "endereco", "retorno da funcao", "entrou no modulo", "saiu do modulo", "buffer cheio", "instrucao que nao pode ser rastreada", "breakpoint", "interrompido"];

/// Armado: o próximo `c` começa (ou continua) o rastro.
static ARMED: AtomicBool = AtomicBool::new(false);
/// Passos em andamento.
static ACTIVE: AtomicBool = AtomicBool::new(false);

struct State {
    count: u64,
    until: u64,
    stop_on_return: bool,
    max_depth: i32,
    skip: [(u64, u64); MAX_RANGES],
    skip_count: usize,
    enter: (u64, u64),
    leave: (u64, u64),
    watch: u64,
    watch_size: usize,
    steps: u64,
    depth: i32,
    /// A classe da instrução no RIP (a próxima a executar).
    pending_class: u8,
    skipped: u32,
    last: [u64; REGISTERS],
    /// O próximo registro leva todos os registradores (começo de lote).
    full: bool,
    thread: u64,
    watch_value: u64,
    watch_known: bool,
    cpu: u8,
    reason: u8,
    records: u32,
    length: usize,
    /// O lote parou com o buffer cheio: `trace resume` continua.
    paused: bool,
    /// O próximo começo é continuação (o estado corrente já foi gravado).
    continuing: bool,
}

struct Cell<T>(UnsafeCell<T>);

// SAFETY: só o dono da parada (um processador por vez, com os outros
// congelados) usa o estado.
unsafe impl<T> Sync for Cell<T> {}

/// Os registros: `BUFFER_SIZE` bytes reservados no boot (nulo sem `--kd`).
static BUFFER: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());

/// Reserva o buffer do rastro (o `kd::initialize` com o depurador ligado).
pub fn reserve() {
    if BUFFER.load(Ordering::Acquire).is_null() {
        let buffer: &'static mut [u8] = Box::leak(vec![0u8; BUFFER_SIZE].into_boxed_slice());
        BUFFER.store(buffer.as_mut_ptr(), Ordering::Release);
    }
}

static STATE: Cell<State> = Cell(UnsafeCell::new(State {
    count: 0,
    until: 0,
    stop_on_return: false,
    max_depth: i32::MAX,
    skip: [(0, 0); MAX_RANGES],
    skip_count: 0,
    enter: (0, 0),
    leave: (0, 0),
    watch: 0,
    watch_size: 0,
    steps: 0,
    depth: 0,
    pending_class: 0,
    skipped: 0,
    last: [0; REGISTERS],
    full: true,
    thread: 0,
    watch_value: 0,
    watch_known: false,
    cpu: 0,
    reason: 0,
    records: 0,
    length: 0,
    paused: false,
    continuing: false,
}));

fn state() -> &'static mut State {
    // SAFETY: ver `Cell`.
    unsafe { &mut *STATE.0.get() }
}

fn buffer() -> Option<&'static mut [u8]> {
    let pointer = BUFFER.load(Ordering::Acquire);
    // SAFETY: `BUFFER_SIZE` bytes vivos para sempre (`reserve`), usados só
    // pelo processador da parada (ver `Cell`).
    (!pointer.is_null()).then(|| unsafe { core::slice::from_raw_parts_mut(pointer, BUFFER_SIZE) })
}

pub fn armed() -> bool {
    ARMED.load(Ordering::Acquire)
}

pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

/// Como seguir depois de um passo.
pub enum Next {
    Continue,
    /// Para (o tipo da parada para a resposta ao host).
    Stop(stop::Kind),
}

/// A classe da instrução em `rip`.
pub fn classify(cr3: u64, rip: u64) -> u8 {
    let mut bytes = [0u8; 16];
    let length = memory::read(cr3, rip, &mut bytes);
    let code = &bytes[..length];
    let mut index = 0;
    while index < code.len() && index < 14 && matches!(code[index], 0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65) {
        index += 1;
    }
    if code.get(index).is_some_and(|byte| byte & 0xF0 == 0x40) {
        index += 1;
    }
    match (code.get(index).copied(), code.get(index + 1).copied()) {
        (Some(0xE8), _) => CLASS_CALL,
        (Some(0xFF), Some(modrm)) if matches!((modrm >> 3) & 7, 2 | 3) => CLASS_CALL,
        (Some(0xC3 | 0xC2 | 0xCB | 0xCA), _) => CLASS_RETURN,
        (Some(0xCF | 0xF4 | 0xCC | 0xCD | 0xCE | 0xF1), _) => CLASS_UNSAFE,
        (Some(0x0F), Some(0x05 | 0x07 | 0x34 | 0x35)) => CLASS_UNSAFE,
        (None, _) => CLASS_UNSAFE,
        _ => CLASS_OTHER,
    }
}

fn current_thread() -> u64 {
    if pcr::get_pcr_address() == 0 {
        return 0;
    }
    pcr::current().prcb.current_thread.get()
}

/// Os registradores do passo na ordem do formato (RAX..R15, RFLAGS).
fn read_registers(view: &View) -> [u64; REGISTERS] {
    let mut values = [0u64; REGISTERS];
    let mut bytes = [0u8; 16];
    for (index, value) in values.iter_mut().enumerate().take(16) {
        if view.read(index, &mut bytes) {
            *value = u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]));
        }
    }
    values[16] = view.rflags();
    values
}

fn push(state: &mut State, bytes: &[u8]) {
    let end = state.length + bytes.len();
    if let Some(buffer) = buffer().filter(|_| end <= BUFFER_SIZE) {
        buffer[state.length..end].copy_from_slice(bytes);
        state.length = end;
    }
}

/// Grava o estado corrente.
fn record(state: &mut State, view: &View, cr3: u64) {
    let values = read_registers(view);
    let mask = if state.full { FULL_MASK } else { (0..REGISTERS).filter(|&index| values[index] != state.last[index]).fold(0u32, |mask, index| mask | 1 << index) };
    let mut flags = state.pending_class & 3;
    let thread = current_thread();
    let thread_changed = state.full || thread != state.thread;
    if thread_changed {
        flags |= FLAG_THREAD;
    }
    let mut watch = 0u64;
    let mut watch_changed = false;
    if state.watch_size != 0 {
        let mut bytes = [0u8; 8];
        if memory::read(cr3, state.watch, &mut bytes[..state.watch_size]) == state.watch_size {
            watch = u64::from_le_bytes(bytes);
            watch_changed = state.full || !state.watch_known || watch != state.watch_value;
        }
        if watch_changed {
            flags |= FLAG_WATCH;
        }
    }
    if state.skipped != 0 {
        flags |= FLAG_SKIPPED;
    }
    push(state, &[flags]);
    push(state, &mask.to_le_bytes());
    push(state, &view.rip().to_le_bytes());
    push(state, &(state.depth.clamp(i16::MIN as i32, i16::MAX as i32) as i16).to_le_bytes());
    if thread_changed {
        push(state, &thread.to_le_bytes());
        state.thread = thread;
    }
    if watch_changed {
        push(state, &watch.to_le_bytes());
        state.watch_value = watch;
        state.watch_known = true;
    }
    if state.skipped != 0 {
        let skipped = state.skipped;
        push(state, &skipped.to_le_bytes());
        state.skipped = 0;
    }
    for (index, value) in values.iter().enumerate() {
        if mask & (1 << index) != 0 {
            push(state, &value.to_le_bytes());
        }
    }
    state.last = values;
    state.full = false;
    state.records += 1;
}

fn finish(state: &mut State, reason: u8) {
    state.reason = reason;
    state.paused = reason == REASON_BUFFER_FULL;
    ACTIVE.store(false, Ordering::Release);
}

/// Começa (ou continua) o rastro no dono da parada, com um breakpoint no
/// RIP já suspenso. `false`: a instrução no RIP não pode ser rastreada (o
/// lote termina sem passo).
pub fn begin(number: usize, view: &View) -> bool {
    let state = state();
    ARMED.store(false, Ordering::Release);
    ACTIVE.store(true, Ordering::Release);
    state.cpu = number as u8;
    state.reason = REASON_RUNNING;
    let cr3 = cpu::read_cr3();
    state.pending_class = classify(cr3, view.rip());
    if !state.continuing {
        record(state, view, cr3);
    }
    state.continuing = false;
    if state.pending_class == CLASS_UNSAFE {
        finish(state, REASON_UNSAFE);
        return false;
    }
    true
}

/// Depois de um passo do rastro: grava e decide o próximo.
pub fn after_step(view: &View) -> Next {
    let state = state();
    let cr3 = cpu::read_cr3();
    state.steps += 1;
    match state.pending_class {
        CLASS_CALL => state.depth += 1,
        CLASS_RETURN => state.depth -= 1,
        _ => {}
    }
    let rip = view.rip();
    state.pending_class = classify(cr3, rip);
    let inside = |range: (u64, u64)| rip >= range.0 && rip < range.1;
    let reason = if state.until != 0 && rip == state.until {
        Some(REASON_ADDRESS)
    } else if state.stop_on_return && state.depth < 0 {
        Some(REASON_RETURN)
    } else if state.enter.1 != 0 && inside(state.enter) {
        Some(REASON_ENTERED)
    } else if state.leave.1 != 0 && !inside(state.leave) {
        Some(REASON_LEFT)
    } else if breakpoints::inserted_at(rip) {
        Some(REASON_BREAKPOINT)
    } else if state.pending_class == CLASS_UNSAFE {
        Some(REASON_UNSAFE)
    } else if state.steps >= state.count {
        Some(REASON_COUNT)
    } else {
        None
    };
    if let Some(reason) = reason {
        record(state, view, cr3);
        finish(state, reason);
        let kind = if reason == REASON_BREAKPOINT { stop::Kind::SoftwareBreak } else { stop::Kind::Signal };
        return Next::Stop(kind);
    }
    let skip = state.skip[..state.skip_count].iter().any(|&range| inside(range));
    if state.depth > state.max_depth || skip {
        state.skipped = state.skipped.saturating_add(1);
        return Next::Continue;
    }
    record(state, view, cr3);
    if BUFFER_SIZE - state.length < 2 * MAX_RECORD {
        state.continuing = true;
        finish(state, REASON_BUFFER_FULL);
        return Next::Stop(stop::Kind::Signal);
    }
    Next::Continue
}

/// Outra parada chegou com o rastro em andamento.
pub fn abandon() {
    if active() {
        finish(state(), REASON_INTERRUPTED);
    }
}

/// O cabeçalho mais o buffer, a partir de `offset` (o `qOpenNTTrace`).
pub fn read(offset: usize, output: &mut [u8]) -> usize {
    let state = state();
    let mut header = [0u8; HEADER_SIZE];
    header[..4].copy_from_slice(b"OTRC");
    header[4] = 1;
    header[5] = state.cpu;
    header[6] = state.reason;
    header[7] = (state.paused as u8) | ((state.watch_size != 0) as u8) << 1;
    header[8..12].copy_from_slice(&state.records.to_le_bytes());
    header[12..16].copy_from_slice(&(state.length as u32).to_le_bytes());
    header[16..24].copy_from_slice(&state.steps.to_le_bytes());
    let total = HEADER_SIZE + state.length;
    let Some(buffer) = buffer() else { return 0 };
    let mut written = 0;
    let mut position = offset;
    while written < output.len() && position < total {
        output[written] = if position < HEADER_SIZE { header[position] } else { buffer[position - HEADER_SIZE] };
        written += 1;
        position += 1;
    }
    written
}

fn parse_hex(text: &str) -> Option<u64> {
    u64::from_str_radix(text.trim_start_matches("0x"), 16).ok()
}

fn parse_range(text: &str) -> Option<(u64, u64)> {
    let (low, high) = text.split_once('-')?;
    Some((parse_hex(low)?, parse_hex(high)?))
}

/// O `trace` do monitor.
pub fn command(owner: usize, line: &str, out: &mut Payload) {
    let state = state();
    let mut words = line.split_whitespace();
    match words.next().unwrap_or("status") {
        "start" => {
            if buffer().is_none() {
                out.push_str("trace: sem o buffer do rastro
");
                return;
            }
            let mut count = 1000u64;
            let mut until = 0;
            let mut stop_on_return = false;
            let mut max_depth = i32::MAX;
            let mut skip = [(0u64, 0u64); MAX_RANGES];
            let mut skip_count = 0;
            let mut enter = (0, 0);
            let mut leave = (0, 0);
            let mut watch = (0u64, 0usize);
            for word in words {
                let (key, value) = word.split_once('=').unwrap_or((word, ""));
                let ok = match key {
                    "count" => value.parse().map(|value| count = value).is_ok(),
                    "until" => parse_hex(value).map(|value| until = value).is_some(),
                    "ret" => {
                        stop_on_return = true;
                        true
                    }
                    "depth" => value.parse().map(|value| max_depth = value).is_ok(),
                    "skip" if skip_count < MAX_RANGES => parse_range(value).map(|range| {
                        skip[skip_count] = range;
                        skip_count += 1;
                    }).is_some(),
                    "enter" => parse_range(value).map(|range| enter = range).is_some(),
                    "leave" => parse_range(value).map(|range| leave = range).is_some(),
                    "watch" => value.split_once(':').and_then(|(address, size)| Some((parse_hex(address)?, size.parse::<usize>().ok().filter(|size| matches!(size, 1 | 2 | 4 | 8))?))).map(|pair| watch = pair).is_some(),
                    _ => false,
                };
                if !ok {
                    let _ = writeln!(out, "trace: opcao invalida {}", word);
                    return;
                }
            }
            let Some(view) = stop::view(owner) else {
                out.push_str("trace: o dono da parada nao tem quadro\n");
                return;
            };
            let rip = view.rip();
            let cr3 = stop::address_space(owner);
            // O RIP pode ter um breakpoint gravado: a classe é a da instrução original.
            let class = if breakpoints::inserted_at(rip) { CLASS_OTHER } else { classify(cr3, rip) };
            if class == CLASS_UNSAFE {
                let _ = writeln!(out, "trace: a instrucao em {:#x} nao pode ser rastreada", rip);
                return;
            }
            state.count = count.max(1);
            state.until = until;
            state.stop_on_return = stop_on_return;
            state.max_depth = max_depth;
            state.skip = skip;
            state.skip_count = skip_count;
            state.enter = enter;
            state.leave = leave;
            state.watch = watch.0;
            state.watch_size = watch.1;
            state.steps = 0;
            state.depth = 0;
            state.skipped = 0;
            state.full = true;
            state.thread = 0;
            state.watch_known = false;
            state.records = 0;
            state.length = 0;
            state.reason = REASON_RUNNING;
            state.paused = false;
            state.continuing = false;
            ARMED.store(true, Ordering::Release);
            let _ = writeln!(out, "rastro armado: ate {} instrucoes a partir de {:#x} (continue para executar)", state.count, rip);
        }
        "resume" => {
            if !state.paused {
                out.push_str("trace: nenhum lote para continuar\n");
                return;
            }
            state.paused = false;
            state.full = true;
            state.records = 0;
            state.length = 0;
            state.reason = REASON_RUNNING;
            ARMED.store(true, Ordering::Release);
            out.push_str("rastro armado (continuacao)\n");
        }
        "stop" | "clear" => {
            ARMED.store(false, Ordering::Release);
            state.paused = false;
            state.continuing = false;
            state.records = 0;
            state.length = 0;
            out.push_str("rastro desarmado\n");
        }
        _ => {
            let _ = writeln!(
                out,
                "rastro: {} registros, {} bytes, {} instrucoes, profundidade {}, CPU {}, motivo: {}{}",
                state.records,
                state.length,
                state.steps,
                state.depth,
                state.cpu,
                REASON_TEXT.get(state.reason as usize).copied().unwrap_or("?"),
                if armed() { " (armado)" } else { "" }
            );
        }
    }
}
