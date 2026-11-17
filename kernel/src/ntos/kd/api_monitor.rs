//! Monitor de APIs: cada chamada de um driver aos exports do ntoskrnl e da
//! HAL que passa pelo despacho dos trampolins (`init::exports::dispatch`)
//! vira um registro do fluxo (`stream`): o id do export, os argumentos, o
//! resultado, a thread e o processo, a hora, a duração e o endereço de
//! retorno no chamador.
//!
//! O gancho no despacho só lê um booleano quando tudo está desligado
//! (`enter`). Ligado, o filtro é o endereço de retorno: as faixas dos
//! módulos pedidos (`mod=INICIO-FIM`, até `MAX_RANGES`) ou todos os
//! chamadores (`all`). Os exports com corpo x64 próprio não passam pelo
//! despacho e não aparecem.
//!
//! O host diz quantos argumentos cada export tem e quais apontam para texto
//! (`api spec ID:ARGC[:ARG:TIPO]...`, a partir dos protótipos do cliente):
//! o texto é copiado na volta da chamada, com o leitor de memória do
//! depurador (sem faltas nem travas), no espaço de endereços corrente. Sem
//! especificação, vão os quatro argumentos dos registradores.
//!
//! O registro (depois do cabeçalho do fluxo): id u32 | argumentos u8 |
//! textos u8 | reservado u16 | PID u32 | TID u32 | ETHREAD u64 | retorno
//! u64 | duração u64 | resultado u64 | argumentos u64... | para cada texto:
//! argumento u8, tipo u8, tamanho u16 e os bytes (UTF-8). Flags: bit 0 = o
//! provedor falhou (sem resultado nativo), bit 1 = transferência de
//! contexto (o retorno não é o da chamada).

use core::fmt::Write;
use core::mem::offset_of;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::packet::Payload;
use super::stream::{self, Record};
use super::{irp_trace, memory, stop};
use crate::hal::cpu;
use crate::ntos::inc::types::{Ethread, ObjectAttributes, UnicodeString};
use crate::ntos::init::exports::Call;
use crate::ntos::mm::memory_map::MAX_CPUS;
use crate::rtl::KernelError;

const MAX_RANGES: usize = 8;
const MAX_SPECS: usize = 512;
const DEFAULT_ARGUMENTS: u8 = 4;
const MAX_ARGUMENTS: u8 = 14;
/// Bytes de texto por argumento copiado.
const TEXT_LIMIT: usize = 96;

pub const TEXT_UNICODE_STRING: u8 = 1;
pub const TEXT_ANSI_STRING: u8 = 2;
pub const TEXT_WIDE: u8 = 3;
pub const TEXT_ANSI: u8 = 4;
pub const TEXT_OBJECT_ATTRIBUTES: u8 = 5;
/// Um ponteiro de saída: o qword apontado, na volta (o objeto criado).
pub const TEXT_OUTPUT_POINTER: u8 = 6;

pub const FLAG_ERROR: u32 = 1;
pub const FLAG_TRANSFER: u32 = 2;

/// Algum gancho ligado (o monitor ou o rastreador de IRPs).
static ACTIVE: AtomicBool = AtomicBool::new(false);
static ENABLED: AtomicBool = AtomicBool::new(false);
static ALL: AtomicBool = AtomicBool::new(false);
static RANGES: [(AtomicU64, AtomicU64); MAX_RANGES] = [const { (AtomicU64::new(0), AtomicU64::new(0)) }; MAX_RANGES];
static RANGE_COUNT: AtomicU32 = AtomicU32::new(0);
/// Especificações: id << 32 | argumentos << 24 | (arg1 << 4 | tipo1) << 12 | (arg2 << 4 | tipo2).
static SPECS: [AtomicU64; MAX_SPECS] = [const { AtomicU64::new(0) }; MAX_SPECS];
static SPEC_COUNT: AtomicU32 = AtomicU32::new(0);
static RECORDED: AtomicU64 = AtomicU64::new(0);
/// O chamador da chamada de export em curso em cada processador (ETHREAD,
/// retorno): o rastreador de IRPs o usa no IofCallDriver.
static CALLER: [(AtomicU64, AtomicU64); MAX_CPUS] = [const { (AtomicU64::new(0), AtomicU64::new(0)) }; MAX_CPUS];

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

/// Religa o gancho comum depois de mudar o monitor ou o rastreador.
pub fn update_active() {
    ACTIVE.store(enabled() || irp_trace::enabled(), Ordering::Release);
}

/// O que `enter` guardou para `leave`.
pub struct Token {
    start: u64,
    record: bool,
    processor: usize,
    saved: (u64, u64),
}

/// Antes do provedor de um export. Desligado, só lê `ACTIVE`.
#[inline]
pub fn enter(id: u64, call: &Call) -> Option<Token> {
    if !ACTIVE.load(Ordering::Relaxed) {
        return None;
    }
    enter_slow(id, call)
}

fn caller_wanted(address: u64) -> bool {
    if address == 0 {
        return false;
    }
    if ALL.load(Ordering::Relaxed) {
        return true;
    }
    let count = (RANGE_COUNT.load(Ordering::Acquire) as usize).min(MAX_RANGES);
    RANGES[..count].iter().any(|(start, end)| address >= start.load(Ordering::Relaxed) && address < end.load(Ordering::Relaxed))
}

fn enter_slow(_id: u64, call: &Call) -> Option<Token> {
    let processor = stop::current_processor();
    let thread = crate::ntos::ke::pcr::current_thread();
    let slot = &CALLER[processor];
    let saved = (slot.0.load(Ordering::Relaxed), slot.1.load(Ordering::Relaxed));
    slot.0.store(thread, Ordering::Relaxed);
    slot.1.store(call.return_address, Ordering::Relaxed);
    let record = enabled() && caller_wanted(call.return_address);
    Some(Token { start: stream::now(), record, processor, saved })
}

/// O chamador do export em curso neste processador, se for da thread
/// corrente (o IofCallDriver de um driver).
pub fn current_caller() -> u64 {
    let processor = stop::current_processor();
    let thread = crate::ntos::ke::pcr::current_thread();
    let slot = &CALLER[processor];
    if slot.0.load(Ordering::Relaxed) == thread {
        slot.1.load(Ordering::Relaxed)
    } else {
        0
    }
}

/// Depois do provedor.
pub fn leave(token: Token, id: u64, call: &Call, result: &Result<u64, KernelError>) {
    let slot = &CALLER[token.processor.min(MAX_CPUS - 1)];
    slot.0.store(token.saved.0, Ordering::Relaxed);
    slot.1.store(token.saved.1, Ordering::Relaxed);
    if irp_trace::enabled() {
        irp_trace::after_export(id, call, result);
    }
    if token.record {
        record_call(token.start, id, call, result);
    }
}

fn spec_of(id: u64) -> Option<u64> {
    let count = (SPEC_COUNT.load(Ordering::Acquire) as usize).min(MAX_SPECS);
    SPECS[..count].iter().map(|spec| spec.load(Ordering::Relaxed)).find(|spec| spec >> 32 == id)
}

fn record_call(start: u64, id: u64, call: &Call, result: &Result<u64, KernelError>) {
    let end = stream::now();
    let (value, flags) = match result {
        Ok(value) => (*value, 0),
        Err(error) if crate::ntos::rtl::native_context::is_transfer(error) => (0, FLAG_ERROR | FLAG_TRANSFER),
        Err(_) => (0, FLAG_ERROR),
    };
    let spec = spec_of(id);
    let argument_count = spec.map_or(DEFAULT_ARGUMENTS, |spec| ((spec >> 24) & 0xFF) as u8).min(MAX_ARGUMENTS);
    let texts: [(u8, u8); 2] = match spec {
        Some(spec) => [(((spec >> 16) & 0xF) as u8, ((spec >> 12) & 0xF) as u8), (((spec >> 4) & 0xF) as u8, (spec & 0xF) as u8)],
        None => [(0, 0), (0, 0)],
    };
    let thread = crate::ntos::ke::pcr::current_thread();
    let (pid, tid) = thread_ids(thread);
    let mut record = Record::new(stream::KIND_API, flags, start);
    record.push_u32(id as u32);
    record.push_u8(argument_count);
    let texts_at = record.len();
    record.push_u8(0);
    record.push_u16(0);
    record.push_u32(pid as u32);
    record.push_u32(tid as u32);
    record.push_u64(thread);
    record.push_u64(call.return_address);
    record.push_u64(end.saturating_sub(start));
    record.push_u64(value);
    for index in 0..argument_count as usize {
        record.push_u64(call.args[index]);
    }
    let cr3 = cpu::read_cr3();
    let mut count = 0u8;
    for (argument, kind) in texts {
        if kind == 0 || argument == 0 || argument as usize > call.args.len() {
            continue;
        }
        let mut text = [0u8; TEXT_LIMIT];
        let length = read_text(cr3, kind, call.args[argument as usize - 1], &mut text);
        if record.room() < 4 + length {
            break;
        }
        record.push_u8(argument);
        record.push_u8(kind);
        record.push_u16(length as u16);
        record.push_bytes(&text[..length]);
        count += 1;
    }
    record.patch_u16(texts_at, count as u16);
    RECORDED.fetch_add(1, Ordering::Relaxed);
    stream::commit(record);
}

/// PID e TID da thread (o CLIENT_ID da ETHREAD, pelo leitor do depurador).
pub fn thread_ids(thread: u64) -> (u64, u64) {
    if thread == 0 {
        return (0, 0);
    }
    let cr3 = cpu::read_cr3();
    let cid = thread + offset_of!(Ethread, cid) as u64;
    (memory::read_u64(cr3, cid).unwrap_or(0), memory::read_u64(cr3, cid + 8).unwrap_or(0))
}

/// UTF-16 em UTF-8 (só o plano básico; o resto vira '?').
fn push_utf8(unit: u16, output: &mut [u8], length: &mut usize) -> bool {
    let mut buffer = [0u8; 4];
    let encoded = char::from_u32(unit as u32).unwrap_or('?').encode_utf8(&mut buffer).len();
    if *length + encoded > output.len() {
        return false;
    }
    output[*length..*length + encoded].copy_from_slice(&buffer[..encoded]);
    *length += encoded;
    true
}

fn read_wide(cr3: u64, address: u64, units: usize, output: &mut [u8]) -> usize {
    let mut length = 0;
    for index in 0..units.min(TEXT_LIMIT) {
        match memory::read_u16(cr3, address + index as u64 * 2) {
            Some(0) | None => break,
            Some(unit) => {
                if !push_utf8(unit, output, &mut length) {
                    break;
                }
            }
        }
    }
    length
}

fn read_narrow(cr3: u64, address: u64, bytes: usize, output: &mut [u8]) -> usize {
    let mut length = 0;
    for index in 0..bytes.min(TEXT_LIMIT) {
        match memory::read_u8(cr3, address + index as u64) {
            Some(0) | None => break,
            Some(byte) => {
                if !push_utf8(byte as u16, output, &mut length) {
                    break;
                }
            }
        }
    }
    length
}

fn read_counted(cr3: u64, pointer: u64, wide: bool, output: &mut [u8]) -> usize {
    if pointer == 0 {
        return 0;
    }
    let length = memory::read_u16(cr3, pointer + offset_of!(UnicodeString, length) as u64).unwrap_or(0) as usize;
    let buffer = memory::read_u64(cr3, pointer + offset_of!(UnicodeString, buffer) as u64).unwrap_or(0);
    if buffer == 0 {
        return 0;
    }
    if wide {
        read_wide(cr3, buffer, length / 2, output)
    } else {
        read_narrow(cr3, buffer, length, output)
    }
}

/// O texto apontado por um argumento, pelo tipo.
fn read_text(cr3: u64, kind: u8, value: u64, output: &mut [u8]) -> usize {
    if value == 0 {
        return 0;
    }
    match kind {
        TEXT_UNICODE_STRING => read_counted(cr3, value, true, output),
        TEXT_ANSI_STRING => read_counted(cr3, value, false, output),
        TEXT_WIDE => read_wide(cr3, value, TEXT_LIMIT, output),
        TEXT_ANSI => read_narrow(cr3, value, TEXT_LIMIT, output),
        TEXT_OBJECT_ATTRIBUTES => {
            let name = memory::read_u64(cr3, value + offset_of!(ObjectAttributes, object_name) as u64).unwrap_or(0);
            read_counted(cr3, name, true, output)
        }
        TEXT_OUTPUT_POINTER => match memory::read_u64(cr3, value) {
            Some(pointer) if output.len() >= 8 => {
                output[..8].copy_from_slice(&pointer.to_le_bytes());
                8
            }
            _ => 0,
        },
        _ => 0,
    }
}

fn parse_hex(text: &str) -> Option<u64> {
    u64::from_str_radix(text.trim_start_matches("0x"), 16).ok()
}

fn parse_range(text: &str) -> Option<(u64, u64)> {
    let (low, high) = text.split_once('-')?;
    Some((parse_hex(low)?, parse_hex(high)?))
}

/// Uma especificação `ID:ARGC[:ARG:TIPO[:ARG:TIPO]]` (números decimais).
fn parse_spec(text: &str) -> Option<u64> {
    let mut parts = text.split(':').map(|part| part.parse::<u64>().ok());
    let id = parts.next()??;
    let count = parts.next()??.min(MAX_ARGUMENTS as u64);
    let mut packed = id << 32 | count << 24;
    for shift in [12u32, 0] {
        match (parts.next(), parts.next()) {
            (Some(Some(argument)), Some(Some(kind))) if argument <= 14 && kind <= 15 => packed |= (argument << 4 | kind) << shift,
            (None, None) => break,
            _ => return None,
        }
    }
    Some(packed)
}

/// Linhas de nomes por página do `api names`.
const NAMES_PER_PAGE: usize = 110;

/// O `api` do monitor.
pub fn command(line: &str, out: &mut Payload) {
    let mut words = line.split_whitespace();
    match words.next().unwrap_or("status") {
        "on" => {
            if !stream::available() {
                out.push_str("api: sem o anel do fluxo\n");
                return;
            }
            let mut all = false;
            let mut count = 0usize;
            for word in words {
                if word == "all" {
                    all = true;
                } else if let Some(range) = word.strip_prefix("mod=").and_then(parse_range) {
                    if count == MAX_RANGES {
                        let _ = writeln!(out, "api: no maximo {} faixas", MAX_RANGES);
                        return;
                    }
                    RANGES[count].0.store(range.0, Ordering::Relaxed);
                    RANGES[count].1.store(range.1, Ordering::Relaxed);
                    count += 1;
                } else {
                    let _ = writeln!(out, "api: opcao invalida {}", word);
                    return;
                }
            }
            if !all && count == 0 {
                out.push_str("api: diga all ou mod=INICIO-FIM\n");
                return;
            }
            RANGE_COUNT.store(count as u32, Ordering::Release);
            ALL.store(all, Ordering::Release);
            ENABLED.store(true, Ordering::Release);
            update_active();
            let _ = writeln!(out, "api: monitor ligado ({})", if all { "todos os chamadores" } else { "faixas pedidas" });
        }
        "off" => {
            ENABLED.store(false, Ordering::Release);
            update_active();
            out.push_str("api: monitor desligado\n");
        }
        "spec" => {
            let mut added = 0;
            for word in words {
                let Some(spec) = parse_spec(word) else {
                    let _ = writeln!(out, "api: especificacao invalida {}", word);
                    return;
                };
                let count = SPEC_COUNT.load(Ordering::Acquire) as usize;
                let existing = SPECS[..count.min(MAX_SPECS)].iter().position(|cell| cell.load(Ordering::Relaxed) >> 32 == spec >> 32);
                match existing {
                    Some(index) => SPECS[index].store(spec, Ordering::Relaxed),
                    None if count < MAX_SPECS => {
                        SPECS[count].store(spec, Ordering::Relaxed);
                        SPEC_COUNT.store(count as u32 + 1, Ordering::Release);
                    }
                    None => {
                        out.push_str("api: tabela de especificacoes cheia\n");
                        return;
                    }
                }
                added += 1;
            }
            let _ = writeln!(out, "api: {} especificacoes ({} no total)", added, SPEC_COUNT.load(Ordering::Acquire));
        }
        "clear" => {
            SPEC_COUNT.store(0, Ordering::Release);
            RANGE_COUNT.store(0, Ordering::Release);
            out.push_str("api: faixas e especificacoes limpas\n");
        }
        "names" => {
            let start = words.next().and_then(|word| word.parse::<usize>().ok()).unwrap_or(0);
            let names = crate::ntos::init::exports::export_names();
            for (index, name) in names.iter().enumerate().skip(start) {
                if index - start == NAMES_PER_PAGE {
                    let _ = writeln!(out, "mais: {}", index);
                    return;
                }
                let _ = writeln!(out, "{} {}", index + 32, name);
            }
        }
        _ => {
            let _ = writeln!(
                out,
                "api: {} ({}), {} faixas, {} especificacoes, {} registros",
                if enabled() { "ligado" } else { "desligado" },
                if ALL.load(Ordering::Relaxed) { "todos" } else { "faixas" },
                RANGE_COUNT.load(Ordering::Acquire),
                SPEC_COUNT.load(Ordering::Acquire),
                RECORDED.load(Ordering::Relaxed)
            );
            let count = (RANGE_COUNT.load(Ordering::Acquire) as usize).min(MAX_RANGES);
            for (start, end) in &RANGES[..count] {
                let _ = writeln!(out, "  faixa {:#x}-{:#x}", start.load(Ordering::Relaxed), end.load(Ordering::Relaxed));
            }
            stream::status(out);
        }
    }
}
