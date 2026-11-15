//! Sessão com o host: o laço de comandos do protocolo remoto do GDB com a
//! máquina parada (o papel do KdpSendWaitContinue).
//!
//! Cada processador é uma thread do protocolo (thread N = processador
//! N - 1): `g`/`G`/`p`/`P` leem e gravam o quadro do processador escolhido
//! por `Hg`, e `m`/`M`/`X` usam o espaço de endereços (CR3) dele. O passo
//! (`s`, `vCont;s`) roda no dono da parada. `Z0`/`z0` são breakpoints de
//! software; `Z1` (execução), `Z2` (escrita) e `Z4` (acesso) são os
//! comparadores DR0-DR3 (o `Z3`, só leitura, não existe no x86 e volta sem
//! suporte). As consultas próprias do OpenNT vêm pelo `qRcmd` (`monitor`
//! no GDB, `kd::monitor`), e a lista de módulos também pelo
//! `qXfer:libraries:read`.
//!
//! Anexar: o primeiro pacote válido do host liga KdDebuggerNotPresent =
//! FALSE e o bit de presença do KUSER_SHARED_DATA.KdDebuggerEnabled, como o
//! transporte do NT quando o host responde; o `D` (ou `k`) desfaz, tira os
//! breakpoints e devolve o modo com confirmação.

use core::cell::UnsafeCell;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::breakpoints::{self, Watch};
use super::packet::{self, Payload, Received, PACKET_SIZE};
use super::registers::{self, View};
use super::stop::{self, Kind, Resume};
use super::{debugger, memory, monitor};
use crate::ntos::mm::memory_map::MAX_CPUS;

/// Um host trocou pacotes e não se desligou.
static ATTACHED: AtomicBool = AtomicBool::new(false);
/// O host espera uma resposta de parada (mandou `c`/`s` ou 0x03).
static HOST_WAITING: AtomicBool = AtomicBool::new(false);
/// O host entende as razões `swbreak`/`hwbreak` (qSupported).
static REPORT_SOFTWARE_BREAK: AtomicBool = AtomicBool::new(false);
static REPORT_HARDWARE_BREAK: AtomicBool = AtomicBool::new(false);
/// Thread escolhida por `Hg` (processador + 1; 0 = o dono).
static SELECTED: AtomicU32 = AtomicU32::new(0);

/// Tamanho do texto de saída do `monitor` e do XML das bibliotecas.
pub const TEXT_SIZE: usize = 0x6000;

struct Buffers {
    input: UnsafeCell<[u8; PACKET_SIZE + 16]>,
    output: UnsafeCell<[u8; PACKET_SIZE + 64]>,
    data: UnsafeCell<[u8; PACKET_SIZE]>,
    text: UnsafeCell<[u8; TEXT_SIZE]>,
}

// SAFETY: só o dono da parada usa os buffers, e há um dono por vez.
unsafe impl Sync for Buffers {}

static BUFFERS: Buffers = Buffers {
    input: UnsafeCell::new([0; PACKET_SIZE + 16]),
    output: UnsafeCell::new([0; PACKET_SIZE + 64]),
    data: UnsafeCell::new([0; PACKET_SIZE]),
    text: UnsafeCell::new([0; TEXT_SIZE]),
};

pub fn attached() -> bool {
    ATTACHED.load(Ordering::Acquire)
}

/// O host mandou 0x03 e espera a resposta de parada.
pub fn set_host_waiting() {
    HOST_WAITING.store(true, Ordering::Release);
}

fn attach() {
    if !ATTACHED.swap(true, Ordering::AcqRel) {
        debugger::set_debugger_present(true);
        debug_print!("[kd] depurador anexado");
    }
}

fn detach() {
    ATTACHED.store(false, Ordering::Release);
    HOST_WAITING.store(false, Ordering::Release);
    breakpoints::remove_all();
    packet::set_no_ack(false);
    REPORT_SOFTWARE_BREAK.store(false, Ordering::Release);
    REPORT_HARDWARE_BREAK.store(false, Ordering::Release);
    SELECTED.store(0, Ordering::Release);
    debugger::set_debugger_present(false);
    debug_print!("KD_SESSION_DETACHED: o depurador se desligou e a maquina segue");
}

/// Anuncia ao host anexado um erro fatal antes da parada (o "Fatal System
/// Error" que o KD imprime no bugcheck).
pub fn announce_fatal(code: u32, parameters: [u64; 4]) {
    let mut buffer = [0u8; 160];
    let mut text = Payload::new(&mut buffer);
    let _ = write!(text, "*** Fatal System Error: 0x{:08x} (0x{:x},0x{:x},0x{:x},0x{:x})", code, parameters[0], parameters[1], parameters[2], parameters[3]);
    if let Ok(line) = core::str::from_utf8(text.as_bytes()) {
        super::print_log::output(line);
    }
}

/// Processador das leituras de registradores e memória.
fn selected(owner: usize) -> usize {
    match SELECTED.load(Ordering::Acquire) {
        0 => owner,
        value => value as usize - 1,
    }
}

/// Thread do protocolo (hexadecimal; -1 = todas, 0 = qualquer) para
/// processador.
fn parse_thread(text: &[u8], owner: usize) -> Option<usize> {
    if text == b"-1" || text == b"0" {
        return Some(owner);
    }
    let thread = packet::parse_number(text)? as usize;
    (thread >= 1 && thread <= MAX_CPUS).then(|| thread - 1)
}

/// Resposta de parada: `T` com o sinal, a thread e a razão.
fn stop_reply(reply: &mut Payload) {
    let (signal, kind, data, number) = stop::stop_reason();
    reply.push(b'T');
    reply.push_hex_byte(signal);
    let _ = write!(reply, "thread:{:x};", number + 1);
    match kind {
        Kind::SoftwareBreak if REPORT_SOFTWARE_BREAK.load(Ordering::Acquire) => reply.push_str("swbreak:;"),
        Kind::HardwareBreak if REPORT_HARDWARE_BREAK.load(Ordering::Acquire) => reply.push_str("hwbreak:;"),
        Kind::Watch(Watch::Write) => {
            let _ = write!(reply, "watch:{:x};", data);
        }
        Kind::Watch(_) => {
            let _ = write!(reply, "awatch:{:x};", data);
        }
        _ => {}
    }
}

/// O que fazer depois de um comando.
enum Action {
    Reply,
    ReplyThenNoAck,
    Resume(Resume),
    Detach,
    Kill,
}

/// O laço da parada: devolve como a máquina sai.
pub fn run(number: usize) -> Resume {
    // SAFETY: o dono da parada é o único usuário dos buffers.
    let (input, output, data, text) = unsafe { (&mut *BUFFERS.input.get(), &mut *BUFFERS.output.get(), &mut *BUFFERS.data.get(), &mut *BUFFERS.text.get()) };
    if !attached() {
        let (signal, _, _, _) = stop::stop_reason();
        debug_print!("[kd] maquina parada (sinal {}) no processador {}, esperando o depurador", signal, number);
    }
    if HOST_WAITING.swap(false, Ordering::AcqRel) {
        let mut reply = Payload::new(&mut output[..]);
        stop_reply(&mut reply);
        packet::send(reply.as_bytes());
    }
    loop {
        let length = match packet::receive(&mut input[..]) {
            Received::Interrupt => {
                let mut reply = Payload::new(&mut output[..]);
                stop_reply(&mut reply);
                packet::send(reply.as_bytes());
                continue;
            }
            Received::Packet(length) => length,
        };
        attach();
        let mut reply = Payload::new(&mut output[..]);
        let action = handle(number, &mut input[..length], &mut reply, &mut data[..], &mut text[..]);
        match action {
            Action::Reply => {
                packet::send(reply.as_bytes());
            }
            Action::ReplyThenNoAck => {
                packet::send(reply.as_bytes());
                packet::set_no_ack(true);
            }
            Action::Resume(resume) => {
                HOST_WAITING.store(true, Ordering::Release);
                return resume;
            }
            Action::Detach => {
                packet::send(b"OK");
                detach();
                return Resume::Continue { pass: false };
            }
            Action::Kill => {
                detach();
                return Resume::Continue { pass: false };
            }
        }
    }
}

/// Divide `a,b` (ou `a,b:resto`) nos números e no resto.
fn split_address_length(text: &[u8]) -> Option<(u64, usize, &[u8])> {
    let comma = text.iter().position(|&byte| byte == b',')?;
    let address = packet::parse_number(&text[..comma])?;
    let rest = &text[comma + 1..];
    let (length, tail) = match rest.iter().position(|&byte| byte == b':') {
        Some(colon) => (&rest[..colon], &rest[colon + 1..]),
        None => (rest, &rest[rest.len()..]),
    };
    Some((address, packet::parse_number(length)? as usize, tail))
}

fn handle(owner: usize, command: &mut [u8], reply: &mut Payload, data: &mut [u8], text: &mut [u8]) -> Action {
    let Some(&first) = command.first() else { return Action::Reply };
    match first {
        b'?' => stop_reply(reply),
        b'g' => read_registers(selected(owner), reply),
        b'G' => write_registers(selected(owner), &command[1..], reply),
        b'p' => read_register(selected(owner), &command[1..], reply),
        b'P' => write_register(selected(owner), &command[1..], reply),
        b'm' => read_memory(selected(owner), &command[1..], reply, data),
        b'M' => write_memory_hex(selected(owner), &command[1..], reply, data),
        b'X' => write_memory_binary(selected(owner), &mut command[1..], reply),
        b'Z' | b'z' => breakpoint(owner, first == b'Z', &command[1..], reply),
        b'c' | b'C' | b's' | b'S' => return resume(owner, first, &command[1..], reply),
        b'H' => {
            if command.len() >= 2 {
                match parse_thread(&command[2..], owner) {
                    Some(number) if stop::processor_stopped(number) => {
                        if command[1] == b'g' {
                            SELECTED.store(number as u32 + 1, Ordering::Release);
                        }
                        reply.push_str("OK");
                    }
                    _ => reply.push_str("E01"),
                }
            }
        }
        b'T' => match parse_thread(&command[1..], owner) {
            Some(number) if stop::processor_stopped(number) => reply.push_str("OK"),
            _ => reply.push_str("E01"),
        },
        b'D' => return Action::Detach,
        b'k' => return Action::Kill,
        b'q' => query(owner, command, reply, text),
        b'Q' => {
            if command == b"QStartNoAckMode" {
                reply.push_str("OK");
                return Action::ReplyThenNoAck;
            }
        }
        b'v' => return v_packet(owner, command, reply),
        _ => {}
    }
    Action::Reply
}

fn read_registers(number: usize, reply: &mut Payload) {
    let Some(view) = stop::view(number) else {
        reply.push_str("E01");
        return;
    };
    let mut value = [0u8; 16];
    for register in 0..registers::PACKET_REGISTERS {
        let width = registers::size(register);
        if view.read(register, &mut value) {
            reply.push_hex(&value[..width]);
        } else {
            for _ in 0..width * 2 {
                reply.push(b'x');
            }
        }
    }
}

fn write_registers(number: usize, hex: &[u8], reply: &mut Payload) {
    let Some(view) = stop::view(number) else {
        reply.push_str("E01");
        return;
    };
    let mut offset = 0;
    let mut value = [0u8; 16];
    for register in 0..registers::PACKET_REGISTERS {
        let width = registers::size(register);
        let Some(digits) = hex.get(offset..offset + width * 2) else { break };
        offset += width * 2;
        if digits.iter().all(|&digit| digit == b'x') {
            continue;
        }
        if packet::decode_hex(digits, &mut value).is_some() {
            view.write(register, &value[..width]);
        }
    }
    reply.push_str("OK");
}

fn read_register(number: usize, text: &[u8], reply: &mut Payload) {
    let (Some(view), Some(register)) = (stop::view(number), packet::parse_number(text)) else {
        reply.push_str("E01");
        return;
    };
    let register = register as usize;
    if register > registers::LAST_REGISTER {
        reply.push_str("E00");
        return;
    }
    let width = registers::size(register);
    let mut value = [0u8; 16];
    if view.read(register, &mut value) {
        reply.push_hex(&value[..width]);
    } else {
        for _ in 0..width * 2 {
            reply.push(b'x');
        }
    }
}

fn write_register(number: usize, text: &[u8], reply: &mut Payload) {
    let Some(view) = stop::view(number) else {
        reply.push_str("E01");
        return;
    };
    let Some(equals) = text.iter().position(|&byte| byte == b'=') else {
        reply.push_str("E01");
        return;
    };
    let mut value = [0u8; 16];
    let register = packet::parse_number(&text[..equals]).map(|value| value as usize);
    match (register, packet::decode_hex(&text[equals + 1..], &mut value)) {
        (Some(register), Some(length)) if register <= registers::LAST_REGISTER && length >= registers::size(register) => {
            view.write(register, &value[..length]);
            reply.push_str("OK");
        }
        _ => reply.push_str("E01"),
    }
}

fn read_memory(number: usize, text: &[u8], reply: &mut Payload, data: &mut [u8]) {
    let Some((address, length, _)) = split_address_length(text) else {
        reply.push_str("E01");
        return;
    };
    let length = length.min((PACKET_SIZE - 8) / 2).min(data.len());
    let done = memory::read(stop::address_space(number), address, &mut data[..length]);
    if done == 0 && length != 0 {
        reply.push_str("E14");
        return;
    }
    breakpoints::mask_read(address, &mut data[..done]);
    reply.push_hex(&data[..done]);
}

fn store(number: usize, address: u64, bytes: &mut [u8], reply: &mut Payload) {
    breakpoints::shadow_write(address, bytes);
    if memory::write(stop::address_space(number), address, bytes) == bytes.len() {
        reply.push_str("OK");
    } else {
        reply.push_str("E14");
    }
}

fn write_memory_hex(number: usize, text: &[u8], reply: &mut Payload, data: &mut [u8]) {
    let Some((address, length, hex)) = split_address_length(text) else {
        reply.push_str("E01");
        return;
    };
    match packet::decode_hex(hex, data) {
        Some(decoded) if decoded == length => store(number, address, &mut data[..decoded], reply),
        _ => reply.push_str("E01"),
    }
}

fn write_memory_binary(number: usize, text: &mut [u8], reply: &mut Payload) {
    let Some(colon) = text.iter().position(|&byte| byte == b':') else {
        reply.push_str("E01");
        return;
    };
    let Some((address, length, _)) = split_address_length(&text[..colon]) else {
        reply.push_str("E01");
        return;
    };
    let payload = &mut text[colon + 1..];
    let decoded = packet::unescape_binary(payload);
    if decoded != length {
        reply.push_str("E01");
        return;
    }
    if length == 0 {
        reply.push_str("OK");
        return;
    }
    store(number, address, &mut payload[..decoded], reply);
}

/// `Z`/`z` tipo,endereço,tamanho.
fn breakpoint(owner: usize, insert: bool, text: &[u8], reply: &mut Payload) {
    let fields: [Option<&[u8]>; 3] = {
        let mut parts = text.split(|&byte| byte == b',' || byte == b';');
        [parts.next(), parts.next(), parts.next()]
    };
    let (Some(kind), Some(address), Some(length)) = (fields[0], fields[1].and_then(packet::parse_number), fields[2].and_then(packet::parse_number)) else {
        reply.push_str("E01");
        return;
    };
    let done = match kind {
        b"0" if insert => breakpoints::insert(stop::address_space(owner), address),
        b"0" => breakpoints::remove(address),
        b"1" | b"2" | b"4" => {
            let watch = match kind {
                b"1" => Watch::Execute,
                b"2" => Watch::Write,
                _ => Watch::Access,
            };
            if insert {
                breakpoints::insert_hardware(watch, address, length)
            } else {
                breakpoints::remove_hardware(watch, address)
            }
        }
        // Só leitura: o x86 não vigia; sem suporte.
        _ => return,
    };
    reply.push_str(if done { "OK" } else { "E01" });
}

/// `c [endereço]`, `C sig[;endereço]`, `s [endereço]`, `S sig[;endereço]`.
fn resume(owner: usize, command: u8, text: &[u8], reply: &mut Payload) -> Action {
    let (signal, address) = match command {
        b'C' | b'S' => {
            let mut parts = text.splitn(2, |&byte| byte == b';');
            let signal = parts.next().and_then(packet::parse_number).unwrap_or(0);
            (signal, parts.next().and_then(packet::parse_number))
        }
        _ => (0, packet::parse_number(text)),
    };
    let Some(view) = stop::view(owner) else {
        reply.push_str("E01");
        return Action::Reply;
    };
    if let Some(address) = address {
        view.set_rip(address);
    }
    if command == b's' || command == b'S' {
        return Action::Resume(Resume::Step);
    }
    Action::Resume(Resume::Continue { pass: signal != 0 })
}

/// `vCont?`, `vCont;ação[:thread]...`, `vMustReplyEmpty`, `vKill`.
fn v_packet(owner: usize, command: &[u8], reply: &mut Payload) -> Action {
    if command == b"vCont?" {
        reply.push_str("vCont;c;C;s;S");
        return Action::Reply;
    }
    if command.starts_with(b"vKill") {
        reply.push_str("OK");
        return Action::Kill;
    }
    let Some(actions) = command.strip_prefix(b"vCont;") else { return Action::Reply };
    // A primeira ação que vale para o dono (ou para todas) decide.
    for action in actions.split(|&byte| byte == b';') {
        let (verb, thread) = match action.iter().position(|&byte| byte == b':') {
            Some(colon) => (&action[..colon], Some(&action[colon + 1..])),
            None => (action, None),
        };
        let applies = match thread {
            None => true,
            Some(thread) => parse_thread(thread, owner) == Some(owner),
        };
        if !applies {
            if matches!(verb.first(), Some(b's') | Some(b'S')) {
                // Passo em outro processador: só o dono executa passos.
                reply.push_str("E01");
                return Action::Reply;
            }
            continue;
        }
        match verb.first() {
            Some(b's') | Some(b'S') => return Action::Resume(Resume::Step),
            Some(b'c') => return Action::Resume(Resume::Continue { pass: false }),
            Some(b'C') => {
                let signal = packet::parse_number(&verb[1..]).unwrap_or(0);
                return Action::Resume(Resume::Continue { pass: signal != 0 });
            }
            _ => {}
        }
    }
    reply.push_str("E01");
    Action::Reply
}

/// Janela `offset,length` de um anexo do `qXfer`.
fn xfer_window(document: &[u8], annex: &[u8], reply: &mut Payload) {
    let Some(comma) = annex.iter().position(|&byte| byte == b',') else {
        reply.push_str("E01");
        return;
    };
    let (Some(offset), Some(length)) = (packet::parse_number(&annex[..comma]), packet::parse_number(&annex[comma + 1..])) else {
        reply.push_str("E01");
        return;
    };
    let offset = (offset as usize).min(document.len());
    let length = (length as usize).min(PACKET_SIZE - 16);
    let end = (offset + length).min(document.len());
    reply.push(if end == document.len() { b'l' } else { b'm' });
    for &byte in &document[offset..end] {
        // Binário do protocolo: `#`, `$`, `}` e `*` vão escapados.
        if matches!(byte, b'#' | b'$' | b'}' | b'*') {
            reply.push(b'}');
            reply.push(byte ^ 0x20);
        } else {
            reply.push(byte);
        }
    }
}

fn query(owner: usize, command: &[u8], reply: &mut Payload, text: &mut [u8]) {
    if command.starts_with(b"qSupported") {
        let features = &command[10..];
        let has = |name: &[u8]| features.split(|&byte| byte == b';' || byte == b':').any(|feature| feature == name);
        REPORT_SOFTWARE_BREAK.store(has(b"swbreak+"), Ordering::Release);
        REPORT_HARDWARE_BREAK.store(has(b"hwbreak+"), Ordering::Release);
        let _ = write!(reply, "PacketSize={:x};swbreak+;hwbreak+;QStartNoAckMode+;vContSupported+;qXfer:libraries:read+", PACKET_SIZE);
    } else if command == b"qAttached" {
        reply.push_str("1");
    } else if command == b"qC" {
        let _ = write!(reply, "QC{:x}", owner + 1);
    } else if command == b"qfThreadInfo" {
        reply.push(b'm');
        let mut first = true;
        for number in 0..MAX_CPUS {
            if stop::processor_stopped(number) {
                if !first {
                    reply.push(b',');
                }
                first = false;
                reply.push_number(number as u64 + 1);
            }
        }
    } else if command == b"qsThreadInfo" {
        reply.push(b'l');
    } else if let Some(thread) = command.strip_prefix(b"qThreadExtraInfo,") {
        let Some(number) = parse_thread(thread, owner) else {
            reply.push_str("E01");
            return;
        };
        let mut buffer = [0u8; 160];
        let mut description = Payload::new(&mut buffer);
        monitor::describe_processor(number, &mut description);
        reply.push_hex_text(description.as_bytes());
    } else if command == b"qOffsets" {
        reply.push_str("Text=0;Data=0;Bss=0");
    } else if command.starts_with(b"qSymbol") {
        reply.push_str("OK");
    } else if let Some(annex) = command.strip_prefix(b"qXfer:libraries:read::") {
        let length = {
            let mut document = Payload::new(text);
            monitor::libraries_xml(&mut document);
            document.len()
        };
        xfer_window(&text[..length], annex, reply);
    } else if let Some(hex) = command.strip_prefix(b"qRcmd,") {
        let mut line = [0u8; 256];
        let Some(decoded) = packet::decode_hex(hex, &mut line) else {
            reply.push_str("E01");
            return;
        };
        let length = {
            let mut output = Payload::new(text);
            monitor::run(owner, core::str::from_utf8(&line[..decoded]).unwrap_or(""), &mut output);
            output.len()
        };
        send_console(&text[..length]);
        reply.push_str("OK");
    }
}

/// Texto para o console do host em pacotes `O`, antes da resposta final.
fn send_console(text: &[u8]) {
    let mut buffer = [0u8; 2 * 480 + 4];
    for chunk in text.chunks(480) {
        let mut payload = Payload::new(&mut buffer);
        payload.push(b'O');
        payload.push_hex(chunk);
        packet::send(payload.as_bytes());
    }
}

/// Visão do processador `number` para os módulos irmãos.
pub fn processor_view(number: usize) -> Option<View> {
    stop::view(number)
}
