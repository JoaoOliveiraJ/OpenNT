//! Diagnóstico opcional de chamada de export — `system32/ntos/ps/user/call-capture.js`.
//!
//! Um breakpoint de execução de hardware limitado conserva a função nativa
//! e o seu retorno: nenhum IAT nem código é alterado.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::{index, state};
use crate::hal::amd64::usermode;
use crate::rtl::SpinLock;
use crate::ntos::mm::guest_memory as guest;

struct Capture {
    armed: bool,
    address: u64,
    remaining: u32,
}

static CAPTURE: SpinLock<Capture> = SpinLock::new(Capture { armed: false, address: 0, remaining: 1 });

pub fn reset() {
    usermode::clear_user_call_capture();
    let limit = state::with(|state| state.capture_limit).clamp(1, 32);
    *CAPTURE.lock() = Capture { armed: false, address: 0, remaining: limit };
}

/// Arma o breakpoint no export pedido quando a DLL dele é mapeada.
pub fn arm(dll: &str, exports: &BTreeMap<String, u64>) {
    let export = state::with(|state| state.capture_export.clone());
    if CAPTURE.lock().armed || export.is_empty() {
        return;
    }
    let mut parts = export.splitn(2, '!');
    let (module, name) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if !module.eq_ignore_ascii_case(dll) {
        return;
    }
    let Some(&address) = exports.get(name).filter(|&&address| address != 0) else {
        crate::debug_print!("[call-capture] export ausente: {}", export);
        return;
    };
    if usermode::arm_user_call_capture(address).is_err() {
        return;
    }
    let mut capture = CAPTURE.lock();
    capture.armed = true;
    capture.address = address;
    drop(capture);
    crate::debug_print!("[call-capture] armado: {} @0x{:x}", export, address);
}

fn string_at(address: u64, wide: bool) -> String {
    if address == 0 {
        return String::from("(null)");
    }
    let mut result = String::new();
    let width = if wide { 2 } else { 1 };
    for index in 0..2048u64 {
        let at = address + index * width;
        if !state::probe_user_read(at, width) {
            result.push_str("[unmapped]");
            return result;
        }
        let value = if wide { guest::read16(at) as u32 } else { guest::read8(at) as u32 };
        if value == 0 {
            return result;
        }
        result.push(char::from_u32(value).unwrap_or('?'));
    }
    result.push_str("[truncated]");
    result
}

fn exception_at(record: u64) {
    if !state::probe_user_read(record, 0x98) {
        return;
    }
    let code = guest::read32(record);
    let count = guest::read32(record + 0x18).min(15) as u64;
    let parameters: Vec<u64> = (0..count).map(|index| guest::read64(record + 0x20 + index * 8)).collect();
    let listed: Vec<String> = parameters.iter().map(|value| alloc::format!("0x{value:x}")).collect();
    crate::debug_print!("[call-capture] exception=0x{:x} address=0x{:x} params={}", code, guest::read64(record + 0x10), listed.join(","));
    if code != 0xE06D_7363 || count != 4 {
        return;
    }
    let (object, info, image) = (parameters[1], parameters[2], parameters[3]);
    if !state::probe_user_read(info, 16) {
        return;
    }
    let types = image + guest::read32(info + 12) as u64;
    if !state::probe_user_read(types, 8) || guest::read32(types) == 0 {
        return;
    }
    let kind = image + guest::read32(types + 4) as u64;
    if !state::probe_user_read(kind, 28) {
        return;
    }
    let descriptor = image + guest::read32(kind + 4) as u64;
    let size = guest::read32(kind + 20) as u64;
    crate::debug_print!("[call-capture] C++ type={} size={}", string_at(descriptor + 16, false), size);
    let length = size.min(128);
    if !state::probe_user_read(object, length) {
        return;
    }
    let bytes: String = (0..length).map(|index| alloc::format!("{:02x}", guest::read8(object + index))).collect();
    crate::debug_print!("[call-capture] C++ object={}", bytes);
    // Só ponteiros de caracteres candidatos; nenhuma chamada pela vtable.
    let mut offset = 0;
    while offset + 8 <= length {
        let pointer = guest::read64(object + offset);
        if pointer != 0 && state::probe_user_read(pointer, 1) {
            let candidate = string_at(pointer, false);
            if candidate.len() >= 4 && candidate.chars().all(|character| matches!(character, '\x20'..='\x7E' | '\r' | '\n' | '\t')) {
                crate::debug_print!("[call-capture] C++ text@+{}: {}", offset, candidate);
            }
        }
        offset += 8;
    }
}

/// Registro capturado pela HAL (estado 2 → 3): argumentos e pilha.
pub fn consume() {
    if !CAPTURE.lock().armed || guest::read32(usermode::CAPTURE_STATE) != 2 {
        return;
    }
    guest::write32(usermode::CAPTURE_STATE, 3);
    let values: Vec<u64> = [0x160u64, 0x168, 0x170, 0x178].iter().map(|offset| guest::read64(0x8_F000 + offset)).collect();
    let raw: Vec<String> = values.iter().map(|value| alloc::format!("0x{value:016x}")).collect();
    let export = state::with(|state| state.capture_export.clone());
    let stack = guest::read64(0x8_F180);
    crate::debug_print!("[call-capture] {} args={} rsp=0x{:x}", export, raw.join(","), stack);
    let name = export.split('!').nth(1).unwrap_or("");
    if name == "RtlRaiseException" {
        exception_at(values[0]);
    }
    if name == "MessageBoxW" || name == "MessageBoxA" {
        crate::debug_print!("[call-capture] caption: {}", string_at(values[2], name.ends_with('W')));
        crate::debug_print!("[call-capture] text: {}", string_at(values[1], name.ends_with('W')));
    }
    if name == "CryptAcquireContextW" || name == "CryptAcquireContextA" {
        let flags = if state::probe_user_read(stack + 0x28, 4) { alloc::format!("0x{:x}", guest::read32(stack + 0x28)) } else { String::from("[unmapped]") };
        crate::debug_print!("[call-capture] container={} provider={} type={} flags={}", string_at(values[1], name.ends_with('W')), string_at(values[2], name.ends_with('W')), values[3] as u32, flags);
    }
    // O CONTEXT capturado leva RF: rearmar não dispara de novo na instrução
    // retomada; cada invocação seguinte pode ser capturada.
    let mut capture = CAPTURE.lock();
    capture.remaining = capture.remaining.saturating_sub(1);
    if capture.remaining > 0 {
        let address = capture.address;
        drop(capture);
        let _ = usermode::arm_user_call_capture(address);
    }
}

pub fn finish() {
    consume();
    usermode::clear_user_call_capture();
}

pub fn init() {
    index::set_capture_consumer(consume);
}
