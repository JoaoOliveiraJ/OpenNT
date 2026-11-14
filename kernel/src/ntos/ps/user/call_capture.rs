//! Diagnóstico opcional de chamada de export.
//!
//! Um breakpoint de execução de hardware limitado conserva a função nativa
//! e o seu retorno: nenhum IAT nem código é alterado.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::{index, state};
use crate::hal::amd64::usermode;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::inc::types::{ExceptionRecord, NtStruct};
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
        let value = if wide { guest::try_read::<u16>(at).map(u32::from) } else { guest::try_read::<u8>(at).map(u32::from) };
        let Ok(value) = value else {
            result.push_str("[unmapped]");
            return result;
        };
        if value == 0 {
            return result;
        }
        result.push(char::from_u32(value).unwrap_or('?'));
    }
    result.push_str("[truncated]");
    result
}

/// Estruturas de exceção C++ do MSVC (não são do NT), com RVAs relativos
/// à imagem: ThrowInfo.pCatchableTypeArray, CatchableTypeArray (contagem e
/// o primeiro tipo), CatchableType.pType/sizeOrOffset e TypeDescriptor.name.
const THROW_INFO_CATCHABLE_TYPES: u64 = 12;
const CATCHABLE_TYPE_ARRAY_FIRST: u64 = 4;
const CATCHABLE_TYPE_DESCRIPTOR: u64 = 4;
const CATCHABLE_TYPE_SIZE: u64 = 20;
const TYPE_DESCRIPTOR_NAME: u64 = 16;

fn exception_at(record: u64) {
    if !state::probe_user_read(record, ExceptionRecord::SIZE) {
        return;
    }
    // Diagnóstico: qualquer falha de sonda só encerra o relato.
    let _ = (|| -> Result<(), KernelError> {
        let exception = state::user_struct::<ExceptionRecord>(record)?;
        let code = exception.exception_code.probe_get()? as u32;
        let count = exception.number_parameters.probe_get()?.min(15) as usize;
        let parameters: Vec<u64> = exception.exception_information[..count].iter().map(|parameter| parameter.probe_get()).collect::<Result<_, _>>()?;
        let listed: Vec<String> = parameters.iter().map(|value| alloc::format!("0x{value:x}")).collect();
        crate::debug_print!("[call-capture] exception=0x{:x} address=0x{:x} params={}", code, exception.exception_address.probe_get()?, listed.join(","));
        if code != 0xE06D_7363 || count != 4 {
            return Ok(());
        }
        let (object, info, image) = (parameters[1], parameters[2], parameters[3]);
        if !state::probe_user_read(info, 16) {
            return Ok(());
        }
        let types = image + guest::try_read::<u32>(info + THROW_INFO_CATCHABLE_TYPES)? as u64;
        if !state::probe_user_read(types, 8) || guest::try_read::<u32>(types)? == 0 {
            return Ok(());
        }
        let kind = image + guest::try_read::<u32>(types + CATCHABLE_TYPE_ARRAY_FIRST)? as u64;
        if !state::probe_user_read(kind, 28) {
            return Ok(());
        }
        let descriptor = image + guest::try_read::<u32>(kind + CATCHABLE_TYPE_DESCRIPTOR)? as u64;
        let size = guest::try_read::<u32>(kind + CATCHABLE_TYPE_SIZE)? as u64;
        crate::debug_print!("[call-capture] C++ type={} size={}", string_at(descriptor + TYPE_DESCRIPTOR_NAME, false), size);
        let length = size.min(128);
        if !state::probe_user_read(object, length) {
            return Ok(());
        }
        let contents = guest::try_read_bytes(object, length as usize)?;
        let bytes: String = contents.iter().map(|byte| alloc::format!("{byte:02x}")).collect();
        crate::debug_print!("[call-capture] C++ object={}", bytes);
        // Só ponteiros de caracteres candidatos; nenhuma chamada pela vtable.
        for (index, word) in contents.chunks_exact(8).enumerate() {
            let offset = index * 8;
            let pointer = u64::from_le_bytes(word.try_into().unwrap_or([0; 8]));
            if pointer != 0 && state::probe_user_read(pointer, 1) {
                let candidate = string_at(pointer, false);
                if candidate.len() >= 4 && candidate.chars().all(|character| matches!(character, '\x20'..='\x7E' | '\r' | '\n' | '\t')) {
                    crate::debug_print!("[call-capture] C++ text@+{}: {}", offset, candidate);
                }
            }
        }
        Ok(())
    })();
}

/// Registro capturado pela HAL (estado 2 → 3): argumentos e pilha.
pub fn consume() {
    let block = usermode::block();
    if !CAPTURE.lock().armed || block.capture_state.get() != 2 {
        return;
    }
    block.capture_state.set(3);
    let values: Vec<u64> = block.capture_arguments.iter().map(|argument| argument.get()).collect();
    let raw: Vec<String> = values.iter().map(|value| alloc::format!("0x{value:016x}")).collect();
    let export = state::with(|state| state.capture_export.clone());
    let stack = block.capture_stack.get();
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
        // Quinto argumento da chamada capturada (dwFlags), na pilha de usuário.
        let flags = match guest::try_read::<u32>(stack + 0x28) {
            Ok(value) if state::probe_user_read(stack + 0x28, 4) => alloc::format!("0x{value:x}"),
            _ => String::from("[unmapped]"),
        };
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
