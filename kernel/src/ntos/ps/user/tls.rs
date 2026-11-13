//! ProcessTlsInformation da ABI x64 das DLLs do volume — `system32/ntos/ps/user/tls.js`.
//!
//! Layout confirmado na ntdll e no ntoskrnl: cabeçalho de 16 bytes e
//! entradas de 24 bytes; TlsData é entrada/saída.

use super::{state, syscalls_core, threads};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

fn set_information(process: u64, buffer: u64, length: u64) -> Result<u32, KernelError> {
    if process != u64::MAX {
        return Ok(0xC000_000D);
    }
    if length < 40 || (length - 16) % 24 != 0 {
        return Ok(0xC000_0004);
    }
    if !state::probe_user_write(buffer, length) {
        return Ok(0xC000_0005);
    }
    let flags = guest::read32(buffer);
    let operation = guest::read32(buffer + 4);
    let count = guest::read32(buffer + 8) as u64;
    let index_or_previous_count = guest::read32(buffer + 12) as u64;
    if operation > 1 || flags & !1 != 0 || count != (length - 16) / 24 {
        return Ok(0xC000_0004);
    }
    // Não existe TEB WOW64 neste processo x64.
    if flags & 1 != 0 {
        return Ok(0xC000_000D);
    }
    for index in 0..count {
        if guest::read32(buffer + 16 + index * 24) != 0 {
            return Ok(0xC000_000D);
        }
    }
    let mut entry_index = 0u64;
    for thread in threads::all() {
        let (dead, teb) = thread.with(|thread| (thread.dead, thread.teb_va));
        if dead || teb == 0 {
            continue;
        }
        if entry_index == count {
            break;
        }
        let vector_field = teb + 0x58;
        let vector = guest::read64(vector_field);
        // A thread ainda não inicializou o TLS.
        if vector == 0 {
            continue;
        }
        let entry = buffer + 16 + entry_index * 24;
        let replacement = guest::read64(entry + 8);
        let previous;
        if operation == 1 {
            previous = if vector == vector_field { 0 } else { vector };
            let bytes = index_or_previous_count * 8;
            if previous != 0 && bytes != 0 {
                if !state::probe_user_write(previous, bytes) || !state::probe_user_write(replacement, bytes) {
                    return Ok(0xC000_0005);
                }
                // Copia antes de publicar: preserva os slots das DLLs já carregadas.
                let values: alloc::vec::Vec<u64> = (0..bytes).step_by(8).map(|offset| guest::read64(previous + offset)).collect();
                for (index, value) in values.iter().enumerate() {
                    guest::write64(replacement + index as u64 * 8, *value);
                }
            }
            if replacement == 0 || !state::probe_user_write(replacement, 8) {
                return Ok(0xC000_0005);
            }
            guest::write64(vector_field, replacement);
            guest::write64(entry + 16, thread.thread_id);
        } else {
            let slot = vector + index_or_previous_count * 8;
            if !state::probe_user_write(slot, 8) {
                return Ok(0xC000_0005);
            }
            previous = guest::read64(slot);
            guest::write64(slot, replacement);
        }
        guest::write64(entry + 8, previous);
        // Troca concluída: o chamador pode liberar o bloco antigo.
        guest::write32(entry, 2);
        entry_index += 1;
    }
    Ok(0)
}

pub fn init() {
    syscalls_core::set_tls_setter(set_information);
}
