//! ProcessTlsInformation da ABI x64 das DLLs do volume.
//!
//! Layout confirmado na ntdll e no ntoskrnl: cabeçalho de 16 bytes e
//! entradas de 24 bytes; TlsData é entrada/saída.

use super::{state, syscalls_core, threads};
use crate::rtl::KernelError;
use core::mem::offset_of;
use core::sync::atomic::Ordering;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{NtStruct, ProcessTlsInformation, Teb, ThreadTlsInformation};

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
    state::guarded(|| swap_vectors(buffer, length))
}

/// PROCESS_TLS_INFORMATION de usuário (sondado): troca o vetor ou um slot
/// de cada thread viva do processo corrente e devolve os antigos em
/// ThreadData.
fn swap_vectors(buffer: u64, length: u64) -> Result<u32, KernelError> {
    let information = state::user_struct::<ProcessTlsInformation>(buffer)?;
    let flags = information.flags.probe_get()?;
    let operation = information.operation_type.probe_get()?;
    let count = information.thread_data_count.probe_get()? as u64;
    // TlsIndex ou, na troca de vetores, TlsVectorLength.
    let index_or_previous_count = information.tls_index.probe_get()? as u64;
    let header = offset_of!(ProcessTlsInformation, thread_data) as u64;
    if operation > 1 || flags & !1 != 0 || count != (length - header) / ThreadTlsInformation::SIZE {
        return Ok(0xC000_0004);
    }
    // Não existe TEB WOW64 neste processo x64.
    if flags & 1 != 0 {
        return Ok(0xC000_000D);
    }
    let thread_data = |index: u64| state::user_struct::<ThreadTlsInformation>(buffer + header + index * ThreadTlsInformation::SIZE);
    for index in 0..count {
        if thread_data(index)?.flags.probe_get()? != 0 {
            return Ok(0xC000_000D);
        }
    }
    let mut entry_index = 0u64;
    for thread in threads::of_process(crate::ntos::ps::process::get_current_process()) {
        let (dead, teb) = thread.with(|thread| (thread.dead, thread.teb_va));
        if dead || teb == 0 {
            continue;
        }
        if entry_index == count {
            break;
        }
        // TEB.ThreadLocalStoragePointer da thread (memória de usuário).
        let vector_field = state::user_struct::<Teb>(teb)?.thread_local_storage_pointer.address();
        if !state::probe_user_write(vector_field, 8) {
            return Ok(0xC000_0005);
        }
        let vector = guest::try_read::<u64>(vector_field)?;
        // A thread ainda não inicializou o TLS.
        if vector == 0 {
            continue;
        }
        let entry = thread_data(entry_index)?;
        let replacement = entry.new_tls_data.probe_get()?;
        let previous;
        if operation == 1 {
            previous = if vector == vector_field { 0 } else { vector };
            let bytes = index_or_previous_count * 8;
            if previous != 0 && bytes != 0 {
                if !state::probe_user_write(previous, bytes) || !state::probe_user_write(replacement, bytes) {
                    return Ok(0xC000_0005);
                }
                // Copia antes de publicar: preserva os slots das DLLs já carregadas.
                let values = guest::try_read_bytes(previous, bytes as usize)?;
                guest::try_write_bytes(replacement, &values)?;
            }
            if replacement == 0 || !state::probe_user_write(replacement, 8) {
                return Ok(0xC000_0005);
            }
            guest::try_write::<u64>(vector_field, replacement)?;
            entry.thread_id.probe_set(thread.thread_id)?;
        } else {
            let slot = vector + index_or_previous_count * 8;
            if !state::probe_user_write(slot, 8) {
                return Ok(0xC000_0005);
            }
            // Troca do slot numa instrução: o valor antigo vai para OldTlsData.
            previous = guest::try_atomic_u64(slot)?.swap(replacement, Ordering::SeqCst);
        }
        entry.old_tls_data.probe_set(previous)?;
        // Troca concluída: o chamador pode liberar o bloco antigo.
        entry.flags.probe_set(2)?;
        entry_index += 1;
    }
    Ok(0)
}

pub fn init() {
    syscalls_core::set_tls_setter(set_information);
}
