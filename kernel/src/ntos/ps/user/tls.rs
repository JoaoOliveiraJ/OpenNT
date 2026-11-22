//! ProcessTlsInformation da ABI x64 das DLLs do volume.
//!
//! Layout confirmado na ntdll e no ntoskrnl: cabeçalho de 16 bytes e
//! entradas de 24 bytes; TlsData é entrada/saída. Com o bit 0 de Flags (que
//! o whNtSetInformationProcessTlsInformation do wow64.dll liga para a ntdll
//! de 32 bits), o vetor é o TEB32.ThreadLocalStoragePointer de cada thread,
//! com ponteiros de 32 bits, como no ramo da classe 35 do
//! NtSetInformationProcess 19041 (0x6590e1): só num processo WoW64 x86.

use super::{state, syscalls_core, threads};
use crate::rtl::KernelError;
use core::mem::offset_of;
use core::sync::atomic::Ordering;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{NtStruct, ProcessTlsInformation, Teb, Teb32, ThreadTlsInformation};

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
    // O vetor de 32 bits só existe num processo WoW64 x86.
    let wow64 = flags & 1 != 0;
    if wow64 && !crate::ntos::ps::wow64::is_x86_process(crate::ntos::ps::process::get_current_process()) {
        return Ok(0xC000_000D);
    }
    // O tamanho de um ponteiro do vetor.
    let slot_size: u64 = if wow64 { 4 } else { 8 };
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
        // TEB.ThreadLocalStoragePointer da thread (memória de usuário), ou o
        // da TEB de 32 bits.
        let vector_field = if wow64 {
            state::user_struct::<Teb32>(teb + crate::ntos::ps::wow64::TEB32_OFFSET)?.thread_local_storage_pointer.address()
        } else {
            state::user_struct::<Teb>(teb)?.thread_local_storage_pointer.address()
        };
        if !state::probe_user_write(vector_field, slot_size) {
            return Ok(0xC000_0005);
        }
        let read_pointer = |address: u64| if wow64 { guest::try_read::<u32>(address).map(u64::from) } else { guest::try_read::<u64>(address) };
        let write_pointer = |address: u64, value: u64| if wow64 { guest::try_write::<u32>(address, value as u32) } else { guest::try_write::<u64>(address, value) };
        let vector = read_pointer(vector_field)?;
        // A thread ainda não inicializou o TLS.
        if vector == 0 {
            continue;
        }
        let entry = thread_data(entry_index)?;
        let replacement = entry.new_tls_data.probe_get()?;
        let previous;
        if operation == 1 {
            previous = if vector == vector_field { 0 } else { vector };
            let bytes = index_or_previous_count * slot_size;
            if previous != 0 && bytes != 0 {
                if !state::probe_user_write(previous, bytes) || !state::probe_user_write(replacement, bytes) {
                    return Ok(0xC000_0005);
                }
                // Copia antes de publicar: preserva os slots das DLLs já carregadas.
                let values = guest::try_read_bytes(previous, bytes as usize)?;
                guest::try_write_bytes(replacement, &values)?;
            }
            if replacement == 0 || !state::probe_user_write(replacement, slot_size) {
                return Ok(0xC000_0005);
            }
            write_pointer(vector_field, replacement)?;
            entry.thread_id.probe_set(thread.thread_id)?;
        } else {
            let slot = vector + index_or_previous_count * slot_size;
            if !state::probe_user_write(slot, slot_size) {
                return Ok(0xC000_0005);
            }
            // Troca do slot numa instrução: o valor antigo vai para OldTlsData.
            previous = if wow64 { read_pointer(slot).and_then(|previous| write_pointer(slot, replacement).map(|_| previous))? } else { guest::try_atomic_u64(slot)?.swap(replacement, Ordering::SeqCst) };
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
