//! Zw/NtQueryInformationThread.
//!
//! Contrato ThreadPagePriority medido nos bytes originais e em chamadas do
//! Windows; a ThreadIoPriority e a ThreadBreakOnTermination (a thread
//! crítica) seguem o mesmo caminho; ThreadCycleTime e ThreadNameInformation
//! têm ramos próprios. `access_mode` separa Nt (chamador usuário) de Zw
//! (parâmetros de kernel). A variante de syscall de usuário (`query_user`)
//! entra com o estado de modo usuário (fase 7).

use super::user_probe;
use crate::ntos::ke::irql;
use crate::ntos::mm::{page_residency, paging};
use crate::ntos::ob::handles::thread as thread_handles;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::Ethread;

const THREAD_PAGE_PRIORITY: u32 = 24;
/// ThreadIoPriority: os bits 9..11 do CrossThreadFlags (o ramo da classe 22
/// do NtQueryInformationThread 19041, rva 0x5fbf01), com o mesmo contrato da
/// ThreadPagePriority: um ULONG, THREAD_QUERY_LIMITED_INFORMATION, o valor e
/// depois o ReturnLength 4.
const THREAD_IO_PRIORITY: u32 = 22;
/// ThreadCycleTime e ThreadNameInformation.
const THREAD_CYCLE_TIME: u32 = 23;
const THREAD_NAME_INFORMATION: u32 = 38;
/// ThreadBreakOnTermination.
pub const THREAD_BREAK_ON_TERMINATION: u32 = 18;
const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x800;
const THREAD_QUERY_INFORMATION: u32 = 0x40;
const PAGE_PRIORITY_SIZE: u64 = 4;
/// MmUserProbeAddress.
pub(crate) const USER_PROBE_LIMIT: u64 = crate::ntos::mm::memory_map::USER_PROBE_ADDRESS;
pub(crate) const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
/// Classes do ramo INVALID_INFO_CLASS da imagem de referência 19041.
const REJECTED_QUERY_CLASSES: [u32; 12] = [2, 3, 4, 5, 7, 8, 10, 13, 15, 19, 27, 28];

/// Endereço de kernel válido para `length` bytes (a metade baixa não pode
/// atravessar o limite canônico).
pub(crate) fn kernel_range_valid(address: u64, length: u64) -> bool {
    let Some(end) = address.checked_add(length) else { return address != 0 && address.wrapping_add(length) == 0 };
    address != 0 && !(address < 0xFFFF_8000_0000_0000 && end > 0x8000_0000_0000)
}

/// Verifica a escrita de um ULONG, inclusive o segundo mapeamento quando
/// cruza a página; só materializa páginas de um dono real.
fn can_write_priority_output(address: u64, from_user_mode: bool) -> bool {
    if from_user_mode {
        return address < USER_PROBE_LIMIT && user_probe::probe_user_write(address, PAGE_PRIORITY_SIZE);
    }
    if !kernel_range_valid(address, PAGE_PRIORITY_SIZE) {
        return false;
    }
    let end = address.wrapping_add(PAGE_PRIORITY_SIZE);
    let mut page = address & !0xFFF;
    loop {
        let flags = paging::access_flags(page);
        if flags & 3 != 3 && (!page_residency::fault(page, 2 | (flags & 1) as u32) || paging::access_flags(page) & 3 != 3) {
            return false;
        }
        page = page.wrapping_add(4096);
        if page == 0 || page >= end {
            return true;
        }
    }
}

pub fn query(thread_handle: u64, information_class: u32, output: u64, output_length: u32, returned_length: u64, access_mode: u8) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("thread information query requires PASSIVE_LEVEL"));
    }
    let from_user_mode = access_mode != 0;
    if from_user_mode {
        // Alinha a quatro só comprimentos >= 4 (oito na classe 38).
        let alignment: u64 = if information_class == 38 { 8 } else if output_length < 4 { 1 } else { 4 };
        if output_length != 0 && output & (alignment - 1) != 0 {
            return Ok(0x8000_0002);
        }
        if output_length != 0 && output.wrapping_add(output_length as u64) > USER_PROBE_LIMIT {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        // ReturnLength é sondado antes da classe, do tamanho e do handle.
        if returned_length != 0 && !can_write_priority_output(returned_length, true) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    if information_class > 45 || REJECTED_QUERY_CLASSES.contains(&information_class) {
        return Ok(0xC000_0003);
    }
    if information_class == THREAD_CYCLE_TIME {
        return query_cycle_time(thread_handle, output, output_length, returned_length, access_mode);
    }
    if information_class == THREAD_NAME_INFORMATION {
        return query_name(thread_handle, output, output_length, returned_length, access_mode);
    }
    // Classes válidas ainda sem provedor falham explicitamente.
    if information_class != THREAD_PAGE_PRIORITY && information_class != THREAD_IO_PRIORITY && information_class != THREAD_BREAK_ON_TERMINATION {
        return Ok(0xC000_0002);
    }
    if output_length as u64 != PAGE_PRIORITY_SIZE {
        return Ok(0xC000_0004);
    }
    // ThreadBreakOnTermination (ntoskrnl 19041, rva 0x7f0c77; o
    // RtlSetThreadIsCritical lê assim o valor antigo): o mesmo ULONG, com
    // THREAD_QUERY_INFORMATION, 1 com CrossThreadFlags.BreakOnTermination.
    let access = if information_class == THREAD_BREAK_ON_TERMINATION { THREAD_QUERY_INFORMATION } else { THREAD_QUERY_LIMITED_INFORMATION };
    let mut reference = match thread_handles::reference(thread_handle, access, access_mode)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let result = (|| {
        // SAFETY: ETHREAD referenciado pelo handle.
        let ethread = unsafe { Ethread::at(reference.pointer) };
        let value = match information_class {
            THREAD_BREAK_ON_TERMINATION => ethread.break_on_termination(),
            THREAD_IO_PRIORITY => ethread.thread_io_priority(),
            _ => ethread.thread_page_priority(),
        };
        // A escrita vem depois da referência; erros anteriores preservam os buffers.
        if !can_write_priority_output(output, from_user_mode) {
            return STATUS_ACCESS_VIOLATION;
        }
        if guest::try_write::<u32>(output, value).is_err() {
            return STATUS_ACCESS_VIOLATION;
        }
        if returned_length != 0 {
            // Em KernelMode esta falha pode vir depois da escrita, como no NT.
            if !can_write_priority_output(returned_length, from_user_mode) {
                return STATUS_ACCESS_VIOLATION;
            }
            if guest::try_write::<u32>(returned_length, PAGE_PRIORITY_SIZE as u32).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }
        }
        0
    })();
    reference.release()?;
    Ok(result)
}


/// ThreadCycleTime (o ramo da classe 23 do NtQueryInformationThread 19041,
/// rva 0x5fbb5f): exatamente os 0x10 bytes do THREAD_CYCLE_TIME_INFORMATION
/// (outro tamanho dá STATUS_INFO_LENGTH_MISMATCH antes do handle); a thread
/// corrente pelo pseudo-handle, outra pelo handle com
/// THREAD_QUERY_LIMITED_INFORMATION; AccumulatedCycles e CurrentCycleCount
/// do KeQueryTotalCycleTimeThread (o KTHREAD.CycleTime e o TSC da amostra).
/// ReturnLength 0x10. O QueryThreadCycleTime do kernelbase lê a classe (o
/// agendador de quadros do dwmcore mede o próprio custo por ela).
fn query_cycle_time(thread_handle: u64, output: u64, output_length: u32, returned_length: u64, access_mode: u8) -> Result<u32, KernelError> {
    if output_length != 0x10 {
        return Ok(0xC000_0004);
    }
    let mut reference = match thread_handles::reference(thread_handle, THREAD_QUERY_LIMITED_INFORMATION, access_mode)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let accumulated = crate::ntos::ke::thread_dispatch::query_total_cycle_time(reference.pointer, None);
    let current = crate::hal::cpu::rdtsc();
    let written = guest::try_write::<u64>(output, accumulated).and_then(|()| guest::try_write::<u64>(output + 8, current)).and_then(|()| if returned_length != 0 { guest::try_write::<u32>(returned_length, 0x10) } else { Ok(()) });
    reference.release()?;
    Ok(match written {
        Ok(()) => 0,
        Err(error) => error.status,
    })
}

/// ThreadNameInformation (o ramo da classe 38, rva 0x7f1536): o handle com
/// THREAD_QUERY_LIMITED_INFORMATION; sob a trava da thread, o nome do
/// ETHREAD.ThreadName (vazio sem nome) pede o UNICODE_STRING e o texto logo
/// depois (Length + 0x10 bytes, o valor do ReturnLength também na recusa):
/// menor dá STATUS_BUFFER_TOO_SMALL; senão o texto vai a +0x10 e o
/// UNICODE_STRING sai com Length = MaximumLength e o Buffer apontando para
/// ele.
fn query_name(thread_handle: u64, output: u64, output_length: u32, returned_length: u64, access_mode: u8) -> Result<u32, KernelError> {
    let mut reference = match thread_handles::reference(thread_handle, THREAD_QUERY_LIMITED_INFORMATION, access_mode)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let text = super::set_thread_information::thread_name(reference.pointer);
    let required = text.len() as u32 + 0x10;
    let written = (|| -> Result<u32, KernelError> {
        let status = if required > output_length {
            0xC000_0023
        } else {
            guest::try_write_bytes(output + 0x10, &text)?;
            guest::try_write::<u16>(output, text.len() as u16)?;
            guest::try_write::<u16>(output + 2, text.len() as u16)?;
            guest::try_write::<u64>(output + 8, output + 0x10)?;
            0
        };
        if returned_length != 0 {
            guest::try_write::<u32>(returned_length, required)?;
        }
        Ok(status)
    })();
    reference.release()?;
    Ok(match written {
        Ok(status) => status,
        Err(error) => error.status,
    })
}

/// Variante de syscall: recupera os bits originais dos argumentos (ULONG
/// com lixo nos bits altos incluso) do frame bruto ou da pilha de usuário.
pub fn query_user(user_rsp: u64) -> Result<u32, KernelError> {
    let argument = |index: u64| {
        let words = crate::ntos::ps::user::state::syscall_arg_words(user_rsp, index);
        words[0] as u64 | ((words[1] as u64) << 32)
    };
    let low = |index: u64| crate::ntos::ps::user::state::syscall_arg_words(user_rsp, index)[0];
    query(argument(1), low(2), argument(3), low(4), argument(5), 1)
}
