//! Zw/NtQueryInformationThread.
//!
//! Contrato ThreadPagePriority medido nos bytes originais e em chamadas do
//! Windows. `access_mode` separa Nt (chamador usuário) de Zw (parâmetros de
//! kernel). A variante de syscall de usuário (`query_user`) entra com o
//! estado de modo usuário (fase 7).

use super::user_probe;
use crate::ntos::ke::irql;
use crate::ntos::mm::{page_residency, paging};
use crate::ntos::ob::handles::thread as thread_handles;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::kthread;

const THREAD_PAGE_PRIORITY: u32 = 24;
const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x800;
const PAGE_PRIORITY_SIZE: u64 = 4;
pub(crate) const USER_PROBE_LIMIT: u64 = 0x7FFF_FFFF_0000;
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
    // Classes válidas ainda sem provedor falham explicitamente.
    if information_class != THREAD_PAGE_PRIORITY {
        return Ok(0xC000_0002);
    }
    if output_length as u64 != PAGE_PRIORITY_SIZE {
        return Ok(0xC000_0004);
    }
    let mut reference = match thread_handles::reference(thread_handle, THREAD_QUERY_LIMITED_INFORMATION, access_mode)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let result = (|| {
        let flags = guest::read32(reference.pointer + kthread::CROSS_THREAD_FLAGS);
        let page_priority = (flags >> kthread::PAGE_PRIORITY_SHIFT) & 7;
        // A escrita vem depois da referência; erros anteriores preservam os buffers.
        if !can_write_priority_output(output, from_user_mode) {
            return STATUS_ACCESS_VIOLATION;
        }
        guest::write32(output, page_priority);
        if returned_length != 0 {
            // Em KernelMode esta falha pode vir depois da escrita, como no NT.
            if !can_write_priority_output(returned_length, from_user_mode) {
                return STATUS_ACCESS_VIOLATION;
            }
            guest::write32(returned_length, PAGE_PRIORITY_SIZE as u32);
        }
        0
    })();
    reference.release()?;
    Ok(result)
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
