//! Zw/NtSetInformationThread — `system32/ntos/ps/set-thread-information.js`.
//!
//! ThreadPagePriority altera só os três bits medidos na ETHREAD original. A
//! ordem medida é sondagem, tamanho, captura/valor, referência, alteração
//! atômica e liberação. A variante de syscall de usuário (`setUser`) entra
//! com o estado de modo usuário (fase 7).

use super::query_thread::{kernel_range_valid, STATUS_ACCESS_VIOLATION, USER_PROBE_LIMIT};
use super::user_probe;
use crate::ntos::ke::irql;
use crate::ntos::mm::{page_residency, paging};
use crate::ntos::ob::handles::thread as thread_handles;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::kthread;

const THREAD_PAGE_PRIORITY: u32 = 24;
const THREAD_SET_INFORMATION: u32 = 0x20;
const REJECTED_SET_CLASSES: [u32; 17] = [0, 6, 8, 11, 12, 16, 20, 21, 23, 26, 27, 28, 35, 37, 40, 41, 45];

/// A captura aceita memória só de leitura e endereços desalinhados em
/// KernelMode.
fn can_read_page_priority(address: u64, from_user_mode: bool) -> bool {
    if from_user_mode {
        return address < USER_PROBE_LIMIT && user_probe::probe_user_read(address, 4);
    }
    if !kernel_range_valid(address, 4) {
        return false;
    }
    let end = address.wrapping_add(4);
    let mut page = address & !4095;
    loop {
        if paging::access_flags(page) & 1 == 0 && (!page_residency::fault(page, 0) || paging::access_flags(page) & 1 == 0) {
            return false;
        }
        page = page.wrapping_add(4096);
        if page == 0 || page >= end {
            return true;
        }
    }
}

pub fn set(thread_handle: u64, information_class: u32, input: u64, input_length: u32, access_mode: u8) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("thread information set requires PASSIVE_LEVEL"));
    }
    let from_user_mode = access_mode != 0;
    if from_user_mode && input_length != 0 {
        // Qualquer comprimento não nulo exige alinhamento de quatro bytes.
        if input & 3 != 0 {
            return Ok(0x8000_0002);
        }
        if input.wrapping_add(input_length as u64) > USER_PROBE_LIMIT {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    if information_class > 50 || REJECTED_SET_CLASSES.contains(&information_class) {
        return Ok(0xC000_0003);
    }
    if information_class != THREAD_PAGE_PRIORITY {
        return Ok(0xC000_0002);
    }
    if input_length != 4 {
        return Ok(0xC000_0004);
    }
    if !can_read_page_priority(input, from_user_mode) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    // Captura uma vez: outra thread pode mudar o buffer enquanto o handle é resolvido.
    let page_priority = guest::read32(input);
    if !(1..=5).contains(&page_priority) {
        return Ok(0xC000_000D);
    }
    let mut reference = match thread_handles::reference(thread_handle, THREAD_SET_INFORMATION, access_mode)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let result = (|| -> Result<u32, KernelError> {
        let flags_address = reference.pointer + kthread::CROSS_THREAD_FLAGS;
        let mut previous = guest::read32(flags_address);
        loop {
            let replacement = (previous & !0x7000) | (page_priority << kthread::PAGE_PRIORITY_SHIFT);
            let observed = guest::compare_exchange32(flags_address, previous, replacement)?;
            if observed == previous {
                return Ok(0);
            }
            // Recalcula sobre os flags novos, preservando mudanças concorrentes.
            previous = observed;
        }
    })();
    reference.release()?;
    result
}


/// Variante de syscall: recupera os argumentos originais, inclusive o lixo
/// nos bits altos de ULONG.
pub fn set_user(user_rsp: u64) -> Result<u32, KernelError> {
    let argument = |index: u64| {
        let words = crate::ntos::ps::user::state::syscall_arg_words(user_rsp, index);
        words[0] as u64 | ((words[1] as u64) << 32)
    };
    let low = |index: u64| crate::ntos::ps::user::state::syscall_arg_words(user_rsp, index)[0];
    set(argument(1), low(2), argument(3), low(4), 1)
}
