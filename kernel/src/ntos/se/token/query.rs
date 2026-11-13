//! NtQueryInformationToken — `system32/ntos/se/query-token.js`.
//!
//! Contrato observado: TokenStatistics (classe 10), pedido pelo MSRPC
//! original, também pela variante de syscall de usuário (`queryUser`).

use crate::ntos::se::token::{reference as token_reference, statistics as token_statistics};
use crate::ntos::ke::irql;
use crate::ntos::mm::{page_residency, paging};
use crate::ntos::ps::user_probe;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const USER_PROBE_LIMIT: u64 = 0x7FFF_FFFF_0000;
const REJECTED_CLASSES: [u32; 7] = [0, 14, 35, 36, 38, 45, 46];
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;

/// Só memória com dono; a falha de um campo preserva os anteriores.
fn writable(address: u64, length: u64, from_user_mode: bool) -> bool {
    if from_user_mode {
        return address < USER_PROBE_LIMIT && user_probe::probe_user_write(address, length);
    }
    let Some(end) = address.checked_add(length) else { return false };
    if address == 0 || (address < 0xFFFF_8000_0000_0000 && end > 0x8000_0000_0000) {
        return false;
    }
    let mut page = address & !0xFFF;
    while page < end {
        let flags = paging::access_flags(page);
        if flags & 3 != 3 && (!page_residency::fault(page, 2 | (flags & 1) as u32) || paging::access_flags(page) & 3 != 3) {
            return false;
        }
        page += 4096;
    }
    true
}

/// NtQueryInformationToken(handle, classe, saída, tamanho, ReturnLength).
pub fn query(handle: u64, information_class: u32, output: u64, length: u32, returned: u64, access_mode: u8) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("Token query requires PASSIVE_LEVEL"));
    }
    let from_user_mode = access_mode != 0;
    if from_user_mode {
        // ProbeForWrite alinha a quatro mesmo com Length 1.
        if length != 0 && output & 3 != 0 {
            return Ok(0x8000_0002);
        }
        if length != 0 && (output + length as u64 > USER_PROBE_LIMIT || !writable(output, length as u64, true)) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        // ReturnLength é obrigatório e sondado antes da classe e do handle.
        if !writable(returned, 4, true) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    if information_class > 48 || REJECTED_CLASSES.contains(&information_class) {
        return Ok(0xC000_0003);
    }
    if information_class != 10 {
        return Ok(0xC000_0002);
    }
    let mut reference = match token_reference::reference(handle, 8, access_mode, true)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let result = (|| -> Result<u32, KernelError> {
        if !writable(returned, 4, from_user_mode) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        guest::write32(returned, 56);
        if length < 56 {
            return Ok(0xC000_0023);
        }
        // ReturnLength precede os dados, inclusive com endereços sobrepostos.
        for (offset, width, value) in token_statistics::fields(reference.token)? {
            let destination = output + offset;
            if !writable(destination, width as u64, from_user_mode) {
                return Ok(STATUS_ACCESS_VIOLATION);
            }
            if width == 8 {
                guest::write64(destination, value);
            } else {
                guest::write32(destination, value as u32);
            }
        }
        Ok(0)
    })();
    reference.release()?;
    result
}

/// Variante de syscall: os 64 bits dos argumentos vêm do frame bruto ou da
/// pilha de usuário.
pub fn query_user(user_rsp: u64) -> Result<u32, KernelError> {
    let argument = |index: u64| {
        let words = crate::ntos::ps::user::state::syscall_arg_words(user_rsp, index);
        words[0] as u64 | ((words[1] as u64) << 32)
    };
    let low = |index: u64| crate::ntos::ps::user::state::syscall_arg_words(user_rsp, index)[0];
    query(argument(1), low(2), argument(3), low(4), argument(5), 1)
}
