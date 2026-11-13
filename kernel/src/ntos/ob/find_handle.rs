//! ObFindHandleForObject — `system32/ntos/ob/find-handle.js`.
//!
//! Busca um objeto na HANDLE_TABLE viva do processo. A enumeração entrega
//! cada entrada bloqueada; o filtro libera o bloqueio antes de acordar os
//! aguardantes.

use super::get_object_type;
use crate::ntos::ob::handles::process as process_handles;
use crate::ntos::ex::{enum_handles, unblock_push_lock};
use crate::ntos::ke::irql;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::init::exports::private_routines;

/// Compara cabeçalho, tipo e informações de acesso pelo contexto de três
/// ponteiros; o handle recebido não participa e a entrada sempre é liberada.
pub fn filter(table: u64, entry: u64, _handle: u64, context: u64) -> Result<u64, KernelError> {
    // O bit baixo zerado confirma a posse do bloqueio.
    let low = guest::read64(entry);
    if low & 1 != 0 {
        return Err(KernelError::new("ObFindHandleForObject callback does not own entry lock"));
    }
    let result = (|| -> Result<u64, KernelError> {
        // Endereço canônico do cabeçalho a partir da palavra compactada.
        let header = (((low as i64) >> 16) as u64) & !15;
        let object = guest::read64(context);
        let object_type = guest::read64(context + 8);
        if object != 0 && header != object {
            return Ok(0);
        }
        if object_type != 0 && get_object_type::get(header + 0x30)? != object_type {
            return Ok(0);
        }
        let information = guest::read64(context + 16);
        if information != 0 && (guest::read32(information) as u64 != (low >> 17) & 7 || guest::read32(information + 4) != guest::read32(entry + 8) & 0x1FF_FFFF) {
            return Ok(0);
        }
        Ok(1)
    })();
    // Preserva atualizações concorrentes da contagem na palavra da entrada.
    let mut previous = guest::compare_exchange64(entry, 0, 0)?;
    loop {
        let actual = guest::compare_exchange64(entry, previous, previous.wrapping_add(1))?;
        if actual == previous {
            break;
        }
        previous = actual;
    }
    if guest::read64(table + 0x30) != 0 {
        unblock_push_lock::unblock(table + 0x30, 0)?;
    }
    result
}

/// Retém a tabela do processo, monta o contexto do filtro e enumera com a
/// rotina nativa privada; o handle encontrado vai para a saída.
pub fn find(process: u64, object: u64, object_type: u64, handle_information: u64, output: u64) -> Result<u64, KernelError> {
    if irql::get_irql() >= 2 {
        return Err(KernelError::new("ObFindHandleForObject requires IRQL below DISPATCH_LEVEL"));
    }
    let table = process_handles::reference(process)?;
    if table == 0 {
        return Ok(0);
    }
    let context = guest::alloc_bytes(24);
    let result = (|| -> Result<u64, KernelError> {
        if context == 0 {
            return Err(KernelError::new("handle search context allocation failed"));
        }
        guest::write64(context, if object != 0 { object.wrapping_sub(0x30) } else { 0 });
        guest::write64(context + 8, object_type);
        guest::write64(context + 16, handle_information);
        Ok(enum_handles::enumerate(table, private_routines::address("ObpFindHandleForObject"), context, output)? as u64)
    })();
    if context != 0 {
        guest::free_bytes(context);
    }
    process_handles::release(process)?;
    result
}
