//! ObFindHandleForObject.
//!
//! Busca um objeto na HANDLE_TABLE viva do processo. A enumeração entrega
//! cada entrada bloqueada; o filtro libera o bloqueio antes de acordar os
//! aguardantes.

use super::get_object_type;
use crate::ntos::ob::handles::process as process_handles;
use crate::ntos::ex::{enum_handles, unblock_push_lock};
use crate::ntos::ke::irql;
use core::sync::atomic::Ordering;

use crate::rtl::KernelError;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{HandleTable, HandleTableEntry, ObjectHandleInformation};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::init::exports::private_routines;

/// Contexto da busca (três ponteiros) entregue ao filtro pela enumeração.
#[repr(C)]
struct SearchContext {
    /// -> `_OBJECT_HEADER` (corpo - 0x30), 0 = qualquer objeto
    object_header: Field<u64>,
    /// -> `_OBJECT_TYPE`, 0 = qualquer tipo
    object_type: Field<u64>,
    /// -> `_OBJECT_HANDLE_INFORMATION`, 0 = sem comparação
    handle_information: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for SearchContext {}

const _: () = assert!(core::mem::size_of::<SearchContext>() == 0x18);

/// Distância do corpo ao início do OBJECT_HEADER (`Body` em +0x30).
const OBJECT_HEADER_BODY: u64 = core::mem::offset_of!(crate::ntos::inc::types::ObjectHeader, body) as u64;

/// Compara cabeçalho, tipo e informações de acesso pelo contexto de três
/// ponteiros; o handle recebido não participa e a entrada sempre é liberada.
pub fn filter(table: u64, entry: u64, _handle: u64, context: u64) -> Result<u64, KernelError> {
    // SAFETY: a enumeração nativa entrega a tabela viva, a entrada bloqueada
    // e o contexto montado por `find`.
    let (table, entry, context) = unsafe { (HandleTable::at(table), HandleTableEntry::at(entry), SearchContext::at(context)) };
    // O bit baixo zerado confirma a posse do bloqueio.
    let low = entry.volatile_low_value.get() as u64;
    if low & 1 != 0 {
        return Err(KernelError::new("ObFindHandleForObject callback does not own entry lock"));
    }
    let result = (|| -> Result<u64, KernelError> {
        // Endereço canônico do cabeçalho a partir da palavra compactada.
        let header = (((low as i64) >> 16) as u64) & !15;
        let object = context.object_header.get();
        let object_type = context.object_type.get();
        if object != 0 && header != object {
            return Ok(0);
        }
        if object_type != 0 && get_object_type::get(header + OBJECT_HEADER_BODY)? != object_type {
            return Ok(0);
        }
        let information = context.handle_information.get();
        if information != 0 {
            // SAFETY: POBJECT_HANDLE_INFORMATION do chamador de kernel.
            let information = unsafe { ObjectHandleInformation::at(information) };
            if information.handle_attributes.get() as u64 != entry.attributes() || information.granted_access.get() != entry.granted_access_bits() {
                return Ok(0);
            }
        }
        Ok(1)
    })();
    // Destrava (Unlocked = 1) preservando atualizações concorrentes da contagem.
    entry.volatile_low_value.atomic().fetch_add(1, Ordering::SeqCst);
    if table.handle_contention_event.value.get() != 0 {
        unblock_push_lock::unblock(table.handle_contention_event.address(), 0)?;
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
    let context = guest::alloc_bytes(SearchContext::SIZE);
    let result = (|| -> Result<u64, KernelError> {
        if context == 0 {
            return Err(KernelError::new("handle search context allocation failed"));
        }
        // SAFETY: alocação nova do tamanho do contexto.
        let search = unsafe { SearchContext::at(context) };
        search.object_header.set(if object != 0 { object.wrapping_sub(OBJECT_HEADER_BODY) } else { 0 });
        search.object_type.set(object_type);
        search.handle_information.set(handle_information);
        Ok(enum_handles::enumerate(table, private_routines::address("ObpFindHandleForObject"), context, output)? as u64)
    })();
    if context != 0 {
        guest::free_bytes(context);
    }
    process_handles::release(process)?;
    result
}
