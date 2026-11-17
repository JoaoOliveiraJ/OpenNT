//! Rundown de processos e threads do logger do kernel.
//!
//! No ntoskrnl 19041 o EtwpProcessEnumCallback (rva 0x7924f0) recebe cada
//! processo com o contexto do rundown: +0x00 aponta a máscara de grupos e
//! +0x28 guarda o tipo do evento corrente. Com o grupo de threads (bit 2 da
//! máscara), as threads passam pelo EtwpThreadEnumCallback (rva 0x792a00),
//! que marca o tipo 0x601903 (DCStart de thread) antes de gravar o evento.
//! O OpenNT tem o mesmo par de rotinas (`hal/amd64/private_entries.rs`),
//! mas o seu logger só grava eventos com EVENT_HEADER de provedores
//! registrados: o rundown clássico do NT Kernel Logger não existe ainda, e
//! nenhum caminho do OpenNT inicia um rundown.

use crate::ntos::inc::field::{Field, NtStruct};

/// O tipo de evento que o EtwpThreadEnumCallback grava em +0x28.
pub const THREAD_DC_START: u32 = 0x0060_1903;
/// O tipo do evento no contexto do rundown (estrutura de pilha do
/// EtwpProcessThreadImageRundown, sem tipo público no PDB).
pub const EVENT_TYPE_OFFSET: u64 = 0x28;

/// EtwpThreadEnumCallback(Process, Thread, Context): marca o DCStart de
/// thread no contexto e devolve STATUS_SUCCESS para seguir a enumeração.
pub fn thread_enum_callback(_thread: u64, context: u64) -> u32 {
    if context != 0 {
        // SAFETY: o contexto do rundown que o chamador repassa.
        unsafe { Field::<u32>::at(context + EVENT_TYPE_OFFSET) }.set(THREAD_DC_START);
    }
    0
}
