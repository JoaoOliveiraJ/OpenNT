//! Rotinas de notificação (o psnotify do NT): criação de processo, de thread
//! e carga de imagem.

pub mod thread;
pub mod image;
pub mod process;

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::ExRundownRef;

/// Bloco de um registro de notificação (pool 'Cbrb'; layout do OpenNT no
/// formato do EX_CALLBACK_ROUTINE_BLOCK do NT): proteção de rundown, rotina
/// e contexto.
#[repr(C)]
struct CallbackBlock {
    rundown_protect: ExRundownRef,
    function: Field<u64>,
    context: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for CallbackBlock {}

const _: () = assert!(core::mem::size_of::<CallbackBlock>() == 24);

impl CallbackBlock {
    /// O bloco recém-alocado (24 bytes zerados do pool) de um registro.
    fn of(pointer: u64) -> &'static CallbackBlock {
        // SAFETY: bloco de 24 bytes alocado pelo registro chamador.
        unsafe { CallbackBlock::at(pointer) }
    }
}
