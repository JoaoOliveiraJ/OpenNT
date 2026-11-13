//! Tabela publicada pelo Filter Manager.
//!
//! O kernel não interpreta nomes, não possui os buffers devolvidos e não
//! substitui um provedor ausente. FltMgrCallbacks começa nulo; o dono da
//! tabela conserva memória e callbacks enquanto publicados ou em execução.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::amd64::native_call;
use crate::ntos::inc::field::{Field, NtStruct};

/// A tabela publicada pelo Filter Manager (sem tipo público): o kernel só
/// chama as duas rotinas de nome de arquivo.
#[repr(C)]
struct FltMgrCallbacks {
    /// Slots que o kernel não usa.
    other: [Field<u64>; 3],
    get_file_name_information: Field<u64>,
    release_file_name_information: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for FltMgrCallbacks {}

const _: () = assert!(core::mem::offset_of!(FltMgrCallbacks, get_file_name_information) == 0x18);

fn callbacks_at(table: u64) -> &'static FltMgrCallbacks {
    // SAFETY: o dono da tabela a conserva enquanto publicada ou em execução.
    unsafe { FltMgrCallbacks::at(table) }
}

static CALLBACKS: AtomicU64 = AtomicU64::new(0);

/// FsRtlRegisterFltMgrCalls: publica a tabela e devolve a anterior (para a
/// inicialização e os testes restaurarem o dono).
pub fn exchange_callbacks(table: u64) -> u64 {
    CALLBACKS.swap(table, Ordering::AcqRel)
}

pub fn current_callbacks() -> u64 {
    CALLBACKS.load(Ordering::Acquire)
}

/// FsRtlGetFileNameInformation: slot 0x18 da tabela com os quatro
/// argumentos; sem Filter Manager devolve STATUS_NOT_SUPPORTED sem tocar
/// nos buffers do chamador.
pub fn get_file_name_information(file_object: u64, name_options: u32, file_name: u64, information: u64) -> u32 {
    let table = current_callbacks();
    if table == 0 {
        return 0xC000_00BB;
    }
    let callback = callbacks_at(table).get_file_name_information.get();
    native_call::call(callback, &[file_object, name_options as u64, file_name, information]) as u32
}

/// FsRtlReleaseFileNameInformation: slot 0x20, sem testar tabela nem
/// informação NULL; o dono controla o armazenamento.
pub fn release_file_name_information(information: u64) {
    let table = current_callbacks();
    let callback = callbacks_at(table).release_file_name_information.get();
    native_call::call(callback, &[information, 0, 0, 0]);
}
