//! Tabela publicada pelo Filter Manager.
//!
//! O kernel não interpreta nomes, não possui os buffers devolvidos e não
//! substitui um provedor ausente. FltMgrCallbacks começa nulo; o dono da
//! tabela conserva memória e callbacks enquanto publicados ou em execução.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::amd64::native_call;
use crate::ntos::mm::guest_memory as guest;

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
    let callback = guest::read64(table + 0x18);
    native_call::call(callback, &[file_object, name_options as u64, file_name, information]) as u32
}

/// FsRtlReleaseFileNameInformation: slot 0x20, sem testar tabela nem
/// informação NULL, como o original; o dono controla o armazenamento.
pub fn release_file_name_information(information: u64) {
    let table = current_callbacks();
    let callback = guest::read64(table + 0x20);
    native_call::call(callback, &[information, 0, 0, 0]);
}
