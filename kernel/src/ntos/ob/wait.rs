//! Espera por handle em modo kernel (ZwWaitForSingleObject).
//!
//! O handle é resolvido na ordem: eventos da tabela nativa (abertos por
//! ponteiro), threads de sistema e os eventos abertos pelo núcleo de
//! handles de kernel do I/O; a espera em si é a do dispatcher do Ke.

use crate::ntos::init::exports::signed_status;
use crate::ntos::io::file::zw as zw_files;
use crate::ntos::ke::dispatcher;
use crate::ntos::ob::open_pointer;
use crate::ntos::ps::kernel_threads;

const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;

/// ZwWaitForSingleObject: eventos da tabela nativa (abertos por ponteiro),
/// threads de sistema e os eventos abertos pelo zw. Devolve o valor nativo
/// do export: a falha da resolução e a espera numa thread de sistema saem
/// estendidas com zeros; os demais NTSTATUS, com sinal.
pub fn wait_for_single_object(handle: u64, alertable: bool, timeout: u64) -> u64 {
    match open_pointer::resolve(handle, false) {
        Some(Err(status)) => return status as u64,
        Some(Ok(opened)) if opened.item.object_type.name == "Event" => {
            // O último fechamento durante a espera não libera o KEVENT em uso.
            opened.item.reference();
            let status = dispatcher::wait_for_single_object(opened.item.pointer, timeout, 0, alertable);
            opened.item.dereference();
            return signed_status(status);
        }
        _ => {}
    }
    if let Some(thread) = kernel_threads::of_handle(handle) {
        return dispatcher::wait_for_single_object(thread, timeout, 0, alertable) as u64;
    }
    let pointer = zw_files::wait_object_of_handle(handle);
    if pointer == 0 {
        return signed_status(STATUS_INVALID_HANDLE);
    }
    signed_status(dispatcher::wait_for_single_object(pointer, timeout, 0, alertable))
}
