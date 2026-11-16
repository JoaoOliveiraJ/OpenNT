//! A porta de conclusão de um FILE_OBJECT, como no I/O Manager do 19041.
//!
//! - FileCompletionInformation (o NtSetInformationFile da classe 30, o
//!   CreateIoCompletionPort do Win32): com o FILE_OBJECT assíncrono e ainda
//!   sem porta, a IOCP é referenciada com IO_COMPLETION_MODIFY_STATE e o
//!   IO_COMPLETION_CONTEXT (Port, Key) vai para FileObject->CompletionContext;
//!   o FO_GENERATE_AUDIT_ON_CLOSE sai das flags, como no NtSetInformationFile.
//!   Um arquivo síncrono recusa (STATUS_INVALID_PARAMETER) e uma segunda
//!   porta também (STATUS_PORT_ALREADY_SET).
//! - FileIoCompletionNotificationInformation (classe 41, o
//!   SetFileCompletionNotificationModes): num arquivo assíncrono, os bits
//!   FILE_SKIP_COMPLETION_PORT_ON_SUCCESS, FILE_SKIP_SET_EVENT_ON_HANDLE e
//!   FILE_SKIP_SET_USER_EVENT_ON_FAST_IO viram FO_SKIP_COMPLETION_PORT,
//!   FO_SKIP_SET_EVENT e FO_SKIP_SET_FAST_IO.
//! - A conclusão (IopCompleteRequest) de um IRP de arquivo com porta e com
//!   UserApcContext põe na IOCP o pacote (Key da porta, o contexto, o
//!   IoStatus), salvo com FO_SKIP_COMPLETION_PORT quando o pedido concluiu
//!   sem STATUS_PENDING e sem status de aviso.
//! - O fim do FILE_OBJECT (IopDeleteFile) solta a IOCP e o contexto.

use crate::ntos::inc::types::{FileObject, IoCompletionContext, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::objects::completion::{self as completion_objects, Packet};
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::ps::user::io_completion;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_PORT_ALREADY_SET: u32 = 0xC000_0048;
/// IO_COMPLETION_MODIFY_STATE.
const IO_COMPLETION_MODIFY_STATE: u32 = 2;
const FO_SYNCHRONOUS_IO: u32 = 0x2;
const FO_GENERATE_AUDIT_ON_CLOSE: u32 = 0x400;
const FO_SKIP_COMPLETION_PORT: u32 = 0x0200_0000;
const FO_SKIP_SET_EVENT: u32 = 0x0400_0000;
const FO_SKIP_SET_FAST_IO: u32 = 0x0800_0000;

fn file_at(file: u64) -> &'static FileObject {
    // SAFETY: FILE_OBJECT vivo, referenciado por quem chama.
    unsafe { FileObject::at(file) }
}

fn context_at(context: u64) -> &'static IoCompletionContext {
    // SAFETY: IO_COMPLETION_CONTEXT alocado por `associate`, vivo enquanto o
    // FILE_OBJECT o aponta.
    unsafe { IoCompletionContext::at(context) }
}

/// FileCompletionInformation: `port_handle` (handle de usuário da IOCP) e
/// `key`.
pub fn associate(file: u64, port_handle: u64, key: u64) -> u32 {
    let object = file_at(file);
    if object.completion_context.get() != 0 || object.flags.get() & FO_SYNCHRONOUS_IO != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let port = match io_completion::resolve(port_handle, IO_COMPLETION_MODIFY_STATE) {
        Ok((_, port)) => port,
        Err(status) => return status,
    };
    let context = guest::alloc_bytes(IoCompletionContext::SIZE);
    if context == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if dispatcher_objects::reference(port.pointer).is_err() {
        guest::free_bytes(context);
        return STATUS_INVALID_PARAMETER;
    }
    let record = context_at(context);
    record.port.set(port.pointer);
    record.key.set(key);
    record.usage_count.set(0);
    if object.completion_context.atomic().compare_exchange(0, context, core::sync::atomic::Ordering::SeqCst, core::sync::atomic::Ordering::SeqCst).is_err() {
        let _ = dispatcher_objects::dereference(port.pointer);
        guest::free_bytes(context);
        return STATUS_PORT_ALREADY_SET;
    }
    object.flags.atomic().fetch_and(!FO_GENERATE_AUDIT_ON_CLOSE, core::sync::atomic::Ordering::SeqCst);
    0
}

/// FileIoCompletionNotificationInformation: os modos de `flags`.
pub fn set_notification_modes(file: u64, flags: u32) -> u32 {
    let object = file_at(file);
    if object.flags.get() & FO_SYNCHRONOUS_IO != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let mut set = 0;
    for (bit, flag) in [(1, FO_SKIP_COMPLETION_PORT), (2, FO_SKIP_SET_EVENT), (4, FO_SKIP_SET_FAST_IO)] {
        if flags & bit != 0 {
            set |= flag;
        }
    }
    object.flags.atomic().fetch_or(set, core::sync::atomic::Ordering::SeqCst);
    0
}

/// O FILE_OBJECT pede que a conclusão sem UserEvent deixe o evento dele
/// como está (FO_SKIP_SET_EVENT).
pub fn skips_file_event(file: u64) -> bool {
    file_at(file).flags.get() & FO_SKIP_SET_EVENT != 0
}

/// A conclusão de um IRP de `file`: o pacote na IOCP do arquivo, quando ela
/// existe e o pedido levou contexto (`apc_context`, o UserApcContext).
pub fn complete(file: u64, apc_context: u64, status: u32, information: u64, pending_returned: bool) {
    let object = file_at(file);
    let context = object.completion_context.get();
    if context == 0 || apc_context == 0 {
        return;
    }
    if object.flags.get() & FO_SKIP_COMPLETION_PORT != 0 && !pending_returned && status & 0xC000_0000 != 0x8000_0000 {
        return;
    }
    let record = context_at(context);
    if let Some(port) = completion_objects::port_of(record.port.get()).filter(|port| !port.closed()) {
        completion_objects::enqueue(&port, Packet { key: record.key.get(), context: apc_context, status, information, ..Packet::default() });
    }
}

/// IopDeleteFile: a IOCP e o contexto do FILE_OBJECT que acaba.
pub fn release(file: u64) {
    let context = file_at(file).completion_context.atomic().swap(0, core::sync::atomic::Ordering::SeqCst);
    if context == 0 {
        return;
    }
    let _ = dispatcher_objects::dereference(context_at(context).port.get());
    guest::free_bytes(context);
}
