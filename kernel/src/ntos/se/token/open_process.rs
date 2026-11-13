//! NtOpenProcessTokenEx.

use crate::ntos::se::token::{thread as thread_tokens, handles as token_handles, tokens};
use crate::ntos::alpc::message::buffer as message_buffer;
use crate::ntos::ke::irql;
use crate::ntos::ob::{object_access, object_types, process_reference};
use crate::ntos::ps::process;
use crate::rtl::KernelError;

/// Abre o token primário do processo do handle.
pub fn open(process_handle: u64, desired_access: u32, attributes: u32, output: u64, access_mode: u8) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("process token open requires PASSIVE_LEVEL"));
    }
    let from_user_mode = access_mode != 0;
    let attributes = attributes & if from_user_mode { 0x1DF2 } else { 0x11FF2 };
    // A sonda de usuário precede a resolução do processo, sem alinhamento.
    if from_user_mode && !message_buffer::accessible(output, 8, 1, true) {
        return Ok(0xC000_0005);
    }
    let mut referenced = match process_reference::reference(process_handle, 0x1000, from_user_mode as u8)? {
        Ok(referenced) => referenced,
        Err(status) => return Ok(status),
    };
    let token = process::get_primary_token(referenced.pointer);
    if let Some(token) = token {
        tokens::retain(token)?;
    }
    referenced.release()?;
    let Some(token) = token else { return Ok(0xC000_007C) };
    let result = (|| -> Result<u32, KernelError> {
        // Token recusa OBJ_EXCLUSIVE e OBJ_OPENLINK.
        if attributes & 0x120 != 0 {
            return Ok(0xC000_000D);
        }
        if !from_user_mode && attributes & 0x200 == 0 && process::get_current_process() != process::get_system_process() {
            return Ok(0xC000_000D);
        }
        let enforce = from_user_mode || attributes & 0x400 != 0;
        if enforce && thread_tokens::get(process::get_current_thread()).is_some_and(|impersonation| impersonation.level < 2) {
            return Ok(0xC000_00A5);
        }
        let security = tokens::with(token, |record| record.security.clone()).unwrap_or_default();
        let rights = match object_access::check(&security, object_access::subject(), desired_access, &object_types::token_type(), !enforce) {
            Ok(rights) => rights,
            Err(status) => return Ok(status),
        };
        // SeAccessCheck não publica uma abertura de usuário sem direito algum.
        if enforce && rights == 0 {
            return Ok(0xC000_0022);
        }
        let handle = match token_handles::create(token, rights, attributes, from_user_mode) {
            Ok(handle) => handle,
            Err(error) if error.status != 0 => return Ok(error.status),
            Err(error) => return Err(error),
        };
        // O handle já está publicado na cópia final; a tabela o recolhe no término.
        if !message_buffer::accessible(output, 8, from_user_mode as u8, true) {
            return Ok(0xC000_0005);
        }
        // Escrita sondada: o ponteiro pode ser de modo usuário.
        if crate::ntos::mm::guest_memory::try_write::<u64>(output, handle).is_err() {
            return Ok(0xC000_0005);
        }
        Ok(0)
    })();
    tokens::release(token)?;
    result
}
