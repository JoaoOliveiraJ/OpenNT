//! Tokens de modo usuário.
//!
//! Abertura de tokens de processo e thread, impersonação anônima e as
//! classes de NtQueryInformationToken montadas sobre o token real, com os
//! ponteiros internos relativos ao buffer do chamador.

use alloc::string::String;
use alloc::vec::Vec;

use super::state::{self, probe_user_read, probe_user_write, stack_arg};
use crate::ntos::ps::process;
use crate::ntos::se::token::{impersonate_anonymous, open_process as open_process_token, query as query_token, thread as thread_tokens, handles as token_handles, tokens};
use crate::ntos::se::security_attributes;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{NtStruct, UnicodeString};

fn current() -> Option<u64> {
    process::get_primary_token(process::get_current_process())
}

/// Token do handle; os pseudo-handles -4/-5/-6 só consultam.
pub fn lookup(handle: u64, access: u32) -> Result<u64, u32> {
    let pseudo = handle as i64;
    if (-6..=-4).contains(&pseudo) {
        if access & !8 != 0 {
            return Err(0xC000_0022);
        }
        let impersonation = thread_tokens::get(process::get_current_thread());
        let token = match pseudo {
            -4 => current(),
            _ => impersonation.map(|state| state.token).or_else(|| if pseudo == -6 { current() } else { None }),
        };
        return token.ok_or(0xC000_007C);
    }
    let Some(entry) = state::get_user_handle(handle) else { return Err(0xC000_0008) };
    if entry.kind() != "token" {
        return Err(0xC000_0024);
    }
    if entry.access() & access != access {
        return Err(0xC000_0022);
    }
    entry.downcast::<token_handles::UserToken>().map(|object| object.token).ok_or(0xC000_0008u32)
}

/// O frame bruto conserva handles, ponteiros e os bits baixos dos ULONGs.
fn token_argument(index: u64, fallback: u64) -> u64 {
    let raw = state::service_raw_arguments();
    if raw != 0 {
        guest::read64(raw + index * 8)
    } else {
        fallback
    }
}

fn nt_open_process_token(process_handle: u64, access: u64, output: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    open_process_token::open(token_argument(1, process_handle), token_argument(2, access) as u32, 0, token_argument(3, output), 1)
}

fn nt_open_process_token_ex(process_handle: u64, access: u64, attributes: u64, output: u64, _rsp: u64) -> Result<u32, KernelError> {
    open_process_token::open(token_argument(1, process_handle), token_argument(2, access) as u32, token_argument(3, attributes) as u32, token_argument(4, output), 1)
}

/// A syscall conserva os 64 bits do handle e exige direitos de UserMode.
fn nt_impersonate_anonymous_token(thread: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    impersonate_anonymous::impersonate(token_argument(1, thread), 1)
}

fn nt_open_thread_token(thread: u64, access: u64, as_self: u64, out: u64, _rsp: u64) -> Result<u32, KernelError> {
    token_handles::open_thread(thread, access as u32, as_self & 0xFF != 0, 0, out, true)
}

fn nt_open_thread_token_ex(thread: u64, access: u64, as_self: u64, attributes: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 8) {
        return Ok(0xC000_0005);
    }
    token_handles::open_thread(thread, access as u32, as_self & 0xFF != 0, attributes as u32, stack_arg(rsp, 5), true)
}

/// O ReturnLength e o buffer de usuário, com o contrato do Zw
/// (`query_token::write_encoded`).
fn write_result(result: Result<Vec<u8>, u32>, out: u64, length: u32, returned: u64) -> u32 {
    query_token::write_encoded(result, out, length, returned, true)
}

/// NtAllocateLocallyUniqueId(Luid*): o LUID sondado (ULONG alinhado) e um
/// valor novo do contador único (o ExAllocateLocallyUniqueId).
fn nt_allocate_locally_unique_id(luid: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if luid & 3 != 0 {
        return Ok(0x8000_0002);
    }
    if !probe_user_write(luid, 8) {
        return Ok(0xC000_0005);
    }
    let value = tokens::allocate_luid();
    // LUID: LowPart e HighPart (ULONG e LONG).
    let written = guest::try_write::<u32>(luid, value as u32).and_then(|_| guest::try_write::<u32>(luid + 4, (value >> 32) as u32));
    Ok(match written {
        Ok(()) => 0,
        Err(error) => error.status,
    })
}

/// A classe 10 usa a mesma ordem de sondagens, handles e escritas do Zw.
fn nt_query_information_token(handle: u64, class: u64, out: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    let class = class as u32;
    if class == 10 {
        return query_token::query_user(rsp);
    }
    let token = match lookup(handle, if class == 7 { 0x10 } else { 8 }) {
        Ok(token) => token,
        Err(status) => return Ok(status),
    };
    Ok(write_result(query_token::encode(token, class, out), out, length as u32, stack_arg(rsp, 5)))
}

/// Seis parâmetros, com o buffer em R9: a API exige saída não nula mesmo na
/// consulta de tamanho.
fn nt_query_security_attributes_token(handle: u64, attributes: u64, count: u64, out: u64, rsp: u64) -> Result<u32, KernelError> {
    let count = count as u32 as u64;
    let length = state::stack_arg32(rsp, 5);
    let returned = stack_arg(rsp, 6);
    if out == 0 || length == 0 || returned == 0 || (attributes != 0) != (count != 0) {
        return Ok(0xC000_000D);
    }
    if !probe_user_write(returned, 4) || !probe_user_write(out, length as u64) {
        return Ok(0xC000_0005);
    }
    let token = match lookup(handle, 8) {
        Ok(token) => token,
        Err(status) => return Ok(status),
    };
    if count != 0 && !probe_user_read(attributes, count * 16) {
        return Ok(0xC000_0005);
    }
    let mut names: Vec<String> = Vec::new();
    for index in 0..count {
        // Vetor de UNICODE_STRINGs de entrada (sondado acima).
        let name = match state::user_struct::<UnicodeString>(attributes + index * UnicodeString::SIZE).and_then(|name| Ok((name.length.probe_get()? as u64, name.buffer.probe_get()?))) {
            Ok(name) => name,
            Err(error) => return Ok(error.status),
        };
        let (size, pointer) = name;
        if size == 0 {
            let _ = guest::try_write::<u32>(returned, 0);
            return Ok(0xC000_000D);
        }
        if !probe_user_read(pointer, size) {
            return Ok(0xC000_0005);
        }
        // MaximumLength não limita a entrada desta API de strings contadas.
        match state::try_read_user_wide_string(pointer, size / 2) {
            Ok(text) => names.push(text),
            Err(error) => return Ok(error.status),
        }
    }
    let attributes_of_token = tokens::with(token, |record| record.security_attributes.clone()).unwrap_or_default();
    let selected = security_attributes::select(&attributes_of_token, if count != 0 { Some(&names) } else { None })?;
    let Some(selected) = selected else {
        let _ = guest::try_write::<u32>(returned, 0);
        return Ok(0xC000_0225);
    };
    Ok(write_result(security_attributes::encode(&selected, out), out, length, returned))
}

/// NtAdjustPrivilegesToken(TokenHandle, DisableAllPrivileges, NewState,
/// BufferLength, PreviousState, ReturnLength): o handle com
/// TOKEN_ADJUST_PRIVILEGES (e TOKEN_QUERY quando há PreviousState); o resto
/// em `se/token/adjust`.
fn nt_adjust_privileges_token(handle: u64, disable_all: u64, new_state: u64, buffer_length: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 16) {
        return Ok(0xC000_0005);
    }
    let (previous_state, return_length) = (stack_arg(rsp, 5), stack_arg(rsp, 6));
    let access = 0x20 | if previous_state != 0 { 8 } else { 0 };
    let token = match lookup(token_argument(1, handle), access) {
        Ok(token) => token,
        Err(status) => return Ok(status),
    };
    crate::ntos::se::token::adjust::adjust_privileges(token, disable_all as u8 != 0, new_state, buffer_length as u32, previous_state, return_length)
}

pub fn init() {
    state::register_handler("NtAdjustPrivilegesToken", nt_adjust_privileges_token);
    state::register_handler("NtOpenProcessToken", nt_open_process_token);
    state::register_handler("NtOpenProcessTokenEx", nt_open_process_token_ex);
    state::register_handler("NtImpersonateAnonymousToken", nt_impersonate_anonymous_token);
    state::register_handler("NtOpenThreadToken", nt_open_thread_token);
    state::register_handler("NtOpenThreadTokenEx", nt_open_thread_token_ex);
    state::register_handler("NtQueryInformationToken", nt_query_information_token);
    state::register_handler("NtAllocateLocallyUniqueId", nt_allocate_locally_unique_id);
    state::register_handler("NtQuerySecurityAttributesToken", nt_query_security_attributes_token);
}
