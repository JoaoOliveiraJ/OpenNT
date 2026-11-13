//! Tokens de modo usuário.
//!
//! Abertura de tokens de processo e thread, impersonação anônima e as
//! classes de NtQueryInformationToken montadas sobre o token real, com os
//! ponteiros internos relativos ao buffer do chamador.

use alloc::string::String;
use alloc::vec::Vec;

use super::state::{self, probe_user_read, probe_user_write, stack_arg};
use crate::ntos::ps::process;
use crate::ntos::se::model::{Group, Sid};
use crate::ntos::se::token::{impersonate_anonymous, open_process as open_process_token, query as query_token, thread as thread_tokens, handles as token_handles, statistics as token_statistics, tokens};
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
    let raw = state::with(|state| state.service_raw_arguments);
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

/// Montador de layouts com SIDs anexados depois da parte fixa.
struct Layout {
    bytes: Vec<u8>,
    base: u64,
}

impl Layout {
    fn reserve(&mut self, size: usize) -> usize {
        let offset = self.bytes.len();
        self.bytes.resize(offset + size, 0);
        offset
    }
    fn u32(&mut self, offset: usize, value: u32) {
        self.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn u64(&mut self, offset: usize, value: u64) {
        self.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn append_sid(&mut self, pointer_offset: usize, sid: &Sid) {
        let offset = self.reserve(sid.len());
        self.bytes[offset..offset + sid.len()].copy_from_slice(sid);
        self.u64(pointer_offset, self.base + offset as u64);
    }
    fn groups(&mut self, entries: &[Group]) {
        self.reserve(8 + entries.len() * 16);
        self.u32(0, entries.len() as u32);
        for (index, group) in entries.iter().enumerate() {
            self.append_sid(8 + index * 16, &group.sid);
            self.u32(16 + index * 16, group.attributes);
        }
    }
    fn scalar(&mut self, value: u32) {
        self.reserve(4);
        self.u32(0, value);
    }
}

/// Layout da classe com ponteiros relativos a `base`, ou o NTSTATUS.
pub fn encode(token_pointer: u64, class: u32, base: u64) -> Result<Vec<u8>, u32> {
    let Some(token) = tokens::get(token_pointer) else { return Err(0xC000_0008) };
    let mut layout = Layout { bytes: Vec::with_capacity(512), base };
    match class {
        1 => {
            layout.reserve(16);
            layout.append_sid(0, &token.user);
            layout.u32(8, token.user_attributes);
        }
        2 => layout.groups(&token.groups),
        3 => {
            layout.reserve(4 + token.privileges.len() * 12);
            layout.u32(0, token.privileges.len() as u32);
            for (index, privilege) in token.privileges.iter().enumerate() {
                layout.u64(4 + index * 12, privilege.id);
                layout.u32(12 + index * 12, privilege.attributes);
            }
        }
        4 | 5 => {
            layout.reserve(8);
            layout.append_sid(0, if class == 4 { &token.owner } else { &token.primary_group });
        }
        6 => match &token.default_dacl {
            None => {
                layout.reserve(8);
            }
            Some(entries) => {
                let sids: Vec<Sid> = entries.iter().map(|ace| ace.sid.clone().unwrap_or_default()).collect();
                let size = 8 + sids.iter().map(|sid| 8 + sid.len()).sum::<usize>();
                layout.reserve(8 + size);
                layout.u64(0, base + 8);
                layout.bytes[8] = 2;
                layout.bytes[10..12].copy_from_slice(&(size as u16).to_le_bytes());
                layout.bytes[12..14].copy_from_slice(&(entries.len() as u16).to_le_bytes());
                let mut cursor = 16;
                for (ace, sid) in entries.iter().zip(&sids) {
                    layout.bytes[cursor] = if ace.deny { 1 } else { 0 };
                    layout.bytes[cursor + 1] = ace.flags;
                    layout.bytes[cursor + 2..cursor + 4].copy_from_slice(&((8 + sid.len()) as u16).to_le_bytes());
                    layout.u32(cursor + 4, ace.mask);
                    layout.bytes[cursor + 8..cursor + 8 + sid.len()].copy_from_slice(sid);
                    cursor += 8 + sid.len();
                }
            }
        },
        // TOKEN_SOURCE: o contexto de boot do OpenNT.
        7 => {
            layout.reserve(16);
            layout.bytes[..8].copy_from_slice(b"OpenNTbt");
            layout.u64(8, token.authentication_id);
        }
        8 => layout.scalar(token.kind),
        9 => {
            if token.kind != 2 {
                return Err(0xC000_0003);
            }
            layout.scalar(token.impersonation_level);
        }
        10 => return token_statistics::encode(token_pointer).map(|bytes| bytes.to_vec()).map_err(|error| if error.status != 0 { error.status } else { 0xC000_0001 }),
        11 => layout.groups(&token.restricted_sids),
        28 | 37 | 38 => layout.groups(&[]),
        30 => layout.groups(&token.capabilities),
        29 => layout.scalar(token.app_container.is_some() as u32),
        12 => layout.scalar(token.session_id),
        17 => {
            layout.reserve(8);
            layout.u64(0, token.authentication_id);
        }
        // TokenElevationTypeDefault: sem token vinculado ou filtrado.
        18 => layout.scalar(1),
        19 => return Err(0xC000_000D),
        // Contexto LocalSystem de boot.
        20 => layout.scalar(1),
        25 => {
            layout.reserve(16);
            layout.u32(8, 0x60);
            layout.append_sid(0, &token.integrity);
        }
        31 => {
            layout.reserve(8);
            if let Some(container) = &token.app_container {
                layout.append_sid(0, container);
            }
        }
        // Sem pacote nem SID de confiança do processo.
        41 => {
            layout.reserve(8);
        }
        39 => return security_attributes::encode(&token.security_attributes, base),
        // Versão 1, atributos de segurança vazios.
        33..=36 | 43 => {
            layout.reserve(16);
            layout.bytes[0] = 1;
        }
        // Sem isolamento BNO: o namespace nomeado do kernel é compartilhado.
        44 => {
            layout.reserve(16);
        }
        15 | 21 | 23 | 24 | 26 | 27 | 32 | 40 | 42 | 47 | 48 => layout.scalar(0),
        _ => return Err(0xC000_0003),
    }
    Ok(layout.bytes)
}

fn write_result(result: Result<Vec<u8>, u32>, out: u64, length: u32, returned: u64) -> u32 {
    let bytes = match result {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    // ULONG *ReturnLength e o buffer, sondados; as cópias também.
    if !probe_user_write(returned, 4) || guest::try_write::<u32>(returned, bytes.len() as u32).is_err() {
        return 0xC000_0005;
    }
    if (length as usize) < bytes.len() {
        return 0xC000_0023;
    }
    if !probe_user_write(out, bytes.len() as u64) || guest::try_write_bytes(out, &bytes).is_err() {
        return 0xC000_0005;
    }
    0
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
    Ok(write_result(encode(token, class, out), out, length as u32, stack_arg(rsp, 5)))
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

pub fn init() {
    state::register_handler("NtOpenProcessToken", nt_open_process_token);
    state::register_handler("NtOpenProcessTokenEx", nt_open_process_token_ex);
    state::register_handler("NtImpersonateAnonymousToken", nt_impersonate_anonymous_token);
    state::register_handler("NtOpenThreadToken", nt_open_thread_token);
    state::register_handler("NtOpenThreadTokenEx", nt_open_thread_token_ex);
    state::register_handler("NtQueryInformationToken", nt_query_information_token);
    state::register_handler("NtQuerySecurityAttributesToken", nt_query_security_attributes_token);
}
