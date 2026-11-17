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

/// THREAD_IMPERSONATE (a thread servidora) e THREAD_DIRECT_IMPERSONATION (a
/// thread cliente).
const THREAD_IMPERSONATE: u32 = 0x100;
const THREAD_DIRECT_IMPERSONATION: u32 = 0x200;

/// NtImpersonateThread(ServerThreadHandle, ClientThreadHandle, SecurityQos),
/// como o 19041: o QOS de modo usuário alinhado a 4 (senão
/// STATUS_DATATYPE_MISALIGNMENT) e sondado, copiado sem conferir o Length; o
/// handle do cliente referenciado com THREAD_DIRECT_IMPERSONATION antes do
/// handle do servidor com THREAD_IMPERSONATE; depois o corpo de
/// `ps::security::impersonate_thread`.
fn nt_impersonate_thread(server: u64, client: u64, qos: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    use crate::ntos::inc::types::SecurityQualityOfService;
    use crate::ntos::ps::security::{self as ps_security, CapturedQuality};
    let (server, client, qos) = (token_argument(1, server), token_argument(2, client), token_argument(3, qos));
    if qos & 3 != 0 {
        return Ok(0x8000_0002);
    }
    if !probe_user_read(qos, SecurityQualityOfService::SIZE) {
        return Ok(0xC000_0005);
    }
    let captured = state::user_struct::<SecurityQualityOfService>(qos).and_then(|source| {
        Ok(CapturedQuality { level: source.impersonation_level.probe_get()?.0 as u32, tracking: source.context_tracking_mode.probe_get()?, effective_only: source.effective_only.probe_get()? })
    });
    let Ok(captured) = captured else { return Ok(0xC000_0005) };
    let client = match super::threads::resolve(client, THREAD_DIRECT_IMPERSONATION) {
        Ok(thread) => thread,
        Err(status) => return Ok(status),
    };
    let server = match super::threads::resolve(server, THREAD_IMPERSONATE) {
        Ok(thread) => thread,
        Err(status) => return Ok(status),
    };
    ps_security::impersonate_thread(server.pointer(), client.pointer(), captured)
}

/// RtlIsSandboxedToken: o token efetivo de quem chama tem integridade abaixo
/// de média (SECURITY_MANDATORY_MEDIUM_RID) ou é de AppContainer.
fn caller_sandboxed() -> bool {
    const MEDIUM_RID: u32 = 0x2000;
    crate::ntos::se::token::thread::effective(process::get_current_thread(), false)
        .and_then(|token| tokens::with(token, |token| {
            let rid = token.integrity.len().checked_sub(4).map_or(0, |at| u32::from_le_bytes([token.integrity[at], token.integrity[at + 1], token.integrity[at + 2], token.integrity[at + 3]]));
            rid < MEDIUM_RID || token.app_container.is_some()
        }))
        .unwrap_or(false)
}

/// NtDuplicateToken(ExistingToken, DesiredAccess, ObjectAttributes,
/// EffectiveOnly, TokenType, NewToken): o `se/token/duplicate.rs` em
/// UserMode (as capturas sondadas, o handle novo na tabela de quem chama).
/// O RtlAcquirePrivilege da ntdll (o ScGetPrivilege do services.exe)
/// duplica assim o próprio token para ligar um privilégio. Lacuna: quem
/// chama de um token sandboxed (o SepNewTokenAsRestrictedAsProcessToken do
/// 19041) recebe STATUS_NOT_SUPPORTED, com registro.
fn nt_duplicate_token(existing: u64, access: u64, attributes: u64, effective_only: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 16) {
        return Ok(0xC000_0005);
    }
    if caller_sandboxed() {
        crate::debug_print!("[se] NtDuplicateToken de um token sandboxed sem suporte");
        return Ok(0xC000_00BB);
    }
    crate::ntos::se::token::duplicate::duplicate(token_argument(1, existing), access as u32, attributes, effective_only & 0xFF != 0, state::stack_arg32(rsp, 5), stack_arg(rsp, 6), 1)
}

/// NtPrivilegeCheck(ClientToken, RequiredPrivileges, Result), como o 19041:
/// o token com TOKEN_QUERY (um token de impersonação abaixo de
/// SecurityIdentification dá STATUS_BAD_IMPERSONATION_LEVEL); o
/// PRIVILEGE_SET alinhado a 4 e sondado para escrita no tamanho do
/// PrivilegeCount, e o BOOLEAN do resultado; o SepPrivilegeCheck nos
/// privilégios capturados, que voltam ao PRIVILEGE_SET com
/// SE_PRIVILEGE_USED_FOR_ACCESS nos que o token tem habilitados. O
/// ScGetPrivilege do services.exe confere assim o privilégio que acabou de
/// ligar.
fn nt_privilege_check(token_handle: u64, required: u64, result: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    let token = match lookup(token_argument(1, token_handle), 8) {
        Ok(token) => token,
        Err(status) => return Ok(status),
    };
    if tokens::with(token, |token| token.kind == 2 && token.impersonation_level < 1).unwrap_or(false) {
        return Ok(0xC000_00A5);
    }
    if required & 3 != 0 {
        return Ok(0x8000_0002);
    }
    if !probe_user_write(required, 8) {
        return Ok(0xC000_0005);
    }
    let Ok(count) = guest::try_read::<u32>(required) else { return Ok(0xC000_0005) };
    let size = (count as u64).saturating_sub(1) * 12 + 0x14;
    if !probe_user_write(required, size) || !probe_user_write(result, 1) {
        return Ok(0xC000_0005);
    }
    let Ok(control) = guest::try_read::<u32>(required + 4) else { return Ok(0xC000_0005) };
    let mut entries = Vec::with_capacity(count as usize);
    for index in 0..count as u64 {
        let entry = required + 8 + index * 12;
        let (Ok(low), Ok(high), Ok(attributes)) = (guest::try_read::<u32>(entry), guest::try_read::<u32>(entry + 4), guest::try_read::<u32>(entry + 8)) else { return Ok(0xC000_0005) };
        entries.push((low as u64 | (high as u64) << 32, attributes));
    }
    let granted = crate::ntos::se::privilege::token_privilege_check(token, &mut entries, control, 1);
    for (index, (_, attributes)) in entries.iter().enumerate() {
        if guest::try_write::<u32>(required + 8 + index as u64 * 12 + 8, *attributes).is_err() {
            return Ok(0xC000_0005);
        }
    }
    if guest::try_write::<u8>(result, granted as u8).is_err() {
        return Ok(0xC000_0005);
    }
    Ok(0)
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

/// NtCreateToken(TokenHandle, DesiredAccess, ObjectAttributes, TokenType,
/// AuthenticationId, ExpirationTime, User, Groups, Privileges, Owner,
/// PrimaryGroup, DefaultDacl, TokenSource): o NtCreateTokenEx sem atributos
/// de usuário e de dispositivo, grupos de dispositivo e política
/// obrigatória (`se/token/create`).
fn nt_create_token(handle: u64, access: u64, attributes: u64, token_type: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 9 * 8) {
        return Ok(0xC000_0005);
    }
    let request = crate::ntos::se::token::create::Request {
        token_handle: handle,
        desired_access: access as u32,
        object_attributes: attributes,
        token_type: token_type as u32,
        authentication_id: stack_arg(rsp, 5),
        expiration_time: stack_arg(rsp, 6),
        user: stack_arg(rsp, 7),
        groups: stack_arg(rsp, 8),
        privileges: stack_arg(rsp, 9),
        user_attributes: 0,
        device_attributes: 0,
        device_groups: 0,
        mandatory_policy: 0,
        owner: stack_arg(rsp, 10),
        primary_group: stack_arg(rsp, 11),
        default_dacl: stack_arg(rsp, 12),
        token_source: stack_arg(rsp, 13),
    };
    crate::ntos::se::token::create::create(&request, 1)
}

/// NtCreateTokenEx(TokenHandle, DesiredAccess, ObjectAttributes, TokenType,
/// AuthenticationId, ExpirationTime, User, Groups, Privileges,
/// UserAttributes, DeviceAttributes, DeviceGroups, MandatoryPolicy, Owner,
/// PrimaryGroup, DefaultDacl, TokenSource) (`se/token/create`).
fn nt_create_token_ex(handle: u64, access: u64, attributes: u64, token_type: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 13 * 8) {
        return Ok(0xC000_0005);
    }
    let request = crate::ntos::se::token::create::Request {
        token_handle: handle,
        desired_access: access as u32,
        object_attributes: attributes,
        token_type: token_type as u32,
        authentication_id: stack_arg(rsp, 5),
        expiration_time: stack_arg(rsp, 6),
        user: stack_arg(rsp, 7),
        groups: stack_arg(rsp, 8),
        privileges: stack_arg(rsp, 9),
        user_attributes: stack_arg(rsp, 10),
        device_attributes: stack_arg(rsp, 11),
        device_groups: stack_arg(rsp, 12),
        mandatory_policy: stack_arg(rsp, 13),
        owner: stack_arg(rsp, 14),
        primary_group: stack_arg(rsp, 15),
        default_dacl: stack_arg(rsp, 16),
        token_source: stack_arg(rsp, 17),
    };
    crate::ntos::se::token::create::create(&request, 1)
}

/// NtSetInformationToken(TokenHandle, TokenInformationClass,
/// TokenInformation, TokenInformationLength) (`se/token/set_information`):
/// a classe é conferida antes do handle, que pede o acesso dela.
fn nt_set_information_token(handle: u64, class: u64, information: u64, length: u64, _rsp: u64) -> Result<u32, KernelError> {
    use crate::ntos::se::token::set_information;
    let class = class as u32;
    let Some(access) = set_information::required_access(class) else { return Ok(0xC000_0003) };
    if length != 0 && !probe_user_read(information, length) {
        return Ok(0xC000_0005);
    }
    let token = match lookup(token_argument(1, handle), access) {
        Ok(token) => token,
        Err(status) => return Ok(status),
    };
    set_information::set(token, class, information, length as u32, 1)
}

/// NtAccessCheck(SecurityDescriptor, ClientToken, DesiredAccess,
/// GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccess,
/// AccessStatus) (`se/access_check`): o token pelo handle com TOKEN_QUERY.
fn nt_access_check(descriptor: u64, client_token: u64, desired: u64, mapping: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 4 * 8) {
        return Ok(0xC000_0005);
    }
    let (privilege_set, privilege_length, granted, status) = (stack_arg(rsp, 5), stack_arg(rsp, 6), stack_arg(rsp, 7), stack_arg(rsp, 8));
    if !probe_user_read(mapping, 16) || !probe_user_write(privilege_length, 4) || !probe_user_write(granted, 4) || !probe_user_write(status, 4) {
        return Ok(0xC000_0005);
    }
    let available = guest::try_read::<u32>(privilege_length).unwrap_or(0) as u64;
    if available != 0 && !probe_user_write(privilege_set, available) {
        return Ok(0xC000_0005);
    }
    let handle = token_argument(2, client_token);
    let token = match lookup(handle, 8) {
        Ok(token) => token,
        Err(status) => return Ok(status),
    };
    let pseudo = (-6..=-4).contains(&(handle as i64));
    Ok(crate::ntos::se::access_check::check_by_token(descriptor, token, pseudo, desired as u32, mapping, privilege_set, privilege_length, granted, status))
}

/// NtPrivilegedServiceAuditAlarm(SubsystemName, ServiceName, ClientToken,
/// Privileges, AccessGranted): o SeAuditPrivilege do chamador
/// (STATUS_PRIVILEGE_NOT_HELD), o token do cliente com TOKEN_QUERY e o
/// PRIVILEGE_SET sondado; o alarme é `se::audit`.
fn nt_privileged_service_audit_alarm(_subsystem: u64, service: u64, client_token: u64, privileges: u64, rsp: u64) -> Result<u32, KernelError> {
    let granted = stack_arg(rsp, 5) as u8 != 0;
    if !crate::ntos::se::privilege::audit_privilege_check(1) {
        return Ok(0xC000_0061);
    }
    let token = match lookup(client_token, 8) {
        Ok(token) => token,
        Err(status) => return Ok(status),
    };
    if !probe_user_read(privileges, 8) {
        return Ok(0xC000_0005);
    }
    let count = guest::try_read::<u32>(privileges).unwrap_or(0);
    if !probe_user_read(privileges, 8 + count as u64 * 12) {
        return Ok(0xC000_0005);
    }
    let service_name = if service != 0 && probe_user_read(service, UnicodeString::SIZE) {
        crate::ntos::rtl::guest_strings::read_unicode_string(service)
    } else {
        String::new()
    };
    let Some((kind, level)) = tokens::with(token, |token| (token.kind, token.impersonation_level)) else { return Ok(0xC000_0008) };
    Ok(crate::ntos::se::audit::privileged_service_audit_alarm(&service_name, kind, level, count, granted))
}


/// NtCloseObjectAuditAlarm e NtDeleteObjectAuditAlarm(SubsystemName,
/// HandleId, GenerateOnClose): o SubsystemName sondado só com
/// GenerateOnClose; o alarme é `se::audit`.
fn object_audit_alarm(subsystem: u64, handle_id: u64, generate_on_close: u64, delete: bool) -> Result<u32, KernelError> {
    let generate = generate_on_close as u8 != 0;
    let privileged = generate && crate::ntos::se::privilege::audit_privilege_check(1);
    let name = if generate && privileged {
        if subsystem == 0 || !probe_user_read(subsystem, UnicodeString::SIZE) {
            return Ok(0xC000_0005);
        }
        crate::ntos::rtl::guest_strings::read_unicode_string(subsystem)
    } else {
        String::new()
    };
    Ok(crate::ntos::se::audit::close_object_audit_alarm(&name, handle_id, generate, privileged, delete))
}

/// NtAccessCheckAndAuditAlarm e NtAccessCheckByTypeAndAuditAlarm: o
/// SeAuditPrivilege do token primário (STATUS_PRIVILEGE_NOT_HELD), o
/// descritor, o GENERIC_MAPPING e as três saídas sondados, e a checagem de
/// `se::access_check` com o token de impersonação da thread.
#[allow(clippy::too_many_arguments)]
fn access_check_and_audit_alarm(descriptor: u64, desired: u32, mapping: u64, granted: u64, status: u64, generate: u64) -> Result<u32, KernelError> {
    if !crate::ntos::se::privilege::audit_privilege_check(1) {
        return Ok(0xC000_0061);
    }
    if !probe_user_read(mapping, 16) || !probe_user_write(granted, 4) || !probe_user_write(status, 4) || !probe_user_write(generate, 1) {
        return Ok(0xC000_0005);
    }
    let Some(impersonation) = thread_tokens::get(process::get_current_thread()) else { return Ok(0xC000_005C) };
    Ok(crate::ntos::se::access_check::check_and_audit_alarm(descriptor, impersonation.token, impersonation.level, desired, mapping, granted, status, generate))
}

/// NtAccessCheckAndAuditAlarm(SubsystemName, HandleId, ObjectTypeName,
/// ObjectName, SecurityDescriptor, DesiredAccess, GenericMapping,
/// ObjectCreation, GrantedAccess*, AccessStatus*, GenerateOnClose*).
fn nt_access_check_and_audit_alarm(_subsystem: u64, _handle_id: u64, _type_name: u64, _object_name: u64, rsp: u64) -> Result<u32, KernelError> {
    access_check_and_audit_alarm(stack_arg(rsp, 5), stack_arg(rsp, 6) as u32, stack_arg(rsp, 7), stack_arg(rsp, 9), stack_arg(rsp, 10), stack_arg(rsp, 11))
}

/// NtAccessCheckByTypeAndAuditAlarm(SubsystemName, HandleId,
/// ObjectTypeName, ObjectName, SecurityDescriptor, PrincipalSelfSid,
/// DesiredAccess, AuditType, Flags, ObjectTypeList, ObjectTypeListLength,
/// GenericMapping, ObjectCreation, GrantedAccess*, AccessStatus*,
/// GenerateOnClose*).
fn nt_access_check_by_type_and_audit_alarm(_subsystem: u64, _handle_id: u64, _type_name: u64, _object_name: u64, rsp: u64) -> Result<u32, KernelError> {
    access_check_and_audit_alarm(stack_arg(rsp, 5), stack_arg(rsp, 7) as u32, stack_arg(rsp, 12), stack_arg(rsp, 14), stack_arg(rsp, 15), stack_arg(rsp, 16))
}

fn nt_close_object_audit_alarm(subsystem: u64, handle_id: u64, generate_on_close: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    object_audit_alarm(subsystem, handle_id, generate_on_close, false)
}

fn nt_delete_object_audit_alarm(subsystem: u64, handle_id: u64, generate_on_close: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    object_audit_alarm(subsystem, handle_id, generate_on_close, true)
}

pub fn init() {
    state::register_handler("NtPrivilegedServiceAuditAlarm", nt_privileged_service_audit_alarm);
    state::register_handler("NtCloseObjectAuditAlarm", nt_close_object_audit_alarm);
    state::register_handler("NtAccessCheckAndAuditAlarm", nt_access_check_and_audit_alarm);
    state::register_handler("NtAccessCheckByTypeAndAuditAlarm", nt_access_check_by_type_and_audit_alarm);
    state::register_handler("NtDeleteObjectAuditAlarm", nt_delete_object_audit_alarm);
    state::register_handler("NtCreateToken", nt_create_token);
    state::register_handler("NtAccessCheck", nt_access_check);
    state::register_handler("NtSetInformationToken", nt_set_information_token);
    state::register_handler("NtCreateTokenEx", nt_create_token_ex);
    state::register_handler("NtAdjustPrivilegesToken", nt_adjust_privileges_token);
    state::register_handler("NtOpenProcessToken", nt_open_process_token);
    state::register_handler("NtOpenProcessTokenEx", nt_open_process_token_ex);
    state::register_handler("NtImpersonateAnonymousToken", nt_impersonate_anonymous_token);
    state::register_handler("NtImpersonateThread", nt_impersonate_thread);
    state::register_handler("NtDuplicateToken", nt_duplicate_token);
    state::register_handler("NtPrivilegeCheck", nt_privilege_check);
    state::register_handler("NtOpenThreadToken", nt_open_thread_token);
    state::register_handler("NtOpenThreadTokenEx", nt_open_thread_token_ex);
    state::register_handler("NtQueryInformationToken", nt_query_information_token);
    state::register_handler("NtAllocateLocallyUniqueId", nt_allocate_locally_unique_id);
    state::register_handler("NtQuerySecurityAttributesToken", nt_query_security_attributes_token);
}
