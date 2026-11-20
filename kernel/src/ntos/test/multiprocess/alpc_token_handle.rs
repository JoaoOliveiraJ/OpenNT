//! O token de uma mensagem ALPC duplicado num processo comum
//! (`alpc/message/handles.rs` duplicate, `se/token/handles.rs` insert_for),
//! o caminho da exposição na recepção e da classe 3 do
//! NtAlpcQueryInformationMessage:
//!
//! - um processo receptor real, dono de uma porta ALPC com DupObjectTypes
//!   0xFFD; o token primário do System entra na mensagem pela captura do
//!   ALPC_HANDLE_ATTR de um envio de kernel (um handle de kernel com
//!   TOKEN_QUERY);
//! - a duplicação no dono da porta dá um handle de usuário (sem o bit de
//!   kernel) do tipo Token (0x200) com o acesso pedido, na tabela de usuário
//!   do receptor como os handles de token dele: a procura do
//!   NtQueryInformationToken, anexada ao receptor, acha o mesmo token.
//!
//! No código anterior o token entrava como linha do Object Manager: o
//! NtClose a aceitava, mas o NtQueryInformationToken devolvia
//! STATUS_INVALID_HANDLE (o token do UMgrLogonUser no winlogon).

use alloc::boxed::Box;

use crate::ntos::alpc::message::handles as message_handles;
use crate::ntos::alpc::message::identity::Retained;
use crate::ntos::inc::types::{AlpcHandleAttr, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::ob::objects::port::{self as port_objects, CreateOptions, PortState, Role};
use crate::ntos::ps::user::{process_state, state, tokens as user_tokens};
use crate::ntos::ps::{cid, process, process_context};
use crate::ntos::se::token::handles as token_handles;

type Assert = fn(bool, &str);

/// TOKEN_QUERY.
const TOKEN_QUERY: u32 = 8;
/// O código ALPC do tipo Token.
const TOKEN_TYPE: u32 = 0x200;

pub fn run(assert: Assert) {
    let system = process::get_system_process();
    let Some(token) = process::get_primary_token(system) else {
        assert(false, "alpctoken: token primario do System");
        return;
    };
    let Ok(receiver) = process::create_process(cid::ALLOCATE, "alpc-token.exe", 0, None) else {
        assert(false, "alpctoken: processo receptor criado");
        return;
    };
    let port = port_objects::create("alpc", PortState { role: Role::Listener, duplicate_object_types: 0xFFD, ..PortState::default() }, 0x200, 0, 0, Box::new(|_| {}), CreateOptions { owner_process: Some(receiver), ..CreateOptions::default() });
    let source = token_handles::create(token, TOKEN_QUERY, 0x200, false);
    let attribute = guest::alloc_bytes(AlpcHandleAttr::SIZE);
    guest::write_bytes(attribute, &[0u8; AlpcHandleAttr::SIZE as usize]);
    let mut outcome = None;
    if let (Ok(port), Ok(source)) = (&port, &source) {
        // SAFETY: ALPC_HANDLE_ATTR do teste.
        let handle_attribute = unsafe { AlpcHandleAttr::at(attribute) };
        handle_attribute.handle.set(*source);
        handle_attribute.desired_access.set(TOKEN_QUERY);
        if let Ok(Ok(captured)) = message_handles::capture(attribute, 0) {
            let duplicated = captured.entries.lock().first().map(|entry| message_handles::duplicate(entry, port, 1));
            if let Some(Ok(Ok(duplicated))) = duplicated {
                let handle = duplicated.handle as u64;
                let table = process_state::get(receiver);
                let kind = table.as_ref().and_then(|table| state::get_user_handle_in(table, handle)).map(|entry| entry.kind());
                let found = process_context::with_process(receiver, || user_tokens::lookup(handle, TOKEN_QUERY)).ok();
                outcome = Some((duplicated.handle, duplicated.object_type, duplicated.granted, kind, found));
                if let Some(table) = &table {
                    let _ = process_context::with_process(receiver, || state::close_user_handle_in(table, handle, true, false));
                }
            }
            captured.release();
        }
    }
    assert(port.is_ok() && source.is_ok(), "alpctoken: porta do receptor e handle de kernel do token");
    assert(
        outcome.as_ref().is_some_and(|&(handle, object_type, granted, kind, found)| handle != 0 && handle & 0x8000_0000 == 0 && object_type == TOKEN_TYPE && granted == TOKEN_QUERY && kind == Some("token") && found == Some(Ok(token))),
        "alpctoken: o token da mensagem entra na tabela de usuario do receptor como handle de token, e a procura do NtQueryInformationToken acha o mesmo token",
    );
    if let Ok(source) = source {
        let _ = token_handles::close_native(source);
    }
    guest::free_bytes(attribute);
    if let Ok(port) = port {
        let pointer = port.pointer;
        drop(port);
        dispatcher_objects::collect(pointer);
    }
    let _ = process::terminate_process(receiver, 0);
}
