//! Consultas do OpenNT sobre objetos cujo estado vive nas coleções do
//! kernel, sem layout do NT na memória (`monitor obtypes`, `token`, `iocp`,
//! `waitpkt`, `alpc`). O cliente (`tools/opennt-kd`, `nt_objects.rs`) lê
//! pelos tipos do PDB o que está na memória (EPROCESS, ETHREAD, OBJECT_HEADER,
//! HANDLE_TABLE, WNF) e pede aqui o resto:
//!
//! - `obtypes`: o ObHeaderCookie e a ObTypeIndexTable (índice, OBJECT_TYPE,
//!   contagens e nome), com que o cliente decodifica o TypeIndex de um
//!   OBJECT_HEADER;
//! - `token <end>`: o registro do token (o corpo nativo do OpenNT só publica
//!   AuthenticationId, TokenId e TokenFlags): usuário, sessão, integridade,
//!   grupos e privilégios;
//! - `iocp <end>`: a porta de conclusão (o cabeçalho da KQUEUE e os pacotes,
//!   consumidores e threads associadas, que ficam fora da EntryListHead);
//! - `waitpkt <end>`: o pacote de espera (fase, alvo, porta e os dados de
//!   conclusão);
//! - `alpc <end>`: a porta ALPC/LPC (papel, conexão, fila do servidor,
//!   cliente ligado e as mensagens pendentes, a primeira é a do topo).
//!
//! As coleções ficam atrás de travas do kernel: como o `obj` e o `handles`,
//! as consultas só rodam quando nenhum processador parado tinha trava
//! (`stop::locks_held`); senão a resposta é `ocupado` e nada é lido. Nada
//! aqui aloca: o texto vai direto ao buffer do `qRcmd`, com as listas
//! cortadas e a contagem do que ficou de fora. Cada linha começa com uma
//! palavra fixa (`IOCP`, `PACOTE`, `MENSAGEM`...) e as colunas não mudam de
//! ordem: o cliente e os roteiros as leem.

use core::fmt::Write;
use core::mem::offset_of;

use super::packet::Payload;
use super::{handles, memory, stop};
use crate::ntos::alpc::server as alpc_server;
use crate::ntos::inc::types::{DispatcherHeader, Kqueue, ListEntry, ObjectHeader, ObjectType};
use crate::ntos::ob::object_types;
use crate::ntos::ob::objects::completion as completion_objects;
use crate::ntos::ob::objects::port as port_objects;
use crate::ntos::ob::objects::work::{self as work_objects, Held};
use crate::ntos::se::token::tokens;

/// Linhas de cada lista (pacotes, mensagens, grupos, privilégios).
const LIST_LINES: usize = 32;

const BUSY: &str = "ocupado: um processador parado tinha trava do kernel\n";

/// LUID.LowPart -> nome dos privilégios do 19041 (SE_*_PRIVILEGE).
const PRIVILEGES: [&str; 37] = [
    "",
    "",
    "SeCreateTokenPrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeLockMemoryPrivilege",
    "SeIncreaseQuotaPrivilege",
    "SeMachineAccountPrivilege",
    "SeTcbPrivilege",
    "SeSecurityPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege",
    "SeSystemProfilePrivilege",
    "SeSystemtimePrivilege",
    "SeProfileSingleProcessPrivilege",
    "SeIncreaseBasePriorityPrivilege",
    "SeCreatePagefilePrivilege",
    "SeCreatePermanentPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeShutdownPrivilege",
    "SeDebugPrivilege",
    "SeAuditPrivilege",
    "SeSystemEnvironmentPrivilege",
    "SeChangeNotifyPrivilege",
    "SeRemoteShutdownPrivilege",
    "SeUndockPrivilege",
    "SeSyncAgentPrivilege",
    "SeEnableDelegationPrivilege",
    "SeManageVolumePrivilege",
    "SeImpersonatePrivilege",
    "SeCreateGlobalPrivilege",
    "SeTrustedCredManAccessPrivilege",
    "SeRelabelPrivilege",
    "SeIncreaseWorkingSetPrivilege",
    "SeTimeZonePrivilege",
    "SeCreateSymbolicLinkPrivilege",
    "SeDelegateSessionUserImpersonatePrivilege",
];

fn read_u64(cr3: u64, address: u64) -> u64 {
    memory::read_u64(cr3, address).unwrap_or(0)
}

/// Um endereço do argumento (`0x...` ou hexadecimal sem prefixo).
fn parse_address(text: &str) -> Option<u64> {
    let text = text.trim();
    let digits = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text);
    let mut value = 0u64;
    let mut any = false;
    for character in digits.chars() {
        if character == '`' {
            continue;
        }
        value = value.checked_mul(16)?.checked_add(character.to_digit(16)? as u64)?;
        any = true;
    }
    (any && value != 0).then_some(value)
}

/// O texto `-` para zero; o endereço em hexadecimal para o resto.
fn push_pointer(out: &mut Payload, value: u64) {
    if value == 0 {
        out.push_str("-");
    } else {
        let _ = write!(out, "{:#x}", value);
    }
}

/// Um SID serializado (revision, count, autoridade big-endian,
/// subautoridades little-endian) no formato S-R-A-S1-S2...
fn push_sid(out: &mut Payload, sid: &[u8]) {
    if sid.len() < 8 {
        out.push_str("-");
        return;
    }
    let count = sid[1] as usize;
    let authority = sid[2..8].iter().fold(0u64, |value, &byte| (value << 8) | byte as u64);
    let _ = write!(out, "S-{}-{}", sid[0], authority);
    for index in 0..count {
        let at = 8 + index * 4;
        let Some(bytes) = sid.get(at..at + 4) else { break };
        let _ = write!(out, "-{}", u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    }
}

/// O OBJECT_TYPE de um corpo de objeto (o ObGetObjectType pela memória: o
/// TypeIndex do cabeçalho com o ObHeaderCookie e o byte 1 do endereço do
/// cabeçalho).
fn object_type_of(cr3: u64, body: u64) -> u64 {
    let header = body.wrapping_sub(offset_of!(ObjectHeader, body) as u64);
    let Some(encoded) = memory::read_u8(cr3, header + offset_of!(ObjectHeader, type_index) as u64) else { return 0 };
    object_types::type_at_index(encoded ^ object_types::header_cookie() ^ (header >> 8) as u8)
}

/// O nome do tipo de um corpo (`-` se o cabeçalho não decodifica).
fn push_type_name(cr3: u64, body: u64, out: &mut Payload) {
    let object_type = object_type_of(cr3, body);
    if object_type == 0 || !handles::push_unicode(cr3, object_type + offset_of!(ObjectType, name) as u64, 32, out) {
        out.push_str("-");
    }
}

/// `obtypes`: o cookie e cada entrada viva da ObTypeIndexTable.
fn object_type_table(cr3: u64, out: &mut Payload) {
    let _ = writeln!(out, "ObHeaderCookie {:#04x}", object_types::header_cookie());
    let _ = writeln!(out, "{:>6} {:>18} {:>8} {:>8} NOME", "INDICE", "OBJECT_TYPE", "OBJETOS", "HANDLES");
    for index in 1..=255u8 {
        let object_type = object_types::type_at_index(index);
        if object_type == 0 {
            continue;
        }
        let objects = memory::read_u32(cr3, object_type + offset_of!(ObjectType, total_number_of_objects) as u64).unwrap_or(0);
        let handles_open = memory::read_u32(cr3, object_type + offset_of!(ObjectType, total_number_of_handles) as u64).unwrap_or(0);
        let _ = write!(out, "{:>6} {:#018x} {:>8} {:>8} ", index, object_type, objects, handles_open);
        if !handles::push_unicode(cr3, object_type + offset_of!(ObjectType, name) as u64, 48, out) {
            out.push_str("-");
        }
        out.push(b'\n');
    }
}

/// `token <end>`: o registro vivo do token.
fn token(argument: &str, out: &mut Payload) {
    let Some(pointer) = parse_address(argument) else {
        out.push_str("uso: token <endereco do token>\n");
        return;
    };
    let found = tokens::with(pointer, |token| {
        let _ = writeln!(
            out,
            "TOKEN {:#x} id {:#x} modificado {:#x} pai {:#x} autenticacao {:#x} tipo {} nivel {} sessao {} refs {}",
            pointer,
            token.id,
            token.modified_id,
            token.parent_token_id,
            token.authentication_id,
            if token.kind == 2 { "impersonacao" } else { "primario" },
            token.impersonation_level,
            token.session_id,
            token.refs
        );
        out.push_str("usuario ");
        push_sid(out, &token.user);
        let _ = writeln!(out, " {:#010x}", token.user_attributes);
        out.push_str("integridade ");
        push_sid(out, &token.integrity);
        out.push(b'\n');
        out.push_str("appcontainer ");
        match &token.app_container {
            Some(sid) => push_sid(out, sid),
            None => out.push_str("-"),
        }
        out.push(b'\n');
        let _ = writeln!(out, "politica {:#x} restrito {} grupos {} privilegios {} capacidades {}", token.mandatory_policy, token.restricted_sids.len(), token.groups.len(), token.privileges.len(), token.capabilities.len());
        for (index, group) in token.groups.iter().enumerate().take(LIST_LINES) {
            let _ = write!(out, "GRUPO {} {:#010x} ", index, group.attributes);
            push_sid(out, &group.sid);
            out.push(b'\n');
        }
        if token.groups.len() > LIST_LINES {
            let _ = writeln!(out, "mais grupos: {}", token.groups.len() - LIST_LINES);
        }
        for privilege in token.privileges.iter().take(LIST_LINES) {
            let name = PRIVILEGES.get(privilege.id as usize).copied().filter(|name| !name.is_empty()).unwrap_or("?");
            let _ = writeln!(out, "PRIVILEGIO {} {:#010x} {}", privilege.id, privilege.attributes, name);
        }
        if token.privileges.len() > LIST_LINES {
            let _ = writeln!(out, "mais privilegios: {}", token.privileges.len() - LIST_LINES);
        }
    });
    if found.is_none() {
        let _ = writeln!(out, "{:#x}: nao e um token conhecido", pointer);
    }
}

/// `iocp <end>`: a porta de conclusão de E/S.
fn completion_port(cr3: u64, argument: &str, out: &mut Payload) {
    let Some(pointer) = parse_address(argument) else {
        out.push_str("uso: iocp <endereco do IoCompletion>\n");
        return;
    };
    let Some(port) = completion_objects::port_of(pointer) else {
        let _ = writeln!(out, "{:#x}: nao e uma porta de conclusao conhecida", pointer);
        return;
    };
    let header = pointer + offset_of!(Kqueue, header) as u64;
    let signal_state = memory::read_u32(cr3, header + offset_of!(DispatcherHeader, signal_state) as u64).unwrap_or(0) as i32;
    let current = memory::read_u32(cr3, pointer + offset_of!(Kqueue, current_count) as u64).unwrap_or(0);
    let maximum = memory::read_u32(cr3, pointer + offset_of!(Kqueue, maximum_count) as u64).unwrap_or(0);
    let entry_head = pointer + offset_of!(Kqueue, entry_list_head) as u64;
    let entry_first = read_u64(cr3, entry_head + offset_of!(ListEntry, flink) as u64);
    let _ = write!(out, "IOCP {:#x} fechada {} concorrencia {} processo-exclusivo ", pointer, port.closed() as u8, port.concurrency());
    push_pointer(out, port.exclusive_process.load(core::sync::atomic::Ordering::Acquire));
    out.push_str(" nome ");
    {
        let name = port.name.lock();
        if name.is_empty() {
            out.push_str("-");
        } else {
            for byte in name.bytes().take(96) {
                out.push(if (0x20..0x7F).contains(&byte) { byte } else { b'?' });
            }
        }
    }
    out.push(b'\n');
    let _ = writeln!(out, "KQUEUE SignalState {} CurrentCount {} MaximumCount {} EntryListHead {}", signal_state, current, maximum, if entry_first == entry_head || entry_first == 0 { "vazia" } else { "com-entradas" });
    // As coleções são a verdade da porta; o `inspect` só lê (o `with`
    // republicaria na KQUEUE e testaria as esperas com a máquina parada).
    port.inspect(|state| {
        let _ = writeln!(out, "pacotes {} ativas {} esperando {} associadas {}", state.packets.len(), state.active.len(), state.waiters.len(), state.associated.len());
        for (index, packet) in state.packets.iter().enumerate().take(LIST_LINES) {
            let (key, context, status, information) = packet.values();
            let _ = write!(out, "PACOTE {} chave {:#x} contexto {:#x} status {:#010x} info {:#x} memoria ", index, key, context, status, information);
            push_pointer(out, packet.native_pointer);
            out.push_str(" pacote-espera ");
            push_pointer(out, packet.tag);
            out.push(b'\n');
        }
        if state.packets.len() > LIST_LINES {
            let _ = writeln!(out, "mais pacotes: {}", state.packets.len() - LIST_LINES);
        }
        for thread in state.active.iter().take(LIST_LINES) {
            let _ = writeln!(out, "ATIVA {:#x}", thread);
        }
        for waiter in state.waiters.iter().take(LIST_LINES) {
            out.push_str("ESPERA ");
            push_pointer(out, waiter.thread.unwrap_or(0));
            out.push(b'\n');
        }
        for thread in state.associated.iter().take(LIST_LINES) {
            let _ = writeln!(out, "ASSOCIADA {:#x}", thread);
        }
    });
}

fn held_kind(held: &Held) -> &'static str {
    match held {
        Held::Handle(handle) => handle.kind(),
        Held::Object(_) => "objeto",
    }
}

/// `waitpkt <end>`: o pacote de espera (NtCreateWaitCompletionPacket).
fn wait_packet(cr3: u64, argument: &str, out: &mut Payload) {
    let Some(pointer) = parse_address(argument) else {
        out.push_str("uso: waitpkt <endereco do WaitCompletionPacket>\n");
        return;
    };
    let Some(packet) = work_objects::packet_of(pointer) else {
        let _ = writeln!(out, "{:#x}: nao e um pacote de espera conhecido", pointer);
        return;
    };
    let association = packet.association();
    let queued = packet.queued();
    let phase = if association.is_some() {
        "associado"
    } else if queued.is_some() {
        "enfileirado"
    } else {
        "livre"
    };
    let _ = writeln!(out, "WAITPKT {:#x} fase {} fechado {}", pointer, phase, packet.closed() as u8);
    let _ = writeln!(out, "conclusao chave {:#x} contexto {:#x} status {:#010x} info {:#x}", packet.key(), packet.context(), packet.status(), packet.information());
    if let Some(association) = association {
        let _ = write!(out, "alvo {:#x} tipo ", association.target_pointer);
        push_type_name(cr3, association.target_pointer, out);
        let _ = writeln!(out, " retido {}", held_kind(&association.target));
        let _ = writeln!(out, "porta {:#x} retida {} pulsos {}", association.port.pointer, held_kind(&association.port_entry), association.pulses_since);
    }
    if let Some(queued) = queued {
        let _ = writeln!(out, "porta {:#x} (o pacote esta na fila dela)", queued.port.pointer);
    }
}

/// `alpc <end>`: a porta ALPC ou LPC.
fn alpc_port(argument: &str, out: &mut Payload) {
    let Some(pointer) = parse_address(argument) else {
        out.push_str("uso: alpc <endereco da porta>\n");
        return;
    };
    let Some(port) = port_objects::port_of(pointer) else {
        let _ = writeln!(out, "{:#x}: nao e uma porta ALPC conhecida", pointer);
        return;
    };
    let _ = writeln!(out, "ALPC {:#x} tipo {} fechada {} handles {} PID {} TID {} processo {:#x}", pointer, port.kind, port.closed() as u8, port.handles(), port.process_id(), port.thread_id(), port.process_pointer);
    port.inspect(|state| {
        let _ = writeln!(
            out,
            "papel {:?} conexao {} fechando {} par-desconectado {} flags {:#x} criacao {:#x} sequencia {} maximo {}",
            state.role,
            state.connection_state,
            state.closing as u8,
            state.peer_disconnected as u8,
            state.port_flags,
            state.creation_flags,
            state.message_sequence,
            port.maximum()
        );
        out.push_str("porta-de-conexao ");
        push_pointer(out, state.connection_port.as_ref().map_or(0, |connection| connection.pointer));
        out.push(b'\n');
        let _ = writeln!(out, "servico processo {:#x} contexto {:#x} PortContext {:#x}", state.service_process, state.context, state.port_context);
        out.push_str("conclusao ");
        push_pointer(out, state.completion.as_ref().map_or(0, |completion| completion.port_pointer()));
        let _ = writeln!(out, " chave {:#x} semaforo {:#x}", port.completion_key(), port.wait_object());
        let _ = writeln!(out, "pendentes {} jobs {}", state.pending.len(), state.jobs.len());
        for (index, message) in state.pending.iter().enumerate().take(LIST_LINES) {
            let (process, thread) = message.sender.map_or((0, 0), |sender| (sender.process, sender.thread));
            let bytes = message.bytes.as_deref().unwrap_or(&[]);
            let _ = write!(out, "MENSAGEM {} id {} seq {} contexto {:#x} status {:#010x} PID {} TID {} sync {} bytes {}", index, message.id, message.sequence, message.context, message.status, process, thread, message.synchronous as u8, bytes.len());
            // O PORT_MESSAGE no começo dos bytes: DataLength, TotalLength e Type.
            if bytes.len() >= 0x28 {
                let word = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
                let _ = write!(out, " tipo {:#06x} DataLength {} TotalLength {}", word(4), word(0), word(2));
            }
            out.push(b'\n');
        }
        if state.pending.len() > LIST_LINES {
            let _ = writeln!(out, "mais mensagens: {}", state.pending.len() - LIST_LINES);
        }
    });
    // A fila do servidor e o cliente ligado ficam no servidor da porta (fora
    // da trava da porta).
    let _ = writeln!(out, "fila-do-servidor {}", alpc_server::queued_messages(&port));
    out.push_str("cliente-conectado ");
    push_pointer(out, alpc_server::connected_client(&port).map_or(0, |client| client.pointer));
    out.push(b'\n');
}

/// Executa `obtypes`, `token`, `iocp`, `waitpkt` ou `alpc`.
pub fn run(owner: usize, command: &str, argument: &str, out: &mut Payload) {
    if stop::locks_held() {
        out.push_str(BUSY);
        return;
    }
    let cr3 = stop::address_space(owner);
    match command {
        "obtypes" => object_type_table(cr3, out),
        "token" => token(argument, out),
        "iocp" => completion_port(cr3, argument, out),
        "waitpkt" => wait_packet(cr3, argument, out),
        "alpc" => alpc_port(argument, out),
        _ => out.push_str("uso: obtypes | token <end> | iocp <end> | waitpkt <end> | alpc <end>\n"),
    }
}
