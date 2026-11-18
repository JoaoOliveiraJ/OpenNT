//! Autoteste do aviso de sessão de logon apagada ao LSA
//! (`se/lsa_call.rs`), sem o lsass.exe:
//!
//! - o datagrama do SepRmDispatchDataToLsa num par LPC de kernel em threads
//!   de sistema: um servidor no papel da `\SeLsaCommandPort` (ZwCreatePort,
//!   ZwReplyWaitReceivePort, ZwAcceptConnectPort) e o cliente no papel do
//!   Reference Monitor (ZwSecureConnectPort com o QOS da conexão de volta).
//!   Sem LsaCommandPortHandle nada vai e o status é STATUS_SUCCESS; acima de
//!   0x1D0 bytes de parâmetros, STATUS_INVALID_PARAMETER sem envio; o aviso
//!   chega como LPC_DATAGRAM com DataLength 0x10, TotalLength 0x38, o
//!   CommandNumber 3, o tipo de memória 1 e o LUID;
//! - a fila e o trabalhador numa fila própria do teste: antes do registro da
//!   auditoria no ETW (o autoteste roda antes do SeRmInitPhase1) o
//!   trabalhador espera no `\ADT_ETW_CHANNEL_INIT` com o item na fila; o
//!   SepAdtInitializeAuditingOptions o libera e, sem o SepRmAuditingEnabled,
//!   o item sai da fila sem envio; com a auditoria ligada e sem o LSA
//!   conectado, também; depois do esvaziamento (o LSA saiu) a fila recusa;
//! - a sessão de logon que sai com o último token põe o aviso na fila da
//!   sessão apagada; a que o LSA apaga (RmDeleteLogonSession) não.

use alloc::vec::Vec;

use super::phase6::{call_export, object_attributes_for, unicode_string_for};
use crate::ntos::alpc::lpc;
use crate::ntos::inc::types::{NtStruct, PortMessage, SecurityImpersonationLevel, SecurityQualityOfService, SepRmLsaConnectionState};
use crate::ntos::io::work_items;
use crate::ntos::ke::clock;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager;
use crate::ntos::ps::{kernel_threads, scheduler};
use crate::ntos::se::lsa_call::{self, QueueCounters, WorkQueue};
use crate::ntos::se::token::tokens;
use crate::ntos::se::{audit, logon_session};

type Assert = fn(bool, &str);

pub fn run(assert: Assert) {
    datagram(assert);
    queue_and_worker(assert);
    logon_session_notice(assert);
}

// ---- o datagrama no par LPC ---------------------------------------------------

/// A porta no papel da `\SeLsaCommandPort` do lsass.
const LSA_PORT_NAME: &str = "\\OpenNtSeLsaCommandTest";
/// O LUID do aviso do teste (HighPart não nulo).
const NOTICE_LUID: u64 = 0x0000_0003_8765_4321;
/// Os resultados, um u64 por índice, a partir deste deslocamento do bloco.
const RESULTS: u64 = 0x900;
const PENDING: u64 = 0xFFFF_FFFF_FFFF_FFFF;
const RESULT_COUNT: u64 = 12;
/// O evento "porta criada" do bloco.
const READY_EVENT: u64 = 0x28;
/// A SEP_RM_LSA_CONNECTION_STATE do teste.
const CONNECTION: u64 = 0x60;
/// O QOS da conexão de volta.
const QUALITY: u64 = 0x40;
/// O UNICODE_STRING do nome, para o cliente.
const NAME_POINTER: u64 = 0x800;

fn record(block: u64, index: u64, value: u64) {
    guest::write64(block + RESULTS + index * 8, value);
}

/// O servidor no papel do lsass: a conexão aceita e a mensagem seguinte.
/// Resultados: [0] criação, [1] recepção da conexão, [2] o Type dela, [3]
/// aceitação, [4] recepção seguinte, [5] Type | DataLength << 16 |
/// TotalLength << 32, [6] CommandNumber | tipo de memória << 32, [7] o LUID.
extern "win64" fn lsa_server(block: u64) {
    let (server_out, communication_out, context, receive) = (block, block + 8, block + 0x10, block + 0x100);
    let object_attributes = object_attributes_for(block + 0x700, LSA_PORT_NAME, 0x200);
    let created = lpc::create_port(server_out, object_attributes, 0x200).unwrap_or(u32::MAX);
    record(block, 0, created as u64);
    call_export("KeSetEvent", &[block + READY_EVENT, 0, 0]);
    if created != 0 {
        return;
    }
    let server = guest::read64(server_out);
    // SAFETY: o PORT_MESSAGE recebido no bloco do teste.
    let message = unsafe { PortMessage::at(receive) };
    let connection = lpc::reply_wait_receive_port(server, context, 0, receive).unwrap_or(u32::MAX);
    record(block, 1, connection as u64);
    record(block, 2, message.u2.s2.type_.get() as u64 & 0xFF);
    let accepted = lpc::accept_connect_port(communication_out, 0, receive, true, 0, 0).unwrap_or(u32::MAX);
    record(block, 3, accepted as u64);
    if connection != 0 || accepted != 0 {
        return;
    }
    let received = lpc::reply_wait_receive_port(server, context, 0, receive).unwrap_or(u32::MAX);
    record(block, 4, received as u64);
    let header = (message.u2.s2.type_.get() as u64 & 0xFF) | (message.u1.s1.data_length.get() as u16 as u64) << 16 | (message.u1.s1.total_length.get() as u16 as u64) << 32;
    record(block, 5, header);
    record(block, 6, guest::read64(receive + 0x28));
    record(block, 7, guest::read64(receive + 0x30));
}

/// O cliente no papel do Reference Monitor. Resultados: [8] conexão |
/// MaxMessageLength << 32, [9] o envio sem LsaCommandPortHandle, [10] o
/// envio com parâmetros acima de 0x1D0 bytes, [11] o aviso.
extern "win64" fn rm_client(block: u64) {
    let ready = call_export("KeWaitForSingleObject", &[block + READY_EVENT, 0, 0, 0, 0]).unwrap_or(u64::MAX);
    if ready != 0 || guest::read64(block + RESULTS) != 0 {
        record(block, 8, ready | 0x1_0000_0000);
        return;
    }
    // SAFETY: o QOS no bloco zerado do teste.
    let quality = unsafe { SecurityQualityOfService::at(block + QUALITY) };
    quality.impersonation_level.set(SecurityImpersonationLevel(2));
    quality.context_tracking_mode.set(1);
    quality.effective_only.set(1);
    let (client_out, maximum) = (block + 0x20, block + 0x50);
    let connected = lpc::secure_connect_port(client_out, guest::read64(block + NAME_POINTER), block + QUALITY, 0, 0, 0, maximum, 0, 0).unwrap_or(u32::MAX);
    record(block, 8, connected as u64 | (guest::read32(maximum) as u64) << 32);
    if connected != 0 {
        return;
    }
    let client = guest::read64(client_out);
    // SAFETY: a SEP_RM_LSA_CONNECTION_STATE no bloco zerado do teste.
    let connection = unsafe { SepRmLsaConnectionState::at(block + CONNECTION) };
    let item = lsa_call::deleted_logon_item(NOTICE_LUID, 0);
    let oversized = lsa_call::deleted_logon_item(NOTICE_LUID, 0);
    if item == 0 || oversized == 0 {
        call_export("ZwClose", &[client]);
        return;
    }
    // Sem a conexão de volta, nada vai.
    record(block, 9, lsa_call::dispatch_data_to_lsa(item, Some(connection)).map_or(PENDING - 1, |status| status as u64));
    connection.lsa_command_port_handle.set(client);
    // SAFETY: o item recém-alocado.
    unsafe { crate::ntos::inc::types::extra_obpsse::SepWorkItem::at(oversized) }.command_params_length.set(0x1D1);
    record(block, 10, lsa_call::dispatch_data_to_lsa(oversized, Some(connection)).map_or(PENDING - 1, |status| status as u64));
    record(block, 11, lsa_call::dispatch_data_to_lsa(item, Some(connection)).map_or(PENDING - 1, |status| status as u64));
    lsa_call::free_item(item);
    lsa_call::free_item(oversized);
    call_export("ZwClose", &[client]);
}

/// Roda o escalonador até `done` (com limite de tempo).
fn pump(milliseconds: u64, done: &dyn Fn() -> bool) -> bool {
    let deadline = clock::uptime_ms() + milliseconds;
    while clock::uptime_ms() < deadline {
        if done() {
            return true;
        }
        scheduler::tick(-1);
    }
    done()
}

/// Cria a thread de sistema e devolve (handle, KTHREAD).
fn start(routine: extern "win64" fn(u64), block: u64) -> (u64, u64) {
    let handle = kernel_threads::create_system_thread(0, routine as usize as u64, block, 0x1F_FFFF, 0, None).unwrap_or(0);
    (handle, kernel_threads::of_handle(handle).unwrap_or(0))
}

fn datagram(assert: Assert) {
    let block = guest::alloc_bytes(0xA00);
    guest::write_bytes(block, &alloc::vec![0u8; 0xA00]);
    for index in 0..RESULT_COUNT {
        record(block, index, PENDING);
    }
    call_export("KeInitializeEvent", &[block + READY_EVENT, 0, 0]);
    let name = unicode_string_for(LSA_PORT_NAME);
    guest::write64(block + NAME_POINTER, name);
    let (server_handle, server) = start(lsa_server, block);
    let (client_handle, client) = start(rm_client, block);
    let finished = server != 0 && client != 0 && pump(20_000, &|| kernel_threads::is_terminated(server) && kernel_threads::is_terminated(client));
    let results: Vec<u64> = (0..RESULT_COUNT).map(|index| guest::read64(block + RESULTS + index * 8)).collect();
    crate::debug_print!("[se] aviso ao LSA, par LPC: {:x?}", results);
    let connected = results[0] == 0 && results[1] == 0 && results[2] == 10 && results[3] == 0 && results[8] == 0x200 << 32;
    let refused = results[9] == 0 && results[10] == 0xC000_000D;
    let delivered = results[11] == 0 && results[4] == 0 && results[5] == (3 | 0x10 << 16 | 0x38 << 32) && results[6] == (3 | 1 << 32) && results[7] == NOTICE_LUID;
    assert(
        finished && connected && refused && delivered,
        "lsa-aviso: o SepRmDispatchDataToLsa manda o comando 3 como LPC_DATAGRAM (DataLength 0x10, TotalLength 0x38, tipo 1, o LUID) pelo ZwRequestPort na conexao de volta; sem ela nada vai, e acima de 0x1D0 bytes STATUS_INVALID_PARAMETER sem envio",
    );
    for opened in [guest::read64(block + 8), guest::read64(block)] {
        if opened != 0 {
            call_export("ZwClose", &[opened]);
        }
    }
    for handle in [server_handle, client_handle] {
        let _ = object_manager::close(handle as u32);
    }
    guest::free_bytes(name);
    guest::free_bytes(block);
}

// ---- a fila e o trabalhador --------------------------------------------------

/// Uma fila no molde da SepLsaDeletedLogonQueueInfo, só do teste.
static TEST_QUEUE: WorkQueue = WorkQueue::new();

fn queue_and_worker(assert: Assert) {
    let gated = !audit::registered_with_etw();
    // O autoteste do comando 7 (fase 6) já ligou o SepRmAuditingEnabled; a
    // primeira parte roda sem ele, como depois de a conexão do LSA fechar.
    let auditing_before = audit::auditing_enabled();
    audit::disable_auditing();
    let first = lsa_call::deleted_logon_item(0x7_0000_5E01, 0);
    let queued = first != 0 && TEST_QUEUE.queue(first);
    // O trabalhador roda até parar na espera do registro no ETW, ou até o
    // fim se o SeRmInitPhase1 já rodou.
    work_items::run_queue();
    let waiting = !gated || (object_manager::lookup(audit::ETW_READY_EVENT_NAME).is_some() && TEST_QUEUE.counters() == QueueCounters { queued: 1, last_sequence: 1, processed: 0, draining: false });
    let registered = audit::initialize_auditing_options().unwrap_or(u32::MAX);
    work_items::run_queue();
    let drained = TEST_QUEUE.counters() == QueueCounters { queued: 0, last_sequence: 1, processed: 1, draining: false };
    assert(
        queued && waiting && registered == 0 && audit::registered_with_etw() && drained,
        "lsa-aviso: antes do registro da auditoria no ETW o SepRmCallLsa espera no \\ADT_ETW_CHANNEL_INIT com o item na fila; o SepAdtInitializeAuditingOptions o libera e, sem o SepRmAuditingEnabled, o item sai sem envio",
    );
    // Com a auditoria ligada (o comando 7 liga o SepRmAuditingEnabled; a
    // auditoria da linha de comando fica como estava) e sem o LSA conectado,
    // o item também sai sem envio.
    let _ = audit::set_process_command_line_audit(audit::audit_process_command_line());
    let enabled = audit::auditing_enabled();
    let second = lsa_call::deleted_logon_item(0x7_0000_5E02, 0);
    let queued_enabled = second != 0 && TEST_QUEUE.queue(second);
    work_items::run_queue();
    let processed = TEST_QUEUE.counters() == QueueCounters { queued: 0, last_sequence: 2, processed: 2, draining: false };
    audit::disable_auditing();
    // O LSA saiu: o esvaziamento da fila vazia não espera, e ela passa a
    // recusar o item.
    TEST_QUEUE.drain();
    let third = lsa_call::deleted_logon_item(0x7_0000_5E03, 0);
    let refused = third != 0 && !TEST_QUEUE.queue(third);
    if third != 0 {
        lsa_call::free_item(third);
    }
    let after = TEST_QUEUE.counters();
    let disabled = !audit::auditing_enabled();
    if auditing_before {
        let _ = audit::set_process_command_line_audit(audit::audit_process_command_line());
    }
    assert(
        enabled && queued_enabled && processed && disabled && refused && after == QueueCounters { queued: 0, last_sequence: 2, processed: 2, draining: true },
        "lsa-aviso: com o SepRmAuditingEnabled e sem o LSA conectado o item sai da fila sem envio; esvaziada (o LSA saiu), a fila recusa o item",
    );
}

// ---- o gancho da sessão de logon ---------------------------------------------

fn system_token() -> u64 {
    crate::ntos::ps::process::get_primary_token(crate::ntos::ps::process::get_system_process()).unwrap_or(0)
}

fn logon_session_notice(assert: Assert) {
    let queue = lsa_call::deleted_logon_queue();
    let before = queue.counters();
    let logon = tokens::allocate_luid();
    let created = logon_session::create_track(logon);
    let token = tokens::create(Some(system_token()), Some(&|token: &mut tokens::Token| token.authentication_id = logon)).unwrap_or(0);
    let held = queue.counters().last_sequence == before.last_sequence;
    let _ = tokens::release(token);
    let gone = !logon_session::exists(logon, 0);
    let noticed = queue.counters().last_sequence == before.last_sequence.wrapping_add(1);
    // A sessão que o LSA apaga não volta a ele.
    let other = tokens::allocate_luid();
    let deleted = logon_session::create_track(other) == 0 && logon_session::delete_track(other) == 0;
    let quiet = queue.counters().last_sequence == before.last_sequence.wrapping_add(1);
    work_items::run_queue();
    let after = queue.counters();
    assert(
        created == 0 && token != 0 && held && gone && noticed && deleted && quiet && after.queued == 0 && after.processed == after.last_sequence && !after.draining,
        "lsa-aviso: a sessao de logon que sai com o ultimo token poe o aviso na fila da sessao apagada (o RmDeleteLogonSession do LSA nao), e o trabalhador a esvazia",
    );
}
