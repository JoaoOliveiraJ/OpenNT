//! Os comandos do Reference Monitor ao LSA: a fila do aviso de sessão de
//! logon apagada e o trabalhador SepRmCallLsa, como no ntoskrnl 19041.
//!
//! Quando o último token de uma sessão de logon sai, o
//! SepDeReferenceLogonSession (`se/logon_session.rs`) limpa a sessão e chama
//! o SepInformLsaOfDeletedLogon (rva 0x6f7da0,
//! [`inform_lsa_of_deleted_logon`]): um SEP_WORK_ITEM
//! (`inc/types/extra_obpsse.rs`) com o comando 3, os 8 bytes do LUID como
//! parâmetros imediatos (tipo 1), sem buffer de resposta e com o silo da
//! sessão, posto na fila SepLsaDeletedLogonQueueInfo. O NT reaproveita o
//! bloco da SEP_LOGON_SESSION_REFERENCES como item; as sessões do OpenNT não
//! são blocos de pool, então o item vem do outro caminho da mesma rotina: 0x40
//! bytes de PagedPool com a marca 'SeLw'. Sem pool, nenhum aviso; o item que
//! a fila recusa é liberado. O silo de servidor do item (a referência que a
//! sessão passa a ele e que o trabalhador solta) não aparece no OpenNT, que
//! só tem o silo hospedeiro.
//!
//! A fila ([`WorkQueue`], a SEP_WORK_QUEUE_INFO; o SepInitializeWorkList, rva
//! 0xa489fc, liga a da sessão apagada com a lista protegida pelo ERESOURCE,
//! sem filtro e com o ExFreePool como rotina de liberação dos itens):
//! - SepQueueWorkItem (rva 0x34d010, [`WorkQueue::queue`]): o item recebe o
//!   número de sequência seguinte (+0x34) e entra no fim da lista; quando a
//!   contagem de itens passa de 0 a 1, o WORK_QUEUE_ITEM da fila (o
//!   SepRmCallLsa com a fila como parâmetro) vai à DelayedWorkQueue. Depois
//!   que o LSA saiu (o evento de esvaziamento da fila posto,
//!   [`WorkQueue::drain`]) a fila recusa o item (FALSE).
//! - SepRmCallLsa (rva 0x34d310, o trabalhador): lê o SepRmAuditingEnabled
//!   (`se/audit.rs`) uma vez, no começo. Sem o AdtpRegisteredWithEtw (o
//!   SeRmInitPhase1 ainda não rodou), cria ou abre o `\ADT_ETW_CHANNEL_INIT`
//!   (SepAdtOpenEtwReadyEvent), espera nele (alertável, sem prazo) e fecha o
//!   handle; a falha da abertura ou da espera encerra o trabalhador com os
//!   itens na fila. Com a auditoria ligada, anexa ao SepRmLsaCallProcess (o
//!   processo da thread do servidor de comandos, dono do handle da conexão de
//!   volta). Depois tira os itens na ordem das sequências (a lista vazia
//!   sinaliza o evento de esvaziamento, se houver): cada item vai ao LSA pelo
//!   SepRmDispatchDataToLsa só com a auditoria ligada (sem ela, sai da fila
//!   sem envio), conta como processado, sai da contagem e é liberado; a
//!   contagem zerada encerra o trabalhador. A contagem sobe na inserção e
//!   desce depois do processamento, sob a mesma trava da lista, então o
//!   trabalhador nunca acha a lista vazia com a contagem acima de zero.
//! - SepRmDispatchDataToLsa (rva 0x34d558, [`dispatch_data_to_lsa`]): sem o
//!   LsaCommandPortHandle da SEP_RM_LSA_CONNECTION_STATE (o LSA ainda não
//!   conectou), nada e STATUS_SUCCESS. A LSA_COMMAND_MESSAGE de 0x200 bytes
//!   leva TotalLength = comprimento dos parâmetros + 0x30, DataLength =
//!   comprimento + 8, o CommandNumber em +0x28, o tipo de memória 1 em +0x2C
//!   e os parâmetros imediatos em +0x30 (acima de 0x1D0 bytes,
//!   STATUS_INVALID_PARAMETER sem envio). O comando 3 sem buffer de resposta
//!   vai como datagrama, ZwRequestPort no LsaCommandPortHandle
//!   (`alpc/lpc.rs`): no aviso de sessão apagada, TotalLength 0x38,
//!   DataLength 0x10 e o LUID em +0x30.
//!
//! Do lado do LSA, o LsapRmServerThread do lsass.exe recebe na
//! `\SeLsaCommandPort` os LPC_REQUEST e os LPC_DATAGRAM e os passa à extensão
//! do Reference Monitor do lsasrv.dll (LsapRmExtensionFunc), que despacha
//! pelo CommandNumber. O comando 3 (LsapAsyncWrkr) copia a mensagem e a põe
//! no pool de threads (QueueUserWorkItem; um datagrama fica sem resposta); o
//! LsapAsyncRmWorker chama o LsapLogonSessionDeletedWrkr, que apaga o LUID da
//! tabela de sessões de logon do LSA (o DeleteHandle da LogonSessionTable).
//! Com a última referência, a rotina de remoção da tabela
//! (LsapLogonSessionDelete) avisa os pacotes de segurança, o cofre de
//! credenciais e o DPAPI do fim da sessão e libera a sessão do LSA. Fora das
//! falhas do próprio logon (LsapDeleteLogonSession), o LSA só apaga uma
//! sessão por esse aviso: o logoff fecha os tokens, e o fim do último token
//! dispara a limpeza. Sem ele, toda sessão de logon cujo último token saiu
//! fica viva no LSA: a de cada logon de usuário depois do logoff e as das
//! contas virtuais DWM-n e UMFD-n de cada sessão (uma a mais a cada
//! reinício do dwm).
//!
//! Lacunas: só existe a fila da sessão apagada (os registros de auditoria do
//! SepAdtLogAuditRecord, com a SepLsaAuditQueueInfo e a lista de pool não
//! paginado, vão ao anel de `se/audit.rs`), então só há itens de tipo 1 e o
//! comando 3 sem resposta. Os outros tipos de memória (os blocos de pool 4 a
//! 6; a vista de 4 KB e a memória no processo do LSA dos parâmetros grandes)
//! e o ZwRequestWaitReplyPort dos comandos com resposta respondem
//! STATUS_NOT_SUPPORTED, com registro.

use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::alpc::lpc;
use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::types::extra_obpsse::{LsaCommandMessage, SepWorkItem};
use crate::ntos::inc::types::{KapcState, Kevent, NtStruct, SepRmLsaConnectionState, WorkQueueItem};
use crate::ntos::io::work_items;
use crate::ntos::ke::{dispatcher, process_attachment};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{close, wait};
use crate::ntos::se::{audit, reference_monitor};
use crate::rtl::{KernelError, SpinLock};

/// O comando 3 do Reference Monitor ao LSA: a sessão de logon apagada.
pub const LOGON_SESSION_DELETED_COMMAND: u32 = 3;
/// Os tipos de memória dos parâmetros: imediatos, no item e na mensagem.
const IMMEDIATE_MEMORY: u32 = 1;
/// O maior bloco de parâmetros imediatos de uma LSA_COMMAND_MESSAGE.
const MAXIMUM_IMMEDIATE_PARAMETERS: u32 = 0x1D0;
/// PagedPool e 'SeLw', a alocação do item do SepInformLsaOfDeletedLogon.
const PAGED_POOL: u32 = 1;
const DELETED_LOGON_TAG: u32 = u32::from_le_bytes(*b"SeLw");
/// NotificationEvent.
const NOTIFICATION_EVENT: u8 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;

/// O estado de uma SEP_WORK_QUEUE_INFO que o SepQueueWorkItem e o
/// SepRmCallLsa mudam sob o ERESOURCE dela.
struct QueueState {
    /// A lista (+0x00): os SEP_WORK_ITEM na ordem das sequências.
    items: VecDeque<u64>,
    /// +0xB0: os itens na lista e o que o trabalhador processa.
    queued: u32,
    /// +0xB4: o último número de sequência dado.
    last_sequence: u32,
    /// +0xB8: o número de sequência do último item processado.
    processed: u32,
    /// +0xC0: o KEVENT de esvaziamento, posto quando o LSA sai (0 antes).
    drain_event: u64,
}

/// Uma SEP_WORK_QUEUE_INFO de lista protegida, sem filtro, com o ExFreePool
/// como rotina de liberação dos itens.
pub struct WorkQueue {
    state: SpinLock<QueueState>,
    /// O WORK_QUEUE_ITEM (+0x90) do SepRmCallLsa, alocado no primeiro uso.
    work_item: AtomicU64,
}

/// As contagens de uma fila: (itens, última sequência dada, última
/// processada, esvaziada).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct QueueCounters {
    pub queued: u32,
    pub last_sequence: u32,
    pub processed: u32,
    pub draining: bool,
}

fn item_at(item: u64) -> &'static SepWorkItem {
    // SAFETY: um SEP_WORK_ITEM vivo, alocado por quem o pôs na fila.
    unsafe { SepWorkItem::at(item) }
}

impl WorkQueue {
    pub const fn new() -> Self {
        Self { state: SpinLock::new(QueueState { items: VecDeque::new(), queued: 0, last_sequence: 0, processed: 0, drain_event: 0 }), work_item: AtomicU64::new(0) }
    }

    /// SepQueueWorkItem: o item no fim da lista com a sequência seguinte; a
    /// passagem de 0 para 1 item põe o trabalhador na DelayedWorkQueue.
    /// `false` (o item fica com quem chamou) depois que o LSA saiu.
    pub fn queue(&'static self, item: u64) -> bool {
        let start = {
            let mut state = self.state.lock();
            if state.drain_event != 0 {
                return false;
            }
            state.last_sequence = state.last_sequence.wrapping_add(1);
            item_at(item).sequence_number.set(state.last_sequence);
            state.items.push_back(item);
            state.queued += 1;
            state.queued == 1
        };
        if start {
            self.start_worker();
        }
        true
    }

    /// O WORK_QUEUE_ITEM da fila com o SepRmCallLsa na DelayedWorkQueue.
    fn start_worker(&'static self) {
        let mut block = self.work_item.load(Ordering::Acquire);
        if block == 0 {
            let fresh = guest::alloc_bytes(WorkQueueItem::SIZE);
            if fresh == 0 {
                crate::debug_print!("[se] SepRmCallLsa: sem memoria para o WORK_QUEUE_ITEM; os itens ficam na fila");
                return;
            }
            guest::write_bytes(fresh, &[0u8; WorkQueueItem::SIZE as usize]);
            block = match self.work_item.compare_exchange(0, fresh, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => fresh,
                Err(existing) => {
                    guest::free_bytes(fresh);
                    existing
                }
            };
        }
        work_items::queue_kernel_ex_work_item(block, call_lsa, self as *const Self as u64);
    }

    /// O item seguinte do trabalhador: a cabeça da lista, se ela tem a
    /// sequência depois da última processada. A lista vazia sinaliza o evento
    /// de esvaziamento.
    fn take(&self) -> Option<u64> {
        let (item, drain_event) = {
            let mut state = self.state.lock();
            match state.items.front().copied() {
                None => (None, state.drain_event),
                Some(head) if item_at(head).sequence_number.get() == state.processed.wrapping_add(1) => {
                    state.items.pop_front();
                    (Some(head), 0)
                }
                Some(_) => (None, 0),
            }
        };
        if drain_event != 0 {
            dispatcher::set_event(drain_event);
        }
        item
    }

    /// O item processado: a sequência processada sobe e a contagem desce.
    /// Devolve os itens que restam.
    fn complete(&self) -> u32 {
        let mut state = self.state.lock();
        state.processed = state.processed.wrapping_add(1);
        state.queued = state.queued.saturating_sub(1);
        state.queued
    }

    /// O esvaziamento da fila quando o LSA sai (o LPC_PORT_CLOSED do
    /// SepRmCommandServerThread no silo hospedeiro): o evento de
    /// esvaziamento posto na fila, que passa a recusar itens, e a espera
    /// nele (KeWaitForSingleObject sem prazo) se a lista tem itens. Só o
    /// trabalhador que acha a lista vazia sinaliza o evento; como no 19041,
    /// numa fila só de lista protegida isso não ocorre enquanto há itens, e
    /// a espera com itens pendentes não volta (o fim do lsass, processo
    /// crítico, já para o sistema).
    pub fn drain(&self) {
        let event = guest::alloc_bytes(Kevent::SIZE);
        if event == 0 {
            return;
        }
        dispatcher::initialize_event(event, NOTIFICATION_EVENT, false);
        let pending = {
            let mut state = self.state.lock();
            if state.drain_event != 0 {
                drop(state);
                guest::free_bytes(event);
                return;
            }
            state.drain_event = event;
            !state.items.is_empty()
        };
        if pending {
            dispatcher::wait_for_single_object(event, 0, 0, false);
        }
    }

    /// As contagens da fila.
    pub fn counters(&self) -> QueueCounters {
        let state = self.state.lock();
        QueueCounters { queued: state.queued, last_sequence: state.last_sequence, processed: state.processed, draining: state.drain_event != 0 }
    }
}

impl Default for WorkQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// SepLsaDeletedLogonQueueInfo.
static DELETED_LOGON_QUEUE: WorkQueue = WorkQueue::new();

/// A fila do aviso de sessão de logon apagada.
pub fn deleted_logon_queue() -> &'static WorkQueue {
    &DELETED_LOGON_QUEUE
}

/// O SEP_WORK_ITEM do aviso de sessão apagada, num bloco de 0x40 bytes de
/// PagedPool ('SeLw'): o comando 3, o LUID como os 8 bytes de parâmetros
/// imediatos, sem resposta, e o silo. 0 sem pool.
pub fn deleted_logon_item(logon_id: u64, server_silo: u64) -> u64 {
    let item = pool_allocation::allocate_tagged(PAGED_POOL, SepWorkItem::SIZE, DELETED_LOGON_TAG).unwrap_or(0);
    if item == 0 {
        return 0;
    }
    let work = item_at(item);
    work.reply_buffer.set(0);
    work.reply_buffer_length.set(0);
    work.reserved.set(0);
    work.command_params.set(logon_id);
    work.command_number.set(LOGON_SESSION_DELETED_COMMAND);
    work.command_params_length.set(8);
    work.command_params_memory_type.set(IMMEDIATE_MEMORY);
    work.server_silo.set(server_silo);
    item
}

/// O item liberado (a rotina de liberação da fila, o ExFreePool).
pub fn free_item(item: u64) {
    let _ = pool_allocation::free(item, 0);
}

/// SepInformLsaOfDeletedLogon(LogonId, ServerSilo): o aviso na fila da sessão
/// apagada; o item recusado é liberado.
pub fn inform_lsa_of_deleted_logon(logon_id: u64, server_silo: u64) {
    let item = deleted_logon_item(logon_id, server_silo);
    if item != 0 && !DELETED_LOGON_QUEUE.queue(item) {
        free_item(item);
    }
}

/// A espera do SepRmCallLsa pelo registro da auditoria no ETW: o
/// `\ADT_ETW_CHANNEL_INIT` criado ou aberto, a espera alertável sem prazo e o
/// handle fechado. `false` se a abertura ou a espera falhou.
fn wait_for_etw_registration() -> bool {
    let (status, handle) = match audit::open_etw_ready_event() {
        Ok(opened) => opened,
        Err(error) => {
            crate::debug_print!("[se] SepRmCallLsa: {} nao aberto: {}", audit::ETW_READY_EVENT_NAME, error);
            return false;
        }
    };
    if status & 0x8000_0000 != 0 {
        crate::debug_print!("[se] SepRmCallLsa: {} -> {:#x}", audit::ETW_READY_EVENT_NAME, status);
        return false;
    }
    let waited = wait::wait_for_single_object(handle, true, 0) as u32;
    let _ = close::close(handle, Some(0));
    waited & 0x8000_0000 == 0
}

/// KiStackAttachProcess ao SepRmLsaCallProcess: o KAPC_STATE da anexação (0
/// sem o processo ou se a anexação falhou).
fn attach_to_lsa_call_process() -> u64 {
    let process = reference_monitor::lsa_call_process();
    if process == 0 {
        return 0;
    }
    let state = guest::alloc_bytes(KapcState::SIZE);
    if state == 0 {
        return 0;
    }
    guest::write_bytes(state, &[0u8; KapcState::SIZE as usize]);
    match process_attachment::attach(process, state) {
        Ok(_) => state,
        Err(error) => {
            crate::debug_print!("[se] SepRmCallLsa: anexacao ao processo {:#x}: {}", process, error);
            guest::free_bytes(state);
            0
        }
    }
}

/// SepRmCallLsa: o trabalhador da fila (o parâmetro é a WorkQueue).
fn call_lsa(_device: u64, parameter: u64) {
    // SAFETY: o Parameter do WORK_QUEUE_ITEM é a WorkQueue estática que o pôs
    // na fila (`start_worker`).
    let queue = unsafe { &*(parameter as *const WorkQueue) };
    let auditing = audit::auditing_enabled();
    if !audit::registered_with_etw() && !wait_for_etw_registration() {
        return;
    }
    let attached = if auditing { attach_to_lsa_call_process() } else { 0 };
    let mut remaining = 1;
    while remaining != 0 {
        let Some(item) = queue.take() else { continue };
        if auditing {
            let connection = reference_monitor::connection_state();
            let connected = connection.is_some_and(|state| state.lsa_command_port_handle.get() != 0);
            let work = item_at(item);
            let (command, logon_id) = (work.command_number.get(), work.command_params.get());
            match dispatch_data_to_lsa(item, connection) {
                Ok(status) if connected => crate::debug_print!("[se] SepRmCallLsa: comando {} ao LSA (LUID {:#x}) -> {:#x}", command, logon_id, status),
                Ok(_) => crate::debug_print!("[se] SepRmCallLsa: comando {} (LUID {:#x}) sem a conexao de volta do LSA, nada enviado", command, logon_id),
                Err(error) => crate::debug_print!("[se] SepRmCallLsa: comando {} ao LSA: {}", command, error),
            }
        }
        remaining = queue.complete();
        free_item(item);
    }
    if attached != 0 {
        if let Err(error) = process_attachment::detach(attached) {
            crate::debug_print!("[se] SepRmCallLsa: fim da anexacao: {}", error);
        }
        guest::free_bytes(attached);
    }
}

/// SepRmDispatchDataToLsa(WorkItem) na conexão dada (a do silo hospedeiro).
/// Devolve o NTSTATUS.
pub fn dispatch_data_to_lsa(item: u64, connection: Option<&SepRmLsaConnectionState>) -> Result<u32, KernelError> {
    let Some(port) = connection.map(|state| state.lsa_command_port_handle.get()).filter(|&port| port != 0) else { return Ok(0) };
    let work = item_at(item);
    let length = work.command_params_length.get();
    let block = guest::alloc_bytes(LsaCommandMessage::SIZE);
    if block == 0 {
        return Err(KernelError::new("SepRmDispatchDataToLsa: sem memoria"));
    }
    guest::write_bytes(block, &[0u8; LsaCommandMessage::SIZE as usize]);
    // SAFETY: bloco zerado do tamanho da mensagem.
    let message = unsafe { LsaCommandMessage::at(block) };
    message.message_header.u1.s1.total_length.set((length as u16).wrapping_add(0x30) as i16);
    message.message_header.u1.s1.data_length.set((length as u16).wrapping_add(8) as i16);
    message.command_number.set(work.command_number.get());
    let result = (|| -> Result<u32, KernelError> {
        let memory_type = work.command_params_memory_type.get();
        if memory_type != IMMEDIATE_MEMORY {
            crate::debug_print!("[se] SepRmDispatchDataToLsa: parametros de tipo {} sem suporte", memory_type);
            return Ok(STATUS_NOT_SUPPORTED);
        }
        message.command_params_memory_type.set(IMMEDIATE_MEMORY);
        if length > MAXIMUM_IMMEDIATE_PARAMETERS {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        // O memcpy dos parâmetros imediatos a partir de CommandParams.
        let bytes = guest::read_bytes(work.command_params.address(), length as usize);
        for (cell, byte) in message.command_params.iter().zip(bytes) {
            cell.set(byte);
        }
        if work.command_number.get() != LOGON_SESSION_DELETED_COMMAND || work.reply_buffer.get() != 0 {
            crate::debug_print!("[se] SepRmDispatchDataToLsa: comando {} com resposta (ZwRequestWaitReplyPort) sem suporte", work.command_number.get());
            return Ok(STATUS_NOT_SUPPORTED);
        }
        lpc::request_port_by_handle(port, block)
    })();
    guest::free_bytes(block);
    result
}
