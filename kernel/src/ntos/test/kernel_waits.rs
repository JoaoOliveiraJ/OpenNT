//! Esperas de threads de kernel pelo despachante.
//!
//! Threads de sistema reais (PsCreateSystemThread), com o corpo chamando os
//! exports pelo trampolim, como um driver:
//!
//! - pingue-pongue por dois eventos de sincronização: a thread parada no
//!   KeWaitForSingleObject tem o KWAIT_BLOCK dela (WaitAny, ativo, o objeto e
//!   a thread) ligado à WaitListHead do evento, fica fora das prontas
//!   (Waiting) e não gasta um ciclo nem uma troca de contexto enquanto outra
//!   gira; o KeSetEvent a apronta na hora, consumindo o evento por ela, e as
//!   duas trocam as 64 rodadas;
//! - pingue-pongue por duas KQUEUE: a thread parada no KeRemoveQueue tem o
//!   bloco WaitDequeue na cabeça da WaitListHead da fila (WrQueue) e também
//!   não gasta CPU; o KeInsertQueue entrega a entrada direto a ela (a lista
//!   da fila fica vazia, SignalState 0, CurrentCount 1, KTHREAD.WaitStatus =
//!   a entrada) e as duas trocam as rodadas;
//! - um servidor ALPC de kernel e um cliente de kernel, cada um numa thread:
//!   o servidor cria a porta e espera a conexão, aceita, espera o pedido e
//!   responde; o cliente conecta e manda o pedido síncrono, e as duas
//!   esperas bloqueiam de fato até a outra thread agir;
//! - o mesmo par no LPC de modo kernel (o servidor de comandos do Reference
//!   Monitor): o servidor cria a porta pelo ZwCreatePort e recebe a conexão
//!   (com os dados de conexão do cliente) pelo ZwReplyWaitReceivePort, aceita
//!   com um PortContext, recebe o pedido com esse PortContext e responde na
//!   chamada seguinte; o cliente conecta pelo ZwSecureConnectPort (o
//!   MaxMessageLength 0x200 da porta) e manda o pedido síncrono;
//! - a resposta que é também um pedido (o protocolo do lsm.dll com o
//!   winsrvext do csrss): o servidor ALPC responde sem RELEASE_MESSAGE, o
//!   cliente a recebe como LPC_REQUEST com LPC_CONTINUATION_REQUIRED e a
//!   responde pelo MessageId dela, no buffer reaproveitado (Type 0 e o
//!   CLIENT_ID do servidor), com um pedido síncrono; o servidor recebe esse
//!   pedido e responde com RELEASE_MESSAGE, que chega como LPC_REPLY e não se
//!   responde mais;
//! - o tick que não aninha: um processo de kernel em execução que é dado como
//!   pronto continua em execução (não entra na fila), e a espera dele deixa a
//!   CPU sem girar o escalonador na pilha dele; ela vence pelo prazo com
//!   STATUS_TIMEOUT sem a thread gastar CPU, e o processo sai com o próprio
//!   código;
//! - duas consumidoras numa mesma fila, com as entregas vindas de fora: duas
//!   threads de sistema repetem o ZwRemoveIoCompletionEx numa porta de
//!   conclusão (e, na outra rodada, o KeRemoveQueueEx numa KQUEUE), e uma
//!   terceira publica dois pacotes por rodada e espera as duas confirmações.
//!   Cada pacote chega a uma consumidora já parada (Waiting, WrQueue, fora da
//!   CPU): ela sai da espera Ready, nunca Running, e nenhuma se perde nas 64
//!   rodadas.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::phase6::{call_export, kernel_handle_attributes, object_attributes_for, port_message_with, unicode_string_for};
use crate::ntos::alpc::lpc;
use crate::ntos::inc::types::{Kevent, Kqueue, Kthread, NtStruct, PortMessage};
use crate::ntos::ke::{clock, dispatcher, thread_dispatch, wait};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager;
use crate::ntos::ps::{kernel_threads, process, scheduler};

type Assert = fn(bool, &str);

const ROUNDS: u64 = 64;
/// O ponto de partida de uma thread de sistema, como um PKSTART_ROUTINE.
type StartRoutine = extern "win64" fn(u64);

fn kthread(thread: u64) -> &'static Kthread {
    // SAFETY: a KTHREAD de uma thread de sistema retida pelo teste.
    unsafe { Kthread::at(thread) }
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
fn start(routine: StartRoutine, block: u64) -> (u64, u64) {
    let handle = kernel_threads::create_system_thread(0, routine as usize as u64, block, 0x1F_FFFF, 0, None).unwrap_or(0);
    (handle, kernel_threads::of_handle(handle).unwrap_or(0))
}

/// Os ciclos e as trocas de contexto da thread.
fn usage(thread: u64) -> (u64, u64) {
    let cycles = thread_dispatch::query_total_cycle_time(thread, None);
    let switches = process::thread_record(thread).map_or(0, |record| record.context_switches as u64);
    (cycles, switches)
}

/// Gira o escalonador e o contexto de boot por `milliseconds` com a thread
/// parada; devolve se ela não gastou ciclo nem troca de contexto e seguiu
/// esperando.
fn stays_idle(thread: u64, milliseconds: u64) -> bool {
    let before = usage(thread);
    let deadline = clock::uptime_ms() + milliseconds;
    let mut spins = 0u64;
    while clock::uptime_ms() < deadline {
        scheduler::tick(-1);
        spins = spins.wrapping_add(1);
    }
    spins > 0 && usage(thread) == before && wait::is_waiting(thread) && thread_dispatch::thread_state(thread) == thread_dispatch::state::WAITING
}

// ---- pingue-pongue por eventos --------------------------------------------

/// [0] evento ping, [0x20] evento pong, [0x40] rodadas, [0x48] contador,
/// [0x50] o primeiro status diferente de zero.
extern "win64" fn event_ponger(block: u64) {
    let (ping, pong, rounds) = (block, block + 0x20, guest::read64(block + 0x40));
    for _ in 0..rounds {
        let status = call_export("KeWaitForSingleObject", &[ping, 0, 0, 0, 0]).unwrap_or(u64::MAX);
        if status != 0 {
            guest::write64(block + 0x50, status);
            return;
        }
        guest::write64(block + 0x48, guest::read64(block + 0x48) + 1);
        call_export("KeSetEvent", &[pong, 0, 0]);
    }
}

/// O pinger: os eventos são os do bloco do ponger ([0x58] o aponta).
extern "win64" fn event_pinger(block: u64) {
    let events = guest::read64(block + 0x58);
    let (ping, pong, rounds) = (events, events + 0x20, guest::read64(block + 0x40));
    for _ in 0..rounds {
        call_export("KeSetEvent", &[ping, 0, 0]);
        let status = call_export("KeWaitForSingleObject", &[pong, 0, 0, 0, 0]).unwrap_or(u64::MAX);
        if status != 0 {
            guest::write64(block + 0x50, status);
            return;
        }
        guest::write64(block + 0x48, guest::read64(block + 0x48) + 1);
    }
}

fn event_ping_pong(assert: Assert) {
    let (ponger_block, pinger_block) = (guest::alloc_bytes(0x80), guest::alloc_bytes(0x80));
    guest::write_bytes(ponger_block, &[0; 0x80]);
    guest::write_bytes(pinger_block, &[0; 0x80]);
    let (ping, pong) = (ponger_block, ponger_block + 0x20);
    dispatcher::initialize_event(ping, 1, false);
    dispatcher::initialize_event(pong, 1, false);
    guest::write64(ponger_block + 0x40, ROUNDS);
    let (ponger_handle, ponger) = start(event_ponger, ponger_block);
    let parked = ponger != 0 && pump(5000, &|| wait::is_waiting(ponger));
    // O bloco de espera real na KTHREAD e na WaitListHead do evento.
    let target = kthread(ponger);
    let block = &target.wait_block[0];
    // SAFETY: KEVENT do teste.
    let event = unsafe { Kevent::at(ping) };
    let linked = event.header.wait_list_head.flink.get() == block.address() && event.header.wait_list_head.blink.get() == block.address();
    assert(
        parked && target.state.get() == 5 && target.wait_reason.get() == wait::reason::EXECUTIVE && target.wait_block_count.get() == 1 && target.wait_block_list.get() == block.address() && block.wait_type.get() == wait::wait_type::ANY && block.block_state.get() == 4 && block.object.get() == ping && block.thread.get() == ponger && linked,
        "kwait: KeWaitForSingleObject de uma thread de sistema liga o KWAIT_BLOCK dela a WaitListHead do evento e a deixa Waiting",
    );
    assert(stays_idle(ponger, 60), "kwait: a thread parada no evento nao gasta ciclo nem troca de contexto enquanto o sistema gira");
    // O KeSetEvent a apronta na hora (sem tick), consumindo o evento por ela.
    let previous = dispatcher::set_event(ping);
    let readied = !wait::is_waiting(ponger) && thread_dispatch::thread_state(ponger) == thread_dispatch::state::READY && event.header.signal_state.get() == 0 && target.wait_status.get() == 0 && event.header.wait_list_head.flink.get() == event.header.wait_list_head.address();
    assert(previous == 0 && readied, "kwait: KeSetEvent tira a thread da espera e a poe na fila pronta, consumindo o evento de sincronizacao por ela");
    // A primeira resposta, e o pingue-pongue com a outra thread.
    let answered = pump(5000, &|| guest::read64(ponger_block + 0x48) == 1 && wait::is_waiting(ponger));
    let pong_seen = dispatcher::acquire_status(pong, true) == Some(0);
    // O pinger usa os eventos do ponger (o bloco dele os aponta).
    guest::write64(pinger_block + 0x40, ROUNDS - 1);
    guest::write64(pinger_block + 0x58, ponger_block);
    let (pinger_handle, pinger) = start(event_pinger, pinger_block);
    let finished = pinger != 0 && pump(20_000, &|| kernel_threads::is_terminated(ponger) && kernel_threads::is_terminated(pinger));
    assert(
        answered && pong_seen && finished && guest::read64(ponger_block + 0x48) == ROUNDS && guest::read64(pinger_block + 0x48) == ROUNDS - 1 && guest::read64(ponger_block + 0x50) == 0 && guest::read64(pinger_block + 0x50) == 0,
        "kwait: duas threads de sistema trocam 64 rodadas por dois eventos, cada espera pronta pelo KeSetEvent da outra",
    );
    for handle in [ponger_handle, pinger_handle] {
        let _ = object_manager::close(handle as u32);
    }
    guest::free_bytes(ponger_block);
    guest::free_bytes(pinger_block);
}

// ---- pingue-pongue por KQUEUE ---------------------------------------------

/// [0] fila A->B, [0x40] fila B->A, [0x80] rodadas, [0x88] contador,
/// [0x90] a primeira entrada inválida, [0x98] o bloco das filas (pinger),
/// [0x100..] as entradas (LIST_ENTRY de 16 bytes).
extern "win64" fn queue_ponger(block: u64) {
    let (inbound, outbound, rounds) = (block, block + 0x40, guest::read64(block + 0x80));
    for round in 0..rounds {
        let entry = call_export("KeRemoveQueue", &[inbound, 0, 0]).unwrap_or(0);
        if entry < block + 0x100 || entry >= block + 0x100 + 0x10 * 2 * ROUNDS {
            guest::write64(block + 0x90, entry | 1);
            return;
        }
        guest::write64(block + 0x88, guest::read64(block + 0x88) + 1);
        call_export("KeInsertQueue", &[outbound, block + 0x100 + 0x10 * (ROUNDS + round)]);
    }
}

extern "win64" fn queue_pinger(block: u64) {
    let queues = guest::read64(block + 0x98);
    let (outbound, inbound, rounds) = (queues, queues + 0x40, guest::read64(block + 0x80));
    for round in 0..rounds {
        call_export("KeInsertQueue", &[outbound, queues + 0x100 + 0x10 * (round + 1)]);
        let entry = call_export("KeRemoveQueue", &[inbound, 0, 0]).unwrap_or(0);
        if entry < queues + 0x100 || entry >= queues + 0x100 + 0x10 * 2 * ROUNDS {
            guest::write64(block + 0x90, entry | 1);
            return;
        }
        guest::write64(block + 0x88, guest::read64(block + 0x88) + 1);
    }
}

fn queue_ping_pong(assert: Assert) {
    let size = 0x100 + 0x10 * 2 * ROUNDS;
    let (ponger_block, pinger_block) = (guest::alloc_bytes(size), guest::alloc_bytes(0x100));
    guest::write_bytes(ponger_block, &alloc::vec![0; size as usize]);
    guest::write_bytes(pinger_block, &[0; 0x100]);
    let (inbound, outbound) = (ponger_block, ponger_block + 0x40);
    // Vagas folgadas: a entrega direta nunca esbarra no MaximumCount.
    call_export("KeInitializeQueue", &[inbound, 8]);
    call_export("KeInitializeQueue", &[outbound, 8]);
    guest::write64(ponger_block + 0x80, ROUNDS);
    let (ponger_handle, ponger) = start(queue_ponger, ponger_block);
    let parked = ponger != 0 && pump(5000, &|| wait::is_waiting(ponger));
    let target = kthread(ponger);
    let block = &target.wait_block[0];
    // SAFETY: KQUEUE do teste.
    let queue = unsafe { Kqueue::at(inbound) };
    assert(
        parked && target.state.get() == 5 && target.wait_reason.get() == wait::reason::WR_QUEUE && block.wait_type.get() == wait::wait_type::DEQUEUE && block.object.get() == inbound && queue.header.wait_list_head.flink.get() == block.address() && target.queue.get() == inbound && queue.current_count.get() == 0,
        "kwait: KeRemoveQueue de uma thread de sistema poe o bloco WaitDequeue na cabeca da WaitListHead da fila (WrQueue), com a vaga liberada",
    );
    assert(stays_idle(ponger, 60), "kwait: a thread parada na fila nao gasta ciclo nem troca de contexto enquanto o sistema gira");
    // O KeInsertQueue entrega a entrada direto à thread parada.
    let first = ponger_block + 0x100;
    let previous = call_export("KeInsertQueue", &[inbound, first]).unwrap_or(u64::MAX);
    let handed = previous == 0 && queue.header.signal_state.get() == 0 && queue.entry_list_head.flink.get() == queue.entry_list_head.address() && queue.current_count.get() == 1 && target.wait_status.get() as u64 == first && !wait::is_waiting(ponger) && thread_dispatch::thread_state(ponger) == thread_dispatch::state::READY;
    assert(handed, "kwait: KeInsertQueue entrega a entrada direto a thread parada na fila (lista vazia, SignalState 0, CurrentCount 1, WaitStatus = a entrada)");
    let answered = pump(5000, &|| guest::read64(ponger_block + 0x88) == 1 && wait::is_waiting(ponger));
    guest::write64(pinger_block + 0x80, ROUNDS - 1);
    guest::write64(pinger_block + 0x98, ponger_block);
    let (pinger_handle, pinger) = start(queue_pinger, pinger_block);
    let finished = pinger != 0 && pump(20_000, &|| kernel_threads::is_terminated(ponger) && kernel_threads::is_terminated(pinger));
    // SAFETY: KQUEUE do teste.
    let returned = unsafe { Kqueue::at(outbound) };
    assert(
        answered && finished && guest::read64(ponger_block + 0x88) == ROUNDS && guest::read64(pinger_block + 0x88) == ROUNDS - 1 && guest::read64(ponger_block + 0x90) == 0 && guest::read64(pinger_block + 0x90) == 0 && returned.header.signal_state.get() == 1,
        "kwait: duas threads de sistema trocam 64 rodadas por duas KQUEUE, cada entrada entregue pelo KeInsertQueue da outra",
    );
    for handle in [ponger_handle, pinger_handle] {
        let _ = object_manager::close(handle as u32);
    }
    guest::free_bytes(ponger_block);
    guest::free_bytes(pinger_block);
}

// ---- servidor e cliente ALPC de kernel ------------------------------------

/// O bloco do par ALPC: [0] porta do servidor, [8] porta de comunicação,
/// [0x10] comprimento da recepção do servidor, [0x18] comprimento do
/// cliente, [0x20] porta do cliente, [0x28] evento "servidor pronto" (0x18),
/// [0x40] ALPC_PORT_ATTRIBUTES, [0x100] recepção do servidor (0x200),
/// [0x300] resposta do servidor (0x100), [0x400] mensagem de conexão do
/// cliente (0x100), [0x500] pedido e resposta do cliente (0x200),
/// [0x700] OBJECT_ATTRIBUTES com o nome, [0x800] nome UNICODE_STRING do
/// cliente, [0x900] resultados (status por etapa; [10] e [11], as trocas de
/// contexto do servidor na espera da conexão e do cliente na do pedido).
const ALPC_PAIR_NAME: &str = "\\OpenNtAlpcPair";
const RESULTS: u64 = 0x900;
const PENDING_RESULT: u64 = 0xDEAD;

fn record(block: u64, index: u64, value: u64) {
    guest::write64(block + RESULTS + index * 8, value);
}

extern "win64" fn alpc_server(block: u64) {
    let (server_out, communication_out, length, attributes, receive, reply) = (block, block + 8, block + 0x10, block + 0x40, block + 0x100, block + 0x300);
    let object_attributes = object_attributes_for(block + 0x700, ALPC_PAIR_NAME, 0x200);
    let created = call_export("ZwAlpcCreatePort", &[server_out, object_attributes, attributes]).unwrap_or(u64::MAX);
    record(block, 0, created);
    call_export("KeSetEvent", &[block + 0x28, 0, 0]);
    if created != 0 {
        return;
    }
    let server = guest::read64(server_out);
    // A conexão: a recepção bloqueia até o cliente conectar (a thread sai da
    // CPU: as trocas de contexto dela sobem durante a espera).
    guest::write64(length, 0x200);
    let me = process::get_current_thread();
    let before = context_switches(me);
    let connection = call_export("ZwAlpcSendWaitReceivePort", &[server, 0, 0, 0, receive, length, 0, 0]).unwrap_or(u64::MAX);
    record(block, 10, context_switches(me).wrapping_sub(before));
    // SAFETY: PORT_MESSAGE recebido.
    let message = unsafe { PortMessage::at(receive) };
    record(block, 1, connection);
    record(block, 2, (message.u2.s2.type_.get() as u64 & 0xFF) << 32 | guest::read32(receive + 0x28) as u64);
    let unnamed = kernel_handle_attributes();
    let accepted = call_export("ZwAlpcAcceptConnectPort", &[communication_out, server, 0, unnamed, 0, 0xC0DE, receive, 0, 1]).unwrap_or(u64::MAX);
    record(block, 3, accepted);
    guest::free_bytes(unnamed);
    // O pedido: a recepção bloqueia até o cliente mandar.
    guest::write64(length, 0x200);
    let request = call_export("ZwAlpcSendWaitReceivePort", &[server, 0, 0, 0, receive, length, 0, 0]).unwrap_or(u64::MAX);
    record(block, 4, request);
    record(block, 5, (message.u2.s2.type_.get() as u64 & 0xFF) << 32 | guest::read32(receive + 0x28) as u64);
    // A resposta, pelo MessageId do pedido.
    port_message_with(reply, b"PONG");
    // SAFETY: PORT_MESSAGE montado acima.
    unsafe { PortMessage::at(reply) }.message_id.set(message.message_id.get());
    let communication = guest::read64(communication_out);
    let replied = call_export("ZwAlpcSendWaitReceivePort", &[communication, 0, reply, 0, 0, 0, 0, 0]).unwrap_or(u64::MAX);
    record(block, 6, replied);
}

extern "win64" fn alpc_client(block: u64) {
    let (client_out, length, attributes, connect, exchange) = (block + 0x20, block + 0x18, block + 0x40, block + 0x400, block + 0x500);
    // Espera o servidor criar a porta.
    let ready = call_export("KeWaitForSingleObject", &[block + 0x28, 0, 0, 0, 0]).unwrap_or(u64::MAX);
    if ready != 0 || guest::read64(block + RESULTS) != 0 {
        record(block, 7, ready | 0x1_0000_0000);
        return;
    }
    let name = guest::read64(block + 0x800);
    port_message_with(connect, b"HELO");
    guest::write64(length, 0x100);
    let connected = call_export("ZwAlpcConnectPort", &[client_out, name, 0, attributes, 0x2_0000, 0, connect, length, 0, 0, 0]).unwrap_or(u64::MAX);
    record(block, 7, connected);
    if connected != 0 {
        return;
    }
    let client = guest::read64(client_out);
    port_message_with(exchange, b"PING");
    guest::write64(length, 0x200);
    // O pedido síncrono: o cliente espera a resposta fora da CPU.
    let me = process::get_current_thread();
    let before = context_switches(me);
    let exchanged = call_export("ZwAlpcSendWaitReceivePort", &[client, 0x2_0000, exchange, 0, exchange, length, 0, 0]).unwrap_or(u64::MAX);
    record(block, 11, context_switches(me).wrapping_sub(before));
    record(block, 8, exchanged);
    record(block, 9, guest::read32(exchange + 0x28) as u64);
    call_export("ZwClose", &[client]);
}

fn alpc_kernel_pair(assert: Assert) {
    let block = guest::alloc_bytes(0xA00);
    guest::write_bytes(block, &alloc::vec![0; 0xA00]);
    for index in 0..12 {
        record(block, index, PENDING_RESULT);
    }
    dispatcher::initialize_event(block + 0x28, 0, false);
    // SAFETY: ALPC_PORT_ATTRIBUTES do teste.
    unsafe { crate::ntos::inc::types::AlpcPortAttributes::at(block + 0x40) }.max_message_length.set(0x200);
    let name = unicode_string_for(ALPC_PAIR_NAME);
    guest::write64(block + 0x800, name);
    let (server_handle, server) = start(alpc_server, block);
    let (client_handle, client) = start(alpc_client, block);
    // As esperas do servidor e do cliente bloqueiam de verdade: a thread que
    // espera sai da CPU (as trocas de contexto dela sobem na espera). Um
    // tick do escalonador pode levar a troca inteira, com outras threads de
    // sistema existentes: quem confere é cada thread, na própria espera.
    let finished = server != 0 && client != 0 && pump(20_000, &|| kernel_threads::is_terminated(server) && kernel_threads::is_terminated(client));
    let results: Vec<u64> = (0..12).map(|index| guest::read64(block + RESULTS + index * 8)).collect();
    let parked = results[10] != PENDING_RESULT && results[10] > 0 && results[11] != PENDING_RESULT && results[11] > 0;
    debug_print!("[kwait] par ALPC: {:x?}", results);
    let word = |bytes: &[u8; 4]| u32::from_le_bytes(*bytes) as u64;
    assert(
        finished && parked && results[0] == 0 && results[1] == 0 && results[2] == (10 << 32 | word(b"HELO")) && results[3] == 0 && results[4] == 0 && results[5] >> 32 == 1 && results[5] & 0xFFFF_FFFF == word(b"PING") && results[6] == 0 && results[7] == 0 && results[8] == 0 && results[9] == word(b"PONG"),
        "kwait: servidor ALPC de kernel e cliente de kernel em threads de sistema: conexao aceita, pedido e resposta, cada espera bloqueando ate a outra thread agir",
    );
    let _ = call_export("ZwClose", &[guest::read64(block + 8)]);
    let _ = call_export("ZwClose", &[guest::read64(block)]);
    for handle in [server_handle, client_handle] {
        let _ = object_manager::close(handle as u32);
    }
    guest::free_bytes(name);
    guest::free_bytes(block);
}

// ---- par LPC de kernel ----------------------------------------------------

/// A porta do par LPC; o bloco usa os mesmos campos do par ALPC.
const LPC_PAIR_NAME: &str = "\\OpenNtLpcPair";

extern "win64" fn lpc_server(block: u64) {
    let (server_out, communication_out, context, receive, reply) = (block, block + 8, block + 0x10, block + 0x100, block + 0x300);
    let object_attributes = object_attributes_for(block + 0x700, LPC_PAIR_NAME, 0x200);
    let created = lpc::create_port(server_out, object_attributes, 0x200).unwrap_or(u32::MAX);
    record(block, 0, created as u64);
    call_export("KeSetEvent", &[block + 0x28, 0, 0]);
    if created != 0 {
        return;
    }
    let server = guest::read64(server_out);
    // SAFETY: PORT_MESSAGE recebido.
    let message = unsafe { PortMessage::at(receive) };
    // A conexão: o ZwReplyWaitReceivePort bloqueia até o cliente conectar.
    let me = process::get_current_thread();
    let before = context_switches(me);
    let connection = lpc::reply_wait_receive_port(server, context, 0, receive).unwrap_or(u32::MAX);
    record(block, 10, context_switches(me).wrapping_sub(before));
    record(block, 1, connection as u64);
    record(block, 2, (message.u2.s2.type_.get() as u64 & 0xFF) << 32 | guest::read32(receive + 0x28) as u64);
    let accepted = lpc::accept_connect_port(communication_out, 0xC0DE, receive, true, 0, 0).unwrap_or(u32::MAX);
    record(block, 3, accepted as u64 | (lpc::complete_connect_port(guest::read64(communication_out)) as u64) << 32);
    // O pedido, com o PortContext da porta de comunicação.
    let request = lpc::reply_wait_receive_port(server, context, 0, receive).unwrap_or(u32::MAX);
    record(block, 4, request as u64);
    record(block, 5, (message.u2.s2.type_.get() as u64 & 0xFF) << 32 | guest::read32(receive + 0x28) as u64);
    record(block, 12, guest::read64(context));
    // A resposta vai na chamada seguinte, sem recepção.
    port_message_with(reply, b"PONG");
    // SAFETY: PORT_MESSAGE montado acima.
    unsafe { PortMessage::at(reply) }.message_id.set(message.message_id.get());
    let replied = lpc::reply_wait_receive_port(server, context, reply, 0).unwrap_or(u32::MAX);
    record(block, 6, replied as u64);
}

extern "win64" fn lpc_client(block: u64) {
    let (client_out, maximum, information, information_length, exchange, length) = (block + 0x20, block + 0x50, block + 0x58, block + 0x68, block + 0x500, block + 0x18);
    let ready = call_export("KeWaitForSingleObject", &[block + 0x28, 0, 0, 0, 0]).unwrap_or(u64::MAX);
    if ready != 0 || guest::read64(block + RESULTS) != 0 {
        record(block, 7, ready | 0x1_0000_0000);
        return;
    }
    let name = guest::read64(block + 0x800);
    guest::write_bytes(information, b"HELO");
    guest::write32(information_length, 4);
    let connected = lpc::secure_connect_port(client_out, name, 0, 0, 0, 0, maximum, information, information_length).unwrap_or(u32::MAX);
    record(block, 7, connected as u64 | (guest::read32(maximum) as u64) << 32);
    if connected != 0 {
        return;
    }
    let client = guest::read64(client_out);
    port_message_with(exchange, b"PING");
    guest::write64(length, 0x200);
    let me = process::get_current_thread();
    let before = context_switches(me);
    let exchanged = call_export("ZwAlpcSendWaitReceivePort", &[client, 0x2_0000, exchange, 0, exchange, length, 0, 0]).unwrap_or(u64::MAX);
    record(block, 11, context_switches(me).wrapping_sub(before));
    record(block, 8, exchanged);
    record(block, 9, guest::read32(exchange + 0x28) as u64);
    call_export("ZwClose", &[client]);
}

/// O lado servidor LPC de modo kernel (o do servidor de comandos do Reference
/// Monitor): ZwCreatePort, ZwReplyWaitReceivePort, ZwAcceptConnectPort e
/// ZwCompleteConnectPort numa thread de sistema, com um cliente de kernel
/// (ZwSecureConnectPort e o pedido síncrono) noutra.
fn lpc_kernel_pair(assert: Assert) {
    let block = guest::alloc_bytes(0xA00);
    guest::write_bytes(block, &alloc::vec![0; 0xA00]);
    for index in 0..13 {
        record(block, index, PENDING_RESULT);
    }
    dispatcher::initialize_event(block + 0x28, 0, false);
    let name = unicode_string_for(LPC_PAIR_NAME);
    guest::write64(block + 0x800, name);
    let (server_handle, server) = start(lpc_server, block);
    let (client_handle, client) = start(lpc_client, block);
    let finished = server != 0 && client != 0 && pump(20_000, &|| kernel_threads::is_terminated(server) && kernel_threads::is_terminated(client));
    let results: Vec<u64> = (0..13).map(|index| guest::read64(block + RESULTS + index * 8)).collect();
    let parked = results[10] != PENDING_RESULT && results[10] > 0 && results[11] != PENDING_RESULT && results[11] > 0;
    debug_print!("[kwait] par LPC: {:x?}", results);
    let word = |bytes: &[u8; 4]| u32::from_le_bytes(*bytes) as u64;
    assert(
        finished && parked && results[0] == 0 && results[1] == 0 && results[2] == (10 << 32 | word(b"HELO")) && results[3] == 0 && results[4] == 0 && results[5] == (1 << 32 | word(b"PING")) && results[12] == 0xC0DE && results[6] == 0 && results[7] == 0x200 << 32 && results[8] == 0 && results[9] == word(b"PONG"),
        "kwait: servidor LPC de kernel (ZwCreatePort, ZwReplyWaitReceivePort, ZwAcceptConnectPort) e cliente de kernel: conexao com dados, PortContext no pedido, resposta pela recepcao seguinte",
    );
    let _ = call_export("ZwClose", &[guest::read64(block + 8)]);
    let _ = call_export("ZwClose", &[guest::read64(block)]);
    for handle in [server_handle, client_handle] {
        let _ = object_manager::close(handle as u32);
    }
    guest::free_bytes(name);
    guest::free_bytes(block);
}

// ---- a resposta ALPC que é também um pedido --------------------------------

/// A porta do par; o bloco usa os mesmos campos do par ALPC. Resultados: [0]
/// criação, [1] conexão recebida, [2] aceitação, [3] o pedido recebido
/// (Type << 32 | dados), [4] a resposta sem RELEASE, [5] a resposta do
/// cliente recebida, [6] a resposta com RELEASE, [7] conexão do cliente,
/// [8] o primeiro pedido, [9] a primeira resposta (Type << 32 | dados), [10]
/// o pedido que responde, [11] a segunda resposta, [12] o reenvio do MessageId
/// da resposta com RELEASE.
const ALPC_ANSWER_NAME: &str = "\\OpenNtAlpcAnswer";

/// O Type (com os bits altos) e os quatro bytes de dados de um PORT_MESSAGE.
fn type_and_word(message: u64) -> u64 {
    (guest::read16(message + 4) as u64) << 32 | guest::read32(message + 0x28) as u64
}

extern "win64" fn alpc_answer_server(block: u64) {
    let (server_out, communication_out, length, attributes, receive, reply) = (block, block + 8, block + 0x10, block + 0x40, block + 0x100, block + 0x300);
    let object_attributes = object_attributes_for(block + 0x700, ALPC_ANSWER_NAME, 0x200);
    let created = call_export("ZwAlpcCreatePort", &[server_out, object_attributes, attributes]).unwrap_or(u64::MAX);
    record(block, 0, created);
    call_export("KeSetEvent", &[block + 0x28, 0, 0]);
    if created != 0 {
        return;
    }
    let server = guest::read64(server_out);
    let next = || {
        guest::write64(length, 0x200);
        call_export("ZwAlpcSendWaitReceivePort", &[server, 0, 0, 0, receive, length, 0, 0]).unwrap_or(u64::MAX)
    };
    // SAFETY: PORT_MESSAGE recebido.
    let message = unsafe { PortMessage::at(receive) };
    record(block, 1, next());
    let unnamed = kernel_handle_attributes();
    record(block, 2, call_export("ZwAlpcAcceptConnectPort", &[communication_out, server, 0, unnamed, 0, 0xC0DE, receive, 0, 1]).unwrap_or(u64::MAX));
    guest::free_bytes(unnamed);
    let communication = guest::read64(communication_out);
    let answer = |data: &[u8; 4], flags: u64| {
        port_message_with(reply, data);
        // SAFETY: PORT_MESSAGE montado acima.
        unsafe { PortMessage::at(reply) }.message_id.set(message.message_id.get());
        call_export("ZwAlpcSendWaitReceivePort", &[communication, flags, reply, 0, 0, 0, 0, 0]).unwrap_or(u64::MAX)
    };
    let request = next();
    record(block, 3, if request == 0 { type_and_word(receive) } else { request });
    record(block, 4, answer(b"PONG", 0));
    let answered = next();
    record(block, 5, if answered == 0 { type_and_word(receive) } else { answered });
    record(block, 6, answer(b"DONE", 0x1_0000));
}

extern "win64" fn alpc_answer_client(block: u64) {
    let (client_out, length, attributes, connect, exchange) = (block + 0x20, block + 0x18, block + 0x40, block + 0x400, block + 0x500);
    let ready = call_export("KeWaitForSingleObject", &[block + 0x28, 0, 0, 0, 0]).unwrap_or(u64::MAX);
    if ready != 0 || guest::read64(block + RESULTS) != 0 {
        record(block, 7, ready | 0x1_0000_0000);
        return;
    }
    let name = guest::read64(block + 0x800);
    port_message_with(connect, b"HELO");
    guest::write64(length, 0x100);
    let connected = call_export("ZwAlpcConnectPort", &[client_out, name, 0, attributes, 0x2_0000, 0, connect, length, 0, 0, 0]).unwrap_or(u64::MAX);
    record(block, 7, connected);
    if connected != 0 {
        return;
    }
    let client = guest::read64(client_out);
    let send = || {
        guest::write64(length, 0x200);
        call_export("ZwAlpcSendWaitReceivePort", &[client, 0x2_0000, exchange, 0, exchange, length, 0, 0]).unwrap_or(u64::MAX)
    };
    port_message_with(exchange, b"PING");
    record(block, 8, send());
    record(block, 9, type_and_word(exchange));
    // O buffer da resposta reaproveitado, como o gApiMsg do winsrvext: os
    // comprimentos e o Type 0 de novo, o MessageId e o CallbackId recebidos e
    // o CLIENT_ID da própria thread.
    let reuse = |data: &[u8; 4]| {
        guest::write64(exchange, 0x002C_0004);
        guest::write64(exchange + 8, process::get_current_process_id());
        guest::write64(exchange + 0x10, process::get_current_thread_id());
        guest::write_bytes(exchange + 0x28, data);
    };
    reuse(b"ACK1");
    record(block, 10, send());
    record(block, 11, type_and_word(exchange));
    reuse(b"ACK2");
    record(block, 12, send());
    call_export("ZwClose", &[client]);
}

fn alpc_answer_pair(assert: Assert) {
    let block = guest::alloc_bytes(0xA00);
    guest::write_bytes(block, &alloc::vec![0; 0xA00]);
    for index in 0..13 {
        record(block, index, PENDING_RESULT);
    }
    dispatcher::initialize_event(block + 0x28, 0, false);
    // SAFETY: ALPC_PORT_ATTRIBUTES do teste.
    unsafe { crate::ntos::inc::types::AlpcPortAttributes::at(block + 0x40) }.max_message_length.set(0x200);
    let name = unicode_string_for(ALPC_ANSWER_NAME);
    guest::write64(block + 0x800, name);
    let (server_handle, server) = start(alpc_answer_server, block);
    let (client_handle, client) = start(alpc_answer_client, block);
    let finished = server != 0 && client != 0 && pump(20_000, &|| kernel_threads::is_terminated(server) && kernel_threads::is_terminated(client));
    let results: Vec<u64> = (0..13).map(|index| guest::read64(block + RESULTS + index * 8)).collect();
    debug_print!("[kwait] resposta ALPC que e pedido: {:x?}", results);
    let word = |bytes: &[u8; 4]| u32::from_le_bytes(*bytes) as u64;
    let request = 0x2001 << 32;
    assert(
        finished && results[..3] == [0, 0, 0] && results[3] == request | word(b"PING") && results[4] == 0 && results[5] == request | word(b"ACK1") && results[6] == 0 && results[7] == 0 && results[8] == 0 && results[9] == request | word(b"PONG") && results[10] == 0 && results[11] == 2 << 32 | word(b"DONE") && results[12] as u32 == 0xC000_0702,
        "kwait: resposta ALPC sem RELEASE_MESSAGE chega como LPC_REQUEST com LPC_CONTINUATION_REQUIRED e o cliente a responde pelo MessageId, no buffer reaproveitado; a resposta com RELEASE_MESSAGE e LPC_REPLY e nao se responde",
    );
    let _ = call_export("ZwClose", &[guest::read64(block + 8)]);
    let _ = call_export("ZwClose", &[guest::read64(block)]);
    for handle in [server_handle, client_handle] {
        let _ = object_manager::close(handle as u32);
    }
    guest::free_bytes(name);
    guest::free_bytes(block);
}

// ---- o tick que não aninha ------------------------------------------------

/// [0] status da espera, [1] estado da thread depois de ser dada como
/// pronta em execução, [2] despachos da thread durante a espera, [3] pronto,
/// [4] a KTHREAD.
static NESTED: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];
const NESTED_EXIT: u32 = 0x5A;

fn context_switches(thread: u64) -> u64 {
    process::thread_record(thread).map_or(0, |record| record.context_switches as u64)
}

async fn nested_body() -> u32 {
    let me = process::get_current_thread();
    NESTED[4].store(me, Ordering::SeqCst);
    // Algo dá a thread em execução como pronta (o que punha o shell na
    // fila enquanto ele rodava): ela continua em execução, fora da fila.
    let _ = thread_dispatch::make_ready(me);
    NESTED[1].store(thread_dispatch::thread_state(me) as u64, Ordering::SeqCst);
    // Uma espera com prazo (o caminho de uma espera do NTFS): deixa a CPU.
    let event = guest::alloc_bytes(0x20);
    let timeout = guest::alloc_bytes(8);
    dispatcher::initialize_event(event, 0, false);
    guest::write64(timeout, (-500_000i64) as u64);
    let before = context_switches(me);
    let status = dispatcher::wait_for_single_object(event, timeout, 0, false);
    let after = context_switches(me);
    guest::free_bytes(event);
    guest::free_bytes(timeout);
    NESTED[0].store(status as u64, Ordering::SeqCst);
    NESTED[2].store(after.wrapping_sub(before), Ordering::SeqCst);
    NESTED[3].store(1, Ordering::SeqCst);
    NESTED_EXIT
}

/// A contabilidade da própria thread enquanto ela espera, vista de fora a
/// cada volta do despachante: quantas vezes estava Waiting e se o
/// KTHREAD.CycleTime ficou o mesmo em todas (nenhum ciclo cobrado dela
/// parada, qualquer que seja a carga do hospedeiro).
#[derive(Default)]
struct BlockedSamples {
    count: u64,
    first: u64,
    constant: bool,
}

impl BlockedSamples {
    fn sample(&mut self, thread: u64) {
        if thread == 0 || thread_dispatch::thread_state(thread) != thread_dispatch::state::WAITING {
            return;
        }
        let cycles = thread_dispatch::query_total_cycle_time(thread, None);
        if self.count == 0 {
            self.first = cycles;
            self.constant = true;
        } else if cycles != self.first {
            self.constant = false;
        }
        self.count += 1;
    }
}

fn nested_tick(assert: Assert) {
    for slot in &NESTED {
        slot.store(0, Ordering::SeqCst);
    }
    let pid = scheduler::spawn("kwait-nested", nested_body());
    let exit = core::cell::Cell::new(None);
    let blocked = core::cell::RefCell::new(BlockedSamples::default());
    let finished = pump(5000, &|| {
        if let Some(info) = scheduler::list().into_iter().find(|info| info.pid == pid) {
            exit.set(info.exit_status);
        }
        if NESTED[3].load(Ordering::SeqCst) == 0 {
            blocked.borrow_mut().sample(NESTED[4].load(Ordering::SeqCst));
        }
        NESTED[3].load(Ordering::SeqCst) == 1 && !scheduler::list().iter().any(|info| info.pid == pid)
    });
    // Parada pelo prazo de 50 ms, a thread não roda: nenhum ciclo cobrado
    // dela enquanto Waiting e um único despacho, o que a acorda (uma espera
    // que girasse o escalonador na pilha dela nunca ficaria Waiting, e uma
    // sondada seria despachada a cada tick).
    let blocked = blocked.into_inner();
    let dispatches = NESTED[2].load(Ordering::SeqCst);
    debug_print!("[kwait] tick aninhado: fim={} estado={} espera={:#x} amostras paradas={} ciclos constantes={} despachos={} saida={:?}", finished, NESTED[1].load(Ordering::SeqCst), NESTED[0].load(Ordering::SeqCst), blocked.count, blocked.constant, dispatches, exit.get());
    assert(
        finished && NESTED[1].load(Ordering::SeqCst) == thread_dispatch::state::RUNNING as u64 && NESTED[0].load(Ordering::SeqCst) == 0x102 && blocked.count > 0 && blocked.constant && dispatches == 1 && exit.get().is_none_or(|status| status == NESTED_EXIT),
        "kwait: um processo de kernel dado como pronto em execucao segue fora da fila, e a espera dele deixa a CPU sem tick aninhado, vencendo pelo prazo",
    );
}

// ---- duas consumidoras numa fila, entregas de fora --------------------------

/// O bloco das consumidoras: [0] handle da porta de conclusão, [0x20] o
/// KSEMAPHORE das confirmações, [0x40] rodadas, [0x80] a KQUEUE,
/// [SLOTS + i * SLOT] a área da consumidora i, [ENTRIES + 0x10 * n] as
/// entradas da KQUEUE (LIST_ENTRY), n de 1 a 2 * ROUNDS + 1 os dados e as
/// duas seguintes as de fim. Cada área: [0] o FILE_IO_COMPLETION_INFORMATION
/// (0x20), [0x20] o ULONG retirado ou a entrada retirada, [0x28] pacotes
/// recebidos, [0x30] o bloco, [0x38] o primeiro status inválido, [0x40] a
/// soma das chaves.
const SLOTS: u64 = 0x100;
const SLOT: u64 = 0x60;
const ENTRIES: u64 = 0x200;
/// A chave do pacote de fim (a consumidora sai).
const STOP_KEY: u64 = 0xFFFF_FFFF;
/// Pacotes de dados: um da partida (chave 1) e dois por rodada.
const PACKETS: u64 = 2 * ROUNDS + 1;

fn slot(block: u64, index: u64) -> u64 {
    block + SLOTS + index * SLOT
}

fn queue_entry(block: u64, number: u64) -> u64 {
    block + ENTRIES + 0x10 * number
}

/// Conta o pacote recebido e confirma pelo semáforo.
fn consumed(slot: u64, key: u64) {
    let block = guest::read64(slot + 0x30);
    guest::write64(slot + 0x28, guest::read64(slot + 0x28) + 1);
    guest::write64(slot + 0x40, guest::read64(slot + 0x40) + key);
    call_export("KeReleaseSemaphore", &[block + 0x20, 0, 1, 0]);
}

extern "win64" fn completion_consumer(slot: u64) {
    let port = guest::read64(guest::read64(slot + 0x30));
    loop {
        let status = call_export("ZwRemoveIoCompletionEx", &[port, slot, 1, slot + 0x20, 0, 0]).map_or(u32::MAX, |status| status as u32);
        if status != 0 || guest::read32(slot + 0x20) != 1 {
            guest::write64(slot + 0x38, status as u64 | 0x1_0000_0000);
            return;
        }
        // FILE_IO_COMPLETION_INFORMATION.KeyContext.
        let key = guest::read64(slot);
        if key == STOP_KEY {
            return;
        }
        consumed(slot, key);
    }
}

extern "win64" fn queue_consumer(slot: u64) {
    let block = guest::read64(slot + 0x30);
    loop {
        let removed = call_export("KeRemoveQueueEx", &[block + 0x80, 0, 0, 0, slot + 0x20, 1]).unwrap_or(0) as u32;
        let entry = guest::read64(slot + 0x20);
        let number = entry.wrapping_sub(block + ENTRIES) / 0x10;
        if removed != 1 || entry < queue_entry(block, 1) || number > PACKETS + 2 || entry & 0xF != 0 {
            guest::write64(slot + 0x38, entry | 1);
            return;
        }
        if number > PACKETS {
            return;
        }
        consumed(slot, number);
    }
}

/// A publicadora: dois pacotes por rodada (chaves 2 em diante), e espera as
/// duas confirmações antes da rodada seguinte; no fim, os dois de fim.
extern "win64" fn completion_poster(block: u64) {
    let (port, rounds) = (guest::read64(block), guest::read64(block + 0x40));
    for round in 0..rounds {
        for key in [2 + 2 * round, 3 + 2 * round] {
            call_export("ZwSetIoCompletionEx", &[port, 0, key, 0, 0, 0]);
        }
        for _ in 0..2 {
            call_export("KeWaitForSingleObject", &[block + 0x20, 0, 0, 0, 0]);
        }
    }
    for _ in 0..2 {
        call_export("ZwSetIoCompletionEx", &[port, 0, STOP_KEY, 0, 0, 0]);
    }
}

extern "win64" fn queue_poster(block: u64) {
    let rounds = guest::read64(block + 0x40);
    for round in 0..rounds {
        for number in [2 + 2 * round, 3 + 2 * round] {
            call_export("KeInsertQueue", &[block + 0x80, queue_entry(block, number)]);
        }
        for _ in 0..2 {
            call_export("KeWaitForSingleObject", &[block + 0x20, 0, 0, 0, 0]);
        }
    }
    for number in [PACKETS + 1, PACKETS + 2] {
        call_export("KeInsertQueue", &[block + 0x80, queue_entry(block, number)]);
    }
}

/// Uma rodada do teste: `completion` escolhe a porta de conclusão ou a
/// KQUEUE.
fn shared_queue_waiters(assert: Assert, completion: bool) {
    let what = if completion { "ZwRemoveIoCompletionEx" } else { "KeRemoveQueueEx" };
    let size = ENTRIES + 0x10 * (PACKETS + 3);
    let block = guest::alloc_bytes(size);
    guest::write_bytes(block, &alloc::vec![0; size as usize]);
    dispatcher::initialize_semaphore(block + 0x20, 0, 0x1000);
    guest::write64(block + 0x40, ROUNDS);
    let attributes = kernel_handle_attributes();
    let created = if completion { call_export("ZwCreateIoCompletion", &[block, 0x001F_0003, attributes, 2]) == Some(0) } else { call_export("KeInitializeQueue", &[block + 0x80, 2]).is_some() };
    let consumer = if completion { completion_consumer } else { queue_consumer };
    let mut threads = Vec::new();
    for index in 0..2 {
        guest::write64(slot(block, index) + 0x30, block);
        threads.push(start(consumer, slot(block, index)));
    }
    let consumers = [threads[0].1, threads[1].1];
    // As duas param fora da CPU: Waiting, WrQueue, sem espera pendente de
    // confirmação.
    let parked = created && consumers.iter().all(|&thread| thread != 0) && pump(5000, &|| consumers.iter().all(|&thread| wait::is_waiting(thread) && thread_dispatch::thread_state(thread) == thread_dispatch::state::WAITING));
    assert(parked && consumers.iter().all(|&thread| kthread(thread).wait_reason.get() == wait::reason::WR_QUEUE), if completion { "kwait: duas threads de sistema param no ZwRemoveIoCompletionEx da mesma porta (Waiting, WrQueue)" } else { "kwait: duas threads de sistema param no KeRemoveQueueEx da mesma KQUEUE (Waiting, WrQueue)" });
    // O primeiro pacote, publicado pelo contexto de boot: a consumidora que o
    // recebe sai da espera Ready (o KiReadyThread do KiUnwaitThread), e a
    // outra segue parada.
    let posted = if completion { call_export("ZwSetIoCompletionEx", &[guest::read64(block), 0, 1, 0, 0, 0]) == Some(0) } else { call_export("KeInsertQueue", &[block + 0x80, queue_entry(block, 1)]).is_some() };
    let woken: Vec<u64> = consumers.iter().copied().filter(|&thread| !wait::is_waiting(thread)).collect();
    let readied = posted && woken.len() == 1 && thread_dispatch::thread_state(woken[0]) == thread_dispatch::state::READY && consumers.iter().any(|&thread| wait::is_waiting(thread) && thread_dispatch::thread_state(thread) == thread_dispatch::state::WAITING);
    debug_print!("[kwait] {}: entrega a uma consumidora parada: acordadas={} estados={}/{}", what, woken.len(), thread_dispatch::thread_state(consumers[0]), thread_dispatch::thread_state(consumers[1]));
    assert(readied, if completion { "kwait: o pacote publicado na porta tira a consumidora parada da espera como Ready (nunca Running fora da CPU)" } else { "kwait: o KeInsertQueue tira a consumidora parada da espera como Ready" });
    // A confirmação do primeiro pacote, consumida aqui; então a publicadora.
    let acknowledged = pump(5000, &|| dispatcher::acquire_status(block + 0x20, false) == Some(0) && consumers.iter().all(|&thread| wait::is_waiting(thread)));
    let _ = dispatcher::acquire_status(block + 0x20, true);
    threads.push(start(if completion { completion_poster } else { queue_poster }, block));
    let all = [threads[0].1, threads[1].1, threads[2].1];
    let finished = acknowledged && all[2] != 0 && pump(20_000, &|| all.iter().all(|&thread| kernel_threads::is_terminated(thread)));
    let counts = [guest::read64(slot(block, 0) + 0x28), guest::read64(slot(block, 1) + 0x28)];
    let sums = guest::read64(slot(block, 0) + 0x40) + guest::read64(slot(block, 1) + 0x40);
    let errors = [guest::read64(slot(block, 0) + 0x38), guest::read64(slot(block, 1) + 0x38)];
    debug_print!("[kwait] {}: fim={} pacotes={:?} soma={:#x} erros={:x?} estados={}/{}/{}", what, finished, counts, sums, errors, thread_dispatch::thread_state(all[0]), thread_dispatch::thread_state(all[1]), thread_dispatch::thread_state(all[2]));
    assert(
        finished && counts[0] + counts[1] == PACKETS && counts[0] > 0 && counts[1] > 0 && sums == PACKETS * (PACKETS + 1) / 2 && errors == [0, 0],
        if completion { "kwait: duas consumidoras da porta de conclusao recebem os 129 pacotes publicados por outra thread, cada um entregue a uma consumidora parada, e nenhuma se perde" } else { "kwait: duas consumidoras da KQUEUE recebem as 129 entradas inseridas por outra thread, e nenhuma se perde" },
    );
    for (handle, _) in threads {
        let _ = object_manager::close(handle as u32);
    }
    guest::free_bytes(attributes);
    // Uma consumidora perdida ainda aponta para o bloco e para a porta: na
    // falha, os dois ficam.
    if !finished {
        return;
    }
    if completion {
        let _ = call_export("ZwClose", &[guest::read64(block)]);
    }
    guest::free_bytes(block);
}

pub fn run(assert: Assert) {
    event_ping_pong(assert);
    queue_ping_pong(assert);
    nested_tick(assert);
    alpc_kernel_pair(assert);
    lpc_kernel_pair(assert);
    alpc_answer_pair(assert);
    shared_queue_waiters(assert, true);
    shared_queue_waiters(assert, false);
}
