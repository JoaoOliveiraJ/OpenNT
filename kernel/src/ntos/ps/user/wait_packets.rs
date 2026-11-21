//! Pacotes de espera.
//!
//! Uma associação de uso único consome um objeto esperável e publica os
//! contextos do chamador numa IOCP. As referências sobrevivem ao fechamento
//! dos handles originais.
//!
//! Como o bloco de notificação do KeRegisterObjectNotification do 19041 (um
//! KWAIT_BLOCK WaitNotification com a fila, na WaitListHead do objeto), o
//! pacote sobre um evento ou um semáforo vai para a fila dentro do próprio
//! sinal: o KeSetEvent, o KePulseEvent e a liberação do semáforo satisfazem
//! a associação no contexto de quem sinaliza (`ke::wait::signal` chama
//! [`object_signaled`]), então quem consulta a porta logo depois (com prazo
//! zero) já vê o pacote. Os demais objetos, e um sinal em DISPATCH_LEVEL ou
//! com um SpinLock retido, ficam com o pump do despachante, que também
//! sonda as associações pendentes a cada volta.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::io_completion;
use super::state::{self, probe_user_read, probe_user_write};
use super::threads::{self, pump};
use crate::ntos::ke::{dispatcher, irql};
use crate::ntos::ob::objects::completion::{self as completion_objects, Packet};
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::ob::objects::work::{self as work_objects, Association, Held, Queued, WaitPacket};
use crate::ntos::ob::{object_reference, open_pointer, reference_trace, wait as ob_wait};
use crate::rtl::{sync, KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{DispatcherHeader, NtStruct, ObjectAttributes};

/// Associações pendentes, na ordem de inserção, com o objeto de espera de
/// cada uma (o que o sinal procura).
static PENDING: SpinLock<Vec<(u64, Arc<WaitPacket>)>> = SpinLock::new(Vec::new());
/// Serializa a tomada do sinal de uma associação: o sinal, no contexto de
/// quem sinaliza, e o pump do despachante nunca entregam a mesma duas vezes.
static CLAIM: SpinLock<()> = SpinLock::new(());

fn forget(packet: &Arc<WaitPacket>) {
    PENDING.lock().retain(|(_, candidate)| !Arc::ptr_eq(candidate, packet));
}

fn resolve(handle: u64) -> Result<Arc<WaitPacket>, u32> {
    let Some(entry) = state::get_user_handle(handle) else { return Err(0xC000_0008) };
    if entry.kind() != "waitpacket" {
        return Err(0xC000_0024);
    }
    if entry.access() & 1 == 0 {
        return Err(0xC000_0022);
    }
    entry.downcast::<dispatcher_objects::UserDispatcher>().and_then(|dispatcher| work_objects::packet_of(dispatcher.pointer)).ok_or(0xC000_0008u32)
}

fn detach(packet: &Arc<WaitPacket>, remove_queued: bool) -> u32 {
    if let Some(association) = packet.association() {
        packet.set_association(None);
        forget(packet);
        release(&association.target);
        release(&association.port_entry);
        let _ = dispatcher_objects::dereference(packet.pointer);
        return 0;
    }
    if let Some(queued) = packet.queued() {
        if !remove_queued {
            return 0x103;
        }
        let item = queued.port.with(|state| state.packets.iter().position(|item| item.tag == packet.pointer).and_then(|index| state.packets.remove(index)));
        if let Some(on_dequeue) = item.and_then(|item| item.on_dequeue) {
            on_dequeue();
        }
        return 0;
    }
    0xC000_0120
}

fn nt_create_wait_completion_packet(out: u64, access: u64, attributes: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if !probe_user_write(out, 8) || (attributes != 0 && !probe_user_read(attributes, 48)) {
        return Ok(0xC000_0005);
    }
    // Pacotes de espera não têm nome.
    if attributes != 0 {
        match state::user_struct::<ObjectAttributes>(attributes).and_then(|object| object.object_name.probe_get()) {
            Ok(0) => {}
            Ok(_) => return Ok(0xC000_0033),
            Err(error) => return Ok(error.status),
        }
    }
    create(out, access as u32, attributes)
}

/// O núcleo do NtCreateWaitCompletionPacket (e do Zw, em modo kernel): o
/// pacote novo e o handle dele, na tabela do processo corrente, em `out`.
pub fn create(out: u64, access: u32, attributes: u64) -> Result<u32, KernelError> {
    let result = work_objects::packet(attributes, detach).and_then(|packet| work_objects::publish(packet.pointer, out, access, attributes, packet.clone()));
    match result {
        Ok(status) => Ok(status),
        Err(error) if error.status != 0 => Ok(error.status),
        Err(error) => Err(error),
    }
}

/// Entrega a associação se o objeto dela está sinalizado (consumindo o
/// sinal, como a espera de uma thread): o pacote vai para a fila da porta.
fn poll(packet: &Arc<WaitPacket>) -> bool {
    let association = {
        let claim = CLAIM.lock();
        let Some(association) = packet.association() else { return false };
        if association.port.closed() {
            drop(claim);
            detach(packet, true);
            return false;
        }
        let target = [association.target_pointer];
        if dispatcher::try_wait_objects(&target, 1).or_else(|| dispatcher::pulsed_since(&target, 1, association.pulses_since)).is_none() {
            return false;
        }
        // A associação sai do pacote sob o lock: só quem tomou o sinal o
        // entrega.
        packet.set_association(None);
        packet.set_queued(Some(Queued { port: association.port.clone() }));
        association
    };
    // O alarme das esperas satisfeitas em processos (`ob::wait`), com o alvo
    // ainda retido pela associação; só observa.
    ob_wait::check_packet_delivery(association.target_pointer);
    let pointer = packet.pointer;
    let _ = dispatcher_objects::reference(pointer);
    forget(packet);
    let port = association.port.clone();
    let (owner, port_entry) = (packet.clone(), association.port_entry.clone());
    let item = Packet {
        key: packet.key(),
        context: packet.context(),
        status: packet.status(),
        information: packet.information(),
        tag: pointer,
        on_dequeue: Some(Box::new(move || {
            if owner.queued().is_none() {
                return;
            }
            owner.set_queued(None);
            release(&port_entry);
            let _ = dispatcher_objects::dereference(owner.pointer);
        })),
        ..Packet::default()
    };
    completion_objects::enqueue(&port, item);
    release(&association.target);
    let _ = dispatcher_objects::dereference(pointer);
    true
}

/// NtAssociateWaitCompletionPacket(packet, port, target, key, context,
/// status, information, alreadySignaled*).
fn nt_associate_wait_completion_packet(handle: u64, port_handle: u64, target_handle: u64, _key: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 32) {
        return Ok(0xC000_0005);
    }
    let already = state::stack_arg(rsp, 8);
    let completion = (state::syscall_arg_words(rsp, 4), state::syscall_arg_words(rsp, 5), state::stack_arg32(rsp, 6), state::syscall_arg_words(rsp, 7));
    let signaled = match associate(handle, port_handle, target_handle, completion, 1) {
        Ok(signaled) => signaled,
        Err(status) => return Ok(status),
    };
    // BOOLEAN *AlreadySignaled, sondado só na gravação, depois da
    // associação, como no 19041.
    if already != 0 && (!probe_user_write(already, 1) || guest::try_write::<u8>(already, signaled as u8).is_err()) {
        return Ok(0xC000_0005);
    }
    Ok(0)
}

/// O núcleo do NtAssociateWaitCompletionPacket (e do Zw), na ordem do
/// 19041 (rva 0x2ed670): o pacote, a IOCP (IO_COMPLETION_MODIFY_STATE) e o
/// alvo (SYNCHRONIZE, de qualquer tipo). O alvo precisa de um objeto de
/// espera de verdade (ObpGetWaitObject, `ob::wait::wait_object_of`) que não
/// seja mutant nem fila, senão STATUS_INVALID_PARAMETER_3; um pacote já
/// associado ou na fila dá STATUS_INVALID_PARAMETER_1. A conclusão (chave,
/// contexto, status e informação) vai para a fila quando o objeto sinaliza.
/// Devolve se ele já estava sinalizado (o pacote foi para a fila na hora).
/// `previous_mode`: o do Nt (UserMode) ou do Zw (KernelMode), para o alvo
/// fora da tabela de usuário.
pub fn associate(handle: u64, port_handle: u64, target_handle: u64, completion: ([u32; 2], [u32; 2], u32, [u32; 2]), previous_mode: u8) -> Result<bool, u32> {
    let packet = resolve(handle)?;
    let (port_entry, port) = match state::get_user_handle(port_handle) {
        Some(_) => {
            let (entry, port) = io_completion::resolve(port_handle, IO_COMPLETION_MODIFY_STATE)?;
            (Held::Handle(entry), port)
        }
        None => {
            let pointer = reference_object(port_handle, IO_COMPLETION_MODIFY_STATE, previous_mode)?;
            match completion_objects::port_of(pointer) {
                Some(port) => (Held::Object(pointer), port),
                None => {
                    release(&Held::Object(pointer));
                    return Err(0xC000_0024);
                }
            }
        }
    };
    let target = match state::get_user_handle(target_handle) {
        Some(target) if target.access() & SYNCHRONIZE == 0 => Err(0xC000_0022),
        Some(target) => Ok((target.object.native_body().and_then(|body| ob_wait::wait_object_of(body.pointer, &body.type_name)), Held::Handle(target))),
        None => reference_object(target_handle, SYNCHRONIZE, previous_mode).map(|pointer| (open_pointer::type_name(pointer).and_then(|name| ob_wait::wait_object_of(pointer, &name)), Held::Object(pointer))),
    };
    let refusal = match &target {
        Err(status) => Some(*status),
        // Sem objeto de espera (ObpDefaultObject), ou um mutant ou fila.
        Ok((None, _)) => Some(STATUS_INVALID_PARAMETER_3),
        Ok((Some(wait), _)) if matches!(header_type(*wait), MUTANT_OBJECT | QUEUE_OBJECT) => Some(STATUS_INVALID_PARAMETER_3),
        Ok(_) if packet.association().is_some() || packet.queued().is_some() => Some(STATUS_INVALID_PARAMETER_1),
        Ok(_) => None,
    };
    if let Some(status) = refusal {
        if let Ok((_, held @ Held::Object(_))) = &target {
            release(held);
        }
        if let Held::Object(_) = port_entry {
            release(&port_entry);
        }
        return Err(status);
    }
    let Ok((Some(target_pointer), target)) = target else { return Err(STATUS_INVALID_PARAMETER_3) };
    packet.set_completion(completion.0, completion.1, completion.2, completion.3);
    for held in [&port_entry, &target] {
        if let Held::Handle(entry) = held {
            state::retain_user_handle_reference(entry);
        }
    }
    let _ = dispatcher_objects::reference(packet.pointer);
    packet.set_association(Some(Association { port_entry, port, target, target_pointer, pulses_since: dispatcher::pulse_clock() }));
    PENDING.lock().push((target_pointer, packet.clone()));
    Ok(poll(&packet))
}

/// STATUS_INVALID_PARAMETER_1 (pacote já associado ou na fila) e
/// STATUS_INVALID_PARAMETER_3 (alvo sem objeto de espera aceito).
const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
/// DISPATCHER_HEADER.Type que a associação recusa: MutantObject e
/// QueueObject.
const MUTANT_OBJECT: u8 = 2;
const QUEUE_OBJECT: u8 = 4;
/// DISPATCHER_HEADER.Type entregue dentro do sinal ([`object_signaled`]):
/// EventNotificationObject, EventSynchronizationObject e SemaphoreObject.
const EVENT_NOTIFICATION_OBJECT: u8 = 0;
const EVENT_SYNCHRONIZATION_OBJECT: u8 = 1;
const SEMAPHORE_OBJECT: u8 = 5;

/// O DISPATCHER_HEADER.Type (sem o bit alto) do objeto de espera.
fn header_type(wait: u64) -> u8 {
    // SAFETY: o objeto de espera de um corpo retido pela associação.
    unsafe { DispatcherHeader::at(wait) }.type_.get() & 0x7F
}

/// SYNCHRONIZE, o direito que o alvo de uma associação exige, e
/// IO_COMPLETION_MODIFY_STATE, o da IOCP.
const SYNCHRONIZE: u32 = 0x10_0000;
const IO_COMPLETION_MODIFY_STATE: u32 = 2;

/// Um objeto fora da tabela de usuário (um handle do Object Manager, de
/// kernel ou do processo corrente): ObReferenceObjectByHandle com `access`
/// no modo de quem chama. A referência fica com a associação.
fn reference_object(handle: u64, access: u32, previous_mode: u8) -> Result<u64, u32> {
    let slot = guest::alloc_bytes(8);
    let referenced = object_reference::reference_by_handle(handle, access, 0, previous_mode, slot, 0);
    let pointer = guest::read64(slot);
    guest::free_bytes(slot);
    let status = referenced.map_err(|error| if error.status != 0 { error.status } else { 0xC000_0008 })? as u32;
    if status & 0x8000_0000 != 0 {
        return Err(status);
    }
    Ok(pointer)
}

/// Solta um objeto retido por uma associação.
fn release(held: &Held) {
    match held {
        Held::Handle(entry) => {
            let _ = state::release_user_handle_reference(entry);
        }
        Held::Object(pointer) => {
            let _ = object_reference::dereference_with_tag(*pointer, reference_trace::DEFAULT_TAG, false);
        }
    }
}

/// O núcleo do NtCancelWaitCompletionPacket (e do Zw).
pub fn cancel(handle: u64, remove_signaled: bool) -> u32 {
    match resolve(handle) {
        Ok(packet) => detach(&packet, remove_signaled),
        Err(status) => status,
    }
}

fn nt_cancel_wait_completion_packet(handle: u64, remove: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(cancel(handle, state::boolean(remove)))
}

pub fn pump() {
    let pending: Vec<Arc<WaitPacket>> = PENDING.lock().iter().map(|(_, packet)| packet.clone()).collect();
    for packet in pending {
        poll(&packet);
    }
}

/// O sinal de `object` (o KiWaitTest dos blocos de notificação do
/// KeRegisterObjectNotification): as associações com esse objeto de espera
/// vão para a fila agora, na ordem em que foram feitas; um evento de
/// sincronização satisfaz só a primeira. Entram na hora os eventos e os
/// semáforos (o evento da fila de mensagens do win32k, o semáforo de uma
/// porta ALPC esperável), cujo sinal pode ser consumido ou desfeito logo
/// depois (KePulseEvent, KeClearEvent); timers, processos e threads ficam
/// sinalizados e seguem com o pump, fora do caminho do vencimento e do
/// término. Em DISPATCH_LEVEL ou acima, ou com um SpinLock retido, a
/// entrega também fica para o pump.
fn object_signaled(object: u64) {
    // SAFETY: o objeto de despacho que o chamador acabou de sinalizar.
    let kind = unsafe { DispatcherHeader::at(object) }.type_.get() & 0x7F;
    if !matches!(kind, EVENT_NOTIFICATION_OBJECT | EVENT_SYNCHRONIZATION_OBJECT | SEMAPHORE_OBJECT) {
        return;
    }
    if irql::get_irql() >= irql::DISPATCH_LEVEL || sync::spin_locks_held() != 0 {
        return;
    }
    let targets: Vec<Arc<WaitPacket>> = PENDING.lock().iter().filter(|(target, _)| *target == object).map(|(_, packet)| packet.clone()).collect();
    for packet in targets {
        poll(&packet);
    }
}

pub fn init() {
    crate::ntos::ke::wait::set_signal_observer(object_signaled);
    threads::set_pump(pump::WAIT_PACKETS, pump);
    state::register_handler("NtCreateWaitCompletionPacket", nt_create_wait_completion_packet);
    state::register_handler("NtAssociateWaitCompletionPacket", nt_associate_wait_completion_packet);
    state::register_handler("NtCancelWaitCompletionPacket", nt_cancel_wait_completion_packet);
}
