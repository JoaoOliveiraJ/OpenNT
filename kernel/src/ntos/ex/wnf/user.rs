//! Entradas WNF de modo usuário — `system32/ntos/ex/{wnf-query-user,
//! wnf-subscribe-user,wnf-process-event}.js`.
//!
//! A captura de NtQueryWnfStateData compartilha namespace, referências,
//! locks e dados com a consulta Zw; a inscrição sonda e zera a saída antes do
//! nome; o evento de processo fica registrado no contexto WNF do processo.

use crate::ntos::ex::wnf::name::{self as wnf_name, SuppliedType};
use crate::ntos::ex::wnf::query::{UserInputs, UserQuery};
use crate::ntos::ex::wnf::{namespace as namespace, security as wnf_security, subscriptions as wnf_subscriptions};
use crate::ntos::ke::critical_region;
use crate::ntos::ob::{object_reference, object_types, open_pointer};
use crate::ntos::ps::process;
use crate::ntos::ps::user::state;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const PROCESS_NOTIFICATION_EVENT_OFFSET: u64 = 0x80;
const EVENT_MODIFY_STATE: u64 = 2;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_ALREADY_REGISTERED: u32 = 0xC000_0718;

/// O original aceita ULONGs desalinhados: sonda ChangeStamp, lê BufferSize,
/// sonda BufferSize para escrita e por fim o buffer de dados.
fn capture_inputs(type_identifier: u64, change_stamp: u64, buffer: u64, returned_length: u64) -> Result<UserInputs, u32> {
    let mut captured = SuppliedType::None;
    if type_identifier != 0 {
        if !state::probe_user_read(type_identifier, 16) {
            return Err(0xC000_0005);
        }
        let mut bytes = [0u8; 16];
        for (offset, byte) in bytes.iter_mut().enumerate() {
            *byte = guest::read8(type_identifier + offset as u64);
        }
        captured = SuppliedType::Captured(bytes);
    }
    if !state::probe_user_write(change_stamp, 4) || !state::probe_user_read(returned_length, 4) {
        return Err(0xC000_0005);
    }
    let capacity = guest::read32(returned_length);
    if !state::probe_user_write(returned_length, 4) {
        return Err(0xC000_0005);
    }
    // Comprimento zero dispensa a sondagem, mesmo com VA de kernel.
    if capacity != 0 && !state::probe_user_write(buffer, capacity as u64) {
        return Err(0xC000_0005);
    }
    Ok(UserInputs { capacity, type_identifier: captured })
}

fn check_access(descriptor: u64, desired: u32) -> u32 {
    wnf_security::check(descriptor, desired).unwrap_or(0xC000_0022)
}

fn check_cross_scope(name: &wnf_name::DecodedName) -> Result<u32, KernelError> {
    wnf_security::check_cross_scope(name, namespace::lookup_definition)
}

/// Capturas e verificações do caminho de usuário da consulta.
pub fn user_query() -> UserQuery {
    UserQuery { probe_read: state::probe_user_read, capture_inputs, check_access, check_cross_scope }
}

/// NtSubscribeWnfStateChange: UserMode é obrigatório, independente do
/// PreviousMode de quem alcançou o provedor.
pub fn subscribe(state_name: u64, change_stamp: u32, event_mask: u32, identifier: u64, ensure: impl FnOnce() -> Result<bool, KernelError>) -> Result<u32, KernelError> {
    critical_region::enter_critical()?;
    let result = (|| -> Result<u32, KernelError> {
        if identifier != 0 {
            if !state::probe_user_write(identifier, 8) {
                return Ok(0xC000_0005);
            }
            guest::write64(identifier, 0);
        }
        if !state::probe_user_read(state_name, 8) {
            return Ok(0xC000_0005);
        }
        let name = wnf_name::decode(guest::read64(state_name));
        if name.status != 0 {
            return Ok(name.status);
        }
        if event_mask & !0x1F != 0 {
            return Ok(0xC000_000D);
        }
        // A criação preguiçosa do serviço vem depois das validações de
        // ponteiro e nome, para não trocar esses erros por falta de memória.
        if !ensure()? {
            return Ok(STATUS_INSUFFICIENT_RESOURCES);
        }
        let subscribed = match wnf_subscriptions::subscribe_captured(&name, change_stamp, event_mask)? {
            Ok(subscribed) => subscribed,
            Err(status) => return Ok(status),
        };
        if identifier != 0 {
            // O mapeamento pode mudar durante a inscrição: a falha da cópia
            // final não desfaz uma inscrição já publicada.
            if !state::probe_user_write(identifier, 8) {
                return Ok(0xC000_0005);
            }
            guest::write64(identifier, subscribed);
        }
        Ok(0)
    })();
    let _ = critical_region::leave_critical();
    result
}

/// Registra o evento de notificações no contexto WNF do processo corrente;
/// a referência pertence ao contexto até a saída do processo.
pub fn set_process_notification_event(handle: u64) -> Result<u32, KernelError> {
    critical_region::enter_critical()?;
    let mut output = 0u64;
    let mut event: Option<open_pointer::Described> = None;
    let result = (|| -> Result<u32, KernelError> {
        // O contexto é criado antes da validação do handle; a referência
        // usa UserMode explicitamente.
        let context = namespace::ensure_process_context(process::get_current_process())?;
        if context == 0 {
            return Ok(STATUS_INSUFFICIENT_RESOURCES);
        }
        output = guest::alloc_bytes(8);
        if output == 0 {
            return Ok(STATUS_INSUFFICIENT_RESOURCES);
        }
        guest::write64(output, 0);
        let status = object_reference::reference_by_handle(handle, EVENT_MODIFY_STATE as u32, object_types::event_type().pointer, 1, output, 0)? as u32;
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        let pointer = guest::read64(output);
        let Some(described) = open_pointer::describe(pointer) else { return Err(KernelError::new("referência WNF sem proprietário de evento")) };
        event = Some(described);
        // A publicação atômica aceita só a primeira inscrição; até uma
        // repetição com o mesmo evento falha e devolve a referência extra.
        let previous = guest::compare_exchange64(context + PROCESS_NOTIFICATION_EVENT_OFFSET, 0, pointer)?;
        if previous != 0 {
            return Ok(STATUS_ALREADY_REGISTERED);
        }
        // A limpeza de wnf-notifications devolve a referência; registrar não
        // altera o estado de sinalização do evento.
        event = None;
        Ok(0)
    })();
    if let Some(event) = event {
        event.dereference();
    }
    if output != 0 {
        guest::free_bytes(output);
    }
    let _ = critical_region::leave_critical();
    result
}
