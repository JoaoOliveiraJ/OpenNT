//! Módulos pequenos do ALPC: atributo de contexto, evento direto e política
//! de despertar.

use crate::ntos::ps::process;
use crate::ntos::mm::guest_memory as guest;

/// Contexto ALPC sem alterar os quatro bytes reservados no fim do atributo.
pub mod context_attribute {
    use super::guest;
    use crate::ntos::alpc::message::identity::Identity;

    pub fn write(pointer: u64, port_context: u64, message_context: u64, sequence: u32, identifier: u32, callback: u32) {
        guest::write64(pointer, port_context);
        guest::write64(pointer + 8, message_context);
        guest::write32(pointer + 16, sequence);
        guest::write32(pointer + 20, identifier);
        guest::write32(pointer + 24, callback);
    }

    /// A captura publica a identidade e sequência zero; MessageContext
    /// permanece opaco.
    pub fn capture(pointer: u64, port_context: u64, identity: &Identity) -> u64 {
        let message_context = guest::read64(pointer + 8);
        identity.with(|state| state.client_context = message_context);
        write(pointer, port_context, message_context, 0, identity.identifier, identity.callback);
        message_context
    }
}

/// Atributo direto: o evento pertence à requisição identificada.
pub mod direct_event {
    /// Exige contexto válido e rejeita datagrama ou reutilização de
    /// mensagem/reserva.
    pub fn validate(work_flags: u32, valid_attributes: u32) -> u32 {
        if work_flags & 0x10010 != 0 || valid_attributes & 0x2000_0000 == 0 { 0xC000_000D } else { 0 }
    }

    /// Em KernelMode o campo é PKEVENT, conservado pelo chamador até a
    /// conclusão: sem referência de handle.
    pub fn borrow(event_pointer: u64) -> u64 {
        event_pointer
    }
}

/// A flag 800000h participa da cobrança de ativação do processo receptor
/// (AlpcpCompleteDispatchMessage); datagramas dispensam a cobrança.
pub mod wake_policy {
    use super::process;

    /// Modo encaminhado a PsChargeProcessWakeCounter, ou `None` quando a
    /// política dispensa a chamada.
    pub fn select_charge_mode(message_flags: u32, port_policy: u32, default_policy: u32, datagram: bool) -> Option<u32> {
        if datagram {
            return None;
        }
        let force = message_flags & 0x82_0000 != 0;
        let policy = if port_policy & 0x40_0000 != 0 { 2 } else if port_policy & 0x20_0000 != 0 { 1 } else { 0 };
        if !force && policy == 0 && default_policy & 1 != 0 {
            return None;
        }
        if policy != 0 {
            return Some(if policy == 1 { 3 } else { 1 });
        }
        if default_policy & 1 != 0 {
            return Some(if default_policy & 2 != 0 { 0x8000_0003 } else { 3 });
        }
        Some(1)
    }

    /// Serviços deste transporte executam no kernel e pertencem ao System:
    /// sem InheritedFromUniqueProcessId não há cobrança.
    pub fn check_system_service(service_process: u64, message_flags: u32, datagram: bool) -> u32 {
        let record = process::with_record(service_process, |record| (record.exiting || record.terminated, record.parent_id));
        let Some((ending, parent)) = record.filter(|_| service_process == process::get_system_process()) else { return 0xC000_00BB };
        if ending {
            return 0xC000_00BB;
        }
        if select_charge_mode(message_flags, 0, 0, datagram).is_none() || parent == 0 { 0 } else { 0xC000_00BB }
    }
}
