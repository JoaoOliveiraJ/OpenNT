//! Módulos pequenos do ALPC: atributo de contexto, evento direto e política
//! de despertar.

use crate::ntos::ps::process;

/// Contexto ALPC sem alterar os quatro bytes reservados no fim do atributo.
/// O atributo fica no buffer de atributos do chamador (de modo usuário):
/// cada campo é escrito com sonda.
pub mod context_attribute {
    use core::mem::offset_of;

    use crate::ntos::alpc::message::buffer::{read_field, write_field};
    use crate::ntos::alpc::message::identity::Identity;
    use crate::ntos::inc::types::AlpcContextAttr;

    /// Grava o atributo; ACCESS_VIOLATION se o buffer sumiu.
    pub fn try_write(pointer: u64, port_context: u64, message_context: u64, sequence: u32, identifier: u32, callback: u32) -> Result<(), u32> {
        write_field::<u64>(pointer, offset_of!(AlpcContextAttr, port_context), port_context)?;
        write_field::<u64>(pointer, offset_of!(AlpcContextAttr, message_context), message_context)?;
        write_field::<u32>(pointer, offset_of!(AlpcContextAttr, sequence), sequence)?;
        write_field::<u32>(pointer, offset_of!(AlpcContextAttr, message_id), identifier)?;
        write_field::<u32>(pointer, offset_of!(AlpcContextAttr, callback_id), callback)
    }

    /// Como `try_write`, para chamadores que já validaram o buffer: uma
    /// falha de sonda deixa o atributo como estava.
    pub fn write(pointer: u64, port_context: u64, message_context: u64, sequence: u32, identifier: u32, callback: u32) {
        let _ = try_write(pointer, port_context, message_context, sequence, identifier, callback);
    }

    /// A captura publica a identidade e sequência zero; MessageContext
    /// permanece opaco.
    pub fn try_capture(pointer: u64, port_context: u64, identity: &Identity) -> Result<u64, u32> {
        let message_context = read_field::<u64>(pointer, offset_of!(AlpcContextAttr, message_context))?;
        identity.with(|state| state.client_context = message_context);
        try_write(pointer, port_context, message_context, 0, identity.identifier, identity.callback)?;
        Ok(message_context)
    }

    /// Como `try_capture`; uma falha de sonda devolve MessageContext zero.
    pub fn capture(pointer: u64, port_context: u64, identity: &Identity) -> u64 {
        try_capture(pointer, port_context, identity).unwrap_or(0)
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
