//! O atributo de vista das mensagens ALPC (ALPC_DATA_VIEW_ATTR).
//!
//! Uma mensagem grande leva os dados numa vista de uma seção de porta (o
//! NtAlpcCreatePortSection e o NtAlpcCreateSectionView de quem envia):
//!
//! - o envio ([`capture`], o AlpcpCaptureViewAttributeInternal) acha a seção
//!   pelo handle na tabela da porta de quem envia e a vista dele pela base;
//!   a mensagem retém a seção e guarda a região (deslocamento e tamanho);
//! - a recepção ([`expose`] e [`publish`], o
//!   AlpcpExposeViewAttributeInSenderContext e o AlpcpExposeViewAttribute)
//!   mapeia a mesma região no processo da porta que recebe, registrada nela
//!   (que a apaga pelo NtAlpcDeleteSectionView com a própria base), e
//!   escreve {Flags, 0, base, tamanho} no atributo, com o bit 30 do
//!   ValidAttributes. Flags 0x40000 diz que a vista é segura (quem enviou não
//!   a altera depois do envio) e pode ser usada no lugar;
//! - quem recebeu uma resposta com vista a solta reenviando a resposta com
//!   Flags 0x10000 (UNMAP_EXISTING) e sem seção ([`release_received`]).

use alloc::sync::Arc;
use core::mem::offset_of;

use crate::ntos::alpc::message::buffer::{self as message_buffer, read_field};
use crate::ntos::alpc::port_sections::{self, SectionRecord};
use crate::ntos::alpc::section_views::{self, ViewBinding};
use crate::ntos::inc::types::{AlpcDataViewAttr, AlpcMessageAttributes, NtStruct};
use crate::ntos::ob::objects::port::Port;
use crate::ntos::ps::user::state;
use crate::rtl::KernelError;

/// ALPC_MESSAGE_VIEW_ATTRIBUTE.
pub const VIEW_ATTRIBUTE: u32 = 0x4000_0000;
/// ALPC_VIEWFLG_UNMAP_EXISTING: a vista que a mensagem já tem sai.
const UNMAP_EXISTING: u32 = 0x1_0000;
/// A vista é segura: o receptor pode usá-la no lugar.
const SECURE_VIEW: u32 = 0x4_0000;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_ADDRESS: u32 = 0xC000_0141;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;

/// A região que uma mensagem leva: a seção (retida até a mensagem sair) e o
/// deslocamento e o tamanho da vista de quem enviou.
pub struct Carried {
    record: Arc<SectionRecord>,
    offset: u64,
    size: u64,
    secure: bool,
}

impl Drop for Carried {
    fn drop(&mut self) {
        let _ = port_sections::release(&self.record);
    }
}

/// O atributo de envio capturado.
pub enum Captured {
    /// Sem seção: nada a levar.
    Empty,
    View(Arc<Carried>),
}

/// AlpcpCaptureViewAttributeInternal: Flags só com os bits 16 a 18
/// (STATUS_INVALID_PARAMETER); sem SectionHandle não há o que levar; base
/// zero é STATUS_INVALID_ADDRESS; o handle se resolve na tabela de seções da
/// porta (STATUS_INVALID_HANDLE) e a base, nas vistas dessa seção que a
/// porta criou (STATUS_INVALID_ADDRESS).
pub fn capture(port: &Arc<Port>, attribute: u64, mode: u8) -> Result<Result<Captured, u32>, KernelError> {
    if !message_buffer::accessible(attribute, AlpcDataViewAttr::SIZE, mode, false) {
        return Ok(Err(STATUS_ACCESS_VIOLATION));
    }
    let fields = (|| -> Result<(u32, u64, u64), u32> {
        Ok((
            read_field::<u32>(attribute, offset_of!(AlpcDataViewAttr, flags))?,
            read_field::<u64>(attribute, offset_of!(AlpcDataViewAttr, section_handle))?,
            read_field::<u64>(attribute, offset_of!(AlpcDataViewAttr, view_base))?,
        ))
    })();
    let (flags, section_handle, base) = match fields {
        Ok(fields) => fields,
        Err(status) => return Ok(Err(status)),
    };
    if flags & 0xFFF8_FFFF != 0 {
        return Ok(Err(STATUS_INVALID_PARAMETER));
    }
    if section_handle == 0 {
        return Ok(Ok(Captured::Empty));
    }
    if base == 0 {
        return Ok(Err(STATUS_INVALID_ADDRESS));
    }
    let record = match port_sections::reference(port, section_handle) {
        Ok(record) => record,
        Err(status) => return Ok(Err(status)),
    };
    let found = port.with(|state| state.owned_section_views.iter().find(|binding| binding.view.base == base && Arc::ptr_eq(&binding.section, &record) && !binding.state.lock().deleted).map(|binding| (binding.view.offset, binding.view.size)));
    let Some((offset, size)) = found else {
        port_sections::release(&record)?;
        return Ok(Err(STATUS_INVALID_ADDRESS));
    };
    let secure = record.secure && flags & SECURE_VIEW != 0;
    Ok(Ok(Captured::View(Arc::new(Carried { record, offset, size, secure }))))
}

/// A vista da região no processo da porta que recebe (reaproveitada se ela
/// já tem uma).
pub fn expose(receiver: &Arc<Port>, carried: &Carried) -> Result<Result<Arc<ViewBinding>, u32>, KernelError> {
    section_views::expose_region(receiver, &carried.record, carried.offset, carried.size)
}

/// AlpcpExposeViewAttribute: o ALPC_DATA_VIEW_ATTR de recepção (Flags 0x40000
/// numa vista segura, sem handle de seção, a base e o tamanho da vista do
/// receptor) e o bit 30 do ValidAttributes, quando o receptor alocou o
/// atributo. Devolve se publicou.
pub fn publish(attributes: u64, binding: &ViewBinding, carried: &Carried) -> Result<bool, u32> {
    if attributes == 0 {
        return Ok(false);
    }
    let header = state::user_struct::<AlpcMessageAttributes>(attributes).map_err(|error| error.status)?;
    if header.allocated_attributes.probe_get().map_err(|error| error.status)? & VIEW_ATTRIBUTE == 0 {
        return Ok(false);
    }
    let at = crate::ntos::ps::user::alpc::attribute_address(attributes, VIEW_ATTRIBUTE);
    let attribute = state::user_struct::<AlpcDataViewAttr>(at).map_err(|error| error.status)?;
    let fill = || -> Result<(), KernelError> {
        attribute.flags.probe_set(if carried.secure { SECURE_VIEW } else { 0 })?;
        attribute.section_handle.probe_set(0)?;
        attribute.view_base.probe_set(binding.view.base)?;
        attribute.view_size.probe_set(binding.view.size)?;
        let valid = header.valid_attributes.probe_get()?;
        header.valid_attributes.probe_set(valid | VIEW_ATTRIBUTE)
    };
    fill().map_err(|error| error.status)?;
    Ok(true)
}

/// Exposição e publicação juntas; uma falha de mapeamento devolve o
/// NTSTATUS. Devolve a vista do receptor quando publicada.
pub fn deliver(receiver: &Arc<Port>, attributes: u64, carried: &Carried) -> Result<Result<Option<Arc<ViewBinding>>, u32>, KernelError> {
    let wanted = attributes != 0 && state::user_struct::<AlpcMessageAttributes>(attributes).and_then(|header| header.allocated_attributes.probe_get()).is_ok_and(|allocated| allocated & VIEW_ATTRIBUTE != 0);
    if !wanted {
        return Ok(Ok(None));
    }
    let binding = match expose(receiver, carried)? {
        Ok(binding) => binding,
        Err(status) => return Ok(Err(status)),
    };
    Ok(match publish(attributes, &binding, carried) {
        Ok(true) => Ok(Some(binding)),
        Ok(false) => Ok(None),
        Err(status) => Err(status),
    })
}

/// O atributo de envio pede que a vista que a mensagem já tem saia
/// (UNMAP_EXISTING): na resposta do servidor, a vista que o pedido trouxe a
/// ele é apagada.
pub fn unmap_existing(attribute: u64, mode: u8) -> bool {
    message_buffer::accessible(attribute, 4, mode, false) && read_field::<u32>(attribute, offset_of!(AlpcDataViewAttr, flags)).is_ok_and(|flags| flags & UNMAP_EXISTING != 0)
}

/// O reenvio de uma resposta já recebida (MessageId positivo, sem pedido
/// novo) com o atributo de vista: Flags 0x10000 (UNMAP_EXISTING) apaga a
/// vista que essa resposta trouxe para a porta. `None` quando o atributo não
/// pede a retirada.
pub fn release_received(port: &Arc<Port>, message_id: u32, attribute: u64, mode: u8) -> Result<Option<u32>, KernelError> {
    if !message_buffer::accessible(attribute, AlpcDataViewAttr::SIZE, mode, false) {
        return Ok(Some(STATUS_ACCESS_VIOLATION));
    }
    let flags = match read_field::<u32>(attribute, offset_of!(AlpcDataViewAttr, flags)) {
        Ok(flags) => flags,
        Err(status) => return Ok(Some(status)),
    };
    if flags & 0xFFF8_FFFF != 0 {
        return Ok(Some(STATUS_INVALID_PARAMETER));
    }
    if flags & UNMAP_EXISTING == 0 {
        return Ok(None);
    }
    let Some(binding) = port.with(|state| state.received_views.remove(&message_id)) else { return Ok(Some(0)) };
    if binding.state.lock().deleted {
        return Ok(Some(0));
    }
    section_views::delete_referenced(&binding).map(Some)
}

/// Guarda a vista que a resposta `message_id` trouxe à porta (uma entrada
/// por vista: a mesma vista reaproveitada troca de mensagem).
pub fn remember_received(port: &Arc<Port>, message_id: u32, binding: &Arc<ViewBinding>) {
    port.with(|state| {
        state.received_views.retain(|_, candidate| !Arc::ptr_eq(candidate, binding));
        state.received_views.insert(message_id, binding.clone());
    });
}
