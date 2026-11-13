//! Contrato LPC dos serviços locais.
//!
//! O servidor recebe o PORT_MESSAGE copiado e pode concluir agora ou por
//! uma continuação.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::offset_of;

use crate::ntos::alpc::message::buffer::{Captured, HEADER_SIZE};
use crate::ntos::inc::types::{PortMessage, PortMessageView1};
use super::transport::{Job, JobResult, Reply, Request, ServiceContinuation, ServiceReply};
use crate::ntos::ob::objects::port::Port;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};

/// Campo de 16 bits da cópia do PORT_MESSAGE.
fn get16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

/// Grava `value` (little-endian) no offset do campo da cópia.
fn put(bytes: &mut [u8], offset: usize, value: &[u8]) {
    bytes[offset..offset + value.len()].copy_from_slice(value);
}

fn response(bytes: &[u8], status: u32) -> JobResult {
    if status != 0 {
        return JobResult { status, ..JobResult::default() };
    }
    let header = HEADER_SIZE as usize;
    let data_length = get16(bytes, offset_of!(PortMessage, u1.s1.data_length)) as usize;
    let total_length = get16(bytes, offset_of!(PortMessage, u1.s1.total_length)) as usize;
    if total_length != data_length + header || total_length > bytes.len() || get16(bytes, offset_of!(PortMessage, u2.s2.data_info_offset)) != 0 {
        return JobResult { status: 0xC000_000D, ..JobResult::default() };
    }
    JobResult { status: 0, data: bytes[header..total_length].to_vec(), sender: None }
}

/// A continuação do serviço lê o PORT_MESSAGE que ele próprio alterou.
struct Continuation {
    bytes: Arc<SpinLock<Vec<u8>>>,
    inner: SpinLock<Box<dyn ServiceContinuation>>,
}

impl Job for Continuation {
    fn poll(&mut self) -> Option<JobResult> {
        let status = self.inner.lock().poll()?;
        Some(response(&self.bytes.lock(), status))
    }
    fn cleanup(&mut self, status: u32) {
        self.inner.lock().cleanup(status);
    }
}

pub fn exchange(port: &Arc<Port>, captured: &Captured, request: &Arc<Request>, datagram: bool) -> Result<Reply, KernelError> {
    let Some(service) = port.with(|state| state.service.clone()) else { return Err(KernelError::new("LPC port has no service")) };
    let mut bytes = Vec::with_capacity(HEADER_SIZE as usize + captured.data.len());
    bytes.extend_from_slice(&captured.header);
    bytes.extend_from_slice(&captured.data);
    // LPC_DATAGRAM (3) ou LPC_REQUEST (1).
    put(&mut bytes, offset_of!(PortMessage, u2.s2.type_), &(if datagram { 3u16 } else { 1 }).to_le_bytes());
    put(&mut bytes, offset_of!(PortMessage, client_id.unique_process), &process::get_current_process_id().to_le_bytes());
    put(&mut bytes, offset_of!(PortMessage, client_id.unique_thread), &process::get_current_thread_id().to_le_bytes());
    put(&mut bytes, offset_of!(PortMessage, message_id), &request.identity.identifier.to_le_bytes());
    // Os quatro bytes depois de MessageId e CallbackId (com a parte alta de
    // ClientViewSize) zerados.
    put(&mut bytes, offset_of!(PortMessage, message_id) + 4, &0u32.to_le_bytes());
    put(&mut bytes, offset_of!(PortMessageView1, callback_id), &(request.identity.callback as u64).to_le_bytes());
    let bytes = Arc::new(SpinLock::new(bytes));
    Ok(match service.request(port, &bytes) {
        ServiceReply::Now(status) => Reply::Now(response(&bytes.lock(), status)),
        ServiceReply::Later(inner) => Reply::Later(Box::new(Continuation { bytes, inner: SpinLock::new(inner) })),
    })
}
