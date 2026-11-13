//! Contrato LPC dos serviços locais — `system32/ntos/alpc/legacy-service.js`.
//!
//! O servidor recebe o PORT_MESSAGE copiado e pode concluir agora ou por
//! uma continuação.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::alpc::message::buffer::Captured;
use super::transport::{Job, JobResult, Reply, Request, ServiceContinuation, ServiceReply};
use crate::ntos::ob::objects::port::Port;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};

fn response(bytes: &[u8], status: u32) -> JobResult {
    if status != 0 {
        return JobResult { status, ..JobResult::default() };
    }
    let data_length = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
    let total_length = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    if total_length != data_length + 40 || total_length > bytes.len() || u16::from_le_bytes([bytes[6], bytes[7]]) != 0 {
        return JobResult { status: 0xC000_000D, ..JobResult::default() };
    }
    JobResult { status: 0, data: bytes[40..total_length].to_vec(), sender: None }
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
    let mut bytes = Vec::with_capacity(40 + captured.data.len());
    bytes.extend_from_slice(&captured.header);
    bytes.extend_from_slice(&captured.data);
    bytes[4..6].copy_from_slice(&(if datagram { 3u16 } else { 1 }).to_le_bytes());
    bytes[8..16].copy_from_slice(&process::get_current_process_id().to_le_bytes());
    bytes[16..24].copy_from_slice(&process::get_current_thread_id().to_le_bytes());
    bytes[24..28].copy_from_slice(&request.identity.identifier.to_le_bytes());
    bytes[28..32].copy_from_slice(&0u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&(request.identity.callback as u64).to_le_bytes());
    let bytes = Arc::new(SpinLock::new(bytes));
    Ok(match service.request(port, &bytes) {
        ServiceReply::Now(status) => Reply::Now(response(&bytes.lock(), status)),
        ServiceReply::Later(inner) => Reply::Later(Box::new(Continuation { bytes, inner: SpinLock::new(inner) })),
    })
}
