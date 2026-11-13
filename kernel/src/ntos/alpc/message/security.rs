//! Segurança por mensagem — `system32/ntos/alpc/message-security.js`.
//!
//! O contexto pertence à mensagem: trocas posteriores de impersonação não
//! substituem o token já capturado; o rastreamento estático conserva uma
//! cópia.

use alloc::sync::Arc;

use crate::ntos::alpc::message::buffer as message_buffer;
use crate::ntos::alpc::message::identity::{Identity, Retained};
use crate::ntos::alpc::security_contexts::{self, Borrowed, ClientIdentity, Quality};
use crate::ntos::ob::objects::port::{Port, Role};
use crate::ntos::se::token::tokens;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

pub use crate::ntos::alpc::security_contexts::capture as capture_client;

/// Atributo capturado: vazio (RELEASE) ou um contexto emprestado.
pub enum Captured {
    Empty,
    Borrowed(Arc<Borrowed>),
}

/// Reutiliza contextos da mesma porta. CREATE publica a identidade atual;
/// RELEASE retira o contexto sem anexar identidade explícita à mensagem.
pub fn capture(port: &Arc<Port>, attribute: u64, mode: u8) -> Result<Result<Captured, u32>, KernelError> {
    let captured = match security_contexts::quality(guest::read64(attribute + 8), mode) {
        Ok(captured) => captured,
        Err(status) => return Ok(Err(status)),
    };
    let flags = guest::read32(attribute);
    if flags & !0x3_0000 != 0 || flags & 0x3_0000 == 0x3_0000 {
        return Ok(Err(0xC000_000D));
    }
    let handle = guest::read64(attribute + 16);
    let mut published = handle;
    let result = if handle == 0xFFFF_FFFF_FFFF_FFFE {
        if flags & 0x1_0000 != 0 {
            return Ok(Err(0xC000_0008));
        }
        let quality = captured.or_else(|| port.with(|state| state.security_quality)).unwrap_or(Quality { level: 2, tracking: 0, effective_only: false });
        let record = match security_contexts::create(port, &quality, flags & 0x2_0000 != 0)? {
            Ok(record) => record,
            Err(status) => return Ok(Err(status)),
        };
        if flags & 0x2_0000 != 0 {
            published = record.handle;
        }
        // O empréstimo herda a referência do criador.
        Captured::Borrowed(Arc::new(security_contexts::borrow(&record)))
    } else {
        let record = match security_contexts::reference(port, handle)? {
            Ok(record) => record,
            Err(status) => return Ok(Err(status)),
        };
        if flags & 0x1_0000 != 0 {
            security_contexts::delete_referenced(&record)?;
            security_contexts::release(&record)?;
            Captured::Empty
        } else {
            Captured::Borrowed(Arc::new(security_contexts::borrow(&record)))
        }
    };
    // UserMode copia ContextHandle de volta mesmo sem mudança; CREATE também
    // escreve em KernelMode. Uma mensagem falha devolve sua retenção.
    if mode != 0 || published != handle {
        if !message_buffer::writable(attribute + 16, 8, mode) {
            if let Captured::Borrowed(borrowed) = &result {
                borrowed.release();
            }
            return Ok(Err(0xC000_0005));
        }
        guest::write64(attribute + 16, published);
    }
    Ok(Ok(result))
}

/// Token selecionado para a impersonação; `release` devolve a retenção.
pub struct Selected {
    pub token: u64,
    client: Option<Arc<ClientIdentity>>,
}

impl Selected {
    pub fn release(&self) {
        match &self.client {
            Some(client) => {
                let _ = client.release();
            }
            None => {
                let _ = tokens::release(self.token);
            }
        }
    }
}

fn retained(token: u64) -> Result<Selected, u32> {
    tokens::retain(token).map_err(|error| if error.status != 0 { error.status } else { 0xC000_0022 })?;
    Ok(Selected { token, client: None })
}

/// Apenas a porta de conexão consulta o contexto implícito do cliente; o
/// atributo anônimo é uma recusa explícita, sem fallback ao token da porta.
pub fn select(port: &Arc<Port>, identity: &Identity) -> Result<Result<Selected, u32>, KernelError> {
    let (disconnected, replied, explicit) = identity.with(|state| (state.disconnected, state.replied, state.security.clone()));
    if disconnected || identity.port.closed() {
        return Ok(Err(0xC000_0703));
    }
    if let Some(explicit) = explicit {
        if explicit.level < 1 {
            return Ok(Err(0xC000_0022));
        }
        return Ok(retained(explicit.token));
    }
    let sender_role = identity.port.with(|state| state.role);
    let sender_role = if sender_role == Role::None { Role::Client } else { sender_role };
    if port.with(|state| state.role) != Role::Listener || replied || sender_role != Role::Client {
        return Ok(Err(0xC000_0022));
    }
    let (quality, client) = identity.port.with(|state| (state.security_quality, state.client_security.clone()));
    if let Some(quality) = quality.filter(|quality| quality.tracking != 0) {
        let sender = identity.with(|state| state.sender_thread);
        return Ok(capture_client(sender, &quality)?.map(|client| Selected { token: client.token, client: Some(client) }));
    }
    let token = client.map(|client| client.token).filter(|&token| token != 0).unwrap_or_else(|| identity.port.token());
    if token == 0 {
        return Ok(Err(0xC000_0022));
    }
    Ok(retained(token))
}
