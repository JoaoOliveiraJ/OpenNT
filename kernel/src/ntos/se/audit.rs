//! Auditoria de segurança: os eventos que os drivers reportam ao Security
//! Reference Monitor, como o `se\seaudit.c` do NT.
//!
//! Não há serviço de eventlog em modo usuário: os eventos ficam num anel do
//! kernel (os mais antigos saem) e são ecoados na serial.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::ke::clock;
use crate::rtl::SpinLock;

/// Evento de auditoria gravado no anel.
#[derive(Clone, Debug)]
pub struct AuditEvent {
    pub kind: &'static str,
    pub detail: String,
    pub at_ms: u64,
}

const AUDIT_RING_LIMIT: usize = 256;
static AUDIT_RING: SpinLock<VecDeque<AuditEvent>> = SpinLock::new(VecDeque::new());

/// Consulta interna (eventlog/depuração futuros): os eventos gravados.
pub fn events() -> Vec<AuditEvent> {
    AUDIT_RING.lock().iter().cloned().collect()
}

fn record_audit_event(kind: &'static str, detail: String) {
    let line = if detail.is_empty() { format!("[se-audit] {kind}") } else { format!("[se-audit] {kind}: {detail}") };
    let mut ring = AUDIT_RING.lock();
    ring.push_back(AuditEvent { kind, detail, at_ms: clock::now_ms() });
    if ring.len() > AUDIT_RING_LIMIT {
        ring.pop_front();
    }
    drop(ring);
    debug_print!("{}", line);
}

/// SeSetAuditParameter: registra tipo, categoria e endereço; não copia o
/// conteúdo apontado.
pub fn set_audit_parameter(kind: u32, category: u32, parameters: u32) {
    record_audit_event("SetAuditParameter", format!("type={} category={} params={:#x}", kind, category, parameters));
}

/// SeReportSecurityEventWithSubCategory: registra a categoria.
pub fn report_security_event(category: u32) {
    record_audit_event("SecurityEvent", format!("category={}", category));
}

/// SeAuditFipsCryptoSelftests: o cng audita o resultado dos selftests FIPS
/// por aqui.
pub fn fips_crypto_selftests(general: u32, causing: u32, extra: u32) {
    record_audit_event("FipsCryptoSelftest", format!("general={} causing={} extra={:#x}", general, causing, extra));
}
