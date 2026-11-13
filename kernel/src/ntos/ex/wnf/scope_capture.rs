//! Captura de ExplicitScope.
//!
//! O SID é emprestado (KernelMode) ou copiado (UserMode); processo e sessão
//! mantêm uma referência de objeto até o fim da operação. A referência por
//! handle do escopo de processo usa ObReferenceObjectByHandle, que entra
//! por [`set_handle_reference`] junto com `ntos/ob`.

use alloc::collections::BTreeSet;

use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ob::object_types;
use crate::ntos::ps::{process, user_probe};
use crate::ntos::ps::silo::query as silo_query;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::eprocess;

const CAPTURE_TAG: u32 = 0x6366_6E57;

/// ObReferenceObjectByHandle(handle, acesso, tipo, modo, &objeto, info).
pub type HandleReference = fn(u64, u32, u64, u8, u64, u64) -> u32;

static HANDLE_REFERENCE: SpinLock<Option<HandleReference>> = SpinLock::new(None);

pub fn set_handle_reference(provider: Option<HandleReference>) {
    *HANDLE_REFERENCE.lock() = provider;
}

/// Escopo capturado; [`Captured::release`] devolve a referência e a cópia.
#[derive(Debug, Default)]
pub struct Captured {
    pub identity: u64,
    frame: u64,
    process: u64,
    sid_copy: u64,
}

impl Captured {
    pub fn release(self) -> Result<(), KernelError> {
        let mut result = Ok(());
        if self.process != 0 {
            result = process::dereference(self.process).map(|_| ());
        }
        if self.frame != 0 {
            let _ = kernel_pool::free(self.frame, Some(CAPTURE_TAG));
        }
        if self.sid_copy != 0 {
            let _ = kernel_pool::free(self.sid_copy, Some(CAPTURE_TAG));
        }
        result
    }
}

/// Processo de anexação da sessão, com os filtros de
/// MiSelectSessionAttachProcess do kernel medido.
fn reference_session_process(session_identifier: u32) -> u64 {
    let current_silo = silo_query::current_server_silo();
    let mut visited = BTreeSet::new();
    for active in process::list_active_processes() {
        let session = guest::read64(active.address + eprocess::SESSION);
        if session == 0 || !visited.insert(session) {
            continue;
        }
        if guest::read32(session + 8) != session_identifier {
            continue;
        }
        if current_silo != 0 && guest::read64(session + 0x418) != current_silo {
            continue;
        }
        if guest::read64(session + 0x2A8) == 0 || guest::read32(session + 4) & 2 != 0 {
            return 0;
        }
        let head = session + 0x10;
        let mut entry = guest::read64(head);
        while entry != head {
            let candidate = entry - 0x4A0;
            entry = guest::read64(entry);
            if guest::read8(candidate + 0x739) & 1 != 0 {
                continue;
            }
            if guest::read32(candidate + 0x464) & 0xC00 < 0xC00 {
                continue;
            }
            if guest::read8(candidate + 0x73B) & 0x60 == 0x40 {
                continue;
            }
            if process::reference(candidate).is_some() {
                return candidate;
            }
        }
        return 0;
    }
    0
}

fn capture(scope: u32, explicit_scope: u64, access_mode: u8) -> Result<Result<Captured, u32>, KernelError> {
    if explicit_scope == 0 {
        return Ok(Ok(Captured::default()));
    }
    if scope == 0 || scope >= 4 {
        return Ok(Err(0xC000_000D));
    }
    if scope == 2 {
        // KernelMode: o SID não é validado nem copiado.
        if access_mode == 0 {
            return Ok(Ok(Captured { identity: explicit_scope, ..Default::default() }));
        }
        // SeCaptureSid: SubAuthorityCount, alinhamento, cópia e validação.
        if !user_probe::probe_user_read(explicit_scope + 1, 1) {
            return Ok(Err(0xC000_0005));
        }
        let count = guest::read8(explicit_scope + 1);
        let length = 8 + count as u64 * 4;
        if explicit_scope & 3 != 0 {
            return Ok(Err(0x8000_0002));
        }
        if !user_probe::probe_user_read(explicit_scope, length) {
            return Ok(Err(0xC000_0005));
        }
        if guest::read8(explicit_scope) & 15 != 1 || count > 15 {
            return Ok(Err(0xC000_0078));
        }
        let Ok(copy) = kernel_pool::allocate(length, AllocateOptions { tag: CAPTURE_TAG, ..Default::default() }) else { return Ok(Err(0xC000_009A)) };
        guest::write_bytes(copy, &guest::read_bytes(explicit_scope, length as usize));
        return Ok(Ok(Captured { identity: copy, sid_copy: copy, ..Default::default() }));
    }
    let Ok(frame) = kernel_pool::allocate(16, AllocateOptions { zero: true, tag: CAPTURE_TAG, ..Default::default() }) else { return Ok(Err(0xC000_0017)) };
    let referenced = (|| -> Result<Result<u64, u32>, KernelError> {
        if scope == 1 {
            if access_mode != 0 && !user_probe::probe_user_read(explicit_scope, 4) {
                return Ok(Err(0xC000_0005));
            }
            let identifier = guest::read32(explicit_scope);
            guest::write32(frame + 8, identifier);
            let process = reference_session_process(identifier);
            return Ok(if process != 0 { Ok(process) } else { Err(0xC000_000D) });
        }
        let Some(reference) = *HANDLE_REFERENCE.lock() else {
            return Err(KernelError::new("ObReferenceObjectByHandle is not available yet"));
        };
        let status = reference(explicit_scope, 0, object_types::process_type().pointer, access_mode, frame, 0);
        if status & 0x8000_0000 != 0 {
            return Ok(Err(status));
        }
        Ok(Ok(guest::read64(frame)))
    })();
    match referenced {
        Ok(Ok(process)) => Ok(Ok(Captured { identity: if scope == 1 { frame + 8 } else { frame }, frame, process, sid_copy: 0 })),
        other => {
            let _ = kernel_pool::free(frame, Some(CAPTURE_TAG));
            other.map(|result| result.map(|_| Captured::default()))
        }
    }
}

pub fn capture_kernel(scope: u32, explicit_scope: u64) -> Result<Result<Captured, u32>, KernelError> {
    capture(scope, explicit_scope, 0)
}

pub fn capture_user(scope: u32, explicit_scope: u64) -> Result<Result<Captured, u32>, KernelError> {
    capture(scope, explicit_scope, 1)
}
