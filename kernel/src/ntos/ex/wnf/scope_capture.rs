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
use core::mem::offset_of;

use super::objects::process_at;
use crate::ntos::ex::list_entry;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{Eprocess, MmSessionSpace, Sid};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

/// Moldura de pool da captura: o objeto referenciado pelo handle e o
/// identificador de sessão (a identidade aponta para um dos dois).
#[repr(C)]
struct CaptureFrame {
    object: Field<u64>,
    session_id: Field<u32>,
    _pad_c: Reserved<0x4>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for CaptureFrame {}

const _: () = assert!(core::mem::size_of::<CaptureFrame>() == 16);

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
        let session = process_at(active.address).session.get();
        if session == 0 || !visited.insert(session) {
            continue;
        }
        // SAFETY: MM_SESSION_SPACE de um processo ativo.
        let space = unsafe { MmSessionSpace::at(session) };
        if space.session_id.get() != session_identifier {
            continue;
        }
        if current_silo != 0 && space.server_silo.get() != current_silo {
            continue;
        }
        // Sessão sem descarregamento registrado ou com DeletePending (bit 1).
        if space.driver_unload.function.get() == 0 || space.u.long_flags.get() & 2 != 0 {
            return 0;
        }
        let head = &space.process_list;
        let mut entry = head.flink.get();
        while entry != head.address() {
            let candidate = process_at(entry - offset_of!(Eprocess, session_process_links) as u64);
            entry = list_entry::at(entry).flink.get();
            let working_set = &candidate.vm.instance.flags;
            if working_set.bitfield_1.get() & 1 != 0 {
                continue;
            }
            if candidate.flags.get() & 0xC00 < 0xC00 {
                continue;
            }
            if working_set.u2.get() & 0x60 == 0x40 {
                continue;
            }
            let candidate = candidate.address();
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
        let count_address = explicit_scope + offset_of!(Sid, sub_authority_count) as u64;
        if !user_probe::probe_user_read(count_address, 1) {
            return Ok(Err(0xC000_0005));
        }
        let Ok(count) = guest::try_read::<u8>(count_address) else { return Ok(Err(0xC000_0005)) };
        let length = offset_of!(Sid, sub_authority) as u64 + count as u64 * 4;
        if explicit_scope & 3 != 0 {
            return Ok(Err(0x8000_0002));
        }
        if !user_probe::probe_user_read(explicit_scope, length) {
            return Ok(Err(0xC000_0005));
        }
        // Cópia sondada: o SID de usuário pode perder o mapeamento a qualquer momento.
        let Ok(bytes) = guest::try_read_bytes(explicit_scope, length as usize) else { return Ok(Err(0xC000_0005)) };
        if bytes[offset_of!(Sid, revision)] & 15 != 1 || count > 15 {
            return Ok(Err(0xC000_0078));
        }
        let Ok(copy) = kernel_pool::allocate(length, AllocateOptions { tag: CAPTURE_TAG, ..Default::default() }) else { return Ok(Err(0xC000_009A)) };
        guest::write_bytes(copy, &bytes);
        return Ok(Ok(Captured { identity: copy, sid_copy: copy, ..Default::default() }));
    }
    let Ok(frame) = kernel_pool::allocate(CaptureFrame::SIZE, AllocateOptions { zero: true, tag: CAPTURE_TAG, ..Default::default() }) else { return Ok(Err(0xC000_0017)) };
    // SAFETY: alocação nova do tamanho da moldura.
    let capture_frame = unsafe { CaptureFrame::at(frame) };
    let referenced = (|| -> Result<Result<u64, u32>, KernelError> {
        if scope == 1 {
            if access_mode != 0 && !user_probe::probe_user_read(explicit_scope, 4) {
                return Ok(Err(0xC000_0005));
            }
            // ULONG de sessão do chamador (sondado no modo usuário).
            let Ok(identifier) = guest::try_read::<u32>(explicit_scope) else { return Ok(Err(0xC000_0005)) };
            capture_frame.session_id.set(identifier);
            let process = reference_session_process(identifier);
            return Ok(if process != 0 { Ok(process) } else { Err(0xC000_000D) });
        }
        let Some(reference) = *HANDLE_REFERENCE.lock() else {
            return Err(KernelError::new("ObReferenceObjectByHandle is not available yet"));
        };
        let status = reference(explicit_scope, 0, object_types::process_type().pointer, access_mode, capture_frame.object.address(), 0);
        if status & 0x8000_0000 != 0 {
            return Ok(Err(status));
        }
        Ok(Ok(capture_frame.object.get()))
    })();
    match referenced {
        Ok(Ok(process)) => Ok(Ok(Captured { identity: if scope == 1 { capture_frame.session_id.address() } else { capture_frame.object.address() }, frame, process, sid_copy: 0 })),
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
