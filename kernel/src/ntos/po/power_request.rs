//! Pedidos de energia de kernel: PoCreatePowerRequest, PoSetPowerRequest,
//! PoClearPowerRequest e PoDeletePowerRequest.
//!
//! ntoskrnl 19041:
//! - O tipo de objeto "PowerRequest" (PopPowerRequestInit 0xa704d4):
//!   GenericMapping {0x20000, 0x20000, 0x20000, 0x1F0000}, ValidAccessMask
//!   0x1F0000, InvalidAttributes 0x192, UseDefaultObject | MaintainHandleCount,
//!   NonPagedPoolNx, corpo de 0x98 bytes.
//! - PoCreatePowerRequest(PowerRequest*, DeviceObject, Context) 0x772320:
//!   *PowerRequest = NULL; sem DeviceObject, STATUS_INVALID_PARAMETER; o
//!   contexto é capturado (PoCaptureReasonContext; erro volta) e o
//!   PopCreateKernelPowerRequest cria o objeto (PopCreatePowerRequestObject
//!   0x6f5d58: corpo zerado, SessionId do processo corrente, Id do contador
//!   PopPowerRequestId, o contexto e, num pedido de modo kernel, ProcessId
//!   0), marca os tipos aceitos (0x12: PowerRequestSystemRequired e o
//!   interno 4) e o põe no fim da PopPowerRequestObjectList.
//! - PoSetPowerRequest(PowerRequest, Type) 0x34af80 e PoClearPowerRequest
//!   0x34b770: o tipo público (Display 0, System 1, AwayMode 2, Execution 3)
//!   vira o índice interno; outro é STATUS_NOT_SUPPORTED. O
//!   PoSetPowerRequestInternal (0x34b170) recusa um índice acima de 5 ou fora
//!   dos tipos aceitos (STATUS_NOT_SUPPORTED), soma o contador do tipo
//!   (estouro: STATUS_INTEGER_OVERFLOW) e, na passagem de 0 para 1 sem
//!   sobreposição do tipo (o OverrideMask, que só o UMPO liga), soma o
//!   contador global do tipo em PopPowerRequestAttributes. O
//!   PoClearPowerRequestInternal (0x34afac) também recusa o tipo cujo
//!   contador já é zero e desfaz na passagem de 1 para 0.
//! - PoDeletePowerRequest 0x6a6180: PopPowerRequestCleanUp (tira da lista e,
//!   para cada tipo ainda ligado e não sobreposto, desconta o global) e o
//!   ObDereferenceObject; o PopDeletePowerRequestObject solta o contexto.
//!
//! As notificações de mudança (PopQueuePowerRequestCallback: as callbacks
//! de configuração de energia, o UMPO e o rastreamento) ainda não têm
//! destino no OpenNT; os contadores são os que elas leriam.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{ListEntry, ObjectAttributes};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_types::{self, TypeTemplate};
use crate::ntos::ob::{object_create, object_reference, reference_trace};
use crate::rtl::{KernelError, SpinLock};

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_INTEGER_OVERFLOW: u32 = 0xC000_0095;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
/// Os índices internos dos tipos (POWER_REQUEST_TYPE_INTERNAL).
const TYPE_COUNT: usize = 6;
/// Os tipos que um pedido de kernel aceita (PopCreateKernelPowerRequest).
const KERNEL_SUPPORTED_TYPES: u32 = 0x12;
/// OBJ_EXCLUSIVE dos atributos do PopCreatePowerRequestObject.
const OBJ_EXCLUSIVE: u32 = 0x20;
const KERNEL_MODE: u8 = 0;
/// Tamanho fixo cobrado do pool paginado além do contexto capturado.
const PAGED_CHARGE: u32 = 0x38;

const POWER_REQUEST_TYPE: TypeTemplate = TypeTemplate {
    name: "PowerRequest",
    mapping: [0x2_0000, 0x2_0000, 0x2_0000, 0x1F_0000],
    valid_access: 0x1F_0000,
    flags: 0x14,
    object_type_code: 0,
    invalid_attributes: 0x192,
    pool_type: 0x200,
    paged_charge: 0,
    non_paged_charge: 0x98,
};

/// O corpo do objeto PowerRequest (layout privado do kernel, lido na
/// desmontagem; 0x98 bytes).
#[repr(C)]
struct PowerRequest {
    /// Elo da PopPowerRequestObjectList no NT; o OpenNT guarda a lista no
    /// registro deste módulo e deixa o elo zerado.
    _links: ListEntry,
    session_id: Field<u32>,
    /// Os tipos internos que o pedido aceita (bit por índice).
    supported_types: Field<u32>,
    /// Tipos sobrepostos pelo UMPO.
    override_mask: Field<u32>,
    id: Field<u32>,
    /// Quantas vezes cada tipo interno está ligado.
    counts: [Field<u32>; TYPE_COUNT],
    _reserved_38: Reserved<0x18>,
    /// O contexto capturado (PoCaptureReasonContext).
    reason: Field<u64>,
    process_id: Field<u32>,
    _reserved_5c: Reserved<0x3C>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for PowerRequest {}

const _: () = {
    assert!(core::mem::size_of::<PowerRequest>() == 0x98);
    assert!(core::mem::offset_of!(PowerRequest, session_id) == 0x10);
    assert!(core::mem::offset_of!(PowerRequest, supported_types) == 0x14);
    assert!(core::mem::offset_of!(PowerRequest, id) == 0x1C);
    assert!(core::mem::offset_of!(PowerRequest, counts) == 0x20);
    assert!(core::mem::offset_of!(PowerRequest, reason) == 0x50);
    assert!(core::mem::offset_of!(PowerRequest, process_id) == 0x58);
};

/// PopPowerRequestObjectList (os corpos, na ordem de inserção) e os
/// contadores globais de PopPowerRequestAttributes.
struct Registry {
    objects: Vec<u64>,
    active: [u32; TYPE_COUNT],
}

static REGISTRY: SpinLock<Registry> = SpinLock::new(Registry { objects: Vec::new(), active: [0; TYPE_COUNT] });
/// PopPowerRequestId.
static NEXT_ID: AtomicU32 = AtomicU32::new(0);

fn request(object: u64) -> &'static PowerRequest {
    // SAFETY: os exports recebem o pedido devolvido pelo PoCreatePowerRequest.
    unsafe { PowerRequest::at(object) }
}

/// POWER_REQUEST_TYPE público -> índice interno.
fn internal_type(public: u32) -> Option<usize> {
    (public <= 3).then_some(public as usize)
}

/// PoCreatePowerRequest(PowerRequest*, DeviceObject, Context) -> NTSTATUS.
pub fn create(output: &Field<u64>, device: u64, context: u64) -> Result<u32, KernelError> {
    output.set(0);
    if device == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let reason = match super::reason_context::capture(context) {
        Ok(reason) => reason,
        Err(status) => return Ok(status),
    };
    let type_pointer = object_types::ensure(&POWER_REQUEST_TYPE).pointer;
    let cells = guest::alloc_bytes(8 + ObjectAttributes::SIZE);
    if cells == 0 {
        super::reason_context::destroy(reason);
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(cells, &[0u8; 8 + ObjectAttributes::SIZE as usize]);
    // SAFETY: as células alocadas acima: o PVOID de saída e os atributos.
    let (object_cell, attributes) = unsafe { (Field::<u64>::at(cells), ObjectAttributes::at(cells + 8)) };
    attributes.length.set(ObjectAttributes::SIZE as u32);
    attributes.attributes.set(OBJ_EXCLUSIVE);
    let status = object_create::create(KERNEL_MODE, type_pointer, attributes.address(), KERNEL_MODE, PowerRequest::SIZE as u32, PAGED_CHARGE, 0, object_cell.address());
    let object = object_cell.get();
    guest::free_bytes(cells);
    if status & 0x8000_0000 != 0 {
        super::reason_context::destroy(reason);
        return Ok(status);
    }
    guest::write_bytes(object, &[0u8; PowerRequest::SIZE as usize]);
    let body = request(object);
    body.session_id.set(crate::ntos::ps::session::current_process_session_id());
    body.reason.set(reason);
    body.id.set(NEXT_ID.fetch_add(1, Ordering::SeqCst).wrapping_add(1));
    body.supported_types.set(KERNEL_SUPPORTED_TYPES);
    REGISTRY.lock().objects.push(object);
    output.set(object);
    Ok(STATUS_SUCCESS)
}

/// PoSetPowerRequestInternal / PoClearPowerRequestInternal.
fn change(object: u64, public: u32, set: bool) -> u32 {
    let Some(kind) = internal_type(public) else { return STATUS_NOT_SUPPORTED };
    let body = request(object);
    let bit = 1u32 << kind;
    if body.supported_types.get() & bit == 0 {
        return STATUS_NOT_SUPPORTED;
    }
    let mut registry = REGISTRY.lock();
    let count = body.counts[kind].get();
    let overridden = body.override_mask.get() & bit != 0;
    if set {
        let Some(next) = count.checked_add(1) else { return STATUS_INTEGER_OVERFLOW };
        if next == 1 && !overridden {
            let Some(active) = registry.active[kind].checked_add(1) else { return STATUS_INTEGER_OVERFLOW };
            registry.active[kind] = active;
        }
        body.counts[kind].set(next);
    } else {
        if count == 0 {
            return STATUS_NOT_SUPPORTED;
        }
        body.counts[kind].set(count - 1);
        if count == 1 && !overridden {
            registry.active[kind] = registry.active[kind].wrapping_sub(1);
        }
    }
    STATUS_SUCCESS
}

/// PoSetPowerRequest(PowerRequest, Type) -> NTSTATUS.
pub fn set(object: u64, public: u32) -> u32 {
    change(object, public, true)
}

/// PoClearPowerRequest(PowerRequest, Type) -> NTSTATUS.
pub fn clear(object: u64, public: u32) -> u32 {
    change(object, public, false)
}

/// PoDeletePowerRequest(PowerRequest).
pub fn delete(object: u64) -> Result<(), KernelError> {
    let body = request(object);
    {
        let mut registry = REGISTRY.lock();
        if let Some(position) = registry.objects.iter().position(|&candidate| candidate == object) {
            registry.objects.remove(position);
            for kind in 0..TYPE_COUNT {
                if body.override_mask.get() & (1 << kind) == 0 && body.counts[kind].get() > 0 {
                    registry.active[kind] = registry.active[kind].wrapping_sub(1);
                }
            }
        }
    }
    // PopDeletePowerRequestObject: o contexto capturado sai com o objeto.
    let reason = body.reason.atomic().swap(0, Ordering::SeqCst);
    if reason != 0 {
        super::reason_context::destroy(reason);
    }
    object_reference::dereference_with_tag(object, reference_trace::DEFAULT_TAG, false)?;
    Ok(())
}

/// Quantos pedidos têm o tipo interno ligado (PopPowerRequestAttributes).
pub fn active_requests(kind: usize) -> u32 {
    REGISTRY.lock().active.get(kind).copied().unwrap_or(0)
}

/// Os pedidos vivos (PopPowerRequestObjectList).
pub fn live_requests() -> usize {
    REGISTRY.lock().objects.len()
}
