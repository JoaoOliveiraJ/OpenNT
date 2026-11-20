//! Pedidos de energia: os de kernel (PoCreatePowerRequest, PoSetPowerRequest,
//! PoClearPowerRequest e PoDeletePowerRequest), os de modo usuário
//! (NtPowerInformation PowerRequestCreate, PlmPowerRequestCreate e
//! PowerRequestAction) e o pedido legado por thread do
//! NtSetThreadExecutionState.
//!
//! ntoskrnl 19041:
//! - O tipo de objeto "PowerRequest" (PopPowerRequestInit 0xa704d4):
//!   GenericMapping {0x20000, 0x20000, 0x20000, 0x1F0000}, ValidAccessMask
//!   0x1F0000, InvalidAttributes 0x192, UseDefaultObject | MaintainHandleCount,
//!   NonPagedPoolNx, corpo de 0x98 bytes, CloseProcedure
//!   PopClosePowerRequestObject (0x6f72c0: no fechamento do último handle,
//!   SystemHandleCount 1, o PopPowerRequestCleanUp) e DeleteProcedure
//!   PopDeletePowerRequestObject (o PopPowerRequestCleanUp; o contexto
//!   capturado sai com o objeto).
//! - PopCreatePowerRequestObject 0x6f5d58: corpo zerado, SessionId do
//!   processo corrente, Id do contador PopPowerRequestId, o contexto e, num
//!   pedido de processo (o requisitante da captura), o dono UserMode e o
//!   ProcessId; num pedido de kernel, dono KernelMode e ProcessId 0.
//! - PoCreatePowerRequest(PowerRequest*, DeviceObject, Context) 0x772320:
//!   *PowerRequest = NULL; sem DeviceObject, STATUS_INVALID_PARAMETER; o
//!   contexto é capturado (PoCaptureReasonContext; erro volta) e o
//!   PopCreateKernelPowerRequest cria o objeto, marca os tipos aceitos (0x12:
//!   PowerRequestSystemRequired e o interno 4) e o põe no fim da
//!   PopPowerRequestObjectList.
//! - PopCreateUserPowerRequest(&Object, Special, Context) 0x6f70e8: o pedido
//!   especial (do PLM) é recusado com STATUS_NOT_SUPPORTED a um processo com
//!   WIN://SYSAPPID no token (PsQueryProcessAttributes); guarda Special
//!   (+0x88) e, num pedido comum, o EPROCESS criador (+0x78, sem referência:
//!   o PopPowerRequestCleanUp o zera); os tipos aceitos são 8
//!   (PowerRequestExecutionRequired) no especial, 0x3F numa sessão
//!   interativa (SessionIsInteractive da sessão do requisitante) e 0x1E nas
//!   outras (sem tela nem tela de bloqueio ativa).
//! - PoSetPowerRequest(PowerRequest, Type) 0x34af80 e PoClearPowerRequest
//!   0x34b770: o tipo público (Display 0, System 1, AwayMode 2, Execution 3)
//!   vira o índice interno; outro é STATUS_NOT_SUPPORTED. O
//!   PoSetPowerRequestInternal (0x34b170) recusa um índice acima de 5 ou fora
//!   dos tipos aceitos (STATUS_NOT_SUPPORTED), e o ExecutionRequired de um
//!   processo que não é o criador; soma o contador do tipo (estouro:
//!   STATUS_INTEGER_OVERFLOW) e, na passagem de 0 para 1 sem sobreposição do
//!   tipo (o OverrideMask, que só o UMPO liga), soma o contador global do tipo
//!   em PopPowerRequestAttributes. O PoClearPowerRequestInternal (0x34afac)
//!   também recusa o tipo cujo contador já é zero e desfaz na passagem de 1
//!   para 0.
//! - PoDeletePowerRequest 0x6a6180: PopPowerRequestCleanUp (tira da lista e,
//!   para cada tipo ainda ligado e não sobreposto, desconta o global) e o
//!   ObDereferenceObject.
//! - PopPowerRequestCreateInfo 0x6f72e0 (NtPowerInformation 43 e 72, só de
//!   modo usuário, senão STATUS_NOT_SUPPORTED): o contexto capturado de modo
//!   usuário, o PopCreateUserPowerRequest e um handle sem acesso
//!   (ObInsertObjectEx com DesiredAccess 0) na tabela do processo; o contexto
//!   é solto se o objeto não chega a existir.
//! - PopPowerRequestActionInfo 0x6f4e58 (NtPowerInformation 44, o
//!   POWER_REQUEST_ACTION {PowerRequestHandle, RequestType, SetAction,
//!   ProcessHandle}): o handle referenciado como PowerRequest (sem acesso),
//!   o tipo interno 4 só de modo usuário (senão STATUS_NOT_SUPPORTED), e o
//!   PoSet/PoClearPowerRequestInternal. O tipo 3 também passa pelo
//!   SeIsAppContainerOrIdentifyLevelContext (STATUS_ACCESS_DENIED a um
//!   AppContainer); o OpenNT não tem essa checagem e aceita. Um pedido
//!   especial vai ao PopSet/ClearSpecialRequest do PLM, que o OpenNT não tem
//!   (STATUS_NOT_SUPPORTED).
//! - NtSetThreadExecutionState(EsFlags, PreviousFlags*) 0x6f8630: de modo
//!   kernel é STATUS_NOT_SUPPORTED; flags com bits de 0x7FFFFFBC, ou
//!   ES_AWAYMODE_REQUIRED sem ES_CONTINUOUS, STATUS_INVALID_PARAMETER;
//!   PreviousFlags sondado para escrita. Com ES_CONTINUOUS, a primeira chamada
//!   cria o pedido da thread (o contexto não especificado e o
//!   PopCreateUserPowerRequest, em ETHREAD.LegacyPowerObject). O
//!   PopGetLegacyPowerRequestFlags dá as flags anteriores (ES_CONTINUOUS mais
//!   ES_DISPLAY_REQUIRED, ES_SYSTEM_REQUIRED e ES_AWAYMODE_REQUIRED pelos
//!   contadores 0, 1 e 2 do pedido; sem pedido, só ES_CONTINUOUS) e as que
//!   mudam; com ES_CONTINUOUS o PopApplyLegacyPowerRequestFlags liga ou
//!   desliga só os tipos que mudam. Sem ES_CONTINUOUS nada fica: o
//!   ES_SYSTEM_REQUIRED reinicia a contagem de ociosidade
//!   (PopSystemRequiredSet) e o ES_DISPLAY_REQUIRED, numa plataforma sem
//!   Modern Standby e numa sessão interativa, avisa o win32k da presença do
//!   usuário no console (PopNotifyConsoleUserPresent). O PspExitThread faz o
//!   PopPowerRequestCleanUp e solta o pedido da thread.
//!
//! As notificações de mudança (PopQueuePowerRequestCallback: as callbacks
//! de configuração de energia, o UMPO e o rastreamento) ainda não têm
//! destino no OpenNT; os contadores são os que elas leriam.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::hal::amd64::routine_stubs::Routine;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{Ethread, ListEntry, ObjectAttributes};
use crate::ntos::init::exports::Call;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_types::{self, TypeTemplate};
use crate::ntos::ob::{object_create, object_reference, reference_trace};
use crate::ntos::ps::{process, user_probe};
use crate::rtl::{KernelError, SpinLock};

const STATUS_SUCCESS: u32 = 0;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_INTEGER_OVERFLOW: u32 = 0xC000_0095;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
/// Os índices internos dos tipos (POWER_REQUEST_TYPE_INTERNAL).
const TYPE_COUNT: usize = 6;
const DISPLAY_REQUIRED: usize = 0;
const SYSTEM_REQUIRED: usize = 1;
const AWAY_MODE_REQUIRED: usize = 2;
const EXECUTION_REQUIRED: usize = 3;
/// Os tipos que um pedido de kernel aceita (PopCreateKernelPowerRequest).
const KERNEL_SUPPORTED_TYPES: u32 = 0x12;
/// Os tipos de um pedido de processo: o especial do PLM, o de uma sessão
/// interativa e o das outras.
const SPECIAL_SUPPORTED_TYPES: u32 = 0x8;
const INTERACTIVE_SUPPORTED_TYPES: u32 = 0x3F;
const NON_INTERACTIVE_SUPPORTED_TYPES: u32 = 0x1E;
/// OBJ_EXCLUSIVE dos atributos do PopCreatePowerRequestObject.
const OBJ_EXCLUSIVE: u32 = 0x20;
const KERNEL_MODE: u8 = 0;
const USER_MODE: u8 = 1;
/// Tamanho fixo cobrado do pool paginado além do contexto capturado.
const PAGED_CHARGE: u32 = 0x38;
/// A tag das referências do Po ao objeto ('PoPr').
const POWER_REQUEST_TAG: u32 = u32::from_le_bytes(*b"PoPr");

/// EXECUTION_STATE.
const ES_SYSTEM_REQUIRED: u32 = 0x1;
const ES_DISPLAY_REQUIRED: u32 = 0x2;
const ES_AWAYMODE_REQUIRED: u32 = 0x40;
const ES_CONTINUOUS: u32 = 0x8000_0000;
/// Os bits que o NtSetThreadExecutionState recusa.
const ES_INVALID_FLAGS: u32 = 0x7FFF_FFBC;

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
    _reserved_5c: Reserved<0x1C>,
    /// O EPROCESS criador de um pedido de processo comum.
    process: Field<u64>,
    _reserved_80: Reserved<0x8>,
    /// Pedido especial (PlmPowerRequestCreate).
    special: Field<u8>,
    _reserved_89: Reserved<0xF>,
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
    assert!(core::mem::offset_of!(PowerRequest, process) == 0x78);
    assert!(core::mem::offset_of!(PowerRequest, special) == 0x88);
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
    // SAFETY: os exports e os serviços recebem um pedido vivo (devolvido
    // pela criação, referenciado por handle ou guardado na thread).
    unsafe { PowerRequest::at(object) }
}

fn ethread(thread: u64) -> &'static Ethread {
    // SAFETY: ETHREAD viva (a corrente ou a que sai).
    unsafe { Ethread::at(thread) }
}

/// POWER_REQUEST_TYPE público -> índice interno.
fn internal_type(public: u32) -> Option<usize> {
    (public <= 3).then_some(public as usize)
}

/// O OBJECT_TYPE PowerRequest, com as rotinas de fechamento e remoção.
fn power_request_type() -> u64 {
    object_types::ensure(&POWER_REQUEST_TYPE).pointer
}

/// Rotinas entregues por ponteiro ao gerenciador de objetos.
pub const ROUTINES: &[Routine] = &[
    Routine { name: "PopClosePowerRequestObject", handler: close_routine },
    Routine { name: "PopDeletePowerRequestObject", handler: delete_routine },
];

/// PopClosePowerRequestObject(Process, Object, ProcessHandleCount,
/// SystemHandleCount).
fn close_routine(call: &Call) -> Result<u64, KernelError> {
    if call.arg(4) == 1 {
        clean_up(call.arg(2));
    }
    Ok(0)
}

/// PopDeletePowerRequestObject(Object).
fn delete_routine(call: &Call) -> Result<u64, KernelError> {
    let object = call.arg(1);
    clean_up(object);
    let reason = request(object).reason.atomic().swap(0, Ordering::SeqCst);
    super::reason_context::destroy(reason);
    Ok(0)
}

/// Liga as rotinas ao tipo PowerRequest e a limpeza do pedido legado à
/// saída das threads.
pub fn initialize_type() {
    let pointer = power_request_type();
    if let Some(info) = object_types::type_object(pointer) {
        if let Ok(close) = crate::hal::amd64::routine_stubs::address("PopClosePowerRequestObject") {
            info.type_info.close_procedure.set(close);
        }
        if let Ok(delete) = crate::hal::amd64::routine_stubs::address("PopDeletePowerRequestObject") {
            info.type_info.delete_procedure.set(delete);
        }
    }
    process::register_thread_exit_routine(thread_rundown);
}

/// PopCreatePowerRequestObject(&Object, Reason): o objeto vivo (sem
/// lista), dono UserMode e com ProcessId quando o requisitante é um
/// processo.
fn create_object(reason: u64) -> Result<u64, u32> {
    let user = super::reason_context::requested_by_process(reason);
    let type_pointer = power_request_type();
    let cells = guest::alloc_bytes(8 + ObjectAttributes::SIZE);
    if cells == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(cells, &[0u8; 8 + ObjectAttributes::SIZE as usize]);
    // SAFETY: as células alocadas acima: o PVOID de saída e os atributos.
    let (object_cell, attributes) = unsafe { (Field::<u64>::at(cells), ObjectAttributes::at(cells + 8)) };
    attributes.length.set(ObjectAttributes::SIZE as u32);
    attributes.attributes.set(OBJ_EXCLUSIVE);
    let ownership = if user { USER_MODE } else { KERNEL_MODE };
    let status = object_create::create(KERNEL_MODE, type_pointer, attributes.address(), ownership, PowerRequest::SIZE as u32, PAGED_CHARGE, 0, object_cell.address());
    let object = object_cell.get();
    guest::free_bytes(cells);
    if status & 0x8000_0000 != 0 {
        return Err(status);
    }
    guest::write_bytes(object, &[0u8; PowerRequest::SIZE as usize]);
    let body = request(object);
    body.session_id.set(crate::ntos::ps::session::current_process_session_id());
    if user {
        body.process_id.set(process::get_current_process_id() as u32);
    }
    body.reason.set(reason);
    body.id.set(NEXT_ID.fetch_add(1, Ordering::SeqCst).wrapping_add(1));
    Ok(object)
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
    let object = match create_object(reason) {
        Ok(object) => object,
        Err(status) => {
            super::reason_context::destroy(reason);
            return Ok(status);
        }
    };
    request(object).supported_types.set(KERNEL_SUPPORTED_TYPES);
    REGISTRY.lock().objects.push(object);
    output.set(object);
    Ok(STATUS_SUCCESS)
}

/// SessionIsInteractive(SessionId): toda sessão que não é a dos serviços;
/// a sessão 0 só quando é a do console ativo.
fn session_is_interactive(session: u32) -> bool {
    if session == u32::MAX {
        return false;
    }
    session != 0 || crate::ntos::rtl::shared_data::active_console_id().is_ok_and(|console| console == 0)
}

/// PopCreateUserPowerRequest(&Object, Special, Reason): o pedido de
/// processo, já na lista; o contexto passa a ser do objeto.
pub fn create_user(special: bool, reason: u64) -> Result<u64, u32> {
    let current = process::get_current_process();
    if special && crate::ntos::ps::security::is_system_application(current) {
        return Err(STATUS_NOT_SUPPORTED);
    }
    let object = create_object(reason)?;
    let body = request(object);
    body.special.set(special as u8);
    if !special {
        body.process.set(current);
    }
    let supported = if special {
        SPECIAL_SUPPORTED_TYPES
    } else if session_is_interactive(crate::ntos::mm::session::session_id_ex(current)) {
        INTERACTIVE_SUPPORTED_TYPES
    } else {
        NON_INTERACTIVE_SUPPORTED_TYPES
    };
    body.supported_types.set(supported);
    REGISTRY.lock().objects.push(object);
    Ok(object)
}

/// PoSetPowerRequestInternal / PoClearPowerRequestInternal sobre o índice
/// interno.
fn change_internal(object: u64, kind: usize, set: bool) -> u32 {
    if kind >= TYPE_COUNT {
        return STATUS_NOT_SUPPORTED;
    }
    let body = request(object);
    let bit = 1u32 << kind;
    if body.supported_types.get() & bit == 0 {
        return STATUS_NOT_SUPPORTED;
    }
    if set && kind == EXECUTION_REQUIRED && body.process.get() != process::get_current_process() {
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
    internal_type(public).map_or(STATUS_NOT_SUPPORTED, |kind| change_internal(object, kind, true))
}

/// PoClearPowerRequest(PowerRequest, Type) -> NTSTATUS.
pub fn clear(object: u64, public: u32) -> u32 {
    internal_type(public).map_or(STATUS_NOT_SUPPORTED, |kind| change_internal(object, kind, false))
}

/// PopPowerRequestCleanUp: tira o pedido da lista e desconta os tipos ainda
/// ligados (uma segunda limpeza não faz nada).
fn clean_up(object: u64) {
    let body = request(object);
    let mut registry = REGISTRY.lock();
    let Some(position) = registry.objects.iter().position(|&candidate| candidate == object) else { return };
    registry.objects.remove(position);
    for kind in 0..TYPE_COUNT {
        if body.override_mask.get() & (1 << kind) == 0 && body.counts[kind].get() > 0 {
            registry.active[kind] = registry.active[kind].wrapping_sub(1);
        }
    }
    body.process.set(0);
}

/// PoDeletePowerRequest(PowerRequest).
pub fn delete(object: u64) -> Result<(), KernelError> {
    clean_up(object);
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

/// SystemExecutionState (NtPowerInformation 16): ES_SYSTEM_REQUIRED com
/// algum pedido de sistema ligado e ES_DISPLAY_REQUIRED com algum de tela.
pub fn system_execution_state() -> u32 {
    let registry = REGISTRY.lock();
    (if registry.active[SYSTEM_REQUIRED] != 0 { ES_SYSTEM_REQUIRED } else { 0 }) | (if registry.active[DISPLAY_REQUIRED] != 0 { ES_DISPLAY_REQUIRED } else { 0 })
}

/// PopPowerRequestCreateInfo(Context, Special): o handle do pedido novo
/// (o NtPowerInformation já conferiu a entrada de 0x28 bytes e a saída de 8).
pub fn create_info(context: &[u8], special: bool) -> Result<u64, u32> {
    let reason = super::reason_context::capture_user(context)?;
    let object = match create_user(special, reason) {
        Ok(object) => object,
        Err(status) => {
            super::reason_context::destroy(reason);
            return Err(status);
        }
    };
    let cell = guest::alloc_bytes(8);
    if cell == 0 {
        let _ = delete(object);
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write64(cell, 0);
    let _ = object_reference::reference_with_tag(object, POWER_REQUEST_TAG, false);
    let status = object_create::insert(object, 0, 0, 0, cell).unwrap_or(STATUS_INSUFFICIENT_RESOURCES);
    let handle = guest::read64(cell);
    guest::free_bytes(cell);
    let _ = object_reference::dereference_with_tag(object, POWER_REQUEST_TAG, false);
    if status & 0x8000_0000 != 0 {
        return Err(status);
    }
    Ok(handle)
}

/// PopPowerRequestActionInfo sobre o POWER_REQUEST_ACTION capturado (0x18
/// bytes): {PowerRequestHandle, RequestType, SetAction, ProcessHandle}.
pub fn action_info(action: &[u8]) -> Result<u32, KernelError> {
    let handle = u64::from_le_bytes(action[0..8].try_into().unwrap_or([0; 8]));
    let kind = u32::from_le_bytes(action[8..12].try_into().unwrap_or([0; 4]));
    let set = action[12] != 0;
    let slot = guest::alloc_bytes(8);
    if slot == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    let status = object_reference::reference_by_handle_with_tag(handle, 0, power_request_type(), USER_MODE, POWER_REQUEST_TAG, slot, 0)? as u32;
    let object = guest::read64(slot);
    guest::free_bytes(slot);
    if status != 0 {
        return Ok(status);
    }
    let result = if request(object).special.get() != 0 {
        // PopSetSpecialRequest/PopClearSpecialRequest: o pedido do PLM.
        STATUS_NOT_SUPPORTED
    } else {
        change_internal(object, kind as usize, set)
    };
    object_reference::dereference_with_tag(object, POWER_REQUEST_TAG, false)?;
    Ok(result)
}

/// PopGetLegacyPowerRequestFlags(Request, NewFlags): (as flags anteriores,
/// os bits que mudam fora o ES_CONTINUOUS).
fn legacy_flags(object: u64, new_flags: u32) -> (u32, u32) {
    if object == 0 {
        return (ES_CONTINUOUS, 0);
    }
    let counts = &request(object).counts;
    let mut previous = ES_CONTINUOUS;
    if counts[DISPLAY_REQUIRED].get() != 0 {
        previous |= ES_DISPLAY_REQUIRED;
    }
    if counts[SYSTEM_REQUIRED].get() != 0 {
        previous |= ES_SYSTEM_REQUIRED;
    }
    if counts[AWAY_MODE_REQUIRED].get() != 0 {
        previous |= ES_AWAYMODE_REQUIRED;
    }
    (previous, (previous ^ new_flags) & !ES_CONTINUOUS)
}

/// PopApplyLegacyPowerRequestFlags(Request, NewFlags, Changed).
fn apply_legacy_flags(object: u64, new_flags: u32, changed: u32) {
    for (flag, kind) in [(ES_SYSTEM_REQUIRED, SYSTEM_REQUIRED), (ES_DISPLAY_REQUIRED, DISPLAY_REQUIRED), (ES_AWAYMODE_REQUIRED, AWAY_MODE_REQUIRED)] {
        if changed & flag != 0 {
            let _ = change_internal(object, kind, new_flags & flag != 0);
        }
    }
}

/// NtSetThreadExecutionState(EsFlags, PreviousFlags*) de modo usuário.
pub fn set_thread_execution_state(flags: u32, previous_flags: u64) -> Result<u32, KernelError> {
    if flags & ES_INVALID_FLAGS != 0 || (flags & ES_AWAYMODE_REQUIRED != 0 && flags & ES_CONTINUOUS == 0) {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if !user_probe::probe_user_write(previous_flags, 4) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let continuous = flags & ES_CONTINUOUS != 0;
    let thread = ethread(process::get_current_thread());
    let mut object = thread.legacy_power_object.get();
    if object == 0 && continuous {
        let reason = match super::reason_context::capture_user(&[]) {
            Ok(reason) => reason,
            Err(status) => return Ok(status),
        };
        object = match create_user(false, reason) {
            Ok(object) => object,
            Err(status) => {
                super::reason_context::destroy(reason);
                return Ok(status);
            }
        };
        thread.legacy_power_object.set(object);
    }
    let (previous, changed) = legacy_flags(object, flags);
    if let Err(error) = guest::try_write::<u32>(previous_flags, previous) {
        return Ok(error.status);
    }
    if continuous {
        apply_legacy_flags(object, flags, changed);
        return Ok(STATUS_SUCCESS);
    }
    if flags & ES_SYSTEM_REQUIRED != 0 {
        super::system_state::system_required_set();
    }
    if flags & ES_DISPLAY_REQUIRED != 0 && super::power_information::platform_aoac() == 0 && session_is_interactive(crate::ntos::mm::session::session_id_ex(process::get_current_process())) {
        super::win32_callout::notify_console_user_present(true, super::win32_callout::USER_PRESENT_EXECUTION_STATE);
    }
    Ok(STATUS_SUCCESS)
}

/// As flags do pedido legado de uma thread (ES_CONTINUOUS sem pedido).
pub fn thread_execution_state(thread: u64) -> u32 {
    legacy_flags(ethread(thread).legacy_power_object.get(), 0).0
}

/// O PspExitThread: o pedido legado da thread sai com ela.
fn thread_rundown(thread: u64) {
    let cell = &ethread(thread).legacy_power_object;
    let object = cell.atomic().swap(0, Ordering::SeqCst);
    if object != 0 {
        clean_up(object);
        let _ = object_reference::dereference_with_tag(object, reference_trace::DEFAULT_TAG, false);
    }
}

