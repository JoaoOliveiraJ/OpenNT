//! O objeto IRTimer (ExpIRTimerObjectType), o timer do NtCreateTimer2, do
//! NtCreateIRTimer, do NtSetTimer2, do NtSetIRTimer, do NtCancelTimer2 e do
//! ramo Timer2 do NtSetTimerEx, com o acesso a um identificador IR.
//!
//! Como no ntoskrnl 19041:
//!
//! - O corpo tem 0xA8 bytes: o KTIMER2 no início (`ke/timer2.rs`, o objeto
//!   de espera), um qword zerado em +0x88, o DueTime e o NoWakeTolerance do
//!   último set em +0x90/+0x98 e os atributos em +0xA0. O Header.Type é
//!   Timer2NotificationObject (0x18) com o bit 31 dos atributos, senão
//!   Timer2SynchronizationObject (0x19).
//! - NtCreateTimer2(TimerHandle, Reserved, ObjectAttributes, Attributes,
//!   DesiredAccess), na ordem do original: atributos fora de 0x8000000E, ou
//!   NO_WAKE (8) com IR (2) ou HIGH_RESOLUTION (4)
//!   (ExpExTimerAttributesAreValid, rva 0x35a780), dão
//!   STATUS_INVALID_PARAMETER_4; um ObjectAttributes dá
//!   STATUS_INVALID_PARAMETER_3 (o objeto não tem nome); Reserved sem IR dá
//!   STATUS_INVALID_PARAMETER_2; só então o handle de saída e o ULONG de
//!   Reserved (o identificador IR) são sondados. HIGH_RESOLUTION é aceito (o
//!   KTIMER2 de alta resolução). Com IR, o identificador passa pelo
//!   ExpCheckIRTimerAccess (rva 0x7724c8); sem hardware de wake IR, o timer
//!   IR é um Timer2 com o TypeFlags IdleResilient. O NtCreateIRTimer
//!   (TimerHandle, IrTimerId, DesiredAccess) é o NtCreateTimer2 sem
//!   OBJECT_ATTRIBUTES e com o atributo IR.
//! - O identificador IR é `índice | sub << 16`: índice de 1 a 15 e sub até o
//!   máximo do ExpIRTimerDescs (senão STATUS_INVALID_PARAMETER). De modo
//!   usuário, um índice com SID exige o SID na identidade do chamador
//!   (RtlCheckTokenMembership); sem SID, o ExpCheckWakeTimerAccess (acesso 1
//!   no ExpWakeTimerSecurityDescriptor: a DACL dá o bit 1 ao SYSTEM e a dois
//!   SIDs de serviço) e o sub abaixo do máximo (ExCheckValidIRTimerId). Fora
//!   disso, STATUS_ACCESS_DENIED.
//! - ExpSetTimerObject2(Timer, DueTime*, Period, Parameters*): Period num
//!   timer IR dá STATUS_INVALID_PARAMETER; T2_SET_PARAMETERS com Version != 0
//!   ou NoWakeTolerance < -1 dá STATUS_INVALID_PARAMETER_3; com DueTime, o
//!   KeSetTimer2 (relativo sobre o tempo de interrupção, absoluto convertido
//!   da hora do sistema; SignalState volta a 0); sem DueTime, o
//!   KeCancelTimer2. O NtCancelTimer2 é o set sem DueTime (o Parameters dele
//!   não é lido).
//! - O vencimento é o do KTIMER2 (`ke/timer2::expire_due`, no pump dos
//!   timers): SignalState = 1 e as esperas no corpo testadas.
//!
//! O corpo é um objeto de espera do registro de `ob/objects/dispatcher`
//! (tipo "IRTimer", handle de usuário de tipo "timer").

use alloc::vec::Vec;

use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::Ktimer2;
use crate::ntos::ke::timer2;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::objects::dispatcher::{self as dispatcher_objects, DispatcherHooks, UserDispatcher};
use crate::ntos::ob::object_types;
use crate::ntos::ps::user::state;
use crate::ntos::se::model::sid;
use crate::rtl::KernelError;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;
/// TIMER_MODIFY_STATE.
pub const TIMER_MODIFY_STATE: u32 = 2;
/// EX_TIMER_*: IR (2), HIGH_RESOLUTION (4), NO_WAKE (8) e NOTIFICATION
/// (bit 31).
pub const ATTRIBUTE_IR: u32 = 2;
const ATTRIBUTE_NO_WAKE: u32 = 8;
const VALID_ATTRIBUTES: u32 = 0x8000_000E;
/// KTIMER2.TypeFlags de um timer IR (IdleResilient).
const TYPE_IDLE_RESILIENT: u8 = 2;
/// O tipo do handle de usuário deste objeto.
pub const KIND: &str = "timer";

/// Uma entrada do ExpIRTimerDescs: o nome, as subautoridades do SID de
/// serviço (S-1-5-80-...) e o maior sub.
struct IrTimerDescriptor {
    _name: &'static str,
    service: Option<[u32; 5]>,
    maximum: u16,
}

const fn descriptor(name: &'static str, service: Option<[u32; 5]>, maximum: u16) -> IrTimerDescriptor {
    IrTimerDescriptor { _name: name, service, maximum }
}

/// ExpIRTimerDescs (rva 0x5240, 16 entradas).
const DESCRIPTORS: [IrTimerDescriptor; 16] = [
    descriptor("Unknown", None, 1),
    descriptor("TestIdentifier", None, 1),
    descriptor("BrokerInfrastructure", Some([1_988_685_059, 1_921_232_356, 378_231_328, 2_704_142_597, 890_457_928]), 1),
    descriptor("TimeBrokerSvc", Some([410_965_207, 2_550_896_871, 1_717_734_767, 2_321_332_215, 3_755_966_139]), 1),
    descriptor("LfSvc", Some([3_704_025_948, 1_094_794_811, 1_175_534_343, 2_088_422_159, 783_153_058]), 9),
    descriptor("WinLogon", None, 1),
    descriptor("Power", Some([2_343_416_411, 2_961_288_913, 598_565_901, 392_633_850, 2_111_459_193]), 2),
    descriptor("SensorService", Some([869_152_694, 422_618_349, 3_448_047_118, 1_397_179_936, 2_828_741_493]), 1),
    descriptor("NtosPo", None, 6),
    descriptor("Acpi", None, 1),
    descriptor("Button", None, 1),
    descriptor("MsGpioClx", None, 2),
    descriptor("ButtonConverter", None, 1),
    descriptor("MsGpioWin32", None, 2),
    descriptor("KNetPwrDepBroker", None, 2),
    descriptor("Cmbatt", None, 1),
];

/// Os SIDs de serviço que a DACL do ExpWakeTimerSecurityDescriptor lista
/// depois do SYSTEM.
const WAKE_TIMER_SERVICES: [[u32; 5]; 2] = [[3_557_709_225, 3_446_934_100, 2_592_608_561, 3_401_846_376, 4_273_827_271], [3_704_025_948, 1_094_794_811, 1_175_534_343, 2_088_422_159, 783_153_058]];

/// S-1-5-80-a-b-c-d-e.
fn service_sid(parts: &[u32; 5]) -> Vec<u8> {
    sid(5, &[80, parts[0], parts[1], parts[2], parts[3], parts[4]])
}

/// RtlCheckTokenMembership(NULL, Sid) da identidade do chamador.
fn caller_is_member(identifier: &[u8]) -> bool {
    let block = guest::alloc_bytes(8 + identifier.len() as u64);
    if block == 0 {
        return false;
    }
    guest::write_bytes(block + 8, identifier);
    let status = crate::ntos::se::token::membership::check(0, block + 8, block).unwrap_or(STATUS_ACCESS_DENIED);
    let member = status & 0x8000_0000 == 0 && guest::read8(block) != 0;
    guest::free_bytes(block);
    member
}

/// ExpCheckIRTimerAccess(Id, UserMode): o NTSTATUS.
pub fn check_user_access(id: u32) -> u32 {
    let (index, sub) = ((id & 0xFFFF) as usize, (id >> 16) as u16);
    if !(1..=15).contains(&index) || sub > DESCRIPTORS[index].maximum {
        return STATUS_INVALID_PARAMETER;
    }
    let allowed = match &DESCRIPTORS[index].service {
        Some(service) => caller_is_member(&service_sid(service)),
        None => {
            let wake_access = caller_is_member(&sid(5, &[18])) || WAKE_TIMER_SERVICES.iter().any(|service| caller_is_member(&service_sid(service)));
            wake_access && sub < DESCRIPTORS[index].maximum
        }
    };
    if allowed { 0 } else { STATUS_ACCESS_DENIED }
}

/// O corpo do IRTimer no layout do 19041.
#[repr(C)]
struct IrTimer {
    ke_timer: Ktimer2,
    _reserved_88: Field<u64>,
    due_time: Field<i64>,
    no_wake_tolerance: Field<i64>,
    attributes: Field<u32>,
    _pad_a4: Reserved<4>,
}

// SAFETY: #[repr(C)] só de células e de structs do NT.
unsafe impl NtStruct for IrTimer {}

const _: () = {
    assert!(core::mem::size_of::<IrTimer>() == 0xA8);
    assert!(core::mem::offset_of!(IrTimer, due_time) == 0x90);
    assert!(core::mem::offset_of!(IrTimer, no_wake_tolerance) == 0x98);
    assert!(core::mem::offset_of!(IrTimer, attributes) == 0xA0);
};

fn body(pointer: u64) -> &'static IrTimer {
    // SAFETY: corpo IRTimer vivo, retido por quem chama.
    unsafe { IrTimer::at(pointer) }
}

/// O OBJECT_TYPE "IRTimer" (ExpIRTimerObjectType).
pub fn timer_type() -> u64 {
    object_types::user_type(KIND).map_or(0, |object_type| object_type.pointer)
}

/// ExpExTimerAttributesAreValid.
pub fn attributes_are_valid(attributes: u32) -> bool {
    attributes & !VALID_ATTRIBUTES == 0 && !(attributes & ATTRIBUTE_NO_WAKE != 0 && attributes & 0x6 != 0)
}

/// O último ponteiro solto: o KTIMER2 sai da fila antes de o corpo voltar.
fn dispose(pointer: u64) {
    timer2::cancel(&body(pointer).ke_timer);
    guest::free_bytes(pointer);
}

/// NtCreateTimer2 de modo usuário. Devolve o NTSTATUS.
pub fn create_from_user(handle_out: u64, reserved: u64, object_attributes: u64, attributes: u32, access: u32) -> Result<u32, KernelError> {
    if !attributes_are_valid(attributes) {
        return Ok(STATUS_INVALID_PARAMETER_4);
    }
    if object_attributes != 0 {
        return Ok(STATUS_INVALID_PARAMETER_3);
    }
    let ir = attributes & ATTRIBUTE_IR != 0;
    if reserved != 0 && !ir {
        return Ok(STATUS_INVALID_PARAMETER_2);
    }
    if !state::probe_user_write(handle_out, 8) || (reserved != 0 && !state::probe_user_read(reserved, 4)) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let identifier = if reserved != 0 {
        match guest::try_read::<u32>(reserved) {
            Ok(identifier) => identifier,
            Err(_) => return Ok(STATUS_ACCESS_VIOLATION),
        }
    } else {
        0
    };
    if ir {
        let status = check_user_access(identifier);
        if status != 0 {
            return Ok(status);
        }
    }
    let pointer = guest::alloc_bytes(IrTimer::SIZE);
    if pointer == 0 {
        return Ok(STATUS_NO_MEMORY);
    }
    guest::write_bytes(pointer, &[0u8; IrTimer::SIZE as usize]);
    let timer = body(pointer);
    timer2::initialize(&timer.ke_timer, 0, 0, attributes);
    timer.attributes.set(attributes);
    if let Err(error) = dispatcher_objects::create(pointer, KIND, dispose, None, 0, true, DispatcherHooks::default()) {
        guest::free_bytes(pointer);
        return if error.status != 0 { Ok(error.status) } else { Err(error) };
    }
    state::guarded(|| dispatcher_objects::publish(pointer, handle_out, access, 0, 0, true, None))
}

/// O corpo de um handle de usuário IRTimer com `access`, retido (o
/// ObReferenceObjectByHandle com ExpIRTimerObjectType).
fn reference(handle: u64, access: u32) -> Result<u64, u32> {
    let Some(entry) = state::get_user_handle(handle) else { return Err(STATUS_INVALID_HANDLE) };
    if entry.kind() != KIND {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    if entry.access() & access != access {
        return Err(STATUS_ACCESS_DENIED);
    }
    let pointer = entry.downcast::<UserDispatcher>().map(|dispatcher| dispatcher.pointer).ok_or(STATUS_OBJECT_TYPE_MISMATCH)?;
    dispatcher_objects::reference(pointer).map_err(|_| STATUS_INVALID_HANDLE)?;
    Ok(pointer)
}

/// ExpSetTimerObject2(Timer, DueTime*, Period, Parameters*) sobre o corpo
/// já referenciado, que a chamada solta. `parameters` é o T2_SET_PARAMETERS
/// capturado (Version, NoWakeTolerance); `period` em 100 ns.
pub fn set_object(pointer: u64, due_time: Option<i64>, period: i64, parameters: Option<(u32, i64)>) -> u32 {
    let timer = body(pointer);
    let status = (|| {
        if period != 0 && timer.ke_timer.type_flags.get() & TYPE_IDLE_RESILIENT != 0 {
            return STATUS_INVALID_PARAMETER;
        }
        if parameters.is_some_and(|(version, tolerance)| version != 0 || tolerance < -1) {
            return STATUS_INVALID_PARAMETER_3;
        }
        match due_time {
            Some(due) => {
                let tolerance = parameters.map(|(_, tolerance)| tolerance);
                timer.due_time.set(due);
                timer.no_wake_tolerance.set(tolerance.unwrap_or(0));
                timer2::set_with_tolerance(&timer.ke_timer, due, period, tolerance.map(|tolerance| tolerance as u64));
            }
            None => {
                timer2::cancel(&timer.ke_timer);
            }
        }
        0
    })();
    let _ = dispatcher_objects::dereference(pointer);
    status
}

/// ExpSetTimer2 depois da captura: o handle com TIMER_MODIFY_STATE e o
/// ExpSetTimerObject2.
pub fn set(handle: u64, due_time: Option<i64>, period: i64, parameters: Option<(u32, i64)>) -> u32 {
    match reference(handle, TIMER_MODIFY_STATE) {
        Ok(pointer) => set_object(pointer, due_time, period, parameters),
        Err(status) => status,
    }
}

/// NtCancelTimer2(TimerHandle, Parameters): o ExpSetTimer2 sem DueTime.
pub fn cancel(handle: u64) -> u32 {
    set(handle, None, 0, None)
}
