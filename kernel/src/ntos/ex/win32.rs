//! Os tipos de objeto do subsistema Win32 que o executive cria no boot (o
//! ExpWin32Initialization do ntoskrnl 19041): WindowStation, Desktop,
//! Composition, RawInputManager, CoreMessaging e ActivationObject,
//! publicados nas células exportadas ExWindowStationObjectType,
//! ExDesktopObjectType, ExCompositionObjectType, ExRawInputManagerObjectType,
//! ExCoreMessagingObjectType e ExActivationObjectType. O win32k não cria
//! esses tipos: ele os importa, cria os objetos com eles (ObCreateObject) e
//! ajusta o GenericMapping e o ValidAccessMask do TypeInfo na própria
//! inicialização.
//!
//! O OBJECT_TYPE_INITIALIZER de cada um é o do ntoskrnl: mapeamento
//! {0x20000, 0x20000, 0x20000, 0xF0000} (Exp*Mapping), ValidAccessMask
//! 0xF0000, InvalidAttributes 0x130 (OBJ_PERMANENT | OBJ_EXCLUSIVE |
//! OBJ_OPENLINK) e PoolType NonPagedPoolNx (0x221 no ActivationObject); as
//! flags são SecurityRequired | MaintainHandleCount (0x18) na WindowStation,
//! mais SupportsObjectCallbacks (0x58) no Desktop, UnnamedObjectsOnly |
//! SecurityRequired | MaintainHandleCount (0x1A) nos três seguintes e mais
//! UseDefaultObject (0x1E) no ActivationObject; o Composition leva
//! ObjectTypeCode 0x400.
//!
//! As rotinas Open/OkayToClose/Close/Delete dos seis tipos e a Parse da
//! WindowStation são as ExpWin32*Procedure do ntoskrnl: cada uma monta o
//! bloco de parâmetros da rotina e chama o callout do win32k pelo
//! PsInvokeWin32Callout no modo de sessão (Flags 1, com o SessionId que o
//! win32k grava no primeiro ULONG de todo objeto desses tipos), escolhendo o
//! callout pelo tipo do objeto (o ObTypeIndexTable do cabeçalho):
//!
//! | tipo            | Open | OkayToClose | Close | Delete | Parse |
//! |-----------------|------|-------------|-------|--------|-------|
//! | WindowStation   | 0x10 | 0x0C        | 0x0D  | 0x0E   | 0x0F  |
//! | Desktop         | 0x08 | 0x09        | 0x0A  | 0x0B   |       |
//! | Composition     | 0x12 | 0x13        | 0x14  | 0x15   |       |
//! | RawInputManager | 0x1B | 0x1C        | 0x1D  | 0x1E   |       |
//! | CoreMessaging   | 0x21 | 0x22        | 0x23  | 0x24   |       |
//! | Activation      | 0x25 | 0x26        | 0x27  | 0x28   |       |
//!
//! Os blocos: Open {OpenReason, 0, Process, Object, GrantedAccess,
//! HandleCount}; OkayToClose {Process, Object, Handle, PreviousMode};
//! Close {Process, Object, ProcessHandleCount, SystemHandleCount}; Delete
//! {Object}; Parse {ParseObject, ObjectType, AccessState, AccessMode,
//! Attributes, CompleteName, RemainingName, Context, SecurityQos, Object*}.
//! Um tipo que não é desses é STATUS_UNSUCCESSFUL; o OkayToClose devolve o
//! sucesso do callout como BOOLEAN.

use crate::ntos::mm::kernel_data;
use crate::ntos::ob::object_types::{self, TypeTemplate};

/// GENERIC_READ/WRITE/EXECUTE -> READ_CONTROL e GENERIC_ALL ->
/// STANDARD_RIGHTS_REQUIRED (Exp*Mapping).
const WIN32_MAPPING: [u32; 4] = [0x2_0000, 0x2_0000, 0x2_0000, 0xF_0000];
const VALID_ACCESS: u32 = 0xF_0000;
/// OBJ_PERMANENT | OBJ_EXCLUSIVE | OBJ_OPENLINK.
const INVALID_ATTRIBUTES: u32 = 0x130;
const NON_PAGED_POOL_NX: u32 = 0x200;

const fn win32_type(name: &'static str, flags: u16, object_type_code: u32, pool_type: u32) -> TypeTemplate {
    TypeTemplate { name, mapping: WIN32_MAPPING, valid_access: VALID_ACCESS, flags, object_type_code, invalid_attributes: INVALID_ATTRIBUTES, pool_type, paged_charge: 0, non_paged_charge: 0 }
}

/// (célula exportada, inicializador), na ordem do ExpWin32Initialization.
pub const TYPES: [(&str, TypeTemplate); 6] = [
    ("ExWindowStationObjectType", win32_type("WindowStation", 0x18, 0, NON_PAGED_POOL_NX)),
    ("ExDesktopObjectType", win32_type("Desktop", 0x58, 0, NON_PAGED_POOL_NX)),
    ("ExCompositionObjectType", win32_type("Composition", 0x1A, 0x400, NON_PAGED_POOL_NX)),
    ("ExRawInputManagerObjectType", win32_type("RawInputManager", 0x1A, 0, NON_PAGED_POOL_NX)),
    ("ExCoreMessagingObjectType", win32_type("CoreMessaging", 0x1A, 0, NON_PAGED_POOL_NX)),
    ("ExActivationObjectType", win32_type("ActivationObject", 0x1E, 0, 0x221)),
];

/// ExpWin32Initialization: cria os seis tipos (uma vez) e publica as
/// células.
pub fn initialize() {
    use crate::ntos::init::exports::private_routines;
    let routines = [
        private_routines::address("ExpWin32OpenProcedure"),
        private_routines::address("ExpWin32OkayToCloseProcedure"),
        private_routines::address("ExpWin32CloseProcedure"),
        private_routines::address("ExpWin32DeleteProcedure"),
        private_routines::address("ExpWin32ParseProcedure"),
    ];
    for (index, (cell, template)) in TYPES.iter().enumerate() {
        let pointer = object_types::ensure(template).pointer;
        kernel_data::write(cell, pointer);
        if let Some(info) = object_types::type_object(pointer) {
            info.type_info.open_procedure.set(routines[0]);
            info.type_info.okay_to_close_procedure.set(routines[1]);
            info.type_info.close_procedure.set(routines[2]);
            info.type_info.delete_procedure.set(routines[3]);
            // Só a WindowStation tem a ParseProcedure.
            if index == 0 {
                info.type_info.parse_procedure.set(routines[4]);
            }
        }
    }
}

const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;

/// As rotinas de um tipo Win32.
#[derive(Clone, Copy)]
enum Routine {
    Open = 0,
    OkayToClose = 1,
    Close = 2,
    Delete = 3,
}

/// O callout (PSW32CALLOUTTYPE) de cada rotina para cada tipo, na ordem de
/// [`TYPES`].
const CALLOUTS: [[i32; 4]; 6] = [[0x10, 0x0C, 0x0D, 0x0E], [0x08, 0x09, 0x0A, 0x0B], [0x12, 0x13, 0x14, 0x15], [0x1B, 0x1C, 0x1D, 0x1E], [0x21, 0x22, 0x23, 0x24], [0x25, 0x26, 0x27, 0x28]];
/// O callout da ParseProcedure da WindowStation.
const WINDOW_STATION_PARSE: i32 = 0x0F;

/// O callout de `routine` para o tipo do objeto `body`, se for Win32.
fn callout(body: u64, routine: Routine) -> Option<i32> {
    let object_type = crate::ntos::ob::object_header::object_type(body)?;
    TYPES.iter().position(|(cell, _)| kernel_data::read(cell) == object_type).map(|index| CALLOUTS[index][routine as usize])
}

/// O SessionId que o win32k grava no primeiro ULONG do objeto.
fn object_session(body: u64) -> u32 {
    crate::ntos::mm::guest_memory::read32(body)
}

/// Um bloco de parâmetros de `size` bytes zerado, que `fill` preenche; o
/// callout roda no modo de sessão do objeto `body`.
fn invoke(body: u64, callout_type: i32, size: u64, fill: impl FnOnce(u64)) -> u32 {
    use crate::ntos::mm::guest_memory as guest;
    let block = guest::alloc_bytes(size);
    if block == 0 {
        return 0xC000_009A;
    }
    guest::write_bytes(block, &alloc::vec![0u8; size as usize]);
    fill(block);
    let status = crate::ntos::ps::win32::invoke_callout_for_session(callout_type, block, object_session(body));
    guest::free_bytes(block);
    status
}

/// ExpWin32OpenProcedure(OpenReason, AccessMode, Process, Object,
/// &GrantedAccess, HandleCount): o GrantedAccess vai por valor no bloco.
pub fn open_procedure(open_reason: u32, process: u64, body: u64, granted_access: u64, handle_count: u32) -> u32 {
    use crate::ntos::mm::guest_memory as guest;
    let Some(callout_type) = callout(body, Routine::Open) else { return STATUS_UNSUCCESSFUL };
    let granted = guest::read32(granted_access);
    invoke(body, callout_type, 0x20, |block| {
        guest::write32(block, open_reason);
        guest::write64(block + 8, process);
        guest::write64(block + 0x10, body);
        guest::write32(block + 0x18, granted);
        guest::write32(block + 0x1C, handle_count);
    })
}

/// ExpWin32OkayToCloseProcedure(Process, Object, Handle, PreviousMode).
pub fn okay_to_close_procedure(process: u64, body: u64, handle: u64, previous_mode: u8) -> bool {
    use crate::ntos::mm::guest_memory as guest;
    let Some(callout_type) = callout(body, Routine::OkayToClose) else { return false };
    let status = invoke(body, callout_type, 0x20, |block| {
        guest::write64(block, process);
        guest::write64(block + 8, body);
        guest::write64(block + 0x10, handle);
        guest::write8(block + 0x18, previous_mode);
    });
    status & 0x8000_0000 == 0
}

/// ExpWin32CloseProcedure(Process, Object, ProcessHandleCount,
/// SystemHandleCount).
pub fn close_procedure(process: u64, body: u64, process_handle_count: u32, system_handle_count: u32) {
    use crate::ntos::mm::guest_memory as guest;
    let Some(callout_type) = callout(body, Routine::Close) else { return };
    invoke(body, callout_type, 0x18, |block| {
        guest::write64(block, process);
        guest::write64(block + 8, body);
        guest::write32(block + 0x10, process_handle_count);
        guest::write32(block + 0x14, system_handle_count);
    });
}

/// ExpWin32DeleteProcedure(Object).
pub fn delete_procedure(body: u64) {
    let Some(callout_type) = callout(body, Routine::Delete) else { return };
    invoke(body, callout_type, 8, |block| crate::ntos::mm::guest_memory::write64(block, body));
}

/// ExpWin32ParseProcedure(ParseObject, ObjectType, AccessState, AccessMode,
/// Attributes, CompleteName, RemainingName, Context, SecurityQos, &Object).
#[allow(clippy::too_many_arguments)]
pub fn parse_procedure(parse_object: u64, object_type: u64, access_state: u64, access_mode: u8, attributes: u32, complete_name: u64, remaining_name: u64, context: u64, security_qos: u64, object: u64) -> u32 {
    use crate::ntos::mm::guest_memory as guest;
    invoke(parse_object, WINDOW_STATION_PARSE, 0x48, |block| {
        guest::write64(block, parse_object);
        guest::write64(block + 8, object_type);
        guest::write64(block + 0x10, access_state);
        guest::write8(block + 0x18, access_mode);
        guest::write32(block + 0x1C, attributes);
        guest::write64(block + 0x20, complete_name);
        guest::write64(block + 0x28, remaining_name);
        guest::write64(block + 0x30, context);
        guest::write64(block + 0x38, security_qos);
        guest::write64(block + 0x40, object);
    })
}

/// O endereço da célula exportada `name`.
pub fn cell(name: &str) -> u64 {
    object_types::exported_cell(name)
}
