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
//! ObjectTypeCode 0x400. No NT as rotinas Open/Close/Delete/OkayToClose (e
//! Parse, da WindowStation) dos seis despacham aos callouts do win32k
//! (PsInvokeWin32Callout). O Ob já chama as rotinas de tipo
//! (`ob/type_procedures.rs`), mas as ExpWin32* que despacham aos callouts
//! ainda não existem, então elas ficam nulas.

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
    for (cell, template) in &TYPES {
        kernel_data::write(cell, object_types::ensure(template).pointer);
    }
}

/// O endereço da célula exportada `name`.
pub fn cell(name: &str) -> u64 {
    object_types::exported_cell(name)
}
