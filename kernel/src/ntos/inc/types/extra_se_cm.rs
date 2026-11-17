//! Estruturas públicas do WDK usadas pelo Configuration Manager que não
//! constam dos símbolos do ntoskrnl: as notificações `REG_*_INFORMATION`
//! que os filtros de registro (CmRegisterCallbackEx) recebem como Argument2.
//!
//! Mantido à mão no estilo de `wdk.rs`: `#[repr(C)]`, folhas `Field<T>`,
//! ponteiros como `Field<u64>` com o tipo apontado no comentário, layout x64
//! de `wdm.h` conferido em compilação.

use super::*;

/// `_REG_CREATE_KEY_INFORMATION_V1` (wdm.h); `_REG_OPEN_KEY_INFORMATION_V1`
/// tem o mesmo layout (RegNtPreCreateKeyEx / RegNtPreOpenKeyEx).
#[repr(C)]
pub struct RegCreateKeyInformationV1 {
    /// -> `_UNICODE_STRING`
    pub complete_name: Field<u64>,
    /// -> `void` (corpo da chave raiz)
    pub root_object: Field<u64>,
    /// -> `_OBJECT_TYPE`
    pub object_type: Field<u64>,
    pub options: Field<u32>,
    _pad_1c: Reserved<0x4>,
    /// -> `_UNICODE_STRING`
    pub class: Field<u64>,
    /// -> `void`
    pub security_descriptor: Field<u64>,
    /// -> `void`
    pub security_quality_of_service: Field<u64>,
    pub desired_access: Field<u32>,
    pub granted_access: Field<u32>,
    /// -> `u32`
    pub disposition: Field<u64>,
    /// -> `void *`
    pub result_object: Field<u64>,
    /// -> `void`
    pub call_context: Field<u64>,
    /// -> `void`
    pub root_object_context: Field<u64>,
    /// -> `void`
    pub transaction: Field<u64>,
    pub version: Field<u64>,
    /// -> `_UNICODE_STRING`
    pub remaining_name: Field<u64>,
    pub wow64_flags: Field<u32>,
    pub attributes: Field<u32>,
    pub check_access_mode: Field<u8>,
    _pad_81: Reserved<0x7>,
}

unsafe impl NtStruct for RegCreateKeyInformationV1 {}

const _: () = {
    assert!(core::mem::size_of::<RegCreateKeyInformationV1>() == 0x88);
    assert!(core::mem::offset_of!(RegCreateKeyInformationV1, complete_name) == 0x0);
    assert!(core::mem::offset_of!(RegCreateKeyInformationV1, root_object) == 0x8);
    assert!(core::mem::offset_of!(RegCreateKeyInformationV1, object_type) == 0x10);
    assert!(core::mem::offset_of!(RegCreateKeyInformationV1, options) == 0x18);
    assert!(core::mem::offset_of!(RegCreateKeyInformationV1, class) == 0x20);
    assert!(core::mem::offset_of!(RegCreateKeyInformationV1, security_descriptor) == 0x28);
    assert!(core::mem::offset_of!(RegCreateKeyInformationV1, security_quality_of_service) == 0x30);
    assert!(core::mem::offset_of!(RegCreateKeyInformationV1, desired_access) == 0x38);
    assert!(core::mem::offset_of!(RegCreateKeyInformationV1, granted_access) == 0x3c);
    assert!(core::mem::offset_of!(RegCreateKeyInformationV1, disposition) == 0x40);
    assert!(core::mem::offset_of!(RegCreateKeyInformationV1, result_object) == 0x48);
    assert!(core::mem::offset_of!(RegCreateKeyInformationV1, call_context) == 0x50);
    assert!(core::mem::offset_of!(RegCreateKeyInformationV1, root_object_context) == 0x58);
    assert!(core::mem::offset_of!(RegCreateKeyInformationV1, transaction) == 0x60);
    assert!(core::mem::offset_of!(RegCreateKeyInformationV1, version) == 0x68);
    assert!(core::mem::offset_of!(RegCreateKeyInformationV1, remaining_name) == 0x70);
    assert!(core::mem::offset_of!(RegCreateKeyInformationV1, wow64_flags) == 0x78);
    assert!(core::mem::offset_of!(RegCreateKeyInformationV1, attributes) == 0x7c);
    assert!(core::mem::offset_of!(RegCreateKeyInformationV1, check_access_mode) == 0x80);
};

/// `_REG_DELETE_KEY_INFORMATION` (wdm.h); `_REG_KEY_HANDLE_CLOSE_INFORMATION`
/// tem o mesmo layout (RegNtPreDeleteKey / RegNtPreKeyHandleClose).
#[repr(C)]
pub struct RegDeleteKeyInformation {
    /// -> `void`
    pub object: Field<u64>,
    /// -> `void`
    pub call_context: Field<u64>,
    /// -> `void`
    pub object_context: Field<u64>,
    /// -> `void`
    pub reserved: Field<u64>,
}

unsafe impl NtStruct for RegDeleteKeyInformation {}

const _: () = {
    assert!(core::mem::size_of::<RegDeleteKeyInformation>() == 0x20);
    assert!(core::mem::offset_of!(RegDeleteKeyInformation, object) == 0x0);
    assert!(core::mem::offset_of!(RegDeleteKeyInformation, call_context) == 0x8);
    assert!(core::mem::offset_of!(RegDeleteKeyInformation, object_context) == 0x10);
    assert!(core::mem::offset_of!(RegDeleteKeyInformation, reserved) == 0x18);
};

/// `_REG_DELETE_VALUE_KEY_INFORMATION` (wdm.h, RegNtPreDeleteValueKey).
#[repr(C)]
pub struct RegDeleteValueKeyInformation {
    /// -> `void`
    pub object: Field<u64>,
    /// -> `_UNICODE_STRING`
    pub value_name: Field<u64>,
    /// -> `void`
    pub call_context: Field<u64>,
    /// -> `void`
    pub object_context: Field<u64>,
    /// -> `void`
    pub reserved: Field<u64>,
}

unsafe impl NtStruct for RegDeleteValueKeyInformation {}

const _: () = {
    assert!(core::mem::size_of::<RegDeleteValueKeyInformation>() == 0x28);
    assert!(core::mem::offset_of!(RegDeleteValueKeyInformation, object) == 0x0);
    assert!(core::mem::offset_of!(RegDeleteValueKeyInformation, value_name) == 0x8);
    assert!(core::mem::offset_of!(RegDeleteValueKeyInformation, call_context) == 0x10);
    assert!(core::mem::offset_of!(RegDeleteValueKeyInformation, object_context) == 0x18);
    assert!(core::mem::offset_of!(RegDeleteValueKeyInformation, reserved) == 0x20);
};

/// `_REG_SET_VALUE_KEY_INFORMATION` (wdm.h, RegNtPreSetValueKey).
#[repr(C)]
pub struct RegSetValueKeyInformation {
    /// -> `void`
    pub object: Field<u64>,
    /// -> `_UNICODE_STRING`
    pub value_name: Field<u64>,
    pub title_index: Field<u32>,
    pub type_: Field<u32>,
    /// -> `void`
    pub data: Field<u64>,
    pub data_size: Field<u32>,
    _pad_24: Reserved<0x4>,
    /// -> `void`
    pub call_context: Field<u64>,
    /// -> `void`
    pub object_context: Field<u64>,
    /// -> `void`
    pub reserved: Field<u64>,
}

unsafe impl NtStruct for RegSetValueKeyInformation {}

const _: () = {
    assert!(core::mem::size_of::<RegSetValueKeyInformation>() == 0x40);
    assert!(core::mem::offset_of!(RegSetValueKeyInformation, object) == 0x0);
    assert!(core::mem::offset_of!(RegSetValueKeyInformation, value_name) == 0x8);
    assert!(core::mem::offset_of!(RegSetValueKeyInformation, title_index) == 0x10);
    assert!(core::mem::offset_of!(RegSetValueKeyInformation, type_) == 0x14);
    assert!(core::mem::offset_of!(RegSetValueKeyInformation, data) == 0x18);
    assert!(core::mem::offset_of!(RegSetValueKeyInformation, data_size) == 0x20);
    assert!(core::mem::offset_of!(RegSetValueKeyInformation, call_context) == 0x28);
    assert!(core::mem::offset_of!(RegSetValueKeyInformation, object_context) == 0x30);
    assert!(core::mem::offset_of!(RegSetValueKeyInformation, reserved) == 0x38);
};

/// `_REG_SET_INFORMATION_KEY_INFORMATION` (wdm.h, RegNtPreSetInformationKey).
#[repr(C)]
pub struct RegSetInformationKeyInformation {
    /// -> `void`
    pub object: Field<u64>,
    /// KEY_SET_INFORMATION_CLASS.
    pub key_set_information_class: Field<u32>,
    _pad_c: Reserved<0x4>,
    /// -> `void`
    pub key_set_information: Field<u64>,
    pub key_set_information_length: Field<u32>,
    _pad_1c: Reserved<0x4>,
    /// -> `void`
    pub call_context: Field<u64>,
    /// -> `void`
    pub object_context: Field<u64>,
    /// -> `void`
    pub reserved: Field<u64>,
}

unsafe impl NtStruct for RegSetInformationKeyInformation {}

const _: () = {
    assert!(core::mem::size_of::<RegSetInformationKeyInformation>() == 0x38);
    assert!(core::mem::offset_of!(RegSetInformationKeyInformation, object) == 0x0);
    assert!(core::mem::offset_of!(RegSetInformationKeyInformation, key_set_information_class) == 0x8);
    assert!(core::mem::offset_of!(RegSetInformationKeyInformation, key_set_information) == 0x10);
    assert!(core::mem::offset_of!(RegSetInformationKeyInformation, key_set_information_length) == 0x18);
    assert!(core::mem::offset_of!(RegSetInformationKeyInformation, call_context) == 0x20);
    assert!(core::mem::offset_of!(RegSetInformationKeyInformation, object_context) == 0x28);
    assert!(core::mem::offset_of!(RegSetInformationKeyInformation, reserved) == 0x30);
};

/// `_REG_QUERY_KEY_INFORMATION` (wdm.h, RegNtPreQueryKey).
#[repr(C)]
pub struct RegQueryKeyInformation {
    /// -> `void`
    pub object: Field<u64>,
    /// KEY_INFORMATION_CLASS.
    pub key_information_class: Field<u32>,
    _pad_c: Reserved<0x4>,
    /// -> `void`
    pub key_information: Field<u64>,
    pub length: Field<u32>,
    _pad_1c: Reserved<0x4>,
    /// -> `u32`
    pub result_length: Field<u64>,
    /// -> `void`
    pub call_context: Field<u64>,
    /// -> `void`
    pub object_context: Field<u64>,
    /// -> `void`
    pub reserved: Field<u64>,
}

unsafe impl NtStruct for RegQueryKeyInformation {}

const _: () = {
    assert!(core::mem::size_of::<RegQueryKeyInformation>() == 0x40);
    assert!(core::mem::offset_of!(RegQueryKeyInformation, object) == 0x0);
    assert!(core::mem::offset_of!(RegQueryKeyInformation, key_information_class) == 0x8);
    assert!(core::mem::offset_of!(RegQueryKeyInformation, key_information) == 0x10);
    assert!(core::mem::offset_of!(RegQueryKeyInformation, length) == 0x18);
    assert!(core::mem::offset_of!(RegQueryKeyInformation, result_length) == 0x20);
    assert!(core::mem::offset_of!(RegQueryKeyInformation, call_context) == 0x28);
    assert!(core::mem::offset_of!(RegQueryKeyInformation, object_context) == 0x30);
    assert!(core::mem::offset_of!(RegQueryKeyInformation, reserved) == 0x38);
};

/// `_REG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION` (wdm.h,
/// RegNtPreQueryMultipleValueKey).
#[repr(C)]
pub struct RegQueryMultipleValueKeyInformation {
    /// -> `void`
    pub object: Field<u64>,
    /// -> `_KEY_VALUE_ENTRY`
    pub value_entries: Field<u64>,
    pub entry_count: Field<u32>,
    _pad_14: Reserved<0x4>,
    /// -> `void`
    pub value_buffer: Field<u64>,
    /// -> `u32`
    pub buffer_length: Field<u64>,
    /// -> `u32`
    pub required_buffer_length: Field<u64>,
    /// -> `void`
    pub call_context: Field<u64>,
    /// -> `void`
    pub object_context: Field<u64>,
    /// -> `void`
    pub reserved: Field<u64>,
}

unsafe impl NtStruct for RegQueryMultipleValueKeyInformation {}

const _: () = {
    assert!(core::mem::size_of::<RegQueryMultipleValueKeyInformation>() == 0x48);
    assert!(core::mem::offset_of!(RegQueryMultipleValueKeyInformation, object) == 0x0);
    assert!(core::mem::offset_of!(RegQueryMultipleValueKeyInformation, value_entries) == 0x8);
    assert!(core::mem::offset_of!(RegQueryMultipleValueKeyInformation, entry_count) == 0x10);
    assert!(core::mem::offset_of!(RegQueryMultipleValueKeyInformation, value_buffer) == 0x18);
    assert!(core::mem::offset_of!(RegQueryMultipleValueKeyInformation, buffer_length) == 0x20);
    assert!(core::mem::offset_of!(RegQueryMultipleValueKeyInformation, required_buffer_length) == 0x28);
    assert!(core::mem::offset_of!(RegQueryMultipleValueKeyInformation, call_context) == 0x30);
    assert!(core::mem::offset_of!(RegQueryMultipleValueKeyInformation, object_context) == 0x38);
    assert!(core::mem::offset_of!(RegQueryMultipleValueKeyInformation, reserved) == 0x40);
};

/// `_REG_QUERY_VALUE_KEY_INFORMATION` (wdm.h, RegNtPreQueryValueKey).
#[repr(C)]
pub struct RegQueryValueKeyInformation {
    /// -> `void`
    pub object: Field<u64>,
    /// -> `_UNICODE_STRING`
    pub value_name: Field<u64>,
    /// KEY_VALUE_INFORMATION_CLASS.
    pub key_value_information_class: Field<u32>,
    _pad_14: Reserved<0x4>,
    /// -> `void`
    pub key_value_information: Field<u64>,
    pub length: Field<u32>,
    _pad_24: Reserved<0x4>,
    /// -> `u32`
    pub result_length: Field<u64>,
    /// -> `void`
    pub call_context: Field<u64>,
    /// -> `void`
    pub object_context: Field<u64>,
    /// -> `void`
    pub reserved: Field<u64>,
}

unsafe impl NtStruct for RegQueryValueKeyInformation {}

const _: () = {
    assert!(core::mem::size_of::<RegQueryValueKeyInformation>() == 0x48);
    assert!(core::mem::offset_of!(RegQueryValueKeyInformation, object) == 0x0);
    assert!(core::mem::offset_of!(RegQueryValueKeyInformation, value_name) == 0x8);
    assert!(core::mem::offset_of!(RegQueryValueKeyInformation, key_value_information_class) == 0x10);
    assert!(core::mem::offset_of!(RegQueryValueKeyInformation, key_value_information) == 0x18);
    assert!(core::mem::offset_of!(RegQueryValueKeyInformation, length) == 0x20);
    assert!(core::mem::offset_of!(RegQueryValueKeyInformation, result_length) == 0x28);
    assert!(core::mem::offset_of!(RegQueryValueKeyInformation, call_context) == 0x30);
    assert!(core::mem::offset_of!(RegQueryValueKeyInformation, object_context) == 0x38);
    assert!(core::mem::offset_of!(RegQueryValueKeyInformation, reserved) == 0x40);
};

/// `_REG_ENUMERATE_KEY_INFORMATION` (wdm.h, RegNtPreEnumerateKey);
/// `_REG_ENUMERATE_VALUE_KEY_INFORMATION` tem o mesmo layout (com a classe
/// KEY_VALUE_INFORMATION_CLASS no lugar de KEY_INFORMATION_CLASS).
#[repr(C)]
pub struct RegEnumerateKeyInformation {
    /// -> `void`
    pub object: Field<u64>,
    pub index: Field<u32>,
    /// KEY_INFORMATION_CLASS (ou KEY_VALUE_INFORMATION_CLASS).
    pub key_information_class: Field<u32>,
    /// -> `void`
    pub key_information: Field<u64>,
    pub length: Field<u32>,
    _pad_1c: Reserved<0x4>,
    /// -> `u32`
    pub result_length: Field<u64>,
    /// -> `void`
    pub call_context: Field<u64>,
    /// -> `void`
    pub object_context: Field<u64>,
    /// -> `void`
    pub reserved: Field<u64>,
}

unsafe impl NtStruct for RegEnumerateKeyInformation {}

const _: () = {
    assert!(core::mem::size_of::<RegEnumerateKeyInformation>() == 0x40);
    assert!(core::mem::offset_of!(RegEnumerateKeyInformation, object) == 0x0);
    assert!(core::mem::offset_of!(RegEnumerateKeyInformation, index) == 0x8);
    assert!(core::mem::offset_of!(RegEnumerateKeyInformation, key_information_class) == 0xc);
    assert!(core::mem::offset_of!(RegEnumerateKeyInformation, key_information) == 0x10);
    assert!(core::mem::offset_of!(RegEnumerateKeyInformation, length) == 0x18);
    assert!(core::mem::offset_of!(RegEnumerateKeyInformation, result_length) == 0x20);
    assert!(core::mem::offset_of!(RegEnumerateKeyInformation, call_context) == 0x28);
    assert!(core::mem::offset_of!(RegEnumerateKeyInformation, object_context) == 0x30);
    assert!(core::mem::offset_of!(RegEnumerateKeyInformation, reserved) == 0x38);
};

/// `_REG_QUERY_KEY_SECURITY_INFORMATION` (wdm.h, RegNtPreQueryKeySecurity).
#[repr(C)]
pub struct RegQueryKeySecurityInformation {
    /// -> `void`
    pub object: Field<u64>,
    /// -> `u32` (SECURITY_INFORMATION)
    pub security_information: Field<u64>,
    /// -> `void`
    pub security_descriptor: Field<u64>,
    /// -> `u32`
    pub length: Field<u64>,
    /// -> `void`
    pub call_context: Field<u64>,
    /// -> `void`
    pub object_context: Field<u64>,
    /// -> `void`
    pub reserved: Field<u64>,
}

unsafe impl NtStruct for RegQueryKeySecurityInformation {}

const _: () = {
    assert!(core::mem::size_of::<RegQueryKeySecurityInformation>() == 0x38);
    assert!(core::mem::offset_of!(RegQueryKeySecurityInformation, object) == 0x0);
    assert!(core::mem::offset_of!(RegQueryKeySecurityInformation, security_information) == 0x8);
    assert!(core::mem::offset_of!(RegQueryKeySecurityInformation, security_descriptor) == 0x10);
    assert!(core::mem::offset_of!(RegQueryKeySecurityInformation, length) == 0x18);
    assert!(core::mem::offset_of!(RegQueryKeySecurityInformation, call_context) == 0x20);
    assert!(core::mem::offset_of!(RegQueryKeySecurityInformation, object_context) == 0x28);
    assert!(core::mem::offset_of!(RegQueryKeySecurityInformation, reserved) == 0x30);
};

/// `_REG_LOAD_KEY_INFORMATION_V2` (wdm.h, RegNtPreLoadKey) como o
/// CmLoadDifferencingKey do 19041 a monta: Version = 2 depois do
/// ObjectContext e o FileAccessToken no fim (0x60 bytes).
#[repr(C)]
pub struct RegLoadKeyInformation {
    /// -> `void` (o corpo da chave raiz do TargetKey, ou nulo)
    pub object: Field<u64>,
    /// -> `UNICODE_STRING`
    pub key_name: Field<u64>,
    /// -> `UNICODE_STRING`
    pub source_file: Field<u64>,
    pub flags: Field<u32>,
    _pad_1c: Reserved<0x4>,
    /// -> `void`
    pub trust_class_object: Field<u64>,
    /// -> `void` (KEVENT)
    pub user_event: Field<u64>,
    pub desired_access: Field<u32>,
    _pad_34: Reserved<0x4>,
    /// -> `HANDLE`
    pub root_handle: Field<u64>,
    /// -> `void`
    pub call_context: Field<u64>,
    /// -> `void`
    pub object_context: Field<u64>,
    pub version: Field<u64>,
    /// -> `void`
    pub file_access_token: Field<u64>,
}

unsafe impl NtStruct for RegLoadKeyInformation {}

const _: () = {
    assert!(core::mem::size_of::<RegLoadKeyInformation>() == 0x60);
    assert!(core::mem::offset_of!(RegLoadKeyInformation, flags) == 0x18);
    assert!(core::mem::offset_of!(RegLoadKeyInformation, user_event) == 0x28);
    assert!(core::mem::offset_of!(RegLoadKeyInformation, desired_access) == 0x30);
    assert!(core::mem::offset_of!(RegLoadKeyInformation, root_handle) == 0x38);
    assert!(core::mem::offset_of!(RegLoadKeyInformation, call_context) == 0x40);
    assert!(core::mem::offset_of!(RegLoadKeyInformation, object_context) == 0x48);
    assert!(core::mem::offset_of!(RegLoadKeyInformation, version) == 0x50);
};

/// `_REG_UNLOAD_KEY_INFORMATION` (wdm.h, RegNtPreUnLoadKey).
#[repr(C)]
pub struct RegUnloadKeyInformation {
    /// -> `void`
    pub object: Field<u64>,
    /// -> `void` (KEVENT)
    pub user_event: Field<u64>,
    /// -> `void`
    pub call_context: Field<u64>,
    /// -> `void`
    pub object_context: Field<u64>,
    /// -> `void`
    pub reserved: Field<u64>,
}

unsafe impl NtStruct for RegUnloadKeyInformation {}

const _: () = {
    assert!(core::mem::size_of::<RegUnloadKeyInformation>() == 0x28);
    assert!(core::mem::offset_of!(RegUnloadKeyInformation, call_context) == 0x10);
    assert!(core::mem::offset_of!(RegUnloadKeyInformation, object_context) == 0x18);
};

/// `_REG_SAVE_KEY_INFORMATION` (wdm.h, RegNtPreSaveKey);
/// `_REG_RESTORE_KEY_INFORMATION` tem o mesmo layout, com Flags no lugar de
/// Format (RegNtPreRestoreKey).
#[repr(C)]
pub struct RegSaveKeyInformation {
    /// -> `void`
    pub object: Field<u64>,
    /// -> `HANDLE`
    pub file_handle: Field<u64>,
    pub format: Field<u32>,
    _pad_14: Reserved<0x4>,
    /// -> `void`
    pub call_context: Field<u64>,
    /// -> `void`
    pub object_context: Field<u64>,
    /// -> `void`
    pub reserved: Field<u64>,
}

unsafe impl NtStruct for RegSaveKeyInformation {}

const _: () = {
    assert!(core::mem::size_of::<RegSaveKeyInformation>() == 0x30);
    assert!(core::mem::offset_of!(RegSaveKeyInformation, format) == 0x10);
    assert!(core::mem::offset_of!(RegSaveKeyInformation, call_context) == 0x18);
    assert!(core::mem::offset_of!(RegSaveKeyInformation, object_context) == 0x20);
};

/// `_REG_CALLBACK_CONTEXT_CLEANUP_INFORMATION` (wdm.h,
/// RegNtCallbackObjectContextCleanup).
#[repr(C)]
pub struct RegCallbackContextCleanupInformation {
    /// -> `void`
    pub object: Field<u64>,
    /// -> `void`
    pub object_context: Field<u64>,
    /// -> `void`
    pub reserved: Field<u64>,
}

unsafe impl NtStruct for RegCallbackContextCleanupInformation {}

const _: () = {
    assert!(core::mem::size_of::<RegCallbackContextCleanupInformation>() == 0x18);
    assert!(core::mem::offset_of!(RegCallbackContextCleanupInformation, object_context) == 0x8);
};
