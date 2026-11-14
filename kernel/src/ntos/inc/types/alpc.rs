//! Alpc: mensagens e atributos de portas (LPC/ALPC).
//!
//! Gerado a partir dos símbolos do ntoskrnl; ver `types/mod.rs`.

use super::*;

/// `_ALPC_PROCESS_CONTEXT` (0x20 bytes).
#[repr(C)]
pub struct AlpcProcessContext {
    pub lock: ExPushLock,
    pub view_list_head: ListEntry,
    pub paged_pool_quota_cache: Field<u64>,
}

unsafe impl NtStruct for AlpcProcessContext {}

const _: () = {
    assert!(core::mem::size_of::<AlpcProcessContext>() == 0x20);
    assert!(core::mem::offset_of!(AlpcProcessContext, lock) == 0x0);
    assert!(core::mem::offset_of!(AlpcProcessContext, view_list_head) == 0x8);
    assert!(core::mem::offset_of!(AlpcProcessContext, paged_pool_quota_cache) == 0x18);
};

/// `_PORT_MESSAGE` (0x28 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `PortMessageView1`, alcançada por `Deref`.
#[repr(C)]
pub struct PortMessage {
    pub u1: PortMessageU1,
    pub u2: PortMessageU2,
    pub client_id: ClientId,
    pub message_id: Field<u32>,
    _pad_1c: Reserved<0x4>,
    pub client_view_size: Field<u64>,
}

/// Vista 1 de `_PORT_MESSAGE` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct PortMessageView1 {
    _pad_0: Reserved<0x8>,
    pub do_not_use_this_field: Field<f64>,
    _pad_10: Reserved<0x10>,
    pub callback_id: Field<u32>,
    _pad_24: Reserved<0x4>,
}

impl core::ops::Deref for PortMessage {
    type Target = PortMessageView1;
    #[inline(always)]
    fn deref(&self) -> &PortMessageView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<PortMessageView1>() }
    }
}

unsafe impl NtStruct for PortMessage {}

const _: () = {
    assert!(core::mem::size_of::<PortMessage>() == 0x28);
    assert!(core::mem::offset_of!(PortMessage, u1) == 0x0);
    assert!(core::mem::offset_of!(PortMessage, u2) == 0x4);
    assert!(core::mem::offset_of!(PortMessage, client_id) == 0x8);
    assert!(core::mem::offset_of!(PortMessage, message_id) == 0x18);
    assert!(core::mem::offset_of!(PortMessage, client_view_size) == 0x20);
    assert!(core::mem::size_of::<PortMessageView1>() == 0x28);
    assert!(core::mem::align_of::<PortMessageView1>() == core::mem::align_of::<PortMessage>());
    assert!(core::mem::offset_of!(PortMessageView1, do_not_use_this_field) == 0x8);
    assert!(core::mem::offset_of!(PortMessageView1, callback_id) == 0x20);
};

/// `_PORT_MESSAGE::u1` (0x4 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `PortMessageU1View1`, alcançada por `Deref`.
#[repr(C)]
pub struct PortMessageU1 {
    _align: [u32; 0],
    pub s1: PortMessageU1S1,
}

/// Vista 1 de `_PORT_MESSAGE::u1` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct PortMessageU1View1 {
    pub length: Field<u32>,
}

impl core::ops::Deref for PortMessageU1 {
    type Target = PortMessageU1View1;
    #[inline(always)]
    fn deref(&self) -> &PortMessageU1View1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<PortMessageU1View1>() }
    }
}

unsafe impl NtStruct for PortMessageU1 {}

const _: () = {
    assert!(core::mem::size_of::<PortMessageU1>() == 0x4);
    assert!(core::mem::offset_of!(PortMessageU1, s1) == 0x0);
    assert!(core::mem::size_of::<PortMessageU1View1>() == 0x4);
    assert!(core::mem::align_of::<PortMessageU1View1>() == core::mem::align_of::<PortMessageU1>());
    assert!(core::mem::offset_of!(PortMessageU1View1, length) == 0x0);
};

/// `_PORT_MESSAGE::u1::s1` (0x4 bytes).
#[repr(C)]
pub struct PortMessageU1S1 {
    pub data_length: Field<i16>,
    pub total_length: Field<i16>,
}

unsafe impl NtStruct for PortMessageU1S1 {}

const _: () = {
    assert!(core::mem::size_of::<PortMessageU1S1>() == 0x4);
    assert!(core::mem::offset_of!(PortMessageU1S1, data_length) == 0x0);
    assert!(core::mem::offset_of!(PortMessageU1S1, total_length) == 0x2);
};

/// `_PORT_MESSAGE::u2` (0x4 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `PortMessageU2View1`, alcançada por `Deref`.
#[repr(C)]
pub struct PortMessageU2 {
    _align: [u32; 0],
    pub s2: PortMessageU2S2,
}

/// Vista 1 de `_PORT_MESSAGE::u2` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct PortMessageU2View1 {
    pub zero_init: Field<u32>,
}

impl core::ops::Deref for PortMessageU2 {
    type Target = PortMessageU2View1;
    #[inline(always)]
    fn deref(&self) -> &PortMessageU2View1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<PortMessageU2View1>() }
    }
}

unsafe impl NtStruct for PortMessageU2 {}

const _: () = {
    assert!(core::mem::size_of::<PortMessageU2>() == 0x4);
    assert!(core::mem::offset_of!(PortMessageU2, s2) == 0x0);
    assert!(core::mem::size_of::<PortMessageU2View1>() == 0x4);
    assert!(core::mem::align_of::<PortMessageU2View1>() == core::mem::align_of::<PortMessageU2>());
    assert!(core::mem::offset_of!(PortMessageU2View1, zero_init) == 0x0);
};

/// `_PORT_MESSAGE::u2::s2` (0x4 bytes).
#[repr(C)]
pub struct PortMessageU2S2 {
    pub type_: Field<i16>,
    pub data_info_offset: Field<i16>,
}

unsafe impl NtStruct for PortMessageU2S2 {}

const _: () = {
    assert!(core::mem::size_of::<PortMessageU2S2>() == 0x4);
    assert!(core::mem::offset_of!(PortMessageU2S2, type_) == 0x0);
    assert!(core::mem::offset_of!(PortMessageU2S2, data_info_offset) == 0x2);
};

/// `_ALPC_MESSAGE_ATTRIBUTES` (0x8 bytes).
#[repr(C)]
pub struct AlpcMessageAttributes {
    pub allocated_attributes: Field<u32>,
    pub valid_attributes: Field<u32>,
}

unsafe impl NtStruct for AlpcMessageAttributes {}

const _: () = {
    assert!(core::mem::size_of::<AlpcMessageAttributes>() == 0x8);
    assert!(core::mem::offset_of!(AlpcMessageAttributes, allocated_attributes) == 0x0);
    assert!(core::mem::offset_of!(AlpcMessageAttributes, valid_attributes) == 0x4);
};

/// `_ALPC_PORT_ATTRIBUTES` (0x48 bytes).
#[repr(C)]
pub struct AlpcPortAttributes {
    pub flags: Field<u32>,
    pub security_qos: SecurityQualityOfService,
    pub max_message_length: Field<u64>,
    pub memory_bandwidth: Field<u64>,
    pub max_pool_usage: Field<u64>,
    pub max_section_size: Field<u64>,
    pub max_view_size: Field<u64>,
    pub max_total_section_size: Field<u64>,
    pub dup_object_types: Field<u32>,
    pub reserved: Field<u32>,
}

unsafe impl NtStruct for AlpcPortAttributes {}

const _: () = {
    assert!(core::mem::size_of::<AlpcPortAttributes>() == 0x48);
    assert!(core::mem::offset_of!(AlpcPortAttributes, flags) == 0x0);
    assert!(core::mem::offset_of!(AlpcPortAttributes, security_qos) == 0x4);
    assert!(core::mem::offset_of!(AlpcPortAttributes, max_message_length) == 0x10);
    assert!(core::mem::offset_of!(AlpcPortAttributes, memory_bandwidth) == 0x18);
    assert!(core::mem::offset_of!(AlpcPortAttributes, max_pool_usage) == 0x20);
    assert!(core::mem::offset_of!(AlpcPortAttributes, max_section_size) == 0x28);
    assert!(core::mem::offset_of!(AlpcPortAttributes, max_view_size) == 0x30);
    assert!(core::mem::offset_of!(AlpcPortAttributes, max_total_section_size) == 0x38);
    assert!(core::mem::offset_of!(AlpcPortAttributes, dup_object_types) == 0x40);
    assert!(core::mem::offset_of!(AlpcPortAttributes, reserved) == 0x44);
};

/// `_REMOTE_PORT_VIEW` (0x18 bytes).
#[repr(C)]
pub struct RemotePortView {
    pub length: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub view_size: Field<u64>,
    /// -> `void`
    pub view_base: Field<u64>,
}

unsafe impl NtStruct for RemotePortView {}

const _: () = {
    assert!(core::mem::size_of::<RemotePortView>() == 0x18);
    assert!(core::mem::offset_of!(RemotePortView, length) == 0x0);
    assert!(core::mem::offset_of!(RemotePortView, view_size) == 0x8);
    assert!(core::mem::offset_of!(RemotePortView, view_base) == 0x10);
};

/// `_ALPC_WORK_ON_BEHALF_TICKET` (0x8 bytes).
#[repr(C)]
pub struct AlpcWorkOnBehalfTicket {
    pub thread_id: Field<u32>,
    pub thread_creation_time_low: Field<u32>,
}

unsafe impl NtStruct for AlpcWorkOnBehalfTicket {}

const _: () = {
    assert!(core::mem::size_of::<AlpcWorkOnBehalfTicket>() == 0x8);
    assert!(core::mem::offset_of!(AlpcWorkOnBehalfTicket, thread_id) == 0x0);
    assert!(core::mem::offset_of!(AlpcWorkOnBehalfTicket, thread_creation_time_low) == 0x4);
};

/// `_PORT_MESSAGE32` (0x18 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `PortMessage32View1`, alcançada por `Deref`.
#[repr(C)]
pub struct PortMessage32 {
    _align: [u64; 0],
    pub u1: PortMessageU1,
    pub u2: PortMessageU2,
    pub client_id: ClientId32,
    pub message_id: Field<u32>,
    pub client_view_size: Field<u32>,
}

/// Vista 1 de `_PORT_MESSAGE32` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct PortMessage32View1 {
    _pad_0: Reserved<0x8>,
    pub do_not_use_this_field: Field<f64>,
    _pad_10: Reserved<0x4>,
    pub callback_id: Field<u32>,
}

impl core::ops::Deref for PortMessage32 {
    type Target = PortMessage32View1;
    #[inline(always)]
    fn deref(&self) -> &PortMessage32View1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<PortMessage32View1>() }
    }
}

unsafe impl NtStruct for PortMessage32 {}

const _: () = {
    assert!(core::mem::size_of::<PortMessage32>() == 0x18);
    assert!(core::mem::offset_of!(PortMessage32, u1) == 0x0);
    assert!(core::mem::offset_of!(PortMessage32, u2) == 0x4);
    assert!(core::mem::offset_of!(PortMessage32, client_id) == 0x8);
    assert!(core::mem::offset_of!(PortMessage32, message_id) == 0x10);
    assert!(core::mem::offset_of!(PortMessage32, client_view_size) == 0x14);
    assert!(core::mem::size_of::<PortMessage32View1>() == 0x18);
    assert!(core::mem::align_of::<PortMessage32View1>() == core::mem::align_of::<PortMessage32>());
    assert!(core::mem::offset_of!(PortMessage32View1, do_not_use_this_field) == 0x8);
    assert!(core::mem::offset_of!(PortMessage32View1, callback_id) == 0x14);
};
