//! Estruturas do formato de hive do Registro (regf) usadas pelo
//! Configuration Manager: o bloco base, o cabeçalho de bin e as células de
//! chave, valor, segurança, índice e dados grandes.
//!
//! Mantido à mão no estilo de `wdk.rs`: `#[repr(C)]`, folhas `Field<T>`,
//! layout conferido em compilação. Todas vêm dos símbolos do ntoskrnl 19041
//! (`ntkrnlmp.pdb`), fora do conjunto gerado: `_HBASE_BLOCK` (0x1000),
//! `_HBIN` (0x20), `_CM_KEY_NODE` (0x50), `_CM_KEY_VALUE` (0x18),
//! `_CM_KEY_SECURITY` (0x28), `_CM_KEY_INDEX` (0x8), `_CM_INDEX` (0x8),
//! `_CM_KEY_FAST_INDEX` (o `_CM_KEY_INDEX` com `_CM_INDEX` na lista) e
//! `_CM_BIG_DATA` (0x8). O NT declara essas estruturas com empacotamento
//! de 4 bytes: os campos de 64 bits fora do alinhamento natural
//! (`TimeStamp`, `LastWriteTime`) são `UnalignedField`.

use super::*;

/// `_HBASE_BLOCK` (0x1000 bytes): o primeiro bloco do arquivo de hive.
#[repr(C)]
pub struct HbaseBlock {
    /// 'regf'.
    pub signature: Field<u32>,
    pub sequence1: Field<u32>,
    pub sequence2: Field<u32>,
    pub time_stamp: UnalignedField<u64>,
    pub major: Field<u32>,
    pub minor: Field<u32>,
    /// HFILE_TYPE_PRIMARY (0) ou de log.
    pub type_: Field<u32>,
    /// HBASE_FORMAT_MEMORY (1).
    pub format: Field<u32>,
    pub root_cell: Field<u32>,
    /// Tamanho dos dados de bins (múltiplo de 0x1000).
    pub length: Field<u32>,
    pub cluster: Field<u32>,
    /// Os últimos caracteres do nome do arquivo (UTF-16, 64 bytes).
    pub file_name: [Field<u16>; 32],
    pub rm_id: Guid,
    pub log_id: Guid,
    pub flags: Field<u32>,
    pub tm_id: Guid,
    pub guid_signature: Field<u32>,
    pub last_reorganize_time: UnalignedField<u64>,
    _reserved1: Reserved<0x14c>,
    /// XOR dos 127 DWORDs anteriores (HvpHeaderCheckSum).
    pub check_sum: Field<u32>,
    _reserved2: Reserved<0xdc8>,
    pub thaw_tm_id: Guid,
    pub thaw_rm_id: Guid,
    pub thaw_log_id: Guid,
    pub boot_type: Field<u32>,
    pub boot_recover: Field<u32>,
}

unsafe impl NtStruct for HbaseBlock {}

const _: () = {
    assert!(core::mem::size_of::<HbaseBlock>() == 0x1000);
    assert!(core::mem::offset_of!(HbaseBlock, time_stamp) == 0xc);
    assert!(core::mem::offset_of!(HbaseBlock, major) == 0x14);
    assert!(core::mem::offset_of!(HbaseBlock, type_) == 0x1c);
    assert!(core::mem::offset_of!(HbaseBlock, root_cell) == 0x24);
    assert!(core::mem::offset_of!(HbaseBlock, cluster) == 0x2c);
    assert!(core::mem::offset_of!(HbaseBlock, file_name) == 0x30);
    assert!(core::mem::offset_of!(HbaseBlock, rm_id) == 0x70);
    assert!(core::mem::offset_of!(HbaseBlock, log_id) == 0x80);
    assert!(core::mem::offset_of!(HbaseBlock, flags) == 0x90);
    assert!(core::mem::offset_of!(HbaseBlock, tm_id) == 0x94);
    assert!(core::mem::offset_of!(HbaseBlock, guid_signature) == 0xa4);
    assert!(core::mem::offset_of!(HbaseBlock, last_reorganize_time) == 0xa8);
    assert!(core::mem::offset_of!(HbaseBlock, check_sum) == 0x1fc);
    assert!(core::mem::offset_of!(HbaseBlock, thaw_tm_id) == 0xfc8);
    assert!(core::mem::offset_of!(HbaseBlock, boot_type) == 0xff8);
    assert!(core::mem::offset_of!(HbaseBlock, boot_recover) == 0xffc);
};

/// `_HBIN` (0x20 bytes): o cabeçalho de cada bin.
#[repr(C)]
pub struct Hbin {
    /// 'hbin'.
    pub signature: Field<u32>,
    /// Offset do bin a partir do primeiro bin.
    pub file_offset: Field<u32>,
    pub size: Field<u32>,
    _reserved1: Reserved<8>,
    pub time_stamp: UnalignedField<u64>,
    pub spare: Field<u32>,
}

unsafe impl NtStruct for Hbin {}

const _: () = {
    assert!(core::mem::size_of::<Hbin>() == 0x20);
    assert!(core::mem::offset_of!(Hbin, size) == 0x8);
    assert!(core::mem::offset_of!(Hbin, time_stamp) == 0x14);
    assert!(core::mem::offset_of!(Hbin, spare) == 0x1c);
};

/// `_CM_KEY_NODE` (0x50 bytes com o primeiro caractere do nome): 'nk'.
#[repr(C)]
pub struct CmKeyNode {
    pub signature: Field<u16>,
    pub flags: Field<u16>,
    pub last_write_time: UnalignedField<u64>,
    pub access_bits: Field<u8>,
    /// LayerSemantics (2 bits), Spare1 (5), InheritClass (1).
    pub layer_bits: Field<u8>,
    pub spare2: Field<u16>,
    pub parent: Field<u32>,
    /// SubKeyCounts[Stable], SubKeyCounts[Volatile].
    pub sub_key_counts: [Field<u32>; 2],
    /// SubKeyLists[Stable], SubKeyLists[Volatile].
    pub sub_key_lists: [Field<u32>; 2],
    /// ValueList.Count.
    pub value_count: Field<u32>,
    /// ValueList.List.
    pub value_list: Field<u32>,
    pub security: Field<u32>,
    pub class: Field<u32>,
    /// MaxNameLen (16 bits), UserFlags (4), VirtControlFlags (4), Debug (8).
    pub max_name_len: Field<u32>,
    pub max_class_len: Field<u32>,
    pub max_value_name_len: Field<u32>,
    pub max_value_data_len: Field<u32>,
    pub work_var: Field<u32>,
    pub name_length: Field<u16>,
    pub class_length: Field<u16>,
    pub name: [Field<u16>; 1],
    _pad: Reserved<2>,
}

unsafe impl NtStruct for CmKeyNode {}

const _: () = {
    assert!(core::mem::size_of::<CmKeyNode>() == 0x50);
    assert!(core::mem::offset_of!(CmKeyNode, last_write_time) == 0x4);
    assert!(core::mem::offset_of!(CmKeyNode, access_bits) == 0xc);
    assert!(core::mem::offset_of!(CmKeyNode, parent) == 0x10);
    assert!(core::mem::offset_of!(CmKeyNode, sub_key_counts) == 0x14);
    assert!(core::mem::offset_of!(CmKeyNode, sub_key_lists) == 0x1c);
    assert!(core::mem::offset_of!(CmKeyNode, value_count) == 0x24);
    assert!(core::mem::offset_of!(CmKeyNode, value_list) == 0x28);
    assert!(core::mem::offset_of!(CmKeyNode, security) == 0x2c);
    assert!(core::mem::offset_of!(CmKeyNode, class) == 0x30);
    assert!(core::mem::offset_of!(CmKeyNode, max_name_len) == 0x34);
    assert!(core::mem::offset_of!(CmKeyNode, max_value_data_len) == 0x40);
    assert!(core::mem::offset_of!(CmKeyNode, work_var) == 0x44);
    assert!(core::mem::offset_of!(CmKeyNode, name_length) == 0x48);
    assert!(core::mem::offset_of!(CmKeyNode, class_length) == 0x4a);
    assert!(core::mem::offset_of!(CmKeyNode, name) == 0x4c);
};

/// `_CM_KEY_VALUE` (0x18 bytes com o primeiro caractere do nome): 'vk'.
#[repr(C)]
pub struct CmKeyValue {
    pub signature: Field<u16>,
    pub name_length: Field<u16>,
    /// Bit 31 (CM_KEY_VALUE_SPECIAL_SIZE): dado no próprio `data`.
    pub data_length: Field<u32>,
    pub data: Field<u32>,
    pub type_: Field<u32>,
    pub flags: Field<u16>,
    pub spare: Field<u16>,
    pub name: [Field<u16>; 1],
    _pad: Reserved<2>,
}

unsafe impl NtStruct for CmKeyValue {}

const _: () = {
    assert!(core::mem::size_of::<CmKeyValue>() == 0x18);
    assert!(core::mem::offset_of!(CmKeyValue, data_length) == 0x4);
    assert!(core::mem::offset_of!(CmKeyValue, data) == 0x8);
    assert!(core::mem::offset_of!(CmKeyValue, type_) == 0xc);
    assert!(core::mem::offset_of!(CmKeyValue, flags) == 0x10);
    assert!(core::mem::offset_of!(CmKeyValue, name) == 0x14);
};

/// `_CM_KEY_SECURITY` (0x28 bytes com o cabeçalho do descritor): 'sk'.
#[repr(C)]
pub struct CmKeySecurity {
    pub signature: Field<u16>,
    pub reserved: Field<u16>,
    pub flink: Field<u32>,
    pub blink: Field<u32>,
    pub reference_count: Field<u32>,
    pub descriptor_length: Field<u32>,
    pub descriptor: SecurityDescriptorRelative,
}

unsafe impl NtStruct for CmKeySecurity {}

const _: () = {
    assert!(core::mem::size_of::<CmKeySecurity>() == 0x28);
    assert!(core::mem::offset_of!(CmKeySecurity, flink) == 0x4);
    assert!(core::mem::offset_of!(CmKeySecurity, reference_count) == 0xc);
    assert!(core::mem::offset_of!(CmKeySecurity, descriptor_length) == 0x10);
    assert!(core::mem::offset_of!(CmKeySecurity, descriptor) == 0x14);
};

/// `_CM_KEY_INDEX` (0x8 bytes com a primeira entrada): 'li' e 'ri'.
#[repr(C)]
pub struct CmKeyIndex {
    pub signature: Field<u16>,
    pub count: Field<u16>,
    pub list: [Field<u32>; 1],
}

unsafe impl NtStruct for CmKeyIndex {}

const _: () = {
    assert!(core::mem::size_of::<CmKeyIndex>() == 0x8);
    assert!(core::mem::offset_of!(CmKeyIndex, list) == 0x4);
};

/// `_CM_INDEX` (0x8 bytes): uma entrada de 'lf' (NameHint, os quatro
/// primeiros caracteres) ou de 'lh' (HashKey).
#[repr(C)]
pub struct CmIndex {
    pub cell: Field<u32>,
    pub hash_key: Field<u32>,
}

unsafe impl NtStruct for CmIndex {}

const _: () = {
    assert!(core::mem::size_of::<CmIndex>() == 0x8);
    assert!(core::mem::offset_of!(CmIndex, hash_key) == 0x4);
};

/// `_CM_KEY_FAST_INDEX` (0xc bytes com a primeira entrada): 'lf' e 'lh'.
#[repr(C)]
pub struct CmKeyFastIndex {
    pub signature: Field<u16>,
    pub count: Field<u16>,
    pub list: [CmIndex; 1],
}

unsafe impl NtStruct for CmKeyFastIndex {}

const _: () = {
    assert!(core::mem::size_of::<CmKeyFastIndex>() == 0xc);
    assert!(core::mem::offset_of!(CmKeyFastIndex, list) == 0x4);
};

/// `_CM_BIG_DATA` (0x8 bytes): 'db', o número de segmentos e a célula com a
/// lista deles.
#[repr(C)]
pub struct CmBigData {
    pub signature: Field<u16>,
    pub count: Field<u16>,
    pub list: Field<u32>,
}

unsafe impl NtStruct for CmBigData {}

const _: () = {
    assert!(core::mem::size_of::<CmBigData>() == 0x8);
    assert!(core::mem::offset_of!(CmBigData, list) == 0x4);
};
