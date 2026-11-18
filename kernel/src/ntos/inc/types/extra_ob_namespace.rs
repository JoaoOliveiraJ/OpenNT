//! Os namespaces privados do Object Manager: o OBJECT_NAMESPACE_ENTRY que
//! os símbolos só citam como `void` (OBJECT_DIRECTORY.NamespaceEntry) e o
//! descritor de fronteira que a ntdll monta (RtlCreateBoundaryDescriptor,
//! RtlAddSIDToBoundaryDescriptor, RtlAddIntegrityLabelToBoundaryDescriptor).
//!
//! Layouts lidos do ntoskrnl 19041: o NtCreatePrivateNamespace (rva
//! 0x718640) põe a entrada logo depois do OBJECT_DIRECTORY de 0x158 bytes,
//! com ListEntry (+0), o diretório (+0x10), o tamanho da fronteira (+0x18),
//! o hash (+0x28) e a cópia da fronteira em +0x30; o
//! ObpCaptureBoundaryDescriptor (rva 0x718a8c) aloca a captura já nesse
//! formato. O RtlEnumerateBoundaryDescriptorEntries (rva 0x6ec33c) lê o
//! cabeçalho {Version, Items, TotalSize, Flags} e as entradas {EntryType,
//! EntrySize, dados}, cada uma alinhada a 8.
//!
//! Mantido à mão, no estilo de `types`: `#[repr(C)]`, folhas `Field<T>`,
//! `size_of`/`offset_of!` conferidos em compilação.

use super::*;

/// OBJECT_NAMESPACE_ENTRY (0x30 bytes; a fronteira segue em +0x30).
#[repr(C)]
pub struct ObjectNamespaceEntry {
    /// O balde da OBJECT_NAMESPACE_LOOKUPTABLE.
    pub list_entry: ListEntry,
    /// -> `_OBJECT_DIRECTORY` (0 enquanto o handle do criador não saiu, e
    /// depois da retirada da tabela).
    pub namespace: Field<u64>,
    /// O tamanho da cópia da fronteira em +0x30.
    pub size_of_boundary_information: Field<u64>,
    _reserved_20: Reserved<8>,
    /// Soma dos bytes de dados das entradas, módulo 37.
    pub hash_value: Field<u8>,
    _reserved_29: Reserved<7>,
}

unsafe impl NtStruct for ObjectNamespaceEntry {}

/// O cabeçalho do descritor de fronteira (0x10 bytes).
#[repr(C)]
pub struct ObjectBoundaryDescriptor {
    /// 1.
    pub version: Field<u32>,
    pub items: Field<u32>,
    pub total_size: Field<u32>,
    /// BOUNDARY_DESCRIPTOR_ADD_APPCONTAINER_SID (1).
    pub flags: Field<u32>,
}

unsafe impl NtStruct for ObjectBoundaryDescriptor {}

/// O cabeçalho de uma entrada da fronteira (0x8 bytes; os dados seguem).
#[repr(C)]
pub struct ObjectBoundaryEntry {
    /// 1 = nome, 2 = SID, 3 = rótulo de integridade.
    pub entry_type: Field<u32>,
    /// Cabeçalho mais dados.
    pub entry_data_size: Field<u32>,
}

unsafe impl NtStruct for ObjectBoundaryEntry {}

const _: () = {
    assert!(core::mem::size_of::<ObjectNamespaceEntry>() == 0x30);
    assert!(core::mem::offset_of!(ObjectNamespaceEntry, namespace) == 0x10);
    assert!(core::mem::offset_of!(ObjectNamespaceEntry, size_of_boundary_information) == 0x18);
    assert!(core::mem::offset_of!(ObjectNamespaceEntry, hash_value) == 0x28);
    assert!(core::mem::size_of::<ObjectBoundaryDescriptor>() == 0x10);
    assert!(core::mem::offset_of!(ObjectBoundaryDescriptor, total_size) == 0x8);
    assert!(core::mem::size_of::<ObjectBoundaryEntry>() == 0x8);
};
