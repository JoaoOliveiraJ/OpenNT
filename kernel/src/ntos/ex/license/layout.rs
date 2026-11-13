//! Estruturas do licenciamento: o contexto por silo (EXP_LICENSE_STATE,
//! apontado por ESERVERSILO_GLOBALS.ExpLicenseState), os descritores do
//! índice e o formato binário do valor ProductPolicy.

use crate::ntos::inc::field::{Field, NtStruct, Reserved, UnalignedField};
use crate::ntos::inc::types::{ExPushLock, UnicodeString};
use crate::ntos::mm::guest_memory as guest;

/// Capacidade do índice de descritores do contexto.
pub const DESCRIPTOR_CAPACITY: usize = 0xB6D;
/// Capacidade do buffer primário do ProductPolicy capturado no boot.
pub const POLICY_CAPACITY: u32 = 0x14000;
/// `kind` de um descritor que aponta direto para uma entrada do blob.
pub const RAW_ENTRY: u8 = 2;

/// Descritor do índice (16 bytes): `kind` 2 aponta para uma entrada do blob;
/// os demais apontam para um UNICODE_STRING com o nome.
#[repr(C)]
pub struct Descriptor {
    pub kind: Field<u8>,
    _pad_1: Reserved<0x7>,
    pub entry: Field<u64>,
}

/// Contexto de licença (0xB7C0 bytes): blob primário, seção e visão da
/// política publicada, o índice ordenado, os dois push locks e o estado.
#[repr(C)]
pub struct ExpLicenseState {
    /// -> buffer primário ([`PolicyCapture`] no fim).
    pub primary: Field<u64>,
    pub context_value: Field<u32>,
    _pad_c: Reserved<0x4>,
    /// -> SECTION da política publicada.
    pub section: Field<u64>,
    pub descriptors: [Descriptor; DESCRIPTOR_CAPACITY],
    pub descriptor_count: Field<u32>,
    pub index_built: Field<u8>,
    _pad_b6ed: Reserved<0x3>,
    /// -> visão de sistema da política publicada.
    pub view: Field<u64>,
    pub policy_lock: ExPushLock,
    /// -> KEVENT sinalizado na mudança de estado.
    pub change_event: Field<u64>,
    pub subscription_cached: Field<u8>,
    _pad_b709: Reserved<0x1>,
    pub subscription_pfn: [Field<u8>; 0x82],
    pub local_state: Field<u32>,
    pub corrupt: Field<u8>,
    pub session_identifier: [Field<u8>; 16],
    _pad_b7a1: Reserved<0x7>,
    /// -> portador do registro de estado (ver `state.rs`).
    pub state_carrier: Field<u64>,
    pub state_lock: ExPushLock,
    pub refresh_interval: Field<u32>,
    _pad_b7bc: Reserved<0x4>,
}

impl ExpLicenseState {
    /// Endereço do vetor de descritores (para quem o recebe como ponteiro).
    pub fn descriptor_array(&self) -> u64 {
        self.descriptors.as_ptr() as u64
    }
}

/// Cabeçalho do valor ProductPolicy (0x14 bytes), seguido das entradas e
/// do marcador final.
#[repr(C)]
pub struct PolicyHeader {
    pub total_size: Field<u32>,
    pub values_size: Field<u32>,
    pub end_marker_size: Field<u32>,
    pub flags: Field<u32>,
    pub version: Field<u32>,
}

/// Entrada do ProductPolicy (cabeçalho de 0x10 bytes, depois nome e dados).
/// O formato binário não garante alinhamento das entradas: os campos são
/// lidos sem exigir alinhamento natural, como o helper nativo faz.
#[repr(C)]
pub struct PolicyEntry {
    pub size: UnalignedField<u16>,
    pub name_size: UnalignedField<u16>,
    pub data_type: UnalignedField<u16>,
    pub data_size: UnalignedField<u16>,
    pub flags: UnalignedField<u32>,
    pub reserved: UnalignedField<u32>,
}

/// Rodapé do buffer primário (logo após os POLICY_CAPACITY bytes de dados).
#[repr(C)]
pub struct PolicyCapture {
    pub captured_size: Field<u32>,
    pub value_type: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for Descriptor {}
// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for ExpLicenseState {}
// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for PolicyHeader {}
// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for PolicyEntry {}
// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for PolicyCapture {}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<Descriptor>() == 0x10);
    assert!(size_of::<ExpLicenseState>() == 0xB7C0);
    assert!(offset_of!(ExpLicenseState, section) == 0x10);
    assert!(offset_of!(ExpLicenseState, descriptors) == 0x18);
    assert!(offset_of!(ExpLicenseState, descriptor_count) == 0xB6E8);
    assert!(offset_of!(ExpLicenseState, index_built) == 0xB6EC);
    assert!(offset_of!(ExpLicenseState, view) == 0xB6F0);
    assert!(offset_of!(ExpLicenseState, policy_lock) == 0xB6F8);
    assert!(offset_of!(ExpLicenseState, change_event) == 0xB700);
    assert!(offset_of!(ExpLicenseState, subscription_cached) == 0xB708);
    assert!(offset_of!(ExpLicenseState, subscription_pfn) == 0xB70A);
    assert!(offset_of!(ExpLicenseState, local_state) == 0xB78C);
    assert!(offset_of!(ExpLicenseState, corrupt) == 0xB790);
    assert!(offset_of!(ExpLicenseState, session_identifier) == 0xB791);
    assert!(offset_of!(ExpLicenseState, state_carrier) == 0xB7A8);
    assert!(offset_of!(ExpLicenseState, state_lock) == 0xB7B0);
    assert!(offset_of!(ExpLicenseState, refresh_interval) == 0xB7B8);
    assert!(size_of::<PolicyHeader>() == 0x14);
    assert!(size_of::<PolicyEntry>() == 0x10);
    assert!(size_of::<PolicyCapture>() == 0x8);
};

/// O contexto em `context` (alocado pelo boot ou lido do silo).
pub fn context_at(context: u64) -> &'static ExpLicenseState {
    // SAFETY: só contextos alocados por `boot::create` circulam.
    unsafe { ExpLicenseState::at(context) }
}

/// Cabeçalho de um blob de política (primário, visão ou cópia).
pub fn header_at(blob: u64) -> &'static PolicyHeader {
    // SAFETY: blobs vivos do contexto ou do chamador.
    unsafe { PolicyHeader::at(blob) }
}

/// Entrada de política em `entry`.
pub fn entry_at(entry: u64) -> &'static PolicyEntry {
    // SAFETY: entradas dentro de um blob validado.
    unsafe { PolicyEntry::at(entry) }
}

/// Rodapé do buffer primário `primary`.
pub fn capture_at(primary: u64) -> &'static PolicyCapture {
    // SAFETY: o buffer primário tem POLICY_CAPACITY + 8 bytes.
    unsafe { PolicyCapture::at(primary + POLICY_CAPACITY as u64) }
}

/// Descritor em `descriptor` (do contexto ou de um vetor do pool).
pub fn descriptor_at(descriptor: u64) -> &'static Descriptor {
    // SAFETY: vetores de descritores alocados pelo licenciamento.
    unsafe { Descriptor::at(descriptor) }
}

/// Parâmetro de saída ULONG do chamador (PULONG Type / ResultDataSize).
pub fn ulong_at(address: u64) -> &'static Field<u32> {
    // SAFETY: ponteiros de saída de chamadores de modo kernel.
    unsafe { Field::<u32>::at(address) }
}

/// Indicador "tratado" (um BOOLEAN) na moldura da consulta.
pub fn byte_at(address: u64) -> &'static Field<u8> {
    // SAFETY: byte de uma moldura do licenciamento.
    unsafe { Field::<u8>::at(address) }
}

/// PUNICODE_STRING do nome consultado (chamador de modo kernel).
pub fn unicode_at(address: u64) -> &'static UnicodeString {
    // SAFETY: o ValueName do ZwQueryLicenseValue.
    unsafe { UnicodeString::at(address) }
}

/// UNICODE_STRING com os caracteres logo depois dele (+0x10), terminados
/// por NUL, numa moldura do licenciamento.
pub fn write_inline_name(descriptor: u64, text: &str) {
    write_name(descriptor, descriptor + UnicodeString::SIZE, text);
}

/// UNICODE_STRING apontando para `buffer`, que recebe os caracteres e o NUL.
pub fn write_name(descriptor: u64, buffer: u64, text: &str) {
    let units: alloc::vec::Vec<u16> = text.encode_utf16().collect();
    // SAFETY: moldura do pool do próprio licenciamento.
    let name = unsafe { UnicodeString::at(descriptor) };
    name.length.set(units.len() as u16 * 2);
    name.maximum_length.set((units.len() as u16 + 1) * 2);
    name.buffer.set(buffer);
    let bytes: alloc::vec::Vec<u8> = units.iter().chain(core::iter::once(&0)).flat_map(|unit| unit.to_le_bytes()).collect();
    guest::write_bytes(buffer, &bytes);
}

/// memmove: lê o bloco inteiro antes de gravar, então sobreposição é segura.
pub fn move_bytes(destination: u64, source: u64, length: u32) {
    if length != 0 {
        guest::write_bytes(destination, &guest::read_bytes(source, length as usize));
    }
}
