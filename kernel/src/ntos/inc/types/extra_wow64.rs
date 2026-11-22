//! Estruturas do WoW64 que os símbolos do ntoskrnl não têm.
//!
//! Mantido à mão, no estilo de `types`: `#[repr(C)]`, folhas `Field<T>`,
//! `size_of`/`offset_of!` conferidos em compilação. A PEB de 32 bits
//! (`_PEB32`), a TEB de 32 bits (`_TEB32`), o `_EWOW64PROCESS` e as
//! strings de 32 bits (`_STRING32`) constam dos símbolos e são gerados
//! (`ps.rs`, `rtl.rs`); ficam reexportados aqui.
//!
//! - [`Wow64Context`]: o CONTEXT do x86 (`WOW64_CONTEXT` do winnt.h, 0x2CC
//!   bytes), o que o PspWow64InitThreadGuestx86 monta na área de CPU da
//!   thread.
//! - [`Wow64CpuReserved`]: o cabeçalho da área de CPU no topo da pilha de 64
//!   bits (TEB.TlsSlots[WOW64_TLS_CPURESERVED]): Flags e Machine, com o
//!   contexto x86 logo depois (o PspWow64InitThread grava Machine << 16 no
//!   primeiro ULONG; o RunSimulatedCode do wow64cpu lê o contexto em +4 e o
//!   bit 0 de Flags pede a restauração completa).
//! - [`RtlUserProcessParameters32`]: o bloco de parâmetros de 32 bits que o
//!   PspWow64ThunkProcessParameters (19041 0x32068c) copia do nativo, com os
//!   deslocamentos dele.
//! - [`PsSystemDllInitBlock`]: o LdrSystemDllInitBlock das ntdll (0xF0
//!   bytes), como o PspPrepareSystemDllInitBlock (0x611e28) o preenche.

use super::*;

pub use super::{Ewow64process, Peb32, String32, Teb32};

/// `WOW64_FLOATING_SAVE_AREA` (0x70 bytes).
#[repr(C)]
pub struct Wow64FloatingSaveArea {
    pub control_word: Field<u32>,
    pub status_word: Field<u32>,
    pub tag_word: Field<u32>,
    pub error_offset: Field<u32>,
    pub error_selector: Field<u32>,
    pub data_offset: Field<u32>,
    pub data_selector: Field<u32>,
    pub register_area: [Field<u8>; 80],
    pub cr0_npx_state: Field<u32>,
}

unsafe impl NtStruct for Wow64FloatingSaveArea {}

/// `WOW64_CONTEXT` (0x2CC bytes).
#[repr(C)]
pub struct Wow64Context {
    pub context_flags: Field<u32>,
    pub dr0: Field<u32>,
    pub dr1: Field<u32>,
    pub dr2: Field<u32>,
    pub dr3: Field<u32>,
    pub dr6: Field<u32>,
    pub dr7: Field<u32>,
    pub float_save: Wow64FloatingSaveArea,
    pub seg_gs: Field<u32>,
    pub seg_fs: Field<u32>,
    pub seg_es: Field<u32>,
    pub seg_ds: Field<u32>,
    pub edi: Field<u32>,
    pub esi: Field<u32>,
    pub ebx: Field<u32>,
    pub edx: Field<u32>,
    pub ecx: Field<u32>,
    pub eax: Field<u32>,
    pub ebp: Field<u32>,
    pub eip: Field<u32>,
    pub seg_cs: Field<u32>,
    pub e_flags: Field<u32>,
    pub esp: Field<u32>,
    pub seg_ss: Field<u32>,
    /// A área do FXSAVE: FCW em +0, MXCSR em +0x18.
    pub extended_registers: [Field<u8>; 512],
}

unsafe impl NtStruct for Wow64Context {}

impl Wow64Context {
    /// FCW e MXCSR dentro de ExtendedRegisters (o formato do FXSAVE).
    pub const EXTENDED_CONTROL_WORD: usize = 0;
    pub const EXTENDED_MX_CSR: usize = 0x18;
}

/// O cabeçalho da área de CPU de uma thread WoW64.
#[repr(C)]
pub struct Wow64CpuReserved {
    pub flags: Field<u16>,
    pub machine: Field<u16>,
}

unsafe impl NtStruct for Wow64CpuReserved {}

impl Wow64CpuReserved {
    /// O contexto x86 vem logo depois do cabeçalho (o alinhamento do
    /// contexto do x86 é 4).
    pub const CONTEXT_OFFSET: u64 = 4;
    /// Flags: o contexto mudou e o simulador faz a restauração completa.
    pub const FLAG_RESET_STATE: u16 = 1;
}

/// `RTL_DRIVE_LETTER_CURDIR32` (0x10 bytes).
#[repr(C)]
pub struct RtlDriveLetterCurdir32 {
    pub flags: Field<u16>,
    pub length: Field<u16>,
    pub time_stamp: Field<u32>,
    pub dos_path: String32,
}

unsafe impl NtStruct for RtlDriveLetterCurdir32 {}

/// `RTL_USER_PROCESS_PARAMETERS32` (0x2C0 bytes).
#[repr(C)]
pub struct RtlUserProcessParameters32 {
    pub maximum_length: Field<u32>,
    pub length: Field<u32>,
    pub flags: Field<u32>,
    pub debug_flags: Field<u32>,
    pub console_handle: Field<u32>,
    pub console_flags: Field<u32>,
    pub standard_input: Field<u32>,
    pub standard_output: Field<u32>,
    pub standard_error: Field<u32>,
    pub current_directory_dos_path: String32,
    pub current_directory_handle: Field<u32>,
    pub dll_path: String32,
    pub image_path_name: String32,
    pub command_line: String32,
    pub environment: Field<u32>,
    pub starting_x: Field<u32>,
    pub starting_y: Field<u32>,
    pub count_x: Field<u32>,
    pub count_y: Field<u32>,
    pub count_chars_x: Field<u32>,
    pub count_chars_y: Field<u32>,
    pub fill_attribute: Field<u32>,
    pub window_flags: Field<u32>,
    pub show_window_flags: Field<u32>,
    pub window_title: String32,
    pub desktop_info: String32,
    pub shell_info: String32,
    pub runtime_data: String32,
    pub current_directores: [RtlDriveLetterCurdir32; 32],
    pub environment_size: Field<u32>,
    pub environment_version: Field<u32>,
    pub package_dependency_data: Field<u32>,
    pub process_group_id: Field<u32>,
    pub loader_threads: Field<u32>,
    pub redirection_dll_name: String32,
    pub heap_partition_name: String32,
    pub default_threadpool_cpu_set_masks: Field<u32>,
    pub default_threadpool_cpu_set_mask_count: Field<u32>,
    pub default_threadpool_thread_maximum: Field<u32>,
}

unsafe impl NtStruct for RtlUserProcessParameters32 {}

/// `PS_MITIGATION_OPTIONS_MAP` e `PS_MITIGATION_AUDIT_OPTIONS_MAP` (três
/// ULONGLONG).
#[repr(C)]
pub struct PsMitigationOptionsMap {
    pub map: [Field<u64>; 3],
}

unsafe impl NtStruct for PsMitigationOptionsMap {}

/// `PS_SYSTEM_DLL_INIT_BLOCK` (0xF0 bytes).
#[repr(C)]
pub struct PsSystemDllInitBlock {
    pub size: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub system_dll_wow_relocation: Field<u64>,
    pub system_dll_native_relocation: Field<u64>,
    pub wow64_shared_information: [Field<u64>; 16],
    pub rng_data: Field<u32>,
    pub flags: Field<u32>,
    pub mitigation_options_map: PsMitigationOptionsMap,
    pub cfg_bit_map: Field<u64>,
    pub cfg_bit_map_size: Field<u64>,
    pub wow64_cfg_bit_map: Field<u64>,
    pub wow64_cfg_bit_map_size: Field<u64>,
    pub mitigation_audit_options_map: PsMitigationOptionsMap,
}

unsafe impl NtStruct for PsSystemDllInitBlock {}

const _: () = {
    assert!(core::mem::size_of::<Wow64FloatingSaveArea>() == 0x70);
    assert!(core::mem::size_of::<Wow64Context>() == 0x2cc);
    assert!(core::mem::offset_of!(Wow64Context, float_save) == 0x1c);
    assert!(core::mem::offset_of!(Wow64Context, seg_gs) == 0x8c);
    assert!(core::mem::offset_of!(Wow64Context, seg_fs) == 0x90);
    assert!(core::mem::offset_of!(Wow64Context, edi) == 0x9c);
    assert!(core::mem::offset_of!(Wow64Context, eax) == 0xb0);
    assert!(core::mem::offset_of!(Wow64Context, eip) == 0xb8);
    assert!(core::mem::offset_of!(Wow64Context, seg_cs) == 0xbc);
    assert!(core::mem::offset_of!(Wow64Context, esp) == 0xc4);
    assert!(core::mem::offset_of!(Wow64Context, seg_ss) == 0xc8);
    assert!(core::mem::offset_of!(Wow64Context, extended_registers) == 0xcc);
    assert!(core::mem::size_of::<Wow64CpuReserved>() == 0x4);
    assert!(core::mem::size_of::<RtlDriveLetterCurdir32>() == 0x10);
    assert!(core::mem::size_of::<RtlUserProcessParameters32>() == 0x2c0);
    assert!(core::mem::offset_of!(RtlUserProcessParameters32, current_directory_dos_path) == 0x24);
    assert!(core::mem::offset_of!(RtlUserProcessParameters32, current_directory_handle) == 0x2c);
    assert!(core::mem::offset_of!(RtlUserProcessParameters32, dll_path) == 0x30);
    assert!(core::mem::offset_of!(RtlUserProcessParameters32, environment) == 0x48);
    assert!(core::mem::offset_of!(RtlUserProcessParameters32, starting_x) == 0x4c);
    assert!(core::mem::offset_of!(RtlUserProcessParameters32, window_title) == 0x70);
    assert!(core::mem::offset_of!(RtlUserProcessParameters32, runtime_data) == 0x88);
    assert!(core::mem::offset_of!(RtlUserProcessParameters32, current_directores) == 0x90);
    assert!(core::mem::offset_of!(RtlUserProcessParameters32, environment_size) == 0x290);
    assert!(core::mem::offset_of!(RtlUserProcessParameters32, process_group_id) == 0x29c);
    assert!(core::mem::offset_of!(RtlUserProcessParameters32, redirection_dll_name) == 0x2a4);
    assert!(core::mem::offset_of!(RtlUserProcessParameters32, heap_partition_name) == 0x2ac);
    assert!(core::mem::offset_of!(RtlUserProcessParameters32, default_threadpool_thread_maximum) == 0x2bc);
    assert!(core::mem::size_of::<PsSystemDllInitBlock>() == 0xf0);
    assert!(core::mem::offset_of!(PsSystemDllInitBlock, system_dll_wow_relocation) == 0x8);
    assert!(core::mem::offset_of!(PsSystemDllInitBlock, wow64_shared_information) == 0x18);
    assert!(core::mem::offset_of!(PsSystemDllInitBlock, rng_data) == 0x98);
    assert!(core::mem::offset_of!(PsSystemDllInitBlock, mitigation_options_map) == 0xa0);
    assert!(core::mem::offset_of!(PsSystemDllInitBlock, cfg_bit_map) == 0xb8);
    assert!(core::mem::offset_of!(PsSystemDllInitBlock, wow64_cfg_bit_map_size) == 0xd0);
    assert!(core::mem::offset_of!(PsSystemDllInitBlock, mitigation_audit_options_map) == 0xd8);
};
