//! Estruturas de processo.
//!
//! TEB, PEB, RTL_USER_PROCESS_PARAMETERS e PEB_LDR_DATA que o loader da
//! ntdll (LdrInitializeThunk) lê: tudo em páginas de usuário reais. Os
//! offsets do PEB foram conferidos na ntdll 24H2 (NLS em +0xA0/+0xA8/+0xB0).

use alloc::format;

use super::memory;
use super::state::{self, write_user_wide, USER_STACK_SIZE, USER_STACK_TOP};
use crate::ntos::ke::smp;
use crate::ntos::ps::session;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::eprocess;

/// PEB_LDR_DATA (x64, estável do Win8 ao 24H2).
pub mod peb_ldr {
    pub const INITIALIZED: u64 = 0x04;
    pub const IN_LOAD_ORDER: u64 = 0x10;
    pub const IN_MEMORY_ORDER: u64 = 0x20;
    pub const IN_INIT_ORDER: u64 = 0x30;
}

/// LDR_DATA_TABLE_ENTRY.
pub mod ldr_entry {
    pub const IN_LOAD_ORDER_LINKS: u64 = 0x00;
    pub const IN_MEMORY_ORDER_LINKS: u64 = 0x10;
    pub const IN_INIT_ORDER_LINKS: u64 = 0x20;
    pub const DLL_BASE: u64 = 0x30;
    pub const ENTRY_POINT: u64 = 0x38;
    pub const SIZE_OF_IMAGE: u64 = 0x40;
    pub const FULL_DLL_NAME: u64 = 0x48;
    pub const BASE_DLL_NAME: u64 = 0x58;
    pub const FLAGS: u64 = 0x68;
    pub const LOAD_COUNT: u64 = 0x6C;
    pub const SIZE: u64 = 0x110;
}

/// Processo sendo montado (`process` de `runWindowsProcess`).
pub struct ProcessDescription<'a> {
    pub process_id: u64,
    pub process_pointer: u64,
    pub image_base: u64,
    pub dos_path: &'a str,
    pub detached: bool,
    pub console_handle: u64,
}

/// LIST_ENTRY circular vazia.
pub fn write_list_head(head: u64) {
    guest::write64(head, head);
    guest::write64(head + 8, head);
}

/// Insere `entry + entry_offset` no fim da lista de `head + head_offset`.
pub fn insert_list_tail(head: u64, head_offset: u64, entry: u64, entry_offset: u64) {
    let head = head + head_offset;
    let link = entry + entry_offset;
    let last = guest::read64(head + 8);
    guest::write64(link, head);
    guest::write64(link + 8, last);
    guest::write64(last, link);
    guest::write64(head + 8, link);
}

fn units(text: &str) -> u64 {
    text.encode_utf16().count() as u64
}

/// Regiões separadas como no NT: PEB/TEB/Ldr pertencem ao kernel pela vida
/// do processo; o bloco de parâmetros (que o loader pode normalizar e
/// substituir) vive na própria região. Devolve a TEB da primeira thread.
pub fn build_process_structures(process: &ProcessDescription) -> Result<u64, KernelError> {
    let core = memory::map_user_region(0x8000)?;
    // A TEB x64 passa de 0x1800 (TLS/FLS/SameTebFlags): sua segunda página
    // nunca pode coincidir com a PEB.
    let teb = core;
    let peb = core + 0x2000;
    let ldr = core + 0x3000;
    let rupp = memory::map_user_region(0x2000)?;
    // Strings bem depois da estrutura: a 24H2 lê campos até +0x440.
    let mut string_offset = 0x800u64;
    let _strings = memory::map_user_region(0x4000)?;

    // TEB: StackBase/Limit, Self, ClientId e ProcessEnvironmentBlock.
    guest::write64(teb + 0x08, USER_STACK_TOP);
    guest::write64(teb + 0x10, USER_STACK_TOP - USER_STACK_SIZE);
    guest::write64(teb + 0x30, teb);
    guest::write64(teb + 0x40, process.process_id);
    guest::write64(teb + 0x48, process.process_id); // tid = pid na primeira thread
    guest::write64(teb + 0x60, peb);
    guest::write64(teb + 0x1478, USER_STACK_TOP - USER_STACK_SIZE);

    // RTL_USER_PROCESS_PARAMETERS no formato entregue pelo kernel:
    // auto-relativo (ponteiros são offsets desde a base, sem NORMALIZED).
    let mut rupp_string = |text: &str| {
        let offset = string_offset;
        write_user_wide(rupp + offset, text);
        string_offset += (units(text) + 1) * 2 + 8;
        offset
    };
    let command_line = format!("\"{}\"", process.dos_path);
    let image_path_offset = rupp_string(process.dos_path);
    let command_line_offset = rupp_string(&command_line);
    let dll_path_offset = rupp_string("C:\\Windows\\System32");
    let current_directory_offset = rupp_string("C:\\");
    let environment_offset = string_offset;
    let environment = "SystemRoot=C:\\Windows\0PATH=C:\\Windows\\System32;C:\\Windows\0WINDIR=C:\\Windows\0";
    let mut count = 0u64;
    for unit in environment.encode_utf16() {
        guest::write16(rupp + environment_offset + count * 2, unit);
        count += 1;
    }
    guest::write16(rupp + environment_offset + count * 2, 0);
    string_offset += (count + 1) * 2;
    // Length cobre estrutura + strings; MaximumLength, a região inteira.
    guest::write32(rupp, 0x2000);
    guest::write32(rupp + 0x04, string_offset as u32);
    guest::write32(rupp + 0x08, 0);
    guest::write64(rupp + 0x10, if process.detached { u64::MAX } else { 0 }); // HANDLE_DETACHED_PROCESS
    let relative = |structure: u64, offset: u64, text: &str| {
        let bytes = units(text) * 2;
        guest::write16(structure, bytes as u16);
        guest::write16(structure + 2, (bytes + 2) as u16);
        guest::write32(structure + 4, 0);
        guest::write64(structure + 8, offset);
    };
    relative(rupp + 0x38, current_directory_offset, "C:\\");
    relative(rupp + 0x50, dll_path_offset, "C:\\Windows\\System32");
    relative(rupp + 0x60, image_path_offset, process.dos_path);
    relative(rupp + 0x70, command_line_offset, &command_line);
    // Environment é absoluto: a cópia do loader só converte os Buffers.
    guest::write64(rupp + 0x80, rupp + environment_offset);
    guest::write64(rupp + 0x20, 0);
    guest::write64(rupp + 0x28, process.console_handle);
    guest::write64(rupp + 0x30, process.console_handle);

    // PEB_LDR_DATA começa vazio: os módulos entram por `createLdrEntry`.
    guest::write32(ldr, 0x58);
    guest::write8(ldr + peb_ldr::INITIALIZED, 1);
    write_list_head(ldr + peb_ldr::IN_LOAD_ORDER);
    write_list_head(ldr + peb_ldr::IN_MEMORY_ORDER);
    write_list_head(ldr + peb_ldr::IN_INIT_ORDER);

    let (api_set_map, nls) = state::with(|state| (state.api_set_map_va, state.nls_vas.unwrap_or_default()));
    let processors = smp::online_cpu_count() as u64;
    guest::write8(peb + 0x02, 0); // BeingDebugged
    guest::write64(peb + 0x10, process.image_base);
    guest::write64(peb + 0x18, ldr);
    guest::write64(peb + 0x20, rupp);
    guest::write64(peb + 0x68, api_set_map);
    guest::write64(peb + 0xA0, nls.ansi);
    guest::write64(peb + 0xA8, nls.oem);
    guest::write64(peb + 0xB0, nls.unicode);
    guest::write32(peb + 0xB8, processors as u32);
    guest::write64(peb + 0xC8, 0x10_0000); // reserva do heap
    guest::write64(peb + 0xD0, 0x2000); // commit inicial dos segmentos
    guest::write64(peb + 0xD8, 0x10000); // decommit total livre
    guest::write64(peb + 0xE0, 0x1000); // decommit de bloco livre
    guest::write32(peb + 0xEC, 0x100); // capacidade do vetor de heaps
    guest::write64(peb + 0xF0, peb + 0x800);
    guest::write64(peb + 0x138, (1u64 << processors) - 1);
    guest::write32(peb + 0x118, 10); // OSMajorVersion
    guest::write32(peb + 0x11C, 0); // OSMinorVersion
    guest::write16(peb + 0x120, 26100); // OSBuildNumber
    guest::write32(peb + 0x124, 2); // VER_PLATFORM_WIN32_NT
    guest::write32(peb + 0x2C0, session::query(process.process_pointer));
    state::with(|state| {
        state.current_peb_va = peb;
        state.current_ldr_va = ldr;
    });
    guest::write64(process.process_pointer + eprocess::PEB, peb);
    Ok(teb)
}
