//! Estruturas de processo.
//!
//! TEB, PEB, RTL_USER_PROCESS_PARAMETERS e PEB_LDR_DATA que o loader da
//! ntdll (LdrInitializeThunk) lê: tudo em páginas de usuário reais. Os
//! offsets do PEB foram conferidos na ntdll 24H2 (NLS em +0xA0/+0xA8/+0xB0).

use alloc::format;
use alloc::vec::Vec;

use super::memory;
use super::state::{self, write_user_wide, USER_STACK_SIZE, USER_STACK_TOP};
use crate::ntos::ke::smp;
use crate::ntos::ps::session;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{Eprocess, ListEntry, NtStruct, Peb, PebLdrData, RtlUserProcessParameters, Teb, UnicodeString};

/// Processo sendo montado (por `run_windows_process`).
pub struct ProcessDescription<'a> {
    pub process_id: u64,
    pub process_pointer: u64,
    pub image_base: u64,
    pub dos_path: &'a str,
    pub detached: bool,
    pub console_handle: u64,
}

/// LIST_ENTRY circular vazia (InitializeListHead).
pub fn initialize_list_head(head: &ListEntry) {
    head.flink.set(head.address());
    head.blink.set(head.address());
}

/// InsertTailList numa lista de uma estrutura do processo montada pelo kernel.
pub fn insert_tail_list(head: &ListEntry, link: &ListEntry) {
    // SAFETY: o último elemento é outro LIST_ENTRY vivo da mesma lista.
    let last = unsafe { ListEntry::at(head.blink.get()) };
    link.flink.set(head.address());
    link.blink.set(last.address());
    last.flink.set(link.address());
    head.blink.set(link.address());
}

/// [`initialize_list_head`] por endereço.
pub fn write_list_head(head: u64) {
    // SAFETY: estrutura do processo criada e comprometida pelo kernel.
    initialize_list_head(unsafe { ListEntry::at(head) });
}

/// Insere `entry + entry_offset` no fim da lista de `head + head_offset`.
pub fn insert_list_tail(head: u64, head_offset: u64, entry: u64, entry_offset: u64) {
    // SAFETY: cabeça e elo são LIST_ENTRYs de estruturas do processo.
    unsafe { insert_tail_list(ListEntry::at(head + head_offset), ListEntry::at(entry + entry_offset)) }
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

    // SAFETY: as estruturas acabam de ser comprometidas acima e nenhum
    // código de usuário roda no processo ainda.
    let (teb_block, peb_block, ldr_block, parameters) = unsafe { (Teb::at(teb), Peb::at(peb), PebLdrData::at(ldr), RtlUserProcessParameters::at(rupp)) };
    // TEB: StackBase/Limit, Self, ClientId e ProcessEnvironmentBlock.
    teb_block.nt_tib.stack_base.set(USER_STACK_TOP);
    teb_block.nt_tib.stack_limit.set(USER_STACK_TOP - USER_STACK_SIZE);
    teb_block.nt_tib.self_.set(teb);
    teb_block.client_id.unique_process.set(process.process_id);
    teb_block.client_id.unique_thread.set(process.process_id); // tid = pid na primeira thread
    teb_block.process_environment_block.set(peb);
    teb_block.deallocation_stack.set(USER_STACK_TOP - USER_STACK_SIZE);

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
    // Bloco de ambiente: as strings com NUL e o NUL final.
    let block: Vec<u8> = environment.encode_utf16().chain(core::iter::once(0)).flat_map(u16::to_le_bytes).collect();
    guest::write_bytes(rupp + environment_offset, &block);
    string_offset += block.len() as u64;
    // Length cobre estrutura + strings; MaximumLength, a região inteira.
    parameters.maximum_length.set(0x2000);
    parameters.length.set(string_offset as u32);
    parameters.flags.set(0);
    parameters.console_handle.set(if process.detached { u64::MAX } else { 0 }); // HANDLE_DETACHED_PROCESS
    // Auto-relativo: Buffer é o offset desde a base do bloco.
    let relative = |string: &UnicodeString, offset: u64, text: &str| {
        let bytes = units(text) as u16 * 2;
        string.length.set(bytes);
        string.maximum_length.set(bytes + 2);
        string.buffer.set(offset);
    };
    relative(&parameters.current_directory.dos_path, current_directory_offset, "C:\\");
    relative(&parameters.dll_path, dll_path_offset, "C:\\Windows\\System32");
    relative(&parameters.image_path_name, image_path_offset, process.dos_path);
    relative(&parameters.command_line, command_line_offset, &command_line);
    // Environment é absoluto: a cópia do loader só converte os Buffers.
    parameters.environment.set(rupp + environment_offset);
    parameters.standard_input.set(0);
    parameters.standard_output.set(process.console_handle);
    parameters.standard_error.set(process.console_handle);

    // PEB_LDR_DATA começa vazio: os módulos entram por `create_ldr_entry`.
    ldr_block.length.set(PebLdrData::SIZE as u32);
    ldr_block.initialized.set(1);
    initialize_list_head(&ldr_block.in_load_order_module_list);
    initialize_list_head(&ldr_block.in_memory_order_module_list);
    initialize_list_head(&ldr_block.in_initialization_order_module_list);

    let (api_set_map, nls) = state::with(|state| (state.api_set_map_va, state.nls_vas.unwrap_or_default()));
    let processors = smp::online_cpu_count() as u64;
    peb_block.being_debugged.set(0);
    peb_block.image_base_address.set(process.image_base);
    peb_block.ldr.set(ldr);
    peb_block.process_parameters.set(rupp);
    peb_block.api_set_map.set(api_set_map);
    peb_block.ansi_code_page_data.set(nls.ansi);
    peb_block.oem_code_page_data.set(nls.oem);
    peb_block.unicode_case_table_data.set(nls.unicode);
    peb_block.number_of_processors.set(processors as u32);
    peb_block.heap_segment_reserve.set(0x10_0000); // reserva do heap
    peb_block.heap_segment_commit.set(0x2000); // commit inicial dos segmentos
    peb_block.heap_de_commit_total_free_threshold.set(0x10000); // decommit total livre
    peb_block.heap_de_commit_free_block_threshold.set(0x1000); // decommit de bloco livre
    peb_block.maximum_number_of_heaps.set(0x100); // capacidade do vetor de heaps
    // O vetor de heaps fica na mesma página, logo depois da PEB.
    peb_block.process_heaps.set(peb + 0x800);
    peb_block.active_process_affinity_mask.set((1u64 << processors) - 1);
    peb_block.os_major_version.set(10);
    peb_block.os_minor_version.set(0);
    peb_block.os_build_number.set(26100);
    peb_block.os_platform_id.set(2); // VER_PLATFORM_WIN32_NT
    peb_block.session_id.set(session::query(process.process_pointer));
    state::with(|state| {
        state.current_peb_va = peb;
        state.current_ldr_va = ldr;
    });
    // SAFETY: o EPROCESS do processo em montagem.
    unsafe { Eprocess::at(process.process_pointer) }.peb.set(peb);
    Ok(teb)
}
