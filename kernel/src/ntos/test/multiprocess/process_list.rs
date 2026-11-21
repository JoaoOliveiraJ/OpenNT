//! A lista de processos do NtQuerySystemInformation contra a
//! ProcessVmCounters, sobre um processo real.
//!
//! - Um processo criado pelo caminho único com a thread principal suspensa
//!   (o VAD e as tabelas dele ficam parados) aparece nas classes 5, 57 e
//!   148 com o nome da imagem (o caminho inteiro na 148), uma thread do
//!   tamanho da classe (0x50 ou 0x88), o UniqueProcessKey só fora da 5, a
//!   extensão depois das threads (o ProcessSequenceNumber do EPROCESS) e,
//!   na 148, o SID do usuário do token no UserSidOffset 0x170.
//! - Os campos de memória do registro são os da ProcessVmCounters
//!   (VM_COUNTERS_EX2) do mesmo processo: VirtualSize, PeakVirtualSize,
//!   WorkingSetSize, PeakWorkingSetSize, PageFaultCount, as cotas de pool,
//!   PagefileUsage, PeakPagefileUsage e PrivatePageCount (o PrivateUsage);
//!   o WorkingSetPrivateSize é o menor entre o privado e o working set. O
//!   working set, o privado e o tamanho virtual não são zero.
//! - O processo que consulta (o System) sai com o nome "System", a contagem
//!   de handles do ExHandleTableQuery da tabela dele e tempo de CPU.
//! - Depois o processo é retomado e sai com o código.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_ps_user::VmCountersEx2;
use crate::ntos::inc::types::{Eprocess, SystemExtendedThreadInformation, SystemProcessInformation, SystemProcessInformationExtension, SystemThreadInformation};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::handle_table;
use crate::ntos::ob::handles::process as process_handles;
use crate::ntos::ps::create::{self, CreateProcessRequest, ImageOrigin};
use crate::ntos::ps::process_parameters::ProcessParameters;
use crate::ntos::ps::system_process_information::{self as list, SYSTEM_EXTENDED_PROCESS_INFORMATION, SYSTEM_FULL_PROCESS_INFORMATION, SYSTEM_PROCESS_INFORMATION};
use crate::ntos::ps::user::process as user_process;
use crate::ntos::ps::{process, query_process};

type Assert = fn(bool, &str);

const EXIT_CODE: u32 = 0x63;
const IMAGE_NAME: &str = "lista.exe";
const IMAGE_PATH: &str = "C:\\OpenNT\\lista.exe";
const THREAD_CREATE_SUSPENDED: u32 = 1;

/// NtTerminateProcess(-1, código) pela syscall da ntdll de bring-up.
fn program() -> Vec<u8> {
    let code = EXIT_CODE.to_le_bytes();
    let entry: &[u8] = &[0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0xBA, code[0], code[1], code[2], code[3], 0x49, 0x89, 0xCA, 0xB8, 0x2C, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xEB, 0xFE];
    crate::ntos::test::phase7::single_section_image(0x1_4000_0000, 0x0022, b".text", 0x6000_0020, 0x1000, entry)
}

/// A lista da classe `class` em modo kernel, num buffer próprio alinhado:
/// os registros ficam nele até o fim da consulta.
struct List {
    buffer: u64,
}

impl List {
    fn query(class: u32) -> Option<List> {
        let (status, needed) = list::get_process_information(0, 0, None, class, 0, &mut |_, _| false);
        if status != 0xC000_0004 || needed == 0 {
            return None;
        }
        let size = needed as u64 + 0x1000;
        let buffer = guest::alloc_aligned(size, 8, true);
        let (status, _) = list::get_process_information(buffer, size as u32, None, class, 0, &mut |address, bytes| {
            guest::write_bytes(address, bytes);
            true
        });
        if status != 0 {
            guest::free_bytes(buffer);
            return None;
        }
        Some(List { buffer })
    }

    /// O registro do processo `pid`.
    fn find(&self, pid: u64) -> Option<&'static SystemProcessInformation> {
        let mut at = self.buffer;
        for _ in 0..1024 {
            // SAFETY: registro dentro do buffer preenchido pela consulta.
            let entry = unsafe { SystemProcessInformation::at(at) };
            if entry.unique_process_id.get() == pid {
                return Some(entry);
            }
            match entry.next_entry_offset.get() {
                0 => return None,
                next => at += next as u64,
            }
        }
        None
    }
}

impl Drop for List {
    fn drop(&mut self) {
        guest::free_bytes(self.buffer);
    }
}

/// O nome do registro (o Buffer aponta para dentro do buffer da lista).
fn name_of(entry: &SystemProcessInformation) -> String {
    let (length, buffer) = (entry.image_name.length.get() as usize, entry.image_name.buffer.get());
    if buffer == 0 {
        return String::new();
    }
    let units: Vec<u16> = guest::read_bytes(buffer, length).chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    String::from_utf16_lossy(&units)
}

/// O VM_COUNTERS_EX2 do processo pela ProcessVmCounters, numa cópia.
struct Counters {
    buffer: u64,
}

impl Counters {
    fn query(process_pointer: u64) -> Option<Counters> {
        let buffer = guest::alloc_bytes(VmCountersEx2::SIZE);
        if matches!(query_process::query_vm_counters(buffer, VmCountersEx2::SIZE as u32, 0, |_| Ok(process_pointer)), Ok(0)) {
            Some(Counters { buffer })
        } else {
            guest::free_bytes(buffer);
            None
        }
    }

    fn get(&self) -> &'static VmCountersEx2 {
        // SAFETY: o VM_COUNTERS_EX2 preenchido pela consulta.
        unsafe { VmCountersEx2::at(self.buffer) }
    }
}

impl Drop for Counters {
    fn drop(&mut self) {
        guest::free_bytes(self.buffer);
    }
}

/// Os campos de memória do registro e do VM_COUNTERS_EX2 batem.
fn memory_matches(entry: &SystemProcessInformation, counters: &VmCountersEx2) -> bool {
    entry.virtual_size.get() == counters.virtual_size.get()
        && entry.peak_virtual_size.get() == counters.peak_virtual_size.get()
        && entry.working_set_size.get() == counters.working_set_size.get()
        && entry.peak_working_set_size.get() == counters.peak_working_set_size.get()
        && entry.page_fault_count.get() == counters.page_fault_count.get()
        && entry.quota_paged_pool_usage.get() == counters.quota_paged_pool_usage.get()
        && entry.quota_peak_paged_pool_usage.get() == counters.quota_peak_paged_pool_usage.get()
        && entry.quota_non_paged_pool_usage.get() == counters.quota_non_paged_pool_usage.get()
        && entry.quota_peak_non_paged_pool_usage.get() == counters.quota_peak_non_paged_pool_usage.get()
        && entry.pagefile_usage.get() == counters.pagefile_usage.get()
        && entry.peak_pagefile_usage.get() == counters.peak_pagefile_usage.get()
        && entry.private_page_count.get() == counters.private_usage.get()
        && entry.working_set_private_size.quad_part.get() as u64 == counters.private_working_set_size.get().min(counters.working_set_size.get())
}

/// Memória: a lista e a ProcessVmCounters do mesmo processo parado. Uma
/// página que o corte do working set tira entre as duas leituras troca os
/// valores; a comparação é refeita, até três vezes.
fn memory(assert: Assert, process_pointer: u64, pid: u64) {
    let mut matched = false;
    let mut nonzero = false;
    for _ in 0..3 {
        let (Some(list), Some(counters)) = (List::query(SYSTEM_EXTENDED_PROCESS_INFORMATION), Counters::query(process_pointer)) else { break };
        let Some(entry) = list.find(pid) else { break };
        let counters = counters.get();
        nonzero = entry.working_set_size.get() != 0 && entry.working_set_private_size.quad_part.get() != 0 && entry.virtual_size.get() != 0;
        crate::debug_print!(
            "[lista] pid {} ws {:#x} privado {:#x} pico {:#x} va {:#x} commit {:#x} faltas {} | vm ws {:#x} privado {:#x} va {:#x}",
            pid,
            entry.working_set_size.get(),
            entry.working_set_private_size.quad_part.get(),
            entry.peak_working_set_size.get(),
            entry.virtual_size.get(),
            entry.private_page_count.get(),
            entry.page_fault_count.get(),
            counters.working_set_size.get(),
            counters.private_working_set_size.get(),
            counters.virtual_size.get()
        );
        if memory_matches(entry, counters) {
            matched = true;
            break;
        }
    }
    assert(matched, "lista: os campos de memoria do registro sao os da ProcessVmCounters do processo");
    assert(nonzero, "lista: working set, working set privado e tamanho virtual do processo nao sao zero");
}

/// Forma de cada classe: threads, extensão, chave, SID e nome.
fn shapes(assert: Assert, process_pointer: u64, pid: u64, thread_id: u64) {
    // SAFETY: EPROCESS retido pelo chamador.
    let sequence = unsafe { Eprocess::at(process_pointer) }.sequence_number.get();
    let mut ok = true;
    for class in [SYSTEM_PROCESS_INFORMATION, SYSTEM_EXTENDED_PROCESS_INFORMATION, SYSTEM_FULL_PROCESS_INFORMATION] {
        let Some(list) = List::query(class) else {
            ok = false;
            continue;
        };
        let Some(entry) = list.find(pid) else {
            ok = false;
            continue;
        };
        let thread_size = if class == SYSTEM_PROCESS_INFORMATION { SystemThreadInformation::SIZE } else { SystemExtendedThreadInformation::SIZE };
        let threads = entry.number_of_threads.get() as u64;
        let records = entry.address() + SystemProcessInformation::SIZE;
        // SAFETY: o primeiro registro de thread e a extensão, dentro do buffer.
        let (thread, extension) = unsafe { (SystemThreadInformation::at(records), SystemProcessInformationExtension::at(records + threads * thread_size)) };
        let name = name_of(entry);
        let name_ok = if class == SYSTEM_FULL_PROCESS_INFORMATION { name.ends_with(IMAGE_NAME) } else { name == IMAGE_NAME };
        let key_ok = entry.unique_process_key.get() == if class == SYSTEM_PROCESS_INFORMATION { 0 } else { pid };
        let sid_ok = if class == SYSTEM_FULL_PROCESS_INFORMATION {
            let token = process::get_primary_token(process_pointer).unwrap_or(0);
            let sid = crate::ntos::se::token::tokens::with(token, |token| token.user.clone()).unwrap_or_default();
            extension.user_sid_offset.get() == 0x170 && !sid.is_empty() && guest::read_bytes(extension.address() + 0x170, sid.len()) == sid
        } else {
            extension.user_sid_offset.get() == 0
        };
        let thread_ok = threads == 1 && thread.client_id.unique_process.get() == pid && thread.client_id.unique_thread.get() == thread_id;
        let maximum_ok = entry.image_name.maximum_length.get() as u64 == (entry.image_name.length.get() as u64 + 2).div_ceil(8) * 8;
        let class_ok = name_ok && key_ok && sid_ok && thread_ok && maximum_ok && extension.process_sequence_number.get() == sequence;
        if !class_ok {
            crate::debug_print!("[lista] classe {}: nome {:?} threads {} chave {:#x} sid {} seq {:#x}/{:#x}", class, name, threads, entry.unique_process_key.get(), extension.user_sid_offset.get(), extension.process_sequence_number.get(), sequence);
        }
        ok &= class_ok;
    }
    assert(ok, "lista: classes 5, 57 e 148 com o nome, uma thread do tamanho da classe, a extensao depois dela, a chave fora da 5 e o SID na 148");
}

/// O System: nome, handles da tabela dele e tempo de CPU.
fn system(assert: Assert) {
    let system = process::get_system_process();
    let Some(list) = List::query(SYSTEM_PROCESS_INFORMATION) else {
        assert(false, "lista: o System na lista");
        return;
    };
    let Some(entry) = list.find(process::SYSTEM_PROCESS_ID) else {
        assert(false, "lista: o System na lista");
        return;
    };
    let table = process_handles::reference(system).unwrap_or(0);
    let handles = if table != 0 { handle_table::query_handle_count(table) } else { 0 };
    if table != 0 {
        let _ = process_handles::release(system);
    }
    let time = entry.kernel_time.quad_part.get() + entry.user_time.quad_part.get();
    crate::debug_print!("[lista] System: handles {} ({} na tabela) tempo {} ciclos {:#x} ws {:#x}", entry.handle_count.get(), handles, time, entry.cycle_time.get(), entry.working_set_size.get());
    assert(name_of(entry) == "System" && entry.handle_count.get() == handles && time > 0, "lista: o System com o nome, os handles da tabela dele e tempo de CPU");
}

pub fn run(assert: Assert) {
    let request = CreateProcessRequest { image: ImageOrigin::Bytes(program()), image_name: IMAGE_NAME, parameters: ProcessParameters::for_image(IMAGE_PATH), parent: None, thread_flags: THREAD_CREATE_SUSPENDED, inherit_handles_from: None, on_created: None, protection: 0, create_session: false, primary_token: None, image_request: Default::default() };
    let created = match create::create_user_process(&request) {
        Ok(created) => created,
        Err(failure) => {
            crate::debug_print!("[lista] {} nao criado: {}", IMAGE_NAME, failure);
            assert(false, "lista: processo criado pelo caminho unico");
            return;
        }
    };
    let process_pointer = created.process_pointer;
    process::reference(process_pointer);
    // SAFETY: EPROCESS retido pela referência acima.
    let pid = unsafe { Eprocess::at(process_pointer) }.unique_process_id.get();
    memory(assert, process_pointer, pid);
    shapes(assert, process_pointer, pid, created.thread_id);
    system(assert);
    let resumed = crate::ntos::test::phase6::call_export("PsResumeProcess", &[process_pointer]).map(|status| status as u32);
    assert(resumed == Some(0), "lista: PsResumeProcess tira a suspensao da thread principal");
    let exit = user_process::run_created(created);
    assert(matches!(exit, Ok(EXIT_CODE)), "lista: o processo retomado roda e sai com o codigo");
    let _ = process::dereference(process_pointer);
}
