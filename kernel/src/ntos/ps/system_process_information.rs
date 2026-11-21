//! A lista de processos do NtQuerySystemInformation: o
//! ExpGetProcessInformation do ntoskrnl 19041 (rva 0x63e980) para as classes
//! SystemProcessInformation (5), SystemSessionProcessInformation (53, com o
//! filtro de sessão), SystemExtendedProcessInformation (57) e
//! SystemFullProcessInformation (148).
//!
//! Cada processo do PsActiveProcessHead vira um registro, nesta ordem no
//! buffer do chamador:
//!
//! - o SYSTEM_PROCESS_INFORMATION (0x100), com os campos que o
//!   ExpCopyProcessInfo (rva 0x618e80) copia do EPROCESS: o working set
//!   (Vm.PeakWorkingSetSize, WorkingSetLeafSize e o menor entre ele e
//!   WorkingSetLeafPrivateSize, em bytes), PageFaultCount, HardFaultCount,
//!   VirtualSize e PeakVirtualSize, as cotas de pool (ProcessQuotaUsage e
//!   ProcessQuotaPeak), CommitCharge (PagefileUsage e PrivatePageCount) e
//!   CommitChargePeak em bytes, CreateTime, Pcb.BasePriority, os ids, o
//!   ActiveThreadsHighWatermark, a contagem de handles do ExHandleTableQuery
//!   sob o RundownProtect, os tempos, o CycleTime e os contadores de E/S do
//!   PsQueryStatisticsProcess e, fora da classe 5, o UniqueProcessKey;
//!   depois o NumberOfThreads, o SessionId (MmGetSessionId) e o nome;
//! - um SYSTEM_THREAD_INFORMATION (0x50, classe 5) ou
//!   SYSTEM_EXTENDED_THREAD_INFORMATION (0x88) por thread viva, com os
//!   valores do KeQueryValuesThread (WaitTime, State, WaitReason, Priority,
//!   BasePriority), os tempos da KTHREAD em ticks vezes o KeMaximumIncrement,
//!   o CreateTime e o Cid da ETHREAD e o endereço inicial (o
//!   Win32StartAddress numa thread de sistema, o StartAddress nas outras,
//!   zero com StartAddressInvalid); no estendido, StackBase, StackLimit,
//!   Win32StartAddress e Teb. Uma thread Terminated não entra. Para um
//!   chamador restrito (ExIsRestrictedCaller) os endereços de kernel e a
//!   pilha saem zero;
//! - o SYSTEM_PROCESS_INFORMATION_EXTENSION (0x170), em todas as classes:
//!   os contadores de disco (EPROCESS.DiskCounters), as trocas de contexto,
//!   as flags (o HasStrongId pelo claim WIN://SYSAPPID do token, a
//!   classificação e o BackgroundActivityModerated), os valores de energia,
//!   o SharedCommitCharge em bytes, o JobId e o SequenceNumber;
//! - na classe 148, o SID do usuário do token (alinhado a 8, UserSidOffset
//!   0x170), o nome completo do pacote e o AppId do RtlQueryPackageIdentity
//!   (deslocamentos relativos à extensão);
//! - o nome da imagem, terminado em zero e alinhado a 8: o "System" do
//!   processo inicial e o SeAuditProcessCreationInfo.ImageFileName dos
//!   outros, inteiro na classe 148 e só o último componente nas outras.
//!
//! O NextEntryOffset de cada registro é o tamanho dele (zero no último) e o
//! ReturnLength o total. Um registro mínimo é 0x270 bytes: um Length menor
//! já sai STATUS_INFO_LENGTH_MISMATCH. Sem caber no Length, nada é gravado e
//! o ReturnLength recebe o tamanho necessário. A classe 148 exige do modo
//! usuário o ExCheckFullProcessInformationAccess: um token membro do SID do
//! valor FullProcessInformationSID de Control\Windows ou dos
//! Administradores; senão, STATUS_ACCESS_DENIED.
//!
//! Diferenças: o OpenNT não tem o PsIdleProcess (a lista começa no primeiro
//! processo ativo), nem server silos (todo processo está no silo do
//! chamador), nem valores de energia (zerados). Os registros são montados
//! numa cópia de kernel e copiados para o buffer do chamador de uma vez.

use alloc::vec::Vec;

use super::{process, process_statistics, scheduler, session, user_probe};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{
    Eprocess, Ethread, Kthread, LargeInteger, ProcessDiskCounters, SystemExtendedThreadInformation, SystemProcessInformation, SystemProcessInformationExtension, SystemThreadInformation, UnicodeString,
};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::process_usage;
use crate::ntos::ob::handles::process as process_handles;
use crate::ntos::ob::handle_table;
use crate::rtl::KernelError;

pub const SYSTEM_PROCESS_INFORMATION: u32 = 5;
pub const SYSTEM_SESSION_PROCESS_INFORMATION: u32 = 53;
pub const SYSTEM_EXTENDED_PROCESS_INFORMATION: u32 = 57;
pub const SYSTEM_FULL_PROCESS_INFORMATION: u32 = 148;

const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;

/// SYSTEM_PROCESS_INFORMATION mais a extensão: o menor registro.
const MINIMUM_ENTRY: u64 = SystemProcessInformation::SIZE + SystemProcessInformationExtension::SIZE;
/// O maior endereço de usuário que um chamador restrito vê (o
/// MM_HIGHEST_USER_ADDRESS do 19041).
const HIGHEST_USER_ADDRESS: u64 = 0x7FFF_FFFE_FFFF;
/// KTHREAD.State Running, Ready, Waiting e Terminated.
const THREAD_RUNNING: u32 = 2;
const THREAD_READY: u32 = 1;
const THREAD_WAITING: u32 = 5;
const THREAD_TERMINATED: u32 = 4;
/// Classificação do processo nas flags da extensão (bits 1..=4).
const CLASSIFICATION_SYSTEM: u32 = 1 << 1;
/// BackgroundActivityModerated (bit 5) e HasStrongId (bit 0).
const BACKGROUND_ACTIVITY_MODERATED: u32 = 1 << 5;
const HAS_STRONG_ID: u32 = 1;
/// O claim do id de aplicativo do sistema (PspSysAppIdClaim).
const SYS_APP_ID_CLAIM: &str = "WIN://SYSAPPID";
/// O nome do processo inicial (ExpSystemProcessName).
const SYSTEM_PROCESS_NAME: &str = "System";

/// Os dados de uma thread, lidos antes da montagem.
struct ThreadValues {
    kernel_time: u64,
    user_time: u64,
    create_time: u64,
    wait_time: u32,
    start_address: u64,
    unique_process: u64,
    unique_thread: u64,
    priority: i32,
    base_priority: i32,
    context_switches: u32,
    state: u32,
    wait_reason: u32,
    stack_base: u64,
    stack_limit: u64,
    win32_start_address: u64,
    teb: u64,
}

/// Os dados de um processo, lidos antes da montagem.
struct ProcessValues {
    process: u64,
    session_id: u32,
    handle_count: u32,
    statistics: process_statistics::ProcessStatistics,
    threads: Vec<ThreadValues>,
    flags: u32,
    disk_counters: Option<[u64; 5]>,
    job_id: u32,
    sid: Vec<u8>,
    package_full_name: Vec<u8>,
    app_id: Vec<u8>,
    name: Option<Vec<u16>>,
    size: u64,
}

fn eprocess(process: u64) -> &'static Eprocess {
    // SAFETY: EPROCESS da lista de processos ativos, referenciado enquanto
    // o registro é lido.
    unsafe { Eprocess::at(process) }
}

fn align8(value: u64) -> u64 {
    value.div_ceil(8) * 8
}

/// ExIsRestrictedCaller(PreviousMode): o access check de READ_CONTROL
/// contra o SeMediumDaclSd, o mesmo do RtlIsSandboxedToken.
fn is_restricted_caller(previous_mode: u8) -> bool {
    crate::ntos::rtl::security::is_sandboxed_token(0, previous_mode).unwrap_or(true)
}

/// RtlCheckTokenMembership(NULL, Sid) da identidade do chamador.
fn caller_is_member(identifier: &[u8]) -> bool {
    let block = guest::alloc_bytes(8 + identifier.len() as u64);
    if block == 0 {
        return false;
    }
    guest::write_bytes(block, &[0; 8]);
    guest::write_bytes(block + 8, identifier);
    let status = crate::ntos::se::token::membership::check(0, block + 8, block).unwrap_or(STATUS_ACCESS_DENIED);
    let member = status & 0x8000_0000 == 0 && guest::read8(block) != 0;
    guest::free_bytes(block);
    member
}

/// ExCheckFullProcessInformationAccess(PreviousMode) (rva 0x69dfcc): o
/// modo kernel passa; o modo usuário precisa do SID de
/// HKLM\SYSTEM\CurrentControlSet\Control\Windows\FullProcessInformationSID
/// (REG_BINARY de até 0x44 bytes, lido uma vez pelo
/// ExpInitFullProcessSecurityInfo) ou dos Administradores (SeAliasAdminsSid).
fn check_full_process_information_access(previous_mode: u8) -> u32 {
    if previous_mode == 0 {
        return 0;
    }
    let configured = crate::ntos::cm::registry::read_value_by_path("\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Windows", "FullProcessInformationSID").filter(|value| value.data.len() <= 0x44 && !value.data.is_empty());
    if configured.is_some_and(|value| caller_is_member(&value.data)) {
        return 0;
    }
    // S-1-5-32-544.
    let administrators = [1u8, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0];
    if caller_is_member(&administrators) { 0 } else { STATUS_ACCESS_DENIED }
}

/// O ThreadState de um registro: Running para quem consulta, o
/// KTHREAD.State das threads do despacho, e Waiting/Ready pelo agendador de
/// processos nas demais.
fn thread_state(pointer: u64, current: u64, waiting: bool) -> u32 {
    use crate::ntos::ke::thread_dispatch;
    if pointer == current {
        THREAD_RUNNING
    } else if thread_dispatch::owner(pointer).is_some() {
        thread_dispatch::thread_state(pointer) as u32
    } else if waiting {
        THREAD_WAITING
    } else {
        THREAD_READY
    }
}

/// Os valores de uma thread viva (`None` para uma Terminated).
fn thread_values(pointer: u64, current: u64, scheduled: &[scheduler::ProcessInfo], restricted: bool) -> Option<ThreadValues> {
    let record = process::thread_record(pointer)?;
    let waiting = record.runtime.is_some_and(|pid| scheduled.iter().any(|entry| entry.pid == pid && entry.state == scheduler::ProcessState::Waiting));
    let state = thread_state(pointer, current, waiting);
    if state == THREAD_TERMINATED {
        return None;
    }
    // SAFETY: ETHREAD referenciada pelo chamador.
    let ethread = unsafe { Ethread::at(pointer) };
    let tcb: &Kthread = &ethread.tcb;
    let kernel_view = |address: u64| if restricted && address > HIGHEST_USER_ADDRESS { 0 } else { address };
    let start_address = if tcb.system_thread() != 0 {
        ethread.win32_start_address.get()
    } else if ethread.start_address_invalid() != 0 {
        0
    } else {
        ethread.start_address.get()
    };
    let (stack_base, stack_limit) = if restricted { (0, 0) } else { (tcb.stack_base.get(), tcb.stack_limit.get()) };
    Some(ThreadValues {
        kernel_time: process_statistics::tick_time(record.kernel_time),
        user_time: process_statistics::tick_time(record.user_time),
        create_time: large_integer(&ethread.create_time),
        wait_time: tcb.wait_time.get(),
        start_address: kernel_view(start_address),
        unique_process: ethread.cid.unique_process.get(),
        unique_thread: ethread.cid.unique_thread.get(),
        priority: tcb.priority.get() as i32,
        base_priority: tcb.base_priority.get() as i32,
        context_switches: record.context_switches,
        state,
        wait_reason: tcb.wait_reason.get() as u32,
        stack_base,
        stack_limit,
        win32_start_address: kernel_view(ethread.win32_start_address.get()),
        teb: tcb.teb.get(),
    })
}

fn large_integer(value: &LargeInteger) -> u64 {
    value.quad_part.get() as u64
}

/// ExHandleTableQuery do EPROCESS.ObjectTable sob o RundownProtect (zero
/// sem tabela).
fn handle_count(process: u64) -> u32 {
    let table = process_handles::reference(process).unwrap_or(0);
    if table == 0 {
        return 0;
    }
    let count = handle_table::query_handle_count(table);
    let _ = process_handles::release(process);
    count
}

/// O nome do registro em UTF-16, como o ExpGetProcessInformation o escolhe.
fn image_name(process: u64, full_path: bool) -> Vec<u16> {
    if process == process::get_system_process() {
        return SYSTEM_PROCESS_NAME.encode_utf16().collect();
    }
    let cache = eprocess(process).se_audit_process_creation_info.image_file_name.get();
    if cache == 0 {
        return Vec::new();
    }
    // SAFETY: o OBJECT_NAME_INFORMATION de auditoria do processo
    // (`ps/process_image`), vivo com o EPROCESS.
    let name = unsafe { UnicodeString::at(cache) };
    let (length, buffer) = (name.length.get() as usize & !1, name.buffer.get());
    if length == 0 || buffer == 0 {
        return Vec::new();
    }
    let units: Vec<u16> = guest::read_bytes(buffer, length).chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    if full_path {
        return units;
    }
    match units.iter().rposition(|&unit| unit == u16::from(b'\\')) {
        Some(separator) => units[separator + 1..].to_vec(),
        None => units,
    }
}

/// As flags da extensão.
fn extension_flags(process: u64, token: u64) -> u32 {
    let object = eprocess(process);
    let mut flags = 0;
    if token != 0 && crate::ntos::se::token::information::attribute_present(token, SYS_APP_ID_CLAIM) {
        flags |= HAS_STRONG_ID;
    }
    if object.system_process() != 0 {
        flags |= CLASSIFICATION_SYSTEM;
    }
    if object.pcb.process_timer_delay.get() != 0 {
        flags |= BACKGROUND_ACTIVITY_MODERATED;
    }
    flags
}

/// O SID do usuário do token e, de um processo empacotado, o nome completo
/// do pacote e o AppId (o RtlQueryPackageIdentity com 0xfe e 0x82 bytes).
fn full_identity(token: u64) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    if token == 0 {
        return (Vec::new(), Vec::new(), Vec::new());
    }
    let sid = crate::ntos::se::token::tokens::with(token, |token| token.user.clone()).unwrap_or_default();
    let (package_capacity, app_capacity) = (0xFEu64, 0x82u64);
    let block = guest::alloc_bytes(16 + package_capacity + app_capacity);
    if block == 0 {
        return (sid, Vec::new(), Vec::new());
    }
    guest::write64(block, package_capacity);
    guest::write64(block + 8, app_capacity);
    let (package, app) = (block + 16, block + 16 + package_capacity);
    let status = crate::ntos::se::package_identity::query(token, package, block, app, block + 8, 0).unwrap_or(STATUS_INSUFFICIENT_RESOURCES);
    let identity = if status & 0x8000_0000 == 0 {
        let package_size = guest::read64(block).min(package_capacity) as usize;
        let app_size = guest::read64(block + 8).min(app_capacity) as usize;
        (guest::read_bytes(package, package_size), guest::read_bytes(app, app_size))
    } else {
        (Vec::new(), Vec::new())
    };
    guest::free_bytes(block);
    (sid, identity.0, identity.1)
}

/// Lê os dados do processo `process`, já referenciado; o working set e o
/// tamanho virtual são recalculados no EPROCESS antes da cópia.
fn process_values(process: u64, threads: &[u64], class: u32, restricted: bool) -> ProcessValues {
    let object = eprocess(process);
    process_usage::refresh(process);
    let thread_size = if class == SYSTEM_PROCESS_INFORMATION { SystemThreadInformation::SIZE } else { SystemExtendedThreadInformation::SIZE };
    let current = process::get_current_thread();
    let scheduled = scheduler::list();
    let mut thread_list = Vec::new();
    for &pointer in threads {
        if !process::reference_thread_safe(pointer) {
            continue;
        }
        if let Some(values) = thread_values(pointer, current, &scheduled, restricted) {
            thread_list.push(values);
        }
        let _ = process::dereference_thread(pointer);
    }
    let token = process::get_primary_token(process).unwrap_or(0);
    let disk = object.disk_counters.get();
    let disk_counters = (disk != 0).then(|| {
        // SAFETY: EPROCESS.DiskCounters não nulo aponta para o
        // PROCESS_DISK_COUNTERS do processo.
        let counters = unsafe { ProcessDiskCounters::at(disk) };
        [counters.bytes_read.get(), counters.bytes_written.get(), counters.read_operation_count.get(), counters.write_operation_count.get(), counters.flush_operation_count.get()]
    });
    let job = object.job.get();
    // SAFETY: EPROCESS.Job não nulo aponta para o EJOB do processo.
    let job_id = if job != 0 { unsafe { crate::ntos::inc::types::Ejob::at(job) }.job_id.get() } else { 0 };
    let (sid, package_full_name, app_id) = if class == SYSTEM_FULL_PROCESS_INFORMATION { full_identity(token) } else { (Vec::new(), Vec::new(), Vec::new()) };
    let name = image_name(process, class == SYSTEM_FULL_PROCESS_INFORMATION);
    let size = MINIMUM_ENTRY + thread_list.len() as u64 * thread_size + if sid.is_empty() { 0 } else { align8(sid.len() as u64) } + package_full_name.len() as u64 + app_id.len() as u64 + align8(name.len() as u64 * 2 + 2);
    ProcessValues {
        process,
        session_id: session::query(process),
        handle_count: handle_count(process),
        statistics: process_statistics::query(process),
        threads: thread_list,
        flags: extension_flags(process, token),
        disk_counters,
        job_id,
        sid,
        package_full_name,
        app_id,
        name: Some(name),
        size,
    }
}

/// Os registros de todos os processos que entram na lista: os ativos,
/// menos os que já saíram sem threads, e com `session`, só os da sessão.
fn snapshot(class: u32, session: Option<u32>, restricted: bool) -> Vec<ProcessValues> {
    let mut records = Vec::new();
    for active in process::list_active_processes() {
        if process::reference(active.address).is_none() {
            continue;
        }
        let object = eprocess(active.address);
        // Saindo, sinalizado, sem ActiveThreads e com a ThreadListHead vazia.
        let gone = object.process_exiting() != 0 && object.pcb.header.signal_state.get() != 0 && object.active_threads.get() == 0 && active.threads.is_empty();
        let in_session = session.is_none_or(|id| session::query(active.address) == id);
        if !gone && in_session {
            records.push(process_values(active.address, &active.threads, class, restricted));
        }
        let _ = process::dereference(active.address);
    }
    records
}

/// O ExpCopyProcessInfo e o resto do SYSTEM_PROCESS_INFORMATION.
fn fill_process(information: &SystemProcessInformation, values: &ProcessValues, class: u32, name_buffer: u64, next: u32) {
    let object = eprocess(values.process);
    let vm = &object.vm.instance;
    let statistics = &values.statistics;
    information.next_entry_offset.set(next);
    information.number_of_threads.set(values.threads.len() as u32);
    let working_set = vm.working_set_leaf_size.get() << 12;
    let private = vm.working_set_leaf_private_size.get() << 12;
    information.working_set_private_size.quad_part.set(private.min(working_set) as i64);
    information.hard_fault_count.set(vm.hard_fault_count.get());
    information.number_of_threads_high_watermark.set(object.active_threads_high_watermark.get());
    information.cycle_time.set(statistics.cycle_time);
    information.create_time.quad_part.set(large_integer(&object.create_time) as i64);
    information.user_time.quad_part.set(statistics.user_time as i64);
    information.kernel_time.quad_part.set(statistics.kernel_time as i64);
    if let Some(name) = &values.name {
        information.image_name.length.set((name.len() * 2) as u16);
        information.image_name.maximum_length.set(align8(name.len() as u64 * 2 + 2) as u16);
        information.image_name.buffer.set(name_buffer);
    }
    information.base_priority.set(object.pcb.base_priority.get() as i32);
    information.unique_process_id.set(object.unique_process_id.get());
    information.inherited_from_unique_process_id.set(object.inherited_from_unique_process_id.get());
    information.handle_count.set(values.handle_count);
    information.session_id.set(values.session_id);
    if class != SYSTEM_PROCESS_INFORMATION {
        information.unique_process_key.set(object.unique_process_id.get());
    }
    information.peak_virtual_size.set(object.peak_virtual_size.get());
    information.virtual_size.set(object.virtual_size.get());
    information.page_fault_count.set(vm.page_fault_count.get());
    information.peak_working_set_size.set(vm.peak_working_set_size.get() << 12);
    information.working_set_size.set(working_set);
    information.quota_peak_paged_pool_usage.set(object.process_quota_peak[1].get());
    information.quota_paged_pool_usage.set(object.process_quota_usage[1].get());
    information.quota_peak_non_paged_pool_usage.set(object.process_quota_peak[0].get());
    information.quota_non_paged_pool_usage.set(object.process_quota_usage[0].get());
    information.pagefile_usage.set(object.commit_charge.get() << 12);
    information.peak_pagefile_usage.set(object.commit_charge_peak.get() << 12);
    information.private_page_count.set(object.commit_charge.get() << 12);
    information.read_operation_count.quad_part.set(statistics.read_operation_count as i64);
    information.write_operation_count.quad_part.set(statistics.write_operation_count as i64);
    information.other_operation_count.quad_part.set(statistics.other_operation_count as i64);
    information.read_transfer_count.quad_part.set(statistics.read_transfer_count as i64);
    information.write_transfer_count.quad_part.set(statistics.write_transfer_count as i64);
    information.other_transfer_count.quad_part.set(statistics.other_transfer_count as i64);
}

fn fill_thread(information: &SystemThreadInformation, values: &ThreadValues) {
    information.kernel_time.quad_part.set(values.kernel_time as i64);
    information.user_time.quad_part.set(values.user_time as i64);
    information.create_time.quad_part.set(values.create_time as i64);
    information.wait_time.set(values.wait_time);
    information.start_address.set(values.start_address);
    information.client_id.unique_process.set(values.unique_process);
    information.client_id.unique_thread.set(values.unique_thread);
    information.priority.set(values.priority);
    information.base_priority.set(values.base_priority);
    information.context_switches.set(values.context_switches);
    information.thread_state.set(values.state);
    information.wait_reason.set(values.wait_reason);
}

fn fill_extension(extension: &SystemProcessInformationExtension, values: &ProcessValues) {
    let object = eprocess(values.process);
    if let Some([read, written, reads, writes, flushes]) = values.disk_counters {
        extension.disk_counters.bytes_read.set(read);
        extension.disk_counters.bytes_written.set(written);
        extension.disk_counters.read_operation_count.set(reads);
        extension.disk_counters.write_operation_count.set(writes);
        extension.disk_counters.flush_operation_count.set(flushes);
    }
    extension.context_switches.set(values.statistics.context_switches);
    extension.flags.set(values.flags);
    extension.shared_commit_charge.set(object.shared_commit_charge.get() << 12);
    extension.job_object_id.set(values.job_id);
    extension.process_sequence_number.set(object.sequence_number.get());
}

/// Monta os registros numa cópia de kernel zerada, com os ponteiros dos
/// nomes relativos a `base` (o buffer do chamador).
fn encode(records: &[ProcessValues], class: u32, base: u64, scratch: u64) {
    let thread_size = if class == SYSTEM_PROCESS_INFORMATION { SystemThreadInformation::SIZE } else { SystemExtendedThreadInformation::SIZE };
    let mut at = 0u64;
    for (index, values) in records.iter().enumerate() {
        let entry = scratch + at;
        let mut cursor = entry + SystemProcessInformation::SIZE;
        for thread in &values.threads {
            if class == SYSTEM_PROCESS_INFORMATION {
                // SAFETY: registro de 0x50 bytes dentro da cópia de kernel.
                fill_thread(unsafe { SystemThreadInformation::at(cursor) }, thread);
            } else {
                // SAFETY: registro de 0x88 bytes dentro da cópia de kernel.
                let extended = unsafe { SystemExtendedThreadInformation::at(cursor) };
                fill_thread(&extended.thread_info, thread);
                extended.stack_base.set(thread.stack_base);
                extended.stack_limit.set(thread.stack_limit);
                extended.win32_start_address.set(thread.win32_start_address);
                extended.teb_base.set(thread.teb);
            }
            cursor += thread_size;
        }
        let extension_address = cursor;
        // SAFETY: a extensão de 0x170 bytes dentro da cópia de kernel.
        let extension = unsafe { SystemProcessInformationExtension::at(extension_address) };
        fill_extension(extension, values);
        cursor += SystemProcessInformationExtension::SIZE;
        if !values.sid.is_empty() {
            extension.user_sid_offset.set((cursor - extension_address) as u32);
            guest::write_bytes(cursor, &values.sid);
            cursor += align8(values.sid.len() as u64);
        }
        if !values.package_full_name.is_empty() {
            extension.package_full_name_offset.set((cursor - extension_address) as u32);
            guest::write_bytes(cursor, &values.package_full_name);
            cursor += values.package_full_name.len() as u64;
        }
        if !values.app_id.is_empty() {
            extension.app_id_offset.set((cursor - extension_address) as u32);
            guest::write_bytes(cursor, &values.app_id);
            cursor += values.app_id.len() as u64;
        }
        if let Some(name) = &values.name {
            let bytes: Vec<u8> = name.iter().flat_map(|unit| unit.to_le_bytes()).collect();
            guest::write_bytes(cursor, &bytes);
        }
        let next = if index + 1 == records.len() { 0 } else { values.size as u32 };
        // SAFETY: o SYSTEM_PROCESS_INFORMATION no começo do registro.
        fill_process(unsafe { SystemProcessInformation::at(entry) }, values, class, base + (cursor - scratch), next);
        at += values.size;
    }
}

/// ExpGetProcessInformation(Buffer, Length, ReturnLength, SessionId, Class):
/// (NTSTATUS, ReturnLength). `write` copia a lista pronta para o buffer do
/// chamador (sondada no modo usuário); uma cópia recusada é
/// STATUS_ACCESS_VIOLATION.
pub fn get_process_information(buffer: u64, length: u32, session: Option<u32>, class: u32, previous_mode: u8, write: &mut dyn FnMut(u64, &[u8]) -> bool) -> (u32, u32) {
    if class == SYSTEM_FULL_PROCESS_INFORMATION {
        let status = check_full_process_information_access(previous_mode);
        if status != 0 {
            return (status, 0);
        }
    }
    let restricted = is_restricted_caller(previous_mode);
    let records = snapshot(class, session, restricted);
    let needed: u64 = records.iter().map(|record| record.size).sum();
    let reported = needed.min(u32::MAX as u64) as u32;
    if (length as u64) < MINIMUM_ENTRY || (length as u64) < needed {
        return (STATUS_INFO_LENGTH_MISMATCH, reported);
    }
    let scratch = guest::alloc_bytes(needed.max(1));
    if scratch == 0 {
        return (STATUS_INSUFFICIENT_RESOURCES, 0);
    }
    guest::write_bytes(scratch, &alloc::vec![0u8; needed as usize]);
    encode(&records, class, buffer, scratch);
    let copied = write(buffer, &guest::read_bytes(scratch, needed as usize));
    guest::free_bytes(scratch);
    if !copied {
        return (STATUS_ACCESS_VIOLATION, reported);
    }
    (0, reported)
}

/// A entrada das classes 5, 57 e 148 do NtQuerySystemInformation (e da
/// ZwQuerySystemInformation de modo kernel): ReturnLength opcional, saída
/// alinhada a 8, buffer de modo usuário sondado.
pub fn query_class(class: u32, output: u64, length: u64, returned: u64, user_mode: bool) -> Result<u32, KernelError> {
    if length > 0xFFFF_FFFF {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if user_mode && returned != 0 && !user_probe::probe_user_write(returned, 4) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    if output % 8 != 0 && length != 0 {
        return Ok(STATUS_DATATYPE_MISALIGNMENT);
    }
    if user_mode && length != 0 && !user_probe::probe_user_write(output, length) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let (status, reported) = get_process_information(output, length as u32, None, class, u8::from(user_mode), &mut |address, bytes| guest::try_write_bytes(address, bytes).is_ok());
    // ReturnLength pode ser de modo usuário: a escrita é sondada mesmo
    // depois da sondagem (a página pode sumir).
    if returned != 0 && guest::try_write::<u32>(returned, reported).is_err() {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    Ok(status)
}

/// SystemProcessInformation (5).
pub fn query(output: u64, length: u64, returned: u64, user_mode: bool) -> Result<u32, KernelError> {
    query_class(SYSTEM_PROCESS_INFORMATION, output, length, returned, user_mode)
}

/// SystemSessionProcessInformation (53) (o ramo do ExpQuerySystemInformation
/// em 0x6cac96): a entrada SYSTEM_SESSION_PROCESS_INFORMATION de 0x10 bytes
/// (SessionId, SizeOfBuf, Buffer); um Length menor dá
/// STATUS_INFO_LENGTH_MISMATCH com 0x10 no ReturnLength. O Buffer dela é
/// sondado para escrita com SizeOfBuf e a lista da classe 5 só com os
/// processos da sessão vai para ele.
pub fn query_session(input: u64, length: u64, returned: u64, user_mode: bool) -> Result<u32, KernelError> {
    let set_returned = |value: u32| returned == 0 || guest::try_write::<u32>(returned, value).is_ok();
    if length < 0x10 {
        return Ok(if set_returned(0x10) { STATUS_INFO_LENGTH_MISMATCH } else { STATUS_ACCESS_VIOLATION });
    }
    if user_mode && !user_probe::probe_user_write(input, 0x10) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let (Ok(session), Ok(size), Ok(buffer)) = (guest::try_read::<u32>(input), guest::try_read::<u32>(input + 4), guest::try_read::<u64>(input + 8)) else {
        return Ok(STATUS_ACCESS_VIOLATION);
    };
    if buffer % 8 != 0 && size != 0 {
        return Ok(STATUS_DATATYPE_MISALIGNMENT);
    }
    if user_mode && size != 0 && !user_probe::probe_user_write(buffer, size as u64) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let (status, reported) = get_process_information(buffer, size, Some(session), SYSTEM_PROCESS_INFORMATION, u8::from(user_mode), &mut |address, bytes| guest::try_write_bytes(address, bytes).is_ok());
    if !set_returned(reported) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    Ok(status)
}
