//! Autotestes dos serviços de modo usuário que o smss.exe e o csrss.exe
//! reais pedem no boot e que antes não tinham provedor ou respondiam
//! errado: NtInitializeRegistry (`cm/hive_init`), NtIsUILanguageComitted
//! (`ps/locale`), NtApphelpCacheControl (`ps/apphelp_cache`), as classes
//! ProcessDefaultHardErrorMode e ProcessHandleCheckingMode do
//! NtSetInformationProcess (`ps/set_process_information`), as classes de
//! tamanho fixo do NtQuerySystemInformation (`ex/system_information`) e os
//! vizinhos NtPulseEvent, NtSetEventBoostPriority e NtQueryDirectoryObject.

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Eprocess, Ethread, HandleTable, ObjectAttributes};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::process;
use crate::ntos::ps::user::{memory, state};

type Assert = fn(bool, &str);
type Call<'a> = &'a dyn Fn(&str, u64, u64, u64, u64) -> u32;

const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_TOO_LATE: u32 = 0xC000_0189;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;

pub fn run(assert: Assert) {
    let Ok(block) = memory::map_user_region(0x3000) else {
        assert(false, "userboot: memoria de usuario");
        return;
    };
    let rsp = block + 0x2000;
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map_or(u32::MAX, |handler| handler(a1, a2, a3, a4, rsp).unwrap_or(u32::MAX));
    initialize_registry(assert, &call);
    ui_language_and_apphelp(assert, &call);
    process_classes(assert, block, &call);
    system_classes(assert, block, &call);
    events(assert, block, rsp, &call);
    directory_query(assert, block, rsp, &call);
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

/// NtInitializeRegistry: cada etapa uma vez só. O boot dos autotestes não
/// roda o smss, então a primeira chamada de cada uma é a deste teste.
fn initialize_registry(assert: Assert, call: Call) {
    let invalid = call("NtInitializeRegistry", 5, 0, 0, 0);
    let backup = call("NtInitializeRegistry", 0x13E8, 0, 0, 0);
    let held = crate::ntos::se::privilege::single_privilege_check(17, 1);
    assert(invalid == STATUS_INVALID_PARAMETER && backup == if held { STATUS_TOO_LATE } else { STATUS_PRIVILEGE_NOT_HELD }, "userboot: NtInitializeRegistry recusa a condicao desconhecida e a copia periodica segue o SeBackupPrivilege");
    let first = call("NtInitializeRegistry", 0, 0, 0, 0);
    let again = call("NtInitializeRegistry", 0, 0, 0, 0);
    let setup = call("NtInitializeRegistry", 1, 0, 0, 0);
    assert(first == 0 && again == STATUS_ACCESS_DENIED && setup == STATUS_ACCESS_DENIED, "userboot: NtInitializeRegistry(CM_BOOT_FLAG_SMSS) completa o registro uma vez; depois STATUS_ACCESS_DENIED");
    let paging = call("NtInitializeRegistry", 2, 0, 0, 0);
    let paging_again = call("NtInitializeRegistry", 2, 0, 0, 0);
    assert(paging == 0 && paging_again == STATUS_ACCESS_DENIED, "userboot: NtInitializeRegistry(2) avisa os arquivos de paginacao uma vez");
    // 0x1000 puro consome a vez do aceite do boot.
    let accept_zero = call("NtInitializeRegistry", 0x1000, 0, 0, 0);
    let accept = call("NtInitializeRegistry", 0x1001, 0, 0, 0);
    assert(accept_zero == STATUS_INVALID_PARAMETER && accept == STATUS_ACCESS_DENIED, "userboot: CM_BOOT_FLAG_ACCEPTED sem conjunto consome o aceite unico");
}

fn ui_language_and_apphelp(assert: Assert, call: Call) {
    assert(call("NtIsUILanguageComitted", 0, 0, 0, 0) == STATUS_OBJECT_NAME_NOT_FOUND, "userboot: NtIsUILanguageComitted antes da confirmacao do idioma");
    // Sem o \Device\ahcache: o status pré-definido de cada serviço.
    let statuses = [12u64, u64::MAX, 0, 6, 1, 7, 10, 4, 11].map(|service| call("NtApphelpCacheControl", service, 0, 0, 0));
    assert(
        statuses == [STATUS_INVALID_PARAMETER, STATUS_INVALID_PARAMETER, STATUS_NOT_FOUND, STATUS_NOT_FOUND, 0, 0, 0, STATUS_UNSUCCESSFUL, STATUS_UNSUCCESSFUL],
        "userboot: NtApphelpCacheControl sem o ahcache.sys responde o status de cada servico",
    );
}

fn process_classes(assert: Assert, block: u64, call: Call) {
    let buffer = block + 0x100;
    // SAFETY: o EPROCESS do processo corrente.
    let eprocess = unsafe { Eprocess::at(process::get_current_process()) };
    let saved = eprocess.default_hard_error_processing.get();
    let set = |class: u64, value: u32, address: u64, length: u64| {
        guest::write32(address, value);
        call("NtSetInformationProcess", u64::MAX, class, address, length)
    };
    let alignment = set(12, 4, buffer, 4);
    let automatic = eprocess.default_hard_error_processing.get() == 4 && eprocess.pcb.auto_alignment() == 1;
    let failing = set(12, 1, buffer, 4);
    let manual = eprocess.default_hard_error_processing.get() == 1 && eprocess.pcb.auto_alignment() == 0;
    assert(alignment == 0 && automatic && failing == 0 && manual, "userboot: ProcessDefaultHardErrorMode grava o modo e o AutoAlignment do SEM_NOALIGNMENTFAULTEXCEPT");
    assert(set(12, 1, buffer, 8) == STATUS_INFO_LENGTH_MISMATCH && set(12, 1, buffer + 2, 4) == STATUS_DATATYPE_MISALIGNMENT, "userboot: ProcessDefaultHardErrorMode exige um ULONG alinhado");
    // A consulta das duas classes (ReturnLength só na 12).
    let (output, returned) = (block + 0x180, block + 0x190);
    let rsp = block + 0x2000;
    let query = |class: u64, length: u64| {
        guest::write32(output, 0xFFFF_FFFF);
        guest::write32(returned, 0);
        guest::write64(rsp + 0x28, returned);
        call("NtQueryInformationProcess", u64::MAX, class, output, length)
    };
    let mode = query(12, 4);
    assert(mode == 0 && guest::read32(output) == 1 && guest::read32(returned) == 4 && query(12, 8) == STATUS_INFO_LENGTH_MISMATCH, "userboot: NtQueryInformationProcess(ProcessDefaultHardErrorMode) devolve o modo gravado");
    let _ = set(12, saved, buffer, 4);
    let table = eprocess.object_table.get();
    // SAFETY: a HANDLE_TABLE do processo corrente.
    let flag = || table != 0 && unsafe { HandleTable::at(table) }.enable_handle_exceptions() == 1;
    let bad = set(54, 2, buffer, 4);
    let enabled = set(54, 1, buffer, 4);
    let on = flag();
    let disabled = set(54, 0, buffer, 4);
    assert(bad == STATUS_INVALID_PARAMETER && enabled == 0 && on && disabled == 0 && flag(), "userboot: ProcessHandleCheckingMode liga HANDLE_TABLE.EnableHandleExceptions e ele nao desliga");
    let checking = query(54, 4);
    assert(checking == 0 && guest::read32(output) == 1 && guest::read32(returned) == 0, "userboot: NtQueryInformationProcess(ProcessHandleCheckingMode) le o EnableHandleExceptions sem gravar o ReturnLength");
    // ThreadBreakOnTermination na thread corrente, desligado no fim.
    // SAFETY: a ETHREAD da thread corrente.
    let ethread = unsafe { Ethread::at(process::get_current_thread()) };
    // A variante de syscall lê os argumentos do vetor bruto do despacho.
    let raw = block + 0x800;
    let set_thread = |value: u32, length: u64| {
        guest::write32(buffer, value);
        let arguments = [(-2i64) as u64, 18, buffer, length];
        for (index, argument) in arguments.into_iter().enumerate() {
            guest::write64(raw + (index as u64 + 1) * 8, argument);
        }
        state::with_syscall_record(state::SyscallRecord::raw(raw), || call("NtSetInformationThread", arguments[0], arguments[1], arguments[2], arguments[3]))
    };
    let length = set_thread(1, 8);
    let critical = set_thread(1, 4);
    let marked = ethread.break_on_termination() == 1;
    let normal = set_thread(0, 4);
    let held = crate::ntos::se::privilege::single_privilege_check(20, 1);
    let expected = if held { critical == 0 && marked && normal == 0 } else { critical == STATUS_PRIVILEGE_NOT_HELD && !marked };
    assert(length == STATUS_INFO_LENGTH_MISMATCH && expected && ethread.break_on_termination() == 0, "userboot: ThreadBreakOnTermination liga e desliga a thread critica com SeDebugPrivilege");
}

fn system_classes(assert: Assert, block: u64, call: Call) {
    let (buffer, returned) = (block + 0x200, block + 0x1F0);
    let query = |class: u64, address: u64, length: u64| {
        guest::write32(returned, 0);
        call("NtQuerySystemInformation", class, address, length, returned)
    };
    let flags = query(9, buffer, 4);
    let flags_value = guest::read32(buffer);
    let flags_long = query(9, buffer, 8);
    assert(flags == 0 && flags_value == crate::ntos::rtl::shared_data::nt_global_flag() && flags_long == STATUS_INFO_LENGTH_MISMATCH && guest::read32(returned) == 4, "userboot: SystemFlagsInformation devolve o NtGlobalFlag em exatamente 4 bytes");
    let memory_status = query(184, buffer, 0x18);
    let (total, lowest, highest) = (guest::read64(buffer), guest::read64(buffer + 8), guest::read64(buffer + 0x10));
    let (low_page, high_page) = crate::ntos::mm::pfn::physical_page_bounds();
    let memory_long = query(184, buffer, 0x20);
    assert(
        memory_status == 0 && total == crate::ntos::mm::pfn::total_count() << 12 && lowest == low_page << 12 && highest == (high_page << 12) | 0xFFF && lowest < highest && memory_long == STATUS_INFO_LENGTH_MISMATCH && guest::read32(returned) == 0x18,
        "userboot: SystemPhysicalMemoryInformation com o total e os limites da RAM",
    );
    guest::write64(buffer, u64::MAX);
    let shared = query(197, buffer, 16);
    let shared_page = guest::read64(buffer);
    let shared_returned = guest::read32(returned);
    assert(shared == 0 && shared_page == crate::ntos::mm::shared_user_data::hypervisor_shared_user_va() && shared_page != 0 && shared_returned == 8 && query(197, buffer, 4) == STATUS_INFO_LENGTH_MISMATCH && guest::read32(returned) == 8 && query(197, buffer + 2, 8) == STATUS_DATATYPE_MISALIGNMENT, "userboot: SystemHypervisorSharedPageInformation publica a pagina de referencia do QPC");
}

fn events(assert: Assert, block: u64, rsp: u64, call: Call) {
    let (out, previous) = (block + 0x400, block + 0x410);
    // Evento de notificação sinalizado: o pulso devolve 1 e o deixa zerado.
    guest::write32(rsp + 0x28, 1);
    let created = call("NtCreateEvent", out, 0x1F_0003, 0, 0);
    let notification = guest::read64(out);
    let pointer = |handle: u64| state::get_user_handle(handle).and_then(|entry| entry.object.native_body()).map_or(0, |body| body.pointer);
    guest::write32(previous, 0xFF);
    let pulsed = call("NtPulseEvent", notification, previous, 0, 0);
    let cleared = pointer(notification) != 0 && dispatcher::read_state(pointer(notification)) == 0;
    assert(created == 0 && pulsed == 0 && guest::read32(previous) == 1 && cleared, "userboot: NtPulseEvent devolve o estado anterior e deixa o evento nao sinalizado");
    // O reforço de prioridade exige evento de sincronização.
    guest::write32(rsp + 0x28, 0);
    let synchronization_created = call("NtCreateEvent", out, 0x1F_0003, 0, 1);
    let synchronization = guest::read64(out);
    let mismatch = call("NtSetEventBoostPriority", notification, 0, 0, 0);
    let boosted = call("NtSetEventBoostPriority", synchronization, 0, 0, 0);
    let signaled = pointer(synchronization) != 0 && dispatcher::read_state(pointer(synchronization)) == 1;
    assert(synchronization_created == 0 && mismatch == STATUS_OBJECT_TYPE_MISMATCH && boosted == 0 && signaled, "userboot: NtSetEventBoostPriority recusa o evento de notificacao e sinaliza o de sincronizacao");
    for handle in [notification, synchronization] {
        let _ = call("NtClose", handle, 0, 0, 0);
    }
}

/// OBJECT_ATTRIBUTES de usuário em `block` com o nome em `block + 0x100`.
fn attributes(block: u64, name: &str) -> u64 {
    state::write_user_wide(block + 0x100, name);
    state::write_unicode_string(block + 0x40, block + 0x100, name);
    // SAFETY: memória de usuário do teste, mapeada pelo kernel.
    let object = unsafe { ObjectAttributes::at(block) };
    object.length.set(ObjectAttributes::SIZE as u32);
    object.root_directory.set(0);
    object.object_name.set(block + 0x40);
    object.attributes.set(0x40);
    object.security_descriptor.set(0);
    object.security_quality_of_service.set(0);
    block
}

/// NtQueryDirectoryObject de modo usuário num diretório com dois filhos.
fn directory_query(assert: Assert, block: u64, rsp: u64, call: Call) {
    let (oa, out, buffer, context, returned) = (block + 0x1000, block + 0x500, block + 0x600, block + 0x510, block + 0x518);
    let create = |name: &str, access: u64| {
        guest::write64(out, 0);
        let status = call("NtCreateDirectoryObject", out, access, attributes(oa, name), 0);
        (status, guest::read64(out))
    };
    let (root_status, root) = create("\\OpenNtDirConsulta", 0xF);
    let (first_status, first) = create("\\OpenNtDirConsulta\\Sub1", 0xF);
    let (second_status, second) = create("\\OpenNtDirConsulta\\Sub2", 0xF);
    let query = |handle: u64, address: u64, length: u64, single: u64, restart: u64| {
        guest::write64(rsp + 0x28, restart);
        guest::write64(rsp + 0x30, context);
        guest::write64(rsp + 0x38, returned);
        guest::write32(returned, 0xFFFF_FFFF);
        call("NtQueryDirectoryObject", handle, address, length, single)
    };
    let text = |unicode: u64| {
        let length = guest::read16(unicode) as usize;
        let pointer = guest::read64(unicode + 8);
        let units: alloc::vec::Vec<u16> = (0..length / 2).map(|index| guest::read16(pointer + index as u64 * 2)).collect();
        alloc::string::String::from_utf16_lossy(&units)
    };
    // Uma entrada: 0x20 do descritor, 0x20 do terminador, "Sub1" e
    // "Directory" com os terminadores.
    let entry_total = 0x40 + 10 + 20;
    let one = query(root, buffer, 0x200, 1, 1);
    let first_entry = (text(buffer), text(buffer + 0x10), guest::read32(context), guest::read32(returned));
    let two = query(root, buffer, 0x200, 1, 0);
    let second_name = text(buffer);
    let second_context = guest::read32(context);
    assert(
        root_status == 0 && first_status == 0 && second_status == 0 && one == 0 && first_entry.0 == "Sub1" && first_entry.1 == "Directory" && first_entry.2 == 1 && first_entry.3 == entry_total && two == 0 && second_name == "Sub2" && second_context == 2,
        "userboot: NtQueryDirectoryObject devolve uma entrada por vez com o nome, o tipo e o contexto",
    );
    guest::write_bytes(buffer, &[0xEE; 0x40]);
    let none = query(root, buffer, 0x200, 1, 0);
    assert(none == 0x8000_001A && guest::read32(returned) == 0x20 && guest::read32(context) == 2 && guest::read64(buffer) == 0, "userboot: NtQueryDirectoryObject sem mais entradas devolve o terminador, ReturnLength 0x20 e o contexto intacto");
    let more = query(root, buffer, 0x30, 0, 1);
    let more_context = guest::read32(context);
    let small = query(root, buffer, 0x30, 1, 1);
    assert(more == 0x105 && more_context == 0 && small == 0xC000_0023 && guest::read32(returned) == entry_total, "userboot: NtQueryDirectoryObject com a primeira entrada grande demais: STATUS_MORE_ENTRIES sem ReturnSingleEntry, STATUS_BUFFER_TOO_SMALL com");
    // Alinhamento de WCHAR e DIRECTORY_QUERY no handle.
    guest::write64(out, 0);
    let opened = call("NtOpenDirectoryObject", out, 2, attributes(oa, "\\OpenNtDirConsulta"), 0);
    let traverse = guest::read64(out);
    assert(query(root, buffer + 1, 0x200, 1, 1) == 0x8000_0002 && opened == 0 && query(traverse, buffer, 0x200, 1, 1) == STATUS_ACCESS_DENIED, "userboot: NtQueryDirectoryObject exige buffer alinhado e DIRECTORY_QUERY");
    for handle in [traverse, second, first, root] {
        let _ = call("NtClose", handle, 0, 0, 0);
    }
}
