//! Autotestes dos serviços de modo usuário que o smss.exe e o csrss.exe
//! reais pedem no boot e que antes não tinham provedor ou respondiam
//! errado: NtInitializeRegistry (`cm/hive_init`), NtIsUILanguageComitted
//! (`ps/locale`), NtApphelpCacheControl (`ps/apphelp_cache`), as classes
//! ProcessDefaultHardErrorMode e ProcessHandleCheckingMode do
//! NtSetInformationProcess (`ps/set_process_information`), as classes de
//! tamanho fixo do NtQuerySystemInformation (`ex/system_information`) e os
//! vizinhos NtPulseEvent, NtSetEventBoostPriority e NtQueryDirectoryObject,
//! e o objeto Timer do Executive de modo usuário (NtCreateTimer, NtSetTimer
//! e NtCancelTimer, que o WUDFPlatform.dll do services.exe pede), o
//! NtAdjustGroupsToken, os objetos de reserva de modo usuário
//! (NtAllocateReserveObject e NtSetIoCompletionEx, do RPC assíncrono do
//! rpcrt4) e o NtFlushProcessWriteBuffers (do d3d11).

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
    // O KeFlushProcessWriteBuffers do serviço (a trava do d3d11) não tem
    // status: o NtFlushProcessWriteBuffers do 19041 sempre devolve sucesso.
    assert(call("NtFlushProcessWriteBuffers", 0, 0, 0, 0) == 0, "userboot: NtFlushProcessWriteBuffers tem provedor e devolve STATUS_SUCCESS");
    ui_language_and_apphelp(assert, &call);
    process_classes(assert, block, &call);
    system_classes(assert, block, &call);
    events(assert, block, rsp, &call);
    directory_query(assert, block, rsp, &call);
    executive_timer(assert, block, rsp, &call);
    coalescable_timer(assert, block, rsp, &call);
    adjust_groups(assert, block, rsp, &call);
    power_information(assert, block, rsp, &call);
    reserve_objects(assert, block, rsp, &call);
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
    // NtFlushInstallUILanguage sem SetComittedFlag e com o idioma da
    // instalação: sucesso com SeTcbPrivilege, e a confirmação (que só o
    // winlogon liga) continua desligada.
    let install = crate::ntos::ps::locale::install_ui_language() as u64;
    let tcb = crate::ntos::se::privilege::single_privilege_check(7, 1);
    let flushed = call("NtFlushInstallUILanguage", install, 0, 0, 0);
    assert(flushed == if tcb { 0 } else { 0xC000_0022 } && call("NtIsUILanguageComitted", 0, 0, 0, 0) == STATUS_OBJECT_NAME_NOT_FOUND && crate::ntos::ps::locale::install_ui_language() as u64 == install, "userboot: NtFlushInstallUILanguage sem confirmar mantem o idioma e a confirmacao desligada");
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
    // ProcessRaiseUMExceptionOnInvalidHandleClose: 1 liga, 0 desliga, outro
    // valor não muda o bit da HANDLE_TABLE.
    // SAFETY: a HANDLE_TABLE do processo corrente.
    let raise = || table != 0 && unsafe { HandleTable::at(table) }.raise_um_exception_on_invalid_handle_close() == 1;
    let saved_raise = raise();
    let raise_on = set(71, 1, buffer, 4);
    let after_on = raise();
    let raise_other = set(71, 7, buffer, 4);
    let after_other = raise();
    let raise_off = set(71, 0, buffer, 4);
    let after_off = raise();
    let raise_length = set(71, 1, buffer, 8);
    let _ = set(71, saved_raise as u32, buffer, 4);
    assert(raise_on == 0 && after_on && raise_other == 0 && after_other && raise_off == 0 && !after_off && raise_length == STATUS_INFO_LENGTH_MISMATCH, "userboot: ProcessRaiseUMExceptionOnInvalidHandleClose liga e desliga o bit da HANDLE_TABLE");
    // ProcessTimes, ProcessImageFileNameWin32 e ProcessMitigationPolicy.
    let (wide, wide_returned) = (block + 0x400, block + 0x3F0);
    let query_wide = |class: u64, address: u64, length: u64| {
        guest::write32(wide_returned, 0);
        guest::write64(rsp + 0x28, wide_returned);
        call("NtQueryInformationProcess", u64::MAX, class, address, length)
    };
    guest::write_bytes(wide, &[0xFF; 0x20]);
    let times = query_wide(4, wide, 0x20);
    let create_time = guest::read64(wide);
    let exit_time = guest::read64(wide + 8);
    let kernel_time = guest::read64(wide + 0x10);
    let times_returned = guest::read32(wide_returned);
    let increment = u64::from(crate::ntos::ke::clock::MAXIMUM_INCREMENT);
    let quad = |time: &crate::ntos::inc::types::LargeInteger| (time.high_part.get() as u32 as u64) << 32 | time.low_part.get() as u64;
    assert(
        times == 0 && create_time == quad(&eprocess.create_time) && exit_time == 0 && kernel_time % increment == 0 && times_returned == 0x20 && query_wide(4, wide, 0x18) == STATUS_INFO_LENGTH_MISMATCH && query_wide(4, wide + 2, 0x20) == STATUS_DATATYPE_MISALIGNMENT,
        "userboot: ProcessTimes com CreateTime do EPROCESS e os tempos em ticks; 0x20 bytes alinhados",
    );
    let image_path = crate::ntos::ps::user::process_state::get(process::get_current_process()).map(|identity| identity.image_path()).unwrap_or_default();
    if !image_path.is_empty() {
        let required = (image_path.trim_start_matches("\\??\\").encode_utf16().count() as u32 + 1) * 2 + 0x10;
        let short = query_wide(43, wide, 0x10);
        let short_returned = guest::read32(wide_returned);
        let full = query_wide(43, wide, 0x200);
        let text_length = u32::from(guest::read16(wide));
        assert(short == STATUS_INFO_LENGTH_MISMATCH && short_returned == required && full == 0 && text_length + 0x12 == required && guest::read64(wide + 8) == wide + 0x10, "userboot: ProcessImageFileNameWin32 com o UNICODE_STRING e o texto depois dele");
    }
    let mitigation = |policy: u32| {
        guest::write32(wide, policy);
        guest::write32(wide + 4, 0xFFFF_FFFF);
        (query_wide(52, wide, 8), guest::read32(wide + 4), guest::read32(wide_returned))
    };
    let flags = eprocess.mitigation_flags.get();
    let aslr = mitigation(1);
    let expected_aslr = (flags & 0x40 == 0) as u32 | if flags & 0x10 != 0 { 2 } else { 0 } | if flags & 0x20 != 0 { 4 } else { 0 } | if flags & 8 != 0 { 8 } else { 0 };
    let unsupported = mitigation(5);
    let dep = mitigation(0);
    assert(aslr == (0, expected_aslr, 0) && unsupported.0 == 0xC000_00BB && dep.0 == 0xC000_00BB && query_wide(52, wide, 4) == STATUS_INFO_LENGTH_MISMATCH, "userboot: ProcessMitigationPolicy le as flags do EPROCESS por politica; 0 e 5 sem consulta");
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
    // A consulta da mesma classe (o valor antigo do RtlSetThreadIsCritical):
    // ULONG, ReturnLength 4 (o quinto argumento, na pilha de usuário).
    let (thread_output, thread_returned) = (block + 0x1A0, block + 0x1A8);
    let query_thread = |length: u64| {
        guest::write32(thread_output, 0xFFFF_FFFF);
        guest::write32(thread_returned, 0);
        guest::write64(rsp + 0x28, thread_returned);
        let arguments = [(-2i64) as u64, 18, thread_output, length];
        for (index, argument) in arguments.into_iter().enumerate() {
            guest::write64(raw + (index as u64 + 1) * 8, argument);
        }
        let status = state::with_syscall_record(state::SyscallRecord::raw(raw), || call("NtQueryInformationThread", arguments[0], arguments[1], arguments[2], arguments[3]));
        (status, guest::read32(thread_output), guest::read32(thread_returned))
    };
    let length = set_thread(1, 8);
    let critical = set_thread(1, 4);
    let marked = ethread.break_on_termination() == 1;
    let queried = query_thread(4);
    let normal = set_thread(0, 4);
    let held = crate::ntos::se::privilege::single_privilege_check(20, 1);
    let expected = if held { critical == 0 && marked && normal == 0 } else { critical == STATUS_PRIVILEGE_NOT_HELD && !marked };
    assert(length == STATUS_INFO_LENGTH_MISMATCH && expected && ethread.break_on_termination() == 0, "userboot: ThreadBreakOnTermination liga e desliga a thread critica com SeDebugPrivilege");
    assert(queried == (0, marked as u32, 4) && query_thread(4) == (0, 0, 4) && query_thread(8).0 == STATUS_INFO_LENGTH_MISMATCH, "userboot: NtQueryInformationThread(ThreadBreakOnTermination) devolve a marca da thread");
    // ProcessBreakOnTermination: a consulta devolve a marca do processo
    // (o processo de teste não é crítico).
    let critical_process = query(29, 4);
    let process_value = guest::read32(output);
    let process_returned = guest::read32(returned);
    assert(critical_process == 0 && process_value == eprocess.break_on_termination() && process_returned == 4 && query(29, 8) == STATUS_INFO_LENGTH_MISMATCH, "userboot: NtQueryInformationProcess(ProcessBreakOnTermination) devolve a marca do processo");
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
    // SystemBasicInformation e a KUSER_SHARED_DATA contam o mesmo bloco de
    // memória física (MmNumberOfPhysicalPages, MmLowestPhysicalPage,
    // MmHighestPhysicalPage) que a classe 184.
    let basic_status = query(0, buffer, 0x40);
    let (basic_pages, basic_lowest, basic_highest) = (guest::read32(buffer + 0xC) as u64, guest::read32(buffer + 0x10) as u64, guest::read32(buffer + 0x14) as u64);
    let kuser_pages = crate::ntos::mm::shared_user_data::data().map_or(0, |data| data.number_of_physical_pages.get() as u64);
    assert(
        basic_status == 0 && basic_pages << 12 == total && basic_lowest == low_page && basic_highest == high_page && kuser_pages == basic_pages && basic_pages == crate::ntos::mm::physical_layout::number_of_physical_pages(),
        "userboot: SystemBasicInformation e KUSER_SHARED_DATA com as paginas, o Lowest e o Highest do bloco de memoria fisica",
    );
    guest::write64(buffer, u64::MAX);
    let shared = query(197, buffer, 16);
    let shared_page = guest::read64(buffer);
    let shared_returned = guest::read32(returned);
    assert(shared == 0 && shared_page == crate::ntos::mm::shared_user_data::hypervisor_shared_user_va() && shared_page != 0 && shared_returned == 8 && query(197, buffer, 4) == STATUS_INFO_LENGTH_MISMATCH && guest::read32(returned) == 8 && query(197, buffer + 2, 8) == STATUS_DATATYPE_MISALIGNMENT, "userboot: SystemHypervisorSharedPageInformation publica a pagina de referencia do QPC");
    // SystemKernelDebuggerInformation: dois bytes, sem exigência de
    // alinhamento (o ProbeForWrite de alinhamento 1).
    guest::write32(buffer, u32::MAX);
    let debugger = query(35, buffer + 1, 4);
    let (debugger_enabled, debugger_absent) = (guest::read8(buffer + 1), guest::read8(buffer + 2));
    let debugger_returned = guest::read32(returned);
    let debugger_short = query(35, buffer, 1);
    assert(
        debugger == 0 && debugger_enabled == crate::ntos::kd::debugger::enabled() as u8 && debugger_absent == crate::ntos::kd::debugger::debugger_not_present() as u8 && debugger_returned == 2 && guest::read8(buffer + 3) == 0xFF && debugger_short == STATUS_INFO_LENGTH_MISMATCH && guest::read32(returned) == 2,
        "userboot: SystemKernelDebuggerInformation com o KdDebuggerEnabled e o KdDebuggerNotPresent",
    );
    // SystemObjectSecurityMode, SystemIsolatedUserModeInformation,
    // SystemFlushInformation e SystemWriteConstraintInformation.
    let security_mode = query(70, buffer, 4);
    let security_value = guest::read32(buffer);
    let security_long = query(70, buffer, 8);
    assert(security_mode == 0 && security_value == crate::ntos::ex::system_information::object_security_mode() && security_long == STATUS_INFO_LENGTH_MISMATCH && guest::read32(returned) == 4, "userboot: SystemObjectSecurityMode devolve o ObpObjectSecurityMode em exatamente 4 bytes");
    guest::write_bytes(buffer, &[0xFF; 0x20]);
    let isolated = query(165, buffer, 0x10);
    let isolated_zero = guest::read64(buffer) == 0 && guest::read64(buffer + 8) == 0;
    assert(isolated == 0 && isolated_zero && guest::read32(returned) == 0x10 && query(165, buffer, 0x20) == STATUS_INFO_LENGTH_MISMATCH, "userboot: SystemIsolatedUserModeInformation zerado sem o kernel seguro");
    guest::write_bytes(buffer, &[0xFF; 0x28]);
    let flush = query(192, buffer, 0x28);
    let flush_expected = crate::ntos::ex::system_information::flush_information();
    let flush_bytes = (0..0x20u64).map(|offset| guest::read8(buffer + offset)).collect::<alloc::vec::Vec<u8>>();
    assert(flush == 0 && flush_bytes == flush_expected && flush_bytes[0] & 1 == 1 && guest::read32(returned) == 0x20 && query(192, buffer, 0x1F) == STATUS_INFO_LENGTH_MISMATCH, "userboot: SystemFlushInformation com os metodos do KeFeatureBits e o CFlushSize");
    guest::write64(buffer, u64::MAX);
    let constraint = query(195, buffer, 8);
    assert(constraint == 0 && guest::read64(buffer) == 0 && guest::read32(returned) == 8 && query(195, buffer, 4) == STATUS_INFO_LENGTH_MISMATCH, "userboot: SystemWriteConstraintInformation zero sem o \\Device\\UwfvolControl");
    // NtQuerySystemEnvironmentValueEx: com o SeSystemEnvironmentPrivilege, o
    // firmware BIOS responde STATUS_NOT_IMPLEMENTED sem tocar os argumentos;
    // sem ele (e fora de SeUserModeDriversSid), STATUS_PRIVILEGE_NOT_HELD.
    // O PreviousMode de uma syscall de modo usuário (o RtlCheckTokenMembershipEx
    // em KernelMode concede sempre).
    // SAFETY: a ETHREAD da thread corrente.
    let previous = &unsafe { Ethread::at(process::get_current_thread()) }.tcb.previous_mode;
    let saved_previous = previous.get();
    previous.set(1);
    let environment = call("NtQuerySystemEnvironmentValueEx", 0, 0, 0, 0);
    previous.set(saved_previous);
    let environment_held = crate::ntos::se::privilege::single_privilege_check(22, 1);
    assert(environment == if environment_held { 0xC000_0002 } else { STATUS_PRIVILEGE_NOT_HELD }, "userboot: NtQuerySystemEnvironmentValueEx confere o privilegio antes do firmware BIOS");
}

/// O ETIMER de modo usuário: o TimerType acima de SynchronizationTimer e o
/// período negativo recusados, o estado anterior e o corrente pelos
/// BOOLEANs de saída e o handle fechado.
/// NtAdjustGroupsToken de modo usuário num token com um grupo opcional
/// (S-1-5-32-545, habilitado por padrão), um só de negação (S-1-5-4) e o
/// Everyone obrigatório: o PreviousState curto, a mudança com o estado de
/// antes, o SID ausente, as recusas de negação e de obrigatório e o
/// ResetToDefault.
fn adjust_groups(assert: Assert, block: u64, rsp: u64, call: Call) {
    use crate::ntos::se::model::{sid, Group};
    use crate::ntos::se::token::{handles, tokens};
    let Some(primary) = process::get_primary_token(process::get_current_process()) else { return };
    let users = sid(5, &[32, 545]);
    let initialize = |token: &mut tokens::Token| {
        token.groups = alloc::vec![Group { sid: sid(1, &[0]), attributes: 7 }, Group { sid: sid(5, &[32, 545]), attributes: 6 }, Group { sid: sid(5, &[4]), attributes: 0x10 }];
    };
    let Ok(token) = tokens::create(Some(primary), Some(&initialize)) else { return };
    let handle = handles::create(token, 0xF01FF, 0, true).unwrap_or(0);
    let _ = tokens::release(token);
    let (state, sids, previous, returned) = (block + 0xA00, block + 0xA80, block + 0xB00, block + 0xBF8);
    let request = |entries: &[(&[u8], u32)]| {
        guest::write32(state, entries.len() as u32);
        let mut cursor = sids;
        for (index, (identifier, attributes)) in entries.iter().enumerate() {
            guest::write_bytes(cursor, identifier);
            guest::write64(state + 8 + index as u64 * 16, cursor);
            guest::write32(state + 16 + index as u64 * 16, *attributes);
            cursor += identifier.len() as u64;
        }
    };
    let adjust = |reset: u64, length: u64, previous_state: u64| {
        guest::write64(rsp + 0x28, previous_state);
        guest::write64(rsp + 0x30, returned);
        call("NtAdjustGroupsToken", handle, reset, state, length)
    };
    let attributes_of = |identifier: &[u8]| tokens::with(token, |record| record.groups.iter().find(|group| group.sid == identifier).map(|group| group.attributes)).flatten();
    request(&[(&users, 0)]);
    let short = adjust(0, 8, previous);
    let needed = guest::read32(returned);
    let unchanged = attributes_of(&users) == Some(6);
    let changed = adjust(0, 0x100, previous);
    let previous_ok = guest::read32(previous) == 1 && guest::read32(previous + 16) == 6 && guest::read_bytes(guest::read64(previous + 8), users.len()) == users;
    let disabled = attributes_of(&users) == Some(2);
    let unknown_sid = sid(5, &[32, 999]);
    request(&[(&users, 0), (&unknown_sid, 4)]);
    let not_all = adjust(0, 0, 0);
    let deny_sid = sid(5, &[4]);
    request(&[(&deny_sid, 4)]);
    let deny_only = adjust(0, 0, 0);
    let world = sid(1, &[0]);
    request(&[(&world, 0)]);
    let mandatory = adjust(0, 0, 0);
    let reset = adjust(1, 0x100, previous);
    let restored = attributes_of(&users) == Some(6) && guest::read32(previous) == 1;
    let closed = call("NtClose", handle, 0, 0, 0);
    assert(
        handle != 0 && short == 0xC000_0023 && needed == 40 && unchanged && changed == 0 && previous_ok && disabled && not_all == 0x106 && deny_only == 0xC000_02B3 && mandatory == 0xC000_005D && reset == 0 && restored && closed == 0,
        "userboot: NtAdjustGroupsToken com PreviousState, SID ausente, recusas de negacao e de obrigatorio e ResetToDefault",
    );
}

fn executive_timer(assert: Assert, block: u64, rsp: u64, call: Call) {
    let (handle_cell, due, previous, current) = (block + 0x600, block + 0x608, block + 0x610, block + 0x611);
    let invalid_type = call("NtCreateTimer", handle_cell, 0x1F_0003, 0, 2);
    let created = call("NtCreateTimer", handle_cell, 0x1F_0003, 0, 0);
    let handle = guest::read64(handle_cell);
    // Prazo relativo de 1 s, sem APC, sem ResumeTimer, período 0.
    guest::write64(due, (-10_000_000i64) as u64);
    guest::write64(rsp + 0x28, 0);
    guest::write64(rsp + 0x30, (-1i64) as u64);
    guest::write64(rsp + 0x38, previous);
    let negative_period = call("NtSetTimer", handle, due, 0, 0);
    guest::write64(rsp + 0x30, 0);
    guest::write8(previous, 0xFF);
    let set = call("NtSetTimer", handle, due, 0, 0);
    let previous_state = guest::read8(previous);
    // NtQueryTimer: o tempo restante até o prazo (no máximo 1 s) e o estado.
    let (information, returned) = (block + 0x620, block + 0x630);
    guest::write64(rsp + 0x28, returned);
    let queried = call("NtQueryTimer", handle, 0, information, 0x10);
    let remaining = guest::read64(information) as i64;
    let query_ok = queried == 0 && remaining > 0 && remaining <= 10_000_000 && guest::read8(information + 8) == 0 && guest::read32(returned) == 0x10;
    let query_refused = call("NtQueryTimer", handle, 1, information, 0x10) == 0xC000_0003 && call("NtQueryTimer", handle, 0, information, 8) == 0xC000_0004 && call("NtQueryTimer", handle, 0, information + 1, 0x10) == 0x8000_0002;
    guest::write8(current, 0xFF);
    let cancelled = call("NtCancelTimer", handle, current, 0, 0);
    let current_state = guest::read8(current);
    // Fora da fila, o KeQueryTimerDueTime dá 0: o restante fica negativo.
    let idle = call("NtQueryTimer", handle, 0, information, 0x10) == 0 && (guest::read64(information) as i64) < 0;
    let closed = call("NtClose", handle, 0, 0, 0);
    assert(
        invalid_type == 0xC000_00F2 && created == 0 && handle != 0 && negative_period == 0xC000_00F4 && set == 0 && previous_state == 0 && cancelled == 0 && current_state == 0 && closed == 0,
        "userboot: NtCreateTimer, NtSetTimer e NtCancelTimer do ETIMER de modo usuario",
    );
    assert(query_ok && query_refused && idle, "userboot: NtQueryTimer do ETIMER (restante, estado, recusas e timer fora da fila)");
    // NtOpenTimer (o OpenWaitableTimerW): um timer nomeado abre pelo nome;
    // um nome ausente dá STATUS_OBJECT_NAME_NOT_FOUND e um objeto de outro
    // tipo, STATUS_OBJECT_TYPE_MISMATCH.
    let (named_cell, opened_cell, oa) = (block + 0x638, block + 0x640, block + 0x1C00);
    let named = call("NtCreateTimer", named_cell, 0x1F_0003, attributes(oa, "\\OpenNtTimerAberto"), 0);
    let named_handle = guest::read64(named_cell);
    let opened = call("NtOpenTimer", opened_cell, 0x1F_0003, attributes(oa, "\\OpenNtTimerAberto"), 0);
    let opened_handle = guest::read64(opened_cell);
    let missing = call("NtOpenTimer", opened_cell, 0x1F_0003, attributes(oa, "\\OpenNtTimerAusente"), 0);
    let directory = call("NtCreateDirectoryObject", block + 0x648, 0xF, attributes(oa, "\\OpenNtTimerDiretorio"), 0);
    let mismatch = call("NtOpenTimer", opened_cell, 0x1F_0003, attributes(oa, "\\OpenNtTimerDiretorio"), 0);
    let closed = [named_handle, opened_handle, guest::read64(block + 0x648)].map(|handle| call("NtClose", handle, 0, 0, 0));
    if !(named == 0 && opened == 0 && opened_handle != 0 && opened_handle != named_handle && missing == 0xC000_0034 && directory == 0 && mismatch == 0xC000_0024 && closed == [0, 0, 0]) {
        crate::debug_print!("[userboot] NtOpenTimer: criado {:#x} ({:#x}), aberto {:#x} ({:#x}), ausente {:#x}, diretorio {:#x}, outro tipo {:#x}, fechados {:x?}", named, named_handle, opened, opened_handle, missing, directory, mismatch, closed);
    }
    assert(
        named == 0 && opened == 0 && opened_handle != 0 && opened_handle != named_handle && missing == 0xC000_0034 && directory == 0 && mismatch == 0xC000_0024 && closed == [0, 0, 0],
        "userboot: NtOpenTimer abre o ETIMER nomeado e recusa nome ausente e objeto de outro tipo",
    );
}

/// NtSetTimerEx no ETIMER (o SetWaitableTimer do kernelbase): as recusas de
/// classe, tamanho, alinhamento e período, o set com TolerableDelay e
/// PreviousState, a espera de modo usuário no handle nativo do ETIMER e um
/// handle de outro tipo.
fn coalescable_timer(assert: Assert, block: u64, rsp: u64, call: Call) {
    let (handle_cell, info, previous, zero, event_cell) = (block + 0x680, block + 0x6C0, block + 0x6F8, block + 0x700, block + 0x708);
    let created = call("NtCreateTimer", handle_cell, 0x1F_0003, 0, 0);
    let handle = guest::read64(handle_cell);
    let fill = |due: i64, period: u32, tolerable_delay: u32| {
        guest::write64(info, due as u64);
        guest::write64(info + 0x08, 0);
        guest::write64(info + 0x10, 0);
        guest::write64(info + 0x18, 0);
        guest::write32(info + 0x20, period);
        guest::write32(info + 0x24, tolerable_delay);
        guest::write64(info + 0x28, previous);
    };
    fill(-10_000_000, 0, 50);
    let refused = call("NtSetTimerEx", handle, 1, info, 0x30) == 0xC000_0003 && call("NtSetTimerEx", handle, 0, info, 0x28) == 0xC000_0004 && call("NtSetTimerEx", handle, 0, info + 2, 0x30) == STATUS_DATATYPE_MISALIGNMENT;
    fill(-10_000_000, 0x8000_0000, 50);
    let period_refused = call("NtSetTimerEx", handle, 0, info, 0x30) == 0xC000_00F1;
    fill(-10_000_000, 0, 50);
    guest::write8(previous, 0xFF);
    let set = call("NtSetTimerEx", handle, 0, info, 0x30) == 0 && guest::read8(previous) == 0;
    // A espera de modo usuário resolve o handle nativo do ETIMER.
    guest::write64(zero, 0);
    let pending = call("NtWaitForSingleObject", handle, 0, zero, 0) == 0x102;
    // Prazo absoluto já passado: o timer de notificação fica sinalizado.
    fill(116_444_736_000_000_000, 0, 0);
    let expired = call("NtSetTimerEx", handle, 0, info, 0x30) == 0 && {
        crate::ntos::ke::timer::check_timers();
        call("NtWaitForSingleObject", handle, 0, zero, 0) == 0 && call("NtWaitForSingleObject", handle, 0, zero, 0) == 0
    };
    let _ = call("NtCancelTimer", handle, 0, 0, 0);
    let closed = call("NtClose", handle, 0, 0, 0) == 0;
    guest::write64(rsp + 0x28, 0);
    let event = call("NtCreateEvent", event_cell, 0x1F_0003, 0, 0) == 0;
    let mismatch = call("NtSetTimerEx", guest::read64(event_cell), 0, info, 0x30) == 0xC000_0024;
    let _ = call("NtClose", guest::read64(event_cell), 0, 0, 0);
    assert(
        created == 0 && refused && period_refused && set && pending && expired && closed && event && mismatch,
        "userboot: NtSetTimerEx no ETIMER (recusas, TolerableDelay, PreviousState, espera no handle nativo e outro tipo)",
    );
}

/// NtAllocateReserveObject e NtSetIoCompletionEx de modo usuário, como no
/// 19041: tipo inválido; a reserva de conclusão tomada pelo envio, recusada
/// em uso (STATUS_INVALID_PARAMETER_2) e devolvida pela retirada; o handle
/// de reserva nulo é inválido no Nt.
fn reserve_objects(assert: Assert, block: u64, rsp: u64, call: Call) {
    let (reserve_cell, port_cell, key, context, iosb, raw) = (block + 0x800, block + 0x808, block + 0x810, block + 0x818, block + 0x820, block + 0x840);
    let invalid = call("NtAllocateReserveObject", reserve_cell, 0, 2, 0);
    let allocated = call("NtAllocateReserveObject", reserve_cell, 0, 1, 0);
    let reserve = guest::read64(reserve_cell);
    guest::write64(rsp + 0x28, 0);
    let created = call("NtCreateIoCompletion", port_cell, 0x1F_0003, 0, 1);
    let port = guest::read64(port_cell);
    // KeyContext e ApcContext pelo frame bruto; IoStatus e
    // IoStatusInformation na pilha.
    let post = |reserve: u64, key: u64, context: u64| {
        for (index, value) in [port, reserve, key, context].into_iter().enumerate() {
            guest::write64(raw + 8 + index as u64 * 8, value);
        }
        guest::write64(rsp + 0x28, 0x77);
        guest::write64(rsp + 0x30, 0x99);
        state::with_syscall_record(state::SyscallRecord::raw(raw), || call("NtSetIoCompletionEx", port, reserve, key, context))
    };
    let posted = post(reserve, 0x11, 0x22);
    let again = post(reserve, 0x33, 0x44);
    let null_reserve = post(0, 0x33, 0x44);
    let remove = || {
        guest::write64(rsp + 0x28, 0);
        call("NtRemoveIoCompletion", port, key, context, iosb)
    };
    let removed = remove();
    let values = (guest::read64(key), guest::read64(context), guest::read32(iosb), guest::read64(iosb + 8));
    let reposted = post(reserve, 0x55, 0x66);
    let removed_again = remove();
    let closed = [reserve, port].map(|handle| call("NtClose", handle, 0, 0, 0));
    assert(
        invalid == STATUS_INVALID_PARAMETER && allocated == 0 && reserve != 0 && created == 0 && posted == 0 && again == 0xC000_00F0 && null_reserve == 0xC000_0008 && removed == 0 && values == (0x11, 0x22, 0x77, 0x99) && reposted == 0 && removed_again == 0 && guest::read64(key) == 0x55 && closed == [0, 0],
        "userboot: NtAllocateReserveObject e NtSetIoCompletionEx com a reserva de conclusao (em uso recusada, devolvida pela retirada; nula invalida)",
    );
}

/// NtPowerInformation de modo usuário: PlatformInformation e PlatformRole
/// sem entrada, o PowerInformationInternal 4 (o UmpoSmartPresenceInit), os
/// níveis só de kernel e o tamanho da saída.
fn power_information(assert: Assert, block: u64, rsp: u64, call: Call) {
    let (input, output) = (block + 0x700, block + 0x720);
    let power = |level: u64, input: u64, input_length: u64, output: u64, output_length: u64| {
        guest::write64(rsp + 0x28, output_length);
        call("NtPowerInformation", level, input, input_length, output)
    };
    guest::write32(output, 0xFFFF_FFFF);
    let platform = power(66, 0, 0, output, 1);
    let aoac = guest::read8(output);
    let platform_input = power(66, input, 4, output, 1);
    let platform_no_output = power(66, 0, 0, 0, 0);
    guest::write32(output, 0);
    let role = power(75, 0, 0, output, 4);
    let role_value = guest::read32(output);
    let role_short = power(75, 0, 0, output, 2);
    guest::write32(input, 4);
    guest::write32(input + 4, 0);
    guest::write8(output, 0xFF);
    let absence = power(87, input, 8, output, 1);
    let absence_value = guest::read8(output);
    let absence_short_input = power(87, input, 4, output, 1);
    let absence_no_output = power(87, input, 8, 0, 0);
    guest::write32(input, 0x100);
    let internal_invalid = power(87, input, 8, output, 1);
    // Os tipos internos só de kernel do win32kbase (SessionPowerState 0x13,
    // SetWatchdog 0x15, InputControllerState 0x1C): STATUS_ACCESS_DENIED ao
    // modo usuário (PopPowerInformationInternal 0x6f1c77).
    let internal_denied = [0x13u32, 0x15, 0x1C].map(|internal| {
        guest::write32(input, internal);
        power(87, input, 8, 0, 0)
    });
    let kernel_only = power(41, 0, 0, output, 0x40);
    let out_of_range = power(0x60, 0, 0, output, 4);
    assert(
        platform == 0 && aoac == 0 && platform_input == STATUS_INVALID_PARAMETER && platform_no_output == STATUS_INVALID_PARAMETER && role == 0 && role_value == 1 && role_short == 0xC000_0023 && absence == 0 && absence_value == 0 && absence_short_input == STATUS_INVALID_PARAMETER && absence_no_output == 0xC000_0023 && internal_invalid == STATUS_INVALID_PARAMETER && internal_denied == [STATUS_ACCESS_DENIED; 3] && kernel_only == STATUS_ACCESS_DENIED && out_of_range == STATUS_INVALID_PARAMETER,
        "userboot: NtPowerInformation de modo usuario (66, 75, 87 tipo 4, tipos internos e niveis so de kernel)",
    );
    // SystemVideoState (29, o CProcessStateManager do LogonUI): sem entrada,
    // os 4 bytes do PopConsoleDisplayState, sem privilégio.
    guest::write32(output, 0xEEEE_EEEE);
    let video = power(29, 0, 0, output, 4);
    let video_value = guest::read32(output);
    let video_short = power(29, 0, 0, output, 2);
    let video_no_output = power(29, 0, 0, 0, 0);
    let video_empty_output = power(29, 0, 0, output, 0);
    assert(
        video == 0 && video_value == crate::ntos::po::display_state::console_display_state() && video_short == 0xC000_0023 && video_no_output == STATUS_INVALID_PARAMETER && video_empty_output == STATUS_INVALID_PARAMETER,
        "userboot: NtPowerInformation 29 (SystemVideoState) de modo usuario",
    );
    // SystemPowerCapabilities (0x4c bytes) e SystemBatteryState (0x20).
    let capabilities_output = block + 0x800;
    guest::write_bytes(capabilities_output, &[0xEE; 0x80]);
    let capabilities = power(4, 0, 0, capabilities_output, 0x4C);
    let (sleep_button, s1, s5, ups) = (guest::read8(capabilities_output + 1), guest::read8(capabilities_output + 3), guest::read8(capabilities_output + 7), guest::read8(capabilities_output + 0xC));
    let capabilities_short = power(4, 0, 0, capabilities_output, 0x40);
    let battery = power(5, 0, 0, capabilities_output + 0x60, 0x20);
    let (ac_on_line, battery_present) = (guest::read8(capabilities_output + 0x60), guest::read8(capabilities_output + 0x61));
    let battery_short = power(5, 0, 0, capabilities_output + 0x60, 0x1F);
    assert(
        capabilities == 0 && sleep_button == 0 && s1 == 0 && s5 == 1 && ups == 0 && capabilities_short == 0xC000_0023 && battery == 0 && ac_on_line == 1 && battery_present == 0 && battery_short == 0xC000_0023,
        "userboot: NtPowerInformation 4 e 5 (desktop S0/S5 com AC e sem bateria)",
    );
    // PowerSettingNotificationName e GetPowerSettingValue sobre
    // GUID_ACDC_POWER_SOURCE (o powrprof do RpcSs e do psmsrv).
    let acdc: [u8; 16] = [0x59, 0x9A, 0x3E, 0x5D, 0xD5, 0xE9, 0x00, 0x4B, 0xA6, 0xBD, 0xFF, 0x34, 0xFF, 0x51, 0x65, 0x48];
    let (setting, value) = (block + 0x900, block + 0x940);
    guest::write_bytes(setting, &acdc);
    guest::write32(setting + 0x10, 0xFFFF_FFFF);
    let name = power(58, setting, 0x14, value, 8);
    let first_name = guest::read64(value);
    let again = power(58, setting, 0x14, value, 8);
    let same_name = guest::read64(value) == first_name && first_name != 0;
    let global = power(58, 0, 0, value, 8);
    let global_name = guest::read64(value);
    let name_short_input = power(58, setting, 0x10, value, 8);
    let name_short_output = power(58, setting, 0x14, value, 4);
    let name_no_output = power(58, setting, 0x14, 0, 0);
    guest::write_bytes(value, &[0xEE; 0x30]);
    let get = power(59, setting, 0x10, value, 0x34);
    let records = (guest::read32(value), guest::read32(value + 8), guest::read32(value + 0xC), guest::read32(value + 0x18), guest::read32(value + 0x24));
    let same_stamps = guest::read32(value + 4) == guest::read32(value + 0x10) && guest::read32(value + 4) == guest::read32(value + 0x1C) && guest::read32(value + 4) != 0;
    let get_short = power(59, setting, 0x10, value, 0x27);
    let get_input = power(59, setting, 0x14, value, 0x34);
    guest::write_bytes(setting, &[0x11; 16]);
    let unknown_name = power(58, setting, 0x14, value, 8);
    let unknown_value = power(59, setting, 0x10, value, 0x34);
    assert(
        name == 0 && again == 0 && same_name && global == 0 && global_name != 0 && global_name != first_name && name_short_input == 0xC000_0023 && name_short_output == 0xC000_0023 && name_no_output == STATUS_INVALID_PARAMETER && get == 0 && records == (0x24, 4, 0, 0, 0) && same_stamps && get_short == 0xC000_0023 && get_input == 0xC000_0023 && unknown_name == STATUS_NOT_FOUND && unknown_value == STATUS_INVALID_PARAMETER,
        "userboot: NtPowerInformation 58 e 59 (nome WNF e valor AC de GUID_ACDC_POWER_SOURCE)",
    );
    // PowerInformationInternal 0x1F/0x20 (o RtlGet/SetSystemBootStatus do
    // lsass): entrada de 0x18 bytes, Count diferente de zero e itens
    // alinhados a 8; o pedido válido chega ao arquivo bootstat.dat (sem ele,
    // o status da abertura).
    let (request, items, data) = (block + 0x980, block + 0x9A0, block + 0x9C0);
    let boot_status = |internal: u32, count: u32, items_address: u64, length: u64| {
        guest::write32(request, internal);
        guest::write32(request + 4, 0);
        guest::write32(request + 8, count);
        guest::write32(request + 0xC, 0);
        guest::write64(request + 0x10, items_address);
        power(87, request, length, 0, 0)
    };
    guest::write32(items, 4);
    guest::write32(items + 4, 0);
    guest::write64(items + 8, data);
    guest::write32(items + 0x10, 4);
    guest::write32(data, 1);
    let short = boot_status(0x20, 1, items, 0x10);
    let empty = boot_status(0x20, 0, items, 0x18);
    let misaligned = boot_status(0x1F, 1, items + 4, 0x18);
    let get = boot_status(0x1F, 1, items, 0x18);
    let set = boot_status(0x20, 1, items, 0x18);
    assert(
        short == STATUS_INVALID_PARAMETER && empty == STATUS_INVALID_PARAMETER && misaligned == STATUS_DATATYPE_MISALIGNMENT && ![0xC000_0002, STATUS_INVALID_PARAMETER].contains(&get) && ![0xC000_0002, STATUS_INVALID_PARAMETER].contains(&set),
        "userboot: NtPowerInformation 87 tipos 0x1F e 0x20 (boot status data)",
    );
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
