//! Autoteste dos exports de Ps, Ke, Kd e Mm que eram os últimos imports de
//! drivers reais.
//!
//! Os vetores do KeInitializeTriageDumpDataArray/KeAddTriageDumpDataBlock,
//! do PsWrapApcWow64Thread, da validação de proteção do MmMapMdl e dos
//! parâmetros do MmSetPermanentCacheAttribute e do MmRemovePhysicalMemory
//! foram calculados executando as rotinas do ntoskrnl 19041 real num
//! emulador; cada teste chama o export pelo trampolim nativo (ABI MS x64).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::physical;
use crate::ntos::inc::types::extra_ke_misc::KtriageDumpDataArray;
use crate::ntos::inc::types::{self as nt, NtStruct};
use crate::ntos::ke::clock;
use crate::ntos::mm::{guest_memory as guest, loaded_images, paging};
use crate::ntos::ps::{kernel_threads, notify::thread as thread_notify, process, scheduler};
use crate::rtl::SpinLock;

type Assert = fn(bool, &str);

fn call(name: &str, arguments: &[u64]) -> u64 {
    super::phase6::call_export(name, arguments).unwrap_or(0xDEAD_DEAD_DEAD_DEAD)
}

fn status(name: &str, arguments: &[u64]) -> u32 {
    call(name, arguments) as u32
}

fn at<T: NtStruct>(address: u64) -> &'static T {
    // SAFETY: blocos alocados pelo teste com o tamanho do tipo ou objetos vivos.
    unsafe { T::at(address) }
}

/// Roda o escalonador até `done` (com limite de tempo).
fn pump(milliseconds: u64, done: &dyn Fn() -> bool) -> bool {
    let deadline = clock::uptime_ms() + milliseconds;
    while clock::uptime_ms() < deadline {
        if done() {
            return true;
        }
        scheduler::tick(-1);
    }
    done()
}

pub fn run(assert: Assert) {
    ps_parent_silo(assert);
    ps_thread_notify_ex(assert);
    ps_wow64_apc(assert);
    nt_query_information_process(assert);
    ke_alert_thread(assert);
    ke_triage_dump_data(assert);
    kd_poll_break_in(assert);
    mm_nonpaged_address(assert);
    mm_mdl_maps(assert);
    mm_physical_remove_cache(assert);
}

// ---- Ps -------------------------------------------------------------------------

fn ps_parent_silo(assert: Assert) {
    let job = || {
        let address = guest::alloc_bytes(nt::Ejob::SIZE);
        guest::write_bytes(address, &alloc::vec![0; nt::Ejob::SIZE as usize]);
        address
    };
    let (outer, middle, inner, nested) = (job(), job(), job(), job());
    at::<nt::Ejob>(outer).set_silo(1);
    at::<nt::Ejob>(middle).parent_job.set(outer);
    at::<nt::Ejob>(inner).parent_job.set(middle);
    at::<nt::Ejob>(nested).set_silo(1);
    at::<nt::Ejob>(nested).parent_job.set(outer);
    let parent = |job: u64| call("PsGetParentSilo", &[job]);
    assert(parent(inner) == outer && parent(middle) == outer, "ps-parent-silo: o primeiro silo acima do job pai");
    assert(parent(nested) == outer && call("PsGetJobSilo", &[nested, guest::alloc_bytes(8)]) == 0, "ps-parent-silo: um silo devolve o silo pai, nao a si mesmo");
    assert(parent(outer) == 0 && parent(0) == 0, "ps-parent-silo: sem pai ou job nulo e o hospedeiro (NULL)");
    for address in [outer, middle, inner, nested] {
        guest::free_bytes(address);
    }
}

/// (rotina, ThreadId, Create) de cada chamada das rotinas de teste.
static NOTIFY_LOG: SpinLock<Vec<(u8, u64, u8)>> = SpinLock::new(Vec::new());

fn record_notify(kind: u8, thread: u64, create: u8) {
    let mut log = NOTIFY_LOG.lock();
    if log.len() < 512 {
        log.push((kind, thread, create));
    }
}

/// Rotina registrada como PsCreateThreadNotifyNonSystem.
extern "win64" fn non_system_notify(_process: u64, thread: u64, create: u8) {
    record_notify(1, thread, create);
}

/// Rotina registrada como PsCreateThreadNotifySubsystems.
extern "win64" fn subsystem_notify(_process: u64, thread: u64, create: u8) {
    record_notify(2, thread, create);
}

/// Thread de sistema que sai na hora.
extern "win64" fn notify_probe_thread(_context: u64) {}

fn ps_thread_notify_ex(assert: Assert) {
    let set = |notify_type: u64, routine: u64| status("PsSetCreateThreadNotifyRoutineEx", &[notify_type, routine]);
    let outside = super::executable_code::place(&[0xC3]);
    assert(set(2, outside) == 0xC000_000D, "ps-thread-notify-ex: tipo alem de PsCreateThreadNotifySubsystems = STATUS_INVALID_PARAMETER");
    assert(set(0, outside) == 0xC000_0022 && set(1, outside) == 0xC000_0022 && set(0, 0x7FF6_0000_1000) == 0xC000_0022, "ps-thread-notify-ex: rotina fora de imagem com integridade forcada = STATUS_ACCESS_DENIED");
    let non_system = non_system_notify as *const () as u64;
    let subsystem = subsystem_notify as *const () as u64;
    let Some(kernel) = loaded_images::find(non_system) else {
        assert(false, "ps-thread-notify-ex: imagem do kernel registrada");
        return;
    };
    let forced = kernel.loader_flags & 0x20 != 0;
    if !forced {
        assert(set(0, non_system) == 0xC000_0022, "ps-thread-notify-ex: imagem sem LDRP_IMAGE_INTEGRITY_FORCED recusada");
        loaded_images::update_flags(kernel.id, 0x20, 0);
    }
    NOTIFY_LOG.lock().clear();
    let first = set(0, non_system);
    let second = set(1, subsystem);
    if !forced {
        loaded_images::update_flags(kernel.id, 0, 0x20);
    }
    assert(first == 0 && second == 0 && thread_notify::registered_flags(non_system) == Some(1) && thread_notify::registered_flags(subsystem) == Some(2), "ps-thread-notify-ex: tipos 0 e 1 registram com as flags 1 e 2");
    // Uma thread de sistema não tem código de usuário: a rotina de código
    // não de sistema só a vê sair; a de subsistemas vê criação e saída.
    let handle = kernel_threads::create_system_thread(0, notify_probe_thread as *const () as u64, 0, 0x1F_FFFF, 0, None).unwrap_or(0);
    let thread = kernel_threads::of_handle(handle).unwrap_or(0);
    let id = if thread != 0 { at::<nt::Ethread>(thread).cid.unique_thread.get() } else { 0 };
    let seen = |entry: (u8, u64, u8)| NOTIFY_LOG.lock().iter().any(|&logged| logged == entry);
    let exited = thread != 0 && pump(10_000, &|| seen((1, id, 0)) && seen((2, id, 0)));
    let removed = status("PsRemoveCreateThreadNotifyRoutine", &[non_system]) == 0 && status("PsRemoveCreateThreadNotifyRoutine", &[subsystem]) == 0;
    assert(exited && seen((2, id, 1)) && !seen((1, id, 1)), "ps-thread-notify-ex: thread de sistema chama a rotina de subsistemas na criacao e as duas na saida");
    assert(removed && thread_notify::registered_flags(non_system).is_none() && thread_notify::registered_flags(subsystem).is_none(), "ps-thread-notify-ex: PsRemoveCreateThreadNotifyRoutine tira os registros Ex");
    if handle != 0 {
        let _ = call("ZwClose", &[handle]);
    }
    super::executable_code::release(outside);
}

fn ps_wow64_apc(assert: Assert) {
    let routine = guest::alloc_bytes(8);
    let wrap = |value: u64| {
        guest::write64(routine, value);
        (status("PsWrapApcWow64Thread", &[0, routine]), guest::read64(routine))
    };
    assert(wrap(0x7FF6_1234_5670) == (0, 0x7FF6_1234_5670), "ps-wow64-apc: processo sem WOW64 nao muda a rotina");
    // O processo do ApcState da thread corrente vira WOW64 por um instante.
    let system = at::<nt::Ethread>(process::get_current_thread()).tcb.apc_state.process.get();
    let eprocess = at::<nt::Eprocess>(system);
    let saved = eprocess.wo_w64_process.get();
    let wow64 = guest::alloc_bytes(nt::Ewow64process::SIZE);
    guest::write_bytes(wow64, &[0; 0x10]);
    let mut results = [(0, 0); 3];
    for (slot, machine) in results.iter_mut().zip([0x14Cu16, 0x1C4, 0x8664]) {
        at::<nt::Ewow64process>(wow64).machine.set(machine);
        eprocess.wo_w64_process.set(wow64);
        *slot = wrap(0x7FF6_1234_5670);
        eprocess.wo_w64_process.set(saved);
    }
    assert(results[0] == (0, 0xFFFE_0027_B72E_A640) && results[1] == (0, 0xFFFE_0027_B72E_A640), "ps-wow64-apc: x86 e ARM32 viram -(rotina) << 2");
    assert(results[2] == (0, 0x7FF6_1234_5670), "ps-wow64-apc: outra maquina WOW64 nao muda a rotina");
    guest::free_bytes(wow64);
    guest::free_bytes(routine);
}

fn nt_query_information_process(assert: Assert) {
    let block = guest::alloc_bytes(0x100);
    guest::write_bytes(block, &[0xCC; 0x100]);
    let (nt_buffer, zw_buffer, returned) = (block, block + 0x40, block + 0x80);
    let current = u64::MAX;
    let nt = status("NtQueryInformationProcess", &[current, 0, nt_buffer, 0x30, returned]);
    let nt_returned = guest::read32(returned);
    let zw = status("ZwQueryInformationProcess", &[current, 0, zw_buffer, 0x30, 0]);
    let pid = at::<nt::Ethread>(process::get_current_thread()).cid.unique_process.get();
    assert(nt == 0 && zw == 0 && nt_returned == 0x30 && guest::read_bytes(nt_buffer, 0x30) == guest::read_bytes(zw_buffer, 0x30) && at::<nt::ProcessBasicInformation>(nt_buffer).unique_process_id.get() == pid, "nt-query-process: em KernelMode e o servico do ZwQueryInformationProcess");
    // A forma estendida de 0x40 bytes que o RunGPU do BasicRender pede:
    // Size, a básica do EPROCESS (o preenchimento intocado) e os Flags; um
    // comprimento que não é 0x30 nem 0x40 dá STATUS_INFO_LENGTH_MISMATCH sem
    // ReturnLength.
    guest::write_bytes(zw_buffer, &[0xCC; 0x40]);
    guest::write32(returned, 0);
    let extended = status("ZwQueryInformationProcess", &[current, 0, zw_buffer, 0x40, returned]);
    let information = at::<nt::ProcessExtendedBasicInformation>(zw_buffer);
    // SAFETY: o EPROCESS corrente.
    let eprocess = unsafe { nt::Eprocess::at(process::get_current_process()) };
    let fields = information.size.get() == 0x40 && information.basic_info.exit_status.get() == eprocess.exit_status.get() && information.basic_info.peb_base_address.get() == eprocess.peb.get() && information.basic_info.base_priority.get() == eprocess.pcb.base_priority.get() as i32 && information.basic_info.unique_process_id.get() == pid && information.basic_info.inherited_from_unique_process_id.get() == eprocess.inherited_from_unique_process_id.get() && guest::read32(zw_buffer + 0xC) == 0xCCCC_CCCC;
    let flags = information.flags.get() == crate::ntos::ps::query_process::basic_information(process::get_current_process()).flags && information.flags.get() & 0x106 == 0 && guest::read32(zw_buffer + 0x3C) == 0xCCCC_CCCC;
    let extended_returned = guest::read32(returned);
    let mismatch = status("ZwQueryInformationProcess", &[current, 0, zw_buffer, 0x38, returned]);
    assert(extended == 0 && fields && flags && extended_returned == 0x40 && mismatch == 0xC000_0004 && guest::read32(returned) == 0x40, "nt-query-process: PROCESS_EXTENDED_BASIC_INFORMATION em KernelMode (Size, campos do EPROCESS, Flags) e comprimento invalido");
    // UserMode: o prólogo sonda os parâmetros antes da classe.
    let field = &at::<nt::Ethread>(process::get_current_thread()).tcb.previous_mode;
    let saved = field.get();
    field.set(1);
    let misaligned = status("NtQueryInformationProcess", &[current, 0, 0x1000_0001, 0x30, 0]);
    let kernel_buffer = status("NtQueryInformationProcess", &[current, 0, nt_buffer, 0x30, 0]);
    let byte_class = status("NtQueryInformationProcess", &[current, 61, 0x1000_0001, 0x30, returned]);
    let kernel_handle = status("NtQueryInformationProcess", &[0xFFFF_FFFF_8000_0004, 0, 0, 0, 0]);
    field.set(saved);
    assert(misaligned == 0x8000_0002, "nt-query-process: UserMode com buffer desalinhado = STATUS_DATATYPE_MISALIGNMENT");
    assert(kernel_buffer == 0xC000_0005 && byte_class == 0xC000_0005, "nt-query-process: UserMode com buffer ou ReturnLength de kernel = STATUS_ACCESS_VIOLATION (classe 61 sem alinhamento)");
    assert(kernel_handle == 0xC000_0008, "nt-query-process: UserMode com handle de kernel = STATUS_INVALID_HANDLE");
    guest::free_bytes(block);
}

// ---- Ke e Kd ----------------------------------------------------------------------

/// Thread de sistema numa espera alertável de KernelMode pelo evento do
/// bloco; grava o status da espera em +0x20.
extern "win64" fn alertable_waiter(block: u64) {
    let result = super::phase6::call_export("KeWaitForSingleObject", &[block, 0, 0, 1, 0]).unwrap_or(u64::MAX);
    guest::write64(block + 0x20, result);
}

fn ke_alert_thread(assert: Assert) {
    // KTHREAD que não espera: o alerta fica pendente em Alerted[modo].
    let thread = guest::alloc_bytes(nt::Kthread::SIZE);
    guest::write_bytes(thread, &alloc::vec![0; nt::Kthread::SIZE as usize]);
    let kernel = (call("KeAlertThread", &[thread, 0]) as u8, call("KeAlertThread", &[thread, 0]) as u8);
    let user = call("KeAlertThread", &[thread, 1]) as u8;
    let target = at::<nt::Kthread>(thread);
    assert(kernel == (0, 1) && user == 0 && target.alerted[0].get() == 1 && target.alerted[1].get() == 1, "ke-alert-thread: sem espera alertavel o alerta fica em Alerted e devolve o anterior");
    guest::free_bytes(thread);
    // Thread numa espera alertável de KernelMode: sai com STATUS_ALERTED.
    let block = guest::alloc_bytes(0x40);
    guest::write_bytes(block, &[0; 0x40]);
    guest::write64(block + 0x20, 0xFFFF);
    call("KeInitializeEvent", &[block, 0, 0]);
    let handle = kernel_threads::create_system_thread(0, alertable_waiter as *const () as u64, block, 0x1F_FFFF, 0, None).unwrap_or(0);
    let waiter = kernel_threads::of_handle(handle).unwrap_or(0);
    let waiting = waiter != 0 && pump(10_000, &|| at::<nt::Kthread>(waiter).state.get() == 5);
    let previous = if waiting { call("KeAlertThread", &[waiter, 0]) as u8 } else { 0xFF };
    let woke = waiting && pump(10_000, &|| guest::read64(block + 0x20) != 0xFFFF);
    assert(waiting && previous == 0 && woke && guest::read64(block + 0x20) as u32 == 0x101 && at::<nt::Kthread>(waiter).alerted[0].get() == 0, "ke-alert-thread: a espera alertavel sai com STATUS_ALERTED sem deixar alerta pendente");
    if !woke {
        call("KeSetEvent", &[block, 0, 0]);
        pump(10_000, &|| guest::read64(block + 0x20) != 0xFFFF);
    }
    if handle != 0 {
        let _ = call("ZwClose", &[handle]);
    }
    if kernel_threads::is_terminated(waiter) {
        guest::free_bytes(block);
    }
}

fn ke_triage_dump_data(assert: Assert) {
    let array = guest::alloc_bytes(0x100);
    let data = guest::alloc_bytes(0x200);
    guest::write_bytes(array, &[0xAA; 0x100]);
    let initialize = |size: u64| status("KeInitializeTriageDumpDataArray", &[array, size]);
    let header = at::<KtriageDumpDataArray>(array);
    assert(status("KeInitializeTriageDumpDataArray", &[0, 0x40]) == 0xC000_000D && initialize(0x3F) == 0xC000_0023, "ke-triage: vetor nulo e menor que 0x40 recusados");
    assert(initialize(0x60) == 0 && header.list.flink.get() == array && header.list.blink.get() == array && header.num_blocks_total.get() == 3 && header.num_blocks_used.get() == 0 && header.data_size.get() == 0 && header.max_data_size.get() == 0x200_0000 && header.component_name_buffer_length.get() == 0 && header.component_name.get() == 0, "ke-triage: (0x60 - 0x30) / 16 blocos, lista vazia e 32 MiB de limite");
    let add = |address: u64, size: u64| status("KeAddTriageDumpDataBlock", &[array, address, size]);
    let blocks = || -> Vec<(u64, u64)> { (0..header.num_blocks_used.get() as u64).map(|index| (guest::read64(array + 0x30 + index * 16).wrapping_sub(data), guest::read64(array + 0x38 + index * 16))).collect() };
    assert(add(0x1000, 0x10) == 0xC000_000D && status("KeAddTriageDumpDataBlock", &[0, data, 0x10]) == 0xC000_000D && add(data, 0) == 0 && blocks().is_empty(), "ke-triage: faixa nos primeiros 64 KiB e vetor nulo recusados; bloco vazio aceito sem mudar nada");
    let first = add(data, 0x40);
    let contained = add(data + 0x10, 0x20);
    let trimmed = add(data + 0x20, 0x40);
    let third = add(data + 0x80, 0x20);
    let full = add(data + 0xC0, 0x10);
    assert(first == 0 && contained == 0 && trimmed == 0 && third == 0 && full == 0xC000_0023 && blocks() == [(0, 0x40), (0x40, 0x20), (0x80, 0x20)] && header.data_size.get() == 0x80, "ke-triage: faixa contida ignorada, sobreposta aparada pelo inicio e vetor cheio = STATUS_BUFFER_TOO_SMALL");
    assert(initialize(0x70) == 0 && add(data + 0x40, 0x20) == 0 && add(data + 0x30, 0x20) == 0 && add(data, 0x100) == 0 && blocks() == [(0x40, 0x20), (0x30, 0x10), (0, 0x100)] && header.data_size.get() == 0x130, "ke-triage: sobreposta pelo fim aparada; faixa que cobre um bloco entra inteira");
    initialize(0x50);
    header.max_data_size.set(0x10);
    assert(add(data, 0x20) == 0xC000_009A && add(data, 0x10) == 0 && blocks() == [(0, 0x10)], "ke-triage: alem do MaxDataSize = STATUS_INSUFFICIENT_RESOURCES");
    initialize(0x50);
    header.list.flink.set(data);
    let broken_list = add(data, 0x10);
    initialize(0x50);
    header.data_size.set(4);
    assert(broken_list == 0xC000_000D && add(data, 0x10) == 0xC000_000D, "ke-triage: lista corrompida ou DataSize sem os blocos invalidam o vetor");
    guest::free_bytes(data);
    guest::free_bytes(array);
}

fn kd_poll_break_in(assert: Assert) {
    // A suíte não liga o depurador (KdPitchDebugger): nunca há pedido.
    assert(call("KdPollBreakIn", &[]) & 0xFF == 0 && crate::ntos::kd::debugger::pitched(), "kd-poll-break-in: sem depurador no boot e FALSE");
}

// ---- Mm -----------------------------------------------------------------------------

fn mm_nonpaged_address(assert: Assert) {
    let valid = |address: u64| call("MmIsNonPagedSystemAddressValid", &[address]) & 0xFF != 0;
    let paged = call("ExAllocatePoolWithTag", &[1, 0x40, 0x3257_514B]);
    let nonpaged = call("ExAllocatePoolWithTag", &[0x200, 0x40, 0x3257_514B]);
    let kernel_code = mm_nonpaged_address as *const () as u64;
    assert(paged != 0 && nonpaged != 0 && !valid(paged) && valid(nonpaged), "mm-nonpaged-address: pool paginado FALSE, nao paginado TRUE");
    assert(!valid(crate::ntos::mm::memory_map::SESSION_SPACE_BASE + 0x1000) && valid(kernel_code) && valid(0x1_0000), "mm-nonpaged-address: espaco de sessao FALSE; imagem do kernel e VA de usuario (MiVaUnused) TRUE");
    call("ExFreePoolWithTag", &[paged, 0x3257_514B]);
    call("ExFreePoolWithTag", &[nonpaged, 0x3257_514B]);
}

static MAP_MDL_CONTEXT: AtomicU64 = AtomicU64::new(0);

/// MM_MDL_ROUTINE(DriverContext, MappedVa): grava a VA, os dois primeiros
/// quadwords das páginas e as permissões; com escrita pedida, grava 0xABCD
/// em MappedVa + 8.
extern "win64" fn map_mdl_routine(context: u64, mapped: u64) {
    MAP_MDL_CONTEXT.store(context, Ordering::SeqCst);
    guest::write64(context, mapped);
    if guest::read64(context + 0x28) == 1 {
        guest::write64(context + 0x08, guest::read64(mapped));
        guest::write64(context + 0x10, guest::read64(mapped + 0x1000));
        guest::write64(context + 0x18, paging::access_flags(mapped));
        guest::write64(context + 0x20, paging::translate(mapped));
        if guest::read64(context + 0x30) == 1 {
            guest::write64(mapped + 8, 0xABCD);
        }
    }
}

fn mdl_frame(descriptor: u64, index: u64) -> u64 {
    guest::read64(descriptor + nt::Mdl::SIZE + index * 8) * 0x1000
}

fn mm_mdl_maps(assert: Assert) {
    let context = guest::alloc_bytes(0x40);
    guest::write_bytes(context, &[0; 0x40]);
    let routine = map_mdl_routine as *const () as u64;
    let pages = call("MmAllocatePagesForMdl", &[0, u64::MAX, 0, 0x2000]);
    if pages == 0 || pages == 0xDEAD_DEAD_DEAD_DEAD {
        assert(false, "mm-mdl-maps: MDL de duas paginas");
        return;
    }
    let (frame0, frame1) = (mdl_frame(pages, 0), mdl_frame(pages, 1));
    physical::write64(frame0, 0x1122_3344_5566_7788);
    physical::write64(frame0 + 8, 0);
    physical::write64(frame1, 0x99AA_BBCC_DDEE_FF00);
    // Proteções recusadas não chamam a rotina.
    let rejected = [0x1u32, 0x8, 0x10, 0x20, 0x40, 0x104, 0x200, 0x401].iter().all(|&protection| {
        MAP_MDL_CONTEXT.store(0, Ordering::SeqCst);
        status("MmMapMdl", &[pages, protection as u64, routine, context]) == 0xC000_0045 && MAP_MDL_CONTEXT.load(Ordering::SeqCst) == 0
    });
    assert(rejected, "mm-mdl-maps: MmMapMdl com NOACCESS, WRITECOPY, execucao, GUARD ou sem acesso = STATUS_INVALID_PAGE_PROTECTION");
    // PAGE_READWRITE: PTEs novos sobre as páginas do MDL, desfeitos na volta.
    guest::write64(context + 0x28, 1);
    guest::write64(context + 0x30, 1);
    let written = status("MmMapMdl", &[pages, 0x04, routine, context]);
    let va = guest::read64(context);
    assert(written == 0 && va != 0 && guest::read64(context + 0x08) == 0x1122_3344_5566_7788 && guest::read64(context + 0x10) == 0x99AA_BBCC_DDEE_FF00 && guest::read64(context + 0x18) & paging::PAGE_RW != 0 && guest::read64(context + 0x20) == frame0 && physical::read64(frame0 + 8) == 0xABCD, "mm-mdl-maps: MmMapMdl de leitura e escrita entrega as paginas do MDL a rotina");
    assert(paging::translate(va) != frame0 && at::<nt::Mdl>(pages).mdl_flags.get() & 1 == 0, "mm-mdl-maps: o mapeamento sai na volta e o MDL continua sem MappedSystemVa");
    guest::write64(context + 0x30, 0);
    let read_only = status("MmMapMdl", &[pages, 0x02, routine, context]);
    assert(read_only == 0 && guest::read64(context + 0x18) & paging::PAGE_RW == 0 && guest::read64(context + 0x08) == 0x1122_3344_5566_7788, "mm-mdl-maps: PAGE_READONLY mapeia sem escrita");
    // MDL de pool não paginado: a rotina recebe o MappedSystemVa.
    let pool = guest::alloc_bytes(nt::Mdl::SIZE + 8);
    guest::write_bytes(pool, &[0; 0x38]);
    at::<nt::Mdl>(pool).mdl_flags.set(4);
    at::<nt::Mdl>(pool).mapped_system_va.set(0xFFFF_8000_1234_0010);
    guest::write64(context + 0x28, 0);
    assert(status("MmMapMdl", &[pool, 0x204, routine, context]) == 0 && guest::read64(context) == 0xFFFF_8000_1234_0010, "mm-mdl-maps: MDL ja mapeado ou de pool chama a rotina com MappedSystemVa");
    guest::free_bytes(pool);

    // MmMapMemoryDumpMdlEx numa faixa de MmAllocateMappingAddress.
    let tag = 0x3257_514B;
    let window = call("MmAllocateMappingAddress", &[0x2000, tag]);
    assert(status("MmMapMemoryDumpMdlEx", &[window, 2, pages, 1]) == 0xC000_00F2, "mm-mdl-maps: MmMapMemoryDumpMdlEx so aceita MM_DUMP_MAP_INVALIDATE");
    let header = at::<nt::Mdl>(pages);
    let mapped = status("MmMapMemoryDumpMdlEx", &[window, 2, pages, 0]);
    let (view, flags_mapped) = (header.mapped_system_va.get(), header.mdl_flags.get());
    let contents = (guest::read64(window), guest::read64(window + 0x1000));
    assert(window != 0 && mapped == 0 && view == window && flags_mapped & 0x11 == 0x11 && paging::translate(window) == frame0 && paging::translate(window + 0x1000) == frame1 && contents == (0x1122_3344_5566_7788, 0x99AA_BBCC_DDEE_FF00), "mm-mdl-maps: MmMapMemoryDumpMdlEx mapeia as paginas do MDL no Va e liga MAPPED|PARTIAL");
    let invalidated = status("MmMapMemoryDumpMdlEx", &[window, 2, pages, 2]);
    assert(invalidated == 0 && header.mdl_flags.get() & 0x21 == 0 && paging::access_flags(window) & paging::PAGE_PRESENT == 0, "mm-mdl-maps: MM_DUMP_MAP_INVALIDATE zera os PTEs e desliga MAPPED");
    call("MmFreeMappingAddress", &[window, tag]);

    // MmFreePagesFromMdlEx: zera (o passo da lógica), desfaz o mapeamento e devolve.
    crate::ntos::mm::mdl::zero_pages(pages);
    assert(physical::read64(frame0) == 0 && physical::read64(frame1) == 0, "mm-mdl-maps: MM_FREE_MDL_PAGES_ZERO zera as paginas do MDL");
    header.mdl_flags.set(header.mdl_flags.get() | 1);
    assert(call("MmFreePagesFromMdlEx", &[pages, 1]) == 0 && header.mdl_flags.get() & 1 == 0, "mm-mdl-maps: MmFreePagesFromMdlEx desfaz o mapeamento de sistema e devolve as paginas");
    guest::free_bytes(pages);
    guest::free_bytes(context);
}

fn mm_physical_remove_cache(assert: Assert) {
    let cells = guest::alloc_bytes(16);
    let remove = |start: u64, bytes: u64| {
        guest::write64(cells, start);
        guest::write64(cells + 8, bytes);
        (status("MmRemovePhysicalMemory", &[cells, cells + 8]), guest::read64(cells + 8))
    };
    assert(remove(0x10_0000, 0) == (0xC000_00EF, 0) && remove(0x10_0000, 0xFFF) == (0xC000_00EF, 0xFFF) && remove(0x10_0001, 0) == (0xC000_00EF, 0), "mm-remove-physical: faixa vazia = STATUS_INVALID_PARAMETER_1");
    assert(remove(0x10_0001, 0x1000) == (0xC000_0002, 0x1000), "mm-remove-physical: paginas ruins sem a lista de paginas ruins = STATUS_NOT_IMPLEMENTED");
    assert(remove(0x10_0000, 0x1000) == (0xC000_0017, 0x1000), "mm-remove-physical: RAM que nao pode ser tomada = STATUS_NO_MEMORY e NumberOfBytes intacto");
    guest::free_bytes(cells);
    let permanent = |start: u64, bytes: u64, cache: u64, flags: u64| status("MmSetPermanentCacheAttribute", &[start, bytes, cache, flags]);
    let base = 0xFEBF_0000u64;
    assert(permanent(base, 0x1000, 1, 2) == 0xC000_00F2 && permanent(base + 1, 0x1000, 1, 0) == 0xC000_00EF && permanent(base, 0x1001, 1, 0) == 0xC000_00F0 && permanent(base, 0, 1, 0) == 0xC000_00F0 && permanent(base, 0x1000, 0, 1) == 0xC000_00F1 && permanent(base, 0x1000, 2, 0) == 0xC000_00F1, "mm-permanent-cache: Flags, inicio, tamanho e tipo de cache validados nessa ordem");
    let apc = crate::ntos::ke::irql::raise_irql(1);
    let raised = permanent(base, 0x1000, 1, 0);
    crate::ntos::ke::irql::lower_irql(apc as u64);
    assert(raised == 0xC000_000D, "mm-permanent-cache: em APC_LEVEL = STATUS_INVALID_PARAMETER");
    assert(permanent(base, 0x2000, 1, 0) == 0 && permanent(base + 0x1000, 0x1000, 1, 1) == 0xC000_0018 && permanent(base + 0x2000, 0x1000, 1, 0) == 0, "mm-permanent-cache: faixa sobreposta a uma permanente = STATUS_CONFLICTING_ADDRESSES; a vizinha entra");
}
