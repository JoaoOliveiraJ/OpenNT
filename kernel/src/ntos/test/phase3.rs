//! Autotestes da fase 3 — Ke (dispatcher, APC, timers, alertas), Ex (push
//! lock, rundown), Ob (handle table, tabela por processo), Ps e Se.
//!
//! As rotinas nativas são funções `extern "win64"` chamadas pelo gateway
//! MS-ABI, e as chamadas de export são chamadas diretas à API.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::ex::{push_lock, rundown};
use crate::ntos::ke::{apc, clock, critical_region, dispatcher, dpc, irql, thread_alert, timer};
use crate::ntos::ob::handle_table::{self, HandleDescription};
use crate::ntos::ob::object_types;
use crate::ntos::ob::handles::process as process_handles;
use crate::ntos::ps::process;
use crate::ntos::se::token::tokens;
use crate::rtl::SpinLock;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{eprocess, kthread};

type Assert = fn(bool, &str);

fn dispatcher_objects(assert: Assert) {
    let first = guest::alloc_bytes(0x40);
    let second = guest::alloc_bytes(0x40);
    let vector = guest::alloc_bytes(16);
    let timeout = guest::alloc_bytes(8);
    guest::write64(vector, first);
    guest::write64(vector + 8, second);
    guest::write64(timeout, 0);
    dispatcher::initialize_event(first, 1, false);
    dispatcher::initialize_event(second, 0, true);
    assert(guest::read64(first + 8) == first + 8 && guest::read64(first + 16) == first + 8, "dispatcher: links canonicos do evento");
    assert(dispatcher::read_state(first) == 0, "dispatcher: estado inicial BOOLEAN");
    assert(dispatcher::wait_for_multiple_objects(2, vector, 1, timeout, 0, false) == 1, "dispatcher: WaitAny devolve o indice");
    assert(dispatcher::read_state(second) == 1, "dispatcher: notificacao conserva o sinal");
    assert(dispatcher::set_event(first) == 0, "dispatcher: estado anterior do evento");
    assert(dispatcher::wait_for_multiple_objects(2, vector, 0, timeout, 0, false) == 0, "dispatcher: WaitAll");
    assert(dispatcher::read_state(first) == 0, "dispatcher: sincronizacao consumida");
    assert(dispatcher::reset_event(second) == 1, "dispatcher: reset");
    assert(dispatcher::wait_for_single_object(second, timeout, 0, false) == 0x102, "dispatcher: timeout canonico");
    dispatcher::set_event(first);
    dispatcher::clear_event(first);
    assert(dispatcher::read_state(first) == 0, "dispatcher: clear");
    dispatcher::initialize_mutex(first, 0);
    assert(dispatcher::wait_for_single_object(first, timeout, 0, false) == 0, "dispatcher: mutex");
    assert(dispatcher::wait_for_single_object(first, timeout, 0, false) == 0, "dispatcher: mutex recursivo");
    dispatcher::release_mutex(first);
    dispatcher::release_mutex(first);
    assert(guest::read32(first + 4) == 1 && guest::read64(first + 0x28) == 0, "dispatcher: mutex liberado por completo");
    assert(dispatcher::release_mutant(first, false) == Err(0xC000_0046), "dispatcher: liberar sem posse");
    dispatcher::initialize_semaphore(second, 1, 2);
    assert(dispatcher::release_semaphore(second, 1) == Ok(1), "dispatcher: semaforo libera");
    assert(dispatcher::release_semaphore(second, 1) == Err(0xC000_0047), "dispatcher: limite do semaforo");
    assert(dispatcher::wait_for_single_object(second, timeout, 0, false) == 0, "dispatcher: semaforo consome");
    for pointer in [first, second, vector, timeout] {
        guest::free_bytes(pointer);
    }
}

// Rotinas "nativas" das APCs.
extern "win64" fn special_routine(_apc: u64, _normal: u64, _context: u64, first: u64, _second: u64) {
    let state = guest::read64(first);
    guest::write32(state + 4, irql::get_irql() as u32);
    guest::write32(state, guest::read32(state) + 1);
}

extern "win64" fn kernel_routine(apc: u64, _normal: u64, context: u64, _first: u64, _second: u64) {
    let state = guest::read64(context);
    guest::write32(state + 8, irql::get_irql() as u32);
    guest::free_bytes(apc);
    guest::write32(state + 12, 1);
    // Modifica a cópia independente de NormalContext.
    guest::write64(context, state + 16);
}

extern "win64" fn normal_routine(context: u64, first: u64, second: u64) {
    guest::write64(context + 8, first);
    guest::write64(context + 16, second);
    guest::write32(context + 4, irql::get_irql() as u32);
    guest::write32(context, guest::read32(context) + 1);
}

fn apc_regions(assert: Assert) {
    let thread = process::get_current_thread();
    let state = guest::alloc_bytes(40);
    let special = guest::alloc_bytes(0x58);
    let normal = guest::alloc_bytes(0x58);
    assert(state != 0 && special != 0 && normal != 0, "apc: alocacoes");
    assert(guest::read32(thread + kthread::KERNEL_APC_DISABLE) == 0, "apc: regioes iniciais");
    let entered = critical_region::enter_critical().and_then(|_| critical_region::enter_critical()).and_then(|_| critical_region::enter_guarded());
    assert(entered.is_ok(), "apc: entra nas regioes");
    assert(guest::read16(thread + kthread::KERNEL_APC_DISABLE) == 0xFFFE && guest::read16(thread + kthread::SPECIAL_APC_DISABLE) == 0xFFFF, "apc: contadores SHORT da KTHREAD");
    assert(critical_region::disabled() && critical_region::all_disabled(), "apc: estado guardado");
    let address = |routine: u64| routine;
    apc::initialize(normal, thread, 0, address(kernel_routine as extern "win64" fn(u64, u64, u64, u64, u64) as usize as u64), 0, address(normal_routine as extern "win64" fn(u64, u64, u64) as usize as u64), 0, state);
    apc::initialize(special, thread, 0, address(special_routine as extern "win64" fn(u64, u64, u64, u64, u64) as usize as u64), 0, 0, 0, 0);
    assert(apc::insert(normal, 0xFEDC_BA98_7654_3210, 0x8000_0000_0000_0001), "apc: insercao normal");
    assert(apc::insert(special, state, 0), "apc: insercao especial");
    assert(apc::deliver_all_queued().is_ok() && guest::read32(state) == 0, "apc: regiao guardada retem a especial");
    assert(critical_region::leave_guarded().is_ok(), "apc: sai da regiao guardada");
    assert(guest::read32(state) == 1 && guest::read32(state + 4) == 1, "apc: especial roda em APC_LEVEL");
    assert(!critical_region::all_disabled() && critical_region::disabled(), "apc: regiao critica permite a especial");
    assert(critical_region::leave_critical().is_ok(), "apc: sai da regiao critica interna");
    assert(guest::read32(state + 16) == 0, "apc: regiao aninhada retem a normal");
    assert(critical_region::leave_critical().is_ok(), "apc: sai da regiao critica externa");
    assert(guest::read32(state + 8) == 1 && guest::read32(state + 12) == 1, "apc: IRQL da KernelRoutine e KAPC liberada");
    assert(guest::read32(state + 16) == 1 && guest::read32(state + 20) == 0, "apc: NormalRoutine em PASSIVE_LEVEL");
    assert(guest::read64(state + 24) == 0xFEDC_BA98_7654_3210 && guest::read64(state + 32) == 0x8000_0000_0000_0001, "apc: argumentos opacos");
    assert(guest::read32(thread + kthread::KERNEL_APC_DISABLE) == 0 && guest::read8(thread + kthread::APC_STATE + 0x28) & 1 == 0, "apc: estado restaurado");
    assert(critical_region::leave_critical().is_err(), "apc: saida sem entrada recusada");
    guest::free_bytes(special);
    guest::free_bytes(state);
}

fn handle_table_storage(assert: Assert) {
    let process = process::get_current_process();
    let thread = process::get_current_thread();
    let table = handle_table::create(process, process::get_current_process_id());
    assert(table.is_ok(), "handle table: criacao");
    let table = table.unwrap();
    let identities = [process, thread, process, thread];
    let handles = [4u64, 0x3FC, 0x404, 0x80004];
    for (index, &handle) in handles.iter().enumerate() {
        let description = HandleDescription {
            pointer: identities[index],
            type_name: alloc::string::String::from("Test"),
            identity: 0,
            native_body: 0,
            attributes: index as u32,
            access: 0x120080 + index as u32,
        };
        assert(handle_table::insert(table, handle, &description).is_ok(), "handle table: insercao");
    }
    let (leaves, free, links) = handle_table::storage(table).unwrap();
    assert(leaves == 513 && guest::read64(table + 8) & 3 == 2, "handle table: nivel dois real");
    assert(free == 513 * 255 - 4 && links == 513 * 512, "handle table: lista livre completa");
    // Travessia nativa: TableCode -> raiz -> diretórios -> folhas.
    let code = guest::read64(table + 8);
    let top = code & !3;
    for (index, &handle) in handles.iter().enumerate() {
        let leaf_index = handle / 1024;
        let directory = guest::read64(top + (leaf_index / 512) * 8);
        let leaf = guest::read64(directory + (leaf_index % 512) * 8);
        let entry = leaf + (handle & 1023) * 4;
        let low = guest::read64(entry);
        let body = ((((low as i64) >> 16) as u64) & !15) + 0x30;
        assert(body == identities[index] && low & 1 != 0, "handle table: identidade real do objeto");
        assert((low >> 17) & 7 == index as u64 && guest::read64(entry + 8) == 0x120080 + index as u64, "handle table: atributos e acesso");
    }
    assert(matches!(handle_table::change(table, 0x404, 5, 0x210031), Ok(true)), "handle table: mudanca de entrada");
    let row = handle_table::row(table, 0x404).unwrap();
    assert((guest::read64(row.entry) >> 17) & 7 == 5 && guest::read64(row.entry + 8) == 0x210031, "handle table: mudanca visivel");
    let before = guest::read16(thread + kthread::KERNEL_APC_DISABLE);
    let removed = handle_table::remove(table, 4);
    assert(matches!(&removed, Ok(Some(row)) if row.pointer == process), "handle table: remocao devolve a identidade");
    assert(guest::read16(thread + kthread::KERNEL_APC_DISABLE) == before, "handle table: regioes criticas restauradas");
    assert(handle_table::destroy(table).is_err(), "handle table: destruicao com handles vivos recusada");
    for handle in [0x3FC, 0x404, 0x80004] {
        let _ = handle_table::remove(table, handle);
    }
    assert(handle_table::destroy(table).is_ok(), "handle table: destruicao");
}

fn rundown_protection(assert: Assert) {
    let allocation = guest::alloc_bytes(0x400);
    let p = allocation + 0x40;
    for cache in [false, true] {
        let size = if cache { rundown::size_cache() } else { 8 };
        assert(size <= 0x380, "rundown: descritor cabe na area");
        guest::write64(p - 8, 0xA55A_1234_5678_9ABC);
        guest::write64(p + size, 0xFEDC_BA98_7654_3210);
        let initialized = if cache { rundown::initialize_cache(p, size as u32) } else { rundown::initialize(p) };
        assert(initialized.is_ok(), "rundown: inicializacao");
        let acquired = if cache { rundown::acquire_cache(p, 2) } else { rundown::acquire_ex(p, 2) };
        assert(matches!(acquired, Ok(true)), "rundown: aquisicao de duas referencias");
        let slot = if cache { guest::read64(p) } else { p };
        assert(guest::read64(slot) == 4, "rundown: contador de 64 bits");
        let request = rundown::begin(p, cache);
        assert(request.is_ok(), "rundown: inicio do encerramento");
        let mut request = request.unwrap();
        assert(guest::read64(slot) & 1 != 0, "rundown: bloco publicado");
        let block = guest::read64(slot) & !1;
        assert(block != 0 && guest::read64(block) == 2, "rundown: bloco guarda as referencias");
        let refused = if cache { rundown::acquire_cache(p, 1) } else { rundown::acquire(p) };
        assert(matches!(refused, Ok(false)), "rundown: recusa novas referencias");
        let released = if cache { rundown::release_cache(p, 1) } else { rundown::release(p) };
        assert(released.is_ok() && !request.poll() && guest::read64(block) == 1, "rundown: espera continua com uma referencia");
        let released = if cache { rundown::release_cache(p, 1) } else { rundown::release(p) };
        assert(released.is_ok() && request.poll(), "rundown: retoma apos a ultima liberacao");
        assert(guest::read64(slot) == 1, "rundown: marcador terminal");
        let finished = if cache {
            rundown::wait_cache(p).and_then(|_| rundown::completed_cache(p)).and_then(|_| rundown::reinitialize_cache(p))
        } else {
            rundown::wait(p).and_then(|_| rundown::completed(p)).and_then(|_| rundown::reinitialize(p))
        };
        assert(finished.is_ok(), "rundown: conclusao e reinicializacao");
        let reopened = if cache { rundown::acquire_cache(p, 1) } else { rundown::acquire(p) };
        assert(matches!(reopened, Ok(true)), "rundown: reinicializacao reabre referencias");
        let closed = if cache { rundown::release_cache(p, 1).and_then(|_| rundown::wait_cache(p)) } else { rundown::release(p).and_then(|_| rundown::wait(p)) };
        assert(closed.is_ok(), "rundown: espera final");
        assert(guest::read64(p - 8) == 0xA55A_1234_5678_9ABC && guest::read64(p + size) == 0xFEDC_BA98_7654_3210, "rundown: canarios do buffer");
    }
    let allocated = rundown::allocate_cache(0x200, 0x7465_7354);
    assert(matches!(allocated, Ok(pointer) if pointer != 0), "rundown: alocacao por CPU");
    let allocated = allocated.unwrap();
    assert(matches!(rundown::acquire_cache(allocated, 1), Ok(true)) && rundown::release_cache(allocated, 1).is_ok(), "rundown: referencia por CPU");
    assert(rundown::free_cache(allocated).is_ok(), "rundown: liberacao por CPU");
    assert(rundown::initialize_cache(p, 32).is_ok() && rundown::free_cache(p).is_err(), "rundown: buffer do chamador nao vai ao pool");
    guest::free_bytes(allocation);
}

fn push_locks(assert: Assert) {
    let lock = guest::alloc_bytes(16);
    push_lock::initialize(lock);
    assert(push_lock::acquire_exclusive(lock, 0).is_ok() && guest::read64(lock) == 1, "push lock: exclusivo");
    assert(matches!(push_lock::try_shared(lock, 0), Ok(false)), "push lock: compartilhado recusado");
    let request = push_lock::begin(lock, true, 0);
    assert(request.is_ok(), "push lock: inicio da espera");
    let mut request = request.unwrap();
    assert(matches!(request.poll(), Ok(None)), "push lock: aguardante enfileirado");
    let word = guest::read64(lock);
    assert(word & 3 == 3 && word & !15 != 0, "push lock: bloco de espera publicado");
    assert(push_lock::release_exclusive(lock, 0).is_ok(), "push lock: liberacao acorda");
    assert(matches!(request.poll(), Ok(Some(()))), "push lock: aguardante adquire");
    assert(guest::read64(lock) == 17, "push lock: um leitor");
    assert(push_lock::release_shared(lock, 0).is_ok() && guest::read64(lock) == 0, "push lock: livre");
    assert(push_lock::acquire_exclusive(lock, 0).is_ok(), "push lock: exclusivo de novo");
    push_lock::convert_exclusive_to_shared(lock);
    assert(guest::read64(lock) == 17 && push_lock::release_any(lock, 0).is_ok() && guest::read64(lock) == 0, "push lock: conversao e liberacao generica");
    assert(push_lock::acquire_exclusive(lock, 4).is_err(), "push lock: flags invalidas");
    guest::free_bytes(lock);
}

static TIMER_DPC: AtomicU64 = AtomicU64::new(0);

fn timer_dpc(_dpc: u64, context: u64, _first: u64, _second: u64) {
    TIMER_DPC.store(context, Ordering::SeqCst);
}

fn timers(assert: Assert) {
    let ktimer = guest::alloc_bytes(0x40);
    let kdpc = guest::alloc_bytes(0x40);
    timer::initialize_timer(ktimer, 8);
    dpc::initialize_kernel_dpc(kdpc, timer_dpc, 0x7171);
    assert(!timer::set_timer(ktimer, -100_000, kdpc, 0), "timer: primeira programacao");
    assert(dispatcher::read_state(ktimer) == 0, "timer: ainda nao venceu");
    let deadline = clock::uptime_ms() + 20;
    while clock::uptime_ms() < deadline {
        crate::hal::cpu::pause();
    }
    timer::check_timers();
    assert(dispatcher::read_state(ktimer) == 1, "timer: sinalizado no vencimento");
    let _ = dpc::run_queue();
    assert(TIMER_DPC.load(Ordering::SeqCst) == 0x7171, "timer: DPC executada");
    assert(timer::set_timer(ktimer, -10_000_000, 0, 0) == false && timer::cancel_timer(ktimer), "timer: cancelamento");
    // Espera relativa de 1 ms pelo caminho cooperativo.
    let interval = guest::alloc_bytes(8);
    guest::write64(interval, (-10_000i64) as u64);
    assert(matches!(timer::delay_execution_thread(interval, 0, false), Ok(0)), "timer: KeDelayExecutionThread");
    for pointer in [ktimer, kdpc, interval] {
        guest::free_bytes(pointer);
    }
}

fn thread_alerts(assert: Assert) {
    let thread = process::get_current_thread();
    assert(matches!(thread_alert::alert(thread, 0), Ok(0)), "alerta: primeiro alerta");
    assert(guest::read8(thread + kthread::ALERTED) == 1, "alerta: byte de kernel");
    assert(matches!(thread_alert::alert(thread, 0), Ok(1)), "alerta: repetido nao conta");
    let event = guest::alloc_bytes(0x18);
    dispatcher::initialize_event(event, 0, false);
    assert(dispatcher::wait_for_single_object(event, 0, 0, true) == thread_alert::STATUS_ALERTED, "alerta: espera alertavel interrompida");
    assert(thread_alert::consume(thread, 0, true).is_none(), "alerta: consumido uma vez");
    assert(guest::read8(thread + kthread::STATE) == 2, "alerta: thread volta a executar");
    guest::free_bytes(event);
}

static PUBLISHED: SpinLock<Option<process_handles::Binding>> = SpinLock::new(None);

fn close_published(_process: u64, _handle: u32) {
    if let Some(binding) = PUBLISHED.lock().take() {
        let _ = process_handles::remove(&binding, None);
    }
}

fn processes(assert: Assert) {
    let system = process::get_system_process();
    assert(system != 0 && guest::read64(system + eprocess::UNIQUE_PROCESS_ID) == 4, "ps: EPROCESS do System");
    assert(process::get_primary_token(system).is_some_and(tokens::exists), "ps: token primario do System");
    assert(process::list_active_processes().iter().any(|entry| entry.pid == 4 && entry.name == "System"), "ps: PsActiveProcessHead");
    let objects_before = object_types::counts("Process").map(|counts| counts.0);
    let created = process::create_process(0x7A38, "phase3-test.exe", 0, None);
    assert(created.is_ok(), "ps: criacao de processo");
    let target = created.unwrap();
    let thread = process::create_kernel_thread(target, 0x7A3C, false, 0, None);
    assert(thread.is_ok(), "ps: criacao de thread");
    let thread = thread.unwrap();
    assert(guest::read64(thread + kthread::APC_STATE_PROCESS) == target && guest::read64(thread + kthread::CID_UNIQUE_PROCESS) == 0x7A38, "ps: KTHREAD ligado ao processo");
    let token = process::get_primary_token(target);
    assert(token.is_some_and(|token| token != process::get_primary_token(system).unwrap()), "ps: token proprio herdado");
    assert(guest::read64(target + eprocess::TOKEN) == token.unwrap(), "ps: EPROCESS.Token");
    let table = process_handles::get(target);
    assert(table.is_some_and(|table| guest::read64(target + eprocess::OBJECT_TABLE) == table), "ps: ObjectTable publicado");
    assert(process::list_active_processes().iter().any(|entry| entry.pid == 0x7A38 && entry.name == "phase3-test.exe" && entry.threads.contains(&thread)), "ps: processo e thread enumerados");
    // Handle publicado na tabela do processo e fechado pelo dono na saída.
    let description = HandleDescription { pointer: target, type_name: alloc::string::String::from("Process"), identity: target, native_body: 0, attributes: 0, access: 0x1F_FFFF };
    let binding = process_handles::publish(target, 4, &description, close_published, None);
    assert(binding.is_ok(), "ps: handle publicado");
    *PUBLISHED.lock() = binding.ok();
    assert(process::reference(target) == Some(1), "ps: referencia de driver");
    assert(process::terminate_process(target, 0x1234).is_ok(), "ps: terminacao");
    assert(guest::read32(target + eprocess::EXIT_STATUS) == 0x1234 && guest::read32(target + eprocess::FLAGS) & eprocess::PROCESS_EXITING_FLAG != 0, "ps: status e flag de saida");
    assert(PUBLISHED.lock().is_none() && process_handles::get(target).is_none(), "ps: handles fechados pelo dono");
    assert(process::is_process(target), "ps: referencia retem o EPROCESS");
    assert(!process::list_active_processes().iter().any(|entry| entry.pid == 0x7A38), "ps: fora da lista ativa");
    assert(process::release_thread(thread).is_ok() && !process::is_thread(thread), "ps: thread recolhida");
    assert(matches!(process::dereference(target), Ok(Some(0))) && !process::is_process(target), "ps: EPROCESS recolhido");
    assert(object_types::counts("Process").map(|counts| counts.0) == objects_before, "ps: contabilidade do tipo Process");
}

fn namespace(assert: Assert) {
    use crate::ntos::ob::object_manager::{self as om, ObjectData, OpenOptions};
    use crate::ntos::ob::objects::namespace as namespace_objects;
    // Bootstrap do phase0: todas as grafias DOS levam ao mesmo volume.
    let fs = om::lookup("\\FS");
    assert(fs.is_some() && om::lookup("\\??\\C:") == fs && om::lookup("\\DosDevices\\C:") == fs && om::lookup("\\GLOBAL??\\GLOBALROOT\\FS") == fs, "ob: links DOS e GLOBALROOT");
    assert(om::lookup("\\device") == om::lookup("\\Device") && om::lookup("\\Device").is_some(), "ob: resolucao sem caixa");
    assert(om::lookup("\\KnownDlls\\Nada").is_none(), "ob: nome inexistente");
    let (mounted, rest) = om::resolve("\\??\\C:\\hello.exe");
    assert(mounted == fs && rest.as_deref() == Some("hello.exe"), "ob: resto delegado ao volume montado");
    // Arquivo aberto pela montagem (sem corpo nativo: fora da tabela do processo).
    let names = crate::drivers::fs::memory_file_system::list();
    if let Some(first) = names.first() {
        let upper = alloc::format!("\\??\\C:\\{}", first[1..].to_uppercase());
        let handle = om::open(&upper);
        assert(matches!(handle, Ok(handle) if handle != 0), "ob: abertura sem caixa dentro do volume");
        let handle = handle.unwrap();
        let file = om::get_object(handle).and_then(om::node);
        assert(file.is_some_and(|node| node.type_name == "File" && node.data.as_ref().and_then(|data| data.file_path.clone()).as_deref() == Some(first.as_str())), "ob: objeto File temporario");
        assert(matches!(om::close(handle), Ok(true)) && om::get_object(handle).is_none(), "ob: fechamento do arquivo");
    }
    assert(matches!(om::open("\\??\\C:\\nao-existe.bin"), Ok(0)), "ob: arquivo ausente");
    // Laço de links é cortado na profundidade 8.
    assert(om::create_symlink("\\LoopA", "\\LoopB").is_ok() && om::create_symlink("\\LoopB", "\\LoopA").is_ok(), "ob: links em laco");
    assert(om::lookup("\\LoopA\\x").is_none(), "ob: laco de links");
    assert(om::unlink("\\LoopA") && om::unlink("\\LoopB") && om::lookup("\\LoopB").is_none(), "ob: unlink");
    // Nomes que só diferem na caixa coexistem quando a criação é sensível à caixa.
    let directory = om::create_directory("\\Phase3Test");
    assert(directory.is_ok(), "ob: diretorio de teste");
    let directory = directory.unwrap();
    let upper = om::insert_named(directory, "Abc", "Event", None, false);
    let lower = om::insert_named(directory, "abc", "Event", None, false);
    assert(upper.is_some() && lower.is_some() && upper != lower, "ob: nomes sensiveis a caixa");
    assert(om::insert_named(directory, "ABC", "Event", None, true).is_none(), "ob: colisao sem caixa");
    assert(om::create_object("\\Phase3Test", "abc", "Event", None).is_err(), "ob: createObject recusa colisao");
    assert(om::path_of(lower.unwrap()).as_deref() == Some("\\Phase3Test\\abc"), "ob: pathOf");
    assert(om::remove_named(upper.unwrap()) && om::remove_named(lower.unwrap()) && om::path_of(lower.unwrap()).is_none(), "ob: removeNamed");
    // Handle de diretório: corpo nativo, contagem no corpo e linha na tabela.
    let directory_handles = om::type_stats("Directory").handles;
    let handle = om::open("\\Phase3Test");
    assert(matches!(handle, Ok(handle) if handle != 0), "ob: abertura de diretorio");
    let handle = handle.unwrap();
    let body = om::node(directory).map_or(0, |node| node.native_namespace);
    assert(body != 0 && namespace_objects::handles(body) == 1 && namespace_objects::refs(body) == 2, "ob: corpo de diretorio com handle e referencia da arvore");
    let record = om::handle_record(handle);
    assert(record.as_ref().is_some_and(|record| record.pointer == body && record.type_name.as_deref() == Some("Directory") && record.options.owner_process == Some(process::get_current_process())), "ob: linha nativa do handle");
    assert(om::type_stats("Directory").handles == directory_handles + 1, "ob: estatistica de handles de diretorio");
    assert(object_types::bound(body).is_some_and(|object_type| object_type.name == "Directory"), "ob: corpo ligado ao OBJECT_TYPE");
    assert(matches!(om::close(handle), Ok(true)) && namespace_objects::handles(body) == 0, "ob: fechamento do diretorio");
    assert(!matches!(om::close(handle), Ok(true)), "ob: fechamento repetido");
    // Link temporário: o último handle remove o nome e o corpo é recolhido.
    let link = om::create_symlink("\\Phase3Test\\Temp", "\\Device");
    assert(link.is_ok(), "ob: link temporario");
    let link = link.unwrap();
    let (resolved, _) = om::resolve_from("\\Phase3Test\\Temp", 0, true, true, om::ROOT);
    assert(resolved == Some(link), "ob: abertura do proprio link");
    let handle = om::open_object(link, None);
    assert(matches!(handle, Ok(handle) if handle != 0), "ob: handle do link");
    let link_body = om::node(link).map_or(0, |node| node.native_namespace);
    assert(link_body != 0 && namespace_objects::target(link_body).ok().as_deref() == Some("\\Device"), "ob: UNICODE_STRING do destino");
    namespace_objects::set_permanent(link_body, false);
    assert(matches!(om::close(handle.unwrap()), Ok(true)), "ob: fecha o ultimo handle do link");
    assert(om::lookup("\\Phase3Test\\Temp").is_none() && namespace_objects::get(link_body).is_none() && om::node(link).is_none(), "ob: link temporario removido e recolhido");
    assert(om::unlink("\\Phase3Test"), "ob: remove o diretorio de teste");
    // Handles por processo: o dono é o processo da abertura; kernel fica no System.
    let target = process::create_process(0x7B10, "phase3-ob.exe", 0, None);
    assert(target.is_ok(), "ob: processo de teste");
    let target = target.unwrap();
    let thread = process::create_kernel_thread(target, 0x7B14, false, 0, None).unwrap_or(0);
    let process_handle = process::open_handle(target, 0x1000);
    assert(matches!(process_handle, Ok(handle) if handle != 0) && process::reference_count(target) == Some(1), "ob: handle de processo retem o EPROCESS");
    let process_handle = process_handle.unwrap();
    assert(process::open_handle(target, 0x8000_0000).ok() == Some(0), "ob: direitos fora do tipo");
    let owned = om::new_node("", "Process", Some(ObjectData { native_pointer: target, access: Some(0x400), ..ObjectData::default() }));
    let owned = om::open_object(owned, Some(OpenOptions { owner_process: Some(target), ..OpenOptions::default() }));
    assert(matches!(owned, Ok(handle) if handle != 0), "ob: handle na tabela do processo alvo");
    let owned = owned.unwrap();
    let table = process_handles::get(target).unwrap_or(0);
    assert(handle_table::row(table, owned).is_some_and(|row| row.pointer == target && row.access == 0x400), "ob: linha no ObjectTable do alvo");
    let kernel = om::new_node("", "Process", Some(ObjectData { native_pointer: target, ..ObjectData::default() }));
    let kernel = om::open_object(kernel, Some(OpenOptions { open_attributes: Some(0x200), owner_process: Some(target), ..OpenOptions::default() })).unwrap_or(0);
    assert(om::handle_record(kernel).is_some_and(|record| record.options.owner_process == Some(process::get_system_process()) && record.options.kernel_handle), "ob: OBJ_KERNEL_HANDLE vai para o System");
    assert(process::terminate_process(target, 0).is_ok(), "ob: terminacao do processo");
    assert(om::get_object(owned).is_none() && om::get_object(kernel).is_some(), "ob: saida fecha os handles do processo e preserva os de kernel");
    assert(matches!(om::close(kernel), Ok(true)) && matches!(om::close(process_handle), Ok(true)), "ob: fecha os handles restantes");
    assert(process::release_thread(thread).is_ok() && !process::is_process(target), "ob: EPROCESS recolhido apos o ultimo handle");
}

fn object_callbacks(assert: Assert) {
    use crate::ntos::mm::loaded_images::{self, ImageDescription};
    use crate::ntos::ob::callbacks;
    use core::cmp::Ordering as AltitudeOrder;
    assert(callbacks::compare_altitude("320000", "0320000.000") == AltitudeOrder::Equal, "ob callbacks: altitude normalizada");
    assert(callbacks::compare_altitude("1.5", "1.45") == AltitudeOrder::Greater && callbacks::compare_altitude("99", "100") == AltitudeOrder::Less, "ob callbacks: ordem decimal textual");
    // Imagem verificada mínima: pré-callback conta e remove PROCESS_TERMINATE;
    // pós-callback conta.
    let page = guest::alloc_page();
    let code: [u8; 16] = [
        0xFF, 0x01, // inc dword [rcx]
        0x48, 0x8B, 0x42, 0x20, // mov rax, [rdx+0x20]  (Parameters)
        0x83, 0x20, 0xFE, // and dword [rax], ~1   (DesiredAccess)
        0x31, 0xC0, // xor eax, eax
        0xC3, // ret
        0xFF, 0x41, 0x04, // inc dword [rcx+4]
        0xC3, // ret
    ];
    guest::write_bytes(page, &code);
    let image = loaded_images::register(ImageDescription { image_base: page, size_of_image: 0x1000, loader_flags: 0x20, ..ImageDescription::default() }, "obcallback-test.sys");
    assert(image.is_ok(), "ob callbacks: imagem verificada registrada");
    let image = image.unwrap();
    let scratch = guest::alloc_bytes(0x100);
    let counters = scratch;
    let type_cell = scratch + 0x10;
    let operation = scratch + 0x20;
    let registration = scratch + 0x40;
    let altitude = scratch + 0x80;
    let output = scratch + 0xC0;
    let process_type = object_types::process_type();
    guest::write64(type_cell, process_type.pointer);
    guest::write64(operation, type_cell);
    guest::write32(operation + 8, 3); // CREATE | DUPLICATE
    guest::write64(operation + 16, page);
    guest::write64(operation + 24, page + 12);
    crate::ntos::rtl::guest_strings::write_wide_string(altitude, "321000");
    guest::write16(registration, 0x100);
    guest::write16(registration + 2, 1);
    guest::write16(registration + 8, 12);
    guest::write16(registration + 10, 14);
    guest::write64(registration + 16, altitude);
    guest::write64(registration + 24, counters);
    guest::write64(registration + 32, operation);
    assert(matches!(callbacks::register(registration, output), Ok(0)), "ob callbacks: registro");
    let handle = guest::read64(output);
    assert(handle != 0 && guest::read64(process_type.pointer + 0xC8) == handle + 32, "ob callbacks: lista nativa do OBJECT_TYPE");
    assert(matches!(callbacks::register(registration, output), Ok(0xC01C_0011)), "ob callbacks: altitude duplicada");
    // Callback fora de imagem verificada é recusado.
    guest::write64(operation + 16, kernel_routine as extern "win64" fn(u64, u64, u64, u64, u64) as usize as u64);
    crate::ntos::rtl::guest_strings::write_wide_string(altitude, "321001");
    assert(matches!(callbacks::register(registration, output), Ok(0xC000_0022)), "ob callbacks: imagem nao verificada");
    let target = process::create_process(0x7B20, "phase3-obcb.exe", 0, None).unwrap_or(0);
    let thread = process::create_kernel_thread(target, 0x7B24, false, 0, None).unwrap_or(0);
    let opened = process::open_handle(target, 0x1F_FFFF);
    assert(matches!(opened, Ok(handle) if handle != 0), "ob callbacks: abertura passa pelos callbacks");
    assert(guest::read32(counters) == 1 && guest::read32(counters + 4) == 1, "ob callbacks: pre e pos executados");
    let opened = opened.unwrap();
    // Modo kernel não aplica a redução feita pelo pré-callback.
    assert(crate::ntos::ob::object_manager::handle_record(opened).is_some_and(|record| record.access == 0x1F_FFFF), "ob callbacks: modo kernel conserva o acesso");
    let _ = crate::ntos::ob::object_manager::close(opened);
    assert(matches!(callbacks::unregister(handle), Ok(0)), "ob callbacks: remocao");
    assert(guest::read64(process_type.pointer + 0xC8) == process_type.pointer + 0xC8 && callbacks::registration_count() == 0, "ob callbacks: lista vazia apos remocao");
    let _ = process::terminate_process(target, 0);
    let _ = process::release_thread(thread);
    assert(matches!(loaded_images::unregister(image.id), Ok(true)), "ob callbacks: imagem descarregada");
    guest::free_bytes(scratch);
    guest::free_bytes(page);
}

fn open_by_pointer(assert: Assert) {
    use crate::ntos::ob::objects::namespace as namespace_objects;
    use crate::ntos::ob::{object_manager as om, open_pointer};
    let target = process::create_process(0x7B30, "phase3-open.exe", 0, None).unwrap_or(0);
    let thread = process::create_kernel_thread(target, 0x7B34, false, 0, None).unwrap_or(0);
    let process_type = object_types::process_type();
    let scratch = guest::alloc_bytes(0x40);
    let output = scratch;
    let object = scratch + 8;
    let information = scratch + 16;
    assert(open_pointer::describe(target).is_some_and(|item| item.object_type.name == "Process"), "open-pointer: describe de processo");
    assert(open_pointer::describe(thread).is_some_and(|item| item.object_type.name == "Thread"), "open-pointer: describe de thread");
    assert(open_pointer::describe(scratch).is_none(), "open-pointer: corpo desconhecido");
    // Validações na ordem nativa; a saída é zerada antes.
    guest::write64(output, 0xA5A5);
    assert(matches!(open_pointer::open(target, 0, 0, 0x1000, object_types::thread_type().pointer, 0, output), Ok(0xC000_0024)) && guest::read64(output) == 0, "open-pointer: tipo divergente e saida zerada");
    assert(matches!(open_pointer::open(target, 0, 0, 0x1000, 0, 1, output), Ok(0xC000_0024)), "open-pointer: modo usuario exige tipo");
    assert(matches!(open_pointer::open(target, 0x20, 0, 0x1000, process_type.pointer, 0, output), Ok(0xC000_000D)), "open-pointer: OBJ_EXCLUSIVE em corpo compartilhado");
    let references = process::reference_count(target).unwrap_or(0);
    assert(matches!(open_pointer::open(target, 0, 0, 0x1000, process_type.pointer, 0, output), Ok(0)), "open-pointer: abertura por ponteiro");
    let handle = guest::read64(output);
    assert(handle != 0 && handle < 0x8000_0000 && process::reference_count(target) == Some(references + 1), "open-pointer: handle retem o corpo");
    let record = om::handle_record(handle as u32);
    assert(record.is_some_and(|record| record.pointer == target && record.access == 0x1000 && record.options.owner_process == Some(process::get_current_process())), "open-pointer: linha nativa do handle");
    assert(matches!(open_pointer::reference_handle(handle, 0x1000, process_type.pointer, 1, object, information), Ok(Some(0))), "open-pointer: ObReferenceObjectByHandle");
    assert(guest::read64(object) == target && guest::read32(information + 4) == 0x1000 && process::reference_count(target) == Some(references + 2), "open-pointer: corpo e informacao do handle");
    let _ = process::dereference(target);
    assert(matches!(open_pointer::reference_handle(handle, 0x1F_FFFF, process_type.pointer, 1, object, 0), Ok(Some(0xC000_0022))), "open-pointer: acesso alem do concedido");
    assert(matches!(open_pointer::reference_handle(handle, 0, object_types::token_type().pointer, 0, object, 0), Ok(Some(0xC000_0024))), "open-pointer: tipo do handle");
    assert(open_pointer::close(handle) == Some(0) && process::reference_count(target) == Some(references), "open-pointer: ObCloseHandle solta o corpo");
    assert(open_pointer::close(handle).is_none(), "open-pointer: handle fechado some");
    // Handle de kernel: codificação alta e isolamento do modo usuário.
    assert(matches!(open_pointer::open(target, 0x200, 0, 0x1000, process_type.pointer, 0, output), Ok(0)), "open-pointer: OBJ_KERNEL_HANDLE");
    let kernel = guest::read64(output);
    assert(kernel & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000, "open-pointer: handle de kernel codificado");
    assert(matches!(open_pointer::reference_handle(kernel, 0x1000, 0, 1, object, 0), Ok(Some(0xC000_0008))), "open-pointer: modo usuario nao usa handle de kernel");
    assert(matches!(open_pointer::resolve(kernel & 0x7FFF_FFFF, false), Some(Err(0xC000_0008))), "open-pointer: handle de kernel exige a forma alta");
    assert(open_pointer::close(kernel) == Some(0), "open-pointer: fecha o handle de kernel");
    // Corpo de namespace aberto por ponteiro conta no próprio corpo.
    let directory = om::lookup("\\KernelObjects").and_then(om::node);
    if let Some(directory) = directory {
        let body = match directory.native_namespace {
            0 => namespace_objects::ensure(directory.id).ok().flatten().unwrap_or(0),
            body => body,
        };
        let before = namespace_objects::handles(body);
        assert(matches!(open_pointer::open(body, 0, 0, 1, object_types::directory_type().pointer, 0, output), Ok(0)), "open-pointer: diretorio por ponteiro");
        let handle = guest::read64(output);
        assert(namespace_objects::refs(body) >= 2 && om::handle_record(handle as u32).is_some_and(|record| record.pointer == body), "open-pointer: handle do corpo de diretorio");
        assert(open_pointer::close(handle) == Some(0) && namespace_objects::handles(body) == before, "open-pointer: fechamento do diretorio");
    }
    let _ = process::terminate_process(target, 0);
    let _ = process::release_thread(thread);
    assert(!process::is_process(target), "open-pointer: processo recolhido");
    guest::free_bytes(scratch);
}

fn security_descriptors(assert: Assert) {
    use crate::ntos::ex::callback_security;
    use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
    use crate::ntos::se::{acl, descriptor, model, object_security, sid};
    // Descritor relativo real (dono, grupo, DACL) em memória de kernel.
    let policy = object_security::directory(u64::MAX - 7);
    let bytes = object_security::encode(&policy, 7);
    let pool = kernel_pool::allocate(0x200, AllocateOptions { zero: true, ..AllocateOptions::default() }).unwrap_or(0);
    assert(pool >= 0xFFFF_8000_0000_0000, "se: pool de kernel para os descritores");
    guest::write_bytes(pool, &bytes);
    assert(descriptor::valid(pool) && descriptor::valid_relative(pool, bytes.len() as u32, 3), "se: descritor relativo valido");
    assert(descriptor::length(pool) == bytes.len() as u32, "se: RtlLengthSecurityDescriptor");
    assert(!descriptor::valid_relative(pool, 19, 0), "se: descritor curto recusado");
    let control = descriptor::control(pool);
    let owner = descriptor::component(pool, control, 0);
    assert(sid::valid(owner) && sid::read(owner) == model::sid(5, &[18]) && sid::length(owner) == 12, "se: SID do dono");
    assert(!sid::valid(0x1000), "se: SID em endereco de usuario recusado");
    let dacl = descriptor::component(pool, control, 3);
    assert(acl::valid(dacl), "se: RtlValidAcl");
    let out = pool + 0x180;
    assert(descriptor::get_ace(dacl, 1, out) == 0 && guest::read32(guest::read64(out) + 4) == 0x20003, "se: RtlGetAce");
    assert(descriptor::get_ace(dacl, 2, out) == 0xC000_000D, "se: indice de ACE fora da ACL");
    let capacity = pool + 0x190;
    guest::write32(capacity, 0x100);
    assert(descriptor::absolute_to_relative(pool, pool + 0x100, capacity) == 0xC000_00E7, "se: descritor ja relativo");
    assert(sid::copy(4, pool + 0x100, owner) == 0xC000_0023 && sid::copy(12, pool + 0x100, owner) == 0 && sid::equal(pool + 0x100, owner), "se: RtlCopySid e RtlEqualSid");
    // Captura própria das componentes e avaliação do tipo Callback.
    let captured = callback_security::capture(pool);
    assert(captured.as_ref().is_ok_and(|captured| captured.owner == policy.owner && captured.dacl.as_ref().is_some_and(|dacl| dacl.len() == 2 && dacl[0].mask == 0xF000F) && captured.control == Some(control)), "ex: captura do descritor");
    let captured = captured.unwrap_or_default();
    assert(callback_security::access(&captured, 1, false) == Ok(1), "ex: acesso sem verificacao");
    assert(callback_security::access(&captured, 0x0200_0000, false) == Ok(0x1F_0001), "ex: MAXIMUM_ALLOWED sem verificacao");
    assert(callback_security::access(&captured, 0x4, false) == Err(0xC000_0022), "ex: direito fora do tipo Callback");
    guest::write8(pool, 2);
    assert(callback_security::capture(pool) == Err(0xC000_0079), "ex: descritor invalido");
    let _ = kernel_pool::free(pool, None);
}

static DISPOSED: AtomicU64 = AtomicU64::new(0);

fn dispose_event(pointer: u64) {
    DISPOSED.store(pointer, Ordering::SeqCst);
}

fn dispatcher_bodies_and_close(assert: Assert) {
    use crate::ntos::ob::{close, open_pointer};
    use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
    let event = guest::alloc_bytes(0x18);
    dispatcher::initialize_event(event, 0, false);
    let created = dispatcher_objects::create(event, "event", dispose_event, None, 0, false, dispatcher_objects::DispatcherHooks::default());
    assert(created.is_ok() && object_types::bound(event).is_some_and(|object_type| object_type.name == "Event"), "ob: corpo de evento registrado");
    assert(dispatcher_objects::create(event, "event", dispose_event, None, 0, false, dispatcher_objects::DispatcherHooks::default()).is_err(), "ob: registro duplicado");
    assert(open_pointer::describe(event).is_some_and(|item| item.object_type.name == "Event"), "ob: slot de dispatcher no describe");
    let output = guest::alloc_bytes(8);
    assert(matches!(dispatcher_objects::reference(event), Ok(1)), "ob: referencia de ponteiro");
    assert(matches!(open_pointer::open(event, 0, 0, 0x10_0000, object_types::event_type().pointer, 0, output), Ok(0)), "ob: abertura do evento por ponteiro");
    let handle = guest::read64(output);
    assert(dispatcher_objects::get(event) == Some((alloc::string::String::from("event"), 2, 1)), "ob: handle retem o corpo");
    assert(matches!(dispatcher_objects::dereference(event), Ok(1)), "ob: solta a referencia de ponteiro");
    assert(dispatcher_objects::dereference(event).is_err(), "ob: ultima referencia pertence ao handle");
    // NtClose: pseudohandles, isolamento de modo e handles protegidos.
    assert(matches!(close::close(u64::MAX, Some(0)), Ok(0)) && matches!(close::close((-6i64) as u64, Some(1)), Ok(0)), "ob: pseudohandles");
    assert(matches!(close::close(0xFFFF_FFFF_8000_0004, Some(1)), Ok(close::STATUS_INVALID_HANDLE)), "ob: handle de kernel vindo do modo usuario");
    assert(matches!(close::close(0x7FFF_FFF0, Some(1)), Ok(close::STATUS_INVALID_HANDLE)), "ob: handle desconhecido");
    let table = process_handles::get(process::get_current_process()).unwrap_or(0);
    assert(matches!(handle_table::change(table, handle, 1, 0x10_0000), Ok(true)), "ob: OBJ_PROTECT_CLOSE na linha");
    assert(matches!(close::close(handle, Some(1)), Ok(close::STATUS_HANDLE_NOT_CLOSABLE)), "ob: handle protegido em modo usuario");
    assert(matches!(handle_table::change(table, handle, 0, 0x10_0000), Ok(true)), "ob: protecao retirada");
    assert(matches!(close::close(handle, Some(1)), Ok(0)), "ob: NtClose");
    assert(dispatcher_objects::get(event).is_none() && DISPOSED.load(Ordering::SeqCst) == event && object_types::bound(event).is_none(), "ob: ultimo handle libera o corpo");
    assert(matches!(close::close(handle, Some(1)), Ok(close::STATUS_INVALID_HANDLE)), "ob: fechamento repetido");
    guest::free_bytes(output);
    guest::free_bytes(event);
}

/// OBJECT_ATTRIBUTES de 48 bytes com o nome dado (UNICODE_STRING em +0x30).
fn object_attributes(scratch: u64, root: u64, name: &str, flags: u32) -> u64 {
    let units: alloc::vec::Vec<u16> = name.encode_utf16().collect();
    for offset in (0..48).step_by(8) {
        guest::write64(scratch + offset, 0);
    }
    guest::write32(scratch, 48);
    guest::write64(scratch + 8, root);
    guest::write64(scratch + 16, scratch + 0x30);
    guest::write32(scratch + 24, flags);
    guest::write16(scratch + 0x30, units.len() as u16 * 2);
    guest::write16(scratch + 0x32, units.len() as u16 * 2);
    guest::write64(scratch + 0x38, scratch + 0x40);
    for (index, &unit) in units.iter().enumerate() {
        guest::write16(scratch + 0x40 + index as u64 * 2, unit);
    }
    scratch
}

fn namespace_handles(assert: Assert) {
    use crate::ntos::ob::{close, object_manager as om};
    use crate::ntos::ob::handles::namespace as nh;
    let scratch = guest::alloc_bytes(0x400);
    let attributes = scratch;
    let output = scratch + 0x200;
    let length = scratch + 0x208;
    let context = scratch + 0x20C;
    let link_buffer = scratch + 0x210;
    let query = scratch + 0x280;
    // Criação de diretório temporário (sem OBJ_PERMANENT), sem caixa.
    object_attributes(attributes, 0, "\\Phase3Ns", 0x40);
    assert(nh::open(output, 0xF000F, attributes, "Directory", false, true) == 0, "ns: NtCreateDirectoryObject");
    let directory = guest::read64(output);
    assert(om::lookup("\\phase3ns").is_some(), "ns: diretorio no namespace");
    assert(nh::open(output, 0xF000F, attributes, "Directory", false, true) == 0xC000_0035, "ns: nome ja existe");
    object_attributes(attributes, 0, "\\Phase3Ns", 0xC0);
    assert(nh::open(output, 0xF000F, attributes, "Directory", false, true) == 0x4000_0000, "ns: OBJ_OPENIF devolve STATUS_OBJECT_NAME_EXISTS");
    let reopened = guest::read64(output);
    object_attributes(attributes, 0, "Relativo", 0x40);
    assert(nh::open(output, 1, attributes, "Directory", false, false) == 0xC000_003B, "ns: nome relativo sem raiz");
    object_attributes(attributes, 0, "\\Phase3Ns", 0x40);
    assert(nh::open(output, 1, attributes, "SymbolicLink", false, false) == 0xC000_0024, "ns: tipo divergente");
    // Link aberto pelo nome relativo ao diretório.
    assert(om::create_symlink("\\Phase3Ns\\Link", "\\Device").is_ok(), "ns: link de teste");
    object_attributes(attributes, directory, "link", 0x40);
    assert(nh::open(output, 1, attributes, "SymbolicLink", false, false) == 0, "ns: NtOpenSymbolicLinkObject relativo");
    let link = guest::read64(output);
    guest::write16(link_buffer, 0);
    guest::write16(link_buffer + 2, 4);
    guest::write64(link_buffer + 8, link_buffer + 0x10);
    assert(nh::query_link(link, link_buffer, length, false) == 0xC000_0023 && guest::read32(length) == 14, "ns: buffer pequeno informa o tamanho");
    guest::write16(link_buffer + 2, 0x40);
    assert(nh::query_link(link, link_buffer, length, false) == 0 && guest::read16(link_buffer) == 14 && crate::ntos::rtl::guest_strings::read_unicode_string(link_buffer) == "\\Device", "ns: NtQuerySymbolicLinkObject");
    assert(nh::query_link(directory, link_buffer, length, false) == 0xC000_0024, "ns: diretorio nao e link");
    // Enumeração do diretório.
    assert(nh::query_directory(directory, query, 0x100, false, true, context, length) == 0, "ns: NtQueryDirectoryObject");
    assert(guest::read32(context) == 1 && crate::ntos::rtl::guest_strings::read_unicode_string(query) == "Link" && crate::ntos::rtl::guest_strings::read_unicode_string(query + 16) == "SymbolicLink", "ns: entrada nome/tipo");
    assert(guest::read64(query + 32) == 0 && guest::read64(query + 40) == 0, "ns: terminador vazio");
    assert(nh::query_directory(directory, query, 0x100, false, false, context, length) == 0x8000_001A, "ns: STATUS_NO_MORE_ENTRIES");
    assert(nh::query_directory(directory, query, 40, false, true, context, length) == 0xC000_0023, "ns: buffer insuficiente");
    // O último handle remove o nome do diretório temporário.
    assert(matches!(close::close(link, Some(0)), Ok(0)) && om::unlink("\\Phase3Ns\\Link"), "ns: fecha e remove o link");
    assert(matches!(close::close(reopened, Some(0)), Ok(0)) && om::lookup("\\Phase3Ns").is_some(), "ns: nome vivo enquanto ha handle");
    assert(matches!(close::close(directory, Some(0)), Ok(0)) && om::lookup("\\Phase3Ns").is_none(), "ns: diretorio temporario removido no ultimo handle");
    assert(nh::make_temporary(directory).is_some_and(|status| status == 0xC000_0008), "ns: handle fechado");
    guest::free_bytes(scratch);
}

static LOOKASIDE_FREES: AtomicU64 = AtomicU64::new(0);

extern "win64" fn lookaside_allocate(_pool_type: u64, size: u64, _tag: u64) -> u64 {
    guest::alloc_bytes(size)
}

extern "win64" fn lookaside_free(block: u64) {
    LOOKASIDE_FREES.fetch_add(1, Ordering::SeqCst);
    guest::free_bytes(block);
}

fn executive_primitives(assert: Assert) {
    use crate::ntos::ex::{lookaside, pool_allocation, slist, spin_lock};
    use crate::ntos::inc::nt_abi::lookaside_list as layout;
    // SLIST: profundidade, sequência e ABA.
    let area = guest::alloc_aligned(0x200, 16, true);
    let head = area;
    assert(slist::initialize(head + 8).is_err_and(|error| error.status == 0x8000_0002), "slist: desalinhamento");
    assert(slist::initialize(head).is_ok(), "slist: InitializeSListHead");
    let entries = [area + 0x40, area + 0x60, area + 0x80];
    for &entry in &entries {
        assert(slist::push(head, entry).is_ok(), "slist: push");
    }
    assert(slist::depth(head) == 3 && slist::first(head) == entries[2] && guest::read64(head) >> 16 == 3, "slist: profundidade, sequencia e primeiro");
    assert(matches!(slist::pop(head), Ok(entry) if entry == entries[2]) && slist::depth(head) == 2 && guest::read64(head) >> 16 == 3, "slist: pop so decrementa a profundidade");
    assert(matches!(slist::flush(head), Ok(entry) if entry == entries[1]) && slist::depth(head) == 0 && slist::first(head) == 0 && guest::read64(head) >> 16 == 3, "slist: flush conserva a sequencia");
    assert(matches!(slist::pop(head), Ok(0)), "slist: lista vazia");
    // EX_SPIN_LOCK: escritor, leitores e conversão.
    let lock = area + 0x100;
    guest::write32(lock, 0);
    assert(spin_lock::acquire_exclusive_at_dpc(lock).is_err(), "spinlock: exige DISPATCH_LEVEL");
    let previous = spin_lock::acquire_exclusive(lock);
    assert(previous == 0 && irql::get_irql() == 2 && guest::read32(lock) == 0x8000_0000, "spinlock: exclusivo eleva o IRQL");
    assert(spin_lock::release_exclusive(lock, previous).is_ok() && guest::read32(lock) == 0 && irql::get_irql() == 0, "spinlock: liberacao exclusiva");
    let previous = spin_lock::acquire_shared(lock);
    assert(spin_lock::acquire_shared_at_dpc(lock).is_ok() && guest::read32(lock) == 2, "spinlock: dois leitores");
    assert(spin_lock::release_shared_from_dpc(lock).is_ok() && guest::read32(lock) == 1, "spinlock: um leitor sai");
    assert(matches!(spin_lock::try_convert(lock), Ok(true)) && guest::read32(lock) == 0x8000_0001, "spinlock: conversao para exclusivo");
    assert(spin_lock::release_exclusive(lock, previous).is_ok() && guest::read32(lock) == 0 && irql::get_irql() == 0, "spinlock: liberacao apos conversao");
    // ExAllocatePoolWithTag.
    let block = pool_allocation::allocate_tagged(0x200, 0x40, 0x7473_6554).unwrap_or(0);
    assert(block != 0, "pool: ExAllocatePoolWithTag");
    assert(crate::ntos::mm::kernel_pool::info(block).is_some_and(|info| info.tag == 0x7473_6554), "pool: tag registrada");
    let _ = crate::ntos::mm::kernel_pool::free(block, None);
    // Sem rotinas próprias, a lista usa os exports públicos de pool.
    let list = guest::alloc_aligned(layout::SIZE, 16, true);
    let export = |name: &str| crate::ntos::init::exports::export_module().ok().and_then(|module| module.exports.exports.get(name).copied());
    let defaults = lookaside::initialize(list, 0, 0, 0, 0x30, 0x6B6F_6F4C, false).is_ok() && Some(guest::read64(list + layout::ALLOCATE_CALLBACK)) == export("ExAllocatePoolWithTag") && Some(guest::read64(list + layout::FREE_CALLBACK)) == export("ExFreePool");
    assert(defaults && lookaside::delete(list).is_ok(), "lookaside: callbacks padrao sao os exports de pool");
    // Lookaside com callbacks próprios.
    let registered = lookaside::registered_count();
    let allocate_routine = lookaside_allocate as extern "win64" fn(u64, u64, u64) -> u64 as usize as u64;
    let free_routine = lookaside_free as extern "win64" fn(u64) as usize as u64;
    assert(lookaside::initialize(list, allocate_routine, free_routine, 0, 0x30, 0x6B6F_6F4C, false).is_ok() && lookaside::registered_count() == registered + 1, "lookaside: ExInitializeNPagedLookasideList");
    assert(guest::read16(list + layout::DEPTH) == 4 && guest::read32(list + layout::BLOCK_SIZE) == 0x30, "lookaside: profundidade inicial e tamanho");
    let first = lookaside::allocate(list).unwrap_or(0);
    assert(first != 0 && guest::read32(list + layout::ALLOC_MISSES) == 1, "lookaside: falta chama o alocador");
    assert(lookaside::free(list, first).is_ok() && slist::depth(list) == 1, "lookaside: devolucao vai ao cache");
    assert(lookaside::allocate(list).ok() == Some(first) && guest::read32(list + layout::ALLOC_COUNT) == 2 && guest::read32(list + layout::ALLOC_MISSES) == 1, "lookaside: acerto no cache");
    let blocks: alloc::vec::Vec<u64> = (0..5).map(|_| lookaside::allocate(list).unwrap_or(0)).collect();
    LOOKASIDE_FREES.store(0, Ordering::SeqCst);
    for &block in &blocks {
        let _ = lookaside::free(list, block);
    }
    let _ = lookaside::free(list, first);
    assert(slist::depth(list) == 4 && guest::read32(list + layout::FREE_MISSES) == 2 && LOOKASIDE_FREES.load(Ordering::SeqCst) == 2, "lookaside: cache cheio libera pelo callback");
    assert(lookaside::delete(list).is_ok() && LOOKASIDE_FREES.load(Ordering::SeqCst) == 6 && lookaside::registered_count() == registered, "lookaside: exclusao esvazia o cache");
    guest::free_bytes(list);
    guest::free_bytes(area);
}

fn executive_resources(assert: Assert) {
    use crate::ntos::ex::resource;
    let first = process::get_current_thread();
    let second = process::create_kernel_thread(process::get_system_process(), 0x7C04, false, 0, None).unwrap_or(0);
    assert(second != 0, "eresource: segunda thread");
    let lock = guest::alloc_bytes(resource::STRUCT_SIZE);
    assert(matches!(resource::initialize(lock), Ok(0)), "eresource: ExInitializeResourceLite");
    // Exclusivo com recursão; compartilhado do dono exclusivo também recursa.
    assert(matches!(resource::acquire_exclusive(lock, true), Ok(1)) && matches!(resource::acquire_exclusive(lock, true), Ok(1)), "eresource: exclusivo recursivo");
    assert(matches!(resource::acquire_shared(lock, true), Ok(1)) && matches!(resource::is_acquired_shared(lock), Ok(3)) && matches!(resource::is_acquired_exclusive(lock), Ok(true)), "eresource: recursao do dono exclusivo");
    assert(matches!(resource::delete(lock), Ok(0xC000_000D)), "eresource: exclusao com dono recusada");
    // A segunda thread não adquire sem espera e enfileira com espera.
    process::set_current_thread(second);
    assert(matches!(resource::acquire_shared(lock, false), Ok(0)), "eresource: sem espera devolve FALSE");
    let request = resource::begin(lock, resource::Mode::Shared, true, false);
    assert(request.is_ok(), "eresource: inicio da espera compartilhada");
    let mut request = request.unwrap();
    assert(matches!(request.poll(), Ok(None)) && resource::shared_waiters(lock) == 1, "eresource: leitor aguardando");
    process::set_current_thread(first);
    for _ in 0..3 {
        assert(resource::release(lock).is_ok(), "eresource: liberacao do dono");
    }
    assert(resource::shared_waiters(lock) == 0 && matches!(resource::is_acquired_exclusive(lock), Ok(false)), "eresource: posse entregue aos leitores");
    process::set_current_thread(second);
    assert(matches!(request.poll(), Ok(Some(1))) && matches!(resource::is_acquired_shared(lock), Ok(1)), "eresource: leitor recebe a posse");
    // Um escritor espera o leitor sair.
    process::set_current_thread(first);
    let writer = resource::begin(lock, resource::Mode::Exclusive, true, false);
    let mut writer = writer.unwrap_or_else(|_| panic!("begin"));
    assert(matches!(writer.poll(), Ok(None)) && resource::exclusive_waiters(lock) == 1, "eresource: escritor aguardando");
    process::set_current_thread(second);
    assert(matches!(resource::acquire_shared_wait_for_exclusive(lock, false), Ok(0)), "eresource: WaitForExclusive respeita o escritor");
    assert(matches!(resource::acquire_shared_starve_exclusive(lock, false), Ok(1)), "eresource: StarveExclusive passa a frente");
    assert(resource::release(lock).is_ok() && resource::release(lock).is_ok(), "eresource: leitor sai");
    process::set_current_thread(first);
    assert(matches!(writer.poll(), Ok(Some(1))) && matches!(resource::is_acquired_exclusive(lock), Ok(true)), "eresource: escritor recebe a posse");
    assert(resource::convert_exclusive_to_shared(lock).is_ok() && matches!(resource::is_acquired_exclusive(lock), Ok(false)) && matches!(resource::is_acquired_shared(lock), Ok(1)), "eresource: conversao para compartilhado");
    assert(resource::release(lock).is_ok(), "eresource: liberacao final");
    process::set_current_thread(second);
    assert(resource::release(lock).is_err(), "eresource: liberacao por quem nao e dono");
    process::set_current_thread(first);
    // Helpers combinados com região crítica.
    let apc_disable = guest::read16(first + kthread::KERNEL_APC_DISABLE);
    assert(resource::enter_exclusive(lock).is_ok() && guest::read16(first + kthread::KERNEL_APC_DISABLE) == apc_disable.wrapping_sub(1), "eresource: entra na regiao critica e adquire");
    assert(resource::release_and_leave(lock).is_ok() && guest::read16(first + kthread::KERNEL_APC_DISABLE) == apc_disable, "eresource: libera e sai da regiao critica");
    assert(matches!(resource::reinitialize(lock), Ok(0)) && matches!(resource::delete(lock), Ok(0)), "eresource: reinicializacao e exclusao");
    guest::free_bytes(lock);
    let _ = process::release_thread(second);
}

static NOTIFIED: AtomicU64 = AtomicU64::new(0);

extern "win64" fn callback_routine(context: u64, first: u64, second: u64) {
    NOTIFIED.fetch_add(context + first + second, Ordering::SeqCst);
}

fn executive_callbacks(assert: Assert) {
    use crate::ntos::ex::callbacks;
    use crate::ntos::ob::{close, object_manager as om, open_pointer};
    let scratch = guest::alloc_bytes(0x200);
    let output = scratch + 0x180;
    // Objeto permanente criado no boot.
    object_attributes(scratch, 0, "\\Callback\\PowerState", 0x40);
    assert(matches!(callbacks::create(output, scratch, false, true), Ok(0)), "excb: ExCreateCallback abre objeto existente");
    let power = guest::read64(output);
    assert(callbacks::counts(power).is_some_and(|(references, _, _)| references == 1) && callbacks::name(power).as_deref() == Some("\\Callback\\PowerState"), "excb: referencia e nome do objeto do sistema");
    assert(matches!(callbacks::dereference(power), Ok(Some(0))) && callbacks::exists(power), "excb: objeto permanente sobrevive sem referencias");
    object_attributes(scratch, 0, "\\Callback\\Phase3Cb", 0x40);
    assert(matches!(callbacks::create(output, scratch, false, false), Ok(0xC000_0034)), "excb: nome inexistente sem criacao");
    assert(matches!(callbacks::create(output, scratch, true, false), Ok(0)), "excb: criacao temporaria");
    let object = guest::read64(output);
    assert(om::lookup("\\Callback\\Phase3Cb").is_none() && open_pointer::describe(object).is_some_and(|item| item.object_type.name == "Callback"), "excb: nome temporario some ao fechar o handle interno");
    // Registro unico e notificação pela ABI nativa.
    let routine = callback_routine as extern "win64" fn(u64, u64, u64) as usize as u64;
    let registration = callbacks::register(object, routine, 100).unwrap_or(0);
    assert(registration != 0 && guest::read64(object + 0x10) == registration && guest::read64(registration + 0x10) == object, "excb: ExRegisterCallback na lista nativa");
    assert(matches!(callbacks::register(object, routine, 1), Ok(0)), "excb: objeto sem multiplos registros");
    NOTIFIED.store(0, Ordering::SeqCst);
    assert(callbacks::notify(object, 2, 3).is_ok() && NOTIFIED.load(Ordering::SeqCst) == 105, "excb: ExNotifyCallback");
    assert(callbacks::counts(object) == Some((2, 0, 1)), "excb: registro retem o objeto");
    assert(matches!(callbacks::unregister(registration), Ok(0)) && callbacks::counts(object) == Some((1, 0, 0)) && guest::read64(object + 0x10) == object + 0x10, "excb: ExUnregisterCallback");
    // Handle de kernel fechado pelo NtClose através do dono registrado.
    let opened = callbacks::open_handle(object, 0x1F_0001, 0x200, false);
    assert(matches!(opened, Ok(Ok(handle)) if handle & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000), "excb: handle de kernel");
    let handle = match opened { Ok(Ok(handle)) => handle, _ => 0 };
    assert(callbacks::counts(object) == Some((2, 1, 0)) && callbacks::resolve_handle(handle, false).is_some() && callbacks::resolve_handle(handle, true).is_none(), "excb: handle retem o objeto");
    assert(matches!(close::close(handle, Some(0)), Ok(0)) && callbacks::counts(object) == Some((1, 0, 0)), "excb: NtClose pelo dono de callbacks");
    assert(matches!(callbacks::dereference(object), Ok(Some(0))) && !callbacks::exists(object), "excb: objeto temporario recolhido");
    guest::free_bytes(scratch);
}

fn token_handles(assert: Assert) {
    use crate::ntos::ob::close;
    use crate::ntos::se::token::{thread as thread_tokens, access as token_access, handles as th, reference as token_reference};
    let system = process::get_primary_token(process::get_system_process()).unwrap_or(0);
    assert(token_access::check(system, None, 0x8, true) == Ok(0x8) && token_access::check(system, None, 0x0200_0000, true) == Ok(0x1F_01FF), "token: acesso em modo kernel");
    assert(token_access::check(system, None, 0x40_0000, true) == Err(0xC000_0022), "token: direito fora do tipo");
    assert(token_access::check(system, None, 0x8, false) == Err(0xC000_007C), "token: sem sujeito");
    assert(token_access::map_generic_access(0x8000_0000) == 0x2001A, "token: GENERIC_READ");
    // Handle de kernel do token, resolvido e fechado pelos donos registrados.
    let references = tokens::get(system).map_or(0, |token| token.refs);
    let handle = th::create(system, 0x8, 0x200, false).unwrap_or(0);
    assert(handle & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000 && th::resolve_native(handle).is_some_and(|data| data.native_pointer == system), "token: handle de kernel");
    assert(tokens::get(system).is_some_and(|token| token.refs == references + 1), "token: handle retem o token");
    let referenced = token_reference::reference(handle, 0x8, 0, true);
    assert(matches!(&referenced, Ok(Ok(reference)) if reference.token == system && reference.granted_access == 0x8), "token: SepReferenceTokenByHandle");
    if let Ok(Ok(mut reference)) = referenced {
        assert(reference.release().is_ok() && reference.release().is_err(), "token: referencia liberada uma vez");
    }
    assert(matches!(token_reference::reference(handle, 0x8, 1, true), Ok(Err(0xC000_0008))), "token: modo usuario nao usa handle de kernel");
    assert(matches!(token_reference::reference(u64::MAX, 0x8, 0, true), Ok(Err(0xC000_0024))), "token: pseudo-handle de processo");
    let primary = token_reference::reference((-4i64) as u64, 0x8, 0, true);
    assert(matches!(&primary, Ok(Ok(reference)) if reference.token == system), "token: pseudo-handle do token primario");
    if let Ok(Ok(mut reference)) = primary {
        let _ = reference.release();
    }
    assert(matches!(token_reference::reference((-5i64) as u64, 0x8, 0, true), Ok(Err(0xC000_007C))), "token: sem impersonacao");
    assert(matches!(close::close(handle, Some(0)), Ok(0)) && tokens::get(system).is_some_and(|token| token.refs == references), "token: NtClose solta o token");
    // NtOpenThreadToken com impersonação ativa e com nível Anonymous.
    let output = guest::alloc_bytes(8);
    let thread = process::get_current_thread();
    assert(matches!(th::open_thread((-2i64) as u64, 0x8, false, 0x200, output, false), Ok(0xC000_007C)), "token: thread sem impersonacao");
    let duplicate = tokens::duplicate(system, 2, false, 2).unwrap_or(0);
    assert(thread_tokens::assign(thread, Some(duplicate), 2, false, false).is_ok(), "token: impersonacao atribuida");
    assert(matches!(th::open_thread((-2i64) as u64, 0x8, false, 0x200, output, false), Ok(0)), "token: NtOpenThreadToken");
    let opened = guest::read64(output);
    assert(th::resolve_native(opened).is_some_and(|data| data.native_pointer == duplicate), "token: handle do token de impersonacao");
    assert(matches!(close::close(opened, Some(0)), Ok(0)), "token: fecha o handle de impersonacao");
    assert(thread_tokens::assign(thread, Some(duplicate), 0, false, false).is_ok() && matches!(th::open_thread((-2i64) as u64, 0x8, false, 0x200, output, false), Ok(0xC000_00A6)), "token: nivel Anonymous");
    assert(thread_tokens::release(thread).is_ok() && thread_tokens::get(thread).is_none(), "token: impersonacao encerrada");
    let _ = tokens::release(duplicate);
    guest::free_bytes(output);
}

fn token_services(assert: Assert) {
    use crate::ntos::ob::close;
    use crate::ntos::se::token::{duplicate as duplicate_token, query as query_token, handles as th};
    let system = process::get_primary_token(process::get_system_process()).unwrap_or(0);
    let handle = th::create(system, 0xA, 0x200, false).unwrap_or(0);
    let output = guest::alloc_bytes(0x80);
    let returned = output + 0x70;
    let new_handle = output + 0x78;
    // TokenStatistics (classe 10).
    assert(matches!(query_token::query(handle, 10, output, 56, returned, 0), Ok(0)) && guest::read32(returned) == 56, "token: TokenStatistics");
    let record = tokens::get(system).unwrap();
    assert(guest::read64(output) == record.id && guest::read32(output + 24) == 1 && guest::read32(output + 40) == record.groups.len() as u32 && guest::read64(output + 48) == record.modified_id, "token: campos de TOKEN_STATISTICS");
    let (charged, available) = tokens::accounting(system).unwrap_or((0, 0));
    assert(guest::read32(output + 32) as u64 == charged && guest::read32(output + 36) as u64 == available, "token: memoria dinamica do token");
    assert(matches!(query_token::query(handle, 10, output, 8, returned, 0), Ok(0xC000_0023)) && guest::read32(returned) == 56, "token: buffer pequeno informa o tamanho");
    assert(matches!(query_token::query(handle, 0, output, 56, returned, 0), Ok(0xC000_0003)) && matches!(query_token::query(handle, 5, output, 56, returned, 0), Ok(0xC000_0002)), "token: classes recusadas e nao implementadas");
    // ZwDuplicateToken para um token de impersonação.
    assert(matches!(duplicate_token::duplicate(handle, 0, 0, false, 3, new_handle, 0), Ok(0xC000_000D)), "token: tipo de token invalido");
    assert(matches!(duplicate_token::duplicate(handle, 0, 0, false, 2, new_handle, 0), Ok(0)), "token: ZwDuplicateToken");
    let duplicated = guest::read64(new_handle);
    let copy = th::resolve_native(duplicated).map_or(0, |data| data.native_pointer);
    assert(copy != 0 && copy != system && tokens::with(copy, |token| (token.kind, token.user.clone())) == Some((2, record.user.clone())), "token: copia de impersonacao com a mesma identidade");
    assert(om_access(duplicated) == Some(0xA), "token: acesso herdado do handle de origem");
    assert(matches!(close::close(duplicated, Some(0)), Ok(0)) && !tokens::exists(copy), "token: copia liberada no ultimo handle");
    assert(matches!(close::close(handle, Some(0)), Ok(0)), "token: fecha o handle de origem");
    guest::free_bytes(output);
}

fn process_tokens_and_membership(assert: Assert) {
    use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
    use crate::ntos::ob::{close, process_reference};
    use crate::ntos::se::model;
    use crate::ntos::se::token::{open_process as open_process_token, capability_access as token_capability_access, handles as th, membership as token_membership};
    // Referência de processo por handle.
    let current = process::get_current_process();
    let referenced = process_reference::reference(u64::MAX, 0x1000, 0);
    assert(matches!(&referenced, Ok(Ok(reference)) if reference.pointer == current), "procref: -1 e o processo corrente");
    if let Ok(Ok(mut reference)) = referenced {
        assert(reference.release().is_ok() && reference.release().is_err(), "procref: liberacao unica");
    }
    assert(matches!(process_reference::reference((-2i64) as u64, 0x1000, 0), Ok(Err(0xC000_0024))), "procref: -2 nao e processo");
    let target = process::create_process(0x7C40, "phase3-token.exe", 0, None).unwrap_or(0);
    let thread = process::create_kernel_thread(target, 0x7C44, false, 0, None).unwrap_or(0);
    let handle = process::open_handle(target, 0x1000).unwrap_or(0) as u64;
    let referenced = process_reference::reference(handle, 0x1000, 1);
    assert(matches!(&referenced, Ok(Ok(reference)) if reference.pointer == target), "procref: handle de processo");
    if let Ok(Ok(mut reference)) = referenced {
        let _ = reference.release();
    }
    assert(matches!(process_reference::reference(handle, 0x400, 1), Ok(Err(0xC000_0022))), "procref: direito nao concedido em modo usuario");
    // NtOpenProcessToken pelo handle do processo.
    let output = guest::alloc_bytes(8);
    assert(matches!(open_process_token::open(handle, 0x8, 0x200, output, 0), Ok(0)), "token: NtOpenProcessToken");
    let token_handle = guest::read64(output);
    assert(th::resolve_native(token_handle).is_some_and(|data| Some(data.native_pointer) == process::get_primary_token(target)), "token: token primario do processo alvo");
    assert(matches!(open_process_token::open(handle, 0x8, 0x220, output, 0), Ok(0xC000_000D)), "token: OBJ_EXCLUSIVE recusado");
    assert(matches!(close::close(token_handle, Some(0)), Ok(0)) && matches!(close::close(handle, Some(0)), Ok(0)), "token: fecha os handles");
    let _ = process::terminate_process(target, 0);
    let _ = process::release_thread(thread);
    // Membership e capability pelo token real.
    let system = process::get_primary_token(process::get_system_process()).unwrap_or(0);
    let everyone = model::sid(1, &[0]);
    assert(token_membership::contains(system, Some(&everyone)) && !token_membership::contains(system, Some(&model::sid(5, &[99]))), "token: membership pelos grupos habilitados");
    assert(token_capability_access::permits_capability(system, None) && token_capability_access::permits_membership(system, None, 0) == false, "token: capability pela identidade");
    let sid_pointer = kernel_pool::allocate(16, AllocateOptions::default()).unwrap_or(0);
    guest::write_bytes(sid_pointer, &everyone);
    assert(token_membership::read_security_identifier(sid_pointer).as_deref() == Some(everyone.as_slice()) && token_membership::read_security_identifier(0x1000).is_none(), "token: SID de kernel capturado");
    let references = tokens::get(system).map_or(0, |token| token.refs);
    assert(matches!(token_membership::check(0, sid_pointer, output), Ok(0)) && guest::read8(output) == 1, "token: RtlCheckTokenMembership da identidade atual");
    let explicit = th::create(system, 0xA, 0x200, false).unwrap_or(0);
    assert(matches!(token_membership::check(explicit, sid_pointer, output), Ok(0)) && guest::read8(output) == 1, "token: membership por handle explicito");
    assert(matches!(close::close(explicit, Some(0)), Ok(0)) && tokens::get(system).is_some_and(|token| token.refs == references), "token: membership nao vaza referencias");
    let _ = kernel_pool::free(sid_pointer, None);
    guest::free_bytes(output);
}

fn descriptor_inheritance(assert: Assert) {
    use crate::ntos::se::inherit_descriptor::{assign, Captured};
    use crate::ntos::se::model::sid;
    let creator_owner = sid(3, &[0]);
    let mut ace = alloc::vec![0u8, 3, 20, 0];
    ace.extend_from_slice(&0x1000_0000u32.to_le_bytes());
    ace.extend_from_slice(&creator_owner);
    let mut acl = alloc::vec![2u8, 0, 28, 0, 1, 0, 0, 0];
    acl.extend_from_slice(&ace);
    let system = sid(5, &[18]);
    let parent = Captured { control: 4, owner: system.clone(), group: system.clone(), dacl: Some(acl), sacl: None };
    let creator = Captured { control: 0, owner: system.clone(), group: system.clone(), dacl: None, sacl: None };
    let mapping = [0x12_0089, 0x12_0116, 0x12_00A0, 0x1F_01FF];
    let assigned = assign(Some(&parent), &creator, &mapping, 0, true);
    assert(matches!(&assigned, Ok(Ok(_))), "heranca: atribuicao");
    let child = match assigned { Ok(Ok(child)) => child, _ => Captured::default() };
    let dacl = child.dacl.clone().unwrap_or_default();
    assert(child.control & 4 != 0 && dacl.len() == 8 + 20 + 20 && u16::from_le_bytes([dacl[4], dacl[5]]) == 2, "heranca: DACL com a efetiva e a INHERIT_ONLY");
    let effective = &dacl[8..28];
    assert(effective[1] == 0 && u32::from_le_bytes([effective[4], effective[5], effective[6], effective[7]]) == 0x1F_01FF && effective[8..20] == system[..], "heranca: CREATOR OWNER vira o dono com GENERIC_ALL mapeado");
    let inherit_only = &dacl[28..48];
    assert(inherit_only[1] == 0x0B && u32::from_le_bytes([inherit_only[4], inherit_only[5], inherit_only[6], inherit_only[7]]) == 0x1000_0000 && inherit_only[8..20] == creator_owner[..], "heranca: regra preservada para os descendentes");
    let protected_child = Captured { control: 0x1004, owner: system.clone(), group: system.clone(), dacl: None, sacl: None };
    assert(matches!(assign(Some(&parent), &protected_child, &mapping, 0, true), Ok(Ok(result)) if result.dacl.is_none() && result.control & 0x1004 == 0x1004), "heranca: DACL protegida e nula nao herda");
    let null_dacl = Captured { control: 4, owner: system.clone(), group: system.clone(), dacl: None, sacl: None };
    assert(matches!(assign(Some(&parent), &null_dacl, &mapping, 1, true), Ok(Err(0xC000_0077))), "heranca: DACL nula com heranca automatica");
    assert(assign(None, &Captured::default(), &mapping, 0, true).is_err(), "heranca: exige owner e group");
}

fn descriptor_queries(assert: Assert) {
    use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
    use crate::ntos::se::{descriptor, object_security, policy_descriptor, query_descriptor};
    let policy = object_security::directory(u64::MAX - 9);
    let owned = policy_descriptor::capture(&policy);
    assert(owned.as_ref().is_ok_and(|owned| owned.control & 0x14 == 0x14 && owned.owner.as_ref() == Some(&policy.owner) && owned.dacl.as_ref().is_some_and(|dacl| dacl[0] == 2 && u16::from_le_bytes([dacl[4], dacl[5]]) == 2)), "se: descritor da politica do objeto");
    let owned = owned.unwrap_or_default();
    let sacl = owned.sacl.clone().unwrap_or_default();
    assert(sacl.len() == 28 && sacl[8] == 17 && u32::from_le_bytes([sacl[24], sacl[25], sacl[26], sacl[27]]) == 0x2000, "se: ACE de integridade NO_WRITE_UP");
    let buffer = kernel_pool::allocate(0x200, AllocateOptions { zero: true, ..AllocateOptions::default() }).unwrap_or(0);
    let small = query_descriptor::query_descriptor(Some(&owned), 7, buffer, 20);
    assert(small.status == 0xC000_0023 && small.needed > 20, "se: BUFFER_TOO_SMALL informa LengthNeeded");
    let result = query_descriptor::query_descriptor(Some(&owned), 7, buffer, 0x200);
    assert(result.status == 0 && descriptor::valid(buffer) && descriptor::valid_relative(buffer, result.needed as u32, 3), "se: descritor relativo consultado");
    assert(descriptor::control(buffer) & 0x8000 != 0 && descriptor::control(buffer) & 16 == 0, "se: SACL fora sem pedido");
    let read = query_descriptor::read_descriptor(buffer);
    assert(read.as_ref().is_some_and(|read| read.owner == owned.owner && read.dacl == owned.dacl && read.sacl.is_none()), "se: leitura de volta dos componentes");
    let label = query_descriptor::query_descriptor(Some(&owned), 0x10, buffer, 0x200);
    let read = query_descriptor::read_descriptor(buffer).unwrap_or_default();
    assert(label.status == 0 && read.sacl.as_ref().is_some_and(|sacl| sacl.len() == 28 && sacl[8] == 17), "se: LABEL_SECURITY_INFORMATION");
    let audit = query_descriptor::query_descriptor(Some(&owned), 8, buffer, 0x200);
    let read = query_descriptor::read_descriptor(buffer).unwrap_or_default();
    assert(audit.status == 0 && read.sacl.as_ref().is_some_and(|sacl| sacl.len() == 8 && sacl[4] == 0), "se: auditoria sem o rotulo");
    let backup = query_descriptor::select_descriptor(Some(&owned), 0x10000);
    assert(backup.information == 0x1_007F, "se: BACKUP_SECURITY_INFORMATION sem confianca nem filtro");
    let _ = kernel_pool::free(buffer, None);
}

fn capabilities_and_anonymous(assert: Assert) {
    use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
    use crate::ntos::rtl::sha256;
    use crate::ntos::se::token::anonymous as anonymous_tokens;
    use crate::ntos::se::capability::{identifiers as capability_identifiers, token_checks as capability_token_checks};
    use crate::ntos::se::model;
    let area = kernel_pool::allocate(0x200, AllocateOptions { zero: true, ..AllocateOptions::default() }).unwrap_or(0);
    let name = area;
    let text = area + 0x10;
    let group = area + 0x80;
    let capability = area + 0xC0;
    let output = area + 0x1F0;
    let write_name = |value: &str| {
        let units: alloc::vec::Vec<u16> = value.encode_utf16().collect();
        for (index, &unit) in units.iter().enumerate() {
            guest::write16(text + index as u64 * 2, unit);
        }
        guest::write16(name, units.len() as u16 * 2);
        guest::write16(name + 2, units.len() as u16 * 2);
        guest::write64(name + 8, text);
    };
    // Nome legado: SID de capability S-1-15-3-1; o de grupo continua por hash.
    write_name("internetClient");
    assert(matches!(capability_identifiers::derive(name, group, capability), Ok(0)), "cap: derivacao de nome legado");
    assert(guest::read_bytes(capability, 16) == model::sid(15, &[3, 1]), "cap: S-1-15-3-1 para internetClient");
    let upper: alloc::vec::Vec<u8> = "INTERNETCLIENT".encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
    let digest = sha256::hash_bytes(&upper);
    assert(guest::read8(group + 1) == 9 && guest::read8(group + 7) == 5 && guest::read32(group + 8) == 32 && guest::read_bytes(group + 12, 32) == digest, "cap: SID de grupo S-1-5-32 por SHA-256 do nome em maiusculas");
    assert(capability_token_checks::is_capability_identifier(capability) && !capability_token_checks::is_capability_identifier(group), "cap: RtlIsCapabilitySid");
    // Nome por hash: S-1-15-3-1024-<digest>.
    write_name("phase3Capability");
    assert(matches!(capability_identifiers::derive(name, group, capability), Ok(0)), "cap: derivacao por hash");
    let upper: alloc::vec::Vec<u8> = "PHASE3CAPABILITY".encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
    assert(guest::read8(capability + 1) == 10 && guest::read32(capability + 12) == 1024 && guest::read_bytes(capability + 16, 32) == sha256::hash_bytes(&upper), "cap: SID de capability por hash");
    assert(capability_identifiers::derive(0, group, capability).is_err(), "cap: ponteiro nulo e fast fail");
    // Verificações de token (modo kernel concede pela regra medida).
    assert(matches!(capability_token_checks::check_capability(0, capability, output), Ok(0)) && guest::read8(output) == 1, "cap: RtlCheckTokenCapability em modo kernel");
    assert(matches!(capability_token_checks::check_capability(0, group, output), Ok(0xC000_000D)) && guest::read8(output) == 0, "cap: SID que nao e capability");
    assert(matches!(capability_token_checks::check_membership(0, group, 4, output), Ok(0xC000_000D)), "cap: flags invalidas de membership");
    // Tokens anônimos do sistema.
    let system = process::get_primary_token(process::get_system_process()).unwrap_or(0);
    let anonymous = anonymous_tokens::acquire(system, true, 0, -1);
    assert(matches!(anonymous, Ok((_, true))), "anon: variante compartilhada com CopyOnOpen");
    let (shared, _) = anonymous.unwrap_or((0, false));
    assert(tokens::with(shared, |token| token.user == model::sid(5, &[7]) && token.authentication_id == 0x3E6 && token.groups.iter().any(|group| group.sid == model::sid(1, &[0]))) == Some(true), "anon: identidade ANONYMOUS LOGON com Everyone");
    assert(matches!(anonymous_tokens::acquire(system, true, 0, -1), Ok((again, true)) if again == shared), "anon: corpo permanente reutilizado");
    let _ = tokens::release(shared);
    let silo = anonymous_tokens::acquire(system, true, 0x1234, 5);
    assert(matches!(silo, Ok((token, false)) if token != shared && tokens::with(token, |record| (record.server_silo, record.session_id, record.groups.len())) == Some((0x1234, 5, 1))), "anon: token privado do server silo sem Everyone");
    if let Ok((token, _)) = silo {
        let _ = tokens::release(token);
    }
    let _ = tokens::release(shared);
    let _ = kernel_pool::free(area, None);
}

fn process_accessors(assert: Assert) {
    use crate::ntos::ps::{lookup_thread, pool_quota, process_context, session};
    use crate::ntos::ps::silo::query as silo_query;
    use crate::ntos::inc::nt_abi::ejob;
    // Silos: o host é NULL; -3 herda do processo dono.
    let system = process::get_system_process();
    assert(silo_query::current_silo() == 0 && silo_query::current_server_silo() == 0, "silo: host sem silo");
    let previous = silo_query::attach(0x1234);
    assert(previous == silo_query::INHERIT && silo_query::current_silo() == 0x1234, "silo: PsAttachSiloToCurrentThread");
    silo_query::detach(previous);
    let job = guest::alloc_bytes(ejob::SIZE);
    let output = guest::alloc_bytes(8);
    assert(silo_query::get_job_silo(0, output) == 0xC000_000D && silo_query::get_job_silo(job, output) == 0xC000_0509, "silo: job sem container");
    guest::write32(job + ejob::FLAGS, 0x4000_0000);
    assert(silo_query::get_job_silo(job, output) == 0 && guest::read64(output) == job, "silo: PsGetJobSilo");
    guest::write64(output, 0xFFFF);
    assert(silo_query::get_job_server_silo(job, output) == 0 && guest::read64(output) == 0, "silo: job sem server silo");
    assert(session::query(system) == 0 && session::debug_port(system) == 0, "ps: sessao e porta de debug do System");
    // Processo de teste para anexação, quota e lookup.
    let target = process::create_process(0x7C50, "phase3-quota.exe", 0, None).unwrap_or(0);
    let thread = process::create_kernel_thread(target, 0x7C54, false, 0, None).unwrap_or(0);
    let inside = process_context::with_process(target, process::get_current_process);
    assert(matches!(inside, Ok(current) if current == target) && process::get_current_process() == system, "ps: anexacao com escopo ao processo");
    let references = process::reference_count(target).unwrap_or(0);
    let charged = pool_quota::charge(target, false, 0x100);
    assert(matches!(&charged, Ok(Ok(Some(_)))) && process::reference_count(target) == Some(references + 1), "quota: cobranca retem o EPROCESS");
    let snapshot = pool_quota::snapshot(target).unwrap_or([pool_quota::QuotaSnapshot { usage: 0, peak: 0, limit: 0 }; 2]);
    assert(snapshot[0].usage == 0x100 && snapshot[0].peak == 0x100 && snapshot[1].usage == 0, "quota: uso e pico no EPROCESS");
    assert(pool_quota::set_limits(target, 0x80, pool_quota::MAXIMUM_QUOTA).is_err() && pool_quota::set_limits(target, 0x200, pool_quota::MAXIMUM_QUOTA).is_ok(), "quota: limite abaixo do uso recusado");
    assert(matches!(pool_quota::charge(target, false, 0x200), Ok(Err(0xC000_0044))), "quota: STATUS_QUOTA_EXCEEDED");
    if let Ok(Ok(Some(quota))) = charged {
        (quota.release)(quota.process_pointer, quota.paged, quota.bytes);
    }
    let snapshot = pool_quota::snapshot(target).unwrap_or([pool_quota::QuotaSnapshot { usage: 1, peak: 0, limit: 0 }; 2]);
    assert(snapshot[0].usage == 0 && snapshot[0].peak == 0x100 && process::reference_count(target) == Some(references), "quota: devolucao conserva o pico");
    assert(matches!(pool_quota::charge(system, true, 0x100), Ok(Ok(None))), "quota: System nao e cobrado");
    // PsLookupThreadByThreadId.
    assert(matches!(lookup_thread::lookup(0x7C54, output), Ok(0)) && guest::read64(output) == thread && process::thread_reference_count(thread) == Some(1), "ps: PsLookupThreadByThreadId");
    let _ = process::dereference_thread(thread);
    assert(matches!(lookup_thread::lookup(0x7FF8, output), Ok(0xC000_000B)), "ps: id de thread inexistente");
    let _ = process::terminate_process(target, 0);
    let _ = process::release_thread(thread);
    guest::free_bytes(job);
    guest::free_bytes(output);
}

static ENUMERATED: AtomicU64 = AtomicU64::new(0);

extern "win64" fn enumerate_routine(_process: u64, _thread: u64, stop_after: u64) -> u32 {
    let count = ENUMERATED.fetch_add(1, Ordering::SeqCst) + 1;
    if stop_after != 0 && count >= stop_after { 0xC000_0001 } else { 0 }
}

fn process_thread_enumeration(assert: Assert) {
    use crate::ntos::ps::enum_process_threads as enumeration;
    let target = process::create_process(0x7C60, "phase3-enum.exe", 0, None).unwrap_or(0);
    let threads: alloc::vec::Vec<u64> = (0..3).map(|index| process::create_kernel_thread(target, 0x7C64 + index * 4, false, 0, None).unwrap_or(0)).collect();
    // PsGetNextProcessThread percorre a lista nativa na ordem de inserção.
    let mut cursor = 0;
    let mut visited = alloc::vec::Vec::new();
    loop {
        match enumeration::get_next(target, cursor) {
            Ok(0) => break,
            Ok(next) => {
                visited.push(next);
                cursor = next;
            }
            Err(_) => break,
        }
    }
    assert(visited == threads, "ps: PsGetNextProcessThread na ordem da lista");
    assert(threads.iter().all(|&thread| process::thread_reference_count(thread) == Some(0)), "ps: referencias anteriores devolvidas");
    let routine = enumerate_routine as extern "win64" fn(u64, u64, u64) -> u32 as usize as u64;
    ENUMERATED.store(0, Ordering::SeqCst);
    assert(matches!(enumeration::enumerate(target, routine, 0), Ok(0)) && ENUMERATED.load(Ordering::SeqCst) == 3, "ps: PsEnumProcessThreads visita todas");
    ENUMERATED.store(0, Ordering::SeqCst);
    assert(matches!(enumeration::enumerate(target, routine, 2), Ok(0xC000_0001)) && ENUMERATED.load(Ordering::SeqCst) == 2, "ps: NTSTATUS de erro encerra a enumeracao");
    assert(threads.iter().all(|&thread| process::thread_reference_count(thread) == Some(0)), "ps: enumeracao nao vaza referencias");
    assert(enumeration::enumerate(target, 0, 0).is_err() && enumeration::get_next(target, threads[0]).is_err(), "ps: callback nula e anterior sem referencia");
    let _ = process::terminate_process(target, 0);
    for thread in threads {
        let _ = process::release_thread(thread);
    }
    assert(!process::is_process(target), "ps: processo da enumeracao recolhido");
}

static SILO_CLEANUPS: AtomicU64 = AtomicU64::new(0);

extern "win64" fn silo_cleanup(_context: u64) {
    SILO_CLEANUPS.fetch_add(1, Ordering::SeqCst);
}

fn silo_contexts(assert: Assert) {
    use crate::ntos::ob::open_pointer;
    use crate::ntos::ps::silo::contexts;
    use crate::ntos::inc::nt_abi::ejob;
    let scratch = guest::alloc_bytes(0x40);
    let slot_out = scratch;
    let output = scratch + 8;
    let cleanup = silo_cleanup as extern "win64" fn(u64) as usize as u64;
    SILO_CLEANUPS.store(0, Ordering::SeqCst);
    assert(contexts::alloc_slot(slot_out) == 0, "silo: PsAllocSiloContextSlot");
    let slot = guest::read32(slot_out);
    assert(matches!(contexts::create(0, 0x20, 7, cleanup, output), Ok(0xC000_000D)), "silo: tipo de pool invalido");
    assert(matches!(contexts::create(0, 0x20, 0x200, cleanup, output), Ok(0)), "silo: PsCreateSiloContext");
    let context = guest::read64(output);
    assert(contexts::ref_count(context) == 1 && open_pointer::describe(context).is_some(), "silo: contexto com uma referencia e slot no open-pointer");
    // Inserção, consulta, permanência e remoção no silo host.
    assert(matches!(contexts::insert(0, slot, context, false), Ok(0)) && contexts::ref_count(context) == 2, "silo: insercao retem o contexto");
    assert(matches!(contexts::insert(0, slot, context, false), Ok(0xC000_00BB)) && contexts::ref_count(context) == 2, "silo: slot ocupado");
    assert(matches!(contexts::get_context(0, slot, output, false), Ok(0)) && guest::read64(output) == context && contexts::ref_count(context) == 3, "silo: PsGetSiloContext referencia");
    let _ = contexts::dereference(context);
    assert(matches!(contexts::get_context(0, slot, output, true), Ok(0xC000_00BB)), "silo: contexto ainda nao permanente");
    assert(matches!(contexts::make_permanent(0, slot), Ok(0)) && matches!(contexts::get_context(0, slot, output, true), Ok(0)) && contexts::ref_count(context) == 2, "silo: PsGetPermanentSiloContext sem referencia");
    assert(matches!(contexts::remove(0, slot, 0, false), Ok(0xC000_00BB)) && matches!(contexts::remove(0, slot, 0, true), Ok(0)) && contexts::ref_count(context) == 1, "silo: remocao forcada de permanente");
    assert(matches!(contexts::get_context(0, 300, output, false), Ok(0xC000_000D)), "silo: slot fora do intervalo");
    assert(matches!(contexts::free_slot(slot), Ok(0)) && contexts::release_slot(slot) == 0xC000_000D, "silo: PsFreeSiloContextSlot");
    let _ = contexts::dereference(context);
    if contexts::exists(context) {
        crate::ntos::io::work_items::run_queue();
    }
    assert(!contexts::exists(context) && SILO_CLEANUPS.load(Ordering::SeqCst) == 1, "silo: ultima referencia chama o cleanup");
    // Tabela própria de um silo, desmontada com seus contextos.
    let job = guest::alloc_bytes(ejob::SIZE);
    let table = contexts::create_table(job).unwrap_or(0);
    assert(table != 0 && guest::read64(job + ejob::SILO_CONTEXT) == table && contexts::create_table(job).is_err(), "silo: tabela de contextos do silo");
    let _ = contexts::alloc_slot(slot_out);
    let slot = guest::read32(slot_out);
    let _ = contexts::create(job, 0x10, 1, cleanup, output);
    let owned = guest::read64(output);
    assert(matches!(contexts::insert(0, slot, owned, false), Ok(0xC000_000D)), "silo: contexto de outro silo recusado");
    assert(matches!(contexts::insert(job, slot, owned, true), Ok(0)), "silo: insercao permanente no silo");
    let _ = contexts::dereference(owned);
    assert(contexts::destroy_table(job).is_ok() && guest::read64(job + ejob::SILO_CONTEXT) == 0, "silo: desmontagem da tabela");
    if contexts::exists(owned) {
        crate::ntos::io::work_items::run_queue();
    }
    assert(!contexts::exists(owned) && SILO_CLEANUPS.load(Ordering::SeqCst) == 2 && contexts::release_slot(slot) == 0, "silo: contexto do silo destruido com a tabela");
    guest::free_bytes(job);
    guest::free_bytes(scratch);
}

static MONITOR_CREATES: AtomicU64 = AtomicU64::new(0);
static MONITOR_TERMINATES: AtomicU64 = AtomicU64::new(0);
static MONITOR_CREATE_STATUS: AtomicU64 = AtomicU64::new(0);

extern "win64" fn monitor_create(_silo: u64) -> u32 {
    MONITOR_CREATES.fetch_add(1, Ordering::SeqCst);
    MONITOR_CREATE_STATUS.load(Ordering::SeqCst) as u32
}

extern "win64" fn monitor_terminate(_silo: u64) {
    MONITOR_TERMINATES.fetch_add(1, Ordering::SeqCst);
}

fn silo_monitors(assert: Assert) {
    use crate::ntos::ps::silo::monitors;
    let scratch = guest::alloc_bytes(0x80);
    let registration = scratch;
    let name = scratch + 0x20;
    let text = scratch + 0x30;
    let output = scratch + 0x60;
    for (index, unit) in "Phase3Mon".encode_utf16().enumerate() {
        guest::write16(text + index as u64 * 2, unit);
    }
    guest::write16(name, 18);
    guest::write16(name + 2, 18);
    guest::write64(name + 8, text);
    guest::write8(registration, 1);
    guest::write8(registration + 1, 1); // CreateAsHost
    guest::write8(registration + 2, 1); // MonitorExistingSilos
    guest::write64(registration + 8, name);
    guest::write64(registration + 0x10, 0);
    guest::write64(registration + 0x18, 0);
    assert(matches!(monitors::register(registration, output), Ok(0xC000_000D)), "monitor: sem callbacks recusado");
    guest::write64(registration + 0x10, monitor_create as extern "win64" fn(u64) -> u32 as usize as u64);
    guest::write64(registration + 0x18, monitor_terminate as extern "win64" fn(u64) as usize as u64);
    MONITOR_CREATES.store(0, Ordering::SeqCst);
    MONITOR_TERMINATES.store(0, Ordering::SeqCst);
    MONITOR_CREATE_STATUS.store(0, Ordering::SeqCst);
    assert(matches!(monitors::register(registration, output), Ok(0)), "monitor: PsRegisterSiloMonitor");
    let monitor = guest::read64(output);
    assert(monitors::get_slot(monitor).is_ok_and(|slot| slot < 288) && crate::ntos::rtl::guest_strings::read_unicode_string(monitor + 0x28) == "Phase3Mon", "monitor: slot e nome copiado");
    assert(matches!(monitors::start(monitor), Ok(0)) && MONITOR_CREATES.load(Ordering::SeqCst) == 1, "monitor: CREATE do host na partida");
    assert(matches!(monitors::start(monitor), Ok(0)) && MONITOR_CREATES.load(Ordering::SeqCst) == 1, "monitor: segunda partida inerte");
    assert(matches!(monitors::unregister(monitor), Ok(0)) && MONITOR_TERMINATES.load(Ordering::SeqCst) == 1, "monitor: TERMINATE do host no unregister");
    assert(monitors::get_slot(monitor).is_err(), "monitor: registro liberado");
    // CREATE do host com falha: TERMINATE desfaz e o status volta ao chamador.
    MONITOR_CREATE_STATUS.store(0xC000_0001, Ordering::SeqCst);
    assert(matches!(monitors::register(registration, output), Ok(0)), "monitor: novo registro");
    let failing = guest::read64(output);
    assert(matches!(monitors::start(failing), Ok(0xC000_0001)) && MONITOR_TERMINATES.load(Ordering::SeqCst) == 2, "monitor: falha do CREATE desfeita com TERMINATE");
    assert(matches!(monitors::unregister(failing), Ok(0)) && MONITOR_TERMINATES.load(Ordering::SeqCst) == 2, "monitor: monitor nao ligado nao recebe TERMINATE");
    guest::free_bytes(scratch);
}

static DESTROYED_OBJECT: AtomicU64 = AtomicU64::new(0);

fn destroy_driver(pointer: u64) {
    DESTROYED_OBJECT.store(pointer, Ordering::SeqCst);
}

fn destroy_section(pointer: u64) -> Result<(), crate::rtl::KernelError> {
    DESTROYED_OBJECT.store(pointer, Ordering::SeqCst);
    Ok(())
}

fn driver_and_section_objects(assert: Assert) {
    use crate::ntos::ob::{close, object_manager as om, open_pointer};
    use crate::ntos::ob::objects::{driver as driver_objects, section as section_objects};
    use crate::ntos::ob::object_manager::ObjectData;
    // DRIVER_OBJECT: o nome some na retirada, o corpo vive até o último handle.
    let driver = guest::alloc_bytes(0x150);
    let node = om::create_object("\\Driver", "Phase3Drv", "Driver", Some(ObjectData::pointer(driver)));
    assert(node.is_ok(), "driver: no no namespace");
    assert(matches!(driver_objects::register(node.unwrap(), destroy_driver), Ok(pointer) if pointer == driver), "driver: registro do DRIVER_OBJECT");
    assert(open_pointer::describe(driver).is_some_and(|item| item.object_type.name == "Driver"), "driver: slot Driver no open-pointer");
    assert(driver_objects::access(0x0040_0000).is_none() && driver_objects::access(0x8000_0000).is_some(), "driver: mapeamento de direitos");
    let by_name = om::open("\\Driver\\Phase3Drv").unwrap_or(0);
    let by_pointer = driver_objects::open_handle(driver, 0x8000_0000, 0x200).unwrap_or(0);
    assert(by_name != 0 && by_pointer & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000 && driver_objects::reference_count(driver) == Some(2), "driver: handles por nome e por ponteiro retem o corpo");
    DESTROYED_OBJECT.store(0, Ordering::SeqCst);
    assert(driver_objects::retire(driver).is_ok() && driver_objects::is_driver(driver) && driver_objects::retire(driver).is_err(), "driver: retirada com handles abertos adia a destruicao");
    assert(driver_objects::open_handle(driver, 0x8000_0000, 0).ok() == Some(0), "driver: retirado nao abre novos handles");
    assert(matches!(close::close(by_pointer, Some(0)), Ok(0)) && matches!(om::close(by_name as u32), Ok(true)), "driver: fecha os handles");
    assert(!driver_objects::is_driver(driver) && DESTROYED_OBJECT.load(Ordering::SeqCst) == driver, "driver: destruido no ultimo handle");
    let _ = om::unlink("\\Driver\\Phase3Drv");
    guest::free_bytes(driver);
    // Seção: handles, vistas e permanência retêm o corpo de forma independente.
    let state = section_objects::SectionState { size: 0x2000, name: alloc::string::String::from("Phase3Sec"), ..section_objects::SectionState::default() };
    let section = section_objects::register(state.clone(), destroy_section).unwrap_or(0);
    assert(section != 0 && guest::read64(section + 0x30) == 0x2000 && open_pointer::describe(section).is_some_and(|item| item.object_type.name == "Section"), "secao: corpo com SizeOfSection");
    let handle = section_objects::open_handle(section, 0x4, 0).unwrap_or(0);
    assert(handle != 0 && section_objects::state(section).is_some_and(|state| state.handles == 1), "secao: handle conta no estado");
    let _ = section_objects::update(section, |state| state.views += 1);
    assert(matches!(om::close(handle as u32), Ok(true)) && section_objects::is_section(section), "secao: vista mapeada retem a secao");
    let _ = section_objects::update(section, |state| state.views -= 1);
    assert(section_objects::collect(section).is_ok() && !section_objects::is_section(section) && DESTROYED_OBJECT.load(Ordering::SeqCst) == section, "secao: destruida sem handles nem vistas");
    let permanent = section_objects::register(state, destroy_section).unwrap_or(0);
    let _ = section_objects::update(permanent, |state| state.permanent = true);
    assert(section_objects::reference(permanent) == Some(1) && matches!(section_objects::dereference(permanent), Ok(Some(0))) && section_objects::is_section(permanent), "secao: permanente sobrevive sem referencias");
    let _ = section_objects::update(permanent, |state| state.permanent = false);
    assert(section_objects::collect(permanent).is_ok() && !section_objects::is_section(permanent), "secao: temporaria recolhida");
}

static FILE_EVENTS: AtomicU64 = AtomicU64::new(0);

struct TestSource;

impl crate::ntos::ob::objects::file::FileSource for TestSource {
    fn name(&self) -> &str {
        "\\SelfTest\\image.sys"
    }
    fn size(&self) -> u64 {
        4
    }
    fn read_at(&self, _offset: u64, length: usize) -> Result<alloc::vec::Vec<u8>, crate::rtl::KernelError> {
        Ok(alloc::vec![0x4D; length])
    }
    fn acquire(&self) {
        FILE_EVENTS.fetch_add(0x100, Ordering::SeqCst);
    }
    fn release(&self) {
        FILE_EVENTS.fetch_add(0x1000, Ordering::SeqCst);
    }
}

fn file_objects(assert: Assert) {
    use crate::ntos::ob::objects::file::{self as files, FileCallbacks};
    use crate::ntos::ob::{close, open_pointer};
    use crate::ntos::inc::nt_abi::file_object as layout;
    let file = files::create(0, "\\Phase3\\a.txt").unwrap_or(0);
    assert(file != 0 && guest::read16(file) == 5 && crate::ntos::rtl::guest_strings::read_unicode_string(file + layout::FILE_NAME) == "\\Phase3\\a.txt", "file: FILE_OBJECT com nome UTF-16");
    assert(guest::read64(file + layout::IRP_LIST) == file + layout::IRP_LIST && files::reference_count(file) == Some(1), "file: lista de IRPs vazia e referencia do criador");
    FILE_EVENTS.store(0, Ordering::SeqCst);
    let callbacks = FileCallbacks {
        cleanup: Some(alloc::sync::Arc::new(|| {
            FILE_EVENTS.fetch_add(1, Ordering::SeqCst);
            0
        })),
        close: Some(alloc::sync::Arc::new(|| {
            FILE_EVENTS.fetch_add(0x10, Ordering::SeqCst);
        })),
        destroy: Some(alloc::sync::Arc::new(|| {
            FILE_EVENTS.fetch_add(0x100, Ordering::SeqCst);
        })),
    };
    assert(files::set_callbacks(file, callbacks).is_ok(), "file: rotinas de vida");
    let output = guest::alloc_bytes(8);
    assert(matches!(open_pointer::open(file, 0, 0, 1, object_types::file_type().pointer, 0, output), Ok(0xC000_0128)), "file: sem handle o arquivo nao abre por ponteiro");
    assert(files::open_handle(file).is_ok() && guest::read32(file + layout::FLAGS) & 0x40000 != 0, "file: FO_HANDLE_CREATED");
    assert(matches!(open_pointer::open(file, 0, 0, 1, object_types::file_type().pointer, 0, output), Ok(0)), "file: abertura por ponteiro de arquivo aberto");
    let handle = guest::read64(output);
    assert(files::state(file).is_some_and(|state| state.0 == 2) && matches!(close::close(handle, Some(0)), Ok(0)), "file: handle por ponteiro conta e fecha");
    assert(matches!(files::close_handle(file), Ok(0)) && FILE_EVENTS.load(Ordering::SeqCst) == 1 && guest::read32(file + layout::FLAGS) & 0x4000 != 0, "file: ultimo handle executa CLEANUP");
    assert(matches!(open_pointer::open(file, 0, 0, 1, object_types::file_type().pointer, 0, output), Ok(0xC000_0128)), "file: arquivo limpo recusa abertura");
    assert(matches!(files::dereference(file), Ok(Some(0))) && FILE_EVENTS.load(Ordering::SeqCst) == 0x111 && !files::is_file(file), "file: ultima referencia executa CLOSE e destroy");
    // Fonte exata de imagem retida pelo FILE_OBJECT.
    FILE_EVENTS.store(0, Ordering::SeqCst);
    let sourced = files::create_source(alloc::sync::Arc::new(TestSource)).unwrap_or(0);
    assert(sourced != 0 && FILE_EVENTS.load(Ordering::SeqCst) == 0x100 && files::source(sourced).is_some_and(|source| source.size() == 4 && source.read_at(0, 2).ok() == Some(alloc::vec![0x4D, 0x4D])), "file: fonte adquirida e legivel");
    assert(matches!(files::dereference(sourced), Ok(Some(0))) && FILE_EVENTS.load(Ordering::SeqCst) == 0x1100, "file: fonte liberada com o FILE_OBJECT");
    assert(files::access(0x8000_0000) & 0x8000_0000 == 0 && files::access(0x8000_0000) != 0, "file: mapeamento de GENERIC_READ");
    guest::free_bytes(output);
}

static DEVICE_EVENTS: AtomicU64 = AtomicU64::new(0);

fn device_unlinked(_pointer: u64) {
    DEVICE_EVENTS.fetch_add(1, Ordering::SeqCst);
}

fn device_destroyed(_pointer: u64) {
    DEVICE_EVENTS.fetch_add(0x10, Ordering::SeqCst);
}

fn device_objects(assert: Assert) {
    use crate::ntos::ob::objects::{device as devices, driver as driver_objects};
    use crate::ntos::ob::object_manager as om;
    use crate::ntos::ob::object_manager::ObjectData;
    let driver = guest::alloc_bytes(0x150);
    let node = om::create_object("\\Driver", "Phase3Dev", "Driver", Some(ObjectData::pointer(driver))).unwrap_or(0);
    let _ = driver_objects::register(node, destroy_driver);
    let lower = guest::alloc_bytes(0x150);
    let upper = guest::alloc_bytes(0x150);
    for &device in &[lower, upper] {
        guest::write64(device + 8, driver);
    }
    guest::write64(driver + 8, lower);
    guest::write64(lower + 0x10, upper);
    guest::write8(lower + 0x4C, 1);
    DEVICE_EVENTS.store(0, Ordering::SeqCst);
    assert(devices::register(lower, Some(device_destroyed), Some(device_unlinked)).is_ok() && devices::register(upper, Some(device_destroyed), Some(device_unlinked)).is_ok(), "device: registro de dois DEVICE_OBJECT");
    assert(guest::read16(devices::extension(lower)) == 13 && guest::read64(devices::extension(lower) + 8) == lower && driver_objects::reference_count(driver) == Some(2), "device: DEVOBJ_EXTENSION e retencao do driver");
    let output = guest::alloc_bytes(0x20);
    assert(matches!(devices::attach(upper, lower, output), Ok(attached) if attached == lower) && guest::read64(output) == lower, "device: IoAttachDeviceToDeviceStackSafe");
    assert(devices::top(lower) == upper && devices::base(upper) == lower && guest::read8(upper + 0x4C) == 2, "device: topo, base e StackSize");
    assert(devices::attach(upper, lower, output).is_err(), "device: anexacao repetida recusada");
    assert(matches!(devices::attached_reference(lower, false), Ok(found) if found == upper) && devices::reference_count(upper) == Some(2), "device: IoGetAttachedDeviceReference");
    let _ = devices::dereference(upper);
    assert(matches!(devices::get_lower(upper), Ok(found) if found == lower) && devices::reference_count(lower) == Some(2), "device: IoGetLowerDeviceObject");
    let _ = devices::dereference(lower);
    assert(matches!(devices::enumerate(driver, output, 8, output + 0x18), Ok(0xC000_0023)) && guest::read32(output + 0x18) == 2 && guest::read64(output) == lower, "device: enumeracao com buffer curto");
    let _ = devices::dereference(lower);
    // Exclusão adiada enquanto houver anexação.
    assert(matches!(devices::retire(lower), Ok(true)) && devices::is_device(lower) && DEVICE_EVENTS.load(Ordering::SeqCst) == 0, "device: IoDeleteDevice adiado com dispositivo anexado");
    assert(matches!(devices::detach(lower), Ok(found) if found == upper) && !devices::is_device(lower) && DEVICE_EVENTS.load(Ordering::SeqCst) == 0x11, "device: IoDetachDevice libera o inferior");
    assert(matches!(devices::retire(upper), Ok(true)) && !devices::is_device(upper) && DEVICE_EVENTS.load(Ordering::SeqCst) == 0x22, "device: exclusao do superior");
    assert(driver_objects::reference_count(driver) == Some(0) && driver_objects::retire(driver).is_ok() && !driver_objects::is_driver(driver), "device: driver liberado depois dos dispositivos");
    let _ = om::unlink("\\Driver\\Phase3Dev");
    for pointer in [driver, lower, upper, output] {
        guest::free_bytes(pointer);
    }
}

fn query_object_format(assert: Assert) {
    use crate::ntos::ob::object_types;
    use crate::ntos::ob::query_object_format::{self as qof, Formatted, ObjectInformation};
    let event = object_types::event_type();
    let file = object_types::file_type();
    let buffer = guest::alloc_bytes(0x200);
    let information = ObjectInformation {
        attributes: 3,
        object_flags: 0x10,
        access: 0x1F0003,
        handles: 2,
        references: 5,
        paged_charge: 0,
        nonpaged_charge: 0x58,
        name: Some("\\KernelObjects\\Phase3".into()),
        object_type: event.clone(),
        security_length: 0x5C,
        creation_time: 0x1234_5678,
    };
    const MISMATCH: u32 = 0xC000_0004;
    assert(qof::type_size(&event) == 120 && qof::type_size(&file) == 120, "queryobject: tamanho de OBJECT_TYPE_INFORMATION");
    assert(qof::format(&information, 0, buffer, 48, &[]) == Formatted { status: MISMATCH, needed: None }, "queryobject: basica exige 56 bytes");
    guest::write_bytes(buffer, &[0xCC; 56]);
    assert(qof::format(&information, 0, buffer, 56, &[]).status == 0 && guest::read32(buffer) == 0x13 && guest::read32(buffer + 4) == 0x1F0003 && guest::read32(buffer + 8) == 2 && guest::read32(buffer + 12) == 5 && guest::read32(buffer + 20) == 0x58 && guest::read32(buffer + 24) == 0 && guest::read32(buffer + 36) == 18 + 21 * 2 && guest::read32(buffer + 40) == 106 + 10 && guest::read32(buffer + 44) == 0x5C && guest::read64(buffer + 48) == 0x1234_5678, "queryobject: OBJECT_BASIC_INFORMATION");
    assert(qof::format(&information, 1, buffer, 16, &[]) == Formatted { status: MISMATCH, needed: Some(60) }, "queryobject: nome com buffer curto");
    assert(qof::format(&information, 1, buffer, 60, &[]).status == 0 && guest::read16(buffer) == 42 && guest::read16(buffer + 2) == 44 && guest::read64(buffer + 8) == buffer + 16 && guest::read16(buffer + 16) == b'\\' as u16 && guest::read16(buffer + 16 + 42) == 0, "queryobject: OBJECT_NAME_INFORMATION");
    let anonymous = ObjectInformation { name: None, ..information.clone() };
    assert(qof::format(&anonymous, 1, buffer, 16, &[]).status == 0 && guest::read16(buffer + 2) == 0 && guest::read64(buffer + 8) == 0, "queryobject: objeto sem nome");
    assert(qof::format(&information, 2, buffer, 100, &[]) == Formatted { status: MISMATCH, needed: Some(120) }, "queryobject: tipo com buffer curto");
    assert(qof::format(&information, 2, buffer, 128, &[]).status == 0 && guest::read16(buffer) == 10 && guest::read64(buffer + 8) == buffer + 104 && guest::read16(buffer + 104) == b'E' as u16 && guest::read32(buffer + 16) == guest::read32(event.pointer + 0x2C) && guest::read32(buffer + 64) == guest::read32(event.pointer + 0x48), "queryobject: OBJECT_TYPE_INFORMATION");
    let types = [event.clone(), file.clone()];
    assert(qof::format(&information, 3, buffer, 2, &types) == Formatted { status: MISMATCH, needed: Some(8) }, "queryobject: lista de tipos sem contador");
    assert(qof::format(&information, 3, buffer, 0xC0, &types) == Formatted { status: MISMATCH, needed: Some(248) } && guest::read32(buffer) == 2, "queryobject: lista de tipos curta informa o total");
    assert(qof::format(&information, 3, buffer, 0x200, &types) == Formatted { status: 0, needed: Some(248) } && guest::read16(buffer + 8 + 104) == b'E' as u16 && guest::read16(buffer + 128 + 104) == b'F' as u16, "queryobject: OBJECT_TYPES_INFORMATION");
    assert(qof::format(&information, 4, buffer, 1, &[]) == Formatted { status: MISMATCH, needed: Some(2) } && qof::format(&information, 4, buffer, 2, &[]).status == 0 && guest::read8(buffer) == 1 && guest::read8(buffer + 1) == 1, "queryobject: OBJECT_HANDLE_FLAG_INFORMATION");
    assert(qof::format(&information, 9, buffer, 0x200, &[]) == Formatted { status: 0xC000_0003, needed: None }, "queryobject: classe invalida");
    guest::free_bytes(buffer);
}

fn thread_and_file_handles(assert: Assert) {
    use crate::ntos::ob::{close, open_pointer};
    use crate::ntos::ob::handles::{file as file_handles, thread as thread_handles};
    use crate::ntos::ob::objects::file as files;
    const INVALID: u32 = 0xC000_0008;
    const MISMATCH: u32 = 0xC000_0024;
    const DENIED: u32 = 0xC000_0022;
    // Threads por handle.
    let current = process::get_current_thread();
    let referenced = thread_handles::reference((-2i64) as u64, 0, 0);
    assert(matches!(&referenced, Ok(Ok(reference)) if reference.pointer == current), "threadref: -2 e a thread corrente");
    if let Ok(Ok(mut reference)) = referenced {
        assert(reference.release().is_ok() && reference.release().is_err(), "threadref: liberacao unica");
    }
    assert(matches!(thread_handles::reference(u64::MAX, 0, 0), Ok(Err(MISMATCH))), "threadref: -1 nao e thread");
    let target = process::create_process(0x7C80, "phase3-threadref.exe", 0, None).unwrap_or(0);
    let thread = process::create_kernel_thread(target, 0x7C84, false, 0, None).unwrap_or(0);
    let output = guest::alloc_bytes(8);
    let thread_type = object_types::thread_type();
    assert(matches!(open_pointer::open(thread, 0, 0, 0x40, thread_type.pointer, 0, output), Ok(0)), "threadref: handle de thread");
    let handle = guest::read64(output);
    let references = process::reference_thread(thread).unwrap_or(0);
    let _ = process::dereference_thread(thread);
    let referenced = thread_handles::reference(handle, 0x40, 1);
    assert(matches!(&referenced, Ok(Ok(reference)) if reference.pointer == thread) && process::reference_thread(thread) == Some(references + 1), "threadref: handle retem a ETHREAD");
    let _ = process::dereference_thread(thread);
    if let Ok(Ok(mut reference)) = referenced {
        let _ = reference.release();
    }
    let missing = !om_access(handle).unwrap_or(0) & 0x1F_FFFF;
    assert(missing == 0 || matches!(thread_handles::reference(handle, missing, 1), Ok(Err(DENIED))), "threadref: direito nao concedido em modo usuario");
    let process_handle = process::open_handle(target, 0x1000).unwrap_or(0) as u64;
    assert(matches!(thread_handles::reference(process_handle, 0, 0), Ok(Err(MISMATCH))), "threadref: handle de processo nao e thread");
    assert(matches!(open_pointer::open(thread, 0x200, 0, 0x40, thread_type.pointer, 0, output), Ok(0)), "threadref: handle de kernel");
    let kernel_handle = guest::read64(output);
    assert(kernel_handle >> 31 == 0x1_FFFF_FFFF && matches!(thread_handles::reference(kernel_handle, 0, 1), Ok(Err(INVALID))), "threadref: handle de kernel recusado em modo usuario");
    let referenced = thread_handles::reference(kernel_handle, 0, 0);
    assert(matches!(&referenced, Ok(Ok(reference)) if reference.pointer == thread), "threadref: handle de kernel em modo kernel");
    if let Ok(Ok(mut reference)) = referenced {
        let _ = reference.release();
    }
    assert(matches!(thread_handles::reference(kernel_handle & 0x7FFF_FFFF, 0, 0), Ok(Err(INVALID))) && matches!(thread_handles::reference(0x7FFF_0000, 0, 0), Ok(Err(INVALID))), "threadref: indice baixo de handle de kernel e handle livre");
    for value in [handle, process_handle, kernel_handle] {
        let _ = close::close(value, Some(0));
    }
    let _ = process::terminate_process(target, 0);
    let _ = process::release_thread(thread);
    // Arquivos por handle e duplicação para System.
    let file = files::create(0, "\\Phase3\\dup.txt").unwrap_or(0);
    let file_type = object_types::file_type();
    let _ = files::open_handle(file);
    assert(matches!(open_pointer::open(file, 0, 0, 0x1, file_type.pointer, 0, output), Ok(0)), "fileref: handle de arquivo");
    let handle = guest::read64(output);
    let granted = om_access(handle).unwrap_or(0);
    let referenced = file_handles::reference(handle, 1);
    assert(matches!(&referenced, Ok(Ok(reference)) if reference.pointer == file && reference.access == granted) && files::reference_count(file) == Some(4), "fileref: referencia com direitos da entrada");
    if let Ok(Ok(mut reference)) = referenced {
        assert(reference.release().is_ok() && reference.release().is_err() && files::reference_count(file) == Some(3), "fileref: liberacao unica");
    }
    assert(matches!(file_handles::reference(u64::MAX, 0), Ok(Err(MISMATCH))) && matches!(file_handles::reference((-2i64) as u64, 0), Ok(Err(MISMATCH))), "fileref: pseudo-handles nao sao arquivos");
    assert(matches!(file_handles::duplicate_to_kernel(handle, 0x0020_0000), Ok(Err(DENIED))), "fileref: bits reservados recusados");
    let wider = file_type.valid_access & !granted;
    let wider = wider & wider.wrapping_neg();
    assert(wider == 0 || matches!(file_handles::duplicate_to_kernel(handle, wider), Ok(Err(DENIED))), "fileref: duplicacao nao amplia direitos");
    let duplicated = file_handles::duplicate_to_kernel(handle, granted);
    let copy = match duplicated {
        Ok(Ok(copy)) => copy,
        _ => 0,
    };
    assert(copy >> 31 == 0x1_FFFF_FFFF && files::state(file).is_some_and(|state| state.0 == 3) && om_access(copy) == Some(granted), "fileref: copia de kernel com handle proprio");
    assert(matches!(file_handles::reference(copy, 1), Ok(Err(INVALID))) && matches!(file_handles::reference(copy, 0), Ok(Ok(_))), "fileref: copia so em modo kernel");
    let _ = files::dereference(file);
    assert(file_handles::close_kernel(copy).is_ok() && files::state(file).is_some_and(|state| state.0 == 2) && file_handles::close_kernel(copy).is_err(), "fileref: fechamento da copia privada");
    let _ = files::cleanup(file);
    assert(matches!(file_handles::duplicate_to_kernel(handle, granted), Ok(Err(0xC000_0128))), "fileref: arquivo limpo nao duplica");
    assert(matches!(close::close(handle, Some(0)), Ok(0)) && matches!(files::close_handle(file), Ok(0)) && matches!(files::dereference(file), Ok(Some(0))) && !files::is_file(file), "fileref: corpo liberado no fim");
    guest::free_bytes(output);
}

fn unblock_and_quota_pool(assert: Assert) {
    use crate::ntos::ex::{pool_quota as quota_pool, unblock_push_lock as unblock};
    use crate::ntos::ke::dispatcher;
    use crate::ntos::mm::kernel_pool;
    use crate::ntos::ps::{pool_quota, process_context};
    // ExfUnblockPushLock: cadeia de dois blocos, o segundo em espera ativa.
    let lock = guest::alloc_bytes(8);
    let first = guest::alloc_bytes(0x40);
    let second = guest::alloc_bytes(0x40);
    let own = guest::alloc_bytes(0x40);
    for &block in &[first, second, own] {
        guest::write_bytes(block, &[0; 0x40]);
        dispatcher::initialize_event(block, 0, false);
    }
    guest::write64(lock, first);
    guest::write64(first + 0x18, second);
    guest::write32(second + 0x34, 2);
    assert(unblock::unblock(lock, 0).is_ok() && guest::read64(lock) == 0, "unblock: cadeia retirada da cabeca");
    assert(dispatcher::read_state(first) == 1 && dispatcher::read_state(second) == 0 && guest::read32(second + 0x34) == 0, "unblock: evento sinalizado e espera ativa dispensada");
    // O bloco do chamador já foi retirado por outro desbloqueador.
    guest::write32(own + 0x34, 2);
    let mut request = unblock::begin(lock, own);
    assert(matches!(request.poll(), Ok(None)) && guest::read32(own + 0x34) == 0, "unblock: espera o proprio bloco");
    dispatcher::set_event(own);
    assert(matches!(request.poll(), Ok(Some(()))), "unblock: conclui quando o bloco e sinalizado");
    assert(unblock::unblock(lock, own).is_ok(), "unblock: bloco sem espera ativa nao estaciona");
    for pointer in [lock, first, second, own] {
        guest::free_bytes(pointer);
    }
    // ExAllocatePoolWithQuotaTag cobrado do processo corrente.
    let tag = u32::from_le_bytes(*b"Qtst");
    let target = process::create_process(0x7CA0, "phase3-poolquota.exe", 0, None).unwrap_or(0);
    let thread = process::create_kernel_thread(target, 0x7CA4, false, 0, None).unwrap_or(0);
    let usage = |paged: usize| pool_quota::snapshot(target).map_or(u64::MAX, |snapshot| snapshot[paged].usage);
    let allocate_in = |pool_type: u32, bytes: u64| process_context::with_process(target, || quota_pool::allocate(pool_type, bytes, tag)).and_then(|result| result);
    let charged = allocate_in(0, 0x40).unwrap_or(0);
    let info = kernel_pool::info(charged);
    assert(charged != 0 && info.is_some_and(|info| info.quota_owner == target && usage(0) == info.rounded && info.rounded >= 0x50), "poolquota: bloco cobrado com cabecalho");
    assert(kernel_pool::free(charged, Some(tag)).is_ok() && usage(0) == 0, "poolquota: free devolve a quota");
    let aligned = allocate_in(5, 0x40).unwrap_or(0);
    assert(aligned != 0 && aligned % 64 == 0 && usage(1) != 0, "poolquota: pool paginavel alinhado ao cache");
    let _ = kernel_pool::free(aligned, Some(tag));
    let large = allocate_in(0, 0x2000).unwrap_or(0);
    assert(large != 0 && kernel_pool::info(large).is_some_and(|info| info.quota_owner == 0) && usage(0) == 0, "poolquota: bloco grande nao e cobrado");
    let _ = kernel_pool::free(large, Some(tag));
    let _ = pool_quota::set_limits(target, 0x10, pool_quota::MAXIMUM_QUOTA);
    assert(matches!(allocate_in(8, 0x40), Ok(0)), "poolquota: quota excedida com FAIL_INSTEAD_OF_RAISE");
    assert(matches!(allocate_in(0, 0x40), Err(error) if error.status == 0xC000_0044), "poolquota: quota excedida levanta STATUS_QUOTA_EXCEEDED");
    assert(usage(0) == 0, "poolquota: falha de quota libera o bloco");
    let system = quota_pool::allocate(0, 0x40, tag).unwrap_or(0);
    assert(system != 0 && kernel_pool::info(system).is_some_and(|info| info.quota_owner == 0), "poolquota: System nao e cobrado");
    let _ = kernel_pool::free(system, Some(tag));
    let _ = process::terminate_process(target, 0);
    let _ = process::release_thread(thread);
}

/// Destrava a entrada (bit 0) como ExUnlockHandleTableEntry.
fn unlock_entry(entry: u64) {
    loop {
        let low = guest::read64(entry);
        if guest::compare_exchange64(entry, low, low | 1).ok() == Some(low) {
            return;
        }
    }
}

/// Callback de ExEnumHandleTable: anota o handle, destrava e para no alvo
/// (contexto: +0 alvo, +8 quantidade, +0x10 handles vistos).
extern "win64" fn enum_handle_callback(_table: u64, entry: u64, handle: u64, context: u64) -> u64 {
    let count = guest::read64(context + 8);
    guest::write64(context + 0x10 + count * 8, handle);
    guest::write64(context + 8, count + 1);
    let locked = guest::read64(entry) & 1 == 0;
    unlock_entry(entry);
    (locked && handle == guest::read64(context)) as u64
}

fn enum_handle_table(assert: Assert) {
    use crate::ntos::ex::enum_handles::{self, Step};
    let process = process::get_current_process();
    let thread = process::get_current_thread();
    let table = handle_table::create(process, process::get_current_process_id()).unwrap_or(0);
    let handles = [4u64, 8, 0x404, 0x80004];
    for &handle in &handles {
        let description = HandleDescription { pointer: process, type_name: alloc::string::String::from("Test"), identity: 0, native_body: 0, attributes: 0, access: 0x1F };
        let _ = handle_table::insert(table, handle, &description);
    }
    assert(handle_table::row(table, 0x80004).is_some_and(|row| enum_handles::lookup(table, 0x80007) == row.entry) && enum_handles::lookup(table, 0x7FFF_0000) == 0, "enumhandles: lookup em dois niveis e limite");
    let context = guest::alloc_bytes(0x80);
    let output = guest::alloc_bytes(8);
    let callback = enum_handle_callback as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64;
    let disabled = guest::read16(thread + kthread::KERNEL_APC_DISABLE);
    guest::write_bytes(context, &[0; 0x80]);
    assert(matches!(enum_handles::enumerate(table, callback, context, output), Ok(0)) && guest::read64(context + 8) == 4 && (0..4).all(|index| guest::read64(context + 0x10 + index * 8) == handles[index as usize]), "enumhandles: percorre todas as entradas em ordem");
    assert(handles.iter().all(|&handle| handle_table::row(table, handle as u32).is_some_and(|row| guest::read64(row.entry) & 1 != 0)) && guest::read16(thread + kthread::KERNEL_APC_DISABLE) == disabled, "enumhandles: entradas destravadas e regiao critica encerrada");
    guest::write_bytes(context, &[0; 0x80]);
    guest::write64(context, 0x404);
    assert(matches!(enum_handles::enumerate(table, callback, context, output), Ok(1)) && guest::read64(output) == 0x404 && guest::read64(context + 8) == 3, "enumhandles: callback interrompe e publica o handle");
    // Entrada ocupada suspende a enumeração até ser destravada.
    let busy = handle_table::row(table, 8).map_or(0, |row| row.entry);
    let mut request = enum_handles::begin(table, callback, context, 0).ok();
    let first = request.as_mut().map(|request| request.poll());
    if let Some(Ok(Step::Callback { arguments, .. })) = first {
        unlock_entry(arguments[1]);
    }
    let _ = guest::compare_exchange64(busy, guest::read64(busy), guest::read64(busy) & !1);
    let resumed = request.as_mut().map(|request| request.resume(0));
    assert(matches!(first, Some(Ok(Step::Callback { arguments, .. })) if arguments[2] == 4 && arguments[0] == table) && matches!(resumed, Some(Ok(()))), "enumhandles: callback com tabela, entrada e handle");
    assert(matches!(request.as_mut().map(|request| request.poll()), Some(Ok(Step::Busy))) && guest::read16(thread + kthread::KERNEL_APC_DISABLE) != disabled, "enumhandles: entrada ocupada suspende dentro da regiao critica");
    unlock_entry(busy);
    let next = request.as_mut().map(|request| request.poll());
    assert(matches!(next, Some(Ok(Step::Callback { arguments, .. })) if arguments[2] == 8), "enumhandles: retoma depois do desbloqueio");
    if let Some(request) = request.as_mut() {
        request.callback_failed();
    }
    assert(guest::read64(busy) & 1 != 0 && guest::read16(thread + kthread::KERNEL_APC_DISABLE) == disabled, "enumhandles: falha do callback devolve o bloqueio");
    drop(request);
    for &handle in &handles {
        let _ = handle_table::remove(table, handle);
    }
    let _ = handle_table::destroy(table);
    guest::free_bytes(context);
    guest::free_bytes(output);
}

fn service_tables(assert: Assert) {
    use crate::hal::amd64::native_call;
    use crate::ntos::ex::service_table as st;
    use crate::ntos::mm::kernel_address;
    let Ok(addresses) = st::init() else {
        assert(false, "services: enderecos publicados");
        return;
    };
    // O boot com a ntdll de bring-up já instalou a tabela nativa: o teste a
    // guarda, trabalha com a tabela livre e a reinstala no fim.
    let live = st::installed(0);
    if live.is_some() {
        let _ = st::self_test_reset(0);
    }
    assert(addresses.descriptor % 32 == 0 && addresses.shadow == addresses.descriptor + 64 && addresses.tables[1] == addresses.tables[0] + 0x4000 && addresses.argument_tables[0] == addresses.tables[1] + 0x4000, "services: descritores e tabelas no alias da imagem");
    let alias = |routine: u64| kernel_address::virtual_address(routine).unwrap_or(0);
    let targets = [
        alias(enum_handle_callback as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64),
        alias(special_routine as extern "win64" fn(u64, u64, u64, u64, u64) as usize as u64),
        alias(normal_routine as extern "win64" fn(u64, u64, u64) as usize as u64),
    ];
    let table = addresses.tables[0];
    assert(targets.iter().all(|&target| target != 0) && st::encode_entry(table, targets[1], 3).is_ok_and(|value| st::decode_entry(table, value) == (targets[1], 3)), "services: codificacao relativa de 28 bits");
    assert(st::encode_entry(table, table - 0x10, 1).is_ok_and(|value| st::decode_entry(table, value) == (table - 0x10, 1)), "services: deslocamento negativo");
    assert(st::encode_entry(table, 0, 0).is_err() && st::encode_entry(table, table + 0x800_0000, 0).is_err() && st::encode_entry(table, targets[0], 16).is_err(), "services: entradas fora do formato recusadas");
    assert(st::install(2, &targets, &[0, 3, 15]).is_err() && st::install(0, &targets, &[0, 3]).is_err(), "services: tabela invalida recusada");
    assert(st::install(0, &targets, &[0, 3, 15]).is_ok_and(|record| record.limit == 3 && record.descriptors == alloc::vec![addresses.descriptor, addresses.shadow]), "services: KiServiceTable publicada");
    assert([addresses.descriptor, addresses.shadow].iter().all(|&descriptor| guest::read64(descriptor) == table && guest::read64(descriptor + 8) == 0 && guest::read64(descriptor + 16) == 3 && guest::read64(descriptor + 24) == addresses.argument_tables[0]) && guest::read8(addresses.argument_tables[0] + 1) == 12 && guest::read8(addresses.argument_tables[0] + 2) == 60, "services: KeServiceDescriptorTable e Shadow");
    assert(matches!(st::inspect(1, false), Ok(found) if found == (targets[1], 3)) && matches!(st::inspect(3, false), Ok((0, 0))) && matches!(st::inspect(0x1000, true), Ok((0, 0))), "services: inspecao e limite");
    let output = guest::alloc_bytes(8);
    let found = native_call::call(addresses.lookup, &[2, 0, output]);
    let count = guest::read64(output);
    let missing = native_call::call(addresses.lookup, &[5, 1, output]);
    assert(found == targets[2] && count == 15 && missing == 0 && guest::read64(output) == 0, "services: nt_service_lookup nativo");
    assert(st::install(0, &targets, &[0, 3, 15]).is_ok() && st::install(0, &targets, &[0, 3, 14]).is_err(), "services: ABI viva so pode ser confirmada");
    assert(st::install(1, &targets[2..], &[2]).is_ok() && guest::read64(addresses.shadow + 32) == addresses.tables[1], "services: tabela win32 so no shadow");
    assert(matches!(st::inspect(0x1000, true), Ok(found) if found == (targets[2], 2)) && native_call::call(addresses.lookup, &[0x1000, 1, 0]) == targets[2] && matches!(st::inspect(0x1000, false), Ok((0, 0))), "services: servico grafico pelo shadow");
    assert(st::self_test_reset(0).is_ok() && st::self_test_reset(1).is_ok() && matches!(st::inspect(1, false), Ok((0, 0))) && guest::read32(addresses.tables[0]) == 0, "services: tabelas devolvidas para o boot");
    guest::free_bytes(output);
    if let Some(record) = live {
        let (targets, arguments): (alloc::vec::Vec<u64>, alloc::vec::Vec<u32>) = record.values.iter().map(|&value| st::decode_entry(record.table, value)).unzip();
        assert(st::install(0, &targets, &arguments).is_ok_and(|restored| restored.values == record.values && restored.limit == record.limit), "services: tabela do boot reinstalada");
    }
}

fn signing_policy_and_appcontainer(assert: Assert) {
    use crate::hal::amd64::native_call;
    use crate::ntos::se::capability::appcontainer as capability_appcontainer;
    use crate::ntos::se::runtime_signing_policy as signing;
    use crate::ntos::se::token::tokens;
    // SeILSigningPolicyRuntime pelo callback nativo privado da CI.
    let (Ok(state), Ok(entry)) = (signing::address(), signing::callback_address()) else {
        assert(false, "signing: callback e celula publicados");
        return;
    };
    let original = guest::read8(state);
    let neighbors: alloc::vec::Vec<u8> = (1..16).map(|offset| guest::read8(state + offset)).collect();
    let mut shared = true;
    let mut preserved = true;
    for upper in [0u64, 0x9E06_DD9C_213E_0000] {
        for value in 0..256u64 {
            native_call::call(entry, &[upper | value]);
            shared &= signing::read().ok() == Some(value as u8);
            preserved &= (1..16).all(|offset| guest::read8(state + offset) == neighbors[offset as usize - 1]);
        }
    }
    native_call::call(entry, &[original as u64]);
    assert(entry != state && shared, "signing: setter nativo grava o byte do kernel");
    assert(preserved && signing::read().ok() == Some(original), "signing: bytes vizinhos preservados e valor restaurado");
    // RtlpIsAppContainer.
    let output = guest::alloc_bytes(8);
    let system = process::get_primary_token(process::get_system_process()).unwrap_or(0);
    guest::write8(output, 0xCC);
    assert(matches!(capability_appcontainer::check(system, output), Ok(0)) && guest::read8(output) == 0, "appcontainer: token comum");
    let lowbox = tokens::duplicate(system, 2, false, 2).unwrap_or(0);
    guest::write32(lowbox + 0xC8, guest::read32(lowbox + 0xC8) | 0x4000);
    assert(matches!(capability_appcontainer::check(lowbox, output), Ok(0)) && guest::read8(output) == 1, "appcontainer: TOKEN_LOWBOX em TokenFlags");
    let _ = tokens::release(lowbox);
    let handles = object_types::counts("Token").map_or(0, |counts| counts.1);
    let implicit = capability_appcontainer::check(0, output);
    assert(implicit.is_err() && guest::read8(output) == 0, "appcontainer: sem token o handle temporario segue como TOKEN (falha de memoria)");
    assert(object_types::counts("Token").map_or(u32::MAX, |counts| counts.1) == handles, "appcontainer: handles temporarios fechados");
    guest::free_bytes(output);
}

fn counted_utf16(text: &str) -> alloc::vec::Vec<u8> {
    let units: alloc::vec::Vec<u16> = text.encode_utf16().collect();
    let mut bytes = ((units.len() * 2) as u16).to_le_bytes().to_vec();
    for unit in units {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

/// UNICODE_STRING no convidado (descritor em +0, texto em +0x10).
fn guest_unicode(pointer: u64, text: &str) {
    let units: alloc::vec::Vec<u16> = text.encode_utf16().collect();
    guest::write16(pointer, units.len() as u16 * 2);
    guest::write16(pointer + 2, units.len() as u16 * 2);
    guest::write64(pointer + 8, pointer + 0x10);
    for (index, unit) in units.iter().enumerate() {
        guest::write16(pointer + 0x10 + index as u64 * 2, *unit);
    }
}

fn boot_policies(assert: Assert) {
    use crate::ntos::se::{platform_manifest as manifest, secure_boot_policy as policy};
    use alloc::vec::Vec;
    // Sem pacote do loader neste boot.
    assert(matches!(manifest::query(0x1000, 32), Ok(0xC0EB_0006)) && manifest::init(None).is_err(), "manifest: boot sem manifesto ativo");
    assert(matches!(policy::query(0, 0, 0, 0, 0, 0), Ok(0x8043_0006)) && matches!(policy::get_information(), Ok(None)) && policy::init(None).is_err(), "secureboot: boot sem politica");
    // Manifesto capturado: identificadores ordenados lexicograficamente.
    let mut ids = [[0x11u8; 32], [0x22; 32], [0x22; 32], [0x33; 32]];
    ids[1][31] = 0x01;
    ids[2][31] = 0x02;
    ids[2][0] = 0x22;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&(ids.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&[0; 16]);
    bytes.extend_from_slice(&[0xEE; 0x114]);
    for id in &ids {
        bytes.extend_from_slice(id);
    }
    let captured = manifest::capture(Some(&bytes));
    assert(captured.is_ok() && manifest::capture(Some(&bytes[..20])).is_err() && manifest::capture(Some(&bytes[..bytes.len() - 1])).is_err(), "manifest: captura estrutural do bloco do loader");
    let key = guest::alloc_bytes(0x80);
    if let Ok(captured) = captured {
        let found = |id: &[u8; 32], misaligned: bool| {
            let at = key + misaligned as u64;
            guest::write_bytes(at, id);
            captured.query(at, 32)
        };
        assert(ids.iter().all(|id| found(id, false) == 0 && found(id, true) == 0), "manifest: busca binaria acha todos (chave alinhada e desalinhada)");
        let mut absent = ids[1];
        absent[31] = 0x03;
        assert(found(&absent, false) == 0xC000_0225 && found(&[0x00; 32], true) == 0xC000_0225 && found(&[0xFF; 32], false) == 0xC000_0225, "manifest: identificador ausente");
        guest::write_bytes(key, &ids[3]);
        assert(captured.query(0, 7) == 0xC000_0225 && captured.query(key, 31) == 0xC000_000D && captured.query(key, 0x1_0000_0020) == 0, "manifest: NULL antes do tamanho e tamanho de 32 bits");
    }
    let empty = manifest::capture(Some(&[0u8; 24]));
    assert(empty.is_ok_and(|captured| captured.query(key, 32) == 0xC000_0225), "manifest: tabela vazia");
    // Política com uma regra REG_DWORD, uma de outro tipo e uma sem suporte.
    let key_name = counted_utf16("Software\\Policy");
    let value_name = counted_utf16("Value");
    let binary_name = counted_utf16("Bin");
    let mut values = Vec::new();
    let key_offset = values.len() as u32;
    values.extend_from_slice(&key_name);
    let name_offset = values.len() as u32;
    values.extend_from_slice(&value_name);
    let value_offset = values.len() as u32;
    values.extend_from_slice(&2u16.to_le_bytes());
    values.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    let binary_name_offset = values.len() as u32;
    values.extend_from_slice(&binary_name);
    let binary_value_offset = values.len() as u32;
    values.extend_from_slice(&3u16.to_le_bytes());
    let mut header = alloc::vec![0u8; 0x3C];
    header[0x26..0x28].copy_from_slice(&3u16.to_le_bytes());
    header[0x34..0x38].copy_from_slice(&48u32.to_le_bytes());
    let mut rules = Vec::new();
    for (kind, key_at, name_at, value_at) in [(0x8100_0000u32, key_offset, name_offset, value_offset), (5, 0xFFFF, 0xFFFF, 0xFFFF), (0x8100_0000, key_offset, binary_name_offset, binary_value_offset)] {
        for word in [kind, key_at, name_at, value_at] {
            rules.extend_from_slice(&word.to_le_bytes());
        }
    }
    let policy_bytes: Vec<u8> = header.iter().chain(&rules).chain(&values).copied().collect();
    assert(policy::capture(Some(&policy_bytes[..0x3C + 40])).is_err() && policy::capture(Some(&policy_bytes[..0x30])).is_err(), "secureboot: tabelas fora da politica recusadas");
    let names = guest::alloc_bytes(0x200);
    let (key_descriptor, name_descriptor, other_descriptor, binary_descriptor) = (names, names + 0x80, names + 0x100, names + 0x180);
    guest_unicode(key_descriptor, "software\\POLICY");
    guest_unicode(name_descriptor, "VALUE");
    guest_unicode(other_descriptor, "Missing");
    guest_unicode(binary_descriptor, "bin");
    let output = guest::alloc_bytes(0x20);
    if let Ok(captured) = policy::capture(Some(&policy_bytes)) {
        assert(captured.query(key_descriptor, name_descriptor, 2, output + 8, 4, output) == 0 && guest::read32(output) == 4 && guest::read32(output + 8) == 0xDEAD_BEEF, "secureboot: regra REG_DWORD sem diferenca de caixa ASCII");
        guest::write32(output, 0);
        assert(captured.query(key_descriptor, name_descriptor, 2, 0, 0, output) == 0 && guest::read32(output) == 4, "secureboot: so o tamanho sem buffer");
        assert(captured.query(key_descriptor, name_descriptor, 2, output + 8, 3, output) == 0xC000_0023, "secureboot: buffer curto");
        assert(captured.query(key_descriptor, name_descriptor, 5, output + 8, 8, output) == 0xC000_0034 && captured.query(key_descriptor, other_descriptor, 2, output + 8, 8, output) == 0xC000_0034, "secureboot: tipo diferente e nome ausente");
        assert(captured.query(key_descriptor, binary_descriptor, 3, output + 8, 8, output) == 0xC000_0002, "secureboot: tipo de valor sem suporte");
    } else {
        assert(false, "secureboot: captura da politica");
    }
    for pointer in [key, names, output] {
        guest::free_bytes(pointer);
    }
}

fn se_exports(assert: Assert) {
    use crate::ntos::mm::kernel_data;
    use crate::ntos::se::{se_exports as exports, model};
    let table = kernel_data::read("SeExports");
    let (storage, size) = kernel_data::region("SeExports").unwrap_or((0, 0));
    assert(table != 0 && table == storage + 8 && matches!(exports::init(), Ok(found) if found == table), "seexports: ponteiro publicado uma vez na reserva da imagem");
    let field = |name: &str| exports::field_index(name).map_or(0, |index| guest::read64(table + index as u64 * 8));
    assert(field("SeCreateTokenPrivilege") == 2 && field("SeCreatePagefilePrivilege") == 15 && field("SeIncreaseBasePriorityPrivilege") == 14 && field("SeDebugPrivilege") == 20 && field("SeDelegateSessionUserImpersonatePrivilege") == 36, "seexports: LUIDs na ordem nativa");
    let sid_at = |pointer: u64| {
        let count = guest::read8(pointer + 1) as usize;
        guest::read_bytes(pointer, 8 + count * 4)
    };
    let body_start = table + exports::field_count() as u64 * 8;
    let inside = |pointer: u64| pointer >= body_start && pointer < storage + size;
    assert(inside(field("SeWorldSid")) && sid_at(field("SeWorldSid")) == model::sid(1, &[0]) && sid_at(field("SeNtAuthoritySid")) == model::sid(5, &[]), "seexports: SIDs Everyone e NT AUTHORITY");
    assert(sid_at(field("SeAliasAdminsSid")) == model::sid(5, &[32, 544]) && sid_at(field("SeTrustedInstallerSid")) == model::sid(5, &[80, 956_008_885, 3_418_522_649, 1_831_038_044, 1_853_292_631, 2_271_478_464]) && inside(field("SeTrustedInstallerSid")), "seexports: SIDs de alias e TrustedInstaller");
    assert(sid_at(field("SeHighMandatorySid")) == model::sid(16, &[0x3000]) && sid_at(field("SeAllAppPackagesSid")) == model::sid(15, &[2, 1]), "seexports: rotulos de integridade e ALL APP PACKAGES");
}

/// (pid, flags, base, tamanho, FILE_OBJECT, tamanho do nome, chamadas, recusas internas).
static IMAGE_SEEN: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
static IMAGE_CALLBACK: AtomicU64 = AtomicU64::new(0);

extern "win64" fn image_notify_callback(name: u64, process_id: u64, info: u64) {
    let values = [process_id, guest::read32(info) as u64, guest::read64(info + 8), guest::read64(info + 24), guest::read64(info + 40), if name != 0 { guest::read16(name) as u64 } else { u64::MAX }];
    for (slot, value) in IMAGE_SEEN.iter().zip(values) {
        slot.store(value, Ordering::SeqCst);
    }
    IMAGE_SEEN[6].fetch_add(1, Ordering::SeqCst);
    let inside = crate::ntos::ps::notify::image::begin_remove(IMAGE_CALLBACK.load(Ordering::SeqCst));
    if inside.is_err() && critical_region::disabled() {
        IMAGE_SEEN[7].fetch_add(1, Ordering::SeqCst);
    }
}

fn alert_and_image_notify(assert: Assert) {
    use crate::ntos::ke::thread_alert;
    use crate::ntos::ob::objects::file as files;
    use crate::ntos::ps::alert_thread;
    use crate::ntos::ps::notify::image::{self as image_notify, Image, NotifyOptions};
    // NtAlertThread pela referência de thread com THREAD_ALERT.
    let current = process::get_current_thread();
    assert(matches!(alert_thread::alert((-2i64) as u64, 0), Ok(0)) && thread_alert::consume(current, 0, true).is_some(), "alertthread: alerta a thread corrente");
    assert(matches!(alert_thread::alert(u64::MAX, 0), Ok(0xC000_0024)) && matches!(alert_thread::alert(0x7FFF_0000, 1), Ok(0xC000_0008)), "alertthread: processo e handle livre recusados");
    // PsSetLoadImageNotifyRoutine.
    let callback = image_notify_callback as extern "win64" fn(u64, u64, u64) as usize as u64;
    IMAGE_CALLBACK.store(callback, Ordering::SeqCst);
    for slot in &IMAGE_SEEN {
        slot.store(0, Ordering::SeqCst);
    }
    let image = Image { image_base: 0x1_4000_0000, size_of_image: 0x5000 };
    assert(image_notify::notify(image, &NotifyOptions::default()).is_ok() && IMAGE_SEEN[6].load(Ordering::SeqCst) == 0, "imagenotify: sem rotinas nada executa");
    assert(matches!(image_notify::register(callback), Ok(0)), "imagenotify: registro");
    let name = "\\SystemRoot\\phase3.sys";
    let options = NotifyOptions { name: Some(name.into()), process_id: Some(0x1234), ..Default::default() };
    let seen = |index: usize| IMAGE_SEEN[index].load(Ordering::SeqCst);
    assert(image_notify::notify(image, &options).is_ok() && seen(6) == 1 && seen(0) == 0x1234 && seen(1) == 3 && seen(2) == 0x1_4000_0000 && seen(3) == 0x5000 && seen(4) == 0 && seen(5) == name.len() as u64 * 2, "imagenotify: IMAGE_INFO_EX de imagem de usuario");
    assert(seen(7) == 1, "imagenotify: remocao dentro da notificacao recusada em regiao critica");
    let file = files::create(0, "\\SystemRoot\\phase3.sys").unwrap_or(0);
    let system = NotifyOptions { system: true, file_object: file, process_id: Some(0x1234), ..Default::default() };
    assert(image_notify::notify(image, &system).is_ok() && seen(0) == 0 && seen(1) == 0x503 && seen(4) == file && seen(5) == u64::MAX && files::reference_count(file) == Some(1), "imagenotify: imagem de sistema com FILE_OBJECT referenciado so durante a chamada");
    let _ = files::dereference(file);
    assert(image_notify::notify(image, &NotifyOptions { no_execute: true, ..options.clone() }).is_ok() && seen(6) == 2, "imagenotify: imagem sem execucao nao notifica");
    let extra = (0..63).filter(|_| matches!(image_notify::register(callback), Ok(0))).count();
    assert(extra == 63 && matches!(image_notify::register(callback), Ok(0xC000_009A)), "imagenotify: 64 slots");
    let removed = (0..64).filter(|_| matches!(image_notify::remove(callback), Ok(0))).count();
    assert(removed == 64 && matches!(image_notify::remove(callback), Ok(0xC000_007A)), "imagenotify: remocao de cada registro e rotina ausente");
    assert(image_notify::notify(image, &options).is_ok() && seen(6) == 2, "imagenotify: nada executa depois da remocao");
}

fn thread_context_registers(assert: Assert) {
    use crate::ntos::ps::context::registers::{self as tcr, AMD64};
    // Validação de ContextFlags.
    assert(tcr::validate(AMD64 | 0x1F, 0, false) == (0, AMD64 | 0x1F) && tcr::validate(AMD64 | 0x40, 0, false) == (0xC000_00BB, AMD64 | 0x40) && tcr::validate(AMD64 | 0x40, 0, true) == (0, AMD64 | 0x40), "context: CONTEXT_ALL e XSTATE");
    assert(tcr::validate(0, 0, false) == (0xC000_000D, 0) && tcr::validate(0, 1, false) == (0, AMD64) && tcr::validate(0x1_0001, 1, false) == (0, 0x10_0001) && tcr::validate(0x1_0001, 0, false).0 == 0xC000_000D, "context: flags invalidos so normalizados em UserMode");
    assert(tcr::debug_registers([0x7FFF_FFFF_0000, 0x1000, 0x7FFF_FFFE_FFFF, u64::MAX, 0xAA, 0xFFFF_FFFF], 1) == [0, 0x1000, 0x7FFF_FFFE_FFFF, 0, 0, 0xFFFF_0355] && tcr::debug_registers([u64::MAX, 0, 0, 0, 0, 0], 0)[0] == u64::MAX, "context: registradores de depuracao saneados");
    let source = guest::alloc_bytes(tcr::SIZE);
    let target = guest::alloc_bytes(tcr::SIZE);
    let fill = |pointer: u64, seed: u64| {
        let mut offset = 0;
        while offset < tcr::SIZE {
            guest::write64(pointer + offset, seed ^ offset.wrapping_mul(0x0101_0101_0101));
            offset += 8;
        }
    };
    // Captura: só os grupos selecionados, flags publicados.
    fill(source, 0x5A5A_0000_0000_0000);
    assert(tcr::capture_registers(target, source, AMD64 | 0x40).is_err(), "context: XSTATE exige validacao antes da captura");
    assert(tcr::capture_registers(target, source, AMD64 | 1).is_ok() && guest::read32(target + 0x30) == AMD64 | 1 && guest::read64(target + 0xF8) == guest::read64(source + 0xF8) && guest::read16(target + 0x38) == guest::read16(source + 0x38) && guest::read32(target + 0x44) == guest::read32(source + 0x44), "context: CONTROL capturado");
    assert(guest::read64(target + 0x78) == 0 && guest::read64(target + 0x100) == 0 && guest::read64(target + 0x48) == 0, "context: grupos nao selecionados ficam zerados");
    assert(tcr::capture_registers(target, source, AMD64 | 0x1F).is_ok() && tcr::INTEGER.iter().all(|&offset| guest::read64(target + offset) == guest::read64(source + offset)) && guest::read64(target + 0x298) == guest::read64(source + 0x298) && guest::read64(target + 0x4B0) == guest::read64(source + 0x4B0) && guest::read64(target + 0x2A0) == 0, "context: CONTEXT_ALL sem extensao vetorial");
    // Escrita em UserMode: CS/SS de usuário, RIP canônico, EFLAGS e Dr saneados.
    fill(target, 0);
    guest::write32(source + 0x30, AMD64 | 0x1B);
    guest::write64(source + 0xF8, 0x0000_8000_0000_1234);
    guest::write16(source + 0x38, 0x33);
    guest::write32(source + 0x44, 0xFFFF_FFFF);
    guest::write64(source + 0x48, 0x7FFF_FFFF_0000);
    guest::write64(source + 0x50, 0x1000);
    guest::write64(source + 0x70, 0xFFFF_FFFF);
    guest::write32(source + 0x34, 0xFFFF);
    assert(tcr::write_registers(target, source, 1, 0xFFBF, 0x1F80).is_ok() && guest::read64(target + 0xF8) == 0xFFFF_8000_0000_1234 && guest::read16(target + 0x38) == 0x33 && guest::read16(target + 0x42) == 0x2B && guest::read32(target + 0x44) == 0x21_0FD5, "context: CONTROL em UserMode");
    assert(guest::read64(target + 0x48) == 0 && guest::read64(target + 0x50) == 0x1000 && guest::read64(target + 0x68) == 0 && guest::read64(target + 0x70) == 0xFFFF_0355, "context: Dr0-Dr7 de usuario");
    assert(guest::read32(target + 0x34) == 0xFFBF && guest::read32(source + 0x118) == 0x1F80 && guest::read16(source + 0x100) & !0x1F3F == 0, "context: MXCSR mascarado e imagem FXSAVE preparada");
    guest::write16(source + 0x38, 0x23);
    guest::write64(source + 0xF8, 0x1234_5678_9ABC_DEF0);
    assert(tcr::write_registers(target, source, 1, 0xFFBF, 0x1F80).is_ok() && guest::read64(target + 0xF8) == 0x9ABC_DEF0 && guest::read16(target + 0x38) == 0x23, "context: segmento de 32 bits trunca o RIP");
    // KernelMode: CS do kernel, SS nulo, EFLAGS do kernel.
    assert(tcr::write_registers(target, source, 0, 0xFFBF, 0x1F80).is_ok() && guest::read64(target + 0xF8) == 0x1234_5678_9ABC_DEF0 && guest::read16(target + 0x38) == 0x10 && guest::read16(target + 0x42) == 0 && guest::read32(target + 0x44) == 0x25_0FD5 && guest::read64(target + 0x48) == 0x7FFF_FFFF_0000, "context: CONTROL em KernelMode");
    // CONTEXT salvo com imagem FXSAVE: x87/MMX só em UserMode.
    guest::write64(source + 0x120, 0xABCD);
    guest::write64(target + 0x120, 0);
    assert(tcr::write_saved_context(target, source, 0, 0xFFBF, 0x1F80).is_ok() && guest::read64(target + 0x120) == 0 && guest::read32(target + 0x118) == guest::read32(target + 0x34), "context: KernelMode conserva x87");
    assert(tcr::write_saved_context(target, source, 1, 0xFFBF, 0x1F80).is_ok() && guest::read64(target + 0x120) == 0xABCD && guest::read32(target + 0x118) == guest::read32(target + 0x34), "context: UserMode restaura x87 e MXCSR da imagem");
    guest::free_bytes(source);
    guest::free_bytes(target);
}

fn section_parameters_and_address(assert: Assert) {
    use crate::ntos::mm::memory_map as map;
    use crate::ntos::mm::section::address::{self, FindOptions, Region};
    use crate::ntos::mm::section::parameters::{self, Decoded};
    // SEC_COMMIT + PAGE_READWRITE vindo de syscall.
    let commit = parameters::decode(0x0800_0000, 4, 0x3000, 0, 1, false);
    assert(matches!(commit, Decoded::Request(request) if request.attributes == 0x0800_0000 && request.protection_mask == 4 && request.flags == 0 && request.size == 0x3000), "sectionparams: SEC_COMMIT PAGE_READWRITE");
    assert(matches!(parameters::decode(0, 4, 0x1000, 0, 1, false), Decoded::Status(0xC000_00F4)) && matches!(parameters::decode(0x0300_0000, 4, 0x1000, 0, 1, false), Decoded::Status(0xC000_00F4)), "sectionparams: atributos de syscall invalidos");
    assert(matches!(parameters::decode(0, 4, 0x1000, 0, 1, true), Decoded::Request(request) if request.attributes == 0), "sectionparams: MmCreateSection aceita atributos zero");
    assert(matches!(parameters::decode(0x0800_0000, 0x104, 0x1000, 0, 1, false), Decoded::Status(0xC000_0045)) && matches!(parameters::decode(0x0800_0000, 3, 0x1000, 0, 1, false), Decoded::Status(0xC000_0045)), "sectionparams: protecao invalida");
    // SEC_FILE sem SEC_NOCACHE marca a seção de arquivo (flag 0x400).
    assert(matches!(parameters::decode(0x0100_0000, 2, 0, 0x44, 1, false), Decoded::Request(request) if request.attributes == 0x0100_0000 && request.flags == 0x400 && request.protection_mask == 1), "sectionparams: SEC_IMAGE");
    assert(matches!(parameters::decode(0x0800_0000 | 0x1000_0000, 4, 0x1000, 0, 1, false), Decoded::Request(request) if request.page_protect == 0x204 && request.protection_mask == 4 | 8), "sectionparams: SEC_NOCACHE vira PAGE_NOCACHE");
    assert(matches!(parameters::decode(0x0800_0000 | 3, 4, 0x1000, 0, 2, false), Decoded::Status(0xC000_000D)) && matches!(parameters::decode(0x0800_0000 | 2, 4, 0x1000, 0, 2, false), Decoded::Request(request) if request.preferred_node_plus_one == 2), "sectionparams: no NUMA preferido");
    if let Decoded::Request(request) = commit {
        assert(parameters::pagefile_size(&request) == Ok(parameters::PagefileSize { pages: 3, rounded_size: 0x3000, committed: true, large: false }) && parameters::pagefile_size(&parameters::Request { size: 0, ..request }) == Err(0xC000_00F2), "sectionparams: tamanho de pagefile");
        assert(parameters::file_request(&request) == Ok(0x3) && parameters::file_request(&parameters::Request { protection_mask: 1, ..request }) == Ok(1), "sectionparams: acesso exigido ao arquivo");
    }
    // Endereços de vistas de seção.
    let regions = [Region { base: 0x1_0000_0000, size: 0x2_0000 }];
    assert(address::find(&FindOptions { size: 0x1000, ..Default::default() }, &regions) == Ok(0x1_0002_0000), "sectionaddr: primeira faixa livre acima do piso");
    assert(address::find(&FindOptions { size: 0x1000, base: 0x1_0001_0000, ..Default::default() }, &regions) == Err(0xC000_0018) && address::find(&FindOptions { size: 0, ..Default::default() }, &regions) == Err(0xC000_001F), "sectionaddr: base fixa em conflito e tamanho zero");
    let top = address::find(&FindOptions { size: 0x1000, top_down: true, ..Default::default() }, &regions);
    assert(matches!(top, Ok(base) if base + 0x1000 <= map::USER_ADDRESS_LIMIT && base % 0x10000 == 0 && base > 0x7000_0000_0000), "sectionaddr: top-down abaixo do limite de usuario");
    assert(address::find(&FindOptions { size: 0x1000, upper: Some(0x1_0001_FFFF), ..Default::default() }, &regions) == Err(0xC000_0017), "sectionaddr: faixa esgotada");
    let system = address::find(&FindOptions { system_space: true, size: 0x10000, ..Default::default() }, &[Region { base: map::KERNEL_SECTION_BASE, size: 0x10000 }]);
    assert(matches!(system, Ok(base) if base >= map::KERNEL_SECTION_BASE + 0x10000 && base + 0x10000 <= map::KERNEL_SECTION_TOP), "sectionaddr: espaco de sistema");
}

/// Direitos concedidos pela linha nativa de um handle do Object Manager.
fn om_access(handle: u64) -> Option<u32> {
    crate::ntos::ob::object_manager::handle_record((handle & 0x7FFF_FFFF) as u32).map(|record| record.access)
}

pub fn run(assert: Assert) {
    dispatcher_objects(assert);
    apc_regions(assert);
    handle_table_storage(assert);
    rundown_protection(assert);
    push_locks(assert);
    timers(assert);
    thread_alerts(assert);
    processes(assert);
    namespace(assert);
    object_callbacks(assert);
    open_by_pointer(assert);
    security_descriptors(assert);
    dispatcher_bodies_and_close(assert);
    namespace_handles(assert);
    executive_primitives(assert);
    executive_resources(assert);
    executive_callbacks(assert);
    token_handles(assert);
    token_services(assert);
    process_tokens_and_membership(assert);
    descriptor_inheritance(assert);
    descriptor_queries(assert);
    capabilities_and_anonymous(assert);
    process_accessors(assert);
    process_thread_enumeration(assert);
    silo_contexts(assert);
    silo_monitors(assert);
    driver_and_section_objects(assert);
    file_objects(assert);
    device_objects(assert);
    query_object_format(assert);
    thread_and_file_handles(assert);
    unblock_and_quota_pool(assert);
    enum_handle_table(assert);
    service_tables(assert);
    signing_policy_and_appcontainer(assert);
    boot_policies(assert);
    se_exports(assert);
    alert_and_image_notify(assert);
    thread_context_registers(assert);
    section_parameters_and_address(assert);
    debug_print!("PHASE3_SELFTEST_OK");
}
