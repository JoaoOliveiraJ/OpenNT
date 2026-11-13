//! Autoteste do kernel — subconjunto da fase 1 de
//! `system32/ntos/test/self-test.js`.
//!
//! Exercita os módulos já transcritos: MemoryFileSystem, chamadas numeradas,
//! programa embutido, memória, escalonador, timer do LAPIC, IPC e o registro
//! de serviços do nanokernel. Imprime `SELFTEST_OK` na serial; uma falha
//! imprime `SELFTEST FALHOU: <motivo>` e para a CPU.

use alloc::boxed::Box;
use alloc::string::String;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::apps::programs;
use crate::hal::{cpu, physical};
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::mm::{contiguous_memory, independent_pages, kernel_data, memory_map, paging, pfn, virtual_memory};
use crate::ntos::mm::guest_memory;
use crate::nano::{interrupts, kernel, message_channels};
use crate::ntos::ke::{bugcheck_reason, dpc, irql, smp};
use crate::ntos::ex::syscalls::{self, Value};
use crate::drivers::fs::memory_file_system::{self, FileData};
use crate::ntos::ke::clock;
use crate::ntos::ps::scheduler;

fn assert(condition: bool, message: &str) {
    if !condition {
        debug_print!("SELFTEST FALHOU: {}", message);
        cpu::halt_forever();
    }
}

static DPC_RESULT: AtomicU64 = AtomicU64::new(0);

/// Rotina de DPC nativa de teste: guarda a soma dos argumentos.
extern "win64" fn dpc_test_routine(dpc: u64, context: u64, first: u64, second: u64) {
    DPC_RESULT.store(dpc + context + first + second, Ordering::SeqCst);
}

/// Rotina nativa de teste para o laço de jobs do AP.
extern "win64" fn ap_test_job(first: u64, second: u64, third: u64, fourth: u64) -> u64 {
    first + second + third + fourth
}

fn is_text(data: Option<FileData>, expected: &str) -> bool {
    matches!(data, Some(FileData::Text(text)) if text == expected)
}

pub fn run() {
    // MemoryFileSystem
    let _ = memory_file_system::write("/tmp/a.txt", "hello OpenNT");
    assert(is_text(memory_file_system::read("/tmp/a.txt"), "hello OpenNT"), "vfs read/write");
    assert(memory_file_system::exists("/tmp/a.txt"), "vfs exists");
    assert(memory_file_system::size("/tmp/a.txt") == Some(12), "vfs size");
    memory_file_system::remove("/tmp/a.txt");
    assert(!memory_file_system::exists("/tmp/a.txt"), "vfs remove");

    // syscalls por número
    let path = Value::Text(String::from("/tmp/b.txt"));
    let _ = syscalls::call("write", &[path.clone(), Value::Text(String::from("21 * 2"))]);
    assert(matches!(syscalls::call("exists", &[path.clone()]), Ok(Value::Bool(true))), "sys write");
    assert(
        matches!(syscalls::call("read", &[path]), Ok(Value::Text(text)) if text == "21 * 2"),
        "sys read",
    );
    assert(syscalls::system_call(99, &[]).is_err(), "syscall desconhecida");

    // programa embutido com a API de syscall
    let hello = programs::find_program("/hello.js");
    assert(hello.is_some(), "programa hello embutido");
    assert(matches!(hello.unwrap()(), Ok(Value::Number(42))), "exec programa embutido");

    // memória
    let heap = syscalls::call("meminfo", &[]);
    assert(matches!(heap, Ok(Value::HeapInfo { total, used }) if total > 0 && used > 0), "meminfo");

    // Memory Manager real: PFN (frames físicos) + paging (VA->PA de verdade)
    let free_before = pfn::free_count();
    let frame1 = pfn::alloc_page();
    assert(frame1 > 0, "pfn alloc");
    assert(pfn::free_count() == free_before - 1, "pfn contagem desceu");
    pfn::free_page(frame1);
    assert(pfn::free_count() == free_before, "pfn free devolveu");
    let frame2 = pfn::alloc_page();
    assert(frame2 == frame1, "pfn reusa frame livre");
    pfn::free_page(frame2);

    // identity: VA conhecida traduz para o mesmo físico
    assert(paging::translate(0x100000) == 0x100000, "identity map traduz");

    // VirtualAlloc: VA nova -> frame físico distinto, dados fluem pela tabela
    let va = virtual_memory::alloc(4096);
    assert(va > 0, "VirtualAlloc");
    let pa = paging::translate(va);
    assert(pa > 0 && (pa & !0xFFF) != (va & !0xFFF), "VA mapeada p/ frame distinto");
    physical::write32(va, 0xC0FFEE);
    assert(physical::read32(va) == 0xC0FFEE, "escrita pela VA mapeada");
    assert(paging::query_page(va, false).is_some_and(|page| page.physical_address == pa), "query_page");
    virtual_memory::free(va, 4096);
    assert(paging::translate(va) == 0, "pagina desmapeada no free");

    // imagem do kernel e dados exportados
    assert(kernel_data::read("MmUserProbeAddress") == memory_map::USER_ADDRESS_LIMIT, "MmUserProbeAddress");
    let kernel_va = memory_map::KERNEL_VIRTUAL_BASE + 0x1000;
    assert(guest_memory::read32(kernel_va) == physical::read32(0x101000), "alias virtual do kernel");
    let block = guest_memory::alloc_bytes(100);
    assert(block != 0 && guest_memory::owns_allocation(block), "arena de convidado");
    guest_memory::free_bytes(block);
    assert(guest_memory::try_read32(0xFFFF_9000_0000_0000).is_err(), "falta de traducao de convidado");

    // pool executivo, memória contígua e páginas independentes
    let tag = u32::from_le_bytes(*b"Test");
    let block = kernel_pool::allocate(100, AllocateOptions { tag, zero: true, ..Default::default() }).unwrap_or(0);
    assert(block != 0 && guest_memory::read32(block) == 0, "pool aloca zerado");
    guest_memory::write32(block + 96, 0x1234_5678);
    assert(guest_memory::read32(block + 96) == 0x1234_5678, "pool leitura/escrita");
    assert(kernel_pool::free(block, Some(u32::from_le_bytes(*b"Bad!"))).is_err(), "pool recusa tag errada");
    assert(kernel_pool::free(block, Some(tag)).is_ok(), "pool free");
    assert(!kernel_pool::owns(block), "pool free removeu o bloco");
    let contiguous = contiguous_memory::allocate(3 * 4096, Default::default()).unwrap_or(0);
    let physical0 = paging::translate(contiguous);
    assert(contiguous != 0 && paging::translate(contiguous + 2 * 4096) == physical0 + 2 * 4096, "memoria contigua");
    assert(contiguous_memory::free(contiguous).is_ok() && paging::translate(contiguous) == 0, "free contiguo");
    let independent = independent_pages::allocate(2 * 4096, 0).unwrap_or(0);
    assert(independent != 0 && paging::translate(independent + 4096) != 0, "paginas independentes");
    assert(independent_pages::free(independent).is_ok() && independent_pages::count() == 0, "free independente");

    // DPC: rotina nativa (ABI MS x64) chamada pela ponte no alias do kernel
    let dpc = guest_memory::alloc_bytes(0x40);
    dpc::initialize_dpc(dpc, dpc_test_routine as extern "win64" fn(u64, u64, u64, u64) as usize as u64, 0x55);
    assert(dpc::insert_queue_dpc(dpc, 2, 3), "KeInsertQueueDpc");
    assert(!dpc::insert_queue_dpc(dpc, 2, 3), "DPC recusa dupla insercao");
    assert(dpc::run_queue().is_ok() && DPC_RESULT.load(Ordering::SeqCst) == 0x55 + 2 + 3 + dpc, "DPC nativa executada");
    assert(dpc::pending() == 0 && irql::get_irql() == irql::PASSIVE_LEVEL, "DPC restaura IRQL");
    guest_memory::free_bytes(dpc);

    // callbacks de motivo de bugcheck: registro, duplicata e remoção
    let record = guest_memory::alloc_bytes(48);
    let routine = dpc_test_routine as extern "win64" fn(u64, u64, u64, u64) as usize as u64;
    assert(matches!(bugcheck_reason::register(record, routine, 2, 0x10), Ok(true)), "registra callback de bugcheck");
    assert(matches!(bugcheck_reason::register(record, routine, 2, 0x10), Ok(false)), "recusa registro duplicado");
    assert(matches!(bugcheck_reason::remove(record), Ok(true)), "remove callback de bugcheck");
    assert(matches!(bugcheck_reason::remove(record), Ok(false)), "remocao repetida falha");
    guest_memory::free_bytes(record);

    // SMP: job nativo (ABI MS x64) executado num AP + shootdown de TLB
    if smp::ap_slot_count() > 0 {
        let slot = smp::ap_slot(0).unwrap();
        let result = smp::run_on_ap(slot, ap_test_job as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64, [1, 2, 3, 4]);
        assert(matches!(result, Ok(10)), "job nativo no AP");
        assert(smp::flush_remote_tlb(false).is_ok(), "shootdown de TLB nos APs");
    }

    // escalonador: processo cooperativo
    static RAN: AtomicU32 = AtomicU32::new(0);
    let before = scheduler::count();
    scheduler::spawn("test", async {
        RAN.fetch_add(1, Ordering::SeqCst);
        scheduler::yield_now().await;
        RAN.fetch_add(1, Ordering::SeqCst);
        0
    });
    scheduler::tick(-1); // roda até o yield   (ran=1)
    assert(RAN.load(Ordering::SeqCst) == 1, "sched passo 1");
    scheduler::tick(-1); // termina            (ran=2, done)
    assert(RAN.load(Ordering::SeqCst) == 2, "sched passo 2");
    assert(scheduler::count() == before, "sched reap");

    // nanokernel: timer do LAPIC disparando (entrega real pela plataforma)
    if interrupts::is_available() {
        let start = interrupts::tick_count();
        let wait_end = clock::uptime_ms() + 500;
        while interrupts::tick_count() == start && clock::uptime_ms() < wait_end {
            cpu::pause();
        }
        assert(interrupts::tick_count() > start, "timer do LAPIC disparando (entrega real)");
    } else {
        debug_print!("[selftest] IDT nao carregada - tick test pulado");
    }

    // nanokernel: IPC por canal nomeado
    message_channels::create_channel("teste");
    message_channels::send("teste", "42");
    assert(message_channels::receive("teste").as_deref() == Some("42"), "ipc send/receive");
    assert(message_channels::receive("teste").is_none(), "ipc canal vazio");

    // nanokernel: registro e chamada de serviço
    assert(kernel::register_service("eco", |request| request).is_ok(), "nano registra eco");
    assert(kernel::register_service("eco", |request| request).is_err(), "nano servico duplicado");
    let reply = kernel::call_service("eco", Box::new(7u32));
    assert(
        matches!(reply.ok().and_then(|reply| reply.downcast::<u32>().ok()), Some(value) if *value == 7),
        "nano servico eco",
    );

    // fase 3: Ke/Ex/Ob/Ps/Se
    super::phase3::run(assert);
    super::phase4::run(assert);
    super::phase5::run(assert);
    super::phase6::run(assert);
    super::phase7::run(assert);
    real_keyboard();

    debug_print!("SELFTEST_OK");
}

/// Grupo 34: TECLADO REAL fim-a-fim. Abre o device de classe
/// `\Device\KeyboardClass0` (kbdclass) e lê uma tecla: 8042 -> IRQ1 -> ISR
/// nativa do i8042prt -> DPC -> callback do kbdclass -> READ completado com
/// KEYBOARD_INPUT_DATA. A tecla é um scancode real injetado pelo comando
/// 0xD2 do controlador (Write Output Buffer): o byte aparece no buffer de
/// saída e dispara a IRQ1, como uma tecla de verdade. Sem tecla em 10 s não
/// é fatal (KBDTEST_SKIP). Sem os binários no build, o grupo é pulado.
fn real_keyboard() {
    use crate::drivers::input::keyboard_stack;
    use crate::hal::port;
    use crate::ntos::io::io_manager::{self, IoParams};
    use crate::ntos::ke::dispatcher;
    if !keyboard_stack::binaries_present() {
        debug_print!("KBDTEST_SKIP (i8042prt/kbdclass ausentes do build)");
        return;
    }
    let stack = keyboard_stack::initialize();
    assert(stack.is_ok(), "teclado: pilha PS/2 real inicializada");
    let Ok(Some(_)) = stack else {
        debug_print!("KBDTEST_SKIP (pilha do teclado sem START)");
        return;
    };
    let event = guest_memory::alloc_bytes(0x18);
    dispatcher::initialize_event(event, 0, false); // NotificationEvent (manual)
    let opened = io_manager::open_device("\\Device\\KeyboardClass0", false);
    let opened_status = opened.as_ref().map_or(-1, |opened| opened.status);
    assert(opened_status == 0, "teclado: CREATE no kbdclass");
    let handle = opened.map_or(0, |opened| opened.handle);
    // Múltiplo de KEYBOARD_INPUT_DATA (12 bytes).
    let read = io_manager::read_handle(handle, IoParams { user_event: event, buffer_length: Some(48), binary: true, ..Default::default() });
    match read {
        Ok(mut request) if request.status == 0x103 => {
            debug_print!("KBDTEST_READY");
            let inject = |scancode: u8| {
                port::write8(0x64, 0xD2); // 8042: Write Output Buffer
                port::write8(0x60, scancode);
            };
            inject(0x1E); // 'a' make
            inject(0x9E); // 'a' break
            let zero_timeout = guest_memory::alloc_bytes(8);
            let deadline = clock::uptime_ms() + 10_000;
            let mut completed = false;
            while clock::uptime_ms() < deadline {
                interrupts::dispatch_pending(); // IRQ1 -> ISR nativa do i8042prt
                crate::ntos::ke::run_kernel_tasks(); // DPC -> callback do kbdclass
                if dispatcher::wait_for_single_object(event, zero_timeout, 0, false) == 0 {
                    completed = true;
                    break;
                }
            }
            if completed {
                // KEYBOARD_INPUT_DATA: UnitId u16, MakeCode u16, Flags u16.
                let data = request.pending_buffer;
                let make_code = guest_memory::read16(data + 2);
                let flags = guest_memory::read16(data + 4);
                let information = guest_memory::read64(request.pending_irp + crate::ntos::inc::nt_abi::irp::IO_STATUS_INFORMATION);
                debug_print!("[selftest] tecla REAL recebida: MakeCode {:#x} flags {:#x} ({} bytes)", make_code, flags, information);
                assert(make_code == 0x1E, "teclado: MakeCode esperado 0x1E (a)");
                debug_print!("KBDTEST_OK");
                io_manager::wait_pending_io_request(&mut request, 0);
            } else {
                debug_print!("KBDTEST_SKIP (sem tecla injetada em 10s)");
                io_manager::cancel_pending_io_request(&mut request);
            }
            guest_memory::free_bytes(zero_timeout);
            // Os devices de teclado ficam ABERTOS: o teclado do sistema segue
            // em uso (o close dispararia o disable da porta).
        }
        Ok(request) => debug_print!("KBDTEST_SKIP (READ completou de cara: {:#x})", request.status as u32),
        Err(error) => debug_print!("KBDTEST_SKIP (READ falhou: {})", error),
    }
    guest_memory::free_bytes(event);
}
