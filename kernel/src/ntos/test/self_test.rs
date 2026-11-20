//! Autoteste do kernel (fase 1).
//!
//! Exercita os módulos já implementados: MemoryFileSystem, chamadas numeradas,
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

/// As opções de carga do loader: este boot chegou com o autoteste pelo
/// bloco (`KERNELTESTSCOPE=all`), que também mostra a ntdll de bring-up do
/// bundle; e o leitor segue o formato do LoadOptions (nome sem diferença de
/// maiúsculas, valor como escrito, a primeira ocorrência vale, bloco sem
/// assinatura ou com texto fora do ASCII imprimível ignorado).
fn load_options() {
    use crate::ntos::init::{boot_config, load_options as options};
    let text = boot_config::load_options();
    assert(options::value(text, options::KERNEL_TEST_SCOPE) == Some(boot_config::kernel_test_scope()) && boot_config::kernel_tests(), "opcoes de carga: o autoteste veio do bloco do loader");
    assert(crate::hal::bundle::read("apps/ntdll.dll").is_some(), "opcoes de carga: ntdll de bring-up visivel com o autoteste");
    let sample = "DEBUG debugport=COM2 STARTDRIVER=NDIS,AFD startdriver=beep CONSOLEMIRROR";
    assert(options::flag(sample, "debug") && options::flag(sample, options::CONSOLE_MIRROR) && !options::flag(sample, options::DEBUG_PORT), "opcoes de carga: flags");
    assert(options::value(sample, options::DEBUG_PORT) == Some("COM2") && options::value(sample, options::START_DRIVER) == Some("NDIS,AFD"), "opcoes de carga: valores");
    assert(options::value(sample, options::DISPLAY).is_none() && options::value("", options::DISPLAY).is_none(), "opcoes de carga: ausentes");
    let mut block = [0u8; options::BLOCK_SIZE];
    block[..4].copy_from_slice(&options::SIGNATURE.to_le_bytes());
    block[4..8].copy_from_slice(&5u32.to_le_bytes());
    block[8..13].copy_from_slice(b"DEBUG");
    assert(options::text_of(&block) == Some("DEBUG"), "opcoes de carga: bloco valido");
    block[10] = 0;
    assert(options::text_of(&block).is_none(), "opcoes de carga: texto fora do ASCII");
    block[10] = b'B';
    block[4..8].copy_from_slice(&(options::TEXT_MAX as u32 + 1).to_le_bytes());
    assert(options::text_of(&block).is_none(), "opcoes de carga: tamanho fora do setor");
    block[4..8].copy_from_slice(&5u32.to_le_bytes());
    block[0] ^= 1;
    assert(options::text_of(&block).is_none(), "opcoes de carga: sem assinatura");
}

/// O bloco de memória física e o alocador de frames: o bloco tem toda a RAM
/// do E820 abaixo do limite do mapa direto (menos a página 0) e é o total
/// da partição; o alocador recebe o bloco inteiro menos PFN_EXCLUDED, até o
/// topo da RAM; a lista livre do banco nativo encadeia exatamente os frames
/// livres do bitmap.
fn physical_memory_block(assert: fn(bool, &str)) {
    use crate::ntos::mm::{native_frame_descriptors, physical_layout};
    let block = physical_layout::ranges();
    let page = memory_map::PAGE_SIZE;
    let block_pages: u64 = block.iter().map(|&(base, top)| (top - base) / page).sum();
    assert(
        block_pages == physical_layout::number_of_physical_pages() && pfn::total_count() == block_pages && pfn::partition().total == block_pages,
        "bloco de memoria fisica: MmNumberOfPhysicalPages e o total da particao",
    );
    let (lowest, highest) = pfn::physical_page_bounds();
    assert(
        block.first().is_some_and(|&(base, _)| base >= page && base / page == lowest) && block.last().is_some_and(|&(_, top)| top / page - 1 == highest) && !physical_layout::contains_ram_range(0, page),
        "bloco de memoria fisica: Lowest/Highest nas pontas, pagina 0 fora",
    );
    let firmware = physical_layout::firmware_map();
    let whole_ram = firmware.iter().filter(|range| range.range_type == 1).all(|ram| {
        let base = ram.base.max(page).div_ceil(page) * page;
        let top = (ram.base + ram.length).min(memory_map::PHYSICAL_ADDRESS_LIMIT) / page * page;
        let touched = firmware.iter().any(|other| other.range_type != 1 && other.base < ram.base + ram.length && other.base + other.length > ram.base);
        base >= top || touched || physical_layout::contains_ram_range(base, top - base)
    });
    assert(whole_ram, "bloco de memoria fisica: toda a RAM do E820 abaixo do limite do mapa direto");
    let overlap = |(low, high): (u64, u64), (base, top): (u64, u64)| high.min(top).saturating_sub(low.max(base));
    let excluded: u64 = block.iter().map(|&range| memory_map::PFN_EXCLUDED.iter().map(|&reserved| overlap(range, reserved)).sum::<u64>()).sum();
    let ranges = pfn::ranges();
    let managed: u64 = ranges.iter().map(|&(base, top)| (top - base) / page).sum();
    assert(
        pfn::frame_count() == block_pages - excluded / page && managed == pfn::frame_count() && ranges == pfn::allocator_ranges(&block, &memory_map::PFN_EXCLUDED),
        "alocador de frames: o bloco inteiro menos PFN_EXCLUDED",
    );
    assert(
        ranges.iter().all(|&(base, top)| physical_layout::contains_ram_range(base, top - base) && memory_map::PFN_EXCLUDED.iter().all(|&reserved| overlap((base, top), reserved) == 0))
            && ranges.last().map(|range| range.1) == block.last().map(|range| range.1),
        "alocador de frames: so RAM do bloco fora de PFN_EXCLUDED, ate o topo da RAM",
    );
    let (walk, available) = pfn::native_free_list();
    assert(walk.linked && walk.reached == walk.free_count && walk.last_reached == walk.last_free && walk.free_count == available, "banco de PFN nativo: a lista livre encadeia os frames livres do bitmap");
    // O banco só tem descritores dos frames do bloco: as pontas sim, o
    // primeiro frame depois de uma faixa (um buraco) não.
    let described = |frame: u64| native_frame_descriptors::descriptor(frame).is_some_and(|entry| entry.u4.pfn_exists() != 0);
    let hole = block.first().map(|range| range.1 / page).filter(|&frame| block.len() > 1 && !physical_layout::contains_ram_range(frame * page, page));
    assert(described(lowest) && described(highest) && hole.is_none_or(|frame| native_frame_descriptors::descriptor(frame).is_none()), "banco de PFN nativo: descritores so dos frames do bloco");
    high_memory(assert, &block);
}

/// RAM acima de 4 GB: o mapa direto vai até o topo do bloco e um frame de
/// lá sai do PFN, guarda dados pelo endereço físico, tem o descritor em uso
/// e volta à lista livre.
fn high_memory(assert: fn(bool, &str), block: &[(u64, u64)]) {
    use crate::ntos::mm::native_frame_descriptors;
    let top = block.last().map_or(0, |range| range.1);
    if top <= memory_map::BOOT_DIRECT_MAP_LIMIT {
        return;
    }
    assert(physical::direct_map_limit() >= top, "mapa direto ate o topo da RAM acima de 4 GB");
    let frame = pfn::alloc_contiguous(1, 1, 0xF_FFFF_FFFF, memory_map::BOOT_DIRECT_MAP_LIMIT / memory_map::PAGE_SIZE, 0);
    assert(frame >= memory_map::BOOT_DIRECT_MAP_LIMIT && frame < top, "PFN entrega um frame acima de 4 GB");
    physical::write64(frame, 0x0123_4567_89AB_CDEF);
    physical::write64(frame + 0xFF8, !frame);
    let kept = physical::read64(frame) == 0x0123_4567_89AB_CDEF && physical::read64(frame + 0xFF8) == !frame;
    let active = native_frame_descriptors::mapping_of(frame) == Some((0, 0, 0));
    let freed = pfn::free_page(frame) && native_frame_descriptors::mapping_of(frame).is_none();
    assert(kept && active && freed, "frame acima de 4 GB: dados pelo mapa direto, descritor em uso e devolvido a lista livre");
}

fn is_text(data: Option<FileData>, expected: &str) -> bool {
    matches!(data, Some(FileData::Text(text)) if text == expected)
}

pub fn run() {
    // `--kernel-test-scope=disk-stress`: só a estressa do caminho de escrita
    // do disco, com mais rodadas.
    if crate::ntos::init::boot_config::kernel_test_scope() == "disk-stress" {
        super::phase7::disk_write_stress(assert, 300, 3);
        debug_print!("DISK_STRESS_OK");
        return;
    }
    // `--kernel-test-scope=e-process` (com `--storage=nvme`): processos e
    // mapeamentos de arquivo a partir do volume E: do ntfs.sys real.
    if crate::ntos::init::boot_config::kernel_test_scope() == "e-process" {
        super::e_process::run(assert);
        debug_print!("E_PROCESS_OK");
        return;
    }
    load_options();
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
    let hello = programs::find_program("/hello.exe");
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
    physical_memory_block(assert);

    // a imagem do kernel na ImageBase traduz para os frames que o stage2
    // carregou; a metade de usuário não tem identidade
    assert(paging::translate(memory_map::KERNEL_VIRTUAL_BASE + 0x1000) == memory_map::KERNEL_IMAGE_PHYS + 0x1000, "imagem do kernel na ImageBase");
    assert(paging::translate(memory_map::KERNEL_IMAGE_PHYS) == 0 && paging::translate(memory_map::AP_TRAMPOLINE_PHYS) == 0, "sem identidade baixa");

    // VirtualAlloc: VA nova -> frame físico distinto, dados fluem pela tabela
    let va = virtual_memory::alloc(4096);
    assert(va > 0, "VirtualAlloc");
    let pa = paging::translate(va);
    assert(pa > 0 && (pa & !0xFFF) != (va & !0xFFF), "VA mapeada p/ frame distinto");
    guest_memory::write32(va, 0xC0FFEE);
    assert(guest_memory::read32(va) == 0xC0FFEE && physical::read32(pa) == 0xC0FFEE, "escrita pela VA mapeada");
    assert(paging::query_page(va, false).is_some_and(|page| page.physical_address == pa), "query_page");
    virtual_memory::free(va, 4096);
    assert(paging::translate(va) == 0, "pagina desmapeada no free");

    // imagem do kernel e dados exportados
    assert(kernel_data::read("MmUserProbeAddress") == memory_map::USER_ADDRESS_LIMIT, "MmUserProbeAddress");
    let kernel_va = memory_map::KERNEL_VIRTUAL_BASE + 0x1000;
    assert(guest_memory::read32(kernel_va) == physical::read32(memory_map::KERNEL_IMAGE_PHYS + 0x1000), "imagem do kernel sobre os frames de boot");
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

    // DPC: rotina nativa (ABI MS x64) chamada pela ponte MS-ABI do kernel
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
    // O tick dá até um passo por processo existente: com outras threads de
    // sistema no escalonador (as dos drivers da árvore de dispositivos,
    // paradas em esperas), a tarefa que cedeu volta pronta e pode ser
    // retomada no mesmo tick. O primeiro tick a leva pelo menos até o
    // yield; os seguintes a terminam.
    scheduler::tick(-1);
    assert(RAN.load(Ordering::SeqCst) >= 1, "sched passo 1");
    for _ in 0..4 {
        if RAN.load(Ordering::SeqCst) == 2 && scheduler::count() == before {
            break;
        }
        scheduler::tick(-1);
    }
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

    // relógio: a frequência do TSC medida de novo contra a mesma referência
    // do boot (timer do ACPI ou PIT) concorda com a calibrada (até 0,5%):
    // a calibração não depende de quanto a CPU virtual andou na janela.
    if let Some(measured) = clock::remeasure_tsc_frequency() {
        let calibrated = clock::tsc_frequency_hz();
        let difference = measured.abs_diff(calibrated);
        debug_print!("[selftest] TSC calibrado {} Hz, medido de novo {} Hz", calibrated, measured);
        assert(calibrated > 0 && difference * 200 <= calibrated, "TSC: a frequencia medida de novo concorda com a do boot (ate 0,5%)");
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
    assert(super::system_images::listed_in_system_window(&["kbdclass.sys", "i8042prt.sys"]), "teclado: kbdclass e i8042prt na janela de imagens de sistema");
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
            // Espera como um driver espera: a IRQ1 chega à ISR nativa do
            // i8042prt e o DPC chama o kbdclass durante o próprio
            // KeWaitForSingleObject, sem ninguém despachar as IRQs à mão.
            let timeout = guest_memory::alloc_bytes(8);
            guest_memory::write64(timeout, (-100_000_000i64) as u64); // 10 s relativos
            let completed = dispatcher::wait_for_single_object(event, timeout, 0, false) == 0;
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
            guest_memory::free_bytes(timeout);
            // Os devices de teclado ficam ABERTOS: o teclado do sistema segue
            // em uso (o close dispararia o disable da porta).
        }
        Ok(request) => debug_print!("KBDTEST_SKIP (READ completou de cara: {:#x})", request.status as u32),
        Err(error) => debug_print!("KBDTEST_SKIP (READ falhou: {})", error),
    }
    guest_memory::free_bytes(event);
}
