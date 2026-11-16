//! Ponto de entrada do kernel (o KiSystemStartup do OpenNT).
//!
//! Boot em fases, estilo NT: fase 0 (núcleo mínimo) -> fase 1 (I/O, drivers,
//! serviços do Registry, PnP) -> processos (serviço de teclado + shell) ->
//! laço principal que despacha IRQs e o escalonador.

use alloc::format;

use crate::drivers::{console, input::keyboard, video::vga};
use crate::hal::kmalloc;
use crate::ntos::init::{boot_config, phase0, phase1};
use crate::nano::{interrupts, message_channels};
use crate::ntos::ke::clock;
use crate::ntos::mm::shared_user_data;
use crate::ntos::ps::scheduler;

fn banner() {
    console::print("=================================================");
    console::print(&format!(" OpenNT v{} - kernel 100% Rust", crate::VERSION));
    console::print(" bare metal x86-64 (BIOS real mode -> long mode)");
    console::print(&format!(" RAM: {} MB", kmalloc::ram_top() / 1_048_576));
    console::print("=================================================");
}

/// Despeja os KEYBOARD_INPUT_DATA lidos -> ASCII -> canal `kbd`. KEY_BREAK
/// (bit 0 de Flags) vira o break code.
fn pump_keyboard_data(records: &[u8]) {
    use core::mem::{offset_of, size_of};
    use crate::ntos::inc::types::KeyboardInputData;
    let field = |record: &[u8], offset: usize| u16::from_le_bytes([record[offset], record[offset + 1]]);
    for record in records.chunks_exact(size_of::<KeyboardInputData>()) {
        let make_code = field(record, offset_of!(KeyboardInputData, make_code));
        let flags = field(record, offset_of!(KeyboardInputData, flags));
        let scancode = if flags & 1 != 0 { make_code as u8 | 0x80 } else { make_code as u8 };
        if let Some(character) = keyboard::decode(scancode) {
            message_channels::send("kbd", character);
        }
    }
}

/// Serviço de teclado: processo que lê as teclas e publica os caracteres no
/// canal `kbd` (fluxo nanokernel: driver -> IPC -> shell).
///
/// Mantém um READ pendente em `\Device\KeyboardClass0` (i8042prt.sys +
/// kbdclass.sys reais) com um evento de notificação. Sem a pilha real (os
/// binários não vieram no build), lê do driver PS/2 interno: IRQ1 -> ring
/// buffer -> decode -> canal.
async fn keyboard_service() -> u32 {
    use crate::ntos::io::io_manager::{self, IoParams, IoResult};
    use crate::ntos::inc::types::{Irp, NtStruct};
    use crate::ntos::ke::dispatcher;
    use crate::ntos::mm::guest_memory as guest;
    let opened = io_manager::open_device("\\Device\\KeyboardClass0", false);
    let Some(handle) = opened.ok().filter(|opened| opened.status == 0).map(|opened| opened.handle) else {
        debug_print!("[kbd] KeyboardClass0 indisponivel; lendo do driver PS/2 interno (IRQ1 + ring buffer)");
        loop {
            while let Some(character) = keyboard::poll_key() {
                message_channels::send("kbd", character);
            }
            scheduler::yield_now().await;
        }
    };
    debug_print!("[kbd] lendo teclas do driver real (i8042prt+kbdclass)");
    let event = guest::alloc_bytes(0x18);
    let zero_timeout = guest::alloc_bytes(8); // LARGE_INTEGER 0
    let mut pending: Option<io_manager::IoRequest> = None;
    loop {
        match pending.as_mut() {
            None => {
                dispatcher::initialize_event(event, 0, false);
                if let Ok(request) = io_manager::read_handle(handle, IoParams { user_event: event, buffer_length: Some(48), binary: true, ..Default::default() }) {
                    if request.status == 0 && request.info > 0 {
                        // Dados já na fila: o resultado traz os bytes.
                        if let IoResult::Bytes(bytes) = &request.result {
                            pump_keyboard_data(&bytes[..(request.info as usize).min(bytes.len())]);
                        }
                    } else if request.status == 0x103 {
                        pending = Some(request);
                    }
                }
            }
            Some(request) => {
                if dispatcher::wait_for_single_object(event, zero_timeout, 0, false) == 0 {
                    // O READ completou: lê os dados ANTES de liberar.
                    let data = request.pending_buffer;
                    // SAFETY: o IRP do READ pendente (liberado só depois).
                    let information = unsafe { Irp::at(request.pending_irp) }.io_status.information.get();
                    pump_keyboard_data(&guest::read_bytes(data, information as usize));
                    io_manager::wait_pending_io_request(request, 0);
                    pending = None;
                }
            }
        }
        scheduler::yield_now().await;
    }
}

/// `--start-driver`: ativa a CI para esta carga e as seguintes e inicia o
/// serviço; imprime `DRIVER_START_COMPLETED` com o estado e os códigos.
fn start_boot_driver(name: &str) {
    use crate::ntos::cm::service::{driver as driver_services, database as service_database};
    let (mut win32, mut ntstatus) = (0u32, 0u32);
    let started = crate::ntos::se::code_integrity::initialize().map_err(|error| (31, error.status, error.message)).and_then(|_| {
        crate::ntos::init::exports::set_api_trace(boot_config::trace_driver_api());
        let started = driver_services::start(name).map(|_| ()).map_err(|error| (error.win32, error.ntstatus.unwrap_or(0), error.message));
        crate::ntos::init::exports::set_api_trace(false);
        started
    });
    if let Err((code, status, message)) = started {
        win32 = if code == 0 { 31 } else { code };
        ntstatus = status;
        debug_print!("[boot-driver] {}: {}", name, message);
    }
    let state = match service_database::read(name) {
        Ok(Some(_)) => service_database::status(name).map_or(0, |status| status.current_state),
        _ => 0,
    };
    debug_print!("DRIVER_START_COMPLETED name={} state={} win32={} ntstatus=0x{:x}", name, state, win32, ntstatus);
    if state == 4 {
        crate::ntos::test::file_system_mount::after_driver_start(name);
        crate::ntos::test::console_driver::after_driver_start(name);
        crate::ntos::test::import_cycle::after_driver_start(name);
        crate::ntos::test::minifilters::after_driver_start(name);
    }
}

/// PREEMPÇÃO POR TIMER: cada IRQ do timer do LAPIC (100 Hz) é um quantum.
fn timer_tick(_vector: u8, _count: u32) {
    scheduler::tick(-1);
}

pub fn kmain() -> ! {
    vga::clear();
    banner();

    phase0::init(); // nanokernel + escalonador + arquivos em memória
    phase1::init(); // I/O manager + drivers internos + NTFS + serviços + PnP
    if let Err(error) = crate::ntos::ex::system_services::initialize() {
        debug_print!("[services] tabela nativa nao registrada: {}", error);
    }

    // Início opcional de drivers antes do programa de usuário, pelo mesmo
    // ciclo de vida do SCM/CM, na ordem da lista (a dos grupos de boot do
    // Windows: NDIS antes do Tcpip, o Tcpip antes do AFD). O marcador de
    // cada um registra a conclusão, não o sucesso da carga.
    for name in boot_config::start_driver().split(',').filter(|name| !name.is_empty()) {
        start_boot_driver(name);
    }

    // Com o depurador do kernel (`--kd`), o contrato que os drivers veem.
    if !boot_config::kernel_debugger().is_empty() {
        crate::ntos::test::kernel_debugger::run();
    }

    debug_print!("KERNEL_RS_OK"); // kernel Rust montado e executando

    if let Err(error) = crate::ntos::ps::user::index::init() {
        debug_print!("[usermode] anel 3 nao armado: {}", error);
    }

    // Os drivers iniciados, usados por um processo de teste (null, beep, fs_rec).
    for name in boot_config::start_driver().split(',').filter(|name| !name.is_empty()) {
        crate::ntos::test::boot_drivers::after_start(name);
    }

    // `--shutdown-test`: grava pelo ntfs.sys e no Registro e desliga (ou
    // confere o que o desligamento anterior deixou e desliga).
    if !boot_config::shutdown_test().is_empty() {
        crate::ntos::test::shutdown::run_boot_scenario();
    }

    if boot_config::kernel_test_scope() != "none" {
        crate::ntos::test::self_test::run();
    }

    // O boot comum inicializa a pilha PS/2 real antes de despachar os
    // processos; a suíte de testes já a inicializa.
    if boot_config::kernel_test_scope() == "none" && crate::drivers::input::keyboard_stack::binaries_present() {
        if let Err(error) = crate::drivers::input::keyboard_stack::initialize() {
            debug_print!("[kbd] pilha PS/2 real nao inicializou: {}", error);
        }
    }

    // processos: serviço de teclado (IPC) + shell; no boot do processo
    // inicial real, o smss.exe no lugar do shell
    message_channels::create_channel("kbd");
    scheduler::spawn("kbd-service", keyboard_service());
    if boot_config::smss_boot() {
        if let Err(error) = crate::ntos::init::initial_process::start() {
            debug_print!("[init] processo inicial nao criado: {}", error);
        }
    } else if boot_config::user_program() == "shell" {
        scheduler::spawn("shell", crate::shell::main());
    } else {
        debug_print!("[boot] programa de usuario desconhecido: {}", boot_config::user_program());
    }

    // Se a plataforma não entregar IRQs, cai no modo cooperativo com log claro.
    interrupts::register_irq_handler(interrupts::VECTOR_LAPIC_TIMER, timer_tick);
    let warmup_end = clock::uptime_ms() + 300;
    while clock::uptime_ms() < warmup_end {
        shared_user_data::update_system_times();
        crate::ntos::ke::run_kernel_tasks();
        interrupts::dispatch_pending();
        scheduler::tick(-1); // cooperativo durante o aquecimento
    }

    if interrupts::irqs_arriving() {
        debug_print!("[kernel] preempcao por timer ativa (quantum 10ms, LAPIC timer vetor 0x40)");
        loop {
            shared_user_data::update_system_times();
            crate::ntos::ke::run_kernel_tasks();
            interrupts::dispatch_pending(); // IRQ do timer -> scheduler::tick
            // Como o laço ocioso do NT: uma thread aprontada pelo sinal não
            // espera o próximo tick do relógio.
            if crate::ntos::ke::thread_dispatch::has_ready_threads() {
                scheduler::tick(-1);
            }
            core::hint::spin_loop();
        }
    } else {
        debug_print!("[kernel] AVISO: plataforma nao entrega IRQs — escalonador cooperativo (sem preempcao)");
        loop {
            shared_user_data::update_system_times();
            crate::ntos::ke::run_kernel_tasks();
            interrupts::dispatch_pending();
            scheduler::tick(-1);
        }
    }
}
