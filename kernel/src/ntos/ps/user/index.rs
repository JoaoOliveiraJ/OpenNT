//! Subsistema de modo usuário.
//!
//! `init` arma o anel 3 (pilhas reserva e de falta dupla, GDT/TSS da HAL,
//! KUSER_SHARED_DATA no endereço de usuário, modo estrito de posse da
//! memória de usuário, assert de CR3, registro semeado);
//! `invoke_service` é a ponte que o gateway nativo escolhido pelo descritor
//! usa para chegar ao handler registrado por nome. Os módulos de área
//! registram seus handlers no init do ntoskrnl.

use crate::ntos::ex::system_services;
use crate::ntos::ke::{clock, context_switch};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::{kernel_stack, paging, shared_user_data};
use crate::ntos::ps::{process, system_process_information};
use crate::ntos::ps::user::{memory, registry};
use crate::ntos::ps::user::state::{self, STATUS_NOT_IMPLEMENTED};
use crate::rtl::{KernelError, SpinLock};

/// `user_mode_init(fallback_stack, double_fault_stack)` da HAL de modo
/// usuário: devolve a GDT.
static USER_MODE_INIT: SpinLock<Option<fn(u64, u64) -> Result<u64, KernelError>>> = SpinLock::new(None);
/// Inicializações que dependem de módulos posteriores (CSR, `cm::service::rpc`,
/// ksecdd), nesta ordem.
static LATE_INITIALIZERS: SpinLock<[Option<fn() -> Result<(), KernelError>>; 3]> = SpinLock::new([None; 3]);
/// `call_capture::consume`, quando a captura de export está ligada.
static CAPTURE_CONSUMER: SpinLock<Option<fn()>> = SpinLock::new(None);

pub mod late {
    pub const CSR: usize = 0;
    pub const SERVICE_RPC: usize = 1;
    pub const KSECDD: usize = 2;
}

pub fn set_user_mode_init(init: fn(u64, u64) -> Result<u64, KernelError>) {
    *USER_MODE_INIT.lock() = Some(init);
}

pub fn set_late_initializer(slot: usize, initializer: fn() -> Result<(), KernelError>) {
    LATE_INITIALIZERS.lock()[slot] = Some(initializer);
}

pub fn set_capture_consumer(consumer: fn()) {
    *CAPTURE_CONSUMER.lock() = Some(consumer);
}

/// `call_capture::consume()` na saída do intervalo de usuário.
pub fn consume_capture() {
    if let Some(consume) = *CAPTURE_CONSUMER.lock() {
        consume();
    }
}

/// CPU pronta para o anel 3.
pub fn init() -> Result<(), KernelError> {
    let Some(user_mode_init) = *USER_MODE_INIT.lock() else { return Err(KernelError::new("HAL de modo usuario indisponivel")) };
    // Cada thread despachada traz a sua pilha de kernel (KPRCB.RspBase e
    // TSS.RSP0 vêm da InitialStack dela). A CPU ganha duas pilhas próprias,
    // permanentes: a reserva, para o anel 3 cru de uma thread que roda na
    // pilha de boot, e a da IST da falta dupla, onde um estouro de pilha de
    // kernel vira diagnóstico em vez de falta tripla.
    let fallback = kernel_stack::create(false)?;
    let double_fault = kernel_stack::create(false)?;
    let gdt = user_mode_init(fallback.initial, double_fault.initial)?;
    let top = fallback.initial;
    // KUSER_SHARED_DATA no endereço de usuário real (só leitura para o anel
    // 3), o mesmo frame da visão de kernel, como em todo espaço de
    // endereçamento.
    if shared_user_data::frame() == 0 {
        return Err(KernelError::new("KUSER_SHARED_DATA sem frame (init do mm faltou?)"));
    }
    if !shared_user_data::map_user_view_in(paging::current_root()) {
        return Err(KernelError::new("mapPage falhou p/ KUSER_SHARED_DATA de usuario"));
    }
    crate::debug_print!("[usermode] ring 3 armado: GDT em {:#x}, pilha reserva ate {:#x}, IST da falta dupla ate {:#x}, KUSER user em 0x7FFE0000", gdt, top, double_fault.initial);
    // Modo estrito de posse: daqui em diante toda sonda de VA de usuário
    // exige o processo dono corrente (ou anexado) ou uma faixa de sistema.
    guest::set_ownership_check(Some(memory::check_user_access));
    // Assert de CR3: toda VA de usuário que o kernel toca, confiável ou
    // sondada, cai na raiz do processo corrente.
    guest::set_root_check(Some(context_switch::check_loaded_root));
    registry::seed_registry_for_user_mode()?;
    let initializers = *LATE_INITIALIZERS.lock();
    for initializer in initializers.into_iter().flatten() {
        initializer()?;
    }
    Ok(())
}

/// Entrada por número para os testes diretos do subsistema.
pub fn handle(number: u32, arguments: [u64; 4], rip: u64, user_rsp: u64) -> Result<u32, KernelError> {
    let name = state::with(|state| state.name_by_number.get(&number).cloned());
    handle_service(name.as_deref(), arguments, rip, user_rsp, number)
}

/// Despacha ao handler por nome; NOT_FOUND, TIMEOUT, BUFFER_TOO_SMALL e
/// PORT_NOT_SET são respostas legítimas e não aparecem como falha.
pub fn handle_service(name: Option<&str>, arguments: [u64; 4], rip: u64, user_rsp: u64, number: u32) -> Result<u32, KernelError> {
    if state::with(|state| !state.capture_export.is_empty()) {
        if let Some(consume) = *CAPTURE_CONSUMER.lock() {
            consume();
        }
    }
    let Some((name, handler)) = name.and_then(|name| state::handler(name).map(|handler| (name, handler))) else {
        let label = name.map_or_else(|| alloc::format!("{number:#x}"), alloc::string::String::from);
        crate::debug_print!("[usermode] syscall {} sem implementacao (rip {:#x}, args={:#x},{:#x},{:#x},{:#x})", label, rip, arguments[0], arguments[1], arguments[2], arguments[3]);
        return Ok(STATUS_NOT_IMPLEMENTED);
    };
    if state::with(|state| state.seen_syscalls.insert(alloc::string::String::from(name))) {
        crate::debug_print!("[usermode] primeiro: {}", name);
    }
    let result = handler(arguments[0], arguments[1], arguments[2], arguments[3], user_rsp)?;
    if crate::ntos::init::boot_config::TRACE_SYSCALLS {
        crate::debug_print!("[sys] {}:{} {}({:#x}, {:#x}, {:#x}, {:#x}) = {:#x} (rip {:#x})", crate::ntos::ps::process::get_current_process_id(), crate::ntos::ps::process::get_current_thread_id(), name, arguments[0], arguments[1], arguments[2], arguments[3], result, rip);
    }
    if result & 0x8000_0000 != 0 && ![0xC000_0034, 0xC000_0225, 0x102, 0xC000_0023, 0xC000_0353, 0xC000_0002].contains(&result) {
        crate::debug_print!("[usermode] {} FALHOU com {:#x} (rip {:#x})", name, result, rip);
    }
    Ok(result)
}

/// Chamada vinda do descritor: amostra a memória antes das liberações e
/// contabiliza o tempo de kernel da thread.
pub fn invoke_service(name: &str, arguments: [u64; 4], rip: u64, user_rsp: u64) -> Result<u32, KernelError> {
    let thread = process::get_current_thread();
    let started = clock::uptime_ms();
    if matches!(name, "NtFreeVirtualMemory" | "NtUnmapViewOfSection" | "NtUnmapViewOfSectionEx") {
        system_process_information::sample();
    }
    let result = handle_service(Some(name), arguments, rip, user_rsp, 0);
    process::account_thread(thread, true, (clock::uptime_ms() - started) * 10_000);
    result
}

/// Liga a ponte ao despacho de serviços.
pub fn register() {
    system_services::set_user_invoker(invoke_service);
}
