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
use crate::ntos::ps::process;
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

/// Rastreio de serviços (`OPENNT_TRACE_SYSCALLS`): o nome do OBJECT_ATTRIBUTES
/// dos serviços que abrem ou criam objetos por nome, lido (sondado) antes da
/// chamada. Nt{Open,Create}*(Handle*, Access, ObjectAttributes*, ...) têm o
/// OA no terceiro argumento; os serviços de atributos de arquivo, no primeiro.
fn traced_object_name(name: &str, arguments: &[u64; 4]) -> Option<alloc::string::String> {
    let attributes = match name {
        "NtQueryAttributesFile" | "NtQueryFullAttributesFile" | "NtDeleteFile" => arguments[0],
        "NtAlpcCreatePort" | "NtAlpcConnectPortEx" => arguments[1],
        "NtOpenProcessToken" | "NtOpenProcessTokenEx" | "NtOpenThreadToken" | "NtOpenThreadTokenEx" => return None,
        _ if name.starts_with("NtOpen") || name.starts_with("NtCreate") => arguments[2],
        _ => return None,
    };
    if attributes == 0 {
        return None;
    }
    registry::parse_user_object_attributes(attributes).map(|parsed| parsed.path).filter(|path| !path.is_empty())
}

/// O nome da porta dos serviços de conexão, lido (sondado) antes da chamada:
/// a UNICODE_STRING PortName no segundo argumento do NtAlpcConnectPort, do
/// NtConnectPort e do NtSecureConnectPort, o OBJECT_ATTRIBUTES do
/// NtAlpcConnectPortEx. Uma falha de conexão aparece com o nome, inclusive
/// STATUS_OBJECT_NAME_NOT_FOUND (a porta que ainda não existe).
fn connect_port_name(name: &str, arguments: &[u64; 4]) -> Option<alloc::string::String> {
    use crate::ntos::inc::field::NtStruct as _;
    match name {
        "NtAlpcConnectPort" | "NtConnectPort" | "NtSecureConnectPort" => {
            let string = crate::ntos::inc::types::UnicodeString::try_at(arguments[1]).ok()?;
            let (length, buffer) = (string.length.probe_get().ok()?, string.buffer.probe_get().ok()?);
            state::try_read_user_wide_string(buffer, (length / 2).min(256) as u64).ok()
        }
        "NtAlpcConnectPortEx" => traced_object_name(name, arguments),
        _ => None,
    }
}

/// O retorno do chamador do stub da ntdll (`[rsp]` do RSP de modo usuário
/// salvo na entrada do syscall, não a pilha de argumentos copiada que os
/// handlers recebem): o `rip` da linha é sempre o `ret` do próprio stub.
fn stub_return() -> u64 {
    let user_stack = state::syscall_record().user_stack;
    if user_stack == 0 || !state::probe_user_read(user_stack, 8) { 0 } else { guest::try_read::<u64>(user_stack).unwrap_or(0) }
}

/// O chamador do stub como `módulo+deslocamento` quando o endereço cai num
/// módulo.
fn describe_caller(caller: u64) -> alloc::string::String {
    if caller == 0 {
        return alloc::string::String::from("0x0");
    }
    super::crash_report::module_offset(caller)
}

/// Falhas já vistas por (pid, serviço, status, chamador).
static FAILURE_LINES: SpinLock<alloc::collections::BTreeMap<(u64, alloc::string::String, u32, u64), u32>> = SpinLock::new(alloc::collections::BTreeMap::new());

/// Quantas vezes a falha (pid, serviço, status, chamador) já aconteceu, com
/// esta, quando ela sai na serial: as quatro primeiras e depois uma a cada
/// 256, como as `[win32k] FALHOU`; todas com TRACEFAILURES (`--trace-failures`).
/// Uma falha repetida do mesmo chamador é o padrão comum do Windows (o
/// NtOpenThreadToken sem personificação, a sondagem de valores do
/// Registro), e cada byte da serial custa uns 5 us no WHPX.
fn failure_printed(name: &str, result: u32, caller: u64) -> Option<u32> {
    if crate::ntos::init::boot_config::trace_failures() {
        return Some(1);
    }
    let key = (process::get_current_process_id(), alloc::string::String::from(name), result, caller);
    let count = {
        let mut lines = FAILURE_LINES.lock();
        let count = lines.entry(key).or_insert(0);
        *count = count.saturating_add(1);
        *count
    };
    super::win32k_status::printed(count).then_some(count)
}

/// Linhas `negado:` já impressas por (pid, serviço, motivo, tipo).
static DENIAL_LINES: SpinLock<alloc::collections::BTreeMap<(u64, alloc::string::String, &'static str, alloc::string::String), u32>> = SpinLock::new(alloc::collections::BTreeMap::new());

/// O sufixo ` negado: ...` de uma recusa de acesso (STATUS_ACCESS_DENIED ou
/// STATUS_PRIVILEGE_NOT_HELD) com a checagem que recusou: as 4 primeiras de
/// cada (pid, serviço, motivo, tipo), depois uma a cada 64.
fn denial_detail(name: &str, arguments: &[u64; 4], result: u32, denial: Option<state::Denial>) -> alloc::string::String {
    let Some(denial) = denial.filter(|_| matches!(result, 0xC000_0022 | 0xC000_0061)) else { return alloc::string::String::new() };
    let key = (process::get_current_process_id(), alloc::string::String::from(name), denial.reason, denial.type_name.clone());
    let count = {
        let mut lines = DENIAL_LINES.lock();
        let count = lines.entry(key).or_insert(0);
        *count += 1;
        *count
    };
    if count > 4 && count % 64 != 0 {
        return alloc::string::String::new();
    }
    let missing = denial.desired & !denial.granted;
    // O nome do OBJECT_ATTRIBUTES de uma abertura ou criação por nome (a
    // chave do NtOpenKeyEx, o evento do NtOpenEvent...).
    let object = traced_object_name(name, arguments).map_or_else(alloc::string::String::new, |path| alloc::format!(" objeto=\"{path}\""));
    alloc::format!(
        " negado: {} tipo={} pedido={:#x} concedido={:#x} falta={:#x} imagem={}{}",
        denial.reason,
        if denial.type_name.is_empty() { "-" } else { &denial.type_name },
        denial.desired,
        denial.granted,
        missing,
        super::crash_report::current_image_name(),
        object
    )
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
    let traced_name = if crate::ntos::init::boot_config::TRACE_SYSCALLS { traced_object_name(name, &arguments) } else { None };
    let port_name = connect_port_name(name, &arguments);
    // O IoControlCode/FsControlCode (sexto argumento) antes da chamada.
    let control_code = if matches!(name, "NtDeviceIoControlFile" | "NtFsControlFile") { Some(state::stack_arg32(user_rsp, 6)) } else { None };
    // A recusa de acesso é anotada por chamada.
    let _ = state::take_denial();
    let result = handler(arguments[0], arguments[1], arguments[2], arguments[3], user_rsp);
    let denial = state::take_denial();
    let result = result?;
    if crate::ntos::init::boot_config::TRACE_SYSCALLS {
        crate::debug_print!("[sys] {}:{} {}({:#x}, {:#x}, {:#x}, {:#x}) = {:#x} (rip {:#x}){}", crate::ntos::ps::process::get_current_process_id(), crate::ntos::ps::process::get_current_thread_id(), name, arguments[0], arguments[1], arguments[2], arguments[3], result, rip, traced_name.map_or_else(alloc::string::String::new, |path| alloc::format!(" \"{path}\"")));
    }
    let failed = result & 0x8000_0000 != 0;
    if failed && (![0xC000_0034, 0xC000_0225, 0x102, 0xC000_0023, 0xC000_0353].contains(&result) || port_name.is_some()) {
        let caller = stub_return();
        if let Some(count) = failure_printed(name, result, caller) {
            let mut detail = alloc::string::String::new();
            if let Some(port) = &port_name {
                detail = alloc::format!(" porta \"{port}\"");
            }
            if let Some(code) = control_code {
                detail = alloc::format!(" codigo {code:#x}");
            }
            detail.push_str(&denial_detail(name, &arguments, result, denial));
            if count > 4 {
                detail.push_str(&alloc::format!(" ({count} vezes)"));
            }
            crate::debug_print!("[usermode] {}:{} {} FALHOU com {:#x} (rip {:#x}, chamador {}){}", crate::ntos::ps::process::get_current_process_id(), crate::ntos::ps::process::get_current_thread_id(), name, result, rip, describe_caller(caller), detail);
        }
    }
    Ok(result)
}

/// Chamada vinda do descritor: amostra a memória antes das liberações e
/// contabiliza o tempo de kernel da thread.
pub fn invoke_service(name: &str, arguments: [u64; 4], rip: u64, user_rsp: u64) -> Result<u32, KernelError> {
    let thread = process::get_current_thread();
    let started = clock::uptime_ms();
    let result = handle_service(Some(name), arguments, rip, user_rsp, 0);
    process::account_thread(thread, true, (clock::uptime_ms() - started) * 10_000);
    result
}

/// Liga a ponte ao despacho de serviços.
pub fn register() {
    system_services::set_user_invoker(invoke_service);
}
