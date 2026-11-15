//! O processo inicial: o smss.exe real (`--initial-process=smss`).
//!
//! O papel do StartFirstUserProcess do ntoskrnl 19041. Ele monta no pool um
//! RTL_USER_PROCESS_PARAMETERS normalizado com:
//!
//! - ImagePathName e CommandLine `\SystemRoot\System32\smss.exe`;
//! - diretório corrente = NtSystemRoot (`C:\Windows`), DllPath vazio;
//! - o ambiente protegido do PspInitializeProtectedProcessParameters:
//!   `Path=C:\Windows\System32`, `SystemDrive=C:`, `SystemRoot=C:\Windows`;
//! - sem console nem handles padrão.
//!
//! Depois chama o RtlCreateUserProcessEx (o ZwCreateUserProcess com a thread
//! suspensa, protegido WinTcb-Light, PS_PROTECTION 0x61), marca o processo
//! como crítico (ProcessBreakOnTermination) e retoma a thread. Aqui a
//! criação passa pelo caminho único (`ps/create.rs`): o processo sai parado,
//! recebe a proteção e a marca de crítico e só então entra no despachante,
//! o que equivale à thread suspensa retomada depois.
//!
//! O processo System segue vivo e despacha: o laço principal do kernel e o
//! `scheduler::tick` dão intervalos às threads de usuário.
//!
//! O portão do M0 (`SMSS_CSRSS_OK`) é uma observação, não um caminho: os
//! NtCreateUserProcess bem-sucedidos ficam registrados com quem chamou
//! ([`record_creation`]); quando uma thread pede pela primeira vez um serviço
//! da tabela do win32k ([`win32k_requested`], antes da conversão para thread
//! GUI do KiSystemCall64), o marcador sai se ela é do csrss.exe criado por um
//! smss.exe e o smss inicial e o csrss ainda estão vivos.
//!
//! O `WIN32K_LOADED` ([`session_driver_initialized`]) também é observação: o
//! smss da sessão carrega o `Kmode` pela SystemExtendServiceTableInformation
//! e o marcador sai quando o DriverEntry do win32k.sys volta com sucesso, a
//! tabela 1 do KeServiceDescriptorTableShadow publicada e os callouts Win32
//! estabelecidos.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::Eprocess;
use crate::ntos::init::boot_config;
use crate::ntos::ps::create::{self, CreateProcessRequest, ImageOrigin};
use crate::ntos::ps::process;
use crate::ntos::ps::process_parameters::ProcessParameters;
use crate::ntos::ps::user::process::{self as user_process, StartedProcess};
use crate::rtl::{KernelError, SpinLock};

/// NtInitialUserProcess.
const INITIAL_PROCESS_PATH: &str = "\\SystemRoot\\System32\\smss.exe";
/// STATUS_ALREADY_WIN32: a repetição da conversão de uma thread já GUI.
const STATUS_ALREADY_WIN32: u32 = 0x4000_001B;
/// O `Kmode` do Session Manager.
const WIN32K_PATH: &str = "\\SystemRoot\\System32\\win32k.sys";
/// O NtSystemRoot da instalação (KUSER_SHARED_DATA.NtSystemRoot).
const SYSTEM_ROOT: &str = "C:\\Windows";
/// PS_PROTECTION do processo inicial: PsProtectedTypeProtectedLight (1) com
/// PsProtectedSignerWinTcb (6).
const WINTCB_LIGHT: u8 = 0x61;

/// Um NtCreateUserProcess bem-sucedido: quem chamou e o processo novo.
struct Creation {
    creator_id: u64,
    creator_name: String,
    child_pointer: u64,
    child_id: u64,
    child_name: String,
}

/// O smss inicial, retido enquanto o sistema roda.
static INITIAL: SpinLock<Option<StartedProcess>> = SpinLock::new(None);
static CREATIONS: SpinLock<Vec<Creation>> = SpinLock::new(Vec::new());
static GATE_REACHED: AtomicBool = AtomicBool::new(false);

/// O nome curto da imagem de um processo (EPROCESS.ImageFileName).
fn image_name(process_pointer: u64) -> String {
    process::with_record(process_pointer, |record| record.name.clone()).unwrap_or_default()
}

/// O processo não terminou nem tem o fim pedido.
fn alive(process_pointer: u64) -> bool {
    process::with_record(process_pointer, |record| !record.terminated && !record.exiting).unwrap_or(false)
}

/// Os parâmetros do StartFirstUserProcess.
fn parameters() -> ProcessParameters {
    let mut parameters = ProcessParameters::for_image(INITIAL_PROCESS_PATH);
    parameters.command_line = String::from(INITIAL_PROCESS_PATH);
    parameters.current_directory = String::from(SYSTEM_ROOT);
    parameters.dll_path = String::new();
    parameters.environment = alloc::vec![alloc::format!("Path={SYSTEM_ROOT}\\System32"), String::from("SystemDrive=C:"), alloc::format!("SystemRoot={SYSTEM_ROOT}")];
    parameters.console_handle = 0;
    parameters
}

/// Cria o smss.exe e o põe no despachante; o kernel segue sem esperá-lo.
pub fn start() -> Result<(), KernelError> {
    let request = CreateProcessRequest { image: ImageOrigin::NtPath(String::from(INITIAL_PROCESS_PATH)), image_name: "smss.exe", parameters: parameters(), parent: None, thread_flags: 0, on_created: None, inherit_handles_from: None, protection: WINTCB_LIGHT, create_session: false };
    let created = create::create_user_process(&request).map_err(|failure| KernelError::with_status(alloc::format!("{INITIAL_PROCESS_PATH}: {failure}"), failure.status()))?;
    // ProcessBreakOnTermination, antes de a thread andar.
    // SAFETY: o EPROCESS recém-criado, retido pela criação.
    unsafe { Eprocess::at(created.process_pointer) }.set_break_on_termination(1);
    crate::debug_print!("[init] processo inicial {} (pid {}): protegido {:#x}, critico", INITIAL_PROCESS_PATH, created.process_id, WINTCB_LIGHT);
    let started = user_process::start_created(created)?;
    *INITIAL.lock() = Some(started);
    Ok(())
}

/// Registra um NtCreateUserProcess bem-sucedido de um processo de usuário.
pub fn record_creation(creator_pointer: u64, child_pointer: u64) {
    if !boot_config::SMSS_BOOT {
        return;
    }
    // SAFETY: os dois EPROCESS estão retidos por quem cria.
    let (creator_id, child_id) = unsafe { (Eprocess::at(creator_pointer).unique_process_id.get(), Eprocess::at(child_pointer).unique_process_id.get()) };
    let creation = Creation { creator_id, creator_name: image_name(creator_pointer), child_pointer, child_id, child_name: image_name(child_pointer) };
    crate::debug_print!("[init] {} (pid {}) criou {} (pid {}) por NtCreateUserProcess", creation.creator_name, creation.creator_id, creation.child_name, creation.child_id);
    CREATIONS.lock().push(creation);
}

/// O driver de sessão da classe 38 voltou do DriverEntry com `status`.
pub fn session_driver_initialized(name: &str, image_base: u64, status: u32) {
    if !boot_config::SMSS_BOOT || !name.eq_ignore_ascii_case(WIN32K_PATH) || status & 0x8000_0000 != 0 {
        return;
    }
    let shadow = crate::ntos::ex::service_table::shadow_second_table().unwrap_or([0; 4]);
    let callouts = crate::ntos::ps::win32::win32_callout();
    crate::debug_print!("[init] win32k.sys em {:#x}: DriverEntry -> {:#x}, Shadow[1] base {:#x} limite {}, callouts {:#x}", image_base, status, shadow[0], shadow[2] & 0xFFFF_FFFF, callouts.unwrap_or(0));
    if shadow[0] != 0 && shadow[2] & 0xFFFF_FFFF != 0 && callouts.is_some() {
        crate::debug_print!("WIN32K_LOADED");
    }
}

/// A conversão em thread GUI (PsConvertToGuiThread) de uma thread do
/// csrss.exe voltou com `status`: a primeira é anotada.
pub fn gui_thread_converted(status: u32) {
    static NOTED: AtomicBool = AtomicBool::new(false);
    if !boot_config::SMSS_BOOT || status == STATUS_ALREADY_WIN32 {
        return;
    }
    let current = process::get_current_process();
    let name = image_name(current);
    if !name.eq_ignore_ascii_case("csrss.exe") || NOTED.swap(true, Ordering::AcqRel) {
        return;
    }
    crate::debug_print!("[init] csrss.exe (pid {}): thread GUI pelo PsConvertToGuiThread -> {:#x}", process::get_current_process_id(), status);
}

/// Uma thread do processo corrente pediu pela primeira vez um serviço da
/// tabela do win32k (o KiSystemCall64 vai convertê-la em thread GUI).
pub fn win32k_requested(service_number: u32) {
    if !boot_config::SMSS_BOOT || GATE_REACHED.load(Ordering::Acquire) {
        return;
    }
    let current = process::get_current_process();
    let name = image_name(current);
    let loaded = crate::ntos::ps::win32::win32_callout().is_some();
    crate::debug_print!("[init] {} (pid {}) pediu o servico {:#x} da tabela do win32k ({})", name, process::get_current_process_id(), service_number, if loaded { "carregado" } else { "nao carregado" });
    if !name.eq_ignore_ascii_case("csrss.exe") {
        return;
    }
    let Some((creator_id, creator_name)) = CREATIONS.lock().iter().find(|creation| creation.child_pointer == current).map(|creation| (creation.creator_id, creation.creator_name.clone())) else { return };
    if !creator_name.eq_ignore_ascii_case("smss.exe") {
        return;
    }
    let Some(initial) = INITIAL.lock().as_ref().map(|started| (started.process_pointer, started.process_id)) else { return };
    if !alive(initial.0) || !alive(current) {
        return;
    }
    if GATE_REACHED.swap(true, Ordering::AcqRel) {
        return;
    }
    let child_id = CREATIONS.lock().iter().find(|creation| creation.child_pointer == current).map_or(0, |creation| creation.child_id);
    crate::debug_print!("[init] csrss.exe (pid {}) criado pelo smss.exe (pid {}); smss inicial (pid {}) e csrss vivos ao pedir o win32k", child_id, creator_id, initial.1);
    crate::debug_print!("SMSS_CSRSS_OK");
}
