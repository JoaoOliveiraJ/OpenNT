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
//! ([`record_creation`]); quando um processo pede o primeiro serviço da
//! tabela do win32k ([`win32k_requested`], da conversão para thread GUI que
//! falha sem o win32k carregado), o marcador sai se ele é o csrss.exe criado
//! por um smss.exe e o smss inicial e o csrss ainda estão vivos.

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

/// O processo corrente pediu um serviço da tabela do win32k e a conversão
/// para thread GUI falhou (o win32k.sys não está carregado).
pub fn win32k_requested(service_number: u32) {
    if !boot_config::SMSS_BOOT || GATE_REACHED.load(Ordering::Acquire) {
        return;
    }
    let current = process::get_current_process();
    let name = image_name(current);
    crate::debug_print!("[init] {} (pid {}) pediu o servico {:#x} da tabela do win32k, que nao esta carregado", name, process::get_current_process_id(), service_number);
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
