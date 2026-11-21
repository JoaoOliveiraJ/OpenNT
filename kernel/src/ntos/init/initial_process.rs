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
//!
//! Os marcadores do logon do usuário (`--conta-de-teste`) também são
//! observações: o `USER_LOGON_OK` ([`token_handle_received`]) quando o token
//! do logon interativo de uma conta chega ao winlogon.exe da sessão 1, o
//! `PROFILE_LOADED` ([`user_hive_loaded`]) quando o NTUSER.DAT desse usuário
//! é montado em `\REGISTRY\USER\<SID>`, e o `USERINIT_STARTED` e o
//! `EXPLORER_STARTED` quando o winlogon.exe cria o userinit.exe e o
//! userinit.exe cria o explorer.exe com o token dele. Depois dele, o
//! `SHELL_TRAY_CREATED` ([`win32k_window_created`]) quando o explorer.exe
//! cria a janela da barra de tarefas (Shell_TrayWnd), o `SHELL_RESTARTED`
//! quando o explorer.exe que o winlogon.exe recria depois de o shell sair
//! ([`shell_recreated`]) cria a dele, e o `STARTMENU_HOST_STARTED` quando o
//! StartMenuExperienceHost.exe nasce com o token LowBox do usuário. Os do UserManager também: o `USERMGR_STARTED`
//! ([`image_mapped`]) quando um svchost.exe mapeia o usermgr.dll, e o
//! `UMGR_USER_LOGIN` e o `SIHOST_READY` ([`wnf_updated`]) quando esse svchost
//! publica o aviso do logon e o do sihost.exe pronto.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

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
    let request = CreateProcessRequest { image: ImageOrigin::NtPath(String::from(INITIAL_PROCESS_PATH)), image_name: "smss.exe", parameters: parameters(), parent: None, thread_flags: 0, on_created: None, inherit_handles_from: None, protection: WINTCB_LIGHT, create_session: false, primary_token: None, image_request: Default::default() };
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
    if !boot_config::smss_boot() {
        return;
    }
    // SAFETY: os dois EPROCESS estão retidos por quem cria.
    let (creator_id, child_id) = unsafe { (Eprocess::at(creator_pointer).unique_process_id.get(), Eprocess::at(child_pointer).unique_process_id.get()) };
    let creation = Creation { creator_id, creator_name: image_name(creator_pointer), child_pointer, child_id, child_name: image_name(child_pointer) };
    crate::debug_print!("[init] {} (pid {}) criou {} (pid {}) por NtCreateUserProcess", creation.creator_name, creation.creator_id, creation.child_name, creation.child_id);
    logon_process_created(&creation, child_pointer);
    CREATIONS.lock().push(creation);
}

static DWM_STARTED: AtomicBool = AtomicBool::new(false);
static LOGONUI_STARTED: AtomicBool = AtomicBool::new(false);
static USERINIT_STARTED: AtomicBool = AtomicBool::new(false);
static EXPLORER_STARTED: AtomicBool = AtomicBool::new(false);

/// Um processo da sessão 1 criado pelo winlogon.exe ou pelo userinit.exe:
/// o `DWM_STARTED` sai no primeiro dwm.exe que o winlogon cria (o do
/// dwminit.dll) e o `LOGONUI_STARTED` no primeiro LogonUI.exe (o do
/// StartLogonUI), os dois depois da conexão do console
/// (`SESSION1_CONNECTED`); o `USERINIT_STARTED` e o `EXPLORER_STARTED` no
/// userinit.exe do winlogon e no explorer.exe do userinit com o token do
/// usuário do `USER_LOGON_OK` ([`user_process_created`]); o
/// `STARTMENU_HOST_STARTED` no StartMenuExperienceHost.exe com o token LowBox
/// desse usuário ([`start_menu_host_created`]).
fn logon_process_created(creation: &Creation, child_pointer: u64) {
    if crate::ntos::mm::session::session_id(child_pointer) != 1 {
        return;
    }
    let (creator, child) = (creation.creator_name.as_str(), creation.child_name.as_str());
    if creator.eq_ignore_ascii_case("winlogon.exe") {
        if child.eq_ignore_ascii_case("dwm.exe") && !DWM_STARTED.swap(true, Ordering::AcqRel) {
            crate::debug_print!("DWM_STARTED");
        } else if child.eq_ignore_ascii_case("LogonUI.exe") && !LOGONUI_STARTED.swap(true, Ordering::AcqRel) {
            crate::debug_print!("LOGONUI_STARTED");
        } else if child.eq_ignore_ascii_case("userinit.exe") {
            user_process_created(creation, child_pointer, &USERINIT_STARTED, "USERINIT_STARTED");
        } else if child.eq_ignore_ascii_case("explorer.exe") {
            shell_recreated(creation, child_pointer);
        }
    } else if creator.eq_ignore_ascii_case("userinit.exe") && child.eq_ignore_ascii_case("explorer.exe") {
        user_process_created(creation, child_pointer, &EXPLORER_STARTED, "EXPLORER_STARTED");
    } else if child.eq_ignore_ascii_case("StartMenuExperienceHost.exe") {
        start_menu_host_created(creation, child_pointer);
    }
}

/// O driver de sessão da classe 38 voltou do DriverEntry com `status`.
pub fn session_driver_initialized(name: &str, image_base: u64, status: u32) {
    if !boot_config::smss_boot() || !name.eq_ignore_ascii_case(WIN32K_PATH) || status & 0x8000_0000 != 0 {
        return;
    }
    let shadow = crate::ntos::ex::service_table::shadow_second_table().unwrap_or([0; 4]);
    let callouts = crate::ntos::ps::win32::win32_callout();
    crate::debug_print!("[init] win32k.sys em {:#x}: DriverEntry -> {:#x}, Shadow[1] base {:#x} limite {}, callouts {:#x}", image_base, status, shadow[0], shadow[2] & 0xFFFF_FFFF, callouts.unwrap_or(0));
    if shadow[0] != 0 && shadow[2] & 0xFFFF_FFFF != 0 && callouts.is_some() {
        crate::debug_print!("WIN32K_LOADED");
    }
}

/// O número de serviço do NtUserInitialize (0: ainda não lido).
static USER_INITIALIZE_SERVICE: AtomicU32 = AtomicU32::new(0);
static USER_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// A base de um módulo no Ldr do processo corrente (PEB->Ldr, memória de
/// usuário sondada a cada passo).
fn user_module_base(name: &str) -> Option<u64> {
    use crate::ntos::inc::types::{LdrDataTableEntry, ListEntry, Peb, PebLdrData};
    use crate::ntos::ps::user::state;
    // SAFETY: o EPROCESS corrente.
    let peb = unsafe { Eprocess::at(process::get_current_process()) }.peb.get();
    let ldr = state::user_struct::<Peb>(peb).and_then(|peb| peb.ldr.probe_get()).ok()?;
    let links = core::mem::offset_of!(LdrDataTableEntry, in_load_order_links) as u64;
    let head = ldr + core::mem::offset_of!(PebLdrData, in_load_order_module_list) as u64;
    let mut link = state::user_struct::<ListEntry>(head).and_then(|head| head.flink.probe_get()).ok()?;
    for _ in 0..256 {
        if link == 0 || link == head {
            break;
        }
        let entry = state::user_struct::<LdrDataTableEntry>(link - links).ok()?;
        let (base, length, buffer) = (entry.dll_base.probe_get().ok()?, entry.base_dll_name.length.probe_get().ok()? as u64, entry.base_dll_name.buffer.probe_get().ok()?);
        if state::try_read_user_wide_string(buffer, (length / 2).min(64)).is_ok_and(|module| module.eq_ignore_ascii_case(name)) {
            return Some(base);
        }
        link = state::user_struct::<ListEntry>(link).and_then(|link| link.flink.probe_get()).ok()?;
    }
    None
}

/// O número de serviço de um stub de syscall exportado por um módulo do
/// processo corrente (`mov r10, rcx; mov eax, número`).
fn user_service_number(module: &str, export: &str) -> Option<u32> {
    use crate::ntos::inc::types::{ImageDosHeader, ImageExportDirectory, ImageNtHeaders64};
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::ps::user::state;
    let base = user_module_base(module)?;
    let nt = base + state::user_struct::<ImageDosHeader>(base).and_then(|dos| dos.e_lfanew.probe_get()).ok()? as u64;
    let directory = state::user_struct::<ImageNtHeaders64>(nt).and_then(|headers| headers.optional_header.data_directory[0].virtual_address.probe_get()).ok()? as u64;
    let exports = state::user_struct::<ImageExportDirectory>(base + directory).ok()?;
    let (count, functions, names, ordinals) = (exports.number_of_names.probe_get().ok()?, exports.address_of_functions.probe_get().ok()? as u64, exports.address_of_names.probe_get().ok()? as u64, exports.address_of_name_ordinals.probe_get().ok()? as u64);
    let wanted = export.as_bytes();
    for index in 0..count.min(0x4000) as u64 {
        let name = base + guest::try_read::<u32>(base + names + index * 4).ok()? as u64;
        if !state::probe_user_read(name, wanted.len() as u64 + 1) || guest::try_read_bytes(name, wanted.len() + 1).ok()?.as_slice() != [wanted, &[0]].concat().as_slice() {
            continue;
        }
        let ordinal = guest::try_read::<u16>(base + ordinals + index * 2).ok()? as u64;
        let stub = base + guest::try_read::<u32>(base + functions + ordinal * 4).ok()? as u64;
        if !state::probe_user_read(stub, 8) {
            return None;
        }
        let code = guest::try_read_bytes(stub, 8).ok()?;
        return (code[..4] == [0x4C, 0x8B, 0xD1, 0xB8]).then(|| u32::from_le_bytes([code[4], code[5], code[6], code[7]]));
    }
    None
}

/// Um serviço da tabela do win32k voltou ao modo usuário com `result`: o
/// `USER_INITIALIZED` sai quando o NtUserInitialize do csrss.exe (o número
/// do stub do win32u.dll dele) volta com sucesso.
pub fn win32k_service_returned(service_number: u32, result: u64) {
    if !boot_config::smss_boot() || USER_INITIALIZED.load(Ordering::Acquire) {
        return;
    }
    if !image_name(process::get_current_process()).eq_ignore_ascii_case("csrss.exe") {
        return;
    }
    let mut number = USER_INITIALIZE_SERVICE.load(Ordering::Acquire);
    if number == 0 {
        number = user_service_number("win32u.dll", "NtUserInitialize").unwrap_or(0);
        USER_INITIALIZE_SERVICE.store(number, Ordering::Release);
    }
    if number == 0 || service_number != number {
        return;
    }
    crate::debug_print!("[init] csrss.exe (pid {}): NtUserInitialize -> {:#x}", process::get_current_process_id(), result as u32);
    if result as u32 == 0 && !USER_INITIALIZED.swap(true, Ordering::AcqRel) {
        crate::debug_print!("USER_INITIALIZED");
    }
}

/// O número de serviço do NtUserCreateWindowEx (0: ainda não lido; u32::MAX:
/// o stub não foi achado).
static CREATE_WINDOW_SERVICE: AtomicU32 = AtomicU32::new(0);
static SHELL_TRAY_CREATED: AtomicBool = AtomicBool::new(false);
/// O PID do explorer.exe que o winlogon recriou ([`shell_recreated`]; 0
/// antes dele) e o `SHELL_RESTARTED`, quando ele cria a barra de tarefas.
static RESTARTED_SHELL: AtomicU64 = AtomicU64::new(0);
static SHELL_RESTARTED: AtomicBool = AtomicBool::new(false);
/// A classe da janela da barra de tarefas do explorer.exe.
const SHELL_TRAY_CLASS: &str = "Shell_TrayWnd";

/// Um serviço da tabela do win32k voltou ao modo usuário com `result`, com
/// os argumentos `arguments` (o pacote do serviço): o `SHELL_TRAY_CREATED`
/// sai quando o NtUserCreateWindowEx (o número do stub do win32u.dll) do
/// explorer.exe da sessão 1 volta, depois do `USER_LOGON_OK`, com uma janela
/// da classe Shell_TrayWnd: o CreateWindowExW do CTray::_CreateTrayWindow
/// (explorer 19041, 0x2e2d8). O user32 passa o nome da classe no segundo
/// argumento, um [`LargeString`](crate::ntos::inc::types::extra_usermode::LargeString)
/// (VerNtUserCreateWindowEx, 0x7766); um átomo de classe não é o nome. A
/// mesma janela criada pelo explorer.exe que o winlogon recriou
/// ([`shell_recreated`]) dá o `SHELL_RESTARTED`.
pub fn win32k_window_created(service_number: u32, arguments: &[u64], result: u64) {
    use crate::ntos::inc::types::extra_usermode::LargeString;
    use crate::ntos::ps::user::state;
    if !boot_config::smss_boot() || result == 0 || arguments.len() < 2 || !USER_LOGON_OK.load(Ordering::Acquire) {
        return;
    }
    let restarted = RESTARTED_SHELL.load(Ordering::Acquire);
    let restart = restarted != 0 && !SHELL_RESTARTED.load(Ordering::Acquire) && process::get_current_process_id() == restarted;
    if !restart && SHELL_TRAY_CREATED.load(Ordering::Acquire) {
        return;
    }
    let current = process::get_current_process();
    if crate::ntos::mm::session::session_id(current) != 1 || !image_name(current).eq_ignore_ascii_case("explorer.exe") {
        return;
    }
    let mut number = CREATE_WINDOW_SERVICE.load(Ordering::Acquire);
    if number == 0 {
        number = user_service_number("win32u.dll", "NtUserCreateWindowEx").unwrap_or(u32::MAX);
        CREATE_WINDOW_SERVICE.store(number, Ordering::Release);
    }
    if service_number != number || !state::probe_user_read(arguments[1], core::mem::size_of::<LargeString>() as u64) {
        return;
    }
    let Ok(class) = state::user_struct::<LargeString>(arguments[1]) else { return };
    let (Ok(length), Ok(buffer)) = (class.length.probe_get(), class.buffer.probe_get()) else { return };
    if buffer < 0x1_0000 || length as usize != SHELL_TRAY_CLASS.len() * 2 {
        return;
    }
    if !state::try_read_user_wide_string(buffer, u64::from(length / 2)).is_ok_and(|name| name.eq_ignore_ascii_case(SHELL_TRAY_CLASS)) {
        return;
    }
    if restart {
        if !SHELL_RESTARTED.swap(true, Ordering::AcqRel) {
            crate::debug_print!("[init] explorer.exe (pid {}) recriado pelo winlogon: janela {} criada (hwnd {:#x})", restarted, SHELL_TRAY_CLASS, result);
            crate::debug_print!("SHELL_RESTARTED");
        }
        return;
    }
    if SHELL_TRAY_CREATED.swap(true, Ordering::AcqRel) {
        return;
    }
    crate::debug_print!("[init] explorer.exe (pid {}): janela {} criada (hwnd {:#x})", process::get_current_process_id(), SHELL_TRAY_CLASS, result);
    crate::debug_print!("SHELL_TRAY_CREATED");
}

/// O marcador de um processo que abre as Desktops Winlogon e Default da
/// WinSta0 da sessão dele.
struct DesktopMarker {
    process: &'static str,
    marker: &'static str,
    opened: SpinLock<Vec<String>>,
    done: AtomicBool,
}

/// `WINSTA0_OK`: o wininit.exe da sessão 0; `WINLOGON_DESKTOPS_OK`: o
/// winlogon.exe da sessão 1.
static DESKTOP_MARKERS: [DesktopMarker; 2] = [
    DesktopMarker { process: "wininit.exe", marker: "WINSTA0_OK", opened: SpinLock::new(Vec::new()), done: AtomicBool::new(false) },
    DesktopMarker { process: "winlogon.exe", marker: "WINLOGON_DESKTOPS_OK", opened: SpinLock::new(Vec::new()), done: AtomicBool::new(false) },
];

/// Uma Desktop aberta (criada ou reaberta) pela ParseProcedure de uma
/// WindowStation, pelo ObOpenObjectByName do win32k (`ob/object_open.rs`):
/// o marcador do processo sai quando ele tem as Desktops Winlogon e Default
/// da WinSta0, como as que o wininit.exe cria na partida da sessão 0 e o
/// winlogon.exe na da sessão 1.
pub fn desktop_opened(window_station: &str, desktop: &str) {
    if !boot_config::smss_boot() {
        return;
    }
    let name = image_name(process::get_current_process());
    crate::debug_print!("[init] {} (pid {}): Desktop {}\\{} aberta pela ParseProcedure da WindowStation", name, process::get_current_process_id(), window_station, desktop);
    if !window_station.eq_ignore_ascii_case("WinSta0") {
        return;
    }
    for tracker in &DESKTOP_MARKERS {
        if tracker.done.load(Ordering::Acquire) || !name.eq_ignore_ascii_case(tracker.process) {
            continue;
        }
        let complete = {
            let mut desktops = tracker.opened.lock();
            if !desktops.iter().any(|known| known.eq_ignore_ascii_case(desktop)) {
                desktops.push(String::from(desktop));
            }
            ["Winlogon", "Default"].iter().all(|wanted| desktops.iter().any(|known| known.eq_ignore_ascii_case(wanted)))
        };
        if complete && !tracker.done.swap(true, Ordering::AcqRel) {
            crate::debug_print!("[init] {} (pid {}): WinSta0 com as Desktops Winlogon e Default", tracker.process, process::get_current_process_id());
            crate::debug_print!("{}", tracker.marker);
        }
    }
}

/// A conversão em thread GUI (PsConvertToGuiThread) de uma thread do
/// csrss.exe voltou com `status`: a primeira é anotada.
pub fn gui_thread_converted(status: u32) {
    static NOTED: AtomicBool = AtomicBool::new(false);
    if !boot_config::smss_boot() || status == STATUS_ALREADY_WIN32 {
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
    if !boot_config::smss_boot() || GATE_REACHED.load(Ordering::Acquire) {
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
    // `--trace-driver-api` no boot do smss: depois do portão, cada export
    // que os drivers (o win32k, o dxgkrnl e o miniport) chamam é impresso.
    if boot_config::trace_driver_api() {
        crate::ntos::init::exports::set_api_trace(true);
    }
}

static SERVICES_STARTED: AtomicBool = AtomicBool::new(false);
static LSASS_STARTED: AtomicBool = AtomicBool::new(false);

/// A porta ALPC de servidor `name` foi criada pelo processo corrente
/// (`alpc/server.rs`): o `SERVICES_STARTED` sai quando o services.exe
/// publica a interface RPC do gerenciador de serviços (a
/// `\RPC Control\ntsvcs` do RpcServerUseProtseqEp do ScEnableRpcInterface,
/// depois do ScInitDatabase).
pub fn server_port_created(name: &str) {
    lsa_endpoint_created(name);
    console_connected(name);
    if !boot_config::smss_boot() || SERVICES_STARTED.load(Ordering::Acquire) || !name.eq_ignore_ascii_case("\\RPC Control\\ntsvcs") {
        return;
    }
    if image_name(process::get_current_process()).eq_ignore_ascii_case("services.exe") && !SERVICES_STARTED.swap(true, Ordering::AcqRel) {
        crate::debug_print!("[init] services.exe (pid {}): interface RPC do gerenciador de servicos em {}", process::get_current_process_id(), name);
        crate::debug_print!("SERVICES_STARTED");
    }
}

static LSA_POLICY_READY: AtomicBool = AtomicBool::new(false);

/// O `LSA_POLICY_READY` sai quando o lsass.exe publica o
/// `\RPC Control\LSARPC_ENDPOINT` (o LsapRPCInit do LsapInitLsa do lsasrv):
/// o banco de política instalado, a auditoria, as sessões de logon, as
/// credenciais e os pacotes de segurança já inicializados.
fn lsa_endpoint_created(name: &str) {
    if !boot_config::smss_boot() || LSA_POLICY_READY.load(Ordering::Acquire) || !name.eq_ignore_ascii_case("\\RPC Control\\LSARPC_ENDPOINT") {
        return;
    }
    if image_name(process::get_current_process()).eq_ignore_ascii_case("lsass.exe") && !LSA_POLICY_READY.swap(true, Ordering::AcqRel) {
        crate::debug_print!("[init] lsass.exe (pid {}): LsapInitLsa publicou {}", process::get_current_process_id(), name);
        crate::debug_print!("LSA_POLICY_READY");
    }
}

static SVCHOST_LSM_STARTED: AtomicBool = AtomicBool::new(false);
static USERMGR_STARTED: AtomicBool = AtomicBool::new(false);
static TERMSRV_READY: AtomicBool = AtomicBool::new(false);
static SESSION1_CONNECTED: AtomicBool = AtomicBool::new(false);

/// Uma vista de imagem completa entrou no processo `process`
/// (`mm/section/image_view.rs`): o `SVCHOST_LSM_STARTED` sai quando um
/// svchost.exe mapeia o lsm.dll, o ServiceDll do Local Session Manager que
/// o services.exe pediu, e o `USERMGR_STARTED` quando um svchost.exe mapeia
/// o usermgr.dll, o ServiceDll do UserManager (início automático depois do
/// RpcSs e do ProfSvc).
pub fn image_mapped(process: u64, dll_name: &str) {
    if !boot_config::smss_boot() {
        return;
    }
    let (done, dll, marker) = if dll_name.eq_ignore_ascii_case("lsm.dll") {
        (&SVCHOST_LSM_STARTED, "lsm.dll", "SVCHOST_LSM_STARTED")
    } else if dll_name.eq_ignore_ascii_case("usermgr.dll") {
        (&USERMGR_STARTED, "usermgr.dll", "USERMGR_STARTED")
    } else {
        return;
    };
    if done.load(Ordering::Acquire) || !image_name(process).eq_ignore_ascii_case("svchost.exe") || done.swap(true, Ordering::AcqRel) {
        return;
    }
    // SAFETY: o EPROCESS do processo da vista, retido por ela.
    let pid = unsafe { Eprocess::at(process) }.unique_process_id.get();
    crate::debug_print!("[init] svchost.exe (pid {}): {} mapeado", pid, dll);
    crate::debug_print!("{}", marker);
}

/// WNF_UMGR_USER_LOGIN, de escopo de sistema: o SendServiceAndLsaNotification
/// do usermgr.dll (0x5f140) o publica no UMgrInformUserLogon do winlogon,
/// depois do LoadUserProfileW, com o contexto e a sessão do usuário.
const WNF_UMGR_USER_LOGIN: u64 = 0x1381_0338_A3BC_1075;
/// WNF_UMGR_SIHOST_READY, de escopo de sessão: o LaunchShell do usermgr.dll
/// (0x896f8) o publica do svchost da sessão 0 com o ExplicitScope da sessão
/// do usuário, quando o sihost.exe, com todos os componentes de pé, chama o
/// UMgrLaunchShell; o ShellStartup do winlogon espera por ele até 30 s antes
/// de criar o userinit.
const WNF_UMGR_SIHOST_READY: u64 = 0x1381_0338_A3BC_0835;

static UMGR_USER_LOGIN: AtomicBool = AtomicBool::new(false);
static SIHOST_READY: AtomicBool = AtomicBool::new(false);

/// Um NtUpdateWnfStateData de usuário voltou com sucesso
/// (`ps/user/wnf.rs`) para o nome `state_name`, com o ULONG do ExplicitScope
/// em `scope` quando havia um: o `UMGR_USER_LOGIN` sai quando o svchost.exe
/// do UserManager publica o WNF_UMGR_USER_LOGIN, e o `SIHOST_READY` quando
/// ele publica o WNF_UMGR_SIHOST_READY para a sessão do usuário.
pub fn wnf_updated(state_name: u64, scope: Option<u32>) {
    if !boot_config::smss_boot() || state_name != WNF_UMGR_USER_LOGIN && state_name != WNF_UMGR_SIHOST_READY {
        return;
    }
    if !image_name(process::get_current_process()).eq_ignore_ascii_case("svchost.exe") {
        return;
    }
    let pid = process::get_current_process_id();
    if state_name == WNF_UMGR_USER_LOGIN {
        if !UMGR_USER_LOGIN.swap(true, Ordering::AcqRel) {
            crate::debug_print!("[init] svchost.exe (pid {}): WNF_UMGR_USER_LOGIN publicado", pid);
            crate::debug_print!("UMGR_USER_LOGIN");
        }
        return;
    }
    let Some(session) = scope else { return };
    if !SIHOST_READY.swap(true, Ordering::AcqRel) {
        crate::debug_print!("[init] svchost.exe (pid {}): WNF_UMGR_SIHOST_READY publicado para a sessao {}", pid, session);
        crate::debug_print!("SIHOST_READY");
    }
}

/// O NtSetEvent de usuário sinalizou o evento `name`: o `TERMSRV_READY` sai
/// no `\BaseNamedObjects\TermSrvReadyEvent` (o `Global\TermSrvReadyEvent`
/// que o Local Session Manager sinaliza e que o winlogon espera).
pub fn event_set(name: &str) {
    shell_desktop_ready(name);
    if !boot_config::smss_boot() || TERMSRV_READY.load(Ordering::Acquire) || !name.eq_ignore_ascii_case("\\BaseNamedObjects\\TermSrvReadyEvent") {
        return;
    }
    if !TERMSRV_READY.swap(true, Ordering::AcqRel) {
        crate::debug_print!("[init] {} (pid {}): TermSrvReadyEvent sinalizado", image_name(process::get_current_process()), process::get_current_process_id());
        crate::debug_print!("TERMSRV_READY");
    }
}

/// O `SESSION1_CONNECTED` sai quando o csrss.exe da sessão 1 cria a
/// `\RPC Control\AutoRotationApiPort`. O W32WinStationDoConnect do
/// winsrvext.dll (o comando DoConnect do console que o Local Session Manager
/// manda pela `\SmSsWinStationApiPort`) só chega ao AutoRotationAPIInit
/// (0xd87e) depois de o NtUserRemoteConnect, o CsrConnectToUser e o
/// CtxInitUser32 voltarem com sucesso.
fn console_connected(name: &str) {
    if !boot_config::smss_boot() || SESSION1_CONNECTED.load(Ordering::Acquire) || !name.eq_ignore_ascii_case("\\RPC Control\\AutoRotationApiPort") {
        return;
    }
    let current = process::get_current_process();
    if !image_name(current).eq_ignore_ascii_case("csrss.exe") || crate::ntos::mm::session::session_id(current) != 1 {
        return;
    }
    if !SESSION1_CONNECTED.swap(true, Ordering::AcqRel) {
        crate::debug_print!("[init] csrss.exe (pid {}) da sessao 1: DoConnect do console concluido ({})", process::get_current_process_id(), name);
        crate::debug_print!("SESSION1_CONNECTED");
    }
}

/// O RID da primeira conta criada num domínio de contas (o NextRid do banco
/// novo do samsrv, 0x3E8): as embutidas ficam abaixo (Administrador 500,
/// Convidado 501, DefaultAccount 503, WDAGUtilityAccount 504).
const FIRST_ACCOUNT_RID: u32 = 1000;
/// INTERACTIVE (S-1-5-4), serializado como o `se::model::Sid`.
const INTERACTIVE_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 4, 0, 0, 0];
/// A raiz das hives de usuário.
const USER_HIVES: &str = "\\REGISTRY\\USER\\";

static USER_LOGON_OK: AtomicBool = AtomicBool::new(false);
static PROFILE_LOADED: AtomicBool = AtomicBool::new(false);
static SHELL_DESKTOP_SWITCH: AtomicBool = AtomicBool::new(false);
/// O SID (texto) do usuário do `USER_LOGON_OK`: o `PROFILE_LOADED`, o
/// `USERINIT_STARTED` e o `EXPLORER_STARTED` só saem para ele.
static LOGGED_ON_USER: SpinLock<Option<String>> = SpinLock::new(None);

/// O texto de um SID de conta (S-1-5-21-a-b-c-RID, com o RID de uma conta
/// criada, não embutida), ou None. O SID vem serializado como o
/// `se::model::Sid`: revisão, número de subautoridades, autoridade
/// big-endian e subautoridades little-endian.
fn account_sid_text(sid: &[u8]) -> Option<String> {
    if sid.len() != 8 + 5 * 4 || sid[0] != 1 || sid[1] != 5 || sid[2..8] != [0, 0, 0, 0, 0, 5] {
        return None;
    }
    let sub: Vec<u32> = sid[8..].chunks_exact(4).map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])).collect();
    (sub[0] == 21 && sub[4] >= FIRST_ACCOUNT_RID).then(|| alloc::format!("S-1-5-21-{}-{}-{}-{}", sub[1], sub[2], sub[3], sub[4]))
}

/// O usuário (texto do SID) de um token de logon interativo de uma conta:
/// o usuário é um SID de conta ([`account_sid_text`]) e o token tem o grupo
/// INTERACTIVE, como o que o lsass monta no LsapAuApiDispatchLogonUser. Os
/// logons virtuais do winlogon (DWM-1, S-1-5-90-0-1, e UMFD-1,
/// S-1-5-96-0-1) e os de serviço não são contas.
fn interactive_account(token: u64) -> Option<String> {
    crate::ntos::se::token::tokens::with(token, |token| {
        if !token.groups.iter().any(|group| group.sid == INTERACTIVE_SID) {
            return None;
        }
        account_sid_text(&token.user)
    })
    .flatten()
}

/// Um handle de token entrou na tabela do processo `target_process`, vindo
/// de `source_process`: pelo NtDuplicateObject (`ps/user/handles.rs`; o
/// LsapDuplicateHandle do LsapAuApiDispatchLogonUser do lsass, lsasrv
/// 0x343ae, põe o token no cliente do LsaLogonUser) ou pelo atributo de
/// handle de uma mensagem ALPC (`alpc/message/handles.rs`; a resposta do
/// UMLogonUser do UserManager leva o DuplicateTokenEx do token como
/// `[system_handle]`). O `USER_LOGON_OK` sai quando o destino é o
/// winlogon.exe da sessão 1 e o token é o de um logon interativo de uma
/// conta ([`interactive_account`]): é o token que o LsaLogonUser do winlogon
/// devolve. No lsass a cópia para o cliente é o último passo que pode falhar
/// (o LsapPostLogonUser seguinte não muda o status), e a resposta do
/// UserManager é a própria volta do UMgrLogonUser.
pub fn token_handle_received(source_process: u64, target_process: u64, token: u64) {
    if !boot_config::smss_boot() || USER_LOGON_OK.load(Ordering::Acquire) {
        return;
    }
    if !image_name(target_process).eq_ignore_ascii_case("winlogon.exe") || crate::ntos::mm::session::session_id(target_process) != 1 {
        return;
    }
    let Some(user) = interactive_account(token) else { return };
    if USER_LOGON_OK.swap(true, Ordering::AcqRel) {
        return;
    }
    // SAFETY: os dois EPROCESS estão retidos por quem duplica.
    let (source_id, target_id) = unsafe { (Eprocess::at(source_process).unique_process_id.get(), Eprocess::at(target_process).unique_process_id.get()) };
    crate::debug_print!("[init] {} (pid {}) entregou ao winlogon.exe (pid {}) o token do logon interativo de {}", image_name(source_process), source_id, target_id, user);
    *LOGGED_ON_USER.lock() = Some(user);
    crate::debug_print!("USER_LOGON_OK");
}

/// Um NtLoadKey* voltou com sucesso, com a hive do arquivo `file` montada
/// em `mount` (`cm/hive_services.rs`): o `PROFILE_LOADED` sai quando é o
/// NTUSER.DAT do usuário do `USER_LOGON_OK` em `\REGISTRY\USER\<SID>`, o
/// MountRegHive do profsvc (0x1ae68: o NtLoadKey3 com o token do usuário,
/// do CopyDefaultProfileAndLoadHive no primeiro logon). O `<SID>_Classes`
/// (o UsrClass.dat) e as hives dos perfis de serviço não contam.
pub fn user_hive_loaded(mount: &str, file: &str) {
    if !boot_config::smss_boot() || PROFILE_LOADED.load(Ordering::Acquire) {
        return;
    }
    let Some(user) = LOGGED_ON_USER.lock().clone() else { return };
    let Some(sid) = mount.get(USER_HIVES.len()..).filter(|_| mount.get(..USER_HIVES.len()).is_some_and(|prefix| prefix.eq_ignore_ascii_case(USER_HIVES))) else { return };
    if !sid.eq_ignore_ascii_case(&user) || !file.to_ascii_lowercase().ends_with("\\ntuser.dat") || PROFILE_LOADED.swap(true, Ordering::AcqRel) {
        return;
    }
    crate::debug_print!("[init] {} (pid {}): {} montado em {}", image_name(process::get_current_process()), process::get_current_process_id(), file, mount);
    crate::debug_print!("PROFILE_LOADED");
}

/// O `USERINIT_STARTED` sai no userinit.exe que o ShellStartup do
/// winlogon.exe cria (CUser::CreateProcessW 0x20e94: o CreateProcessAsUserW
/// com o token do usuário, impersonando-o) e o `EXPLORER_STARTED` no
/// explorer.exe que o ExecApplication do userinit.exe cria (0x1bb0: o
/// CreateProcessW, com o token herdado), os dois só quando o token primário
/// do processo novo é o do usuário do `USER_LOGON_OK`.
fn user_process_created(creation: &Creation, child_pointer: u64, done: &AtomicBool, marker: &str) {
    let Some(user) = LOGGED_ON_USER.lock().clone() else { return };
    let owner = process::get_primary_token(child_pointer).and_then(|token| crate::ntos::se::token::tokens::with(token, |token| account_sid_text(&token.user))).flatten();
    if owner.as_deref() != Some(user.as_str()) || done.swap(true, Ordering::AcqRel) {
        return;
    }
    crate::debug_print!("[init] {} (pid {}) criou {} (pid {}) com o token de {}", creation.creator_name, creation.creator_id, creation.child_name, creation.child_id, user);
    crate::debug_print!("{}", marker);
}

/// O winlogon.exe da sessão 1 criou um explorer.exe com o token do usuário
/// do `USER_LOGON_OK` depois do `EXPLORER_STARTED`: o shell recriado pelo
/// WLGeneric_ShellRestart_Enter (winlogon 19041, 0x7d6a0), que lê o
/// AutoRestartShell (1 sem o valor) e o Shell da chave Winlogon e chama o
/// CUser::CreateProcessW na Winsta0\Default. O sinal vem do win32kbase: o
/// DestroyProcessInfo (0x46f60), no callout de saída do processo, vê que o
/// processo que saiu é o shell da Desktop de entrada (o ppiShellProcess do
/// DESKTOPINFO, posto pelo SetShellWindow) e, com o código de saída
/// diferente de 1 e de 0xff (um fim pedido pelo próprio explorer, que não
/// se recria), chama o PostWinlogonMessage(0x401, código); o RPC do kernel
/// (msrpc.sys) o leva ao WMsgKMessageHandler do winlogon pelo endpoint
/// `WMsgKRpc*`, que liga o sinal Winsrv_ShellRestart (0xa) da máquina de
/// estados. Só uma linha no log; o `SHELL_RESTARTED` sai quando esse
/// explorer.exe cria a barra de tarefas ([`win32k_window_created`]).
fn shell_recreated(creation: &Creation, child_pointer: u64) {
    if !EXPLORER_STARTED.load(Ordering::Acquire) {
        return;
    }
    let Some(user) = LOGGED_ON_USER.lock().clone() else { return };
    let owner = process::get_primary_token(child_pointer).and_then(|token| crate::ntos::se::token::tokens::with(token, |token| account_sid_text(&token.user))).flatten();
    if owner.as_deref() != Some(user.as_str()) || RESTARTED_SHELL.compare_exchange(0, creation.child_id, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return;
    }
    crate::debug_print!("[init] {} (pid {}) recriou o shell: {} (pid {}) com o token de {}", creation.creator_name, creation.creator_id, creation.child_name, creation.child_id, user);
}

static STARTMENU_HOST_STARTED: AtomicBool = AtomicBool::new(false);

/// O `STARTMENU_HOST_STARTED` sai no StartMenuExperienceHost.exe da sessão 1
/// criado com um token LowBox (AppContainer) do usuário do `USER_LOGON_OK`:
/// a ativação do pacote Microsoft.Windows.StartMenuExperienceHost pelo
/// DcomLaunch, no pré-lançamento do logon ou na tecla do Windows. O token
/// LowBox guarda o SID do usuário e ganha o número do LowBox
/// (`se/token/tokens.rs`).
fn start_menu_host_created(creation: &Creation, child_pointer: u64) {
    let Some(user) = LOGGED_ON_USER.lock().clone() else { return };
    let token = process::get_primary_token(child_pointer).and_then(|token| crate::ntos::se::token::tokens::with(token, |token| (account_sid_text(&token.user), token.lowbox_number.is_some())));
    let Some((Some(owner), true)) = token else { return };
    if owner != user || STARTMENU_HOST_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    crate::debug_print!("[init] {} (pid {}) criou {} (pid {}) com o token LowBox de {}", creation.creator_name, creation.creator_id, creation.child_name, creation.child_id, user);
    crate::debug_print!("STARTMENU_HOST_STARTED");
}

/// O explorer.exe da sessão 1 sinalizou o `ShellDesktopSwitchEvent` (o
/// CTray::_FireDesktopSwitchIfReady do explorer, 0x37104, com a barra de
/// tarefas, a área de trabalho e a volta dos aplicativos prontas): o
/// winlogon troca para a Desktop Default. Só uma linha no log; o
/// `DESKTOP_OK` é a tela, lida pelo xtask.
fn shell_desktop_ready(name: &str) {
    if !boot_config::smss_boot() || SHELL_DESKTOP_SWITCH.load(Ordering::Acquire) || !name.rsplit('\\').next().is_some_and(|last| last.eq_ignore_ascii_case("ShellDesktopSwitchEvent")) {
        return;
    }
    let current = process::get_current_process();
    if !image_name(current).eq_ignore_ascii_case("explorer.exe") || crate::ntos::mm::session::session_id(current) != 1 || SHELL_DESKTOP_SWITCH.swap(true, Ordering::AcqRel) {
        return;
    }
    crate::debug_print!("[init] explorer.exe (pid {}): {} sinalizado; o winlogon troca para a Desktop Default", process::get_current_process_id(), name);
}

/// O Reference Monitor terminou a conexão com o LSA do processo
/// `process_id` (`se/reference_monitor.rs`): o `LSASS_STARTED` sai quando
/// ele é o lsass.exe, que passa do LsapRmInitializeServer.
pub fn lsa_connected(process_id: u64) {
    if !boot_config::smss_boot() || LSASS_STARTED.load(Ordering::Acquire) {
        return;
    }
    let Some(entry) = process::list_active_processes().into_iter().find(|entry| entry.pid == process_id) else { return };
    if image_name(entry.address).eq_ignore_ascii_case("lsass.exe") && !LSASS_STARTED.swap(true, Ordering::AcqRel) {
        crate::debug_print!("[init] lsass.exe (pid {}): conectado ao Reference Monitor pela \\SeRmCommandPort e com a \\SeLsaCommandPort", process_id);
        crate::debug_print!("LSASS_STARTED");
    }
}
