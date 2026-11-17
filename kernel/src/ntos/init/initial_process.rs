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
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

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
    let request = CreateProcessRequest { image: ImageOrigin::NtPath(String::from(INITIAL_PROCESS_PATH)), image_name: "smss.exe", parameters: parameters(), parent: None, thread_flags: 0, on_created: None, inherit_handles_from: None, protection: WINTCB_LIGHT, create_session: false, primary_token: None };
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
    CREATIONS.lock().push(creation);
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
static TERMSRV_READY: AtomicBool = AtomicBool::new(false);
static SESSION1_CONNECTED: AtomicBool = AtomicBool::new(false);

/// Uma vista de imagem completa entrou no processo `process`
/// (`mm/section/image_view.rs`): o `SVCHOST_LSM_STARTED` sai quando um
/// svchost.exe mapeia o lsm.dll, o ServiceDll do Local Session Manager que
/// o services.exe pediu.
pub fn image_mapped(process: u64, dll_name: &str) {
    if !boot_config::smss_boot() || SVCHOST_LSM_STARTED.load(Ordering::Acquire) || !dll_name.eq_ignore_ascii_case("lsm.dll") {
        return;
    }
    if image_name(process).eq_ignore_ascii_case("svchost.exe") && !SVCHOST_LSM_STARTED.swap(true, Ordering::AcqRel) {
        // SAFETY: o EPROCESS do processo da vista, retido por ela.
        let pid = unsafe { Eprocess::at(process) }.unique_process_id.get();
        crate::debug_print!("[init] svchost.exe (pid {}): lsm.dll mapeado", pid);
        crate::debug_print!("SVCHOST_LSM_STARTED");
    }
}

/// O NtSetEvent de usuário sinalizou o evento `name`: o `TERMSRV_READY` sai
/// no `\BaseNamedObjects\TermSrvReadyEvent` (o `Global\TermSrvReadyEvent`
/// que o Local Session Manager sinaliza e que o winlogon espera).
pub fn event_set(name: &str) {
    if !boot_config::smss_boot() || TERMSRV_READY.load(Ordering::Acquire) || !name.eq_ignore_ascii_case("\\BaseNamedObjects\\TermSrvReadyEvent") {
        return;
    }
    if !TERMSRV_READY.swap(true, Ordering::AcqRel) {
        crate::debug_print!("[init] {} (pid {}): TermSrvReadyEvent sinalizado", image_name(process::get_current_process()), process::get_current_process_id());
        crate::debug_print!("TERMSRV_READY");
    }
}

/// Uma sessão carregou a imagem de sessão `name` (`mm/session_image.rs`):
/// o `SESSION1_CONNECTED` sai quando a sessão 1 carrega o cdd.dll, o que o
/// win32k dela só faz depois de o dxgkrnl entregar o adaptador à sessão
/// (DxgkSessionConnected, no NtUserRemoteConnect do csrss).
pub fn session_image_loaded(session_id: u32, name: &str) {
    if !boot_config::smss_boot() || session_id != 1 || SESSION1_CONNECTED.load(Ordering::Acquire) || !name.to_ascii_lowercase().ends_with("cdd.dll") {
        return;
    }
    if !SESSION1_CONNECTED.swap(true, Ordering::AcqRel) {
        crate::debug_print!("[init] sessao 1: cdd.dll carregado");
        crate::debug_print!("SESSION1_CONNECTED");
    }
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
