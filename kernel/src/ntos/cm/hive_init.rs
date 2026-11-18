//! A montagem das hives no boot (o CmInitSystem1, o CmpCreateControlSet e o
//! CmpInitializeHiveList do NT).
//!
//! Como no ntoskrnl 19041:
//! - o CmInitSystem1 cria as chaves mestras `\REGISTRY\MACHINE`,
//!   `\REGISTRY\USER` e `\REGISTRY\A` (a raiz das hives de aplicativo, que
//!   não se abre por nome), liga a hive SYSTEM, escolhe o conjunto de
//!   controle (CmpCreateControlSet) e cria a hive volátil HARDWARE
//!   (CmpCreateHive com HIVE_VOLATILE e CmpLinkHiveToMaster em
//!   `\REGISTRY\MACHINE\HARDWARE`);
//! - o CmpCreateControlSet (rva 0xa58080) abre `\Registry\Machine\SYSTEM`
//!   e o `Select` dele, lê o `Current` e cria `CurrentControlSet` com
//!   REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK e KEY_CREATE_LINK, com o
//!   `SymbolicLinkValue` REG_LINK = `\Registry\Machine\SYSTEM\ControlSet%03d`
//!   (o comprimento do texto, sem o NUL);
//! - o CmpCreateHardwareProfiles (rva 0xa58540) liga `Hardware
//!   Profiles\Current` ao perfil que `Control\IDConfigDB\CurrentConfig`
//!   escolhe, também com um link volátil;
//! - as hives de máquina vêm de `\SystemRoot\System32\config`: SOFTWARE,
//!   SAM, SECURITY e DEFAULT (`\REGISTRY\USER\.DEFAULT`), além da SYSTEM;
//!   depois da DEFAULT, o CmpFinishSystemHivesLoad liga
//!   `\Registry\User\S-1-5-18` a ela (CmpLinkKeyToHive: link volátil com
//!   o `SymbolicLinkValue` `\Registry\User\.Default`);
//! - cada hive ligada entra na lista de hives, a chave volátil
//!   `\registry\machine\system\currentcontrolset\control\hivelist`
//!   (CmpAddToHiveFileList, rva 0x6a1cfc): um REG_SZ com o nome da raiz da
//!   hive e, como dado, o nome do FILE_OBJECT do primário (o ZwQueryObject
//!   com ObjectNameInformation) ou o texto vazio de uma hive volátil. As
//!   hives de aplicativo ficam fora (CmpLoadKeyCommon com REG_APP_HIVE).
//!
//! A HARDWARE é criada no início do boot, antes da descrição do hardware
//! que o kernel grava nela (`hw_description`); a entrada dela na lista
//! espera a SYSTEM. As outras hives são ligadas na fase 1, logo depois da
//! montagem do volume (o Windows liga a SOFTWARE e as demais quando o smss
//! chama o NtInitializeRegistry; aqui o kernel e os programas reais leem
//! a SOFTWARE desde a fase 1). Sem o arquivo de uma hive, as chaves das
//! tabelas de semente (`cm/seed.rs`) entram em memória.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::ntos::cm::registry;
use crate::ntos::cm::seed::{self, SeedKey};
use crate::ntos::cm::{hive_list, lazy_flush, machine_hive};
use crate::rtl::{KernelError, SpinLock};

/// A raiz das hives de aplicativo.
pub const APP_HIVE_ROOT: &str = "\\REGISTRY\\A";
pub const HARDWARE_MOUNT: &str = "\\REGISTRY\\MACHINE\\HARDWARE";
pub const SYSTEM_MOUNT: &str = "\\REGISTRY\\MACHINE\\SYSTEM";
const HIVE_LIST: &str = "\\registry\\machine\\system\\currentcontrolset\\control\\hivelist";
const SYSTEM_FILE: &str = "\\SystemRoot\\System32\\config\\SYSTEM";

/// As outras hives de máquina: ponto de montagem e arquivo.
const MACHINE_HIVES: [(&str, &str); 4] = [
    ("\\REGISTRY\\MACHINE\\SOFTWARE", "\\SystemRoot\\System32\\config\\SOFTWARE"),
    ("\\REGISTRY\\MACHINE\\SAM", "\\SystemRoot\\System32\\config\\SAM"),
    ("\\REGISTRY\\MACHINE\\SECURITY", "\\SystemRoot\\System32\\config\\SECURITY"),
    ("\\REGISTRY\\USER\\.DEFAULT", "\\SystemRoot\\System32\\config\\DEFAULT"),
];

static SYSTEM_FROM_FILE: AtomicBool = AtomicBool::new(false);
/// O handle interno da lista de hives (o CmpHiveFileListHandle).
static HIVE_LIST_HANDLE: AtomicU32 = AtomicU32::new(0);
/// Hives que vieram do arquivo no boot, pelo ponto de montagem.
static FROM_FILE: SpinLock<Vec<String>> = SpinLock::new(Vec::new());

/// As chaves mestras (CmInitSystem1). `\REGISTRY\A` é volátil, como toda a
/// hive mestra.
fn create_master_keys() -> Result<(), KernelError> {
    for master in ["\\Registry\\Machine", "\\Registry\\User"] {
        registry::close_handle(registry::open_or_create(master, None)?);
    }
    registry::close_handle(registry::open_or_create_options(APP_HIVE_ROOT, None, true)?);
    Ok(())
}

/// O início do CmInitSystem1, antes da descrição do hardware: as chaves
/// mestras e a hive volátil HARDWARE.
pub fn initialize_hardware_hive() -> Result<(), KernelError> {
    create_master_keys()?;
    match hive_list::create_volatile_hive(HARDWARE_MOUNT) {
        Ok(_) => Ok(()),
        Err(status) => Err(KernelError::with_status("hive HARDWARE", status)),
    }
}

/// Semeia em memória as chaves de uma hive sem arquivo, sob `root`.
fn seed_in_memory(root: &str, keys: Vec<SeedKey>) -> Result<(), KernelError> {
    registry::close_handle(registry::open_or_create(root, None)?);
    for key in keys {
        let path = format!("{root}\\{}", key.path);
        let handle = if key.link {
            let resolved = registry::resolve_path(&path, true).unwrap_or(path);
            registry::create_resolved(&resolved, None, false, true)?.0
        } else {
            registry::open_or_create(&path, None)?
        };
        for (name, value_type, data) in key.values {
            registry::set_value(handle, &name, value_type, data);
        }
        registry::close_handle(handle);
    }
    Ok(())
}

/// Liga uma hive de máquina do arquivo; sem ele, as chaves de semente em
/// memória. Devolve se veio do arquivo.
fn load_machine_hive(mount: &str, file: &str, keys: impl FnOnce() -> Vec<SeedKey>) -> Result<bool, KernelError> {
    match hive_list::load(mount, file, 0) {
        0 => {
            FROM_FILE.lock().push(String::from(mount));
            crate::debug_print!("[cm] hive {} carregada de {}", mount, file);
            Ok(true)
        }
        status => {
            crate::debug_print!("[cm] hive {} sem arquivo ({:#x}); chaves estaticas semeadas em memoria", mount, status);
            seed_in_memory(mount, keys())?;
            machine_hive::notify_loaded(mount);
            Ok(false)
        }
    }
}

/// CmpCreateControlSet: `CurrentControlSet`, link volátil para o conjunto
/// que `Select\Current` escolhe.
pub fn create_control_set() -> Result<(), KernelError> {
    let select = format!("{SYSTEM_MOUNT}\\Select");
    let current = registry::read_value_by_path(&select, "Current").filter(|value| value.value_type == seed::REG_DWORD && value.data.len() >= 4).map(|value| u32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]]));
    let Some(current) = current else { return Err(KernelError::new("SYSTEM\\Select\\Current ausente")) };
    let link = format!("{SYSTEM_MOUNT}\\CurrentControlSet");
    let (handle, _) = registry::create_resolved(&registry::resolve_path(&link, true).unwrap_or(link), None, true, true)?;
    if handle == 0 {
        return Err(KernelError::new("CurrentControlSet"));
    }
    let target = format!("\\Registry\\Machine\\SYSTEM\\ControlSet{current:03}");
    registry::set_value(handle, registry::SYMBOLIC_LINK_VALUE, registry::REG_LINK, target.encode_utf16().flat_map(u16::to_le_bytes).collect());
    registry::close_handle(handle);
    Ok(())
}

/// O conjunto de controle dos dispositivos (o CmpOpenDevicesControlSet com
/// o CmStateSeparationEnabled zerado, como no boot daqui: a SYSTEM).
const DEVICES_CONTROL_SET: &str = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet";

/// CmDeleteKeyRecursive: as subchaves primeiro, depois a chave.
fn delete_key_recursive(node: registry::NodeId) {
    for child in registry::children(node) {
        delete_key_recursive(child);
    }
    let path = registry::path_of(node).unwrap_or_default();
    registry::delete_node(node, &path);
}

/// CmpCreateHardwareProfiles (rva 0xa58540), que o CmInitSystem1 chama
/// depois do conjunto de controle e ignora a falha:
/// - lê o REG_DWORD `CurrentConfig` de `Control\IDConfigDB` do conjunto de
///   controle dos dispositivos (sem a chave, sem o valor ou com outro tipo,
///   nada é criado) e abre `Hardware Profiles` e `Hardware Profiles\%04d`
///   (sem elas, nada é criado);
/// - o estado do perfil que o carregador entrega (o PROFILE_PARAMETER_BLOCK
///   da extensão do bloco de parâmetros) é HW_PROFILE_STATUS_SUCCESS aqui,
///   sem casamento de alias nem clonagem: não há `CurrentDockInfo` nem
///   perfil ACPI;
/// - um `Hardware Profiles\Current` que já exista é excluído com as
///   subchaves, e a chave é criada com KEY_CREATE_LINK e
///   REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK, com o `SymbolicLinkValue`
///   REG_LINK = `\Registry\Machine\SYSTEM\CurrentControlSet\Hardware
///   Profiles\%04d` (o comprimento do texto, sem o NUL).
///
/// É por esse link que o win32kfull lê o DPI (`Software\Fonts\LogPixels`) e
/// as fontes de estoque, e o HKEY_CURRENT_CONFIG dos programas aponta para
/// ele.
pub fn create_hardware_profiles() {
    let Ok(control_set) = registry::resolve_path(DEVICES_CONTROL_SET, false) else { return };
    let configuration = registry::read_value_by_path(&format!("{control_set}\\Control\\IDConfigDB"), "CurrentConfig");
    let Some(profile) = configuration.filter(|value| value.value_type == seed::REG_DWORD && value.data.len() >= 4).map(|value| i32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]])) else { return };
    let profiles = format!("{control_set}\\Hardware Profiles");
    if registry::node_by_path(&profiles).is_none() || registry::node_by_path(&format!("{profiles}\\{profile:04}")).is_none() {
        return;
    }
    let link = format!("{profiles}\\Current");
    if let Some(existing) = registry::node_by_path(&link) {
        delete_key_recursive(existing);
    }
    let resolved = registry::resolve_path(&link, true).unwrap_or(link);
    let Ok((handle, _)) = registry::create_resolved(&resolved, None, true, true) else { return };
    if handle == 0 {
        return;
    }
    let target = format!("\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\{profile:04}");
    registry::set_value(handle, registry::SYMBOLIC_LINK_VALUE, registry::REG_LINK, target.encode_utf16().flat_map(u16::to_le_bytes).collect());
    registry::close_handle(handle);
}

/// O perfil do LocalSystem e o perfil padrão (o par do
/// CmpFinishSystemHivesLoad depois da hive DEFAULT).
const LOCAL_SYSTEM_USER: &str = "\\Registry\\User\\S-1-5-18";
const DEFAULT_USER: &str = "\\Registry\\User\\.Default";

/// CmpLinkKeyToHive (rva 0x7a7e10): `link` criado com KEY_CREATE_LINK,
/// REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK e, só quando a chave é
/// nova, o `SymbolicLinkValue` REG_LINK = `target` (sem o NUL).
fn link_key_to_hive(link: &str, target: &str) -> Result<(), KernelError> {
    let resolved = registry::resolve_path(link, true).unwrap_or_else(|_| String::from(link));
    let (handle, created) = registry::create_resolved(&resolved, None, true, true)?;
    if handle == 0 {
        return Err(KernelError::new("CmpLinkKeyToHive"));
    }
    if created {
        registry::set_value(handle, registry::SYMBOLIC_LINK_VALUE, registry::REG_LINK, target.encode_utf16().flat_map(u16::to_le_bytes).collect());
    }
    registry::close_handle(handle);
    Ok(())
}

/// CmInitSystem1 / CmpInitializeHiveList na fase 1: a SYSTEM do arquivo do
/// volume em `\Registry\Machine\SYSTEM` (sem ele, as chaves estáticas em
/// memória), o `CurrentControlSet`, as outras hives de máquina e a lista de
/// hives.
pub fn initialize_hives() -> Result<(), KernelError> {
    create_master_keys()?;
    let smss = crate::ntos::init::boot_config::smss_boot();
    let from_file = load_machine_hive(SYSTEM_MOUNT, SYSTEM_FILE, || seed::system_keys(smss))?;
    SYSTEM_FROM_FILE.store(from_file, Ordering::Release);
    create_control_set()?;
    create_hardware_profiles();
    // CmGetSystemControlValues: o idioma da instalação (`Control\Nls\Language`),
    // o ObjectSecurityMode do Session Manager e o `ProductOptions\ProductPolicy`
    // (a entrada do CmControlVector que enche o buffer primário do
    // licenciamento, o ExpHostBootLicensingData).
    crate::ntos::ps::locale::initialize_from_registry();
    // As páginas ANSI e OEM de `Control\Nls\CodePage`, como o CmpFindNLSData
    // do winload as escolhe, antes do primeiro processo de usuário (o PEB as
    // recebe do `ps/user/loader::ensure_nls_data`).
    crate::ntos::rtl::nls_configuration::initialize_code_pages_from_registry();
    crate::ntos::ex::system_information::initialize_control_values();
    crate::ntos::ex::license::values::init();
    // A lista de hives existe a partir daqui (CmpHiveFileListHandle): as
    // hives já ligadas entram nela e as próximas entram na carga.
    hive_list::start_hive_list();
    let [software, sam, security, default] = MACHINE_HIVES;
    load_machine_hive(software.0, software.1, || seed::software_keys(smss))?;
    load_machine_hive(sam.0, sam.1, seed::sam_keys)?;
    load_machine_hive(security.0, security.1, seed::security_keys)?;
    load_machine_hive(default.0, default.1, seed::default_keys)?;
    link_key_to_hive(LOCAL_SYSTEM_USER, DEFAULT_USER)?;
    // CmpCmdInit: os escritores preguiçosos, ainda retidos até o fim do
    // atraso do boot.
    lazy_flush::initialize();
    Ok(())
}

/// CmFirstTime, CmBootAcceptFirstTime e CmpBootPageFilesCreated: cada etapa
/// do NtInitializeRegistry roda uma vez só (os valores iniciais da imagem do
/// ntoskrnl são 1, 1 e 0).
static FIRST_TIME: AtomicBool = AtomicBool::new(true);
static BOOT_ACCEPT_FIRST_TIME: AtomicBool = AtomicBool::new(true);
static BOOT_PAGE_FILES_CREATED: AtomicBool = AtomicBool::new(false);

const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_TOO_LATE: u32 = 0xC000_0189;
/// SeBackupPrivilege.
const SE_BACKUP_PRIVILEGE: u64 = 17;
/// CM_BOOT_FLAG_ACCEPTED: 0x1000 + o conjunto de controle aceito (até 999).
const BOOT_FLAG_ACCEPTED: u16 = 0x1000;
const BOOT_FLAG_MAX: u16 = BOOT_FLAG_ACCEPTED + 999;
/// O pedido de cópia periódica de uma hive (o RegIdleBackup), só de modo
/// usuário.
const BOOT_FLAG_SYNC_BACKUP: u16 = 0x13E8;

/// NtInitializeRegistry(BootCondition) (ntoskrnl 19041, rva 0x78d320).
///
/// De modo usuário, 0x13E8 exige SeBackupPrivilege e vai ao
/// CmpSyncNextBackupHive; o resto entra de novo pelo ZwInitializeRegistry,
/// em modo kernel, onde:
/// - 0x1000..=0x13E7 (CM_BOOT_FLAG_ACCEPTED + n, o NotifyBootConfigStatus do
///   services.exe) é o CmpAcceptBoot: uma vez só (depois
///   STATUS_ACCESS_DENIED); 0x1000 puro consome a vez e dá
///   STATUS_INVALID_PARAMETER; sem LastKnownGood (o CmpLKGEnabled fica 0 sem
///   o valor `LastKnownGood\Enabled`) não há conjunto de controle a salvar;
/// - 2 é o CmpHandlePageFileOpenNotification, que o smss pede depois de
///   criar os arquivos de paginação: uma vez só (depois
///   STATUS_ACCESS_DENIED); avisa os volumes das hives, e o OpenNT não tem
///   volumes de hive com política de paginação;
/// - 0 (CM_BOOT_FLAG_SMSS) e 1 (setup) são o
///   CmCompleteRegistryInitialization: uma vez só (depois
///   STATUS_ACCESS_DENIED). No NT ele liga a SOFTWARE, a SAM, a SECURITY e
///   a DEFAULT e inicia os escritores preguiçosos (CmpCmdInit); no OpenNT a
///   fase 1 já fez isso (`initialize_hives`). Ele termina no
///   PsBootPhaseComplete (`ps/boot_phase.rs`, os bits do UAC);
/// - o resto é STATUS_INVALID_PARAMETER.
pub fn initialize_registry(boot_condition: u16, previous_mode: u8) -> u32 {
    if previous_mode != 0 && boot_condition == BOOT_FLAG_SYNC_BACKUP {
        if !crate::ntos::se::privilege::single_privilege_check(SE_BACKUP_PRIVILEGE, u32::from(previous_mode)) {
            return STATUS_PRIVILEGE_NOT_HELD;
        }
        // CmpSyncNextBackupHive sem o processamento ocioso do Cm
        // (CmpDoIdleProcessing): STATUS_TOO_LATE.
        return STATUS_TOO_LATE;
    }
    if (BOOT_FLAG_ACCEPTED..=BOOT_FLAG_MAX).contains(&boot_condition) {
        if !BOOT_ACCEPT_FIRST_TIME.swap(false, Ordering::AcqRel) {
            return STATUS_ACCESS_DENIED;
        }
        return if boot_condition == BOOT_FLAG_ACCEPTED { STATUS_INVALID_PARAMETER } else { 0 };
    }
    match boot_condition {
        2 => {
            if BOOT_PAGE_FILES_CREATED.swap(true, Ordering::AcqRel) {
                STATUS_ACCESS_DENIED
            } else {
                0
            }
        }
        0 | 1 => {
            if FIRST_TIME.swap(false, Ordering::AcqRel) {
                // O CmCompleteRegistryInitialization termina no
                // PsBootPhaseComplete (os bits do UAC).
                crate::ntos::ps::boot_phase::complete();
                0
            } else {
                STATUS_ACCESS_DENIED
            }
        }
        _ => STATUS_INVALID_PARAMETER,
    }
}

/// A hive SYSTEM veio do arquivo no boot.
pub fn system_hive_from_file() -> bool {
    SYSTEM_FROM_FILE.load(Ordering::Acquire)
}

/// A hive do ponto de montagem veio do arquivo no boot.
pub fn hive_from_file(mount: &str) -> bool {
    FROM_FILE.lock().iter().any(|candidate| candidate.eq_ignore_ascii_case(mount))
}

/// CmpHiveFileListHandle: a chave da lista, criada volátil no primeiro uso
/// e mantida aberta.
fn hive_list_handle() -> Option<u32> {
    let current = HIVE_LIST_HANDLE.load(Ordering::Acquire);
    if current != 0 {
        return Some(current);
    }
    let handle = registry::open_or_create_options(HIVE_LIST, None, true).ok().filter(|&handle| handle != 0)?;
    match HIVE_LIST_HANDLE.compare_exchange(0, handle, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Some(handle),
        Err(existing) => {
            registry::close_handle(handle);
            Some(existing)
        }
    }
}

/// CmpAddToHiveFileList: o valor da hive na lista (o nome do arquivo, ou o
/// texto vazio de uma hive volátil).
pub fn add_to_hive_file_list(mount: &str, file_name: Option<&str>) {
    if let Some(handle) = hive_list_handle() {
        registry::set_value(handle, mount, seed::REG_SZ, seed::wide(file_name.unwrap_or("")));
    }
}

/// CmpRemoveFromHiveFileList: a hive descarregada sai da lista.
pub fn remove_from_hive_file_list(mount: &str) {
    if let Some(handle) = hive_list_handle() {
        registry::delete_value(handle, mount);
    }
}
