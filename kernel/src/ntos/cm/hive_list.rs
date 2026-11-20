//! As hives carregadas (o CmpHiveListHead do NT) e as operações do Cm sobre
//! elas: carga (CmLoadKey, CmLoadAppKey), descarga (CmUnloadKey), descarga
//! para o arquivo (CmFlushKey, o escritor preguiçoso e o CmShutdownSystem),
//! cópia para um arquivo (CmSaveKey), restauração (CmRestoreKey, com
//! REG_WHOLE_HIVE_VOLATILE e REG_REFRESH_HIVE) e compressão
//! (CmCompressKey). A montagem das hives do boot mora em `cm/hive_init.rs`.
//!
//! Como no ntoskrnl 19041:
//! - a carga liga a hive numa chave nova sob um pai existente; a chave que
//!   já existe dá STATUS_OBJECT_NAME_COLLISION; um primário com as
//!   sequências diferentes passa pela recuperação pelos logs antes de ser
//!   lido; com LastReorganizeTime = 1 (pedido pelo NtCompressKey) a hive é
//!   reorganizada na carga; uma carga num dos pontos de montagem das hives
//!   de máquina avisa as notificações do
//!   CmRegisterMachineHiveLoadedNotification (CmpNotifyMachineHiveLoaded);
//!   a hive entra na lista de hives (CmpLoadKeyCommon chama o
//!   CmpAddToHiveFileList), salvo uma hive de aplicativo; o arquivo ausente
//!   vira uma hive nova e vazia (o primário abre com FILE_OPEN_IF), salvo
//!   com REG_OPEN_READ_ONLY; as hives de máquina do boot precisam do
//!   arquivo;
//! - a carga abre o primário e os dois logs (`.LOG1` e `.LOG2`) antes de
//!   ler a hive (CmpInitHiveFromFile, rva 0x6e9cb8): um log que falta é
//!   criado nessa hora, oculto e de sistema; numa carga só de leitura, só os
//!   existentes. Um primário existente e vazio é uma hive nova;
//! - a carga do NtLoadKey(2/3/Ex) passa pelo CmpCmdHiveOpen (rva 0x603588):
//!   sem o token de acesso ao arquivo, uma falha de acesso ou de conta do
//!   CmpInitHiveFromFile repete a abertura impersonando o próprio processo
//!   (RtlImpersonateSelfEx), salvo numa hive de aplicativo com
//!   REG_NO_IMPERSONATION_FALLBACK; as hives do boot não repetem;
//! - as hives do CmLoadKey e do CmLoadAppKey são não confiáveis (o bit 0
//!   que o CmpLoadKeyCommon liga em CMHIVE.Flags), cada uma na própria
//!   classe de confiança; com o TrustClassKey (CmpJoinClassOfTrust, rva
//!   0x32cbb4) a hive entra na classe da hive da chave, e uma chave de hive
//!   confiável deixa a hive nova confiável — do modo usuário isso é
//!   STATUS_INVALID_PARAMETER (CmpPerformTrustClassAccessCheck) e a carga
//!   não acontece. Uma hive de aplicativo não entra em classe nenhuma;
//! - uma hive de aplicativo (CmLoadAppKey, rva 0x6e8bfc) cujo arquivo já
//!   está aberto (a abertura nova dá STATUS_SHARING_VIOLATION) volta como a
//!   hive de aplicativo já carregada do mesmo arquivo (CmpIsThisSameFile),
//!   se ela tiver o mesmo modo só de leitura e nenhuma das duas cargas for
//!   REG_PROCESS_PRIVATE (o bit 0x40 de CMHIVE.Flags); senão,
//!   STATUS_SHARING_VIOLATION. Ela é descarregada quando o último handle de
//!   chave dela fecha;
//! - a descarga (CmpPerformUnloadKey, rva 0x66cbfc) de uma hive congelada
//!   por um NtUnloadKeyEx pendente é STATUS_TOO_LATE (salvo REG_FORCE_UNLOAD
//!   numa hive de aplicativo); exige a raiz de uma hive (senão
//!   STATUS_INVALID_PARAMETER); uma hive do boot (o bit 4 que o
//!   CmpLoadHiveThread liga) é STATUS_ACCESS_DENIED; handles abertos em
//!   chaves dela dão STATUS_CANNOT_DELETE no NtUnloadKey(2) e congelam a hive
//!   no NtUnloadKeyEx (CmpFreezeHive: STATUS_PENDING, com ou sem evento),
//!   salvo REG_FORCE_UNLOAD; a descarga tira a hive do namespace, da lista
//!   de hives e da classe de confiança e então a descarrega para o arquivo
//!   (CmpCompleteUnloadKey chama o CmpFlushHive depois do
//!   CmpRemoveHiveFromNamespace); o evento da carga (o UserEvent do
//!   NtLoadKeyEx) é sinalizado;
//! - a descarga de uma chave fora das hives de arquivo descarrega todas
//!   (CmpDoFlushAll); uma falha de E/S é STATUS_REGISTRY_IO_FAILED;
//! - o NtSaveKey grava uma hive nova e compacta com a subárvore (versão 1.3
//!   no REG_STANDARD_FORMAT, 1.5 no REG_LATEST_FORMAT), sem as chaves
//!   voláteis;
//! - o NtCompressKey só marca a hive: LastReorganizeTime = o modo (0 para
//!   3) e o bloco base sujo (CmCompressKey, rva 0x86c170);
//! - o REG_WHOLE_HIVE_VOLATILE (CmpLoadHiveVolatile, rva 0x87cecc) exige uma
//!   chave da hive mestra (senão STATUS_INVALID_PARAMETER), copia a hive do
//!   arquivo para uma hive volátil nova e a liga em `<chave>\<nome da raiz
//!   da hive do arquivo>`, com a entrada vazia na lista de hives;
//! - o REG_REFRESH_HIVE (CmpRefreshHive, rva 0x87d368) exige a raiz de uma
//!   hive carregada com REG_NO_LAZY_FLUSH (senão STATUS_INVALID_PARAMETER) e
//!   desfaz as mudanças desde a última descarga, relendo o primário.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::ntos::cm::hive::storage::{Storage, HBLOCK_SIZE, STATUS_INSUFFICIENT_RESOURCES, STATUS_REGISTRY_CORRUPT};
use crate::ntos::cm::hive::{base_block, log, sync, tree};
use crate::ntos::cm::hive_file::{self, HiveFile, OpenMode, FILE_CREATED, FILE_OPEN, STATUS_REGISTRY_IO_FAILED};
use crate::ntos::cm::key::{policy as key_policy, security as key_security};
use crate::ntos::cm::registry::{self, NodeId};
use crate::ntos::cm::{hive_init, machine_hive};
use crate::ntos::io::file::request::EventReference;
use crate::ntos::ke::{clock, dispatcher};
use crate::rtl::SpinLock;

const STATUS_PENDING: u32 = 0x103;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_SHARING_VIOLATION: u32 = 0xC000_0043;
const STATUS_CANNOT_DELETE: u32 = 0xC000_0121;
const STATUS_KEY_DELETED: u32 = 0xC000_017C;
const STATUS_TOO_LATE: u32 = 0xC000_0189;

/// REG_FORCE_UNLOAD, REG_NO_LAZY_FLUSH, REG_FORCE_RESTORE, REG_APP_HIVE,
/// REG_PROCESS_PRIVATE, REG_OPEN_READ_ONLY.
pub const REG_FORCE_UNLOAD: u32 = 1;
pub const REG_NO_LAZY_FLUSH: u32 = 4;
pub const REG_FORCE_RESTORE: u32 = 8;
pub const REG_APP_HIVE: u32 = 0x10;
pub const REG_PROCESS_PRIVATE: u32 = 0x20;
pub const REG_OPEN_READ_ONLY: u32 = 0x2000;
/// REG_NO_IMPERSONATION_FALLBACK, que o NtLoadKey3 sempre liga.
pub const REG_NO_IMPERSONATION_FALLBACK: u32 = 0x8000;

/// Uma carga do NtLoadKey(2/3/Ex) já validada (CmLoadKey e CmLoadAppKey).
#[derive(Default)]
pub struct LoadRequest {
    /// As flags REG_* da carga.
    pub flags: u32,
    /// O UserEvent, sinalizado na descarga.
    pub unload_event: Option<EventReference>,
    /// A chave do TrustClassKey (o nó dela).
    pub trust: Option<NodeId>,
    /// O token de impersonação do CmExtendedParameterFileAccessToken e o
    /// nível dele.
    pub token: Option<(u64, u32)>,
    /// O PreviousMode do serviço é UserMode.
    pub previous_mode: bool,
}

/// HSYS_MINOR das hives novas: REG_STANDARD_FORMAT grava 1.3 e
/// REG_LATEST_FORMAT 1.5 (NtSaveKeyEx, rva 0x729730).
pub const STANDARD_MINOR: u32 = 3;
pub const LATEST_MINOR: u32 = 5;

/// Os arquivos de uma hive carregada. Os logs são abertos (ou criados) na
/// primeira descarga.
struct LoadedHive {
    primary: HiveFile,
    file_name: String,
    writable: bool,
    logs: [Option<HiveFile>; 2],
    current_log: usize,
    /// O caminho da raiz (o HiveRootPath).
    mount: String,
    /// As flags REG_* da carga (REG_NO_LAZY_FLUSH, REG_APP_HIVE,
    /// REG_PROCESS_PRIVATE, REG_OPEN_READ_ONLY).
    flags: u32,
    /// O UserEvent do NtLoadKeyEx, sinalizado na descarga.
    unload_event: Option<EventReference>,
    /// Hive do boot (CmpInitializeHiveList): não se descarrega.
    boot: bool,
}

static HIVES: SpinLock<BTreeMap<u32, LoadedHive>> = SpinLock::new(BTreeMap::new());
/// As hives voláteis (sem arquivo): identificador e ponto de montagem.
static VOLATILE: SpinLock<Vec<(u32, String)>> = SpinLock::new(Vec::new());
static NEXT_HIVE: AtomicU32 = AtomicU32::new(1);
static FLUSHING: AtomicBool = AtomicBool::new(false);
/// A lista de hives (o CmpHiveFileListHandle) já existe.
static HIVE_LIST_STARTED: AtomicBool = AtomicBool::new(false);

fn now() -> u64 {
    clock::system_time_100ns()
}

/// Serializa as descargas (a E/S acontece fora das travas).
struct FlushGuard;

impl FlushGuard {
    fn acquire() -> FlushGuard {
        while FLUSHING.swap(true, Ordering::AcqRel) {
            core::hint::spin_loop();
        }
        FlushGuard
    }

    /// Sem esperar: o escritor preguiçoso tenta de novo depois.
    fn try_acquire() -> Option<FlushGuard> {
        (!FLUSHING.swap(true, Ordering::AcqRel)).then_some(FlushGuard)
    }
}

impl Drop for FlushGuard {
    fn drop(&mut self) {
        FLUSHING.store(false, Ordering::Release);
    }
}

/// Uma descarga está em curso.
pub fn flush_in_progress() -> bool {
    FLUSHING.load(Ordering::Acquire)
}

fn parent_path(path: &str) -> String {
    let components = registry::split_path(path);
    let mut parent = String::new();
    for component in &components[..components.len().saturating_sub(1)] {
        parent.push('\\');
        parent.push_str(component);
    }
    parent
}

fn log_name(primary: &str, index: usize) -> String {
    alloc::format!("{primary}.LOG{}", index + 1)
}

/// Lê e valida um primário, aplicando os logs a um primário invalidado.
/// Um primário válido (Sequence1 = Sequence2) vai do arquivo para os bins
/// um bin de cada vez, sem a imagem inteira na memória
/// (`Storage::from_file`); só a recuperação pelos logs monta a imagem. Os
/// logs já abertos pela carga são lidos pelo handle deles; um log que a
/// carga não abriu é procurado pelo nome. Devolve as células e se houve
/// recuperação.
fn read_primary(primary: &HiveFile, logs: &[Option<HiveFile>; 2], file_name: &str) -> Result<(Storage, bool), u32> {
    let size = primary.size();
    if size < HBLOCK_SIZE as u64 {
        return Err(STATUS_REGISTRY_CORRUPT);
    }
    let base = primary.read_range(0, HBLOCK_SIZE as u64)?;
    if base[4..8] == base[8..12] {
        let storage = Storage::from_file(size, &|offset, length| primary.read_range(offset, length))?;
        return Ok((storage, false));
    }
    drop(base);
    let mut image = primary.read()?;
    if image.len() < HBLOCK_SIZE as usize {
        return Err(STATUS_REGISTRY_CORRUPT);
    }
    let mut recovered = false;
    if image[4..8] != image[8..12] {
        let logs: Vec<Vec<u8>> = (0..2)
            .filter_map(|index| match &logs[index] {
                Some(log) => log.read().ok(),
                None => HiveFile::open(&log_name(file_name, index), FILE_OPEN, false).ok().and_then(|log| log.read().ok()),
            })
            .collect();
        recovered = log::recover(&mut image, &logs) > 0;
    }
    let storage = Storage::from_image(&image)?;
    base_block::validate_primary(storage.base_block(), image.len() as u64)?;
    Ok((storage, recovered))
}

/// O nome do FILE_OBJECT do primário de uma hive (o ZwQueryObject com
/// ObjectNameInformation do CmpAddToHiveFileList).
fn primary_object_name(identifier: u32) -> Option<String> {
    HIVES.lock().get(&identifier).and_then(|hive| hive.primary.object_name())
}

/// A entrada da hive na lista de hives, se a lista já existe.
fn add_to_hive_list(identifier: u32, mount: &str, volatile: bool) {
    if !HIVE_LIST_STARTED.load(Ordering::Acquire) {
        return;
    }
    let name = if volatile { None } else { primary_object_name(identifier) };
    hive_init::add_to_hive_file_list(mount, Some(name.as_deref().unwrap_or("")));
}

/// A lista de hives começa (CmpHiveFileListHandle): as hives já ligadas
/// entram nela.
pub fn start_hive_list() {
    HIVE_LIST_STARTED.store(true, Ordering::Release);
    let volatile: Vec<(u32, String)> = VOLATILE.lock().clone();
    for (identifier, mount) in volatile {
        add_to_hive_list(identifier, &mount, true);
    }
    let loaded: Vec<(u32, String)> = HIVES.lock().iter().filter(|(_, hive)| hive.flags & REG_APP_HIVE == 0).map(|(&identifier, hive)| (identifier, hive.mount.clone())).collect();
    for (identifier, mount) in loaded {
        add_to_hive_list(identifier, &mount, false);
    }
}

/// Uma hive volátil nova em `mount` (a HARDWARE): sem arquivo, com a
/// entrada vazia na lista de hives.
pub fn create_volatile_hive(mount: &str) -> Result<u32, u32> {
    let identifier = NEXT_HIVE.fetch_add(1, Ordering::AcqRel);
    registry::create_volatile_hive(mount, identifier)?;
    VOLATILE.lock().push((identifier, String::from(mount)));
    add_to_hive_list(identifier, mount, true);
    machine_hive::notify_loaded(mount);
    Ok(identifier)
}

/// Uma hive de máquina do boot (o CmpInitializeHiveList): o arquivo
/// precisa existir; sem ele, `hive_init` semeia as chaves em memória. As
/// hives do boot são confiáveis e não se descarregam.
pub fn load(target: &str, file_name: &str, flags: u32) -> u32 {
    let mut request = LoadRequest { flags, ..LoadRequest::default() };
    match load_hive_files(target, file_name, &mut request, false, true) {
        Ok(_) => 0,
        Err(status) => status,
    }
}

/// CmLoadKey: carrega o arquivo `file_name` numa chave nova em `target`,
/// com o evento da descarga; devolve o identificador da hive. Como o
/// CmLoadKey e o CmLoadAppKey do 19041 (Allocate = TRUE no
/// CmpCmdHiveOpen), um arquivo ausente vira uma hive nova e vazia, salvo
/// numa carga só de leitura.
pub fn load_hive(target: &str, file_name: &str, mut request: LoadRequest) -> Result<u32, u32> {
    let result = load_hive_files(target, file_name, &mut request, true, false);
    if let Some(mut event) = request.unload_event.take() {
        event.release();
    }
    result
}

/// CmpJoinClassOfTrust (e o bit 0 de CMHIVE.Flags que o CmpLoadKeyCommon
/// liga antes): a classe de confiança da hive nova `identifier`, ou `None`
/// para uma hive confiável. Sem TrustClassKey, a classe é a própria hive;
/// uma hive de aplicativo não entra em classe nenhuma.
fn trust_class_for(identifier: u32, request: &LoadRequest) -> Result<Option<u32>, u32> {
    let Some(node) = request.trust.filter(|_| request.flags & REG_APP_HIVE == 0) else { return Ok(Some(identifier)) };
    // CmpIsKeyDeletedForKeyBody.
    if registry::is_deleted(node) {
        return Err(STATUS_KEY_DELETED);
    }
    match registry::owning_hive(node).and_then(registry::trust_class) {
        Some(class) => Ok(Some(class)),
        // CmpPerformTrustClassAccessCheck: do modo usuário, a chave precisa
        // ser de uma hive não confiável.
        None if request.previous_mode => Err(STATUS_INVALID_PARAMETER),
        None => Ok(None),
    }
}

/// A imagem de uma hive nova e vazia para `target` (o HINIT_CREATE do
/// CmpInitHiveFromFile e a raiz que o CmpLinkHiveToMaster cria nela): só a
/// raiz, com o último componente do nome, KEY_HIVE_ENTRY | KEY_NO_DELETE e
/// o descritor que a chave nova herda do pai pelo sujeito corrente.
fn new_hive_image(target: &str, file_name: &str) -> Result<Vec<u8>, u32> {
    let components = registry::split_path(target);
    let name = components.last().map(|name| String::from(*name)).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let parent = registry::node_by_path(&parent_path(target)).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let parent_security = registry::with_node(parent, |key| key.security.clone()).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let security = match key_security::create(&parent_security, 0, false) {
        Ok(Ok(security)) => security,
        Ok(Err(status)) => return Err(status),
        Err(_) => key_policy::boot_child(&parent_security).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?,
    };
    let time = now();
    let root = tree::NewKey { name, last_write_time: time, security, values: Vec::new(), parent: None, link: false, class: Vec::new() };
    let (storage, _) = tree::build(&[root], LATEST_MINOR, time, file_name).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    Ok(storage.image())
}

/// O que o CmpInitHiveFromFile deixa pronto: o primário e os logs abertos,
/// as células lidas (com os logs aplicados a um primário invalidado) e as
/// chaves.
struct HiveFromFile {
    primary: HiveFile,
    logs: [Option<HiveFile>; 2],
    storage: Storage,
    recovered: bool,
    keys: Vec<tree::FlatKey>,
}

/// CmpInitHiveFromFile (rva 0x6e9cb8): o primário (FILE_OPEN_IF quando a
/// carga pode alocar), os logs e a leitura; um arquivo criado agora (ou
/// vazio) recebe a hive nova.
fn init_hive_from_file(target: &str, file_name: &str, allocate: bool, mode: OpenMode) -> Result<HiveFromFile, u32> {
    // CmpOpenHiveFile: FILE_OPEN_IF quando a carga pode alocar a hive e não
    // é só de leitura ((Flags & 0x21) == 1), senão FILE_OPEN; depois os
    // logs.
    let (primary, information) = HiveFile::open_primary(file_name, allocate, mode)?;
    let logs: [Option<HiveFile>; 2] = [0, 1].map(|index| HiveFile::open_log(&log_name(file_name, index), mode).ok());
    if information == FILE_CREATED {
        // O arquivo foi criado agora (ou estava vazio): a hive nova vai
        // inteira para ele e a carga segue pelo caminho normal.
        let image = new_hive_image(target, file_name)?;
        if primary.write(0, &image).and_then(|_| primary.set_size(image.len() as u64)).is_err() {
            return Err(STATUS_REGISTRY_IO_FAILED);
        }
    }
    let (storage, recovered) = read_primary(&primary, &logs, file_name)?;
    let keys = tree::read(&storage)?;
    Ok(HiveFromFile { primary, logs, storage, recovered, keys })
}

/// Os status do primeiro CmpInitHiveFromFile que levam o CmpCmdHiveOpen
/// (rva 0x603684-0x6036a5) à segunda tentativa: STATUS_ACCESS_DENIED,
/// STATUS_NO_SUCH_USER, STATUS_WRONG_PASSWORD, STATUS_ACCOUNT_RESTRICTION,
/// STATUS_ACCOUNT_DISABLED e STATUS_ACCOUNT_EXPIRED (as falhas de conta vêm
/// de um arquivo remoto aberto com as credenciais da impersonação).
pub fn impersonation_fallback_status(status: u32) -> bool {
    matches!(status, 0xC000_0022 | 0xC000_0064 | 0xC000_006A | 0xC000_006E | 0xC000_0072 | 0xC000_0193)
}

/// A segunda tentativa é permitida: sem o token de acesso ao arquivo do
/// NtLoadKey3 e, numa hive de aplicativo, sem REG_NO_IMPERSONATION_FALLBACK
/// (o CmLoadAppKey o passa como o bit 0x20 das OpenFlags, rva 0x6e8deb; o
/// CmLoadKey nunca: numa hive comum o bit não muda nada).
pub fn impersonation_fallback_allowed(flags: u32, token: bool) -> bool {
    !token && !(flags & REG_APP_HIVE != 0 && flags & REG_NO_IMPERSONATION_FALLBACK != 0)
}

/// CmpCmdHiveOpen (rva 0x603588): o CmpInitHiveFromFile no contexto da
/// thread (ou impersonando o token do NtLoadKey3); se falhar por acesso ou
/// conta e a segunda tentativa for permitida, de novo impersonando o
/// próprio processo (RtlImpersonateSelfEx(SecurityImpersonation)), sem
/// OBJ_FORCE_ACCESS_CHECK, e a impersonação anterior da thread volta.
fn cmd_hive_open(target: &str, file_name: &str, allocate: bool, mode: OpenMode, flags: u32) -> Result<HiveFromFile, u32> {
    match init_hive_from_file(target, file_name, allocate, mode) {
        Err(status) if impersonation_fallback_status(status) && impersonation_fallback_allowed(flags, mode.token.is_some()) => {
            hive_file::impersonating_self(|| init_hive_from_file(target, file_name, allocate, OpenMode { token: None, ..mode }))
        }
        other => other,
    }
}

fn load_hive_files(target: &str, file_name: &str, request: &mut LoadRequest, allocate: bool, boot: bool) -> Result<u32, u32> {
    let flags = request.flags;
    if registry::node_by_path(target).is_some() {
        return Err(STATUS_OBJECT_NAME_COLLISION);
    }
    if registry::node_by_path(&parent_path(target)).is_none() {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    }
    let write = flags & REG_OPEN_READ_ONLY == 0;
    let mode = OpenMode { read_only: !write, token: request.token };
    // As hives do boot vêm do CmpLoadHiveThread, sem o CmpCmdHiveOpen: não
    // repetem a abertura.
    let opened = if boot { init_hive_from_file(target, file_name, allocate, mode) } else { cmd_hive_open(target, file_name, allocate, mode, flags) };
    let HiveFromFile { primary, logs, mut storage, recovered, mut keys } = opened?;
    // CmpReorganizeHive: o pedido do NtCompressKey (LastReorganizeTime = 1)
    // recompõe a hive compacta na carga.
    let reorganize = write && storage.base_block().last_reorganize_time.get() == 1;
    if reorganize {
        let new_keys: Vec<tree::NewKey> = keys.iter().map(|key| tree::NewKey { name: key.record.name.clone(), last_write_time: key.record.last_write_time, security: key.record.security.clone(), values: key.record.values.clone(), parent: key.parent, link: key.record.flags & crate::ntos::cm::hive::key_cells::KEY_SYM_LINK != 0, class: key.record.class.clone() }).collect();
        let sequence = storage.base_block().sequence1.get();
        let Some((rebuilt, _)) = tree::build(&new_keys, storage.minor(), now(), file_name) else { return Err(STATUS_INSUFFICIENT_RESOURCES) };
        storage = rebuilt;
        let base = storage.base_block();
        base.sequence1.set(sequence);
        base.sequence2.set(sequence);
        base.last_reorganize_time.set(now());
        keys = tree::read(&storage)?;
    }
    if write && (recovered || reorganize) {
        // O primário recuperado (ou recomposto) volta inteiro ao arquivo.
        let image = storage.image();
        if primary.write(0, &image).and_then(|_| primary.set_size(image.len() as u64)).is_err() {
            return Err(STATUS_REGISTRY_IO_FAILED);
        }
        storage.clear_dirty();
    }
    let identifier = NEXT_HIVE.fetch_add(1, Ordering::AcqRel);
    // A classe de confiança é decidida antes do CmpLinkHiveToMaster: uma
    // recusa não liga nada.
    let class = if boot { None } else { trust_class_for(identifier, request)? };
    if let Err((status, _)) = registry::link_hive(target, identifier, storage, keys) {
        return Err(status);
    }
    registry::set_trust_class(identifier, class);
    // O HiveRootPath: o nome do ponto de montagem como a carga o recebeu.
    let mount = String::from(target);
    HIVES.lock().insert(identifier, LoadedHive { primary, file_name: String::from(file_name), writable: write, logs, current_log: 0, mount, flags, unload_event: request.unload_event.take(), boot });
    if flags & REG_APP_HIVE == 0 {
        add_to_hive_list(identifier, target, false);
    }
    machine_hive::notify_loaded(target);
    Ok(identifier)
}

/// CmLoadAppKey: a hive de aplicativo do arquivo em `target`
/// (`\REGISTRY\A\{...}`), ou a já carregada do mesmo arquivo. Devolve o
/// caminho da raiz.
pub fn load_app_hive(target: &str, file_name: &str, mut request: LoadRequest) -> Result<String, u32> {
    request.flags |= REG_APP_HIVE;
    let flags = request.flags;
    let result = load_hive_files(target, file_name, &mut request, true, false);
    if let Some(mut event) = request.unload_event.take() {
        event.release();
    }
    let identifier = match result {
        Ok(identifier) => identifier,
        // O arquivo está aberto: só uma hive de aplicativo compartilhável do
        // mesmo arquivo serve (CmpIsThisSameFile).
        Err(STATUS_SHARING_VIOLATION) if flags & REG_PROCESS_PRIVATE == 0 => return shared_app_hive(file_name, flags),
        Err(status) => return Err(status),
    };
    registry::set_close_observer(Some(handle_closed));
    Ok(registry::hive_path(identifier).unwrap_or_else(|| String::from(target)))
}

/// A hive de aplicativo já carregada do arquivo `file_name` (CmpIsThisSameFile
/// sobre o FILE_OBJECT de uma abertura só com READ_CONTROL, que não esbarra
/// no compartilhamento do primário aberto): ela precisa ser de aplicativo,
/// sem REG_PROCESS_PRIVATE e com o mesmo modo só de leitura; senão,
/// STATUS_SHARING_VIOLATION.
fn shared_app_hive(file_name: &str, flags: u32) -> Result<String, u32> {
    let path = HiveFile::open_identity(file_name).map(|file| file.volume_path()).map_err(|_| STATUS_SHARING_VIOLATION)?;
    let hives = HIVES.lock();
    let same = hives.values().find(|hive| hive.primary.volume_path() == path);
    match same {
        Some(hive) if hive.flags & REG_APP_HIVE != 0 && hive.flags & REG_PROCESS_PRIVATE == 0 && (hive.flags ^ flags) & REG_OPEN_READ_ONLY == 0 => Ok(hive.mount.clone()),
        _ => Err(STATUS_SHARING_VIOLATION),
    }
}

/// Grava uma descarga montada: primário invalidado, log, faixas e o bloco
/// base validado.
fn write_plan(primary: &HiveFile, log: Option<&HiveFile>, plan: &sync::Plan) -> Result<(), u32> {
    primary.write(0, &plan.invalid_header)?;
    if let Some(log) = log {
        log.write(0, &plan.log)?;
        log.set_size(plan.log.len() as u64)?;
    }
    if primary.size() < plan.file_length {
        primary.set_size(plan.file_length)?;
    }
    for (offset, bytes) in &plan.writes {
        primary.write(*offset, bytes)?;
    }
    primary.write(0, &plan.valid_header)
}

/// Apelidos (sem posse do handle) do primário e do log corrente, que passa
/// a ser o outro (HvSwapLogFiles). O log ausente é criado aqui, fora da
/// trava.
fn files_of(identifier: u32) -> Option<(HiveFile, Option<HiveFile>)> {
    let (primary, index, existing, file_name, writable) = {
        let mut hives = HIVES.lock();
        let hive = hives.get_mut(&identifier)?;
        let index = hive.current_log;
        hive.current_log ^= 1;
        (hive.primary.alias(), index, hive.logs[index].as_ref().map(HiveFile::alias), hive.file_name.clone(), hive.writable)
    };
    let log = match existing {
        Some(log) => Some(log),
        None if writable => {
            let opened = HiveFile::open_log(&log_name(&file_name, index), OpenMode::default()).ok();
            let alias = opened.as_ref().map(HiveFile::alias);
            if let Some(hive) = HIVES.lock().get_mut(&identifier) {
                hive.logs[index] = opened;
            }
            alias
        }
        None => None,
    };
    Some((primary, log))
}

/// CmpFlushHive de uma hive carregada, com a descarga já serializada.
fn flush_hive_locked(identifier: u32) -> u32 {
    if !HIVES.lock().contains_key(&identifier) {
        return 0;
    }
    let plan = match registry::with_storage(identifier, |storage| if storage.broken { Err(STATUS_REGISTRY_IO_FAILED) } else { Ok(sync::prepare(storage)) }) {
        Some(Ok(Some(plan))) => plan,
        Some(Ok(None)) | None => return 0,
        Some(Err(status)) => return status,
    };
    let Some((primary, log)) = files_of(identifier) else {
        registry::with_storage(identifier, |storage| sync::abandon(storage, &plan));
        return 0;
    };
    match write_plan(&primary, log.as_ref(), &plan) {
        Ok(()) => 0,
        Err(_) => {
            registry::with_storage(identifier, |storage| sync::abandon(storage, &plan));
            STATUS_REGISTRY_IO_FAILED
        }
    }
}

/// CmpFlushHive de uma hive carregada.
fn flush_hive(identifier: u32) -> u32 {
    let _guard = FlushGuard::acquire();
    flush_hive_locked(identifier)
}

/// CmFlushKey: descarrega a hive da chave; fora das hives de arquivo,
/// todas (CmpDoFlushAll).
pub fn flush(node: NodeId) -> u32 {
    match registry::hive_of(node) {
        Some((identifier, _)) => flush_hive(identifier),
        None => flush_all(),
    }
}

/// CmpDoFlushAll: cada hive de arquivo; o primeiro erro é o resultado.
pub fn flush_all() -> u32 {
    let identifiers: Vec<u32> = HIVES.lock().keys().copied().collect();
    let mut status = 0;
    for identifier in identifiers {
        let flushed = flush_hive(identifier);
        if status == 0 {
            status = flushed;
        }
    }
    status
}

/// As hives sujas que o escritor preguiçoso descarrega.
fn lazy_dirty_hives() -> Vec<u32> {
    let eligible: Vec<u32> = HIVES.lock().iter().filter(|(_, hive)| hive.writable && hive.flags & REG_NO_LAZY_FLUSH == 0).map(|(&identifier, _)| identifier).collect();
    registry::dirty_hives().into_iter().filter(|&(identifier, dirty)| dirty && eligible.contains(&identifier)).map(|(identifier, _)| identifier).collect()
}

/// Há hive suja para o escritor preguiçoso.
pub fn lazy_flush_pending() -> bool {
    !lazy_dirty_hives().is_empty()
}

/// Uma passada do escritor preguiçoso (CmpDoFlushNextHive): as hives de
/// arquivo sujas, menos as carregadas com REG_NO_LAZY_FLUSH e as abertas
/// só para leitura. `None` quando outra descarga está em curso (o
/// escritor tenta de novo); senão, quantas hives foram descarregadas.
pub fn lazy_flush_pass() -> Option<u32> {
    let _guard = FlushGuard::try_acquire()?;
    let mut flushed = 0;
    for identifier in lazy_dirty_hives() {
        if flush_hive_locked(identifier) == 0 {
            flushed += 1;
        }
    }
    Some(flushed)
}

/// CmpPerformUnloadKey sobre a chave resolvida. `extended` é o
/// NtUnloadKeyEx: com handles abertos a hive congela (CmpFreezeHive) e é
/// descarregada quando o último handle dela fecha, com o evento (se houver)
/// sinalizado (CmpSignalUnloadEventArrayForHive); o NtUnloadKey(2) recusa
/// com STATUS_CANNOT_DELETE.
pub fn unload_key(node: NodeId, flags: u32, extended: bool, event: Option<EventReference>) -> u32 {
    fn finish(status: u32, event: Option<EventReference>) -> u32 {
        if let Some(mut event) = event {
            event.release();
        }
        status
    }
    let force = flags & REG_FORCE_UNLOAD != 0;
    // O KeyHive congelado: só a descarga forçada de uma hive de aplicativo
    // passa.
    if let Some(identifier) = registry::owning_hive(node).filter(|identifier| DEFERRED.lock().iter().any(|(candidate, _)| candidate == identifier)) {
        let app = HIVES.lock().get(&identifier).is_some_and(|hive| hive.flags & REG_APP_HIVE != 0);
        if !force || !app {
            return finish(STATUS_TOO_LATE, event);
        }
    }
    let Some((identifier, true)) = registry::hive_of(node) else { return finish(STATUS_INVALID_PARAMETER, event) };
    if HIVES.lock().get(&identifier).is_some_and(|hive| hive.boot) {
        return finish(STATUS_ACCESS_DENIED, event);
    }
    if !force && registry::subtree_has_open_handles(node, true) {
        if !extended {
            return finish(STATUS_CANNOT_DELETE, event);
        }
        DEFERRED.lock().push((identifier, event));
        registry::set_close_observer(Some(handle_closed));
        return STATUS_PENDING;
    }
    finish(unload_hive(identifier, flags), event)
}

/// CmUnloadKey (NtUnloadKey/NtUnloadKey2) sobre a chave resolvida.
pub fn unload(node: NodeId, flags: u32) -> u32 {
    unload_key(node, flags, false, None)
}

fn unload_hive(identifier: u32, flags: u32) -> u32 {
    let path = registry::hive_path(identifier).unwrap_or_default();
    let mut storage = match registry::unlink_hive(identifier, flags & REG_FORCE_UNLOAD != 0) {
        Ok(storage) => storage,
        Err(status) => return status,
    };
    machine_hive::notify_unloaded(&path);
    let loaded = HIVES.lock().get(&identifier).map(|hive| (hive.flags & REG_APP_HIVE != 0, hive.mount.clone()));
    let volatile = VOLATILE.lock().iter().find(|&&(candidate, _)| candidate == identifier).map(|(_, mount)| mount.clone());
    // CmpRemoveFromHiveFileList, pelo nome com que a hive entrou na lista.
    match (loaded, volatile) {
        (Some((false, mount)), _) | (None, Some(mount)) => hive_init::remove_from_hive_file_list(&mount),
        _ => {}
    }
    VOLATILE.lock().retain(|&(candidate, _)| candidate != identifier);
    let _guard = FlushGuard::acquire();
    if let Some((primary, log)) = files_of(identifier).filter(|_| !storage.broken) {
        if let Some(plan) = sync::prepare(&mut storage) {
            let _ = write_plan(&primary, log.as_ref(), &plan);
        }
    }
    let removed = HIVES.lock().remove(&identifier);
    if let Some(mut event) = removed.and_then(|hive| hive.unload_event) {
        dispatcher::set_event(event.pointer);
        event.release();
    }
    // Uma hive congelada descarregada à força: os eventos do NtUnloadKeyEx.
    let frozen: Vec<Option<EventReference>> = {
        let mut deferred = DEFERRED.lock();
        let mut frozen = Vec::new();
        let mut index = 0;
        while index < deferred.len() {
            if deferred[index].0 == identifier {
                frozen.push(deferred.remove(index).1);
            } else {
                index += 1;
            }
        }
        frozen
    };
    for mut event in frozen.into_iter().flatten() {
        dispatcher::set_event(event.pointer);
        event.release();
    }
    0
}

/// As hives congeladas pelo NtUnloadKeyEx esperando o último handle (o
/// CMHIVE.Frozen) e o evento de cada pedido.
static DEFERRED: SpinLock<Vec<(u32, Option<EventReference>)>> = SpinLock::new(Vec::new());

/// Um handle de chave fechou: completa as descargas pendentes que ficaram
/// sem handles (CmpLateUnloadHiveWorker) e descarrega as hives de
/// aplicativo sem handles.
fn handle_closed() {
    let ready: Vec<u32> = {
        let deferred = DEFERRED.lock();
        let mut ready: Vec<u32> = Vec::new();
        for &(identifier, _) in deferred.iter() {
            let free = registry::hive_root(identifier).is_none_or(|root| !registry::subtree_has_open_handles(root, true));
            if free && !ready.contains(&identifier) {
                ready.push(identifier);
            }
        }
        ready
    };
    for identifier in ready {
        if registry::hive_root(identifier).is_some() {
            // unload_hive sinaliza os eventos dos pedidos.
            unload_hive(identifier, 0);
        } else {
            let events: Vec<Option<EventReference>> = {
                let mut deferred = DEFERRED.lock();
                let (gone, kept): (Vec<_>, Vec<_>) = core::mem::take(&mut *deferred).into_iter().partition(|(candidate, _)| *candidate == identifier);
                *deferred = kept;
                gone.into_iter().map(|(_, event)| event).collect()
            };
            for mut event in events.into_iter().flatten() {
                dispatcher::set_event(event.pointer);
                event.release();
            }
        }
    }
    let apps: Vec<u32> = HIVES.lock().iter().filter(|(_, hive)| hive.flags & REG_APP_HIVE != 0).map(|(&identifier, _)| identifier).collect();
    for identifier in apps {
        if !registry::hive_has_open_handles(identifier) {
            unload_hive(identifier, 0);
        }
    }
}

/// CmSaveKey: a subárvore numa hive nova e compacta, gravada no arquivo.
pub fn save(node: NodeId, file: &HiveFile, minor: u32) -> u32 {
    let Some(keys) = registry::snapshot(node) else { return STATUS_INVALID_PARAMETER };
    let Some((storage, _)) = tree::build(&keys, minor, now(), "") else { return STATUS_INSUFFICIENT_RESOURCES };
    let image = storage.image();
    match file.write(0, &image).and_then(|_| file.set_size(image.len() as u64)) {
        Ok(()) => 0,
        Err(status) => status,
    }
}

/// As chaves de uma hive de arquivo (o primário validado, lido bin a bin).
fn read_hive_file(file: &HiveFile) -> Result<Vec<tree::FlatKey>, u32> {
    let storage = Storage::from_file(file.size(), &|offset, length| file.read_range(offset, length))?;
    tree::read(&storage)
}

/// CmRestoreKey: troca a subárvore da chave pela hive do arquivo.
pub fn restore(node: NodeId, file: &HiveFile, flags: u32) -> u32 {
    let keys = match read_hive_file(file) {
        Ok(keys) => keys,
        Err(status) => return status,
    };
    if flags & REG_FORCE_RESTORE == 0 && registry::subtree_has_open_handles(node, false) {
        return STATUS_CANNOT_DELETE;
    }
    match registry::restore_subtree(node, keys) {
        Ok(()) => match registry::hive_of(node) {
            Some((identifier, _)) => flush_hive(identifier),
            None => 0,
        },
        Err(error) => if error.status != 0 { error.status } else { STATUS_INSUFFICIENT_RESOURCES },
    }
}

/// CmpLoadHiveVolatile (REG_WHOLE_HIVE_VOLATILE): a hive do arquivo copiada
/// para uma hive volátil nova em `<chave>\<nome da raiz>`. A chave precisa
/// ser da hive mestra.
pub fn restore_volatile(node: NodeId, file: &HiveFile) -> u32 {
    if registry::hive_of(node).is_some() || registry::path_of(node).is_none() {
        return STATUS_INVALID_PARAMETER;
    }
    let keys = match read_hive_file(file) {
        Ok(keys) => keys,
        Err(status) => return status,
    };
    let Some(root_name) = keys.first().map(|key| key.record.name.clone()) else { return STATUS_REGISTRY_CORRUPT };
    let Some(base) = registry::path_of(node) else { return STATUS_INVALID_PARAMETER };
    let mount = alloc::format!("{base}\\{root_name}");
    // CmpCopySyncTree para a hive volátil.
    let copies: Vec<tree::NewKey> = keys.iter().map(|key| tree::NewKey { name: key.record.name.clone(), last_write_time: key.record.last_write_time, security: key.record.security.clone(), values: key.record.values.clone(), parent: key.parent, link: key.record.flags & crate::ntos::cm::hive::key_cells::KEY_SYM_LINK != 0, class: key.record.class.clone() }).collect();
    let Some((storage, _)) = tree::build(&copies, LATEST_MINOR, now(), "") else { return STATUS_INSUFFICIENT_RESOURCES };
    let keys = match tree::read(&storage) {
        Ok(keys) => keys,
        Err(status) => return status,
    };
    let identifier = NEXT_HIVE.fetch_add(1, Ordering::AcqRel);
    if let Err((status, _)) = registry::link_hive(&mount, identifier, storage, keys) {
        return status;
    }
    VOLATILE.lock().push((identifier, mount.clone()));
    add_to_hive_list(identifier, &mount, true);
    machine_hive::notify_loaded(&mount);
    0
}

/// CmpRefreshHive (REG_REFRESH_HIVE): a raiz de uma hive carregada com
/// REG_NO_LAZY_FLUSH volta ao estado da última descarga.
pub fn refresh(node: NodeId) -> u32 {
    let Some((identifier, true)) = registry::hive_of(node) else { return STATUS_INVALID_PARAMETER };
    let Some((primary, logs, file_name)) = HIVES.lock().get(&identifier).filter(|hive| hive.flags & REG_NO_LAZY_FLUSH != 0).map(|hive| (hive.primary.alias(), [hive.logs[0].as_ref().map(HiveFile::alias), hive.logs[1].as_ref().map(HiveFile::alias)], hive.file_name.clone())) else { return STATUS_INVALID_PARAMETER };
    let _guard = FlushGuard::acquire();
    let (storage, _) = match read_primary(&primary, &logs, &file_name) {
        Ok(read) => read,
        Err(status) => return status,
    };
    let keys = match tree::read(&storage) {
        Ok(keys) => keys,
        Err(status) => return status,
    };
    match registry::refresh_hive(identifier, storage, keys) {
        Ok(()) => 0,
        Err(status) => status,
    }
}

/// CmCompressKey: a raiz de uma hive de arquivo; LastReorganizeTime = o
/// modo (0 para 3) e o bloco base sujo.
pub fn compress(node: NodeId, mode: u32) -> u32 {
    let Some((identifier, true)) = registry::hive_of(node) else { return STATUS_INVALID_PARAMETER };
    if mode & !3 != 0 || !HIVES.lock().contains_key(&identifier) {
        return STATUS_INVALID_PARAMETER;
    }
    registry::with_storage(identifier, |storage| {
        storage.base_block().last_reorganize_time.set(if mode == 3 { 0 } else { mode as u64 });
        storage.mark_base_dirty();
    });
    0
}

/// As chaves da subárvore pertencem todas à mesma hive de arquivo, nenhuma
/// é raiz de hive (o NtCompactKeys aceita e não muda nada).
pub fn same_hive(nodes: &[NodeId]) -> bool {
    let hives: Vec<Option<(u32, bool)>> = nodes.iter().map(|&node| registry::hive_of(node)).collect();
    hives.iter().all(|hive| hive.map(|(_, root)| !root).unwrap_or(true)) && hives.windows(2).all(|pair| pair[0].map(|(id, _)| id) == pair[1].map(|(id, _)| id))
}

/// A hive do nó foi carregada com REG_NO_LAZY_FLUSH (o HIVE_NOLAZYFLUSH
/// que o NtFlushKey confere).
pub fn no_lazy_flush(node: NodeId) -> bool {
    registry::owning_hive(node).is_some_and(|identifier| HIVES.lock().get(&identifier).is_some_and(|hive| hive.flags & REG_NO_LAZY_FLUSH != 0))
}

/// A hive de um nó é volátil (sem arquivo).
pub fn is_volatile_hive(node: NodeId) -> bool {
    registry::hive_of(node).is_some_and(|(identifier, _)| VOLATILE.lock().iter().any(|&(candidate, _)| candidate == identifier))
}
