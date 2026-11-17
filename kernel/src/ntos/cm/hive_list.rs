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
//!   CmpAddToHiveFileList), salvo uma hive de aplicativo;
//! - uma hive de aplicativo (CmLoadAppKey, rva 0x6e8bfc) cujo arquivo já
//!   está carregado como hive de aplicativo não é carregada de novo: a
//!   carga devolve a hive existente (CmpIsThisSameFile). Ela é descarregada
//!   quando o último handle de chave dela fecha;
//! - a descarga exige a raiz de uma hive (senão STATUS_INVALID_PARAMETER),
//!   recusa handles abertos em chaves dela com STATUS_CANNOT_DELETE (salvo
//!   REG_FORCE_UNLOAD), tira a hive do namespace e da lista de hives e
//!   então a descarrega para o arquivo (CmpCompleteUnloadKey chama o
//!   CmpFlushHive depois do CmpRemoveHiveFromNamespace); o evento da carga
//!   (o UserEvent do NtLoadKeyEx) é sinalizado;
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
use crate::ntos::cm::hive_file::{HiveFile, FILE_OPEN, FILE_OPEN_IF, STATUS_REGISTRY_IO_FAILED};
use crate::ntos::cm::registry::{self, NodeId};
use crate::ntos::cm::{hive_init, machine_hive};
use crate::ntos::io::file::request::EventReference;
use crate::ntos::ke::{clock, dispatcher};
use crate::rtl::SpinLock;

const STATUS_PENDING: u32 = 0x103;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_CANNOT_DELETE: u32 = 0xC000_0121;

/// REG_FORCE_UNLOAD, REG_NO_LAZY_FLUSH, REG_FORCE_RESTORE, REG_APP_HIVE,
/// REG_OPEN_READ_ONLY.
pub const REG_FORCE_UNLOAD: u32 = 1;
pub const REG_NO_LAZY_FLUSH: u32 = 4;
pub const REG_FORCE_RESTORE: u32 = 8;
pub const REG_APP_HIVE: u32 = 0x10;
pub const REG_OPEN_READ_ONLY: u32 = 0x2000;

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
    /// As flags REG_* da carga (REG_NO_LAZY_FLUSH, REG_APP_HIVE).
    flags: u32,
    /// O UserEvent do NtLoadKeyEx, sinalizado na descarga.
    unload_event: Option<EventReference>,
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
/// Devolve as células e se houve recuperação.
fn read_primary(primary: &HiveFile, file_name: &str) -> Result<(Storage, bool), u32> {
    let mut image = primary.read()?;
    if image.len() < HBLOCK_SIZE as usize {
        return Err(STATUS_REGISTRY_CORRUPT);
    }
    let mut recovered = false;
    if image[4..8] != image[8..12] {
        let logs: Vec<Vec<u8>> = (0..2).filter_map(|index| HiveFile::open(&log_name(file_name, index), FILE_OPEN, false).ok()).filter_map(|log| log.read().ok()).collect();
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

/// CmLoadKey: carrega o arquivo `file_name` numa chave nova em `target`.
pub fn load(target: &str, file_name: &str, flags: u32) -> u32 {
    match load_hive(target, file_name, flags, None) {
        Ok(_) => 0,
        Err(status) => status,
    }
}

/// [`load`] com o evento da descarga; devolve o identificador da hive.
pub fn load_hive(target: &str, file_name: &str, flags: u32, unload_event: Option<EventReference>) -> Result<u32, u32> {
    let mut unload_event = unload_event;
    let result = load_hive_files(target, file_name, flags, &mut unload_event);
    if let Some(mut event) = unload_event {
        event.release();
    }
    result
}

fn load_hive_files(target: &str, file_name: &str, flags: u32, unload_event: &mut Option<EventReference>) -> Result<u32, u32> {
    if registry::node_by_path(target).is_some() {
        return Err(STATUS_OBJECT_NAME_COLLISION);
    }
    if registry::node_by_path(&parent_path(target)).is_none() {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    }
    let write = flags & REG_OPEN_READ_ONLY == 0;
    let primary = HiveFile::open(file_name, FILE_OPEN, write)?;
    let (mut storage, recovered) = read_primary(&primary, file_name)?;
    let mut keys = tree::read(&storage)?;
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
    if let Err((status, _)) = registry::link_hive(target, identifier, storage, keys) {
        return Err(status);
    }
    // O HiveRootPath: o nome do ponto de montagem como a carga o recebeu.
    let mount = String::from(target);
    HIVES.lock().insert(identifier, LoadedHive { primary, file_name: String::from(file_name), writable: write, logs: [None, None], current_log: 0, mount, flags, unload_event: unload_event.take() });
    if flags & REG_APP_HIVE == 0 {
        add_to_hive_list(identifier, target, false);
    }
    machine_hive::notify_loaded(target);
    Ok(identifier)
}

/// CmLoadAppKey: a hive de aplicativo do arquivo em `target`
/// (`\REGISTRY\A\{...}`), ou a já carregada do mesmo arquivo. Devolve o
/// caminho da raiz.
pub fn load_app_hive(target: &str, file_name: &str, flags: u32, unload_event: Option<EventReference>) -> Result<String, u32> {
    // CmpIsThisSameFile: o arquivo já é uma hive de aplicativo (pelo nome,
    // ou pelo arquivo do volume quando ele ainda abre: o primário de uma
    // hive carregada fica aberto sem compartilhamento).
    let mut existing = HIVES.lock().values().find(|hive| hive.flags & REG_APP_HIVE != 0 && hive.file_name.eq_ignore_ascii_case(file_name)).map(|hive| hive.mount.clone());
    if existing.is_none() {
        if let Some(path) = HiveFile::open(file_name, FILE_OPEN, false).ok().map(|file| file.volume_path()) {
            existing = HIVES.lock().values().find(|hive| hive.flags & REG_APP_HIVE != 0 && hive.primary.volume_path() == path).map(|hive| hive.mount.clone());
        }
    }
    if let Some(mount) = existing {
        if let Some(mut event) = unload_event {
            event.release();
        }
        return Ok(mount);
    }
    let identifier = load_hive(target, file_name, flags | REG_APP_HIVE, unload_event)?;
    registry::set_close_observer(Some(handle_closed));
    Ok(registry::hive_path(identifier).unwrap_or_else(|| String::from(target)))
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
            let opened = HiveFile::open(&log_name(&file_name, index), FILE_OPEN_IF, true).ok();
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

/// CmUnloadKey sobre a chave resolvida.
pub fn unload(node: NodeId, flags: u32) -> u32 {
    let Some((identifier, true)) = registry::hive_of(node) else { return STATUS_INVALID_PARAMETER };
    if flags & REG_FORCE_UNLOAD == 0 && registry::subtree_has_open_handles(node, true) {
        return STATUS_CANNOT_DELETE;
    }
    unload_hive(identifier, flags)
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
    0
}

/// Descargas do NtUnloadKeyEx esperando o último handle: (hive, evento).
static DEFERRED: SpinLock<Vec<(u32, EventReference)>> = SpinLock::new(Vec::new());

/// NtUnloadKeyEx com evento: com handles abertos a hive fica pendente
/// (STATUS_PENDING, o CmpFreezeHive) e é descarregada quando o último handle
/// dela fecha, com o evento sinalizado (CmpSignalUnloadEventArrayForHive).
pub fn unload_or_defer(node: NodeId, flags: u32, mut event: EventReference) -> u32 {
    let Some((identifier, true)) = registry::hive_of(node) else {
        event.release();
        return STATUS_INVALID_PARAMETER;
    };
    if flags & REG_FORCE_UNLOAD != 0 || !registry::subtree_has_open_handles(node, true) {
        event.release();
        return unload(node, flags);
    }
    DEFERRED.lock().push((identifier, event));
    registry::set_close_observer(Some(handle_closed));
    STATUS_PENDING
}

/// Um handle de chave fechou: completa as descargas pendentes que ficaram
/// sem handles e descarrega as hives de aplicativo sem handles.
fn handle_closed() {
    let ready: Vec<(u32, EventReference)> = {
        let mut deferred = DEFERRED.lock();
        let mut ready = Vec::new();
        let mut index = 0;
        while index < deferred.len() {
            let identifier = deferred[index].0;
            let free = registry::hive_root(identifier).is_none_or(|root| !registry::subtree_has_open_handles(root, true));
            if free {
                ready.push(deferred.remove(index));
            } else {
                index += 1;
            }
        }
        ready
    };
    for (identifier, mut event) in ready {
        if let Some(root) = registry::hive_root(identifier) {
            unload(root, 0);
        }
        dispatcher::set_event(event.pointer);
        event.release();
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

/// As chaves de uma hive de arquivo (o primário validado).
fn read_hive_file(file: &HiveFile) -> Result<Vec<tree::FlatKey>, u32> {
    let image = file.read()?;
    let storage = Storage::from_image(&image)?;
    base_block::validate_primary(storage.base_block(), image.len() as u64)?;
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
    let Some((primary, file_name)) = HIVES.lock().get(&identifier).filter(|hive| hive.flags & REG_NO_LAZY_FLUSH != 0).map(|hive| (hive.primary.alias(), hive.file_name.clone())) else { return STATUS_INVALID_PARAMETER };
    let _guard = FlushGuard::acquire();
    let (storage, _) = match read_primary(&primary, &file_name) {
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

/// A hive de um nó é volátil (sem arquivo).
pub fn is_volatile_hive(node: NodeId) -> bool {
    registry::hive_of(node).is_some_and(|(identifier, _)| VOLATILE.lock().iter().any(|&(candidate, _)| candidate == identifier))
}
