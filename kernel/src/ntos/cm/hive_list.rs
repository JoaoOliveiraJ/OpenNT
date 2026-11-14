//! As hives carregadas de arquivo (o CmpHiveListHead do NT) e as operações
//! do Cm sobre elas: carga (CmLoadKey), descarga (CmUnloadKey), descarga
//! para o arquivo (CmFlushKey), cópia para um arquivo (CmSaveKey),
//! restauração (CmRestoreKey), compressão (CmCompressKey) e a hive SYSTEM
//! do boot (o papel do CmInitSystem1 / CmpInitializeHiveList).
//!
//! Como no ntoskrnl 19041:
//! - a carga liga a hive numa chave nova sob um pai existente; a chave que
//!   já existe dá STATUS_OBJECT_NAME_COLLISION; um primário com as
//!   sequências diferentes passa pela recuperação pelos logs antes de ser
//!   lido; com LastReorganizeTime = 1 (pedido pelo NtCompressKey) a hive é
//!   reorganizada na carga; uma carga num dos pontos de montagem das hives
//!   de máquina avisa as notificações do
//!   CmRegisterMachineHiveLoadedNotification (CmpNotifyMachineHiveLoaded);
//! - a descarga exige a raiz de uma hive (senão STATUS_INVALID_PARAMETER),
//!   recusa handles abertos em chaves dela com STATUS_CANNOT_DELETE (salvo
//!   REG_FORCE_UNLOAD), tira a hive do namespace e então a descarrega para
//!   o arquivo (CmpCompleteUnloadKey chama o CmpFlushHive depois do
//!   CmpRemoveHiveFromNamespace);
//! - a descarga de uma chave fora das hives de arquivo descarrega todas
//!   (CmpDoFlushAll); uma falha de E/S é STATUS_REGISTRY_IO_FAILED;
//! - o NtSaveKey grava uma hive nova e compacta com a subárvore (versão 1.3
//!   no REG_STANDARD_FORMAT, 1.5 no REG_LATEST_FORMAT), sem as chaves
//!   voláteis;
//! - o NtCompressKey só marca a hive: LastReorganizeTime = o modo (0 para
//!   3) e o bloco base sujo (CmCompressKey, rva 0x86c170).
//!
//! A hive SYSTEM vem de `\SystemRoot\System32\config\SYSTEM`, gravado pelo
//! build com as tabelas de `cm/seed.rs`. Sem o arquivo (ou com um arquivo
//! que não carrega), as mesmas chaves são semeadas em memória e o boot
//! segue como antes. Não há escritor preguiçoso: as mudanças vão para o
//! arquivo no NtFlushKey, no NtUnloadKey e no NtRestoreKey.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::ntos::cm::hive::storage::{Storage, HBLOCK_SIZE, STATUS_INSUFFICIENT_RESOURCES, STATUS_REGISTRY_CORRUPT};
use crate::ntos::cm::hive::{base_block, log, sync, tree};
use crate::ntos::cm::hive_file::{HiveFile, FILE_OPEN, FILE_OPEN_IF, STATUS_REGISTRY_IO_FAILED};
use crate::ntos::cm::registry::{self, NodeId};
use crate::ntos::cm::{machine_hive, seed};
use crate::ntos::io::file::request::EventReference;
use crate::ntos::ke::{clock, dispatcher};
use crate::rtl::SpinLock;

const STATUS_PENDING: u32 = 0x103;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_CANNOT_DELETE: u32 = 0xC000_0121;

/// REG_FORCE_UNLOAD, REG_FORCE_RESTORE, REG_OPEN_READ_ONLY.
pub const REG_FORCE_UNLOAD: u32 = 1;
pub const REG_FORCE_RESTORE: u32 = 8;
pub const REG_OPEN_READ_ONLY: u32 = 0x2000;

/// HSYS_MINOR das hives novas: REG_STANDARD_FORMAT grava 1.3 e
/// REG_LATEST_FORMAT 1.5 (NtSaveKeyEx, rva 0x729730).
pub const STANDARD_MINOR: u32 = 3;
pub const LATEST_MINOR: u32 = 5;

const SYSTEM_MOUNT: &str = "\\Registry\\Machine\\SYSTEM";
const SYSTEM_FILE: &str = "\\SystemRoot\\System32\\config\\SYSTEM";

/// Os arquivos de uma hive carregada. Os logs são abertos (ou criados) na
/// primeira descarga.
struct LoadedHive {
    primary: HiveFile,
    file_name: String,
    writable: bool,
    logs: [Option<HiveFile>; 2],
    current_log: usize,
}

static HIVES: SpinLock<BTreeMap<u32, LoadedHive>> = SpinLock::new(BTreeMap::new());
static NEXT_HIVE: AtomicU32 = AtomicU32::new(1);
static FLUSHING: AtomicBool = AtomicBool::new(false);
static SYSTEM_FROM_FILE: AtomicBool = AtomicBool::new(false);

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
}

impl Drop for FlushGuard {
    fn drop(&mut self) {
        FLUSHING.store(false, Ordering::Release);
    }
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
    format!("{primary}.LOG{}", index + 1)
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

/// CmLoadKey: carrega o arquivo `file_name` numa chave nova em `target`.
pub fn load(target: &str, file_name: &str, flags: u32) -> u32 {
    if registry::node_by_path(target).is_some() {
        return STATUS_OBJECT_NAME_COLLISION;
    }
    if registry::node_by_path(&parent_path(target)).is_none() {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    let write = flags & REG_OPEN_READ_ONLY == 0;
    let primary = match HiveFile::open(file_name, FILE_OPEN, write) {
        Ok(primary) => primary,
        Err(status) => return status,
    };
    let (mut storage, recovered) = match read_primary(&primary, file_name) {
        Ok(read) => read,
        Err(status) => return status,
    };
    let mut keys = match tree::read(&storage) {
        Ok(keys) => keys,
        Err(status) => return status,
    };
    // CmpReorganizeHive: o pedido do NtCompressKey (LastReorganizeTime = 1)
    // recompõe a hive compacta na carga.
    let reorganize = write && storage.base_block().last_reorganize_time.get() == 1;
    if reorganize {
        let new_keys: Vec<tree::NewKey> = keys.iter().map(|key| tree::NewKey { name: key.record.name.clone(), last_write_time: key.record.last_write_time, security: key.record.security.clone(), values: key.record.values.clone(), parent: key.parent }).collect();
        let sequence = storage.base_block().sequence1.get();
        let Some((rebuilt, _)) = tree::build(&new_keys, storage.minor(), now(), file_name) else { return STATUS_INSUFFICIENT_RESOURCES };
        storage = rebuilt;
        let base = storage.base_block();
        base.sequence1.set(sequence);
        base.sequence2.set(sequence);
        base.last_reorganize_time.set(now());
        keys = match tree::read(&storage) {
            Ok(keys) => keys,
            Err(status) => return status,
        };
    }
    if write && (recovered || reorganize) {
        // O primário recuperado (ou recomposto) volta inteiro ao arquivo.
        let image = storage.image();
        if primary.write(0, &image).and_then(|_| primary.set_size(image.len() as u64)).is_err() {
            return STATUS_REGISTRY_IO_FAILED;
        }
        storage.clear_dirty();
    }
    let identifier = NEXT_HIVE.fetch_add(1, Ordering::AcqRel);
    if let Err((status, _)) = registry::link_hive(target, identifier, storage, keys) {
        return status;
    }
    HIVES.lock().insert(identifier, LoadedHive { primary, file_name: String::from(file_name), writable: write, logs: [None, None], current_log: 0 });
    machine_hive::notify_loaded(target);
    0
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

/// CmpFlushHive de uma hive carregada.
fn flush_hive(identifier: u32) -> u32 {
    let _guard = FlushGuard::acquire();
    let Some((primary, log)) = files_of(identifier) else { return 0 };
    let plan = match registry::with_storage(identifier, |storage| if storage.broken { Err(STATUS_REGISTRY_IO_FAILED) } else { Ok(sync::prepare(storage)) }) {
        Some(Ok(Some(plan))) => plan,
        Some(Ok(None)) | None => return 0,
        Some(Err(status)) => return status,
    };
    match write_plan(&primary, log.as_ref(), &plan) {
        Ok(()) => 0,
        Err(_) => {
            registry::with_storage(identifier, |storage| sync::abandon(storage, &plan));
            STATUS_REGISTRY_IO_FAILED
        }
    }
}

/// CmFlushKey: descarrega a hive da chave; fora das hives de arquivo,
/// todas (CmpDoFlushAll).
pub fn flush(node: NodeId) -> u32 {
    match registry::hive_of(node) {
        Some((identifier, _)) => flush_hive(identifier),
        None => {
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
    }
}

/// CmUnloadKey sobre a chave resolvida.
pub fn unload(node: NodeId, flags: u32) -> u32 {
    let Some((identifier, true)) = registry::hive_of(node) else { return STATUS_INVALID_PARAMETER };
    if flags & REG_FORCE_UNLOAD == 0 && registry::subtree_has_open_handles(node, true) {
        return STATUS_CANNOT_DELETE;
    }
    let path = registry::path_of(node).unwrap_or_default();
    let mut storage = match registry::unlink_hive(identifier, flags & REG_FORCE_UNLOAD != 0) {
        Ok(storage) => storage,
        Err(status) => return status,
    };
    machine_hive::notify_unloaded(&path);
    let _guard = FlushGuard::acquire();
    if let Some((primary, log)) = files_of(identifier).filter(|_| !storage.broken) {
        if let Some(plan) = sync::prepare(&mut storage) {
            let _ = write_plan(&primary, log.as_ref(), &plan);
        }
    }
    HIVES.lock().remove(&identifier);
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
/// sem handles.
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

/// CmRestoreKey: troca a subárvore da chave pela hive do arquivo.
pub fn restore(node: NodeId, file: &HiveFile, flags: u32) -> u32 {
    let image = match file.read() {
        Ok(image) => image,
        Err(status) => return status,
    };
    let storage = match Storage::from_image(&image) {
        Ok(storage) => storage,
        Err(status) => return status,
    };
    if let Err(status) = base_block::validate_primary(storage.base_block(), image.len() as u64) {
        return status;
    }
    let keys = match tree::read(&storage) {
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

/// A hive SYSTEM veio do arquivo no boot.
pub fn system_hive_from_file() -> bool {
    SYSTEM_FROM_FILE.load(Ordering::Acquire)
}

/// Semeia em memória as chaves estáticas da hive SYSTEM.
fn seed_system_in_memory() -> Result<(), crate::rtl::KernelError> {
    for key in seed::system_keys(crate::ntos::init::boot_config::SMSS_BOOT) {
        let handle = registry::open_or_create(&format!("\\Registry\\Machine\\System\\{}", key.path), None)?;
        for (name, value_type, data) in key.values {
            registry::set_value(handle, &name, value_type, data);
        }
        registry::close_handle(handle);
    }
    Ok(())
}

/// CmInitSystem1 / CmpInitializeHiveList: a hive SYSTEM do arquivo do
/// volume em `\Registry\Machine\SYSTEM`; sem ele, as chaves estáticas em
/// memória.
pub fn initialize_system_hive() -> Result<(), crate::rtl::KernelError> {
    for master in ["\\Registry\\Machine", "\\Registry\\User"] {
        let handle = registry::open_or_create(master, None)?;
        registry::close_handle(handle);
    }
    match load(SYSTEM_MOUNT, SYSTEM_FILE, 0) {
        0 => {
            SYSTEM_FROM_FILE.store(true, Ordering::Release);
            crate::debug_print!("[cm] hive SYSTEM carregada de {}", SYSTEM_FILE);
            Ok(())
        }
        status => {
            crate::debug_print!("[cm] hive SYSTEM sem arquivo ({:#x}); chaves estaticas semeadas em memoria", status);
            seed_system_in_memory()
        }
    }
}
