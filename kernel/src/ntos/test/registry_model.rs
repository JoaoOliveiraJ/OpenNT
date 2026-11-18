//! Autoteste do modelo de hives do Configuration Manager, chamado pela fase
//! 5 depois das hives de arquivo (`registry_hive`):
//! - o `CurrentControlSet` como link volátil para `ControlSet001`
//!   (`Select\Current` = 1) e os links do Registro (REG_OPTION_CREATE_LINK,
//!   OBJ_OPENLINK, o `SymbolicLinkValue`, ciclo e link sem alvo, o
//!   KEY_SYM_LINK na célula, o `SECURITY\SAM` do volume);
//! - as hives de máquina do volume (SOFTWARE, SAM, SECURITY, DEFAULT), a
//!   HARDWARE volátil e a lista de hives (`Control\hivelist`);
//! - o escritor preguiçoso (descarga sem NtFlushKey, REG_NO_LAZY_FLUSH) e o
//!   REG_REFRESH_HIVE;
//! - as hives de aplicativo (REG_APP_HIVE) e o REG_LOAD_HIVE_OPEN_HANDLE;
//! - o REG_WHOLE_HIVE_VOLATILE;
//! - o CmRegisterCallback legado, os contextos de objeto, a identidade da
//!   chave e as notificações dos serviços de hive.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::phase6::call_export;
use super::registry_hive::{attributes, create_file, load, open, read_volume, status, u32_at, unload, SOURCE};
use crate::ntos::cm::hive::key_cells;
use crate::ntos::cm::key::services::{self as key_services, fields, Kind};
use crate::ntos::cm::key::objects as key_objects;
use crate::ntos::cm::registry;
use crate::ntos::cm::{callbacks, hive_init, hive_list, lazy_flush, seed};
use crate::ntos::inc::types::{CmKeyBody, KeyNameInformation, LargeInteger, NtStruct, ObjectAttributes, UnicodeString};
use crate::ntos::io::file::zw as zw_files;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

type Assert = fn(bool, &str);

const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_CANNOT_DELETE: u32 = 0xC000_0121;
const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
const STATUS_INVALID_PARAMETER_7: u32 = 0xC000_00F5;
const KEY_READ: u64 = 0x2_0019;
const KEY_ALL_ACCESS: u32 = 0xF_003F;
const HIVE_LIST: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\hivelist";

/// UTF-16LE sem NUL (o dado de um REG_LINK).
fn link_data(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn wide_text(data: &[u8]) -> alloc::string::String {
    let units: Vec<u16> = data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
    alloc::string::String::from_utf16_lossy(&units)
}

/// NtOpenKey/NtCreateKey de modo kernel com os atributos e as opções:
/// (status, handle).
fn open_with(path: &str, root: u64, object_attributes: u32, create: bool, options: u32) -> (u32, u64) {
    let block = attributes(path);
    // SAFETY: OBJECT_ATTRIBUTES de `attributes`.
    let object = unsafe { ObjectAttributes::at(block) };
    object.attributes.set(object_attributes);
    object.root_directory.set(root);
    let output = guest::alloc_bytes(16);
    let result = if create { key_services::create(output, KEY_ALL_ACCESS, block, 0, 0, options, output + 8, false) } else { key_services::open(output, KEY_ALL_ACCESS, block, false, options) };
    let handle = guest::read64(output);
    guest::free_bytes(output);
    guest::free_bytes(block);
    match result {
        Ok(0) => (0, handle),
        Ok(status) => (status, 0),
        Err(_) => (0xC000_0001, 0),
    }
}

fn close(handle: u64) {
    if handle != 0 {
        registry::close_handle(handle as u32);
    }
}

/// O KeyNameInformation de um handle.
fn key_name(handle: u64) -> alloc::string::String {
    let buffer = guest::alloc_bytes(0x400);
    let returned = guest::alloc_bytes(8);
    let result = key_services::key_operation(Kind::QueryKey, handle, &fields(&[("klass", 3), ("out", buffer), ("length", 0x400), ("returned", returned)]), false);
    // SAFETY: KEY_NAME_INFORMATION no bloco próprio.
    let information = unsafe { KeyNameInformation::at(buffer) };
    let name = if matches!(result, Ok(0)) { wide_text(&guest::read_bytes(information.name[0].address(), information.name_length.get() as usize)) } else { alloc::string::String::new() };
    guest::free_bytes(buffer);
    guest::free_bytes(returned);
    name
}

fn control_set_link(assert: Assert) {
    let select = registry::read_value_by_path("\\Registry\\Machine\\SYSTEM\\Select", "Current");
    assert(select.is_some_and(|value| value.value_type == 4 && value.data == [1, 0, 0, 0]), "cmmodel: SYSTEM\\Select\\Current = 1 na hive do volume");
    // OBJ_OPENLINK (0x100) abre o próprio link.
    let (opened, link) = open_with("\\Registry\\Machine\\System\\CurrentControlSet", 0, 0x340, false, 0);
    let node = registry::get_node(link as u32);
    let shape = node.and_then(|node| registry::with_node(node, |key| (key.link, key.volatile, key.cell.is_none(), key.value("symboliclinkvalue").cloned())));
    let expected = link_data("\\Registry\\Machine\\SYSTEM\\ControlSet001");
    assert(opened == 0 && shape.as_ref().is_some_and(|(is_link, volatile, no_cell, value)| *is_link && *volatile && *no_cell && value.as_ref().is_some_and(|value| value.value_type == 6 && value.data == expected)), "cmmodel: CurrentControlSet e link volatil com SymbolicLinkValue REG_LINK = \\Registry\\Machine\\SYSTEM\\ControlSet001 sem NUL");
    close(link);
    let through = registry::node_by_path("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\disk");
    let real = registry::node_by_path("\\Registry\\Machine\\System\\ControlSet001\\Services\\disk");
    assert(through.is_some() && through == real, "cmmodel: CurrentControlSet\\Services\\disk resolve para ControlSet001\\Services\\disk");
    let (opened, services) = open_with("\\Registry\\Machine\\System\\CurrentControlSet\\Services", 0, 0x240, false, 0);
    let name = key_name(services);
    close(services);
    assert(opened == 0 && name.eq_ignore_ascii_case("\\Registry\\Machine\\SYSTEM\\ControlSet001\\Services"), "cmmodel: KeyNameInformation de uma chave aberta pelo link e o nome real (ControlSet001)");
    let in_file = registry::node_by_path("\\Registry\\Machine\\System").and_then(registry::hive_of).and_then(|(identifier, _)| registry::with_storage(identifier, |storage| (key_cells::find_child(storage, storage.root_cell(), "CurrentControlSet").is_none(), key_cells::find_child(storage, storage.root_cell(), "ControlSet001").is_some())));
    assert(in_file == Some((true, true)), "cmmodel: a hive SYSTEM do volume guarda ControlSet001 e nao o link volatil");
}

fn symbolic_links(assert: Assert) {
    const LINK: &str = "\\Registry\\Machine\\Software\\OpenNTLink";
    let target = "\\Registry\\Machine\\Software\\Microsoft";
    let (created, link) = open_with(LINK, 0, 0x240, true, 2);
    assert(created == 0 && link != 0, "cmmodel: NtCreateKey com REG_OPTION_CREATE_LINK");
    let refused = key_services::named_value(Kind::Set, link, "Outro", 1, &seed::wide("x")).map(|(status, _)| status);
    let wrong_type = key_services::named_value(Kind::Set, link, "SymbolicLinkValue", 1, &link_data(target)).map(|(status, _)| status);
    let set = key_services::named_value(Kind::Set, link, "SymbolicLinkValue", 6, &link_data(target)).map(|(status, _)| status);
    assert(matches!(refused, Ok(STATUS_ACCESS_DENIED)) && matches!(wrong_type, Ok(STATUS_ACCESS_DENIED)) && matches!(set, Ok(0)), "cmmodel: numa chave de link so cabe o SymbolicLinkValue REG_LINK (o resto e STATUS_ACCESS_DENIED)");
    let link_node = registry::get_node(link as u32);
    close(link);
    let followed = registry::node_by_path(&alloc::format!("{LINK}\\Windows NT\\CurrentVersion"));
    assert(followed.is_some() && followed == registry::node_by_path(&alloc::format!("{target}\\Windows NT\\CurrentVersion")), "cmmodel: um link no meio do caminho troca o prefixo pelo alvo");
    let (plain, opened_target) = open_with(LINK, 0, 0x240, false, 0);
    let (with_openlink, opened_link) = open_with(LINK, 0, 0x340, false, 0);
    assert(plain == 0 && registry::get_node(opened_target as u32) == registry::node_by_path(target) && with_openlink == 0 && registry::get_node(opened_link as u32) == link_node, "cmmodel: o ultimo componente de link e seguido salvo com OBJ_OPENLINK");
    close(opened_target);
    let (again, _) = open_with(LINK, 0, 0x240, true, 2);
    let (existing, _) = open_with(target, 0, 0x240, true, 2);
    assert(again == STATUS_OBJECT_NAME_COLLISION && existing == STATUS_OBJECT_NAME_COLLISION, "cmmodel: REG_OPTION_CREATE_LINK sobre chave existente = STATUS_OBJECT_NAME_COLLISION");
    let flagged = link_node.and_then(registry::hive_of).and_then(|(identifier, _)| registry::with_storage(identifier, |storage| key_cells::find_child(storage, storage.root_cell(), "OpenNTLink").and_then(|cell| key_cells::node(storage, cell)).is_some_and(|node| node.flags.get() & key_cells::KEY_SYM_LINK != 0)));
    assert(flagged == Some(true), "cmmodel: o link nao volatil da SOFTWARE tem KEY_SYM_LINK na celula 'nk'");
    // Um link para ele mesmo e um link sem alvo.
    let (_, loop_link) = open_with("\\Registry\\Machine\\Software\\OpenNTLoop", 0, 0x240, true, 3);
    let _ = key_services::named_value(Kind::Set, loop_link, "SymbolicLinkValue", 6, &link_data("\\Registry\\Machine\\Software\\OpenNTLoop"));
    let (_, empty_link) = open_with("\\Registry\\Machine\\Software\\OpenNTSemAlvo", 0, 0x240, true, 3);
    let (cycle, _) = open_with("\\Registry\\Machine\\Software\\OpenNTLoop", 0, 0x240, false, 0);
    let (no_target, _) = open_with("\\Registry\\Machine\\Software\\OpenNTSemAlvo\\Filho", 0, 0x240, false, 0);
    assert(cycle == STATUS_OBJECT_NAME_NOT_FOUND && no_target == STATUS_OBJECT_NAME_NOT_FOUND, "cmmodel: ciclo de links e link sem SymbolicLinkValue = STATUS_OBJECT_NAME_NOT_FOUND");
    for handle in [opened_link, loop_link, empty_link] {
        let deleted = key_services::key_operation(Kind::DeleteKey, handle, &fields(&[]), false);
        assert(matches!(deleted, Ok(0)), "cmmodel: o link aberto com OBJ_OPENLINK e excluido");
        close(handle);
    }
    // SECURITY\SAM do volume é o link para SAM\SAM, que a hive SAM de um
    // sistema novo ainda não tem (o samsrv cria o banco no primeiro boot):
    // criado o destino, o link resolve para ele.
    let through_link = "\\Registry\\Machine\\SECURITY\\SAM\\OpenNTTeste";
    let missing = registry::node_by_path(through_link).is_none() && registry::node_by_path("\\Registry\\Machine\\SAM\\SAM").is_none();
    let (created_root, sam_root) = open_with("\\Registry\\Machine\\SAM\\SAM", 0, 0x240, true, 0);
    let (created_child, child) = open_with("\\Registry\\Machine\\SAM\\SAM\\OpenNTTeste", 0, 0x240, true, 0);
    let resolved = registry::node_by_path(through_link);
    let same = resolved.is_some() && resolved == registry::node_by_path("\\Registry\\Machine\\SAM\\SAM\\OpenNTTeste");
    let mut deleted = true;
    for handle in [child, sam_root] {
        deleted &= matches!(key_services::key_operation(Kind::DeleteKey, handle, &fields(&[]), false), Ok(0));
        close(handle);
    }
    assert(missing && created_root == 0 && created_child == 0 && same && deleted && registry::node_by_path("\\Registry\\Machine\\SAM\\SAM").is_none(), "cmmodel: SECURITY\\SAM, link da hive do volume, resolve para SAM\\SAM quando o destino existe");
}

fn machine_hives(assert: Assert) {
    let mounts = ["\\REGISTRY\\MACHINE\\SYSTEM", "\\REGISTRY\\MACHINE\\SOFTWARE", "\\REGISTRY\\MACHINE\\SAM", "\\REGISTRY\\MACHINE\\SECURITY", "\\REGISTRY\\USER\\.DEFAULT"];
    let files = ["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"];
    for (mount, file) in mounts.iter().zip(files) {
        let root = registry::node_by_path(mount).and_then(registry::hive_of);
        assert(root.is_some_and(|(_, is_root)| is_root) && hive_init::hive_from_file(mount), "cmmodel: hive de maquina carregada de \\SystemRoot\\System32\\config");
        let listed = registry::read_value_by_path(HIVE_LIST, mount).map(|value| (value.value_type, wide_text(&value.data)));
        let suffix = alloc::format!("\\windows\\system32\\config\\{}", file.to_lowercase());
        assert(listed.as_ref().is_some_and(|(kind, name)| *kind == 1 && name.to_lowercase().ends_with(&suffix)), "cmmodel: a lista de hives leva o nome do arquivo de cada hive de maquina");
    }
    // CmpLinkKeyToHive: S-1-5-18 é link volátil para .Default.
    let (opened, system_user) = open_with("\\Registry\\User\\S-1-5-18", 0, 0x340, false, 0);
    let shape = registry::get_node(system_user as u32).and_then(|node| registry::with_node(node, |key| (key.link, key.volatile, key.value("symboliclinkvalue").cloned())));
    close(system_user);
    let expected = link_data("\\Registry\\User\\.Default");
    let followed = registry::node_by_path("\\Registry\\User\\S-1-5-18");
    assert(opened == 0 && shape.is_some_and(|(is_link, volatile, value)| is_link && volatile && value.is_some_and(|value| value.value_type == 6 && value.data == expected)) && followed.is_some() && followed == registry::node_by_path("\\Registry\\User\\.Default"), "cmmodel: \\Registry\\User\\S-1-5-18 e link volatil para \\Registry\\User\\.Default");
    hardware_profiles(assert);
    let hardware = registry::node_by_path("\\Registry\\Machine\\Hardware");
    let volatile = hardware.is_some_and(|node| registry::hive_of(node).is_some_and(|(_, root)| root) && hive_list::is_volatile_hive(node));
    let listed = registry::read_value_by_path(HIVE_LIST, "\\REGISTRY\\MACHINE\\HARDWARE");
    assert(volatile && listed.is_some_and(|value| value.value_type == 1 && value.data == [0, 0]), "cmmodel: HARDWARE e uma hive volatil, com a entrada vazia na lista de hives");
    let described = registry::node_by_path("\\Registry\\Machine\\Hardware\\Description\\System\\CentralProcessor\\0").and_then(|node| registry::with_node(node, |key| key.cell.is_some()));
    assert(described == Some(true), "cmmodel: a descricao do hardware vive em celulas da hive HARDWARE");
    let list_volatile = registry::node_by_path(HIVE_LIST).and_then(|node| registry::with_node(node, |key| key.volatile));
    assert(list_volatile == Some(true), "cmmodel: Control\\hivelist e volatil");
    let software = registry::read_value_by_path("\\Registry\\Machine\\Software\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Strong Cryptographic Provider", "Type");
    let ifeo = registry::node_by_path("\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options").and_then(registry::hive_of);
    assert(software.is_some_and(|value| value.data == [1, 0, 0, 0]) && ifeo.is_some(), "cmmodel: a SOFTWARE do volume traz os CSPs e as Image File Execution Options");
}

/// CmpCreateHardwareProfiles: `Hardware Profiles\Current` é link volátil
/// para o perfil de `Control\IDConfigDB\CurrentConfig`. Uma SYSTEM sem o
/// IDConfigDB (a hive das tabelas de semente) recebe chaves voláteis de
/// teste com o perfil 1, apagadas no fim.
fn hardware_profiles(assert: Assert) {
    const CONTROL_SET: &str = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet";
    let configuration = alloc::format!("{CONTROL_SET}\\Control\\IDConfigDB");
    let profiles = alloc::format!("{CONTROL_SET}\\Hardware Profiles");
    let seeded = registry::node_by_path(&configuration).is_none() && registry::node_by_path(&profiles).is_none();
    let mut created = Vec::new();
    if seeded {
        for path in [configuration.clone(), profiles.clone(), alloc::format!("{profiles}\\0001"), alloc::format!("{profiles}\\0001\\Software"), alloc::format!("{profiles}\\0001\\Software\\Fonts")] {
            created.push(open_with(&path, 0, 0x240, true, 1).1);
        }
        registry::set_value(created[0] as u32, "CurrentConfig", 4, 1u32.to_le_bytes().to_vec());
        registry::set_value(created[4] as u32, "LogPixels", 4, 96u32.to_le_bytes().to_vec());
        hive_init::create_hardware_profiles();
    }
    let profile = registry::read_value_by_path(&configuration, "CurrentConfig").filter(|value| value.value_type == 4 && value.data.len() >= 4).map(|value| u32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]]));
    let link = alloc::format!("{profiles}\\Current");
    let (opened, current) = open_with(&link, 0, 0x340, false, 0);
    let shape = registry::get_node(current as u32).and_then(|node| registry::with_node(node, |key| (key.link, key.volatile, key.value("symboliclinkvalue").cloned())));
    let expected = profile.map(|profile| link_data(&alloc::format!("{profiles}\\{profile:04}")));
    let followed = registry::node_by_path(&alloc::format!("{link}\\Software"));
    let target = profile.and_then(|profile| registry::node_by_path(&alloc::format!("{profiles}\\{profile:04}\\Software")));
    let linked = opened == 0 && shape.is_some_and(|(is_link, volatile, value)| is_link && volatile && value.is_some_and(|value| value.value_type == 6 && Some(&value.data) == expected.as_ref())) && followed.is_some() && followed == target;
    if seeded {
        let removed = registry::delete_key(current as u32);
        close(current);
        let mut deleted = removed;
        for handle in created.into_iter().rev() {
            deleted &= registry::delete_key(handle as u32);
            close(handle);
        }
        assert(linked && deleted && registry::node_by_path(&configuration).is_none() && registry::node_by_path(&profiles).is_none(), "cmmodel: Hardware Profiles\\Current e link volatil para o perfil de IDConfigDB\\CurrentConfig");
    } else {
        close(current);
        assert(linked, "cmmodel: Hardware Profiles\\Current e link volatil para o perfil de IDConfigDB\\CurrentConfig");
    }
}

/// Grava SOURCE num arquivo novo pelo ZwSaveKeyEx (REG_LATEST_FORMAT).
fn save_source(file: &str) -> bool {
    let source = open(SOURCE, false);
    let handle = create_file(file);
    let saved = status(call_export("ZwSaveKeyEx", &[source, handle, 2]));
    zw_files::close_file_entry(handle as u32);
    close(source);
    source != 0 && handle != 0 && saved == 0
}

/// Gira o pump do kernel até a condição ou o prazo.
fn wait_until(limit_ms: u64, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = crate::ntos::ke::clock::uptime_ms() + limit_ms;
    loop {
        if condition() {
            return true;
        }
        if crate::ntos::ke::clock::uptime_ms() >= deadline {
            return false;
        }
        crate::ntos::ke::dispatcher::pump_kernel();
    }
}

/// ZwLoadKeyEx(TargetKey, SourceFile, Flags, NULL, Event, DesiredAccess,
/// RootHandle, NULL): (status, *RootHandle).
fn load_ex(target: u64, file: &str, flags: u64, event: u64, root: bool) -> (u32, u64) {
    let source = attributes(file);
    let output = guest::alloc_bytes(8);
    let result = status(call_export("ZwLoadKeyEx", &[target, source, flags, 0, event, KEY_READ, if root { output } else { 0 }, 0]));
    let handle = guest::read64(output);
    guest::free_bytes(output);
    guest::free_bytes(source);
    (result, handle)
}

fn lazy_flusher_and_refresh(assert: Assert) {
    const LAZY: &str = "\\Registry\\Machine\\OpenNTHivePreguicosa";
    const STILL: &str = "\\Registry\\Machine\\OpenNTHiveSemPreguica";
    let saved = save_source("\\??\\D:\\opennt-hive-lazy.dat") && save_source("\\??\\D:\\opennt-hive-nolazy.dat");
    lazy_flush::enable(lazy_flush::HOLD_BOOT);
    let loaded = load(LAZY, "\\??\\D:\\opennt-hive-lazy.dat");
    let target = attributes(STILL);
    let (still_loaded, _) = load_ex(target, "\\??\\D:\\opennt-hive-nolazy.dat", hive_list::REG_NO_LAZY_FLUSH as u64, 0, false);
    guest::free_bytes(target);
    assert(saved && loaded == 0 && still_loaded == 0 && u32_at(&read_volume("/opennt-hive-lazy.dat"), 4) == 1, "cmmodel: copias carregadas para o escritor preguicoso (uma com REG_NO_LAZY_FLUSH)");
    // A mudança arma o escritor; sem NtFlushKey, a hive vai para o disco.
    let root = open(LAZY, false);
    let still = open(STILL, false);
    let passes = lazy_flush::passes();
    let changed = registry::set_value(root as u32, "Preguicoso", 4, 7u32.to_le_bytes().to_vec()) && registry::set_value(still as u32, "Retido", 4, 9u32.to_le_bytes().to_vec());
    let armed = lazy_flush::armed();
    lazy_flush::arm(true);
    let flushed = wait_until(20_000, || {
        let file = read_volume("/opennt-hive-lazy.dat");
        u32_at(&file, 4) >= 2 && u32_at(&file, 4) == u32_at(&file, 8) && file.windows(10).any(|window| window == b"Preguicoso")
    });
    assert(changed && armed && flushed && lazy_flush::passes() > passes, "cmmodel: a hive suja arma o escritor preguicoso, que a descarrega sem NtFlushKey");
    let untouched = read_volume("/opennt-hive-nolazy.dat");
    assert(u32_at(&untouched, 4) == 1 && !untouched.windows(6).any(|window| window == b"Retido"), "cmmodel: o escritor preguicoso pula a hive carregada com REG_NO_LAZY_FLUSH");
    // REG_REFRESH_HIVE: as mudanças desde a última descarga somem; o handle
    // de uma chave que continua existindo segue valendo.
    let child = open(&alloc::format!("{STILL}\\Filho"), false);
    let created = open(&alloc::format!("{STILL}\\NovaDescartada"), true);
    let refreshed = status(call_export("ZwRestoreKey", &[still, 0, 2]));
    let discarded = registry::read_value_by_path(STILL, "Retido").is_none() && registry::node_by_path(&alloc::format!("{STILL}\\NovaDescartada")).is_none();
    let child_alive = registry::get_node(child as u32).is_some() && registry::get_value(child as u32, "Cinco").is_some_and(|value| value.data == [5; 5]);
    assert(refreshed == 0 && discarded && child_alive && registry::get_node(created as u32).is_none(), "cmmodel: REG_REFRESH_HIVE volta a hive REG_NO_LAZY_FLUSH ao estado da ultima descarga");
    let lazy_refused = status(call_export("ZwRestoreKey", &[root, 0, 2]));
    let child_refused = status(call_export("ZwRestoreKey", &[child, 0, 2]));
    assert(lazy_refused == STATUS_INVALID_PARAMETER && child_refused == STATUS_INVALID_PARAMETER, "cmmodel: REG_REFRESH_HIVE sem REG_NO_LAZY_FLUSH ou fora da raiz = STATUS_INVALID_PARAMETER");
    // CmShutdownSystem: o escritor para e cada hive suja vai para o disco
    // na hora, inclusive a REG_NO_LAZY_FLUSH.
    let dirtied = registry::set_value(root as u32, "NoDesligamento", 4, 1u32.to_le_bytes().to_vec()) && registry::set_value(still as u32, "TambemNoDesligamento", 4, 2u32.to_le_bytes().to_vec());
    let shutdown = lazy_flush::shutdown();
    let contains = |path: &str, needle: &[u8]| read_volume(path).windows(needle.len()).any(|window| window == needle);
    let written = contains("/opennt-hive-lazy.dat", b"NoDesligamento") && contains("/opennt-hive-nolazy.dat", b"TambemNoDesligamento");
    let stopped = registry::set_value(root as u32, "DepoisDoDesligamento", 4, 3u32.to_le_bytes().to_vec()) && !lazy_flush::armed();
    lazy_flush::enable(lazy_flush::HOLD_DISABLED);
    assert(dirtied && shutdown == 0 && written && stopped, "cmmodel: o desligamento (CmShutdownSystem) para o escritor e descarrega todas as hives");
    for handle in [root, still, child, created] {
        close(handle);
    }
    assert(unload(LAZY) == 0 && unload(STILL) == 0, "cmmodel: descarga das copias do escritor preguicoso");
}

fn app_hives_and_open_handle(assert: Assert) {
    const FIRST: &str = "\\Registry\\A\\{6f70656e-6e74-4000-8000-000000000001}";
    const SECOND: &str = "\\Registry\\A\\{6f70656e-6e74-4000-8000-000000000002}";
    const FILE: &str = "\\??\\D:\\opennt-hive-app.dat";
    let saved = save_source(FILE);
    let target = attributes(FIRST);
    let (loaded, root) = load_ex(target, FILE, 0x10, 0, true);
    guest::free_bytes(target);
    let node = registry::node_by_path(FIRST);
    assert(saved && loaded == 0 && root != 0 && node.is_some() && registry::get_node(root as u32) == node, "cmmodel: ZwLoadKeyEx com REG_APP_HIVE carrega em \\Registry\\A e devolve o handle da raiz");
    let value = key_services::named_value(Kind::QueryValue, root, "Dword", 0, &[]);
    assert(matches!(value, Ok((0, Some(ref value))) if value.data == 0x1234_5678u32.to_le_bytes()), "cmmodel: a hive de aplicativo e lida pelo handle da raiz");
    let (absolute, _) = open_with(FIRST, 0, 0x240, false, 0);
    let (relative, child) = open_with("Filho", root, 0x240, false, 0);
    assert(absolute == STATUS_ACCESS_DENIED && relative == 0 && child != 0, "cmmodel: \\Registry\\A nao abre por nome, so relativo ao handle da hive de aplicativo");
    let target = attributes(SECOND);
    let (shared, second) = load_ex(target, FILE, 0x10, 0, true);
    guest::free_bytes(target);
    assert(shared == 0 && registry::get_node(second as u32) == node && registry::node_by_path(SECOND).is_none(), "cmmodel: o mesmo arquivo de novo devolve a hive de aplicativo ja carregada");
    assert(registry::read_value_by_path(HIVE_LIST, FIRST).is_none(), "cmmodel: a hive de aplicativo fica fora da lista de hives");
    close(child);
    close(root);
    let still = registry::node_by_path(FIRST).is_some();
    close(second);
    assert(still && registry::node_by_path(FIRST).is_none(), "cmmodel: a hive de aplicativo e descarregada no fechamento do ultimo handle");
    // Validações do REG_APP_HIVE.
    let target = attributes(FIRST);
    let (no_root, _) = load_ex(target, FILE, 0x10, 0, false);
    let (no_lazy, _) = load_ex(target, FILE, 0x14, 0, true);
    let parent = open("\\Registry\\Machine\\Software", false);
    // SAFETY: OBJECT_ATTRIBUTES de `attributes`.
    unsafe { ObjectAttributes::at(target) }.root_directory.set(parent);
    let (with_root, _) = load_ex(target, FILE, 0x10, 0, true);
    close(parent);
    guest::free_bytes(target);
    assert(no_root == STATUS_INVALID_PARAMETER_7 && no_lazy == STATUS_INVALID_PARAMETER_3 && with_root == STATUS_INVALID_PARAMETER_1, "cmmodel: REG_APP_HIVE sem RootHandle, com REG_NO_LAZY_FLUSH ou com RootDirectory e recusado");
    // REG_LOAD_HIVE_OPEN_HANDLE com evento: o handle da raiz e o evento
    // sinalizado na descarga.
    const MOUNTED: &str = "\\Registry\\Machine\\OpenNTHiveComHandle";
    let event_out = guest::alloc_bytes(8);
    let created = status(call_export("ZwCreateEvent", &[event_out, 0x1F_0003, 0, 0, 0]));
    let event = guest::read64(event_out);
    guest::free_bytes(event_out);
    let target = attributes(MOUNTED);
    let (refused, _) = load_ex(target, FILE, 0x800, 0, false);
    let (loaded, root) = load_ex(target, FILE, 0x800, event, true);
    guest::free_bytes(target);
    let rooted = registry::get_node(root as u32).is_some() && registry::get_node(root as u32) == registry::node_by_path(MOUNTED);
    let busy = unload(MOUNTED);
    close(root);
    let unloaded = unload(MOUNTED);
    let signaled = crate::ntos::io::file::request::event_reference(event, 0).is_ok_and(|mut reference| {
        let state = crate::ntos::ke::dispatcher::read_state(reference.pointer);
        reference.release();
        state == 1
    });
    let _ = call_export("ZwClose", &[event]);
    assert(created == 0 && refused == STATUS_INVALID_PARAMETER_7 && loaded == 0 && rooted && busy == STATUS_CANNOT_DELETE && unloaded == 0 && signaled, "cmmodel: REG_LOAD_HIVE_OPEN_HANDLE devolve a raiz e o evento da carga e sinalizado na descarga");
}

/// CmLoadAppKey com Allocate: o arquivo ausente vira uma hive nova e vazia
/// (FILE_OPEN_IF); numa carga só de leitura, STATUS_OBJECT_NAME_NOT_FOUND.
fn new_hive_from_missing_file(assert: Assert) {
    const MOUNT: &str = "\\Registry\\A\\{6f70656e-6e74-4000-8000-000000000003}";
    const FILE: &str = "\\??\\D:\\opennt-hive-nova.dat";
    let target = attributes(MOUNT);
    let (loaded, root) = load_ex(target, FILE, 0x10, 0, true);
    let node = registry::node_by_path(MOUNT);
    let empty = node.and_then(|node| registry::with_node(node, |key| key.children.is_empty() && key.values.is_empty() && key.name.eq_ignore_ascii_case("{6f70656e-6e74-4000-8000-000000000003}")));
    let file = read_volume("/opennt-hive-nova.dat");
    assert(loaded == 0 && root != 0 && registry::get_node(root as u32) == node && empty == Some(true) && file.len() >= 0x2000 && file[..4] == *b"regf", "cmmodel: NtLoadKeyEx de arquivo ausente cria a hive nova com a raiz vazia");
    close(root);
    let unloaded = registry::node_by_path(MOUNT).is_none();
    let (read_only, _) = load_ex(target, "\\??\\D:\\opennt-hive-ausente.dat", 0x2010, 0, true);
    guest::free_bytes(target);
    assert(unloaded && read_only == STATUS_OBJECT_NAME_NOT_FOUND, "cmmodel: a hive nova sai no fechamento da raiz; carga so de leitura de arquivo ausente = STATUS_OBJECT_NAME_NOT_FOUND");
}

fn whole_hive_volatile(assert: Assert) {
    let user = open("\\Registry\\User", false);
    let file = create_file("\\??\\D:\\opennt-hive-vol.dat");
    let source = open(SOURCE, false);
    let saved = status(call_export("ZwSaveKeyEx", &[source, file, 2]));
    let restored = status(call_export("ZwRestoreKey", &[user, file, 1]));
    let refused = status(call_export("ZwRestoreKey", &[source, file, 1]));
    zw_files::close_file_entry(file as u32);
    close(source);
    close(user);
    let mount = "\\Registry\\User\\OpenNTHiveFonte";
    let node = registry::node_by_path(mount);
    let volatile = node.is_some_and(hive_list::is_volatile_hive);
    let copied = registry::read_value_by_path(mount, "Dword").is_some_and(|value| value.data == 0x1234_5678u32.to_le_bytes()) && registry::node_by_path(&alloc::format!("{mount}\\Filho")).is_some();
    let listed = registry::read_value_by_path(HIVE_LIST, mount).is_some_and(|value| value.data == [0, 0]);
    assert(saved == 0 && restored == 0 && volatile && copied && listed, "cmmodel: REG_WHOLE_HIVE_VOLATILE liga a copia volatil da hive em \\Registry\\User\\<raiz>, com a entrada vazia na lista");
    assert(refused == STATUS_INVALID_PARAMETER, "cmmodel: REG_WHOLE_HIVE_VOLATILE numa chave de hive de arquivo = STATUS_INVALID_PARAMETER");
    assert(unload(mount) == 0 && registry::node_by_path(mount).is_none() && registry::read_value_by_path(HIVE_LIST, mount).is_none(), "cmmodel: a hive volatil sai do namespace e da lista na descarga");
}

static OBJECT_LOG: SpinLock<Vec<(u64, u64)>> = SpinLock::new(Vec::new());
static BLOCK_LOAD: AtomicU32 = AtomicU32::new(0);

/// Filtro de teste: a classe e o ObjectContext que ele recebe
/// (QueryValue pré e pós, fechamento pré e a limpeza de contexto).
extern "win64" fn object_logger(_context: u64, class: u64, information: u64) -> u64 {
    let object_context = match class {
        8 => guest::read64(information + 0x38),
        23 => guest::read64(information + 0x28),
        14 => guest::read64(information + 0x10),
        40 => guest::read64(information + 0x8),
        _ => 0,
    };
    OBJECT_LOG.lock().push((class, object_context));
    if class == 32 && BLOCK_LOAD.load(Ordering::SeqCst) != 0 {
        return STATUS_ACCESS_DENIED as u64;
    }
    0
}

extern "win64" fn quiet_filter(_context: u64, _class: u64, _information: u64) -> u64 {
    0
}

fn classes() -> Vec<u64> {
    OBJECT_LOG.lock().iter().map(|&(class, _)| class).collect()
}

fn callback_objects(assert: Assert) {
    let storage = guest::alloc_bytes(0x100);
    let (major, minor, cookie, quiet_cookie, old, id, name, second_id) = (storage, storage + 4, storage + 0x10, storage + 0x18, storage + 0x20, storage + 0x28, storage + 0x30, storage + 0x38);
    let _ = call_export("CmGetCallbackVersion", &[major, minor]);
    assert(guest::read32(major) == 1 && guest::read32(minor) == 1, "cmmodel: CmGetCallbackVersion devolve 1 e 1");
    let logger = object_logger as extern "win64" fn(u64, u64, u64) -> u64 as usize as u64;
    let quiet = quiet_filter as extern "win64" fn(u64, u64, u64) -> u64 as usize as u64;
    let registered = status(call_export("CmRegisterCallback", &[logger, 0x77, cookie]));
    let repeated = status(call_export("CmRegisterCallback", &[quiet, 0, quiet_cookie]));
    // SAFETY: LARGE_INTEGER do bloco próprio.
    let cookie_value = unsafe { LargeInteger::at(cookie) }.quad_part.get() as u64;
    assert(registered == 0 && repeated == 0 && callbacks::get(cookie_value).is_some_and(|(_, altitude, _, _)| altitude == callbacks::LEGACY_ALTITUDE), "cmmodel: CmRegisterCallback com a altitude legada 425000, repetida permitida");
    let handle = open(SOURCE, false);
    let body = key_objects::for_handle(handle as u32).unwrap_or(0);
    let first = status(call_export("CmSetCallbackObjectContext", &[body, cookie, 0x1234, old]));
    let first_old = guest::read64(old);
    let swapped = status(call_export("CmSetCallbackObjectContext", &[body, cookie, 0x5678, old]));
    let invalid_object = status(call_export("CmSetCallbackObjectContext", &[storage, cookie, 1, 0]));
    // SAFETY: LARGE_INTEGER no bloco próprio.
    unsafe { LargeInteger::at(storage + 0x40) }.quad_part.set(0x7FFF_FFFF);
    let invalid_cookie = status(call_export("CmSetCallbackObjectContext", &[body, storage + 0x40, 1, 0]));
    assert(first == 0 && first_old == 0 && swapped == 0 && guest::read64(old) == 0x1234 && invalid_object == STATUS_INVALID_PARAMETER_1 && invalid_cookie == STATUS_INVALID_PARAMETER_2, "cmmodel: CmSetCallbackObjectContext guarda, troca e valida objeto e cookie");
    OBJECT_LOG.lock().clear();
    let _ = key_services::named_value(Kind::QueryValue, handle, "Dword", 0, &[]);
    let seen = OBJECT_LOG.lock().clone();
    assert(seen.len() >= 2 && seen[0] == (8, 0x5678) && seen[1] == (23, 0x5678), "cmmodel: o ObjectContext do filtro vai nas notificacoes pre e pos sobre o objeto");
    // A identidade da chave e o nome.
    let other = open(SOURCE, false);
    let other_body = key_objects::for_handle(other as u32).unwrap_or(0);
    let got = status(call_export("CmCallbackGetKeyObjectID", &[cookie, body, id, name]));
    let got_other = status(call_export("CmCallbackGetKeyObjectID", &[cookie, other_body, second_id, 0]));
    // SAFETY: o UNICODE_STRING devolvido pelo export.
    let cached = (guest::read64(name) != 0).then(|| crate::ntos::rtl::guest_strings::read_unicode_string(unsafe { UnicodeString::at(guest::read64(name)) }.address())).unwrap_or_default();
    // SAFETY: o corpo vivo do handle.
    let kcb = unsafe { CmKeyBody::at(body) }.key_control_block.get();
    assert(got == 0 && got_other == 0 && guest::read64(id) == kcb && guest::read64(second_id) == kcb && cached.eq_ignore_ascii_case(SOURCE), "cmmodel: CmCallbackGetKeyObjectID da a mesma identidade para a mesma chave e o nome em cache");
    let got_ex = status(call_export("CmCallbackGetKeyObjectIDEx", &[cookie, body, id, name, 0]));
    let fresh = guest::read64(name);
    let copy = if fresh != 0 { crate::ntos::rtl::guest_strings::read_unicode_string(fresh) } else { alloc::string::String::new() };
    let _ = call_export("CmCallbackReleaseKeyObjectIDEx", &[fresh]);
    let bad_flags = status(call_export("CmCallbackGetKeyObjectIDEx", &[cookie, body, id, name, 1]));
    assert(got_ex == 0 && fresh != guest::read64(id) && copy.eq_ignore_ascii_case(SOURCE) && bad_flags == STATUS_INVALID_PARAMETER, "cmmodel: CmCallbackGetKeyObjectIDEx devolve uma copia do nome (Flags 0)");
    assert(call_export("CmGetBoundTransaction", &[cookie, body]) == Some(0), "cmmodel: CmGetBoundTransaction sem transacao devolve nulo");
    // O fechamento destrói o objeto: o contexto volta ao filtro.
    OBJECT_LOG.lock().clear();
    close(handle);
    let seen = OBJECT_LOG.lock().clone();
    assert(seen.first() == Some(&(14, 0x5678)) && seen.contains(&(40, 0x5678)), "cmmodel: a destruicao do objeto entrega RegNtCallbackObjectContextCleanup com o contexto");
    // A remoção da inscrição também devolve os contextos.
    let _ = call_export("CmSetCallbackObjectContext", &[other_body, cookie, 0x9ABC, 0]);
    // Notificações dos serviços de hive.
    let file = create_file("\\??\\D:\\opennt-hive-cb.dat");
    OBJECT_LOG.lock().clear();
    let flushed = status(call_export("ZwFlushKey", &[other]));
    let saved = status(call_export("ZwSaveKeyEx", &[other, file, 2]));
    zw_files::close_file_entry(file as u32);
    let loaded = load("\\Registry\\Machine\\OpenNTHiveFiltrada", "\\??\\D:\\opennt-hive-cb.dat");
    let unloaded = unload("\\Registry\\Machine\\OpenNTHiveFiltrada");
    let target = open("\\Registry\\Machine\\Software\\OpenNTHiveFiltradaDestino", true);
    let file = create_file("\\??\\D:\\opennt-hive-cb2.dat");
    let _ = call_export("ZwSaveKeyEx", &[other, file, 2]);
    let restored = status(call_export("ZwRestoreKey", &[target, file, 0]));
    zw_files::close_file_entry(file as u32);
    let order = classes();
    let expected = [30u64, 31, 43, 44, 32, 33, 34, 35];
    let in_order = order.windows(expected.len()).any(|window| window == expected);
    if !in_order || [flushed, saved, loaded, unloaded, restored].iter().any(|&status| status != 0) {
        crate::debug_print!("[cmmodel] classes {:?}; flush {:#x} save {:#x} load {:#x} unload {:#x} restore {:#x}", order, flushed, saved, loaded, unloaded, restored);
    }
    assert(flushed == 0 && saved == 0 && loaded == 0 && unloaded == 0 && restored == 0 && in_order && order.contains(&41) && order.contains(&42), "cmmodel: RegNtPre/Post Flush, Save, Load, UnLoad e RestoreKey chegam aos filtros");
    BLOCK_LOAD.store(1, Ordering::SeqCst);
    let blocked = load("\\Registry\\Machine\\OpenNTHiveFiltrada", "\\??\\D:\\opennt-hive-cb.dat");
    BLOCK_LOAD.store(0, Ordering::SeqCst);
    assert(blocked == STATUS_ACCESS_DENIED && registry::node_by_path("\\Registry\\Machine\\OpenNTHiveFiltrada").is_none(), "cmmodel: um RegNtPreLoadKey com erro bloqueia o ZwLoadKey");
    let _ = key_services::key_operation(Kind::DeleteKey, target, &fields(&[]), false);
    close(target);
    OBJECT_LOG.lock().clear();
    let removed = status(call_export("CmUnRegisterCallback", &[cookie_value]));
    let seen = OBJECT_LOG.lock().clone();
    // SAFETY: LARGE_INTEGER do bloco próprio.
    let quiet_value = unsafe { LargeInteger::at(quiet_cookie) }.quad_part.get() as u64;
    let removed_quiet = status(call_export("CmUnRegisterCallback", &[quiet_value]));
    close(other);
    assert(removed == 0 && removed_quiet == 0 && seen.contains(&(40, 0x9ABC)) && !callbacks::has(), "cmmodel: CmUnRegisterCallback entrega a limpeza dos contextos da inscricao");
    guest::free_bytes(storage);
}

pub fn run(assert: Assert) {
    control_set_link(assert);
    symbolic_links(assert);
    machine_hives(assert);
    lazy_flusher_and_refresh(assert);
    app_hives_and_open_handle(assert);
    new_hive_from_missing_file(assert);
    whole_hive_volatile(assert);
    callback_objects(assert);
}
