//! Autoteste das hives de usuário, chamado pela fase 5 depois do modelo de
//! hives (`registry_model`), no caminho do serviço de perfis:
//! - o NTUSER de um arquivo do volume em `\Registry\User\<SID>` pelo
//!   ZwLoadKeyEx com REG_LOAD_HIVE_OPEN_HANDLE (o handle da raiz), os logs
//!   `.LOG1`/`.LOG2` criados na carga, ocultos e de sistema;
//! - o `<SID>_Classes` de um arquivo ausente (a hive nova) pelo NtLoadKey3
//!   com o TrustClassKey da raiz do NTUSER e o evento da descarga, os
//!   parâmetros estendidos repetidos ou desconhecidos e o token de acesso ao
//!   arquivo (primário recusado; de impersonação, a abertura impersona e a
//!   thread volta ao estado anterior);
//! - os links entre hives: `Software\Classes` do NTUSER para o
//!   `<SID>_Classes` (mesma classe de confiança) abre; um link do NTUSER
//!   para uma hive confiável ou para uma hive de outra classe dá
//!   STATUS_ACCESS_DENIED; um link de uma hive confiável para o NTUSER abre;
//!   a classe pedida do modo usuário numa chave de hive confiável é
//!   STATUS_INVALID_PARAMETER, e do modo kernel deixa a hive confiável;
//! - leitura, escrita e ZwFlushKey do NTUSER; o ZwUnloadKeyEx sem evento com
//!   handle aberto (STATUS_PENDING, a hive congelada: STATUS_TOO_LATE para o
//!   ZwUnloadKey e para o REG_FORCE_UNLOAD, a descarga no último handle) e a
//!   carga de novo com os dados;
//! - a descarga de uma hive do boot (STATUS_ACCESS_DENIED), o primário vazio
//!   como hive nova e a hive de aplicativo REG_PROCESS_PRIVATE, que não se
//!   compartilha;
//! - NtQueryOpenSubKeys(Ex) numa hive com chaves abertas (a contagem com o
//!   corpo da própria referência, o PID e o nome de cada corpo, o buffer
//!   curto e os erros de parâmetro) e o logoff do serviço de perfis
//!   (NtUnloadKey recusado com chaves abertas, NtUnloadKey2 com
//!   REG_FORCE_UNLOAD, STATUS_KEY_DELETED no handle que sobrou);
//! - as regras da segunda tentativa do CmpCmdHiveOpen e a impersonação do
//!   próprio processo só durante a abertura;
//! - um `.LOG` antigo ao lado da hive não é aberto sem REG_HIVE_SINGLE_LOG.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::phase6::call_export;
use super::registry_hive::{attributes, create_file, open, read_volume, status, u32_at, SOURCE};
use crate::drivers::fs::{ntfs, volume::FileSystem};
use crate::ntos::cm::hive::base_block;
use crate::ntos::cm::key::services::{self as key_services, Kind};
use crate::ntos::cm::registry::{self, NodeId};
use crate::ntos::cm::{hive_file, hive_init, hive_list, hive_services};
use crate::ntos::inc::types::{KeyPidArray, NtStruct, ObjectAttributes};
use crate::ntos::io::file::zw as zw_files;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::process;
use crate::ntos::rtl::guest_strings;
use crate::ntos::se::token::thread as thread_tokens;

type Assert = fn(bool, &str);

const STATUS_PENDING: u32 = 0x103;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_SHARING_VIOLATION: u32 = 0xC000_0043;
const STATUS_BAD_TOKEN_TYPE: u32 = 0xC000_00A8;
const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;
const STATUS_TOO_LATE: u32 = 0xC000_0189;
const KEY_READ: u64 = 0x2_0019;
const KEY_ALL_ACCESS: u32 = 0xF_003F;
const REG_LOAD_HIVE_OPEN_HANDLE: u64 = 0x800;

/// Um SID de teste (domínio e RID inventados).
const USER: &str = "\\Registry\\User\\S-1-5-21-1000-2000-3000-1001";
const CLASSES: &str = "\\Registry\\User\\S-1-5-21-1000-2000-3000-1001_Classes";
const OTHER: &str = "\\Registry\\User\\OpenNTOutraClasse";
const NTUSER_FILE: &str = "\\??\\D:\\opennt-ntuser.dat";
const CLASSES_FILE: &str = "\\??\\D:\\opennt-usrclass.dat";
const OTHER_FILE: &str = "\\??\\D:\\opennt-outra.dat";

fn volume() -> Option<&'static dyn FileSystem> {
    ntfs::fixed().map(|volume| volume as &dyn FileSystem)
}

fn remove(path: &str) {
    if let Some(volume) = volume() {
        if volume.exists(path) {
            let _ = volume.remove(path);
        }
    }
}

fn file_attributes(path: &str) -> Option<u32> {
    volume().and_then(|volume| volume.stat(path)).map(|stat| stat.attributes)
}

/// UTF-16LE sem NUL (o dado de um REG_LINK).
fn link_data(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// NtOpenKey/NtCreateKey de modo kernel: (status, handle).
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

/// Um link volátil (REG_OPTION_CREATE_LINK | REG_OPTION_VOLATILE) para
/// `target`.
fn create_link(path: &str, target: &str) -> bool {
    let (created, link) = open_with(path, 0, 0x240, true, 3);
    let set = created == 0 && matches!(key_services::named_value(Kind::Set, link, "SymbolicLinkValue", 6, &link_data(target)), Ok((0, _)));
    close(link);
    set
}

/// O status da abertura de `path` (seguindo os links).
fn open_status(path: &str) -> u32 {
    let (status, handle) = open_with(path, 0, 0x240, false, 0);
    close(handle);
    status
}

/// ZwLoadKeyEx(Target, Source, Flags, TrustClassKey, NULL, KEY_READ,
/// &RootHandle?): (status, raiz).
fn load_ex(target: &str, file: &str, flags: u64, trust: u64, root: bool) -> (u32, u64) {
    let (target, source) = (attributes(target), attributes(file));
    let output = guest::alloc_bytes(8);
    guest::write64(output, 0);
    let result = status(call_export("ZwLoadKeyEx", &[target, source, flags, trust, 0, KEY_READ, if root { output } else { 0 }, 0]));
    let handle = guest::read64(output);
    for block in [target, source, output] {
        guest::free_bytes(block);
    }
    (result, handle)
}

/// NtLoadKey3 de modo kernel com os CM_EXTENDED_PARAMETER (tipo, valor):
/// (status, raiz).
fn load3(target: &str, file: &str, flags: u32, extended: &[(u64, u64)]) -> (u32, u64) {
    let (target, source) = (attributes(target), attributes(file));
    let array = guest::alloc_bytes(16 * extended.len().max(1) as u64);
    for (index, &(kind, value)) in extended.iter().enumerate() {
        guest::write64(array + index as u64 * 16, kind);
        guest::write64(array + index as u64 * 16 + 8, value);
    }
    let output = guest::alloc_bytes(8);
    guest::write64(output, 0);
    let result = hive_services::load_key3(target, source, flags, array, extended.len() as u32, KEY_READ as u32, output, false);
    let handle = guest::read64(output);
    for block in [target, source, array, output] {
        guest::free_bytes(block);
    }
    (result, handle)
}

fn unload_with(name: &str, target: &str, extra: &[u64]) -> u32 {
    let block = attributes(target);
    let mut arguments = alloc::vec![block];
    arguments.extend_from_slice(extra);
    let result = status(call_export(name, &arguments));
    guest::free_bytes(block);
    result
}

fn hive_identifier(path: &str) -> Option<u32> {
    registry::node_by_path(path).and_then(registry::hive_of).filter(|&(_, root)| root).map(|(identifier, _)| identifier)
}

/// O token primário do processo e uma cópia de impersonação
/// (SecurityImpersonation), em handles de kernel.
fn tokens() -> (u64, u64) {
    let block = guest::alloc_bytes(0x100);
    guest::write_bytes(block, &[0; 0x100]);
    let (primary_out, copy_out, object_attributes) = (block, block + 8, block + 0x40);
    // SAFETY: OBJECT_ATTRIBUTES no bloco próprio.
    let object = unsafe { ObjectAttributes::at(object_attributes) };
    object.length.set(ObjectAttributes::SIZE as u32);
    object.attributes.set(0x200);
    // SECURITY_QUALITY_OF_SERVICE: Length 12, SecurityImpersonation.
    let quality = block + 0x90;
    guest::write32(quality, 12);
    guest::write32(quality + 4, 2);
    object.security_quality_of_service.set(quality);
    let opened = call_export("ZwOpenProcessTokenEx", &[u64::MAX, 0xF01FF, 0x200, primary_out]);
    let primary = if opened == Some(0) { guest::read64(primary_out) } else { 0 };
    let duplicated = if primary != 0 { call_export("ZwDuplicateToken", &[primary, 0xF01FF, object_attributes, 0, 2, copy_out]) } else { None };
    let copy = if duplicated == Some(0) { guest::read64(copy_out) } else { 0 };
    guest::free_bytes(block);
    (primary, copy)
}

/// A fonte gravada num arquivo pelo ZwSaveKeyEx (REG_LATEST_FORMAT).
fn save_source(file: &str) -> bool {
    let source = open(SOURCE, false);
    let handle = create_file(file);
    let saved = status(call_export("ZwSaveKeyEx", &[source, handle, 2]));
    zw_files::close_file_entry(handle as u32);
    close(source);
    source != 0 && handle != 0 && saved == 0
}

fn mount_user_hives(assert: Assert) -> (u64, u64) {
    for path in ["/opennt-ntuser.dat", "/opennt-ntuser.dat.LOG1", "/opennt-ntuser.dat.LOG2", "/opennt-usrclass.dat", "/opennt-usrclass.dat.LOG1", "/opennt-usrclass.dat.LOG2"] {
        remove(path);
    }
    let saved = save_source(NTUSER_FILE);
    let (loaded, root) = load_ex(USER, NTUSER_FILE, REG_LOAD_HIVE_OPEN_HANDLE, 0, true);
    let user = hive_identifier(USER);
    assert(saved && loaded == 0 && root != 0 && registry::get_node(root as u32) == registry::node_by_path(USER) && user.is_some(), "userhive: ZwLoadKeyEx com REG_LOAD_HIVE_OPEN_HANDLE liga o NTUSER do volume em \\Registry\\User\\<SID> e devolve a raiz");
    let hidden_system = |path: &str| file_attributes(path).is_some_and(|attributes| attributes & 6 == 6);
    assert(hidden_system("/opennt-ntuser.dat.LOG1") && hidden_system("/opennt-ntuser.dat.LOG2"), "userhive: a carga cria o .LOG1 e o .LOG2 ocultos e de sistema");
    assert(user.and_then(registry::trust_class) == user, "userhive: a hive do NtLoadKey e nao confiavel, na propria classe de confianca");
    // ZwQueryKey(KeyTrustInformation): o bit 0 do CMHIVE.Flags que o
    // CmpLoadKeyCommon liga aparece como TrustedKey = 0.
    let key = open(USER, false);
    let trust = guest::alloc_bytes(8);
    guest::write32(trust, 0xFFFF_FFFF);
    let queried = status(call_export("ZwQueryKey", &[key, 8, trust, 4, trust + 4]));
    close(key);
    assert(queried == 0 && guest::read32(trust) == 0xFFFF_FFFE && guest::read32(trust + 4) == 4, "userhive: ZwQueryKey(KeyTrustInformation) na hive do NtLoadKey desliga TrustedKey");
    // NtLoadKey3: parâmetros estendidos repetidos ou desconhecidos.
    let (repeated, _) = load3(CLASSES, CLASSES_FILE, 0x800, &[(1, root), (1, root)]);
    let (unknown, _) = load3(CLASSES, CLASSES_FILE, 0x800, &[(7, 0)]);
    assert(repeated == STATUS_INVALID_PARAMETER_4 && unknown == STATUS_INVALID_PARAMETER_4 && registry::node_by_path(CLASSES).is_none(), "userhive: NtLoadKey3 com parametro estendido repetido ou desconhecido = STATUS_INVALID_PARAMETER_4");
    // O token de acesso ao arquivo: o primário é recusado; o de
    // impersonação abre o arquivo impersonando e a thread volta ao que era.
    let (primary, impersonation) = tokens();
    let (bad_token, _) = load3(CLASSES, CLASSES_FILE, 0x800, &[(3, primary)]);
    assert(primary != 0 && bad_token == STATUS_BAD_TOKEN_TYPE, "userhive: NtLoadKey3 com token primario = STATUS_BAD_TOKEN_TYPE");
    // UsrClass ausente: a hive nova, na classe do NTUSER.
    let thread = process::get_current_thread();
    let before = thread_tokens::get(thread).map(|state| state.token);
    let (classes_loaded, classes_root) = load3(CLASSES, CLASSES_FILE, 0x800, &[(1, root), (3, impersonation)]);
    let restored = thread_tokens::get(thread).map(|state| state.token) == before;
    let classes = hive_identifier(CLASSES);
    let empty = registry::node_by_path(CLASSES).and_then(|node| registry::with_node(node, |key| key.subkey_count() == 0)).unwrap_or(false);
    assert(impersonation != 0 && classes_loaded == 0 && classes_root != 0 && restored && empty && read_volume("/opennt-usrclass.dat").get(..4) == Some(&b"regf"[..]), "userhive: NtLoadKey3 cria o UsrClass ausente em <SID>_Classes com o token de impersonacao e devolve a raiz");
    assert(classes.is_some() && classes.and_then(registry::trust_class) == user, "userhive: o TrustClassKey poe o <SID>_Classes na classe de confianca do NTUSER");
    let _ = call_export("ZwClose", &[impersonation]);
    let _ = call_export("ZwClose", &[primary]);
    (root, classes_root)
}

fn trust_class_links(assert: Assert) {
    // O link Software\Classes do NTUSER para o <SID>_Classes.
    let software = open(&alloc::format!("{USER}\\Software"), true);
    close(software);
    let extension = open(&alloc::format!("{CLASSES}\\.txt"), true);
    close(extension);
    let linked = create_link(&alloc::format!("{USER}\\Software\\Classes"), CLASSES);
    let through = registry::node_by_path(&alloc::format!("{USER}\\Software\\Classes\\.txt"));
    assert(linked && open_status(&alloc::format!("{USER}\\Software\\Classes\\.txt")) == 0 && through.is_some() && through == registry::node_by_path(&alloc::format!("{CLASSES}\\.txt")), "userhive: o link Software\\Classes do NTUSER leva ao <SID>_Classes da mesma classe");
    // Do NTUSER para uma hive confiável: recusado.
    let machine = create_link(&alloc::format!("{USER}\\Software\\Maquina"), "\\Registry\\Machine\\System\\Select");
    assert(machine && open_status(&alloc::format!("{USER}\\Software\\Maquina")) == STATUS_ACCESS_DENIED, "userhive: um link do NTUSER para uma hive confiavel = STATUS_ACCESS_DENIED");
    // Do NTUSER para uma hive de outra classe: recusado.
    let other_saved = save_source(OTHER_FILE);
    let (other_loaded, _) = load_ex(OTHER, OTHER_FILE, 0, 0, false);
    let other = create_link(&alloc::format!("{USER}\\Software\\Outra"), OTHER);
    assert(other_saved && other_loaded == 0 && other && open_status(&alloc::format!("{USER}\\Software\\Outra\\Filho")) == STATUS_ACCESS_DENIED, "userhive: um link do NTUSER para uma hive de outra classe = STATUS_ACCESS_DENIED");
    // De uma chave confiável para o NTUSER: aberto.
    let trusted = create_link("\\Registry\\Machine\\Software\\OpenNTLinkPerfil", &alloc::format!("{USER}\\Software"));
    assert(trusted && open_status("\\Registry\\Machine\\Software\\OpenNTLinkPerfil\\Classes\\.txt") == 0, "userhive: um link de chave confiavel para o NTUSER abre, inclusive seguindo o link do NTUSER");
    // A própria chave de link, com OBJ_OPENLINK, abre sem seguir.
    let (openlink, link) = open_with(&alloc::format!("{USER}\\Software\\Maquina"), 0, 0x340, false, 0);
    close(link);
    assert(openlink == 0 && link != 0, "userhive: OBJ_OPENLINK abre a chave de link sem seguir");
    let (opened, handle) = open_with("\\Registry\\Machine\\Software\\OpenNTLinkPerfil", 0, 0x340, false, 0);
    if opened == 0 {
        let _ = call_export("ZwDeleteKey", &[handle]);
    }
    close(handle);
    let unloaded = unload_with("ZwUnloadKey", OTHER, &[]);
    // A classe pedida do modo usuário numa chave de hive confiável (o
    // arquivo já está livre: a recusa vem depois da abertura).
    let select: Option<NodeId> = registry::node_by_path("\\Registry\\Machine\\System\\Select");
    let refused = hive_list::load_hive("\\Registry\\User\\OpenNTClasseRecusada", OTHER_FILE, hive_list::LoadRequest { trust: select, previous_mode: true, ..hive_list::LoadRequest::default() });
    assert(refused == Err(STATUS_INVALID_PARAMETER) && registry::node_by_path("\\Registry\\User\\OpenNTClasseRecusada").is_none(), "userhive: do modo usuario, TrustClassKey de hive confiavel = STATUS_INVALID_PARAMETER sem carga");
    // Do modo kernel, a chave de hive confiável deixa a hive confiável.
    let anchor = open("\\Registry\\Machine\\System\\Select", false);
    let (kernel_trusted, _) = load_ex(OTHER, OTHER_FILE, 0, anchor, false);
    close(anchor);
    let trusted_hive = hive_identifier(OTHER);
    assert(unloaded == 0 && kernel_trusted == 0 && trusted_hive.is_some() && trusted_hive.and_then(registry::trust_class).is_none(), "userhive: do modo kernel, TrustClassKey de hive confiavel deixa a hive nova confiavel");
    assert(unload_with("ZwUnloadKey", OTHER, &[]) == 0, "userhive: ZwUnloadKey da hive de outra classe");
}

fn write_flush_unload_reload(assert: Assert, root: u64, classes_root: u64) {
    let settings = open(&alloc::format!("{USER}\\Software\\OpenNT"), true);
    let written = settings != 0 && registry::set_value(settings as u32, "Persistido", 4, 0x0102_0304u32.to_le_bytes().to_vec());
    let read = registry::read_value_by_path(&alloc::format!("{USER}\\Software\\OpenNT"), "Persistido").is_some_and(|value| value.data == 0x0102_0304u32.to_le_bytes());
    let flushed = status(call_export("ZwFlushKey", &[settings]));
    close(settings);
    let file = read_volume("/opennt-ntuser.dat");
    let header = file.len() >= 0x1000 && u32_at(&file, 4) == u32_at(&file, 8) && u32_at(&file, 4) >= 2 && u32_at(&file, 0x1fc) == base_block::checksum_bytes(&file) && file.windows(10).any(|window| window == b"Persistido");
    let log = read_volume("/opennt-ntuser.dat.LOG1");
    assert(written && read && flushed == 0 && header && log.len() > 0x200 && u32_at(&log, 0x200) == 0x454C_7648, "userhive: valor gravado no NTUSER, lido e descarregado pelo ZwFlushKey no primario e no .LOG1");
    // O <SID>_Classes sai antes do NTUSER, como no perfil.
    close(classes_root);
    assert(unload_with("ZwUnloadKey", CLASSES, &[]) == 0 && registry::node_by_path(CLASSES).is_none(), "userhive: ZwUnloadKey do <SID>_Classes sem handles");
    // ZwUnloadKeyEx sem evento com a raiz aberta: a hive congela.
    let pending = unload_with("ZwUnloadKeyEx", USER, &[0]);
    let late = unload_with("ZwUnloadKey", USER, &[]);
    let forced = unload_with("ZwUnloadKey2", USER, &[1]);
    let still = registry::node_by_path(USER).is_some();
    close(root);
    let gone = registry::node_by_path(USER).is_none();
    assert(pending == STATUS_PENDING && late == STATUS_TOO_LATE && forced == STATUS_TOO_LATE && still && gone, "userhive: ZwUnloadKeyEx sem evento congela a hive (STATUS_PENDING, STATUS_TOO_LATE ate com REG_FORCE_UNLOAD) e descarrega no ultimo handle");
    // A carga de novo: o valor ficou, o link volátil não.
    let (reloaded, _) = load_ex(USER, NTUSER_FILE, 0, 0, false);
    let kept = registry::read_value_by_path(&alloc::format!("{USER}\\Software\\OpenNT"), "Persistido").is_some_and(|value| value.data == 0x0102_0304u32.to_le_bytes());
    let link_gone = registry::node_by_path(&alloc::format!("{USER}\\Software\\Classes")).is_none();
    assert(reloaded == 0 && kept && link_gone, "userhive: a carga seguinte do NTUSER traz o valor descarregado, sem o link volatil");
    assert(unload_with("ZwUnloadKey", USER, &[]) == 0, "userhive: ZwUnloadKey do NTUSER");
}

fn boot_empty_and_private(assert: Assert) {
    // Uma hive do boot não se descarrega.
    if hive_init::hive_from_file("\\REGISTRY\\MACHINE\\SOFTWARE") {
        assert(unload_with("ZwUnloadKey", "\\Registry\\Machine\\Software", &[]) == STATUS_ACCESS_DENIED, "userhive: ZwUnloadKey de uma hive do boot = STATUS_ACCESS_DENIED");
    }
    // Um primário vazio é uma hive nova.
    const EMPTY: &str = "\\Registry\\User\\OpenNTHiveVazia";
    let empty_file = create_file("\\??\\D:\\opennt-hive-vazia.dat");
    zw_files::close_file_entry(empty_file as u32);
    let (loaded, _) = load_ex(EMPTY, "\\??\\D:\\opennt-hive-vazia.dat", 0, 0, false);
    let fresh = registry::node_by_path(EMPTY).and_then(|node| registry::with_node(node, |key| key.subkey_count() == 0 && key.value_count() == 0)).unwrap_or(false);
    let image = read_volume("/opennt-hive-vazia.dat");
    assert(empty_file != 0 && loaded == 0 && fresh && image.get(..4) == Some(&b"regf"[..]), "userhive: um primario vazio carrega como hive nova");
    assert(unload_with("ZwUnloadKey", EMPTY, &[]) == 0, "userhive: ZwUnloadKey da hive nova");
    // REG_PROCESS_PRIVATE: a hive de aplicativo não se compartilha.
    const PRIVATE: &str = "\\Registry\\A\\{6f70656e-6e74-4000-8000-000000000010}";
    const SHARED: &str = "\\Registry\\A\\{6f70656e-6e74-4000-8000-000000000011}";
    const FILE: &str = "\\??\\D:\\opennt-hive-privada.dat";
    let saved = save_source(FILE);
    let (private, private_root) = load_ex(PRIVATE, FILE, 0x30, 0, true);
    let (refused, _) = load_ex(SHARED, FILE, 0x10, 0, true);
    close(private_root);
    let gone = registry::node_by_path(PRIVATE).is_none();
    let (shared, shared_root) = load_ex(SHARED, FILE, 0x10, 0, true);
    let (private_again, _) = load_ex(PRIVATE, FILE, 0x30, 0, true);
    close(shared_root);
    assert(saved && private == 0 && refused == STATUS_SHARING_VIOLATION && gone && shared == 0 && private_again == STATUS_SHARING_VIOLATION && registry::node_by_path(SHARED).is_none(), "userhive: hive de aplicativo REG_PROCESS_PRIVATE nao e compartilhada nem compartilha o arquivo de outra");
}

/// As entradas do KEY_OPEN_SUBKEYS_INFORMATION: (PID, nome, Length ==
/// MaximumLength, o nome dentro da área de nomes do buffer).
fn open_sub_key_entries(buffer: u64, length: u64) -> Vec<(u64, String, bool, bool)> {
    let count = guest::read32(buffer) as u64;
    (0..count)
        .map(|index| {
            // SAFETY: entrada escrita pelo serviço no buffer próprio.
            let entry = unsafe { KeyPidArray::at(buffer + 8 + index * 0x18) };
            let (name_length, maximum, pointer) = (entry.key_name.length.get(), entry.key_name.maximum_length.get(), entry.key_name.buffer.get());
            let inside = pointer >= buffer + 8 + count * 0x18 && pointer + name_length as u64 <= buffer + length;
            (entry.process_id.get(), guest_strings::read_unicode_string(entry.key_name.address()), name_length == maximum, inside)
        })
        .collect()
}

/// NtQueryOpenSubKeys(Ex) numa hive de usuário com chaves abertas, e o
/// logoff do serviço de perfis: NtUnloadKey recusado com chaves abertas,
/// NtUnloadKey2(REG_FORCE_UNLOAD), e o handle que sobrou dando
/// STATUS_KEY_DELETED.
fn open_sub_keys_and_logoff(assert: Assert) {
    const HIVE: &str = "\\Registry\\User\\S-1-5-21-1000-2000-3000-1002";
    const FILE: &str = "\\??\\D:\\opennt-chaves-abertas.dat";
    for path in ["/opennt-chaves-abertas.dat", "/opennt-chaves-abertas.dat.LOG1", "/opennt-chaves-abertas.dat.LOG2"] {
        remove(path);
    }
    let saved = save_source(FILE);
    let (loaded, root) = load_ex(HIVE, FILE, REG_LOAD_HIVE_OPEN_HANDLE, 0, true);
    let child = open(&alloc::format!("{HIVE}\\Aberta"), true);
    let grandchild = open(&alloc::format!("{HIVE}\\Aberta\\Funda"), true);
    let target = attributes(HIVE);
    let block = guest::alloc_bytes(0x410);
    let (buffer, required) = (block, block + 0x400);
    // NtQueryOpenSubKeys: os três corpos e o da própria referência por nome.
    let counted = hive_services::query_open_sub_keys(target, required, false);
    assert(saved && loaded == 0 && root != 0 && child != 0 && grandchild != 0 && counted == 0 && guest::read32(required) == 4, "hiverest: NtQueryOpenSubKeys conta os corpos de chave abertos na hive mais o da propria referencia");
    // NtQueryOpenSubKeysEx: PID e nome de cada corpo.
    let listed = hive_services::query_open_sub_keys_ex(target, 0x400, buffer, required, false);
    let entries = open_sub_key_entries(buffer, 0x400);
    let pid = process::get_current_process_id();
    let expected = [HIVE.to_string(), alloc::format!("{HIVE}\\Aberta"), alloc::format!("{HIVE}\\Aberta\\Funda")];
    let names = expected.iter().all(|name| entries.iter().any(|entry| entry.1.eq_ignore_ascii_case(name)));
    let size = 8 + entries.iter().map(|entry| 0x18 + entry.1.encode_utf16().count() as u32 * 2).sum::<u32>();
    assert(listed == 0 && entries.len() == 3 && names && entries.iter().all(|entry| entry.0 == pid && entry.2 && entry.3) && guest::read32(required) == size, "hiverest: NtQueryOpenSubKeysEx lista o PID e o nome de cada chave aberta, com o RequiredSize");
    // Buffer curto: STATUS_BUFFER_OVERFLOW, Count e RequiredSize completos,
    // nenhuma entrada escrita.
    guest::write_bytes(buffer, &[0xAA; 0x20]);
    let short = hive_services::query_open_sub_keys_ex(target, 0x20, buffer, required, false);
    assert(short == 0x8000_0005 && guest::read32(buffer) == 3 && guest::read32(required) == size && guest::read32(buffer + 8) == 0xAAAA_AAAA, "hiverest: NtQueryOpenSubKeysEx com buffer curto = STATUS_BUFFER_OVERFLOW, Count e RequiredSize completos");
    // Os erros de parâmetro.
    let small = hive_services::query_open_sub_keys_ex(target, 6, buffer, required, false);
    let odd = hive_services::query_open_sub_keys_ex(target, 0x41, buffer, required, false);
    let inner = attributes(&alloc::format!("{HIVE}\\Aberta"));
    let not_root = hive_services::query_open_sub_keys_ex(inner, 0x400, buffer, required, false);
    let not_root_count = hive_services::query_open_sub_keys(inner, required, false);
    guest::free_bytes(inner);
    assert(small == 0xC000_0023 && odd == STATUS_INVALID_PARAMETER && not_root == STATUS_INVALID_PARAMETER && not_root_count == STATUS_INVALID_PARAMETER, "hiverest: BufferLength < 8 = STATUS_BUFFER_TOO_SMALL, impar = STATUS_INVALID_PARAMETER, chave que nao e raiz de hive = STATUS_INVALID_PARAMETER");
    // O logoff: a raiz fechada (o UnmountRegHiveFromPath fecha o handle da
    // carga), NtUnloadKey recusado pelos handles que sobraram,
    // NtUnloadKey2(REG_FORCE_UNLOAD) descarrega e grava.
    close(root);
    let refused = unload_with("ZwUnloadKey", HIVE, &[]);
    let forced = unload_with("ZwUnloadKey2", HIVE, &[1]);
    let gone = registry::node_by_path(HIVE).is_none();
    let stale = status(call_export("ZwFlushKey", &[child]));
    close(grandchild);
    close(child);
    guest::free_bytes(block);
    guest::free_bytes(target);
    let (reloaded, _) = load_ex(HIVE, FILE, 0, 0, false);
    let kept = registry::node_by_path(&alloc::format!("{HIVE}\\Aberta\\Funda")).is_some();
    assert(refused == 0xC000_0121 && forced == 0 && gone && stale == 0xC000_017C && reloaded == 0 && kept && unload_with("ZwUnloadKey", HIVE, &[]) == 0, "hiverest: logoff do perfil: NtUnloadKey com chaves abertas = STATUS_CANNOT_DELETE, NtUnloadKey2(REG_FORCE_UNLOAD) descarrega e grava, o handle que sobrou da STATUS_KEY_DELETED");
}

/// O CmpCmdHiveOpen: quais status e cargas repetem a abertura como o
/// próprio processo, e a impersonação da thread de volta depois.
fn hive_open_fallbacks(assert: Assert) {
    let retried = [0xC000_0022, 0xC000_0064, 0xC000_006A, 0xC000_006E, 0xC000_0072, 0xC000_0193].iter().all(|&status| hive_list::impersonation_fallback_status(status));
    let kept = [STATUS_SHARING_VIOLATION, 0xC000_0034, 0xC000_014D].iter().all(|&status| !hive_list::impersonation_fallback_status(status));
    assert(retried && kept, "hiverest: o CmpCmdHiveOpen repete so por acesso negado ou falha de conta");
    let allowed = hive_list::impersonation_fallback_allowed(0x800, false) && hive_list::impersonation_fallback_allowed(0x8800, false) && hive_list::impersonation_fallback_allowed(0x10, false);
    let refused = !hive_list::impersonation_fallback_allowed(0x8800, true) && !hive_list::impersonation_fallback_allowed(0x8010, false);
    assert(allowed && refused, "hiverest: a segunda tentativa so sem token; REG_NO_IMPERSONATION_FALLBACK so vale na hive de aplicativo");
    // RtlImpersonateSelfEx: dentro, uma cópia de impersonação do primário;
    // depois, o estado anterior da thread.
    let thread = process::get_current_thread();
    let before = thread_tokens::get(thread).map(|state| state.token);
    let inside = hive_file::impersonating_self(|| Ok(thread_tokens::get(thread).map(|state| (state.token, state.level))));
    let after = thread_tokens::get(thread).map(|state| state.token);
    assert(matches!(inside, Ok(Some((token, 2))) if Some(token) != before) && after == before, "hiverest: a impersonacao do proprio processo vale so durante a abertura");
}

/// Um `.LOG` antigo ao lado do primário: sem REG_HIVE_SINGLE_LOG a carga
/// usa o `.LOG1`/`.LOG2` e não abre nem muda o `.LOG` (o comportamento de
/// hoje, guardado contra regressão).
fn legacy_log_ignored(assert: Assert) {
    const HIVE: &str = "\\Registry\\User\\OpenNTLogLegado";
    const FILE: &str = "\\??\\D:\\opennt-log-legado.dat";
    for path in ["/opennt-log-legado.dat", "/opennt-log-legado.dat.LOG", "/opennt-log-legado.dat.LOG1", "/opennt-log-legado.dat.LOG2"] {
        remove(path);
    }
    let saved = save_source(FILE);
    let legacy = create_file("\\??\\D:\\opennt-log-legado.dat.LOG");
    zw_files::close_file_entry(legacy as u32);
    let wrote = volume().is_some_and(|volume| matches!(volume.write_at("/opennt-log-legado.dat.LOG", 0, b"DIRTlixo"), Ok(8)));
    let (loaded, _) = load_ex(HIVE, FILE, 0, 0, false);
    let untouched = read_volume("/opennt-log-legado.dat.LOG") == b"DIRTlixo";
    let dual = file_attributes("/opennt-log-legado.dat.LOG1").is_some() && file_attributes("/opennt-log-legado.dat.LOG2").is_some();
    assert(saved && legacy != 0 && wrote && loaded == 0 && untouched && dual && unload_with("ZwUnloadKey", HIVE, &[]) == 0, "hiverest: sem REG_HIVE_SINGLE_LOG a carga usa .LOG1/.LOG2 e nao abre o .LOG antigo");
}

pub fn run(assert: Assert) {
    if ntfs::mounted().is_none() {
        assert(false, "userhive: volume NTFS montado para os arquivos de hive");
        return;
    }
    let (root, classes_root) = mount_user_hives(assert);
    trust_class_links(assert);
    write_flush_unload_reload(assert, root, classes_root);
    boot_empty_and_private(assert);
    open_sub_keys_and_logoff(assert);
    hive_open_fallbacks(assert);
    legacy_log_ignored(assert);
    // read_only_primary (Q-HIVEREST §6.3) só entra com o P1 de io/file/zw.rs
    // e o CmpOpenFileWithExtremePrejudice.
}
