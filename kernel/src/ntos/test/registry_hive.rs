//! Autoteste das hives de arquivo (formato regf), chamado pela fase 5.
//!
//! - o formato contra vetores calculados pelo ntoskrnl real
//!   (HvpHeaderCheckSum, SymCryptMarvin32 com a semente das hives,
//!   CmpHashUnicodeComponent e CmpGenerateFastLeafHintForUnicodeString,
//!   emulados sobre a imagem 19041);
//! - a hive SYSTEM do boot veio do arquivo do volume, com cada chave e valor
//!   das tabelas de semente e os descritores da política do kernel;
//! - ida e volta: chaves e valores de todos os tipos (dado vazio, no campo
//!   Data, numa célula e em 'db'), nome fora de Latin-1, descritor próprio e
//!   chave volátil, ZwSaveKeyEx para um arquivo e ZwLoadKey dele em outro
//!   lugar; o formato padrão (1.3, 'lf', dado grande numa célula só);
//! - descarga: mudanças na hive carregada, ZwFlushKey (primário com as
//!   sequências 2/2 e o log com a entrada 'HvLE' íntegra), descarga
//!   recusada com handle aberto, ZwUnloadKey e a carga de novo com as
//!   mudanças; recuperação de um primário invalidado pelo log;
//! - restauração (ZwRestoreKey), compressão (NtCompressKey marca
//!   LastReorganizeTime e a carga seguinte reorganiza), descarga adiada do
//!   ZwUnloadKeyEx, a notificação de hive de máquina numa carga real;
//! - privilégios (SeRestorePrivilege/SeBackupPrivilege pelo PreviousMode de
//!   usuário) e as validações de parâmetros dos serviços;
//! - a classe de uma chave (o Class do ZwCreateKey): a célula de classe na
//!   hive, o ClassOffset e o ClassLength do KeyNodeInformation e do
//!   KeyFullInformation (o layout do CmpPopulateKeyNodeInformation e do
//!   CmpPopulateKeyFullInformation do 19041), o MaxClassLen do pai e o
//!   Length ímpar recusado;
//! - o heap de uma hive carregada: uma hive de 4041 chaves ocupa no máximo
//!   [`HEAP_PER_KEY`] bytes de heap por chave (o conteúdo fica nas células,
//!   sem cópia decodificada), as chaves criadas e excluídas saem da arena e
//!   do heap, e a descarga devolve os nós e o heap da hive.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::phase6::call_export;
use crate::drivers::fs::{ntfs, volume::FileSystem};
use crate::ntos::cm::hive::{base_block, index, key_cells, log, tree};
use crate::ntos::cm::key::{policy, services as key_services};
use crate::ntos::cm::registry::{self, NodeId};
use crate::ntos::cm::{hive_init, seed};
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::HbaseBlock;
use crate::ntos::inc::types::{IoStatusBlock, NtStruct, ObjectAttributes, UnicodeString};
use crate::ntos::io::file::zw as zw_files;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::se::inherit_descriptor::Captured;

type Assert = fn(bool, &str);

const STATUS_PENDING: u32 = 0x103;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_CANNOT_DELETE: u32 = 0xC000_0121;
const STATUS_REGISTRY_CORRUPT: u32 = 0xC000_014C;
const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;

pub(super) fn status(result: Option<u64>) -> u32 {
    result.map_or(0xFFFF_FFFF, |value| value as u32)
}

/// OBJECT_ATTRIBUTES (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE) com o nome,
/// numa alocação nova.
pub(super) fn attributes(name: &str) -> u64 {
    let units: Vec<u16> = name.encode_utf16().collect();
    let block = guest::alloc_bytes(0x80 + units.len() as u64 * 2 + 2);
    guest::write_bytes(block, &[0u8; 0x80]);
    guest::write_bytes(block + 0x80, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    // SAFETY: bloco próprio recém-alocado.
    let string = unsafe { UnicodeString::at(block + 0x40) };
    string.length.set(units.len() as u16 * 2);
    string.maximum_length.set(units.len() as u16 * 2);
    string.buffer.set(block + 0x80);
    // SAFETY: idem.
    let object = unsafe { ObjectAttributes::at(block) };
    object.length.set(ObjectAttributes::SIZE as u32);
    object.object_name.set(block + 0x40);
    object.attributes.set(0x240);
    block
}

/// ZwCreateFile com FILE_OVERWRITE_IF: um handle de kernel para o arquivo.
pub(super) fn create_file(name: &str) -> u64 {
    let oa = attributes(name);
    let block = guest::alloc_bytes(0x20);
    let _ = zw_files::create_kernel_file(block, 0x0012_019F, oa, block + 8, 0, 5, 0x60);
    // SAFETY: IO_STATUS_BLOCK no bloco próprio.
    let ok = unsafe { IoStatusBlock::at(block + 8) }.status.get() == 0;
    let handle = if ok { guest::read64(block) } else { 0 };
    guest::free_bytes(block);
    guest::free_bytes(oa);
    handle
}

pub(super) fn load(target: &str, file: &str) -> u32 {
    let (target, file) = (attributes(target), attributes(file));
    let result = status(call_export("ZwLoadKey", &[target, file]));
    guest::free_bytes(target);
    guest::free_bytes(file);
    result
}

pub(super) fn unload(target: &str) -> u32 {
    let target = attributes(target);
    let result = status(call_export("ZwUnloadKey", &[target]));
    guest::free_bytes(target);
    result
}

pub(super) fn open(path: &str, create: bool) -> u64 {
    key_services::open_path(path, create).map_or(0, |(status, handle)| if status == 0 { handle } else { 0 })
}

fn wide(text: &str) -> Vec<u8> {
    seed::wide(text)
}

/// As duas árvores têm os mesmos nomes de subchaves, valores, descritores e
/// LastWriteTime.
fn same_tree(left: NodeId, right: NodeId, check_root_name: bool) -> bool {
    let mut pending = alloc::vec![(left, right, check_root_name)];
    while let Some((left, right, check_name)) = pending.pop() {
        let snapshot = |node| {
            let (name, values, security, time, children) = registry::with_node(node, |key| (key.name().to_lowercase(), key.values().iter().map(|value| (value.name.to_lowercase(), (value.value_type, value.data.clone()))).collect::<BTreeMap<_, _>>(), Captured::clone(&key.security), key.last_write_time(), key.children.iter().map(|&(_, child)| child).collect::<Vec<_>>()))?;
            let children = children.into_iter().filter_map(|child| registry::with_node(child, |key| (key.name().to_lowercase(), child))).collect::<BTreeMap<_, _>>();
            Some((name, values, security, time, children))
        };
        let (Some(a), Some(b)) = (snapshot(left), snapshot(right)) else { return false };
        if (check_name && a.0 != b.0) || a.1 != b.1 || a.2 != b.2 || a.3 != b.3 || a.4.len() != b.4.len() {
            return false;
        }
        for (name, child) in &a.4 {
            let Some(other) = b.4.get(name) else { return false };
            pending.push((*child, *other, true));
        }
    }
    true
}

fn format_vectors(assert: Assert) {
    // HvpHeaderCheckSum (rva 0x723b98) sobre blocos montados aqui.
    let page = guest::alloc_bytes(0x1000);
    guest::write_bytes(page, &[0u8; 0x1000]);
    // SAFETY: página própria de 0x1000 bytes.
    let block = unsafe { HbaseBlock::at(page) };
    let zero = base_block::checksum(block);
    // SAFETY: o primeiro DWORD da página.
    unsafe { Field::<u32>::at(page) }.set(0xFFFF_FFFF);
    let ones = base_block::checksum(block);
    block.signature.set(0x6667_6572);
    block.sequence1.set(7);
    block.sequence2.set(7);
    block.time_stamp.quad_part.set(0x01DB_0000_0000_0000);
    let filled = base_block::checksum(block);
    guest::free_bytes(page);
    assert(zero == 1 && ones == 0xFFFF_FFFE && filled == 0x67BC_6572, "hive: HvpHeaderCheckSum (0 vira 1, 0xFFFFFFFF vira 0xFFFFFFFE, bloco com regf e sequencias)");
    // SymCryptMarvin32 com a semente das hives (rva 0x3eb528).
    let sequence: Vec<u8> = (0..32).collect();
    assert(log::marvin32(b"") == 0xB39E_FCA4_0396_6E08 && log::marvin32(b"OpenNT") == 0x726E_9F19_D74A_EDBC && log::marvin32(&sequence) == 0xC64F_EEE4_25C2_E24C, "hive: Marvin32 dos logs igual ao do ntoskrnl");
    // Hash de 'lh' e dica de 'lf' (rva 0x6e2f34 e 0x692dd4).
    let units = |text: &str| text.encode_utf16().collect::<Vec<u16>>();
    assert(index::hash(&units("Services")) == 0x227A_F730 && index::hash(&units("ControlSet001")) == 0x8F3B_A9A2 && index::hash(&units("OpenNT")) == 0x4FAD_1454 && index::hint(&units("Services")) == 0x7672_6553 && index::hint(&units("OpenNT")) == 0x6E65_704F, "hive: hash de lh e dica de lf iguais aos do ntoskrnl");
}

fn system_hive_from_file(assert: Assert) {
    let root = registry::node_by_path("\\Registry\\Machine\\System");
    let hive = root.and_then(registry::hive_of);
    assert(hive_init::system_hive_from_file() && hive.is_some_and(|(_, is_root)| is_root), "hive: \\Registry\\Machine\\SYSTEM carregada de \\SystemRoot\\System32\\config\\SYSTEM");
    let Some((identifier, _)) = hive else { return };
    let mut complete = true;
    for key in seed::system_keys(crate::ntos::init::boot_config::smss_boot()) {
        let path = alloc::format!("\\Registry\\Machine\\System\\{}", key.path);
        for (name, value_type, data) in key.values {
            let matches = registry::read_value_by_path(&path, &name).is_some_and(|value| value.value_type == value_type && value.data == data);
            if !matches {
                debug_print!("[hive] valor da semente ausente ou diferente: {}\\{}", path, name);
            }
            complete &= matches;
        }
    }
    assert(complete, "hive: cada valor das tabelas de semente esta na hive SYSTEM do arquivo");
    let expected = policy::boot_child(&policy::boot_root()).ok();
    let disk = registry::node_by_path("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\disk");
    let descriptors = [root, disk].iter().all(|node| node.and_then(|node| registry::with_node(node, |key| Captured::clone(&key.security))) == expected);
    assert(descriptors, "hive: descritores da hive SYSTEM iguais aos da politica do kernel");
    let layout = registry::with_storage(identifier, |storage| {
        let root_cell = storage.root_cell();
        let services = key_cells::find_child(storage, root_cell, "ControlSet001").and_then(|cell| key_cells::find_child(storage, cell, "Services"));
        let list = services.and_then(|cell| key_cells::node(storage, cell)).map(|node| node.sub_key_lists[0].get());
        storage.minor() == 5 && list.and_then(|list| index::signature(storage, list)) == Some(index::LH) && !storage.broken
    });
    assert(layout == Some(true), "hive: SYSTEM na versao 1.5 com listas lh");
    // ZwFlushKey numa chave da SYSTEM grava o arquivo do volume.
    let key = open("\\Registry\\Machine\\System\\OpenNTHiveDescarga", true);
    let written = key != 0 && registry::set_value(key as u32, "ValorDescarregado", 4, 0x0BAD_F00Du32.to_le_bytes().to_vec());
    let flushed = status(call_export("ZwFlushKey", &[key]));
    let file = read_volume("/Windows/System32/config/SYSTEM");
    let contains = |needle: &[u8]| file.windows(needle.len()).any(|window| window == needle);
    let valid = file.len() >= 0x1000 && u32_at(&file, 4) == u32_at(&file, 8) && u32_at(&file, 4) >= 2 && u32_at(&file, 0x1fc) == base_block::checksum_bytes(&file);
    let logged = [read_volume("/Windows/System32/config/SYSTEM.LOG1"), read_volume("/Windows/System32/config/SYSTEM.LOG2")].iter().any(|log| log.len() >= 0x200 && u32_at(log, 0) == 0x6667_6572 && u32_at(log, 0x1c) == 6);
    assert(written && flushed == 0 && valid && contains(b"OpenNTHiveDescarga") && contains(b"ValorDescarregado") && logged, "hive: ZwFlushKey de uma chave da SYSTEM grava o primario validado e o log no volume");
    let deleted = registry::delete_key(key as u32);
    registry::close_handle(key as u32);
    assert(deleted, "hive: exclusao da chave de teste da SYSTEM");
}

/// Descritor próprio: owner e group SYSTEM, DACL com SYSTEM e Everyone de
/// leitura.
fn custom_descriptor() -> Captured {
    let system = alloc::vec![1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let mut acl = alloc::vec![2u8, 0, 0x30, 0, 2, 0, 0, 0];
    acl.extend_from_slice(&[0, 0, 0x14, 0, 0x3F, 0, 0x0F, 0]);
    acl.extend_from_slice(&system);
    acl.extend_from_slice(&[0, 0, 0x14, 0, 0x19, 0, 0x02, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]);
    Captured { control: 0x0004, owner: system.clone(), group: system, dacl: Some(acl), sacl: None }
}

pub(super) const SOURCE: &str = "\\Registry\\Machine\\Software\\OpenNTHiveFonte";
const COPY: &str = "\\Registry\\Machine\\OpenNTHiveCopia";
const COPY_FILE: &str = "\\??\\D:\\opennt-hive-rt.dat";

/// A árvore de origem: valores de todos os tipos, dados de 0, 4, 5 e 40000
/// bytes, um nome fora de Latin-1, um descritor próprio e uma chave volátil.
fn build_source() -> bool {
    let root = open(SOURCE, true);
    let big: Vec<u8> = (0..40_000u32).map(|index| (index * 7 + 3) as u8).collect();
    let values: [(&str, u32, Vec<u8>); 13] = [
        ("Nenhum", 0, alloc::vec![1, 2, 3]),
        ("Texto", 1, wide("OpenNT")),
        ("Expansivel", 2, wide("%SystemRoot%\\x")),
        ("Binario", 3, alloc::vec![0xAA; 5]),
        ("Dword", 4, 0x1234_5678u32.to_le_bytes().to_vec()),
        ("DwordBE", 5, 0x1234_5678u32.to_be_bytes().to_vec()),
        ("Link", 6, wide("\\Registry\\Machine")),
        ("Multi", 7, seed::multi(&["um", "dois"])),
        ("Recursos", 8, alloc::vec![0x11; 24]),
        ("Descritor", 9, alloc::vec![0x22; 32]),
        ("Requisitos", 10, alloc::vec![0x33; 48]),
        ("Qword", 11, 0x0102_0304_0506_0708u64.to_le_bytes().to_vec()),
        ("", 1, wide("padrao")),
    ];
    let mut ok = root != 0;
    for (name, value_type, data) in values {
        ok &= registry::set_value(root as u32, name, value_type, data);
    }
    ok &= registry::set_value(root as u32, "Vazio", 3, Vec::new());
    ok &= registry::set_value(root as u32, "Grande", 3, big);
    let child = registry::open_or_create(&alloc::format!("{SOURCE}\\Filho"), Some(custom_descriptor())).unwrap_or(0);
    ok &= child != 0 && registry::set_value(child, "Cinco", 3, alloc::vec![5; 5]);
    let grandchild = open(&alloc::format!("{SOURCE}\\Filho\\Neto"), true);
    let unicode = open(&alloc::format!("{SOURCE}\\Ключ"), true);
    ok &= unicode != 0 && registry::set_value(unicode as u32, "Значение", 4, 7u32.to_le_bytes().to_vec());
    let volatile = registry::open_or_create_options(&alloc::format!("{SOURCE}\\Volatil"), None, true).unwrap_or(0);
    ok &= grandchild != 0 && volatile != 0;
    for handle in [root, child as u64, grandchild, unicode, volatile as u64] {
        registry::close_handle(handle as u32);
    }
    ok
}

fn save_load_round_trip(assert: Assert) {
    assert(build_source(), "hive: arvore de origem com valores de todos os tipos");
    let source = open(SOURCE, false);
    let file = create_file(COPY_FILE);
    let saved = status(call_export("ZwSaveKeyEx", &[source, file, 2]));
    zw_files::close_file_entry(file as u32);
    assert(file != 0 && saved == 0, "hive: ZwSaveKeyEx (REG_LATEST_FORMAT) grava a subarvore num arquivo");
    let loaded = load(COPY, COPY_FILE);
    let (source_node, copy_node) = (registry::node_by_path(SOURCE), registry::node_by_path(COPY));
    let volatile_absent = registry::node_by_path(&alloc::format!("{COPY}\\Volatil")).is_none();
    let unique_volatile = registry::node_by_path(&alloc::format!("{SOURCE}\\Volatil")).inspect(|&node| {
        // A comparação ignora a chave volátil da origem.
        let path = alloc::format!("{SOURCE}\\Volatil");
        registry::delete_node(node, &path);
    });
    assert(loaded == 0 && volatile_absent && unique_volatile.is_some() && source_node.zip(copy_node).is_some_and(|(left, right)| same_tree(left, right, false)), "hive: ZwLoadKey da copia traz as mesmas chaves, valores, descritores e LastWriteTime, sem a chave volatil");
    let Some((identifier, true)) = copy_node.and_then(registry::hive_of) else {
        assert(false, "hive: a copia e raiz de uma hive de arquivo");
        registry::close_handle(source as u32);
        return;
    };
    let layout = registry::with_storage(identifier, |storage| {
        let root = storage.root_cell();
        let big = key_cells::value_layout(storage, root, "Grande").is_some_and(|(length, cell)| length == 40_000 && key_cells::data_signature(storage, cell) == Some(key_cells::DB));
        let inline = key_cells::value_layout(storage, root, "Dword") == Some((0x8000_0004, 0x1234_5678));
        let empty = key_cells::value_layout(storage, root, "Vazio").is_some_and(|(length, _)| length == 0x8000_0000);
        let unicode = key_cells::find_child(storage, root, "Ключ").and_then(|cell| key_cells::node(storage, cell)).is_some_and(|node| node.flags.get() & key_cells::KEY_COMP_NAME == 0);
        let compressed = key_cells::find_child(storage, root, "Filho").and_then(|cell| key_cells::node(storage, cell)).is_some_and(|node| node.flags.get() & key_cells::KEY_COMP_NAME != 0);
        let root_flags = key_cells::node(storage, root).is_some_and(|node| node.flags.get() & (key_cells::KEY_HIVE_ENTRY | key_cells::KEY_NO_DELETE) == (key_cells::KEY_HIVE_ENTRY | key_cells::KEY_NO_DELETE));
        // Contagem da 'sk' da raiz e da do Filho (descritor próprio).
        let count = |cell: Option<u32>| cell.and_then(|cell| key_cells::node(storage, cell)).and_then(|node| crate::ntos::cm::hive::security_cells::reference_count(storage, node.security.get()));
        (storage.minor() == 5, big, inline, empty, unicode && compressed, root_flags, count(Some(root)), count(key_cells::find_child(storage, root, "Filho")))
    });
    assert(layout.is_some_and(|layout| layout.0 && layout.1 && layout.2 && layout.3 && layout.4 && layout.5), "hive: versao 1.5, dado grande em db, ate 4 bytes no campo Data, nome Unicode sem KEY_COMP_NAME e raiz KEY_HIVE_ENTRY|KEY_NO_DELETE");
    // Cada descritor distinto numa 'sk' com a contagem das chaves que o usam.
    let mut descriptors: Vec<(Captured, u32)> = Vec::new();
    let mut stack = copy_node.map_or(Vec::new(), |node| alloc::vec![node]);
    while let Some(node) = stack.pop() {
        if let Some((security, children)) = registry::with_node(node, |key| (Captured::clone(&key.security), key.children.iter().map(|&(_, child)| child).collect::<Vec<_>>())) {
            match descriptors.iter_mut().find(|(known, _)| *known == security) {
                Some(entry) => entry.1 += 1,
                None => descriptors.push((security, 1)),
            }
            stack.extend(children);
        }
    }
    let expected = |name: &str| registry::node_by_path(name).and_then(|node| registry::with_node(node, |key| Captured::clone(&key.security))).and_then(|security| descriptors.iter().find(|(known, _)| *known == security).map(|&(_, count)| count));
    assert(layout.is_some_and(|layout| layout.6.is_some() && layout.6 == expected(COPY) && layout.7 == expected(&alloc::format!("{COPY}\\Filho"))), "hive: celulas sk compartilhadas com a contagem de referencias das chaves");
    // REG_STANDARD_FORMAT: versão 1.3, 'lf' e o dado grande numa célula só.
    let standard = create_file("\\??\\D:\\opennt-hive-std.dat");
    let saved = status(call_export("ZwSaveKey", &[source, standard]));
    zw_files::close_file_entry(standard as u32);
    let loaded = load("\\Registry\\Machine\\OpenNTHivePadrao", "\\??\\D:\\opennt-hive-std.dat");
    let layout = registry::node_by_path("\\Registry\\Machine\\OpenNTHivePadrao").and_then(registry::hive_of).and_then(|(identifier, _)| {
        registry::with_storage(identifier, |storage| {
            let root = storage.root_cell();
            let list = key_cells::node(storage, root).map(|node| node.sub_key_lists[0].get());
            let single = key_cells::value_layout(storage, root, "Grande").is_some_and(|(length, cell)| length == 40_000 && key_cells::data_signature(storage, cell) != Some(key_cells::DB) && storage.cell_size(cell).is_some_and(|size| size >= 40_004));
            storage.minor() == 3 && list.and_then(|list| index::signature(storage, list)) == Some(index::LF) && single
        })
    });
    let same = registry::node_by_path(SOURCE).zip(registry::node_by_path("\\Registry\\Machine\\OpenNTHivePadrao")).is_some_and(|(left, right)| same_tree(left, right, false));
    assert(saved == 0 && loaded == 0 && layout == Some(true) && same, "hive: ZwSaveKey (REG_STANDARD_FORMAT) grava a versao 1.3 com lf e o dado grande numa celula");
    assert(unload("\\Registry\\Machine\\OpenNTHivePadrao") == 0, "hive: ZwUnloadKey da copia padrao");
    registry::close_handle(source as u32);
}

pub(super) fn read_volume(path: &str) -> Vec<u8> {
    ntfs::mounted().and_then(|volume| {
        let volume: &dyn FileSystem = volume.as_ref();
        volume.read_bytes(path)
    }).unwrap_or_default()
}

fn write_volume(path: &str, bytes: &[u8]) -> bool {
    ntfs::mounted().is_some_and(|volume| {
        let volume: &dyn FileSystem = volume.as_ref();
        volume.truncate(path).is_ok() && volume.write_at(path, 0, bytes).is_ok_and(|written| written == bytes.len() as u64)
    })
}

pub(super) fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    bytes.get(offset..offset + 4).map_or(0, |word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
}

fn flush_unload_reload(assert: Assert) {
    let before = read_volume("/opennt-hive-rt.dat");
    let handle = open(COPY, false);
    let changed = registry::set_value(handle as u32, "Persistido", 1, wide("sim")) && registry::delete_value(handle as u32, "Nenhum");
    let child = open(&alloc::format!("{COPY}\\NovoFilho"), true);
    let changed = changed && child != 0 && registry::set_value(child as u32, "Valor", 4, 9u32.to_le_bytes().to_vec());
    registry::close_handle(child as u32);
    let flushed = status(call_export("ZwFlushKey", &[handle]));
    let after = read_volume("/opennt-hive-rt.dat");
    let header_ok = after.len() >= 0x1000 && u32_at(&after, 4) == 2 && u32_at(&after, 8) == 2 && u32_at(&after, 0x1fc) == base_block::checksum_bytes(&after);
    assert(changed && flushed == 0 && u32_at(&before, 4) == 1 && header_ok, "hive: ZwFlushKey grava o primario e valida o bloco base com as sequencias 2/2");
    let log = read_volume("/opennt-hive-rt.dat.LOG1");
    let entry_size = u32_at(&log, 0x204) as usize;
    let entry_ok = log.len() >= 0x1000
        && u32_at(&log, 0) == 0x6667_6572
        && u32_at(&log, 0x1c) == 6
        && u32_at(&log, 4) == 1
        && u32_at(&log, 0x200) == 0x454C_7648
        && u32_at(&log, 0x20c) == 1
        && entry_size + 0x200 == log.len()
        && log::marvin32(&log[0x200..0x220]).to_le_bytes() == log[0x220..0x228]
        && log::marvin32(&log[0x228..0x200 + entry_size]).to_le_bytes() == log[0x218..0x220];
    assert(entry_ok, "hive: o .LOG1 leva o bloco base de log (tipo 6) e a entrada HvLE de sequencia 1 com os dois hashes");
    assert(unload(COPY) == STATUS_CANNOT_DELETE, "hive: ZwUnloadKey com handle aberto = STATUS_CANNOT_DELETE");
    registry::close_handle(handle as u32);
    let unloaded = unload(COPY);
    assert(unloaded == 0 && registry::node_by_path(COPY).is_none(), "hive: ZwUnloadKey tira a hive do namespace");
    let reloaded = load(COPY, COPY_FILE);
    let persisted = registry::read_value_by_path(COPY, "Persistido").is_some_and(|value| value.data == wide("sim"))
        && registry::read_value_by_path(COPY, "Nenhum").is_none()
        && registry::read_value_by_path(&alloc::format!("{COPY}\\NovoFilho"), "Valor").is_some_and(|value| value.data == [9, 0, 0, 0]);
    assert(reloaded == 0 && persisted, "hive: a carga seguinte ve as mudancas descarregadas");
    // Recuperação: o primário de antes, invalidado (1/0), com o log da
    // descarga, volta com as mudanças e o bloco base validado.
    let mut invalid = before.clone();
    let written = invalid.len() >= 0x1000 && {
        invalid[8..12].copy_from_slice(&0u32.to_le_bytes());
        let sum = base_block::checksum_bytes(&invalid);
        invalid[0x1fc..0x200].copy_from_slice(&sum.to_le_bytes());
        write_volume("/opennt-hive-rec.dat", &invalid) && write_volume("/opennt-hive-rec.dat.LOG1", &log)
    };
    let recovered = load("\\Registry\\Machine\\OpenNTHiveRecuperada", "\\??\\D:\\opennt-hive-rec.dat");
    let applied = registry::read_value_by_path("\\Registry\\Machine\\OpenNTHiveRecuperada", "Persistido").is_some_and(|value| value.data == wide("sim"));
    let rewritten = read_volume("/opennt-hive-rec.dat");
    assert(written && recovered == 0 && applied && u32_at(&rewritten, 4) == 2 && u32_at(&rewritten, 8) == 2, "hive: primario invalidado recuperado pelo log na carga");
    assert(unload("\\Registry\\Machine\\OpenNTHiveRecuperada") == 0, "hive: ZwUnloadKey da hive recuperada");
}

fn restore_compress_and_deferred_unload(assert: Assert) {
    // ZwRestoreKey: a subárvore do destino vira a do arquivo.
    let target = open("\\Registry\\Machine\\Software\\OpenNTHiveRestaurada", true);
    let stale = open("\\Registry\\Machine\\Software\\OpenNTHiveRestaurada\\Antiga", true);
    registry::close_handle(stale as u32);
    let source = open(SOURCE, false);
    let file = create_file("\\??\\D:\\opennt-hive-res.dat");
    let saved = status(call_export("ZwSaveKeyEx", &[source, file, 2]));
    let restored = status(call_export("ZwRestoreKey", &[target, file, 0]));
    zw_files::close_file_entry(file as u32);
    let same = registry::with_node(registry::node_by_path(SOURCE).unwrap_or(0), |key| key.children.len()) == registry::with_node(registry::node_by_path("\\Registry\\Machine\\Software\\OpenNTHiveRestaurada").unwrap_or(0), |key| key.children.len());
    let replaced = registry::node_by_path("\\Registry\\Machine\\Software\\OpenNTHiveRestaurada\\Antiga").is_none() && registry::read_value_by_path("\\Registry\\Machine\\Software\\OpenNTHiveRestaurada\\Filho", "Cinco").is_some_and(|value| value.data == [5; 5]);
    assert(saved == 0 && restored == 0 && same && replaced, "hive: ZwRestoreKey troca subchaves e valores pelos do arquivo");
    registry::close_handle(target as u32);
    registry::close_handle(source as u32);
    // NtCompressKey: só a raiz; o modo vem dos bits baixos do handle.
    let not_root = open(&alloc::format!("{COPY}\\Filho"), false);
    let refused = crate::ntos::cm::hive_services::compress_key(not_root, false);
    registry::close_handle(not_root as u32);
    let root = open(COPY, false);
    let marked = crate::ntos::cm::hive_services::compress_key(root | 1, false);
    let identifier = registry::node_by_path(COPY).and_then(registry::hive_of).map(|(identifier, _)| identifier).unwrap_or(0);
    let reorganize = registry::with_storage(identifier, |storage| storage.base_block().last_reorganize_time.get());
    registry::close_handle(root as u32);
    assert(refused == STATUS_INVALID_PARAMETER && marked == 0 && reorganize == Some(1), "hive: NtCompressKey exige a raiz e marca LastReorganizeTime = 1");
    let unloaded = unload(COPY);
    let reloaded = load(COPY, COPY_FILE);
    let identifier = registry::node_by_path(COPY).and_then(registry::hive_of).map(|(identifier, _)| identifier).unwrap_or(0);
    let reorganized = registry::with_storage(identifier, |storage| storage.base_block().last_reorganize_time.get() > 1 && !storage.broken);
    let intact = registry::read_value_by_path(COPY, "Persistido").is_some_and(|value| value.data == wide("sim"));
    assert(unloaded == 0 && reloaded == 0 && reorganized == Some(true) && intact, "hive: a carga seguinte reorganiza a hive marcada");
    // ZwUnloadKeyEx com handle aberto: STATUS_PENDING e a descarga no
    // fechamento do último handle, com o evento sinalizado.
    let held = open(&alloc::format!("{COPY}\\Filho"), false);
    let event_out = guest::alloc_bytes(8);
    // ZwCreateEvent(&Handle, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE).
    let event_status = status(call_export("ZwCreateEvent", &[event_out, 0x1F_0003, 0, 0, 0]));
    let event = guest::read64(event_out);
    guest::free_bytes(event_out);
    let target = attributes(COPY);
    let pending = status(call_export("ZwUnloadKeyEx", &[target, event]));
    guest::free_bytes(target);
    let still = registry::node_by_path(COPY).is_some();
    registry::close_handle(held as u32);
    let gone = registry::node_by_path(COPY).is_none();
    let signaled = crate::ntos::io::file::request::event_reference(event, 0).is_ok_and(|mut reference| {
        let state = crate::ntos::ke::dispatcher::read_state(reference.pointer);
        reference.release();
        state == 1
    });
    let _ = call_export("ZwClose", &[event]);
    assert(event_status == 0 && pending == STATUS_PENDING && still && gone && signaled, "hive: ZwUnloadKeyEx adia a descarga ate o ultimo handle e sinaliza o evento");
}

fn machine_hive_load_notifies(assert: Assert) {
    use crate::ntos::io::work_items;
    // Callback: (*Context)++, numa alocação executável (o heap não executa).
    let callback = super::executable_code::place(&[0x48, 0xFF, 0x01, 0xC3]);
    let counter = guest::alloc_bytes(8);
    guest::write64(counter, 0);
    let handle = guest::alloc_bytes(8);
    // OSDATA: um ponto de montagem de máquina que o boot não carrega (as
    // outras hives de máquina já vêm do volume).
    let mount = attributes("\\Registry\\Machine\\OSDATA");
    let registered = status(call_export("CmRegisterMachineHiveLoadedNotification", &[callback, counter, mount + 0x40, handle]));
    work_items::run_queue();
    let before = guest::read64(counter);
    let loaded = load("\\Registry\\Machine\\OSDATA", "\\??\\D:\\opennt-hive-std.dat");
    work_items::run_queue();
    assert(registered == 0 && before == 0 && loaded == 0 && guest::read64(counter) == 1, "hive: a carga de uma hive no ponto de montagem OSDATA chama a notificacao de hive de maquina");
    let _ = call_export("CmUnregisterMachineHiveLoadedNotification", &[guest::read64(handle)]);
    assert(unload("\\Registry\\Machine\\OSDATA") == 0, "hive: ZwUnloadKey da hive OSDATA de teste");
    guest::free_bytes(mount);
    super::executable_code::release(callback);
}

fn privileges_and_validation(assert: Assert) {
    let target = attributes("\\Registry\\Machine\\OpenNTHiveInvalida");
    let file = attributes(COPY_FILE);
    let software = attributes("\\Registry\\Machine\\Software\\Microsoft");
    let missing = attributes("\\Registry\\Machine\\OpenNTHiveAusente");
    assert(status(call_export("ZwLoadKeyEx", &[target, file, 1, 0, 0, 0, 0, 0])) == STATUS_INVALID_PARAMETER_3, "hive: ZwLoadKeyEx com REG_WHOLE_HIVE_VOLATILE = STATUS_INVALID_PARAMETER_3");
    assert(status(call_export("ZwLoadKey", &[software, file])) == STATUS_OBJECT_NAME_COLLISION, "hive: ZwLoadKey sobre chave existente = STATUS_OBJECT_NAME_COLLISION");
    assert(status(call_export("ZwUnloadKey2", &[target, 2])) == STATUS_INVALID_PARAMETER && status(call_export("ZwUnloadKey", &[software])) == STATUS_INVALID_PARAMETER && status(call_export("ZwUnloadKey", &[missing])) == STATUS_INVALID_PARAMETER, "hive: ZwUnloadKey de flags invalidas, de chave que nao e raiz de hive e de chave ausente = STATUS_INVALID_PARAMETER");
    let key = open(SOURCE, false);
    let out = create_file("\\??\\D:\\opennt-hive-inv.dat");
    assert(status(call_export("ZwSaveKeyEx", &[key, out, 3])) == STATUS_INVALID_PARAMETER, "hive: ZwSaveKeyEx com formato 3 = STATUS_INVALID_PARAMETER");
    zw_files::close_file_entry(out as u32);
    registry::close_handle(key as u32);
    let garbage = write_volume("/opennt-hive-inv.dat", &[0x5A; 0x2000]);
    let corrupt = attributes("\\??\\D:\\opennt-hive-inv.dat");
    assert(garbage && status(call_export("ZwLoadKey", &[target, corrupt])) == STATUS_REGISTRY_CORRUPT && registry::node_by_path("\\Registry\\Machine\\OpenNTHiveInvalida").is_none(), "hive: arquivo que nao e hive = STATUS_REGISTRY_CORRUPT");
    for block in [target, file, software, missing, corrupt] {
        guest::free_bytes(block);
    }
    // PreviousMode de usuário sem SeRestorePrivilege/SeBackupPrivilege.
    use crate::ntos::ps::user::state;
    use crate::ntos::se::token::tokens;
    let outcome = super::multiprocess::identity::with_test_process("hive-privilegios.exe", None, |_| {
        let Some(token) = crate::ntos::ob::object_access::subject() else { return false };
        let saved: Vec<(u64, u32)> = tokens::with(token, |token| token.privileges.iter().map(|privilege| (privilege.id, privilege.attributes)).collect()).unwrap_or_default();
        let set_backup_restore = |enabled: bool| {
            tokens::update(token, |token| {
                for privilege in token.privileges.iter_mut().filter(|privilege| privilege.id == 17 || privilege.id == 18) {
                    privilege.attributes = if enabled { privilege.attributes | 2 } else { privilege.attributes & !2 };
                }
            });
        };
        let call = |name: &str, a1: u64, a2: u64| state::handler(name).map(|handler| handler(a1, a2, 0, 0, 0).unwrap_or(1)).unwrap_or(1);
        // Com SeBackupPrivilege habilitado, Count 0 do NtCompactKeys é sucesso.
        set_backup_restore(true);
        let allowed = call("NtCompactKeys", 0, 0) == 0;
        set_backup_restore(false);
        let refused = ["NtLoadKey", "NtLoadKey2", "NtUnloadKey", "NtUnloadKey2", "NtSaveKey", "NtSaveKeyEx", "NtRestoreKey", "NtCompressKey"].iter().all(|name| call(name, 0, 0) == STATUS_PRIVILEGE_NOT_HELD) && call("NtCompactKeys", 1, 0) == STATUS_PRIVILEGE_NOT_HELD;
        tokens::update(token, |token| {
            for privilege in token.privileges.iter_mut() {
                if let Some(&(_, attributes)) = saved.iter().find(|(id, _)| *id == privilege.id) {
                    privilege.attributes = attributes;
                }
            }
        });
        allowed && refused
    });
    assert(outcome == Some(true), "hive: sem SeRestorePrivilege/SeBackupPrivilege os servicos de hive de usuario devolvem STATUS_PRIVILEGE_NOT_HELD");
}

/// ZwCreateKey com Class: a chave `Classe` sob a origem, com a classe
/// "4a1b" (o formato das classes que o lsasrv grava nas chaves da chave de
/// sistema).
fn key_class(assert: Assert) {
    let path = alloc::format!("{SOURCE}\\Classe");
    let class: Vec<u16> = "4a1b".encode_utf16().collect();
    let block = guest::alloc_bytes(0x400);
    guest::write_bytes(block, &[0u8; 0x400]);
    let (output, disposition, class_string, class_buffer, information, returned) = (block, block + 8, block + 0x10, block + 0x20, block + 0x100, block + 0x40);
    guest::write_bytes(class_buffer, &class.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    // SAFETY: bloco próprio recém-alocado.
    let string = unsafe { UnicodeString::at(class_string) };
    string.length.set(7);
    string.maximum_length.set(8);
    string.buffer.set(class_buffer);
    let oa = attributes(&path);
    let odd = status(call_export("ZwCreateKey", &[output, 0xF003F, oa, 0, class_string, 0, disposition]));
    string.length.set(8);
    let created = status(call_export("ZwCreateKey", &[output, 0xF003F, oa, 0, class_string, 0, disposition]));
    let handle = guest::read64(output);
    assert(odd == STATUS_INVALID_PARAMETER && created == 0 && guest::read32(disposition) == 1, "hive: ZwCreateKey com Class cria a chave; Length impar da STATUS_INVALID_PARAMETER");
    // KeyNodeInformation: o nome em 0x18 e a classe depois dele, com o
    // ClassOffset alinhado a 8 (0x18 + 12 bytes de "Classe" = 0x24 -> 0x28).
    let node = status(call_export("ZwQueryKey", &[handle, 1, information, 0x100, returned]));
    let class_bytes = |offset: u64| (0..class.len() as u64).map(|index| guest::read16(information + offset + index * 2)).collect::<Vec<u16>>();
    assert(node == 0 && guest::read32(returned) == 0x30 && guest::read32(information + 0xC) == 0x28 && guest::read32(information + 0x10) == 8 && guest::read32(information + 0x14) == 12 && class_bytes(0x28) == class, "hive: KeyNodeInformation com ClassOffset 0x28, ClassLength 8 e a classe depois do nome");
    let full = status(call_export("ZwQueryKey", &[handle, 2, information, 0x100, returned]));
    assert(full == 0 && guest::read32(returned) == 0x34 && guest::read32(information + 0xC) == 0x2C && guest::read32(information + 0x10) == 8 && class_bytes(0x2C) == class, "hive: KeyFullInformation com ClassOffset 0x2C, ClassLength 8 e a classe");
    let small = status(call_export("ZwQueryKey", &[handle, 2, information, 0x30, returned]));
    assert(small == 0x8000_0005 && guest::read32(returned) == 0x34, "hive: KeyFullInformation sem espaco para a classe da STATUS_BUFFER_OVERFLOW");
    let parent = open(SOURCE, false);
    let parent_full = status(call_export("ZwQueryKey", &[parent, 2, information, 0x100, returned]));
    assert(parent_full == 0 && guest::read32(information + 0x1C) == 8 && guest::read32(information + 0xC) == 0xFFFF_FFFF, "hive: o MaxClassLen do pai e 8 e a chave sem classe tem ClassOffset 0xFFFFFFFF");
    registry::close_handle(parent as u32);
    // A célula 'nk' na hive: ClassLength 8 e os bytes da classe.
    let cell = registry::node_by_path(&path).and_then(|node| registry::with_node(node, |key| key.cell)).flatten();
    let stored = cell.and_then(|(identifier, cell)| registry::with_storage(identifier, |storage| key_cells::node(storage, cell).map(|node| node.class_length.get()) == Some(8) && key_cells::class_units(storage, cell) == class));
    assert(stored == Some(true), "hive: a celula nk guarda ClassLength 8 e a celula de classe");
    let _ = call_export("ZwDeleteKey", &[handle]);
    let _ = call_export("ZwClose", &[handle]);
    guest::free_bytes(oa);
    // Um componente intermediário ausente: STATUS_OBJECT_NAME_NOT_FOUND, como
    // o CmpDoParseKey, sem criar nada.
    let deep = alloc::format!("{SOURCE}\\Ausente\\Filho");
    let deep_oa = attributes(&deep);
    let missing_parent = status(call_export("ZwCreateKey", &[output, 0xF003F, deep_oa, 0, 0, 0, disposition]));
    assert(missing_parent == 0xC000_0034 && registry::node_by_path(&alloc::format!("{SOURCE}\\Ausente")).is_none(), "hive: ZwCreateKey com o pai ausente da STATUS_OBJECT_NAME_NOT_FOUND");
    guest::free_bytes(deep_oa);
    guest::free_bytes(block);
}

const BIG: &str = "\\Registry\\Machine\\OpenNTHiveGrande";
const BIG_FILE: &str = "\\??\\D:\\opennt-hive-grande.dat";
/// Filhas da raiz da hive grande e netas de cada filha.
const BIG_CHILDREN: usize = 40;
const BIG_GRANDCHILDREN: usize = 100;
/// O heap (com os cabeçalhos dos blocos) que uma chave de hive carregada
/// pode ocupar: o nó da arena e a entrada na lista de subchaves do pai. Uma
/// cópia decodificada de cada chave (nome, valores com os dados, classe)
/// passaria de 700 bytes por chave desta hive.
const HEAP_PER_KEY: usize = 256;
/// Chaves criadas e excluídas na hive grande, cada uma com um valor de
/// [`TEMPORARY_DATA`] bytes.
const TEMPORARY_KEYS: usize = 400;
const TEMPORARY_DATA: usize = 1024;
/// O que pode sobrar no heap depois de excluir as chaves temporárias (o
/// vetor de bins e o mapa de células livres da hive crescem com elas) e
/// depois da descarga (os caches do NTFS dos arquivos da hive).
const DELETE_SLACK: usize = 128 << 10;
const UNLOAD_SLACK: usize = 256 << 10;

/// A hive grande: a raiz, BIG_CHILDREN filhas e BIG_GRANDCHILDREN netas de
/// cada uma, todas com um REG_SZ, um REG_DWORD e 160 bytes de REG_BINARY.
fn big_hive_keys() -> Vec<tree::NewKey> {
    let values = |index: usize| {
        alloc::vec![
            registry::Value { name: alloc::string::String::from("Descricao"), value_type: 1, data: wide(&alloc::format!("chave numero {index:05} da hive grande")) },
            registry::Value { name: alloc::string::String::from("Tamanho"), value_type: 4, data: (index as u32).to_le_bytes().to_vec() },
            registry::Value { name: alloc::string::String::from("Dados"), value_type: 3, data: (0..160).map(|byte| (byte + index) as u8).collect() },
        ]
    };
    let key = |name: alloc::string::String, parent: Option<usize>, index: usize| tree::NewKey { name, last_write_time: 0x01D7_0000_0000_0000, security: policy::boot_root(), values: values(index), parent, link: false, class: Vec::new() };
    let mut keys = alloc::vec![key(alloc::string::String::from("Grande"), None, 0)];
    for child in 0..BIG_CHILDREN {
        let parent = keys.len();
        keys.push(key(alloc::format!("Filha{child}"), Some(0), parent));
        for grandchild in 0..BIG_GRANDCHILDREN {
            let index = keys.len();
            keys.push(key(alloc::format!("Neta{grandchild}"), Some(parent), index));
        }
    }
    keys
}

/// O heap de uma hive carregada fica nos nós (o conteúdo é lido das
/// células), as chaves excluídas saem da arena e a descarga devolve tudo.
fn heap_of_loaded_hives(assert: Assert) {
    let keys = big_hive_keys();
    let count = keys.len();
    let written = tree::build(&keys, 5, 0x01D7_0000_0000_0000, "").is_some_and(|(storage, _)| write_volume("/opennt-hive-grande.dat", &storage.image()));
    drop(keys);
    let (nodes_before, _) = registry::arena_counts();
    let heap_before = crate::hal::kmalloc::occupied();
    let loaded = load(BIG, BIG_FILE);
    let (nodes_loaded, _) = registry::arena_counts();
    let heap_loaded = crate::hal::kmalloc::occupied();
    crate::debug_print!("[cm-teste] hive grande: {} chaves, {} nos novos, heap +{} bytes ({} por chave)", count, nodes_loaded - nodes_before, heap_loaded.saturating_sub(heap_before), heap_loaded.saturating_sub(heap_before) / count);
    assert(written && loaded == 0 && nodes_loaded == nodes_before + count && heap_loaded.saturating_sub(heap_before) <= count * HEAP_PER_KEY, "hive: a carga de uma hive de 4041 chaves cria um no por chave e ocupa no maximo 256 bytes de heap por chave");
    let sample = alloc::format!("{BIG}\\Filha17\\Neta42");
    let index = 1 + 17 * (BIG_GRANDCHILDREN + 1) + 1 + 42;
    let read = registry::read_value_by_path(&sample, "descricao").is_some_and(|value| value.name == "Descricao" && value.data == wide(&alloc::format!("chave numero {index:05} da hive grande")))
        && registry::read_value_by_path(&sample, "DADOS").is_some_and(|value| value.value_type == 3 && value.data == (0..160).map(|byte| (byte + index) as u8).collect::<Vec<u8>>())
        && registry::list_keys(&alloc::format!("{BIG}\\Filha17")).len() == BIG_GRANDCHILDREN
        && registry::node_by_path(&sample).and_then(|node| registry::with_node(node, |key| (key.name(), key.value_count(), key.last_write_time()))) == Some((alloc::string::String::from("Neta42"), 3, 0x01D7_0000_0000_0000));
    assert(read, "hive: nomes, valores e LastWriteTime da hive grande lidos das celulas");
    // Chaves criadas e excluídas: os nós saem da arena e o heap volta.
    let parent = alloc::format!("{BIG}\\Filha3");
    let heap_middle = crate::hal::kmalloc::occupied();
    let mut created = true;
    for key in 0..TEMPORARY_KEYS {
        let handle = registry::open_or_create(&alloc::format!("{parent}\\Temporaria{key}"), None).unwrap_or(0);
        created &= handle != 0 && registry::set_value(handle, "Valor", 3, alloc::vec![key as u8; TEMPORARY_DATA]);
        registry::close_handle(handle);
    }
    let (nodes_created, _) = registry::arena_counts();
    let mut deleted = true;
    for key in 0..TEMPORARY_KEYS {
        let path = alloc::format!("{parent}\\Temporaria{key}");
        deleted &= registry::node_by_path(&path).is_some_and(|node| registry::delete_node(node, &path));
    }
    let (nodes_deleted, _) = registry::arena_counts();
    let heap_deleted = crate::hal::kmalloc::occupied();
    crate::debug_print!("[cm-teste] hive grande: {} chaves temporarias, heap +{} bytes depois de excluidas", TEMPORARY_KEYS, heap_deleted.saturating_sub(heap_middle));
    assert(created && deleted && nodes_created == nodes_loaded + TEMPORARY_KEYS && nodes_deleted == nodes_loaded && heap_deleted <= heap_middle + DELETE_SLACK, "hive: as chaves excluidas saem da arena e devolvem o heap");
    // Uma chave excluída com handle aberto fica até o handle fechar.
    let held = registry::open_or_create(&alloc::format!("{parent}\\Aberta"), None).unwrap_or(0);
    let held_node = registry::get_node(held);
    let removed = held_node.is_some_and(|node| registry::delete_node(node, ""));
    let tombstone = held_node.is_some_and(registry::is_deleted) && registry::arena_counts().0 == nodes_loaded + 1 && registry::get_node(held).is_none();
    registry::close_handle(held);
    assert(removed && tombstone && registry::arena_counts().0 == nodes_loaded, "hive: a chave excluida com handle aberto sai da arena quando o handle fecha");
    let unloaded = unload(BIG);
    let (nodes_after, _) = registry::arena_counts();
    let heap_after = crate::hal::kmalloc::occupied();
    crate::debug_print!("[cm-teste] hive grande: descarregada, nos {} -> {}, heap {:+} bytes", nodes_before, nodes_after, heap_after as i64 - heap_before as i64);
    assert(unloaded == 0 && nodes_after == nodes_before && heap_after <= heap_before + UNLOAD_SLACK, "hive: a descarga da hive grande devolve os nos e o heap dela");
}

pub fn run(assert: Assert) {
    format_vectors(assert);
    if ntfs::mounted().is_none() {
        assert(false, "hive: volume NTFS montado para os arquivos de hive");
        return;
    }
    system_hive_from_file(assert);
    save_load_round_trip(assert);
    key_class(assert);
    flush_unload_reload(assert);
    restore_compress_and_deferred_unload(assert);
    machine_hive_load_notifies(assert);
    privileges_and_validation(assert);
    heap_of_loaded_hives(assert);
}
