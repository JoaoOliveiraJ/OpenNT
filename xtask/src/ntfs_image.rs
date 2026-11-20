//! Gera `ntfs.img`: um volume NTFS 3.1 que o leitor do kernel
//! (`drivers/fs/ntfs`) lê como D: e que o ntfs.sys real monta; e, com
//! `--storage=nvme`, o `nvme.img`: um disco particionado (MBR com uma
//! partição NTFS a partir do LBA 2048) com um volume do mesmo formato.
//!
//! Layout: setor = cluster = 512 B, registros de arquivo de 4 KB (o "large
//! FRS" do NTFS) e blocos de índice de 4 KB. Clusters: 0..16 = $Boot (o setor
//! de boot e o resto zerado), a MFT no LCN 16, o espelho dos quatro
//! primeiros registros, o $LogFile, o $AttrDef, o $UpCase, o $SDS do $Secure,
//! os arquivos extras, os blocos INDX dos diretórios grandes, o $Bitmap e o
//! espaço livre. O último setor da imagem é a cópia do setor de boot, fora
//! dos clusters do volume (NumberSectors não o conta).
//!
//! Registros: 0=$MFT 1=$MFTMirr 2=$LogFile 3=$Volume 4=$AttrDef 5='.' (raiz)
//! 6=$Bitmap 7=$Boot 8=$BadClus 9=$Secure 10=$UpCase 11=$Extend, 12..15
//! reservados (em uso, vazios), 16=HELLO.TXT, 17.. os arquivos extras, os
//! diretórios intermediários e por fim os arquivos do $Extend ($Quota,
//! $ObjId, $Reparse): o NTFS só aceita uma entrada de índice que aponte um
//! registro abaixo de 16 no diretório raiz. Os registros do sistema têm o
//! número de sequência igual ao número do registro (o $MFT, 1), como o NTFS
//! os abre; os demais, 1.
//!
//! O formato segue o NTFS 3.1 do Windows 10, conferido com o ntfs.sys
//! 10.0.19041 desta máquina:
//! - NtfsIsBootSectorNtfs: OEM "NTFS    ", 512 bytes por setor, campos de FAT
//!   zerados, NumberSectors dentro do disco, MFT e espelho dentro do volume,
//!   ClustersPerFileRecordSegment e ClustersPerIndexBuffer válidos;
//! - NtfsCheckFileRecord: USA de (4096 / 512) + 1 entradas, em uso, tamanho
//!   alocado 4096, primeiro atributo alinhado depois da USA e o número do
//!   segmento no cabeçalho (0x2A/0x2C); cada atributo com tipo da tabela de
//!   definições (índice tipo / 0x10 - 1);
//! - a tabela de definições de atributo é a do NtfsAttributeDefinitions do
//!   ntfs.sys (17 entradas, com o lugar vazio do 0xF0);
//! - LfsReadRestart: um $LogFile cujas páginas começam com 0xFFFFFFFF é um
//!   log novo, que o LFS inicializa na primeira montagem; o LFS exige pelo
//!   menos 0x50 páginas de 4 KB além das duas de reinício;
//! - NtfsHashSecurityDescriptor: o hash do $SDS/$SDH é `rol(hash, 3) + dword`
//!   sobre o descritor; cada entrada do $SDS fica alinhada a 16 bytes, o
//!   $SII ordenado por SecurityId e o $SDH por hash e SecurityId;
//! - o $UpCase é o RtlUpcaseUnicodeChar de cada unidade (a tabela de
//!   maiúsculas do l_intl.nls desta máquina acima de U+00BF, 'a'..'z' abaixo).
//!
//! Cada arquivo extra vira um registro com $DATA não residente numa run
//! contígua, o que permite embutir arquivos grandes sem runlist fragmentada.
//! Um nó ([`Node`]) dá a um caminho atributos e descritor de segurança
//! próprios: cada descritor distinto ganha um SecurityId a partir de 0x101
//! (o 0x100 é o comum do volume, com Todos), os atributos vão para o
//! $STANDARD_INFORMATION e para o $FILE_NAME (sem o de diretório, que o
//! NTFS marca no registro e no DUP_FILE_NAME_INDEX_PRESENT), e o diretório
//! de um nó entra no volume mesmo vazio.
//! Nomes com `/` (`Windows/System32/x.sys`) criam os diretórios
//! intermediários, registrados depois dos arquivos. O índice $I30 de cada
//! diretório é residente enquanto cabe no registro; senão os nomes vão para
//! blocos INDX e o $INDEX_ROOT guarda os separadores da B-tree.

use std::collections::BTreeMap;

use std::fs;
use std::path::Path;

const SECTOR: usize = 512;
const CLUSTER: usize = 512;
/// $Boot: 8 KB no início do volume.
const BOOT_CLUSTERS: usize = 16;
const MFT_LCN: usize = 16;
const RECORD_SIZE: usize = 4096;
const SECTORS_PER_RECORD: usize = RECORD_SIZE / SECTOR;
const INDEX_BLOCK: usize = 4096;
/// Registros copiados no $MFTMirr.
const MIRROR_RECORDS: usize = 4;
/// $LogFile de 2 MB (o mínimo do LFS é 2 + 0x50 páginas de 4 KB).
const LOG_FILE_BYTES: usize = 2 * 1_048_576;
/// SECURITY_DESCRIPTOR_HEADER do $SDS e a cópia de cada bloco de 256 KB.
const SDS_MIRROR: usize = 0x40000;
/// SecurityId de todos os arquivos: o primeiro do $Secure.
const SECURITY_ID: u32 = 0x100;
const VOLUME_LABEL: &str = "OPENNT";
const HELLO_NAME: &str = "HELLO.TXT";
const HELLO_DATA: &[u8] = b"Ola do NTFS no OpenNT!\r\n";
const HELLO_RECORD: u64 = 16;
const ROOT: u64 = 5;
const EXTEND: u64 = 11;
/// Atributos de arquivo: oculto | sistema e, nas informações duplicadas,
/// o diretório (DUP_FILE_NAME_INDEX_PRESENT) e o índice de visão
/// (DUP_VIEW_INDEX_PRESENT: o $Secure e os índices do $Extend; o ntfs.sys
/// só abre um índice com nome diferente de $I30, como `$Reparse:$R:$INDEX_ALLOCATION`,
/// num arquivo que o tem).
const HIDDEN_SYSTEM: u32 = 0x06;
const DIRECTORY_DUPLICATE: u32 = 0x1000_0000;
const VIEW_INDEX_DUPLICATE: u32 = 0x2000_0000;
const FILE_ARCHIVE: u32 = 0x20;
/// Flags do registro: em uso, diretório ($I30) e índice de visão.
const IN_USE: u16 = 1;
const DIRECTORY: u16 = 3;
const VIEW_INDEX: u16 = 9;

/// Tabela de definições de atributo (nome, tipo, flags, mínimo, máximo), a
/// mesma do NtfsAttributeDefinitions do ntfs.sys 10.0.19041; a entrada vazia
/// ocupa o lugar do tipo 0xF0, e a tabela termina numa entrada zerada.
const ATTRIBUTE_DEFINITIONS: &[(&str, u32, u32, i64, i64)] = &[
    ("$STANDARD_INFORMATION", 0x10, 0x40, 0x30, 0x48),
    ("$ATTRIBUTE_LIST", 0x20, 0x80, 0, -1),
    ("$FILE_NAME", 0x30, 0x42, 0x44, 0x242),
    ("$OBJECT_ID", 0x40, 0x40, 0, 0x100),
    ("$SECURITY_DESCRIPTOR", 0x50, 0x80, 0, -1),
    ("$VOLUME_NAME", 0x60, 0x40, 2, 0x100),
    ("$VOLUME_INFORMATION", 0x70, 0x40, 0xC, 0x18),
    ("$DATA", 0x80, 0x00, 0, -1),
    ("$INDEX_ROOT", 0x90, 0x40, 0, -1),
    ("$INDEX_ALLOCATION", 0xA0, 0x80, 0, -1),
    ("$BITMAP", 0xB0, 0x80, 0, -1),
    ("$REPARSE_POINT", 0xC0, 0x80, 0, 0x4000),
    ("$EA_INFORMATION", 0xD0, 0x40, 8, 8),
    ("$EA", 0xE0, 0x80, 0, 0x10000),
    ("", 0, 0, 0, 0),
    ("$LOGGED_UTILITY_STREAM", 0x100, 0x80, 0, 0x10000),
    ("", 0, 0, 0, 0),
];

fn put16(buffer: &mut [u8], offset: usize, value: u16) {
    buffer[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(buffer: &mut [u8], offset: usize, value: u64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn align8(value: usize) -> usize {
    (value + 7) & !7
}

fn bit_length(value: u64) -> u32 {
    64 - value.leading_zeros()
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Número de sequência do registro: o do sistema é o próprio número.
fn sequence(record: u64) -> u16 {
    match record {
        0 => 1,
        1..=15 => record as u16,
        _ => 1,
    }
}

/// FILE_REFERENCE com o número de sequência.
fn reference(record: u64) -> u64 {
    record | (sequence(record) as u64) << 48
}

/// Corpo de um atributo.
enum Body {
    /// Valor residente; `true` = indexado (o $FILE_NAME).
    Resident(Vec<u8>, bool),
    /// Runs (LCN ou `None` para buraco, clusters) e o tamanho real.
    NonResident(Vec<(Option<u64>, u64)>, u64),
}

struct Attribute {
    kind: u32,
    name: &'static str,
    body: Body,
}

fn resident(kind: u32, name: &'static str, value: Vec<u8>) -> Attribute {
    Attribute { kind, name, body: Body::Resident(value, false) }
}

fn nonresident(kind: u32, name: &'static str, runs: Vec<(Option<u64>, u64)>, real_size: u64) -> Attribute {
    Attribute { kind, name, body: Body::NonResident(runs, real_size) }
}

/// Runlist NTFS: contagem e delta de LCN com sinal; buraco sem LCN. A
/// contagem também é lida com sinal pelo ntfs.sys: o byte mais alto leva o
/// bit de sinal livre (0xA344 clusters são três bytes, 44 A3 00; em dois, o
/// run teria -23740 clusters e o registro seria corrompido).
fn runlist_bytes(runs: &[(Option<u64>, u64)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut previous = 0i64;
    for &(lcn, count) in runs {
        let count_length = ((bit_length(count) + 8) / 8).max(1) as usize;
        let count_bytes = &count.to_le_bytes()[..count_length];
        match lcn {
            None => {
                out.push(count_length as u8);
                out.extend_from_slice(count_bytes);
            }
            Some(lcn) => {
                let delta = lcn as i64 - previous;
                let magnitude = if delta >= 0 { delta as u64 } else { delta.unsigned_abs() };
                let delta_length = ((bit_length(magnitude) + 8) / 8).max(1) as usize;
                out.push(((delta_length as u8) << 4) | count_length as u8);
                out.extend_from_slice(count_bytes);
                out.extend_from_slice(&delta.to_le_bytes()[..delta_length]);
                previous = lcn as i64;
            }
        }
    }
    out.push(0);
    out
}

/// O registro de atributo com a instância dada.
fn encode_attribute(attribute: &Attribute, instance: u16) -> Vec<u8> {
    let name = utf16(attribute.name);
    let name_length = attribute.name.encode_utf16().count() as u8;
    match &attribute.body {
        Body::Resident(value, indexed) => {
            let value_offset = align8(0x18 + name.len());
            let total = align8(value_offset + value.len());
            let mut bytes = vec![0u8; total];
            put32(&mut bytes, 0, attribute.kind);
            put32(&mut bytes, 4, total as u32);
            bytes[9] = name_length;
            put16(&mut bytes, 10, 0x18);
            put16(&mut bytes, 14, instance);
            put32(&mut bytes, 16, value.len() as u32);
            put16(&mut bytes, 20, value_offset as u16);
            bytes[22] = *indexed as u8;
            bytes[0x18..0x18 + name.len()].copy_from_slice(&name);
            bytes[value_offset..value_offset + value.len()].copy_from_slice(value);
            bytes
        }
        Body::NonResident(runs, real_size) => {
            let mapping = runlist_bytes(runs);
            let clusters: u64 = runs.iter().map(|&(_, count)| count).sum();
            let mapping_offset = align8(0x40 + name.len());
            let total = align8(mapping_offset + mapping.len());
            let mut bytes = vec![0u8; total];
            put32(&mut bytes, 0, attribute.kind);
            put32(&mut bytes, 4, total as u32);
            bytes[8] = 1;
            bytes[9] = name_length;
            put16(&mut bytes, 10, 0x40);
            put16(&mut bytes, 14, instance);
            put64(&mut bytes, 16, 0);
            put64(&mut bytes, 24, clusters.wrapping_sub(1));
            put16(&mut bytes, 32, mapping_offset as u16);
            put64(&mut bytes, 40, clusters * CLUSTER as u64);
            put64(&mut bytes, 48, *real_size);
            put64(&mut bytes, 56, *real_size);
            bytes[0x40..0x40 + name.len()].copy_from_slice(&name);
            bytes[mapping_offset..mapping_offset + mapping.len()].copy_from_slice(&mapping);
            bytes
        }
    }
}

/// Primeiro atributo depois do cabeçalho de 0x30 e da USA.
fn first_attribute_offset() -> usize {
    align8(0x30 + (SECTORS_PER_RECORD + 1) * 2)
}

/// Bytes que os atributos ocupam num registro.
fn attributes_size(attributes: &[Attribute]) -> usize {
    attributes.iter().map(|attribute| encode_attribute(attribute, 0).len()).sum()
}

/// Registro FILE com a USA (USN 1 no fim de cada setor, os originais na
/// USA), o número do segmento e as instâncias dos atributos em ordem.
fn make_record(number: u64, flags: u16, attributes: &[Attribute]) -> Result<Vec<u8>, String> {
    let mut record = vec![0u8; RECORD_SIZE];
    record[0..4].copy_from_slice(b"FILE");
    let usa_count = SECTORS_PER_RECORD + 1;
    let first = first_attribute_offset();
    put16(&mut record, 4, 0x30);
    put16(&mut record, 6, usa_count as u16);
    put16(&mut record, 16, sequence(number));
    let links = attributes.iter().filter(|attribute| attribute.kind == 0x30).count() as u16;
    put16(&mut record, 18, links);
    put16(&mut record, 20, first as u16);
    put16(&mut record, 22, flags);
    put32(&mut record, 28, RECORD_SIZE as u32);
    put16(&mut record, 40, attributes.len() as u16);
    put16(&mut record, 42, (number >> 32) as u16);
    put32(&mut record, 44, number as u32);
    let mut offset = first;
    for (instance, attribute) in attributes.iter().enumerate() {
        let blob = encode_attribute(attribute, instance as u16);
        if offset + blob.len() + 8 > RECORD_SIZE {
            return Err(format!("MFT record {number}: attributes exceed {RECORD_SIZE} bytes"));
        }
        record[offset..offset + blob.len()].copy_from_slice(&blob);
        offset += blob.len();
    }
    put32(&mut record, offset, 0xFFFF_FFFF);
    put32(&mut record, 24, (offset + 8) as u32);
    apply_usa(&mut record, 0x30, usa_count);
    Ok(record)
}

/// USN 1 no fim de cada setor e os bytes originais na USA.
fn apply_usa(block: &mut [u8], usa_offset: usize, usa_count: usize) {
    put16(block, usa_offset, 1);
    for index in 1..usa_count {
        let tail = index * SECTOR - 2;
        let original = u16::from_le_bytes([block[tail], block[tail + 1]]);
        put16(block, usa_offset + index * 2, original);
        put16(block, tail, 1);
    }
}

/// $STANDARD_INFORMATION do NTFS 3.x (72 bytes) com o SecurityId comum.
fn standard_information(file_attributes: u32) -> Attribute {
    standard_information_with(file_attributes, SECURITY_ID)
}

/// $STANDARD_INFORMATION com o SecurityId dado.
fn standard_information_with(file_attributes: u32, security_id: u32) -> Attribute {
    let mut value = vec![0u8; 72];
    put32(&mut value, 32, file_attributes);
    put32(&mut value, 52, security_id);
    resident(0x10, "", value)
}

/// Valor de $FILE_NAME (sem o cabeçalho do atributo).
fn file_name_value(parent: u64, name: &str, file_attributes: u32, allocated: u64, real_size: u64, namespace: u8) -> Result<Vec<u8>, String> {
    let units = utf16(name);
    let characters = units.len() / 2;
    if !(1..=255).contains(&characters) || name.contains(['\\', '/', ':']) {
        return Err(format!("nome NTFS invalido: {name:?}"));
    }
    let mut value = vec![0u8; 66 + units.len()];
    put64(&mut value, 0, reference(parent));
    put64(&mut value, 40, allocated);
    put64(&mut value, 48, real_size);
    put32(&mut value, 56, file_attributes);
    value[64] = characters as u8;
    value[65] = namespace;
    value[66..].copy_from_slice(&units);
    Ok(value)
}

/// O espaço de nomes do $FILE_NAME: um nome que já é um nome curto do DOS
/// (8.3, maiúsculo) é Win32 e DOS ao mesmo tempo (3, como o NTFS grava);
/// os demais vão no espaço POSIX (0), que dispensa o par de nome curto que
/// um nome só Win32 (1) exige do ntfs.sys.
fn name_space(name: &str) -> u8 {
    if is_short_name(name) { 3 } else { 0 }
}

/// Nome curto válido do DOS: base de 1 a 8 e extensão de até 3 caracteres
/// maiúsculos, dígitos ou símbolos permitidos.
fn is_short_name(name: &str) -> bool {
    let legal = |part: &str| part.chars().all(|character| character.is_ascii_uppercase() || character.is_ascii_digit() || "!#$%&'()-@^_`{}~".contains(character));
    let (base, extension) = match name.split_once('.') {
        Some((base, extension)) => (base, Some(extension)),
        None => (name, None),
    };
    (1..=8).contains(&base.len()) && legal(base) && extension.is_none_or(|extension| (1..=3).contains(&extension.len()) && legal(extension))
}

fn file_name_attribute(value: Vec<u8>) -> Attribute {
    Attribute { kind: 0x30, name: "", body: Body::Resident(value, true) }
}

/// Entrada de um índice de arquivos ($I30): referência, chave (o
/// $FILE_NAME) e o VCN do filho no fim.
fn index_entry(reference: u64, key: &[u8], child: Option<u64>) -> Vec<u8> {
    let size = align8(16 + key.len()) + if child.is_some() { 8 } else { 0 };
    let mut entry = vec![0u8; size];
    put64(&mut entry, 0, reference);
    put16(&mut entry, 8, size as u16);
    put16(&mut entry, 10, key.len() as u16);
    put16(&mut entry, 12, child.is_some() as u16);
    entry[16..16 + key.len()].copy_from_slice(key);
    if let Some(child) = child {
        put64(&mut entry, size - 8, child);
    }
    entry
}

/// Entrada final de um nó (com o VCN do filho à esquerda, se houver).
fn end_entry(child: Option<u64>) -> Vec<u8> {
    let size = 16 + if child.is_some() { 8 } else { 0 };
    let mut entry = vec![0u8; size];
    put16(&mut entry, 8, size as u16);
    put16(&mut entry, 12, 2 | child.is_some() as u16);
    if let Some(child) = child {
        put64(&mut entry, 16, child);
    }
    entry
}

/// Entrada de um índice de visão: deslocamento e tamanho dos dados, chave e
/// dados (alinhada a 8, com o preenchimento dado no fim).
fn view_entry(key: &[u8], data: &[u8], padding: &[u8]) -> Vec<u8> {
    let data_offset = 16 + key.len();
    let size = align8(data_offset + data.len() + padding.len());
    let mut entry = vec![0u8; size];
    put16(&mut entry, 0, data_offset as u16);
    put16(&mut entry, 2, data.len() as u16);
    put16(&mut entry, 8, size as u16);
    put16(&mut entry, 10, key.len() as u16);
    entry[16..16 + key.len()].copy_from_slice(key);
    entry[data_offset..data_offset + data.len()].copy_from_slice(data);
    entry[data_offset + data.len()..data_offset + data.len() + padding.len()].copy_from_slice(padding);
    entry
}

/// Valor do $INDEX_ROOT: tipo indexado, colação, tamanho do bloco e o
/// INDEX_HEADER com as entradas (LARGE_INDEX quando há blocos).
fn index_root_value(indexed_type: u32, collation: u32, entries: &[u8], large: bool) -> Vec<u8> {
    let mut value = vec![0u8; 32 + entries.len()];
    put32(&mut value, 0, indexed_type);
    put32(&mut value, 4, collation);
    put32(&mut value, 8, INDEX_BLOCK as u32);
    value[12] = (INDEX_BLOCK / CLUSTER) as u8;
    put32(&mut value, 16, 16);
    put32(&mut value, 20, (16 + entries.len()) as u32);
    put32(&mut value, 24, (16 + entries.len()) as u32);
    value[28] = large as u8;
    value[32..].copy_from_slice(entries);
    value
}

/// Inteiro com os `count` bits baixos ligados, em `length` bytes.
fn low_bits(count: usize, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    for bit in 0..count {
        bytes[bit / 8] |= 1 << (bit % 8);
    }
    bytes
}

/// Alocação sequencial de clusters, com os bytes de cada faixa.
struct Clusters {
    next: usize,
    writes: Vec<(usize, Vec<u8>)>,
}

impl Clusters {
    fn allocate(&mut self, bytes: Vec<u8>) -> (u64, u64) {
        let count = bytes.len().div_ceil(CLUSTER).max(1);
        let lcn = self.next;
        self.next += count;
        self.writes.push((lcn, bytes));
        (lcn as u64, count as u64)
    }
}

/// O índice $I30 de um diretório: o $INDEX_ROOT residente e, se não couber
/// em `room` bytes, os blocos INDX ($INDEX_ALLOCATION e $BITMAP).
fn directory_index(children: &[(u64, Vec<u8>)], room: usize, clusters: &mut Clusters) -> Result<Vec<Attribute>, String> {
    let entries: Vec<Vec<u8>> = children.iter().map(|(record, key)| index_entry(reference(*record), key, None)).collect();
    let all: usize = entries.iter().map(Vec::len).sum::<usize>() + 16;
    let root_overhead = encode_attribute(&resident(0x90, "$I30", index_root_value(0x30, 1, &[], false)), 0).len();
    if all + root_overhead <= room {
        let flat = [entries.concat(), end_entry(None)].concat();
        return Ok(vec![resident(0x90, "$I30", index_root_value(0x30, 1, &flat, false))]);
    }
    // B-tree de dois níveis: cada separador sai da folha anterior e vai para
    // o $INDEX_ROOT com o VCN do filho.
    let usable = INDEX_BLOCK - 0x40 - 24;
    let mut groups: Vec<Vec<(u64, Vec<u8>)>> = Vec::new();
    let mut group = Vec::new();
    let mut used = 0;
    for (child, entry) in children.iter().zip(&entries) {
        if used + entry.len() > usable && !group.is_empty() {
            groups.push(std::mem::take(&mut group));
            used = 0;
        }
        used += entry.len();
        group.push(child.clone());
    }
    if !group.is_empty() {
        groups.push(group);
    }
    let group_count = groups.len();
    let mut root_entries = Vec::new();
    let mut blocks = Vec::new();
    for (number, mut group) in groups.into_iter().enumerate() {
        let vcn = (number * (INDEX_BLOCK / CLUSTER)) as u64;
        if number + 1 < group_count {
            let (record, key) = group.pop().ok_or("grupo de indice vazio")?;
            root_entries.push(index_entry(reference(record), &key, Some(vcn)));
        } else {
            root_entries.push(end_entry(Some(vcn)));
        }
        let leaf = [group.iter().map(|(record, key)| index_entry(reference(*record), key, None)).collect::<Vec<_>>().concat(), end_entry(None)].concat();
        let mut block = vec![0u8; INDEX_BLOCK];
        block[..4].copy_from_slice(b"INDX");
        put16(&mut block, 4, 0x28);
        put16(&mut block, 6, (INDEX_BLOCK / SECTOR + 1) as u16);
        put64(&mut block, 16, vcn);
        put32(&mut block, 24, 0x28);
        put32(&mut block, 28, (0x28 + leaf.len()) as u32);
        put32(&mut block, 32, (INDEX_BLOCK - 24) as u32);
        block[0x40..0x40 + leaf.len()].copy_from_slice(&leaf);
        apply_usa(&mut block, 0x28, INDEX_BLOCK / SECTOR + 1);
        blocks.push(block);
    }
    let root = root_entries.concat();
    if root.len() + root_overhead > room {
        return Err("indice NTFS grande demais para dois niveis".into());
    }
    let count = blocks.len();
    let length = (count * INDEX_BLOCK) as u64;
    let (lcn, run) = clusters.allocate(blocks.concat());
    Ok(vec![
        resident(0x90, "$I30", index_root_value(0x30, 1, &root, true)),
        nonresident(0xA0, "$I30", vec![(Some(lcn), run)], length),
        resident(0xB0, "$I30", low_bits(count, count.div_ceil(64) * 8)),
    ])
}

/// Descritor de segurança autorrelativo do $Secure: dono e grupo
/// Administradores (S-1-5-32-544) e uma DACL com Todos (S-1-1-0) com
/// FILE_ALL_ACCESS.
fn security_descriptor() -> Vec<u8> {
    let everyone: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    let administrators: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 0x02, 0, 0];
    let mut ace = vec![0u8, 0, 20, 0];
    ace.extend_from_slice(&0x001F_01FFu32.to_le_bytes());
    ace.extend_from_slice(&everyone);
    let mut dacl = vec![2u8, 0, 0, 0, 1, 0, 0, 0];
    put16(&mut dacl, 2, (8 + ace.len()) as u16);
    dacl.extend_from_slice(&ace);
    let mut descriptor = vec![0u8; 20];
    descriptor[0] = 1;
    put16(&mut descriptor, 2, 0x8004);
    let dacl_offset = 20;
    let owner_offset = dacl_offset + dacl.len();
    let group_offset = owner_offset + administrators.len();
    put32(&mut descriptor, 4, owner_offset as u32);
    put32(&mut descriptor, 8, group_offset as u32);
    put32(&mut descriptor, 16, dacl_offset as u32);
    descriptor.extend_from_slice(&dacl);
    descriptor.extend_from_slice(&administrators);
    descriptor.extend_from_slice(&administrators);
    descriptor
}

/// NtfsHashSecurityDescriptor: `rol(hash, 3) + dword` sobre o descritor.
fn security_hash(descriptor: &[u8]) -> u32 {
    descriptor.chunks_exact(4).fold(0u32, |hash, word| hash.rotate_left(3).wrapping_add(u32::from_le_bytes([word[0], word[1], word[2], word[3]])))
}

/// Metadados de um caminho do volume: os atributos de arquivo e o descritor
/// de segurança autorrelativo próprios (sem descritor, o comum do volume)
/// e, num diretório, a entrada no volume mesmo sem arquivos dentro. O caminho
/// de um arquivo é o de um arquivo extra.
pub struct Node {
    pub path: String,
    pub directory: bool,
    pub attributes: u32,
    pub security: Option<Vec<u8>>,
}

/// Os atributos que o $STANDARD_INFORMATION e o $FILE_NAME guardam: os de
/// FILE_ATTRIBUTE_VALID_FLAGS (0x7FB7) menos o de diretório, que o NTFS
/// marca no registro e no DUP_FILE_NAME_INDEX_PRESENT do $FILE_NAME, e o de
/// ponto de reanálise, que exige o atributo $REPARSE_POINT no registro.
const STORED_ATTRIBUTES: u32 = 0x7FB7 & !0x10 & !0x400;

/// Os descritores do $Secure: o comum do volume no SecurityId 0x100 e um
/// SecurityId para cada descritor distinto dos nós, em ordem de aparição.
struct Descriptors(Vec<Vec<u8>>);

impl Descriptors {
    fn id(&mut self, descriptor: &[u8]) -> Result<u32, String> {
        if descriptor.len() < 20 || descriptor.len() % 4 != 0 || descriptor[0] != 1 {
            return Err(format!("descritor de seguranca invalido ({} bytes)", descriptor.len()));
        }
        let index = match self.0.iter().position(|known| known == descriptor) {
            Some(index) => index,
            None => {
                self.0.push(descriptor.to_vec());
                self.0.len() - 1
            }
        };
        Ok(SECURITY_ID + index as u32)
    }
}

/// O $SDS e as entradas dos índices do $Secure. Cada entrada do $SDS é o
/// SECURITY_DESCRIPTOR_HEADER (hash, SecurityId, deslocamento no $SDS e
/// tamanho) seguido do descritor, alinhada a 16 bytes no primeiro bloco de
/// 256 KB, com a cópia do bloco no seguinte; o $SII tem uma entrada por
/// SecurityId e o $SDH uma por hash e SecurityId (colação
/// COLLATION_NTOFS_SECURITY_HASH: o hash e depois o SecurityId), ambas com o
/// cabeçalho como dados.
fn secure_streams(descriptors: &[Vec<u8>]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let mut block = Vec::new();
    let mut sii = Vec::new();
    let mut sdh = Vec::new();
    for (index, descriptor) in descriptors.iter().enumerate() {
        let id = SECURITY_ID + index as u32;
        let hash = security_hash(descriptor);
        let offset = block.len().next_multiple_of(16);
        block.resize(offset, 0);
        let mut header = vec![0u8; 20];
        put32(&mut header, 0, hash);
        put32(&mut header, 4, id);
        put64(&mut header, 8, offset as u64);
        put32(&mut header, 16, (20 + descriptor.len()) as u32);
        block.extend_from_slice(&header);
        block.extend_from_slice(descriptor);
        sii.push((id, view_entry(&id.to_le_bytes(), &header, &[])));
        let key = [hash.to_le_bytes(), id.to_le_bytes()].concat();
        sdh.push(((hash, id), view_entry(&key, &header, &[b'I', 0, b'I', 0])));
    }
    if block.len() > SDS_MIRROR {
        return Err(format!("$SDS com {} bytes nao cabe no primeiro bloco", block.len()));
    }
    sii.sort_by_key(|(id, _)| *id);
    sdh.sort_by_key(|(key, _)| *key);
    let mut sds = vec![0u8; SDS_MIRROR + block.len()];
    sds[..block.len()].copy_from_slice(&block);
    sds[SDS_MIRROR..].copy_from_slice(&block);
    let sii = sii.into_iter().flat_map(|(_, entry)| entry).collect();
    let sdh = sdh.into_iter().flat_map(|(_, entry)| entry).collect();
    Ok((sds, sii, sdh))
}

/// Tabela de maiúsculas do l_intl.nls (o trie de três níveis da seção de
/// maiúsculas), como o kernel a lê.
fn upcase_table() -> Result<Vec<u8>, String> {
    let windows = std::env::var("SystemRoot").unwrap_or_else(|_| String::from("C:/Windows"));
    let path = Path::new(&windows).join("System32/l_intl.nls");
    let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let word = |offset: usize| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    if bytes.len() < 516 || word(0) != 1 {
        return Err(format!("{}: cabecalho de maiusculas invalido", path.display()));
    }
    let end = 2 + word(2) as usize * 2;
    if end < 516 || end > bytes.len() {
        return Err(format!("{}: tamanho de maiusculas invalido", path.display()));
    }
    let trie: Vec<u16> = (4..end).step_by(2).map(word).collect();
    let read = |index: usize| trie.get(index).copied().ok_or_else(|| format!("{}: trie de maiusculas invalido", path.display()));
    let mut table = Vec::with_capacity(131_072);
    for unit in 0..=u16::MAX {
        // RtlUpcaseUnicodeChar: 'a'..'z' direto, o resto abaixo de U+00C0
        // inalterado e a tabela daí para cima.
        let upper = match unit {
            0x61..=0x7A => unit - 0x20,
            0..=0xBF => unit,
            _ => {
                let first = read((unit >> 8) as usize)? as usize;
                let second = read(first + ((unit >> 4) & 15) as usize)? as usize;
                unit.wrapping_add(read(second + (unit & 15) as usize)?)
            }
        };
        table.extend_from_slice(&upper.to_le_bytes());
    }
    Ok(table)
}

/// Bytes do $AttrDef.
fn attribute_definitions() -> Vec<u8> {
    let mut table = vec![0u8; ATTRIBUTE_DEFINITIONS.len() * 0xA0];
    for (index, &(name, kind, flags, minimum, maximum)) in ATTRIBUTE_DEFINITIONS.iter().enumerate() {
        let entry = &mut table[index * 0xA0..(index + 1) * 0xA0];
        let units = utf16(name);
        entry[..units.len()].copy_from_slice(&units);
        put32(entry, 0x80, kind);
        put32(entry, 0x8C, flags);
        put64(entry, 0x90, minimum as u64);
        put64(entry, 0x98, maximum as u64);
    }
    table
}

/// Monta a imagem com os arquivos extras `(nome no volume, bytes)` e os
/// metadados de `nodes` e a grava em `output`; devolve o tamanho.
pub fn build(output: &Path, extras: &[(String, Vec<u8>)], nodes: &[Node], free_space_mib: usize, extra_records: usize) -> Result<usize, String> {
    let image = volume_image(extras, nodes, free_space_mib, extra_records, 0)?;
    write(output, &image)?;
    Ok(image.len())
}

fn write(output: &Path, image: &[u8]) -> Result<(), String> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    fs::write(output, image).map_err(|error| format!("{}: {error}", output.display()))
}

/// Primeiro setor da partição do disco particionado (o alinhamento de 1 MB
/// que o particionador do Windows usa).
const PARTITION_START_LBA: usize = 2048;
/// Tipo de partição MBR do NTFS (PARTITION_IFS).
const PARTITION_IFS: u8 = 0x07;
/// Assinatura de disco MBR do disco particionado.
const DISK_SIGNATURE: u32 = 0x4F4E_5654;

/// Grava em `output` um disco particionado: MBR com uma partição NTFS
/// (tipo 0x07, ativa, a partir do LBA 2048) que ocupa o volume inteiro, com
/// os arquivos extras. O setor de boot do volume leva o deslocamento da
/// partição em HiddenSectors, como o formatador grava. Devolve o tamanho.
pub fn build_partitioned(output: &Path, extras: &[(String, Vec<u8>)], free_space_mib: usize, extra_records: usize) -> Result<usize, String> {
    let volume = volume_image(extras, &[], free_space_mib, extra_records, PARTITION_START_LBA as u32)?;
    let volume_sectors = volume.len() / SECTOR;
    let mut disk = vec![0u8; (PARTITION_START_LBA + volume_sectors) * SECTOR];
    put32(&mut disk, 0x1B8, DISK_SIGNATURE);
    let entry = 0x1BE;
    disk[entry] = 0x80;
    // CHS de início e fim: os valores de um LBA além de 1024 cilindros.
    disk[entry + 1..entry + 4].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    disk[entry + 4] = PARTITION_IFS;
    disk[entry + 5..entry + 8].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    put32(&mut disk, entry + 8, PARTITION_START_LBA as u32);
    put32(&mut disk, entry + 12, volume_sectors as u32);
    disk[510] = 0x55;
    disk[511] = 0xAA;
    disk[PARTITION_START_LBA * SECTOR..].copy_from_slice(&volume);
    write(output, &disk)?;
    Ok(disk.len())
}

/// A imagem do volume; `hidden_sectors` é o LBA do início da partição que a
/// contém (0 num disco sem partições). Um nome terminado em '/' é um
/// diretório vazio: uma pasta da instalação sem arquivo da imagem dentro.
fn volume_image(entries: &[(String, Vec<u8>)], nodes: &[Node], free_space_mib: usize, extra_records: usize, hidden_sectors: u32) -> Result<Vec<u8>, String> {
    let extras: Vec<&(String, Vec<u8>)> = entries.iter().filter(|(name, _)| !name.ends_with('/')).collect();
    // Diretórios intermediários dos nomes com '/' e os vazios, na ordem de
    // criação, e os diretórios dos nós (com os pais).
    let mut directories: Vec<String> = Vec::new();
    let names = entries.iter().map(|(name, _)| (name.as_str(), name.ends_with('/'))).chain(nodes.iter().filter(|node| node.directory).map(|node| (node.path.as_str(), true)));
    for (name, directory) in names {
        let components: Vec<&str> = name.trim_end_matches('/').split('/').collect();
        if components.iter().any(|component| component.is_empty()) {
            return Err(format!("caminho NTFS invalido: {name}"));
        }
        let depths = if directory { components.len() } else { components.len() - 1 };
        for depth in 1..=depths {
            let directory = components[..depth].join("/");
            if !directories.iter().any(|known| known.eq_ignore_ascii_case(&directory)) {
                directories.push(directory);
            }
        }
    }
    // Atributos e SecurityId dos nós, pelo caminho em maiúsculas.
    let mut descriptors = Descriptors(vec![security_descriptor()]);
    let mut metadata: BTreeMap<String, (u32, u32)> = BTreeMap::new();
    for node in nodes {
        let file = extras.iter().any(|(name, _)| name.eq_ignore_ascii_case(&node.path));
        if file == node.directory {
            return Err(format!("no do volume sem {}: {}", if node.directory { "diretorio (e um arquivo extra)" } else { "arquivo extra" }, node.path));
        }
        let security_id = match &node.security {
            Some(descriptor) => descriptors.id(descriptor).map_err(|error| format!("{}: {error}", node.path))?,
            None => SECURITY_ID,
        };
        if metadata.insert(node.path.to_uppercase(), (node.attributes & STORED_ATTRIBUTES, security_id)).is_some() {
            return Err(format!("no do volume repetido: {}", node.path));
        }
    }
    let first_extra = HELLO_RECORD + 1;
    let directory_record = |path: &str| -> u64 {
        if path.is_empty() {
            ROOT
        } else {
            first_extra + extras.len() as u64 + directories.iter().position(|known| known.eq_ignore_ascii_case(path)).unwrap_or(0) as u64
        }
    };
    let split = |path: &str| -> (String, String) {
        match path.rsplit_once('/') {
            Some((parent, leaf)) => (parent.to_string(), leaf.to_string()),
            None => (String::new(), path.to_string()),
        }
    };
    // Os arquivos do $Extend vêm depois dos de usuário
    // (NtfsCheckIndexEntryFileReference: registro < 16 só na raiz).
    let quota = first_extra + (extras.len() + directories.len()) as u64;
    let (object_id, reparse) = (quota + 1, quota + 2);
    let record_count = reparse as usize + 1;
    let mft_capacity = 512usize.max(1usize << bit_length((record_count + extra_records - 1) as u64));
    let mft_clusters = mft_capacity * RECORD_SIZE / CLUSTER;
    let mut clusters = Clusters { next: MFT_LCN + mft_clusters, writes: Vec::new() };
    // ---- dados dos arquivos do sistema
    // O $BITMAP do $MFT é sempre não residente: o NTFS pré-carrega a
    // alocação dele na montagem.
    let mft_bitmap = low_bits(record_count, mft_capacity.div_ceil(64) * 8);
    let mft_bitmap_length = mft_bitmap.len() as u64;
    let (mft_bitmap_lcn, mft_bitmap_count) = clusters.allocate(mft_bitmap);
    let (mirror_lcn, mirror_count) = clusters.allocate(vec![0u8; MIRROR_RECORDS * RECORD_SIZE]);
    let (log_lcn, log_count) = clusters.allocate(vec![0xFFu8; LOG_FILE_BYTES]);
    let attribute_table = attribute_definitions();
    let attribute_table_length = attribute_table.len() as u64;
    let (attrdef_lcn, attrdef_count) = clusters.allocate(attribute_table);
    let upcase = upcase_table()?;
    let upcase_length = upcase.len() as u64;
    let (upcase_lcn, upcase_count) = clusters.allocate(upcase);
    // $SDS: os descritores no primeiro bloco de 256 KB e a cópia no seguinte.
    let (sds, sii_entries, sdh_entries) = secure_streams(&descriptors.0)?;
    let sds_length = sds.len();
    let (sds_lcn, sds_count) = clusters.allocate(sds);
    // ---- dados dos arquivos extras
    let mut file_runs = Vec::new();
    for (_, blob) in &extras {
        file_runs.push(if blob.is_empty() { None } else { Some(clusters.allocate(blob.clone())) });
    }
    // ---- registros
    let mut records: Vec<(u64, u16, Vec<Attribute>)> = Vec::new();
    // Filhos de cada diretório: (registro, chave $FILE_NAME).
    let mut children: BTreeMap<u64, Vec<(u64, Vec<u8>)>> = BTreeMap::new();
    let system_file = |records: &mut Vec<(u64, u16, Vec<Attribute>)>, children: &mut BTreeMap<u64, Vec<(u64, Vec<u8>)>>, number: u64, parent: u64, name: &str, flags: u16, file_attributes: u32, data: (u64, u64), mut attributes: Vec<Attribute>| -> Result<(), String> {
        let value = file_name_value(parent, name, file_attributes, data.0, data.1, 3)?;
        children.entry(parent).or_default().push((number, value.clone()));
        let mut list = vec![standard_information(HIDDEN_SYSTEM), file_name_attribute(value)];
        list.append(&mut attributes);
        records.push((number, flags, list));
        Ok(())
    };
    let bytes_of = |count: u64| count * CLUSTER as u64;
    system_file(&mut records, &mut children, 1, ROOT, "$MFTMirr", IN_USE, HIDDEN_SYSTEM, (bytes_of(mirror_count), (MIRROR_RECORDS * RECORD_SIZE) as u64), vec![nonresident(0x80, "", vec![(Some(mirror_lcn), mirror_count)], (MIRROR_RECORDS * RECORD_SIZE) as u64)])?;
    system_file(&mut records, &mut children, 2, ROOT, "$LogFile", IN_USE, HIDDEN_SYSTEM, (bytes_of(log_count), LOG_FILE_BYTES as u64), vec![nonresident(0x80, "", vec![(Some(log_lcn), log_count)], LOG_FILE_BYTES as u64)])?;
    let mut volume_information = vec![0u8; 12];
    volume_information[8] = 3;
    volume_information[9] = 1;
    system_file(&mut records, &mut children, 3, ROOT, "$Volume", IN_USE, HIDDEN_SYSTEM, (0, 0), vec![resident(0x60, "", utf16(VOLUME_LABEL)), resident(0x70, "", volume_information)])?;
    system_file(&mut records, &mut children, 4, ROOT, "$AttrDef", IN_USE, HIDDEN_SYSTEM, (bytes_of(attrdef_count), attribute_table_length), vec![nonresident(0x80, "", vec![(Some(attrdef_lcn), attrdef_count)], attribute_table_length)])?;
    system_file(&mut records, &mut children, 7, ROOT, "$Boot", IN_USE, HIDDEN_SYSTEM, (bytes_of(BOOT_CLUSTERS as u64), (BOOT_CLUSTERS * CLUSTER) as u64), vec![nonresident(0x80, "", vec![(Some(0), BOOT_CLUSTERS as u64)], (BOOT_CLUSTERS * CLUSTER) as u64)])?;
    system_file(&mut records, &mut children, 10, ROOT, "$UpCase", IN_USE, HIDDEN_SYSTEM, (bytes_of(upcase_count), upcase_length), vec![nonresident(0x80, "", vec![(Some(upcase_lcn), upcase_count)], upcase_length)])?;
    system_file(&mut records, &mut children, 9, ROOT, "$Secure", VIEW_INDEX, VIEW_INDEX_DUPLICATE | HIDDEN_SYSTEM, (0, 0), vec![
        nonresident(0x80, "$SDS", vec![(Some(sds_lcn), sds_count)], sds_length as u64),
        resident(0x90, "$SDH", index_root_value(0, 0x12, &[sdh_entries, end_entry(None)].concat(), false)),
        resident(0x90, "$SII", index_root_value(0, 0x10, &[sii_entries, end_entry(None)].concat(), false)),
    ])?;
    // Arquivos do $Extend: índices de visão vazios.
    system_file(&mut records, &mut children, quota, EXTEND, "$Quota", VIEW_INDEX, VIEW_INDEX_DUPLICATE | HIDDEN_SYSTEM, (0, 0), vec![resident(0x90, "$O", index_root_value(0, 0x11, &end_entry(None), false)), resident(0x90, "$Q", index_root_value(0, 0x10, &end_entry(None), false))])?;
    system_file(&mut records, &mut children, object_id, EXTEND, "$ObjId", VIEW_INDEX, VIEW_INDEX_DUPLICATE | HIDDEN_SYSTEM, (0, 0), vec![resident(0x90, "$O", index_root_value(0, 0x13, &end_entry(None), false))])?;
    system_file(&mut records, &mut children, reparse, EXTEND, "$Reparse", VIEW_INDEX, VIEW_INDEX_DUPLICATE | HIDDEN_SYSTEM, (0, 0), vec![resident(0x90, "$R", index_root_value(0, 0x13, &end_entry(None), false))])?;
    // Registros 12..15: reservados, em uso.
    for number in 12..16 {
        records.push((number, IN_USE, vec![standard_information(HIDDEN_SYSTEM), resident(0x80, "", Vec::new())]));
    }
    // HELLO.TXT e os arquivos extras.
    let hello = file_name_value(ROOT, HELLO_NAME, FILE_ARCHIVE, 0, HELLO_DATA.len() as u64, name_space(HELLO_NAME))?;
    children.entry(ROOT).or_default().push((HELLO_RECORD, hello.clone()));
    records.push((HELLO_RECORD, IN_USE, vec![standard_information(0), file_name_attribute(hello), resident(0x80, "", HELLO_DATA.to_vec())]));
    for (index, (name, blob)) in extras.iter().enumerate() {
        let number = first_extra + index as u64;
        let (parent_path, leaf) = split(name);
        let parent = directory_record(&parent_path);
        let (data, allocated) = match file_runs[index] {
            Some((lcn, count)) => (nonresident(0x80, "", vec![(Some(lcn), count)], blob.len() as u64), count * CLUSTER as u64),
            None => (resident(0x80, "", Vec::new()), 0),
        };
        // Sem nó: o $STANDARD_INFORMATION sem atributos e o arquivo no
        // índice do pai como arquivo pronto para backup.
        let (attributes, security_id, listed) = match metadata.get(&name.to_uppercase()) {
            Some(&(attributes, security_id)) => (attributes, security_id, attributes),
            None => (0, SECURITY_ID, FILE_ARCHIVE),
        };
        let value = file_name_value(parent, &leaf, listed, allocated, blob.len() as u64, name_space(&leaf))?;
        children.entry(parent).or_default().push((number, value.clone()));
        records.push((number, IN_USE, vec![standard_information_with(attributes, security_id), file_name_attribute(value), data]));
    }
    // Diretórios: o $FILE_NAME de cada um no pai; os índices depois.
    let mut directory_names = Vec::new();
    for directory in &directories {
        let (parent_path, leaf) = split(directory);
        let (attributes, security_id) = metadata.get(&directory.to_uppercase()).copied().unwrap_or((0, SECURITY_ID));
        let value = file_name_value(directory_record(&parent_path), &leaf, attributes | DIRECTORY_DUPLICATE, 0, 0, name_space(&leaf))?;
        children.entry(directory_record(&parent_path)).or_default().push((directory_record(directory), value.clone()));
        directory_names.push((directory_record(directory), value, attributes, security_id));
    }
    let root_name = file_name_value(ROOT, ".", DIRECTORY_DUPLICATE | HIDDEN_SYSTEM, 0, 0, 3)?;
    let extend_name = file_name_value(ROOT, "$Extend", DIRECTORY_DUPLICATE | HIDDEN_SYSTEM, 0, 0, 3)?;
    let mft_bytes = (mft_capacity * RECORD_SIZE) as u64;
    let mft_name = file_name_value(ROOT, "$MFT", HIDDEN_SYSTEM, mft_bytes, mft_bytes, 3)?;
    let badclus_name = file_name_value(ROOT, "$BadClus", HIDDEN_SYSTEM, 0, 0, 3)?;
    // O $Bitmap entra na raiz com tamanhos provisórios: o comprimento da
    // chave não depende deles, então o índice da raiz ocupa o mesmo espaço
    // antes e depois de o volume ser dimensionado.
    let bitmap_name = |allocated: u64, size: u64| file_name_value(ROOT, "$Bitmap", HIDDEN_SYSTEM, allocated, size, 3);
    for (number, value) in [(ROOT, root_name.clone()), (EXTEND, extend_name.clone()), (0, mft_name.clone()), (6, bitmap_name(0, 0)?), (8, badclus_name.clone())] {
        children.entry(ROOT).or_default().push((number, value));
    }
    // Entradas de índice em ordem de colação (maiúsculas, como o NT).
    let sorted = |parent: u64, children: &BTreeMap<u64, Vec<(u64, Vec<u8>)>>| -> Vec<(u64, Vec<u8>)> {
        let mut listed = children.get(&parent).cloned().unwrap_or_default();
        listed.sort_by_key(|(_, value)| {
            let length = value[64] as usize;
            String::from_utf16_lossy(&value[66..66 + length * 2].chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect::<Vec<_>>()).to_uppercase()
        });
        listed
    };
    // ---- índices dos diretórios (residentes ou em blocos)
    let index_room = |attributes: &[Attribute]| RECORD_SIZE - first_attribute_offset() - 8 - attributes_size(attributes) - 256;
    let mut directory_records = Vec::new();
    for (number, value, attributes, security_id) in &directory_names {
        let base = vec![standard_information_with(*attributes, *security_id), file_name_attribute(value.clone())];
        let index = directory_index(&sorted(*number, &children), index_room(&base), &mut clusters)?;
        directory_records.push((*number, base, index));
    }
    let extend_base = vec![standard_information(HIDDEN_SYSTEM), file_name_attribute(extend_name)];
    let extend_index = directory_index(&sorted(EXTEND, &children), index_room(&extend_base), &mut clusters)?;
    let root_base = vec![standard_information(0), file_name_attribute(root_name)];
    let root_room = index_room(&root_base);
    let index_start = clusters.next;
    let provisional = directory_index(&sorted(ROOT, &children), root_room, &mut Clusters { next: index_start, writes: Vec::new() })?;
    let index_end = index_start + provisional.iter().map(|attribute| match &attribute.body {
        Body::NonResident(runs, _) => runs.iter().map(|&(_, count)| count as usize).sum(),
        Body::Resident(..) => 0,
    }).sum::<usize>();
    // ---- tamanho do volume e do $Bitmap
    let bitmap_lcn = index_end;
    let free_clusters = free_space_mib * 1_048_576 / CLUSTER;
    let mut volume_clusters = bitmap_lcn + free_clusters;
    let (bitmap_bytes, bitmap_clusters) = loop {
        let bitmap_bytes = volume_clusters.div_ceil(64) * 8;
        let bitmap_clusters = bitmap_bytes.div_ceil(CLUSTER);
        let total = bitmap_lcn + bitmap_clusters + free_clusters;
        if total == volume_clusters {
            break (bitmap_bytes, bitmap_clusters);
        }
        volume_clusters = total;
    };
    let bitmap_value = bitmap_name((bitmap_clusters * CLUSTER) as u64, bitmap_bytes as u64)?;
    if let Some(entry) = children.get_mut(&ROOT).and_then(|listed| listed.iter_mut().find(|(number, _)| *number == 6)) {
        entry.1 = bitmap_value.clone();
    }
    let root_index = directory_index(&sorted(ROOT, &children), root_room, &mut clusters)?;
    if clusters.next != index_end {
        return Err("indice da raiz mudou de tamanho".into());
    }
    let volume_bytes = (volume_clusters * CLUSTER) as u64;
    let total_sectors = volume_clusters + 1;
    // ---- registros que dependem do tamanho do volume
    records.push((0, IN_USE, vec![standard_information(HIDDEN_SYSTEM), file_name_attribute(mft_name), nonresident(0x80, "", vec![(Some(MFT_LCN as u64), mft_clusters as u64)], mft_bytes), nonresident(0xB0, "", vec![(Some(mft_bitmap_lcn), mft_bitmap_count)], mft_bitmap_length)]));
    records.push((6, IN_USE, vec![standard_information(HIDDEN_SYSTEM), file_name_attribute(bitmap_value), nonresident(0x80, "", vec![(Some(bitmap_lcn as u64), bitmap_clusters as u64)], bitmap_bytes as u64)]));
    records.push((8, IN_USE, vec![standard_information(HIDDEN_SYSTEM), file_name_attribute(badclus_name), resident(0x80, "", Vec::new()), nonresident(0x80, "$Bad", vec![(None, volume_clusters as u64)], volume_bytes)]));
    let mut root_attributes = root_base;
    root_attributes.extend(root_index);
    records.push((ROOT, DIRECTORY, root_attributes));
    let mut extend_attributes = extend_base;
    extend_attributes.extend(extend_index);
    records.push((EXTEND, DIRECTORY, extend_attributes));
    for (number, mut base, index) in directory_records {
        base.extend(index);
        records.push((number, DIRECTORY, base));
    }
    // ---- imagem
    let mut image = vec![0u8; total_sectors * SECTOR];
    let mut boot = vec![0u8; SECTOR];
    boot[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
    boot[3..11].copy_from_slice(b"NTFS    ");
    put16(&mut boot, 11, SECTOR as u16);
    boot[13] = (CLUSTER / SECTOR) as u8;
    boot[0x15] = 0xF8; // disco fixo
    put16(&mut boot, 0x18, 63);
    put16(&mut boot, 0x1A, 255);
    put32(&mut boot, 0x1C, hidden_sectors);
    put32(&mut boot, 0x24, 0x0080_0080);
    put64(&mut boot, 0x28, volume_clusters as u64 * (CLUSTER / SECTOR) as u64);
    put64(&mut boot, 0x30, MFT_LCN as u64);
    put64(&mut boot, 0x38, mirror_lcn);
    boot[0x40] = (-12i8) as u8; // registro = 2^12
    boot[0x44] = (INDEX_BLOCK / CLUSTER) as u8;
    put64(&mut boot, 0x48, u64::from_le_bytes(*b"OPENNT!!"));
    boot[510] = 0x55;
    boot[511] = 0xAA;
    image[..SECTOR].copy_from_slice(&boot);
    let last = image.len() - SECTOR;
    image[last..].copy_from_slice(&boot);
    for (lcn, bytes) in &clusters.writes {
        image[lcn * CLUSTER..lcn * CLUSTER + bytes.len()].copy_from_slice(bytes);
    }
    // $Bitmap: todo o espaço até o fim dos índices, o próprio bitmap e os
    // bits além do último cluster.
    let mut bitmap = vec![0u8; bitmap_bytes];
    let mut mark_used = |start: usize, count: usize| {
        for cluster in start..start + count {
            bitmap[cluster / 8] |= 1 << (cluster % 8);
        }
    };
    mark_used(0, index_end);
    mark_used(bitmap_lcn, bitmap_clusters);
    mark_used(volume_clusters, bitmap_bytes * 8 - volume_clusters);
    image[bitmap_lcn * CLUSTER..bitmap_lcn * CLUSTER + bitmap.len()].copy_from_slice(&bitmap);
    let mft_offset = MFT_LCN * CLUSTER;
    for (number, flags, attributes) in &records {
        let at = mft_offset + *number as usize * RECORD_SIZE;
        image[at..at + RECORD_SIZE].copy_from_slice(&make_record(*number, *flags, attributes)?);
    }
    let mirror = image[mft_offset..mft_offset + MIRROR_RECORDS * RECORD_SIZE].to_vec();
    let mirror_offset = mirror_lcn as usize * CLUSTER;
    image[mirror_offset..mirror_offset + mirror.len()].copy_from_slice(&mirror);
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
    }

    fn dword(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    fn qword(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }

    /// O registro `number` da MFT com a USA desfeita.
    fn record(image: &[u8], number: u64) -> Vec<u8> {
        let at = MFT_LCN * CLUSTER + number as usize * RECORD_SIZE;
        let mut record = image[at..at + RECORD_SIZE].to_vec();
        let (usa, count) = (word(&record, 4) as usize, word(&record, 6) as usize);
        for index in 1..count {
            let tail = index * SECTOR - 2;
            let original = [record[usa + index * 2], record[usa + index * 2 + 1]];
            record[tail..tail + 2].copy_from_slice(&original);
        }
        record
    }

    /// Um atributo lido: tipo, nome, valor residente, primeira run (LCN,
    /// clusters) e tamanho real do não residente.
    type Read = (u32, String, Vec<u8>, Option<(u64, u64)>, u64);

    fn attributes(record: &[u8]) -> Vec<Read> {
        let mut list = Vec::new();
        let mut offset = word(record, 20) as usize;
        while dword(record, offset) != 0xFFFF_FFFF {
            let length = dword(record, offset + 4) as usize;
            let name_length = record[offset + 9] as usize;
            let name_offset = offset + word(record, offset + 10) as usize;
            let name = String::from_utf16_lossy(&(0..name_length).map(|index| word(record, name_offset + index * 2)).collect::<Vec<_>>());
            if record[offset + 8] == 0 {
                let value_offset = offset + word(record, offset + 20) as usize;
                list.push((dword(record, offset), name, record[value_offset..value_offset + dword(record, offset + 16) as usize].to_vec(), None, 0));
            } else {
                let run = offset + word(record, offset + 32) as usize;
                let header = record[run] as usize;
                let (count_length, lcn_length) = (header & 15, header >> 4);
                let mut count = [0u8; 8];
                count[..count_length].copy_from_slice(&record[run + 1..run + 1 + count_length]);
                let mut lcn = [0u8; 8];
                lcn[..lcn_length].copy_from_slice(&record[run + 1 + count_length..run + 1 + count_length + lcn_length]);
                list.push((dword(record, offset), name, Vec::new(), Some((u64::from_le_bytes(lcn), u64::from_le_bytes(count))), qword(record, offset + 48)));
            }
            offset += length;
        }
        list
    }

    /// Os registros de usuário em uso: caminho → (flags do registro,
    /// atributos e SecurityId do $STANDARD_INFORMATION, atributos do
    /// $FILE_NAME).
    fn tree(image: &[u8]) -> BTreeMap<String, (u16, u32, u32, u32)> {
        let mut named = BTreeMap::new();
        for number in 0..512u64 {
            let record = record(image, number);
            if &record[..4] != b"FILE" || word(&record, 22) & IN_USE == 0 {
                continue;
            }
            let found = attributes(&record);
            let Some((_, _, standard, _, _)) = found.iter().find(|attribute| attribute.0 == 0x10) else { continue };
            let Some((_, _, name, _, _)) = found.iter().find(|attribute| attribute.0 == 0x30) else { continue };
            let leaf = String::from_utf16_lossy(&(0..name[64] as usize).map(|index| word(name, 66 + index * 2)).collect::<Vec<_>>());
            named.insert(number, (qword(name, 0) & 0xFFFF_FFFF_FFFF, leaf, (word(&record, 22), dword(standard, 32), dword(standard, 52), dword(name, 56))));
        }
        let path = |mut number: u64| {
            let mut parts = Vec::new();
            while number != ROOT {
                let (parent, leaf, _) = &named[&number];
                parts.push(leaf.clone());
                number = *parent;
            }
            parts.reverse();
            parts.join("/")
        };
        named.iter().filter(|(&number, _)| number >= 16).map(|(&number, (_, _, info))| (path(number), *info)).collect()
    }

    /// O descritor comum com outra subautoridade no dono.
    fn descriptor_with_owner(owner: u8) -> Vec<u8> {
        let mut descriptor = security_descriptor();
        let at = dword(&descriptor, 4) as usize + 8;
        descriptor[at] = owner;
        descriptor
    }

    /// Nós com atributos e descritores: cada descritor distinto ganha um
    /// SecurityId, o diretório vazio entra no volume, o arquivo sem nó fica
    /// como antes, e o $Secure lista os três descritores.
    #[test]
    fn nodes_keep_attributes_and_descriptors() {
        let (first, second) = (descriptor_with_owner(18), descriptor_with_owner(19));
        let extras = vec![(String::from("Users/Default/NTUSER.DAT"), vec![7u8; 1000]), (String::from("PLAIN.TXT"), b"x".to_vec())];
        let nodes = vec![
            Node { path: String::from("Users"), directory: true, attributes: 0x11, security: Some(first.clone()) },
            Node { path: String::from("Users/Default"), directory: true, attributes: 0x13, security: Some(second.clone()) },
            Node { path: String::from("Users/Default/NTUSER.DAT"), directory: false, attributes: 0x20, security: Some(first.clone()) },
            Node { path: String::from("Users/Default/Desktop"), directory: true, attributes: 0x11, security: Some(first.clone()) },
            Node { path: String::from("Users/Default/AppData/Local"), directory: true, attributes: 0x2410, security: None },
        ];
        let image = volume_image(&extras, &nodes, 1, 0, 0).unwrap();
        let tree = tree(&image);
        assert_eq!(tree["Users"], (DIRECTORY, 0x01, 0x101, 0x01 | DIRECTORY_DUPLICATE));
        assert_eq!(tree["Users/Default"], (DIRECTORY, 0x03, 0x102, 0x03 | DIRECTORY_DUPLICATE));
        assert_eq!(tree["Users/Default/NTUSER.DAT"], (IN_USE, 0x20, 0x101, 0x20));
        assert_eq!(tree["Users/Default/Desktop"], (DIRECTORY, 0x01, 0x101, 0x01 | DIRECTORY_DUPLICATE));
        assert_eq!(tree["Users/Default/AppData"], (DIRECTORY, 0, SECURITY_ID, DIRECTORY_DUPLICATE));
        assert_eq!(tree["Users/Default/AppData/Local"], (DIRECTORY, 0x2000, SECURITY_ID, 0x2000 | DIRECTORY_DUPLICATE));
        assert_eq!(tree["PLAIN.TXT"], (IN_USE, 0, SECURITY_ID, FILE_ARCHIVE));
        // $Secure: as entradas do $SDS alinhadas a 16 com o hash, o
        // SecurityId e o deslocamento, e a cópia no bloco seguinte.
        let secure = attributes(&record(&image, 9));
        let Some((_, _, _, Some((lcn, _)), length)) = secure.iter().find(|attribute| attribute.0 == 0x80) else { panic!("$SDS ausente ou residente") };
        let start = *lcn as usize * CLUSTER;
        let sds = &image[start..start + *length as usize];
        let mut offset = 0usize;
        for (index, descriptor) in [security_descriptor(), first, second].iter().enumerate() {
            offset = offset.next_multiple_of(16);
            let id = SECURITY_ID + index as u32;
            assert_eq!((dword(sds, offset), dword(sds, offset + 4), qword(sds, offset + 8), dword(sds, offset + 16) as usize), (security_hash(descriptor), id, offset as u64, 20 + descriptor.len()));
            assert_eq!(&sds[offset + 20..offset + 20 + descriptor.len()], descriptor.as_slice());
            offset += 20 + descriptor.len();
        }
        assert_eq!(*length as usize, SDS_MIRROR + offset);
        assert_eq!(&sds[..offset], &sds[SDS_MIRROR..]);
        // Os índices: as chaves do $SII em ordem de SecurityId e as do $SDH
        // em ordem de hash e SecurityId.
        let keys = |name: &str| {
            let (_, _, root, _, _) = secure.iter().find(|attribute| attribute.0 == 0x90 && attribute.1 == name).unwrap();
            let mut at = 16 + dword(root, 16) as usize;
            let mut keys = Vec::new();
            while word(root, at + 12) & 2 == 0 {
                keys.push(root[at + 16..at + 16 + word(root, at + 10) as usize].to_vec());
                at += word(root, at + 8) as usize;
            }
            keys
        };
        assert_eq!(keys("$SII"), (0..3u32).map(|index| (SECURITY_ID + index).to_le_bytes().to_vec()).collect::<Vec<_>>());
        let sdh: Vec<(u32, u32)> = keys("$SDH").iter().map(|key| (dword(key, 0), dword(key, 4))).collect();
        let mut sorted = sdh.clone();
        sorted.sort();
        assert_eq!(sdh.len(), 3);
        assert_eq!(sdh, sorted);
    }

    /// Sem nós, o $Secure tem só o descritor comum, como antes.
    #[test]
    fn without_nodes_the_volume_has_one_descriptor() {
        let image = volume_image(&[(String::from("A.TXT"), b"a".to_vec())], &[], 1, 0, 0).unwrap();
        let secure = attributes(&record(&image, 9));
        let (_, _, _, _, length) = secure.iter().find(|attribute| attribute.0 == 0x80).unwrap();
        assert_eq!(*length as usize, SDS_MIRROR + 20 + security_descriptor().len());
    }

    #[test]
    fn nodes_must_match_the_files() {
        let extras = vec![(String::from("Users/A.TXT"), b"a".to_vec())];
        let node = |path: &str, directory: bool| Node { path: String::from(path), directory, attributes: 0, security: None };
        assert!(volume_image(&extras, &[node("Users/B.TXT", false)], 1, 0, 0).is_err());
        assert!(volume_image(&extras, &[node("Users/A.TXT", true)], 1, 0, 0).is_err());
        assert!(volume_image(&extras, &[node("Users", true), node("USERS", true)], 1, 0, 0).is_err());
        assert!(volume_image(&extras, &[Node { path: String::from("Users"), directory: true, attributes: 0, security: Some(vec![1, 0, 4]) }], 1, 0, 0).is_err());
    }
}
