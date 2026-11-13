//! Gera `ntfs.img`: um NTFS válido para o leitor do kernel (`drivers/fs/ntfs`).
//!
//! Layout: setor = cluster = 512 B, MFT no LCN 4, registros de 16 KB.
//! Registros: 0=$MFT 1=$MFTMirr 2=$LogFile 3=$Volume 4=$AttrDef 5='.' (raiz)
//! 6=$Bitmap, 16=HELLO.TXT, 17..=arquivos extras. Reserva registros na MFT
//! e espaço livre; os bitmaps são a autoridade de alocação. Imagem de
//! desenvolvimento: sem journal nem ACLs do Windows.
//!
//! Cada arquivo extra vira um registro com $DATA não residente numa run
//! contígua depois da zona da MFT, o que permite embutir arquivos grandes
//! sem runlist fragmentada. Nomes com `/` (`Windows/System32/x.sys`) criam
//! os diretórios intermediários, registrados depois dos arquivos, cada um com
//! o seu $INDEX_ROOT residente.

use std::collections::BTreeMap;

use std::fs;
use std::path::Path;

const SECTOR: usize = 512;
const CLUSTER: usize = 512;
const MFT_LCN: usize = 4;
/// O $INDEX_ROOT da raiz é residente: com dezenas de arquivos 1 KB não cabe.
const RECORD_SIZE: usize = 16384;
const SECTORS_PER_RECORD: usize = RECORD_SIZE / SECTOR;
const VOLUME_LABEL: &str = "OPENNT";
const HELLO_NAME: &str = "HELLO.TXT";
const HELLO_DATA: &[u8] = b"Ola do NTFS no OpenNT!\r\n";

fn put16(buffer: &mut [u8], offset: usize, value: u16) {
    buffer[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(buffer: &mut [u8], offset: usize, value: u64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn bit_length(value: u64) -> u32 {
    64 - value.leading_zeros()
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Registro FILE com USA/fixup: USN=1 no fim de todos os setores e os
/// originais na USA.
fn make_record(number: u32, flags: u16, attributes: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    let mut record = vec![0u8; RECORD_SIZE];
    record[0..4].copy_from_slice(b"FILE");
    let usa_count = SECTORS_PER_RECORD + 1;
    let attributes_offset = (48 + usa_count * 2 + 7) & !7;
    put16(&mut record, 4, 48);
    put16(&mut record, 6, usa_count as u16);
    put16(&mut record, 16, 1); // sequence
    put16(&mut record, 18, 1); // link count
    put16(&mut record, 20, attributes_offset as u16);
    put16(&mut record, 22, flags); // 1 = em uso | 2 = diretório
    put32(&mut record, 28, RECORD_SIZE as u32);
    put32(&mut record, 44, number);
    let mut offset = attributes_offset;
    for blob in attributes {
        if offset + blob.len() + 8 > RECORD_SIZE {
            return Err(format!("MFT record {number}: attributes exceed {RECORD_SIZE} bytes"));
        }
        record[offset..offset + blob.len()].copy_from_slice(blob);
        offset += blob.len();
    }
    put32(&mut record, offset, 0xFFFF_FFFF); // fim dos atributos
    put32(&mut record, 24, (offset + 8) as u32); // tamanho usado
    put16(&mut record, 48, 1);
    for index in 1..usa_count {
        let tail = index * SECTOR - 2;
        let original = u16::from_le_bytes([record[tail], record[tail + 1]]);
        put16(&mut record, 48 + index * 2, original);
        put16(&mut record, tail, 1);
    }
    Ok(record)
}

fn attribute_resident(attribute_type: u32, value: &[u8], attribute_id: u16) -> Vec<u8> {
    let total = (24 + value.len() + 7) & !7;
    let mut attribute = vec![0u8; total];
    put32(&mut attribute, 0, attribute_type);
    put32(&mut attribute, 4, total as u32);
    attribute[8] = 0; // residente
    put16(&mut attribute, 14, attribute_id);
    put32(&mut attribute, 16, value.len() as u32);
    put16(&mut attribute, 20, 24);
    attribute[24..24 + value.len()].copy_from_slice(value);
    attribute
}

/// Runlist NTFS (deltas com sinal), terminada em zero.
fn runlist_bytes(runs: &[(i64, u64)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut previous = 0i64;
    for &(lcn, count) in runs {
        let delta = lcn - previous;
        let count_length = bit_length(count).div_ceil(8).max(1) as usize;
        let count_bytes = &count.to_le_bytes()[..count_length];
        // Menor quantidade de bytes com sinal que representa o delta.
        let magnitude = if delta >= 0 { delta as u64 } else { delta.unsigned_abs() };
        let delta_length = ((bit_length(magnitude) + 8) / 8).max(1) as usize;
        let delta_bytes = &delta.to_le_bytes()[..delta_length];
        out.push(((delta_length as u8) << 4) | count_length as u8);
        out.extend_from_slice(count_bytes);
        out.extend_from_slice(delta_bytes);
        previous = lcn;
    }
    out.push(0);
    out
}

fn attribute_nonresident(attribute_type: u32, runs: &[u8], real_size: u64, attribute_id: u16) -> Vec<u8> {
    let total = (64 + runs.len() + 7) & !7;
    let mut attribute = vec![0u8; total];
    let clusters = real_size.div_ceil(CLUSTER as u64);
    put32(&mut attribute, 0, attribute_type);
    put32(&mut attribute, 4, total as u32);
    attribute[8] = 1; // não residente
    put16(&mut attribute, 14, attribute_id);
    put64(&mut attribute, 16, 0); // lowest VCN
    put64(&mut attribute, 24, clusters.wrapping_sub(1)); // highest VCN
    put16(&mut attribute, 32, 64); // offset do runlist
    put64(&mut attribute, 40, clusters * CLUSTER as u64);
    put64(&mut attribute, 48, real_size);
    put64(&mut attribute, 56, real_size);
    attribute[64..64 + runs.len()].copy_from_slice(runs);
    attribute
}

/// Valor de $FILE_NAME (sem o cabeçalho do atributo).
fn file_name_value(parent: u64, name: &str, directory: bool, real_size: u64) -> Result<Vec<u8>, String> {
    let units = utf16(name);
    let characters = units.len() / 2;
    if !(1..=255).contains(&characters) || name.contains(['\\', '/', ':']) {
        return Err(format!("nome NTFS invalido: {name:?}"));
    }
    let mut value = vec![0u8; 66 + units.len()];
    put64(&mut value, 0, parent);
    put64(&mut value, 40, real_size);
    put64(&mut value, 48, real_size);
    put32(&mut value, 56, if directory { 0x10 } else { 0x20 });
    value[64] = characters as u8;
    value[65] = if name == "." { 3 } else { 1 }; // namespace
    value[66..].copy_from_slice(&units);
    Ok(value)
}

fn file_name_attribute(parent: u64, name: &str, directory: bool, real_size: u64) -> Result<Vec<u8>, String> {
    Ok(attribute_resident(0x30, &file_name_value(parent, name, directory, real_size)?, 0))
}

/// Inteiro com os `count` bits baixos ligados, em `length` bytes.
fn low_bits(count: usize, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    for bit in 0..count {
        bytes[bit / 8] |= 1 << (bit % 8);
    }
    bytes
}

/// Monta a imagem com os arquivos extras `(nome no volume, bytes)`.
pub fn build(output: &Path, extras: &[(String, Vec<u8>)], free_space_mib: usize, extra_records: usize) -> Result<usize, String> {
    // Diretórios intermediários dos nomes com '/', na ordem de criação.
    let mut directories: Vec<String> = Vec::new();
    for (name, _) in extras {
        let components: Vec<&str> = name.split('/').collect();
        if components.iter().any(|component| component.is_empty()) {
            return Err(format!("caminho NTFS invalido: {name}"));
        }
        for depth in 1..components.len() {
            let directory = components[..depth].join("/");
            if !directories.iter().any(|known| known.eq_ignore_ascii_case(&directory)) {
                directories.push(directory);
            }
        }
    }
    let directory_record = |path: &str| -> u64 {
        if path.is_empty() {
            5
        } else {
            (17 + extras.len() + directories.iter().position(|known| known.eq_ignore_ascii_case(path)).unwrap_or(0)) as u64
        }
    };
    let split = |path: &str| -> (String, String) {
        match path.rsplit_once('/') {
            Some((parent, leaf)) => (parent.to_string(), leaf.to_string()),
            None => (String::new(), path.to_string()),
        }
    };
    let record_count = 17 + extras.len() + directories.len();
    let mft_capacity = 512usize.max(1usize << bit_length((record_count + extra_records - 1) as u64));
    let mft_clusters = mft_capacity * RECORD_SIZE / CLUSTER;
    let mirror_lcn = MFT_LCN + mft_clusters;
    let data_start_lcn = mirror_lcn + 4 * SECTORS_PER_RECORD;
    let mut data_lcn = data_start_lcn;
    let mut file_runs = Vec::new();
    for (_, blob) in extras {
        let clusters = blob.len().div_ceil(CLUSTER);
        file_runs.push((data_lcn, clusters));
        data_lcn += clusters;
    }
    let index_lcn = data_lcn;
    // Pior caso de folha (255 caracteres UTF-16 por nome).
    let root_entries = 1 + extras.iter().filter(|(name, _)| !name.contains('/')).count() + directories.iter().filter(|directory| !directory.contains('/')).count();
    let index_reserve = (root_entries * 608).div_ceil(4096) * 8 + 8;
    let bitmap_lcn = data_lcn + index_reserve;
    // Resolve o tamanho do próprio bitmap; o último setor é o boot de reserva.
    let free_sectors = free_space_mib * 1_048_576 / SECTOR;
    let mut total_sectors = bitmap_lcn + free_sectors + 1;
    let (bitmap_bytes, bitmap_clusters) = loop {
        let bitmap_bytes = total_sectors.div_ceil(8);
        let bitmap_clusters = bitmap_bytes.div_ceil(CLUSTER);
        let total = bitmap_lcn + bitmap_clusters + free_sectors + 1;
        if total == total_sectors {
            break (bitmap_bytes, bitmap_clusters);
        }
        total_sectors = total;
    };
    let mut image = vec![0u8; total_sectors * SECTOR];
    // ---- setor de boot
    let mut boot = vec![0u8; SECTOR];
    boot[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
    boot[3..11].copy_from_slice(b"NTFS    ");
    put16(&mut boot, 11, SECTOR as u16);
    boot[13] = 1; // setores por cluster
    put64(&mut boot, 40, total_sectors as u64);
    put64(&mut boot, 48, MFT_LCN as u64);
    put64(&mut boot, 56, mirror_lcn as u64);
    boot[64] = (-14i8) as u8; // registro = 2^14
    boot[68] = (-12i8) as u8; // bloco de índice = 4096
    put64(&mut boot, 72, u64::from_le_bytes(*b"OPENNT!!")); // número de série
    boot[510] = 0x55;
    boot[511] = 0xAA;
    image[0..SECTOR].copy_from_slice(&boot);
    let last = image.len() - SECTOR;
    image[last..].copy_from_slice(&boot);
    let standard_information = attribute_resident(0x10, &[0; 72], 0);
    // ---- $MFT (registro 0)
    let mft_runlist = runlist_bytes(&[(MFT_LCN as i64, mft_clusters as u64)]);
    let mft_self = make_record(0, 1, &[
        standard_information.clone(),
        file_name_attribute(5, "$MFT", false, 0)?,
        attribute_nonresident(0x80, &mft_runlist, (mft_capacity * RECORD_SIZE) as u64, 0),
        attribute_resident(0xB0, &low_bits(record_count, mft_capacity.div_ceil(8)), 0),
    ])?;
    let mft_offset = MFT_LCN * CLUSTER;
    image[mft_offset..mft_offset + RECORD_SIZE].copy_from_slice(&mft_self);
    // (número, flags, atributos): 1 = em uso, 3 = em uso e diretório.
    let mut records: Vec<(u32, u16, Vec<Vec<u8>>)> = vec![
        (1, 1, vec![standard_information.clone(), file_name_attribute(5, "$MFTMirr", false, 0)?, attribute_nonresident(0x80, &runlist_bytes(&[(mirror_lcn as i64, (4 * SECTORS_PER_RECORD) as u64)]), (4 * RECORD_SIZE) as u64, 0)]),
        (2, 1, vec![standard_information.clone(), file_name_attribute(5, "$LogFile", false, 0)?]),
        (3, 1, vec![standard_information.clone(), file_name_attribute(5, "$Volume", false, 0)?, attribute_resident(0x60, &utf16(VOLUME_LABEL), 0), attribute_resident(0x70, &[0; 12], 0)]),
        (4, 1, vec![standard_information.clone(), file_name_attribute(5, "$AttrDef", false, 0)?]),
        (16, 1, vec![standard_information.clone(), file_name_attribute(5, HELLO_NAME, false, HELLO_DATA.len() as u64)?, attribute_resident(0x80, HELLO_DATA, 0)]),
    ];
    // Filhos de cada diretório: (registro, nome, tamanho, diretório).
    let mut children: BTreeMap<u64, Vec<(u64, String, u64, bool)>> = BTreeMap::new();
    children.entry(5).or_default().push((16, HELLO_NAME.to_string(), HELLO_DATA.len() as u64, false));
    for (index, (name, blob)) in extras.iter().enumerate() {
        let number = (17 + index) as u32;
        let (lcn, count) = file_runs[index];
        let (parent_path, leaf) = split(name);
        let parent = directory_record(&parent_path);
        let data = if blob.is_empty() { attribute_resident(0x80, &[], 0) } else { attribute_nonresident(0x80, &runlist_bytes(&[(lcn as i64, count as u64)]), blob.len() as u64, 0) };
        records.push((number, 1, vec![standard_information.clone(), file_name_attribute(parent, &leaf, false, blob.len() as u64)?, data]));
        image[lcn * CLUSTER..lcn * CLUSTER + blob.len()].copy_from_slice(blob);
        children.entry(parent).or_default().push((number as u64, leaf, blob.len() as u64, false));
    }
    for directory in &directories {
        let (parent_path, leaf) = split(directory);
        children.entry(directory_record(&parent_path)).or_default().push((directory_record(directory), leaf, 0, true));
    }
    // Entradas de índice de um diretório em ordem alfabética (como o NT).
    let index_keys_of = |parent: u64| -> Result<Vec<Vec<u8>>, String> {
        let mut listed = children.get(&parent).cloned().unwrap_or_default();
        listed.sort_by_key(|(_, name, _, _)| name.to_uppercase());
        let mut keys = Vec::new();
        for (number, name, size, directory) in &listed {
            let value = file_name_value(parent, name, *directory, *size)?;
            let entry_size = (16 + value.len() + 7) & !7;
            let mut entry = vec![0u8; entry_size];
            put64(&mut entry, 0, *number);
            put16(&mut entry, 8, entry_size as u16);
            put16(&mut entry, 10, value.len() as u16);
            entry[16..16 + value.len()].copy_from_slice(&value);
            keys.push(entry);
        }
        Ok(keys)
    };
    let mut last_entry = vec![0u8; 16];
    put16(&mut last_entry, 8, 16);
    put16(&mut last_entry, 12, 2); // última
    let resident_index_root = |entries: &[u8], large: bool| -> Vec<u8> {
        let mut index_root = vec![0u8; 32 + entries.len()];
        put32(&mut index_root, 0, 0x30); // indexa $FILE_NAME
        put32(&mut index_root, 4, 1); // collation FILENAME
        put32(&mut index_root, 8, 4096);
        index_root[12] = (4096 / CLUSTER) as u8;
        put32(&mut index_root, 16, 16);
        put32(&mut index_root, 20, (16 + entries.len()) as u32);
        put32(&mut index_root, 24, (16 + entries.len()) as u32);
        put32(&mut index_root, 28, large as u32);
        index_root[32..].copy_from_slice(entries);
        index_root
    };
    // ---- subdiretórios: índice residente
    for directory in &directories {
        let number = directory_record(directory);
        let (parent_path, leaf) = split(directory);
        let entries = [index_keys_of(number)?.concat(), last_entry.clone()].concat();
        if entries.len() + 512 > RECORD_SIZE {
            return Err(format!("diretorio NTFS grande demais para indice residente: {directory}"));
        }
        records.push((number as u32, 3, vec![standard_information.clone(), file_name_attribute(directory_record(&parent_path), &leaf, true, 0)?, attribute_resident(0x90, &resident_index_root(&entries, false), 0)]));
    }
    // ---- $INDEX_ROOT da raiz
    let index_keys = index_keys_of(5)?;
    let index_entries = index_keys.concat();
    let mut entries = [index_entries, last_entry.clone()].concat();
    let mut index_attributes = Vec::new();
    let large_index = entries.len() + 512 > RECORD_SIZE;
    let mut allocation_length = 0;
    if large_index {
        // B-tree de dois níveis: cada separador sai da folha anterior e vai
        // para o INDEX_ROOT com o VCN do filho.
        let mut groups: Vec<Vec<Vec<u8>>> = Vec::new();
        let mut group = Vec::new();
        let mut used = 0;
        for key in index_keys {
            if used + key.len() + 16 > 4096 - 64 {
                groups.push(std::mem::take(&mut group));
                used = 0;
            }
            used += key.len();
            group.push(key);
        }
        if !group.is_empty() {
            groups.push(group);
        }
        let group_count = groups.len();
        let mut root_keys = Vec::new();
        let mut blocks = Vec::new();
        for (number, mut group) in groups.into_iter().enumerate() {
            let vcn = (number * (4096 / CLUSTER)) as u64;
            let separator = if number + 1 < group_count {
                let mut separator = group.pop().unwrap_or_default();
                separator.extend_from_slice(&vcn.to_le_bytes());
                let length = separator.len() as u16;
                put16(&mut separator, 8, length);
                put16(&mut separator, 12, 1);
                separator
            } else {
                let mut separator = vec![0u8; 24];
                put16(&mut separator, 8, 24);
                put16(&mut separator, 12, 3);
                put64(&mut separator, 16, vcn);
                separator
            };
            root_keys.push(separator);
            let leaf = [group.concat(), last_entry.clone()].concat();
            let mut block = vec![0u8; 4096];
            block[..4].copy_from_slice(b"INDX");
            put16(&mut block, 4, 40);
            put16(&mut block, 6, 9);
            put64(&mut block, 16, vcn);
            put32(&mut block, 24, 40);
            put32(&mut block, 28, (40 + leaf.len()) as u32);
            put32(&mut block, 32, (4096 - 24) as u32);
            block[64..64 + leaf.len()].copy_from_slice(&leaf);
            put16(&mut block, 40, 1);
            for sector in 1..9 {
                let tail = sector * 512 - 2;
                let original = [block[tail], block[tail + 1]];
                block[40 + sector * 2..42 + sector * 2].copy_from_slice(&original);
                put16(&mut block, tail, 1);
            }
            blocks.push(block);
        }
        let allocation = blocks.concat();
        if allocation.len() > index_reserve * CLUSTER {
            return Err("reserva do indice excedida".into());
        }
        allocation_length = allocation.len();
        image[index_lcn * CLUSTER..index_lcn * CLUSTER + allocation.len()].copy_from_slice(&allocation);
        index_attributes.push(attribute_nonresident(0xA0, &runlist_bytes(&[(index_lcn as i64, (allocation.len() / CLUSTER) as u64)]), allocation.len() as u64, 3));
        index_attributes.push(attribute_resident(0xB0, &low_bits(blocks.len(), blocks.len().div_ceil(8)), 4));
        entries = root_keys.concat();
    }
    let index_root = resident_index_root(&entries, large_index);
    let mut root = vec![standard_information.clone(), file_name_attribute(5, ".", true, 0)?, attribute_resident(0x90, &index_root, 0)];
    root.extend(index_attributes);
    records.push((5, 3, root));
    // ---- $Bitmap
    let mut bitmap = vec![0u8; bitmap_bytes];
    let mut mark_used = |start: usize, count: usize| {
        for cluster in start..start + count {
            bitmap[cluster / 8] |= 1 << (cluster % 8);
        }
    };
    mark_used(0, index_lcn); // boot, MFT, espelho e arquivos embutidos
    if large_index {
        mark_used(index_lcn, allocation_length / CLUSTER);
    }
    mark_used(bitmap_lcn, bitmap_clusters);
    mark_used(total_sectors - 1, bitmap_bytes * 8 - total_sectors + 1);
    records.push((6, 1, vec![standard_information.clone(), file_name_attribute(5, "$Bitmap", false, bitmap_bytes as u64)?, attribute_nonresident(0x80, &runlist_bytes(&[(bitmap_lcn as i64, bitmap_clusters as u64)]), bitmap_bytes as u64, 0)]));
    image[bitmap_lcn * CLUSTER..bitmap_lcn * CLUSTER + bitmap.len()].copy_from_slice(&bitmap);
    for (number, flags, attributes) in &records {
        let at = mft_offset + *number as usize * RECORD_SIZE;
        image[at..at + RECORD_SIZE].copy_from_slice(&make_record(*number, *flags, attributes)?);
    }
    let mirror = image[mft_offset..mft_offset + 4 * RECORD_SIZE].to_vec();
    image[mirror_lcn * CLUSTER..mirror_lcn * CLUSTER + mirror.len()].copy_from_slice(&mirror);
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    fs::write(output, &image).map_err(|error| format!("{}: {error}", output.display()))?;
    Ok(total_sectors * SECTOR)
}
