//! Mutações persistentes do NTFS.
//!
//! Toda validação e alocação acontece antes da publicação no disco. Isto
//! NÃO é um journal NTFS: queda de energia no commit pode rasgar uma
//! operação de vários setores. Uma falha de E/S envenena este writer até a
//! remontagem.

use alloc::string::String;
use alloc::vec::Vec;

use super::extended_attributes::{self as ea, Entry};
use super::ntfs::{each_attribute, find_attribute, parse_runs, u16_at, u32_at, u64_at, IndexEntry, Ntfs, PendingWrite, Run, Stat};
use crate::drivers::storage::ata_pio;
use crate::ntos::ke::clock;
use crate::rtl::{KernelError, SpinLock};

#[derive(Clone)]
struct Allocation {
    bits: Vec<u8>,
    records: Vec<u8>,
    capacity: u64,
    clusters: u64,
    bitmap_runs: Vec<Run>,
}

/// Estado do writer de um volume montado.
#[derive(Default)]
pub struct WriterState {
    allocation: Option<Allocation>,
    allocation_generation: Option<u64>,
    tx: Option<Allocation>,
    poisoned: bool,
}

pub type WriterLock = SpinLock<WriterState>;

pub const fn new_writer() -> WriterLock {
    SpinLock::new(WriterState { allocation: None, allocation_generation: None, tx: None, poisoned: false })
}

fn fail<T>(status: u32, message: &str) -> Result<T, KernelError> {
    Err(KernelError::with_status(alloc::format!("NTFS: {message}"), status))
}

fn align(value: usize) -> usize {
    value.div_ceil(8) * 8
}

fn put16(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 2].copy_from_slice(&(value as u16).to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn wide(name: &str) -> Vec<u8> {
    name.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn resident(attribute_type: u32, value: &[u8], name: &str) -> Vec<u8> {
    let name_bytes = wide(name);
    let value_offset = align(24 + name_bytes.len());
    let mut attribute = alloc::vec![0u8; align(value_offset + value.len())];
    let length = attribute.len() as u64;
    put32(&mut attribute, 0, attribute_type as u64);
    put32(&mut attribute, 4, length);
    attribute[9] = name.encode_utf16().count() as u8;
    if !name.is_empty() {
        put16(&mut attribute, 10, 24);
        attribute[24..24 + name_bytes.len()].copy_from_slice(&name_bytes);
    }
    put32(&mut attribute, 16, value.len() as u64);
    put16(&mut attribute, 20, value_offset as u64);
    attribute[value_offset..value_offset + value.len()].copy_from_slice(value);
    attribute
}

/// Runlist com o menor número de bytes por contagem e delta com sinal.
fn encode_runs(runs: &[Run]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut previous = 0i64;
    for run in runs {
        let mut count = run.count as u128;
        let mut delta = (run.lcn - previous) as i128;
        let mut count_length = 1u32;
        let mut delta_length = 1u32;
        while count >= 1u128 << (count_length * 8) {
            count_length += 1;
        }
        while delta < -(1i128 << (delta_length * 8 - 1)) || delta >= 1i128 << (delta_length * 8 - 1) {
            delta_length += 1;
        }
        out.push(((delta_length << 4) | count_length) as u8);
        for _ in 0..count_length {
            out.push((count & 255) as u8);
            count >>= 8;
        }
        for _ in 0..delta_length {
            out.push((delta & 255) as u8);
            delta >>= 8;
        }
        previous = run.lcn;
    }
    out.push(0);
    out
}

fn bit(bytes: &[u8], index: u64) -> bool {
    bytes[(index >> 3) as usize] & (1 << (index & 7)) != 0
}

fn set_bit(bytes: &mut [u8], index: u64, value: bool) -> Result<(), KernelError> {
    if index >= bytes.len() as u64 * 8 {
        return fail(0xC000_0032, "bitmap fora dos limites");
    }
    if value {
        bytes[(index >> 3) as usize] |= 1 << (index & 7);
    } else {
        bytes[(index >> 3) as usize] &= !(1 << (index & 7));
    }
    Ok(())
}

fn merge_runs(runs: &[Run]) -> Vec<Run> {
    let mut out: Vec<Run> = Vec::new();
    for run in runs {
        match out.last_mut() {
            Some(last) if last.lcn + last.count as i64 == run.lcn => last.count += run.count,
            _ => out.push(*run),
        }
    }
    out
}

fn now() -> u64 {
    clock::now_ms() * 10_000 + 116_444_736_000_000_000
}

fn attributes(record: &[u8]) -> Result<Vec<Vec<u8>>, KernelError> {
    let mut list = Vec::new();
    each_attribute(record, |attribute| {
        list.push(attribute.raw.clone());
        true
    })?;
    Ok(list)
}

fn replace(attributes: &mut Vec<Vec<u8>>, attribute_type: u32, raw: Option<Vec<u8>>) {
    if let Some(at) = attributes.iter().position(|attribute| u32_at(attribute, 0) == attribute_type) {
        attributes.remove(at);
    }
    if let Some(raw) = raw {
        attributes.push(raw);
    }
    attributes.sort_by_key(|attribute| u32_at(attribute, 0));
}

fn value_of(raw: &[u8]) -> Vec<u8> {
    let offset = u16_at(raw, 20) as usize;
    raw[offset..offset + u32_at(raw, 16) as usize].to_vec()
}

fn parent_of(file_name: &[u8]) -> u64 {
    u32_at(file_name, 0) as u64 | (u16_at(file_name, 4) as u64) << 32
}

/// Contexto de uma operação com o estado do writer retido.
struct Tx<'a> {
    volume: &'a Ntfs,
    state: &'a mut WriterState,
}

impl Tx<'_> {
    fn cluster(&self) -> u64 {
        self.volume.geometry.cluster_size
    }

    fn sector(&self) -> u64 {
        self.volume.geometry.sector_size
    }

    fn tx(&mut self) -> &mut Allocation {
        self.state.tx.as_mut().expect("NTFS: transacao ativa")
    }

    fn nonresident(&self, attribute_type: u32, runs: &[Run], size: u64, name: &str) -> Vec<u8> {
        let name_bytes = wide(name);
        let run_offset = align(64 + name_bytes.len());
        let runlist = encode_runs(runs);
        let mut attribute = alloc::vec![0u8; align(run_offset + runlist.len())];
        let allocated: u64 = runs.iter().map(|run| run.count * self.cluster()).sum();
        let length = attribute.len() as u64;
        put32(&mut attribute, 0, attribute_type as u64);
        put32(&mut attribute, 4, length);
        attribute[8] = 1;
        attribute[9] = name.encode_utf16().count() as u8;
        if !name.is_empty() {
            put16(&mut attribute, 10, 64);
            attribute[64..64 + name_bytes.len()].copy_from_slice(&name_bytes);
        }
        put64(&mut attribute, 24, if allocated != 0 { allocated / self.cluster() - 1 } else { u64::MAX });
        put16(&mut attribute, 32, run_offset as u64);
        put64(&mut attribute, 40, allocated);
        put64(&mut attribute, 48, size);
        put64(&mut attribute, 56, size);
        attribute[run_offset..run_offset + runlist.len()].copy_from_slice(&runlist);
        attribute
    }

    fn stage(&mut self, lba: u64, bytes: Option<Vec<u8>>, count: u64) -> Result<(), KernelError> {
        let sector = self.sector();
        if self.state.tx.is_none() || lba + count > self.volume.geometry.total_sectors || bytes.as_ref().is_some_and(|bytes| bytes.len() as u64 != count * sector) {
            return fail(0xC000_0032, "escrita fora do volume");
        }
        self.volume.pending.lock().push(PendingWrite { lba, count, bytes });
        Ok(())
    }

    fn fixup(&self, block: &mut [u8], usa: usize, count: usize, previous: u16) {
        let usn = (previous as u64 % 65534) + 1;
        put16(block, usa, usn);
        let sector = self.sector() as usize;
        for index in 1..count {
            let tail = index * sector - 2;
            let original = u16_at(block, tail) as u64;
            put16(block, usa + index * 2, original);
            put16(block, tail, usn);
        }
    }

    /// Grava um registro MFT (e o espelho dos quatro primeiros).
    fn record(&mut self, reference: u64, list: &[Vec<u8>], flags: u16, old: Option<&[u8]>, sequence: u16) -> Result<(), KernelError> {
        let record_size = self.volume.geometry.record_size as usize;
        let sector = self.sector() as usize;
        let mut record = alloc::vec![0u8; record_size];
        let count = record_size / sector + 1;
        let start = align(48 + count * 2);
        record[0..4].copy_from_slice(b"FILE");
        put16(&mut record, 4, 48);
        put16(&mut record, 6, count as u64);
        put16(&mut record, 16, old.map_or(sequence, |old| u16_at(old, 16)) as u64);
        put16(&mut record, 18, (flags & 1) as u64);
        put16(&mut record, 20, start as u64);
        put16(&mut record, 22, flags as u64);
        put32(&mut record, 28, record_size as u64);
        put32(&mut record, 44, reference);
        let mut offset = start;
        let mut id = 0u64;
        for raw in list {
            if offset + raw.len() + 8 > record_size {
                return fail(0xC000_007F, "atributos excedem registro MFT");
            }
            record[offset..offset + raw.len()].copy_from_slice(raw);
            put16(&mut record, offset + 14, id);
            id += 1;
            offset += raw.len();
        }
        put16(&mut record, 40, id);
        put32(&mut record, offset, 0xFFFF_FFFF);
        put32(&mut record, 24, (offset + 8) as u64);
        let previous = old.map_or(0, |old| u16_at(old, u16_at(old, 4) as usize));
        self.fixup(&mut record, 48, count, previous);
        let geometry = self.volume.geometry;
        let sectors = record_size as u64 / geometry.sector_size;
        self.stage(geometry.mft_lcn * geometry.sectors_per_cluster + reference * sectors, Some(record.clone()), sectors)?;
        if reference < 4 {
            self.stage(geometry.mirror_lcn * geometry.sectors_per_cluster + reference * sectors, Some(record), sectors)?;
        }
        self.volume.invalidate();
        Ok(())
    }

    fn load_allocation(&mut self) -> Result<(), KernelError> {
        if self.state.allocation.is_some() && self.state.allocation_generation == Some(self.volume.generation()) {
            return Ok(());
        }
        let mft = self.volume.read_record(0)?;
        let data = find_attribute(&mft, 0x80)?;
        let mft_bitmap = find_attribute(&mft, 0xB0)?;
        let bitmap_record = self.volume.read_record(6)?;
        let bitmap_data = find_attribute(&bitmap_record, 0x80)?;
        let geometry = self.volume.geometry;
        let (Some(data), Some(mft_bitmap), Some(bitmap_data)) = (data, mft_bitmap, bitmap_data) else {
            return fail(0xC000_00A2, "volume sem metadados de alocacao gravaveis");
        };
        if !data.non_resident || mft_bitmap.non_resident || !bitmap_data.non_resident || geometry.total_sectors == 0 || geometry.mirror_lcn == 0 {
            return fail(0xC000_00A2, "volume sem metadados de alocacao gravaveis");
        }
        let runs = parse_runs(&mft, data.run_offset)?;
        let capacity = data.real_size / geometry.record_size;
        if runs.len() != 1 || runs[0].lcn as u64 != geometry.mft_lcn || data.real_size % geometry.record_size != 0 || capacity > mft_bitmap.value.len() as u64 * 8 {
            return fail(0xC000_00BB, "MFT fragmentada ou bitmap invalido");
        }
        let bits = self.volume.read_data(&bitmap_record, 0x80)?;
        let clusters = geometry.total_sectors / geometry.sectors_per_cluster;
        if (bits.len() as u64) * 8 < clusters {
            return fail(0xC000_0032, "$Bitmap incompleto");
        }
        self.state.allocation = Some(Allocation { bits, records: mft_bitmap.value, capacity, clusters, bitmap_runs: parse_runs(&bitmap_record, bitmap_data.run_offset)? });
        self.state.allocation_generation = Some(self.volume.generation());
        Ok(())
    }

    /// Primeiros clusters livres, em runs.
    fn allocate(&mut self, count: u64) -> Result<Vec<Run>, KernelError> {
        let tx = self.tx();
        if count > tx.clusters {
            return fail(0xC000_007F, "volume cheio");
        }
        let mut runs = Vec::new();
        let mut remaining = count;
        let mut index = 0;
        while index < tx.clusters && remaining != 0 {
            if bit(&tx.bits, index) {
                index += 1;
                continue;
            }
            let first = index;
            while index < tx.clusters && remaining != 0 && !bit(&tx.bits, index) {
                set_bit(&mut tx.bits, index, true)?;
                index += 1;
                remaining -= 1;
            }
            runs.push(Run { lcn: first as i64, count: index - first });
        }
        if remaining != 0 {
            return fail(0xC000_007F, "volume cheio");
        }
        Ok(runs)
    }

    fn release(&mut self, runs: &[Run]) -> Result<(), KernelError> {
        let tx = self.tx();
        for run in runs {
            for cluster in run.lcn as u64..run.lcn as u64 + run.count {
                if !bit(&tx.bits, cluster) {
                    return fail(0xC000_0032, "cluster liberado duas vezes");
                }
                set_bit(&mut tx.bits, cluster, false)?;
            }
        }
        Ok(())
    }

    /// Setores parciais com leitura/modificação/escrita; extensões zeradas
    /// inteiras vão em buffers limitados no commit.
    fn transfer(&mut self, runs: &[Run], offset: u64, bytes: Option<&[u8]>, length: u64) -> Result<(), KernelError> {
        let cluster = self.cluster();
        let sector = self.sector();
        let mut base = 0u64;
        let mut done = 0u64;
        for run in runs {
            let end = base + run.count * cluster;
            if offset + done >= end {
                base = end;
                continue;
            }
            while done < length && offset + done < end {
                let physical = run.lcn as u64 * cluster + offset + done - base;
                let skip = physical % sector;
                let lba = physical / sector;
                let mut take = (length - done).min(end - offset - done);
                if skip != 0 || take < sector {
                    take = take.min(sector - skip);
                    let mut current = self.volume.read_sectors(lba, 1)?;
                    let range = skip as usize..(skip + take) as usize;
                    match bytes {
                        Some(bytes) => current[range].copy_from_slice(&bytes[done as usize..(done + take) as usize]),
                        None => current[range].fill(0),
                    }
                    self.stage(lba, Some(current), 1)?;
                } else {
                    take = take / sector * sector;
                    let chunk = bytes.map(|bytes| bytes[done as usize..(done + take) as usize].to_vec());
                    self.stage(lba, chunk, take / sector)?;
                }
                done += take;
            }
            if done == length {
                return Ok(());
            }
            base = end;
        }
        if done != length {
            return fail(0xC000_0032, "runlist curta");
        }
        Ok(())
    }

    fn persist_bitmap(&mut self, before: &[u8], after: &[u8], runs: &[Run]) -> Result<(), KernelError> {
        let sector = self.sector() as usize;
        let mut offset = 0;
        while offset < after.len() {
            let end = (offset + sector).min(after.len());
            if before[offset..end] != after[offset..end] {
                self.transfer(runs, offset as u64, Some(&after[offset..end]), (end - offset) as u64)?;
            }
            offset += sector;
        }
        Ok(())
    }

    /// Executa `action` numa transação (ou dentro da transação atual).
    fn transaction<T>(&mut self, action: impl FnOnce(&mut Self) -> Result<T, KernelError>) -> Result<T, KernelError> {
        if self.state.tx.is_some() {
            return action(self);
        }
        if self.state.poisoned {
            return fail(0xC000_0185, "volume requer remontagem apos erro de E/S");
        }
        self.load_allocation()?;
        self.state.tx = self.state.allocation.clone();
        self.volume.pending.lock().clear();
        self.volume.invalidate();
        let mut committing = false;
        let result: Result<T, KernelError> = (|| {
            let result = action(self)?;
            let allocation = self.state.allocation.clone().expect("alocacao carregada");
            let tx = self.state.tx.clone().expect("transacao ativa");
            self.persist_bitmap(&allocation.bits, &tx.bits, &tx.bitmap_runs)?;
            if tx.records != allocation.records {
                let mft = self.volume.read_record(0)?;
                let mut list = attributes(&mft)?;
                replace(&mut list, 0xB0, Some(resident(0xB0, &tx.records, "")));
                self.record(0, &list, 1, Some(&mft), 1)?;
            }
            committing = true;
            let pending = core::mem::take(&mut *self.volume.pending.lock());
            let sector = self.sector() as usize;
            for operation in &pending {
                let mut index = 0;
                while index < operation.count {
                    let count = (operation.count - index).min(128);
                    let bytes = match &operation.bytes {
                        Some(bytes) => bytes[index as usize * sector..(index + count) as usize * sector].to_vec(),
                        None => alloc::vec![0u8; count as usize * sector],
                    };
                    ata_pio::write_sectors(operation.lba + index, &bytes, self.volume.drive)?;
                    index += count;
                }
            }
            ata_pio::flush(self.volume.drive)?;
            self.state.allocation = self.state.tx.clone();
            self.volume.changed();
            self.state.allocation_generation = Some(self.volume.generation());
            Ok(result)
        })();
        if let Err(error) = &result {
            if committing {
                self.state.poisoned = true;
                self.state.allocation = None;
                if error.status == 0 {
                    self.volume.pending.lock().clear();
                    self.state.tx = None;
                    self.volume.invalidate();
                    return fail(0xC000_0185, &alloc::format!("{error}"));
                }
            }
        }
        self.volume.pending.lock().clear();
        self.state.tx = None;
        self.volume.invalidate();
        result
    }

    fn split(&self, path: &str) -> Result<(IndexEntry, String), KernelError> {
        let mut parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
        let name = parts.pop().unwrap_or("");
        let invalid = name.is_empty() || name.encode_utf16().count() > 255 || name == "." || name == ".." || name.chars().any(|character| (character as u32) < 0x20 || "\\:*?\"<>|".contains(character));
        if invalid {
            return fail(0xC000_0033, "nome invalido");
        }
        let parent_path = alloc::format!("/{}", parts.join("/"));
        let Some(parent) = self.volume.find(&parent_path)? else {
            return fail(0xC000_003A, "diretorio pai ausente");
        };
        let record = self.volume.read_record(parent.reference)?;
        if u16_at(&record, 22) & 2 == 0 {
            return fail(0xC000_0103, "pai nao e diretorio");
        }
        Ok((parent, String::from(name)))
    }

    #[allow(clippy::too_many_arguments)]
    fn filename(&self, parent: u64, name: &str, directory: bool, size: u64, allocated: u64, times: Option<&[u8]>, file_attributes: u32) -> Result<Vec<u8>, KernelError> {
        let units = wide(name);
        let mut value = alloc::vec![0u8; 66 + units.len()];
        let parent_record = self.volume.read_record(parent)?;
        put64(&mut value, 0, parent | (u16_at(&parent_record, 16) as u64) << 48);
        if let Some(times) = times {
            value[8..40].copy_from_slice(&times[..32]);
        }
        put64(&mut value, 40, allocated);
        put64(&mut value, 48, size);
        put32(&mut value, 56, if file_attributes != 0 { file_attributes } else if directory { 0x10 } else { 0x20 } as u64);
        value[64] = (units.len() / 2) as u8;
        value[65] = 1;
        value[66..].copy_from_slice(&units);
        Ok(value)
    }

    fn entry(entry: Option<&IndexEntry>, child: Option<u64>) -> Vec<u8> {
        let size = align(16 + entry.map_or(0, |entry| entry.value.len())) + if child.is_some() { 8 } else { 0 };
        let mut bytes = alloc::vec![0u8; size];
        if let Some(entry) = entry {
            put64(&mut bytes, 0, entry.reference | (if entry.sequence != 0 { entry.sequence } else { 1 } as u64) << 48);
            bytes[16..16 + entry.value.len()].copy_from_slice(&entry.value);
        }
        put16(&mut bytes, 8, size as u64);
        put16(&mut bytes, 10, entry.map_or(0, |entry| entry.value.len()) as u64);
        put16(&mut bytes, 12, (if entry.is_some() { 0 } else { 2 }) | if child.is_some() { 1 } else { 0 });
        if let Some(child) = child {
            put64(&mut bytes, size - 8, child);
        }
        bytes
    }

    /// Reconstrói o índice $I30 do diretório (raiz residente e, se não
    /// couber, blocos INDX numa B-tree).
    fn directory(&mut self, reference: u64, mut entries: Vec<IndexEntry>) -> Result<(), KernelError> {
        let record = self.volume.read_record(reference)?;
        let mut list = attributes(&record)?;
        if let Some(old) = find_attribute(&record, 0xA0)? {
            let runs = parse_runs(&record, old.run_offset)?;
            self.release(&runs)?;
        }
        for attribute_type in [0x90, 0xA0, 0xB0] {
            replace(&mut list, attribute_type, None);
        }
        if find_attribute(&record, 0xE0)?.is_some() {
            // Espaço para a raiz residente: EAs grandes de diretório vão
            // para runs em vez de impedir a criação de filhos.
            let index_room = 512 + 4096usize.min(entries.iter().fold(16, |total, entry| total + align(16 + entry.value.len())));
            let current = self.read_ea(&record)?;
            self.store_ea(&record, &mut list, &current, index_room)?;
        }
        entries.sort_by_key(|entry| entry.name.to_uppercase());
        let record_size = self.volume.geometry.record_size as usize;
        let sector = self.sector() as usize;
        let cluster = self.cluster() as usize;
        let root_limit = record_size as i64 - align(48 + (record_size / sector + 1) * 2) as i64 - list.iter().map(|attribute| attribute.len() as i64).sum::<i64>() - 512;
        let block_size = 4096usize;
        let usa_count = block_size / sector + 1;
        let start = align(40 + usa_count * 2);
        let mut blocks: Vec<Vec<u8>> = Vec::new();
        let mut nodes: Vec<(IndexEntry, Option<u64>)> = entries.into_iter().map(|entry| (entry, None)).collect();
        let mut last_child: Option<u64> = None;
        let encoded = |nodes: &[(IndexEntry, Option<u64>)], last_child: Option<u64>| -> Vec<u8> {
            let mut bytes: Vec<u8> = nodes.iter().flat_map(|(entry, child)| Self::entry(Some(entry), *child)).collect();
            bytes.extend(Self::entry(None, last_child));
            bytes
        };
        while encoded(&nodes, last_child).len() as i64 > root_limit {
            let mut groups: Vec<Vec<(IndexEntry, Option<u64>)>> = Vec::new();
            let mut group = Vec::new();
            let mut used = 0;
            for node in nodes {
                let size = Self::entry(Some(&node.0), node.1).len();
                if used + size + 24 > block_size - start && !group.is_empty() {
                    groups.push(core::mem::take(&mut group));
                    used = 0;
                }
                used += size;
                group.push(node);
            }
            if !group.is_empty() {
                groups.push(group);
            }
            if groups.len() <= 1 {
                return fail(0xC000_007F, "indice nao cabe na MFT");
            }
            let group_count = groups.len();
            let mut parents = Vec::new();
            let mut terminal = None;
            for (index, mut children) in groups.into_iter().enumerate() {
                let separator = if index + 1 < group_count { children.pop() } else { None };
                let vcn = (blocks.len() * block_size / cluster.min(block_size)) as u64;
                let mut leaf: Vec<u8> = children.iter().flat_map(|(entry, child)| Self::entry(Some(entry), *child)).collect();
                leaf.extend(Self::entry(None, separator.as_ref().map_or(last_child, |separator| separator.1)));
                let mut block = alloc::vec![0u8; block_size];
                block[0..4].copy_from_slice(b"INDX");
                put16(&mut block, 4, 40);
                put16(&mut block, 6, usa_count as u64);
                put64(&mut block, 16, vcn);
                put32(&mut block, 24, (start - 24) as u64);
                put32(&mut block, 28, (start - 24 + leaf.len()) as u64);
                put32(&mut block, 32, (block_size - 24) as u64);
                block[36] = last_child.is_some() as u8;
                block[start..start + leaf.len()].copy_from_slice(&leaf);
                self.fixup(&mut block, 40, usa_count, 0);
                blocks.push(block);
                match separator {
                    Some(separator) => parents.push((separator.0, Some(vcn))),
                    None => terminal = Some(vcn),
                }
            }
            nodes = parents;
            last_child = terminal;
        }
        let keys = encoded(&nodes, last_child);
        let mut root = alloc::vec![0u8; 32 + keys.len()];
        put32(&mut root, 0, 0x30);
        put32(&mut root, 4, 1);
        put32(&mut root, 8, block_size as u64);
        root[12] = if cluster <= block_size { (block_size / cluster) as u8 } else { 0xF4 };
        put32(&mut root, 16, 16);
        put32(&mut root, 20, (16 + keys.len()) as u64);
        put32(&mut root, 24, (16 + keys.len()) as u64);
        root[28] = !blocks.is_empty() as u8;
        root[32..].copy_from_slice(&keys);
        replace(&mut list, 0x90, Some(resident(0x90, &root, "$I30")));
        if !blocks.is_empty() {
            let data = blocks.concat();
            let runs = self.allocate((data.len() as u64).div_ceil(self.cluster()))?;
            let allocated: u64 = runs.iter().map(|run| run.count * self.cluster()).sum();
            self.transfer(&runs, 0, None, allocated)?;
            self.transfer(&runs, 0, Some(&data), data.len() as u64)?;
            let attribute = self.nonresident(0xA0, &runs, data.len() as u64, "$I30");
            replace(&mut list, 0xA0, Some(attribute));
            let mut bits = alloc::vec![0u8; blocks.len().div_ceil(8)];
            for index in 0..blocks.len() {
                set_bit(&mut bits, index as u64, true)?;
            }
            replace(&mut list, 0xB0, Some(resident(0xB0, &bits, "$I30")));
        }
        if let Some(standard) = find_attribute(&record, 0x10)? {
            let mut value = standard.value;
            put64(&mut value, 8, now());
            put64(&mut value, 16, now());
            replace(&mut list, 0x10, Some(resident(0x10, &value, "")));
        }
        self.record(reference, &list, 3, Some(&record), 1)
    }

    fn require_file(&self, path: &str) -> Result<(IndexEntry, Vec<u8>), KernelError> {
        let Some(entry) = self.volume.find(path)? else { return fail(0xC000_0034, "arquivo ausente") };
        if entry.reference < 16 {
            return fail(0xC000_0022, "metadado reservado");
        }
        let record = self.volume.read_record(entry.reference)?;
        if u16_at(&record, 18) != 1 {
            return fail(0xC000_00BB, "multiplos hard links");
        }
        let mut unsupported = false;
        each_attribute(&record, |attribute| {
            let raw = &attribute.raw;
            if attribute.attribute_type == 0x20 || attribute.attribute_type == 0xC0 || u16_at(raw, 12) != 0 || (attribute.attribute_type == 0x80 && raw[9] != 0) {
                unsupported = true;
            }
            !unsupported
        })?;
        if unsupported {
            return fail(0xC000_00BB, "atributo estendido nao suportado para escrita");
        }
        Ok((entry, record))
    }

    fn refresh_name(&mut self, reference: u64, record: &[u8], list: &mut Vec<Vec<u8>>, size: u64, allocated: u64) -> Result<(), KernelError> {
        let mut value = find_attribute(record, 0x30)?.map(|name| name.value).unwrap_or_default();
        let standard = list.iter().find(|attribute| u32_at(attribute, 0) == 0x10).map(|raw| value_of(raw)).unwrap_or_default();
        put64(&mut value, 40, allocated);
        put64(&mut value, 48, size);
        value[8..40].copy_from_slice(&standard[..32]);
        let ea_size = list.iter().find(|attribute| u32_at(attribute, 0) == 0xD0).map_or(0, |raw| u16_at(raw, u16_at(raw, 20) as usize) as u64);
        put32(&mut value, 60, ea_size);
        put32(&mut value, 56, u32_at(&standard, 32) as u64);
        replace(list, 0x30, Some(resident(0x30, &value, "")));
        self.record(reference, list, u16_at(record, 22), Some(record), 1)?;
        let parent = parent_of(&value);
        let entries = self.volume.root_index(parent)?.into_iter().map(|entry| if entry.reference == reference { IndexEntry { value: value.clone(), ..entry } } else { entry }).collect();
        self.directory(parent, entries)
    }

    fn read_ea(&self, record: &[u8]) -> Result<Vec<Entry>, KernelError> {
        let summary = find_attribute(record, 0xD0)?;
        let data = find_attribute(record, 0xE0)?;
        if summary.is_none() && data.is_none() {
            return Ok(Vec::new());
        }
        let (Some(summary), Some(data)) = (summary, data) else { return fail(0xC000_0053, "EA corrompido") };
        if summary.non_resident || summary.value.len() != 8 || u32_at(&summary.value, 4) > 65536 || u32_at(&summary.value, 4) == 0 {
            return fail(0xC000_0053, "EA corrompido");
        }
        let length = if data.non_resident { data.real_size } else { data.value.len() as u64 };
        if length != u32_at(&summary.value, 4) as u64 {
            return fail(0xC000_0053, "tamanho EA inconsistente");
        }
        let bytes = self.volume.read_data(record, 0xE0)?;
        let Ok(entries) = ea::parse(&bytes, false, true) else { return fail(0xC000_0053, "EA corrompido") };
        let info = ea::info(&entries);
        if info.packed != u16_at(&summary.value, 0) as usize || info.need != u16_at(&summary.value, 2) as usize || info.unpacked as u64 != length {
            return fail(0xC000_0053, "EA corrompido");
        }
        Ok(entries)
    }

    fn store_ea(&mut self, record: &[u8], list: &mut Vec<Vec<u8>>, entries: &[Entry], reserved: usize) -> Result<(), KernelError> {
        let old = find_attribute(record, 0xE0)?;
        let old_runs = match &old {
            Some(old) if old.non_resident => parse_runs(record, old.run_offset)?,
            _ => Vec::new(),
        };
        replace(list, 0xD0, None);
        replace(list, 0xE0, None);
        if entries.is_empty() {
            return self.release(&old_runs);
        }
        let bytes = ea::encode(entries, true);
        let info = ea::info(entries);
        let mut summary = [0u8; 8];
        put16(&mut summary, 0, info.packed as u64);
        put16(&mut summary, 2, info.need as u64);
        put32(&mut summary, 4, bytes.len() as u64);
        replace(list, 0xD0, Some(resident(0xD0, &summary, "")));
        let raw = resident(0xE0, &bytes, "");
        let record_size = self.volume.geometry.record_size as usize;
        let start = align(48 + (record_size / self.sector() as usize + 1) * 2);
        if start + 8 + reserved + raw.len() + list.iter().map(Vec::len).sum::<usize>() <= record_size {
            self.release(&old_runs)?;
            replace(list, 0xE0, Some(raw));
            return Ok(());
        }
        // Reaproveita a alocação antiga, inclusive ao expurgar em disco cheio.
        let mut remaining = (bytes.len() as u64).div_ceil(self.cluster());
        let mut runs = Vec::new();
        let mut freed = Vec::new();
        for run in &old_runs {
            let take = remaining.min(run.count);
            if take != 0 {
                runs.push(Run { lcn: run.lcn, count: take });
            }
            remaining -= take;
            if take < run.count {
                freed.push(Run { lcn: run.lcn + take as i64, count: run.count - take });
            }
        }
        self.release(&freed)?;
        if remaining != 0 {
            let extra = self.allocate(remaining)?;
            runs.extend(extra);
        }
        self.transfer(&runs, 0, Some(&bytes), bytes.len() as u64)?;
        let allocated: u64 = runs.iter().map(|run| run.count * self.cluster()).sum();
        if allocated > bytes.len() as u64 {
            self.transfer(&runs, bytes.len() as u64, None, allocated - bytes.len() as u64)?;
        }
        let attribute = self.nonresident(0xE0, &merge_runs(&runs), bytes.len() as u64, "");
        replace(list, 0xE0, Some(attribute));
        Ok(())
    }

    /// Núcleo de write/resize/allocate: residente enquanto couber, senão
    /// runs crescendo/encolhendo com zeros nas extensões.
    fn mutate_data(&mut self, path: &str, new_size: Option<u64>, offset: u64, bytes: Option<&[u8]>, reservation: Option<u64>) -> Result<u64, KernelError> {
        let (entry, record) = self.require_file(path)?;
        if u16_at(&record, 22) & 2 != 0 {
            return fail(0xC000_00BA, "arquivo e diretorio");
        }
        let data = find_attribute(&record, 0x80)?.ok_or_else(|| KernelError::with_status("NTFS: arquivo sem $DATA", 0xC000_0032))?;
        let old_size = if data.non_resident { data.real_size } else { data.value.len() as u64 };
        let write_end = offset + bytes.map_or(0, |bytes| bytes.len() as u64);
        let size = match (reservation, new_size) {
            (Some(reservation), _) => old_size.min(reservation),
            (None, None) => old_size.max(write_end),
            (None, Some(size)) => size,
        };
        let reserve = match (reservation, new_size) {
            (Some(reservation), _) => reservation,
            (None, None) if data.non_resident => size.max(data.allocated_size),
            _ => size,
        };
        let cluster = self.cluster();
        if reserve > self.tx().clusters * cluster {
            return fail(0xC000_007F, "volume cheio");
        }
        let mut list = attributes(&record)?;
        let mut allocated = 0u64;
        let record_size = self.volume.geometry.record_size as usize;
        let resident_fits = align(48 + (record_size / self.sector() as usize + 1) * 2) + 8 + align(24 + size as usize) + list.iter().filter(|attribute| u32_at(attribute, 0) != 0x80).map(Vec::len).sum::<usize>() <= record_size;
        if !data.non_resident && reservation.is_none() && size <= record_size as u64 - 2048 && resident_fits {
            let mut value = alloc::vec![0u8; size as usize];
            let keep = data.value.len().min(size as usize);
            value[..keep].copy_from_slice(&data.value[..keep]);
            if let Some(bytes) = bytes {
                value[offset as usize..offset as usize + bytes.len()].copy_from_slice(bytes);
            }
            replace(&mut list, 0x80, Some(resident(0x80, &value, "")));
        } else {
            let mut runs = if data.non_resident { parse_runs(&record, data.run_offset)? } else { Vec::new() };
            let need = reserve.div_ceil(cluster);
            let have: u64 = runs.iter().map(|run| run.count).sum();
            if need > have {
                let extra = self.allocate(need - have)?;
                self.transfer(&extra, 0, None, (need - have) * cluster)?;
                runs.extend(extra);
                runs = merge_runs(&runs);
            } else if need < have {
                let mut keep = need;
                let mut kept = Vec::new();
                let mut freed = Vec::new();
                for run in &runs {
                    let take = keep.min(run.count);
                    if take != 0 {
                        kept.push(Run { lcn: run.lcn, count: take });
                    }
                    if take < run.count {
                        freed.push(Run { lcn: run.lcn + take as i64, count: run.count - take });
                    }
                    keep -= take;
                }
                self.release(&freed)?;
                runs = kept;
            }
            allocated = need * cluster;
            if !data.non_resident && old_size != 0 {
                let keep = data.value.len().min(size as usize);
                self.transfer(&runs, 0, Some(&data.value[..keep]), keep as u64)?;
            }
            if size > old_size {
                self.transfer(&runs, old_size, None, size - old_size)?;
            }
            if let Some(bytes) = bytes.filter(|bytes| !bytes.is_empty()) {
                self.transfer(&runs, offset, Some(bytes), bytes.len() as u64)?;
            }
            if allocated > size {
                self.transfer(&runs, size, None, allocated - size)?;
            }
            let attribute = if allocated != 0 { self.nonresident(0x80, &runs, size, "") } else { resident(0x80, &[], "") };
            replace(&mut list, 0x80, Some(attribute));
        }
        if size != old_size || bytes.is_some_and(|bytes| !bytes.is_empty()) {
            let entries = self.read_ea(&record)?;
            let kept: Vec<Entry> = entries.iter().filter(|entry| !entry.name.starts_with(b"$KERNEL.PURGE.")).cloned().collect();
            if kept.len() != entries.len() {
                self.store_ea(&record, &mut list, &kept, 0)?;
            }
        }
        let mut standard = find_attribute(&record, 0x10)?.map(|standard| standard.value).unwrap_or_else(|| alloc::vec![0; 72]);
        put64(&mut standard, 8, now());
        put64(&mut standard, 16, now());
        let flags = u32_at(&standard, 32) as u64 | 0x20;
        put32(&mut standard, 32, flags);
        replace(&mut list, 0x10, Some(resident(0x10, &standard, "")));
        self.refresh_name(entry.reference, &record, &mut list, size, allocated)?;
        Ok(bytes.map_or(size, |bytes| bytes.len() as u64))
    }

    fn remove(&mut self, path: &str) -> Result<(), KernelError> {
        let (entry, record) = self.require_file(path)?;
        let name = find_attribute(&record, 0x30)?.map(|name| name.value).unwrap_or_default();
        if u16_at(&record, 22) & 2 != 0 && !self.volume.root_index(entry.reference)?.is_empty() {
            return fail(0xC000_0101, "diretorio nao vazio");
        }
        let mut runs = Vec::new();
        let mut failure = None;
        each_attribute(&record, |attribute| {
            if attribute.non_resident {
                match parse_runs(&record, attribute.run_offset) {
                    Ok(found) => runs.extend(found),
                    Err(error) => failure = Some(error),
                }
            }
            true
        })?;
        if let Some(error) = failure {
            return Err(error);
        }
        self.release(&runs)?;
        let parent = parent_of(&name);
        let remaining = self.volume.root_index(parent)?.into_iter().filter(|child| child.reference != entry.reference).collect();
        self.directory(parent, remaining)?;
        set_bit(&mut self.tx().records, entry.reference, false)?;
        self.record(entry.reference, &[], 0, None, (u16_at(&record, 16) % 65535) + 1)
    }

    fn create(&mut self, path: &str, directory: bool, file_attributes: u32, reservation: u64) -> Result<(), KernelError> {
        self.transaction(|tx| {
            let (parent, name) = tx.split(path)?;
            if tx.volume.find(path)?.is_some() {
                return fail(0xC000_0035, "nome ja existe");
            }
            let capacity = tx.tx().capacity;
            let mut reference = 16;
            while reference < capacity && bit(&tx.tx().records, reference) {
                reference += 1;
            }
            if reference == capacity {
                return fail(0xC000_007F, "reserva MFT esgotada");
            }
            set_bit(&mut tx.tx().records, reference, true)?;
            let geometry = tx.volume.geometry;
            let raw = tx.volume.read_sectors(geometry.mft_lcn * geometry.sectors_per_cluster + reference * geometry.record_size / geometry.sector_size, 1)?;
            let sequence = if u32_at(&raw, 0) == 0x454C_4946 { u16_at(&raw, 16).max(1) } else { 1 };
            let mut standard = alloc::vec![0u8; 72];
            let time = now();
            for offset in [0, 8, 16, 24] {
                put64(&mut standard, offset, time);
            }
            let flags = (file_attributes & !0x90) | if directory { 0x10 } else { 0x20 };
            put32(&mut standard, 32, flags as u64);
            let file_name = tx.filename(parent.reference, &name, directory, 0, 0, Some(&standard), flags)?;
            let mut list = alloc::vec![resident(0x10, &standard, ""), resident(0x30, &file_name, "")];
            if !directory {
                list.push(resident(0x80, &[], ""));
            }
            tx.record(reference, &list, if directory { 3 } else { 1 }, None, sequence)?;
            if directory {
                tx.directory(reference, Vec::new())?;
            }
            let mut siblings = tx.volume.root_index(parent.reference)?;
            siblings.push(IndexEntry { name, reference, sequence, value: file_name });
            tx.directory(parent.reference, siblings)?;
            if reservation != 0 {
                if directory {
                    return fail(0xC000_000D, "diretorio nao tem reserva DATA");
                }
                tx.mutate_data(path, Some(0), 0, None, Some(reservation))?;
            }
            Ok(())
        })
    }

    fn set_basic(&mut self, path: &str, times: Option<&[u8]>, file_attributes: u32) -> Result<(), KernelError> {
        self.transaction(|tx| {
            let (entry, record) = tx.require_file(path)?;
            let mut list = attributes(&record)?;
            let mut standard = find_attribute(&record, 0x10)?.map(|standard| standard.value).unwrap_or_else(|| alloc::vec![0; 72]);
            if let Some(times) = times {
                for offset in (0..32).step_by(8) {
                    let part = &times[offset..offset + 8];
                    if part.iter().any(|&byte| byte != 0) && !part.iter().all(|&byte| byte == 255) {
                        standard[offset..offset + 8].copy_from_slice(part);
                    }
                }
            }
            if file_attributes != 0 {
                put32(&mut standard, 32, ((file_attributes & !0x90) | if u16_at(&record, 22) & 2 != 0 { 0x10 } else { 0 }) as u64);
            }
            replace(&mut list, 0x10, Some(resident(0x10, &standard, "")));
            let name = find_attribute(&record, 0x30)?.map(|name| name.value).unwrap_or_default();
            tx.refresh_name(entry.reference, &record, &mut list, u64_at(&name, 48), u64_at(&name, 40))
        })
    }
}

/// Espaço do volume pelo $Bitmap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Space {
    pub clusters: u64,
    pub free_clusters: u64,
    pub cluster_size: u64,
    pub sector_size: u64,
    pub sectors_per_cluster: u64,
}

impl Ntfs {
    fn with_writer<T>(&self, action: impl FnOnce(&mut Tx<'_>) -> Result<T, KernelError>) -> Result<T, KernelError> {
        let mut state = self.writer.lock();
        let mut tx = Tx { volume: self, state: &mut state };
        action(&mut tx)
    }

    pub fn query_ea(&self, path: &str, length: usize, options: &ea::QueryOptions, state: &mut ea::QueryState) -> Result<ea::QueryResult, KernelError> {
        let Some(entry) = self.find(path)? else { return fail(0xC000_0034, "arquivo ausente") };
        let record = self.read_record(entry.reference)?;
        let entries = self.with_writer(|tx| tx.read_ea(&record))?;
        Ok(ea::query(&entries, length, options, state))
    }

    pub fn set_ea(&self, path: &str, bytes: &[u8], kernel_call: bool) -> Result<(), KernelError> {
        self.with_writer(|writer| {
            writer.transaction(|tx| {
                let (entry, record) = tx.require_file(path)?;
                let entries = tx.read_ea(&record)?;
                let updated = ea::update(&entries, bytes, kernel_call).map_err(|error| KernelError::with_status("NTFS: EA invalido", error.status))?;
                if ea::encode(&entries, false) == ea::encode(&updated, false) {
                    return Ok(());
                }
                let mut list = attributes(&record)?;
                tx.store_ea(&record, &mut list, &updated, 0)?;
                let mut standard = find_attribute(&record, 0x10)?.map(|standard| standard.value).unwrap_or_else(|| alloc::vec![0; 72]);
                put64(&mut standard, 16, now());
                replace(&mut list, 0x10, Some(resident(0x10, &standard, "")));
                let name = find_attribute(&record, 0x30)?.map(|name| name.value).unwrap_or_default();
                tx.refresh_name(entry.reference, &record, &mut list, u64_at(&name, 48), u64_at(&name, 40))
            })
        })
    }

    pub fn create(&self, path: &str, directory: bool, file_attributes: u32, reservation: u64) -> Result<Option<Stat>, KernelError> {
        self.with_writer(|tx| tx.create(path, directory, file_attributes, reservation))?;
        self.stat(path)
    }

    pub fn write(&self, path: &str, offset: u64, bytes: &[u8]) -> Result<u64, KernelError> {
        if bytes.is_empty() {
            self.with_writer(|tx| tx.require_file(path).map(|_| ()))?;
            return Ok(0);
        }
        self.with_writer(|writer| writer.transaction(|tx| tx.mutate_data(path, None, offset, Some(bytes), None)))
    }

    pub fn write_at(&self, path: &str, offset: u64, bytes: &[u8]) -> Result<u64, KernelError> {
        self.write(path, offset, bytes)
    }

    pub fn resize(&self, path: &str, size: u64) -> Result<u64, KernelError> {
        self.with_writer(|writer| writer.transaction(|tx| tx.mutate_data(path, Some(size), 0, None, None)))
    }

    pub fn allocate(&self, path: &str, size: u64) -> Result<u64, KernelError> {
        self.with_writer(|writer| writer.transaction(|tx| tx.mutate_data(path, Some(0), 0, None, Some(size))))
    }

    pub fn overwrite(&self, path: &str, reservation: u64, file_attributes: u32) -> Result<(), KernelError> {
        self.with_writer(|writer| {
            writer.transaction(|tx| {
                tx.mutate_data(path, Some(0), 0, None, None)?;
                if reservation != 0 {
                    tx.mutate_data(path, Some(0), 0, None, Some(reservation))?;
                }
                if file_attributes != 0 {
                    let current = tx.volume.stat(path)?.map_or(0, |stat| stat.attributes);
                    tx.set_basic(path, None, current | file_attributes)?;
                }
                Ok(())
            })
        })
    }

    pub fn supersede(&self, path: &str, file_attributes: u32, reservation: u64) -> Result<(), KernelError> {
        self.with_writer(|writer| {
            writer.transaction(|tx| {
                tx.remove(path)?;
                tx.create(path, false, file_attributes, reservation)
            })
        })
    }

    pub fn remove(&self, path: &str) -> Result<(), KernelError> {
        self.with_writer(|writer| writer.transaction(|tx| tx.remove(path)))
    }

    pub fn rename(&self, path: &str, target: &str, replace_existing: bool) -> Result<(), KernelError> {
        self.with_writer(|writer| {
            writer.transaction(|tx| {
                let (entry, record) = tx.require_file(path)?;
                let (destination, destination_name) = tx.split(target)?;
                if let Some(existing) = tx.volume.find(target)?.filter(|existing| existing.reference != entry.reference) {
                    if !replace_existing {
                        return fail(0xC000_0035, "destino existe");
                    }
                    if (u16_at(&tx.volume.read_record(existing.reference)?, 22) | u16_at(&record, 22)) & 2 != 0 {
                        return fail(0xC000_0022, "substituicao de diretorio");
                    }
                    tx.remove(target)?;
                }
                // Anda pelos pais reais: apelidos textuais não escapam do ciclo.
                let mut parent = destination.reference;
                let mut depth = 0;
                while parent != 5 {
                    if parent == entry.reference || depth > 256 {
                        return fail(0xC000_000D, "ciclo de diretorios");
                    }
                    let name = find_attribute(&tx.volume.read_record(parent)?, 0x30)?.map(|name| name.value).unwrap_or_default();
                    parent = parent_of(&name);
                    depth += 1;
                }
                let mut list = attributes(&record)?;
                let old = find_attribute(&record, 0x30)?.map(|name| name.value).unwrap_or_default();
                let old_parent = parent_of(&old);
                let mut value = tx.filename(destination.reference, &destination_name, u16_at(&record, 22) & 2 != 0, u64_at(&old, 48), u64_at(&old, 40), Some(&old[8..40]), u32_at(&old, 56))?;
                put32(&mut value, 60, u32_at(&old, 60) as u64);
                replace(&mut list, 0x30, Some(resident(0x30, &value, "")));
                if find_attribute(&record, 0xE0)?.is_some() {
                    let current = tx.read_ea(&record)?;
                    tx.store_ea(&record, &mut list, &current, 0)?;
                }
                tx.record(entry.reference, &list, u16_at(&record, 22), Some(&record), 1)?;
                let remaining = tx.volume.root_index(old_parent)?.into_iter().filter(|child| child.reference != entry.reference).collect();
                tx.directory(old_parent, remaining)?;
                let mut siblings = tx.volume.root_index(destination.reference)?;
                siblings.push(IndexEntry { name: destination_name, value, ..entry });
                tx.directory(destination.reference, siblings)
            })
        })
    }

    pub fn set_basic(&self, path: &str, times: Option<&[u8]>, file_attributes: u32) -> Result<(), KernelError> {
        self.with_writer(|tx| tx.set_basic(path, times, file_attributes))
    }

    pub fn space(&self) -> Result<Space, KernelError> {
        self.with_writer(|tx| {
            tx.load_allocation()?;
            let allocation = tx.state.allocation.as_ref().expect("alocacao carregada");
            let free = (0..allocation.clusters).filter(|&cluster| !bit(&allocation.bits, cluster)).count() as u64;
            Ok(Space { clusters: allocation.clusters, free_clusters: free, cluster_size: tx.cluster(), sector_size: tx.sector(), sectors_per_cluster: tx.volume.geometry.sectors_per_cluster })
        })
    }
}
