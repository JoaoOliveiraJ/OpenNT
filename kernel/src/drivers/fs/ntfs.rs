//! Driver NTFS.
//!
//! Boot sector, MFT com fixup (USA), atributos residentes e não residentes
//! (runlists com deltas com sinal), $FILE_NAME e diretórios B-tree com
//! blocos INDX. As mutações persistentes (`ntfs_write`) e os controles
//! (`ntfs_control`) se acoplam a este volume.
//!
//! Cada drive tem um recurso compartilhado/exclusivo (o `Vcb->Resource` do
//! NTFS): as leituras do volume o tomam compartilhado e uma transação do
//! writer o toma exclusivo, do primeiro setor lido ao fim do commit. Assim
//! nenhuma CPU lê no meio de um commit (com parte dos setores gravados) nem
//! enche os caches com o que o commit acabou de invalidar.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::drivers::storage::ata_pio;
use crate::hal::physical;
use crate::rtl::{KernelError, SharedLock, SpinLock};

const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;

pub fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

pub fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

pub fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u32_at(bytes, offset) as u64 | (u32_at(bytes, offset + 4) as u64) << 32
}

/// Inteiro little-endian com sinal de `length` bytes (só o delta do LCN da
/// runlist tem sinal; a contagem nunca tem).
fn signed_n(bytes: &[u8], offset: usize, length: usize) -> i64 {
    let mut value = unsigned_n(bytes, offset, length) as i64;
    if length > 0 && bytes[offset + length - 1] & 0x80 != 0 {
        value -= 1i64 << (8 * length);
    }
    value
}

fn unsigned_n(bytes: &[u8], offset: usize, length: usize) -> u64 {
    let mut value = 0u64;
    for index in (0..length).rev() {
        value = value * 256 + bytes[offset + index] as u64;
    }
    value
}

fn utf16_at(bytes: &[u8], offset: usize, characters: usize) -> String {
    let units: Vec<u16> = (0..characters).map(|index| u16_at(bytes, offset + index * 2)).collect();
    String::from_utf16_lossy(&units)
}

fn error(message: &str) -> KernelError {
    KernelError::new(message)
}

/// Geometria do volume lida do boot sector.
#[derive(Clone, Copy, Debug)]
pub struct Geometry {
    pub sector_size: u64,
    pub sectors_per_cluster: u64,
    pub mft_lcn: u64,
    pub mirror_lcn: u64,
    pub total_sectors: u64,
    pub serial: u64,
    pub record_size: u64,
    pub cluster_size: u64,
}

/// Atributo de um registro.
#[derive(Clone, Debug)]
pub struct Attribute {
    pub attribute_type: u32,
    pub non_resident: bool,
    pub run_offset: usize,
    pub real_size: u64,
    pub allocated_size: u64,
    pub initialized_size: u64,
    pub record_offset: usize,
    pub raw: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Run {
    pub lcn: i64,
    pub count: u64,
}

/// Entrada de diretório do índice.
#[derive(Clone, Debug)]
pub struct IndexEntry {
    pub name: String,
    pub reference: u64,
    pub sequence: u16,
    pub value: Vec<u8>,
}

/// Run em setores do $DATA não residente.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectorRun {
    pub lba: u64,
    pub sectors: u64,
}

/// Tamanho real e runs (`None` = residente).
#[derive(Clone, Debug)]
pub struct Layout {
    pub size: u64,
    pub runs: Option<Vec<SectorRun>>,
}

/// Escrita pendente sobreposta às leituras (zeros quando `bytes` é `None`).
#[derive(Clone, Debug)]
pub struct PendingWrite {
    pub lba: u64,
    pub count: u64,
    pub bytes: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct VolumeInformation {
    pub label: String,
    pub serial: u32,
    pub creation_time: u64,
    pub file_system: &'static str,
    pub attributes: u32,
    pub maximum_component_length: u32,
    pub supports_objects: bool,
    pub device_type: u32,
    pub characteristics: u32,
}

#[derive(Clone, Debug)]
pub struct Stat {
    pub reference: u64,
    pub sequence: u16,
    pub directory: bool,
    pub size: u64,
    pub allocated: u64,
    pub ea_size: u32,
    pub need_ea: u16,
    pub attributes: u32,
    pub times: Vec<u8>,
}

struct Caches {
    generation: u64,
    directories: BTreeMap<u64, Vec<IndexEntry>>,
    layouts: BTreeMap<String, Option<Layout>>,
}

/// Gerações por drive: mudanças invalidam caches entre montagens.
static GENERATIONS: SpinLock<BTreeMap<u8, u64>> = SpinLock::new(BTreeMap::new());

fn generation_of(drive: u8) -> u64 {
    GENERATIONS.lock().get(&drive).copied().unwrap_or(0)
}

/// Recursos dos drives 0 e 1. São por drive, não por montagem: as montagens
/// do mesmo disco dividem o disco e a geração.
static VOLUME_RESOURCES: [SharedLock; 2] = [SharedLock::new(), SharedLock::new()];

/// Volume NTFS montado.
pub struct Ntfs {
    pub drive: u8,
    pub geometry: Geometry,
    boot: Vec<u8>,
    pub pending: SpinLock<Vec<PendingWrite>>,
    caches: SpinLock<Caches>,
    /// Estado do writer (`ntfs_write`), acoplado na primeira mutação.
    pub(super) writer: super::ntfs_write::WriterLock,
}

fn ascii(bytes: &[u8], offset: usize, length: usize) -> String {
    bytes[offset..offset + length].iter().map(|&byte| byte as char).collect()
}

/// Monta o volume do drive ATA indicado.
pub fn mount(drive: u8) -> Result<Arc<Ntfs>, KernelError> {
    let boot = ata_pio::read_sectors(0, 1, drive)?;
    let oem = ascii(&boot, 3, 8);
    if oem != "NTFS    " {
        return Err(KernelError::new(alloc::format!("NTFS: assinatura ausente ({oem})")));
    }
    let sector_size = u16_at(&boot, 11) as u64;
    let sectors_per_cluster = boot[13] as u64;
    let raw = boot[64] as i8;
    let record_size = if raw < 0 { 1u64 << (-raw as u32) } else { raw as u64 * sector_size * sectors_per_cluster };
    let geometry = Geometry {
        sector_size,
        sectors_per_cluster,
        mft_lcn: u64_at(&boot, 48),
        mirror_lcn: u64_at(&boot, 56),
        total_sectors: u64_at(&boot, 40),
        serial: u64_at(&boot, 72),
        record_size,
        cluster_size: sector_size * sectors_per_cluster,
    };
    if sector_size != 512 || sectors_per_cluster == 0 || !(512..=65536).contains(&record_size) {
        return Err(error("NTFS: geometria nao suportada"));
    }
    let generation = generation_of(drive);
    Ok(Arc::new(Ntfs { drive, geometry, boot, pending: SpinLock::new(Vec::new()), caches: SpinLock::new(Caches { generation, directories: BTreeMap::new(), layouts: BTreeMap::new() }), writer: super::ntfs_write::new_writer() }))
}

/// Volume montado em `\NTFS` (`object_manager::mount` + o volume que o
/// carregador de imagens e o ZwCreateFile resolvem).
static MOUNTED: SpinLock<Option<Arc<Ntfs>>> = SpinLock::new(None);

pub fn set_mounted(volume: Option<Arc<Ntfs>>) {
    *MOUNTED.lock() = volume;
}

pub fn mounted() -> Option<Arc<Ntfs>> {
    MOUNTED.lock().clone()
}

impl super::volume::FileSystem for Ntfs {
    fn name(&self) -> &str {
        "NTFS"
    }

    fn control(&self, path: &str, code: u32, input: &[u8], output_length: u32) -> Option<Result<super::ntfs_control::ControlResult, KernelError>> {
        Some(Ntfs::control(self, path, code, input, output_length))
    }

    fn query_ea(&self, path: &str, length: usize, options: &super::extended_attributes::QueryOptions, state: &mut super::extended_attributes::QueryState) -> Option<Result<super::extended_attributes::QueryResult, KernelError>> {
        Some(Ntfs::query_ea(self, path, length, options, state))
    }

    fn set_ea(&self, path: &str, bytes: &[u8], kernel_call: bool) -> Option<Result<(), KernelError>> {
        Some(Ntfs::set_ea(self, path, bytes, kernel_call))
    }

    fn exists(&self, path: &str) -> bool {
        Ntfs::exists(self, path).unwrap_or(false)
    }

    fn list(&self) -> Vec<String> {
        Ntfs::list(self, "/").ok().flatten().unwrap_or_default()
    }

    fn list_directory(&self, path: &str) -> Vec<String> {
        Ntfs::list(self, path).ok().flatten().unwrap_or_default()
    }

    fn writable(&self) -> bool {
        true
    }

    fn stat(&self, path: &str) -> Option<super::volume::VolumeStat> {
        Ntfs::stat(self, path).ok().flatten().map(|stat| super::volume::VolumeStat { reference: Some(stat.reference), sequence: stat.sequence, directory: stat.directory, size: stat.size, allocated: stat.allocated, attributes: stat.attributes, ea_size: stat.ea_size, need_ea: stat.need_ea, times: stat.times })
    }

    fn read_bytes(&self, path: &str) -> Option<Vec<u8>> {
        let size = Ntfs::stat(self, path).ok().flatten()?.size;
        Ntfs::read_range(self, path, 0, size).ok().flatten()
    }

    fn read_range(&self, path: &str, offset: u64, length: u64) -> Result<Option<Vec<u8>>, KernelError> {
        Ntfs::read_range(self, path, offset, length)
    }

    fn write_at(&self, path: &str, offset: u64, bytes: &[u8]) -> Result<u64, KernelError> {
        Ntfs::write(self, path, offset, bytes)
    }

    fn resize(&self, path: &str, size: u64) -> Option<Result<u64, KernelError>> {
        Some(Ntfs::resize(self, path, size))
    }

    fn copy_range_to_physical(&self, path: &str, offset: u64, address: u64, length: u64) -> Option<Result<(), KernelError>> {
        Some(Ntfs::copy_range_to_physical(self, path, offset, address, length))
    }

    fn truncate(&self, path: &str) -> Result<(), KernelError> {
        if Ntfs::exists(self, path)? {
            Ntfs::resize(self, path, 0).map(|_| ())
        } else {
            Ntfs::create(self, path, false, 0x20, 0).map(|_| ())
        }
    }

    fn remove(&self, path: &str) -> Option<Result<bool, KernelError>> {
        Some(Ntfs::remove(self, path).map(|()| true))
    }

    fn volume_serial(&self) -> Option<u64> {
        Ntfs::volume_information(self).ok().map(|information| information.serial as u64)
    }

    fn volume_query(&self) -> Option<&dyn crate::drivers::fs::volume_information::VolumeQuery> {
        Some(self)
    }
}

/// Percorre os atributos do registro.
pub fn each_attribute(record: &[u8], mut callback: impl FnMut(&Attribute) -> bool) -> Result<(), KernelError> {
    let mut offset = u16_at(record, 20) as usize;
    loop {
        if offset + 8 > record.len() {
            return Err(error("NTFS: atributos fora do record"));
        }
        let attribute_type = u32_at(record, offset);
        if attribute_type == 0xFFFF_FFFF {
            return Ok(());
        }
        let length = u32_at(record, offset + 4) as usize;
        let non_resident = record[offset + 8] != 0;
        if length < if non_resident { 64 } else { 24 } || length % 8 != 0 || offset + length > record.len() {
            return Err(error("NTFS: tamanho de atributo invalido"));
        }
        let raw = record[offset..offset + length].to_vec();
        let attribute = if non_resident {
            Attribute { attribute_type, non_resident, run_offset: offset + u16_at(record, offset + 32) as usize, real_size: u64_at(record, offset + 48), allocated_size: u64_at(record, offset + 40), initialized_size: u64_at(record, offset + 56), record_offset: offset, raw, value: Vec::new() }
        } else {
            let value_length = u32_at(record, offset + 16) as usize;
            let value_offset = u16_at(record, offset + 20) as usize;
            if value_offset < 24 || value_offset + value_length > length {
                return Err(error("NTFS: valor residente invalido"));
            }
            Attribute { attribute_type, non_resident, run_offset: 0, real_size: 0, allocated_size: 0, initialized_size: 0, record_offset: offset, raw, value: record[offset + value_offset..offset + value_offset + value_length].to_vec() }
        };
        if !callback(&attribute) {
            return Ok(());
        }
        offset += length;
    }
}

pub fn find_attribute(record: &[u8], attribute_type: u32) -> Result<Option<Attribute>, KernelError> {
    let mut found = None;
    each_attribute(record, |attribute| {
        if attribute.attribute_type == attribute_type {
            found = Some(attribute.clone());
            return false;
        }
        true
    })?;
    Ok(found)
}

/// Runlist -> runs; runs esparsas ou vazias não são suportadas.
pub fn parse_runs(record: &[u8], run_offset: usize) -> Result<Vec<Run>, KernelError> {
    let mut runs = Vec::new();
    let mut offset = run_offset;
    let mut lcn = 0i64;
    loop {
        let header = record[offset];
        if header == 0 {
            return Ok(runs);
        }
        let length_size = (header & 0x0F) as usize;
        let offset_size = (header >> 4) as usize;
        if length_size == 0 || length_size > 6 || offset_size > 6 || offset + 1 + length_size + offset_size >= record.len() {
            return Err(error("NTFS: runlist invalida"));
        }
        let count = unsigned_n(record, offset + 1, length_size);
        if count == 0 || offset_size == 0 {
            return Err(error("NTFS: run sparse/zero nao suportada"));
        }
        lcn += signed_n(record, offset + 1 + length_size, offset_size);
        runs.push(Run { lcn, count });
        offset += 1 + length_size + offset_size;
    }
}

fn file_name_of(value: &[u8]) -> String {
    utf16_at(value, 66, value[64] as usize)
}

/// Desfaz o fixup USA de um bloco de `sectors` setores.
fn apply_fixup(block: &mut [u8], usa: usize, count: usize, sector_size: usize, message: &str) -> Result<(), KernelError> {
    let usn = u16_at(block, usa);
    for index in 1..count {
        let tail = index * sector_size - 2;
        if u16_at(block, tail) != usn {
            return Err(error(message));
        }
        block[tail] = block[usa + index * 2];
        block[tail + 1] = block[usa + index * 2 + 1];
    }
    Ok(())
}

impl Ntfs {
    /// O recurso do volume: compartilhado nas leituras, exclusivo nas
    /// transações.
    pub fn resource(&self) -> &'static SharedLock {
        &VOLUME_RESOURCES[self.drive as usize % VOLUME_RESOURCES.len()]
    }

    /// Lê setores com as escritas pendentes sobrepostas.
    pub fn read_sectors(&self, lba: u64, count: u64) -> Result<Vec<u8>, KernelError> {
        let _shared = self.resource().acquire_shared();
        let mut bytes = ata_pio::read_sectors(lba, count as u32, self.drive)?;
        for operation in self.pending.lock().iter() {
            let first = lba.max(operation.lba);
            let last = (lba + count).min(operation.lba + operation.count);
            if first >= last {
                continue;
            }
            let target = ((first - lba) * 512) as usize..((last - lba) * 512) as usize;
            match &operation.bytes {
                Some(source) => bytes[target].copy_from_slice(&source[((first - operation.lba) * 512) as usize..((last - operation.lba) * 512) as usize]),
                None => bytes[target].fill(0),
            }
        }
        Ok(bytes)
    }

    /// Registro MFT com fixup.
    pub fn read_record(&self, number: u64) -> Result<Vec<u8>, KernelError> {
        let _shared = self.resource().acquire_shared();
        let volume = &self.geometry;
        let offset = volume.mft_lcn * volume.cluster_size + number * volume.record_size;
        let mut record = self.read_sectors(offset / volume.sector_size, volume.record_size / volume.sector_size)?;
        if &record[0..4] != b"FILE" {
            return Err(KernelError::new(alloc::format!("NTFS: record sem magic FILE (rec {number})")));
        }
        let usa = u16_at(&record, 4) as usize;
        let count = u16_at(&record, 6) as usize;
        if count as u64 != volume.record_size / volume.sector_size + 1 || usa < 8 || usa + count * 2 > u16_at(&record, 20) as usize {
            return Err(error("NTFS: USA de record invalida"));
        }
        apply_fixup(&mut record, usa, count, volume.sector_size as usize, "NTFS: fixup USN invalido")?;
        Ok(record)
    }

    /// Conteúdo de um atributo (residente ou pela runlist).
    pub fn read_data(&self, record: &[u8], attribute_type: u32) -> Result<Vec<u8>, KernelError> {
        let _shared = self.resource().acquire_shared();
        let Some(data) = find_attribute(record, attribute_type)? else { return Ok(Vec::new()) };
        if !data.non_resident {
            return Ok(data.value);
        }
        let runs = parse_runs(record, data.run_offset)?;
        let mut out = Vec::with_capacity(data.real_size as usize);
        for run in runs {
            if out.len() as u64 >= data.real_size {
                break;
            }
            let spc = self.geometry.sectors_per_cluster;
            let chunk = self.read_sectors(run.lcn as u64 * spc, run.count * spc)?;
            let take = chunk.len().min(data.real_size as usize - out.len());
            out.extend_from_slice(&chunk[..take]);
        }
        if (out.len() as u64) < data.real_size {
            return Err(error("NTFS: runlist menor que atributo"));
        }
        Ok(out)
    }

    pub fn generation(&self) -> u64 {
        generation_of(self.drive)
    }

    pub fn invalidate(&self) {
        let mut caches = self.caches.lock();
        caches.directories.clear();
        caches.layouts.clear();
    }

    fn fresh(&self) {
        let current = generation_of(self.drive);
        let mut caches = self.caches.lock();
        if caches.generation != current {
            caches.directories.clear();
            caches.layouts.clear();
            caches.generation = current;
        }
    }

    /// Mutação persistente: avança a geração do drive.
    pub fn changed(&self) {
        let _exclusive = self.resource().acquire_exclusive();
        *GENERATIONS.lock().entry(self.drive).or_insert(0) += 1;
        self.fresh();
    }

    /// Entradas do diretório `reference`, com blocos INDX dos índices grandes.
    pub fn root_index(&self, reference: u64) -> Result<Vec<IndexEntry>, KernelError> {
        let _shared = self.resource().acquire_shared();
        self.fresh();
        if let Some(entries) = self.caches.lock().directories.get(&reference) {
            return Ok(entries.clone());
        }
        let root = self.read_record(reference)?;
        if u16_at(&root, 22) & 2 == 0 {
            return Err(KernelError::with_status("NTFS: nao e diretorio", STATUS_NOT_A_DIRECTORY));
        }
        let index = find_attribute(&root, 0x90)?.filter(|index| !index.non_resident).ok_or_else(|| error("NTFS: $INDEX_ROOT nao residente nao suportado"))?;
        let allocation = find_attribute(&root, 0xA0)?;
        let block_size = u32_at(&index.value, 8) as u64;
        let runs = match &allocation {
            Some(allocation) if allocation.non_resident => parse_runs(&root, allocation.run_offset)?,
            _ => Vec::new(),
        };
        let mut visited = alloc::collections::BTreeSet::new();
        let mut names = Vec::new();
        let read_block = |vcn: u64, visited: &mut alloc::collections::BTreeSet<u64>| -> Result<Vec<u8>, KernelError> {
            if !visited.insert(vcn) || visited.len() > 65536 {
                return Err(error("NTFS: ciclo no indice"));
            }
            let offset = vcn * self.geometry.cluster_size.min(block_size);
            let valid = allocation.as_ref().is_some_and(|allocation| allocation.non_resident && offset + block_size <= allocation.real_size);
            if !valid || !(512..=65536).contains(&block_size) {
                return Err(error("NTFS: VCN de indice invalido"));
            }
            let mut block = alloc::vec![0u8; block_size as usize];
            let (mut cursor, mut done, mut run_start) = (offset, 0u64, 0u64);
            for run in &runs {
                let run_end = run_start + run.count * self.geometry.cluster_size;
                if cursor >= run_end {
                    run_start = run_end;
                    continue;
                }
                let take = (block_size - done).min(run_end - cursor);
                let physical_offset = run.lcn as u64 * self.geometry.cluster_size + cursor - run_start;
                let sectors = self.read_sectors(physical_offset / self.geometry.sector_size, take / self.geometry.sector_size)?;
                block[done as usize..(done + take) as usize].copy_from_slice(&sectors[..take as usize]);
                cursor += take;
                done += take;
                run_start = run_end;
                if done == block_size {
                    break;
                }
            }
            if done != block_size || &block[0..4] != b"INDX" || u64_at(&block, 16) != vcn {
                return Err(error("NTFS: bloco INDX invalido"));
            }
            let usa = u16_at(&block, 4) as usize;
            let count = u16_at(&block, 6) as usize;
            if count as u64 != block_size / self.geometry.sector_size + 1 || usa + count * 2 > block_size as usize {
                return Err(error("NTFS: USA de indice invalida"));
            }
            apply_fixup(&mut block, usa, count, self.geometry.sector_size as usize, "NTFS: fixup INDX invalido")?;
            Ok(block)
        };
        fn walk(node: &[u8], header: usize, depth: u32, names: &mut Vec<IndexEntry>, visited: &mut alloc::collections::BTreeSet<u64>, read_block: &dyn Fn(u64, &mut alloc::collections::BTreeSet<u64>) -> Result<Vec<u8>, KernelError>) -> Result<(), KernelError> {
            if depth > 32 {
                return Err(error("NTFS: profundidade de indice invalida"));
            }
            let mut offset = header + u32_at(node, header) as usize;
            let end = header + u32_at(node, header + 4) as usize;
            if offset < header + 16 || end > node.len() || end < offset {
                return Err(error("NTFS: limites de indice invalidos"));
            }
            while offset + 16 <= end {
                let size = u16_at(node, offset + 8) as usize;
                let stream_length = u16_at(node, offset + 10) as usize;
                let flags = u16_at(node, offset + 12);
                if size < 16 || size % 8 != 0 || offset + size > end || 16 + stream_length + if flags & 1 != 0 { 8 } else { 0 } > size {
                    return Err(error("NTFS: entrada de indice invalida"));
                }
                if flags & 1 != 0 {
                    let child = read_block(u64_at(node, offset + size - 8), visited)?;
                    walk(&child, 24, depth + 1, names, visited, read_block)?;
                }
                if flags & 2 != 0 {
                    return Ok(());
                }
                if stream_length < 66 || 66 + node[offset + 16 + 64] as usize * 2 > stream_length {
                    return Err(error("NTFS: nome de indice invalido"));
                }
                let reference = u32_at(node, offset) as u64 | (u16_at(node, offset + 4) as u64) << 32;
                let value = node[offset + 16..offset + 16 + stream_length].to_vec();
                names.push(IndexEntry { name: file_name_of(&value), reference, sequence: u16_at(node, offset + 6), value });
                offset += size;
            }
            Err(error("NTFS: indice sem entrada final"))
        }
        walk(&index.value, 16, 0, &mut names, &mut visited, &read_block)?;
        self.caches.lock().directories.insert(reference, names.clone());
        Ok(names)
    }

    /// Resolve um caminho `/A/B` sem diferença de caixa; `.` e `..` são recusados.
    pub fn find(&self, path: &str) -> Result<Option<IndexEntry>, KernelError> {
        let _shared = self.resource().acquire_shared();
        self.fresh();
        let mut found = IndexEntry { name: String::new(), reference: 5, sequence: 0, value: Vec::new() };
        for part in path.split('/').filter(|part| !part.is_empty()) {
            if part == "." || part == ".." {
                return Err(error("NTFS: caminho nao canonico"));
            }
            let wanted = part.to_uppercase();
            match self.root_index(found.reference)?.into_iter().find(|entry| entry.name.to_uppercase() == wanted) {
                Some(entry) => found = entry,
                None => return Ok(None),
            }
        }
        Ok(Some(found))
    }

    pub fn volume_information(&self) -> Result<VolumeInformation, KernelError> {
        let _shared = self.resource().acquire_shared();
        let record = self.read_record(3)?;
        let name = find_attribute(&record, 0x60)?;
        let standard = find_attribute(&record, 0x10)?;
        let invalid = name.as_ref().is_some_and(|name| name.non_resident || name.value.len() % 2 != 0) || standard.as_ref().is_none_or(|standard| standard.non_resident || standard.value.len() < 8);
        if invalid {
            return Err(error("NTFS: metadados de volume invalidos"));
        }
        let standard = standard.unwrap();
        Ok(VolumeInformation {
            label: name.map(|name| utf16_at(&name.value, 0, name.value.len() / 2)).unwrap_or_default(),
            serial: u32_at(&self.boot, 72),
            creation_time: u64_at(&standard.value, 0),
            file_system: "NTFS",
            attributes: 6,
            maximum_component_length: 255,
            supports_objects: false,
            device_type: 7,
            characteristics: 0,
        })
    }

    pub fn exists(&self, path: &str) -> Result<bool, KernelError> {
        Ok(self.find(path)?.is_some())
    }

    pub fn list(&self, path: &str) -> Result<Option<Vec<String>>, KernelError> {
        let _shared = self.resource().acquire_shared();
        let Some(entry) = self.find(path)? else { return Ok(None) };
        let prefix = path.trim_end_matches('/');
        Ok(Some(self.root_index(entry.reference)?.into_iter().map(|child| alloc::format!("{prefix}/{}", child.name)).collect()))
    }

    pub fn stat(&self, path: &str) -> Result<Option<Stat>, KernelError> {
        let _shared = self.resource().acquire_shared();
        let Some(entry) = self.find(path)? else { return Ok(None) };
        let record = self.read_record(entry.reference)?;
        let data = find_attribute(&record, 0x80)?;
        let standard = find_attribute(&record, 0x10)?;
        let ea = find_attribute(&record, 0xD0)?.filter(|ea| !ea.non_resident);
        let directory = u16_at(&record, 22) & 2 != 0;
        let file_attributes = standard.as_ref().map(|standard| u32_at(&standard.value, 32)).filter(|&value| value != 0).unwrap_or(if directory { 0x10 } else { 0x20 });
        Ok(Some(Stat {
            reference: entry.reference,
            sequence: u16_at(&record, 16),
            directory,
            size: data.as_ref().map_or(0, |data| if data.non_resident { data.real_size } else { data.value.len() as u64 }),
            allocated: data.as_ref().filter(|data| data.non_resident).map_or(0, |data| data.allocated_size),
            ea_size: ea.as_ref().map_or(0, |ea| u32_at(&ea.value, 4)),
            need_ea: ea.as_ref().map_or(0, |ea| u16_at(&ea.value, 2)),
            attributes: file_attributes,
            times: standard.map_or(alloc::vec![0; 32], |standard| standard.value[..32].to_vec()),
        }))
    }

    /// Tamanho real e runs em setores do $DATA, sem ler o arquivo inteiro.
    pub fn file_layout(&self, path: &str) -> Result<Option<Layout>, KernelError> {
        let _shared = self.resource().acquire_shared();
        self.fresh();
        let key = path.to_lowercase();
        if let Some(layout) = self.caches.lock().layouts.get(&key) {
            return Ok(layout.clone());
        }
        let Some(entry) = self.find(path)? else { return Ok(None) };
        let record = self.read_record(entry.reference)?;
        let layout = match find_attribute(&record, 0x80)? {
            None => None,
            Some(data) if !data.non_resident => Some(Layout { size: data.value.len() as u64, runs: None }),
            Some(data) => {
                let spc = self.geometry.sectors_per_cluster;
                Some(Layout { size: data.real_size, runs: Some(parse_runs(&record, data.run_offset)?.iter().map(|run| SectorRun { lba: run.lcn as u64 * spc, sectors: run.count * spc }).collect()) })
            }
        };
        self.caches.lock().layouts.insert(key, layout.clone());
        Ok(layout)
    }

    /// Lê `[offset, offset+length)` do $DATA andando pelas runs.
    pub fn read_range(&self, path: &str, offset: u64, length: u64) -> Result<Option<Vec<u8>>, KernelError> {
        let _shared = self.resource().acquire_shared();
        let Some(layout) = self.file_layout(path)? else { return Ok(None) };
        let length = length.min(layout.size.saturating_sub(offset));
        if length == 0 {
            return Ok(Some(Vec::new()));
        }
        let Some(runs) = layout.runs else {
            let entry = self.find(path)?.ok_or_else(|| error("NTFS: arquivo sumiu"))?;
            let record = self.read_record(entry.reference)?;
            let value = find_attribute(&record, 0x80)?.map(|data| data.value).unwrap_or_default();
            return Ok(Some(value[offset as usize..(offset + length) as usize].to_vec()));
        };
        let mut out = Vec::with_capacity(length as usize);
        let mut file_sector_base = 0u64;
        for run in runs {
            let run_start = file_sector_base * 512;
            let run_end = run_start + run.sectors * 512;
            let want = offset + out.len() as u64;
            if want >= run_end {
                file_sector_base += run.sectors;
                continue;
            }
            let from = want.max(run_start);
            let to = (offset + length).min(run_end);
            let lba = run.lba + (from - run_start) / 512;
            let skip = ((from - run_start) % 512) as usize;
            let sectors = (skip as u64 + (to - from)).div_ceil(512);
            let chunk = self.read_sectors(lba, sectors)?;
            out.extend_from_slice(&chunk[skip..skip + (to - from) as usize]);
            if out.len() as u64 >= length {
                break;
            }
            file_sector_base += run.sectors;
        }
        Ok(Some(out))
    }

    /// Copia `[offset, offset+length)` do $DATA direto para a memória física:
    /// o miolo alinhado vai por DMA de bus master e os cantos por um setor.
    pub fn copy_range_to_physical(&self, path: &str, offset: u64, destination: u64, length: u64) -> Result<(), KernelError> {
        let _shared = self.resource().acquire_shared();
        let layout = self.file_layout(path)?.filter(|layout| offset + length <= layout.size).ok_or_else(|| error("NTFS: faixa de copia invalida"))?;
        let Some(runs) = layout.runs else {
            let bytes = self.read_range(path, offset, length)?.unwrap_or_default();
            physical::write_bytes(destination, &bytes);
            return Ok(());
        };
        let (mut cursor, mut target, mut remaining, mut run_start) = (offset, destination, length, 0u64);
        for run in runs {
            let run_end = run_start + run.sectors * 512;
            if cursor >= run_end {
                run_start = run_end;
                continue;
            }
            while remaining > 0 && cursor < run_end {
                let in_run = cursor - run_start;
                let sector_offset = in_run % 512;
                let available = remaining.min(run_end - cursor);
                let lba = run.lba + in_run / 512;
                let take = if sector_offset == 0 && available >= 512 && target % 2 == 0 {
                    let take = available / 512 * 512;
                    ata_pio::read_sectors_dma_to_physical(lba, (take / 512) as u32, self.drive, target)?;
                    take
                } else {
                    let sector = ata_pio::read_sectors(lba, 1, self.drive)?;
                    let take = (512 - sector_offset).min(available);
                    physical::write_bytes(target, &sector[sector_offset as usize..(sector_offset + take) as usize]);
                    take
                };
                cursor += take;
                target += take;
                remaining -= take;
            }
            if remaining == 0 {
                return Ok(());
            }
            run_start = run_end;
        }
        if remaining != 0 {
            return Err(error("NTFS: runlist menor que o tamanho do arquivo"));
        }
        Ok(())
    }

    /// Só metadado (registro e runlist); -1 quando o arquivo não existe.
    pub fn size(&self, path: &str) -> Result<i64, KernelError> {
        Ok(self.file_layout(path)?.map_or(-1, |layout| layout.size as i64))
    }

    pub fn read_bytes(&self, path: &str) -> Result<Option<Vec<u8>>, KernelError> {
        let _shared = self.resource().acquire_shared();
        let Some(entry) = self.find(path)? else { return Ok(None) };
        let record = self.read_record(entry.reference)?;
        self.read_data(&record, 0x80).map(Some)
    }

    /// Conteúdo como texto latin-1.
    pub fn read(&self, path: &str) -> Result<Option<String>, KernelError> {
        Ok(self.read_bytes(path)?.map(|bytes| bytes.iter().map(|&byte| byte as char).collect()))
    }

    pub fn flush(&self) -> Result<(), KernelError> {
        ata_pio::flush(self.drive)
    }
}
