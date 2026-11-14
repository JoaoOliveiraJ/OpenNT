//! Armazenamento de uma hive: o bloco base, os bins e as células (o Hv do
//! NT: HvGetCell, HvAllocateCell, HvFreeCell, HvReallocateCell,
//! HvMarkCellDirty e o mapa de bins).
//!
//! Um índice de célula é o offset dela a partir do primeiro bin (o offset
//! no arquivo menos 0x1000) e aponta para o tamanho: um `i32` negativo para
//! célula alocada e positivo para livre, múltiplo de 8 e incluindo os quatro
//! bytes do próprio tamanho. Os dados começam logo depois (o endereço que o
//! HvGetCell devolve). Cada bin começa com o `_HBIN` de 0x20 bytes e tem
//! tamanho múltiplo de 0x1000; as células cobrem o resto dele sem buracos.
//!
//! O vetor de sujeira tem um bit por setor de 512 bytes dos dados de bins
//! (HSECTOR_SIZE), como o DirtyVector do `_HHIVE`: toda escrita numa célula
//! marca os setores que ela cobre, e a descarga (`sync`) grava só eles.
//!
//! Os bins são blocos próprios do kernel que não mudam de endereço quando a
//! hive cresce (cada bin novo é outro bloco, como as vistas do NT), então o
//! endereço de uma célula vale enquanto ela não é liberada.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::ntos::inc::types::{HbaseBlock, Hbin};
use crate::ntos::inc::types::NtStruct;

pub const HBLOCK_SIZE: u32 = 0x1000;
pub const HSECTOR_SIZE: u32 = 0x200;
pub const HBIN_HEADER: u32 = 0x20;
pub const HCELL_NIL: u32 = 0xFFFF_FFFF;
/// 'regf' e 'hbin'.
pub const HBASE_SIGNATURE: u32 = 0x6667_6572;
pub const HBIN_SIGNATURE: u32 = 0x6e69_6268;

/// STATUS_REGISTRY_CORRUPT e STATUS_INSUFFICIENT_RESOURCES.
pub const STATUS_REGISTRY_CORRUPT: u32 = 0xC000_014C;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// Um bin: o offset a partir do primeiro bin e os bytes (cabeçalho + células).
struct Bin {
    offset: u32,
    data: Vec<u64>,
}

impl Bin {
    fn size(&self) -> u32 {
        (self.data.len() * 8) as u32
    }

    fn address(&self) -> u64 {
        self.data.as_ptr() as u64
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: o vetor de u64 tem `size()` bytes inicializados.
        unsafe { core::slice::from_raw_parts(self.data.as_ptr() as *const u8, self.data.len() * 8) }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: idem, com acesso exclusivo.
        unsafe { core::slice::from_raw_parts_mut(self.data.as_mut_ptr() as *mut u8, self.data.len() * 8) }
    }
}

fn round_up(value: u32, alignment: u32) -> u32 {
    value.div_ceil(alignment) * alignment
}

/// A hive na memória.
pub struct Storage {
    base: Vec<u64>,
    bins: Vec<Bin>,
    /// Células livres: índice -> tamanho.
    free: BTreeMap<u32, u32>,
    dirty: Vec<u64>,
    /// O bloco base mudou desde a última descarga.
    base_dirty: bool,
    /// Uma operação de célula falhou: a hive não corresponde mais à árvore
    /// e não pode ser descarregada.
    pub broken: bool,
}

impl Storage {
    /// Hive vazia (HvHiveStartMemoryBacked): bloco base zerado com 'regf',
    /// Sequence1 = Sequence2 = 1, Major 1, a versão pedida, Format 1,
    /// Cluster 1, RootCell nil, o carimbo de tempo e o nome do arquivo.
    pub fn new(minor: u32, time: u64, file_name: &str) -> Storage {
        let storage = Storage { base: vec![0u64; (HBLOCK_SIZE / 8) as usize], bins: Vec::new(), free: BTreeMap::new(), dirty: Vec::new(), base_dirty: true, broken: false };
        let base = storage.base_block();
        base.signature.set(HBASE_SIGNATURE);
        base.sequence1.set(1);
        base.sequence2.set(1);
        base.time_stamp.quad_part.set(time as i64);
        base.major.set(1);
        base.minor.set(minor);
        base.type_.set(0);
        base.format.set(1);
        base.root_cell.set(HCELL_NIL);
        base.length.set(0);
        base.cluster.set(1);
        super::base_block::fill_file_name(base, file_name);
        storage
    }

    /// O `_HBASE_BLOCK` da hive.
    pub fn base_block(&self) -> &HbaseBlock {
        // SAFETY: bloco próprio de 0x1000 bytes, vivo enquanto a hive existe.
        unsafe { HbaseBlock::at(self.base.as_ptr() as u64) }
    }

    pub fn minor(&self) -> u32 {
        self.base_block().minor.get()
    }

    pub fn root_cell(&self) -> u32 {
        self.base_block().root_cell.get()
    }

    pub fn set_root_cell(&mut self, cell: u32) {
        self.base_block().root_cell.set(cell);
        self.base_dirty = true;
    }

    /// Tamanho dos dados de bins.
    pub fn length(&self) -> u32 {
        self.bins.last().map_or(0, |bin| bin.offset + bin.size())
    }

    fn bin_index(&self, offset: u32) -> Option<usize> {
        let index = self.bins.partition_point(|bin| bin.offset <= offset);
        let index = index.checked_sub(1)?;
        let bin = &self.bins[index];
        (offset < bin.offset + bin.size()).then_some(index)
    }

    /// Lê o campo de tamanho de uma célula.
    fn raw_size(&self, cell: u32) -> Option<i32> {
        let index = self.bin_index(cell)?;
        let bin = &self.bins[index];
        let local = (cell - bin.offset) as usize;
        if cell & 7 != 0 || local < HBIN_HEADER as usize || local + 4 > bin.size() as usize {
            return None;
        }
        let bytes = bin.bytes();
        Some(i32::from_le_bytes([bytes[local], bytes[local + 1], bytes[local + 2], bytes[local + 3]]))
    }

    /// Tamanho de uma célula alocada (com os 4 bytes do cabeçalho).
    pub fn cell_size(&self, cell: u32) -> Option<u32> {
        let size = self.raw_size(cell)?;
        (size < 0).then(|| size.unsigned_abs())
    }

    /// HvGetCell: o endereço dos dados de uma célula alocada, com pelo menos
    /// `minimum` bytes.
    pub fn cell(&self, cell: u32, minimum: u32) -> Option<u64> {
        let size = self.cell_size(cell)?;
        if size < 4 + minimum {
            return None;
        }
        let index = self.bin_index(cell)?;
        let bin = &self.bins[index];
        if cell - bin.offset + size > bin.size() {
            return None;
        }
        Some(bin.address() + (cell - bin.offset) as u64 + 4)
    }

    /// Bytes de dados de uma célula alocada.
    pub fn read_cell(&self, cell: u32, length: u32) -> Option<Vec<u8>> {
        let size = self.cell_size(cell)?;
        if length + 4 > size {
            return None;
        }
        let bin = &self.bins[self.bin_index(cell)?];
        let local = (cell - bin.offset + 4) as usize;
        Some(bin.bytes()[local..local + length as usize].to_vec())
    }

    /// Escreve bytes nos dados de uma célula alocada e a marca suja.
    pub fn write_cell(&mut self, cell: u32, offset: u32, data: &[u8]) -> bool {
        let Some(size) = self.cell_size(cell) else { return false };
        if offset as usize + data.len() + 4 > size as usize {
            return false;
        }
        let Some(index) = self.bin_index(cell) else { return false };
        let bin = &mut self.bins[index];
        let local = (cell - bin.offset + 4 + offset) as usize;
        bin.bytes_mut()[local..local + data.len()].copy_from_slice(data);
        self.mark_range(cell, size);
        true
    }

    fn write_size(&mut self, cell: u32, size: i32) {
        if let Some(index) = self.bin_index(cell) {
            let bin = &mut self.bins[index];
            let local = (cell - bin.offset) as usize;
            bin.bytes_mut()[local..local + 4].copy_from_slice(&size.to_le_bytes());
        }
    }

    fn mark_range(&mut self, offset: u32, length: u32) {
        if length == 0 {
            return;
        }
        let first = offset / HSECTOR_SIZE;
        let last = (offset + length - 1) / HSECTOR_SIZE;
        for sector in first..=last {
            let word = (sector / 64) as usize;
            if word >= self.dirty.len() {
                self.dirty.resize(word + 1, 0);
            }
            self.dirty[word] |= 1u64 << (sector % 64);
        }
    }

    /// HvMarkCellDirty.
    pub fn mark_cell_dirty(&mut self, cell: u32) {
        if let Some(size) = self.cell_size(cell) {
            self.mark_range(cell, size);
        }
    }

    pub fn mark_base_dirty(&mut self) {
        self.base_dirty = true;
    }

    /// HvpAddBin: um bin novo no fim, com espaço para `needed` bytes de
    /// célula; o que sobra vira uma célula livre.
    fn add_bin(&mut self, needed: u32) -> u32 {
        let size = round_up(needed + HBIN_HEADER, HBLOCK_SIZE);
        let offset = self.length();
        let mut bin = Bin { offset, data: vec![0u64; (size / 8) as usize] };
        {
            let bytes = bin.bytes_mut();
            bytes[0..4].copy_from_slice(&HBIN_SIGNATURE.to_le_bytes());
            bytes[4..8].copy_from_slice(&offset.to_le_bytes());
            bytes[8..12].copy_from_slice(&size.to_le_bytes());
        }
        if offset == 0 {
            // SAFETY: cabeçalho do bin recém-criado.
            unsafe { Hbin::at(bin.address()) }.time_stamp.quad_part.set(self.base_block().time_stamp.quad_part.get());
        }
        let cell = offset + HBIN_HEADER;
        let free = size - HBIN_HEADER;
        self.bins.push(bin);
        self.write_size(cell, free as i32);
        self.free.insert(cell, free);
        self.mark_range(offset, size);
        self.base_block().length.set(self.length());
        self.base_dirty = true;
        cell
    }

    /// HvAllocateCell: `data_size` bytes de dados (o tamanho da célula é
    /// arredondado para 8 com os 4 bytes do cabeçalho). Os dados vêm zerados.
    pub fn allocate(&mut self, data_size: u32) -> Option<u32> {
        let needed = round_up(data_size.checked_add(4)?, 8);
        let candidate = self.free.iter().filter(|&(_, &size)| size >= needed).min_by_key(|&(&cell, &size)| (size, cell)).map(|(&cell, &size)| (cell, size));
        let (cell, size) = match candidate {
            Some(found) => found,
            None => {
                let cell = self.add_bin(needed);
                (cell, self.free[&cell])
            }
        };
        self.free.remove(&cell);
        let remainder = size - needed;
        let used = if remainder >= 8 {
            let rest = cell + needed;
            self.write_size(rest, remainder as i32);
            self.free.insert(rest, remainder);
            self.mark_range(rest, 8);
            needed
        } else {
            size
        };
        self.write_size(cell, -(used as i32));
        let index = self.bin_index(cell)?;
        let bin = &mut self.bins[index];
        let local = (cell - bin.offset + 4) as usize;
        bin.bytes_mut()[local..local + (used - 4) as usize].fill(0);
        self.mark_range(cell, used);
        Some(cell)
    }

    /// HvFreeCell: a célula volta a ser livre e se junta às vizinhas livres
    /// do mesmo bin.
    pub fn free(&mut self, cell: u32) {
        let Some(size) = self.cell_size(cell) else { return };
        let Some(index) = self.bin_index(cell) else { return };
        let (bin_start, bin_end) = (self.bins[index].offset, self.bins[index].offset + self.bins[index].size());
        let mut start = cell;
        let mut length = size;
        let next = cell + size;
        if next < bin_end {
            if let Some(next_size) = self.free.remove(&next) {
                length += next_size;
            }
        }
        if let Some((&previous, &previous_size)) = self.free.range(bin_start..cell).next_back() {
            if previous + previous_size == cell {
                self.free.remove(&previous);
                start = previous;
                length += previous_size;
            }
        }
        self.write_size(start, length as i32);
        self.free.insert(start, length);
        self.mark_range(cell, size);
        self.mark_range(start, 8);
    }

    /// HvReallocateCell: a mesma célula quando cabe, senão uma nova com os
    /// dados copiados e a antiga liberada.
    pub fn reallocate(&mut self, cell: u32, data_size: u32) -> Option<u32> {
        let size = self.cell_size(cell)?;
        if data_size + 4 <= size {
            self.mark_range(cell, size);
            return Some(cell);
        }
        let old = self.read_cell(cell, size - 4)?;
        let new = self.allocate(data_size)?;
        self.write_cell(new, 0, &old);
        self.free(cell);
        Some(new)
    }

    /// Carrega a imagem de um arquivo primário já validada pelo bloco base:
    /// cada bin com assinatura, offset e tamanho coerentes, e as células
    /// cobrindo o bin inteiro.
    pub fn from_image(image: &[u8]) -> Result<Storage, u32> {
        if image.len() < HBLOCK_SIZE as usize {
            return Err(STATUS_REGISTRY_CORRUPT);
        }
        let mut storage = Storage { base: vec![0u64; (HBLOCK_SIZE / 8) as usize], bins: Vec::new(), free: BTreeMap::new(), dirty: Vec::new(), base_dirty: false, broken: false };
        // SAFETY: bloco próprio de 0x1000 bytes.
        unsafe { core::slice::from_raw_parts_mut(storage.base.as_mut_ptr() as *mut u8, HBLOCK_SIZE as usize) }.copy_from_slice(&image[..HBLOCK_SIZE as usize]);
        let length = storage.base_block().length.get();
        if length % HBLOCK_SIZE != 0 || HBLOCK_SIZE as usize + length as usize > image.len() {
            return Err(STATUS_REGISTRY_CORRUPT);
        }
        let data = &image[HBLOCK_SIZE as usize..HBLOCK_SIZE as usize + length as usize];
        let read32 = |offset: usize| u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        let mut offset = 0u32;
        while offset < length {
            let at = offset as usize;
            let size = read32(at + 8);
            if read32(at) != HBIN_SIGNATURE || read32(at + 4) != offset || size < HBLOCK_SIZE || size % HBLOCK_SIZE != 0 || offset as u64 + size as u64 > length as u64 {
                return Err(STATUS_REGISTRY_CORRUPT);
            }
            let mut bin = Bin { offset, data: vec![0u64; (size / 8) as usize] };
            bin.bytes_mut().copy_from_slice(&data[at..at + size as usize]);
            let mut cursor = HBIN_HEADER;
            while cursor < size {
                let raw = read32(at + cursor as usize) as i32;
                let cell_size = raw.unsigned_abs();
                if raw == 0 || cell_size % 8 != 0 || cursor as u64 + cell_size as u64 > size as u64 {
                    return Err(STATUS_REGISTRY_CORRUPT);
                }
                if raw > 0 {
                    storage.free.insert(offset + cursor, cell_size);
                }
                cursor += cell_size;
            }
            storage.bins.push(bin);
            offset += size;
        }
        Ok(storage)
    }

    /// A imagem completa do arquivo primário (bloco base com a soma
    /// recalculada e os bins).
    pub fn image(&self) -> Vec<u8> {
        let mut image = Vec::with_capacity((HBLOCK_SIZE + self.length()) as usize);
        image.extend_from_slice(&self.base_bytes());
        for bin in &self.bins {
            image.extend_from_slice(bin.bytes());
        }
        image
    }

    /// Os 0x1000 bytes do bloco base, com a soma recalculada.
    pub fn base_bytes(&self) -> Vec<u8> {
        let base = self.base_block();
        base.check_sum.set(super::base_block::checksum(base));
        // SAFETY: bloco próprio de 0x1000 bytes.
        unsafe { core::slice::from_raw_parts(self.base.as_ptr() as *const u8, HBLOCK_SIZE as usize) }.to_vec()
    }

    /// Bytes dos dados de bins no intervalo (para o log e a descarga).
    pub fn read_bins(&self, offset: u32, length: u32) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(length as usize);
        let mut cursor = offset;
        while cursor < offset + length {
            let Some(index) = self.bin_index(cursor) else { break };
            let bin = &self.bins[index];
            let local = (cursor - bin.offset) as usize;
            let take = ((bin.offset + bin.size()).min(offset + length) - cursor) as usize;
            bytes.extend_from_slice(&bin.bytes()[local..local + take]);
            cursor += take as u32;
        }
        bytes
    }

    /// Faixas sujas (offset, tamanho) em bytes dos dados de bins, cada uma
    /// uma sequência de setores marcados (HvpGenerateLogMetadata).
    pub fn dirty_runs(&self) -> Vec<(u32, u32)> {
        let sectors = self.length() / HSECTOR_SIZE;
        let mut runs = Vec::new();
        let mut sector = 0;
        while sector < sectors {
            let set = |sector: u32| self.dirty.get((sector / 64) as usize).is_some_and(|word| word & (1u64 << (sector % 64)) != 0);
            if !set(sector) {
                sector += 1;
                continue;
            }
            let start = sector;
            while sector < sectors && set(sector) {
                sector += 1;
            }
            runs.push((start * HSECTOR_SIZE, (sector - start) * HSECTOR_SIZE));
        }
        runs
    }

    pub fn is_dirty(&self) -> bool {
        self.base_dirty || self.dirty.iter().any(|&word| word != 0)
    }

    /// Setores sujos (o DirtyCount).
    pub fn dirty_count(&self) -> u32 {
        self.dirty.iter().map(|word| word.count_ones()).sum()
    }

    /// HvResetDirtyData.
    pub fn clear_dirty(&mut self) {
        self.dirty.clear();
        self.base_dirty = false;
    }

    /// Volta a marcar faixas que não chegaram ao arquivo.
    pub fn restore_dirty(&mut self, runs: &[(u32, u32)]) {
        for &(offset, length) in runs {
            self.mark_range(offset, length);
        }
        self.base_dirty = true;
    }

    /// Bytes ocupados por células alocadas (o "uso" para NtCompressKey).
    pub fn free_bytes(&self) -> u32 {
        self.free.values().sum()
    }
}
