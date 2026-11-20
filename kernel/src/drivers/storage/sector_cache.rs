//! Cache dos setores de metadados dos discos ATA.
//!
//! O NTFS do Windows lê o MFT e os índices dos diretórios pelo Cache
//! Manager: um registro de arquivo ou um bloco INDX lido uma vez fica na
//! memória e as próximas consultas não vão ao disco. O NTFS interno lia cada
//! registro e cada bloco do disco a cada consulta (um `stat`, um passo de
//! caminho, uma enumeração de diretório), e cada leitura é um comando de DMA
//! com dezenas de saídas da máquina virtual. Aqui ficam as leituras de
//! metadados (`read`), em unidades alinhadas de 4 KB (8 setores, um bloco
//! INDX ou quatro registros de 1 KB), em frames do PFN (fora do heap do
//! kernel), até [`MAX_UNITS`] unidades com despejo da menos usada.
//!
//! Coerência: toda escrita no disco passa por `ata_pio::write_sectors` (ou a
//! versão PIO), que chama [`invalidate`] antes e depois do comando. A
//! unidade que cobre um setor escrito sai do cache, e uma leitura que
//! começou antes da escrita e terminou depois dela não entra (o contador de
//! escritas mudou). As escritas pendentes de uma transação do NTFS ainda não
//! estão no disco: o volume as sobrepõe por cima do que vem daqui, como
//! sobrepunha por cima da leitura direta.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::ata_pio;
use crate::ntos::mm::{memory_map, pfn};
use crate::rtl::{KernelError, SpinLock};

/// Setores por unidade (4 KB).
const UNIT_SECTORS: u64 = 8;
const UNIT_BYTES: usize = 4096;
/// Unidades guardadas no máximo (16 MB de frames).
const MAX_UNITS: usize = 4096;

struct Unit {
    frame: u64,
    stamp: u64,
}

struct Cache {
    /// (drive, número da unidade) -> frame.
    units: BTreeMap<(u8, u64), Unit>,
    /// Ordem de uso: carimbo -> unidade.
    order: BTreeMap<u64, (u8, u64)>,
    clock: u64,
    /// Escritas começadas ou terminadas: uma leitura que viu o contador
    /// mudar não guarda o que leu.
    writes: u64,
}

static CACHE: SpinLock<Cache> = SpinLock::new(Cache { units: BTreeMap::new(), order: BTreeMap::new(), clock: 0, writes: 0 });

impl Cache {
    fn touch(&mut self, key: (u8, u64)) -> Option<u64> {
        let stamp = self.clock + 1;
        let unit = self.units.get_mut(&key)?;
        self.order.remove(&unit.stamp);
        unit.stamp = stamp;
        self.clock = stamp;
        self.order.insert(stamp, key);
        Some(unit.frame)
    }

    fn remove(&mut self, key: (u8, u64)) {
        if let Some(unit) = self.units.remove(&key) {
            self.order.remove(&unit.stamp);
            pfn::free_page(unit.frame);
        }
    }

    fn insert(&mut self, key: (u8, u64), bytes: &[u8]) {
        if self.units.contains_key(&key) {
            return;
        }
        while self.units.len() >= MAX_UNITS {
            let Some((_, oldest)) = self.order.pop_first() else { break };
            if let Some(unit) = self.units.remove(&oldest) {
                pfn::free_page(unit.frame);
            }
        }
        let frame = pfn::alloc_page();
        if frame == 0 {
            return;
        }
        // SAFETY: o frame acabou de sair do PFN para o cache e o mapa direto
        // cobre toda a RAM.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), memory_map::direct_map(frame) as *mut u8, UNIT_BYTES) };
        self.clock += 1;
        self.order.insert(self.clock, key);
        self.units.insert(key, Unit { frame, stamp: self.clock });
    }
}

/// Os 4 KB da unidade `unit` do drive: do cache, ou do disco (e guardados).
fn unit_bytes(drive: u8, unit: u64, out: &mut Vec<u8>) -> Result<(), KernelError> {
    let key = (drive, unit);
    let writes = {
        let mut cache = CACHE.lock();
        if let Some(frame) = cache.touch(key) {
            // SAFETY: o frame é do cache enquanto a unidade estiver nele, e a
            // trava está tomada.
            out.extend_from_slice(unsafe { core::slice::from_raw_parts(memory_map::direct_map(frame) as *const u8, UNIT_BYTES) });
            return Ok(());
        }
        cache.writes
    };
    let bytes = ata_pio::read_sectors(unit * UNIT_SECTORS, UNIT_SECTORS as u32, drive)?;
    let mut cache = CACHE.lock();
    if cache.writes == writes {
        cache.insert(key, &bytes);
    }
    drop(cache);
    out.extend_from_slice(&bytes);
    Ok(())
}

/// Lê `count` setores de metadados a partir de `lba` pelo cache. `limit` é
/// o fim do que pode ser lido (o tamanho do volume em setores): uma unidade
/// que passaria dele é lida direto, só com os setores pedidos.
pub fn read(lba: u64, count: u64, drive: u8, limit: u64) -> Result<Vec<u8>, KernelError> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let (first, last) = (lba / UNIT_SECTORS, (lba + count - 1) / UNIT_SECTORS);
    if (last + 1) * UNIT_SECTORS > limit || count > 64 * UNIT_SECTORS {
        return ata_pio::read_sectors(lba, count as u32, drive);
    }
    let mut units = Vec::with_capacity(((last - first + 1) as usize) * UNIT_BYTES);
    for unit in first..=last {
        unit_bytes(drive, unit, &mut units)?;
    }
    let start = ((lba - first * UNIT_SECTORS) * 512) as usize;
    Ok(units[start..start + count as usize * 512].to_vec())
}

/// Uma escrita de `count` setores a partir de `lba` vai começar ou acabou:
/// as unidades que ela cobre saem do cache (chamado por `ata_pio` antes e
/// depois de cada escrita).
pub fn invalidate(lba: u64, count: u64, drive: u8) {
    let mut cache = CACHE.lock();
    cache.writes += 1;
    if count == 0 || cache.units.is_empty() {
        return;
    }
    let (first, last) = (lba / UNIT_SECTORS, (lba + count - 1) / UNIT_SECTORS);
    let keys: Vec<(u8, u64)> = cache.units.range((drive, first)..=(drive, last)).map(|(key, _)| *key).collect();
    for key in keys {
        cache.remove(key);
    }
}
