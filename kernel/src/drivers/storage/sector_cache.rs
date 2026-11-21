//! Cache dos setores de metadados dos discos ATA.
//!
//! O NTFS do Windows lê o MFT e os índices dos diretórios pelo Cache
//! Manager: um registro de arquivo ou um bloco INDX lido uma vez fica na
//! memória e as próximas consultas não vão ao disco. O NTFS interno lia cada
//! registro e cada bloco do disco a cada consulta (um `stat`, um passo de
//! caminho, uma enumeração de diretório), e cada leitura é um comando de DMA
//! com dezenas de saídas da máquina virtual. Aqui ficam as leituras de
//! metadados (`read`), em unidades alinhadas de 4 KB (8 setores, um bloco
//! INDX ou um registro de arquivo), em frames do PFN (fora do heap do
//! kernel), com despejo da menos usada.
//!
//! Limite e pressão: no máximo 1/64 da RAM e [`MAX_UNITS`] unidades (16
//! MB). O cache é o primeiro provedor de residência (`mm::page_residency`,
//! registrado na fase 0 antes dos outros): quando o PFN fica sem frames, as
//! unidades menos usadas voltam ao PFN antes de qualquer página ir para o
//! arquivo de paginação, como a lista standby do NT antes das páginas
//! modificadas. Nenhum frame é pedido ao PFN com a trava do cache tomada (o
//! pedido pode chamar a recuperação, que toma a trava).
//!
//! Coerência: toda escrita do OpenNT no disco passa por
//! `ata_pio::write_sectors` (ou a versão PIO), que chama [`invalidate`] antes
//! e depois do comando: o NTFS interno (o commit das transações e as
//! escritas de paginação, inclusive o arquivo de paginação), o volume bruto
//! (`ata_volume`) e os autotestes. A unidade que cobre um setor escrito sai
//! do cache, e uma leitura que começou antes da escrita e terminou depois
//! dela não entra (o contador de escritas mudou). As escritas pendentes de
//! uma transação do NTFS ainda não estão no disco: o volume as sobrepõe por
//! cima do que vem daqui, como sobrepunha por cima da leitura direta. A
//! pilha de armazenamento real (`--storage=real`) programa o DMA da
//! controladora IDE pelo atapi.sys, sem passar pelo `ata_pio`: quando ela
//! assume a controladora o cache se esvazia e deixa de guardar ([`disable`]).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use super::ata_pio;
use crate::ntos::mm::page_residency::{self, FaultResult, Provider};
use crate::ntos::mm::{memory_map, pfn};
use crate::rtl::{KernelError, SpinLock};

/// Setores por unidade (4 KB).
const UNIT_SECTORS: u64 = 8;
const UNIT_BYTES: usize = 4096;
/// Unidades guardadas no máximo (16 MB de frames).
const MAX_UNITS: usize = 4096;
/// Fração da RAM que o cache pode ocupar (1/64).
const RAM_SHARE: u64 = 64;

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
/// A pilha real assumiu a controladora: nada mais é guardado.
static DISABLED: AtomicBool = AtomicBool::new(false);

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

    /// Tira a unidade e devolve o frame dela (a quem chama, que o devolve
    /// ao PFN fora da trava).
    fn remove(&mut self, key: (u8, u64)) -> Option<u64> {
        let unit = self.units.remove(&key)?;
        self.order.remove(&unit.stamp);
        Some(unit.frame)
    }

    /// Tira a unidade menos usada.
    fn evict_oldest(&mut self) -> Option<u64> {
        let (_, oldest) = self.order.pop_first()?;
        self.units.remove(&oldest).map(|unit| unit.frame)
    }
}

/// As unidades que cabem: 1/64 da RAM, até [`MAX_UNITS`].
fn capacity() -> usize {
    ((pfn::total_count() / RAM_SHARE) as usize).min(MAX_UNITS)
}

fn release(frames: Vec<u64>) {
    for frame in frames {
        pfn::free_page(frame);
    }
}

/// Registra o cache como o primeiro provedor de residência (fase 0, antes
/// das imagens de driver e do pool): na pressão do PFN ele devolve frames
/// antes de qualquer página ir para o disco.
pub fn initialize() -> Result<(), KernelError> {
    page_residency::register("disk metadata cache", Provider { fault: |_, _| FaultResult::NotMine, resolve: |_| Ok(None), reclaim, prepare: || Ok(()), resolve_range: Some((0, 0)) })
}

/// A recuperação do PFN: até `count` unidades, as menos usadas.
fn reclaim(count: u64) -> Result<u64, KernelError> {
    let frames: Vec<u64> = {
        let mut cache = CACHE.lock();
        (0..count).map_while(|_| cache.evict_oldest()).collect()
    };
    let freed = frames.len() as u64;
    release(frames);
    Ok(freed)
}

/// Guarda os 4 KB lidos da unidade, se nenhuma escrita cruzou a leitura.
fn insert(key: (u8, u64), bytes: &[u8], writes: u64) {
    let frame = pfn::alloc_page();
    if frame == 0 {
        return;
    }
    // SAFETY: o frame acabou de sair do PFN para o cache e o mapa direto
    // cobre toda a RAM.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), memory_map::direct_map(frame) as *mut u8, UNIT_BYTES) };
    let limit = capacity();
    let mut unused = Vec::new();
    {
        let mut cache = CACHE.lock();
        if cache.writes != writes || cache.units.contains_key(&key) || DISABLED.load(Ordering::Acquire) || limit == 0 {
            unused.push(frame);
        } else {
            while cache.units.len() >= limit {
                match cache.evict_oldest() {
                    Some(old) => unused.push(old),
                    None => break,
                }
            }
            cache.clock += 1;
            let stamp = cache.clock;
            cache.order.insert(stamp, key);
            cache.units.insert(key, Unit { frame, stamp });
        }
    }
    release(unused);
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
    insert(key, &bytes, writes);
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
    if DISABLED.load(Ordering::Acquire) || (last + 1) * UNIT_SECTORS > limit || count > 64 * UNIT_SECTORS {
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
    let frames: Vec<u64> = {
        let mut cache = CACHE.lock();
        cache.writes += 1;
        if count == 0 || cache.units.is_empty() {
            return;
        }
        let (first, last) = (lba / UNIT_SECTORS, (lba + count - 1) / UNIT_SECTORS);
        let keys: Vec<(u8, u64)> = cache.units.range((drive, first)..=(drive, last)).map(|(key, _)| *key).collect();
        keys.into_iter().filter_map(|key| cache.remove(key)).collect()
    };
    release(frames);
}

/// A pilha de armazenamento real vai assumir a controladora IDE: as escritas
/// dela não passam pelo `ata_pio`, então o cache se esvazia e não guarda
/// mais nada (as leituras seguintes vão direto ao disco).
pub fn disable() {
    DISABLED.store(true, Ordering::Release);
    let frames: Vec<u64> = {
        let mut cache = CACHE.lock();
        cache.writes += 1;
        cache.order.clear();
        core::mem::take(&mut cache.units).into_values().map(|unit| unit.frame).collect()
    };
    release(frames);
}
