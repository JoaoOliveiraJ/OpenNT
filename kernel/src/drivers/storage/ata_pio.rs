//! Driver de disco ATA (LBA28) — `system32/drivers/storage/ata-pio.js`.
//!
//! Fala com o controlador IDE primário pelas portas 0x1F0-0x1F7. Leituras e
//! escritas usam DMA de bus master (BMIDE do PIIX3) para um buffer físico de
//! 128 KiB, como o atapi: cada palavra PIO seria uma saída da VM. O caminho
//! PIO (READ/WRITE SECTORS multi-setor) fica disponível como alternativa.

use alloc::vec::Vec;

use crate::hal::{physical, port};
use crate::hal::pci_config;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const ATA_DATA: u16 = 0x1F0;
const ATA_SECTORS: u16 = 0x1F2;
const ATA_LBA_LO: u16 = 0x1F3;
const ATA_LBA_MID: u16 = 0x1F4;
const ATA_LBA_HI: u16 = 0x1F5;
const ATA_DRIVE: u16 = 0x1F6;
const ATA_STATUS: u16 = 0x1F7;
const ATA_CMD: u16 = 0x1F7;
const ATA_ALT_STATUS: u16 = 0x3F6;
const ATA_CMD_READ: u8 = 0x20;
const ATA_CMD_WRITE: u8 = 0x30;
const ATA_CMD_READ_DMA: u8 = 0xC8;
const ATA_CMD_WRITE_DMA: u8 = 0xCA;
const ATA_CMD_FLUSH: u8 = 0xE7;
const SR_BSY: u8 = 0x80;
const SR_DRQ: u8 = 0x08;
const SR_ERR: u8 = 0x01;
const SR_DF: u8 = 0x20;
const POLLS: u32 = 1_000_000;

/// 8086:7010 (PIIX3) em 00:01.1 no QEMU pc.
const IDE_BUS: u32 = 0;
const IDE_DEVICE: u32 = 1;
const IDE_FUNCTION: u32 = 1;
const PCI_COMMAND_BUS_MASTER: u32 = 0x04;
const PCI_COMMAND_IO_SPACE: u32 = 0x01;
const READ_BOUNCE_SECTORS: u32 = 256;

struct State {
    /// BAR4 do controlador IDE (registradores de bus master); 0 = ainda não ligado.
    bmide_base: u16,
    prd_table: u64,
    bounce: u64,
    read_log_count: u32,
}

static STATE: SpinLock<State> = SpinLock::new(State { bmide_base: 0, prd_table: 0, bounce: 0, read_log_count: 0 });

fn error(message: &str) -> KernelError {
    KernelError::new(message)
}

/// Liga I/O decode e bus master e lê o BAR4; a tabela PRD ocupa uma página
/// alinhada (a BMIDE exige endereço físico alinhado).
fn ensure_bus_master() -> Result<(u16, u64), KernelError> {
    {
        let state = STATE.lock();
        if state.bmide_base != 0 {
            return Ok((state.bmide_base, state.prd_table));
        }
    }
    pci_config::enable_command(IDE_BUS, IDE_DEVICE, IDE_FUNCTION, PCI_COMMAND_BUS_MASTER | PCI_COMMAND_IO_SPACE)?;
    let base = (pci_config::read(IDE_BUS, IDE_DEVICE, IDE_FUNCTION, 0x20, 4)? & 0xFFFC) as u16;
    let table = guest::alloc_page();
    debug_print!("[atapio] BMIDE em {:#x} (bus master ligado; PRD em {:#x})", base, table);
    let mut state = STATE.lock();
    state.bmide_base = base;
    state.prd_table = table;
    Ok((base, table))
}

fn ensure_bounce_buffer() -> Result<u64, KernelError> {
    let mut state = STATE.lock();
    if state.bounce == 0 {
        state.bounce = guest::alloc_bytes(READ_BOUNCE_SECTORS as u64 * 512);
        if state.bounce == 0 {
            return Err(error("ATA DMA: sem memoria para transferencia"));
        }
    }
    Ok(state.bounce)
}

fn validate_range(lba: u64, count: u64, drive: u8) -> Result<(), KernelError> {
    if lba + count > 0x1000_0000 || drive > 1 {
        return Err(error("ATA: faixa LBA28 invalida"));
    }
    Ok(())
}

fn wait_ready() -> Result<(), KernelError> {
    for _ in 0..POLLS {
        if port::read8(ATA_STATUS) & SR_BSY == 0 {
            return Ok(());
        }
    }
    Err(error("ATA: timeout BSY"))
}

fn wait_data() -> Result<(), KernelError> {
    for _ in 0..POLLS {
        let status = port::read8(ATA_STATUS);
        if status & SR_BSY != 0 {
            continue;
        }
        if status & (SR_ERR | SR_DF) != 0 {
            return Err(error("ATA: erro de transferencia"));
        }
        if status & SR_DRQ != 0 {
            return Ok(());
        }
    }
    Err(error("ATA: timeout DRQ"))
}

fn wait_complete() -> Result<(), KernelError> {
    for _ in 0..POLLS {
        let status = port::read8(ATA_STATUS);
        if status & SR_BSY != 0 {
            continue;
        }
        if status & (SR_ERR | SR_DF) != 0 {
            return Err(error("ATA: comando falhou"));
        }
        if status & SR_DRQ == 0 {
            return Ok(());
        }
    }
    Err(error("ATA: timeout de conclusao"))
}

/// Seleciona o drive; quatro leituras do status alternativo dão o atraso
/// de seleção do ATA.
fn select_drive(lba: u64, drive: u8) -> Result<(), KernelError> {
    wait_ready()?;
    port::write8(ATA_DRIVE, 0xE0 | drive << 4 | ((lba >> 24) & 15) as u8);
    for _ in 0..4 {
        port::read8(ATA_ALT_STATUS);
    }
    wait_ready()
}

fn task_file(lba: u64, count: u32) {
    port::write8(ATA_SECTORS, (count & 0xFF) as u8); // 0 = 256
    port::write8(ATA_LBA_LO, lba as u8);
    port::write8(ATA_LBA_MID, (lba >> 8) as u8);
    port::write8(ATA_LBA_HI, (lba >> 16) as u8);
}

/// READ/WRITE DMA para memória física contígua: até 256 setores por
/// comando, PRDs quebrados nas fronteiras de 64 KiB; sempre espera a
/// conclusão do hardware.
fn transfer_sectors_dma(lba: u64, count: u32, drive: u8, destination: u64, write: bool) -> Result<(), KernelError> {
    validate_range(lba, count as u64, drive)?;
    if destination % 2 != 0 || destination + count as u64 * 512 > 0x1_0000_0000 {
        return Err(error("ATA DMA: destino invalido"));
    }
    let (bmide, table) = ensure_bus_master()?;
    let mut done = 0u32;
    while done < count {
        let chunk = (count - done).min(256);
        let target = destination + done as u64 * 512;
        // Tabela PRD (Physical Region Descriptors).
        let mut entries = 0u64;
        let mut region = target;
        let mut remaining = chunk as u64 * 512;
        while remaining > 0 {
            let length = remaining.min(0x10000 - (region & 0xFFFF));
            let prd = table + entries * 8;
            physical::write32(prd, region as u32);
            physical::write16(prd + 4, (length & 0xFFFF) as u16);
            physical::write16(prd + 6, if remaining <= length { 0x8000 } else { 0 });
            entries += 1;
            region += length;
            remaining -= length;
        }
        select_drive(lba + done as u64, drive)?;
        // BMIDE primário: +0 comando (bit 3 = dispositivo->memória), +2 status, +4 PRD.
        port::write32(bmide + 4, table as u32);
        let direction = if write { 0 } else { 0x08 };
        port::write8(bmide, direction);
        port::write8(bmide + 2, port::read8(bmide + 2) | 0x06);
        task_file(lba + done as u64, chunk);
        port::write8(ATA_CMD, if write { ATA_CMD_WRITE_DMA } else { ATA_CMD_READ_DMA });
        port::write8(bmide, direction | 0x01); // inicia o bus master
        let mut outcome = Err(error("ATA DMA: timeout"));
        for _ in 0..POLLS {
            let ata_status = port::read8(ATA_STATUS);
            let bmide_status = port::read8(bmide + 2);
            if ata_status & SR_BSY == 0 && ata_status & (SR_ERR | SR_DF) != 0 {
                outcome = Err(error(if write { "ATA DMA: erro de escrita" } else { "ATA DMA: erro de leitura" }));
                break;
            }
            if bmide_status & 0x02 != 0 {
                outcome = Err(error("ATA DMA: erro do bus master"));
                break;
            }
            if ata_status & SR_BSY == 0 && bmide_status & 0x04 != 0 {
                outcome = Ok(());
                break;
            }
        }
        port::write8(bmide, direction);
        port::write8(bmide + 2, port::read8(bmide + 2) | 0x06);
        outcome?;
        done += chunk;
    }
    Ok(())
}

/// READ DMA real para memória física (identidade).
pub fn read_sectors_dma_to_physical(lba: u64, count: u32, drive: u8, destination: u64) -> Result<(), KernelError> {
    transfer_sectors_dma(lba, count, drive, destination, false)
}

/// Lê `count` setores a partir do LBA (drive 0 = mestre, 1 = escravo). Só
/// publica bytes depois da conclusão real do DMA.
pub fn read_sectors(lba: u64, count: u32, drive: u8) -> Result<Vec<u8>, KernelError> {
    validate_range(lba, count as u64, drive)?;
    let log = {
        let mut state = STATE.lock();
        state.read_log_count += 1;
        state.read_log_count <= 3 || (14..=17).contains(&lba)
    };
    if log {
        debug_print!("[atapio] readSectors lba={} count={} drive={}", lba, count, drive);
    }
    let mut out = Vec::with_capacity(count as usize * 512);
    if count == 0 {
        return Ok(out);
    }
    let bounce = ensure_bounce_buffer()?;
    let mut done = 0;
    while done < count {
        let chunk = READ_BOUNCE_SECTORS.min(count - done);
        read_sectors_dma_to_physical(lba + done as u64, chunk, drive, bounce)?;
        out.extend_from_slice(&physical::read_bytes(bounce, chunk as usize * 512));
        done += chunk;
    }
    Ok(out)
}

/// READ SECTORS (0x20) multi-setor por PIO: um comando cobre até 256
/// setores, com uma espera DRQ e 256 palavras por setor.
pub fn read_sectors_pio(lba: u64, count: u32, drive: u8) -> Result<Vec<u8>, KernelError> {
    validate_range(lba, count as u64, drive)?;
    let mut out = alloc::vec![0u8; count as usize * 512];
    let mut done = 0;
    while done < count {
        let chunk = (count - done).min(256);
        let sector = lba + done as u64;
        wait_ready()?;
        task_file(sector, chunk);
        port::write8(ATA_DRIVE, 0xE0 | (drive & 1) << 4 | ((sector >> 24) & 0x0F) as u8);
        port::write8(ATA_CMD, ATA_CMD_READ);
        for index in 0..chunk {
            wait_data()?;
            let offset = (done + index) as usize * 512;
            for word in 0..256 {
                let value = port::read16(ATA_DATA);
                out[offset + word * 2] = value as u8;
                out[offset + word * 2 + 1] = (value >> 8) as u8;
            }
        }
        done += chunk;
    }
    Ok(out)
}

/// Grava setores completos por DMA a partir do buffer físico de passagem.
pub fn write_sectors(lba: u64, bytes: &[u8], drive: u8) -> Result<(), KernelError> {
    if bytes.len() % 512 != 0 {
        return Err(error("ATA: escrita exige setores completos"));
    }
    let count = (bytes.len() / 512) as u32;
    validate_range(lba, count as u64, drive)?;
    if count == 0 {
        return Ok(());
    }
    let bounce = ensure_bounce_buffer()?;
    let mut done = 0;
    while done < count {
        let chunk = READ_BOUNCE_SECTORS.min(count - done);
        physical::write_bytes(bounce, &bytes[done as usize * 512..(done + chunk) as usize * 512]);
        transfer_sectors_dma(lba + done as u64, chunk, drive, bounce, true)?;
        done += chunk;
    }
    Ok(())
}

/// WRITE SECTORS (0x30) por PIO.
pub fn write_sectors_pio(lba: u64, bytes: &[u8], drive: u8) -> Result<(), KernelError> {
    if bytes.len() % 512 != 0 {
        return Err(error("ATA: escrita exige setores completos"));
    }
    let count = (bytes.len() / 512) as u32;
    validate_range(lba, count as u64, drive)?;
    let mut done = 0;
    while done < count {
        let chunk = (count - done).min(256);
        let sector = lba + done as u64;
        select_drive(sector, drive)?;
        task_file(sector, chunk);
        port::write8(ATA_CMD, ATA_CMD_WRITE);
        for index in 0..chunk {
            wait_data()?;
            let base = (done + index) as usize * 512;
            for word in (0..512).step_by(2) {
                port::write16(ATA_DATA, bytes[base + word] as u16 | (bytes[base + word + 1] as u16) << 8);
            }
        }
        wait_complete()?;
        done += chunk;
    }
    Ok(())
}

/// FLUSH CACHE.
pub fn flush(drive: u8) -> Result<(), KernelError> {
    validate_range(0, 0, drive)?;
    select_drive(0, drive)?;
    port::write8(ATA_CMD, ATA_CMD_FLUSH);
    wait_complete()
}

/// Detecta se um drive responde (status não flutuante).
pub fn present(drive: u8) -> Result<bool, KernelError> {
    port::write8(ATA_DRIVE, 0xE0 | (drive & 1) << 4);
    wait_ready()?;
    let status = port::read8(ATA_STATUS);
    Ok(status != 0xFF && status != 0x00)
}
