//! Driver de disco ATA (LBA28).
//!
//! Fala com o canal IDE primário pelas portas 0x1F0-0x1F7 e 0x3F6. Leituras
//! e escritas usam DMA de bus master (BMIDE do PIIX3) para um buffer físico
//! de 128 KiB, como o atapi: cada palavra PIO seria uma saída da VM. O
//! caminho PIO (READ/WRITE SECTORS multi-setor) fica disponível como
//! alternativa.
//!
//! O canal tem um único task file para o mestre e o escravo, uma tabela PRD
//! e um buffer de passagem: um comando por vez, da seleção do drive até a
//! cópia do buffer, sob o lock do canal (o papel da fila do canal no
//! ataport). As esperas têm prazo em tempo de relógio, como o TimeOutValue
//! dos pedidos do disk.sys, e não em número de leituras do status: quanto
//! dura uma leitura de porta depende do host, e no QEMU um FLUSH CACHE é o
//! flush do arquivo de imagem no host, que sob carga leva centenas de
//! milissegundos ou mais.

use alloc::vec::Vec;

use crate::hal::{cpu, port, volatile};
use crate::hal::pci_config;
use crate::ntos::ke::clock;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::paging;

const ATA_DATA: u16 = 0x1F0;
const ATA_SECTORS: u16 = 0x1F2;
const ATA_LBA_LO: u16 = 0x1F3;
const ATA_LBA_MID: u16 = 0x1F4;
const ATA_LBA_HI: u16 = 0x1F5;
const ATA_DRIVE: u16 = 0x1F6;
const ATA_STATUS: u16 = 0x1F7;
const ATA_CMD: u16 = 0x1F7;
/// Status alternativo: o mesmo valor sem reconhecer a interrupção.
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
/// Prazo de seleção e de comandos de dados (o TimeOutValue padrão do
/// disk.sys, 10 s).
const COMMAND_TIMEOUT_MS: u64 = 10_000;
/// FLUSH CACHE descarrega o cache inteiro do dispositivo; o ATA admite que
/// leve dezenas de segundos.
const FLUSH_TIMEOUT_MS: u64 = 30_000;

/// 8086:7010 (PIIX3) em 00:01.1 no QEMU pc.
const IDE_BUS: u32 = 0;
const IDE_DEVICE: u32 = 1;
const IDE_FUNCTION: u32 = 1;
const PCI_COMMAND_BUS_MASTER: u32 = 0x04;
const PCI_COMMAND_IO_SPACE: u32 = 0x01;
const READ_BOUNCE_SECTORS: u32 = 256;
/// BMIDE primário: +0 comando (bit 0 = início, bit 3 = dispositivo->memória),
/// +2 status (bit 1 = erro, bit 2 = interrupção; escrever 1 limpa), +4 PRD.
const BM_COMMAND: u16 = 0;
const BM_STATUS: u16 = 2;
const BM_PRD: u16 = 4;
const BM_START: u8 = 0x01;
const BM_TO_MEMORY: u8 = 0x08;
const BM_STATUS_ERROR: u8 = 0x02;
const BM_STATUS_INTERRUPT: u8 = 0x04;

/// Uma região da arena (VA na janela do heap) e o endereço físico que o
/// controlador recebe. A arena é fisicamente contígua.
#[derive(Clone, Copy)]
struct DmaBuffer {
    address: u64,
    physical: u64,
}

/// Estado do canal primário; só se mexe com o lock do canal.
struct Channel {
    /// BAR4 do controlador IDE (registradores de bus master); 0 = ainda não ligado.
    bmide_base: u16,
    prd_table: DmaBuffer,
    bounce: DmaBuffer,
    read_log_count: u32,
}

const NO_BUFFER: DmaBuffer = DmaBuffer { address: 0, physical: 0 };

static CHANNEL: SpinLock<Channel> = SpinLock::new(Channel { bmide_base: 0, prd_table: NO_BUFFER, bounce: NO_BUFFER, read_log_count: 0 });

/// Bloco da arena para DMA: a VA e a tradução real pelas tabelas de páginas.
fn dma_buffer(address: u64) -> DmaBuffer {
    DmaBuffer { address, physical: paging::translate(address) }
}

fn error(message: &str) -> KernelError {
    KernelError::new(message)
}

impl Channel {
    /// Liga I/O decode e bus master e lê o BAR4 na primeira transferência;
    /// a tabela PRD ocupa uma página alinhada (a BMIDE exige endereço físico
    /// alinhado).
    fn bus_master(&mut self) -> Result<(u16, DmaBuffer), KernelError> {
        if self.bmide_base == 0 {
            pci_config::enable_command(IDE_BUS, IDE_DEVICE, IDE_FUNCTION, PCI_COMMAND_BUS_MASTER | PCI_COMMAND_IO_SPACE)?;
            let base = (pci_config::read(IDE_BUS, IDE_DEVICE, IDE_FUNCTION, 0x20, 4)? & 0xFFFC) as u16;
            let table = guest::alloc_page();
            if table == 0 {
                return Err(error("ATA DMA: sem memoria para a tabela PRD"));
            }
            let table = dma_buffer(table);
            debug_print!("[atapio] BMIDE em {:#x} (bus master ligado; PRD em {:#x}, fisico {:#x})", base, table.address, table.physical);
            self.bmide_base = base;
            self.prd_table = table;
        }
        Ok((self.bmide_base, self.prd_table))
    }

    fn bounce(&mut self) -> Result<DmaBuffer, KernelError> {
        if self.bounce.address == 0 {
            let bounce = guest::alloc_bytes(READ_BOUNCE_SECTORS as u64 * 512);
            if bounce == 0 {
                return Err(error("ATA DMA: sem memoria para transferencia"));
            }
            self.bounce = dma_buffer(bounce);
        }
        Ok(self.bounce)
    }

    /// READ/WRITE DMA para memória física contígua: até 256 setores por
    /// comando, PRDs quebrados nas fronteiras de 64 KiB; sempre espera a
    /// conclusão do hardware.
    fn transfer_dma(&mut self, lba: u64, count: u32, drive: u8, destination: u64, write: bool) -> Result<(), KernelError> {
        validate_range(lba, count as u64, drive)?;
        if destination % 2 != 0 || destination + count as u64 * 512 > 0x1_0000_0000 {
            return Err(error("ATA DMA: destino invalido"));
        }
        let (bmide, table) = self.bus_master()?;
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
                let prd = table.address + entries * 8;
                guest::write32(prd, region as u32);
                guest::write16(prd + 4, (length & 0xFFFF) as u16);
                guest::write16(prd + 6, if remaining <= length { 0x8000 } else { 0 });
                entries += 1;
                region += length;
                remaining -= length;
            }
            select_drive(lba + done as u64, drive)?;
            port::write32(bmide + BM_PRD, table.physical as u32);
            let direction = if write { 0 } else { BM_TO_MEMORY };
            port::write8(bmide + BM_COMMAND, direction);
            port::write8(bmide + BM_STATUS, port::read8(bmide + BM_STATUS) | BM_STATUS_ERROR | BM_STATUS_INTERRUPT);
            task_file(lba + done as u64, chunk);
            port::write8(ATA_CMD, if write { ATA_CMD_WRITE_DMA } else { ATA_CMD_READ_DMA });
            port::write8(bmide + BM_COMMAND, direction | BM_START);
            settle();
            // Concluído = dispositivo fora de BSY e interrupção sinalizada no
            // status do bus master.
            let deadline = clock::uptime_ms() + COMMAND_TIMEOUT_MS;
            let outcome = loop {
                let expired = clock::uptime_ms() >= deadline;
                let bus_master = port::read8(bmide + BM_STATUS);
                let status = port::read8(ATA_ALT_STATUS);
                if status & SR_BSY == 0 && status & (SR_ERR | SR_DF) != 0 {
                    break Err(error(if write { "ATA DMA: erro de escrita" } else { "ATA DMA: erro de leitura" }));
                }
                if bus_master & BM_STATUS_ERROR != 0 {
                    break Err(error("ATA DMA: erro do bus master"));
                }
                if status & SR_BSY == 0 && bus_master & BM_STATUS_INTERRUPT != 0 {
                    break Ok(());
                }
                if expired {
                    break Err(error("ATA DMA: timeout"));
                }
                cpu::pause();
            };
            port::write8(bmide + BM_COMMAND, direction);
            port::read8(ATA_STATUS); // reconhece a interrupção do dispositivo
            port::write8(bmide + BM_STATUS, port::read8(bmide + BM_STATUS) | BM_STATUS_ERROR | BM_STATUS_INTERRUPT);
            outcome?;
            done += chunk;
        }
        Ok(())
    }
}

fn validate_range(lba: u64, count: u64, drive: u8) -> Result<(), KernelError> {
    if lba + count > 0x1000_0000 || drive > 1 {
        return Err(error("ATA: faixa LBA28 invalida"));
    }
    Ok(())
}

/// Os 400 ns que o dispositivo tem para publicar o status depois de uma
/// seleção ou de um comando: quatro leituras do status alternativo.
fn settle() {
    for _ in 0..4 {
        port::read8(ATA_ALT_STATUS);
    }
}

/// Espera o status alternativo satisfazer `done` até o prazo. O status é
/// relido depois de o prazo vencer, então uma CPU virtual que ficou sem
/// rodar não dá por perdido um comando que já concluiu.
fn wait_status(timeout_ms: u64, message: &str, mut done: impl FnMut(u8) -> Result<bool, KernelError>) -> Result<(), KernelError> {
    let deadline = clock::uptime_ms() + timeout_ms;
    loop {
        let expired = clock::uptime_ms() >= deadline;
        if done(port::read8(ATA_ALT_STATUS))? {
            return Ok(());
        }
        if expired {
            return Err(error(message));
        }
        cpu::pause();
    }
}

fn wait_ready() -> Result<(), KernelError> {
    wait_status(COMMAND_TIMEOUT_MS, "ATA: timeout BSY", |status| Ok(status & SR_BSY == 0))
}

fn wait_data() -> Result<(), KernelError> {
    wait_status(COMMAND_TIMEOUT_MS, "ATA: timeout DRQ", |status| {
        if status & SR_BSY != 0 {
            return Ok(false);
        }
        if status & (SR_ERR | SR_DF) != 0 {
            return Err(error("ATA: erro de transferencia"));
        }
        Ok(status & SR_DRQ != 0)
    })
}

/// Fim de um comando sem dados pendentes; reconhece a interrupção.
fn wait_complete(timeout_ms: u64) -> Result<(), KernelError> {
    let outcome = wait_status(timeout_ms, "ATA: timeout de conclusao", |status| {
        if status & SR_BSY != 0 {
            return Ok(false);
        }
        if status & (SR_ERR | SR_DF) != 0 {
            return Err(error("ATA: comando falhou"));
        }
        Ok(status & SR_DRQ == 0)
    });
    port::read8(ATA_STATUS);
    outcome
}

/// Seleciona o drive e espera o atraso de seleção do ATA.
fn select_drive(lba: u64, drive: u8) -> Result<(), KernelError> {
    wait_ready()?;
    port::write8(ATA_DRIVE, 0xE0 | drive << 4 | ((lba >> 24) & 15) as u8);
    settle();
    wait_ready()
}

fn task_file(lba: u64, count: u32) {
    port::write8(ATA_SECTORS, (count & 0xFF) as u8); // 0 = 256
    port::write8(ATA_LBA_LO, lba as u8);
    port::write8(ATA_LBA_MID, (lba >> 8) as u8);
    port::write8(ATA_LBA_HI, (lba >> 16) as u8);
}

/// READ DMA real para memória física (endereço físico do destino).
pub fn read_sectors_dma_to_physical(lba: u64, count: u32, drive: u8, destination: u64) -> Result<(), KernelError> {
    CHANNEL.lock().transfer_dma(lba, count, drive, destination, false)
}

/// Lê `count` setores a partir do LBA (drive 0 = mestre, 1 = escravo). Só
/// publica bytes depois da conclusão real do DMA.
pub fn read_sectors(lba: u64, count: u32, drive: u8) -> Result<Vec<u8>, KernelError> {
    validate_range(lba, count as u64, drive)?;
    let log = {
        let mut channel = CHANNEL.lock();
        channel.read_log_count += 1;
        channel.read_log_count <= 3 || (14..=17).contains(&lba)
    };
    if log {
        debug_print!("[atapio] readSectors lba={} count={} drive={}", lba, count, drive);
    }
    let mut out = Vec::with_capacity(count as usize * 512);
    let mut done = 0;
    while done < count {
        let chunk = READ_BOUNCE_SECTORS.min(count - done);
        // O buffer de passagem é do canal: o DMA e a cópia sob o mesmo lock.
        let mut channel = CHANNEL.lock();
        let bounce = channel.bounce()?;
        channel.transfer_dma(lba + done as u64, chunk, drive, bounce.physical, false)?;
        out.extend_from_slice(&volatile::read_bytes(bounce.address, chunk as usize * 512));
        drop(channel);
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
        let _channel = CHANNEL.lock();
        select_drive(sector, drive)?;
        task_file(sector, chunk);
        port::write8(ATA_CMD, ATA_CMD_READ);
        settle();
        for index in 0..chunk {
            wait_data()?;
            let offset = (done + index) as usize * 512;
            for word in 0..256 {
                let value = port::read16(ATA_DATA);
                out[offset + word * 2] = value as u8;
                out[offset + word * 2 + 1] = (value >> 8) as u8;
            }
        }
        port::read8(ATA_STATUS);
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
    let mut done = 0;
    while done < count {
        let chunk = READ_BOUNCE_SECTORS.min(count - done);
        let mut channel = CHANNEL.lock();
        let bounce = channel.bounce()?;
        volatile::write_bytes(bounce.address, &bytes[done as usize * 512..(done + chunk) as usize * 512]);
        channel.transfer_dma(lba + done as u64, chunk, drive, bounce.physical, true)?;
        drop(channel);
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
        let _channel = CHANNEL.lock();
        select_drive(sector, drive)?;
        task_file(sector, chunk);
        port::write8(ATA_CMD, ATA_CMD_WRITE);
        settle();
        for index in 0..chunk {
            wait_data()?;
            let base = (done + index) as usize * 512;
            for word in (0..512).step_by(2) {
                port::write16(ATA_DATA, bytes[base + word] as u16 | (bytes[base + word + 1] as u16) << 8);
            }
        }
        wait_complete(COMMAND_TIMEOUT_MS)?;
        done += chunk;
    }
    Ok(())
}

/// FLUSH CACHE.
pub fn flush(drive: u8) -> Result<(), KernelError> {
    validate_range(0, 0, drive)?;
    let _channel = CHANNEL.lock();
    select_drive(0, drive)?;
    port::write8(ATA_CMD, ATA_CMD_FLUSH);
    settle();
    wait_complete(FLUSH_TIMEOUT_MS)
}

/// Detecta se um drive responde: status flutuante (0xFF) ou zero é
/// ausência; um drive presente sai de BSY dentro do prazo de seleção.
pub fn present(drive: u8) -> Result<bool, KernelError> {
    let _channel = CHANNEL.lock();
    port::write8(ATA_DRIVE, 0xE0 | (drive & 1) << 4);
    settle();
    let status = port::read8(ATA_ALT_STATUS);
    if status == 0xFF || status == 0x00 {
        return Ok(false);
    }
    wait_ready()?;
    let status = port::read8(ATA_ALT_STATUS);
    Ok(status != 0xFF && status != 0x00)
}
