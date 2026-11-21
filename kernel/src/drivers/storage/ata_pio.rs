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
//!
//! Falhas seguem a pilha de disco do 19041 num disco IDE (disk.sys e
//! classpnp.sys sobre atapi.sys e ataport.sys). Cada comando tem o prazo do
//! TimeOutValue do disco, e o FLUSH CACHE quatro vezes ele. Um comando que
//! vence o prazo leva o canal ao reset (SRST), como o ataport faz com um
//! pedido vencido; um comando que o dispositivo termina com erro volta sem
//! reset. Nos dois casos o pedido é mandado de novo até MaxNumberOfIoRetries
//! vezes antes de falhar. Cada tentativa que falha sai numa linha `[ata]`
//! na serial, com o comando, o drive, o LBA, os setores, o status, o
//! registrador de erro, o status do bus master e o tempo gasto.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::hal::{cpu, port};
use crate::hal::pci_config;
use crate::ntos::ke::clock;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::paging;

const ATA_DATA: u16 = 0x1F0;
/// Registrador de erro (leitura): o motivo de um comando terminado com ERR.
const ATA_ERROR: u16 = 0x1F1;
const ATA_SECTORS: u16 = 0x1F2;
const ATA_LBA_LO: u16 = 0x1F3;
const ATA_LBA_MID: u16 = 0x1F4;
const ATA_LBA_HI: u16 = 0x1F5;
const ATA_DRIVE: u16 = 0x1F6;
const ATA_STATUS: u16 = 0x1F7;
const ATA_CMD: u16 = 0x1F7;
/// Status alternativo: o mesmo valor sem reconhecer a interrupção.
const ATA_ALT_STATUS: u16 = 0x3F6;
/// Controle do dispositivo (escrita no endereço do status alternativo):
/// bit 2 = SRST (reset dos dois drives do canal), bit 1 = nIEN.
const ATA_DEVICE_CONTROL: u16 = 0x3F6;
const DEVICE_CONTROL_SRST: u8 = 0x04;
const DEVICE_CONTROL_NIEN: u8 = 0x02;
/// Seleção do mestre que o atapi grava antes do SRST.
const SELECT_MASTER: u8 = 0xA0;
const ATA_CMD_READ: u8 = 0x20;
const ATA_CMD_WRITE: u8 = 0x30;
const ATA_CMD_READ_DMA: u8 = 0xC8;
const ATA_CMD_WRITE_DMA: u8 = 0xCA;
const ATA_CMD_FLUSH: u8 = 0xE7;
const ATA_CMD_IDENTIFY: u8 = 0xEC;
const SR_BSY: u8 = 0x80;
const SR_DRQ: u8 = 0x08;
const SR_ERR: u8 = 0x01;
const SR_DF: u8 = 0x20;

/// O TimeOutValue de um disco no disk.sys do 19041 (DiskInitFdo, rva
/// 0xd7b0): o IoTimeoutValue do STORAGE_MINIPORT_DESCRIPTOR quando o driver
/// de porta informa um, senão o TimeOutValue da chave do serviço disk
/// (ClassQueryTimeOutRegistryValue do classpnp, rva 0x51a00), senão 0xA
/// segundos. O ataport não lê IoTimeoutValue (só o storport tem esse valor),
/// então num disco IDE valem o Registro e os 10 s.
const DEFAULT_TIMEOUT_SECONDS: u32 = 10;
/// O SYNCHRONIZE CACHE do DiskFlushDispatch (disk.sys, rva 0x1340) leva o
/// TimeOutValue deslocado 2 bits: quatro vezes o prazo dos outros pedidos.
const FLUSH_TIMEOUT_SHIFT: u32 = 2;
/// Novas tentativas de um pedido: o MaxNumberOfIoRetries do classpnp do
/// 19041 (a global em rva 0x470b0 começa em 4, o MAXIMUM_RETRIES), que o
/// ClassSetMaxNumberOfIoRetries (rva 0x126b4, chamado pelo ClassInitialize)
/// troca pelo valor MaxNumberOfIoRetries de Control\Classpnp quando ele não
/// é zero, limitado a 0xFF. O ClassPnpStartDevice (rva 0x4feb0) copia a
/// global para o dispositivo e o SetupReadWriteTransferPacket (rva 0x76f0)
/// para cada pedido; o ClassSendSrbSynchronous (rva 0x1570), por onde o
/// disk.sys manda o SYNCHRONIZE CACHE, também conta 4 novas tentativas.
const DEFAULT_RETRIES: u32 = 4;
const RETRIES_LIMIT: u32 = 0xFF;
/// O reset do canal do atapi.sys (AtapiIssueSoftReset, rva 0x3500): o SRST
/// fica ligado 10 µs e o driver espera 2 ms depois de soltá-lo.
const RESET_ASSERT_US: u32 = 10;
const RESET_RELEASE_US: u32 = 2_000;
/// Depois do reset o atapi espera o BSY cair por até 60 s
/// (AtapiCheckStatusAsync, rva 0x3030: 0x1D4C0 leituras do status, uma a
/// cada 500 µs).
const RESET_BUSY_TIMEOUT_MS: u64 = 60_000;
const RESET_POLL_US: u32 = 500;

/// O TimeOutValue em vigor (segundos) e as novas tentativas por pedido: os
/// padrões do disk.sys e do classpnp até [`configure_from_registry`].
static TIMEOUT_SECONDS: AtomicU32 = AtomicU32::new(DEFAULT_TIMEOUT_SECONDS);
static RETRIES: AtomicU32 = AtomicU32::new(DEFAULT_RETRIES);
/// Pedidos que só concluíram numa nova tentativa.
static RECOVERED: AtomicU32 = AtomicU32::new(0);

/// O que os registradores do canal guardam desde o último comando que
/// terminou bem, para o comando seguinte não os escrever de novo: sob um
/// hipervisor cada acesso a porta é uma saída da máquina virtual. Só o
/// driver interno programa o canal, sob o lock dele, então o valor do
/// Device/Head com o drive parado (sem BSY), o endereço da tabela PRD no
/// BMIDE e o comando de bus master parado (a direção) continuam lá. Uma
/// falha, um reset ou a pilha real assumindo a controladora
/// ([`release_controller`]) esquecem tudo (0 = desconhecido).
static KNOWN_SELECT: AtomicU32 = AtomicU32::new(0);
static KNOWN_PRD: AtomicU64 = AtomicU64::new(0);
static KNOWN_BM_COMMAND: AtomicU32 = AtomicU32::new(0);
/// Os bits de interrupção e de erro do status do bus master foram limpos no
/// fim do último comando, um DMA que terminou bem. Qualquer outro comando
/// liga o bit de interrupção quando o dispositivo levanta o INTRQ.
static BM_CLEAN: AtomicBool = AtomicBool::new(false);
/// O atapi.sys programa a controladora (`--storage=real`): nada fica
/// lembrado.
static FOREIGN_OWNER: AtomicBool = AtomicBool::new(false);
/// Marca de valor conhecido nos registradores lembrados de 8 bits.
const KNOWN: u32 = 0x100;

fn forget_registers() {
    BM_CLEAN.store(false, Ordering::Relaxed);
    KNOWN_SELECT.store(0, Ordering::Relaxed);
    KNOWN_PRD.store(0, Ordering::Relaxed);
    KNOWN_BM_COMMAND.store(0, Ordering::Relaxed);
}

fn remember(cell: &AtomicU32, value: u8) {
    if !FOREIGN_OWNER.load(Ordering::Relaxed) {
        cell.store(KNOWN | value as u32, Ordering::Relaxed);
    }
}

/// A pilha real (atapi.sys) assume a controladora: daqui em diante o driver
/// interno não supõe nada sobre os registradores.
pub fn release_controller() {
    let _channel = CHANNEL.lock();
    FOREIGN_OWNER.store(true, Ordering::Relaxed);
    forget_registers();
}

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

/// Os comandos do canal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Command {
    ReadDma,
    WriteDma,
    ReadSectors,
    WriteSectors,
    Identify,
    FlushCache,
}

impl Command {
    fn opcode(self) -> u8 {
        match self {
            Command::ReadDma => ATA_CMD_READ_DMA,
            Command::WriteDma => ATA_CMD_WRITE_DMA,
            Command::ReadSectors => ATA_CMD_READ,
            Command::WriteSectors => ATA_CMD_WRITE,
            Command::Identify => ATA_CMD_IDENTIFY,
            Command::FlushCache => ATA_CMD_FLUSH,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Command::ReadDma => "READ DMA",
            Command::WriteDma => "WRITE DMA",
            Command::ReadSectors => "READ SECTORS",
            Command::WriteSectors => "WRITE SECTORS",
            Command::Identify => "IDENTIFY DEVICE",
            Command::FlushCache => "FLUSH CACHE",
        }
    }
}

/// O prazo de um comando em milissegundos: o TimeOutValue, e quatro vezes
/// ele no FLUSH CACHE.
pub fn timeout_ms(command: Command) -> u64 {
    let seconds = TIMEOUT_SECONDS.load(Ordering::Relaxed) as u64;
    let seconds = if command == Command::FlushCache { seconds << FLUSH_TIMEOUT_SHIFT } else { seconds };
    seconds * 1000
}

/// Quantas vezes um pedido que falhou é mandado de novo.
pub fn retries() -> u32 {
    RETRIES.load(Ordering::Relaxed)
}

/// O TimeOutValue de `Services\disk` e o MaxNumberOfIoRetries de
/// `Control\Classpnp`, que o disk.sys e o classpnp.sys leem do Registro
/// quando iniciam (valor ausente ou zero = o padrão). Chamado quando a hive
/// SYSTEM existe; até lá valem os padrões.
pub fn configure_from_registry() {
    use crate::ntos::io::pnp::install::{read_dword, CONTROL_SET};
    let timeout = read_dword(&format!("{CONTROL_SET}\\Services\\disk"), "TimeOutValue").filter(|&seconds| seconds != 0).unwrap_or(DEFAULT_TIMEOUT_SECONDS);
    let retries = read_dword(&format!("{CONTROL_SET}\\Control\\Classpnp"), "MaxNumberOfIoRetries").filter(|&count| count != 0).map_or(DEFAULT_RETRIES, |count| count.min(RETRIES_LIMIT));
    TIMEOUT_SECONDS.store(timeout, Ordering::Relaxed);
    RETRIES.store(retries, Ordering::Relaxed);
    debug_print!("[ata] TimeOutValue {} s (FLUSH CACHE {} s), {} novas tentativas por pedido", timeout, timeout_ms(Command::FlushCache) / 1000, retries);
}

/// Uma tentativa que não concluiu: o motivo e os registradores lidos quando
/// a falha foi vista.
#[derive(Clone, Copy)]
struct Failure {
    reason: &'static str,
    /// O prazo venceu (o canal vai ao reset); senão o dispositivo ou o bus
    /// master terminaram o comando com erro.
    timed_out: bool,
    status: u8,
    error: u8,
    /// Status do bus master, nos comandos DMA.
    bus_master: Option<u8>,
}

impl Failure {
    fn timeout(reason: &'static str, status: u8, bus_master: Option<u8>) -> Failure {
        Failure { reason, timed_out: true, status, error: port::read8(ATA_ERROR), bus_master }
    }

    fn device(reason: &'static str, status: u8, bus_master: Option<u8>) -> Failure {
        Failure { reason, timed_out: false, status, error: port::read8(ATA_ERROR), bus_master }
    }

    fn bus_master_text(&self) -> String {
        match self.bus_master {
            Some(status) => format!("{status:#04x}"),
            None => String::from("-"),
        }
    }
}

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

    /// Manda um comando com o tratamento de erro da pilha de disco do 19041.
    /// `attempt` executa o comando uma vez com o prazo dado. Uma tentativa
    /// que falha sai numa linha `[ata]`; se o prazo venceu, o canal vai ao
    /// reset, como o ataport faz com um pedido vencido (o IdePortTickHandler,
    /// rva 0x1b40, chama o IdeTargetReset, rva 0x16cd0, que recorre ao
    /// IdeChannelReset, rva 0x169c8), e um comando que o dispositivo
    /// terminou com erro volta sem reset. O pedido é mandado de novo até
    /// [`retries`] vezes (o NumRetries do classpnp) antes de falhar.
    fn run<T>(&mut self, command: Command, lba: u64, count: u32, drive: u8, mut attempt: impl FnMut(u64) -> Result<T, Failure>) -> Result<T, KernelError> {
        let timeout = timeout_ms(command);
        // Um comando sem DMA liga o bit de interrupção do bus master.
        if !matches!(command, Command::ReadDma | Command::WriteDma) {
            BM_CLEAN.store(false, Ordering::Relaxed);
        }
        let attempts = retries() + 1;
        let mut tries = 0;
        loop {
            tries += 1;
            let start = clock::uptime_ms();
            let failure = match attempt(timeout) {
                Ok(value) => {
                    // Os comandos de PIO terminam sem conferir o BSY do fim: a
                    // seleção é feita de novo depois deles.
                    if matches!(command, Command::ReadSectors | Command::WriteSectors | Command::Identify) {
                        KNOWN_SELECT.store(0, Ordering::Relaxed);
                    }
                    if tries > 1 {
                        debug_print!("[ata] {} ({:#04x}) drive={} lba={} setores={} concluido na tentativa {} de {}", command.name(), command.opcode(), drive, lba, count, tries, attempts);
                        if RECOVERED.fetch_add(1, Ordering::AcqRel) == 0 {
                            debug_print!("ATA_RETRY_OK");
                        }
                    }
                    return Ok(value);
                }
                Err(failure) => failure,
            };
            forget_registers();
            let elapsed = clock::uptime_ms().saturating_sub(start);
            let last = tries >= attempts;
            let action = match (failure.timed_out, last) {
                (true, false) => "reset do canal e nova tentativa",
                (false, false) => "nova tentativa",
                (true, true) => "reset do canal; o pedido falha",
                (false, true) => "o pedido falha",
            };
            debug_print!(
                "[ata] {} ({:#04x}) drive={} lba={} setores={}: {} em {} ms (status={:#04x} erro={:#04x} bm={}), tentativa {} de {}; {}",
                command.name(),
                command.opcode(),
                drive,
                lba,
                count,
                failure.reason,
                elapsed,
                failure.status,
                failure.error,
                failure.bus_master_text(),
                tries,
                attempts,
                action
            );
            if failure.timed_out {
                self.reset();
            }
            if last {
                return Err(KernelError::new(format!(
                    "ATA: {} drive={} lba={} setores={} falhou nas {} tentativas: {} (status {:#04x}, erro {:#04x})",
                    command.name(),
                    drive,
                    lba,
                    count,
                    attempts,
                    failure.reason,
                    failure.status,
                    failure.error
                )));
            }
        }
    }

    /// O reset do canal depois de um comando vencido, como o HwReset do
    /// atapi.sys (rva 0x1940): o bus master parado e o status dele limpo
    /// (AtapiDisarmDma, rva 0x2a50), o SRST dos dois drives
    /// (AtapiIssueSoftReset, rva 0x3500: mestre selecionado, SRST com nIEN
    /// por 10 µs, o controle zerado e 2 ms de espera) e o BSY esperado por
    /// até 60 s (AtapiCheckStatusAsync, rva 0x3030; o status 0xFF de um
    /// canal sem drive também encerra a espera). No QEMU o reset só solta o
    /// BSY depois de a E/S em andamento no host terminar. Devolve se o BSY
    /// caiu.
    fn reset(&mut self) -> bool {
        forget_registers();
        if self.bmide_base != 0 {
            let status = port::read8(self.bmide_base + BM_STATUS);
            port::write8(self.bmide_base + BM_COMMAND, 0);
            port::write8(self.bmide_base + BM_STATUS, status | BM_STATUS_ERROR | BM_STATUS_INTERRUPT);
        }
        port::write8(ATA_DRIVE, SELECT_MASTER);
        port::write8(ATA_DEVICE_CONTROL, DEVICE_CONTROL_SRST | DEVICE_CONTROL_NIEN);
        clock::stall_execution_processor(RESET_ASSERT_US);
        port::write8(ATA_DEVICE_CONTROL, 0);
        clock::stall_execution_processor(RESET_RELEASE_US);
        let start = clock::uptime_ms();
        let deadline = start + RESET_BUSY_TIMEOUT_MS;
        loop {
            let expired = clock::uptime_ms() >= deadline;
            let status = port::read8(ATA_STATUS);
            if status == 0xFF || status & SR_BSY == 0 {
                debug_print!("[ata] reset do canal: BSY caiu em {} ms (status={:#04x})", clock::uptime_ms().saturating_sub(start), status);
                return true;
            }
            if expired {
                debug_print!("[ata] reset do canal: BSY nao caiu em {} ms (status={:#04x} erro={:#04x})", RESET_BUSY_TIMEOUT_MS, status, port::read8(ATA_ERROR));
                return false;
            }
            clock::stall_execution_processor(RESET_POLL_US);
        }
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
            write_prd_table(table, destination + done as u64 * 512, chunk);
            self.dma_command(bmide, table, lba + done as u64, chunk, drive, write)?;
            done += chunk;
        }
        Ok(())
    }

    /// READ DMA para uma lista de páginas físicas, como a lista de
    /// dispersão que o ataport monta do MDL de uma leitura: os setores enchem
    /// as páginas em ordem a partir do byte `start` da lista, até 256
    /// setores por comando, um PRD por pedaço de página.
    fn transfer_dma_pages(&mut self, lba: u64, count: u32, drive: u8, pages: &[u64], start: u64) -> Result<(), KernelError> {
        validate_range(lba, count as u64, drive)?;
        if start % 2 != 0 || (start + count as u64 * 512).div_ceil(PAGE_BYTES) > pages.len() as u64 || pages.iter().any(|&page| page % PAGE_BYTES != 0 || page + PAGE_BYTES > 0x1_0000_0000) {
            return Err(error("ATA DMA: paginas de destino invalidas"));
        }
        let (bmide, table) = self.bus_master()?;
        let mut done = 0u32;
        while done < count {
            let chunk = (count - done).min(256);
            write_prd_pages(table, pages, start + done as u64 * 512, chunk);
            self.dma_command(bmide, table, lba + done as u64, chunk, drive, false)?;
            done += chunk;
        }
        Ok(())
    }

    /// Um comando de DMA já descrito na tabela PRD, com o tratamento de erro
    /// de `run` e a contagem da linha `[perf]`.
    fn dma_command(&mut self, bmide: u16, table: DmaBuffer, sector: u64, chunk: u32, drive: u8, write: bool) -> Result<(), KernelError> {
        let command = if write { Command::WriteDma } else { Command::ReadDma };
        let started = cpu::rdtsc();
        let result = self.run(command, sector, chunk, drive, |timeout| dma_attempt(bmide, table, sector, chunk, drive, write, timeout));
        DMA_TSC.fetch_add(cpu::rdtsc().wrapping_sub(started), Ordering::Relaxed);
        DMA_COMMANDS.fetch_add(1, Ordering::Relaxed);
        DMA_SECTORS.fetch_add(chunk as u64, Ordering::Relaxed);
        result
    }
}

const PAGE_BYTES: u64 = 4096;

/// Tabela PRD de `count` setores a partir do byte `start` da lista de
/// páginas: uma região por página (nenhuma cruza 64 KiB), a última com o bit
/// de fim.
fn write_prd_pages(table: DmaBuffer, pages: &[u64], start: u64, count: u32) {
    let end = start + count as u64 * 512;
    let (mut at, mut entries) = (start, 0u64);
    while at < end {
        let offset = at % PAGE_BYTES;
        let length = (PAGE_BYTES - offset).min(end - at);
        let prd = table.address + entries * 8;
        guest::write32(prd, (pages[(at / PAGE_BYTES) as usize] + offset) as u32);
        guest::write16(prd + 4, length as u16);
        guest::write16(prd + 6, if at + length >= end { 0x8000 } else { 0 });
        entries += 1;
        at += length;
    }
}

/// O TSC gasto nos comandos de DMA, os comandos e os setores desde o boot
/// (a linha `[perf]` mostra o que andou em cada intervalo).
static DMA_TSC: AtomicU64 = AtomicU64::new(0);
static DMA_COMMANDS: AtomicU64 = AtomicU64::new(0);
static DMA_SECTORS: AtomicU64 = AtomicU64::new(0);

/// (TSC, comandos, setores) dos comandos de DMA desde o boot.
pub fn dma_cost() -> (u64, u64, u64) {
    (DMA_TSC.load(Ordering::Relaxed), DMA_COMMANDS.load(Ordering::Relaxed), DMA_SECTORS.load(Ordering::Relaxed))
}

/// Tabela PRD (Physical Region Descriptors) de um bloco: regiões quebradas
/// nas fronteiras de 64 KiB, a última com o bit de fim.
fn write_prd_table(table: DmaBuffer, target: u64, count: u32) {
    let mut entries = 0u64;
    let mut region = target;
    let mut remaining = count as u64 * 512;
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
}

/// Uma tentativa de READ/WRITE DMA de um bloco já descrito na tabela PRD,
/// como o atapi.sys a programa: a tabela PRD no BMIDE, a direção, o status
/// do bus master limpo, o task file, o comando e o início do bus master.
/// Concluído = interrupção sinalizada no status do bus master (o INTRQ do
/// dispositivo) e, lido só então, o status do dispositivo fora de BSY (a
/// leitura do status reconhece a interrupção); o bus master sai parado e
/// com o status limpo. O que o canal já guarda do comando anterior
/// ([`KNOWN_SELECT`]) não é escrito de novo.
fn dma_attempt(bmide: u16, table: DmaBuffer, lba: u64, count: u32, drive: u8, write: bool, timeout_ms: u64) -> Result<(), Failure> {
    let clean = BM_CLEAN.swap(false, Ordering::Relaxed);
    select_drive(lba, drive, timeout_ms)?;
    if KNOWN_PRD.load(Ordering::Relaxed) != table.physical | 1 {
        port::write32(bmide + BM_PRD, table.physical as u32);
        if !FOREIGN_OWNER.load(Ordering::Relaxed) {
            KNOWN_PRD.store(table.physical | 1, Ordering::Relaxed);
        }
    }
    let direction = if write { 0 } else { BM_TO_MEMORY };
    if KNOWN_BM_COMMAND.load(Ordering::Relaxed) != KNOWN | direction as u32 {
        port::write8(bmide + BM_COMMAND, direction);
        remember(&KNOWN_BM_COMMAND, direction);
    }
    if !clean {
        port::write8(bmide + BM_STATUS, port::read8(bmide + BM_STATUS) | BM_STATUS_ERROR | BM_STATUS_INTERRUPT);
    }
    task_file(lba, count);
    port::write8(ATA_CMD, if write { ATA_CMD_WRITE_DMA } else { ATA_CMD_READ_DMA });
    port::write8(bmide + BM_COMMAND, direction | BM_START);
    settle();
    let deadline = clock::uptime_ms() + timeout_ms;
    let mut bus_master;
    let outcome = loop {
        let expired = clock::uptime_ms() >= deadline;
        bus_master = port::read8(bmide + BM_STATUS);
        if bus_master & BM_STATUS_ERROR != 0 {
            break Err(Failure::device("erro do bus master", port::read8(ATA_STATUS), Some(bus_master)));
        }
        if bus_master & BM_STATUS_INTERRUPT != 0 {
            // O status (não o alternativo) reconhece a interrupção.
            let status = port::read8(ATA_STATUS);
            if status & SR_BSY == 0 {
                if status & (SR_ERR | SR_DF) != 0 {
                    break Err(Failure::device(if write { "erro de escrita" } else { "erro de leitura" }, status, Some(bus_master)));
                }
                break Ok(());
            }
        }
        if expired {
            break Err(Failure::timeout("timeout do DMA", port::read8(ATA_STATUS), Some(bus_master)));
        }
        poll_gap();
    };
    port::write8(bmide + BM_COMMAND, direction);
    port::write8(bmide + BM_STATUS, bus_master | BM_STATUS_ERROR | BM_STATUS_INTERRUPT);
    if outcome.is_ok() && !FOREIGN_OWNER.load(Ordering::Relaxed) {
        BM_CLEAN.store(true, Ordering::Relaxed);
    }
    outcome
}

fn validate_range(lba: u64, count: u64, drive: u8) -> Result<(), KernelError> {
    if lba + count > 0x1000_0000 || drive > 1 {
        return Err(error("ATA: faixa LBA28 invalida"));
    }
    Ok(())
}

/// Os 400 ns que o dispositivo tem para publicar o status depois de uma
/// seleção ou de um comando: pelo TSC, quando calibrado; antes dele, quatro
/// leituras do status alternativo (a espera do padrão ATA). Sob um
/// hipervisor cada leitura de porta é uma saída da máquina virtual de
/// alguns microssegundos, e o padrão só pede o tempo.
fn settle() {
    if !spin_ns(400) {
        for _ in 0..4 {
            port::read8(ATA_ALT_STATUS);
        }
    }
}

/// Gira `nanoseconds` pelo TSC, sem acesso a porta; `false` antes da
/// calibração do TSC.
fn spin_ns(nanoseconds: u64) -> bool {
    let hertz = clock::tsc_frequency_hz();
    if hertz == 0 {
        return false;
    }
    let until = cpu::rdtsc().wrapping_add(hertz / 1_000_000 * nanoseconds / 1_000 + 1);
    while cpu::rdtsc() < until {
        cpu::pause();
    }
    true
}

/// O intervalo entre duas leituras de status na espera de um DMA. No QEMU
/// cada leitura de porta é uma saída que toma o lock global do QEMU, o
/// mesmo que a conclusão da E/S precisa: lidas sem intervalo, elas atrasam
/// a conclusão que esperam. O intervalo é pequeno perto da duração de um
/// comando.
const DMA_POLL_GAP_NS: u64 = 20_000;

fn poll_gap() {
    if !spin_ns(DMA_POLL_GAP_NS) {
        cpu::pause();
    }
}

/// Espera o status alternativo satisfazer `done` até o prazo. O status é
/// relido depois de o prazo vencer, então uma CPU virtual que ficou sem
/// rodar não dá por perdido um comando que já concluiu. `done` devolve
/// `Err(motivo)` quando o dispositivo terminou o comando com erro.
fn wait_status(timeout_ms: u64, reason: &'static str, mut done: impl FnMut(u8) -> Result<bool, &'static str>) -> Result<(), Failure> {
    let deadline = clock::uptime_ms() + timeout_ms;
    loop {
        let expired = clock::uptime_ms() >= deadline;
        let status = port::read8(ATA_ALT_STATUS);
        match done(status) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(device) => return Err(Failure::device(device, status, None)),
        }
        if expired {
            return Err(Failure::timeout(reason, status, None));
        }
        cpu::pause();
    }
}

fn wait_ready(timeout_ms: u64) -> Result<(), Failure> {
    wait_status(timeout_ms, "timeout BSY", |status| Ok(status & SR_BSY == 0))
}

fn wait_data(timeout_ms: u64) -> Result<(), Failure> {
    wait_status(timeout_ms, "timeout DRQ", |status| {
        if status & SR_BSY != 0 {
            return Ok(false);
        }
        if status & (SR_ERR | SR_DF) != 0 {
            return Err("erro de transferencia");
        }
        Ok(status & SR_DRQ != 0)
    })
}

/// Fim de um comando sem dados pendentes; reconhece a interrupção.
fn wait_complete(timeout_ms: u64) -> Result<(), Failure> {
    let outcome = wait_status(timeout_ms, "timeout de conclusao", |status| {
        if status & SR_BSY != 0 {
            return Ok(false);
        }
        if status & (SR_ERR | SR_DF) != 0 {
            return Err("comando falhou");
        }
        Ok(status & SR_DRQ == 0)
    });
    port::read8(ATA_STATUS);
    outcome
}

/// Seleciona o drive (Device/Head com o modo LBA e os bits 24-27 do LBA)
/// com o BSY baixo antes e depois. O drive que o último comando bem
/// terminado deixou selecionado, com os mesmos bits, já está pronto
/// ([`KNOWN_SELECT`]).
fn select_drive(lba: u64, drive: u8, timeout_ms: u64) -> Result<(), Failure> {
    let value = 0xE0 | drive << 4 | ((lba >> 24) & 15) as u8;
    if KNOWN_SELECT.load(Ordering::Relaxed) == KNOWN | value as u32 {
        return Ok(());
    }
    KNOWN_SELECT.store(0, Ordering::Relaxed);
    wait_ready(timeout_ms)?;
    port::write8(ATA_DRIVE, value);
    settle();
    wait_ready(timeout_ms)?;
    remember(&KNOWN_SELECT, value);
    Ok(())
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

/// READ DMA de `count` setores para as páginas `pages` (frames de 4 KB
/// abaixo de 4 GB), em ordem a partir do byte `start` da lista: um comando
/// por até 256 setores, em vez de um por página.
pub fn read_sectors_dma_to_pages(lba: u64, count: u32, drive: u8, pages: &[u64], start: u64) -> Result<(), KernelError> {
    CHANNEL.lock().transfer_dma_pages(lba, count, drive, pages, start)
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
        // SAFETY: o buffer de passagem é RAM do canal, mapeada, com o DMA já
        // concluído (o status lido no fim do comando) e o lock tomado.
        out.extend_from_slice(unsafe { core::slice::from_raw_parts(bounce.address as *const u8, chunk as usize * 512) });
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
        let block = &mut out[done as usize * 512..(done + chunk) as usize * 512];
        let mut channel = CHANNEL.lock();
        channel.run(Command::ReadSectors, sector, chunk, drive, |timeout| {
            select_drive(sector, drive, timeout)?;
            task_file(sector, chunk);
            port::write8(ATA_CMD, ATA_CMD_READ);
            settle();
            for data in block.chunks_exact_mut(512) {
                wait_data(timeout)?;
                for word in 0..256 {
                    let value = port::read16(ATA_DATA);
                    data[word * 2] = value as u8;
                    data[word * 2 + 1] = (value >> 8) as u8;
                }
            }
            port::read8(ATA_STATUS);
            Ok(())
        })?;
        drop(channel);
        done += chunk;
    }
    Ok(out)
}

/// Uma escrita em `[lba, lba + count)`: o cache de metadados
/// (`sector_cache`) esquece as unidades cobertas antes do comando e de novo
/// depois dele, com sucesso ou não.
fn writing<T>(lba: u64, count: u32, drive: u8, write: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
    super::sector_cache::invalidate(lba, count as u64, drive);
    let result = write();
    super::sector_cache::invalidate(lba, count as u64, drive);
    result
}

/// Grava setores completos por DMA a partir do buffer físico de passagem.
pub fn write_sectors(lba: u64, bytes: &[u8], drive: u8) -> Result<(), KernelError> {
    if bytes.len() % 512 != 0 {
        return Err(error("ATA: escrita exige setores completos"));
    }
    let count = (bytes.len() / 512) as u32;
    validate_range(lba, count as u64, drive)?;
    writing(lba, count, drive, || write_sectors_dma(lba, bytes, count, drive))
}

fn write_sectors_dma(lba: u64, bytes: &[u8], count: u32, drive: u8) -> Result<(), KernelError> {
    let mut done = 0;
    while done < count {
        let chunk = READ_BOUNCE_SECTORS.min(count - done);
        let mut channel = CHANNEL.lock();
        let bounce = channel.bounce()?;
        let source = &bytes[done as usize * 512..(done + chunk) as usize * 512];
        // SAFETY: o buffer de passagem é RAM do canal, mapeada, do tamanho de
        // READ_BOUNCE_SECTORS setores, com o lock tomado; o DMA só começa
        // depois da cópia.
        unsafe { core::ptr::copy_nonoverlapping(source.as_ptr(), bounce.address as *mut u8, source.len()) };
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
    writing(lba, count, drive, || write_sectors_pio_commands(lba, bytes, count, drive))
}

fn write_sectors_pio_commands(lba: u64, bytes: &[u8], count: u32, drive: u8) -> Result<(), KernelError> {
    let mut done = 0;
    while done < count {
        let chunk = (count - done).min(256);
        let sector = lba + done as u64;
        let block = &bytes[done as usize * 512..(done + chunk) as usize * 512];
        let mut channel = CHANNEL.lock();
        channel.run(Command::WriteSectors, sector, chunk, drive, |timeout| {
            select_drive(sector, drive, timeout)?;
            task_file(sector, chunk);
            port::write8(ATA_CMD, ATA_CMD_WRITE);
            settle();
            for data in block.chunks_exact(512) {
                wait_data(timeout)?;
                for word in (0..512).step_by(2) {
                    port::write16(ATA_DATA, data[word] as u16 | (data[word + 1] as u16) << 8);
                }
            }
            wait_complete(timeout)
        })?;
        drop(channel);
        done += chunk;
    }
    Ok(())
}

/// IDENTIFY DEVICE (0xEC) por PIO: as palavras 60-61 dão o total de setores
/// endereçáveis em LBA28 (a capacidade que o disco informa).
pub fn capacity_sectors(drive: u8) -> Result<u64, KernelError> {
    validate_range(0, 0, drive)?;
    let mut channel = CHANNEL.lock();
    let words = channel.run(Command::Identify, 0, 1, drive, |timeout| {
        select_drive(0, drive, timeout)?;
        port::write8(ATA_CMD, ATA_CMD_IDENTIFY);
        settle();
        wait_data(timeout)?;
        let mut words = [0u16; 256];
        for word in words.iter_mut() {
            *word = port::read16(ATA_DATA);
        }
        port::read8(ATA_STATUS);
        Ok(words)
    })?;
    Ok(words[60] as u64 | (words[61] as u64) << 16)
}

/// FLUSH CACHE, com quatro vezes o prazo dos outros comandos.
pub fn flush(drive: u8) -> Result<(), KernelError> {
    validate_range(0, 0, drive)?;
    CHANNEL.lock().run(Command::FlushCache, 0, 0, drive, |timeout| {
        select_drive(0, drive, timeout)?;
        port::write8(ATA_CMD, ATA_CMD_FLUSH);
        settle();
        wait_complete(timeout)
    })
}

/// O reset do canal que segue um comando vencido, sob o lock do canal (o
/// autoteste confere que os discos respondem depois dele). Devolve se o BSY
/// caiu.
pub fn reset_channel() -> bool {
    CHANNEL.lock().reset()
}

/// Detecta se um drive responde: status flutuante (0xFF) ou zero é
/// ausência; um drive presente sai de BSY dentro do prazo de seleção.
pub fn present(drive: u8) -> Result<bool, KernelError> {
    let _channel = CHANNEL.lock();
    forget_registers();
    port::write8(ATA_DRIVE, 0xE0 | (drive & 1) << 4);
    settle();
    let status = port::read8(ATA_ALT_STATUS);
    if status == 0xFF || status == 0x00 {
        return Ok(false);
    }
    if let Err(failure) = wait_ready(timeout_ms(Command::Identify)) {
        return Err(KernelError::new(format!("ATA: drive {} sem resposta na deteccao: {} (status {:#04x})", drive, failure.reason, failure.status)));
    }
    let status = port::read8(ATA_ALT_STATUS);
    Ok(status != 0xFF && status != 0x00)
}
