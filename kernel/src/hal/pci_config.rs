//! Mecanismo de configuração PCI 1 (PC/i440fx) — `system32/ntos/hal/pci-config.js`.
//!
//! O latch de endereço e a porta de dados são uma transação única, inclusive
//! sondagens compostas de BAR e atualizações de comando; nunca há
//! leitura/alteração/escrita de registradores vizinhos.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::{cpu, physical, port};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const ADDRESS: u16 = 0xCF8;
const DATA: u16 = 0xCFC;

static LOCK: AtomicU64 = AtomicU64::new(0);

/// Chamado no BSP antes de iniciar os APs ou publicar entradas da HAL.
pub fn init() -> Result<(), KernelError> {
    if LOCK.load(Ordering::Acquire) != 0 {
        return Ok(());
    }
    let lock = guest::alloc_bytes(8);
    if lock == 0 {
        return Err(KernelError::new("PCI configuration lock allocation failed"));
    }
    physical::write32(lock, 0);
    physical::write32(lock + 4, 0);
    LOCK.store(lock, Ordering::Release);
    Ok(())
}

pub fn valid(bus: u32, device: u32, function: u32) -> bool {
    bus < 256 && device < 32 && function < 8
}

/// Acesso aos registradores dentro de uma transação.
pub struct Io {
    base: u32,
}

impl Io {
    fn port(&self, offset: u32, width: u32) -> Result<u16, KernelError> {
        if ![1, 2, 4].contains(&width) || offset + width > 256 || offset % width != 0 {
            return Err(KernelError::new("invalid PCI configuration register width/range"));
        }
        port::write32(ADDRESS, self.base | (offset & 0xFC));
        Ok(DATA + (offset & 3) as u16)
    }

    pub fn read(&self, offset: u32, width: u32) -> Result<u32, KernelError> {
        let at = self.port(offset, width)?;
        Ok(match width {
            1 => port::read8(at) as u32,
            2 => port::read16(at) as u32,
            _ => port::read32(at),
        })
    }

    pub fn write(&self, offset: u32, width: u32, value: u32) -> Result<(), KernelError> {
        let at = self.port(offset, width)?;
        match width {
            1 => port::write8(at, value as u8),
            2 => port::write16(at, value as u16),
            _ => port::write32(at, value),
        }
        Ok(())
    }
}

/// Transação com interrupções desligadas e o lock de configuração retido.
pub fn transaction<T>(bus: u32, device: u32, function: u32, action: impl FnOnce(&Io) -> Result<T, KernelError>) -> Result<T, KernelError> {
    let lock = LOCK.load(Ordering::Acquire);
    if lock == 0 {
        return Err(KernelError::new("PCI configuration used before phase0 initialization"));
    }
    if !valid(bus, device, function) {
        return Err(KernelError::new("invalid PCI bus/device/function"));
    }
    let flags = cpu::save_and_disable_interrupts();
    while physical::compare_exchange64(lock, 0, 1) != 0 {
        cpu::pause();
    }
    let result = action(&Io { base: 0x8000_0000 | bus << 16 | device << 11 | function << 8 });
    let released = physical::compare_exchange64(lock, 1, 0) == 1;
    cpu::restore_interrupts(flags);
    if !released {
        return Err(KernelError::new("PCI configuration lock ownership corrupted"));
    }
    result
}

pub fn read(bus: u32, device: u32, function: u32, offset: u32, width: u32) -> Result<u32, KernelError> {
    transaction(bus, device, function, |io| io.read(offset, width))
}

pub fn write(bus: u32, device: u32, function: u32, offset: u32, width: u32, value: u32) -> Result<(), KernelError> {
    transaction(bus, device, function, |io| io.write(offset, width, value))
}

/// Liga bits do registrador de comando numa única transação.
pub fn enable_command(bus: u32, device: u32, function: u32, bits: u32) -> Result<u32, KernelError> {
    transaction(bus, device, function, |io| {
        let command = io.read(4, 2)? | bits;
        io.write(4, 2, command)?;
        Ok(command & 0xFFFF)
    })
}
