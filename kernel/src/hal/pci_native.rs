//! Entradas nativas HalGet/SetBusData sobre as portas PCI.
//!
//! Esta plataforma tem um espaço de 256 bytes do mecanismo 1 no segmento
//! zero. ECAM e outros segmentos exigiriam outro transporte; offsets e
//! segmentos nunca são dobrados sobre registradores do mecanismo 1.

use super::pci_config::{self, Io};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

#[derive(Clone, Copy)]
struct Request {
    bus: u32,
    device: u32,
    function: u32,
    offset: u32,
    length: u32,
}

fn request(bus: u32, slot: u32, offset: u32, length: u32) -> Option<Request> {
    if bus > 255 || slot > 255 || offset >= 256 || length == 0 {
        return None;
    }
    Some(Request { bus, device: slot & 31, function: slot >> 5, offset, length: length.min(256 - offset) })
}

fn accessible(request: &Request) -> Result<bool, KernelError> {
    if request.function == 0 {
        return Ok(true);
    }
    pci_config::transaction(request.bus, request.device, 0, |io| Ok(io.read(0, 2)? != 0xFFFF && io.read(14, 1)? & 0x80 != 0))
}

fn transfer_bytes(io: &Io, request: &Request, buffer: u64, writing: bool) -> Result<u32, KernelError> {
    let mut done = 0;
    while done < request.length {
        let at = request.offset + done;
        let remaining = request.length - done;
        let width = if at % 4 == 0 && remaining >= 4 { 4 } else if at % 2 == 0 && remaining >= 2 { 2 } else { 1 };
        let pointer = buffer + done as u64;
        if writing {
            let value = match width {
                4 => guest::read32(pointer),
                2 => guest::read16(pointer) as u32,
                _ => guest::read8(pointer) as u32,
            };
            io.write(at, width, value)?;
        } else {
            let value = io.read(at, width)?;
            match width {
                4 => guest::write32(pointer, value),
                2 => guest::write16(pointer, value as u16),
                _ => guest::write8(pointer, value as u8),
            }
        }
        done += width;
    }
    Ok(done)
}

/// Função inválida ou ausente: a HAL nativa responde como vendor ausente.
fn absent(request: &Request, buffer: u64, writing: bool) -> u32 {
    if writing || request.offset >= 2 {
        return 0;
    }
    let count = request.length.min(2 - request.offset);
    for index in 0..count {
        guest::write8(buffer + index as u64, 0xFF);
    }
    count
}

fn transfer(request: Request, buffer: u64, writing: bool) -> Result<u32, KernelError> {
    if !accessible(&request)? {
        return Ok(absent(&request, buffer, writing));
    }
    pci_config::transaction(request.bus, request.device, request.function, |io| {
        if io.read(0, 2)? == 0xFFFF {
            return Ok(absent(&request, buffer, writing));
        }
        // O kernel 26100 conferido recusa escrita nos primeiros 64 bytes de
        // um cabeçalho que não seja tipo 0.
        if writing && request.offset < 64 && io.read(14, 1)? & 0x7F != 0 {
            return Ok(0);
        }
        transfer_bytes(io, &request, buffer, writing)
    })
}

/// HalGetBusDataByOffset (só PCIConfiguration = 4).
pub fn get_bus_data_by_offset(bus_type: u32, bus: u32, slot: u32, buffer: u64, offset: u32, length: u32) -> Result<u32, KernelError> {
    if bus_type != 4 {
        return Ok(0);
    }
    request(bus, slot, offset, length).map_or(Ok(0), |request| transfer(request, buffer, false))
}

pub fn set_bus_data_by_offset(bus_type: u32, bus: u32, slot: u32, buffer: u64, offset: u32, length: u32) -> Result<u32, KernelError> {
    if bus_type != 4 {
        return Ok(0);
    }
    request(bus, slot, offset, length).map_or(Ok(0), |request| transfer(request, buffer, true))
}

pub fn get_bus_data(bus_type: u32, bus: u32, slot: u32, buffer: u64, length: u32) -> Result<u32, KernelError> {
    get_bus_data_by_offset(bus_type, bus, slot, buffer, 0, length)
}

pub fn set_bus_data(bus_type: u32, bus: u32, slot: u32, buffer: u64, length: u32) -> Result<u32, KernelError> {
    set_bus_data_by_offset(bus_type, bus, slot, buffer, 0, length)
}

/// Callbacks KD da HAL nativa usam o transporte direto: dispositivo ausente
/// devolve os bytes FFFF do hardware, e escritas emitem ciclos reais.
fn kd_transfer(bus: u32, slot: u32, buffer: u64, offset: u32, length: u32, writing: bool) -> Result<u32, KernelError> {
    let Some(request) = request(bus, slot, offset, length) else { return Ok(0) };
    pci_config::transaction(request.bus, request.device, request.function, |io| transfer_bytes(io, &request, buffer, writing))
}

pub fn kd_get_pci_data_by_offset(bus: u32, slot: u32, buffer: u64, offset: u32, length: u32) -> Result<u32, KernelError> {
    kd_transfer(bus, slot, buffer, offset, length, false)
}

pub fn kd_set_pci_data_by_offset(bus: u32, slot: u32, buffer: u64, offset: u32, length: u32) -> Result<u32, KernelError> {
    kd_transfer(bus, slot, buffer, offset, length, true)
}
