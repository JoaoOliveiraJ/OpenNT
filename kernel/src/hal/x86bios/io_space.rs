//! Portas de I/O e PCI BIOS do processador emulado, como as do emulador da
//! HAL do Windows 10 19041 (x86BiosReadIoSpace/x86BiosWriteIoSpace e
//! XmExecuteInt1a):
//!
//! - toda porta vai ao hardware (`in`/`out` reais), menos:
//! - CF8h-CFBh, o endereço do mecanismo de configuração PCI 1, que fica num
//!   latch próprio (XmPCIConfigAddress; os dois bits baixos sempre limpos), e
//!   CFCh-CFFh com o latch habilitado (bit 31), que viram leituras e escritas
//!   do espaço de configuração pelas rotinas KdGet/SetPciDataByOffset da
//!   HalPrivateDispatchTable (XmGetPciData/XmSetPciData) — o BIOS nunca toca
//!   o par CF8/CFC do hardware, que é do kernel;
//! - 70h, o índice da CMOS, também num latch (XmCmosAddress); 71h faz a
//!   transação índice + dado sob o lock da CMOS;
//! - INT 1Ah com AH = B1h é o PCI BIOS emulado sobre as mesmas rotinas:
//!   B101h (presença), B102h (procura por fabricante e dispositivo), B103h
//!   (por classe), B106h, B10Eh e B10Fh (sem suporte, CF=1, AH=81h) e
//!   B108h-B10Dh (leitura e escrita de configuração); as outras funções
//!   seguem para o vetor da IVT.
//!
//! Os detalhes de cada caminho são os do binário: o acesso que passa do fim
//! do registrador de 4 bytes é encurtado; uma leitura de configuração que não
//! transfere nada devolve todos os bits 1 da largura (e 0 numa leitura de 4
//! bytes, como o deslocamento de 32 posições do x86 dá); a procura por
//! dispositivo testa AX (não DX) contra FFFFh; as escritas de configuração do
//! INT 1Ah dão CF=1 e AH=87h quando a rotina da tabela transfere bytes e
//! CF=0 quando ela devolve 0.

use super::emulator::{Cpu, EAX, EBX, ECX, EDI, EDX, ESI};
use super::operations::CF;
use crate::hal::{port, private_dispatch, rtc};

const PCI_ADDRESS_PORT: u16 = 0xCF8;
const PCI_DATA_PORT: u16 = 0xCFC;
const CMOS_ADDRESS_PORT: u16 = 0x70;
/// Bit de habilitação do endereço de configuração.
const PCI_ENABLE: u32 = 0x8000_0000;

/// Códigos de retorno do PCI BIOS (AH).
const FUNCTION_NOT_SUPPORTED: u8 = 0x81;
const BAD_VENDOR_ID: u8 = 0x83;
const DEVICE_NOT_FOUND: u8 = 0x86;
const BAD_REGISTER_NUMBER: u8 = 0x87;
/// 'PCI ' em EDX na resposta de B101h.
const PCI_SIGNATURE: u32 = 0x2049_4350;
/// Versão da interface informada em BX (2.10).
const PCI_BIOS_VERSION: u32 = 0x0210;

/// Estado das portas emuladas.
pub struct IoSpace {
    /// XmPCIConfigAddress.
    pci_config_address: u32,
    /// XmCmosAddress.
    cmos_address: u8,
    /// XmPciBiosPresent: a tabela privada tem KdGetPciDataByOffset.
    pci_bios_present: bool,
    /// XmNumberPciBusses.
    pci_buses: u8,
}

/// Tipo de dado da HAL: 0 = byte, 1 = word, 3 = dword (largura - 1).
fn data_type(size: u32) -> u32 {
    size - 1
}

/// Número do slot (PCI_SLOT_NUMBER) de dispositivo e função.
fn slot_number(device: u32, function: u32) -> u32 {
    (device & 0x1F) | ((function & 7) << 5)
}

impl IoSpace {
    /// x86BiosInitializeBiosEx: PCI BIOS presente quando a tabela privada
    /// oferece a leitura de configuração; o número de barramentos é o último
    /// barramento + 1, ou FFh quando o último é 0 ou FFh.
    pub fn new(pci_bios_present: bool, last_pci_bus: u32) -> Self {
        let pci_buses = if last_pci_bus == 0 || last_pci_bus == 0xFF { 0xFF } else { (last_pci_bus as u8).wrapping_add(1) };
        Self { pci_config_address: 0, cmos_address: 0, pci_bios_present, pci_buses }
    }

    fn pci_latch_bytes(&self) -> [u8; 4] {
        self.pci_config_address.to_le_bytes()
    }

    /// x86BiosReadIoSpace.
    pub fn read(&mut self, port: u16, size: u32) -> u32 {
        let data_type = data_type(size);
        if self.pci_bios_present {
            let offset = port.wrapping_sub(PCI_ADDRESS_PORT);
            if offset <= 3 {
                return self.read_pci_address_port(data_type, offset as u32);
            }
            let offset = port.wrapping_sub(PCI_DATA_PORT);
            if self.pci_config_address & PCI_ENABLE != 0 && offset <= 3 {
                return self.read_pci_data_port(data_type, offset as u32);
            }
        }
        if port.wrapping_sub(CMOS_ADDRESS_PORT) <= 1 {
            return self.read_cmos_port(data_type, port);
        }
        match size {
            1 => port::read8(port) as u32,
            2 => port::read16(port) as u32,
            _ => port::read32(port),
        }
    }

    /// x86BiosWriteIoSpace.
    pub fn write(&mut self, port: u16, size: u32, value: u32) {
        let data_type = data_type(size);
        if self.pci_bios_present {
            let offset = port.wrapping_sub(PCI_ADDRESS_PORT);
            if offset <= 3 {
                return self.write_pci_address_port(data_type, offset as u32, value);
            }
            let offset = port.wrapping_sub(PCI_DATA_PORT);
            if self.pci_config_address & PCI_ENABLE != 0 && offset <= 3 {
                return self.write_pci_data_port(data_type, offset as u32, value);
            }
        }
        if port.wrapping_sub(CMOS_ADDRESS_PORT) <= 1 {
            return self.write_cmos_port(data_type, port, value);
        }
        match size {
            1 => port::write8(port, value as u8),
            2 => port::write16(port, value as u16),
            _ => port::write32(port, value),
        }
    }

    /// Acesso que passa do fim do registrador de 4 bytes é encurtado.
    fn clamp(data_type: u32, offset: u32) -> u32 {
        if offset + data_type > 3 { 3 - offset } else { data_type }
    }

    /// x86BiosReadPciAddressPort.
    fn read_pci_address_port(&self, data_type: u32, offset: u32) -> u32 {
        let bytes = self.pci_latch_bytes();
        let at = offset as usize;
        let word = |index: usize| u16::from_le_bytes([bytes[index], bytes[index + 1]]) as u32;
        match Self::clamp(data_type, offset) {
            0 => bytes[at] as u32,
            1 => word(at),
            2 => word(at) | ((bytes[3] as u32) << 16),
            _ => self.pci_config_address,
        }
    }

    /// x86BiosWritePciAddressPort: grava no latch; os dois bits baixos ficam
    /// sempre limpos.
    fn write_pci_address_port(&mut self, data_type: u32, offset: u32, value: u32) {
        let mut bytes = self.pci_latch_bytes();
        let at = offset as usize;
        match Self::clamp(data_type, offset) {
            0 => bytes[at] = value as u8,
            1 => bytes[at..at + 2].copy_from_slice(&(value as u16).to_le_bytes()),
            2 => {
                bytes[at..at + 2].copy_from_slice(&(value as u16).to_le_bytes());
                bytes[3] = (value >> 16) as u8;
            }
            _ => bytes = value.to_le_bytes(),
        }
        self.pci_config_address = u32::from_le_bytes(bytes) & !3;
    }

    /// Barramento, slot e registrador do latch para um acesso em `offset`.
    fn pci_target(&self, offset: u32) -> (u32, u32, u32) {
        let address = self.pci_config_address;
        let slot = slot_number((address >> 11) & 0x1F, (address >> 8) & 7);
        ((address >> 16) & 0xFF, slot, (address & 0xFF) | offset)
    }

    /// x86BiosReadPciDataPort.
    fn read_pci_data_port(&self, data_type: u32, offset: u32) -> u32 {
        let data_type = Self::clamp(data_type, offset);
        let (bus, slot, register) = self.pci_target(offset);
        let mut bytes = [0u8; 4];
        let length = data_type as usize + 1;
        if private_dispatch::kd_pci_config(bus, slot, register, &mut bytes[..length], false) == 0 {
            // (1 << largura em bits) - 1, com o deslocamento de 32 posições
            // mascarado como no x86: 0 para 4 bytes.
            return (1u32 << ((data_type * 8 + 8) & 31)).wrapping_sub(1);
        }
        u32::from_le_bytes(bytes)
    }

    /// x86BiosWritePciDataPort.
    fn write_pci_data_port(&self, data_type: u32, offset: u32, value: u32) {
        let data_type = Self::clamp(data_type, offset);
        let (bus, slot, register) = self.pci_target(offset);
        let mut bytes = value.to_le_bytes();
        private_dispatch::kd_pci_config(bus, slot, register, &mut bytes[..data_type as usize + 1], true);
    }

    /// x86BiosReadCmosPortByte: as portas ímpares fazem a transação, as pares
    /// devolvem o latch do índice.
    fn read_cmos_byte(&self, port: u16) -> u8 {
        if port & 1 != 0 { rtc::cmos_read(self.cmos_address) } else { self.cmos_address }
    }

    fn write_cmos_byte(&mut self, port: u16, value: u8) {
        if port & 1 != 0 {
            rtc::cmos_write(self.cmos_address, value);
        } else {
            self.cmos_address = value;
        }
    }

    /// x86BiosReadCmosPort: byte a byte (o terceiro e o quarto lidos na
    /// ordem porta+3, porta+2).
    fn read_cmos_port(&self, data_type: u32, port: u16) -> u32 {
        let mut value = self.read_cmos_byte(port) as u32;
        if data_type >= 1 {
            value |= (self.read_cmos_byte(port + 1) as u32) << 8;
        }
        if data_type >= 2 {
            let high = (self.read_cmos_byte(port + 3) as u32) << 8;
            value |= (self.read_cmos_byte(port + 2) as u32 | high) << 16;
        }
        value
    }

    fn write_cmos_port(&mut self, data_type: u32, port: u16, value: u32) {
        self.write_cmos_byte(port, value as u8);
        if data_type >= 1 {
            self.write_cmos_byte(port + 1, (value >> 8) as u8);
        }
        if data_type >= 2 {
            self.write_cmos_byte(port + 2, (value >> 16) as u8);
            self.write_cmos_byte(port + 3, (value >> 24) as u8);
        }
    }

    // ---- INT 1Ah: PCI BIOS ----------------------------------------------------

    /// XmExecuteInt1a: `true` se a função foi atendida aqui.
    pub fn pci_bios(&mut self, cpu: &mut Cpu) -> bool {
        if !self.pci_bios_present || (cpu.gpr[EAX] >> 8) & 0xFF != 0xB1 {
            return false;
        }
        match cpu.gpr[EAX] & 0xFF {
            0x01 => {
                cpu.eflags &= !CF;
                cpu.gpr[ECX] = (cpu.gpr[ECX] & !0xFF) | self.pci_buses as u32;
                cpu.gpr[EDX] = PCI_SIGNATURE;
                cpu.gpr[EAX] &= !0xFFFF;
                cpu.gpr[EBX] = (cpu.gpr[EBX] & !0xFFFF) | PCI_BIOS_VERSION;
            }
            0x02 => self.find_device(cpu),
            0x03 => self.find_class_code(cpu),
            0x06 | 0x0E | 0x0F => Self::finish(cpu, Some(FUNCTION_NOT_SUPPORTED)),
            0x08..=0x0A => self.read_config_register(cpu),
            0x0B..=0x0D => self.write_config_register(cpu),
            _ => return false,
        }
        true
    }

    /// CF e AH da resposta: `None` é sucesso (CF=0, AH=0).
    fn finish(cpu: &mut Cpu, error: Option<u8>) {
        match error {
            None => cpu.eflags &= !CF,
            Some(_) => cpu.eflags |= CF,
        }
        cpu.gpr[EAX] = (cpu.gpr[EAX] & !0xFF00) | ((error.unwrap_or(0) as u32) << 8);
    }

    /// BH = barramento, BL = dispositivo << 3 | função.
    fn set_location(cpu: &mut Cpu, bus: u32, device: u32, function: u32) {
        cpu.gpr[EBX] = (cpu.gpr[EBX] & !0xFFFF) | (bus << 8) | (device << 3) | function;
    }

    /// Dword do espaço de configuração; FFFFFFFFh se a rotina não devolve
    /// os quatro bytes.
    fn config_dword(bus: u32, device: u32, function: u32, register: u32) -> u32 {
        let mut bytes = [0u8; 4];
        if private_dispatch::kd_pci_config(bus, slot_number(device, function), register, &mut bytes, false) != 4 {
            return 0xFFFF_FFFF;
        }
        u32::from_le_bytes(bytes)
    }

    /// Percorre barramento, dispositivo e função até a ocorrência `index` de
    /// `matches` (sobre o dword do registrador `register`).
    fn find(&self, register: u32, index: u32, matches: impl Fn(u32) -> bool) -> Option<(u32, u32, u32)> {
        let mut count = 0u32;
        for bus in 0..self.pci_buses as u32 {
            for device in 0..32 {
                for function in 0..8 {
                    if matches(Self::config_dword(bus, device, function, register)) {
                        if count == index {
                            return Some((bus, device, function));
                        }
                        count += 1;
                    }
                }
            }
        }
        None
    }

    /// B102h: DX = fabricante, CX = dispositivo, SI = índice.
    fn find_device(&self, cpu: &mut Cpu) {
        if cpu.gpr[EAX] & 0xFFFF == 0xFFFF {
            return Self::finish(cpu, Some(BAD_VENDOR_ID));
        }
        let (vendor, device_id, index) = (cpu.gpr[EDX] & 0xFFFF, cpu.gpr[ECX] & 0xFFFF, cpu.gpr[ESI] & 0xFFFF);
        match self.find(0, index, |id| id & 0xFFFF == vendor && id >> 16 == device_id) {
            Some((bus, device, function)) => {
                Self::set_location(cpu, bus, device, function);
                Self::finish(cpu, None);
            }
            None => Self::finish(cpu, Some(DEVICE_NOT_FOUND)),
        }
    }

    /// B103h: ECX[23:0] = classe, SI = índice.
    fn find_class_code(&self, cpu: &mut Cpu) {
        let (class_code, index) = (cpu.gpr[ECX] & 0xFF_FFFF, cpu.gpr[ESI] & 0xFFFF);
        match self.find(8, index, |value| value >> 8 == class_code) {
            Some((bus, device, function)) => {
                Self::set_location(cpu, bus, device, function);
                Self::finish(cpu, None);
            }
            None => Self::finish(cpu, Some(DEVICE_NOT_FOUND)),
        }
    }

    /// Barramento, slot, registrador (DI) e largura de B108h-B10Dh.
    fn config_access(cpu: &Cpu, first: u32) -> (u32, u32, u32, usize) {
        let location = cpu.gpr[EBX] & 0xFFFF;
        let (bus, device_function) = (location >> 8, location & 0xFF);
        let width = match (cpu.gpr[EAX] & 0xFF) - first {
            0 => 1,
            1 => 2,
            _ => 4,
        };
        (bus, slot_number(device_function >> 3, device_function & 7), cpu.gpr[EDI] & 0xFFFF, width)
    }

    /// B108h/B109h/B10Ah: o valor sai em CL/CX/ECX.
    fn read_config_register(&self, cpu: &mut Cpu) {
        let (bus, slot, register, width) = Self::config_access(cpu, 0x08);
        let mut bytes = [0u8; 4];
        if private_dispatch::kd_pci_config(bus, slot, register, &mut bytes[..width], false) == 0 {
            return Self::finish(cpu, Some(BAD_REGISTER_NUMBER));
        }
        let mask = super::operations::mask(width as u32);
        cpu.gpr[ECX] = (cpu.gpr[ECX] & !mask) | (u32::from_le_bytes(bytes) & mask);
        Self::finish(cpu, None);
    }

    /// B10Bh/B10Ch/B10Dh: o valor vem de CL/CX/ECX.
    fn write_config_register(&self, cpu: &mut Cpu) {
        let (bus, slot, register, width) = Self::config_access(cpu, 0x0B);
        let mut bytes = cpu.gpr[ECX].to_le_bytes();
        let written = private_dispatch::kd_pci_config(bus, slot, register, &mut bytes[..width], true);
        Self::finish(cpu, if written != 0 { Some(BAD_REGISTER_NUMBER) } else { None });
    }
}
