//! HaliQuerySystemInformation — a rotina que a HAL grava no slot
//! HalQuerySystemInformation da HalDispatchTable pública.
//!
//! Como no ntoskrnl 19041, a rotina zera o *ReturnedLength e despacha pela
//! classe (HAL_QUERY_INFORMATION_CLASS). As classes atendidas são as que os
//! drivers desta plataforma consultam:
//! - HalDisplayBiosInformation (9), do BasicDisplay.sys: o
//!   HalpGetDisplayBiosInformation devolve HalDisplayEmulatedBios (1) com o
//!   BIOS de vídeo inicializado (`hal::x86bios`) e HalDisplayNoBios (2) sem
//!   ele; o valor de 4 bytes é copiado até o tamanho do buffer, que também
//!   vai para o *ReturnedLength, e o status é STATUS_SUCCESS;
//! - HalQueryAMLIIllegalIOPortAddresses (0x10): a BadIOAddrList da HAL, 19
//!   entradas de 24 bytes { início, tamanho, gatilho de versão, tratador }
//!   (0x1C8 bytes, com a entrada nula do fim); buffer menor =
//!   STATUS_INFO_LENGTH_MISMATCH com o tamanho em *ReturnedLength. As portas de
//!   configuração PCI (0xCF8, 8 portas) têm o tratador
//!   HaliHandlePCIConfigSpaceAccess, que o interpretador AML do acpi.sys
//!   chama em vez de tocar as portas;
//! - HalSecondaryInterruptInformation (0x1C): os serviços de controladores
//!   secundários só existem com uma tabela de GSIVs secundárias, que um PC
//!   não tem: 0x38 bytes zerados e STATUS_UNSUCCESSFUL (buffer menor que
//!   0x38 = STATUS_INFO_LENGTH_MISMATCH, sem tamanho);
//! - HalQueryDebuggerInformation (0x21): *ReturnedLength = 4 e, sem
//!   dispositivo de depuração do KD, STATUS_UNSUCCESSFUL;
//! - HalQueryPerDeviceMsiLimitInformation (0x32): o USHORT
//!   HalpInterruptPerDeviceMsiLimit (0x800), com 2 em *ReturnedLength.
//!
//! As demais classes esta plataforma não oferece: STATUS_NOT_SUPPORTED, como
//! o stub dos outros slots.

use crate::hal::amd64::routine_stubs::{self, Routine};
use crate::hal::{acpi_pm, x86bios};
use crate::ntos::init::exports::Call;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::{KernelError, SpinLock};

/// HAL_QUERY_INFORMATION_CLASS::HalDisplayBiosInformation.
pub const HAL_DISPLAY_BIOS_INFORMATION: u32 = 9;

/// Classes de HAL_QUERY_INFORMATION_CLASS tratadas.
pub mod class {
    pub const DISPLAY_BIOS_INFORMATION: u32 = super::HAL_DISPLAY_BIOS_INFORMATION;
    pub const AMLI_ILLEGAL_IO_PORT_ADDRESSES: u32 = 0x10;
    pub const SECONDARY_INTERRUPT_INFORMATION: u32 = 0x1C;
    pub const DEBUGGER_INFORMATION: u32 = 0x21;
    pub const PER_DEVICE_MSI_LIMIT: u32 = 0x32;
}

const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;

/// HalpInterruptPerDeviceMsiLimit (valor inicial da `.data`).
const PER_DEVICE_MSI_LIMIT: u16 = 0x800;

/// BadIOAddrList da `.data` do ntoskrnl 19041: (início, tamanho, gatilho de
/// versão); a entrada 0xCF8 tem o tratador de configuração PCI.
const BAD_IO_ADDRESSES: [(u32, u32, u32); 18] = [
    (0x00, 0x10, 1),
    (0x20, 0x02, 0),
    (0x40, 0x04, 1),
    (0x48, 0x04, 1),
    (0x70, 0x02, 1),
    (0x74, 0x03, 1),
    (0x81, 0x03, 1),
    (0x87, 0x01, 1),
    (0x89, 0x01, 1),
    (0x8A, 0x02, 1),
    (0x8F, 0x01, 1),
    (0x90, 0x02, 1),
    (0x93, 0x02, 1),
    (0x96, 0x02, 1),
    (0xA0, 0x02, 0),
    (0xC0, 0x20, 1),
    (0x4D0, 0x02, 0),
    (0xCF8, 0x08, 1),
];
/// Bytes da lista: as 18 entradas e a nula.
pub const BAD_IO_LIST_SIZE: u32 = 19 * 24;

/// As rotinas por ponteiro deste módulo.
pub const ROUTINES: &[Routine] = &[
    Routine { name: "HaliQuerySystemInformation", handler: query_system_information_routine },
    Routine { name: "HaliHandlePCIConfigSpaceAccess", handler: handle_pci_config_space_access_routine },
];

/// O corpo do slot +0x08 do HalDispatchTable.
pub fn query_system_information_address() -> Result<u64, KernelError> {
    routine_stubs::address("HaliQuerySystemInformation")
}

/// HaliQuerySystemInformation(InformationClass, BufferSize, Buffer,
/// ReturnedLength) -> NTSTATUS.
pub fn query(information_class: u32, buffer_size: u32, buffer: u64, returned_length: u64) -> Result<u32, KernelError> {
    let set_length = |length: u32| {
        if returned_length != 0 {
            guest::write32(returned_length, length);
        }
    };
    set_length(0);
    match information_class {
        class::DISPLAY_BIOS_INFORMATION => {
            let value = x86bios::display_bios_information().to_le_bytes();
            let length = buffer_size.min(value.len() as u32);
            set_length(length);
            guest::write_bytes(buffer, &value[..length as usize]);
            Ok(0)
        }
        class::AMLI_ILLEGAL_IO_PORT_ADDRESSES => {
            if buffer_size < BAD_IO_LIST_SIZE {
                set_length(BAD_IO_LIST_SIZE);
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            let handler = routine_stubs::address("HaliHandlePCIConfigSpaceAccess")?;
            let mut bytes = alloc::vec::Vec::with_capacity(BAD_IO_LIST_SIZE as usize);
            for &(start, size, trigger) in BAD_IO_ADDRESSES.iter() {
                bytes.extend_from_slice(&start.to_le_bytes());
                bytes.extend_from_slice(&size.to_le_bytes());
                bytes.extend_from_slice(&trigger.to_le_bytes());
                bytes.extend_from_slice(&[0; 4]);
                bytes.extend_from_slice(&if start == 0xCF8 { handler } else { 0 }.to_le_bytes());
            }
            bytes.resize(BAD_IO_LIST_SIZE as usize, 0);
            guest::write_bytes(buffer, &bytes);
            set_length(BAD_IO_LIST_SIZE);
            Ok(0)
        }
        class::SECONDARY_INTERRUPT_INFORMATION => {
            if buffer_size < 0x38 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            guest::write_bytes(buffer, &[0; 0x38]);
            set_length(0x38);
            Ok(STATUS_UNSUCCESSFUL)
        }
        class::DEBUGGER_INFORMATION => {
            set_length(4);
            Ok(STATUS_UNSUCCESSFUL)
        }
        class::PER_DEVICE_MSI_LIMIT => {
            if buffer_size < 2 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            guest::write16(buffer, PER_DEVICE_MSI_LIMIT);
            set_length(2);
            Ok(0)
        }
        _ => Ok(STATUS_NOT_SUPPORTED),
    }
}

/// O endereço que o AML escreveu em 0xCF8 (HaliHandlePCIConfigSpaceAccess).
static LATCHED_ADDRESS: SpinLock<Option<u32>> = SpinLock::new(None);

/// HaliHandlePCIConfigSpaceAccess(Read, Port, Length, Buffer): uma escrita
/// em 0xCF8 só guarda o endereço; 0xCFC-0xCFF com endereço guardado vão ao
/// espaço de configuração (barramento, slot, registrador do endereço mais o
/// deslocamento da porta) pela HAL. Outra porta, ou nenhum endereço
/// guardado: STATUS_UNSUCCESSFUL.
pub fn handle_pci_config_space_access(read: bool, port: u32, length: u32, buffer: u64) -> Result<u32, KernelError> {
    if port == 0xCF8 {
        *LATCHED_ADDRESS.lock() = Some(guest::read32(buffer));
        return Ok(0);
    }
    let Some(address) = *LATCHED_ADDRESS.lock() else { return Ok(STATUS_UNSUCCESSFUL) };
    if !(0xCFC..=0xCFF).contains(&port) {
        return Ok(STATUS_UNSUCCESSFUL);
    }
    let offset = (address & 0xFC) + (port - 0xCFC);
    let slot = (((address >> 8) & 0xF8) | (address & 0x700)) >> 3;
    let bus = (address >> 16) & 0xFF;
    acpi_pm::pci_interface_config(bus, slot, buffer, offset, length, !read)?;
    Ok(0)
}

fn query_system_information_routine(call: &Call) -> Result<u64, KernelError> {
    Ok(query(call.arg(1) as u32, call.arg(2) as u32, call.arg(3), call.arg(4))? as u64)
}

fn handle_pci_config_space_access_routine(call: &Call) -> Result<u64, KernelError> {
    Ok(handle_pci_config_space_access(call.arg(1) & 0xFF != 0, call.arg(2) as u32, call.arg(3) as u32, call.arg(4))? as u64)
}
