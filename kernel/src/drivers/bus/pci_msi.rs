//! Interrupções por mensagem das funções PCI (o MSI e o MSI-X do pci.sys).
//!
//! - As capacidades: a lista do espaço de configuração (Status bit 4 e o
//!   ponteiro em 0x34) com o MSI (id 05h: Message Control com o Multiple
//!   Message Capable e o bit de 64 bits) e o MSI-X (id 11h: o tamanho da
//!   tabela e o BIR/offset da tabela). O MSI-X tem preferência, como no
//!   PciGetInterruptRequirement.
//! - Quantas mensagens pedir (o PciGetMessageCount): nenhuma sem o
//!   `MSISupported` diferente de zero na chave de hardware da instância
//!   (`Device Parameters\Interrupt Management\MessageSignaledInterruptProperties`,
//!   que o INF grava); senão o número da capacidade, limitado pelo
//!   `MessageNumberLimit` da mesma chave e, no MSI, a 16.
//! - Os requisitos (o PciBuildRequirementsList com o
//!   PciPopulateMsiRequirements): cada mensagem é um IO_RESOURCE_DESCRIPTOR
//!   de interrupção exclusivo com CM_RESOURCE_INTERRUPT_LATCHED |
//!   CM_RESOURCE_INTERRUPT_MESSAGE e Mínimo = Máximo =
//!   CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN. O MSI-X de várias mensagens pede
//!   um descritor por mensagem (Option 0) e nenhuma linha; o MSI de n
//!   mensagens pede um descritor com Mínimo = token - (n - 1), uma mensagem
//!   só como alternativa (IO_RESOURCE_ALTERNATIVE) e a linha como mais uma
//!   alternativa; com uma mensagem, ela é a preferida e a linha a
//!   alternativa.
//! - O START (o PciProcessStartResources com o PciProgramMsiXInterrupt e o
//!   PciProgramMsiInterrupt): as mensagens atribuídas vêm dos dados de
//!   conexão que o PnP manager gravou no PDO, com o endereço e o dado pelo
//!   HalGetMessageRoutingInfo (`pnp::message_interrupts`); o MSI-X recebe
//!   cada entrada da tabela (endereço, dado, desmascarada) e as demais
//!   ficam mascaradas, o MSI recebe o endereço, o dado e o Multiple Message
//!   Enable; a capacidade é ligada e a interrupção de linha desligada
//!   (Interrupt Disable do registrador de comando).

use alloc::vec::Vec;

use super::pci::PciFunction;
use crate::hal::pci_config;
use crate::ntos::io::pnp::{devnode, install, message_interrupts};

const CAPABILITY_MSI: u32 = 0x05;
const CAPABILITY_MSIX: u32 = 0x11;
/// Status: Capabilities List.
const STATUS_CAPABILITIES: u32 = 1 << 4;
/// Command: Interrupt Disable.
const COMMAND_INTERRUPT_DISABLE: u32 = 1 << 10;
/// MSI-X Message Control: MSI-X Enable e Function Mask.
const MSIX_ENABLE: u32 = 1 << 15;
const MSIX_FUNCTION_MASK: u32 = 1 << 14;
/// Entrada da tabela MSI-X: endereço baixo, alto, dado e Vector Control.
const MSIX_ENTRY_SIZE: u64 = 16;
const MSIX_VECTOR_MASKED: u32 = 1;
/// O MSI é limitado a 16 mensagens (PciGetMessageCount).
const MSI_MESSAGE_LIMIT: u32 = 16;

/// A capacidade de mensagens de uma função.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    /// MSI: offset, mensagens que a função suporta, endereço de 64 bits.
    Msi { offset: u32, messages: u32, wide: bool },
    /// MSI-X: offset, tamanho da tabela, BIR e offset da tabela.
    MsiX { offset: u32, table_size: u32, table_bar: u32, table_offset: u32 },
}

fn config(function: &PciFunction, offset: u32, width: u32) -> u32 {
    pci_config::read(function.bus, function.device, function.function, offset, width).unwrap_or(0)
}

fn write_config(function: &PciFunction, offset: u32, width: u32, value: u32) {
    let _ = pci_config::write(function.bus, function.device, function.function, offset, width, value);
}

/// As capacidades (id, offset) da lista do espaço de configuração.
fn capabilities(function: &PciFunction) -> Vec<(u32, u32)> {
    let mut found = Vec::new();
    if config(function, 0x06, 2) & STATUS_CAPABILITIES == 0 {
        return found;
    }
    let mut pointer = config(function, 0x34, 1) & 0xFC;
    while pointer >= 0x40 && found.len() < 48 {
        found.push((config(function, pointer, 1), pointer));
        pointer = config(function, pointer + 1, 1) & 0xFC;
    }
    found
}

/// A capacidade de mensagens da função (o MSI-X primeiro).
pub fn capability(function: &PciFunction) -> Option<Capability> {
    let list = capabilities(function);
    if let Some(&(_, offset)) = list.iter().find(|(id, _)| *id == CAPABILITY_MSIX) {
        let control = config(function, offset + 2, 2);
        let table = config(function, offset + 4, 4);
        return Some(Capability::MsiX { offset, table_size: (control & 0x7FF) + 1, table_bar: table & 7, table_offset: table & !7 });
    }
    let &(_, offset) = list.iter().find(|(id, _)| *id == CAPABILITY_MSI)?;
    let control = config(function, offset + 2, 2);
    Some(Capability::Msi { offset, messages: 1 << ((control >> 1) & 7), wide: control & (1 << 7) != 0 })
}

/// A chave das propriedades de MSI da instância do PDO.
fn properties_key(pdo: u64) -> Option<alloc::string::String> {
    let node = devnode::get(pdo).filter(|node| !node.instance_path.is_empty())?;
    Some(alloc::format!("{}\\Enum\\{}\\Device Parameters\\Interrupt Management\\MessageSignaledInterruptProperties", install::CONTROL_SET, node.instance_path))
}

/// Quantas mensagens a função pede (0 = só a linha).
pub fn message_count(function: &PciFunction, pdo: u64) -> u32 {
    let Some(capability) = capability(function) else { return 0 };
    let Some(key) = properties_key(pdo) else { return 0 };
    if install::read_dword(&key, "MSISupported").unwrap_or(0) == 0 {
        return 0;
    }
    let mut count = match capability {
        Capability::Msi { messages, .. } => messages,
        Capability::MsiX { table_size, .. } => table_size,
    };
    if let Some(limit) = install::read_dword(&key, "MessageNumberLimit") {
        count = count.min(limit);
    }
    if matches!(capability, Capability::Msi { .. }) {
        count = count.min(MSI_MESSAGE_LIMIT);
    }
    count
}

/// Um descritor de interrupção dos requisitos: (Option, Mínimo, Máximo).
pub type Descriptor = (u8, u32, u32);

/// IO_RESOURCE_PREFERRED e IO_RESOURCE_ALTERNATIVE.
const PREFERRED: u8 = 1;
const ALTERNATIVE: u8 = 8;

/// Os descritores de mensagem dos requisitos e o Option da linha (None =
/// sem linha), ou None se a função não pede mensagens.
pub fn requirement_descriptors(function: &PciFunction, pdo: u64, has_line: bool) -> Option<(Vec<Descriptor>, Option<u8>)> {
    let count = message_count(function, pdo);
    if count == 0 {
        return None;
    }
    let token = message_interrupts::MESSAGE_TOKEN;
    let single_option = if has_line { PREFERRED } else { 0 };
    match capability(function)? {
        Capability::MsiX { .. } if count > 1 => Some(((0..count).map(|_| (0, token, token)).collect(), None)),
        Capability::MsiX { .. } => Some((alloc::vec![(single_option, token, token)], Some(ALTERNATIVE))),
        Capability::Msi { .. } if count > 1 => Some((alloc::vec![(PREFERRED, token - (count - 1), token), (ALTERNATIVE, token, token)], Some(ALTERNATIVE))),
        Capability::Msi { .. } => Some((alloc::vec![(single_option, token, token)], Some(ALTERNATIVE))),
    }
}

/// Endereço físico de um BAR de memória como está programado.
fn bar_address(function: &PciFunction, index: u32) -> u64 {
    let low = config(function, 0x10 + index * 4, 4);
    let wide = low & 1 == 0 && (low >> 1) & 3 == 2;
    let high = if wide { config(function, 0x14 + index * 4, 4) as u64 } else { 0 };
    (low & 0xFFFF_FFF0) as u64 | high << 32
}

/// Programa as mensagens atribuídas e liga a capacidade. Devolve quantas
/// mensagens foram programadas (0 = a função segue com a linha).
pub fn program(function: &PciFunction, pdo: u64) -> usize {
    let messages = message_interrupts::connection_messages(pdo);
    if messages.is_empty() {
        return 0;
    }
    match capability(function) {
        Some(Capability::MsiX { offset, table_size, table_bar, table_offset }) => {
            let table = bar_address(function, table_bar) + table_offset as u64;
            let length = table_size as u64 * MSIX_ENTRY_SIZE;
            let mapped = crate::ntos::mm::io_space::map(table, length);
            if mapped == 0 {
                return 0;
            }
            // Função mascarada enquanto a tabela muda; a capacidade ligada.
            let control = config(function, offset + 2, 2);
            write_config(function, offset + 2, 2, control | MSIX_ENABLE | MSIX_FUNCTION_MASK);
            for index in 0..table_size as u64 {
                let entry = mapped + index * MSIX_ENTRY_SIZE;
                match messages.get(index as usize) {
                    Some(message) => {
                        crate::hal::volatile::write32(entry + 12, MSIX_VECTOR_MASKED);
                        crate::hal::volatile::write32(entry, message.address as u32);
                        crate::hal::volatile::write32(entry + 4, (message.address >> 32) as u32);
                        crate::hal::volatile::write32(entry + 8, message.data);
                        crate::hal::volatile::write32(entry + 12, 0);
                    }
                    None => crate::hal::volatile::write32(entry + 12, MSIX_VECTOR_MASKED),
                }
            }
            crate::ntos::mm::io_space::unmap(mapped, length);
            write_config(function, 4, 2, config(function, 4, 2) | COMMAND_INTERRUPT_DISABLE);
            write_config(function, offset + 2, 2, (control | MSIX_ENABLE) & !MSIX_FUNCTION_MASK);
        }
        Some(Capability::Msi { offset, wide, .. }) => {
            let first = messages[0];
            // Multiple Message Enable: log2 das mensagens atribuídas.
            let enabled = (messages.len() as u32).next_power_of_two().trailing_zeros();
            write_config(function, offset + 4, 4, first.address as u32);
            if wide {
                write_config(function, offset + 8, 4, (first.address >> 32) as u32);
                write_config(function, offset + 0xC, 2, first.data);
            } else {
                write_config(function, offset + 8, 2, first.data);
            }
            write_config(function, 4, 2, config(function, 4, 2) | COMMAND_INTERRUPT_DISABLE);
            let control = config(function, offset + 2, 2);
            write_config(function, offset + 2, 2, (control & !(7 << 4)) | enabled << 4 | 1);
        }
        None => return 0,
    }
    messages.len()
}
