//! Recursos de hardware do PnP: leitura e escrita das listas do NT, o
//! árbitro e o tradutor da raiz.
//!
//! - `Requirements` é uma IO_RESOURCE_REQUIREMENTS_LIST lida da memória: as
//!   listas alternativas e, em cada uma, os requisitos (um descritor e as
//!   alternativas dele, IO_RESOURCE_ALTERNATIVE), cada opção com o endereço
//!   do IO_RESOURCE_DESCRIPTOR de onde veio; os descritores
//!   CmResourceTypeConfigData só levam a prioridade da lista.
//! - `place_at_root`/`assign` são os árbitros da raiz da árvore (os
//!   IopRoot*Arbiter do NT), para os requisitos que nenhum driver de
//!   barramento acima do nó arbitra (`arbiter.rs` acha quem arbitra cada
//!   tipo): a primeira opção dentro de [Mínimo, Máximo], alinhada, sem
//!   conflito com as faixas exclusivas já atribuídas na raiz
//!   (CmResourceShareShared divide). Portas, memória, IRQs, canais de DMA e
//!   números de barramento; CmResourceTypeDevicePrivate passa direto para a
//!   lista. As faixas que um driver de barramento aloca nos árbitros dele
//!   não passam por aqui.
//! - `translate_at_root` é a tradução da HAL na raiz: portas e memória não
//!   mudam (PC, sem janela de I/O deslocada). Com a HAL sem ACPI (o
//!   barramento PCI interno do boot comum) a IRQ de linha `n` (Level =
//!   Vector = n na lista bruta) vira o vetor do IDT `0x20 + n` com IRQL `n`,
//!   a convenção da HAL do OpenNT para o 8259, afinidade em todos os
//!   processadores; com a raiz ACPI o tradutor da raiz é a identidade (o
//!   IopTranslatorHandlerCm), porque o tradutor de interrupções do acpi.sys
//!   já traduziu.
//! - `CmList` escreve e lê CM_RESOURCE_LIST com um FULL descriptor.

use alloc::vec::Vec;

use core::sync::atomic::{AtomicBool, Ordering};

use crate::ntos::inc::types::{CmPartialResourceDescriptor, CmResourceList, InterfaceType, IoResourceDescriptor, IoResourceRequirementsList, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

/// CM_RESOURCE_TYPE (wdm.h).
pub mod resource_type {
    pub const NULL: u8 = 0;
    pub const PORT: u8 = 1;
    pub const INTERRUPT: u8 = 2;
    pub const MEMORY: u8 = 3;
    pub const DMA: u8 = 4;
    pub const DEVICE_SPECIFIC: u8 = 5;
    pub const BUS_NUMBER: u8 = 6;
    pub const CONFIG_DATA: u8 = 0x80;
    pub const DEVICE_PRIVATE: u8 = 0x81;
}

/// CM_SHARE_DISPOSITION.
pub const SHARE_DEVICE_EXCLUSIVE: u8 = 1;
pub const SHARE_SHARED: u8 = 3;
/// IO_RESOURCE_DESCRIPTOR.Option.
const IO_RESOURCE_ALTERNATIVE: u8 = 0x08;
/// Vetor do IDT da linha 0 do PIC na HAL do OpenNT.
const PIC_VECTOR_BASE: u32 = 0x20;

/// Um recurso atribuído (um CM_PARTIAL_RESOURCE_DESCRIPTOR).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resource {
    pub resource_type: u8,
    pub share: u8,
    pub flags: u16,
    /// Início (porta, memória, IRQ/nível, canal, barramento).
    pub start: u64,
    /// Comprimento (portas, memória, barramento); vetor da interrupção.
    pub length: u32,
    /// Afinidade da interrupção; dados da DevicePrivate nos três u32 baixos.
    pub extra: [u32; 3],
}

/// Uma CM_RESOURCE_LIST de um FULL descriptor.
#[derive(Clone, Debug, Default)]
pub struct CmList {
    pub interface_type: i32,
    pub bus_number: u32,
    pub resources: Vec<Resource>,
}

/// Bytes de uma CM_RESOURCE_LIST com `count` descritores parciais.
fn cm_list_size(count: usize) -> u64 {
    // Count + FULL (InterfaceType, BusNumber) + PARTIAL_LIST (Version,
    // Revision, Count) e os descritores.
    (4 + 8 + 8 + count * CmPartialResourceDescriptor::SIZE as usize) as u64
}

impl CmList {
    /// CM_RESOURCE_LIST em pool (o chamador é o dono).
    pub fn write(&self) -> u64 {
        let address = guest::alloc_bytes(cm_list_size(self.resources.len()));
        // SAFETY: bloco recém-alocado com espaço para todos os descritores.
        let list = unsafe { CmResourceList::at(address) };
        list.count.set(1);
        let full = &list.list[0];
        full.interface_type.set(InterfaceType(self.interface_type));
        full.bus_number.set(self.bus_number);
        let partial = &full.partial_resource_list;
        partial.version.set(1);
        partial.revision.set(1);
        partial.count.set(self.resources.len() as u32);
        // SAFETY: os descritores seguem a lista parcial no mesmo bloco.
        let descriptors = unsafe { CmPartialResourceDescriptor::array_at(partial.partial_descriptors[0].address(), self.resources.len()) };
        for (descriptor, resource) in descriptors.iter().zip(&self.resources) {
            write_partial(descriptor.address(), resource);
        }
        address
    }

    /// Lê o primeiro FULL descriptor de uma CM_RESOURCE_LIST.
    pub fn read(address: u64) -> Option<CmList> {
        if address == 0 {
            return None;
        }
        // SAFETY: CM_RESOURCE_LIST viva do chamador.
        let list = unsafe { CmResourceList::at(address) };
        if list.count.get() == 0 {
            return Some(CmList::default());
        }
        let full = &list.list[0];
        let partial = &full.partial_resource_list;
        let count = partial.count.get() as usize;
        // SAFETY: descritores declarados pela lista.
        let descriptors = unsafe { CmPartialResourceDescriptor::array_at(partial.partial_descriptors[0].address(), count) };
        let resources = descriptors.iter().map(|descriptor| read_partial(descriptor.address())).collect();
        Some(CmList { interface_type: full.interface_type.get().0, bus_number: full.bus_number.get(), resources })
    }
}

/// Grava um recurso num CM_PARTIAL_RESOURCE_DESCRIPTOR.
pub fn write_partial(address: u64, resource: &Resource) {
    // SAFETY: CM_PARTIAL_RESOURCE_DESCRIPTOR do chamador.
    let descriptor = unsafe { CmPartialResourceDescriptor::at(address) };
    descriptor.type_.set(resource.resource_type);
    descriptor.share_disposition.set(resource.share);
    descriptor.flags.set(resource.flags);
    match resource.resource_type {
        resource_type::INTERRUPT => {
            let interrupt = &descriptor.u.interrupt;
            interrupt.level.set(resource.start as u16);
            interrupt.group.set(0);
            interrupt.vector.set(resource.length);
            interrupt.affinity.set(resource.extra[0] as u64 | (resource.extra[1] as u64) << 32);
        }
        resource_type::DMA => {
            descriptor.u.dma.channel.set(resource.start as u32);
            descriptor.u.dma.port.set(resource.length);
            descriptor.u.dma.reserved1.set(0);
        }
        resource_type::BUS_NUMBER => {
            descriptor.u.bus_number.start.set(resource.start as u32);
            descriptor.u.bus_number.length.set(resource.length);
            descriptor.u.bus_number.reserved.set(0);
        }
        resource_type::DEVICE_PRIVATE => {
            for (cell, value) in descriptor.u.device_private.data.iter().zip(resource.extra) {
                cell.set(value);
            }
        }
        _ => {
            descriptor.u.port.start.quad_part.set(resource.start as i64);
            descriptor.u.port.length.set(resource.length);
        }
    }
}

/// Lê um CM_PARTIAL_RESOURCE_DESCRIPTOR.
pub fn read_partial(address: u64) -> Resource {
    // SAFETY: CM_PARTIAL_RESOURCE_DESCRIPTOR vivo do chamador.
    let descriptor = unsafe { CmPartialResourceDescriptor::at(address) };
    let resource_type = descriptor.type_.get();
    let mut resource = Resource { resource_type, share: descriptor.share_disposition.get(), flags: descriptor.flags.get(), start: 0, length: 0, extra: [0; 3] };
    match resource_type {
        resource_type::INTERRUPT => {
            let interrupt = &descriptor.u.interrupt;
            resource.start = interrupt.level.get() as u64;
            resource.length = interrupt.vector.get();
            let affinity = interrupt.affinity.get();
            resource.extra = [affinity as u32, (affinity >> 32) as u32, 0];
        }
        resource_type::DMA => {
            resource.start = descriptor.u.dma.channel.get() as u64;
            resource.length = descriptor.u.dma.port.get();
        }
        resource_type::BUS_NUMBER => {
            resource.start = descriptor.u.bus_number.start.get() as u64;
            resource.length = descriptor.u.bus_number.length.get();
        }
        resource_type::DEVICE_PRIVATE => {
            for (slot, cell) in resource.extra.iter_mut().zip(descriptor.u.device_private.data.iter()) {
                *slot = cell.get();
            }
        }
        _ => {
            resource.start = descriptor.u.port.start.quad_part.get() as u64;
            resource.length = descriptor.u.port.length.get();
        }
    }
    resource
}

/// Uma opção de um requisito (um IO_RESOURCE_DESCRIPTOR).
#[derive(Clone, Copy, Debug)]
pub struct Choice {
    pub resource_type: u8,
    pub share: u8,
    pub flags: u16,
    pub length: u32,
    pub alignment: u64,
    pub minimum: u64,
    pub maximum: u64,
    /// DevicePrivate: os três u32 de dados.
    pub private: [u32; 3],
    pub affinity: u64,
    /// O IO_RESOURCE_DESCRIPTOR de onde a opção veio (0 = opção montada à mão).
    pub address: u64,
}

/// Uma IO_RESOURCE_REQUIREMENTS_LIST: listas alternativas de requisitos,
/// cada requisito com as suas opções na ordem de preferência.
#[derive(Clone, Debug, Default)]
pub struct Requirements {
    pub interface_type: i32,
    pub bus_number: u32,
    pub slot_number: u32,
    pub alternatives: Vec<Vec<Vec<Choice>>>,
}

/// A opção de um IO_RESOURCE_DESCRIPTOR.
pub fn choice_at(address: u64) -> Choice {
    // SAFETY: IO_RESOURCE_DESCRIPTOR vivo do chamador.
    read_choice(unsafe { IoResourceDescriptor::at(address) })
}

fn read_choice(descriptor: &IoResourceDescriptor) -> Choice {
    let resource_type = descriptor.type_.get();
    let mut choice = Choice { resource_type, share: descriptor.share_disposition.get(), flags: descriptor.flags.get(), length: 0, alignment: 1, minimum: 0, maximum: 0, private: [0; 3], affinity: 0, address: descriptor.option.address() };
    let union_address = descriptor.u.port.length.address();
    match resource_type {
        resource_type::PORT | resource_type::MEMORY => {
            let port = &descriptor.u.port;
            choice.length = port.length.get();
            choice.alignment = (port.alignment.get() as u64).max(1);
            choice.minimum = port.minimum_address.quad_part.get() as u64;
            choice.maximum = port.maximum_address.quad_part.get() as u64;
        }
        resource_type::INTERRUPT => {
            let interrupt = &descriptor.u.interrupt;
            choice.minimum = interrupt.minimum_vector.get() as u64;
            choice.maximum = interrupt.maximum_vector.get() as u64;
            choice.affinity = interrupt.targeted_processors.get();
        }
        resource_type::DMA => {
            choice.minimum = descriptor.u.dma.minimum_channel.get() as u64;
            choice.maximum = descriptor.u.dma.maximum_channel.get() as u64;
        }
        resource_type::BUS_NUMBER => {
            // BusNumber: Length, MinBusNumber, MaxBusNumber.
            let words = guest::read_bytes(union_address, 12);
            choice.length = u32::from_le_bytes([words[0], words[1], words[2], words[3]]);
            choice.minimum = u32::from_le_bytes([words[4], words[5], words[6], words[7]]) as u64;
            choice.maximum = u32::from_le_bytes([words[8], words[9], words[10], words[11]]) as u64;
        }
        resource_type::DEVICE_PRIVATE => {
            let words = guest::read_bytes(union_address, 12);
            for (index, slot) in choice.private.iter_mut().enumerate() {
                *slot = u32::from_le_bytes([words[index * 4], words[index * 4 + 1], words[index * 4 + 2], words[index * 4 + 3]]);
            }
        }
        _ => {}
    }
    choice
}

impl Requirements {
    pub fn read(address: u64) -> Option<Requirements> {
        if address == 0 {
            return None;
        }
        // SAFETY: IO_RESOURCE_REQUIREMENTS_LIST viva do chamador.
        let header = unsafe { IoResourceRequirementsList::at(address) };
        let mut requirements = Requirements { interface_type: header.interface_type.get().0, bus_number: header.bus_number.get(), slot_number: header.slot_number.get(), alternatives: Vec::new() };
        let mut list = header.list[0].address();
        for _ in 0..header.alternative_lists.get() {
            // SAFETY: lista alternativa dentro do bloco declarado (ListSize).
            let alternative = unsafe { crate::ntos::inc::types::IoResourceList::at(list) };
            let count = alternative.count.get() as usize;
            // SAFETY: os descritores seguem o cabeçalho da lista.
            let descriptors = unsafe { IoResourceDescriptor::array_at(alternative.descriptors[0].address(), count) };
            let mut needs: Vec<Vec<Choice>> = Vec::new();
            for descriptor in descriptors {
                let choice = read_choice(descriptor);
                if choice.resource_type == resource_type::CONFIG_DATA || choice.resource_type == resource_type::NULL {
                    continue;
                }
                match needs.last_mut() {
                    Some(last) if descriptor.option.get() & IO_RESOURCE_ALTERNATIVE != 0 => last.push(choice),
                    _ => needs.push(alloc::vec![choice]),
                }
            }
            requirements.alternatives.push(needs);
            list = alternative.descriptors[0].address() + count as u64 * IoResourceDescriptor::SIZE;
        }
        Some(requirements)
    }
}

/// Faixas atribuídas pelos árbitros da raiz: (PDO dono, recurso).
static ASSIGNED: SpinLock<Vec<(u64, Resource)>> = SpinLock::new(Vec::new());

/// A faixa [start, start+length) colide com uma atribuição exclusiva de
/// outro nó na raiz ou com uma escolha pendente do mesmo pedido.
fn conflicts(owner: u64, resource_type: u8, start: u64, length: u64, share: u8, pending: &[Resource]) -> bool {
    let overlaps = |other: &Resource| {
        if other.resource_type != resource_type {
            return false;
        }
        let other_length = match resource_type {
            resource_type::INTERRUPT | resource_type::DMA => 1,
            _ => other.length.max(1) as u64,
        };
        start < other.start + other_length && other.start < start + length && !(share == SHARE_SHARED && other.share == SHARE_SHARED)
    };
    ASSIGNED.lock().iter().any(|(holder, other)| *holder != owner && overlaps(other)) || pending.iter().any(overlaps)
}

/// A primeira posição livre de uma opção nos árbitros da raiz (None = não
/// cabe); `pending` são as escolhas do mesmo pedido ainda não registradas.
pub fn place_at_root(owner: u64, choice: &Choice, pending: &[Resource]) -> Option<Resource> {
    let share = if choice.share == 0 { SHARE_DEVICE_EXCLUSIVE } else { choice.share };
    let make = |start: u64, length: u32, extra: [u32; 3]| Resource { resource_type: choice.resource_type, share, flags: choice.flags, start, length, extra };
    match choice.resource_type {
        resource_type::PORT | resource_type::MEMORY | resource_type::BUS_NUMBER => {
            let length = choice.length as u64;
            if length == 0 {
                return None;
            }
            let alignment = choice.alignment.max(1);
            let mut start = choice.minimum.div_ceil(alignment) * alignment;
            while start.checked_add(length - 1).is_some_and(|end| end <= choice.maximum) {
                if !conflicts(owner, choice.resource_type, start, length, share, pending) {
                    return Some(make(start, choice.length, [0; 3]));
                }
                start += alignment;
            }
            None
        }
        resource_type::INTERRUPT | resource_type::DMA => {
            (choice.minimum..=choice.maximum).find(|&value| !conflicts(owner, choice.resource_type, value, 1, share, pending)).map(|value| {
                // Lista bruta: Level = Vector = a linha.
                let affinity = if choice.affinity == 0 { u64::MAX } else { choice.affinity };
                make(value, value as u32, [affinity as u32, (affinity >> 32) as u32, 0])
            })
        }
        resource_type::DEVICE_PRIVATE => Some(make(0, 0, choice.private)),
        _ => None,
    }
}

/// Arbitra na raiz todos os requisitos de `owner`: a lista bruta atribuída,
/// ou None se nenhuma lista alternativa cabe. As faixas ficam registradas
/// para o nó.
pub fn assign(owner: u64, requirements: &Requirements) -> Option<CmList> {
    for alternative in &requirements.alternatives {
        let mut chosen: Vec<Resource> = Vec::new();
        let fits = alternative.iter().all(|options| match options.iter().find_map(|choice| place_at_root(owner, choice, &chosen)) {
            Some(resource) => {
                chosen.push(resource);
                true
            }
            None => false,
        });
        if fits {
            let list = CmList { interface_type: requirements.interface_type, bus_number: requirements.bus_number, resources: chosen };
            release(owner);
            reserve(owner, &list);
            return Some(list);
        }
    }
    None
}

/// Registra recursos já em uso (configuração de boot de um nó iniciado
/// pelo próprio kernel) para os árbitros.
pub fn reserve(owner: u64, list: &CmList) {
    ASSIGNED.lock().extend(list.resources.iter().filter(|resource| resource.resource_type != resource_type::DEVICE_PRIVATE).map(|&resource| (owner, resource)));
}

/// Devolve as faixas de um nó.
pub fn release(owner: u64) {
    ASSIGNED.lock().retain(|(holder, _)| *holder != owner);
}

/// Linha de interrupção bruta -> (vetor do IDT, IRQL) na HAL do OpenNT.
pub fn translate_interrupt(line: u32) -> (u32, u32) {
    (PIC_VECTOR_BASE + line, line)
}

/// A raiz traduz as linhas de interrupção (a HAL sem ACPI); desligado com a
/// raiz ACPI, em que o tradutor da raiz é a identidade.
static ROOT_LINE_TRANSLATION: AtomicBool = AtomicBool::new(true);

/// Liga ou desliga a tradução de linhas na raiz (a HAL da árvore montada).
pub fn set_root_line_translation(enabled: bool) {
    ROOT_LINE_TRANSLATION.store(enabled, Ordering::Release);
}

/// A tradução da raiz de um recurso bruto que nenhum tradutor de driver
/// completou: as linhas de interrupção na HAL sem ACPI, o resto igual.
pub fn translate_at_root(resource: &Resource) -> Resource {
    if resource.resource_type != resource_type::INTERRUPT || !ROOT_LINE_TRANSLATION.load(Ordering::Acquire) {
        return *resource;
    }
    let (vector, level) = translate_interrupt(resource.length);
    Resource { start: level as u64, length: vector, ..*resource }
}

/// Tradução de uma lista bruta inteira na raiz.
pub fn translate(raw: &CmList) -> CmList {
    CmList { interface_type: raw.interface_type, bus_number: raw.bus_number, resources: raw.resources.iter().map(translate_at_root).collect() }
}
