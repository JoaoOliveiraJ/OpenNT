//! Interrupções por mensagem (MSI e MSI-X) no PnP manager: arbitragem,
//! tradução e os dados de conexão do PDO.
//!
//! O barramento pede as mensagens nos requisitos com descritores de
//! interrupção com CM_RESOURCE_INTERRUPT_MESSAGE (e LATCHED) e a faixa de
//! vetores [CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN - (n - 1),
//! CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN]: o MSI de n mensagens num descritor
//! só, o MSI-X num descritor por mensagem (o PciPopulateMsiRequirements do
//! pci.sys). As mensagens não disputam as linhas do controlador:
//! - a arbitragem dá a cada descritor o recurso bruto da mensagem
//!   (u.MessageInterrupt.Raw: Group 0, MessageCount n, Vector = o token,
//!   a afinidade pedida ou todos os processadores);
//! - a tradução pede à HAL um bloco de n vetores do IDT
//!   (`hal::message_interrupts`) e escreve o recurso traduzido
//!   (u.MessageInterrupt.Translated: Level = o IRQL do vetor, Group 0, o
//!   primeiro vetor e a afinidade do processador que recebe as mensagens);
//! - os dados de conexão do PDO (INTERRUPT_CONNECTION_DATA_PKEY: um ULONG
//!   de contagem e um INTERRUPT_VECTOR_DATA por mensagem) passam a descrever
//!   cada mensagem como no NT: InterruptTypeMessageRequest, com o vetor, o
//!   IRQL, o disparo por borda (Latched, InterruptRisingEdge), o destino, o
//!   modo de destino do APIC e, no IntRemapInfo.u.Msi, o endereço e o dado
//!   que a HAL compôs para a mensagem (o HalpPopulateMsiMessages). Quem
//!   programa o dispositivo (o START do barramento) e quem conecta
//!   (IoConnectInterruptEx MESSAGE_BASED) leem essas entradas e pedem o
//!   endereço e o dado ao HalGetMessageRoutingInfo, como o pci.sys e o
//!   IopConnectMessageBasedInterrupt.
//! Os vetores de um nó voltam à HAL quando os recursos dele são liberados.

use alloc::vec::Vec;

use super::resources::{CmList, Resource};
use crate::hal::message_interrupts as hal;
use crate::ntos::inc::types::{HalApicDestinationMode, InterruptConnectionType, InterruptVectorData, KinterruptMode, KinterruptPolarity, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

/// CM_RESOURCE_INTERRUPT_LATCHED e CM_RESOURCE_INTERRUPT_MESSAGE.
pub const CM_RESOURCE_INTERRUPT_LATCHED: u16 = 1;
pub const CM_RESOURCE_INTERRUPT_MESSAGE: u16 = 2;
/// CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN ((ULONG)-2).
pub const MESSAGE_TOKEN: u32 = 0xFFFF_FFFE;
/// INTERRUPT_CONNECTION_DATA_PKEY {f0e20f09-d97a-49a9-8046-bb6e22e6bb2e}, 2.
pub const INTERRUPT_CONNECTION_DATA_PKEY: [u8; 16] = [0x09, 0x0F, 0xE2, 0xF0, 0x7A, 0xD9, 0xA9, 0x49, 0x80, 0x46, 0xBB, 0x6E, 0x22, 0xE6, 0xBB, 0x2E];
pub const INTERRUPT_CONNECTION_DATA_PID: u32 = 2;
/// DEVPROP_TYPE_BINARY (DEVPROP_TYPE_BYTE | DEVPROP_TYPEMOD_ARRAY).
const DEVPROP_TYPE_BINARY: u32 = 0x1003;
/// Cabeçalho do INTERRUPT_CONNECTION_DATA (Count e o alinhamento dos
/// INTERRUPT_VECTOR_DATA).
const CONNECTION_DATA_HEADER: usize = 8;
const ENTRY_SIZE: usize = InterruptVectorData::SIZE as usize;
/// O pedido e a saída do HalGetMessageRoutingInfo, como o
/// IopConnectMessageBasedInterrupt os monta: o pedido (tipo 0) com o vetor
/// (+8), o GROUP_AFFINITY do destino (+0x10), o modo de destino (+0x20) e o
/// IntRemapInfo da entrada (+0x24); a saída com um ULONG e o
/// INTERRUPT_VECTOR_DATA resultante em +8.
const ROUTING_REQUEST_SIZE: u64 = 0x38;
const ROUTING_OUTPUT_SIZE: u64 = 8 + InterruptVectorData::SIZE;

/// Um recurso de interrupção por mensagem (bruto ou traduzido).
pub fn is_message(resource: &Resource) -> bool {
    resource.resource_type == super::resources::resource_type::INTERRUPT && resource.flags & CM_RESOURCE_INTERRUPT_MESSAGE != 0
}

/// Quantas mensagens um descritor de requisito pede (a faixa até o token).
pub fn requested_messages(minimum: u64, maximum: u64) -> u32 {
    if maximum != MESSAGE_TOKEN as u64 || minimum > maximum {
        return 1;
    }
    (maximum - minimum + 1).min(32) as u32
}

/// O recurso bruto de um descritor de mensagem: Group 0 (no lugar do
/// Level), o token como Vector, MessageCount (extra[2]) e a afinidade.
pub fn place(share: u8, flags: u16, minimum: u64, maximum: u64, affinity: u64) -> Resource {
    let affinity = if affinity == 0 { u64::MAX } else { affinity };
    Resource { resource_type: super::resources::resource_type::INTERRUPT, share, flags, start: 0, length: MESSAGE_TOKEN, extra: [affinity as u32, (affinity >> 32) as u32, requested_messages(minimum, maximum)] }
}

/// Blocos de vetores da HAL de cada nó: (PDO, primeiro vetor).
static VECTORS: SpinLock<Vec<(u64, u32)>> = SpinLock::new(Vec::new());

/// Uma mensagem: vetor, IRQL, processador de destino, endereço e dado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message {
    pub vector: u32,
    pub irql: u8,
    pub processor: u32,
    pub address: u64,
    pub data: u32,
}

/// Traduz os recursos de mensagem de `raw` que os árbitros da raiz deram
/// (`place`, com o token como Vector) em `translated` (mesma posição) com
/// vetores da HAL e grava os dados de conexão do PDO. Uma mensagem que o
/// árbitro de IRQ de um driver atribuiu (o do acpi.sys, que grava ele mesmo
/// os dados de conexão) fica como o árbitro e o tradutor dele a deixaram.
/// Devolve as mensagens na ordem da lista (o MSI de n mensagens dá n
/// entradas).
pub fn translate(owner: u64, raw: &CmList, translated: &mut CmList) -> Vec<Message> {
    release(owner);
    let mut messages = Vec::new();
    let (processor, apic_id) = hal::target_processor();
    for (index, resource) in raw.resources.iter().enumerate() {
        if !is_message(resource) || resource.length != MESSAGE_TOKEN {
            continue;
        }
        let count = resource.extra[2].max(1);
        let Some(base) = hal::allocate_vectors(count) else {
            debug_print!("[pnp] sem vetores de mensagem para {} mensagem(ns)", count);
            continue;
        };
        VECTORS.lock().push((owner, base));
        let irql = hal::vector_irql(base);
        let affinity = 1u64 << processor;
        translated.resources[index] = Resource { start: irql as u64, length: base, extra: [affinity as u32, (affinity >> 32) as u32, 0], ..*resource };
        for message in 0..count {
            let vector = base + message;
            messages.push(Message { vector, irql, processor, address: hal::message_address(apic_id), data: hal::message_data(vector) });
        }
    }
    if !messages.is_empty() {
        crate::ntos::io::device_property::store_device_property(owner, INTERRUPT_CONNECTION_DATA_PKEY, INTERRUPT_CONNECTION_DATA_PID, DEVPROP_TYPE_BINARY, &connection_data(&messages));
    }
    messages
}

/// INTERRUPT_CONNECTION_DATA com uma entrada InterruptTypeMessageRequest por
/// mensagem, o endereço e o dado no IntRemapInfo.u.Msi.
pub fn connection_data(messages: &[Message]) -> Vec<u8> {
    let size = CONNECTION_DATA_HEADER + messages.len() * ENTRY_SIZE;
    let block = guest::alloc_bytes(size as u64);
    guest::write_bytes(block, &(messages.len() as u32).to_le_bytes());
    for (index, message) in messages.iter().enumerate() {
        // SAFETY: entrada dentro do bloco recém-alocado (zerado).
        let entry = unsafe { InterruptVectorData::at(block + (CONNECTION_DATA_HEADER + index * ENTRY_SIZE) as u64) };
        entry.type_.set(InterruptConnectionType::INTERRUPT_TYPE_MESSAGE_REQUEST);
        entry.vector.set(message.vector);
        entry.irql.set(message.irql);
        entry.polarity.set(KinterruptPolarity::INTERRUPT_RISING_EDGE);
        entry.mode.set(KinterruptMode::LATCHED);
        entry.target_processors.mask.set(1u64 << message.processor);
        entry.target_processors.group.set(0);
        let msi = &entry.int_remap_info.u.msi;
        msi.message_address_high.set((message.address >> 32) as u32);
        msi.message_address_low.set(message.address as u32);
        msi.message_data.set(message.data as u16);
        entry.message_request.destination_mode.set(HalApicDestinationMode::APIC_DESTINATION_MODE_PHYSICAL);
    }
    let bytes = guest::read_bytes(block, size);
    guest::free_bytes(block);
    bytes
}

/// Endereço e dado de uma entrada InterruptTypeMessageRequest pelo
/// HalGetMessageRoutingInfo; None se a HAL recusa o pedido.
fn route(entry: &InterruptVectorData) -> Option<(u64, u32)> {
    let request = guest::alloc_bytes(ROUTING_REQUEST_SIZE);
    let output = guest::alloc_bytes(ROUTING_OUTPUT_SIZE);
    guest::write32(request + 8, entry.vector.get());
    guest::write_bytes(request + 0x10, &guest::read_bytes(entry.target_processors.address(), 0x10));
    guest::write32(request + 0x20, entry.message_request.destination_mode.get().0 as u32);
    guest::write_bytes(request + 0x24, &guest::read_bytes(entry.int_remap_info.address(), 0x10));
    let status = crate::hal::interrupt_targets::message_routing_info(request, output);
    // SAFETY: o INTERRUPT_VECTOR_DATA da saída, em +8 do bloco.
    let routed = unsafe { InterruptVectorData::at(output + 8) };
    let result = (status >= 0 && routed.type_.get() == InterruptConnectionType::INTERRUPT_TYPE_XAPIC_MESSAGE).then(|| (routed.xapic_message.address.quad_part.get() as u64, routed.xapic_message.data_payload.get()));
    guest::free_bytes(request);
    guest::free_bytes(output);
    result
}

/// As mensagens dos dados de conexão de um PDO, na ordem: as entradas
/// InterruptTypeXapicMessage como estão e as InterruptTypeMessageRequest
/// pelo HalGetMessageRoutingInfo.
pub fn connection_messages(pdo: u64) -> Vec<Message> {
    let Some((_, bytes)) = crate::ntos::io::device_property::device_property_value(pdo, INTERRUPT_CONNECTION_DATA_PKEY, INTERRUPT_CONNECTION_DATA_PID) else { return Vec::new() };
    let count = bytes.get(0..4).map_or(0, |count| u32::from_le_bytes([count[0], count[1], count[2], count[3]])) as usize;
    let block = guest::alloc_bytes(bytes.len().max(1) as u64);
    guest::write_bytes(block, &bytes);
    let mut messages = Vec::new();
    for index in 0..count {
        let start = CONNECTION_DATA_HEADER + index * ENTRY_SIZE;
        if start + ENTRY_SIZE > bytes.len() {
            break;
        }
        // SAFETY: entrada dentro da cópia dos dados de conexão.
        if let Some(message) = entry_message(unsafe { InterruptVectorData::at(block + start as u64) }) {
            messages.push(message);
        }
    }
    guest::free_bytes(block);
    messages
}

/// A mensagem de uma entrada dos dados de conexão: a XapicMessage como
/// está, a MessageRequest pelo HalGetMessageRoutingInfo; None para as
/// outras ou se a HAL recusa o pedido.
pub fn entry_message(entry: &InterruptVectorData) -> Option<Message> {
    let (address, data) = match entry.type_.get() {
        InterruptConnectionType::INTERRUPT_TYPE_XAPIC_MESSAGE => (entry.xapic_message.address.quad_part.get() as u64, entry.xapic_message.data_payload.get()),
        InterruptConnectionType::INTERRUPT_TYPE_MESSAGE_REQUEST => route(entry)?,
        _ => return None,
    };
    let mask = entry.target_processors.mask.get();
    Some(Message { vector: entry.vector.get(), irql: entry.irql.get(), processor: mask.trailing_zeros().min(63), address, data })
}

/// Devolve à HAL os vetores de mensagem do nó.
pub fn release(owner: u64) {
    let blocks: Vec<u32> = {
        let mut vectors = VECTORS.lock();
        let blocks = vectors.iter().filter(|(holder, _)| *holder == owner).map(|&(_, base)| base).collect();
        vectors.retain(|(holder, _)| *holder != owner);
        blocks
    };
    for base in blocks {
        hal::release_vectors(base);
    }
}
