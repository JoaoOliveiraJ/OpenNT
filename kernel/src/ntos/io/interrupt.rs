//! Interrupções dos exports Io* — IoConnectInterruptEx (LINE_BASED pelos
//! dados de conexão do PDO ou pelo recurso dele, FULLY_SPECIFIED pelos
//! campos), IoDisconnectInterruptEx e IoGetAffinityInterrupt, sobre o
//! KINTERRUPT de `ke::interrupt_object`.
//!
//! Como o IopConnectLineBasedInterrupt do ntoskrnl 19041, o LINE_BASED usa
//! primeiro os dados de conexão que o barramento gravou no PDO
//! (INTERRUPT_CONNECTION_DATA_PKEY, o IopGetInterruptConnectionData: um
//! ULONG de contagem e os INTERRUPT_VECTOR_DATA de 0x58 bytes; o acpi.sys
//! grava os da SCI no dispositivo ACPI da HAL). Do vetor de entrada de
//! controlador valem a GSIV e o vetor e o IRQL que o árbitro de IRQ
//! atribuiu a ela: a HAL registra a linha do 8259 que alimenta o vetor
//! (`hal::interrupt_lines`); sem vetor atribuído, a linha chega no vetor
//! fixo dela (`resources::translate_interrupt`). O modo vem do próprio dado.

use crate::ntos::init::exports::signed_status;
use crate::ntos::inc::types::{GroupAffinity, InterruptConnectionType, InterruptVectorData, IoConnectInterruptParameters, IoDisconnectInterruptParameters, Kinterrupt, NtStruct};
use crate::ntos::io::device_resources;
use crate::ntos::ke::interrupt_object;
use crate::rtl::KernelError;

/// CONNECT_FULLY_SPECIFIED, CONNECT_LINE_BASED e CONNECT_FULLY_SPECIFIED_GROUP.
const CONNECT_FULLY_SPECIFIED: u32 = 1;
const CONNECT_LINE_BASED: u32 = 2;
const CONNECT_FULLY_SPECIFIED_GROUP: u32 = 4;

/// IoConnectInterruptEx: LINE_BASED (2) pelo recurso do PDO; FULLY_SPECIFIED
/// (1/4) pelos campos; MESSAGE_BASED (MSI) sem suporte. O KINTERRUPT vai
/// para *InterruptObject. Devolve o valor do export: as falhas próprias com
/// sinal, o status do IoConnectInterrupt sem sinal.
pub fn connect_interrupt_ex(parameters: u64) -> Result<u64, KernelError> {
    // SAFETY: IO_CONNECT_INTERRUPT_PARAMETERS do driver (modo kernel).
    let parameters = unsafe { IoConnectInterruptParameters::at(parameters) };
    let version = parameters.version.get();
    // ServiceRoutine/ServiceContext/SpinLock/InterruptObject têm o mesmo
    // offset nas variantes FullySpecified e LineBased.
    let fully = &parameters.fully_specified;
    let service_routine = fully.service_routine.get();
    let service_context = fully.service_context.get();
    let spin_lock = fully.spin_lock.get();
    let output = fully.interrupt_object.get();
    if version == CONNECT_LINE_BASED {
        let physical = parameters.line_based.physical_device_object.get();
        if let Some(line) = connection_data_line(physical) {
            // O vetor e o IRQL que o árbitro de IRQ atribuiu à GSIV: a HAL
            // entrega a linha nele; sem vetor atribuído, o vetor fixo da linha.
            let (vector, level) = if line.vector != 0 {
                crate::hal::interrupt_lines::route_vector(line.vector, line.gsiv);
                (line.vector, line.irql as u32)
            } else {
                crate::ntos::io::pnp::resources::translate_interrupt(line.gsiv)
            };
            let status = interrupt_object::io_connect_interrupt(output, service_routine, service_context, spin_lock, vector, level as u8, level as u8, line.mode, true)?;
            debug_print!("[io] interrupt LINE_BASED pelos dados de conexao: GSIV {} vetor 0x{:x} irql {} -> ISR 0x{:x}", line.gsiv, vector, level, service_routine);
            return Ok(status as u64);
        }
        // PDO da árvore do PnP: as interrupções de linha da lista traduzida
        // do devnode, como o IopConnectInterruptExLineBased.
        if let Some(node) = crate::ntos::io::pnp::devnode::get(physical) {
            let list = crate::ntos::io::pnp::resources::CmList::read(node.resources_translated).unwrap_or_default();
            let interrupts: alloc::vec::Vec<_> = list.resources.iter().filter(|resource| resource.resource_type == crate::ntos::io::pnp::resources::resource_type::INTERRUPT).copied().collect();
            let Some(first) = interrupts.first() else {
                debug_print!("[io] IoConnectInterruptEx LINE_BASED: {} sem interrupcao atribuida", node.instance_path);
                return Ok(signed_status(0xC000_000D));
            };
            if interrupts.len() > 1 {
                debug_print!("[io] IoConnectInterruptEx LINE_BASED: {} tem {} interrupcoes; conecta a primeira", node.instance_path, interrupts.len());
            }
            // CM_RESOURCE_INTERRUPT_LATCHED (bit 0) -> Latched; senão LevelSensitive.
            let mode = if first.flags & 1 != 0 { 1 } else { 0 };
            let share = first.share == crate::ntos::io::pnp::resources::SHARE_SHARED;
            let level = first.start as u8;
            let status = interrupt_object::io_connect_interrupt(output, service_routine, service_context, spin_lock, first.length, level, level, mode, share)?;
            debug_print!("[io] interrupt LINE_BASED {}: vetor 0x{:x} irql {} -> ISR 0x{:x}", node.instance_path, first.length, level, service_routine);
            return Ok(status as u64);
        }
        let Some(resource) = device_resources::consume_next_interrupt(physical) else {
            debug_print!("[io] IoConnectInterruptEx LINE_BASED: PDO 0x{:x} sem IRQ restante", physical);
            return Ok(signed_status(0xC000_009A));
        };
        // O modo vem do recurso (LEVEL_SENSITIVE), como a HAL faz.
        let mode = if resource.flags & 2 != 0 { 1 } else { 0 };
        let status = interrupt_object::io_connect_interrupt(output, service_routine, service_context, spin_lock, resource.vector, resource.level as u8, resource.level as u8, mode, false)?;
        debug_print!("[io] interrupt LINE_BASED: vetor 0x{:x} -> ISR 0x{:x}", resource.vector, service_routine);
        return Ok(status as u64);
    }
    if version == CONNECT_FULLY_SPECIFIED || version == CONNECT_FULLY_SPECIFIED_GROUP {
        let synchronize = fully.synchronize_irql.get();
        let share = fully.share_vector.get();
        let vector = fully.vector.get();
        let level = fully.irql.get();
        let mode = fully.interrupt_mode.get() as u32;
        debug_print!("[io] interrupt FULLY_SPECIFIED: vetor 0x{:x} irql {} -> ISR 0x{:x}", vector, level, service_routine);
        return Ok(interrupt_object::io_connect_interrupt(output, service_routine, service_context, spin_lock, vector, level, synchronize, mode, share != 0)? as u64);
    }
    debug_print!("[io] IoConnectInterruptEx: version {} (MESSAGE_BASED) sem suporte — MSI nao configurado", version);
    Ok(signed_status(0xC000_00BB))
}

/// INTERRUPT_CONNECTION_DATA_PKEY {f0e20f09-d97a-49a9-8046-bb6e22e6bb2e}, 2.
const INTERRUPT_CONNECTION_DATA_PKEY: [u8; 16] = [0x09, 0x0F, 0xE2, 0xF0, 0x7A, 0xD9, 0xA9, 0x49, 0x80, 0x46, 0xBB, 0x6E, 0x22, 0xE6, 0xBB, 0x2E];
/// Tamanho de um INTERRUPT_VECTOR_DATA.
const VECTOR_DATA_SIZE: usize = core::mem::size_of::<InterruptVectorData>();

/// Uma entrada de controlador dos dados de conexão: a GSIV, o modo (0 =
/// LevelSensitive, 1 = Latched), o vetor do IDT e o IRQL atribuídos.
struct ConnectionLine {
    gsiv: u32,
    mode: u32,
    vector: u32,
    irql: u8,
}

/// A primeira entrada de controlador (InterruptTypeControllerInput) dos
/// dados de conexão do PDO.
fn connection_data_line(pdo: u64) -> Option<ConnectionLine> {
    let (_, bytes) = crate::ntos::io::device_property::device_property_value(pdo, INTERRUPT_CONNECTION_DATA_PKEY, 2)?;
    let count = u32::from_le_bytes(bytes.get(0..4)?.try_into().ok()?) as usize;
    if count == 0 || bytes.len() < 8 + count * VECTOR_DATA_SIZE {
        return None;
    }
    let entry = |index: usize, offset: usize| u32::from_le_bytes(bytes[8 + index * VECTOR_DATA_SIZE + offset..8 + index * VECTOR_DATA_SIZE + offset + 4].try_into().unwrap());
    let type_offset = core::mem::offset_of!(InterruptVectorData, type_);
    let mode_offset = core::mem::offset_of!(InterruptVectorData, mode);
    let gsiv_offset = core::mem::offset_of!(InterruptVectorData, controller_input);
    let vector_offset = core::mem::offset_of!(InterruptVectorData, vector);
    let irql_offset = core::mem::offset_of!(InterruptVectorData, irql);
    let index = (0..count).find(|&index| entry(index, type_offset) == InterruptConnectionType::INTERRUPT_TYPE_CONTROLLER_INPUT.0 as u32)?;
    Some(ConnectionLine { gsiv: entry(index, gsiv_offset), mode: entry(index, mode_offset), vector: entry(index, vector_offset), irql: entry(index, irql_offset) as u8 })
}

/// IoDisconnectInterruptEx: o KINTERRUPT em ConnectionContext.
pub fn disconnect_interrupt_ex(parameters: u64) -> u32 {
    // SAFETY: IO_DISCONNECT_INTERRUPT_PARAMETERS do driver (modo kernel).
    let object = unsafe { IoDisconnectInterruptParameters::at(parameters) }.connection_context.get();
    if object == 0 {
        return 0xC000_000D;
    }
    interrupt_object::io_disconnect_interrupt(object);
    0
}

/// IoGetAffinityInterrupt: o processador que recebe a interrupção (o
/// KINTERRUPT.Number), no grupo 0.
pub fn affinity_interrupt(object: u64, affinity: u64) -> u32 {
    if object == 0 || affinity == 0 {
        return 0xC000_000D;
    }
    // SAFETY: KINTERRUPT conectado e o GROUP_AFFINITY de saída do driver.
    let (interrupt, output) = unsafe { (Kinterrupt::at(object), GroupAffinity::at(affinity)) };
    let processor = interrupt.number.get() & 63;
    crate::ntos::mm::guest_memory::write_bytes(affinity, &[0; GroupAffinity::SIZE as usize]);
    output.mask.set(1u64 << processor);
    0
}
