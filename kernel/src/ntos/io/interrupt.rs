//! Interrupções dos exports Io* — IoConnectInterruptEx (LINE_BASED pelo
//! recurso do PDO, FULLY_SPECIFIED pelos campos), IoDisconnectInterruptEx e
//! IoGetAffinityInterrupt, sobre o KINTERRUPT de `ke::interrupt_object`.

use crate::ntos::init::exports::signed_status;
use crate::ntos::inc::types::{GroupAffinity, IoConnectInterruptParameters, IoDisconnectInterruptParameters, Kinterrupt, NtStruct};
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
