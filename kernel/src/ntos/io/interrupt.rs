//! Interrupções dos exports Io* — IoConnectInterruptEx (LINE_BASED pelo
//! recurso do PDO, FULLY_SPECIFIED pelos campos), IoDisconnectInterruptEx e
//! IoGetAffinityInterrupt, sobre o KINTERRUPT de `ke::interrupt_object`.

use crate::ntos::init::exports::signed_status;
use crate::ntos::io::device_resources;
use crate::ntos::ke::interrupt_object;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::kinterrupt;

/// IoConnectInterruptEx: LINE_BASED (2) pelo recurso do PDO; FULLY_SPECIFIED
/// (1/4) pelos campos; MESSAGE_BASED (MSI) sem suporte. O KINTERRUPT vai
/// para *(params+0x10). Devolve o valor do export: as falhas próprias com
/// sinal, o status do IoConnectInterrupt sem sinal.
pub fn connect_interrupt_ex(parameters: u64) -> Result<u64, KernelError> {
    let version = guest::read32(parameters);
    let service_routine = guest::read64(parameters + 0x18);
    let service_context = guest::read64(parameters + 0x20);
    let spin_lock = guest::read64(parameters + 0x28);
    let output = guest::read64(parameters + 0x10);
    if version == 2 {
        let physical = guest::read64(parameters + 8);
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
    if version == 1 || version == 4 {
        let synchronize = guest::read8(parameters + 0x30);
        let share = guest::read8(parameters + 0x32);
        let vector = guest::read32(parameters + 0x34);
        let level = guest::read8(parameters + 0x38);
        let mode = guest::read32(parameters + 0x3C);
        debug_print!("[io] interrupt FULLY_SPECIFIED: vetor 0x{:x} irql {} -> ISR 0x{:x}", vector, level, service_routine);
        return Ok(interrupt_object::io_connect_interrupt(output, service_routine, service_context, spin_lock, vector, level, synchronize, mode, share != 0)? as u64);
    }
    debug_print!("[io] IoConnectInterruptEx: version {} (MESSAGE_BASED) sem suporte — MSI nao configurado", version);
    Ok(signed_status(0xC000_00BB))
}

/// IoDisconnectInterruptEx: o KINTERRUPT em *(params+8).
pub fn disconnect_interrupt_ex(parameters: u64) -> u32 {
    let object = guest::read64(parameters + 8);
    if object == 0 {
        return 0xC000_000D;
    }
    interrupt_object::io_disconnect_interrupt(object);
    0
}

/// IoGetAffinityInterrupt: o processador que recebe a interrupção (o
/// Number do KINTERRUPT), no grupo 0.
pub fn affinity_interrupt(object: u64, affinity: u64) -> u32 {
    if object == 0 || affinity == 0 {
        return 0xC000_000D;
    }
    let processor = guest::read32(object + kinterrupt::NUMBER) & 63;
    guest::write_bytes(affinity, &[0; 16]);
    guest::write64(affinity, 1u64 << processor);
    0
}
