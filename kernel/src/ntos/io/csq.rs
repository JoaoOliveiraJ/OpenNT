//! Fila de IRPs segura contra cancelamento (Cancel-Safe Queue) — o assunto
//! do `io\csq.c` do NT.
//!
//! Transcrição do ntoskrnl 19041:
//!   IoCsqInitialize      rva 0x322b40   IoCsqInitializeEx   rva 0x32bcf0
//!   IoCsqInsertIrp       rva 0x3005d0   IoCsqInsertIrpEx    rva 0x3005f0
//!   IoCsqRemoveIrp       rva 0x3996c0   IoCsqRemoveNextIrp  rva 0x3023d0
//!   IopCsqCancelRoutine  rva 0x3a4c10   (rotina privada instalada no IRP)
//!
//! _IO_CSQ (0x40, sem tipo no PDB; offsets das escritas do Initialize):
//!   +0x00 Type (2 = IO_TYPE_CSQ, 3 = IO_TYPE_CSQ_EX)   +0x08 CsqInsertIrp(Ex)
//!   +0x10 CsqRemoveIrp  +0x18 CsqPeekNextIrp  +0x20 CsqAcquireLock
//!   +0x28 CsqReleaseLock  +0x30 CsqCompleteCanceledIrp  +0x38 ReservePointer
//! _IO_CSQ_IRP_CONTEXT (0x18): +0 Type (1), +8 Irp, +0x10 Csq.
//! O IRP guarda o contexto (ou a própria IO_CSQ) em
//! Tail.Overlay.DriverContext[3] (IRP+0x90; PDB: Tail @0x78).
//!
//! As estruturas são do driver e vivem na memória do convidado; as rotinas
//! do driver entram por `native_call`. O PKIRQL do CsqAcquireLock aponta para
//! uma célula do convidado (no NT é um byte da pilha). O IopCsqCancelRoutine
//! é uma rotina privada (id próprio, fora da EAT) que o `IoCancelIrp` do
//! OpenNT chama com o cancel spin lock retido.

use crate::hal::amd64::native_call;
use crate::ntos::inc::nt_abi::{io_stack_location as stack, irp};
use crate::ntos::init::exports::private_routines;
use crate::ntos::io::cancel;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

// _IO_CSQ
const CSQ_TYPE: u64 = 0x00;
const CSQ_INSERT_IRP: u64 = 0x08;
const CSQ_REMOVE_IRP: u64 = 0x10;
const CSQ_PEEK_NEXT_IRP: u64 = 0x18;
const CSQ_ACQUIRE_LOCK: u64 = 0x20;
const CSQ_RELEASE_LOCK: u64 = 0x28;
const CSQ_COMPLETE_CANCELED_IRP: u64 = 0x30;
const CSQ_RESERVE_POINTER: u64 = 0x38;
// _IO_CSQ_IRP_CONTEXT
const CONTEXT_TYPE: u64 = 0x00;
const CONTEXT_IRP: u64 = 0x08;
const CONTEXT_CSQ: u64 = 0x10;

const IO_TYPE_CSQ_IRP_CONTEXT: u32 = 1;
const IO_TYPE_CSQ: u32 = 2;
const IO_TYPE_CSQ_EX: u32 = 3;
/// IRP.Tail.Overlay.DriverContext[3].
const IRP_CSQ_CONTEXT: u64 = 0x90;
/// IO_STACK_LOCATION.Control: SL_PENDING_RETURNED.
const SL_PENDING_RETURNED: u8 = 0x01;

/// `xchg qword [address], value` sobre a memória do convidado.
fn exchange64(address: u64, value: u64) -> Result<u64, KernelError> {
    let mut current = guest::read64(address);
    loop {
        let previous = guest::compare_exchange64(address, current, value)?;
        if previous == current {
            return Ok(previous);
        }
        current = previous;
    }
}

/// Endereço nativo do IopCsqCancelRoutine.
fn cancel_routine_address() -> Result<u64, KernelError> {
    match private_routines::address("IopCsqCancelRoutine") {
        0 => Err(KernelError::new("IopCsqCancelRoutine sem entrada nativa")),
        address => Ok(address),
    }
}

/// Lock do driver retido: a célula guarda o KIRQL devolvido.
struct Locked {
    csq: u64,
    cell: u64,
}

/// `Csq->ReservePointer = NULL; Csq->CsqAcquireLock(Csq, &Irql)` (Irql = 0 antes).
fn acquire(csq: u64) -> Result<Locked, KernelError> {
    let cell = guest::alloc_bytes(8);
    if cell == 0 {
        return Err(KernelError::new("IoCsq: celula do KIRQL sem memoria"));
    }
    guest::write64(csq + CSQ_RESERVE_POINTER, 0);
    native_call::call(guest::read64(csq + CSQ_ACQUIRE_LOCK), &[csq, cell]);
    Ok(Locked { csq, cell })
}

/// `Csq->CsqReleaseLock(Csq, Irql)`.
fn release(locked: Locked) {
    let irql = guest::read8(locked.cell) as u64;
    native_call::call(guest::read64(locked.csq + CSQ_RELEASE_LOCK), &[locked.csq, irql]);
    guest::free_bytes(locked.cell);
}

fn remove_from_driver_queue(csq: u64, packet: u64) {
    native_call::call(guest::read64(csq + CSQ_REMOVE_IRP), &[csq, packet]);
}

fn complete_canceled(csq: u64, packet: u64) {
    native_call::call(guest::read64(csq + CSQ_COMPLETE_CANCELED_IRP), &[csq, packet]);
}

/// Rotinas do driver de uma IO_CSQ, na ordem do IoCsqInitialize.
pub struct CsqRoutines {
    pub insert: u64,
    pub remove: u64,
    pub peek_next: u64,
    pub acquire_lock: u64,
    pub release_lock: u64,
    pub complete_canceled: u64,
}

/// IoCsqInitialize (`extended = false`, Type 2) / IoCsqInitializeEx (Type 3):
/// preenchimento puro, sempre STATUS_SUCCESS.
pub fn initialize(csq: u64, routines: &CsqRoutines, extended: bool) -> u32 {
    guest::write64(csq + CSQ_RESERVE_POINTER, 0);
    guest::write64(csq + CSQ_ACQUIRE_LOCK, routines.acquire_lock);
    guest::write64(csq + CSQ_RELEASE_LOCK, routines.release_lock);
    guest::write64(csq + CSQ_COMPLETE_CANCELED_IRP, routines.complete_canceled);
    guest::write64(csq + CSQ_INSERT_IRP, routines.insert);
    guest::write64(csq + CSQ_REMOVE_IRP, routines.remove);
    guest::write64(csq + CSQ_PEEK_NEXT_IRP, routines.peek_next);
    guest::write32(csq + CSQ_TYPE, if extended { IO_TYPE_CSQ_EX } else { IO_TYPE_CSQ });
    0
}

/// IoCsqInsertIrpEx(Csq, Irp, Context, InsertContext); IoCsqInsertIrp passa
/// InsertContext = NULL. Devolve o NTSTATUS (0 na variante antiga).
pub fn insert_irp(csq: u64, packet: u64, context: u64, insert_context: u64) -> Result<u32, KernelError> {
    if context == 0 {
        guest::write64(packet + IRP_CSQ_CONTEXT, csq);
    } else {
        guest::write64(packet + IRP_CSQ_CONTEXT, context);
        guest::write64(context + CONTEXT_IRP, packet);
        guest::write64(context + CONTEXT_CSQ, csq);
        guest::write32(context + CONTEXT_TYPE, IO_TYPE_CSQ_IRP_CONTEXT);
    }
    let locked = acquire(csq)?;
    let insert_routine = guest::read64(csq + CSQ_INSERT_IRP);
    // Só a variante Ex devolve NTSTATUS; a antiga é VOID (status 0).
    let status = if guest::read32(csq + CSQ_TYPE) == IO_TYPE_CSQ_EX {
        native_call::call(insert_routine, &[csq, packet, insert_context]) as u32
    } else {
        native_call::call(insert_routine, &[csq, packet]);
        0
    };
    if status & 0x8000_0000 == 0 {
        // IoMarkIrpPending + cancel routine do kernel.
        let current = guest::read64(packet + irp::CURRENT_STACK_LOCATION);
        guest::write8(current + stack::CONTROL, guest::read8(current + stack::CONTROL) | SL_PENDING_RETURNED);
        exchange64(packet + irp::CANCEL_ROUTINE, cancel_routine_address()?)?;
        if guest::read8(packet + irp::CANCEL) != 0 && exchange64(packet + irp::CANCEL_ROUTINE, 0)? != 0 {
            // A corrida com o IoCancelIrp foi ganha aqui: o próprio insert
            // retira e entrega ao CsqCompleteCanceledIrp.
            remove_from_driver_queue(csq, packet);
            if context != 0 {
                guest::write64(context + CONTEXT_IRP, 0);
            }
            guest::write64(packet + IRP_CSQ_CONTEXT, 0);
            release(locked);
            complete_canceled(csq, packet);
            return Ok(status);
        }
    }
    release(locked);
    Ok(status)
}

/// IoCsqRemoveIrp(Csq, Context): NULL se o IRP já saiu ou está sendo cancelado.
pub fn remove_irp(csq: u64, context: u64) -> Result<u64, KernelError> {
    let locked = acquire(csq)?;
    let packet = guest::read64(context + CONTEXT_IRP);
    if packet == 0 || exchange64(packet + irp::CANCEL_ROUTINE, 0)? == 0 {
        release(locked);
        return Ok(0);
    }
    remove_from_driver_queue(csq, packet);
    guest::write64(context + CONTEXT_IRP, 0);
    guest::write64(packet + IRP_CSQ_CONTEXT, 0);
    release(locked);
    Ok(packet)
}

/// IoCsqRemoveNextIrp(Csq, PeekContext): pula IRPs cujo cancelamento já tomou
/// a cancel routine e espia o seguinte.
pub fn remove_next_irp(csq: u64, peek_context: u64) -> Result<u64, KernelError> {
    let locked = acquire(csq)?;
    let mut previous = 0;
    loop {
        let packet = native_call::call(guest::read64(csq + CSQ_PEEK_NEXT_IRP), &[csq, previous, peek_context]);
        if packet == 0 {
            release(locked);
            return Ok(0);
        }
        if exchange64(packet + irp::CANCEL_ROUTINE, 0)? == 0 {
            previous = packet;
            continue;
        }
        remove_from_driver_queue(csq, packet);
        let context = guest::read64(packet + IRP_CSQ_CONTEXT);
        if context != 0 && guest::read32(context + CONTEXT_TYPE) == IO_TYPE_CSQ_IRP_CONTEXT {
            guest::write64(context + CONTEXT_IRP, 0);
        }
        guest::write64(packet + IRP_CSQ_CONTEXT, 0);
        release(locked);
        return Ok(packet);
    }
}

/// IopCsqCancelRoutine(DeviceObject, Irp) — corpo da rotina privada. O NT
/// solta o cancel spin lock (KeReleaseQueuedSpinLock(7, CancelIrql)) antes
/// de tudo; o caminho interno do OpenNT que cancela pedidos pendentes sem
/// retê-lo é tolerado.
pub fn cancel_routine(_device: u64, packet: u64) -> Result<(), KernelError> {
    if cancel::is_held() {
        cancel::release(guest::read8(packet + irp::CANCEL_IRQL))?;
    }
    let pointer = guest::read64(packet + IRP_CSQ_CONTEXT);
    if pointer == 0 {
        return Ok(());
    }
    let csq = match guest::read32(pointer) {
        IO_TYPE_CSQ_IRP_CONTEXT => guest::read64(pointer + CONTEXT_CSQ),
        IO_TYPE_CSQ | IO_TYPE_CSQ_EX => pointer,
        _ => return Ok(()),
    };
    let locked = acquire(csq)?;
    remove_from_driver_queue(csq, packet);
    if pointer != csq {
        guest::write64(pointer + CONTEXT_IRP, 0);
        guest::write64(packet + IRP_CSQ_CONTEXT, 0);
    }
    release(locked);
    complete_canceled(csq, packet);
    Ok(())
}
