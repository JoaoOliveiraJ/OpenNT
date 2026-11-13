//! Fila de IRPs segura contra cancelamento (Cancel-Safe Queue) — o assunto
//! do `io\csq.c` do NT.
//!
//! Transcrição do ntoskrnl 19041:
//!   IoCsqInitialize      rva 0x322b40   IoCsqInitializeEx   rva 0x32bcf0
//!   IoCsqInsertIrp       rva 0x3005d0   IoCsqInsertIrpEx    rva 0x3005f0
//!   IoCsqRemoveIrp       rva 0x3996c0   IoCsqRemoveNextIrp  rva 0x3023d0
//!   IopCsqCancelRoutine  rva 0x3a4c10   (rotina privada instalada no IRP)
//!
//! _IO_CSQ (0x40) e _IO_CSQ_IRP_CONTEXT (0x18) vêm do wdm.h (sem tipo no
//! PDB): `inc::types::{IoCsq, IoCsqIrpContext}`. O IRP guarda o contexto (ou
//! a própria IO_CSQ) em Tail.Overlay.DriverContext[3].
//!
//! As estruturas são do driver e vivem na memória do convidado; as rotinas
//! do driver entram por `native_call`. O PKIRQL do CsqAcquireLock aponta para
//! uma célula do convidado (no NT é um byte da pilha). O IopCsqCancelRoutine
//! é uma rotina privada (id próprio, fora da EAT) que o `IoCancelIrp` do
//! OpenNT chama com o cancel spin lock retido.

use core::sync::atomic::Ordering;

use crate::hal::amd64::native_call;
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{IoCsq, IoCsqIrpContext, IoStackLocation, Irp, NtStruct};
use crate::ntos::init::exports::private_routines;
use crate::ntos::io::cancel;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

const IO_TYPE_CSQ_IRP_CONTEXT: u32 = 1;
const IO_TYPE_CSQ: u32 = 2;
const IO_TYPE_CSQ_EX: u32 = 3;
/// Tail.Overlay.DriverContext[3]: contexto da CSQ (ou a IO_CSQ).
const CSQ_DRIVER_CONTEXT: usize = 3;
/// IO_STACK_LOCATION.Control: SL_PENDING_RETURNED.
const SL_PENDING_RETURNED: u8 = 0x01;

/// IO_CSQ do driver.
fn csq_at(csq: u64) -> &'static IoCsq {
    // SAFETY: a IO_CSQ que o driver inicializou e mantém viva.
    unsafe { IoCsq::at(csq) }
}

/// IO_CSQ_IRP_CONTEXT do driver.
fn context_at(context: u64) -> &'static IoCsqIrpContext {
    // SAFETY: o contexto que o driver passou ao insert e mantém vivo.
    unsafe { IoCsqIrpContext::at(context) }
}

/// IRP vivo da fila.
fn irp_at(packet: u64) -> &'static Irp {
    // SAFETY: IRPs passados pelo driver ou devolvidos pela própria fila.
    unsafe { Irp::at(packet) }
}

/// Irp->Tail.Overlay.DriverContext[3].
fn csq_slot(irp: &Irp) -> &Field<u64> {
    &irp.tail.overlay.driver_context[CSQ_DRIVER_CONTEXT]
}

/// IoSetCancelRoutine: `xchg` no Irp->CancelRoutine.
fn exchange_cancel_routine(irp: &Irp, routine: u64) -> u64 {
    irp.cancel_routine.atomic().swap(routine, Ordering::SeqCst)
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
    let queue = csq_at(csq);
    queue.reserve_pointer.set(0);
    native_call::call(queue.csq_acquire_lock.get(), &[csq, cell]);
    Ok(Locked { csq, cell })
}

/// `Csq->CsqReleaseLock(Csq, Irql)`.
fn release(locked: Locked) {
    // SAFETY: a célula KIRQL alocada em `acquire`.
    let irql = unsafe { Field::<u8>::at(locked.cell) }.get() as u64;
    native_call::call(csq_at(locked.csq).csq_release_lock.get(), &[locked.csq, irql]);
    guest::free_bytes(locked.cell);
}

fn remove_from_driver_queue(csq: u64, packet: u64) {
    native_call::call(csq_at(csq).csq_remove_irp.get(), &[csq, packet]);
}

fn complete_canceled(csq: u64, packet: u64) {
    native_call::call(csq_at(csq).csq_complete_canceled_irp.get(), &[csq, packet]);
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
    let queue = csq_at(csq);
    queue.reserve_pointer.set(0);
    queue.csq_acquire_lock.set(routines.acquire_lock);
    queue.csq_release_lock.set(routines.release_lock);
    queue.csq_complete_canceled_irp.set(routines.complete_canceled);
    queue.csq_insert_irp.set(routines.insert);
    queue.csq_remove_irp.set(routines.remove);
    queue.csq_peek_next_irp.set(routines.peek_next);
    queue.type_.set(if extended { IO_TYPE_CSQ_EX } else { IO_TYPE_CSQ });
    0
}

/// IoCsqInsertIrpEx(Csq, Irp, Context, InsertContext); IoCsqInsertIrp passa
/// InsertContext = NULL. Devolve o NTSTATUS (0 na variante antiga).
pub fn insert_irp(csq: u64, packet: u64, context: u64, insert_context: u64) -> Result<u32, KernelError> {
    let irp = irp_at(packet);
    if context == 0 {
        csq_slot(irp).set(csq);
    } else {
        csq_slot(irp).set(context);
        let record = context_at(context);
        record.irp.set(packet);
        record.csq.set(csq);
        record.type_.set(IO_TYPE_CSQ_IRP_CONTEXT);
    }
    let locked = acquire(csq)?;
    let queue = csq_at(csq);
    let insert_routine = queue.csq_insert_irp.get();
    // Só a variante Ex devolve NTSTATUS; a antiga é VOID (status 0).
    let status = if queue.type_.get() == IO_TYPE_CSQ_EX {
        native_call::call(insert_routine, &[csq, packet, insert_context]) as u32
    } else {
        native_call::call(insert_routine, &[csq, packet]);
        0
    };
    if status & 0x8000_0000 == 0 {
        // IoMarkIrpPending + cancel routine do kernel.
        // SAFETY: CurrentStackLocation de um IRP vivo.
        let current = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get()) };
        current.control.set(current.control.get() | SL_PENDING_RETURNED);
        exchange_cancel_routine(irp, cancel_routine_address()?);
        if irp.cancel.get() != 0 && exchange_cancel_routine(irp, 0) != 0 {
            // A corrida com o IoCancelIrp foi ganha aqui: o próprio insert
            // retira e entrega ao CsqCompleteCanceledIrp.
            remove_from_driver_queue(csq, packet);
            if context != 0 {
                context_at(context).irp.set(0);
            }
            csq_slot(irp).set(0);
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
    let record = context_at(context);
    let packet = record.irp.get();
    if packet == 0 || exchange_cancel_routine(irp_at(packet), 0) == 0 {
        release(locked);
        return Ok(0);
    }
    remove_from_driver_queue(csq, packet);
    record.irp.set(0);
    csq_slot(irp_at(packet)).set(0);
    release(locked);
    Ok(packet)
}

/// IoCsqRemoveNextIrp(Csq, PeekContext): pula IRPs cujo cancelamento já tomou
/// a cancel routine e espia o seguinte.
pub fn remove_next_irp(csq: u64, peek_context: u64) -> Result<u64, KernelError> {
    let locked = acquire(csq)?;
    let mut previous = 0;
    loop {
        let packet = native_call::call(csq_at(csq).csq_peek_next_irp.get(), &[csq, previous, peek_context]);
        if packet == 0 {
            release(locked);
            return Ok(0);
        }
        let irp = irp_at(packet);
        if exchange_cancel_routine(irp, 0) == 0 {
            previous = packet;
            continue;
        }
        remove_from_driver_queue(csq, packet);
        let context = csq_slot(irp).get();
        if context != 0 && context_at(context).type_.get() == IO_TYPE_CSQ_IRP_CONTEXT {
            context_at(context).irp.set(0);
        }
        csq_slot(irp).set(0);
        release(locked);
        return Ok(packet);
    }
}

/// IopCsqCancelRoutine(DeviceObject, Irp) — corpo da rotina privada. O NT
/// solta o cancel spin lock (KeReleaseQueuedSpinLock(7, CancelIrql)) antes
/// de tudo; o caminho interno do OpenNT que cancela pedidos pendentes sem
/// retê-lo é tolerado.
pub fn cancel_routine(_device: u64, packet: u64) -> Result<(), KernelError> {
    let irp = irp_at(packet);
    if cancel::is_held() {
        cancel::release(irp.cancel_irql.get())?;
    }
    let pointer = csq_slot(irp).get();
    if pointer == 0 {
        return Ok(());
    }
    // IO_CSQ_IRP_CONTEXT e IO_CSQ começam pelo mesmo ULONG Type.
    let csq = match context_at(pointer).type_.get() {
        IO_TYPE_CSQ_IRP_CONTEXT => context_at(pointer).csq.get(),
        IO_TYPE_CSQ | IO_TYPE_CSQ_EX => pointer,
        _ => return Ok(()),
    };
    let locked = acquire(csq)?;
    remove_from_driver_queue(csq, packet);
    if pointer != csq {
        context_at(pointer).irp.set(0);
        csq_slot(irp).set(0);
    }
    release(locked);
    complete_canceled(csq, packet);
    Ok(())
}
