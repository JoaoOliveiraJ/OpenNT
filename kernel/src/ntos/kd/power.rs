//! Trava do depurador e energia do transporte KD num boot sem /DEBUG.
//!
//! - KdAcquireDebuggerLock/KdReleaseDebuggerLock: a KdDebuggerLock (uma
//!   KSPIN_LOCK) tomada em DISPATCH_LEVEL, com a IRQL anterior devolvida
//!   ao chamador e restaurada na liberação.
//! - KdRegisterPowerHandler/KdDeregisterPowerHandler: a lista KdpPowerList
//!   dos tratadores de energia do transporte; cada registro é um bloco de
//!   0x20 bytes de NonPagedPoolNx com a tag 'KdIo' (LIST_ENTRY, rotina e
//!   contexto), inserido no fim sob a KdpPowerSpinLock em HIGH_LEVEL. O
//!   handle devolvido é o próprio bloco.
//! - KdPowerTransitionEx e KdDisableDebugger: o KdPitchDebugger de um boot
//!   sem /DEBUG faz a transição devolver STATUS_SUCCESS sem tocar no
//!   transporte (os tratadores registrados só são chamados pela energia do
//!   transporte, que não existe) e o disable devolver
//!   STATUS_DEBUGGER_INACTIVE.
//! - DbgCommandString(Name, Command): o serviço de depuração
//!   BREAKPOINT_COMMAND_STRING (5) pelo `int 0x2D`, com os dois STRINGs
//!   montados pelo corpo nativo; sem KD, o serviço só avança o contexto.

use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;

use crate::hal::amd64::{native_call, private_entries};
use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::ListEntry;
use crate::ntos::ke::{irql, spin_lock};
use crate::ntos::mm::kernel_address;
use crate::rtl::{KernelError, SpinLock};

const STATUS_SUCCESS: u32 = 0;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const STATUS_DEBUGGER_INACTIVE: u32 = 0xC000_0354;
const NON_PAGED_POOL_NX: u32 = 0x200;
const POWER_HANDLER_TAG: u32 = u32::from_le_bytes(*b"KdIo");
const HIGH_LEVEL: u8 = 15;

/// KdPitchDebugger: o boot do OpenNT não tem /DEBUG.
const PITCH_DEBUGGER: bool = true;

/// A KSPIN_LOCK KdDebuggerLock.
static DEBUGGER_LOCK: AtomicU64 = AtomicU64::new(0);

/// Os registros de KdpPowerListHead, na ordem de inserção.
static POWER_HANDLERS: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());

/// O registro de um tratador de energia (0x20 bytes, 'KdIo').
#[repr(C)]
struct PowerHandlerRecord {
    link: ListEntry,
    routine: Field<u64>,
    context: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for PowerHandlerRecord {}

const _: () = assert!(core::mem::size_of::<PowerHandlerRecord>() == 0x20);

fn debugger_lock() -> u64 {
    DEBUGGER_LOCK.as_ptr() as u64
}

/// KdAcquireDebuggerLock(OldIrql*): DISPATCH_LEVEL e a trava.
pub fn acquire_debugger_lock(old_irql: &Field<u8>) {
    let previous = irql::raise_irql(irql::DISPATCH_LEVEL);
    old_irql.set(previous);
    spin_lock::acquire_at_dpc_level(debugger_lock());
}

/// KdReleaseDebuggerLock(OldIrql).
pub fn release_debugger_lock(old_irql: u8) {
    spin_lock::release_from_dpc_level(debugger_lock());
    irql::lower_irql(old_irql as u64);
}

/// A trava está tomada (autotestes).
pub fn debugger_lock_held() -> bool {
    !spin_lock::test(debugger_lock())
}

/// KdRegisterPowerHandler(Routine, Context, Handle*).
pub fn register_power_handler(routine: u64, context: u64, handle: &Field<u64>) -> u32 {
    let block = pool_allocation::allocate_tagged(NON_PAGED_POOL_NX, PowerHandlerRecord::SIZE, POWER_HANDLER_TAG).unwrap_or(0);
    if block == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: o bloco recém-alocado do registro.
    let record = unsafe { PowerHandlerRecord::at(block) };
    record.routine.set(routine);
    record.context.set(context);
    let previous = irql::raise_irql(HIGH_LEVEL);
    {
        let mut handlers = POWER_HANDLERS.lock();
        // Os elos do bloco seguem a ordem da lista (o fim é o mais novo).
        record.link.flink.set(0);
        record.link.blink.set(handlers.last().copied().unwrap_or(0));
        if let Some(&last) = handlers.last() {
            // SAFETY: o registro anterior, vivo enquanto está na lista.
            unsafe { PowerHandlerRecord::at(last) }.link.flink.set(block);
        }
        handlers.push(block);
    }
    irql::lower_irql(previous as u64);
    handle.set(block);
    STATUS_SUCCESS
}

/// KdDeregisterPowerHandler(Handle): STATUS_NOT_FOUND se não registrado.
pub fn deregister_power_handler(handle: u64) -> u32 {
    let previous = irql::raise_irql(HIGH_LEVEL);
    let found = {
        let mut handlers = POWER_HANDLERS.lock();
        match handlers.iter().position(|&record| record == handle) {
            Some(index) => {
                handlers.remove(index);
                true
            }
            None => false,
        }
    };
    irql::lower_irql(previous as u64);
    if !found {
        return STATUS_NOT_FOUND;
    }
    let _ = pool_allocation::free(handle, 0);
    STATUS_SUCCESS
}

/// Os tratadores registrados (autotestes).
pub fn registered_power_handlers() -> Vec<u64> {
    POWER_HANDLERS.lock().clone()
}

/// KdPowerTransitionEx(PowerState, AcquireLock): sem /DEBUG, nada a fazer.
pub fn power_transition(_power_state: u32, _acquire_lock: bool) -> u32 {
    if PITCH_DEBUGGER {
        return STATUS_SUCCESS;
    }
    STATUS_SUCCESS
}

/// KdDisableDebugger: o depurador foi descartado no boot.
pub fn disable_debugger() -> u32 {
    if PITCH_DEBUGGER {
        return STATUS_DEBUGGER_INACTIVE;
    }
    STATUS_SUCCESS
}

/// DbgCommandString(Name, Command): o corpo nativo com `int 0x2D`.
pub fn command_string(name: u64, command: u64) -> Result<(), KernelError> {
    let entry = private_entries::entry("dbg_command_string").ok_or_else(|| KernelError::new("DbgCommandString native body is missing"))?;
    let address = kernel_address::image_address(entry)?;
    native_call::call(address, &[name, command]);
    Ok(())
}
