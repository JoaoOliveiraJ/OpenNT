//! Identificadores de atividade do ETW (EtwActivityIdControl e o
//! EtwActivityIdCreate do NtTraceControl).
//!
//! Como no ntoskrnl 19041:
//! - um ID novo vem da semente por processador em KPRCB.EtwSupport
//!   (EtwpCreateActivityId): os oito primeiros bytes do GUID são a base da
//!   semente e os oito últimos o contador dela incrementado atomicamente. O
//!   EtwpInitializeActivityIdSeed monta a base com o KUSER_SHARED_DATA.SystemTime
//!   (sem o GUID do Headless, ausente aqui): ULONG baixo, USHORT seguinte e
//!   o número do processador; o contador parte do mesmo SystemTime;
//! - a atividade corrente é a da thread, no TEB (TEB.ActivityId, +0x1710):
//!   thread de sistema (KTHREAD.MiscFlags.SystemThread) ou anexada a outro
//!   processo (ApcStateIndex 1) não tem TEB e GET/SET devolvem
//!   STATUS_NOT_SUPPORTED; CREATE_ID não depende da thread.

use crate::ntos::inc::types::{Guid, Kthread, NtStruct};
use crate::ntos::ke::{clock, pcr};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
/// KTHREAD.MiscFlags.SystemThread.
const SYSTEM_THREAD: i32 = 0x400;
/// Tamanho da semente (base e contador).
const SEED_SIZE: u64 = 16;
/// Tag do bloco por processador ('EtwP').
const SEED_TAG: u32 = 0x5077_7445;

pub const EVENT_ACTIVITY_CTRL_GET_ID: u32 = 1;
pub const EVENT_ACTIVITY_CTRL_SET_ID: u32 = 2;
pub const EVENT_ACTIVITY_CTRL_CREATE_ID: u32 = 3;
pub const EVENT_ACTIVITY_CTRL_GET_SET_ID: u32 = 4;
pub const EVENT_ACTIVITY_CTRL_CREATE_SET_ID: u32 = 5;

/// A semente do processador corrente (KPRCB.EtwSupport), criada na primeira
/// vez como o EtwInitializeProcessor.
fn seed() -> u64 {
    let prcb = &pcr::current().prcb;
    let current = prcb.etw_support.get();
    if current != 0 {
        return current;
    }
    let Ok(block) = kernel_pool::allocate(SEED_SIZE, AllocateOptions { tag: SEED_TAG, zero: true, ..Default::default() }) else { return 0 };
    let time = clock::system_time_100ns();
    guest::write32(block, time as u32);
    guest::write16(block + 4, (time >> 32) as u16);
    guest::write16(block + 6, prcb.number.get() as u16);
    guest::write64(block + 8, time);
    prcb.etw_support.set(block);
    block
}

/// EtwpCreateActivityId: o GUID novo em `output` (16 bytes graváveis).
pub fn create_id(output: u64) -> Result<(), crate::rtl::KernelError> {
    let seed = seed();
    if seed == 0 {
        return Err(crate::rtl::KernelError::new("ETW activity seed allocation failed"));
    }
    // SAFETY: a semente do processador (16 bytes do pool, alinhados).
    let counter = unsafe { crate::ntos::inc::field::Field::<u64>::at(seed + 8) }.atomic().fetch_add(1, core::sync::atomic::Ordering::SeqCst).wrapping_add(1);
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&guest::read64(seed).to_le_bytes());
    bytes[8..].copy_from_slice(&counter.to_le_bytes());
    guest::try_write_bytes(output, &bytes)
}

/// O TEB.ActivityId da thread corrente (0 sem TEB).
fn thread_activity() -> u64 {
    let thread = pcr::current_thread();
    if thread == 0 {
        return 0;
    }
    // SAFETY: KTHREAD da thread corrente.
    let kthread = unsafe { Kthread::at(thread) };
    if kthread.misc_flags.get() & SYSTEM_THREAD != 0 || kthread.apc_state_index.get() == 1 {
        return 0;
    }
    match kthread.teb.get() {
        0 => 0,
        teb => teb + core::mem::offset_of!(crate::ntos::inc::types::Teb, activity_id) as u64,
    }
}

/// O ID de atividade de um evento: o explícito ou o da thread (GUID nulo
/// sem TEB). Devolve os 16 bytes.
pub fn resolve(explicit: u64) -> [u8; 16] {
    let source = if explicit != 0 { explicit } else { thread_activity() };
    let mut bytes = [0u8; 16];
    if source != 0 {
        if let Ok(read) = guest::try_read_bytes(source, Guid::SIZE as usize) {
            bytes.copy_from_slice(&read);
        }
    }
    bytes
}

/// EtwActivityIdControl(ControlCode, ActivityId). Devolve o NTSTATUS.
pub fn control(code: u32, pointer: u64) -> u32 {
    if code == EVENT_ACTIVITY_CTRL_CREATE_ID {
        return match create_id(pointer) {
            Ok(()) => 0,
            Err(_) => 0xC000_0005,
        };
    }
    let current = thread_activity();
    if current == 0 {
        return STATUS_NOT_SUPPORTED;
    }
    let read = |address: u64| guest::try_read_bytes(address, Guid::SIZE as usize);
    let result = (|| -> Result<u32, crate::rtl::KernelError> {
        match code {
            EVENT_ACTIVITY_CTRL_GET_ID => guest::try_write_bytes(pointer, &read(current)?)?,
            EVENT_ACTIVITY_CTRL_SET_ID => guest::try_write_bytes(current, &read(pointer)?)?,
            EVENT_ACTIVITY_CTRL_GET_SET_ID => {
                let (old, new) = (read(current)?, read(pointer)?);
                guest::try_write_bytes(current, &new)?;
                guest::try_write_bytes(pointer, &old)?;
            }
            EVENT_ACTIVITY_CTRL_CREATE_SET_ID => {
                guest::try_write_bytes(pointer, &read(current)?)?;
                create_id(current)?;
            }
            _ => return Ok(STATUS_INVALID_PARAMETER),
        }
        Ok(0)
    })();
    result.unwrap_or(0xC000_0005)
}
