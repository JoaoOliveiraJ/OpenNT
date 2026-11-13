//! Atividade corrente do ETW (EtwActivityIdControl).
//!
//! Um GUID de atividade corrente (16 bytes no pool do convidado), que
//! EtwWrite e EtwWriteTransfer usam quando o chamador não passa um ID, e o
//! gerador de IDs novos: uuid v4 por xorshift32 semeado no TSC (o mesmo
//! padrão do Ex).

use crate::hal::cpu;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

struct Activity {
    /// GUID da atividade corrente (16 bytes).
    current: u64,
    /// Estado do gerador xorshift32 (CREATE_ID).
    random: u32,
}

static ACTIVITY: SpinLock<Activity> = SpinLock::new(Activity { current: 0, random: 0 });

/// Sem ID explícito vale a atividade mantida pelo EtwActivityIdControl.
pub fn resolve(explicit: u64) -> u64 {
    if explicit != 0 { explicit } else { ACTIVITY.lock().current }
}

fn xorshift(state: &mut u32) {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
}

/// EtwActivityIdControl(code, &guid): GET_ID=1, SET_ID=2, CREATE_ID=3,
/// GET_SET_ID=4, CREATE_SET_ID=5 (evntprov.h) sobre o GUID corrente.
/// Devolve o NTSTATUS.
pub fn control(code: u32, pointer: u64) -> u32 {
    let mut activity = ACTIVITY.lock();
    if activity.current == 0 {
        activity.current = guest::alloc_bytes(16);
    }
    let current = activity.current;
    let copy_current = || {
        for byte in 0..16 {
            guest::write8(pointer + byte, guest::read8(current + byte));
        }
    };
    let store_current = || {
        for byte in 0..16 {
            guest::write8(current + byte, guest::read8(pointer + byte));
        }
    };
    // uuid v4 por xorshift32 semeado no TSC (o mesmo padrão do Ex).
    let generate = |state: &mut u32| {
        xorshift(state);
        if *state == 0 {
            *state = match cpu::rdtsc() as u32 {
                0 => 0x2545_F491,
                seed => seed,
            };
        }
        for word in 0..4 {
            xorshift(state);
            guest::write32(pointer + word * 4, *state);
        }
        guest::write8(pointer + 6, (guest::read8(pointer + 6) & 0x0F) | 0x40);
        guest::write8(pointer + 8, (guest::read8(pointer + 8) & 0x3F) | 0x80);
    };
    match code {
        1 => copy_current(),
        2 => store_current(),
        3 => generate(&mut activity.random),
        4 => {
            copy_current();
            store_current();
        }
        5 => {
            generate(&mut activity.random);
            store_current();
        }
        _ => return STATUS_INVALID_PARAMETER,
    }
    0
}
