//! Atividade corrente do ETW (EtwActivityIdControl).
//!
//! Um GUID de atividade corrente (16 bytes no pool do convidado), que
//! EtwWrite e EtwWriteTransfer usam quando o chamador não passa um ID, e o
//! gerador de IDs novos: uuid v4 por xorshift32 semeado no TSC (o mesmo
//! padrão do Ex).

use crate::hal::cpu;
use crate::ntos::inc::types::{Guid, NtStruct};
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
        activity.current = guest::alloc_bytes(Guid::SIZE);
    }
    let current = activity.current;
    let copy_current = || guest::write_bytes(pointer, &guest::read_bytes(current, Guid::SIZE as usize));
    let store_current = || guest::write_bytes(current, &guest::read_bytes(pointer, Guid::SIZE as usize));
    // uuid v4 por xorshift32 semeado no TSC (o mesmo padrão do Ex).
    let generate = |state: &mut u32| {
        xorshift(state);
        if *state == 0 {
            *state = match cpu::rdtsc() as u32 {
                0 => 0x2545_F491,
                seed => seed,
            };
        }
        let mut bytes = [0u8; 16];
        for word in bytes.chunks_exact_mut(4) {
            xorshift(state);
            word.copy_from_slice(&state.to_le_bytes());
        }
        // Versão 4 e variante RFC (ordem de bytes RFC, como antes).
        bytes[6] = (bytes[6] & 0x0F) | 0x40;
        bytes[8] = (bytes[8] & 0x3F) | 0x80;
        guest::write_bytes(pointer, &bytes);
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
