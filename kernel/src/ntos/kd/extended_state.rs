//! Registradores além do pacote `g`, só por `p` (extensões do OpenNT):
//!
//! | n.º   | registradores          | bytes |
//! |-------|------------------------|-------|
//! | 59-74 | ymm0h-ymm15h           | 16    |
//! | 75-78 | dr0-dr3                | 8     |
//! | 79    | dr6                    | 8     |
//! | 80    | dr7                    | 8     |
//!
//! A metade alta dos YMM sai de um XSAVE do componente AVX no próprio
//! processador da parada, quando o sistema ligou o XSAVE (CR4.OSXSAVE) e o
//! AVX no XCR0; senão, e nos processadores congelados, fica indisponível.
//! O código do kernel não usa SSE nem AVX, então os registradores da CPU
//! ainda são os do código interrompido.
//!
//! Os registradores de depuração: numa parada de usuário, os do CONTEXT da
//! thread (o banco que ela carrega no anel 3); numa parada do kernel, o
//! conjunto do depurador (os comparadores armados e o DR7 que volta na
//! saída) e o DR6 lido na entrada.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

use super::breakpoints;
use crate::hal::cpu;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::Context;

pub const YMM_HIGH_FIRST: usize = 59;
pub const YMM_HIGH_LAST: usize = 74;
pub const DEBUG_FIRST: usize = 75;
pub const DEBUG_LAST: usize = 80;

const CR4_OSXSAVE: u64 = 1 << 18;
const XCR0_AVX: u64 = 1 << 2;

/// O DR6 da última entrada pelo #DB (gravado por `stop`).
static ENTRY_DR6: AtomicU64 = AtomicU64::new(0xFFFF_0FF0);

pub fn set_entry_dr6(value: u64) {
    ENTRY_DR6.store(value, Ordering::Relaxed);
}

/// Tamanho de um registrador desta faixa (0 = fora dela).
pub fn size(number: usize) -> usize {
    match number {
        YMM_HIGH_FIRST..=YMM_HIGH_LAST => 16,
        DEBUG_FIRST..=DEBUG_LAST => 8,
        _ => 0,
    }
}

/// A área do XSAVE (alinhada a 64 bytes).
#[repr(C, align(64))]
struct Area(UnsafeCell<[u8; 4096]>);

// SAFETY: só o dono da parada usa a área, e há um dono por vez.
unsafe impl Sync for Area {}

static AREA: Area = Area(UnsafeCell::new([0; 4096]));

/// O deslocamento do componente AVX no formato padrão do XSAVE, se o
/// sistema o ligou.
fn avx_offset() -> Option<usize> {
    if cpu::read_cr4() & CR4_OSXSAVE == 0 {
        return None;
    }
    let xcr0_low: u32;
    let xcr0_high: u32;
    // SAFETY: XGETBV (0F 01 D0) com ECX = 0 e o OSXSAVE ligado.
    unsafe { core::arch::asm!(".byte 0x0f, 0x01, 0xd0", in("ecx") 0u32, out("eax") xcr0_low, out("edx") xcr0_high, options(nomem, nostack)) };
    let xcr0 = xcr0_low as u64 | (xcr0_high as u64) << 32;
    if xcr0 & XCR0_AVX == 0 {
        return None;
    }
    let offset = cpu::cpuid_subleaf(0xD, 2)[1] as usize;
    (offset != 0 && offset + 256 <= 4096).then_some(offset)
}

/// Lê o registrador `number` desta faixa em `output`. `owner`: a leitura é
/// do processador da parada; `context`: o CONTEXT da thread de uma parada
/// de usuário.
pub fn read(number: usize, owner: bool, context: Option<u64>, output: &mut [u8]) -> bool {
    let width = size(number);
    if width == 0 || output.len() < width {
        return false;
    }
    match number {
        YMM_HIGH_FIRST..=YMM_HIGH_LAST => {
            if !owner {
                return false;
            }
            let Some(offset) = avx_offset() else { return false };
            let area = AREA.0.get() as u64;
            // SAFETY: XSAVE64 só do componente AVX (EDX:EAX = 4) na área
            // alinhada, com o OSXSAVE ligado; escrito como bytes porque o
            // alvo do kernel não liga o recurso no montador.
            unsafe {
                core::ptr::write_bytes(area as *mut u8, 0, 4096);
                core::arch::asm!(".byte 0x48, 0x0f, 0xae, 0x27", in("rdi") area, in("eax") XCR0_AVX as u32, in("edx") 0u32, options(nostack));
            }
            let start = area + (offset + (number - YMM_HIGH_FIRST) * 16) as u64;
            for (index, byte) in output[..16].iter_mut().enumerate() {
                // SAFETY: dentro da área de 4096 bytes conferida acima.
                *byte = unsafe { core::ptr::read_volatile((start + index as u64) as *const u8) };
            }
            true
        }
        _ => {
            let index = number - DEBUG_FIRST;
            let value = match context {
                Some(address) => {
                    // SAFETY: o CONTEXT vivo da thread parada (memória do kernel).
                    let context = unsafe { Context::at(address) };
                    [context.dr0.get(), context.dr1.get(), context.dr2.get(), context.dr3.get(), context.dr6.get(), context.dr7.get()][index]
                }
                None => match index {
                    0..=3 => breakpoints::hardware_slot(index).map_or(0, |(_, address, _)| address),
                    4 => ENTRY_DR6.load(Ordering::Relaxed),
                    _ => breakpoints::dr7(),
                },
            };
            output[..8].copy_from_slice(&value.to_le_bytes());
            true
        }
    }
}
