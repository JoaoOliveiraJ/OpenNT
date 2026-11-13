//! Captura da pilha do chamador — RtlCaptureStackBackTrace.
//!
//! Varre a pilha a partir do quadro de entrada do export por valores que
//! caem dentro de imagens carregadas (endereços de retorno). As leituras são
//! protegidas e limitadas: sem nada reconhecível, nada é capturado.

use crate::ntos::mm::guest_memory as guest;

/// Máximo de quadros por captura.
const MAXIMUM_FRAMES: usize = 0xC0;
/// Slots de pilha examinados por captura.
const MAXIMUM_SCANNED_SLOTS: usize = 1024;

/// RtlCaptureStackBackTrace(Skip, Capture, PVOID* BackTrace, PULONG Hash):
/// devolve quantos endereços foram gravados; o hash é a soma dos 32 bits
/// baixos deles.
pub fn capture_back_trace(frame: u64, skip: usize, capture: usize, back_trace: u64, hash_out: u64) -> u64 {
    let want = capture.min(MAXIMUM_FRAMES);
    let (mut captured, mut seen, mut hash, mut slot, mut scanned) = (0usize, 0usize, 0u32, frame, 0usize);
    while captured < want && scanned < MAXIMUM_SCANNED_SLOTS {
        if let Ok(value) = guest::try_read64(slot) {
            if value != 0 && crate::ntos::mm::loaded_images::find(value).is_some() {
                if seen >= skip {
                    guest::write64(back_trace + captured as u64 * 8, value);
                    hash = hash.wrapping_add(value as u32);
                    captured += 1;
                }
                seen += 1;
            }
        }
        slot += 8;
        scanned += 1;
    }
    if hash_out != 0 {
        guest::write32(hash_out, hash);
    }
    captured as u64
}
