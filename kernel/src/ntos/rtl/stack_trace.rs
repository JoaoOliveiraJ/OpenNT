//! Captura da pilha do chamador — RtlCaptureStackBackTrace.
//!
//! Varre a pilha a partir do quadro de entrada do export por valores que
//! caem dentro de imagens carregadas (endereços de retorno). As leituras são
//! protegidas e limitadas: sem nada reconhecível, nada é capturado.

use crate::ntos::inc::types::{Field, NtStruct};
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
                    // SAFETY: PVOID BackTrace[FramesToCapture] do chamador.
                    unsafe { Field::<u64>::at(back_trace + captured as u64 * 8) }.set(value);
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
        // SAFETY: PULONG BackTraceHash do chamador.
        unsafe { Field::<u32>::at(hash_out) }.set(hash);
    }
    captured as u64
}

/// Flags aceitos pelo RtlWalkFrameChain: modo (bits 0..1) e quadros a pular
/// (bits 8..15).
const WALK_INVALID_FLAGS: u32 = 0xFFFF_00FC;
const WALK_USER_MODE_STACK: u32 = 1;

/// RtlWalkFrameChain(Callers, Count, Flags) (ntoskrnl 19045, 0x21ce70):
/// flags inválidos, mais de 0xFE quadros a pular ou Count = -1 devolvem 0. A
/// pilha de kernel é percorrida a partir do quadro de entrada do export com a
/// mesma varredura do RtlCaptureStackBackTrace (endereços de retorno em imagens
/// carregadas), pulando `(Flags >> 8) & 0xFF` quadros.
///
/// Pilha de usuário (Flags bit 0): o NT desenrola a partir do trap frame de
/// modo usuário da thread; esse caminho não tem o trap frame do usuário aqui e
/// devolve 0 quadros, o mesmo resultado do NT para uma thread sem contexto de
/// usuário.
pub fn walk_frame_chain(frame: u64, callers: u64, count: u32, flags: u32) -> u32 {
    let skip = flags >> 8;
    if flags & WALK_INVALID_FLAGS != 0 || skip > 0xFE || count == u32::MAX {
        return 0;
    }
    if flags & WALK_USER_MODE_STACK != 0 {
        return 0;
    }
    capture_back_trace(frame, skip as usize, count as usize, callers, 0) as u32
}
