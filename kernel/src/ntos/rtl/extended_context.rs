//! O CONTEXT estendido (CONTEXT_EX com o XSTATE) do lado do kernel, como as
//! rotinas internas do ntoskrnl 19041 o montam e copiam:
//! RtlpValidateContextFlags, RtlpGetLegacyContextLength,
//! RtlpGetEntireXStateAreaLength, RtlpGetNonLegacyXStateAreaLength,
//! RtlGetExtendedContextLength2, RtlInitializeExtendedContext2 e
//! RtlpCopyXStateChunk. O ntoskrnl 19041 não as exporta (as versões
//! exportadas são as da ntdll, que o modo usuário usa sobre o que o kernel
//! monta); o kernel as usa no despacho de exceções, no frame das APCs de
//! usuário especiais, no NtContinue e no NtGet/SetContextThread.
//!
//! Layout de um CONTEXT estendido x64: o CONTEXT (0x4D0 bytes, alinhado a
//! 16), o CONTEXT_EX logo depois (três CONTEXT_CHUNK de deslocamentos
//! relativos ao próprio CONTEXT_EX: All, Legacy e XState) e, com
//! CONTEXT_XSTATE, o pedaço XSTATE alinhado a 64: o XSAVE_AREA_HEADER (Mask =
//! XSTATE_BV, CompactionMask = XCOMP_BV) seguido dos recursos além do x87 e
//! do SSE, nos deslocamentos da área de XSAVE menos os 0x200 da área legada
//! (que ficam no CONTEXT.FltSave).

use alloc::vec::Vec;

use crate::ntos::inc::types::{ContextEx, NtStruct};
use crate::ntos::ke::xsave::{self, feature, HEADER_SIZE, LEGACY_AND_HEADER, LEGACY_SIZE};
use crate::ntos::mm::guest_memory as guest;

pub const CONTEXT_LENGTH: u32 = 0x4D0;
pub const CONTEXT_EX_LENGTH: u32 = 0x18;
/// CONTEXT_AMD64 e CONTEXT_XSTATE (o bit 6 com a arquitetura).
pub const CONTEXT_AMD64: u32 = 0x10_0000;
pub const CONTEXT_XSTATE: u32 = 0x10_0040;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
pub const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;

/// RtlpValidateContextFlags: os flags de uma das arquiteturas conhecidas;
/// devolve 1, ou 3 com o XSTATE pedido (STATUS_NOT_SUPPORTED sem recursos
/// habilitados).
pub fn validate_context_flags(flags: u32) -> Result<u32, u32> {
    let architecture = flags & 0x27FF_FF80 == 0x1_0000 || flags & 0x27FF_FFA0 == CONTEXT_AMD64 || flags & 0x07FF_FFF0 == 0x20_0000 || flags & 0x07FF_FFE0 == 0x40_0000;
    if !architecture {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if flags & CONTEXT_XSTATE == CONTEXT_XSTATE || flags & 0x1_0040 == 0x1_0040 {
        if xsave::enabled_features() == 0 {
            return Err(STATUS_NOT_SUPPORTED);
        }
        return Ok(3);
    }
    Ok(1)
}

/// RtlpGetLegacyContextLength: (tamanho, alinhamento) do CONTEXT legado de
/// cada arquitetura.
pub fn legacy_context_length(flags: u32) -> (u32, u32) {
    if flags & 0x1_0000 != 0 {
        (0x2CC, 4)
    } else if flags & CONTEXT_AMD64 != 0 {
        (CONTEXT_LENGTH, 0x10)
    } else if flags & 0x20_0000 != 0 {
        (0x1A0, 8)
    } else if flags & 0x40_0000 != 0 {
        (0x390, 0x10)
    } else {
        (0, 0)
    }
}

/// RtlpGetEntireXStateAreaLength(Mask): XState.Size sem a compactação;
/// com ela, 0x240 mais cada recurso de `mask` (AllFeatures, com os
/// alinhados a 64).
pub fn entire_xstate_area_length(mask: u64) -> u32 {
    let config = xsave::configuration();
    if !xsave::compaction() {
        return config.size.get();
    }
    let aligned = config.aligned_features.get();
    let mut length = LEGACY_AND_HEADER;
    for index in 2..64usize {
        let bit = 1u64 << index;
        if mask & bit == 0 {
            continue;
        }
        if aligned & bit != 0 {
            length = (length + 0x3F) & !0x3F;
        }
        length += config.all_features[index].get();
    }
    length
}

/// A máscara de compactação aceita: com a compactação, restrita aos
/// recursos habilitados de usuário, aos de supervisor visíveis e ao bit 63.
fn compaction_mask(mask: u64) -> u64 {
    if xsave::compaction() {
        mask & (xsave::enabled_features() | xsave::enabled_user_visible_supervisor_features() | feature::COMPACTED_FORMAT)
    } else {
        mask
    }
}

/// RtlpGetNonLegacyXStateAreaLength(Mask): o tamanho do pedaço XSTATE de
/// `mask` sem a área legada (que fica no CONTEXT.FltSave); com a
/// compactação, a máscara restrita como em [`compaction_mask`].
pub fn non_legacy_xstate_area_length(mask: u64) -> u32 {
    entire_xstate_area_length(compaction_mask(mask)) - LEGACY_SIZE
}

/// RtlGetExtendedContextLength2(ContextFlags, XStateCompactionMask): o
/// tamanho a reservar para um CONTEXT estendido (com a folga do
/// alinhamento).
pub fn extended_context_length2(flags: u32, mask: u64) -> Result<u32, u32> {
    let extended = validate_context_flags(flags)?;
    let (legacy, alignment) = legacy_context_length(flags);
    let mut length = legacy + CONTEXT_EX_LENGTH;
    if extended & 2 != 0 {
        let aligned = (length + alignment - 1) & !(alignment - 1);
        let area = entire_xstate_area_length(compaction_mask(mask));
        length = area + aligned - alignment - (LEGACY_SIZE - 0x40);
    }
    Ok(length - 1 + alignment)
}

/// RtlInitializeExtendedContext2(Context, ContextFlags, XStateCompactionMask):
/// grava os flags no CONTEXT (alinhado), os pedaços do CONTEXT_EX e, com
/// XSTATE, zera o pedaço (com a compactação, CompactionMask = máscara | bit
/// 63). Devolve o endereço do CONTEXT_EX.
pub fn initialize_extended_context2(context: u64, flags: u32, mask: u64) -> Result<u64, u32> {
    let extended = validate_context_flags(flags)?;
    if flags & CONTEXT_AMD64 == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let aligned = (context + 0xF) & !0xF;
    guest::write32(aligned + 0x30, flags);
    let context_ex = aligned + CONTEXT_LENGTH as u64;
    // SAFETY: o CONTEXT_EX do buffer do chamador (memória do kernel).
    let chunks = unsafe { ContextEx::at(context_ex) };
    let legacy = (context_ex - aligned) as u32;
    chunks.legacy.length.set(legacy);
    chunks.legacy.offset.set(-(legacy as i32));
    chunks.all.offset.set(-(legacy as i32));
    chunks.all.length.set(legacy + CONTEXT_EX_LENGTH);
    if extended & 2 == 0 {
        chunks.x_state.offset.set(0x19);
        chunks.x_state.length.set(0);
        return Ok(context_ex);
    }
    let header = (context_ex + CONTEXT_EX_LENGTH as u64 + 0x3F) & !0x3F;
    let mask = compaction_mask(mask);
    let length = non_legacy_xstate_area_length(mask);
    guest::write_bytes(header, &alloc::vec![0; length as usize]);
    if xsave::compaction() {
        guest::write64(header + 8, mask | feature::COMPACTED_FORMAT);
    }
    let offset = (header - context_ex) as u32;
    chunks.x_state.offset.set(offset as i32);
    chunks.all.length.set(offset.wrapping_add(legacy) + length);
    chunks.x_state.length.set(length);
    Ok(context_ex)
}

/// O pedaço XSTATE de um CONTEXT_EX: (endereço do cabeçalho, tamanho).
pub fn xstate_chunk(context_ex: u64) -> (u64, u32) {
    // SAFETY: CONTEXT_EX em memória do kernel do chamador.
    let chunks = unsafe { ContextEx::at(context_ex) };
    (context_ex.wrapping_add(chunks.x_state.offset.get() as i64 as u64), chunks.x_state.length.get())
}

/// RtlpCopyXStateChunk(1, Destination, DestinationChunks, Source,
/// SourceChunks): cabeçalho de destino zerado, Mask = (EnabledFeatures |
/// supervisor visível) & Mask da origem sem x87 e SSE; CompactionMask, com a
/// compactação, a da origem restrita aos habilitados (com x87 e SSE) | bit
/// 63; os recursos de Mask copiados nos deslocamentos do layout (o padrão,
/// ou o compactado pelo CompactionMask). Um recurso além de um dos tamanhos
/// dá STATUS_BUFFER_OVERFLOW. Devolve as faixas copiadas (relativas ao
/// cabeçalho, além dele), para quem leva o resultado a outro buffer.
pub fn copy_xstate_chunk(destination_ex: u64, destination_chunks: u64, source_ex: u64, source_chunks: u64) -> Result<Vec<(u32, u32)>, u32> {
    let (destination, destination_length) = {
        // SAFETY: CONTEXT_EX do chamador.
        let chunks = unsafe { ContextEx::at(destination_chunks) };
        (destination_ex.wrapping_add(chunks.x_state.offset.get() as i64 as u64), chunks.x_state.length.get())
    };
    let (source, source_length) = {
        // SAFETY: CONTEXT_EX do chamador.
        let chunks = unsafe { ContextEx::at(source_chunks) };
        (source_ex.wrapping_add(chunks.x_state.offset.get() as i64 as u64), chunks.x_state.length.get())
    };
    if destination_length < HEADER_SIZE || source_length < HEADER_SIZE {
        return Err(STATUS_BUFFER_OVERFLOW);
    }
    guest::write_bytes(destination, &[0; HEADER_SIZE as usize]);
    let config = xsave::configuration();
    let visible = config.enabled_features.get() | config.enabled_user_visible_supervisor_features.get();
    let mut remaining = visible & guest::read64(source) & !feature::LEGACY;
    guest::write64(destination, remaining);
    let compaction = xsave::compaction();
    let (compacted, aligned) = if compaction { (((visible | feature::LEGACY) & guest::read64(source + 8)) | feature::COMPACTED_FORMAT, config.aligned_features.get()) } else { (0, 0) };
    guest::write64(destination + 8, compacted);
    let (mut start, mut end) = (HEADER_SIZE, HEADER_SIZE);
    let mut copied = Vec::new();
    for index in 2..64usize {
        if remaining == 0 {
            break;
        }
        let bit = 1u64 << index;
        if compaction {
            if compacted & bit != 0 {
                start = end;
                if aligned & bit != 0 {
                    start = (end + 0x3F) & !0x3F;
                }
                end = config.all_features[index].get().wrapping_add(start);
            }
        } else {
            let offset = config.features[index].offset.get();
            end = config.features[index].size.get().wrapping_sub(LEGACY_SIZE).wrapping_add(offset);
            start = offset.wrapping_sub(LEGACY_SIZE);
        }
        if remaining & bit != 0 {
            if end > destination_length || end > source_length {
                return Err(STATUS_BUFFER_OVERFLOW);
            }
            let bytes = guest::read_bytes(source + start as u64, (end - start) as usize);
            guest::write_bytes(destination + start as u64, &bytes);
            copied.push((start, end));
            remaining &= !bit;
        }
    }
    Ok(copied)
}
