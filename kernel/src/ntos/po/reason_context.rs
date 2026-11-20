//! Captura do COUNTED_REASON_CONTEXT (PoCaptureReasonContext, de modo
//! kernel e de modo usuário) e a liberação dele (PoDestroyReasonContext).
//!
//! As validações são as do PopCaptureReasonContext do ntoskrnl 19041
//! (0x34c910):
//! - Version acima de POWER_REQUEST_CONTEXT_VERSION (0) é inválida;
//!   POWER_REQUEST_CONTEXT_SIMPLE_STRING (1) exige SimpleString com Length
//!   par; POWER_REQUEST_CONTEXT_DETAILED_STRING (2) exige ResourceFileName
//!   com Length par e StringCount * 16 dentro de 32 bits; sem nenhum dos
//!   dois, só o bit 31 (contexto não especificado) é aceito, e um contexto
//!   NULL vale como ele.
//! - Cada texto é copiado com o terminador (PopSafeCopyUnicodeString
//!   0x34cbe8) e um NUL no meio dele (o comprimento copiado diferente de
//!   Length) é STATUS_INVALID_PARAMETER.
//! - De modo usuário (o NtPowerInformation já capturou os 0x28 bytes da
//!   estrutura) os textos e o vetor ReasonStrings são memória do chamador: o
//!   vetor alinhado a 4 e cada Buffer alinhado a 2 (senão
//!   STATUS_DATATYPE_MISALIGNMENT, o ExRaiseDatatypeMisalignment), sondados
//!   para leitura (senão STATUS_ACCESS_VIOLATION).
//!
//! O bloco capturado é de pool paginado 'PRCx' com o tamanho do original
//! (0x38 sem textos, 0x58 + textos com os terminadores). Por dentro guarda o
//! tipo do requisitante no primeiro ULONG, como o PoGetRequester (0 para um
//! pedido de kernel, 1 para um processo, o que o PopCreatePowerRequestObject
//! lê para escolher o dono do objeto), as Flags e os textos copiados, no
//! layout próprio do OpenNT (o objeto requisitante, que o NT referencia, não
//! é guardado).

use alloc::vec::Vec;

use crate::ntos::ex::pool_allocation;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user_probe;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const PAGED_POOL: u32 = 1;
const REASON_TAG: u32 = u32::from_le_bytes(*b"PRCx");
const SIMPLE_STRING: u32 = 1;
const DETAILED_STRING: u32 = 2;
const NOT_SPECIFIED: u32 = 0x8000_0000;
/// Cabeçalho do bloco capturado: requisitante, Flags, contagem.
const HEADER_SIZE: u64 = 0x38;
const TEXT_HEADER_SIZE: u64 = 0x58;
/// Tamanho do COUNTED_REASON_CONTEXT.
pub const CONTEXT_SIZE: usize = 0x28;
/// O tipo do requisitante no começo do bloco (PoGetRequester).
const REQUESTER_KERNEL: u32 = 0;
const REQUESTER_PROCESS: u32 = 1;

/// (Length, Buffer) de um UNICODE_STRING de 16 bytes.
fn unicode(bytes: &[u8]) -> (u16, u64) {
    (u16::from_le_bytes([bytes[0], bytes[1]]), u64::from_le_bytes(bytes[8..16].try_into().unwrap_or([0; 8])))
}

/// `length` bytes de `address`, sondados de modo usuário.
fn read(user: bool, address: u64, length: usize) -> Result<Vec<u8>, u32> {
    if length == 0 {
        return Ok(Vec::new());
    }
    if !user {
        return Ok(guest::read_bytes(address, length));
    }
    if !user_probe::probe_user_read(address, length as u64) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    guest::try_read_bytes(address, length).map_err(|error| error.status)
}

/// PoCaptureReasonContext(Context, KernelMode): o bloco capturado.
pub fn capture(context: u64) -> Result<u64, u32> {
    let header = if context == 0 { None } else { Some(guest::read_bytes(context, CONTEXT_SIZE)) };
    capture_from(header.as_deref(), false)
}

/// PoCaptureReasonContext(Context, UserMode, AlreadyCaptured = TRUE) sobre
/// os 0x28 bytes que o NtPowerInformation capturou (vazio = NULL).
pub fn capture_user(context: &[u8]) -> Result<u64, u32> {
    if context.is_empty() {
        return capture_from(None, true);
    }
    if context.len() < CONTEXT_SIZE {
        return Err(STATUS_INVALID_PARAMETER);
    }
    capture_from(Some(&context[..CONTEXT_SIZE]), true)
}

/// PopCaptureReasonContext sobre a estrutura (já na memória do kernel).
fn capture_from(context: Option<&[u8]>, user: bool) -> Result<u64, u32> {
    // (Length, Buffer) dos textos, na ordem do bloco.
    let mut texts: Vec<(u16, u64)> = Vec::new();
    let (flags, size) = match context {
        None => (NOT_SPECIFIED, HEADER_SIZE),
        Some(context) => {
            if u32::from_le_bytes([context[0], context[1], context[2], context[3]]) > 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let flags = u32::from_le_bytes([context[4], context[5], context[6], context[7]]);
            if flags & SIMPLE_STRING != 0 || flags & DETAILED_STRING != 0 {
                let first = unicode(&context[8..0x18]);
                if first.0 & 1 != 0 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                let mut size = first.0 as u64 + 2 + TEXT_HEADER_SIZE;
                texts.push(first);
                if flags & SIMPLE_STRING == 0 {
                    let count = u32::from_le_bytes([context[0x1C], context[0x1D], context[0x1E], context[0x1F]]);
                    let array_size = (count as u64) << 4;
                    if array_size > u32::MAX as u64 {
                        return Err(STATUS_INVALID_PARAMETER);
                    }
                    let strings = u64::from_le_bytes(context[0x20..0x28].try_into().unwrap_or([0; 8]));
                    if user && count != 0 && strings & 3 != 0 {
                        return Err(STATUS_DATATYPE_MISALIGNMENT);
                    }
                    let array = read(user, strings, array_size as usize)?;
                    for entry in array.chunks_exact(0x10) {
                        let text = unicode(entry);
                        size = size.checked_add(text.0 as u64 + 2).ok_or(STATUS_INVALID_PARAMETER)?;
                        texts.push(text);
                    }
                }
                (flags, size)
            } else if flags & NOT_SPECIFIED != 0 {
                (flags, HEADER_SIZE)
            } else {
                return Err(STATUS_INVALID_PARAMETER);
            }
        }
    };
    // Os textos lidos antes da alocação: uma falha não deixa bloco.
    let mut copies: Vec<Vec<u8>> = Vec::with_capacity(texts.len());
    for &(length, buffer) in &texts {
        if user && length != 0 && buffer & 1 != 0 {
            return Err(STATUS_DATATYPE_MISALIGNMENT);
        }
        let text = read(user, buffer, length as usize)?;
        // O RtlStringCbCopyUnicodeString para no primeiro NUL.
        if text.chunks_exact(2).any(|unit| unit == [0, 0]) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        copies.push(text);
    }
    let block = pool_allocation::allocate_tagged(PAGED_POOL, size, REASON_TAG).unwrap_or(0);
    if block == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(block, &alloc::vec![0u8; size as usize]);
    guest::write32(block, if user { REQUESTER_PROCESS } else { REQUESTER_KERNEL });
    guest::write32(block + 4, flags);
    guest::write32(block + 0x30, copies.len() as u32);
    let mut cursor = block + if copies.is_empty() { HEADER_SIZE } else { TEXT_HEADER_SIZE };
    for text in copies {
        guest::write_bytes(cursor, &text);
        cursor += text.len() as u64 + 2;
    }
    Ok(block)
}

/// O tipo do requisitante gravado na captura: um processo (modo usuário).
pub fn requested_by_process(block: u64) -> bool {
    block != 0 && guest::read32(block) == REQUESTER_PROCESS
}

/// PoDestroyReasonContext.
pub fn destroy(block: u64) {
    if block != 0 {
        let _ = pool_allocation::free(block, 0);
    }
}
