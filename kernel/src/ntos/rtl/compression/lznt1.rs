//! LZNT1 (COMPRESSION_FORMAT_LZNT1), como o `rtl\lznt1.c` do NT: compressor
//! standard/maximum, descompressão de buffer e de fragmento.
//!
//! Formato: chunks de até 4096 bytes descomprimidos, cada um com cabeçalho
//! USHORT `((tamanho_total - 3) & 0xFFF) | 0x3000 | (comprimido << 15)`. Um
//! chunk comprimido é uma sequência de grupos (byte de flags + 8 tokens):
//! bit 0 = literal, bit 1 = USHORT `((deslocamento - 1) << shift) | (len - 3)`,
//! com o `shift` dado pela posição dentro do chunk (`LZNT1Formats`: 12 até a
//! posição 16, 11 até 32, ..., 4 a partir de 2048).
//!
//! Transcrito do ntoskrnl 19045 e conferido byte a byte contra o mesmo código
//! do `ntdll.dll`:
//! - `RtlCompressBufferLZNT1`/`LZNT1CompressChunk`: chunk que não cabe em
//!   0xFFF bytes vira chunk não comprimido; STATUS_BUFFER_ALL_ZEROS quando todos
//!   os literais são zero; USHORT 0 terminador se couber (fora do tamanho final).
//! - `LZNT1FindMatchStandard`: tabela de hash de 4096 pares de ponteiros no
//!   workspace (+0x20), persistente entre chamadas (usada no lugar, como no
//!   NT); `LZNT1FindMatchMaximum`: busca exaustiva.
//! - `LZNT1DecompressChunk`: match que passa do fim da saída ou aponta antes do
//!   início do chunk dá STATUS_BAD_COMPRESSION_BUFFER; a saída cheia num
//!   literal termina com sucesso.
//! - `RtlDecompressBufferLZNT1`: chunk curto seguido de outro é completado com
//!   zeros até 4096; com `UncompressedChunkSize` != 0 cada chunk comprimido avança
//!   a saída por esse tamanho e, para endereços de kernel com espaço suficiente,
//!   o erro de um chunk (executado no NT por um work item) é guardado e o laço
//!   segue — aqui de forma síncrona, na ordem dos chunks.
//! - `RtlDecompressFragmentLZNT1`: chunks inteiros antes de `FragmentOffset` são
//!   pulados pelo cabeçalho; um chunk parcial é decodificado no workspace.
//!
//! Os caminhos de erro escrevem em `*FinalSize` o mesmo valor que o NT (inclusive
//! os 32 bits baixos do cursor comprimido onde o original faz isso).

use alloc::vec::Vec;

use super::{GuestWindow, STATUS_BAD_COMPRESSION_BUFFER, STATUS_BUFFER_ALL_ZEROS, STATUS_BUFFER_TOO_SMALL};
use crate::ntos::inc::types::{Field, NtStruct, Reserved};
use crate::ntos::mm::guest_memory as guest;

const CHUNK: usize = 0x1000;
/// Maior chunk comprimido (o tamanho total cabe nos 12 bits do cabeçalho).
const MAX_COMPRESSED_CHUNK: usize = 0xFFF;
/// LZNT1Formats (RVA 0x9b3d90): (MaxLength, Boundary, Shift) por posição.
const FORMATS: [(u32, usize, u32); 9] = [(4098, 16, 12), (2050, 32, 11), (1026, 64, 10), (514, 128, 9), (258, 256, 8), (130, 512, 7), (66, 1024, 6), (34, 2048, 5), (18, 4096, 4)];
/// Tabelas do LZNT1DecompressChunk (RVA 0xec00 / 0xec44): limite de posição
/// e máscara de comprimento por `shift`.
const BOUNDARY: [usize; 17] = [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x800, 0x400, 0x200, 0x100, 0x80, 0x40, 0x20, 0x10, 0, 0, 0, 0];
/// Workspace standard: cabeçalho de 0x20 bytes + 4096 pares de ponteiros.
const WORK_SPACE_TABLE: u64 = 0x20;
const HASH_SLOTS: usize = 4096 * 2;
/// MM_USER_PROBE_ADDRESS usado pelo LZNT1DecompressChunkNewThread.
const USER_LIMIT: u64 = 0x7FFF_FFFF_0000;

/// Cabeçalho do workspace do LZNT1 (layout interno do ntoskrnl, sem nome
/// público): início e fim do chunk corrente, MaxLength do formato vigente e o
/// ponteiro do último match. No engine standard seguem 4096 pares de ponteiros
/// da tabela de hash (`LZNT1FindMatchStandard`).
#[repr(C)]
struct WorkSpaceHeader {
    chunk_start: Field<u64>,
    chunk_end: Field<u64>,
    max_length: Field<u32>,
    _pad_14: Reserved<0x4>,
    matched: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for WorkSpaceHeader {}

const _: () = {
    assert!(core::mem::size_of::<WorkSpaceHeader>() == WORK_SPACE_TABLE as usize);
    assert!(core::mem::offset_of!(WorkSpaceHeader, chunk_start) == 0x0);
    assert!(core::mem::offset_of!(WorkSpaceHeader, chunk_end) == 0x8);
    assert!(core::mem::offset_of!(WorkSpaceHeader, max_length) == 0x10);
    assert!(core::mem::offset_of!(WorkSpaceHeader, matched) == 0x18);
};

/// Workspace do chamador, usado no lugar como no NT (a tabela de hash
/// persiste entre chamadas).
struct WorkSpace {
    header: &'static WorkSpaceHeader,
    table: &'static [Field<u64>],
}

impl WorkSpace {
    fn new(address: u64, maximum: bool) -> Self {
        // SAFETY: WorkSpace do chamador com o tamanho de
        // RtlGetCompressionWorkSpaceSize (0x10020 standard, 0x20 maximum),
        // vindo do pool (alinhado).
        let header = unsafe { WorkSpaceHeader::at(address) };
        let table: &'static [Field<u64>] = if maximum { &[] } else { unsafe { Field::<u64>::array_at(address + WORK_SPACE_TABLE, HASH_SLOTS) } };
        WorkSpace { header, table }
    }
}

fn hash(input: &[u8], at: usize) -> usize {
    let value = (((input[at] as u32) << 4 ^ input[at + 1] as u32) << 4) ^ input[at + 2] as u32;
    let product = (value as i32).wrapping_mul(0xFFFF_9E5Fu32 as i32);
    ((product >> 4) & 0xFFF) as usize
}

/// Comprimento de um candidato do hash (0 se fora do chunk ou sem 3 bytes iguais).
fn candidate_length(input: &[u8], base: u64, chunk_start: u64, current: usize, end: usize, candidate: u64, max_length: u32) -> u32 {
    let current_address = base + current as u64;
    if candidate < chunk_start || candidate >= current_address {
        return 0;
    }
    let at = (candidate - base) as usize;
    if input[at..at + 3] != input[current..current + 3] {
        return 0;
    }
    let mut length = 3u32;
    if max_length <= 3 {
        return length;
    }
    while current + (length as usize) < end && input[at + length as usize] == input[current + length as usize] {
        length += 1;
        if length >= max_length {
            break;
        }
    }
    length
}

/// LZNT1FindMatchStandard: dois candidatos por slot; o novo vira o primeiro.
fn find_match_standard(input: &[u8], base: u64, current: usize, end: usize, work_space: &WorkSpace) -> (u32, usize) {
    let slot = hash(input, current) * 2;
    let (first, second) = (work_space.table[slot].get(), work_space.table[slot + 1].get());
    let (chunk_start, max_length) = (work_space.header.chunk_start.get(), work_space.header.max_length.get());
    let first_length = candidate_length(input, base, chunk_start, current, end, first, max_length);
    let second_length = candidate_length(input, base, chunk_start, current, end, second, max_length);
    work_space.table[slot + 1].set(first);
    work_space.table[slot].set(base + current as u64);
    let (length, pointer) = if first_length >= second_length { (first_length, first) } else { (second_length, second) };
    work_space.header.matched.set(pointer);
    (length, pointer.wrapping_sub(base) as usize)
}

/// LZNT1FindMatchMaximum: todas as posições anteriores do chunk; empate fica
/// com a mais próxima.
fn find_match_maximum(input: &[u8], base: u64, start: usize, current: usize, end: usize, work_space: &WorkSpace) -> (u32, usize) {
    let max_length = work_space.header.max_length.get();
    let mut best = 0u32;
    let mut matched = 0usize;
    for candidate in start..current {
        let mut length = 0u32;
        while length < max_length && current + (length as usize) < end && input[candidate + length as usize] == input[current + length as usize] {
            length += 1;
        }
        if length >= best {
            best = length;
            matched = candidate;
            work_space.header.matched.set(base + candidate as u64);
        }
    }
    (if best >= 3 { best } else { 0 }, matched)
}

/// LZNT1CompressChunk: Ok(todos os literais zero) ou STATUS_BUFFER_TOO_SMALL.
#[allow(clippy::too_many_arguments)]
fn compress_chunk(input: &[u8], base: u64, start: usize, output: &mut GuestWindow, cursor: &mut usize, capacity: usize, work_space: &WorkSpace, maximum: bool) -> Result<bool, u32> {
    let end = (start + CHUNK).min(input.len());
    let chunk_out = *cursor;
    let limit = capacity.min(chunk_out + MAX_COMPRESSED_CHUNK);
    work_space.header.chunk_start.set(base + start as u64);
    work_space.header.chunk_end.set(base + end as u64);
    work_space.header.max_length.set(FORMATS[0].0);
    let mut flag_position = chunk_out + 2;
    let mut out = chunk_out + 3;
    let mut flags = 0u8;
    let mut bit = 0u32;
    let mut format = 0usize;
    let mut literals = 0u8;
    let mut current = start;
    let mut overflow = false;
    while current < end {
        while start + FORMATS[format].1 < current {
            format += 1;
            work_space.header.max_length.set(FORMATS[format].0);
        }
        let (length, matched) = if current + 3 <= end {
            if maximum { find_match_maximum(input, base, start, current, end, work_space) } else { find_match_standard(input, base, current, end, work_space) }
        } else {
            (0, 0)
        };
        if length != 0 {
            if out + 1 >= limit {
                overflow = true;
                break;
            }
            let token = ((((current - matched - 1) as u32) << FORMATS[format].2) | (length - 3)) as u16;
            output.put_slice(out, &token.to_le_bytes());
            out += 2;
            current += length as usize;
            flags |= 1 << bit;
        } else {
            if out >= limit {
                overflow = true;
                break;
            }
            output.put(out, input[current]);
            literals |= input[current];
            out += 1;
            current += 1;
            flags &= !(1 << bit);
        }
        bit = (bit + 1) & 7;
        if bit == 0 {
            if current >= end {
                break;
            }
            output.put(flag_position, flags);
            flag_position = out;
            out += 1;
            flags = 0;
        }
    }
    if overflow {
        // Não coube comprimido: chunk não comprimido (pode ser menor que 4096).
        let length = end - start;
        if chunk_out + 2 + length > capacity {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        output.put_slice(chunk_out + 2, &input[start..end]);
        let header = (((length + 2 - 3) & 0xFFF) as u16) | 0x3000;
        output.put_slice(chunk_out, &header.to_le_bytes());
        *cursor = chunk_out + 2 + length;
        return Ok(false);
    }
    if flag_position >= limit {
        out -= 1;
    } else {
        output.put(flag_position, flags);
    }
    let header = (((out - chunk_out - 3) & 0xFFF) as u16) | 0xB000;
    output.put_slice(chunk_out, &header.to_le_bytes());
    *cursor = out;
    Ok(literals == 0)
}

/// RtlCompressBufferLZNT1 (engine standard ou maximum).
pub fn compress(uncompressed: u64, uncompressed_size: u32, compressed: u64, compressed_size: u32, final_size_out: &Field<u32>, work_space: u64, maximum: bool) -> u32 {
    let input = if uncompressed_size == 0 { Vec::new() } else { guest::read_bytes(uncompressed, uncompressed_size as usize) };
    let capacity = compressed_size as usize;
    // Pior caso escrito: cada chunk ocupa no máximo 2 + 4096 bytes, mais o terminador.
    let reach = capacity.min(input.len().div_ceil(CHUNK) * (CHUNK + 2) + 2);
    let mut output = GuestWindow::read(compressed, reach);
    let work_space = WorkSpace::new(work_space, maximum);
    let mut cursor = 0usize;
    let mut all_zero = true;
    let mut status = 0;
    let mut position = 0usize;
    while position < input.len() {
        match compress_chunk(&input, uncompressed, position, &mut output, &mut cursor, reach, &work_space, maximum) {
            Ok(zero) => all_zero &= zero,
            Err(error) => {
                status = error;
                break;
            }
        }
        position += CHUNK;
    }
    if status == 0 && cursor + 2 <= capacity {
        output.put_slice(cursor, &[0, 0]);
    }
    output.flush();
    if status != 0 {
        return status;
    }
    final_size_out.set(cursor as u32);
    if all_zero { STATUS_BUFFER_ALL_ZEROS } else { 0 }
}

/// LZNT1DecompressChunk: decodifica `input[at..end]` em `output` a partir de
/// `out_start`, limitado a `out_end`. Ok(bytes produzidos).
fn decompress_chunk(output: &mut GuestWindow, out_start: usize, out_end: usize, input: &[u8], at: usize, end: usize) -> Result<usize, u32> {
    let mut out = out_start;
    let mut shift = 13usize;
    let mut boundary = out_start;
    let mut group = at;
    loop {
        if group == end {
            return Ok(out - out_start);
        }
        if group > end {
            return Err(STATUS_BAD_COMPRESSION_BUFFER);
        }
        let flags = input[group];
        let mut token = group + 1;
        for bit in 0..8 {
            // Fim do chunk antes da saída cheia; posição além de qualquer um dos dois é erro.
            if token == end {
                return Ok(out - out_start);
            }
            if token > end {
                return Err(STATUS_BAD_COMPRESSION_BUFFER);
            }
            if out == out_end {
                return Ok(out - out_start);
            }
            if out > out_end {
                return Err(STATUS_BAD_COMPRESSION_BUFFER);
            }
            if (flags >> bit) & 1 == 0 {
                output.put(out, input[token]);
                out += 1;
                token += 1;
                continue;
            }
            if token + 2 > end {
                return Err(STATUS_BAD_COMPRESSION_BUFFER);
            }
            while out > boundary {
                shift -= 1;
                boundary = out_start + BOUNDARY[shift];
            }
            let value = u16::from_le_bytes([input[token], input[token + 1]]) as usize;
            let length = (value & ((1 << shift) - 1)) + 3;
            let displacement = (value >> shift) + 1;
            if displacement > out - out_start {
                return Err(STATUS_BAD_COMPRESSION_BUFFER);
            }
            if out + length > out_end {
                return Err(STATUS_BAD_COMPRESSION_BUFFER);
            }
            for _ in 0..length {
                let byte = output.bytes[out - displacement];
                output.put(out, byte);
                out += 1;
            }
            token += 2;
        }
        group = token;
    }
}

fn header_at(input: &[u8], at: usize) -> u16 {
    let low = input.get(at).copied().unwrap_or(0);
    let high = input.get(at + 1).copied().unwrap_or(0);
    u16::from_le_bytes([low, high])
}

/// O NT entrega o chunk a um work item (assíncrono) só com endereços de kernel
/// e espaço de saída para o chunk inteiro (LZNT1DecompressChunkNewThread).
fn runs_asynchronously(out_address: u64, in_address: u64, room: i64, chunk_size: u32) -> bool {
    out_address > USER_LIMIT && in_address > USER_LIMIT && room >= chunk_size as i32 as i64
}

/// RtlDecompressBufferLZNT1(Uncompressed, Size, Compressed, CompressedSize,
/// UncompressedChunkSize, *FinalUncompressedSize).
pub fn decompress_buffer(uncompressed: u64, size: u32, compressed: u64, compressed_size: u32, chunk_size: u32, final_size_out: &Field<u32>) -> u32 {
    let input = if compressed_size == 0 { Vec::new() } else { guest::read_bytes(compressed, compressed_size as usize) };
    let mut output = GuestWindow::read(uncompressed, size as usize);
    let (status, final_size) = decompress_chunks(&input, compressed, &mut output, uncompressed, size as usize, chunk_size);
    output.flush();
    final_size_out.set(final_size);
    status
}

fn decompress_chunks(input: &[u8], compressed: u64, output: &mut GuestWindow, uncompressed: u64, out_end: usize, chunk_size: u32) -> (u32, u32) {
    let input_end = input.len();
    let mut out = 0usize;
    let mut at = 0usize;
    let mut previous = 0u32;
    let mut deferred = 0u32;
    let mut header = header_at(input, 0);
    loop {
        let total = (header as usize & 0xFFF) + 3;
        if at + total > input_end {
            return (STATUS_BAD_COMPRESSION_BUFFER, (compressed + at as u64) as u32);
        }
        let advance;
        if header & 0x8000 == 0 {
            let mut length = total - 2;
            if out + length > out_end {
                length = out_end.saturating_sub(out);
            }
            if at + 2 + length > input_end {
                return (STATUS_BAD_COMPRESSION_BUFFER, (compressed + at as u64) as u32);
            }
            if length != 0 {
                output.put_slice(out, &input[at + 2..at + 2 + length]);
            }
            advance = length;
        } else if chunk_size == 0 {
            match decompress_chunk(output, out, out_end, input, at + 2, at + total) {
                Ok(produced) => advance = produced,
                Err(status) => return (status, previous),
            }
        } else {
            let room = out_end as i64 - out as i64;
            let asynchronous = runs_asynchronously(uncompressed + out as u64, compressed + at as u64 + 2, room, chunk_size);
            if let Err(status) = decompress_chunk(output, out, out_end, input, at + 2, at + total) {
                if !asynchronous {
                    return (status, previous);
                }
                if deferred == 0 {
                    deferred = status;
                }
            }
            advance = chunk_size as usize;
        }
        previous = advance as u32;
        at += total;
        out += advance;
        if out == out_end || at + 2 > input_end {
            break;
        }
        header = header_at(input, at);
        if header == 0 {
            break;
        }
        if advance < CHUNK {
            let fill = CHUNK - advance;
            if out + fill >= out_end {
                break;
            }
            for index in out..out + fill {
                output.put(index, 0);
            }
            out += fill;
        }
    }
    (deferred, out as u32)
}

/// RtlDecompressFragmentLZNT1(Fragment, FragmentSize, Compressed,
/// CompressedSize, FragmentOffset, UncompressedChunkSize,
/// *FinalUncompressedSize, WorkSpace).
#[allow(clippy::too_many_arguments)]
pub fn decompress_fragment(fragment: u64, fragment_size: u32, compressed: u64, compressed_size: u32, fragment_offset: u32, chunk_size: u32, final_size_out: &Field<u32>, work_space: u64) -> u32 {
    let input = if compressed_size == 0 { Vec::new() } else { guest::read_bytes(compressed, compressed_size as usize) };
    let mut output = GuestWindow::read(fragment, fragment_size as usize);
    let mut scratch: Option<GuestWindow> = None;
    let (status, final_size) = fragment_chunks(&input, compressed, &mut output, fragment, fragment_size, fragment_offset, chunk_size, work_space, &mut scratch);
    output.flush();
    if let Some(scratch) = &scratch {
        scratch.flush();
    }
    final_size_out.set(final_size);
    status
}

#[allow(clippy::too_many_arguments)]
fn fragment_chunks(input: &[u8], compressed: u64, output: &mut GuestWindow, fragment: u64, fragment_size: u32, fragment_offset: u32, chunk_size: u32, work_space: u64, scratch: &mut Option<GuestWindow>) -> (u32, u32) {
    let input_end = input.len();
    let out_end = fragment_size as usize;
    let mut out = 0usize;
    let mut remaining = fragment_size;
    let mut at = 0usize;
    let mut header = header_at(input, 0);
    let mut skip = fragment_offset as usize;
    let mut deferred = 0u32;
    let bad = |at: usize| (STATUS_BAD_COMPRESSION_BUFFER, (compressed + at as u64) as u32);
    let mut total = (header as usize & 0xFFF) + 3;
    // Chunks inteiros antes do deslocamento: só o cabeçalho é lido.
    while skip >= CHUNK {
        if at + total > input_end {
            return bad(at);
        }
        skip -= CHUNK;
        at += total;
        if at + 2 > input_end {
            return (0, 0);
        }
        header = header_at(input, at);
        if header == 0 {
            return (0, 0);
        }
        total = (header as usize & 0xFFF) + 3;
    }
    if at + total > input_end {
        return bad(at);
    }
    loop {
        let mut copy = ((CHUNK - skip) as u32).min(remaining);
        if header & 0x8000 == 0 {
            let source = at + 2 + skip;
            if source + copy as usize > input_end {
                return bad(at);
            }
            output.put_slice(out, &input[source..source + copy as usize]);
        } else if skip == 0 && copy as usize == CHUNK {
            if chunk_size == 0 {
                match decompress_chunk(output, out, out_end, input, at + 2, at + total) {
                    Ok(produced) => copy = produced as u32,
                    Err(status) => return (status, copy),
                }
            } else {
                let asynchronous = runs_asynchronously(fragment + out as u64, compressed + at as u64 + 2, out_end as i64 - out as i64, chunk_size);
                if let Err(status) = decompress_chunk(output, out, out_end, input, at + 2, at + total) {
                    if !asynchronous {
                        return (status, copy);
                    }
                    if deferred == 0 {
                        deferred = status;
                    }
                }
                copy = chunk_size;
            }
        } else {
            // Chunk parcial: decodificado inteiro no workspace e copiado.
            let window = scratch.get_or_insert_with(|| GuestWindow::read(work_space, CHUNK));
            let produced = match decompress_chunk(window, 0, CHUNK, input, at + 2, at + total) {
                Ok(produced) => produced as u32,
                Err(status) => return (status, CHUNK as u32),
            };
            let available = produced.wrapping_sub(skip as u32);
            if available < copy {
                let bytes: Vec<u8> = window.bytes[skip..skip + available as usize].to_vec();
                output.put_slice(out, &bytes);
                out += available as usize;
                return (deferred, out as u32);
            }
            let bytes: Vec<u8> = window.bytes[skip..skip + copy as usize].to_vec();
            output.put_slice(out, &bytes);
        }
        skip = 0;
        out += copy as usize;
        remaining = remaining.wrapping_sub(copy);
        if remaining == 0 {
            break;
        }
        at += total;
        if at + 2 > input_end {
            break;
        }
        header = header_at(input, at);
        if header == 0 {
            break;
        }
        total = (header as usize & 0xFFF) + 3;
        if at + total > input_end {
            return bad(at);
        }
    }
    (deferred, out as u32)
}
