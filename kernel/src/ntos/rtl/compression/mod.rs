//! Compressão do Rtl, como no NT: RtlGetCompressionWorkSpaceSize,
//! RtlCompressBuffer, RtlDecompressBufferEx2 e RtlDecompressFragmentEx.
//!
//! Contrato (ntoskrnl 10.0.19045): o formato é o byte baixo de
//! `CompressionFormatAndEngine` (0/1 → STATUS_INVALID_PARAMETER; acima de 4 →
//! STATUS_UNSUPPORTED_COMPRESSION) e indexa as tabelas `RtlWorkSpaceProcs`,
//! `RtlCompressBufferProcs`, `RtlDecompressBufferProcs` e
//! `RtlDecompressFragmentProcs`:
//!
//! | formato | workspace (standard / maximum, fragmento) | fragmento |
//! | --- | --- | --- |
//! | 2 LZNT1 | 0x10020 / 0x20, 0x1000 | `lznt1` |
//! | 3 XPRESS | 0xEF27 / 0x60007, 0 | STATUS_UNSUPPORTED_COMPRESSION |
//! | 4 XPRESS_HUFF | 0x28A5F / 0x159B3F, 0x1429 | STATUS_UNSUPPORTED_COMPRESSION |
//!
//! O engine (`& 0xFF00`) só vale 0 (standard) ou 0x100 (maximum); outro valor dá
//! STATUS_NOT_SUPPORTED sem tocar nas saídas. A descompressão ignora o engine.
//!
//! Os buffers de bytes são copiados em bloco (`read_bytes`/`write_bytes`),
//! processados e devolvidos só nas faixas que o NT escreve (inclusive a saída parcial
//! dos caminhos de erro). O LZNT1 e os três descompressores reproduzem o
//! ntoskrnl byte a byte (conferido contra o mesmo código do `ntdll.dll`); os
//! compressores XPRESS geram fluxos MS-XCA válidos com o mesmo contrato de
//! status, mas não a mesma escolha de matches do compressor da Microsoft.

pub mod lznt1;
pub mod xpress;
pub mod xpress_huffman;

use crate::ntos::inc::types::Field;
use crate::ntos::mm::guest_memory as guest;

pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
pub const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
pub const STATUS_INVALID_USER_BUFFER: u32 = 0xC000_00E8;
pub const STATUS_BAD_COMPRESSION_BUFFER: u32 = 0xC000_0242;
pub const STATUS_UNSUPPORTED_COMPRESSION: u32 = 0xC000_025F;
pub const STATUS_BUFFER_ALL_ZEROS: u32 = 0x0000_0117;

pub const COMPRESSION_FORMAT_LZNT1: u16 = 2;
pub const COMPRESSION_FORMAT_XPRESS: u16 = 3;
pub const COMPRESSION_FORMAT_XPRESS_HUFF: u16 = 4;
pub const COMPRESSION_ENGINE_STANDARD: u16 = 0x0000;
pub const COMPRESSION_ENGINE_MAXIMUM: u16 = 0x0100;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Lznt1,
    Xpress,
    XpressHuffman,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Engine {
    Standard,
    Maximum,
}

fn format(format_and_engine: u16) -> Result<Format, u32> {
    match format_and_engine & 0xFF {
        0 | 1 => Err(STATUS_INVALID_PARAMETER),
        COMPRESSION_FORMAT_LZNT1 => Ok(Format::Lznt1),
        COMPRESSION_FORMAT_XPRESS => Ok(Format::Xpress),
        COMPRESSION_FORMAT_XPRESS_HUFF => Ok(Format::XpressHuffman),
        _ => Err(STATUS_UNSUPPORTED_COMPRESSION),
    }
}

fn engine(format_and_engine: u16) -> Result<Engine, u32> {
    match format_and_engine & 0xFF00 {
        COMPRESSION_ENGINE_STANDARD => Ok(Engine::Standard),
        COMPRESSION_ENGINE_MAXIMUM => Ok(Engine::Maximum),
        _ => Err(STATUS_NOT_SUPPORTED),
    }
}

/// RtlGetCompressionWorkSpaceSize(FormatAndEngine, *BufferWorkSpaceSize,
/// *FragmentWorkSpaceSize): constantes de `RtlCompressWorkSpaceSize*`.
pub fn work_space_size(format_and_engine: u16, buffer_size_out: &Field<u32>, fragment_size_out: &Field<u32>) -> u32 {
    let format = match format(format_and_engine) {
        Ok(format) => format,
        Err(status) => return status,
    };
    let engine = match engine(format_and_engine) {
        Ok(engine) => engine,
        Err(status) => return status,
    };
    let (buffer, fragment) = match (format, engine) {
        (Format::Lznt1, Engine::Standard) => (0x10020, 0x1000),
        (Format::Lznt1, Engine::Maximum) => (0x20, 0x1000),
        (Format::Xpress, Engine::Standard) => (0xEF27, 0),
        (Format::Xpress, Engine::Maximum) => (0x6_0007, 0),
        (Format::XpressHuffman, Engine::Standard) => (0x2_8A5F, 0x1429),
        (Format::XpressHuffman, Engine::Maximum) => (0x15_9B3F, 0x1429),
    };
    buffer_size_out.set(buffer);
    fragment_size_out.set(fragment);
    0
}

/// RtlCompressBuffer(FormatAndEngine, Uncompressed, UncompressedSize,
/// Compressed, CompressedSize, UncompressedChunkSize, *FinalCompressedSize,
/// WorkSpace). `UncompressedChunkSize` é ignorado por todos os formatos.
#[allow(clippy::too_many_arguments)]
pub fn compress_buffer(format_and_engine: u16, uncompressed: u64, uncompressed_size: u32, compressed: u64, compressed_size: u32, final_size_out: &Field<u32>, work_space: u64) -> u32 {
    let format = match format(format_and_engine) {
        Ok(format) => format,
        Err(status) => return status,
    };
    let engine = match engine(format_and_engine) {
        Ok(engine) => engine,
        Err(status) => return status,
    };
    match format {
        Format::Lznt1 => lznt1::compress(uncompressed, uncompressed_size, compressed, compressed_size, final_size_out, work_space, engine == Engine::Maximum),
        Format::Xpress => xpress::compress(uncompressed, uncompressed_size, compressed, compressed_size, final_size_out),
        Format::XpressHuffman => xpress_huffman::compress(uncompressed, uncompressed_size, compressed, compressed_size, final_size_out),
    }
}

/// RtlDecompressBufferEx2(Format, Uncompressed, UncompressedSize, Compressed,
/// CompressedSize, UncompressedChunkSize, *FinalUncompressedSize, WorkSpace).
#[allow(clippy::too_many_arguments)]
pub fn decompress_buffer(format_and_engine: u16, uncompressed: u64, uncompressed_size: u32, compressed: u64, compressed_size: u32, chunk_size: u32, final_size_out: &Field<u32>, work_space: u64) -> u32 {
    match format(format_and_engine) {
        Err(status) => status,
        Ok(Format::Lznt1) => lznt1::decompress_buffer(uncompressed, uncompressed_size, compressed, compressed_size, chunk_size, final_size_out),
        Ok(Format::Xpress) => xpress::decompress(uncompressed, uncompressed_size, compressed, compressed_size, final_size_out),
        Ok(Format::XpressHuffman) => {
            if work_space == 0 {
                return STATUS_INVALID_USER_BUFFER;
            }
            xpress_huffman::decompress(uncompressed, uncompressed_size, compressed, compressed_size, final_size_out, work_space)
        }
    }
}

/// RtlDecompressFragmentEx(Format, Fragment, FragmentSize, Compressed,
/// CompressedSize, FragmentOffset, UncompressedChunkSize,
/// *FinalUncompressedSize, WorkSpace): só o LZNT1 tem fragmentos
/// (`RtlDecompressFragmentNS` para os XPRESS).
#[allow(clippy::too_many_arguments)]
pub fn decompress_fragment(format_and_engine: u16, fragment: u64, fragment_size: u32, compressed: u64, compressed_size: u32, fragment_offset: u32, chunk_size: u32, final_size_out: &Field<u32>, work_space: u64) -> u32 {
    match format(format_and_engine) {
        Err(status) => status,
        Ok(Format::Lznt1) => lznt1::decompress_fragment(fragment, fragment_size, compressed, compressed_size, fragment_offset, chunk_size, final_size_out, work_space),
        Ok(_) => STATUS_UNSUPPORTED_COMPRESSION,
    }
}

/// Janela de um buffer do convidado lida para o host; `flush` devolve só a
/// faixa `[0, high_water)` que foi escrita, preservando o resto do buffer.
pub(crate) struct GuestWindow {
    pub address: u64,
    pub bytes: alloc::vec::Vec<u8>,
    pub high_water: usize,
}

impl GuestWindow {
    pub fn read(address: u64, length: usize) -> Self {
        let bytes = if length == 0 { alloc::vec::Vec::new() } else { guest::read_bytes(address, length) };
        GuestWindow { address, bytes, high_water: 0 }
    }

    pub fn put(&mut self, index: usize, value: u8) {
        self.bytes[index] = value;
        if index + 1 > self.high_water {
            self.high_water = index + 1;
        }
    }

    pub fn put_slice(&mut self, index: usize, values: &[u8]) {
        self.bytes[index..index + values.len()].copy_from_slice(values);
        if index + values.len() > self.high_water {
            self.high_water = index + values.len();
        }
    }

    pub fn flush(&self) {
        if self.high_water != 0 {
            guest::write_bytes(self.address, &self.bytes[..self.high_water]);
        }
    }
}
