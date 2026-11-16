//! Autoteste de RtlDecompressBuffer, RtlDecompressBufferEx,
//! RtlDecompressFragment e RtlGetCompressionWorkSpaceSize, chamados pelo
//! trampolim nativo (ABI MS x64).
//!
//! Os fluxos embutidos são a saída do RtlCompressBuffer do Windows 10 19041
//! (LZNT1, XPRESS e XPRESS_HUFF). Os status, os tamanhos finais e o conteúdo dos
//! buffers depois de cada chamada — inclusive com entradas truncadas, saídas de
//! tamanho errado e formatos inválidos — foram medidos nas mesmas rotinas, com a
//! saída preenchida antes com 0xCC, `*FinalUncompressedSize` com 0xAAAAAAAA e o
//! workspace de fragmento com 0x5A. O texto descomprimido é regenerado aqui por
//! `sample` e `phrase`.

use alloc::vec;
use alloc::vec::Vec;

use crate::ntos::inc::{types as nt, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::compression::{STATUS_BAD_COMPRESSION_BUFFER, STATUS_INVALID_PARAMETER, STATUS_INVALID_USER_BUFFER, STATUS_NOT_SUPPORTED, STATUS_UNSUPPORTED_COMPRESSION};

type Assert = fn(bool, &str);

/// Valor prévio das saídas ULONG: o que não foi escrito continua assim.
const UNTOUCHED: u32 = 0xAAAA_AAAA;
/// Byte prévio dos buffers de saída.
const FILL: u8 = 0xCC;
/// Byte prévio do workspace de fragmento.
const WORK_FILL: u8 = 0x5A;
/// Folga depois de cada saída, para ver que nada além do tamanho é escrito.
const SLACK: usize = 16;
/// CompressFragmentWorkSpaceSize do XPRESS_HUFF: a tabela de decodificação.
const HUFF_WORK_SPACE: usize = 0x1429;

/// LZNT1 de `sample(200)`: um chunk comprimido.
const LZNT1_SAMPLE: [u8; 69] = [
    0x42, 0xb0, 0x00, 0x64, 0x72, 0x69, 0x76, 0x65, 0x72, 0x20, 0x78, 0x40, 0x70, 0x72, 0x65, 0x73, 0x73, 0x20, 0x04, 0xd0,
    0x6b, 0xc0, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x20, 0x04, 0x30, 0x0b, 0x88, 0x3f, 0x04, 0xa4, 0x0b, 0x88, 0x04, 0x1a, 0x04,
    0x36, 0x0b, 0x44, 0x04, 0x7c, 0x63, 0x68, 0xf8, 0x75, 0x6e, 0x6b, 0x0c, 0xa4, 0x04, 0x6c, 0x03, 0x1a, 0x0a, 0x20, 0x03,
    0x0c, 0x07, 0x04, 0x48, 0x04, 0x41, 0x19, 0x06, 0x63,
];

/// LZNT1 de `phrase(4296)`: chunk de 4096 bytes (352 comprimidos) e chunk de
/// 200 bytes (48 comprimidos, a partir do byte 352).
const LZNT1_TWO_CHUNKS: [u8; 400] = [
    0x5d, 0xb1, 0x00, 0x4f, 0x70, 0x65, 0x6e, 0x4e, 0x54, 0x20, 0x64, 0x00, 0x65, 0x73, 0x63, 0x6f, 0x6d, 0x70, 0x72, 0x69,
    0x00, 0x6d, 0x65, 0x20, 0x6f, 0x20, 0x66, 0x72, 0x61, 0x00, 0x67, 0x6d, 0x65, 0x6e, 0x74, 0x6f, 0x20, 0x70, 0x80, 0x65,
    0x64, 0x69, 0x64, 0x6f, 0x2e, 0x20, 0xff, 0x9b, 0xff, 0x9f, 0x83, 0x7f, 0x88, 0x5f, 0x8d, 0x5f, 0x8d, 0x3f, 0x92, 0x1f,
    0x97, 0xff, 0x9b, 0xdf, 0xa0, 0xff, 0xbf, 0xa5, 0x9f, 0xaa, 0x7f, 0xaf, 0x7f, 0xaf, 0x5f, 0xb4, 0x3f, 0xb9, 0x1f, 0xbe,
    0xff, 0xc2, 0xff, 0xdf, 0xc7, 0xbf, 0xcc, 0xbf, 0xcc, 0x9f, 0xd1, 0x7f, 0xd6, 0x5f, 0xdb, 0x3f, 0xe0, 0x1f, 0xe5, 0xff,
    0xff, 0xe9, 0xdf, 0xee, 0xdf, 0xee, 0xbf, 0xf3, 0x9f, 0xf8, 0xbf, 0x7e, 0x7f, 0x3a, 0x1f, 0x22, 0xff, 0xbf, 0x09, 0x9f,
    0x83, 0xdf, 0x2b, 0x7f, 0x13, 0x0f, 0x86, 0x9f, 0x35, 0x3f, 0x1d, 0xef, 0x8a, 0xff, 0x5f, 0x3f, 0xff, 0x26, 0x9f, 0x0e,
    0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0xff, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f,
    0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0xff, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e,
    0x9f, 0x0e, 0x9f, 0x0e, 0xff, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f,
    0x0e, 0xff, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0xff, 0x9f,
    0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0xff, 0x9f, 0x0e, 0x9f, 0x0e,
    0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0xff, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f,
    0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0xff, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e,
    0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0xff, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f,
    0x0e, 0x9f, 0x0e, 0xff, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e,
    0xff, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x7f, 0x9f, 0x0e,
    0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x9f, 0x0e, 0x98, 0x0e, 0x2d, 0xb0, 0x00, 0x70, 0x65, 0x6e, 0x4e, 0x54,
    0x20, 0x64, 0x65, 0x00, 0x73, 0x63, 0x6f, 0x6d, 0x70, 0x72, 0x69, 0x6d, 0x00, 0x65, 0x20, 0x6f, 0x20, 0x66, 0x72, 0x61,
    0x67, 0x00, 0x6d, 0x65, 0x6e, 0x74, 0x6f, 0x20, 0x70, 0x65, 0x80, 0x64, 0x69, 0x64, 0x6f, 0x2e, 0x20, 0x4f, 0x9e, 0x98,
];

/// XPRESS de `mixed()` (560 bytes): matches curtos, comprimento estendido por
/// meio byte, por byte e por USHORT.
const XPRESS_MIXED: [u8; 121] = [
    0xff, 0x03, 0x02, 0x00, 0x64, 0x72, 0x69, 0x76, 0x65, 0x72, 0x20, 0x78, 0x70, 0x72, 0x65, 0x73, 0x73, 0x20, 0x6c, 0x00,
    0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x20, 0x34, 0x00, 0xa4, 0x00, 0x14, 0x01, 0x34, 0x00, 0xdc, 0x00, 0x37, 0x00, 0x54,
    0xdc, 0x00, 0x34, 0x00, 0xdc, 0x00, 0xf4, 0x01, 0x00, 0x00, 0xe0, 0x07, 0x63, 0x68, 0x75, 0x6e, 0x6b, 0x97, 0x02, 0x0c,
    0x01, 0xd3, 0x00, 0x2b, 0x00, 0x97, 0x00, 0xf3, 0x40, 0x02, 0x4f, 0x70, 0x65, 0x6e, 0x4e, 0x54, 0x20, 0x64, 0x65, 0x73,
    0x63, 0x6f, 0x6d, 0x70, 0x72, 0x69, 0x6d, 0x65, 0x20, 0x6f, 0x20, 0xff, 0x07, 0x00, 0x00, 0x66, 0x72, 0x61, 0x67, 0x6d,
    0x65, 0x6e, 0x74, 0x6f, 0x20, 0x70, 0x65, 0x64, 0x69, 0x64, 0x6f, 0x2e, 0x20, 0x4f, 0x70, 0x65, 0x37, 0x01, 0xff, 0x63,
    0x01,
];

/// XPRESS_HUFF de `mixed()`: tabela de 256 bytes e um bloco.
const XPRESS_HUFF_MIXED: [u8; 323] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66,
    0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x50, 0x35, 0x66, 0x56, 0x50, 0x56, 0x55, 0x04, 0x54, 0x66, 0x06,
    0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x05, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x60, 0x05, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x60, 0x06, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x5a, 0x85, 0x50,
    0xa0, 0xb1, 0x4b, 0x8c, 0xd0, 0xac, 0x19, 0x8f, 0xb9, 0x14, 0x07, 0xad, 0x79, 0x2e, 0x3c, 0xcf, 0x3c, 0x97, 0xd5, 0xa7,
    0x8f, 0x8e, 0xe9, 0x6f, 0x5d, 0xd0, 0x17, 0xdf, 0xf1, 0x87, 0x18, 0x36, 0x76, 0x7d, 0xc4, 0x92, 0x07, 0x55, 0x31, 0x1a,
    0xa0, 0xc0, 0xa5, 0x57, 0x38, 0xd8, 0x38, 0x3f, 0x85, 0x11, 0x70, 0xb1, 0xac, 0xa8, 0xe9, 0x31, 0x00, 0xf7, 0xff, 0x63,
    0x01, 0x00, 0x00,
];

/// Texto dos vetores: palavras escolhidas por um gerador congruente linear.
fn sample(length: usize) -> Vec<u8> {
    const WORDS: [&[u8]; 4] = [b"kernel ", b"driver ", b"chunk ", b"xpress "];
    let mut state = 0x1234_5678u32;
    let mut text = Vec::with_capacity(length + 8);
    while text.len() < length {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        text.extend_from_slice(WORDS[(state >> 16) as usize & 3]);
    }
    text.truncate(length);
    text
}

/// Uma frase de 39 bytes repetida até `length` bytes.
fn phrase(length: usize) -> Vec<u8> {
    b"OpenNT descomprime o fragmento pedido. ".iter().copied().cycle().take(length).collect()
}

/// `sample(160)` seguido de `phrase(400)`: 560 bytes.
fn mixed() -> Vec<u8> {
    let mut text = sample(160);
    text.extend_from_slice(&phrase(400));
    text
}

fn status(name: &str, arguments: &[u64]) -> u32 {
    super::phase6::call_export(name, arguments).map_or(0xDEAD_DEAD, |value| value as u32)
}

fn ulong(address: u64) -> &'static nt::Field<u32> {
    // SAFETY: célula de 4 bytes alocada pelo próprio teste (alinhada a 16).
    unsafe { nt::Field::<u32>::at(address) }
}

/// Bytes copiados para um bloco novo do convidado.
fn put(bytes: &[u8]) -> u64 {
    let address = guest::alloc_bytes(bytes.len() as u64);
    guest::write_bytes(address, bytes);
    address
}

/// Repreenche `length` bytes e a folga com `fill`.
fn refill(address: u64, length: usize, fill: u8) {
    guest::write_bytes(address, &vec![fill; length + SLACK]);
}

/// Bloco novo de `length` bytes mais a folga, todo com `fill`.
fn filled(length: usize, fill: u8) -> u64 {
    let address = guest::alloc_bytes((length + SLACK) as u64);
    refill(address, length, fill);
    address
}

/// O conteúdo esperado: `written` seguido de `untouched` bytes ainda com FILL.
fn expect(written: &[u8], untouched: usize) -> Vec<u8> {
    let mut bytes = written.to_vec();
    bytes.resize(written.len() + untouched, FILL);
    bytes
}

pub fn run(assert: Assert) {
    work_space_sizes(assert);
    lznt1(assert);
    lznt1_fragments(assert);
    xpress(assert);
    xpress_huffman(assert);
    formats(assert);
}

fn work_space_sizes(assert: Assert) {
    let sizes = guest::alloc_bytes(8);
    let (buffer, fragment) = (ulong(sizes), ulong(sizes + 4));
    let reported = |format: u64| {
        buffer.set(UNTOUCHED);
        fragment.set(UNTOUCHED);
        (status("RtlGetCompressionWorkSpaceSize", &[format, sizes, sizes + 4]), buffer.get(), fragment.get())
    };
    let supported: [(u64, u32, u32); 6] = [(2, 0x1_0020, 0x1000), (3, 0xEF27, 0), (4, 0x2_8A5F, 0x1429), (0x102, 0x20, 0x1000), (0x103, 0x6_0007, 0), (0x104, 0x15_9B3F, 0x1429)];
    assert(
        supported.iter().all(|&(format, buffer_size, fragment_size)| reported(format) == (0, buffer_size, fragment_size)),
        "rtl-decompression: RtlGetCompressionWorkSpaceSize dos tres formatos, standard e maximum",
    );
    let rejected: [(u64, u32); 7] = [(0x202, STATUS_NOT_SUPPORTED), (0x204, STATUS_NOT_SUPPORTED), (0, STATUS_INVALID_PARAMETER), (1, STATUS_INVALID_PARAMETER), (5, STATUS_UNSUPPORTED_COMPRESSION), (0xFF, STATUS_UNSUPPORTED_COMPRESSION), (0x1FF, STATUS_UNSUPPORTED_COMPRESSION)];
    assert(
        rejected.iter().all(|&(format, code)| reported(format) == (code, UNTOUCHED, UNTOUCHED)),
        "rtl-decompression: RtlGetCompressionWorkSpaceSize recusa engine e formato sem tocar nas saidas",
    );
    guest::free_bytes(sizes);
}

fn lznt1(assert: Assert) {
    let plain = sample(200);
    let packed = put(&LZNT1_SAMPLE);
    let output = filled(300, FILL);
    let final_size = guest::alloc_bytes(4);
    let result = ulong(final_size);
    let decompress = |format: u64, size: u64| {
        refill(output, 300, FILL);
        result.set(UNTOUCHED);
        status("RtlDecompressBuffer", &[format, output, size, packed, LZNT1_SAMPLE.len() as u64, final_size])
    };
    assert(
        decompress(2, 200) == 0 && result.get() == 200 && guest::read_bytes(output, 200 + SLACK) == expect(&plain, SLACK),
        "rtl-decompression: RtlDecompressBuffer LZNT1",
    );
    assert(
        decompress(2, 300) == 0 && result.get() == 200 && guest::read_bytes(output, 300 + SLACK) == expect(&plain, 100 + SLACK),
        "rtl-decompression: LZNT1 com saida maior escreve so o texto",
    );
    // O match que passaria do fim é recusado antes de copiar.
    assert(
        decompress(2, 150) == STATUS_BAD_COMPRESSION_BUFFER && result.get() == 0 && guest::read_bytes(output, 150 + SLACK) == expect(&plain[..138], 12 + SLACK),
        "rtl-decompression: LZNT1 com saida menor para antes do match",
    );
    assert(
        decompress(0x102, 200) == 0 && result.get() == 200 && decompress(0xF02, 200) == 0 && result.get() == 200 && guest::read_bytes(output, 200) == plain,
        "rtl-decompression: a descompressao ignora o engine",
    );

    let text = phrase(4296);
    let chunks = put(&LZNT1_TWO_CHUNKS);
    let big = filled(4296, FILL);
    let work = filled(0x1000, WORK_FILL);
    let whole = |routine: &str, compressed_size: u64| {
        refill(big, 4296, FILL);
        result.set(UNTOUCHED);
        if routine == "RtlDecompressBufferEx" {
            status(routine, &[2, big, 4296, chunks, compressed_size, final_size, work])
        } else {
            status(routine, &[2, big, 4296, chunks, compressed_size, final_size])
        }
    };
    assert(
        whole("RtlDecompressBuffer", 400) == 0 && result.get() == 4296 && guest::read_bytes(big, 4296 + SLACK) == expect(&text, SLACK)
            && whole("RtlDecompressBufferEx", 400) == 0 && result.get() == 4296 && guest::read_bytes(big, 4296) == text,
        "rtl-decompression: LZNT1 com dois chunks por RtlDecompressBuffer e RtlDecompressBufferEx",
    );
    // Chunk que passa do fim da entrada: o tamanho final recebe os 32 bits
    // baixos do endereço do cabeçalho dele.
    assert(
        whole("RtlDecompressBuffer", 390) == STATUS_BAD_COMPRESSION_BUFFER && result.get() == (chunks + 352) as u32 && guest::read_bytes(big, 4096 + SLACK) == expect(&text[..4096], SLACK)
            && whole("RtlDecompressBuffer", 100) == STATUS_BAD_COMPRESSION_BUFFER && result.get() == chunks as u32 && guest::read_bytes(big, SLACK) == [FILL; SLACK],
        "rtl-decompression: LZNT1 truncado no segundo e no primeiro chunk",
    );
    for address in [packed, output, final_size, chunks, big, work] {
        guest::free_bytes(address);
    }
}

fn lznt1_fragments(assert: Assert) {
    let text = phrase(4296);
    let chunks = put(&LZNT1_TWO_CHUNKS);
    let work = filled(0x1000, WORK_FILL);
    let output = filled(300, FILL);
    let final_size = guest::alloc_bytes(4);
    let result = ulong(final_size);
    let fragment = |format: u64, offset: u64, size: u64| {
        refill(output, 300, FILL);
        result.set(UNTOUCHED);
        status("RtlDecompressFragment", &[format, output, size, chunks, LZNT1_TWO_CHUNKS.len() as u64, offset, final_size, work])
    };
    // (deslocamento, tamanho pedido, bytes produzidos)
    let cases: [(usize, usize, usize); 6] = [(0, 64, 64), (100, 50, 50), (4000, 200, 200), (4096, 100, 100), (4150, 300, 146), (4296, 10, 0)];
    assert(
        cases.iter().all(|&(offset, size, produced)| {
            fragment(2, offset as u64, size as u64) == 0
                && result.get() == produced as u32
                && guest::read_bytes(output, size + SLACK) == expect(&text[offset..offset + produced], size + SLACK - produced)
        }),
        "rtl-decompression: RtlDecompressFragment LZNT1 no inicio, no meio, entre chunks, no segundo chunk e no fim",
    );
    // Além do último chunk o NT copia o que estiver no workspace depois do
    // chunk decodificado.
    refill(work, 0x1000, WORK_FILL);
    assert(
        fragment(2, 5000, 10) == 0 && result.get() == 10 && guest::read_bytes(output, 10) == [WORK_FILL; 10],
        "rtl-decompression: RtlDecompressFragment alem do ultimo chunk le o workspace",
    );
    let rejected: [(u64, u32); 5] = [(3, STATUS_UNSUPPORTED_COMPRESSION), (4, STATUS_UNSUPPORTED_COMPRESSION), (0x103, STATUS_UNSUPPORTED_COMPRESSION), (1, STATUS_INVALID_PARAMETER), (5, STATUS_UNSUPPORTED_COMPRESSION)];
    assert(
        rejected.iter().all(|&(format, code)| fragment(format, 0, 16) == code && result.get() == UNTOUCHED && guest::read_bytes(output, 16 + SLACK) == [FILL; 16 + SLACK]),
        "rtl-decompression: RtlDecompressFragment sem fragmentos nos XPRESS e com formato invalido",
    );
    for address in [chunks, work, output, final_size] {
        guest::free_bytes(address);
    }
}

fn xpress(assert: Assert) {
    let text = mixed();
    let packed = put(&XPRESS_MIXED);
    let full = XPRESS_MIXED.len() as u64;
    let output = filled(561, FILL);
    let work = filled(HUFF_WORK_SPACE, 0);
    let final_size = guest::alloc_bytes(4);
    let result = ulong(final_size);
    let decompress = |size: u64, compressed_size: u64| {
        refill(output, 561, FILL);
        result.set(UNTOUCHED);
        status("RtlDecompressBuffer", &[3, output, size, packed, compressed_size, final_size])
    };
    assert(
        decompress(560, full) == 0 && result.get() == 560 && guest::read_bytes(output, 560 + SLACK) == expect(&text, SLACK),
        "rtl-decompression: RtlDecompressBuffer XPRESS",
    );
    assert(
        decompress(561, full) == 0 && result.get() == 560 && guest::read_bytes(output, 561 + SLACK) == expect(&text, 1 + SLACK)
            && decompress(559, full) == STATUS_BAD_COMPRESSION_BUFFER && result.get() == UNTOUCHED,
        "rtl-decompression: XPRESS aceita saida maior e recusa saida menor",
    );
    // Entrada truncada: o fluxo acaba num bit de match e a decodificação
    // termina com sucesso, curta.
    assert(
        decompress(560, 4) == STATUS_BAD_COMPRESSION_BUFFER && result.get() == UNTOUCHED && guest::read_bytes(output, SLACK) == [FILL; SLACK]
            && decompress(560, full - 5) == 0 && result.get() == 202 && guest::read_bytes(output, 560 + SLACK) == expect(&text[..202], 560 - 202 + SLACK),
        "rtl-decompression: XPRESS com menos de 5 bytes e truncado",
    );
    refill(output, 561, FILL);
    result.set(UNTOUCHED);
    assert(
        status("RtlDecompressBufferEx", &[3, output, 560, packed, full, final_size, work]) == 0 && result.get() == 560 && guest::read_bytes(output, 560) == text,
        "rtl-decompression: RtlDecompressBufferEx XPRESS",
    );
    for address in [packed, output, work, final_size] {
        guest::free_bytes(address);
    }
}

fn xpress_huffman(assert: Assert) {
    let text = mixed();
    let packed = put(&XPRESS_HUFF_MIXED);
    let full = XPRESS_HUFF_MIXED.len() as u64;
    let output = filled(561, FILL);
    let work = filled(HUFF_WORK_SPACE, 0);
    let final_size = guest::alloc_bytes(4);
    let result = ulong(final_size);
    let decompress_ex = |format: u64, size: u64, compressed_size: u64, work_space: u64| {
        refill(output, 561, FILL);
        result.set(UNTOUCHED);
        status("RtlDecompressBufferEx", &[format, output, size, packed, compressed_size, final_size, work_space])
    };
    // A tabela de decodificação mora no workspace: sem ele, nada é tocado.
    refill(output, 561, FILL);
    result.set(UNTOUCHED);
    assert(
        status("RtlDecompressBuffer", &[4, output, 560, packed, full, final_size]) == STATUS_INVALID_USER_BUFFER
            && result.get() == UNTOUCHED
            && guest::read_bytes(output, 561 + SLACK) == vec![FILL; 561 + SLACK]
            && decompress_ex(4, 560, full, 0) == STATUS_INVALID_USER_BUFFER
            && result.get() == UNTOUCHED,
        "rtl-decompression: XPRESS_HUFF sem workspace (RtlDecompressBuffer e Ex com NULL)",
    );
    assert(
        decompress_ex(4, 560, full, work) == 0 && result.get() == 560 && guest::read_bytes(output, 560 + SLACK) == expect(&text, SLACK)
            && decompress_ex(0x104, 560, full, work) == 0 && result.get() == 560 && guest::read_bytes(output, 560) == text,
        "rtl-decompression: RtlDecompressBufferEx XPRESS_HUFF",
    );
    assert(
        decompress_ex(4, 561, full, work) == STATUS_BAD_COMPRESSION_BUFFER && result.get() == UNTOUCHED
            && decompress_ex(4, 559, full, work) == STATUS_BAD_COMPRESSION_BUFFER && result.get() == UNTOUCHED
            && decompress_ex(4, 560, full - 20, work) == STATUS_BAD_COMPRESSION_BUFFER && result.get() == UNTOUCHED
            && decompress_ex(4, 0, 0x103, work) == 0 && result.get() == 0,
        "rtl-decompression: XPRESS_HUFF exige a saida exata, recusa truncado e aceita bloco curto com saida vazia",
    );
    for address in [packed, output, work, final_size] {
        guest::free_bytes(address);
    }
}

fn formats(assert: Assert) {
    let packed = put(&LZNT1_SAMPLE);
    let output = filled(200, FILL);
    let work = filled(HUFF_WORK_SPACE, 0);
    let final_size = guest::alloc_bytes(4);
    let result = ulong(final_size);
    let rejected: [(u64, u32); 5] = [(0, STATUS_INVALID_PARAMETER), (1, STATUS_INVALID_PARAMETER), (5, STATUS_UNSUPPORTED_COMPRESSION), (0xFF, STATUS_UNSUPPORTED_COMPRESSION), (0x105, STATUS_UNSUPPORTED_COMPRESSION)];
    let refused = rejected.iter().all(|&(format, code)| {
        result.set(UNTOUCHED);
        let plain = status("RtlDecompressBuffer", &[format, output, 200, packed, LZNT1_SAMPLE.len() as u64, final_size]);
        let plain_untouched = result.get() == UNTOUCHED;
        let ex = status("RtlDecompressBufferEx", &[format, output, 200, packed, LZNT1_SAMPLE.len() as u64, final_size, work]);
        plain == code && plain_untouched && ex == code && result.get() == UNTOUCHED
    });
    assert(
        refused && guest::read_bytes(output, 200 + SLACK) == vec![FILL; 200 + SLACK],
        "rtl-decompression: formato 0/1 e acima de 4 recusados sem tocar nas saidas",
    );
    for address in [packed, output, work, final_size] {
        guest::free_bytes(address);
    }
}
