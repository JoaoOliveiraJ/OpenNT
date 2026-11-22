//! O cabeçalho de uma imagem SEC_IMAGE: as regras do MiVerifyImageHeader e
//! do MiCreateImageFileMap que decidem se o arquivo serve de imagem e qual é
//! o layout da control area.
//!
//! O MiVerifyImageHeader confere os alinhamentos: um FileAlignment que não
//! é múltiplo de 512 só vale igual ao SectionAlignment; FileAlignment zero,
//! um dos dois que não seja potência de dois ou um SectionAlignment menor
//! que o FileAlignment recusam a imagem, e também um SizeOfImage acima de
//! 0x77000000 e um SizeOfHeaders que não fica abaixo do SizeOfImage. O
//! MiCreateImageFileMap arredonda o SizeOfImage à página (o SizeOfSegment;
//! nenhum múltiplo é exigido) e exige que o maior entre SizeOfHeaders e o
//! fim da tabela de seções caiba no SizeOfImage.
//!
//! Um SectionAlignment menor que PAGE_SIZE (o 0x80 de um driver antigo)
//! leva ao caminho plano, só para x86 e AMD64 (MiLegacyImageArchitecture):
//! o MiBuildImageControlArea monta uma subseção única que mapeia o arquivo
//! inteiro a partir do offset zero, o offset no arquivo é o RVA, as páginas
//! além do fim do arquivo são zero por demanda, toda a imagem é
//! MM_EXECUTE_WRITECOPY e a SECTION_IMAGE_INFORMATION recebe ImageMappedFlat
//! e ImageContainsCode. O MiParseImageSectionHeaders só confere cada seção:
//! PointerToRawData + SizeOfRawData sem estouro, PointerToRawData igual ao
//! VirtualAddress e o VirtualSize (o SizeOfRawData quando zero) sem passar
//! do SizeOfRawData. O MiCreateImageFileMap recusa o caminho plano só quando
//! a criação exige imagens alinhadas à página (o HVCI do MiFlags, um processo
//! seguro do IUM ou um driver carregado com essa exigência); o OpenNT não tem
//! nenhum desses modos.
//!
//! As máquinas aceitas são a nativa (PE32+ AMD64) e a x86 do WoW64 (PE32
//! i386, os binários de SysWOW64), cada uma com o seu cabeçalho opcional; os
//! campos lidos aqui (alinhamentos, SizeOfImage e SizeOfHeaders) ficam nos
//! mesmos deslocamentos nos dois formatos.
//!
//! Lacuna: as outras recusas do MiVerifyImageHeader (características,
//! ImageBase, tamanho do cabeçalho opcional) não estão aqui, e um arquivo
//! sem MZ dá STATUS_INVALID_IMAGE_FORMAT em vez de
//! STATUS_INVALID_IMAGE_NOT_MZ.

use alloc::vec::Vec;

use crate::rtl::KernelError;

pub const PAGE: u64 = 0x1000;
/// STATUS_INVALID_IMAGE_FORMAT.
pub const STATUS_INVALID_IMAGE_FORMAT: u32 = 0xC000_007B;
/// O maior SizeOfImage que o MiVerifyImageHeader aceita.
const MAXIMUM_SIZE_OF_IMAGE: u64 = 0x7700_0000;
/// Signature + IMAGE_FILE_HEADER, até o cabeçalho opcional.
const OPTIONAL_HEADER: u64 = 24;
/// Os campos do cabeçalho NT lidos aqui (até o SizeOfHeaders).
const NT_HEADERS_READ: u64 = 88;
const SECTION_HEADER_SIZE: u64 = 40;

/// O layout que o MiCreateImageFileMap escolhe para a imagem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageHeader {
    /// O SizeOfImage do cabeçalho.
    pub size_of_image: u64,
    /// O SizeOfImage arredondado à página: o tamanho da seção e da control
    /// area.
    pub segment_size: u64,
    pub size_of_headers: u64,
    /// SectionAlignment menor que PAGE_SIZE: o arquivo mapeado plano numa
    /// subseção única, todo MM_EXECUTE_WRITECOPY.
    pub flat: bool,
}

/// Lê `length` bytes do arquivo em `offset`; `None` quando o arquivo acaba
/// antes.
pub type Reader<'a> = &'a dyn Fn(u64, u64) -> Result<Option<Vec<u8>>, KernelError>;

fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn dword(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

/// IMAGE_FILE_MACHINE_AMD64 com IMAGE_NT_OPTIONAL_HDR64_MAGIC e
/// IMAGE_FILE_MACHINE_I386 com IMAGE_NT_OPTIONAL_HDR32_MAGIC.
pub const MACHINE_AMD64: u16 = 0x8664;
pub const MACHINE_I386: u16 = 0x14C;
pub const MAGIC_PE32_PLUS: u16 = 0x20B;
pub const MAGIC_PE32: u16 = 0x10B;

/// As máquinas que a seção de imagem aceita: a nativa (PE32+ AMD64) e a do
/// WoW64 (PE32 i386), cada uma com o cabeçalho opcional do seu formato, como
/// o MiVerifyImageHeader do x64 aceita as imagens de 32 bits de SysWOW64.
pub fn machine_supported(machine: u16, magic: u16) -> bool {
    matches!((machine, magic), (MACHINE_AMD64, MAGIC_PE32_PLUS) | (MACHINE_I386, MAGIC_PE32))
}

/// Os alinhamentos que o MiVerifyImageHeader aceita.
pub fn alignments_valid(section_alignment: u32, file_alignment: u32) -> bool {
    if file_alignment & 0x1FF != 0 && file_alignment != section_alignment {
        return false;
    }
    // Um SectionAlignment zero passa o teste de potência de dois e cai no
    // de ser menor que o FileAlignment.
    file_alignment != 0 && section_alignment & section_alignment.wrapping_sub(1) == 0 && file_alignment & (file_alignment - 1) == 0 && section_alignment >= file_alignment
}

/// As seções de uma imagem plana: o offset no arquivo é o RVA e os dados
/// cobrem o tamanho virtual.
fn flat_sections_valid(table: &[u8]) -> bool {
    table.chunks_exact(SECTION_HEADER_SIZE as usize).all(|header| {
        let (virtual_size, virtual_address, raw_size, raw_pointer) = (dword(header, 8), dword(header, 12), dword(header, 16), dword(header, 20));
        let size = if virtual_size != 0 { virtual_size } else { raw_size };
        raw_pointer.checked_add(raw_size).is_some() && raw_pointer == virtual_address && size <= raw_size
    })
}

/// O cabeçalho do arquivo `file_size` lido por `read`, ou
/// STATUS_INVALID_IMAGE_FORMAT quando ele não serve de imagem.
pub fn parse(file_size: u64, read: Reader) -> Result<Result<ImageHeader, u32>, KernelError> {
    let invalid = Ok(Err(STATUS_INVALID_IMAGE_FORMAT));
    let Some(dos) = read(0, 64)? else { return invalid };
    if dos[0] != b'M' || dos[1] != b'Z' {
        return invalid;
    }
    let portable = dword(&dos, 0x3C) as u64;
    if file_size < NT_HEADERS_READ || portable > file_size - NT_HEADERS_READ {
        return invalid;
    }
    let Some(nt) = read(portable, NT_HEADERS_READ)? else { return invalid };
    let optional_size = word(&nt, 20) as u64;
    if dword(&nt, 0) != 0x4550 || optional_size < 64 || !machine_supported(word(&nt, 4), word(&nt, 24)) {
        return invalid;
    }
    let section_count = word(&nt, 6) as u64;
    let (section_alignment, file_alignment) = (dword(&nt, 24 + 32), dword(&nt, 24 + 36));
    let (size_of_image, size_of_headers) = (dword(&nt, 80) as u64, dword(&nt, 84) as u64);
    if !alignments_valid(section_alignment, file_alignment) || size_of_image > MAXIMUM_SIZE_OF_IMAGE || size_of_headers >= size_of_image {
        return invalid;
    }
    let table = portable + OPTIONAL_HEADER + optional_size;
    let table_end = table + section_count * SECTION_HEADER_SIZE;
    if table_end > u32::MAX as u64 || size_of_headers.max(table_end) > size_of_image {
        return invalid;
    }
    let flat = (section_alignment as u64) < PAGE;
    if flat {
        let Some(headers) = read(table, section_count * SECTION_HEADER_SIZE)? else { return invalid };
        if !flat_sections_valid(&headers) {
            return invalid;
        }
    }
    Ok(Ok(ImageHeader { size_of_image, segment_size: size_of_image.div_ceil(PAGE) * PAGE, size_of_headers, flat }))
}

/// O mesmo cabeçalho, lido de um arquivo cujas leituras curtas devolvem
/// menos bytes (`SectionFile::read_at`, `ImageSource::read_bytes`).
pub fn parse_with(file_size: u64, read_at: &dyn Fn(u64, u64) -> Result<Vec<u8>, KernelError>) -> Result<Result<ImageHeader, u32>, KernelError> {
    parse(file_size, &|offset, length| {
        let bytes = read_at(offset, length)?;
        Ok((bytes.len() as u64 == length).then_some(bytes))
    })
}
