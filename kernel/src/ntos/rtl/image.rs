//! Cabeçalhos e diretórios PE de imagens mapeadas ou bytes de arquivo —
//! `system32/ntos/rtl/image.js` (RtlImageNtHeaderEx, RtlImageDirectoryEntryToData).
//!
//! Só lê os bytes fornecidos; carregamento, relocação e execução pertencem
//! ao loader PE. Sobre as imagens já carregadas: a base que contém um
//! endereço (RtlPcToFileHeader) e a busca de export por nome
//! (RtlFindExportedRoutineByName).

use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const MAXIMUM_POINTER: u64 = u64::MAX;
const USER_ADDRESS_LIMIT: u64 = 0x7FFF_FFFE_FFFF;
pub const INVALID_PARAMETER: u32 = 0xC000_000D;
pub const INVALID_IMAGE: u32 = 0xC000_007B;

/// Valida flags, assinatura DOS, e_lfanew e assinatura NT. A flag 1 dispensa
/// a verificação contra o tamanho (os testes de overflow continuam).
pub fn inspect_header(flags: u32, base: u64, length: u64) -> Result<(u32, u64), KernelError> {
    if flags & !1 != 0 || base == 0 || base == MAXIMUM_POINTER {
        return Ok((INVALID_PARAMETER, 0));
    }
    let invalid = Ok((INVALID_IMAGE, 0));
    if flags & 1 == 0 && length < 64 {
        return invalid;
    }
    if base > MAXIMUM_POINTER - 63 || guest::try_read16(base)? != 0x5A4D {
        return invalid;
    }
    let header_offset = guest::try_read32(base + 0x3C)? as u64;
    if flags & 1 == 0 && (header_offset >= length || header_offset >= 0xFFFF_FFE7 || header_offset + 24 >= length) {
        return invalid;
    }
    let Some(header) = base.checked_add(header_offset) else { return invalid };
    if base < USER_ADDRESS_LIMIT && header + 0x108 >= USER_ADDRESS_LIMIT {
        return invalid;
    }
    if guest::try_read32(header)? != 0x4550 {
        return invalid;
    }
    Ok((0, header))
}

/// RtlImageNtHeaderEx: zera a saída antes da inspeção.
pub fn nt_header_ex(flags: u32, base: u64, length: u64, output: u64) -> Result<u32, KernelError> {
    if output == 0 {
        return Ok(INVALID_PARAMETER);
    }
    guest::try_write64(output, 0)?;
    let (status, address) = inspect_header(flags, base, length)?;
    if status == 0 {
        guest::try_write64(output, address)?;
    }
    Ok(status)
}

/// RtlImageNtHeader: 0 quando a inspeção falha.
pub fn nt_header(base: u64) -> Result<u64, KernelError> {
    Ok(inspect_header(1, base, 0)?.1)
}

/// RtlImageDirectoryEntryToData: imagens usam o RVA direto; arquivos
/// traduzem pelo intervalo e offset bruto de uma seção.
pub fn directory_entry(base: u64, mapped_as_image: bool, index: u32, output_size: u64) -> Result<u64, KernelError> {
    // O bit baixo marca uma vista de arquivo.
    let mapped_as_image = mapped_as_image && base & 1 == 0;
    let base = base & !3;
    let index = index & 0xFFFF;
    let (status, header) = inspect_header(1, base, 0)?;
    if status != 0 {
        return Ok(0);
    }
    let optional = header + 24;
    let array_offset = match guest::try_read16(optional)? {
        0x20B => 112,
        0x10B => 96,
        _ => 0,
    };
    if array_offset == 0 || index >= guest::try_read32(optional + array_offset - 4)? {
        return Ok(0);
    }
    let entry = optional + array_offset + index as u64 * 8;
    let rva = guest::try_read32(entry)? as u64;
    if rva == 0 || base.checked_add(rva).is_none() || (base < USER_ADDRESS_LIMIT && base + rva >= USER_ADDRESS_LIMIT) {
        return Ok(0);
    }
    // O tamanho é publicado antes da tradução por seções.
    guest::try_write32(output_size, guest::try_read32(entry + 4)?)?;
    if mapped_as_image || rva < guest::try_read32(optional + 60)? as u64 {
        return Ok(base + rva);
    }
    let count = guest::try_read16(header + 6)?;
    let mut section = optional + guest::try_read16(header + 20)? as u64;
    for _ in 0..count {
        let section_rva = guest::try_read32(section + 12)? as u64;
        let raw_size = guest::try_read32(section + 16)? as u64;
        if rva >= section_rva && rva - section_rva < raw_size {
            let file_offset = guest::try_read32(section + 20)? as u64 + rva - section_rva;
            return Ok(base.checked_add(file_offset).unwrap_or(0));
        }
        section += 40;
    }
    Ok(0)
}

/// RtlPcToFileHeader: base da imagem carregada que contém `pc` (0 se
/// nenhuma), também gravada em `base_out`.
pub fn pc_to_file_header(pc: u64, base_out: u64) -> u64 {
    let base = crate::ntos::mm::loaded_images::find(pc).map_or(0, |image| image.image_base);
    guest::write64(base_out, base);
    base
}

/// RtlFindExportedRoutineByName(PVOID ImageBase, PCCH Name): varre a EDATA
/// de uma imagem carregada e devolve o VA do export (NULL em forwarder).
pub fn find_exported_routine_by_name(base: u64, name_pointer: u64) -> u64 {
    let target = crate::ntos::rtl::guest_strings::read_c_string(name_pointer);
    let size_cell = guest::alloc_bytes(4);
    let directory = directory_entry(base, true, 0, size_cell).unwrap_or(0);
    let directory_size = guest::read32(size_cell) as u64;
    guest::free_bytes(size_cell);
    if directory == 0 {
        return 0;
    }
    let export_rva = directory.wrapping_sub(base); // directory = base + export_rva
    let number_of_names = guest::read32(directory + 0x18) as u64;
    let functions = base + guest::read32(directory + 0x1C) as u64;
    let names = base + guest::read32(directory + 0x20) as u64;
    let ordinals = base + guest::read32(directory + 0x24) as u64;
    for index in 0..number_of_names {
        let name_rva = guest::read32(names + index * 4) as u64;
        if crate::ntos::rtl::guest_strings::read_c_string(base + name_rva) == target {
            let ordinal = guest::read16(ordinals + index * 2) as u64;
            let function_rva = guest::read32(functions + ordinal * 4) as u64;
            if function_rva >= export_rva && function_rva < export_rva + directory_size {
                return 0; // forwarder
            }
            return base + function_rva;
        }
    }
    0
}

pub mod pe_metadata_reader {
    //! Leitura escalar de metadados PE — `system32/win32/pe-metadata-reader.js`.
    //!
    //! Cada leitor pertence ao arquivo já validado e retido pelo loader durante
    //! uma carga; não é um cache global do volume. Oito páginas de 4 KiB.

    use alloc::vec::Vec;
    use core::cell::RefCell;

    use crate::ntos::mm::sysload::kernel_image_source::ImageSource;
    use crate::rtl::KernelError;

    const PAGE_SIZE: u64 = 4096;
    const CACHE_PAGES: usize = 8;

    pub struct MetadataReader<'a> {
        source: &'a dyn ImageSource,
        size: u64,
        pages: RefCell<[Option<(u64, Vec<u8>)>; CACHE_PAGES]>,
    }

    impl<'a> MetadataReader<'a> {
        pub fn new(source: &'a dyn ImageSource) -> Self {
            Self { size: source.size(), source, pages: RefCell::new(Default::default()) }
        }

        fn validate(&self, offset: u64, width: u64) -> Result<(), KernelError> {
            if width > self.size || offset > self.size - width {
                return Err(KernelError::new("PE: metadado fora do arquivo"));
            }
            Ok(())
        }

        /// Página capturada por cópia: reutilizar um buffer na origem não altera
        /// uma página já lida.
        fn page_byte(&self, offset: u64) -> Result<u8, KernelError> {
            let index = offset / PAGE_SIZE;
            let slot = (index % CACHE_PAGES as u64) as usize;
            let mut pages = self.pages.borrow_mut();
            if !matches!(&pages[slot], Some((cached, _)) if *cached == index) {
                let start = index * PAGE_SIZE;
                let length = PAGE_SIZE.min(self.size - start);
                let bytes = self.source.read_bytes(start, length)?;
                if bytes.len() as u64 != length {
                    return Err(KernelError::new("PE: leitura incompleta de metadados"));
                }
                pages[slot] = Some((index, bytes));
            }
            Ok(pages[slot].as_ref().map_or(0, |(_, bytes)| bytes[(offset % PAGE_SIZE) as usize]))
        }

        pub fn read_u8(&self, offset: u64) -> Result<u32, KernelError> {
            self.validate(offset, 1)?;
            Ok(self.page_byte(offset)? as u32)
        }

        /// Campos que atravessam páginas são lidos byte a byte, em little endian.
        fn read_unsigned(&self, offset: u64, width: u64) -> Result<u32, KernelError> {
            self.validate(offset, width)?;
            let mut value = 0u32;
            for index in 0..width {
                value |= (self.page_byte(offset + index)? as u32) << (8 * index);
            }
            Ok(value)
        }

        pub fn read_u16(&self, offset: u64) -> Result<u32, KernelError> {
            self.read_unsigned(offset, 2)
        }

        pub fn read_u32(&self, offset: u64) -> Result<u32, KernelError> {
            self.read_unsigned(offset, 4)
        }
    }
}

pub mod pe_exports {
    //! Tabelas de exports PE — `system32/win32/pe-exports.js`.
    //!
    //! A EAT inclui ordinais sem nome e encaminhamentos; `read_rva` lê bytes da
    //! imagem (arquivo ou memória), sem depender do hardware.

    use alloc::collections::BTreeMap;
    use alloc::string::String;
    use alloc::vec::Vec;

    use crate::rtl::KernelError;

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Exports {
        pub exports: BTreeMap<String, u64>,
        pub exports_by_ordinal: BTreeMap<u32, u64>,
        pub forwarders: BTreeMap<String, String>,
        pub forwarders_by_ordinal: BTreeMap<u32, String>,
    }

    fn error(message: &str) -> KernelError {
        KernelError::new(message)
    }

    pub fn read_exports(read_rva: &dyn Fn(u64, u64) -> Result<Vec<u8>, KernelError>, image_base: u64, image_size: u64, directory_rva: u64, directory_size: u64) -> Result<Exports, KernelError> {
        let mut result = Exports::default();
        if directory_rva == 0 || directory_size == 0 {
            return Ok(result);
        }
        let bytes = |rva: u64, length: u64| -> Result<Vec<u8>, KernelError> {
            if rva.checked_add(length).is_none_or(|end| end > image_size) {
                return Err(error("PE: export fora da imagem"));
            }
            let data = read_rva(rva, length)?;
            if data.len() as u64 != length {
                return Err(error("PE: export truncado"));
            }
            Ok(data)
        };
        let string = |mut rva: u64, end: u64| -> Result<String, KernelError> {
            let mut text = String::new();
            while rva < end {
                let data = bytes(rva, 64.min(end - rva))?;
                for &character in &data {
                    if character == 0 {
                        return Ok(text);
                    }
                    text.push(character as char);
                }
                rva += data.len() as u64;
            }
            Err(error("PE: string de export sem terminador"))
        };
        if directory_size < 40 || directory_rva + directory_size > image_size {
            return Err(error("PE: diretorio de exports invalido"));
        }
        let directory = bytes(directory_rva, 40)?;
        let u32_at = |data: &[u8], offset: usize| u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        let ordinal_base = u32_at(&directory, 16);
        let function_count = u32_at(&directory, 20);
        let name_count = u32_at(&directory, 24);
        let functions = bytes(u32_at(&directory, 28) as u64, function_count as u64 * 4)?;
        let names = bytes(u32_at(&directory, 32) as u64, name_count as u64 * 4)?;
        let ordinals = bytes(u32_at(&directory, 36) as u64, name_count as u64 * 2)?;
        for index in 0..function_count as usize {
            let rva = u32_at(&functions, index * 4) as u64;
            if rva == 0 {
                continue; // buraco na EAT, não a base da imagem
            }
            if rva >= image_size {
                return Err(error("PE: endereco de export invalido"));
            }
            let ordinal = ordinal_base.wrapping_add(index as u32);
            if rva >= directory_rva && rva < directory_rva + directory_size {
                result.forwarders_by_ordinal.insert(ordinal, string(rva, directory_rva + directory_size)?);
            } else {
                result.exports_by_ordinal.insert(ordinal, image_base.wrapping_add(rva));
            }
        }
        for index in 0..name_count as usize {
            let function = u16::from_le_bytes([ordinals[index * 2], ordinals[index * 2 + 1]]) as u32;
            if function >= function_count {
                return Err(error("PE: indice ordinal invalido"));
            }
            let name = string(u32_at(&names, index * 4) as u64, image_size)?;
            let ordinal = ordinal_base.wrapping_add(function);
            if let Some(&address) = result.exports_by_ordinal.get(&ordinal) {
                result.exports.insert(name, address);
            } else if let Some(target) = result.forwarders_by_ordinal.get(&ordinal).cloned() {
                result.forwarders.insert(name, target);
            }
        }
        Ok(result)
    }
}

pub mod pe_image_information {
    //! SECTION_IMAGE_INFORMATION — `system32/win32/pe-image-information.js`.
    //!
    //! Capturada na criação da imagem PE32+; a consulta posterior usa esta
    //! cópia, e escrever nos cabeçalhos mapeados não altera os metadados que o
    //! gerenciador de processos reteve.

    use crate::ntos::rtl::image::pe_metadata_reader::MetadataReader;
    use crate::rtl::KernelError;

    pub const INFORMATION_SIZE: usize = 64;

    pub fn capture(metadata: &MetadataReader, source_size: u64, coff: u64, optional: u64, mapped_base: u64) -> Result<[u8; INFORMATION_SIZE], KernelError> {
        let mut information = [0u8; INFORMATION_SIZE];
        let put16 = |information: &mut [u8; INFORMATION_SIZE], offset: usize, value: u32| information[offset..offset + 2].copy_from_slice(&(value as u16).to_le_bytes());
        let put32 = |information: &mut [u8; INFORMATION_SIZE], offset: usize, value: u32| information[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        let preferred = metadata.read_u32(optional + 24)? as u64 | (metadata.read_u32(optional + 28)? as u64) << 32;
        // TransferAddress acompanha a seção realmente mapeada (com relocação).
        let transfer = mapped_base.wrapping_add(metadata.read_u32(optional + 16)? as u64);
        let dll_characteristics = metadata.read_u16(optional + 70)?;
        put32(&mut information, 0, transfer as u32);
        put32(&mut information, 4, (transfer >> 32) as u32);
        // ZeroBits e o padding ficam zero nas imagens x64 aceitas.
        for (destination, source) in [(16usize, 72u64), (24, 80)] {
            put32(&mut information, destination, metadata.read_u32(optional + source)?);
            put32(&mut information, destination + 4, metadata.read_u32(optional + source + 4)?);
        }
        put32(&mut information, 32, metadata.read_u16(optional + 68)?);
        // Versão do subsistema: minor antes de major; versão do SO: o inverso.
        put16(&mut information, 36, metadata.read_u16(optional + 50)?);
        put16(&mut information, 38, metadata.read_u16(optional + 48)?);
        put16(&mut information, 40, metadata.read_u16(optional + 40)?);
        put16(&mut information, 42, metadata.read_u16(optional + 42)?);
        put16(&mut information, 44, metadata.read_u16(coff + 18)?);
        put16(&mut information, 46, dll_characteristics);
        put16(&mut information, 48, metadata.read_u16(coff)?);
        // ImageContainsCode: existe uma seção IMAGE_SCN_MEM_EXECUTE.
        let section_table = optional + metadata.read_u16(coff + 16)? as u64;
        for index in 0..metadata.read_u16(coff + 2)? as u64 {
            if metadata.read_u32(section_table + index * 40 + 36)? & 0x2000_0000 != 0 {
                information[50] = 1;
            }
        }
        // DYNAMIC_BASE sozinho não prova relocação: o bit descreve o mapeamento.
        information[51] = if mapped_base != preferred && dll_characteristics & 0x40 != 0 { 4 } else { 0 };
        put32(&mut information, 52, metadata.read_u32(optional + 104)?);
        put32(&mut information, 56, source_size as u32);
        put32(&mut information, 60, metadata.read_u32(optional + 64)?);
        Ok(information)
    }
}
