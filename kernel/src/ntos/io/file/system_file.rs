//! Arquivos que o kernel abre por handle de kernel e lê ou grava pelo I/O
//! Manager: o ZwCreateFile, o ZwReadFile, o ZwWriteFile, o
//! ZwQueryInformationFile, o ZwSetInformationFile e o ZwFlushBuffersFile de
//! um componente do kernel, como o MmLoadSystemImage lê uma imagem e o
//! CmpFileRead/CmpFileWrite leem e gravam uma hive. Num arquivo de file
//! system real (o volume do sistema servido pelo ntfs.sys, com
//! `--volume-sistema=ntfs.sys`) cada operação é um IRP ao file system; no
//! volume do kernel, a do serviço Zw dele.

use alloc::vec::Vec;

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{FileStandardInformation, IoStatusBlock, LargeInteger, ObjectAttributes, UnicodeString};
use crate::ntos::io::file::{query, read, write, zw};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;

const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
const STATUS_PENDING: u32 = 0x103;
/// FILE_GENERIC_READ e FILE_GENERIC_READ | FILE_GENERIC_WRITE.
pub const READ_ACCESS: u32 = 0x0012_0089;
pub const READ_WRITE_ACCESS: u32 = 0x0012_019F;
/// FILE_SHARE_READ.
pub const FILE_SHARE_READ: u32 = 1;
/// FILE_OPEN.
pub const FILE_OPEN: u32 = 1;
/// FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE.
pub const SYNCHRONOUS_FILE: u32 = 0x60;
/// OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE.
const OPEN_ATTRIBUTES: u32 = 0x240;
/// FileStandardInformation e FileEndOfFileInformation.
const FILE_STANDARD_INFORMATION: u32 = 5;
const FILE_END_OF_FILE_INFORMATION: u32 = 20;
/// O tamanho de cada ZwReadFile/ZwWriteFile (o buffer de rascunho).
const TRANSFER: u64 = 0x10000;

/// Os argumentos do ZwCreateFile (o texto do nome vem logo depois).
#[repr(C)]
struct CreateRequest {
    attributes: ObjectAttributes,
    handle: Field<u64>,
    name: UnicodeString,
    io_status: IoStatusBlock,
}

// SAFETY: #[repr(C)] só de células e estruturas do NT.
unsafe impl NtStruct for CreateRequest {}

/// O IO_STATUS_BLOCK, o deslocamento e o buffer de uma transferência.
#[repr(C)]
struct TransferRequest {
    io_status: IoStatusBlock,
    offset: LargeInteger,
    standard: FileStandardInformation,
}

// SAFETY: #[repr(C)] só de células e estruturas do NT.
unsafe impl NtStruct for TransferRequest {}

/// Um arquivo aberto num handle de kernel: próprio (fechado no fim) ou
/// emprestado de quem o abriu ([`SystemFile::borrowed`]).
pub struct SystemFile {
    handle: u64,
    owned: bool,
}

impl SystemFile {
    /// ZwCreateFile do nome NT num handle de kernel; devolve o arquivo e o
    /// Information do IO_STATUS_BLOCK.
    pub fn open(nt_path: &str, access: u32, share: u32, disposition: u32, options: u32) -> Result<(SystemFile, u64), u32> {
        let units = nt_path.encode_utf16().count() as u64;
        let block = guest::alloc_bytes(CreateRequest::SIZE + units * 2 + 2);
        if block == 0 {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        // SAFETY: bloco recém-alocado; o texto vem logo depois dele.
        let request = unsafe { CreateRequest::at(block) };
        let text = block + CreateRequest::SIZE;
        guest::write_bytes(block, &alloc::vec![0u8; CreateRequest::SIZE as usize]);
        guest_strings::write_wide_string(text, nt_path);
        request.name.length.set(units as u16 * 2);
        request.name.maximum_length.set(units as u16 * 2 + 2);
        request.name.buffer.set(text);
        request.attributes.length.set(ObjectAttributes::SIZE as u32);
        request.attributes.object_name.set(request.name.address());
        request.attributes.attributes.set(OPEN_ATTRIBUTES);
        let status = crate::ntos::ps::previous_mode::with_kernel(|| zw::create_kernel_file(request.handle.address(), access, request.attributes.address(), request.io_status.address(), share, disposition, options)).and_then(|status| status);
        let (handle, information) = (request.handle.get(), request.io_status.information.get());
        guest::free_bytes(block);
        match status {
            Ok(0) => Ok((SystemFile { handle, owned: true }, information)),
            Ok(status) => Err(status),
            Err(error) => Err(if error.status != 0 { error.status } else { STATUS_UNSUCCESSFUL }),
        }
    }

    /// O arquivo aberto só para leitura, compartilhado com outras leituras.
    pub fn open_read(nt_path: &str) -> Result<SystemFile, u32> {
        Self::open(nt_path, READ_ACCESS, FILE_SHARE_READ, FILE_OPEN, SYNCHRONOUS_FILE).map(|(file, _)| file)
    }

    /// A E/S num handle de kernel de outro dono, que continua aberto.
    pub fn borrowed(handle: u64) -> SystemFile {
        SystemFile { handle, owned: false }
    }

    pub fn handle(&self) -> u64 {
        self.handle
    }

    /// O FILE_OBJECT do handle.
    pub fn file_object(&self) -> u64 {
        zw::file_object_of_handle(self.handle)
    }

    /// O fim de uma transferência num handle assíncrono (o dos logs das
    /// hives, aberto sem FILE_SYNCHRONOUS_IO_*): sem evento próprio, o
    /// STATUS_PENDING espera o FileObject->Event, que a conclusão sinaliza,
    /// e o status é o do IO_STATUS_BLOCK.
    fn settle(&self, status: u32, io_status: &IoStatusBlock) -> u32 {
        if status != STATUS_PENDING {
            return status;
        }
        let file = self.file_object();
        if file == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        // SAFETY: o FILE_OBJECT vivo do handle aberto.
        let event = unsafe { crate::ntos::inc::types::FileObject::at(file) }.event.address();
        crate::ntos::ke::dispatcher::wait_for_single_object(event, 0, 0, false);
        io_status.status.get() as u32
    }

    /// O EndOfFile do FileStandardInformation.
    pub fn size(&self) -> Result<u64, u32> {
        with_transfer(|request| {
            let status = query::query(self.handle, request.io_status.address(), request.standard.address(), FileStandardInformation::SIZE as u32, FILE_STANDARD_INFORMATION).unwrap_or(STATUS_UNSUCCESSFUL);
            if status != 0 {
                return Err(status);
            }
            Ok(request.standard.end_of_file.quad_part.get() as u64)
        })
    }

    /// `length` bytes a partir de `offset` (menos no fim do arquivo).
    pub fn read_at(&self, offset: u64, length: u64) -> Result<Vec<u8>, u32> {
        let buffer = guest::alloc_bytes(TRANSFER.min(length.max(1)));
        if buffer == 0 {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let result = with_transfer(|request| {
            let mut bytes = Vec::with_capacity(length as usize);
            while (bytes.len() as u64) < length {
                let chunk = (length - bytes.len() as u64).min(TRANSFER);
                request.offset.quad_part.set((offset + bytes.len() as u64) as i64);
                let status = read::read(self.handle, 0, 0, 0, request.io_status.address(), buffer, chunk as u32, request.offset.address(), 0).unwrap_or(STATUS_UNSUCCESSFUL);
                let status = self.settle(status, &request.io_status);
                if status == STATUS_END_OF_FILE {
                    break;
                }
                if status != 0 {
                    return Err(status);
                }
                let transferred = request.io_status.information.get().min(chunk);
                bytes.extend_from_slice(&guest::read_bytes(buffer, transferred as usize));
                if transferred < chunk {
                    break;
                }
            }
            Ok(bytes)
        });
        guest::free_bytes(buffer);
        result
    }

    /// O arquivo inteiro.
    pub fn read_all(&self) -> Result<Vec<u8>, u32> {
        let size = self.size()?;
        self.read_at(0, size)
    }

    /// Grava `data` em `offset`; devolve os bytes gravados.
    pub fn write_at(&self, offset: u64, data: &[u8]) -> Result<u64, u32> {
        let buffer = guest::alloc_bytes(TRANSFER.min((data.len() as u64).max(1)));
        if buffer == 0 {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let result = with_transfer(|request| {
            let mut done = 0u64;
            while done < data.len() as u64 {
                let chunk = (data.len() as u64 - done).min(TRANSFER);
                guest::write_bytes(buffer, &data[done as usize..(done + chunk) as usize]);
                request.offset.quad_part.set((offset + done) as i64);
                let status = write::write(self.handle, 0, 0, 0, request.io_status.address(), buffer, chunk as u32, request.offset.address(), 0).unwrap_or(STATUS_UNSUCCESSFUL);
                let status = self.settle(status, &request.io_status);
                if status != 0 {
                    return Err(status);
                }
                let transferred = request.io_status.information.get().min(chunk);
                done += transferred;
                if transferred < chunk {
                    break;
                }
            }
            Ok(done)
        });
        guest::free_bytes(buffer);
        result
    }

    /// O EndOfFile novo (FileEndOfFileInformation).
    pub fn set_size(&self, size: u64) -> Result<(), u32> {
        with_transfer(|request| {
            request.offset.quad_part.set(size as i64);
            match zw::set_information_file(self.handle, request.io_status.address(), request.offset.address(), FILE_END_OF_FILE_INFORMATION) {
                Ok(0) => Ok(()),
                Ok(status) => Err(status),
                Err(error) => Err(if error.status != 0 { error.status } else { STATUS_UNSUCCESSFUL }),
            }
        })
    }

    /// ZwFlushBuffersFile.
    pub fn flush(&self) -> Result<(), u32> {
        with_transfer(|request| match zw::flush_buffers_file(self.handle, request.io_status.address()) {
            0 => Ok(()),
            status => Err(status),
        })
    }
}

impl Drop for SystemFile {
    fn drop(&mut self) {
        if self.owned {
            zw::close_file_entry(self.handle as u32);
        }
    }
}

/// O arquivo NT inteiro, lido por um handle de kernel só de leitura.
pub fn read_file(nt_path: &str) -> Result<Vec<u8>, u32> {
    SystemFile::open_read(nt_path)?.read_all()
}

/// Executa `operation` com um bloco de rascunho zerado (o IO_STATUS_BLOCK,
/// o LARGE_INTEGER e o FILE_STANDARD_INFORMATION), em KernelMode como os
/// serviços Zw: quem chama pode estar numa chamada de sistema de modo
/// usuário (o NtFlushKey do smss que descarrega uma hive), e o handle de
/// kernel e os buffers do kernel não valem em UserMode.
fn with_transfer<T>(operation: impl FnOnce(&TransferRequest) -> Result<T, u32>) -> Result<T, u32> {
    let block = guest::alloc_bytes(TransferRequest::SIZE);
    if block == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(block, &alloc::vec![0u8; TransferRequest::SIZE as usize]);
    // SAFETY: o bloco de rascunho recém-alocado e zerado.
    let result = crate::ntos::ps::previous_mode::with_kernel(|| operation(unsafe { TransferRequest::at(block) })).unwrap_or(Err(STATUS_UNSUCCESSFUL));
    guest::free_bytes(block);
    result
}
