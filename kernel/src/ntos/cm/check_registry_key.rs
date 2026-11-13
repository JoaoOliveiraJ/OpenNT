//! RtlCheckRegistryKey.
//!
//! Consulta a existência pela abertura real do Configuration Manager; os
//! prefixos, direitos e propriedade seguem o kernel 19041.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::cm::key::services as key_services;
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ob::close;
use crate::ntos::ps::{previous_mode, process};
use crate::ntos::se::token::{thread as thread_tokens, tokens};
use crate::rtl::KernelError;
use crate::ntos::{mm::guest_memory as guest, rtl::guest_strings};
use crate::ntos::inc::types::{NtStruct, ObjectAttributes, UnicodeString};

const ALLOCATION_TAG: u32 = 0x6B43_6C52;
const PATH_CAPACITY: usize = 0x20C;
const FRAME_SIZE: u64 = 80;
const ROOT_PATHS: [&str; 6] = [
    "",
    "\\Registry\\Machine\\System\\CurrentControlSet\\Services",
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control",
    "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion",
    "\\Registry\\Machine\\Hardware\\DeviceMap",
    "\\Registry\\User\\.Default",
];

fn allocate(size: u64, zero: bool) -> Option<u64> {
    kernel_pool::allocate(size, AllocateOptions { tag: ALLOCATION_TAG, paged: true, zero, ..Default::default() }).ok()
}

/// Caminho `\REGISTRY\USER\<SID>` do TokenUser efetivo; o texto é montado
/// num buffer de pool. `Err(status)` em falha.
fn current_user_path() -> Result<Result<String, u32>, KernelError> {
    let Some(token) = thread_tokens::effective(process::get_current_thread(), false) else { return Ok(Err(0xC000_007C)) };
    tokens::retain(token)?;
    let identifier = tokens::with(token, |token| token.user.clone()).unwrap_or_default();
    let result = (|| -> Result<String, u32> {
        if identifier.len() < 2 {
            return Err(0xC000_0078);
        }
        let count = identifier[1] as usize;
        if 16 + 8 + count * 4 > 0x58 {
            return Err(0xC000_0023);
        }
        if identifier[0] & 15 != 1 || count > 15 || identifier.len() < 8 + count * 4 {
            return Err(0xC000_0078);
        }
        let hexadecimal = identifier[2] != 0 || identifier[3] != 0;
        let capacity = (if hexadecimal { 36 } else { 28 }) + count * 22;
        let Some(buffer) = allocate(capacity as u64 + 34, false) else { return Err(0xC000_0017) };
        let text = (|| {
            // RtlLengthSidAsUnicodeString admite a revisão baixa; a conversão exige 1.
            if identifier[0] != 1 {
                return Err(0xC000_0078);
            }
            let authority = identifier[2..8].iter().fold(0u64, |value, &byte| value << 8 | byte as u64);
            let mut text = if hexadecimal { alloc::format!("S-1-0x{authority:X}") } else { alloc::format!("S-1-{authority}") };
            for index in 0..count {
                let offset = 8 + index * 4;
                let value = u32::from_le_bytes([identifier[offset], identifier[offset + 1], identifier[offset + 2], identifier[offset + 3]]);
                text.push_str(&alloc::format!("-{value}"));
            }
            if text.len() * 2 >= capacity {
                return Err(0x8000_0005);
            }
            let text = String::from("\\REGISTRY\\USER\\") + &text;
            guest_strings::write_wide_string(buffer, &text);
            Ok(text)
        })();
        // A abertura copia o prefixo e devolve o buffer em seguida.
        let _ = kernel_pool::free(buffer, Some(ALLOCATION_TAG));
        text
    })();
    tokens::release(token)?;
    Ok(result)
}

/// RtlCheckRegistryKey(RelativeTo, Path).
pub fn check(relative_to: u32, path_pointer: u64) -> Result<u32, KernelError> {
    // RTL_REGISTRY_HANDLE devolve sucesso sem validar nem fechar o handle,
    // antes da validação do índice e sem ler Path.
    if relative_to & 0x4000_0000 != 0 {
        return Ok(0);
    }
    let root = (relative_to & 0x7FFF_FFFF) as usize;
    if root >= ROOT_PATHS.len() {
        return Ok(0xC000_000D);
    }
    let Some(frame) = allocate(FRAME_SIZE + PATH_CAPACITY as u64, true) else { return Ok(0xC000_0017) };
    let opened = (|| -> Result<Result<u64, u32>, KernelError> {
        let mut path: Vec<u16> = ROOT_PATHS[root].encode_utf16().collect();
        if root == 5 {
            // Falha ao obter ou converter o token usa .Default.
            if let Ok(text) = current_user_path()? {
                path = text.encode_utf16().collect();
                if path.len() * 2 > PATH_CAPACITY {
                    return Ok(Err(0xC000_0023));
                }
            }
        }
        if root != 0 {
            path.push(b'\\' as u16);
        }
        if path.len() * 2 > PATH_CAPACITY {
            return Ok(Err(0xC000_0023));
        }
        if path_pointer != 0 {
            // RtlInitUnicodeStringEx percorre a string inteira antes de
            // comparar a capacidade.
            let suffix = guest_strings::read_wide_units(path_pointer);
            if suffix.len() > 0x7FFE || (path.len() + suffix.len()) * 2 > PATH_CAPACITY {
                return Ok(Err(0xC000_0023));
            }
            path.extend_from_slice(&suffix);
        }
        let buffer = frame + FRAME_SIZE;
        guest::write_bytes(buffer, &path.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
        // Locais da rotina nativa no frame privado: OBJECT_ATTRIBUTES, o
        // UNICODE_STRING do caminho e o HANDLE de saída.
        // SAFETY: frame próprio recém-alocado e zerado.
        let (attributes, name) = unsafe { (ObjectAttributes::at(frame), UnicodeString::at(frame + ObjectAttributes::SIZE)) };
        let handle = super::out::<u64>(name.address() + UnicodeString::SIZE);
        attributes.length.set(ObjectAttributes::SIZE as u32);
        attributes.object_name.set(name.address());
        attributes.attributes.set(0x240);
        name.length.set(path.len() as u16 * 2);
        name.maximum_length.set(PATH_CAPACITY as u16);
        name.buffer.set(buffer);
        let status = previous_mode::with_kernel(|| key_services::open(handle.address(), 0x8200_0000, frame, false, 0))??;
        if status & 0x8000_0000 != 0 {
            return Ok(Err(status));
        }
        Ok(Ok(handle.get()))
    })();
    let _ = kernel_pool::free(frame, Some(ALLOCATION_TAG));
    let handle = match opened? {
        Ok(handle) => handle,
        Err(status) => return Ok(status),
    };
    // Sucesso informacional é normalizado; o retorno do fechamento não muda
    // o resultado.
    let _ = previous_mode::with_kernel(|| close::close(handle, Some(0)));
    Ok(0)
}
