//! Níveis de assinatura em cache dos arquivos e a comparação de níveis.
//!
//! Como no ntoskrnl 19041: SeCompareSigningLevels (rva 0x77f060), o
//! SeGetCachedSigningLevel (rva 0x6829a0) com o NtGetCachedSigningLevel
//! (rva 0x682700) e o NtSetCachedSigningLevel (rva 0x72b3e0, que chama o
//! NtSetCachedSigningLevel2 com o sexto argumento nulo). O kernel só valida
//! e encaminha: quem lê, grava e compara é a ci.dll real, pelos slots da
//! SeCiCallbacks (`se/code_integrity`). Sem a CI inicializada os slots são
//! nulos: a comparação devolve FALSE e as consultas STATUS_UNSUCCESSFUL. As
//! entradas Zw rodam em KernelMode (sem sondas).

use crate::hal::amd64::native_call;
use crate::ntos::ex::pool_allocation;
use crate::ntos::init::exports;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_types;
use crate::ntos::se::code_integrity::{self, SigningCallback};
use crate::rtl::KernelError;

const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;
const STATUS_INVALID_PARAMETER_5: u32 = 0xC000_00F3;
/// FILE_READ_DATA, o acesso do NtGetCachedSigningLevel ao handle.
const FILE_READ_DATA: u64 = 1;
/// 'CIsc', a cópia dos handles de origem.
const SOURCE_FILES_TAG: u32 = 0x6373_4943;
const PAGED_POOL: u32 = 1;
/// O buffer local da impressão digital do NtGetCachedSigningLevel.
const THUMBPRINT_CAPACITY: u32 = 0x40;

/// SeCompareSigningLevels(ActualSigningLevel, ExpectedSigningLevel): o RAX
/// do callback da CI, ou 0 sem ele.
pub fn compare(actual: u8, expected: u8) -> u64 {
    match code_integrity::signing_callback(SigningCallback::CompareSigningLevels) {
        0 => 0,
        routine => native_call::call(routine, &[actual as u64, expected as u64]),
    }
}

/// SeGetCachedSigningLevel(FileObject, Flags*, SigningLevel*, Thumbprint,
/// ThumbprintSize*, ThumbprintAlgorithm*).
pub fn get_for_file_object(file_object: u64, flags: u64, level: u64, thumbprint: u64, size: u64, algorithm: u64) -> u32 {
    let routine = code_integrity::signing_callback(SigningCallback::GetFileCache);
    if routine == 0 {
        return STATUS_UNSUCCESSFUL;
    }
    if file_object == 0 || flags == 0 || level == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    // A CI recebe o nível antes das flags.
    native_call::call(routine, &[file_object, level, flags, thumbprint, size, algorithm]) as u32
}

/// ZwGetCachedSigningLevel(File, Flags*, SigningLevel*, Thumbprint,
/// ThumbprintSize*, ThumbprintAlgorithm*): o NtGetCachedSigningLevel em
/// KernelMode. A CI escreve num buffer local de 0x40 bytes; a impressão
/// digital só é copiada com a flag 2 e espaço suficiente
/// (STATUS_BUFFER_TOO_SMALL senão), e o tamanho volta sempre.
pub fn get_cached(file: u64, flags: u64, level: u64, thumbprint: u64, size: u64, algorithm: u64) -> Result<u32, KernelError> {
    if file == 0 || flags == 0 || level == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    // Locais: objeto (8), flags (4), tamanho (4), algoritmo (4), nível (1) e
    // a impressão digital (0x40).
    let locals = guest::alloc_bytes(0x60);
    if locals == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(locals, &[0; 0x60]);
    let (object_cell, local_flags, local_size, local_algorithm, local_level, local_thumbprint) = (locals, locals + 8, locals + 0xC, locals + 0x10, locals + 0x14, locals + 0x20);
    guest::write32(local_size, THUMBPRINT_CAPACITY);
    let result = (|| -> Result<u32, KernelError> {
        let referenced = exports::invoke_handler("ObReferenceObjectByHandle", &[file, FILE_READ_DATA, object_types::file_type().pointer, 0, object_cell, 0])? as u32;
        if referenced & 0x8000_0000 != 0 {
            return Ok(referenced);
        }
        let file_object = guest::read64(object_cell);
        let wants = thumbprint != 0;
        let mut status = get_for_file_object(file_object, local_flags, local_level, if wants { local_thumbprint } else { 0 }, if wants { local_size } else { 0 }, if wants { local_algorithm } else { 0 });
        if status & 0x8000_0000 == 0 {
            let cached_flags = guest::read32(local_flags);
            guest::write32(flags, cached_flags);
            guest::write8(level, guest::read8(local_level));
            if size != 0 {
                if cached_flags & 2 != 0 {
                    let length = guest::read32(local_size);
                    if guest::read32(size) >= length && thumbprint != 0 {
                        guest::write_bytes(thumbprint, &guest::read_bytes(local_thumbprint, length as usize));
                    } else {
                        status = STATUS_BUFFER_TOO_SMALL;
                    }
                    guest::write32(size, length);
                    if algorithm != 0 {
                        guest::write32(algorithm, guest::read32(local_algorithm));
                    }
                } else {
                    guest::write32(size, 0);
                }
            }
        }
        exports::invoke_handler("ObfDereferenceObject", &[file_object])?;
        Ok(status)
    })();
    guest::free_bytes(locals);
    result
}

/// ZwSetCachedSigningLevel(Flags, InputSigningLevel, SourceFiles,
/// SourceFileCount, TargetFile): o NtSetCachedSigningLevel2 em KernelMode
/// sem o sexto argumento. Flags 1 pede o nível 0xF, flags 2 o nível 8; com
/// as flags 2 ou 4 a origem é o próprio alvo (um handle só). Os handles vão
/// à CI numa cópia 'CIsc'.
pub fn set_cached(flags: u32, input_level: u8, source_files: u64, count: u32, target: u64) -> Result<u32, KernelError> {
    let routine = code_integrity::signing_callback(SigningCallback::SetFileCache);
    if routine == 0 {
        return Ok(STATUS_UNSUCCESSFUL);
    }
    if input_level & 0x30 != 0 {
        return Ok(STATUS_INVALID_PARAMETER_2);
    }
    if count.wrapping_sub(1) > 0xFFF {
        return Ok(STATUS_INVALID_PARAMETER_4);
    }
    if flags & 6 == 0 && input_level != 0 {
        return Ok(STATUS_INVALID_PARAMETER_2);
    }
    if flags & 3 == 3 {
        return Ok(STATUS_INVALID_PARAMETER_1);
    }
    let level = if flags & 1 != 0 {
        0xF
    } else if flags & 2 != 0 {
        8
    } else {
        return Ok(STATUS_INVALID_PARAMETER_1);
    };
    let bytes = count as u64 * 8;
    let copy = pool_allocation::allocate_tagged(PAGED_POOL, bytes, SOURCE_FILES_TAG)?;
    if copy == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(copy, &guest::read_bytes(source_files, bytes as usize));
    let status = if flags & 6 != 0 && count != 1 {
        STATUS_INVALID_PARAMETER_4
    } else if flags & 6 != 0 && guest::read64(copy) != target {
        STATUS_INVALID_PARAMETER_5
    } else {
        native_call::call(routine, &[(flags & 0x807) as u64, 0, input_level as u64, level, copy, count as u64, target, 0]) as u32
    };
    pool_allocation::free(copy, SOURCE_FILES_TAG as u64)?;
    Ok(status)
}
