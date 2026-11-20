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
//!
//! De modo usuário:
//! - NtCompareSigningLevels(Actual, Expected) (0x69ffe0): o EAX do callback
//!   da CI (0 sem ele) vira STATUS_SUCCESS quando não é zero e
//!   STATUS_INVALID_IMAGE_HASH quando é.
//! - NtGetCachedSigningLevel (0x682700): File, Flags e SigningLevel nulos
//!   são STATUS_INVALID_PARAMETER; o handle com FILE_READ_DATA em UserMode;
//!   uma falha da CI (STATUS_NOT_FOUND num arquivo sem o cache) volta sem
//!   tocar a memória do chamador. Só depois do sucesso as saídas são
//!   sondadas (Flags e ThumbprintSize alinhados a 4, SigningLevel e
//!   Thumbprint a 1, ThumbprintAlgorithm a 4) e gravadas; uma exceção é o
//!   status.

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

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_INVALID_IMAGE_HASH: u32 = 0xC000_0428;
const USER_MODE: u64 = 1;

/// NtCompareSigningLevels(ActualSigningLevel, ExpectedSigningLevel) de modo
/// usuário.
pub fn compare_user(actual: u8, expected: u8) -> u32 {
    if compare(actual, expected) as u32 != 0 {
        0
    } else {
        STATUS_INVALID_IMAGE_HASH
    }
}

/// O ProbeForWrite de uma saída de modo usuário: alinhamento e faixa.
fn probe_output(address: u64, length: u64, alignment: u64) -> Result<(), u32> {
    if length == 0 {
        return Ok(());
    }
    if address & (alignment - 1) != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    if !crate::ntos::ps::user_probe::probe_user_write(address, length) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(())
}

/// Grava os resultados da CI nas saídas de modo usuário, na ordem do
/// NtGetCachedSigningLevel; o status final ou a exceção.
fn write_user_outputs(status: u32, locals: u64, flags: u64, level: u64, thumbprint: u64, size: u64, algorithm: u64) -> Result<u32, u32> {
    let (local_flags, local_size, local_algorithm, local_level, local_thumbprint) = (locals + 8, locals + 0xC, locals + 0x10, locals + 0x14, locals + 0x20);
    probe_output(flags, 4, 4)?;
    probe_output(level, 1, 1)?;
    let cached_flags = guest::read32(local_flags);
    let fault = |error: KernelError| error.status;
    guest::try_write::<u32>(flags, cached_flags).map_err(fault)?;
    guest::try_write::<u8>(level, guest::read8(local_level)).map_err(fault)?;
    if size == 0 {
        return Ok(status);
    }
    probe_output(size, 4, 4)?;
    if cached_flags & 2 == 0 {
        guest::try_write::<u32>(size, 0).map_err(fault)?;
        return Ok(status);
    }
    let length = guest::read32(local_size);
    let mut result = status;
    if guest::try_read::<u32>(size).map_err(fault)? >= length && thumbprint != 0 {
        probe_output(thumbprint, length as u64, 1)?;
        guest::try_write_bytes(thumbprint, &guest::read_bytes(local_thumbprint, length as usize)).map_err(fault)?;
    } else {
        result = STATUS_BUFFER_TOO_SMALL;
    }
    guest::try_write::<u32>(size, length).map_err(fault)?;
    if algorithm != 0 {
        probe_output(algorithm, 4, 4)?;
        guest::try_write::<u32>(algorithm, guest::read32(local_algorithm)).map_err(fault)?;
    }
    Ok(result)
}

/// NtGetCachedSigningLevel(File, Flags*, SigningLevel*, Thumbprint,
/// ThumbprintSize*, ThumbprintAlgorithm*) de modo usuário.
pub fn get_cached_user(file: u64, flags: u64, level: u64, thumbprint: u64, size: u64, algorithm: u64) -> Result<u32, KernelError> {
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
    guest::write32(locals + 0xC, THUMBPRINT_CAPACITY);
    let result = (|| -> Result<u32, KernelError> {
        let referenced = exports::invoke_handler("ObReferenceObjectByHandle", &[file, FILE_READ_DATA, object_types::file_type().pointer, USER_MODE, locals, 0])? as u32;
        if referenced & 0x8000_0000 != 0 {
            return Ok(referenced);
        }
        let file_object = guest::read64(locals);
        let wants = thumbprint != 0;
        let status = get_for_file_object(file_object, locals + 8, locals + 0x14, if wants { locals + 0x20 } else { 0 }, if wants { locals + 0xC } else { 0 }, if wants { locals + 0x10 } else { 0 });
        let status = if status & 0x8000_0000 != 0 {
            status
        } else {
            write_user_outputs(status, locals, flags, level, thumbprint, size, algorithm).unwrap_or_else(|exception| exception)
        };
        exports::invoke_handler("ObfDereferenceObject", &[file_object])?;
        Ok(status)
    })();
    guest::free_bytes(locals);
    result
}

fn nt_compare_signing_levels(actual: u64, expected: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(compare_user(actual as u8, expected as u8))
}

fn nt_get_cached_signing_level(file: u64, flags: u64, level: u64, thumbprint: u64, rsp: u64) -> Result<u32, KernelError> {
    use crate::ntos::ps::user::state;
    get_cached_user(file, flags, level, thumbprint, state::stack_arg(rsp, 5), state::stack_arg(rsp, 6))
}

/// Os handlers dos serviços NtCompareSigningLevels e
/// NtGetCachedSigningLevel de modo usuário.
pub fn register_user_services() {
    use crate::ntos::ps::user::state;
    state::register_handler("NtCompareSigningLevels", nt_compare_signing_levels);
    state::register_handler("NtGetCachedSigningLevel", nt_get_cached_signing_level);
}
