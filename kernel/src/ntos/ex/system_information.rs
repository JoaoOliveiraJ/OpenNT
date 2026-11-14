//! Informações do sistema em modo kernel: Zw/NtQuerySystemInformation e
//! ZwSetSystemInformation.
//!
//! A consulta despacha cada classe para a folha dona (boot, Code Integrity,
//! Secure Boot, módulos, processadores, processos); a alteração aceita a
//! classe 131, que registra as rotinas de entropia que o RNG do kernel chama
//! ao coletar/resemear entropia.

use alloc::vec::Vec;

use crate::ntos::ex::boot_environment_information;
use crate::ntos::ke::processor_information;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::module_queries;
use crate::ntos::ps::system_process_information;
use crate::ntos::se::{code_integrity_information, secure_boot_information};
use crate::rtl::{KernelError, SpinLock};

/// Rotinas de entropia registradas por ZwSetSystemInformation(131): o RNG
/// do kernel as chama ao coletar/resemear entropia.
#[derive(Clone, Copy, Debug)]
pub struct EntropyRegistration {
    pub entropy_routine: u64,
    pub initialization_routine: u64,
    pub initialization_context: u64,
}

static ENTROPY_TIMING_REGISTRATIONS: SpinLock<Vec<EntropyRegistration>> = SpinLock::new(Vec::new());

/// Buffer da classe 131 (registro de entropia por tempo de interrupção).
#[repr(C)]
struct EntropyTimingInformation {
    entropy_routine: Field<u64>,
    initialization_routine: Field<u64>,
    initialization_context: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for EntropyTimingInformation {}

const _: () = assert!(core::mem::size_of::<EntropyTimingInformation>() == 24);

pub fn entropy_registrations() -> Vec<EntropyRegistration> {
    ENTROPY_TIMING_REGISTRATIONS.lock().clone()
}

/// ZwQuerySystemInformation/NtQuerySystemInformation (o mesmo corpo).
pub fn query(class: u32, output: u64, length: u32, returned: u64) -> Result<u32, KernelError> {
    debug_print!("[zw] QuerySystemInformation classe {} buf={}", class, length);
    match class {
        90 => return boot_environment_information::query(output, length as u64, returned, false),
        103 => return code_integrity_information::query(output, length as u64, returned, false),
        143 => return secure_boot_information::query(output, length as u64, returned, false),
        157 => return crate::ntos::ex::manufacturing_information::query(output, length as u64, returned, false),
        11 | 77 => return module_queries::query_system_modules(class, output, length as u64, returned),
        1 | 63 => return Ok(processor_information::query(output, length, returned, false, class == 63)),
        // SystemCodeIntegrityCertificateManagementInformation: nenhuma
        // operação de certificados pendente (o cng percorre e segue).
        117 => {
            guest::write_bytes(output, &alloc::vec![0u8; length as usize]);
            if returned != 0 {
                // SAFETY: o PULONG ReturnLength do chamador (modo kernel).
                unsafe { Field::<u32>::at(returned) }.set(length);
            }
            return Ok(0);
        }
        5 => {}
        _ => return Ok(0xC000_000D),
    }
    system_process_information::query(output, length as u64, returned, false)
}

/// ZwSetSystemInformation: 131 registra as rotinas de entropia do chamador;
/// classes desconhecidas = STATUS_INVALID_INFO_CLASS.
pub fn set(class: u32, buffer: u64, length: u32) -> u32 {
    if class == SYSTEM_EXTEND_SERVICE_TABLE_INFORMATION {
        return extend_service_table(buffer, length).unwrap_or_else(|error| if error.status != 0 { error.status } else { 0xC000_0001 });
    }
    if class == 131 {
        if (length as u64) < EntropyTimingInformation::SIZE {
            return 0xC000_0004;
        }
        let count = {
            let mut registrations = ENTROPY_TIMING_REGISTRATIONS.lock();
            // SAFETY: buffer de entrada do chamador (modo kernel), tamanho conferido.
            let information = unsafe { EntropyTimingInformation::at(buffer) };
            registrations.push(EntropyRegistration { entropy_routine: information.entropy_routine.get(), initialization_routine: information.initialization_routine.get(), initialization_context: information.initialization_context.get() });
            registrations.len()
        };
        debug_print!("[zw] entropia: rotinas registradas ({} provedor(es))", count);
        return 0;
    }
    debug_print!("[zw] ZwSetSystemInformation classe {} (sem suporte)", class);
    0xC000_0003
}

// ---- SystemExtendServiceTableInformation (38): a carga do win32k.sys ------
//
// (append de `ke-service-tables` ao ex/system_information.rs. Usa o `Field`,
// o `NtStruct` e o `guest` já importados pelo arquivo, sem linhas `use` novas.)
//
// NtSetSystemInformation(38) no ntoskrnl 19041 (modo kernel): a entrada é uma
// UNICODE_STRING (Length != 0x10 -> STATUS_INFO_LENGTH_MISMATCH). Para
// "\SystemRoot\System32\win32k.sys" o LoadFlags é 0x80000005 (sessão +
// compactação das tabelas de serviço, `mm::sysload`); para outra imagem, só
// sessão. IMAGE_ALREADY_LOADED_AS_DLL vira IMAGE_ALREADY_LOADED; sem cabeçalho
// NT, descarrega e devolve INVALID_IMAGE_FORMAT; depois o
// ExpInitializeSessionDriver chama o ponto de entrada com um DRIVER_OBJECT
// zerado de 0x150 bytes (só o DriverStart = base) e RegistryPath NULL, e uma
// falha descarrega a imagem. O MmSessionSetUnloadAddress do sucesso guarda o
// DriverUnload para o fim da sessão; o OpenNT tem sessão única e não o usa.

/// SYSTEM_INFORMATION_CLASS SystemExtendServiceTableInformation.
pub const SYSTEM_EXTEND_SERVICE_TABLE_INFORMATION: u32 = 38;
const EXTEND_SERVICE_TABLE_WIN32K: &str = "\\SystemRoot\\System32\\win32k.sys";
/// LoadFlags do win32k.sys e das demais imagens.
const EXTEND_SERVICE_TABLE_WIN32K_FLAGS: u32 = 0x8000_0005;
const EXTEND_SERVICE_TABLE_SESSION_FLAGS: u32 = 1;
const EXTEND_STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const EXTEND_STATUS_INVALID_IMAGE_FORMAT: u32 = 0xC000_007B;
const EXTEND_STATUS_IMAGE_ALREADY_LOADED: u32 = 0xC000_010E;
const EXTEND_STATUS_IMAGE_ALREADY_LOADED_AS_DLL: u32 = 0xC000_019D;

/// ExpInitializeSessionDriver(EntryPoint, ImageBase): o NTSTATUS do ponto de
/// entrada.
fn initialize_session_driver(entry_point: u64, image_base: u64) -> u32 {
    use crate::ntos::inc::types::DriverObject;
    let address = guest::alloc_bytes(DriverObject::SIZE);
    if address == 0 {
        return crate::ntos::inc::status::STATUS_INSUFFICIENT_RESOURCES;
    }
    guest::write_bytes(address, &alloc::vec![0u8; DriverObject::SIZE as usize]);
    // SAFETY: DRIVER_OBJECT recém-alocado e zerado.
    unsafe { DriverObject::at(address) }.driver_start.set(image_base);
    let status = crate::hal::amd64::native_call::call(entry_point, &[address, 0]) as u32;
    guest::free_bytes(address);
    status
}

/// SystemExtendServiceTableInformation: carrega a imagem nomeada pela
/// UNICODE_STRING em `buffer` (convertendo as tabelas de serviço do
/// win32k.sys) e chama o ponto de entrada; devolve o NTSTATUS.
pub fn extend_service_table(buffer: u64, length: u32) -> Result<u32, KernelError> {
    use crate::ntos::mm::sysload;
    if length as u64 != crate::ntos::inc::types::UnicodeString::SIZE {
        return Ok(EXTEND_STATUS_INFO_LENGTH_MISMATCH);
    }
    let name = crate::ntos::rtl::guest_strings::read_unicode_string(buffer);
    let flags = if name == EXTEND_SERVICE_TABLE_WIN32K { EXTEND_SERVICE_TABLE_WIN32K_FLAGS } else { EXTEND_SERVICE_TABLE_SESSION_FLAGS };
    let outputs = guest::alloc_bytes(16);
    if outputs == 0 {
        return Ok(crate::ntos::inc::status::STATUS_INSUFFICIENT_RESOURCES);
    }
    let loaded = sysload::load_system_image_extending_services(buffer, flags, outputs, outputs + 8);
    // SAFETY: as duas células PVOID alocadas acima.
    let (handle, image_base) = unsafe { (Field::<u64>::at(outputs).get(), Field::<u64>::at(outputs + 8).get()) };
    guest::free_bytes(outputs);
    let status = loaded?;
    if status & 0x8000_0000 != 0 {
        return Ok(if status == EXTEND_STATUS_IMAGE_ALREADY_LOADED_AS_DLL { EXTEND_STATUS_IMAGE_ALREADY_LOADED } else { status });
    }
    let header = crate::ntos::rtl::image::nt_header(image_base)?;
    if header == 0 {
        sysload::unload_system_image(handle)?;
        return Ok(EXTEND_STATUS_INVALID_IMAGE_FORMAT);
    }
    // SAFETY: cabeçalho NT da imagem recém-carregada.
    let entry_point = image_base + unsafe { crate::ntos::inc::types::ImageNtHeaders64::at(header) }.optional_header.address_of_entry_point.get() as u64;
    let status = initialize_session_driver(entry_point, image_base);
    if status & 0x8000_0000 != 0 {
        sysload::unload_system_image(handle)?;
    }
    Ok(status)
}
