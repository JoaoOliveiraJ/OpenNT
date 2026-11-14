//! LdrResFindResource / LdrResSearchResource.
//!
//! A pesquisa validada com os donos reais de módulos, VADs, arquivos e NLS;
//! a API só publica endereços de bytes existentes.

use crate::ntos::rtl::nls_configuration;
use crate::ntos::rtl::resource::lookup::{self as resource_lookup, Request};
use crate::ntos::rtl::resource::memory as resource_memory;
use crate::ntos::rtl::resource::search::{self as resource_search, Context};
use crate::ntos::io::small::boot_drivers_state;
use crate::ntos::mm::{loaded_images, query_virtual};
use crate::rtl::KernelError;
use crate::ntos::inc::types::{MemoryRegionInformation, NtStruct};
use crate::ntos::mm::guest_memory as guest;

/// Extensão da alocação: a imagem carregada ou a região da VAD
/// (MemoryRegionInformation.RegionSize).
fn allocation_size(base: u64) -> Result<Result<u64, u32>, KernelError> {
    if let Some(image) = loaded_images::find(base) {
        return Ok(Ok(image.size_of_image));
    }
    let buffer = guest::alloc_bytes(MemoryRegionInformation::SIZE);
    if buffer == 0 {
        return Ok(Err(0xC000_009A));
    }
    let status = query_virtual::query(u64::MAX, base, 3, buffer, MemoryRegionInformation::SIZE, 0);
    // SAFETY: MEMORY_REGION_INFORMATION recém-preenchido no bloco alocado acima.
    let result = status.map(|status| if status != 0 { Err(status) } else { Ok(unsafe { MemoryRegionInformation::at(buffer) }.region_size.get()) });
    guest::free_bytes(buffer);
    result
}

fn execute(prepared: Result<Result<Request, u32>, KernelError>) -> Result<u32, KernelError> {
    let outcome = (|| -> Result<u32, KernelError> {
        let request = match prepared? {
            Ok(request) => request,
            Err(status) => return Ok(status),
        };
        let size = match resource_lookup::mapping_size(&request, allocation_size)? {
            Ok(size) => size,
            Err(status) => return Ok(status),
        };
        let context = Context { system_languages: nls_configuration::resource_languages(), boot_drivers_initialized: boot_drivers_state::is_initialized() };
        let resource = resource_search::search(&request, size, &context)?;
        resource_lookup::publish(&request, &resource)
    })();
    // Só uma falha de memória identificada vira NTSTATUS; erros internos,
    // transferências SEH e bugchecks seguem para os seus dispatchers.
    match outcome {
        Err(error) => match resource_memory::access_status(&error) {
            Some(status) => Ok(status),
            None => Err(error),
        },
        other => other,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn find(image_base: u64, resource_type: u64, resource_name: u64, language: u64, buffer_output: u64, size_output: u64, culture_output: u64, culture_length_output: u64, flags: u64) -> Result<u32, KernelError> {
    execute(resource_lookup::prepare(image_base, resource_type, resource_name, language, buffer_output, size_output, culture_output, culture_length_output, flags))
}

#[allow(clippy::too_many_arguments)]
pub fn search(image_base: u64, resource_path: u64, count: u64, flags: u64, buffer_output: u64, size_output: u64, culture_output: u64, culture_length_output: u64) -> Result<u32, KernelError> {
    execute(resource_lookup::prepare_search(image_base, resource_path, count, flags, buffer_output, size_output, culture_output, culture_length_output))
}

/// LdrResFindResourceDirectory(DllHandle, Type, Name, ResourceDirectory,
/// CultureName, CultureNameLength, Flags) no ntoskrnl 19041 (0x78dd80):
/// Flags com 0x400/0x800 dá STATUS_INVALID_PARAMETER; senão é o
/// LdrResSearchResource do caminho [Type, Name] com Flags |
/// LDR_FIND_RESOURCE_DIRECTORY (2), contando só até a última chave dada
/// (Name sem Type ainda conta duas; a chave de tipo ausente, que o original
/// deixa sem inicializar, vai como 0).
#[allow(clippy::too_many_arguments)]
pub fn find_directory(image_base: u64, resource_type: u64, resource_name: u64, directory_output: u64, culture_output: u64, culture_length_output: u64, flags: u64) -> Result<u32, KernelError> {
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    if flags as u32 & 0xC00 != 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let count = if resource_name != 0 { 2 } else { (resource_type != 0) as u64 };
    let path = guest::alloc_bytes(16);
    if path == 0 {
        return Ok(0xC000_009A);
    }
    guest::write64(path, resource_type);
    guest::write64(path + 8, resource_name);
    let result = search(image_base, path, count, (flags as u32 | 2) as u64, directory_output, 0, culture_output, culture_length_output);
    guest::free_bytes(path);
    result
}
