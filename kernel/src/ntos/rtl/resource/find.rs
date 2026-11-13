//! LdrResFindResource / LdrResSearchResource — `system32/ntos/rtl/find-resource.js`.
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
use crate::ntos::mm::guest_memory as guest;

/// Extensão da alocação: a imagem carregada ou a região da VAD
/// (MemoryRegionInformation.RegionSize).
fn allocation_size(base: u64) -> Result<Result<u64, u32>, KernelError> {
    if let Some(image) = loaded_images::find(base) {
        return Ok(Ok(image.size_of_image));
    }
    let buffer = guest::alloc_bytes(48);
    if buffer == 0 {
        return Ok(Err(0xC000_009A));
    }
    let status = query_virtual::query(u64::MAX, base, 3, buffer, 48, 0);
    let result = status.map(|status| if status != 0 { Err(status) } else { Ok(guest::read64(buffer + 16)) });
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
