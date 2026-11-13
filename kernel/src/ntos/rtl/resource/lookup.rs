//! Etapas da pesquisa de recursos — `system32/ntos/rtl/resource-lookup.js`.
//!
//! Preparação com a ordem de rejeição do wrapper e de LdrResSearchResource,
//! extensão da vista, publicação das saídas e validação da tabela de
//! intervalos MUI.

use alloc::vec::Vec;

use crate::ntos::rtl::resource::languages as resource_languages;
use crate::ntos::rtl::resource::memory as resource_memory;
use crate::ntos::rtl::resource::tree::{self as resource_tree, Found, Key, LookupOptions};
use crate::rtl::KernelError;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;

/// Pedido preparado.
#[derive(Clone, Debug, Default)]
pub struct Request {
    pub image_base: u64,
    pub raw_file: bool,
    pub type_key: u64,
    pub name: u64,
    pub language: u32,
    /// Chaves usadas (3 no LdrResFindResource).
    pub count: u32,
    pub range_identifier: u32,
    pub buffer_output: u64,
    pub size_output: u64,
    pub culture_output: u64,
    pub culture_length_output: u64,
    pub supplied_size: u64,
    pub flags: u32,
}

/// Ponteiro abaixo de 0x10000 é um identificador; senão, uma string terminada.
pub fn read_key(pointer: u64) -> Result<Key, KernelError> {
    if pointer < 0x10000 {
        return Ok(Key::Id(pointer as u32));
    }
    let mut units = Vec::new();
    let mut at = pointer;
    loop {
        let character = resource_memory::read16(at)?;
        if character == 0 {
            return Ok(Key::Name(units));
        }
        units.push(character);
        at = at.wrapping_add(2);
    }
}

/// Flags padrão e as recusas comuns às duas entradas.
fn normalize(mut flags: u32) -> Result<u32, u32> {
    if flags & 0xF00 == 0 {
        flags |= 0x100;
    }
    if flags & 0x2000 == 0 {
        flags |= 0x1000;
    }
    if flags & 0xFFF0_0000 != 0 {
        return Err(STATUS_INVALID_PARAMETER_4);
    }
    Ok(flags)
}

fn conflicting(flags: u32) -> bool {
    (flags & 0x100 != 0 && flags & 0xE00 != 0) || flags & 0x8000 != 0 || flags & 0x3000 == 0x3000 || flags & 0x18 == 0x18
}

fn supplied_size(flags: u32, size_output: u64) -> Result<Result<u64, u32>, KernelError> {
    if flags & 0x8_0000 == 0 {
        return Ok(Ok(0));
    }
    if size_output == 0 {
        return Ok(Err(STATUS_INVALID_PARAMETER));
    }
    let size = resource_memory::read64(size_output)?;
    Ok(if size == 0 { Err(STATUS_INVALID_PARAMETER) } else { Ok(size) })
}

/// LdrResFindResource: nenhuma saída é alterada ao rejeitar flags,
/// ponteiros obrigatórios ou LANGID.
#[allow(clippy::too_many_arguments)]
pub fn prepare(image_base: u64, resource_type: u64, resource_name: u64, language: u64, buffer_output: u64, size_output: u64, culture_output: u64, culture_length_output: u64, flags: u64) -> Result<Result<Request, u32>, KernelError> {
    let flags = flags as u32;
    if flags & 0xC02 != 0 {
        return Ok(Err(STATUS_INVALID_PARAMETER));
    }
    if image_base == 0 || (culture_output != 0 && culture_length_output == 0) {
        return Ok(Err(STATUS_INVALID_PARAMETER));
    }
    let flags = match normalize(flags) {
        Ok(flags) => flags,
        Err(status) => return Ok(Err(status)),
    };
    if flags & 0x41 != 0 {
        return Ok(Err(STATUS_INVALID_PARAMETER_3));
    }
    if conflicting(flags) {
        return Ok(Err(STATUS_INVALID_PARAMETER_4));
    }
    if flags & 0x2_0000 != 0 {
        return Ok(Err(STATUS_INVALID_PARAMETER));
    }
    let supplied = match supplied_size(flags, size_output)? {
        Ok(size) => size,
        Err(status) => return Ok(Err(status)),
    };
    let language = match resource_languages::resolve(&read_key(language)?) {
        Ok(language) => language,
        Err(status) => return Ok(Err(status)),
    };
    Ok(Ok(Request { image_base: image_base & !3, raw_file: image_base & 1 != 0 || flags & 0x200 != 0, type_key: resource_type, name: resource_name, language, count: 3, range_identifier: 0, buffer_output, size_output, culture_output, culture_length_output, supplied_size: supplied, flags }))
}

/// LdrResSearchResource: lista contada de ULONG_PTR, com os guardas antes
/// da cópia (mesmo com ResourcePath inválido).
#[allow(clippy::too_many_arguments)]
pub fn prepare_search(image_base: u64, resource_path: u64, count: u64, flags: u64, buffer_output: u64, size_output: u64, culture_output: u64, culture_length_output: u64) -> Result<Result<Request, u32>, KernelError> {
    let count = count as u32;
    let flags = flags as u32;
    if image_base == 0 || resource_path == 0 || (culture_output != 0 && culture_length_output == 0) {
        return Ok(Err(STATUS_INVALID_PARAMETER));
    }
    if flags & 0xC00 != 0 {
        return Ok(Err(STATUS_INVALID_PARAMETER_4));
    }
    let flags = match normalize(flags) {
        Ok(flags) => flags,
        Err(status) => return Ok(Err(status)),
    };
    if count > 4 || (count < 3 && flags & 2 == 0) {
        return Ok(Err(STATUS_INVALID_PARAMETER_3));
    }
    if flags & 0x41 != 0 {
        if count != 4 {
            return Ok(Err(STATUS_INVALID_PARAMETER_3));
        }
    } else if count == 4 {
        return Ok(Err(STATUS_INVALID_PARAMETER_4));
    }
    if conflicting(flags) {
        return Ok(Err(STATUS_INVALID_PARAMETER_4));
    }
    if flags & 0x2_0000 != 0 {
        return Ok(Err(STATUS_INVALID_PARAMETER));
    }
    let supplied = match supplied_size(flags, size_output)? {
        Ok(size) => size,
        Err(status) => return Ok(Err(status)),
    };
    // Todas as chaves são copiadas antes de ler strings ou escrever saídas:
    // a lista original pode sobrepor as saídas sem alterar a pesquisa.
    let mut keys = Vec::new();
    for index in 0..count as u64 {
        keys.push(resource_memory::read64(resource_path.wrapping_add(index * 8))?);
    }
    let language = if count >= 3 {
        match resource_languages::resolve(&read_key(keys[2])?) {
            Ok(language) => language,
            Err(status) => return Ok(Err(status)),
        }
    } else {
        0
    };
    let key = |index: usize| keys.get(index).copied().unwrap_or(0);
    Ok(Ok(Request { image_base: image_base & !3, raw_file: image_base & 1 != 0 || flags & 0x200 != 0, type_key: key(0), name: key(1), language, count: count.min(3), range_identifier: key(3) as u32, buffer_output, size_output, culture_output, culture_length_output, supplied_size: supplied, flags }))
}

/// Extensão da vista: o tamanho do cabeçalho no caminho de imagem; arquivos
/// usam a extensão da alocação, consultada só quando necessário.
pub fn mapping_size(request: &Request, query_allocation_size: fn(u64) -> Result<Result<u64, u32>, KernelError>) -> Result<Result<u64, u32>, KernelError> {
    if request.flags & 0x8_0000 != 0 {
        return Ok(Ok(request.supplied_size));
    }
    let header = match resource_tree::inspect_header(request.image_base, 0, request.raw_file, false)? {
        Ok(image) => image,
        Err(status) => return Ok(Err(status)),
    };
    let image_size = header.image_size as u64;
    if !request.raw_file && request.flags & 0x100 != 0 && image_size != 0 {
        return Ok(Ok(image_size));
    }
    let allocation = query_allocation_size(request.image_base)?;
    if matches!(allocation, Ok(size) if size != 0) {
        return Ok(allocation);
    }
    Ok(if image_size != 0 { Ok(image_size) } else { allocation })
}

/// Ponteiro, SIZE_T e só então cultura; falta de espaço na cultura não
/// desfaz as duas primeiras saídas.
pub fn publish_payload(request: &Request, resource: &Found) -> Result<u32, KernelError> {
    if request.buffer_output != 0 {
        resource_memory::write64(request.buffer_output, resource.address)?;
    }
    if request.size_output != 0 && !resource.directory {
        resource_memory::write64(request.size_output, resource.size as u64)?;
    }
    // O modo de quatro chaves/0x40 valida a tabela de intervalos só quando o
    // payload veio do MUI; a publicação precede essa verificação.
    if request.flags & 0x40 != 0 && resource.satellite && request.buffer_output != 0 {
        let pointer = resource_memory::read64(request.buffer_output)?;
        let size = if request.size_output != 0 { resource_memory::read64(request.size_output)? } else { resource.size as u64 };
        let status = validate_range(pointer, size, request.range_identifier)?;
        if status != 0 {
            resource_memory::write64(request.buffer_output, 0)?;
            return Ok(status);
        }
    }
    Ok(0)
}

pub fn publish(request: &Request, resource: &Found) -> Result<u32, KernelError> {
    if resource.status != 0 {
        return Ok(resource.status);
    }
    if !resource.published {
        let status = publish_payload(request, resource)?;
        if status != 0 {
            return Ok(status);
        }
    }
    if request.culture_length_output != 0 {
        let Some(culture) = resource_languages::name_for_identifier(resource.language) else { return Ok(0xC000_0001) };
        let units: Vec<u16> = culture.encode_utf16().collect();
        let capacity = resource_memory::read32(request.culture_length_output)?;
        let required = units.len() as u32 + 1;
        if capacity < required || request.culture_output == 0 {
            resource_memory::write32(request.culture_length_output, required)?;
            return Ok(0xC000_0023);
        }
        for (index, unit) in units.iter().enumerate() {
            resource_memory::write16(request.culture_output + index as u64 * 2, *unit)?;
        }
        resource_memory::write32(request.culture_length_output, required)?;
        resource_memory::write16(request.culture_output + units.len() as u64 * 2, 0)?;
    }
    Ok(0)
}

/// Registros com início/fim inclusivos e um DWORD adicional; a extensão
/// completa é conferida antes de procurar o identificador.
pub fn validate_range(pointer: u64, size: u64, identifier: u32) -> Result<u32, KernelError> {
    if pointer == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let count = resource_memory::read32(pointer)? as u64;
    if count * 12 + 4 > size {
        return Ok(0xC000_007B);
    }
    for index in 0..count {
        let entry = pointer + 4 + index * 12;
        if identifier >= resource_memory::read32(entry)? && identifier <= resource_memory::read32(entry + 4)? {
            return Ok(0);
        }
    }
    Ok(0xC000_0109)
}

/// Pesquisa só no módulo principal com o fallback de idiomas.
pub fn lookup_primary(request: &Request, size: u64, system_languages: &[u32]) -> Result<Found, KernelError> {
    let image = match resource_tree::inspect(request.image_base, size as u128, request.raw_file, request.flags & 0x1000 != 0)? {
        Ok(image) => image,
        Err(status) => return Ok(Found::fail(status)),
    };
    let plan = resource_languages::fallback(request.language, request.flags, system_languages)?;
    resource_tree::lookup(&image, &read_key(request.type_key)?, &read_key(request.name)?, &plan, [request.type_key, request.name], LookupOptions::default())
}
