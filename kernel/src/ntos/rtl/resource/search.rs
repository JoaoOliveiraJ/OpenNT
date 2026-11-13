//! Política de recursos do kernel.
//!
//! O contexto fornece os idiomas e a fase de boot reais; os arquivos MUI
//! são abertos e retidos pelo `resource::satellites`.

use crate::ntos::rtl::resource::configuration::{self as resource_configuration, Configuration};
use crate::ntos::rtl::resource::languages as resource_languages;
use crate::ntos::rtl::resource::lookup::{self as resource_lookup, Request};
use crate::ntos::rtl::resource::satellites::{self as resource_satellites, Primary};
use crate::ntos::rtl::resource::tree::{self as resource_tree, Found, Image, Key, LookupOptions, Plan, STATUS_RESOURCE_LANG_NOT_FOUND, STATUS_RESOURCE_TYPE_NOT_FOUND};
use crate::ntos::rtl::unicode_case;
use crate::rtl::KernelError;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// Idiomas da máquina e a fase de boot.
#[derive(Clone, Copy, Debug)]
pub struct Context {
    pub system_languages: [u32; 3],
    pub boot_drivers_initialized: bool,
}

/// VERSION, MANIFEST e MUI com idioma neutro usam o módulo principal, salvo
/// pedido explícito de seleção MUI.
fn base_only(request: &Request, resource_type: &Key) -> Result<bool, KernelError> {
    if request.flags & 0x100_0010 != 0 {
        return Ok(true);
    }
    if request.flags & 8 != 0 || request.language != 0 {
        return Ok(false);
    }
    Ok(match resource_type {
        Key::Id(16) | Key::Id(24) => true,
        Key::Name(units) => unicode_case::upcase_units(units)? == "MUI".encode_utf16().collect::<alloc::vec::Vec<u16>>(),
        _ => false,
    })
}

fn options(request: &Request) -> LookupOptions {
    LookupOptions { count: request.count, directory: request.flags & 2 != 0 }
}

fn lookup(image: &Image, request: &Request, resource_type: &Key, resource_name: &Key, language: u32, select_first: bool) -> Result<Found, KernelError> {
    resource_tree::lookup(image, resource_type, resource_name, &Plan { candidates: alloc::vec![language], select_first, allow_any: false }, [request.type_key, request.name], options(request))
}

pub fn search_mapped(request: &Request, size: u64, context: &Context) -> Result<Found, KernelError> {
    let resource_type = if request.count == 0 { Key::Id(0) } else { resource_lookup::read_key(request.type_key)? };
    let resource_name = if request.count < 2 || request.name < 0x10000 { Key::Id(request.name as u32) } else { Key::Pointer(request.name) };
    let image = match resource_tree::inspect(request.image_base, size as u128, request.raw_file, request.flags & 0x1000 != 0)? {
        Ok(image) => image,
        Err(status) => return Ok(Found::fail(status)),
    };
    let mut membership = 0u32;
    let mut configuration: Option<Configuration> = None;
    let only_primary = base_only(request, &resource_type)?;
    if !only_primary && request.count != 0 {
        match resource_configuration::inspect(&image)? {
            Err(status) if status != STATUS_RESOURCE_TYPE_NOT_FOUND => return Ok(Found::fail(status)),
            Err(_) => {}
            Ok(found) => {
                configuration = Some(found);
                membership = resource_configuration::type_membership(&found, &resource_type)?;
                if membership & 0x6_0000 == 0x6_0000 {
                    return Ok(Found::fail(STATUS_RESOURCE_TYPE_NOT_FOUND));
                }
            }
        }
    }
    let plan = resource_languages::fallback(request.language, request.flags, &context.system_languages)?;
    let last = plan.candidates.last().copied().unwrap_or(0);
    // Sem RC_CONFIG não há particionamento MUI: os mesmos limites, fallback e
    // ordem de erros da árvore PE comum.
    if only_primary || (configuration.is_none() && request.count != 0) {
        let mut result = resource_tree::lookup(&image, &resource_type, &resource_name, &plan, [request.type_key, request.name], options(request))?;
        // A lista interna é mutável: depois de uma busca sem
        // sucesso, a etapa MUN recebe o último idioma tentado.
        if result.status != 0 {
            result.next_language = Some(if only_primary && plan.select_first { 0 } else { last });
        }
        return Ok(result);
    }
    let mut result = Found::fail(STATUS_RESOURCE_LANG_NOT_FOUND);
    for &language in &plan.candidates {
        let any_language = request.language == 0 && language == 0x1234 && plan.allow_any;
        if !any_language && language != 0 && membership & 0x2_0000 == 0 && context.boot_drivers_initialized {
            let primary = Primary { base: image.base, size: image.size, raw_file: image.raw_file };
            if let Ok(alternate) = resource_satellites::load(&primary, configuration, language, membership | 0x1000)? {
                match resource_tree::inspect(alternate.base, alternate.size as u128, true, image.validate)? {
                    Ok(child) => {
                        result = lookup(&child, request, &resource_type, &resource_name, language, true)?;
                        if result.status == 0 {
                            result.language = language;
                            result.satellite = true;
                            if request.flags & 0x40 != 0 && request.buffer_output != 0 {
                                // A tabela MUI publica ponteiro/tamanho antes de
                                // validar a quarta chave; fora do intervalo, limpa e
                                // tenta o principal; formato inválido encerra.
                                let status = resource_lookup::publish_payload(request, &result)?;
                                if status == 0xC000_007B {
                                    return Ok(Found::fail(status));
                                }
                                if status == 0 {
                                    result.published = true;
                                    return Ok(result);
                                }
                                // Fora do intervalo: segue para o módulo principal.
                            } else {
                                return Ok(result);
                            }
                        }
                    }
                    // O status do satélite é substituído pela busca no principal.
                    Err(_) => {}
                }
            }
        }
        // Com o tipo excluído pelo RC_CONFIG, a raiz principal fica nula e a
        // busca nela devolve INVALID_PARAMETER, não um recurso inventado.
        result = if membership & 0x4_0000 != 0 { Found::fail(STATUS_INVALID_PARAMETER) } else { lookup(&image, request, &resource_type, &resource_name, language, plan.select_first || any_language)? };
        if result.status == 0 {
            return Ok(result);
        }
    }
    result.next_language = Some(last);
    Ok(result)
}

/// O fallback MUN só vem depois de TYPE_NOT_FOUND, nunca de falha de
/// idioma/nome; VERSION e MANIFEST ficam de fora.
pub fn search(request: &Request, size: u64, context: &Context) -> Result<Found, KernelError> {
    let result = search_mapped(request, size, context)?;
    if result.status != STATUS_RESOURCE_TYPE_NOT_FOUND || request.type_key == 16 || request.type_key == 24 {
        return Ok(result);
    }
    let primary = Primary { base: request.image_base, size: size as u128, raw_file: request.raw_file };
    let Ok(alternate) = resource_satellites::load(&primary, None, 0xF2EE, 0x100_0000)? else { return Ok(result) };
    let fallback = Request { image_base: alternate.base, raw_file: true, language: result.next_language.unwrap_or(request.language), flags: request.flags | 0x100_0000, ..request.clone() };
    search_mapped(&fallback, alternate.size, context)
}
