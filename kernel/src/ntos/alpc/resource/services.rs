//! Serviços ALPC de recursos e de controle da porta —
//! `system32/ntos/alpc/{create,delete}-{security-context,resource-reserve,
//! port-section,section-view}.js`, `disconnect-port.js` e `set-information.js`.
//!
//! Cada serviço referencia a porta pela tabela dona (acesso 1), entra em
//! região crítica e devolve o NTSTATUS do provedor.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::alpc::message::buffer as message_buffer;
use crate::ntos::alpc::port_reference::{self, PortReference};
use crate::ntos::alpc::port_sections::{self, Creation, Region, SectionRecord};
use crate::ntos::alpc::section_views::{self, MapOptions};
use crate::ntos::alpc::security_contexts::{self, Quality};
use crate::ntos::alpc::completion_association;
use crate::ntos::alpc::resource::reserves as resource_reserves;
use crate::ntos::ke::critical_region;
use crate::ntos::mm::section::handles::{self as section_handles, Kind};
use crate::ntos::mm::section::parameters::{self as section_parameters, Decoded};
use crate::ntos::ob::objects::port::Port;
use crate::ntos::ob::objects::section as section_objects;
use crate::ntos::ps::process;
use crate::ntos::ps::user::sections::{self, MapRequest, Section};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const INVALID_PARAMETER: u32 = 0xC000_000D;
const ACCESS_VIOLATION: u32 = 0xC000_0005;
const SECURE: u32 = 0x4_0000;

/// Região crítica em volta do corpo do serviço.
fn critical<R>(body: impl FnOnce() -> Result<R, KernelError>) -> Result<R, KernelError> {
    critical_region::enter_critical()?;
    let result = body();
    let _ = critical_region::leave_critical();
    result
}

/// Executa `body` com a porta referenciada e solta a referência no fim.
fn with_port(handle: u64, mode: u8, body: impl FnOnce(&Arc<Port>) -> Result<u32, KernelError>) -> Result<u32, KernelError> {
    let mut reference: PortReference = match port_reference::reference(handle, 1, mode)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let result = body(&reference.port.clone());
    let _ = reference.release();
    result
}

pub fn create_security_context(handle: u64, flags: u32, attribute: u64, mode: u8) -> Result<u32, KernelError> {
    critical(|| {
        if flags != 0 {
            return Ok(INVALID_PARAMETER);
        }
        if mode != 0 && attribute & 7 != 0 {
            return Ok(0x8000_0002);
        }
        if mode != 0 && !message_buffer::writable(attribute, 24, mode) {
            return Ok(ACCESS_VIOLATION);
        }
        if !message_buffer::accessible(attribute, 16, mode, false) {
            return Ok(ACCESS_VIOLATION);
        }
        let captured = match security_contexts::quality(guest::read64(attribute + 8), mode) {
            Ok(captured) => captured,
            Err(status) => return Ok(status),
        };
        with_port(handle, mode, |port| {
            let quality = captured.or_else(|| port.with(|state| state.security_quality)).unwrap_or(Quality { level: 2, tracking: 0, effective_only: false });
            let record = match security_contexts::create(port, &quality, true)? {
                Ok(record) => record,
                Err(status) => return Ok(status),
            };
            let published = message_buffer::writable(attribute + 16, 8, mode);
            if published {
                guest::write64(attribute + 16, record.handle);
            } else {
                security_contexts::delete_referenced(&record)?;
            }
            security_contexts::release(&record)?;
            Ok(if published { 0 } else { ACCESS_VIOLATION })
        })
    })
}

pub fn delete_security_context(port_handle: u64, flags: u32, context_handle: u64, mode: u8) -> Result<u32, KernelError> {
    critical(|| {
        if flags != 0 {
            return Ok(INVALID_PARAMETER);
        }
        with_port(port_handle, mode, |port| {
            let record = match security_contexts::reference(port, context_handle)? {
                Ok(record) => record,
                Err(status) => return Ok(status),
            };
            let result = security_contexts::delete_referenced(&record);
            security_contexts::release(&record)?;
            result
        })
    })
}

pub fn create_resource_reserve(port_handle: u64, flags: u32, size: u64, output: u64, mode: u8) -> Result<u32, KernelError> {
    critical(|| {
        if flags != 0 {
            return Ok(INVALID_PARAMETER);
        }
        if mode != 0 && !message_buffer::writable(output, 4, mode) {
            return Ok(ACCESS_VIOLATION);
        }
        with_port(port_handle, mode, |port| {
            port.run(|| {
                let record = match resource_reserves::create(port, size)? {
                    Ok(record) => record,
                    Err(status) => return Ok(status),
                };
                if !message_buffer::writable(output, 4, mode) {
                    return Ok(ACCESS_VIOLATION);
                }
                guest::write32(output, record.identifier);
                Ok(0)
            })
        })
    })
}

pub fn delete_resource_reserve(port_handle: u64, flags: u32, identifier: u32, mode: u8) -> Result<u32, KernelError> {
    critical(|| {
        if flags != 0 || identifier & 0x8000_0000 == 0 {
            return Ok(INVALID_PARAMETER);
        }
        with_port(port_handle, mode, |port| {
            port.run(|| match resource_reserves::find(port, identifier) {
                Some(record) => resource_reserves::remove(&record),
                None => Ok(0xC000_0008),
            })
        })
    })
}

/// Backing da seção: um SECTION existente (acesso 6) ou uma seção de
/// pagefile com o tamanho real arredondado a 64 KiB.
fn allocate(port: &Arc<Port>, secure: bool, section_handle: u64, requested: u64, mode: u8) -> Result<Result<(u32, Arc<SectionRecord>), u32>, KernelError> {
    if requested == 0 {
        return Ok(Err(INVALID_PARAMETER));
    }
    if port.with(|state| state.port_flags) & 0x100_0000 != 0 {
        return Ok(Err(0xC000_0706));
    }
    let storage = guest::alloc_bytes(0x48);
    if storage == 0 {
        return Ok(Err(0xC000_009A));
    }
    let actual_size = requested.wrapping_add(0xFFFF) & !0xFFFF;
    let creator = process::get_current_process();
    let mut backing: Option<Arc<Section>> = None;
    let mut backing_reference: Option<section_handles::Reference> = None;
    let mut creator_retained = false;
    let mut published = false;
    let outcome = (|| -> Result<Result<(u32, Arc<SectionRecord>), u32>, KernelError> {
        if section_handle != 0 {
            let reference = match section_handles::reference(section_handle, Kind::Section, 6, mode) {
                Ok(reference) => reference,
                Err(status) => return Ok(Err(status)),
            };
            backing = reference.section.clone();
            backing_reference = Some(reference);
            if backing.is_none() {
                return Ok(Err(0xC000_0024));
            }
        } else {
            let request = match section_parameters::decode(0x0800_0000, 4, actual_size, 0, 1, false) {
                Decoded::Request(request) => request,
                Decoded::Status(status) => return Ok(Err(status)),
                Decoded::Partition { .. } => return Ok(Err(INVALID_PARAMETER)),
            };
            let size = match section_parameters::pagefile_size(&request) {
                Ok(size) => size,
                Err(status) => return Ok(Err(status)),
            };
            match sections::create(sections::CreateOptions { size: size.rounded_size, page_protect: 4, attributes: 0x0800_0000, ..sections::CreateOptions::default() })? {
                Ok(section) => backing = Some(section),
                Err(status) => return Ok(Err(status)),
            }
        }
        if process::reference(creator).is_none() {
            return Err(KernelError::new("ALPC section creator has no process object"));
        }
        creator_retained = true;
        let Some(section) = backing.clone() else { return Ok(Err(0xC000_0024)) };
        let attached = port_sections::attach(
            port,
            &section,
            Creation {
                actual_size: Some(actual_size),
                secure,
                created_backing: section_handle == 0,
                creator_process: Some(creator),
                release_metadata: Some(Box::new(move || {
                    let _ = process::dereference(creator);
                    guest::free_bytes(storage);
                })),
            },
        )?;
        published = attached.is_ok();
        Ok(attached)
    })();
    if let Some(reference) = backing_reference {
        let _ = reference.release();
    } else if let Some(section) = backing.as_ref().filter(|_| !published) {
        let _ = section_objects::collect(section.pointer());
    }
    if !published {
        if creator_retained {
            let _ = process::dereference(creator);
        }
        guest::free_bytes(storage);
    }
    outcome
}

pub fn create_port_section(port_handle: u64, flags: u32, section_handle: u64, requested: u64, output_handle: u64, output_size: u64, mode: u8) -> Result<u32, KernelError> {
    critical(|| {
        if flags & !SECURE != 0 || (flags & SECURE != 0 && section_handle != 0) {
            return Ok(INVALID_PARAMETER);
        }
        if mode != 0 && (!message_buffer::writable(output_handle, 8, mode) || !message_buffer::writable(output_size, 8, mode)) {
            return Ok(ACCESS_VIOLATION);
        }
        with_port(port_handle, mode, |port| {
            let (handle, record) = match allocate(port, flags & SECURE != 0, section_handle, requested, mode)? {
                Ok(allocated) => allocated,
                Err(status) => return Ok(status),
            };
            let Ok(retained) = port_sections::reference(port, handle as u64) else { return Err(KernelError::new("ALPC created resource disappeared before delivery")) };
            let mut delivered = false;
            let status = if !message_buffer::writable(output_handle, 8, mode) {
                ACCESS_VIOLATION
            } else {
                guest::write64(output_handle, handle as u64);
                if !message_buffer::writable(output_size, 8, mode) {
                    ACCESS_VIOLATION
                } else {
                    guest::write64(output_size, record.actual_size);
                    delivered = true;
                    0
                }
            };
            if !delivered && !record.state.lock().deleted {
                port_sections::delete_referenced(&record)?;
            }
            port_sections::release(&retained)?;
            Ok(status)
        })
    })
}

pub fn delete_port_section(port_handle: u64, flags: u32, section_handle: u64, mode: u8) -> Result<u32, KernelError> {
    critical(|| {
        if flags != 0 {
            return Ok(INVALID_PARAMETER);
        }
        with_port(port_handle, mode, |port| {
            let record = match port_sections::reference(port, section_handle) {
                Ok(record) => record,
                Err(status) => return Ok(status),
            };
            let result = port_sections::delete_referenced(&record);
            port_sections::release(&record)?;
            result
        })
    })
}

pub fn create_section_view(handle: u64, flags: u32, attributes: u64, mode: u8) -> Result<u32, KernelError> {
    critical(|| {
        if flags != 0 {
            return Ok(INVALID_PARAMETER);
        }
        if mode != 0 && attributes & 3 != 0 {
            return Ok(0x8000_0002);
        }
        if !message_buffer::accessible(attributes, 32, mode, mode != 0) {
            return Ok(ACCESS_VIOLATION);
        }
        let view_flags = guest::read32(attributes);
        let section_handle = guest::read64(attributes + 8);
        let initial_base = guest::read64(attributes + 16);
        let requested = guest::read64(attributes + 24);
        if view_flags != 0 || initial_base != 0 || requested == 0 {
            return Ok(INVALID_PARAMETER);
        }
        with_port(handle, mode, |port| {
            let record = match port_sections::reference(port, section_handle) {
                Ok(record) => record,
                Err(status) => return Ok(status),
            };
            let mut region: Option<Arc<Region>> = None;
            let mut mapped: Option<Arc<section_views::ViewBinding>> = None;
            let mut temporary: Option<Arc<section_views::ViewBinding>> = None;
            let mut delivered = false;
            let outcome = (|| -> Result<u32, KernelError> {
                if record.creator_process.is_some_and(|creator| creator != process::get_current_process()) {
                    return Ok(0xC000_0022);
                }
                region = match port_sections::allocate_region(&record, requested) {
                    Ok(allocated) => Some(allocated),
                    Err(status) => return Ok(status),
                };
                let system_space = port.with(|state| state.port_flags) & 0x10_0000 != 0;
                let request = MapRequest { offset: region.as_ref().map_or(0, |region| region.offset), size: region.as_ref().map_or(0, |region| region.view_size), protect: 4, system_space, supervisor: system_space, ..MapRequest::default() };
                let binding = match section_views::map(port, section_handle, MapOptions { request, owner_process: Some(port.process_pointer), region: region.clone() })? {
                    Ok(binding) => binding,
                    Err(status) => return Ok(status),
                };
                mapped = Some(binding.clone());
                region = None;
                match section_views::reference(port, binding.view.base) {
                    Ok(view) => temporary = Some(view),
                    Err(_) => return Err(KernelError::new("ALPC created view disappeared before delivery")),
                }
                if !message_buffer::writable(attributes + 16, 8, mode) {
                    return Ok(ACCESS_VIOLATION);
                }
                guest::write64(attributes + 16, binding.view.base);
                if !message_buffer::writable(attributes + 24, 8, mode) {
                    return Ok(ACCESS_VIOLATION);
                }
                guest::write64(attributes + 24, binding.view.size);
                delivered = true;
                Ok(0)
            })();
            if let Some(binding) = mapped.as_ref().filter(|binding| !delivered && !binding.state.lock().deleted) {
                let _ = section_views::unmap(binding);
            }
            if let Some(view) = &temporary {
                let _ = section_views::release(view);
            }
            if let Some(region) = &region {
                let _ = port_sections::release_region(&record, region);
            }
            let _ = port_sections::release(&record);
            outcome
        })
    })
}

pub fn delete_section_view(port_handle: u64, flags: u32, base: u64, mode: u8) -> Result<u32, KernelError> {
    critical(|| {
        if flags != 0 {
            return Ok(INVALID_PARAMETER);
        }
        with_port(port_handle, mode, |port| {
            let binding = match section_views::reference(port, base) {
                Ok(binding) => binding,
                Err(status) => return Ok(status),
            };
            let result = section_views::delete_referenced(&binding);
            section_views::release(&binding)?;
            result
        })
    })
}

pub fn disconnect_port(handle: u64, flags: u32, mode: u8) -> Result<u32, KernelError> {
    critical(|| {
        if flags & !1 != 0 {
            return Ok(INVALID_PARAMETER);
        }
        with_port(handle, mode, |port| Ok(port.disconnect(flags)))
    })
}

/// Só a associação de conclusão (classe 2) é aceita; as demais classes
/// conhecidas devolvem NOT_SUPPORTED.
pub fn set_information(handle: u64, class: u32, input: u64, length: u32, mode: u8) -> Result<u32, KernelError> {
    critical(|| {
        if handle == 0 || (input == 0 && class != 7 && class != 10) {
            return Ok(INVALID_PARAMETER);
        }
        let mut captured: Option<Vec<u8>> = None;
        if mode != 0 && length != 0 {
            if length > 72 {
                return Ok(0xC000_0004);
            }
            if !message_buffer::accessible(input, length as u64, mode, false) {
                return Ok(ACCESS_VIOLATION);
            }
            captured = Some((0..length as u64).map(|index| guest::read8(input + index)).collect());
        }
        with_port(handle, mode, |port| {
            port.run(|| {
                if class == 2 {
                    if length != 16 {
                        return Ok(0xC000_0004);
                    }
                    let (key, completion) = match &captured {
                        Some(bytes) => (u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8])), u64::from_le_bytes(bytes[8..16].try_into().unwrap_or([0; 8]))),
                        None => {
                            if !message_buffer::accessible(input, 16, mode, false) {
                                return Ok(ACCESS_VIOLATION);
                            }
                            (guest::read64(input), guest::read64(input + 8))
                        }
                    };
                    return completion_association::associate(port, completion, key, mode);
                }
                if [1, 5, 6, 7, 8, 9, 10].contains(&class) {
                    return Ok(0xC000_00BB);
                }
                Ok(INVALID_PARAMETER)
            })
        })
    })
}
