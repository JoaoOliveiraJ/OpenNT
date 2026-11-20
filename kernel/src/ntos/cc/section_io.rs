//! Paginação das vistas do cache — o papel que a seção de dados do Mm faz
//! debaixo do Cc no NT (falta de página resolvida por IoPageRead, escrita por
//! IoSynchronousPageWrite).
//!
//! Num mapa com seção do cache (`cache_section`), as páginas ausentes de uma
//! vista são confirmadas na control area do stream: lidas pela E/S de
//! paginação do Mm (`mm/section/fsd_file`) ou zeradas, e publicadas em todas
//! as vistas, inclusive as de usuário; uma página que outra seção já trouxe
//! só é publicada na vista do Cc, sem E/S. Num mapa sem seção (um arquivo
//! que não é servido pela pilha de um file system), o próprio Cc traz as
//! páginas que vai entregar: antes de copiar, mapear ou fixar, as páginas
//! ausentes são lidas por um IRP de paginação enviado à pilha do próprio
//! arquivo (IoGetRelatedDeviceObject), com
//! IRP_MJ_READ/WRITE, Flags 0x43 (IRP_PAGING_IO | IRP_NOCACHE |
//! IRP_SYNCHRONOUS_PAGING_IO, como IoPageReadEx/IoSynchronousPageWriteEx),
//! MdlAddress descrevendo as páginas da vista e o FILE_OBJECT do cache map no
//! stack location. IRPs pendentes são esperados num KEVENT.
//!
//! Páginas além de FileSize são zeradas sem I/O; numa escrita, páginas
//! inteiramente sobrescritas e páginas a partir de ValidDataGoal também (os
//! ZeroFlags do CcCopyWrite).

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::cache_map::{self, CACHE};
use super::layout::{self, status, PAGE_SIZE};
use super::status::{CcResult, Failure};
use super::vacb;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{DeviceObject, IoStackLocation, Irp, Kevent, Mdl};
use crate::ntos::io::file::information;
use crate::ntos::io::io_manager::{self, irp_mj};
use crate::ntos::io::irp_builder::{self, BuildOptions};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::mdl as mm_mdl;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};

/// Como cada página de um intervalo é preparada.
#[derive(Clone, Copy)]
pub enum Fill {
    /// A página precisa dos dados do arquivo.
    Read,
    /// Os bytes [start, end) serão sobrescritos pelo chamador.
    Overwrite { start: u64, end: u64 },
}

/// MDL das páginas de sistema [buffer, buffer+length): MmCreateMdl +
/// MmBuildMdlForNonPagedPool (SOURCE_IS_NONPAGED_POOL e os PFNs reais) com
/// MappedSystemVa, para o MmGetSystemAddressForMdlSafe do driver devolver o
/// próprio VA, e MDL_PAGES_LOCKED, como num MDL de paginação; leituras levam
/// MDL_IO_PAGE_READ.
pub fn build_mdl(buffer: u64, length: u64, read: bool) -> u64 {
    let descriptor = mm_mdl::create(0, buffer, length);
    if descriptor == 0 {
        return 0;
    }
    mm_mdl::build_for_non_paged_pool(descriptor);
    // SAFETY: MDL recém-criado por MmCreateMdl.
    let mdl = unsafe { Mdl::at(descriptor) };
    mdl.process.set(0);
    mdl.mapped_system_va.set(buffer);
    mdl.mdl_flags.set(mdl.mdl_flags.get() | layout::MDL_PAGES_LOCKED);
    if read {
        mdl.mdl_flags.set(mdl.mdl_flags.get() | layout::MDL_IO_PAGE_READ);
    }
    descriptor
}

/// Um IRP de paginação síncrono ao arquivo: (NTSTATUS, Information).
pub fn page_io(file: u64, write: bool, offset: u64, buffer: u64, length: u64) -> Result<(u32, u64), KernelError> {
    let device = information::related_device(file)?;
    if device == 0 {
        return Ok((status::INVALID_DEVICE_REQUEST, 0));
    }
    // SAFETY: o dispositivo do topo da pilha do arquivo (IoGetRelatedDeviceObject).
    let stack_count = (unsafe { DeviceObject::at(device) }.stack_size.get() as u8 as u32).max(1);
    let packet = guest::alloc_bytes(irp_builder::size_for(stack_count));
    let descriptor = build_mdl(buffer, length, !write);
    let event = guest::alloc_bytes(Kevent::SIZE);
    let release = |packet: u64, descriptor: u64, event: u64| {
        for block in [packet, descriptor, event] {
            if block != 0 {
                guest::free_bytes(block);
            }
        }
    };
    if packet == 0 || descriptor == 0 || event == 0 {
        release(packet, descriptor, event);
        return Ok((status::INSUFFICIENT_RESOURCES, 0));
    }
    dispatcher::initialize_event(event, 0, false);
    irp_builder::build(packet, &BuildOptions {
        major: if write { irp_mj::WRITE } else { irp_mj::READ },
        buffer_length: length as u32,
        device_object: device,
        stack_count,
        file_object: file,
        byte_offset: offset,
        user_buffer: buffer,
        thread: process::get_current_thread(),
        requestor_mode: 0,
        ..Default::default()
    });
    // SAFETY: IRP recém-montado por `irp_builder::build`.
    let irp = unsafe { Irp::at(packet) };
    irp.flags.set(layout::PAGING_IRP_FLAGS);
    irp.mdl_address.set(descriptor);
    // SAFETY: o slot do topo do mesmo IRP.
    unsafe { IoStackLocation::at(irp_builder::first_stack_location(packet, stack_count)) }.parameters.read.key.set(0);
    let completion: Arc<SpinLock<Option<(i32, u64)>>> = Arc::new(SpinLock::new(None));
    let sink = completion.clone();
    io_manager::manage_completion(packet, Box::new(move |result, information| {
        // O evento antes do resultado: depois de publicar, o IRP e o evento
        // podem ser liberados pela thread que espera.
        dispatcher::set_event(event);
        *sink.lock() = Some((result, information));
    }));
    let returned = io_manager::iof_call_driver(device, packet);
    let outcome = loop {
        if let Some((result, information)) = *completion.lock() {
            break Ok((result as u32, information));
        }
        if returned as u32 != status::PENDING {
            io_manager::forget_managed_completion(packet);
            break match returned {
                io_manager::status::NOT_SUPPORTED | io_manager::status::NOT_FOUND => Ok((status::INVALID_DEVICE_REQUEST, 0)),
                failure if failure < 0 => Ok((failure as u32, 0)),
                _ => Err(KernelError::new("file system returned from a paging IRP without completing it")),
            };
        }
        dispatcher::wait_for_single_object(event, 0, 0, false);
    };
    release(packet, descriptor, event);
    outcome
}

/// Prepara as páginas `mask` da vista `index` e devolve a base da vista com
/// uma referência (liberar com `cache_map::release_view`). `Ok(None)`: sem
/// espera e seria preciso I/O. `Raise(status)` traz o status cru da leitura.
pub fn prepare_view(base: u64, index: u64, mask: u64, fill: Fill, wait: bool) -> CcResult<Option<u64>> {
    loop {
        vacb::ensure_view(base, index)?;
        let plan = {
            let mut cache = CACHE.lock();
            vacb::touch(&mut cache, base, index);
            let Some(map) = cache.maps.get_mut(&base) else { return Err(Failure::Kernel(KernelError::new("cache map vanished"))) };
            let (file_size, goal, file) = (map.file_size, map.valid_data_goal, map.file_object);
            let section = map.section.clone();
            let Some(view) = map.views.get_mut(&index) else { continue };
            // Páginas sendo lidas por outra thread: esperar.
            if view.reading & mask != 0 {
                if !wait {
                    return Ok(None);
                }
                None
            } else {
                let mut zero = 0u64;
                let mut read = 0u64;
                for page in 0..layout::PAGES_PER_VIEW {
                    let bit = 1u64 << page;
                    if mask & bit == 0 || view.valid & bit != 0 {
                        continue;
                    }
                    let start = vacb::view_offset(index) + page * PAGE_SIZE;
                    let overwritten = match fill {
                        Fill::Read => false,
                        Fill::Overwrite { start: first, end } => (first <= start && start + PAGE_SIZE <= end) || start >= goal,
                    };
                    if start >= file_size || overwritten {
                        zero |= bit;
                    } else {
                        read |= bit;
                    }
                }
                match &section {
                    Some(section) => {
                        // A control area já tem as páginas que outra seção
                        // trouxe: só falta publicá-las na vista, sem E/S.
                        let present = super::cache_section::present(section, vacb::view_offset(index) / PAGE_SIZE, layout::PAGES_PER_VIEW) & (zero | read);
                        let read = read & !present;
                        if read != 0 && !wait {
                            return Ok(None);
                        }
                        view.refs += 1;
                        view.reading |= zero | read | present;
                        Some((view.base, zero | read | present, file, Some((section.clone(), zero & !present, read, file_size))))
                    }
                    None => {
                        if read != 0 && !wait {
                            return Ok(None);
                        }
                        vacb::zero_pages(view.base, zero);
                        view.valid |= zero;
                        view.refs += 1;
                        view.reading |= read;
                        Some((view.base, read, file, None))
                    }
                }
            }
        };
        let Some((view_base, read, file, section_fill)) = plan else {
            dispatcher::pump_kernel();
            continue;
        };
        if let Some((section, zero, from_file, file_size)) = section_fill {
            return fill_from_section(base, index, view_base, &section, read, zero, from_file, file_size);
        }
        if read == 0 {
            return Ok(Some(view_base));
        }
        let mut failure = None;
        let mut loaded = 0u64;
        for (first, count) in vacb::runs(read) {
            let offset = vacb::view_offset(index) + first * PAGE_SIZE;
            let address = view_base + first * PAGE_SIZE;
            let length = count * PAGE_SIZE;
            match page_io(file, false, offset, address, length) {
                Ok((result, transferred)) if result >> 30 != 3 || result == status::END_OF_FILE => {
                    let transferred = if result == status::END_OF_FILE { 0 } else { transferred.min(length) };
                    vacb::zero_bytes(address + transferred, length - transferred);
                    loaded |= vacb::page_mask(first, first + count - 1);
                }
                Ok((result, _)) => {
                    failure = Some(Failure::Raise(result));
                    break;
                }
                Err(error) => {
                    failure = Some(Failure::Kernel(error));
                    break;
                }
            }
        }
        {
            let mut cache = CACHE.lock();
            if let Some(view) = cache.maps.get_mut(&base).and_then(|map| map.views.get_mut(&index)) {
                view.valid |= loaded;
                view.reading &= !read;
            }
        }
        if let Some(failure) = failure {
            cache_map::release_view(base, index);
            return Err(failure);
        }
        return Ok(Some(view_base));
    }
}

/// As páginas `pages` da vista `index` pela seção do cache: as de `zero`
/// confirmadas zeradas, as de `from_file` lidas do arquivo, e todas
/// publicadas na vista de sistema do Cc antes de ficarem válidas.
#[allow(clippy::too_many_arguments)]
fn fill_from_section(base: u64, index: u64, view_base: u64, section: &super::cache_section::CacheSection, pages: u64, zero: u64, from_file: u64, file_size: u64) -> CcResult<Option<u64>> {
    let first_page = vacb::view_offset(index) / PAGE_SIZE;
    let mut failure = None;
    match vacb::section_view(view_base) {
        None => failure = Some(Failure::Kernel(KernelError::new("cache view without section view"))),
        Some(view) => {
            // Some(ler do arquivo) confirma; None só publica o que a control area tem.
            for (mask, read) in [(zero, Some(false)), (from_file, Some(true)), (pages & !(zero | from_file), None)] {
                for (first, count) in vacb::runs(mask) {
                    let result = match read {
                        Some(read) => super::cache_section::fill(section, &view, first_page + first, count, read, file_size),
                        None => Ok(if super::cache_section::attach(&view, first_page + first, count) { 0 } else { status::INSUFFICIENT_RESOURCES }),
                    };
                    match result {
                        Ok(0) => {}
                        Ok(code) => {
                            failure = Some(Failure::Raise(code));
                            break;
                        }
                        Err(error) => {
                            failure = Some(Failure::Kernel(error));
                            break;
                        }
                    }
                }
                if failure.is_some() {
                    break;
                }
            }
        }
    }
    {
        let mut cache = CACHE.lock();
        if let Some(view) = cache.maps.get_mut(&base).and_then(|map| map.views.get_mut(&index)) {
            if failure.is_none() {
                view.valid |= pages;
            }
            view.reading &= !pages;
        }
    }
    if let Some(failure) = failure {
        cache_map::release_view(base, index);
        return Err(failure);
    }
    Ok(Some(view_base))
}

/// As vistas de [start, end) preparadas, cada uma com uma referência. Sem
/// espera e com I/O necessário, solta o que pegou e devolve `None`.
pub fn prepare_range(base: u64, start: u64, end: u64, fill: Fill, wait: bool) -> CcResult<Option<Vec<(u64, u64)>>> {
    let mut held = Vec::new();
    for index in vacb::views_in(start, end) {
        match prepare_view(base, index, vacb::range_mask(index, start, end), fill, wait) {
            Ok(Some(view_base)) => held.push((index, view_base)),
            other => {
                for &(index, _) in &held {
                    cache_map::release_view(base, index);
                }
                return other.map(|_| None);
            }
        }
    }
    Ok(Some(held))
}

/// Solta as referências de `prepare_range`.
pub fn release_range(base: u64, held: &[(u64, u64)]) {
    for &(index, _) in held {
        cache_map::release_view(base, index);
    }
}
