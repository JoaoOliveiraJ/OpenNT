//! Contextos de licenciamento do boot.
//!
//! A política capturada passa para uma SECTION real antes de o índice ser
//! publicado (`publish_boot`); a mesma rotina (`update`, o
//! SLUpdateLicenseDataInternal) atende o ExUpdateLicenseData em execução,
//! trocando a seção publicada e gravando o ProductPolicy. As operações de
//! seção (ZwCreateSection, referência do handle, MmMapViewInSystemSpace)
//! são os exports do próprio kernel; um teste pode trocá-las por
//! [`set_section_backend`].

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::ntos::ex::license::{index as license_index, special as license_special, state as license_state};
use crate::ntos::ex::{pool_allocation, push_lock};
use crate::hal::cpu;
use crate::ntos::ke::{critical_region, dispatcher};
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ps::previous_mode;
use super::layout::{self, capture_at, context_at, header_at, ExpLicenseState};
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{LargeInteger, ObjectAttributes};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

pub const CONTEXT_BYTES: u64 = ExpLicenseState::SIZE;
pub const POLICY_CAPACITY: u32 = layout::POLICY_CAPACITY;
const OWNER_TAG: u32 = 0x624C_7354;
const VALUE_TAG: u32 = 0x2053_4C53;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_DATA_ERROR: u32 = 0xC000_003E;
const STATUS_OBJECT_NAME_EXISTS: u32 = 0x4000_0000;
const STATUS_SOME_NOT_MAPPED: u32 = 0x0000_0107;
const REG_BINARY: u32 = 3;
/// Chave do valor ProductPolicy.
const PRODUCT_OPTIONS: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ProductOptions";

/// Operações de seção usadas pela publicação.
#[derive(Clone, Copy)]
pub struct SectionBackend {
    /// ZwCreateSection(&handle, acesso, OA, &tamanho, proteção, atributos, arquivo).
    pub create_section: fn(u64, u32, u64, u64, u32, u32, u64) -> u32,
    /// Referência do handle criado (`None` = handle sem dono).
    pub reference_handle: fn(u64, u64) -> Option<u32>,
    pub close_handle: fn(u64),
    /// MmMapViewInSystemSpace(seção, &base, &tamanho, ...).
    pub map_system_view: fn(u64, u64, u64, u64, u64) -> u32,
    pub unmap_system_view: fn(u64),
    pub reference_section: fn(u64),
    pub dereference_section: fn(u64),
}

/// As operações de seção do próprio kernel (os exports do Mm e do Ob), o
/// padrão; um teste pode trocá-las ou retirá-las.
static BACKEND: SpinLock<Option<SectionBackend>> = SpinLock::new(Some(KERNEL_BACKEND));

const KERNEL_BACKEND: SectionBackend = SectionBackend {
    create_section: kernel_create_section,
    reference_handle: kernel_reference_handle,
    close_handle: kernel_close_handle,
    map_system_view: kernel_map_system_view,
    unmap_system_view: kernel_unmap_system_view,
    reference_section: kernel_reference_section,
    dereference_section: kernel_dereference_section,
};

fn kernel_call(name: &str, arguments: &[u64]) -> u32 {
    crate::ntos::init::exports::invoke_handler(name, arguments).map_or(STATUS_NO_MEMORY, |status| status as u32)
}

fn kernel_create_section(handle: u64, access: u32, attributes: u64, size: u64, protect: u32, flags: u32, file: u64) -> u32 {
    kernel_call("ZwCreateSection", &[handle, access as u64, attributes, size, protect as u64, flags as u64, file])
}

/// ObReferenceObjectByHandle(Handle, 0, NULL, KernelMode, &Section, NULL).
fn kernel_reference_handle(handle: u64, object: u64) -> Option<u32> {
    Some(kernel_call("ObReferenceObjectByHandle", &[handle, 0, 0, 0, object, 0]))
}

fn kernel_close_handle(handle: u64) {
    kernel_call("ZwClose", &[handle]);
}

/// MmMapViewInSystemSpace(Section, &MappedBase, &ViewSize).
fn kernel_map_system_view(section: u64, base: u64, size: u64, _offset: u64, _unused: u64) -> u32 {
    kernel_call("MmMapViewInSystemSpace", &[section, base, size])
}

fn kernel_unmap_system_view(view: u64) {
    kernel_call("MmUnmapViewInSystemSpace", &[view]);
}

fn kernel_reference_section(section: u64) {
    kernel_call("ObfReferenceObject", &[section]);
}

fn kernel_dereference_section(section: u64) {
    kernel_call("ObfDereferenceObject", &[section]);
}

pub fn set_section_backend(backend: Option<SectionBackend>) {
    *BACKEND.lock() = backend;
}

/// Volta às operações de seção do kernel.
pub fn restore_kernel_section_backend() {
    *BACKEND.lock() = Some(KERNEL_BACKEND);
}

fn backend() -> Result<SectionBackend, KernelError> {
    (*BACKEND.lock()).ok_or_else(|| KernelError::new("license SECTION backend is not available yet"))
}

/// Provedores opcionais do dono do contexto.
#[derive(Clone, Copy, Default)]
pub struct BootProviders {
    pub notify_corruption: Option<fn(u64)>,
    /// Publicação alternativa: (contexto, tamanho, blob primário).
    pub publish_policy: Option<fn(u64, u32, u64) -> u32>,
    pub read_timestamp: Option<fn() -> u64>,
}

/// Resultados da inicialização.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Diagnostics {
    pub state_status: u32,
    pub header_status: Option<u32>,
    pub publication_status: Option<u32>,
}

static OWNERS: SpinLock<BTreeMap<u64, Diagnostics>> = SpinLock::new(BTreeMap::new());

/// Moldura de pool da publicação: atributos e tamanho da SECTION e as
/// saídas de ZwCreateSection, da referência, do mapeamento e do índice.
#[repr(C)]
struct SectionFrame {
    attributes: ObjectAttributes,
    maximum_size: LargeInteger,
    section_handle: Field<u64>,
    section: Field<u64>,
    view: Field<u64>,
    view_size: Field<u64>,
    view_offset: Field<u64>,
    descriptor_count: Field<u32>,
    _pad_64: Reserved<0xC>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for SectionFrame {}

const _: () = {
    assert!(core::mem::size_of::<SectionFrame>() == 112);
    assert!(core::mem::offset_of!(SectionFrame, section_handle) == 0x38);
    assert!(core::mem::offset_of!(SectionFrame, descriptor_count) == 0x60);
};

fn locked<T>(context: u64, exclusive: bool, operation: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
    critical_region::enter_critical()?;
    let lock = context_at(context).policy_lock.address();
    let acquired = if exclusive { push_lock::acquire_exclusive(lock, 0) } else { push_lock::acquire_shared(lock, 0) };
    let result = match acquired {
        Ok(()) => {
            let result = operation();
            let released = if exclusive { push_lock::release_exclusive(lock, 0) } else { push_lock::release_shared(lock, 0) };
            released.and(result)
        }
        Err(error) => Err(error),
    };
    let left = critical_region::leave_critical();
    let result = result?;
    left?;
    Ok(result)
}


/// Registro inicial: prazo de tolerância de 10800 s e flag 1.
fn initial_state() -> [u8; 48] {
    let mut bytes = [0u8; 48];
    bytes[32..40].copy_from_slice(&10800u64.to_le_bytes());
    bytes[40] = 1;
    bytes
}

fn notify_change(context: u64) {
    let event = context_at(context).change_event.get();
    if event != 0 {
        dispatcher::set_event(event);
    }
}

/// Validação inicial de 0x94E200; o rodapé é conferido depois da cópia.
pub fn validate_publication(blob: u64, size: u32) -> u32 {
    if blob == 0 || size < 25 || size > POLICY_CAPACITY || blob & 3 != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let header = header_at(blob);
    let total = header.total_size.get();
    let entries = header.values_size.get();
    let footer = header.end_marker_size.get();
    if total > POLICY_CAPACITY || entries > POLICY_CAPACITY || footer > POLICY_CAPACITY {
        return 0xC000_0040;
    }
    let header_size = layout::PolicyHeader::SIZE as u32;
    if (blob + header_size as u64 + entries as u64) & 3 != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if header_size + entries + footer != total || total != size || header.version.get() != 1 {
        return STATUS_INVALID_PARAMETER;
    }
    0
}

/// Publicação inicial com posse exclusiva do ciclo de vida: a política vai
/// para uma seção mapeada no espaço do sistema e o índice é publicado.
pub fn publish_boot(context: u64, blob: u64, size: u32) -> Result<u32, KernelError> {
    let state = context_at(context);
    if state.primary.get() != blob || state.view.get() != 0 || state.section.get() != 0 {
        return Err(KernelError::new("license boot publication requires a new context with its primary blob"));
    }
    update(context, blob, size)
}

/// A política em `blob` é a mesma já publicada: cabeçalho, valores e
/// rodapé iguais byte a byte.
fn same_policy(view: u64, blob: u64) -> bool {
    let (published, candidate) = (header_at(view), header_at(blob));
    let fields = |header: &layout::PolicyHeader| [header.total_size.get(), header.values_size.get(), header.end_marker_size.get(), header.flags.get(), header.version.get()];
    if fields(published) != fields(candidate) {
        return false;
    }
    let header_size = layout::PolicyHeader::SIZE;
    let values = candidate.values_size.get() as usize;
    let footer = candidate.end_marker_size.get() as usize;
    guest::read_bytes(view + header_size, values) == guest::read_bytes(blob + header_size, values) && guest::read_bytes(view + header_size + values as u64, footer) == guest::read_bytes(blob + header_size + values as u64, footer)
}

/// Algum valor marcado com o flag 2 entrou ou mudou de dados entre o índice
/// publicado e o novo (`descriptors`, ordenado); valores que saem não contam.
fn flagged_values_changed(state: &ExpLicenseState, descriptors: u64, count: u32) -> bool {
    const FLAGGED: u32 = 2;
    let (mut new, mut old) = (0u32, 0u32);
    let published = state.descriptor_count.get();
    while new < count {
        let candidate = descriptors + new as u64 * layout::Descriptor::SIZE;
        let candidate_entry = layout::descriptor_at(candidate).entry.get();
        let flagged = layout::entry_at(candidate_entry).flags.get() & FLAGGED != 0;
        if old >= published {
            if flagged {
                return true;
            }
            new += 1;
            continue;
        }
        let current = state.descriptor_array() + old as u64 * layout::Descriptor::SIZE;
        let order = license_index::compare(candidate, current);
        if order < 0 {
            if flagged {
                return true;
            }
            new += 1;
        } else if order > 0 {
            old += 1;
        } else {
            if flagged {
                let current_entry = layout::descriptor_at(current).entry.get();
                let (left, right) = (layout::entry_at(candidate_entry), layout::entry_at(current_entry));
                let data = |entry: u64, header: &layout::PolicyEntry| guest::read_bytes(entry + layout::PolicyEntry::SIZE + header.name_size.get() as u64, header.data_size.get() as usize);
                if left.data_size.get() != right.data_size.get() || data(candidate_entry, left) != data(current_entry, right) {
                    return true;
                }
            }
            new += 1;
            old += 1;
        }
    }
    false
}

/// ExpPutLicenseDataIntoRegistry (0x94DBFC): a política publicada volta ao
/// valor REG_BINARY ProductPolicy de Control\ProductOptions, sob o push lock
/// da política.
fn put_into_registry(context: u64) -> Result<u32, KernelError> {
    let state = context_at(context);
    locked(context, false, || {
        let view = state.view.get();
        if view == 0 {
            return Ok(0);
        }
        let handle = crate::ntos::cm::registry::open_or_create(PRODUCT_OPTIONS, None)?;
        let bytes = guest::read_bytes(view, header_at(view).total_size.get() as usize);
        crate::ntos::cm::registry::set_value(handle, "ProductPolicy", REG_BINARY, bytes);
        crate::ntos::cm::registry::close_handle(handle);
        Ok(0)
    })
}

/// SLUpdateLicenseDataInternal (0x94E200), a publicação de uma política no
/// contexto: a do boot (o buffer primário do contexto novo) e a atualização
/// em execução (ExUpdateLicenseData, contexto sem buffer primário). Depois da
/// validação, uma atualização com a mesma política publicada só renova o
/// registro de estado (STATUS_OBJECT_NAME_EXISTS); senão a política vai para
/// uma SECTION nova mapeada no espaço do sistema, o índice é refeito e
/// trocado sob o push lock, a seção e a visão antigas são soltas, e a
/// atualização em execução grava a política no Registry e avisa os
/// interessados. Um valor marcado (flag 2) que entra ou muda devolve
/// STATUS_SOME_NOT_MAPPED. Os erros de formato marcam um estado local zero
/// como violado (5). O modo de licença reduzida (modo seguro ou WinPE) não
/// existe no OpenNT.
pub fn update(context: u64, blob: u64, size: u32) -> Result<u32, KernelError> {
    let state = context_at(context);
    let mut status = validate_publication(blob, size);
    let mut frame = 0u64;
    let mut section = 0u64;
    let mut view = 0u64;
    let mut descriptors = 0u64;
    let mut published = false;
    let mut publication_reference = false;
    let mut sections: Option<SectionBackend> = None;
    // [rsp+0x44]: atualização sem buffer primário ou política com o flag 1.
    let mut reset_grace = false;
    let mut released: (u64, u64) = (0, 0);
    let result = (|| -> Result<u32, KernelError> {
        if status != 0 {
            return Ok(status);
        }
        state.subscription_cached.set(0);
        let mut primary = 0u64;
        let mut identical = false;
        locked(context, false, || {
            primary = state.primary.get();
            reset_grace = primary == 0;
            if primary == 0 && header_at(blob).flags.get() & 1 != 0 {
                status = STATUS_INVALID_PARAMETER;
            } else if primary == 0 && state.view.get() != 0 && state.corrupt.get() == 0 {
                identical = same_policy(state.view.get(), blob);
            }
            Ok(())
        })?;
        if status != 0 {
            return Ok(status);
        }
        if identical {
            let mut tampered = false;
            locked(context, true, || {
                tampered = license_special::read_local_state(context)? != 0;
                license_state::update_snapshot(context, &initial_state(), 7, 1)?;
                Ok(())
            })?;
            if tampered {
                notify_change(context);
            }
            status = STATUS_OBJECT_NAME_EXISTS;
            return Ok(status);
        }
        let backend = backend()?;
        sections = Some(backend);
        frame = kernel_pool::allocate(SectionFrame::SIZE, AllocateOptions { zero: true, paged: true, tag: OWNER_TAG, ..Default::default() }).unwrap_or(0);
        if frame == 0 {
            status = STATUS_NO_MEMORY;
            return Ok(status);
        }
        // SAFETY: alocação nova do tamanho da moldura.
        let section_frame = unsafe { SectionFrame::at(frame) };
        section_frame.attributes.length.set(ObjectAttributes::SIZE as u32);
        section_frame.attributes.attributes.set(0x220);
        section_frame.maximum_size.quad_part.set(size as i64);
        status = previous_mode::with_kernel(|| (backend.create_section)(section_frame.section_handle.address(), 0xF0007, section_frame.attributes.address(), section_frame.maximum_size.address(), 4, 0x800_0000, 0))?;
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        let handle = section_frame.section_handle.get();
        let referenced = (backend.reference_handle)(handle, section_frame.section.address());
        let _ = previous_mode::with_kernel(|| (backend.close_handle)(handle));
        status = referenced.ok_or_else(|| KernelError::new("created license SECTION handle lost its owner"))?;
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        section = section_frame.section.get();
        status = (backend.map_system_view)(section, section_frame.view.address(), section_frame.view_size.address(), section_frame.view_offset.address(), 0);
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        view = section_frame.view.get();
        let header_size = layout::PolicyHeader::SIZE;
        let source = header_at(blob);
        layout::move_bytes(view, blob, header_size as u32);
        layout::move_bytes(view + header_size, blob + header_size, source.values_size.get());
        let footer_offset = header_size + source.values_size.get() as u64;
        layout::move_bytes(view + footer_offset, blob + footer_offset, source.end_marker_size.get());
        let published_header = header_at(view);
        // O marcador final (um DWORD 0x45) segue a área de valores.
        // SAFETY: dentro da visão recém-copiada, validada por `validate_publication`.
        let end_marker = unsafe { Field::<u32>::at(view + header_size + published_header.values_size.get() as u64) }.get();
        if published_header.end_marker_size.get() != 4 || end_marker != 0x45 {
            status = 0xC000_003F;
            return Ok(status);
        }
        status = license_index::build(view, 1, 0, 0, section_frame.descriptor_count.address());
        if status == 0xC000_0023 {
            let count = section_frame.descriptor_count.get();
            status = locked(context, false, || Ok(if count > 0xB6D { STATUS_INVALID_PARAMETER } else { 0 }))?;
            if status != 0 {
                return Ok(status);
            }
            descriptors = pool_allocation::allocate_tagged(1, count as u64 * 16, VALUE_TAG).unwrap_or(0);
            if descriptors == 0 {
                status = STATUS_NO_MEMORY;
                return Ok(status);
            }
            status = license_index::build(view, 0, descriptors, count, 0);
            if status & 0x8000_0000 == 0 {
                license_index::sort(descriptors, count);
            }
        }
        if status & 0x8000_0000 != 0 {
            if status == STATUS_DATA_ERROR {
                status = STATUS_INVALID_PARAMETER;
            }
            return Ok(status);
        }
        let count = section_frame.descriptor_count.get();
        let mut flagged_changed = false;
        locked(context, false, || {
            if primary == 0 {
                flagged_changed = flagged_values_changed(state, descriptors, if descriptors != 0 { count } else { 0 });
            }
            Ok(())
        })?;
        (backend.reference_section)(section);
        publication_reference = true;
        let mut changed = false;
        locked(context, true, || {
            // Os bits 0..2 atualizam checksum, estado e timestamp.
            license_state::update_snapshot(context, &initial_state(), 7, 1)?;
            released = (state.section.get(), state.view.get());
            state.section.set(section);
            state.view.set(view);
            state.primary.set(0);
            state.corrupt.set(0);
            let old_count = state.descriptor_count.get();
            guest::write_bytes(state.descriptor_array(), &alloc::vec![0u8; old_count as usize * layout::Descriptor::SIZE as usize]);
            state.descriptor_count.set(0);
            if descriptors != 0 {
                layout::move_bytes(state.descriptor_array(), descriptors, count * layout::Descriptor::SIZE as u32);
                state.descriptor_count.set(count);
            }
            state.index_built.set(1);
            let previous_state = license_special::read_local_state(context)?;
            let new_state = (header_at(view).flags.get() & 1) * 2;
            reset_grace |= new_state != 0;
            license_state::set_context_state(context, new_state)?;
            let current_state = license_special::read_local_state(context)?;
            changed = previous_state != current_state && (previous_state == 0 || current_state == 0);
            published = true;
            Ok(())
        })?;
        if primary == 0 {
            status = put_into_registry(context)?;
            if status & 0x8000_0000 != 0 {
                return Ok(status);
            }
        }
        if changed || primary == 0 {
            notify_change(context);
        }
        status = if flagged_changed { STATUS_SOME_NOT_MAPPED } else { 0 };
        Ok(status)
    })();
    if reset_grace {
        locked(context, true, || license_state::update_snapshot(context, &[0u8; 48], 32, 0).map(|_| ()))?;
    }
    if let Some(backend) = sections {
        if section != 0 {
            (backend.dereference_section)(section);
        }
        if !published && publication_reference {
            (backend.dereference_section)(section);
        }
        if !published && view != 0 {
            (backend.unmap_system_view)(view);
        }
        let (old_section, old_view) = released;
        if old_section != 0 {
            (backend.dereference_section)(old_section);
        }
        if old_view != 0 {
            (backend.unmap_system_view)(old_view);
        }
    }
    if descriptors != 0 {
        let _ = kernel_pool::free(descriptors, None);
    }
    if frame != 0 {
        let _ = kernel_pool::free(frame, Some(OWNER_TAG));
    }
    // Só estes erros de formato invalidam um estado local zero; falta de
    // memória não vira licença inválida nem ativa.
    if [STATUS_INVALID_PARAMETER, 0xC000_003F, 0xC000_0040].contains(&status) {
        let mut changed = false;
        locked(context, true, || {
            if license_special::read_local_state(context)? == 0 {
                license_state::set_context_state(context, 5)?;
                changed = true;
            }
            Ok(())
        })?;
        if changed {
            notify_change(context);
        }
    }
    result
}

/// Campos e decisões de 0x7AB058; sem UUID, relógio ou licença fixos.
pub fn initialize(context: u64, providers: &BootProviders) -> Result<Diagnostics, KernelError> {
    let state = context_at(context);
    state.refresh_interval.set(0xFFFF_FFFF);
    state.context_value.set(0);
    state.local_state.set(0);
    let initial_corrupt = state.corrupt.get();
    let state_status = locked(context, true, || license_state::update_snapshot(context, &initial_state(), 0xFFFF_FFFF, 1))?;
    locked(context, true, || {
        state.context_value.set(0);
        Ok(())
    })?;
    let primary = state.primary.get();
    let mut diagnostics = Diagnostics { state_status, header_status: None, publication_status: None };
    if primary != 0 {
        let header = locked(context, true, || {
            let result = license_index::validate_header(context);
            if result == STATUS_DATA_ERROR {
                state.corrupt.set(1);
            }
            Ok(result)
        })?;
        diagnostics.header_status = Some(header);
        let corrupted = state.corrupt.get() != 0;
        if initial_corrupt == 0 && corrupted {
            if let Some(notify) = providers.notify_corruption {
                notify(context);
            }
        }
        if header & 0x8000_0000 == 0 && !corrupted {
            let size = capture_at(primary).captured_size.get();
            diagnostics.publication_status = Some(match providers.publish_policy {
                Some(publish) => publish(context, size, primary),
                None => publish_boot(context, primary, size)?,
            });
        }
        let identifier: Vec<u8> = (0..16).map(|_| providers.read_timestamp.map_or_else(cpu::rdtsc, |read| read()) as u8).collect();
        locked(context, true, || {
            guest::write_bytes(state.session_identifier.as_ptr() as u64, &identifier);
            Ok(())
        })?;
        locked(context, true, || {
            state.primary.set(0);
            if state.view.get() == 0 {
                let count = state.descriptor_count.get();
                guest::write_bytes(state.descriptor_array(), &alloc::vec![0u8; count as usize * layout::Descriptor::SIZE as usize]);
                state.descriptor_count.set(0);
            }
            Ok(())
        })?;
    }
    Ok(diagnostics)
}

/// Captura privada limitada pela capacidade do loader; o chamador recebe um
/// contexto criado, não uma afirmação de licenciamento.
pub fn create(captured: Option<(u32, &[u8])>, providers: &BootProviders) -> Result<Result<(u64, Diagnostics), u32>, KernelError> {
    let Ok(context) = kernel_pool::allocate(CONTEXT_BYTES, AllocateOptions { zero: true, paged: true, tag: OWNER_TAG, ..Default::default() }) else { return Ok(Err(STATUS_NO_MEMORY)) };
    let mut primary = 0u64;
    let result = (|| -> Result<Result<(u64, Diagnostics), u32>, KernelError> {
        primary = kernel_pool::allocate(POLICY_CAPACITY as u64 + layout::PolicyCapture::SIZE, AllocateOptions { zero: true, paged: true, tag: OWNER_TAG, ..Default::default() }).unwrap_or(0);
        if primary == 0 {
            return Ok(Err(STATUS_NO_MEMORY));
        }
        context_at(context).primary.set(primary);
        let capture = capture_at(primary);
        capture.captured_size.set(captured.map_or(POLICY_CAPACITY, |(_, data)| data.len() as u32));
        capture.value_type.set(captured.map_or(0, |(value_type, _)| value_type));
        if let Some((_, data)) = captured.filter(|(_, data)| data.len() as u32 <= POLICY_CAPACITY) {
            guest::write_bytes(primary, data);
        }
        let diagnostics = initialize(context, providers)?;
        OWNERS.lock().insert(context, diagnostics);
        Ok(Ok((context, diagnostics)))
    })();
    if primary != 0 {
        let _ = kernel_pool::free(primary, Some(OWNER_TAG));
    }
    if !matches!(result, Ok(Ok(_))) {
        release_resources(context)?;
        let _ = kernel_pool::free(context, Some(OWNER_TAG));
    }
    result
}

fn release_resources(context: u64) -> Result<(), KernelError> {
    let state = context_at(context);
    let section = state.section.get();
    let view = state.view.get();
    if section != 0 || view != 0 {
        let backend = backend()?;
        if section != 0 {
            (backend.dereference_section)(section);
        }
        if view != 0 {
            (backend.unmap_system_view)(view);
        }
    }
    critical_region::enter_critical()?;
    let released = license_state::release(context);
    critical_region::leave_critical()?;
    released
}

/// O dono retira todos os consumidores antes de destruir.
pub fn destroy(context: u64) -> Result<(), KernelError> {
    if OWNERS.lock().remove(&context).is_none() {
        return Err(KernelError::new("license context is not owned by this boot provider"));
    }
    release_resources(context)?;
    let _ = kernel_pool::free(context, Some(OWNER_TAG));
    Ok(())
}
