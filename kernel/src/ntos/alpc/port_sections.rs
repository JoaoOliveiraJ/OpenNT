//! Seções de porta ALPC.
//!
//! Uma tabela por comunicação, distinta da tabela de HANDLEs NT; a
//! publicação retém a porta dona e um SECTION real do Mm. Cada vista
//! pública usa uma região distinta da seção (reserva em 64 KiB, extensão
//! mapeada em páginas de 4 KiB).

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::alpc::resource::handles::{self as resource_handles, Resource, ResourceTable};
use crate::ntos::ob::objects::port::Port;
use crate::ntos::ob::objects::{dispatcher as dispatcher_objects, section as section_objects};
use crate::ntos::ps::user::sections::Section;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const INVALID_HANDLE: u32 = 0xC000_0008;

/// Região de uma vista dentro da seção da porta.
pub struct Region {
    pub offset: u64,
    pub reserved_size: u64,
    pub view_size: u64,
    pub storage: u64,
    released: SpinLock<bool>,
}

#[derive(Default)]
pub struct Creation {
    pub actual_size: Option<u64>,
    pub secure: bool,
    pub created_backing: bool,
    pub creator_process: Option<u64>,
    pub release_metadata: Option<Box<dyn FnOnce() + Send>>,
}

pub struct SectionState {
    pub owner: Option<Arc<Port>>,
    pub references: u32,
    pub deleted: bool,
    pub regions: Vec<Arc<Region>>,
    release_metadata: Option<Box<dyn FnOnce() + Send>>,
}

pub struct SectionRecord {
    pub handle: u32,
    pub table: ResourceTable,
    pub section: Arc<Section>,
    pub actual_size: u64,
    pub secure: bool,
    pub created_backing: bool,
    pub creator_process: Option<u64>,
    pub state: SpinLock<SectionState>,
}

static LIVE: SpinLock<Vec<usize>> = SpinLock::new(Vec::new());

fn identity(record: &Arc<SectionRecord>) -> usize {
    Arc::as_ptr(record) as usize
}

fn live(record: &Arc<SectionRecord>) -> bool {
    LIVE.lock().contains(&identity(record))
}

/// O criador interno já validou e alocou o backing.
pub fn attach(port: &Arc<Port>, section: &Arc<Section>, creation: Creation) -> Result<Result<(u32, Arc<SectionRecord>), u32>, KernelError> {
    if port.closed() {
        return Ok(Err(0xC000_0037));
    }
    if section_objects::state(section.pointer()).is_none() {
        return Ok(Err(INVALID_HANDLE));
    }
    let table = resource_handles::table_for(port);
    let Some(handle) = resource_handles::available(&table) else { return Ok(Err(0xC000_009A)) };
    section_objects::reference(section.pointer());
    let _ = dispatcher_objects::reference(port.pointer);
    let record = Arc::new(SectionRecord {
        handle,
        table: table.clone(),
        section: section.clone(),
        actual_size: creation.actual_size.unwrap_or(section.size),
        secure: creation.secure,
        created_backing: creation.created_backing,
        creator_process: creation.creator_process,
        state: SpinLock::new(SectionState { owner: Some(port.clone()), references: 1, deleted: false, regions: Vec::new(), release_metadata: creation.release_metadata }),
    });
    port.with(|state| state.owned_sections.push(record.clone()));
    table.lock().insert(handle, Resource::Section(record.clone()));
    LIVE.lock().push(identity(&record));
    Ok(Ok((handle, record)))
}

/// O índice usa EAX: ignora os 32 bits altos, sem mascarar tags.
pub fn reference(port: &Arc<Port>, handle: u64) -> Result<Arc<SectionRecord>, u32> {
    let Some(Resource::Section(record)) = resource_handles::find(port, handle) else { return Err(INVALID_HANDLE) };
    if !live(&record) {
        return Err(INVALID_HANDLE);
    }
    record.state.lock().references += 1;
    Ok(record)
}

/// Vistas e operações podem reter o registro depois da retirada do nome.
pub fn release(record: &Arc<SectionRecord>) -> Result<(), KernelError> {
    if !live(record) {
        return Err(KernelError::new("invalid ALPC section reference release"));
    }
    let (remaining, deleted, metadata) = {
        let mut state = record.state.lock();
        if state.references < 1 {
            return Err(KernelError::new("invalid ALPC section reference release"));
        }
        state.references -= 1;
        let metadata = if state.references == 0 { state.release_metadata.take() } else { None };
        (state.references, state.deleted, metadata)
    };
    if remaining != 0 {
        return Ok(());
    }
    if !deleted {
        return Err(KernelError::new("live ALPC section lost its owning reference"));
    }
    section_objects::dereference(record.section.pointer())?;
    if let Some(metadata) = metadata {
        metadata();
    }
    LIVE.lock().retain(|&candidate| candidate != identity(record));
    Ok(())
}

/// Retira o nome já; o backing só sai na última referência. Um segundo
/// excluidor que já retinha o registro recebe DELETE_PENDING.
pub fn delete_referenced(record: &Arc<SectionRecord>) -> Result<u32, KernelError> {
    if !live(record) {
        return Err(KernelError::new("ALPC section already destroyed"));
    }
    let owner = {
        let mut state = record.state.lock();
        if state.deleted {
            return Ok(0xC000_0056);
        }
        state.deleted = true;
        state.owner.take()
    };
    let Some(owner) = owner else { return Err(KernelError::new("ALPC section ownership mismatch")) };
    record.table.lock().remove(&record.handle);
    owner.with(|state| state.owned_sections.retain(|candidate| !Arc::ptr_eq(candidate, record)));
    let result = release(record);
    let _ = dispatcher_objects::dereference(owner.pointer);
    result.map(|_| 0)
}

/// O último handle inicia o rundown do dono.
pub fn close_owner(port: &Arc<Port>) -> Result<(), KernelError> {
    let records = port.with(|state| state.owned_sections.clone());
    for record in records {
        delete_referenced(&record)?;
    }
    Ok(())
}

/// O menor buraco interno suficiente; o final só quando nenhum serve. Uma
/// região ainda retida ocupa seu intervalo.
pub fn allocate_region(record: &Arc<SectionRecord>, requested: u64) -> Result<Arc<Region>, u32> {
    let view_size = requested.wrapping_add(0xFFF) & !0xFFF;
    let reserved_size = requested.wrapping_add(0xFFFF) & !0xFFFF;
    if requested == 0 || view_size < requested || reserved_size < requested {
        return Err(0xC000_000D);
    }
    let mut state = record.state.lock();
    let mut offset = 0u64;
    let mut best: Option<(u64, u64)> = None;
    for region in &state.regions {
        let gap = region.offset - offset;
        if gap >= reserved_size && best.is_none_or(|(_, length)| gap < length) {
            best = Some((offset, gap));
            if gap == reserved_size {
                break;
            }
        }
        offset = region.offset + region.reserved_size;
    }
    if let Some((best_offset, _)) = best {
        offset = best_offset;
    } else if offset + reserved_size > record.actual_size {
        return Err(0xC000_009A);
    }
    let storage = guest::alloc_bytes(0x58);
    if storage == 0 {
        return Err(0xC000_009A);
    }
    let region = Arc::new(Region { offset, reserved_size, view_size, storage, released: SpinLock::new(false) });
    state.regions.push(region.clone());
    state.regions.sort_by_key(|region| region.offset);
    Ok(region)
}

pub fn release_region(record: &Arc<SectionRecord>, region: &Arc<Region>) -> Result<(), KernelError> {
    let mut state = record.state.lock();
    let Some(index) = state.regions.iter().position(|candidate| Arc::ptr_eq(candidate, region)).filter(|_| !*region.released.lock()) else { return Err(KernelError::new("invalid ALPC region release")) };
    state.regions.remove(index);
    *region.released.lock() = true;
    guest::free_bytes(region.storage);
    Ok(())
}
