//! Vistas de seção ALPC.
//!
//! A vista conserva o SECTION e a porta que a publicou; o mapeamento e a
//! retirada de PTEs pertencem ao Mm. O callback Delete do original é vazio:
//! só a última referência executa o Destroy.

use alloc::sync::Arc;

use super::port_sections::{self, Region, SectionRecord};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::section::secured_views::{self, SecuredToken};
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::ob::objects::port::Port;
use crate::ntos::ps::process;
use crate::ntos::ps::user::sections::{self, MapRequest, View};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const INVALID_ADDRESS: u32 = 0xC000_0141;
const DELETE_PENDING: u32 = 0xC000_0056;

pub struct BindingState {
    pub references: u32,
    pub deleted: bool,
    pub released: bool,
    pub retiring: bool,
}

pub struct ViewBinding {
    pub port: Arc<Port>,
    pub view: Arc<View>,
    pub section: Arc<SectionRecord>,
    pub owner_process: u64,
    pub security: Option<Arc<SecuredToken>>,
    pub storage: u64,
    pub region: Option<Arc<Region>>,
    pub state: SpinLock<BindingState>,
}

pub struct MapOptions {
    pub request: MapRequest,
    pub owner_process: Option<u64>,
    pub region: Option<Arc<Region>>,
}

pub fn map(port: &Arc<Port>, handle: u64, options: MapOptions) -> Result<Result<Arc<ViewBinding>, u32>, KernelError> {
    let record = match port_sections::reference(port, handle) {
        Ok(record) => record,
        Err(status) => return Ok(Err(status)),
    };
    let owner_process = options.owner_process.unwrap_or_else(process::get_current_process);
    let mut storage = 0u64;
    let mut process_retained = false;
    let mut port_retained = false;
    let mut mapped: Option<Arc<View>> = None;
    let mut security: Option<Arc<SecuredToken>> = None;
    let outcome = (|| -> Result<Result<Arc<ViewBinding>, u32>, KernelError> {
        if record.creator_process.is_some_and(|creator| creator != process::get_current_process()) {
            return Ok(Err(0xC000_0022));
        }
        if port.closed() {
            return Ok(Err(0xC000_0037));
        }
        let maximum = port.with(|state| state.maximum_view_size);
        if maximum != 0 && options.request.size > maximum {
            return Ok(Err(0xC000_0044));
        }
        storage = guest::alloc_bytes(0x60);
        if storage == 0 {
            return Ok(Err(0xC000_009A));
        }
        let ending = process::with_record(owner_process, |record| record.exiting || record.terminated);
        if ending.is_none_or(|ending| ending) {
            return Ok(Err(0xC000_010A));
        }
        process::reference(owner_process);
        process_retained = true;
        let _ = dispatcher_objects::reference(port.pointer);
        port_retained = true;
        let mut request = options.request.clone();
        if !request.system_space {
            request.owner_process = Some(owner_process);
        }
        let view = match sections::map(&record.section, &request)? {
            Ok(view) => view,
            Err(status) => return Ok(Err(status)),
        };
        mapped = Some(view.clone());
        if record.secure && !request.system_space {
            match secured_views::acquire(&view) {
                Ok(token) => security = Some(token),
                Err(status) => return Ok(Err(status)),
            }
        }
        let binding = Arc::new(ViewBinding { port: port.clone(), view: view.clone(), section: record.clone(), owner_process, security: security.clone(), storage, region: options.region.clone(), state: SpinLock::new(BindingState { references: 1, deleted: false, released: false, retiring: false }) });
        port.with(|state| state.owned_section_views.push(binding.clone()));
        // A saída do processo respeita os consumidores antes de retirar as
        // PTEs: o Mm chama este dono em vez de destruir a vista por fora.
        let owner = binding.clone();
        view.state.lock().release_process_view = Some(Arc::new(move || {
            unmap(&owner)?;
            while !owner.state.lock().released {
                dispatcher::pump_kernel();
            }
            Ok(())
        }));
        Ok(Ok(binding))
    })();
    if !matches!(outcome, Ok(Ok(_))) {
        if let Some(view) = mapped {
            let _ = sections::unmap(&view, security.as_deref());
        }
        if let Some(token) = &security {
            let _ = secured_views::release(token);
        }
        if storage != 0 {
            guest::free_bytes(storage);
        }
        let _ = port_sections::release(&record);
        if port_retained {
            let _ = dispatcher_objects::dereference(port.pointer);
        }
        if process_retained {
            let _ = process::dereference(owner_process);
        }
    }
    outcome
}

/// A busca compara a base inteira na lista desta porta, sem arredondar nem
/// consultar a porta par.
pub fn reference(port: &Arc<Port>, address: u64) -> Result<Arc<ViewBinding>, u32> {
    let bindings = port.with(|state| state.owned_section_views.clone());
    for binding in bindings {
        let mut state = binding.state.lock();
        if binding.view.base == address && state.references > 0 {
            state.references += 1;
            drop(state);
            return Ok(binding);
        }
    }
    Err(INVALID_ADDRESS)
}

pub fn release(binding: &Arc<ViewBinding>) -> Result<(), KernelError> {
    let owned = binding.port.with(|state| state.owned_section_views.iter().any(|candidate| Arc::ptr_eq(candidate, binding)));
    {
        let mut state = binding.state.lock();
        if state.released || state.references < 1 || !owned {
            return Err(KernelError::new("invalid ALPC section view reference release"));
        }
        if state.references > 1 {
            state.references -= 1;
            return Ok(());
        }
        if !state.deleted {
            return Err(KernelError::new("live ALPC view lost its owning reference"));
        }
    }
    // Uma vista comum pode ter sido desmontada pelo usuário antes; as
    // seguras exigem a autorização privada do dono.
    if !binding.view.state.lock().unmapped {
        if let Err(error) = sections::unmap(&binding.view, binding.security.as_deref()) {
            // Conserva uma retenção de retirada até o Mm concluir o flush.
            binding.state.lock().retiring = true;
            return Err(error);
        }
    }
    binding.port.with(|state| state.owned_section_views.retain(|candidate| !Arc::ptr_eq(candidate, binding)));
    {
        let mut state = binding.state.lock();
        state.references = 0;
        state.released = true;
        state.retiring = false;
    }
    if let Some(token) = &binding.security {
        let _ = secured_views::release(token);
    }
    if let Some(region) = &binding.region {
        let _ = port_sections::release_region(&binding.section, region);
    }
    guest::free_bytes(binding.storage);
    let result = port_sections::release(&binding.section);
    let _ = dispatcher_objects::dereference(binding.port.pointer);
    let _ = process::dereference(binding.owner_process);
    result
}

/// A marca impede exclusões repetidas; a base continua localizável enquanto
/// houver referências emprestadas.
pub fn delete_referenced(binding: &Arc<ViewBinding>) -> Result<u32, KernelError> {
    {
        let mut state = binding.state.lock();
        if state.released {
            return Err(KernelError::new("ALPC section view already destroyed"));
        }
        if state.deleted {
            return Ok(DELETE_PENDING);
        }
        state.deleted = true;
    }
    release(binding).map(|_| 0)
}

/// Retirada usada pelo fechamento: consome só a retenção deixada por uma
/// falha anterior.
pub fn unmap(binding: &Arc<ViewBinding>) -> Result<u32, KernelError> {
    let retiring = {
        let mut state = binding.state.lock();
        core::mem::replace(&mut state.retiring, false)
    };
    if retiring {
        return release(binding).map(|_| 0);
    }
    delete_referenced(binding)
}

pub fn close_owner(port: &Arc<Port>) -> Result<(), KernelError> {
    let bindings = port.with(|state| state.owned_section_views.clone());
    for binding in bindings {
        unmap(&binding)?;
    }
    Ok(())
}
