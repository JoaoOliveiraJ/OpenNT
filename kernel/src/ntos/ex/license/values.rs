//! Seleção do contexto de licenciamento.
//!
//! A hive é capturada na fase 0; o dono nativo só é criado depois de pool,
//! threads e objetos (e das seções que recebem a política).

use alloc::vec::Vec;

use crate::ntos::ex::license::boot::{self as license_boot, BootProviders};
use crate::ntos::ex::license::service as license_service;
use crate::ntos::ex::license::special::Providers;
use crate::ntos::cm::registry;
use crate::ntos::ps::silo::query as silo_query;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Ejob, EserversiloGlobals};

pub const PRODUCT_OPTIONS: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ProductOptions";

struct Values {
    captured: bool,
    policy: Option<(u32, Vec<u8>)>,
    host_context: u64,
}

static VALUES: SpinLock<Values> = SpinLock::new(Values { captured: false, policy: None, host_context: 0 });

/// Cópia própria deste boot: mudanças posteriores da hive não trocam o que
/// foi entregue ao contexto nativo.
pub fn init() {
    let mut values = VALUES.lock();
    if values.captured {
        return;
    }
    values.policy = registry::read_value_by_path(PRODUCT_OPTIONS, "ProductPolicy").map(|value| (value.value_type, value.data));
    values.captured = true;
}

pub fn init_runtime(providers: &BootProviders) -> Result<(), KernelError> {
    let policy = {
        let values = VALUES.lock();
        if values.host_context != 0 {
            return Ok(());
        }
        if !values.captured {
            return Err(KernelError::new("ProductPolicy: boot capture not initialized"));
        }
        values.policy.clone()
    };
    let created = license_boot::create(policy.as_ref().map(|(value_type, data)| (*value_type, data.as_slice())), providers)?;
    let (context, _) = created.map_err(|status| KernelError::with_status("ProductPolicy: could not allocate boot context", status))?;
    let mut values = VALUES.lock();
    values.host_context = context;
    values.policy = None;
    Ok(())
}

/// Um server silo empresta o contexto de SILO_GLOBALS; ausência ou
/// corrupção nunca autoriza consultar a política do hospedeiro.
pub fn current_context() -> Result<u64, KernelError> {
    let host = VALUES.lock().host_context;
    if host == 0 {
        return Err(KernelError::new("ProductPolicy: native boot context not initialized"));
    }
    let silo = silo_query::current_server_silo();
    if silo == 0 {
        return Ok(host);
    }
    // SAFETY: o silo de servidor corrente e seus globais vivos.
    let globals = unsafe { Ejob::at(silo) }.server_silo_globals.get();
    Ok(unsafe { EserversiloGlobals::at(globals) }.exp_license_state.get())
}

/// ZwQueryLicenseValue pelo contexto do silo corrente.
pub fn query(name: u64, type_pointer: u64, buffer: u64, capacity: u32, length: u64) -> Result<u32, KernelError> {
    let mut selected: Result<u64, KernelError> = Ok(0);
    let status = license_service::query_kernel(|| {
        selected = current_context();
        *selected.as_ref().unwrap_or(&0)
    }, name, type_pointer, buffer, capacity, length, &Providers::default())?;
    selected?;
    Ok(status)
}

pub fn host_context() -> u64 {
    VALUES.lock().host_context
}
