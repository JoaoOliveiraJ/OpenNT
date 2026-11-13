//! Vistas de seção no espaço de sessão (MiMapViewInSystemSpace sobre o
//! MMSESSION da sessão do processo, e MmCommitSessionMappedView).
//!
//! Contrato do ntoskrnl 19041:
//! - MmMapViewInSessionSpace(Section, *MappedBase, *ViewSize) = Ex com um
//!   SectionOffset local zero e Flags 0.
//! - MmMapViewInSessionSpaceEx: `ApcState.Process->Flags.ProcessInSession`
//!   (+0x464 bit 16) limpo -> STATUS_NOT_MAPPED_VIEW; senão a mesma validação
//!   e mapeamento do MmMapViewInSystemSpaceEx.
//! - MmUnmapViewInSessionSpace = MmUnmapViewInSystemSpace (0xD7 sem vista).
//! - MmCommitSessionMappedView(MappedAddress, ViewSize): endereço fora da
//!   região de sessão -> INVALID_PARAMETER_1; fim com overflow ou fora ->
//!   INVALID_PARAMETER_2; processo fora de sessão -> NOT_MAPPED_VIEW; sem
//!   vista -> bugcheck 0xD7(addr, 2); control area com FilePointer ->
//!   STATUS_ALREADY_COMMITTED; faixa além da subseção do pagefile ->
//!   INVALID_PARAMETER_2; falha da cobrança de commit -> COMMITMENT_LIMIT.
//!
//! O OpenNT tem uma só sessão e nenhuma janela de VA de sessão separada: a
//! "região de sessão" é o conjunto das vistas globais mapeadas por estas
//! entradas, conferido contra o registro vivo de vistas de sistema (uma vista
//! removida por outro caminho deixa de contar). Por isso o ramo 0xD7 do
//! commit é inalcançável aqui. A exigência de ProcessInSession é a real; o ps
//! do OpenNT ainda não liga esse bit nos processos de sessão.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use super::{map_system_view, unmap_system_view};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::Eprocess;
use crate::ntos::ps::process;
use crate::ntos::ps::user::sections::{self, View};
use crate::rtl::{KernelError, SpinLock};

const PAGE: u64 = 0x1000;
const STATUS_NOT_MAPPED_VIEW: u32 = 0xC000_0019;
const STATUS_ALREADY_COMMITTED: u32 = 0xC000_0021;
const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const STATUS_COMMITMENT_LIMIT: u32 = 0xC000_012D;

/// Vistas globais mapeadas pelas entradas de sessão: base -> tamanho.
static SESSION_VIEWS: SpinLock<BTreeMap<u64, u64>> = SpinLock::new(BTreeMap::new());

/// O processo anexado (ApcState.Process) está numa sessão.
fn in_session() -> bool {
    // SAFETY: o processo corrente (o anexado).
    unsafe { Eprocess::at(process::get_current_process()) }.process_in_session() != 0
}

/// A vista de sessão viva que contém o endereço.
fn session_view(address: u64) -> Option<Arc<View>> {
    let view = sections::find_system_view(address)?;
    let recorded = SESSION_VIEWS.lock().get(&view.base).copied();
    (recorded == Some(view.size)).then_some(view)
}

fn record(base_pointer: u64, status: u32) -> u32 {
    if status == 0 {
        // SAFETY: PVOID* MappedBase do chamador de kernel, gravado pelo mapeamento.
        if let Some(view) = sections::find_system_view(unsafe { Field::<u64>::at(base_pointer) }.get()) {
            SESSION_VIEWS.lock().insert(view.base, view.size);
        }
    }
    status
}

/// MmMapViewInSessionSpace: o offset local zero do original equivale ao
/// caminho sem offset do MmMapViewInSystemSpace.
pub fn map(section: u64, base_pointer: u64, size_pointer: u64) -> Result<u32, KernelError> {
    if !in_session() {
        return Ok(STATUS_NOT_MAPPED_VIEW);
    }
    Ok(record(base_pointer, map_system_view::map_from_start(section, base_pointer, size_pointer)?))
}

/// MmMapViewInSessionSpaceEx.
pub fn map_ex(section: u64, base_pointer: u64, size_pointer: u64, offset_pointer: u64, flags: u64) -> Result<u32, KernelError> {
    if !in_session() {
        return Ok(STATUS_NOT_MAPPED_VIEW);
    }
    Ok(record(base_pointer, map_system_view::map(section, base_pointer, size_pointer, offset_pointer, flags)?))
}

/// MmUnmapViewInSessionSpace.
pub fn unmap(address: u64) -> Result<u32, KernelError> {
    let status = unmap_system_view::unmap(address)?;
    if status == 0 {
        SESSION_VIEWS.lock().retain(|&base, &mut size| !(address >= base && address < base + size));
    }
    Ok(status)
}

/// MmCommitSessionMappedView.
pub fn commit(address: u64, size: u64) -> Result<u32, KernelError> {
    let Some(view) = session_view(address) else { return Ok(STATUS_INVALID_PARAMETER_1) };
    let end = address.wrapping_add(size);
    if end <= address || session_view(end - 1).is_none() {
        return Ok(STATUS_INVALID_PARAMETER_2);
    }
    if !in_session() {
        return Ok(STATUS_NOT_MAPPED_VIEW);
    }
    if view.section.file.is_some() {
        return Ok(STATUS_ALREADY_COMMITTED);
    }
    // A faixa precisa caber na parte da seção que a vista descreve.
    let last = end - 1;
    if last >= view.base + view.size {
        return Ok(STATUS_INVALID_PARAMETER_2);
    }
    let first = address & !(PAGE - 1);
    let limit = (last | (PAGE - 1)) + 1;
    let status = sections::commit_view(&view, first, limit - first, view.section.page_protect())?;
    Ok(if status == 0 { 0 } else { STATUS_COMMITMENT_LIMIT })
}
