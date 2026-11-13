//! Fronteira endereço -> objeto WNF: as instâncias vivem no pool e circulam
//! como ponteiros (vínculos de lista, árvore AVL, contexto do EPROCESS).

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{
    Eprocess, WnfNameInstance, WnfProcessContext, WnfScopeInstance, WnfScopeMap, WnfStateData, WnfSubscription,
};

pub(super) fn name_at(pointer: u64) -> &'static WnfNameInstance {
    // SAFETY: instâncias de nome publicadas pelo namespace (ou ainda privadas).
    unsafe { WnfNameInstance::at(pointer) }
}

pub(super) fn scope_at(pointer: u64) -> &'static WnfScopeInstance {
    // SAFETY: instâncias de escopo publicadas pelo namespace.
    unsafe { WnfScopeInstance::at(pointer) }
}

pub(super) fn scope_map_at(pointer: u64) -> &'static WnfScopeMap {
    // SAFETY: mapas de escopo alocados pelo namespace.
    unsafe { WnfScopeMap::at(pointer) }
}

pub(super) fn subscription_at(pointer: u64) -> &'static WnfSubscription {
    // SAFETY: inscrições alocadas pelo serviço de notificações.
    unsafe { WnfSubscription::at(pointer) }
}

pub(super) fn process_context_at(pointer: u64) -> &'static WnfProcessContext {
    // SAFETY: contextos publicados em EPROCESS.WnfContext.
    unsafe { WnfProcessContext::at(pointer) }
}

pub(super) fn state_data_at(pointer: u64) -> &'static WnfStateData {
    // SAFETY: blocos de dados alocados por `data_block`.
    unsafe { WnfStateData::at(pointer) }
}

pub(super) fn process_at(process: u64) -> &'static Eprocess {
    // SAFETY: processos vivos (referenciados pelo chamador ou pela inscrição).
    unsafe { Eprocess::at(process) }
}
