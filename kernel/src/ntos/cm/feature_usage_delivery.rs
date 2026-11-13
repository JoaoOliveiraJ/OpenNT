//! Entrega dos relatos de uso.
//!
//! Cada estado WNF guarda pares únicos (recurso, tipo de relato); as
//! atualizações usam o carimbo da consulta.

use crate::ntos::ex::wnf::state_data as wnf_state_data;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{NtStruct, RtlFeatureUsageReport};

const NOT_FOUND: u32 = 0xC000_0225;

/// Inscrição interna: recurso, tipo, opção exigida e estado WNF de destino.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Subscription {
    pub feature_id: u32,
    pub reporting_kind: u16,
    pub reporting_options: u16,
    pub target_name: u64,
}

/// Consulta o estado num workspace de 4096 bytes, procura o par e o
/// acrescenta se houver espaço; conflitos de versão repetem a operação.
pub fn send_target(report: u64, target: u64) -> u32 {
    let report = report_at(report);
    let workspace = guest::alloc_bytes(4096);
    if workspace == 0 {
        return 0xC000_0017;
    }
    let status = loop {
        let queried = wnf_state_data::query(target, workspace, 4096);
        if queried.status == 0xC000_0001 {
            continue;
        }
        if queried.status & 0x8000_0000 != 0 {
            break queried.status;
        }
        // Sequência de entradas de oito bytes; tamanho fora do múltiplo
        // reinicia a sequência.
        let entry_size = RtlFeatureUsageReport::SIZE;
        let mut used = if queried.size as u64 % entry_size != 0 { 0 } else { queried.size as u64 };
        let (feature, kind) = (report.feature_id.get(), report.reporting_kind.get());
        // As entradas do estado têm a forma de um RTL_FEATURE_USAGE_REPORT
        // (o último USHORT é reservado).
        // SAFETY: `used` bytes de entradas no workspace próprio de 4096 bytes.
        let entries = unsafe { RtlFeatureUsageReport::array_at(workspace, (used / entry_size) as usize) };
        let present = entries.iter().any(|entry| entry.feature_id.get() == feature && entry.reporting_kind.get() == kind);
        if !present && used + entry_size <= 4096 {
            // SAFETY: a entrada nova cabe no workspace.
            let entry = unsafe { RtlFeatureUsageReport::at(workspace + used) };
            entry.feature_id.set(feature);
            entry.reporting_kind.set(kind);
            // Os dois bytes finais da entrada são reservados e conservam o
            // conteúdo do workspace, como na referência.
            used += entry_size;
        }
        let delivered = wnf_state_data::update(target, workspace, used as u32, queried.stamp, true);
        if delivered != 0xC000_0001 {
            break delivered;
        }
    };
    guest::free_bytes(workspace);
    status
}

fn report_at(report: u64) -> &'static RtlFeatureUsageReport {
    // SAFETY: relato copiado no banco (ou do chamador), vivo durante a entrega.
    unsafe { RtlFeatureUsageReport::at(report) }
}

/// Filtra por recurso, tipo e opção exigida; uma entrega bem-sucedida já
/// obtida prevalece sobre falhas de destinos posteriores.
pub fn send(report: u64, subscriptions: &[Subscription]) -> u32 {
    let mut status = NOT_FOUND;
    let entry = report_at(report);
    let feature = entry.feature_id.get();
    let kind = entry.reporting_kind.get();
    let options = entry.reporting_options.get();
    for subscription in subscriptions {
        if subscription.feature_id != feature || subscription.reporting_kind != kind {
            continue;
        }
        if subscription.reporting_options & 1 != 0 && options & 1 == 0 {
            continue;
        }
        let target = send_target(report, subscription.target_name);
        if target & 0x8000_0000 == 0 {
            status = target;
        }
    }
    status
}
