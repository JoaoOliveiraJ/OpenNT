//! Entrega dos relatos de uso — `system32/ntos/cm/feature-usage-delivery.js`.
//!
//! Cada estado WNF guarda pares únicos (recurso, tipo de relato); as
//! atualizações usam o carimbo da consulta.

use crate::ntos::ex::wnf::state_data as wnf_state_data;
use crate::ntos::mm::guest_memory as guest;

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
        let mut used = if queried.size & 7 != 0 { 0 } else { queried.size as u64 };
        let feature = guest::read32(report);
        let kind = guest::read16(report + 4);
        let present = (0..used).step_by(8).any(|offset| guest::read32(workspace + offset) == feature && guest::read16(workspace + offset + 4) == kind);
        if !present && used + 8 <= 4096 {
            guest::write32(workspace + used, feature);
            guest::write16(workspace + used + 4, kind);
            // Os dois bytes finais da entrada são reservados e conservam o
            // conteúdo do workspace, como na referência.
            used += 8;
        }
        let delivered = wnf_state_data::update(target, workspace, used as u32, queried.stamp, true);
        if delivered != 0xC000_0001 {
            break delivered;
        }
    };
    guest::free_bytes(workspace);
    status
}

/// Filtra por recurso, tipo e opção exigida; uma entrega bem-sucedida já
/// obtida prevalece sobre falhas de destinos posteriores.
pub fn send(report: u64, subscriptions: &[Subscription]) -> u32 {
    let mut status = NOT_FOUND;
    let feature = guest::read32(report);
    let kind = guest::read16(report + 4);
    let options = guest::read16(report + 6);
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
