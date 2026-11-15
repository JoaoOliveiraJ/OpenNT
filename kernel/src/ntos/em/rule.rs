//! EmClientQueryRuleState e EmClientRuleEvaluate, as consultas dos drivers
//! clientes.
//!
//! - EmClientQueryRuleState(RuleId, State): grava UNKNOWN em *State, procura
//!   a regra e a regra-alvo dela (sem uma das duas, STATUS_NOT_FOUND) e,
//!   contando a consulta como cliente da regra-alvo, atualiza o estado da
//!   regra (EmpUpdateRuleState, que a avalia quando está pronta); *State é o
//!   estado resultante (uma avaliação UNKNOWN vira FALSE).
//! - EmClientRuleEvaluate(RuleId, EntryInformation, NumberOfEntries, State):
//!   avalia a regra-alvo com as entradas do chamador (uma por tipo de
//!   entrada da regra, na ordem do [RuleDef]; cada uma aponta {Data,
//!   DataSize}) e devolve o estado cru (0, 1 ou 2), sem tocar no estado
//!   guardado da regra.
//! Antes do EmInitSystem as duas devolvem STATUS_IN_PAGE_ERROR (o
//! EmpAcquirePagingReference sem a paginação habilitada).

use alloc::vec::Vec;

use crate::ntos::em::database::{self, STATE_UNKNOWN};
use crate::ntos::em::evaluate;
use crate::ntos::inc::field::Field;
use crate::ntos::mm::guest_memory as guest;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const STATUS_IN_PAGE_ERROR: u32 = 0xC000_0006;

/// EmClientQueryRuleState.
pub fn query_rule_state(rule_id: u64, state: Option<&Field<u32>>) -> u32 {
    let Some(state) = state else { return STATUS_INVALID_PARAMETER };
    if rule_id == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    state.set(STATE_UNKNOWN);
    if !crate::ntos::em::initialized() {
        return STATUS_IN_PAGE_ERROR;
    }
    let mut database = database::lock();
    let guid = database::guid_at(rule_id);
    let Some((rule, target)) = database.search_rule(&guid).and_then(|rule| database.search_target(rule).map(|target| (rule, target))) else { return STATUS_NOT_FOUND };
    database.targets[target].references += 1;
    evaluate::update_rule_state(&mut database, rule);
    database.targets[target].references -= 1;
    state.set(database.rules[rule].state);
    STATUS_SUCCESS
}

/// EmClientRuleEvaluate.
pub fn evaluate(rule_id: u64, entry_information: u64, number_of_entries: u32, state: Option<&Field<u32>>) -> u32 {
    let Some(state) = state else { return STATUS_INVALID_PARAMETER };
    if rule_id == 0 || entry_information == 0 || number_of_entries == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    state.set(STATE_UNKNOWN);
    if !crate::ntos::em::initialized() {
        return STATUS_IN_PAGE_ERROR;
    }
    let database = database::lock();
    let guid = database::guid_at(rule_id);
    let Some((rule, target)) = database.search_rule(&guid).and_then(|rule| database.search_target(rule).map(|target| (rule, target))) else { return STATUS_NOT_FOUND };
    if number_of_entries as usize != database.rules[rule].entry_types.len() {
        return STATUS_INVALID_PARAMETER;
    }
    let entries: Vec<u64> = (0..number_of_entries as u64).map(|index| guest::read64(entry_information + index * 8)).collect();
    state.set(evaluate::evaluate_target(&database, target, &entries));
    STATUS_SUCCESS
}
