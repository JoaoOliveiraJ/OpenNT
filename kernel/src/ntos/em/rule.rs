//! EmClientRuleEvaluate(RuleId, EntryInformation, NumberOfEntries, State).
//!
//! Valida os quatro argumentos, grava STATE_UNKNOWN (1) em *State e procura
//! a regra (EmpSearchRuleDatabase) sob a trava do banco. As regras só
//! existem quando o INF de errata do carregador foi interpretado; o banco
//! do OpenNT não tem regras (veja `em/mod.rs`), então a busca falha com
//! STATUS_NOT_FOUND e *State fica STATE_UNKNOWN, como no ntoskrnl sem o INF.

use crate::ntos::em::database;
use crate::ntos::inc::field::Field;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
/// EM_RULE_STATE: STATE_UNKNOWN.
pub const STATE_UNKNOWN: u32 = 1;

/// EmClientRuleEvaluate.
pub fn evaluate(rule_id: u64, entry_information: u64, number_of_entries: u32, state: Option<&Field<u32>>) -> u32 {
    let Some(state) = state else { return STATUS_INVALID_PARAMETER };
    if rule_id == 0 || entry_information == 0 || number_of_entries == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    state.set(STATE_UNKNOWN);
    let _database = database::lock();
    STATUS_NOT_FOUND
}
