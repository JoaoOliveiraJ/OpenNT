//! A avaliação das regras e a atualização do estado delas.
//!
//! - EmpEvaluateTargetRule: cada conjunto de argumentos da regra-alvo vira
//!   as cadeias (endereços da tabela) e os números da regra; o primeiro
//!   conjunto TRUE vence e um UNKNOWN também encerra a busca.
//! - EmpEvaluateNodeLink: `&` e `|` com curto-circuito e UNKNOWN propagado
//!   na hora; o termo sem rotina registrada (ou a regra que não está pronta)
//!   é UNKNOWN; os índices do termo remapeiam os argumentos de quem o contém
//!   (EmpEvaluateParseNodeMapping; um índice fora dos limites é UNKNOWN), e
//!   o termo sem índices recebe os do chamador como estão.
//! - O callback de um driver é chamado na ABI do EM_CALLBACK_ROUTINE
//!   (Entries, NumberOfEntries, Strings, NumberOfStrings, Numerics,
//!   NumberOfNumerics, Context), com as listas num bloco 'EMev' de pool; o
//!   valor devolvido é o estado do termo.
//! - EmpUpdateRuleState: a regra está pronta quando todo tipo de entrada
//!   dela tem provedor, todo callback dela tem rotina e toda regra que ela
//!   referencia está pronta; a mudança de prontidão repassa às dependentes
//!   antes do estado próprio. Pronta, a regra sai de UNKNOWN para FALSE e,
//!   sempre que a regra-alvo tem clientes interessados (a consulta conta
//!   como um), é avaliada (EmpEvaluateUpdateRuleEvalState: UNKNOWN vira
//!   FALSE).
//! - EmpQueueRuleUpdateState e o EmpRuleUpdateWorkerThread: a fila (a
//!   regra já na fila perde a âncora) e o work item da DelayedWorkQueue que
//!   a esvazia sob o EmpDatabaseLock, da cabeça (a última enfileirada).

use alloc::vec::Vec;

use crate::hal::amd64::native_call;
use crate::ntos::em::database::{self, Arguments, Database, Node, Routine, STATE_FALSE, STATE_TRUE, STATE_UNKNOWN};
use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::types::{NtStruct, WorkQueueItem};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

const PAGED_POOL: u32 = 1;
/// 'EMev': as listas de uma avaliação.
const EVALUATION_TAG: u32 = u32::from_le_bytes(*b"EMev");

/// Os argumentos que chegam a um nó: as entradas, as cadeias e os números.
struct Incoming<'a> {
    entries: &'a [u64],
    strings: &'a [u64],
    numerics: &'a [u32],
}

/// Chama a rotina de um callback com os argumentos dados.
fn call_routine(routine: Routine, entries: &[u64], strings: &[u64], numerics: &[u32], context: u64) -> u32 {
    match routine {
        Routine::Native(function) => function(&Arguments { entries, strings, numerics, context }),
        Routine::Guest(address) => {
            let bytes = (entries.len() + strings.len()) as u64 * 8 + numerics.len() as u64 * 4;
            let block = if bytes != 0 { pool_allocation::allocate_tagged(PAGED_POOL, bytes, EVALUATION_TAG).unwrap_or(0) } else { 0 };
            if bytes != 0 && block == 0 {
                return STATE_UNKNOWN;
            }
            let entries_address = if entries.is_empty() { 0 } else { block };
            let strings_address = if strings.is_empty() { 0 } else { block + entries.len() as u64 * 8 };
            let numerics_address = if numerics.is_empty() { 0 } else { block + (entries.len() + strings.len()) as u64 * 8 };
            for (index, &entry) in entries.iter().enumerate() {
                guest::write64(entries_address + index as u64 * 8, entry);
            }
            for (index, &string) in strings.iter().enumerate() {
                guest::write64(strings_address + index as u64 * 8, string);
            }
            for (index, &numeric) in numerics.iter().enumerate() {
                guest::write32(numerics_address + index as u64 * 4, numeric);
            }
            let state = native_call::call(address, &[entries_address, entries.len() as u64, strings_address, strings.len() as u64, numerics_address, numerics.len() as u64, context]) as u32;
            if block != 0 {
                let _ = pool_allocation::free(block, EVALUATION_TAG as u64);
            }
            state
        }
    }
}

/// EmpEvaluateParseNodeMapping: os argumentos do chamado a partir dos
/// índices do termo; `None` se um índice sai dos limites.
fn map_arguments(indices: &[u32], counts: (u32, u32, u32), incoming: &Incoming) -> Option<(Vec<u64>, Vec<u64>, Vec<u32>)> {
    let (strings, numerics, entries) = (counts.0 as usize, counts.1 as usize, counts.2 as usize);
    if indices.len() != strings + numerics + entries {
        return None;
    }
    let mut mapped_strings = Vec::new();
    for &index in &indices[..strings] {
        mapped_strings.push(*incoming.strings.get(index as usize)?);
    }
    let mut mapped_numerics = Vec::new();
    for &index in &indices[strings..strings + numerics] {
        mapped_numerics.push(*incoming.numerics.get(index as usize)?);
    }
    let mut mapped_entries = Vec::new();
    for &index in &indices[strings + numerics..] {
        mapped_entries.push(*incoming.entries.get(index as usize)?);
    }
    Some((mapped_entries, mapped_strings, mapped_numerics))
}

/// EmpEvaluateNodeLink.
fn evaluate_node(database: &Database, node: &Node, incoming: &Incoming) -> u32 {
    match node {
        Node::Operator { operator, left, right } => {
            let left = evaluate_node(database, left, incoming);
            if left == STATE_UNKNOWN {
                return STATE_UNKNOWN;
            }
            if *operator == b'&' && left == STATE_FALSE {
                return STATE_FALSE;
            }
            if *operator == b'|' && left == STATE_TRUE {
                return STATE_TRUE;
            }
            let right = evaluate_node(database, right, incoming);
            if right == STATE_UNKNOWN {
                return STATE_UNKNOWN;
            }
            match operator {
                b'&' => if left != 0 && right != 0 { STATE_TRUE } else { STATE_FALSE },
                b'|' => if left != 0 || right != 0 { STATE_TRUE } else { STATE_FALSE },
                _ => STATE_UNKNOWN,
            }
        }
        Node::Callback { index, arguments } => {
            let callback = &database.callbacks[*index];
            let Some(routine) = callback.routine else { return STATE_UNKNOWN };
            match arguments {
                None => call_routine(routine, incoming.entries, incoming.strings, incoming.numerics, callback.context),
                Some(indices) => match map_arguments(indices, (callback.strings, callback.numerics, callback.entry_types.len() as u32), incoming) {
                    Some((entries, strings, numerics)) => call_routine(routine, &entries, &strings, &numerics, callback.context),
                    None => STATE_UNKNOWN,
                },
            }
        }
        Node::Rule { index, arguments } => {
            let rule = &database.rules[*index];
            if !rule.ready {
                return STATE_UNKNOWN;
            }
            match arguments {
                None => evaluate_node(database, &rule.root, incoming),
                Some(indices) => match map_arguments(indices, (rule.strings, rule.numerics, rule.entry_types.len() as u32), incoming) {
                    Some((entries, strings, numerics)) => evaluate_node(database, &rule.root, &Incoming { entries: &entries, strings: &strings, numerics: &numerics }),
                    None => STATE_UNKNOWN,
                },
            }
        }
    }
}

/// EmpEvaluateTargetRule: o estado cru (0, 1 ou 2) da regra-alvo com as
/// entradas dadas.
pub fn evaluate_target(database: &Database, target: usize, entries: &[u64]) -> u32 {
    let target = &database.targets[target];
    let rule = &database.rules[target.rule];
    let width = (rule.strings + rule.numerics) as usize;
    let sets = if width == 0 { 1 } else { target.arguments.len() / width };
    let mut result = STATE_UNKNOWN;
    for set in 0..sets {
        let arguments = if width == 0 { &[][..] } else { &target.arguments[set * width..(set + 1) * width] };
        let (string_indices, numerics) = arguments.split_at(rule.strings as usize);
        let strings: Vec<u64> = string_indices.iter().map(|&index| database.strings.get(index as usize).map_or(0, |(_, address)| *address)).collect();
        result = evaluate_node(database, &rule.root, &Incoming { entries, strings: &strings, numerics });
        if result == STATE_UNKNOWN || result == STATE_TRUE {
            break;
        }
    }
    result
}

/// EmpEvaluateUpdateRuleEvalState.
fn update_evaluation_state(database: &mut Database, target: usize) {
    let rule_index = database.targets[target].rule;
    if !database.rules[rule_index].ready {
        database.rules[rule_index].state = STATE_UNKNOWN;
        return;
    }
    if database.rules[rule_index].entry_types.is_empty() {
        let result = evaluate_target(database, target, &[]);
        database.rules[rule_index].state = if result == STATE_TRUE { STATE_TRUE } else { STATE_FALSE };
        return;
    }
    // Com tipos de entrada: os callbacks preguiçosos de cada tipo, na ordem
    // dele, e as combinações das entradas registradas. Nenhum driver desta
    // instalação registra entradas avulsas (EmProviderRegisterEntry): sem
    // entradas no tipo, a regra fica FALSE.
    let entry_type = database.rules[rule_index].entry_types[0];
    let (guid_address, lazy) = (database.entry_types[entry_type].guid_address, database.entry_types[entry_type].lazy.clone());
    for (routine, context, _) in lazy {
        let _ = native_call::call(routine, &[guid_address, context]);
    }
    database.rules[rule_index].state = STATE_FALSE;
}

/// EmpUpdateRuleState.
pub fn update_rule_state(database: &mut Database, rule_index: usize) {
    let old = database.rules[rule_index].state;
    let rule = &database.rules[rule_index];
    let ready = rule.entry_types.iter().all(|&entry_type| database.entry_types[entry_type].provider_count > 0)
        && rule.callbacks.iter().all(|&callback| database.callbacks[callback].routine.is_some())
        && rule.referenced.iter().all(|&referenced| database.rules[referenced].ready);
    if database.rules[rule_index].ready != ready {
        database.rules[rule_index].ready = ready;
        for dependent in database.rules[rule_index].dependents.clone() {
            update_rule_state(database, dependent);
        }
    }
    if !ready {
        database.rules[rule_index].state = STATE_UNKNOWN;
        return;
    }
    if old == STATE_UNKNOWN {
        database.rules[rule_index].state = STATE_FALSE;
    }
    if let Some(target) = database.search_target(rule_index).filter(|&target| database.targets[target].references > 0) {
        update_evaluation_state(database, target);
    }
}

/// A fila do EmpQueueRuleUpdateState (com o EmpEvaluationQueueLock) e o
/// EmpWorkerBusy.
struct UpdateQueue {
    entries: Vec<usize>,
    busy: bool,
    /// O WORK_QUEUE_ITEM do EmpRuleUpdateWorker.
    work_item: u64,
}

static QUEUE: SpinLock<UpdateQueue> = SpinLock::new(UpdateQueue { entries: Vec::new(), busy: false, work_item: 0 });

/// EmpQueueRuleUpdateState(rule, NULL).
pub fn queue_rule_update(rule: usize) {
    let mut queue = QUEUE.lock();
    if queue.entries.contains(&rule) {
        return;
    }
    queue.entries.push(rule);
    if queue.busy {
        return;
    }
    if queue.work_item == 0 {
        queue.work_item = pool_allocation::allocate_tagged(0, WorkQueueItem::SIZE, u32::from_le_bytes(*b"EMqu")).unwrap_or(0);
        if queue.work_item == 0 {
            return;
        }
    }
    queue.busy = true;
    let item = queue.work_item;
    drop(queue);
    crate::ntos::io::work_items::queue_kernel_ex_work_item(item, rule_update_worker, 0);
}

/// EmpRuleUpdateWorkerThread: esvazia a fila pela cabeça.
fn rule_update_worker(_item: u64, _parameter: u64) {
    loop {
        let next = {
            let mut queue = QUEUE.lock();
            let next = queue.entries.pop();
            if next.is_none() {
                queue.busy = false;
            }
            next
        };
        let Some(rule) = next else { return };
        let mut database = database::lock();
        update_rule_state(&mut database, rule);
    }
}
