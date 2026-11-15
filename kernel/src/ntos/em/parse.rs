//! EmpParseInfDatabase: o banco a partir do INF de errata interpretado
//! (`cm/inf_parse.rs`), na ordem do ntoskrnl 19041: tipos de entrada,
//! callbacks, regras, cadeias e regras-alvo; a primeira etapa com status
//! negativo encerra a carga.
//!
//! - [EntryTypeGuidDef]: um tipo por linha (o GUID é o primeiro valor).
//! - [CallbackDef] `Nome = cadeias, números, Tipo...`: o GUID pelo
//!   [CallbackGuidDef] e os tipos de entrada pelo [EntryTypeGuidDef] (busca
//!   pela primeira chave que começa pelo nome, sem diferenciar maiúsculas).
//! - [RuleDef] `Nome = cadeias, números, Tipo...` e a expressão da linha de
//!   mesmo nome em [Rule]: valores em notação pós-fixa, `?Callback(c)(n)(e)`,
//!   `%Regra(c)(n)(e)` (índices decimais separados por ponto, nos
//!   argumentos da regra que contém o termo), `&` e `|`. Uma regra só
//!   referencia as já carregadas (definidas antes); a expressão inválida
//!   descarta a regra sem falhar a carga.
//! - [Strings]: a tabela de cadeias (os valores, numa cópia em pool cada).
//! - [TargetRuleDef] `Regra = {s.s...n.n...}, ...`: os conjuntos de
//!   argumentos, as cadeias pelo nome da chave em [Strings] (o índice da
//!   primeira cópia igual na tabela) e os números em hexadecimal
//!   (RtlCharToInteger, que nunca falha).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::cm::inf_parse::Inf;
use crate::ntos::em::database::{Callback, Database, EntryType, Node, Rule, TargetRule, STATE_UNKNOWN};
use crate::ntos::ex::pool_allocation;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const PAGED_POOL: u32 = 1;
/// 'EMit': os registros do banco.
pub const DATABASE_TAG: u32 = u32::from_le_bytes(*b"EMit");

fn failed(status: u32) -> bool {
    status as i32 <= -1
}

/// strtoul(texto, NULL, 10): espaços, sinal opcional e os dígitos.
fn strtoul(text: &str) -> u32 {
    let bytes = text.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']).as_bytes();
    let (negative, digits) = match bytes.first() {
        Some(b'-') => (true, &bytes[1..]),
        Some(b'+') => (false, &bytes[1..]),
        _ => (false, bytes),
    };
    let mut value: u32 = 0;
    for &byte in digits.iter().take_while(|byte| byte.is_ascii_digit()) {
        value = value.wrapping_mul(10).wrapping_add((byte - b'0') as u32);
    }
    if negative { value.wrapping_neg() } else { value }
}

/// RtlCharToInteger(texto, 16): pula os caracteres até 0x20, sinal
/// opcional e os dígitos hexadecimais até o primeiro que não for; sempre
/// tem sucesso.
fn char_to_integer_hex(text: &str) -> u32 {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() && bytes[index] <= 0x20 {
        index += 1;
    }
    let negative = match bytes.get(index) {
        Some(b'-') => {
            index += 1;
            true
        }
        Some(b'+') => {
            index += 1;
            false
        }
        _ => false,
    };
    let mut value: u32 = 0;
    while let Some(digit) = bytes.get(index).and_then(|&byte| (byte as char).to_digit(16)) {
        value = value.wrapping_mul(16).wrapping_add(digit);
        index += 1;
    }
    if negative { value.wrapping_neg() } else { value }
}

/// EmpInfParseGetGuidFromName.
fn guid_from_name(inf: &Inf, section: &str, name: &str) -> Result<[u8; 16], u32> {
    let (text, _) = inf.value_by_key(section, name).ok_or(STATUS_NOT_FOUND)?;
    crate::ntos::em::database::guid_from_text(text).ok_or(STATUS_INVALID_PARAMETER)
}

/// Uma cópia em pool ('EMit') de bytes terminados por NUL.
fn pool_copy(bytes: &[u8]) -> u64 {
    let block = pool_allocation::allocate_tagged(PAGED_POOL, bytes.len() as u64 + 1, DATABASE_TAG).unwrap_or(0);
    if block != 0 {
        crate::ntos::mm::guest_memory::write_bytes(block, bytes);
        crate::ntos::mm::guest_memory::write8(block + bytes.len() as u64, 0);
    }
    block
}

/// EmpParseEntryTypes.
fn parse_entry_types(inf: &Inf, database: &mut Database) -> u32 {
    let mut status = STATUS_SUCCESS;
    for index in 0..inf.line_count("EntryTypeGuidDef") {
        let Some(text) = inf.value("EntryTypeGuidDef", index, 0) else { return STATUS_SUCCESS };
        let Some(guid) = crate::ntos::em::database::guid_from_text(text) else {
            status = STATUS_INVALID_PARAMETER;
            continue;
        };
        if database.search_entry(&guid).is_some() {
            continue;
        }
        let guid_address = pool_allocation::allocate_tagged(PAGED_POOL, 16, DATABASE_TAG).unwrap_or(0);
        if guid_address != 0 {
            crate::ntos::mm::guest_memory::write_bytes(guid_address, &guid);
        }
        database.entry_types.push(EntryType { guid, provider_count: 0, lazy: Vec::new(), rules: Vec::new(), guid_address });
        status = STATUS_SUCCESS;
    }
    status
}

/// Os tipos de entrada dos valores 2.. de uma linha ([CallbackDef] ou
/// [RuleDef]), pelo [EntryTypeGuidDef].
fn entry_types_of(inf: &Inf, database: &Database, section: &str, index: u32) -> Result<Vec<usize>, u32> {
    let count = inf.value_count(section, index);
    let mut types = Vec::new();
    for value in 2..count {
        let name = inf.value(section, index, value).unwrap_or("");
        let guid = guid_from_name(inf, "EntryTypeGuidDef", name)?;
        types.push(database.search_entry(&guid).ok_or(STATUS_NOT_FOUND)?);
    }
    Ok(types)
}

/// EmpParseCallbacks.
fn parse_callbacks(inf: &Inf, database: &mut Database) -> u32 {
    let mut status = STATUS_SUCCESS;
    for index in 0..inf.line_count("CallbackDef") {
        let Some(name) = inf.key_name("CallbackDef", index) else { return status };
        if inf.value_count("CallbackDef", index) < 2 {
            status = STATUS_INVALID_PARAMETER;
            continue;
        }
        let guid = match guid_from_name(inf, "CallbackGuidDef", name) {
            Ok(guid) if database.search_callback(&guid).is_none() => guid,
            Ok(_) => continue,
            Err(error) => {
                status = error;
                continue;
            }
        };
        let strings = strtoul(inf.value("CallbackDef", index, 0).unwrap_or(""));
        let numerics = strtoul(inf.value("CallbackDef", index, 1).unwrap_or(""));
        match entry_types_of(inf, database, "CallbackDef", index) {
            Ok(entry_types) => {
                database.callbacks.push(Callback { guid, routine: None, registrations: 0, context: 0, rules: Vec::new(), strings, numerics, entry_types });
                status = STATUS_SUCCESS;
            }
            Err(error) => status = error,
        }
    }
    status
}

/// As contagens (cadeias, números, entradas) de um callback ou regra.
fn callee_counts(database: &Database, node: &Node) -> (u32, u32, u32) {
    match node {
        Node::Callback { index, .. } => {
            let callback = &database.callbacks[*index];
            (callback.strings, callback.numerics, callback.entry_types.len() as u32)
        }
        Node::Rule { index, .. } => {
            let rule = &database.rules[*index];
            (rule.strings, rule.numerics, rule.entry_types.len() as u32)
        }
        Node::Operator { .. } => (0, 0, 0),
    }
}

/// EmpParseRuleTermArgMapping: os grupos `(...)` de índices decimais
/// separados por ponto, com as contagens exatas do chamado.
fn parse_argument_mapping(text: &str, counts: (u32, u32, u32)) -> Option<Vec<u32>> {
    let expected = [counts.0, counts.1, counts.2];
    let bytes = text.as_bytes();
    let mut position = 0;
    let mut indices = Vec::new();
    for (group, &count) in expected.iter().enumerate() {
        if position == bytes.len() {
            // O texto pode acabar depois do grupo 1 (sem números nem
            // entradas) ou do grupo 2 (sem entradas).
            return expected[group..].iter().all(|&rest| rest == 0).then_some(indices);
        }
        if bytes[position] != b'(' {
            return None;
        }
        position += 1;
        let mut found = 0u32;
        loop {
            match bytes.get(position) {
                Some(b')') => {
                    position += 1;
                    break;
                }
                Some(b'.') => position += 1,
                Some(byte) if byte.is_ascii_digit() => {
                    let start = position;
                    while bytes.get(position).is_some_and(|byte| byte.is_ascii_digit()) {
                        position += 1;
                    }
                    indices.push(strtoul(&text[start..position]));
                    found += 1;
                }
                _ => return None,
            }
        }
        if found != count {
            return None;
        }
    }
    (position == bytes.len()).then_some(indices)
}

/// EmpParseRuleTerm + a validação do EmpParseRuleExpression: o termo
/// `?Nome(...)` ou `%Nome(...)` nos argumentos da regra `rule`.
fn parse_term(inf: &Inf, database: &Database, rule: &Rule, token: &str) -> Result<Node, u32> {
    let callback = token.starts_with('?');
    let open = token.find('(').ok_or(STATUS_INVALID_PARAMETER)?;
    let name = &token[1..open];
    let section = if callback { "CallbackGuidDef" } else { "RuleNameGuidDef" };
    let guid = guid_from_name(inf, section, name).map_err(|_| STATUS_NOT_FOUND)?;
    let (node, entry_types) = if callback {
        let index = database.search_callback(&guid).ok_or(STATUS_NOT_FOUND)?;
        (Node::Callback { index, arguments: None }, database.callbacks[index].entry_types.clone())
    } else {
        let index = database.search_rule(&guid).ok_or(STATUS_NOT_FOUND)?;
        (Node::Rule { index, arguments: None }, database.rules[index].entry_types.clone())
    };
    let counts = callee_counts(database, &node);
    let total = counts.0 + counts.1 + counts.2;
    let arguments = if total != 0 { Some(parse_argument_mapping(&token[open..], counts).ok_or(STATUS_INVALID_PARAMETER)?) } else { None };
    if let Some(indices) = &arguments {
        let (strings, numerics) = (counts.0 as usize, counts.1 as usize);
        let valid = indices[..strings].iter().all(|&index| index < rule.strings)
            && indices[strings..strings + numerics].iter().all(|&index| index < rule.numerics)
            && indices[strings + numerics..].iter().enumerate().all(|(position, &index)| (index as usize) < rule.entry_types.len() && entry_types.get(position) == Some(&rule.entry_types[index as usize]));
        if !valid {
            return Err(STATUS_INVALID_PARAMETER);
        }
    }
    Ok(match node {
        Node::Callback { index, .. } => Node::Callback { index, arguments },
        Node::Rule { index, .. } => Node::Rule { index, arguments },
        operator => operator,
    })
}

/// EmpParseRuleExpression: a árvore da linha de [Rule] da regra.
fn parse_expression(inf: &Inf, database: &Database, name: &str, rule: &mut Rule) -> Result<Node, u32> {
    let section = inf.section("Rule").ok_or(STATUS_NOT_FOUND)?;
    let mut line = None;
    for candidate in &section.lines {
        let Some(key) = candidate.key.as_deref() else { break };
        if key.len() >= name.len() && key.as_bytes()[..name.len()].eq_ignore_ascii_case(name.as_bytes()) {
            line = Some(candidate);
            break;
        }
    }
    let line = line.ok_or(STATUS_NOT_FOUND)?;
    let index = section.lines.iter().position(|candidate| core::ptr::eq(candidate, line)).unwrap_or(0) as u32;
    let mut stack: Vec<Node> = Vec::new();
    for value in 0..line.values.len() as u32 {
        let token = inf.value("Rule", index, value).unwrap_or("");
        match token.as_bytes().first() {
            Some(b'?') | Some(b'%') => {
                let node = parse_term(inf, database, rule, token)?;
                match &node {
                    Node::Callback { index, .. } => rule.callbacks.push(*index),
                    Node::Rule { index, .. } => rule.referenced.push(*index),
                    Node::Operator { .. } => {}
                }
                stack.push(node);
            }
            Some(&operator @ (b'&' | b'|')) => {
                if stack.len() < 2 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                let right = stack.pop().ok_or(STATUS_INVALID_PARAMETER)?;
                let left = stack.pop().ok_or(STATUS_INVALID_PARAMETER)?;
                stack.push(Node::Operator { operator, left: Box::new(left), right: Box::new(right) });
            }
            _ => return Err(STATUS_INVALID_PARAMETER),
        }
    }
    if stack.len() != 1 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    stack.pop().ok_or(STATUS_INVALID_PARAMETER)
}

/// EmpParseRules.
fn parse_rules(inf: &Inf, database: &mut Database) -> u32 {
    let mut status = STATUS_SUCCESS;
    for index in 0..inf.line_count("RuleDef") {
        let Some(name) = inf.key_name("RuleDef", index) else { return status };
        let guid = match guid_from_name(inf, "RuleNameGuidDef", name) {
            Ok(guid) => guid,
            Err(error) => {
                status = error;
                continue;
            }
        };
        if database.search_rule(&guid).is_some() {
            continue;
        }
        status = STATUS_SUCCESS;
        if inf.value_count("RuleDef", index) < 2 {
            continue;
        }
        let strings = strtoul(inf.value("RuleDef", index, 0).unwrap_or(""));
        let numerics = strtoul(inf.value("RuleDef", index, 1).unwrap_or(""));
        let Ok(entry_types) = entry_types_of(inf, database, "RuleDef", index) else { continue };
        let mut rule = Rule { guid, state: STATE_UNKNOWN, ready: false, dependents: Vec::new(), strings, numerics, entry_types, callbacks: Vec::new(), referenced: Vec::new(), root: Node::Operator { operator: 0, left: Box::new(Node::Callback { index: 0, arguments: None }), right: Box::new(Node::Callback { index: 0, arguments: None }) } };
        let Ok(root) = parse_expression(inf, database, name, &mut rule) else { continue };
        rule.root = root;
        let rule_index = database.rules.len();
        // As listas inversas: os tipos de entrada (+0x48), os callbacks
        // (+0x30) e as regras referenciadas (+0x20), sem repetição.
        for &entry_type in &rule.entry_types {
            if !database.entry_types[entry_type].rules.contains(&rule_index) {
                database.entry_types[entry_type].rules.push(rule_index);
            }
        }
        for &callback in &rule.callbacks {
            if !database.callbacks[callback].rules.contains(&rule_index) {
                database.callbacks[callback].rules.push(rule_index);
            }
        }
        for &referenced in &rule.referenced {
            if !database.rules[referenced].dependents.contains(&rule_index) {
                database.rules[referenced].dependents.push(rule_index);
            }
        }
        database.rules.push(rule);
    }
    status
}

/// EmpParseStrings.
fn parse_strings(inf: &Inf, database: &mut Database) -> u32 {
    for index in 0..inf.line_count("Strings") {
        let Some(value) = inf.value("Strings", index, 0) else { continue };
        let address = pool_copy(value.as_bytes());
        if address == 0 {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        database.strings.push((String::from(value), address));
    }
    STATUS_SUCCESS
}

/// EmpInfParseGetStringIndexFromName.
fn string_index(inf: &Inf, database: &Database, name: &str) -> Option<u32> {
    let (value, _) = inf.value_by_key("Strings", name)?;
    database.strings.iter().position(|(text, _)| text == value).map(|index| index as u32)
}

/// EmpParseTargetRuleStringIndexList: um conjunto `{...}`; devolve os
/// índices (cadeias e depois números) ou `None` se for inválido.
fn parse_target_set(inf: &Inf, database: &Database, value: &str, strings: u32, numerics: u32) -> Option<Vec<u32>> {
    let body = value.strip_prefix('{')?;
    let close = body.find('}')?;
    if close + 1 != body.len() {
        return None;
    }
    let tokens: Vec<&str> = body[..close].split('.').collect();
    if tokens.len() != (strings + numerics) as usize {
        return None;
    }
    let mut indices = Vec::new();
    for (position, token) in tokens.iter().enumerate() {
        if (position as u32) < strings {
            indices.push(string_index(inf, database, token)?);
        } else {
            indices.push(char_to_integer_hex(token));
        }
    }
    Some(indices)
}

/// EmpParseTargetRules.
fn parse_target_rules(inf: &Inf, database: &mut Database) -> u32 {
    let mut status = STATUS_SUCCESS;
    for index in 0..inf.line_count("TargetRuleDef") {
        status = STATUS_SUCCESS;
        let Some(name) = inf.key_name("TargetRuleDef", index) else { continue };
        let guid = match guid_from_name(inf, "RuleNameGuidDef", name) {
            Ok(guid) => guid,
            Err(error) => {
                status = error;
                continue;
            }
        };
        let Some(rule) = database.search_rule(&guid) else { continue };
        let (strings, numerics) = (database.rules[rule].strings, database.rules[rule].numerics);
        if strings + numerics == 0 {
            database.targets.push(TargetRule { references: 0, rule, arguments: Vec::new() });
            continue;
        }
        if database.search_target(rule).is_some() {
            continue;
        }
        let mut arguments = Vec::new();
        for value in 0..inf.value_count("TargetRuleDef", index) {
            if let Some(set) = inf.value("TargetRuleDef", index, value).and_then(|text| parse_target_set(inf, database, text, strings, numerics)) {
                arguments.extend(set);
            }
        }
        if !arguments.is_empty() {
            database.targets.push(TargetRule { references: 0, rule, arguments });
        }
    }
    status
}

/// EmpParseInfDatabase: o banco a partir da imagem do INF.
pub fn parse_database(image: &[u8], database: &mut Database) -> u32 {
    let inf = match crate::ntos::cm::inf_parse::parse(image) {
        Ok(inf) => inf,
        Err(line) => {
            crate::debug_print!("[em] INF de errata: erro de sintaxe na linha {}", line);
            return STATUS_INVALID_PARAMETER;
        }
    };
    for step in [parse_entry_types, parse_callbacks, parse_rules, parse_strings, parse_target_rules] {
        let status = step(&inf, database);
        if failed(status) {
            return status;
        }
    }
    STATUS_SUCCESS
}
