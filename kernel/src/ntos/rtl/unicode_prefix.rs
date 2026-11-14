//! Tabelas de prefixos Unicode: RtlInitializeUnicodePrefix,
//! RtlInsertUnicodePrefix, RtlRemoveUnicodePrefix e RtlFindUnicodePrefix.
//!
//! A tabela (UNICODE_PREFIX_TABLE) e as entradas (UNICODE_PREFIX_TABLE_ENTRY)
//! moram na memória de quem chama, que só usa os ponteiros devolvidos (os
//! file systems de pipes e mailslots embutem a entrada nos próprios FCBs).
//! A organização interna é esta: a tabela tem o código de nó
//! RTL_NTC_UNICODE_PREFIX_TABLE (0x800) e, em NextPrefixTree, a primeira
//! entrada de uma lista circular que volta à tabela; cada entrada é uma raiz
//! de árvore (RTL_NTC_UNICODE_ROOT, 0x801) com os links de splay apontando
//! para ela mesma, CaseMatch nela mesma e NameLength com o número de
//! componentes do prefixo. A lista fica em ordem decrescente de componentes,
//! então a primeira entrada que casa é o prefixo mais longo.
//!
//! O casamento segue o contrato do NT: o prefixo casa com o começo do nome
//! numa fronteira de componente (o nome acaba ali, o próximo caractere é `\`
//! ou o prefixo termina em `\`); os primeiros `CaseInsensitiveIndex`
//! caracteres comparam com caixa e o resto sem caixa (RtlUpcaseUnicodeChar).
//! Inserir um prefixo que já existe (sem caixa) devolve FALSE.

use alloc::vec::Vec;

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{UnicodePrefixTable, UnicodePrefixTableEntry};
use crate::ntos::rtl::guest_strings;
use crate::ntos::rtl::nls_translation::upcase_unicode_char;
use crate::rtl::KernelError;

/// RTL_NTC_UNICODE_PREFIX_TABLE e RTL_NTC_UNICODE_ROOT.
const NODE_TABLE: i16 = 0x800;
const NODE_ROOT: i16 = 0x801;

fn table_at(address: u64) -> &'static UnicodePrefixTable {
    // SAFETY: a UNICODE_PREFIX_TABLE viva do chamador de kernel.
    unsafe { UnicodePrefixTable::at(address) }
}

fn entry_at(address: u64) -> &'static UnicodePrefixTableEntry {
    // SAFETY: uma UNICODE_PREFIX_TABLE_ENTRY viva do chamador (inserida na
    // tabela ou a ser inserida).
    unsafe { UnicodePrefixTableEntry::at(address) }
}

/// O número de componentes de um nome: as barras, mais um componente final
/// que não termine em barra.
fn components(name: &[u16]) -> i16 {
    let separators = name.iter().filter(|&&unit| unit == u16::from(b'\\')).count();
    let trailing = name.last().is_some_and(|&unit| unit != u16::from(b'\\'));
    (separators + usize::from(trailing)).min(i16::MAX as usize) as i16
}

/// O texto de uma UNICODE_STRING do chamador.
fn text(unicode: u64) -> Result<Vec<u16>, KernelError> {
    guest_strings::try_read_unicode_units(unicode)
}

/// `prefix` casa com o começo de `name` numa fronteira de componente; os
/// primeiros `case_sensitive` caracteres comparam com caixa.
fn matches(prefix: &[u16], name: &[u16], case_sensitive: usize) -> bool {
    if prefix.len() > name.len() {
        return false;
    }
    let equal = prefix.iter().zip(name).enumerate().all(|(index, (&left, &right))| if index < case_sensitive { left == right } else { upcase_unicode_char(left) == upcase_unicode_char(right) });
    let slash = u16::from(b'\\');
    equal && (prefix.len() == name.len() || name[prefix.len()] == slash || prefix.last() == Some(&slash))
}

/// As entradas da tabela, na ordem da lista.
fn entries(table: u64) -> Vec<u64> {
    let mut list = Vec::new();
    let mut current = table_at(table).next_prefix_tree.get();
    while current != 0 && current != table {
        list.push(current);
        current = entry_at(current).next_prefix_tree.get();
    }
    list
}

/// RtlInitializeUnicodePrefix(PrefixTable): a tabela vazia.
pub fn initialize(table: u64) {
    let header = table_at(table);
    header.node_type_code.set(NODE_TABLE);
    header.name_length.set(0);
    header.next_prefix_tree.set(table);
    header.last_next_entry.set(0);
}

/// RtlInsertUnicodePrefix(PrefixTable, Prefix, PrefixTableEntry) -> BOOLEAN.
pub fn insert(table: u64, prefix: u64, entry: u64) -> Result<bool, KernelError> {
    let name = text(prefix)?;
    let length = components(&name);
    let mut previous = table;
    for candidate in entries(table) {
        let other = entry_at(candidate);
        let other_name = text(other.prefix.get())?;
        if other_name.len() == name.len() && matches(&other_name, &name, 0) {
            return Ok(false);
        }
        if other.name_length.get() < length {
            break;
        }
        previous = candidate;
    }
    let item = entry_at(entry);
    item.node_type_code.set(NODE_ROOT);
    item.name_length.set(length);
    item.case_match.set(entry);
    item.links.parent.set(entry);
    item.links.left_child.set(0);
    item.links.right_child.set(0);
    item.prefix.set(prefix);
    if previous == table {
        item.next_prefix_tree.set(table_at(table).next_prefix_tree.get());
        table_at(table).next_prefix_tree.set(entry);
    } else {
        item.next_prefix_tree.set(entry_at(previous).next_prefix_tree.get());
        entry_at(previous).next_prefix_tree.set(entry);
    }
    Ok(true)
}

/// RtlRemoveUnicodePrefix(PrefixTable, PrefixTableEntry).
pub fn remove(table: u64, entry: u64) {
    let next = entry_at(entry).next_prefix_tree.get();
    let mut previous = table;
    for candidate in entries(table) {
        if candidate == entry {
            if previous == table {
                table_at(table).next_prefix_tree.set(next);
            } else {
                entry_at(previous).next_prefix_tree.set(next);
            }
            if table_at(table).last_next_entry.get() == entry {
                table_at(table).last_next_entry.set(0);
            }
            entry_at(entry).next_prefix_tree.set(0);
            return;
        }
        previous = candidate;
    }
}

/// RtlFindUnicodePrefix(PrefixTable, FullName, CaseInsensitiveIndex): a
/// entrada do prefixo mais longo de `FullName`, ou 0.
pub fn find(table: u64, full_name: u64, case_insensitive_index: u32) -> Result<u64, KernelError> {
    let name = text(full_name)?;
    let length = components(&name);
    for candidate in entries(table) {
        let entry = entry_at(candidate);
        if entry.name_length.get() > length {
            continue;
        }
        if matches(&text(entry.prefix.get())?, &name, case_insensitive_index as usize) {
            return Ok(candidate);
        }
    }
    Ok(0)
}
