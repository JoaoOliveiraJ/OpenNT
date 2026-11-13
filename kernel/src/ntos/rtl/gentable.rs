//! Splay links e tabelas genéricas (RTL_GENERIC_TABLE) — o splay e o
//! gentable do NT.
//!
//! RTL_SPLAY_LINKS { Parent, LeftChild, RightChild } tem 0x18 bytes; a raiz
//! aponta para si no Parent. Cada elemento da tabela é alocado pela
//! AllocateRoutine do chamador com os splay links, o LIST_ENTRY da ordem de
//! inserção e os dados (+0x28); a FreeRoutine recebe o mesmo ponteiro. A
//! busca e a enumeração em ordem sobem o elemento achado para a raiz, e
//! RtlGetElementGenericTable segue a ordem de inserção.

use crate::hal::amd64::native_call;
use crate::ntos::mm::guest_memory as guest;
use super::avltable::{EMPTY_TREE, FOUND_NODE, GREATER_THAN, INSERT_AS_LEFT, INSERT_AS_RIGHT, LESS_THAN};

const PARENT: u64 = 0x00;
const LEFT: u64 = 0x08;
const RIGHT: u64 = 0x10;

/// Offsets do RTL_GENERIC_TABLE.
pub mod table {
    pub const TABLE_ROOT: u64 = 0x00;
    pub const INSERT_ORDER_LIST: u64 = 0x08;
    pub const ORDERED_POINTER: u64 = 0x18;
    pub const WHICH_ORDERED_ELEMENT: u64 = 0x20;
    pub const NUMBER_ELEMENTS: u64 = 0x24;
    pub const COMPARE_ROUTINE: u64 = 0x28;
    pub const ALLOCATE_ROUTINE: u64 = 0x30;
    pub const FREE_ROUTINE: u64 = 0x38;
    pub const TABLE_CONTEXT: u64 = 0x40;
    pub const SIZE: u64 = 0x48;
}

/// O LIST_ENTRY da ordem de inserção e os dados, depois dos splay links.
const LIST_ENTRY: u64 = 0x18;
pub const USER_DATA: u64 = 0x28;

fn parent(node: u64) -> u64 {
    guest::read64(node + PARENT)
}
fn left(node: u64) -> u64 {
    guest::read64(node + LEFT)
}
fn right(node: u64) -> u64 {
    guest::read64(node + RIGHT)
}
fn set_parent(node: u64, value: u64) {
    guest::write64(node + PARENT, value);
}
fn set_left(node: u64, value: u64) {
    guest::write64(node + LEFT, value);
}
fn set_right(node: u64, value: u64) {
    guest::write64(node + RIGHT, value);
}
fn is_root(node: u64) -> bool {
    parent(node) == node
}
fn is_left_child(node: u64) -> bool {
    !is_root(node) && left(parent(node)) == node
}
fn is_right_child(node: u64) -> bool {
    !is_root(node) && right(parent(node)) == node
}

/// Troca o filho `old` de `up` por `new` (ou faz de `new` a raiz).
fn replace_child(up: u64, old: u64, new: u64, old_was_root: bool) {
    if old_was_root {
        set_parent(new, new);
    } else {
        set_parent(new, up);
        if left(up) == old {
            set_left(up, new);
        } else {
            set_right(up, new);
        }
    }
}

fn rotate_right(node: u64) {
    let (pivot, up, root) = (left(node), parent(node), is_root(node));
    let inner = right(pivot);
    set_left(node, inner);
    if inner != 0 {
        set_parent(inner, node);
    }
    set_right(pivot, node);
    replace_child(up, node, pivot, root);
    set_parent(node, pivot);
}

fn rotate_left(node: u64) {
    let (pivot, up, root) = (right(node), parent(node), is_root(node));
    let inner = left(pivot);
    set_right(node, inner);
    if inner != 0 {
        set_parent(inner, node);
    }
    set_left(pivot, node);
    replace_child(up, node, pivot, root);
    set_parent(node, pivot);
}

/// RtlSplay: sobe o nó até a raiz (zig, zig-zig, zig-zag) e o devolve.
pub fn splay(node: u64) -> u64 {
    while !is_root(node) {
        let up = parent(node);
        if is_root(up) {
            if left(up) == node { rotate_right(up) } else { rotate_left(up) }
            continue;
        }
        let grand = parent(up);
        match (left(up) == node, left(grand) == up) {
            (true, true) => {
                rotate_right(grand);
                rotate_right(up);
            }
            (false, false) => {
                rotate_left(grand);
                rotate_left(up);
            }
            (true, false) => {
                rotate_right(up);
                rotate_left(grand);
            }
            (false, true) => {
                rotate_left(up);
                rotate_right(grand);
            }
        }
    }
    node
}

/// RtlSubtreeSuccessor.
pub fn subtree_successor(node: u64) -> u64 {
    match right(node) {
        0 => 0,
        mut next => {
            while left(next) != 0 {
                next = left(next);
            }
            next
        }
    }
}

/// RtlSubtreePredecessor.
pub fn subtree_predecessor(node: u64) -> u64 {
    match left(node) {
        0 => 0,
        mut previous => {
            while right(previous) != 0 {
                previous = right(previous);
            }
            previous
        }
    }
}

/// RtlRealSuccessor: sucessor em ordem na árvore inteira.
pub fn real_successor(node: u64) -> u64 {
    let next = subtree_successor(node);
    if next != 0 {
        return next;
    }
    let mut current = node;
    while is_right_child(current) {
        current = parent(current);
    }
    if is_left_child(current) { parent(current) } else { 0 }
}

/// RtlRealPredecessor.
pub fn real_predecessor(node: u64) -> u64 {
    let previous = subtree_predecessor(node);
    if previous != 0 {
        return previous;
    }
    let mut current = node;
    while is_left_child(current) {
        current = parent(current);
    }
    if is_right_child(current) { parent(current) } else { 0 }
}

/// Troca o nó (com dois filhos) pelo predecessor, sem mexer nos dados.
fn swap_with_predecessor(node: u64, previous: u64) {
    let (up, node_left, node_right, node_root) = (parent(node), left(node), right(node), is_root(node));
    let (previous_parent, previous_left) = (parent(previous), left(previous));
    replace_child(up, node, previous, node_root);
    set_right(previous, node_right);
    set_parent(node_right, previous);
    if previous_parent == node {
        set_left(previous, node);
        set_parent(node, previous);
    } else {
        set_left(previous, node_left);
        set_parent(node_left, previous);
        set_right(previous_parent, node);
        set_parent(node, previous_parent);
    }
    set_left(node, previous_left);
    if previous_left != 0 {
        set_parent(previous_left, node);
    }
    set_right(node, 0);
}

/// Tira o nó da árvore: (raiz nova se ele era a raiz, nó de onde subir).
fn detach(node: u64) -> (Option<u64>, u64) {
    if left(node) != 0 && right(node) != 0 {
        swap_with_predecessor(node, subtree_predecessor(node));
    }
    let child = if left(node) != 0 { left(node) } else { right(node) };
    if is_root(node) {
        if child != 0 {
            set_parent(child, child);
        }
        return (Some(child), 0);
    }
    let up = parent(node);
    if left(up) == node {
        set_left(up, child);
    } else {
        set_right(up, child);
    }
    if child != 0 {
        set_parent(child, up);
    }
    (None, up)
}

/// RtlDelete: tira o nó e sobe o pai para a raiz; devolve a raiz nova.
pub fn delete(node: u64) -> u64 {
    match detach(node) {
        (Some(root), _) => root,
        (None, up) => splay(up),
    }
}

/// RtlDeleteNoSplay: tira o nó sem reorganizar; a raiz muda só se era ele.
pub fn delete_no_splay(node: u64, root: u64) {
    if let (Some(new_root), _) = detach(node) {
        guest::write64(root, new_root);
    }
}

// ---- RTL_GENERIC_TABLE --------------------------------------------------

fn root(table: u64) -> u64 {
    guest::read64(table + table::TABLE_ROOT)
}

fn set_root(table: u64, node: u64) {
    guest::write64(table + table::TABLE_ROOT, node);
}

pub fn number(table: u64) -> u32 {
    guest::read32(table + table::NUMBER_ELEMENTS)
}

pub fn is_empty(table: u64) -> bool {
    root(table) == 0
}

fn reset_order_cache(table: u64) {
    guest::write64(table + table::ORDERED_POINTER, table + table::INSERT_ORDER_LIST);
    guest::write32(table + table::WHICH_ORDERED_ELEMENT, 0);
}

/// RtlInitializeGenericTable.
pub fn initialize(table: u64, compare: u64, allocate: u64, free: u64, context: u64) {
    guest::write_bytes(table, &[0; table::SIZE as usize]);
    let list = table + table::INSERT_ORDER_LIST;
    guest::write64(list, list);
    guest::write64(list + 8, list);
    reset_order_cache(table);
    guest::write64(table + table::COMPARE_ROUTINE, compare);
    guest::write64(table + table::ALLOCATE_ROUTINE, allocate);
    guest::write64(table + table::FREE_ROUTINE, free);
    guest::write64(table + table::TABLE_CONTEXT, context);
}

fn compare(table: u64, buffer: u64, node: u64) -> u64 {
    native_call::call(guest::read64(table + table::COMPARE_ROUTINE), &[table, buffer, node + USER_DATA]) & 0xFFFF_FFFF
}

/// Busca sem reorganizar: (resultado, nó ou pai do ponto de inserção).
pub fn find(table: u64, buffer: u64) -> (u32, u64) {
    let mut node = root(table);
    if node == 0 {
        return (EMPTY_TREE, 0);
    }
    loop {
        match compare(table, buffer, node) {
            LESS_THAN => match left(node) {
                0 => return (INSERT_AS_LEFT, node),
                child => node = child,
            },
            GREATER_THAN => match right(node) {
                0 => return (INSERT_AS_RIGHT, node),
                child => node = child,
            },
            _ => return (FOUND_NODE, node),
        }
    }
}

/// RtlInsertElementGenericTableFull.
pub fn insert_full(table: u64, buffer: u64, size: u32, new_element: u64, node_or_parent: u64, result: u32) -> u64 {
    if result == FOUND_NODE {
        set_root(table, splay(node_or_parent));
        if new_element != 0 {
            guest::write8(new_element, 0);
        }
        return node_or_parent + USER_DATA;
    }
    let node = native_call::call(guest::read64(table + table::ALLOCATE_ROUTINE), &[table, size as u64 + USER_DATA]);
    if node == 0 {
        if new_element != 0 {
            guest::write8(new_element, 0);
        }
        return 0;
    }
    guest::write_bytes(node, &[0; USER_DATA as usize]);
    set_parent(node, node);
    if size != 0 && buffer != 0 {
        guest::write_bytes(node + USER_DATA, &guest::read_bytes(buffer, size as usize));
    }
    match result {
        INSERT_AS_LEFT => {
            set_parent(node, node_or_parent);
            set_left(node_or_parent, node);
        }
        INSERT_AS_RIGHT => {
            set_parent(node, node_or_parent);
            set_right(node_or_parent, node);
        }
        _ => {}
    }
    // InsertTailList na ordem de inserção.
    let list = table + table::INSERT_ORDER_LIST;
    let entry = node + LIST_ENTRY;
    let tail = guest::read64(list + 8);
    guest::write64(entry, list);
    guest::write64(entry + 8, tail);
    guest::write64(tail, entry);
    guest::write64(list + 8, entry);
    guest::write32(table + table::NUMBER_ELEMENTS, number(table) + 1);
    set_root(table, splay(node));
    if new_element != 0 {
        guest::write8(new_element, 1);
    }
    node + USER_DATA
}

/// RtlInsertElementGenericTable.
pub fn insert(table: u64, buffer: u64, size: u32, new_element: u64) -> u64 {
    let (result, at) = find(table, buffer);
    insert_full(table, buffer, size, new_element, at, result)
}

/// RtlLookupElementGenericTableFull: sem reorganizar.
pub fn lookup_full(table: u64, buffer: u64, node_or_parent: u64, search_result: u64) -> u64 {
    let (result, at) = find(table, buffer);
    guest::write64(node_or_parent, at);
    guest::write32(search_result, result);
    if result == FOUND_NODE { at + USER_DATA } else { 0 }
}

/// RtlLookupElementGenericTable: o achado vira a raiz.
pub fn lookup(table: u64, buffer: u64) -> u64 {
    match find(table, buffer) {
        (FOUND_NODE, node) => {
            set_root(table, splay(node));
            node + USER_DATA
        }
        _ => 0,
    }
}

/// RtlDeleteElementGenericTable.
pub fn delete_element(table: u64, buffer: u64) -> bool {
    let (FOUND_NODE, node) = find(table, buffer) else { return false };
    set_root(table, delete(node));
    // RemoveEntryList da ordem de inserção.
    let entry = node + LIST_ENTRY;
    let (next, previous) = (guest::read64(entry), guest::read64(entry + 8));
    guest::write64(previous, next);
    guest::write64(next + 8, previous);
    guest::write32(table + table::NUMBER_ELEMENTS, number(table).saturating_sub(1));
    reset_order_cache(table);
    native_call::call(guest::read64(table + table::FREE_ROUTINE), &[table, node]);
    true
}

fn leftmost(mut node: u64) -> u64 {
    while left(node) != 0 {
        node = left(node);
    }
    node
}

/// RtlEnumerateGenericTable: em ordem, com o último devolvido na raiz.
pub fn enumerate(table: u64, restart: bool) -> u64 {
    let current = root(table);
    if current == 0 {
        return 0;
    }
    let node = if restart { leftmost(current) } else { real_successor(current) };
    if node == 0 {
        return 0;
    }
    set_root(table, splay(node));
    node + USER_DATA
}

/// RtlEnumerateGenericTableWithoutSplaying: a chave guarda o último nó.
pub fn enumerate_without_splaying(table: u64, restart_key: u64) -> u64 {
    let previous = guest::read64(restart_key);
    let node = if previous == 0 {
        match root(table) {
            0 => 0,
            current => leftmost(current),
        }
    } else {
        real_successor(previous)
    };
    guest::write64(restart_key, node);
    if node == 0 { 0 } else { node + USER_DATA }
}

/// RtlGetElementGenericTable: o I-ésimo na ordem de inserção, a partir do
/// último achado (OrderedPointer/WhichOrderedElement) quando ele vem antes.
pub fn get_element(table: u64, index: u32) -> u64 {
    if index == u32::MAX || index >= number(table) {
        return 0;
    }
    let wanted = index + 1;
    let list = table + table::INSERT_ORDER_LIST;
    let cached = guest::read32(table + table::WHICH_ORDERED_ELEMENT);
    let (mut entry, mut position) = if cached != 0 && cached <= wanted {
        (guest::read64(table + table::ORDERED_POINTER), cached)
    } else {
        (list, 0)
    };
    while position < wanted {
        entry = guest::read64(entry);
        position += 1;
    }
    guest::write64(table + table::ORDERED_POINTER, entry);
    guest::write32(table + table::WHICH_ORDERED_ELEMENT, wanted);
    entry - LIST_ENTRY + USER_DATA
}
