//! Splay links e tabelas genéricas (RTL_GENERIC_TABLE) — o splay e o
//! gentable do NT.
//!
//! RTL_SPLAY_LINKS { Parent, LeftChild, RightChild } tem 0x18 bytes; a raiz
//! aponta para si no Parent. Cada elemento da tabela é alocado pela
//! AllocateRoutine do chamador com os splay links, o LIST_ENTRY da ordem de
//! inserção e os dados (+0x28); a FreeRoutine recebe o mesmo ponteiro. A
//! busca e a enumeração em ordem sobem o elemento achado para a raiz, e
//! RtlGetElementGenericTable segue a ordem de inserção.

use core::mem::{offset_of, size_of};

use super::avltable::{EMPTY_TREE, FOUND_NODE, GREATER_THAN, INSERT_AS_LEFT, INSERT_AS_RIGHT, LESS_THAN};
use crate::hal::amd64::native_call;
use crate::ntos::inc::types::{Field, ListEntry, NtStruct, RtlGenericTable, RtlSplayLinks};
use crate::ntos::mm::guest_memory as guest;

/// Cabeçalho de cada elemento (o TABLE_ENTRY_HEADER privado do gentable):
/// os splay links, o LIST_ENTRY da ordem de inserção e então os dados.
#[repr(C)]
struct TableEntryHeader {
    splay_links: RtlSplayLinks,
    list_entry: ListEntry,
}

// SAFETY: #[repr(C)] só de estruturas de células.
unsafe impl NtStruct for TableEntryHeader {}

const _: () = {
    assert!(size_of::<TableEntryHeader>() == 0x28);
    assert!(offset_of!(TableEntryHeader, list_entry) == 0x18);
};

/// Deslocamento do LIST_ENTRY e dos dados do usuário no elemento.
const LIST_ENTRY: u64 = offset_of!(TableEntryHeader, list_entry) as u64;
pub const USER_DATA: u64 = TableEntryHeader::SIZE;

/// PRTL_SPLAY_LINKS: nós vivos da árvore do chamador.
fn links(node: u64) -> &'static RtlSplayLinks {
    // SAFETY: nó vivo e alinhado (alocado pelo chamador ou pela tabela).
    unsafe { RtlSplayLinks::at(node) }
}
fn parent(node: u64) -> u64 {
    links(node).parent.get()
}
fn left(node: u64) -> u64 {
    links(node).left_child.get()
}
fn right(node: u64) -> u64 {
    links(node).right_child.get()
}
fn set_parent(node: u64, value: u64) {
    links(node).parent.set(value);
}
fn set_left(node: u64, value: u64) {
    links(node).left_child.set(value);
}
fn set_right(node: u64, value: u64) {
    links(node).right_child.set(value);
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
        // SAFETY: PRTL_SPLAY_LINKS* Root do chamador.
        unsafe { Field::<u64>::at(root) }.set(new_root);
    }
}

// ---- RTL_GENERIC_TABLE --------------------------------------------------

/// PRTL_GENERIC_TABLE do chamador.
fn generic(table: u64) -> &'static RtlGenericTable {
    // SAFETY: tabela viva e alinhada, inicializada pelo RtlInitializeGenericTable.
    unsafe { RtlGenericTable::at(table) }
}

/// O cabeçalho do elemento `node`.
fn header(node: u64) -> &'static TableEntryHeader {
    // SAFETY: elemento vivo alocado pela AllocateRoutine da tabela.
    unsafe { TableEntryHeader::at(node) }
}

/// Parâmetro de saída escalar do chamador (PBOOLEAN, PVOID*, enum...).
fn out<T: Copy>(address: u64) -> &'static Field<T> {
    // SAFETY: ponteiro de saída do chamador, vivo e alinhado.
    unsafe { Field::<T>::at(address) }
}

pub fn number(table: u64) -> u32 {
    generic(table).number_generic_table_elements.get()
}

pub fn is_empty(table: u64) -> bool {
    generic(table).table_root.get() == 0
}

fn reset_order_cache(table: &RtlGenericTable) {
    table.ordered_pointer.set(table.insert_order_list.address());
    table.which_ordered_element.set(0);
}

/// RtlInitializeGenericTable.
pub fn initialize(table: u64, compare: u64, allocate: u64, free: u64, context: u64) {
    guest::write_bytes(table, &[0; size_of::<RtlGenericTable>()]);
    let table = generic(table);
    let list = &table.insert_order_list;
    list.flink.set(list.address());
    list.blink.set(list.address());
    reset_order_cache(table);
    table.compare_routine.set(compare);
    table.allocate_routine.set(allocate);
    table.free_routine.set(free);
    table.table_context.set(context);
}

fn compare(table: &RtlGenericTable, buffer: u64, node: u64) -> u64 {
    native_call::call(table.compare_routine.get(), &[table.address(), buffer, node + USER_DATA]) & 0xFFFF_FFFF
}

/// Busca sem reorganizar: (resultado, nó ou pai do ponto de inserção).
pub fn find(table: u64, buffer: u64) -> (u32, u64) {
    let table = generic(table);
    let mut node = table.table_root.get();
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
    let table = generic(table);
    if result == FOUND_NODE {
        table.table_root.set(splay(node_or_parent));
        if new_element != 0 {
            out::<u8>(new_element).set(0);
        }
        return node_or_parent + USER_DATA;
    }
    let node = native_call::call(table.allocate_routine.get(), &[table.address(), size as u64 + USER_DATA]);
    if node == 0 {
        if new_element != 0 {
            out::<u8>(new_element).set(0);
        }
        return 0;
    }
    guest::write_bytes(node, &[0; size_of::<TableEntryHeader>()]);
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
    let list = &table.insert_order_list;
    let entry = &header(node).list_entry;
    let tail = list.blink.get();
    entry.flink.set(list.address());
    entry.blink.set(tail);
    // SAFETY: o último LIST_ENTRY da ordem de inserção (ou a própria cabeça).
    unsafe { ListEntry::at(tail) }.flink.set(entry.address());
    list.blink.set(entry.address());
    let count = &table.number_generic_table_elements;
    count.set(count.get() + 1);
    table.table_root.set(splay(node));
    if new_element != 0 {
        out::<u8>(new_element).set(1);
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
    out::<u64>(node_or_parent).set(at);
    out::<u32>(search_result).set(result);
    if result == FOUND_NODE { at + USER_DATA } else { 0 }
}

/// RtlLookupElementGenericTable: o achado vira a raiz.
pub fn lookup(table: u64, buffer: u64) -> u64 {
    match find(table, buffer) {
        (FOUND_NODE, node) => {
            generic(table).table_root.set(splay(node));
            node + USER_DATA
        }
        _ => 0,
    }
}

/// RtlDeleteElementGenericTable.
pub fn delete_element(address: u64, buffer: u64) -> bool {
    let (FOUND_NODE, node) = find(address, buffer) else { return false };
    let table = generic(address);
    table.table_root.set(delete(node));
    // RemoveEntryList da ordem de inserção.
    let entry = &header(node).list_entry;
    let (next, previous) = (entry.flink.get(), entry.blink.get());
    // SAFETY: vizinhos vivos na lista da ordem de inserção.
    unsafe {
        ListEntry::at(previous).flink.set(next);
        ListEntry::at(next).blink.set(previous);
    }
    let count = &table.number_generic_table_elements;
    count.set(count.get().saturating_sub(1));
    reset_order_cache(table);
    native_call::call(table.free_routine.get(), &[address, node]);
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
    let table = generic(table);
    let current = table.table_root.get();
    if current == 0 {
        return 0;
    }
    let node = if restart { leftmost(current) } else { real_successor(current) };
    if node == 0 {
        return 0;
    }
    table.table_root.set(splay(node));
    node + USER_DATA
}

/// RtlEnumerateGenericTableWithoutSplaying: a chave guarda o último nó.
pub fn enumerate_without_splaying(table: u64, restart_key: u64) -> u64 {
    let key = out::<u64>(restart_key);
    let previous = key.get();
    let node = if previous == 0 {
        match generic(table).table_root.get() {
            0 => 0,
            current => leftmost(current),
        }
    } else {
        real_successor(previous)
    };
    key.set(node);
    if node == 0 { 0 } else { node + USER_DATA }
}

/// RtlGetElementGenericTable: o I-ésimo na ordem de inserção, a partir do
/// último achado (OrderedPointer/WhichOrderedElement) quando ele vem antes.
pub fn get_element(table: u64, index: u32) -> u64 {
    let table = generic(table);
    if index == u32::MAX || index >= table.number_generic_table_elements.get() {
        return 0;
    }
    let wanted = index + 1;
    let cached = table.which_ordered_element.get();
    let (mut entry, mut position) = if cached != 0 && cached <= wanted {
        (table.ordered_pointer.get(), cached)
    } else {
        (table.insert_order_list.address(), 0)
    };
    while position < wanted {
        // SAFETY: LIST_ENTRY vivo da ordem de inserção.
        entry = unsafe { ListEntry::at(entry) }.flink.get();
        position += 1;
    }
    table.ordered_pointer.set(entry);
    table.which_ordered_element.set(wanted);
    entry - LIST_ENTRY + USER_DATA
}

