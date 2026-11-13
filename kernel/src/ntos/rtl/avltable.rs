//! Tabelas genéricas AVL (RTL_AVL_TABLE) — o avltable do NT.
//!
//! Layout x64 do WDK. RTL_BALANCED_LINKS { Parent, LeftChild, RightChild,
//! Balance (CHAR), Reserved[3] } tem 0x20 bytes; o BalancedRoot da tabela é
//! uma sentinela cujo Parent aponta para si e cujo RightChild é a raiz de
//! verdade. Cada elemento é alocado pela AllocateRoutine do chamador com os
//! links seguidos dos dados (+0x20), e a FreeRoutine recebe o mesmo ponteiro.
//! Balance = altura da direita - altura da esquerda. A remoção troca nós de
//! lugar (nunca copia dados): o ponteiro devolvido para um elemento continua
//! válido até ele sair da tabela.

use core::mem::size_of;

use crate::hal::amd64::native_call;
use crate::ntos::inc::types::{Field, NtStruct, RtlAvlTable, RtlBalancedLinks};
use crate::ntos::mm::guest_memory as guest;

/// Os dados do usuário depois do RTL_BALANCED_LINKS (TABLE_ENTRY_HEADER).
pub const USER_DATA: u64 = RtlBalancedLinks::SIZE;

/// RTL_GENERIC_COMPARE_RESULTS.
pub const LESS_THAN: u64 = 0;
pub const GREATER_THAN: u64 = 1;
pub const EQUAL: u64 = 2;

/// TABLE_SEARCH_RESULT.
pub const EMPTY_TREE: u32 = 0;
pub const FOUND_NODE: u32 = 1;
pub const INSERT_AS_LEFT: u32 = 2;
pub const INSERT_AS_RIGHT: u32 = 3;

const STATUS_NO_MATCH: u32 = 0xC000_0272;
const STATUS_NO_MORE_MATCHES: u32 = 0xC000_0273;

/// PRTL_BALANCED_LINKS: nós vivos da árvore (a sentinela é o BalancedRoot).
fn links(node: u64) -> &'static RtlBalancedLinks {
    // SAFETY: nó vivo e alinhado (elemento da tabela ou a sentinela).
    unsafe { RtlBalancedLinks::at(node) }
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
fn balance(node: u64) -> i8 {
    links(node).balance.get()
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
fn set_balance(node: u64, value: i8) {
    links(node).balance.set(value);
}

/// PRTL_AVL_TABLE do chamador.
fn avl(table: u64) -> &'static RtlAvlTable {
    // SAFETY: tabela viva e alinhada, inicializada pelo RtlInitializeGenericTableAvl.
    unsafe { RtlAvlTable::at(table) }
}

/// A sentinela BalancedRoot (Parent aponta para si; RightChild é a raiz).
fn sentinel_of(table: u64) -> u64 {
    avl(table).balanced_root.address()
}

/// Parâmetro escalar do chamador (PBOOLEAN, PVOID*, PULONG...).
fn out<T: Copy>(address: u64) -> &'static Field<T> {
    // SAFETY: ponteiro do chamador, vivo e alinhado.
    unsafe { Field::<T>::at(address) }
}

fn root(table: u64) -> u64 {
    right(sentinel_of(table))
}

pub fn number(table: u64) -> u32 {
    avl(table).number_generic_table_elements.get()
}

pub fn is_empty(table: u64) -> bool {
    root(table) == 0
}

/// RtlInitializeGenericTableAvl.
pub fn initialize(table: u64, compare: u64, allocate: u64, free: u64, context: u64) {
    guest::write_bytes(table, &[0; size_of::<RtlAvlTable>()]);
    set_parent(sentinel_of(table), sentinel_of(table));
    let avl = avl(table);
    avl.compare_routine.set(compare);
    avl.allocate_routine.set(allocate);
    avl.free_routine.set(free);
    avl.table_context.set(context);
}

fn compare(table: u64, buffer: u64, node: u64) -> u64 {
    native_call::call(avl(table).compare_routine.get(), &[table, buffer, node + USER_DATA]) & 0xFFFF_FFFF
}

/// Busca: (resultado, nó encontrado ou pai do ponto de inserção).
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

fn leftmost(mut node: u64) -> u64 {
    while left(node) != 0 {
        node = left(node);
    }
    node
}

fn rightmost(mut node: u64) -> u64 {
    while right(node) != 0 {
        node = right(node);
    }
    node
}

fn first(table: u64) -> u64 {
    match root(table) {
        0 => 0,
        node => leftmost(node),
    }
}

/// Sucessor em ordem (0 no último).
pub fn successor(table: u64, node: u64) -> u64 {
    if right(node) != 0 {
        return leftmost(right(node));
    }
    let sentinel = sentinel_of(table);
    let (mut child, mut up) = (node, parent(node));
    while up != sentinel && right(up) == child {
        child = up;
        up = parent(up);
    }
    if up == sentinel { 0 } else { up }
}

/// Predecessor em ordem (0 no primeiro).
pub fn predecessor(table: u64, node: u64) -> u64 {
    if left(node) != 0 {
        return rightmost(left(node));
    }
    let sentinel = sentinel_of(table);
    let (mut child, mut up) = (node, parent(node));
    while up != sentinel && left(up) == child {
        child = up;
        up = parent(up);
    }
    if up == sentinel { 0 } else { up }
}

fn replace_child(table: u64, up: u64, old: u64, new: u64) {
    let sentinel = sentinel_of(table);
    if up == sentinel || right(up) == old {
        set_right(up, new);
    } else {
        set_left(up, new);
    }
}

fn rotate_left(table: u64, node: u64) -> u64 {
    let (pivot, up) = (right(node), parent(node));
    let inner = left(pivot);
    set_right(node, inner);
    if inner != 0 {
        set_parent(inner, node);
    }
    set_left(pivot, node);
    set_parent(node, pivot);
    set_parent(pivot, up);
    replace_child(table, up, node, pivot);
    pivot
}

fn rotate_right(table: u64, node: u64) -> u64 {
    let (pivot, up) = (left(node), parent(node));
    let inner = right(pivot);
    set_left(node, inner);
    if inner != 0 {
        set_parent(inner, node);
    }
    set_right(pivot, node);
    set_parent(node, pivot);
    set_parent(pivot, up);
    replace_child(table, up, node, pivot);
    pivot
}

/// Reequilibra um nó com |Balance| == 2: (nova raiz da subárvore, se a
/// altura da subárvore caiu).
fn rebalance(table: u64, node: u64) -> (u64, bool) {
    if balance(node) > 0 {
        let child = right(node);
        let child_balance = balance(child);
        if child_balance >= 0 {
            let top = rotate_left(table, node);
            if child_balance == 0 {
                set_balance(node, 1);
                set_balance(child, -1);
            } else {
                set_balance(node, 0);
                set_balance(child, 0);
            }
            (top, child_balance != 0)
        } else {
            let grandchild = left(child);
            let grandchild_balance = balance(grandchild);
            rotate_right(table, child);
            let top = rotate_left(table, node);
            set_balance(node, if grandchild_balance == 1 { -1 } else { 0 });
            set_balance(child, if grandchild_balance == -1 { 1 } else { 0 });
            set_balance(grandchild, 0);
            (top, true)
        }
    } else {
        let child = left(node);
        let child_balance = balance(child);
        if child_balance <= 0 {
            let top = rotate_right(table, node);
            if child_balance == 0 {
                set_balance(node, -1);
                set_balance(child, 1);
            } else {
                set_balance(node, 0);
                set_balance(child, 0);
            }
            (top, child_balance != 0)
        } else {
            let grandchild = right(child);
            let grandchild_balance = balance(grandchild);
            rotate_left(table, child);
            let top = rotate_right(table, node);
            set_balance(node, if grandchild_balance == -1 { 1 } else { 0 });
            set_balance(child, if grandchild_balance == 1 { -1 } else { 0 });
            set_balance(grandchild, 0);
            (top, true)
        }
    }
}

fn changed(table: u64) {
    avl(table).ordered_pointer.set(0);
    avl(table).which_ordered_element.set(0);
}

fn link(table: u64, node: u64, result: u32, at: u64) {
    let sentinel = sentinel_of(table);
    set_left(node, 0);
    set_right(node, 0);
    set_balance(node, 0);
    match result {
        INSERT_AS_LEFT => {
            set_parent(node, at);
            set_left(at, node);
        }
        INSERT_AS_RIGHT => {
            set_parent(node, at);
            set_right(at, node);
        }
        _ => {
            set_parent(node, sentinel);
            set_right(sentinel, node);
        }
    }
    avl(table).number_generic_table_elements.set(number(table) + 1);
    changed(table);
    let (mut child, mut up) = (node, parent(node));
    while up != sentinel {
        let value = balance(up) + if left(up) == child { -1 } else { 1 };
        set_balance(up, value);
        if value == 0 {
            break;
        }
        if value.abs() == 1 {
            child = up;
            up = parent(up);
            continue;
        }
        rebalance(table, up);
        break;
    }
}

/// Troca o nó (com dois filhos) pelo sucessor, sem mexer nos dados.
fn swap_with_successor(table: u64, node: u64, next: u64) {
    let (up, node_left, node_right, node_balance) = (parent(node), left(node), right(node), balance(node));
    let (next_parent, next_right, next_balance) = (parent(next), right(next), balance(next));
    replace_child(table, up, node, next);
    set_parent(next, up);
    set_left(next, node_left);
    set_parent(node_left, next);
    set_balance(next, node_balance);
    if next_parent == node {
        set_right(next, node);
        set_parent(node, next);
    } else {
        set_right(next, node_right);
        set_parent(node_right, next);
        set_left(next_parent, node);
        set_parent(node, next_parent);
    }
    set_left(node, 0);
    set_right(node, next_right);
    if next_right != 0 {
        set_parent(next_right, node);
    }
    set_balance(node, next_balance);
}

/// Tira o nó da árvore e reequilibra; não libera a memória.
fn unlink(table: u64, node: u64) {
    let sentinel = sentinel_of(table);
    if left(node) != 0 && right(node) != 0 {
        swap_with_successor(table, node, leftmost(right(node)));
    }
    let child = if left(node) != 0 { left(node) } else { right(node) };
    let up = parent(node);
    let mut from_left = up != sentinel && left(up) == node;
    replace_child(table, up, node, child);
    if child != 0 {
        set_parent(child, up);
    }
    let avl = avl(table);
    avl.number_generic_table_elements.set(number(table).saturating_sub(1));
    avl.delete_count.set(avl.delete_count.get().wrapping_add(1));
    changed(table);
    let mut up = up;
    while up != sentinel {
        let value = balance(up) + if from_left { 1 } else { -1 };
        set_balance(up, value);
        if value.abs() == 1 {
            break;
        }
        let mut top = up;
        if value.abs() == 2 {
            let (new_top, dropped) = rebalance(table, up);
            if !dropped {
                break;
            }
            top = new_top;
        }
        let above = parent(top);
        from_left = above != sentinel && left(above) == top;
        up = above;
    }
}

fn free(table: u64, node: u64) {
    native_call::call(avl(table).free_routine.get(), &[table, node]);
}

/// RtlInsertElementGenericTableFullAvl: com o resultado de uma busca anterior.
pub fn insert_full(table: u64, buffer: u64, size: u32, new_element: u64, node_or_parent: u64, result: u32) -> u64 {
    if result == FOUND_NODE {
        if new_element != 0 {
            out::<u8>(new_element).set(0);
        }
        return node_or_parent + USER_DATA;
    }
    let node = native_call::call(avl(table).allocate_routine.get(), &[table, size as u64 + USER_DATA]);
    if node == 0 {
        if new_element != 0 {
            out::<u8>(new_element).set(0);
        }
        return 0;
    }
    guest::write_bytes(node, &[0; size_of::<RtlBalancedLinks>()]);
    if size != 0 && buffer != 0 {
        guest::write_bytes(node + USER_DATA, &guest::read_bytes(buffer, size as usize));
    }
    link(table, node, result, node_or_parent);
    if new_element != 0 {
        out::<u8>(new_element).set(1);
    }
    node + USER_DATA
}

/// RtlInsertElementGenericTableAvl.
pub fn insert(table: u64, buffer: u64, size: u32, new_element: u64) -> u64 {
    let (result, at) = find(table, buffer);
    insert_full(table, buffer, size, new_element, at, result)
}

/// RtlLookupElementGenericTableFullAvl.
pub fn lookup_full(table: u64, buffer: u64, node_or_parent: u64, search_result: u64) -> u64 {
    let (result, at) = find(table, buffer);
    out::<u64>(node_or_parent).set(at);
    out::<u32>(search_result).set(result);
    if result == FOUND_NODE { at + USER_DATA } else { 0 }
}

/// RtlLookupElementGenericTableAvl.
pub fn lookup(table: u64, buffer: u64) -> u64 {
    match find(table, buffer) {
        (FOUND_NODE, node) => node + USER_DATA,
        _ => 0,
    }
}

/// RtlDeleteElementGenericTableAvl.
pub fn delete(table: u64, buffer: u64) -> bool {
    match find(table, buffer) {
        (FOUND_NODE, node) => {
            unlink(table, node);
            free(table, node);
            true
        }
        _ => false,
    }
}

/// RtlDeleteElementGenericTableAvlEx: o nó devolvido pela busca completa.
pub fn delete_node(table: u64, node: u64) {
    unlink(table, node);
    free(table, node);
}

/// RtlEnumerateGenericTableWithoutSplayingAvl: a chave guarda o último nó.
pub fn enumerate_without_splaying(table: u64, restart_key: u64) -> u64 {
    let key = out::<u64>(restart_key);
    let previous = key.get();
    let node = if previous == 0 { first(table) } else { successor(table, previous) };
    key.set(node);
    if node == 0 { 0 } else { node + USER_DATA }
}

/// RtlEnumerateGenericTableAvl: a chave fica no RestartKey da tabela.
pub fn enumerate(table: u64, restart: bool) -> u64 {
    if restart {
        avl(table).restart_key.set(0);
    }
    enumerate_without_splaying(table, avl(table).restart_key.address())
}

/// RtlGetElementGenericTableAvl: o I-ésimo em ordem (OrderedPointer guarda o
/// último nó achado e WhichOrderedElement a sua posição, a partir de 1).
pub fn get_element(table: u64, index: u32) -> u64 {
    if index == u32::MAX || index >= number(table) {
        return 0;
    }
    let wanted = index + 1;
    let cached = avl(table).which_ordered_element.get();
    let (mut node, mut position) = if cached != 0 && cached <= wanted {
        (avl(table).ordered_pointer.get(), cached)
    } else {
        (first(table), 1)
    };
    while position < wanted && node != 0 {
        node = successor(table, node);
        position += 1;
    }
    if node == 0 {
        return 0;
    }
    avl(table).ordered_pointer.set(node);
    avl(table).which_ordered_element.set(wanted);
    node + USER_DATA
}

/// RtlLookupFirstMatchingElementGenericTableAvl: o primeiro (em ordem) que a
/// comparação dá como igual; a chave permite continuar a enumeração.
pub fn lookup_first_matching(table: u64, buffer: u64, restart_key: u64) -> u64 {
    let (result, mut node) = find(table, buffer);
    if result != FOUND_NODE {
        out::<u64>(restart_key).set(0);
        return 0;
    }
    loop {
        let previous = predecessor(table, node);
        if previous == 0 || compare(table, buffer, previous) != EQUAL {
            break;
        }
        node = previous;
    }
    out::<u64>(restart_key).set(node);
    node + USER_DATA
}

/// RtlEnumerateGenericTableLikeADirectory: em ordem a partir da chave dada
/// (ou da posição salva, se nada foi apagado desde então), pulando quem a
/// MatchFunction recusa com STATUS_NO_MATCH e parando em
/// STATUS_NO_MORE_MATCHES.
#[allow(clippy::too_many_arguments)]
pub fn enumerate_like_a_directory(table: u64, match_function: u64, match_data: u64, next_flag: bool, restart_key: u64, delete_count: u64, buffer: u64) -> u64 {
    if is_empty(table) {
        out::<u64>(restart_key).set(0);
        return 0;
    }
    let saved = out::<u64>(restart_key).get();
    let mut node = if saved != 0 && out::<u32>(delete_count).get() == avl(table).delete_count.get() {
        successor(table, saved)
    } else {
        match find(table, buffer) {
            (FOUND_NODE, found) => {
                if next_flag { successor(table, found) } else { found }
            }
            (INSERT_AS_LEFT, at) => at,
            (INSERT_AS_RIGHT, at) => successor(table, at),
            _ => 0,
        }
    };
    while node != 0 {
        let status = if match_function == 0 { 0 } else { native_call::call(match_function, &[table, node + USER_DATA, match_data]) as u32 };
        match status {
            STATUS_NO_MATCH => node = successor(table, node),
            STATUS_NO_MORE_MATCHES => break,
            _ => {
                out::<u64>(restart_key).set(node);
                out::<u32>(delete_count).set(avl(table).delete_count.get());
                return node + USER_DATA;
            }
        }
    }
    out::<u64>(restart_key).set(0);
    0
}
