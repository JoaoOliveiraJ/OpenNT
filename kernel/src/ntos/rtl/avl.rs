//! RTL_AVL_TREE na memória do convidado.
//!
//! A raiz fica em +0; RTL_BALANCED_NODE tem filhos em +0/+8 e o pai com dois
//! bits de balanço em +16. O chamador fornece nós, ordenação e sincronização;
//! este módulo não aloca nem copia dados.

use crate::ntos::inc::types::{NtStruct, RtlAvlTree, RtlBalancedNode};
use crate::rtl::KernelError;

/// PRTL_BALANCED_NODE do chamador.
fn node_at(node: u64) -> &'static RtlBalancedNode {
    // SAFETY: nó vivo e alinhado fornecido pelo chamador (o módulo não aloca).
    unsafe { RtlBalancedNode::at(node) }
}

/// PRTL_AVL_TREE do chamador.
fn tree_at(tree: u64) -> &'static RtlAvlTree {
    // SAFETY: idem `node_at`.
    unsafe { RtlAvlTree::at(tree) }
}

fn child(node: u64, side: u64) -> u64 {
    node_at(node).children[side as usize].get()
}

fn parent_and_balance(node: u64) -> u64 {
    node_at(node).parent_value.get()
}

fn parent(node: u64) -> u64 {
    parent_and_balance(node) & !3
}

/// Altura direita menos esquerda: 3 representa -1; 2 indica corrupção.
fn balance(node: u64) -> Result<i64, KernelError> {
    match parent_and_balance(node) & 3 {
        2 => Err(KernelError::new("corrupt RTL_AVL_TREE balance")),
        3 => Ok(-1),
        bits => Ok(bits as i64),
    }
}

fn set_balance(node: u64, factor: i64) {
    node_at(node).parent_value.set(parent(node) | (factor as u64 & 3));
}

fn set_parent(node: u64, linked: u64) {
    if node != 0 {
        node_at(node).parent_value.set((parent_and_balance(node) & 3) | linked);
    }
}

fn set_child(node: u64, side: u64, linked: u64) {
    node_at(node).children[side as usize].set(linked);
    set_parent(linked, node);
}

fn child_side(node: u64, linked: u64) -> Result<u64, KernelError> {
    if child(node, 0) == linked {
        Ok(0)
    } else if child(node, 1) == linked {
        Ok(1)
    } else {
        Err(KernelError::new("corrupt RTL_AVL_TREE parent/child link"))
    }
}

/// Substitui o nó no pai ou na raiz (conferindo a identidade da raiz).
fn replace_node(tree: u64, node: u64, replacement: u64) -> Result<(), KernelError> {
    let parent_address = parent(node);
    if parent_address != 0 {
        node_at(parent_address).children[child_side(parent_address, node)? as usize].set(replacement);
    } else {
        if tree_at(tree).root.get() != node {
            return Err(KernelError::new("corrupt RTL_AVL_TREE root"));
        }
        tree_at(tree).root.set(replacement);
    }
    set_parent(replacement, parent_address);
    Ok(())
}

/// Promove o filho escolhido (lado direito = rotação à esquerda).
fn rotate(tree: u64, node: u64, side: u64) -> Result<u64, KernelError> {
    let root = child(node, side);
    let middle = child(root, side ^ 1);
    if parent(root) != node {
        return Err(KernelError::new("corrupt RTL_AVL_TREE rotation"));
    }
    replace_node(tree, node, root)?;
    set_child(node, side, middle);
    set_child(root, side ^ 1, node);
    Ok(root)
}

/// Rotação simples ou dupla; devolve a nova raiz e se a altura diminuiu.
fn rebalance(tree: u64, node: u64, factor: i64) -> Result<(u64, bool), KernelError> {
    let side = if factor > 0 { 1 } else { 0 };
    let direction = if side == 1 { 1 } else { -1 };
    let heavy = child(node, side);
    let heavy_balance = balance(heavy)?;
    if heavy_balance * direction >= 0 {
        let root = rotate(tree, node, side)?;
        set_balance(node, if heavy_balance == 0 { direction } else { 0 });
        set_balance(root, if heavy_balance == 0 { -direction } else { 0 });
        return Ok((root, heavy_balance != 0));
    }
    let middle = child(heavy, side ^ 1);
    let middle_balance = balance(middle)?;
    rotate(tree, heavy, side ^ 1)?;
    let root = rotate(tree, node, side)?;
    set_balance(node, if middle_balance == direction { -direction } else { 0 });
    set_balance(heavy, if middle_balance == -direction { direction } else { 0 });
    set_balance(root, 0);
    Ok((root, true))
}

/// RtlAvlInsertNodeEx: exige alinhamento e posição vazia.
pub fn insert(tree: u64, parent_node: u64, insert_on_right: u64, node: u64) -> Result<u32, KernelError> {
    let right = insert_on_right & 255;
    let misplaced = node == 0 || node & 3 != 0 || parent_node & 3 != 0 || right > 1;
    // A posição só é lida com ponteiros alinhados.
    if misplaced || if parent_node != 0 { child(parent_node, right) != 0 } else { tree_at(tree).root.get() != 0 } {
        return Err(KernelError::new("invalid RTL_AVL_TREE insertion position"));
    }
    let inserted = node_at(node);
    inserted.left.set(0);
    inserted.right.set(0);
    inserted.parent_value.set(parent_node);
    if parent_node == 0 {
        tree_at(tree).root.set(node);
        return Ok(0);
    }
    set_child(parent_node, right, node);
    let mut current = parent_node;
    let mut below = node;
    while current != 0 {
        let factor = balance(current)? + if child_side(current, below)? == 1 { 1 } else { -1 };
        if factor == 2 || factor == -2 {
            rebalance(tree, current, factor)?;
            break;
        }
        set_balance(current, factor);
        if factor == 0 {
            break;
        }
        below = current;
        current = parent(current);
    }
    Ok(0)
}

/// RtlAvlRemoveNode: com dois filhos move o predecessor (se pesa à esquerda)
/// ou o sucessor; corrige alturas até a raiz.
pub fn remove(tree: u64, node: u64) -> Result<u32, KernelError> {
    let left = child(node, 0);
    let right = child(node, 1);
    let mut current;
    let mut delta;
    if left != 0 && right != 0 {
        let side = if balance(node)? < 0 { 0 } else { 1 };
        let mut replacement = child(node, side);
        while child(replacement, side ^ 1) != 0 {
            replacement = child(replacement, side ^ 1);
        }
        let previous_parent = parent(replacement);
        let previous_side = child_side(previous_parent, replacement)?;
        replace_node(tree, replacement, child(replacement, side))?;
        replace_node(tree, node, replacement)?;
        set_child(replacement, 0, child(node, 0));
        set_child(replacement, 1, child(node, 1));
        set_balance(replacement, balance(node)?);
        current = if previous_parent == node { replacement } else { previous_parent };
        delta = if previous_side == 1 { -1 } else { 1 };
    } else {
        current = parent(node);
        delta = if current != 0 && child_side(current, node)? == 1 { -1 } else { 1 };
        replace_node(tree, node, if left != 0 { left } else { right })?;
    }
    while current != 0 {
        let factor = balance(current)? + delta;
        let mut root = current;
        if factor == 2 || factor == -2 {
            let (top, shrank) = rebalance(tree, current, factor)?;
            root = top;
            if !shrank {
                break;
            }
        } else {
            set_balance(current, factor);
            if factor != 0 {
                break;
            }
        }
        current = parent(root);
        if current != 0 {
            delta = if child_side(current, root)? == 1 { -1 } else { 1 };
        }
    }
    Ok(0)
}
