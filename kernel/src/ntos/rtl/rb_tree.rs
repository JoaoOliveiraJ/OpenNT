//! Árvore rubro-negra do Rtl (RTL_RB_TREE) — RtlRbInsertNodeEx,
//! RtlRbRemoveNode e RtlRbReplaceNode do ntoskrnl 19041 (rva 0x2c0b10,
//! 0x2c1170 e 0x2e5850).
//!
//! A árvore é a do chamador: RTL_RB_TREE { Root; Min | Encoded:1 } e nós
//! RTL_BALANCED_NODE { Left, Right, ParentValue (Red no bit 0) }; o
//! chamador escolhe o lugar da inserção (Parent e o lado), ordena, sincroniza
//! e é dono da memória.
//!
//! - Com Encoded (bit 0 do segundo campo da árvore) os ponteiros ficam
//!   codificados: um filho não nulo é guardado como nó ^ filho, o pai como
//!   nó ^ pai (com a cor nos bits baixos), a raiz como árvore ^ raiz e o
//!   mínimo como (árvore ^ mínimo) | 1; um ponteiro nulo é 0, e a árvore
//!   vazia codificada guarda Min = 1.
//! - Inserção: o nó entra vermelho como filho de Parent (raiz preta se
//!   Parent é NULL); entrando à esquerda do mínimo, vira o mínimo. A
//!   correção sobe enquanto o pai é vermelho: tio vermelho recolore (sem
//!   pintar a raiz), tio preto gira uma ou duas vezes.
//! - Remoção: com dois filhos, o sucessor (o menor da subárvore direita)
//!   assume o lugar e a cor do nó; o filho que sobe no lugar removido fica
//!   preto. O mínimo removido passa ao filho direito ou ao pai. Sem filho
//!   que suba e com a cor removida preta, a correção sobe pelo irmão nos
//!   quatro casos clássicos.
//! - Os elos tocados numa rotação são conferidos; uma árvore corrompida dá
//!   o fast-fail FAST_FAIL_INVALID_BALANCED_TREE (KERNEL_SECURITY_CHECK_FAILURE
//!   0x139, parâmetro 0x1D), como o `int 0x29` do original.

use crate::ntos::inc::types::{NtStruct, RtlBalancedNode, RtlRbTree};
use crate::ntos::ke::bugcheck;

const KERNEL_SECURITY_CHECK_FAILURE: u32 = 0x139;
const FAST_FAIL_INVALID_BALANCED_TREE: u64 = 0x1D;
const LEFT: usize = 0;
const RIGHT: usize = 1;

fn node_at(node: u64) -> &'static RtlBalancedNode {
    // SAFETY: nó vivo e alinhado do chamador (o módulo não aloca nós).
    unsafe { RtlBalancedNode::at(node) }
}

/// Vista da árvore com o modo de codificação lido uma vez, como o original.
struct Tree {
    address: u64,
    encoded: bool,
}

impl Tree {
    fn open(address: u64) -> Self {
        // SAFETY: PRTL_RB_TREE do chamador.
        let tree = unsafe { RtlRbTree::at(address) };
        Tree { address, encoded: tree.encoded() != 0 }
    }

    fn header(&self) -> &'static RtlRbTree {
        // SAFETY: a árvore aberta em `open`.
        unsafe { RtlRbTree::at(self.address) }
    }

    /// Valor guardado relativo a `base`: só ponteiros não nulos codificam.
    fn decode(&self, base: u64, stored: u64) -> u64 {
        if self.encoded && stored != 0 { stored ^ base } else { stored }
    }

    fn child(&self, node: u64, side: usize) -> u64 {
        self.decode(node, node_at(node).children[side].get())
    }

    fn set_child(&self, node: u64, side: usize, child: u64) {
        node_at(node).children[side].set(self.decode(node, child));
    }

    fn parent(&self, node: u64) -> u64 {
        self.decode(node, node_at(node).parent_value.get() & !3)
    }

    fn red(&self, node: u64) -> bool {
        node_at(node).red() != 0
    }

    fn set_red(&self, node: u64, red: bool) {
        node_at(node).set_red(red as u8);
    }

    /// Troca o pai conservando os dois bits baixos.
    fn set_parent(&self, node: u64, parent: u64) {
        let cell = &node_at(node).parent_value;
        cell.set(self.decode(node, parent) | (cell.get() & 3));
    }

    /// Pai e cor de uma vez (os bits de balanço zerados).
    fn set_parent_and_color(&self, node: u64, parent: u64, red: bool) {
        node_at(node).parent_value.set(self.decode(node, parent) | red as u64);
    }

    fn root(&self) -> u64 {
        self.decode(self.address, self.header().root.get())
    }

    fn set_root(&self, root: u64) {
        self.header().root.set(self.decode(self.address, root));
    }

    fn min(&self) -> u64 {
        let stored = self.header().min.get();
        if !self.encoded {
            stored
        } else if stored == 1 {
            0
        } else {
            stored ^ (self.address | 1)
        }
    }

    fn set_min(&self, min: u64) {
        let stored = if !self.encoded {
            min
        } else if min == 0 {
            1
        } else {
            (self.address ^ min) | 1
        };
        self.header().min.set(stored);
    }

    fn verify(&self, consistent: bool) {
        if !consistent {
            bugcheck::bug_check_ex(KERNEL_SECURITY_CHECK_FAILURE, FAST_FAIL_INVALID_BALANCED_TREE, self.address, 0, 0);
        }
    }

    /// Lado de `node` sob `parent`, conferindo que o pai aponta para ele.
    fn side_of(&self, parent: u64, node: u64) -> usize {
        if self.child(parent, RIGHT) == node {
            RIGHT
        } else {
            self.verify(self.child(parent, LEFT) == node);
            LEFT
        }
    }

    /// `node` desce para `side` e o filho do outro lado sobe ao seu lugar.
    fn rotate(&self, node: u64, side: usize) {
        let other = side ^ 1;
        let raised = self.child(node, other);
        self.verify(raised != 0 && self.parent(raised) == node);
        let parent = self.parent(node);
        let moved = self.child(raised, side);
        if parent == 0 {
            self.verify(self.root() == node);
            self.set_root(raised);
        } else {
            let position = self.side_of(parent, node);
            self.set_child(parent, position, raised);
        }
        self.set_parent(raised, parent);
        self.set_child(node, other, moved);
        if moved != 0 {
            self.verify(self.parent(moved) == raised);
            self.set_parent(moved, node);
        }
        self.set_child(raised, side, node);
        self.set_parent(node, raised);
    }
}

/// RtlRbInsertNodeEx(Tree, Parent, Right, Node).
pub fn insert(tree: u64, parent: u64, right: bool, node: u64) {
    let tree = Tree::open(tree);
    let entry = node_at(node);
    entry.children[LEFT].set(0);
    entry.children[RIGHT].set(0);
    if parent == 0 {
        tree.set_root(node);
        tree.set_min(node);
        entry.parent_value.set(0);
        return;
    }
    let side = if right { RIGHT } else { LEFT };
    tree.set_child(parent, side, node);
    tree.set_parent_and_color(node, parent, true);
    if side == LEFT && tree.min() == parent {
        tree.set_min(node);
    }
    let mut current = node;
    loop {
        let parent = tree.parent(current);
        if parent == 0 || !tree.red(parent) {
            return;
        }
        let grandparent = tree.parent(parent);
        tree.verify(grandparent != 0);
        let parent_side = if tree.child(grandparent, LEFT) == parent { LEFT } else { RIGHT };
        let uncle = tree.child(grandparent, parent_side ^ 1);
        if uncle != 0 && tree.red(uncle) {
            tree.set_red(parent, false);
            tree.set_red(uncle, false);
            if tree.parent(grandparent) == 0 {
                return;
            }
            tree.set_red(grandparent, true);
            current = grandparent;
            continue;
        }
        let mut top = parent;
        if tree.side_of(parent, current) != parent_side {
            tree.rotate(parent, parent_side);
            top = current;
        }
        tree.rotate(grandparent, parent_side ^ 1);
        tree.set_red(grandparent, true);
        tree.set_red(top, false);
        return;
    }
}

/// RtlRbReplaceNode(Tree, Node, ReplacementNode) (0x2e5850): o substituto
/// recebe os 24 bytes do nó (filhos, pai e cor); cada filho não nulo passa a
/// apontar para ele (os dois bits baixos conservados) e, sem filho esquerdo,
/// o mínimo que era o nó vira o substituto; sem pai, a raiz é o substituto,
/// senão o elo do pai que guardava o nó. Só a raiz e o mínimo seguem a
/// codificação da árvore: os elos dos nós são lidos e gravados como estão,
/// como no original.
pub fn replace_node(tree: u64, node: u64, replacement: u64) {
    let tree = Tree::open(tree);
    let (old, new) = (node_at(node), node_at(replacement));
    let (left, right, parent_value) = (old.left.get(), old.right.get(), old.parent_value.get());
    new.left.set(left);
    new.right.set(right);
    new.parent_value.set(parent_value);
    let adopt = |child: u64| {
        let cell = &node_at(child).parent_value;
        cell.set((cell.get() & 3) | replacement);
    };
    if left != 0 {
        adopt(left);
    } else if tree.min() == node {
        tree.set_min(replacement);
    }
    if right != 0 {
        adopt(right);
    }
    let parent = parent_value & !3;
    if parent == 0 {
        tree.set_root(replacement);
    } else if node_at(parent).left.get() == node {
        node_at(parent).left.set(replacement);
    } else {
        node_at(parent).right.set(replacement);
    }
}

/// RtlRbRemoveNode(Tree, Node).
pub fn remove(tree: u64, node: u64) {
    let tree = Tree::open(tree);
    let (left, right) = (tree.child(node, LEFT), tree.child(node, RIGHT));
    // O filho que sobe ao lugar removido, o pai desse lugar e o lado.
    let (raised, mut parent, mut side, removed_red);
    if left != 0 && right != 0 {
        let mut successor = right;
        while tree.child(successor, LEFT) != 0 {
            successor = tree.child(successor, LEFT);
        }
        removed_red = tree.red(successor);
        raised = tree.child(successor, RIGHT);
        (parent, side) = if successor == right { (successor, RIGHT) } else { (tree.parent(successor), LEFT) };
        tree.verify(tree.parent(left) == node && tree.parent(right) == node);
        tree.set_child(successor, LEFT, left);
        tree.set_parent(left, successor);
        if successor != right {
            tree.set_child(successor, RIGHT, right);
            tree.set_parent(right, successor);
        }
        let above = tree.parent(node);
        tree.set_parent_and_color(successor, above, tree.red(node));
        if above == 0 {
            tree.verify(tree.root() == node);
            tree.set_root(successor);
        } else {
            let position = tree.side_of(above, node);
            tree.set_child(above, position, successor);
        }
        tree.set_child(parent, side, raised);
    } else {
        raised = if left != 0 { left } else { right };
        removed_red = tree.red(node);
        let above = tree.parent(node);
        if above == 0 {
            tree.verify(tree.root() == node);
            if raised != 0 {
                tree.verify(tree.parent(raised) == node);
                tree.set_parent_and_color(raised, 0, false);
                tree.set_root(raised);
                if tree.min() == node {
                    tree.set_min(raised);
                }
            } else {
                tree.set_min(0);
                tree.set_root(0);
            }
            return;
        }
        side = tree.side_of(above, node);
        if side == LEFT && tree.min() == node {
            tree.set_min(if raised != 0 { raised } else { above });
        }
        parent = above;
        tree.set_child(above, side, raised);
    }
    if raised != 0 {
        // O filho que sobe é vermelho: assume o lugar já preto.
        tree.set_parent_and_color(raised, parent, false);
        return;
    }
    if removed_red {
        return;
    }
    loop {
        let mut sibling = tree.child(parent, side ^ 1);
        tree.verify(sibling != 0);
        if tree.red(sibling) {
            tree.rotate(parent, side);
            tree.set_red(sibling, false);
            tree.set_red(parent, true);
            sibling = tree.child(parent, side ^ 1);
        }
        let near = tree.child(sibling, side);
        let mut far = tree.child(sibling, side ^ 1);
        let far_red = far != 0 && tree.red(far);
        if far_red || (near != 0 && tree.red(near)) {
            if !far_red {
                tree.set_red(near, false);
                tree.rotate(sibling, side ^ 1);
                far = sibling;
                sibling = near;
            }
            tree.set_red(sibling, tree.red(parent));
            tree.set_red(parent, false);
            tree.set_red(far, false);
            tree.rotate(parent, side);
            return;
        }
        if tree.red(parent) {
            tree.set_red(parent, false);
            tree.set_red(sibling, true);
            return;
        }
        tree.set_red(sibling, true);
        let lower = parent;
        parent = tree.parent(lower);
        if parent == 0 {
            return;
        }
        side = tree.side_of(parent, lower);
    }
}
