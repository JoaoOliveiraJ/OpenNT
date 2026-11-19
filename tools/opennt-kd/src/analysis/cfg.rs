//! O grafo de fluxo de controle de uma função: blocos básicos a partir da
//! entrada, arestas de desvio (verdadeira e falsa nos condicionais, salto
//! incondicional e queda para o bloco seguinte) e um arranjo em camadas
//! para desenhar o grafo.
//!
//! A descoberta segue os desvios diretos a partir da entrada (descida
//! recursiva): uma chamada não termina o bloco; um salto para fora da faixa
//! da função é um salto de cauda (o bloco é uma saída); um salto para o meio
//! de um bloco já visto divide o bloco.

use std::collections::{BTreeMap, BTreeSet};

use super::decode::{Flow, Insn};

/// O tipo de uma aresta.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeKind {
    /// `jmp` incondicional.
    Jump,
    /// O desvio condicional tomado.
    True,
    /// O desvio condicional não tomado.
    False,
    /// O bloco acaba porque o seguinte começa ali.
    Fallthrough,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edge {
    pub to: u64,
    pub kind: EdgeKind,
}

/// Um bloco básico.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub start: u64,
    /// Fim exclusivo (o endereço depois da última instrução).
    pub end: u64,
    pub insns: Vec<Insn>,
    pub edges: Vec<Edge>,
    /// Termina num `ret`, numa parada, num salto indireto ou num salto de
    /// cauda para fora da faixa.
    pub exit: bool,
}

/// O grafo de uma função.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Graph {
    pub entry: u64,
    /// Em ordem de endereço.
    pub blocks: Vec<Block>,
    /// O limite de instruções acabou antes da descoberta.
    pub truncated: bool,
}

impl Graph {
    /// O bloco que contém `address`.
    pub fn block_at(&self, address: u64) -> Option<usize> {
        let candidates = self.blocks.partition_point(|block| block.start <= address);
        (0..candidates).rev().find(|&index| address < self.blocks[index].end)
    }

    /// Os blocos com aresta para o bloco `index`.
    pub fn predecessors(&self, index: usize) -> Vec<usize> {
        let Some(block) = self.blocks.get(index) else { return Vec::new() };
        self.blocks.iter().enumerate().filter(|(_, other)| other.edges.iter().any(|edge| edge.to == block.start)).map(|(position, _)| position).collect()
    }

    /// O índice do bloco que começa em `address`.
    fn index_of(&self, address: u64) -> Option<usize> {
        self.blocks.binary_search_by_key(&address, |block| block.start).ok()
    }
}

/// Monta o grafo a partir de `entry`. `range` (início, fim exclusivo)
/// limita os desvios seguidos; `decode` dá a instrução de um endereço;
/// `limit` é o máximo de instruções decodificadas.
pub fn build(entry: u64, range: Option<(u64, u64)>, decode: &mut dyn FnMut(u64) -> Option<Insn>, limit: usize) -> Graph {
    let inside = |address: u64| range.is_none_or(|(start, end)| address >= start && address < end);
    let mut insns: BTreeMap<u64, Insn> = BTreeMap::new();
    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    let mut truncated = false;
    leaders.insert(entry);
    let mut work = vec![entry];
    while let Some(start) = work.pop() {
        let mut address = start;
        loop {
            if insns.contains_key(&address) {
                // Uma queda num trecho já decodificado: começa um bloco ali.
                if address != start {
                    leaders.insert(address);
                }
                break;
            }
            if insns.len() >= limit {
                truncated = true;
                break;
            }
            let Some(insn) = decode(address) else { break };
            insns.insert(address, insn);
            let next = insn.end();
            match insn.flow {
                Flow::Next | Flow::Call | Flow::Interrupt => {
                    if !inside(next) {
                        break;
                    }
                    address = next;
                }
                Flow::Conditional => {
                    if let Some(target) = insn.target.filter(|&target| inside(target)) {
                        leaders.insert(target);
                        work.push(target);
                    }
                    if inside(next) {
                        leaders.insert(next);
                        work.push(next);
                    }
                    break;
                }
                Flow::Jump => {
                    if let Some(target) = insn.target.filter(|&target| inside(target)) {
                        leaders.insert(target);
                        work.push(target);
                    }
                    break;
                }
                Flow::IndirectCall => {
                    if !inside(next) {
                        break;
                    }
                    address = next;
                }
                Flow::IndirectJump | Flow::Return | Flow::Stop => break,
            }
        }
    }
    let mut blocks = Vec::new();
    for &leader in &leaders {
        if !insns.contains_key(&leader) {
            continue;
        }
        let mut block = Block { start: leader, end: leader, insns: Vec::new(), edges: Vec::new(), exit: false };
        let mut address = leader;
        loop {
            let insn = insns[&address];
            block.insns.push(insn);
            let next = insn.end();
            block.end = next;
            match insn.flow {
                Flow::Conditional => {
                    if let Some(target) = insn.target.filter(|&target| inside(target)) {
                        block.edges.push(Edge { to: target, kind: EdgeKind::True });
                    }
                    if inside(next) {
                        block.edges.push(Edge { to: next, kind: EdgeKind::False });
                    } else {
                        block.exit = true;
                    }
                    break;
                }
                Flow::Jump => {
                    match insn.target.filter(|&target| inside(target)) {
                        Some(target) => block.edges.push(Edge { to: target, kind: EdgeKind::Jump }),
                        None => block.exit = true,
                    }
                    break;
                }
                Flow::IndirectJump | Flow::Return | Flow::Stop => {
                    block.exit = true;
                    break;
                }
                Flow::Next | Flow::Call | Flow::IndirectCall | Flow::Interrupt => {
                    if leaders.contains(&next) && insns.contains_key(&next) {
                        block.edges.push(Edge { to: next, kind: EdgeKind::Fallthrough });
                        break;
                    }
                    if !insns.contains_key(&next) {
                        // Fim da faixa, código ilegível ou o limite.
                        block.exit = true;
                        break;
                    }
                    address = next;
                }
            }
        }
        blocks.push(block);
    }
    // Só arestas para blocos que existem (um destino ilegível some).
    let starts: BTreeSet<u64> = blocks.iter().map(|block| block.start).collect();
    for block in &mut blocks {
        block.edges.retain(|edge| starts.contains(&edge.to));
    }
    Graph { entry, blocks, truncated }
}

/// O arranjo em camadas: a camada e a coluna de cada bloco (pelo índice em
/// `Graph::blocks`), o número de camadas e a largura da maior.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Layout {
    pub layer: Vec<usize>,
    pub column: Vec<usize>,
    pub layers: usize,
    pub width: usize,
}

/// Camadas pelo caminho mais longo sobre as arestas de avanço (as de volta
/// dos laços, achadas pela busca em profundidade a partir da entrada, não
/// contam) e a ordem dentro de cada camada pelo baricentro dos vizinhos.
pub fn layout(graph: &Graph) -> Layout {
    let count = graph.blocks.len();
    if count == 0 {
        return Layout::default();
    }
    let successors: Vec<Vec<usize>> = graph.blocks.iter().map(|block| block.edges.iter().filter_map(|edge| graph.index_of(edge.to)).collect()).collect();
    // Busca em profundidade iterativa: uma aresta para um bloco na pilha é
    // de volta.
    let mut back = vec![Vec::new(); count];
    let mut state = vec![0u8; count];
    let entry = graph.index_of(graph.entry).unwrap_or(0);
    let mut roots = vec![entry];
    roots.extend((0..count).filter(|&index| index != entry));
    for root in roots {
        if state[root] != 0 {
            continue;
        }
        let mut stack: Vec<(usize, usize)> = vec![(root, 0)];
        state[root] = 1;
        while let Some(top) = stack.last_mut() {
            let node = top.0;
            if top.1 < successors[node].len() {
                let child = successors[node][top.1];
                top.1 += 1;
                match state[child] {
                    0 => {
                        state[child] = 1;
                        stack.push((child, 0));
                    }
                    1 => back[node].push(child),
                    _ => {}
                }
            } else {
                state[node] = 2;
                stack.pop();
            }
        }
    }
    let forward: Vec<Vec<usize>> = (0..count).map(|node| successors[node].iter().copied().filter(|child| !back[node].contains(child)).collect()).collect();
    // Caminho mais longo pela ordem topológica (Kahn).
    let mut incoming = vec![0usize; count];
    for children in &forward {
        for &child in children {
            incoming[child] += 1;
        }
    }
    let mut layer = vec![0usize; count];
    let mut ready: Vec<usize> = (0..count).filter(|&node| incoming[node] == 0).collect();
    ready.sort_by_key(|&node| std::cmp::Reverse(node));
    while let Some(node) = ready.pop() {
        for &child in &forward[node] {
            layer[child] = layer[child].max(layer[node] + 1);
            incoming[child] -= 1;
            if incoming[child] == 0 {
                ready.push(child);
            }
        }
    }
    let layers = layer.iter().max().copied().unwrap_or(0) + 1;
    let mut rows: Vec<Vec<usize>> = vec![Vec::new(); layers];
    for node in 0..count {
        rows[layer[node]].push(node);
    }
    let mut predecessors = vec![Vec::new(); count];
    for (node, children) in forward.iter().enumerate() {
        for &child in children {
            predecessors[child].push(node);
        }
    }
    let mut position = vec![0usize; count];
    let place = |rows: &Vec<Vec<usize>>, position: &mut Vec<usize>| {
        for row in rows {
            for (index, &node) in row.iter().enumerate() {
                position[node] = index;
            }
        }
    };
    place(&rows, &mut position);
    // Varreduras alternadas: para baixo pelos predecessores, para cima
    // pelos sucessores.
    for sweep in 0..4 {
        let downward = sweep % 2 == 0;
        let order: Vec<usize> = if downward { (1..layers).collect() } else { (0..layers.saturating_sub(1)).rev().collect() };
        for row_index in order {
            let mut keyed: Vec<(f64, usize, usize)> = rows[row_index]
                .iter()
                .enumerate()
                .map(|(current, &node)| {
                    let neighbors = if downward { &predecessors[node] } else { &forward[node] };
                    let key = if neighbors.is_empty() { current as f64 } else { neighbors.iter().map(|&other| position[other] as f64).sum::<f64>() / neighbors.len() as f64 };
                    (key, current, node)
                })
                .collect();
            keyed.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
            rows[row_index] = keyed.into_iter().map(|(_, _, node)| node).collect();
            for (index, &node) in rows[row_index].iter().enumerate() {
                position[node] = index;
            }
        }
    }
    let width = rows.iter().map(Vec::len).max().unwrap_or(0);
    Layout { layer, column: position, layers, width }
}

#[cfg(test)]
mod tests {
    use super::super::decode::decode;
    use super::*;

    fn graph(base: u64, code: &[u8], range: Option<(u64, u64)>, limit: usize) -> Graph {
        let mut decoder = |address: u64| {
            let offset = address.checked_sub(base)? as usize;
            decode(code.get(offset..)?, address)
        };
        build(base, range, &mut decoder, limit)
    }

    fn starts(graph: &Graph) -> Vec<u64> {
        graph.blocks.iter().map(|block| block.start).collect()
    }

    /// test eax, eax; jz +4; inc eax; jmp +2; dec eax; ret
    const DIAMOND: [u8; 11] = [0x85, 0xC0, 0x74, 0x04, 0xFF, 0xC0, 0xEB, 0x02, 0xFF, 0xC8, 0xC3];

    #[test]
    fn diamond() {
        let graph = graph(0x1000, &DIAMOND, None, 100);
        assert_eq!(starts(&graph), vec![0x1000, 0x1004, 0x1008, 0x100A]);
        assert_eq!(graph.blocks[0].edges, vec![Edge { to: 0x1008, kind: EdgeKind::True }, Edge { to: 0x1004, kind: EdgeKind::False }]);
        assert_eq!(graph.blocks[1].edges, vec![Edge { to: 0x100A, kind: EdgeKind::Jump }]);
        assert_eq!(graph.blocks[2].edges, vec![Edge { to: 0x100A, kind: EdgeKind::Fallthrough }]);
        assert!(graph.blocks[3].exit && graph.blocks[3].edges.is_empty());
        assert_eq!(graph.blocks[0].end, 0x1004);
        assert_eq!(graph.block_at(0x1005), Some(1));
        assert_eq!(graph.block_at(0x100A), Some(3));
        assert_eq!(graph.block_at(0x2000), None);
        let mut predecessors = graph.predecessors(3);
        predecessors.sort();
        assert_eq!(predecessors, vec![1, 2]);
        assert!(!graph.truncated);
        let layout = layout(&graph);
        assert_eq!(layout.layer, vec![0, 1, 1, 2]);
        assert_eq!((layout.layers, layout.width), (3, 2));
        assert_ne!(layout.column[1], layout.column[2]);
        assert!(layout.column.iter().all(|&column| column < layout.width));
    }

    #[test]
    fn loop_with_back_edge() {
        // xor eax, eax; inc eax; cmp eax, 10; jnz -7; ret
        let code = [0x31, 0xC0, 0xFF, 0xC0, 0x83, 0xF8, 0x0A, 0x75, 0xF9, 0xC3];
        let graph = graph(0x2000, &code, None, 100);
        assert_eq!(starts(&graph), vec![0x2000, 0x2002, 0x2009]);
        assert_eq!(graph.blocks[0].edges, vec![Edge { to: 0x2002, kind: EdgeKind::Fallthrough }]);
        assert_eq!(graph.blocks[1].edges, vec![Edge { to: 0x2002, kind: EdgeKind::True }, Edge { to: 0x2009, kind: EdgeKind::False }]);
        let layout = layout(&graph);
        assert_eq!(layout.layer, vec![0, 1, 2]);
    }

    #[test]
    fn jump_into_the_middle_splits_the_block() {
        // nop; nop; nop; jz -4 (para o segundo nop); ret
        let code = [0x90, 0x90, 0x90, 0x74, 0xFC, 0xC3];
        let graph = graph(0x3000, &code, None, 100);
        assert_eq!(starts(&graph), vec![0x3000, 0x3001, 0x3005]);
        assert_eq!(graph.blocks[0].insns.len(), 1);
        assert_eq!(graph.blocks[0].edges, vec![Edge { to: 0x3001, kind: EdgeKind::Fallthrough }]);
        assert_eq!(graph.blocks[1].insns.len(), 3);
        assert_eq!(graph.blocks[1].edges[0], Edge { to: 0x3001, kind: EdgeKind::True });
    }

    #[test]
    fn tail_jump_out_of_range() {
        // test eax, eax; jnz +2; jmp +0x10 (fora); xor eax, eax; ret
        let code = [0x85, 0xC0, 0x75, 0x02, 0xEB, 0x10, 0x31, 0xC0, 0xC3];
        let graph = graph(0x4000, &code, Some((0x4000, 0x4009)), 100);
        assert_eq!(starts(&graph), vec![0x4000, 0x4004, 0x4006]);
        assert!(graph.blocks[1].exit);
        assert!(graph.blocks[1].edges.is_empty());
        assert!(graph.blocks[2].exit);
        // Sem faixa, o salto é seguido (e o destino ilegível some).
        let open = super::tests::graph(0x4000, &code, None, 100);
        assert_eq!(open.blocks[1].edges, Vec::new());
    }

    #[test]
    fn truncation() {
        let graph = graph(0x1000, &DIAMOND, None, 2);
        assert!(graph.truncated);
        assert_eq!(graph.blocks.len(), 1);
        assert!(graph.blocks[0].insns.len() <= 2);
    }

    #[test]
    fn calls_do_not_end_blocks() {
        // call +0; ret
        let code = [0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3];
        let graph = graph(0x5000, &code, Some((0x5000, 0x5006)), 100);
        assert_eq!(graph.blocks.len(), 1);
        assert_eq!(graph.blocks[0].insns.len(), 2);
    }
}
