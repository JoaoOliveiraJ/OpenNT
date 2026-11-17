//! Limites de funções e laços para a desmontagem.
//!
//! Fontes dos limites, nesta ordem:
//! - a `.pdata` dos binários da Microsoft (início e fim de cada função);
//! - o tamanho do símbolo (o ELF do kernel e os PDBs);
//! - uma passada pelo fluxo de código a partir do início conhecido (o
//!   símbolo sem tamanho ou o destino de um `call`): o fim é o fim do bloco
//!   mais distante alcançado sem sair por `call`.
//!
//! Laços: um desvio para trás dentro da mesma função (o destino fica entre
//! o começo da função e o próprio desvio) fecha um laço do destino até o
//! desvio.

use super::cfg;
use super::decode::{Flow, Insn};

/// De onde veio o limite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundSource {
    /// `.pdata` (RUNTIME_FUNCTION).
    Table,
    /// Símbolo com tamanho.
    Symbol,
    /// Passada pelo fluxo de código.
    Flow,
}

impl BoundSource {
    pub fn name(self) -> &'static str {
        match self {
            BoundSource::Table => ".pdata",
            BoundSource::Symbol => "simbolo",
            BoundSource::Flow => "fluxo",
        }
    }
}

/// Uma função: `[start, end)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Function {
    pub start: u64,
    pub end: u64,
    pub source: BoundSource,
}

impl Function {
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start && address < self.end
    }
}

/// O fim de uma função pela passada no fluxo de código a partir de
/// `entry` (sem seguir `call`): os blocos alcançados que ficam contíguos a
/// partir da entrada. Um salto de cauda para longe (outra função) não
/// estica o fim. `limit` é o máximo de instruções decodificadas.
pub fn flow_extent(entry: u64, decode: &mut dyn FnMut(u64) -> Option<Insn>, limit: usize) -> Option<u64> {
    let graph = cfg::build(entry, None, decode, limit);
    let mut blocks: Vec<(u64, u64)> = graph.blocks.iter().map(|block| (block.start, block.end)).filter(|&(start, _)| start >= entry).collect();
    blocks.sort_unstable();
    let mut end = entry;
    for (start, finish) in blocks {
        // Tolera o preenchimento entre blocos (int3/nop de alinhamento).
        if start > end + 16 {
            break;
        }
        end = end.max(finish);
    }
    (end > entry).then_some(end)
}

/// A função que contém `address`: a entrada da `.pdata` (pares início e
/// fim absolutos, ordenados), o símbolo com tamanho (início, tamanho) ou,
/// com o início de um símbolo sem tamanho, a passada pelo fluxo.
pub fn function_at(address: u64, table: &[(u64, u64)], symbol: Option<(u64, u64)>, decode: &mut dyn FnMut(u64) -> Option<Insn>) -> Option<Function> {
    let index = table.partition_point(|&(start, _)| start <= address);
    if index > 0 {
        let (start, end) = table[index - 1];
        if address < end {
            return Some(Function { start, end, source: BoundSource::Table });
        }
    }
    let (start, size) = symbol?;
    if size > 0 {
        return (address < start + size).then_some(Function { start, end: start + size, source: BoundSource::Symbol });
    }
    let end = flow_extent(start, decode, 512)?;
    (address >= start && address < end).then_some(Function { start, end, source: BoundSource::Flow })
}

/// Os começos de função achados pelos `call` diretos de uma lista de
/// instruções (destinos dentro de `range`), sem repetição e em ordem.
pub fn call_targets(insns: &[Insn], range: (u64, u64)) -> Vec<u64> {
    let mut targets: Vec<u64> = insns.iter().filter(|insn| insn.flow == Flow::Call).filter_map(|insn| insn.target).filter(|&target| target >= range.0 && target < range.1).collect();
    targets.sort_unstable();
    targets.dedup();
    targets
}

/// Um laço: do destino do desvio para trás (`start`) até o fim do desvio.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Loop {
    pub start: u64,
    /// O desvio que volta.
    pub branch: u64,
    /// Fim exclusivo (depois do desvio).
    pub end: u64,
}

/// Os laços de uma função: desvios (condicionais ou não) cujo destino fica
/// entre o começo da função e o próprio desvio. Ordenados pelo começo, os
/// externos antes dos internos.
pub fn loops(insns: &[Insn], function: (u64, u64)) -> Vec<Loop> {
    let mut found: Vec<Loop> = insns
        .iter()
        .filter(|insn| insn.address >= function.0 && insn.address < function.1)
        .filter(|insn| matches!(insn.flow, Flow::Jump | Flow::Conditional))
        .filter_map(|insn| insn.target.filter(|&target| target >= function.0 && target <= insn.address).map(|target| Loop { start: target, branch: insn.address, end: insn.end() }))
        .collect();
    found.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    found.dedup();
    found
}

/// A marca de uma linha na coluna dos colchetes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mark {
    None,
    /// Primeira instrução.
    Start,
    Middle,
    /// Última instrução.
    End,
    /// Função (ou laço) de uma instrução só.
    Single,
}

/// A marca de cada linha (endereço e tamanho da instrução) para uma faixa
/// `[start, end)`.
pub fn mark(address: u64, length: u64, start: u64, end: u64) -> Mark {
    let next = address + length.max(1);
    if address < start || address >= end {
        return Mark::None;
    }
    match (address == start, next >= end) {
        (true, true) => Mark::Single,
        (true, false) => Mark::Start,
        (false, true) => Mark::End,
        (false, false) => Mark::Middle,
    }
}

/// Os colchetes das linhas: para cada linha (endereço, tamanho), a marca da
/// função que a contém.
pub fn bracket_marks(lines: &[(u64, u64)], functions: &[Function]) -> Vec<Mark> {
    lines
        .iter()
        .map(|&(address, length)| functions.iter().find(|function| function.contains(address)).map_or(Mark::None, |function| mark(address, length, function.start, function.end)))
        .collect()
}

/// A marca de laço de cada linha e a profundidade do laço (0 = fora). Com
/// laços aninhados, vale o mais interno.
pub fn loop_marks(lines: &[(u64, u64)], loops: &[Loop]) -> Vec<(Mark, usize)> {
    lines
        .iter()
        .map(|&(address, length)| {
            let containing: Vec<&Loop> = loops.iter().filter(|candidate| address >= candidate.start && address < candidate.end).collect();
            match containing.last() {
                Some(inner) => (mark(address, length, inner.start, inner.end), containing.len()),
                None => (Mark::None, 0),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::decode::{decode, decode_all};
    use super::*;

    const BASE: u64 = 0x1000;

    /// Uma função com um laço:
    /// 1000 xor eax, eax
    /// 1002 inc eax          <- laço
    /// 1004 cmp eax, 10
    /// 1007 jne 1002
    /// 1009 call 1010
    /// 100e ret
    /// 100f int3
    /// 1010 ret              (a função chamada)
    fn code() -> Vec<u8> {
        vec![0x31, 0xC0, 0xFF, 0xC0, 0x83, 0xF8, 0x0A, 0x75, 0xF9, 0xE8, 0x02, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xC3]
    }

    fn decoder(bytes: &[u8]) -> impl FnMut(u64) -> Option<Insn> + '_ {
        move |address: u64| {
            let offset = address.checked_sub(BASE)? as usize;
            decode(bytes.get(offset..)?, address)
        }
    }

    #[test]
    fn bounds_from_table_symbol_and_flow() {
        let bytes = code();
        let mut decode = decoder(&bytes);
        let table = [(BASE, BASE + 0xF), (BASE + 0x10, BASE + 0x11)];
        let function = function_at(BASE + 7, &table, None, &mut decode).unwrap();
        assert_eq!((function.start, function.end, function.source), (BASE, BASE + 0xF, BoundSource::Table));
        // Sem `.pdata`: o símbolo com tamanho.
        let function = function_at(BASE + 3, &[], Some((BASE, 0xF)), &mut decode).unwrap();
        assert_eq!(function.source, BoundSource::Symbol);
        assert!(function_at(BASE + 0x20, &[], Some((BASE, 0xF)), &mut decode).is_none());
        // Símbolo sem tamanho: o fluxo vai até o `ret` (o `call` não conta).
        let function = function_at(BASE + 3, &[], Some((BASE, 0)), &mut decode).unwrap();
        assert_eq!((function.end, function.source), (BASE + 0xF, BoundSource::Flow));
        assert_eq!(flow_extent(BASE + 0x10, &mut decode, 16), Some(BASE + 0x11));
    }

    #[test]
    fn loops_and_call_targets() {
        let bytes = code();
        let insns = decode_all(&bytes, BASE);
        let found = loops(&insns, (BASE, BASE + 0xF));
        assert_eq!(found, vec![Loop { start: BASE + 2, branch: BASE + 7, end: BASE + 9 }]);
        assert_eq!(call_targets(&insns, (BASE, BASE + 0x100)), vec![BASE + 0x10]);
        // Um desvio para trás que sai da função não é laço.
        assert!(loops(&insns, (BASE + 4, BASE + 0xF)).is_empty());
    }

    #[test]
    fn marks_for_brackets() {
        let lines: Vec<(u64, u64)> = vec![(BASE, 2), (BASE + 2, 2), (BASE + 4, 3), (BASE + 7, 2), (BASE + 9, 5), (BASE + 0xE, 1), (BASE + 0xF, 1), (BASE + 0x10, 1)];
        let functions = [Function { start: BASE, end: BASE + 0xF, source: BoundSource::Table }, Function { start: BASE + 0x10, end: BASE + 0x11, source: BoundSource::Table }];
        let marks = bracket_marks(&lines, &functions);
        assert_eq!(marks, vec![Mark::Start, Mark::Middle, Mark::Middle, Mark::Middle, Mark::Middle, Mark::End, Mark::None, Mark::Single]);
        let loops = [Loop { start: BASE + 2, branch: BASE + 7, end: BASE + 9 }];
        let marks = loop_marks(&lines, &loops);
        assert_eq!(marks[0], (Mark::None, 0));
        assert_eq!(marks[1], (Mark::Start, 1));
        assert_eq!(marks[2], (Mark::Middle, 1));
        assert_eq!(marks[3], (Mark::End, 1));
        assert_eq!(marks[4], (Mark::None, 0));
    }
}
