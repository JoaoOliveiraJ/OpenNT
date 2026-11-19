//! A análise de um módulo inteiro para as referências cruzadas, feita aos
//! poucos numa thread própria:
//!
//! - as funções pela `.pdata`, com os pedaços encadeados (UNW_FLAG_CHAININFO
//!   e o encadeamento indireto do bit 0) juntos na função dona, como o
//!   compilador da Microsoft separa o código frio;
//! - as referências de cada instrução: chamada e salto diretos, chamada e
//!   salto pela IAT, leitura de memória, endereço (`lea`) e imediato que cai
//!   no módulo;
//! - os ponteiros dos dados pela `.reloc` (vtables, tabelas de despacho e de
//!   callbacks), que nenhuma instrução referencia direto.
//!
//! Os lotes ficam prontos um a um e já respondem "quem referencia X" com o
//! que foi analisado, enquanto o resto anda (win32kfull e dwmcore levam
//! alguns segundos). Sem `.pdata` (o `kernel.elf` do OpenNT), a varredura é
//! linear, por faixas das seções de código.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use opennt_kd::analysis::decode::{self, Class, Flow};
use opennt_kd::pe::PeImage;

use crate::imports::ImportMap;
use crate::scan::ModuleImage;

/// Funções por lote.
const BATCH_FUNCTIONS: usize = 1024;
/// Bytes por lote na varredura linear.
const BATCH_BYTES: u64 = 0x4_0000;
/// Menor endereço absoluto que vale como referência (`gs:[0x188]` e
/// `[rbx+8]` sem base não são endereços).
const LOWEST_ADDRESS: u64 = 0x1_0000;
/// IMAGE_REL_BASED_DIR64.
const REL_DIR64: u16 = 10;

/// O tipo de uma referência.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefKind {
    Call,
    Jump,
    /// `call [__imp_X]`.
    ImportCall,
    /// `jmp [__imp_X]` (um trampolim).
    ImportJump,
    /// Operando de memória lido ou gravado.
    Memory,
    /// `lea` (o endereço, não o conteúdo).
    Address,
    /// Imediato que cai no módulo.
    Immediate,
    /// Ponteiro nos dados (pela `.reloc`).
    Data,
}

impl RefKind {
    pub fn name(self) -> &'static str {
        match self {
            RefKind::Call => "chamada",
            RefKind::Jump => "salto",
            RefKind::ImportCall => "chamada pela IAT",
            RefKind::ImportJump => "salto pela IAT",
            RefKind::Memory => "memória",
            RefKind::Address => "endereço (lea)",
            RefKind::Immediate => "imediato",
            RefKind::Data => "ponteiro nos dados",
        }
    }
}

/// Uma referência: de onde (instrução ou slot de dados) para onde.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ref {
    pub from: u64,
    pub to: u64,
    pub kind: RefKind,
}

/// A forma guardada nos lotes (16 bytes): o destino, o RVA de origem e o
/// tipo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    to: u64,
    from: u32,
    kind: RefKind,
}

/// Uma função da `.pdata` com os pedaços dela.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    pub start: u64,
    /// O fim do pedaço principal.
    pub end: u64,
    /// Os pedaços (começo, fim); o principal primeiro.
    pub chunks: Vec<(u64, u64)>,
}

impl Function {
    pub fn contains(&self, address: u64) -> bool {
        self.chunks.iter().any(|&(start, end)| address >= start && address < end)
    }

    /// Os bytes de código de todos os pedaços.
    pub fn size(&self) -> u64 {
        self.chunks.iter().map(|&(start, end)| end - start).sum()
    }
}

/// O andamento da análise.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    pub done: usize,
    pub total: usize,
    pub finished: bool,
    pub milliseconds: u128,
}

/// A análise de um módulo (compartilhada com a thread que a faz).
pub struct ModuleAnalysis {
    pub base: u64,
    pub end: u64,
    pub name: String,
    /// A geração dos patches da imagem analisada.
    pub generation: u64,
    pub functions: Arc<Vec<Function>>,
    /// (começo, fim, índice da função) de cada pedaço, pelo começo.
    chunks: Vec<(u64, u64, usize)>,
    pub imports: Arc<ImportMap>,
    batches: Mutex<Vec<Arc<Vec<Entry>>>>,
    progress: Mutex<Progress>,
    cancel: AtomicBool,
}

fn u32_le(bytes: &[u8], at: usize) -> u32 {
    bytes.get(at..at + 4).map_or(0, |slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// O cabeçalho PE de uma imagem mapeada.
fn header(image: &ModuleImage) -> Option<PeImage> {
    PeImage::parse_mapped(image.bytes[..image.bytes.len().min(0x1000)].to_vec())
}

/// O começo da função dona de uma entrada da `.pdata` (seguindo os
/// encadeamentos).
fn chain_root(image: &ModuleImage, begin: u32, unwind: u32) -> u32 {
    let (mut begin, mut unwind) = (begin, unwind);
    for _ in 0..16 {
        if unwind & 1 != 0 {
            // O bit 0: a entrada aponta outra RUNTIME_FUNCTION.
            let Some(next) = image.read(image.base + (unwind & !1) as u64, 12).filter(|bytes| bytes.len() == 12) else { break };
            begin = u32_le(&next, 0);
            unwind = u32_le(&next, 8);
            continue;
        }
        let Some(info) = image.read(image.base + unwind as u64, 4).filter(|bytes| bytes.len() == 4) else { break };
        if (info[0] >> 3) & 4 == 0 {
            break;
        }
        // UNW_FLAG_CHAININFO: a RUNTIME_FUNCTION da dona vem depois dos
        // códigos (em número par).
        let count = info[2] as u64;
        let after = unwind as u64 + 4 + 2 * ((count + 1) & !1);
        let Some(next) = image.read(image.base + after, 12).filter(|bytes| bytes.len() == 12) else { break };
        begin = u32_le(&next, 0);
        unwind = u32_le(&next, 8);
    }
    begin
}

/// As funções da `.pdata` da imagem, com os pedaços juntos e ordenadas pelo
/// começo (vazio sem `.pdata`).
pub fn functions(image: &ModuleImage) -> Vec<Function> {
    let Some(header) = header(image) else { return Vec::new() };
    let Some((rva, size)) = header.directory(3).filter(|&(rva, size)| rva != 0 && size >= 12) else { return Vec::new() };
    let Some(table) = image.read(image.base + rva as u64, size as usize) else { return Vec::new() };
    let mut groups: BTreeMap<u32, Vec<(u32, u32)>> = BTreeMap::new();
    for entry in table.chunks_exact(12) {
        let (begin, end, unwind) = (u32_le(entry, 0), u32_le(entry, 4), u32_le(entry, 8));
        if end <= begin || begin == 0 {
            continue;
        }
        let root = chain_root(image, begin, unwind);
        groups.entry(root).or_default().push((begin, end));
    }
    let base = image.base;
    groups
        .into_iter()
        .map(|(root, mut chunks)| {
            chunks.sort_unstable();
            chunks.dedup();
            if let Some(position) = chunks.iter().position(|&(begin, _)| begin == root) {
                let main = chunks.remove(position);
                chunks.insert(0, main);
            }
            let (start, end) = chunks[0];
            Function { start: base + start as u64, end: base + end as u64, chunks: chunks.iter().map(|&(begin, end)| (base + begin as u64, base + end as u64)).collect() }
        })
        .collect()
}

/// Os ponteiros dos dados pela `.reloc` (DIR64): (slot, destino) com o
/// destino dentro do módulo. A imagem do arquivo tem os ponteiros na base
/// preferida do PE; a da memória, já na base em que o módulo carregou.
pub fn data_pointers(image: &ModuleImage) -> Vec<(u64, u64)> {
    let Some(header) = header(image) else { return Vec::new() };
    let Some((rva, size)) = header.directory(5).filter(|&(rva, size)| rva != 0 && size >= 8) else { return Vec::new() };
    let Some(table) = image.read(image.base + rva as u64, size as usize) else { return Vec::new() };
    let preferred = header.header.image_base;
    let shift = |value: u64| if image.source == "memoria" { value } else { value.wrapping_sub(preferred).wrapping_add(image.base) };
    let end = image.base + image.bytes.len() as u64;
    let mut pointers = Vec::new();
    let mut at = 0usize;
    while at + 8 <= table.len() {
        let page = u32_le(&table, at);
        let block = u32_le(&table, at + 4) as usize;
        if block < 8 || at + block > table.len() {
            break;
        }
        for index in 0..(block - 8) / 2 {
            let offset = at + 8 + 2 * index;
            let entry = u16::from_le_bytes([table[offset], table[offset + 1]]);
            if entry >> 12 != REL_DIR64 {
                continue;
            }
            let slot = image.base + page as u64 + (entry & 0xFFF) as u64;
            let Some(bytes) = image.read(slot, 8).filter(|bytes| bytes.len() == 8) else { continue };
            let value = u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]));
            let target = shift(value);
            if target >= image.base && target < end {
                pointers.push((slot, target));
            }
        }
        at += block;
    }
    pointers
}

/// As referências de uma faixa de código.
fn references(image: &ModuleImage, imports: &ImportMap, start: u64, end: u64, output: &mut Vec<Entry>) {
    let image_end = image.base + image.bytes.len() as u64;
    if start < image.base || end > image_end || end <= start {
        return;
    }
    let slice = &image.bytes[(start - image.base) as usize..(end - image.base) as usize];
    let inside = |address: u64| address >= image.base && address < image_end;
    for insn in decode::decode_all(slice, start) {
        let from = (insn.address - image.base) as u32;
        if let Some(target) = insn.target {
            let kind = if insn.flow == Flow::Call { RefKind::Call } else { RefKind::Jump };
            output.push(Entry { to: target, from, kind });
        }
        if let Some(memory) = insn.memory {
            let import = imports.contains(memory);
            let kind = match insn.flow {
                Flow::IndirectCall if import => RefKind::ImportCall,
                Flow::IndirectJump if import => RefKind::ImportJump,
                _ if insn.class == Class::Lea => RefKind::Address,
                _ => RefKind::Memory,
            };
            if import || inside(memory) || memory >= LOWEST_ADDRESS {
                output.push(Entry { to: memory, from, kind });
            }
        }
        if let Some(value) = insn.immediate.filter(|&value| inside(value)) {
            output.push(Entry { to: value, from, kind: RefKind::Immediate });
        }
    }
}

impl ModuleAnalysis {
    /// Prepara a análise (as funções e os pedaços já ficam prontos).
    pub fn new(image: &ModuleImage, imports: Arc<ImportMap>, generation: u64) -> ModuleAnalysis {
        let functions = functions(image);
        let mut chunks: Vec<(u64, u64, usize)> = functions.iter().enumerate().flat_map(|(index, function)| function.chunks.iter().map(move |&(start, end)| (start, end, index))).collect();
        chunks.sort_unstable();
        ModuleAnalysis {
            base: image.base,
            end: image.base + image.bytes.len() as u64,
            name: image.name.clone(),
            generation,
            functions: Arc::new(functions),
            chunks,
            imports,
            batches: Mutex::new(Vec::new()),
            progress: Mutex::new(Progress::default()),
            cancel: AtomicBool::new(false),
        }
    }

    /// Começa a análise numa thread própria.
    pub fn start(image: Arc<ModuleImage>, imports: Arc<ImportMap>, generation: u64) -> Arc<ModuleAnalysis> {
        let analysis = Arc::new(ModuleAnalysis::new(&image, imports, generation));
        let worker = Arc::clone(&analysis);
        let spawned = std::thread::Builder::new().name(format!("kd-re-analise-{}", image.name)).spawn(move || worker.run(&image));
        if spawned.is_err() {
            // Sem thread: a análise fica marcada como terminada e vazia.
            analysis.finish(0);
        }
        analysis
    }

    /// Faz a análise inteira, lote a lote (a thread chama isto).
    pub fn run(&self, image: &ModuleImage) {
        let started = Instant::now();
        // As faixas de cada lote: funções da .pdata, ou pedaços das seções
        // de código.
        let mut work: Vec<Vec<(u64, u64)>> = Vec::new();
        if self.functions.is_empty() {
            for &(start, end) in &image.code {
                let mut at = start;
                while at < end {
                    let stop = (at + BATCH_BYTES).min(end);
                    work.push(vec![(at, stop)]);
                    at = stop;
                }
            }
        } else {
            for group in self.functions.chunks(BATCH_FUNCTIONS) {
                work.push(group.iter().flat_map(|function| function.chunks.iter().copied()).collect());
            }
        }
        // O último lote: os ponteiros dos dados.
        let total = work.len() + 1;
        self.set_progress(0, total, started);
        for (index, ranges) in work.iter().enumerate() {
            if self.cancel.load(Ordering::Relaxed) {
                return;
            }
            let mut entries = Vec::new();
            for &(start, end) in ranges {
                references(image, &self.imports, start, end, &mut entries);
            }
            self.push_batch(entries);
            self.set_progress(index + 1, total, started);
        }
        let entries: Vec<Entry> = data_pointers(image).into_iter().map(|(slot, target)| Entry { to: target, from: (slot - image.base) as u32, kind: RefKind::Data }).collect();
        self.push_batch(entries);
        self.finish(started.elapsed().as_millis());
    }

    fn push_batch(&self, mut entries: Vec<Entry>) {
        entries.sort_unstable_by_key(|entry| (entry.to, entry.from));
        if let Ok(mut batches) = self.batches.lock() {
            batches.push(Arc::new(entries));
        }
    }

    fn set_progress(&self, done: usize, total: usize, started: Instant) {
        if let Ok(mut progress) = self.progress.lock() {
            *progress = Progress { done, total, finished: false, milliseconds: started.elapsed().as_millis() };
        }
    }

    fn finish(&self, milliseconds: u128) {
        if let Ok(mut progress) = self.progress.lock() {
            progress.done = progress.total;
            progress.finished = true;
            progress.milliseconds = milliseconds;
        }
    }

    /// Para a thread (a análise ficou velha).
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn progress(&self) -> Progress {
        self.progress.lock().map(|progress| *progress).unwrap_or_default()
    }

    /// Quem referencia `target`, com o que já foi analisado, pela origem.
    pub fn references_to(&self, target: u64) -> Vec<Ref> {
        let batches: Vec<Arc<Vec<Entry>>> = self.batches.lock().map(|batches| batches.clone()).unwrap_or_default();
        let mut found = Vec::new();
        for batch in batches {
            let start = batch.partition_point(|entry| entry.to < target);
            for entry in batch[start..].iter().take_while(|entry| entry.to == target) {
                found.push(Ref { from: self.base + entry.from as u64, to: target, kind: entry.kind });
            }
        }
        found.sort_by_key(|reference| (reference.from, reference.kind));
        found.dedup();
        found
    }

    /// A função (da `.pdata`) que contém o endereço.
    pub fn function_at(&self, address: u64) -> Option<&Function> {
        let index = self.chunks.partition_point(|&(start, _, _)| start <= address);
        let &(_, end, function) = self.chunks.get(index.checked_sub(1)?)?;
        (address < end).then(|| &self.functions[function])
    }
}

/// As referências que saem de uma função (os pedaços dela), decodificadas
/// na hora: chamadas, saltos para fora dela, a IAT, a memória, os endereços
/// e os imediatos no módulo. Pela origem.
pub fn references_from(image: &ModuleImage, imports: &ImportMap, function: &Function) -> Vec<Ref> {
    let mut entries = Vec::new();
    for &(start, end) in &function.chunks {
        references(image, imports, start, end, &mut entries);
    }
    let mut found: Vec<Ref> = entries
        .into_iter()
        .map(|entry| Ref { from: image.base + entry.from as u64, to: entry.to, kind: entry.kind })
        // Os saltos dentro da própria função são o fluxo dela, não saídas.
        .filter(|reference| reference.kind != RefKind::Jump || !function.contains(reference.to))
        .collect();
    found.sort_by_key(|reference| (reference.from, reference.kind));
    found
}

/// Uma faixa sem `.pdata` vira uma função de um pedaço (o símbolo do ELF
/// com tamanho, ou a extensão do fluxo).
pub fn plain_function(start: u64, end: u64) -> Function {
    Function { start, end, chunks: vec![(start, end)] }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::tests::{mapped_pe, put_u32, put_u64};

    const BASE: u64 = 0x7FF8_0000_0000;

    /// Uma imagem com `.pdata` (diretório 3 em 0x300), `.reloc` (diretório
    /// 5 em 0x380) e código em 0x1000:
    ///
    /// - função A em 0x1000..0x1010: `call B`, `lea rcx, [rip->0x3000]`,
    ///   `nop`s e `ret`;
    /// - função B em 0x1010..0x1020: `ret`;
    /// - o pedaço frio de A em 0x1100..0x1108 (UNWIND_INFO encadeado em
    ///   0x400 apontando a entrada de A), com `call [rip->IAT 0x2000]`;
    /// - em 0x3010, um ponteiro para B listado na `.reloc`.
    fn sample() -> ModuleImage {
        let mut bytes = mapped_pe(0x4000, 0x1_8000_0000, &[(3, 0x300, 36), (5, 0x380, 12)]);
        // .pdata: A, B, pedaço frio.
        for (index, (begin, end, unwind)) in [(0x1000u32, 0x1010u32, 0x410u32), (0x1010, 0x1020, 0x410), (0x1100, 0x1108, 0x400)].iter().enumerate() {
            put_u32(&mut bytes, 0x300 + 12 * index, *begin);
            put_u32(&mut bytes, 0x304 + 12 * index, *end);
            put_u32(&mut bytes, 0x308 + 12 * index, *unwind);
        }
        // UNWIND_INFO encadeado: versão 1, flags CHAININFO (4), 0 códigos;
        // depois a RUNTIME_FUNCTION de A.
        bytes[0x400] = 1 | (4 << 3);
        put_u32(&mut bytes, 0x404, 0x1000);
        put_u32(&mut bytes, 0x408, 0x1010);
        put_u32(&mut bytes, 0x40C, 0x410);
        // UNWIND_INFO simples de A e B.
        bytes[0x410] = 1;
        // .reloc: página 0x3000, um DIR64 em +0x10 e um preenchimento.
        put_u32(&mut bytes, 0x380, 0x3000);
        put_u32(&mut bytes, 0x384, 12);
        bytes[0x388..0x38A].copy_from_slice(&((REL_DIR64 << 12) | 0x10).to_le_bytes());
        // O ponteiro em 0x3010 aponta B (na base preferida do arquivo).
        put_u64(&mut bytes, 0x3010, 0x1_8000_0000 + 0x1010);
        // A: call B (0x1000, 5 bytes), lea rcx, [rip+x] (0x1005, 7 bytes),
        // nop, nop, nop, ret (0x100C).
        let code = 0x1000usize;
        bytes[code] = 0xE8;
        put_u32(&mut bytes, code + 1, (0x1010i64 - 0x1005) as u32);
        bytes[code + 5..code + 8].copy_from_slice(&[0x48, 0x8D, 0x0D]);
        put_u32(&mut bytes, code + 8, (0x3000i64 - 0x100C) as u32);
        bytes[code + 0xC..code + 0x10].copy_from_slice(&[0x90, 0x90, 0x90, 0xC3]);
        // B: ret.
        bytes[0x1010] = 0xC3;
        // Pedaço frio: call [rip+x] para o slot 0x2000, ret.
        bytes[0x1100..0x1102].copy_from_slice(&[0xFF, 0x15]);
        put_u32(&mut bytes, 0x1102, (0x2000i64 - 0x1106) as u32);
        bytes[0x1106] = 0xC3;
        ModuleImage { base: BASE, end: BASE + 0x4000, name: "teste".into(), bytes, code: vec![(BASE + 0x1000, BASE + 0x1200)], sections: Vec::new(), source: "arquivo" }
    }

    fn imports() -> ImportMap {
        // Um import no slot 0x2000, montado pelo mesmo leitor de PE.
        let mut bytes = mapped_pe(0x1000, 0x1_8000_0000, &[(1, 0x400, 40)]);
        put_u32(&mut bytes, 0x400, 0x500);
        put_u32(&mut bytes, 0x40C, 0x700);
        put_u32(&mut bytes, 0x410, 0x2000 - 0x1000);
        bytes[0x700..0x709].copy_from_slice(b"ntdll.dll");
        put_u64(&mut bytes, 0x500, 0x720);
        bytes[0x722..0x729].copy_from_slice(b"NtClose");
        let image = PeImage::parse_mapped(bytes).unwrap();
        // A IAT em RVA 0x1000 da imagem de 0x1000 bytes: base + 0x1000 =
        // BASE + 0x2000.
        ImportMap::from_pe(BASE + 0x1000, &image)
    }

    #[test]
    fn merges_chained_chunks() {
        let image = sample();
        let functions = functions(&image);
        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].start, BASE + 0x1000);
        assert_eq!(functions[0].chunks, vec![(BASE + 0x1000, BASE + 0x1010), (BASE + 0x1100, BASE + 0x1108)]);
        assert!(functions[0].contains(BASE + 0x1104));
        assert_eq!(functions[0].size(), 0x18);
        assert_eq!(functions[1].chunks, vec![(BASE + 0x1010, BASE + 0x1020)]);
    }

    #[test]
    fn reads_data_pointers() {
        let image = sample();
        assert_eq!(data_pointers(&image), vec![(BASE + 0x3010, BASE + 0x1010)]);
    }

    #[test]
    fn indexes_references_in_batches() {
        let image = sample();
        let imports = Arc::new(imports());
        assert!(imports.contains(BASE + 0x2000));
        let analysis = ModuleAnalysis::new(&image, Arc::clone(&imports), 0);
        analysis.run(&image);
        let progress = analysis.progress();
        assert!(progress.finished);
        assert_eq!(progress.done, progress.total);
        // B: chamada de A e o ponteiro da .reloc.
        let to_b = analysis.references_to(BASE + 0x1010);
        assert_eq!(to_b, vec![Ref { from: BASE + 0x1000, to: BASE + 0x1010, kind: RefKind::Call }, Ref { from: BASE + 0x3010, to: BASE + 0x1010, kind: RefKind::Data }]);
        // O lea e a IAT.
        assert_eq!(analysis.references_to(BASE + 0x3000), vec![Ref { from: BASE + 0x1005, to: BASE + 0x3000, kind: RefKind::Address }]);
        assert_eq!(analysis.references_to(BASE + 0x2000), vec![Ref { from: BASE + 0x1100, to: BASE + 0x2000, kind: RefKind::ImportCall }]);
        // A função do pedaço frio é A.
        assert_eq!(analysis.function_at(BASE + 0x1104).map(|function| function.start), Some(BASE + 0x1000));
        assert_eq!(analysis.function_at(BASE + 0x1050), None);
        // O que sai de A: a chamada, o lea e a IAT.
        let from_a = references_from(&image, &imports, &analysis.functions[0]);
        let kinds: Vec<RefKind> = from_a.iter().map(|reference| reference.kind).collect();
        assert_eq!(kinds, vec![RefKind::Call, RefKind::Address, RefKind::ImportCall]);
    }

    #[test]
    fn linear_sweep_without_pdata() {
        let mut image = sample();
        // Sem o diretório 3: as faixas de código viram os lotes.
        let optional = 0x80 + 24;
        let at = optional + 112 + 8 * 3;
        image.bytes[at..at + 8].copy_from_slice(&[0; 8]);
        let analysis = ModuleAnalysis::new(&image, Arc::new(ImportMap::default()), 0);
        assert!(analysis.functions.is_empty());
        analysis.run(&image);
        assert!(analysis.references_to(BASE + 0x1010).iter().any(|reference| reference.kind == RefKind::Call));
    }
}
