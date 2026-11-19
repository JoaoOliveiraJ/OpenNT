//! O rastro de instruções: o formato dos registros que o depurador do
//! kernel grava passo a passo dentro do convidado (`kernel/src/ntos/kd/
//! trace.rs`), o estado dos registradores em qualquer ponto do rastro
//! (pontos de controle mais as diferenças), a árvore de chamadas, a
//! comparação de dois rastros, a exportação em CSV e o log de execução do
//! QEMU (`-d exec,nochain`, o caminho rápido sob o TCG).
//!
//! Um lote (o que o `qOpenNTTrace` lê) é um cabeçalho de 32 bytes e os
//! registros:
//!
//! ```text
//! cabeçalho: "OTRC" | versão u8 | CPU u8 | motivo u8 | flags u8 |
//!            registros u32 | bytes u32 | passos u64 | reservado u64
//! registro:  flags u8 | máscara u32 | RIP u64 | profundidade i16 |
//!            [thread u64] [vigia u64] [pulados u32] | valores u64 x bits da máscara
//! ```
//!
//! As flags do registro: bits 0-1 a classe da instrução no RIP (1 `call`,
//! 2 `ret`), bit 2 a thread corrente veio, bit 3 o valor da vigia veio, bit
//! 4 instruções não gravadas antes deste registro (o filtro de módulos ou
//! de profundidade). A máscara diz quais registradores mudaram, na ordem
//! `REGISTERS`; o primeiro registro de cada lote traz todos.

use std::collections::HashMap;

/// Os registradores de cada passo, na ordem dos bits da máscara.
pub const REGISTERS: [&str; 17] = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rflags"];
pub const FULL_MASK: u32 = (1 << 17) - 1;
pub const HEADER_SIZE: usize = 32;
pub const MAGIC: &[u8; 4] = b"OTRC";

pub const FLAG_CLASS: u8 = 3;
pub const FLAG_THREAD: u8 = 4;
pub const FLAG_WATCH: u8 = 8;
pub const FLAG_SKIPPED: u8 = 16;

/// Por que o lote terminou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Running,
    Count,
    Address,
    Return,
    EnteredModule,
    LeftModule,
    BufferFull,
    Unsafe,
    Breakpoint,
    Interrupted,
    Other(u8),
}

impl Reason {
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => Reason::Running,
            1 => Reason::Count,
            2 => Reason::Address,
            3 => Reason::Return,
            4 => Reason::EnteredModule,
            5 => Reason::LeftModule,
            6 => Reason::BufferFull,
            7 => Reason::Unsafe,
            8 => Reason::Breakpoint,
            9 => Reason::Interrupted,
            other => Reason::Other(other),
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Reason::Running => 0,
            Reason::Count => 1,
            Reason::Address => 2,
            Reason::Return => 3,
            Reason::EnteredModule => 4,
            Reason::LeftModule => 5,
            Reason::BufferFull => 6,
            Reason::Unsafe => 7,
            Reason::Breakpoint => 8,
            Reason::Interrupted => 9,
            Reason::Other(code) => code,
        }
    }

    pub fn text(self) -> &'static str {
        match self {
            Reason::Running => "em andamento",
            Reason::Count => "chegou ao numero de instrucoes",
            Reason::Address => "chegou ao endereco",
            Reason::Return => "a funcao retornou",
            Reason::EnteredModule => "entrou no modulo",
            Reason::LeftModule => "saiu do modulo",
            Reason::BufferFull => "buffer cheio (continua no proximo lote)",
            Reason::Unsafe => "parou antes de uma instrucao que nao pode ser rastreada (iretq, sysret, hlt, int)",
            Reason::Breakpoint => "chegou a um breakpoint",
            Reason::Interrupted => "interrompido",
            Reason::Other(_) => "motivo desconhecido",
        }
    }
}

/// A classe da instrução no RIP do registro.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Other,
    Call,
    Return,
}

impl Class {
    fn from_bits(bits: u8) -> Self {
        match bits & FLAG_CLASS {
            1 => Class::Call,
            2 => Class::Return,
            _ => Class::Other,
        }
    }

    fn bits(self) -> u8 {
        match self {
            Class::Other => 0,
            Class::Call => 1,
            Class::Return => 2,
        }
    }
}

/// O cabeçalho de um lote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub cpu: u8,
    pub reason: Reason,
    pub records: u32,
    pub bytes: u32,
    pub steps: u64,
}

impl Header {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < HEADER_SIZE || &bytes[..4] != MAGIC {
            return Err("rastro: cabecalho invalido".into());
        }
        if bytes[4] != 1 {
            return Err(format!("rastro: versao {} desconhecida", bytes[4]));
        }
        Ok(Header {
            cpu: bytes[5],
            reason: Reason::from_code(bytes[6]),
            records: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            bytes: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
            steps: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&[1, self.cpu, self.reason.code(), 0]);
        bytes.extend_from_slice(&self.records.to_le_bytes());
        bytes.extend_from_slice(&self.bytes.to_le_bytes());
        bytes.extend_from_slice(&self.steps.to_le_bytes());
        bytes.extend_from_slice(&[0; 8]);
        bytes
    }
}

/// Um passo gravado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub rip: u64,
    pub class: Class,
    /// Profundidade de chamada relativa ao começo do rastro.
    pub depth: i32,
    pub thread: u64,
    pub watch: Option<u64>,
    /// Registradores que mudaram desde o registro anterior (bits de `REGISTERS`).
    pub changed: u32,
    /// Instruções executadas e não gravadas logo antes deste registro.
    pub skipped: u32,
    pub cpu: u8,
}

/// Um registro para o codificador (os testes e o caminho do QEMU).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawRecord {
    pub rip: u64,
    pub class: Class,
    pub depth: i16,
    pub thread: Option<u64>,
    pub watch: Option<u64>,
    pub skipped: u32,
    pub registers: [u64; 17],
}

/// Codifica registros em formato de lote (a mesma regra do convidado: o
/// primeiro com todos os registradores, os outros com as diferenças).
pub fn encode_records(records: &[RawRecord]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut previous: Option<[u64; 17]> = None;
    for record in records {
        let mask = match previous {
            None => FULL_MASK,
            Some(before) => (0..17).filter(|&index| before[index] != record.registers[index]).fold(0, |mask, index| mask | 1 << index),
        };
        let mut flags = record.class.bits();
        if record.thread.is_some() {
            flags |= FLAG_THREAD;
        }
        if record.watch.is_some() {
            flags |= FLAG_WATCH;
        }
        if record.skipped != 0 {
            flags |= FLAG_SKIPPED;
        }
        bytes.push(flags);
        bytes.extend_from_slice(&mask.to_le_bytes());
        bytes.extend_from_slice(&record.rip.to_le_bytes());
        bytes.extend_from_slice(&record.depth.to_le_bytes());
        if let Some(thread) = record.thread {
            bytes.extend_from_slice(&thread.to_le_bytes());
        }
        if let Some(watch) = record.watch {
            bytes.extend_from_slice(&watch.to_le_bytes());
        }
        if record.skipped != 0 {
            bytes.extend_from_slice(&record.skipped.to_le_bytes());
        }
        for (index, value) in record.registers.iter().enumerate() {
            if mask & (1 << index) != 0 {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
        }
        previous = Some(record.registers);
    }
    bytes
}

/// De onde veio o rastro.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Passo a passo dentro do convidado (registradores completos).
    Stub,
    /// Log de execução do QEMU (só o RIP).
    Qemu,
    /// Lido de um CSV exportado.
    File,
}

const CHECKPOINT: usize = 256;

/// Um rastro inteiro (vários lotes).
#[derive(Clone)]
pub struct Trace {
    pub records: Vec<Record>,
    pub source: Source,
    /// Valores dos registradores que mudaram, na ordem dos registros.
    values: Vec<u64>,
    /// Onde começam os valores de cada registro.
    offsets: Vec<u32>,
    /// Estado completo a cada `CHECKPOINT` registros.
    checkpoints: Vec<[u64; 17]>,
    current: [u64; 17],
    thread: u64,
    pub steps: u64,
    pub reason: Reason,
    pub batches: usize,
}

impl Default for Trace {
    fn default() -> Self {
        Self::new(Source::Stub)
    }
}

impl Trace {
    pub fn new(source: Source) -> Self {
        Trace { records: Vec::new(), source, values: Vec::new(), offsets: Vec::new(), checkpoints: Vec::new(), current: [0; 17], thread: 0, steps: 0, reason: Reason::Running, batches: 0 }
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn push(&mut self, mut record: Record, changed: &[(usize, u64)]) {
        if record.thread == 0 {
            record.thread = self.thread;
        }
        self.thread = record.thread;
        self.offsets.push(self.values.len() as u32);
        for &(index, value) in changed {
            self.current[index] = value;
            self.values.push(value);
        }
        if self.records.len() % CHECKPOINT == 0 {
            self.checkpoints.push(self.current);
        }
        self.records.push(record);
    }

    /// Acrescenta um lote (cabeçalho e registros).
    pub fn append_batch(&mut self, bytes: &[u8]) -> Result<Header, String> {
        let header = Header::parse(bytes)?;
        let body = bytes.get(HEADER_SIZE..HEADER_SIZE + header.bytes as usize).ok_or("rastro: lote truncado")?;
        self.append_records(body, header.records as usize, header.cpu)?;
        self.steps = header.steps;
        self.reason = header.reason;
        self.batches += 1;
        Ok(header)
    }

    /// Decodifica `count` registros.
    pub fn append_records(&mut self, body: &[u8], count: usize, cpu: u8) -> Result<(), String> {
        let mut at = 0;
        let take = |at: &mut usize, size: usize| -> Result<&[u8], String> {
            let slice = body.get(*at..*at + size).ok_or_else(|| format!("rastro: registro truncado em {at}", at = *at))?;
            *at += size;
            Ok(slice)
        };
        for _ in 0..count {
            let flags = take(&mut at, 1)?[0];
            let mask = u32::from_le_bytes(take(&mut at, 4)?.try_into().unwrap());
            let rip = u64::from_le_bytes(take(&mut at, 8)?.try_into().unwrap());
            let depth = i16::from_le_bytes(take(&mut at, 2)?.try_into().unwrap()) as i32;
            let thread = if flags & FLAG_THREAD != 0 { u64::from_le_bytes(take(&mut at, 8)?.try_into().unwrap()) } else { 0 };
            let watch = if flags & FLAG_WATCH != 0 { Some(u64::from_le_bytes(take(&mut at, 8)?.try_into().unwrap())) } else { None };
            let skipped = if flags & FLAG_SKIPPED != 0 { u32::from_le_bytes(take(&mut at, 4)?.try_into().unwrap()) } else { 0 };
            let mut changed = Vec::new();
            for index in 0..17 {
                if mask & (1 << index) != 0 {
                    changed.push((index, u64::from_le_bytes(take(&mut at, 8)?.try_into().unwrap())));
                }
            }
            // O registro "cheio" de um lote novo só conta o que mudou mesmo.
            let real_mask = changed.iter().filter(|&&(index, value)| self.records.is_empty() || self.current[index] != value).fold(0u32, |mask, &(index, _)| mask | 1 << index);
            self.push(Record { rip, class: Class::from_bits(flags), depth, thread, watch, changed: real_mask, skipped, cpu }, &changed);
        }
        Ok(())
    }

    /// Um registro só com o RIP (o caminho do QEMU).
    pub fn push_rip(&mut self, cpu: u8, rip: u64, class: Class, depth: i32) {
        self.push(Record { rip, class, depth, thread: 0, watch: None, changed: 0, skipped: 0, cpu }, &[]);
    }

    /// Os registradores antes de executar a instrução do registro `index`.
    pub fn registers_at(&self, index: usize) -> [u64; 17] {
        let checkpoint = index / CHECKPOINT;
        let mut state = self.checkpoints.get(checkpoint).copied().unwrap_or([0; 17]);
        for position in checkpoint * CHECKPOINT + 1..=index.min(self.records.len().saturating_sub(1)) {
            self.apply(position, &mut state);
        }
        state
    }

    fn apply(&self, position: usize, state: &mut [u64; 17]) {
        let start = self.offsets[position] as usize;
        let end = self.offsets.get(position + 1).map_or(self.values.len(), |&end| end as usize);
        let record = &self.records[position];
        let mut values = self.values[start..end].iter();
        // Os valores gravados incluem os do registro cheio de cada lote.
        let stored = end - start;
        if stored == 17 {
            for (index, value) in values.enumerate() {
                state[index] = *value;
            }
            return;
        }
        for index in 0..17 {
            if record.changed & (1 << index) != 0 {
                if let Some(value) = values.next() {
                    state[index] = *value;
                }
            }
        }
    }

    /// Os registradores que mudaram no registro `index` (nome, valor).
    pub fn changed_at(&self, index: usize) -> Vec<(&'static str, u64)> {
        let Some(record) = self.records.get(index) else { return Vec::new() };
        let state = self.registers_at(index);
        (0..17).filter(|bit| record.changed & (1 << bit) != 0).map(|bit| (REGISTERS[bit], state[bit])).collect()
    }

    /// A árvore de chamadas pela profundidade de cada registro.
    pub fn call_tree(&self) -> Vec<CallNode> {
        build_call_tree(&self.records.iter().map(|record| record.depth).collect::<Vec<_>>(), &self.records.iter().map(|record| record.rip).collect::<Vec<_>>())
    }

    /// Exporta em CSV: índice, CPU, thread, RIP, símbolo, instrução,
    /// profundidade e os registradores que mudaram.
    pub fn to_csv(&self, symbol: &dyn Fn(u64) -> String, instruction: &dyn Fn(u64) -> String) -> String {
        let mut output = String::from("indice;cpu;thread;rip;simbolo;instrucao;profundidade;mudou\n");
        for (index, record) in self.records.iter().enumerate() {
            let changed: Vec<String> = self.changed_at(index).into_iter().map(|(name, value)| format!("{name}={value:#x}")).collect();
            output.push_str(&format!("{index};{};{:#x};{:#x};{};{};{};{}\n", record.cpu, record.thread, record.rip, symbol(record.rip).replace(';', ","), instruction(record.rip).replace(';', ","), record.depth, changed.join(" ")));
        }
        output
    }

    /// Lê um CSV exportado (RIP, CPU, thread e profundidade; os registradores
    /// que mudaram voltam como diferenças).
    pub fn from_csv(text: &str) -> Result<Trace, String> {
        let mut trace = Trace::new(Source::File);
        for (number, line) in text.lines().enumerate().skip(1) {
            if line.trim().is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split(';').collect();
            if fields.len() < 8 {
                return Err(format!("CSV, linha {}: campos faltando", number + 1));
            }
            let parse = |text: &str| super::parse_number(text).ok_or_else(|| format!("CSV, linha {}: numero invalido {text:?}", number + 1));
            let rip = parse(fields[3])?;
            let changed: Vec<(usize, u64)> = fields[7]
                .split_whitespace()
                .filter_map(|pair| {
                    let (name, value) = pair.split_once('=')?;
                    Some((REGISTERS.iter().position(|register| *register == name)?, super::parse_number(value)?))
                })
                .collect();
            let mask = changed.iter().fold(0u32, |mask, &(index, _)| mask | 1 << index);
            let depth = fields[6].trim().parse::<i32>().unwrap_or(0);
            let record = Record { rip, class: Class::Other, depth, thread: parse(fields[2])?, watch: None, changed: mask, skipped: 0, cpu: parse(fields[1])? as u8 };
            trace.push(record, &changed);
        }
        Ok(trace)
    }
}

/// Um nó da árvore de chamadas: a função que começa no registro `start`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallNode {
    pub start: usize,
    /// O último registro dentro desta chamada (incluindo os filhos).
    pub end: usize,
    pub depth: i32,
    pub address: u64,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
    /// Instruções gravadas no próprio nível (sem os filhos).
    pub own: usize,
}

/// Monta a árvore de chamadas: cada subida de profundidade abre um nó
/// filho, cada descida fecha. Um rastro que começa numa função e retorna
/// dela ganha um nó raiz para o chamador.
pub fn build_call_tree(depths: &[i32], rips: &[u64]) -> Vec<CallNode> {
    let mut nodes: Vec<CallNode> = Vec::new();
    if depths.is_empty() {
        return nodes;
    }
    let minimum = depths.iter().copied().min().unwrap_or(0);
    // A raiz fica no nível mais raso que o rastro alcança.
    nodes.push(CallNode { start: 0, end: depths.len() - 1, depth: minimum - 1, address: rips[0], parent: None, children: Vec::new(), own: 0 });
    let mut stack: Vec<usize> = vec![0];
    // Níveis entre a raiz e o primeiro registro (o rastro começou fundo): os
    // chamadores ganham o endereço do primeiro registro no nível deles.
    for depth in minimum..=depths[0] {
        let parent = *stack.last().unwrap();
        let index = nodes.len();
        let address = if depth == depths[0] { rips[0] } else { 0 };
        nodes.push(CallNode { start: 0, end: 0, depth, address, parent: Some(parent), children: Vec::new(), own: 0 });
        nodes[parent].children.push(index);
        stack.push(index);
    }
    for (position, &depth) in depths.iter().enumerate() {
        while nodes[*stack.last().unwrap()].depth > depth && stack.len() > 1 {
            let closed = stack.pop().unwrap();
            nodes[closed].end = position.saturating_sub(1);
        }
        while nodes[*stack.last().unwrap()].depth < depth {
            let parent = *stack.last().unwrap();
            let index = nodes.len();
            nodes.push(CallNode { start: position, end: position, depth: nodes[parent].depth + 1, address: rips[position], parent: Some(parent), children: Vec::new(), own: 0 });
            nodes[parent].children.push(index);
            stack.push(index);
        }
        let current = *stack.last().unwrap();
        if nodes[current].address == 0 {
            nodes[current].address = rips[position];
        }
        nodes[current].own += 1;
        nodes[current].end = position;
    }
    for &open in stack.iter().skip(1) {
        nodes[open].end = depths.len() - 1;
    }
    nodes
}

/// O primeiro ponto em que dois rastros divergem (o RIP diferente, ou um
/// acabou antes): os índices nos dois, alinhados pelo primeiro RIP comum.
pub fn first_divergence(first: &[u64], second: &[u64]) -> Option<(usize, usize)> {
    // Alinha os começos: o primeiro RIP de um no outro (até 4096 passos).
    let (mut a, mut b) = (0usize, 0usize);
    if first.first() != second.first() {
        if let Some(position) = second.iter().take(4096).position(|rip| Some(rip) == first.first()) {
            b = position;
        } else if let Some(position) = first.iter().take(4096).position(|rip| Some(rip) == second.first()) {
            a = position;
        } else {
            return Some((0, 0));
        }
    }
    loop {
        match (first.get(a), second.get(b)) {
            (Some(x), Some(y)) if x == y => {
                a += 1;
                b += 1;
            }
            (None, None) => return None,
            _ => return Some((a, b)),
        }
    }
}

/// O log `-d exec` do QEMU: (CPU, PC) de cada bloco executado, na ordem.
/// Linhas: `Trace 0: 0x7f.. [00000000/fffff80040123456/00c0b0b3/ff200000] `.
pub fn parse_qemu_exec(text: &str) -> Vec<(u8, u64)> {
    text.lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("Trace ")?;
            let (cpu, rest) = rest.split_once(':')?;
            let inside = rest.split_once('[')?.1;
            let pc = inside.split('/').nth(1)?;
            Some((cpu.trim().parse().ok()?, u64::from_str_radix(pc.trim(), 16).ok()?))
        })
        .collect()
}

/// Um texto curto de um registro para o prompt (`trace show`).
pub fn format_record(trace: &Trace, index: usize, symbol: &dyn Fn(u64) -> String) -> String {
    let record = &trace.records[index];
    let changed: Vec<String> = trace.changed_at(index).into_iter().map(|(name, value)| format!("{name}={value:x}")).collect();
    let indent = " ".repeat(record.depth.clamp(0, 40) as usize);
    let watch = record.watch.map(|value| format!(" vigia={value:#x}")).unwrap_or_default();
    format!("{index:>6} cpu{} {:#018x} {indent}{} {}{watch}", record.cpu, record.rip, symbol(record.rip), changed.join(" "))
}

/// A árvore em texto (`trace tree`).
pub fn format_tree(trace: &Trace, symbol: &dyn Fn(u64) -> String, limit: usize) -> String {
    let nodes = trace.call_tree();
    let mut output = String::new();
    let mut lines = 0;
    let mut stack = vec![(0usize, 0usize)];
    while let Some((node, level)) = stack.pop() {
        if lines >= limit {
            output.push_str("...\n");
            break;
        }
        let entry = &nodes[node];
        if node != 0 {
            output.push_str(&format!("{}{} ({} instrucoes, registros {}..{})\n", "  ".repeat(level.saturating_sub(1)), symbol(entry.address), entry.own, entry.start, entry.end));
            lines += 1;
        }
        for &child in entry.children.iter().rev() {
            stack.push((child, level + 1));
        }
    }
    output
}

/// Contagem de instruções por símbolo (o resumo do `trace`).
pub fn histogram(trace: &Trace, symbol: &dyn Fn(u64) -> String) -> Vec<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut cache: HashMap<u64, String> = HashMap::new();
    for record in &trace.records {
        let name = cache.entry(record.rip).or_insert_with(|| {
            let full = symbol(record.rip);
            full.rsplit_once("+0x").map_or(full.clone(), |(name, _)| name.to_string())
        });
        *counts.entry(name.clone()).or_default() += 1;
    }
    let mut list: Vec<(String, usize)> = counts.into_iter().collect();
    list.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    list
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(rip: u64, class: Class, depth: i16, rax: u64, rsp: u64) -> RawRecord {
        let mut registers = [0u64; 17];
        registers[0] = rax;
        registers[7] = rsp;
        registers[16] = 0x246;
        RawRecord { rip, class, depth, thread: None, watch: None, skipped: 0, registers }
    }

    fn batch(records: &[RawRecord], reason: Reason) -> Vec<u8> {
        let body = encode_records(records);
        let mut bytes = Header { cpu: 1, reason, records: records.len() as u32, bytes: body.len() as u32, steps: records.len() as u64 }.encode();
        bytes.extend_from_slice(&body);
        bytes
    }

    #[test]
    fn round_trips_records_and_registers() {
        let mut first = raw(0x1000, Class::Other, 0, 1, 0x8000);
        first.thread = Some(0xffffe000_00003000);
        let records = vec![first, raw(0x1004, Class::Call, 0, 2, 0x8000), raw(0x2000, Class::Other, 1, 2, 0x7ff8), raw(0x2001, Class::Return, 1, 7, 0x7ff8), raw(0x1009, Class::Other, 0, 7, 0x8000)];
        let mut trace = Trace::default();
        let header = trace.append_batch(&batch(&records, Reason::Count)).unwrap();
        assert_eq!(header.cpu, 1);
        assert_eq!(header.reason, Reason::Count);
        assert_eq!(trace.len(), 5);
        assert_eq!(trace.records[1].class, Class::Call);
        assert_eq!(trace.records[2].depth, 1);
        // A thread do primeiro registro vale para os seguintes.
        assert_eq!(trace.records[4].thread, 0xffffe000_00003000);
        assert_eq!(trace.registers_at(3)[0], 7);
        assert_eq!(trace.registers_at(2)[7], 0x7ff8);
        assert_eq!(trace.registers_at(4)[7], 0x8000);
        assert_eq!(trace.changed_at(1), vec![("rax", 2)]);
        assert_eq!(trace.changed_at(2), vec![("rsp", 0x7ff8)]);
        // Um segundo lote começa cheio; só o que mudou de fato conta.
        let more = vec![raw(0x100d, Class::Other, 0, 7, 0x8000), raw(0x1010, Class::Other, 0, 8, 0x8000)];
        trace.append_batch(&batch(&more, Reason::Address)).unwrap();
        assert_eq!(trace.len(), 7);
        assert_eq!(trace.records[5].changed, 0);
        assert_eq!(trace.changed_at(6), vec![("rax", 8)]);
        assert_eq!(trace.reason, Reason::Address);
        assert!(trace.append_batch(b"XXXX").is_err());
    }

    #[test]
    fn checkpoints_keep_long_traces_consistent() {
        let records: Vec<RawRecord> = (0..1000u64).map(|index| raw(0x1000 + index, Class::Other, 0, index * 3, 0x8000)).collect();
        let mut trace = Trace::default();
        trace.append_batch(&batch(&records, Reason::Count)).unwrap();
        for index in [0, 1, 255, 256, 257, 511, 999] {
            assert_eq!(trace.registers_at(index)[0], index as u64 * 3, "registro {index}");
        }
    }

    #[test]
    fn builds_the_call_tree() {
        // main -> f -> g, volta a f, volta a main, chama h, retorna de main.
        let depths = [0, 0, 1, 1, 2, 2, 1, 0, 1, 0, -1];
        let rips = [0x100, 0x104, 0x200, 0x204, 0x300, 0x301, 0x208, 0x108, 0x400, 0x10c, 0x50];
        let nodes = build_call_tree(&depths, &rips);
        // Raiz (nível -2), chamador (-1), main (0) com f e h, f com g.
        let main = nodes.iter().position(|node| node.depth == 0 && node.address == 0x100).unwrap();
        let children: Vec<u64> = nodes[main].children.iter().map(|&child| nodes[child].address).collect();
        assert_eq!(children, vec![0x200, 0x400]);
        let f = nodes[main].children[0];
        assert_eq!(nodes[f].own, 3);
        assert_eq!(nodes[f].end, 6);
        assert_eq!(nodes[nodes[f].children[0]].address, 0x300);
        assert_eq!(nodes[main].own, 4);
        let caller = nodes[main].parent.unwrap();
        assert_eq!(nodes[caller].depth, -1);
        assert_eq!(nodes[caller].own, 1);
        assert_eq!(nodes[caller].address, 0x50);
        assert!(build_call_tree(&[], &[]).is_empty());
        let mut trace = Trace::default();
        for (&depth, &rip) in depths.iter().zip(&rips) {
            trace.push_rip(0, rip, Class::Other, depth);
        }
        let text = format_tree(&trace, &|address| format!("f{address:x}"), 100);
        assert!(text.contains("f200 (3 instrucoes"), "{text}");
    }

    #[test]
    fn finds_the_first_divergence() {
        assert_eq!(first_divergence(&[1, 2, 3, 4], &[1, 2, 3, 4]), None);
        assert_eq!(first_divergence(&[1, 2, 3, 4], &[1, 2, 9, 4]), Some((2, 2)));
        assert_eq!(first_divergence(&[1, 2, 3], &[1, 2, 3, 4]), Some((3, 3)));
        // Começos diferentes: alinha pelo primeiro RIP comum.
        assert_eq!(first_divergence(&[5, 6, 7], &[1, 5, 6, 8]), Some((2, 3)));
        assert_eq!(first_divergence(&[1], &[2]), Some((0, 0)));
    }

    #[test]
    fn csv_round_trip_and_qemu_log() {
        let records = vec![raw(0x1000, Class::Other, 0, 1, 0x8000), raw(0x1004, Class::Other, 0, 2, 0x8000)];
        let mut trace = Trace::default();
        trace.append_batch(&batch(&records, Reason::Count)).unwrap();
        let csv = trace.to_csv(&|address| format!("f+{address:#x}"), &|_| "mov rax; rbx".into());
        assert!(csv.lines().nth(2).unwrap().contains("rax=0x2"), "{csv}");
        let back = Trace::from_csv(&csv).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back.records[1].rip, 0x1004);
        assert_eq!(back.registers_at(1)[0], 2);
        let log = "Trace 0: 0x7f00 [00000000/fffff80040123456/00c0b0b3/ff200000] \nIN:\nTrace 1: 0x7f10 [00000000/0000000000001000/00c0b0b3/ff200000] sym\n";
        assert_eq!(parse_qemu_exec(log), vec![(0, 0xfffff80040123456), (1, 0x1000)]);
        let list = histogram(&trace, &|address| format!("f+{:#x}", address - 0x1000));
        assert_eq!(list, vec![("f".to_string(), 2)]);
    }
}
