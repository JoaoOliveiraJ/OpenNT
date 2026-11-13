//! Histórico opcional de referências — `system32/ntos/ob/reference-trace.js`.
//!
//! Registra chamadas reais sem reter o objeto observado; a capacidade fixa
//! impede o crescimento durante o boot. Desligado por padrão.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::rtl::SpinLock;

const TRACE_CAPACITY: usize = 1024;
/// 'Dflt'.
pub const DEFAULT_TAG: u32 = 0x746C_6644;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub sequence: u64,
    pub pointer: u64,
    pub tag: u32,
    pub delta: i32,
}

struct Trace {
    entries: Vec<Option<Entry>>,
    next: usize,
    count: usize,
    sequence: u64,
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static TRACE: SpinLock<Trace> = SpinLock::new(Trace { entries: Vec::new(), next: 0, count: 0, sequence: 0 });

/// Liga ou desliga só a observação; contadores e destrutores seguem seus donos.
pub fn set_enabled(value: bool) {
    ENABLED.store(value, Ordering::Release);
}

pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

/// O kernel registra a tentativa antes de alterar a referência, inclusive no erro.
pub fn record(pointer: u64, tag: u32, delta: i32) {
    if !is_enabled() {
        return;
    }
    let mut trace = TRACE.lock();
    if trace.entries.is_empty() {
        trace.entries = alloc::vec![None; TRACE_CAPACITY];
    }
    trace.sequence += 1;
    let (next, sequence) = (trace.next, trace.sequence);
    trace.entries[next] = Some(Entry { sequence, pointer, tag, delta });
    trace.next = (next + 1) % TRACE_CAPACITY;
    trace.count = (trace.count + 1).min(TRACE_CAPACITY);
}

/// Cópias em ordem cronológica.
pub fn snapshot() -> Vec<Entry> {
    let trace = TRACE.lock();
    (0..trace.count).filter_map(|index| trace.entries.get((trace.next + TRACE_CAPACITY - trace.count + index) % TRACE_CAPACITY).copied().flatten()).collect()
}

/// Descarta as observações sem tocar na vida dos objetos.
pub fn clear() {
    let mut trace = TRACE.lock();
    trace.entries.iter_mut().for_each(|entry| *entry = None);
    trace.next = 0;
    trace.count = 0;
    trace.sequence = 0;
}
