//! IPC do nanokernel — canais nomeados de mensagens entre serviços e
//! processos. O produtor não conhece
//! o consumidor.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;

use crate::rtl::SpinLock;

static CHANNELS: SpinLock<BTreeMap<String, VecDeque<String>>> = SpinLock::new(BTreeMap::new());

pub fn create_channel(name: &str) {
    CHANNELS.lock().entry(String::from(name)).or_default();
}

pub fn send(name: &str, message: impl Into<String>) {
    CHANNELS.lock().entry(String::from(name)).or_default().push_back(message.into());
}

/// Não bloqueante: mensagem ou `None`.
pub fn receive(name: &str) -> Option<String> {
    CHANNELS.lock().get_mut(name).and_then(|queue| queue.pop_front())
}

pub fn pending(name: &str) -> usize {
    CHANNELS.lock().get(name).map_or(0, |queue| queue.len())
}

pub fn list() -> Vec<String> {
    CHANNELS.lock().keys().cloned().collect()
}
