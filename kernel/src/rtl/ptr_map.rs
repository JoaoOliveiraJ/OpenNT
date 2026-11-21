//! Mapa pelo endereço de um objeto (u64), com endereçamento aberto.
//!
//! Os registros consultados a cada referência, handle ou sondagem (o corpo
//! de cada objeto de despacho, os pulsos dos eventos) eram `BTreeMap`: cada
//! busca percorria alguns nós comparando chave a chave, e no perfil do boot
//! essas buscas somavam alguns por cento do tempo de CPU. Aqui a chave vai
//! direto a uma posição (o endereço sem os bits de alinhamento, espalhado
//! pela multiplicação de Fibonacci) e a sondagem é linear; a remoção puxa
//! para trás as entradas seguintes do mesmo grupo (sem lápides). A tabela
//! dobra com metade das posições ocupadas.

use alloc::vec::Vec;

pub struct PtrMap<V> {
    slots: Vec<Option<(u64, V)>>,
    len: usize,
}

impl<V> PtrMap<V> {
    pub const fn new() -> Self {
        PtrMap { slots: Vec::new(), len: 0 }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn mask(&self) -> usize {
        self.slots.len() - 1
    }

    fn home(&self, key: u64) -> usize {
        let bits = self.slots.len().trailing_zeros();
        ((key >> 4).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> (64 - bits)) as usize
    }

    /// A posição de `key`, se está no mapa.
    fn find(&self, key: u64) -> Option<usize> {
        if self.len == 0 {
            return None;
        }
        let mask = self.mask();
        let mut index = self.home(key);
        loop {
            match &self.slots[index] {
                None => return None,
                Some((candidate, _)) if *candidate == key => return Some(index),
                Some(_) => index = (index + 1) & mask,
            }
        }
    }

    pub fn get(&self, key: &u64) -> Option<&V> {
        self.find(*key).and_then(|index| self.slots[index].as_ref()).map(|(_, value)| value)
    }

    pub fn get_mut(&mut self, key: &u64) -> Option<&mut V> {
        let index = self.find(*key)?;
        self.slots[index].as_mut().map(|(_, value)| value)
    }

    pub fn contains_key(&self, key: &u64) -> bool {
        self.find(*key).is_some()
    }

    fn grow(&mut self) {
        let capacity = (self.slots.len() * 2).max(16);
        let old = core::mem::replace(&mut self.slots, Vec::with_capacity(capacity));
        self.slots.resize_with(capacity, || None);
        self.len = 0;
        for (key, value) in old.into_iter().flatten() {
            self.insert(key, value);
        }
    }

    /// Insere ou troca; devolve o valor anterior.
    pub fn insert(&mut self, key: u64, value: V) -> Option<V> {
        if (self.len + 1) * 2 > self.slots.len() {
            self.grow();
        }
        let mask = self.mask();
        let mut index = self.home(key);
        loop {
            match &mut self.slots[index] {
                None => {
                    self.slots[index] = Some((key, value));
                    self.len += 1;
                    return None;
                }
                Some((candidate, existing)) if *candidate == key => return Some(core::mem::replace(existing, value)),
                Some(_) => index = (index + 1) & mask,
            }
        }
    }

    pub fn remove(&mut self, key: &u64) -> Option<V> {
        let mut hole = self.find(*key)?;
        let (_, value) = self.slots[hole].take()?;
        self.len -= 1;
        // As entradas seguintes do grupo cuja posição de origem não fica
        // entre o buraco e elas voltam para o buraco.
        let mask = self.mask();
        let mut next = (hole + 1) & mask;
        while let Some((candidate, _)) = &self.slots[next] {
            let home = self.home(*candidate);
            let between = if hole <= next { hole < home && home <= next } else { hole < home || home <= next };
            if !between {
                self.slots[hole] = self.slots[next].take();
                hole = next;
            }
            next = (next + 1) & mask;
        }
        Some(value)
    }

    pub fn iter(&self) -> impl Iterator<Item = (u64, &V)> {
        self.slots.iter().filter_map(|slot| slot.as_ref().map(|(key, value)| (*key, value)))
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.slots.iter().filter_map(|slot| slot.as_ref().map(|(_, value)| value))
    }

    pub fn keys(&self) -> impl Iterator<Item = u64> + '_ {
        self.slots.iter().filter_map(|slot| slot.as_ref().map(|(key, _)| *key))
    }

    /// Mantém só as entradas para as quais `keep` devolve verdadeiro.
    pub fn retain(&mut self, mut keep: impl FnMut(u64, &mut V) -> bool) {
        let mut doomed: Vec<u64> = Vec::new();
        for (key, value) in self.slots.iter_mut().flatten() {
            if !keep(*key, value) {
                doomed.push(*key);
            }
        }
        for key in doomed {
            self.remove(&key);
        }
    }
}

impl<V> Default for PtrMap<V> {
    fn default() -> Self {
        Self::new()
    }
}
