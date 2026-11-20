//! Descritores divididos entre os corpos do OpenNT.
//!
//! Os corpos com registro próprio (os objetos de despacho) guardam o
//! descritor de segurança como política. Como o ObLogSecurityDescriptor do
//! ntoskrnl 19041 (0x6d8b90) faz com o OBJECT_HEADER.SecurityDescriptor —
//! o FullHash do descritor, a comparação dos bytes dentro do balde e o
//! RefCount da entrada achada, ou uma entrada nova do ObpCreateCacheEntry
//! (0x6d8e84) —, políticas iguais dividem uma cópia contada. A cópia sai da
//! tabela com o último corpo que a usa, como a entrada que o
//! ObDereferenceSecurityDescriptor (0x6d8380) solta quando o RefCount zera.
//! O cache dos descritores de cabeçalho fica em `object_security.rs`.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::hash::{Hash, Hasher};
use core::mem::ManuallyDrop;
use core::ops::Deref;

use crate::ntos::se::model::SecurityPolicy;
use crate::rtl::SpinLock;

/// As cópias vivas por hash; cada balde compara as políticas inteiras.
static SHARED: SpinLock<BTreeMap<u64, Vec<Weak<SecurityPolicy>>>> = SpinLock::new(BTreeMap::new());

/// FNV-1a de 64 bits sobre os campos da política.
struct Fnv(u64);

impl Hasher for Fnv {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 = (self.0 ^ byte as u64).wrapping_mul(0x0000_0100_0000_01B3);
        }
    }
}

fn hash_of(policy: &SecurityPolicy) -> u64 {
    let mut hasher = Fnv(0xCBF2_9CE4_8422_2325);
    policy.hash(&mut hasher);
    hasher.finish()
}

/// Uma política dividida: a cópia contada da tabela. A última a cair tira a
/// cópia da tabela sob a trava dela, então nenhuma busca acha uma cópia
/// morrendo.
pub struct SharedPolicy(ManuallyDrop<Arc<SecurityPolicy>>);

impl SharedPolicy {
    /// As duas são a mesma cópia (o mesmo descritor do cache).
    pub fn same(&self, other: &SharedPolicy) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Clone for SharedPolicy {
    fn clone(&self) -> Self {
        SharedPolicy(ManuallyDrop::new(Arc::clone(&self.0)))
    }
}

impl Deref for SharedPolicy {
    type Target = SecurityPolicy;
    fn deref(&self) -> &SecurityPolicy {
        &self.0
    }
}

impl Drop for SharedPolicy {
    fn drop(&mut self) {
        let mut shared = SHARED.lock();
        // SAFETY: o Arc sai uma vez só, aqui; o campo não é mais usado.
        let policy = unsafe { ManuallyDrop::take(&mut self.0) };
        if Arc::strong_count(&policy) == 1 {
            let hash = hash_of(&policy);
            if let Some(bucket) = shared.get_mut(&hash) {
                bucket.retain(|weak| !core::ptr::eq(weak.as_ptr(), Arc::as_ptr(&policy)));
                if bucket.is_empty() {
                    shared.remove(&hash);
                }
            }
        }
        // A contagem cai com a trava retida.
        drop(policy);
    }
}

/// A cópia dividida de `policy`: a existente igual, com mais uma
/// referência, ou uma nova na tabela.
pub fn share(policy: SecurityPolicy) -> SharedPolicy {
    let hash = hash_of(&policy);
    let mut shared = SHARED.lock();
    let bucket = shared.entry(hash).or_default();
    if let Some(existing) = bucket.iter().find_map(|weak| weak.upgrade().filter(|candidate| **candidate == policy)) {
        return SharedPolicy(ManuallyDrop::new(existing));
    }
    let fresh = Arc::new(policy);
    bucket.push(Arc::downgrade(&fresh));
    SharedPolicy(ManuallyDrop::new(fresh))
}

/// Quantas cópias distintas estão vivas (o censo do `--heap-census`).
pub fn live() -> usize {
    SHARED.lock().values().map(Vec::len).sum()
}

/// Quantas cópias vivas são iguais a `policy` (0 ou 1).
pub fn copies_of(policy: &SecurityPolicy) -> usize {
    SHARED.lock().get(&hash_of(policy)).map_or(0, |bucket| bucket.iter().filter(|weak| weak.upgrade().is_some_and(|candidate| *candidate == *policy)).count())
}
