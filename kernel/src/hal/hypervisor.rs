//! Interface de hypervisor (Hvi*) e o Secure Kernel ausente (Sk*).
//!
//! Lê as leaves CPUID reais de hypervisor; sem Secure Kernel (VBS) nesta
//! máquina, as entradas Sk* têm o comportamento do ntoskrnl sem SK: push
//! locks comuns e o pool não paginado normal no lugar do pool seguro.

use core::sync::atomic::Ordering;

use crate::hal::cpu;
use crate::ntos::inc::types::{HvX64HypervisorFeatures, NtStruct};
use crate::ntos::mm::guest_memory as guest;

/// Vendor da interface (CPUID.0x40000000 EBX/ECX/EDX, 12 caracteres).
fn vendor() -> [u8; 12] {
    let leaf = cpu::cpuid(0x4000_0000);
    let mut vendor = [0u8; 12];
    for (index, register) in [leaf[1], leaf[2], leaf[3]].iter().enumerate() {
        vendor[index * 4..index * 4 + 4].copy_from_slice(&register.to_le_bytes());
    }
    vendor
}

/// HviIsAnyHypervisorPresent: bit 31 de CPUID.1:ECX.
pub fn is_any_hypervisor_present() -> bool {
    cpu::cpuid(1)[2] & 0x8000_0000 != 0
}

/// HviIsHypervisorMicrosoftCompatible: vendor "Microsoft Hv".
pub fn is_microsoft_compatible() -> bool {
    &vendor() == b"Microsoft Hv"
}

/// HviGetHypervisorFeatures(&features): HV_X64_HYPERVISOR_FEATURES é o
/// CPUID 0x40000003 inteiro (EAX:EBX = máscara de privilégios da partição,
/// ECX e EDX); zeros quando a interface não existe.
pub fn get_features(output: u64) {
    let maximum = cpu::cpuid(0x4000_0000)[0];
    let leaf = if maximum >= 0x4000_0003 { cpu::cpuid(0x4000_0003) } else { [0; 4] };
    // SAFETY: HV_X64_HYPERVISOR_FEATURES do chamador.
    let features = unsafe { HvX64HypervisorFeatures::at(output) };
    features.partition_privileges.as_uint64.set(u64::from(leaf[1]) << 32 | u64::from(leaf[0]));
    features.bitfield_8.set(leaf[2]);
    features.bitfield_c.set(leaf[3]);
}

// ---- Secure Kernel ausente ---------------------------------------------------
// SkInitializePushLock, SkAcquirePushLockExclusive e SkReleasePushLockExclusive
// operam numa EX_PUSH_LOCK normal (bit 0 = Locked), trocado atomicamente.

pub fn initialize_push_lock(lock: u64) {
    guest::atomic_u64(lock).store(0, Ordering::Release);
}

/// LOCK BTS do bit 0; com o lock ocupado, espera observá-lo livre.
pub fn acquire_push_lock_exclusive(lock: u64) {
    let cell = guest::atomic_u64(lock);
    while cell.fetch_or(1, Ordering::Acquire) & 1 != 0 {
        while cell.load(Ordering::Relaxed) & 1 != 0 {
            core::hint::spin_loop();
        }
    }
}

/// LOCK AND: limpa só o bit 0, preservando os demais.
pub fn release_push_lock_exclusive(lock: u64) {
    guest::atomic_u64(lock).fetch_and(!1, Ordering::Release);
}

/// SkAllocatePool: sem SK o pool seguro não existe, pool não paginado normal.
pub fn allocate_pool(size: u64) -> u64 {
    guest::alloc_bytes(size)
}

/// SkFreePool.
pub fn free_pool(pointer: u64) {
    guest::free_bytes(pointer);
}
