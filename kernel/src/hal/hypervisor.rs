//! Interface de hypervisor (Hvi*) e o Secure Kernel ausente (Sk*).
//!
//! Lê as leaves CPUID reais de hypervisor; sem Secure Kernel (VBS) nesta
//! máquina, as entradas Sk* têm o comportamento do ntoskrnl sem SK: push
//! locks comuns e o pool não paginado normal no lugar do pool seguro.

use crate::hal::cpu;
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

/// HviGetHypervisorFeatures(&features): features/privilégios (0x40000003) e
/// recomendações (0x40000004); zeros quando a interface não existe.
pub fn get_features(output: u64) {
    let maximum = cpu::cpuid(0x4000_0000)[0];
    let (mut features, mut privileges, mut recommendations) = (0, 0, 0);
    if maximum >= 0x4000_0003 {
        let leaf = cpu::cpuid(0x4000_0003);
        features = leaf[0];
        privileges = leaf[1];
    }
    if maximum >= 0x4000_0004 {
        recommendations = cpu::cpuid(0x4000_0004)[0];
    }
    guest::write32(output, features);
    guest::write32(output + 4, privileges);
    guest::write32(output + 8, recommendations);
}

// ---- Secure Kernel ausente ---------------------------------------------------
// SkInitializePushLock, SkAcquirePushLockExclusive e SkReleasePushLockExclusive
// operam numa EX_PUSH_LOCK normal (bit 0 = Locked).

pub fn initialize_push_lock(lock: u64) {
    guest::write64(lock, 0);
}

pub fn acquire_push_lock_exclusive(lock: u64) {
    loop {
        let value = guest::read64(lock);
        if value & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }
        guest::write64(lock, value | 1);
        return;
    }
}

pub fn release_push_lock_exclusive(lock: u64) {
    guest::write64(lock, guest::read64(lock) & !1);
}

/// SkAllocatePool: sem SK o pool seguro não existe, pool não paginado normal.
pub fn allocate_pool(size: u64) -> u64 {
    guest::alloc_bytes(size)
}

/// SkFreePool.
pub fn free_pool(pointer: u64) {
    guest::free_bytes(pointer);
}
