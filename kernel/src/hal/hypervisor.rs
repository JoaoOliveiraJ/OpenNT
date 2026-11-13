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

// ---- Fornecedor e features de hardware (hvi-hardware) ------------------------
//
// HviIsHypervisorVendorMicrosoft (0x3aa5f0) e HviGetHardwareFeatures
// (0x5beeb0) do ntoskrnl 10.0.19045, sobre o HviIsAnyHypervisorPresent
// (0x3a5310) e o HviGetHypervisorVendorAndMaxFunction (0x5bef30) exatos:
// "algum hipervisor" é CPUID.1:ECX bit 31 com interface (leaf 0x40000001 EAX)
// diferente de "Xbnv". Tudo vem do CPUID da máquina em que o OpenNT roda
// (com QEMU/WHPX, o que o anfitrião expõe ao convidado).
//
// Nota para o integrador: `is_any_hypervisor_present` acima não exclui a
// interface "Xbnv", e o HviIsHypervisorMicrosoftCompatible real (0x3a9060)
// compara a interface da leaf 0x40000001 com "Hv#1" (0x31237648), não o
// fornecedor; `any_hypervisor_interface_present` é a versão exata.

const HYPERVISOR_PRESENT: u32 = 1 << 31;
const LEAF_VENDOR_AND_MAX_FUNCTION: u32 = 0x4000_0000;
const LEAF_INTERFACE: u32 = 0x4000_0001;
const LEAF_HARDWARE_FEATURES: u32 = 0x4000_0006;
/// Interface "Xbnv" (EAX da leaf 0x40000001), que o NT não conta como hipervisor.
const INTERFACE_XBNV: u32 = 0x766E_6258;
/// "Microsoft Hv" em EBX, ECX, EDX da leaf 0x40000000.
const VENDOR_MICROSOFT: [u32; 3] = [0x7263_694D, 0x666F_736F, 0x7648_2074];

/// HviIsAnyHypervisorPresent exato (bit 31 e interface diferente de "Xbnv").
pub fn any_hypervisor_interface_present() -> bool {
    cpu::cpuid(1)[2] & HYPERVISOR_PRESENT != 0 && cpu::cpuid(LEAF_INTERFACE)[0] != INTERFACE_XBNV
}

/// HviGetHypervisorVendorAndMaxFunction: a leaf 0x40000000 ou zeros.
fn vendor_and_max_function() -> [u32; 4] {
    if any_hypervisor_interface_present() { cpu::cpuid(LEAF_VENDOR_AND_MAX_FUNCTION) } else { [0; 4] }
}

/// HviIsHypervisorVendorMicrosoft.
pub fn is_vendor_microsoft() -> bool {
    any_hypervisor_interface_present() && cpu::cpuid(LEAF_VENDOR_AND_MAX_FUNCTION)[1..] == VENDOR_MICROSOFT
}

/// EAX..EDX da leaf 0x40000006, ou zeros quando a função máxima não chega lá.
pub fn hardware_features() -> [u32; 4] {
    if vendor_and_max_function()[0] >= LEAF_HARDWARE_FEATURES { cpu::cpuid(LEAF_HARDWARE_FEATURES) } else { [0; 4] }
}

/// HviGetHardwareFeatures(*HV_X64_HYPERVISOR_HARDWARE_FEATURES): os quatro
/// ULONGs da estrutura (EAX..EDX da leaf 0x40000006).
pub fn get_hardware_features(output: &[crate::ntos::inc::field::Field<u32>]) {
    for (cell, value) in output.iter().zip(hardware_features()) {
        cell.set(value);
    }
}

// ---- VslGetSecurePciEnabled / VslQuerySecureDevice /
//      VslGetSecurePciDeviceAlternateFunctionNumberForVtl0Dma ------------------
//
// ntoskrnl 19041: as três começam por HvlQueryVsmConnection; sem conexão VSM
// (nenhum Secure Kernel/VTL1):
//   VslGetSecurePciEnabled rva 0x3cf530                      -> FALSE
//   VslQuerySecureDevice rva 0x7c8e90 (Device, Output[16])   -> zera a saída e
//     devolve o VslpEnterIumSecureMode sem VSM: STATUS_DEVICE_NOT_CONNECTED
//   VslGetSecurePciDeviceAlternateFunctionNumberForVtl0Dma rva 0x4fc3f0 -> 0xFF
// O OpenNT não tem Secure Kernel (o mesmo estado das entradas Sk* acima).

const VSL_STATUS_DEVICE_NOT_CONNECTED: u32 = 0xC000_009D;
const VSL_NO_ALTERNATE_FUNCTION: u8 = 0xFF;
/// Saída do VslQuerySecureDevice (zerada antes da chamada ao IUM).
const VSL_SECURE_DEVICE_INFORMATION_SIZE: usize = 16;

/// VslGetSecurePciEnabled().
pub fn secure_pci_enabled() -> bool {
    false
}

/// VslQuerySecureDevice(DeviceId, SecureDeviceInformation[16]).
pub fn query_secure_device(_device: u64, output: u64) -> u32 {
    guest::write_bytes(output, &[0u8; VSL_SECURE_DEVICE_INFORMATION_SIZE]);
    VSL_STATUS_DEVICE_NOT_CONNECTED
}

/// VslGetSecurePciDeviceAlternateFunctionNumberForVtl0Dma(Segment, Bus,
/// Device, Function).
pub fn secure_pci_alternate_function(_segment: u32, _bus: u8, _device: u8, _function: u8) -> u8 {
    VSL_NO_ALTERNATE_FUNCTION
}
