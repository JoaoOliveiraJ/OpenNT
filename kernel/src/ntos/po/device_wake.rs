//! Marca de despertar dos IRPs de energia e flags de DRIPS dirigido de um
//! dispositivo (NT: po\pocall.c e po\drips.c).
//!
//! ntoskrnl 19041:
//!   PoSetSystemWake rva 0x5652e0 / PoGetSystemWake rva 0x3a7050: o bloco do
//!     Power Manager (_POP_IRP_DATA) fica no Context da última posição de pilha
//!     do IRP; com MinorFunction == IRP_MN_WAIT_WAKE (0), Set grava 1 em
//!     Device.SystemWake e Get o lê; senão Get devolve FALSE.
//!   PoDirectedDripsSetDeviceFlags rva 0x3c9770 (Pdo, Flags): Flags fora de 0x3F,
//!     PDO NULL ou sem devnode = STATUS_INVALID_PARAMETER; senão
//!     DeviceNode->DirectedDripsFlags (+0x2F8) |= Flags.
//! Os IRPs de energia do OpenNT não carregam o bloco do Power Manager (Context
//! nulo): Set não faz nada e Get devolve FALSE, o resultado do NT para um IRP
//! sem marca. Os flags de DRIPS ficam numa tabela por PDO do PnP do OpenNT, que
//! não tem DEVICE_NODE; nada no OpenNT entra em DRIPS.

use alloc::collections::BTreeMap;

use crate::ntos::inc::types::extra_storage::PopIrpData;
use crate::ntos::inc::types::{IoStackLocation, Irp, NtStruct};
use crate::ntos::io::io_manager;
use crate::rtl::SpinLock;

/// IRP_MN_WAIT_WAKE: o único IRP cujo bloco aceita a marca.
const IRP_MN_WAIT_WAKE: u8 = 0;
const DIRECTED_DRIPS_VALID_FLAGS: u32 = 0x3F;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

static DIRECTED_DRIPS_FLAGS: SpinLock<BTreeMap<u64, u32>> = SpinLock::new(BTreeMap::new());

/// Bloco do Power Manager: Context da última posição de pilha do IRP.
fn power_block(irp: &Irp) -> Option<&'static PopIrpData> {
    let count = irp.stack_count.get();
    if count <= 0 {
        return None;
    }
    // SAFETY: as StackCount posições seguem o cabeçalho do IRP.
    let locations = unsafe { IoStackLocation::array_at(irp.address() + Irp::SIZE, count as usize) };
    let block = locations[count as usize - 1].context.get();
    // SAFETY: Context não nulo da última posição de um IRP de energia é o POP_IRP_DATA.
    (block != 0).then(|| unsafe { PopIrpData::at(block) })
}

/// PoSetSystemWake(Irp).
pub fn set_system_wake(irp: &Irp) {
    if let Some(block) = power_block(irp).filter(|block| block.minor_function.get() == IRP_MN_WAIT_WAKE) {
        block.device_system_wake.set(1);
    }
}

/// PoGetSystemWake(Irp).
pub fn get_system_wake(irp: &Irp) -> bool {
    power_block(irp).is_some_and(|block| block.minor_function.get() == IRP_MN_WAIT_WAKE && block.device_system_wake.get() != 0)
}

/// PoDirectedDripsSetDeviceFlags(PhysicalDeviceObject, Flags).
pub fn set_directed_drips_flags(pdo: u64, flags: u32) -> u32 {
    let is_pnp = pdo != 0 && io_manager::devices().into_iter().any(|(_, entry)| entry.native_device == pdo && (entry.pdo || entry.extra.is_some()));
    if !is_pnp || flags & !DIRECTED_DRIPS_VALID_FLAGS != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    *DIRECTED_DRIPS_FLAGS.lock().entry(pdo).or_insert(0) |= flags;
    0
}

/// Flags acumulados de um PDO (autoteste).
pub fn directed_drips_flags(pdo: u64) -> u32 {
    DIRECTED_DRIPS_FLAGS.lock().get(&pdo).copied().unwrap_or(0)
}
