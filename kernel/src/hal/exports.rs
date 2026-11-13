//! Exports de I/O de porta da HAL — `system32/win32/ntoskrnl/hal.js`.
//!
//! No NT/x64, READ_PORT_*/WRITE_PORT_* são funções reais da HAL; aqui descem
//! às primitivas de porta.

use crate::ntos::init::exports::{Call, Group};
use crate::hal::port;
use crate::rtl::KernelError;

fn read_port_uchar(call: &Call) -> Result<u64, KernelError> {
    Ok(port::read8(call.arg(1) as u16) as u64)
}

fn read_port_ushort(call: &Call) -> Result<u64, KernelError> {
    Ok(port::read16(call.arg(1) as u16) as u64)
}

fn read_port_ulong(call: &Call) -> Result<u64, KernelError> {
    Ok(port::read32(call.arg(1) as u16) as u64)
}

fn write_port_uchar(call: &Call) -> Result<u64, KernelError> {
    port::write8(call.arg(1) as u16, call.arg(2) as u8);
    Ok(0)
}

fn write_port_ushort(call: &Call) -> Result<u64, KernelError> {
    port::write16(call.arg(1) as u16, call.arg(2) as u16);
    Ok(0)
}

fn write_port_ulong(call: &Call) -> Result<u64, KernelError> {
    port::write32(call.arg(1) as u16, call.arg(2) as u32);
    Ok(0)
}

pub static GROUP: Group = Group {
    name: "hal",
    names: &["READ_PORT_UCHAR", "READ_PORT_USHORT", "READ_PORT_ULONG", "WRITE_PORT_UCHAR", "WRITE_PORT_USHORT", "WRITE_PORT_ULONG"],
    handlers: &[read_port_uchar, read_port_ushort, read_port_ulong, write_port_uchar, write_port_ushort, write_port_ulong],
    data_exports: &[("HalPrivateDispatchTable", private_dispatch_table_address), ("HalDispatchTable", dispatch_table_address)],
};

/// HalPrivateDispatchTable: o export de dados preenchido pela HAL
/// (`ntos::hal::private_dispatch`).
fn private_dispatch_table_address() -> u64 {
    crate::ntos::mm::kernel_data::address("HalPrivateDispatchTable").unwrap_or_else(|error| panic!("HalPrivateDispatchTable: {error}"))
}

/// HalDispatchTable: o HAL_DISPATCH público preenchido pela HAL
/// (`hal::public_dispatch`).
fn dispatch_table_address() -> u64 {
    crate::ntos::mm::kernel_data::address("HalDispatchTable").unwrap_or_else(|error| panic!("HalDispatchTable: {error}"))
}

pub mod hal_platform {
    //! Adaptadores ACPI e PCI da HAL — `system32/win32/ntoskrnl/hal-platform.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::hal::{acpi_native, pci_native};

    fn acpi_get_table_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(acpi_native::get_table_ex(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4)))
    }

    fn kd_get_acpi_table_phase0(call: &Call) -> Result<u64, KernelError> {
        Ok(acpi_native::get_table_phase0(call.arg(1), call.arg(2) as u32))
    }

    fn get_cached_acpi_table(call: &Call) -> Result<u64, KernelError> {
        Ok(acpi_native::get_cached_table(call.arg(1) as u32, call.arg(2), call.arg(3)))
    }

    fn get_bus_data(call: &Call) -> Result<u64, KernelError> {
        Ok(pci_native::get_bus_data(call.arg(1) as u32, call.arg(2) as u32, call.arg(3) as u32, call.arg(4), call.arg(5) as u32)? as u64)
    }

    fn get_bus_data_by_offset(call: &Call) -> Result<u64, KernelError> {
        Ok(pci_native::get_bus_data_by_offset(call.arg(1) as u32, call.arg(2) as u32, call.arg(3) as u32, call.arg(4), call.arg(5) as u32, call.arg(6) as u32)? as u64)
    }

    fn set_bus_data(call: &Call) -> Result<u64, KernelError> {
        Ok(pci_native::set_bus_data(call.arg(1) as u32, call.arg(2) as u32, call.arg(3) as u32, call.arg(4), call.arg(5) as u32)? as u64)
    }

    fn set_bus_data_by_offset(call: &Call) -> Result<u64, KernelError> {
        Ok(pci_native::set_bus_data_by_offset(call.arg(1) as u32, call.arg(2) as u32, call.arg(3) as u32, call.arg(4), call.arg(5) as u32, call.arg(6) as u32)? as u64)
    }

    fn kd_get_pci_data_by_offset(call: &Call) -> Result<u64, KernelError> {
        Ok(pci_native::kd_get_pci_data_by_offset(call.arg(1) as u32, call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5) as u32)? as u64)
    }

    fn kd_set_pci_data_by_offset(call: &Call) -> Result<u64, KernelError> {
        Ok(pci_native::kd_set_pci_data_by_offset(call.arg(1) as u32, call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5) as u32)? as u64)
    }

    pub static GROUP: Group = Group {
        name: "hal-platform",
        names: &["HalAcpiGetTableEx", "KdGetAcpiTablePhase0", "HalGetCachedAcpiTable", "HalGetBusData", "HalGetBusDataByOffset", "HalSetBusData", "HalSetBusDataByOffset", "KdGetPciDataByOffset", "KdSetPciDataByOffset"],
        handlers: &[acpi_get_table_ex, kd_get_acpi_table_phase0, get_cached_acpi_table, get_bus_data, get_bus_data_by_offset, set_bus_data, set_bus_data_by_offset, kd_get_pci_data_by_offset, kd_set_pci_data_by_offset],
        data_exports: &[],
    };
}

pub mod hvi {
    //! Interface de hypervisor (Hvi*, Sk*, Vsl*) — `system32/win32/ntoskrnl/hvi.js`.
    //!
    //! Lê as leaves CPUID reais de hypervisor; sem Secure Kernel (VBS) nesta
    //! máquina, as entradas Sk* têm o comportamento do ntoskrnl sem SK.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::hal::cpu;
    use crate::rtl::KernelError;
    use crate::ntos::mm::guest_memory as guest;

    /// Vendor da interface (CPUID.0x40000000 EBX/ECX/EDX, 12 caracteres).
    fn hypervisor_vendor() -> [u8; 12] {
        let leaf = cpu::cpuid(0x4000_0000);
        let mut vendor = [0u8; 12];
        for (index, register) in [leaf[1], leaf[2], leaf[3]].iter().enumerate() {
            vendor[index * 4..index * 4 + 4].copy_from_slice(&register.to_le_bytes());
        }
        vendor
    }

    /// Bit 31 de CPUID.1:ECX.
    fn is_any_hypervisor_present(_: &Call) -> Result<u64, KernelError> {
        Ok((cpu::cpuid(1)[2] & 0x8000_0000 != 0) as u64)
    }

    fn is_hypervisor_microsoft_compatible(_: &Call) -> Result<u64, KernelError> {
        Ok((&hypervisor_vendor() == b"Microsoft Hv") as u64)
    }

    /// Features/privilégios (0x40000003) e recomendações (0x40000004); zeros
    /// quando a interface não existe.
    fn get_hypervisor_features(call: &Call) -> Result<u64, KernelError> {
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
        let output = call.arg(1);
        guest::write32(output, features);
        guest::write32(output + 4, privileges);
        guest::write32(output + 8, recommendations);
        Ok(0)
    }

    /// Sem SK o export real é `mov eax, 0xC0000002; ret`: NTSTATUS negativo
    /// sem extensão de sinal (o cng testa o bit de sinal).
    fn is_secure_kernel(_: &Call) -> Result<u64, KernelError> {
        Ok(0xC000_0002)
    }

    /// As três operam numa EX_PUSH_LOCK normal (bit 0 = Locked).
    fn initialize_push_lock(call: &Call) -> Result<u64, KernelError> {
        guest::write64(call.arg(1), 0);
        Ok(0)
    }

    fn acquire_push_lock_exclusive(call: &Call) -> Result<u64, KernelError> {
        loop {
            let value = guest::read64(call.arg(1));
            if value & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }
            guest::write64(call.arg(1), value | 1);
            return Ok(0);
        }
    }

    fn release_push_lock_exclusive(call: &Call) -> Result<u64, KernelError> {
        guest::write64(call.arg(1), guest::read64(call.arg(1)) & !1);
        Ok(0)
    }

    /// Sem SK o pool seguro não existe: pool não paginado normal.
    fn allocate_pool(call: &Call) -> Result<u64, KernelError> {
        Ok(guest::alloc_bytes(call.arg(1)))
    }

    fn free_pool(call: &Call) -> Result<u64, KernelError> {
        guest::free_bytes(call.arg(1));
        Ok(0)
    }

    fn query_secure_kernel_information(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(0xC000_0010))
    }

    fn exchange_entropy(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(0xC000_00BB))
    }

    pub static GROUP: Group = Group {
        name: "hvi",
        names: &["HviIsAnyHypervisorPresent", "HviIsHypervisorMicrosoftCompatible", "HviGetHypervisorFeatures", "SkIsSecureKernel", "SkInitializePushLock", "SkAcquirePushLockExclusive", "SkReleasePushLockExclusive", "SkAllocatePool", "SkFreePool", "SkQuerySecureKernelInformation", "VslExchangeEntropy"],
        handlers: &[is_any_hypervisor_present, is_hypervisor_microsoft_compatible, get_hypervisor_features, is_secure_kernel, initialize_push_lock, acquire_push_lock_exclusive, release_push_lock_exclusive, allocate_pool, free_pool, query_secure_kernel_information, exchange_entropy],
        data_exports: &[],
    };
}
