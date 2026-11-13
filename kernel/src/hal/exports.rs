//! Exports de I/O de porta da HAL.
//!
//! No NT/x64, READ_PORT_*/WRITE_PORT_* são funções reais da HAL; aqui descem
//! às primitivas de porta. As células de HalPrivateDispatchTable e
//! HalDispatchTable vêm de `hal::private_dispatch` e `hal::public_dispatch`.

use crate::ntos::init::exports::{Call, Group};
use crate::hal::{port, private_dispatch, public_dispatch};
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
    data_exports: &[("HalPrivateDispatchTable", private_dispatch::data_export_address), ("HalDispatchTable", public_dispatch::data_export_address)],
};

pub mod hal_platform {
    //! Adaptadores ACPI e PCI da HAL.

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
    //! Interface de hypervisor (Hvi*, Sk*, Vsl*).
    //!
    //! Adaptadores de `hal::hypervisor`; sem Secure Kernel (VBS) nesta
    //! máquina, as entradas Sk* têm o comportamento do ntoskrnl sem SK.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::hal::hypervisor;
    use crate::rtl::KernelError;

    fn is_any_hypervisor_present(_: &Call) -> Result<u64, KernelError> {
        Ok(hypervisor::is_any_hypervisor_present() as u64)
    }

    fn is_hypervisor_microsoft_compatible(_: &Call) -> Result<u64, KernelError> {
        Ok(hypervisor::is_microsoft_compatible() as u64)
    }

    fn get_hypervisor_features(call: &Call) -> Result<u64, KernelError> {
        hypervisor::get_features(call.arg(1));
        Ok(0)
    }

    /// Sem SK o export real é `mov eax, 0xC0000002; ret`: NTSTATUS negativo
    /// sem extensão de sinal (o cng testa o bit de sinal).
    fn is_secure_kernel(_: &Call) -> Result<u64, KernelError> {
        Ok(0xC000_0002)
    }

    fn initialize_push_lock(call: &Call) -> Result<u64, KernelError> {
        hypervisor::initialize_push_lock(call.arg(1));
        Ok(0)
    }

    fn acquire_push_lock_exclusive(call: &Call) -> Result<u64, KernelError> {
        hypervisor::acquire_push_lock_exclusive(call.arg(1));
        Ok(0)
    }

    fn release_push_lock_exclusive(call: &Call) -> Result<u64, KernelError> {
        hypervisor::release_push_lock_exclusive(call.arg(1));
        Ok(0)
    }

    fn allocate_pool(call: &Call) -> Result<u64, KernelError> {
        Ok(hypervisor::allocate_pool(call.arg(1)))
    }

    fn free_pool(call: &Call) -> Result<u64, KernelError> {
        hypervisor::free_pool(call.arg(1));
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

pub mod hvi_hardware {
    //! HviIsHypervisorVendorMicrosoft e HviGetHardwareFeatures pelo CPUID real.

    use crate::hal::hypervisor;
    use crate::ntos::inc::field::{Field, NtStruct};
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    /// ULONGs do HV_X64_HYPERVISOR_HARDWARE_FEATURES (EAX..EDX da leaf 0x40000006).
    const HARDWARE_FEATURE_REGISTERS: usize = 4;

    /// HviGetHardwareFeatures(*HV_X64_HYPERVISOR_HARDWARE_FEATURES) -> VOID.
    fn get_hardware_features(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: estrutura de saída de 16 bytes do chamador de modo kernel.
        hypervisor::get_hardware_features(unsafe { Field::<u32>::array_at(call.arg(1), HARDWARE_FEATURE_REGISTERS) });
        Ok(0)
    }

    /// HviIsHypervisorVendorMicrosoft() -> BOOLEAN.
    fn is_hypervisor_vendor_microsoft(_: &Call) -> Result<u64, KernelError> {
        Ok(hypervisor::is_vendor_microsoft() as u64)
    }

    pub static GROUP: Group = Group {
        name: "hvi-hardware",
        names: &["HviGetHardwareFeatures", "HviIsHypervisorVendorMicrosoft"],
        handlers: &[get_hardware_features, is_hypervisor_vendor_microsoft],
        data_exports: &[],
    };
}

pub mod vsl_secure_pci {
    use crate::hal::hypervisor;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    fn get_secure_pci_device_alternate_function(call: &Call) -> Result<u64, KernelError> {
        Ok(hypervisor::secure_pci_alternate_function(call.arg(1) as u32, call.arg(2) as u8, call.arg(3) as u8, call.arg(4) as u8) as u64)
    }

    fn get_secure_pci_enabled(_: &Call) -> Result<u64, KernelError> {
        Ok(hypervisor::secure_pci_enabled() as u64)
    }

    fn query_secure_device(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(hypervisor::query_secure_device(call.arg(1), call.arg(2))))
    }

    pub static GROUP: Group = Group {
        name: "vsl-secure-pci",
        names: &["VslGetSecurePciDeviceAlternateFunctionNumberForVtl0Dma", "VslGetSecurePciEnabled", "VslQuerySecureDevice"],
        handlers: &[get_secure_pci_device_alternate_function, get_secure_pci_enabled, query_secure_device],
        data_exports: &[],
    };
}
