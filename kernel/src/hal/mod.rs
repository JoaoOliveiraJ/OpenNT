//! HAL do OpenNT — a camada de abstração de hardware.
//!
//! Hardware: portas (`port`), serial (`serial`), CPU (`cpu`), acesso volátil
//! a endereços virtuais (`volatile`), memória física pelo mapa direto
//! (`physical`), LAPIC (`lapic`), RTC (`rtc`), heap do kernel (`kmalloc`),
//! arquivos embutidos (`bundle`) e a arena dos convidados (`host`). O código
//! x64 (interrupções, anel 3, APs, chamadas MS-ABI e trampolins) fica em
//! `amd64`. As interfaces vistas pelo executive — ACPI, PCI, firmware, a
//! HalPrivateDispatchTable e a HalDispatchTable (com o HaliQuerySystemInformation,
//! `system_information`), a interface de hypervisor, a interface x86 BIOS
//! (`x86bios`: o BIOS de vídeo num processador de modo real emulado) e os
//! exports Hal* — vêm em seguida.

pub mod amd64;
pub mod bundle;
pub mod cpu;
pub mod host;
pub mod kmalloc;
pub mod lapic;
pub mod physical;
pub mod port;
pub mod rtc;
pub mod serial;
pub mod volatile;

// Interfaces da HAL vistas pelo executivo: ACPI, PCI, firmware, a tabela
// privada (HalPrivateDispatchTable) e os exports Hal*.
pub mod acpi;
pub mod acpi_native;
pub mod acpi_pm;
pub mod errata;
pub mod interrupt_lines;
pub mod interrupt_targets;
pub mod pci_config;
pub mod pci_native;
pub mod firmware_environment;
pub mod firmware_return;
pub mod pnp;
pub mod private_dispatch;
pub mod public_dispatch;
pub mod system_information;
pub mod hypervisor;
pub mod dma;
pub mod x86bios;
pub mod exports;
