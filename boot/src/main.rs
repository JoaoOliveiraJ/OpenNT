//! Setor de boot e stage2 do OpenNT.
//!
//! O código é Assembly x86 em sintaxe Intel do LLVM, montado pelo próprio
//! rustc. Os dois estágios ficam numa única seção `.boot`, ligada em 0x7C00:
//! os bytes 0..512 são o setor de boot e o stage2 começa em 0x7E00. O xtask
//! extrai a seção como binário plano e grava `kernel_sectors` (offset 3 do
//! stage2) antes de montar `os.img`.
//!
//! Um único bloco `global_asm!` garante a ordem dos dois estágios dentro da
//! seção, independentemente das unidades de geração de código. Os endereços
//! do layout de memória vêm de `kernel/src/ntos/mm/memory_map.rs`, a mesma
//! fonte que o kernel usa.
#![no_std]
#![no_main]

use core::arch::global_asm;

#[path = "../../kernel/src/ntos/mm/memory_map.rs"]
mod memory_map;

use memory_map as map;

global_asm!(
    include_str!("boot.s"),
    include_str!("stage2.s"),
    STAGE2_SECTORS = const 64,
    STAGE2_LBA = const 1,
    E820_COUNT = const map::E820_COUNT_PHYS,
    E820_TABLE = const map::E820_TABLE_PHYS,
    FIRMWARE_INFO = const map::BOOT_FIRMWARE_PHYS,
    GDTR_COPY = const map::BOOT_GDTR_PHYS,
    BOOT_FLAGS_INFO = const map::BOOT_FLAGS_PHYS,
    PML4 = const map::PML4_PHYS,
    // Identidade transitória: uma página de 2 MB em [0, 2 MB).
    IDENTITY_PDPT = const map::BOOT_IDENTITY_PDPT_PHYS,
    IDENTITY_PD = const map::BOOT_IDENTITY_PD_PHYS,
    // Mapa direto da memória física: PDPT e 4 PDs logo depois.
    DIRECT_MAP_BASE = const map::DIRECT_MAP_BASE,
    DIRECT_PML4_INDEX = const map::DIRECT_MAP_PML4_INDEX,
    DIRECT_PDPT = const map::DIRECT_MAP_PDPT_PHYS,
    DIRECT_PD = const map::DIRECT_MAP_PD_PHYS,
    // Imagem do kernel na sua ImageBase de sistema e pilha de boot.
    KERNEL_LBA = const 65,
    KERNEL_PHYS = const map::KERNEL_IMAGE_PHYS,
    KERNEL_IMAGE_MAX = const map::KERNEL_IMAGE_MAX,
    KERNEL_BASE = const map::KERNEL_VIRTUAL_BASE,
    KERNEL_BASE_LOW = const map::KERNEL_VIRTUAL_BASE & 0xFFFF_FFFF,
    KERNEL_BASE_HIGH = const map::KERNEL_VIRTUAL_BASE >> 32,
    KERNEL_PML4_INDEX = const map::KERNEL_PML4_INDEX,
    KERNEL_PDPT_INDEX = const (map::KERNEL_VIRTUAL_BASE >> 30) & 511,
    KERNEL_PDPT = const map::KERNEL_PDPT_PHYS,
    KERNEL_PD = const map::KERNEL_PD_PHYS,
    KERNEL_PT = const map::KERNEL_PT_PHYS,
    KERNEL_PT_COUNT = const map::KERNEL_PT_COUNT,
    STACK_PT = const map::BOOT_STACK_PT_PHYS,
    STACK_PD_INDEX = const (map::BOOT_STACK_LIMIT - map::KERNEL_VIRTUAL_BASE) / map::LARGE_PAGE_SIZE,
    STACK_FIRST_PTE = const (map::BOOT_STACK_LIMIT >> 12) & 511,
    STACK_PAGES = const map::BOOT_STACK_SIZE / map::PAGE_SIZE,
    STACK_PHYS = const map::BOOT_STACK_PHYS_BASE,
    STACK_TOP = const map::BOOT_STACK_TOP,
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
