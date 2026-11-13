//! Setor de boot e stage2 do OpenNT.
//!
//! O código é Assembly x86 em sintaxe Intel do LLVM, montado pelo próprio
//! rustc. Os dois estágios ficam numa única seção `.boot`, ligada em 0x7C00:
//! os bytes 0..512 são o setor de boot e o stage2 começa em 0x7E00. O xtask
//! extrai a seção como binário plano e grava `kernel_sectors` (offset 3 do
//! stage2) antes de montar `os.img`.
//!
//! Um único bloco `global_asm!` garante a ordem dos dois estágios dentro da
//! seção, independentemente das unidades de geração de código.
#![no_std]
#![no_main]

use core::arch::global_asm;

global_asm!(
    include_str!("boot.s"),
    include_str!("stage2.s"),
    STAGE2_SECTORS = const 64,
    STAGE2_LBA = const 1,
    E820_COUNT = const 0x4FF0,
    E820_TABLE = const 0x5000,
    FIRMWARE_INFO = const 0x4FE0,
    GDTR_COPY = const 0x4FE8,
    BOOT_FLAGS_INFO = const 0x4FD0,
    PML4 = const 0x70000,
    PDPT = const 0x71000,
    PD0 = const 0x72000,
    KERNEL_LBA = const 65,
    KERNEL_DEST = const 0x100000,
    STACK_TOP = const 0xF80008,
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
