/* boot.ld - setor de boot (0x7C00, 512 bytes) seguido do stage2 (0x7E00). */
ENTRY(boot_start)

SECTIONS
{
    . = 0x7C00;
    .boot : { KEEP(*(.boot)) }

    /DISCARD/ : {
        *(.eh_frame*)
        *(.comment*)
        *(.note*)
    }
}
