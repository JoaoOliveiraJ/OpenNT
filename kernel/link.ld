/* link.ld - kernel do OpenNT ligado em 0x100000 (1 MB), identity-mapped.
 *
 * A primeira página (0x100000) é o cabeçalho PE32+ gerado pelo xtask a
 * partir destas seções; os offsets do arquivo são iguais às RVAs, então o
 * stage2 carrega a imagem linearmente e entra pelo AddressOfEntryPoint.
 * O kernel ocupa [1 MB, 14 MB); a pilha de boot fica em 15,5 MB. */
ENTRY(kernel_main)

SECTIONS
{
    . = 0x101000;

    .text : ALIGN(4096) {
        *(.text.boot)
        *(.text .text.*)
    }

    . = ALIGN(4096);
    .rodata : ALIGN(4096) {
        *(.rodata .rodata.*)
    }

    . = ALIGN(4096);
    .data : ALIGN(4096) {
        *(.data .data.*)
        *(.got .got.*)
    }

    . = ALIGN(4096);
    .bss : ALIGN(4096) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }

    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.comment*)
        *(.note*)
        *(.gcc_except_table*)
    }
}
