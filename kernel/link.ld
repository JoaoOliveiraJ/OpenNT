/* link.ld - kernel do OpenNT ligado na sua VA de sistema.
 *
 * A ImageBase é KERNEL_VIRTUAL_BASE (0xFFFFF800_40000000,
 * kernel/src/ntos/mm/memory_map.rs): a primeira página é o cabeçalho PE32+
 * gerado pelo xtask a partir destas seções, e `.text` começa em +0x1000. Os
 * offsets do arquivo são iguais às RVAs; o stage2 carrega a imagem
 * linearmente nos frames de 1 MB a 14 MB, mapeia SizeOfImage páginas na
 * ImageBase e entra pelo AddressOfEntryPoint.
 *
 * O código é independente de posição (relocation-model=pic) e o executável
 * é estático (--no-pie): o linker resolve toda referência para estes
 * endereços. `.data.rel.ro` (dados constantes com ponteiros) fica em
 * `.rodata`, como ficaria num executável de relocação estática. */
ENTRY(kernel_main)

SECTIONS
{
    . = 0xFFFFF80040001000;

    .text : ALIGN(4096) {
        *(.text.boot)
        *(.text .text.*)
    }

    . = ALIGN(4096);
    .rodata : ALIGN(4096) {
        *(.rodata .rodata.*)
        *(.data.rel.ro .data.rel.ro.*)
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
