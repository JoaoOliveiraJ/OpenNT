# ---------------------------------------------------------------------------
# boot.s - setor de boot (512 bytes) do OpenNT.
# A BIOS nos carrega em 0x7C00 em modo real. Carregamos o stage2 (64 setores
# a partir do LBA 1) para 0x7E00 via int 13h LBA e saltamos para ele.
# ---------------------------------------------------------------------------
.pushsection .boot, "awx", @progbits
.code16

.global boot_start
boot_start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    sti
    mov byte ptr [boot_drive], dl

    mov si, offset boot_dap
    mov ah, 0x42                # int 13h LBA read (EDD)
    mov dl, byte ptr [boot_drive]
    int 0x13
    jc boot_disk_error

    # jmp 0x0000:0x7E00 (salto longe em modo real)
    .byte 0xEA
    .word 0x7E00, 0x0000

boot_disk_error:
    mov si, offset boot_msg_err
boot_print:
    lodsb
    or al, al
    jz boot_halt
    mov ah, 0x0E
    int 0x10
    jmp boot_print
boot_halt:
    cli
    hlt

boot_drive:
    .byte 0
boot_msg_err:
    .asciz "boot: erro de disco"

.balign 4
boot_dap:
    .byte 0x10, 0x00            # tamanho do DAP, reservado
    .word {STAGE2_SECTORS}      # setores a ler
    .word 0x7E00                # offset destino
    .word 0x0000                # segmento destino
    .quad {STAGE2_LBA}          # LBA inicial

.org 510
    .word 0xAA55
.popsection
.code64
