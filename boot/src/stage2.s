# ---------------------------------------------------------------------------
# stage2.s - modo real -> protegido -> long mode (64 bits).
#
# 1. E820 (mapa de memoria) -> 0x4FF0 (count u16) / 0x5000 (entradas 24B)
# 2. A20 via porta 0x92
# 3. Modo protegido (GDT flat)
# 4. Kernel do disco p/ 0x100000 via ATA PIO (LBA 65, sem BIOS) e conferencia
#    do cabecalho PE (ImageBase, SizeOfImage, entrada)
# 5. Paginacao: identidade transitoria so de [0, 2MB) (este codigo enquanto
#    liga a paginacao), mapa direto em 0xFFFFB000_00000000 (2MB pages, NX),
#    imagem do kernel na sua ImageBase de sistema (PTEs de 4KB) e pilha de
#    boot de sistema (PTEs de 4KB, NX, guarda embaixo); SSE habilitado
# 6. PAE + LME -> long mode, GDTR pelo mapa direto, RSP na pilha de sistema,
#    salta p/ a entrada do kernel na VA de link
#
# Marcadores de progresso na serial COM1: B E A P K G L 6
#
# ATENCAO: codigo 16-bit NAO pode ser chamado de codigo 32/64-bit (mesmos
# bytes decodificam diferente). Por isso existem stage2_putc16 e stage2_putc32.
#
# Rsp % 16 == 8 na entrada do kernel (como se viesse de um call). Os
# enderecos vem de kernel/src/ntos/mm/memory_map.rs: o kernel ocupa os frames
# [1MB, 14MB) e a pilha de boot os frames logo abaixo de 15.5MB. O kernel
# desfaz a identidade transitoria na entrada.
# ---------------------------------------------------------------------------
.pushsection .boot, "awx", @progbits
.code16

stage2_base:
    .byte 0xEB, 0x03            # jmp short -> stage2_trampoline (offset 5)
    nop
.global kernel_sectors
kernel_sectors:
    .word 0                     # patcheado pelo xtask (offset 3)
stage2_trampoline:
    jmp stage2_start

# --- serial putc, MODO REAL 16-bit apenas (AL = char; clobbera dx) --------
stage2_putc16:
    push ax
    mov dx, 0x3FD
stage2_putc16_wait:
    in al, dx
    test al, 0x20
    jz stage2_putc16_wait
    pop ax
    mov dx, 0x3F8
    out dx, al
    ret

stage2_start:
    cli
    mov al, 0x80                # mascara NMI (IDT ainda nao existe)
    out 0x70, al
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00

    # Este loader foi iniciado pela BIOS legada. Publica o caminho real de
    # boot, nao o firmware do host nem uma capacidade pedida.
    mov dword ptr [{FIRMWARE_INFO}], 0x31545746     # "FWT1", handoff versao 1
    mov dword ptr [{FIRMWARE_INFO} + 4], 1          # FirmwareTypeBios

    # Este caminho inicia o kernel do disco, sem menu, hibernacao, soft boot,
    # measured launch ou substituicao da hive SYSTEM (consulta da classe 90).
    mov dword ptr [{BOOT_FLAGS_INFO}], 0x31464F42   # "BOF1"
    mov dword ptr [{BOOT_FLAGS_INFO} + 4], 16       # tamanho do handoff
    mov dword ptr [{BOOT_FLAGS_INFO} + 8], 0        # BootFlags, parte baixa
    mov dword ptr [{BOOT_FLAGS_INFO} + 12], 0       # BootFlags, parte alta

    # serial COM1: 38400 8N1
    mov dx, 0x3F9
    xor al, al
    out dx, al
    mov dx, 0x3FB
    mov al, 0x80
    out dx, al
    mov dx, 0x3F8
    mov al, 0x03
    out dx, al
    mov dx, 0x3F9
    xor al, al
    out dx, al
    mov dx, 0x3FB
    mov al, 0x03
    out dx, al
    mov dx, 0x3FA
    mov al, 0xC7
    out dx, al
    mov dx, 0x3FC
    mov al, 0x0B
    out dx, al

    mov al, 'B'
    call stage2_putc16

    # ---- E820 ----
    mov di, {E820_TABLE}
    xor ebx, ebx
    xor bp, bp
    mov edx, 0x534D4150
stage2_e820_next:
    mov eax, 0xE820
    mov ecx, 24
    mov dword ptr [di + 20], 1
    int 0x15
    jc stage2_e820_done
    cmp eax, 0x534D4150
    jne stage2_e820_done
    test ecx, ecx
    jz stage2_e820_skip
    inc bp
    add di, 24
    cmp bp, 170                 # tabela E820 deve terminar antes de 0x6000
    jae stage2_e820_done
stage2_e820_skip:
    test ebx, ebx
    jnz stage2_e820_next
stage2_e820_done:
    mov word ptr [{E820_COUNT}], bp
    mov al, 'E'
    call stage2_putc16

    # ---- A20 (porta 0x92) ----
    in al, 0x92
    or al, 2
    out 0x92, al
    mov al, 'A'
    call stage2_putc16

    # ---- entra no modo protegido ----
    lgdt [stage2_gdtr]
    sgdt [{GDTR_COPY}]          # publica o GDTR (base da GDT p/ a KPCR)
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    # jmp dword 0x08:stage2_pm32 (salto longe com operando de 32 bits)
    .byte 0x66, 0xEA
    .long stage2_pm32
    .word 0x08

# ---------------------------------------------------------------------------
.code32

# --- serial putc, 32-bit; os mesmos bytes sao validos em 64-bit ----------
stage2_putc32:
    push eax                    # em 64-bit vira push rax; pop casa
    mov dx, 0x3FD               # 66 BA ... igual nas duas decodificacoes
stage2_putc32_wait:
    in al, dx
    test al, 0x20
    jz stage2_putc32_wait
    pop eax
    mov dx, 0x3F8
    out dx, al
    ret

stage2_pm32:
    mov ax, 0x20                # bootstrap data32, separado do code64 do NT
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax
    mov al, 'P'
    call stage2_putc32

    # ---- ATA PIO: kernel_sectors setores do LBA KERNEL_LBA p/ 0x100000
    movzx ecx, word ptr [kernel_sectors]
    test ecx, ecx
    jz stage2_no_disk
    mov dword ptr [stage2_sectors_left], ecx
    mov esi, {KERNEL_LBA}
    mov edi, {KERNEL_PHYS}
stage2_sector:
    mov dx, 0x1F7
stage2_wait_busy:
    in al, dx
    test al, 0x80
    jnz stage2_wait_busy
    mov dx, 0x1F2
    mov al, 1
    out dx, al
    mov dx, 0x1F3
    mov eax, esi
    out dx, al
    shr eax, 8
    mov dx, 0x1F4
    out dx, al
    shr eax, 8
    mov dx, 0x1F5
    out dx, al
    shr eax, 8
    and al, 0x0F
    or al, 0xE0
    mov dx, 0x1F6
    out dx, al
    mov dx, 0x1F7
    mov al, 0x20                # READ SECTORS
    out dx, al
stage2_wait_drq:
    in al, dx
    test al, 0x80
    jnz stage2_wait_drq
    test al, 0x08               # DRQ
    jz stage2_wait_drq
    mov ecx, 256
    mov dx, 0x1F0
    .byte 0xF3, 0x66, 0x6D      # rep insw: 256 words = 512 bytes p/ ES:EDI
    inc esi
    dec dword ptr [stage2_sectors_left]
    jnz stage2_sector
stage2_no_disk:
    mov al, 'K'
    call stage2_putc32

    # ---- cabecalho PE do kernel (offsets crus == RVAs) ----
    # Base fixa = a VA de sistema em que o kernel foi ligado; SizeOfImage
    # inteiro no disco e dentro da reserva fisica; entrada dentro da imagem.
    mov ebx, {KERNEL_PHYS}
    cmp word ptr [ebx], 0x5A4D
    jne stage2_bad_kernel32
    mov eax, dword ptr [ebx + 0x3C]
    cmp eax, 0xF00
    ja stage2_bad_kernel32
    add eax, ebx
    cmp dword ptr [eax], 0x4550
    jne stage2_bad_kernel32
    cmp word ptr [eax + 4], 0x8664
    jne stage2_bad_kernel32
    cmp word ptr [eax + 24], 0x20B
    jne stage2_bad_kernel32
    cmp dword ptr [eax + 48], {KERNEL_BASE_LOW}     # ImageBase
    jne stage2_bad_kernel32
    cmp dword ptr [eax + 52], {KERNEL_BASE_HIGH}
    jne stage2_bad_kernel32
    mov ecx, dword ptr [eax + 80]       # SizeOfImage
    test ecx, 0xFFF
    jnz stage2_bad_kernel32
    cmp ecx, {KERNEL_IMAGE_MAX}
    ja stage2_bad_kernel32
    movzx edx, word ptr [kernel_sectors]
    shl edx, 9
    cmp ecx, edx
    ja stage2_bad_kernel32
    mov edx, dword ptr [eax + 40]       # AddressOfEntryPoint
    cmp edx, 0x1000
    jb stage2_bad_kernel32
    cmp edx, ecx
    jae stage2_bad_kernel32
    mov dword ptr [stage2_entry_rva], edx
    mov dword ptr [stage2_image_size], ecx

    # ---- tabelas de paginas ----
    # Zera as da identidade de boot e do mapa direto (contiguas) e as da
    # imagem do kernel e da pilha de boot (PDPT, PD, PTs da imagem, PT da
    # pilha, contiguas).
    mov edi, {PML4}
    xor eax, eax
    mov ecx, ({DIRECT_PD} + 0x4000 - {PML4}) / 4
    .byte 0xF3, 0xAB            # rep stosd
    mov edi, {KERNEL_PDPT}
    mov ecx, ({STACK_PT} + 0x1000 - {KERNEL_PDPT}) / 4
    .byte 0xF3, 0xAB            # rep stosd

    # Identidade transitoria: so a pagina de 2MB com este codigo. O kernel
    # a desfaz assim que entra.
    mov dword ptr [{PML4}], {IDENTITY_PDPT} + 3
    mov dword ptr [{IDENTITY_PDPT}], {IDENTITY_PD} + 3
    mov dword ptr [{IDENTITY_PD}], 0x83         # present|rw|page-size(2MB)

    # ---- imagem do kernel: KERNEL_BASE + RVA -> KERNEL_PHYS + RVA ----
    # Exatamente SizeOfImage paginas de 4KB, supervisor, RW e executaveis.
    mov dword ptr [{PML4} + {KERNEL_PML4_INDEX} * 8], {KERNEL_PDPT} + 3
    mov dword ptr [{KERNEL_PDPT} + {KERNEL_PDPT_INDEX} * 8], {KERNEL_PD} + 3
    mov edi, {KERNEL_PD}
    mov eax, {KERNEL_PT} + 3
    mov ecx, {KERNEL_PT_COUNT}
stage2_kernel_pd:
    mov dword ptr [edi], eax
    add eax, 0x1000
    add edi, 8
    dec ecx
    jnz stage2_kernel_pd
    mov edi, {KERNEL_PT}
    mov eax, {KERNEL_PHYS} + 3
    mov ecx, dword ptr [stage2_image_size]
    shr ecx, 12
stage2_kernel_pt:
    mov dword ptr [edi], eax
    add eax, 0x1000
    add edi, 8
    dec ecx
    jnz stage2_kernel_pt

    # ---- pilha de boot: STACK_PAGES paginas de 4KB, RW e NX ----
    # A entrada logo abaixo da primeira fica vazia (pagina de guarda).
    mov dword ptr [{KERNEL_PD} + {STACK_PD_INDEX} * 8], {STACK_PT} + 3
    mov edi, {STACK_PT} + {STACK_FIRST_PTE} * 8
    mov eax, {STACK_PHYS} + 3
    mov ecx, {STACK_PAGES}
stage2_stack_pt:
    mov dword ptr [edi], eax
    mov dword ptr [edi + 4], 0x80000000     # NX
    add eax, 0x1000
    add edi, 8
    dec ecx
    jnz stage2_stack_pt

    # ---- mapa direto: DIRECT_MAP_BASE + PA -> PA nos mesmos 4GB ----
    # Paginas de 2MB de supervisor, RW e NX (o NXE e exigido abaixo antes
    # de ligar a paginacao). E por aqui que o kernel acessa memoria fisica.
    mov dword ptr [{PML4} + {DIRECT_PML4_INDEX} * 8], {DIRECT_PDPT} + 3
    mov dword ptr [{DIRECT_PDPT}], {DIRECT_PD} + 3
    mov dword ptr [{DIRECT_PDPT} + 8], {DIRECT_PD} + 0x1000 + 3
    mov dword ptr [{DIRECT_PDPT} + 16], {DIRECT_PD} + 0x2000 + 3
    mov dword ptr [{DIRECT_PDPT} + 24], {DIRECT_PD} + 0x3000 + 3
    mov edi, {DIRECT_PD}
    mov eax, 0x83               # present|rw|page-size(2MB)
    mov ecx, 2048
stage2_fill_direct:
    mov dword ptr [edi], eax
    mov dword ptr [edi + 4], 0x80000000     # NX
    add eax, 0x200000
    add edi, 8
    dec ecx
    jnz stage2_fill_direct
    mov al, 'G'
    call stage2_putc32

    # ---- SSE (CR0.MP|NE, CR0.EM=0; CR4.OSFXSR|OSXMMEXCPT|PAE) ----
    mov eax, cr0
    and eax, 0xFFFFFFFB
    or eax, 0x22
    mov cr0, eax
    mov eax, cr4
    or eax, 0x620
    mov cr4, eax

    # Paginas de dados nao executaveis exigem NXE em toda CPU. Com NXE
    # desligado, o bit NX da PTE e reservado e ate leituras falham.
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb stage2_no_nx
    mov eax, 0x80000001
    cpuid
    test edx, 0x100000          # CPUID.NX
    jz stage2_no_nx

    # Uma entrada PAT dedicada para secoes PAGE_WRITECOMBINE. Programada antes
    # da paginacao, com caches desligados/esvaziados e interrupcoes off.
    mov eax, 1
    cpuid
    test edx, 0x10000
    jz stage2_no_nx
    mov ebx, cr0
    mov eax, ebx
    or eax, 0x40000000
    and eax, 0xDFFFFFFF
    mov cr0, eax
    wbinvd
    mov ecx, 0x277
    mov eax, 0x00070406
    mov edx, 0x00070401         # PAT[4]=WC; valores de reset nos outros slots
    wrmsr
    wbinvd
    mov cr0, ebx

    # ---- long mode ----
    mov eax, {PML4}
    mov cr3, eax
    mov ecx, 0xC0000080         # EFER
    rdmsr
    or eax, 0x900               # LME | NXE antes de ligar a paginacao
    wrmsr
    mov eax, cr0
    or eax, 0x80010000          # PG|WP: escritas supervisor obedecem PTEs RO
    mov cr0, eax
    mov al, 'L'
    call stage2_putc32
    # jmp 0x10:stage2_lm64
    .byte 0xEA
    .long stage2_lm64
    .word 0x10
stage2_no_nx:
    mov al, 'N'                 # protecao de pagina exigida indisponivel
    call stage2_putc32
    cli
stage2_nx_halt:
    hlt
    jmp stage2_nx_halt
stage2_bad_kernel32:
    mov al, '!'                 # PE do kernel fora do layout de boot
    call stage2_putc32
    cli
stage2_bad_kernel32_halt:
    hlt
    jmp stage2_bad_kernel32_halt

# ---------------------------------------------------------------------------
.code64
stage2_lm64:
    mov ax, 0x18
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax
    # A GDT continua a mesma, alcancada agora pela VA do mapa direto: o
    # kernel nao depende da identidade transitoria nem para recarregar
    # seletores.
    lgdt [stage2_gdtr64]
    movabs rsp, {STACK_TOP} - 8
    mov al, '6'
    call stage2_putc32          # bytes 32-bit validos aqui tambem
    # A imagem precisa aparecer na VA de link antes do salto.
    movabs rbx, {KERNEL_BASE}
    cmp word ptr [rbx], 0x5A4D
    jne stage2_bad_kernel
    mov eax, dword ptr [stage2_entry_rva]
    add rax, rbx
    jmp rax
stage2_bad_kernel:
    mov al, '!'
    call stage2_putc32
    cli
stage2_halt:
    hlt
    jmp stage2_halt

# ---------------------------------------------------------------------------
.balign 8
stage2_gdt:
    .quad 0                         # null
    .quad 0x00CF9A000000FFFF        # 0x08 code32
    .quad 0x00209A0000000000        # 0x10 code64 (L=1), CS do kernel NT
    .quad 0x0000920000000000        # 0x18 data64, SS do SYSCALL = CS + 8
    .quad 0x00CF92000000FFFF        # 0x20 bootstrap data32
stage2_gdt_end:

.balign 4
stage2_gdtr:
    .word stage2_gdt_end - stage2_gdt - 1
    .long stage2_gdt

.balign 8
    .word 0, 0, 0
stage2_gdtr64:
    .word stage2_gdt_end - stage2_gdt - 1
    .quad stage2_gdt + {DIRECT_MAP_BASE}

stage2_entry_rva:
    .long 0
stage2_image_size:
    .long 0

stage2_sectors_left:
    .long 0
.popsection
.code64
