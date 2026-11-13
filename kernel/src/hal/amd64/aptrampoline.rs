//! Trampolim de Application Processor.
//!
//! O BSP (`ntos::ke::smp`) copia estes bytes para 0x9000, preenche a mailbox
//! em 0xA000 (CR3, pilha, slot) e dispara INIT-SIPI-SIPI pelo LAPIC. O AP
//! entra em modo real (CS=0x900), sobe para 64 bits com o MESMO CR3 do BSP,
//! marca seu slot online e entra no laço de jobs nativos:
//! SLOT_JOB_FUNC != 0 -> func(args 1..4) MS ABI -> SLOT_JOB_RES, SLOT_JOB_DONE=1.
//!
//! Os bytes ficam na imagem do kernel; todo endereço absoluto é escrito como
//! `rótulo - ap_trampoline_start + 0x9000`, resolvido pelo montador, para o
//! código funcionar depois de copiado.

use core::arch::global_asm;

pub const LOAD_ADDRESS: u64 = 0x9000;

global_asm!(
    r#"
.pushsection .rodata.aptrampoline, "a", @progbits
.global ap_trampoline_start
.global ap_trampoline_end
.code16
ap_trampoline_start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov dword ptr [{mailbox} + 0x20], 0x16          # AP vivo em modo real
    .byte 0x0F, 0x01, 0x16                          # lgdt [disp16] (16 bits)
    .word ap_gdtr - ap_trampoline_start + {base}
    mov eax, cr0
    or eax, 1                                       # PE
    mov cr0, eax
    .byte 0x66, 0xEA                                # jmp dword 0x08:ap_pm32
    .long ap_pm32 - ap_trampoline_start + {base}
    .word 0x08

.code32
ap_pm32:
    mov ax, 0x20                                    # bootstrap data32
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov dword ptr [{mailbox} + 0x24], 0x32          # AP em modo protegido
    # O CR3 compartilhado já pode ter páginas NX: liga NXE antes de PG.
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb ap_no_nx
    mov eax, 0x80000001
    cpuid
    test edx, 0x100000
    jz ap_no_nx
    mov eax, 1
    cpuid
    test edx, 0x10000
    jz ap_no_nx
    wbinvd                                          # INIT deixa os caches desligados
    mov ecx, 0x277
    mov eax, 0x00070406
    mov edx, 0x00070401                             # mesmo PAT do BSP (4 = WC)
    wrmsr
    wbinvd
    mov eax, cr4
    or eax, 0x620                                   # PAE|OSFXSR|OSXMMEXCPT
    mov cr4, eax
    mov eax, dword ptr [{mailbox} + 0x18]
    mov cr3, eax                                    # mesmas tabelas do BSP
    mov ecx, 0xC0000080                             # EFER
    rdmsr
    or eax, 0x900                                   # LME | NXE
    wrmsr
    mov eax, cr0
    and eax, 0x9FFFFFFB                             # EM=0, CD=0, NW=0
    or eax, 0x80010022                              # PG|WP|MP|NE
    mov cr0, eax
    .byte 0xEA                                      # jmp 0x10:ap_lm64
    .long ap_lm64 - ap_trampoline_start + {base}
    .word 0x10
ap_no_nx:
    mov dword ptr [{mailbox} + 0x24], 0x4E58        # 'NX': o AP fica offline
    cli
ap_nx_halt:
    hlt
    jmp ap_nx_halt

.code64
ap_lm64:
    mov ax, 0x18
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax
    # Um AP atrasado não pode consumir pilha/mailbox de outro AP.
    mov edx, 0xFEE00020
    mov eax, dword ptr [rdx]
    shr eax, 24
    mov ecx, {mailbox} + 0x2C
    cmp eax, dword ptr [rcx]
    jne ap_park
    mov ecx, {mailbox} + 0x0C
    mov ebx, dword ptr [rcx]
    cmp ebx, 15
    jae ap_park
    mov ecx, {mailbox} + 0x10
    mov rsp, qword ptr [rcx]
    mov ecx, {mailbox} + 0x28
    mov dword ptr [rcx], 0x64
    shl rbx, 6                                      # * 64 (tamanho do slot)
    lea r15, [rbx + {mailbox} + 0x100]
    # NMIs de shootdown podem interromper um job nativo mesmo com IF=0:
    # instala o handler antes de publicar o processador como online.
    .byte 0xB9                                      # mov ecx, imm32
    .long ap_idtr - ap_trampoline_start + {base}
    lidt [rcx]
    mov dword ptr [r15], eax                        # SLOT_APIC_ID
    mov dword ptr [r15 + 0x38], 1                   # SLOT_JOB_DONE
    mov dword ptr [r15 + 0x04], 1                   # SLOT_ONLINE
    mov ecx, {mailbox} + 0x04
    lock inc dword ptr [rcx]                        # MB_ONLINE
    mov ecx, {mailbox} + 0x0C
    mov eax, dword ptr [rcx]
    inc eax
    mov ecx, {mailbox} + 0x08
    mov dword ptr [rcx], eax                        # confirmação exata do slot

ap_job_loop:
    mov rax, qword ptr [r15 + 0x08]                 # SLOT_JOB_FUNC
    test rax, rax
    jnz ap_run_job
    pause
    jmp ap_job_loop
ap_run_job:
    # O BSP pode paginar/remapear imagens com os APs ociosos.
    mov rax, cr3
    mov cr3, rax
    mov rax, qword ptr [r15 + 0x08]
    mov rcx, qword ptr [r15 + 0x10]
    mov rdx, qword ptr [r15 + 0x18]
    mov r8, qword ptr [r15 + 0x20]
    mov r9, qword ptr [r15 + 0x28]
    mov qword ptr [r15 + 0x08], 0
    and rsp, -16                                    # alinhamento da ABI MS x64
    sub rsp, 32                                     # shadow space do chamador
    call rax
    add rsp, 32
    mov qword ptr [r15 + 0x30], rax                 # SLOT_JOB_RES
    mov dword ptr [r15 + 0x38], 1                   # SLOT_JOB_DONE
    jmp ap_job_loop
ap_park:
    cli
    hlt
    jmp ap_park

ap_tlb_nmi:
    push rax
    push rcx
    push rdx
    mov edx, 0xFEE00020
    mov eax, dword ptr [rdx]
    shr eax, 24
    mov edx, {mailbox} + 0x100
    mov ecx, 15
ap_find_slot:
    cmp dword ptr [rdx], eax
    je ap_found_slot
    add edx, 64
    loop ap_find_slot
    jmp ap_nmi_done
ap_found_slot:
    cmp dword ptr [rdx + 0x04], 1
    jne ap_nmi_done
    mov ecx, {mailbox} + 0x30
    mov eax, dword ptr [rcx]                        # MB_TLB_EPOCH
    cmp dword ptr [rdx + 0x3C], eax
    je ap_nmi_done
    mov ecx, {mailbox} + 0x34
    cmp dword ptr [rcx], 0                          # MB_CACHE_FLUSH
    je ap_translations
    wbinvd
ap_translations:
    # Alternar CR4.PGE também invalida traduções globais; preserva CR4.
    mov rax, cr4
    mov rcx, rax
    and rcx, -129
    mov cr4, rcx
    mov rcx, cr3
    mov cr3, rcx
    mov cr4, rax
    mov ecx, {mailbox} + 0x30
    mov eax, dword ptr [rcx]
    mov dword ptr [rdx + 0x3C], eax                 # SLOT_TLB_ACK
ap_nmi_done:
    pop rdx
    pop rcx
    pop rax
    iretq

.balign 16
ap_idt:
    .quad 0, 0, 0, 0                                # vetores 0 e 1
    .word ap_tlb_nmi - ap_trampoline_start + {base} # vetor 2: NMI
    .word 0x10
    .byte 0, 0x8E
    .word 0
    .long 0, 0
ap_idt_end:
ap_idtr:
    .word ap_idt_end - ap_idt - 1
    .quad ap_idt - ap_trampoline_start + {base}

.balign 8
ap_gdt:
    .quad 0                                         # null
    .quad 0x00CF9A000000FFFF                        # 0x08 code32
    .quad 0x00209A0000000000                        # 0x10 code64 (L=1)
    .quad 0x0000920000000000                        # 0x18 data64
    .quad 0x00CF92000000FFFF                        # 0x20 bootstrap data32
ap_gdt_end:
.balign 4
ap_gdtr:
    .word ap_gdt_end - ap_gdt - 1
    .long ap_gdt - ap_trampoline_start + {base}
ap_trampoline_end:
.popsection
.code64
"#,
    mailbox = const 0xA000,
    base = const LOAD_ADDRESS,
);

extern "C" {
    static ap_trampoline_start: u8;
    static ap_trampoline_end: u8;
}

/// Bytes do trampolim.
pub fn bytes() -> &'static [u8] {
    let start = core::ptr::addr_of!(ap_trampoline_start);
    let end = core::ptr::addr_of!(ap_trampoline_end);
    unsafe { core::slice::from_raw_parts(start, end as usize - start as usize) }
}
