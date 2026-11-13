//! Trampolim de Application Processor.
//!
//! O BSP (`ntos::ke::smp`) copia o trampolim para 0x9000, mapeia essa página
//! em identidade só enquanto os APs partem (como o stub baixo do NT),
//! preenche a mailbox em 0xA000 (CR3, pilha, slot) e dispara INIT-SIPI-SIPI
//! pelo LAPIC. O AP entra em modo real (CS=0x900), sobe para 64 bits com o
//! MESMO CR3 do BSP e salta para `ap_kernel_entry`, na imagem do kernel (VA
//! de sistema): dali em diante nada do AP depende da página baixa. Na imagem
//! ele troca para a GDT e a IDT do kernel, marca seu slot online e entra no
//! laço de jobs nativos:
//! SLOT_JOB_FUNC != 0 -> func(args 1..4) MS ABI -> SLOT_JOB_RES, SLOT_JOB_DONE=1.
//!
//! Os bytes do trampolim ficam na imagem do kernel; todo endereço absoluto
//! do trecho de 16/32 bits é escrito como `rótulo - ap_trampoline_start +
//! 0x9000`, resolvido pelo montador, para o código funcionar depois de
//! copiado. O salto para a imagem leva a VA absoluta de `ap_kernel_entry`,
//! resolvida pelo linker.
//!
//! Antes da paginação (modos real e protegido) o AP lê a mailbox pelo
//! endereço físico, como exige a CPU. Em 64 bits, os dados (mailbox, slots,
//! LAPIC, pilha) são acessados pelo mapa direto da metade de sistema.

use core::arch::global_asm;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::mm::memory_map;

pub const LOAD_ADDRESS: u64 = memory_map::AP_TRAMPOLINE_PHYS;
const MAILBOX_PHYS: u64 = memory_map::SMP_MAILBOX_PHYS;
/// Seletor de código de 64 bits das GDTs de boot e do AP.
const CODE_SELECTOR: u64 = 0x10;

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
    # Sai da página do trampolim: o resto roda na imagem do kernel.
    .byte 0x48, 0xB8                                # movabs rax, imm64
    .quad ap_kernel_entry
    jmp rax

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

.pushsection .text.ap_kernel, "ax", @progbits
.code64
ap_kernel_entry:
    # GDT e IDT do AP na imagem do kernel: depois daqui nenhuma carga de
    # seletor nem NMI passa pela página baixa.
    lgdt [rip + ap_kernel_gdtr]
    lidt [rip + ap_kernel_idtr]
    # Dados pelo mapa direto: RSI = mailbox.
    movabs rsi, {direct_mailbox}
    # Um AP atrasado não pode consumir pilha/mailbox de outro AP.
    movabs rdx, {direct_lapic_id}
    mov eax, dword ptr [rdx]
    shr eax, 24
    cmp eax, dword ptr [rsi + 0x2C]
    jne ap_park
    mov ebx, dword ptr [rsi + 0x0C]
    cmp ebx, 15
    jae ap_park
    mov rsp, qword ptr [rsi + 0x10]                 # pilha (VA do mapa direto)
    mov dword ptr [rsi + 0x28], 0x64
    shl rbx, 6                                      # * 64 (tamanho do slot)
    lea r15, [rsi + rbx + 0x100]
    mov dword ptr [r15], eax                        # SLOT_APIC_ID
    mov dword ptr [r15 + 0x38], 1                   # SLOT_JOB_DONE
    mov dword ptr [r15 + 0x04], 1                   # SLOT_ONLINE
    lock inc dword ptr [rsi + 0x04]                 # MB_ONLINE
    mov eax, dword ptr [rsi + 0x0C]
    inc eax
    mov dword ptr [rsi + 0x08], eax                 # confirmação exata do slot

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

.global ap_tlb_nmi
ap_tlb_nmi:
    push rax
    push rcx
    push rdx
    movabs rdx, {direct_lapic_id}
    mov eax, dword ptr [rdx]
    shr eax, 24
    movabs rdx, {direct_mailbox} + 0x100
    mov ecx, 15
ap_find_slot:
    cmp dword ptr [rdx], eax
    je ap_found_slot
    add rdx, 64
    loop ap_find_slot
    jmp ap_nmi_done
ap_found_slot:
    cmp dword ptr [rdx + 0x04], 1
    jne ap_nmi_done
    movabs rcx, {direct_mailbox}
    mov eax, dword ptr [rcx + 0x30]                 # MB_TLB_EPOCH
    cmp dword ptr [rdx + 0x3C], eax
    je ap_nmi_done
    cmp dword ptr [rcx + 0x34], 0                   # MB_CACHE_FLUSH
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
    movabs rcx, {direct_mailbox}
    mov eax, dword ptr [rcx + 0x30]
    mov dword ptr [rdx + 0x3C], eax                 # SLOT_TLB_ACK
ap_nmi_done:
    pop rdx
    pop rcx
    pop rax
    iretq
.popsection

.pushsection .rodata.ap_kernel, "a", @progbits
.balign 8
ap_kernel_gdt:
    .quad 0                                         # null
    .quad 0x00CF9A000000FFFF                        # 0x08 code32
    .quad 0x00209A0000000000                        # 0x10 code64 (L=1)
    .quad 0x0000920000000000                        # 0x18 data64
    .quad 0x00CF92000000FFFF                        # 0x20 bootstrap data32
ap_kernel_gdt_end:
.balign 8
    .word 0, 0, 0
ap_kernel_gdtr:
    .word ap_kernel_gdt_end - ap_kernel_gdt - 1
    .quad ap_kernel_gdt
.balign 8
    .word 0, 0, 0
ap_kernel_idtr:
    .word 3 * 16 - 1                                # vetores 0..2
    .quad ap_kernel_idt
.popsection

.pushsection .data.ap_kernel, "aw", @progbits
.balign 16
.global ap_kernel_idt
ap_kernel_idt:
    .quad 0, 0, 0, 0, 0, 0                          # vetor 2 (NMI): `prepare_kernel_entry`
.popsection
.code64
"#,
    mailbox = const MAILBOX_PHYS,
    base = const LOAD_ADDRESS,
    direct_mailbox = const memory_map::direct_map(MAILBOX_PHYS),
    direct_lapic_id = const memory_map::direct_map(memory_map::LAPIC_PHYS + 0x20),
);

extern "C" {
    static ap_trampoline_start: u8;
    static ap_trampoline_end: u8;
    static ap_tlb_nmi: u8;
    static ap_kernel_idt: [AtomicU64; 6];
}

/// Bytes do trampolim.
pub fn bytes() -> &'static [u8] {
    let start = core::ptr::addr_of!(ap_trampoline_start);
    let end = core::ptr::addr_of!(ap_trampoline_end);
    unsafe { core::slice::from_raw_parts(start, end as usize - start as usize) }
}

/// Grava o portão de NMI (vetor 2, interrupção de 64 bits, DPL 0) da IDT
/// dos APs com a VA da rotina de shootdown na imagem do kernel. O BSP chama
/// antes do primeiro SIPI; a IDT não muda depois.
pub fn prepare_kernel_entry() {
    let handler = core::ptr::addr_of!(ap_tlb_nmi) as u64;
    let low = (handler & 0xFFFF) | (CODE_SELECTOR << 16) | (0x8E << 40) | ((handler >> 16) & 0xFFFF) << 48;
    // SAFETY: a IDT dos APs é desta camada; nenhum AP está rodando ainda.
    let table = unsafe { &ap_kernel_idt };
    table[4].store(low, Ordering::Release);
    table[5].store(handler >> 32, Ordering::Release);
}
