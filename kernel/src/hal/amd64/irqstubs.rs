//! Trampolins de interrupção.
//!
//! O hardware exige código de máquina no vetor da IDT; a lógica fica no
//! kernel. Cada stub de 10 bytes empilha o vetor e salta para `irq_common`,
//! que registra o evento na memória compartilhada, alimenta o ring do
//! teclado, faz EOI e volta com IRETQ — sem chamar Rust.
//!
//! Página física compartilhada (frame 0x81000), acessada pelo mapa direto
//! da metade de sistema; os stubs mantêm a VA da página em R9 e a da página
//! de controle do anel 3 em R8:
//!   +0x000: u32 irq_count[256]       (contagem de interrupções por vetor)
//!   +0x400: ring buffer do teclado   (head u32 @+0x400, tail u32 @+0x404,
//!                                     dados 256B @+0x408)
//!   +0x510: byte de controle — não zero quando um port driver nativo
//!           (i8042prt) é dono da porta 0x60
//!
//! Exceções (vetores 0–31), o fast-fail `int 0x29` e o serviço de depuração
//! `int 0x2D` não podem voltar com IRET cego: no anel 3 o processo morre com o
//! NTSTATUS da exceção (CONTEXT salvo, saída tipo 3, longjmp ao chamador) e o
//! kernel continua; no anel 0 vão para [`rs_kernel_exception`], que imprime o
//! diagnóstico e para a CPU. Antes disso, uma falta de página do anel 0 passa
//! pelos provedores de residência ([`rs_kernel_page_fault`]): página paginável
//! despejada ou cópia na escrita resolvida repete a instrução. O timer
//! encerra intervalos de usuário (tipo 2) e
//! as entradas/saídas do anel 3 trocam o GS (SWAPGS) e o banco de depuração.

use core::arch::global_asm;

use crate::hal::amd64::usermode::{cell, CONTROL_PAGE};
use crate::hal::{cpu, serial};
use crate::ntos::mm::memory_map;
use crate::rtl::print::write_args;

/// Tamanho de cada stub em `irq_stub_table` (push imm8 + jmp rel32 + 3 NOPs).
pub const STUB_SIZE: u64 = 10;

/// Endereços FÍSICOS das células (lidos e gravados por `hal::physical`).
pub const IRQ_PAGE_PHYS: u64 = 0x81000;
pub const IRQ_COUNT_BASE: u64 = IRQ_PAGE_PHYS;
pub const KEYBOARD_HEAD: u64 = IRQ_PAGE_PHYS + 0x400;
pub const KEYBOARD_TAIL: u64 = IRQ_PAGE_PHYS + 0x404;
pub const KEYBOARD_DATA: u64 = IRQ_PAGE_PHYS + 0x408;
pub const NATIVE_KEYBOARD_OWNER: u64 = IRQ_PAGE_PHYS + 0x510;
/// Registrador de EOI do LAPIC (xAPIC) pelo mapa direto.
const LAPIC_EOI: u64 = memory_map::direct_map(memory_map::LAPIC_PHYS + 0xB0);

global_asm!(
    r#"
.pushsection .text.irq, "ax", @progbits

.global irq_stub_table
.balign 16
irq_stub_table:
.set irq_vector, 0
.rept 256
    .byte 0x6A, irq_vector          # push imm8: vetor na pilha, sem clobberar regs
    .byte 0xE9                      # jmp rel32 forcado (stub de tamanho fixo)
    .long irq_common - . - 4
    .byte 0x90, 0x90, 0x90          # alinhamento do stub em 10 bytes
    .set irq_vector, irq_vector + 1
.endr

.balign 16
irq_common:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi                        # todos os regs usados pelo stub (IRQ chega
    push r8                         # em qualquer ponto: nada pode ser clobberado)
    push r9
    push r10
    push r11
    # Veio do anel 3 (CS do frame = 0x33)? Troca para a KPCR (drivers leem
    # gs:[0x188]) e captura os registradores de depuracao do usuario.
    movzx edi, byte ptr [rsp + 72]
    mov r11d, 88
    cmp edi, 8
    je irq_entry_error_code
    cmp edi, 10
    jb irq_entry_cs
    cmp edi, 14
    jbe irq_entry_error_code
    cmp edi, 17
    je irq_entry_error_code
    cmp edi, 21
    je irq_entry_error_code
    cmp edi, 29
    je irq_entry_error_code
    cmp edi, 30
    jne irq_entry_cs
irq_entry_error_code:
    mov r11d, 96                    # com codigo de erro, o CS fica 8 bytes depois
irq_entry_cs:
    cmp word ptr [rsp + r11], 0x33
    jne irq_gs_ready
    swapgs
    call user_debug_leave
irq_gs_ready:
    movzx edi, byte ptr [rsp + 72]  # vetor (push imm8 estende o sinal: so o byte)
    # Celulas pelo mapa direto: R8 = pagina de controle, R9 = pagina de IRQ
    # (os dois ja estao salvos no quadro).
    movabs r8, {control_page}
    movabs r9, {irq_page}

    # irq_count[vetor]++
    inc dword ptr [r9 + rdi*4 + {irq_count}]

    # excecoes (0-31), int 0x29 (fast fail) e int 0x2D (servico de depuracao)
    cmp edi, 0x20
    jb irq_exception
    cmp edi, 0x29
    je irq_exception
    cmp edi, 0x2D
    je irq_exception

    # O timer pode encerrar um intervalo de usuario: o CONTEXT e capturado
    # antes de qualquer ISR tocar x87/SSE.
    cmp edi, 0x40
    jne irq_context_saved
    cmp word ptr [rsp + 88], 0x33
    jne irq_context_saved
    mov rax, [r8 + {context_cell}]
    test rax, rax
    jz irq_context_saved
    fxsave64 [rax + 0x100]
    mov edx, [rax + 0x118]
    mov [rax + 0x34], edx
    mov [rax + 0x90], rbx
    mov [rax + 0xA0], rbp
    mov [rax + 0xD8], r12
    mov [rax + 0xE0], r13
    mov [rax + 0xE8], r14
    mov [rax + 0xF0], r15
    mov rdx, [rsp + 64]
    mov [rax + 0x78], rdx
    mov rdx, [rsp + 56]
    mov [rax + 0x80], rdx
    mov rdx, [rsp + 48]
    mov [rax + 0x88], rdx
    mov rdx, [rsp + 104]
    mov [rax + 0x98], rdx
    mov rdx, [rsp + 40]
    mov [rax + 0xA8], rdx
    mov rdx, [rsp + 32]
    mov [rax + 0xB0], rdx
    mov rdx, [rsp + 24]
    mov [rax + 0xB8], rdx
    mov rdx, [rsp + 16]
    mov [rax + 0xC0], rdx
    mov rdx, [rsp + 8]
    mov [rax + 0xC8], rdx
    mov rdx, [rsp]
    mov [rax + 0xD0], rdx
    mov rdx, [rsp + 80]
    mov [rax + 0xF8], rdx
    mov edx, [rsp + 96]
    mov [rax + 0x44], edx
irq_context_saved:

    # IRQ1 (teclado): le o scancode e empilha no ring buffer, exceto quando
    # um port driver nativo conectou o vetor (byte de controle nao zero)
    cmp edi, 0x21
    jne irq_no_key
    cmp byte ptr [r9 + {native_keyboard}], 0
    jne irq_no_key
    in al, 0x60
    mov ecx, dword ptr [r9 + {kbd_head}]
    mov edx, ecx
    inc edx
    and edx, 0xFF
    cmp edx, dword ptr [r9 + {kbd_tail}]
    je irq_no_key                   # cheio: descarta
    mov byte ptr [r9 + rcx + {kbd_data}], al
    mov dword ptr [r9 + {kbd_head}], edx
irq_no_key:
    # EOI: vetores >= 0x40 sao do LAPIC (timer etc.)
    cmp edi, 0x40
    jb irq_pic_eoi
    movabs rax, {lapic_eoi}
    mov dword ptr [rax], 0
    jmp irq_restore
irq_pic_eoi:
    # IRQs 8-15 (vetores 0x28+) tambem no slave
    cmp edi, 0x28
    jb irq_master_eoi
    mov al, 0x20
    out 0xA0, al
irq_master_eoi:
    mov al, 0x20
    out 0x20, al
irq_restore:
    # Fim do intervalo de usuario pelo timer: volta ao escalonador (tipo 2).
    cmp edi, 0x40
    jne irq_restore_registers
    cmp word ptr [rsp + 88], 0x33
    jne irq_restore_registers
    cmp qword ptr [r8 + {context_cell}], 0
    je irq_restore_registers
    mov dword ptr [r8 + {exit_kind}], 2
    xor edi, edi
    jmp user_terminate_current
irq_restore_registers:
    cmp word ptr [rsp + 88], 0x33
    jne irq_kernel_registers
    call user_debug_enter
irq_kernel_registers:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    add rsp, 8                      # descarta o vetor empilhado
    cmp word ptr [rsp + 8], 0x33    # voltando para o anel 3?
    jne irq_iret
    swapgs
irq_iret:
    iretq

irq_exception:
    # Excecao no anel 3: o processo morre com o codigo NTSTATUS e o kernel
    # continua (o longjmp e user_terminate_current). O estado arquitetural
    # vai para o CONTEXT do intervalo; a pilha do usuario nunca e lida aqui.
    mov r10d, edi
    cmp word ptr [rsp + r11], 0x33
    jne irq_kernel_exception
    cmp r10d, 0x29
    je irq_user_context_saved
    mov rax, [r8 + {context_cell}]
    test rax, rax
    jz irq_user_context_saved
    fxsave64 [rax + 0x100]
    mov edx, [rax + 0x118]
    mov [rax + 0x34], edx
    mov [rax + 0x90], rbx
    mov [rax + 0xA0], rbp
    mov [rax + 0xD8], r12
    mov [rax + 0xE0], r13
    mov [rax + 0xE8], r14
    mov [rax + 0xF0], r15
    mov rdx, [rsp + 64]
    mov [rax + 0x78], rdx
    mov rdx, [rsp + 56]
    mov [rax + 0x80], rdx
    mov rdx, [rsp + 48]
    mov [rax + 0x88], rdx
    mov rdx, [rsp + 40]
    mov [rax + 0xA8], rdx
    mov rdx, [rsp + 32]
    mov [rax + 0xB0], rdx
    mov rdx, [rsp + 24]
    mov [rax + 0xB8], rdx
    mov rdx, [rsp + 16]
    mov [rax + 0xC0], rdx
    mov rdx, [rsp + 8]
    mov [rax + 0xC8], rdx
    mov rdx, [rsp]
    mov [rax + 0xD0], rdx
    mov rdx, [rsp + r11 + 16]
    mov [rax + 0x98], rdx
    mov rdx, [rsp + r11 - 8]
    mov [rax + 0xF8], rdx
    mov edx, [rsp + r11 + 8]
    mov [rax + 0x44], edx
    xor edx, edx
    cmp r11d, 96
    jne irq_user_error_saved
    mov rdx, [rsp + 80]
irq_user_error_saved:
    mov [r8 + {error_code}], rdx    # codigo de erro do hardware (acesso do #PF)
    mov dword ptr [r8 + {exit_kind}], 3  # excecao, despachada pelo kernel
irq_user_context_saved:
    mov [r8 + {fault_vector}], r10d
    mov rax, [rsp + 56]             # RCX original, inclusive __fastfail(codigo)
    mov [r8 + {fault_rcx}], rax
    mov rax, [rsp + r11 - 8]
    mov [r8 + {fault_rip}], rax
    # vetor -> NTSTATUS (o que o KiDispatchException relataria)
    mov edi, 0xC0000005
    cmp r10d, 0x29
    je irq_user_fastfail
    cmp r10d, 6
    je irq_user_illegal
    cmp r10d, 0
    je irq_user_divide
    cmp r10d, 3
    je irq_user_breakpoint
    cmp r10d, 1
    je irq_user_single_step
    jmp irq_user_terminate
irq_user_illegal:
    mov edi, 0xC000001D
    jmp irq_user_terminate
irq_user_divide:
    mov edi, 0xC0000094
    jmp irq_user_terminate
irq_user_breakpoint:
    mov edi, 0x80000003
    jmp irq_user_terminate
irq_user_single_step:
    mov edi, 0x80000004
    jmp irq_user_terminate
irq_user_fastfail:
    mov edi, 0xC0000409             # fast fail nao continuavel, parametro = RCX
irq_user_terminate:
    # Publica a pilha do usuario e o CR2, e os imprime antes de encerrar.
    mov rax, [rsp + r11 + 16]
    mov [r8 + {fault_rsp}], rax
    mov rax, cr2
    mov [r8 + {fault_cr2}], rax
    mov dx, 0x3F8
    mov al, 0x20
    out dx, al
    mov al, 0x43
    out dx, al
    mov al, 0x32
    out dx, al
    mov al, 0x3D
    out dx, al
    mov r10, cr2
    call irq_hex64
    mov al, 0x20
    out dx, al
    mov al, 0x53
    out dx, al
    mov al, 0x50
    out dx, al
    mov al, 0x3D
    out dx, al
    mov r10, [rsp + r11 + 16]
    call irq_hex64
    mov al, 0x0D
    out dx, al
    mov al, 0x0A
    out dx, al
    jmp user_terminate_current

# Imprime r10 em 16 digitos hexadecimais na COM1 (dx = 0x3F8).
irq_hex64:
    mov ecx, 16
irq_hex_digit:
    rol r10, 4
    mov eax, r10d
    and eax, 15
    cmp eax, 10
    jb irq_hex_decimal
    add eax, 0x37
    jmp irq_hex_emit
irq_hex_decimal:
    add eax, 0x30
irq_hex_emit:
    out dx, al
    dec ecx
    jnz irq_hex_digit
    ret

irq_kernel_exception:
    # #PF do anel 0: os provedores de residencia (pagina paginavel
    # despejada, copia na escrita) tratam a falta antes do SEH e do
    # diagnostico, como o MmAccessFault; resolvida, a instrucao repete.
    cmp r10d, 14
    jne irq_kernel_not_resident
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rsp
    and rsp, -16
    sub rsp, 512
    fxsave64 [rsp]
    cld
    mov r12, cr2
    mov r13, [rip + opennt_kernel_native_active]
    mov r14, [rip + opennt_kernel_native_host_rsp]
    mov r15, [rip + opennt_kernel_sync_active]
    mov qword ptr [rip + opennt_kernel_native_active], 0
    mov qword ptr [rip + opennt_kernel_sync_active], 0
    mov rdi, r12
    mov rsi, [rbx + 40 + 80]        # codigo de erro do hardware
    mov rdx, [rbx + 40 + 104]       # RFLAGS interrompido
    call rs_kernel_page_fault
    mov [rip + opennt_kernel_native_host_rsp], r14
    mov [rip + opennt_kernel_native_active], r13
    mov [rip + opennt_kernel_sync_active], r15
    mov cr2, r12                    # faltas aninhadas resolvidas nao mudam o CR2
    fxrstor64 [rsp]
    mov rsp, rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    mov r10d, 14                    # vetor e deslocamento do CS (com codigo de erro)
    mov r11d, 96
    test eax, eax
    jz irq_kernel_not_resident
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    add rsp, 16                     # vetor e codigo de erro
    iretq
irq_kernel_not_resident:
    # So faltas numa execucao nativa possuida entram no SEH de kernel; o
    # fast fail continua fatal. Machine check e double fault nao rodam
    # tratador.
    cmp r10d, 0x29
    je irq_kernel_diagnostic
    cmp qword ptr [rip + opennt_kernel_native_active], 0
    jne irq_kernel_trap_owner
    cmp qword ptr [rip + opennt_kernel_sync_active], 0
    je irq_kernel_diagnostic
irq_kernel_trap_owner:
    cmp word ptr [rsp + r11], 0x10
    jne irq_kernel_diagnostic
    cmp r10d, 8
    je irq_kernel_diagnostic
    cmp r10d, 18
    je irq_kernel_diagnostic
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov rbp, rsp
    mov ebx, r11d                   # 96 = frame com codigo de erro
    and rsp, -16
    sub rsp, 528
    fxsave64 [rsp]
    cld
    mov r12, [rip + opennt_kernel_native_active]
    mov r13, [rip + opennt_kernel_native_host_rsp]
    mov r14, [rip + opennt_kernel_sync_active]
    mov qword ptr [rip + opennt_kernel_native_active], 0
    mov qword ptr [rip + opennt_kernel_sync_active], 0
    mov edi, r10d
    mov rsi, rbp
    mov rdx, rsp
    call rs_kernel_trap_dispatch
    mov [rsp + 512], eax
    mov [rip + opennt_kernel_native_host_rsp], r13
    mov [rip + opennt_kernel_native_active], r12
    mov [rip + opennt_kernel_sync_active], r14
    fxrstor64 [rsp]
    mov eax, [rsp + 512]
    cmp ebx, 96
    mov rsp, rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    je irq_kernel_trap_with_error
    test eax, eax
    jz irq_kernel_diagnostic
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    add rsp, 8
    iretq
irq_kernel_trap_with_error:
    test eax, eax
    jz irq_kernel_diagnostic
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    add rsp, 16
    iretq
irq_kernel_diagnostic:
    # Completa o frame com os registradores preservados e entrega ao
    # diagnostico do kernel, que nao retorna.
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov rdi, rsp
    and rsp, -16
    cld
    call rs_kernel_exception
irq_exception_halt:
    cli
    hlt
    jmp irq_exception_halt

.popsection
"#,
    control_page = const CONTROL_PAGE,
    irq_page = const memory_map::direct_map(IRQ_PAGE_PHYS),
    lapic_eoi = const LAPIC_EOI,
    irq_count = const IRQ_COUNT_BASE - IRQ_PAGE_PHYS,
    native_keyboard = const NATIVE_KEYBOARD_OWNER - IRQ_PAGE_PHYS,
    kbd_head = const KEYBOARD_HEAD - IRQ_PAGE_PHYS,
    kbd_tail = const KEYBOARD_TAIL - IRQ_PAGE_PHYS,
    kbd_data = const KEYBOARD_DATA - IRQ_PAGE_PHYS,
    context_cell = const cell::USER_CONTEXT,
    exit_kind = const cell::EXIT_KIND,
    error_code = const cell::ERROR_CODE,
    fault_vector = const cell::FAULT_VECTOR,
    fault_rcx = const cell::FAULT_RCX,
    fault_rip = const cell::FAULT_RIP,
    fault_rsp = const cell::FAULT_RSP,
    fault_cr2 = const cell::FAULT_CR2,
);

extern "C" {
    static irq_stub_table: u8;
}

/// Endereço do primeiro stub.
pub fn stub_table() -> u64 {
    core::ptr::addr_of!(irq_stub_table) as u64
}

/// Frame salvo por `irq_common` + `irq_exception`, do topo da pilha para
/// baixo. Depois do vetor vem o frame do hardware, precedido do código de
/// erro nos vetores que o empilham.
#[repr(C)]
pub struct TrapFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub vector: u64,
    pub hardware: [u64; 6],
}

/// Vetores cujas exceções empilham código de erro.
pub fn has_error_code(vector: u8) -> bool {
    matches!(vector, 8 | 10..=14 | 17 | 21 | 29 | 30)
}

fn exception_name(vector: u8) -> &'static str {
    match vector {
        0 => "#DE divisao",
        1 => "#DB depuracao",
        2 => "NMI",
        3 => "#BP breakpoint",
        4 => "#OF overflow",
        5 => "#BR bound",
        6 => "#UD instrucao invalida",
        7 => "#NM FPU indisponivel",
        8 => "#DF falta dupla",
        10 => "#TS TSS invalida",
        11 => "#NP segmento ausente",
        12 => "#SS pilha",
        13 => "#GP protecao geral",
        14 => "#PF falta de pagina",
        16 => "#MF x87",
        17 => "#AC alinhamento",
        18 => "#MC machine check",
        19 => "#XM SIMD",
        20 => "#VE virtualizacao",
        21 => "#CP controle de fluxo",
        0x29 => "fast fail (int 0x29)",
        0x2D => "servico de depuracao (int 0x2D)",
        _ => "excecao",
    }
}

/// Estado do processador entregue ao despacho: banco de depuração, base do
/// GS, seletores, código de erro e CR2.
#[repr(C)]
struct ProcessorState {
    debug: [u64; 6],
    gs_base: u64,
    segments: [u16; 4],
    error_code: u64,
    fault_address: u64,
}

#[repr(C, align(16))]
struct TrapWorkspace([u8; 0xB00]);

/// #PF do anel 0, antes do SEH e do diagnóstico: os provedores de
/// residência resolvem uma página paginável despejada ou uma cópia na
/// escrita (IRQL até APC_LEVEL), e a instrução é repetida. Roda com o IF do
/// contexto interrompido, como o acesso que faltou; devolve não zero quando
/// a falta foi resolvida.
#[no_mangle]
extern "sysv64" fn rs_kernel_page_fault(address: u64, error_code: u64, interrupted_flags: u64) -> u32 {
    if interrupted_flags & 0x200 != 0 {
        cpu::enable_interrupts();
    }
    let resolved = crate::ntos::mm::page_residency::fault(address, error_code as u32);
    unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
    resolved as u32
}

/// Primeira chance de um trap do anel 0 numa execução nativa possuída:
/// devolve não zero quando o SEH pediu continuação.
#[no_mangle]
extern "sysv64" fn rs_kernel_trap_dispatch(vector: u32, registers: u64, fx: u64) -> u32 {
    use core::arch::asm;
    let error_size = if has_error_code(vector as u8) { 8 } else { 0 };
    let interrupted_flags = unsafe { core::ptr::read_volatile((registers + 144 + error_size) as *const u64) };
    let mut state = ProcessorState { debug: [0; 6], gs_base: 0, segments: [0; 4], error_code: 0, fault_address: 0 };
    unsafe {
        asm!("mov {}, dr7", out(reg) state.debug[5]);
        asm!("mov dr7, {}", in(reg) 0u64);
        asm!("mov {}, dr0", out(reg) state.debug[0]);
        asm!("mov {}, dr1", out(reg) state.debug[1]);
        asm!("mov {}, dr2", out(reg) state.debug[2]);
        asm!("mov {}, dr3", out(reg) state.debug[3]);
        asm!("mov {}, dr6", out(reg) state.debug[4]);
        if error_size != 0 {
            state.error_code = core::ptr::read_volatile((registers + 128) as *const u64);
        }
        let (ds, es, fs, gs): (u16, u16, u16, u16);
        asm!("mov {:x}, ds", out(reg) ds);
        asm!("mov {:x}, es", out(reg) es);
        asm!("mov {:x}, fs", out(reg) fs);
        asm!("mov {:x}, gs", out(reg) gs);
        state.segments = [ds, es, fs, gs];
    }
    // CR2 guarda o endereço do page fault; em outros vetores pode refletir
    // uma falha anterior.
    state.fault_address = cpu::read_cr2();
    state.gs_base = cpu::read_msr(0xC000_0101);
    let mut workspace = TrapWorkspace([0; 0xB00]);
    // O despacho recebe o IF anterior; TF continua limpo até o IRET.
    if interrupted_flags & 0x200 != 0 {
        cpu::enable_interrupts();
    }
    let handled = match crate::ntos::ke::kernel_exception::dispatch(vector, registers, fx, &mut state as *mut ProcessorState as u64, workspace.0.as_mut_ptr() as u64) {
        Ok(handled) => handled,
        Err(error) => {
            write_args(format_args!("\n*** excecao de kernel nao despachada: {}\n", error));
            false
        }
    };
    // Nenhuma interrupção no meio da restauração do banco de depuração; o
    // IF definitivo volta pelo frame IRET.
    unsafe {
        asm!("cli");
        asm!("mov dr0, {}", in(reg) state.debug[0]);
        asm!("mov dr1, {}", in(reg) state.debug[1]);
        asm!("mov dr2, {}", in(reg) state.debug[2]);
        asm!("mov dr3, {}", in(reg) state.debug[3]);
        asm!("mov dr6, {}", in(reg) state.debug[4]);
        asm!("mov dr7, {}", in(reg) state.debug[5]);
    }
    handled as u32
}

/// Diagnóstico de exceção de kernel. Não aloca nem adquire locks.
#[no_mangle]
extern "C" fn rs_kernel_exception(frame: &TrapFrame) -> ! {
    let vector = (frame.vector & 0xFF) as u8;
    let (error_code, rest) = if has_error_code(vector) {
        (Some(frame.hardware[0]), &frame.hardware[1..])
    } else {
        (None, &frame.hardware[..5])
    };
    let (rip, cs, rflags, rsp) = (rest[0], rest[1], rest[2], rest[3]);
    serial::puts("\n*** EXCECAO DE KERNEL: ");
    write_args(format_args!("vetor {:#04x} ({})", vector, exception_name(vector)));
    if let Some(code) = error_code {
        write_args(format_args!(" erro={:#x}", code));
    }
    write_args(format_args!("\n    RIP={:#018x} CS={:#06x} RFLAGS={:#x} RSP={:#018x}\n", rip, cs, rflags, rsp));
    if vector == 14 {
        write_args(format_args!("    CR2={:#018x}\n", cpu::read_cr2()));
    }
    write_args(format_args!(
        "    RAX={:#018x} RBX={:#018x} RCX={:#018x} RDX={:#018x}\n",
        frame.rax, frame.rbx, frame.rcx, frame.rdx
    ));
    write_args(format_args!(
        "    RSI={:#018x} RDI={:#018x} RBP={:#018x}\n",
        frame.rsi, frame.rdi, frame.rbp
    ));
    write_args(format_args!(
        "    R8 ={:#018x} R9 ={:#018x} R10={:#018x} R11={:#018x}\n",
        frame.r8, frame.r9, frame.r10, frame.r11
    ));
    write_args(format_args!(
        "    R12={:#018x} R13={:#018x} R14={:#018x} R15={:#018x}\n",
        frame.r12, frame.r13, frame.r14, frame.r15
    ));
    serial::puts("*** sistema parado ***\n");
    cpu::halt_forever()
}
