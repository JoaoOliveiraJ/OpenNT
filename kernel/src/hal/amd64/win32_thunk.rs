//! Trampolins dos exports do kernel.
//!
//! O IAT de um PE carregado recebe o endereço destes stubs. Cada stub de dez
//! bytes marca seu id (`mov eax, id` + `jmp rel32` forçado) e cai no
//! trampolim comum, que captura um CONTEXT AMD64 do chamador e chama o
//! despachante Rust (`opennt_ntoskrnl_dispatch`, ABI MS x64) com o id, o
//! frame original e o contexto. Se o despachante marcar a ação em
//! CONTEXT+0x4D0, a execução retoma no RIP/RSP do contexto (exceções e
//! unwind); senão restaura os não voláteis e retorna o RAX do handler.
//!
//! Quando um contexto nativo agendado está ativo (`kernel_native_active`),
//! o trampolim comum desvia para `kernel_native_trap`, que salva o estado no
//! contexto e volta ao `kernel_context_run` do hospedeiro; o despacho da API
//! acontece fora do contexto (`ntos::rtl::native_context`).
//!
//! Ids: 0–31 = kernel32 (modo usuário), >= 32 = exports do ntoskrnl.

/// Quantidade de stubs. Os ids 0–31 são do kernel32 e cada export do ntoskrnl
/// ocupa o id `32 + índice`, então a tabela precisa de `32 + EXPORT_NAMES.len()`
/// stubs — o boot verifica isso (`init::exports`). O `.rept` abaixo usa esta
/// constante, então os dois não divergem.
pub const MAX_WIN32: u32 = 2048;
/// Bytes por stub.
pub const STUB_SIZE: u64 = 10;

core::arch::global_asm!(
    r#"
.pushsection .text.win32_thunks, "ax", @progbits
.global opennt_win32_stubs
.balign 16
opennt_win32_stubs:
.set opennt_stub_index, 0
.rept {stubs}
    .byte 0xB8
    .long opennt_stub_index
    .byte 0xE9
    .long opennt_win32_common - . - 4
    .set opennt_stub_index, opennt_stub_index + 1
.endr

.balign 16
.global opennt_win32_common
opennt_win32_common:
    # Preserva as flags antes de escolher o caminho síncrono ou o agendado.
    pushfq
    cmp qword ptr [rip + opennt_kernel_native_active], 0
    jne 5f
    popfq
    push rbp
    mov rbp, rsp
    pushfq
    # CONTEXT AMD64 em rbp-500h; DWORD de ação em +4D0h.
    lea rsp, [rbp - 0x500]
    mov [rsp + 0x78], rax
    mov [rsp + 0x80], rcx
    mov [rsp + 0x88], rdx
    mov [rsp + 0x90], rbx
    lea rax, [rbp + 16]
    mov [rsp + 0x98], rax
    mov rax, [rbp]
    mov [rsp + 0xA0], rax
    mov [rsp + 0xA8], rsi
    mov [rsp + 0xB0], rdi
    mov [rsp + 0xB8], r8
    mov [rsp + 0xC0], r9
    mov [rsp + 0xC8], r10
    mov [rsp + 0xD0], r11
    mov [rsp + 0xD8], r12
    mov [rsp + 0xE0], r13
    mov [rsp + 0xE8], r14
    mov [rsp + 0xF0], r15
    mov rax, [rbp + 8]
    mov [rsp + 0xF8], rax
    fxsave64 [rsp + 0x100]
    xor eax, eax
    mov rdi, rsp
    mov ecx, 15
    cld
    rep stosq
    lea rdi, [rsp + 0x300]
    mov ecx, 59
    rep stosq
    mov dword ptr [rsp + 0x30], 0x10000B
    stmxcsr dword ptr [rsp + 0x34]
    mov word ptr [rsp + 0x38], cs
    mov word ptr [rsp + 0x3A], ds
    mov word ptr [rsp + 0x3C], es
    mov word ptr [rsp + 0x3E], fs
    mov word ptr [rsp + 0x40], gs
    mov word ptr [rsp + 0x42], ss
    mov eax, [rbp - 8]
    mov [rsp + 0x44], eax
    # Despachante MS x64: (id, frame original, CONTEXT).
    mov rcx, [rsp + 0x78]
    lea rdx, [rbp + 8]
    mov r8, rsp
    sub rsp, 32
    call opennt_ntoskrnl_dispatch
    lea r11, [rbp - 0x500]
    cmp dword ptr [r11 + 0x4D0], 0
    jne 2f
    fxrstor64 [r11 + 0x100]
    mov rbx, [r11 + 0x90]
    mov rsi, [r11 + 0xA8]
    mov rdi, [r11 + 0xB0]
    mov r12, [r11 + 0xD8]
    mov r13, [r11 + 0xE0]
    mov r14, [r11 + 0xE8]
    mov r15, [r11 + 0xF0]
    mov rsp, rbp
    pop rbp
    ret
2:
    # Retoma no contexto alterado pelo despachante (nenhum frame sobrevive).
    fxrstor64 [r11 + 0x100]
    mov rsp, [r11 + 0x98]
    mov r10d, [r11 + 0x44]
    push r10
    popfq
    push qword ptr [r11 + 0xF8]
    mov rax, [r11 + 0x78]
    mov rcx, [r11 + 0x80]
    mov rdx, [r11 + 0x88]
    mov rbx, [r11 + 0x90]
    mov rbp, [r11 + 0xA0]
    mov rsi, [r11 + 0xA8]
    mov rdi, [r11 + 0xB0]
    mov r8, [r11 + 0xB8]
    mov r9, [r11 + 0xC0]
    mov r10, [r11 + 0xC8]
    mov r12, [r11 + 0xD8]
    mov r13, [r11 + 0xE0]
    mov r14, [r11 + 0xE8]
    mov r15, [r11 + 0xF0]
    mov r11, [r11 + 0xD0]
    ret
5:
    popfq
    jmp opennt_kernel_native_trap

# Contexto nativo: 16 GPRs (RAX,RCX,RDX,RBX,RSP,RBP,RSI,RDI,R8..R15), RIP
# +0x80, RFLAGS +0x88, seletores +0x90, DR0..3/DR6/DR7 +0xA0, FXSAVE64
# +0x100 (512 bytes). Uma CPU executa código nativo agendado por vez; o
# despacho de APIs acontece com kernel_native_active zerado, permitindo
# callbacks nativos síncronos.
.balign 16
.global opennt_kernel_context_run
opennt_kernel_context_run:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    # O contexto nativo é dono de IF/DF/TF; as flags do chamador voltam ao
    # ceder, senão o POPFQ vazaria o estado do worker para o escalonador.
    pushfq
    sub rsp, 576
    mov rax, dr7
    mov [rsp + 0x228], rax
    xor eax, eax
    mov dr7, rax
    mov rax, dr0
    mov [rsp + 0x200], rax
    mov rax, dr1
    mov [rsp + 0x208], rax
    mov rax, dr2
    mov [rsp + 0x210], rax
    mov rax, dr3
    mov [rsp + 0x218], rax
    mov rax, dr6
    mov [rsp + 0x220], rax
    fxsave64 [rsp]
    mov [rip + opennt_kernel_native_host_rsp], rsp
    mov [rip + opennt_kernel_native_active], rdi
    mov rax, [rdi + 0xA0]
    mov dr0, rax
    mov rax, [rdi + 0xA8]
    mov dr1, rax
    mov rax, [rdi + 0xB0]
    mov dr2, rax
    mov rax, [rdi + 0xB8]
    mov dr3, rax
    mov rax, [rdi + 0xC0]
    mov dr6, rax
    fxrstor64 [rdi + 0x100]
    mov rsp, [rdi + 0x20]
    push qword ptr [rdi + 0x88]
    popfq
    push qword ptr [rdi + 0x80]
    mov rcx, [rdi + 0x08]
    mov rdx, [rdi + 0x10]
    mov rbx, [rdi + 0x18]
    mov rbp, [rdi + 0x28]
    mov rsi, [rdi + 0x30]
    mov r8, [rdi + 0x40]
    mov r9, [rdi + 0x48]
    mov r10, [rdi + 0x50]
    mov r11, [rdi + 0x58]
    mov r12, [rdi + 0x60]
    mov r13, [rdi + 0x68]
    mov r14, [rdi + 0x70]
    mov r15, [rdi + 0x78]
    mov rax, [rdi + 0xC8]
    mov dr7, rax
    mov rax, [rdi + 0x00]
    mov rdi, [rdi + 0x38]
    ret

.balign 16
opennt_kernel_native_trap:
    push r11
    mov r11, [rip + opennt_kernel_native_active]
    mov [r11 + 0x00], rax
    mov [r11 + 0x08], rcx
    mov [r11 + 0x10], rdx
    mov [r11 + 0x18], rbx
    # O retorno da API já consumiu o endereço de retorno.
    lea rax, [rsp + 16]
    mov [r11 + 0x20], rax
    mov [r11 + 0x28], rbp
    mov [r11 + 0x30], rsi
    mov [r11 + 0x38], rdi
    mov [r11 + 0x40], r8
    mov [r11 + 0x48], r9
    mov [r11 + 0x50], r10
    mov rax, [rsp]
    mov [r11 + 0x58], rax
    mov [r11 + 0x60], r12
    mov [r11 + 0x68], r13
    mov [r11 + 0x70], r14
    mov [r11 + 0x78], r15
    mov rax, [rsp + 8]
    mov [r11 + 0x80], rax
    pushfq
    pop rax
    mov [r11 + 0x88], rax
    mov word ptr [r11 + 0x90], cs
    mov word ptr [r11 + 0x92], ds
    mov word ptr [r11 + 0x94], es
    mov word ptr [r11 + 0x96], fs
    mov word ptr [r11 + 0x98], gs
    mov word ptr [r11 + 0x9A], ss
    mov rax, dr7
    mov [r11 + 0xC8], rax
    xor eax, eax
    mov dr7, rax
    mov rax, dr0
    mov [r11 + 0xA0], rax
    mov rax, dr1
    mov [r11 + 0xA8], rax
    mov rax, dr2
    mov [r11 + 0xB0], rax
    mov rax, dr3
    mov [r11 + 0xB8], rax
    mov rax, dr6
    mov [r11 + 0xC0], rax
    fxsave64 [r11 + 0x100]
    mov qword ptr [rip + opennt_kernel_native_active], 0
    mov rsp, [rip + opennt_kernel_native_host_rsp]
    fxrstor64 [rsp]
    mov rax, [rsp + 0x200]
    mov dr0, rax
    mov rax, [rsp + 0x208]
    mov dr1, rax
    mov rax, [rsp + 0x210]
    mov dr2, rax
    mov rax, [rsp + 0x218]
    mov dr3, rax
    mov rax, [rsp + 0x220]
    mov dr6, rax
    mov rax, [rsp + 0x228]
    mov dr7, rax
    add rsp, 576
    popfq
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

.global opennt_kernel_thread_return
opennt_kernel_thread_return:
    # Conserva o retorno de um callback nativo aninhado; a sentinela nunca
    # é retomada.
    mov r10, rax
    push 0
    mov eax, 0xFFFFFFFF
    jmp opennt_kernel_native_trap
.popsection

.pushsection .data.kernel_native, "aw", @progbits
.balign 8
.global opennt_kernel_native_active
opennt_kernel_native_active: .quad 0
.global opennt_kernel_native_host_rsp
opennt_kernel_native_host_rsp: .quad 0
# Uma chamada nativa síncrona está usando o processador; o despacho de
# volta ao kernel e os callbacks de interrupção suspendem essa posse.
.global opennt_kernel_sync_active
opennt_kernel_sync_active: .quad 0
.popsection
"#,
    stubs = const MAX_WIN32,
);

extern "C" {
    static opennt_win32_stubs: u8;
    static opennt_kernel_thread_return: u8;
    fn opennt_kernel_context_run(context: *mut u64);
}

/// Executa o contexto nativo (alinhado a 16) até a próxima saída e devolve o
/// id dela (32 bits baixos de RAX).
pub fn run_kernel_context(context: u64) -> u32 {
    assert!(context != 0 && context & 15 == 0, "kernel context must be 16-byte aligned");
    unsafe {
        opennt_kernel_context_run(context as *mut u64);
        core::ptr::read_volatile(context as *const u32)
    }
}

/// Estado FX corrente na área FXSAVE do quadro.
pub fn init_kernel_context_fx(context: u64) {
    assert!(context != 0 && context & 15 == 0, "kernel context must be 16-byte aligned");
    unsafe { core::arch::asm!("fxsave64 [{}]", in(reg) context + 0x100) };
}

/// Continuação usada quando a função de um contexto nativo retorna.
pub fn kernel_thread_return() -> u64 {
    core::ptr::addr_of!(opennt_kernel_thread_return) as u64
}

/// Endereço (identidade) da tabela de stubs e quantidade.
pub fn thunk_table() -> (u64, u32) {
    (core::ptr::addr_of!(opennt_win32_stubs) as u64, MAX_WIN32)
}
