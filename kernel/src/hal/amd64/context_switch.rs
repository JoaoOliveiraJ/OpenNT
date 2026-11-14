//! KiSwapContext: a troca de pilha de kernel entre uma thread que bloqueia
//! dentro de um serviço e o despachante que a retoma.
//!
//! A thread que bloqueia salva o quadro de troca na própria pilha de kernel
//! e grava o RSP dele em KTHREAD.KernelStack; o quadro leva os registradores
//! preservados das duas convenções, a do kernel e a MS x64 (pode haver um
//! driver nativo mais acima na pilha): rbx, rbp, rdi, rsi, r12-r15, RFLAGS,
//! xmm6-xmm15, o MXCSR e a palavra de controle x87. Layout, a partir do RSP
//! salvo:
//!
//! ```text
//!   +0x00  xmm6..xmm15 (10 x 16 bytes)
//!   +0xA0  MXCSR             +0xA4  palavra de controle x87
//!   +0xB0  RFLAGS            +0xB8  r15, r14, r13, r12, rsi, rdi, rbx, rbp
//!   +0xF8  endereço de retorno (quem chamou o bloqueio)
//! ```
//!
//! O outro lado é o despachante: a pilha da thread que chamou o despacho,
//! descrita pelo quadro de `dispatcher_rsp` do bloco por CPU, o mesmo que a
//! entrada no anel 3 (`user_exec_context`) monta e que o fim do intervalo
//! (`user_terminate_current`) consome. Bloquear salva o quadro de troca e
//! sai pelo fim do intervalo, com o tipo de saída [`EXIT_BLOCKED`]; retomar
//! monta um quadro de despachante novo e entra no quadro de troca salvo, de
//! onde o serviço segue até terminar o intervalo como qualquer syscall (ou
//! até bloquear de novo). A troca não mexe em CR3, IRQL nem thread corrente:
//! quem decide (`ke::context_switch`) ajusta isso antes e depois.

use core::arch::global_asm;
use core::mem::offset_of;

use super::usermode::{gs_offset, UserExecutionBlock};

/// Tipo de saída de um intervalo que terminou porque a thread bloqueou no
/// kernel (os outros: 0 término, 1 syscall, 2 timer, 3 exceção).
pub const EXIT_BLOCKED: u32 = 4;

global_asm!(
    r#"
.pushsection .text.context_switch, "ax", @progbits

# opennt_block_thread(save_rsp=rdi): a thread corrente deixa a CPU dentro de
# um serviço. Volta (como uma chamada comum) quando o despachante a retoma.
.global opennt_block_thread
opennt_block_thread:
    push rbp
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    pushfq
    sub rsp, 0xB0
    movups [rsp + 0x00], xmm6
    movups [rsp + 0x10], xmm7
    movups [rsp + 0x20], xmm8
    movups [rsp + 0x30], xmm9
    movups [rsp + 0x40], xmm10
    movups [rsp + 0x50], xmm11
    movups [rsp + 0x60], xmm12
    movups [rsp + 0x70], xmm13
    movups [rsp + 0x80], xmm14
    movups [rsp + 0x90], xmm15
    stmxcsr [rsp + 0xA0]
    fnstcw [rsp + 0xA4]
    cli
    mov [rdi], rsp
    mov dword ptr gs:[{exit_kind}], {blocked}
    xor edi, edi
    jmp user_terminate_current

# opennt_resume_thread(saved_rsp=rdi) -> rax: o despachante salva o seu
# quadro (o de user_exec_context) e entra no quadro de troca salvo; volta
# quando o intervalo da thread termina, com o RAX do fim do intervalo.
.global opennt_resume_thread
opennt_resume_thread:
    cli
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 0x208
    fxsave64 [rsp]
    mov gs:[{dispatcher_rsp}], rsp
    mov rsp, rdi
    fldcw [rsp + 0xA4]
    ldmxcsr [rsp + 0xA0]
    movups xmm6, [rsp + 0x00]
    movups xmm7, [rsp + 0x10]
    movups xmm8, [rsp + 0x20]
    movups xmm9, [rsp + 0x30]
    movups xmm10, [rsp + 0x40]
    movups xmm11, [rsp + 0x50]
    movups xmm12, [rsp + 0x60]
    movups xmm13, [rsp + 0x70]
    movups xmm14, [rsp + 0x80]
    movups xmm15, [rsp + 0x90]
    add rsp, 0xB0
    popfq
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret
.popsection
"#,
    exit_kind = const gs_offset(offset_of!(UserExecutionBlock, exit_kind)),
    dispatcher_rsp = const gs_offset(offset_of!(UserExecutionBlock, dispatcher_rsp)),
    blocked = const EXIT_BLOCKED,
);

extern "C" {
    fn opennt_block_thread(save_rsp: *mut u64);
    fn opennt_resume_thread(saved_rsp: u64) -> u64;
}

/// Salva o quadro de troca da thread corrente e grava o RSP em `save_rsp`
/// (KTHREAD.KernelStack); a CPU volta ao despachante pelo fim do intervalo.
/// Retorna quando o despachante retomar o quadro.
///
/// # Safety
///
/// Só dentro de um intervalo despachado (`dispatcher_rsp` válido), na pilha
/// de kernel da própria thread, que precisa continuar viva até a retomada;
/// `save_rsp` aponta uma célula de 8 bytes gravável.
pub unsafe fn block(save_rsp: *mut u64) {
    opennt_block_thread(save_rsp)
}

/// Entra no quadro de troca de RSP `saved_rsp` e devolve o RAX do fim do
/// intervalo da thread.
///
/// # Safety
///
/// `saved_rsp` é o RSP gravado por [`block`] numa pilha ainda viva, e o
/// quadro ainda não foi retomado.
pub unsafe fn resume(saved_rsp: u64) -> u64 {
    opennt_resume_thread(saved_rsp)
}
