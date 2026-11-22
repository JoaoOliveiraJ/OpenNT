//! Anel 3 (modo usuário).
//!
//! A HAL só oferece as primitivas de CPU: GDT/TSS/MSRs, entrada em anel 3,
//! a entrada de syscall (o KiSystemCall64 deste kernel, alvo do LSTAR) e o
//! "longjmp" de volta ao chamador no término do processo ou ao fim de um
//! intervalo de execução — inclusive quando a thread bloqueia dentro de um
//! serviço e é retomada depois na própria pilha (`context_switch`).
//! Despacho, loader e números NT ficam no kernel.
//!
//! A saída de syscall é por IRETQ: sob WHPX o SYSRETQ não entrega RIP=RCX,
//! e o IRETQ é o caminho que o próprio NT usa em KiSystemServiceExit.
//!
//! Estado por CPU, como no NT: a pilha do usuário na entrada de syscall é a
//! KPCR.UserRsp (gs:[10h]) e o topo da pilha de kernel é a KPRCB.RspBase
//! (gs:[1A8h]), os campos do KiSystemCall64. Como no KiSwapContext, cada
//! despacho para o anel 3 grava em KPRCB.RspBase e TSS.RSP0 a InitialStack
//! da thread despachada (a KTHREAD corrente, gs:[188h]): syscalls, IRQs e
//! exceções do anel 3 caem na pilha de kernel da própria thread. Uma thread
//! sem pilha própria (a que roda na pilha de boot, como o anel 3 cru dos
//! autotestes) usa a pilha reserva da CPU. A TSS também leva a IST1, a pilha
//! da falta dupla (vetor 8): um estouro de pilha de kernel falta na guarda, a
//! entrega da falta não cabe na pilha estourada e a falta dupla roda numa
//! pilha boa, que imprime o diagnóstico. O resto do estado de uma
//! execução no anel 3 fica no `UserExecutionBlock` da CPU, na cauda da
//! reserva da KPCR. Os stubs endereçam tudo por `gs:` (ou pela VA da KPCR,
//! gs:[KPCR.Self], quando precisam de um ponteiro); o Rust usa [`block`] e
//! `pcr::current()`. No anel 0 o GS é sempre a KPCR da CPU: o GS do usuário
//! (a TEB) fica no KernelGSbase e o SWAPGS troca os dois na fronteira, logo
//! depois da entrada e logo antes do IRETQ.

use core::arch::{asm, global_asm};
use core::mem::{offset_of, size_of};

use crate::hal::amd64::{context_switch, native_call};
use crate::hal::cpu;
use crate::ntos::ex::system_services;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{Eprocess, Ethread, Kthread, KthreadView1};
use crate::ntos::ke::pcr::{self, layout};
use crate::ntos::mm::memory_map::MAX_CPUS;
use crate::rtl::SpinLock;
use core::sync::atomic::{AtomicBool, Ordering};

/// Estado de execução de usuário de uma CPU (`gs:[pcr::layout::USER_EXECUTION]`).
#[repr(C)]
pub struct UserExecutionBlock {
    /// RSP do despachante salvo na entrada no anel 3; o fim do intervalo
    /// (ou do processo) volta a ele.
    pub dispatcher_rsp: Field<u64>,
    /// CONTEXT do intervalo em curso (0 fora de um intervalo).
    pub context: Field<u64>,
    /// ProcessInstrumentationCallback dos retornos de syscall.
    pub instrumentation: Field<u64>,
    /// Tipo da saída: 0 término, 1 syscall, 2 timer, 3 exceção, 4 bloqueio no
    /// kernel, 5 a thread saiu de vez.
    pub exit_kind: Field<u32>,
    /// Código de saída publicado pelo NtTerminateProcess.
    pub exit_code: Field<u32>,
    /// NtContinue: flag e os RCX/R11 do CONTEXT, independentes de RIP e RFLAGS.
    pub continue_flag: Field<u32>,
    _pad0: Reserved<4>,
    pub continue_rcx: Field<u64>,
    pub continue_r11: Field<u64>,
    /// Falta de usuário: código de erro do hardware, vetor, RCX, RIP, RSP e CR2.
    pub error_code: Field<u64>,
    pub fault_vector: Field<u32>,
    _pad1: Reserved<4>,
    pub fault_rcx: Field<u64>,
    pub fault_rip: Field<u64>,
    pub fault_rsp: Field<u64>,
    pub fault_cr2: Field<u64>,
    /// Captura de chamada: estado (1 pedido, 2 capturado, 3 consumido), o
    /// slot de depuração usado (máscara), o endereço, os argumentos e a pilha.
    pub capture_state: Field<u32>,
    pub capture_mask: Field<u32>,
    pub capture_address: Field<u64>,
    pub capture_arguments: [Field<u64>; 4],
    pub capture_stack: Field<u64>,
    /// DR6 do usuário (só os comparadores habilitados) e o DR6 lido na saída.
    pub debug_causes: Field<u32>,
    _pad2: Reserved<4>,
    pub debug_status: Field<u64>,
    /// Bancos DR0-DR3, DR6 e DR7: o do kernel, o lógico do usuário e o
    /// carregado na CPU durante o anel 3.
    pub debug_kernel: [Field<u64>; 6],
    pub debug_user: [Field<u64>; 6],
    pub debug_hardware: [Field<u64>; 6],
    /// O banco do usuário está na CPU (byte baixo).
    pub debug_active: Field<u64>,
    /// A área de XSAVE da thread do intervalo (KTHREAD.StateSaveArea; 0 no
    /// anel 3 cru): o fim do intervalo salva nela o estado estendido e a
    /// entrada o recarrega dela (`hal::amd64::extended_state`).
    pub xstate_area: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for UserExecutionBlock {}

const _: () = assert!(size_of::<UserExecutionBlock>() == 0x150);

/// Deslocamento de um campo do bloco a partir da KPCR (o operando `gs:` dos stubs).
pub const fn gs_offset(field: usize) -> u64 {
    layout::USER_EXECUTION + field as u64
}

/// O bloco da CPU corrente.
pub fn block() -> &'static UserExecutionBlock {
    // SAFETY: a reserva da KPCR de cada CPU inclui o bloco e fica mapeada
    // por toda a vida do sistema.
    unsafe { UserExecutionBlock::at(pcr::current_address() + layout::USER_EXECUTION) }
}

/// Zera o estado de falta antes de uma execução no anel 3.
pub fn reset_fault_state() {
    let block = block();
    block.fault_vector.set(0);
    for field in [&block.fault_rcx, &block.fault_rip, &block.fault_rsp, &block.fault_cr2] {
        field.set(0);
    }
}

const CONTEXT_SIZE: usize = 0x4D0;

const MSR_EFER: u32 = 0xC000_0080;
const MSR_STAR: u32 = 0xC000_0081;
const MSR_LSTAR: u32 = 0xC000_0082;
const MSR_SFMASK: u32 = 0xC000_0084;
const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// Seletores: 0x10/0x18 do stage2, 0x20 o código de 32 bits do usuário
/// (KGDT64_R3_CMCODE, o modo de compatibilidade do WoW64), 0x28 dados e 0x30
/// código de usuário, 0x38 a TSS de 16 bytes e 0x50 o descritor da TEB de 32
/// bits (KGDT64_R3_CMTEB, o FS do código x86).
const SEL_KERNEL_CODE: u64 = 0x10;
const SEL_USER_COMPAT_CODE: u64 = 0x20;
const SEL_USER_DATA: u64 = 0x28;
const SEL_USER_CODE: u64 = 0x30;
const SEL_TSS: u64 = 0x38;
const SEL_USER_COMPAT_TEB: u64 = 0x50;
const SEL_SYSRET_BASE: u64 = SEL_USER_DATA - 8;
/// O seletor de código de 32 bits como o CONTEXT e o quadro do IRETQ o levam
/// (KGDT64_R3_CMCODE | RPL 3).
pub const USER_COMPAT_CS: u16 = (SEL_USER_COMPAT_CODE | 3) as u16;
/// KGDT64_R3_DATA | RPL 3 e KGDT64_R3_CMTEB | RPL 3.
pub const USER_DS: u16 = (SEL_USER_DATA | 3) as u16;
pub const USER_COMPAT_FS: u16 = (SEL_USER_COMPAT_TEB | 3) as u16;
/// Os descritores de usuário da GDT, os do NT x64 (o winload os monta e o
/// KiSystemStartup do 19041 grava o limite 0x3C00 do CMTEB): o código de 32
/// bits DPL 3 de 4 GB (D=1, G=1), os dados planos DPL 3 de 4 GB (B=1: a pilha
/// de 32 bits do modo de compatibilidade), o código de 64 bits DPL 3 (L=1) e
/// o CMTEB, dados DPL 3 de 0x3C00 bytes com B=1, cuja base é a TEB de 32 bits
/// da thread corrente (o SwapContext a regrava a cada troca).
const GDT_USER_COMPAT_CODE: u64 = 0x00CF_FB00_0000_FFFF;
const GDT_USER_DATA: u64 = 0x00CF_F300_0000_FFFF;
const GDT_USER_CODE: u64 = 0x0020_FB00_0000_0000;
const GDT_USER_COMPAT_TEB: u64 = 0x0040_F300_0000_3C00;
/// As entradas da GDT de cada CPU: da nula ao CMTEB.
const GDT_ENTRIES: u16 = (SEL_USER_COMPAT_TEB / 8 + 1) as u16;
/// IA32_FS_BASE.
const MSR_FS_BASE: u32 = 0xC000_0100;
/// RFLAGS limpos na entrada de syscall: TF|IF|DF|IOPL|NT|AC.
const SFMASK_VALUE: u64 = 0x47700;
/// Sem IOPB: toda porta de E/S falta para o anel 3.
const TSS_LIMIT: u64 = 104;
/// Retorno de NtTerminateProcess ("TRMI").
const TERMINATE_MAGIC: u64 = 0x5452_4D49;
const STATUS_INVALID_SYSTEM_SERVICE: u32 = 0xC000_001C;

global_asm!(
    r#"
.pushsection .text.usermode, "ax", @progbits

# Os bancos de depuração moram no bloco da CPU: R8 = VA da KPCR
# (gs:[KPCR.Self]) e os campos em [r8 + deslocamento].
.global user_debug_enter
user_debug_enter:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    mov r8, gs:[{pcr_self}]
    lea rdi, [r8 + {debug_kernel}]
    call user_debug_save
    mov rsi, [r8 + {context}]
    test rsi, rsi
    jz opennt_ude_logical_ready
    mov rax, [rsi + 0x48 ]
    mov [r8 + {debug_user} ], rax
    mov rax, [rsi + 0x48 + 8]
    mov [r8 + {debug_user} + 8], rax
    mov rax, [rsi + 0x48 + 16]
    mov [r8 + {debug_user} + 16], rax
    mov rax, [rsi + 0x48 + 24]
    mov [r8 + {debug_user} + 24], rax
    mov rax, [rsi + 0x48 + 32]
    mov [r8 + {debug_user} + 32], rax
    mov rax, [rsi + 0x48 + 40]
    mov [r8 + {debug_user} + 40], rax
opennt_ude_logical_ready:
    mov rax, [r8 + {debug_user} ]
    mov [r8 + {debug_hardware} ], rax
    mov rax, [r8 + {debug_user} + 8]
    mov [r8 + {debug_hardware} + 8], rax
    mov rax, [r8 + {debug_user} + 16]
    mov [r8 + {debug_hardware} + 16], rax
    mov rax, [r8 + {debug_user} + 24]
    mov [r8 + {debug_hardware} + 24], rax
    mov rax, [r8 + {debug_user} + 32]
    mov [r8 + {debug_hardware} + 32], rax
    mov rax, [r8 + {debug_user} + 40]
    mov [r8 + {debug_hardware} + 40], rax
    mov dword ptr [r8 + {capture_mask}], 0
    cmp dword ptr [r8 + {capture_state}], 1
    jne opennt_ude_load
    # Um par com habilitação local OU global está ocupado.
    mov rdx, [r8 + {debug_user} + 40]
    xor ecx, ecx
opennt_ude_find_slot:
    test dl, 3
    jz opennt_ude_overlay
    shr rdx, 2
    inc ecx
    cmp ecx, 4
    jb opennt_ude_find_slot
    ud2
opennt_ude_overlay:
    mov eax, 1
    shl eax, cl
    mov [r8 + {capture_mask}], eax
    mov rdi, rcx
    mov rax, [r8 + {capture_address}]
    lea rsi, [r8 + {debug_hardware}]
    mov [rsi + rdi*8], rax
    mov rax, [r8 + {debug_hardware} + 40]
    lea ecx, [rdi*4 + 16]
    mov edx, 15
    shl rdx, cl
    not rdx
    and rax, rdx
    lea ecx, [rdi*2]
    mov edx, 1
    shl rdx, cl
    or rax, rdx
    mov [r8 + {debug_hardware} + 40], rax
    mov edx, [r8 + {capture_mask}]
    not rdx
    and [r8 + {debug_hardware} + 32], rdx
opennt_ude_load:
    mov byte ptr [r8 + {debug_active}], 1
    lea rdi, [r8 + {debug_hardware}]
    call user_debug_load
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    ret

.global user_debug_leave
user_debug_leave:
    cmp byte ptr gs:[{debug_active}], 0
    je opennt_udl_done
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    mov r8, gs:[{pcr_self}]
    lea rdi, [r8 + {debug_hardware}]
    call user_debug_save
    mov rax, [r8 + {debug_hardware} + 32]
    mov [r8 + {debug_status}], rax
    # DR6 pode citar comparadores desligados: só os habilitados são do usuário.
    mov rdx, [r8 + {debug_user} + 40]
    mov edi, 0xE000
    xor ecx, ecx
opennt_udl_enabled:
    test dl, 3
    jz opennt_udl_next_slot
    bts edi, ecx
opennt_udl_next_slot:
    shr rdx, 2
    inc ecx
    cmp ecx, 4
    jb opennt_udl_enabled
    and eax, edi
    mov [r8 + {debug_causes}], eax
    mov edx, [r8 + {capture_mask}]
    test edx, edx
    jz opennt_udl_captured
    bsf ecx, edx
    lea rsi, [r8 + {debug_user}]
    mov rax, [rsi + rcx*8]
    lea rsi, [r8 + {debug_hardware}]
    mov [rsi + rcx*8], rax
    lea ecx, [rcx*4 + 16]
    mov edi, 15
    shl rdi, cl
    bsf ecx, edx
    add ecx, ecx
    mov eax, 3
    shl rax, cl
    or rdi, rax
    mov rax, [r8 + {debug_user} + 40]
    and rax, rdi
    not rdi
    and [r8 + {debug_hardware} + 40], rdi
    or [r8 + {debug_hardware} + 40], rax
    mov rax, [r8 + {debug_user} + 32]
    and rax, rdx
    not rdx
    and [r8 + {debug_hardware} + 32], rdx
    or [r8 + {debug_hardware} + 32], rax
opennt_udl_captured:
    mov rsi, [r8 + {context}]
    mov rax, [r8 + {debug_hardware} ]
    mov [r8 + {debug_user} ], rax
    mov rax, [r8 + {debug_hardware} + 8]
    mov [r8 + {debug_user} + 8], rax
    mov rax, [r8 + {debug_hardware} + 16]
    mov [r8 + {debug_user} + 16], rax
    mov rax, [r8 + {debug_hardware} + 24]
    mov [r8 + {debug_user} + 24], rax
    mov rax, [r8 + {debug_hardware} + 32]
    mov [r8 + {debug_user} + 32], rax
    mov rax, [r8 + {debug_hardware} + 40]
    mov [r8 + {debug_user} + 40], rax
    test rsi, rsi
    jz opennt_udl_restore_kernel
    mov rax, [r8 + {debug_user} ]
    mov [rsi + 0x48 ], rax
    mov rax, [r8 + {debug_user} + 8]
    mov [rsi + 0x48 + 8], rax
    mov rax, [r8 + {debug_user} + 16]
    mov [rsi + 0x48 + 16], rax
    mov rax, [r8 + {debug_user} + 24]
    mov [rsi + 0x48 + 24], rax
    mov rax, [r8 + {debug_user} + 32]
    mov [rsi + 0x48 + 32], rax
    mov rax, [r8 + {debug_user} + 40]
    mov [rsi + 0x48 + 40], rax
opennt_udl_restore_kernel:
    mov byte ptr [r8 + {debug_active}], 0
    lea rdi, [r8 + {debug_kernel}]
    call user_debug_load
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
opennt_udl_done:
    ret

# Banco arquitetural: DR7 primeiro (desligado), depois DR0-3 e DR6.
user_debug_save:
    mov rax, dr7
    mov [rdi + 40], rax
    xor eax, eax
    mov dr7, rax
    mov rax, dr0
    mov [rdi], rax
    mov rax, dr1
    mov [rdi + 8], rax
    mov rax, dr2
    mov [rdi + 16], rax
    mov rax, dr3
    mov [rdi + 24], rax
    mov rax, dr6
    mov [rdi + 32], rax
    ret
user_debug_load:
    mov rax, [rdi]
    mov dr0, rax
    mov rax, [rdi + 8]
    mov dr1, rax
    mov rax, [rdi + 16]
    mov dr2, rax
    mov rax, [rdi + 24]
    mov dr3, rax
    mov rax, [rdi + 32]
    mov dr6, rax
    mov rax, [rdi + 40]
    mov dr7, rax
    ret

# Retoma um CONTEXT x64 completo do escalonador (rdi=CONTEXT, rsi=pilha).
# O GS do usuário já está no KernelGSbase: o SWAPGS antes do IRETQ o troca
# pela KPCR.
.global user_exec_context
user_exec_context:
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
    mov rsp, rsi
    # O estado estendido da thread antes do x87/SSE do CONTEXT.
    mov rcx, gs:[{xstate_area}]
    call opennt_xstate_restore
    fxrstor64 [rdi + 0x100]
    push {user_ds}
    push qword ptr [rdi + 0x98]
    mov eax, [rdi + 0x44]
    push rax
    # CONTEXT.SegCs: o código de 32 bits (KGDT64_R3_CMCODE) volta ao modo de
    # compatibilidade; qualquer outro valor, ao código de 64 bits.
    movzx eax, word ptr [rdi + 0x38]
    cmp eax, {compat_cs}
    je opennt_uec_cs_ready
    mov eax, {user_cs}
opennt_uec_cs_ready:
    push rax
    push qword ptr [rdi + 0xF8]
    call user_debug_enter
    mov rax, [rdi + 0x78]
    mov rcx, [rdi + 0x80]
    mov rdx, [rdi + 0x88]
    mov rbx, [rdi + 0x90]
    mov rbp, [rdi + 0xA0]
    mov rsi, [rdi + 0xA8]
    mov r8,  [rdi + 0xB8]
    mov r9,  [rdi + 0xC0]
    mov r10, [rdi + 0xC8]
    mov r11, [rdi + 0xD0]
    mov r12, [rdi + 0xD8]
    mov r13, [rdi + 0xE0]
    mov r14, [rdi + 0xE8]
    mov r15, [rdi + 0xF0]
    mov rdi, [rdi + 0xB0]
    swapgs
    iretq

# Entrada de syscall (LSTAR): rcx = RIP e r11 = RFLAGS do usuário; a CPU
# não troca pilha nem GS; IF=0 aqui. Como no KiSystemCall64: SWAPGS, a pilha
# do usuário em KPCR.UserRsp e a de kernel de KPRCB.RspBase.
.global user_syscall_entry
user_syscall_entry:
    swapgs
    mov gs:[{user_rsp}], rsp
    mov rsp, gs:[{rsp_base}]
    push r15
    push r14
    push r13
    push r12
    push rbp
    push rbx
    push r11
    push r10
    push r9
    push r8
    push rdi
    push rsi
    push rdx
    push rcx
    push rax
    call user_debug_leave
    # RBX (salvo no quadro e preservado pelas chamadas) guarda a VA da KPCR
    # desta CPU até o IRETQ.
    mov rbx, gs:[{pcr_self}]
    # A syscall de anel 3 registra a origem na KTHREAD corrente.
    mov rax, gs:[{current_thread}]
    mov byte ptr [rax + {previous_mode}], 1
    mov dword ptr [rbx + {continue_flag}], 0
    mov rdi, rsp
    sub rsp, 0x208
    fxsave64 [rsp]
    mov rax, [rbx + {dispatcher_rsp}]
    fxrstor64 [rax]
    call opennt_user_syscall
    # O serviço pode ter bloqueado numa CPU e sido retomado em outra: o RBX
    # que a troca recolocou é a KPCR de onde ele bloqueou. Depois da chamada
    # vale a desta CPU (no anel 0 o GS é sempre a KPCR corrente).
    mov rbx, gs:[{pcr_self}]
    fxrstor64 [rsp]
    add rsp, 0x208
    cmp dword ptr [rbx + {continue_flag}], 0
    jne user_syscall_exit
    mov [rsp], rax

user_syscall_exit:
    # A instrumentação x64 roda nos retornos de syscall, exceto NtContinue.
    cmp dword ptr [rbx + {continue_flag}], 0
    jne opennt_usx_instrumentation_ready
    mov rax, [rbx + {instrumentation}]
    test rax, rax
    jz opennt_usx_instrumentation_ready
    mov rcx, [rsp + 0x08]
    mov [rsp + 0x38], rcx
    mov [rsp + 0x08], rax
opennt_usx_instrumentation_ready:
    call user_debug_enter
    # O quadro do IRETQ vai logo abaixo do quadro dos registradores, que
    # passa a ficar em [rsp + 40]; os registradores saem dele por último.
    mov rax, [rsp + 0x08]
    mov rdx, [rsp + 0x40]
    push {user_ds}
    push qword ptr [rbx + {user_rsp}]
    push rdx
    push {user_cs}
    push rax
    mov rcx, [rsp + 40 + 0x08]
    mov r11, [rsp + 40 + 0x40]
    cmp dword ptr [rbx + {continue_flag}], 0
    je opennt_usx_registers_ready
    mov rcx, [rbx + {continue_rcx}]
    mov r11, [rbx + {continue_r11}]
    mov dword ptr [rbx + {continue_flag}], 0
opennt_usx_registers_ready:
    mov rax, [rsp + 40 + 0x00]
    mov rdx, [rsp + 40 + 0x10]
    mov rsi, [rsp + 40 + 0x18]
    mov rdi, [rsp + 40 + 0x20]
    mov r8,  [rsp + 40 + 0x28]
    mov r9,  [rsp + 40 + 0x30]
    mov r10, [rsp + 40 + 0x38]
    mov rbx, [rsp + 40 + 0x48]
    mov rbp, [rsp + 40 + 0x50]
    mov r12, [rsp + 40 + 0x58]
    mov r13, [rsp + 40 + 0x60]
    mov r14, [rsp + 40 + 0x68]
    mov r15, [rsp + 40 + 0x70]
    swapgs
    iretq

# user_exec_ring3(rip=rdi, rsp=rsi, pilha=rdx, arg1=rcx, rflags=r8, arg2=r9).
.global user_exec_ring3
user_exec_ring3:
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
    mov qword ptr gs:[{debug_user} ], 0
    mov qword ptr gs:[{debug_user} + 8], 0
    mov qword ptr gs:[{debug_user} + 16], 0
    mov qword ptr gs:[{debug_user} + 24], 0
    mov qword ptr gs:[{debug_user} + 32], 0
    mov qword ptr gs:[{debug_user} + 40], 0
    mov rsp, rdx
    mov rdx, r9
    test r8, r8
    jnz opennt_uer_have_rflags
    mov r8d, 0x202
opennt_uer_have_rflags:
    push {user_ds}
    push rsi
    push r8
    push {user_cs}
    push rdi
    call user_debug_enter
    swapgs
    iretq

# user_terminate_current(exitCode=rdi): abandona a pilha de syscall, volta
# à pilha do chamador e retorna exitCode como uma chamada comum. O sti é
# obrigatório: a entrada de syscall limpou IF e este caminho não passa
# pelo iretq. Chega depois do SWAPGS da entrada: o GS é a KPCR.
.global user_terminate_current
user_terminate_current:
    call user_debug_leave
    # O estado estendido da thread do intervalo sai da CPU (o salvamento
    # ansioso do SwapContext).
    mov rcx, gs:[{xstate_area}]
    call opennt_xstate_save
    mov rsp, gs:[{dispatcher_rsp}]
    fxrstor64 [rsp]
    add rsp, 0x208
    sti
    mov rax, rdi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.popsection
"#,
    pcr_self = const layout::SELF,
    user_rsp = const layout::USER_RSP,
    rsp_base = const layout::PRCB_RSP_BASE,
    current_thread = const layout::PRCB_CURRENT_THREAD,
    previous_mode = const offset_of!(KthreadView1, previous_mode),
    dispatcher_rsp = const gs_offset(offset_of!(UserExecutionBlock, dispatcher_rsp)),
    context = const gs_offset(offset_of!(UserExecutionBlock, context)),
    instrumentation = const gs_offset(offset_of!(UserExecutionBlock, instrumentation)),
    continue_flag = const gs_offset(offset_of!(UserExecutionBlock, continue_flag)),
    continue_rcx = const gs_offset(offset_of!(UserExecutionBlock, continue_rcx)),
    continue_r11 = const gs_offset(offset_of!(UserExecutionBlock, continue_r11)),
    capture_state = const gs_offset(offset_of!(UserExecutionBlock, capture_state)),
    capture_mask = const gs_offset(offset_of!(UserExecutionBlock, capture_mask)),
    capture_address = const gs_offset(offset_of!(UserExecutionBlock, capture_address)),
    debug_causes = const gs_offset(offset_of!(UserExecutionBlock, debug_causes)),
    debug_status = const gs_offset(offset_of!(UserExecutionBlock, debug_status)),
    debug_kernel = const gs_offset(offset_of!(UserExecutionBlock, debug_kernel)),
    debug_user = const gs_offset(offset_of!(UserExecutionBlock, debug_user)),
    debug_hardware = const gs_offset(offset_of!(UserExecutionBlock, debug_hardware)),
    debug_active = const gs_offset(offset_of!(UserExecutionBlock, debug_active)),
    xstate_area = const gs_offset(offset_of!(UserExecutionBlock, xstate_area)),
    user_ds = const SEL_USER_DATA | 3,
    user_cs = const SEL_USER_CODE | 3,
    compat_cs = const SEL_USER_COMPAT_CODE | 3,
);

extern "C" {
    fn user_syscall_entry();
    fn user_exec_ring3(rip: u64, rsp: u64, kernel_stack: u64, argument1: u64, rflags: u64, argument2: u64) -> u64;
    fn user_exec_context(context: u64, kernel_stack: u64) -> u64;
    fn user_terminate_current(exit_code: u64) -> !;
}

/// `nt_service_lookup` (MS x64): a mesma tabela consumida pela invocação.
fn service_lookup(number: u64, shadow: u64, stack_count: &mut u64) -> u64 {
    let routine: extern "win64" fn(u64, u64, *mut u64) -> u64 = unsafe { core::mem::transmute(crate::hal::amd64::service_table::entries()[0] as usize) };
    routine(number, shadow, stack_count)
}

/// O estado de execução de usuário de uma CPU.
struct Execution {
    /// Topo da pilha reserva da CPU (thread sem pilha de kernel própria).
    fallback_stack: u64,
    /// A CPU tem a GDT, a TSS e os MSRs de syscall dela
    /// ([`processor_user_mode_init`]).
    armed: bool,
    running: bool,
    /// CONTEXT salvo pela syscall em curso (`g_userFrameContext`).
    frame_context: u64,
    service_frame: u64,
}

/// O estado de cada CPU, pelo número do processador: uma syscall que
/// bloqueia numa CPU leva o dela (`SuspendedService`) e o recoloca na CPU
/// em que é retomada.
static EXECUTION: [SpinLock<Execution>; MAX_CPUS] = [const { SpinLock::new(Execution { fallback_stack: 0, armed: false, running: false, frame_context: 0, service_frame: 0 }) }; MAX_CPUS];
/// O anel 3 foi armado (o BSP, [`user_mode_init`]).
static READY: AtomicBool = AtomicBool::new(false);
/// Faixas do CONTEXT escritas pelo kernel durante a syscall, preservadas
/// sobre o salvamento do retorno.
type Keep = ([bool; CONTEXT_SIZE], [u8; CONTEXT_SIZE]);
/// As faixas preservadas de cada CPU.
static CONTEXT_KEEP: [SpinLock<Keep>; MAX_CPUS] = [const { SpinLock::new(([false; CONTEXT_SIZE], [0; CONTEXT_SIZE])) }; MAX_CPUS];

/// O número do processador corrente (KPRCB.Number pelo GS).
fn processor_number() -> usize {
    (pcr::current().prcb.number.get() as usize).min(MAX_CPUS - 1)
}

/// O estado de execução de usuário da CPU corrente.
fn state() -> &'static SpinLock<Execution> {
    &EXECUTION[processor_number()]
}

/// As faixas preservadas do CONTEXT da CPU corrente.
fn context_keep() -> &'static SpinLock<Keep> {
    &CONTEXT_KEEP[processor_number()]
}

fn read64(address: u64) -> u64 {
    unsafe { core::ptr::read_volatile(address as *const u64) }
}

fn write64(address: u64, value: u64) {
    unsafe { core::ptr::write_volatile(address as *mut u64, value) }
}

fn read32(address: u64) -> u32 {
    unsafe { core::ptr::read_volatile(address as *const u32) }
}

fn write32(address: u64, value: u32) {
    unsafe { core::ptr::write_volatile(address as *mut u32, value) }
}

/// Deslocamentos da TSS de 64 bits: RSP0 e IST1.
const TSS_RSP0: usize = 4;
const TSS_IST1: usize = 0x24;
/// Vetor da falta dupla e a entrada da IST que ele usa.
const DOUBLE_FAULT_VECTOR: u8 = 8;
const DOUBLE_FAULT_IST: u8 = 1;

/// O anel 3 no processador de boot: a GDT, a TSS e os MSRs dele
/// ([`processor_user_mode_init`]) e o portão do vetor 8 da IDT na IST1.
/// Devolve a GDT.
pub fn user_mode_init(stack_top: u64, double_fault_stack: u64) -> Result<u64, crate::rtl::KernelError> {
    if READY.load(Ordering::Acquire) {
        return Err(crate::rtl::KernelError::new("userModeInit: ja inicializado"));
    }
    let gdt = processor_user_mode_init(stack_top, double_fault_stack)?;
    // Só com a TSS carregada o portão pode apontar a IST. A IDT dos APs é
    // uma cópia desta, feita depois (`nano::interrupts::processor_idt`).
    crate::nano::interrupts::set_interrupt_stack(DOUBLE_FAULT_VECTOR, DOUBLE_FAULT_IST);
    READY.store(true, Ordering::Release);
    Ok(gdt)
}

/// O anel 3 numa CPU, como o KiInitializeProcessor do 19041 monta a GDT e a
/// TSS de cada processador: a GDT da CPU (cópia da de boot, com os dados e o
/// código de usuário em 0x28/0x30 e a TSS de 16 bytes em 0x38) e a TSS (RSP0
/// = a pilha reserva da CPU, IST1 = a pilha da falta dupla) na reserva da
/// KPCR dela, publicadas em KPCR.GdtBase/TssBase; LGDT/LTR, EFER.SCE e
/// STAR/LSTAR/SFMASK, e KPRCB.RspBase. A KPCR continua no GS do kernel; o
/// KernelGSbase do usuário vai a zero. Devolve a GDT.
pub fn processor_user_mode_init(stack_top: u64, double_fault_stack: u64) -> Result<u64, crate::rtl::KernelError> {
    if state().lock().armed {
        return Err(crate::rtl::KernelError::new("userModeInit: CPU ja armada"));
    }
    if stack_top == 0 || stack_top & 0xF != 0 || double_fault_stack == 0 || double_fault_stack & 0xF != 0 {
        return Err(crate::rtl::KernelError::new("userModeInit: pilha invalida"));
    }
    #[repr(C, packed)]
    struct Register {
        limit: u16,
        base: u64,
    }
    let mut current = Register { limit: 0, base: 0 };
    unsafe {
        asm!("sgdt [{}]", in(reg) &mut current, options(nostack));
    }
    let limit = current.limit as usize;
    if limit + 1 > 5 * 8 {
        return Err(crate::rtl::KernelError::new("userModeInit: GDT de boot inesperada"));
    }
    let base = pcr::current_address();
    let (gdt, tss) = ((base + layout::PROCESSOR_GDT) as *mut u64, (base + layout::PROCESSOR_TSS) as *mut u8);
    // SAFETY: a GDT e a TSS ficam na reserva da KPCR desta CPU, mapeada por
    // toda a vida do sistema e de uso só dela.
    unsafe {
        core::ptr::copy_nonoverlapping(current.base as *const u8, gdt as *mut u8, limit + 1);
        // O 0x20 do stage2 (os dados de 32 bits do bootstrap) só serve antes
        // do modo longo: aqui ele vira o código de 32 bits do usuário.
        *gdt.add((SEL_USER_COMPAT_CODE / 8) as usize) = GDT_USER_COMPAT_CODE;
        *gdt.add((SEL_USER_DATA / 8) as usize) = GDT_USER_DATA;
        *gdt.add((SEL_USER_CODE / 8) as usize) = GDT_USER_CODE;
        *gdt.add((SEL_TSS / 8) as usize + 2) = 0;
        *gdt.add((SEL_USER_COMPAT_TEB / 8) as usize) = GDT_USER_COMPAT_TEB;
        core::ptr::write_bytes(tss, 0, TSS_LIMIT as usize);
        core::ptr::write_unaligned(tss.add(TSS_RSP0) as *mut u64, stack_top);
        core::ptr::write_unaligned(tss.add(TSS_IST1) as *mut u64, double_fault_stack);
        core::ptr::write_unaligned(tss.add(102) as *mut u16, TSS_LIMIT as u16);
        let base = tss as u64;
        *gdt.add((SEL_TSS / 8) as usize) = (TSS_LIMIT - 1) | ((base & 0xFF_FFFF) << 16) | (0x89 << 40) | (((base >> 24) & 0xFF) << 56);
        *gdt.add((SEL_TSS / 8) as usize + 1) = base >> 32;
        let register = Register { limit: GDT_ENTRIES * 8 - 1, base: gdt as u64 };
        asm!("lgdt [{}]", in(reg) &register, options(readonly, nostack));
        asm!("mov ax, {selector}", "ltr ax", selector = const SEL_TSS, out("ax") _, options(nostack));
        // Os seletores de dados do KiSystemStartup: DS e ES no KGDT64_R3_DATA
        // e o FS no CMTEB, os valores que o anel 3 recebe (o IRETQ zeraria um
        // seletor DPL 0, e o código de 32 bits precisa de DS e ES válidos).
        asm!("mov ds, {data:x}", "mov es, {data:x}", "mov fs, {teb:x}", data = in(reg) USER_DS as u64, teb = in(reg) USER_COMPAT_FS as u64, options(nostack, preserves_flags));
    }
    // A entrada de syscall desta CPU carrega a mesma pilha da TSS.RSP0.
    let kpcr = pcr::current();
    kpcr.gdt_base.set(gdt as u64);
    kpcr.tss_base.set(tss as u64);
    kpcr.prcb.rsp_base.set(stack_top);
    kpcr.user_rsp.set(0);
    let efer = cpu::read_msr(MSR_EFER);
    cpu::write_msr(MSR_EFER, efer | 1);
    cpu::write_msr(MSR_STAR, (SEL_KERNEL_CODE << 32) | (SEL_SYSRET_BASE << 48));
    cpu::write_msr(MSR_LSTAR, user_syscall_entry as unsafe extern "C" fn() as usize as u64);
    cpu::write_msr(MSR_SFMASK, SFMASK_VALUE);
    cpu::write_msr(MSR_KERNEL_GS_BASE, 0);
    let mut state = state().lock();
    state.fallback_stack = stack_top;
    state.armed = true;
    Ok(gdt as u64)
}

/// A CPU corrente tem a GDT, a TSS e os MSRs de syscall dela.
pub fn processor_armed() -> bool {
    state().lock().armed
}

/// A TSS desta CPU (KPCR.TssBase).
fn current_tss() -> *mut u8 {
    let tss = pcr::current().tss_base.get();
    assert!(tss != 0, "TSS da CPU ainda nao montada");
    tss as *mut u8
}

/// RSP0 e IST1 da TSS desta CPU.
pub fn tss_stacks() -> (u64, u64) {
    let tss = current_tss();
    // SAFETY: a TSS desta CPU, na reserva da KPCR dela.
    unsafe { (core::ptr::read_unaligned(tss.add(TSS_RSP0) as *const u64), core::ptr::read_unaligned(tss.add(TSS_IST1) as *const u64)) }
}

/// O topo da pilha de kernel do despacho: a InitialStack da KTHREAD
/// corrente quando ela tem pilha própria; senão (a thread roda na pilha de
/// boot) a pilha reserva da CPU.
fn dispatch_stack(fallback: u64) -> u64 {
    let thread = pcr::current().prcb.current_thread.get();
    // SAFETY: a KTHREAD corrente está viva enquanto é despachada.
    let initial = if thread != 0 { unsafe { Kthread::at(thread) }.initial_stack.get() } else { 0 };
    if crate::ntos::mm::memory_map::is_kernel_stack(initial) { initial } else { fallback }
}

/// A área de XSAVE da KTHREAD corrente (KTHREAD.StateSaveArea).
fn current_xstate_area() -> u64 {
    crate::ntos::ke::xstate::thread_area(pcr::current().prcb.current_thread.get())
}

/// O KiSwapContext do despacho: a pilha de kernel da thread vira a da
/// entrada de syscall (KPRCB.RspBase) e a das IRQs e exceções do anel 3
/// (TSS.RSP0). No fim do intervalo as duas voltam à pilha reserva da CPU:
/// nenhuma aponta para a pilha de uma thread que o ceifador pode devolver.
fn load_kernel_stack(top: u64) {
    pcr::current().prcb.rsp_base.set(top);
    let tss = current_tss();
    // SAFETY: a TSS desta CPU; ela só lê o RSP0 numa entrada vinda do anel
    // 3, e aqui está no anel 0.
    unsafe { core::ptr::write_unaligned(tss.add(TSS_RSP0) as *mut u64, top) };
}

const _: () = assert!(GDT_ENTRIES as u64 * 8 <= layout::PROCESSOR_TSS - layout::PROCESSOR_GDT);

/// A thread do intervalo (gs:[188h]) e o processo dela (KTHREAD.Process),
/// com o EPROCESS.WoW64Process.
fn dispatched_thread() -> Option<(&'static Ethread, bool)> {
    let thread = pcr::current().prcb.current_thread.get();
    if thread == 0 {
        return None;
    }
    // SAFETY: a KTHREAD corrente (no começo do ETHREAD) está viva enquanto é
    // despachada; o processo dono vive enquanto ela vive.
    let thread = unsafe { Ethread::at(thread) };
    let process = thread.tcb.process.get();
    let wow64 = process != 0 && unsafe { Eprocess::at(process) }.wo_w64_process.get() != 0;
    Some((thread, wow64))
}

/// O lado de entrada do SwapContext do 19041 para os segmentos do usuário
/// (0x406367): a base do descritor KGDT64_R3_CMTEB desta CPU recebe a TEB de
/// 32 bits (`teb` + 0x2000) numa thread de processo WoW64, ou o
/// ETHREAD.UserFsBase nas outras; o FS recarrega o seletor 0x53 e o
/// IA32_FS_BASE recebe o UserFsBase. O `mov fs, 0x53` do wow64cpu (o
/// RunSimulatedCode, sem RDWRFSGSBASE) acha no descritor a TEB de 32 bits da
/// thread que está na CPU. DS e ES voltam ao KGDT64_R3_DATA se mudaram.
fn load_user_segments(teb: u64) {
    let Some((thread, wow64)) = dispatched_thread() else { return };
    let fs_base = thread.user_fs_base.get();
    let base = if wow64 { (teb + crate::ntos::ps::wow64::TEB32_OFFSET) as u32 } else { fs_base as u32 };
    let gdt = pcr::current().gdt_base.get() + SEL_USER_COMPAT_TEB;
    // SAFETY: a GDT desta CPU, na reserva da KPCR dela; só esta CPU a usa e o
    // descritor 0x50 é de dados de usuário (nenhum seletor do kernel o usa).
    unsafe {
        let descriptor = gdt as *mut u64;
        let value = core::ptr::read_volatile(descriptor) & !0xFF00_00FF_FFFF_0000;
        let value = value | ((base as u64 & 0xFF_FFFF) << 16) | (((base as u64 >> 24) & 0xFF) << 56);
        core::ptr::write_volatile(descriptor, value);
        asm!("mov fs, {teb:x}", teb = in(reg) USER_COMPAT_FS as u64, options(nostack, preserves_flags));
    }
    cpu::write_msr(MSR_FS_BASE, fs_base);
    let selectors: u16;
    // SAFETY: só lê os seletores.
    unsafe { asm!("mov {all:x}, ds", "mov {other:x}, es", "and {all:x}, {other:x}", all = out(reg) selectors, other = out(reg) _, options(nomem, nostack, preserves_flags)) };
    if selectors != USER_DS {
        // SAFETY: DS e ES não entram no endereçamento do modo de 64 bits.
        unsafe { asm!("mov ds, {data:x}", "mov es, {data:x}", data = in(reg) USER_DS as u64, options(nostack, preserves_flags)) };
    }
}

/// O lado de saída (o SwapContext 0x405fdd): numa thread de processo WoW64,
/// o IA32_FS_BASE vivo (que o código de 32 bits carregou pelo seletor ou pelo
/// WRFSBASE) volta ao ETHREAD.UserFsBase.
fn save_user_segments() {
    let Some((thread, true)) = dispatched_thread() else { return };
    thread.user_fs_base.set(cpu::read_msr(MSR_FS_BASE));
}

/// O anel 3 foi armado.
pub fn ready() -> bool {
    READY.load(Ordering::Acquire)
}

/// Uma execução de usuário (intervalo, retomada no kernel ou o anel 3 cru
/// dos autotestes) está em curso nesta CPU.
pub fn executing() -> bool {
    state().lock().running
}

/// O anel 3 só entra numa CPU com a GDT, a TSS, o LSTAR e a pilha reserva
/// dela ([`processor_user_mode_init`]).
fn assert_armed() {
    assert!(processor_armed(), "anel 3 numa CPU sem GDT, TSS e MSRs de syscall");
}

/// Entra no processo e só volta no término (protocolo GS: GS.base = TEB e
/// KernelGSbase = KPCR em anel 3; o stub faz o SWAPGS antes do IRETQ, e a
/// entrada de syscall ou de interrupção o desfaz).
pub fn exec_user_mode(entry: u64, user_rsp: u64, teb: u64, argument1: u64, rflags: u64, argument2: u64) -> u64 {
    let fallback = {
        let mut state = state().lock();
        assert!(state.armed, "execUserMode: userModeInit nao rodou nesta CPU");
        assert!(!state.running, "execUserMode: ja ha processo em ring 3");
        state.running = true;
        state.fallback_stack
    };
    assert_armed();
    let stack = dispatch_stack(fallback);
    load_kernel_stack(stack);
    let previous_swap = cpu::read_msr(MSR_KERNEL_GS_BASE);
    reset_fault_state();
    block().xstate_area.set(0);
    cpu::write_msr(MSR_KERNEL_GS_BASE, teb);
    let exit_code = unsafe { user_exec_ring3(entry, user_rsp, stack, argument1, rflags, argument2) };
    load_kernel_stack(fallback);
    cpu::write_msr(MSR_KERNEL_GS_BASE, previous_swap);
    state().lock().running = false;
    exit_code
}

/// Um intervalo de escalonamento. A HAL só move o estado dos registradores; o
/// kernel escolhe a thread. O intervalo também termina quando a thread
/// bloqueia dentro de um serviço (tipo de saída `EXIT_BLOCKED`): o estado do
/// despachante volta ao de antes da entrada.
pub fn exec_user_context(context: u64, teb: u64) -> u32 {
    let fallback = {
        let mut state = state().lock();
        assert!(state.armed && !state.running, "execUserContext: invalid execution state");
        assert!(context & 15 == 0, "execUserContext: unaligned CONTEXT");
        state.running = true;
        state.frame_context = 0;
        state.fallback_stack
    };
    assert_armed();
    let stack = dispatch_stack(fallback);
    load_kernel_stack(stack);
    let block = block();
    if block.capture_state.get() == 1 {
        let dr7 = read64(context + 0x70);
        assert!((0..4).any(|slot| dr7 & (3 << (slot * 2)) == 0), "user call capture: all four debug slots are in use");
    }
    let swap_gs = cpu::read_msr(MSR_KERNEL_GS_BASE);
    let native = native_call::state();
    block.context.set(context);
    block.exit_kind.set(0);
    block.continue_flag.set(0);
    block.xstate_area.set(current_xstate_area());
    cpu::write_msr(MSR_KERNEL_GS_BASE, teb);
    load_user_segments(teb);
    let result = unsafe { user_exec_context(context, stack) };
    save_user_segments();
    load_kernel_stack(fallback);
    block.context.set(0);
    block.xstate_area.set(0);
    cpu::write_msr(MSR_KERNEL_GS_BASE, swap_gs);
    native_call::restore_state(native);
    let mut state = state().lock();
    state.frame_context = 0;
    state.running = false;
    result as u32
}

/// Uma syscall despachada está em curso nesta CPU: o intervalo de uma thread
/// com CONTEXT (o anel 3 cru dos autotestes não tem). Só nela uma espera
/// pode deixar a CPU.
pub fn in_service() -> bool {
    state().lock().running && block().context.get() != 0
}

/// O estado por CPU do serviço em curso que uma thread bloqueada leva
/// consigo, na própria pilha, e recoloca ao ser retomada: o CONTEXT do
/// intervalo, o quadro da syscall, as faixas preservadas do CONTEXT, a pilha
/// do usuário (KPCR.UserRsp), o NtContinue e as chamadas nativas em curso. O
/// callback de instrumentação é do processo e não viaja com a thread.
struct SuspendedService {
    context: u64,
    frame_context: u64,
    service_frame: u64,
    keep: ([bool; CONTEXT_SIZE], [u8; CONTEXT_SIZE]),
    user_rsp: u64,
    continue_flag: u32,
    continue_rcx: u64,
    continue_r11: u64,
    native: native_call::NativeState,
}

/// A thread corrente bloqueia dentro do serviço em curso (o lado de saída do
/// KiSwapContext): leva o estado do serviço, salva o quadro de troca, grava
/// o RSP em `kernel_stack` (KTHREAD.KernelStack) e devolve a CPU ao
/// despachante, cujo intervalo termina com `EXIT_BLOCKED`. Retorna quando o
/// despachante a retoma ([`resume_kernel_context`]), com o estado de volta,
/// na CPU que a retomou. Só o serviço de um intervalo despachado bloqueia no
/// sistema (`ke::context_switch::can_block`); o anel 3 cru dos autotestes
/// também pode, para a retomada em outra CPU.
pub fn block_in_service(kernel_stack: &Field<u64>) {
    assert!(state().lock().running, "bloqueio fora de uma execucao de usuario");
    let block = block();
    let (frame_context, service_frame) = {
        let mut state = state().lock();
        (core::mem::replace(&mut state.frame_context, 0), core::mem::replace(&mut state.service_frame, 0))
    };
    let saved = SuspendedService {
        context: block.context.get(),
        frame_context,
        service_frame,
        keep: *context_keep().lock(),
        user_rsp: pcr::current().user_rsp.get(),
        continue_flag: block.continue_flag.get(),
        continue_rcx: block.continue_rcx.get(),
        continue_r11: block.continue_r11.get(),
        native: native_call::state(),
    };
    // SAFETY: dentro de um intervalo despachado, na pilha de kernel da
    // própria thread (`ke::context_switch::can_block`), que o ceifador não
    // devolve enquanto ela está bloqueada; a célula é o KernelStack da
    // KTHREAD corrente.
    unsafe { context_switch::block(kernel_stack.address() as *mut u64) };
    let block = self::block();
    block.context.set(saved.context);
    block.continue_flag.set(saved.continue_flag);
    block.continue_rcx.set(saved.continue_rcx);
    block.continue_r11.set(saved.continue_r11);
    pcr::current().user_rsp.set(saved.user_rsp);
    *context_keep().lock() = saved.keep;
    native_call::restore_state(saved.native);
    let mut state = state().lock();
    state.frame_context = saved.frame_context;
    state.service_frame = saved.service_frame;
}

/// O lado de entrada do KiSwapContext: retoma a thread corrente, bloqueada
/// num serviço com o quadro de troca em `saved_rsp`, na pilha dela, com
/// KPRCB.RspBase e TSS.RSP0 na InitialStack dela e o GS do usuário (`teb`)
/// no KernelGSbase, como num intervalo. Volta quando o intervalo termina (o
/// serviço concluído ou outro bloqueio) e devolve o resultado dele, como
/// [`exec_user_context`].
pub fn resume_kernel_context(saved_rsp: u64, teb: u64) -> u32 {
    let fallback = {
        let mut state = state().lock();
        assert!(state.armed && !state.running, "resumeKernelContext: invalid execution state");
        state.running = true;
        state.fallback_stack
    };
    assert_armed();
    let stack = dispatch_stack(fallback);
    load_kernel_stack(stack);
    let block = block();
    let swap_gs = cpu::read_msr(MSR_KERNEL_GS_BASE);
    let native = native_call::state();
    block.exit_kind.set(0);
    block.xstate_area.set(current_xstate_area());
    cpu::write_msr(MSR_KERNEL_GS_BASE, teb);
    load_user_segments(teb);
    // SAFETY: `saved_rsp` é o KernelStack que `block_in_service` gravou na
    // pilha viva da thread corrente, ainda não retomado.
    let result = unsafe { context_switch::resume(saved_rsp) };
    save_user_segments();
    load_kernel_stack(fallback);
    block.context.set(0);
    block.xstate_area.set(0);
    cpu::write_msr(MSR_KERNEL_GS_BASE, swap_gs);
    native_call::restore_state(native);
    let mut state = state().lock();
    state.frame_context = 0;
    state.service_frame = 0;
    state.running = false;
    result as u32
}

/// Um intervalo da thread corrente que, em vez de entrar no anel 3 pelo
/// CONTEXT, roda `routine(argument)` na pilha de kernel dela (InitialStack,
/// também em KPRCB.RspBase e TSS.RSP0), como um serviço: o CONTEXT do
/// intervalo é `context`, as interrupções ficam desligadas como depois da
/// entrada de syscall e a rotina pode bloquear (`block_in_service`; a
/// retomada é a de qualquer serviço suspenso, [`resume_kernel_context`]). É
/// o lugar da entrega de uma APC de usuário cuja rotina de kernel nunca volta
/// ao anel 3 (o KiSchedulerApcTerminate do término de uma thread que estava
/// no anel 3). A rotina não retorna: termina o intervalo
/// ([`end_thread_interval`]). Devolve o resultado do intervalo, como
/// [`exec_user_context`]; o tipo de saída fica no bloco da CPU.
pub fn exec_kernel_routine(context: u64, teb: u64, routine: extern "C" fn(u64) -> !, argument: u64) -> u32 {
    let fallback = {
        let mut state = state().lock();
        assert!(state.armed && !state.running, "execKernelRoutine: invalid execution state");
        state.running = true;
        state.frame_context = 0;
        state.service_frame = 0;
        state.fallback_stack
    };
    assert_armed();
    let stack = dispatch_stack(fallback);
    assert!(stack != fallback, "execKernelRoutine: thread sem pilha de kernel propria");
    load_kernel_stack(stack);
    let block = block();
    let swap_gs = cpu::read_msr(MSR_KERNEL_GS_BASE);
    let native = native_call::state();
    block.context.set(context);
    block.exit_kind.set(0);
    block.continue_flag.set(0);
    cpu::write_msr(MSR_KERNEL_GS_BASE, teb);
    load_user_segments(teb);
    // SAFETY: a pilha de kernel da thread corrente está viva e sem quadro (a
    // thread não tem serviço suspenso); a rotina sai pelo fim do intervalo,
    // que volta ao quadro de despachante que a retomada grava.
    let result = unsafe {
        let frame = context_switch::build_service_frame(stack, routine, argument);
        context_switch::resume(frame)
    };
    save_user_segments();
    load_kernel_stack(fallback);
    block.context.set(0);
    cpu::write_msr(MSR_KERNEL_GS_BASE, swap_gs);
    native_call::restore_state(native);
    let mut state = state().lock();
    state.frame_context = 0;
    state.service_frame = 0;
    state.running = false;
    result as u32
}

/// O fim do intervalo da thread corrente, que saiu de vez (o PspExitThread
/// dela terminou dentro de um serviço ou de [`exec_kernel_routine`]): a pilha
/// de kernel é abandonada e o despachante do intervalo recebe o tipo de saída
/// [`context_switch::EXIT_THREAD_EXITED`] com `code`.
pub fn end_thread_interval(code: u32) -> ! {
    assert!(in_service(), "fim de thread fora de um intervalo de servico");
    state().lock().frame_context = 0;
    block().exit_kind.set(context_switch::EXIT_THREAD_EXITED);
    // SAFETY: dentro de um intervalo despachado (`dispatcher_rsp` válido);
    // nada desta pilha é usado depois.
    unsafe { user_terminate_current(code as u64) }
}

/// O lado do anel 3 do KiCallUserMode: um intervalo aninhado dentro do
/// serviço em curso da thread corrente (um KeUserModeCallback, que continua
/// esperando na pilha dele). O estado por CPU do serviço de fora — o quadro
/// do despachante (`dispatcher_rsp`, o mesmo que o fim do intervalo
/// consome), o CONTEXT do intervalo e o quadro da syscall, as faixas
/// preservadas do CONTEXT, a pilha do usuário (KPCR.UserRsp), o NtContinue,
/// o tipo de saída, as chamadas nativas em curso, KPRCB.RspBase/TSS.RSP0, o GS
/// do usuário e o IF — é guardado aqui e volta no fim. O intervalo aninhado
/// entra no CONTEXT `context` com a pilha de kernel da KTHREAD corrente (a
/// pilha do callback, que o Ke instalou em InitialStack antes), então as
/// syscalls e interrupções dele caem nela, abaixo dos quadros do serviço de
/// fora. Termina como qualquer intervalo (syscall, timer, exceção, término
/// ou o bloqueio de um serviço aninhado, [`context_switch::EXIT_BLOCKED`]) e
/// devolve o resultado e o tipo de saída dele.
///
/// Um serviço aninhado que bloqueia sai por este quadro, não pelo do
/// despachante: o `dispatcher_rsp` é o que este intervalo gravou. Quem chama
/// (`threads::run_callback`) bloqueia então o serviço de fora e, retomado,
/// volta ao aninhado por [`resume_user_callback`].
pub fn exec_user_callback(context: u64, teb: u64) -> (u32, u32) {
    assert!(context & 15 == 0, "execUserCallback: unaligned CONTEXT");
    nested_interval(teb, |block, stack| {
        block.context.set(context);
        block.continue_flag.set(0);
        // SAFETY: dentro de um serviço despachado nesta CPU, com a pilha de
        // kernel do intervalo aninhado carregada; o fim dele volta a este
        // quadro pelo `dispatcher_rsp` que o stub grava.
        unsafe { user_exec_context(context, stack) }
    })
}

/// O lado de entrada do KiSwapContext para um serviço aninhado num callback
/// de modo usuário: retoma o quadro de troca `saved_rsp` que ele gravou ao
/// bloquear (na pilha do callback, que o Ke reinstalou em InitialStack), num
/// intervalo aninhado novo, como [`exec_user_callback`]. O serviço aninhado
/// recoloca o próprio estado por CPU ao voltar do bloqueio e segue até
/// terminar o intervalo (ou bloquear de novo); devolve o resultado e o tipo
/// de saída.
pub fn resume_user_callback(saved_rsp: u64, teb: u64) -> (u32, u32) {
    nested_interval(teb, |_, _| {
        // SAFETY: `saved_rsp` é o KernelStack que `block_in_service` gravou
        // na pilha do callback, ainda viva e não retomada; o fim do intervalo
        // volta ao quadro do despachante que a retomada grava.
        unsafe { context_switch::resume(saved_rsp) }
    })
}

/// O corpo comum de [`exec_user_callback`] e [`resume_user_callback`]:
/// guarda o estado por CPU do serviço de fora, carrega a pilha de kernel da
/// KTHREAD (a do callback) em RspBase/RSP0 e o GS do usuário, entra no
/// intervalo aninhado por `enter` e, no fim dele, recoloca tudo.
fn nested_interval(teb: u64, enter: impl FnOnce(&UserExecutionBlock, u64) -> u64) -> (u32, u32) {
    assert!(in_service(), "callback de usuario fora de um servico despachado");
    assert_armed();
    let block = block();
    let kpcr = pcr::current();
    let (fallback, frame_context, service_frame) = {
        let mut state = state().lock();
        (state.fallback_stack, core::mem::replace(&mut state.frame_context, 0), core::mem::replace(&mut state.service_frame, 0))
    };
    let saved = SuspendedService {
        context: block.context.get(),
        frame_context,
        service_frame,
        keep: *context_keep().lock(),
        user_rsp: kpcr.user_rsp.get(),
        continue_flag: block.continue_flag.get(),
        continue_rcx: block.continue_rcx.get(),
        continue_r11: block.continue_r11.get(),
        native: native_call::state(),
    };
    let dispatcher_rsp = block.dispatcher_rsp.get();
    let exit_kind = block.exit_kind.get();
    let outer_stack = kpcr.prcb.rsp_base.get();
    let flags = cpu::save_and_disable_interrupts();
    let stack = dispatch_stack(fallback);
    load_kernel_stack(stack);
    let swap_gs = cpu::read_msr(MSR_KERNEL_GS_BASE);
    let outer_area = block.xstate_area.get();
    let area = current_xstate_area();
    block.exit_kind.set(0);
    block.xstate_area.set(area);
    // O estado estendido vivo é o do usuário de fora (o kernel não o toca):
    // o callback parte dele, como no KiCallUserMode.
    crate::ntos::ke::xstate::save_current(area);
    cpu::write_msr(MSR_KERNEL_GS_BASE, teb);
    let result = enter(block, stack);
    // O fim do intervalo voltou com STI: o IF do serviço de fora volta.
    unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
    let nested_kind = block.exit_kind.get();
    load_kernel_stack(outer_stack);
    cpu::write_msr(MSR_KERNEL_GS_BASE, swap_gs);
    block.dispatcher_rsp.set(dispatcher_rsp);
    block.exit_kind.set(exit_kind);
    block.xstate_area.set(outer_area);
    block.context.set(saved.context);
    block.continue_flag.set(saved.continue_flag);
    block.continue_rcx.set(saved.continue_rcx);
    block.continue_r11.set(saved.continue_r11);
    kpcr.user_rsp.set(saved.user_rsp);
    *context_keep().lock() = saved.keep;
    native_call::restore_state(saved.native);
    {
        let mut state = state().lock();
        state.frame_context = saved.frame_context;
        state.service_frame = saved.service_frame;
    }
    cpu::restore_interrupts(flags);
    (result as u32, nested_kind)
}

/// O banco preparado entra no intervalo de usuário pausado.
pub fn set_user_debug_registers(bank: u64) {
    let frame_context = {
        let state = state().lock();
        assert!(state.running, "no paused user execution");
        state.frame_context
    };
    let values: [u64; 6] = core::array::from_fn(|index| read64(bank + index as u64 * 8));
    let block = block();
    for (register, &value) in block.debug_user.iter().zip(&values) {
        register.set(value);
    }
    let context = block.context.get();
    if context != 0 {
        for (index, &value) in values.iter().enumerate() {
            write64(context + 0x48 + index as u64 * 8, value);
        }
        if frame_context == context {
            let mut keep = context_keep().lock();
            for index in 0..48 {
                keep.0[0x48 + index] = true;
                keep.1[0x48 + index] = (values[index / 8] >> ((index % 8) * 8)) as u8;
            }
        }
    }
}

/// Retira o pedido pendente e depois o alvo, sem tocar nos registradores de
/// depuração da CPU.
pub fn clear_user_call_capture() {
    let block = block();
    block.capture_state.set(0);
    block.capture_address.set(0);
}

/// Pedido de captura única num endereço de usuário; a entrada em anel 3
/// escolhe um slot livre do banco USER.
pub fn arm_user_call_capture(address: u64) -> Result<(), crate::rtl::KernelError> {
    if !(0x1_0000..0x8000_0000_0000).contains(&address) {
        return Err(crate::rtl::KernelError::new("user call capture address"));
    }
    clear_user_call_capture();
    // O endereço vai antes do indicador de pedido pendente.
    let block = block();
    block.capture_address.set(address);
    block.capture_state.set(1);
    Ok(())
}

/// Bytes do CONTEXT escritos pelo kernel que sobrevivem ao salvamento do
/// retorno da syscall.
pub fn retain_user_context_ranges(context: u64, ranges: &[(u32, u32)]) -> bool {
    let frame_context = state().lock().frame_context;
    if frame_context == 0 || context != frame_context {
        return false;
    }
    assert!(ranges.len() <= 64, "invalid context ranges");
    assert!(ranges.iter().all(|&(offset, length)| offset as usize <= CONTEXT_SIZE && length as usize <= CONTEXT_SIZE - offset as usize), "context range outside saved frame");
    let mut keep = context_keep().lock();
    for &(offset, length) in ranges {
        for index in offset as usize..(offset + length) as usize {
            keep.1[index] = unsafe { core::ptr::read_volatile((context + index as u64) as *const u8) };
            keep.0[index] = true;
        }
    }
    true
}

/// O frame da syscall em despacho.
pub fn user_service_frame() -> u64 {
    state().lock().service_frame
}

/// Registradores da syscall para o CONTEXT do intervalo.
/// frame: [0]=rax [1]=rip [2]=rdx [3]=rsi [4]=rdi [5]=r8 [6]=r9 [7]=r10
///        [8]=rflags [9..14]=rbx/rbp/r12-r15.
fn capture_syscall_registers(frame: *const u64, result: u64) {
    let block = block();
    let context = block.context.get();
    if context == 0 {
        return;
    }
    let continuing = block.continue_flag.get() != 0;
    let f = |index: usize| unsafe { *frame.add(index) };
    write64(context + 0x78, if continuing { f(0) } else { result });
    write64(context + 0x80, if continuing { block.continue_rcx.get() } else { f(1) });
    write64(context + 0x88, f(2));
    write64(context + 0x90, f(9));
    write64(context + 0x98, pcr::current().user_rsp.get());
    write64(context + 0xA0, f(10));
    write64(context + 0xA8, f(3));
    write64(context + 0xB0, f(4));
    write64(context + 0xB8, f(5));
    write64(context + 0xC0, f(6));
    write64(context + 0xC8, f(7));
    write64(context + 0xD0, if continuing { block.continue_r11.get() } else { f(8) });
    write64(context + 0xD8, f(11));
    write64(context + 0xE0, f(12));
    write64(context + 0xE8, f(13));
    write64(context + 0xF0, f(14));
    write64(context + 0xF8, f(1));
    write32(context + 0x44, f(8) as u32);
    // A syscall vem sempre do código de 64 bits (o WoW64 volta a ele antes
    // da instrução syscall): CS e SS do usuário de 64 bits, mesmo depois de
    // um intervalo que o relógio interrompeu no código de 32 bits.
    unsafe {
        core::ptr::write_volatile((context + 0x38) as *mut u16, (SEL_USER_CODE | 3) as u16);
        core::ptr::write_volatile((context + 0x42) as *mut u16, USER_DS);
        core::ptr::copy_nonoverlapping((frame as *const u8).sub(0x208), (context + 0x100) as *mut u8, 512);
    }
    write32(context + 0x34, read32(context + 0x118));
}

/// Salva o CONTEXT do intervalo e volta ao escalonador (saída tipo 1).
fn save_syscall_context(frame: *const u64, result: u64) {
    let block = block();
    let context = block.context.get();
    if context == 0 {
        return;
    }
    let continuing = block.continue_flag.get() != 0;
    let callback = block.instrumentation.get();
    capture_syscall_registers(frame, result);
    if !continuing && callback != 0 {
        write64(context + 0xC8, unsafe { *frame.add(1) });
        write64(context + 0xF8, callback);
        write64(context + 0x80, callback);
    }
    let frame_context = state().lock().frame_context;
    if frame_context == context {
        let keep = context_keep().lock();
        for index in 0..CONTEXT_SIZE {
            if keep.0[index] {
                unsafe { core::ptr::write_volatile((context + index as u64) as *mut u8, keep.1[index]) };
            }
        }
    }
    state().lock().frame_context = 0;
    block.exit_kind.set(1);
    unsafe { user_terminate_current(0) }
}

/// `OPENNT_TRACE_SYSCALLS`: os serviços da tabela 1 (do win32k) vão direto à
/// rotina do driver, fora do registro de serviços nativos, e são
/// impressos aqui.
fn trace_win32k_service(number: u64, arguments: &[u64], result: u64) {
    if crate::ntos::init::boot_config::TRACE_SYSCALLS && number & 0x1000 != 0 {
        crate::debug_print!("[sys] {}:{} win32k#{:#x}({:#x}, {:#x}, {:#x}, {:#x}) = {:#x}", crate::ntos::ps::process::get_current_process_id(), crate::ntos::ps::process::get_current_thread_id(), number, arguments[0], arguments[1], arguments[2], arguments[3], result);
    }
}

/// Chamado pelo stub de syscall com o frame: escolhe a entrada real do
/// descritor da thread (o Shadow só para threads GUI) e chama o alvo MS x64
/// com os argumentos copiados; um número fora do limite segue o caminho do
/// Executive (conversão em thread GUI ou STATUS_INVALID_SYSTEM_SERVICE).
#[no_mangle]
pub extern "C" fn opennt_user_syscall(frame: *mut u64) -> u64 {
    let mut result: u64 = 0;
    let mut stack_count = 0u64;
    let number = unsafe { *frame };
    // KTHREAD.SystemCallNumber, que o KiSystemCall64 grava na entrada.
    let thread = crate::ntos::ke::pcr::current_thread();
    if thread != 0 {
        // SAFETY: a KTHREAD corrente, viva durante a syscall dela.
        unsafe { crate::ntos::inc::types::Kthread::at(thread) }.system_call_number.set(number as u32);
    }
    let sampled = crate::ntos::kd::sampler::service_start();
    // O papel do KTHREAD.TrapFrame, que o KiSystemServiceStart grava antes da
    // busca na tabela: o CONTEXT do intervalo recebe os registradores desta
    // syscall já aqui. A conversão em thread GUI logo abaixo chama o win32k,
    // que faz um KeUserModeCallback (o __ClientThreadSetup da user32) de
    // dentro dela; o quadro do callback sai do RSP e do RIP desse CONTEXT, e
    // sem a captura eles seriam os da entrada anterior no kernel.
    capture_syscall_registers(frame, number);
    state().lock().frame_context = block().context.get();
    {
        let mut keep = context_keep().lock();
        keep.0 = [false; CONTEXT_SIZE];
    }
    let mut target = service_lookup(number, crate::ntos::ps::win32::is_gui_thread() as u64, &mut stack_count);
    if target == 0 {
        match crate::ntos::ex::service_table::out_of_range(number as u32).unwrap_or(Err(STATUS_INVALID_SYSTEM_SERVICE)) {
            Ok((routine, arguments)) => (target, stack_count) = (routine, u64::from(arguments)),
            Err(status) => result = u64::from(status),
        }
    }
    system_services::note_user_target(number, target);
    if target != 0 {
        // O lote GDI da TEB antes de um serviço da tabela 1, como o
        // KiSystemServiceGdiTebAccess.
        crate::ntos::ps::win32::flush_gdi_batch_for_service(number);
        let mut packet = [0u64; 19];
        unsafe {
            packet[0] = *frame.add(7);
            packet[1] = *frame.add(2);
            packet[2] = *frame.add(5);
            packet[3] = *frame.add(6);
        }
        let entry_rsp = pcr::current().user_rsp.get();
        result = system_services::copy_arguments(packet.as_mut_ptr() as u64, entry_rsp, stack_count) as u64;
        if result == 0 {
            // O trampolim comum também captura posições sem uso: catorze
            // slots zerados no mínimo.
            let count = (stack_count as usize + 4).max(14);
            let previous = core::mem::replace(&mut state().lock().service_frame, frame as u64);
            result = crate::hal::amd64::native_call::call(target, &packet[..count]);
            state().lock().service_frame = previous;
        }
        trace_win32k_service(number, &packet, result);
        if number & 0x1000 != 0 {
            crate::ntos::init::initial_process::win32k_service_returned(number as u32, result);
            crate::ntos::init::initial_process::win32k_window_created(number as u32, &packet, result);
            crate::ntos::ps::user::win32k_status::returned(number as u32, result, entry_rsp);
        }
    } else {
        trace_win32k_service(number, &[0; 4], result);
    }
    // NtTerminateProcess: o código está no bloco da CPU; não volta ao anel 3.
    if result & 0xFFFF_FFFF == TERMINATE_MAGIC {
        unsafe { user_terminate_current(block().exit_code.get() as u64) }
    }
    // A volta ao modo usuário entrega a APC de término pedida para a thread
    // (o KiServiceExit com UserApcPending): o PspExitThread roda aqui, na
    // pilha dela, e o intervalo acaba sem voltar ao anel 3.
    crate::ntos::ps::user::threads::service_exit_termination();
    crate::ntos::kd::sampler::note_service(number, sampled, result);
    if continues_in_interval() {
        return result;
    }
    save_syscall_context(frame, result);
    result
}

/// O KiSystemServiceExit (19041 0x411510): sem troca de thread a fazer, o
/// fim de um serviço volta direto ao anel 3 pelo `user_syscall_exit` do stub
/// (IRETQ, o resultado em RAX) e o intervalo segue. Precisam do caminho do
/// CONTEXT: o serviço fora de um intervalo, o NtContinue, o callback de
/// instrumentação e as faixas do CONTEXT gravadas no serviço para a volta
/// (o SetContext e os registradores de depuração, o KiRestoreSetContextState
/// e o KiRestoreDebugRegisterState do 19041); e as razões da thread e do
/// despachante (`threads::may_return_to_user`).
fn continues_in_interval() -> bool {
    let block = block();
    if block.context.get() == 0 || block.continue_flag.get() != 0 || block.instrumentation.get() != 0 || context_keep().lock().0.contains(&true) {
        if block.context.get() != 0 {
            crate::ntos::ps::dispatch_perf::note_slow(crate::ntos::ps::dispatch_perf::slow::CONTEXT);
        }
        return false;
    }
    if let Err(reason) = crate::ntos::ps::user::threads::may_return_to_user() {
        crate::ntos::ps::dispatch_perf::note_slow(reason);
        return false;
    }
    state().lock().frame_context = 0;
    crate::ntos::ps::dispatch_perf::FAST_RETURNS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    crate::ntos::ps::dispatch_perf::thread_return(crate::ntos::ps::process::get_current_thread_id());
    true
}
