//! Anel 3 (modo usuário).
//!
//! A HAL só oferece as primitivas de CPU: GDT/TSS/MSRs, entrada em anel 3,
//! a entrada de syscall (o KiSystemCall64 deste kernel, alvo do LSTAR) e o
//! "longjmp" de volta ao chamador no término do processo ou ao fim de um
//! intervalo de execução. Despacho, loader e números NT ficam no kernel.
//!
//! A saída de syscall é por IRETQ: sob WHPX o SYSRETQ não entrega RIP=RCX,
//! e o IRETQ é o caminho que o próprio NT usa em KiSystemServiceExit.
//!
//! Células compartilhadas: a página de controle, um frame físico fixo
//! (0x8F000) acessado pelo mapa direto da metade de sistema (os stubs
//! carregam a VA da página num registrador; o Rust usa as constantes
//! abaixo, que já são VAs). Offsets na página:
//!   0x060 u64 pilha do usuário na entrada de syscall
//!   0x068 u64 topo da pilha de kernel das syscalls (RSP0)
//!   0x070 u64 pilha do chamador salva na entrada (retomada no término)
//!   0x078 u32 código de saída (NtTerminateProcess)
//!   0x090/098 RSP e CR2 de uma falta de usuário
//!   0x0A0/A8/B0 NtContinue: flag, RCX e R11 do CONTEXT
//!   0x138/140/148 vetor, RCX e RIP de uma falta de usuário
//!   0x150 estado da captura de chamada; 0x160-0x178 argumentos e 0x180 pilha
//!   capturados; 0x188 endereço; 0x190 máscara; 0x194/198 DR6 do usuário
//!   0x1A0 callback de instrumentação; 0x1A8 CONTEXT do intervalo
//!   0x1B0 tipo da saída: 0 término, 1 syscall, 2 timer, 3 exceção, 4 captura
//!   0x1B8 código de erro do hardware da falta

use core::arch::{asm, global_asm};

use crate::hal::cpu;
use crate::ntos::ex::system_services;
use crate::ntos::mm::memory_map;
use crate::rtl::SpinLock;

/// Frame físico da página de controle do anel 3.
pub const CONTROL_PAGE_PHYS: u64 = 0x8_F000;
/// A página de controle pela VA do mapa direto.
pub const CONTROL_PAGE: u64 = memory_map::direct_map(CONTROL_PAGE_PHYS);

/// Offsets das células na página de controle (usados pelos stubs).
pub mod cell {
    pub const USER_RSP: u64 = 0x060;
    pub const KERNEL_RSP: u64 = 0x068;
    pub const CALLER_STACK: u64 = 0x070;
    pub const EXIT_CODE: u64 = 0x078;
    pub const FAULT_RSP: u64 = 0x090;
    pub const FAULT_CR2: u64 = 0x098;
    pub const CONTINUE_FLAG: u64 = 0x0A0;
    pub const CONTINUE_RCX: u64 = 0x0A8;
    pub const CONTINUE_R11: u64 = 0x0B0;
    pub const FAULT_VECTOR: u64 = 0x138;
    pub const FAULT_RCX: u64 = 0x140;
    pub const FAULT_RIP: u64 = 0x148;
    pub const CAPTURE_STATE: u64 = 0x150;
    pub const CAPTURE_ARGUMENTS: u64 = 0x160;
    pub const CAPTURE_STACK: u64 = 0x180;
    pub const CAPTURE_ADDRESS: u64 = 0x188;
    pub const CAPTURE_MASK: u64 = 0x190;
    pub const DEBUG_CAUSES: u64 = 0x194;
    pub const DEBUG_STATUS: u64 = 0x198;
    pub const INSTRUMENTATION_CALLBACK: u64 = 0x1A0;
    pub const USER_CONTEXT: u64 = 0x1A8;
    pub const EXIT_KIND: u64 = 0x1B0;
    pub const ERROR_CODE: u64 = 0x1B8;
}

pub const USER_RSP_CELL: u64 = CONTROL_PAGE + cell::USER_RSP;
pub const KERNEL_RSP_CELL: u64 = CONTROL_PAGE + cell::KERNEL_RSP;
pub const EXIT_CODE_CELL: u64 = CONTROL_PAGE + cell::EXIT_CODE;
pub const FAULT_RSP_CELL: u64 = CONTROL_PAGE + cell::FAULT_RSP;
pub const FAULT_CR2_CELL: u64 = CONTROL_PAGE + cell::FAULT_CR2;
pub const CONTINUE_FLAG: u64 = CONTROL_PAGE + cell::CONTINUE_FLAG;
pub const CONTINUE_RCX: u64 = CONTROL_PAGE + cell::CONTINUE_RCX;
pub const CONTINUE_R11: u64 = CONTROL_PAGE + cell::CONTINUE_R11;
pub const FAULT_VECTOR_CELL: u64 = CONTROL_PAGE + cell::FAULT_VECTOR;
pub const FAULT_RCX_CELL: u64 = CONTROL_PAGE + cell::FAULT_RCX;
pub const FAULT_RIP_CELL: u64 = CONTROL_PAGE + cell::FAULT_RIP;
pub const CAPTURE_STATE: u64 = CONTROL_PAGE + cell::CAPTURE_STATE;
pub const CAPTURE_ARGUMENTS_CELL: u64 = CONTROL_PAGE + cell::CAPTURE_ARGUMENTS;
pub const CAPTURE_STACK_CELL: u64 = CONTROL_PAGE + cell::CAPTURE_STACK;
pub const CAPTURE_ADDRESS: u64 = CONTROL_PAGE + cell::CAPTURE_ADDRESS;
pub const INSTRUMENTATION_CALLBACK: u64 = CONTROL_PAGE + cell::INSTRUMENTATION_CALLBACK;
pub const USER_CONTEXT_CELL: u64 = CONTROL_PAGE + cell::USER_CONTEXT;
pub const USER_EXIT_KIND: u64 = CONTROL_PAGE + cell::EXIT_KIND;
pub const ERROR_CODE_CELL: u64 = CONTROL_PAGE + cell::ERROR_CODE;
/// Células de falta zeradas antes de cada entrada em anel 3.
pub const FAULT_CELLS: [u64; 5] = [FAULT_RSP_CELL, FAULT_CR2_CELL, FAULT_VECTOR_CELL, FAULT_RCX_CELL, FAULT_RIP_CELL];
const CONTEXT_SIZE: usize = 0x4D0;

const MSR_EFER: u32 = 0xC000_0080;
const MSR_STAR: u32 = 0xC000_0081;
const MSR_LSTAR: u32 = 0xC000_0082;
const MSR_SFMASK: u32 = 0xC000_0084;
const MSR_GS_BASE: u32 = 0xC000_0101;
const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// Seletores: 0x10/0x18 do stage2, 0x28 dados e 0x30 código de usuário,
/// 0x38 a TSS de 16 bytes.
const SEL_KERNEL_CODE: u64 = 0x10;
const SEL_USER_DATA: u64 = 0x28;
const SEL_USER_CODE: u64 = 0x30;
const SEL_TSS: u64 = 0x38;
const SEL_SYSRET_BASE: u64 = SEL_USER_DATA - 8;
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

.global user_debug_enter
user_debug_enter:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    movabs r8, {control_page}       # celulas pelo mapa direto
    lea rdi, [rip + user_debug_kernel]
    call user_debug_save
    mov rsi, [r8 + {context_cell}]
    test rsi, rsi
    jz opennt_ude_logical_ready
    mov rax, [rsi + 0x48 ]
    mov [rip + user_debug_user ], rax
    mov rax, [rsi + 0x48 + 8]
    mov [rip + user_debug_user + 8], rax
    mov rax, [rsi + 0x48 + 16]
    mov [rip + user_debug_user + 16], rax
    mov rax, [rsi + 0x48 + 24]
    mov [rip + user_debug_user + 24], rax
    mov rax, [rsi + 0x48 + 32]
    mov [rip + user_debug_user + 32], rax
    mov rax, [rsi + 0x48 + 40]
    mov [rip + user_debug_user + 40], rax
opennt_ude_logical_ready:
    mov rax, [rip + user_debug_user ]
    mov [rip + user_debug_hardware ], rax
    mov rax, [rip + user_debug_user + 8]
    mov [rip + user_debug_hardware + 8], rax
    mov rax, [rip + user_debug_user + 16]
    mov [rip + user_debug_hardware + 16], rax
    mov rax, [rip + user_debug_user + 24]
    mov [rip + user_debug_hardware + 24], rax
    mov rax, [rip + user_debug_user + 32]
    mov [rip + user_debug_hardware + 32], rax
    mov rax, [rip + user_debug_user + 40]
    mov [rip + user_debug_hardware + 40], rax
    mov dword ptr [r8 + {capture_mask}], 0
    cmp dword ptr [r8 + {capture_state}], 1
    jne opennt_ude_load
    # Um par com habilitação local OU global está ocupado.
    mov rdx, [rip + user_debug_user + 40]
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
    lea rsi, [rip + user_debug_hardware]
    mov [rsi + rdi*8], rax
    mov rax, [rip + user_debug_hardware + 40]
    lea ecx, [rdi*4 + 16]
    mov edx, 15
    shl rdx, cl
    not rdx
    and rax, rdx
    lea ecx, [rdi*2]
    mov edx, 1
    shl rdx, cl
    or rax, rdx
    mov [rip + user_debug_hardware + 40], rax
    mov edx, [r8 + {capture_mask}]
    not rdx
    and [rip + user_debug_hardware + 32], rdx
opennt_ude_load:
    mov byte ptr [rip + user_debug_active], 1
    lea rdi, [rip + user_debug_hardware]
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
    cmp byte ptr [rip + user_debug_active], 0
    je opennt_udl_done
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    movabs r8, {control_page}       # celulas pelo mapa direto
    lea rdi, [rip + user_debug_hardware]
    call user_debug_save
    mov rax, [rip + user_debug_hardware + 32]
    mov [r8 + {debug_status}], rax
    # DR6 pode citar comparadores desligados: só os habilitados são do usuário.
    mov rdx, [rip + user_debug_user + 40]
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
    lea rsi, [rip + user_debug_user]
    mov rax, [rsi + rcx*8]
    lea rsi, [rip + user_debug_hardware]
    mov [rsi + rcx*8], rax
    lea ecx, [rcx*4 + 16]
    mov edi, 15
    shl rdi, cl
    bsf ecx, edx
    add ecx, ecx
    mov eax, 3
    shl rax, cl
    or rdi, rax
    mov rax, [rip + user_debug_user + 40]
    and rax, rdi
    not rdi
    and [rip + user_debug_hardware + 40], rdi
    or [rip + user_debug_hardware + 40], rax
    mov rax, [rip + user_debug_user + 32]
    and rax, rdx
    not rdx
    and [rip + user_debug_hardware + 32], rdx
    or [rip + user_debug_hardware + 32], rax
opennt_udl_captured:
    mov rsi, [r8 + {context_cell}]
    mov rax, [rip + user_debug_hardware ]
    mov [rip + user_debug_user ], rax
    mov rax, [rip + user_debug_hardware + 8]
    mov [rip + user_debug_user + 8], rax
    mov rax, [rip + user_debug_hardware + 16]
    mov [rip + user_debug_user + 16], rax
    mov rax, [rip + user_debug_hardware + 24]
    mov [rip + user_debug_user + 24], rax
    mov rax, [rip + user_debug_hardware + 32]
    mov [rip + user_debug_user + 32], rax
    mov rax, [rip + user_debug_hardware + 40]
    mov [rip + user_debug_user + 40], rax
    test rsi, rsi
    jz opennt_udl_restore_kernel
    mov rax, [rip + user_debug_user ]
    mov [rsi + 0x48 ], rax
    mov rax, [rip + user_debug_user + 8]
    mov [rsi + 0x48 + 8], rax
    mov rax, [rip + user_debug_user + 16]
    mov [rsi + 0x48 + 16], rax
    mov rax, [rip + user_debug_user + 24]
    mov [rsi + 0x48 + 24], rax
    mov rax, [rip + user_debug_user + 32]
    mov [rsi + 0x48 + 32], rax
    mov rax, [rip + user_debug_user + 40]
    mov [rsi + 0x48 + 40], rax
opennt_udl_restore_kernel:
    mov byte ptr [rip + user_debug_active], 0
    lea rdi, [rip + user_debug_kernel]
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
    movabs rax, {control_page}
    mov [rax + {c_stack}], rsp
    mov rsp, rsi
    fxrstor64 [rdi + 0x100]
    push {user_ds}
    push qword ptr [rdi + 0x98]
    mov eax, [rdi + 0x44]
    push rax
    push {user_cs}
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
    iretq

# Entrada de syscall (LSTAR): rcx = RIP e r11 = RFLAGS do usuário; a CPU
# não troca pilha nem GS. Sem registrador livre, a troca de pilha passa o
# RSP do usuário por RAX (MOV moffs64 alcança o mapa direto); IF=0 aqui.
.global user_syscall_entry
user_syscall_entry:
    swapgs
    xchg rsp, rax
    movabs qword ptr [{user_rsp_cell}], rax
    movabs rax, qword ptr [{kernel_rsp_cell}]
    xchg rsp, rax
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
    # RBX (salvo no quadro e preservado pelas chamadas) guarda a VA da
    # página de controle até o IRETQ.
    movabs rbx, {control_page}
    # A syscall de anel 3 registra a origem na KTHREAD corrente.
    mov rax, gs:[0x188]
    mov byte ptr [rax + 0x232], 1
    mov dword ptr [rbx + {continue_flag}], 0
    mov rdi, rsp
    sub rsp, 0x208
    fxsave64 [rsp]
    mov rax, [rbx + {c_stack}]
    fxrstor64 [rax]
    call opennt_user_syscall
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
    movabs rax, {control_page}
    mov [rax + {c_stack}], rsp
    mov qword ptr [rip + user_debug_user ], 0
    mov qword ptr [rip + user_debug_user + 8], 0
    mov qword ptr [rip + user_debug_user + 16], 0
    mov qword ptr [rip + user_debug_user + 24], 0
    mov qword ptr [rip + user_debug_user + 32], 0
    mov qword ptr [rip + user_debug_user + 40], 0
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
    iretq

# user_terminate_current(exitCode=rdi): abandona a pilha de syscall, volta
# à pilha do chamador e retorna exitCode como uma chamada comum. O sti é
# obrigatório: a entrada de syscall limpou IF e este caminho não passa
# pelo iretq.
.global user_terminate_current
user_terminate_current:
    call user_debug_leave
    movabs rax, {control_page}
    mov rsp, [rax + {c_stack}]
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

.pushsection .data.usermode, "aw", @progbits
.balign 8
user_debug_kernel:   .zero 48
.global user_debug_user
user_debug_user:     .zero 48
user_debug_hardware: .zero 48
user_debug_active:   .quad 0
.balign 16
.global user_tss_storage
user_tss_storage:    .zero 136
.popsection
"#,
    control_page = const CONTROL_PAGE,
    user_rsp_cell = const USER_RSP_CELL,
    kernel_rsp_cell = const KERNEL_RSP_CELL,
    context_cell = const cell::USER_CONTEXT,
    capture_state = const cell::CAPTURE_STATE,
    capture_address = const cell::CAPTURE_ADDRESS,
    capture_mask = const cell::CAPTURE_MASK,
    debug_causes = const cell::DEBUG_CAUSES,
    debug_status = const cell::DEBUG_STATUS,
    c_stack = const cell::CALLER_STACK,
    user_rsp = const cell::USER_RSP,
    continue_flag = const cell::CONTINUE_FLAG,
    continue_rcx = const cell::CONTINUE_RCX,
    continue_r11 = const cell::CONTINUE_R11,
    instrumentation = const cell::INSTRUMENTATION_CALLBACK,
    user_ds = const SEL_USER_DATA | 3,
    user_cs = const SEL_USER_CODE | 3,
);

extern "C" {
    fn user_syscall_entry();
    fn user_exec_ring3(rip: u64, rsp: u64, kernel_stack: u64, argument1: u64, rflags: u64, argument2: u64) -> u64;
    fn user_exec_context(context: u64, kernel_stack: u64) -> u64;
    fn user_terminate_current(exit_code: u64) -> !;
    static mut user_tss_storage: [u8; 136];
    static mut user_debug_user: [u64; 6];
}

/// `nt_service_lookup` (MS x64): a mesma tabela consumida pela invocação.
fn service_lookup(number: u64, shadow: u64, stack_count: &mut u64) -> u64 {
    let routine: extern "win64" fn(u64, u64, *mut u64) -> u64 = unsafe { core::mem::transmute(crate::hal::amd64::service_table::entries()[0] as usize) };
    routine(number, shadow, stack_count)
}

struct Execution {
    syscall_stack_top: u64,
    ready: bool,
    running: bool,
    /// CONTEXT salvo pela syscall em curso (`g_userFrameContext`).
    frame_context: u64,
    service_frame: u64,
}

static STATE: SpinLock<Execution> = SpinLock::new(Execution { syscall_stack_top: 0, ready: false, running: false, frame_context: 0, service_frame: 0 });
/// Faixas do CONTEXT escritas pelo kernel durante a syscall, preservadas
/// sobre o salvamento do retorno.
static CONTEXT_KEEP: SpinLock<([bool; CONTEXT_SIZE], [u8; CONTEXT_SIZE])> = SpinLock::new(([false; CONTEXT_SIZE], [0; CONTEXT_SIZE]));
/// GDT nova: as 5 entradas do stage2, dados/código de usuário e a TSS.
static mut GDT: [u64; 16] = [0; 16];

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

/// GDT com os segmentos de usuário e a TSS (RSP0 = pilha de syscall),
/// LGDT/LTR, EFER.SCE e STAR/LSTAR/SFMASK. A KPCR continua no GS do kernel; o
/// KernelGSbase do usuário vai a zero.
pub fn user_mode_init(stack_top: u64) -> Result<u64, crate::rtl::KernelError> {
    if STATE.lock().ready {
        return Err(crate::rtl::KernelError::new("userModeInit: ja inicializado"));
    }
    if stack_top == 0 || stack_top & 0xF != 0 {
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
    let (gdt, tss) = (core::ptr::addr_of_mut!(GDT) as *mut u64, core::ptr::addr_of_mut!(user_tss_storage) as *mut u8);
    unsafe {
        core::ptr::copy_nonoverlapping(current.base as *const u8, gdt as *mut u8, limit + 1);
        *gdt.add((SEL_USER_DATA / 8) as usize) = 0x0000_F200_0000_0000;
        *gdt.add((SEL_USER_CODE / 8) as usize) = 0x0020_FA00_0000_0000;
        core::ptr::write_bytes(tss, 0, TSS_LIMIT as usize);
        core::ptr::write_unaligned(tss.add(4) as *mut u64, stack_top);
        core::ptr::write_unaligned(tss.add(102) as *mut u16, TSS_LIMIT as u16);
        let base = tss as u64;
        *gdt.add((SEL_TSS / 8) as usize) = (TSS_LIMIT - 1) | ((base & 0xFF_FFFF) << 16) | (0x89 << 40) | (((base >> 24) & 0xFF) << 56);
        *gdt.add((SEL_TSS / 8) as usize + 1) = base >> 32;
        let register = Register { limit: 9 * 8 - 1, base: gdt as u64 };
        asm!("lgdt [{}]", in(reg) &register, options(readonly, nostack));
        asm!("mov ax, {selector}", "ltr ax", selector = const SEL_TSS, out("ax") _, options(nostack));
    }
    write64(KERNEL_RSP_CELL, stack_top);
    write64(USER_RSP_CELL, 0);
    let efer = cpu::read_msr(MSR_EFER);
    cpu::write_msr(MSR_EFER, efer | 1);
    cpu::write_msr(MSR_STAR, (SEL_KERNEL_CODE << 32) | (SEL_SYSRET_BASE << 48));
    cpu::write_msr(MSR_LSTAR, user_syscall_entry as unsafe extern "C" fn() as usize as u64);
    cpu::write_msr(MSR_SFMASK, SFMASK_VALUE);
    cpu::write_msr(MSR_KERNEL_GS_BASE, 0);
    let mut state = STATE.lock();
    state.syscall_stack_top = stack_top;
    state.ready = true;
    Ok(gdt as u64)
}

/// O anel 3 foi armado.
pub fn ready() -> bool {
    STATE.lock().ready
}

/// Entra no processo e só volta no término (protocolo GS: GS.base = TEB e
/// KernelGSbase = KPCR em anel 3).
pub fn exec_user_mode(entry: u64, user_rsp: u64, teb: u64, argument1: u64, rflags: u64, argument2: u64) -> u64 {
    let stack = {
        let mut state = STATE.lock();
        assert!(state.ready, "execUserMode: userModeInit nao rodou");
        assert!(!state.running, "execUserMode: ja ha processo em ring 3");
        state.running = true;
        state.syscall_stack_top
    };
    let kernel_gs = cpu::read_msr(MSR_GS_BASE);
    let previous_swap = cpu::read_msr(MSR_KERNEL_GS_BASE);
    for cell in FAULT_CELLS {
        write64(cell, 0);
    }
    cpu::write_msr(MSR_KERNEL_GS_BASE, kernel_gs);
    cpu::write_msr(MSR_GS_BASE, teb);
    let exit_code = unsafe { user_exec_ring3(entry, user_rsp, stack, argument1, rflags, argument2) };
    cpu::write_msr(MSR_GS_BASE, kernel_gs);
    cpu::write_msr(MSR_KERNEL_GS_BASE, previous_swap);
    STATE.lock().running = false;
    exit_code
}

/// Um intervalo de escalonamento. A HAL só move o estado dos registradores; o
/// kernel escolhe a thread.
pub fn exec_user_context(context: u64, teb: u64) -> u32 {
    let stack = {
        let mut state = STATE.lock();
        assert!(state.ready && !state.running, "execUserContext: invalid execution state");
        assert!(context & 15 == 0, "execUserContext: unaligned CONTEXT");
        state.running = true;
        state.frame_context = 0;
        state.syscall_stack_top
    };
    if read32(CAPTURE_STATE) == 1 {
        let dr7 = read64(context + 0x70);
        assert!((0..4).any(|slot| dr7 & (3 << (slot * 2)) == 0), "user call capture: all four debug slots are in use");
    }
    let kernel_gs = cpu::read_msr(MSR_GS_BASE);
    let swap_gs = cpu::read_msr(MSR_KERNEL_GS_BASE);
    write64(USER_CONTEXT_CELL, context);
    write32(USER_EXIT_KIND, 0);
    write32(CONTINUE_FLAG, 0);
    cpu::write_msr(MSR_KERNEL_GS_BASE, kernel_gs);
    cpu::write_msr(MSR_GS_BASE, teb);
    let result = unsafe { user_exec_context(context, stack) };
    write64(USER_CONTEXT_CELL, 0);
    cpu::write_msr(MSR_GS_BASE, kernel_gs);
    cpu::write_msr(MSR_KERNEL_GS_BASE, swap_gs);
    let mut state = STATE.lock();
    state.frame_context = 0;
    state.running = false;
    result as u32
}

/// O banco preparado entra no intervalo de usuário pausado.
pub fn set_user_debug_registers(bank: u64) {
    let frame_context = {
        let state = STATE.lock();
        assert!(state.running, "no paused user execution");
        state.frame_context
    };
    let values: [u64; 6] = core::array::from_fn(|index| read64(bank + index as u64 * 8));
    unsafe {
        *core::ptr::addr_of_mut!(user_debug_user) = values;
    }
    let context = read64(USER_CONTEXT_CELL);
    if context != 0 {
        for (index, &value) in values.iter().enumerate() {
            write64(context + 0x48 + index as u64 * 8, value);
        }
        if frame_context == context {
            let mut keep = CONTEXT_KEEP.lock();
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
    unsafe {
        core::ptr::write_volatile(CAPTURE_STATE as *mut u32, 0);
        core::ptr::write_volatile(CAPTURE_ADDRESS as *mut u64, 0);
    }
}

/// Pedido de captura única num endereço de usuário; a entrada em anel 3
/// escolhe um slot livre do banco USER.
pub fn arm_user_call_capture(address: u64) -> Result<(), crate::rtl::KernelError> {
    if !(0x1_0000..0x8000_0000_0000).contains(&address) {
        return Err(crate::rtl::KernelError::new("user call capture address"));
    }
    clear_user_call_capture();
    // O endereço vai antes do indicador de pedido pendente.
    unsafe {
        core::ptr::write_volatile(CAPTURE_ADDRESS as *mut u64, address);
        core::ptr::write_volatile(CAPTURE_STATE as *mut u32, 1);
    }
    Ok(())
}

/// Bytes do CONTEXT escritos pelo kernel que sobrevivem ao salvamento do
/// retorno da syscall.
pub fn retain_user_context_ranges(context: u64, ranges: &[(u32, u32)]) -> bool {
    let frame_context = STATE.lock().frame_context;
    if frame_context == 0 || context != frame_context {
        return false;
    }
    assert!(ranges.len() <= 64, "invalid context ranges");
    assert!(ranges.iter().all(|&(offset, length)| offset as usize <= CONTEXT_SIZE && length as usize <= CONTEXT_SIZE - offset as usize), "context range outside saved frame");
    let mut keep = CONTEXT_KEEP.lock();
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
    STATE.lock().service_frame
}

/// Registradores da syscall para o CONTEXT do intervalo.
/// frame: [0]=rax [1]=rip [2]=rdx [3]=rsi [4]=rdi [5]=r8 [6]=r9 [7]=r10
///        [8]=rflags [9..14]=rbx/rbp/r12-r15.
fn capture_syscall_registers(frame: *const u64, result: u64) {
    let context = read64(USER_CONTEXT_CELL);
    if context == 0 {
        return;
    }
    let continuing = read32(CONTINUE_FLAG) != 0;
    let f = |index: usize| unsafe { *frame.add(index) };
    write64(context + 0x78, if continuing { f(0) } else { result });
    write64(context + 0x80, if continuing { read64(CONTINUE_RCX) } else { f(1) });
    write64(context + 0x88, f(2));
    write64(context + 0x90, f(9));
    write64(context + 0x98, read64(USER_RSP_CELL));
    write64(context + 0xA0, f(10));
    write64(context + 0xA8, f(3));
    write64(context + 0xB0, f(4));
    write64(context + 0xB8, f(5));
    write64(context + 0xC0, f(6));
    write64(context + 0xC8, f(7));
    write64(context + 0xD0, if continuing { read64(CONTINUE_R11) } else { f(8) });
    write64(context + 0xD8, f(11));
    write64(context + 0xE0, f(12));
    write64(context + 0xE8, f(13));
    write64(context + 0xF0, f(14));
    write64(context + 0xF8, f(1));
    write32(context + 0x44, f(8) as u32);
    unsafe {
        core::ptr::copy_nonoverlapping((frame as *const u8).sub(0x208), (context + 0x100) as *mut u8, 512);
    }
    write32(context + 0x34, read32(context + 0x118));
}

/// Salva o CONTEXT do intervalo e volta ao escalonador (saída tipo 1).
fn save_syscall_context(frame: *const u64, result: u64) {
    let context = read64(USER_CONTEXT_CELL);
    if context == 0 {
        return;
    }
    let continuing = read32(CONTINUE_FLAG) != 0;
    let callback = read64(INSTRUMENTATION_CALLBACK);
    capture_syscall_registers(frame, result);
    if !continuing && callback != 0 {
        write64(context + 0xC8, unsafe { *frame.add(1) });
        write64(context + 0xF8, callback);
        write64(context + 0x80, callback);
    }
    let frame_context = STATE.lock().frame_context;
    if frame_context == context {
        let keep = CONTEXT_KEEP.lock();
        for index in 0..CONTEXT_SIZE {
            if keep.0[index] {
                unsafe { core::ptr::write_volatile((context + index as u64) as *mut u8, keep.1[index]) };
            }
        }
    }
    STATE.lock().frame_context = 0;
    write32(USER_EXIT_KIND, 1);
    unsafe { user_terminate_current(0) }
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
    let mut target = service_lookup(number, crate::ntos::ps::win32::is_gui_thread() as u64, &mut stack_count);
    if target == 0 {
        match crate::ntos::ex::service_table::out_of_range(number as u32).unwrap_or(Err(STATUS_INVALID_SYSTEM_SERVICE)) {
            Ok((routine, arguments)) => (target, stack_count) = (routine, u64::from(arguments)),
            Err(status) => result = u64::from(status),
        }
    }
    capture_syscall_registers(frame, number);
    STATE.lock().frame_context = read64(USER_CONTEXT_CELL);
    {
        let mut keep = CONTEXT_KEEP.lock();
        keep.0 = [false; CONTEXT_SIZE];
    }
    if target != 0 {
        let mut packet = [0u64; 19];
        unsafe {
            packet[0] = *frame.add(7);
            packet[1] = *frame.add(2);
            packet[2] = *frame.add(5);
            packet[3] = *frame.add(6);
        }
        result = system_services::copy_arguments(packet.as_mut_ptr() as u64, read64(USER_RSP_CELL), stack_count) as u64;
        if result == 0 {
            // O trampolim comum também captura posições sem uso: catorze
            // slots zerados no mínimo.
            let count = (stack_count as usize + 4).max(14);
            let previous = core::mem::replace(&mut STATE.lock().service_frame, frame as u64);
            result = crate::hal::amd64::native_call::call(target, &packet[..count]);
            STATE.lock().service_frame = previous;
        }
    }
    // NtTerminateProcess: o código está na célula; não volta ao anel 3.
    if result & 0xFFFF_FFFF == TERMINATE_MAGIC {
        unsafe { user_terminate_current(read32(EXIT_CODE_CELL) as u64) }
    }
    save_syscall_context(frame, result);
    result
}
