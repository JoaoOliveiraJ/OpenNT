//! O estado estendido (AVX) de threads de usuário, com a ntdll real do
//! volume mapeada num processo de teste:
//!
//! - duas threads de usuário carregam YMM0-YMM15 diferentes (VMOVDQU de 256
//!   bits), fazem NtYieldExecution e espera ativa (o relógio encerra
//!   intervalos) várias vezes e conferem que os 16 YMM inteiros voltaram;
//! - RtlGetEnabledExtendedFeatures(-1) da ntdll devolve EnabledFeatures |
//!   supervisor visível (a XState da KUSER_SHARED_DATA);
//! - NtGetContextThread(NtCurrentThread()) com CONTEXT_XSTATE num CONTEXT
//!   estendido montado pela ntdll (RtlGetExtendedContextLength,
//!   RtlInitializeExtendedContext, RtlSetExtendedFeaturesMask): o
//!   RtlLocateExtendedFeature da ntdll acha nele a metade alta dos YMM
//!   carregados, e o RtlGetExtendedFeaturesMask tem o AVX;
//! - um `ud2` com YMM carregados: o frame do despachante de exceções (uma
//!   rotina do programa no lugar do KiUserExceptionDispatcher) traz
//!   STATUS_ILLEGAL_INSTRUCTION, ContextFlags 0x10005F e, pelo
//!   RtlLocateExtendedFeature, a metade alta dos YMM do momento da falta; a
//!   rotina troca os 16 YMM inteiros (a metade baixa no CONTEXT.Xmm, a alta
//!   no pedaço XSTATE), avança o RIP e chama o NtContinue: depois do `ud2` os
//!   YMM são os que a rotina escreveu (a volta pelo CONTEXT_XSTATE);
//! - um chamador de KernelMode com CONTEXT_XSTATE: um serviço de teste monta
//!   um CONTEXT estendido do kernel (CONTEXT_AMD64 | CONTEXT_XSTATE) com só o
//!   AVX no pedaço e chama o PspSetContextThreadInternal(KernelMode,
//!   UserMode) na própria thread; de volta ao anel 3, a metade alta dos YMM
//!   é a do pedaço e a baixa continua a de antes;
//! - uma APC especial na própria thread (NtQueueApcThreadEx com 1), com YMM
//!   carregados: ela sai no retorno da chamada, num despachante do programa
//!   no lugar do KiUserApcDispatcher, que confere o frame (ContextFlags
//!   0x10005B, as flags 2 em P5Home, o CONTEXT_EX e, pelo
//!   RtlLocateExtendedFeature, a metade alta dos YMM no pedaço XSTATE logo
//!   abaixo do RSP interrompido), chama a rotina como o original (que
//!   sobrescreve os 16 YMM) e volta pelo NtContinueEx(CONTEXT, CONTEXT+0x4F0):
//!   depois da chamada os YMM inteiros são os de antes da APC.
//!
//! As chamadas de sistema do programa entram pela tabela 1 do Shadow (as
//! threads são GUI, como no teste dos callbacks), cujos serviços de teste
//! chamam os serviços nativos NtYieldExecution, NtGetContextThread,
//! NtContinue, NtTerminateThread, NtQueueApcThreadEx e NtContinueEx do
//! kernel: o boot de autoteste instala só os números da ntdll de bring-up, e
//! os stubs da ntdll real usam os do 19045. Da ntdll real o programa só usa
//! rotinas Rtl, que não entram no kernel.
//!
//! `XSTATE_USER_OK` sai só se todas as conferências passarem.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

use super::identity::with_test_process;
use crate::hal::amd64::usermode;
use crate::ntos::ex::service_table;
use crate::ntos::inc::types::{Ethread, NtStruct};
use crate::ntos::ke::{pcr, xsave};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::pe_loader::{self, LoadOptions};
use crate::ntos::mm::{kernel_stack, peb_teb};
use crate::ntos::ps::context::set as set_thread_context;
use crate::ntos::ps::user::threads::{self, UserThread};
use crate::ntos::ps::user::{loader, memory, state};
use crate::ntos::ps::{cid, process};
use crate::ntos::rtl::extended_context::{self, CONTEXT_LENGTH, CONTEXT_XSTATE};
use crate::ntos::test::extended_state::{mixed, pattern, upper_halves, YMM_BYTES};

type Assert = fn(bool, &str);

static FAILED: AtomicBool = AtomicBool::new(false);

/// As rotinas da ntdll que o programa chama, na ordem da tabela.
const IMPORTS: [&str; 6] = [
    "RtlGetEnabledExtendedFeatures",
    "RtlGetExtendedContextLength",
    "RtlInitializeExtendedContext",
    "RtlLocateExtendedFeature",
    "RtlGetExtendedFeaturesMask",
    "RtlSetExtendedFeaturesMask",
];

/// Os serviços de teste da tabela 1 e os nativos que eles chamam; o último
/// serviço de teste (o chamador de KernelMode) não tem nativo.
const SERVICES: [&str; 6] = ["NtYieldExecution", "NtGetContextThread", "NtContinue", "NtTerminateThread", "NtQueueApcThreadEx", "NtContinueEx"];
const SERVICE_COUNT: usize = 7;
const YIELD_SERVICE: u32 = 0x1000;
const GET_CONTEXT_SERVICE: u32 = 0x1001;
const CONTINUE_SERVICE: u32 = 0x1002;
const TERMINATE_SERVICE: u32 = 0x1003;
const QUEUE_APC_SERVICE: u32 = 0x1004;
const CONTINUE_EX_SERVICE: u32 = 0x1005;
const KERNEL_SET_SERVICE: u32 = 0x1006;

static SERVICE_TABLE: [AtomicU32; SERVICE_COUNT] = [const { AtomicU32::new(0) }; SERVICE_COUNT];
static SERVICE_ARGUMENTS: [AtomicU8; SERVICE_COUNT] = [const { AtomicU8::new(0) }; SERVICE_COUNT];

/// Um serviço nativo pelo registro de serviços (os quatro primeiros
/// argumentos e a pilha do usuário, para os argumentos 5 em diante).
fn native_with_stack(name: &str, arguments: [u64; 4], rsp: u64) -> u64 {
    state::handler(name).map_or(0xC000_0001, |handler| handler(arguments[0], arguments[1], arguments[2], arguments[3], rsp).unwrap_or(0xC000_0001)) as u64
}

/// Um serviço nativo sem argumento na pilha.
fn native(name: &str, arguments: [u64; 4]) -> u64 {
    native_with_stack(name, arguments, 0)
}

extern "win64" fn yield_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    native(SERVICES[0], [0; 4])
}

extern "win64" fn get_context_service(thread: u64, context: u64, _: u64, _: u64) -> u64 {
    native(SERVICES[1], [thread, context, 0, 0])
}

extern "win64" fn continue_service(context: u64, alertable: u64, _: u64, _: u64) -> u64 {
    native(SERVICES[2], [context, alertable, 0, 0])
}

extern "win64" fn terminate_service(thread: u64, status: u64, _: u64, _: u64) -> u64 {
    native(SERVICES[3], [thread, status, 0, 0])
}

/// NtQueueApcThreadEx(thread, reserve, routine, argument1, argument2,
/// argument3): os dois últimos ficam na pilha do usuário, que a
/// KPCR.UserRsp da chamada aponta.
extern "win64" fn queue_apc_service(thread: u64, reserve: u64, routine: u64, argument: u64) -> u64 {
    native_with_stack(SERVICES[4], [thread, reserve, routine, argument], pcr::current().user_rsp.get())
}

extern "win64" fn continue_ex_service(context: u64, argument: u64, _: u64, _: u64) -> u64 {
    native(SERVICES[5], [context, argument, 0, 0])
}

/// A semente da metade alta que o chamador de KernelMode põe na thread.
const KERNEL_SEED: u8 = 0x39;

/// Um chamador de KernelMode com CONTEXT_XSTATE: um CONTEXT estendido do
/// kernel (RtlInitializeExtendedContext2 com CONTEXT_AMD64 | CONTEXT_XSTATE)
/// cujo pedaço tem só o AVX, com a metade alta de `pattern(KERNEL_SEED)`, e
/// o PspSetContextThreadInternal(thread corrente, CONTEXT, KernelMode,
/// UserMode, 1).
extern "win64" fn kernel_set_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    let mask = xsave::enabled_features() | xsave::enabled_user_visible_supervisor_features();
    let Ok(length) = extended_context::extended_context_length2(CONTEXT_XSTATE, mask) else { return 0xC000_0001 };
    let buffer = guest::alloc_aligned(length as u64, 16, true);
    if buffer == 0 {
        return 0xC000_0017;
    }
    let status = match extended_context::initialize_extended_context2(buffer, CONTEXT_XSTATE, mask) {
        Ok(context_ex) => {
            let (header, _) = extended_context::xstate_chunk(context_ex);
            // O AVX no pedaço: o primeiro recurso depois do cabeçalho no
            // formato compactado; no padrão, o deslocamento dele menos a área
            // legada.
            let offset = if xsave::compaction() { xsave::HEADER_SIZE } else { xsave::configuration().features[2].offset.get() - xsave::LEGACY_SIZE };
            guest::write_bytes(header + offset as u64, &upper_halves(&pattern(KERNEL_SEED)));
            guest::write64(header, xsave::feature::AVX);
            let context = context_ex - CONTEXT_LENGTH as u64;
            set_thread_context::execute(process::get_current_thread(), context, 0, 1, 1).unwrap_or(0xC000_0001)
        }
        Err(status) => status,
    };
    guest::free_bytes(buffer);
    status as u64
}

/// A área de dados do programa.
mod data {
    pub const IMPORTS: u64 = 0x000;
    pub const ENABLED: u64 = 0x080;
    pub const CONTEXT_LENGTH: u64 = 0x088;
    pub const LENGTH_STATUS: u64 = 0x08C;
    pub const INIT_STATUS: u64 = 0x090;
    pub const GET_STATUS: u64 = 0x094;
    pub const CONTEXT_EX: u64 = 0x098;
    pub const LOCATE_LENGTH: u64 = 0x0A0;
    pub const EXCEPTION_FLAGS: u64 = 0x0A4;
    pub const GET_POINTER: u64 = 0x0A8;
    pub const GET_MASK: u64 = 0x0B0;
    pub const EXCEPTION_CODE: u64 = 0x0B8;
    pub const EXCEPTION_LENGTH: u64 = 0x0BC;
    pub const EXCEPTION_POINTER: u64 = 0x0C0;
    pub const EXCEPTION_MASK: u64 = 0x0C8;
    pub const CONTINUE_STATUS: u64 = 0x0D0;
    pub const PATTERN_A: u64 = 0x100;
    pub const PATTERN_B: u64 = 0x300;
    pub const PATTERN_C: u64 = 0x500;
    pub const PATTERN_D: u64 = 0x700;
    pub const PATTERN_E: u64 = 0x900;
    pub const OUT_A: u64 = 0xB00;
    pub const OUT_B: u64 = 0xD00;
    pub const OUT_D: u64 = 0xF00;
    pub const GET_HIGH: u64 = 0x1100;
    pub const EXCEPTION_HIGH: u64 = 0x1200;
    pub const CONTEXT_BUFFER: u64 = 0x1400;
    pub const PATTERN_F: u64 = 0x2400;
    pub const PATTERN_G: u64 = 0x2600;
    pub const PATTERN_H: u64 = 0x2800;
    pub const OUT_F: u64 = 0x2A00;
    pub const OUT_H: u64 = 0x2C00;
    pub const APC_HIGH: u64 = 0x2E00;
    pub const KERNEL_SET_STATUS: u64 = 0x2F00;
    pub const QUEUE_STATUS: u64 = 0x2F04;
    pub const APC_FLAGS: u64 = 0x2F08;
    pub const APC_LENGTH: u64 = 0x2F0C;
    pub const APC_FRAME: u64 = 0x2F10;
    pub const APC_HOME5: u64 = 0x2F18;
    pub const APC_MACHINE_RSP: u64 = 0x2F20;
    pub const APC_POINTER: u64 = 0x2F28;
    pub const APC_RSP: u64 = 0x2F30;
    /// NormalContext, SystemArgument1, SystemArgument2 e o CONTEXT que a
    /// rotina da APC recebeu.
    pub const APC_ARGUMENTS: u64 = 0x2F38;
    /// O CONTEXT_EX do frame da APC (All, Legacy e XState).
    pub const APC_CONTEXT_EX: u64 = 0x2F58;
    pub const APC_CONTINUE_STATUS: u64 = 0x2F70;
    pub const APC_CALLS: u64 = 0x2F74;
    pub const SIZE: u64 = 0x3000;
}

/// CONTEXT_AMD64 | CONTROL | INTEGER | FLOATING_POINT | XSTATE.
const GET_FLAGS: u32 = 0x10_004B;
const ROUNDS: u32 = 24;
const SPIN: u32 = 200_000;
const SENTINEL: u32 = 0xFFFF_FFFF;
/// Os argumentos 2 e 3 da APC especial (SystemArgument1 e SystemArgument2).
const APC_ARGUMENT2: u32 = 0x5A5A_1234;
const APC_ARGUMENT3: u32 = 0x6B6B_5678;
/// As sementes dos YMM da APC especial (antes dela e o que a rotina
/// escreve) e de antes do chamador de KernelMode.
const SEED_F: u8 = 0xC6;
const SEED_G: u8 = 0xE7;
const SEED_H: u8 = 0x18;

core::arch::global_asm!(
    r#"
.pushsection .rodata.opennt_xstate_user_program, "a"
.balign 16
.global opennt_xsu_start
opennt_xsu_start:
    sub rsp, 0x28
    mov rbx, qword ptr [rip + opennt_xsu_data]
    mov rcx, -1
    call qword ptr [rbx + {imp_enabled}]
    mov qword ptr [rbx + {enabled}], rax
    lea rdi, [rbx + {pattern_a}]
    call opennt_xsu_load
    mov r12d, {rounds}
opennt_xsu_loop1:
    mov eax, {svc_yield}
    mov r10, rcx
    syscall
    mov ecx, {spin}
opennt_xsu_spin1:
    pause
    dec ecx
    jnz opennt_xsu_spin1
    dec r12d
    jnz opennt_xsu_loop1
    lea rdi, [rbx + {out_a}]
    call opennt_xsu_store
    mov ecx, {get_flags}
    lea rdx, [rbx + {context_length}]
    call qword ptr [rbx + {imp_length}]
    mov dword ptr [rbx + {length_status}], eax
    lea rcx, [rbx + {context_buffer}]
    mov edx, {get_flags}
    lea r8, [rbx + {context_ex}]
    call qword ptr [rbx + {imp_init}]
    mov dword ptr [rbx + {init_status}], eax
    mov rcx, qword ptr [rbx + {context_ex}]
    mov edx, 4
    call qword ptr [rbx + {imp_set_mask}]
    lea rdi, [rbx + {pattern_e}]
    call opennt_xsu_load
    mov rcx, -2
    mov rdx, qword ptr [rbx + {context_ex}]
    sub rdx, 0x4D0
    mov eax, {svc_get_context}
    mov r10, rcx
    syscall
    mov dword ptr [rbx + {get_status}], eax
    mov rcx, qword ptr [rbx + {context_ex}]
    mov edx, 2
    lea r8, [rbx + {locate_length}]
    call qword ptr [rbx + {imp_locate}]
    mov qword ptr [rbx + {get_pointer}], rax
    test rax, rax
    jz opennt_xsu_no_get
    mov rsi, rax
    lea rdi, [rbx + {get_high}]
    mov ecx, 256
    rep movsb
opennt_xsu_no_get:
    mov rcx, qword ptr [rbx + {context_ex}]
    call qword ptr [rbx + {imp_get_mask}]
    mov qword ptr [rbx + {get_mask}], rax
    lea rdi, [rbx + {pattern_c}]
    call opennt_xsu_load
    ud2
    lea rdi, [rbx + {out_d}]
    call opennt_xsu_store
# CONTEXT_XSTATE de um chamador de KernelMode na própria thread.
    lea rdi, [rbx + {pattern_h}]
    call opennt_xsu_load
    mov eax, {svc_kernel_set}
    mov r10, rcx
    syscall
    mov dword ptr [rbx + {kernel_set_status}], eax
    lea rdi, [rbx + {out_h}]
    call opennt_xsu_store
# APC especial na própria thread: NtQueueApcThreadEx(-2, 1, rotina, bloco,
# argumento 2, argumento 3); ela sai no retorno da chamada.
    lea rdi, [rbx + {pattern_f}]
    call opennt_xsu_load
    sub rsp, 0x38
    mov qword ptr [rsp + 0x28], {apc_argument2}
    mov qword ptr [rsp + 0x30], {apc_argument3}
    mov qword ptr [rbx + {apc_rsp}], rsp
    mov rcx, -2
    mov edx, 1
    lea r8, [rip + opennt_xsu_apc_routine]
    mov r9, rbx
    mov eax, {svc_queue_apc}
    mov r10, rcx
    syscall
    add rsp, 0x38
    mov dword ptr [rbx + {queue_status}], eax
    lea rdi, [rbx + {out_f}]
    call opennt_xsu_store
    mov rcx, -2
    xor edx, edx
    mov eax, {svc_terminate}
    mov r10, rcx
    syscall
opennt_xsu_hang1:
    jmp opennt_xsu_hang1

.global opennt_xsu_thread2
opennt_xsu_thread2:
    sub rsp, 0x28
    mov rbx, qword ptr [rip + opennt_xsu_data]
    lea rdi, [rbx + {pattern_b}]
    call opennt_xsu_load
    mov r12d, {rounds}
opennt_xsu_loop2:
    mov eax, {svc_yield}
    mov r10, rcx
    syscall
    mov ecx, {spin}
opennt_xsu_spin2:
    pause
    dec ecx
    jnz opennt_xsu_spin2
    dec r12d
    jnz opennt_xsu_loop2
    lea rdi, [rbx + {out_b}]
    call opennt_xsu_store
    mov rcx, -2
    xor edx, edx
    mov eax, {svc_terminate}
    mov r10, rcx
    syscall
opennt_xsu_hang2:
    jmp opennt_xsu_hang2

# O despachante de exceções: RSP = CONTEXT do frame (CONTEXT_EX em 0x4D0,
# EXCEPTION_RECORD em 0x4F0).
.global opennt_xsu_dispatcher
opennt_xsu_dispatcher:
    mov r15, rsp
    sub rsp, 0x20
    mov rbx, qword ptr [rip + opennt_xsu_data]
    mov eax, dword ptr [r15 + 0x30]
    mov dword ptr [rbx + {exception_flags}], eax
    mov eax, dword ptr [r15 + 0x4F0]
    mov dword ptr [rbx + {exception_code}], eax
    lea rcx, [r15 + 0x4D0]
    mov edx, 2
    lea r8, [rbx + {exception_length}]
    call qword ptr [rbx + {imp_locate}]
    mov qword ptr [rbx + {exception_pointer}], rax
    test rax, rax
    jz opennt_xsu_no_xstate
    mov r14, rax
    mov rsi, rax
    lea rdi, [rbx + {exception_high}]
    mov ecx, 256
    rep movsb
    lea rsi, [rbx + {pattern_d}]
    xor ecx, ecx
opennt_xsu_patch:
    mov rax, qword ptr [rsi + 16]
    mov qword ptr [r14], rax
    mov rax, qword ptr [rsi + 24]
    mov qword ptr [r14 + 8], rax
    mov rax, qword ptr [rsi]
    mov qword ptr [r15 + rcx + 0x1A0], rax
    mov rax, qword ptr [rsi + 8]
    mov qword ptr [r15 + rcx + 0x1A8], rax
    add rsi, 32
    add r14, 16
    add ecx, 16
    cmp ecx, 256
    jb opennt_xsu_patch
opennt_xsu_no_xstate:
    lea rcx, [r15 + 0x4D0]
    call qword ptr [rbx + {imp_get_mask}]
    mov qword ptr [rbx + {exception_mask}], rax
    add qword ptr [r15 + 0xF8], 2
    mov rcx, r15
    xor edx, edx
    mov eax, {svc_continue}
    mov r10, rcx
    syscall
    mov dword ptr [rbx + {continue_status}], eax
opennt_xsu_hang3:
    jmp opennt_xsu_hang3

# O despachante de APCs (no lugar do KiUserApcDispatcher): RSP = CONTEXT do
# frame (CONTEXT_EX em 0x4D0, KCONTINUE_ARGUMENT em 0x4F0, MACHINE_FRAME em
# 0x530). Chama a rotina como o original, com NormalContext,
# SystemArgument1, SystemArgument2 e o CONTEXT, e volta pelo
# NtContinueEx(CONTEXT, CONTEXT+0x4F0).
.global opennt_xsu_apc_dispatcher
opennt_xsu_apc_dispatcher:
    mov r15, rsp
    sub rsp, 0x20
    mov rbx, qword ptr [rip + opennt_xsu_data]
    inc dword ptr [rbx + {apc_calls}]
    mov qword ptr [rbx + {apc_frame}], r15
    mov eax, dword ptr [r15 + 0x30]
    mov dword ptr [rbx + {apc_flags}], eax
    mov rax, qword ptr [r15 + 0x20]
    mov qword ptr [rbx + {apc_home5}], rax
    mov rax, qword ptr [r15 + 0x548]
    mov qword ptr [rbx + {apc_machine_rsp}], rax
    lea rsi, [r15 + 0x4D0]
    lea rdi, [rbx + {apc_context_ex}]
    mov ecx, 0x18
    rep movsb
    lea rcx, [r15 + 0x4D0]
    mov edx, 2
    lea r8, [rbx + {apc_length}]
    call qword ptr [rbx + {imp_locate}]
    mov qword ptr [rbx + {apc_pointer}], rax
    test rax, rax
    jz opennt_xsu_apc_no_xstate
    mov rsi, rax
    lea rdi, [rbx + {apc_high}]
    mov ecx, 256
    rep movsb
opennt_xsu_apc_no_xstate:
    mov rcx, qword ptr [r15]
    mov rdx, qword ptr [r15 + 8]
    mov r8, qword ptr [r15 + 0x10]
    mov r9, r15
    call qword ptr [r15 + 0x18]
    mov rcx, r15
    lea rdx, [r15 + 0x4F0]
    mov eax, {svc_continue_ex}
    mov r10, rcx
    syscall
    mov dword ptr [rbx + {apc_continue_status}], eax
opennt_xsu_hang4:
    jmp opennt_xsu_hang4

# A rotina da APC: rcx = NormalContext (o bloco de dados), rdx e r8 =
# SystemArgument1 e SystemArgument2, r9 = CONTEXT do frame. Guarda os
# argumentos e sobrescreve os 16 YMM.
opennt_xsu_apc_routine:
    push rdi
    sub rsp, 0x20
    mov qword ptr [rcx + {apc_arguments}], rcx
    mov qword ptr [rcx + {apc_arguments} + 8], rdx
    mov qword ptr [rcx + {apc_arguments} + 16], r8
    mov qword ptr [rcx + {apc_arguments} + 24], r9
    lea rdi, [rcx + {pattern_g}]
    call opennt_xsu_load
    add rsp, 0x20
    pop rdi
    ret

opennt_xsu_load:
    vmovdqu ymm0, [rdi + 0x000]
    vmovdqu ymm1, [rdi + 0x020]
    vmovdqu ymm2, [rdi + 0x040]
    vmovdqu ymm3, [rdi + 0x060]
    vmovdqu ymm4, [rdi + 0x080]
    vmovdqu ymm5, [rdi + 0x0A0]
    vmovdqu ymm6, [rdi + 0x0C0]
    vmovdqu ymm7, [rdi + 0x0E0]
    vmovdqu ymm8, [rdi + 0x100]
    vmovdqu ymm9, [rdi + 0x120]
    vmovdqu ymm10, [rdi + 0x140]
    vmovdqu ymm11, [rdi + 0x160]
    vmovdqu ymm12, [rdi + 0x180]
    vmovdqu ymm13, [rdi + 0x1A0]
    vmovdqu ymm14, [rdi + 0x1C0]
    vmovdqu ymm15, [rdi + 0x1E0]
    ret

opennt_xsu_store:
    vmovdqu [rdi + 0x000], ymm0
    vmovdqu [rdi + 0x020], ymm1
    vmovdqu [rdi + 0x040], ymm2
    vmovdqu [rdi + 0x060], ymm3
    vmovdqu [rdi + 0x080], ymm4
    vmovdqu [rdi + 0x0A0], ymm5
    vmovdqu [rdi + 0x0C0], ymm6
    vmovdqu [rdi + 0x0E0], ymm7
    vmovdqu [rdi + 0x100], ymm8
    vmovdqu [rdi + 0x120], ymm9
    vmovdqu [rdi + 0x140], ymm10
    vmovdqu [rdi + 0x160], ymm11
    vmovdqu [rdi + 0x180], ymm12
    vmovdqu [rdi + 0x1A0], ymm13
    vmovdqu [rdi + 0x1C0], ymm14
    vmovdqu [rdi + 0x1E0], ymm15
    ret

.balign 8
.global opennt_xsu_data
opennt_xsu_data: .quad 0
.global opennt_xsu_end
opennt_xsu_end:
.popsection
"#,
    imp_enabled = const data::IMPORTS,
    imp_length = const data::IMPORTS + 8,
    imp_init = const data::IMPORTS + 16,
    imp_locate = const data::IMPORTS + 24,
    imp_get_mask = const data::IMPORTS + 32,
    imp_set_mask = const data::IMPORTS + 40,
    svc_yield = const YIELD_SERVICE,
    svc_get_context = const GET_CONTEXT_SERVICE,
    svc_continue = const CONTINUE_SERVICE,
    svc_terminate = const TERMINATE_SERVICE,
    svc_queue_apc = const QUEUE_APC_SERVICE,
    svc_continue_ex = const CONTINUE_EX_SERVICE,
    svc_kernel_set = const KERNEL_SET_SERVICE,
    pattern_f = const data::PATTERN_F,
    pattern_g = const data::PATTERN_G,
    pattern_h = const data::PATTERN_H,
    out_f = const data::OUT_F,
    out_h = const data::OUT_H,
    apc_high = const data::APC_HIGH,
    kernel_set_status = const data::KERNEL_SET_STATUS,
    queue_status = const data::QUEUE_STATUS,
    apc_flags = const data::APC_FLAGS,
    apc_length = const data::APC_LENGTH,
    apc_frame = const data::APC_FRAME,
    apc_home5 = const data::APC_HOME5,
    apc_machine_rsp = const data::APC_MACHINE_RSP,
    apc_pointer = const data::APC_POINTER,
    apc_rsp = const data::APC_RSP,
    apc_arguments = const data::APC_ARGUMENTS,
    apc_context_ex = const data::APC_CONTEXT_EX,
    apc_continue_status = const data::APC_CONTINUE_STATUS,
    apc_calls = const data::APC_CALLS,
    apc_argument2 = const APC_ARGUMENT2,
    apc_argument3 = const APC_ARGUMENT3,
    enabled = const data::ENABLED,
    context_length = const data::CONTEXT_LENGTH,
    length_status = const data::LENGTH_STATUS,
    init_status = const data::INIT_STATUS,
    get_status = const data::GET_STATUS,
    context_ex = const data::CONTEXT_EX,
    locate_length = const data::LOCATE_LENGTH,
    exception_flags = const data::EXCEPTION_FLAGS,
    get_pointer = const data::GET_POINTER,
    get_mask = const data::GET_MASK,
    exception_code = const data::EXCEPTION_CODE,
    exception_length = const data::EXCEPTION_LENGTH,
    exception_pointer = const data::EXCEPTION_POINTER,
    exception_mask = const data::EXCEPTION_MASK,
    continue_status = const data::CONTINUE_STATUS,
    pattern_a = const data::PATTERN_A,
    pattern_b = const data::PATTERN_B,
    pattern_c = const data::PATTERN_C,
    pattern_d = const data::PATTERN_D,
    pattern_e = const data::PATTERN_E,
    out_a = const data::OUT_A,
    out_b = const data::OUT_B,
    out_d = const data::OUT_D,
    get_high = const data::GET_HIGH,
    exception_high = const data::EXCEPTION_HIGH,
    context_buffer = const data::CONTEXT_BUFFER,
    get_flags = const GET_FLAGS,
    rounds = const ROUNDS,
    spin = const SPIN,
);

extern "C" {
    static opennt_xsu_start: u8;
    static opennt_xsu_thread2: u8;
    static opennt_xsu_dispatcher: u8;
    static opennt_xsu_apc_dispatcher: u8;
    static opennt_xsu_data: u8;
    static opennt_xsu_end: u8;
}

/// Deslocamento de um rótulo do programa a partir do começo dele.
fn offset(label: &u8) -> u64 {
    // SAFETY: só o endereço do rótulo é usado.
    label as *const u8 as u64 - unsafe { &opennt_xsu_start as *const u8 as u64 }
}

/// Os bytes do programa (independentes de posição).
fn program() -> &'static [u8] {
    // SAFETY: os rótulos delimitam o blob em `.rodata`.
    unsafe {
        let start = &opennt_xsu_start as *const u8;
        core::slice::from_raw_parts(start, (&opennt_xsu_end as *const u8 as usize) - start as usize)
    }
}

fn check(assert: Assert, condition: bool, message: &str) {
    if !condition {
        FAILED.store(true, Ordering::SeqCst);
    }
    assert(condition, message);
}

/// Memória de usuário do processo corrente (`protect`: 0x40 RWX, 4 RW).
fn allocate(size: u64, protect: u32) -> u64 {
    let scratch = guest::alloc_bytes(16);
    if scratch == 0 {
        return 0;
    }
    guest::write64(scratch, 0);
    guest::write64(scratch + 8, size);
    let status = memory::do_user_allocate(scratch, scratch + 8, 0x3000, protect, 0x10000, 0x7FFF_FFFF_0000, 0x10000).unwrap_or(1);
    let base = if status == 0 { guest::read64(scratch) } else { 0 };
    guest::free_bytes(scratch);
    base
}

/// Uma thread de usuário do processo de teste com pilha de kernel própria,
/// TEB e pilha de usuário em `stacks`.
fn user_thread(process: u64, process_id: u64, peb: u64, stacks: u64, start: u64) -> Option<Arc<UserThread>> {
    let stack = kernel_stack::create(false).ok()?;
    let pointer = process::create_kernel_thread(process, cid::ALLOCATE, true, 1, Some(stack)).ok()?;
    // SAFETY: ETHREAD recém-criada, retida pela thread de usuário.
    let ethread = unsafe { Ethread::at(pointer) };
    // GUI: as syscalls da tabela 1 do Shadow vão aos serviços de teste.
    ethread.tcb.set_gui_thread(1);
    let teb = peb_teb::create_teb(&peb_teb::TebDescription { process_id, thread_id: ethread.cid.unique_thread.get(), peb, stack_base: stacks + 0x8000, stack_limit: stacks, deallocation_stack: stacks, current_locale: 0 }).ok()?;
    let thread = UserThread::new(ethread.cid.unique_thread.get(), pointer, teb, start);
    thread.with(|thread| thread.process_pointer = process);
    process::add_thread(process);
    threads::push(thread.clone());
    Some(thread)
}

/// Os bytes da área de dados depois da execução (vazio se não rodou).
fn scenario() -> Option<Vec<u8>> {
    with_test_process("xstate.exe", None, |test| {
        let code_size = (program().len() as u64 + 0xFFF) & !0xFFF;
        let (code, block) = (allocate(code_size, 0x40), allocate(data::SIZE, 4));
        let (first_stacks, second_stacks) = (allocate(0x8000, 4), allocate(0x8000, 4));
        let mut observed = None;
        let ntdll = loader::ntfs_volume().and_then(|volume| volume.read_bytes("/Windows/System32/ntdll.dll").ok().flatten()).and_then(|bytes| pe_loader::load_user(bytes, &LoadOptions { notify_image: false, ..LoadOptions::default() }).ok());
        let ready = code != 0 && block != 0 && first_stacks != 0 && second_stacks != 0;
        if let (true, Some(image)) = (ready, ntdll.as_ref()) {
            guest::write_bytes(code, program());
            // SAFETY: os rótulos do programa.
            let (data_cell, second_entry, dispatcher, apc_dispatcher) = unsafe { (code + offset(&opennt_xsu_data), code + offset(&opennt_xsu_thread2), code + offset(&opennt_xsu_dispatcher), code + offset(&opennt_xsu_apc_dispatcher)) };
            guest::write64(data_cell, block);
            let addresses: Vec<u64> = IMPORTS.iter().map(|name| image.exports.exports.get(*name).copied().unwrap_or(0)).collect();
            for (index, &address) in addresses.iter().enumerate() {
                guest::write64(block + data::IMPORTS + index as u64 * 8, address);
            }
            for (cell, seed) in [(data::PATTERN_A, 0x21), (data::PATTERN_B, 0x42), (data::PATTERN_C, 0x63), (data::PATTERN_D, 0x84), (data::PATTERN_E, 0xA5), (data::PATTERN_F, SEED_F), (data::PATTERN_G, SEED_G), (data::PATTERN_H, SEED_H)] {
                guest::write_bytes(block + cell, &pattern(seed));
            }
            for cell in [data::CONTINUE_STATUS, data::APC_CONTINUE_STATUS, data::KERNEL_SET_STATUS, data::QUEUE_STATUS] {
                guest::write32(block + cell, SENTINEL);
            }
            let first = user_thread(test.process, test.process_id, test.peb, first_stacks, code);
            let second = user_thread(test.process, test.process_id, test.peb, second_stacks, second_entry);
            if let (Some(first), Some(second), true) = (first, second, addresses.iter().all(|&address| address != 0)) {
                let saved_exports = state::with(|state| state.ntdll_exports.clone());
                let exports = [(alloc::string::String::from("KiUserExceptionDispatcher"), dispatcher), (alloc::string::String::from("KiUserApcDispatcher"), apc_dispatcher)];
                state::with(|state| state.ntdll_exports = Some(exports.into_iter().collect()));
                let started = threads::start(&second, second_entry, second_stacks + 0x8000 - 0x28, 0, 0).is_ok();
                let ran = started && threads::run(&first, code, first_stacks + 0x8000 - 0x28, 0, 0).is_ok();
                state::with(|state| state.ntdll_exports = saved_exports);
                if ran {
                    observed = Some(guest::read_bytes(block, data::SIZE as usize));
                }
            }
            threads::release_process(test.process);
            kernel_stack::reap();
        }
        threads::release_process(test.process);
        if let Some(mut image) = ntdll {
            let _ = image.release();
        }
        for base in [code, block, first_stacks, second_stacks] {
            if let Some(region) = memory::find_region(base).filter(|_| base != 0) {
                memory::release_private_region(&region);
            }
        }
        observed
    })
    .flatten()
}

fn read32(bytes: &[u8], offset: u64) -> u32 {
    let offset = offset as usize;
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap_or([0; 4]))
}

fn read64(bytes: &[u8], offset: u64) -> u64 {
    let offset = offset as usize;
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap_or([0; 8]))
}

fn slice(bytes: &[u8], offset: u64, length: usize) -> &[u8] {
    &bytes[offset as usize..offset as usize + length]
}

fn body(assert: Assert) {
    if !usermode::ready() || loader::ntfs_volume().is_none() {
        check(assert, false, "xstate-usuario: anel 3 armado e volume com a ntdll real");
        return;
    }
    if xsave::enabled_features() & xsave::feature::AVX == 0 {
        check(assert, false, "xstate-usuario: AVX habilitado");
        return;
    }
    if threads::all().iter().any(|thread| !thread.dead()) {
        check(assert, false, "xstate-usuario: nenhuma thread de usuario de outro teste viva");
        return;
    }
    let Ok(saved_shadow) = service_table::shadow_second_table() else {
        check(assert, false, "xstate-usuario: descritores de servico publicados");
        return;
    };
    let table = SERVICE_TABLE.as_ptr() as u64;
    let routines: [extern "win64" fn(u64, u64, u64, u64) -> u64; SERVICE_COUNT] = [yield_service, get_context_service, continue_service, terminate_service, queue_apc_service, continue_ex_service, kernel_set_service];
    let mut encoded = true;
    for (slot, routine) in SERVICE_TABLE.iter().zip(routines) {
        match service_table::encode_entry(table, routine as usize as u64, 0) {
            Ok(entry) => slot.store(entry, Ordering::Release),
            Err(_) => encoded = false,
        }
    }
    let published = encoded && SERVICES.iter().all(|name| state::handler(name).is_some()) && service_table::publish_shadow_second_table(table, SERVICE_COUNT as u32, SERVICE_ARGUMENTS.as_ptr() as u64).is_ok();
    let outcome = if published { scenario() } else { None };
    let _ = service_table::restore_shadow_second_table(saved_shadow);
    for slot in &SERVICE_TABLE {
        slot.store(0, Ordering::Release);
    }
    let Some(bytes) = outcome else {
        check(assert, false, "xstate-usuario: duas threads de usuario com a ntdll real rodaram ate o fim pela tabela de servicos de teste");
        return;
    };
    let visible = xsave::enabled_features() | xsave::enabled_user_visible_supervisor_features();
    check(assert, read64(&bytes, data::ENABLED) == visible, "xstate-usuario: RtlGetEnabledExtendedFeatures(-1) da ntdll = EnabledFeatures | supervisor visivel");
    let kept = slice(&bytes, data::OUT_A, YMM_BYTES) == pattern(0x21).as_slice() && slice(&bytes, data::OUT_B, YMM_BYTES) == pattern(0x42).as_slice();
    check(assert, kept, "xstate-usuario: duas threads de usuario mantem os proprios YMM0-YMM15 (256 bits) depois de syscalls e de intervalos encerrados pelo relogio");
    let get_ok = read32(&bytes, data::LENGTH_STATUS) == 0
        && read32(&bytes, data::INIT_STATUS) == 0
        && read32(&bytes, data::GET_STATUS) == 0
        && read64(&bytes, data::GET_POINTER) != 0
        && read32(&bytes, data::LOCATE_LENGTH) == 256
        && slice(&bytes, data::GET_HIGH, 256) == upper_halves(&pattern(0xA5)).as_slice()
        && read64(&bytes, data::GET_MASK) & 4 != 0;
    check(assert, get_ok, "xstate-usuario: NtGetContextThread com CONTEXT_XSTATE num CONTEXT estendido da ntdll; o RtlLocateExtendedFeature acha a metade alta dos YMM e o RtlGetExtendedFeaturesMask tem o AVX");
    let frame_ok = read32(&bytes, data::EXCEPTION_CODE) == 0xC000_001D
        && read32(&bytes, data::EXCEPTION_FLAGS) == 0x10_005F
        && read64(&bytes, data::EXCEPTION_POINTER) != 0
        && read32(&bytes, data::EXCEPTION_LENGTH) == 256
        && slice(&bytes, data::EXCEPTION_HIGH, 256) == upper_halves(&pattern(0x63)).as_slice()
        && read64(&bytes, data::EXCEPTION_MASK) & 4 != 0;
    check(assert, frame_ok, "xstate-usuario: o frame da excecao traz CONTEXT_XSTATE e, pelo RtlLocateExtendedFeature da ntdll, a metade alta dos YMM do momento da falta");
    let round_trip = slice(&bytes, data::OUT_D, YMM_BYTES) == pattern(0x84).as_slice() && read32(&bytes, data::CONTINUE_STATUS) == SENTINEL;
    check(assert, round_trip, "xstate-usuario: o NtContinue com CONTEXT_XSTATE devolve os YMM inteiros que o tratador escreveu no CONTEXT e no pedaco XSTATE");
    let kernel_caller = read32(&bytes, data::KERNEL_SET_STATUS) == 0 && slice(&bytes, data::OUT_H, YMM_BYTES) == mixed(&pattern(SEED_H), &pattern(KERNEL_SEED)).as_slice();
    check(assert, kernel_caller, "xstate-usuario: um CONTEXT de KernelMode com CONTEXT_XSTATE (PspSetContextThreadInternal com KernelMode e UserMode) troca a metade alta dos YMM da thread pela do pedaco do CONTEXT_EX do buffer");
    check(assert, apc_frame_ok(&bytes), "xstate-usuario: o frame da APC especial leva CONTEXT_XSTATE (0x10005B), as flags 2 em P5Home e o pedaco XSTATE alinhado a 64 logo abaixo do RSP interrompido (CONTEXT_EX All, Legacy e XState, MACHINE_FRAME alinhado a 16 abaixo dele)");
    let arguments = read64(&bytes, data::APC_ARGUMENTS);
    let routine_ok = read32(&bytes, data::QUEUE_STATUS) == 0
        && read32(&bytes, data::APC_CALLS) == 1
        && arguments != 0
        && arguments & 0xFFF == 0
        && read64(&bytes, data::APC_ARGUMENTS + 8) == APC_ARGUMENT2 as u64
        && read64(&bytes, data::APC_ARGUMENTS + 16) == APC_ARGUMENT3 as u64
        && read64(&bytes, data::APC_ARGUMENTS + 24) == read64(&bytes, data::APC_FRAME);
    check(assert, routine_ok, "xstate-usuario: a APC especial sai uma vez no retorno do NtQueueApcThreadEx e a rotina recebe NormalContext, SystemArgument1, SystemArgument2 e o CONTEXT do frame");
    let located = read64(&bytes, data::APC_POINTER) != 0 && read32(&bytes, data::APC_LENGTH) == 256 && slice(&bytes, data::APC_HIGH, 256) == upper_halves(&pattern(SEED_F)).as_slice();
    check(assert, located, "xstate-usuario: o RtlLocateExtendedFeature da ntdll acha no pedaco XSTATE do frame da APC a metade alta dos YMM do codigo interrompido");
    let restored = slice(&bytes, data::OUT_F, YMM_BYTES) == pattern(SEED_F).as_slice() && read32(&bytes, data::APC_CONTINUE_STATUS) == SENTINEL;
    check(assert, restored, "xstate-usuario: a rotina da APC especial sobrescreve os 16 YMM e o NtContinueEx do frame devolve os YMM inteiros (a metade alta pelo pedaco XSTATE) ao codigo interrompido");
}

/// O frame da APC especial, pelo que o despachante do programa guardou: o
/// layout do KiInitializeUserApc com o pedaço XSTATE de
/// RtlpGetNonLegacyXStateAreaLength((EnabledFeatures | supervisor visível)
/// sem x87, SSE e CET_U) bytes.
fn apc_frame_ok(bytes: &[u8]) -> bool {
    let (frame, rsp) = (read64(bytes, data::APC_FRAME), read64(bytes, data::APC_RSP));
    let chunk = |index: u64| (read32(bytes, data::APC_CONTEXT_EX + index * 8) as i32, read32(bytes, data::APC_CONTEXT_EX + index * 8 + 4));
    let (all, legacy, xstate) = (chunk(0), chunk(1), chunk(2));
    let mask = (xsave::enabled_features() | xsave::enabled_user_visible_supervisor_features()) & !xsave::feature::LEGACY & !(1 << 11);
    let start = rsp.wrapping_sub(extended_context::non_legacy_xstate_area_length(mask) as u64) & !0x3F;
    let machine = start.wrapping_sub(0x28) & !0xF;
    let header = frame.wrapping_add(CONTEXT_LENGTH as u64).wrapping_add(xstate.0 as i64 as u64);
    rsp != 0
        && read32(bytes, data::APC_FLAGS) == 0x10_005B
        && read64(bytes, data::APC_HOME5) == 2
        && frame == machine.wrapping_sub(0x530)
        && read64(bytes, data::APC_MACHINE_RSP) == rsp
        && all == (-(CONTEXT_LENGTH as i32), rsp.wrapping_sub(frame) as u32)
        && legacy == (-(CONTEXT_LENGTH as i32), CONTEXT_LENGTH)
        && header == start
        && xstate.1 as u64 == rsp.wrapping_sub(start)
}

/// O teste inteiro; `XSTATE_USER_OK` sai só se todas as conferências passarem.
pub fn run(assert: Assert) {
    FAILED.store(false, Ordering::SeqCst);
    body(assert);
    if !FAILED.load(Ordering::SeqCst) {
        crate::debug_print!("XSTATE_USER_OK");
    }
}
