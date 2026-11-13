//! Entradas nativas privadas e corpos x64 próprios — `hal/win32/win32thunk.asm`.
//!
//! As rotinas privadas têm ids próprios (0x80000000+) e nunca entram na EAT;
//! cada stub marca o id e cai no trampolim comum. O ObFindHandleForObject
//! público empresta a tabela viva pelo helper privado real e mantém o
//! contexto do filtro na pilha nativa durante a enumeração.

core::arch::global_asm!(
    r#"
.pushsection .text.win32_private, "ax", @progbits

# ObReferenceProcessHandleTable(process): a mesma sequência do ntoskrnl
# 19041 — RundownProtect (+0x458) pelo ExAcquireRundownProtection (id 277),
# ObjectTable em +0x570 e a liberação (id 278) quando não há tabela. Drivers
# que seguem o primeiro CALL do ObFindHandleForObject leem estes offsets.
.balign 16
.global opennt_ob_reference_process_handle_table
opennt_ob_reference_process_handle_table:
    mov [rsp + 8], rbx
    mov [rsp + 0x10], rsi
    push rdi
    sub rsp, 0x20
    lea rdi, [rcx + 0x458]
    mov rsi, rcx
    mov rcx, rdi
    xor ebx, ebx
    call opennt_win32_stubs + 277 * 10
    test al, al
    je 2f
    mov rbx, [rsi + 0x570]
    test rbx, rbx
    je 3f
2:
    mov rsi, [rsp + 0x38]
    mov rax, rbx
    mov rbx, [rsp + 0x30]
    add rsp, 0x20
    pop rdi
    ret
3:
    mov rcx, rdi
    call opennt_win32_stubs + 278 * 10
    jmp 2b

# HalPrivateDispatchTable: um stub de dez bytes por slot (id 0x80000100 +
# slot), no formato dos trampolins públicos, e os inicializadores padrão do
# kernel para os slots que a HAL não grava.
.balign 16
.global opennt_hal_private_stubs
opennt_hal_private_stubs:
.set opennt_hal_slot, 0
.rept 149
    .byte 0xB8
    .long 0x80000100 + opennt_hal_slot
    .byte 0xE9
    .long opennt_win32_common - . - 4
    .set opennt_hal_slot, opennt_hal_slot + 1
.endr

.balign 16
.global opennt_hal_default_zero
opennt_hal_default_zero:
    xor eax, eax
    ret
.balign 16
.global opennt_hal_default_not_supported
opennt_hal_default_not_supported:
    mov eax, 0xC00000BB
    ret
.balign 16
.global opennt_hal_default_void
opennt_hal_default_void:
    ret
.balign 16
.global opennt_hal_default_true
opennt_hal_default_true:
    mov al, 1
    ret
.balign 16
.global opennt_hal_default_false
opennt_hal_default_false:
    xor al, al
    ret
.balign 16
.global opennt_hal_default_vector_identity
opennt_hal_default_vector_identity:
    mov al, cl
    ret
.balign 16
.global opennt_hal_default_ulong_identity
opennt_hal_default_ulong_identity:
    mov eax, ecx
    ret
# xHalProcessorHalt: para no depurador e informa que não há suporte.
.balign 16
.global opennt_hal_default_processor_halt
opennt_hal_default_processor_halt:
    int3
    mov eax, 0xC00000BB
    ret

# Callback privado entregue à CI; fica fora da tabela pública de exports.
.balign 16
.global opennt_mm_get_image_file_signature_information
opennt_mm_get_image_file_signature_information:
    mov eax, 0x80000009
    jmp opennt_win32_common

.balign 16
.global opennt_psp_context_operation_apc
opennt_psp_context_operation_apc:
    mov eax, 0x80000004
    jmp opennt_win32_common

.balign 16
.global opennt_psp_context_operation_rundown
opennt_psp_context_operation_rundown:
    mov eax, 0x80000005
    jmp opennt_win32_common

# PsSetContextThread: o contrato MS x64 público encaminha o modo de entrada
# como modo de contexto; o CALL executa a operação privada real.
.balign 16
.global opennt_ps_set_context_thread
opennt_ps_set_context_thread:
    sub rsp, 0x38
    mov r9b, r8b
    mov dword ptr [rsp + 0x20], 1
    call opennt_psp_set_context_thread_internal
    add rsp, 0x38
    ret

.balign 16
.global opennt_psp_set_context_thread_internal
opennt_psp_set_context_thread_internal:
    mov eax, 0x80000006
    jmp opennt_win32_common

.balign 16
.global opennt_ob_find_handle_filter
opennt_ob_find_handle_filter:
    mov eax, 0x80000008
    jmp opennt_win32_common

# ObFindHandleForObject(process, object, type, handleInformation, handle):
# a sequência do ntoskrnl 19041, registrador a registrador — contexto de
# três ponteiros em [rsp+0x20] (cabeçalho, tipo, informação), quinto
# argumento em [rsp+0x70], ExEnumHandleTable (id 715) e a liberação da
# RundownProtect com `lea rcx, [rsi + 0x458]` (id 278).
.balign 16
.global opennt_ob_find_handle_for_object
opennt_ob_find_handle_for_object:
    mov rax, rsp
    mov [rax + 8], rbx
    mov [rax + 0x10], rbp
    mov [rax + 0x18], rsi
    mov [rax + 0x20], rdi
    push r14
    sub rsp, 0x40
    mov rbp, r9
    mov r14, r8
    mov rdi, rdx
    mov rsi, rcx
    xor ebx, ebx
    call opennt_ob_reference_process_handle_table
    mov rcx, rax
    test rax, rax
    je 3f
    test rdi, rdi
    je 4f
    lea rax, [rdi - 0x30]
    mov [rsp + 0x20], rax
2:
    mov r9, [rsp + 0x70]
    lea r8, [rsp + 0x20]
    lea rdx, [rip + opennt_ob_find_handle_filter]
    mov [rsp + 0x28], r14
    mov [rsp + 0x30], rbp
    call opennt_win32_stubs + 715 * 10
    test al, al
    movzx ebx, bl
    mov edx, 1
    lea rcx, [rsi + 0x458]
    cmovne ebx, edx
    call opennt_win32_stubs + 278 * 10
3:
    mov rbp, [rsp + 0x58]
    mov al, bl
    mov rbx, [rsp + 0x50]
    mov rsi, [rsp + 0x60]
    mov rdi, [rsp + 0x68]
    add rsp, 0x40
    pop r14
    ret
4:
    mov [rsp + 0x20], rbx
    jmp 2b

# __chkstk (`hal/win32/stack-probe.asm`): ABI própria, RAX é o tamanho e
# volta intacto; só R10, R11 e flags mudam (RCX e os demais argumentos
# sobrevivem). Rotina folha sem mudar RSP nem registro de unwind; cada
# página é tocada por leitura para entregar páginas guardadas ao fault.
.balign 16
.global opennt_probe_kernel_stack
opennt_probe_kernel_stack:
    lea r11, [rsp + 8]
    mov r10, r11
    sub r10, rax
    jae opennt_probe_kernel_stack_target
    xor r10d, r10d
opennt_probe_kernel_stack_target:
    and r10, -4096
    and r11, -4096
opennt_probe_kernel_stack_next:
    cmp r11, r10
    jbe opennt_probe_kernel_stack_done
    sub r11, 4096
    test byte ptr [r11], 0
    jmp opennt_probe_kernel_stack_next
opennt_probe_kernel_stack_done:
    ret

# DbgPrompt público: a CPU executa a interrupção real do serviço de
# depuração. Corpo folha sem registro de unwind (o SEH recupera o chamador
# por [RSP]); a ABI do serviço leva comprimentos USHORT, como medido.
.balign 16
.global opennt_dbg_prompt
opennt_dbg_prompt:
    mov r9d, r8d
    mov r8, rdx
    xor edx, edx
opennt_dbg_prompt_length:
    cmp byte ptr [rcx + rdx], 0
    je opennt_dbg_prompt_service
    inc rdx
    jmp opennt_dbg_prompt_length
opennt_dbg_prompt_service:
    movzx edx, dx
    movzx r9d, r9w
    mov eax, 2
.global opennt_dbg_prompt_interrupt
opennt_dbg_prompt_interrupt:
    int 0x2d
    int3
    ret

.popsection
"#
);

extern "C" {
    static opennt_psp_context_operation_apc: u8;
    static opennt_psp_context_operation_rundown: u8;
    static opennt_ps_set_context_thread: u8;
    static opennt_psp_set_context_thread_internal: u8;
    static opennt_ob_reference_process_handle_table: u8;
    static opennt_ob_find_handle_filter: u8;
    static opennt_ob_find_handle_for_object: u8;
    static opennt_dbg_prompt: u8;
    static opennt_probe_kernel_stack: u8;
    static opennt_mm_get_image_file_signature_information: u8;
    static opennt_hal_private_stubs: u8;
    static opennt_hal_default_zero: u8;
    static opennt_hal_default_not_supported: u8;
    static opennt_hal_default_void: u8;
    static opennt_hal_default_true: u8;
    static opennt_hal_default_false: u8;
    static opennt_hal_default_vector_identity: u8;
    static opennt_hal_default_ulong_identity: u8;
    static opennt_hal_default_processor_halt: u8;
}

/// Ids públicos fixados nos corpos do ObFindHandleForObject e do
/// ObReferenceProcessHandleTable.
pub const ACQUIRE_RUNDOWN_ID: u64 = 277;
pub const ENUM_HANDLES_ID: u64 = 715;
pub const RELEASE_RUNDOWN_ID: u64 = 278;

/// Endereço físico (identidade) de um símbolo privado ou corpo nativo.
pub fn entry(symbol: &str) -> Option<u64> {
    let address = {
        match symbol {
            "PspContextOperationApc" => core::ptr::addr_of!(opennt_psp_context_operation_apc),
            "PspContextOperationRundown" => core::ptr::addr_of!(opennt_psp_context_operation_rundown),
            "PspSetContextThreadInternal" => core::ptr::addr_of!(opennt_psp_set_context_thread_internal),
            "ps_set_context_thread" => core::ptr::addr_of!(opennt_ps_set_context_thread),
            "ObReferenceProcessHandleTable" => core::ptr::addr_of!(opennt_ob_reference_process_handle_table),
            "ObpFindHandleForObject" => core::ptr::addr_of!(opennt_ob_find_handle_filter),
            "ob_find_handle_for_object" => core::ptr::addr_of!(opennt_ob_find_handle_for_object),
            "dbg_prompt" => core::ptr::addr_of!(opennt_dbg_prompt),
            "probe_kernel_stack" => core::ptr::addr_of!(opennt_probe_kernel_stack),
            "MmGetImageFileSignatureInformation" => core::ptr::addr_of!(opennt_mm_get_image_file_signature_information),
            "hal_private_stubs" => core::ptr::addr_of!(opennt_hal_private_stubs),
            "hal_default_zero" => core::ptr::addr_of!(opennt_hal_default_zero),
            "hal_default_not_supported" => core::ptr::addr_of!(opennt_hal_default_not_supported),
            "hal_default_void" => core::ptr::addr_of!(opennt_hal_default_void),
            "hal_default_true" => core::ptr::addr_of!(opennt_hal_default_true),
            "hal_default_false" => core::ptr::addr_of!(opennt_hal_default_false),
            "hal_default_vector_identity" => core::ptr::addr_of!(opennt_hal_default_vector_identity),
            "hal_default_ulong_identity" => core::ptr::addr_of!(opennt_hal_default_ulong_identity),
            "hal_default_processor_halt" => core::ptr::addr_of!(opennt_hal_default_processor_halt),
            _ => return None,
        }
    };
    Some(address as u64)
}
