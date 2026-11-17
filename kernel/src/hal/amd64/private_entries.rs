//! Entradas nativas privadas e corpos x64 próprios.
//!
//! As rotinas privadas têm ids próprios (0x80000000+) e nunca entram na EAT;
//! cada stub marca o id e cai no trampolim comum. O ObFindHandleForObject
//! público empresta a tabela viva pelo helper privado real e mantém o
//! contexto do filtro na pilha nativa durante a enumeração. Os corpos que
//! drivers acham pelos bytes (o KeAllocateProcessorProfileStructures na
//! `.text` e os chamadores privados na seção PAGE) repetem a sequência do
//! ntoskrnl 19041 até o CALL que leva à rotina não exportada.

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

# Rotina de cancelamento que IoCsqInsertIrp(Ex) põe nos IRPs da fila.
.balign 16
.global opennt_iop_csq_cancel_routine
opennt_iop_csq_cancel_routine:
    mov eax, 0x8000000A
    jmp opennt_win32_common

# Rotina de conclusão que IoSetCompletionRoutineEx instala no IRP.
.balign 16
.global opennt_iop_unload_safe_completion
opennt_iop_unload_safe_completion:
    mov eax, 0x8000000B
    jmp opennt_win32_common

# Callback do pacote embutido numa reserva de conclusão de E/S.
.balign 16
.global opennt_psp_io_mini_packet_callback_routine
opennt_psp_io_mini_packet_callback_routine:
    mov eax, 0x8000000C
    jmp opennt_win32_common

# KernelRoutine da APC de um objeto Timer e DeleteProcedure do tipo Timer.
.balign 16
.global opennt_exp_timer_apc_routine
opennt_exp_timer_apc_routine:
    mov eax, 0x8000000D
    jmp opennt_win32_common

.balign 16
.global opennt_exp_delete_timer
opennt_exp_delete_timer:
    mov eax, 0x8000000E
    jmp opennt_win32_common

# CloseProcedure e DeleteProcedure do tipo Job.
.balign 16
.global opennt_psp_job_close
opennt_psp_job_close:
    mov eax, 0x8000000F
    jmp opennt_win32_common

.balign 16
.global opennt_psp_job_delete
opennt_psp_job_delete:
    mov eax, 0x80000010
    jmp opennt_win32_common

# As rotinas dos tipos de objeto Win32 (ExpWin32*Procedure).
.balign 16
.global opennt_exp_win32_open_procedure
opennt_exp_win32_open_procedure:
    mov eax, 0x80000011
    jmp opennt_win32_common

.balign 16
.global opennt_exp_win32_okay_to_close_procedure
opennt_exp_win32_okay_to_close_procedure:
    mov eax, 0x80000012
    jmp opennt_win32_common

.balign 16
.global opennt_exp_win32_close_procedure
opennt_exp_win32_close_procedure:
    mov eax, 0x80000013
    jmp opennt_win32_common

.balign 16
.global opennt_exp_win32_delete_procedure
opennt_exp_win32_delete_procedure:
    mov eax, 0x80000014
    jmp opennt_win32_common

.balign 16
.global opennt_exp_win32_parse_procedure
opennt_exp_win32_parse_procedure:
    mov eax, 0x80000015
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
# argumento em [rsp+0x70], ExEnumHandleTable (id 709) e a liberação da
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
    call opennt_win32_stubs + 709 * 10
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

# DbgBreakPoint público: o corpo do ntoskrnl 19041 (`int 3; ret`). Folha sem
# registro de unwind; o despacho de exceções acha o chamador por [RSP].
.balign 16
.global opennt_dbg_break_point
opennt_dbg_break_point:
    int3
    ret

# sqrtf público (CRT): argumento e resultado em XMM0. O sqrtf do ntoskrnl
# 19041 desvia NaN e negativos para o tratamento de erro da CRT, que com as
# exceções de ponto flutuante mascaradas devolve o mesmo valor que o SQRTSS
# (NaN silenciado; 0xFFC00000 para negativo); o resto é o próprio SQRTSS.
.balign 16
.global opennt_crt_sqrtf
opennt_crt_sqrtf:
    sqrtss xmm0, xmm0
    ret

# DbgCommandString(Name, Command): os STRING (Length, 0, Buffer) do nome
# (rsp+0x30) e do comando (rsp+0x20) e o serviço de depuração 5
# (BREAKPOINT_COMMAND_STRING) com rcx = &nome e rdx = &comando, como o
# DebugService2; sem KD, o serviço volta depois do int3 que o segue.
.balign 16
.global opennt_dbg_command_string
opennt_dbg_command_string:
    sub rsp, 0x48
    xor eax, eax
    mov qword ptr [rsp + 0x30], rax
    mov qword ptr [rsp + 0x38], rcx
    mov qword ptr [rsp + 0x20], rax
    mov qword ptr [rsp + 0x28], rdx
    or r8, -1
2:
    inc r8
    cmp byte ptr [rcx + r8], 0
    jne 2b
    mov word ptr [rsp + 0x30], r8w
    or rax, -1
3:
    inc rax
    cmp byte ptr [rdx + rax], 0
    jne 3b
    mov word ptr [rsp + 0x20], ax
    lea rcx, [rsp + 0x30]
    lea rdx, [rsp + 0x20]
    mov eax, 5
    int 0x2d
    int3
    add rsp, 0x48
    ret

.popsection
"#
);

// Corpos que drivers acham pelos bytes, como no ntoskrnl 19041: o driver
// segue um CALL conhecido para chegar a rotinas que o ntoskrnl não exporta
// (MmAllocateIndependentPages, MmFreeIndependentPages e
// PsEnumProcessThreads). Cada trecho até o CALL repete byte a byte a
// sequência do ntoskrnl real, menos os deslocamentos relativos; por isso vai
// em `.byte`, com o mnemônico ao lado (o montador escolheria outras
// codificações para os mesmos mnemônicos). Depois do CALL, o corpo é o do
// OpenNT. As três rotinas e os chamadores privados ficam na seção PAGE, como
// no ntoskrnl; o KeAllocateProcessorProfileStructures fica na `.text`.
core::arch::global_asm!(
    r#"
.pushsection .rodata.opennt_ke_state, "a", @progbits
# KiIrqlFlags: o OpenNT não liga o rastreio de IRQL do SchedulerAssist.
.balign 4
opennt_ki_irql_flags:
    .long 0
# KiKvaShadow: o OpenNT não separa as tabelas de kernel e de usuário.
opennt_ki_kva_shadow:
    .byte 0
.popsection

.pushsection .text.win32_private, "ax", @progbits

# KeAllocateProcessorProfileStructures(ProcessorCount, BufferSize,
# ProfileStructures, Allocate), ntoskrnl 19041 rva 0x3b5e70.
# Allocate = FALSE: em DISPATCH_LEVEL, a PRCB corrente recebe
# *ProfileStructures em ProcessorProfileControlArea (+0x8498) e o endereço
# do PebsIndex (+0x28) em ProfileEventIndexAddress (+0x84a0).
# Allocate = TRUE: uma alocação de páginas independentes com
# ProcessorCount * BufferSize bytes de buffers seguidos de ProcessorCount
# PROCESSOR_PROFILE_CONTROL_AREA de 0xA0 bytes (sem KVA shadow, o tamanho
# vai sem arredondar), zerada; com PEBS (KiIsIntelPebsSupported: CPU Intel
# e IA32_MISC_ENABLE com o monitoramento de desempenho e sem o bit de PEBS
# indisponível) e sem área já instalada na PRCB, cada PebsBufferBase (+0x20)
# aponta para o seu buffer e *ProfileStructures recebe a primeira área.
# Senão a alocação volta: STATUS_NOT_SUPPORTED, ou
# STATUS_ADDRESS_ALREADY_EXISTS com a área instalada em *ProfileStructures;
# sem memória, STATUS_NO_MEMORY. O CALL de +0xc6 é o que drivers seguem.
.balign 16
.global opennt_ke_allocate_processor_profile_structures
opennt_ke_allocate_processor_profile_structures:
    .byte 0x48, 0x89, 0x54, 0x24, 0x10             # +0x00 mov [rsp + 0x10], rdx
    .byte 0x89, 0x4C, 0x24, 0x08                   # +0x05 mov [rsp + 8], ecx
    .byte 0x53                                     # +0x09 push rbx
    .byte 0x56                                     # +0x0a push rsi
    .byte 0x57                                     # +0x0b push rdi
    .byte 0x41, 0x54                               # +0x0c push r12
    .byte 0x41, 0x55                               # +0x0e push r13
    .byte 0x41, 0x56                               # +0x10 push r14
    .byte 0x41, 0x57                               # +0x12 push r15
    .byte 0x48, 0x83, 0xEC, 0x20                   # +0x14 sub rsp, 0x20
    .byte 0x4D, 0x8B, 0xF0                         # +0x18 mov r14, r8
    .byte 0x8B, 0xC1                               # +0x1b mov eax, ecx
    .byte 0x44, 0x0F, 0x20, 0xC7                   # +0x1d mov rdi, cr8
    .byte 0x45, 0x33, 0xD2                         # +0x21 xor r10d, r10d
    .byte 0x45, 0x84, 0xC9                         # +0x24 test r9b, r9b
    .byte 0x75, 0x64                               # +0x27 jne +0x8d
    .byte 0x41, 0x8D, 0x52, 0x02                   # +0x29 lea edx, [r10 + 2]
    .byte 0x44, 0x0F, 0x22, 0xC2                   # +0x2d mov cr8, rdx
    .byte 0x8B, 0x05                               # +0x31 mov eax, [rip + KiIrqlFlags]
    .long opennt_ki_irql_flags - . - 4
    .byte 0x49, 0x83, 0xCF, 0xFF                   # +0x37 or r15, -1
    .byte 0x85, 0xC0                               # +0x3b test eax, eax
    # +0x3d jne (SchedulerAssist); sem o rastreio, o desvio cai em +0x43.
    .byte 0x0F, 0x85
    .long 0
    .byte 0x65, 0x48, 0x8B, 0x0C, 0x25, 0x20, 0x00, 0x00, 0x00  # +0x43 mov rcx, gs:[0x20]
    .byte 0x49, 0x8B, 0x06                         # +0x4c mov rax, [r14]
    .byte 0x48, 0x89, 0x81, 0x98, 0x84, 0x00, 0x00 # +0x4f mov [rcx + 0x8498], rax
    .byte 0x49, 0x8B, 0x06                         # +0x56 mov rax, [r14]
    .byte 0x48, 0x83, 0xC0, 0x28                   # +0x59 add rax, 0x28
    .byte 0x48, 0x89, 0x81, 0xA0, 0x84, 0x00, 0x00 # +0x5d mov [rcx + 0x84a0], rax
    .byte 0x8B, 0x05                               # +0x64 mov eax, [rip + KiIrqlFlags]
    .long opennt_ki_irql_flags - . - 4
    .byte 0x85, 0xC0                               # +0x6a test eax, eax
    # +0x6c jne (SchedulerAssist); sem o rastreio, o desvio cai em +0x72.
    .byte 0x0F, 0x85
    .long 0
    .byte 0x40, 0x0F, 0xB6, 0xC7                   # +0x72 movzx eax, dil
    .byte 0x44, 0x0F, 0x22, 0xC0                   # +0x76 mov cr8, rax
    .byte 0x33, 0xC0                               # +0x7a xor eax, eax
opennt_ke_profile_epilogue:
    .byte 0x48, 0x83, 0xC4, 0x20                   # +0x7c add rsp, 0x20
    .byte 0x41, 0x5F                               # +0x80 pop r15
    .byte 0x41, 0x5E                               # +0x82 pop r14
    .byte 0x41, 0x5D                               # +0x84 pop r13
    .byte 0x41, 0x5C                               # +0x86 pop r12
    .byte 0x5F                                     # +0x88 pop rdi
    .byte 0x5E                                     # +0x89 pop rsi
    .byte 0x5B                                     # +0x8a pop rbx
    .byte 0xC3                                     # +0x8b ret
    .byte 0xCC                                     # +0x8c int3
    .byte 0x4C, 0x8B, 0xE8                         # +0x8d mov r13, rax
    .byte 0x4D, 0x89, 0x10                         # +0x90 mov [r8], r10
    .byte 0x4C, 0x0F, 0xAF, 0xEA                   # +0x93 imul r13, rdx
    .byte 0x48, 0x8D, 0x34, 0x80                   # +0x97 lea rsi, [rax + rax*4]
    .byte 0x44, 0x88, 0x54, 0x24, 0x78             # +0x9b mov [rsp + 0x78], r10b
    .byte 0x48, 0xC1, 0xE6, 0x05                   # +0xa0 shl rsi, 5
    .byte 0x4C, 0x8B, 0xE0                         # +0xa4 mov r12, rax
    .byte 0x49, 0x03, 0xF5                         # +0xa7 add rsi, r13
    .byte 0x44, 0x38, 0x15                         # +0xaa cmp [rip + KiKvaShadow], r10b
    .long opennt_ki_kva_shadow - . - 4
    .byte 0x74, 0x0E                               # +0xb1 je +0xc1
    .byte 0x48, 0x81, 0xC6, 0xFF, 0x0F, 0x00, 0x00 # +0xb3 add rsi, 0xfff
    .byte 0x48, 0x81, 0xE6, 0x00, 0xF0, 0xFF, 0xFF # +0xba and rsi, -0x1000
    .byte 0x33, 0xD2                               # +0xc1 xor edx, edx
    .byte 0x48, 0x8B, 0xCE                         # +0xc3 mov rcx, rsi
    .byte 0xE8                                     # +0xc6 call MmAllocateIndependentPages
    .long opennt_mm_allocate_independent_pages - . - 4
    mov rbx, rax
    test rbx, rbx
    je 5f
    # memset(buffer, 0, tamanho).
    mov rdi, rbx
    mov rcx, rsi
    xor eax, eax
    rep stosb
    lea r10, [rbx + r13]
    mov rdi, cr8
    mov eax, 2
    mov cr8, rax
    mov r8, gs:[0x20]
    # KiIsIntelPebsSupported(Prcb): CpuVendor (+0x8d) CPU_INTEL e, no
    # IA32_MISC_ENABLE (0x1a0), bit 7 ligado e bit 12 desligado.
    cmp byte ptr [r8 + 0x8d], 2
    jne 6f
    mov ecx, 0x1a0
    rdmsr
    shl rdx, 32
    or rax, rdx
    and eax, 0x1080
    cmp rax, 0x80
    jne 6f
    mov rax, [r8 + 0x8498]
    test rax, rax
    jne 7f
    cmp dword ptr [rsp + 0x60], eax
    jbe 3f
    mov rcx, [rsp + 0x68]
    lea rax, [r10 + 0x20]
2:
    mov [rax], rbx
    add rbx, rcx
    lea rax, [rax + 0xa0]
    sub r12, 1
    jne 2b
3:
    xor ebx, ebx
    mov [r14], r10
    xor r14d, r14d
4:
    movzx eax, dil
    mov cr8, rax
    test rbx, rbx
    jne 8f
9:
    mov eax, r14d
    jmp opennt_ke_profile_epilogue
5:
    mov r14d, 0xC0000017
    jmp 4b
6:
    mov r14d, 0xC00000BB
    jmp 4b
7:
    mov [r14], rax
    mov r14d, 0xC000020A
    jmp 4b
8:
    mov rdx, rsi
    mov rcx, rbx
    call opennt_mm_free_independent_pages
    jmp 9b

.popsection

.pushsection .text.page, "ax", @progbits

# As três rotinas privadas: o stub marca o id e cai no trampolim comum.
.balign 16
.global opennt_mm_allocate_independent_pages
opennt_mm_allocate_independent_pages:
    mov eax, 0x80000000
    jmp opennt_win32_common

.balign 16
.global opennt_mm_free_independent_pages
opennt_mm_free_independent_pages:
    mov eax, 0x80000001
    jmp opennt_win32_common

.balign 16
.global opennt_ps_enum_process_threads
opennt_ps_enum_process_threads:
    mov eax, 0x80000002
    jmp opennt_win32_common

# MmFreeIsrStack(StackTop), rva 0x8d11c8: a pilha de ISR são 0x6000 bytes
# abaixo do topo e uma página de guarda abaixo deles (MmAllocateIsrStack).
# As páginas da pilha voltam pelo MmFreeIndependentPages; a guarda, pela
# rotina privada que devolve a sua VA (o MiReleasePtes do PTE da guarda).
.balign 16
.global opennt_mm_free_isr_stack
opennt_mm_free_isr_stack:
    .byte 0x40, 0x53                               # +0x00 push rbx
    .byte 0x48, 0x83, 0xEC, 0x20                   # +0x02 sub rsp, 0x20
    .byte 0x48, 0x8D, 0x99, 0x00, 0xA0, 0xFF, 0xFF # +0x06 lea rbx, [rcx - 0x6000]
    .byte 0xBA, 0x00, 0x60, 0x00, 0x00             # +0x0d mov edx, 0x6000
    .byte 0x48, 0x8B, 0xCB                         # +0x12 mov rcx, rbx
    .byte 0xE8                                     # +0x15 call MmFreeIndependentPages
    .long opennt_mm_free_independent_pages - . - 4
    lea rcx, [rbx - 0x1000]
    call opennt_mi_release_boot_guard_page
    add rsp, 0x20
    pop rbx
    ret

.balign 16
.global opennt_mi_release_boot_guard_page
opennt_mi_release_boot_guard_page:
    mov eax, 0x80000018
    jmp opennt_win32_common

# PopUpdateSingleProcessHeteroPolicies(Process), rva 0x8f1440: a rotina
# inteira, com o callback 0x30 bytes adiante (o `lea rdx, [rip + 0x22]`).
.balign 16
.global opennt_pop_update_single_process_hetero_policies
opennt_pop_update_single_process_hetero_policies:
    .byte 0x48, 0x83, 0xEC, 0x28                   # +0x00 sub rsp, 0x28
    .byte 0x45, 0x33, 0xC0                         # +0x04 xor r8d, r8d
    .byte 0x48, 0x8D, 0x15                         # +0x07 lea rdx, [rip + callback]
    .long opennt_pop_update_single_thread_hetero_policies - . - 4
    .byte 0xE8                                     # +0x0e call PsEnumProcessThreads
    .long opennt_ps_enum_process_threads - . - 4
    .byte 0x33, 0xC0                               # +0x13 xor eax, eax
    .byte 0x48, 0x83, 0xC4, 0x28                   # +0x15 add rsp, 0x28
    .byte 0xC3                                     # +0x19 ret
    .fill 22, 1, 0xCC                              # +0x1a int3 até +0x30

# PopUpdateSingleThreadHeteroPolicies(Process, Thread, Context), +0x30.
.global opennt_pop_update_single_thread_hetero_policies
opennt_pop_update_single_thread_hetero_policies:
    mov eax, 0x80000016
    jmp opennt_win32_common

# EtwpProcessEnumCallback(Process, Context): com o grupo de threads pedido
# (bit 2 da máscara apontada por Context), as threads do processo passam
# pelo EtwpThreadEnumCallback. A chamada repete a do ntoskrnl em +0x12e
# (mov r8, rsi; lea rdx, [rip + EtwpThreadEnumCallback]; mov rcx, rbx; call).
.balign 16
.global opennt_etwp_process_enum_callback
opennt_etwp_process_enum_callback:
    push rbx
    push rsi
    sub rsp, 0x28
    mov rbx, rcx
    mov rsi, rdx
    mov rax, [rdx]
    test rax, rax
    je 2f
    test byte ptr [rax], 2
    je 2f
    .byte 0x4C, 0x8B, 0xC6                         # mov r8, rsi
    .byte 0x48, 0x8D, 0x15                         # lea rdx, [rip + EtwpThreadEnumCallback]
    .long opennt_etwp_thread_enum_callback - . - 4
    .byte 0x48, 0x8B, 0xCB                         # mov rcx, rbx
    .byte 0xE8                                     # call PsEnumProcessThreads
    .long opennt_ps_enum_process_threads - . - 4
2:
    xor eax, eax
    add rsp, 0x28
    pop rsi
    pop rbx
    ret

.balign 16
.global opennt_etwp_thread_enum_callback
opennt_etwp_thread_enum_callback:
    mov eax, 0x80000017
    jmp opennt_win32_common

.popsection
"#
);

extern "C" {
    static opennt_ke_allocate_processor_profile_structures: u8;
    static opennt_mm_allocate_independent_pages: u8;
    static opennt_mm_free_independent_pages: u8;
    static opennt_ps_enum_process_threads: u8;
    static opennt_mm_free_isr_stack: u8;
    static opennt_mi_release_boot_guard_page: u8;
    static opennt_pop_update_single_process_hetero_policies: u8;
    static opennt_pop_update_single_thread_hetero_policies: u8;
    static opennt_etwp_process_enum_callback: u8;
    static opennt_etwp_thread_enum_callback: u8;
    static opennt_psp_context_operation_apc: u8;
    static opennt_psp_context_operation_rundown: u8;
    static opennt_ps_set_context_thread: u8;
    static opennt_psp_set_context_thread_internal: u8;
    static opennt_ob_reference_process_handle_table: u8;
    static opennt_ob_find_handle_filter: u8;
    static opennt_ob_find_handle_for_object: u8;
    static opennt_dbg_prompt: u8;
    static opennt_dbg_break_point: u8;
    static opennt_crt_sqrtf: u8;
    static opennt_dbg_command_string: u8;
    static opennt_probe_kernel_stack: u8;
    static opennt_mm_get_image_file_signature_information: u8;
    static opennt_iop_csq_cancel_routine: u8;
    static opennt_iop_unload_safe_completion: u8;
    static opennt_psp_io_mini_packet_callback_routine: u8;
    static opennt_exp_timer_apc_routine: u8;
    static opennt_exp_delete_timer: u8;
    static opennt_psp_job_close: u8;
    static opennt_psp_job_delete: u8;
    static opennt_exp_win32_open_procedure: u8;
    static opennt_exp_win32_okay_to_close_procedure: u8;
    static opennt_exp_win32_close_procedure: u8;
    static opennt_exp_win32_delete_procedure: u8;
    static opennt_exp_win32_parse_procedure: u8;
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
pub const ENUM_HANDLES_ID: u64 = 709;
pub const RELEASE_RUNDOWN_ID: u64 = 278;

/// Endereço (VA na imagem do kernel) de um símbolo privado ou corpo nativo.
pub fn entry(symbol: &str) -> Option<u64> {
    let address = {
        match symbol {
            "ke_allocate_processor_profile_structures" => core::ptr::addr_of!(opennt_ke_allocate_processor_profile_structures),
            "MmAllocateIndependentPages" => core::ptr::addr_of!(opennt_mm_allocate_independent_pages),
            "MmFreeIndependentPages" => core::ptr::addr_of!(opennt_mm_free_independent_pages),
            "PsEnumProcessThreads" => core::ptr::addr_of!(opennt_ps_enum_process_threads),
            "MmFreeIsrStack" => core::ptr::addr_of!(opennt_mm_free_isr_stack),
            "MiReleaseBootGuardPage" => core::ptr::addr_of!(opennt_mi_release_boot_guard_page),
            "PopUpdateSingleProcessHeteroPolicies" => core::ptr::addr_of!(opennt_pop_update_single_process_hetero_policies),
            "PopUpdateSingleThreadHeteroPolicies" => core::ptr::addr_of!(opennt_pop_update_single_thread_hetero_policies),
            "EtwpProcessEnumCallback" => core::ptr::addr_of!(opennt_etwp_process_enum_callback),
            "EtwpThreadEnumCallback" => core::ptr::addr_of!(opennt_etwp_thread_enum_callback),
            "PspContextOperationApc" => core::ptr::addr_of!(opennt_psp_context_operation_apc),
            "PspContextOperationRundown" => core::ptr::addr_of!(opennt_psp_context_operation_rundown),
            "PspSetContextThreadInternal" => core::ptr::addr_of!(opennt_psp_set_context_thread_internal),
            "ps_set_context_thread" => core::ptr::addr_of!(opennt_ps_set_context_thread),
            "ObReferenceProcessHandleTable" => core::ptr::addr_of!(opennt_ob_reference_process_handle_table),
            "ObpFindHandleForObject" => core::ptr::addr_of!(opennt_ob_find_handle_filter),
            "ob_find_handle_for_object" => core::ptr::addr_of!(opennt_ob_find_handle_for_object),
            "dbg_prompt" => core::ptr::addr_of!(opennt_dbg_prompt),
            "dbg_break_point" => core::ptr::addr_of!(opennt_dbg_break_point),
            "crt_sqrtf" => core::ptr::addr_of!(opennt_crt_sqrtf),
            "dbg_command_string" => core::ptr::addr_of!(opennt_dbg_command_string),
            "probe_kernel_stack" => core::ptr::addr_of!(opennt_probe_kernel_stack),
            "MmGetImageFileSignatureInformation" => core::ptr::addr_of!(opennt_mm_get_image_file_signature_information),
            "IopCsqCancelRoutine" => core::ptr::addr_of!(opennt_iop_csq_cancel_routine),
            "IopUnloadSafeCompletion" => core::ptr::addr_of!(opennt_iop_unload_safe_completion),
            "PspIoMiniPacketCallbackRoutine" => core::ptr::addr_of!(opennt_psp_io_mini_packet_callback_routine),
            "ExpTimerApcRoutine" => core::ptr::addr_of!(opennt_exp_timer_apc_routine),
            "ExpDeleteTimer" => core::ptr::addr_of!(opennt_exp_delete_timer),
            "PspJobClose" => core::ptr::addr_of!(opennt_psp_job_close),
            "PspJobDelete" => core::ptr::addr_of!(opennt_psp_job_delete),
            "ExpWin32OpenProcedure" => core::ptr::addr_of!(opennt_exp_win32_open_procedure),
            "ExpWin32OkayToCloseProcedure" => core::ptr::addr_of!(opennt_exp_win32_okay_to_close_procedure),
            "ExpWin32CloseProcedure" => core::ptr::addr_of!(opennt_exp_win32_close_procedure),
            "ExpWin32DeleteProcedure" => core::ptr::addr_of!(opennt_exp_win32_delete_procedure),
            "ExpWin32ParseProcedure" => core::ptr::addr_of!(opennt_exp_win32_parse_procedure),
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
