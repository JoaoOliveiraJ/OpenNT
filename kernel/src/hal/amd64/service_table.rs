//! Descritores de serviço nativos — `hal/win32/service-table.asm`.
//!
//! KSERVICE_TABLE_DESCRIPTOR (normal e shadow), as tabelas compactadas de
//! 4096 DWORDs e os bytes de argumentos de cada tabela, mais
//! `nt_service_lookup`, que decodifica a mesma tabela consumida pela
//! invocação de serviços. O Executive (`ntos::ex::service_table`) é o dono
//! do conteúdo; aqui só ficam o armazenamento e a busca nativa.

core::arch::global_asm!(
    r#"
.pushsection .text.service_lookup, "ax", @progbits
.global nt_service_lookup
.balign 16
# ABI MS x64 privada: (número, useShadow, &quantidadeDeArgumentosNaPilha).
# Preserva o RDI não volátil da ABI MS.
nt_service_lookup:
    push rdi
    mov eax, ecx
    mov edi, eax
    shr edi, 7
    and edi, 0x20
    and eax, 0xFFF
    lea r10, [rip + ke_service_descriptor_table]
    lea r11, [rip + ke_service_descriptor_table_shadow]
    test edx, edx
    cmovnz r10, r11
    cmp eax, dword ptr [r10 + rdi + 0x10]
    jae 2f
    mov r10, qword ptr [r10 + rdi]
    movsxd r11, dword ptr [r10 + rax*4]
    mov edx, r11d
    and edx, 15
    sar r11, 4
    lea rax, [r10 + r11]
    jmp 3f
2:
    xor eax, eax
    xor edx, edx
3:
    test r8, r8
    jz 4f
    mov qword ptr [r8], rdx
4:
    pop rdi
    ret
.popsection

.pushsection .data.service_table, "aw", @progbits
.balign 4096
.global ke_service_descriptor_table
ke_service_descriptor_table: .zero 64
.global ke_service_descriptor_table_shadow
ke_service_descriptor_table_shadow: .zero 64
.balign 4096
.global ki_native_service_table
ki_native_service_table: .zero 16384
.global ki_win32_service_table
ki_win32_service_table: .zero 16384
.global ki_native_argument_table
ki_native_argument_table: .zero 4096
.global ki_win32_argument_table
ki_win32_argument_table: .zero 4096
.popsection
"#
);

unsafe extern "C" {
    static ke_service_descriptor_table: u8;
    static ke_service_descriptor_table_shadow: u8;
    static ki_native_service_table: u8;
    static ki_win32_service_table: u8;
    static ki_native_argument_table: u8;
    static ki_win32_argument_table: u8;
    fn nt_service_lookup();
}

// Provedores MS x64 das tabelas vivas — `hal/win32/service-gateways.asm`.
// Cada gateway de dez bytes marca o id privado (0x40000000 + número) e cai
// no trampolim comum; só slots com implementação registrada os recebem. A
// falha comum dos slots sem provedor nunca relata sucesso.
core::arch::global_asm!(
    r#"
.pushsection .text.service_gateways, "ax", @progbits
.balign 16
.global nt_service_gateways
nt_service_gateways:
.set opennt_service_index, 0
.rept 8192
    .byte 0xB8
    .long 0x40000000 + opennt_service_index
    .byte 0xE9
    .long opennt_win32_common - . - 4
    .set opennt_service_index, opennt_service_index + 1
.endr
.global nt_service_unimplemented
nt_service_unimplemented:
    mov eax, 0xC0000002
    ret
.popsection
"#
);

extern "C" {
    fn nt_service_gateways();
    fn nt_service_unimplemented();
}

/// Endereços na imagem, na ordem de `getSystemServiceEntry`: busca,
/// descritor, shadow, tabelas nativa/win32, argumentos nativo/win32, os
/// gateways e a rotina de serviço indisponível.
pub fn entries() -> [u64; 9] {
    [
        nt_service_lookup as unsafe extern "C" fn() as usize as u64,
        &raw const ke_service_descriptor_table as u64,
        &raw const ke_service_descriptor_table_shadow as u64,
        &raw const ki_native_service_table as u64,
        &raw const ki_win32_service_table as u64,
        &raw const ki_native_argument_table as u64,
        &raw const ki_win32_argument_table as u64,
        nt_service_gateways as unsafe extern "C" fn() as usize as u64,
        nt_service_unimplemented as unsafe extern "C" fn() as usize as u64,
    ]
}
