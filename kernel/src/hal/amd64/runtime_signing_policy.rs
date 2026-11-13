//! Nível de assinatura atualizável em runtime — `hal/win32/runtime-signing-policy.asm`.
//!
//! Callback privado da CI que grava o UCHAR recebido em CL (não um NTSTATUS
//! nem um ponteiro) e a célula única SeILSigningPolicyRuntime. O MOV de um
//! byte preserva os demais registradores e as flags; a rotina folha não
//! reserva pilha.

core::arch::global_asm!(
    r#"
.pushsection .text.runtime_signing, "ax", @progbits
.global sep_set_runtime_updatable_signing_level
.balign 16
sep_set_runtime_updatable_signing_level:
    mov byte ptr [rip + se_il_signing_policy_runtime], cl
    ret
.popsection

# O byte começa em zero, como a célula original antes da publicação pela
# CI; os 15 bytes reservados isolam a célula de outros dados do linker.
.pushsection .data.runtime_signing, "aw", @progbits
.balign 16
.global se_il_signing_policy_runtime
se_il_signing_policy_runtime:
    .zero 16
.popsection
"#
);

unsafe extern "C" {
    static se_il_signing_policy_runtime: u8;
    fn sep_set_runtime_updatable_signing_level();
}

/// Endereços na imagem: 0 = callback, 1 = célula de estado.
pub fn entry(index: u32) -> Option<u64> {
    match index {
        0 => Some(sep_set_runtime_updatable_signing_level as unsafe extern "C" fn() as usize as u64),
        1 => Some(&raw const se_il_signing_policy_runtime as u64),
        _ => None,
    }
}
