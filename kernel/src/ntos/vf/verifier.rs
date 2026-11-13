//! Driver Verifier desligado — VfCheckNxPoolType (RVA 0x5a0700) e
//! VfQueryDispatchTable (RVA 0x5a0b00) do ntoskrnl 10.0.19045.
//!
//! * VfCheckNxPoolType: `cmp ViVerifierEnabled, 0; je ret` — sem o
//!   verificador o VfCheckPoolType não roda (VOID).
//! * VfQueryDispatchTable(TableType, Version): com
//!   ViVerifierDriverAddedThunkListHead vazio e VfClearanceFlag zero devolve
//!   NULL antes de olhar o tipo (`xor eax, eax`).
//!
//! O OpenNT não tem Driver Verifier: nenhum thunk de verificação é
//! adicionado e nenhuma clearance é concedida, então este é o comportamento
//! real de uma máquina com o verificador desligado.

/// ViVerifierEnabled: o verificador nunca é inicializado no OpenNT.
pub const VERIFIER_ENABLED: bool = false;

/// VfCheckNxPoolType(PoolType, CallingAddress, PoolTag): com o verificador
/// desligado o `je ret` pula o VfCheckPoolType — nada a fazer.
pub fn check_nx_pool_type(_pool_type: u32, _calling_address: u64, _pool_tag: u32) {}

/// VfQueryDispatchTable(TableType, Version) -> PVOID: sem thunks de
/// verificação nem clearance, NULL.
pub fn query_dispatch_table(_table_type: u32, _version: u32) -> u64 {
    0
}
