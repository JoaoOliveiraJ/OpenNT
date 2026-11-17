//! Política de CPU heterogênea das threads.
//!
//! O KTHREAD guarda a política pedida (UserHeteroCpuPolicy, bits 0..=6 do
//! byte +0x7e), a marca ExplicitSystemHeteroCpuPolicy (bit 7) e a política
//! efetiva (SystemHeteroCpuPolicy, +0x7d). O OpenNT trata todos os
//! processadores como uma só classe de eficiência, o sistema que o NT
//! descreve com KeHeteroSystem = 0: nele o KiSetHeteroPolicyThread do
//! ntoskrnl 19041 (rva 0x5202a4) leva a política efetiva a 0 e apaga a marca
//! explícita, qualquer que seja a política pedida.

use super::thread_lock;
use crate::ntos::inc::types::{Kthread, NtStruct};

/// KHeteroCpuPolicyDefault: o valor que o PopUpdateSingleThreadHeteroPolicies
/// (rva 0x8f1470) compara e que o KiSetHeteroPolicyThread troca pelo
/// KiDefaultHeteroCpuPolicy.
pub const POLICY_DEFAULT: u8 = 8;

/// PopUpdateSingleThreadHeteroPolicies(Process, Thread, Context): a thread
/// sem política de sistema explícita e com a política padrão refaz a
/// política efetiva (KiSetHeteroPolicyThread(Thread, 8, TRUE, TRUE)).
pub fn update_single_thread(thread: u64) {
    // SAFETY: KTHREAD referenciado pela enumeração do PsEnumProcessThreads.
    let kthread = unsafe { Kthread::at(thread) };
    if kthread.explicit_system_hetero_cpu_policy() == 0 && kthread.user_hetero_cpu_policy() == POLICY_DEFAULT {
        set_thread_policy(thread, POLICY_DEFAULT);
    }
}

/// KiSetHeteroPolicyThread com a política pedida gravada: sob o ThreadLock
/// em DISPATCH_LEVEL, a política pedida vai para UserHeteroCpuPolicy; num
/// sistema homogêneo a efetiva é 0 e a marca explícita cai.
pub fn set_thread_policy(thread: u64, policy: u8) {
    thread_lock::with_lock(thread, || {
        // SAFETY: KTHREAD vivo, sob o ThreadLock.
        let kthread = unsafe { Kthread::at(thread) };
        kthread.set_user_hetero_cpu_policy(policy & Kthread::USER_HETERO_CPU_POLICY_MASK);
        kthread.set_explicit_system_hetero_cpu_policy(0);
        if kthread.system_hetero_cpu_policy.get() != 0 {
            kthread.system_hetero_cpu_policy.set(0);
        }
    });
}
