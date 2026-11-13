//! Informações do sistema em modo kernel: Zw/NtQuerySystemInformation e
//! ZwSetSystemInformation.
//!
//! A consulta despacha cada classe para a folha dona (boot, Code Integrity,
//! Secure Boot, módulos, processadores, processos); a alteração aceita a
//! classe 131, que registra as rotinas de entropia que o RNG do kernel chama
//! ao coletar/resemear entropia.

use alloc::vec::Vec;

use crate::ntos::ex::boot_environment_information;
use crate::ntos::ke::processor_information;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::module_queries;
use crate::ntos::ps::system_process_information;
use crate::ntos::se::{code_integrity_information, secure_boot_information};
use crate::rtl::{KernelError, SpinLock};

/// Rotinas de entropia registradas por ZwSetSystemInformation(131): o RNG
/// do kernel as chama ao coletar/resemear entropia.
#[derive(Clone, Copy, Debug)]
pub struct EntropyRegistration {
    pub entropy_routine: u64,
    pub initialization_routine: u64,
    pub initialization_context: u64,
}

static ENTROPY_TIMING_REGISTRATIONS: SpinLock<Vec<EntropyRegistration>> = SpinLock::new(Vec::new());

pub fn entropy_registrations() -> Vec<EntropyRegistration> {
    ENTROPY_TIMING_REGISTRATIONS.lock().clone()
}

/// ZwQuerySystemInformation/NtQuerySystemInformation (o mesmo corpo).
pub fn query(class: u32, output: u64, length: u32, returned: u64) -> Result<u32, KernelError> {
    debug_print!("[zw] QuerySystemInformation classe {} buf={}", class, length);
    match class {
        90 => return boot_environment_information::query(output, length as u64, returned, false),
        103 => return code_integrity_information::query(output, length as u64, returned, false),
        143 => return secure_boot_information::query(output, length as u64, returned, false),
        11 | 77 => return module_queries::query_system_modules(class, output, length as u64, returned),
        1 | 63 => return Ok(processor_information::query(output, length, returned, false, class == 63)),
        // SystemCodeIntegrityCertificateManagementInformation: nenhuma
        // operação de certificados pendente (o cng percorre e segue).
        117 => {
            for offset in (0..length as u64).step_by(4) {
                guest::write32(output + offset, 0);
            }
            if returned != 0 {
                guest::write32(returned, length);
            }
            return Ok(0);
        }
        5 => {}
        _ => return Ok(0xC000_000D),
    }
    system_process_information::query(output, length as u64, returned, false)
}

/// ZwSetSystemInformation: 131 registra as rotinas de entropia do chamador;
/// classes desconhecidas = STATUS_INVALID_INFO_CLASS.
pub fn set(class: u32, buffer: u64, length: u32) -> u32 {
    if class == 131 {
        if length < 24 {
            return 0xC000_0004;
        }
        let count = {
            let mut registrations = ENTROPY_TIMING_REGISTRATIONS.lock();
            registrations.push(EntropyRegistration { entropy_routine: guest::read64(buffer), initialization_routine: guest::read64(buffer + 8), initialization_context: guest::read64(buffer + 16) });
            registrations.len()
        };
        debug_print!("[zw] entropia: rotinas registradas ({} provedor(es))", count);
        return 0;
    }
    debug_print!("[zw] ZwSetSystemInformation classe {} (sem suporte)", class);
    0xC000_0003
}
