//! Versão do sistema e modo de boot anunciados aos drivers (PsGetVersion,
//! InitSafeBootMode).
//!
//! O OpenNT se apresenta como 10.0.26100 e sobe sempre no boot normal (sem
//! safe boot).

use crate::ntos::inc::types::{Field, NtStruct, UnicodeString};

/// (Major, Minor, Build) publicados.
const VERSION: (u32, u32, u32) = (10, 0, 26100);

/// PsGetVersion: grava Major, Minor e Build (PULONG) e CSDVersion
/// (PUNICODE_STRING, vazia: sem service pack) nas saídas não nulas e
/// devolve TRUE.
pub fn get_version(major: u64, minor: u64, build: u64, csd_version: u64) -> bool {
    let (major_version, minor_version, build_number) = VERSION;
    for (pointer, value) in [(major, major_version), (minor, minor_version), (build, build_number)] {
        if pointer != 0 {
            // SAFETY: PULONG de saída do driver.
            unsafe { Field::<u32>::at(pointer) }.set(value);
        }
    }
    if csd_version != 0 {
        // SAFETY: PUNICODE_STRING de saída do driver.
        let text = unsafe { UnicodeString::at(csd_version) };
        text.length.set(0);
        text.maximum_length.set(0);
        text.buffer.set(0);
    }
    true
}

/// InitSafeBootMode: boot normal.
pub fn safe_boot_mode() -> u64 {
    0
}
