//! Versão do sistema e modo de boot anunciados aos drivers (PsGetVersion,
//! InitSafeBootMode).
//!
//! O OpenNT se apresenta como 10.0.26100 e sobe sempre no boot normal (sem
//! safe boot).

use crate::ntos::mm::guest_memory as guest;

/// (Major, Minor, Build) publicados.
const VERSION: (u32, u32, u32) = (10, 0, 26100);

/// PsGetVersion: grava Major, Minor, Build e CSDVersion (0) nas saídas não
/// nulas e devolve TRUE.
pub fn get_version(major: u64, minor: u64, build: u64, csd_version: u64) -> bool {
    let (major_version, minor_version, build_number) = VERSION;
    for (pointer, value) in [(major, major_version), (minor, minor_version), (build, build_number), (csd_version, 0)] {
        if pointer != 0 {
            guest::write32(pointer, value);
        }
    }
    true
}

/// InitSafeBootMode: boot normal.
pub fn safe_boot_mode() -> u64 {
    0
}
