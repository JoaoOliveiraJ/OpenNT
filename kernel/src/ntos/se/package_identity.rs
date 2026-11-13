//! RtlQueryPackageIdentity do kernel.
//!
//! Recebe TOKEN*, como RtlQueryPackageClaims. A claim é consultada mesmo sem
//! a saída Packaged; seus 32 bits baixos viram BOOLEAN só depois do sucesso
//! de todos os nomes.

use super::package_claims;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

pub fn query(token: u64, package: u64, package_size: u64, application: u64, application_size: u64, packaged_output: u64) -> Result<u32, KernelError> {
    // Equivale às variáveis locais das rotinas originais; não publica claim
    // nem altera o token.
    let claim = guest::alloc_bytes(8);
    if claim == 0 {
        return Ok(0xC000_009A);
    }
    guest::write64(claim, 0);
    let result = package_claims::query(token, package, package_size, application, application_size, 0, claim, 0);
    if let Ok(status) = result {
        if status & 0x8000_0000 == 0 && packaged_output != 0 {
            // A metade alta é Origin, não Flags: a claim 0x100000000 dá FALSE.
            super::out::<u8>(packaged_output).set((guest::read32(claim) != 0) as u8);
        }
    }
    guest::free_bytes(claim);
    result
}
