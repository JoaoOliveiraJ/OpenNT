//! DACLs públicas do sistema, como o SepInitSystemDacls do ntoskrnl 19041
//! as monta (ACL revisão 2, ACEs nesta ordem). O I/O Manager as usa nos
//! descritores padrão dos dispositivos (`io/device_security.rs`).
//!
//! - SePublicDefaultUnrestrictedDacl: World GENERIC_EXECUTE, SYSTEM e
//!   Administrators GENERIC_ALL, RESTRICTED GENERIC_EXECUTE.
//! - SePublicOpenUnrestrictedDacl: World GENERIC_READ|WRITE|EXECUTE, SYSTEM
//!   e Administrators GENERIC_ALL, RESTRICTED GENERIC_READ|EXECUTE.

use alloc::vec::Vec;

use super::model::{sid, Ace};

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;

/// S-1-1-0, S-1-5-18, S-1-5-32-544 e S-1-5-12.
fn world() -> Vec<u8> {
    sid(1, &[0])
}

fn local_system() -> Vec<u8> {
    sid(5, &[18])
}

fn administrators() -> Vec<u8> {
    sid(5, &[32, 544])
}

fn restricted() -> Vec<u8> {
    sid(5, &[12])
}

/// SePublicDefaultUnrestrictedDacl.
pub fn public_default_unrestricted() -> Vec<Ace> {
    alloc::vec![Ace::allow(world(), GENERIC_EXECUTE), Ace::allow(local_system(), GENERIC_ALL), Ace::allow(administrators(), GENERIC_ALL), Ace::allow(restricted(), GENERIC_EXECUTE)]
}

/// SePublicOpenUnrestrictedDacl.
pub fn public_open_unrestricted() -> Vec<Ace> {
    alloc::vec![
        Ace::allow(world(), GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE),
        Ace::allow(local_system(), GENERIC_ALL),
        Ace::allow(administrators(), GENERIC_ALL),
        Ace::allow(restricted(), GENERIC_READ | GENERIC_EXECUTE),
    ]
}
