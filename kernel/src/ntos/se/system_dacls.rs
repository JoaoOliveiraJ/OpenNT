//! DACLs públicas do sistema, como o SepInitSystemDacls do ntoskrnl 19041
//! as monta (ACL revisão 2, ACEs nesta ordem). O I/O Manager as usa nos
//! descritores padrão dos dispositivos (`io/device_security.rs`).
//!
//! - SePublicDefaultUnrestrictedDacl: World GENERIC_EXECUTE, SYSTEM e
//!   Administrators GENERIC_ALL, RESTRICTED GENERIC_EXECUTE.
//! - SePublicOpenUnrestrictedDacl: World GENERIC_READ|WRITE|EXECUTE, SYSTEM
//!   e Administrators GENERIC_ALL, RESTRICTED GENERIC_READ|EXECUTE.
//! - SePublicDefaultDacl (export de dado, PACL): World GENERIC_EXECUTE, SYSTEM
//!   e Administrators GENERIC_ALL, numa ACL de 0x54 bytes (o tamanho que o
//!   SepInitSystemDacls calcula, sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid
//!   por ACE; as ACEs ocupam 0x48). A ACL mora na `.kdata`, logo depois da
//!   célula exportada.

use alloc::vec::Vec;

use super::model::{sid, Ace};
use crate::ntos::mm::{guest_memory as guest, kernel_data};

/// AclSize do SePublicDefaultDacl.
const PUBLIC_DEFAULT_DACL_SIZE: u16 = 0x54;

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

/// SePublicDefaultDacl.
pub fn public_default() -> Vec<Ace> {
    alloc::vec![Ace::allow(world(), GENERIC_EXECUTE), Ace::allow(local_system(), GENERIC_ALL), Ace::allow(administrators(), GENERIC_ALL)]
}

/// RtlCreateAcl(Acl, Size, ACL_REVISION) e um RtlAddAccessAllowedAce por
/// entrada: os bytes da ACL com AclSize `size`.
fn acl_bytes(entries: &[Ace], size: u16) -> Vec<u8> {
    let mut bytes = alloc::vec![0u8; size as usize];
    bytes[0] = 2;
    bytes[2..4].copy_from_slice(&size.to_le_bytes());
    let mut offset = 8;
    let mut count = 0u16;
    for ace in entries {
        let Some(identifier) = &ace.sid else { continue };
        let ace_size = 8 + identifier.len();
        bytes[offset + 2..offset + 4].copy_from_slice(&(ace_size as u16).to_le_bytes());
        bytes[offset + 4..offset + 8].copy_from_slice(&ace.mask.to_le_bytes());
        bytes[offset + 8..offset + ace_size].copy_from_slice(identifier);
        offset += ace_size;
        count += 1;
    }
    bytes[4..6].copy_from_slice(&count.to_le_bytes());
    bytes
}

/// A célula exportada SePublicDefaultDacl, com a ACL montada na primeira
/// resolução.
pub fn public_default_dacl_cell() -> u64 {
    let cell = kernel_data::required_address("SePublicDefaultDacl");
    if kernel_data::read("SePublicDefaultDacl") == 0 {
        guest::write_bytes(cell + 8, &acl_bytes(&public_default(), PUBLIC_DEFAULT_DACL_SIZE));
        kernel_data::write("SePublicDefaultDacl", cell + 8);
    }
    cell
}
