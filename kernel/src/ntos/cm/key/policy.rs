//! Política declarada da hive.
//!
//! A raiz concede administração a SYSTEM e Administrators e leitura a
//! Everyone; os descendentes herdam essas ACEs. São permissões aplicadas pelo
//! provedor, não respostas criadas pela consulta.

use alloc::vec::Vec;

use crate::ntos::se::inherit_descriptor::{self, Captured};
use crate::rtl::KernelError;

pub const KEY_MAPPING: [u32; 4] = [0x20019, 0x20006, 0x20039, 0xF003F];

fn bytes_from_hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap_or(0)).collect()
}

pub fn boot_root() -> Captured {
    Captured {
        control: 0x1404,
        owner: bytes_from_hex("010100000000000512000000"),
        group: bytes_from_hex("010100000000000512000000"),
        dacl: Some(bytes_from_hex(concat!(
            "0200480003000000",
            "000214003f000f00010100000000000512000000",
            "000218003f000f0001020000000000052000000020020000",
            "0002140019000200010100000000000100000000",
        ))),
        sacl: None,
    }
}

/// SeAssignSecurity escolhe herança automática quando a ACL do pai já usa
/// esse modelo e o criador não fornece a própria ACL PRESENT.
fn inheritance_flags(parent: &Captured, creator_control: u16) -> u32 {
    (if parent.control & 0x400 != 0 && creator_control & 4 == 0 { 1 } else { 0 })
        | (if parent.control & 0x800 != 0 && creator_control & 16 == 0 { 2 } else { 0 })
}

/// `Ok(Err(status))` quando a atribuição recusa o descritor.
pub fn assign(parent: &Captured, creator: &Captured, source_control: Option<u16>) -> Result<Result<Captured, u32>, KernelError> {
    let flags = inheritance_flags(parent, source_control.unwrap_or(creator.control));
    inherit_descriptor::assign(Some(parent), creator, &KEY_MAPPING, flags, true)
}

/// Chaves internas criadas no boot pertencem ao contexto SYSTEM da hive; o
/// caminho de serviços fornece owner/group do sujeito de cada criação.
pub fn boot_child(parent: &Captured) -> Result<Captured, KernelError> {
    let creator = Captured { control: 0, owner: parent.owner.clone(), group: parent.group.clone(), dacl: None, sacl: None };
    match assign(parent, &creator, None)? {
        Ok(descriptor) => Ok(descriptor),
        Err(_) => Err(KernelError::new("boot key security assignment failed")),
    }
}
