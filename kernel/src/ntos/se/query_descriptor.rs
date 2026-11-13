//! SeQuerySecurityDescriptorInfo.
//!
//! Seleciona componentes do descritor do objeto; formato e filtros medidos no
//! kernel de referência. `query_info` é a forma do export, com os parâmetros
//! por ponteiro.

use alloc::vec::Vec;

use super::policy_descriptor::OwnedDescriptor;
use super::{descriptor, out, sid};
use crate::ntos::inc::types::{Acl, NtStruct, SecurityDescriptorRelative};
use crate::ntos::mm::guest_memory as guest;

fn align4(length: usize) -> usize {
    (length + 3) & !3
}

/// Aceita os dois layouts NT; descritor NULL = sem componentes.
pub fn read_descriptor(pointer: u64) -> Option<OwnedDescriptor> {
    if pointer == 0 {
        return None;
    }
    let control = descriptor::control(pointer);
    let mut owned = OwnedDescriptor { control, ..OwnedDescriptor::default() };
    for index in 0..4usize {
        // Componente nos dois formatos (offset relativo ou ponteiro absoluto);
        // SACL/DACL ausentes pelo Control dão zero.
        let component = descriptor::component(pointer, control, index as u64);
        if component == 0 {
            continue;
        }
        let length = if index < 2 {
            8 + 4 * sid::at(component).sub_authority_count.get() as usize
        } else {
            // SAFETY: componente SACL/DACL do descritor.
            unsafe { Acl::at(component) }.acl_size.get() as usize
        };
        let bytes = Some(guest::read_bytes(component, length));
        match index {
            0 => owned.owner = bytes,
            1 => owned.group = bytes,
            2 => owned.sacl = bytes,
            _ => owned.dacl = bytes,
        }
    }
    Some(owned)
}

/// A SACL conserva só as categorias pedidas: auditoria usa
/// SACL_SECURITY_INFORMATION; label, atributos, escopo, confiança e filtro
/// de acesso (tipos 17–21) usam seus bits; ordem e bytes ficam intactos.
fn filter_system_acl(source: &[u8], information: u32) -> Vec<u8> {
    let count = u16::from_le_bytes([source[4], source[5]]);
    let mut entries: Vec<&[u8]> = Vec::new();
    let mut offset = 8usize;
    for _ in 0..count {
        let ace_type = source[offset];
        let length = u16::from_le_bytes([source[offset + 2], source[offset + 3]]) as usize;
        let bit = if (17..=21).contains(&ace_type) { 0x10 << (ace_type - 17) } else { 8 };
        if information & bit != 0 {
            entries.push(&source[offset..offset + length]);
        }
        offset += length;
    }
    let total = 8 + entries.iter().map(|entry| entry.len()).sum::<usize>();
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(&source[..8]);
    bytes[2..4].copy_from_slice(&(total as u16).to_le_bytes());
    bytes[4..6].copy_from_slice(&(entries.len() as u16).to_le_bytes());
    for entry in entries {
        bytes.extend_from_slice(entry);
    }
    bytes
}

/// Plano da cópia: informação efetiva, Control, LengthNeeded e componentes
/// (offset do campo no cabeçalho, bytes).
pub struct Selection {
    pub information: u32,
    pub control: u16,
    pub needed: usize,
    pub components: Vec<(u64, Vec<u8>)>,
}

/// Planeja antes de escrever: BUFFER_TOO_SMALL não deixa cópia parcial.
pub fn select_descriptor(descriptor: Option<&OwnedDescriptor>, security_information: u32) -> Selection {
    let original = security_information;
    let mut information = original;
    let mut control = 0x8000u16;
    let mut needed = 20usize;
    let mut components = Vec::new();
    let Some(descriptor) = descriptor else {
        return Selection { information, control, needed, components };
    };
    // BACKUP inclui os componentes tradicionais; confiança e filtro de acesso
    // só com seus bits explícitos.
    if information & 0x10000 != 0 {
        information |= 0x1FF;
        if original & 0x80 == 0 {
            information &= !0x80;
        }
        if original & 0x100 == 0 {
            information &= !0x100;
        }
    }
    let source_control = descriptor.control & 0x7FFF;
    for (bytes, bit, header) in [(&descriptor.owner, 1u32, 4u64), (&descriptor.group, 2, 8)] {
        let Some(bytes) = bytes.as_ref().filter(|_| information & bit != 0) else { continue };
        control |= source_control & bit as u16;
        needed += align4(bytes.len());
        components.push((header, bytes.clone()));
    }
    if information & 4 != 0 {
        control |= source_control & 0x140C;
        if let Some(dacl) = descriptor.dacl.as_ref().filter(|_| source_control & 4 != 0) {
            needed += align4(dacl.len());
            components.push((16, dacl.clone()));
        }
    }
    if information & 0x1F8 != 0 {
        control |= source_control & 0x2830;
        if let Some(sacl) = descriptor.sacl.as_ref().filter(|_| source_control & 16 != 0) {
            let bytes = filter_system_acl(sacl, information);
            needed += align4(bytes.len());
            components.push((12, bytes));
        }
    }
    Selection { information, control, needed, components }
}

/// Resultado: NTSTATUS, LengthNeeded e a informação efetiva.
pub struct QueryResult {
    pub status: u32,
    pub needed: usize,
    pub information: u32,
}

/// SECURITY_DESCRIPTOR_RELATIVE no buffer; o chamador publica LengthNeeded.
pub fn query_descriptor(descriptor: Option<&OwnedDescriptor>, information: u32, buffer: u64, buffer_length: u32) -> QueryResult {
    let selection = select_descriptor(descriptor, information);
    if (buffer_length as usize) < selection.needed {
        return QueryResult { status: 0xC000_0023, needed: selection.needed, information: selection.information };
    }
    guest::write_bytes(buffer, &[0u8; SecurityDescriptorRelative::SIZE as usize]);
    // SAFETY: buffer do chamador com pelo menos `needed` bytes.
    let relative = unsafe { SecurityDescriptorRelative::at(buffer) };
    relative.revision.set(1);
    relative.control.set(selection.control);
    let mut cursor = (buffer + SecurityDescriptorRelative::SIZE + 3) & !3;
    for (header, bytes) in &selection.components {
        guest::write_bytes(cursor, bytes);
        let offset = match header {
            4 => &relative.owner,
            8 => &relative.group,
            12 => &relative.sacl,
            _ => &relative.dacl,
        };
        offset.set((cursor - buffer) as u32);
        cursor += align4(bytes.len()) as u64;
    }
    QueryResult { status: 0, needed: selection.needed, information: selection.information }
}

/// SeQuerySecurityDescriptorInfo(*Information, Out, *Length, *ObjectSd):
/// lê os parâmetros por ponteiro, consulta o descritor do objeto (filtro de
/// SACL, LengthNeeded e BUFFER_TOO_SMALL ficam em `query_descriptor`),
/// publica LengthNeeded em `*Length` e devolve o NTSTATUS.
pub fn query_info(information_pointer: u64, buffer: u64, length_pointer: u64, object_sd_pointer: u64) -> u32 {
    let information = out::<u32>(information_pointer).get();
    let object_sd = out::<u64>(object_sd_pointer).get();
    let descriptor = read_descriptor(object_sd);
    let length = out::<u32>(length_pointer);
    let result = query_descriptor(descriptor.as_ref(), information, buffer, length.get());
    length.set(result.needed as u32);
    result.status
}
