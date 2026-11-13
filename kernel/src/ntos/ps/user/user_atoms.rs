//! Átomos USER da sessão.
//!
//! Compartilhados por mensagens registradas, nomes de formato da área de
//! transferência e classes de janela; separados das tabelas de átomos NT.

use alloc::collections::BTreeMap;
use alloc::string::String;

use super::{state, win32k};
use crate::ntos::rtl::unicode_case;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

struct Atoms {
    by_atom: BTreeMap<u16, String>,
    by_key: BTreeMap<String, u16>,
    next: u32,
}

static ATOMS: SpinLock<Atoms> = SpinLock::new(Atoms { by_atom: BTreeMap::new(), by_key: BTreeMap::new(), next: 0xC000 });

fn fail(error: u32) -> u32 {
    win32k::last_error(error)
}

/// Átomo do nome ou o código de erro Win32.
pub fn add(name: &str) -> Result<Result<u16, u32>, KernelError> {
    // RtlGetIntegerAtom reconhece nomes decimais #n antes da tabela.
    if let Some(digits) = name.strip_prefix('#').filter(|digits| digits.bytes().all(|byte| byte.is_ascii_digit())) {
        let mut value = 0u32;
        for byte in digits.bytes() {
            value = value.wrapping_mul(10).wrapping_add((byte - b'0') as u32);
        }
        return Ok(if value > 0 && value < 0xC000 { Ok(value as u16) } else { Err(87) });
    }
    // UserAddAtomEx preserva LastError para nome vazio.
    if name.is_empty() {
        return Ok(Ok(0));
    }
    if name.encode_utf16().count() > 255 {
        return Ok(Err(234));
    }
    let key = unicode_case::upcase(name)?;
    let mut atoms = ATOMS.lock();
    if let Some(&existing) = atoms.by_key.get(&key) {
        return Ok(Ok(existing));
    }
    if atoms.by_atom.len() == 0x4000 {
        return Ok(Err(8));
    }
    while atoms.by_atom.contains_key(&(atoms.next as u16)) {
        atoms.next = if atoms.next == 0xFFFF { 0xC000 } else { atoms.next + 1 };
    }
    let atom = atoms.next as u16;
    atoms.by_atom.insert(atom, String::from(name));
    atoms.by_key.insert(key, atom);
    // Os nomes registrados vivem pela sessão, inclusive após o processo.
    Ok(Ok(atom))
}

pub fn name_of(atom: u32) -> Result<String, u32> {
    let atom = (atom & 0xFFFF) as u16;
    if atom == 0 {
        return Err(87);
    }
    if atom < 0xC000 {
        return Ok(alloc::format!("#{atom}"));
    }
    ATOMS.lock().by_atom.get(&atom).cloned().ok_or(6)
}

fn copy_name(atom: u32, buffer: u64, capacity: u32) -> u32 {
    let name = match name_of(atom) {
        Ok(name) => name,
        Err(error) => return fail(error),
    };
    // A saída de nome é opcional em RtlQueryAtomInAtomTable.
    if buffer == 0 {
        return capacity;
    }
    let units: alloc::vec::Vec<u16> = name.encode_utf16().collect();
    let count = (units.len() as i64).min(capacity as i64 - 1);
    if count <= 0 {
        return fail(122);
    }
    for (index, unit) in units.iter().take(count as usize).enumerate() {
        guest::write16(buffer + index as u64 * 2, *unit);
    }
    guest::write16(buffer + count as u64 * 2, 0);
    count as u32
}

fn nt_user_register_window_message(descriptor: u64, _: u64, _: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_user_read(descriptor, 16) {
        return Ok(fail(87));
    }
    let length = guest::read16(descriptor) as u64;
    let maximum = guest::read16(descriptor + 2) as u64;
    let buffer = guest::read64(descriptor + 8);
    if length & 1 != 0 || buffer & 1 != 0 || length > maximum || buffer > (1 << 53) - 1 || buffer + length + 2 >= 0x8000_0000_0000 {
        return Ok(fail(87));
    }
    // O serviço captura um nome terminado em NUL, não Length WCHARs; cada
    // unidade é sondada antes da leitura (limite de 256 WCHARs).
    let mut units = alloc::vec::Vec::new();
    for index in 0..256u64 {
        if !state::probe_user_read(buffer + index * 2, 2) {
            return Ok(fail(87));
        }
        let unit = guest::read16(buffer + index * 2);
        if unit == 0 {
            let name = String::from_utf16_lossy(&units);
            return Ok(match add(&name)? {
                Ok(atom) => atom as u32,
                Err(error) => fail(error),
            });
        }
        units.push(unit);
    }
    Ok(fail(234))
}

fn nt_user_get_atom_name(atom: u64, descriptor: u64, _: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    // Falhas de sondagem devolvem zero sem mudar LastError; o descritor é
    // só entrada (Length não é reescrito).
    if !state::probe_user_read(descriptor, 16) {
        return Ok(0);
    }
    let maximum = guest::read16(descriptor + 2) as u64;
    let buffer = guest::read64(descriptor + 8);
    if (maximum != 0 && buffer & 1 != 0) || !state::probe_user_write(buffer, maximum) {
        return Ok(0);
    }
    Ok(copy_name(atom as u32, buffer, (maximum >> 1) as u32))
}

fn nt_user_get_clipboard_format_name(format: u64, buffer: u64, capacity: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    let capacity = capacity as u32;
    if (capacity != 0 && buffer & 1 != 0) || !state::probe_user_write(buffer, capacity as u64 * 2) {
        return Ok(0);
    }
    let format = format as u32 & 0xFFFF;
    if format < 0xC000 {
        return Ok(fail(87));
    }
    Ok(copy_name(format, buffer, capacity))
}

pub fn init() {
    state::register_handler("NtUserRegisterWindowMessage", nt_user_register_window_message);
    state::register_handler("NtUserGetAtomName", nt_user_get_atom_name);
    state::register_handler("NtUserGetClipboardFormatName", nt_user_get_clipboard_format_name);
}
