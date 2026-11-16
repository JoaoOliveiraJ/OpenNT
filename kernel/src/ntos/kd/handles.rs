//! A tabela de handles inteira de um processo (`monitor handles`): cada
//! entrada viva da HANDLE_TABLE nativa com o objeto, o tipo, o acesso
//! concedido e o nome.
//!
//! O caminho é o do ExpLookupHandleTableEntry (TableCode com até três
//! níveis, páginas de 256 entradas de 16 bytes). O tipo sai do TypeIndex do
//! OBJECT_HEADER, desembaralhado pelo ObHeaderCookie e pelo byte 1 do
//! endereço do cabeçalho, na ObTypeIndexTable. O nome vem do
//! OBJECT_HEADER_NAME_INFO; num File, do FILE_OBJECT.FileName; num Process,
//! do ImageFileName. Tudo pelo leitor de memória do depurador, sem travas.
//! Um handle de processo de usuário cuja linha nativa não dá o tipo (a
//! identidade publicada pelo `ps/user`) recebe o tipo da tabela de handles
//! de usuário do processo, quando nenhum processador parado tinha trava.
//! A saída é paginada: a última linha dá o índice seguinte (`mais: N`).

use core::fmt::Write;
use core::mem::offset_of;

use super::packet::Payload;
use super::{memory, process_context, stop};
use crate::ntos::inc::types::{ClientId, Eprocess, Ethread, FileObject, HandleTable, HandleTableEntry, ObjectHeader, ObjectHeaderNameInfo, ObjectType, UnicodeString};
use crate::ntos::ob::{object_header, object_types};
use crate::ntos::ps::user::{process_state, state as user_state};

/// Entradas por página da tabela.
const PER_PAGE: u64 = 0x1000 / 16;
/// Linhas por resposta (o texto do `qRcmd` tem tamanho fixo).
const PAGE_LINES: usize = 120;

fn read_u64(cr3: u64, address: u64) -> u64 {
    memory::read_u64(cr3, address).unwrap_or(0)
}

/// Uma UNICODE_STRING como texto ASCII (até `limit` caracteres).
pub fn push_unicode(cr3: u64, string: u64, limit: usize, out: &mut Payload) -> bool {
    let length = memory::read_u16(cr3, string + offset_of!(UnicodeString, length) as u64).unwrap_or(0) as usize / 2;
    let buffer = read_u64(cr3, string + offset_of!(UnicodeString, buffer) as u64);
    if length == 0 || buffer == 0 {
        return false;
    }
    let mut units = [0u8; 2];
    for index in 0..length.min(limit) {
        if memory::read(cr3, buffer + index as u64 * 2, &mut units) != 2 {
            break;
        }
        let unit = u16::from_le_bytes(units);
        out.push(if (0x20..0x7F).contains(&unit) { unit as u8 } else { b'?' });
    }
    if length > limit {
        out.push_str("...");
    }
    true
}

/// O endereço da entrada `index` (0 fora da tabela).
fn entry_address(cr3: u64, code: u64, index: u64) -> u64 {
    let base = code & !3;
    match code & 3 {
        0 => base + index * 16,
        1 => {
            let leaf = read_u64(cr3, base + (index / PER_PAGE) * 8);
            if leaf == 0 { 0 } else { leaf + (index % PER_PAGE) * 16 }
        }
        _ => {
            let middle = read_u64(cr3, base + (index / (PER_PAGE * 512)) * 8);
            let leaf = if middle == 0 { 0 } else { read_u64(cr3, middle + ((index / PER_PAGE) % 512) * 8) };
            if leaf == 0 { 0 } else { leaf + (index % PER_PAGE) * 16 }
        }
    }
}

/// O OBJECT_TYPE de um cabeçalho (o ObGetObjectType, pela memória).
fn object_type(cr3: u64, header: u64) -> u64 {
    let Some(encoded) = memory::read_u8(cr3, header + offset_of!(ObjectHeader, type_index) as u64) else { return 0 };
    let index = encoded ^ object_types::header_cookie() ^ (header >> 8) as u8;
    object_types::type_at_index(index)
}

/// O nome do tipo (OBJECT_TYPE.Name) em `name`; devolve o tamanho.
fn type_name(cr3: u64, object_type: u64, name: &mut [u8; 24]) -> usize {
    if object_type == 0 {
        return 0;
    }
    let string = object_type + offset_of!(ObjectType, name) as u64;
    let length = (memory::read_u16(cr3, string).unwrap_or(0) as usize / 2).min(name.len());
    let buffer = read_u64(cr3, string + offset_of!(UnicodeString, buffer) as u64);
    let mut units = [0u8; 2];
    for index in 0..length {
        if memory::read(cr3, buffer + index as u64 * 2, &mut units) != 2 {
            return index;
        }
        let unit = u16::from_le_bytes(units);
        name[index] = if (0x20..0x7F).contains(&unit) { unit as u8 } else { b'?' };
    }
    length
}

/// O nome do objeto, pelo tipo.
fn push_object_name(cr3: u64, header: u64, body: u64, kind: &[u8], out: &mut Payload) {
    let mask = memory::read_u8(cr3, header + offset_of!(ObjectHeader, info_mask) as u64).unwrap_or(0);
    if mask & object_header::INFO_NAME != 0 {
        let offset = object_header::INFO_MASK_TO_OFFSET[(mask & (object_header::INFO_NAME | (object_header::INFO_NAME - 1))) as usize] as u64;
        let info = header - offset;
        if push_unicode(cr3, info + offset_of!(ObjectHeaderNameInfo, name) as u64, 96, out) {
            return;
        }
    }
    match kind {
        b"File" => {
            push_unicode(cr3, body + offset_of!(FileObject, file_name) as u64, 96, out);
        }
        b"Process" => {
            let mut name = [0u8; 15];
            let length = memory::read(cr3, body + offset_of!(Eprocess, image_file_name) as u64, &mut name);
            let end = name[..length].iter().position(|&byte| byte == 0).unwrap_or(length);
            let pid = read_u64(cr3, body + offset_of!(Eprocess, unique_process_id) as u64);
            for &byte in &name[..end] {
                out.push(if (0x20..0x7F).contains(&byte) { byte } else { b'?' });
            }
            let _ = write!(out, " (PID {})", pid);
        }
        b"Thread" => {
            let cid = body + offset_of!(Ethread, cid) as u64;
            let pid = read_u64(cr3, cid + offset_of!(ClientId, unique_process) as u64);
            let tid = read_u64(cr3, cid + offset_of!(ClientId, unique_thread) as u64);
            let _ = write!(out, "PID {} TID {}", pid, tid);
        }
        _ => {}
    }
}

/// `handles <pid|eprocess> [inicio]`.
pub fn command(owner: usize, argument: &str, out: &mut Payload) {
    let cr3 = stop::address_space(owner);
    let mut words = argument.split_whitespace();
    let Some(process_text) = words.next() else {
        out.push_str("uso: handles <pid|eprocess> [indice inicial]\n");
        return;
    };
    let start = words.next().and_then(|text| text.parse::<u64>().ok()).unwrap_or(0);
    let Some(eprocess) = process_context::resolve(cr3, process_text) else {
        let _ = writeln!(out, "{}: processo nao encontrado", process_text);
        return;
    };
    let table = read_u64(cr3, eprocess + offset_of!(Eprocess, object_table) as u64);
    if table == 0 {
        let _ = writeln!(out, "EPROCESS {:#x} sem ObjectTable", eprocess);
        return;
    }
    let code = read_u64(cr3, table + offset_of!(HandleTable, table_code) as u64);
    let limit = memory::read_u32(cr3, table + offset_of!(HandleTable, next_handle_needing_pool) as u64).unwrap_or(0) as u64 / 4;
    let _ = writeln!(out, "EPROCESS {:#x} HANDLE_TABLE {:#x} TableCode {:#x} entradas {}", eprocess, table, code, limit);
    let _ = writeln!(out, "{:>8} {:>18} {:>10} {:<16} nome", "handle", "objeto", "acesso", "tipo");
    // A tabela de usuário do processo (só com as travas livres).
    let user_table = if stop::locks_held() { None } else { process_state::get(eprocess) };
    let mut lines = 0;
    let mut index = start.max(1);
    while index < limit {
        if index % PER_PAGE == 0 {
            // A primeira entrada de cada página não é handle.
            index += 1;
            continue;
        }
        if lines == PAGE_LINES {
            let _ = writeln!(out, "mais: {}", index);
            return;
        }
        let entry = entry_address(cr3, code, index);
        index += 1;
        if entry == 0 {
            continue;
        }
        let low = read_u64(cr3, entry + offset_of!(HandleTableEntry, volatile_low_value) as u64);
        if low == 0 {
            continue;
        }
        let high = read_u64(cr3, entry + offset_of!(HandleTableEntry, high_value) as u64);
        let header = (((low as i64) >> 16) as u64) & !0xF;
        if header < 0xFFFF_8000_0000_0000 {
            continue;
        }
        let body = header + offset_of!(ObjectHeader, body) as u64;
        let mut name = [0u8; 24];
        let mut length = type_name(cr3, object_type(cr3, header), &mut name);
        if length == 0 {
            if let Some(entry) = user_table.as_ref().and_then(|table| user_state::get_user_handle_in(table, (index - 1) * 4)) {
                let user_kind = entry.kind().as_bytes();
                length = user_kind.len().min(name.len());
                name[..length].copy_from_slice(&user_kind[..length]);
                if let Some(first) = name.first_mut() {
                    first.make_ascii_uppercase();
                }
            }
        }
        let kind = if length == 0 { &b"?"[..] } else { &name[..length] };
        let _ = write!(out, "{:>#8x} {:>#18x} {:>#10x} ", (index - 1) * 4, body, high & 0x1FF_FFFF);
        for &byte in kind {
            out.push(byte);
        }
        for _ in kind.len()..16 {
            out.push(b' ');
        }
        out.push(b' ');
        push_object_name(cr3, header, body, kind, out);
        out.push(b'\n');
        lines += 1;
    }
}
