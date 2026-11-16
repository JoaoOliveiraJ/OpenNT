//! O processo das leituras do host (o `.process /p` do WinDbg).
//!
//! Por padrão, `m`/`M`/`X` e o `Z0` usam o espaço de endereços (CR3) do
//! processador escolhido. Com um processo escolhido pelo `monitor .process`,
//! usam a raiz dele (KPROCESS.DirectoryTableBase): o host lê e grava a
//! metade de usuário daquele processo e arma breakpoints de software nela. A
//! metade de sistema é a mesma em todas as raízes, então as leituras do
//! kernel não mudam. A escolha vale até a máquina seguir: cada parada começa
//! de novo no CR3 do processador.

use core::fmt::Write;
use core::mem::offset_of;
use core::sync::atomic::{AtomicU64, Ordering};

use super::packet::Payload;
use super::{memory, stop};
use crate::ntos::inc::types::{Eprocess, Kprocess};
use crate::ntos::ps::process;

/// A raiz escolhida (0 = a do processador).
static ROOT: AtomicU64 = AtomicU64::new(0);
/// O EPROCESS escolhido (0 = nenhum).
static PROCESS: AtomicU64 = AtomicU64::new(0);

const LIST_LIMIT: usize = 1024;

/// O CR3 dos acessos do host feitos em nome do processador `owner`.
pub fn memory_space(owner: usize) -> u64 {
    match ROOT.load(Ordering::Acquire) {
        0 => stop::address_space(owner),
        root => root,
    }
}

/// O EPROCESS escolhido, se houver.
pub fn selected() -> Option<u64> {
    match PROCESS.load(Ordering::Acquire) {
        0 => None,
        process => Some(process),
    }
}

/// Volta ao CR3 do processador (a máquina vai seguir).
pub fn clear() {
    ROOT.store(0, Ordering::Release);
    PROCESS.store(0, Ordering::Release);
}

/// O EPROCESS de um PID (decimal ou `0x` hexadecimal) ou de um endereço de
/// EPROCESS (hexadecimal, na metade de sistema), pela lista de processos
/// ativos.
pub fn resolve(cr3: u64, text: &str) -> Option<u64> {
    let text = text.trim();
    let value = match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok()?,
        None if text.len() > 8 => u64::from_str_radix(text, 16).ok()?,
        None => text.parse().ok()?,
    };
    let head = process::try_active_process_head()?;
    let mut found = None;
    let mut entry = memory::read_u64(cr3, head)?;
    let mut count = 0;
    while entry != head && entry != 0 && count < LIST_LIMIT {
        let eprocess = entry - offset_of!(Eprocess, active_process_links) as u64;
        let pid = memory::read_u64(cr3, eprocess + offset_of!(Eprocess, unique_process_id) as u64).unwrap_or(u64::MAX);
        if eprocess == value || pid == value {
            found = Some(eprocess);
            break;
        }
        entry = memory::read_u64(cr3, entry).unwrap_or(0);
        count += 1;
    }
    found
}

/// O processo cuja raiz é `root` (EPROCESS e PID), pela lista de processos.
pub fn by_root(cr3: u64, root: u64) -> Option<(u64, u64)> {
    let head = process::try_active_process_head()?;
    let mut entry = memory::read_u64(cr3, head)?;
    let mut count = 0;
    while entry != head && entry != 0 && count < LIST_LIMIT {
        let eprocess = entry - offset_of!(Eprocess, active_process_links) as u64;
        if root_of(cr3, eprocess) == Some(root) {
            let pid = memory::read_u64(cr3, eprocess + offset_of!(Eprocess, unique_process_id) as u64).unwrap_or(0);
            // O System divide a raiz com processos sem espaço próprio.
            if pid != 4 {
                return Some((eprocess, pid));
            }
        }
        entry = memory::read_u64(cr3, entry).unwrap_or(0);
        count += 1;
    }
    None
}

/// A raiz das tabelas de páginas de um EPROCESS.
pub fn root_of(cr3: u64, eprocess: u64) -> Option<u64> {
    memory::read_u64(cr3, eprocess + offset_of!(Kprocess, directory_table_base) as u64).filter(|&root| root != 0)
}

/// `.process [pid|eprocess|0]`: escolhe o processo das leituras (vazio
/// mostra a escolha; 0 volta ao processador).
pub fn command(owner: usize, argument: &str, out: &mut Payload) {
    let cr3 = stop::address_space(owner);
    let argument = argument.trim();
    if argument.is_empty() {
        match selected() {
            Some(process) => {
                let _ = writeln!(out, "processo das leituras: EPROCESS {:#x} CR3 {:#x}", process, ROOT.load(Ordering::Acquire));
            }
            None => {
                let _ = writeln!(out, "processo das leituras: o do processador (CR3 {:#x})", cr3);
            }
        }
        match by_root(cr3, cr3) {
            Some((eprocess, pid)) => {
                let _ = writeln!(out, "processo do CR3 do processador: EPROCESS {:#x} PID {}", eprocess, pid);
            }
            None => out.push_str("processo do CR3 do processador: nenhum da lista (raiz do System)
"),
        }
        return;
    }
    if argument == "0" || argument == "-" {
        clear();
        let _ = writeln!(out, "processo das leituras: o do processador (CR3 {:#x})", cr3);
        return;
    }
    let Some(eprocess) = resolve(cr3, argument) else {
        let _ = writeln!(out, "{}: processo nao encontrado", argument);
        return;
    };
    let Some(root) = root_of(cr3, eprocess) else {
        let _ = writeln!(out, "EPROCESS {:#x} sem DirectoryTableBase", eprocess);
        return;
    };
    PROCESS.store(eprocess, Ordering::Release);
    ROOT.store(root, Ordering::Release);
    let peb = memory::read_u64(cr3, eprocess + offset_of!(Eprocess, peb) as u64).unwrap_or(0);
    let pid = memory::read_u64(cr3, eprocess + offset_of!(Eprocess, unique_process_id) as u64).unwrap_or(0);
    let _ = writeln!(out, "processo das leituras: EPROCESS {:#x} PID {} CR3 {:#x} PEB {:#x}", eprocess, pid, root, peb);
}
