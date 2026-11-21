//! O fim de um processo de usuário pedido pelo host (`monitor kill <pid|end>
//! <código>`), para os roteiros do kd: o `xtask/scripts/reinicio-do-shell.txt`
//! encerra o explorer.exe com o código de uma falha e confere que o winlogon
//! o recria.
//!
//! Com a máquina parada nenhuma trava do kernel pode ser tomada (o código
//! interrompido pode estar com ela), então o comando só acha o processo
//! pelas listas nativas (`process_context::resolve`) e guarda o pedido em
//! duas células atômicas. O fim roda depois que a máquina segue, num work
//! item do kernel reservado e enfileirado no boot com o depurador ligado
//! ([`initialize`]), cujo predicado de prontidão é o pedido: a gerência das
//! filas (`io::work_items::balance`) acorda uma worker quando ele aparece, e
//! ela chama o PspTerminateProcess (`ps::create::exit_process`) a
//! PASSIVE_LEVEL, como o NtTerminateProcess de outro processo. As threads
//! do processo terminam, o callout de saída do win32k roda e o objeto
//! processo fica sinalizado, pelo mesmo caminho de um fim pedido pelo modo
//! usuário. Só processos de usuário terminam assim. Depois de cada pedido o
//! item volta para a fila.

use alloc::string::String;
use core::fmt::Write;
use core::mem::offset_of;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::packet::Payload;
use super::{memory, monitor, process_context, stop};
use crate::ntos::inc::types::Eprocess;
use crate::ntos::io::work_items;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user::process_state;
use crate::ntos::ps::{create, process};

/// O work item do fim (0 antes do [`initialize`]).
static WORK_ITEM: AtomicU64 = AtomicU64::new(0);
/// O PID do processo a encerrar (0 = nenhum pedido; o PID 0 é o Idle).
static REQUEST_PID: AtomicU64 = AtomicU64::new(0);
/// O código de saída do pedido, publicado antes do PID.
static REQUEST_STATUS: AtomicU32 = AtomicU32::new(0);
/// O processo System.
const SYSTEM_PID: u64 = 4;

const USAGE: &str = "uso: kill <pid|eprocess> <codigo em hexadecimal>\n";

/// Com o depurador ligado (`--kd`), reserva o work item e o põe na fila, à
/// espera de um pedido. Chamada uma vez no boot, depois do pool e antes do
/// primeiro processo de usuário.
pub fn initialize() {
    if !stop::active() || WORK_ITEM.load(Ordering::Acquire) != 0 {
        return;
    }
    let item = guest::alloc_bytes(work_items::work_item_size());
    if item == 0 {
        crate::debug_print!("[kd] work item do kill nao reservado: o comando fica desligado");
        return;
    }
    WORK_ITEM.store(item, Ordering::Release);
    work_items::queue_kernel_work_item(item, run, 0, Some(requested));
}

/// O predicado de prontidão do work item: há um pedido.
fn requested() -> bool {
    REQUEST_PID.load(Ordering::Acquire) != 0
}

/// `kill <pid|eprocess> <código>`, com a máquina parada: confere o processo
/// e arma o pedido.
pub fn command(owner: usize, argument: &str, out: &mut Payload) {
    let cr3 = stop::address_space(owner);
    let mut words = argument.split_whitespace();
    let (Some(process_text), Some(status_text), None) = (words.next(), words.next(), words.next()) else {
        out.push_str(USAGE);
        return;
    };
    let Ok(status) = u32::from_str_radix(status_text.trim_start_matches("0x"), 16) else {
        out.push_str(USAGE);
        return;
    };
    if WORK_ITEM.load(Ordering::Acquire) == 0 {
        out.push_str("o work item do kill nao foi reservado\n");
        return;
    }
    if REQUEST_PID.load(Ordering::Acquire) != 0 {
        let _ = writeln!(out, "o fim do processo {} ainda nao rodou (a maquina precisa seguir)", REQUEST_PID.load(Ordering::Acquire));
        return;
    }
    let Some(eprocess) = process_context::resolve(cr3, process_text) else {
        let _ = writeln!(out, "{}: processo nao encontrado (ou a lista de processos esta ocupada)", process_text);
        return;
    };
    let pid = memory::read_u64(cr3, eprocess + offset_of!(Eprocess, unique_process_id) as u64).unwrap_or(0);
    if pid == 0 || pid == SYSTEM_PID {
        let _ = writeln!(out, "o processo {} e do sistema", pid);
        return;
    }
    REQUEST_STATUS.store(status, Ordering::Relaxed);
    REQUEST_PID.store(pid, Ordering::Release);
    let mut name = [0u8; 16];
    let length = monitor::process_name(cr3, eprocess, &mut name);
    let _ = write!(out, "processo {} (", pid);
    monitor::push_name(out, &name[..length]);
    let _ = writeln!(out, ", EPROCESS {:#x}) sera encerrado com o codigo {:#x} quando a maquina seguir", eprocess, status);
}

/// A rotina do work item (o dispositivo, nenhum, e o contexto), a
/// PASSIVE_LEVEL numa worker: encerra o processo pedido e devolve o item à
/// fila.
fn run(_device: u64, _context: u64) {
    let pid = REQUEST_PID.load(Ordering::Acquire);
    let status = REQUEST_STATUS.load(Ordering::Relaxed);
    match terminate(pid, status) {
        Ok(name) => crate::debug_print!("[kd] processo {} ({}) encerrado a pedido do depurador: codigo {:#x}", pid, name, status),
        Err(reason) => crate::debug_print!("[kd] fim do processo {} pedido pelo depurador recusado: {}", pid, reason),
    }
    REQUEST_PID.store(0, Ordering::Release);
    work_items::queue_kernel_work_item(WORK_ITEM.load(Ordering::Acquire), run, 0, Some(requested));
}

/// O PspTerminateProcess do processo `pid` com `status`, se ele ainda é um
/// processo de usuário vivo.
fn terminate(pid: u64, status: u32) -> Result<String, &'static str> {
    let entry = process::list_active_processes().into_iter().find(|entry| entry.pid == pid).ok_or("o processo ja saiu")?;
    if process_state::get(entry.address).is_none() {
        return Err("nao e um processo de usuario");
    }
    process::reference(entry.address).ok_or("o processo ja saiu")?;
    let accepted = create::exit_process(entry.address, status);
    let _ = process::dereference(entry.address);
    if accepted {
        Ok(entry.name)
    } else {
        Err("o fim dele ja tinha sido pedido")
    }
}
