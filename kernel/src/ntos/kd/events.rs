//! Pontos de evento para o host: criação e saída de processo, criação e
//! saída de thread e carga de imagem (de sistema ou num processo de
//! usuário).
//!
//! As notificações do Ps (`ps/notify`) chamam estas funções antes de olhar
//! os registros das rotinas, também sem nenhuma rotina registrada. Cada
//! evento é uma função `extern "sysv64"` com nome fixo e argumentos inteiros
//! nos registradores da convenção (RDI, RSI, RDX, RCX, R8, R9): o host arma
//! um breakpoint na entrada dela e lê os argumentos dos registradores, como
//! o `sxe cpr`/`sxe ld` do WinDbg. Sem depurador ativo, nada acontece além
//! do teste de uma variável. O último evento de cada tipo fica guardado para
//! o `monitor events`.

use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

use super::packet::Payload;
use super::stop;
use crate::hal::cpu;
use crate::ntos::ps::process;

static LAST_PROCESS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
static LAST_THREAD: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
static LAST_IMAGE: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

/// Processo criado (`created` = 1) ou saindo (0): EPROCESS e PID.
#[no_mangle]
#[inline(never)]
pub extern "sysv64" fn opennt_kd_process_event(process: u64, process_id: u64, created: u64) {
    LAST_PROCESS[0].store(process, Ordering::Relaxed);
    LAST_PROCESS[1].store(process_id, Ordering::Relaxed);
    LAST_PROCESS[2].store(created, Ordering::Relaxed);
}

/// Thread criada (`point` 0 = Create, 1 = CreateNonSystem) ou saindo (2):
/// PID e TID.
#[no_mangle]
#[inline(never)]
pub extern "sysv64" fn opennt_kd_thread_event(process_id: u64, thread_id: u64, point: u64) {
    LAST_THREAD[0].store(process_id, Ordering::Relaxed);
    LAST_THREAD[1].store(thread_id, Ordering::Relaxed);
    LAST_THREAD[2].store(point, Ordering::Relaxed);
}

/// Imagem carregada: base, tamanho, PID (0 = imagem de sistema), o nome
/// (UTF-8 na memória do kernel, ponteiro e tamanho) e se é de sistema.
#[no_mangle]
#[inline(never)]
pub extern "sysv64" fn opennt_kd_image_event(base: u64, size: u64, process_id: u64, name: u64, name_length: u64, system: u64) {
    LAST_IMAGE[0].store(base, Ordering::Relaxed);
    LAST_IMAGE[1].store(size | system << 63, Ordering::Relaxed);
    LAST_IMAGE[2].store(process_id ^ name ^ name_length, Ordering::Relaxed);
}

/// O gancho de `ps::notify::process::notify`.
pub fn process(pointer: u64, process_id: u64, created: bool) {
    if stop::active() {
        // Um processo saindo leva os breakpoints dele (de memória, de
        // hardware e de software) antes de o espaço de endereços ser
        // desmontado: o byte original volta aos quadros de imagem que outros
        // processos executam. O host, parado no evento logo depois, já vê
        // os slots livres.
        if !created {
            super::page_breakpoints::process_exited(pointer);
            super::user_hardware::process_exited(pointer);
            if let Some(root) = super::process_context::root_of(cpu::read_cr3(), pointer) {
                super::breakpoints::process_exited(root);
            }
        }
        opennt_kd_process_event(pointer, process_id, created as u64);
    }
}

/// O gancho de `ps::notify::thread::notify` (`point` na ordem do
/// NotifyPoint: Create, CreateNonSystem, Exit).
pub fn thread(process_id: u64, thread_id: u64, point: u64) {
    if stop::active() {
        opennt_kd_thread_event(process_id, thread_id, point);
    }
}

/// O gancho de `ps::notify::image::notify`.
pub fn image(base: u64, size: u64, name: Option<&str>, system: bool, process_id: Option<u64>) {
    if !stop::active() {
        return;
    }
    let process_id = if system { 0 } else { process_id.unwrap_or_else(process::get_current_process_id) };
    let (pointer, length) = name.map_or((0, 0), |name| (name.as_ptr() as u64, name.len() as u64));
    opennt_kd_image_event(base, size, process_id, pointer, length, system as u64);
}

/// `events`: os últimos eventos vistos.
pub fn command(out: &mut Payload) {
    let _ = writeln!(out, "processo: EPROCESS {:#x} PID {} {}", LAST_PROCESS[0].load(Ordering::Relaxed), LAST_PROCESS[1].load(Ordering::Relaxed), if LAST_PROCESS[2].load(Ordering::Relaxed) != 0 { "criado" } else { "saindo" });
    let _ = writeln!(out, "thread: PID {} TID {} ponto {}", LAST_THREAD[0].load(Ordering::Relaxed), LAST_THREAD[1].load(Ordering::Relaxed), LAST_THREAD[2].load(Ordering::Relaxed));
    let size = LAST_IMAGE[1].load(Ordering::Relaxed);
    let _ = writeln!(out, "imagem: base {:#x} tamanho {:#x}{}", LAST_IMAGE[0].load(Ordering::Relaxed), size & !(1 << 63), if size >> 63 != 0 { " (sistema)" } else { "" });
    out.push_str("simbolos dos eventos: opennt_kd_process_event(eprocess, pid, criado), opennt_kd_thread_event(pid, tid, ponto), opennt_kd_image_event(base, tamanho, pid, nome, tamanho do nome, sistema)\n");
}
