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
//!
//! Carga de imagem filtrada no alvo: com o `QOpenNTLoadBreak:nome;nome...`
//! o host diz quais imagens o interessam (os módulos dos breakpoints
//! adiados, das paradas por carga de módulo e das DLLs dos eventos `ld:`;
//! `*` = qualquer uma). Uma carga cujo nome-base, ou o nome sem a extensão,
//! está no filtro para a máquina em `opennt_kd_load_break` com os mesmos
//! argumentos do evento (`stop::load_break`), e a resposta de parada leva
//! `library:;load:base,tamanho,pid,nome;`. As outras cargas não param: no
//! KD do 19041 cada carga de módulo de sistema manda um estado ao host e
//! espera a continuação (uma ida e volta por imagem); aqui não há ida e
//! volta nenhuma sem um pedido que case. O host relê a lista de módulos na
//! parada seguinte pela impressão digital da resposta de parada
//! (`monitor::module_generation`).

use core::fmt::Write;
use core::sync::atomic::{fence, AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

use super::packet::Payload;
use super::{session, stop};
use crate::hal::cpu;
use crate::ntos::ps::process;

static LAST_PROCESS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
static LAST_THREAD: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
static LAST_IMAGE: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

/// Nomes do filtro de carga: até `FILTER_NAMES` nomes de até
/// `FILTER_NAME_SIZE` bytes, em minúsculas. Um nome a mais ou longo demais
/// liga o `FILTER_ANY` (parar a mais é seguro: o host segue sozinho).
const FILTER_NAMES: usize = 32;
const FILTER_NAME_SIZE: usize = 64;
static FILTER_BYTES: [AtomicU8; FILTER_NAMES * FILTER_NAME_SIZE] = [const { AtomicU8::new(0) }; FILTER_NAMES * FILTER_NAME_SIZE];
static FILTER_LENGTHS: [AtomicU8; FILTER_NAMES] = [const { AtomicU8::new(0) }; FILTER_NAMES];
static FILTER_COUNT: AtomicU32 = AtomicU32::new(0);
static FILTER_ANY: AtomicBool = AtomicBool::new(false);
/// Versão do filtro, ímpar durante a troca (como um seqlock): o host só o
/// troca com a máquina parada, e um processador congelado no meio da
/// comparação a refaz no degelo.
static FILTER_VERSION: AtomicU32 = AtomicU32::new(0);

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
    // Sem `stop::stopped()` aqui: um processador que entra enquanto outro
    // congela a máquina fica preso no `int 3` e o repete no degelo.
    if load_filter_active() && session::attached() && load_filter_matches(name) {
        stop::load_break(base, size, process_id, pointer, length, system as u64);
    }
}

/// Há nomes no filtro de carga.
pub fn load_filter_active() -> bool {
    FILTER_ANY.load(Ordering::Acquire) || FILTER_COUNT.load(Ordering::Acquire) != 0
}

/// Troca o filtro de carga (`QOpenNTLoadBreak:nome;nome...`; vazio desliga),
/// com a máquina parada.
pub fn set_load_filter(list: &[u8]) {
    FILTER_VERSION.fetch_add(1, Ordering::AcqRel);
    let mut count = 0;
    let mut any = false;
    for name in list.split(|&byte| byte == b';').filter(|name| !name.is_empty()) {
        if name == b"*" || count == FILTER_NAMES || name.len() > FILTER_NAME_SIZE {
            any = true;
            continue;
        }
        for (offset, &byte) in name.iter().enumerate() {
            FILTER_BYTES[count * FILTER_NAME_SIZE + offset].store(byte.to_ascii_lowercase(), Ordering::Relaxed);
        }
        FILTER_LENGTHS[count].store(name.len() as u8, Ordering::Relaxed);
        count += 1;
    }
    FILTER_COUNT.store(count as u32, Ordering::Relaxed);
    FILTER_ANY.store(any, Ordering::Relaxed);
    FILTER_VERSION.fetch_add(1, Ordering::Release);
}

/// O nome `index` do filtro é igual a `candidate` (sem diferença de caixa).
fn filter_name_equals(index: usize, candidate: &[u8]) -> bool {
    let length = FILTER_LENGTHS[index].load(Ordering::Relaxed) as usize;
    candidate.len() == length && candidate.iter().enumerate().all(|(offset, &byte)| byte.to_ascii_lowercase() == FILTER_BYTES[index * FILTER_NAME_SIZE + offset].load(Ordering::Relaxed))
}

/// A imagem `name` (caminho) passa pelo filtro: o nome-base (depois da
/// última barra) ou ele sem a extensão é um dos nomes; `*` vale qualquer
/// imagem, inclusive sem nome. Uma troca do filtro no meio da comparação a
/// refaz; sem uma leitura estável, a carga para (o host decide).
fn load_filter_matches(name: Option<&str>) -> bool {
    for _ in 0..4 {
        let version = FILTER_VERSION.load(Ordering::Acquire);
        if version & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }
        let matched = FILTER_ANY.load(Ordering::Relaxed)
            || name.is_some_and(|path| {
                let base = path.rsplit(['\\', '/']).next().unwrap_or(path).as_bytes();
                let stem = base.iter().rposition(|&byte| byte == b'.').map_or(base, |dot| &base[..dot]);
                let count = (FILTER_COUNT.load(Ordering::Relaxed) as usize).min(FILTER_NAMES);
                (0..count).any(|index| filter_name_equals(index, base) || filter_name_equals(index, stem))
            });
        fence(Ordering::Acquire);
        if FILTER_VERSION.load(Ordering::Relaxed) == version {
            return matched;
        }
    }
    true
}

/// Os nomes do filtro de carga (no `monitor events`).
fn describe_load_filter(out: &mut Payload) {
    if FILTER_ANY.load(Ordering::Relaxed) {
        out.push_str("filtro de carga: qualquer imagem\n");
        return;
    }
    let count = (FILTER_COUNT.load(Ordering::Relaxed) as usize).min(FILTER_NAMES);
    if count == 0 {
        out.push_str("filtro de carga: vazio (nenhuma carga para a maquina)\n");
        return;
    }
    out.push_str("filtro de carga:");
    for index in 0..count {
        out.push(b' ');
        let length = FILTER_LENGTHS[index].load(Ordering::Relaxed) as usize;
        for offset in 0..length {
            out.push(FILTER_BYTES[index * FILTER_NAME_SIZE + offset].load(Ordering::Relaxed));
        }
    }
    out.push(b'\n');
}

/// `events`: os últimos eventos vistos.
pub fn command(out: &mut Payload) {
    let _ = writeln!(out, "processo: EPROCESS {:#x} PID {} {}", LAST_PROCESS[0].load(Ordering::Relaxed), LAST_PROCESS[1].load(Ordering::Relaxed), if LAST_PROCESS[2].load(Ordering::Relaxed) != 0 { "criado" } else { "saindo" });
    let _ = writeln!(out, "thread: PID {} TID {} ponto {}", LAST_THREAD[0].load(Ordering::Relaxed), LAST_THREAD[1].load(Ordering::Relaxed), LAST_THREAD[2].load(Ordering::Relaxed));
    let size = LAST_IMAGE[1].load(Ordering::Relaxed);
    let _ = writeln!(out, "imagem: base {:#x} tamanho {:#x}{}", LAST_IMAGE[0].load(Ordering::Relaxed), size & !(1 << 63), if size >> 63 != 0 { " (sistema)" } else { "" });
    out.push_str("simbolos dos eventos: opennt_kd_process_event(eprocess, pid, criado), opennt_kd_thread_event(pid, tid, ponto), opennt_kd_image_event(base, tamanho, pid, nome, tamanho do nome, sistema)\n");
    describe_load_filter(out);
}
