//! Perfil por amostragem do processador de boot (opção de carga `PROFILE`,
//! `--perfil` do xtask). Ferramenta de medição do OpenNT, fora da semântica
//! do NT: sem a opção nada aqui roda e os trampolins só leem dois bytes.
//!
//! Fontes de amostra:
//! - `PROFILE=timer`: o tique do timer do LAPIC (vetor 0x40, 100 Hz). Só vê o
//!   que roda com IF=1: o anel 3, o despachante, as threads de kernel e o
//!   laço ocioso. Um serviço roda com IF=0 do SYSCALL ao IRETQ, então o
//!   tique pendente durante ele cai na primeira instrução de volta ao anel 3
//!   (o `ret` do stub da ntdll ou do win32u).
//! - `PROFILE=nmi`: a NMI que o xtask injeta pelo QMP (`inject-nmi`) num
//!   ritmo próprio, sem relação com o relógio do convidado. Vê também o
//!   código com IF=0 (os serviços e os ISRs).
//!
//! O trampolim (`hal/amd64/irqstubs.rs`) chama [`opennt_sampler_record`] com
//! o RIP, o CS e o RSP do quadro, o CR3 e o RBP: a amostra vai para um anel
//! sem trava (nada de GS, de trava ou de alocação, porque a NMI chega em
//! qualquer ponto). No anel 0 a amostra leva também a cadeia de frame
//! pointers (o kernel compila com `force-frame-pointers`), conferida página
//! a página pelas tabelas antes de cada leitura e presa à pilha da
//! interrupção.
//!
//! O tique do escalonador esvazia o anel ([`drain`]) e agrega por janela:
//! no anel 3, (pid, módulo+deslocamento) pela região do VAD; no anel 0, a
//! pilha crua (o xtask resolve os nomes pelo `kernel.elf`) ou, fora da
//! imagem do kernel, o driver+deslocamento pela lista de imagens. Os
//! serviços também são contados por (pid, número): chamadas, falhas, tempo
//! dos que voltaram sem trocar de thread e quantos trocaram ([`note_service`]).
//! A cada linha `[perf]` ([`report`]) a janela vai para a serial em linhas
//! `[pf]` compactas; `cargo xtask perfil <serial.log>` as soma e resolve.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use crate::hal::cpu;
use crate::ntos::init::boot_config;
use crate::ntos::ke::clock;
use crate::ntos::mm::memory_map::KERNEL_VIRTUAL_BASE;
use crate::ntos::mm::{guest_memory as guest, loaded_images, paging};
use crate::ntos::ps::{dispatch_perf, process_accessors};
use crate::ntos::ps::user::memory::Space;
use crate::ntos::ps::user::process_state;
use crate::rtl::SpinLock;

/// Amostra no tique do relógio (lido pelo trampolim do vetor 0x40).
#[export_name = "opennt_sampler_timer"]
static SAMPLE_TIMER: AtomicU8 = AtomicU8::new(0);
/// Amostra na NMI (lido pelo trampolim da NMI, sem o depurador ligado).
#[export_name = "opennt_sampler_nmi"]
static SAMPLE_NMI: AtomicU8 = AtomicU8::new(0);

/// Endereços de retorno guardados de uma amostra do anel 0.
const FRAMES: usize = 12;
/// Posições do anel: o tique o esvazia a cada 10 ms.
const RING: usize = 4096;
/// A cadeia de frames fica dentro desta distância do RSP interrompido.
const STACK_SPAN: u64 = 0x1_0000;
const KERNEL_HALF: u64 = 0xFFFF_8000_0000_0000;
const ROOT_MASK: u64 = 0x000F_FFFF_FFFF_F000;

struct Slot {
    /// Índice de escrita + 1, publicado depois dos campos.
    sequence: AtomicU64,
    rip: AtomicU64,
    /// CR3 (sem os bits baixos) | CPL do CS interrompido.
    root_cpl: AtomicU64,
    frames: [AtomicU64; FRAMES],
}

impl Slot {
    const fn new() -> Self {
        Self { sequence: AtomicU64::new(0), rip: AtomicU64::new(0), root_cpl: AtomicU64::new(0), frames: [const { AtomicU64::new(0) }; FRAMES] }
    }
}

static SLOTS: [Slot; RING] = [const { Slot::new() }; RING];
static WRITE: AtomicU64 = AtomicU64::new(0);
static READ: AtomicU64 = AtomicU64::new(0);
/// Amostras descartadas com o anel cheio.
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Liga a fonte pedida em `PROFILE` (chamado na fase 0, antes das IRQs).
pub fn initialize() {
    match boot_config::profile() {
        None => {}
        Some("nmi") => {
            SAMPLE_NMI.store(1, Ordering::Release);
            crate::debug_print!("[perfil] amostragem pela NMI injetada pelo host");
        }
        Some(_) => {
            SAMPLE_TIMER.store(1, Ordering::Release);
            crate::debug_print!("[perfil] amostragem pelo tique do relogio (100 Hz)");
        }
    }
}

/// O perfil está ligado.
pub fn enabled() -> bool {
    SAMPLE_TIMER.load(Ordering::Relaxed) | SAMPLE_NMI.load(Ordering::Relaxed) != 0
}

/// A página da VA está presente na raiz corrente (leitura das tabelas, sem
/// trava: a NMI pode chegar com qualquer trava tomada).
fn present(address: u64) -> bool {
    paging::translate(address & !0xFFF) != 0
}

/// Grava uma amostra (chamado pelos trampolins do tique e da NMI, com as
/// interrupções desligadas e IF/DF do quadro já salvos). Sem trava, sem GS
/// e sem alocação.
#[no_mangle]
pub extern "sysv64" fn opennt_sampler_record(rip: u64, cs: u64, root: u64, rbp: u64, rsp: u64) {
    // A posição só é tomada com lugar no anel: uma posição tomada é sempre
    // publicada, e o leitor nunca espera por uma que ninguém vai escrever.
    let mut index = WRITE.load(Ordering::Acquire);
    loop {
        if index.wrapping_sub(READ.load(Ordering::Acquire)) >= RING as u64 {
            DROPPED.fetch_add(1, Ordering::Relaxed);
            return;
        }
        match WRITE.compare_exchange_weak(index, index + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(current) => index = current,
        }
    }
    let slot = &SLOTS[index as usize % RING];
    slot.rip.store(rip, Ordering::Relaxed);
    slot.root_cpl.store((root & ROOT_MASK) | (cs & 3), Ordering::Relaxed);
    let mut frame = rbp;
    for cell in &slot.frames {
        let mut value = 0;
        if cs & 3 == 0 && frame >= KERNEL_HALF && frame & 7 == 0 && frame >= rsp && frame - rsp < STACK_SPAN && present(frame) && present(frame + 8) {
            // SAFETY: as duas páginas estão presentes (conferido acima) e a
            // VA é do kernel; a leitura não altera nada.
            let (next, ret) = unsafe { (core::ptr::read_volatile(frame as *const u64), core::ptr::read_volatile((frame + 8) as *const u64)) };
            value = ret;
            frame = if next > frame { next } else { 0 };
        } else {
            frame = 0;
        }
        cell.store(value, Ordering::Relaxed);
    }
    slot.sequence.store(index + 1, Ordering::Release);
}

/// Um processo visto pelas amostras: a raiz, o EPROCESS e o PID.
#[derive(Clone, Copy)]
struct Owner {
    process: u64,
    pid: u64,
}

/// Uma região de imagem ou de memória de usuário, resolvida uma vez.
struct Module {
    base: u64,
    size: u64,
    name: String,
}

/// O que um serviço somou na janela.
#[derive(Default, Clone, Copy)]
struct ServiceCost {
    calls: u64,
    failures: u64,
    /// TSC dos que voltaram sem trocar de thread no meio.
    tsc: u64,
    /// Os que trocaram de thread (bloquearam) no meio: o tempo deles fica
    /// fora.
    switched: u64,
}

#[derive(Default)]
struct Window {
    samples: u64,
    /// (pid, módulo, deslocamento) -> amostras do anel 3.
    user: BTreeMap<(u64, String, u64), u64>,
    /// (pid, RIP, frames) -> amostras do anel 0.
    kernel: BTreeMap<(u64, u64, [u64; FRAMES]), u64>,
    /// (pid, número) -> custo do serviço.
    services: BTreeMap<(u64, u32), ServiceCost>,
}

struct Aggregate {
    window: Window,
    /// Raiz -> dono, refeito quando uma raiz não é achada.
    owners: BTreeMap<u64, Owner>,
    /// (EPROCESS, base) -> módulo do anel 3.
    modules: BTreeMap<u64, Vec<Module>>,
    /// PIDs já descritos na serial (`[pf] p`).
    named: BTreeMap<u64, ()>,
}

static AGGREGATE: SpinLock<Aggregate> = SpinLock::new(Aggregate { window: Window { samples: 0, user: BTreeMap::new(), kernel: BTreeMap::new(), services: BTreeMap::new() }, owners: BTreeMap::new(), modules: BTreeMap::new(), named: BTreeMap::new() });

impl Aggregate {
    fn owner(&mut self, root: u64) -> Option<Owner> {
        if let Some(owner) = self.owners.get(&root).copied() {
            if process_state::get(owner.process).is_some_and(|state| state.directory_table_base.load(Ordering::Relaxed) & ROOT_MASK == root) {
                return Some(owner);
            }
        }
        self.owners.clear();
        self.modules.clear();
        for state in process_state::all() {
            let root = state.directory_table_base.load(Ordering::Relaxed) & ROOT_MASK;
            self.owners.entry(root).or_insert(Owner { process: state.process, pid: state.process_id });
        }
        self.owners.get(&root).copied()
    }

    fn user_module(&mut self, owner: Owner, address: u64) -> (String, u64) {
        let list = self.modules.entry(owner.process).or_default();
        if let Some(module) = list.iter().find(|module| address >= module.base && address - module.base < module.size) {
            return (module.name.clone(), address - module.base);
        }
        let region = Space::of(owner.process).find(address).filter(|region| region.name().is_some()).or_else(|| Space::system().find(address).filter(|region| region.name().is_some()));
        match region {
            Some(region) => {
                let path = region.name().unwrap_or_default();
                let name = String::from(path.rsplit(['\\', '/']).next().unwrap_or(&path));
                list.push(Module { base: region.base(), size: region.size(), name: name.clone() });
                (name, address - region.base())
            }
            None => (String::from("?"), address),
        }
    }
}

/// Esvazia o anel na janela corrente (chamado pelo tique do escalonador).
pub fn drain() {
    if !enabled() {
        return;
    }
    let mut aggregate = AGGREGATE.lock();
    loop {
        let index = READ.load(Ordering::Relaxed);
        let slot = &SLOTS[index as usize % RING];
        let sequence = slot.sequence.load(Ordering::Acquire);
        if sequence != index + 1 {
            // A posição ainda não foi publicada (o escritor foi interrompido
            // entre tomá-la e publicá-la, ou não há mais amostras).
            break;
        }
        let rip = slot.rip.load(Ordering::Relaxed);
        let root_cpl = slot.root_cpl.load(Ordering::Relaxed);
        let frames: [u64; FRAMES] = core::array::from_fn(|position| slot.frames[position].load(Ordering::Relaxed));
        READ.store(index + 1, Ordering::Release);
        let owner = aggregate.owner(root_cpl & ROOT_MASK);
        let pid = owner.map_or(0, |owner| owner.pid);
        aggregate.window.samples += 1;
        if root_cpl & 3 == 3 {
            let (name, offset) = match owner {
                Some(owner) => aggregate.user_module(owner, rip),
                None => (String::from("?"), rip),
            };
            *aggregate.window.user.entry((pid, name, offset)).or_insert(0) += 1;
        } else {
            *aggregate.window.kernel.entry((pid, rip, frames)).or_insert(0) += 1;
        }
    }
}

/// O TSC na entrada de um serviço e o número de intervalos de usuário então:
/// se o número mudou na saída, a thread trocou (bloqueou) no meio.
pub fn service_start() -> (u64, u64) {
    if !enabled() {
        return (0, 0);
    }
    (cpu::rdtsc(), dispatch_perf::slices())
}

/// O fim de um serviço `number` que começou em `start` e devolveu `result`.
pub fn note_service(number: u64, start: (u64, u64), result: u64) {
    if start.0 == 0 {
        return;
    }
    let elapsed = cpu::rdtsc().wrapping_sub(start.0);
    let switched = dispatch_perf::slices() != start.1;
    let pid = crate::ntos::ps::process::get_current_process_id();
    let mut aggregate = AGGREGATE.lock();
    let cost = aggregate.window.services.entry((pid, number as u32)).or_default();
    cost.calls += 1;
    if result & 0x8000_0000 != 0 {
        cost.failures += 1;
    }
    if switched {
        cost.switched += 1;
    } else {
        cost.tsc += elapsed;
    }
}

fn microseconds(tsc: u64) -> u64 {
    tsc / (clock::tsc_frequency_hz() / 1_000_000).max(1)
}

/// O nome curto do processo de um PID (ImageFileName).
fn process_name(process: u64) -> String {
    let bytes = guest::read_bytes(process_accessors::image_file_name(process), 15);
    bytes.iter().take_while(|&&byte| byte != 0).map(|&byte| byte as char).collect()
}

/// Escreve a janela em linhas `[pf]` e a zera (chamado por
/// `dispatch_perf::report_if_due`, depois da linha `[perf]`).
///
/// - `[pf] p <pid> <nome>`: o nome de um PID, na primeira vez;
/// - `[pf] u <pid> <amostras> <módulo>+<desl>`: o anel 3;
/// - `[pf] k <pid> <amostras> <rip> <ret>...`: o anel 0, cada endereço em
///   hexadecimal relativo à base da janela (a ImageBase do kernel, na linha
///   `[pf] janela`), o que encurta a linha dos endereços do kernel;
/// - `[pf] s <pid> <chamadas> <falhas> <us> <trocas> <número>`: o número do
///   serviço em hexadecimal (o xtask dá o nome pelos stubs da ntdll e do
///   win32u).
pub fn report() {
    if !enabled() {
        return;
    }
    drain();
    let (window, new_names) = {
        let mut aggregate = AGGREGATE.lock();
        let window = core::mem::take(&mut aggregate.window);
        let mut new_names = Vec::new();
        let pids: Vec<u64> = window.user.keys().map(|key| key.0).chain(window.kernel.keys().map(|key| key.0)).chain(window.services.keys().map(|key| key.0)).collect();
        for pid in pids {
            if aggregate.named.insert(pid, ()).is_none() {
                let process = aggregate.owners.values().find(|owner| owner.pid == pid).map(|owner| owner.process);
                new_names.push((pid, process));
            }
        }
        (window, new_names)
    };
    crate::debug_print!("[pf] janela {} amostras ({} perdidas no total) base {:x}", window.samples, DROPPED.load(Ordering::Relaxed), KERNEL_VIRTUAL_BASE);
    for (pid, process) in new_names {
        let name = process.map_or_else(|| String::from("?"), process_name);
        crate::debug_print!("[pf] p {} {}", pid, name);
    }
    let mut line = String::new();
    for ((pid, module, offset), count) in &window.user {
        line.clear();
        let _ = write!(line, "[pf] u {pid} {count} {module}+{offset:x}");
        crate::debug_print!("{}", line);
    }
    for ((pid, rip, frames), count) in &window.kernel {
        line.clear();
        let _ = write!(line, "[pf] k {pid} {count} {:x}", rip.wrapping_sub(KERNEL_VIRTUAL_BASE));
        for frame in frames.iter().take_while(|&&frame| frame != 0) {
            let _ = write!(line, " {:x}", frame.wrapping_sub(KERNEL_VIRTUAL_BASE));
        }
        crate::debug_print!("{}", line);
    }
    for ((pid, number), cost) in &window.services {
        crate::debug_print!("[pf] s {} {} {} {} {} {:x}", pid, cost.calls, cost.failures, microseconds(cost.tsc), cost.switched, number);
    }
}

/// Imagens de kernel fora do próprio kernel, para quem lê o perfil:
/// `[pf] m <base> <tamanho> <nome>` de cada uma (no primeiro relatório e a
/// cada imagem nova).
pub fn report_images() {
    if !enabled() {
        return;
    }
    static REPORTED: SpinLock<BTreeMap<u64, ()>> = SpinLock::new(BTreeMap::new());
    let images = loaded_images::list();
    let mut reported = REPORTED.lock();
    for image in images {
        if reported.insert(image.image_base, ()).is_none() {
            crate::debug_print!("[pf] m {:x} {:x} {}", image.image_base, image.size_of_image, image.name);
        }
    }
}
