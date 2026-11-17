//! Breakpoints de memória por página (o `monitor membp`), no processo
//! escolhido pelo `monitor .process`.
//!
//! Armar liga um bit reservado do endereço físico (o bit 51, quando a CPU
//! tem MAXPHYADDR menor que 52) na PTE de cada página da faixa. Qualquer
//! acesso do anel 3 à página dá então #PF com o bit RSVD no código de
//! erro: os provedores de residência do Mm recusam essa falta
//! (`mm::page_residency::fault`) e ela chega ao despacho de exceções do
//! anel 3, que chama o depurador antes da entrega (`kd::user_debug`). A
//! proteção da região (VAD) não muda: o NtQueryVirtualMemory do processo
//! responde o mesmo.
//!
//! Na falta, a página volta ao normal, o tipo pedido é conferido pelo
//! código de erro (escrita: bit W; execução: bit I/D; acesso: qualquer) e,
//! se bate, a máquina para com `membp:endereço` na resposta. A instrução
//! executa num passo da thread (TF) com a página normal, e o bit volta
//! depois do passo.
//!
//! Limites:
//! - só faltas do anel 3: uma leitura do kernel na página (um serviço que
//!   lê o buffer do processo) falha como violação de acesso;
//! - as leituras do depurador ignoram o bit (`memory::translate`);
//! - a saída do processo desarma as páginas dele (`kd::events`).

use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use super::memory;
use super::packet::Payload;
use super::process_context;
use crate::hal::cpu;

const SLOTS: usize = 16;
/// Páginas por breakpoint, no máximo.
const MAX_PAGES: u64 = 64;
const PAGE: u64 = 0x1000;
const USER_LIMIT: u64 = 0x8000_0000_0000;

/// Bits do código de erro do #PF.
const ERROR_WRITE: u32 = 1 << 1;
const ERROR_RESERVED: u32 = 1 << 3;
const ERROR_FETCH: u32 = 1 << 4;

/// O tipo de acesso vigiado.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Access {
    Any,
    Write,
    Execute,
}

impl Access {
    fn code(self) -> u8 {
        match self {
            Access::Any => 1,
            Access::Write => 2,
            Access::Execute => 3,
        }
    }

    fn from_code(code: u8) -> Option<Access> {
        match code {
            1 => Some(Access::Any),
            2 => Some(Access::Write),
            3 => Some(Access::Execute),
            _ => None,
        }
    }

    fn letter(self) -> char {
        match self {
            Access::Any => 'a',
            Access::Write => 'w',
            Access::Execute => 'x',
        }
    }

    /// A falta (código de erro) é do tipo vigiado.
    pub fn matches(self, error: u32) -> bool {
        match self {
            Access::Any => true,
            Access::Write => error & ERROR_WRITE != 0,
            Access::Execute => error & ERROR_FETCH != 0,
        }
    }
}

struct Slot {
    /// 0 = livre; senão o código do tipo.
    access: AtomicU8,
    start: AtomicU64,
    pages: AtomicU64,
    root: AtomicU64,
    eprocess: AtomicU64,
}

impl Slot {
    const fn new() -> Self {
        Slot { access: AtomicU8::new(0), start: AtomicU64::new(0), pages: AtomicU64::new(0), root: AtomicU64::new(0), eprocess: AtomicU64::new(0) }
    }
}

static TABLE: [Slot; SLOTS] = [const { Slot::new() }; SLOTS];
/// Os processadores congelados descartam o TLB no degelo (as PTEs
/// mudaram durante a parada).
static FLUSH_PENDING: AtomicBool = AtomicBool::new(false);

/// O bit reservado usado (0 = a CPU não tem bit reservado livre).
fn marker() -> u64 {
    let physical_bits = cpu::cpuid(0x8000_0008)[0] & 0xFF;
    if physical_bits == 0 || physical_bits >= 52 {
        0
    } else {
        1 << 51
    }
}

/// A PTE da página (endereço físico da entrada) pela raiz.
fn entry(root: u64, page: u64) -> Option<u64> {
    memory::pte_address(root, page)
}

fn read_entry(physical: u64) -> u64 {
    memory::read_physical_u64(physical)
}

fn write_entry(physical: u64, value: u64) {
    memory::write_physical_u64(physical, value);
}

/// Liga ou desliga o bit nas páginas de um slot.
fn set_marker(root: u64, start: u64, pages: u64, armed: bool) -> bool {
    let bit = marker();
    if bit == 0 {
        return false;
    }
    let mut all = true;
    for page in 0..pages {
        let address = start + page * PAGE;
        match entry(root, address) {
            Some(physical) => {
                let value = read_entry(physical);
                if value & 1 == 0 {
                    all = false;
                    continue;
                }
                write_entry(physical, if armed { value | bit } else { value & !bit });
                flush_page(root, address);
            }
            None => all = false,
        }
    }
    all
}

/// Descarta a página do TLB deste processador (se a raiz é a corrente) e
/// pede o descarte nos outros no degelo.
fn flush_page(root: u64, address: u64) {
    if cpu::read_cr3() & !0xFFF == root & !0xFFF {
        // SAFETY: INVLPG de uma VA de usuário, em anel 0.
        unsafe { core::arch::asm!("invlpg [{}]", in(reg) address, options(nostack)) };
    }
    FLUSH_PENDING.store(true, Ordering::Release);
}

/// O degelo de um processador congelado: descarta o TLB se as PTEs
/// mudaram (chamado por `stop` na saída da prisão).
pub fn after_thaw() {
    if FLUSH_PENDING.load(Ordering::Acquire) {
        // SAFETY: recarregar o CR3 com ele mesmo descarta as entradas não
        // globais do TLB.
        unsafe { core::arch::asm!("mov {0}, cr3", "mov cr3, {0}", out(reg) _, options(nostack)) };
    }
}

/// A máquina vai seguir: o próximo pedido de descarte começa limpo.
pub fn resume() {
    if FLUSH_PENDING.swap(false, Ordering::AcqRel) {
        after_thaw();
    }
}

/// Arma a faixa (páginas inteiras) no processo escolhido.
pub fn insert(owner: usize, start: u64, length: u64, access: Access) -> Result<(), &'static str> {
    let Some(eprocess) = process_context::selected() else { return Err("escolha o processo antes (.process)") };
    if marker() == 0 {
        return Err("a CPU nao tem bit reservado livre na PTE (MAXPHYADDR 52)");
    }
    let start = start & !(PAGE - 1);
    let pages = (length.max(1) + PAGE - 1) / PAGE;
    if start == 0 || start + pages * PAGE > USER_LIMIT || pages > MAX_PAGES {
        return Err("faixa fora da metade de usuario ou grande demais");
    }
    let root = process_context::memory_space(owner);
    if TABLE.iter().any(|slot| slot.access.load(Ordering::Acquire) != 0 && slot.root.load(Ordering::Relaxed) == root && overlaps(slot, start, pages)) {
        return Err("a faixa cruza outro breakpoint de memoria");
    }
    let Some(slot) = TABLE.iter().find(|slot| slot.access.load(Ordering::Acquire) == 0) else { return Err("sem slot livre") };
    if !set_marker(root, start, pages, true) {
        set_marker(root, start, pages, false);
        return Err("pagina ausente na faixa (toque nela antes)");
    }
    slot.start.store(start, Ordering::Relaxed);
    slot.pages.store(pages, Ordering::Relaxed);
    slot.root.store(root, Ordering::Relaxed);
    slot.eprocess.store(eprocess, Ordering::Relaxed);
    slot.access.store(access.code(), Ordering::Release);
    Ok(())
}

fn overlaps(slot: &Slot, start: u64, pages: u64) -> bool {
    let (other, count) = (slot.start.load(Ordering::Relaxed), slot.pages.load(Ordering::Relaxed));
    start < other + count * PAGE && other < start + pages * PAGE
}

/// Desarma o slot que começa em `start` (no processo escolhido, ou em
/// qualquer um).
pub fn remove(owner: usize, start: u64) -> bool {
    let root = process_context::selected().map(|_| process_context::memory_space(owner));
    let start = start & !(PAGE - 1);
    let Some(slot) = TABLE.iter().find(|slot| slot.access.load(Ordering::Acquire) != 0 && slot.start.load(Ordering::Relaxed) == start && root.is_none_or(|root| slot.root.load(Ordering::Relaxed) == root)) else { return false };
    set_marker(slot.root.load(Ordering::Relaxed), start, slot.pages.load(Ordering::Relaxed), false);
    slot.access.store(0, Ordering::Release);
    true
}

/// O host se desligou: todas as páginas voltam ao normal.
pub fn remove_all() {
    for slot in TABLE.iter() {
        if slot.access.swap(0, Ordering::AcqRel) != 0 {
            set_marker(slot.root.load(Ordering::Relaxed), slot.start.load(Ordering::Relaxed), slot.pages.load(Ordering::Relaxed), false);
        }
    }
}

/// O processo saiu: as páginas dele saem da tabela (antes de o espaço de
/// endereços ser desmontado).
pub fn process_exited(eprocess: u64) {
    for slot in TABLE.iter() {
        if slot.access.load(Ordering::Acquire) != 0 && slot.eprocess.load(Ordering::Relaxed) == eprocess {
            set_marker(slot.root.load(Ordering::Relaxed), slot.start.load(Ordering::Relaxed), slot.pages.load(Ordering::Relaxed), false);
            slot.access.store(0, Ordering::Release);
        }
    }
}

/// O slot que cobre a página de `address` na raiz.
fn find(root: u64, address: u64) -> Option<&'static Slot> {
    TABLE.iter().find(|slot| {
        let start = slot.start.load(Ordering::Relaxed);
        slot.access.load(Ordering::Acquire) != 0 && slot.root.load(Ordering::Relaxed) & !0xFFF == root & !0xFFF && address >= start && address < start + slot.pages.load(Ordering::Relaxed) * PAGE
    })
}

/// A PTE com o bit tirado, para as leituras do depurador.
pub fn unmarked(value: u64) -> u64 {
    value & !marker_cached()
}

static MARKER: AtomicU64 = AtomicU64::new(u64::MAX);

fn marker_cached() -> u64 {
    let value = MARKER.load(Ordering::Relaxed);
    if value != u64::MAX {
        return value;
    }
    let computed = marker();
    MARKER.store(computed, Ordering::Relaxed);
    computed
}

/// Há breakpoint de memória armado (as leituras conferem o bit).
pub fn any() -> bool {
    TABLE.iter().any(|slot| slot.access.load(Ordering::Acquire) != 0)
}

/// Uma falta de página do anel 3 (`error`, `cr2`) com a raiz `root`: é de
/// um breakpoint de memória? Devolve se o tipo bate e a página a rearmar
/// depois do passo. A página fica normal até lá.
pub fn fault(root: u64, cr2: u64, error: u32) -> Option<(bool, u64)> {
    if error & ERROR_RESERVED == 0 {
        return None;
    }
    let slot = find(root, cr2)?;
    let access = Access::from_code(slot.access.load(Ordering::Relaxed))?;
    let page = cr2 & !(PAGE - 1);
    set_marker(slot.root.load(Ordering::Relaxed), page, 1, false);
    Some((access.matches(error), page))
}

/// Religa o bit na página depois do passo (se o breakpoint ainda existe).
pub fn rearm(root: u64, page: u64) {
    if find(root, page).is_some() {
        set_marker(root, page, 1, true);
    }
}

/// `membp [set <inicio> <tamanho> <a|w|x> | clear <inicio>]`.
pub fn command(owner: usize, argument: &str, out: &mut Payload) {
    let words: [&str; 4] = {
        let mut iterator = argument.split_whitespace();
        [iterator.next().unwrap_or(""), iterator.next().unwrap_or(""), iterator.next().unwrap_or(""), iterator.next().unwrap_or("")]
    };
    let number = |text: &str| -> Option<u64> {
        let text = text.trim();
        match text.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).ok(),
            None => u64::from_str_radix(text, 16).ok(),
        }
    };
    match words[0] {
        "set" => {
            let access = match words[3] {
                "w" => Access::Write,
                "x" => Access::Execute,
                _ => Access::Any,
            };
            match (number(words[1]), number(words[2])) {
                (Some(start), Some(length)) => match insert(owner, start, length, access) {
                    Ok(()) => {
                        let _ = writeln!(out, "membp ok {:#x} {:#x} {}", start & !(PAGE - 1), (length.max(1) + PAGE - 1) & !(PAGE - 1), access.letter());
                    }
                    Err(error) => {
                        let _ = writeln!(out, "membp: {}", error);
                    }
                },
                _ => out.push_str("uso: membp set <inicio> <tamanho> <a|w|x>\n"),
            }
        }
        "clear" => match number(words[1]) {
            Some(start) if remove(owner, start) => {
                let _ = writeln!(out, "membp ok removido {:#x}", start & !(PAGE - 1));
            }
            _ => out.push_str("membp: nenhum breakpoint de memoria nesse inicio\n"),
        },
        _ => {
            let mut any = false;
            for slot in TABLE.iter() {
                let Some(access) = Access::from_code(slot.access.load(Ordering::Acquire)) else { continue };
                any = true;
                let _ = writeln!(out, "{:#x} {:#x} {} EPROCESS {:#x} CR3 {:#x}", slot.start.load(Ordering::Relaxed), slot.pages.load(Ordering::Relaxed) * PAGE, access.letter(), slot.eprocess.load(Ordering::Relaxed), slot.root.load(Ordering::Relaxed));
            }
            if !any {
                out.push_str("nenhum breakpoint de memoria\n");
            }
            if marker() == 0 {
                out.push_str("(esta CPU nao tem bit reservado livre na PTE: membp indisponivel)\n");
            }
        }
    }
}
