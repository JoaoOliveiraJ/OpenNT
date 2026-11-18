//! Censo do heap do kernel: bytes e blocos vivos por local de alocação.
//!
//! Cada bloco do `kmalloc` guarda no cabeçalho o índice do local que o pediu.
//! O local é a cadeia dos endereços de retorno de quem chamou o alocador,
//! lida pelos frame pointers (o kernel é compilado com
//! `force-frame-pointers`) só dentro da pilha de kernel da thread corrente
//! (StackLimit..StackBase da KTHREAD, ou a pilha de boot): um RBP fora dela
//! encerra a cadeia, e um retorno fora da imagem do kernel (código de um
//! driver convidado) também. A tabela dos locais mora em frames físicos fixos
//! fora do heap (`memory_map::KERNEL_HEAP_CENSUS_PHYS`, pelo mapa direto),
//! então contar não tira nada do heap; ela só é tocada com o lock do heap
//! adquirido. Um local que não cabe na tabela (ou um bloco de antes dela)
//! conta no local 0.
//!
//! O censo vai para a serial na falha do heap (`[heap-census]`, todos os
//! locais grandes) e, com a opção de carga HEAPCENSUS, cada vez que o uso
//! passa um múltiplo novo de [`WATERMARK_STEP`] (os maiores locais). Os
//! retornos saem como offsets da imagem do kernel (a base vem na linha de
//! abertura); `cargo xtask heap-census` dá os nomes pelos símbolos do
//! kernel.elf do build.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::ntos::inc::types::{Kthread, NtStruct};
use crate::ntos::ke::pcr;
use crate::ntos::mm::kernel_stack;
use crate::ntos::mm::memory_map as map;

/// Retornos guardados por local.
pub const DEPTH: usize = 8;
/// Um retorno fora da imagem do kernel (a cadeia para nele).
pub const FOREIGN: u32 = u32::MAX;
/// O passo dos avisos de uso com HEAPCENSUS (4 MB).
pub const WATERMARK_STEP: usize = 4 << 20;

/// A cadeia de retornos de uma alocação (offsets da imagem do kernel).
pub type Chain = [u32; DEPTH];

#[repr(C)]
#[derive(Clone, Copy)]
struct Site {
    chain: Chain,
    /// Bytes vivos (tamanho dos blocos, sem cabeçalho).
    bytes: u64,
    /// Blocos vivos.
    blocks: u32,
    /// Alocações feitas por este local desde o boot.
    allocations: u32,
}

const SITE_SIZE: u64 = core::mem::size_of::<Site>() as u64;
const SITE_COUNT: usize = (map::KERNEL_HEAP_CENSUS_SIZE / SITE_SIZE) as usize;
/// Tentativas de sondagem linear antes de desistir (o bloco vai ao local 0).
const PROBES: usize = 64;

const _: () = assert!(SITE_SIZE == 48 && SITE_COUNT >= 32768 && SITE_COUNT <= u32::MAX as usize);

/// A tabela existe (a faixa física é RAM utilizável e foi zerada).
static ENABLED: AtomicBool = AtomicBool::new(false);

fn sites() -> *mut Site {
    map::direct_map(map::KERNEL_HEAP_CENSUS_PHYS) as *mut Site
}

/// Zera a tabela. Chamado pelo `kmalloc::init` antes do primeiro bloco,
/// com `usable` = a faixa da tabela é RAM utilizável no E820.
pub fn init(usable: bool) {
    if !usable {
        return;
    }
    // SAFETY: frames fixos da tabela, fora do heap, do PFN e da imagem
    // (`memory_map`), alcançados pelo mapa direto do stage2.
    unsafe { core::ptr::write_bytes(sites() as *mut u8, 0, map::KERNEL_HEAP_CENSUS_SIZE as usize) };
    ENABLED.store(true, Ordering::Release);
}

/// A pilha de kernel em que `rsp` está: a da thread corrente ou a de boot.
fn stack_bounds(rsp: u64) -> Option<(u64, u64)> {
    let thread = pcr::current_thread();
    if thread != 0 {
        // SAFETY: a KTHREAD da thread corrente.
        let thread = unsafe { Kthread::at(thread) };
        let (low, high) = (thread.stack_limit.get(), thread.stack_base.get());
        if low < high && (low..high).contains(&rsp) {
            return Some((low, high));
        }
    }
    if (map::BOOT_STACK_LIMIT..map::BOOT_STACK_TOP).contains(&rsp) {
        return Some((map::BOOT_STACK_LIMIT, map::BOOT_STACK_TOP));
    }
    // Uma pilha de kernel que a KTHREAD não descreve agora (a troca de pilha
    // em curso): as páginas da pilha ficam no topo da reserva dela, então
    // de RSP até o fim da reserva tudo está mapeado.
    if map::is_kernel_stack(rsp) {
        let top = (rsp & !(kernel_stack::SLOT_SIZE - 1)) + kernel_stack::SLOT_SIZE;
        return Some((rsp, top));
    }
    None
}

/// A cadeia de quem chamou o alocador. O próprio frame desta função fica de
/// fora; o primeiro retorno é o da função que a chamou (o alocador).
#[inline(never)]
pub fn capture() -> Chain {
    let mut chain = [0u32; DEPTH];
    if !ENABLED.load(Ordering::Relaxed) {
        return chain;
    }
    let (frame, rsp): (u64, u64);
    // SAFETY: só lê RBP e RSP.
    unsafe { core::arch::asm!("mov {}, rbp", "mov {}, rsp", out(reg) frame, out(reg) rsp, options(nomem, nostack, preserves_flags)) };
    let Some((low, high)) = stack_bounds(rsp) else { return chain };
    let mut frame = frame;
    let mut skip = 1;
    let mut index = 0;
    while index < DEPTH {
        if frame < rsp.max(low) || frame % 8 != 0 || frame > high - 16 {
            break;
        }
        // SAFETY: [frame, frame + 16) está dentro da pilha de kernel corrente,
        // toda mapeada.
        let (next, ret) = unsafe { ((frame as *const u64).read_volatile(), ((frame + 8) as *const u64).read_volatile()) };
        if skip > 0 {
            skip -= 1;
        } else {
            let foreign = !map::is_kernel_image(ret);
            chain[index] = if foreign { FOREIGN } else { (ret - map::KERNEL_VIRTUAL_BASE) as u32 };
            index += 1;
            if foreign {
                break;
            }
        }
        if next <= frame {
            break;
        }
        frame = next;
    }
    chain
}

fn hash(chain: &Chain) -> usize {
    let mut value: u32 = 0x811C_9DC5;
    for &word in chain {
        value = (value ^ word).wrapping_mul(0x0100_0193);
    }
    value as usize
}

/// O índice do local da cadeia (inserido se novo); 0 quando a tabela não
/// existe, a cadeia é vazia ou não há lugar. Um local sem blocos vivos é
/// reaproveitado por uma cadeia nova (nenhum cabeçalho aponta para ele), e a
/// tabela guarda os locais vivos mesmo depois de ter visto mais cadeias do
/// que cabem nela. Com o lock do heap.
fn site_of(chain: &Chain) -> u32 {
    if !ENABLED.load(Ordering::Relaxed) || chain[0] == 0 {
        return 0;
    }
    let start = hash(chain);
    let mut reusable = None;
    for probe in 0..PROBES {
        // O local 0 é o dos blocos sem local; a sondagem não passa por ele.
        let index = 1 + (start + probe) % (SITE_COUNT - 1);
        // SAFETY: índice dentro da tabela; acesso exclusivo com o lock do heap.
        let site = unsafe { &mut *sites().add(index) };
        if site.chain == *chain {
            return index as u32;
        }
        if site.chain[0] == 0 {
            // Fim da sequência: a cadeia não está na tabela.
            let index = reusable.unwrap_or(index);
            // SAFETY: idem.
            let site = unsafe { &mut *sites().add(index) };
            *site = Site { chain: *chain, bytes: 0, blocks: 0, allocations: 0 };
            return index as u32;
        }
        if site.blocks == 0 && reusable.is_none() {
            reusable = Some(index);
        }
    }
    // Sequência cheia: o primeiro local morto dela, se houver.
    let Some(index) = reusable else { return 0 };
    // SAFETY: índice dentro da tabela; lock do heap.
    unsafe { *sites().add(index) = Site { chain: *chain, bytes: 0, blocks: 0, allocations: 0 } };
    index as u32
}

/// Conta o bloco de `size` bytes alocado pela cadeia; devolve o índice do
/// local para o cabeçalho. Com o lock do heap.
pub fn record(chain: &Chain, size: usize) -> u32 {
    if !ENABLED.load(Ordering::Relaxed) {
        return 0;
    }
    let index = site_of(chain);
    // SAFETY: índice devolvido por `site_of` (ou 0); lock do heap.
    let site = unsafe { &mut *sites().add(index as usize) };
    site.bytes += size as u64;
    site.blocks += 1;
    site.allocations = site.allocations.wrapping_add(1);
    index
}

/// Um local do censo, copiado da tabela.
#[derive(Clone, Copy, Debug)]
pub struct Entry {
    pub index: u32,
    pub bytes: u64,
    pub blocks: u32,
    pub allocations: u32,
    pub chain: Chain,
}

/// O local `index` (`None` sem a tabela ou fora dela). Com o lock do heap.
pub fn entry(index: u32) -> Option<Entry> {
    if !ENABLED.load(Ordering::Relaxed) || index as usize >= SITE_COUNT {
        return None;
    }
    // SAFETY: índice dentro da tabela; lock do heap.
    let site = unsafe { &*sites().add(index as usize) };
    Some(Entry { index, bytes: site.bytes, blocks: site.blocks, allocations: site.allocations, chain: site.chain })
}

/// Desconta o bloco de `size` bytes do local `index`. Com o lock do heap.
pub fn forget(index: u32, size: usize) {
    if !ENABLED.load(Ordering::Relaxed) || index as usize >= SITE_COUNT {
        return;
    }
    // SAFETY: índice dentro da tabela; lock do heap.
    let site = unsafe { &mut *sites().add(index as usize) };
    site.bytes = site.bytes.saturating_sub(size as u64);
    site.blocks = site.blocks.saturating_sub(1);
}

/// Imprime os locais com mais bytes vivos, do maior para o menor: até
/// `limit` linhas, parando quando o que falta somar fica abaixo de
/// `minimum` bytes por local. Não aloca (roda com o heap cheio e com o lock
/// dele adquirido).
pub fn print(reason: &str, used: usize, total: usize, limit: usize, minimum: u64) {
    if !ENABLED.load(Ordering::Relaxed) {
        crate::debug_print!("[heap-census] {}: tabela indisponivel", reason);
        return;
    }
    let table = sites();
    let (mut live_sites, mut live_blocks) = (0usize, 0u64);
    for index in 0..SITE_COUNT {
        // SAFETY: índice dentro da tabela; lock do heap.
        let site = unsafe { &*table.add(index) };
        if site.blocks != 0 {
            live_sites += 1;
            live_blocks += site.blocks as u64;
        }
    }
    crate::debug_print!(
        "[heap-census] {}: usado={:#x} total={:#x} blocos={} locais={} base={:#x}",
        reason, used, total, live_blocks, live_sites, map::KERNEL_VIRTUAL_BASE
    );
    // Seleção repetida do próximo maior (bytes, índice) abaixo do último
    // impresso: sem vetor auxiliar.
    let mut last: Option<(u64, usize)> = None;
    for rank in 0..limit {
        let mut best: Option<(u64, usize)> = None;
        for index in 0..SITE_COUNT {
            // SAFETY: índice dentro da tabela; lock do heap.
            let bytes = unsafe { (*table.add(index)).bytes };
            if bytes == 0 {
                continue;
            }
            let key = (bytes, index);
            if last.is_some_and(|last| key >= last) {
                continue;
            }
            if best.is_none_or(|best| key > best) {
                best = Some(key);
            }
        }
        let Some((bytes, index)) = best else { break };
        if bytes < minimum {
            break;
        }
        last = best;
        // SAFETY: índice dentro da tabela; lock do heap.
        let site = unsafe { &*table.add(index) };
        crate::rtl::print::write_args(format_args!("[heap-census] #{} bytes={:#x} blocos={} alocacoes={} local={} cadeia=", rank + 1, bytes, site.blocks, site.allocations, index));
        for &word in site.chain.iter().take_while(|&&word| word != 0) {
            if word == FOREIGN {
                crate::rtl::print::write_args(format_args!(" ?"));
            } else {
                crate::rtl::print::write_args(format_args!(" {:x}", word));
            }
        }
        crate::rtl::print::debug_print_args(format_args!(""));
    }
}
