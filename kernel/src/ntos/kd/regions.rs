//! Mapas de memória para o host: as regiões de usuário de um processo (o
//! papel do EPROCESS.VadRoot, `monitor vad`), as threads de usuário dele
//! com a TEB e o CONTEXT salvo (`monitor uthreads`) e as faixas do espaço de
//! sistema (`monitor kmap`).
//!
//! As regiões e as threads de usuário moram em estruturas do Rust com
//! travas (o `ProcessState` do processo). Como a lista de módulos, essas
//! consultas só rodam quando nenhum processador parado tinha trava
//! (`stop::locks_held`): aí as travas estão livres e ninguém mais roda.

use core::fmt::Write;
use core::mem::offset_of;

use super::packet::Payload;
use super::{memory, process_context, stop};
use crate::ntos::inc::types::KthreadView1;
use crate::ntos::mm::memory_map as map;
use crate::ntos::mm::section::views::ImageView;
use crate::ntos::ps::user::loader::ImageRegion;
use crate::ntos::ps::user::memory::{PrivateRegion, SharedRegion, Space};
use crate::ntos::ps::user::process_state;
use crate::ntos::ps::user::sections::View as SectionView;
use crate::ntos::ps::user::state::Region;

/// Linhas por resposta (o texto do `qRcmd` tem tamanho fixo).
const PAGE_LINES: usize = 100;

const WAIT_REASONS: [&str; 41] = [
    "Executive", "FreePage", "PageIn", "PoolAllocation", "DelayExecution", "Suspended", "UserRequest", "WrExecutive", "WrFreePage", "WrPageIn", "WrPoolAllocation", "WrDelayExecution", "WrSuspended", "WrUserRequest", "WrSpare0", "WrQueue", "WrLpcReceive", "WrLpcReply", "WrVirtualMemory", "WrPageOut", "WrRendezvous", "WrKeyedEvent", "WrTerminated", "WrProcessInSwap", "WrCpuRateControl", "WrCalloutStack", "WrKernel", "WrResource", "WrPushLock", "WrMutex", "WrQuantumEnd", "WrDispatchInt", "WrPreempted", "WrYieldExecution", "WrFastMutex", "WrGuardedMutex", "WrRundown", "WrAlertByThreadId", "WrDeferredPreempt", "WrPhysicalFault", "WrIoRing",
];

const THREAD_STATES: [&str; 10] = ["Initialized", "Ready", "Running", "Standby", "Terminated", "Waiting", "Transition", "DeferredReady", "GateWait", "WaitingForProcessInSwap"];

/// O tipo de uma região, como o MEMORY_BASIC_INFORMATION.Type.
fn region_type(region: &Region) -> &'static str {
    let any = region.as_any();
    if any.is::<PrivateRegion>() {
        "Private"
    } else if any.is::<ImageView>() || any.is::<ImageRegion>() {
        "Image"
    } else if any.is::<SectionView>() || any.is::<SharedRegion>() {
        "Mapped"
    } else {
        "?"
    }
}

fn push_text(out: &mut Payload, text: &str, limit: usize) {
    for (index, byte) in text.bytes().enumerate() {
        if index == limit {
            out.push_str("...");
            break;
        }
        out.push(if (0x20..0x7F).contains(&byte) { byte } else { b'?' });
    }
}

/// `vad <pid|eprocess> [inicio]`: base, tamanho, tipo, proteção e nome de
/// cada região de usuário, em ordem de endereço.
pub fn vad(owner: usize, argument: &str, out: &mut Payload) {
    let cr3 = stop::address_space(owner);
    let mut words = argument.split_whitespace();
    let Some(process_text) = words.next() else {
        out.push_str("uso: vad <pid|eprocess> [indice inicial]\n");
        return;
    };
    let start = words.next().and_then(|text| text.parse::<usize>().ok()).unwrap_or(0);
    let Some(eprocess) = process_context::resolve(cr3, process_text) else {
        let _ = writeln!(out, "{}: processo nao encontrado", process_text);
        return;
    };
    if stop::locks_held() {
        out.push_str("regioes indisponiveis: um processador parado tinha trava do kernel\n");
        return;
    }
    let listed = Space::of(eprocess).with_vad(|vad| {
        let total = vad.regions.len() + vad.images.len();
        // Em ordem de endereço sem alocar: a menor base acima da anterior.
        let mut previous: Option<u64> = None;
        let _ = writeln!(out, "EPROCESS {:#x} regioes {}", eprocess, total);
        let _ = writeln!(out, "{:>18} {:>12} {:<8} {:>8} {:>8}  nome", "base", "tamanho", "tipo", "protecao", "alocacao");
        let mut index = 0;
        let mut lines = 0;
        loop {
            let next = vad.regions.iter().chain(vad.images.iter()).filter(|region| previous.is_none_or(|previous| region.base() > previous)).min_by_key(|region| region.base());
            let Some(region) = next else { break };
            previous = Some(region.base());
            if index >= start {
                if lines == PAGE_LINES {
                    let _ = writeln!(out, "mais: {}", index);
                    return;
                }
                let _ = write!(out, "{:>#18x} {:>#12x} {:<8} {:>#8x} {:>#8x}  ", region.base(), region.size(), region_type(region), region.protect(), region.allocation_protect());
                if let Some(name) = region.name() {
                    push_text(out, &name, 120);
                }
                out.push(b'\n');
                lines += 1;
            }
            index += 1;
        }
    });
    if listed.is_none() {
        let _ = writeln!(out, "EPROCESS {:#x} sem estado de processo de usuario", eprocess);
    }
}

fn read_u64(cr3: u64, address: u64) -> u64 {
    memory::read_u64(cr3, address).unwrap_or(0)
}

/// `uthreads <pid|eprocess>`: as threads de usuário do processo, com a
/// ETHREAD, a TEB, o início, o CONTEXT salvo (memória do kernel), RIP e RSP
/// de usuário, o estado, o motivo da espera e o LastErrorValue da TEB.
pub fn user_threads(owner: usize, argument: &str, out: &mut Payload) {
    let cr3 = stop::address_space(owner);
    let Some(eprocess) = process_context::resolve(cr3, argument) else {
        let _ = writeln!(out, "{}: processo nao encontrado (uso: uthreads <pid|eprocess>)", argument.trim());
        return;
    };
    if stop::locks_held() {
        out.push_str("threads indisponiveis: um processador parado tinha trava do kernel\n");
        return;
    }
    let Some(state) = process_state::get(eprocess) else {
        let _ = writeln!(out, "EPROCESS {:#x} sem estado de processo de usuario", eprocess);
        return;
    };
    let root = process_context::root_of(cr3, eprocess).unwrap_or(cr3);
    let _ = writeln!(out, "EPROCESS {:#x} CR3 {:#x}", eprocess, root);
    let _ = writeln!(out, "{:>6} {:>18} {:>14} {:>18} {:>18} {:>18} {:>14} {:<13} {:<16} {:>10} {:>4} {:>4} {:>8} {:>8} {:>14}", "TID", "ETHREAD", "TEB", "inicio", "CONTEXT", "rip", "rsp", "estado", "espera", "LastError", "prio", "susp", "kernel", "usuario", "ciclos");
    let threads = state.threads.lock();
    for (count, thread) in threads.iter().enumerate() {
        if count == PAGE_LINES {
            out.push_str("...\n");
            break;
        }
        let (ethread, teb, context, start, dead) = thread.with(|thread| (thread.thread_pointer, thread.teb_va, thread.context, thread.start, thread.dead));
        let rip = if context != 0 { read_u64(cr3, context + offset_of!(crate::ntos::inc::types::Context, rip) as u64) } else { 0 };
        let rsp = if context != 0 { read_u64(cr3, context + offset_of!(crate::ntos::inc::types::Context, rsp) as u64) } else { 0 };
        let state_code = if ethread != 0 { memory::read_u8(cr3, ethread + offset_of!(KthreadView1, state) as u64).unwrap_or(0xFF) } else { 0xFF };
        let wait = if ethread != 0 { memory::read_u8(cr3, ethread + offset_of!(KthreadView1, wait_reason) as u64).unwrap_or(0xFF) } else { 0xFF };
        // TEB.LastErrorValue (0x68) pela raiz do processo.
        let last_error = if teb != 0 { memory::read_u32(root, teb + 0x68).map_or("?".into(), |value| alloc::format!("{:#x}", value)) } else { alloc::string::String::from("-") };
        let state_text = if dead { "Terminated" } else { THREAD_STATES.get(state_code as usize).copied().unwrap_or("?") };
        // Prioridade, suspensão, tempos (tiques) e ciclos do KTHREAD.
        let byte_at = |offset: usize| if ethread != 0 { memory::read_u8(cr3, ethread + offset as u64).unwrap_or(0) } else { 0 };
        let dword_at = |offset: usize| if ethread != 0 { memory::read_u32(cr3, ethread + offset as u64).unwrap_or(0) } else { 0 };
        let priority = byte_at(offset_of!(KthreadView1, priority)) as i8;
        let suspend = byte_at(offset_of!(KthreadView1, suspend_count)) as i8;
        let kernel_time = dword_at(offset_of!(KthreadView1, kernel_time));
        let user_time = dword_at(offset_of!(KthreadView1, user_time));
        let cycles = if ethread != 0 { read_u64(cr3, ethread + offset_of!(crate::ntos::inc::types::Kthread, cycle_time) as u64) } else { 0 };
        let _ = writeln!(
            out,
            "{:>6} {:>#18x} {:>#14x} {:>#18x} {:>#18x} {:>#18x} {:>#14x} {:<13} {:<16} {:>10} {:>4} {:>4} {:>8} {:>8} {:>#14x}",
            thread.thread_id,
            ethread,
            teb,
            start,
            context,
            rip,
            rsp,
            state_text,
            WAIT_REASONS.get(wait as usize).copied().unwrap_or("-"),
            last_error,
            priority,
            suspend,
            kernel_time,
            user_time,
            cycles
        );
    }
}

/// `kmap`: as faixas fixas do espaço de sistema do OpenNT (as imagens
/// carregadas vêm do `lm`).
pub fn kernel_map(out: &mut Payload) {
    let ranges: [(&str, u64, u64); 16] = [
        ("metade de usuario", map::LOWEST_USER_ADDRESS, map::USER_PROBE_ADDRESS),
        ("banco de PFN", map::PFN_DATABASE_BASE, map::PFN_DATABASE_TOP),
        ("pool do kernel", map::KERNEL_POOL_BASE, map::KERNEL_POOL_TOP),
        ("despejo", map::KERNEL_DUMP_VIRTUAL_BASE, map::KERNEL_CONTIGUOUS_BASE),
        ("memoria contigua", map::KERNEL_CONTIGUOUS_BASE, map::KERNEL_CONTIGUOUS_TOP),
        ("paginas independentes", map::KERNEL_INDEPENDENT_BASE, map::KERNEL_INDEPENDENT_TOP),
        ("vistas de secao de sistema", map::KERNEL_SECTION_BASE, map::KERNEL_SECTION_TOP),
        ("alocacao virtual do kernel", map::KERNEL_VIRTUAL_ALLOC_BASE, map::KERNEL_VIRTUAL_ALLOC_TOP),
        ("pool global de sessao", map::SESSION_GLOBAL_BASE, map::SESSION_GLOBAL_TOP),
        ("pilhas de kernel", map::KERNEL_STACK_BASE, map::KERNEL_STACK_TOP),
        ("mapa direto da memoria fisica", map::DIRECT_MAP_BASE, map::DIRECT_MAP_BASE + map::PHYSICAL_MEMORY_LIMIT),
        ("KPCR dos processadores", map::PCR_VIRTUAL_BASE, map::KERNEL_DATA_POOL_BASE),
        ("pool de dados do kernel", map::KERNEL_DATA_POOL_BASE, map::KERNEL_DATA_POOL_TOP),
        ("imagem do kernel (ntoskrnl)", map::KERNEL_VIRTUAL_BASE, map::KERNEL_VIRTUAL_BASE + map::KERNEL_IMAGE_MAX),
        ("imagens de sistema (drivers)", map::SYSTEM_IMAGE_BASE, map::SYSTEM_IMAGE_TOP),
        ("espaco de sessao", map::SESSION_SPACE_BASE, map::SESSION_SPACE_TOP),
    ];
    let _ = writeln!(out, "{:>18} {:>18}  faixa", "inicio", "fim");
    for (name, start, end) in ranges {
        let _ = writeln!(out, "{:>#18x} {:>#18x}  {}", start, end, name);
    }
}
