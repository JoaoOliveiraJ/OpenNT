//! Comandos do OpenNT para o host (`monitor` no GDB, o `qRcmd` do
//! protocolo): processos, threads (e os registradores de uma thread fora da
//! CPU, do quadro de troca na pilha de kernel dela), módulos, processadores
//! e IRQL, objetos por nome, o log do DbgPrint, breakpoints e o bugcheck.
//!
//! As listas andam nas estruturas nativas do NT (EPROCESS.ActiveProcessLinks,
//! ThreadListHead, KPCR/KPRCB) com o leitor de memória do depurador, sem
//! travas nem faltas: com a máquina parada, um ponteiro estragado só encerra
//! a lista. A lista de módulos e a busca de objeto por nome usam as
//! estruturas do kernel; só rodam quando nenhum processador parado tinha
//! trava (`stop::locks_held`), e a lista de módulos também só pega a trava
//! do registro de imagens se ela estiver livre.

use core::fmt::Write;
use core::mem::offset_of;

use super::packet::Payload;
use super::{breakpoints, debugger, memory, print_log, stop};
use crate::ntos::inc::types::{ClientId, Eprocess, Ethread, EthreadView1, KapcState, Kpcr, Kprcb, Kprocess, Kthread, KthreadView1};
use crate::ntos::mm::loaded_images;
use crate::ntos::mm::memory_map::MAX_CPUS;
use crate::ntos::ps::process;

const LIST_LIMIT: usize = 1024;

const HELP: &str = "comandos do OpenNT:
  ps                 processos (EPROCESS, PID, CR3, threads, nome)
  threads [pid]      threads (ETHREAD, TID, estado, inicio) de todos ou de um processo
  lm                 modulos carregados (base, fim, nome, caminho)
  cpus | irql        processadores: IRQL, KPCR, thread e processo correntes, RIP
  context <ethread>  registradores de uma thread (fora da CPU: o quadro de troca)
  obj <caminho>      objeto do namespace por nome (tipo e corpo)
  log [bytes]        saida recente do DbgPrint
  bl                 breakpoints armados
  bugcheck           codigo e parametros do bugcheck que parou a maquina
  kd                 estado do depurador visto pelos drivers
";

fn read_u64(cr3: u64, address: u64) -> u64 {
    memory::read_u64(cr3, address).unwrap_or(0)
}

/// O ImageFileName (15 bytes, sem NUL garantido) do EPROCESS.
fn process_name(cr3: u64, eprocess: u64, output: &mut [u8; 16]) -> usize {
    let length = memory::read(cr3, eprocess + offset_of!(Eprocess, image_file_name) as u64, &mut output[..15]);
    output[..length].iter().position(|&byte| byte == 0).unwrap_or(length)
}

fn push_name(out: &mut Payload, bytes: &[u8]) {
    for &byte in bytes {
        out.push(if (0x20..0x7F).contains(&byte) { byte } else { b'?' });
    }
}

/// Percorre uma LIST_ENTRY circular a partir da cabeça, até o limite.
fn walk_list(cr3: u64, head: u64, mut each: impl FnMut(u64) -> bool) {
    let mut entry = read_u64(cr3, head);
    let mut count = 0;
    while entry != head && entry != 0 && count < LIST_LIMIT {
        if !each(entry) {
            return;
        }
        entry = read_u64(cr3, entry);
        count += 1;
    }
}

fn processes(cr3: u64, out: &mut Payload) {
    let Some(head) = process::try_active_process_head() else {
        out.push_str("lista de processos ocupada (trava tomada no codigo interrompido)\n");
        return;
    };
    let _ = writeln!(out, "{:>6} {:>18} {:>18} {:>7}  nome", "PID", "EPROCESS", "CR3", "threads");
    walk_list(cr3, head, |entry| {
        let eprocess = entry - offset_of!(Eprocess, active_process_links) as u64;
        let pid = read_u64(cr3, eprocess + offset_of!(Eprocess, unique_process_id) as u64);
        let directory = read_u64(cr3, eprocess + offset_of!(Kprocess, directory_table_base) as u64);
        let threads = memory::read_u32(cr3, eprocess + offset_of!(Eprocess, active_threads) as u64).unwrap_or(0);
        let mut name = [0u8; 16];
        let length = process_name(cr3, eprocess, &mut name);
        let _ = write!(out, "{:>6} {:>#18x} {:>#18x} {:>7}  ", pid, eprocess, directory, threads);
        push_name(out, &name[..length]);
        out.push(b'\n');
        true
    });
}

const THREAD_STATES: [&str; 10] = ["Initialized", "Ready", "Running", "Standby", "Terminated", "Waiting", "Transition", "DeferredReady", "GateWait", "WaitingForProcessInSwap"];

fn threads(cr3: u64, filter: Option<u64>, out: &mut Payload) {
    let Some(head) = process::try_active_process_head() else {
        out.push_str("lista de processos ocupada (trava tomada no codigo interrompido)\n");
        return;
    };
    let _ = writeln!(out, "{:>6} {:>6} {:>18} {:<13} {:>18}  processo", "PID", "TID", "ETHREAD", "estado", "inicio");
    walk_list(cr3, head, |entry| {
        let eprocess = entry - offset_of!(Eprocess, active_process_links) as u64;
        let pid = read_u64(cr3, eprocess + offset_of!(Eprocess, unique_process_id) as u64);
        if filter.is_some_and(|wanted| wanted != pid) {
            return true;
        }
        let mut name = [0u8; 16];
        let length = process_name(cr3, eprocess, &mut name);
        walk_list(cr3, eprocess + offset_of!(Eprocess, thread_list_head) as u64, |link| {
            let ethread = link - offset_of!(Ethread, thread_list_entry) as u64;
            let tid = read_u64(cr3, ethread + (offset_of!(Ethread, cid) + offset_of!(ClientId, unique_thread)) as u64);
            let state = memory::read_u8(cr3, ethread + offset_of!(KthreadView1, state) as u64).unwrap_or(0xFF);
            let start = read_u64(cr3, ethread + offset_of!(EthreadView1, start_address) as u64);
            let state = THREAD_STATES.get(state as usize).copied().unwrap_or("?");
            let _ = write!(out, "{:>6} {:>6} {:>#18x} {:<13} {:>#18x}  ", pid, tid, ethread, state, start);
            push_name(out, &name[..length]);
            out.push(b'\n');
            true
        });
        true
    });
}

/// Nome base de um caminho (depois da última barra).
fn base_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn modules(out: &mut Payload) {
    let _ = writeln!(out, "{:>18} {:>18}  {:<16} caminho", "base", "fim", "nome");
    let listed = loaded_images::try_for_each(|image| {
        let _ = writeln!(out, "{:>#18x} {:>#18x}  {:<16} {}", image.image_base, image.image_base + image.size_of_image, base_name(&image.name), image.name);
    });
    if !listed {
        out.push_str("lista de modulos ocupada (trava tomada no codigo interrompido)\n");
    }
}

/// XML da lista de bibliotecas do `qXfer:libraries:read` (o endereço do
/// segmento é o da primeira seção, base + 0x1000, como o GDB espera de uma
/// imagem PE).
pub fn libraries_xml(out: &mut Payload) {
    out.push_str("<library-list>");
    loaded_images::try_for_each(|image| {
        out.push_str("<library name=\"");
        for byte in image.name.bytes() {
            match byte {
                b'&' => out.push_str("&amp;"),
                b'<' => out.push_str("&lt;"),
                b'>' => out.push_str("&gt;"),
                b'"' => out.push_str("&quot;"),
                _ => out.push(byte),
            }
        }
        let _ = write!(out, "\"><segment address=\"{:#x}\"/></library>", image.image_base + 0x1000);
    });
    out.push_str("</library-list>");
}

/// Uma linha sobre o processador `number`: IRQL, thread e processo
/// correntes (o `qThreadExtraInfo`).
pub fn describe_processor(number: usize, out: &mut Payload) {
    let pcr = stop::processor_control_region(number);
    let cr3 = stop::address_space(number);
    if !stop::processor_stopped(number) || pcr == 0 {
        let _ = write!(out, "CPU {} (rodando)", number);
        return;
    }
    let irql = stop::processor_irql(number);
    let thread = read_u64(cr3, pcr + (offset_of!(Kpcr, prcb) + offset_of!(Kprcb, current_thread)) as u64);
    let process = if thread != 0 { read_u64(cr3, thread + (offset_of!(Kthread, apc_state) + offset_of!(KapcState, process)) as u64) } else { 0 };
    let mut name = [0u8; 16];
    let length = if process != 0 { process_name(cr3, process, &mut name) } else { 0 };
    let _ = write!(out, "CPU {} IRQL {} thread {:#x} ", number, irql, thread);
    push_name(out, &name[..length]);
}

fn processors(out: &mut Payload) {
    let _ = writeln!(out, "{:>3} {:>4} {:>18} {:>18} {:>18}  processo", "CPU", "IRQL", "KPCR", "thread", "RIP");
    for number in 0..MAX_CPUS {
        if !stop::processor_stopped(number) {
            continue;
        }
        let pcr = stop::processor_control_region(number);
        let cr3 = stop::address_space(number);
        let irql = stop::processor_irql(number);
        let thread = if pcr != 0 { read_u64(cr3, pcr + (offset_of!(Kpcr, prcb) + offset_of!(Kprcb, current_thread)) as u64) } else { 0 };
        let process = if thread != 0 { read_u64(cr3, thread + (offset_of!(Kthread, apc_state) + offset_of!(KapcState, process)) as u64) } else { 0 };
        let rip = stop::view(number).map_or(0, |view| view.rip());
        let mut name = [0u8; 16];
        let length = if process != 0 { process_name(cr3, process, &mut name) } else { 0 };
        let owner = if stop::owner() == Some(number) { "*" } else { " " };
        let _ = write!(out, "{}{:>2} {:>4} {:>#18x} {:>#18x} {:>#18x}  ", owner, number, irql, pcr, thread, rip);
        push_name(out, &name[..length]);
        out.push(b'\n');
    }
}

/// Quadro de troca de uma thread fora da CPU, a partir de
/// KTHREAD.KernelStack (o layout de `hal::amd64::context_switch`: RFLAGS,
/// r15, r14, r13, r12, rsi, rdi, rbx, rbp e o endereço de retorno no fim).
const SWITCH_REGISTERS: [(&str, u64); 9] = [("rflags", 0xB0), ("r15", 0xB8), ("r14", 0xC0), ("r13", 0xC8), ("r12", 0xD0), ("rsi", 0xD8), ("rdi", 0xE0), ("rbx", 0xE8), ("rbp", 0xF0)];
const SWITCH_RETURN: u64 = crate::hal::amd64::context_switch::SWITCH_FRAME_SIZE - 8;

/// Registradores de uma thread: a que roda num processador parado está no
/// quadro do processador (thread do protocolo); a que está fora da CPU, no
/// quadro de troca da pilha de kernel dela.
fn thread_context(cr3: u64, argument: &str, out: &mut Payload) {
    let text = argument.trim_start_matches("0x");
    let Some(thread) = u64::from_str_radix(text, 16).ok().filter(|&thread| thread != 0) else {
        out.push_str("uso: context <ETHREAD em hexadecimal>\n");
        return;
    };
    for number in 0..MAX_CPUS {
        let pcr = stop::processor_control_region(number);
        if stop::processor_stopped(number) && pcr != 0 && read_u64(stop::address_space(number), pcr + (offset_of!(Kpcr, prcb) + offset_of!(Kprcb, current_thread)) as u64) == thread {
            let _ = writeln!(out, "ETHREAD {:#x} roda na CPU {}: registradores da thread {} do protocolo", thread, number, number + 1);
            if let Some(view) = stop::view(number) {
                let _ = writeln!(out, "rip={:#x} rsp={:#x} rbp={:#x}", view.rip(), view.rsp(), view.rbp());
            }
            return;
        }
    }
    let state = memory::read_u8(cr3, thread + offset_of!(KthreadView1, state) as u64).unwrap_or(0xFF);
    let Some(stack) = memory::read_u64(cr3, thread + offset_of!(Kthread, kernel_stack) as u64).filter(|&stack| stack != 0) else {
        let _ = writeln!(out, "ETHREAD {:#x}: KernelStack ilegivel", thread);
        return;
    };
    let Some(rip) = memory::read_u64(cr3, stack + SWITCH_RETURN) else {
        let _ = writeln!(out, "ETHREAD {:#x}: quadro de troca em {:#x} ilegivel", thread, stack);
        return;
    };
    let _ = writeln!(out, "ETHREAD {:#x} estado {} quadro de troca em {:#x}", thread, THREAD_STATES.get(state as usize).copied().unwrap_or("?"), stack);
    let _ = write!(out, "rip={:#x} rsp={:#x}", rip, stack + crate::hal::amd64::context_switch::SWITCH_FRAME_SIZE);
    for (name, offset) in SWITCH_REGISTERS {
        let _ = write!(out, " {}={:#x}", name, read_u64(cr3, stack + offset));
    }
    out.push(b'\n');
}

fn object(path: &str, out: &mut Payload) {
    if path.is_empty() {
        out.push_str("uso: obj \\caminho\\do\\objeto\n");
        return;
    }
    if stop::locks_held() {
        out.push_str("namespace indisponivel: um processador parado tinha trava do kernel\n");
        return;
    }
    use crate::ntos::ob::object_manager;
    let Some(id) = object_manager::lookup(path) else {
        let _ = writeln!(out, "{}: nao encontrado", path);
        return;
    };
    let Some(node) = object_manager::node(id) else {
        let _ = writeln!(out, "{}: nao encontrado", path);
        return;
    };
    let body = node.data.as_ref().map_or(0, |data| if data.native_pointer != 0 { data.native_pointer } else { data.native_body });
    let body = if body != 0 { body } else { node.native_namespace };
    let _ = writeln!(out, "{}: tipo {} corpo {:#x}", path, node.type_name, body);
    if let Some(target) = node.data.as_ref().and_then(|data| data.symlink_target.as_ref()) {
        let _ = writeln!(out, "  destino {}", target);
    }
    if let Some(children) = node.children.as_ref() {
        let _ = writeln!(out, "  {} filhos", children.len());
        for (index, name) in children.keys().enumerate() {
            if index == 32 {
                out.push_str("  ...\n");
                break;
            }
            let _ = writeln!(out, "    {}", name);
        }
    }
}

fn recent_log(bytes: usize, out: &mut Payload) {
    let mut last = b'\n';
    let length = print_log::recent(bytes.clamp(1, 0x4000), |byte| {
        out.push(if byte == b'\n' || (0x20..0x7F).contains(&byte) { byte } else { b'?' });
        last = byte;
    });
    if length == 0 {
        out.push_str("(nenhuma saida do DbgPrint)\n");
    } else if last != b'\n' {
        out.push(b'\n');
    }
}

fn breakpoint_list(out: &mut Payload) {
    let mut any = false;
    breakpoints::software_list(|address| {
        any = true;
        let _ = writeln!(out, "software  {:#x}", address);
    });
    for index in 0..4 {
        if let Some((kind, address, length)) = breakpoints::hardware_slot(index) {
            any = true;
            let _ = writeln!(out, "DR{}       {:#x} {:?} ({} bytes)", index, address, kind, length);
        }
    }
    if !any {
        out.push_str("nenhum breakpoint\n");
    }
}

/// Executa uma linha do `monitor`.
pub fn run(owner: usize, line: &str, out: &mut Payload) {
    let cr3 = stop::address_space(owner);
    let mut words = line.split_whitespace();
    let command = words.next().unwrap_or("help");
    let argument = words.next().unwrap_or("");
    match command {
        "ps" => processes(cr3, out),
        "threads" => threads(cr3, argument.parse().ok(), out),
        "lm" => modules(out),
        "cpus" | "irql" => processors(out),
        "context" => thread_context(cr3, argument, out),
        "obj" => object(argument, out),
        "log" => recent_log(argument.parse().unwrap_or(0x1000), out),
        "bl" => breakpoint_list(out),
        "bugcheck" => {
            let data = stop::bug_check_data();
            if data[0] == 0 {
                out.push_str("nenhum bugcheck\n");
            } else {
                let _ = writeln!(out, "bugcheck {:#010x} ({:#x}, {:#x}, {:#x}, {:#x})", data[0], data[1], data[2], data[3], data[4]);
            }
        }
        "kd" => debugger::describe(out),
        _ => out.push_str(HELP),
    }
}
