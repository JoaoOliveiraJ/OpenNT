//! REPL interativo (o "cmd.exe" do OpenNT).
//!
//! Roda como processo no escalonador (cede a CPU entre teclas). O `sc` vem
//! de `service_control`; `exec`, `loaddriver` e
//! `objects` ainda mostram a dependência pendente.

pub mod service_control;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::apps::programs;
use crate::drivers::console;
use crate::hal::cpu;
use crate::nano::message_channels;
use crate::ntos::ex::syscalls::Value;
use crate::drivers::fs::memory_file_system::{self, FileData};
use crate::ntos::mm::memory;
use crate::ntos::ps::scheduler;
use crate::rtl::text::pad_end;

const HELP: &[&str] = &[
    "help              esta ajuda",
    "version           versao do OpenNT",
    "clear             limpa a tela",
    "echo <txt>        imprime texto",
    "mem               uso do heap/RAM",
    "ls                lista arquivos do MemoryFileSystem",
    "cat <arq>         mostra conteudo",
    "write <arq> <txt> grava arquivo",
    "rm <arq>          remove arquivo",
    "run <prog>        executa programa embutido (hello)",
    "exec <arq.exe>    executa .exe Windows (PE32+) nativo",
    "loaddriver <a.sys> carrega driver .sys nativo (estilo WDM)",
    "sc <comando>      consulta/controla servicos e drivers (sc help)",
    "objects           namespace do Object Manager (estilo NT)",
    "ps                lista processos",
    "spawn <prog>      cria processo embutido (pisca)",
    "kill <pid>        mata processo",
    "halt              desliga",
];

/// Aceita caminhos estilo Windows (`C:\foo`, `C:/foo`, `\foo`) -> `/foo`.
pub fn norm_path(path: &str) -> String {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        let mut rest = &path[2..];
        if rest.starts_with('\\') || rest.starts_with('/') {
            rest = &rest[1..];
        }
        return format!("/{}", rest.replace('\\', "/"));
    }
    path.replace('\\', "/")
}

fn cmd_help(_: &[&str]) {
    for line in HELP {
        console::print(line);
    }
}

fn cmd_version(_: &[&str]) {
    console::print(&format!("OpenNT v{}", crate::VERSION));
}

fn cmd_clear(_: &[&str]) {
    console::clear();
}

fn cmd_echo(arguments: &[&str]) {
    console::print(&arguments.join(" "));
}

fn cmd_mem(_: &[&str]) {
    memory::cmd_mem();
}

fn cmd_ls(_: &[&str]) {
    let list = memory_file_system::list();
    if list.is_empty() {
        console::print("(vazio)");
        return;
    }
    console::print(" Volume em C: montado em \\FS");
    for file in list {
        let size = memory_file_system::size(&file).unwrap_or(0);
        console::print(&format!("  C:{}  ({} bytes)", file.replace('/', "\\"), size));
    }
}

fn cmd_cat(arguments: &[&str]) {
    let name = arguments.first().copied().unwrap_or_default();
    match memory_file_system::read(&norm_path(name)) {
        None => console::print(&format!("arquivo nao encontrado: {name}")),
        Some(FileData::Binary(bytes)) => {
            console::print(&format!("<arquivo binario, {} bytes>", bytes.len()))
        }
        Some(FileData::Text(text)) => console::print(&text),
    }
}

fn cmd_write(arguments: &[&str]) {
    if arguments.len() < 2 {
        console::print("uso: write <arq> <texto>");
        return;
    }
    match memory_file_system::write(&norm_path(arguments[0]), &arguments[1..].join(" ")) {
        Ok(_) => console::print(&format!("gravado: {}", arguments[0])),
        Err(error) => console::print(&format!("erro: {error}")),
    }
}

fn cmd_rm(arguments: &[&str]) {
    let name = arguments.first().copied().unwrap_or_default();
    let removed = memory_file_system::remove(&norm_path(name));
    console::print(if removed { "removido" } else { "nao encontrado" });
}

fn cmd_run(arguments: &[&str]) {
    let name = arguments.first().copied().unwrap_or_default();
    let Some(program) = programs::find_program(&norm_path(name)) else {
        console::print(&format!("arquivo nao encontrado: {name}"));
        return;
    };
    match program() {
        Ok(Value::Undefined) => {}
        Ok(result) => console::print(&format!("= {result}")),
        Err(error) => console::print(&format!("erro no programa: {error}")),
    }
}

fn cmd_ps(_: &[&str]) {
    console::print("PID  STATE    NAME");
    for process in scheduler::list() {
        console::print(&format!(
            "{}{}{}",
            pad_end(&format!("{}", process.pid), 5),
            pad_end(process.state.as_str(), 9),
            process.name
        ));
    }
}

fn cmd_spawn(arguments: &[&str]) {
    let name = arguments.first().copied().unwrap_or_default();
    let Some(make_process) = programs::find_process(name) else {
        console::print(&format!("arquivo nao encontrado: {name}"));
        return;
    };
    let pid = scheduler::spawn(name, make_process());
    console::print(&format!("processo {pid} criado ({name})"));
}

fn cmd_kill(arguments: &[&str]) {
    let pid = arguments.first().and_then(|text| text.parse::<u32>().ok());
    let killed = pid.is_some_and(|pid| scheduler::kill(pid, 0));
    console::print(if killed { "processo morto" } else { "pid nao encontrado" });
}

fn pending_phase(command: &str, requirement: &str) {
    console::print(&format!(
        "{command}: ainda nao implementado (depende de {requirement})"
    ));
}

fn cmd_exec(_: &[&str]) {
    pending_phase("exec", "ntos/mm/pe_loader e ntos/ps/user");
}

fn cmd_load_driver(_: &[&str]) {
    pending_phase("loaddriver", "ntos/io");
}

fn cmd_objects(_: &[&str]) {
    pending_phase("objects", "ntos/ob/object-manager");
}

fn cmd_halt(_: &[&str]) {
    console::print("desligando...");
    cpu::halt_forever();
}

type Command = fn(&[&str]);

const COMMANDS: &[(&str, Command)] = &[
    ("help", cmd_help),
    ("version", cmd_version),
    ("clear", cmd_clear),
    ("echo", cmd_echo),
    ("mem", cmd_mem),
    ("ls", cmd_ls),
    ("cat", cmd_cat),
    ("write", cmd_write),
    ("rm", cmd_rm),
    ("run", cmd_run),
    ("ps", cmd_ps),
    ("spawn", cmd_spawn),
    ("kill", cmd_kill),
    ("exec", cmd_exec),
    ("loaddriver", cmd_load_driver),
    ("objects", cmd_objects),
    ("halt", cmd_halt),
];

fn print_line(text: &str) {
    console::print(text);
}

/// Executa a linha; uma espera do SCM volta ao laço, que cede a CPU até o
/// handler responder ou expirar.
pub fn exec(line: &str) -> Option<alloc::boxed::Box<service_control::Waiting>> {
    // O sc conserva aspas e barras dos caminhos registrados no SCM.
    let trimmed = line.trim_start();
    if trimmed.get(..2).is_some_and(|prefix| prefix.eq_ignore_ascii_case("sc"))
        && trimmed[2..].chars().next().is_none_or(char::is_whitespace)
    {
        return match service_control::execute(trimmed[2..].trim_start(), print_line) {
            service_control::Execution::Done(_) => None,
            service_control::Execution::Pending(waiting) => Some(waiting),
        };
    }

    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    let Some((&name, arguments)) = parts.split_first() else { return None };
    match COMMANDS.iter().find(|(command, _)| *command == name) {
        Some((_, command)) => command(arguments),
        None => console::print(&format!("comando desconhecido: {name} (tente 'help')")),
    }
    None
}

/// Processo do shell: cede a CPU quando o canal `kbd` (IPC) não tem tecla.
pub async fn main() -> u32 {
    console::print("");
    console::print("OpenNT shell - digite 'help'");
    let mut line = String::new();
    console::write("OpenNT> ");
    debug_print!("[shell] pronto");
    loop {
        let Some(key) = message_channels::receive("kbd") else {
            scheduler::yield_now().await;
            continue;
        };
        match key.as_str() {
            "\n" => {
                console::write("\n");
                debug_print!("[shell] > {}", line);
                if let Some(mut waiting) = exec(&line) {
                    while waiting.poll().is_none() {
                        scheduler::yield_now().await;
                    }
                }
                line.clear();
                console::write("OpenNT> ");
            }
            "\u{8}" => {
                if line.pop().is_some() {
                    console::write("\u{8}");
                }
            }
            _ if key.chars().count() == 1 => {
                line.push_str(&key);
                console::write(&key);
            }
            _ => {}
        }
    }
}
