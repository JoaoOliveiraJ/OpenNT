//! Programas de exemplo do shell.
//!
//! Os programas são funções Rust embutidas no kernel que usam a tabela de
//! chamadas (`ntos::ex::syscalls`). `run` executa um programa síncrono;
//! `spawn` cria um processo cooperativo no escalonador.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;

use crate::ntos::ex::syscalls::{self, Value};
use crate::ntos::ps::scheduler::{self, ProcessFuture};
use crate::rtl::KernelError;

fn print(text: impl Into<String>) {
    let _ = syscalls::call("print", &[Value::Text(text.into())]);
}

/// `hello`: imprime uma saudação e devolve 6 * 7.
pub fn hello() -> Result<Value, KernelError> {
    print("Ola de um programa Rust rodando no OpenNT!");
    Ok(Value::Number(6 * 7))
}

/// `pisca`: processo cooperativo que imprime cinco ticks.
pub async fn pisca() -> u32 {
    for tick in 1..=5 {
        print(format!("[pisca] tick {tick}"));
        scheduler::yield_now().await; // devolve a CPU ao kernel
    }
    print("[pisca] fim");
    0
}

pub type Program = fn() -> Result<Value, KernelError>;
pub type ProcessProgram = fn() -> ProcessFuture;

/// Nome canônico de um programa: sem diretório e sem extensão
/// (`/hello.exe`, `C:\hello.exe` e `hello` levam a `hello`).
fn program_name(path: &str) -> String {
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let stem = base.split('.').next().unwrap_or(base);
    stem.to_ascii_lowercase()
}

/// Programas para `run`.
pub fn find_program(path: &str) -> Option<Program> {
    match program_name(path).as_str() {
        "hello" => Some(hello),
        _ => None,
    }
}

/// Programas para `spawn`.
pub fn find_process(path: &str) -> Option<ProcessProgram> {
    match program_name(path).as_str() {
        "pisca" => Some(|| Box::pin(pisca())),
        _ => None,
    }
}

/// Nomes listados na ajuda do shell.
pub const PROGRAMS: &[&str] = &["hello"];
pub const PROCESSES: &[&str] = &["pisca"];
