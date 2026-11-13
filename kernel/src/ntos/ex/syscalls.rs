//! Chamadas numeradas dos programas do OpenNT.
//!
//! A tabela encaminha console, teclado, memória e arquivos aos respectivos
//! proprietários; seus números são internos ao runtime. Argumentos e
//! resultados são valores dinâmicos.

use alloc::string::String;
use alloc::vec::Vec;

use crate::drivers::{console, input::keyboard};
use crate::hal::{cpu, kmalloc};
use crate::drivers::fs::memory_file_system::{self, FileData};
use crate::ntos::inc::status::STATUS_NOT_IMPLEMENTED;
use crate::rtl::KernelError;

#[derive(Clone, Debug)]
pub enum Value {
    Undefined,
    Bool(bool),
    Number(u64),
    Text(String),
    Bytes(Vec<u8>),
    List(Vec<String>),
    HeapInfo { total: usize, used: usize },
}

impl Value {
    fn text(&self) -> String {
        match self {
            Value::Undefined => String::from("undefined"),
            Value::Bool(value) => alloc::format!("{value}"),
            Value::Number(value) => alloc::format!("{value}"),
            Value::Text(text) => text.clone(),
            Value::Bytes(bytes) => alloc::format!("<{} bytes>", bytes.len()),
            Value::List(items) => items.join(","),
            Value::HeapInfo { total, used } => alloc::format!("{{ total: {total}, used: {used} }}"),
        }
    }
}

impl core::fmt::Display for Value {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.text())
    }
}

type Service = fn(&[Value]) -> Result<Value, KernelError>;

fn argument(arguments: &[Value], index: usize) -> String {
    arguments.get(index).map(Value::text).unwrap_or_default()
}

fn print(arguments: &[Value]) -> Result<Value, KernelError> {
    console::print(&argument(arguments, 0));
    Ok(Value::Undefined)
}

fn read(arguments: &[Value]) -> Result<Value, KernelError> {
    Ok(match memory_file_system::read(&argument(arguments, 0)) {
        Some(FileData::Text(text)) => Value::Text(text),
        Some(FileData::Binary(bytes)) => Value::Bytes(bytes),
        None => Value::Undefined,
    })
}

fn write(arguments: &[Value]) -> Result<Value, KernelError> {
    memory_file_system::write(&argument(arguments, 0), &argument(arguments, 1)).map(Value::Bool)
}

fn list(_: &[Value]) -> Result<Value, KernelError> {
    Ok(Value::List(memory_file_system::list()))
}

fn remove(arguments: &[Value]) -> Result<Value, KernelError> {
    Ok(Value::Bool(memory_file_system::remove(&argument(arguments, 0))))
}

fn exists(arguments: &[Value]) -> Result<Value, KernelError> {
    Ok(Value::Bool(memory_file_system::exists(&argument(arguments, 0))))
}

fn meminfo(_: &[Value]) -> Result<Value, KernelError> {
    let (total, used) = kmalloc::info();
    Ok(Value::HeapInfo { total, used })
}

fn getchar(_: &[Value]) -> Result<Value, KernelError> {
    Ok(Value::Text(String::from(keyboard::read_key())))
}

fn clear(_: &[Value]) -> Result<Value, KernelError> {
    console::clear();
    Ok(Value::Undefined)
}

fn halt(_: &[Value]) -> Result<Value, KernelError> {
    cpu::halt_forever()
}

fn ramsize(_: &[Value]) -> Result<Value, KernelError> {
    Ok(Value::Number(kmalloc::ram_top()))
}

/// `open`/`close` pertencem ao Object Manager, ainda não implementado.
fn object_manager_pending(_: &[Value]) -> Result<Value, KernelError> {
    Err(KernelError::with_status(
        "syscall depende do Object Manager (ntos/ob), ainda nao transcrito",
        STATUS_NOT_IMPLEMENTED,
    ))
}

/// Cada entrada contém número, nome público e implementação.
static SYSTEM_CALL_TABLE: &[(u32, &str, Service)] = &[
    (0, "print", print),
    (1, "read", read),
    (2, "write", write),
    (3, "list", list),
    (4, "remove", remove),
    (5, "exists", exists),
    (6, "meminfo", meminfo),
    (7, "getchar", getchar),
    (8, "clear", clear),
    (9, "halt", halt),
    (10, "ramsize", ramsize),
    (11, "open", object_manager_pending),
    (12, "close", object_manager_pending),
];

/// Índice reverso construído da mesma tabela.
pub fn number_by_name(name: &str) -> Option<u32> {
    SYSTEM_CALL_TABLE.iter().find(|entry| entry.1 == name).map(|entry| entry.0)
}

/// Localiza o serviço e encaminha os argumentos. Número desconhecido é erro.
pub fn system_call(service_number: u32, arguments: &[Value]) -> Result<Value, KernelError> {
    match SYSTEM_CALL_TABLE.iter().find(|entry| entry.0 == service_number) {
        Some(entry) => (entry.2)(arguments),
        None => Err(KernelError::new(alloc::format!("syscall desconhecida: {service_number}"))),
    }
}

/// Atalho usado pelos programas: `call("print", &[Value::Text(..)])`.
pub fn call(name: &str, arguments: &[Value]) -> Result<Value, KernelError> {
    match number_by_name(name) {
        Some(number) => system_call(number, arguments),
        None => Err(KernelError::new(alloc::format!("syscall desconhecida: {name}"))),
    }
}
