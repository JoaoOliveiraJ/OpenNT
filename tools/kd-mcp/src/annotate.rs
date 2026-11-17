//! A análise automática sobre uma janela de desmontagem, pela sessão do
//! cliente: os limites das funções (`.pdata`, símbolos e o fluxo de
//! código), os laços e os comentários automáticos (as chamadas com os
//! argumentos decodificados pelos protótipos e as strings referenciadas).
//! A janela CPU do opennt-re e a ferramenta `disassemble` do servidor MCP
//! usam o mesmo código.

use std::collections::HashMap;

use kd_client::analysis::args::{self, Value};
use kd_client::analysis::decode;
use kd_client::analysis::functions::{self, Function, Loop};
use kd_client::analysis::prototypes::{self, Layouts};
use kd_client::analysis::refs;
use kd_client::unwind::Target as _;
use kd_client::Client;

use crate::disasm::Line;

/// Maior função lida para achar os laços.
const LOOP_SCAN_LIMIT: u64 = 0x10000;
/// Instruções olhadas para trás no preparo de uma chamada.
const SETUP_WINDOW: usize = 16;

/// Os registradores de uma parada (o comentário da chamada no RIP usa os
/// valores de verdade).
#[derive(Clone, Debug, Default)]
pub struct Live {
    pub rip: u64,
    pub registers: Vec<(String, u64)>,
}

impl Live {
    fn register(&self, name: &str) -> Option<u64> {
        self.registers.iter().find(|(register, _)| register == name).map(|(_, value)| *value)
    }
}

/// A `.pdata` do módulo do endereço em pares absolutos (início, fim)
/// ordenados; vazia no kernel do OpenNT (os símbolos do ELF têm tamanho).
pub fn function_table(client: &mut Client, address: u64) -> Vec<(u64, u64)> {
    let Some(table) = client.function_table(address) else { return Vec::new() };
    let mut pairs: Vec<(u64, u64)> = table.functions.iter().map(|function| (table.base + function.begin as u64, table.base + function.end as u64)).collect();
    pairs.sort_unstable();
    pairs
}

/// O símbolo de função que contém o endereço: início e tamanho (0 =
/// desconhecido).
pub fn symbol_bounds(client: &Client, address: u64) -> Option<(u64, u64)> {
    let module = client.symbols.module_at(address)?;
    let index = module.symbols.partition_point(|symbol| symbol.address <= address);
    let symbol = module.symbols[..index].iter().rev().take(64).find(|symbol| symbol.function && (symbol.size == 0 || address < symbol.address + symbol.size))?;
    Some((symbol.address, symbol.size))
}

/// A função que contém o endereço.
pub fn function_at(client: &mut Client, address: u64) -> Option<Function> {
    let table = function_table(client, address);
    let symbol = symbol_bounds(client, address);
    let mut decode_at = |at: u64| client.read_memory(at, 16).ok().and_then(|bytes| decode::decode(&bytes, at));
    functions::function_at(address, &table, symbol, &mut decode_at)
}

/// As funções que cobrem as linhas (cada uma uma vez).
pub fn functions_for_lines(client: &mut Client, lines: &[Line]) -> Vec<Function> {
    let table = lines.first().map(|line| function_table(client, line.address)).unwrap_or_default();
    let mut found: Vec<Function> = Vec::new();
    for line in lines {
        if found.iter().any(|function| function.contains(line.address)) {
            continue;
        }
        let symbol = symbol_bounds(client, line.address);
        let mut decode_at = |at: u64| client.read_memory(at, 16).ok().and_then(|bytes| decode::decode(&bytes, at));
        if let Some(function) = functions::function_at(line.address, &table, symbol, &mut decode_at) {
            found.push(function);
        }
    }
    found
}

/// Os laços das funções (lidas inteiras, até `LOOP_SCAN_LIMIT`).
pub fn loops_for(client: &mut Client, functions: &[Function]) -> Vec<Loop> {
    let mut found = Vec::new();
    for function in functions {
        let length = (function.end - function.start).min(LOOP_SCAN_LIMIT);
        let Ok(bytes) = client.read_memory(function.start, length as usize) else { continue };
        let insns = decode::decode_all(&bytes, function.start);
        found.extend(functions::loops(&insns, (function.start, function.end)));
    }
    found
}

/// Os bytes de uma linha (o texto hexadecimal da desmontagem).
fn line_bytes(line: &Line) -> Vec<u8> {
    (0..line.bytes.len() / 2).filter_map(|index| u8::from_str_radix(&line.bytes[index * 2..index * 2 + 2], 16).ok()).collect()
}

/// A linha muda o fluxo (o preparo de uma chamada não passa dela).
fn ends_block(line: &Line) -> bool {
    let mnemonic = line.text.split_whitespace().next().unwrap_or("");
    mnemonic == "call" || mnemonic == "ret" || mnemonic == "jmp" || mnemonic.starts_with('j') || mnemonic == "int3" || mnemonic == "ud2"
}

/// O destino de uma chamada: direto, ou a entrada da IAT de `call [rip+x]`.
fn call_target(client: &mut Client, line: &Line) -> Option<u64> {
    if let Some(target) = line.target {
        return Some(target);
    }
    let slot = line.memory?;
    client.read_integer(slot, 8).ok().filter(|&target| target != 0)
}

/// Os comentários automáticos das linhas: a chamada a uma API conhecida
/// com os argumentos (`Nome(arg=valor, ...)`) e a string que uma instrução
/// referencia. Na linha do RIP de uma parada, os argumentos são os
/// registradores e a pilha de verdade.
pub fn auto_comments(client: &mut Client, lines: &[Line], live: Option<&Live>) -> HashMap<u64, String> {
    let layouts = client.type_database_loaded().map(|types| Layouts::from_types(&types)).unwrap_or_default();
    let targets: Vec<u64> = lines.iter().filter_map(|line| line.target).collect();
    let mut comments = HashMap::new();
    for (index, line) in lines.iter().enumerate() {
        let mnemonic = line.text.split_whitespace().next().unwrap_or("");
        if mnemonic == "call" {
            let Some(target) = call_target(client, line) else { continue };
            let name = client.symbols.describe(target);
            let Some(prototype) = prototypes::find(&name) else { continue };
            let count = prototype.arguments.len();
            let values: Vec<Value> = match live.filter(|live| live.rip == line.address) {
                Some(live) => live_arguments(client, live, count),
                None => {
                    // O preparo: as linhas antes da chamada no mesmo bloco.
                    let mut setup: Vec<(u64, Vec<u8>)> = Vec::new();
                    for previous in lines[..index].iter().rev().take(SETUP_WINDOW) {
                        if ends_block(previous) {
                            break;
                        }
                        setup.push((previous.address, line_bytes(previous)));
                        // Um destino de desvio começa o bloco.
                        if targets.contains(&previous.address) {
                            break;
                        }
                    }
                    setup.reverse();
                    args::trace_arguments(&args::writes_before(&setup), count)
                }
            };
            // A memória e os nomes vêm do mesmo cliente, um de cada vez.
            let cell = std::cell::RefCell::new(&mut *client);
            let symbol = |address: u64| cell.borrow().symbols.name_at(address);
            let mut memory = |address: u64, length: usize| cell.borrow_mut().read_memory(address, length).ok().filter(|bytes| !bytes.is_empty());
            let text = prototypes::call_comment(prototype, &values, &mut memory, &symbol, &layouts);
            comments.insert(line.address, text);
            continue;
        }
        // A string referenciada por um operando relativo ao RIP.
        if let Some(address) = line.memory.filter(|_| mnemonic != "jmp") {
            if let Ok(bytes) = client.read_memory(address, 260) {
                if let Some((text, wide)) = refs::read_string(&bytes, 4) {
                    comments.insert(line.address, if wide { format!("L\"{text}\"") } else { format!("\"{text}\"") });
                }
            }
        }
    }
    comments
}

/// Os argumentos de verdade: RCX, RDX, R8, R9 e a pilha a partir de
/// `[rsp+0x20]` (no RIP do `call`, ainda sem o endereço de retorno).
pub fn live_arguments(client: &mut Client, live: &Live, count: usize) -> Vec<Value> {
    let mut values = Vec::with_capacity(count);
    for name in ["rcx", "rdx", "r8", "r9"].iter().take(count) {
        values.push(live.register(name).map_or(Value::Unknown, Value::Constant));
    }
    if count > 4 {
        let rsp = live.register("rsp").unwrap_or(0);
        for index in 4..count {
            let slot = rsp + 0x20 + 8 * (index as u64 - 4);
            values.push(client.read_integer(slot, 8).map_or(Value::Unknown, Value::Constant));
        }
    }
    values
}

/// Os argumentos da convenção x64 para a caixa sob os registradores:
/// (nome, onde está, valor). `count` inclui os da pilha.
pub fn calling_convention_arguments(client: &mut Client, registers: &[(String, u64)], count: usize) -> Vec<(String, String, Option<u64>)> {
    let value = |name: &str| registers.iter().find(|(register, _)| register == name).map(|(_, value)| *value);
    let mut rows = Vec::with_capacity(count);
    for (index, name) in ["rcx", "rdx", "r8", "r9"].iter().enumerate().take(count) {
        rows.push((format!("{}", index + 1), name.to_string(), value(name)));
    }
    if count > 4 {
        // Na entrada de uma função o RSP aponta o endereço de retorno: o
        // quinto argumento fica em [rsp+0x28].
        let rsp = value("rsp").unwrap_or(0);
        for index in 4..count {
            let offset = 0x28 + 8 * (index as u64 - 4);
            rows.push((format!("{}", index + 1), format!("[rsp+{offset:#x}]"), client.read_integer(rsp + offset, 8).ok()));
        }
    }
    rows
}
