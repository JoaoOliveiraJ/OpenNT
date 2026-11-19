//! A desmontagem (iced-x86, sintaxe MASM) com os símbolos do cliente: o
//! módulo do `opennt-mcp` (`opennt_mcp::disasm`), o mesmo do servidor MCP, e por
//! cima dele a forma do opennt-re com os nomes dentro dos operandos:
//! `call ntdll!NtClose`, `call qword ptr [winlogon!__imp_NtClose]`,
//! `mov rax, qword ptr [win32kbase!gpsi]`. Os saltos dentro da própria
//! função ficam com o endereço (as setas da margem e o comentário mostram
//! o deslocamento).

pub use opennt_mcp::disasm::*;

use std::collections::HashMap;

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, MasmFormatter, OpKind, Register, SymbolResolver, SymbolResult};
use opennt_kd::Symbols;

use crate::annotations::ImportCache;

/// Os nomes dos endereços citados numa janela de código (o formatador do
/// iced pergunta um a um).
struct Names(HashMap<u64, String>);

impl SymbolResolver for Names {
    fn symbol(&mut self, _instruction: &Instruction, _operand: u32, _instruction_operand: Option<u32>, address: u64, _address_size: u32) -> Option<SymbolResult<'_>> {
        self.0.get(&address).map(|name| SymbolResult::with_str(address, name.as_str()))
    }
}

/// O nome de um endereço para dentro de um operando: o slot da IAT, o
/// símbolo, ou `módulo+0xRVA` (só dentro de um módulo).
fn operand_name(symbols: &Symbols, imports: Option<&ImportCache>, address: u64) -> Option<String> {
    if let Some(name) = imports.and_then(|imports| imports.slot_name(symbols, address)) {
        return Some(name);
    }
    symbols.module_at(address).map(|_| symbols.describe(address))
}

/// Os endereços que a instrução cita e o formatador mostraria: o destino
/// de um desvio, o operando relativo ao RIP ou absoluto e os imediatos.
fn cited(instruction: &Instruction) -> Vec<u64> {
    let mut addresses = Vec::new();
    for operand in 0..instruction.op_count() {
        match instruction.op_kind(operand) {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => addresses.push(instruction.near_branch_target()),
            OpKind::Memory if instruction.is_ip_rel_memory_operand() => addresses.push(instruction.ip_rel_memory_address()),
            OpKind::Memory if instruction.memory_base() == Register::None && instruction.memory_index() == Register::None => addresses.push(instruction.memory_displacement64()),
            OpKind::Immediate32to64 | OpKind::Immediate64 => addresses.push(instruction.immediate(operand)),
            _ => {}
        }
    }
    addresses
}

/// O formatador com as opções da janela (as mesmas do `opennt_mcp::disasm`).
fn formatter(names: HashMap<u64, String>) -> MasmFormatter {
    let mut formatter = MasmFormatter::with_options(Some(Box::new(Names(names))), None);
    formatter.options_mut().set_first_operand_char_index(8);
    formatter.options_mut().set_hex_prefix("0x");
    formatter.options_mut().set_hex_suffix("");
    formatter.options_mut().set_uppercase_hex(false);
    formatter.options_mut().set_space_after_operand_separator(true);
    formatter
}

/// Desmonta como `disassemble`, com os nomes dentro dos operandos. O
/// comentário de uma linha cujo nome foi para o texto sai (o
/// `annotations::enrich` põe ali o que o texto não diz).
pub fn disassemble_named(start: u64, bytes: &[u8], symbols: &Symbols, imports: Option<&ImportCache>) -> Vec<Line> {
    let mut lines = disassemble(start, bytes, Some(symbols));
    let mut decoder = Decoder::with_ip(64, bytes, start, DecoderOptions::NONE);
    let mut instructions: Vec<Instruction> = Vec::with_capacity(lines.len());
    let mut names: HashMap<u64, String> = HashMap::new();
    let mut named_lines: Vec<bool> = Vec::with_capacity(lines.len());
    let mut instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        let own = symbols.function_at(instruction.ip()).map(|(function, _)| function);
        let mut named = false;
        for address in cited(&instruction) {
            // Um salto para dentro da mesma função fica com o endereço.
            let local = instruction.op0_kind() != OpKind::Memory && !matches!(instruction.flow_control(), iced_x86::FlowControl::Call) && address == instruction.near_branch_target() && own.is_some() && symbols.function_at(address).map(|(function, _)| function) == own;
            if local {
                continue;
            }
            if let Some(name) = names.get(&address).cloned().or_else(|| operand_name(symbols, imports, address)) {
                names.insert(address, name);
                named = true;
            }
        }
        named_lines.push(named);
        instructions.push(instruction);
    }
    let mut formatter = formatter(names);
    for ((line, instruction), named) in lines.iter_mut().zip(instructions.iter()).zip(named_lines) {
        if line.address != instruction.ip() {
            continue;
        }
        let mut text = String::new();
        formatter.format(instruction, &mut text);
        line.text = text;
        if named {
            line.comment = None;
        }
    }
    lines
}

/// A primeira instrução de `bytes`, com os nomes (as linhas das buscas e
/// das referências cruzadas).
pub fn first_named(address: u64, bytes: &[u8], symbols: &Symbols, imports: Option<&ImportCache>) -> String {
    let length = instruction_length(address, bytes).unwrap_or(bytes.len()).min(bytes.len());
    disassemble_named(address, &bytes[..length], symbols, imports).into_iter().next().map(|line| line.text).unwrap_or_default()
}
