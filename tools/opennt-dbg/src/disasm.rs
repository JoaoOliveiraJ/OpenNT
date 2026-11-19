//! Desmontagem x86-64 (iced-x86, sintaxe MASM, a do WinDbg) com os
//! símbolos do cliente: o nome da função no começo dela e, em comentário,
//! o destino de cada desvio e o endereço de cada operando relativo ao RIP.

use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Formatter, Instruction, InstructionInfoFactory, MasmFormatter, OpAccess, OpKind, Register};
use opennt_kd::x86::Flow;
use opennt_kd::Symbols;

/// Uma instrução desmontada.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub address: u64,
    /// Os bytes em hexadecimal.
    pub bytes: String,
    pub text: String,
    /// O nome da função, na primeira instrução dela.
    pub label: Option<String>,
    /// O símbolo do destino ou do operando de memória.
    pub comment: Option<String>,
    /// Destino de um desvio direto (a navegação por clique duplo).
    pub target: Option<u64>,
}

/// Desmonta `bytes` lidos em `start`; com `symbols`, rotula e comenta.
pub fn disassemble(start: u64, bytes: &[u8], symbols: Option<&Symbols>) -> Vec<Line> {
    let mut decoder = Decoder::with_ip(64, bytes, start, DecoderOptions::NONE);
    let mut formatter = MasmFormatter::new();
    formatter.options_mut().set_first_operand_char_index(8);
    formatter.options_mut().set_hex_prefix("0x");
    formatter.options_mut().set_hex_suffix("");
    formatter.options_mut().set_uppercase_hex(false);
    formatter.options_mut().set_space_after_operand_separator(true);
    let mut instruction = Instruction::default();
    let mut lines = Vec::new();
    while decoder.can_decode() {
        let offset = (decoder.ip() - start) as usize;
        decoder.decode_out(&mut instruction);
        let length = instruction.len();
        let mut text = String::new();
        formatter.format(&instruction, &mut text);
        let address = instruction.ip();
        let raw = &bytes[offset..(offset + length).min(bytes.len())];
        let target = (instruction.op_count() > 0 && matches!(instruction.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64)).then(|| instruction.near_branch_target());
        let memory = instruction.is_ip_rel_memory_operand().then(|| instruction.ip_rel_memory_address());
        let (label, comment) = match symbols {
            Some(symbols) => {
                let label = symbols.function_at(address).filter(|(function, _)| *function == address).map(|(_, name)| name);
                let comment = target.or(memory).and_then(|destination| symbols.name_at(destination).map(|name| if memory.is_some() && target.is_none() { format!("[{name}]") } else { name }));
                (label, comment)
            }
            None => (None, None),
        };
        lines.push(Line { address, bytes: raw.iter().map(|byte| format!("{byte:02x}")).collect(), text, label, comment, target });
    }
    lines
}

/// A janela de código em volta de `focus`: começa no símbolo da função
/// (desmontar para trás no x86 é ambíguo) quando ela não está longe, e
/// mantém até `before` bytes antes do foco e `after` depois.
pub fn window_start(focus: u64, symbols: &Symbols, before: u64) -> u64 {
    match symbols.function_at(focus) {
        Some((start, _)) if focus - start <= 0x2000 => start,
        _ => focus.saturating_sub(before.min(0x20)),
    }
}

/// Corta as linhas à janela e confere que o foco é começo de instrução
/// (senão a desmontagem desalinhou e o chamador recomeça no foco).
pub fn clip(lines: Vec<Line>, focus: u64, before: u64, after: u64) -> Option<Vec<Line>> {
    if !lines.iter().any(|line| line.address == focus) {
        return None;
    }
    Some(lines.into_iter().filter(|line| line.address + before >= focus && line.address <= focus + after).collect())
}

/// O tamanho da instrução em `bytes` (`None` se inválida).
pub fn instruction_length(ip: u64, bytes: &[u8]) -> Option<usize> {
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    let instruction = decoder.decode();
    (instruction.code() != Code::INVALID).then(|| instruction.len())
}

/// As instruções de um bloco do QEMU: de `start` até o primeiro desvio
/// (incluído) ou até o começo do bloco seguinte (`next`).
pub fn block(start: u64, code: &[u8], next: Option<u64>) -> Vec<(u64, Flow)> {
    let mut decoder = Decoder::with_ip(64, code, start, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut output = Vec::new();
    while decoder.can_decode() && output.len() < 512 {
        decoder.decode_out(&mut instruction);
        if instruction.code() == Code::INVALID {
            break;
        }
        let flow = match instruction.flow_control() {
            FlowControl::Call | FlowControl::IndirectCall => Flow::Call(instruction.len()),
            FlowControl::Return => Flow::Return,
            _ => Flow::Other,
        };
        output.push((instruction.ip(), flow));
        if instruction.flow_control() != FlowControl::Next || Some(instruction.next_ip()) == next {
            break;
        }
    }
    output
}

/// Um operando de memória de uma instrução do rastro.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryOperand {
    pub address: u64,
    pub size: usize,
    pub read: bool,
    pub write: bool,
}

/// Os operandos de memória da instrução em `ip`, com o endereço calculado
/// pelos registradores (`register` dá o valor de um registrador de 64 bits
/// pelo nome; segmentos sem base conhecida ficam de fora).
pub fn memory_operands(ip: u64, bytes: &[u8], register: &dyn Fn(&str) -> Option<u64>) -> Vec<MemoryOperand> {
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.code() == Code::INVALID {
        return Vec::new();
    }
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(&instruction);
    let next = instruction.next_ip();
    info.used_memory()
        .iter()
        .filter_map(|memory| {
            let (read, write) = match memory.access() {
                OpAccess::Read | OpAccess::CondRead => (true, false),
                OpAccess::Write | OpAccess::CondWrite => (false, true),
                OpAccess::ReadWrite | OpAccess::ReadCondWrite => (true, true),
                _ => return None,
            };
            let address = memory.virtual_address(0, |register_name, _, _| {
                if register_name == Register::RIP {
                    return Some(next);
                }
                if register_name.is_segment_register() {
                    return if matches!(register_name, Register::FS | Register::GS) { None } else { Some(0) };
                }
                let full = register_name.full_register();
                let value = register(&format!("{full:?}").to_ascii_lowercase())?;
                let size = register_name.size();
                Some(if size >= 8 { value } else { value & ((1u64 << (8 * size)) - 1) })
            })?;
            Some(MemoryOperand { address, size: memory.memory_size().size(), read, write })
        })
        .collect()
}

/// De onde vem o valor de um operando de memória: o registrador que recebe
/// a leitura (o valor está no passo seguinte), o registrador ou o imediato
/// gravado.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValueHint {
    LoadInto(String),
    StoreFrom(String),
    StoreImmediate(u64),
}

pub fn value_hint(ip: u64, bytes: &[u8]) -> Option<ValueHint> {
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.code() == Code::INVALID || instruction.op_count() < 2 {
        return None;
    }
    let name = |register: Register| format!("{:?}", register.full_register()).to_ascii_lowercase();
    match (instruction.op0_kind(), instruction.op1_kind()) {
        (OpKind::Register, OpKind::Memory) => Some(ValueHint::LoadInto(name(instruction.op0_register()))),
        (OpKind::Memory, OpKind::Register) => Some(ValueHint::StoreFrom(name(instruction.op1_register()))),
        (OpKind::Memory, OpKind::Immediate8 | OpKind::Immediate16 | OpKind::Immediate32 | OpKind::Immediate8to32 | OpKind::Immediate8to64 | OpKind::Immediate32to64 | OpKind::Immediate64) => Some(ValueHint::StoreImmediate(instruction.immediate(1))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opennt_kd::symbols::{Module, Symbol};

    #[test]
    fn disassembles_with_symbols() {
        let mut symbols = Symbols::default();
        symbols.set_kernel(Module::new("kernel", "kernel.elf", 0x1000, 0x2000, vec![Symbol { address: 0x1000, size: 0x20, name: "kernel::f".into(), function: true }, Symbol { address: 0x1020, size: 0x10, name: "kernel::g".into(), function: true }], "teste"));
        // push rbp; mov rbp, rsp; call kernel::g; mov rax, [rip+0x10]; pop rbp; ret
        let code = [0x55, 0x48, 0x89, 0xE5, 0xE8, 0x17, 0, 0, 0, 0x48, 0x8B, 0x05, 0x10, 0, 0, 0, 0x5D, 0xC3];
        let lines = disassemble(0x1000, &code, Some(&symbols));
        assert_eq!(lines.len(), 6);
        assert_eq!(lines[0].label.as_deref(), Some("kernel::f"));
        assert!(lines[0].text.starts_with("push"), "{}", lines[0].text);
        assert_eq!(lines[2].target, Some(0x1020));
        assert_eq!(lines[2].comment.as_deref(), Some("kernel::g"));
        assert_eq!(lines[2].bytes, "e817000000");
        assert_eq!(lines[3].comment.as_deref(), Some("[kernel::g]"));
        assert!(lines[5].text.starts_with("ret"));
        assert_eq!(window_start(0x1010, &symbols, 0x40), 0x1000);
        assert!(clip(lines.clone(), 0x1004, 0x100, 0x100).is_some());
        assert!(clip(lines, 0x1005, 0x100, 0x100).is_none());
    }

    #[test]
    fn blocks_and_memory_operands() {
        // mov rax, [rbx+8]; add rax, 1; call +0; ret
        let code = [0x48, 0x8B, 0x43, 0x08, 0x48, 0x83, 0xC0, 0x01, 0xE8, 0, 0, 0, 0, 0xC3];
        let list = block(0x1000, &code, None);
        assert_eq!(list.len(), 3);
        assert_eq!(list[2], (0x1008, Flow::Call(5)));
        assert_eq!(block(0x1000, &code, Some(0x1004)).len(), 1);
        assert_eq!(instruction_length(0x1000, &code), Some(4));
        let operands = memory_operands(0x1000, &code, &|name| (name == "rbx").then_some(0x5000));
        assert_eq!(operands, vec![MemoryOperand { address: 0x5008, size: 8, read: true, write: false }]);
        // mov [rsp+0x10], ecx: escrita de 4 bytes.
        let store = [0x89, 0x4C, 0x24, 0x10];
        assert_eq!(memory_operands(0x2000, &store, &|name| (name == "rsp").then_some(0x8000)), vec![MemoryOperand { address: 0x8010, size: 4, read: false, write: true }]);
    }
}
