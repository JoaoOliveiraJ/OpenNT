//! Desmontagem x86-64 (iced-x86, sintaxe MASM, a do WinDbg) com os
//! símbolos do cliente: o nome da função no começo dela e, em comentário,
//! o destino de cada desvio e o endereço de cada operando relativo ao RIP.

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, MasmFormatter, OpKind};
use kd_client::Symbols;

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

#[cfg(test)]
mod tests {
    use super::*;
    use kd_client::symbols::{Module, Symbol};

    #[test]
    fn disassembles_with_symbols() {
        let mut symbols = Symbols::default();
        symbols.set_kernel(Module {
            name: "kernel".into(),
            path: "kernel.elf".into(),
            base: 0x1000,
            end: 0x2000,
            symbols: vec![Symbol { address: 0x1000, size: 0x20, name: "kernel::f".into(), function: true }, Symbol { address: 0x1020, size: 0x10, name: "kernel::g".into(), function: true }],
            source: "teste".into(),
        });
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
}
