//! O montador da janela CPU (a tecla Espaço): uma linha de assembly x86-64
//! em sintaxe Intel vira bytes, para o patch de uma instrução.
//!
//! O texto vira um mnemônico e até três operandos (registrador, imediato ou
//! memória `[base + índice*escala + desloc]` com `byte/word/dword/qword
//! ptr` opcional). Cada código de instrução do iced com aquele mnemônico é
//! tentado com os operandos; o codificador recusa os que não servem
//! (registrador da classe errada, imediato grande demais, desvio fora do
//! alcance) e fica a codificação mais curta. Os números são hexadecimais
//! por padrão (`0n` para decimal), como nas expressões do depurador; um
//! nome qualquer passa pelo resolvedor (símbolos, rótulos).

use std::collections::HashMap;
use std::sync::OnceLock;

use iced_x86::{Code, Encoder, Instruction, MemoryOperand, Mnemonic, Register};

/// Um operando já lido.
#[derive(Clone, Copy, Debug)]
enum Operand {
    Register(Register),
    Immediate(i64),
    /// A memória e o tamanho pedido (bytes; 0 = não dito).
    Memory(MemoryOperand, usize),
}

/// Os códigos de cada mnemônico (minúsculo).
fn codes_by_mnemonic() -> &'static HashMap<String, Vec<Code>> {
    static TABLE: OnceLock<HashMap<String, Vec<Code>>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table: HashMap<String, Vec<Code>> = HashMap::new();
        for code in Code::values() {
            let mnemonic = code.mnemonic();
            if mnemonic == Mnemonic::INVALID {
                continue;
            }
            table.entry(format!("{mnemonic:?}").to_ascii_lowercase()).or_default().push(code);
        }
        table
    })
}

/// Os registradores pelo nome (minúsculo).
fn registers_by_name() -> &'static HashMap<String, Register> {
    static TABLE: OnceLock<HashMap<String, Register>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = HashMap::new();
        for register in Register::values() {
            if register != Register::None {
                table.insert(format!("{register:?}").to_ascii_lowercase(), register);
            }
        }
        table
    })
}

fn register(name: &str) -> Option<Register> {
    registers_by_name().get(&name.trim().to_ascii_lowercase()).copied()
}

/// Um número (hexadecimal por padrão, `0x`, `0n` decimal, `h` no fim) ou
/// um nome pelo resolvedor.
fn number(text: &str, resolve: &dyn Fn(&str) -> Option<u64>) -> Result<i64, String> {
    let text = text.trim();
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest.trim()),
        None => (false, text),
    };
    let cleaned = digits.replace(['`', '_'], "");
    let value = if let Some(decimal) = cleaned.strip_prefix("0n") {
        decimal.parse::<u64>().ok()
    } else if let Some(hex) = cleaned.strip_prefix("0x").or_else(|| cleaned.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if let Some(hex) = cleaned.strip_suffix('h').filter(|hex| hex.chars().all(|character| character.is_ascii_hexdigit())) {
        u64::from_str_radix(hex, 16).ok()
    } else if cleaned.chars().all(|character| character.is_ascii_hexdigit()) && !cleaned.is_empty() {
        u64::from_str_radix(&cleaned, 16).ok()
    } else {
        None
    };
    let value = match value {
        Some(value) => value,
        None => resolve(digits).ok_or_else(|| format!("operando desconhecido: {digits}"))?,
    };
    Ok(if negative { (value as i64).wrapping_neg() } else { value as i64 })
}

/// `[base + índice*escala + desloc]` (com `seg:` antes, opcional).
fn memory(inner: &str, segment: Register, resolve: &dyn Fn(&str) -> Option<u64>) -> Result<MemoryOperand, String> {
    let mut base = Register::None;
    let mut index = Register::None;
    let mut scale = 1u32;
    let mut displacement: i64 = 0;
    // Termos com o sinal na frente.
    let mut terms = Vec::new();
    let mut current = String::new();
    let mut sign = 1i64;
    for character in inner.chars() {
        match character {
            '+' | '-' => {
                if !current.trim().is_empty() {
                    terms.push((sign, current.trim().to_string()));
                }
                current.clear();
                sign = if character == '-' { -1 } else { 1 };
            }
            _ => current.push(character),
        }
    }
    if !current.trim().is_empty() {
        terms.push((sign, current.trim().to_string()));
    }
    if terms.is_empty() {
        return Err("memoria vazia".into());
    }
    for (sign, term) in terms {
        if let Some((left, right)) = term.split_once('*') {
            let (name, factor) = if register(left).is_some() { (left, right) } else { (right, left) };
            let reg = register(name).ok_or_else(|| format!("indice invalido: {term}"))?;
            if sign < 0 || index != Register::None {
                return Err(format!("indice invalido: {term}"));
            }
            index = reg;
            scale = number(factor, resolve)? as u32;
            if !matches!(scale, 1 | 2 | 4 | 8) {
                return Err(format!("escala invalida: {scale}"));
            }
        } else if let Some(reg) = register(&term) {
            if sign < 0 {
                return Err(format!("registrador subtraido: {term}"));
            }
            if base == Register::None {
                base = reg;
            } else if index == Register::None {
                index = reg;
            } else {
                return Err(format!("registradores demais: {term}"));
            }
        } else {
            displacement = displacement.wrapping_add(sign * number(&term, resolve)?);
        }
    }
    let size = if base == Register::RIP {
        8
    } else if base == Register::None && index == Register::None {
        4
    } else if displacement == 0 {
        0
    } else {
        1
    };
    Ok(MemoryOperand::new(base, index, scale, displacement, size, false, segment))
}

/// O tamanho de `byte ptr` e afins.
fn size_keyword(word: &str) -> Option<usize> {
    Some(match word {
        "byte" => 1,
        "word" => 2,
        "dword" => 4,
        "fword" => 6,
        "qword" => 8,
        "tbyte" | "tword" => 10,
        "xmmword" | "oword" => 16,
        "ymmword" => 32,
        "zmmword" => 64,
        _ => return None,
    })
}

fn operand(text: &str, resolve: &dyn Fn(&str) -> Option<u64>) -> Result<Operand, String> {
    let lower = text.trim().to_ascii_lowercase();
    let mut rest = lower.as_str();
    let mut size = 0;
    if let Some((first, after)) = rest.split_once(char::is_whitespace) {
        if let Some(bytes) = size_keyword(first) {
            size = bytes;
            rest = after.trim_start();
            rest = rest.strip_prefix("ptr").unwrap_or(rest).trim_start();
        }
    }
    if let Some(open) = rest.find('[') {
        let close = rest.rfind(']').ok_or("falta o ]")?;
        let before = rest[..open].trim().trim_end_matches(':');
        let segment = if before.is_empty() { Register::None } else { register(before).ok_or_else(|| format!("segmento invalido: {before}"))? };
        // O texto original (com a caixa dos símbolos).
        let original = text.trim();
        let original_open = original.find('[').unwrap_or(0);
        let original_close = original.rfind(']').unwrap_or(original.len());
        let inner = if original_close > original_open { &original[original_open + 1..original_close] } else { &rest[open + 1..close] };
        return Ok(Operand::Memory(memory(inner, segment, resolve)?, size));
    }
    if let Some(reg) = register(rest) {
        return Ok(Operand::Register(reg));
    }
    Ok(Operand::Immediate(number(text.trim(), resolve)?))
}

/// Divide os operandos pelas vírgulas fora dos colchetes.
fn split_operands(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0;
    let mut current = String::new();
    for character in text.chars() {
        match character {
            '[' => {
                depth += 1;
                current.push(character);
            }
            ']' => {
                depth -= 1;
                current.push(character);
            }
            ',' if depth == 0 => {
                parts.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(character),
        }
    }
    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }
    parts
}

fn is_branch(code: Code) -> bool {
    code.is_jmp_short_or_near() || code.is_jcc_short_or_near() || code.is_call_near() || code.is_loop() || code.is_jcx_short()
}

/// A instrução de `code` com os operandos (os imediatos como i32, u32 ou
/// 64 bits, conforme cabem).
fn build(code: Code, operands: &[Operand]) -> Option<Instruction> {
    use Operand::{Immediate as I, Memory as M, Register as R};
    let small = |value: i64| -> Option<i32> { i32::try_from(value).ok() };
    let result = match operands {
        [] => Ok(Instruction::with(code)),
        [R(a)] => Instruction::with1(code, *a),
        [M(a, _)] => Instruction::with1(code, *a),
        [I(a)] => match small(*a) {
            Some(value) => Instruction::with1(code, value),
            None => Instruction::with1(code, *a as u32),
        },
        [R(a), R(b)] => Instruction::with2(code, *a, *b),
        [R(a), M(b, _)] => Instruction::with2(code, *a, *b),
        [M(a, _), R(b)] => Instruction::with2(code, *a, *b),
        [R(a), I(b)] => match small(*b) {
            Some(value) => Instruction::with2(code, *a, value).or_else(|_| Instruction::with2(code, *a, *b)),
            None if *b >= 0 && *b <= u32::MAX as i64 => Instruction::with2(code, *a, *b as u32).or_else(|_| Instruction::with2(code, *a, *b)),
            None => Instruction::with2(code, *a, *b as u64),
        },
        [M(a, _), I(b)] => match small(*b) {
            Some(value) => Instruction::with2(code, *a, value),
            None => Instruction::with2(code, *a, *b as u32),
        },
        [I(a), R(b)] => Instruction::with2(code, *a as i32, *b),
        [I(a), I(b)] => Instruction::with2(code, *a as i32, *b as i32),
        [R(a), R(b), R(c)] => Instruction::with3(code, *a, *b, *c),
        [R(a), R(b), M(c, _)] => Instruction::with3(code, *a, *b, *c),
        [R(a), R(b), I(c)] => Instruction::with3(code, *a, *b, *c as i32),
        [R(a), M(b, _), I(c)] => Instruction::with3(code, *a, *b, *c as i32),
        [R(a), M(b, _), R(c)] => Instruction::with3(code, *a, *b, *c),
        [M(a, _), R(b), R(c)] => Instruction::with3(code, *a, *b, *c),
        [M(a, _), R(b), I(c)] => Instruction::with3(code, *a, *b, *c as i32),
        _ => return None,
    };
    result.ok()
}

/// Monta `text` em `address`; `resolve` acha os nomes (símbolos, rótulos).
pub fn assemble(text: &str, address: u64, resolve: &dyn Fn(&str) -> Option<u64>) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("instrucao vazia".into());
    }
    let mut words = text.splitn(2, char::is_whitespace);
    let mut mnemonic = words.next().unwrap_or("").to_ascii_lowercase();
    let mut rest = words.next().unwrap_or("").trim().to_string();
    let lock = mnemonic == "lock";
    if lock {
        let mut inner = rest.splitn(2, char::is_whitespace);
        mnemonic = inner.next().unwrap_or("").to_ascii_lowercase();
        rest = inner.next().unwrap_or("").trim().to_string();
    }
    // Sinônimos comuns.
    let mnemonic = match mnemonic.as_str() {
        "ret" | "retn" => "ret".to_string(),
        "jz" => "je".to_string(),
        "jnz" => "jne".to_string(),
        "jc" | "jnae" => "jb".to_string(),
        "jnc" | "jae" => "jae".to_string(),
        "jnb" => "jae".to_string(),
        "jna" => "jbe".to_string(),
        "jnbe" => "ja".to_string(),
        "jnge" => "jl".to_string(),
        "jnl" => "jge".to_string(),
        "jng" => "jle".to_string(),
        "jnle" => "jg".to_string(),
        "jpe" => "jp".to_string(),
        "jpo" => "jnp".to_string(),
        "int3" => "int3".to_string(),
        other => other.to_string(),
    };
    let codes = codes_by_mnemonic().get(&mnemonic).ok_or_else(|| format!("mnemonico desconhecido: {mnemonic}"))?;
    let operands: Vec<Operand> = split_operands(&rest).iter().map(|part| operand(part, resolve)).collect::<Result<_, _>>()?;
    let wanted_size = operands.iter().find_map(|operand| match operand {
        Operand::Memory(_, size) if *size != 0 => Some(*size),
        _ => None,
    });
    let has_memory = operands.iter().any(|operand| matches!(operand, Operand::Memory(..)));
    let mut best: Option<(Vec<u8>, usize)> = None;
    let mut sizes = std::collections::BTreeSet::new();
    let mut last_error = String::new();
    for &code in codes {
        // Só os códigos com o mesmo número de operandos (e válidos em 64 bits).
        let info = code.op_code();
        if info.op_count() as usize != operands.len() || !info.mode64() {
            continue;
        }
        // Desvios de 16 bits (66h) truncam o RIP: fora.
        if is_branch(code) && info.operand_size() == 16 {
            continue;
        }
        let instruction = if is_branch(code) {
            match operands.as_slice() {
                [Operand::Immediate(target)] => match Instruction::with_branch(code, *target as u64) {
                    Ok(instruction) => instruction,
                    Err(error) => {
                        last_error = error.to_string();
                        continue;
                    }
                },
                _ => continue,
            }
        } else {
            match build(code, &operands) {
                Some(instruction) => instruction,
                None => continue,
            }
        };
        let mut instruction = instruction;
        if lock {
            instruction.set_has_lock_prefix(true);
        }
        let memory_size = if has_memory { instruction.memory_size().size() } else { 0 };
        if let Some(size) = wanted_size {
            if memory_size != size {
                continue;
            }
        }
        let mut encoder = Encoder::new(64);
        match encoder.encode(&instruction, address) {
            Ok(_) => {
                let bytes = encoder.take_buffer();
                if has_memory {
                    sizes.insert(memory_size);
                }
                if best.as_ref().is_none_or(|(current, _)| bytes.len() < current.len()) {
                    best = Some((bytes, memory_size));
                }
            }
            Err(error) => last_error = error.to_string(),
        }
    }
    // Memória sem tamanho e sem registrador que o fixe: ambíguo.
    if wanted_size.is_none() && sizes.len() > 1 && !operands.iter().any(|operand| matches!(operand, Operand::Register(_))) {
        return Err("tamanho ambiguo: use byte/word/dword/qword ptr".into());
    }
    best.map(|(bytes, _)| bytes).ok_or_else(|| if last_error.is_empty() { format!("operandos invalidos para {mnemonic}") } else { format!("{mnemonic}: {last_error}") })
}

#[cfg(test)]
mod tests {
    use super::assemble;

    fn none(_: &str) -> Option<u64> {
        None
    }

    #[test]
    fn assembles_common_instructions() {
        assert_eq!(assemble("nop", 0x1000, &none), Ok(vec![0x90]));
        assert_eq!(assemble("int3", 0x1000, &none), Ok(vec![0xCC]));
        assert_eq!(assemble("ret", 0x1000, &none), Ok(vec![0xC3]));
        assert_eq!(assemble("xor eax, eax", 0x1000, &none), Ok(vec![0x31, 0xC0]));
        assert_eq!(assemble("mov rcx, rdx", 0x1000, &none), Ok(vec![0x48, 0x89, 0xD1]));
        assert_eq!(assemble("mov eax, 1", 0x1000, &none), Ok(vec![0xB8, 1, 0, 0, 0]));
        assert_eq!(assemble("add rsp, 28", 0x1000, &none), Ok(vec![0x48, 0x83, 0xC4, 0x28]));
        assert_eq!(assemble("push rbp", 0x1000, &none), Ok(vec![0x55]));
        assert_eq!(assemble("mov qword ptr [rsp+8], rcx", 0x1000, &none), Ok(vec![0x48, 0x89, 0x4C, 0x24, 0x08]));
        assert_eq!(assemble("mov dword ptr [rax], 0n10", 0x1000, &none), Ok(vec![0xC7, 0x00, 10, 0, 0, 0]));
        assert_eq!(assemble("lea rcx, [rip+0x2000]", 0x1000, &none).map(|bytes| bytes.len()), Ok(7));
    }

    #[test]
    fn branches_use_the_address() {
        // jmp curto para 0x1010 a partir de 0x1000: EB 0E.
        assert_eq!(assemble("jmp 1010", 0x1000, &none), Ok(vec![0xEB, 0x0E]));
        assert_eq!(assemble("je 1010", 0x1000, &none), Ok(vec![0x74, 0x0E]));
        assert_eq!(assemble("jz 1010", 0x1000, &none), Ok(vec![0x74, 0x0E]));
        // call rel32 para um símbolo.
        let resolve = |name: &str| (name == "alvo").then_some(0x2000u64);
        assert_eq!(assemble("call alvo", 0x1000, &resolve), Ok(vec![0xE8, 0xFB, 0x0F, 0, 0]));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(assemble("", 0, &none).is_err());
        assert!(assemble("frobnicate eax", 0, &none).is_err());
        assert!(assemble("mov eax, rbx", 0, &none).is_err());
        assert!(assemble("inc [rax]", 0, &none).unwrap_err().contains("ambiguo"));
        assert_eq!(assemble("inc byte ptr [rax]", 0, &none), Ok(vec![0xFE, 0x00]));
    }
}
