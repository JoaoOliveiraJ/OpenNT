//! Referências achadas no código decodificado: strings usadas por uma
//! instrução (o operando de memória ou o imediato aponta para texto ASCII
//! ou UTF-16), referências a um endereço (chamadas, saltos, operandos e
//! imediatos), constantes, chamadas para fora do módulo (diretas ou pela
//! IAT) e os chamadores de uma função.

use super::decode::{Class, Flow, Insn};

/// Uma instrução que usa uma string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StringRef {
    /// A instrução.
    pub address: u64,
    /// O começo da string.
    pub target: u64,
    pub text: String,
    /// UTF-16.
    pub wide: bool,
}

/// Maior texto guardado (o resto vira `...`).
const TEXT_LIMIT: usize = 256;
/// Quanto ler em cada endereço candidato.
const READ_LIMIT: usize = 512;

/// Caractere imprimível de uma string ASCII.
pub(crate) fn printable_byte(byte: u8) -> bool {
    (0x20..=0x7E).contains(&byte) || matches!(byte, b'\t' | b'\r' | b'\n')
}

/// Unidade imprimível de uma string UTF-16 (o latim do BMP).
pub(crate) fn printable_unit(unit: u16) -> bool {
    (0x20..=0x7E).contains(&unit) || (0xA0..=0xFF).contains(&unit) || matches!(unit, 9 | 10 | 13)
}

/// Acrescenta um caractere ao texto, com `\r`, `\n` e `\t` escapados.
/// Devolve `false` quando o texto chegou ao limite.
pub(crate) fn push_char(text: &mut String, count: &mut usize, character: char) -> bool {
    if *count >= TEXT_LIMIT {
        return false;
    }
    match character {
        '\r' => text.push_str("\\r"),
        '\n' => text.push_str("\\n"),
        '\t' => text.push_str("\\t"),
        other => text.push(other),
    }
    *count += 1;
    true
}

/// Uma string ASCII no começo de `bytes`: (texto, caracteres, terminada
/// por NUL ou pelo fim do buffer).
pub(crate) fn ascii_run(bytes: &[u8]) -> (String, usize, bool) {
    let mut text = String::new();
    let mut shown = 0;
    let mut count = 0;
    for &byte in bytes {
        if byte == 0 {
            return (finish(text, count, shown), count, true);
        }
        if !printable_byte(byte) {
            return (finish(text, count, shown), count, false);
        }
        push_char(&mut text, &mut shown, byte as char);
        count += 1;
    }
    (finish(text, count, shown), count, true)
}

/// Uma string UTF-16LE no começo de `bytes`: (texto, caracteres,
/// terminada por NUL ou pelo fim do buffer).
pub(crate) fn wide_run(bytes: &[u8]) -> (String, usize, bool) {
    let mut text = String::new();
    let mut shown = 0;
    let mut count = 0;
    for pair in bytes.chunks_exact(2) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit == 0 {
            return (finish(text, count, shown), count, true);
        }
        if !printable_unit(unit) {
            return (finish(text, count, shown), count, false);
        }
        push_char(&mut text, &mut shown, char::from_u32(unit as u32).unwrap_or('?'));
        count += 1;
    }
    (finish(text, count, shown), count, true)
}

fn finish(mut text: String, count: usize, shown: usize) -> String {
    if count > shown {
        text.push_str("...");
    }
    text
}

/// A string no começo de `bytes`, se houver uma de pelo menos
/// `min_length` caracteres terminada por NUL (ou pelo fim do buffer):
/// (texto, UTF-16). O UTF-16 tem preferência quando os bytes 1 e 3 são
/// zero.
pub fn read_string(bytes: &[u8], min_length: usize) -> Option<(String, bool)> {
    let min_length = min_length.max(1);
    if bytes.len() >= 4 && bytes[1] == 0 && bytes[3] == 0 {
        let (text, count, terminated) = wide_run(bytes);
        if terminated && count >= min_length {
            return Some((text, true));
        }
    }
    let (text, count, terminated) = ascii_run(bytes);
    (terminated && count >= min_length).then_some((text, false))
}

/// O endereço que uma instrução pode estar usando como string.
fn string_candidates(insn: &Insn) -> [Option<u64>; 2] {
    let large = insn.immediate.filter(|&value| value >= 0x10000);
    match insn.class {
        Class::Lea => [insn.memory, None],
        Class::Mov | Class::Push => [insn.memory, large],
        _ => [None, None],
    }
}

/// As instruções que usam strings: `lea`/`mov`/`push` com operando de
/// memória (relativo ao RIP ou absoluto) ou imediato (a partir de 0x10000)
/// que aponta para texto. `memory` lê do alvo (`None` = ilegível). Uma
/// entrada por instrução.
pub fn string_references(insns: &[Insn], memory: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>, min_length: usize) -> Vec<StringRef> {
    let mut output = Vec::new();
    for insn in insns {
        for candidate in string_candidates(insn).into_iter().flatten() {
            let Some(bytes) = memory(candidate, READ_LIMIT) else { continue };
            if let Some((text, wide)) = read_string(&bytes, min_length) {
                output.push(StringRef { address: insn.address, target: candidate, text, wide });
                break;
            }
        }
    }
    output
}

/// O tipo de uma referência.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefKind {
    Call,
    Jump,
    Memory,
    Immediate,
}

fn branch_kind(insn: &Insn) -> RefKind {
    if matches!(insn.flow, Flow::Call | Flow::IndirectCall) {
        RefKind::Call
    } else {
        RefKind::Jump
    }
}

/// As referências a `address`: destino de desvio, operando de memória ou
/// imediato. (instrução, tipo).
pub fn references_to(insns: &[Insn], address: u64) -> Vec<(u64, RefKind)> {
    let mut output = Vec::new();
    for insn in insns {
        if insn.target == Some(address) {
            output.push((insn.address, branch_kind(insn)));
        } else if insn.memory == Some(address) {
            output.push((insn.address, RefKind::Memory));
        } else if insn.immediate == Some(address) {
            output.push((insn.address, RefKind::Immediate));
        }
    }
    output
}

/// Tudo o que aponta para `[start, end)`: (instrução, endereço apontado,
/// tipo).
pub fn references_in(insns: &[Insn], start: u64, end: u64) -> Vec<(u64, u64, RefKind)> {
    let inside = |address: u64| address >= start && address < end;
    let mut output = Vec::new();
    for insn in insns {
        if let Some(target) = insn.target.filter(|&target| inside(target)) {
            output.push((insn.address, target, branch_kind(insn)));
        }
        if let Some(memory) = insn.memory.filter(|&memory| inside(memory)) {
            output.push((insn.address, memory, RefKind::Memory));
        }
        if let Some(value) = insn.immediate.filter(|&value| inside(value)) {
            output.push((insn.address, value, RefKind::Immediate));
        }
    }
    output
}

/// Cabe em 32 bits com sinal (o que um imediato de 32 bits estendido
/// representa).
fn fits_signed_32(value: u64) -> bool {
    value >> 32 == 0 || value >> 32 == 0xFFFF_FFFF
}

/// As instruções com o imediato `value` (também quando só os 32 bits de
/// baixo coincidem, como no `cmp eax, -1` contra `0xffffffffffffffff`).
pub fn constant_references(insns: &[Insn], value: u64) -> Vec<u64> {
    insns
        .iter()
        .filter(|insn| insn.immediate.is_some_and(|immediate| immediate == value || (immediate as u32 == value as u32 && fits_signed_32(immediate) && fits_signed_32(value))))
        .map(|insn| insn.address)
        .collect()
}

/// Uma chamada (ou salto) para fora do módulo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleCall {
    pub address: u64,
    pub target: u64,
    /// A entrada da IAT de um `call [rip+x]`.
    pub slot: Option<u64>,
}

/// As chamadas e saltos para fora de `inside` (início, fim exclusivo):
/// diretos, ou indiretos pela memória cuja entrada de 8 bytes aponta para
/// fora.
pub fn intermodular_calls(insns: &[Insn], inside: (u64, u64), memory: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>) -> Vec<ModuleCall> {
    let outside = |address: u64| address < inside.0 || address >= inside.1;
    let mut output = Vec::new();
    for insn in insns {
        match insn.flow {
            Flow::Call | Flow::Jump => {
                if let Some(target) = insn.target.filter(|&target| outside(target)) {
                    output.push(ModuleCall { address: insn.address, target, slot: None });
                }
            }
            Flow::IndirectCall | Flow::IndirectJump => {
                let Some(slot) = insn.memory else { continue };
                let Some(bytes) = memory(slot, 8).filter(|bytes| bytes.len() >= 8) else { continue };
                let target = u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]));
                if target != 0 && outside(target) {
                    output.push(ModuleCall { address: insn.address, target, slot: Some(slot) });
                }
            }
            _ => {}
        }
    }
    output
}

/// As chamadas diretas a `function`.
pub fn callers(insns: &[Insn], function: u64) -> Vec<u64> {
    insns.iter().filter(|insn| insn.flow == Flow::Call && insn.target == Some(function)).map(|insn| insn.address).collect()
}

/// O índice de referências cruzadas de um módulo: para cada endereço
/// referenciado, as instruções que o referenciam (destino de desvio,
/// operando de memória e imediato). Imediatos só entram quando caem dentro
/// de `range` (um número qualquer não é referência). Feito uma vez por
/// módulo, responde qualquer "quem referencia X" na hora.
pub fn xref_index(insns: &[Insn], range: (u64, u64)) -> std::collections::HashMap<u64, Vec<(u64, RefKind)>> {
    let mut index: std::collections::HashMap<u64, Vec<(u64, RefKind)>> = std::collections::HashMap::new();
    let inside = |address: u64| address >= range.0 && address < range.1;
    for insn in insns {
        if let Some(target) = insn.target {
            index.entry(target).or_default().push((insn.address, branch_kind(insn)));
        }
        if let Some(memory) = insn.memory {
            index.entry(memory).or_default().push((insn.address, RefKind::Memory));
        }
        if let Some(value) = insn.immediate.filter(|&value| inside(value)) {
            index.entry(value).or_default().push((insn.address, RefKind::Immediate));
        }
    }
    index
}

#[cfg(test)]
mod tests {
    use super::super::decode::decode_all;
    use super::*;

    const CODE: u64 = 0x1000;
    const DATA: u64 = 0x10000;

    /// Uma memória de mentira: o código e uma área de dados.
    struct Fake {
        code: Vec<u8>,
        data: Vec<u8>,
    }

    impl Fake {
        fn read(&self, address: u64, length: usize) -> Option<Vec<u8>> {
            let (base, bytes) = if address >= DATA { (DATA, &self.data) } else { (CODE, &self.code) };
            let offset = address.checked_sub(base)? as usize;
            let slice = bytes.get(offset..)?;
            Some(slice[..slice.len().min(length)].to_vec())
        }
    }

    /// `prefixo` + disp32 relativo ao RIP até `target`.
    fn rip_relative(code: &mut Vec<u8>, prefix: &[u8], target: u64) {
        let next = CODE + code.len() as u64 + prefix.len() as u64 + 4;
        code.extend_from_slice(prefix);
        code.extend_from_slice(&((target as i64 - next as i64) as i32).to_le_bytes());
    }

    fn sample() -> Fake {
        let mut data = vec![0u8; 0x100];
        data[0..12].copy_from_slice(b"Hello world\0");
        let wide: Vec<u8> = "Wide text\0".encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
        data[0x20..0x20 + wide.len()].copy_from_slice(&wide);
        data[0x40..0x4E].copy_from_slice(b"pushed string\0");
        data[0x60..0x6E].copy_from_slice(b"movabs string\0");
        data[0x80..0x84].copy_from_slice(&[1, 2, 3, 0]);
        data[0x90..0x98].copy_from_slice(&0x7FF8_0000_1234u64.to_le_bytes());
        data[0xA0..0xA6].copy_from_slice(b"line\n\0");
        let mut code = Vec::new();
        // lea rcx, [rip+x] (com REX.W) para o ASCII.
        rip_relative(&mut code, &[0x48, 0x8D, 0x0D], DATA);
        // lea edx, [rip+x] (sem REX) para o UTF-16.
        rip_relative(&mut code, &[0x8D, 0x15], DATA + 0x20);
        // push imm32 para uma string.
        code.extend_from_slice(&[0x68]);
        code.extend_from_slice(&((DATA + 0x40) as u32).to_le_bytes());
        // mov rax, imm64 para uma string.
        code.extend_from_slice(&[0x48, 0xB8]);
        code.extend_from_slice(&(DATA + 0x60).to_le_bytes());
        // lea rax, [rip+x] para bytes que não são texto.
        rip_relative(&mut code, &[0x48, 0x8D, 0x05], DATA + 0x80);
        // call rel32 para a primeira instrução (offset 0).
        let next = CODE + code.len() as u64 + 5;
        code.push(0xE8);
        code.extend_from_slice(&((CODE as i64 - next as i64) as i32).to_le_bytes());
        // call [rip+x]: a entrada da IAT aponta para fora.
        rip_relative(&mut code, &[0xFF, 0x15], DATA + 0x90);
        // call rel32 para fora do módulo.
        let next = CODE + code.len() as u64 + 5;
        code.push(0xE8);
        code.extend_from_slice(&((0x7000_0000i64 - next as i64) as i32).to_le_bytes());
        // cmp eax, -1 e mov ecx, 0x1234.
        code.extend_from_slice(&[0x83, 0xF8, 0xFF, 0xB9, 0x34, 0x12, 0, 0]);
        // mov rdx, [rip+x] para "line\n".
        rip_relative(&mut code, &[0x48, 0x8B, 0x15], DATA + 0xA0);
        code.push(0xC3);
        Fake { code, data }
    }

    #[test]
    fn reads_strings() {
        assert_eq!(read_string(b"abcd\0", 4), Some(("abcd".into(), false)));
        assert_eq!(read_string(b"abc\0", 4), None);
        assert_eq!(read_string(b"abcd\x01", 4), None);
        assert_eq!(read_string(b"abcd", 4), Some(("abcd".into(), false)));
        assert_eq!(read_string(b"a\tb\r\n\0", 3), Some(("a\\tb\\r\\n".into(), false)));
        let wide: Vec<u8> = "Olá mundo\0".encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
        assert_eq!(read_string(&wide, 4), Some(("Olá mundo".into(), true)));
        let long = vec![b'x'; 300];
        let (text, wide) = read_string(&long, 4).unwrap();
        assert!(!wide && text.ends_with("...") && text.len() == 259);
    }

    #[test]
    fn finds_string_references() {
        let fake = sample();
        let insns = decode_all(&fake.code, CODE);
        let refs = string_references(&insns, &mut |address, length| fake.read(address, length), 4);
        let summary: Vec<(u64, &str, bool)> = refs.iter().map(|reference| (reference.target, reference.text.as_str(), reference.wide)).collect();
        assert_eq!(summary, vec![(DATA, "Hello world", false), (DATA + 0x20, "Wide text", true), (DATA + 0x40, "pushed string", false), (DATA + 0x60, "movabs string", false), (DATA + 0xA0, "line\\n", false)]);
        // A primeira e a segunda são as duas formas do lea.
        assert_eq!(refs[0].address, CODE);
        assert_eq!(refs[1].address, CODE + 7);
    }

    #[test]
    fn references_and_callers() {
        let fake = sample();
        let insns = decode_all(&fake.code, CODE);
        assert_eq!(callers(&insns, CODE).len(), 1);
        let to_first = references_to(&insns, CODE);
        assert_eq!(to_first.len(), 1);
        assert_eq!(to_first[0].1, RefKind::Call);
        assert_eq!(references_to(&insns, DATA), vec![(CODE, RefKind::Memory)]);
        assert_eq!(references_to(&insns, DATA + 0x40)[0].1, RefKind::Immediate);
        let inside = references_in(&insns, DATA, DATA + 0x100);
        assert!(inside.len() >= 6);
        assert!(inside.iter().all(|(_, address, _)| (DATA..DATA + 0x100).contains(address)));
        assert_eq!(constant_references(&insns, u64::MAX).len(), 1);
        assert_eq!(constant_references(&insns, 0xFFFF_FFFF).len(), 1);
        assert_eq!(constant_references(&insns, 0x1234).len(), 1);
    }

    #[test]
    fn intermodular() {
        let fake = sample();
        let insns = decode_all(&fake.code, CODE);
        let calls = intermodular_calls(&insns, (CODE, CODE + 0x1000), &mut |address, length| fake.read(address, length));
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].slot, Some(DATA + 0x90));
        assert_eq!(calls[0].target, 0x7FF8_0000_1234);
        assert_eq!((calls[1].target, calls[1].slot), (0x7000_0000, None));
    }

    #[test]
    fn cross_reference_index() {
        let fake = sample();
        let insns = decode_all(&fake.code, CODE);
        let index = xref_index(&insns, (DATA, DATA + 0x100));
        // A primeira instrução: chamada pelo `call rel32`.
        assert_eq!(index[&CODE], vec![(callers(&insns, CODE)[0], RefKind::Call)]);
        assert_eq!(index[&DATA], vec![(CODE, RefKind::Memory)]);
        // O imediato do `push` cai na faixa; o 0x1234 do `mov ecx`, não.
        assert_eq!(index[&(DATA + 0x40)][0].1, RefKind::Immediate);
        assert!(!index.contains_key(&0x1234));
        // O índice responde o mesmo que a varredura direta.
        for (target, list) in &index {
            let direct: Vec<u64> = references_to(&insns, *target).into_iter().map(|(address, _)| address).collect();
            assert!(list.iter().all(|(address, _)| direct.contains(address)), "{target:#x}");
        }
    }
}
