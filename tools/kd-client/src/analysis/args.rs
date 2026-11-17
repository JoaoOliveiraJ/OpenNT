//! Os argumentos de uma chamada x64 pelo preparo no lugar da chamada.
//!
//! Na convenção x64 da Microsoft os quatro primeiros argumentos vão em
//! RCX, RDX, R8 e R9 e os outros na pilha, em `[rsp+0x20]`, `[rsp+0x28]`...
//! (depois do espaço de home). Antes do `call`, o código costuma montar os
//! argumentos com formas simples: `mov r, imm`, `lea r, [rip+x]`,
//! `xor r, r`, `mov r, r2`, `mov r, [rip+x]`, `lea r, [rsp+x]` e
//! `mov [rsp+0x20], r/imm`. Este módulo reconhece essas escritas
//! (`register_write`) e, numa sequência de instruções antes da chamada,
//! acha o último valor de cada argumento (`trace_arguments`). O que não
//! tem forma simples fica `Unknown`.

/// Os números dos registradores (a ordem do ModRM com REX).
pub const RCX: u8 = 1;
pub const RDX: u8 = 2;
pub const RSP: u8 = 4;
pub const R8: u8 = 8;
pub const R9: u8 = 9;

pub const REGISTER_NAMES: [&str; 16] = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];

/// Os registradores dos quatro primeiros argumentos.
pub const ARGUMENT_REGISTERS: [u8; 4] = [RCX, RDX, R8, R9];

/// Para onde vai a escrita.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Destination {
    Register(u8),
    /// `[rsp + deslocamento]`.
    Stack(i64),
}

/// O valor escrito.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    Constant(u64),
    /// `lea r, [rip+x]`: um endereço (string, dado, função).
    Address(u64),
    /// `mov r, [rip+x]`: o conteúdo da memória em `x`.
    Memory(u64),
    /// Cópia de outro registrador.
    Register(u8),
    /// `lea r, [base+deslocamento]`.
    RegisterOffset(u8, i64),
    /// `mov r, [rsp+x]`: lido da pilha.
    Stack(i64),
    Unknown,
}

/// Uma escrita reconhecida.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Write {
    pub address: u64,
    pub length: u8,
    pub destination: Destination,
    pub value: Value,
}

struct ModRm {
    mode: u8,
    reg: u8,
    rm: u8,
}

/// O operando de memória do ModRM: `Rip(endereço)`, `Base(registrador,
/// deslocamento)` ou complexo (com índice).
enum Memory {
    Rip(u64),
    Base(u8, i64),
    Complex,
}

/// Decodifica o operando r/m de memória a partir de `bytes[at..]` (logo
/// depois do ModRM). Devolve o operando e quantos bytes ele usou.
fn memory_operand(bytes: &[u8], at: usize, modrm: &ModRm, rex_b: u8, rex_x: u8) -> Option<(Memory, usize)> {
    let mut used = 0;
    let mut base = modrm.rm | rex_b << 3;
    let mut index_used = false;
    if modrm.rm == 4 {
        let sib = *bytes.get(at)?;
        used += 1;
        let index = (sib >> 3 & 7) | rex_x << 3;
        base = (sib & 7) | rex_b << 3;
        index_used = index != 4;
        if sib & 7 == 5 && modrm.mode == 0 {
            // Sem base: disp32 absoluto (com ou sem índice).
            let disp = i32::from_le_bytes(bytes.get(at + used..at + used + 4)?.try_into().ok()?) as i64;
            used += 4;
            return Some((if index_used { Memory::Complex } else { Memory::Base(u8::MAX, disp) }, used));
        }
    }
    let disp = match modrm.mode {
        0 if modrm.rm == 5 => {
            let disp = i32::from_le_bytes(bytes.get(at + used..at + used + 4)?.try_into().ok()?) as i64;
            used += 4;
            return Some((Memory::Rip(disp as u64), used));
        }
        0 => 0,
        1 => {
            let disp = *bytes.get(at + used)? as i8 as i64;
            used += 1;
            disp
        }
        2 => {
            let disp = i32::from_le_bytes(bytes.get(at + used..at + used + 4)?.try_into().ok()?) as i64;
            used += 4;
            disp
        }
        _ => return None,
    };
    Some((if index_used { Memory::Complex } else { Memory::Base(base, disp) }, used))
}

/// Reconhece as escritas simples em registrador ou em `[rsp+x]` (as formas
/// do preparo de argumentos). `None` para qualquer outra instrução.
pub fn register_write(code: &[u8], address: u64) -> Option<Write> {
    let mut position = 0;
    let mut operand_16 = false;
    // Prefixos legados que podem aparecer (66 muda o tamanho: só ignorado).
    while let Some(&byte) = code.get(position) {
        match byte {
            0x66 => operand_16 = true,
            0x2E | 0x3E | 0x26 | 0x36 | 0x64 | 0x65 | 0x67 | 0xF2 | 0xF3 | 0xF0 => {}
            _ => break,
        }
        position += 1;
        if position > 4 {
            return None;
        }
    }
    let mut rex = 0u8;
    if let Some(&byte) = code.get(position) {
        if byte & 0xF0 == 0x40 {
            rex = byte;
            position += 1;
        }
    }
    let wide = rex & 8 != 0;
    let (rex_r, rex_x, rex_b) = (rex >> 2 & 1, rex >> 1 & 1, rex & 1);
    let opcode = *code.get(position)?;
    position += 1;
    let read_modrm = |at: usize| -> Option<ModRm> {
        let byte = *code.get(at)?;
        Some(ModRm { mode: byte >> 6, reg: (byte >> 3 & 7) | rex_r << 3, rm: byte & 7 })
    };
    let finish = |length: usize, destination: Destination, value: Value| -> Option<Write> { Some(Write { address, length: length as u8, destination, value }) };
    let next_address = |length: usize| address.wrapping_add(length as u64);
    match opcode {
        // mov r32/r64, imm (B8+r).
        0xB8..=0xBF if !operand_16 => {
            let register = (opcode - 0xB8) | rex_b << 3;
            if wide {
                let value = u64::from_le_bytes(code.get(position..position + 8)?.try_into().ok()?);
                finish(position + 8, Destination::Register(register), Value::Constant(value))
            } else {
                let value = u32::from_le_bytes(code.get(position..position + 4)?.try_into().ok()?) as u64;
                finish(position + 4, Destination::Register(register), Value::Constant(value))
            }
        }
        // mov r/m32/64, imm32 (C7 /0).
        0xC7 if !operand_16 => {
            let modrm = read_modrm(position)?;
            if modrm.reg & 7 != 0 {
                return None;
            }
            position += 1;
            let extend = |value: u32| if wide { value as i32 as i64 as u64 } else { value as u64 };
            if modrm.mode == 3 {
                let value = u32::from_le_bytes(code.get(position..position + 4)?.try_into().ok()?);
                return finish(position + 4, Destination::Register(modrm.rm | rex_b << 3), Value::Constant(extend(value)));
            }
            let (memory, used) = memory_operand(code, position, &modrm, rex_b, rex_x)?;
            position += used;
            let value = u32::from_le_bytes(code.get(position..position + 4)?.try_into().ok()?);
            match memory {
                Memory::Base(RSP, disp) => finish(position + 4, Destination::Stack(disp), Value::Constant(extend(value))),
                _ => None,
            }
        }
        // lea r, m (8D).
        0x8D => {
            let modrm = read_modrm(position)?;
            position += 1;
            if modrm.mode == 3 {
                return None;
            }
            let (memory, used) = memory_operand(code, position, &modrm, rex_b, rex_x)?;
            let length = position + used;
            let value = match memory {
                Memory::Rip(disp) => Value::Address(next_address(length).wrapping_add(disp)),
                Memory::Base(u8::MAX, disp) => Value::Constant(disp as u64),
                Memory::Base(base, disp) => Value::RegisterOffset(base, disp),
                Memory::Complex => Value::Unknown,
            };
            finish(length, Destination::Register(modrm.reg), value)
        }
        // mov r, r/m (8B).
        0x8B if !operand_16 => {
            let modrm = read_modrm(position)?;
            position += 1;
            if modrm.mode == 3 {
                return finish(position, Destination::Register(modrm.reg), Value::Register(modrm.rm | rex_b << 3));
            }
            let (memory, used) = memory_operand(code, position, &modrm, rex_b, rex_x)?;
            let length = position + used;
            let value = match memory {
                Memory::Rip(disp) => Value::Memory(next_address(length).wrapping_add(disp)),
                Memory::Base(u8::MAX, disp) => Value::Memory(disp as u64),
                Memory::Base(RSP, disp) => Value::Stack(disp),
                _ => Value::Unknown,
            };
            finish(length, Destination::Register(modrm.reg), value)
        }
        // mov r/m, r (89).
        0x89 if !operand_16 => {
            let modrm = read_modrm(position)?;
            position += 1;
            if modrm.mode == 3 {
                return finish(position, Destination::Register(modrm.rm | rex_b << 3), Value::Register(modrm.reg));
            }
            let (memory, used) = memory_operand(code, position, &modrm, rex_b, rex_x)?;
            match memory {
                Memory::Base(RSP, disp) => finish(position + used, Destination::Stack(disp), Value::Register(modrm.reg)),
                _ => None,
            }
        }
        // xor r, r (31/33 com os dois operandos iguais): zero.
        0x31 | 0x33 => {
            let modrm = read_modrm(position)?;
            let rm = modrm.rm | rex_b << 3;
            (modrm.mode == 3 && rm == modrm.reg).then_some(())?;
            finish(position + 1, Destination::Register(rm), Value::Constant(0))
        }
        _ => None,
    }
}

/// O valor de cada argumento (`count`: os quatro dos registradores e depois
/// os da pilha) pelas escritas reconhecidas, na ordem do código, antes da
/// chamada. Uma cópia de registrador resolve pelo valor anterior dele.
pub fn trace_arguments(writes: &[Write], count: usize) -> Vec<Value> {
    let last_value = |destination: Destination, before: usize| -> Value { writes[..before].iter().rev().find(|write| write.destination == destination).map_or(Value::Unknown, |write| write.value) };
    (0..count)
        .map(|index| {
            let destination = match ARGUMENT_REGISTERS.get(index) {
                Some(&register) => Destination::Register(register),
                None => Destination::Stack(0x20 + 8 * (index as i64 - 4)),
            };
            let Some(position) = writes.iter().rposition(|write| write.destination == destination) else { return Value::Unknown };
            match writes[position].value {
                // Um nível de cópia: `mov rcx, rbx` depois de `lea rbx, [x]`.
                Value::Register(source) => match last_value(Destination::Register(source), position) {
                    Value::Unknown => Value::Register(source),
                    resolved => resolved,
                },
                value => value,
            }
        })
        .collect()
}

/// As escritas das instruções `(endereço, bytes)` que preparam a chamada,
/// em ordem. Para no começo da lista ou numa instrução que muda o fluxo
/// (quem chama corta a lista no bloco).
pub fn writes_before(instructions: &[(u64, Vec<u8>)]) -> Vec<Write> {
    instructions.iter().filter_map(|(address, bytes)| register_write(bytes, *address)).collect()
}

/// O valor em texto curto (para o comentário).
pub fn value_text(value: &Value) -> String {
    match value {
        Value::Constant(number) => format!("{number:#x}"),
        Value::Address(address) => format!("{address:#x}"),
        Value::Memory(address) => format!("[{address:#x}]"),
        Value::Register(register) => REGISTER_NAMES[*register as usize & 15].to_string(),
        Value::RegisterOffset(register, offset) => format!("{}{offset:+#x}", REGISTER_NAMES[*register as usize & 15]),
        Value::Stack(offset) => format!("[rsp{offset:+#x}]"),
        Value::Unknown => "?".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(bytes: &[u8]) -> Write {
        register_write(bytes, 0x1000).unwrap_or_else(|| panic!("nao reconhecido: {bytes:02x?}"))
    }

    #[test]
    fn recognizes_setup_forms() {
        // mov ecx, 0x40
        assert_eq!(write(&[0xB9, 0x40, 0, 0, 0]), Write { address: 0x1000, length: 5, destination: Destination::Register(RCX), value: Value::Constant(0x40) });
        // mov r8, 0x1122334455667788
        assert_eq!(write(&[0x49, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]).value, Value::Constant(0x1122334455667788));
        assert_eq!(write(&[0x49, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]).destination, Destination::Register(R8));
        // lea rdx, [rip+0x100] (7 bytes): 0x1007 + 0x100.
        assert_eq!(write(&[0x48, 0x8D, 0x15, 0x00, 0x01, 0, 0]).value, Value::Address(0x1107));
        // xor r9d, r9d
        assert_eq!(write(&[0x45, 0x33, 0xC9]).destination, Destination::Register(R9));
        assert_eq!(write(&[0x45, 0x33, 0xC9]).value, Value::Constant(0));
        // mov rcx, rbx
        assert_eq!(write(&[0x48, 0x8B, 0xCB]).value, Value::Register(3));
        // mov r8, rdi (89 /r com REX.B: destino r8)
        assert_eq!(write(&[0x49, 0x89, 0xF8]).destination, Destination::Register(R8));
        // mov rax, [rip+0x10]
        assert_eq!(write(&[0x48, 0x8B, 0x05, 0x10, 0, 0, 0]).value, Value::Memory(0x1017));
        // lea rdx, [rsp+0x40]
        assert_eq!(write(&[0x48, 0x8D, 0x54, 0x24, 0x40]).value, Value::RegisterOffset(RSP, 0x40));
        // mov dword ptr [rsp+0x20], 3
        let stack = write(&[0xC7, 0x44, 0x24, 0x20, 3, 0, 0, 0]);
        assert_eq!((stack.destination, stack.value, stack.length), (Destination::Stack(0x20), Value::Constant(3), 8));
        // mov [rsp+0x28], rax
        assert_eq!(write(&[0x48, 0x89, 0x44, 0x24, 0x28]).destination, Destination::Stack(0x28));
        // mov rcx, [rsp+0x50]
        assert_eq!(write(&[0x48, 0x8B, 0x4C, 0x24, 0x50]).value, Value::Stack(0x50));
        // xor eax, ecx não zera; add não é escrita simples.
        assert!(register_write(&[0x33, 0xC1], 0).is_none());
        assert!(register_write(&[0x48, 0x01, 0xC8], 0).is_none());
    }

    #[test]
    fn traces_the_call_arguments() {
        // lea rbx, [rip+x]; mov rcx, rbx; mov edx, 7; xor r8d, r8d;
        // mov dword [rsp+0x20], 1; mov r9, rsi
        let instructions: Vec<(u64, Vec<u8>)> = vec![
            (0x2000, vec![0x48, 0x8D, 0x1D, 0x00, 0x10, 0, 0]),
            (0x2007, vec![0x48, 0x8B, 0xCB]),
            (0x200A, vec![0xBA, 7, 0, 0, 0]),
            (0x200F, vec![0x45, 0x33, 0xC0]),
            (0x2012, vec![0xC7, 0x44, 0x24, 0x20, 1, 0, 0, 0]),
            (0x201A, vec![0x4C, 0x8B, 0xCE]),
        ];
        let writes = writes_before(&instructions);
        let values = trace_arguments(&writes, 6);
        assert_eq!(values[0], Value::Address(0x3007));
        assert_eq!(values[1], Value::Constant(7));
        assert_eq!(values[2], Value::Constant(0));
        assert_eq!(values[3], Value::Register(6));
        assert_eq!(values[4], Value::Constant(1));
        assert_eq!(values[5], Value::Unknown);
        assert_eq!(value_text(&values[3]), "rsi");
        assert_eq!(value_text(&Value::RegisterOffset(RSP, 0x40)), "rsp+0x40");
    }
}
