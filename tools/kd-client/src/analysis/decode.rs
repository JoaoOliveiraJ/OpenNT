//! Decodificador x86-64 (modo de 64 bits) para as análises: o tamanho
//! exato de cada instrução, o que ela faz com o fluxo, o destino de um
//! desvio direto, o endereço de um operando de memória relativo ao RIP (ou
//! absoluto) e o valor imediato.
//!
//! Cobre os prefixos legados, o REX, os mapas 0F, 0F38 e 0F3A, ModRM, SIB e
//! deslocamentos, todos os imediatos (com o efeito do 66h), os `moffs` do
//! A0-A3 (com o 67h), ENTER e RET imm16, o 3DNow (0F 0F), os prefixos VEX
//! de dois e de três bytes, o EVEX e o XOP. Não monta o texto da
//! instrução: a desmontagem legível fica com a interface gráfica.

/// O que a instrução faz com o fluxo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    /// Segue para a próxima instrução.
    Next,
    /// `call rel32`.
    Call,
    /// `call r/m` (registrador ou memória).
    IndirectCall,
    /// `jmp rel8`/`jmp rel32`.
    Jump,
    /// `jmp r/m`.
    IndirectJump,
    /// `jcc`, `loop`, `jrcxz`.
    Conditional,
    /// `ret`, `retf`, `iretq`, `sysret`.
    Return,
    /// `int n`, `int1`, `syscall`: o trap volta para a próxima instrução.
    Interrupt,
    /// `int3`, `ud2`, `hlt`: sem continuação para o grafo.
    Stop,
}

/// A classe da instrução para as buscas de referência.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Lea,
    /// `mov r/m, r`, `mov r, r/m`, `mov r/m, imm`, `mov r, imm64`, `moffs`.
    Mov,
    /// `push r`, `push imm`, `push r/m`.
    Push,
    /// `cmp`, `test`.
    Compare,
    Other,
}

/// Uma instrução decodificada.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub address: u64,
    pub length: u8,
    pub flow: Flow,
    pub class: Class,
    /// O destino de um desvio ou chamada direta.
    pub target: Option<u64>,
    /// O endereço de um operando relativo ao RIP (próxima instrução +
    /// disp32) ou absoluto (`[disp32]` sem base nem índice, `moffs`).
    pub memory: Option<u64>,
    /// O imediato estendido como a CPU o estende para o tamanho do
    /// operando (o valor inteiro no `mov r64, imm64`).
    pub immediate: Option<u64>,
}

impl Insn {
    /// O endereço da instrução seguinte.
    pub fn end(&self) -> u64 {
        self.address.wrapping_add(self.length as u64)
    }
}

/// Maior instrução que a CPU aceita.
const MAX_LENGTH: usize = 15;

struct Cursor<'a> {
    code: &'a [u8],
    position: usize,
}

impl Cursor<'_> {
    fn byte(&mut self) -> Option<u8> {
        let byte = *self.code.get(self.position)?;
        self.position += 1;
        Some(byte)
    }

    fn peek(&self) -> Option<u8> {
        self.code.get(self.position).copied()
    }

    fn skip(&mut self, count: usize) -> Option<()> {
        if self.position + count > self.code.len() {
            return None;
        }
        self.position += count;
        Some(())
    }

    /// Um inteiro little-endian de `count` bytes.
    fn little_endian(&mut self, count: usize) -> Option<u64> {
        let bytes = self.code.get(self.position..self.position + count)?;
        self.position += count;
        Some(bytes.iter().rev().fold(0u64, |value, &byte| value << 8 | byte as u64))
    }
}

#[derive(Default)]
struct Prefixes {
    operand16: bool,
    address32: bool,
    /// F2 ou F3 (o último).
    repeat: u8,
    /// O REX logo antes do opcode (0 sem REX).
    rex: u8,
}

/// O imediato que segue o ModRM (ou o opcode).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Immediate {
    Empty,
    /// ib sem extensão.
    Byte,
    /// ib estendido com sinal até o tamanho do operando.
    ByteSigned,
    /// iw.
    Word,
    /// iz: 16 bits com 66h, senão 32 estendidos com sinal.
    Full,
    /// iv do `mov r, imm`: 16, 32 ou 64 bits pelo tamanho do operando.
    Value,
    /// O endereço do A0-A3: 64 bits, ou 32 com 67h.
    Offset,
    Relative8,
    Relative32,
    /// iw ib do ENTER.
    Enter,
    /// ib ib (EXTRQ/INSERTQ).
    Pair,
    /// O imediato do grupo 3 (F6/F7): só com /0 e /1 (TEST).
    TestByte,
    TestFull,
    /// imm32 do mapa A do XOP.
    Dword,
}

/// A forma da instrução: ModRM, imediato, fluxo e classe.
#[derive(Clone, Copy)]
struct Shape {
    modrm: bool,
    /// O ModRM é sempre registrador (MOV de CR/DR): sem SIB nem deslocamento.
    register_only: bool,
    immediate: Immediate,
    flow: Flow,
    class: Class,
    /// Operando de 64 bits por padrão (PUSH).
    push: bool,
    /// Do mapa de um byte (os grupos decidem pelo campo reg do ModRM).
    one_byte: bool,
}

impl Shape {
    const fn plain() -> Shape {
        Shape { modrm: false, register_only: false, immediate: Immediate::Empty, flow: Flow::Next, class: Class::Other, push: false, one_byte: false }
    }

    const fn modrm() -> Shape {
        Shape { modrm: true, ..Shape::plain() }
    }

    const fn immediate(mut self, immediate: Immediate) -> Shape {
        self.immediate = immediate;
        self
    }

    const fn flow(mut self, flow: Flow) -> Shape {
        self.flow = flow;
        self
    }

    const fn class(mut self, class: Class) -> Shape {
        self.class = class;
        self
    }
}

/// O operando de memória do ModRM.
enum Reference {
    None,
    /// Relativo ao RIP da próxima instrução.
    Relative(i32),
    /// `[disp32]` sem base nem índice.
    Absolute(i32),
}

/// ModRM, SIB e deslocamento; devolve o campo reg e o operando de memória.
fn modrm(cursor: &mut Cursor, rex: u8, register_only: bool) -> Option<(u8, Reference)> {
    let modrm = cursor.byte()?;
    let mode = modrm >> 6;
    let rm = modrm & 7;
    let reg = (modrm >> 3) & 7;
    if mode == 3 || register_only {
        return Some((reg, Reference::None));
    }
    let mut reference = Reference::None;
    if rm == 4 {
        let sib = cursor.byte()?;
        if mode == 0 && sib & 7 == 5 {
            let displacement = cursor.little_endian(4)? as u32 as i32;
            // Índice 100 sem REX.X: nem base nem índice.
            if (sib >> 3) & 7 == 4 && rex & 2 == 0 {
                reference = Reference::Absolute(displacement);
            }
        }
    } else if mode == 0 && rm == 5 {
        reference = Reference::Relative(cursor.little_endian(4)? as u32 as i32);
    }
    match mode {
        1 => cursor.skip(1)?,
        2 => cursor.skip(4)?,
        _ => {}
    }
    Some((reg, reference))
}

/// O mapa de um byte.
fn one_byte(opcode: u8) -> Option<Shape> {
    use Immediate::*;
    let shape = match opcode {
        0x00..=0x3F => {
            let mut shape = match opcode & 7 {
                0..=3 => Shape::modrm(),
                4 => Shape::plain().immediate(Byte),
                5 => Shape::plain().immediate(Full),
                // PUSH/POP de segmento, DAA, DAS, AAA, AAS: inválidos no modo
                // de 64 bits (os prefixos de segmento e o 0F não chegam aqui).
                _ => return None,
            };
            if opcode >= 0x38 {
                shape.class = Class::Compare;
            }
            shape
        }
        0x50..=0x57 => Shape { push: true, ..Shape::plain().class(Class::Push) },
        0x58..=0x5F => Shape { push: true, ..Shape::plain() },
        0x63 => Shape::modrm(),
        0x68 => Shape { push: true, ..Shape::plain().immediate(Full).class(Class::Push) },
        0x69 => Shape::modrm().immediate(Full),
        0x6A => Shape { push: true, ..Shape::plain().immediate(ByteSigned).class(Class::Push) },
        0x6B => Shape::modrm().immediate(ByteSigned),
        0x6C..=0x6F => Shape::plain(),
        0x70..=0x7F => Shape::plain().immediate(Relative8).flow(Flow::Conditional),
        0x80 => Shape::modrm().immediate(Byte),
        0x81 => Shape::modrm().immediate(Full),
        0x83 => Shape::modrm().immediate(ByteSigned),
        0x84 | 0x85 => Shape::modrm().class(Class::Compare),
        0x86 | 0x87 | 0x8C | 0x8E => Shape::modrm(),
        0x88..=0x8B => Shape::modrm().class(Class::Mov),
        0x8D => Shape::modrm().class(Class::Lea),
        0x8F => Shape { push: true, ..Shape::modrm() },
        0x90..=0x99 | 0x9B..=0x9F => Shape::plain(),
        0xA0..=0xA3 => Shape::plain().immediate(Offset).class(Class::Mov),
        0xA4..=0xA7 | 0xAA..=0xAF => Shape::plain(),
        0xA8 => Shape::plain().immediate(Byte).class(Class::Compare),
        0xA9 => Shape::plain().immediate(Full).class(Class::Compare),
        0xB0..=0xB7 => Shape::plain().immediate(Byte).class(Class::Mov),
        0xB8..=0xBF => Shape::plain().immediate(Value).class(Class::Mov),
        0xC0 | 0xC1 => Shape::modrm().immediate(Byte),
        0xC2 | 0xCA => Shape::plain().immediate(Word).flow(Flow::Return),
        0xC3 | 0xCB | 0xCF => Shape::plain().flow(Flow::Return),
        0xC6 => Shape::modrm().immediate(Byte),
        0xC7 => Shape::modrm().immediate(Full),
        0xC8 => Shape::plain().immediate(Enter),
        0xC9 => Shape::plain(),
        0xCC => Shape::plain().flow(Flow::Stop),
        0xCD => Shape::plain().immediate(Byte).flow(Flow::Interrupt),
        0xD0..=0xD3 | 0xD8..=0xDF => Shape::modrm(),
        0xD7 => Shape::plain(),
        0xE0..=0xE3 => Shape::plain().immediate(Relative8).flow(Flow::Conditional),
        0xE4..=0xE7 => Shape::plain().immediate(Byte),
        0xE8 => Shape::plain().immediate(Relative32).flow(Flow::Call),
        0xE9 => Shape::plain().immediate(Relative32).flow(Flow::Jump),
        0xEB => Shape::plain().immediate(Relative8).flow(Flow::Jump),
        0xEC..=0xEF | 0xF5 | 0xF8..=0xFD => Shape::plain(),
        0xF1 => Shape::plain().flow(Flow::Interrupt),
        0xF4 => Shape::plain().flow(Flow::Stop),
        0xF6 => Shape::modrm().immediate(TestByte),
        0xF7 => Shape::modrm().immediate(TestFull),
        0xFE | 0xFF => Shape::modrm(),
        // 60, 61, 82, 9A, CE, D4, D5, D6, EA: inválidos no modo de 64 bits.
        _ => return None,
    };
    Some(Shape { one_byte: true, ..shape })
}

/// O mapa 0F (depois do 0F).
fn two_byte(opcode: u8, prefixes: &Prefixes) -> Option<Shape> {
    use Immediate::*;
    Some(match opcode {
        0x00..=0x03 | 0x0D | 0x10..=0x1F | 0x28..=0x2F | 0x40..=0x6F | 0x74..=0x76 | 0x79..=0x7F | 0x90..=0x9F => Shape::modrm(),
        0x05 => Shape::plain().flow(Flow::Interrupt),
        0x07 => Shape::plain().flow(Flow::Return),
        0x06 | 0x08 | 0x09 | 0x0E | 0x30..=0x35 | 0x37 | 0x77 => Shape::plain(),
        0x0B => Shape::plain().flow(Flow::Stop),
        // MOV de e para CR e DR: o ModRM é sempre registrador.
        0x20..=0x23 => Shape { register_only: true, ..Shape::modrm() },
        0x70..=0x73 => Shape::modrm().immediate(Byte),
        // EXTRQ/INSERTQ com imediatos (66 0F 78 e F2 0F 78); sem prefixo é o VMREAD.
        0x78 if prefixes.operand16 || prefixes.repeat == 0xF2 => Shape::modrm().immediate(Pair),
        0x78 => Shape::modrm(),
        0x80..=0x8F => Shape::plain().immediate(Relative32).flow(Flow::Conditional),
        0xA0..=0xA2 | 0xA8..=0xAA | 0xC8..=0xCF => Shape::plain(),
        0xA3 | 0xA5 | 0xAB | 0xAD..=0xB9 | 0xBB..=0xC1 | 0xC3 | 0xC7 | 0xD0..=0xFF => Shape::modrm(),
        0xA4 | 0xAC | 0xBA | 0xC2 | 0xC4..=0xC6 => Shape::modrm().immediate(Byte),
        _ => return None,
    })
}

/// Os opcodes do mapa 0F que levam ib também com VEX/EVEX.
fn vex_map1_immediate(opcode: u8) -> bool {
    matches!(opcode, 0x70..=0x73 | 0xC2 | 0xC4..=0xC6)
}

/// A forma de uma instrução VEX/EVEX pelo mapa e pelo opcode.
fn vex_shape(map: u8, opcode: u8) -> Option<Shape> {
    match map {
        1 if opcode == 0x77 => Some(Shape::plain()),
        1 if vex_map1_immediate(opcode) => Some(Shape::modrm().immediate(Immediate::Byte)),
        1 | 2 | 5 | 6 => Some(Shape::modrm()),
        3 => Some(Shape::modrm().immediate(Immediate::Byte)),
        _ => None,
    }
}

/// Decodifica a instrução no começo de `code`, que fica em `address`;
/// `None` para bytes inválidos ou cortados.
pub fn decode(code: &[u8], address: u64) -> Option<Insn> {
    let code = &code[..code.len().min(MAX_LENGTH)];
    let mut cursor = Cursor { code, position: 0 };
    let mut prefixes = Prefixes::default();
    let opcode = loop {
        let byte = cursor.byte()?;
        match byte {
            0x66 => {
                prefixes.operand16 = true;
                prefixes.rex = 0;
            }
            0x67 => {
                prefixes.address32 = true;
                prefixes.rex = 0;
            }
            0xF2 | 0xF3 => {
                prefixes.repeat = byte;
                prefixes.rex = 0;
            }
            0xF0 | 0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 => prefixes.rex = 0,
            // Um REX só vale logo antes do opcode.
            0x40..=0x4F => prefixes.rex = byte,
            _ => break byte,
        }
    };
    let shape = match opcode {
        0x0F => {
            let second = cursor.byte()?;
            match second {
                0x38 => {
                    cursor.byte()?;
                    Shape::modrm()
                }
                0x3A => {
                    cursor.byte()?;
                    Shape::modrm().immediate(Immediate::Byte)
                }
                // 3DNow: o sufixo depois do ModRM ocupa o lugar de um ib.
                0x0F => Shape::modrm().immediate(Immediate::Byte),
                _ => two_byte(second, &prefixes)?,
            }
        }
        // No modo de 64 bits, C5, C4 e 62 são sempre VEX e EVEX.
        0xC5 => {
            cursor.byte()?;
            let opcode = cursor.byte()?;
            vex_shape(1, opcode)?
        }
        0xC4 => {
            let first = cursor.byte()?;
            cursor.byte()?;
            let opcode = cursor.byte()?;
            vex_shape(first & 0x1F, opcode)?
        }
        0x62 => {
            let first = cursor.byte()?;
            cursor.skip(2)?;
            let opcode = cursor.byte()?;
            vex_shape(first & 7, opcode)?
        }
        // XOP (8F com mapa 8 ou acima); senão é o POP r/m.
        0x8F if cursor.peek().is_some_and(|byte| byte & 0x1F >= 8) => {
            let first = cursor.byte()?;
            cursor.byte()?;
            cursor.byte()?;
            match first & 0x1F {
                8 => Shape::modrm().immediate(Immediate::Byte),
                9 => Shape::modrm(),
                0x0A => Shape::modrm().immediate(Immediate::Dword),
                _ => return None,
            }
        }
        _ => one_byte(opcode)?,
    };
    let mut flow = shape.flow;
    let mut class = shape.class;
    let mut kind = shape.immediate;
    let mut reference = Reference::None;
    if shape.modrm {
        let (reg, operand) = modrm(&mut cursor, prefixes.rex, shape.register_only)?;
        reference = operand;
        if shape.one_byte {
            match opcode {
                0x80..=0x83 if reg == 7 => class = Class::Compare,
                0xC6 | 0xC7 if reg == 0 => class = Class::Mov,
                // XBEGIN rel32: o destino é o caminho do aborto.
                0xC7 if reg == 7 && !prefixes.operand16 => kind = Immediate::Relative32,
                0xF6 | 0xF7 if reg <= 1 => class = Class::Compare,
                0xFF => match reg {
                    2 | 3 => flow = Flow::IndirectCall,
                    4 | 5 => flow = Flow::IndirectJump,
                    6 => class = Class::Push,
                    _ => {}
                },
                _ => {}
            }
        }
        kind = match kind {
            Immediate::TestByte if reg <= 1 => Immediate::Byte,
            Immediate::TestFull if reg <= 1 => Immediate::Full,
            Immediate::TestByte | Immediate::TestFull => Immediate::Empty,
            other => other,
        };
    }
    let wide = prefixes.rex & 8 != 0;
    let operand_size = if shape.push {
        if prefixes.operand16 {
            2
        } else {
            8
        }
    } else if wide {
        8
    } else if prefixes.operand16 {
        2
    } else {
        4
    };
    let mut immediate = None;
    let mut relative = None;
    let mut absolute = None;
    match kind {
        Immediate::Empty | Immediate::TestByte | Immediate::TestFull => {}
        Immediate::Byte => immediate = Some(cursor.little_endian(1)?),
        Immediate::ByteSigned => immediate = Some(extend(cursor.little_endian(1)?, 1, operand_size, true)),
        Immediate::Word => immediate = Some(cursor.little_endian(2)?),
        Immediate::Full => {
            let size = if operand_size == 2 { 2 } else { 4 };
            immediate = Some(extend(cursor.little_endian(size)?, size, operand_size, true));
        }
        Immediate::Value => immediate = Some(cursor.little_endian(operand_size)?),
        Immediate::Offset => absolute = Some(cursor.little_endian(if prefixes.address32 { 4 } else { 8 })?),
        Immediate::Relative8 => relative = Some(cursor.little_endian(1)? as u8 as i8 as i64),
        Immediate::Relative32 => relative = Some(cursor.little_endian(4)? as u32 as i32 as i64),
        Immediate::Enter => cursor.skip(3)?,
        Immediate::Pair => cursor.skip(2)?,
        Immediate::Dword => immediate = Some(cursor.little_endian(4)?),
    }
    let length = cursor.position;
    let next = address.wrapping_add(length as u64);
    let target = relative.map(|offset| next.wrapping_add(offset as u64));
    let mut memory = match reference {
        Reference::None => absolute,
        Reference::Relative(displacement) => Some(next.wrapping_add(displacement as i64 as u64)),
        Reference::Absolute(displacement) => Some(displacement as i64 as u64),
    };
    if prefixes.address32 {
        memory = memory.map(|address| address & 0xFFFF_FFFF);
    }
    Some(Insn { address, length: length as u8, flow, class, target, memory, immediate })
}

/// Estende `value` de `from` bytes (com sinal ou sem) e corta no tamanho do
/// operando (`to` bytes).
fn extend(value: u64, from: usize, to: usize, signed: bool) -> u64 {
    let bits = from * 8;
    let value = if signed && bits < 64 { (((value << (64 - bits)) as i64) >> (64 - bits)) as u64 } else { value };
    if to >= 8 {
        value
    } else {
        value & ((1u64 << (to * 8)) - 1)
    }
}

/// Varredura linear de `code` (em `start`): um byte que não decodifica é
/// pulado.
pub fn decode_all(code: &[u8], start: u64) -> Vec<Insn> {
    let mut output = Vec::new();
    let mut offset = 0usize;
    while offset < code.len() {
        match decode(&code[offset..], start.wrapping_add(offset as u64)) {
            Some(insn) => {
                offset += insn.length as usize;
                output.push(insn);
            }
            None => offset += 1,
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(bytes: &[u8], address: u64) -> Insn {
        decode(bytes, address).unwrap_or_else(|| panic!("{bytes:02x?} nao decodificou"))
    }

    fn length(bytes: &[u8]) -> u8 {
        at(bytes, 0x1000).length
    }

    #[test]
    fn branches_and_calls() {
        let call = at(&[0xE8, 0x10, 0, 0, 0], 0x1000);
        assert_eq!((call.length, call.flow, call.target), (5, Flow::Call, Some(0x1015)));
        let jump = at(&[0xEB, 0xFE], 0x2000);
        assert_eq!((jump.length, jump.flow, jump.target), (2, Flow::Jump, Some(0x2000)));
        let conditional = at(&[0x0F, 0x84, 0x00, 0x01, 0, 0], 0x1000);
        assert_eq!((conditional.length, conditional.flow, conditional.target), (6, Flow::Conditional, Some(0x1106)));
        let short = at(&[0x75, 0xF9], 0x2007);
        assert_eq!(short.target, Some(0x2002));
        let indirect = at(&[0xFF, 0x15, 0x10, 0, 0, 0], 0x1000);
        assert_eq!((indirect.length, indirect.flow, indirect.memory, indirect.target), (6, Flow::IndirectCall, Some(0x1016), None));
        let register = at(&[0x41, 0xFF, 0xE3], 0x1000);
        assert_eq!((register.length, register.flow, register.memory), (3, Flow::IndirectJump, None));
        assert_eq!(at(&[0xE2, 0xFE], 0).flow, Flow::Conditional);
        assert_eq!(at(&[0xE3, 0x00], 0).flow, Flow::Conditional);
        assert_eq!(at(&[0xE9, 0, 0, 0, 0], 0).target, Some(5));
        // xbegin rel32: o destino do aborto.
        let xbegin = at(&[0xC7, 0xF8, 0x07, 0, 0, 0], 0x100);
        assert_eq!((xbegin.length, xbegin.target, xbegin.immediate), (6, Some(0x10D), None));
    }

    #[test]
    fn returns_and_stops() {
        assert_eq!(at(&[0xC3], 0).flow, Flow::Return);
        let ret = at(&[0xC2, 0x08, 0x00], 0);
        assert_eq!((ret.length, ret.flow), (3, Flow::Return));
        assert_eq!(at(&[0xF3, 0xC3], 0).flow, Flow::Return);
        assert_eq!(at(&[0xCC], 0).flow, Flow::Stop);
        assert_eq!(at(&[0xF4], 0).flow, Flow::Stop);
        assert_eq!(at(&[0x0F, 0x0B], 0).flow, Flow::Stop);
        let interrupt = at(&[0xCD, 0x29], 0);
        assert_eq!((interrupt.length, interrupt.flow), (2, Flow::Interrupt));
        assert_eq!(at(&[0x0F, 0x05], 0).flow, Flow::Interrupt);
        assert_eq!(at(&[0x48, 0x0F, 0x07], 0).flow, Flow::Return);
        assert_eq!(at(&[0x48, 0xCF], 0).flow, Flow::Return);
    }

    #[test]
    fn rip_relative_operands() {
        // lea rax, [rip-7]: aponta para a própria instrução.
        let lea = at(&[0x48, 0x8D, 0x05, 0xF9, 0xFF, 0xFF, 0xFF], 0x1000);
        assert_eq!((lea.length, lea.class, lea.memory), (7, Class::Lea, Some(0x1000)));
        // lea eax, [rip+0x100], sem REX.
        let lea = at(&[0x8D, 0x05, 0x00, 0x01, 0, 0], 0x1000);
        assert_eq!((lea.length, lea.class, lea.memory), (6, Class::Lea, Some(0x1106)));
        // lea r9, [rip+0x20].
        let lea = at(&[0x4C, 0x8D, 0x0D, 0x20, 0, 0, 0], 0x1000);
        assert_eq!((lea.length, lea.memory), (7, Some(0x1027)));
        // mov rax, [rip+0x10].
        let load = at(&[0x48, 0x8B, 0x05, 0x10, 0, 0, 0], 0x1000);
        assert_eq!((load.class, load.memory), (Class::Mov, Some(0x1017)));
        // mov dword ptr [rip+0x10], 1: o RIP é o do fim, depois do imediato.
        let store = at(&[0xC7, 0x05, 0x10, 0, 0, 0, 1, 0, 0, 0], 0x1000);
        assert_eq!((store.length, store.class, store.memory, store.immediate), (10, Class::Mov, Some(0x101A), Some(1)));
        // cmp byte ptr [rip+0], 0.
        let compare = at(&[0x80, 0x3D, 0, 0, 0, 0, 0], 0x1000);
        assert_eq!((compare.length, compare.class, compare.memory), (7, Class::Compare, Some(0x1007)));
    }

    #[test]
    fn absolute_and_sib_operands() {
        // mov eax, [0x1000] pelo SIB sem base nem índice.
        let absolute = at(&[0x8B, 0x04, 0x25, 0x00, 0x10, 0, 0], 0);
        assert_eq!((absolute.length, absolute.memory), (7, Some(0x1000)));
        // Com REX.X o índice é o r12: não é absoluto.
        let indexed = at(&[0x42, 0x8B, 0x04, 0x25, 0x00, 0x10, 0, 0], 0);
        assert_eq!((indexed.length, indexed.memory), (8, None));
        // mov rax, gs:[0x188].
        let segment = at(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0, 0], 0);
        assert_eq!((segment.length, segment.memory), (9, Some(0x188)));
        assert_eq!(length(&[0x8B, 0x04, 0x24]), 3);
        assert_eq!(length(&[0x8B, 0x44, 0x24, 0x08]), 4);
        assert_eq!(length(&[0x8B, 0x84, 0x24, 0, 1, 0, 0]), 7);
        assert_eq!(length(&[0x8B, 0x45, 0x08]), 3);
        assert_eq!(length(&[0x8B, 0x85, 0, 1, 0, 0]), 6);
        assert_eq!(at(&[0x8B, 0x04, 0x24], 0).memory, None);
    }

    #[test]
    fn moffs() {
        let wide = at(&[0x48, 0xA1, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11], 0);
        assert_eq!((wide.length, wide.class, wide.memory), (10, Class::Mov, Some(0x1122_3344_5566_7788)));
        assert_eq!(length(&[0xA1, 1, 2, 3, 4, 5, 6, 7, 8]), 9);
        let short = at(&[0x67, 0xA1, 0x00, 0x10, 0, 0], 0);
        assert_eq!((short.length, short.memory), (6, Some(0x1000)));
        assert_eq!(length(&[0xA2, 1, 2, 3, 4, 5, 6, 7, 8]), 9);
    }

    #[test]
    fn immediates() {
        let movabs = at(&[0x48, 0xB9, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11], 0);
        assert_eq!((movabs.length, movabs.class, movabs.immediate), (10, Class::Mov, Some(0x1122_3344_5566_7788)));
        let push = at(&[0x68, 0x00, 0x10, 0x40, 0x00], 0);
        assert_eq!((push.length, push.class, push.immediate), (5, Class::Push, Some(0x40_1000)));
        assert_eq!(at(&[0x6A, 0xFF], 0).immediate, Some(u64::MAX));
        let compare = at(&[0x3D, 0x78, 0x56, 0x34, 0x12], 0);
        assert_eq!((compare.length, compare.class, compare.immediate), (5, Class::Compare, Some(0x1234_5678)));
        assert_eq!(at(&[0x83, 0xF8, 0xFF], 0).immediate, Some(0xFFFF_FFFF));
        assert_eq!(at(&[0x48, 0x83, 0xF8, 0xFF], 0).immediate, Some(u64::MAX));
        let minus = at(&[0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF], 0);
        assert_eq!((minus.length, minus.class, minus.immediate), (7, Class::Mov, Some(u64::MAX)));
        assert_eq!(at(&[0xB8, 0xFF, 0xFF, 0xFF, 0xFF], 0).immediate, Some(0xFFFF_FFFF));
        // 66h: imediatos de 16 bits.
        let word = at(&[0x66, 0xB8, 0x34, 0x12], 0);
        assert_eq!((word.length, word.immediate), (4, Some(0x1234)));
        assert_eq!(length(&[0x66, 0x05, 0x34, 0x12]), 4);
        assert_eq!(length(&[0x66, 0x81, 0xC1, 0x34, 0x12]), 5);
        assert_eq!(length(&[0x66, 0xC7, 0x05, 0, 0, 0, 0, 0x34, 0x12]), 9);
        assert_eq!(length(&[0x40, 0xC6, 0xC7, 0x01]), 4);
        assert_eq!(length(&[0xC8, 0x10, 0x00, 0x00]), 4);
        assert_eq!(length(&[0x69, 0xC0, 1, 0, 0, 0]), 6);
        assert_eq!(length(&[0x6B, 0xC0, 0x10]), 3);
        assert_eq!(length(&[0xC1, 0xE0, 0x04]), 3);
    }

    #[test]
    fn group3() {
        let test = at(&[0xF6, 0xC1, 0x01], 0);
        assert_eq!((test.length, test.class, test.immediate), (3, Class::Compare, Some(1)));
        let not = at(&[0xF7, 0xD0], 0);
        assert_eq!((not.length, not.immediate), (2, None));
        let test = at(&[0xF7, 0xC1, 0x00, 0x01, 0, 0], 0);
        assert_eq!((test.length, test.immediate), (6, Some(0x100)));
        assert_eq!(length(&[0xF6, 0x05, 0, 0, 0, 0, 0x80]), 7);
        assert_eq!(length(&[0x48, 0xF7, 0x25, 0, 0, 0, 0]), 7);
    }

    #[test]
    fn extended_maps() {
        assert_eq!(length(&[0x0F, 0x20, 0xC0]), 3);
        assert_eq!(length(&[0x0F, 0x22, 0xD8]), 3);
        // O MOV de CR ignora o campo mod: 0F 20 05 não tem disp32.
        assert_eq!(length(&[0x0F, 0x20, 0x05]), 3);
        assert_eq!(length(&[0xF3, 0x0F, 0x1E, 0xFA]), 4);
        assert_eq!(length(&[0x0F, 0x1F, 0x44, 0x00, 0x00]), 5);
        assert_eq!(length(&[0x66, 0x0F, 0x1F, 0x84, 0, 0, 0, 0, 0]), 9);
        assert_eq!(length(&[0x2E, 0x0F, 0x1F, 0x84, 0, 0, 0, 0, 0]), 9);
        assert_eq!(length(&[0x66, 0x0F, 0x3A, 0x0F, 0xC1, 0x08]), 6);
        assert_eq!(length(&[0x66, 0x0F, 0x38, 0x00, 0xC1]), 5);
        assert_eq!(length(&[0x0F, 0x0F, 0xC1, 0xB4]), 4);
        assert_eq!(length(&[0x66, 0x0F, 0x70, 0xC1, 0x1B]), 5);
        assert_eq!(length(&[0x0F, 0xBA, 0xE0, 0x05]), 4);
        assert_eq!(length(&[0x0F, 0xA2]), 2);
        assert_eq!(length(&[0x0F, 0xB6, 0x05, 0, 0, 0, 0]), 7);
        assert_eq!(length(&[0x66, 0x0F, 0x78, 0xC0, 0x01, 0x02]), 6);
        assert_eq!(length(&[0x0F, 0x78, 0xC0]), 3);
        assert_eq!(length(&[0x0F, 0xC8]), 2);
    }

    #[test]
    fn vex_evex_and_xop() {
        // vmovdqu ymm0, [rsi].
        assert_eq!(length(&[0xC5, 0xFE, 0x6F, 0x06]), 4);
        assert_eq!(length(&[0xC5, 0xF8, 0x77]), 3);
        // vbroadcastss ymm0, [rip+0] (mapa 0F38).
        let broadcast = at(&[0xC4, 0xE2, 0x7D, 0x18, 0x05, 0, 0, 0, 0], 0x1000);
        assert_eq!((broadcast.length, broadcast.memory), (9, Some(0x1009)));
        // vinsertf128 ymm0, ymm0, xmm1, 1 (mapa 0F3A, com ib).
        assert_eq!(length(&[0xC4, 0xE3, 0x7D, 0x18, 0xC1, 0x01]), 6);
        // vpshufd xmm0, xmm1, 0x1b (mapa 0F com ib).
        assert_eq!(length(&[0xC5, 0xF9, 0x70, 0xC1, 0x1B]), 5);
        // vmovups zmm0, [rip+0].
        let evex = at(&[0x62, 0xF1, 0x7C, 0x48, 0x10, 0x05, 0, 0, 0, 0], 0x2000);
        assert_eq!((evex.length, evex.memory), (10, Some(0x200A)));
        // vmovups zmm0, [rax+0x40] com disp8 comprimido.
        assert_eq!(length(&[0x62, 0xF1, 0x7C, 0x48, 0x10, 0x40, 0x01]), 7);
        // XOP vprotb (mapa 9) e pop r/m comum.
        assert_eq!(length(&[0x8F, 0xE9, 0x78, 0x90, 0xC1]), 5);
        assert_eq!(length(&[0x8F, 0xC0]), 2);
        assert_eq!(length(&[0x8F, 0x05, 0, 0, 0, 0]), 6);
    }

    #[test]
    fn prefixes_and_errors() {
        assert_eq!(length(&[0xF0, 0x48, 0x0F, 0xB1, 0x0A]), 5);
        assert_eq!(length(&[0xF3, 0x48, 0xAB]), 3);
        assert_eq!(length(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0, 0, 0]), 9);
        // REX antes de um prefixo legado é ignorado.
        let ignored = at(&[0x48, 0x66, 0xB8, 0x34, 0x12], 0);
        assert_eq!((ignored.length, ignored.immediate), (5, Some(0x1234)));
        assert_eq!(decode(&[0x06], 0), None);
        assert_eq!(decode(&[0x0F, 0x04], 0), None);
        assert_eq!(decode(&[0xE8, 0x00], 0), None);
        assert_eq!(decode(&[], 0), None);
        assert_eq!(decode(&[0x66; 16], 0), None);
        assert_eq!(at(&[0x90], 0).end(), 1);
    }

    #[test]
    fn linear_sweep_skips_bad_bytes() {
        let insns = decode_all(&[0x90, 0x06, 0x48, 0x89, 0xE5, 0xC3], 0x100);
        let addresses: Vec<u64> = insns.iter().map(|insn| insn.address).collect();
        assert_eq!(addresses, vec![0x100, 0x102, 0x105]);
        assert_eq!(insns[2].flow, Flow::Return);
    }
}
