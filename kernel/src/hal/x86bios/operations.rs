//! Aritmética das instruções inteiras do emulador de modo real: o resultado
//! e o EFLAGS de cada operação (soma, subtração, lógica, deslocamentos e
//! rotações, multiplicação e divisão, BCD, varredura e teste de bits), na
//! largura do operando (1, 2 ou 4 bytes).
//!
//! As funções são puras: recebem os operandos e o EFLAGS e devolvem o
//! resultado; o emulador (`emulator.rs`) busca e grava os operandos. Os bits
//! que o manual da Intel define são calculados como ele descreve; os que
//! ficam indefinidos seguem a convenção mais comum dos processadores (AF
//! limpo nas operações lógicas e nas multiplicações, SF/ZF/PF do resultado
//! baixo da multiplicação).

/// Bits do EFLAGS.
pub const CF: u32 = 0x0001;
pub const PF: u32 = 0x0004;
pub const AF: u32 = 0x0010;
pub const ZF: u32 = 0x0040;
pub const SF: u32 = 0x0080;
pub const TF: u32 = 0x0100;
pub const IF: u32 = 0x0200;
pub const DF: u32 = 0x0400;
pub const OF: u32 = 0x0800;

/// Bits aritméticos (os que as operações da ALU recalculam).
const ARITHMETIC: u32 = CF | PF | AF | ZF | SF | OF;

/// Máscara do operando de `size` bytes.
#[inline]
pub const fn mask(size: u32) -> u32 {
    match size {
        1 => 0xFF,
        2 => 0xFFFF,
        _ => 0xFFFF_FFFF,
    }
}

/// Bit de sinal do operando de `size` bytes.
#[inline]
pub const fn sign_bit(size: u32) -> u32 {
    match size {
        1 => 0x80,
        2 => 0x8000,
        _ => 0x8000_0000,
    }
}

/// Estende o sinal de um valor de `size` bytes para 32 bits.
#[inline]
pub const fn sign_extend(value: u32, size: u32) -> u32 {
    match size {
        1 => value as u8 as i8 as i32 as u32,
        2 => value as u16 as i16 as i32 as u32,
        _ => value,
    }
}

#[inline]
fn parity(value: u32) -> u32 {
    if (value as u8).count_ones() % 2 == 0 { PF } else { 0 }
}

/// SF, ZF e PF de um resultado.
#[inline]
fn result_flags(result: u32, size: u32) -> u32 {
    let result = result & mask(size);
    let mut flags = parity(result);
    if result == 0 {
        flags |= ZF;
    }
    if result & sign_bit(size) != 0 {
        flags |= SF;
    }
    flags
}

/// ADD/ADC: `a + b + carry`.
pub fn add(eflags: &mut u32, a: u32, b: u32, carry: bool, size: u32) -> u32 {
    let m = mask(size) as u64;
    let (a, b) = (a as u64 & m, b as u64 & m);
    let full = a + b + carry as u64;
    let result = (full & m) as u32;
    let mut flags = result_flags(result, size);
    if full > m {
        flags |= CF;
    }
    if (a ^ b ^ full) & 0x10 != 0 {
        flags |= AF;
    }
    let sign = sign_bit(size) as u64;
    if (!(a ^ b) & (a ^ full)) & sign != 0 {
        flags |= OF;
    }
    *eflags = (*eflags & !ARITHMETIC) | flags;
    result
}

/// SUB/SBB/CMP/NEG: `a - b - borrow`.
pub fn sub(eflags: &mut u32, a: u32, b: u32, borrow: bool, size: u32) -> u32 {
    let m = mask(size) as u64;
    let (a, b) = (a as u64 & m, b as u64 & m);
    let full = a.wrapping_sub(b).wrapping_sub(borrow as u64);
    let result = (full & m) as u32;
    let mut flags = result_flags(result, size);
    if b + borrow as u64 > a {
        flags |= CF;
    }
    if (a ^ b ^ full) & 0x10 != 0 {
        flags |= AF;
    }
    let sign = sign_bit(size) as u64;
    if ((a ^ b) & (a ^ full)) & sign != 0 {
        flags |= OF;
    }
    *eflags = (*eflags & !ARITHMETIC) | flags;
    result
}

/// AND/OR/XOR/TEST: CF e OF limpos, SF/ZF/PF do resultado.
pub fn logic(eflags: &mut u32, result: u32, size: u32) -> u32 {
    let result = result & mask(size);
    *eflags = (*eflags & !ARITHMETIC) | result_flags(result, size);
    result
}

/// INC/DEC: como ADD/SUB de 1, preservando CF.
pub fn increment(eflags: &mut u32, value: u32, delta_negative: bool, size: u32) -> u32 {
    let carry = *eflags & CF;
    let result = if delta_negative { sub(eflags, value, 1, false, size) } else { add(eflags, value, 1, false, size) };
    *eflags = (*eflags & !CF) | carry;
    result
}

/// Operações do grupo 2 (campo reg do ModRM).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Shift {
    Rol,
    Ror,
    Rcl,
    Rcr,
    Shl,
    Shr,
    Sar,
}

/// Deslocamentos e rotações. A contagem chega mascarada em 5 bits; zero não
/// muda nada (nem os flags).
pub fn shift(eflags: &mut u32, kind: Shift, value: u32, count: u32, size: u32) -> u32 {
    let bits = size * 8;
    let m = mask(size);
    let sign = sign_bit(size);
    let value = value & m;
    if count == 0 {
        return value;
    }
    let mut flags = *eflags;
    let result = match kind {
        Shift::Rol => {
            let rotate = count % bits;
            let result = if rotate == 0 { value } else { ((value << rotate) | (value >> (bits - rotate))) & m };
            flags = (flags & !(CF | OF)) | if result & 1 != 0 { CF } else { 0 };
            if ((result & sign != 0) as u32 ^ (result & 1)) != 0 {
                flags |= OF;
            }
            result
        }
        Shift::Ror => {
            let rotate = count % bits;
            let result = if rotate == 0 { value } else { ((value >> rotate) | (value << (bits - rotate))) & m };
            flags = (flags & !(CF | OF)) | if result & sign != 0 { CF } else { 0 };
            let top = result & sign != 0;
            let next = result & (sign >> 1) != 0;
            if top != next {
                flags |= OF;
            }
            result
        }
        Shift::Rcl => {
            // Rotação de bits + 1 posições (o CF entra no anel).
            let rotate = count % (bits + 1);
            let mut result = value as u64;
            let mut carry = (flags & CF) as u64;
            for _ in 0..rotate {
                let out = (result >> (bits - 1)) & 1;
                result = ((result << 1) | carry) & m as u64;
                carry = out;
            }
            let result = result as u32;
            flags = (flags & !(CF | OF)) | carry as u32;
            if ((result & sign != 0) as u32 ^ carry as u32) != 0 {
                flags |= OF;
            }
            result
        }
        Shift::Rcr => {
            let rotate = count % (bits + 1);
            let mut result = value as u64;
            let mut carry = (flags & CF) as u64;
            let original_carry = carry;
            for _ in 0..rotate {
                let out = result & 1;
                result = (result >> 1) | (carry << (bits - 1));
                carry = out;
            }
            let result = result as u32;
            flags = (flags & !(CF | OF)) | carry as u32;
            // OF da RCR: sinal original XOR CF de entrada (definido para 1).
            if ((value & sign != 0) as u64 ^ original_carry) != 0 {
                flags |= OF;
            }
            result
        }
        Shift::Shl => {
            let result = if count >= 32 { 0 } else { (value << count) & m };
            let carry = if count > bits { 0 } else { (value >> (bits - count)) & 1 };
            flags = (flags & !ARITHMETIC) | result_flags(result, size) | carry;
            if ((result & sign != 0) as u32 ^ carry) != 0 {
                flags |= OF;
            }
            result
        }
        Shift::Shr => {
            let result = if count >= 32 { 0 } else { value >> count };
            let carry = if count > bits { 0 } else { (value >> (count - 1)) & 1 };
            flags = (flags & !ARITHMETIC) | result_flags(result, size) | carry;
            if value & sign != 0 && count == 1 {
                flags |= OF;
            }
            result
        }
        Shift::Sar => {
            let signed = sign_extend(value, size) as i32;
            let effective = count.min(31);
            let result = (signed >> effective) as u32 & m;
            let carry = ((signed >> (count.min(bits) - 1).min(31)) & 1) as u32;
            flags = (flags & !ARITHMETIC) | result_flags(result, size) | carry;
            result
        }
    };
    *eflags = flags;
    result
}

/// SHLD/SHRD: desloca `dest` trazendo bits de `source`. Contagem já
/// mascarada em 5 bits; zero não muda nada.
pub fn shift_double(eflags: &mut u32, left: bool, dest: u32, source: u32, count: u32, size: u32) -> u32 {
    let bits = size * 8;
    let m = mask(size) as u64;
    if count == 0 {
        return dest & m as u32;
    }
    let (dest64, source64) = (dest as u64 & m, source as u64 & m);
    let (result, carry) = if left {
        let combined = (dest64 << bits) | source64;
        let shifted = combined << count;
        (((shifted >> bits) & m) as u32, ((combined >> (2 * bits - count)) & 1) as u32)
    } else {
        let combined = (source64 << bits) | dest64;
        let shifted = combined >> count;
        ((shifted & m) as u32, ((combined >> (count - 1)) & 1) as u32)
    };
    let mut flags = (*eflags & !ARITHMETIC) | result_flags(result, size) | carry;
    if ((result ^ dest) & sign_bit(size)) != 0 {
        flags |= OF;
    }
    *eflags = flags;
    result
}

/// MUL: devolve (baixo, alto). CF=OF=1 se a metade alta não é zero.
pub fn multiply(eflags: &mut u32, a: u32, b: u32, size: u32) -> (u32, u32) {
    let m = mask(size) as u64;
    let product = (a as u64 & m) * (b as u64 & m);
    let (low, high) = ((product & m) as u32, ((product >> (size * 8)) & m) as u32);
    let mut flags = (*eflags & !ARITHMETIC) | result_flags(low, size);
    if high != 0 {
        flags |= CF | OF;
    }
    *eflags = flags;
    (low, high)
}

/// IMUL: devolve (baixo, alto). CF=OF=1 se o produto não cabe no tamanho.
pub fn signed_multiply(eflags: &mut u32, a: u32, b: u32, size: u32) -> (u32, u32) {
    let m = mask(size) as u64;
    let product = (sign_extend(a, size) as i32 as i64) * (sign_extend(b, size) as i32 as i64);
    let low = (product as u64 & m) as u32;
    let high = ((product as u64 >> (size * 8)) & m) as u32;
    let mut flags = (*eflags & !ARITHMETIC) | result_flags(low, size);
    if sign_extend(low, size) as i32 as i64 != product {
        flags |= CF | OF;
    }
    *eflags = flags;
    (low, high)
}

/// Erros de divisão (os status do emulador).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DivideError {
    ByZero,
    Overflow,
}

/// DIV: dividendo (alto:baixo) por `divisor`; devolve (quociente, resto).
pub fn divide(high: u32, low: u32, divisor: u32, size: u32) -> Result<(u32, u32), DivideError> {
    let m = mask(size) as u64;
    let divisor = divisor as u64 & m;
    if divisor == 0 {
        return Err(DivideError::ByZero);
    }
    let dividend = ((high as u64 & m) << (size * 8)) | (low as u64 & m);
    let quotient = dividend / divisor;
    if quotient > m {
        return Err(DivideError::Overflow);
    }
    Ok((quotient as u32, (dividend % divisor) as u32))
}

/// IDIV: dividendo com sinal (alto:baixo) por `divisor`; quociente truncado
/// em direção a zero, resto com o sinal do dividendo.
pub fn signed_divide(high: u32, low: u32, divisor: u32, size: u32) -> Result<(u32, u32), DivideError> {
    let m = mask(size) as u64;
    let bits = size * 8;
    let divisor = sign_extend(divisor, size) as i32 as i64;
    if divisor == 0 {
        return Err(DivideError::ByZero);
    }
    let raw = ((high as u64 & m) << bits) | (low as u64 & m);
    // Estende o sinal do dividendo de 2*bits para 64 bits.
    let dividend = if bits == 32 { raw as i64 } else { ((raw << (64 - 2 * bits)) as i64) >> (64 - 2 * bits) };
    if dividend == i64::MIN && divisor == -1 {
        return Err(DivideError::Overflow);
    }
    let quotient = dividend / divisor;
    let remainder = dividend % divisor;
    let limit = 1i64 << (bits - 1);
    if quotient >= limit || quotient < -limit {
        return Err(DivideError::Overflow);
    }
    Ok(((quotient as u64 & m) as u32, (remainder as u64 & m) as u32))
}

/// DAA sobre AL.
pub fn decimal_adjust_add(eflags: &mut u32, al: u8) -> u8 {
    let (old_al, old_cf) = (al, *eflags & CF != 0);
    let mut al = al;
    let mut flags = *eflags & !(CF | AF);
    if al & 0x0F > 9 || *eflags & AF != 0 {
        al = al.wrapping_add(6);
        flags |= AF;
    }
    if old_al > 0x99 || old_cf {
        al = al.wrapping_add(0x60);
        flags |= CF;
    }
    *eflags = (flags & !(SF | ZF | PF)) | result_flags(al as u32, 1);
    al
}

/// DAS sobre AL.
pub fn decimal_adjust_subtract(eflags: &mut u32, al: u8) -> u8 {
    let (old_al, old_cf) = (al, *eflags & CF != 0);
    let mut al = al;
    let mut flags = *eflags & !(CF | AF);
    if al & 0x0F > 9 || *eflags & AF != 0 {
        al = al.wrapping_sub(6);
        flags |= AF;
    }
    if old_al > 0x99 || old_cf {
        al = al.wrapping_sub(0x60);
        flags |= CF;
    }
    *eflags = (flags & !(SF | ZF | PF)) | result_flags(al as u32, 1);
    al
}

/// AAA/AAS sobre AX: devolve o novo AX.
pub fn ascii_adjust(eflags: &mut u32, ax: u16, subtract: bool) -> u16 {
    let (mut al, mut ah) = (ax as u8, (ax >> 8) as u8);
    if al & 0x0F > 9 || *eflags & AF != 0 {
        if subtract {
            al = al.wrapping_sub(6);
            ah = ah.wrapping_sub(1);
        } else {
            al = al.wrapping_add(6);
            ah = ah.wrapping_add(1);
        }
        *eflags |= AF | CF;
    } else {
        *eflags &= !(AF | CF);
    }
    al &= 0x0F;
    ((ah as u16) << 8) | al as u16
}

/// AAM: AH = AL / base, AL = AL % base.
pub fn ascii_adjust_multiply(eflags: &mut u32, al: u8, base: u8) -> Option<u16> {
    if base == 0 {
        return None;
    }
    let (ah, al) = (al / base, al % base);
    *eflags = (*eflags & !(SF | ZF | PF)) | result_flags(al as u32, 1);
    Some(((ah as u16) << 8) | al as u16)
}

/// AAD: AL = AL + AH * base, AH = 0.
pub fn ascii_adjust_divide(eflags: &mut u32, ax: u16, base: u8) -> u16 {
    let al = (ax as u8).wrapping_add(((ax >> 8) as u8).wrapping_mul(base));
    *eflags = (*eflags & !(SF | ZF | PF)) | result_flags(al as u32, 1);
    al as u16
}

/// Condição de Jcc/SETcc (os quatro bits baixos do opcode).
pub fn condition(eflags: u32, code: u8) -> bool {
    let flag = |bit: u32| eflags & bit != 0;
    let result = match code >> 1 {
        0 => flag(OF),
        1 => flag(CF),
        2 => flag(ZF),
        3 => flag(CF) || flag(ZF),
        4 => flag(SF),
        5 => flag(PF),
        6 => flag(SF) != flag(OF),
        _ => flag(ZF) || (flag(SF) != flag(OF)),
    };
    result != (code & 1 != 0)
}
