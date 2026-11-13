//! Altitudes de minifiltro — RtlCompareAltitudes (ntoskrnl 10.0.19045, RVA 0x313b70).
//!
//! Uma altitude é um número decimal em UNICODE_STRING ("385100", "40000.5").
//! A comparação do NT: tira os zeros à esquerda da parte inteira e à direita da
//! fracionária; a parte inteira mais longa vence, depois os dígitos inteiros,
//! depois os fracionários um a um e por fim a fração mais longa. Os caracteres
//! são comparados como unidades UTF-16 cruas.

use alloc::vec::Vec;

use crate::ntos::inc::types::UnicodeString;
use crate::ntos::mm::guest_memory as guest;

fn units(string: &UnicodeString) -> Vec<u16> {
    let bytes = guest::read_bytes(string.buffer.get(), (string.length.get() & !1) as usize);
    bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect()
}

fn sign(left: u16, right: u16) -> i32 {
    if right < left { 1 } else { -1 }
}

/// Parte inteira sem zeros à esquerda: (dígitos a partir do primeiro útil,
/// índice do ponto, comprimento restante).
fn strip_integer(text: &[u16]) -> (&[u16], usize, usize) {
    let dot = text.iter().position(|&unit| unit == b'.' as u16).unwrap_or(text.len());
    let zeros = text[..dot].iter().take_while(|&&unit| unit == b'0' as u16).count();
    (&text[zeros..], dot - zeros, text.len() - zeros)
}

/// Comprimento da fração sem zeros à direita.
fn fraction_length(text: &[u16], dot: usize, length: usize) -> i32 {
    let mut fraction = (length as i32 - dot as i32 - 1).max(0);
    if length != 0 {
        let mut last = length - 1;
        while last > dot && text[last] == b'0' as u16 {
            fraction -= 1;
            last -= 1;
        }
    }
    fraction
}

/// RtlCompareAltitudes(Altitude1, Altitude2) -> LONG (-1, 0, 1).
pub fn compare_altitudes(first: &UnicodeString, second: &UnicodeString) -> i32 {
    let (left_units, right_units) = (units(first), units(second));
    let (left, left_dot, left_length) = strip_integer(&left_units);
    let (right, right_dot, right_length) = strip_integer(&right_units);
    if left_dot != right_dot {
        return if right_dot < left_dot { 1 } else { -1 };
    }
    for index in 0..left_dot {
        if left[index] != right[index] {
            return sign(left[index], right[index]);
        }
    }
    let left_fraction = fraction_length(left, left_dot, left_length);
    let right_fraction = fraction_length(right, right_dot, right_length);
    if left_fraction > 0 {
        let mut index = 0;
        while index < right_fraction {
            let (a, b) = (left[left_dot + 1 + index as usize], right[right_dot + 1 + index as usize]);
            if a != b {
                return sign(a, b);
            }
            index += 1;
            if index >= left_fraction {
                break;
            }
        }
    }
    if left_fraction != right_fraction {
        return if left_fraction <= right_fraction { -1 } else { 1 };
    }
    0
}
