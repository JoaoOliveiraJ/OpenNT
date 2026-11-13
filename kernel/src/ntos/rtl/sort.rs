//! qsort do CRT do kernel — `system32/ntos/rtl/sort.js`.
//!
//! Ordena registros na memória do convidado. O comparador nativo recebe
//! endereços do próprio array; copiar elementos para buffers auxiliares
//! mudaria esse contrato.

use alloc::vec;

use crate::hal::amd64::native_call;
use crate::ntos::mm::guest_memory as guest;

pub fn sort_elements(base: u64, count: u64, element_size: u64, comparator: u64) {
    if count < 2 || element_size == 0 {
        return; // qsort é void
    }
    let element = |index: i64| base.wrapping_add((index as u64).wrapping_mul(element_size));
    // O contrato devolve int: os bits altos de RAX não definem o sinal.
    let compare = |left: i64, right: i64| native_call::call(comparator, &[element(left), element(right), 0, 0]) as i32;
    let swap = |left: i64, right: i64| {
        if left == right {
            return;
        }
        let (left, right) = (element(left), element(right));
        let mut offset = 0u64;
        if (left | right) & 3 == 0 {
            while offset + 4 <= element_size {
                let a = guest::read32(left + offset);
                let b = guest::read32(right + offset);
                guest::write32(left + offset, b);
                guest::write32(right + offset, a);
                offset += 4;
            }
        }
        while offset < element_size {
            let a = guest::read8(left + offset);
            let b = guest::read8(right + offset);
            guest::write8(left + offset, b);
            guest::write8(right + offset, a);
            offset += 1;
        }
    };
    // Mediana de três, seleção para intervalos curtos; o intervalo maior é
    // adiado, limitando a pilha a O(log n). Índices com sinal, como os
    // BigInt do original, para os decrementos abaixo de `first`.
    let mut pending = vec![(0i64, count as i64 - 1)];
    while let Some((mut first, mut last)) = pending.pop() {
        loop {
            let length = last - first + 1;
            if length <= 8 {
                while last > first {
                    let mut greatest = first;
                    for index in first + 1..=last {
                        if compare(index, greatest) > 0 {
                            greatest = index;
                        }
                    }
                    swap(greatest, last);
                    last -= 1;
                }
                break;
            }
            let mut middle = first + length / 2;
            if compare(first, middle) > 0 {
                swap(first, middle);
            }
            if compare(first, last) > 0 {
                swap(first, last);
            }
            if compare(middle, last) > 0 {
                swap(middle, last);
            }
            let mut lower = first;
            let mut upper = last;
            let mut equal_boundary;
            loop {
                if middle > lower {
                    loop {
                        lower += 1;
                        if !(lower < middle && compare(lower, middle) <= 0) {
                            break;
                        }
                    }
                }
                if lower >= middle {
                    loop {
                        lower += 1;
                        if !(lower <= last && compare(lower, middle) <= 0) {
                            break;
                        }
                    }
                }
                loop {
                    equal_boundary = upper;
                    upper -= 1;
                    if !(upper > middle && compare(upper, middle) > 0) {
                        break;
                    }
                }
                if upper < lower {
                    break;
                }
                swap(lower, upper);
                if middle == upper {
                    middle = lower;
                }
            }
            // Exclui o grupo igual ao pivô das próximas partições.
            if middle < equal_boundary {
                loop {
                    equal_boundary -= 1;
                    if !(equal_boundary > middle && compare(equal_boundary, middle) == 0) {
                        break;
                    }
                }
            }
            if equal_boundary <= middle {
                loop {
                    equal_boundary -= 1;
                    if !(equal_boundary > first && compare(equal_boundary, middle) == 0) {
                        break;
                    }
                }
            }
            if equal_boundary - first >= last - lower {
                if first < equal_boundary {
                    pending.push((first, equal_boundary));
                }
                if lower >= last {
                    break;
                }
                first = lower;
            } else {
                if lower < last {
                    pending.push((lower, last));
                }
                if first >= equal_boundary {
                    break;
                }
                last = equal_boundary;
            }
        }
    }
}
