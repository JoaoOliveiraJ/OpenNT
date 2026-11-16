//! qsort e qsort_s do CRT do kernel.
//!
//! Ordena registros na memória do convidado. O comparador nativo recebe
//! endereços do próprio array; copiar elementos para buffers auxiliares
//! mudaria esse contrato. O qsort_s (ntoskrnl 19041, 0x3d27a0) é o mesmo
//! algoritmo, com o Context como primeiro argumento do comparador; Base
//! NULL com Num != 0, Width 0 ou Compare NULL são parâmetro inválido (o
//! tratador do kernel volta e nada é ordenado).

use alloc::vec;

use crate::hal::amd64::native_call;
use crate::ntos::mm::guest_memory as guest;

pub fn sort_elements(base: u64, count: u64, element_size: u64, comparator: u64) {
    if count < 2 || element_size == 0 {
        return; // qsort é void
    }
    // O contrato devolve int: os bits altos de RAX não definem o sinal.
    sort_with(base, count, element_size, |left, right| native_call::call(comparator, &[left, right, 0, 0]) as i32);
}

/// qsort_s(Base, Num, Width, Compare, Context).
pub fn sort_elements_s(base: u64, count: u64, element_size: u64, comparator: u64, context: u64) {
    if (base == 0 && count != 0) || element_size == 0 || comparator == 0 || count < 2 {
        return;
    }
    sort_with(base, count, element_size, |left, right| native_call::call(comparator, &[context, left, right, 0]) as i32);
}

fn sort_with(base: u64, count: u64, element_size: u64, comparator: impl Fn(u64, u64) -> i32) {
    let element = |index: i64| base.wrapping_add((index as u64).wrapping_mul(element_size));
    let compare = |left: i64, right: i64| comparator(element(left), element(right));
    let swap = |left: i64, right: i64| {
        if left == right {
            return;
        }
        // Elementos distintos do mesmo array não se sobrepõem: troca em bloco.
        let (left, right) = (element(left), element(right));
        let a = guest::read_bytes(left, element_size as usize);
        let b = guest::read_bytes(right, element_size as usize);
        guest::write_bytes(left, &b);
        guest::write_bytes(right, &a);
    };
    // Mediana de três, seleção para intervalos curtos; o intervalo maior é
    // adiado, limitando a pilha a O(log n). Índices com sinal, para os
    // decrementos abaixo de `first`.
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
