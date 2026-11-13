//! Índice nativo de ProductPolicy — `system32/ntos/ex/license-index.js`.
//!
//! Validação e montagem do índice; os descritores apontam para o blob do
//! contexto e nenhuma política é criada.

use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;

const STATUS_DATA_ERROR: u32 = 0xC000_003E;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

/// O blob primário tem comprimento e tipo capturados pelo loader em
/// +0x14000/+0x14004; o secundário vai direto à validação das entradas.
pub fn validate_header(context: u64) -> u32 {
    let blob = guest::read64(context);
    if blob == 0 {
        return 0;
    }
    if guest::read32(blob + 0x14004) != 3 {
        return STATUS_DATA_ERROR;
    }
    let captured = guest::read32(blob + 0x14000);
    if captured < 24 {
        return STATUS_DATA_ERROR;
    }
    let total = guest::read32(blob);
    if captured < total || total < 24 {
        return STATUS_DATA_ERROR;
    }
    let entries = guest::read32(blob + 4);
    if captured < entries || total < entries {
        return STATUS_DATA_ERROR;
    }
    let footer = guest::read32(blob + 8);
    if captured < footer || total < footer {
        return STATUS_DATA_ERROR;
    }
    if entries.wrapping_add(footer) > total { STATUS_DATA_ERROR } else { 0 }
}

/// RVA 0x7ABBDC: limpa a capacidade, valida antes de publicar cada
/// descritor e só informa a contagem depois do blob inteiro; um erro deixa
/// os descritores anteriores visíveis e conserva a contagem antiga.
pub fn build(blob: u64, validate: u8, descriptors: u64, capacity: u32, count_pointer: u64) -> u32 {
    if descriptors != 0 {
        guest::write_bytes(descriptors, &alloc::vec![0u8; capacity as usize * 16]);
    }
    let end_offset = guest::read32(blob + 4).wrapping_add(20) as u64;
    let end = blob + end_offset;
    let mut entry = blob + 20;
    let mut count = 0u32;
    while entry != end {
        if validate == 1 {
            if entry - blob + 20 > end_offset {
                return STATUS_DATA_ERROR;
            }
            let size = guest::read16(entry) as u64;
            if entry - blob + size > end_offset {
                return STATUS_DATA_ERROR;
            }
            let name_length = guest::read16(entry + 2) as u64;
            if name_length > size {
                return STATUS_DATA_ERROR;
            }
            let next = entry.wrapping_add(size);
            if next < entry {
                return STATUS_DATA_ERROR;
            }
            let data_start = entry.wrapping_add(16);
            let name_end = data_start.wrapping_add(name_length);
            if name_end < data_start || name_end > next {
                return STATUS_DATA_ERROR;
            }
            let data_length = guest::read16(entry + 6) as u64;
            let data_end = data_start.wrapping_add(name_length + data_length);
            if data_end < data_start || data_end > next {
                return STATUS_DATA_ERROR;
            }
            let flags = guest::read32(entry + 8);
            if flags != 0 && flags & 3 == 0 {
                return STATUS_DATA_ERROR;
            }
        }
        if descriptors != 0 && count < capacity {
            let descriptor = descriptors + count as u64 * 16;
            guest::write8(descriptor, 2);
            guest::write64(descriptor + 8, entry);
        }
        count = count.wrapping_add(1);
        entry = entry.wrapping_add(guest::read16(entry) as u64);
    }
    if count_pointer != 0 {
        guest::write32(count_pointer, count);
    }
    if count > capacity { STATUS_BUFFER_TOO_SMALL } else { 0 }
}

/// Comparador do índice: kind 2 (entrada do blob) ou UNICODE_STRING; WCHARs
/// contados, sensível a caixa.
pub fn compare(left: u64, right: u64) -> i32 {
    let text = |descriptor: u64| -> (u64, u32) {
        let entry = guest::read64(descriptor + 8);
        let raw = guest::read8(descriptor) == 2;
        let text = if raw { entry + 16 } else { guest::read64(entry + 8) };
        (text, (guest::read16(entry + if raw { 2 } else { 0 }) >> 1) as u32)
    };
    let (left_text, left_length) = text(left);
    let (right_text, right_length) = text(right);
    for index in 0..left_length.min(right_length) as u64 {
        let difference = guest::read16(left_text + index * 2) as i32 - guest::read16(right_text + index * 2) as i32;
        if difference != 0 {
            return if difference < 0 { -1 } else { 1 };
        }
    }
    match left_length.cmp(&right_length) {
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Greater => 1,
    }
}

/// Troca os 16 bytes, inclusive os campos reservados.
fn swap(left: u64, right: u64) {
    if left == right {
        return;
    }
    let first = guest::read_bytes(left, 16);
    let second = guest::read_bytes(right, 16);
    guest::write_bytes(left, &second);
    guest::write_bytes(right, &first);
}

/// qsort do kernel: seleção até oito elementos e partição pela mediana
/// acima disso. A ordem de nomes duplicados afeta a entrada que a busca
/// binária escolhe, por isso não é uma ordenação estável qualquer.
pub fn sort(descriptors: u64, count: u32) {
    if count < 2 {
        return;
    }
    let pointer = |index: i64| descriptors + index as u64 * 16;
    let compare_at = |left: i64, right: i64| compare(pointer(left), pointer(right));
    let swap_at = |left: i64, right: i64| swap(pointer(left), pointer(right));
    let mut pending: Vec<(i64, i64)> = alloc::vec![(0, count as i64 - 1)];
    while let Some((mut first, mut last)) = pending.pop() {
        loop {
            let length = last - first + 1;
            if length <= 8 {
                while last > first {
                    let mut greatest = first;
                    for index in first + 1..=last {
                        if compare_at(index, greatest) > 0 {
                            greatest = index;
                        }
                    }
                    swap_at(greatest, last);
                    last -= 1;
                }
                break;
            }
            let mut middle = first + (length >> 1);
            if compare_at(first, middle) > 0 {
                swap_at(first, middle);
            }
            if compare_at(first, last) > 0 {
                swap_at(first, last);
            }
            if compare_at(middle, last) > 0 {
                swap_at(middle, last);
            }
            let mut lower = first;
            let mut upper = last;
            let mut equal_end;
            loop {
                if middle > lower {
                    loop {
                        lower += 1;
                        if !(lower < middle && compare_at(lower, middle) <= 0) {
                            break;
                        }
                    }
                }
                if lower >= middle {
                    loop {
                        lower += 1;
                        if !(lower <= last && compare_at(lower, middle) <= 0) {
                            break;
                        }
                    }
                }
                loop {
                    equal_end = upper;
                    upper -= 1;
                    if !(upper > middle && compare_at(upper, middle) > 0) {
                        break;
                    }
                }
                if upper < lower {
                    break;
                }
                swap_at(lower, upper);
                if middle == upper {
                    middle = lower;
                }
            }
            if middle < equal_end {
                loop {
                    equal_end -= 1;
                    if !(equal_end > middle && compare_at(equal_end, middle) == 0) {
                        break;
                    }
                }
            }
            if equal_end <= middle {
                loop {
                    equal_end -= 1;
                    if !(equal_end > first && compare_at(equal_end, middle) == 0) {
                        break;
                    }
                }
            }
            // Adia a partição maior, como o limite de profundidade do original.
            if equal_end - first >= last - lower {
                if first < equal_end {
                    pending.push((first, equal_end));
                }
                if lower >= last {
                    break;
                }
                first = lower;
            } else {
                if lower < last {
                    pending.push((lower, last));
                }
                if first >= equal_end {
                    break;
                }
                last = equal_end;
            }
        }
    }
}
