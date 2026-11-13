//! Índice nativo de ProductPolicy.
//!
//! Validação e montagem do índice; os descritores apontam para o blob do
//! contexto e nenhuma política é criada.

use alloc::vec::Vec;

use super::layout::{capture_at, context_at, descriptor_at, entry_at, header_at, ulong_at, unicode_at, Descriptor, PolicyEntry, PolicyHeader, RAW_ENTRY};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::mm::guest_memory as guest;

/// Tamanho do cabeçalho do blob (os valores começam logo depois).
const HEADER: u64 = PolicyHeader::SIZE;

const STATUS_DATA_ERROR: u32 = 0xC000_003E;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

/// O blob primário tem comprimento e tipo capturados pelo loader em
/// +0x14000/+0x14004; o secundário vai direto à validação das entradas.
pub fn validate_header(context: u64) -> u32 {
    let blob = context_at(context).primary.get();
    if blob == 0 {
        return 0;
    }
    if capture_at(blob).value_type.get() != 3 {
        return STATUS_DATA_ERROR;
    }
    let captured = capture_at(blob).captured_size.get();
    if captured < 24 {
        return STATUS_DATA_ERROR;
    }
    let total = header_at(blob).total_size.get();
    if captured < total || total < 24 {
        return STATUS_DATA_ERROR;
    }
    let entries = header_at(blob).values_size.get();
    if captured < entries || total < entries {
        return STATUS_DATA_ERROR;
    }
    let footer = header_at(blob).end_marker_size.get();
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
        guest::write_bytes(descriptors, &alloc::vec![0u8; capacity as usize * Descriptor::SIZE as usize]);
    }
    let end_offset = header_at(blob).values_size.get().wrapping_add(HEADER as u32) as u64;
    let end = blob + end_offset;
    let mut entry = blob + HEADER;
    let mut count = 0u32;
    while entry != end {
        if validate == 1 {
            if entry - blob + HEADER > end_offset {
                return STATUS_DATA_ERROR;
            }
            let size = entry_at(entry).size.get() as u64;
            if entry - blob + size > end_offset {
                return STATUS_DATA_ERROR;
            }
            let name_length = entry_at(entry).name_size.get() as u64;
            if name_length > size {
                return STATUS_DATA_ERROR;
            }
            let next = entry.wrapping_add(size);
            if next < entry {
                return STATUS_DATA_ERROR;
            }
            let data_start = entry.wrapping_add(PolicyEntry::SIZE);
            let name_end = data_start.wrapping_add(name_length);
            if name_end < data_start || name_end > next {
                return STATUS_DATA_ERROR;
            }
            let data_length = entry_at(entry).data_size.get() as u64;
            let data_end = data_start.wrapping_add(name_length + data_length);
            if data_end < data_start || data_end > next {
                return STATUS_DATA_ERROR;
            }
            let flags = entry_at(entry).flags.get();
            if flags != 0 && flags & 3 == 0 {
                return STATUS_DATA_ERROR;
            }
        }
        if descriptors != 0 && count < capacity {
            let descriptor = descriptor_at(descriptors + count as u64 * Descriptor::SIZE);
            descriptor.kind.set(RAW_ENTRY);
            descriptor.entry.set(entry);
        }
        count = count.wrapping_add(1);
        entry = entry.wrapping_add(entry_at(entry).size.get() as u64);
    }
    if count_pointer != 0 {
        ulong_at(count_pointer).set(count);
    }
    if count > capacity { STATUS_BUFFER_TOO_SMALL } else { 0 }
}

/// Comparador do índice: kind 2 (entrada do blob) ou UNICODE_STRING; WCHARs
/// contados, sensível a caixa.
pub fn compare(left: u64, right: u64) -> i32 {
    let text = |descriptor: u64| -> (u64, u32) {
        let entry = descriptor_at(descriptor).entry.get();
        if descriptor_at(descriptor).kind.get() == RAW_ENTRY {
            (entry + PolicyEntry::SIZE, (entry_at(entry).name_size.get() >> 1) as u32)
        } else {
            let name = unicode_at(entry);
            (name.buffer.get(), (name.length.get() >> 1) as u32)
        }
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
    let first = guest::read_bytes(left, Descriptor::SIZE as usize);
    let second = guest::read_bytes(right, Descriptor::SIZE as usize);
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
    let pointer = |index: i64| descriptors + index as u64 * Descriptor::SIZE;
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
            // Adia a partição maior, limitando a profundidade.
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
