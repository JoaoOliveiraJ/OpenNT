//! Autotestes (fase 6) das listas de faixas, da codificação de descritores
//! de memória e porta, do RtlCopyBitMap e das conversões _strtoui64 e
//! strtok_s, cada export chamado pelo nome.
//!
//! Os valores esperados foram calculados fora do kernel executando o código
//! real do ntoskrnl 19041 (as mesmas sequências de chamadas, num emulador
//! x64 com os alocadores interceptados).

use alloc::vec::Vec;

use super::phase6::call_export;
use crate::ntos::ex::pool_allocation;
use crate::ntos::mm::guest_memory as guest;

type Assert = fn(bool, &str);

const M: u64 = u64::MAX;
const IF_CONFLICT: u64 = 1;
const SHARED: u64 = 2;
const COUNTED: u64 = 0x10;
const STATUS_NO_MORE_ENTRIES: u32 = 0x8000_001A;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_RANGE_LIST_CONFLICT: u32 = 0xC000_0282;
const STATUS_RANGE_NOT_FOUND: u32 = 0xC000_028C;

fn status(name: &str, arguments: &[u64]) -> u32 {
    call_export(name, arguments).map_or(u32::MAX, |value| value as u32)
}

/// O estado de uma RTL_RANGE_LIST: (início, fim, atributos, PublicFlags,
/// PrivateFlags, dono) por entrada de topo; numa fundida, o último valor é
/// o tamanho da sublista e as faixas dela vêm em seguida.
fn dump(list: u64) -> (Vec<[u64; 6]>, u32, u32) {
    let mut rows = Vec::new();
    let mut link = guest::read64(list);
    while link != list {
        let entry = link - 0x28;
        let private = guest::read16(entry + 0x22) as u64;
        let mut row = [guest::read64(entry), guest::read64(entry + 8), guest::read8(entry + 0x20) as u64, guest::read8(entry + 0x21) as u64, private, guest::read64(entry + 0x18)];
        if private & 1 != 0 {
            let head = entry + 0x10;
            let mut subs = Vec::new();
            let mut sub = guest::read64(head);
            while sub != head {
                let sub_entry = sub - 0x28;
                subs.push([guest::read64(sub_entry), guest::read64(sub_entry + 8), guest::read8(sub_entry + 0x20) as u64, guest::read8(sub_entry + 0x21) as u64, guest::read16(sub_entry + 0x22) as u64, guest::read64(sub_entry + 0x18)]);
                sub = guest::read64(sub);
            }
            row[5] = subs.len() as u64;
            rows.push(row);
            rows.extend(subs);
        } else {
            rows.push(row);
        }
        link = guest::read64(link);
    }
    (rows, guest::read32(list + 0x14), guest::read32(list + 0x18))
}

fn same(list: u64, rows: &[[u64; 6]], count: u32, stamp: u32) -> bool {
    let (actual, actual_count, actual_stamp) = dump(list);
    actual == rows && actual_count == count && actual_stamp == stamp
}

fn new_list(scratch: u64) -> u64 {
    let _ = call_export("RtlInitializeRangeList", &[scratch]);
    scratch
}

fn add(list: u64, start: u64, end: u64, attributes: u64, flags: u64, user_data: u64, owner: u64) -> u32 {
    status("RtlAddRange", &[list, start, end, attributes, flags, user_data, owner])
}

/// PRTL_CONFLICT_RANGE_CALLBACK do teste: a faixa do dono `context` não
/// conflita.
extern "win64" fn owner_matches(context: u64, range: u64) -> u8 {
    (guest::read64(range + 0x18) == context) as u8
}

fn range_lists(assert: Assert) {
    let scratch = guest::alloc_bytes(0x400);
    let list = new_list(scratch);
    assert(guest::read64(list) == list && guest::read64(list + 8) == list && guest::read64(list + 0x10) == 0 && guest::read32(list + 0x18) == 0, "range: RtlInitializeRangeList");
    let steps: [(u64, u64, u64, u64, u64, u64); 12] = [
        (0x100, 0x1FF, 0, 0, 1, 0xA),
        (0x300, 0x3FF, 0, 0, 2, 0xB),
        (0x150, 0x160, 0, 0, 3, 0xC),
        (0x150, 0x160, 0, IF_CONFLICT, 3, 0xC),
        (0x380, 0x3A0, 0, SHARED, 4, 0xD),
        (0x500, 0x5FF, 0, SHARED, 5, 0xE),
        (0x580, 0x6FF, 0, SHARED, 6, 0xF),
        (0x050, 0x0FF, 1, 0, 7, 0x10),
        (0x1F0, 0x310, 0, IF_CONFLICT, 8, 0x11),
        (0x200, 0x100, 0, 0, 9, 0x12),
        (0x800, 0x8FF, 2, 0, 9, 0),
        (0x5F0, 0x5F8, 0, SHARED | IF_CONFLICT, 10, 0x13),
    ];
    let statuses: Vec<u32> = steps.iter().map(|&(start, end, attributes, flags, user_data, owner)| add(list, start, end, attributes, flags, user_data, owner)).collect();
    assert(statuses == [0, 0, STATUS_RANGE_LIST_CONFLICT, 0, STATUS_RANGE_LIST_CONFLICT, 0, 0, 0, 0, STATUS_INVALID_PARAMETER, 0, 0], "range: RtlAddRange com conflitos, compartilhadas e faixa invertida");
    let state1: [[u64; 6]; 11] = [[0x50, 0xff, 0x1, 0x0, 0x0, 0x10], [0x100, 0x3ff, 0x0, 0x0, 0x1, 0x4], [0x100, 0x1ff, 0x0, 0x2, 0x0, 0xa], [0x150, 0x160, 0x0, 0x2, 0x0, 0xc], [0x1f0, 0x310, 0x0, 0x2, 0x0, 0x11], [0x300, 0x3ff, 0x0, 0x2, 0x0, 0xb], [0x500, 0x6ff, 0x0, 0x1, 0x1, 0x3], [0x500, 0x5ff, 0x0, 0x1, 0x0, 0xe], [0x580, 0x6ff, 0x0, 0x1, 0x0, 0xf], [0x5f0, 0x5f8, 0x0, 0x1, 0x0, 0x13], [0x800, 0x8ff, 0x2, 0x0, 0x0, 0x0]];
    assert(same(list, &state1, 9, 9), "range: faixas fundidas, sublistas ordenadas e bandeiras SHARED/CONFLICT do original");

    // Iteração para a frente: o RTL_RANGE de cada faixa (as fundidas nunca).
    let (iterator, range_out) = (scratch + 0x100, scratch + 0x120);
    let mut seen = Vec::new();
    let mut step = status("RtlGetFirstRange", &[list, iterator, range_out]);
    while step == 0 {
        let range = guest::read64(range_out);
        seen.push([guest::read64(range), guest::read64(range + 8), guest::read64(range + 0x10), guest::read64(range + 0x18), guest::read8(range + 0x20) as u64, guest::read8(range + 0x21) as u64]);
        step = status("RtlGetNextRange", &[iterator, range_out, 1]);
    }
    let expected_seen: [[u64; 6]; 9] = [[0x50, 0xff, 0x7, 0x10, 0x1, 0x0], [0x100, 0x1ff, 0x1, 0xa, 0x0, 0x2], [0x150, 0x160, 0x3, 0xc, 0x0, 0x2], [0x1f0, 0x310, 0x8, 0x11, 0x0, 0x2], [0x300, 0x3ff, 0x2, 0xb, 0x0, 0x2], [0x500, 0x5ff, 0x5, 0xe, 0x0, 0x1], [0x580, 0x6ff, 0x6, 0xf, 0x0, 0x1], [0x5f0, 0x5f8, 0xa, 0x13, 0x0, 0x1], [0x800, 0x8ff, 0x9, 0x0, 0x2, 0x0]];
    assert(seen == expected_seen && step == STATUS_NO_MORE_ENTRIES && guest::read64(range_out) == 0, "range: RtlGetFirstRange/RtlGetNextRange atravessam as sublistas");
    // Passos manuais e carimbo velho.
    let _ = call_export("RtlGetFirstRange", &[list, iterator, range_out]);
    let first = guest::read64(range_out);
    let forward = status("RtlGetNextRange", &[iterator, range_out, 1]);
    let second_start = guest::read64(guest::read64(range_out));
    let back = status("RtlGetNextRange", &[iterator, range_out, 0]);
    let back_range = guest::read64(range_out);
    let before_first = status("RtlGetNextRange", &[iterator, range_out, 0]);
    assert(forward == 0 && second_start == 0x100 && back == 0 && back_range == first && before_first == STATUS_NO_MORE_ENTRIES && guest::read64(range_out) == 0 && guest::read64(iterator + 0x10) == 0, "range: RtlGetNextRange para tras ate o inicio");
    let _ = call_export("RtlGetFirstRange", &[list, iterator, range_out]);
    let _ = add(list, 0x900, 0x9FF, 0, 0, 11, 0x14);
    guest::write64(range_out, 0x1234);
    assert(status("RtlGetNextRange", &[iterator, range_out, 1]) == STATUS_INVALID_PARAMETER && guest::read64(range_out) == 0x1234, "range: carimbo diferente recusa o iterador");

    // RtlIsRangeAvailable.
    let callback = owner_matches as extern "win64" fn(u64, u64) -> u8 as usize as u64;
    let available = scratch + 0x130;
    let availability: [(u64, u64, u64, u64, u64, u64, u8); 14] = [
        (0x000, 0x04F, 0, 0, 0, 0, 1),
        (0x040, 0x060, 0, 0, 0, 0, 0),
        (0x040, 0x060, 0, 1, 0, 0, 1),
        (0x520, 0x530, 0, 0, 0, 0, 0),
        (0x520, 0x530, 1, 0, 0, 0, 1),
        (0x5F0, 0x5F0, 1, 0, 0, 0, 1),
        (0x880, 0x880, 0, 0, 0, 0, 0),
        (0x880, 0x880, 2, 0, 0, 0, 1),
        (0x880, 0x880, 0, 4, 0, 0, 0),
        (0x300, 0x300, 0, 0, 0xB, callback, 0),
        (0x320, 0x330, 0, 0, 0xB, callback, 1),
        (0x320, 0x330, 0, 0, 0x11, callback, 0),
        (0xA00, M, 0, 0, 0, 0, 1),
        (0x9FF, 0xA00, 0, 0, 0, 0, 0),
    ];
    let available_ok = availability.iter().all(|&(start, end, flags, mask, context, callback, expected)| {
        guest::write8(available, 0x55);
        status("RtlIsRangeAvailable", &[list, start, end, flags, mask, context, callback, available]) == 0 && guest::read8(available) == expected
    });
    assert(available_ok, "range: RtlIsRangeAvailable com SHARED_OK, NULL_CONFLICT_OK, mascara de atributos e callback");

    // RtlFindRange: o intervalo livre alinhado mais alto.
    let start_out = scratch + 0x138;
    let finds: [(u64, u64, u64, u64, u64, u64, u64, u64, u32, u64); 15] = [
        (0, 0xFFF, 0x100, 0x100, 0, 0, 0, 0, 0, 0xF00),
        (0, 0x9FF, 0x10, 0x10, 0, 0, 0, 0, 0, 0x7F0),
        (0, 0x8FF, 0x10, 0x10, 0, 0, 0, 0, 0, 0x7F0),
        (0, 0x8FF, 0x10, 0x10, 2, 0, 0, 0, 0, 0x8F0),
        (0, 0x6FF, 0x40, 0x40, 0, 0, 0, 0, 0, 0x4C0),
        (0, 0x6FF, 0x40, 0x40, 1, 0, 0, 0, 0, 0x6C0),
        (0x500, 0x6FF, 0x40, 0x40, 0, 0, 0, 0, STATUS_UNSUCCESSFUL, 0x5555),
        (0, 0x3FF, 0x20, 0x20, 0, 0, 0x11, callback, 0, 0x2E0),
        (0x40, 0x4F, 0x10, 1, 0, 0, 0, 0, 0, 0x40),
        (0x40, 0x4F, 0x11, 1, 0, 0, 0, 0, STATUS_INVALID_PARAMETER, 0x5555),
        (0x50, 0x40, 0x10, 1, 0, 0, 0, 0, STATUS_INVALID_PARAMETER, 0x5555),
        (0, 0x100, 0, 1, 0, 0, 0, 0, STATUS_INVALID_PARAMETER, 0x5555),
        (0, 0xFF, 0x10, 0x10, 0, 1, 0, 0, 0, 0xF0),
        (M - 0xF, M, 0x10, 0x10, 0, 0, 0, 0, STATUS_INVALID_PARAMETER, 0x5555),
        (0x10, 0x1F, 0x8, 0x20, 0, 0, 0, 0, STATUS_INVALID_PARAMETER, 0x5555),
    ];
    let finds_ok = finds.iter().all(|&(minimum, maximum, length, alignment, flags, mask, context, callback, expected, start)| {
        guest::write64(start_out, 0x5555);
        status("RtlFindRange", &[list, minimum, maximum, length, alignment, flags, mask, context, callback, start_out]) == expected && guest::read64(start_out) == start
    });
    assert(finds_ok, "range: RtlFindRange de cima para baixo, alinhamento, criterios e parametros invalidos");

    // Cópia, inversão.
    let copy = new_list(scratch + 0x140);
    let copied = status("RtlCopyRangeList", &[copy, list]);
    let copy_same = dump(copy) == dump(list);
    assert(copied == 0 && copy_same && status("RtlCopyRangeList", &[copy, list]) == STATUS_INVALID_PARAMETER, "range: RtlCopyRangeList copia sublistas, contagem e carimbo; destino nao vazio recusado");
    let inverted = new_list(scratch + 0x160);
    let inverted_status = status("RtlInvertRangeList", &[inverted, list]);
    assert(inverted_status == 0 && same(inverted, &[[0x0, 0x4f, 0x0, 0x0, 0x0, 0x0], [0x400, 0x4ff, 0x0, 0x0, 0x0, 0x0], [0x700, 0x7ff, 0x0, 0x0, 0x0, 0x0], [0xa00, M, 0x0, 0x0, 0x0, 0x0]], 4, 4), "range: RtlInvertRangeList");
    let (empty, filled, edges, fresh) = (new_list(scratch + 0x180), new_list(scratch + 0x1A0), new_list(scratch + 0x1C0), new_list(scratch + 0x1E0));
    let whole = status("RtlInvertRangeListEx", &[filled, empty, 7, 0x77, 0x88]);
    let _ = add(edges, 0, 0xF, 0, 0, 0, 1);
    let _ = add(edges, 0x20, M, 0, 0, 0, 1);
    let into_filled = status("RtlInvertRangeListEx", &[filled, edges, 3, 0x33, 0x44]);
    let gap = status("RtlInvertRangeListEx", &[fresh, edges, 3, 0x33, 0x44]);
    assert(whole == 0 && into_filled == STATUS_RANGE_LIST_CONFLICT && same(filled, &[[0, M, 7, 0, 0, 0x88]], 1, 1) && gap == 0 && same(fresh, &[[0x10, 0x1F, 3, 0, 0, 0x44]], 1, 1) && guest::read64(guest::read64(fresh) - 0x28 + 0x10) == 0x33, "range: RtlInvertRangeListEx com atributos, UserData e dono");

    // Exclusões.
    let deletes = [status("RtlDeleteRange", &[list, 0x150, 0x160, 0xC]), status("RtlDeleteRange", &[list, 0x150, 0x160, 0xC]), status("RtlDeleteRange", &[list, 0x100, 0x1FF, 0xB]), status("RtlDeleteRange", &[list, 0x050, 0x0FF, 0x10])];
    let state2: [[u64; 6]; 10] = [[0x100, 0x3ff, 0x0, 0x0, 0x1, 0x3], [0x100, 0x1ff, 0x0, 0x2, 0x0, 0xa], [0x1f0, 0x310, 0x0, 0x2, 0x0, 0x11], [0x300, 0x3ff, 0x0, 0x2, 0x0, 0xb], [0x500, 0x6ff, 0x0, 0x1, 0x1, 0x3], [0x500, 0x5ff, 0x0, 0x1, 0x0, 0xe], [0x580, 0x6ff, 0x0, 0x1, 0x0, 0xf], [0x5f0, 0x5f8, 0x0, 0x1, 0x0, 0x13], [0x800, 0x8ff, 0x2, 0x0, 0x0, 0x0], [0x900, 0x9ff, 0x0, 0x0, 0x0, 0x14]];
    assert(deletes == [0, STATUS_RANGE_NOT_FOUND, STATUS_RANGE_NOT_FOUND, 0] && same(list, &state2, 8, 12), "range: RtlDeleteRange exige inicio, fim e dono");
    let split = status("RtlDeleteRange", &[list, 0x1F0, 0x310, 0x11]);
    let state3: [[u64; 6]; 8] = [[0x100, 0x1ff, 0x0, 0x0, 0x0, 0xa], [0x300, 0x3ff, 0x0, 0x0, 0x0, 0xb], [0x500, 0x6ff, 0x0, 0x1, 0x1, 0x3], [0x500, 0x5ff, 0x0, 0x1, 0x0, 0xe], [0x580, 0x6ff, 0x0, 0x1, 0x0, 0xf], [0x5f0, 0x5f8, 0x0, 0x1, 0x0, 0x13], [0x800, 0x8ff, 0x2, 0x0, 0x0, 0x0], [0x900, 0x9ff, 0x0, 0x0, 0x0, 0x14]];
    assert(split == 0 && same(list, &state3, 7, 13), "range: excluir de uma fundida separa as que nao se cruzam e limpa CONFLICT");
    let owners = [status("RtlDeleteOwnersRanges", &[list, 0xF]), status("RtlDeleteOwnersRanges", &[list, 0x99])];
    let state4: [[u64; 6]; 7] = [[0x100, 0x1ff, 0x0, 0x0, 0x0, 0xa], [0x300, 0x3ff, 0x0, 0x0, 0x0, 0xb], [0x500, 0x5ff, 0x0, 0x1, 0x1, 0x2], [0x500, 0x5ff, 0x0, 0x1, 0x0, 0xe], [0x5f0, 0x5f8, 0x0, 0x1, 0x0, 0x13], [0x800, 0x8ff, 0x2, 0x0, 0x0, 0x0], [0x900, 0x9ff, 0x0, 0x0, 0x0, 0x14]];
    assert(owners == [0, 0] && same(list, &state4, 6, 14), "range: RtlDeleteOwnersRanges dentro das fundidas");
    for target in [list, copy, inverted, filled, edges, fresh] {
        let _ = call_export("RtlFreeRangeList", &[target]);
    }
    assert(guest::read64(list) == list && guest::read64(list + 8) == list && guest::read64(list + 0x10) == 0 && guest::read32(list + 0x18) == 14, "range: RtlFreeRangeList esvazia e preserva o carimbo");

    // Bandeira 0x10: UserData é um contador de referências em pool.
    let counted = new_list(scratch + 0x200);
    let counter = pool_allocation::allocate_tagged(1, 8, u32::from_le_bytes(*b"PAtr")).unwrap_or(0);
    guest::write32(counter, 1);
    let first_add = add(counted, 0x10, 0x1F, 0, COUNTED, counter, 1);
    let after_first = guest::read32(counter);
    let merged_add = add(counted, 0x18, 0x28, 0, IF_CONFLICT, 0, 2);
    let after_merge = guest::read32(counter);
    let duplicate = new_list(scratch + 0x220);
    let duplicated = status("RtlCopyRangeList", &[duplicate, counted]);
    let after_copy = guest::read32(counter);
    let deleted = status("RtlDeleteRange", &[counted, 0x10, 0x1F, 1]);
    let after_delete = guest::read32(counter);
    assert(counter != 0 && first_add == 0 && after_first == 1 && merged_add == 0 && after_merge == 1 && duplicated == 0 && after_copy == 2 && deleted == 0 && after_delete == 1 && same(counted, &[[0x18, 0x28, 0, 0, 0, 2]], 1, 3), "range: contador do UserData acompanha copias e exclusoes");
    // A última referência devolve o contador ao pool (ExFreePool).
    let _ = call_export("RtlFreeRangeList", &[duplicate]);
    let _ = call_export("RtlFreeRangeList", &[counted]);
    guest::free_bytes(scratch);
}

fn resource_encoding(assert: Assert) {
    let scratch = guest::alloc_bytes(0x100);
    let (descriptor, out) = (scratch, scratch + 0x80);
    // (tipo, comprimento, início) -> (status, Type, Flags, Start, Length, decodificado).
    let cm: [(u8, u64, u64, u32, u8, u16, u64, u32, u64); 15] = [
        (1, 0x10, 0x1000, 0, 0x1, 0xa5a5, 0x1000, 0x10, 0x10),
        (1, 0x100000000, 0, STATUS_INVALID_PARAMETER, 0xa5, 0xa5a5, 0xa5a5a5a5a5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a50000),
        (3, 0x1000, 0xF0000000, 0, 0x3, 0xa1a5, 0xf0000000, 0x1000, 0x1000),
        (7, 0x1000, 5, 0, 0x3, 0xa1a5, 0x5, 0x1000, 0x1000),
        (3, 0x100000000, 0x1_0000_0000, 0, 0x7, 0xa3a5, 0x100000000, 0x1000000, 0x100000000),
        (3, 0x100000100, 1, 0, 0x7, 0xa3a5, 0x1, 0x1000001, 0x100000100),
        (3, 0x100000001, 2, STATUS_UNSUCCESSFUL, 0xa5, 0xa1a5, 0x2, 0xa5a5a5a5, 0),
        (3, 0x12_3456_7800, 3, 0, 0x7, 0xa3a5, 0x3, 0x12345678, 0x1234567800),
        (3, 0x1_0000_0001_0000, 4, STATUS_UNSUCCESSFUL, 0xa5, 0xa1a5, 0x4, 0xa5a5a5a5, 0),
        (3, 0xFFFF_FFFF_0000, 5, 0, 0x7, 0xa5a5, 0x5, 0xffffffff, 0xffffffff0000),
        (3, 0x1_0000_0000_0000, 6, 0, 0x7, 0xa9a5, 0x6, 0x10000, 0x1000000000000),
        (3, 0x1234_0000_0000, 7, 0, 0x7, 0xa5a5, 0x7, 0x12340000, 0x123400000000),
        (3, 0xFFFF_FFFF_0000_0001, 8, STATUS_UNSUCCESSFUL, 0xa5, 0xa1a5, 0x8, 0xa5a5a5a5, 0),
        (3, M, 9, STATUS_UNSUCCESSFUL, 0xa5, 0xa1a5, 0x9, 0xa5a5a5a5, 0),
        (2, 0x10, 10, STATUS_INVALID_PARAMETER, 0xa5, 0xa5a5, 0xa5a5a5a5a5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a50000),
    ];
    let cm_ok = cm.iter().all(|&(kind, length, start, expected, out_kind, flags, out_start, out_length, decoded)| {
        guest::write_bytes(descriptor, &[0xA5; 0x14]);
        let encoded = status("RtlCmEncodeMemIoResource", &[descriptor, kind as u64, length, start]);
        let fields = (guest::read8(descriptor), guest::read16(descriptor + 2), u64::from_le_bytes(guest::read_bytes(descriptor + 4, 8).try_into().unwrap_or([0; 8])), guest::read32(descriptor + 0xC));
        guest::write64(out, 0x5555);
        let length_back = call_export("RtlCmDecodeMemIoResource", &[descriptor, out]);
        encoded == expected && fields == (out_kind, flags, out_start, out_length) && length_back == Some(decoded) && guest::read64(out) == out_start
    });
    assert(cm_ok, "resource: RtlCmEncodeMemIoResource/RtlCmDecodeMemIoResource nas tres formas grandes");
    let decode_cases: [(u8, u16, u32, u64); 9] = [(1, 0x0E00, 0x10, 0x10), (3, 0x0E00, 0x10, 0x10), (7, 0x200, 0x10, 0x1000), (7, 0x400, 0x10, 0x100000), (7, 0x800, 0x10, 0x1000000000), (7, 0x600, 0x10, 0x1000), (7, 0, 0x10, 0), (2, 0x200, 0x10, 0x1000), (0x81, 0x800, 0xFFFFFFFF, 0xffffffff00000000)];
    let decode_ok = decode_cases.iter().all(|&(kind, flags, length, expected)| {
        guest::write_bytes(descriptor, &[0; 0x14]);
        guest::write8(descriptor, kind);
        guest::write16(descriptor + 2, flags);
        guest::write_bytes(descriptor + 4, &0x1122334455667788u64.to_le_bytes());
        guest::write32(descriptor + 0xC, length);
        call_export("RtlCmDecodeMemIoResource", &[descriptor, 0]) == Some(expected)
    });
    assert(decode_ok, "resource: RtlCmDecodeMemIoResource olha so os tipos 1/3 e as bandeiras");
    // (tipo, comprimento, alinhamento, mínimo, máximo) -> status, Type, Flags,
    // Length, Alignment e o decodificado (comprimento, alinhamento).
    let io: [(u8, u64, u64, u64, u64, u32, u8, u16, u32, u32, u64, u64); 18] = [
        (1, 0x10, 0x1, 0x100, 0x1FF, 0, 0x1, 0xa5a5, 0x10, 0x1, 0x10, 0x1),
        (1, 0x100000000, 1, 0, 0, STATUS_INVALID_PARAMETER, 0xa5, 0xa5a5, 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a50000, 0xa5a5a5a50000),
        (1, 0x10, 0x100000000, 0, 0, STATUS_INVALID_PARAMETER, 0xa5, 0xa5a5, 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a50000, 0xa5a5a5a50000),
        (3, 0x1000, 0x1000, 0, M, 0, 0x3, 0xa1a5, 0x1000, 0x1000, 0x1000, 0x1000),
        (3, 0x100000000, 0x1000, 0x10, 0x20, 0, 0x7, 0xa3a5, 0x1000000, 0x10, 0x100000000, 0x1000),
        (3, 0x100000000, 0x1001, 0, 0, 0, 0x7, 0xa3a5, 0x1000000, 0x1001, 0x100000000, 0x100100),
        (3, 0x100000000, 0x100000000, 0, 0, 0, 0x7, 0xa3a5, 0x1000000, 0x1000000, 0x100000000, 0x100000000),
        (3, 0x1000, 0x100000000, 0, 0, 0, 0x7, 0xa3a5, 0x10, 0x1000000, 0x1000, 0x100000000),
        (3, 0x1000, 0x100000001, 0, 0, STATUS_UNSUCCESSFUL, 0xa5, 0xa1a5, 0xa5a5a5a5, 0xa5a5a5a5, 0, 0),
        (3, 0x100, 0x1_0000_0000_0000, 0, 0, STATUS_UNSUCCESSFUL, 0xa5, 0xa1a5, 0xa5a5a5a5, 0xa5a5a5a5, 0, 0),
        (3, 0x1_0000_0001_0000, 0x10000, 0, 0, STATUS_UNSUCCESSFUL, 0xa5, 0xa1a5, 0xa5a5a5a5, 0xa5a5a5a5, 0, 0),
        (3, 0x1_0000_0001_0000, 0x3, 0, 0, STATUS_UNSUCCESSFUL, 0xa5, 0xa1a5, 0xa5a5a5a5, 0xa5a5a5a5, 0, 0),
        (3, 0x2_0000_0000_0000, 0x1_0000_0000, 0, 0, 0, 0x7, 0xa9a5, 0x20000, 0x1, 0x2000000000000, 0x100000000),
        (3, 0x2_0000_0000_0000, 0x3, 0, 0, 0, 0x7, 0xa9a5, 0x20000, 0x3, 0x2000000000000, 0x300000000),
        (3, 0x2_0000_0000_0000, 0, 0, 0, 0, 0x7, 0xa9a5, 0x20000, 0x0, 0x2000000000000, 0),
        (7, 0x100000000, 0, 0, 0, 0, 0x7, 0xa3a5, 0x1000000, 0x0, 0x100000000, 0),
        (3, M, 1, 0, 0, STATUS_UNSUCCESSFUL, 0xa5, 0xa1a5, 0xa5a5a5a5, 0xa5a5a5a5, 0, 0),
        (5, 1, 1, 0, 0, STATUS_INVALID_PARAMETER, 0xa5, 0xa5a5, 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a50000, 0xa5a5a5a50000),
    ];
    let io_ok = io.iter().all(|&(kind, length, alignment, minimum, maximum, expected, out_kind, flags, out_length, out_alignment, decoded, decoded_alignment)| {
        guest::write_bytes(descriptor, &[0xA5; 0x20]);
        let encoded = status("RtlIoEncodeMemIoResource", &[descriptor, kind as u64, length, alignment, minimum, maximum]);
        let fields = (guest::read8(descriptor + 1), guest::read16(descriptor + 4), guest::read32(descriptor + 8), guest::read32(descriptor + 0xC));
        let stored = (guest::read64(descriptor + 0x10), guest::read64(descriptor + 0x18));
        for slot in 0..3 {
            guest::write64(out + slot * 8, 0x5555);
        }
        let length_back = call_export("RtlIoDecodeMemIoResource", &[descriptor, out, out + 8, out + 16]);
        let addresses_ok = if expected == STATUS_INVALID_PARAMETER { stored == (0xa5a5a5a5a5a5a5a5, 0xa5a5a5a5a5a5a5a5) } else { stored == (minimum, maximum) };
        encoded == expected && fields == (out_kind, flags, out_length, out_alignment) && addresses_ok && length_back == Some(decoded) && guest::read64(out) == decoded_alignment && guest::read64(out + 8) == stored.0 && guest::read64(out + 16) == stored.1
    });
    assert(io_ok, "resource: RtlIoEncodeMemIoResource/RtlIoDecodeMemIoResource com alinhamento dobrado ate caber");
    let closest: [(u64, u32, u64); 13] = [
        (0, 0, 0),
        (0xFFFFFFFF, 0, 0xffffffff),
        (0x100000000, 0, 0x100000000),
        (0x100000001, 0, 0x100000100),
        (0xFFFFFFFF01, 0, 0x10000000000),
        (0xFFFFFFFF00, 0, 0xffffffff00),
        (0xFFFFFFFF0001, 0, 0x1000000000000),
        (0xFFFFFFFF0000, 0, 0xffffffff0000),
        (0x1000000000001, 0, 0x1000100000000),
        (0xFFFF_FFFF_0000_0000, 0, 0xffffffff00000000),
        (0xFFFF_FFFF_0000_0001, STATUS_UNSUCCESSFUL, 0),
        (0xFFFF_FFFE_0000_0001, 0, 0xffffffff00000000),
        (M, STATUS_UNSUCCESSFUL, 0),
    ];
    let closest_ok = closest.iter().all(|&(length, expected, rounded)| {
        guest::write64(out, 0x5555);
        status("RtlFindClosestEncodableLength", &[length, out]) == expected && guest::read64(out) == rounded
    });
    assert(closest_ok, "resource: RtlFindClosestEncodableLength arredonda para a forma seguinte");
    guest::free_bytes(scratch);
}

fn bitmap_copy(assert: Assert) {
    const SOURCE: [u8; 12] = [0x5A, 0xC3, 0x0F, 0xF0, 0x81, 0x7E, 0x33, 0xCC, 0x96, 0x69, 0xAA, 0x55];
    let scratch = guest::alloc_bytes(0x100);
    let (source, destination, source_header, destination_header) = (scratch, scratch + 0x20, scratch + 0x40, scratch + 0x50);
    // (bits da origem, bits do destino, TargetBit) -> os 24 bytes do destino.
    let cases: [(u32, u32, u32, &str); 9] = [
        (0x60, 0xC0, 0, "5ac30ff0817e33cc9669aa55eeeeeeeeeeeeeeeeeeeeeeee"),
        (0x60, 0xC0, 8, "ee5ac30ff0817e33cc9669aa55eeeeeeeeeeeeeeeeeeeeee"),
        (0x60, 0xC0, 3, "d61a7e800ff49b61b64c53adeaeeeeeeeeeeeeeeeeeeeeee"),
        (0x60, 0xC0, 37, "eeeeeeee4e6bf8013ed06f86d9324db5eaeeeeeeeeeeeeee"),
        (0x13, 0xC0, 5, "4e6bf8eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        (0x60, 0x40, 20, "eeeeae35fc001fe8eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        (0x60, 0xC0, 0xC0, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        (5, 0xC0, 31, "eeeeee6eedeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        (0x60, 0x70, 0x6D, "eeeeeeeeeeeeeeeeeeeeeeeeee4eeeeeeeeeeeeeeeeeeeee"),
    ];
    let hex = |bytes: &[u8]| bytes.iter().map(|byte| alloc::format!("{:02x}", byte)).collect::<alloc::string::String>();
    let header = |address: u64, size: u32, buffer: u64| {
        guest::write32(address, size);
        guest::write64(address + 8, buffer);
    };
    let copies_ok = cases.iter().all(|&(source_bits, destination_bits, target, expected)| {
        guest::write_bytes(source, &[0; 0x20]);
        guest::write_bytes(source, &SOURCE);
        guest::write_bytes(destination, &[0xEE; 0x20]);
        header(source_header, source_bits, source);
        header(destination_header, destination_bits, destination);
        let _ = call_export("RtlCopyBitMap", &[source_header, destination_header, target as u64]);
        hex(&guest::read_bytes(destination, 0x18)) == expected
    });
    // Mesmo buffer: os 64 bits da origem vão para o bit 12.
    guest::write_bytes(source, &[0; 0x20]);
    guest::write_bytes(source, &SOURCE);
    header(source_header, 0x40, source);
    header(destination_header, 0xC0, source);
    let _ = call_export("RtlCopyBitMap", &[source_header, destination_header, 12]);
    let overlap = hex(&guest::read_bytes(source, 0x18)) == "5aa335fc001fe837c36caa55000000000000000000000000";
    assert(copies_ok && overlap, "bitmap: RtlCopyBitMap com TargetBit, limites dos dois mapas e sobreposicao");
    guest::free_bytes(scratch);
}

fn crt_conversion(assert: Assert) {
    let scratch = guest::alloc_bytes(0x100);
    let (text, end) = (scratch, scratch + 0xF0);
    // (texto, base) -> (valor, deslocamento do *EndPtr).
    let cases: [(&[u8], u64, u64, u64); 18] = [
        (b"  123", 10, 0x7b, 5),
        (b"0x1F", 0, 0x1f, 4),
        (b"0x1F", 16, 0x1f, 4),
        (b"017", 0, 0xf, 3),
        (b"-5", 10, 0xfffffffffffffffb, 2),
        (b"+42xyz", 0, 0x2a, 3),
        (b"zz", 36, 0x50f, 2),
        (b"18446744073709551615", 10, M, 20),
        (b"18446744073709551616", 10, M, 20),
        (b"-18446744073709551616", 10, 0x1, 21),
        (b"", 10, 0, 0),
        (b"abc", 10, 0, 0),
        (b"\t\n 0X", 0, 0, 0),
        (b"7", 1, 0, 0),
        (b"7", 37, 0, 0),
        (b"1010", 2, 0xa, 4),
        (b"0x", 16, 0, 0),
        (b"FFFFFFFFFFFFFFFFF", 16, M, 17),
    ];
    let conversions_ok = cases.iter().all(|&(source, base, value, offset)| {
        let mut bytes = source.to_vec();
        bytes.push(0);
        guest::write_bytes(text, &bytes);
        guest::write64(end, 0x5555);
        call_export("_strtoui64", &[text, end, base]) == Some(value) && guest::read64(end) == text + offset
    });
    guest::write_bytes(text, b"99999999999999999999x\0");
    assert(conversions_ok && call_export("_strtoui64", &[text, 0, 10]) == Some(M), "crt: _strtoui64 com brancos, sinais, prefixos, estouro e base invalida");
    // strtok_s sobre ",,alpha, beta;;gamma," com ", ;".
    let (delimiters, context) = (scratch + 0x80, scratch + 0xE8);
    guest::write_bytes(text, b",,alpha, beta;;gamma,\0");
    guest::write_bytes(delimiters, b", ;\0");
    guest::write64(context, 0);
    let mut tokens = Vec::new();
    let mut token = call_export("strtok_s", &[text, delimiters, context]).unwrap_or(0);
    while token != 0 {
        tokens.push((token - text, guest::read64(context) - text));
        token = call_export("strtok_s", &[0, delimiters, context]).unwrap_or(0);
    }
    let last_context = guest::read64(context) - text;
    let rewritten = guest::read_bytes(text, 22) == b",,alpha\0 beta\0;gamma\0\0";
    guest::write64(context, 0);
    let invalid = [call_export("strtok_s", &[0, delimiters, context]), call_export("strtok_s", &[text, 0, context]), call_export("strtok_s", &[text, delimiters, 0])];
    guest::write_bytes(text, b";;;\0");
    let only_delimiters = call_export("strtok_s", &[text, delimiters, context]) == Some(0) && guest::read64(context) == text + 3;
    assert(tokens == [(2, 8), (9, 14), (15, 21)] && last_context == 21 && rewritten && invalid == [Some(0); 3] && only_delimiters, "crt: strtok_s corta os tokens no lugar e guarda o contexto");
    guest::free_bytes(scratch);
}

pub fn run(assert: Assert) {
    range_lists(assert);
    resource_encoding(assert);
    bitmap_copy(assert);
    crt_conversion(assert);
}
