//! Autotestes das tabelas de funções dinâmicas (`rtl/dynamic_function_table.rs`)
//! num processo de teste, pelo NtSetInformationProcess(-1,
//! ProcessDynamicFunctionTableInformation) de modo usuário que o
//! RtlAddGrowableFunctionTable e o RtlDeleteGrowableFunctionTable da ntdll
//! fazem, contra o ntoskrnl 19041:
//!
//! - o registro abre o EPROCESS.InvertedFunctionTable com a entrada 0 zerada
//!   e guarda a tabela, a base, o tamanho da faixa e EntryCount * 12; as
//!   faixas ficam ordenadas pela base; uma faixa que se sobrepõe dá
//!   STATUS_CONFLICTING_ADDRESSES e uma que só encosta entra; o vetor cresce
//!   de 10 em 10 entradas;
//! - a busca do RtlpLookupUserFunctionTable acha a faixa e lê da tabela de
//!   usuário o FunctionTable e o EntryCount correntes;
//! - a retirada pela mesma base e o mesmo tamanho; de novo,
//!   STATUS_BAD_FUNCTION_TABLE; o vetor fica com só a entrada 0;
//! - recusas: MaximumAddress abaixo da base, faixa acima de 4 GB e EntryCount
//!   acima de 0x15555555 (STATUS_INTEGER_OVERFLOW); handle diferente de -1
//!   (STATUS_INVALID_PARAMETER); tamanho diferente de 16
//!   (STATUS_INFO_LENGTH_MISMATCH); buffer fora do alinhamento 8 e tabela
//!   fora do alinhamento 4 (STATUS_DATATYPE_MISALIGNMENT); tabela fora do
//!   espaço de usuário (STATUS_ACCESS_VIOLATION);
//! - a classe não tem consulta (STATUS_INVALID_INFO_CLASS).
//!
//! Sem a classe, o NtSetInformationProcess responde STATUS_INVALID_INFO_CLASS
//! e o RtlAddGrowableFunctionTable falha.

use crate::ntos::inc::types::{DynamicFunctionTable, Eprocess, InvertedFunctionTable, InvertedFunctionTableEntry, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user::{memory, state};
use crate::ntos::rtl::dynamic_function_table::{self, UserFunctionTable};
use crate::ntos::test::multiprocess::identity::with_test_process;

type Assert = fn(bool, &str);

const CLASS: u64 = 53;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
const STATUS_INTEGER_OVERFLOW: u32 = 0xC000_0095;
const STATUS_BAD_FUNCTION_TABLE: u32 = 0xC000_00FF;
/// A faixa da primeira tabela e o começo das faixas do crescimento.
const BASE: u64 = 0x1_0000_0000;
const SPAN: u64 = 0x1_0000;

pub fn run(assert: Assert) {
    let ran = with_test_process("jit.exe", None, |test| run_in(assert, test.process));
    assert(ran.is_some(), "dynfunc: processo de usuario do teste");
}

fn run_in(assert: Assert, process: u64) {
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "dynfunc: memoria de usuario");
        return;
    };
    // O PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION, três DYNAMIC_FUNCTION_TABLE
    // e um vetor de RUNTIME_FUNCTION.
    let (information, first, second, third, functions, rsp) = (block, block + 0x100, block + 0x200, block + 0x300, block + 0x800, block + 0x1000);
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map(|handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1)).unwrap_or(1);
    let set_at = |handle: u64, buffer: u64, table: u64, remove: bool, length: u64| {
        guest::write64(buffer, table);
        guest::write64(buffer + 8, remove as u64);
        call("NtSetInformationProcess", handle, CLASS, buffer, length)
    };
    let set = |table: u64, remove: bool| set_at(u64::MAX, information, table, remove, 16);
    let describe = |table: u64, base: u64, maximum: u64, count: u32| {
        // SAFETY: tabela na memória de usuário do teste.
        let target = unsafe { DynamicFunctionTable::at(table) };
        target.function_table.set(functions);
        target.minimum_address.set(base);
        target.maximum_address.set(maximum);
        target.base_address.set(base);
        target.entry_count.set(count);
    };
    // SAFETY: o EPROCESS do teste, vivo durante o corpo.
    let eprocess = unsafe { Eprocess::at(process) };
    let vector = || eprocess.inverted_function_table.get();
    let size = || if vector() == 0 { 0 } else { unsafe { InvertedFunctionTable::at(vector()) }.current_size.get() };
    let capacity = || if vector() == 0 { 0 } else { unsafe { InvertedFunctionTable::at(vector()) }.maximum_size.get() };
    let entry = |index: usize| {
        // SAFETY: vetor do processo de teste, índice abaixo de CurrentSize.
        let entry = unsafe { &InvertedFunctionTableEntry::array_at(vector() + 0x10, index + 1)[index] };
        (entry.dynamic_table.get(), entry.image_base.get(), entry.size_of_image.get(), entry.size_of_table.get())
    };

    // Registro, entrada 0 zerada e a busca da faixa.
    describe(first, BASE, BASE + SPAN, 3);
    let inserted = vector() == 0 && set(first, false) == 0 && vector() != 0 && size() == 2 && capacity() == 10 && entry(0) == (0, 0, 0, 0) && entry(1) == (first, BASE, SPAN as u32, 36);
    assert(inserted, "dynfunc: o registro abre o vetor com a entrada 0 zerada e a faixa da tabela");
    let found = dynamic_function_table::lookup(BASE + 0x8000).ok().flatten();
    let expected = UserFunctionTable { function_table: functions, image_base: BASE, size_of_image: SPAN as u32, size_of_table: 36 };
    describe(first, BASE, BASE + SPAN, 5);
    let grown = dynamic_function_table::lookup(BASE + SPAN - 1).ok().flatten();
    let outside = dynamic_function_table::lookup(BASE + SPAN).ok().flatten();
    assert(found == Some(expected) && grown == Some(UserFunctionTable { size_of_table: 60, ..expected }) && outside.is_none() && entry(1).3 == 36, "dynfunc: a busca acha a faixa e le o EntryCount corrente da tabela de usuario");

    // Sobreposição, faixa encostada e a ordem pela base.
    describe(second, BASE + 0x8000, BASE + SPAN + 0x8000, 1);
    let overlapping = set(second, false) == STATUS_CONFLICTING_ADDRESSES;
    describe(second, BASE - 0x8000, BASE + 0x10, 1);
    let overlapping_before = set(second, false) == STATUS_CONFLICTING_ADDRESSES;
    describe(second, BASE + SPAN, BASE + 2 * SPAN, 1);
    let adjacent = set(second, false) == 0;
    describe(third, BASE - SPAN, BASE, 2);
    let before = set(third, false) == 0;
    let ordered = size() == 4 && entry(1) == (third, BASE - SPAN, SPAN as u32, 24) && entry(2).1 == BASE && entry(3) == (second, BASE + SPAN, SPAN as u32, 12);
    assert(overlapping && overlapping_before && adjacent && before && ordered, "dynfunc: sobreposicao recusada, faixa encostada aceita e vetor ordenado pela base");

    // Crescimento de 10 em 10: oito faixas a mais passam de 10 entradas.
    let previous = vector();
    let mut filled = true;
    for index in 0..8u64 {
        let base = BASE + (4 + index) * SPAN;
        describe(third, base, base + SPAN, 1);
        filled &= set(third, false) == 0;
    }
    assert(filled && size() == 12 && capacity() == 20 && vector() != previous && entry(1).1 == BASE - SPAN && entry(11).1 == BASE + 11 * SPAN, "dynfunc: o vetor cheio cresce 10 entradas e conserva as faixas");
    let mut emptied = true;
    for index in 0..8u64 {
        let base = BASE + (4 + index) * SPAN;
        describe(third, base, base + SPAN, 1);
        emptied &= set(third, true) == 0;
    }
    assert(emptied && size() == 4, "dynfunc: as faixas do crescimento saem pela base e pelo tamanho");

    // Retirada, retirada repetida e o vetor que fica.
    describe(first, BASE, BASE + SPAN, 5);
    let removed = set(first, true) == 0 && size() == 3 && entry(2).1 == BASE + SPAN;
    let again = set(first, true) == STATUS_BAD_FUNCTION_TABLE;
    describe(second, BASE + SPAN, BASE + SPAN + 0x1000, 1);
    let wrong_size = set(second, true) == STATUS_BAD_FUNCTION_TABLE;
    describe(second, BASE + SPAN, BASE + 2 * SPAN, 1);
    describe(third, BASE - SPAN, BASE, 2);
    let rest = set(second, true) == 0 && set(third, true) == 0 && size() == 1 && vector() != 0 && dynamic_function_table::lookup(BASE).ok().flatten().is_none();
    assert(removed && again && wrong_size && rest, "dynfunc: retirada pela base e pelo tamanho, repetida da STATUS_BAD_FUNCTION_TABLE e o vetor fica");

    // Recusas.
    describe(first, BASE + SPAN, BASE, 1);
    let below = set(first, false) == STATUS_INTEGER_OVERFLOW && set(first, true) == STATUS_INTEGER_OVERFLOW;
    describe(first, BASE, BASE + 0x1_0000_0000, 1);
    let wide = set(first, false) == STATUS_INTEGER_OVERFLOW && set(first, true) == STATUS_INTEGER_OVERFLOW;
    describe(first, BASE, BASE + SPAN, 0x1555_5556);
    let entries = set(first, false) == STATUS_INTEGER_OVERFLOW;
    assert(below && wide && entries && size() == 1, "dynfunc: faixa invertida, faixa acima de 4 GB e EntryCount grande dao STATUS_INTEGER_OVERFLOW");
    describe(first, BASE, BASE + SPAN, 1);
    let handle = set_at(0, information, first, false, 16) == STATUS_INVALID_PARAMETER && set_at(4, information, first, false, 16) == STATUS_INVALID_PARAMETER;
    let length = set_at(u64::MAX, information, first, false, 8) == STATUS_INFO_LENGTH_MISMATCH && set_at(u64::MAX, information, first, false, 24) == STATUS_INFO_LENGTH_MISMATCH;
    let misaligned = set_at(u64::MAX, information + 4, first, false, 16) == STATUS_DATATYPE_MISALIGNMENT && set(first + 2, false) == STATUS_DATATYPE_MISALIGNMENT;
    let kernel = set(0xFFFF_8000_0000_0000, false) == STATUS_ACCESS_VIOLATION && set(0, false) == STATUS_ACCESS_VIOLATION;
    let query = call("NtQueryInformationProcess", u64::MAX, CLASS, information, 16) == STATUS_INVALID_INFO_CLASS;
    assert(handle && length && misaligned && kernel && query && size() == 1, "dynfunc: handle, tamanho, alinhamento, tabela fora do usuario e a consulta inexistente");

    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}
