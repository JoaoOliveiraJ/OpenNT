//! Autotestes das tabelas de átomos, do heap de modo kernel, das páginas de
//! código e das rotinas Rtl de estado do sistema (fase 6), e do
//! RtlGetThreadLangIdByIndex sobre a TEB de uma thread de usuário (fase 7).
//!
//! Os valores esperados vêm do comportamento do ntoskrnl 19041 (as
//! instruções de cada rotina) e, para as páginas de código, das tabelas
//! c_1252.nls e l_intl.nls reais, calculados fora do kernel.

use alloc::vec::Vec;

use super::phase6::call_export;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::mm::guest_memory as guest;

type Assert = fn(bool, &str);

const STATUS_SUCCESS: u32 = 0;
const STATUS_WAS_LOCKED: u32 = 0x4000_0019;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_MESSAGE_NOT_FOUND: u32 = 0xC000_0109;
const STATUS_INTERNAL_ERROR: u32 = 0xC000_00E5;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;

fn status(name: &str, arguments: &[u64]) -> u32 {
    call_export(name, arguments).map_or(u32::MAX, |value| value as u32)
}

fn cell<T: Copy + 'static>(address: u64) -> &'static Field<T> {
    // SAFETY: células do teste em memória do kernel.
    unsafe { Field::<T>::at(address) }
}

/// Texto UTF-16 com terminador em memória do kernel.
fn wide(scratch: u64, text: &str) -> u64 {
    let mut bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    bytes.extend_from_slice(&[0, 0]);
    guest::write_bytes(scratch, &bytes);
    scratch
}

fn read_units(address: u64, count: usize) -> Vec<u16> {
    (0..count).map(|index| guest::read16(address + index as u64 * 2)).collect()
}

fn atom_tables(assert: Assert) {
    let scratch = guest::alloc_bytes(0x1000);
    let (handle, atom, name) = (scratch, scratch + 0x10, scratch + 0x100);
    let (reference_count, pins, length, buffer) = (scratch + 0x20, scratch + 0x24, scratch + 0x28, scratch + 0x800);
    // Criação: 37 baldes por padrão, a assinatura e um handle já preenchido.
    let created = status("RtlCreateAtomTable", &[0, handle]);
    let table = guest::read64(handle);
    // SAFETY: a tabela recém-criada.
    let fields = unsafe { crate::ntos::inc::types::extra_rtl::RtlAtomTable::at(table) };
    let again = status("RtlCreateAtomTable", &[5, handle]);
    assert(created == STATUS_SUCCESS && table != 0 && fields.signature.get() == 0x6D6F_7441 && fields.number_of_buckets.get() == 37 && fields.reference_count.get() == 1 && again == STATUS_SUCCESS && guest::read64(handle) == table, "atom: RtlCreateAtomTable com 37 baldes, assinatura 'Atom' e handle preenchido intocado");
    // Strings: 0xC001 em diante, sem distinção de caixa ASCII.
    let first = status("RtlAddAtomToAtomTable", &[table, wide(name, "Hello"), atom]);
    let hello = guest::read16(atom);
    let same = status("RtlAddAtomToAtomTable", &[table, wide(name, "hELLO"), atom]);
    let same_atom = guest::read16(atom);
    let world_status = status("RtlAddAtomToAtomTable", &[table, wide(name, "World"), atom]);
    let world = guest::read16(atom);
    assert(first == 0 && hello == 0xC001 && same == 0 && same_atom == 0xC001 && world_status == 0 && world == 0xC002, "atom: atomos de string a partir de 0xC001 e nomes sem distincao de caixa");
    // Inteiros: MAKEINTATOM e "#n"; 0 e 0xC000 são inválidos.
    let integer = status("RtlAddAtomToAtomTable", &[table, 0x1234, atom]);
    let integer_atom = guest::read16(atom);
    let decimal = status("RtlAddAtomToAtomTable", &[table, wide(name, "#100"), atom]);
    let decimal_atom = guest::read16(atom);
    guest::write16(atom, 0x5555);
    let zero = status("RtlAddAtomToAtomTable", &[table, 0, atom]);
    let zero_atom = guest::read16(atom);
    let large = status("RtlAddAtomToAtomTable", &[table, wide(name, "#49152"), atom]);
    let large_atom = guest::read16(atom);
    let mixed = status("RtlAddAtomToAtomTable", &[table, wide(name, "#12a"), atom]);
    let mixed_atom = guest::read16(atom);
    assert(integer == 0 && integer_atom == 0x1234 && decimal == 0 && decimal_atom == 100 && zero == STATUS_INVALID_PARAMETER && zero_atom == 0 && large == STATUS_INVALID_PARAMETER && large_atom == 0 && mixed == 0 && mixed_atom == 0xC003, "atom: atomos inteiros (MAKEINTATOM e #n), 0/0xC000 invalidos e #12a como string");
    // Nome vazio e o limite de 255 caracteres.
    let empty = status("RtlAddAtomToAtomTable", &[table, wide(name, ""), atom]);
    let long: alloc::string::String = core::iter::repeat_n('x', 256).collect();
    let too_long = status("RtlAddAtomToAtomTable", &[table, wide(name, &long), atom]);
    let longest = status("RtlAddAtomToAtomTable", &[table, wide(name, &long[..255]), atom]);
    assert(empty == STATUS_OBJECT_NAME_INVALID && too_long == STATUS_INVALID_PARAMETER && longest == 0 && guest::read16(atom) == 0xC004, "atom: nome vazio invalido e limite de 255 caracteres");
    // Lookup não soma referência; nome ausente.
    let found = status("RtlLookupAtomInAtomTable", &[table, wide(name, "WORLD"), atom]);
    let found_atom = guest::read16(atom);
    let missing = status("RtlLookupAtomInAtomTable", &[table, wide(name, "Nope"), atom]);
    let looked_integer = status("RtlLookupAtomInAtomTable", &[table, 7, atom]);
    assert(found == 0 && found_atom == world && missing == STATUS_OBJECT_NAME_NOT_FOUND && looked_integer == 0 && guest::read16(atom) == 7, "atom: RtlLookupAtomInAtomTable acha sem distincao de caixa e recusa nome ausente");
    // Query: contagem, Flags e o nome com as regras de truncamento.
    guest::write32(length, 64);
    let queried = status("RtlQueryAtomInAtomTable", &[table, hello as u64, reference_count, pins, buffer, length]);
    let queried_name = read_units(buffer, 6);
    let (queried_count, queried_pins, queried_length) = (cell::<u32>(reference_count).get(), cell::<u32>(pins).get(), guest::read32(length));
    guest::write32(length, 6);
    let truncated = status("RtlQueryAtomInAtomTable", &[table, hello as u64, 0, 0, buffer, length]);
    let truncated_length = guest::read32(length);
    let truncated_name = read_units(buffer, 3);
    guest::write32(length, 1);
    let small = status("RtlQueryAtomInAtomTable", &[table, hello as u64, 0, 0, buffer, length]);
    let small_length = guest::read32(length);
    guest::write32(length, 64);
    let integer_query = status("RtlQueryAtomInAtomTable", &[table, 0x1234, reference_count, pins, buffer, length]);
    let integer_name = read_units(buffer, 6);
    let queried_zero = status("RtlQueryAtomInAtomTable", &[table, 0, 0, 0, 0, 0]);
    assert(queried == 0 && queried_count == 2 && queried_pins == 0 && queried_length == 10 && queried_name == [b'H' as u16, b'e' as u16, b'l' as u16, b'l' as u16, b'o' as u16, 0], "atom: RtlQueryAtomInAtomTable devolve contagem, flags e o nome original");
    assert(truncated == 0 && truncated_length == 4 && truncated_name == [b'H' as u16, b'e' as u16, 0] && small == STATUS_BUFFER_TOO_SMALL && small_length == 10, "atom: nome truncado a capacidade-2 com sucesso e capacidade menor que 2 = BUFFER_TOO_SMALL");
    assert(integer_query == 0 && cell::<u32>(reference_count).get() == 1 && cell::<u32>(pins).get() == 1 && integer_name == [b'#' as u16, b'4' as u16, b'6' as u16, b'6' as u16, b'0' as u16, 0] && queried_zero == STATUS_INVALID_PARAMETER, "atom: atomo inteiro consulta como #valor com 1/1 e o atomo 0 e invalido");
    // Delete: referências, liberação e o índice devolvido primeiro.
    let delete_one = status("RtlDeleteAtomFromAtomTable", &[table, hello as u64]);
    let after_one = status("RtlQueryAtomInAtomTable", &[table, hello as u64, reference_count, 0, 0, 0]);
    let count_after_one = cell::<u32>(reference_count).get();
    let delete_two = status("RtlDeleteAtomFromAtomTable", &[table, hello as u64]);
    let gone = status("RtlQueryAtomInAtomTable", &[table, hello as u64, 0, 0, 0, 0]);
    let gone_lookup = status("RtlLookupAtomInAtomTable", &[table, wide(name, "Hello"), atom]);
    let reused = status("RtlAddAtomToAtomTable", &[table, wide(name, "Again"), atom]);
    assert(delete_one == 0 && after_one == 0 && count_after_one == 1 && delete_two == 0 && gone == STATUS_INVALID_HANDLE && gone_lookup == STATUS_OBJECT_NAME_NOT_FOUND && reused == 0 && guest::read16(atom) == 0xC001, "atom: Delete solta uma referencia por vez, a ultima libera e o indice volta primeiro");
    // Pin: a entrada fixada não sai.
    let pinned = status("RtlPinAtomInAtomTable", &[table, world as u64]);
    let locked = status("RtlDeleteAtomFromAtomTable", &[table, world as u64]);
    let pin_query = status("RtlQueryAtomInAtomTable", &[table, world as u64, reference_count, pins, 0, 0]);
    let pin_flags = cell::<u32>(pins).get();
    let integer_delete = status("RtlDeleteAtomFromAtomTable", &[table, 0x1234]);
    let zero_delete = status("RtlDeleteAtomFromAtomTable", &[table, 0]);
    let unused_delete = status("RtlDeleteAtomFromAtomTable", &[table, 0xC0FF]);
    let pin_zero = status("RtlPinAtomInAtomTable", &[table, 0]);
    assert(pinned == 0 && locked == STATUS_WAS_LOCKED && pin_query == 0 && pin_flags == 1 && integer_delete == 0 && zero_delete == STATUS_INVALID_HANDLE && unused_delete == STATUS_INVALID_HANDLE && pin_zero == STATUS_INVALID_HANDLE, "atom: Pin fixa a entrada (Delete = WAS_LOCKED) e os atomos 0 e livres sao handles invalidos");
    // Ex: o bit 2 do Flags vai para a referência; tabela Ex com 5 baldes.
    let ex_status = status("RtlAddAtomToAtomTableEx", &[table, wide(name, "Flagged"), atom, 2]);
    let flagged = guest::read16(atom);
    let flag_query = status("RtlQueryAtomInAtomTable", &[table, flagged as u64, 0, pins, 0, 0]);
    let flag_bits = cell::<u32>(pins).get();
    guest::write64(handle, 0);
    let ex_created = status("RtlCreateAtomTableEx", &[5, 1, handle]);
    let second = guest::read64(handle);
    // SAFETY: a segunda tabela recém-criada.
    let second_fields = unsafe { crate::ntos::inc::types::extra_rtl::RtlAtomTable::at(second) };
    assert(ex_status == 0 && flag_query == 0 && flag_bits == 2 && ex_created == 0 && second_fields.number_of_buckets.get() == 5 && second_fields.flags.get() == 1, "atom: RtlAddAtomToAtomTableEx guarda o bit 2 e RtlCreateAtomTableEx os baldes e o Flags");
    // RtlGetIntegerAtom.
    guest::write16(atom, 0);
    let text = status("RtlGetIntegerAtom", &[wide(name, "#123"), atom]) & 0xFF;
    let text_value = guest::read16(atom);
    let make = status("RtlGetIntegerAtom", &[5, atom]) & 0xFF;
    let make_value = guest::read16(atom);
    let string_atom = status("RtlGetIntegerAtom", &[0xC001, atom]) & 0xFF;
    let plain = status("RtlGetIntegerAtom", &[wide(name, "abc"), atom]) & 0xFF;
    let hash_only = status("RtlGetIntegerAtom", &[wide(name, "#"), atom]) & 0xFF;
    let zero_value = status("RtlGetIntegerAtom", &[0, atom]) & 0xFF;
    assert(text == 1 && text_value == 123 && make == 1 && make_value == 5 && string_atom == 0 && plain == 0 && hash_only == 0 && zero_value == 1 && guest::read16(atom) == 0xC000, "atom: RtlGetIntegerAtom com #n, MAKEINTATOM, atomo de string, texto e o 0 que vira 0xC000");
    // Destroy e uma tabela sem assinatura.
    let destroyed = status("RtlDestroyAtomTable", &[table]);
    let destroyed_second = status("RtlDestroyAtomTable", &[second]);
    let fake = guest::alloc_bytes(0x40);
    let unsigned = status("RtlAddAtomToAtomTable", &[fake, wide(name, "x"), atom]);
    let null_table = status("RtlLookupAtomInAtomTable", &[0, wide(name, "x"), atom]);
    assert(destroyed == 0 && destroyed_second == 0 && unsigned == STATUS_INVALID_PARAMETER && null_table == STATUS_INVALID_PARAMETER, "atom: RtlDestroyAtomTable e tabela nula ou sem assinatura = INVALID_PARAMETER");
    guest::free_bytes(fake);
    guest::free_bytes(scratch);
}

/// CommitRoutine de teste (MS x64): conta as chamadas e guarda o último
/// pedido (endereço e tamanho) em `record`; devolve STATUS_SUCCESS.
fn commit_routine(record: u64) -> u64 {
    let code = guest::alloc_bytes(64);
    let mut bytes = alloc::vec![0x48, 0xB8];
    bytes.extend_from_slice(&record.to_le_bytes());
    // lock inc qword [rax]; mov r9,[rdx]; mov [rax+8],r9; mov r9,[r8]; mov [rax+16],r9; xor eax,eax; ret
    bytes.extend_from_slice(&[0xF0, 0x48, 0xFF, 0x00, 0x4C, 0x8B, 0x0A, 0x4C, 0x89, 0x48, 0x08, 0x4D, 0x8B, 0x08, 0x4C, 0x89, 0x48, 0x10, 0x31, 0xC0, 0xC3]);
    guest::write_bytes(code, &bytes);
    code
}

/// RTL_HEAP_PARAMETERS com InitialCommit/InitialReserve/CommitRoutine.
fn heap_parameters(commit: u64, reserve: u64, routine: u64) -> u64 {
    let parameters = guest::alloc_bytes(0x60);
    // SAFETY: o bloco recém-alocado do tamanho da estrutura.
    let fields = unsafe { crate::ntos::inc::types::extra_rtl::RtlHeapParameters::at(parameters) };
    fields.length.set(0x60);
    fields.initial_commit.set(commit);
    fields.initial_reserve.set(reserve);
    fields.commit_routine.set(routine);
    parameters
}

fn fixed_heap(assert: Assert) {
    use crate::ntos::rtl::heap;
    let record = guest::alloc_bytes(32);
    let routine = commit_routine(record);
    let region = guest::alloc_aligned(0x1_0000, 0x1000, true);
    guest::write_bytes(region + 0x1000, &alloc::vec![0xABu8; 0xF000]);
    let parameters = heap_parameters(0x2000, 0x1_0000, routine);
    // As recusas do caminho fixo.
    let with_lock = status("RtlCreateHeap", &[0x309, region, 0x1_0000, 0x2000, region, parameters]);
    let growable = status("RtlCreateHeap", &[0x30B, region, 0x1_0000, 0x2000, 0, parameters]);
    let no_base = status("RtlCreateHeap", &[0x309, 0, 0x1_0000, 0x2000, 0, parameters]);
    let inverted = heap_parameters(0x2_0000, 0x1_0000, routine);
    let bad_sizes = status("RtlCreateHeap", &[0x309, region, 0x1_0000, 0x2000, 0, inverted]);
    assert(with_lock == 0 && growable == 0 && no_base == 0 && bad_sizes == 0, "heap: o heap fixo recusa Lock, HEAP_GROWABLE, base nula e InitialCommit > InitialReserve");
    // O desktop heap do win32k: 0x309 sobre a memória do chamador.
    let handle = call_export("RtlCreateHeap", &[0x309, region, 0x1_0000, 0x2000, 0, parameters]).unwrap_or(0);
    let described = heap::describe(handle);
    assert(handle == region && guest::read32(region + 0x10) == 0xCCDD_CCDD && described.is_some_and(|(fixed, _, committed, _)| fixed && committed == 0x1000) && guest::read64(record) == 0, "heap: RtlCreateHeap(0x309) devolve o HeapBase, so o cabecalho conta como confirmado e a rotina nao e chamada");
    let first = call_export("RtlAllocateHeap", &[handle, 0, 100]).unwrap_or(0);
    let committed_call = guest::read64(record) == 1 && guest::read64(record + 8) == region + 0x1000 && guest::read64(record + 16) == 0x1000;
    let zeroed = guest::read_bytes(first, 100).iter().all(|&byte| byte == 0);
    assert(first > region + 0x1000 && first < region + 0x1_0000 && first % 16 == 0 && committed_call && zeroed, "heap: a primeira alocacao confirma a pagina seguinte pela CommitRoutine e sai zerada (HEAP_ZERO_MEMORY da criacao)");
    let too_big = call_export("RtlAllocateHeap", &[handle, 4, 0x2_0001]);
    assert(too_big == Some(0), "heap: o heap fixo devolve NULL acima de 128 KB, sem excecao mesmo com HEAP_GENERATE_EXCEPTIONS");
    let freed = status("RtlFreeHeap", &[handle, 0, first]) & 0xFF;
    let freed_again = status("RtlFreeHeap", &[handle, 0, first]) & 0xFF;
    let freed_null = status("RtlFreeHeap", &[handle, 0, 0]) & 0xFF;
    let freed_bogus = status("RtlFreeHeap", &[handle, 0, region + 0x8008]) & 0xFF;
    let reused = call_export("RtlAllocateHeap", &[handle, 0, 100]).unwrap_or(0);
    assert(freed == 1 && freed_again == 0 && freed_null == 1 && freed_bogus == 0 && reused == first, "heap: RtlFreeHeap aceita NULL, recusa bloco livre ou estranho e o bloco liberado volta");
    // Esgota a reserva: 0xF000 bytes depois do cabeçalho, três blocos de 16 KB.
    let _ = status("RtlFreeHeap", &[handle, 0, reused]);
    let blocks: Vec<u64> = (0..4).map(|_| call_export("RtlAllocateHeap", &[handle, 0, 0x4000]).unwrap_or(0)).collect();
    assert(blocks[0] != 0 && blocks[1] != 0 && blocks[2] != 0 && blocks[3] == 0 && guest::read64(record + 8) + guest::read64(record + 16) <= region + 0x1_0000, "heap: a reserva limita o heap fixo e as paginas novas ficam dentro dela");
    let destroyed = status("RtlDestroyHeap", &[handle]);
    let after = call_export("RtlAllocateHeap", &[handle, 0, 16]);
    assert(destroyed == 0 && after == Some(0) && guest::read32(region + 0x10) == 0xCCDD_CCDD, "heap: RtlDestroyHeap do heap fixo devolve NULL e nao toca a memoria do chamador");
    // CommitRoutine que falha: a alocação devolve NULL.
    let failing = guest::alloc_bytes(16);
    guest::write_bytes(failing, &[0xB8, 0x17, 0x00, 0x00, 0xC0, 0xC3]);
    let failing_parameters = heap_parameters(0x1000, 0x8000, failing);
    let second_region = guest::alloc_aligned(0x8000, 0x1000, true);
    let failing_heap = call_export("RtlCreateHeap", &[0x309, second_region, 0x8000, 0x1000, 0, failing_parameters]).unwrap_or(0);
    let refused = call_export("RtlAllocateHeap", &[failing_heap, 0, 32]);
    assert(failing_heap == second_region && refused == Some(0), "heap: sem pagina confirmada pela CommitRoutine a alocacao devolve NULL");
    let _ = status("RtlDestroyHeap", &[failing_heap]);
    for block in [record, routine, region, parameters, inverted, failing, failing_parameters, second_region] {
        guest::free_bytes(block);
    }
}

fn nt_heap(assert: Assert) {
    use crate::ntos::rtl::heap;
    // HEAP_CREATE_HARDENED sem segment heap e HEAP_NO_SERIALIZE com Lock.
    let lock = guest::alloc_bytes(0x80);
    let _ = crate::ntos::ex::resource::initialize(lock);
    let hardened = status("RtlCreateHeap", &[0x200, 0, 0, 0, 0, 0]);
    let unserialized_lock = status("RtlCreateHeap", &[0x1, 0, 0, 0, lock, 0]);
    assert(hardened == 0 && unserialized_lock == 0, "heap: HEAP_CREATE_HARDENED sozinho e HEAP_NO_SERIALIZE com Lock devolvem NULL");
    // Heap crescível no espaço do processo corrente (sem serialização: o
    // ERESOURCE interno ficaria na memória de usuário do System).
    let handle = call_export("RtlCreateHeap", &[0x3, 0, 0, 0, 0, 0]).unwrap_or(0);
    let header_ok = handle != 0 && guest::read32(handle + 0x10) == 0xFFEE_FFEE && guest::read32(handle + 0x98) == 0xEEFF_EEFF && guest::read32(handle + 0x70) == 0x3 && guest::read32(handle + 0x74) == 0x1;
    let committed = heap::describe(handle).map_or(0, |(_, _, committed, _)| committed);
    assert(header_ok && committed == 0x2000, "heap: RtlCreateHeap(HEAP_GROWABLE) reserva e confirma 8 KB no processo, com as assinaturas e os flags do HEAP");
    let small = call_export("RtlAllocateHeap", &[handle, 8, 0x30]).unwrap_or(0);
    let small_zero = small != 0 && guest::read_bytes(small, 0x30).iter().all(|&byte| byte == 0);
    let big = call_export("RtlAllocateHeap", &[handle, 0, 0x20_0000]).unwrap_or(0);
    let big_writable = big != 0 && big % 16 == 0 && guest::try_write64(big + 0x1F_FFF0, 0x55).is_ok();
    let big_freed = status("RtlFreeHeap", &[handle, 0, big]) & 0xFF;
    assert(small_zero && small % 16 == 0 && big_writable && big_freed == 1, "heap: HEAP_ZERO_MEMORY zera o pedido e um bloco acima do VirtualMemoryThreshold vem de reserva propria");
    let chunks: Vec<u64> = (0..20).map(|_| call_export("RtlAllocateHeap", &[handle, 0, 0x1_0000]).unwrap_or(0)).collect();
    let segments = heap::describe(handle).map_or(0, |(_, _, _, segments)| segments);
    assert(chunks.iter().all(|&chunk| chunk != 0) && segments >= 2, "heap: o heap crescivel ganha segmento novo quando a reserva acaba");
    assert(status("RtlDestroyHeap", &[handle]) == 0, "heap: RtlDestroyHeap devolve NULL e libera as reservas");
    // Lock do chamador e base com CommitRoutine (InitialCommit zerado).
    let record = guest::alloc_bytes(32);
    let routine = commit_routine(record);
    let region = guest::alloc_aligned(0x8000, 0x1000, true);
    guest::write_bytes(region, &alloc::vec![0xCDu8; 0x8000]);
    let parameters = heap_parameters(0x1000, 0x8000, routine);
    let based = call_export("RtlCreateHeap", &[0x0, region, 0, 0, lock, parameters]).unwrap_or(0);
    let force = heap::describe(based).map_or(u32::MAX, |(_, force, _, _)| force);
    let initial_zero = guest::read_bytes(region + 0x800, 0x800).iter().all(|&byte| byte == 0);
    let block = call_export("RtlAllocateHeap", &[based, 0, 0x2000]).unwrap_or(0);
    assert(based == region && force == 0 && initial_zero && block > region && guest::read64(record) >= 1 && guest::read64(record + 8) == region + 0x1000, "heap: com HeapBase e CommitRoutine o commit inicial e zerado e as paginas seguintes vem da rotina, sob o Lock do chamador");
    // Serializado sem Lock: o ERESOURCE interno em HeapBase + 0x2C0.
    let internal_region = guest::alloc_aligned(0x8000, 0x1000, true);
    let internal = call_export("RtlCreateHeap", &[0x0, internal_region, 0, 0, 0, parameters]).unwrap_or(0);
    let internal_block = call_export("RtlAllocateHeap", &[internal, 0, 0x40]).unwrap_or(0);
    let internal_freed = status("RtlFreeHeap", &[internal, 0, internal_block]) & 0xFF;
    assert(internal == internal_region && internal_block > internal_region + 0x2C0 + 0x68 && internal_freed == 1 && status("RtlDestroyHeap", &[internal]) == 0, "heap: heap serializado sem Lock usa o ERESOURCE do proprio cabecalho");
    guest::free_bytes(internal_region);
    let growable_based = call_export("RtlCreateHeap", &[0x2, region, 0, 0, 0, parameters]);
    assert(growable_based == Some(0) && status("RtlDestroyHeap", &[based]) == 0, "heap: HEAP_GROWABLE com CommitRoutine e recusado");
    let _ = crate::ntos::ex::resource::delete(lock);
    for block in [lock, record, routine, region, parameters] {
        guest::free_bytes(block);
    }
}

/// Imagem com SEH: F(0x1300) chama o import 0 com os argumentos recebidos e
/// devolve 0x55; o handler (0x1330) desenrola até o bloco de tratamento
/// (0x1314), que devolve o ExceptionCode. G(0x1380) faz a mesma chamada,
/// mas o handler dela (0x13A0) continua a exceção.
fn seh_image(import: &[u8]) -> Option<crate::ntos::mm::pe_loader::PeImage> {
    use crate::ntos::mm::pe_loader::{self as loader, LoadOptions};
    let mut bytes = super::phase6::ntoskrnl_importer(import);
    for byte in &mut bytes[0x4442..0x4480] {
        *byte = 0;
    }
    bytes[0x4442..0x444E].copy_from_slice(b"RtlUnwindEx\0");
    let rel = |from_next: usize, to: usize| ((to as i64 - from_next as i64) as i32).to_le_bytes();
    let body = |start: usize| {
        let mut code = alloc::vec![0x48, 0x83, 0xEC, 0x28, 0xFF, 0x15];
        code.extend_from_slice(&rel(start + 10, 0x4200));
        code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28, 0xB8, 0x55, 0x00, 0x00, 0x00, 0xC3, 0x48, 0x83, 0xC4, 0x28, 0xC3]);
        code
    };
    let f = body(0x1300);
    bytes[0x1300..0x1300 + f.len()].copy_from_slice(&f);
    let g = body(0x1380);
    bytes[0x1380..0x1380 + g.len()].copy_from_slice(&g);
    // Handler de F: RtlUnwindEx(frame, 0x1314, record, record->ExceptionCode, NULL, NULL).
    let mut handler = alloc::vec![0x48, 0x83, 0xEC, 0x38, 0x48, 0x89, 0xC8, 0x48, 0x89, 0xD1, 0x48, 0x8D, 0x15];
    handler.extend_from_slice(&rel(0x1341, 0x1314));
    handler.extend_from_slice(&[0x49, 0x89, 0xC0, 0x44, 0x8B, 0x08, 0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0, 0x48, 0xC7, 0x44, 0x24, 0x28, 0, 0, 0, 0, 0xFF, 0x15]);
    handler.extend_from_slice(&rel(0x135F, 0x4210));
    handler.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]);
    bytes[0x1330..0x1330 + handler.len()].copy_from_slice(&handler);
    // Handler de G: ExceptionContinueExecution.
    bytes[0x13A0..0x13A3].copy_from_slice(&[0x31, 0xC0, 0xC3]);
    for (info, handler) in [(0x1400usize, 0x1330u32), (0x1410, 0x13A0)] {
        bytes[info..info + 4].copy_from_slice(&[0x09, 0x04, 0x01, 0x00]);
        bytes[info + 4..info + 6].copy_from_slice(&(4u16 | (2 << 8) | (4 << 12)).to_le_bytes());
        bytes[info + 8..info + 12].copy_from_slice(&handler.to_le_bytes());
    }
    for (entry, (start, end, info)) in [(0x1300u32, 0x1318u32, 0x1400u32), (0x1380, 0x1398, 0x1410)].into_iter().enumerate() {
        let at = 0x1500 + entry * 12;
        bytes[at..at + 4].copy_from_slice(&start.to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&end.to_le_bytes());
        bytes[at + 8..at + 12].copy_from_slice(&info.to_le_bytes());
    }
    loader::load(bytes, &LoadOptions { image_name: Some(alloc::string::String::from("opennt-w1-seh.sys")), ..Default::default() }).ok()
}

fn raised_exceptions(assert: Assert) {
    use crate::ntos::rtl::{native_context, unwind};
    // RtlRaiseException: o handler recebe o registro do chamador; o de G continua.
    let Some(mut image) = seh_image(b"RtlRaiseException\0") else {
        assert(false, "raise: imagem de teste carregada");
        return;
    };
    let base = image.image_base;
    let added = unwind::add_function_table(base + 0x1500, 2, base);
    let record = guest::alloc_bytes(0x98);
    guest::write32(record, 0xE000_1234);
    let unwound = native_context::call(base + 0x1300, &[record], 0);
    let address = guest::read64(record + 0x10);
    let continued = native_context::call(base + 0x1380, &[record], 0);
    assert(added.is_ok_and(|added| added == 1) && unwound.as_ref().is_ok_and(|value| *value as u32 == 0xE000_1234) && address > base + 0x1300 && address < base + 0x1318 && continued.as_ref().is_ok_and(|value| *value as u32 == 0x55), "raise: RtlRaiseException entrega o registro (ExceptionAddress = retorno do chamador) e volta quando o handler continua");
    let _ = unwind::delete_function_table(base + 0x1500);
    let _ = image.release();
    guest::free_bytes(record);
    // RtlAllocateHeap com HEAP_GENERATE_EXCEPTIONS levanta STATUS_NO_MEMORY.
    let Some(mut image) = seh_image(b"RtlAllocateHeap\0") else {
        assert(false, "raise: imagem do heap carregada");
        return;
    };
    let base = image.image_base;
    let added = unwind::add_function_table(base + 0x1500, 2, base);
    let heap = call_export("RtlCreateHeap", &[0x5, 0, 0x1_0000, 0x1_0000, 0, 0]).unwrap_or(0);
    let raised = native_context::call(base + 0x1300, &[heap, 0, 0x2_0000], 0);
    let continued = native_context::call(base + 0x1380, &[heap, 0, 0x2_0000], 0);
    let plain = call_export("RtlAllocateHeap", &[heap, 0, 0x10]).unwrap_or(0);
    assert(heap != 0 && added.is_ok_and(|added| added == 1) && raised.as_ref().is_ok_and(|value| *value as u32 == STATUS_NO_MEMORY) && continued.as_ref().is_ok_and(|value| *value as u32 == 0x55) && plain != 0, "raise: HEAP_GENERATE_EXCEPTIONS do ForceFlags levanta STATUS_NO_MEMORY e o handler pode continuar");
    let _ = status("RtlDestroyHeap", &[heap]);
    let _ = unwind::delete_function_table(base + 0x1500);
    let _ = image.release();
}

fn code_pages(assert: Assert) {
    use crate::ntos::init::exports;
    use crate::ntos::mm::pe_loader::ResolvedImport;
    use crate::ntos::rtl::nls_configuration;
    let data = |name: &str| match exports::lookup("ntoskrnl.exe", name) {
        Some(ResolvedImport::Address { address, .. }) => Some(address),
        _ => None,
    };
    let (ansi, oem, tag) = (data("NlsAnsiCodePage"), data("NlsOemCodePage"), data("NlsMbCodePageTag"));
    assert(ansi.is_some_and(|cell| guest::read16(cell) as u32 == nls_configuration::ANSI_CODE_PAGE) && oem.is_some_and(|cell| guest::read16(cell) as u32 == crate::ntos::rtl::oem_code_page::OEM_CODE_PAGE) && tag.is_some_and(|cell| guest::read8(cell) == 0), "nls: NlsAnsiCodePage = 1252, NlsOemCodePage = 437 e NlsMbCodePageTag = FALSE");
    let scratch = guest::alloc_bytes(0x1000);
    let defaults = status("RtlGetDefaultCodePage", &[scratch, scratch + 2]);
    assert(defaults != u32::MAX && guest::read16(scratch) == 1252 && guest::read16(scratch + 2) == 437, "nls: RtlGetDefaultCodePage devolve as duas paginas");
    // RtlUpcaseUnicodeToMultiByteN: valores das tabelas reais (c_1252 + l_intl).
    let units: [u16; 8] = [0x61, 0xE9, 0x20AC, 0xFF, 0x7A, 0x0101, 0xB5, 0x3042];
    let source = scratch + 0x100;
    guest::write_bytes(source, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    let (output, written) = (scratch + 0x200, scratch + 0x300);
    let upcased = status("RtlUpcaseUnicodeToMultiByteN", &[output, 16, written, source, 16]);
    let short = status("RtlUpcaseUnicodeToMultiByteN", &[output + 0x40, 3, written + 4, source, 16]);
    assert(upcased == 0 && guest::read32(written) == 8 && guest::read_bytes(output, 8) == [0x41, 0xC9, 0x80, 0x9F, 0x5A, 0x41, 0xB5, 0x3F] && short == STATUS_BUFFER_OVERFLOW && guest::read32(written + 4) == 3, "nls: RtlUpcaseUnicodeToMultiByteN passa pela pagina, sobe com NLS_UPCASE e avisa o que nao coube");
    let sized = status("RtlMultiByteToUnicodeSize", &[written, output, 5]);
    assert(sized == 0 && guest::read32(written) == 10, "nls: RtlMultiByteToUnicodeSize em pagina SBCS = 2 por byte");
    // RtlIntegerToChar.
    let text = scratch + 0x400;
    guest::write_bytes(text, &[0x77; 16]);
    let decimal = status("RtlIntegerToChar", &[123, 10, 8, text]);
    let decimal_text = guest::read_bytes(text, 4);
    guest::write_bytes(text, &[0x77; 16]);
    let padded = status("RtlIntegerToChar", &[0xBEEF, 16, (-6i32) as u32 as u64, text]);
    let padded_text = guest::read_bytes(text, 7);
    let base = status("RtlIntegerToChar", &[5, 3, 8, text]);
    let overflow = status("RtlIntegerToChar", &[12345, 10, 3, text]);
    guest::write_bytes(text, &[0x77; 16]);
    let binary = status("RtlIntegerToChar", &[255, 2, 9, text]);
    assert(decimal == 0 && decimal_text == *b"123\0" && padded == 0 && padded_text == *b"00BEEF\x77" && base == STATUS_INVALID_PARAMETER && overflow == STATUS_BUFFER_OVERFLOW && binary == 0 && guest::read_bytes(text, 9) == *b"11111111\0", "nls: RtlIntegerToChar com base, preenchimento negativo, terminador e estouro");
    guest::free_bytes(scratch);
}

/// Tabela DBCS sintética no formato c_<página>.nls: página 9999, inicial
/// 0x81, 0x81 0x40 <-> U+3042.
fn synthetic_dbcs_table() -> u64 {
    const WIDE: u64 = 784;
    let table = guest::alloc_bytes(WIDE * 2 + 0x2_0000);
    let set = |index: u64, value: u16| guest::write16(table + index * 2, value);
    set(0, 13);
    set(1, 9999);
    set(2, 2);
    set(3, 0x3F);
    set(4, 0x3F);
    set(5, 0x3F);
    set(6, 0x3F);
    guest::write8(table + 0xE, 0x81);
    guest::write8(table + 0xF, 0x81);
    set(13, (WIDE - 13 - 1) as u16);
    for byte in 0..0x80u64 {
        set(14 + byte, byte as u16);
    }
    set(270, 0);
    set(271, 1);
    // DBCSOffsets: o inicial 0x81 aponta a tabela de segundos bytes (256).
    set(272 + 0x81, 256);
    set(272 + 256 + 0x40, 0x3042);
    for unit in 0..0x80u64 {
        set(WIDE + unit, unit as u16);
    }
    set(WIDE + 0x3042, 0x8140);
    table
}

fn custom_code_pages(assert: Assert) {
    let info = guest::alloc_bytes(0x40);
    let scratch = guest::alloc_bytes(0x400);
    // SAFETY: o CPTABLEINFO do teste.
    let fields = unsafe { crate::ntos::inc::types::extra_rtl::CpTableInfo::at(info) };
    // A tabela c_1252.nls real.
    let file = crate::drivers::fs::volume_files::lookup_volume_file("C:\\Windows\\System32\\c_1252.nls");
    let bytes = file.and_then(|file| file.read_at(0, file.size()).ok()).unwrap_or_default();
    let table = guest::alloc_bytes(bytes.len() as u64 + 16);
    guest::write_bytes(table, &bytes);
    let _ = status("RtlInitCodePageTable", &[table, info]);
    assert(!bytes.is_empty() && fields.code_page.get() == 1252 && fields.maximum_character_size.get() == 1 && fields.dbcs_code_page.get() == 0 && fields.multi_byte_table.get() == table + 28 && fields.dbcs_offsets.get() == 0 && fields.wide_char_table.get() == table + 546, "nls: RtlInitCodePageTable sobre a c_1252.nls real");
    let (input, output, written) = (scratch, scratch + 0x100, scratch + 0x200);
    guest::write_bytes(input, &[0x41, 0x80, 0xE9]);
    let to_unicode = status("RtlCustomCPToUnicodeN", &[info, output, 16, written, input, 3]);
    let converted = read_units(output, 3);
    let to_custom = status("RtlUnicodeToCustomCPN", &[info, output + 0x40, 16, written + 4, output, 6]);
    let short = status("RtlCustomCPToUnicodeN", &[info, output, 4, written + 8, input, 3]);
    assert(to_unicode == 0 && guest::read32(written) == 6 && converted == [0x41, 0x20AC, 0xE9] && to_custom == 0 && guest::read32(written + 4) == 3 && guest::read_bytes(output + 0x40, 3) == [0x41, 0x80, 0xE9] && short == STATUS_BUFFER_OVERFLOW && guest::read32(written + 8) == 4, "nls: RtlCustomCPToUnicodeN/RtlUnicodeToCustomCPN pela c_1252 e o estouro do destino");
    // DBCS sintética.
    let dbcs = synthetic_dbcs_table();
    let _ = status("RtlInitCodePageTable", &[dbcs, info]);
    assert(fields.code_page.get() == 9999 && fields.dbcs_code_page.get() == 1 && fields.lead_byte[0].get() == 0x81 && fields.dbcs_ranges.get() == dbcs + 271 * 2 && fields.dbcs_offsets.get() == dbcs + 272 * 2 && fields.wide_char_table.get() == dbcs + 784 * 2, "nls: RtlInitCodePageTable de uma tabela DBCS");
    guest::write_bytes(input, &[0x41, 0x81, 0x40, 0x42]);
    let pairs = status("RtlCustomCPToUnicodeN", &[info, output, 16, written, input, 4]);
    let pairs_units = read_units(output, 3);
    let lone = status("RtlCustomCPToUnicodeN", &[info, output + 0x40, 16, written + 4, input, 2]);
    let lone_units = read_units(output + 0x40, 2);
    guest::write_bytes(scratch + 0x300, &[0x41, 0x00, 0x42, 0x30, 0x42, 0x00]);
    let back = status("RtlUnicodeToCustomCPN", &[info, output + 0x80, 16, written + 8, scratch + 0x300, 6]);
    let tight = status("RtlUnicodeToCustomCPN", &[info, output + 0xC0, 2, written + 12, scratch + 0x300, 4]);
    assert(pairs == 0 && guest::read32(written) == 6 && pairs_units == [0x41, 0x3042, 0x42] && lone == 0 && guest::read32(written + 4) == 4 && lone_units == [0x41, 0], "nls: RtlCustomCPToUnicodeN DBCS com par e inicial isolado no fim");
    assert(back == 0 && guest::read32(written + 8) == 4 && guest::read_bytes(output + 0x80, 4) == [0x41, 0x81, 0x40, 0x42] && tight == STATUS_BUFFER_OVERFLOW && guest::read32(written + 12) == 1, "nls: RtlUnicodeToCustomCPN DBCS grava o par e para quando ele nao cabe");
    // Pseudo-tabela UTF-8 (TableBase NULL).
    let _ = status("RtlInitCodePageTable", &[0, info]);
    guest::write_bytes(input, &[0xC3, 0xA9]);
    let utf8 = status("RtlCustomCPToUnicodeN", &[info, output, 16, written, input, 2]);
    let utf8_back = status("RtlUnicodeToCustomCPN", &[info, output + 0x40, 16, written + 4, output, 2]);
    assert(fields.code_page.get() == 65001 && fields.maximum_character_size.get() == 4 && fields.uni_default_char.get() == 0xFFFD && utf8 == 0 && guest::read16(output) == 0xE9 && utf8_back == 0 && guest::read_bytes(output + 0x40, 2) == [0xC3, 0xA9], "nls: a pseudo-tabela UTF-8 converte pelo RtlUTF8ToUnicodeN/RtlUnicodeToUTF8N");
    for block in [info, scratch, table, dbcs] {
        guest::free_bytes(block);
    }
}

fn system_state(assert: Assert) {
    use crate::ntos::mm::shared_user_data;
    use crate::ntos::rtl::shared_data;
    let scratch = guest::alloc_bytes(0x100);
    assert(status("RtlAreAllAccessesGranted", &[0x1F, 0x3]) & 0xFF == 1 && status("RtlAreAllAccessesGranted", &[0x1, 0x3]) & 0xFF == 0 && status("RtlAreAnyAccessesGranted", &[0x1, 0x3]) & 0xFF == 1 && status("RtlAreAnyAccessesGranted", &[0x4, 0x3]) & 0xFF == 0, "rtl: RtlAreAllAccessesGranted e RtlAreAnyAccessesGranted");
    let previous = shared_data::set_nt_global_flag(0x40_0000);
    let flag = status("RtlGetNtGlobalFlags", &[]);
    shared_data::set_nt_global_flag(previous);
    assert(flag == 0x40_0000, "rtl: RtlGetNtGlobalFlags devolve NtGlobalFlag");
    let Some(shared) = shared_user_data::data() else {
        assert(false, "rtl: KUSER_SHARED_DATA publicada");
        return;
    };
    let saved = shared.shared_data_flags.get();
    shared.set_dbg_elevation_enabled(1);
    shared.set_dbg_virt_enabled(0);
    shared.set_dbg_installer_detect_enabled(1);
    let elevation = status("RtlQueryElevationFlags", &[scratch]);
    let elevation_flags = guest::read32(scratch);
    shared.shared_data_flags.set(saved);
    assert(elevation == 0 && elevation_flags == 5, "rtl: RtlQueryElevationFlags le os bits de elevacao da KUSER_SHARED_DATA");
    let (console, foreground) = (shared.active_console_id.get(), shared.console_session_foreground_process_id.get());
    let _ = status("RtlSetActiveConsoleId", &[7]);
    let _ = status("RtlSetConsoleSessionForegroundProcessId", &[0x1234]);
    let written = shared.active_console_id.get() == 7 && shared.console_session_foreground_process_id.get() == 0x1234;
    shared.active_console_id.set(console);
    shared.console_session_foreground_process_id.set(foreground);
    assert(written && status("RtlGetCurrentServiceSessionId", &[]) == 0, "rtl: RtlSetActiveConsoleId/RtlSetConsoleSessionForegroundProcessId gravam a KUSER_SHARED_DATA e o host tem sessao de servico 0");
    // RtlCapabilityCheckForSingleSessionSku.
    let name = scratch + 0x40;
    let text = wide(scratch + 0x60, "lpacCom");
    guest::write16(name, 14);
    guest::write16(name + 2, 16);
    guest::write64(name + 8, text);
    let null_output = status("RtlCapabilityCheckForSingleSessionSku", &[0, name, 0]);
    let saved = shared.shared_data_flags.get();
    shared.set_dbg_multi_session_sku(1);
    guest::write8(scratch + 0x20, 0xFF);
    let multi = status("RtlCapabilityCheckForSingleSessionSku", &[0, name, scratch + 0x20]);
    let multi_value = guest::read8(scratch + 0x20);
    shared.shared_data_flags.set(saved);
    let single = status("RtlCapabilityCheckForSingleSessionSku", &[0, name, scratch + 0x20]);
    let single_value = guest::read8(scratch + 0x20);
    let direct = status("RtlCapabilityCheck", &[0, name, scratch + 0x21]);
    assert(null_output == STATUS_INVALID_PARAMETER && multi == 0 && multi_value == 0 && single == direct && single_value == guest::read8(scratch + 0x21), "rtl: RtlCapabilityCheckForSingleSessionSku recusa saida nula, responde FALSE em SKU multissessao e senao e o RtlCapabilityCheck");
    // vDbgPrintEx com va_list.
    let format = scratch + 0xA0;
    guest::write_bytes(format, b"[w1] vDbgPrintEx %d\n\0");
    let arguments = scratch + 0xE0;
    guest::write64(arguments, 42);
    assert(call_export("vDbgPrintEx", &[0, 0, format, arguments]) == Some(0), "rtl: vDbgPrintEx formata pela va_list e devolve STATUS_SUCCESS");
    guest::free_bytes(scratch);
}

/// sqrtf pelo corpo nativo publicado e pela rotina soft-float da tabela.
fn crt_sqrtf(assert: Assert) {
    use crate::hal::amd64::native_call;
    use crate::ntos::init::exports;
    use crate::ntos::mm::pe_loader::ResolvedImport;
    let Some(ResolvedImport::Address { address, .. }) = exports::lookup("ntoskrnl.exe", "sqrtf") else {
        assert(false, "sqrtf: o export resolve para o corpo nativo");
        return;
    };
    // movd xmm0, ecx; call rdx; movd eax, xmm0; ret
    let caller = guest::alloc_bytes(16);
    guest::write_bytes(caller, &[0x66, 0x0F, 0x6E, 0xC1, 0xFF, 0xD2, 0x66, 0x0F, 0x7E, 0xC0, 0xC3]);
    let native = |bits: u32| native_call::call(caller, &[bits as u64, address]) as u32;
    let fixed = native(0x4080_0000) == 0x4000_0000 && native(0x4000_0000) == 0x3FB5_04F3 && native(0xBF80_0000) == 0xFFC0_0000 && native(0x8000_0000) == 0x8000_0000 && native(0x7F80_0000) == 0x7F80_0000;
    // A rotina soft-float confere com o SQRTSS em uma amostra ampla.
    let mut value = 0x0000_0001u32;
    let mut matches = true;
    for _ in 0..256 {
        matches &= crate::ntos::rtl::math::sqrtf_bits(value) == native(value);
        value = value.wrapping_mul(0x9E37_79B9).wrapping_add(0x7F4A_7C15);
    }
    assert(fixed && matches, "sqrtf: o corpo nativo e a rotina soft-float dao o resultado do SQRTSS");
    guest::free_bytes(caller);
}

/// Tabela de mensagens na fixture MAPPED (RT_MESSAGETABLE, 1, 0x409).
fn messages(assert: Assert) {
    use super::resource_search_fixtures as fixtures;
    let options = crate::ntos::mm::kernel_pool::AllocateOptions { tag: 0x7352_7354, zero: true, ..Default::default() };
    let Ok(image) = crate::ntos::mm::kernel_pool::allocate(0x4000, options) else {
        assert(false, "msg: imagem de teste alocada");
        return;
    };
    for &(offset, value) in fixtures::MAPPED.words {
        guest::write32(image + offset as u64, value);
    }
    // Tipo 11 no lugar de 16; dados de 0x2C bytes em 0x1800.
    guest::write32(image + 0x1010, 11);
    guest::write32(image + 0x104C, 0x2C);
    let data = image + 0x1800;
    guest::write_bytes(data, &[0u8; 0x40]);
    guest::write32(data, 1);
    guest::write32(data + 4, 0x100);
    guest::write32(data + 8, 0x110);
    guest::write32(data + 12, 0x10);
    guest::write_bytes(data + 0x10, &[8, 0, 0, 0, b'A', b'B', 0, 0]);
    guest::write_bytes(data + 0x18, &[12, 0, 0, 0, b'C', b'D', b'E', b'F', b'G', 0, 0, 0]);
    guest::write_bytes(data + 0x24, &[8, 0, 1, 0, b'H', 0, 0, 0]);
    let entry = guest::alloc_bytes(16);
    let first = status("RtlFindMessage", &[image, 11, 0x409, 0x100, entry]);
    let first_entry = guest::read64(entry);
    let third = status("RtlFindMessage", &[image, 11, 0x409, 0x102, entry]);
    let third_entry = guest::read64(entry);
    let neutral = status("RtlFindMessage", &[image, 11, 0, 0x101, entry]);
    let neutral_entry = guest::read64(entry);
    let past_end = status("RtlFindMessage", &[image, 11, 0x409, 0x103, entry]);
    let no_block = status("RtlFindMessage", &[image, 11, 0x409, 0x111, entry]);
    let no_table = status("RtlFindMessage", &[image, 12, 0x409, 0x100, entry]);
    assert(first == 0 && first_entry == data + 0x10 && third == 0 && third_entry == data + 0x24 && neutral == 0 && neutral_entry == data + 0x18 && past_end == STATUS_MESSAGE_NOT_FOUND && no_block == STATUS_MESSAGE_NOT_FOUND && no_table != 0, "msg: RtlFindMessage acha a entrada pelo bloco, pula pelo Length e para no fim do recurso");
    // LdrResFindResourceDirectory: o diretório do tipo e o do nome.
    let directory = guest::alloc_bytes(16);
    let by_type = status("LdrResFindResourceDirectory", &[image, 11, 0, directory, 0, 0, 0]);
    let type_directory = guest::read64(directory);
    let by_name = status("LdrResFindResourceDirectory", &[image, 11, 1, directory, 0, 0, 0]);
    let name_directory = guest::read64(directory);
    let bad_flags = status("LdrResFindResourceDirectory", &[image, 11, 0, directory, 0, 0, 0x400]);
    assert(by_type == 0 && type_directory == image + 0x1018 && by_name == 0 && name_directory == image + 0x1030 && bad_flags == STATUS_INVALID_PARAMETER, "msg: LdrResFindResourceDirectory devolve o diretorio do tipo e do nome e recusa 0x400/0x800");
    guest::free_bytes(entry);
    guest::free_bytes(directory);
    let _ = crate::ntos::mm::kernel_pool::free(image, None);
}

/// Fase 6.
pub fn run(assert: Assert) {
    atom_tables(assert);
    fixed_heap(assert);
    nt_heap(assert);
    raised_exceptions(assert);
    code_pages(assert);
    custom_code_pages(assert);
    system_state(assert);
    crt_sqrtf(assert);
    messages(assert);
    // A thread do System não tem TEB: nada a achar.
    let cells = guest::alloc_bytes(16);
    guest::write64(cells, u64::MAX);
    let system = status("RtlGetThreadLangIdByIndex", &[0, 0, cells, cells + 4]);
    let flags = status("RtlGetThreadLangIdByIndex", &[1, 0, cells, 0]);
    let null = status("RtlGetThreadLangIdByIndex", &[0, 0, 0, 0]);
    assert(system == STATUS_NOT_FOUND && guest::read32(cells) == 0 && guest::read32(cells + 4) == 0 && flags == STATUS_INVALID_PARAMETER && null == STATUS_INVALID_PARAMETER, "lang: sem TEB nao ha idioma (STATUS_NOT_FOUND) e Flags/LangId sao validados");
    guest::free_bytes(cells);
}

/// Fase 7: os idiomas preferidos na TEB de uma thread de usuário.
pub fn run_phase7(assert: Assert) {
    use crate::ntos::inc::types::Kthread;
    use crate::ntos::ps::user::memory;
    let outcome = super::multiprocess::identity::with_test_process("w1-lang", None, |test| {
        let Ok(teb) = memory::map_user_region(0x2000) else { return false };
        // SAFETY: a KTHREAD da thread de teste, viva durante o corpo.
        let thread = unsafe { Kthread::at(test.thread) };
        let (saved_teb, saved_system) = (thread.teb.get(), thread.system_thread());
        thread.teb.set(teb);
        thread.set_system_thread(0);
        let (block, entries) = (teb + 0x1000, teb + 0x1100);
        let _ = guest::try_write64(teb + 0x17D0, block);
        let _ = guest::try_write16(block + 4, 2);
        let _ = guest::try_write64(block + 0x18, entries);
        let _ = guest::try_write32(entries, 1);
        let _ = guest::try_write16(entries + 4, 0x409);
        let _ = guest::try_write32(entries + 6, 1);
        let _ = guest::try_write16(entries + 10, 0x416);
        let cells = guest::alloc_bytes(16);
        let query = |index: u64| (status("RtlGetThreadLangIdByIndex", &[0, index, cells, cells + 4]), guest::read32(cells), guest::read32(cells + 4));
        let first = query(0);
        let second = query(1);
        let beyond = query(2);
        let _ = guest::try_write32(entries + 6, 2);
        let invalid = query(1);
        let _ = guest::try_write64(teb + 0x17D0, block + 1);
        let misaligned = status("RtlGetThreadLangIdByIndex", &[0, 0, cells, cells + 4]);
        let _ = guest::try_write64(teb + 0x17D0, 0);
        let empty = query(0);
        guest::free_bytes(cells);
        thread.teb.set(saved_teb);
        thread.set_system_thread(saved_system);
        if let Some(region) = memory::find_region(teb) {
            memory::release_private_region(&region);
        }
        first == (0, 0x409, 2) && second == (0, 0x416, 2) && beyond == (STATUS_NOT_FOUND, 0, 2) && invalid == (STATUS_INTERNAL_ERROR, 0, 2) && misaligned == STATUS_DATATYPE_MISALIGNMENT && empty == (STATUS_NOT_FOUND, 0, 0)
    });
    assert(outcome == Some(true), "lang: RtlGetThreadLangIdByIndex le os idiomas preferidos da TEB, valida a entrada e o alinhamento");
}
