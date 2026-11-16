//! Autoteste dos exports de Rtl e da CRT que eram os últimos imports de
//! drivers reais: memchr, memcmp, memmove_s, islower, isxdigit, iswspace,
//! strncat, wcsncat_s, qsort_s, _ui64tow_s, as strings OEM em maiúsculas,
//! RtlIpv4/6StringToAddressA, RtlRbReplaceNode,
//! RtlSetControlSecurityDescriptor, RtlIsCloudFilesPlaceholder,
//! LdrFindResource_U e LdrAccessResource.
//!
//! Os vetores foram calculados executando as rotinas do ntoskrnl 19041 real
//! num emulador (as strings OEM com a c_437.nls e a l_intl.nls da máquina
//! carregadas nas tabelas NLS dele; a busca de recursos sobre a mesma
//! fixture MAPPED dos testes do LdrRes*). Cada teste chama o export pelo
//! trampolim nativo (ABI MS x64).

use alloc::vec::Vec;

use crate::ntos::inc::{types as nt, NtStruct};
use crate::ntos::mm::guest_memory as guest;

type Assert = fn(bool, &str);

const UNTOUCHED: u8 = 0x55;

fn call(name: &str, arguments: &[u64]) -> u64 {
    super::phase6::call_export(name, arguments).unwrap_or(0xDEAD_DEAD_DEAD_DEAD)
}

fn status(name: &str, arguments: &[u64]) -> u32 {
    call(name, arguments) as u32
}

fn at<T: NtStruct>(address: u64) -> &'static T {
    // SAFETY: blocos alocados pelo teste com o tamanho do tipo ou objetos vivos.
    unsafe { T::at(address) }
}

/// Bloco novo preenchido com `fill`.
fn block(size: u64, fill: u8) -> u64 {
    let pointer = guest::alloc_bytes(size);
    guest::write_bytes(pointer, &alloc::vec![fill; size as usize]);
    pointer
}

fn bytes_of(text: &[u8]) -> u64 {
    let pointer = block(text.len() as u64 + 16, UNTOUCHED);
    guest::write_bytes(pointer, text);
    pointer
}

fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn wide(text: &str) -> u64 {
    let mut bytes: Vec<u8> = units(text).iter().flat_map(|unit| unit.to_le_bytes()).collect();
    bytes.extend_from_slice(&[0, 0]);
    bytes_of(&bytes)
}

fn read(address: u64, length: usize) -> Vec<u8> {
    guest::read_bytes(address, length)
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap_or(0)).collect()
}

fn unicode_string(text: &str, length: Option<u16>) -> u64 {
    let buffer = wide(text);
    let string = block(nt::UnicodeString::SIZE, 0);
    let length = length.unwrap_or(units(text).len() as u16 * 2);
    at::<nt::UnicodeString>(string).length.set(length);
    at::<nt::UnicodeString>(string).maximum_length.set(length + 2);
    at::<nt::UnicodeString>(string).buffer.set(buffer);
    string
}

// ---- CRT: memória e classes de caractere ----------------------------------------

fn crt_memory_ctype(assert: Assert) {
    let text = bytes_of(b"abcdefgh\0");
    assert(
        call("memchr", &[text, b'd' as u64, 8]) == text + 3 && call("memchr", &[text, b'z' as u64, 8]) == 0 && call("memchr", &[text, b'a' as u64, 0]) == 0 && call("memchr", &[text, 0x165, 8]) == text + 4,
        "crt: memchr acha o byte baixo de C em Count bytes e devolve NULL sem ele",
    );
    let (left, right) = (bytes_of(b"abcdefghijklmnopq"), bytes_of(b"abcdefghijklmnopz"));
    let compare = |a: u64, b: u64, count: u64| call("memcmp", &[a, b, count]) as i32;
    assert(compare(left, right, 17) == -1 && compare(right, left, 17) == 1 && compare(left, right, 16) == 0 && compare(bytes_of(&[1]), bytes_of(&[0xFF]), 1) == -1, "crt: memcmp sem sinal devolve -1/0/1");

    let destination = block(16, UNTOUCHED);
    let source = bytes_of(b"XYZW");
    let ok = status("memmove_s", &[destination, 8, source, 4]);
    assert(ok == 0 && read(destination, 8) == b"XYZWUUUU", "crt: memmove_s copia Count bytes");
    let destination = block(16, UNTOUCHED);
    let range = status("memmove_s", &[destination, 3, source, 4]);
    assert(range == 34 && read(destination, 4) == b"UUUU", "crt: memmove_s com Size < Count = ERANGE sem tocar o destino");
    assert(status("memmove_s", &[0, 3, source, 4]) == 22 && status("memmove_s", &[destination, 3, 0, 4]) == 22 && status("memmove_s", &[0, 0, 0, 0]) == 0, "crt: memmove_s com ponteiro NULL = EINVAL e Count 0 = sucesso");
    let overlap = bytes_of(b"0123456789");
    assert(status("memmove_s", &[overlap + 2, 8, overlap, 6]) == 0 && read(overlap, 10) == b"0101234589", "crt: memmove_s trata a sobreposição");

    let classes: [(u64, u64, u64); 9] = [(0x61, 2, 0x80), (0x41, 0, 0x80), (0x66, 2, 0x80), (0x67, 2, 0), (0x39, 0, 0x80), (0xE9, 0, 0), (0x161, 2, 0x80), (0xFFFF_FFFF, 0, 0), (0x20, 0, 0)];
    assert(classes.iter().all(|&(character, lower, hexadecimal)| call("islower", &[character]) == lower && call("isxdigit", &[character]) == hexadecimal), "crt: islower e isxdigit pelo pctype sobre o byte baixo, EOF = 0");
    let spaces: [(u64, u64); 9] = [(0x20, 8), (0x09, 8), (0x0D, 8), (0xA0, 8), (0x85, 0), (0x1680, 0), (0x3000, 0), (0x1_0020, 8), (0x61, 0)];
    assert(spaces.iter().all(|&(character, expected)| call("iswspace", &[character]) == expected), "crt: iswspace pelo pwctype (só até U+00FF, 16 bits baixos)");
}

// ---- CRT: concatenação, conversão e qsort_s --------------------------------------

/// wcsncat_s sobre "abc" (ou outro inicial) num buffer de 12 WCHARs: (errno, bytes).
fn wcsncat(initial: &str, size: u64, source: u64, count: u64) -> (u64, Vec<u8>) {
    let destination = wide(initial);
    let buffer = block(32, UNTOUCHED);
    guest::write_bytes(buffer, &read(destination, (units(initial).len() + 1) * 2));
    (call("wcsncat_s", &[buffer, size, source, count]) & 0xFFFF_FFFF, read(buffer, 24))
}

fn crt_string_append(assert: Assert) {
    let destination = block(32, UNTOUCHED);
    guest::write_bytes(destination, b"abc\0");
    let source = bytes_of(b"defgh\0");
    let returned = call("strncat", &[destination, source, 3]);
    let three = read(destination, 10);
    guest::write_bytes(destination, b"abc\0UUUUUUUUUUUU");
    call("strncat", &[destination, source, 10]);
    let ten = read(destination, 10);
    guest::write_bytes(destination, b"abc\0UUUUUUUUUUUU");
    call("strncat", &[destination, source, 0]);
    assert(returned == destination && three == b"abcdef\0UUU" && ten == b"abcdefgh\0U" && read(destination, 10) == b"abc\0UUUUUU", "crt: strncat anexa até Count bytes com NUL e Count 0 não toca em nada");

    let source = wide("defgh");
    let rows: [((&str, u64, u64, u64), (u64, &str)); 9] = [
        (("abc", 10, source, 2), (0, "610062006300640065000000555555555555555555555555")),
        (("abc", 10, source, 10), (0, "610062006300640065006600670068000000555555555555")),
        (("abc", 6, source, 5), (34, "000062006300640065006600555555555555555555555555")),
        (("abc", 6, source, u64::MAX), (80, "610062006300640065000000555555555555555555555555")),
        (("abc", 10, source, u64::MAX), (0, "610062006300640065006600670068000000555555555555")),
        (("abcdef", 3, source, 2), (22, "000062006300640065006600000055555555555555555555")),
        (("abc", 10, 0, 2), (22, "000062006300000055555555555555555555555555555555")),
        (("abc", 10, 0, 0), (0, "610062006300000055555555555555555555555555555555")),
        (("abc", 0, source, 1), (22, "610062006300000055555555555555555555555555555555")),
    ];
    let failed = rows.iter().position(|&((initial, size, from, count), (errno, bytes))| wcsncat(initial, size, from, count) != (errno, hex(bytes)));
    assert(failed.is_none(), "crt: wcsncat_s (Count, _TRUNCATE = STRUNCATE, ERANGE e EINVAL com Dest[0] = 0)");
    assert(status("wcsncat_s", &[0, 0, 0, 0]) == 0 && status("wcsncat_s", &[0, 5, source, 0]) == 22 && status("wcsncat_s", &[0, 0, source, 1]) == 22, "crt: wcsncat_s com Dest NULL");

    let conversions: [(u64, u64, u64, u64, &str); 10] = [
        (1_234_567_890_123, 20, 10, 0, "31003200330034003500360037003800390030003100320033000000"),
        (0xDEAD_BEEF, 20, 16, 0, "6400650061006400620065006500660000005555"),
        (5, 2, 10, 0, "350000005555"),
        (55, 2, 10, 34, "000035005555"),
        (255, 10, 2, 0, "310031003100310031003100310031000000"),
        (7, 10, 1, 22, "00005555"),
        (7, 10, 37, 22, "00005555"),
        (35, 4, 36, 0, "7a000000"),
        (u64::MAX, 20, 10, 34, "0000310036003100350035003900300037003300370030003400340037003600340034003800310055"),
        (0, 2, 10, 0, "30000000"),
    ];
    let failed = conversions.iter().position(|&(value, size, radix, errno, bytes)| {
        let buffer = block(64, UNTOUCHED);
        let expected = hex(bytes);
        call("_ui64tow_s", &[value, buffer, size, radix]) & 0xFFFF_FFFF != errno || read(buffer, expected.len()) != expected
    });
    assert(failed.is_none(), "crt: _ui64tow_s (dígitos minúsculos, ERANGE com Buffer[0] = 0 e os dígitos já gravados, Radix inválido)");
    assert(status("_ui64tow_s", &[5, 0, 10, 10]) == 22 && status("_ui64tow_s", &[5, block(8, 0), 0, 10]) == 22, "crt: _ui64tow_s com Buffer NULL ou Size 0 = EINVAL");

    // Comparador nativo (Context, a, b): a - b, negado com Context != 0.
    let comparator = super::executable_code::place(&[0x44, 0x8B, 0x0A, 0x41, 0x8B, 0x00, 0x41, 0x29, 0xC1, 0x44, 0x89, 0xC8, 0x85, 0xC9, 0x74, 0x02, 0xF7, 0xD8, 0xC3]);
    let values: [u32; 12] = [5, 3, 9, 1, 7, 2, 8, 6, 4, 0, 11, 10];
    let array = block(48, 0);
    let fill = || guest::write_bytes(array, &values.iter().flat_map(|value| value.to_le_bytes()).collect::<Vec<u8>>());
    let numbers = || (0..12).map(|index| guest::read32(array + index * 4)).collect::<Vec<u32>>();
    fill();
    call("qsort_s", &[array, 12, 4, comparator, 0]);
    let ascending = numbers();
    fill();
    call("qsort_s", &[array, 12, 4, comparator, 1]);
    let descending = numbers();
    fill();
    call("qsort_s", &[array, 12, 0, comparator, 0]);
    call("qsort_s", &[array, 12, 4, 0, 0]);
    call("qsort_s", &[0, 0, 4, comparator, 0]);
    let untouched = numbers();
    super::executable_code::release(comparator);
    assert(ascending == (0..12).collect::<Vec<u32>>() && descending == (0..12).rev().collect::<Vec<u32>>() && untouched == values, "crt: qsort_s passa o Context ao comparador e Width 0/Compare NULL não ordenam");
}

// ---- Rtl: strings OEM em maiúsculas -----------------------------------------------

fn rtl_oem_upcase(assert: Assert) {
    let sizes = call("RtlxUnicodeStringToOemSize", &[unicode_string("ab\u{e9}\u{ff}", None)]) == 5 && call("RtlxUnicodeStringToOemSize", &[unicode_string("ab\u{e9}\u{ff}", Some(7))]) == 4 && call("RtlxUnicodeStringToOemSize", &[unicode_string("", None)]) == 1;
    assert(sizes, "rtl-oem: RtlxUnicodeStringToOemSize = WCHARs + 1");
    let source = wide("a\u{e9}\u{101}\u{4e00}\u{ff}");
    let output = block(16, UNTOUCHED);
    let count = block(4, 0xAA);
    let full = status("RtlUpcaseUnicodeToOemN", &[output, 8, count, source, 10]);
    let full_bytes = read(output, 8);
    let full_count = guest::read32(count);
    let output = block(16, UNTOUCHED);
    let short = status("RtlUpcaseUnicodeToOemN", &[output, 3, count, source, 10]);
    assert(full == 0 && full_count == 5 && full_bytes == hex("4190413f59555555") && short == 0x8000_0005 && guest::read32(count) == 3 && read(output, 8) == hex("4190415555555555"), "rtl-oem: RtlUpcaseUnicodeToOemN passa pelo best fit da 437 e pelo NLS_UPCASE (U+0101 -> A, U+00FF -> Y)");
    let output = block(16, UNTOUCHED);
    assert(status("RtlUpcaseUnicodeToOemN", &[output, 8, 0, source, 9]) == 0 && read(output, 8) == hex("4190413f55555555"), "rtl-oem: RtlUpcaseUnicodeToOemN sem BytesInOemString e Length ímpar");

    // (texto, Allocate, MaximumLength) -> (status, Length, MaximumLength, bytes ou NULL).
    let upcase = |text: &str, allocate: bool, maximum: u16| {
        let destination = block(nt::String::SIZE, 0);
        if !allocate {
            at::<nt::String>(destination).maximum_length.set(maximum);
            at::<nt::String>(destination).buffer.set(block(16, UNTOUCHED));
        }
        let result = status("RtlUpcaseUnicodeStringToOemString", &[destination, unicode_string(text, None), allocate as u64]);
        let string = at::<nt::String>(destination);
        let buffer = string.buffer.get();
        let bytes = if buffer != 0 { read(buffer, if allocate { string.maximum_length.get() as usize } else { 8 }) } else { Vec::new() };
        let outcome = (result, string.length.get(), string.maximum_length.get(), bytes);
        // O RtlFreeAnsiString zera a STRING depois do ExFreePool do buffer.
        if allocate && buffer != 0 {
            call("RtlFreeAnsiString", &[destination]);
            assert(string.buffer.get() == 0 && string.length.get() == 0 && string.maximum_length.get() == 0, "rtl-oem: RtlFreeAnsiString libera a string alocada pelo pool e zera os campos");
        }
        outcome
    };
    assert(upcase("ab\u{e9}\u{ff}", true, 0) == (0, 4, 5, hex("4142905900")), "rtl-oem: RtlUpcaseUnicodeStringToOemString alocando (Length, MaximumLength e o NUL)");
    assert(upcase("ab\u{e9}\u{ff}", false, 4) == (0x8000_0005, 4, 4, hex("5555555555555555")) && upcase("ab\u{e9}\u{ff}", false, 5) == (0, 4, 5, hex("4142905900555555")), "rtl-oem: buffer do chamador curto = STATUS_BUFFER_OVERFLOW com Length já gravado");
    assert(upcase("a\u{4e00}", true, 0) == (0xC000_0162, 2, 3, Vec::new()) && upcase("a\u{4e00}", false, 8) == (0xC000_0162, 2, 8, hex("413f555555555555")), "rtl-oem: caractere sem mapeamento = STATUS_UNMAPPABLE_CHARACTER (buffer alocado liberado)");
    assert(upcase("a?", false, 8) == (0, 2, 8, hex("413f005555555555")) && upcase("", false, 1) == (0, 0, 1, hex("0055555555555555")), "rtl-oem: '?' de origem não é falta de mapeamento");
}

// ---- Rtl: endereços IP em ANSI -------------------------------------------------------

fn rtl_network_string_ansi(assert: Assert) {
    let ipv4: [(&[u8], u64, u32, u64, u32); 15] = [
        (b"1.2.3.4", 1, 0, 7, 0x0403_0201),
        (b"1.2.3.4", 0, 0, 7, 0x0403_0201),
        (b"0x7f.1", 0, 0, 6, 0x0100_007F),
        (b"010.0.0.1", 0, 0, 9, 0x0100_0008),
        (b"010.0.0.1", 1, 0xC000_000D, 1, 0xAAAA_AAAA),
        (b"1.2.3", 1, 0xC000_000D, 5, 0xAAAA_AAAA),
        (b"1.2.3.256", 0, 0xC000_000D, 9, 0xAAAA_AAAA),
        (b"4294967295", 0, 0, 10, 0xFFFF_FFFF),
        (b"1.2.3.4x", 0, 0, 7, 0x0403_0201),
        (b"1..2", 0, 0xC000_000D, 3, 0xAAAA_AAAA),
        (b"1.2.3.4.5", 0, 0xC000_000D, 7, 0xAAAA_AAAA),
        (b"0xg", 0, 0xC000_000D, 2, 0xAAAA_AAAA),
        (b"\xb9.1", 0, 0xC000_000D, 0, 0xAAAA_AAAA),
        (b"192.168.1.10:80", 0, 0, 12, 0x0A01_A8C0),
        (b"0x", 0, 0xC000_000D, 2, 0xAAAA_AAAA),
    ];
    let failed = ipv4.iter().position(|&(text, strict, expected, end, address)| {
        let mut bytes = text.to_vec();
        bytes.push(0);
        let string = bytes_of(&bytes);
        let (terminator, output) = (block(8, 0xAA), block(4, 0xAA));
        status("RtlIpv4StringToAddressA", &[string, strict, terminator, output]) != expected || guest::read64(terminator) != string + end || guest::read32(output) != address
    });
    assert(failed.is_none(), "rtl-ip: RtlIpv4StringToAddressA (bases, Strict, *Terminator e char com sinal)");
    let ipv6: [(&[u8], u32, Option<u64>, &str); 16] = [
        (b"::1", 0, Some(3), "00000000000000000000000000000001"),
        (b"1:2:3:4:5:6:7:8", 0, Some(15), "00010002000300040005000600070008"),
        (b"fe80::1%4", 0, Some(7), "fe800000000000000000000000000001"),
        (b"::ffff:1.2.3.4", 0, Some(14), "00000000000000000000ffff01020304"),
        (b"1::0x12", 0, Some(4), "00010000000000000000000000000012"),
        (b"::0x123456789", 0, Some(3), "0000000000000000000000000000ffff"),
        (b"::0X", 0, Some(3), "00000000000000000000000000000000"),
        (b"1:2:3:4:5:6:7", 0xC000_000D, Some(13), "000100020003000400050006aaaaaaaa"),
        (b"12345::", 0xC000_000D, None, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        (b"::1.2.3", 0xC000_000D, Some(7), "00000102aaaaaaaaaaaaaaaaaaaaaaaa"),
        (b"1::2::3", 0, Some(4), "00010000000000000000000000000002"),
        (b"abcd:ef01::", 0, Some(11), "abcdef01000000000000000000000000"),
        (b"::1.2.3.256", 0xC000_000D, Some(11), "0000010203aaaaaaaaaaaaaaaaaaaaaa"),
        (b"1:2:3:4:5:6:1.2.3.4", 0, Some(19), "00010002000300040005000601020304"),
        (b"g::", 0xC000_000D, Some(0), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        (b"::", 0, Some(2), "00000000000000000000000000000000"),
    ];
    let failed = ipv6.iter().position(|&(text, expected, end, address)| {
        let mut bytes = text.to_vec();
        bytes.push(0);
        let string = bytes_of(&bytes);
        let (terminator, output) = (block(8, 0xAA), block(16, 0xAA));
        let result = status("RtlIpv6StringToAddressA", &[string, terminator, output]);
        result != expected || guest::read64(terminator) != end.map_or(0xAAAA_AAAA_AAAA_AAAA, |end| string + end) || read(output, 16) != hex(address)
    });
    assert(failed.is_none(), "rtl-ip: RtlIpv6StringToAddressA (grupos pelo strtol: prefixo 0x e saturação em LONG_MAX)");
}

// ---- Rtl: árvore rubro-negra, controle do SD e placeholders ------------------------

fn rtl_small_helpers(assert: Assert) {
    // Árvore: raiz A com filhos B (esquerda, o mínimo) e C.
    let tree = block(16, 0);
    let [a, b, c, r1, r2, r3] = [(); 6].map(|_| block(24, 0));
    let node = |address: u64| at::<nt::RtlBalancedNode>(address);
    let links = |address: u64| (node(address).left.get(), node(address).right.get(), node(address).parent_value.get());
    node(a).left.set(b);
    node(a).right.set(c);
    node(b).parent_value.set(a | 1);
    node(c).parent_value.set(a | 1);
    at::<nt::RtlRbTree>(tree).root.set(a);
    at::<nt::RtlRbTree>(tree).min.set(b);
    call("RtlRbReplaceNode", &[tree, b, r1]);
    let first = at::<nt::RtlRbTree>(tree).root.get() == a && at::<nt::RtlRbTree>(tree).min.get() == r1 && links(a) == (r1, c, 0) && links(r1) == (0, 0, a | 1);
    call("RtlRbReplaceNode", &[tree, a, r2]);
    let second = at::<nt::RtlRbTree>(tree).root.get() == r2 && links(r2) == (r1, c, 0) && links(r1) == (0, 0, r2 | 1) && links(c) == (0, 0, r2 | 1);
    call("RtlRbReplaceNode", &[tree, c, r3]);
    let third = links(r2) == (r1, r3, 0) && links(r3) == (0, 0, r2 | 1) && at::<nt::RtlRbTree>(tree).min.get() == r1;
    let encoded = block(16, 0);
    let (n, m) = (block(24, 0), block(24, 0));
    at::<nt::RtlRbTree>(encoded).root.set(encoded ^ n);
    at::<nt::RtlRbTree>(encoded).min.set((encoded ^ n) | 1);
    call("RtlRbReplaceNode", &[encoded, n, m]);
    let coded = at::<nt::RtlRbTree>(encoded).root.get() == encoded ^ m && at::<nt::RtlRbTree>(encoded).min.get() == (encoded ^ m) | 1;
    assert(first && second && third && coded, "rtl-rb: RtlRbReplaceNode troca o elo do pai, o pai dos filhos, a raiz e o mínimo (codificados na árvore codificada)");

    let rows: [(u64, u64, u32, u16); 8] = [(0x1000, 0x1000, 0, 0x3C14), (0x1400, 0x0400, 0, 0x2C14), (0x3FC0, 0x3FC0, 0, 0x3FD4), (0x0004, 0, 0xC000_000D, 0x2C14), (0x1000, 0x2000, 0xC000_000D, 0x2C14), (0x8000, 0, 0xC000_000D, 0x2C14), (0x1_3000, 0x1000, 0, 0x1C14), (0x1000, 0x1_1000, 0, 0x3C14)];
    let failed = rows.iter().position(|&(interest, to_set, expected, control)| {
        let descriptor = block(40, 0);
        guest::write8(descriptor, 1);
        guest::write16(descriptor + 2, 0x2C14);
        status("RtlSetControlSecurityDescriptor", &[descriptor, interest, to_set]) != expected || guest::read16(descriptor + 2) != control
    });
    assert(failed.is_none(), "rtl-sd: RtlSetControlSecurityDescriptor só muda os bits 0x3FC0 de interesse (parâmetros de 16 bits)");

    let placeholders: [(u64, u64, u64); 7] = [(0x400, 0x9000_001A, 1), (0x400, 0x9000_F01A, 1), (0x400, 0x9000_101A, 1), (0, 0x9000_001A, 0), (0x400, 0x9000_001B, 0), (0x401, 0x9001_001A, 0), (0xFFFF_FFFF, 0x9000_A01A, 1)];
    assert(placeholders.iter().all(|&(attributes, tag, expected)| call("RtlIsCloudFilesPlaceholder", &[attributes, tag]) & 0xFF == expected), "rtl-cloud: RtlIsCloudFilesPlaceholder = reparse point com a tag de nuvem de qualquer provedor");
}

// ---- Ldr: LdrFindResource_U e LdrAccessResource -----------------------------------

fn ldr_resource(assert: Assert) {
    use super::resource_search_fixtures as fixtures;
    use crate::ntos::rtl::resource::satellites;
    let options = crate::ntos::mm::kernel_pool::AllocateOptions { tag: 0x7352_7354, zero: true, ..Default::default() };
    let Ok(image) = crate::ntos::mm::kernel_pool::allocate(0x4000, options) else {
        assert(false, "ldr: imagem de teste alocada");
        return;
    };
    let populate = || {
        guest::write_bytes(image, &[0u8; 0x4000]);
        for &(offset, value) in fixtures::MAPPED.words {
            guest::write32(image + offset as u64, value);
        }
    };
    populate();
    let (path, output) = (block(64, 0), block(8, 0));
    let find = |dll: u64, keys: &[u64], length: u64| -> (u32, u64) {
        for (index, key) in keys.iter().enumerate() {
            guest::write64(path + index as u64 * 8, *key);
        }
        guest::write64(output, 0xAAAA_AAAA_AAAA_AAAA);
        let result = status("LdrFindResource_U", &[dll, path, length | 1 << 40, output]);
        let entry = guest::read64(output);
        (result, if result == 0 { entry.wrapping_sub(dll) } else { entry })
    };
    const UNCHANGED: u64 = 0xAAAA_AAAA_AAAA_AAAA;
    let rows: [(&[u64], u32, u64); 7] = [
        (&[16, 1, 0x409], 0, 0x1048),
        (&[16, 1, 0], 0, 0x1048),
        (&[16, 1, 0x407], 0xC000_0204, UNCHANGED),
        (&[16, 1, 0x400], 0, 0x1048),
        (&[17, 1, 0x409], 0xC000_008A, UNCHANGED),
        (&[16, 2, 0x409], 0xC000_008B, UNCHANGED),
        (&[15, 1, 0x409], 0xC000_008A, UNCHANGED),
    ];
    let failed = rows.iter().position(|&(keys, expected, entry)| find(image, keys, 3) != (expected, entry));
    assert(failed.is_none(), "ldr: LdrFindResource_U desce tipo/nome/idioma com o fallback (pais, idioma da máquina) e os status de cada nível");
    let version = wide("VERSION");
    assert(find(image, &[version, 1, 0x409], 3) == (0xC000_008A, UNCHANGED), "ldr: tipo por nome sem entradas com nome = STATUS_RESOURCE_TYPE_NOT_FOUND");
    assert(
        find(image, &[16, 1], 2).0 == 0xC000_00F1 && find(image, &[16, 1, 0x409, 0], 4).0 == 0xC000_00F1 && find(image, &[16, 1, 0x409, 0, 0], 5).0 == 0xC000_00F1 && find(0, &[16, 1, 0x409], 3).0 == 0xC000_000D && find(u64::MAX, &[16, 1, 0x409], 3).0 == 0xC000_000D,
        "ldr: Length fora de 3 = STATUS_INVALID_PARAMETER_3 e DllHandle 0/-1 = STATUS_INVALID_PARAMETER",
    );
    // Diretório de idiomas vazio.
    guest::write32(image + 0x103C, 0);
    let empty = (find(image, &[16, 1, 0x409], 3), find(image, &[16, 1, 0], 3));
    populate();
    // Duas entradas de idioma (0x409 e 0x40C) para a busca binária.
    guest::write32(image + 0x103C, 0x2_0000);
    guest::write32(image + 0x1048, 0x40C);
    guest::write32(image + 0x104C, 0x58);
    guest::write32(image + 0x1058, 0x1800);
    guest::write32(image + 0x105C, 0x10);
    guest::write32(image + 0x1060, 0x4B0);
    let two = [find(image, &[16, 1, 0x409], 3), find(image, &[16, 1, 0x40C], 3), find(image, &[16, 1, 0x80C], 3), find(image, &[16, 1, 0x407], 3), find(image, &[16, 1, 0], 3)];
    populate();
    assert(empty == ((0xC000_0204, UNCHANGED), (0xC000_0204, UNCHANGED)), "ldr: diretório de idiomas vazio encerra com STATUS_RESOURCE_LANG_NOT_FOUND");
    assert(two == [(0, 0x1048), (0, 0x1058), (0xC000_0204, UNCHANGED), (0xC000_0204, UNCHANGED), (0, 0x1048)], "ldr: idioma por busca binária, o pai de fr-CH (fr) ausente e o neutro pelo idioma da máquina");

    let (address, size) = (block(8, 0), block(4, 0));
    let access = |dll: u64, entry: u64, with_address: bool, with_size: bool| -> (u32, u64, u32) {
        guest::write64(address, 0xAAAA);
        guest::write32(size, 0xAAAA);
        let result = status("LdrAccessResource", &[dll, entry, if with_address { address } else { 0 }, if with_size { size } else { 0 }]);
        (result, guest::read64(address), guest::read32(size))
    };
    let entry = image + 0x1048;
    assert(access(image, entry, true, true) == (0, image + 0x1800, 0x10) && access(image, entry, false, true) == (0, 0xAAAA, 0x10) && access(image, entry, true, false) == (0, image + 0x1800, 0xAAAA), "ldr: LdrAccessResource devolve base + OffsetToData e o Size");
    assert(access(image | 1, entry, true, true) == (0, image + 0xC00, 0x10), "ldr: vista de arquivo traduz o dado pela seção do diretório de recursos");
    let outside = (access(image, image, true, true), access(image, image + 0x4000, true, true), access(image, 0, true, true).0, access(0, entry, true, true).0);
    guest::write32(entry, 0x5000);
    let data_outside = access(image, entry, true, true);
    populate();
    assert(outside == ((0xC000_007B, 0xAAAA, 0xAAAA), (0xC000_007B, 0xAAAA, 0xAAAA), 0xC000_000D, 0xC000_000D) && data_outside == (0xC000_007B, 0, 0xAAAA), "ldr: entrada fora da imagem = STATUS_INVALID_IMAGE_FORMAT sem saída e dado fora = *Address zerado");
    let _ = satellites::unload(image);
    let _ = crate::ntos::mm::kernel_pool::free(image, None);

    // A versão de um driver real carregado (hal.dll), conferida por uma
    // descida simples da árvore do próprio arquivo.
    let Some(hal) = crate::ntos::mm::loaded_images::find_by_base_name("hal.dll") else {
        assert(false, "ldr: hal.dll carregado");
        return;
    };
    let base = hal.image_base;
    let header = base + guest::read32(base + 0x3C) as u64;
    let root = base + guest::read32(header + 0x18 + 0x70 + 2 * 8) as u64;
    let child = |directory: u64, id: u32| -> u64 {
        let named = guest::read16(directory + 0xC) as u64;
        let ids = guest::read16(directory + 0xE) as u64;
        (0..ids).map(|index| directory + 0x10 + (named + index) * 8).find(|&slot| guest::read32(slot) == id).map_or(0, |slot| guest::read32(slot + 4) as u64)
    };
    let names = root + (child(root, 16) & 0x7FFF_FFFF);
    let languages = root + (child(names, 1) & 0x7FFF_FFFF);
    let expected = root + child(languages, 0x409);
    let offset = guest::read32(expected) as u64;
    let length = guest::read32(expected + 4);
    let found = find(base, &[16, 1, 0x409], 3);
    let neutral = find(base, &[16, 1, 0], 3);
    // Na vista de arquivo, o RVA do dado vai para o PointerToRawData da seção.
    let sections = header + 0x18 + guest::read16(header + 0x14) as u64;
    let raw = (0..guest::read16(header + 6) as u64).map(|index| sections + index * 0x28).find(|&section| {
        let start = guest::read32(section + 0xC) as u64;
        offset >= start && offset < start + guest::read32(section + 0x10) as u64
    });
    let file_address = raw.map_or(0, |section| base + guest::read32(section + 0x14) as u64 + offset - guest::read32(section + 0xC) as u64);
    assert(
        found == (0, expected - base) && neutral == found && access(base, expected, true, true) == (0, base + offset, length) && access(base | 1, expected, true, true) == (0, file_address, length),
        "ldr: LdrFindResource_U/LdrAccessResource na versão do hal.dll real (imagem e vista de arquivo)",
    );
}

pub fn run(assert: Assert) {
    crt_memory_ctype(assert);
    crt_string_append(assert);
    rtl_oem_upcase(assert);
    rtl_network_string_ansi(assert);
    rtl_small_helpers(assert);
    ldr_resource(assert);
}
