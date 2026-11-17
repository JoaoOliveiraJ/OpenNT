//! Autoteste dos exports Rtl e da CRT que eram os últimos imports de drivers
//! reais: prefixos Unicode (RtlNextUnicodePrefix), RTL_BITMAP_EX
//! (RtlAreBitsSetEx), swprintf e wcsncpy, endereços com porta e escopo
//! (RtlIpv4/Ipv6StringToAddressExW), RtlUnicodeStringToInt64,
//! RtlValidateUnicodeString, os vetores de SID_AND_ATTRIBUTES e
//! LUID_AND_ATTRIBUTES (RtlCopySidAndAttributesArray,
//! RtlCopyLuidAndAttributesArray, RtlSidHashInitialize), os vetores de
//! correlação, o RtlCrc32, o RtlOpenCurrentUser e, por um destino exato que
//! o luafv.sys monta, o RtlAppendUnicodeStringToString.
//!
//! Cada export é chamado pelo trampolim nativo (ABI MS x64). Os valores
//! esperados foram medidos nas rotinas reais: as do ntdll.dll do Windows 10
//! 19041 que existem também no modo usuário (RtlCrc32, os parsers Ex, o
//! RtlValidateUnicodeString, os vetores de correlação, os vetores de SID, o
//! swprintf e o wcsncpy) e, para as que só o kernel tem
//! (RtlUnicodeStringToInt64 e RtlAreBitsSetEx), as do ntoskrnl.exe
//! executadas num emulador, com as saídas preenchidas antes com 0xAA/0xBB/
//! 0xCC/0x5A para ver o que cada rotina grava.

use alloc::vec::Vec;

use crate::ntos::inc::types::{self as nt, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;

type Assert = fn(bool, &str);

const MISSING: u64 = 0xDEAD_DEAD_DEAD_DEAD;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INTEGER_OVERFLOW: u32 = 0xC000_0095;

fn call(name: &str, arguments: &[u64]) -> u64 {
    super::phase6::call_export(name, arguments).unwrap_or(MISSING)
}

fn status(name: &str, arguments: &[u64]) -> u32 {
    let value = call(name, arguments);
    if value == MISSING { 0xFFFF_FFFF } else { value as u32 }
}

fn zeroed(size: u64) -> u64 {
    let block = guest::alloc_bytes(size);
    guest::write_bytes(block, &alloc::vec![0u8; size as usize]);
    block
}

fn filled(size: u64, byte: u8) -> u64 {
    let block = guest::alloc_bytes(size);
    guest::write_bytes(block, &alloc::vec![byte; size as usize]);
    block
}

/// Texto UTF-16 com NUL num bloco novo.
fn wide(text: &str) -> u64 {
    let bytes = guest_strings::wide_bytes_with_nul(text);
    let block = guest::alloc_bytes(bytes.len() as u64);
    guest::write_bytes(block, &bytes);
    block
}

/// UNICODE_STRING de kernel com Length/MaximumLength dados e o texto em
/// seguida (com NUL).
fn unicode_with(text: &str, length: u16, maximum: u16) -> u64 {
    let bytes = guest_strings::wide_bytes_with_nul(text);
    let block = zeroed(nt::UnicodeString::SIZE + bytes.len() as u64 + 2);
    guest::write_bytes(block + nt::UnicodeString::SIZE, &bytes);
    guest_strings::write_string_fields(block, length, maximum, block + nt::UnicodeString::SIZE);
    block
}

fn unicode(text: &str) -> u64 {
    let length = text.encode_utf16().count() as u16 * 2;
    unicode_with(text, length, length + 2)
}

/// O Buffer de uma UNICODE_STRING.
fn buffer_of(string: u64) -> u64 {
    // SAFETY: UNICODE_STRING criada por este teste.
    unsafe { nt::UnicodeString::at(string) }.buffer.get()
}

pub fn run(assert: Assert) {
    next_unicode_prefix(assert);
    are_bits_set_ex(assert);
    wide_copy_format(assert);
    network_string_ex(assert);
    unicode_string_ex(assert);
    sid_attribute_arrays(assert);
    correlation_vector(assert);
    crc32(assert);
    open_current_user(assert);
    append_unicode_string(assert);
}

// ---- RtlNextUnicodePrefix ------------------------------------------------------

fn next_unicode_prefix(assert: Assert) {
    let table = zeroed(nt::UnicodePrefixTable::SIZE);
    let entries: Vec<u64> = (0..3).map(|_| zeroed(nt::UnicodePrefixTableEntry::SIZE)).collect();
    call("RtlInitializeUnicodePrefix", &[table]);
    let empty = [call("RtlNextUnicodePrefix", &[table, 1]), call("RtlNextUnicodePrefix", &[table, 0])];
    // SAFETY: a tabela recém-inicializada.
    let header = unsafe { nt::UnicodePrefixTable::at(table) };
    let untouched = header.last_next_entry.get();
    for (prefix, &entry) in ["\\pipe", "\\", "\\pipe\\a"].iter().zip(&entries) {
        call("RtlInsertUnicodePrefix", &[table, unicode(prefix), entry]);
    }
    // A lista fica em ordem decrescente de componentes: \pipe\a, \pipe, \.
    let mut order = Vec::new();
    let mut entry = call("RtlNextUnicodePrefix", &[table, 1]);
    while entry != 0 && entry != MISSING && order.len() < 8 {
        order.push(entry);
        entry = call("RtlNextUnicodePrefix", &[table, 0]);
    }
    let cursor = header.last_next_entry.get();
    let again = call("RtlNextUnicodePrefix", &[table, 0]);
    let restart = call("RtlNextUnicodePrefix", &[table, 1]);
    let second = call("RtlNextUnicodePrefix", &[table, 0]);
    assert(
        empty == [0, 0] && untouched == 0 && order == [entries[2], entries[0], entries[1]] && entry == 0 && cursor == entries[1] && again == 0 && header.last_next_entry.get() == entries[0] && restart == entries[2] && second == entries[0],
        "rtl-unicode-prefix-next: tabela vazia devolve NULL, enumeracao na ordem da lista com o cursor LastNextEntry, NULL no fim sem mexer no cursor e Restart",
    );
}

// ---- RtlAreBitsSetEx -----------------------------------------------------------

fn are_bits_set_ex(assert: Assert) {
    let words = [0xFFFF_0000_FFFF_FFFFu64, u64::MAX, 0xFF, 0x8000_0000_0000_0001];
    let buffer = zeroed(32);
    for (index, &word) in words.iter().enumerate() {
        guest::write64(buffer + index as u64 * 8, word);
    }
    let header = zeroed(nt::RtlBitmapEx::SIZE);
    // SAFETY: cabeçalho RTL_BITMAP_EX recém-alocado.
    let bitmap = unsafe { nt::RtlBitmapEx::at(header) };
    bitmap.size_of_bit_map.set(250);
    bitmap.buffer.set(buffer);
    let cases: [(u64, u64, u64); 17] = [
        (0, 32, 1), (0, 33, 0), (48, 88, 1), (48, 89, 0), (128, 8, 1), (128, 9, 0), (192, 1, 1), (193, 1, 0), (255, 1, 0),
        (249, 1, 0), (250, 1, 0), (200, 0, 0), (130, 6, 1), (40, 8, 0), (64, 64, 1), (0, 250, 0), (100, 151, 0),
    ];
    let wrong: Vec<(u64, u64)> = cases.iter().filter(|&&(start, length, expected)| call("RtlAreBitsSetEx", &[header, start, length]) & 0xFF != expected).map(|&(start, length, _)| (start, length)).collect();
    assert(wrong.is_empty(), "rtl-bitmap-ex-set: RtlAreBitsSetEx em faixas dentro de uma palavra, entre palavras, bit unico, fora do mapa, Length 0 e faixa que passa do fim");
}

// ---- swprintf / wcsncpy --------------------------------------------------------

fn wide_text(address: u64, units: usize) -> Vec<u16> {
    guest::read_bytes(address, units * 2).chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect()
}

fn wide_copy_format(assert: Assert) {
    let output = filled(64 * 2, 0x5A);
    let format = wide("%s-%d-%04x|%c");
    let written = call("swprintf", &[output, format, wide("abc"), -42i64 as u64, 0xBEEF, 0x5A]);
    let text: Vec<u16> = "abc--42-beef|Z".encode_utf16().chain(core::iter::once(0)).collect();
    let refused = [call("swprintf", &[0, format]) as u32, call("swprintf", &[output, 0]) as u32];
    assert(written == 14 && wide_text(output, 15) == text && refused == [0xFFFF_FFFF, 0xFFFF_FFFF], "crt-wide-copy-format: swprintf grava o texto inteiro e o NUL, devolve os WCHARs, e recusa Buffer ou Format NULL com -1");

    let source = wide("abcdef");
    let target = filled(8 * 2, 0x5A);
    let returned = call("wcsncpy", &[target, source, 3]);
    let short = wide_text(target, 8);
    let padded_target = filled(8 * 2, 0x5A);
    call("wcsncpy", &[padded_target, wide("ab"), 5]);
    let padded = wide_text(padded_target, 8);
    let none_target = filled(8 * 2, 0x5A);
    call("wcsncpy", &[none_target, source, 0]);
    let z: u16 = 0x5A5A;
    assert(
        returned == target && short == [0x61, 0x62, 0x63, z, z, z, z, z] && padded == [0x61, 0x62, 0, 0, 0, z, z, z] && wide_text(none_target, 8) == [z; 8],
        "crt-wide-copy-format: wcsncpy sem NUL quando a origem passa de Count, zeros ate Count depois do NUL e nada com Count 0",
    );
}

// ---- RtlIpv4/Ipv6StringToAddressExW --------------------------------------------

fn network_string_ex(assert: Assert) {
    // (texto, Strict, status, endereço, porta), com o endereço prévio
    // 0xAAAAAAAA e a porta prévia 0xBBBB.
    let ipv4: [(&str, u64, u32, u32, u16); 10] = [
        ("192.168.1.10:8080", 1, 0, 0x0A01_A8C0, 0x901F),
        ("10.0.0.1:0x1F90", 1, 0, 0x0100_000A, 0x901F),
        ("10.0.0.1:010", 1, 0, 0x0100_000A, 0x0800),
        ("10.0.0.1:0", 1, STATUS_INVALID_PARAMETER, 0x0100_000A, 0xBBBB),
        ("10.0.0.1:65536", 1, STATUS_INVALID_PARAMETER, 0x0100_000A, 0xBBBB),
        ("10.1", 0, 0, 0x0100_000A, 0),
        ("10.1", 1, STATUS_INVALID_PARAMETER, 0xAAAA_AAAA, 0xBBBB),
        ("1.2.3.4 ", 1, STATUS_INVALID_PARAMETER, 0x0403_0201, 0xBBBB),
        ("1.2.3.4:0x", 1, STATUS_INVALID_PARAMETER, 0x0403_0201, 0xBBBB),
        ("1.2.3.4:0X10", 1, 0, 0x0403_0201, 0x1000),
    ];
    let wrong4: Vec<&str> = ipv4
        .iter()
        .filter(|&&(text, strict, expected, address, port)| {
            let (address_out, port_out) = (filled(4, 0xAA), filled(2, 0xBB));
            let result = status("RtlIpv4StringToAddressExW", &[wide(text), strict, address_out, port_out]);
            result != expected || guest::read32(address_out) != address || guest::read16(port_out) != port
        })
        .map(|&(text, ..)| text)
        .collect();
    let null_port = status("RtlIpv4StringToAddressExW", &[wide("1.2.3.4"), 1, zeroed(4), 0]);
    assert(wrong4.is_empty() && null_port == STATUS_INVALID_PARAMETER, "rtl-network-string-ex: RtlIpv4StringToAddressExW com porta decimal, hexadecimal e octal, porta vazia ou grande recusada, Strict e ponteiro NULL");

    let loopback: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let link_local: [u8; 16] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let documentation: [u8; 16] = [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
    let mapped: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 1, 2, 3, 4];
    // (texto, status, endereço, escopo, porta), escopo prévio 0xCCCCCCCC.
    let ipv6: [(&str, u32, [u8; 16], u32, u16); 8] = [
        ("[fe80::1%12]:443", 0, link_local, 12, 0xBB01),
        ("[2001:db8::7]:0x50", 0, documentation, 0, 0x5000),
        ("[::1]:", 0, loopback, 0, 0),
        ("[::1", STATUS_INVALID_PARAMETER, loopback, 0xCCCC_CCCC, 0xBBBB),
        ("::1]", STATUS_INVALID_PARAMETER, loopback, 0xCCCC_CCCC, 0xBBBB),
        ("fe80::1%4294967295", 0, link_local, 0xFFFF_FFFF, 0),
        ("fe80::1%4294967296", STATUS_INVALID_PARAMETER, link_local, 0xCCCC_CCCC, 0xBBBB),
        ("[::ffff:1.2.3.4]:80", 0, mapped, 0, 0x5000),
    ];
    let wrong6: Vec<&str> = ipv6
        .iter()
        .filter(|&&(text, expected, address, scope, port)| {
            let (address_out, scope_out, port_out) = (filled(16, 0xAA), filled(4, 0xCC), filled(2, 0xBB));
            let result = status("RtlIpv6StringToAddressExW", &[wide(text), address_out, scope_out, port_out]);
            result != expected || guest::read_bytes(address_out, 16) != address || guest::read32(scope_out) != scope || guest::read16(port_out) != port
        })
        .map(|&(text, ..)| text)
        .collect();
    assert(wrong6.is_empty(), "rtl-network-string-ex: RtlIpv6StringToAddressExW com colchetes, escopo de 32 bits, porta vazia aceita como 0, colchete sem par recusado e sufixo IPv4");
}

// ---- RtlUnicodeStringToInt64 / RtlValidateUnicodeString ------------------------

fn unicode_string_ex(assert: Assert) {
    // (texto, base, status, valor, posição final em WCHARs).
    let cases: [(&str, u64, u32, u64, u64); 15] = [
        ("123", 10, 0, 123, 3),
        ("-123", 10, 0, -123i64 as u64, 4),
        ("  +42xyz", 10, 0, 42, 5),
        ("0x1F", 0, 0, 0x1F, 4),
        ("0x1F", 16, 0, 0x1F, 4),
        ("017", 0, 0, 0o17, 3),
        ("9223372036854775807", 10, 0, i64::MAX as u64, 19),
        ("9223372036854775808", 10, STATUS_INTEGER_OVERFLOW, i64::MAX as u64, 19),
        ("-9223372036854775808", 10, 0, 1 << 63, 20),
        ("-9223372036854775809", 10, STATUS_INTEGER_OVERFLOW, 1 << 63, 20),
        ("zz", 36, 0, 35 * 36 + 35, 2),
        ("abc", 10, 0, 0, 0),
        ("12", 1, 0, 0, 0),
        ("77", 37, 0, 0, 0),
        ("ffffffffffffffffff", 16, STATUS_INTEGER_OVERFLOW, i64::MAX as u64, 18),
    ];
    let wrong: Vec<&str> = cases
        .iter()
        .filter(|&&(text, base, expected, value, stop)| {
            let string = unicode(text);
            let (number, end) = (filled(8, 0xAA), filled(8, 0xBB));
            let result = status("RtlUnicodeStringToInt64", &[string, base, number, end]);
            let buffer = buffer_of(string);
            result != expected || guest::read64(number) != value || guest::read64(end) != buffer + stop * 2
        })
        .map(|&(text, ..)| text)
        .collect();
    assert(wrong.is_empty(), "rtl-unicode-string-ex: RtlUnicodeStringToInt64 com brancos, sinal, prefixos 0x e 0, saturacao com STATUS_INTEGER_OVERFLOW e base invalida");

    // Sem NUL no último WCHAR de MaximumLength: só os Length/2 primeiros
    // contam; com NUL, a conversão vai direto até o NUL (além do Length).
    let truncated = unicode_with("12345", 4, 10);
    let (number, end) = (filled(8, 0xAA), filled(8, 0xBB));
    let first = (status("RtlUnicodeStringToInt64", &[truncated, 10, number, end]), guest::read64(number), guest::read64(end) - buffer_of(truncated));
    let direct = unicode_with("12345", 4, 12);
    let second = (status("RtlUnicodeStringToInt64", &[direct, 10, number, 0]), guest::read64(number));
    // 70 dígitos sem NUL: a cópia local tem 64 WCHARs.
    let digits = unicode_with(&"1".repeat(70), 140, 140);
    let third = (status("RtlUnicodeStringToInt64", &[digits, 2, number, end]), guest::read64(number), guest::read64(end) - buffer_of(digits));
    assert(first == (0, 12, 4) && second == (0, 12345) && third == (STATUS_INTEGER_OVERFLOW, i64::MAX as u64, 128), "rtl-unicode-string-ex: RtlUnicodeStringToInt64 converte a copia de Length (ate 64 WCHARs) ou o Buffer direto quando o fim do MaximumLength e NUL");

    // (Flags, Length, MaximumLength, com Buffer) -> status.
    let validations: [(u64, u16, u16, bool, u32); 9] = [
        (0, 4, 8, true, 0),
        (0, 3, 8, true, STATUS_INVALID_PARAMETER),
        (0, 4, 7, true, STATUS_INVALID_PARAMETER),
        (0, 10, 8, true, STATUS_INVALID_PARAMETER),
        (0, 0, 0, false, 0),
        (0, 2, 4, false, STATUS_INVALID_PARAMETER),
        (0, 0, 2, false, STATUS_INVALID_PARAMETER),
        (1, 4, 8, true, STATUS_INVALID_PARAMETER),
        (0, 0xFFFE, 0xFFFE, true, 0),
    ];
    let wrong: Vec<usize> = validations
        .iter()
        .enumerate()
        .filter(|&(_, &(flags, length, maximum, with_buffer, expected))| {
            let string = zeroed(nt::UnicodeString::SIZE);
            guest_strings::write_string_fields(string, length, maximum, if with_buffer { zeroed(16) } else { 0 });
            status("RtlValidateUnicodeString", &[flags, string]) != expected
        })
        .map(|(index, _)| index)
        .collect();
    let null = [status("RtlValidateUnicodeString", &[0, 0]), status("RtlValidateUnicodeString", &[1, 0])];
    assert(wrong.is_empty() && null == [0, STATUS_INVALID_PARAMETER], "rtl-unicode-string-ex: RtlValidateUnicodeString recusa Flags, tamanhos impares ou invertidos e Buffer NULL com tamanho, e aceita String NULL");
}

// ---- Vetores de SID_AND_ATTRIBUTES e LUID_AND_ATTRIBUTES -----------------------

fn sid(authority: u8, sub_authorities: &[u32]) -> Vec<u8> {
    let mut bytes = alloc::vec![1, sub_authorities.len() as u8, 0, 0, 0, 0, 0, authority];
    for value in sub_authorities {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn sid_attribute_arrays(assert: Assert) {
    let sids = [sid(5, &[18]), sid(5, &[32, 544]), sid(1, &[0]), sid(5, &[21, 1, 2, 3, 0x1F4]), sid(16, &[0x3000])];
    let array = zeroed(nt::SidAndAttributes::SIZE * sids.len() as u64);
    for (index, bytes) in sids.iter().enumerate() {
        let block = guest::alloc_bytes(bytes.len() as u64);
        guest::write_bytes(block, bytes);
        // SAFETY: entrada `index` do vetor recém-alocado.
        let entry = unsafe { nt::SidAndAttributes::at(array + index as u64 * nt::SidAndAttributes::SIZE) };
        entry.sid.set(block);
        entry.attributes.set(7 + index as u32);
    }

    let hash = filled(nt::SidAndAttributesHash::SIZE, 0x77);
    let hashed = status("RtlSidHashInitialize", &[array, sids.len() as u64, hash]);
    // SAFETY: o SID_AND_ATTRIBUTES_HASH recém-preenchido.
    let view = unsafe { nt::SidAndAttributesHash::at(hash) };
    let buckets: Vec<u64> = view.hash.iter().map(|cell| cell.get()).collect();
    let mut expected = [0u64; 32];
    (expected[0], expected[2], expected[4], expected[16], expected[17], expected[18], expected[31]) = (0x16, 1, 8, 0x14, 1, 2, 8);
    let refused = status("RtlSidHashInitialize", &[array, 3, 0]);
    let empty = filled(nt::SidAndAttributesHash::SIZE, 0x77);
    let without = status("RtlSidHashInitialize", &[0, 3, empty]);
    assert(
        hashed == 0 && view.sid_count.get() == 5 && view.sid_attr.get() == array && buckets == expected && refused == STATUS_INVALID_PARAMETER && without == 0 && guest::read_bytes(empty, nt::SidAndAttributesHash::SIZE as usize).iter().all(|&byte| byte == 0),
        "rtl-sid-attribute-arrays: RtlSidHashInitialize marca o byte baixo da ultima subautoridade nos dois baldes, zera sem vetor e recusa hash NULL",
    );

    let destination = zeroed(nt::SidAndAttributes::SIZE * 3);
    let area = zeroed(100);
    let (remaining, size) = (filled(8, 0x11), filled(4, 0x22));
    let copied = status("RtlCopySidAndAttributesArray", &[3, array, 100, destination, area, remaining, size]);
    // SAFETY: o vetor de destino de 3 entradas.
    let targets = unsafe { nt::SidAndAttributes::array_at(destination, 3) };
    let layout: Vec<(u64, u32)> = targets.iter().map(|entry| (entry.sid.get().wrapping_sub(area), entry.attributes.get())).collect();
    let packed: Vec<u8> = sids[..3].concat();
    let (small_remaining, small_size) = (filled(8, 0x11), filled(4, 0x22));
    let small = status("RtlCopySidAndAttributesArray", &[3, array, 30, zeroed(48), zeroed(48), small_remaining, small_size]);
    assert(
        copied == 0 && layout == [(0, 7), (12, 8), (28, 9)] && guest::read_bytes(area, 40) == packed && guest::read64(remaining) == area + 40 && guest::read32(size) == 60 && small == STATUS_BUFFER_TOO_SMALL && guest::read64(small_remaining) == 0x1111_1111_1111_1111 && guest::read32(small_size) == 0x2222_2222,
        "rtl-sid-attribute-arrays: RtlCopySidAndAttributesArray empacota os SIDs na area, devolve o resto e recusa area pequena sem gravar as saidas",
    );

    let luids = zeroed(nt::LuidAndAttributes::SIZE * 3);
    let source: Vec<u8> = (0..36u8).map(|value| value.wrapping_mul(7).wrapping_add(1)).collect();
    guest::write_bytes(luids, &source);
    let copy = filled(nt::LuidAndAttributes::SIZE * 4, 0x5A);
    call("RtlCopyLuidAndAttributesArray", &[3, luids, copy]);
    let tail = guest::read_bytes(copy + 36, 12);
    assert(guest::read_bytes(copy, 36) == source && tail.iter().all(|&byte| byte == 0x5A), "rtl-sid-attribute-arrays: RtlCopyLuidAndAttributesArray copia as entradas de 12 bytes e nada alem de Count");
}

// ---- Vetores de correlação -----------------------------------------------------

const GUID: [u8; 16] = [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
const BASE16: &str = "EDJUdpi63P4BI0Vn";
const BASE22: &str = "EDJUdpi63P4BI0VniavN7w";

/// Um CORRELATION_VECTOR com a versão e o texto dados (o resto zerado).
fn vector(version: u8, text: &str) -> u64 {
    let block = zeroed(nt::CorrelationVector::SIZE);
    // SAFETY: CORRELATION_VECTOR recém-alocado.
    let vector = unsafe { nt::CorrelationVector::at(block) };
    vector.version.set(version);
    for (cell, &byte) in vector.vector.iter().zip(text.as_bytes()) {
        cell.set(byte);
    }
    block
}

/// O texto até o NUL.
fn vector_text(block: u64) -> Vec<u8> {
    // SAFETY: CORRELATION_VECTOR deste teste.
    unsafe { nt::CorrelationVector::at(block) }.vector.iter().map(|cell| cell.get()).take_while(|&byte| byte != 0).collect()
}

fn correlation_vector(assert: Assert) {
    let guid = guest::alloc_bytes(16);
    guest::write_bytes(guid, &GUID);
    let first = filled(nt::CorrelationVector::SIZE, 0x5A);
    let v1 = status("RtlInitializeCorrelationVector", &[first, 1, guid]);
    let second = filled(nt::CorrelationVector::SIZE, 0x5A);
    let v2 = status("RtlInitializeCorrelationVector", &[second, 2, guid]);
    let refused = filled(nt::CorrelationVector::SIZE, 0x5A);
    let bad = [status("RtlInitializeCorrelationVector", &[refused, 0, guid]), status("RtlInitializeCorrelationVector", &[refused, 3, guid]), status("RtlInitializeCorrelationVector", &[refused, 1, 0])];
    // SAFETY: o CORRELATION_VECTOR deste teste.
    let second_version = unsafe { nt::CorrelationVector::at(second) }.version.get();
    let mut v1_bytes = alloc::vec![1u8];
    v1_bytes.extend_from_slice(b"EDJUdpi63P4BI0Vn.0\0N7w==\0");
    v1_bytes.resize(nt::CorrelationVector::SIZE as usize, 0);
    assert(
        v1 == 0 && guest::read_bytes(first, nt::CorrelationVector::SIZE as usize) == v1_bytes && v2 == 0 && second_version == 2 && vector_text(second) == alloc::format!("{BASE22}.0").as_bytes() && bad == [STATUS_INVALID_PARAMETER; 3] && guest::read_bytes(refused, 130).iter().all(|&byte| byte == 0x5A),
        "rtl-correlation-vector: RtlInitializeCorrelationVector grava a base64 do GUID (16 ou 22 caracteres) com .0 e recusa versao ou GUID invalidos sem tocar no vetor",
    );

    let steps = [status("RtlIncrementCorrelationVector", &[second]), status("RtlExtendCorrelationVector", &[second]), status("RtlIncrementCorrelationVector", &[second])];
    let maximum = vector(1, &alloc::format!("{BASE16}.2147483647"));
    let wrapped = status("RtlIncrementCorrelationVector", &[maximum]);
    let carry = vector(1, &alloc::format!("{BASE16}{}.9", ".1".repeat(22)));
    let carried = status("RtlIncrementCorrelationVector", &[carry]);
    let tight = alloc::format!("{BASE16}{}.99", ".1".repeat(22));
    let full = vector(1, &tight);
    let overflowed = status("RtlIncrementCorrelationVector", &[full]);
    assert(
        steps == [0, 0, 0] && vector_text(second) == alloc::format!("{BASE22}.1.1").as_bytes() && wrapped == 0 && vector_text(maximum) == alloc::format!("{BASE16}.-2147483648").as_bytes() && carried == 0 && vector_text(carry) == alloc::format!("{BASE16}{}.10", ".1".repeat(22)).as_bytes() && overflowed == STATUS_BUFFER_OVERFLOW && vector_text(full) == tight.as_bytes(),
        "rtl-correlation-vector: RtlIncrementCorrelationVector soma 1 ao ultimo componente com %d e recusa o que nao cabe no buffer; RtlExtendCorrelationVector acrescenta .0",
    );

    let room = vector(1, &alloc::format!("{BASE16}{}", ".1".repeat(22)));
    let extended = status("RtlExtendCorrelationVector", &[room]);
    let edge = alloc::format!("{BASE16}{}.0", ".1".repeat(22));
    let no_room = vector(1, &edge);
    let refused_extend = [status("RtlExtendCorrelationVector", &[no_room]), status("RtlExtendCorrelationVector", &[vector(9, &alloc::format!("{BASE16}.0"))])];
    assert(
        extended == 0 && vector_text(room) == alloc::format!("{BASE16}{}.0", ".1".repeat(22)).as_bytes() && refused_extend == [STATUS_BUFFER_OVERFLOW; 2] && vector_text(no_room) == edge.as_bytes(),
        "rtl-correlation-vector: RtlExtendCorrelationVector recusa quando o fim chega a buffer - 3 e versao sem buffer",
    );

    let validations: [(u8, alloc::string::String, u32); 12] = [
        (1, alloc::format!("{BASE16}.0"), 0),
        (1, alloc::format!("{BASE16}.1.2147483647"), 0),
        (1, alloc::format!("{BASE16}.1.2147483648"), STATUS_INVALID_PARAMETER),
        (1, alloc::format!("{BASE16}."), STATUS_INVALID_PARAMETER),
        (1, alloc::format!("{BASE16}..1"), STATUS_INVALID_PARAMETER),
        (1, alloc::format!("{BASE16}.01234567890"), STATUS_INVALID_PARAMETER),
        (1, alloc::string::String::from(BASE16), STATUS_INVALID_PARAMETER),
        (2, alloc::format!("{BASE22}.7"), 0),
        (2, alloc::format!("{BASE16}.7"), STATUS_INVALID_PARAMETER),
        (1, alloc::format!("{BASE22}.7"), STATUS_INVALID_PARAMETER),
        (3, alloc::format!("{BASE16}.0"), STATUS_INVALID_PARAMETER),
        (2, alloc::format!("{BASE22}.1x"), STATUS_INVALID_PARAMETER),
    ];
    let wrong: Vec<usize> = validations.iter().enumerate().filter(|(_, (version, text, expected))| status("RtlValidateCorrelationVector", &[vector(*version, text)]) != *expected).map(|(index, _)| index).collect();
    let null = status("RtlValidateCorrelationVector", &[0]);
    assert(wrong.is_empty() && null == STATUS_INVALID_PARAMETER, "rtl-correlation-vector: RtlValidateCorrelationVector confere a base da versao e os componentes de 1 a 10 digitos ate 2147483647");
}

// ---- RtlCrc32 ------------------------------------------------------------------

fn crc32(assert: Assert) {
    let check = |bytes: &[u8], initial: u64| {
        let block = guest::alloc_bytes(bytes.len().max(1) as u64);
        guest::write_bytes(block, bytes);
        call("RtlCrc32", &[block, bytes.len() as u64, initial]) as u32
    };
    let sequence: Vec<u8> = (0..200u8).collect();
    let values = [check(&b"123456789"[..], 0), check(&b"OpenNT kernel"[..], 0x1234_5678), check(&[], 0xDEAD_BEEF), check(&sequence, 0)];
    assert(values == [0xE306_9283, 0x2BA6_E727, 0xDEAD_BEEF, 0xD90B_E573], "rtl-crc32: RtlCrc32 e o CRC-32C encadeavel (Castagnoli), nao o CRC IEEE do RtlComputeCrc32");
}

// ---- RtlOpenCurrentUser --------------------------------------------------------

fn open_current_user(assert: Assert) {
    // O caminho do usuário do token efetivo (o SYSTEM das threads de sistema).
    let path = zeroed(nt::UnicodeString::SIZE);
    let formatted = status("RtlFormatCurrentUserKeyPath", &[path]);
    // SAFETY: a UNICODE_STRING recém-preenchida.
    let string = unsafe { nt::UnicodeString::at(path) };
    let text = guest_strings::read_wide_string(string.buffer.get());
    let user = "\\REGISTRY\\USER\\S-1-5-18";
    let shape = (formatted, string.length.get(), string.maximum_length.get());
    call("RtlFreeUnicodeString", &[path]);
    assert(shape == (0, user.len() as u16 * 2, 0x1C + 0x16 + 0x22) && text == user, "rtl-current-user-key: RtlFormatCurrentUserKeyPath monta \\REGISTRY\\USER\\<SID> do token efetivo com o teto do RtlLengthSidAsUnicodeString");

    // Sem a chave do SYSTEM em \REGISTRY\USER, o RtlOpenCurrentUser abre o
    // perfil padrão, com um handle de kernel (OBJ_KERNEL_HANDLE: no OpenNT, o
    // handle nativo da chave, ligado ao processo do sistema).
    let handle = filled(8, 0xCC);
    let opened = status("RtlOpenCurrentUser", &[0x2_0019, handle]);
    let key = guest::read64(handle);
    let information = zeroed(0x100);
    let returned = zeroed(4);
    let queried = status("ZwQueryKey", &[key, 3, information, 0x100, returned]);
    let name_length = guest::read32(information) as usize / 2;
    let name: alloc::string::String = char::decode_utf16(wide_text(information + 4, name_length)).map(|unit| unit.unwrap_or('?')).collect();
    let closed = if opened == 0 { status("ZwClose", &[key]) } else { 0 };
    assert(
        opened == 0 && key != 0 && key != 0xCCCC_CCCC_CCCC_CCCC && queried == 0 && name.eq_ignore_ascii_case("\\REGISTRY\\USER\\.DEFAULT") && closed == 0,
        "rtl-current-user-key: RtlOpenCurrentUser cai no \\Registry\\User\\.Default quando a chave do usuario nao existe",
    );
}

// ---- RtlAppendUnicodeStringToString --------------------------------------------

/// Destino com Length/MaximumLength dados sobre um buffer preenchido com 0xCC
/// (o que não for escrito continua assim).
fn destination(prefix: &str, maximum: u16) -> (u64, u64) {
    let buffer = filled(maximum as u64 + 8, 0xCC);
    let units = guest_strings::wide_bytes_with_nul(prefix);
    guest::write_bytes(buffer, &units[..units.len() - 2]);
    let string = zeroed(nt::UnicodeString::SIZE);
    guest_strings::write_string_fields(string, (units.len() - 2) as u16, maximum, buffer);
    (string, buffer)
}

fn append_unicode_string(assert: Assert) {
    // SAFETY: UNICODE_STRINGs criadas por este teste.
    let length = |string: u64| unsafe { nt::UnicodeString::at(string) }.length.get();
    let source = unicode("Files");
    // Cabe exato (Length + 10 == MaximumLength): aceito, sem NUL depois.
    let (exact, exact_buffer) = destination("C:\\Program ",32);
    let exact_status = status("RtlAppendUnicodeStringToString", &[exact, source]);
    let exact_text = guest::read_bytes(exact_buffer, 34);
    // Com folga: o NUL vai logo depois do texto.
    let (roomy, roomy_buffer) = destination("C:\\Program ",40);
    let roomy_status = status("RtlAppendUnicodeStringToString", &[roomy, source]);
    // Um byte a menos: STATUS_BUFFER_TOO_SMALL sem tocar no destino.
    let (small, small_buffer) = destination("C:\\Program ",31);
    let small_status = status("RtlAppendUnicodeStringToString", &[small, source]);
    // Origem vazia: nada muda, mesmo com o destino cheio.
    let empty = unicode_with("", 0, 2);
    let empty_status = status("RtlAppendUnicodeStringToString", &[small, empty]);
    let expected: alloc::vec::Vec<u8> = "C:\\Program Files".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert(
        exact_status == 0 && length(exact) == 32 && exact_text[..32] == expected[..] && exact_text[32..34] == [0xCC, 0xCC]
            && roomy_status == 0 && length(roomy) == 32 && guest::read16(roomy_buffer + 32) == 0
            && small_status == STATUS_BUFFER_TOO_SMALL && length(small) == 22 && guest::read16(small_buffer + 22) == 0xCCCC
            && empty_status == 0 && length(small) == 22,
        "rtl-append-unicode: RtlAppendUnicodeStringToString aceita destino exato sem NUL, grava o NUL com folga e recusa com STATUS_BUFFER_TOO_SMALL",
    );
}
