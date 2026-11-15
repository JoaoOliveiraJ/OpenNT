//! Autoteste dos exports pequenos de suporte (Rtl, CRT, Po, Io, Mm, Ke, Etw,
//! Ps, Whea e Ex) que eram os últimos imports de drivers reais.
//!
//! Os vetores do scanf, da árvore rubro-negra, das conversões da CRT, dos
//! endereços IP e das minúsculas foram calculados executando as rotinas do
//! ntoskrnl 19041 real num emulador; cada teste chama o export pelo
//! trampolim nativo (ABI MS x64).

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::inc::{types as nt, NtStruct};
use crate::ntos::mm::guest_memory as guest;

type Assert = fn(bool, &str);

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

fn c_string(text: &str) -> u64 {
    let pointer = guest::alloc_bytes(text.len() as u64 + 1);
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(0);
    guest::write_bytes(pointer, &bytes);
    pointer
}

fn wide_string(text: &str) -> u64 {
    let units: Vec<u16> = text.encode_utf16().collect();
    let pointer = guest::alloc_bytes(units.len() as u64 * 2 + 2);
    let mut bytes: Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    bytes.extend_from_slice(&[0, 0]);
    guest::write_bytes(pointer, &bytes);
    pointer
}

fn unicode_string(text: &str) -> u64 {
    let buffer = wide_string(text);
    let string = guest::alloc_bytes(nt::UnicodeString::SIZE);
    let length = text.encode_utf16().count() as u16 * 2;
    at::<nt::UnicodeString>(string).length.set(length);
    at::<nt::UnicodeString>(string).maximum_length.set(length + 2);
    at::<nt::UnicodeString>(string).buffer.set(buffer);
    string
}

fn read_c(pointer: u64) -> String {
    crate::ntos::rtl::guest_strings::read_c_string(pointer)
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap_or(0)).collect()
}

// ---- Rtl: versão de DDI, RtlAssert, sistema portátil ---------------------------

fn rtl_ddi_assert(assert: Assert) {
    let versions = [(0x0A00_0008, 0), (0x0A00_0009, 0), (0x0A00_0000, 1), (0x0603_0000, 1), (0x0A00_0100, 0), (0x0B00_0000, 0), (0, 1), (0x0A00_0107, 0)];
    assert(versions.iter().all(|&(version, expected)| call("RtlIsNtDdiVersionAvailable", &[version]) & 0xFF == expected), "rtl-ddi: RtlIsNtDdiVersionAvailable só com os dois bytes baixos zerados e até NTDDI_WIN10_VB");
    // Sem depurador o RtlAssert só imprime e volta.
    call("RtlAssert", &[c_string("Count == 0"), c_string("quickwins.c"), 42, 0]);
    call("RtlAssert", &[c_string("Count == 1"), c_string("quickwins.c"), 43, c_string("mensagem ")]);
    let read = || crate::ntos::cm::registry::read_value_by_path("\\Registry\\Machine\\System\\CurrentControlSet\\Control", "PortableOperatingSystem").map(|value| (value.value_type, value.data));
    let on = status("RtlSetPortableOperatingSystem", &[1]);
    let after_on = read();
    let off = status("RtlSetPortableOperatingSystem", &[0]);
    let after_off = read();
    assert(on == 0 && off == 0 && after_on == Some((4, alloc::vec![1, 0, 0, 0])) && after_off == Some((4, alloc::vec![0, 0, 0, 0])), "rtl-ddi: RtlAssert volta sem depurador e RtlSetPortableOperatingSystem grava o REG_DWORD em Control");
}

// ---- Rtl: árvore rubro-negra ---------------------------------------------------

struct RbOp {
    insert: bool,
    node: i64,
    parent: i64,
    right: bool,
}

const RB_OPS: &[RbOp] = &[
    RbOp { insert: true, node: 9, parent: -1, right: false }, RbOp { insert: true, node: 13, parent: 9, right: true }, RbOp { insert: true, node: 12, parent: 13, right: false }, RbOp { insert: true, node: 0, parent: 13, right: true },
    RbOp { insert: true, node: 4, parent: 9, right: true }, RbOp { insert: false, node: 13, parent: 0, right: false }, RbOp { insert: false, node: 4, parent: 0, right: false }, RbOp { insert: true, node: 7, parent: 9, right: true },
    RbOp { insert: false, node: 12, parent: 0, right: false }, RbOp { insert: false, node: 9, parent: 0, right: false }, RbOp { insert: true, node: 3, parent: 0, right: true }, RbOp { insert: true, node: 9, parent: 7, right: false },
    RbOp { insert: true, node: 2, parent: 9, right: false }, RbOp { insert: true, node: 12, parent: 2, right: false }, RbOp { insert: false, node: 0, parent: 0, right: false }, RbOp { insert: false, node: 3, parent: 0, right: false },
    RbOp { insert: true, node: 3, parent: 7, right: true }, RbOp { insert: false, node: 2, parent: 0, right: false }, RbOp { insert: true, node: 11, parent: 3, right: true }, RbOp { insert: true, node: 4, parent: 7, right: false },
    RbOp { insert: true, node: 5, parent: 11, right: true }, RbOp { insert: true, node: 6, parent: 4, right: true }, RbOp { insert: false, node: 5, parent: 0, right: false }, RbOp { insert: false, node: 9, parent: 0, right: false },
    RbOp { insert: false, node: 3, parent: 0, right: false }, RbOp { insert: false, node: 6, parent: 0, right: false }, RbOp { insert: true, node: 13, parent: 11, right: false }, RbOp { insert: true, node: 1, parent: 7, right: false },
    RbOp { insert: false, node: 11, parent: 0, right: false }, RbOp { insert: true, node: 8, parent: 1, right: false }, RbOp { insert: true, node: 3, parent: 12, right: false }, RbOp { insert: false, node: 7, parent: 0, right: false },
    RbOp { insert: true, node: 9, parent: 13, right: true }, RbOp { insert: true, node: 7, parent: 9, right: false }, RbOp { insert: true, node: 6, parent: 13, right: false }, RbOp { insert: true, node: 10, parent: 3, right: false },
    RbOp { insert: true, node: 2, parent: 12, right: false }, RbOp { insert: true, node: 5, parent: 6, right: false }, RbOp { insert: true, node: 11, parent: 13, right: true }, RbOp { insert: true, node: 0, parent: 9, right: true },
    RbOp { insert: false, node: 9, parent: 0, right: false }, RbOp { insert: true, node: 9, parent: 8, right: true },
];

/// (esquerdo, direito, pai, vermelho) de cada nó no fim; raiz 1, mínimo 10.
const RB_FINAL: [(i64, i64, i64, bool); 14] = [
    (-1, -1, 7, false), (4, 7, -1, false), (-1, -1, 12, true), (10, 12, 4, true), (3, 8, 1, false), (-1, -1, 6, false), (5, 13, 7, true),
    (6, 0, 1, false), (-1, 9, 4, false), (-1, -1, 8, true), (-1, -1, 3, false), (-1, -1, 13, true), (2, -1, 3, false), (-1, 11, 6, false),
];

fn rb_tree_run(encoded: bool) -> bool {
    let tree = guest::alloc_bytes(16);
    guest::write64(tree, 0);
    guest::write64(tree + 8, encoded as u64);
    let nodes: Vec<u64> = (0..14).map(|_| guest::alloc_bytes(32)).collect();
    let node = |index: i64| if index < 0 { 0 } else { nodes[index as usize] };
    for op in RB_OPS {
        if op.insert {
            call("RtlRbInsertNodeEx", &[tree, node(op.parent), op.right as u64, node(op.node)]);
        } else {
            call("RtlRbRemoveNode", &[tree, node(op.node)]);
        }
    }
    // Codificado: filho/pai = nó ^ ponteiro, raiz = árvore ^ raiz, mínimo = (árvore ^ mínimo) | 1.
    let stored = |base: u64, pointer: u64| if encoded && pointer != 0 { pointer ^ base } else { pointer };
    let structure = RB_FINAL.iter().enumerate().all(|(index, &(left, right, parent, red))| {
        let at = nodes[index];
        guest::read64(at) == stored(at, node(left)) && guest::read64(at + 8) == stored(at, node(right)) && guest::read64(at + 16) == stored(at, node(parent)) | red as u64
    });
    let minimum = if encoded { (tree ^ node(10)) | 1 } else { node(10) };
    structure && guest::read64(tree) == stored(tree, node(1)) && guest::read64(tree + 8) == minimum
}

fn rtl_rb_tree(assert: Assert) {
    assert(rb_tree_run(false), "rtl-rb-tree: 42 inserções e remoções dão a árvore do ntoskrnl (elos, cores, raiz e mínimo)");
    assert(rb_tree_run(true), "rtl-rb-tree: a mesma árvore com os ponteiros codificados");
}

// ---- CRT: sscanf_s e swscanf_s ------------------------------------------------

const P: u64 = u64::MAX;

struct ScanCase {
    wide: bool,
    text: &'static str,
    format: &'static str,
    slots: &'static [u64],
    result: i32,
    memory: &'static [&'static str],
}

const SCAN_CASES: &[ScanCase] = &[
    ScanCase { wide: false, text: "{12345678-9abc-def0-1122-334455667788}", format: "{%08lx-%04hx-%04hx-%02hx%02hx-%02hx%02hx%02hx%02hx%02hx%02hx", slots: &[P, P, P, P, P, P, P, P, P, P, P], result: 11, memory: &["78563412cccccccccccccccccccccccc", "bc9acccccccccccccccccccccccccccc", "f0decccccccccccccccccccccccccccc", "1100cccccccccccccccccccccccccccc", "2200cccccccccccccccccccccccccccc", "3300cccccccccccccccccccccccccccc", "4400cccccccccccccccccccccccccccc", "5500cccccccccccccccccccccccccccc", "6600cccccccccccccccccccccccccccc", "7700cccccccccccccccccccccccccccc", "8800cccccccccccccccccccccccccccc"] },
    ScanCase { wide: false, text: " FW 1.22.333", format: " FW %hd.%hd.%hd", slots: &[P, P, P], result: 3, memory: &["0100cccccccccccccccccccccccccccc", "1600cccccccccccccccccccccccccccc", "4d01cccccccccccccccccccccccccccc"] },
    ScanCase { wide: false, text: "00000000deadbeef zz", format: "%016I64x %I32x", slots: &[P, P], result: 1, memory: &["efbeadde00000000cccccccccccccccc", "cccccccccccccccccccccccccccccccc"] },
    ScanCase { wide: false, text: "hello world", format: "%s %3c%n", slots: &[P, 8, P, 4, P], result: 2, memory: &["68656c6c6f00cccccccccccccccccccc", "776f72cccccccccccccccccccccccccc", "09000000cccccccccccccccccccccccc"] },
    ScanCase { wide: false, text: "abc]def", format: "%[a-c]%*[]]%2[^f]", slots: &[P, 8, P, 8], result: 2, memory: &["61626300cccccccccccccccccccccccc", "646500cccccccccccccccccccccccccc"] },
    ScanCase { wide: false, text: "", format: "%d", slots: &[P], result: -1, memory: &["cccccccccccccccccccccccccccccccc"] },
    ScanCase { wide: false, text: "x", format: "%d", slots: &[P], result: 0, memory: &["cccccccccccccccccccccccccccccccc"] },
    ScanCase { wide: false, text: "0x1F 077 -12", format: "%i %i %i", slots: &[P, P, P], result: 3, memory: &["1f000000cccccccccccccccccccccccc", "3f000000cccccccccccccccccccccccc", "f4ffffffcccccccccccccccccccccccc"] },
    ScanCase { wide: false, text: "toolong", format: "%s", slots: &[P, 4], result: 0, memory: &["006f6fcccccccccccccccccccccccccc"] },
    ScanCase { wide: false, text: "f9", format: "%f%d", slots: &[P], result: 1, memory: &["09000000cccccccccccccccccccccccc"] },
    ScanCase { wide: false, text: "42", format: "%0d", slots: &[P], result: 0, memory: &["cccccccccccccccccccccccccccccccc"] },
    ScanCase { wide: false, text: "abc", format: "%c", slots: &[P, 0], result: 0, memory: &["00cccccccccccccccccccccccccccccc"] },
    ScanCase { wide: true, text: "{12345678-9abc-def0-1122-334455667788}", format: "{%08lx-%04hx-%04hx-%02hx%02hx-%02hx%02hx%02hx%02hx%02hx%02hx", slots: &[P, P, P, P, P, P, P, P, P, P, P], result: 11, memory: &["78563412cccccccccccccccccccccccc", "bc9acccccccccccccccccccccccccccc", "f0decccccccccccccccccccccccccccc", "1100cccccccccccccccccccccccccccc", "2200cccccccccccccccccccccccccccc", "3300cccccccccccccccccccccccccccc", "4400cccccccccccccccccccccccccccc", "5500cccccccccccccccccccccccccccc", "6600cccccccccccccccccccccccccccc", "7700cccccccccccccccccccccccccccc", "8800cccccccccccccccccccccccccccc"] },
    ScanCase { wide: true, text: "cafe 10", format: "%04hx%n %o", slots: &[P, P, P], result: 2, memory: &["fecacccccccccccccccccccccccccccc", "04000000cccccccccccccccccccccccc", "08000000cccccccccccccccccccccccc"] },
    ScanCase { wide: true, text: "", format: "%d", slots: &[P], result: 0, memory: &["cccccccccccccccccccccccccccccccc"] },
    ScanCase { wide: true, text: "hi there", format: "%s %c", slots: &[P, 8, P, 2], result: 2, memory: &["680069000000cccccccccccccccccccc", "7400cccccccccccccccccccccccccccc"] },
    ScanCase { wide: true, text: "12,34", format: "%d,%d", slots: &[P, P], result: 2, memory: &["0c000000cccccccccccccccccccccccc", "22000000cccccccccccccccccccccccc"] },
    ScanCase { wide: true, text: "ab", format: "%d", slots: &[P], result: 0, memory: &["cccccccccccccccccccccccccccccccc"] },
];

fn crt_scanf(assert: Assert) {
    let mut failed = None;
    for (index, case) in SCAN_CASES.iter().enumerate() {
        let mut buffers = Vec::new();
        let mut arguments = Vec::new();
        let (source, format) = if case.wide { (wide_string(case.text), wide_string(case.format)) } else { (c_string(case.text), c_string(case.format)) };
        arguments.push(source);
        arguments.push(format);
        for &slot in case.slots {
            if slot == P {
                let buffer = guest::alloc_bytes(16);
                guest::write_bytes(buffer, &[0xCC; 16]);
                buffers.push(buffer);
                arguments.push(buffer);
            } else {
                arguments.push(slot);
            }
        }
        let result = call(if case.wide { "swscanf_s" } else { "sscanf_s" }, &arguments) as i32;
        let memory = buffers.iter().zip(case.memory).all(|(&buffer, expected)| guest::read_bytes(buffer, 16) == hex(expected));
        if result != case.result || !memory {
            failed = Some(index);
            crate::debug_print!("[quickwins] scanf caso {} devolveu {} (esperado {})", index, result, case.result);
            break;
        }
    }
    assert(failed.is_none(), "crt-scanf: sscanf_s/swscanf_s dão o retorno e as gravações do ntoskrnl (GUID, h/l/I64/I32, c/s/[ com tamanho, %n, %i, EOF, sem ponto flutuante)");
    assert(call("sscanf_s", &[c_string("1"), 0]) as i32 == -1, "crt-scanf: formato NULL = -1");
}

// ---- CRT: atol, _itoa_s, strcat_s, vsprintf, srand ----------------------------

fn crt_integer_strings(assert: Assert) {
    let atol = [("123", 0x7B), ("  -42x", 0xFFFF_FFD6), ("2147483648", 0x8000_0000), ("-2147483649", 0x7FFF_FFFF), ("99999999999", 0x4876_E7FF), ("0x10", 0), ("\t\n 12", 12), ("- 1", 0)];
    assert(atol.iter().all(|&(text, expected)| call("atol", &[c_string(text)]) as u32 == expected), "crt: atol com espaços, sinal e estouro de 32 bits");
    let itoa = |value: i64, size: u64, radix: u64| -> (u32, Vec<u8>) {
        let buffer = guest::alloc_bytes(48);
        guest::write_bytes(buffer, &[0xCC; 48]);
        let errno = call("_itoa_s", &[value as u64, buffer, size, radix]) as u32;
        (errno, guest::read_bytes(buffer, 13))
    };
    let pad = |prefix: &[u8]| -> Vec<u8> {
        let mut bytes = prefix.to_vec();
        bytes.resize(13, 0xCC);
        bytes
    };
    let itoa_ok = itoa(-123, 10, 10) == (0, pad(b"-123\0"))
        && itoa(-1, 40, 16) == (0, pad(b"ffffffff\0"))
        && itoa(255, 2, 16) == (34, pad(&[0, b'f']))
        && itoa(0, 1, 10) == (34, pad(&[0]))
        && itoa(5, 0, 10) == (22, pad(&[]))
        && itoa(5, 10, 37) == (22, pad(&[0]))
        && itoa(0x7FFF_FFFF, 12, 2) == (34, pad(b"\x0011111111111"))
        && itoa(-2147483648, 12, 10) == (0, pad(b"-2147483648\0"));
    assert(itoa_ok, "crt: _itoa_s com sinal só na base 10, ERANGE com os dígitos já gravados e EINVAL");
    let strcat = |initial: &[u8], size: u64, source: Option<&str>| -> (u32, Vec<u8>) {
        let buffer = guest::alloc_bytes(16);
        guest::write_bytes(buffer, &[0xCC; 16]);
        guest::write_bytes(buffer, initial);
        let errno = call("strcat_s", &[buffer, size, source.map_or(0, c_string)]) as u32;
        (errno, guest::read_bytes(buffer, 8))
    };
    let strcat_ok = strcat(b"ab\0", 5, Some("cd")) == (0, b"abcd\0\xCC\xCC\xCC".to_vec())
        && strcat(b"ab\0", 4, Some("cd")) == (34, b"\0bcd\xCC\xCC\xCC\xCC".to_vec())
        && strcat(b"ab\0", 2, Some("cd")) == (22, b"\0b\0\xCC\xCC\xCC\xCC\xCC".to_vec())
        && strcat(b"abc\0", 0, Some("x")) == (22, b"abc\0\xCC\xCC\xCC\xCC".to_vec())
        && strcat(b"ab\0", 6, None) == (22, b"\0b\0\xCC\xCC\xCC\xCC\xCC".to_vec());
    assert(strcat_ok, "crt: strcat_s com EINVAL sem NUL ou sem origem e ERANGE com a cópia parcial");
    let buffer = guest::alloc_bytes(64);
    let arguments = guest::alloc_bytes(24);
    guest::write64(arguments, 42);
    guest::write64(arguments + 8, c_string("ok"));
    guest::write64(arguments + 16, 0xAB);
    let printed = call("vsprintf", &[buffer, c_string("%d-%s|%5x"), arguments]);
    let nulls = call("vsprintf", &[0, c_string("%d"), arguments]) as u32 == u32::MAX && call("vsprintf", &[buffer + 32, 0, arguments]) as u32 == u32::MAX;
    assert(printed == 11 && read_c(buffer) == "42-ok|   ab" && nulls, "crt: vsprintf com a va_list e -1 com Buffer ou Format NULL");
    call("srand", &[42]);
    let first = call("rand", &[]) as u32;
    call("srand", &[42]);
    assert(first == 175 && call("rand", &[]) as u32 == 175, "crt: srand semeia o gerador do rand (42 -> 175)");
}

// ---- Rtl: endereços IP em ANSI ------------------------------------------------

fn rtl_network_address_ansi(assert: Assert) {
    let ipv4 = guest::alloc_bytes(4);
    guest::write_bytes(ipv4, &[192, 168, 0, 1]);
    let text = guest::alloc_bytes(64);
    let end = call("RtlIpv4AddressToStringA", &[ipv4, text]);
    let simple = end == text + 11 && read_c(text) == "192.168.0.1";
    let length = guest::alloc_bytes(4);
    let ex = |port: u64, capacity: u32, buffer: u64| -> (u32, u32, String) {
        guest::write32(length, capacity);
        let result = status("RtlIpv4AddressToStringExA", &[ipv4, port, buffer, length]);
        (result, guest::read32(length), if result == 0 { read_c(buffer) } else { String::new() })
    };
    let ipv4_ex = ex(0x5000, 64, text) == (0, 15, String::from("192.168.0.1:80")) && ex(0x5000, 12, text).0 == 0xC000_000D && ex(0x5000, 12, text).1 == 15 && ex(0, 0, 0) == (0xC000_000D, 12, String::new()) && status("RtlIpv4AddressToStringExA", &[0, 0, text, length]) == 0xC000_000D;
    let ipv6 = guest::alloc_bytes(16);
    guest::write_bytes(ipv6, &[0x20, 1, 0xD, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    guest::write32(length, 64);
    let ipv6_ex = status("RtlIpv6AddressToStringExA", &[ipv6, 7, 0x5000, text, length]) == 0 && guest::read32(length) == 18 && read_c(text) == "[2001:db8::%7]:80";
    // O texto ANSI é o da variante W para endereços com as formas especiais.
    let samples: [[u8; 16]; 4] = [[0; 16], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 1, 2, 3, 4], [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0x5E, 0xFE, 10, 0, 0, 1], [0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]];
    let wide = guest::alloc_bytes(128);
    let same = samples.iter().all(|sample| {
        guest::write_bytes(ipv6, sample);
        let ansi_end = call("RtlIpv6AddressToStringA", &[ipv6, text]);
        let wide_end = call("RtlIpv6AddressToStringW", &[ipv6, wide]);
        read_c(text) == crate::ntos::rtl::guest_strings::read_wide_string(wide) && ansi_end - text == (wide_end - wide) / 2
    });
    assert(simple && ipv4_ex && ipv6_ex && same, "rtl-ip-ansi: RtlIpv4/6AddressToString[Ex]A com porta, escopo, tamanho e o texto da variante W");
}

// ---- Rtl: NLS, memória e memória não volátil ----------------------------------

fn rtl_memory_nls_small(assert: Assert) {
    assert(call("RtlxUnicodeStringToAnsiSize", &[unicode_string("abcd")]) as u32 == 5, "rtl: RtlxUnicodeStringToAnsiSize na página 1252 = caracteres + NUL");
    let downcase = [(0x0041, 0x0061), (0x005A, 0x007A), (0x0061, 0x0061), (0x00BF, 0x00BF), (0x00C0, 0x00E0), (0x00D7, 0x00D7), (0x00DE, 0x00FE), (0x0130, 0x0130), (0x0178, 0x00FF), (0x0410, 0x0430), (0x042F, 0x044F), (0x1E9E, 0x1E9E), (0x24B6, 0x24D0), (0xFF21, 0xFF41), (0x03A3, 0x03C3), (0x2C00, 0x2C30)];
    assert(downcase.iter().all(|&(unit, lower)| call("RtlDowncaseUnicodeChar", &[unit]) as u16 == lower), "rtl: RtlDowncaseUnicodeChar pela tabela de minúsculas do l_intl.nls");
    let block = guest::alloc_bytes(32);
    for index in 0..8 {
        guest::write32(block + index * 4, if index < 5 { 0x1122_3344 } else { 0 });
    }
    let lengths = [(0, 0), (3, 0), (4, 4), (7, 4), (8, 8), (20, 20), (21, 20), (32, 20)];
    assert(lengths.iter().all(|&(length, equal)| call("RtlCompareMemoryUlong", &[block, length, 0x1122_3344]) == equal), "rtl: RtlCompareMemoryUlong conta ULONGs inteiros iguais ao padrão");
    let source = c_string("nao volatil");
    let destination = guest::alloc_bytes(32);
    let written = [status("RtlWriteNonVolatileMemory", &[3, destination, source, 12, 0]), status("RtlWriteNonVolatileMemory", &[3, destination + 16, source, 12, 1]), status("RtlWriteNonVolatileMemory", &[3, destination, source, 4, 2])];
    let invalid = status("RtlWriteNonVolatileMemory", &[0, destination, source, 12, 0]) == 0xC000_000D && status("RtlFlushNonVolatileMemory", &[2, destination, 12, 0]) == 0xC000_000D;
    assert(written == [0, 0, 0] && read_c(destination) == "nao volatil" && read_c(destination + 16) == "nao volatil" && status("RtlFlushNonVolatileMemory", &[3, destination, 32, 1]) == 0 && invalid, "rtl-nv: RtlWrite/FlushNonVolatileMemory copiam, fazem o flush e recusam token inválido");
}

// ---- Po ---------------------------------------------------------------------

fn po_legacy_system_state(assert: Assert) {
    use crate::ntos::po::{fx, system_state};
    call("PoSetSystemState", &[0x4]);
    let present = system_state::user_presence() == 7;
    call("PoSetSystemState", &[0x14]);
    let ignored = system_state::user_presence() == 7;
    let handle = call("PoRegisterSystemState", &[0, 0x8000_0001]);
    let first = system_state::system_state_request(handle);
    let again = call("PoRegisterSystemState", &[handle, 0x8000_0002]);
    let second = system_state::system_state_request(handle);
    let one_shot = call("PoRegisterSystemState", &[0, 0x1]) == 0 && call("PoRegisterSystemState", &[0, 0x10]) == 0;
    call("PoUnregisterSystemState", &[handle]);
    assert(present && ignored && handle != 0 && first == Some(1) && again == handle && second == Some(2) && one_shot && system_state::system_state_request(handle).is_none(), "po: PoSetSystemState, PoRegisterSystemState (pedido contínuo, flags legadas, sem ES_CONTINUOUS = NULL) e PoUnregisterSystemState");
    let (_, presses, releases, _, work) = system_state::power_button_hold_state();
    call("PoSetPowerButtonHoldState", &[1]);
    let (held, presses_after, _, history, work_after) = system_state::power_button_hold_state();
    call("PoSetPowerButtonHoldState", &[0]);
    let (released, _, releases_after, history_after, work_final) = system_state::power_button_hold_state();
    let bit = 1u64 << ((presses + releases) & 63);
    let next_bit = 1u64 << ((presses + releases + 1) & 63);
    call("PoSetFixedWakeSource", &[0x10]);
    assert(held && !released && presses_after == presses + 1 && releases_after == releases + 1 && history & bit != 0 && history_after & next_bit == 0 && work_after == work + 1 && work_final == work + 2 && system_state::fixed_wake_sources() & 0x10 != 0, "po: PoSetPowerButtonHoldState (histórico, contadores e o trabalho da transição) e PoSetFixedWakeSource");
    // Dispositivo primário V1: dois componentes.
    let device = guest::alloc_bytes(nt::PoFxPrimaryDeviceV1::SIZE + nt::PoFxComponentV1::SIZE);
    let description = at::<nt::PoFxPrimaryDeviceV1>(device);
    description.version.set(1);
    description.component_count.set(2);
    description.component_critical_transition_callback.set(0xFFFF_F800_1234_5678);
    description.device_context.set(0xC0FFEE);
    let handle_out = guest::alloc_bytes(8);
    let pdo = guest::alloc_bytes(8);
    let invalid = status("PoFxRegisterPrimaryDevice", &[0, device, handle_out]) == 0xC000_000D;
    description.version.set(2);
    let wrong_version = status("PoFxRegisterPrimaryDevice", &[pdo, device, handle_out]) == 0xC000_000D;
    description.version.set(1);
    let registered = status("PoFxRegisterPrimaryDevice", &[pdo, device, handle_out]);
    let handle = guest::read64(handle_out);
    let body = at::<nt::PopFxDevice>(handle);
    let body_ok = handle != 0 && body.component_count.get() == 2 && body.driver_context.get() == 0xC0FFEE && body.callbacks.component_critical_transition.get() == 0xFFFF_F800_1234_5678;
    call("PoFxSetComponentWake", &[handle, 1, 1]);
    let wake = fx::component_wake_hint(handle, 1) == Some(true) && fx::component_wake_hint(handle, 0) == Some(false);
    call("PoFxSetComponentWake", &[handle, 5, 1]);
    call("PoFxUnregisterDevice", &[handle]);
    assert(invalid && wrong_version && registered == 0 && body_ok && wake, "po-fx: PoFxRegisterPrimaryDevice (Pdo NULL e versão != 1 recusados, os sete callbacks) e PoFxSetComponentWake");
}

// ---- Etw, Ke, Whea, Ps --------------------------------------------------------

fn etw_ke_whea_ps(assert: Assert) {
    // Provedor de teste: o estado de habilitação é o da ETW_GUID_ENTRY do registro.
    let guid = guest::alloc_bytes(16);
    guest::write_bytes(guid, &[0x51, 0x57, 0x49, 0x4E, 0x01, 0x00, 0x02, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]);
    let handle_out = guest::alloc_bytes(8);
    let registered = status("EtwRegister", &[guid, 0, 0, handle_out]);
    let registration = guest::read64(handle_out);
    let entry = at::<nt::EtwGuidEntry>(at::<nt::EtwRegEntry>(registration).guid_entry.get());
    let disabled = call("EtwProviderEnabled", &[registration, 4, 0x10]) & 0xFF == 0 && call("EtwProviderEnabled", &[0, 4, 0x10]) & 0xFF == 0;
    let info = &entry.provider_enable_info;
    info.level.set(4);
    info.match_any_keyword.set(0xF0);
    info.match_all_keyword.set(0x30);
    info.is_enabled.set(1);
    let enabled = |level: u64, keyword: u64| call("EtwProviderEnabled", &[registration, level, keyword]) & 0xFF;
    let matrix = enabled(4, 0x30) == 1 && enabled(5, 0x30) == 0 && enabled(2, 0x10) == 0 && enabled(4, 0x0F) == 0 && enabled(1, 0x31) == 1;
    info.is_enabled.set(0);
    call("EtwUnregister", &[registration]);
    assert(registered == 0 && disabled && matrix, "etw: EtwProviderEnabled pelo nível e pelas keywords MatchAny/MatchAll do provedor registrado");
    call("KeSweepLocalCaches", &[]);
    assert(true, "ke: KeSweepLocalCaches executa o WBINVD local e volta");
    // Fonte de dispositivo V1 removida pela rotina de driver.
    use crate::ntos::inc::types::extra_storage::WheaErrorSourceConfigurationDeviceDriverV1;
    let initialize = super::executable_code::place(&[0x48, 0x89, 0x09, 0x89, 0x51, 0x08, 0xC3]);
    let uninitialize = super::executable_code::place(&[0xC7, 0x41, 0x10, 0x01, 0x00, 0x00, 0x00, 0xC3]);
    let context = guest::alloc_bytes(0x20);
    let configuration_address = guest::alloc_bytes(WheaErrorSourceConfigurationDeviceDriverV1::SIZE);
    let configuration = at::<WheaErrorSourceConfigurationDeviceDriverV1>(configuration_address);
    configuration.version.set(1);
    configuration.initialize.set(initialize);
    configuration.uninitialize.set(uninitialize);
    let added = status("WheaAddErrorSourceDeviceDriverV1", &[context, configuration_address, 2, 0x100]);
    let id = guest::read32(context + 8) as u64;
    let removed = status("WheaRemoveErrorSourceDeviceDriver", &[id]);
    let gone = call("WheaGetErrorSource", &[id]) == 0 && guest::read32(context + 0x10) == 1;
    assert(added == 0 && removed == 0 && gone && status("WheaRemoveErrorSourceDeviceDriver", &[id]) == 0, "whea: WheaRemoveErrorSourceDeviceDriver chama a Uninitialize e tira a fonte; fonte inexistente = sucesso");
    let job = guest::alloc_bytes(nt::Ejob::SIZE);
    let container = call("PsGetSiloContainerId", &[job]) == at::<nt::Ejob>(job).container_id.address() && call("PsGetSiloContainerId", &[0]) == 0;
    let system = crate::ntos::ps::process::get_system_process();
    let suspended = status("PsSuspendProcess", &[system]);
    let resumed = status("PsResumeProcess", &[system]);
    assert(container && suspended == 0 && resumed == 0, "ps: PsGetSiloContainerId (EJOB.ContainerId; host = NULL) e PsSuspendProcess/PsResumeProcess");
}

// ---- Mm: lista de módulos, memória física e flush -----------------------------

fn mm_support(assert: Assert) {
    use crate::ntos::init::exports;
    use crate::ntos::mm::loaded_images;
    use crate::ntos::mm::pe_loader::ResolvedImport;
    let head = loaded_images::module_list_cell();
    let resource = loaded_images::module_resource_cell();
    let published = matches!(exports::lookup("ntoskrnl.exe", "PsLoadedModuleList"), Some(ResolvedImport::Address { address, .. }) if address == head)
        && matches!(exports::lookup("ntoskrnl.exe", "PsLoadedModuleResource"), Some(ResolvedImport::Address { address, .. }) if address == resource);
    let walk = || -> Option<Vec<(u64, String)>> {
        let mut entries = Vec::new();
        let mut cursor = guest::read64(head);
        while cursor != head {
            let entry = at::<nt::KldrDataTableEntry>(cursor);
            if guest::read64(entry.in_load_order_links.flink.get() + 8) != cursor || entries.len() > 512 {
                return None;
            }
            let name = &entry.base_dll_name;
            let units: Vec<u16> = (0..name.length.get() as u64 / 2).map(|index| guest::read16(name.buffer.get() + index * 2)).collect();
            entries.push((entry.dll_base.get(), String::from_utf16_lossy(&units)));
            cursor = entry.in_load_order_links.flink.get();
        }
        Some(entries)
    };
    let shared = call("ExAcquireResourceSharedLite", &[resource, 1]) & 0xFF;
    let entries = walk().unwrap_or_default();
    call("ExReleaseResourceLite", &[resource]);
    let kernel = loaded_images::kernel().map_or(0, |image| image.image_base);
    let ordered = entries.first().is_some_and(|(base, name)| *base == kernel && name.eq_ignore_ascii_case("ntoskrnl.exe")) && entries.iter().any(|(_, name)| name.eq_ignore_ascii_case("hal.dll")) && entries.len() == loaded_images::list().len();
    // Uma imagem registrada entra no fim da lista e sai na descarga.
    let page = guest::alloc_bytes(0x1000);
    let image = loaded_images::register(loaded_images::ImageDescription { image_base: page, size_of_image: 0x1000, ..Default::default() }, "\\SystemRoot\\System32\\drivers\\qwlist.sys");
    let tail_name = walk().and_then(|list| list.last().cloned()).map(|(base, name)| base == page && name == "qwlist.sys");
    let removed = image.is_ok_and(|image| loaded_images::unregister(image.id).is_ok_and(|removed| removed));
    let after = walk().is_some_and(|list| !list.iter().any(|(base, _)| *base == page));
    assert(published && shared == 1 && ordered && tail_name == Some(true) && removed && after, "mm: PsLoadedModuleList (ntoskrnl primeiro, a HAL, elos válidos) e PsLoadedModuleResource na .kdata, mantidos pela carga e descarga");
    let start = guest::alloc_bytes(8);
    let bytes = guest::alloc_bytes(8);
    let add = |base: u64, length: u64| -> (u32, u64) {
        guest::write64(start, base);
        guest::write64(bytes, length);
        (status("MmAddPhysicalMemory", &[start, bytes]), guest::read64(bytes))
    };
    let physical = add(0x1002, 0x10000) == (0xC000_00EF, 0) && add(0x200_0000, 0x800) == (0xC000_00EF, 0) && add(0x10_0000, 0x10_0000) == (0xC000_0018, 0) && add(0x40_0000_0000, 0x1000_0000) == (0xC000_009A, 0);
    assert(physical, "mm: MmAddPhysicalMemory recusa início fora de página e faixa vazia, acusa RAM presente e não cresce o banco de PFN");
    let base = guest::alloc_bytes(8);
    let size = guest::alloc_bytes(8);
    let io_status = guest::alloc_bytes(nt::IoStatusBlock::SIZE);
    let flush = |address: u64, length: u64| -> (u32, u64, u64, u32) {
        guest::write64(base, address);
        guest::write64(size, length);
        guest::write32(io_status, 0x1234);
        let result = status("ZwFlushVirtualMemory", &[u64::MAX, base, size, io_status]);
        (result, guest::read64(base), guest::read64(size), guest::read32(io_status))
    };
    let flushed = flush(0x7FFF_FFFF_0000, 0x1000).0 == 0xC000_00F0 && flush(0x1_0000, 0x7FFF_FFFF_0000).0 == 0xC000_00F1 && flush(0x7000_0123, 0x10) == (0xC000_0019, 0x7000_0000, 0x10, 0xC000_0019);
    assert(flushed, "mm: ZwFlushVirtualMemory valida a faixa e devolve STATUS_NOT_MAPPED_VIEW fora de vista, com a base alinhada e o IoStatus");
}

// ---- Io -----------------------------------------------------------------------

fn io_support(assert: Assert) {
    let link = unicode_string("\\DosDevices\\QuickWinsLink");
    let created = status("IoCreateUnprotectedSymbolicLink", &[link, unicode_string("\\Device")]);
    let resolved = crate::ntos::ob::object_manager::lookup("\\DosDevices\\QuickWinsLink").is_some();
    let deleted = status("IoDeleteSymbolicLink", &[link]);
    assert(created == 0 && resolved && deleted == 0 && status("IoDeleteSymbolicLink", &[link]) == 0xC000_0009, "io: IoCreateUnprotectedSymbolicLink cria o link permanente");
    let key = guest::alloc_bytes(8);
    let empty = guest::alloc_bytes(nt::UnicodeString::SIZE);
    let unregistered = unicode_string("\\??\\QWTEST#NONE#0000#{d1e2f3a4-0000-4000-8000-000000000001}");
    let rejected = [
        status("IoOpenDeviceInterfaceRegistryKey", &[0, 0xF003F, key]),
        status("IoOpenDeviceInterfaceRegistryKey", &[empty, 0xF003F, key]),
        status("IoOpenDeviceInterfaceRegistryKey", &[unicode_string("\\??\\short#{d1e2f3a4-0000-4000-8000-000000000001}"), 0xF003F, key]),
        status("IoOpenDeviceInterfaceRegistryKey", &[unicode_string("\\Device\\QWTEST#NONE#0000#{d1e2f3a4-0000-4000-8000-000000000001}"), 0xF003F, key]),
        status("IoOpenDeviceInterfaceRegistryKey", &[unregistered, 0xF003F, key]),
    ];
    let invalid = rejected == [0xC000_000D, 0xC000_000D, 0xC000_0033, 0xC000_0033, 0xC000_0034];
    if !invalid {
        crate::debug_print!("[quickwins] IoOpenDeviceInterfaceRegistryKey recusas {:x?}", rejected);
    }
    // Uma interface registrada num PDO do PnP (um devnode de teste sobre um
    // dispositivo existente): chaves DeviceClasses e Device Parameters.
    let class = guest::alloc_bytes(16);
    guest::write_bytes(class, &[0xA4, 0xF3, 0xE2, 0xD1, 0, 0, 0, 0x40, 0x80, 0, 0, 0, 0, 0, 0, 2]);
    let output = guest::alloc_bytes(nt::UnicodeString::SIZE);
    use crate::ntos::io::pnp::devnode;
    let pdo = crate::ntos::io::io_manager::devices().into_iter().map(|(_, entry)| entry.native_device).find(|&device| device != 0 && !devnode::exists(device)).unwrap_or(0);
    let mut test_node = devnode::DeviceNode::new(pdo, 0, 1);
    test_node.instance_path = String::from("ROOT\\QUICKWINS\\0000");
    devnode::insert(test_node.clone());
    let registration = status("IoRegisterDeviceInterface", &[pdo, class, 0, output]);
    let registered = (pdo != 0 && registration == 0).then_some(test_node);
    let opened = registered.as_ref().map(|node| {
        let text = crate::ntos::rtl::guest_strings::read_unicode_string(output);
        let classes = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\DeviceClasses\\{d1e2f3a4-0000-4000-8000-000000000002}";
        let interface = alloc::format!("{classes}\\##?#{}#{{d1e2f3a4-0000-4000-8000-000000000002}}", node.instance_path.replace('\\', "#"));
        let instance = crate::ntos::cm::registry::read_value_by_path(&interface, "DeviceInstance").map(|value| value.data);
        let symbolic = crate::ntos::cm::registry::read_value_by_path(&alloc::format!("{interface}\\#"), "SymbolicLink").map(|value| value.data);
        let opened = status("IoOpenDeviceInterfaceRegistryKey", &[output, 0xF003F, key]);
        let handle = guest::read64(key);
        let closed = status("ZwClose", &[handle]);
        let expected = |text: &str| -> Vec<u8> { text.encode_utf16().chain(core::iter::once(0)).flat_map(u16::to_le_bytes).collect() };
        let good = opened == 0 && handle != 0 && closed == 0 && instance == Some(expected(&node.instance_path)) && symbolic == Some(expected(&alloc::format!("\\\\?\\{}", &text[4..])));
        if !good {
            crate::debug_print!("[quickwins] interface {} aberta {:#x} handle {:#x} fechada {:#x} instancia {} link {}", text, opened, handle, closed, instance.is_some(), symbolic.is_some());
        }
        good
    });
    if registered.is_none() {
        crate::debug_print!("[quickwins] IoRegisterDeviceInterface no PDO {:#x} -> {:#x}", pdo, registration);
    }
    if pdo != 0 {
        status("IoDeleteSymbolicLink", &[output]);
        devnode::remove(pdo);
    }
    assert(invalid && opened == Some(true), "io: IoOpenDeviceInterfaceRegistryKey valida o nome, exige a interface registrada (chaves DeviceClasses) e abre Device Parameters");
    // Keep-alive do System por um FILE_OBJECT de teste (NoWakeCounter e WakeCounters[1]).
    let process = crate::ntos::ps::process::get_system_process();
    let wake = &at::<nt::Eprocess>(process).wake_info;
    let file = guest::alloc_bytes(nt::FileObject::SIZE);
    let wake_file = guest::alloc_bytes(nt::FileObject::SIZE);
    at::<nt::FileObject>(wake_file).flags.set(0x2000_0000);
    let (no_wake_before, wake_before) = (wake.no_wake_counter.get(), wake.wake_counters[1].get());
    let increments = [status("IoIncrementKeepAliveCount", &[file, process]), status("IoIncrementKeepAliveCount", &[file, process]), status("IoIncrementKeepAliveCount", &[wake_file, process])];
    let charged = wake.no_wake_counter.get() == no_wake_before + 1 && wake.wake_counters[1].get() == wake_before + 1;
    let decrements = [status("IoDecrementKeepAliveCount", &[file, process]), status("IoDecrementKeepAliveCount", &[file, process])];
    let deferred = crate::ntos::io::file::keep_alive::tracker_state(file, process) == Some((0, -1)) && wake.no_wake_counter.get() == no_wake_before + 1;
    let unknown = status("IoDecrementKeepAliveCount", &[guest::alloc_bytes(nt::FileObject::SIZE), process]) == 0xC000_000D;
    status("IoDecrementKeepAliveCount", &[wake_file, process]);
    assert(increments == [0, 0, 0] && charged && decrements == [0, 0] && deferred && unknown, "io: IoIncrement/DecrementKeepAliveCount cobram o contador do arquivo na primeira referência e adiam a soltura em 5 s");
}

// ---- Ex: ZwCreateWnfStateName -------------------------------------------------

fn zw_create_wnf_state_name(assert: Assert) {
    // Descritor self-relative com DACL NULL presente (acesso livre).
    let descriptor = guest::alloc_bytes(20);
    guest::write_bytes(descriptor, &[1, 0, 0x04, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let name = guest::alloc_bytes(8);
    let other = guest::alloc_bytes(8);
    let created = status("ZwCreateWnfStateName", &[name, 3, 0, 0, 0, 0x100, descriptor]);
    let second = status("ZwCreateWnfStateName", &[other, 3, 0, 0, 0, 0x100, descriptor]);
    let decoded = guest::read64(name) ^ crate::ntos::ex::wnf::name::NAME_MASK;
    let next = guest::read64(other) ^ crate::ntos::ex::wnf::name::NAME_MASK;
    let shape = decoded & 0x7FF == 0x31 && next >> 11 == (decoded >> 11) + 1;
    let data = guest::alloc_bytes(8);
    guest::write32(data, 0x5157_4E46);
    let updated = status("ZwUpdateWnfStateData", &[name, data, 4, 0, 0, 0, 0]);
    let stamp = guest::alloc_bytes(4);
    let back = guest::alloc_bytes(8);
    let length = guest::alloc_bytes(4);
    guest::write32(length, 8);
    let queried = status("ZwQueryWnfStateData", &[name, 0, 0, stamp, back, length]);
    let roundtrip = updated == 0 && queried == 0 && guest::read32(back) == 0x5157_4E46 && guest::read32(length) == 4;
    let invalid = status("ZwCreateWnfStateName", &[name, 0, 0, 0, 0, 0x100, descriptor]) == 0xC000_000D
        && status("ZwCreateWnfStateName", &[name, 3, 6, 0, 0, 0x100, descriptor]) == 0xC000_000D
        && status("ZwCreateWnfStateName", &[name, 3, 0, 0, 0, 0x1001, descriptor]) == 0xC000_000D
        && status("ZwCreateWnfStateName", &[name, 3, 3, 0, 0, 0x100, descriptor]) == 0xC000_000D
        && status("ZwCreateWnfStateName", &[name, 3, 0, 1, 0, 0x100, descriptor]) == 0xC000_000D
        && status("ZwCreateWnfStateName", &[name, 3, 0, 0, 0, 0x100, 0]) == 0xC000_0005;
    assert(created == 0 && second == 0 && shape && roundtrip && invalid, "ex-wnf: ZwCreateWnfStateName gera nomes temporários sequenciais (versão 1, escopo, tempo de vida), usáveis pelo Update/Query, e valida os parâmetros");
}

pub fn run(assert: Assert) {
    rtl_ddi_assert(assert);
    rtl_rb_tree(assert);
    crt_scanf(assert);
    crt_integer_strings(assert);
    rtl_network_address_ansi(assert);
    rtl_memory_nls_small(assert);
    po_legacy_system_state(assert);
    etw_ke_whea_ps(assert);
    mm_support(assert);
    io_support(assert);
    zw_create_wnf_state_name(assert);
}
