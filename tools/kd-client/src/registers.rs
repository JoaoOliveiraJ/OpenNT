//! Registradores na ordem do GDB para x86-64 (a do depurador do OpenNT,
//! `kernel/src/ntos/kd/registers.rs`): o pacote `g` começa pelos inteiros,
//! RIP, EFLAGS e os seletores; `p`/`P` usam o mesmo número, e FS_BASE e
//! GS_BASE (57 e 58) só existem por `p`.

/// Nome, número no protocolo e tamanho em bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub name: &'static str,
    pub number: usize,
    pub size: usize,
}

const fn register(name: &'static str, number: usize, size: usize) -> Layout {
    Layout { name, number, size }
}

/// O começo do pacote `g` (o resto, x87 e SSE, o cliente não mostra).
pub const GENERAL: &[Layout] = &[
    register("rax", 0, 8),
    register("rbx", 1, 8),
    register("rcx", 2, 8),
    register("rdx", 3, 8),
    register("rsi", 4, 8),
    register("rdi", 5, 8),
    register("rbp", 6, 8),
    register("rsp", 7, 8),
    register("r8", 8, 8),
    register("r9", 9, 8),
    register("r10", 10, 8),
    register("r11", 11, 8),
    register("r12", 12, 8),
    register("r13", 13, 8),
    register("r14", 14, 8),
    register("r15", 15, 8),
    register("rip", 16, 8),
    register("eflags", 17, 4),
    register("cs", 18, 4),
    register("ss", 19, 4),
    register("ds", 20, 4),
    register("es", 21, 4),
    register("fs", 22, 4),
    register("gs", 23, 4),
];

/// Só por `p` (fora do pacote `g`).
pub const EXTRA: &[Layout] = &[register("fs_base", 57, 8), register("gs_base", 58, 8)];

/// O registrador pelo nome (minúsculas; `rflags` vale `eflags`).
pub fn find(name: &str) -> Option<Layout> {
    let name = name.to_ascii_lowercase();
    let name = if name == "rflags" { "eflags".to_string() } else { name };
    GENERAL.iter().chain(EXTRA).find(|layout| layout.name == name).copied()
}

/// Um valor lido; `None` quando o alvo respondeu `xx` (indisponível).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Value {
    pub layout: Layout,
    pub value: Option<u64>,
}

/// Os registradores gerais de um pacote `g`.
pub fn parse_general(reply: &str) -> Result<Vec<Value>, String> {
    let mut values = Vec::with_capacity(GENERAL.len());
    let mut offset = 0;
    for &layout in GENERAL {
        let digits = reply.get(offset..offset + layout.size * 2).ok_or_else(|| format!("pacote g curto ({} digitos)", reply.len()))?;
        offset += layout.size * 2;
        values.push(Value { layout, value: parse_little_endian(digits) });
    }
    Ok(values)
}

/// Inteiro little-endian em hexadecimal (`None` se indisponível).
pub fn parse_little_endian(digits: &str) -> Option<u64> {
    if digits.contains('x') {
        return None;
    }
    let bytes = super::rsp::unhex(digits);
    let mut value = [0u8; 8];
    let count = bytes.len().min(8);
    value[..count].copy_from_slice(&bytes[..count]);
    Some(u64::from_le_bytes(value))
}

/// O conteúdo do `P` que grava `value` no registrador.
pub fn write_packet(layout: Layout, value: u64) -> String {
    format!("P{:x}={}", layout.number, super::rsp::hex(&value.to_le_bytes()[..layout.size]))
}

/// Os bits do EFLAGS ligados, como o WinDbg os mostra.
pub fn flags_text(eflags: u64) -> String {
    const FLAGS: &[(u32, &str)] = &[(0, "cf"), (2, "pf"), (4, "af"), (6, "zf"), (7, "sf"), (8, "tf"), (9, "if"), (10, "df"), (11, "of")];
    FLAGS.iter().filter(|(bit, _)| eflags >> bit & 1 != 0).map(|(_, name)| *name).collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_g_packet() {
        let mut reply = String::new();
        for index in 0..16u64 {
            reply.push_str(&super::super::rsp::hex(&(index + 1).to_le_bytes()));
        }
        reply.push_str(&super::super::rsp::hex(&0xfffff80040001234u64.to_le_bytes()));
        reply.push_str(&super::super::rsp::hex(&0x246u32.to_le_bytes()));
        reply.push_str("10000000");
        reply.push_str("xxxxxxxx");
        reply.push_str(&"00000000".repeat(4));
        reply.push_str(&"xx".repeat(10));
        let values = parse_general(&reply).unwrap();
        assert_eq!(values[0].value, Some(1));
        assert_eq!(values[15].value, Some(16));
        assert_eq!(values[16].layout.name, "rip");
        assert_eq!(values[16].value, Some(0xfffff80040001234));
        assert_eq!(values[17].value, Some(0x246));
        assert_eq!(values[18].value, Some(0x10));
        assert_eq!(values[19].value, None);
        assert!(parse_general("0011").is_err());
    }

    #[test]
    fn write_packet_and_lookup() {
        assert_eq!(write_packet(find("rax").unwrap(), 0x1122), "P0=2211000000000000");
        assert_eq!(write_packet(find("RFLAGS").unwrap(), 0x202), "P11=02020000");
        assert_eq!(find("gs_base").unwrap().number, 58);
        assert!(find("xmm0").is_none());
        assert_eq!(flags_text(0x246), "pf zf if");
    }
}
