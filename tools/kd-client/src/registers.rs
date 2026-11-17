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

/// O x87 no pacote `g`, depois dos seletores: ST0-ST7 (80 bits) e as
/// palavras de controle.
pub const X87: &[Layout] = &[
    register("st0", 24, 10),
    register("st1", 25, 10),
    register("st2", 26, 10),
    register("st3", 27, 10),
    register("st4", 28, 10),
    register("st5", 29, 10),
    register("st6", 30, 10),
    register("st7", 31, 10),
];

/// As palavras do x87 (no protocolo, 4 bytes cada).
pub const X87_CONTROL: &[Layout] = &[
    register("fctrl", 32, 4),
    register("fstat", 33, 4),
    register("ftag", 34, 4),
    register("fiseg", 35, 4),
    register("fioff", 36, 4),
    register("foseg", 37, 4),
    register("fooff", 38, 4),
    register("fop", 39, 4),
];

/// O primeiro XMM no protocolo (XMM0-XMM15 são 40-55) e o MXCSR (56).
pub const XMM_FIRST: usize = 40;
pub const MXCSR: Layout = register("mxcsr", 56, 4);

/// Extensões do OpenNT só por `p`: a metade alta dos YMM (`ymm0h`-`ymm15h`,
/// 59-74, pela área XSAVE quando o sistema liga o AVX) e os registradores
/// de depuração (75-80; numa parada de usuário, os do CONTEXT da thread).
pub const YMM_HIGH_FIRST: usize = 59;
pub const DEBUG: &[Layout] = &[register("dr0", 75, 8), register("dr1", 76, 8), register("dr2", 77, 8), register("dr3", 78, 8), register("dr6", 79, 8), register("dr7", 80, 8)];

/// O registrador pelo nome (minúsculas; `rflags` vale `eflags`). Só os de
/// até 8 bytes (as expressões leem um número).
pub fn find(name: &str) -> Option<Layout> {
    let name = name.to_ascii_lowercase();
    let name = if name == "rflags" { "eflags".to_string() } else { name };
    GENERAL.iter().chain(EXTRA).chain(X87_CONTROL).chain(DEBUG).chain(std::iter::once(&MXCSR)).find(|layout| layout.name == name).copied()
}

/// O estado além dos inteiros: x87, MMX, SSE, a metade alta dos YMM e os
/// registradores de depuração. `None` = indisponível no alvo.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtendedState {
    /// ST0-ST7 na ordem da pilha do x87 (80 bits little-endian).
    pub st: [Option<[u8; 10]>; 8],
    pub fctrl: Option<u32>,
    pub fstat: Option<u32>,
    pub ftag: Option<u32>,
    pub fop: Option<u32>,
    pub xmm: [Option<[u8; 16]>; 16],
    pub mxcsr: Option<u32>,
    /// Os bits 128-255 de cada YMM.
    pub ymm_high: [Option<[u8; 16]>; 16],
    /// DR0, DR1, DR2, DR3, DR6, DR7.
    pub debug: [Option<u64>; 6],
}

impl ExtendedState {
    /// O topo da pilha do x87 (FSW bits 11-13).
    pub fn x87_top(&self) -> u32 {
        self.fstat.map_or(0, |status| (status >> 11) & 7)
    }

    /// MM0-MM7: os 64 bits baixos do registrador físico R0-R7 (MMi é Ri, e
    /// STj é R((TOP + j) mod 8)).
    pub fn mmx(&self, index: usize) -> Option<u64> {
        let top = self.x87_top() as usize;
        let slot = (index + 8 - top) % 8;
        self.st[slot].map(|bytes| u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8])))
    }

    /// O YMM inteiro (XMM nos bits baixos, a metade alta em cima), se as
    /// duas metades existem.
    pub fn ymm(&self, index: usize) -> Option<[u8; 32]> {
        let (low, high) = (self.xmm.get(index).copied().flatten()?, self.ymm_high.get(index).copied().flatten()?);
        let mut value = [0u8; 32];
        value[..16].copy_from_slice(&low);
        value[16..].copy_from_slice(&high);
        Some(value)
    }
}

/// Lê o x87, o SSE e o MXCSR de um pacote `g` completo (o que o OpenNT
/// manda: os 57 registradores). Um pacote curto deixa o resto `None`.
pub fn parse_extended(reply: &str) -> ExtendedState {
    let mut state = ExtendedState::default();
    let offset_of = |number: usize| -> usize { (0..number).map(|index| packet_size(index) * 2).sum() };
    let field = |number: usize| -> Option<Vec<u8>> {
        let start = offset_of(number);
        let digits = reply.get(start..start + packet_size(number) * 2)?;
        (!digits.contains('x')).then(|| super::rsp::unhex(digits))
    };
    for index in 0..8 {
        state.st[index] = field(24 + index).and_then(|bytes| bytes.try_into().ok());
    }
    let word = |number: usize| field(number).map(|bytes| u32::from_le_bytes(bytes[..4].try_into().unwrap_or([0; 4])));
    state.fctrl = word(32);
    state.fstat = word(33);
    state.ftag = word(34);
    state.fop = word(39);
    for index in 0..16 {
        state.xmm[index] = field(XMM_FIRST + index).and_then(|bytes| bytes.try_into().ok());
    }
    state.mxcsr = word(56);
    state
}

/// Tamanho de cada registrador do pacote `g` (a ordem do OpenNT).
pub fn packet_size(number: usize) -> usize {
    match number {
        0..=16 => 8,
        17..=23 => 4,
        24..=31 => 10,
        32..=39 => 4,
        40..=55 => 16,
        56 => 4,
        57 | 58 => 8,
        59..=74 => 16,
        75..=80 => 8,
        _ => 0,
    }
}

/// Um valor de 80 bits do x87 como `f64` (para mostrar).
pub fn extended_to_f64(bytes: &[u8; 10]) -> f64 {
    let mantissa = u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]));
    let sign_exponent = u16::from_le_bytes([bytes[8], bytes[9]]);
    let negative = sign_exponent & 0x8000 != 0;
    let exponent = (sign_exponent & 0x7FFF) as i32;
    let value = if exponent == 0 && mantissa == 0 {
        0.0
    } else if exponent == 0x7FFF {
        if mantissa << 1 == 0 {
            f64::INFINITY
        } else {
            f64::NAN
        }
    } else {
        // valor = mantissa * 2^(exponent - 16383 - 63)
        (mantissa as f64) * 2f64.powi(exponent - 16383 - 63)
    };
    if negative {
        -value
    } else {
        value
    }
}

/// Os bits do MXCSR ligados (exceções, máscaras e arredondamento).
pub fn mxcsr_text(value: u32) -> String {
    const BITS: &[(u32, &str)] = &[(0, "IE"), (1, "DE"), (2, "ZE"), (3, "OE"), (4, "UE"), (5, "PE"), (6, "DAZ"), (15, "FZ")];
    let mut parts: Vec<String> = BITS.iter().filter(|(bit, _)| value >> bit & 1 != 0).map(|(_, name)| name.to_string()).collect();
    let rounding = ["RN", "R-", "R+", "RZ"][((value >> 13) & 3) as usize];
    parts.push(rounding.to_string());
    parts.join(" ")
}

/// O DR7 em palavras: para cada comparador ligado, L/G, o tipo e o tamanho.
pub fn dr7_text(value: u64) -> String {
    let mut parts = Vec::new();
    for index in 0..4 {
        let local = value >> (index * 2) & 1 != 0;
        let global = value >> (index * 2 + 1) & 1 != 0;
        if !local && !global {
            continue;
        }
        let kind = match value >> (16 + index * 4) & 3 {
            0 => "x",
            1 => "w",
            2 => "io",
            _ => "rw",
        };
        let length = match value >> (18 + index * 4) & 3 {
            0 => 1,
            1 => 2,
            2 => 8,
            _ => 4,
        };
        parts.push(format!("DR{index}:{}{} {kind}/{length}", if local { "L" } else { "" }, if global { "G" } else { "" }));
    }
    if parts.is_empty() {
        "nenhum comparador".into()
    } else {
        parts.join(", ")
    }
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
        assert_eq!(find("dr7").unwrap().number, 80);
        assert_eq!(find("mxcsr").unwrap().number, 56);
        assert_eq!(flags_text(0x246), "pf zf if");
    }

    /// Um pacote `g` completo de 57 registradores com x87 e SSE.
    #[test]
    fn parses_extended_state() {
        let mut reply = String::new();
        for number in 0..57 {
            let size = packet_size(number);
            let mut bytes = vec![0u8; size];
            match number {
                // ST0 = 1.0 (expoente 0x3FFF, mantissa com o bit inteiro).
                24 => {
                    bytes[7] = 0x80;
                    bytes[8] = 0xFF;
                    bytes[9] = 0x3F;
                }
                // FSW com TOP = 7.
                33 => bytes[..2].copy_from_slice(&(7u16 << 11).to_le_bytes()),
                40 => bytes.copy_from_slice(&(1..=16).collect::<Vec<u8>>()),
                56 => bytes[..4].copy_from_slice(&0x1F80u32.to_le_bytes()),
                _ => {}
            }
            if number == 41 {
                reply.push_str(&"xx".repeat(size));
            } else {
                reply.push_str(&super::super::rsp::hex(&bytes));
            }
        }
        let state = parse_extended(&reply);
        assert_eq!(extended_to_f64(&state.st[0].unwrap()), 1.0);
        assert_eq!(state.x87_top(), 7);
        // MM7 é R7 = ST0 quando TOP = 7.
        assert_eq!(state.mmx(7), Some(0x8000_0000_0000_0000));
        assert_eq!(state.xmm[0].unwrap()[15], 16);
        assert_eq!(state.xmm[1], None);
        assert_eq!(state.mxcsr, Some(0x1F80));
        assert_eq!(mxcsr_text(0x1F80), "RN");
        assert_eq!(state.ymm(0), None);
        // Um pacote só com os gerais deixa tudo indisponível.
        assert_eq!(parse_extended(&"00".repeat(150)), ExtendedState::default());
    }

    #[test]
    fn debug_control_text() {
        assert_eq!(dr7_text(0x400), "nenhum comparador");
        // DR0 global, escrita de 4 bytes; DR1 local, execução.
        assert_eq!(dr7_text(0x400 | 0b0110 | (0b1101 << 16)), "DR0:G w/4, DR1:L x/1");
        assert_eq!(extended_to_f64(&[0; 10]), 0.0);
    }
}
