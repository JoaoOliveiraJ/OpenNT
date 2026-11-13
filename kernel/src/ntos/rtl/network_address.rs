//! Endereços IPv4/IPv6 em texto (UTF-16) — ntoskrnl 19041
//! RtlIpv4StringToAddressW 0x31e430, RtlIpv6StringToAddressW 0x31c670,
//! RtlIpv4AddressToStringW 0x381600, RtlIpv4AddressToStringExW 0x381560,
//! RtlIpv6AddressToStringW 0x37dda0, RtlIpv6AddressToStringExW 0x37dcc0.
//!
//! As classes de caractere são as do `pwctype` do ntoskrnl para c < 0x80
//! (os dois parsers testam `c < 0x80` antes do iswctype): dígitos '0'..'9',
//! hexadecimais 0-9/A-F/a-f, minúsculas a-z. Os formatadores reproduzem o
//! swprintf_s dos originais (%u decimal, %x hexadecimal minúsculo).
//! Os vetores dos testes foram calculados com um modelo de referência.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::inc::types::Field;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// A string UTF-16 do chamador, lida até o NUL de uma vez (os parsers nunca
/// olham além do terminador); `unit` devolve 0 a partir do NUL.
struct WideText {
    address: u64,
    units: Vec<u16>,
}

impl WideText {
    fn read(address: u64) -> Self {
        Self { address, units: guest_strings::read_wide_units(address) }
    }

    fn unit(&self, index: u64) -> u16 {
        self.units.get(index as usize).copied().unwrap_or(0)
    }

    /// Endereço do caractere `index` (o *Terminator do NT).
    fn pointer(&self, index: u64) -> u64 {
        self.address + index * 2
    }
}

fn is_digit(c: u16) -> bool {
    (0x30..=0x39).contains(&c)
}

fn is_xdigit(c: u16) -> bool {
    is_digit(c) || (0x41..=0x46).contains(&c) || (0x61..=0x66).contains(&c)
}

fn is_lower(c: u16) -> bool {
    (0x61..=0x7A).contains(&c)
}

fn hex_value(c: u16) -> u32 {
    if is_digit(c) {
        (c - 0x30) as u32
    } else if is_lower(c) {
        (c - 0x61 + 10) as u32
    } else {
        (c - 0x41 + 10) as u32
    }
}

// ---- RtlIpv4StringToAddressW -------------------------------------------------

/// RtlIpv4StringToAddressW(S, Strict, Terminator, Addr): até 4 partes
/// separadas por '.', cada uma decimal, octal ("0" + dígito) ou hexadecimal
/// ("0x"); Strict exige 4 partes decimais. A soma de cada parte é de 32 bits
/// e só recusa quando o novo valor fica menor que o anterior. 1 parte = 32
/// bits; 2 = 8.24; 3 = 8.8.16; 4 = 8.8.8.8. *Terminator recebe o cursor
/// também em erro; Addr (ordem de rede) só em sucesso.
pub fn ipv4_string_to_address(string: u64, strict: bool, terminator: &Field<u64>, address_out: &Field<u32>) -> u32 {
    let text = WideText::read(string);
    let mut index = 0u64;
    let mut parts: [u32; 4] = [0; 4];
    let mut count = 0usize;
    let fail = |index: u64| {
        terminator.set(text.pointer(index));
        STATUS_INVALID_PARAMETER
    };
    loop {
        let mut base = 10u32;
        let mut seen = false;
        let mut value = 0u32;
        if text.unit(index) == 0x30 {
            index += 1;
            let c = text.unit(index);
            if c < 0x80 && is_digit(c) {
                base = 8;
            } else if c == 0x58 || c == 0x78 {
                base = 16;
                index += 1;
            } else {
                seen = true;
            }
        }
        if strict && base != 10 {
            return fail(index);
        }
        loop {
            let c = text.unit(index);
            if c == 0 || c >= 0x80 {
                break;
            }
            let next = if is_digit(c) {
                let digit = (c - 0x30) as u32;
                if digit >= base {
                    break;
                }
                base.wrapping_mul(value).wrapping_add(digit)
            } else if base == 16 && is_xdigit(c) {
                let letter_base = if is_lower(c) { 0x61 } else { 0x41 };
                (value << 4).wrapping_sub(letter_base).wrapping_add(10).wrapping_add(c as u32)
            } else {
                break;
            };
            if next < value {
                return fail(index);
            }
            seen = true;
            index += 1;
            value = next;
        }
        if text.unit(index) == 0x2E {
            if count >= 3 {
                return fail(index);
            }
            parts[count] = value;
            count += 1;
            index += 1;
            if !seen {
                return fail(index);
            }
            continue;
        }
        if !seen {
            return fail(index);
        }
        parts[count] = value;
        count += 1;
        break;
    }
    if strict && count != 4 {
        return fail(index);
    }
    let address = match count {
        1 => parts[0],
        2 if parts[0] <= 0xFF && parts[1] <= 0xFF_FFFF => parts[0] << 24 | parts[1],
        3 if parts[0] <= 0xFF && parts[1] <= 0xFF && parts[2] <= 0xFFFF => parts[0] << 24 | parts[1] << 16 | parts[2],
        4 if parts.iter().all(|&part| part <= 0xFF) => parts[0] << 24 | parts[1] << 16 | parts[2] << 8 | parts[3],
        _ => return fail(index),
    };
    terminator.set(text.pointer(index));
    address_out.set(address.swap_bytes());
    0
}

// ---- RtlIpv6StringToAddressW -------------------------------------------------

/// Estado do autômato do original (r14d): início de grupo, dentro de um
/// grupo, logo depois de "::".
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ipv6State {
    GroupStart,
    InGroup,
    AfterDoubleColon,
}

struct Ipv6Parser {
    text: WideText,
    address: [u8; 16],
    /// Palavras gravadas ([rsp+0x88]).
    words: usize,
    /// Separadores contados (esi): ':' soma 1, "::" soma 2, IPv4 final soma 1.
    colons: u32,
    /// Pontos vistos no sufixo IPv4 (edi).
    dots: u32,
    /// Caracteres do grupo corrente (r15d).
    group_length: u32,
    /// Posição da compressão "::" (ebp; 0 = nenhuma).
    compression: u32,
    /// Início do grupo corrente ([rsp+0x20]).
    group_start: Option<u64>,
}

impl Ipv6Parser {
    fn put_word(&mut self, index: usize, value: u16) {
        self.address[index * 2..index * 2 + 2].copy_from_slice(&value.to_be_bytes());
    }

    fn hex_group(&self, start: u64) -> u16 {
        let mut value = 0u32;
        let mut index = start;
        while is_xdigit(self.text.unit(index)) {
            value = value.wrapping_mul(16).wrapping_add(hex_value(self.text.unit(index)));
            index += 1;
        }
        value as u16
    }

    fn decimal_group(&self, start: u64) -> u32 {
        let mut value = 0u32;
        let mut index = start;
        while is_digit(self.text.unit(index)) {
            value = value.wrapping_mul(10).wrapping_add((self.text.unit(index) - 0x30) as u32);
            index += 1;
        }
        value
    }

    /// Conversão do grupo terminado por ':' ou '.' (0x474a26): Err = status
    /// de erro devolvido sem gravar o terminador.
    fn convert_group(&mut self) -> Result<(), u32> {
        let Some(start) = self.group_start else { return Ok(()) };
        if self.dots == 0 {
            if self.group_length > 4 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let value = self.hex_group(start);
            self.put_word(self.words, value);
            self.words += 1;
        } else {
            if self.group_length > 3 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let value = self.decimal_group(start);
            if value > 0xFF {
                return Err(STATUS_INVALID_PARAMETER);
            }
            self.address[self.words * 2 + self.dots as usize - 1] = value as u8;
        }
        Ok(())
    }
}

/// RtlIpv6StringToAddressW(S, Terminator, Addr): o autômato do original,
/// grupo a grupo, com "::" (uma vez), sufixo IPv4 de 4 octetos decimais e a
/// expansão final (memmove das palavras depois da compressão para o fim e
/// zeros no meio). O endereço é escrito no lugar, então um erro no meio da
/// leitura deixa as palavras já gravadas; erros detectados ao converter um
/// grupo dentro do laço voltam sem gravar *Terminator.
pub fn ipv6_string_to_address(string: u64, terminator: &Field<u64>, address_out: u64) -> u32 {
    let mut initial = [0u8; 16];
    initial.copy_from_slice(&guest::read_bytes(address_out, 16));
    let mut parser = Ipv6Parser { text: WideText::read(string), address: initial, words: 0, colons: 0, dots: 0, group_length: 0, compression: 0, group_start: None };
    let status = parse_ipv6(&mut parser, terminator);
    guest::write_bytes(address_out, &parser.address);
    status
}

fn parse_ipv6(p: &mut Ipv6Parser, terminator: &Field<u64>) -> u32 {
    let mut index = 0u64;
    let mut state = Ipv6State::GroupStart;
    let mut hex_seen = false;
    let mut c = p.text.unit(0);
    while c != 0 {
        let mut stop = false;
        let group_state = if state == Ipv6State::AfterDoubleColon { Ipv6State::GroupStart } else { state };
        if group_state == Ipv6State::GroupStart {
            if c == 0x3A {
                if p.dots == 0 && p.colons == 0 && p.text.unit(index + 1) == 0x3A {
                    p.put_word(p.words, 0);
                    p.words += 1;
                    p.compression = 1;
                    p.colons = 2;
                    index += 1;
                    state = Ipv6State::AfterDoubleColon;
                    if let Err(status) = p.convert_group() {
                        return status;
                    }
                } else {
                    stop = true;
                }
            } else if p.colons > 7 || c >= 0x80 {
                stop = true;
            } else if is_digit(c) {
                p.group_start = Some(index);
                hex_seen = false;
                state = Ipv6State::InGroup;
                p.group_length = 1;
            } else if is_xdigit(c) {
                if p.dots != 0 {
                    stop = true;
                } else {
                    hex_seen = true;
                    state = Ipv6State::InGroup;
                    p.group_start = Some(index);
                    p.group_length = 1;
                }
            } else {
                stop = true;
            }
        } else if c < 0x80 && is_digit(c) {
            p.group_length += 1;
        } else if c < 0x80 && is_xdigit(c) {
            p.group_length += 1;
            if p.dots != 0 {
                stop = true;
            } else {
                hex_seen = true;
            }
        } else if c == 0x3A {
            if p.dots != 0 || p.colons > 6 {
                stop = true;
            } else if p.text.unit(index + 1) == 0x3A {
                if p.compression != 0 {
                    stop = true;
                } else {
                    index += 1;
                    state = Ipv6State::AfterDoubleColon;
                    p.compression = p.colons + 1;
                    p.colons += 2;
                    if let Err(status) = p.convert_group() {
                        return status;
                    }
                }
            } else {
                state = Ipv6State::GroupStart;
                p.colons += 1;
                if let Err(status) = p.convert_group() {
                    return status;
                }
            }
        } else if c == 0x2E {
            if hex_seen || p.dots > 2 || p.colons > 6 {
                stop = true;
            } else {
                p.dots += 1;
                state = Ipv6State::GroupStart;
                if let Err(status) = p.convert_group() {
                    return status;
                }
            }
        } else {
            stop = true;
        }
        if stop {
            break;
        }
        index += 1;
        c = p.text.unit(index);
    }
    terminator.set(p.text.pointer(index));
    if p.dots != 0 {
        if p.dots != 3 {
            return STATUS_INVALID_PARAMETER;
        }
        p.colons += 1;
    }
    if p.compression == 0 && p.colons != 7 {
        return STATUS_INVALID_PARAMETER;
    }
    match state {
        Ipv6State::InGroup => {
            let start = p.group_start.unwrap_or(0);
            if p.dots == 0 {
                if p.group_length > 4 {
                    return STATUS_INVALID_PARAMETER;
                }
                let value = p.hex_group(start);
                p.put_word(p.words, value);
            } else {
                if p.group_length > 3 {
                    return STATUS_INVALID_PARAMETER;
                }
                let value = p.decimal_group(start);
                if value > 0xFF {
                    return STATUS_INVALID_PARAMETER;
                }
                p.address[p.dots as usize + p.words * 2] = value as u8;
            }
        }
        Ipv6State::AfterDoubleColon => p.put_word(p.words, 0),
        Ipv6State::GroupStart => return STATUS_INVALID_PARAMETER,
    }
    if p.compression != 0 {
        let compression = p.compression as usize;
        let moved = (p.colons - p.compression) as usize;
        let destination = (p.compression + 8 - p.colons) as usize;
        p.address.copy_within(compression * 2..(compression + moved) * 2, destination * 2);
        let zeros = (8 - p.colons) as usize;
        p.address[compression * 2..(compression + zeros) * 2].fill(0);
    }
    0
}

// ---- Formatação ---------------------------------------------------------------

fn format_ipv4(bytes: &[u8]) -> String {
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

/// RtlIpv6AddressToStringW em texto: ::a.b.c.d / ::ffff:a.b.c.d /
/// ::ffff:0:a.b.c.d para os prefixos zero com a palavra 6 não nula; ISATAP
/// (palavra 4 = 0 ou 0x0200 e palavra 5 = 0x5efe) imprime 6 palavras e o
/// IPv4; a maior sequência de zeros (a primeira em empate, só se > 1
/// palavra) vira "::".
fn format_ipv6(bytes: &[u8; 16]) -> String {
    let word = |index: usize| u16::from_be_bytes([bytes[index * 2], bytes[index * 2 + 1]]);
    let raw = |index: usize| u16::from_le_bytes([bytes[index * 2], bytes[index * 2 + 1]]);
    let tail = format_ipv4(&bytes[12..16]);
    if word(0) == 0 && word(1) == 0 && word(2) == 0 && word(3) == 0 && word(6) != 0 {
        if word(4) == 0 {
            if raw(5).wrapping_add(1) & 0xFFFE == 0 {
                return format!("::{}{}", if raw(5) != 0 { "ffff:" } else { "" }, tail);
            }
        } else if raw(4) == 0xFFFF && raw(5) == 0 {
            return format!("::ffff:0:{tail}");
        }
    }
    let count = if raw(4) & 0xFFFD == 0 && raw(5) == 0xFE5E { 6 } else { 8 };
    let (mut best_start, mut best_end, mut current) = (0usize, 0usize, 0usize);
    for index in 0..count {
        if word(index) == 0 {
            if index + 1 - current > best_end - best_start {
                best_start = current;
                best_end = index + 1;
            }
        } else {
            current = index + 1;
        }
    }
    let (run_start, run_end) = if best_end - best_start > 1 { (best_start, best_end) } else { (0, 0) };
    let mut text = String::new();
    let mut index = 0;
    while index < count {
        if index < run_end && run_start <= index {
            text.push_str("::");
            index = run_end;
            continue;
        }
        if index != 0 && index != run_end {
            text.push(':');
        }
        text.push_str(&format!("{:x}", word(index)));
        index += 1;
    }
    if count < 8 {
        text.push(':');
        text.push_str(&tail);
    }
    text
}

/// Grava o texto UTF-16 com NUL (uma cópia em bloco); devolve o endereço do NUL.
fn write_text(destination: u64, text: &str) -> u64 {
    let bytes = guest_strings::wide_bytes_with_nul(text);
    guest::write_bytes(destination, &bytes);
    destination + bytes.len() as u64 - 2
}

/// Entrega um texto *Ex: Length (em WCHARs, com o NUL) sempre recebe o
/// necessário; buffer pequeno = STATUS_INVALID_PARAMETER sem copiar.
fn deliver_ex(text: &str, buffer: u64, length: &Field<u32>) -> u32 {
    let needed = text.encode_utf16().count() as u32 + 1;
    let capacity = length.get();
    length.set(needed);
    if capacity < needed {
        return STATUS_INVALID_PARAMETER;
    }
    write_text(buffer, text);
    0
}

fn read_ipv4(address: u64) -> [u8; 4] {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&guest::read_bytes(address, 4));
    bytes
}

fn read_ipv6(address: u64) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&guest::read_bytes(address, 16));
    bytes
}

/// RtlIpv4AddressToStringW(Addr, S): "%u.%u.%u.%u"; devolve o fim (o NUL).
pub fn ipv4_address_to_string(address: u64, string: u64) -> u64 {
    write_text(string, &format_ipv4(&read_ipv4(address)))
}

/// RtlIpv6AddressToStringW(Addr, S); devolve o fim (o NUL).
pub fn ipv6_address_to_string(address: u64, string: u64) -> u64 {
    write_text(string, &format_ipv6(&read_ipv6(address)))
}

/// RtlIpv4AddressToStringExW(Addr, Port, Buffer, Length): Addr ou Length
/// NULL, ou Buffer NULL com *Length != 0 = STATUS_INVALID_PARAMETER; Port
/// (ordem de rede) != 0 acrescenta ":%u". IN_ADDR/IN6_ADDR são lidos como
/// blocos de bytes (ordem de rede).
pub fn ipv4_address_to_string_ex(address: u64, port: u16, buffer: u64, length: Option<&Field<u32>>) -> u32 {
    let Some(length) = length.filter(|length| address != 0 && (buffer != 0 || length.get() == 0)) else {
        return STATUS_INVALID_PARAMETER;
    };
    let mut text = format_ipv4(&read_ipv4(address));
    if port != 0 {
        text.push_str(&format!(":{}", port.swap_bytes()));
    }
    deliver_ex(&text, buffer, length)
}

/// RtlIpv6AddressToStringExW(Addr, ScopeId, Port, Buffer, Length): "[" se
/// Port != 0, o endereço, "%<ScopeId>" se != 0 e "]:<porta>" se Port != 0.
pub fn ipv6_address_to_string_ex(address: u64, scope_id: u32, port: u16, buffer: u64, length: Option<&Field<u32>>) -> u32 {
    let Some(length) = length.filter(|length| address != 0 && (buffer != 0 || length.get() == 0)) else {
        return STATUS_INVALID_PARAMETER;
    };
    let mut text = String::new();
    if port != 0 {
        text.push('[');
    }
    text.push_str(&format_ipv6(&read_ipv6(address)));
    if scope_id != 0 {
        text.push_str(&format!("%{scope_id}"));
    }
    if port != 0 {
        text.push_str(&format!("]:{}", port.swap_bytes()));
    }
    deliver_ex(&text, buffer, length)
}
