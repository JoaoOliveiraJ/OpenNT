//! Buscas na memória lida do alvo: padrões de bytes com curingas (byte
//! inteiro ou meio byte) e a varredura simples de strings ASCII e UTF-16,
//! sem olhar quem as usa.

use super::refs::{ascii_run, printable_byte, printable_unit, wide_run};

/// Um padrão: cada byte vale onde a máscara tem 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pattern {
    pub bytes: Vec<u8>,
    /// 0xFF exato, 0x00 qualquer, 0xF0 e 0x0F meio byte.
    pub mask: Vec<u8>,
}

fn nibble(character: char) -> Result<Option<u8>, String> {
    match character {
        '?' => Ok(None),
        _ => character.to_digit(16).map(|digit| Some(digit as u8)).ok_or_else(|| format!("padrao: '{character}' nao e hexadecimal nem '?'")),
    }
}

/// Lê um padrão: bytes em hexadecimal com `??` (ou `?` sozinho) para
/// qualquer byte e `?` num dos dígitos para meio byte (`48 8B ?? 05`,
/// `4?8B`, `?5`), `"texto"` em ASCII ou `u"texto"` em UTF-16LE. Espaço
/// entre bytes inteiros é opcional.
pub fn parse_pattern(text: &str) -> Result<Pattern, String> {
    let text = text.trim();
    let literal = |bytes: Vec<u8>| -> Result<Pattern, String> {
        if bytes.is_empty() {
            return Err("padrao vazio".into());
        }
        Ok(Pattern { mask: vec![0xFF; bytes.len()], bytes })
    };
    if let Some(inner) = text.strip_prefix("u\"").and_then(|rest| rest.strip_suffix('"')) {
        return literal(inner.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect());
    }
    if let Some(inner) = text.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')) {
        return literal(inner.as_bytes().to_vec());
    }
    let mut pattern = Pattern { bytes: Vec::new(), mask: Vec::new() };
    for token in text.split_whitespace() {
        if token == "?" {
            pattern.bytes.push(0);
            pattern.mask.push(0);
            continue;
        }
        let characters: Vec<char> = token.chars().collect();
        if characters.len() % 2 != 0 {
            return Err(format!("padrao: '{token}' tem um numero impar de digitos"));
        }
        for pair in characters.chunks(2) {
            let (high, low) = (nibble(pair[0])?, nibble(pair[1])?);
            pattern.bytes.push(high.unwrap_or(0) << 4 | low.unwrap_or(0));
            pattern.mask.push(if high.is_some() { 0xF0 } else { 0 } | if low.is_some() { 0x0F } else { 0 });
        }
    }
    if pattern.bytes.is_empty() {
        return Err("padrao vazio".into());
    }
    Ok(pattern)
}

impl Pattern {
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// O padrão casa com o começo de `bytes`.
    pub fn matches(&self, bytes: &[u8]) -> bool {
        bytes.len() >= self.len() && self.bytes.iter().zip(&self.mask).zip(bytes).all(|((&wanted, &mask), &byte)| byte & mask == wanted & mask)
    }

    /// Os endereços (a partir de `base`) onde o padrão casa, até `limit`;
    /// acertos sobrepostos contam.
    pub fn find_all(&self, haystack: &[u8], base: u64, limit: usize) -> Vec<u64> {
        let mut found = Vec::new();
        if self.is_empty() || haystack.len() < self.len() {
            return found;
        }
        for position in 0..=haystack.len() - self.len() {
            if found.len() >= limit {
                break;
            }
            if self.matches(&haystack[position..]) {
                found.push(base.wrapping_add(position as u64));
            }
        }
        found
    }
}

/// Uma string achada pela varredura simples.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoundString {
    pub address: u64,
    pub text: String,
    pub wide: bool,
}

/// As strings de `bytes` (em `base`): sequências ASCII e UTF-16LE de pelo
/// menos `min_length` caracteres imprimíveis, até `limit`.
pub fn strings(bytes: &[u8], base: u64, min_length: usize, limit: usize) -> Vec<FoundString> {
    let min_length = min_length.max(1);
    let mut found = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() && found.len() < limit {
        let rest = &bytes[index..];
        // UTF-16: duas unidades imprimíveis com o byte alto zero.
        if rest.len() >= 4 && rest[1] == 0 && rest[3] == 0 && printable_unit(rest[0] as u16) && printable_unit(rest[2] as u16) {
            let (text, count, _) = wide_run(rest);
            if count >= min_length {
                found.push(FoundString { address: base.wrapping_add(index as u64), text, wide: true });
                index += count * 2;
                continue;
            }
        }
        if printable_byte(rest[0]) {
            let (text, count, _) = ascii_run(rest);
            if count >= min_length {
                found.push(FoundString { address: base.wrapping_add(index as u64), text, wide: false });
            }
            index += count.max(1);
            continue;
        }
        index += 1;
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_patterns() {
        let pattern = parse_pattern("48 8B ?? 05").unwrap();
        assert_eq!(pattern.bytes, vec![0x48, 0x8B, 0x00, 0x05]);
        assert_eq!(pattern.mask, vec![0xFF, 0xFF, 0x00, 0xFF]);
        assert_eq!(parse_pattern("48 8b ? 05").unwrap(), pattern);
        assert_eq!(parse_pattern("488B??05").unwrap(), pattern);
        let nibbles = parse_pattern("4?8B ?5").unwrap();
        assert_eq!(nibbles.bytes, vec![0x40, 0x8B, 0x05]);
        assert_eq!(nibbles.mask, vec![0xF0, 0xFF, 0x0F]);
        assert_eq!(parse_pattern("\"MZ\"").unwrap().bytes, b"MZ".to_vec());
        assert_eq!(parse_pattern("u\"Nt\"").unwrap().bytes, vec![b'N', 0, b't', 0]);
        assert!(parse_pattern("4").is_err());
        assert!(parse_pattern("zz").is_err());
        assert!(parse_pattern("").is_err());
        assert!(parse_pattern("\"\"").is_err());
    }

    #[test]
    fn finds_with_wildcards() {
        let haystack = [0x48, 0x8B, 0x05, 0x10, 0x48, 0x8B, 0x0D, 0x05, 0x41, 0x8B, 0xFF, 0x05];
        let pattern = parse_pattern("4? 8B ?? ?5").unwrap();
        assert_eq!(pattern.find_all(&haystack, 0x1000, 10), vec![0x1004, 0x1008]);
        let exact = parse_pattern("48 8B").unwrap();
        assert_eq!(exact.find_all(&haystack, 0, 10), vec![0, 4]);
        assert_eq!(exact.find_all(&haystack, 0, 1), vec![0]);
        // Sobrepostos.
        let overlapping = parse_pattern("AA AA").unwrap();
        assert_eq!(overlapping.find_all(&[0xAA, 0xAA, 0xAA], 0, 10), vec![0, 1]);
        assert!(exact.find_all(&[0x48], 0, 10).is_empty());
        assert!(pattern.matches(&[0x41, 0x8B, 0x00, 0x75, 0x99]));
        assert!(!pattern.matches(&[0x41, 0x8B, 0x00]));
    }

    #[test]
    fn scans_strings() {
        let mut bytes = vec![0x01, 0x02];
        bytes.extend_from_slice(b"first string\0");
        bytes.extend_from_slice(&[0xFF, 0xFE]);
        bytes.extend("wide one".encode_utf16().flat_map(|unit| unit.to_le_bytes()));
        bytes.extend_from_slice(&[0, 0, b'a', b'b', 0, 0x10]);
        bytes.extend_from_slice(b"tail");
        let found = strings(&bytes, 0x5000, 4, 100);
        let summary: Vec<(u64, &str, bool)> = found.iter().map(|string| (string.address, string.text.as_str(), string.wide)).collect();
        assert_eq!(summary, vec![(0x5002, "first string", false), (0x5011, "wide one", true), (0x5000 + bytes.len() as u64 - 4, "tail", false)]);
        assert_eq!(strings(&bytes, 0, 4, 1).len(), 1);
    }
}
