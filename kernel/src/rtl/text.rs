//! Pequenos auxiliares de texto (preenchimento à direita, conversão de
//! bytes em texto, formatação de decimais).

use alloc::string::String;

/// Preenche à direita com espaços até `width` caracteres.
pub fn pad_end(text: &str, width: usize) -> String {
    let mut padded = String::from(text);
    while padded.chars().count() < width {
        padded.push(' ');
    }
    padded
}

/// Formata `numerator / denominator` com uma casa decimal,
/// sem ponto flutuante: o kernel é compilado sem SSE.
pub fn fixed1(numerator: u64, denominator: u64) -> String {
    if denominator == 0 {
        return String::from("0.0");
    }
    let tenths = (numerator as u128 * 10 + denominator as u128 / 2) / denominator as u128;
    alloc::format!("{}.{}", tenths / 10, tenths % 10)
}

/// Bytes Latin-1 em texto (cada byte vira um caractere).
pub fn latin1_to_string(bytes: &[u8]) -> String {
    match core::str::from_utf8(bytes) {
        Ok(text) => String::from(text),
        Err(_) => bytes.iter().map(|&byte| byte as char).collect(),
    }
}
