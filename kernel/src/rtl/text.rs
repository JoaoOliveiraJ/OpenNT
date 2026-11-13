//! Pequenos auxiliares de texto que o JavaScript fornecia nativamente
//! (`padEnd`, conversão de bytes em texto, formatação de decimais).

use alloc::string::String;

/// `String.prototype.padEnd` com espaços.
pub fn pad_end(text: &str, width: usize) -> String {
    let mut padded = String::from(text);
    while padded.chars().count() < width {
        padded.push(' ');
    }
    padded
}

/// Formata `numerator / denominator` com uma casa decimal (`toFixed(1)`),
/// sem ponto flutuante: o kernel é compilado sem SSE.
pub fn fixed1(numerator: u64, denominator: u64) -> String {
    if denominator == 0 {
        return String::from("0.0");
    }
    let tenths = (numerator as u128 * 10 + denominator as u128 / 2) / denominator as u128;
    alloc::format!("{}.{}", tenths / 10, tenths % 10)
}

/// Bytes Latin-1 em texto (o `readBundleText` do original entregava cada byte
/// como um caractere).
pub fn latin1_to_string(bytes: &[u8]) -> String {
    match core::str::from_utf8(bytes) {
        Ok(text) => String::from(text),
        Err(_) => bytes.iter().map(|&byte| byte as char).collect(),
    }
}
