//! Os formatos das janelas Dump: hexadecimal com ASCII ou UTF-16, inteiros
//! com e sem sinal de 1, 2, 4 e 8 bytes, float, double, ponteiros com o
//! símbolo e desmontagem. As funções daqui só formatam os bytes (a janela
//! desenha).

use serde::{Deserialize, Serialize};

/// Como uma janela de memória (Dump) aparece.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryFormat {
    HexAscii,
    HexUnicode,
    Words,
    Dwords,
    Qwords,
    Address,
    Float,
    Double,
    SignedByte,
    UnsignedByte,
    SignedWord,
    UnsignedWord,
    SignedDword,
    UnsignedDword,
    SignedQword,
    UnsignedQword,
    Disassembly,
}

impl MemoryFormat {
    pub const ALL: [MemoryFormat; 17] = [
        MemoryFormat::HexAscii,
        MemoryFormat::HexUnicode,
        MemoryFormat::Words,
        MemoryFormat::Dwords,
        MemoryFormat::Qwords,
        MemoryFormat::Address,
        MemoryFormat::Float,
        MemoryFormat::Double,
        MemoryFormat::SignedByte,
        MemoryFormat::UnsignedByte,
        MemoryFormat::SignedWord,
        MemoryFormat::UnsignedWord,
        MemoryFormat::SignedDword,
        MemoryFormat::UnsignedDword,
        MemoryFormat::SignedQword,
        MemoryFormat::UnsignedQword,
        MemoryFormat::Disassembly,
    ];

    pub fn label(self) -> &'static str {
        match self {
            MemoryFormat::HexAscii => "Hex + ASCII",
            MemoryFormat::HexUnicode => "Hex + UTF-16",
            MemoryFormat::Words => "Word hex (2)",
            MemoryFormat::Dwords => "Dword hex (4)",
            MemoryFormat::Qwords => "Qword hex (8)",
            MemoryFormat::Address => "Ponteiro com símbolo",
            MemoryFormat::Float => "Float",
            MemoryFormat::Double => "Double",
            MemoryFormat::SignedByte => "Inteiro de 1 byte com sinal",
            MemoryFormat::UnsignedByte => "Inteiro de 1 byte sem sinal",
            MemoryFormat::SignedWord => "Inteiro de 2 bytes com sinal",
            MemoryFormat::UnsignedWord => "Inteiro de 2 bytes sem sinal",
            MemoryFormat::SignedDword => "Inteiro de 4 bytes com sinal",
            MemoryFormat::UnsignedDword => "Inteiro de 4 bytes sem sinal",
            MemoryFormat::SignedQword => "Inteiro de 8 bytes com sinal",
            MemoryFormat::UnsignedQword => "Inteiro de 8 bytes sem sinal",
            MemoryFormat::Disassembly => "Desmontagem",
        }
    }

    /// Bytes de cada valor (0 = formato de linha inteira).
    pub fn unit(self) -> usize {
        match self {
            MemoryFormat::HexAscii | MemoryFormat::HexUnicode | MemoryFormat::Disassembly => 0,
            MemoryFormat::SignedByte | MemoryFormat::UnsignedByte => 1,
            MemoryFormat::Words | MemoryFormat::SignedWord | MemoryFormat::UnsignedWord => 2,
            MemoryFormat::Dwords | MemoryFormat::Float | MemoryFormat::SignedDword | MemoryFormat::UnsignedDword => 4,
            MemoryFormat::Qwords | MemoryFormat::Address | MemoryFormat::Double | MemoryFormat::SignedQword | MemoryFormat::UnsignedQword => 8,
        }
    }

    /// Bytes por linha.
    pub fn row_bytes(self) -> usize {
        match self {
            MemoryFormat::Address => 8,
            MemoryFormat::Double | MemoryFormat::SignedQword | MemoryFormat::UnsignedQword => 16,
            _ => 16,
        }
    }
}

/// O valor little-endian de até 8 bytes (os que faltam são zero).
pub fn integer(piece: &[u8]) -> u64 {
    let mut raw = [0u8; 8];
    let count = piece.len().min(8);
    raw[..count].copy_from_slice(&piece[..count]);
    u64::from_le_bytes(raw)
}

/// Um valor no formato (sem o símbolo do ponteiro, que a janela põe).
pub fn format_value(format: MemoryFormat, piece: &[u8]) -> String {
    let value = integer(piece);
    match format {
        MemoryFormat::Words => format!("{value:04X}"),
        MemoryFormat::Dwords => format!("{value:08X}"),
        MemoryFormat::Qwords | MemoryFormat::Address => format!("{value:016X}"),
        MemoryFormat::Float => format!("{:>14.6e}", f32::from_bits(value as u32)),
        MemoryFormat::Double => format!("{:>24.12e}", f64::from_bits(value)),
        MemoryFormat::SignedByte => format!("{:>4}", value as u8 as i8),
        MemoryFormat::UnsignedByte => format!("{:>3}", value as u8),
        MemoryFormat::SignedWord => format!("{:>6}", value as u16 as i16),
        MemoryFormat::UnsignedWord => format!("{:>5}", value as u16),
        MemoryFormat::SignedDword => format!("{:>11}", value as u32 as i32),
        MemoryFormat::UnsignedDword => format!("{:>10}", value as u32),
        MemoryFormat::SignedQword => format!("{:>20}", value as i64),
        MemoryFormat::UnsignedQword => format!("{:>20}", value),
        MemoryFormat::HexAscii | MemoryFormat::HexUnicode | MemoryFormat::Disassembly => piece.iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(" "),
    }
}

/// Os valores de uma linha de bytes no formato.
pub fn format_row(format: MemoryFormat, bytes: &[u8]) -> Vec<String> {
    let unit = format.unit().max(1);
    bytes.chunks(unit).map(|piece| format_value(format, piece)).collect()
}

/// O texto ASCII (os não imprimíveis viram ponto).
pub fn ascii(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| if (0x20..0x7F).contains(&byte) { byte as char } else { '.' }).collect()
}

/// O texto UTF-16 (os de controle viram ponto).
pub fn utf16(bytes: &[u8]) -> String {
    bytes.chunks(2).map(|pair| char::from_u32(u16::from_le_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32).filter(|character| !character.is_control()).unwrap_or('.')).collect()
}

/// Um valor digitado no formato de volta aos bytes (a edição de um item).
pub fn parse_value(format: MemoryFormat, text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    let unit = format.unit();
    match format {
        MemoryFormat::Float => text.parse::<f32>().ok().map(|value| value.to_le_bytes().to_vec()),
        MemoryFormat::Double => text.parse::<f64>().ok().map(|value| value.to_le_bytes().to_vec()),
        MemoryFormat::SignedByte | MemoryFormat::SignedWord | MemoryFormat::SignedDword | MemoryFormat::SignedQword => {
            let value: i64 = text.parse().ok()?;
            let bits = unit * 8;
            if bits < 64 && (value < -(1i64 << (bits - 1)) || value >= 1i64 << (bits - 1)) {
                return None;
            }
            Some(value.to_le_bytes()[..unit].to_vec())
        }
        MemoryFormat::UnsignedByte | MemoryFormat::UnsignedWord | MemoryFormat::UnsignedDword | MemoryFormat::UnsignedQword => {
            let value: u64 = text.parse().ok()?;
            if unit < 8 && value >> (unit * 8) != 0 {
                return None;
            }
            Some(value.to_le_bytes()[..unit].to_vec())
        }
        _ if unit > 0 => {
            let value = u64::from_str_radix(text.trim_start_matches("0x"), 16).ok()?;
            if unit < 8 && value >> (unit * 8) != 0 {
                return None;
            }
            Some(value.to_le_bytes()[..unit].to_vec())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_every_width_and_sign() {
        let bytes = [0xFF, 0xFE, 0x01, 0x00, 0x00, 0x00, 0x80, 0xBF];
        assert_eq!(format_row(MemoryFormat::SignedByte, &bytes[..2]), vec!["  -1", "  -2"]);
        assert_eq!(format_row(MemoryFormat::UnsignedByte, &bytes[..2]), vec!["255", "254"]);
        assert_eq!(format_value(MemoryFormat::SignedWord, &bytes[..2]), "  -257");
        assert_eq!(format_value(MemoryFormat::UnsignedWord, &bytes[..2]), "65279");
        assert_eq!(format_value(MemoryFormat::SignedDword, &bytes[..4]), "     130815");
        assert_eq!(format_value(MemoryFormat::UnsignedDword, &[0xFF, 0xFF, 0xFF, 0xFF]), "4294967295");
        assert_eq!(format_value(MemoryFormat::SignedDword, &[0xFF, 0xFF, 0xFF, 0xFF]), "         -1");
        assert_eq!(format_value(MemoryFormat::SignedQword, &[0xFF; 8]).trim(), "-1");
        assert_eq!(format_value(MemoryFormat::UnsignedQword, &[0xFF; 8]).trim(), "18446744073709551615");
        // -1.0 em double: 0xBFF0000000000000.
        assert_eq!(format_value(MemoryFormat::Double, &(-1.0f64).to_le_bytes()).trim(), "-1.000000000000e0");
        assert_eq!(format_value(MemoryFormat::Float, &1.5f32.to_le_bytes()).trim(), "1.500000e0");
        assert_eq!(format_value(MemoryFormat::Dwords, &[0x78, 0x56, 0x34, 0x12]), "12345678");
        assert_eq!(ascii(b"Ab\x01c"), "Ab.c");
        assert_eq!(utf16(&[b'O', 0, b'k', 0]), "Ok");
        assert_eq!(MemoryFormat::ALL.len(), 17);
    }

    #[test]
    fn parses_edited_values() {
        assert_eq!(parse_value(MemoryFormat::SignedWord, "-2"), Some(vec![0xFE, 0xFF]));
        assert_eq!(parse_value(MemoryFormat::SignedByte, "-129"), None);
        assert_eq!(parse_value(MemoryFormat::UnsignedByte, "256"), None);
        assert_eq!(parse_value(MemoryFormat::UnsignedDword, "4294967295"), Some(vec![0xFF; 4]));
        assert_eq!(parse_value(MemoryFormat::Qwords, "0x10"), Some(vec![0x10, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(parse_value(MemoryFormat::Float, "1.5"), Some(1.5f32.to_le_bytes().to_vec()));
        assert_eq!(parse_value(MemoryFormat::HexAscii, "1"), None);
    }
}
