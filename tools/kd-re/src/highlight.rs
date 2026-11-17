//! O modo de destaque da desmontagem (tecla H): o texto de uma instrução
//! em pedaços (mnemônico, registradores, números, símbolos, pontuação) e
//! a comparação que acha as outras ocorrências do pedaço clicado. Um
//! registrador destaca também as partes dele (`rax`, `eax`, `ax`, `al`).

/// O tipo de um pedaço.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    Mnemonic,
    Register,
    Number,
    /// Nome (símbolo, `ptr`, `qword`).
    Word,
    Punctuation,
    Space,
}

/// Um pedaço: o intervalo de caracteres no texto e o tipo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub start: usize,
    pub end: usize,
    pub kind: TokenKind,
    pub text: String,
}

/// A família de um registrador (o de 64 bits), se o nome é de um.
pub fn register_family(name: &str) -> Option<String> {
    let name = name.to_ascii_lowercase();
    let legacy: [(&str, [&str; 4]); 8] = [
        ("rax", ["eax", "ax", "al", "ah"]),
        ("rbx", ["ebx", "bx", "bl", "bh"]),
        ("rcx", ["ecx", "cx", "cl", "ch"]),
        ("rdx", ["edx", "dx", "dl", "dh"]),
        ("rsi", ["esi", "si", "sil", "sil"]),
        ("rdi", ["edi", "di", "dil", "dil"]),
        ("rbp", ["ebp", "bp", "bpl", "bpl"]),
        ("rsp", ["esp", "sp", "spl", "spl"]),
    ];
    for (full, parts) in legacy {
        if name == full || parts.contains(&name.as_str()) {
            return Some(full.to_string());
        }
    }
    for number in 8..16 {
        let full = format!("r{number}");
        if name == full || [format!("r{number}d"), format!("r{number}w"), format!("r{number}b")].contains(&name) {
            return Some(full);
        }
    }
    if ["rip", "eip"].contains(&name.as_str()) {
        return Some("rip".into());
    }
    // XMM/YMM/ZMM do mesmo número são o mesmo registrador.
    for prefix in ["xmm", "ymm", "zmm"] {
        if let Some(number) = name.strip_prefix(prefix).and_then(|rest| rest.parse::<u32>().ok()) {
            return Some(format!("xmm{number}"));
        }
    }
    let other = ["cs", "ds", "es", "fs", "gs", "ss", "cr0", "cr2", "cr3", "cr4", "cr8", "dr0", "dr1", "dr2", "dr3", "dr6", "dr7"];
    if other.contains(&name.as_str()) || (name.starts_with("st") && name.len() <= 5) || (name.starts_with("mm") && name[2..].parse::<u32>().is_ok()) || (name.starts_with('k') && name.len() == 2 && name[1..].parse::<u32>().is_ok()) {
        return Some(name);
    }
    None
}

/// Os pedaços do texto de uma instrução (`mov rax, qword ptr [rbx+0x10]`).
pub fn tokens(text: &str) -> Vec<Token> {
    let characters: Vec<char> = text.chars().collect();
    let mut output = Vec::new();
    let mut index = 0;
    let mut first_word = true;
    while index < characters.len() {
        let character = characters[index];
        let start = index;
        let kind = if character.is_whitespace() {
            while index < characters.len() && characters[index].is_whitespace() {
                index += 1;
            }
            TokenKind::Space
        } else if character.is_ascii_alphanumeric() || matches!(character, '_' | '@' | '$' | '?' | '!' | ':' | '`' | '.') {
            while index < characters.len() && (characters[index].is_ascii_alphanumeric() || matches!(characters[index], '_' | '@' | '$' | '?' | '!' | ':' | '`' | '.' | '<' | '>')) {
                index += 1;
            }
            let word: String = characters[start..index].iter().collect();
            if first_word {
                first_word = false;
                TokenKind::Mnemonic
            } else if register_family(&word).is_some() {
                TokenKind::Register
            } else if word.starts_with("0x") || word.chars().all(|digit| digit.is_ascii_hexdigit()) && word.chars().next().is_some_and(|digit| digit.is_ascii_digit()) {
                TokenKind::Number
            } else {
                TokenKind::Word
            }
        } else {
            index += 1;
            TokenKind::Punctuation
        };
        output.push(Token { start, end: index, kind, text: characters[start..index].iter().collect() });
    }
    output
}

/// O pedaço na coluna `column` (em caracteres), se não é espaço nem
/// pontuação.
pub fn token_at(text: &str, column: usize) -> Option<Token> {
    tokens(text).into_iter().find(|token| column >= token.start && column < token.end && !matches!(token.kind, TokenKind::Space | TokenKind::Punctuation))
}

/// A chave de comparação de um pedaço: a família do registrador, o número
/// sem zeros à esquerda ou o texto em minúsculas.
pub fn key(token: &Token) -> String {
    match token.kind {
        TokenKind::Register => register_family(&token.text).unwrap_or_else(|| token.text.to_ascii_lowercase()),
        TokenKind::Number => {
            let digits = token.text.trim_start_matches("0x").trim_start_matches('0');
            if digits.is_empty() {
                "0".into()
            } else {
                digits.to_ascii_lowercase()
            }
        }
        _ => token.text.to_ascii_lowercase(),
    }
}

/// Os intervalos (em caracteres) dos pedaços de `text` com a chave `wanted`.
pub fn matches(text: &str, wanted: &str) -> Vec<(usize, usize)> {
    tokens(text).into_iter().filter(|token| !matches!(token.kind, TokenKind::Space | TokenKind::Punctuation) && key(token) == wanted).map(|token| (token.start, token.end)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_instruction_text() {
        let list = tokens("mov rax, qword ptr [rbx+0x10]");
        let kinds: Vec<(TokenKind, &str)> = list.iter().filter(|token| token.kind != TokenKind::Space).map(|token| (token.kind, token.text.as_str())).collect();
        assert_eq!(
            kinds,
            vec![(TokenKind::Mnemonic, "mov"), (TokenKind::Register, "rax"), (TokenKind::Punctuation, ","), (TokenKind::Word, "qword"), (TokenKind::Word, "ptr"), (TokenKind::Punctuation, "["), (TokenKind::Register, "rbx"), (TokenKind::Punctuation, "+"), (TokenKind::Number, "0x10"), (TokenKind::Punctuation, "]")]
        );
        assert_eq!(token_at("mov rax, qword ptr [rbx+0x10]", 5).unwrap().text, "rax");
        assert!(token_at("mov rax, rbx", 7).is_none());
        // Símbolos com `!` e `::` ficam inteiros.
        assert_eq!(tokens("call ntdll!LdrLoadDll")[2].text, "ntdll!LdrLoadDll");
    }

    #[test]
    fn register_families_and_matches() {
        assert_eq!(register_family("eax").as_deref(), Some("rax"));
        assert_eq!(register_family("r9d").as_deref(), Some("r9"));
        assert_eq!(register_family("sil").as_deref(), Some("rsi"));
        assert_eq!(register_family("ymm3").as_deref(), Some("xmm3"));
        assert_eq!(register_family("ptr"), None);
        let token = token_at("xor eax, eax", 4).unwrap();
        assert_eq!(key(&token), "rax");
        assert_eq!(matches("mov rax, qword ptr [rax+8]", "rax"), vec![(4, 7), (20, 23)]);
        assert_eq!(matches("lea r8d, [r8+r8*2]", "r8").len(), 3);
        // Números iguais com outra grafia.
        let number = token_at("add rsp, 0x028", 9).unwrap();
        assert_eq!(key(&number), "28");
        assert_eq!(matches("sub rsp, 0x28", "28"), vec![(9, 13)]);
    }
}
