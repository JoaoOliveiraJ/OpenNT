//! O interpretador de INF do Configuration Manager (CmpParseInfBuffer).
//!
//! O kernel interpreta sozinho os INFs que o carregador de boot lhe entrega
//! (o de errata do Errata Manager, `em/database.rs`). O texto vira uma
//! lista de seções, cada uma com as suas linhas (chave opcional e valores),
//! como as estruturas do CmpParseInfBuffer:
//! - o CmpGetToken separa os tokens: fim (fim do buffer ou Ctrl-Z), fim de
//!   linha, `[`, `]`, `=`, `,` e cadeias; espaços (isspace, menos o `\n`)
//!   separam tokens, `;` e `#` comentam até o fim da linha, `\` seguido de
//!   espaços (e de um comentário) e do fim da linha junta a linha seguinte,
//!   e a cadeia entre aspas vai até a aspa que fecha, sem `\r`, `\n`, `\v`
//!   nem `\f` no meio; a cadeia sem aspas termina em `[]=,`, espaço, tab,
//!   aspa ou nos mesmos controles;
//! - a máquina de estados do CmpParseInfBuffer monta as seções
//!   (`[nome]` sozinho na linha; o nome repetido continua a seção
//!   existente), as linhas `chave = v1, v2...` e as linhas sem chave (os
//!   valores direto); o valor vazio entre vírgulas ou depois do `=` é a
//!   cadeia vazia (o EmptyValue);
//! - as consultas (CmpSearchSectionByName, CmpSearchLineInSectionByIndex,
//!   CmpGetKeyName, CmpGetSectionLineIndex e
//!   CmpGetSectionLineIndexValueCount) comparam nomes de seção sem
//!   diferenciar maiúsculas, e o valor `%nome%` é trocado pelo primeiro
//!   valor da linha `nome` da seção `[Strings]` (CmpProcessForSimpleStringSub).

use alloc::string::String;
use alloc::vec::Vec;

/// Uma linha: a chave (antes do `=`) e os valores.
pub struct Line {
    pub key: Option<String>,
    pub values: Vec<String>,
}

/// Uma seção e as suas linhas, na ordem do arquivo.
pub struct Section {
    pub name: String,
    pub lines: Vec<Line>,
}

/// O INF interpretado.
pub struct Inf {
    sections: Vec<Section>,
    /// A seção `[Strings]`, a das substituições `%nome%`.
    strings: Option<usize>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
enum Token {
    End,
    EndOfLine,
    OpenBracket,
    CloseBracket,
    Text(String),
    Equal,
    Comma,
    Error,
}

/// Os terminadores da cadeia sem aspas (StringTerminators); a cadeia entre
/// aspas usa a cauda, a partir da aspa.
const TERMINATORS: &[u8] = b"[]=,\t \"\n\x0c\x0b\r";
const QUOTED_TERMINATORS: &[u8] = b"\"\n\x0c\x0b\r";

/// isspace da CRT.
fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn text(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| byte as char).collect()
}

struct Tokenizer<'a> {
    buffer: &'a [u8],
    position: usize,
}

impl Tokenizer<'_> {
    fn at(&self, position: usize) -> u8 {
        self.buffer.get(position).copied().unwrap_or(0)
    }

    /// Avança até o `\n` (sem consumi-lo) ou o fim, a partir de `position`.
    fn line_end(&self, mut position: usize) -> usize {
        while position < self.buffer.len() && self.buffer[position] != b'\n' {
            position += 1;
        }
        position
    }

    /// A cadeia sem aspas que começa em `start`.
    fn bare_string(&mut self, start: usize) -> Token {
        let mut end = start;
        while end < self.buffer.len() && !TERMINATORS.contains(&self.buffer[end]) {
            end += 1;
        }
        if end == start {
            self.position = end + 1;
            return Token::Error;
        }
        self.position = end;
        Token::Text(text(&self.buffer[start..end]))
    }

    /// CmpGetToken.
    fn next(&mut self) -> Token {
        loop {
            let mut position = self.position;
            while position < self.buffer.len() && self.buffer[position] != b'\n' && is_space(self.buffer[position]) {
                position += 1;
            }
            if position >= self.buffer.len() {
                self.position = position;
                return Token::End;
            }
            if matches!(self.buffer[position], b';' | b'#') {
                position = self.line_end(position);
            }
            if position >= self.buffer.len() || self.buffer[position] == 0x1a {
                self.position = position;
                return Token::End;
            }
            let simple = match self.buffer[position] {
                b'\n' => Some(Token::EndOfLine),
                b',' => Some(Token::Comma),
                b'=' => Some(Token::Equal),
                b'[' => Some(Token::OpenBracket),
                b']' => Some(Token::CloseBracket),
                _ => None,
            };
            if let Some(token) = simple {
                self.position = position + 1;
                return token;
            }
            match self.buffer[position] {
                b'"' => {
                    let start = position + 1;
                    let mut end = start;
                    while end < self.buffer.len() && !QUOTED_TERMINATORS.contains(&self.buffer[end]) {
                        end += 1;
                    }
                    if end < self.buffer.len() && self.buffer[end] == b'"' {
                        self.position = end + 1;
                        return Token::Text(text(&self.buffer[start..end]));
                    }
                    self.position = end;
                    return Token::Error;
                }
                b'\\' => {
                    // Continuação: espaços, um comentário opcional e o fim da
                    // linha juntam a linha seguinte; outra coisa começa uma
                    // cadeia logo depois da barra.
                    let after = position + 1;
                    let mut cursor = after;
                    while cursor < self.buffer.len() && self.buffer[cursor] != b'\n' && is_space(self.buffer[cursor]) {
                        cursor += 1;
                    }
                    if matches!(self.at(cursor), b';' | b'#') {
                        cursor = self.line_end(after + 1);
                    }
                    if cursor >= self.buffer.len() {
                        self.position = after;
                        return Token::Error;
                    }
                    if self.buffer[cursor] == b'\n' {
                        self.position = cursor + 1;
                        continue;
                    }
                    return self.bare_string(after);
                }
                _ => return self.bare_string(position),
            }
        }
    }
}

/// O montador das seções (CmpAppendSection, CmpAppendLine e
/// CmpAppendValue).
struct Builder {
    sections: Vec<Section>,
    strings: Option<usize>,
    current: Option<usize>,
}

impl Builder {
    fn append_section(&mut self, name: String) {
        if let Some(index) = self.sections.iter().position(|section| section.name.eq_ignore_ascii_case(&name)) {
            self.current = Some(index);
            return;
        }
        let exact_strings = name.eq_ignore_ascii_case("Strings");
        self.sections.push(Section { name, lines: Vec::new() });
        let index = self.sections.len() - 1;
        if exact_strings {
            self.strings = Some(index);
        }
        self.current = Some(index);
    }

    fn append_line(&mut self, key: Option<String>) -> bool {
        let Some(section) = self.current else { return false };
        self.sections[section].lines.push(Line { key, values: Vec::new() });
        true
    }

    fn append_value(&mut self, value: String) -> bool {
        let Some(line) = self.current.and_then(|section| self.sections[section].lines.last_mut()) else { return false };
        line.values.push(value);
        true
    }
}

/// CmpParseInfBuffer: o INF interpretado, ou a linha (contando de 1) do
/// erro de sintaxe.
pub fn parse(buffer: &[u8]) -> Result<Inf, u32> {
    let mut tokens = Tokenizer { buffer, position: 0 };
    let mut builder = Builder { sections: Vec::new(), strings: None, current: None };
    let mut state = 1u32;
    let mut line = 1u32;
    let mut pending = String::new();
    loop {
        let token = tokens.next();
        let mut done = false;
        let ok = match (state, token.clone()) {
            (1, Token::End) | (5, Token::End) | (9, Token::End) => {
                done = true;
                true
            }
            (1, Token::EndOfLine) | (5, Token::EndOfLine) => true,
            (1, Token::OpenBracket) | (5, Token::OpenBracket) => {
                state = 2;
                true
            }
            (2, Token::Text(name)) => {
                pending = name;
                state = 3;
                true
            }
            (2, Token::CloseBracket) => {
                pending = String::new();
                state = 4;
                true
            }
            (3, Token::CloseBracket) => {
                state = 4;
                true
            }
            (4, Token::EndOfLine) | (4, Token::End) => {
                builder.append_section(core::mem::take(&mut pending));
                done = token == Token::End;
                state = 5;
                true
            }
            (5, Token::Text(value)) => {
                pending = value;
                state = 6;
                true
            }
            (6, Token::Equal) => {
                state = 8;
                builder.append_line(Some(core::mem::take(&mut pending)))
            }
            (6, Token::Comma) | (6, Token::EndOfLine) | (6, Token::End) => {
                let appended = builder.append_line(None) && builder.append_value(core::mem::take(&mut pending));
                state = if token == Token::Comma { 7 } else { 5 };
                done = token == Token::End;
                appended
            }
            (7, Token::Text(value)) | (8, Token::Text(value)) => {
                state = 9;
                builder.append_value(value)
            }
            (7, Token::Comma) => builder.append_value(String::new()),
            (8, Token::EndOfLine) | (8, Token::End) => {
                state = 5;
                done = token == Token::End;
                builder.append_value(String::new())
            }
            (9, Token::EndOfLine) => {
                state = 5;
                true
            }
            (9, Token::Comma) => {
                state = 7;
                true
            }
            _ => false,
        };
        if !ok {
            return Err(line);
        }
        if token == Token::EndOfLine {
            line += 1;
        }
        if done {
            return Ok(Inf { sections: builder.sections, strings: builder.strings });
        }
    }
}

impl Inf {
    /// CmpSearchSectionByName.
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|section| section.name.eq_ignore_ascii_case(name))
    }

    /// A linha `index` da seção (CmpSearchLineInSectionByIndex).
    pub fn line(&self, section: &str, index: u32) -> Option<&Line> {
        self.section(section)?.lines.get(index as usize)
    }

    /// Quantas linhas a seção tem (EmpInfParseGetSectionLineCount).
    pub fn line_count(&self, section: &str) -> u32 {
        self.section(section).map_or(0, |section| section.lines.len() as u32)
    }

    /// CmpGetKeyName.
    pub fn key_name(&self, section: &str, index: u32) -> Option<&str> {
        self.line(section, index)?.key.as_deref()
    }

    /// CmpGetSectionLineIndexValueCount.
    pub fn value_count(&self, section: &str, index: u32) -> u32 {
        self.line(section, index).map_or(0, |line| line.values.len() as u32)
    }

    /// CmpGetSectionLineIndex: o valor, com a substituição `%nome%`.
    pub fn value(&self, section: &str, index: u32, value: u32) -> Option<&str> {
        let raw = self.line(section, index)?.values.get(value as usize)?;
        Some(self.substitute(raw))
    }

    /// CmpProcessForSimpleStringSub: `%nome%` (mais de dois caracteres) pelo
    /// primeiro valor da linha `nome` da seção [Strings].
    fn substitute<'a>(&'a self, raw: &'a str) -> &'a str {
        let bytes = raw.as_bytes();
        if bytes.len() <= 2 || bytes[0] != b'%' || bytes[bytes.len() - 1] != b'%' {
            return raw;
        }
        let name = &raw[1..raw.len() - 1];
        let Some(strings) = self.strings.map(|index| &self.sections[index]) else { return raw };
        strings.lines.iter().find(|line| line.key.as_deref().is_some_and(|key| key.eq_ignore_ascii_case(name))).and_then(|line| line.values.first()).map_or(raw, |value| value.as_str())
    }

    /// EmpInfParseGetValueFromSectionAndKeyName: o primeiro valor da
    /// primeira linha cuja chave começa por `name` (strnicmp com o tamanho
    /// do nome procurado) e o índice dela.
    pub fn value_by_key(&self, section: &str, name: &str) -> Option<(&str, u32)> {
        let section_lines = &self.section(section)?.lines;
        for (index, line) in section_lines.iter().enumerate() {
            let Some(key) = line.key.as_deref() else { return None };
            let matches = key.len() >= name.len() && key.as_bytes()[..name.len()].eq_ignore_ascii_case(name.as_bytes());
            if matches {
                return self.value(section, index as u32, 0).map(|value| (value, index as u32));
            }
        }
        None
    }
}
