//! Leitor de um subconjunto de TOML, suficiente para `docs/status/components.toml`
//! sem dependências externas: comentários `#`, tabelas `[nome]`, arrays de
//! tabelas `[[nome]]`, chaves simples ou entre aspas, strings básicas (com
//! `\"`, `\\`, `\n`, `\t`), booleanos, inteiros e arrays (inclusive em várias
//! linhas). Datas, tabelas inline e strings literais não são aceitas.

use std::collections::BTreeMap;

// Booleanos e inteiros são aceitos na leitura, embora nenhum campo os use hoje.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum Value {
    String(String),
    Bool(bool),
    Integer(i64),
    Array(Vec<Value>),
}

#[derive(Clone, Debug, Default)]
pub struct Table {
    pub entries: Vec<(String, Value)>,
}

impl Table {
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.iter().find(|(name, _)| name == key).map(|(_, value)| value)
    }

    pub fn string(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(Value::String(text)) => Some(text),
            _ => None,
        }
    }

    /// Uma string ou um array de strings; ausente = vazio.
    pub fn strings(&self, key: &str) -> Vec<String> {
        match self.get(key) {
            Some(Value::String(text)) => vec![text.clone()],
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|item| match item {
                    Value::String(text) => Some(text.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
pub struct Document {
    pub root: Table,
    pub tables: BTreeMap<String, Table>,
    pub arrays: BTreeMap<String, Vec<Table>>,
}

impl Document {
    pub fn table(&self, name: &str) -> Option<&Table> {
        self.tables.get(name)
    }

    pub fn array(&self, name: &str) -> &[Table] {
        self.arrays.get(name).map(Vec::as_slice).unwrap_or(&[])
    }
}

enum Target {
    Root,
    Table(String),
    Array(String),
}

/// Remove o comentário da linha, respeitando strings.
fn strip_comment(line: &str) -> &str {
    let mut in_string = false;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        match character {
            _ if escaped => escaped = false,
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            '#' if !in_string => return &line[..index],
            _ => {}
        }
    }
    line
}

/// Saldo de colchetes fora de strings (para arrays em várias linhas).
fn bracket_balance(text: &str) -> i32 {
    let mut balance = 0;
    let mut in_string = false;
    let mut escaped = false;
    for character in text.chars() {
        match character {
            _ if escaped => escaped = false,
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            '[' if !in_string => balance += 1,
            ']' if !in_string => balance -= 1,
            _ => {}
        }
    }
    balance
}

struct Cursor<'a> {
    text: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn skip_blank(&mut self) {
        while self.at < self.text.len() && (self.text[self.at] as char).is_whitespace() {
            self.at += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.text.get(self.at).copied()
    }

    fn string(&mut self) -> Result<String, String> {
        self.at += 1; // aspas de abertura
        let mut bytes = Vec::new();
        loop {
            let byte = self.peek().ok_or("string sem aspas de fechamento")?;
            self.at += 1;
            match byte {
                b'"' => break,
                b'\\' => {
                    let escaped = self.peek().ok_or("escape incompleto")?;
                    self.at += 1;
                    bytes.push(match escaped {
                        b'"' => b'"',
                        b'\\' => b'\\',
                        b'n' => b'\n',
                        b't' => b'\t',
                        other => return Err(format!("escape nao suportado: \\{}", other as char)),
                    });
                }
                b'\n' => return Err("string basica nao pode quebrar linha".into()),
                other => bytes.push(other),
            }
        }
        String::from_utf8(bytes).map_err(|_| "string com UTF-8 invalido".into())
    }

    fn value(&mut self) -> Result<Value, String> {
        self.skip_blank();
        match self.peek() {
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b'[') => {
                self.at += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_blank();
                    match self.peek() {
                        Some(b']') => {
                            self.at += 1;
                            break;
                        }
                        Some(_) => {
                            items.push(self.value()?);
                            self.skip_blank();
                            match self.peek() {
                                Some(b',') => self.at += 1,
                                Some(b']') => {}
                                _ => return Err("array: esperado ',' ou ']'".into()),
                            }
                        }
                        None => return Err("array sem ']'".into()),
                    }
                }
                Ok(Value::Array(items))
            }
            Some(_) => {
                let start = self.at;
                while self.at < self.text.len() && !matches!(self.text[self.at], b',' | b']') {
                    self.at += 1;
                }
                let word = std::str::from_utf8(&self.text[start..self.at]).unwrap_or("").trim();
                match word {
                    "true" => Ok(Value::Bool(true)),
                    "false" => Ok(Value::Bool(false)),
                    _ => word
                        .replace('_', "")
                        .parse::<i64>()
                        .map(Value::Integer)
                        .map_err(|_| format!("valor nao suportado: {word}")),
                }
            }
            None => Err("valor ausente".into()),
        }
    }
}

fn parse_key(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if raw.starts_with('"') {
        let mut cursor = Cursor { text: raw.as_bytes(), at: 0 };
        let key = cursor.string()?;
        if cursor.at != raw.len() {
            return Err(format!("chave invalida: {raw}"));
        }
        return Ok(key);
    }
    if !raw.is_empty() && raw.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        Ok(raw.to_string())
    } else {
        Err(format!("chave invalida: {raw}"))
    }
}

/// Divide `chave = valor` no primeiro `=` fora de aspas.
fn split_assignment(line: &str) -> Option<(&str, &str)> {
    let mut in_string = false;
    for (index, character) in line.char_indices() {
        match character {
            '"' => in_string = !in_string,
            '=' if !in_string => return Some((&line[..index], &line[index + 1..])),
            _ => {}
        }
    }
    None
}

pub fn parse(text: &str) -> Result<Document, String> {
    let mut document = Document::default();
    let mut target = Target::Root;
    let mut pending: Option<(usize, String, String)> = None; // (linha, chave, valor parcial)

    for (number, raw_line) in text.lines().enumerate() {
        let number = number + 1;
        let line = strip_comment(raw_line);
        let (line_number, key, value_text) = if let Some((start, key, mut partial)) = pending.take() {
            partial.push('\n');
            partial.push_str(line);
            if bracket_balance(&partial) > 0 {
                pending = Some((start, key, partial));
                continue;
            }
            (start, key, partial)
        } else {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(name) = trimmed.strip_prefix("[[").and_then(|rest| rest.strip_suffix("]]")) {
                let name = parse_key(name).map_err(|error| format!("linha {number}: {error}"))?;
                document.arrays.entry(name.clone()).or_default().push(Table::default());
                target = Target::Array(name);
                continue;
            }
            if let Some(name) = trimmed.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
                let name = parse_key(name).map_err(|error| format!("linha {number}: {error}"))?;
                if document.tables.contains_key(&name) {
                    return Err(format!("linha {number}: tabela [{name}] repetida"));
                }
                document.tables.insert(name.clone(), Table::default());
                target = Target::Table(name);
                continue;
            }
            let (key, value) =
                split_assignment(trimmed).ok_or_else(|| format!("linha {number}: esperado chave = valor"))?;
            let key = parse_key(key).map_err(|error| format!("linha {number}: {error}"))?;
            let value = value.trim().to_string();
            if bracket_balance(&value) > 0 {
                pending = Some((number, key, value));
                continue;
            }
            (number, key, value)
        };

        let mut cursor = Cursor { text: value_text.as_bytes(), at: 0 };
        let value = cursor.value().map_err(|error| format!("linha {line_number}: {error}"))?;
        cursor.skip_blank();
        if cursor.at != value_text.len() {
            return Err(format!("linha {line_number}: texto sobrando depois do valor"));
        }
        let table = match &target {
            Target::Root => &mut document.root,
            Target::Table(name) => document.tables.get_mut(name).unwrap(),
            Target::Array(name) => document.arrays.get_mut(name).unwrap().last_mut().unwrap(),
        };
        if table.get(&key).is_some() {
            return Err(format!("linha {line_number}: chave repetida: {key}"));
        }
        table.entries.push((key, value));
    }
    if let Some((start, key, _)) = pending {
        return Err(format!("linha {start}: array de {key} sem ']'"));
    }
    Ok(document)
}
