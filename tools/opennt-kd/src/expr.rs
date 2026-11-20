//! As expressões do depurador, no espírito das do WinDbg (MASM) com o
//! acesso tipado do C:
//!
//! - números: `0x1f`, `0xfffff800`40000000`, decimais (`42`, `0n42`) e
//!   hexadecimal sem prefixo com letras (`fffff80040000000`) quando não é
//!   um símbolo;
//! - registradores `@rax`, `%rax` ou só `rax` (`@gs_base`, `@fs_base`);
//!   variáveis `$nome` (ou `@$nome`); símbolos (`ntfs!NtfsCommonCreate`,
//!   `kernel::ntos::ke::run_kernel_tasks`, `create<u64>`, `<A as B>::f`) e
//!   módulo mais RVA (`Windows.UI.Logon+0x48b50`);
//! - memória: `poi(x)`, `by(x)`, `wo(x)`, `dwo(x)`, `qwo(x)`, `[x]`,
//!   `byte[x]`, `word[x]`, `dword[x]`, `qword[x]`; `$iment(módulo)` (o
//!   ponto de entrada), `sizeof(_IRP)`;
//! - operadores do C com a precedência do C: `|| && | ^ & == != < > <= >=
//!   << >> + - * / %` e os unários `- ~ ! * &`;
//! - tipos do PDB do ntoskrnl: `(_IRP*)@rcx`, `((nt!_IRP*)@rcx)->Tail.Overlay.CurrentStackLocation`,
//!   `p->Campo`, `s.Campo`, `*p`, `&s.Campo`, `p[2]`.

use std::sync::Arc;

use super::types::{Kind, TypeDb};
use super::unwind::ReadMemory;

/// O que a avaliação consulta.
pub trait Environment {
    fn register(&mut self, name: &str) -> Result<u64, String>;
    fn read_memory(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String>;
    fn symbol(&mut self, name: &str) -> Result<u64, String>;
    fn variable(&mut self, name: &str) -> Option<u64>;
    /// O nome é de um registrador (para aceitar `rax` sem `@`).
    fn is_register(&self, name: &str) -> bool;
    /// Os tipos do NT (carregados na primeira expressão tipada).
    fn types(&mut self) -> Option<Arc<TypeDb>> {
        None
    }
    /// O ponto de entrada de um módulo carregado (`$iment`).
    fn image_entry(&mut self, module: &str) -> Result<u64, String> {
        Err(format!("$iment({module}): sem a lista de modulos"))
    }
}

struct Memory<'a>(&'a mut dyn Environment);

impl ReadMemory for Memory<'_> {
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
        self.0.read_memory(address, length)
    }
}

/// Um tipo: um índice do TPI com níveis de ponteiro por cima (um cast
/// `(_IRP**)` não precisa de LF_POINTER no PDB).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ty {
    pub index: u32,
    pub pointers: u8,
}

/// O resultado: o número e, quando tipado, o tipo e onde mora o valor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Value {
    /// Escalares: o valor; structs e arrays: o endereço.
    pub number: u64,
    pub ty: Option<Ty>,
    /// O endereço do valor tipado (para `&` e para abrir na observação).
    pub address: Option<u64>,
}

impl Value {
    fn plain(number: u64) -> Self {
        Self { number, ty: None, address: None }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Number(u64),
    Name(String),
    Register(String),
    Variable(String),
    Operator(&'static str),
}

const OPERATORS: [&str; 27] = ["->", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "+", "-", "*", "/", "%", "&", "|", "^", "~", "!", "<", ">", "(", ")", "[", "]", ".", ","];

fn is_name_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '$' | '?' | '@' | '!' | ':' | '{' | '}')
}

/// O fim de um grupo `<...>` balanceado a partir de `start` (no `<`).
fn generic_end(text: &[char], start: usize) -> Option<usize> {
    let mut depth = 0;
    for (index, &character) in text.iter().enumerate().skip(start) {
        match character {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    let inner: String = text[start + 1..index].iter().collect();
                    if ["&&", "||", "==", "!=", ">=", "<="].iter().any(|operator| inner.contains(operator)) {
                        return None;
                    }
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_number_token(text: &str) -> Option<u64> {
    let clean = text.replace(['`', '_'], "");
    if let Some(hex) = clean.strip_prefix("0x").or_else(|| clean.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    if let Some(decimal) = clean.strip_prefix("0n") {
        return decimal.parse().ok();
    }
    if clean.chars().all(|character| character.is_ascii_digit()) {
        return clean.parse().ok();
    }
    None
}

fn tokenize(text: &str) -> Result<Vec<Token>, String> {
    let characters: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        if character.is_whitespace() {
            index += 1;
            continue;
        }
        let expects_operand = !matches!(tokens.last(), Some(Token::Number(_) | Token::Name(_) | Token::Register(_) | Token::Variable(_) | Token::Operator(")" | "]")));
        // Números (com ` e _ como separadores).
        if character.is_ascii_digit() {
            let start = index;
            while index < characters.len() && (characters[index].is_ascii_alphanumeric() || matches!(characters[index], '`' | '_')) {
                index += 1;
            }
            let word: String = characters[start..index].iter().collect();
            match parse_number_token(&word) {
                Some(number) => tokens.push(Token::Number(number)),
                // `1f` e afins: hexadecimal sem prefixo, decidido na avaliação.
                None => tokens.push(Token::Name(word)),
            }
            continue;
        }
        // `@$nome` (a forma do WinDbg para as pseudo-variáveis) é `$nome`.
        if character == '@' && characters.get(index + 1) == Some(&'$') {
            index += 1;
            continue;
        }
        // Registradores: `@gs_base`, `%rax`. O `%` só no lugar de um operando
        // (`a%b` é o resto da divisão).
        if (character == '@' || (character == '%' && expects_operand)) && characters.get(index + 1).is_some_and(|next| next.is_ascii_alphabetic()) {
            let start = index + 1;
            index = start;
            while index < characters.len() && (characters[index].is_ascii_alphanumeric() || characters[index] == '_') {
                index += 1;
            }
            tokens.push(Token::Register(characters[start..index].iter().collect::<String>().to_ascii_lowercase()));
            continue;
        }
        if character == '$' && characters.get(index + 1).is_some_and(|next| next.is_ascii_alphanumeric() || *next == '_') {
            let start = index + 1;
            index = start;
            while index < characters.len() && (characters[index].is_ascii_alphanumeric() || characters[index] == '_') {
                index += 1;
            }
            tokens.push(Token::Variable(characters[start..index].iter().collect()));
            continue;
        }
        // Nomes: identificadores do Rust e do C, `módulo!símbolo` e
        // `módulo+RVA` (o módulo pode ter `.`: `Windows.UI.Logon+0x48b50`),
        // `<A as B>::f` no começo e genéricos `f<T>`. Um nome solto nunca tem
        // tipo, então `a.b` não é acesso a campo; depois de `->` ou `.` o
        // nome com pontos é dividido em campos.
        let starts_qualified = character == '<' && expects_operand && generic_end(&characters, index).is_some_and(|end| characters.get(end + 1) == Some(&':') && characters.get(end + 2) == Some(&':'));
        if character.is_ascii_alphabetic() || character == '_' || character == '?' || starts_qualified {
            let start = index;
            if starts_qualified {
                index = generic_end(&characters, index).unwrap_or(index) + 1;
            }
            loop {
                while index < characters.len() && is_name_character(characters[index]) {
                    // `::` faz parte do nome; `:` sozinho não.
                    if characters[index] == ':' && characters.get(index + 1) != Some(&':') && (index == 0 || characters[index - 1] != ':') {
                        break;
                    }
                    index += 1;
                }
                match characters.get(index) {
                    // `ksecdd.sys!Funcao`, `Windows.UI.Logon+0x10`: o ponto
                    // seguido de mais nome.
                    Some('.') if characters.get(index + 1).is_some_and(|next| next.is_ascii_alphanumeric() || *next == '_') => index += 1,
                    Some('<') => match generic_end(&characters, index) {
                        Some(end) => index = end + 1,
                        None => break,
                    },
                    _ => break,
                }
            }
            tokens.push(Token::Name(characters[start..index].iter().collect()));
            continue;
        }
        let rest: String = characters[index..characters.len().min(index + 2)].iter().collect();
        match OPERATORS.iter().find(|operator| rest.starts_with(**operator)) {
            Some(operator) => {
                tokens.push(Token::Operator(operator));
                index += operator.len();
            }
            None => return Err(format!("caractere inesperado na expressao: {character:?}")),
        }
    }
    Ok(tokens)
}

/// Avalia uma expressão.
pub fn evaluate(environment: &mut dyn Environment, text: &str) -> Result<Value, String> {
    let tokens = tokenize(text)?;
    if tokens.is_empty() {
        return Err("expressao vazia".into());
    }
    let mut parser = Parser { tokens, position: 0, environment, types: None, types_loaded: false };
    let value = parser.expression()?;
    if parser.position < parser.tokens.len() {
        return Err(format!("sobra na expressao: {:?}", parser.tokens[parser.position]));
    }
    Ok(value)
}

/// Avalia e devolve só o número.
pub fn evaluate_number(environment: &mut dyn Environment, text: &str) -> Result<u64, String> {
    Ok(evaluate(environment, text)?.number)
}

struct Parser<'a> {
    tokens: Vec<Token>,
    position: usize,
    environment: &'a mut dyn Environment,
    types: Option<Arc<TypeDb>>,
    types_loaded: bool,
}

type Binary = fn(u64, u64) -> Result<u64, String>;

fn checked_division(left: u64, right: u64) -> Result<u64, String> {
    left.checked_div(right).ok_or_else(|| "divisao por zero".to_string())
}

fn checked_remainder(left: u64, right: u64) -> Result<u64, String> {
    left.checked_rem(right).ok_or_else(|| "divisao por zero".to_string())
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }

    fn peek_operator(&self, operator: &str) -> bool {
        matches!(self.peek(), Some(Token::Operator(found)) if *found == operator)
    }

    fn expect(&mut self, operator: &str) -> Result<(), String> {
        if self.peek_operator(operator) {
            self.position += 1;
            Ok(())
        } else {
            Err(format!("esperado {operator:?} na expressao"))
        }
    }

    fn type_database(&mut self) -> Option<Arc<TypeDb>> {
        if !self.types_loaded {
            self.types = self.environment.types();
            self.types_loaded = true;
        }
        self.types.clone()
    }

    fn database(&mut self) -> Result<Arc<TypeDb>, String> {
        self.type_database().ok_or_else(|| "sem os tipos do NT (o PDB do ntoskrnl em build/symbols)".to_string())
    }

    fn expression(&mut self) -> Result<Value, String> {
        self.level(0)
    }

    /// Os níveis binários, do menos para o mais forte.
    fn level(&mut self, depth: usize) -> Result<Value, String> {
        const LEVELS: &[&[(&str, Binary)]] = &[
            &[("||", |a, b| Ok(((a != 0) || (b != 0)) as u64))],
            &[("&&", |a, b| Ok(((a != 0) && (b != 0)) as u64))],
            &[("|", |a, b| Ok(a | b))],
            &[("^", |a, b| Ok(a ^ b))],
            &[("&", |a, b| Ok(a & b))],
            &[("==", |a, b| Ok((a == b) as u64)), ("!=", |a, b| Ok((a != b) as u64))],
            &[("<=", |a, b| Ok((a <= b) as u64)), (">=", |a, b| Ok((a >= b) as u64)), ("<", |a, b| Ok((a < b) as u64)), (">", |a, b| Ok((a > b) as u64))],
            &[("<<", |a, b| Ok(a.wrapping_shl(b as u32))), (">>", |a, b| Ok(a.wrapping_shr(b as u32)))],
            &[("+", |a, b| Ok(a.wrapping_add(b))), ("-", |a, b| Ok(a.wrapping_sub(b)))],
            &[("*", |a, b| Ok(a.wrapping_mul(b))), ("/", checked_division), ("%", checked_remainder)],
        ];
        let Some(operators) = LEVELS.get(depth) else { return self.unary() };
        let mut left = self.level(depth + 1)?;
        loop {
            let Some(&(_, operation)) = operators.iter().find(|(operator, _)| self.peek_operator(operator)) else { break };
            self.position += 1;
            let right = self.level(depth + 1)?;
            left = Value::plain(operation(left.number, right.number)?);
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Value, String> {
        let Some(Token::Operator(operator)) = self.peek().cloned() else { return self.postfix() };
        match operator {
            "-" => {
                self.position += 1;
                Ok(Value::plain(self.unary()?.number.wrapping_neg()))
            }
            "~" => {
                self.position += 1;
                Ok(Value::plain(!self.unary()?.number))
            }
            "!" => {
                self.position += 1;
                Ok(Value::plain((self.unary()?.number == 0) as u64))
            }
            "*" => {
                self.position += 1;
                let value = self.unary()?;
                self.dereference(value)
            }
            "&" => {
                self.position += 1;
                let value = self.unary()?;
                let address = value.address.ok_or("& precisa de um valor tipado na memoria")?;
                Ok(Value { number: address, ty: value.ty.map(|ty| Ty { index: ty.index, pointers: ty.pointers + 1 }), address: None })
            }
            "(" => {
                if let Some(ty) = self.cast_type() {
                    let value = self.unary()?;
                    return self.cast(ty, value);
                }
                self.postfix()
            }
            _ => self.postfix(),
        }
    }

    /// `(Tipo*)`: um cast quando o nome é um tipo conhecido e um operando
    /// vem depois do `)` (os tipos só carregam quando a forma bate).
    fn cast_type(&mut self) -> Option<Ty> {
        let Some(Token::Name(name)) = self.tokens.get(self.position + 1).cloned() else { return None };
        let mut position = self.position + 2;
        let mut pointers = 0u8;
        while matches!(self.tokens.get(position), Some(Token::Operator("*"))) {
            pointers += 1;
            position += 1;
        }
        if !matches!(self.tokens.get(position), Some(Token::Operator(")"))) {
            return None;
        }
        let operand_follows = matches!(self.tokens.get(position + 1), Some(Token::Number(_) | Token::Name(_) | Token::Register(_) | Token::Variable(_) | Token::Operator("(" | "*" | "&" | "-" | "~" | "!" | "[")));
        if !operand_follows {
            return None;
        }
        let database = self.type_database()?;
        let index = database.find(&name)?;
        self.position = position + 1;
        Some(Ty { index, pointers })
    }

    fn cast(&mut self, ty: Ty, value: Value) -> Result<Value, String> {
        if ty.pointers > 0 {
            return Ok(Value { number: value.number, ty: Some(ty), address: None });
        }
        // `(_IRP)x`: a struct em x; um escalar: o valor convertido.
        let database = self.database()?;
        match database.kind(ty.index) {
            Kind::Struct { .. } | Kind::Array { .. } => Ok(Value { number: value.number, ty: Some(ty), address: Some(value.number) }),
            _ => {
                let size = database.size(ty.index).clamp(1, 8);
                let mask = if size >= 8 { u64::MAX } else { (1u64 << (8 * size)) - 1 };
                Ok(Value { number: value.number & mask, ty: Some(ty), address: None })
            }
        }
    }

    /// O valor apontado por um ponteiro tipado (ou um u64 de `[x]`).
    fn dereference(&mut self, value: Value) -> Result<Value, String> {
        let Some(ty) = value.ty else { return self.read_integer(value.number, 8).map(Value::plain) };
        let database = self.database()?;
        let target = if ty.pointers > 0 {
            Ty { index: ty.index, pointers: ty.pointers - 1 }
        } else {
            match database.kind(ty.index) {
                Kind::Pointer { target } => Ty { index: target, pointers: 0 },
                _ => return Err(format!("{} nao e ponteiro", database.name(ty.index))),
            }
        };
        self.at(target, value.number)
    }

    /// O valor de um tipo em `address`: escalares são lidos, structs e
    /// arrays ficam pelo endereço.
    fn at(&mut self, ty: Ty, address: u64) -> Result<Value, String> {
        if ty.pointers > 0 {
            return Ok(Value { number: self.read_integer(address, 8)?, ty: Some(ty), address: Some(address) });
        }
        let database = self.database()?;
        match database.kind(ty.index) {
            Kind::Struct { .. } | Kind::Array { .. } => Ok(Value { number: address, ty: Some(ty), address: Some(address) }),
            Kind::Void | Kind::Function | Kind::Unknown => Ok(Value { number: address, ty: Some(ty), address: Some(address) }),
            _ => {
                let number = database.read_scalar(&mut Memory(self.environment), ty.index, address)?;
                Ok(Value { number, ty: Some(ty), address: Some(address) })
            }
        }
    }

    /// Membro de uma struct (por `.`) ou da struct apontada (por `->`; os
    /// dois aceitam os dois, como no WinDbg).
    fn member(&mut self, value: Value, name: &str) -> Result<Value, String> {
        let ty = value.ty.ok_or_else(|| format!(".{name}: o valor nao tem tipo (use um cast, como (_IRP*)endereco)"))?;
        let database = self.database()?;
        let (structure, base) = match (ty.pointers, database.kind(ty.index)) {
            (1, _) => (ty.index, value.number),
            (0, Kind::Pointer { target }) => (target, value.number),
            (0, Kind::Struct { .. }) => (ty.index, value.address.unwrap_or(value.number)),
            _ => return Err(format!("{}: nao e struct nem ponteiro para struct", database.name(ty.index))),
        };
        let member = database.member(structure, name).ok_or_else(|| format!("{} nao tem o campo {name}", database.name(structure)))?;
        self.at(Ty { index: member.ty, pointers: 0 }, base + member.offset)
    }

    fn index(&mut self, value: Value, position: u64) -> Result<Value, String> {
        let ty = value.ty.ok_or("[i] precisa de um valor tipado (ponteiro ou array)")?;
        let database = self.database()?;
        let (element, base) = match (ty.pointers, database.kind(ty.index)) {
            (pointers, _) if pointers > 0 => (Ty { index: ty.index, pointers: pointers - 1 }, value.number),
            (0, Kind::Pointer { target }) => (Ty { index: target, pointers: 0 }, value.number),
            (0, Kind::Array { element, .. }) => (Ty { index: element, pointers: 0 }, value.address.unwrap_or(value.number)),
            _ => return Err(format!("{}: nao e ponteiro nem array", database.name(ty.index))),
        };
        let size = if element.pointers > 0 { 8 } else { database.size(element.index).max(1) };
        self.at(element, base.wrapping_add(position.wrapping_mul(size)))
    }

    fn postfix(&mut self) -> Result<Value, String> {
        let mut value = self.primary()?;
        loop {
            if self.peek_operator("->") || self.peek_operator(".") {
                self.position += 1;
                let Some(Token::Name(name)) = self.peek().cloned() else { return Err("esperado o nome do campo".into()) };
                self.position += 1;
                // `a.b.c` vem como um nome só quando o tokenizador juntou.
                for part in name.split('.') {
                    value = self.member(value, part)?;
                }
            } else if self.peek_operator("[") && value.ty.is_some() {
                self.position += 1;
                let position = self.expression()?.number;
                self.expect("]")?;
                value = self.index(value, position)?;
            } else {
                return Ok(value);
            }
        }
    }

    fn read_integer(&mut self, address: u64, size: usize) -> Result<u64, String> {
        let bytes = self.environment.read_memory(address, size)?;
        if bytes.len() < size {
            return Err(format!("memoria em {address:#x} inacessivel"));
        }
        let mut value = [0u8; 8];
        value[..size].copy_from_slice(&bytes[..size]);
        Ok(u64::from_le_bytes(value))
    }

    fn primary(&mut self) -> Result<Value, String> {
        let token = self.peek().cloned().ok_or("expressao incompleta")?;
        self.position += 1;
        match token {
            Token::Number(number) => Ok(Value::plain(number)),
            Token::Register(name) => Ok(Value::plain(self.environment.register(&name)?)),
            Token::Variable(name) if name == "iment" && self.peek_operator("(") => {
                self.position += 1;
                let module = match self.peek().cloned() {
                    Some(Token::Name(name)) => {
                        self.position += 1;
                        name
                    }
                    _ => format!("{:#x}", self.expression()?.number),
                };
                self.expect(")")?;
                Ok(Value::plain(self.environment.image_entry(&module)?))
            }
            Token::Variable(name) => self.environment.variable(&name).map(Value::plain).ok_or_else(|| format!("variavel ${name} nao definida")),
            Token::Operator("(") => {
                let value = self.expression()?;
                self.expect(")")?;
                Ok(value)
            }
            Token::Operator("[") => {
                let address = self.expression()?.number;
                self.expect("]")?;
                Ok(Value::plain(self.read_integer(address, 8)?))
            }
            Token::Name(name) => self.name(name),
            Token::Operator(operator) => Err(format!("operador {operator:?} fora do lugar")),
        }
    }

    fn name(&mut self, name: String) -> Result<Value, String> {
        let sizes = [("byte", 1), ("word", 2), ("dword", 4), ("qword", 8)];
        if let Some(&(_, size)) = sizes.iter().find(|(prefix, _)| *prefix == name) {
            if self.peek_operator("[") {
                self.position += 1;
                let address = self.expression()?.number;
                self.expect("]")?;
                return Ok(Value::plain(self.read_integer(address, size)?));
            }
        }
        if self.peek_operator("(") {
            let functions = [("poi", 8), ("qwo", 8), ("dwo", 4), ("wo", 2), ("by", 1)];
            if let Some(&(_, size)) = functions.iter().find(|(function, _)| *function == name) {
                self.position += 1;
                let address = self.expression()?.number;
                self.expect(")")?;
                return Ok(Value::plain(self.read_integer(address, size)?));
            }
            match name.as_str() {
                "sizeof" => {
                    self.position += 1;
                    let Some(Token::Name(type_name)) = self.peek().cloned() else { return Err("sizeof(Tipo)".into()) };
                    self.position += 1;
                    self.expect(")")?;
                    let database = self.database()?;
                    let index = database.find(&type_name).ok_or_else(|| format!("tipo {type_name} desconhecido"))?;
                    return Ok(Value::plain(database.size(index)));
                }
                "hi" | "low" => {
                    self.position += 1;
                    let value = self.expression()?.number;
                    self.expect(")")?;
                    return Ok(Value::plain(if name == "hi" { value >> 32 } else { value & 0xFFFF_FFFF }));
                }
                _ => {}
            }
        }
        match self.environment.symbol(&name) {
            Ok(address) => Ok(Value::plain(address)),
            Err(error) => {
                if self.environment.is_register(&name.to_ascii_lowercase()) {
                    return Ok(Value::plain(self.environment.register(&name.to_ascii_lowercase())?));
                }
                // Hexadecimal sem prefixo (`fffff80040000000`, `1f`).
                if name.chars().all(|character| character.is_ascii_hexdigit() || character == '`') {
                    if let Ok(number) = u64::from_str_radix(&name.replace('`', ""), 16) {
                        return Ok(Value::plain(number));
                    }
                }
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Fake {
        registers: HashMap<String, u64>,
        memory: Vec<(u64, Vec<u8>)>,
        symbols: HashMap<String, u64>,
        types: Option<Arc<TypeDb>>,
    }

    impl Environment for Fake {
        fn register(&mut self, name: &str) -> Result<u64, String> {
            self.registers.get(name).copied().ok_or_else(|| format!("registrador desconhecido: {name}"))
        }

        fn read_memory(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
            for (base, bytes) in &self.memory {
                if address >= *base && address < base + bytes.len() as u64 {
                    let start = (address - base) as usize;
                    return Ok(bytes[start..(start + length).min(bytes.len())].to_vec());
                }
            }
            Err(format!("memoria em {address:#x} inacessivel"))
        }

        fn symbol(&mut self, name: &str) -> Result<u64, String> {
            self.symbols.get(name).copied().ok_or_else(|| format!("{name}: simbolo nao encontrado"))
        }

        fn variable(&mut self, name: &str) -> Option<u64> {
            (name == "base").then_some(0x1000)
        }

        fn is_register(&self, name: &str) -> bool {
            self.registers.contains_key(name)
        }

        fn types(&mut self) -> Option<Arc<TypeDb>> {
            self.types.clone()
        }

        fn image_entry(&mut self, module: &str) -> Result<u64, String> {
            (module == "ksecdd").then_some(0x4242).ok_or_else(|| "nao".into())
        }
    }

    fn fake() -> Fake {
        let mut memory = vec![0u8; 0x40];
        memory[0..8].copy_from_slice(&0x2000u64.to_le_bytes());
        memory[8..12].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
        Fake {
            registers: [("rax".to_string(), 5), ("rcx".to_string(), 0x3000), ("rsp".to_string(), 0x1000)].into_iter().collect(),
            memory: vec![(0x1000, memory)],
            symbols: [
                ("kernel::ntos::ke::run_kernel_tasks".to_string(), 0xfffff800_40002000),
                ("ksecdd.sys!SspiInitAsyncInterface".to_string(), 0xfffff800_42001000),
                ("kernel::ntos::ps::create<u64>".to_string(), 0xfffff800_40004000),
                ("<kernel::Irp as core::fmt::Debug>::fmt".to_string(), 0xfffff800_40003000),
            ]
            .into_iter()
            .collect(),
            types: None,
        }
    }

    fn number(environment: &mut Fake, text: &str) -> Result<u64, String> {
        evaluate_number(environment, text)
    }

    #[test]
    fn arithmetic_and_precedence() {
        let mut environment = fake();
        assert_eq!(number(&mut environment, "1+2*3"), Ok(7));
        assert_eq!(number(&mut environment, "(1+2)*3"), Ok(9));
        assert_eq!(number(&mut environment, "0x10 - 1"), Ok(15));
        assert_eq!(number(&mut environment, "-1"), Ok(u64::MAX));
        assert_eq!(number(&mut environment, "1 << 4 | 1"), Ok(17));
        assert_eq!(number(&mut environment, "7 % 4 == 3 && 2 > 1"), Ok(1));
        assert_eq!(number(&mut environment, "~0 >> 60"), Ok(15));
        assert_eq!(number(&mut environment, "0xfffff800`40000000"), Ok(0xfffff800_40000000));
        assert_eq!(number(&mut environment, "0n10"), Ok(10));
        assert_eq!(number(&mut environment, "1f"), Ok(0x1f));
        assert_eq!(number(&mut environment, "fffff80040000000"), Ok(0xfffff800_40000000));
        assert!(number(&mut environment, "1/0").is_err());
        assert!(number(&mut environment, "1 +").is_err());
    }

    #[test]
    fn registers_memory_and_symbols() {
        let mut environment = fake();
        assert_eq!(number(&mut environment, "@rax"), Ok(5));
        assert_eq!(number(&mut environment, "%rax + rax"), Ok(10));
        assert_eq!(number(&mut environment, "poi(@rsp)"), Ok(0x2000));
        assert_eq!(number(&mut environment, "[rsp]"), Ok(0x2000));
        assert_eq!(number(&mut environment, "dwo(@rsp+8)"), Ok(0xdeadbeef));
        assert_eq!(number(&mut environment, "dword[$base+8]"), Ok(0xdeadbeef));
        assert_eq!(number(&mut environment, "by(rsp+8)"), Ok(0xef));
        assert_eq!(number(&mut environment, "kernel::ntos::ke::run_kernel_tasks+0x10"), Ok(0xfffff800_40002010));
        assert_eq!(number(&mut environment, "ksecdd.sys!SspiInitAsyncInterface"), Ok(0xfffff800_42001000));
        assert_eq!(number(&mut environment, "kernel::ntos::ps::create<u64>"), Ok(0xfffff800_40004000));
        assert_eq!(number(&mut environment, "<kernel::Irp as core::fmt::Debug>::fmt+1"), Ok(0xfffff800_40003001));
        assert_eq!(number(&mut environment, "$iment(ksecdd)"), Ok(0x4242));
        assert_eq!(number(&mut environment, "@rax < 6 && @rcx >= 0x3000"), Ok(1));
        assert_eq!(number(&mut environment, "hi(0x1234567800000000)"), Ok(0x12345678));
        assert!(number(&mut environment, "nada_disso").is_err());
        assert!(number(&mut environment, "$x").is_err());
    }

    #[test]
    fn every_register_name_is_one_token() {
        // Todos os nomes que o cliente aceita (os de `registers::find`),
        // com `@` e com `%`, inclusive os com `_` (FS_BASE e GS_BASE).
        let layouts = crate::registers::GENERAL.iter().chain(crate::registers::EXTRA).chain(crate::registers::X87_CONTROL).chain(crate::registers::DEBUG).chain(std::iter::once(&crate::registers::MXCSR));
        for layout in layouts {
            for prefix in ["@", "%"] {
                let text = format!("{prefix}{}", layout.name);
                assert_eq!(tokenize(&text), Ok(vec![Token::Register(layout.name.to_string())]), "{text}");
            }
        }
        assert_eq!(tokenize("@GS_BASE+0x188"), Ok(vec![Token::Register("gs_base".into()), Token::Operator("+"), Token::Number(0x188)]));
        assert_eq!(tokenize("@rflags"), Ok(vec![Token::Register("rflags".into())]));
    }

    #[test]
    fn underscored_registers() {
        let mut environment = fake();
        // O KPCR em 0x1000: CurrentThread (+0x188) = 0x1010; o processo
        // (+0xb8 da thread) = 0x1000 - 0x5a8 + 8, onde mora 0xdeadbeef.
        environment.registers.insert("gs_base".into(), 0x1000);
        environment.registers.insert("fs_base".into(), 0x20);
        environment.registers.insert("rip".into(), 0xfffff800_40001234);
        let memory = &mut environment.memory[0].1;
        memory.resize(0x200, 0);
        memory[0x188..0x190].copy_from_slice(&0x1010u64.to_le_bytes());
        memory[0x10 + 0xb8..0x10 + 0xc0].copy_from_slice(&(0x1008u64 - 0x5a8).to_le_bytes());
        assert_eq!(number(&mut environment, "@gs_base"), Ok(0x1000));
        assert_eq!(number(&mut environment, "%gs_base"), Ok(0x1000));
        assert_eq!(number(&mut environment, "gs_base"), Ok(0x1000));
        assert_eq!(number(&mut environment, "@GS_BASE+1"), Ok(0x1001));
        assert_eq!(number(&mut environment, "@fs_base"), Ok(0x20));
        assert_eq!(number(&mut environment, "@rip"), Ok(0xfffff800_40001234));
        assert_eq!(number(&mut environment, "@rip-@gs_base"), Ok(0xfffff800_40000234));
        // O `cur=` dos roteiros da tela preta.
        assert_eq!(number(&mut environment, "dwo(poi(poi(@gs_base+0x188)+0xb8)+0x5a8)"), Ok(0xdeadbeef));
        assert!(number(&mut environment, "@gs_basex").is_err());
    }

    #[test]
    fn pseudo_variables_modulo_and_dotted_modules() {
        let mut environment = fake();
        environment.symbols.insert("Windows.UI.Logon".into(), 0x7ff8_1000_0000);
        environment.symbols.insert("ntdll.dll".into(), 0x7ff8_2000_0000);
        // `@$nome` é a variável `$nome`.
        assert_eq!(number(&mut environment, "@$base+8"), Ok(0x1008));
        // `%` depois de um operando é o resto, não um registrador.
        assert_eq!(number(&mut environment, "7%rax"), Ok(2));
        assert_eq!(number(&mut environment, "$base%rax"), Ok(0x1000 % 5));
        // Módulo com pontos e RVA, sem `!`.
        assert_eq!(number(&mut environment, "Windows.UI.Logon+0x48b50"), Ok(0x7ff8_1004_8b50));
        assert_eq!(number(&mut environment, "ntdll.dll+0x10"), Ok(0x7ff8_2000_0010));
        assert_eq!(tokenize("x."), Ok(vec![Token::Name("x".into()), Token::Operator(".")]));
    }

    #[test]
    fn typed_access() {
        let mut environment = fake();
        environment.types = Some(Arc::new(crate::types::tests::sample()));
        // Um _DEVICE_OBJECT em 0x1010 cujo DriverObject (+8) aponta para
        // 0x1030, onde Type = 4.
        let device = &mut environment.memory[0].1;
        device[0x10..0x12].copy_from_slice(&3u16.to_le_bytes());
        device[0x18..0x20].copy_from_slice(&0x1030u64.to_le_bytes());
        device[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
        device[0x30..0x32].copy_from_slice(&4u16.to_le_bytes());
        assert_eq!(number(&mut environment, "((_DEVICE_OBJECT*)0x1010)->Type"), Ok(3));
        assert_eq!(number(&mut environment, "((nt!_DEVICE_OBJECT*)0x1010)->DriverObject->Type"), Ok(4));
        // `DriverObject.Type` vem como um nome só e vira dois campos.
        assert_eq!(number(&mut environment, "((_DEVICE_OBJECT*)0x1010)->DriverObject.Type"), Ok(4));
        assert_eq!(number(&mut environment, "(*(_DEVICE_OBJECT*)0x1010).Power"), Ok(1));
        assert_eq!(number(&mut environment, "&((_DEVICE_OBJECT*)0x1010)->Power"), Ok(0x1020));
        assert_eq!(number(&mut environment, "sizeof(_DEVICE_OBJECT)"), Ok(0x20));
        assert_eq!(number(&mut environment, "((_DEVICE_OBJECT*)0x1010)->Name[1]"), Ok(0));
        let value = evaluate(&mut environment, "((_DEVICE_OBJECT*)0x1010)->DriverObject").unwrap();
        assert_eq!(value.number, 0x1030);
        assert_eq!(value.address, Some(0x1018));
        assert!(number(&mut environment, "((_DEVICE_OBJECT*)0x1010)->Nada").is_err());
        assert!(number(&mut environment, "(0x1010)->Type").is_err());
    }
}
