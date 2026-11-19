//! Roteiros do depurador: uma linguagem pequena de comandos com
//! variáveis, condições e laços. Cada linha é um comando:
//!
//! - `var x = expr`, `x = expr`, `$x = expr`: atribuição (o valor vem do
//!   avaliador de expressões do depurador, com as variáveis do roteiro
//!   trocadas pelo valor);
//! - `if expr` / `elif expr` / `else` / `end` (`se`, `senao se`, `senao`,
//!   `fim`); `while expr` ... `end` (`enquanto`); `for i = a to b [step s]`
//!   ... `end` (`para i = a ate b [passo s]`); `break`, `continue`;
//! - `exit` (termina sem erro), `error "texto"` (termina com erro),
//!   `assert expr ["texto"]`;
//! - `log "texto {expr} {expr:x} {expr:d} {$var}"` e `print`: o texto
//!   com as expressões entre chaves (hexadecimal com `0x` por padrão);
//! - `sleep N`: ignorado;
//! - qualquer outra linha é um comando do depurador (`bp`, `g`, `r`, `db`
//!   ...), com `$var` e `{expr}` trocados pelo valor; depois dele, a
//!   variável `ok` vale 1 se o comando deu certo e 0 se falhou (a falha
//!   não para o roteiro).
//!
//! Comentários começam com `#` ou `//`. Os números seguem o avaliador do
//! depurador (sem prefixo é hexadecimal, como no WinDbg; `0n10` é
//! decimal).

use std::collections::BTreeMap;

/// Quem executa os comandos e avalia as expressões.
pub trait Host {
    /// Um comando do depurador.
    fn execute(&mut self, command: &str) -> Result<String, String>;
    /// Uma expressão do depurador.
    fn evaluate(&mut self, expression: &str) -> Result<u64, String>;
    /// Uma linha do `log`/`print`.
    fn output(&mut self, text: &str);
    /// O usuário pediu para parar.
    fn cancelled(&mut self) -> bool {
        false
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Statement {
    Assign { name: String, expression: String },
    If { branches: Vec<(String, Vec<Node>)>, otherwise: Vec<Node> },
    While { condition: String, body: Vec<Node> },
    For { name: String, from: String, to: String, step: Option<String>, body: Vec<Node> },
    Break,
    Continue,
    Exit,
    Error(String),
    Assert { expression: String, message: Option<String> },
    Log(String),
    Sleep,
    Command(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Node {
    line: usize,
    statement: Statement,
}

/// Um roteiro lido.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Script {
    nodes: Vec<Node>,
}

impl Script {
    /// Comandos do nível de cima.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// O que fecha um bloco.
enum Terminator {
    End,
    Else,
    Elif(String),
}

/// A primeira palavra e o resto.
fn split_word(text: &str) -> (&str, &str) {
    match text.split_once(char::is_whitespace) {
        Some((word, rest)) => (word, rest.trim()),
        None => (text, ""),
    }
}

fn identifier_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
}

/// `nome = expr` (com `$` opcional), sem confundir com `==`.
fn assignment(text: &str) -> Option<(String, String)> {
    let text = text.strip_prefix('$').unwrap_or(text);
    let end = text.find(|character: char| !identifier_char(character)).unwrap_or(text.len());
    if end == 0 || text.starts_with(|character: char| character.is_ascii_digit()) {
        return None;
    }
    let rest = text[end..].trim_start();
    let value = rest.strip_prefix('=')?;
    if value.starts_with('=') {
        return None;
    }
    Some((text[..end].to_string(), value.trim().to_string()))
}

/// O texto entre aspas (ou o próprio texto).
fn unquote(text: &str) -> String {
    let text = text.trim();
    if text.len() >= 2 && text.starts_with('"') && text.ends_with('"') {
        text[1..text.len() - 1].to_string()
    } else {
        text.to_string()
    }
}

/// A posição de `word` como palavra inteira em `text`.
fn find_word(text: &str, words: &[&str]) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    for (index, _) in text.char_indices() {
        for word in words {
            if !text[index..].starts_with(word) {
                continue;
            }
            let before = index == 0 || bytes[index - 1].is_ascii_whitespace();
            let after = bytes.get(index + word.len()).is_none_or(|byte| byte.is_ascii_whitespace());
            if before && after && index > 0 {
                return Some((index, index + word.len()));
            }
        }
    }
    None
}

/// Lê um roteiro; os erros dizem a linha.
pub fn parse(text: &str) -> Result<Script, String> {
    let lines: Vec<(usize, &str)> = text.lines().enumerate().map(|(index, line)| (index + 1, line.trim())).filter(|(_, line)| !line.is_empty() && !line.starts_with('#') && !line.starts_with("//")).collect();
    let mut position = 0;
    let (nodes, terminator) = parse_block(&lines, &mut position, 0)?;
    match terminator {
        None => Ok(Script { nodes }),
        Some((line, Terminator::End)) => Err(format!("linha {line}: 'end' sem bloco aberto")),
        Some((line, _)) => Err(format!("linha {line}: 'else' fora de um 'if'")),
    }
}

type Block = (Vec<Node>, Option<(usize, Terminator)>);

/// Um bloco até o `end`, `else` ou `elif` que o fecha (ou o fim do texto).
fn parse_block(lines: &[(usize, &str)], position: &mut usize, loops: usize) -> Result<Block, String> {
    let mut nodes = Vec::new();
    while *position < lines.len() {
        let (number, text) = lines[*position];
        *position += 1;
        let (word, rest) = split_word(text);
        let fail = |message: &str| format!("linha {number}: {message}");
        let statement = match word {
            "end" | "fim" | "endif" | "endwhile" | "endfor" => {
                if !rest.is_empty() {
                    return Err(fail("texto depois de 'end'"));
                }
                return Ok((nodes, Some((number, Terminator::End))));
            }
            "else" | "senao" => {
                let (second, condition) = split_word(rest);
                if matches!(second, "if" | "se") && !condition.is_empty() {
                    return Ok((nodes, Some((number, Terminator::Elif(condition.to_string())))));
                }
                if !rest.is_empty() {
                    return Err(fail("texto depois de 'else'"));
                }
                return Ok((nodes, Some((number, Terminator::Else))));
            }
            "elif" | "elseif" | "senaose" => {
                if rest.is_empty() {
                    return Err(fail("'elif' sem condicao"));
                }
                return Ok((nodes, Some((number, Terminator::Elif(rest.to_string())))));
            }
            "if" | "se" => {
                if rest.is_empty() {
                    return Err(fail("'if' sem condicao"));
                }
                let mut branches = Vec::new();
                let mut otherwise = Vec::new();
                let mut condition = rest.to_string();
                loop {
                    let (body, terminator) = parse_block(lines, position, loops)?;
                    match terminator {
                        None => return Err(fail("'if' sem 'end'")),
                        Some((_, Terminator::End)) => {
                            branches.push((condition, body));
                            break;
                        }
                        Some((_, Terminator::Elif(next))) => {
                            branches.push((condition, body));
                            condition = next;
                        }
                        Some((_, Terminator::Else)) => {
                            branches.push((condition, body));
                            let (body, terminator) = parse_block(lines, position, loops)?;
                            match terminator {
                                Some((_, Terminator::End)) => {
                                    otherwise = body;
                                    break;
                                }
                                None => return Err(fail("'if' sem 'end'")),
                                Some((line, _)) => return Err(format!("linha {line}: 'else' ou 'elif' depois do 'else'")),
                            }
                        }
                    }
                }
                Statement::If { branches, otherwise }
            }
            "while" | "enquanto" => {
                if rest.is_empty() {
                    return Err(fail("'while' sem condicao"));
                }
                let body = loop_body(lines, position, loops, number, "while")?;
                Statement::While { condition: rest.to_string(), body }
            }
            "for" | "para" => {
                let usage = "uso: for i = inicio to fim [step passo]";
                let (name, range) = assignment(rest).ok_or_else(|| fail(usage))?;
                let (to_start, to_end) = find_word(&range, &["to", "ate"]).ok_or_else(|| fail(usage))?;
                let from = range[..to_start].trim().to_string();
                let tail = &range[to_end..];
                let (to, step) = match find_word(tail, &["step", "passo"]) {
                    Some((step_start, step_end)) => (tail[..step_start].trim().to_string(), Some(tail[step_end..].trim().to_string())),
                    None => (tail.trim().to_string(), None),
                };
                if from.is_empty() || to.is_empty() || step.as_ref().is_some_and(String::is_empty) {
                    return Err(fail(usage));
                }
                let body = loop_body(lines, position, loops, number, "for")?;
                Statement::For { name, from, to, step, body }
            }
            "break" | "continue" => {
                if loops == 0 {
                    return Err(fail(&format!("'{word}' fora de um laco")));
                }
                if word == "break" {
                    Statement::Break
                } else {
                    Statement::Continue
                }
            }
            "exit" => Statement::Exit,
            "error" | "erro" => Statement::Error(unquote(rest)),
            "assert" => {
                if rest.is_empty() {
                    return Err(fail("'assert' sem expressao"));
                }
                let quoted = rest.ends_with('"') && rest.len() >= 2;
                match rest[..rest.len() - 1].rfind('"').filter(|_| quoted) {
                    Some(open) if !rest[..open].trim().is_empty() => Statement::Assert { expression: rest[..open].trim().to_string(), message: Some(rest[open + 1..rest.len() - 1].to_string()) },
                    _ => Statement::Assert { expression: rest.to_string(), message: None },
                }
            }
            "log" | "print" => Statement::Log(unquote(rest)),
            "sleep" => Statement::Sleep,
            "var" => match assignment(rest) {
                Some((name, expression)) => Statement::Assign { name, expression },
                None if !rest.is_empty() && rest.chars().all(identifier_char) => Statement::Assign { name: rest.to_string(), expression: "0x0".into() },
                None => return Err(fail("uso: var nome = expressao")),
            },
            _ => match assignment(text) {
                Some((name, expression)) => Statement::Assign { name, expression },
                None => Statement::Command(text.to_string()),
            },
        };
        nodes.push(Node { line: number, statement });
    }
    Ok((nodes, None))
}

/// O corpo de um laço, até o `end`.
fn loop_body(lines: &[(usize, &str)], position: &mut usize, loops: usize, number: usize, keyword: &str) -> Result<Vec<Node>, String> {
    let (body, terminator) = parse_block(lines, position, loops + 1)?;
    match terminator {
        Some((_, Terminator::End)) => Ok(body),
        None => Err(format!("linha {number}: '{keyword}' sem 'end'")),
        Some((line, _)) => Err(format!("linha {line}: 'else' fora de um 'if'")),
    }
}

/// O resultado de uma execução.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Run {
    pub variables: BTreeMap<String, u64>,
    /// Comandos do roteiro executados (cada volta de laço conta).
    pub steps: usize,
    /// Comandos do depurador mandados ao `Host`.
    pub commands: usize,
}

enum Signal {
    Normal,
    Break,
    Continue,
    Exit,
}

struct Machine<'a> {
    host: &'a mut dyn Host,
    variables: BTreeMap<String, u64>,
    steps: usize,
    max_steps: usize,
    commands: usize,
}

impl Machine<'_> {
    fn tick(&mut self, line: usize) -> Result<(), String> {
        self.steps += 1;
        if self.steps > self.max_steps {
            return Err(format!("linha {line}: limite de passos ({}) atingido", self.max_steps));
        }
        if self.host.cancelled() {
            return Err(format!("linha {line}: roteiro cancelado"));
        }
        Ok(())
    }

    /// Troca as variáveis do roteiro pelo valor: `$x` sempre; `x` quando é
    /// um identificador inteiro que não é registrador (`@x`), módulo (`x!`),
    /// símbolo de módulo (`m!x`), campo (`.x`, `->x`) nem caminho (`a::x`).
    fn substitute(&self, text: &str, bare: bool) -> String {
        let characters: Vec<char> = text.chars().collect();
        let mut output = String::new();
        let mut index = 0;
        let mut quoted = false;
        while index < characters.len() {
            let character = characters[index];
            if character == '"' {
                quoted = !quoted;
            }
            if quoted || !(character == '$' || character.is_ascii_alphanumeric() || character == '_') {
                output.push(character);
                index += 1;
                continue;
            }
            if character.is_ascii_digit() {
                // Um número inteiro (0x1f, 1000`0000) não se divide.
                while index < characters.len() && (characters[index].is_ascii_alphanumeric() || matches!(characters[index], '_' | '`')) {
                    output.push(characters[index]);
                    index += 1;
                }
                continue;
            }
            let dollar = character == '$';
            let start = if dollar { index + 1 } else { index };
            let mut end = start;
            while end < characters.len() && identifier_char(characters[end]) {
                end += 1;
            }
            let name: String = characters[start..end].iter().collect();
            let before = index.checked_sub(1).map(|position| characters[position]);
            let after = characters.get(end).copied();
            let path = after == Some(':') && characters.get(end + 1) == Some(&':');
            let plain = bare && !matches!(before, Some('@' | '!' | '.' | '>' | ':')) && after != Some('!') && !path;
            match self.variables.get(&name) {
                Some(value) if dollar || plain => output.push_str(&format!("{value:#x}")),
                _ => output.extend(&characters[index..end]),
            }
            index = end.max(index + 1);
        }
        output
    }

    fn evaluate(&mut self, expression: &str) -> Result<u64, String> {
        let text = self.substitute(expression, true);
        let trimmed = text.trim();
        if let Some(hex) = trimmed.strip_prefix("0x") {
            if let Ok(value) = u64::from_str_radix(hex, 16) {
                return Ok(value);
            }
        }
        self.host.evaluate(trimmed)
    }

    /// O texto com as expressões entre chaves (`{{` e `}}` são as chaves).
    fn format(&mut self, template: &str) -> Result<String, String> {
        let characters: Vec<char> = template.chars().collect();
        let mut output = String::new();
        let mut index = 0;
        while index < characters.len() {
            let character = characters[index];
            let next = characters.get(index + 1).copied();
            if (character == '{' && next == Some('{')) || (character == '}' && next == Some('}')) {
                output.push(character);
                index += 2;
                continue;
            }
            if character != '{' {
                output.push(character);
                index += 1;
                continue;
            }
            let close = characters[index..].iter().position(|&other| other == '}').map(|offset| index + offset).ok_or("'{' sem '}'")?;
            let content: String = characters[index + 1..close].iter().collect();
            let (expression, spec) = match content.rsplit_once(':') {
                Some((expression, spec)) if matches!(spec.trim(), "x" | "X" | "d" | "i") => (expression.to_string(), spec.trim().to_string()),
                _ => (content.clone(), String::new()),
            };
            let value = self.evaluate(&expression)?;
            output.push_str(&match spec.as_str() {
                "x" => format!("{value:x}"),
                "X" => format!("{value:X}"),
                "d" => format!("{value}"),
                "i" => format!("{}", value as i64),
                _ => format!("{value:#x}"),
            });
            index = close + 1;
        }
        Ok(output)
    }

    fn block(&mut self, nodes: &[Node]) -> Result<Signal, String> {
        for node in nodes {
            self.tick(node.line)?;
            match self.statement(node)? {
                Signal::Normal => {}
                other => return Ok(other),
            }
        }
        Ok(Signal::Normal)
    }

    fn statement(&mut self, node: &Node) -> Result<Signal, String> {
        let line = node.line;
        let fail = |error: String| format!("linha {line}: {error}");
        match &node.statement {
            Statement::Assign { name, expression } => {
                let value = self.evaluate(expression).map_err(fail)?;
                self.variables.insert(name.clone(), value);
            }
            Statement::If { branches, otherwise } => {
                for (condition, body) in branches {
                    if self.evaluate(condition).map_err(fail)? != 0 {
                        return self.block(body);
                    }
                }
                return self.block(otherwise);
            }
            Statement::While { condition, body } => loop {
                if self.evaluate(condition).map_err(fail)? == 0 {
                    break;
                }
                match self.block(body)? {
                    Signal::Break => break,
                    Signal::Exit => return Ok(Signal::Exit),
                    Signal::Normal | Signal::Continue => {}
                }
                self.tick(line)?;
            },
            Statement::For { name, from, to, step, body } => {
                let start = self.evaluate(from).map_err(fail)?;
                let end = self.evaluate(to).map_err(fail)?;
                let step = match step {
                    Some(step) => self.evaluate(step).map_err(fail)?,
                    None => 1,
                };
                if step == 0 {
                    return Err(fail("passo zero no 'for'".into()));
                }
                let downward = (step as i64) < 0;
                let mut counter = start;
                loop {
                    let running = if downward { counter as i64 >= end as i64 } else { counter <= end };
                    if !running {
                        break;
                    }
                    self.variables.insert(name.clone(), counter);
                    match self.block(body)? {
                        Signal::Break => break,
                        Signal::Exit => return Ok(Signal::Exit),
                        Signal::Normal | Signal::Continue => {}
                    }
                    self.tick(line)?;
                    let current = self.variables.get(name).copied().unwrap_or(counter);
                    let (next, overflow) = current.overflowing_add(step);
                    if overflow && !downward {
                        break;
                    }
                    counter = next;
                }
            }
            Statement::Break => return Ok(Signal::Break),
            Statement::Continue => return Ok(Signal::Continue),
            Statement::Exit => return Ok(Signal::Exit),
            Statement::Error(message) => {
                let text = self.format(message).map_err(fail)?;
                return Err(fail(text));
            }
            Statement::Assert { expression, message } => {
                if self.evaluate(expression).map_err(fail)? == 0 {
                    let text = match message {
                        Some(message) => self.format(message).map_err(fail)?,
                        None => format!("assert falhou: {expression}"),
                    };
                    return Err(fail(text));
                }
            }
            Statement::Log(template) => {
                let text = self.format(template).map_err(fail)?;
                self.host.output(&text);
            }
            Statement::Sleep => {}
            Statement::Command(text) => {
                let interpolated = self.format(text).map_err(fail)?;
                let command = self.substitute(&interpolated, false);
                self.commands += 1;
                let ok = self.host.execute(&command).is_ok();
                self.variables.insert("ok".into(), ok as u64);
            }
        }
        Ok(Signal::Normal)
    }
}

/// Executa o roteiro até o fim, um `exit`, um erro ou `max_steps`
/// comandos.
pub fn run(script: &Script, host: &mut dyn Host, max_steps: usize) -> Result<Run, String> {
    let mut machine = Machine { host, variables: BTreeMap::new(), steps: 0, max_steps, commands: 0 };
    machine.block(&script.nodes)?;
    Ok(Run { variables: machine.variables, steps: machine.steps, commands: machine.commands })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Um depurador de mentira: avaliador pequeno (decimal, 0x, @rax,
    /// nt!x, + - * == != < > <= >= && || e parênteses) e os comandos
    /// gravados.
    #[derive(Default)]
    struct Fake {
        commands: Vec<String>,
        expressions: Vec<String>,
        lines: Vec<String>,
    }

    struct Parser<'a> {
        tokens: Vec<&'a str>,
        position: usize,
    }

    fn tokenize(text: &str) -> Vec<&str> {
        let mut tokens = Vec::new();
        let bytes = text.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            let byte = bytes[index];
            if byte.is_ascii_whitespace() {
                index += 1;
                continue;
            }
            let start = index;
            if byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b'_' | b'!') {
                while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'@' | b'_' | b'!')) {
                    index += 1;
                }
            } else if index + 1 < bytes.len() && matches!(&text[index..index + 2], "==" | "!=" | "<=" | ">=" | "&&" | "||") {
                index += 2;
            } else {
                index += 1;
            }
            tokens.push(&text[start..index]);
        }
        tokens
    }

    impl<'a> Parser<'a> {
        fn peek(&self) -> Option<&'a str> {
            self.tokens.get(self.position).copied()
        }

        fn binary(&mut self, level: usize) -> Result<u64, String> {
            const LEVELS: [&[&str]; 5] = [&["||"], &["&&"], &["==", "!=", "<", ">", "<=", ">="], &["+", "-"], &["*"]];
            if level == LEVELS.len() {
                return self.primary();
            }
            let mut left = self.binary(level + 1)?;
            while let Some(operator) = self.peek().filter(|token| LEVELS[level].contains(token)) {
                self.position += 1;
                let right = self.binary(level + 1)?;
                left = match operator {
                    "||" => (left != 0 || right != 0) as u64,
                    "&&" => (left != 0 && right != 0) as u64,
                    "==" => (left == right) as u64,
                    "!=" => (left != right) as u64,
                    "<" => (left < right) as u64,
                    ">" => (left > right) as u64,
                    "<=" => (left <= right) as u64,
                    ">=" => (left >= right) as u64,
                    "+" => left.wrapping_add(right),
                    "-" => left.wrapping_sub(right),
                    _ => left.wrapping_mul(right),
                };
            }
            Ok(left)
        }

        fn primary(&mut self) -> Result<u64, String> {
            let token = self.peek().ok_or("expressao incompleta")?;
            self.position += 1;
            match token {
                "(" => {
                    let value = self.binary(0)?;
                    if self.peek() != Some(")") {
                        return Err("falta ')'".into());
                    }
                    self.position += 1;
                    Ok(value)
                }
                "@rax" => Ok(0x10),
                "nt!x" => Ok(0x99),
                _ => match token.strip_prefix("0x") {
                    Some(hex) => u64::from_str_radix(hex, 16).map_err(|error| error.to_string()),
                    None => token.parse().map_err(|_| format!("simbolo desconhecido: {token}")),
                },
            }
        }
    }

    impl Host for Fake {
        fn execute(&mut self, command: &str) -> Result<String, String> {
            self.commands.push(command.to_string());
            if command.starts_with("fail") {
                Err("falhou".into())
            } else {
                Ok(String::new())
            }
        }

        fn evaluate(&mut self, expression: &str) -> Result<u64, String> {
            self.expressions.push(expression.to_string());
            let mut parser = Parser { tokens: tokenize(expression), position: 0 };
            let value = parser.binary(0)?;
            if parser.position != parser.tokens.len() {
                return Err(format!("sobra em {expression}"));
            }
            Ok(value)
        }

        fn output(&mut self, text: &str) {
            self.lines.push(text.to_string());
        }
    }

    fn execute(text: &str) -> (Result<Run, String>, Fake) {
        let mut fake = Fake::default();
        let result = parse(text).and_then(|script| run(&script, &mut fake, 10_000));
        (result, fake)
    }

    #[test]
    fn loops_and_log() {
        let (result, fake) = execute("# soma\nvar total = 0\nfor i = 1 to 5\n  total = total + i\nend\nlog \"total={total:d} hex={total} {total:x} {{x}}\"");
        let run = result.unwrap();
        assert_eq!(run.variables["total"], 15);
        assert_eq!(fake.lines, vec!["total=15 hex=0xf f {x}".to_string()]);
        let (result, fake) = execute("para i = 3 ate 1 passo 0 - 1\n  print \"{i:d}\"\nfim");
        result.unwrap();
        assert_eq!(fake.lines, vec!["3", "2", "1"]);
    }

    #[test]
    fn conditions() {
        let text = "x = 7\nif x == 1\n  log um\nelif x == 7\n  log sete\nelse\n  log outro\nend\nse x > 100\n  log grande\nsenao se x > 5\n  log medio\nsenao\n  log pequeno\nfim";
        let (result, fake) = execute(text);
        result.unwrap();
        assert_eq!(fake.lines, vec!["sete", "medio"]);
    }

    #[test]
    fn nested_loops_with_break_and_continue() {
        let text = "count = 0\nfor i = 0 to 3\n  for j = 0 to 3\n    if j == 2\n      break\n    end\n    if i == 1\n      continue\n    end\n    count = count + 1\n  end\nend\nn = 0\nwhile 1\n  n = n + 1\n  if n == 4\n    break\n  end\nend";
        let (result, _) = execute(text);
        let run = result.unwrap();
        assert_eq!(run.variables["count"], 6);
        assert_eq!(run.variables["n"], 4);
    }

    #[test]
    fn commands_with_variables() {
        let text = "n = 3\nbase = 0x1000\nwhile n > 0\n  bp 0x1000+$n\n  n = n - 1\nend\ndb {base + 8} L4\nfail now\nlog \"ok={ok:d}\"\nr rax=5\nlog \"ok={$ok:d}\"";
        let (result, fake) = execute(text);
        let run = result.unwrap();
        assert_eq!(fake.commands, vec!["bp 0x1000+0x3", "bp 0x1000+0x2", "bp 0x1000+0x1", "db 0x1008 L4", "fail now", "r rax=5"]);
        assert_eq!(fake.lines, vec!["ok=0", "ok=1"]);
        assert_eq!(run.commands, 6);
        assert!(!run.variables.contains_key("rax"));
    }

    #[test]
    fn bare_names_only_where_they_are_variables() {
        let (result, fake) = execute("x = 5\ny = @rax + x\nz = nt!x\nw = (x)*2");
        let run = result.unwrap();
        assert_eq!(run.variables["y"], 0x15);
        assert_eq!(run.variables["z"], 0x99);
        assert_eq!(run.variables["w"], 10);
        assert!(fake.expressions.contains(&"@rax + 0x5".to_string()));
        assert!(fake.expressions.contains(&"nt!x".to_string()));
    }

    #[test]
    fn exit_error_and_assert() {
        let (result, fake) = execute("log a\nexit\nlog b");
        result.unwrap();
        assert_eq!(fake.lines, vec!["a"]);
        let (result, _) = execute("log a\nerror \"falhou {1+1:d}\"");
        assert_eq!(result.unwrap_err(), "linha 2: falhou 2");
        let (result, _) = execute("assert 1 == 2 \"diferente\"");
        assert!(result.unwrap_err().contains("diferente"));
        let (result, _) = execute("assert 1 == 2");
        assert!(result.unwrap_err().contains("assert falhou: 1 == 2"));
        let (result, _) = execute("assert 1 == 1\nsleep 10");
        assert!(result.is_ok());
        let (result, _) = execute("for i = 0 to 9\n  if i == 2\n    exit\n  end\nend\nlog depois");
        assert_eq!(result.unwrap().variables["i"], 2);
    }

    #[test]
    fn parse_errors_name_the_line() {
        assert!(parse("if 1\nlog x").unwrap_err().starts_with("linha 1:"));
        assert!(parse("log x\nend").unwrap_err().starts_with("linha 2:"));
        assert!(parse("for i = 1\nend").unwrap_err().starts_with("linha 1:"));
        assert!(parse("break").unwrap_err().contains("fora de um laco"));
        assert!(parse("while 1\nelse\nend").unwrap_err().starts_with("linha 2:"));
        assert!(parse("if 1\nelse\nelse\nend").unwrap_err().starts_with("linha 3:"));
        assert!(parse("\n\nwhile 1\n").unwrap_err().starts_with("linha 3:"));
        let script = parse("// nada\n\n# nada\nlog x").unwrap();
        assert_eq!(script.len(), 1);
        assert!(!script.is_empty());
    }

    #[test]
    fn step_limit_and_errors() {
        let mut fake = Fake::default();
        let script = parse("while 1\nend").unwrap();
        assert!(run(&script, &mut fake, 50).unwrap_err().contains("limite de passos"));
        let (result, _) = execute("x = desconhecido + 1");
        assert!(result.unwrap_err().starts_with("linha 1: simbolo desconhecido"));
        let (result, _) = execute("for i = 0 to 1 step 0\nend");
        assert!(result.unwrap_err().contains("passo zero"));
    }
}
