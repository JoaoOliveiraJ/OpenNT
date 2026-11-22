//! Os roteiros do depurador do kernel (`cargo xtask test-boot --kd=com2
//! --script=ARQ` e `cargo xtask debug --script=ARQ`): uma linha por
//! comando, `#` comenta. Além dos comandos do depurador (`commands.rs`), a
//! linguagem tem conferências (`expect...`), variáveis tiradas da saída dos
//! comandos (`save...`, `set`, `${nome}`), condições (`if`), laços
//! (`while`, `repeat`, `for-each` pelas threads, processos, módulos,
//! processadores e linhas da saída), esperas pela COM1 com prazo e
//! tratadores de parada de breakpoint (`on-break <bp> { ... }`). A
//! referência está em `docs/ARQUITETURA.md` (roteiros do kd).
//!
//! Tudo o que o roteiro imprime vai à saída padrão (o log do test-boot) e,
//! quando há, à transcrição da sessão (`kd-sessao.log` ao lado do
//! `serial.log`), à medida que sai: os comandos, a saída deles e as linhas
//! dos breakpoints de log (`[kd-log]`). As esperas (`wait-stop`,
//! `wait-serial`, `sleep`) atendem as paradas enquanto esperam: um
//! breakpoint de log ou a carga de um módulo seguem sozinhos, um tratador
//! roda, e só uma parada sem tratador encerra a espera.
//!
//! O mesmo roteiro roda na janela do `opennt-dbg` e no servidor do
//! `opennt-mcp`: o anfitrião (`ScriptHost`) recebe as linhas no lugar da
//! saída padrão e pode cancelar, dar um prazo, passar o log da COM1,
//! atender uma parada antes dos tratadores e responder a um comando no
//! lugar do depurador (`Client::run_script_hosted`).

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use super::client::Client;
use super::commands::split_two;
use super::parse_number;

/// Prazo do `wait-serial` sem `/t` (o de antes da opção).
const SERIAL_WAIT: Duration = Duration::from_secs(300);
/// Prazo do `wait-stop` sem número, em milissegundos.
const STOP_WAIT_MS: u64 = 120_000;
/// Cada espera lê a conexão em fatias deste tamanho (entre elas saem as
/// linhas de log novas).
const POLL: Duration = Duration::from_millis(250);
/// Com a máquina parada a COM1 não anda: o `wait-serial` desiste depois
/// deste tempo (os últimos bytes do QEMU ainda chegam).
const STOPPED_GRACE: Duration = Duration::from_secs(2);
/// Linhas da saída de um comando numa mensagem de erro.
const ERROR_LINES: usize = 100;
/// Linhas do fim do console e da COM1 numa mensagem de erro.
const CONSOLE_LINES: usize = 60;
const SERIAL_LINES: usize = 20;
/// Voltas no máximo de um `while` ou `repeat`.
const LOOP_LIMIT: u64 = 1_000_000;

/// Opções de um roteiro.
#[derive(Clone, Debug, Default)]
pub struct ScriptOptions {
    /// O nome do arquivo nas mensagens de erro (vazio: só "roteiro").
    pub name: String,
    /// A transcrição da sessão: tudo o que o roteiro imprime, gravado à
    /// medida que sai.
    pub transcript: Option<PathBuf>,
    /// Para onde as linhas vão no lugar da saída padrão (uma janela, um
    /// servidor MCP pelo stdio): cada linha impressa, com o fim de linha.
    pub capture: Option<Arc<Mutex<String>>>,
    /// Variáveis definidas antes da primeira linha (o test-boot passa as da
    /// máquina: `smp`, `processadores` e `user_smp`); um texto que é número
    /// também vale como `$nome` nas expressões.
    pub variables: Vec<(String, String)>,
}

/// O anfitrião de um roteiro fora do test-boot (a janela do `opennt-dbg`,
/// o servidor do `opennt-mcp`). Cada método tem um padrão que não faz nada;
/// a linguagem, as variáveis, as esperas e os tratadores são os mesmos.
pub trait ScriptHost {
    /// Cada linha que o roteiro imprime, no lugar da saída padrão (a
    /// transcrição, se houver, também recebe).
    fn output(&mut self, _line: &str) {}

    /// Antes de cada comando ou bloco: a linha no arquivo e o texto dela.
    fn progress(&mut self, _line: usize, _text: &str) {}

    /// Depois de cada comando e a cada fatia das esperas (a janela põe o
    /// DbgPrint, a COM1 e o estado do alvo em dia).
    fn tick(&mut self, _client: &mut Client) {}

    /// O usuário pediu para parar: o roteiro para antes do próximo comando
    /// ou dentro da espera.
    fn cancelled(&self) -> bool {
        false
    }

    /// O fim do prazo: as esperas não passam dele e nenhum comando começa
    /// depois.
    fn deadline(&self) -> Option<Instant> {
        None
    }

    /// O log da COM1 (o `wait-serial`, o `serial-has`) quando o cliente não
    /// tem a COM1 do test-boot: o arquivo é lido do começo e acompanhado.
    fn serial_log(&self) -> Option<PathBuf> {
        None
    }

    /// Uma parada chegou numa espera, antes dos `/cmd` e dos tratadores:
    /// `true` quando o anfitrião a atendeu (o roteiro faz a máquina seguir
    /// e a espera continua).
    fn service_stop(&mut self, _client: &mut Client) -> bool {
        false
    }

    /// Um comando do depurador que o anfitrião responde no lugar do cliente
    /// (o `attach` de uma sessão já anexada, o `detach` recusado); `None`
    /// manda ao depurador. `word` é a primeira palavra de `text`.
    fn intercept(&mut self, _client: &mut Client, _word: &str, _text: &str) -> Option<Result<String, String>> {
        None
    }
}

/// O resultado de um roteiro rodado por `Client::run_script_hosted`.
#[derive(Clone, Debug)]
pub struct ScriptOutcome {
    /// O erro é a mensagem inteira (arquivo, linha, contexto, saída).
    pub result: Result<(), String>,
    /// A linha do arquivo (do 1) que falhou.
    pub failed_line: Option<usize>,
    /// Quantos comandos rodaram (os blocos não contam; um laço conta cada
    /// volta).
    pub commands: usize,
    /// As variáveis que o roteiro definiu, com o texto delas (as numéricas
    /// em hexadecimal, `0x...`, como o `save` as guarda).
    pub variables: BTreeMap<String, String>,
}

/// Confere a sintaxe do roteiro inteiro sem rodar nada (os blocos, os
/// `for-each`, os `leave` fora de laço): o erro vem com a linha.
pub fn check_script(script: &str) -> Result<(), (usize, String)> {
    parse(script).map(|_| ())
}

/// As coleções do `for-each`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Collection {
    Thread,
    Process,
    Module,
    UserModule,
    Cpu,
    Line,
}

impl Collection {
    fn parse(word: &str) -> Option<Self> {
        Some(match word {
            "thread" | "threads" => Self::Thread,
            "process" | "processes" => Self::Process,
            "module" | "modules" => Self::Module,
            "umodule" | "umodules" => Self::UserModule,
            "cpu" | "cpus" => Self::Cpu,
            "line" | "lines" => Self::Line,
            _ => return None,
        })
    }

    /// Os filtros que a coleção aceita.
    fn filters(self) -> &'static [&'static str] {
        match self {
            Self::Thread => &["pid", "state", "process", "stack"],
            Self::Process | Self::Module | Self::UserModule => &["name"],
            Self::Cpu => &[],
            Self::Line => &["containing"],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Statement {
    /// Um comando do roteiro ou do depurador (o texto da linha).
    Command(String),
    /// `if`, os `else if` (linha, condição, corpo) e o `else`.
    If { branches: Vec<(usize, String, Vec<Node>)>, otherwise: Vec<Node> },
    While { condition: String, body: Vec<Node> },
    Repeat { count: String, variable: Option<String>, body: Vec<Node> },
    ForEach { collection: Collection, variable: String, filters: Vec<(String, String)>, body: Vec<Node> },
    OnBreak { target: String, body: Vec<Node> },
    Leave,
    Next,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Node {
    line: usize,
    text: String,
    statement: Statement,
}

/// Como um bloco terminou.
enum End {
    /// O fim do arquivo.
    File,
    /// `}`.
    Close,
    /// `} else {` (`None`) ou `} else if <condição> {`.
    Else(Option<String>),
}

/// As palavras que abrem bloco (a linha termina com `{`).
const BLOCKS: [&str; 5] = ["if", "while", "repeat", "for-each", "on-break"];

struct Parser<'a> {
    lines: Vec<(usize, &'a str)>,
    index: usize,
}

/// O que vem depois de um `}`.
fn closing(rest: &str) -> Option<End> {
    if rest.is_empty() {
        return Some(End::Close);
    }
    let rest = rest.strip_prefix("else")?.trim();
    if rest == "{" {
        return Some(End::Else(None));
    }
    let after = rest.strip_prefix("if")?;
    if !after.starts_with(char::is_whitespace) {
        return None;
    }
    let condition = after.trim_end().strip_suffix('{')?.trim();
    if condition.is_empty() {
        None
    } else {
        Some(End::Else(Some(condition.to_string())))
    }
}

impl<'a> Parser<'a> {
    /// Lê comandos até o fim do bloco; `loops` é quantos laços envolvem o
    /// bloco (o `leave` e o `next` só valem dentro de um). Devolve o corpo,
    /// como terminou e a linha do fim.
    fn block(&mut self, loops: usize) -> Result<(Vec<Node>, End, usize), (usize, String)> {
        let mut nodes = Vec::new();
        while let Some(&(line, text)) = self.lines.get(self.index) {
            self.index += 1;
            if let Some(rest) = text.strip_prefix('}') {
                let end = closing(rest.trim()).ok_or((line, "depois do } so cabe else { ou else if <condicao> {".to_string()))?;
                return Ok((nodes, end, line));
            }
            let keyword = text.split_whitespace().next().unwrap_or("");
            let opens = text.ends_with('{');
            // O que fica entre a palavra e o `{` (a palavra não tem `{`, então
            // a fatia existe).
            let head = if opens && BLOCKS.contains(&keyword) { text[keyword.len()..text.len() - 1].trim() } else { "" };
            let statement = match keyword {
                "if" | "while" | "repeat" | "for-each" | "on-break" if !opens => {
                    let words: Vec<&str> = text.split_whitespace().collect();
                    if keyword == "on-break" && words.len() >= 3 && words.last() == Some(&"off") {
                        Statement::Command(text.to_string())
                    } else {
                        return Err((line, format!("{keyword} abre um bloco: falta o {{ no fim da linha")));
                    }
                }
                "if" => {
                    if head.is_empty() {
                        return Err((line, "if sem condicao".into()));
                    }
                    self.if_statement(line, head.to_string(), loops)?
                }
                "while" => {
                    if head.is_empty() {
                        return Err((line, "while sem condicao".into()));
                    }
                    Statement::While { condition: head.to_string(), body: self.closed(loops + 1, line, "while")? }
                }
                "repeat" => {
                    let parts: Vec<&str> = head.split_whitespace().collect();
                    let (count, variable) = match parts.split_last() {
                        None => return Err((line, "uso: repeat <n> [variavel] {".into())),
                        Some((last, rest)) if !rest.is_empty() && is_identifier(last) => (rest.join(" "), Some(last.to_string())),
                        Some(_) => (parts.join(" "), None),
                    };
                    Statement::Repeat { count, variable, body: self.closed(loops + 1, line, "repeat")? }
                }
                "for-each" => {
                    let parts = words(head);
                    let usage = "uso: for-each <thread|process|module|umodule|cpu|line> <variavel> [filtro valor]... {";
                    let (Some(kind), Some(variable)) = (parts.first(), parts.get(1)) else {
                        return Err((line, usage.into()));
                    };
                    let collection = Collection::parse(kind).ok_or_else(|| (line, format!("for-each: colecao desconhecida {kind:?} ({usage})")))?;
                    if !is_identifier(variable) {
                        return Err((line, format!("for-each: nome de variavel invalido {variable:?}")));
                    }
                    let rest = &parts[2..];
                    if rest.len() % 2 != 0 {
                        return Err((line, "for-each: filtro sem valor".into()));
                    }
                    let mut filters = Vec::new();
                    for pair in rest.chunks(2) {
                        if !collection.filters().contains(&pair[0].as_str()) {
                            let accepted = if collection.filters().is_empty() { "nenhum".to_string() } else { collection.filters().join(", ") };
                            return Err((line, format!("for-each {kind}: filtro desconhecido {:?} (aceita: {accepted})", pair[0])));
                        }
                        filters.push((pair[0].clone(), pair[1].clone()));
                    }
                    Statement::ForEach { collection, variable: variable.clone(), filters, body: self.closed(loops + 1, line, "for-each")? }
                }
                "on-break" => {
                    if head.is_empty() {
                        return Err((line, "uso: on-break <breakpoint> {".into()));
                    }
                    // O tratador roda fora dos laços de onde foi registrado.
                    Statement::OnBreak { target: head.to_string(), body: self.closed(0, line, "on-break")? }
                }
                _ if text == "leave" || text == "next" => {
                    if loops == 0 {
                        return Err((line, format!("{text} fora de um laco (while, repeat ou for-each)")));
                    }
                    if text == "leave" {
                        Statement::Leave
                    } else {
                        Statement::Next
                    }
                }
                _ => Statement::Command(text.to_string()),
            };
            nodes.push(Node { line, text: text.to_string(), statement });
        }
        Ok((nodes, End::File, 0))
    }

    /// Um bloco que só pode terminar em `}`.
    fn closed(&mut self, loops: usize, line: usize, keyword: &str) -> Result<Vec<Node>, (usize, String)> {
        let (body, end, end_line) = self.block(loops)?;
        match end {
            End::Close => Ok(body),
            End::Else(_) => Err((end_line, format!("else fora de um if (o bloco aberto e o {keyword} da linha {line})"))),
            End::File => Err((line, format!("{keyword} sem }} (o bloco vai ate o fim do arquivo)"))),
        }
    }

    /// O `if` com os `else if` e o `else`.
    fn if_statement(&mut self, line: usize, condition: String, loops: usize) -> Result<Statement, (usize, String)> {
        let mut branches = Vec::new();
        let mut current = (line, condition);
        loop {
            let (body, end, end_line) = self.block(loops)?;
            match end {
                End::Close => {
                    branches.push((current.0, current.1, body));
                    return Ok(Statement::If { branches, otherwise: Vec::new() });
                }
                End::Else(Some(next)) => {
                    branches.push((current.0, current.1, body));
                    current = (end_line, next);
                }
                End::Else(None) => {
                    branches.push((current.0, current.1, body));
                    let otherwise = self.closed(loops, end_line, "else")?;
                    return Ok(Statement::If { branches, otherwise });
                }
                End::File => return Err((current.0, "if sem } (o bloco vai ate o fim do arquivo)".into())),
            }
        }
    }
}

/// Lê o roteiro inteiro; um erro de sintaxe vem com o número da linha.
fn parse(script: &str) -> Result<Vec<Node>, (usize, String)> {
    let lines = script.lines().enumerate().map(|(index, text)| (index + 1, text.trim())).filter(|(_, text)| !text.is_empty() && !text.starts_with('#')).collect();
    let mut parser = Parser { lines, index: 0 };
    let (nodes, end, line) = parser.block(0)?;
    match end {
        End::File => Ok(nodes),
        End::Close => Err((line, "} sem bloco aberto".into())),
        End::Else(_) => Err((line, "else sem if".into())),
    }
}

fn is_identifier(text: &str) -> bool {
    let mut characters = text.chars();
    characters.next().is_some_and(|first| first.is_ascii_alphabetic() || first == '_') && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// As palavras de uma linha; um trecho entre aspas é uma palavra só (sem
/// as aspas).
fn words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut started = false;
    for character in text.chars() {
        match character {
            '"' => {
                quoted = !quoted;
                started = true;
            }
            character if character.is_whitespace() && !quoted => {
                if started {
                    words.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            character => {
                current.push(character);
                started = true;
            }
        }
    }
    if started {
        words.push(current);
    }
    words
}

/// O texto sem as aspas em volta, se tiver.
fn unquote(text: &str) -> &str {
    let text = text.trim();
    match text.strip_prefix('"').and_then(|inner| inner.strip_suffix('"')) {
        Some(inner) => inner,
        None => text,
    }
}

/// A palavra `index` da linha (a partir de 0; negativa conta do fim).
fn pick_word(line: &str, index: i64) -> Option<&str> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let position = if index >= 0 { usize::try_from(index).ok()? } else { words.len().checked_sub(usize::try_from(index.unsigned_abs()).ok()?)? };
    words.get(position).copied()
}

/// Troca `${nome}` pelo texto da variável e `${nome.N}` pela palavra N
/// dele.
/// As linhas de `output` com `needle`; sem nenhuma, as que o têm sem
/// diferença de maiúsculas (o `lmu` mostra `msv1_0.DLL` como a PEB guarda,
/// e o roteiro escreve `msv1_0.dll`).
fn lines_with<'a>(output: &'a str, needle: &str) -> Vec<&'a str> {
    let exact: Vec<&str> = output.lines().filter(|text| text.contains(needle)).collect();
    if !exact.is_empty() {
        return exact;
    }
    let lower = needle.to_ascii_lowercase();
    output.lines().filter(|text| text.to_ascii_lowercase().contains(&lower)).collect()
}

fn substitute(variables: &HashMap<String, String>, text: &str) -> Result<String, String> {
    let mut output = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        output.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}').ok_or_else(|| format!("${{ sem }} em {text:?}"))?;
        let inner = after[..end].trim();
        let (name, word) = match inner.rsplit_once('.').and_then(|(name, index)| index.parse::<i64>().ok().map(|index| (name, index))) {
            Some((name, index)) => (name, Some(index)),
            None => (inner, None),
        };
        let value = variables.get(name).ok_or_else(|| format!("variavel ${{{name}}} nao definida"))?;
        match word {
            None => output.push_str(value),
            Some(index) => output.push_str(pick_word(value, index).ok_or_else(|| format!("${{{inner}}}: o texto {value:?} nao tem a palavra {index}"))?),
        }
        rest = &after[end + 1..];
    }
    output.push_str(rest);
    Ok(output)
}

/// Um texto entre aspas no começo: o texto e o resto.
fn quoted(text: &str) -> Option<(&str, &str)> {
    let inner = text.strip_prefix('"')?;
    let end = inner.find('"')?;
    Some((&inner[..end], &inner[end + 1..]))
}

/// `"a" == "b"`, `"a" != "b"` e `"a" contains "b"`: a comparação de
/// textos (`None` quando a condição não tem essa forma).
fn compare_text(text: &str) -> Option<bool> {
    let (left, rest) = quoted(text.trim())?;
    let rest = rest.trim_start();
    let (operator, rest) = ["==", "!=", "contains"].into_iter().find_map(|operator| rest.strip_prefix(operator).map(|rest| (operator, rest)))?;
    let (right, tail) = quoted(rest.trim_start())?;
    if !tail.trim().is_empty() {
        return None;
    }
    Some(match operator {
        "==" => left == right,
        "!=" => left != right,
        _ => left.contains(right),
    })
}

/// `[/t <ms>] <texto>`: o prazo pedido (o texto dele, que pode ser
/// `$variavel` ou expressão sem espaços) e o texto.
fn wait_options(argument: &str) -> (Option<&str>, &str) {
    match argument.strip_prefix("/t") {
        Some(rest) if rest.starts_with(char::is_whitespace) => {
            let rest = rest.trim_start();
            let (number, text) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
            (Some(number), unquote(text))
        }
        _ => (None, unquote(argument)),
    }
}

/// Lê o que o log da COM1 ganhou desde `offset` (um arquivo menor que o
/// lido recomeçou: o texto volta a ser só o dele).
fn read_serial_file(path: &Path, offset: &mut u64, serial: &Mutex<String>) {
    let Ok(mut file) = File::open(path) else { return };
    let Ok(length) = file.metadata().map(|metadata| metadata.len()) else { return };
    if length < *offset {
        *offset = 0;
        serial_text(serial).clear();
    }
    if length == *offset || file.seek(SeekFrom::Start(*offset)).is_err() {
        return;
    }
    let mut bytes = Vec::new();
    if file.take(length - *offset).read_to_end(&mut bytes).is_ok() && !bytes.is_empty() {
        *offset += bytes.len() as u64;
        serial_text(serial).push_str(&String::from_utf8_lossy(&bytes));
    }
}

/// O nome bate: igual sem caixa, ou igual ao nome sem a extensão
/// (`smss` e `smss.exe`, `ACPI` e `acpi.sys`).
fn name_matches(wanted: &str, name: &str) -> bool {
    let (wanted, name) = (wanted.to_ascii_lowercase(), name.to_ascii_lowercase());
    name == wanted || name.rsplit_once('.').is_some_and(|(stem, _)| stem == wanted)
}

/// O número do breakpoint (ou evento) que parou a máquina, pelo texto da
/// parada: `(breakpoint #3, acerto 1)`, `(breakpoint #3 nome, ...)`,
/// `(modulo carregado: ..., breakpoint #2)` e `(evento #4: ...)`.
fn stop_breakpoint_id(stop: &str) -> Option<u32> {
    for marker in ["(breakpoint #", ", breakpoint #", "(evento #"] {
        if let Some(position) = stop.find(marker) {
            let digits: String = stop[position + marker.len()..].chars().take_while(char::is_ascii_digit).collect();
            if let Ok(id) = digits.parse() {
                return Some(id);
            }
        }
    }
    None
}

/// O texto com `  | ` em cada linha, até `limit` linhas (as primeiras, ou
/// as últimas com `tail`).
fn quote_lines(text: &str, limit: usize, tail: bool) -> String {
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return " (vazia)".to_string();
    }
    let skipped = lines.len().saturating_sub(limit);
    let shown = if tail { &lines[skipped..] } else { &lines[..lines.len() - skipped] };
    let mut output = String::new();
    if tail && skipped > 0 {
        output.push_str(&format!("\n  | ({skipped} linhas antes)"));
    }
    for line in shown {
        output.push_str(&format!("\n  | {line}"));
    }
    if !tail && skipped > 0 {
        output.push_str(&format!("\n  | (mais {skipped} linhas)"));
    }
    output
}

/// O texto da COM1 (um leitor que entrou em pânico não impede a leitura).
fn serial_text(serial: &Mutex<String>) -> MutexGuard<'_, String> {
    serial.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// O que fazer depois de um comando.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    Normal,
    /// `leave`: sai do laço.
    Leave,
    /// `next`: a próxima volta.
    Next,
    /// `stop`: o tratador deixa a máquina parada.
    Stop,
    /// `exit`: o roteiro acaba sem erro.
    Exit,
}

enum StopWait {
    Stopped(String),
    Timeout,
    Exit,
}

enum SerialWait {
    Found,
    Timeout,
    Stopped(String),
    Exit,
}

/// O que ficou de uma parada atendida numa espera.
enum Handled {
    /// A máquina segue (um tratador ou o `/cmd` a fez seguir).
    Resumed,
    /// A máquina ficou parada: a espera acaba.
    Stopped,
    Exit,
}

/// Um campo de um item do `for-each`.
enum Field {
    Number(u64),
    Text(String),
}

/// Os campos de um item: o sufixo da variável (vazio = a própria) e o
/// valor.
type Item = Vec<(&'static str, Field)>;

/// Um tratador de parada: `on-break <alvo> { corpo }`.
struct Handler {
    target: String,
    line: usize,
    body: Vec<Node>,
}

struct Runner<'c, 'h> {
    client: &'c mut Client,
    name: String,
    capture: Option<Arc<Mutex<String>>>,
    host: Option<&'h mut dyn ScriptHost>,
    /// O texto da COM1: o do test-boot, ou o do log do anfitrião.
    serial: Option<Arc<Mutex<String>>>,
    /// O log do anfitrião e quanto dele já foi lido.
    serial_file: Option<(PathBuf, u64)>,
    /// As variáveis definidas por este roteiro (o `ScriptOutcome`).
    assigned: BTreeSet<String>,
    /// Comandos rodados.
    commands: usize,
    /// A linha da última mensagem de erro montada (a que encerra o roteiro).
    failed_line: Cell<Option<usize>>,
    /// O texto de cada variável (as numéricas também ficam no cliente, para
    /// o `$nome` das expressões).
    variables: HashMap<String, String>,
    /// A saída do último comando do depurador (o `expect` e os `save-*`).
    last_output: String,
    /// O último comando do depurador: a linha e o texto.
    last_command: Option<(usize, String)>,
    handlers: Vec<Handler>,
    /// O breakpoint do tratador que está rodando (as paradas dentro dele não
    /// chamam outro tratador).
    in_handler: Option<u32>,
    /// Depois de um `detach`: as esperas não leem a conexão.
    detached: bool,
    /// Quantas linhas de log do cliente já saíram.
    printed_logs: usize,
    transcript: Option<File>,
    /// Onde a execução está (laços e tratadores), para as mensagens de erro.
    context: Vec<String>,
}

impl<'c, 'h> Runner<'c, 'h> {
    fn new(client: &'c mut Client, options: &ScriptOptions, host: Option<&'h mut dyn ScriptHost>) -> Self {
        let printed_logs = client.log_lines().len();
        let variables = client.variables.iter().map(|(name, value)| (name.clone(), format!("{value:#x}"))).collect();
        // Sem a COM1 do test-boot, o log do anfitrião (lido do começo).
        let serial_file = match (&client.serial, host.as_deref().and_then(|host| host.serial_log())) {
            (None, Some(path)) => Some((path, 0)),
            _ => None,
        };
        let serial = client.serial.clone().or_else(|| serial_file.as_ref().map(|_| Arc::new(Mutex::new(String::new()))));
        let mut runner = Runner {
            client,
            name: options.name.clone(),
            capture: options.capture.clone(),
            host,
            serial,
            serial_file,
            assigned: BTreeSet::new(),
            commands: 0,
            failed_line: Cell::new(None),
            variables,
            last_output: String::new(),
            last_command: None,
            handlers: Vec::new(),
            in_handler: None,
            detached: false,
            printed_logs,
            transcript: None,
            context: Vec::new(),
        };
        if let Some(path) = &options.transcript {
            match File::create(path) {
                Ok(file) => {
                    runner.transcript = Some(file);
                    runner.emit(&format!("[kd-script] transcricao em {}", path.display()));
                }
                Err(error) => runner.emit(&format!("[kd-script] sem a transcricao {}: {error}", path.display())),
            }
        }
        for (name, text) in &options.variables {
            runner.variables.insert(name.clone(), text.clone());
            if let Some(value) = parse_number(text) {
                runner.client.variables.insert(name.clone(), value);
            }
        }
        runner
    }

    /// Uma linha no anfitrião, na captura ou na saída padrão, e na
    /// transcrição.
    fn emit(&mut self, line: &str) {
        if let Some(host) = self.host.as_deref_mut() {
            host.output(line);
        } else {
            match &self.capture {
                Some(capture) => {
                    if let Ok(mut text) = capture.lock() {
                        text.push_str(line);
                        text.push('\n');
                    }
                }
                None => println!("{line}"),
            }
        }
        self.note(line);
    }

    /// O anfitrião põe a janela em dia.
    fn tick(&mut self) {
        if let Some(host) = self.host.as_deref_mut() {
            host.tick(self.client);
        }
    }

    /// O usuário pediu para parar.
    fn cancelled(&self) -> bool {
        self.host.as_deref().is_some_and(|host| host.cancelled())
    }

    /// O fim de uma espera, sem passar do prazo do anfitrião.
    fn cap(&self, deadline: Instant) -> Instant {
        match self.host.as_deref().and_then(|host| host.deadline()) {
            Some(limit) => deadline.min(limit),
            None => deadline,
        }
    }

    /// Antes de cada comando ou bloco: o progresso, o Cancelar e o prazo.
    fn checkpoint(&mut self, node: &Node) -> Result<(), String> {
        if let Some(host) = self.host.as_deref_mut() {
            host.progress(node.line, &node.text);
        }
        if self.cancelled() {
            return Err(self.error(node.line, &node.text, "parado pelo usuario antes desta linha (Cancelar)"));
        }
        if self.host.as_deref().and_then(|host| host.deadline()).is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(self.error(node.line, &node.text, "prazo esgotado antes desta linha"));
        }
        Ok(())
    }

    /// O texto da COM1, com o log do anfitrião lido até o fim.
    fn serial_buffer(&mut self) -> Option<Arc<Mutex<String>>> {
        if let (Some((path, offset)), Some(serial)) = (&mut self.serial_file, &self.serial) {
            read_serial_file(path, offset, serial);
        }
        self.serial.clone()
    }

    /// Um prazo em milissegundos: número, `$variavel` ou expressão; vazio
    /// é o padrão.
    fn milliseconds(&mut self, text: &str, default: u64) -> Result<u64, String> {
        let text = text.trim();
        if text.is_empty() {
            return Ok(default);
        }
        if let Some(value) = parse_number(text) {
            return Ok(value);
        }
        self.client.evaluate(text).map_err(|error| format!("{text:?} nao e um prazo em milissegundos ({error})"))
    }

    /// Uma fatia de espera na conexão. Se o alvo fechou a conexão (o QEMU
    /// terminou ou foi fechado), o erro traz o fim da COM1: um bugcheck ou
    /// pânico do kernel aparece ali.
    fn poll(&mut self, line: usize, shown: &str, slice: Duration) -> Result<Option<String>, String> {
        match self.client.poll(slice) {
            Ok(stop) => Ok(stop),
            Err(error) if error.contains("fechou a conexao") => {
                let tail = self.serial_tail();
                Err(self.error(line, shown, &format!("{error}\n  a conexao caiu durante a espera (o QEMU terminou ou foi fechado); fim da COM1:{tail}")))
            }
            Err(error) => Err(self.error(line, shown, &error)),
        }
    }

    /// O prazo e o texto de `[/t <ms>] <texto>`.
    fn wait_arguments<'t>(&mut self, argument: &'t str) -> Result<(Duration, &'t str), String> {
        let (number, text) = wait_options(argument);
        let timeout = match number {
            Some(number) => Duration::from_millis(self.milliseconds(number, 0).map_err(|error| format!("/t: {error}"))?),
            None => SERIAL_WAIT,
        };
        Ok((timeout, text))
    }

    /// Uma linha só na transcrição.
    fn note(&mut self, line: &str) {
        if let Some(file) = &mut self.transcript {
            let _ = writeln!(file, "{line}");
        }
    }

    fn prefix(&self) -> String {
        match self.in_handler {
            Some(id) => format!("[kd-script] [on-break #{id}]"),
            None => "[kd-script]".to_string(),
        }
    }

    /// As linhas novas dos breakpoints de log e dos comandos de acerto.
    fn flush_log(&mut self) {
        let total = self.client.log_lines().len();
        if self.printed_logs >= total {
            self.printed_logs = total;
            return;
        }
        let fresh: Vec<String> = self.client.log_lines()[self.printed_logs..].to_vec();
        self.printed_logs = total;
        for entry in fresh {
            for part in entry.lines() {
                self.emit(&format!("[kd-log] {part}"));
            }
        }
    }

    /// A mensagem de erro de uma linha do roteiro.
    fn error(&self, line: usize, text: &str, message: &str) -> String {
        self.failed_line.set(Some(line));
        let script = if self.name.is_empty() { "roteiro".to_string() } else { format!("roteiro {}", self.name) };
        let mut error = format!("{script}, linha {line}: {text}: {message}");
        if !self.context.is_empty() {
            error.push_str(&format!("\n  dentro de: {}", self.context.join(" > ")));
        }
        error
    }

    /// O comando anterior (para as conferências que olham a saída ou a
    /// parada dele).
    fn command_line(&self) -> String {
        match &self.last_command {
            Some((line, command)) => format!("\n  comando (linha {line}): {command}"),
            None => "\n  (nenhum comando do depurador rodou antes)".to_string(),
        }
    }

    /// O comando anterior e a saída dele.
    fn output_report(&self) -> String {
        format!("{}\n  saida do comando:{}", self.command_line(), quote_lines(&self.last_output, ERROR_LINES, false))
    }

    fn serial_tail(&mut self) -> String {
        match self.serial_buffer() {
            Some(serial) => quote_lines(&serial_text(&serial), SERIAL_LINES, true),
            None => " (sem a COM1)".to_string(),
        }
    }

    fn set_number(&mut self, name: &str, value: u64) {
        self.assigned.insert(name.to_string());
        self.variables.insert(name.to_string(), format!("{value:#x}"));
        self.client.variables.insert(name.to_string(), value);
    }

    /// Uma variável de texto; se o texto é um número, `$nome` também vale nas
    /// expressões.
    fn set_text(&mut self, name: &str, text: &str) {
        self.assigned.insert(name.to_string());
        self.variables.insert(name.to_string(), text.to_string());
        match parse_number(text) {
            Some(value) => {
                self.client.variables.insert(name.to_string(), value);
            }
            None => {
                self.client.variables.remove(name);
            }
        }
    }

    /// Guarda e mostra uma variável tirada da saída.
    fn save_value(&mut self, name: &str, text: &str) {
        self.set_text(name, text);
        let prefix = self.prefix();
        match parse_number(text) {
            Some(value) => self.emit(&format!("{prefix}   ${name} = {value:#x}")),
            None => self.emit(&format!("{prefix}   ${{{name}}} = {text}")),
        }
    }

    /// A saída de um comando do depurador: mostrada e guardada para as
    /// conferências.
    fn record_output(&mut self, line: usize, command: &str, output: String) {
        let prefix = self.prefix();
        for text in output.lines() {
            self.emit(&format!("{prefix}   {text}"));
        }
        self.last_output = output;
        self.last_command = Some((line, command.to_string()));
    }

    /// A pilha da thread (pelo quadro de troca) tem um quadro no módulo. Só
    /// a parte de kernel: sem trocar o processo das leituras a cada
    /// candidata.
    fn thread_in_module(&mut self, thread: u64, module: &str) -> bool {
        let Ok((_, walk)) = self.client.thread_stack(thread, 32, false) else { return false };
        walk.frames.iter().any(|frame| self.client.symbols.module_at(frame.address).is_some_and(|found| found.name.eq_ignore_ascii_case(module) || found.file_name.eq_ignore_ascii_case(module)))
    }

    fn run_block(&mut self, nodes: &[Node]) -> Result<Flow, String> {
        for node in nodes {
            self.checkpoint(node)?;
            let flow = self.run_node(node);
            self.flush_log();
            self.tick();
            let flow = flow?;
            if flow != Flow::Normal {
                return Ok(flow);
            }
        }
        Ok(Flow::Normal)
    }

    fn run_node(&mut self, node: &Node) -> Result<Flow, String> {
        match &node.statement {
            Statement::Command(text) => self.command(node.line, text),
            Statement::If { branches, otherwise } => {
                for (index, (line, condition, body)) in branches.iter().enumerate() {
                    let keyword = if index == 0 { "if" } else { "else if" };
                    let shown = format!("{keyword} {condition}");
                    let Some(value) = self.condition(*line, &shown, condition)? else { return Ok(Flow::Exit) };
                    self.emit(&format!("{} > {shown}: {}", self.prefix(), if value { "sim" } else { "nao" }));
                    if value {
                        return self.run_block(body);
                    }
                }
                if !otherwise.is_empty() {
                    self.emit(&format!("{} > else", self.prefix()));
                }
                self.run_block(otherwise)
            }
            Statement::While { condition, body } => {
                self.emit(&format!("{} > while {condition}", self.prefix()));
                let mut turns = 0u64;
                loop {
                    match self.condition(node.line, &node.text, condition)? {
                        None => return Ok(Flow::Exit),
                        Some(false) => break,
                        Some(true) => {}
                    }
                    turns += 1;
                    if turns > LOOP_LIMIT {
                        return Err(self.error(node.line, &node.text, &format!("mais de {LOOP_LIMIT} voltas")));
                    }
                    // Um laço sem comandos dentro também para no Cancelar.
                    if self.cancelled() {
                        return Err(self.error(node.line, &node.text, &format!("parado pelo usuario na volta {turns} (Cancelar)")));
                    }
                    self.context.push(format!("while da linha {}, volta {turns}", node.line));
                    let result = self.run_block(body);
                    self.context.pop();
                    match result? {
                        Flow::Leave => break,
                        Flow::Normal | Flow::Next => {}
                        other => return Ok(other),
                    }
                }
                self.emit(&format!("{}   while da linha {}: {turns} voltas", self.prefix(), node.line));
                Ok(Flow::Normal)
            }
            Statement::Repeat { count, variable, body } => {
                let expression = substitute(&self.variables, count).map_err(|error| self.error(node.line, &node.text, &error))?;
                let total = self.client.evaluate(&expression).map_err(|error| self.error(node.line, &node.text, &error))?;
                if total > LOOP_LIMIT {
                    return Err(self.error(node.line, &node.text, &format!("{total} voltas: o limite e {LOOP_LIMIT}")));
                }
                self.emit(&format!("{} > repeat {total}", self.prefix()));
                for turn in 0..total {
                    if let Some(name) = variable {
                        self.set_number(name, turn);
                    }
                    self.context.push(format!("repeat da linha {}, volta {} de {total}", node.line, turn + 1));
                    let result = self.run_block(body);
                    self.context.pop();
                    match result? {
                        Flow::Leave => break,
                        Flow::Normal | Flow::Next => {}
                        other => return Ok(other),
                    }
                }
                Ok(Flow::Normal)
            }
            Statement::ForEach { collection, variable, filters, body } => self.for_each(node, *collection, variable, filters, body),
            Statement::OnBreak { target, body } => {
                let target = substitute(&self.variables, target).map_err(|error| self.error(node.line, &node.text, &error))?;
                // Um tratador novo para o mesmo alvo troca o anterior.
                self.handlers.retain(|handler| !handler.target.eq_ignore_ascii_case(&target));
                self.emit(&format!("{} > on-break {target}: tratador registrado (linha {})", self.prefix(), node.line));
                self.handlers.push(Handler { target, line: node.line, body: body.clone() });
                Ok(Flow::Normal)
            }
            Statement::Leave => Ok(Flow::Leave),
            Statement::Next => Ok(Flow::Next),
        }
    }

    /// Um comando: os do roteiro aqui, o resto vai ao depurador.
    fn command(&mut self, line: usize, raw: &str) -> Result<Flow, String> {
        let text = substitute(&self.variables, raw).map_err(|error| self.error(line, raw, &error))?;
        let shown = if text == raw { raw.to_string() } else { format!("{raw} (= {text})") };
        self.commands += 1;
        self.emit(&format!("{} > {text}", self.prefix()));
        let (word, rest) = text.split_once(char::is_whitespace).map_or((text.as_str(), ""), |(word, rest)| (word, rest.trim()));
        match word {
            "expect" | "expect-not" => {
                let present = self.last_output.contains(rest);
                if present != (word == "expect") {
                    let what = if present { "tem" } else { "nao tem" };
                    return Err(self.error(line, &shown, &format!("a saida do comando anterior {what} {rest:?}{}", self.output_report())));
                }
            }
            "expect-stop" => {
                if !self.client.last_stop().contains(rest) {
                    let stop = self.client.last_stop().to_string();
                    let stop = if stop.is_empty() { "(nenhuma)" } else { stop.as_str() };
                    return Err(self.error(line, &shown, &format!("a ultima parada nao tem {rest:?}\n  ultima parada: {stop}{}", self.command_line())));
                }
            }
            "expect-console" => {
                self.client.collect_console();
                if !self.client.console().contains(rest) {
                    let tail = quote_lines(self.client.console(), CONSOLE_LINES, true);
                    return Err(self.error(line, &shown, &format!("a saida do DbgPrint e dos breakpoints de log nao tem {rest:?}\n  fim dela:{tail}")));
                }
            }
            "expect-eq" => {
                let (left, right) = split_two(rest).ok_or_else(|| self.error(line, &shown, "uso: expect-eq <expr> <expr>"))?;
                let a = self.client.evaluate(left).map_err(|error| self.error(line, &shown, &error))?;
                let b = self.client.evaluate(right).map_err(|error| self.error(line, &shown, &error))?;
                if a != b {
                    return Err(self.error(line, &shown, &format!("{left} = {a:#x}, {right} = {b:#x}")));
                }
                self.emit(&format!("{}   {a:#x} == {b:#x}", self.prefix()));
            }
            "save" => {
                let (name, expression) = split_two(rest).ok_or_else(|| self.error(line, &shown, "uso: save <nome> <expr>"))?;
                if !is_identifier(name) {
                    return Err(self.error(line, &shown, &format!("nome de variavel invalido {name:?}")));
                }
                let value = self.client.evaluate(expression).map_err(|error| self.error(line, &shown, &error))?;
                self.set_number(name, value);
                self.emit(&format!("{}   ${name} = {value:#x}", self.prefix()));
            }
            "set" => {
                let (name, value) = rest.split_once(char::is_whitespace).map_or((rest, ""), |(name, value)| (name, value.trim()));
                if !is_identifier(name) {
                    return Err(self.error(line, &shown, "uso: set <nome> <texto>"));
                }
                let value = unquote(value).to_string();
                self.set_text(name, &value);
                self.emit(&format!("{}   ${{{name}}} = {value}", self.prefix()));
            }
            "save-word" | "save-text" | "save-after" | "save-line" | "save-count" | "save-thread" => self.save_from_output(line, &shown, word, rest)?,
            "wait-serial" => {
                let (timeout, needle) = self.wait_arguments(rest).map_err(|error| self.error(line, &shown, &error))?;
                match self.wait_serial(line, &shown, needle, timeout)? {
                    SerialWait::Found => {}
                    SerialWait::Timeout => {
                        let tail = self.serial_tail();
                        return Err(self.error(line, &shown, &format!("tempo esgotado ({} ms) esperando {needle:?} na COM1\n  fim da COM1:{tail}", timeout.as_millis())));
                    }
                    SerialWait::Stopped(stop) => return Err(self.error(line, &shown, &format!("a maquina esta parada e {needle:?} nao chegou na COM1 (nenhum on-break a fez seguir; falta um continue?)\n  parada: {stop}"))),
                    SerialWait::Exit => return Ok(Flow::Exit),
                }
            }
            "wait-stop" => {
                let milliseconds = self.milliseconds(rest, STOP_WAIT_MS).map_err(|error| self.error(line, &shown, &format!("uso: wait-stop [ms]: {error}")))?;
                match self.wait_stop(line, &shown, Duration::from_millis(milliseconds))? {
                    StopWait::Stopped(stop) => self.record_output(line, &text, stop),
                    StopWait::Timeout => return Err(self.error(line, &shown, &format!("tempo esgotado ({milliseconds} ms) esperando a parada (a maquina segue rodando; use break)"))),
                    StopWait::Exit => return Ok(Flow::Exit),
                }
            }
            "sleep" => {
                // `sleep $espera`, `sleep 2*60000`; um argumento que não dá
                // número é erro (antes virava 1000 ms sem aviso).
                let milliseconds = self.milliseconds(rest, 1000).map_err(|error| self.error(line, &shown, &format!("uso: sleep <ms>: {error}")))?;
                if self.sleep(line, &shown, Duration::from_millis(milliseconds))? == Flow::Exit {
                    return Ok(Flow::Exit);
                }
            }
            "echo" => self.emit(&format!("{} {rest}", self.prefix())),
            "print" => {
                let message = self.client.format_log(rest);
                self.emit(&format!("{} {message}", self.prefix()));
            }
            "on-break" => {
                // on-break <alvo> off (a forma com bloco é outro comando).
                let target = rest.strip_suffix("off").map(str::trim).filter(|target| !target.is_empty()).ok_or_else(|| self.error(line, &shown, "uso: on-break <breakpoint> { ... } | on-break <breakpoint> off"))?;
                let before = self.handlers.len();
                self.handlers.retain(|handler| !handler.target.eq_ignore_ascii_case(target));
                let message = if self.handlers.len() == before { format!("nenhum tratador para {target}") } else { format!("tratador de {target} removido") };
                self.emit(&format!("{}   {message}", self.prefix()));
            }
            "stop" => {
                if self.in_handler.is_none() {
                    return Err(self.error(line, &shown, "stop so vale dentro de um on-break"));
                }
                return Ok(Flow::Stop);
            }
            "exit" => {
                self.emit(&format!("{} fim do roteiro (exit na linha {line})", self.prefix()));
                return Ok(Flow::Exit);
            }
            "fail" => return Err(self.error(line, &shown, if rest.is_empty() { "fail" } else { rest })),
            _ => {
                let answered = match self.host.as_deref_mut() {
                    Some(host) => host.intercept(self.client, word, &text),
                    None => None,
                };
                let output = match answered {
                    Some(result) => result,
                    None => self.client.execute(&text),
                }
                .map_err(|error| self.error(line, &shown, &error))?;
                match word {
                    "detach" => self.detached = true,
                    "attach" => self.detached = false,
                    _ => {}
                }
                self.record_output(line, &text, output);
            }
        }
        Ok(Flow::Normal)
    }

    /// Os `save-*`: uma variável tirada da saída do comando anterior.
    fn save_from_output(&mut self, line: usize, shown: &str, word: &str, rest: &str) -> Result<(), String> {
        let parts = words(rest);
        let occurrence = |index: usize| match parts.get(index) {
            None => Some(1),
            Some(text) => text.parse::<usize>().ok().filter(|&value| value >= 1),
        };
        let usage = match word {
            "save-word" | "save-text" => format!("uso: {word} <nome> <texto> <coluna> [ocorrencia]"),
            "save-after" => "uso: save-after <nome> <rotulo> [ocorrencia]".to_string(),
            "save-line" => "uso: save-line <nome> <texto> [ocorrencia]".to_string(),
            "save-count" => "uso: save-count <nome> <texto>".to_string(),
            _ => "uso: save-thread <nome> <texto> <coluna> <modulo>".to_string(),
        };
        let (Some(name), Some(needle)) = (parts.first().cloned(), parts.get(1).cloned()) else {
            return Err(self.error(line, shown, &usage));
        };
        if !is_identifier(&name) {
            return Err(self.error(line, shown, &format!("nome de variavel invalido {name:?}")));
        }
        match word {
            "save-word" | "save-text" => {
                let (Some(column), Some(occurrence)) = (parts.get(2).and_then(|text| text.parse::<i64>().ok()), occurrence(3)) else {
                    return Err(self.error(line, shown, &usage));
                };
                let found = lines_with(&self.last_output, &needle).into_iter().nth(occurrence - 1).and_then(|text| pick_word(text, column)).map(str::to_string);
                match found {
                    Some(value) if word == "save-text" || parse_number(&value).is_some() => self.save_value(&name, &value),
                    _ => {
                        let kind = if word == "save-word" { "numero" } else { "palavra" };
                        return Err(self.error(line, shown, &format!("nenhuma linha {occurrence} com {needle:?} e {kind} na coluna {column}{}", self.output_report())));
                    }
                }
            }
            "save-after" => {
                let Some(occurrence) = occurrence(2) else { return Err(self.error(line, shown, &usage)) };
                // A palavra seguinte na mesma linha do rótulo.
                let found = self.last_output.match_indices(needle.as_str()).nth(occurrence - 1).and_then(|(position, _)| self.last_output[position + needle.len()..].lines().next().and_then(|rest| rest.split_whitespace().next())).map(|value| value.trim_end_matches([',', ';', ')']).to_string());
                match found {
                    Some(value) if !value.is_empty() => self.save_value(&name, &value),
                    _ => return Err(self.error(line, shown, &format!("nenhuma palavra depois de {needle:?} na mesma linha (ocorrencia {occurrence}){}", self.output_report()))),
                }
            }
            "save-line" => {
                let Some(occurrence) = occurrence(2) else { return Err(self.error(line, shown, &usage)) };
                let found = lines_with(&self.last_output, &needle).into_iter().nth(occurrence - 1).map(|text| text.trim().to_string());
                match found {
                    Some(value) => {
                        self.set_text(&name, &value);
                        self.emit(&format!("{}   ${{{name}}} = {value}", self.prefix()));
                    }
                    None => return Err(self.error(line, shown, &format!("nenhuma linha {occurrence} com {needle:?}{}", self.output_report()))),
                }
            }
            "save-count" => {
                let count = self.last_output.lines().filter(|text| text.contains(needle.as_str())).count() as u64;
                self.set_number(&name, count);
                self.emit(&format!("{}   ${name} = {count:#x} ({count} linhas)", self.prefix()));
            }
            _ => {
                // save-thread: das linhas com o texto (o ETHREAD na coluna), a
                // primeira thread com um quadro do módulo na pilha; não
                // depende da ordem da lista.
                let (Some(column), Some(module)) = (parts.get(2).and_then(|text| text.parse::<i64>().ok()), parts.get(3).cloned()) else {
                    return Err(self.error(line, shown, &usage));
                };
                let candidates: Vec<u64> = lines_with(&self.last_output, &needle).into_iter().filter_map(|text| pick_word(text, column)).filter_map(parse_number).collect();
                let mut chosen = None;
                for thread in candidates {
                    if self.thread_in_module(thread, &module) {
                        chosen = Some(thread);
                        break;
                    }
                }
                let Some(value) = chosen else {
                    return Err(self.error(line, shown, &format!("nenhuma thread das linhas com {needle:?} tem quadro no modulo {module}{}", self.output_report())));
                };
                self.set_number(&name, value);
                self.emit(&format!("{}   ${name} = {value:#x}", self.prefix()));
            }
        }
        Ok(())
    }

    /// Uma condição: `Some(valor)`, ou `None` quando um tratador rodado
    /// durante uma espera pediu `exit`.
    fn condition(&mut self, line: usize, shown: &str, raw: &str) -> Result<Option<bool>, String> {
        let text = substitute(&self.variables, raw).map_err(|error| self.error(line, shown, &error))?;
        let mut rest = text.trim();
        let mut negate = false;
        while let Some(inner) = rest.strip_prefix("not ") {
            negate = !negate;
            rest = inner.trim_start();
        }
        let (word, argument) = rest.split_once(char::is_whitespace).map_or((rest, ""), |(word, argument)| (word, argument.trim()));
        let value = match word {
            "output-has" => self.last_output.contains(unquote(argument)),
            "console-has" => {
                self.client.collect_console();
                self.client.console().contains(unquote(argument))
            }
            "serial-has" => {
                let serial = self.serial_buffer().ok_or_else(|| self.error(line, shown, "sem o log da COM1 neste modo"))?;
                let found = serial_text(&serial).contains(unquote(argument));
                found
            }
            "stop-has" => self.client.last_stop().contains(unquote(argument)),
            "stack-has" => {
                let (thread, module) = split_two(argument).ok_or_else(|| self.error(line, shown, "uso: stack-has <ethread> <modulo>"))?;
                let thread = self.client.evaluate(thread).map_err(|error| self.error(line, shown, &error))?;
                self.thread_in_module(thread, unquote(module))
            }
            "defined" => self.variables.contains_key(argument.trim_start_matches('$')),
            "running" if argument.is_empty() => !self.client.is_stopped(),
            "stopped" if argument.is_empty() => self.client.is_stopped(),
            "wait-serial" => {
                let (timeout, needle) = self.wait_arguments(argument).map_err(|error| self.error(line, shown, &error))?;
                match self.wait_serial(line, shown, needle, timeout)? {
                    SerialWait::Found => true,
                    SerialWait::Timeout | SerialWait::Stopped(_) => false,
                    SerialWait::Exit => return Ok(None),
                }
            }
            "wait-stop" => {
                let milliseconds = self.milliseconds(argument, STOP_WAIT_MS).map_err(|error| self.error(line, shown, &format!("uso: wait-stop [ms]: {error}")))?;
                match self.wait_stop(line, shown, Duration::from_millis(milliseconds))? {
                    StopWait::Stopped(stop) => {
                        self.record_output(line, rest, stop);
                        true
                    }
                    StopWait::Timeout => false,
                    StopWait::Exit => return Ok(None),
                }
            }
            _ => match compare_text(rest) {
                Some(result) => result,
                None => self.client.evaluate(rest).map_err(|error| self.error(line, shown, &error))? != 0,
            },
        };
        Ok(Some(value != negate))
    }

    /// Os itens de uma coleção, já com os filtros (menos o `stack`, que
    /// custa uma pilha por thread e fica para a volta).
    fn collect(&mut self, collection: Collection, filters: &[(String, String)]) -> Result<Vec<Item>, String> {
        let filter = |key: &str| filters.iter().find(|(name, _)| name == key).map(|(_, value)| value.as_str());
        let name = filter("name");
        let wanted = |value: &str| name.map_or(true, |name| name_matches(name, value));
        Ok(match collection {
            Collection::Thread => {
                let pid = match filter("pid") {
                    Some(text) => Some(self.client.evaluate(text)?),
                    None => None,
                };
                let (state, process) = (filter("state"), filter("process"));
                self.client
                    .threads(pid)?
                    .into_iter()
                    .filter(|thread| state.map_or(true, |state| thread.state.eq_ignore_ascii_case(state)))
                    .filter(|thread| process.map_or(true, |process| name_matches(process, &thread.process)))
                    .map(|thread| vec![("", Field::Number(thread.ethread)), ("tid", Field::Number(thread.tid)), ("pid", Field::Number(thread.pid)), ("start", Field::Number(thread.start)), ("state", Field::Text(thread.state)), ("process", Field::Text(thread.process))])
                    .collect()
            }
            Collection::Process => self
                .client
                .processes()?
                .into_iter()
                .filter(|process| wanted(&process.name))
                .map(|process| vec![("", Field::Number(process.eprocess)), ("pid", Field::Number(process.pid)), ("cr3", Field::Number(process.cr3)), ("threads", Field::Number(process.threads)), ("name", Field::Text(process.name))])
                .collect(),
            Collection::Module => self
                .client
                .loaded_modules()?
                .into_iter()
                .filter(|module| wanted(&module.name))
                .map(|module| vec![("", Field::Number(module.base)), ("end", Field::Number(module.end)), ("size", Field::Number(module.end.saturating_sub(module.base))), ("name", Field::Text(module.name)), ("path", Field::Text(module.path))])
                .collect(),
            Collection::UserModule => self
                .client
                .user_modules()?
                .into_iter()
                .filter(|module| wanted(&module.name))
                .map(|module| vec![("", Field::Number(module.base)), ("end", Field::Number(module.base.saturating_add(module.size))), ("size", Field::Number(module.size)), ("entry", Field::Number(module.entry)), ("name", Field::Text(module.name)), ("path", Field::Text(module.path))])
                .collect(),
            Collection::Cpu => self
                .client
                .processors()?
                .into_iter()
                .map(|cpu| vec![("", Field::Number(cpu.number)), ("irql", Field::Number(cpu.irql)), ("pcr", Field::Number(cpu.pcr)), ("thread", Field::Number(cpu.thread)), ("rip", Field::Number(cpu.rip)), ("owner", Field::Number(u64::from(cpu.owner))), ("process", Field::Text(cpu.process))])
                .collect(),
            Collection::Line => {
                let containing = filter("containing");
                self.last_output
                    .lines()
                    .enumerate()
                    .filter(|(_, text)| containing.map_or(true, |needle| text.contains(needle)))
                    .map(|(index, text)| vec![("", Field::Text(text.trim().to_string())), ("index", Field::Number(index as u64))])
                    .collect()
            }
        })
    }

    /// As variáveis de um item; devolve o rótulo da volta.
    fn bind(&mut self, variable: &str, item: Item) -> String {
        let mut label = String::new();
        let mut texts = Vec::new();
        for (suffix, field) in item {
            let name = if suffix.is_empty() { variable.to_string() } else { format!("{variable}_{suffix}") };
            match field {
                Field::Number(value) => {
                    if suffix.is_empty() {
                        label = format!("${name} = {value:#x}");
                    }
                    self.set_number(&name, value);
                }
                Field::Text(text) => {
                    if suffix.is_empty() {
                        label = format!("${{{name}}} = {text}");
                    } else if !text.is_empty() {
                        texts.push(text.clone());
                    }
                    self.set_text(&name, &text);
                }
            }
        }
        if !texts.is_empty() {
            label.push_str(&format!(" ({})", texts.join(", ")));
        }
        label
    }

    fn for_each(&mut self, node: &Node, collection: Collection, variable: &str, filters: &[(String, String)], body: &[Node]) -> Result<Flow, String> {
        let mut values = Vec::new();
        for (key, value) in filters {
            let value = substitute(&self.variables, value).map_err(|error| self.error(node.line, &node.text, &error))?;
            values.push((key.clone(), value));
        }
        let items = self.collect(collection, &values).map_err(|error| self.error(node.line, &node.text, &error))?;
        let stack = values.iter().find(|(key, _)| key == "stack").map(|(_, value)| value.clone()).filter(|_| collection == Collection::Thread);
        let total = items.len();
        let note = if stack.is_some() { " (o filtro stack vale em cada volta)" } else { "" };
        self.emit(&format!("{} > {}: {total} itens{note}", self.prefix(), node.text.trim_end_matches('{').trim()));
        let mut turns = 0u64;
        let mut flow = Flow::Normal;
        for (index, item) in items.into_iter().enumerate() {
            if let Some(module) = &stack {
                let thread = match item.first() {
                    Some((_, Field::Number(thread))) => *thread,
                    _ => 0,
                };
                if !self.thread_in_module(thread, module) {
                    continue;
                }
            }
            turns += 1;
            let label = self.bind(variable, item);
            self.emit(&format!("{} -- {label} ({} de {total})", self.prefix(), index + 1));
            self.context.push(format!("for-each da linha {} ({label})", node.line));
            let result = self.run_block(body);
            self.context.pop();
            match result? {
                Flow::Leave => break,
                Flow::Normal | Flow::Next => {}
                other => {
                    flow = other;
                    break;
                }
            }
        }
        self.set_number(&format!("{variable}_count"), turns);
        Ok(flow)
    }

    /// O tratador de uma parada pelo número do breakpoint: `*` (qualquer
    /// breakpoint), `#n`, ou a expressão do breakpoint (como foi pedida ou
    /// pelo endereço).
    fn find_handler(&mut self, id: u32) -> Option<usize> {
        let breakpoint = self.client.breakpoints().iter().find(|breakpoint| breakpoint.id == id).cloned();
        for index in 0..self.handlers.len() {
            let target = self.handlers[index].target.clone();
            let matched = if target == "*" {
                true
            } else if let Some(number) = target.strip_prefix('#') {
                parse_number(number) == Some(u64::from(id))
            } else if let Some(breakpoint) = &breakpoint {
                breakpoint.expression.trim().eq_ignore_ascii_case(target.trim()) || (!breakpoint.pending && breakpoint.address != 0 && self.client.evaluate(&target).ok() == Some(breakpoint.address))
            } else {
                false
            };
            if matched {
                return Some(index);
            }
        }
        None
    }

    /// Uma parada que chegou numa espera: os comandos `/cmd` do breakpoint
    /// e o tratador dele. Sem tratador (ou dentro de um), a máquina fica
    /// parada; depois de um tratador ela segue, a não ser que ele tenha dito
    /// `stop`.
    fn dispatch(&mut self, line: usize, shown: &str, stop: &str) -> Result<Handled, String> {
        // O anfitrião primeiro (o opennt-mcp arma os breakpoints adiados de
        // usuário no aviso de carga da DLL).
        let serviced = match self.host.as_deref_mut() {
            Some(host) => host.service_stop(self.client),
            None => false,
        };
        if serviced {
            if self.client.is_stopped() && !self.detached {
                self.client.go().map_err(|error| self.error(line, shown, &format!("a maquina nao seguiu depois da parada atendida: {error}")))?;
            }
            return Ok(Handled::Resumed);
        }
        if self.in_handler.is_some() {
            return Ok(Handled::Stopped);
        }
        if let Some((id, commands)) = self.client.stop_commands() {
            for command in commands.split(';').map(str::trim).filter(|command| !command.is_empty()) {
                let output = match self.client.execute(command) {
                    Ok(text) => text,
                    Err(error) => format!("erro: {error}"),
                };
                let prefix = self.prefix();
                self.emit(&format!("{prefix} [bp #{id}] > {command}"));
                for text in output.lines() {
                    self.emit(&format!("{prefix}   {text}"));
                }
            }
            self.flush_log();
            if !self.client.is_stopped() {
                return Ok(Handled::Resumed);
            }
        }
        let Some(id) = stop_breakpoint_id(stop) else { return Ok(Handled::Stopped) };
        let Some(index) = self.find_handler(id) else { return Ok(Handled::Stopped) };
        let target = self.handlers[index].target.clone();
        let line = self.handlers[index].line;
        let body = self.handlers[index].body.clone();
        let hits = self.client.breakpoints().iter().find(|breakpoint| breakpoint.id == id).map_or(0, |breakpoint| breakpoint.hits);
        self.emit(&format!("{} > on-break {target} (linha {line}): {stop}", self.prefix()));
        self.set_number("bp", u64::from(id));
        self.set_number("hits", hits);
        self.in_handler = Some(id);
        self.context.push(format!("on-break {target} da linha {line} (breakpoint #{id}, acerto {hits})"));
        let result = self.run_block(&body);
        self.context.pop();
        self.in_handler = None;
        match result? {
            Flow::Stop => Ok(Handled::Stopped),
            Flow::Exit => Ok(Handled::Exit),
            _ => {
                if self.client.is_stopped() && !self.detached {
                    self.client.go().map_err(|error| self.error(line, &format!("on-break {target}"), &format!("a maquina nao seguiu depois do tratador: {error}")))?;
                }
                Ok(Handled::Resumed)
            }
        }
    }

    /// `wait-stop`: a próxima parada que nenhum tratador fez seguir.
    fn wait_stop(&mut self, line: usize, shown: &str, timeout: Duration) -> Result<StopWait, String> {
        if self.client.is_stopped() {
            return Ok(StopWait::Stopped(format!("{} (a maquina ja estava parada)", self.client.last_stop())));
        }
        let deadline = self.cap(Instant::now() + timeout);
        loop {
            if self.cancelled() {
                return Err(self.error(line, shown, "parado pelo usuario (Cancelar)"));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(StopWait::Timeout);
            }
            let stop = self.poll(line, shown, remaining.min(POLL))?;
            self.flush_log();
            self.tick();
            let Some(stop) = stop else { continue };
            match self.dispatch(line, shown, &stop)? {
                Handled::Resumed => {}
                Handled::Stopped => return Ok(StopWait::Stopped(self.client.last_stop().to_string())),
                Handled::Exit => return Ok(StopWait::Exit),
            }
        }
    }

    /// `wait-serial`: o texto em qualquer ponto do log da COM1 (a ordem
    /// entre as tarefas do kernel não importa), atendendo as paradas.
    fn wait_serial(&mut self, line: usize, shown: &str, needle: &str, timeout: Duration) -> Result<SerialWait, String> {
        if needle.is_empty() {
            return Err(self.error(line, shown, "falta o texto que a COM1 deve mostrar"));
        }
        let serial = self.serial_buffer().ok_or_else(|| self.error(line, shown, "sem o log da COM1 neste modo (o test-boot passa a COM1 ao roteiro; o --connect nao)"))?;
        let deadline = self.cap(Instant::now() + timeout);
        let mut stopped_since: Option<Instant> = None;
        loop {
            // O log do anfitrião é lido de novo a cada volta.
            self.serial_buffer();
            if serial_text(&serial).contains(needle) {
                return Ok(SerialWait::Found);
            }
            if self.cancelled() {
                return Err(self.error(line, shown, "parado pelo usuario (Cancelar)"));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(SerialWait::Timeout);
            }
            let slice = remaining.min(POLL);
            if self.detached {
                std::thread::sleep(slice);
                self.tick();
                continue;
            }
            if self.client.is_stopped() {
                let since = *stopped_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= STOPPED_GRACE {
                    return Ok(SerialWait::Stopped(self.client.last_stop().to_string()));
                }
                std::thread::sleep(slice);
                self.tick();
                continue;
            }
            stopped_since = None;
            let stop = self.poll(line, shown, slice)?;
            self.flush_log();
            self.tick();
            let Some(stop) = stop else { continue };
            match self.dispatch(line, shown, &stop)? {
                Handled::Resumed => {}
                Handled::Stopped => return Ok(SerialWait::Stopped(self.client.last_stop().to_string())),
                Handled::Exit => return Ok(SerialWait::Exit),
            }
        }
    }

    /// `sleep`: o tempo passa com as paradas atendidas; uma parada sem
    /// tratador deixa a máquina parada até o fim do tempo.
    fn sleep(&mut self, line: usize, shown: &str, duration: Duration) -> Result<Flow, String> {
        // O prazo do anfitrião encurta o sleep sem erro; o comando seguinte
        // é que não começa.
        let deadline = self.cap(Instant::now() + duration);
        loop {
            if self.cancelled() {
                return Err(self.error(line, shown, "parado pelo usuario (Cancelar)"));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(Flow::Normal);
            }
            let slice = remaining.min(POLL);
            if self.detached || self.client.is_stopped() {
                std::thread::sleep(slice);
                self.tick();
                continue;
            }
            let stop = self.poll(line, shown, slice)?;
            self.flush_log();
            self.tick();
            let Some(stop) = stop else { continue };
            match self.dispatch(line, shown, &stop)? {
                Handled::Resumed => {}
                Handled::Stopped => {
                    let prefix = self.prefix();
                    let stop = self.client.last_stop().to_string();
                    self.emit(&format!("{prefix}   {stop}"));
                }
                Handled::Exit => return Ok(Flow::Exit),
            }
        }
    }
}

impl Client {
    /// Roda um roteiro; a primeira conferência que falha encerra.
    pub fn run_script(&mut self, script: &str) -> Result<(), String> {
        self.run_script_with(script, &ScriptOptions::default())
    }

    /// Roda um roteiro com nome e transcrição.
    pub fn run_script_with(&mut self, script: &str, options: &ScriptOptions) -> Result<(), String> {
        self.run_script_inner(script, options, None).result
    }

    /// Roda um roteiro por um anfitrião (a janela do opennt-dbg, o servidor
    /// do opennt-mcp): as linhas vão para ele, e o resultado diz a linha que
    /// falhou, quantos comandos rodaram e as variáveis definidas.
    pub fn run_script_hosted(&mut self, script: &str, options: &ScriptOptions, host: &mut dyn ScriptHost) -> ScriptOutcome {
        self.run_script_inner(script, options, Some(host))
    }

    fn run_script_inner(&mut self, script: &str, options: &ScriptOptions, host: Option<&mut dyn ScriptHost>) -> ScriptOutcome {
        let mut runner = Runner::new(self, options, host);
        let result = match parse(script) {
            Ok(nodes) => runner.run_block(&nodes).map(|_| ()),
            Err((line, message)) => {
                let text = script.lines().nth(line.saturating_sub(1)).unwrap_or("").trim().to_string();
                Err(runner.error(line, &text, &message))
            }
        };
        runner.flush_log();
        if let Err(error) = &result {
            // Na saída padrão o erro sai pelo test-boot; aqui fica na
            // transcrição.
            runner.note(&format!("[kd-script] FALHOU: {error}"));
        }
        let failed_line = if result.is_err() { runner.failed_line.get() } else { None };
        let variables = runner.assigned.iter().filter_map(|name| runner.variables.get(name).map(|value| (name.clone(), value.clone()))).collect();
        ScriptOutcome { result, failed_line, commands: runner.commands, variables }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(nodes: &[Node]) -> Vec<String> {
        nodes
            .iter()
            .map(|node| match &node.statement {
                Statement::Command(text) => format!("cmd {text}"),
                Statement::If { branches, otherwise } => format!("if {} ramos, else {}", branches.len(), otherwise.len()),
                Statement::While { condition, body } => format!("while {condition} ({})", body.len()),
                Statement::Repeat { count, variable, body } => format!("repeat {count} {variable:?} ({})", body.len()),
                Statement::ForEach { collection, variable, filters, body } => format!("for-each {collection:?} {variable} {filters:?} ({})", body.len()),
                Statement::OnBreak { target, body } => format!("on-break {target} ({})", body.len()),
                Statement::Leave => "leave".into(),
                Statement::Next => "next".into(),
            })
            .collect()
    }

    #[test]
    fn parses_blocks_and_keeps_plain_commands() {
        let script = "# comentario\nbp x /log \"rax={@rax}\"\nif output-has ok {\n  echo a\n} else if $n == 2 {\n  echo b\n} else {\n  echo c\n}\nfor-each thread t state Waiting stack ACPI {\n  if 1 {\n    leave\n  }\n  next\n}\nrepeat 3 i {\n  echo ${i}\n}\nwhile not serial-has X {\n  sleep 100\n}\non-break kernel::f {\n  stop\n}\non-break kernel::f off\ncontinue\nbreak\n";
        let nodes = parse(script).unwrap();
        assert_eq!(
            kinds(&nodes),
            vec![
                "cmd bp x /log \"rax={@rax}\"".to_string(),
                "if 2 ramos, else 1".into(),
                "for-each Thread t [(\"state\", \"Waiting\"), (\"stack\", \"ACPI\")] (2)".into(),
                "repeat 3 Some(\"i\") (1)".into(),
                "while not serial-has X (1)".into(),
                "on-break kernel::f (1)".into(),
                "cmd on-break kernel::f off".into(),
                "cmd continue".into(),
                "cmd break".into(),
            ]
        );
        assert_eq!(nodes[1].line, 3);
        let Statement::If { branches, .. } = &nodes[1].statement else { panic!() };
        assert_eq!((branches[1].0, branches[1].1.as_str()), (5, "$n == 2"));
        let repeat = parse("repeat 2 * 3 {\n}\n").unwrap();
        let Statement::Repeat { count, variable, .. } = &repeat[0].statement else { panic!() };
        assert_eq!((count.as_str(), variable), ("2 * 3", &None));
    }

    #[test]
    fn syntax_errors_carry_the_line() {
        assert_eq!(parse("echo a\nif 1 {\necho b\n").unwrap_err().0, 2);
        assert!(parse("if 1 {\n").unwrap_err().1.contains("sem }"));
        assert_eq!(parse("echo a\n}\n").unwrap_err(), (2, "} sem bloco aberto".to_string()));
        assert_eq!(parse("leave\n").unwrap_err().0, 1);
        assert!(parse("while 1 {\n} else {\n}\n").unwrap_err().1.contains("else fora de um if"));
        assert!(parse("if 1\necho\n").unwrap_err().1.contains("falta o {"));
        assert!(parse("for-each galaxia g {\n}\n").unwrap_err().1.contains("colecao desconhecida"));
        assert!(parse("for-each process p state x {\n}\n").unwrap_err().1.contains("filtro desconhecido"));
        assert!(parse("for-each process p name {\n}\n").unwrap_err().1.contains("filtro sem valor"));
        // O tratador não está dentro do laço que o registrou.
        assert!(parse("repeat 2 {\n  on-break x {\n    leave\n  }\n}\n").unwrap_err().1.contains("fora de um laco"));
        assert!(parse("if 1 {\n} elsewhere {\n").unwrap_err().1.contains("depois do }"));
    }

    #[test]
    fn words_quotes_and_columns() {
        assert_eq!(words("nome \"wait reason\" 3"), vec!["nome", "wait reason", "3"]);
        assert_eq!(words("  a  \"\"  b "), vec!["a", "", "b"]);
        assert_eq!(unquote("\"x y\""), "x y");
        assert_eq!(unquote("x y"), "x y");
        assert_eq!(pick_word("4 0xffff 0x1ab000 12 System", 1), Some("0xffff"));
        assert_eq!(pick_word("4 0xffff 0x1ab000 12 System", -1), Some("System"));
        assert_eq!(pick_word("a b", 2), None);
        assert_eq!(pick_word("a b", -3), None);
        assert!(is_identifier("t_tid") && is_identifier("_x1") && !is_identifier("1x") && !is_identifier("a-b") && !is_identifier(""));
    }

    #[test]
    fn finds_lines_ignoring_case_only_without_exact() {
        // O `lmu` do kd_domain1: a PEB guarda `msv1_0.DLL`.
        let output = "0x1e90000 0x1f1c000 msv1_0.DLL   19 simbolos\n0x140000000 0x140012000 lsass.exe   4 simbolos\n";
        assert_eq!(lines_with(output, "msv1_0.dll"), vec!["0x1e90000 0x1f1c000 msv1_0.DLL   19 simbolos"]);
        assert_eq!(lines_with(output, "lsass.exe").len(), 1);
        // Com uma linha exata, as outras formas ficam de fora.
        let output = "a Foo 1\na foo 2\n";
        assert_eq!(lines_with(output, "foo"), vec!["a foo 2"]);
        assert!(lines_with(output, "bar").is_empty());
    }

    #[test]
    fn substitutes_text_variables() {
        let mut variables = HashMap::new();
        variables.insert("p".to_string(), "0x64".to_string());
        variables.insert("linha".to_string(), "#0 ligado software 0x10".to_string());
        assert_eq!(substitute(&variables, "handles ${p} 2").unwrap(), "handles 0x64 2");
        assert_eq!(substitute(&variables, "${linha.0}|${linha.-1}").unwrap(), "#0|0x10");
        // O `{expr}` do /log e o `$nome` das expressões ficam.
        assert_eq!(substitute(&variables, "bp x /log \"{@rax} {$p}\"").unwrap(), "bp x /log \"{@rax} {$p}\"");
        assert!(substitute(&variables, "${nada}").unwrap_err().contains("nao definida"));
        assert!(substitute(&variables, "${linha.9}").unwrap_err().contains("palavra 9"));
        assert!(substitute(&variables, "${p").is_err());
    }

    #[test]
    fn breakpoint_number_from_the_stop_text() {
        assert_eq!(stop_breakpoint_id("parado: SIGTRAP swbreak (CPU 0) em 0x10 f (breakpoint #8, acerto 1) [T05thread:1;swbreak:;]"), Some(8));
        assert_eq!(stop_breakpoint_id("parado: ... (breakpoint #0 laco, condicao verdadeira, acerto 3) (breakpoint de uma vez so removido) [..]"), Some(0));
        assert_eq!(stop_breakpoint_id("parado: ... (modulo carregado: novo.sys em 0xfffff80043010000, breakpoint #12) [..]"), Some(12));
        assert_eq!(stop_breakpoint_id("parado: ... (evento #3: processo criado smss.exe) [..]"), Some(3));
        assert_eq!(stop_breakpoint_id("parado: SIGINT (CPU 0) em 0x10 kernel::ntos::ke::run_kernel_tasks [T02thread:1;]"), None);
    }

    #[test]
    fn text_comparisons_and_wait_options() {
        assert_eq!(compare_text("\"smss.exe\" == \"smss.exe\""), Some(true));
        assert_eq!(compare_text("\"a\" != \"a\""), Some(false));
        assert_eq!(compare_text("\"winlogon.exe\" contains \"logon\""), Some(true));
        assert_eq!(compare_text("$x == 1"), None);
        assert_eq!(compare_text("\"a\" == \"b\" lixo"), None);
        assert_eq!(wait_options("/t 5000 [shell] pronto"), (Some("5000"), "[shell] pronto"));
        assert_eq!(wait_options("criou dwm.exe"), (None, "criou dwm.exe"));
        assert_eq!(wait_options("/t 0x10 \"a b\""), (Some("0x10"), "a b"));
        assert_eq!(wait_options("/t $espera x"), (Some("$espera"), "x"));
        assert_eq!(wait_options("/texto"), (None, "/texto"));
        assert!(name_matches("smss", "smss.exe") && name_matches("ACPI", "acpi.sys") && name_matches("System", "System"));
        assert!(!name_matches("System", "SystemSettings.exe"));
    }

    #[test]
    fn quoted_output_in_errors() {
        assert_eq!(quote_lines("", 3, false), " (vazia)");
        assert_eq!(quote_lines("a\nb", 3, false), "\n  | a\n  | b");
        assert_eq!(quote_lines("a\nb\nc\nd", 2, false), "\n  | a\n  | b\n  | (mais 2 linhas)");
        assert_eq!(quote_lines("a\nb\nc\nd", 2, true), "\n  | (2 linhas antes)\n  | c\n  | d");
    }
}
