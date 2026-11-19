//! Os roteiros do depurador (os de `cargo xtask test-boot --kd=com2
//! --script=ARQ`) pela sessão do servidor. A linguagem é a do
//! `Client::run_script`: uma linha por comando de texto do depurador, `#`
//! comenta, e `expect`, `expect-stop`, `expect-console`, `expect-eq`,
//! `save`, `save-word`, `save-thread`, `wait-serial`, `echo` e `sleep`.
//!
//! Diferenças, pelo uso dentro do servidor:
//! - a saída vai para o log da resposta, nunca para a saída padrão (no
//!   stdio ela é o canal do MCP);
//! - as esperas respeitam o prazo da ferramenta;
//! - `wait-serial`, `wait-stop` e `sleep` atendem as paradas enquanto
//!   esperam: um breakpoint de log registra e segue, um adiado de usuário é
//!   armado quando a DLL carrega, e uma parada de verdade encerra o
//!   `wait-serial` com erro (o texto não viria mais);
//! - os comandos de parada de um breakpoint (`/cmd`) rodam no `wait-stop`;
//! - `$nome` é trocado pelo valor salvo no texto da linha antes de ela ir
//!   ao depurador (o `.process $dw`, o `/log "{poi($x)}"`);
//! - `attach` não faz nada (a sessão já existe) e `detach`/`quit` são
//!   recusados (a ferramenta `detach` desliga).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use kd_client::Client;

use crate::serial::Watch;
use crate::session::Session;

/// Linhas guardadas no log de um roteiro no máximo.
const MAX_LOG: usize = 20_000;

/// O que o roteiro recebe do servidor.
pub struct Options {
    /// O log da COM1 (o `wait-serial`).
    pub serial: Option<PathBuf>,
    /// O fim do prazo da ferramenta.
    pub deadline: Instant,
}

/// O resultado de um roteiro.
#[derive(Debug, Default)]
pub struct Report {
    pub ok: bool,
    pub error: Option<String>,
    /// A linha (do arquivo, a partir de 1) que falhou.
    pub failed_line: Option<usize>,
    /// Comandos executados (sem os comentários e linhas vazias).
    pub commands: usize,
    pub log: Vec<String>,
    /// Linhas que não couberam no log.
    pub dropped: usize,
    pub variables: BTreeMap<String, u64>,
}

/// Divide no primeiro espaço fora de colchetes e parênteses.
pub fn split_two(text: &str) -> Option<(&str, &str)> {
    let mut depth = 0i32;
    for (index, character) in text.char_indices() {
        match character {
            '[' | '(' => depth += 1,
            ']' | ')' => depth -= 1,
            ' ' if depth == 0 => return Some((&text[..index], text[index + 1..].trim())),
            _ => {}
        }
    }
    None
}

/// Troca `$nome` pelo valor salvo (`0x...`); o `$` depois de `!` é parte
/// de um símbolo (`ksecdd!$entry`) e fica.
pub fn substitute(text: &str, variables: &BTreeMap<String, u64>) -> String {
    if variables.is_empty() || !text.contains('$') {
        return text.to_string();
    }
    let characters: Vec<char> = text.chars().collect();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        if character == '$' && (index == 0 || characters[index - 1] != '!') {
            let mut end = index + 1;
            while end < characters.len() && (characters[end].is_ascii_alphanumeric() || characters[end] == '_') {
                end += 1;
            }
            let name: String = characters[index + 1..end].iter().collect();
            if let Some(value) = variables.get(&name) {
                output.push_str(&format!("{value:#x}"));
                index = end;
                continue;
            }
        }
        output.push(character);
        index += 1;
    }
    output
}

/// `save-word <nome> <texto> <coluna> [ocorrência]`: o número na coluna da
/// N-ésima linha da saída anterior que contém o texto.
pub fn save_word(output: &str, rest: &str) -> Result<(String, u64), String> {
    let usage = "uso: save-word <nome> <texto> <coluna> [ocorrencia]";
    let mut parts = rest.split_whitespace();
    let (Some(name), Some(needle), Some(column)) = (parts.next(), parts.next(), parts.next().and_then(|text| text.parse::<usize>().ok())) else { return Err(usage.into()) };
    let occurrence = match parts.next() {
        Some(text) => text.parse::<usize>().ok().filter(|value| *value >= 1).ok_or(usage)?,
        None => 1,
    };
    let value = output
        .lines()
        .filter(|line| line.contains(needle))
        .nth(occurrence - 1)
        .and_then(|line| line.split_whitespace().nth(column))
        .and_then(kd_client::parse_number)
        .ok_or_else(|| format!("nenhuma linha {occurrence} com {needle:?} e numero na coluna {column}"))?;
    Ok((name.to_string(), value))
}

/// Uma parada encurtada (sem o pacote do protocolo).
fn short_stop(text: &str) -> &str {
    text.split(" [").next().unwrap_or(text)
}

/// Roda o roteiro; a primeira linha que falha encerra.
pub fn run(client: &mut Client, session: &mut Session, script: &str, options: &Options) -> Report {
    let mut runner = Runner { client, session, options, variables: BTreeMap::new(), log: Vec::new(), dropped: 0, last_output: String::new() };
    let mut commands = 0;
    for (number, raw) in script.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        commands += 1;
        runner.push(format!("> {line}"));
        if Instant::now() >= runner.options.deadline {
            let error = "prazo da ferramenta esgotado antes desta linha".to_string();
            runner.push(format!("  erro: {error}"));
            return runner.report(false, Some(format!("linha {}: {line}: {error}", number + 1)), Some(number + 1), commands);
        }
        if let Err(error) = runner.line(line) {
            runner.push(format!("  erro: {error}"));
            return runner.report(false, Some(format!("linha {}: {line}: {error}", number + 1)), Some(number + 1), commands);
        }
    }
    runner.report(true, None, None, commands)
}

struct Runner<'a> {
    client: &'a mut Client,
    session: &'a mut Session,
    options: &'a Options,
    variables: BTreeMap<String, u64>,
    log: Vec<String>,
    dropped: usize,
    last_output: String,
}

impl Runner<'_> {
    fn report(self, ok: bool, error: Option<String>, failed_line: Option<usize>, commands: usize) -> Report {
        Report { ok, error, failed_line, commands, log: self.log, dropped: self.dropped, variables: self.variables }
    }

    fn push(&mut self, line: String) {
        if self.log.len() < MAX_LOG {
            self.log.push(line);
        } else {
            self.dropped += 1;
        }
    }

    /// Uma nota no log (não muda a saída anterior das conferências).
    fn note(&mut self, text: &str) {
        for line in text.lines() {
            self.push(format!("  {line}"));
        }
    }

    /// A saída de um comando: vai para o log e vira a saída anterior.
    fn output(&mut self, text: String) {
        for line in text.trim_end().lines() {
            self.push(format!("  {line}"));
        }
        self.last_output = text;
    }

    fn evaluate(&mut self, expression: &str) -> Result<u64, String> {
        let text = substitute(expression, &self.variables);
        self.client.evaluate(&text)
    }

    fn remaining(&self) -> Duration {
        self.options.deadline.saturating_duration_since(Instant::now())
    }

    /// Recolhe o que chegou com a máquina rodando (DbgPrint, acertos de log).
    fn refresh(&mut self) -> Result<(), String> {
        if !self.client.is_stopped() {
            if self.client.poll(Duration::from_millis(20))?.is_some() && self.session.service_stop(self.client) {
                self.client.go()?;
            }
        }
        Ok(())
    }

    fn line(&mut self, line: &str) -> Result<(), String> {
        let (command, rest) = line.split_once(char::is_whitespace).map_or((line, ""), |(command, rest)| (command, rest.trim()));
        match command {
            "expect" => {
                if !self.last_output.contains(rest) {
                    let shown: String = self.last_output.chars().take(2000).collect();
                    return Err(format!("saida sem {rest:?}:\n{shown}"));
                }
            }
            "expect-stop" => {
                if !self.client.last_stop().contains(rest) {
                    return Err(format!("ultima parada sem {rest:?}: {}", short_stop(self.client.last_stop())));
                }
            }
            "expect-console" => {
                self.refresh()?;
                if !self.client.console().contains(rest) {
                    return Err(format!("saida do DbgPrint sem {rest:?}"));
                }
            }
            "expect-eq" => {
                let (left, right) = split_two(rest).ok_or("uso: expect-eq <expr> <expr>")?;
                let (a, b) = (self.evaluate(left)?, self.evaluate(right)?);
                if a != b {
                    return Err(format!("{left} = {a:#x}, {right} = {b:#x}"));
                }
                self.note(&format!("{a:#x} == {b:#x}"));
            }
            "save" => {
                let (name, expression) = split_two(rest).ok_or("uso: save <nome> <expr>")?;
                let value = self.evaluate(expression)?;
                self.variables.insert(name.trim_start_matches('$').to_string(), value);
                self.note(&format!("${} = {value:#x}", name.trim_start_matches('$')));
            }
            "save-word" => {
                let (name, value) = save_word(&self.last_output, rest)?;
                self.note(&format!("${name} = {value:#x}"));
                self.variables.insert(name, value);
            }
            "save-thread" => {
                let (name, value) = self.save_thread(rest)?;
                self.note(&format!("${name} = {value:#x}"));
                self.variables.insert(name, value);
            }
            "wait-serial" => self.wait_serial(rest)?,
            "wait-stop" => {
                let milliseconds = kd_client::parse_number(rest).unwrap_or(120_000);
                let text = self.wait_stop(Duration::from_millis(milliseconds))?;
                self.output(text);
            }
            "attach" => {
                self.note("sessao ja anexada pelo servidor (attach ignorado)");
                self.last_output = self.client.last_stop().to_string();
            }
            "detach" | "quit" | "q" => return Err("detach/quit: use a ferramenta detach do servidor".into()),
            "echo" => self.note(rest),
            "sleep" => self.sleep(Duration::from_millis(kd_client::parse_number(rest).unwrap_or(1000)))?,
            _ => {
                let text = substitute(line, &self.variables);
                let output = self.client.execute(&text)?;
                self.output(output);
            }
        }
        Ok(())
    }

    /// `save-thread <nome> <texto> <coluna> <módulo>`: das linhas da saída
    /// anterior com o texto (o ETHREAD na coluna), a primeira thread com um
    /// quadro do módulo na pilha.
    fn save_thread(&mut self, rest: &str) -> Result<(String, u64), String> {
        let usage = "uso: save-thread <nome> <texto> <coluna> <modulo>";
        let mut parts = rest.split_whitespace();
        let (Some(name), Some(needle), Some(column), Some(module)) = (parts.next(), parts.next(), parts.next().and_then(|text| text.parse::<usize>().ok()), parts.next()) else { return Err(usage.into()) };
        let candidates: Vec<u64> = self.last_output.lines().filter(|line| line.contains(needle)).filter_map(|line| line.split_whitespace().nth(column)).filter_map(kd_client::parse_number).collect();
        for thread in candidates {
            let Ok((_, frames)) = self.client.thread_backtrace(thread, 32) else { continue };
            let symbols = &self.client.symbols;
            if frames.iter().any(|frame| symbols.module_at(frame.address).is_some_and(|found| found.name.eq_ignore_ascii_case(module) || found.file_name.eq_ignore_ascii_case(module))) {
                return Ok((name.to_string(), thread));
            }
        }
        Err(format!("nenhuma thread das linhas com {needle:?} tem quadro no modulo {module}"))
    }

    /// Espera a próxima parada que não seja um aviso de carga dos adiados;
    /// roda os comandos de parada do breakpoint.
    fn wait_stop(&mut self, timeout: Duration) -> Result<String, String> {
        let deadline = (Instant::now() + timeout).min(self.options.deadline);
        if self.client.is_stopped() {
            // Já parada: a parada é a que vale (o roteiro do xtask esperaria
            // até o prazo).
            return Ok(self.client.last_stop().to_string());
        }
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("tempo esgotado esperando a parada (a maquina segue rodando)".into());
            }
            if let Some(stop) = self.client.poll(remaining.min(Duration::from_millis(500)))? {
                if self.session.service_stop(self.client) {
                    let armed = std::mem::take(&mut self.session.armed);
                    for line in armed {
                        self.push(format!("  [adiado] {line}"));
                    }
                    self.client.go()?;
                    continue;
                }
                if let Some((id, commands)) = self.client.stop_commands() {
                    for command in commands.split(';').map(str::trim).filter(|command| !command.is_empty()) {
                        let output = self.client.execute(command).unwrap_or_else(|error| format!("erro: {error}"));
                        self.push(format!("  [bp #{id}] > {command}"));
                        for line in output.trim_end().lines() {
                            self.push(format!("  [bp #{id}]   {line}"));
                        }
                        if !self.client.is_stopped() {
                            break;
                        }
                    }
                }
                return Ok(stop);
            }
        }
    }

    /// `wait-serial <texto>`: o texto em qualquer ponto do log da COM1.
    fn wait_serial(&mut self, text: &str) -> Result<(), String> {
        let path = self.options.serial.clone().ok_or("sem o log da COM1 (launch, ou connect com serial_log)")?;
        let deadline = (Instant::now() + Duration::from_secs(300)).min(self.options.deadline);
        let mut watch = Watch::new(path, 0);
        let markers = vec![text.to_string()];
        loop {
            if let Some(found) = watch.poll(&markers) {
                self.note(&format!("COM1: {}", found.line));
                return Ok(());
            }
            if self.client.is_stopped() {
                std::thread::sleep(Duration::from_millis(100));
            } else if let Some(stop) = self.client.poll(Duration::from_millis(100))? {
                if self.session.service_stop(self.client) {
                    let armed = std::mem::take(&mut self.session.armed);
                    for line in armed {
                        self.push(format!("  [adiado] {line}"));
                    }
                    self.client.go()?;
                } else {
                    return Err(format!("a maquina parou antes do texto aparecer: {}", short_stop(&stop)));
                }
            }
            if Instant::now() >= deadline {
                return Err(format!("tempo esgotado esperando {text:?} na COM1"));
            }
        }
    }

    /// `sleep <ms>`: com a máquina rodando, os acertos de log seguem
    /// sendo atendidos; uma parada de verdade fica (e vai para o log).
    fn sleep(&mut self, duration: Duration) -> Result<(), String> {
        let end = Instant::now() + duration.min(self.remaining());
        while Instant::now() < end {
            let slice = end.saturating_duration_since(Instant::now()).min(Duration::from_millis(100));
            if self.client.is_stopped() {
                std::thread::sleep(slice);
            } else if let Some(stop) = self.client.poll(slice)? {
                if self.session.service_stop(self.client) {
                    self.client.go()?;
                } else {
                    self.note(&format!("(parada durante o sleep: {})", short_stop(&stop)));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitutes_saved_values() {
        let mut variables = BTreeMap::new();
        variables.insert("dw".to_string(), 0x1f4);
        variables.insert("x".to_string(), 16);
        assert_eq!(substitute(".process $dw", &variables), ".process 0x1f4");
        assert_eq!(substitute("bp ksecdd!$entry /log \"v={poi($x+8)} {$nada}\"", &variables), "bp ksecdd!$entry /log \"v={poi(0x10+8)} {$nada}\"");
        assert_eq!(substitute("? 1", &BTreeMap::new()), "? 1");
    }

    #[test]
    fn saves_words_from_the_previous_output() {
        let output = "PID   EPROCESS           nome\n0x1f4 0xffffc00012340000 dwm.exe\n0x240 0xffffc00012350000 svchost.exe\n0x248 0xffffc00012360000 svchost.exe\n";
        assert_eq!(save_word(output, "dw dwm.exe 0"), Ok(("dw".to_string(), 0x1f4)));
        assert_eq!(save_word(output, "s svchost.exe 1 2"), Ok(("s".to_string(), 0xffffc00012360000)));
        assert!(save_word(output, "s svchost.exe 1 3").unwrap_err().contains("nenhuma linha 3"));
        assert!(save_word(output, "s svchost.exe").unwrap_err().starts_with("uso:"));
        assert_eq!(split_two("poi(@rsp + 8) 4"), Some(("poi(@rsp + 8)", "4")));
    }
}
