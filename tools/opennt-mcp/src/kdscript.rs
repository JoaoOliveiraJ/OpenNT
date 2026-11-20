//! Os roteiros do depurador (os de `cargo xtask test-boot --kd=com2
//! --script=ARQ`) pela sessão do servidor. Quem roda é o executor do
//! `opennt-kd` (`Client::run_script_hosted`, a mesma linguagem do test-boot,
//! do opennt-re e do opennt-dbg); aqui fica só o servidor como anfitrião:
//! - a saída vai para o log da resposta, nunca para a saída padrão (no
//!   stdio ela é o canal do MCP); as linhas dos breakpoints de log vão no
//!   `breakpoint_log` da resposta, não no log;
//! - as esperas respeitam o prazo da ferramenta, e nenhuma linha começa
//!   depois dele;
//! - `wait-serial` e `serial-has` leem o log da COM1 da sessão;
//! - nas esperas, um breakpoint de usuário adiado (`breakpoint_user`) é
//!   armado quando a DLL carrega e a máquina segue;
//! - `attach` não faz nada (a sessão já existe) e `detach`/`quit` são
//!   recusados (a ferramenta `detach` desliga).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

use opennt_kd::kd_script::{ScriptHost, ScriptOptions};
use opennt_kd::Client;

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
    /// Comandos executados (um laço conta cada volta).
    pub commands: usize,
    pub log: Vec<String>,
    /// Linhas que não couberam no log.
    pub dropped: usize,
    /// As variáveis do roteiro: as numéricas em hexadecimal (`0x...`), as de
    /// texto como estão.
    pub variables: BTreeMap<String, String>,
}

/// O servidor como anfitrião do roteiro.
struct Host<'a> {
    session: &'a mut Session,
    options: &'a Options,
    log: Vec<String>,
    dropped: usize,
}

impl Host<'_> {
    fn push(&mut self, line: String) {
        if self.log.len() < MAX_LOG {
            self.log.push(line);
        } else {
            self.dropped += 1;
        }
    }
}

/// Uma linha do executor no log da resposta: sem o `[kd-script] `; os
/// comandos (`> ...`) e a saída deles (indentada) como saem, e o resto
/// (`echo`, `print`, os tratadores) indentado como nota. `None` para as
/// linhas dos breakpoints de log (vão no `breakpoint_log`).
fn log_line(line: &str) -> Option<String> {
    if line.starts_with("[kd-log] ") {
        return None;
    }
    let text = line.strip_prefix("[kd-script] ").unwrap_or(line);
    if text.starts_with("> ") || text.starts_with("  ") {
        Some(text.to_string())
    } else {
        Some(format!("  {text}"))
    }
}

impl ScriptHost for Host<'_> {
    fn output(&mut self, line: &str) {
        if let Some(line) = log_line(line) {
            self.push(line);
        }
    }

    fn deadline(&self) -> Option<Instant> {
        Some(self.options.deadline)
    }

    fn serial_log(&self) -> Option<PathBuf> {
        self.options.serial.clone()
    }

    fn service_stop(&mut self, client: &mut Client) -> bool {
        if !self.session.service_stop(client) {
            return false;
        }
        for line in std::mem::take(&mut self.session.armed) {
            self.push(format!("  [adiado] {line}"));
        }
        true
    }

    fn intercept(&mut self, client: &mut Client, word: &str, _text: &str) -> Option<Result<String, String>> {
        match word {
            "attach" => Some(Ok(format!("sessao ja anexada pelo servidor (attach ignorado)\n{}", client.last_stop()))),
            "detach" | "quit" | "q" => Some(Err("detach/quit: use a ferramenta detach do servidor".into())),
            _ => None,
        }
    }
}

/// Roda o roteiro; a primeira linha que falha encerra.
pub fn run(client: &mut Client, session: &mut Session, script: &str, options: &Options) -> Report {
    let mut host = Host { session, options, log: Vec::new(), dropped: 0 };
    let outcome = client.run_script_hosted(script, &ScriptOptions::default(), &mut host);
    if let Err(error) = &outcome.result {
        for line in error.lines() {
            host.push(format!("  erro: {line}"));
        }
    }
    let variables = outcome.variables.into_iter().map(|(name, text)| {
        let value = opennt_kd::parse_number(&text).map_or(text, |value| format!("{value:#x}"));
        (name, value)
    });
    Report { ok: outcome.result.is_ok(), error: outcome.result.err(), failed_line: outcome.failed_line, commands: outcome.commands, log: host.log, dropped: host.dropped, variables: variables.collect() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executor_lines_in_the_response_log() {
        assert_eq!(log_line("[kd-script] > ? 1+2"), Some("> ? 1+2".to_string()));
        assert_eq!(log_line("[kd-script]   Evaluate expression: 3 = 0x3"), Some("  Evaluate expression: 3 = 0x3".to_string()));
        assert_eq!(log_line("[kd-script] ola"), Some("  ola".to_string()));
        assert_eq!(log_line("[kd-script] [on-break #2] > k"), Some("  [on-break #2] > k".to_string()));
        assert_eq!(log_line("[kd-log] [bp #0] rax=1"), None);
    }
}
