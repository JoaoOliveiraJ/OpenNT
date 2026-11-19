//! O estado do servidor entre uma ferramenta e outra: os breakpoints de
//! usuário adiados (armados quando a DLL carrega no processo), o que já foi
//! entregue do log dos breakpoints e do DbgPrint (cada espera devolve só o
//! que é novo) e o log da COM1 dado no `connect`.
//!
//! O breakpoint adiado de usuário usa o evento de carga de imagem do kernel
//! (`sxe ld:processo!dll`): na parada do evento, o processo da DLL já é o
//! das leituras, os módulos dele são relidos e o breakpoint é armado nele;
//! a máquina segue sozinha.

use std::path::PathBuf;

use opennt_kd::client::BreakpointRequest;
use opennt_kd::{BreakpointKind, Client};

use crate::engine::Engine;
use crate::serial::tail_text;

/// Um breakpoint de usuário esperando a DLL carregar.
#[derive(Clone, Debug)]
pub struct PendingBreakpoint {
    /// O breakpoint de evento `ld:processo!dll` que avisa a carga.
    pub event: u32,
    pub process: String,
    pub module: String,
    pub request: BreakpointRequest,
}

/// O estado de uma conexão MCP.
#[derive(Default)]
pub struct Session {
    pub pending: Vec<PendingBreakpoint>,
    /// O que aconteceu com os adiados desde a última entrega.
    pub armed: Vec<String>,
    /// O log da COM1 dado pelo agente (`connect` com `serial_log`).
    pub serial_log: Option<PathBuf>,
    log_seen: usize,
    console_seen: usize,
}

/// O número do breakpoint de evento na descrição da parada (`... (evento
/// #3: imagem ...)`).
pub fn event_id(stop: &str) -> Option<u32> {
    let start = stop.find("(evento #")? + "(evento #".len();
    let digits: String = stop[start..].chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

impl Session {
    /// Uma sessão nova com o alvo (launch, connect, detach): esquece os
    /// adiados e as marcas de leitura.
    pub fn reset(&mut self) {
        self.pending.clear();
        self.armed.clear();
        self.log_seen = 0;
        self.console_seen = 0;
    }

    /// O log da COM1: o dado no `connect` ou o do engine.
    pub fn serial_path(&self, engine: &dyn Engine) -> Option<PathBuf> {
        self.serial_log.clone().or_else(|| engine.serial_log())
    }

    /// As linhas novas do log dos breakpoints (as últimas `limit`) e quantas
    /// chegaram desde a última entrega.
    pub fn new_log_lines(&mut self, client: &Client, limit: usize) -> (Vec<String>, usize) {
        let lines = client.log_lines();
        if self.log_seen > lines.len() {
            self.log_seen = 0;
        }
        let fresh = &lines[self.log_seen..];
        let count = fresh.len();
        let tail = fresh[count.saturating_sub(limit)..].to_vec();
        self.log_seen = lines.len();
        (tail, count)
    }

    /// Marca o log dos breakpoints e o DbgPrint de agora como entregues.
    pub fn mark_seen(&mut self, client: &Client) {
        self.log_seen = client.log_lines().len();
        self.console_seen = client.console().len();
    }

    /// O DbgPrint novo desde a última entrega (os últimos `max` bytes), sem
    /// as linhas dos breakpoints de log (essas vão em `new_log_lines`).
    pub fn new_console(&mut self, client: &Client, max: usize) -> String {
        let console = client.console();
        if self.console_seen > console.len() || !console.is_char_boundary(self.console_seen) {
            self.console_seen = 0;
        }
        let fresh = &console[self.console_seen..];
        self.console_seen = console.len();
        let text: Vec<&str> = fresh.lines().filter(|line| !line.starts_with("[bp ") && !line.starts_with("[evento #")).collect();
        tail_text(&text.join("\n"), max).to_string()
    }

    /// Guarda um breakpoint de usuário até `module` carregar em `process`
    /// (o nome do processo); devolve o número do breakpoint de evento.
    pub fn add_pending(&mut self, client: &mut Client, process: &str, module: &str, request: BreakpointRequest) -> Result<u32, String> {
        let existing = self.pending.iter().find(|pending| pending.process.eq_ignore_ascii_case(process) && pending.module.eq_ignore_ascii_case(module)).map(|pending| pending.event);
        let event = match existing {
            Some(event) => event,
            None => {
                let mut event = BreakpointRequest::new(BreakpointKind::Event, &format!("ld:{process}!{module}"));
                event.options.name = "carga adiada (opennt-mcp)".into();
                client.add_breakpoint_with(&event)?.id
            }
        };
        self.pending.push(PendingBreakpoint { event, process: process.to_string(), module: module.to_string(), request });
        Ok(event)
    }

    /// A parada é o aviso de carga de uma DLL com breakpoints adiados: arma
    /// os que já resolvem e devolve `true` (quem chama continua a máquina).
    pub fn service_stop(&mut self, client: &mut Client) -> bool {
        if self.pending.is_empty() {
            return false;
        }
        let Some(event) = event_id(client.last_stop()) else { return false };
        if !self.pending.iter().any(|pending| pending.event == event) {
            return false;
        }
        // O cliente já escolheu o processo da DLL no evento; a DLL nova
        // entra nos símbolos.
        let _ = client.reload_user_modules();
        let process = client.process().map(|context| (context.eprocess, format!("{} (PID {})", context.name, context.pid)));
        let mut index = 0;
        while index < self.pending.len() {
            if self.pending[index].event != event {
                index += 1;
                continue;
            }
            let pending = self.pending[index].clone();
            let mut request = pending.request.clone();
            request.process = process.as_ref().map_or(0, |(eprocess, _)| *eprocess);
            let place = process.as_ref().map_or_else(|| pending.process.clone(), |(_, name)| name.clone());
            match client.add_breakpoint_with(&request) {
                Ok(breakpoint) => {
                    self.armed.push(format!("#{} {} armado em {:#x} {} ({} carregou em {place})", breakpoint.id, request.expression, breakpoint.address, client.symbols.describe(breakpoint.address), pending.module));
                    self.pending.remove(index);
                }
                Err(error) => {
                    self.armed.push(format!("{}: {} carregou em {place}, mas o breakpoint nao armou: {error}", request.expression, pending.module));
                    index += 1;
                }
            }
        }
        // Sem adiados para este evento, o breakpoint de evento sai.
        if !self.pending.iter().any(|pending| pending.event == event) {
            let _ = client.remove_breakpoint(event);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_event_breakpoint_of_a_stop() {
        let stop = "parado: SIGTRAP breakpoint (CPU 0) em 0xfffff80040101000 opennt_kd_image_event (evento #3: imagem \\Windows\\System32\\d2d1.dll em 0x7ffe0000 (tamanho 0x1000) no processo dwm.exe (PID 500)) [T05thread:1;]";
        assert_eq!(event_id(stop), Some(3));
        assert_eq!(event_id("parado: SIGTRAP (breakpoint #2, acerto 1)"), None);
        assert_eq!(event_id("(evento #x"), None);
    }
}
