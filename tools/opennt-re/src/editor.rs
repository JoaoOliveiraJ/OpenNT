//! O modelo do editor de breakpoints: os campos do formulário em texto
//! (como o usuário os digita) e a conversão, com a conferência, para o
//! pedido do cliente (`BreakpointRequest`), e de volta a partir de um
//! breakpoint existente.

use opennt_kd::client::{BreakpointOptions, BreakpointRequest};
use opennt_kd::{Breakpoint, BreakpointKind};

/// Os campos do diálogo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BreakpointForm {
    /// `None`: breakpoint novo; senão o número do editado.
    pub id: Option<u32>,
    pub kind: BreakpointKind,
    pub expression: String,
    /// Bytes vigiados (hardware de dados e memória), em decimal ou `0x`.
    pub length: String,
    pub name: String,
    pub break_condition: String,
    pub log_text: String,
    pub log_condition: String,
    pub command_text: String,
    pub command_condition: String,
    /// Para a partir deste acerto (vazio = no primeiro).
    pub hit_count: String,
    pub group: String,
    pub enabled: bool,
    pub single_shot: bool,
    pub silent: bool,
    pub fast_resume: bool,
    pub deferred: bool,
}

impl BreakpointForm {
    /// Um formulário novo para o endereço.
    pub fn new(kind: BreakpointKind, expression: &str) -> BreakpointForm {
        // Um breakpoint de memória cobre as páginas da faixa (com 1, a do
        // endereço).
        let length = match kind {
            BreakpointKind::Write | BreakpointKind::Access => "8",
            _ => "1",
        };
        BreakpointForm {
            id: None,
            kind,
            expression: expression.to_string(),
            length: length.into(),
            name: String::new(),
            break_condition: String::new(),
            log_text: String::new(),
            log_condition: String::new(),
            command_text: String::new(),
            command_condition: String::new(),
            hit_count: String::new(),
            group: String::new(),
            enabled: true,
            single_shot: false,
            silent: false,
            fast_resume: false,
            deferred: false,
        }
    }

    /// O formulário de um breakpoint existente.
    pub fn from_breakpoint(breakpoint: &Breakpoint) -> BreakpointForm {
        BreakpointForm {
            id: Some(breakpoint.id),
            kind: breakpoint.kind,
            expression: breakpoint.expression.clone(),
            length: if breakpoint.length > 9 { format!("{:#x}", breakpoint.length) } else { breakpoint.length.to_string() },
            name: breakpoint.options.name.clone(),
            break_condition: breakpoint.condition.clone(),
            log_text: breakpoint.log.clone(),
            log_condition: breakpoint.options.log_condition.clone(),
            command_text: breakpoint.command.clone(),
            command_condition: breakpoint.options.command_condition.clone(),
            hit_count: if breakpoint.pass_count > 1 { breakpoint.pass_count.to_string() } else { String::new() },
            group: breakpoint.group.clone(),
            enabled: breakpoint.enabled,
            single_shot: breakpoint.options.single_shot,
            silent: breakpoint.options.silent,
            fast_resume: breakpoint.options.fast_resume,
            deferred: breakpoint.pending,
        }
    }

    /// Os tamanhos que o tipo aceita.
    fn check_length(&self, length: u64) -> Result<(), String> {
        match self.kind {
            BreakpointKind::Write | BreakpointKind::Access if !matches!(length, 1 | 2 | 4 | 8) => Err("o comparador de hardware vigia 1, 2, 4 ou 8 bytes".into()),
            kind if kind.is_memory() && (length == 0 || length > 64 * 0x1000) => Err("breakpoint de memória: de 1 byte a 64 páginas".into()),
            _ => Ok(()),
        }
    }

    /// O pedido para o cliente; erro com a explicação do campo errado.
    pub fn to_request(&self) -> Result<BreakpointRequest, String> {
        let expression = self.expression.trim();
        if expression.is_empty() {
            return Err("o endereço (ou o módulo, ou o evento) está vazio".into());
        }
        let mut request = BreakpointRequest::new(self.kind, expression);
        if !self.length.trim().is_empty() {
            let length = opennt_kd::parse_number(&self.length).ok_or("tamanho inválido (decimal ou 0x...)")?;
            self.check_length(length)?;
            request.length = length;
        }
        request.pass_count = if self.hit_count.trim().is_empty() { 0 } else { self.hit_count.trim().parse().map_err(|_| "contagem de acertos inválida")? };
        request.condition = self.break_condition.trim().to_string();
        request.log = self.log_text.trim().to_string();
        request.command = self.command_text.trim().to_string();
        request.group = self.group.trim().to_string();
        request.enabled = self.enabled;
        request.deferred = self.deferred;
        request.options = BreakpointOptions {
            name: self.name.trim().to_string(),
            log_condition: self.log_condition.trim().to_string(),
            command_condition: self.command_condition.trim().to_string(),
            single_shot: self.single_shot,
            silent: self.silent,
            fast_resume: self.fast_resume,
        };
        if !request.options.log_condition.is_empty() && request.log.is_empty() {
            return Err("condição de log sem texto de log".into());
        }
        if !request.options.command_condition.is_empty() && request.command.is_empty() {
            return Err("condição de comando sem comandos".into());
        }
        Ok(request)
    }

    /// O resumo de uma linha (a dica do diálogo).
    pub fn summary(&self) -> String {
        let mut parts = vec![format!("{} em {}", self.kind.name(), self.expression.trim())];
        if !self.break_condition.trim().is_empty() {
            parts.push(format!("para se {}", self.break_condition.trim()));
        } else if !self.log_text.trim().is_empty() {
            parts.push("só registra (sem condição de parada)".into());
        }
        if self.single_shot {
            parts.push("uma vez só".into());
        }
        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_form_to_request_and_back() {
        let mut form = BreakpointForm::new(BreakpointKind::Software, "ntdll!LdrLoadDll");
        form.name = "carga".into();
        form.break_condition = "@rcx != 0".into();
        form.log_text = "dll {@r8:s}".into();
        form.log_condition = "1".into();
        form.command_text = "k 4".into();
        form.hit_count = "3".into();
        form.single_shot = true;
        form.fast_resume = true;
        let request = form.to_request().unwrap();
        assert_eq!(request.expression, "ntdll!LdrLoadDll");
        assert_eq!(request.pass_count, 3);
        assert_eq!(request.options.name, "carga");
        assert!(request.options.single_shot && request.options.fast_resume && !request.options.silent);
        assert_eq!(form.summary(), "software em ntdll!LdrLoadDll, para se @rcx != 0, uma vez só");
        // De volta pelo breakpoint que o cliente criaria.
        let breakpoint = Breakpoint {
            id: 7,
            kind: request.kind,
            address: 0x7ffd_0000_1000,
            length: request.length,
            enabled: true,
            expression: request.expression.clone(),
            condition: request.condition.clone(),
            pass_count: request.pass_count,
            hits: 0,
            pending: false,
            log: request.log.clone(),
            command: request.command.clone(),
            group: String::new(),
            process: 0,
            options: request.options.clone(),
        };
        let mut again = BreakpointForm::from_breakpoint(&breakpoint);
        assert_eq!(again.id, Some(7));
        again.id = None;
        assert_eq!(again, form);
    }

    #[test]
    fn rejects_invalid_fields() {
        let mut form = BreakpointForm::new(BreakpointKind::Write, "@rsp");
        form.length = "3".into();
        assert!(form.to_request().unwrap_err().contains("1, 2, 4 ou 8"));
        form.length = "4".into();
        assert_eq!(form.to_request().unwrap().length, 4);
        form.hit_count = "x".into();
        assert!(form.to_request().is_err());
        let mut form = BreakpointForm::new(BreakpointKind::MemoryExecute, "0x7ff600001000");
        assert_eq!(form.to_request().unwrap().length, 1);
        form.length = "0".into();
        assert!(form.to_request().is_err());
        let mut form = BreakpointForm::new(BreakpointKind::Software, " ");
        assert!(form.to_request().is_err());
        form.expression = "x".into();
        form.log_condition = "1".into();
        assert!(form.to_request().unwrap_err().contains("sem texto de log"));
    }
}
