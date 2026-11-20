//! Os roteiros do kd na janela. Quem roda é o executor do `opennt-kd`
//! (`Client::run_script_hosted`: a linguagem do `--script` do `cargo xtask
//! test-boot --kd=com2`, com conferências, variáveis, blocos, laços,
//! esperas e tratadores); o backend é o anfitrião (`backend.rs`: o
//! Cancelar, a barra de estado e o painel de comandos). Aqui ficam o texto
//! do lado da janela: as linhas do executor no painel, a ordem das linhas
//! de comando, a troca das variáveis nos comandos digitados e o texto da
//! gravação (os comandos da janela viram um roteiro que o test-boot também
//! roda).
//!
//! Diferenças da janela: `attach` não faz nada (a sessão já está anexada);
//! `wait-serial` lê o log da COM1 que a janela segue.

use std::collections::HashMap;
use std::time::Duration;

use opennt_kd::client::BreakpointRequest;
use opennt_kd::{Breakpoint, BreakpointKind};

/// O prazo do `wait-stop` sem número (o do opennt-kd).
pub const WAIT_STOP_DEFAULT_MS: u64 = 120_000;

/// Uma linha do executor no painel de comandos.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PanelLine {
    /// Um comando ou bloco (`> texto`): abre uma entrada.
    Command(String),
    /// Uma volta de `for-each` (`-- $t = ...`): abre uma entrada.
    Item(String),
    /// Saída da entrada aberta.
    Output(String),
    /// As linhas dos breakpoints de log (já vão no painel do DbgPrint).
    Skip,
}

/// Onde uma linha do executor vai no painel: sem o `[kd-script] ` e a
/// indentação da saída; as linhas de um tratador guardam a marca
/// `[on-break #n]` no comando.
pub fn panel_line(line: &str) -> PanelLine {
    if line.starts_with("[kd-log] ") {
        return PanelLine::Skip;
    }
    let text = line.strip_prefix("[kd-script] ").unwrap_or(line);
    let (marker, bare) = match text.strip_prefix("[on-break #").and_then(|rest| rest.split_once("] ")) {
        Some((id, rest)) => (format!("[on-break #{id}] "), rest),
        None => (String::new(), text),
    };
    if let Some(command) = bare.strip_prefix("> ") {
        PanelLine::Command(format!("{marker}{command}"))
    } else if bare.starts_with("-- ") {
        PanelLine::Item(format!("{marker}{bare}"))
    } else {
        PanelLine::Output(bare.strip_prefix("  ").unwrap_or(bare).to_string())
    }
}

/// As linhas de comando do roteiro (sem as vazias e os comentários): o
/// número de ordem de cada uma (do 1) pelo número da linha no arquivo, e o
/// total (a barra de estado).
pub fn command_lines(text: &str) -> (HashMap<usize, usize>, usize) {
    let mut order = HashMap::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if !line.is_empty() && !line.starts_with('#') {
            let next = order.len() + 1;
            order.insert(index + 1, next);
        }
    }
    let total = order.len();
    (order, total)
}

/// Troca cada `$nome` conhecido pelo valor (`0x...`) num comando digitado;
/// um `$nome` que o roteiro não salvou fica como está (o avaliador do
/// cliente decide).
pub fn substitute(text: &str, variables: &HashMap<String, u64>) -> String {
    let mut output = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find('$') {
        output.push_str(&rest[..index]);
        let after = &rest[index + 1..];
        let end = after.find(|character: char| !(character.is_ascii_alphanumeric() || character == '_')).unwrap_or(after.len());
        let name = &after[..end];
        match variables.get(name) {
            Some(value) if !name.is_empty() => output.push_str(&format!("{value:#x}")),
            _ => {
                output.push('$');
                output.push_str(name);
            }
        }
        rest = &after[end..];
    }
    output.push_str(rest);
    output
}

/// O começo de um roteiro gravado: como rodar de novo e o `attach`.
pub fn recording_header(xtask: &[String], path: &str) -> Vec<String> {
    let options = if xtask.is_empty() { String::new() } else { format!("{} ", xtask.join(" ")) };
    vec![
        "# roteiro gravado pelo opennt-dbg (a linguagem do --script do test-boot)".to_string(),
        format!("# como teste: cargo xtask debug {options}--script={path}"),
        "# na janela: Roteiro > Rodar roteiro".to_string(),
        "attach".to_string(),
    ]
}

/// A linha `wait-stop` gravada depois de um `c`: o tempo que a máquina
/// levou para parar, com folga (o dobro, no mínimo o padrão do opennt-kd),
/// arredondado para cima em 10 s.
pub fn wait_stop_line(elapsed: Duration) -> String {
    let wanted = (elapsed.as_millis().min(u64::MAX as u128) as u64).saturating_mul(2).max(WAIT_STOP_DEFAULT_MS);
    format!("wait-stop {}", wanted.div_ceil(10_000) * 10_000)
}

/// O comando de texto que cria o breakpoint pedido pela janela (o que a
/// gravação escreve).
pub fn breakpoint_command(request: &BreakpointRequest) -> String {
    let expression = request.expression.trim();
    let mut text = match request.kind {
        BreakpointKind::Software => {
            let mut text = format!("{} {expression}", if request.deferred { "bu" } else { "bp" });
            if request.pass_count > 1 {
                text.push_str(&format!(" {}", request.pass_count));
            }
            if !request.condition.is_empty() {
                text.push_str(&format!(" /w \"{}\"", request.condition));
            }
            text
        }
        BreakpointKind::Hardware => format!("hbp {expression}"),
        BreakpointKind::Write | BreakpointKind::Access if matches!(request.length, 1 | 2 | 4 | 8) => format!("ba {}{} {expression}", if request.kind == BreakpointKind::Write { "w" } else { "r" }, request.length),
        BreakpointKind::Write => format!("watch {expression} {} w", request.length),
        BreakpointKind::Access => format!("watch {expression} {} a", request.length),
        BreakpointKind::Module => format!("sxe ld:{expression}"),
        BreakpointKind::Event => format!("sxe {expression}"),
        BreakpointKind::MemoryAccess => format!("bpm a {expression} {}", request.length),
        BreakpointKind::MemoryWrite => format!("bpm w {expression} {}", request.length),
        BreakpointKind::MemoryExecute => format!("bpm x {expression} {}", request.length),
    };
    // O log, os comandos e o grupo só existem em texto no `bp`/`bu`.
    if request.kind == BreakpointKind::Software {
        if !request.log.is_empty() {
            text.push_str(&format!(" /log \"{}\"", request.log));
        }
        if !request.command.is_empty() {
            text.push_str(&format!(" /cmd \"{}\"", request.command));
        }
        if !request.group.is_empty() {
            text.push_str(&format!(" /g {}", request.group));
        }
    }
    text
}

/// O comando que tira um breakpoint (a gravação): pela expressão quando
/// ela serve, senão pelo endereço ou pelo número.
pub fn clear_command(breakpoint: &Breakpoint) -> String {
    let expression = breakpoint.expression.trim();
    let target = if expression.is_empty() || expression.contains(char::is_whitespace) { format!("{:#x}", breakpoint.address) } else { expression.to_string() };
    match breakpoint.kind {
        BreakpointKind::Module => format!("sxd ld:{expression}"),
        BreakpointKind::Event => format!("sxd {expression}"),
        _ if breakpoint.pending => format!("bc #{}", breakpoint.id),
        BreakpointKind::Software => format!("bc {target}"),
        BreakpointKind::Hardware => format!("hbc {target}"),
        BreakpointKind::Write => format!("unwatch {target} {} w", breakpoint.length),
        BreakpointKind::Access => format!("unwatch {target} {} a", breakpoint.length),
        BreakpointKind::MemoryAccess | BreakpointKind::MemoryWrite | BreakpointKind::MemoryExecute => format!("bpmc {:#x}", breakpoint.address),
    }
}

/// O `write` de bytes gravados na memória pela janela.
pub fn write_command(address: u64, bytes: &[u8]) -> String {
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("write {address:#x} {hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executor_lines_in_the_panel() {
        assert_eq!(panel_line("[kd-script] > save-word svc svchost.exe 0"), PanelLine::Command("save-word svc svchost.exe 0".into()));
        assert_eq!(panel_line("[kd-script]   $svc = 0x1a4"), PanelLine::Output("$svc = 0x1a4".into()));
        assert_eq!(panel_line("[kd-script] fim"), PanelLine::Output("fim".into()));
        assert_eq!(panel_line("[kd-script] > if output-has ok: sim"), PanelLine::Command("if output-has ok: sim".into()));
        assert_eq!(panel_line("[kd-script] -- $t = 0xffff8000 (Waiting, dwm.exe) (1 de 3)"), PanelLine::Item("-- $t = 0xffff8000 (Waiting, dwm.exe) (1 de 3)".into()));
        assert_eq!(panel_line("[kd-script] [on-break #2] > k 4"), PanelLine::Command("[on-break #2] k 4".into()));
        assert_eq!(panel_line("[kd-script] [on-break #2]   #0 nt!KiSwapContext"), PanelLine::Output("#0 nt!KiSwapContext".into()));
        assert_eq!(panel_line("[kd-log] [bp #0] rax=1"), PanelLine::Skip);
    }

    #[test]
    fn command_line_order() {
        let (order, total) = command_lines("attach\n# comentario\n\nc\nrepeat 2 {\n  echo x\n}\n");
        assert_eq!(total, 5);
        assert_eq!((order.get(&1), order.get(&4), order.get(&6), order.get(&7)), (Some(&1), Some(&2), Some(&4), Some(&5)));
        assert_eq!(order.get(&2), None);
    }

    #[test]
    fn variables() {
        let mut variables = HashMap::new();
        variables.insert("svc".to_string(), 0xffff_8000_1234u64);
        variables.insert("t1".to_string(), 0x10);
        assert_eq!(substitute(".process $svc", &variables), ".process 0xffff80001234");
        assert_eq!(substitute("btt $t1 40", &variables), "btt 0x10 40");
        assert_eq!(substitute("? $t1+$t1", &variables), "? 0x10+0x10");
        assert_eq!(substitute("? $outro $ fim$", &variables), "? $outro $ fim$");
        assert_eq!(substitute("sem variaveis", &variables), "sem variaveis");
    }

    #[test]
    fn recording_text() {
        let header = recording_header(&["--initial-process=smss".to_string()], "build/opennt-dbg/gravado.kd");
        assert_eq!(header[1], "# como teste: cargo xtask debug --initial-process=smss --script=build/opennt-dbg/gravado.kd");
        assert_eq!(header.last().map(String::as_str), Some("attach"));
        assert_eq!(wait_stop_line(Duration::from_secs(5)), "wait-stop 120000");
        assert_eq!(wait_stop_line(Duration::from_millis(61_001)), "wait-stop 130000");
        let mut request = BreakpointRequest::new(BreakpointKind::Software, "lsm!CService::Start");
        request.pass_count = 3;
        request.condition = "@rcx == 0".into();
        request.group = "lsm".into();
        assert_eq!(breakpoint_command(&request), "bp lsm!CService::Start 3 /w \"@rcx == 0\" /g lsm");
        request.deferred = true;
        request.pass_count = 0;
        request.condition.clear();
        request.group.clear();
        assert_eq!(breakpoint_command(&request), "bu lsm!CService::Start");
        assert_eq!(breakpoint_command(&BreakpointRequest::new(BreakpointKind::Write, "@rsp")), "ba w8 @rsp");
        let mut range = BreakpointRequest::new(BreakpointKind::Access, "x");
        range.length = 0x20;
        assert_eq!(breakpoint_command(&range), "watch x 32 a");
        assert_eq!(breakpoint_command(&BreakpointRequest::new(BreakpointKind::Module, "ACPI.sys")), "sxe ld:ACPI.sys");
        assert_eq!(write_command(0x1000, &[0x90, 0xcc]), "write 0x1000 90cc");
    }

    #[test]
    fn clearing_text() {
        let breakpoint = Breakpoint {
            id: 3,
            kind: BreakpointKind::Software,
            address: 0xfffff800_00001000,
            length: 1,
            enabled: true,
            expression: "nt!NtClose".into(),
            condition: String::new(),
            pass_count: 0,
            hits: 0,
            pending: false,
            log: String::new(),
            command: String::new(),
            group: String::new(),
            process: 0,
            options: Default::default(),
        };
        assert_eq!(clear_command(&breakpoint), "bc nt!NtClose");
        assert_eq!(clear_command(&Breakpoint { pending: true, ..breakpoint.clone() }), "bc #3");
        assert_eq!(clear_command(&Breakpoint { expression: "poi(@rsp + 8)".into(), ..breakpoint.clone() }), "bc 0xfffff80000001000");
        assert_eq!(clear_command(&Breakpoint { kind: BreakpointKind::Module, expression: "ntfs.sys".into(), ..breakpoint.clone() }), "sxd ld:ntfs.sys");
        assert_eq!(clear_command(&Breakpoint { kind: BreakpointKind::Write, length: 8, ..breakpoint }), "unwatch nt!NtClose 8 w");
    }
}
