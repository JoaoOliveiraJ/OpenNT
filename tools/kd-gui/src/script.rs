//! Os roteiros do kd na janela: a linguagem do `--script` do `cargo xtask
//! test-boot --kd=com2` (a do `Client::run_script`), uma linha por comando,
//! `#` comenta, com as conferências `expect`, `expect-stop`,
//! `expect-console`, `expect-eq`, as variáveis de `save`, `save-word` e
//! `save-thread` (viram `$nome`), `wait-serial`, `wait-stop`, `echo` e
//! `sleep`. O backend roda as linhas (`backend.rs`, com o Cancelar e a
//! saída no painel de comandos); aqui ficam a leitura, a troca das
//! variáveis e o texto da gravação (os comandos da janela viram um roteiro
//! que o test-boot também roda).
//!
//! Diferenças da janela: `attach` não faz nada (a sessão já está anexada);
//! `wait-stop` volta na hora quando a máquina já parou (no `sleep` ou no
//! `wait-serial` a janela acompanha as paradas); `wait-serial` lê o log da
//! COM1 que a janela segue.

use std::collections::HashMap;
use std::time::Duration;

use kd_client::client::BreakpointRequest;
use kd_client::{parse_number, Breakpoint, BreakpointKind};

/// O prazo do `wait-stop` sem número (o do kd-client).
pub const WAIT_STOP_DEFAULT_MS: u64 = 120_000;

/// O prazo do `wait-serial` (o do kd-client).
pub const WAIT_SERIAL_SECONDS: u64 = 300;

/// Um passo do roteiro.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// `attach`: na janela a sessão já está anexada.
    Attach,
    /// A saída do último comando contém o texto.
    Expect(String),
    /// A descrição da última parada contém o texto.
    ExpectStop(String),
    /// A saída do DbgPrint da sessão contém o texto.
    ExpectConsole(String),
    /// As duas expressões dão o mesmo valor.
    ExpectEq(String, String),
    Save { name: String, expression: String },
    /// Um número da saída anterior: a coluna da N-ésima linha com o texto.
    SaveWord { name: String, needle: String, column: usize, occurrence: usize },
    /// Das linhas da saída anterior com o texto (o ETHREAD na coluna), a
    /// primeira thread com um quadro do módulo na pilha.
    SaveThread { name: String, needle: String, column: usize, module: String },
    /// O texto em qualquer ponto do log da COM1.
    WaitSerial(String),
    /// A próxima parada, até o prazo em milissegundos.
    WaitStop(u64),
    Echo(String),
    Sleep(u64),
    /// Qualquer outro comando do depurador (`bp`, `g`, `k`, `!process`...).
    Command(String),
}

/// Uma linha do roteiro, com o número dela no arquivo (do 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub number: usize,
    pub text: String,
    pub step: Step,
}

/// Lê o roteiro inteiro antes de rodar: um erro de uso aparece com a linha
/// antes de a máquina andar.
pub fn parse(text: &str) -> Result<Vec<Line>, String> {
    let mut lines = Vec::new();
    let mut errors = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let text = raw.trim();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        match parse_step(text) {
            Ok(step) => lines.push(Line { number: index + 1, text: text.to_string(), step }),
            Err(error) => errors.push(format!("linha {}: {text}: {error}", index + 1)),
        }
    }
    if errors.is_empty() {
        Ok(lines)
    } else {
        Err(errors.join("\n"))
    }
}

fn parse_step(line: &str) -> Result<Step, String> {
    let (command, rest) = line.split_once(char::is_whitespace).map_or((line, ""), |(command, rest)| (command, rest.trim()));
    let words: Vec<&str> = rest.split_whitespace().collect();
    Ok(match command {
        "attach" => Step::Attach,
        "expect" => Step::Expect(rest.to_string()),
        "expect-stop" => Step::ExpectStop(rest.to_string()),
        "expect-console" => Step::ExpectConsole(rest.to_string()),
        "expect-eq" => {
            let (left, right) = split_two(rest).ok_or("uso: expect-eq <expr> <expr>")?;
            Step::ExpectEq(left.to_string(), right.to_string())
        }
        "save" => {
            let (name, expression) = split_two(rest).ok_or("uso: save <nome> <expr>")?;
            Step::Save { name: name.trim_start_matches('$').to_string(), expression: expression.to_string() }
        }
        "save-word" => {
            const USAGE: &str = "uso: save-word <nome> <texto> <coluna> [ocorrencia]";
            let (Some(name), Some(needle), Some(column)) = (words.first(), words.get(1), words.get(2).and_then(|text| text.parse::<usize>().ok())) else {
                return Err(USAGE.into());
            };
            let occurrence = match words.get(3) {
                Some(text) => text.parse::<usize>().ok().filter(|&value| value >= 1).ok_or(USAGE)?,
                None => 1,
            };
            Step::SaveWord { name: name.trim_start_matches('$').to_string(), needle: needle.to_string(), column, occurrence }
        }
        "save-thread" => {
            let (Some(name), Some(needle), Some(column), Some(module)) = (words.first(), words.get(1), words.get(2).and_then(|text| text.parse::<usize>().ok()), words.get(3)) else {
                return Err("uso: save-thread <nome> <texto> <coluna> <modulo>".into());
            };
            Step::SaveThread { name: name.trim_start_matches('$').to_string(), needle: needle.to_string(), column, module: module.to_string() }
        }
        "wait-serial" if !rest.is_empty() => Step::WaitSerial(rest.to_string()),
        "wait-serial" => return Err("uso: wait-serial <texto>".into()),
        "wait-stop" => Step::WaitStop(match words.first() {
            Some(text) => parse_number(text).ok_or("uso: wait-stop [ms]")?,
            None => WAIT_STOP_DEFAULT_MS,
        }),
        "echo" => Step::Echo(rest.to_string()),
        "sleep" => Step::Sleep(parse_number(rest).unwrap_or(1000)),
        _ => Step::Command(line.to_string()),
    })
}

/// Separa no primeiro espaço fora de parênteses e colchetes (`expect-eq
/// poi(@rsp + 8) 4`); os dois lados precisam existir.
pub fn split_two(text: &str) -> Option<(&str, &str)> {
    let mut depth = 0i32;
    for (index, character) in text.char_indices() {
        match character {
            '[' | '(' => depth += 1,
            ']' | ')' => depth -= 1,
            _ if character.is_whitespace() && depth == 0 => {
                let (left, right) = (text[..index].trim(), text[index..].trim());
                return (!left.is_empty() && !right.is_empty()).then_some((left, right));
            }
            _ => {}
        }
    }
    None
}

/// Troca cada `$nome` conhecido pelo valor (`0x...`); um `$nome` que o
/// roteiro não salvou fica como está (o avaliador do cliente decide).
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

/// O número da coluna `column` (do 0) da N-ésima linha de `output` que
/// contém `needle` (o `save-word`).
pub fn word_value(output: &str, needle: &str, column: usize, occurrence: usize) -> Option<u64> {
    output.lines().filter(|line| line.contains(needle)).nth(occurrence.checked_sub(1)?).and_then(|line| line.split_whitespace().nth(column)).and_then(parse_number)
}

/// Os números da coluna nas linhas com o texto (os candidatos do
/// `save-thread`), na ordem da saída.
pub fn column_values(output: &str, needle: &str, column: usize) -> Vec<u64> {
    output.lines().filter(|line| line.contains(needle)).filter_map(|line| line.split_whitespace().nth(column)).filter_map(parse_number).collect()
}

/// O fim de um texto longo (as mensagens de erro do `expect-console`).
pub fn tail(text: &str, bytes: usize) -> &str {
    if text.len() <= bytes {
        return text;
    }
    let mut start = text.len() - bytes;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    &text[start..]
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
/// levou para parar, com folga (o dobro, no mínimo o padrão do kd-client),
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
    fn parses_the_test_boot_language() {
        let text = "attach\n# comentario\nc\nwait-serial lsm.dll mapeado\n\nbreak\nps\nsave-word svc svchost.exe 0 1\n.process $svc\nwait-stop 280000\nexpect-stop swbreak\nexpect-eq poi(@rsp + 8) 4\nsave-thread t ntdll.dll 2 lsm\nsleep 1500\necho fim\nwait-stop\n";
        let lines = parse(text).unwrap();
        let steps: Vec<&Step> = lines.iter().map(|line| &line.step).collect();
        assert_eq!(steps[0], &Step::Attach);
        assert_eq!(steps[1], &Step::Command("c".into()));
        assert_eq!(steps[2], &Step::WaitSerial("lsm.dll mapeado".into()));
        assert_eq!(lines[3].number, 6);
        assert_eq!(steps[5], &Step::SaveWord { name: "svc".into(), needle: "svchost.exe".into(), column: 0, occurrence: 1 });
        assert_eq!(steps[6], &Step::Command(".process $svc".into()));
        assert_eq!(steps[7], &Step::WaitStop(280_000));
        assert_eq!(steps[8], &Step::ExpectStop("swbreak".into()));
        assert_eq!(steps[9], &Step::ExpectEq("poi(@rsp + 8)".into(), "4".into()));
        assert_eq!(steps[10], &Step::SaveThread { name: "t".into(), needle: "ntdll.dll".into(), column: 2, module: "lsm".into() });
        assert_eq!(steps[11], &Step::Sleep(1500));
        assert_eq!(steps[12], &Step::Echo("fim".into()));
        assert_eq!(steps[13], &Step::WaitStop(WAIT_STOP_DEFAULT_MS));
    }

    #[test]
    fn usage_errors_come_before_running() {
        let error = parse("c\nsave-word x\nexpect-eq so_um\nwait-stop logo\nwait-serial\n").unwrap_err();
        assert!(error.contains("linha 2: save-word x"));
        assert!(error.contains("linha 3: expect-eq so_um"));
        assert!(error.contains("linha 4: wait-stop logo"));
        assert!(error.contains("linha 5: wait-serial"));
        assert!(parse("save-word x svchost 1 0").is_err());
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
    fn numbers_from_output() {
        let output = "pid 4 System\n  0x1a4  svchost.exe  0xffffa001\n  0x1b8  svchost.exe  0xffffa002\n";
        assert_eq!(word_value(output, "svchost.exe", 0, 1), Some(0x1a4));
        assert_eq!(word_value(output, "svchost.exe", 2, 2), Some(0xffffa002));
        assert_eq!(word_value(output, "svchost.exe", 1, 1), None);
        assert_eq!(word_value(output, "svchost.exe", 0, 3), None);
        assert_eq!(word_value(output, "svchost.exe", 0, 0), None);
        assert_eq!(column_values(output, "svchost", 2), vec![0xffffa001, 0xffffa002]);
        assert_eq!(split_two("x  poi(@rsp + 8)"), Some(("x", "poi(@rsp + 8)")));
        assert_eq!(split_two("so_um"), None);
        assert_eq!(tail("abcdef", 3), "def");
        assert_eq!(tail("ab", 3), "ab");
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
