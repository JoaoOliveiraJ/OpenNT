//! Seguir um processo desde a criação: os planos ("quando o dwm.exe
//! carregar o dwmcore.dll, parar em CD2DContext::InitializeD2D"), o texto
//! dos eventos do opennt-kd em estruturas (a parada `(evento #n: ...)` e a
//! linha de log `[evento #n] ...`) e a mesma regra de casamento dos
//! breakpoints de evento (`cpr:nome`, `epr:nome`, `ct:pid`, `et:pid`,
//! `ld:processo!dll`) do `check_event` do opennt-kd.
//!
//! Um plano vira um breakpoint de evento (o gatilho): `ld:processo!dll`, ou
//! `cpr:processo` sem DLL. Na parada do gatilho o backend troca o contexto
//! para o processo novo, arma os breakpoints de usuário do plano nele (com
//! o processo dono) e segue sozinho; os símbolos de módulos que ainda não
//! carregaram esperam as cargas seguintes do mesmo processo (o evento
//! auxiliar `ld:processo!`).

use opennt_kd::symbols::{base_name, display_name};

/// O uso do comando `seguir`.
pub const USAGE: &str = "uso: seguir <processo>[!<dll>] [simbolo ...] [/parar] [/uma]  (ex.: seguir dwm.exe!dwmcore.dll CD2DContext::InitializeD2D); seguir (lista); seguir -<n> (tira)";

/// Os breakpoints de evento do registro (sem parar): criação e saída de
/// qualquer processo e qualquer carga de DLL.
pub const LOG_CREATE: &str = "cpr:*";
pub const LOG_EXIT: &str = "epr:*";
pub const LOG_IMAGES: &str = "ld:*!";
/// O texto de log desses breakpoints (com log, o evento não para).
pub const LOG_MARK: &str = "(registro)";

/// O tipo de um evento do depurador do kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    ProcessCreated,
    ProcessExiting,
    ThreadCreated,
    ThreadExiting,
    Image,
}

impl EventKind {
    pub fn label(self) -> &'static str {
        match self {
            EventKind::ProcessCreated => "processo criado",
            EventKind::ProcessExiting => "processo saindo",
            EventKind::ThreadCreated => "thread criada",
            EventKind::ThreadExiting => "thread saindo",
            EventKind::Image => "imagem",
        }
    }
}

/// Um evento de processo, thread ou imagem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub kind: EventKind,
    pub pid: u64,
    /// O nome do processo (o ImageFileName do `ps`).
    pub process: String,
    pub eprocess: Option<u64>,
    pub tid: Option<u64>,
    /// A imagem carregada (o caminho do NT) e a base.
    pub path: String,
    pub base: Option<u64>,
}

impl Event {
    /// O nome do arquivo da imagem (`dwmcore.dll`).
    pub fn dll(&self) -> &str {
        base_name(&self.path)
    }

    /// O resto do evento numa linha (a imagem e a base, a thread, o
    /// EPROCESS).
    pub fn detail(&self) -> String {
        match self.kind {
            EventKind::Image => format!("{} em {}", self.path, self.base.map_or_else(|| "?".to_string(), |base| format!("{base:#x}"))),
            EventKind::ThreadCreated | EventKind::ThreadExiting => format!("TID {}", self.tid.unwrap_or(0)),
            EventKind::ProcessCreated | EventKind::ProcessExiting => self.eprocess.map_or_else(String::new, |eprocess| format!("EPROCESS {eprocess:#x}")),
        }
    }
}

fn leading_number(text: &str) -> Option<u64> {
    text.trim_start().chars().take_while(char::is_ascii_digit).collect::<String>().parse().ok()
}

fn number_after(text: &str, marker: &str) -> Option<u64> {
    let start = text.find(marker)? + marker.len();
    leading_number(&text[start..])
}

fn hex_after(text: &str, marker: &str) -> Option<u64> {
    let start = text.find(marker)? + marker.len();
    let rest = text[start..].trim_start();
    let rest = rest.strip_prefix("0x").unwrap_or(rest);
    let digits: String = rest.chars().take_while(char::is_ascii_hexdigit).collect();
    u64::from_str_radix(&digits, 16).ok()
}

/// A descrição de um evento (o texto do `check_event` do opennt-kd):
/// `processo criado NOME (PID n, EPROCESS 0x...)`, `processo saindo ...`,
/// `thread criada TID t no PID p (NOME)`, `thread saindo ...` e `imagem
/// CAMINHO em 0xBASE (tamanho 0x...) no processo NOME (PID p)`. Um texto
/// a mais no fim (o log do breakpoint) não atrapalha.
pub fn parse_description(text: &str) -> Option<Event> {
    let text = text.trim();
    for (prefix, kind) in [("processo criado ", EventKind::ProcessCreated), ("processo saindo ", EventKind::ProcessExiting)] {
        if let Some(rest) = text.strip_prefix(prefix) {
            let (name, tail) = rest.rsplit_once(" (PID ")?;
            let pid = leading_number(tail)?;
            return Some(Event { kind, pid, process: name.trim().to_string(), eprocess: hex_after(tail, "EPROCESS "), tid: None, path: String::new(), base: None });
        }
    }
    for (prefix, kind) in [("thread criada ", EventKind::ThreadCreated), ("thread saindo ", EventKind::ThreadExiting)] {
        if let Some(rest) = text.strip_prefix(prefix) {
            let tid = number_after(rest, "TID ")?;
            let pid = number_after(rest, " no PID ")?;
            let process = rest.split_once(" (").and_then(|(_, tail)| tail.split(')').next()).unwrap_or("").trim().to_string();
            return Some(Event { kind, pid, process, eprocess: None, tid: Some(tid), path: String::new(), base: None });
        }
    }
    let rest = text.strip_prefix("imagem ")?;
    let (left, right) = rest.rsplit_once(" no processo ")?;
    let (name, tail) = right.rsplit_once(" (PID ")?;
    let pid = leading_number(tail)?;
    let (path, location) = left.rsplit_once(" em 0x")?;
    let digits: String = location.chars().take_while(char::is_ascii_hexdigit).collect();
    Some(Event { kind: EventKind::Image, pid, process: name.trim().to_string(), eprocess: None, tid: None, path: path.trim().to_string(), base: u64::from_str_radix(&digits, 16).ok() })
}

/// O evento de uma parada: `... (evento #3: imagem ... (PID 500)) [T05...]`
/// (o número do breakpoint de evento que parou e o evento).
pub fn parse_stop(stop: &str) -> Option<(u32, Event)> {
    let start = stop.find("(evento #")? + "(evento #".len();
    let (id, rest) = stop[start..].split_once(": ")?;
    let id = id.trim().parse().ok()?;
    // A descrição vai até o parêntese que fecha o "(evento #".
    let mut depth = 1usize;
    let mut end = rest.len();
    for (index, character) in rest.char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end = index;
                    break;
                }
            }
            _ => {}
        }
    }
    parse_description(&rest[..end]).map(|event| (id, event))
}

/// Uma linha de evento registrado: `[evento #3] processo criado ...`.
pub fn parse_log_line(line: &str) -> Option<(u32, Event)> {
    let start = line.find("[evento #")? + "[evento #".len();
    let (id, rest) = line[start..].split_once("] ")?;
    let id = id.trim().parse().ok()?;
    parse_description(rest).map(|event| (id, event))
}

/// O nome do processo bate (sem diferença de caixa; `dwm` vale `dwm.exe`;
/// vazio e `*` valem todos).
pub fn same_process(wanted: &str, name: &str) -> bool {
    let (wanted, name) = (wanted.trim().to_ascii_lowercase(), name.to_ascii_lowercase());
    wanted.is_empty() || wanted == "*" || wanted == name || name.strip_suffix(".exe") == Some(wanted.as_str())
}

/// O nome da DLL bate (`dwmcore` vale `dwmcore.dll`; vazio vale todas).
pub fn same_dll(wanted: &str, dll: &str) -> bool {
    let (wanted, dll) = (wanted.trim().to_ascii_lowercase(), dll.to_ascii_lowercase());
    wanted.is_empty() || dll == wanted || dll.strip_suffix(".dll") == Some(wanted.as_str())
}

/// O breakpoint de evento `expression` casa com o evento (a regra do
/// `check_event` do opennt-kd).
pub fn event_matches(expression: &str, event: &Event) -> bool {
    let (code, wanted) = expression.split_once(':').unwrap_or((expression, ""));
    match (code.trim().to_ascii_lowercase().as_str(), event.kind) {
        ("cpr", EventKind::ProcessCreated) | ("epr", EventKind::ProcessExiting) => same_process(wanted, &event.process),
        ("ct", EventKind::ThreadCreated) | ("et", EventKind::ThreadExiting) => wanted.is_empty() || wanted == event.pid.to_string(),
        ("ld", EventKind::Image) => {
            let (process, dll) = wanted.split_once('!').unwrap_or(("*", wanted));
            same_process(process, &event.process) && same_dll(dll, event.dll())
        }
        _ => false,
    }
}

/// Um plano de seguir.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FollowPlan {
    /// O número (dado pelo backend).
    pub id: u32,
    /// O processo (`dwm.exe`).
    pub process: String,
    /// A DLL (`dwmcore.dll`; vazio = a criação do processo).
    pub module: String,
    /// Onde parar no processo (`dwmcore!CD2DContext::InitializeD2D`).
    pub symbols: Vec<String>,
    /// Condição e log dos breakpoints armados.
    pub condition: String,
    pub log: String,
    /// Parar também no evento (a carga ou a criação).
    pub stop_at_trigger: bool,
    /// Só a primeira vez (senão, cada processo novo com o nome).
    pub once: bool,
}

impl FollowPlan {
    /// O texto do comando: `processo[!dll] [símbolo...] [/parar] [/uma]`.
    /// Sem símbolos, o plano para no evento.
    pub fn parse(text: &str) -> Result<FollowPlan, String> {
        let mut words = text.split_whitespace();
        let target = words.next().ok_or_else(|| USAGE.to_string())?;
        let (process, module) = target.split_once('!').unwrap_or((target, ""));
        let mut plan = FollowPlan { process: process.to_string(), module: module.to_string(), ..Default::default() };
        for word in words {
            match word {
                "/parar" => plan.stop_at_trigger = true,
                "/uma" => plan.once = true,
                _ if word.starts_with('/') => return Err(format!("opcao desconhecida {word}\n{USAGE}")),
                _ => plan.symbols.push(word.to_string()),
            }
        }
        if plan.symbols.is_empty() {
            plan.stop_at_trigger = true;
        }
        plan.validate()?;
        plan.symbols = plan.qualified_symbols();
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), String> {
        let process = self.process.trim();
        if process.is_empty() {
            return Err(format!("falta o processo\n{USAGE}"));
        }
        if process.contains(|character: char| character.is_whitespace() || matches!(character, '!' | ':' | ';')) {
            return Err(format!("nome de processo invalido: {process}"));
        }
        if self.module.contains(|character: char| character.is_whitespace() || matches!(character, '!' | ':' | ';')) {
            return Err(format!("nome de DLL invalido: {}", self.module));
        }
        if self.symbols.iter().all(|symbol| symbol.trim().is_empty()) && !self.stop_at_trigger {
            return Err("sem onde parar: de um simbolo ou marque parar no evento".into());
        }
        Ok(())
    }

    /// Os símbolos com o módulo do plano na frente quando não têm um
    /// (`CD2DContext::InitializeD2D` vira `dwmcore!CD2DContext::InitializeD2D`);
    /// endereços, registros e expressões ficam como estão.
    pub fn qualified_symbols(&self) -> Vec<String> {
        let stem = display_name(self.module.trim());
        self.symbols
            .iter()
            .map(|symbol| symbol.trim())
            .filter(|symbol| !symbol.is_empty())
            .map(|symbol| {
                let plain = !stem.is_empty() && !symbol.contains('!') && !symbol.starts_with(|character: char| matches!(character, '@' | '$' | '(' | '*')) && !symbol.starts_with("0x");
                if plain {
                    format!("{stem}!{symbol}")
                } else {
                    symbol.to_string()
                }
            })
            .collect()
    }

    /// O breakpoint de evento que dispara o plano.
    pub fn trigger(&self) -> String {
        if self.module.trim().is_empty() {
            format!("cpr:{}", self.process.trim())
        } else {
            format!("ld:{}!{}", self.process.trim(), self.module.trim())
        }
    }

    /// O evento auxiliar: qualquer DLL carregada no processo (os símbolos
    /// de módulos que ainda não carregaram).
    pub fn helper(&self) -> String {
        format!("ld:{}!", self.process.trim())
    }

    pub fn triggered_by(&self, event: &Event) -> bool {
        event_matches(&self.trigger(), event)
    }

    /// O plano numa linha.
    pub fn describe(&self) -> String {
        let mut text = if self.module.trim().is_empty() { format!("{} criado", self.process) } else { format!("{} carrega {}", self.process, self.module) };
        if !self.symbols.is_empty() {
            text.push_str(&format!(" -> parar em {}", self.symbols.join(", ")));
        }
        if !self.condition.is_empty() {
            text.push_str(&format!(" se {}", self.condition));
        }
        if !self.log.is_empty() {
            text.push_str(&format!(" (log \"{}\")", self.log));
        }
        if self.stop_at_trigger {
            text.push_str(" (para no evento)");
        }
        if self.once {
            text.push_str(" (so a primeira vez)");
        }
        text
    }

    /// A linha do arquivo dos planos: processo, DLL, símbolos (`;`),
    /// condição, log e as flags (`p` para no evento, `1` uma vez só),
    /// separados por tabulação.
    pub fn to_line(&self) -> String {
        let clean = |text: &str| text.replace(['\t', '\n', '\r'], " ");
        let flags: String = [(self.stop_at_trigger, 'p'), (self.once, '1')].iter().filter(|(on, _)| *on).map(|(_, flag)| *flag).collect();
        let symbols: Vec<String> = self.symbols.iter().map(|symbol| clean(symbol).replace(';', " ")).collect();
        format!("{}\t{}\t{}\t{}\t{}\t{flags}", clean(&self.process), clean(&self.module), symbols.join(";"), clean(&self.condition), clean(&self.log))
    }

    pub fn from_line(line: &str) -> Option<FollowPlan> {
        let fields: Vec<&str> = line.split('\t').collect();
        let process = fields.first()?.trim();
        if process.is_empty() || process.starts_with('#') {
            return None;
        }
        let field = |index: usize| fields.get(index).map_or("", |text| text.trim()).to_string();
        let flags = field(5);
        let plan = FollowPlan {
            id: 0,
            process: process.to_string(),
            module: field(1),
            symbols: field(2).split(';').map(str::trim).filter(|symbol| !symbol.is_empty()).map(String::from).collect(),
            condition: field(3),
            log: field(4),
            stop_at_trigger: flags.contains('p'),
            once: flags.contains('1'),
        };
        plan.validate().ok().map(|_| plan)
    }
}

/// O arquivo dos planos (`<build>/opennt-re/seguir.txt`).
pub fn plans_to_text(plans: &[FollowPlan]) -> String {
    let mut text = String::from("# opennt-re: planos de seguir (processo, dll, simbolos, condicao, log, flags: p = para no evento, 1 = uma vez)\n");
    for plan in plans {
        text.push_str(&plan.to_line());
        text.push('\n');
    }
    text
}

pub fn plans_from_text(text: &str) -> Vec<FollowPlan> {
    text.lines().filter_map(FollowPlan::from_line).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE_STOP: &str = "parado: SIGTRAP swbreak (CPU 0) em 0xfffff80040123456 opennt_kd_image_event (evento #3: imagem \\SystemRoot\\System32\\dwmcore.dll em 0x7ffd12340000 (tamanho 0x3a0000) no processo dwm.exe (PID 500)) [T05thread:1;swbreak:;]";

    #[test]
    fn parses_stops_and_log_lines() {
        let (id, event) = parse_stop(IMAGE_STOP).unwrap();
        assert_eq!(id, 3);
        assert_eq!(event.kind, EventKind::Image);
        assert_eq!(event.pid, 500);
        assert_eq!(event.process, "dwm.exe");
        assert_eq!(event.path, "\\SystemRoot\\System32\\dwmcore.dll");
        assert_eq!(event.dll(), "dwmcore.dll");
        assert_eq!(event.base, Some(0x7ffd_1234_0000));
        let created = "parado: SIGTRAP swbreak em 0x1 opennt_kd_process_event (evento #7: processo criado LogonUI.exe (PID 492, EPROCESS 0xffffc000c0123d20)) [T05]";
        let (id, event) = parse_stop(created).unwrap();
        assert_eq!((id, event.kind, event.pid, event.process.as_str(), event.eprocess), (7, EventKind::ProcessCreated, 492, "LogonUI.exe", Some(0xffff_c000_c012_3d20)));
        let line = "[evento #9] processo saindo dwm.exe (PID 504, EPROCESS 0xffffc000c0127900) (registro)";
        let (id, event) = parse_log_line(line).unwrap();
        assert_eq!((id, event.kind, event.pid, event.eprocess), (9, EventKind::ProcessExiting, 504, Some(0xffff_c000_c012_7900)));
        let line = "[evento #2] imagem \\Program Files (x86)\\a.dll em 0x10000 (tamanho 0x1000) no processo app.exe (PID 12) (registro)";
        let (_, event) = parse_log_line(line).unwrap();
        assert_eq!((event.path.as_str(), event.process.as_str(), event.pid, event.base), ("\\Program Files (x86)\\a.dll", "app.exe", 12, Some(0x10000)));
        let thread = parse_description("thread criada TID 540 no PID 492 (LogonUI.exe)").unwrap();
        assert_eq!((thread.kind, thread.tid, thread.pid, thread.process.as_str()), (EventKind::ThreadCreated, Some(540), 492, "LogonUI.exe"));
        assert!(parse_stop("parado: SIGTRAP swbreak (breakpoint #1, acerto 1)").is_none());
        assert!(parse_log_line("[bp #1] acerto 1").is_none());
    }

    #[test]
    fn matches_like_the_client() {
        let (_, image) = parse_stop(IMAGE_STOP).unwrap();
        assert!(event_matches("ld:dwm.exe!dwmcore.dll", &image));
        assert!(event_matches("ld:dwm!dwmcore", &image));
        assert!(event_matches("LD:DWM.EXE!DWMCORE.DLL", &image));
        assert!(event_matches("ld:*!", &image));
        assert!(event_matches("ld:dwm.exe!", &image));
        assert!(event_matches("ld:dwmcore.dll", &image));
        assert!(!event_matches("ld:logonui.exe!dwmcore.dll", &image));
        assert!(!event_matches("ld:dwm.exe!d2d1.dll", &image));
        assert!(!event_matches("cpr:dwm.exe", &image));
        let created = parse_description("processo criado dwm.exe (PID 500, EPROCESS 0x1)").unwrap();
        assert!(event_matches("cpr", &created));
        assert!(event_matches("cpr:*", &created));
        assert!(event_matches("cpr:dwm", &created));
        assert!(!event_matches("epr:dwm.exe", &created));
        let thread = parse_description("thread saindo TID 7 no PID 500 (dwm.exe)").unwrap();
        assert!(event_matches("et:500", &thread));
        assert!(!event_matches("et:501", &thread));
    }

    #[test]
    fn plans() {
        let plan = FollowPlan::parse("dwm.exe!dwmcore.dll CD2DContext::InitializeD2D d2d1!D2D1CreateFactory $iment(dwmcore) 0x7ffd1234 /uma").unwrap();
        assert_eq!(plan.process, "dwm.exe");
        assert_eq!(plan.module, "dwmcore.dll");
        assert_eq!(plan.symbols, vec!["dwmcore!CD2DContext::InitializeD2D", "d2d1!D2D1CreateFactory", "$iment(dwmcore)", "0x7ffd1234"]);
        assert!(plan.once && !plan.stop_at_trigger);
        assert_eq!(plan.trigger(), "ld:dwm.exe!dwmcore.dll");
        assert_eq!(plan.helper(), "ld:dwm.exe!");
        let (_, image) = parse_stop(IMAGE_STOP).unwrap();
        assert!(plan.triggered_by(&image));
        // Sem símbolos: para no evento; sem DLL: a criação.
        let plan = FollowPlan::parse("LogonUI.exe").unwrap();
        assert!(plan.stop_at_trigger);
        assert_eq!(plan.trigger(), "cpr:LogonUI.exe");
        assert!(FollowPlan::parse("").is_err());
        assert!(FollowPlan::parse("dwm.exe /x").is_err());
        assert!(FollowPlan { process: "dwm.exe".into(), ..Default::default() }.validate().is_err());
        assert!(FollowPlan { process: "dw m".into(), stop_at_trigger: true, ..Default::default() }.validate().is_err());
    }

    #[test]
    fn plan_file_round_trip() {
        let plans = vec![
            FollowPlan { id: 4, process: "dwm.exe".into(), module: "dwmcore.dll".into(), symbols: vec!["dwmcore!CD2DContext::InitializeD2D".into(), "dwmcore!MilFailFastForHR".into()], condition: "@rcx != 0".into(), log: "hr={@rcx}".into(), stop_at_trigger: false, once: true },
            FollowPlan { id: 5, process: "LogonUI.exe".into(), stop_at_trigger: true, ..Default::default() },
        ];
        let text = plans_to_text(&plans);
        let back = plans_from_text(&text);
        assert_eq!(back.len(), 2);
        assert_eq!(back[0], FollowPlan { id: 0, ..plans[0].clone() });
        assert_eq!(back[1], FollowPlan { id: 0, ..plans[1].clone() });
        assert!(back[0].describe().contains("dwm.exe carrega dwmcore.dll -> parar em dwmcore!CD2DContext::InitializeD2D"));
    }
}
