//! As ferramentas do fluxo de depuração dos agentes: continuar até uma
//! parada ou um texto da COM1, o breakpoint de usuário pelo nome do
//! processo (adiado até a DLL carregar), as pilhas de kernel e de usuário
//! (agrupadas por pilha igual), a memória em formatos e os roteiros do
//! depurador com o log na resposta.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use kd_client::client::{BreakpointOptions, BreakpointRequest};
use kd_client::types;
use kd_client::unwind::Frame;
use kd_client::user::UserThread;
use kd_client::{BreakpointKind, Client};
use serde_json::{json, Map, Value};

use super::{boolean, breakpoint_value, finish_stop, hex, integer, object, set_process_argument, stop_value, text, timeout, Arguments, ToolError, ToolResult};
use crate::engine::Engine;
use crate::kdscript;
use crate::processes;
use crate::serial::{self, Found, Watch};
use crate::session::Session;

/// Threads de um processo na ferramenta `stack` no máximo.
const MAX_STACK_THREADS: usize = 96;

/// As definições (nome, descrição, esquema).
pub fn definitions() -> Vec<(&'static str, &'static str, Value)> {
    let process = || text("processo pelo nome (dwm.exe, svchost.exe#2 = a segunda instancia), PID ou EPROCESS");
    vec![
        (
            "continue_until",
            "Continua a maquina e espera o primeiro destes: uma parada (breakpoint, excecao, passo), um texto na COM1 (marker/markers) ou o prazo. Atende sozinho os breakpoints de log (seguem) e os adiados de usuario (armados quando a DLL carrega). Devolve o motivo (breakpoint, event, stop, serial, timeout), a parada, as linhas novas dos breakpoints de log e do DbgPrint e os adiados armados.",
            object(
                json!({
                    "marker": text("texto esperado na COM1 (o serial.log do build)"),
                    "markers": {"type": "array", "items": {"type": "string"}, "description": "varios textos: vale o primeiro que aparecer"},
                    "from_start": boolean("procura o texto no log inteiro, nao so no que chegar (padrao false); ja estando la, volta sem continuar"),
                    "break_on_marker": boolean("para a maquina quando o texto aparece (padrao true)"),
                    "break_on_timeout": boolean("no fim do prazo, para a maquina e devolve a parada em vez do erro (padrao false)"),
                    "max_log_lines": integer("linhas novas do log dos breakpoints no resultado (padrao 40)", 0, 5000),
                    "timeout_ms": timeout(300_000)
                }),
                &[],
            ),
        ),
        (
            "breakpoint_user",
            "Breakpoint de software no codigo de um processo de usuario, pelo nome do processo (dwm.exe, svchost.exe#2) ou PID: escolhe o processo, rele os modulos dele e arma. Se a DLL ainda nao carregou nele (ou o processo ainda nao existe), fica adiado e arma sozinho quando ela carregar (continue_until, wait_for_stop e kd_script atendem o aviso). Com log e sem condicao, so registra e segue.",
            object(
                json!({
                    "process": process(),
                    "address": text("modulo!simbolo[+deslocamento] (d2d1!DoStackCapture, dwmcore!CD2DContext::PopulateEffectTable+0x96) ou endereco"),
                    "condition": text("para so quando a expressao der diferente de zero"),
                    "log": text("texto de log ({expr}, {expr:d}, {expr:s}); sem condicao, so registra e segue"),
                    "log_condition": text("o log so sai com esta condicao verdadeira"),
                    "command": text("comandos do depurador separados por ; (rodam na parada)"),
                    "name": text("nome do breakpoint"),
                    "pass_count": integer("para a partir deste acerto", 0, 1_000_000),
                    "single_shot": boolean("some depois da primeira parada"),
                    "silent": boolean("sem a linha de acerto no log")
                }),
                &["process", "address"],
            ),
        ),
        (
            "stack",
            "Pilhas. Sem argumentos: a do processador da parada. thread (ETHREAD): a de uma thread de kernel. process: as threads de usuario do processo (a pilha de usuario pelo CONTEXT salvo e, com kernel, a de kernel), agrupadas por pilha igual; tid: so essa thread. Cada quadro e 'endereco simbolo'.",
            object(
                json!({
                    "process": process(),
                    "tid": integer("TID de uma thread do processo", 0, u32::MAX as u64),
                    "thread": text("ETHREAD (expressao) de uma thread de kernel"),
                    "kernel": boolean("inclui a pilha de kernel das threads de usuario (padrao true)"),
                    "limit": integer("quadros por pilha (padrao 24)", 1, 256)
                }),
                &[],
            ),
        ),
        (
            "memory_view",
            "Le memoria (kernel ou de um processo) num formato: bytes (com ASCII), words, dwords, qwords, pointers (cada qword com o simbolo, como o dps), ascii e unicode (cadeias ate o NUL) ou unicode_string (um UNICODE_STRING: tamanhos, Buffer e o texto).",
            object(
                json!({
                    "address": text("expressao do endereco"),
                    "format": {"type": "string", "enum": ["bytes", "words", "dwords", "qwords", "pointers", "ascii", "unicode", "unicode_string"], "description": "formato (padrao qwords)"},
                    "count": integer("unidades (padrao 16; nas cadeias, caracteres no maximo)", 1, 4096),
                    "process": process()
                }),
                &["address"],
            ),
        ),
        (
            "kd_script",
            "Roda um roteiro do depurador na linguagem do cargo xtask test-boot --kd=com2 --script (bp/bu com /log, c, wait-stop, wait-serial, break, ps, save-word, .process $x, r, k, db, expect...) sobre esta sessao e devolve o log. wait-serial e wait-stop atendem as paradas; $nome vira o valor salvo; attach e ignorado. A primeira linha que falha encerra (ok=false, com o log ate ela e o erro).",
            object(
                json!({
                    "script": text("o roteiro"),
                    "path": text("ou o arquivo do roteiro (relativo a raiz do repositorio)"),
                    "max_log_lines": integer("ultimas linhas do log no resultado (padrao 300)", 1, 20_000),
                    "timeout_ms": timeout(600_000)
                }),
                &[],
            ),
        ),
    ]
}

/// Roda uma das ferramentas deste módulo (`None`: não é daqui).
pub fn run(engine: &mut dyn Engine, session: &mut Session, name: &str, args: &Arguments) -> Option<ToolResult> {
    Some(match name {
        "continue_until" => run_until(engine, session, &Until::from_arguments(args)),
        "breakpoint_user" => breakpoint_user(engine, session, args).map_err(ToolError::Failed),
        "stack" => stack(engine, args).map_err(ToolError::Failed),
        "memory_view" => memory_view(engine, args).map_err(ToolError::Failed),
        "kd_script" => kd_script(engine, session, args),
        _ => return None,
    })
}

/// O que esperar com a máquina rodando.
pub(super) struct Until {
    pub markers: Vec<String>,
    pub from_start: bool,
    pub break_on_marker: bool,
    pub break_on_timeout: bool,
    pub max_log_lines: usize,
    pub timeout: Duration,
}

impl Until {
    fn from_arguments(args: &Arguments) -> Until {
        let mut markers = args.list("markers");
        if let Some(marker) = args.text("marker") {
            markers.insert(0, marker);
        }
        Until {
            markers,
            from_start: args.flag("from_start").unwrap_or(false),
            break_on_marker: args.flag("break_on_marker").unwrap_or(true),
            break_on_timeout: args.flag("break_on_timeout").unwrap_or(false),
            max_log_lines: args.integer("max_log_lines").unwrap_or(40) as usize,
            timeout: args.timeout(300_000),
        }
    }
}

/// O que chegou junto com a parada: as linhas novas dos breakpoints de
/// log, o DbgPrint novo, os adiados armados e o tempo.
fn report(mut value: Value, session: &mut Session, client: &Client, max_lines: usize, started: Instant) -> Value {
    let (log, count) = session.new_log_lines(client, max_lines);
    if count > 0 {
        value["log"] = json!(log);
        value["log_new"] = json!(count);
    }
    let console = session.new_console(client, 2048);
    if !console.trim().is_empty() {
        value["dbgprint"] = json!(console);
    }
    if !session.armed.is_empty() {
        value["armed"] = json!(std::mem::take(&mut session.armed));
    }
    value["elapsed_ms"] = json!(started.elapsed().as_millis() as u64);
    value
}

/// O texto achado na COM1 (com a máquina parada, se pedido).
fn marker_result(client: &mut Client, until: &Until, found: &Found) -> Result<Value, String> {
    let mut value = if client.is_stopped() {
        let stop = client.last_stop().to_string();
        stop_value(client, &stop)
    } else if until.break_on_marker {
        let stop = client.break_in(Duration::from_secs(60))?;
        finish_stop(client, &stop)
    } else {
        json!({"stopped": false})
    };
    value["reason"] = json!("serial");
    value["marker"] = json!(found.marker);
    value["line"] = json!(found.line);
    value["serial_offset"] = json!(found.offset);
    Ok(value)
}

/// Continua até uma parada, um texto da COM1 ou o prazo (o
/// `continue_until` e o `launch` com `until_marker`).
pub(super) fn run_until(engine: &mut dyn Engine, session: &mut Session, until: &Until) -> ToolResult {
    let started = Instant::now();
    let deadline = started + until.timeout;
    let markers: Vec<String> = until.markers.iter().filter(|marker| !marker.is_empty()).cloned().collect();
    let log = session.serial_path(engine);
    let mut watch = match (log, markers.is_empty()) {
        (_, true) => None,
        (Some(path), false) => {
            let from = if until.from_start { 0 } else { serial::size(&path) };
            Some(Watch::new(path, from))
        }
        (None, false) => return Err(ToolError::Failed("log da COM1 desconhecido para esperar texto (launch, ou connect com serial_log)".into())),
    };
    let client = engine.client()?;
    // O texto já no log (from_start): volta sem continuar.
    if let Some(found) = watch.as_mut().and_then(|watch| watch.poll(&markers)) {
        let value = marker_result(client, until, &found)?;
        return Ok(report(value, session, client, until.max_log_lines, started));
    }
    if client.is_stopped() {
        client.go()?;
    }
    loop {
        if let Some(stop) = client.poll(Duration::from_millis(100))? {
            if session.service_stop(client) {
                client.go()?;
                continue;
            }
            let mut value = finish_stop(client, &stop);
            let reason = if stop.contains("(breakpoint #") {
                "breakpoint"
            } else if stop.contains("(evento #") || stop.contains("(modulo carregado") {
                "event"
            } else {
                "stop"
            };
            value["reason"] = json!(reason);
            return Ok(report(value, session, client, until.max_log_lines, started));
        }
        if let Some(found) = watch.as_mut().and_then(|watch| watch.poll(&markers)) {
            let value = marker_result(client, until, &found)?;
            return Ok(report(value, session, client, until.max_log_lines, started));
        }
        if Instant::now() >= deadline {
            if until.break_on_timeout {
                let stop = client.break_in(Duration::from_secs(60))?;
                let mut value = finish_stop(client, &stop);
                value["reason"] = json!("timeout");
                return Ok(report(value, session, client, until.max_log_lines, started));
            }
            let (log, count) = session.new_log_lines(client, 8);
            let recent = if count == 0 { String::new() } else { format!("; {count} linhas novas de log, as ultimas: {}", log.join(" | ")) };
            let what = if markers.is_empty() { "" } else { " nem o texto na COM1" };
            return Err(ToolError::Failed(format!("tempo esgotado ({} ms) sem parada{what}; a maquina segue rodando{recent}", until.timeout.as_millis())));
        }
    }
}

/// O pedido de um breakpoint de usuário pelos argumentos.
fn user_request(args: &Arguments, expression: &str) -> BreakpointRequest {
    let mut request = BreakpointRequest::new(BreakpointKind::Software, expression);
    request.condition = args.text("condition").unwrap_or_default();
    request.log = args.text("log").unwrap_or_default();
    request.command = args.text("command").unwrap_or_default();
    request.pass_count = args.integer("pass_count").unwrap_or(0);
    request.options = BreakpointOptions {
        name: args.text("name").unwrap_or_default(),
        log_condition: args.text("log_condition").unwrap_or_default(),
        command_condition: String::new(),
        single_shot: args.flag("single_shot").unwrap_or(false),
        silent: args.flag("silent").unwrap_or(false),
        fast_resume: false,
    };
    request
}

fn breakpoint_user(engine: &mut dyn Engine, session: &mut Session, args: &Arguments) -> Result<Value, String> {
    let client = engine.client()?;
    let wanted = args.text("process").unwrap_or_default();
    let expression = args.text("address").unwrap_or_default();
    let module = expression.split_once('!').map(|(module, _)| module.trim().to_string()).filter(|module| !module.is_empty());
    let request = user_request(args, &expression);
    let process_name = match processes::find(client, &wanted)? {
        Some(process) => {
            client.set_process(Some(&format!("{:#x}", process.eprocess)))?;
            let _ = client.reload_user_modules();
            let label = format!("{} (PID {})", process.name, process.pid);
            let mut armed = request.clone();
            armed.process = process.eprocess;
            match client.add_breakpoint_with(&armed) {
                Ok(breakpoint) => return Ok(json!({"armed": true, "process": label, "breakpoint": breakpoint_value(client, &breakpoint)})),
                Err(error) => {
                    let missing = error.contains("nao carregado") || error.contains("nao encontrado");
                    if !missing || module.is_none() {
                        return Err(error);
                    }
                    let loaded = module.as_deref().is_some_and(|name| client.symbols.module_named(name).is_some_and(|found| found.user));
                    if loaded {
                        return Err(format!("{error} (o modulo ja esta carregado em {label}: simbolo errado, ou o PDB ainda chegando; tente de novo)"));
                    }
                    process.name.clone()
                }
            }
        }
        None => {
            if module.is_none() {
                return Err(format!("processo {wanted} nao esta rodando; o breakpoint adiado precisa de modulo!simbolo"));
            }
            let processes::Wanted::Name { name, .. } = processes::parse(&wanted)? else { return Err(format!("processo {wanted} nao encontrado")) };
            name
        }
    };
    let module = module.unwrap_or_default();
    let event = session.add_pending(client, &process_name, &module, request)?;
    Ok(json!({
        "armed": false,
        "pending": true,
        "process": process_name,
        "module": module,
        "event_breakpoint": event,
        "waits_for": format!("ld:{process_name}!{module}"),
        "note": "arma quando o modulo carregar num processo com esse nome; continue_until, wait_for_stop e kd_script atendem o aviso de carga",
    }))
}

/// Cada quadro em uma linha: endereço e símbolo.
fn frame_lines(client: &Client, frames: &[Frame]) -> Vec<String> {
    frames.iter().map(|frame| format!("{:#x} {}", frame.address, client.frame_name(frame))).collect()
}

fn stack(engine: &mut dyn Engine, args: &Arguments) -> Result<Value, String> {
    let client = engine.client()?;
    let limit = args.integer("limit").unwrap_or(24) as usize;
    if let Some(thread) = args.text("thread") {
        let ethread = client.evaluate(&thread)?;
        let (context, frames) = client.thread_backtrace(ethread, limit)?;
        return Ok(json!({"thread": hex(ethread), "header": context.header, "frames": frame_lines(client, &frames)}));
    }
    let Some(wanted) = args.text("process") else {
        let frames = client.backtrace(limit)?;
        let user_mode = client.stopped_in_user_mode();
        let process = client.process().map(|context| format!("{} (PID {})", context.name, context.pid));
        return Ok(json!({"cpu": true, "user_mode": user_mode, "process": process, "frames": frame_lines(client, &frames)}));
    };
    let process = processes::resolve(client, &wanted)?;
    let target = format!("{:#x}", process.eprocess);
    client.set_process(Some(&target))?;
    let threads = client.user_threads(&target)?;
    let selected: Vec<UserThread> = match args.integer("tid") {
        Some(tid) => vec![threads.iter().find(|thread| thread.tid == tid).cloned().ok_or_else(|| format!("thread {tid} nao e de {} (PID {})", process.name, process.pid))?],
        None => threads,
    };
    let with_kernel = args.flag("kernel").unwrap_or(true);
    // Threads com a mesma pilha (de kernel e de usuário) ficam juntas.
    let mut groups: Vec<(Vec<String>, Vec<String>, Vec<Value>)> = Vec::new();
    for thread in selected.iter().take(MAX_STACK_THREADS) {
        let user = match client.user_thread_backtrace(thread, limit) {
            Ok((_, frames)) => frame_lines(client, &frames),
            Err(error) => vec![format!("(sem pilha de usuario: {error})")],
        };
        let kernel = if with_kernel {
            match client.thread_backtrace(thread.ethread, limit) {
                Ok((_, frames)) => frame_lines(client, &frames),
                Err(error) => vec![format!("(sem pilha de kernel: {error})")],
            }
        } else {
            Vec::new()
        };
        let info = json!({"tid": thread.tid, "state": thread.state, "wait": thread.wait_reason});
        match groups.iter_mut().find(|group| group.0 == kernel && group.1 == user) {
            Some(group) => group.2.push(info),
            None => groups.push((kernel, user, vec![info])),
        }
    }
    let stacks: Vec<Value> = groups
        .into_iter()
        .map(|(kernel, user, threads)| {
            let mut value = json!({"threads": threads, "user": user});
            if !kernel.is_empty() {
                value["kernel"] = json!(kernel);
            }
            value
        })
        .collect();
    Ok(json!({"process": format!("{} (PID {})", process.name, process.pid), "threads": selected.len(), "shown": selected.len().min(MAX_STACK_THREADS), "stacks": stacks}))
}

fn memory_view(engine: &mut dyn Engine, args: &Arguments) -> Result<Value, String> {
    let client = engine.client()?;
    set_process_argument(client, args)?;
    let address = client.evaluate(&args.text("address").unwrap_or_default())?;
    let format = args.text("format").unwrap_or_else(|| "qwords".into());
    let count = args.integer("count").unwrap_or(16).max(1) as usize;
    match format.as_str() {
        "ascii" | "unicode" => {
            let text = if format == "ascii" { types::read_narrow(client, address, count) } else { types::read_wide(client, address, count * 2) };
            Ok(json!({"address": hex(address), "format": format, "text": text.ok_or("memoria ilegivel")?}))
        }
        "unicode_string" => {
            let header = client.read_memory(address, 16)?;
            if header.len() < 16 {
                return Err(format!("{address:#x}: UNICODE_STRING ilegivel"));
            }
            let length = u16::from_le_bytes([header[0], header[1]]);
            let maximum = u16::from_le_bytes([header[2], header[3]]);
            let buffer = u64::from_le_bytes(header[8..16].try_into().unwrap_or([0; 8]));
            let text = types::read_unicode_string(client, address);
            Ok(json!({"address": hex(address), "format": format, "length": length, "maximum_length": maximum, "buffer": hex(buffer), "text": text}))
        }
        "pointers" => {
            let bytes = client.read_memory(address, count * 8)?;
            let rows: Vec<String> = bytes
                .chunks_exact(8)
                .enumerate()
                .map(|(index, chunk)| {
                    let value = u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]));
                    let at = address + index as u64 * 8;
                    match client.symbols.module_at(value) {
                        Some(_) => format!("{at:#x}: {value:#018x} {}", client.symbols.describe(value)),
                        None => format!("{at:#x}: {value:#018x}"),
                    }
                })
                .collect();
            Ok(json!({"address": hex(address), "format": format, "rows": rows}))
        }
        _ => {
            let size = match format.as_str() {
                "bytes" => 1,
                "words" => 2,
                "dwords" => 4,
                _ => 8,
            };
            let bytes = client.read_memory(address, count * size)?;
            let rows: Vec<String> = bytes
                .chunks(16)
                .enumerate()
                .map(|(row, chunk)| {
                    let at = address + row as u64 * 16;
                    let units: Vec<String> = chunk
                        .chunks(size)
                        .map(|unit| {
                            let mut raw = [0u8; 8];
                            raw[..unit.len()].copy_from_slice(unit);
                            format!("{:0width$x}", u64::from_le_bytes(raw), width = size * 2)
                        })
                        .collect();
                    if size == 1 {
                        let ascii: String = chunk.iter().map(|&byte| if (0x20..0x7F).contains(&byte) { byte as char } else { '.' }).collect();
                        format!("{at:#x}: {}  {ascii}", units.join(" "))
                    } else {
                        format!("{at:#x}: {}", units.join(" "))
                    }
                })
                .collect();
            Ok(json!({"address": hex(address), "format": format, "length": bytes.len(), "rows": rows}))
        }
    }
}

fn kd_script(engine: &mut dyn Engine, session: &mut Session, args: &Arguments) -> ToolResult {
    let script = match (args.text("script"), args.text("path")) {
        (Some(script), None) => script,
        (None, Some(path)) => {
            let path = PathBuf::from(path);
            let path = if path.is_absolute() { path } else { engine.root().join(path) };
            std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?
        }
        (Some(_), Some(_)) => return Err(ToolError::InvalidParams("kd_script: script ou path, nao os dois".into())),
        (None, None) => return Err(ToolError::InvalidParams("kd_script: falta script ou path".into())),
    };
    let started = Instant::now();
    let max_lines = args.integer("max_log_lines").unwrap_or(300) as usize;
    let options = kdscript::Options { serial: session.serial_path(engine), deadline: started + args.timeout(600_000) };
    let client = engine.client()?;
    // O log dos breakpoints da resposta é só o deste roteiro.
    session.mark_seen(client);
    let report = kdscript::run(client, session, &script, &options);
    let total = report.log.len() + report.dropped;
    let skip = report.log.len().saturating_sub(max_lines);
    let variables: Map<String, Value> = report.variables.iter().map(|(name, value)| (name.clone(), json!(hex(*value)))).collect();
    let mut value = json!({
        "ok": report.ok,
        "commands": report.commands,
        "log": report.log[skip..],
        "log_lines": total,
        "variables": variables,
        "stopped": client.is_stopped(),
    });
    if let Some(error) = &report.error {
        value["error"] = json!(error);
        value["failed_line"] = json!(report.failed_line);
    }
    if skip > 0 || report.dropped > 0 {
        value["log_truncated"] = json!(true);
    }
    if client.is_stopped() {
        value["last_stop"] = json!(client.last_stop().split(" [").next().unwrap_or(""));
    }
    let (log, count) = session.new_log_lines(client, 200);
    if count > 0 {
        value["breakpoint_log"] = json!(log);
        value["breakpoint_log_new"] = json!(count);
    }
    if !session.armed.is_empty() {
        value["armed"] = json!(std::mem::take(&mut session.armed));
    }
    value["elapsed_ms"] = json!(started.elapsed().as_millis() as u64);
    Ok(value)
}
