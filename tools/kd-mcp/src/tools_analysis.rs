//! As ferramentas de análise: os códigos de erro (NTSTATUS, HRESULT e
//! Win32), a busca de símbolos pelo trecho do nome, o resumo do log da
//! COM1, a queda (o bugcheck da parada e os blocos de queda do log) e o
//! WdLog do dxgkrnl. As de log funcionam sem sessão, sobre qualquer
//! `serial.log` (`path`).

use std::path::PathBuf;

use serde_json::{json, Value};

use super::{boolean, hex, integer, object, set_process_argument, text, Arguments, ToolError, ToolResult};
use crate::engine::Engine;
use crate::serial::{self, SummaryOptions};
use crate::session::Session;
use crate::status;

/// As definições (nome, descrição, esquema).
pub fn definitions() -> Vec<(&'static str, &'static str, Value)> {
    let path = || text("um log da COM1 qualquer (o serial.log de outro build ou de outra rodada); vazio = o da sessao");
    vec![
        (
            "status_decode",
            "Decodifica codigos de erro do Windows: NTSTATUS (0xC0000034), HRESULT (0x80070578, com HRESULT_FROM_WIN32 e HRESULT_FROM_NT) e erros do Win32 (87, decimal): nome, severidade, facilidade e a leitura mais provavel (best). Nao precisa de sessao.",
            object(json!({"code": text("um codigo: 0x..., hexadecimal, decimal ou negativo"), "codes": {"type": "array", "items": {"type": "string"}, "description": "varios codigos (ate 64)"}}), &[]),
        ),
        (
            "symbol_search",
            "Procura simbolos pelo trecho do nome (sem caixa) nos modulos carregados: o kernel, os drivers e, com process, os de usuario do processo. Devolve 'endereco modulo!nome'.",
            object(
                json!({
                    "pattern": text("trecho do nome (CreateWindowEx, DoStackCapture, ps::create)"),
                    "module": text("so neste modulo"),
                    "process": text("processo pelo nome, PID ou EPROCESS (os modulos de usuario dele)"),
                    "limit": integer("resultados (padrao 50)", 1, 2000)
                }),
                &["pattern"],
            ),
        ),
        (
            "serial_summary",
            "Resume um log da COM1: os marcadores *_OK (e o ultimo), os processos criados, as quedas de processo ([crash]) e do kernel ([kcrash]), o bugcheck, se ha WdLog do dxgkrnl, as falhas mais repetidas (agrupadas por padrao), as etiquetas mais frequentes e as ultimas linhas; grep acha linhas. Funciona sem sessao com path.",
            object(
                json!({
                    "path": path(),
                    "since_offset": integer("so a partir deste byte (o end_offset de um resumo anterior)", 0, u64::MAX >> 1),
                    "tail": integer("ultimas linhas (padrao 20)", 0, 2000),
                    "grep": text("linhas com este texto (sem caixa)"),
                    "grep_limit": integer("linhas do grep (padrao 50)", 1, 5000),
                    "failures": integer("padroes de falha (padrao 15)", 0, 500)
                }),
                &[],
            ),
        ),
        (
            "crash_analyze",
            "A queda. Com a maquina parada num bugcheck: o !analyze (codigo, parametros explicados, driver culpado, pilha). Do log da COM1: os blocos [crash] (processo de usuario: excecao e pilha) e [kcrash] (parada no KeBugCheck), o codigo de parada e se ha WdLog. Funciona sem sessao com path.",
            object(json!({"path": path(), "live": boolean("analisa a parada da sessao (padrao true; ignorado com path)")}), &[]),
        ),
        (
            "wdlog",
            "O WdLog do dxgkrnl (os aneis de erros, avisos e eventos que o bugcheck despeja na COM1 como dados secundarios): se o log tem o despejo, quantos registros e pedacos, e os aneis decodificados quando a analise de WdLog do kd-client estiver ligada.",
            object(json!({"path": path()}), &[]),
        ),
    ]
}

/// Roda uma das ferramentas deste módulo (`None`: não é daqui).
pub fn run(engine: &mut dyn Engine, session: &mut Session, name: &str, args: &Arguments) -> Option<ToolResult> {
    Some(match name {
        "status_decode" => status_decode(args),
        "symbol_search" => symbol_search(engine, args).map_err(ToolError::Failed),
        "serial_summary" => serial_summary(engine, session, args).map_err(ToolError::Failed),
        "crash_analyze" => crash_analyze(engine, session, args).map_err(ToolError::Failed),
        "wdlog" => wdlog(engine, session, args).map_err(ToolError::Failed),
        _ => return None,
    })
}

fn status_decode(args: &Arguments) -> ToolResult {
    let mut codes = args.list("codes");
    if let Some(code) = args.text("code") {
        codes.insert(0, code);
    }
    if codes.is_empty() {
        return Err(ToolError::InvalidParams("status_decode: falta code ou codes".into()));
    }
    let results: Vec<Value> = codes
        .iter()
        .take(64)
        .map(|code| match status::parse_code(code) {
            Ok(value) => {
                let mut decoded = status::decode(value);
                decoded["input"] = json!(code);
                decoded
            }
            Err(error) => json!({"input": code, "error": error}),
        })
        .collect();
    Ok(json!({"results": results}))
}

fn symbol_search(engine: &mut dyn Engine, args: &Arguments) -> Result<Value, String> {
    let client = engine.client()?;
    set_process_argument(client, args)?;
    let pattern = args.text("pattern").unwrap_or_default().to_ascii_lowercase();
    let limit = args.integer("limit").unwrap_or(50) as usize;
    let symbols = &client.symbols;
    let only = match args.text("module") {
        Some(name) => Some(symbols.module_named(&name).ok_or_else(|| format!("modulo {name} nao carregado"))?.base),
        None => None,
    };
    let mut results = Vec::new();
    let mut total = 0usize;
    for module in symbols.modules.iter().filter(|module| only.is_none_or(|base| module.base == base)) {
        let prefix = if symbols.is_kernel(module) { String::new() } else { format!("{}!", module.name) };
        for symbol in module.symbols.iter().filter(|symbol| symbol.name.to_ascii_lowercase().contains(&pattern)) {
            total += 1;
            if results.len() < limit {
                results.push(format!("{:#x} {prefix}{}", symbol.address, symbol.name));
            }
        }
    }
    Ok(json!({"pattern": pattern, "matches": total, "results": results}))
}

/// O texto de um log a partir de `offset`: o do `path` pedido ou o da
/// sessão. Devolve o caminho, o texto, o começo e o fim lidos.
fn log_text(engine: &dyn Engine, session: &Session, args: &Arguments, offset: u64) -> Result<(PathBuf, String, u64, u64), String> {
    let path = match args.text("path") {
        Some(path) => {
            let path = PathBuf::from(path);
            if path.is_absolute() {
                path
            } else {
                engine.root().join(path)
            }
        }
        None => session.serial_path(engine).ok_or("log da COM1 desconhecido: passe path, ou use launch/connect com serial_log")?,
    };
    let start = offset.min(serial::size(&path));
    let bytes = serial::read_from(&path, start)?;
    let end = start + bytes.len() as u64;
    Ok((path, String::from_utf8_lossy(&bytes).into_owned(), start, end))
}

fn serial_summary(engine: &mut dyn Engine, session: &Session, args: &Arguments) -> Result<Value, String> {
    let (path, text, start, end) = log_text(engine, session, args, args.integer("since_offset").unwrap_or(0))?;
    let options = SummaryOptions {
        tail: args.integer("tail").unwrap_or(20) as usize,
        grep: args.text("grep").unwrap_or_default(),
        grep_limit: args.integer("grep_limit").unwrap_or(50) as usize,
        failures: args.integer("failures").unwrap_or(15) as usize,
    };
    let mut value = serial::summarize(&text, &options);
    value["path"] = json!(path.display().to_string());
    value["offset"] = json!(start);
    value["end_offset"] = json!(end);
    Ok(value)
}

fn crash_analyze(engine: &mut dyn Engine, session: &Session, args: &Arguments) -> Result<Value, String> {
    let mut value = json!({});
    if args.flag("live").unwrap_or(true) && args.text("path").is_none() {
        value["live"] = match engine.client() {
            Ok(client) if client.is_stopped() => match client.analyze() {
                Ok(analysis) => json!({
                    "code": format!("{:#010x}", analysis.code),
                    "name": analysis.name,
                    "summary": analysis.summary,
                    "parameters": analysis.parameters.iter().map(|parameter| json!({"label": parameter.label, "value": hex(parameter.value), "note": parameter.note})).collect::<Vec<_>>(),
                    "blamed": analysis.blamed.as_ref().map(|(module, reason)| json!({"module": module, "reason": reason})),
                    "stack": analysis.stack.iter().map(|(address, name)| format!("{address:#x} {name}")).collect::<Vec<_>>(),
                }),
                Err(error) => json!({"error": error}),
            },
            Ok(_) => json!({"error": "a maquina esta rodando (break antes)"}),
            Err(error) => json!({"error": error}),
        };
    }
    match log_text(engine, session, args, 0) {
        Ok((path, text, _, _)) => {
            value["serial"] = serial::crash_report(&text);
            value["path"] = json!(path.display().to_string());
        }
        Err(error) => value["serial"] = json!({"error": error}),
    }
    Ok(value)
}

fn wdlog(engine: &mut dyn Engine, session: &Session, args: &Arguments) -> Result<Value, String> {
    let (path, text, _, _) = log_text(engine, session, args, 0)?;
    let mut value = serial::wdlog_presence(&text);
    let present = value["present"] == true;
    value["path"] = json!(path.display().to_string());
    value["decoded"] = Value::Null;
    value["note"] = json!(if present {
        "o despejo esta no log; os aneis decodificados (sequencia, thread, modulo+RVA com simbolo, parametros) vem da analise de WdLog do kd-client, ainda nao ligada nesta versao do servidor"
    } else {
        "o log nao tem o WdLog do dxgkrnl (ele so sai num bugcheck com o dxgkrnl carregado)"
    });
    Ok(value)
}
