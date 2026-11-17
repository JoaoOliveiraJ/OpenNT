//! As ferramentas do servidor MCP: o esquema de cada uma (`list`), a
//! conferência dos argumentos pelo esquema e a execução sobre o `Engine`
//! (`call`), mais os recursos (o log da COM1, o DbgPrint, os breakpoints e
//! os módulos).
//!
//! Convenções:
//! - endereços são expressões em texto (`0xfffff800...`, `ntdll!LdrLoadDll`,
//!   `@rip`, `poi(@rsp)`), porque um número JSON perde precisão acima de
//!   2^53; os endereços dos resultados também vão em texto (`0x...`);
//! - as esperas têm `timeout_ms` e nunca deixam a máquina parada no meio
//!   (o tempo esgotado devolve erro e a máquina segue rodando);
//! - o resultado de cada ferramenta é um objeto JSON (`structuredContent`)
//!   e o mesmo texto formatado em `content`.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use kd_client::analysis::script;
use kd_client::analysis::search;
use kd_client::client::{BreakpointOptions, BreakpointRequest, Resumed};
use kd_client::commands::TraceOptions;
use kd_client::launcher::LaunchOptions;
use kd_client::registers;
use kd_client::{BreakpointKind, Client};
use serde_json::{json, Map, Value};

use crate::annotate::{self, Live};

#[path = "tools_extra.rs"]
mod extra;
use crate::disasm;
use crate::engine::Engine;
use crate::screenshot;

/// Como uma ferramenta falhou.
#[derive(Debug, PartialEq, Eq)]
pub enum ToolError {
    /// Ferramenta desconhecida ou argumentos fora do esquema (`-32602`).
    InvalidParams(String),
    /// A ferramenta rodou e falhou (o resultado com `isError`).
    Failed(String),
}

impl From<String> for ToolError {
    fn from(message: String) -> Self {
        ToolError::Failed(message)
    }
}

impl From<&str> for ToolError {
    fn from(message: &str) -> Self {
        ToolError::Failed(message.to_string())
    }
}

type ToolResult = Result<Value, ToolError>;

/// Maior espera aceita (30 minutos).
const MAX_WAIT_MS: u64 = 30 * 60 * 1000;

fn hex(value: u64) -> String {
    format!("{value:#x}")
}

/// O esquema de um objeto com as propriedades e as obrigatórias.
fn object(properties: Value, required: &[&str]) -> Value {
    json!({"type": "object", "properties": properties, "required": required, "additionalProperties": false})
}

fn text(description: &str) -> Value {
    json!({"type": "string", "description": description})
}

fn integer(description: &str, minimum: u64, maximum: u64) -> Value {
    json!({"type": "integer", "description": description, "minimum": minimum, "maximum": maximum})
}

fn boolean(description: &str) -> Value {
    json!({"type": "boolean", "description": description})
}

fn timeout(default_ms: u64) -> Value {
    integer(&format!("prazo em milissegundos (padrao {default_ms})"), 1, MAX_WAIT_MS)
}

/// As ferramentas: nome, descrição e o esquema dos argumentos.
pub fn definitions() -> Vec<(&'static str, &'static str, Value)> {
    let address = || text("expressao do endereco: 0x..., simbolo (modulo!nome), @registrador, poi(...), aritmetica");
    let process = || text("PID ou EPROCESS do processo das leituras (muda o processo escolhido, como .process); vazio = o atual");
    vec![
        (
            "launch",
            "Compila o OpenNT com o depurador (--kd=com2), abre o QEMU pelo cargo xtask e anexa (a maquina para). Demora: o build e o boot ate o attach.",
            object(
                json!({
                    "build_dir": text("diretorio de build (padrao build/mcp)"),
                    "headless": boolean("QEMU sem janela (padrao true)"),
                    "smp": integer("processadores (--smp)", 1, 16),
                    "initial_process": text("processo inicial (--initial-process), por exemplo smss para o csrss.exe real"),
                    "accel": text("acelerador do QEMU (--accel): whpx ou tcg"),
                    "extra": {"type": "array", "items": {"type": "string"}, "description": "outras opcoes do xtask (--start-driver=..., --display=basic)"},
                    "timeout_ms": timeout(1_800_000)
                }),
                &[],
            ),
        ),
        ("connect", "Conecta a um QEMU ja aberto com --kd=com2 (cargo xtask run --kd=com2: 127.0.0.1:1234) e anexa.", object(json!({"address": text("HOST:PORTA da COM2"), "elf": text("o kernel.elf do build (padrao <build>/kernel.elf)")}), &["address"])),
        ("detach", "Desliga a sessao: a maquina segue sem depurador; o QEMU aberto pelo launch fecha.", object(json!({}), &[])),
        ("status", "Estado da sessao: conectado, parado ou rodando, a ultima parada, o RIP, o processo escolhido e o numero de modulos e breakpoints.", object(json!({}), &[])),
        ("break", "Pede a parada da maquina e espera.", object(json!({"timeout_ms": timeout(60_000)}), &[])),
        ("go", "Continua a execucao (nao espera; use wait_for_stop).", object(json!({}), &[])),
        ("wait_for_stop", "Espera a proxima parada (breakpoint, passo, excecao). Roda os comandos de parada do breakpoint.", object(json!({"timeout_ms": timeout(60_000)}), &[])),
        ("step_into", "Executa instrucoes (entra nas chamadas).", object(json!({"count": integer("instrucoes (padrao 1)", 1, 1000)}), &[])),
        ("step_over", "Passa por cima da instrucao (um call roda ate voltar).", object(json!({"timeout_ms": timeout(120_000)}), &[])),
        ("step_out", "Roda ate a funcao corrente retornar.", object(json!({"timeout_ms": timeout(120_000)}), &[])),
        ("run_to", "Roda ate um endereco (breakpoint temporario).", object(json!({"address": address(), "timeout_ms": timeout(120_000)}), &["address"])),
        ("registers_get", "Registradores do processador (ou da thread de usuario) da parada: gerais, flags, segmentos; com extended, x87/MMX, XMM, YMM, MXCSR e DR0-DR7; numa parada de usuario, LastError e LastStatus da TEB.", object(json!({"extended": boolean("inclui x87, MMX, SSE, AVX e os registradores de depuracao")}), &[])),
        ("register_set", "Grava um registrador (rax..r15, rip, eflags).", object(json!({"name": text("nome do registrador"), "value": text("expressao do valor")}), &["name", "value"])),
        ("memory_read", "Le memoria (kernel ou o processo escolhido).", object(json!({"address": address(), "length": integer("bytes", 1, 65536), "process": process()}), &["address", "length"])),
        ("memory_write", "Grava bytes na memoria.", object(json!({"address": address(), "hex": text("bytes em hexadecimal (\"90 90\" ou \"9090\")"), "process": process()}), &["address", "hex"])),
        (
            "disassemble",
            "Desmonta a partir de um endereco, com os simbolos, os limites das funcoes, os lacos e os comentarios automaticos (chamadas com argumentos decodificados, strings referenciadas).",
            object(json!({"address": text("expressao (padrao @rip)"), "count": integer("instrucoes (padrao 32)", 1, 400), "annotate": boolean("analise automatica (padrao true)"), "process": process()}), &[]),
        ),
        ("symbol_lookup", "O simbolo de um endereco (modulo!nome+deslocamento).", object(json!({"address": address()}), &["address"])),
        ("symbol_resolve", "O endereco de um nome (simbolo do kernel, modulo!export, PDB publico).", object(json!({"name": text("nome do simbolo")}), &["name"])),
        ("modules", "Modulos carregados: os do kernel e, com um processo escolhido, os de usuario dele.", object(json!({"process": process()}), &[])),
        ("processes", "Processos (PID, EPROCESS, CR3, threads, nome).", object(json!({}), &[])),
        ("threads", "Threads: as do kernel, ou as de usuario de um processo (TEB, CONTEXT, RIP, prioridade, suspensao, espera, LastError, tempos, ciclos).", object(json!({"process": text("PID ou EPROCESS (vazio = threads do kernel)")}), &[])),
        ("set_process", "Escolhe o processo das leituras e dos breakpoints de usuario (vazio volta ao kernel).", object(json!({"process": text("PID ou EPROCESS; vazio ou 0 = o kernel")}), &[])),
        (
            "breakpoint_set",
            "Arma um breakpoint: software, hardware (DR0-DR3; num endereco de usuario, por processo), escrita/acesso (vigias de hardware), memoria por pagina (memory_access, memory_write, memory_execute), carga de modulo ou evento; com condicao, log, comandos e as opcoes de acerto.",
            object(
                json!({
                    "address": text("expressao do endereco; para module, o nome do modulo; para event, cpr[:nome]|epr|ct|et|ld:processo!dll"),
                    "kind": {"type": "string", "enum": ["software", "hardware", "write", "access", "memory_access", "memory_write", "memory_execute", "module", "event"], "description": "tipo (padrao software)"},
                    "length": integer("bytes vigiados (1, 2, 4, 8; memoria: tamanho da faixa)", 1, 0x40000),
                    "condition": text("para so quando a expressao der diferente de zero"),
                    "log": text("texto de log ({expr}, {expr:d}, {expr:s}); sem condicao, so registra e segue"),
                    "log_condition": text("o log so sai com esta condicao verdadeira"),
                    "command": text("comandos do depurador separados por ;"),
                    "command_condition": text("os comandos so rodam com esta condicao verdadeira (padrao: quando para)"),
                    "name": text("nome do breakpoint"),
                    "pass_count": integer("para a partir deste acerto", 0, 1_000_000),
                    "single_shot": boolean("some depois da primeira parada"),
                    "silent": boolean("sem a linha de acerto no log"),
                    "fast_resume": boolean("quando nao para, segue sem reler os modulos"),
                    "deferred": boolean("aceita um simbolo de modulo ainda nao carregado"),
                    "process": process()
                }),
                &["address"],
            ),
        ),
        ("breakpoint_clear", "Tira um breakpoint pelo numero.", object(json!({"id": integer("numero do breakpoint", 0, u32::MAX as u64)}), &["id"])),
        ("breakpoint_enable", "Liga ou desliga um breakpoint.", object(json!({"id": integer("numero do breakpoint", 0, u32::MAX as u64), "enabled": boolean("ligado")}), &["id", "enabled"])),
        ("breakpoint_list", "Os breakpoints da sessao com os acertos.", object(json!({}), &[])),
        ("backtrace", "A pilha de chamadas da parada (.pdata dos binarios da Microsoft, frame pointers do kernel do OpenNT).", object(json!({"limit": integer("quadros (padrao 32)", 1, 256)}), &[])),
        ("search_strings", "Instrucoes que referenciam strings ASCII ou UTF-16 num modulo.", object(json!({"module": text("nome do modulo ou um endereco dentro dele"), "filter": text("so as strings que contem este texto (sem caixa)"), "limit": integer("resultados (padrao 500)", 1, 20000)}), &["module"])),
        ("search_pattern", "Procura bytes com curingas (48 8B ?? 05, \"texto\", u\"texto\") num modulo.", object(json!({"pattern": text("padrao"), "module": text("nome do modulo ou endereco (padrao: o do RIP)"), "limit": integer("resultados (padrao 200)", 1, 5000)}), &["pattern"])),
        ("xrefs", "Quem referencia um endereco (chamadas, saltos, memoria, imediatos), pelo indice do modulo (feito uma vez por modulo).", object(json!({"address": address(), "module": text("modulo onde procurar (padrao: o do endereco)")}), &["address"])),
        (
            "nt_view",
            "Vistas do NT pelo depurador: process, thread, irp, devobj, drvobj, object, handle, analyze (bugcheck), lmv (modulo), dt (struct do PDB).",
            object(json!({"kind": {"type": "string", "enum": ["process", "thread", "irp", "devobj", "drvobj", "object", "handle", "analyze", "lmv", "dt"]}, "argument": text("endereco, nome ou PID conforme a vista")}), &["kind"]),
        ),
        (
            "trace_start",
            "Rastreia instrucoes passo a passo no convidado ate o fim (contagem, endereco, retorno ou modulo) e guarda o rastro.",
            object(
                json!({
                    "count": integer("instrucoes no maximo (padrao 2000)", 1, 10_000_000),
                    "until": text("para neste endereco"),
                    "until_return": boolean("ate a funcao corrente retornar"),
                    "over_calls": boolean("so o nivel da funcao corrente"),
                    "enter_module": text("para ao entrar neste modulo"),
                    "leave_module": text("para ao sair deste modulo"),
                    "skip_modules": {"type": "array", "items": {"type": "string"}, "description": "modulos executados sem gravar"}
                }),
                &[],
            ),
        ),
        ("trace_fetch", "Registros do ultimo rastro (RIP, simbolo, profundidade).", object(json!({"offset": integer("primeiro registro", 0, u32::MAX as u64), "limit": integer("registros (padrao 500)", 1, 5000)}), &[])),
        ("trace_stop", "Descarta o rastro guardado.", object(json!({}), &[])),
        (
            "wait_for_serial",
            "Espera um texto no log da COM1 (o serial.log do build), com a maquina rodando. Volta antes se a maquina parar num breakpoint.",
            object(json!({"marker": text("texto procurado"), "timeout_ms": timeout(300_000), "after_offset": integer("so depois deste byte do log (padrao 0)", 0, u64::MAX >> 1)}), &["marker"]),
        ),
        ("read_serial_log", "Le o log da COM1.", object(json!({"offset": integer("byte inicial (padrao: os ultimos max_bytes)", 0, u64::MAX >> 1), "max_bytes": integer("bytes (padrao 16384)", 1, 1 << 20)}), &[])),
        ("run_script", "Roda um roteiro na linguagem do depurador (comandos, var, if/while/for, log).", object(json!({"script": text("o roteiro"), "max_steps": integer("comandos no maximo (padrao 100000)", 1, 10_000_000)}), &["script"])),
        ("command", "Um comando de texto do depurador (os do cargo xtask debug: r, k, db, bp, !process, lm...).", object(json!({"text": text("o comando")}), &["text"])),
        ("screenshot", "Grava a tela do convidado em PNG (screendump do monitor do QEMU aberto pelo launch).", object(json!({"path": text("arquivo .png (padrao <build>/mcp-tela.png)")}), &[])),
    ]
    .into_iter()
    .chain(extra::definitions())
    .collect()
}

/// O `tools/list`.
pub fn list() -> Vec<Value> {
    definitions().into_iter().map(|(name, description, schema)| json!({"name": name, "description": description, "inputSchema": schema})).collect()
}

/// Confere os argumentos contra o esquema (tipos, obrigatórios, enum,
/// limites e propriedades extras).
pub fn validate(schema: &Value, arguments: &Value) -> Result<(), String> {
    let Some(object) = arguments.as_object() else { return Err("arguments precisa ser um objeto".into()) };
    let properties = schema.get("properties").and_then(Value::as_object).cloned().unwrap_or_default();
    for required in schema.get("required").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
        if !object.contains_key(required) {
            return Err(format!("falta o argumento {required}"));
        }
    }
    for (key, value) in object {
        let Some(property) = properties.get(key) else { return Err(format!("argumento desconhecido: {key}")) };
        let kind = property.get("type").and_then(Value::as_str).unwrap_or("");
        let ok = match kind {
            "string" => value.is_string(),
            "integer" => value.is_u64() || value.is_i64(),
            "boolean" => value.is_boolean(),
            "array" => value.as_array().is_some_and(|items| items.iter().all(Value::is_string)),
            "object" => value.is_object(),
            _ => true,
        };
        if !ok {
            return Err(format!("{key} precisa ser {kind}"));
        }
        if let Some(choices) = property.get("enum").and_then(Value::as_array) {
            if !choices.contains(value) {
                return Err(format!("{key} fora das opcoes: {}", choices.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")));
            }
        }
        if kind == "integer" {
            let number = value.as_i64().unwrap_or(i64::MAX);
            if let Some(minimum) = property.get("minimum").and_then(Value::as_i64) {
                if number < minimum {
                    return Err(format!("{key} menor que {minimum}"));
                }
            }
            if let Some(maximum) = property.get("maximum").and_then(Value::as_u64) {
                if value.as_u64().is_some_and(|number| number > maximum) {
                    return Err(format!("{key} maior que {maximum}"));
                }
            }
        }
    }
    Ok(())
}

/// Os argumentos já conferidos.
struct Arguments<'a>(&'a Map<String, Value>);

impl Arguments<'_> {
    fn text(&self, key: &str) -> Option<String> {
        self.0.get(key).and_then(Value::as_str).map(|text| text.trim().to_string()).filter(|text| !text.is_empty())
    }

    fn integer(&self, key: &str) -> Option<u64> {
        self.0.get(key).and_then(Value::as_u64)
    }

    fn flag(&self, key: &str) -> Option<bool> {
        self.0.get(key).and_then(Value::as_bool)
    }

    fn list(&self, key: &str) -> Vec<String> {
        self.0.get(key).and_then(Value::as_array).map(|items| items.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default()
    }

    fn timeout(&self, default_ms: u64) -> Duration {
        Duration::from_millis(self.integer("timeout_ms").unwrap_or(default_ms).min(MAX_WAIT_MS))
    }
}

/// O `tools/call`.
pub fn call(engine: &mut dyn Engine, name: &str, arguments: &Value) -> ToolResult {
    let Some((_, _, schema)) = definitions().into_iter().find(|(tool, _, _)| *tool == name) else { return Err(ToolError::InvalidParams(format!("ferramenta desconhecida: {name}"))) };
    let empty = Map::new();
    let arguments = if arguments.is_null() { Value::Object(empty.clone()) } else { arguments.clone() };
    validate(&schema, &arguments).map_err(ToolError::InvalidParams)?;
    let map = arguments.as_object().unwrap_or(&empty);
    let args = Arguments(map);
    let result = run(engine, name, &args);
    if !matches!(name, "status" | "read_serial_log" | "breakpoint_list" | "symbol_lookup" | "symbol_resolve" | "snapshot_list" | "api_monitor_fetch" | "irp_trace_fetch" | "registry_list" | "registry_read" | "object_list" | "file_list" | "file_read" | "view_struct") {
        engine.changed();
    }
    result
}

/// A parada em JSON: o texto, o RIP e o símbolo.
fn stop_value(client: &mut Client, text: &str) -> Value {
    let rip = client.register("rip").ok();
    json!({
        "stopped": client.is_stopped(),
        "stop": text.split(" [").next().unwrap_or(text),
        "rip": rip.map(hex),
        "symbol": rip.map(|rip| client.symbols.describe(rip)),
        "user_mode": client.stopped_in_user_mode(),
    })
}

/// Espera a parada e roda os comandos do breakpoint que parou.
fn wait_stop(client: &mut Client, timeout: Duration) -> Result<Value, String> {
    let text = client.wait_stop(timeout)?;
    let mut value = stop_value(client, &text);
    if let Some((id, commands)) = client.stop_commands() {
        let mut outputs = Vec::new();
        for command in commands.split(';').map(str::trim).filter(|command| !command.is_empty()) {
            let output = client.execute(command).unwrap_or_else(|error| format!("erro: {error}"));
            outputs.push(json!({"command": command, "output": output}));
            if !client.is_stopped() {
                break;
            }
        }
        value["breakpoint_commands"] = json!({"breakpoint": id, "outputs": outputs});
    }
    Ok(value)
}

fn set_process_argument(client: &mut Client, args: &Arguments) -> Result<(), String> {
    if let Some(process) = args.text("process") {
        client.set_process(Some(&process))?;
    }
    Ok(())
}

fn parse_hex_bytes(text: &str) -> Result<Vec<u8>, String> {
    let digits: String = text.chars().filter(|character| !character.is_whitespace()).collect();
    let digits = digits.trim_start_matches("0x");
    if digits.len() % 2 != 0 || !digits.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err("hex: bytes em hexadecimal (\"90 90\")".into());
    }
    Ok((0..digits.len() / 2).map(|index| u8::from_str_radix(&digits[index * 2..index * 2 + 2], 16).unwrap_or(0)).collect())
}

fn kind_of(text: &str) -> BreakpointKind {
    match text {
        "hardware" => BreakpointKind::Hardware,
        "write" => BreakpointKind::Write,
        "access" => BreakpointKind::Access,
        "memory_access" => BreakpointKind::MemoryAccess,
        "memory_write" => BreakpointKind::MemoryWrite,
        "memory_execute" => BreakpointKind::MemoryExecute,
        "module" => BreakpointKind::Module,
        "event" => BreakpointKind::Event,
        _ => BreakpointKind::Software,
    }
}

fn kind_name(kind: BreakpointKind) -> &'static str {
    match kind {
        BreakpointKind::Software => "software",
        BreakpointKind::Hardware => "hardware",
        BreakpointKind::Write => "write",
        BreakpointKind::Access => "access",
        BreakpointKind::MemoryAccess => "memory_access",
        BreakpointKind::MemoryWrite => "memory_write",
        BreakpointKind::MemoryExecute => "memory_execute",
        BreakpointKind::Module => "module",
        BreakpointKind::Event => "event",
    }
}

fn breakpoint_value(client: &Client, breakpoint: &kd_client::Breakpoint) -> Value {
    json!({
        "id": breakpoint.id,
        "kind": kind_name(breakpoint.kind),
        "address": hex(breakpoint.address),
        "symbol": if breakpoint.pending || breakpoint.address == 0 { String::new() } else { client.symbols.describe(breakpoint.address) },
        "expression": breakpoint.expression,
        "length": breakpoint.length,
        "enabled": breakpoint.enabled,
        "pending": breakpoint.pending,
        "hits": breakpoint.hits,
        "condition": breakpoint.condition,
        "log": breakpoint.log,
        "command": breakpoint.command,
        "name": breakpoint.options.name,
        "log_condition": breakpoint.options.log_condition,
        "command_condition": breakpoint.options.command_condition,
        "single_shot": breakpoint.options.single_shot,
        "silent": breakpoint.options.silent,
        "fast_resume": breakpoint.options.fast_resume,
        "pass_count": breakpoint.pass_count,
        "process": hex(breakpoint.process),
    })
}

/// O caminho do `kernel.elf` do engine.
fn elf_path(engine: &dyn Engine) -> PathBuf {
    engine.build_dir().unwrap_or_else(|| engine.root().join("build")).join("kernel.elf")
}

/// O endereço de um módulo pelo nome ou por uma expressão.
fn module_base(client: &mut Client, text: &str) -> Result<u64, String> {
    if let Some(module) = client.symbols.module_named(text) {
        return Ok(module.base);
    }
    let address = client.evaluate(text)?;
    client.symbols.module_at(address).map(|module| module.base).ok_or_else(|| format!("{text}: fora dos modulos"))
}

fn run(engine: &mut dyn Engine, name: &str, args: &Arguments) -> ToolResult {
    match name {
        "launch" => {
            let mut extra = Vec::new();
            if let Some(smp) = args.integer("smp") {
                extra.push(format!("--smp={smp}"));
            }
            if let Some(process) = args.text("initial_process") {
                extra.push(format!("--initial-process={process}"));
            }
            if let Some(accel) = args.text("accel") {
                extra.push(format!("--accel={accel}"));
            }
            extra.extend(args.list("extra"));
            let options = LaunchOptions { root: engine.root(), build_dir: PathBuf::from(args.text("build_dir").unwrap_or_else(|| "build/mcp".into())), headless: args.flag("headless").unwrap_or(true), extra };
            let text = engine.launch(options, args.timeout(1_800_000))?;
            let monitor = engine.monitor_address();
            let serial = engine.serial_log().map(|path| path.display().to_string());
            let client = engine.client()?;
            let mut value = stop_value(client, &text);
            value["attach"] = json!(text);
            value["monitor"] = json!(monitor);
            value["serial_log"] = json!(serial);
            Ok(value)
        }
        "connect" => {
            let address = args.text("address").unwrap_or_default();
            let text = engine.connect(&address, args.text("elf").map(PathBuf::from))?;
            let client = engine.client()?;
            let mut value = stop_value(client, &text);
            value["attach"] = json!(text);
            Ok(value)
        }
        "detach" => Ok(json!({"detached": engine.detach()?})),
        "status" => {
            let log = engine.launch_log();
            let serial = engine.serial_log().map(|path| path.display().to_string());
            let Ok(client) = engine.client() else { return Ok(json!({"connected": false, "launch_log": log, "serial_log": serial})) };
            if !client.is_stopped() {
                let _ = client.poll(Duration::from_millis(20))?;
            }
            let mut value = json!({
                "connected": true,
                "stopped": client.is_stopped(),
                "last_stop": client.last_stop().split(" [").next().unwrap_or(""),
                "breakpoints": client.breakpoints().len(),
                "modules": client.symbols.modules.len(),
                "process": client.process().map(|context| json!({"name": context.name, "pid": context.pid, "eprocess": hex(context.eprocess)})),
                "serial_log": serial,
            });
            if client.is_stopped() {
                let rip = client.register("rip").ok();
                value["rip"] = json!(rip.map(hex));
                value["symbol"] = json!(rip.map(|rip| client.symbols.describe(rip)));
                value["user_mode"] = json!(client.stopped_in_user_mode());
            }
            Ok(value)
        }
        "break" => {
            let client = engine.client()?;
            let text = client.break_in(args.timeout(60_000))?;
            Ok(stop_value(client, &text))
        }
        "go" => {
            let client = engine.client()?;
            client.go()?;
            Ok(json!({"running": true}))
        }
        "wait_for_stop" => {
            let client = engine.client()?;
            Ok(wait_stop(client, args.timeout(60_000))?)
        }
        "step_into" => {
            let client = engine.client()?;
            let mut text = String::new();
            for _ in 0..args.integer("count").unwrap_or(1) {
                text = client.step()?;
            }
            Ok(stop_value(client, &text))
        }
        "step_over" | "step_out" => {
            let client = engine.client()?;
            let resumed = if name == "step_over" { client.step_over()? } else { client.step_out()? };
            match resumed {
                Resumed::Stopped(text) => Ok(stop_value(client, &text)),
                Resumed::Running => Ok(wait_stop(client, args.timeout(120_000))?),
            }
        }
        "run_to" => {
            let client = engine.client()?;
            let address = client.evaluate(&args.text("address").unwrap_or_default())?;
            client.run_until(address, None)?;
            Ok(wait_stop(client, args.timeout(120_000))?)
        }
        "registers_get" => {
            let client = engine.client()?;
            let mut general = Map::new();
            let values = client.general_registers()?;
            for value in &values {
                general.insert(value.layout.name.to_string(), json!(value.value.map(hex)));
            }
            for layout in registers::EXTRA {
                general.insert(layout.name.to_string(), json!(client.register(layout.name).ok().map(hex)));
            }
            let rip = client.register("rip").ok();
            let flags = client.register("eflags").ok();
            let mut value = json!({"registers": general, "rip_symbol": rip.map(|rip| client.symbols.describe(rip)), "flags": flags.map(registers::flags_text), "user_mode": client.stopped_in_user_mode()});
            if client.stopped_in_user_mode() {
                if let Ok(teb) = client.register("gs_base") {
                    value["last_error"] = json!(client.read_integer(teb + 0x68, 4).ok().map(hex));
                    value["last_status"] = json!(client.read_integer(teb + 0x1250, 4).ok().map(hex));
                }
            }
            if args.flag("extended").unwrap_or(false) {
                let state = client.extended_registers()?;
                let bytes = |data: &Option<[u8; 16]>| data.map(|data| data.iter().rev().map(|byte| format!("{byte:02x}")).collect::<String>());
                value["extended"] = json!({
                    "xmm": state.xmm.iter().map(bytes).collect::<Vec<_>>(),
                    "ymm_high": state.ymm_high.iter().map(bytes).collect::<Vec<_>>(),
                    "st": state.st.iter().map(|data| data.map(|data| json!({"raw": data.iter().rev().map(|byte| format!("{byte:02x}")).collect::<String>(), "value": registers::extended_to_f64(&data)}))).collect::<Vec<_>>(),
                    "mmx": (0..8).map(|index| state.mmx(index).map(hex)).collect::<Vec<_>>(),
                    "fctrl": state.fctrl.map(|value| hex(value as u64)),
                    "fstat": state.fstat.map(|value| hex(value as u64)),
                    "ftag": state.ftag.map(|value| hex(value as u64)),
                    "mxcsr": state.mxcsr.map(|value| json!({"value": hex(value as u64), "text": registers::mxcsr_text(value)})),
                    "debug": {"dr0": state.debug[0].map(hex), "dr1": state.debug[1].map(hex), "dr2": state.debug[2].map(hex), "dr3": state.debug[3].map(hex), "dr6": state.debug[4].map(hex), "dr7": state.debug[5].map(hex), "dr7_text": state.debug[5].map(registers::dr7_text)},
                });
            }
            Ok(value)
        }
        "register_set" => {
            let client = engine.client()?;
            let register = args.text("name").unwrap_or_default();
            let value = client.evaluate(&args.text("value").unwrap_or_default())?;
            client.write_register(&register, value)?;
            Ok(json!({"name": register, "value": hex(client.register(&register)?)}))
        }
        "memory_read" => {
            let client = engine.client()?;
            set_process_argument(client, args)?;
            let address = client.evaluate(&args.text("address").unwrap_or_default())?;
            let length = args.integer("length").unwrap_or(16) as usize;
            let bytes = client.read_memory(address, length)?;
            let ascii: String = bytes.iter().map(|&byte| if (0x20..0x7F).contains(&byte) { byte as char } else { '.' }).collect();
            Ok(json!({"address": hex(address), "length": bytes.len(), "hex": bytes.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(" "), "ascii": ascii}))
        }
        "memory_write" => {
            let client = engine.client()?;
            set_process_argument(client, args)?;
            let address = client.evaluate(&args.text("address").unwrap_or_default())?;
            let bytes = parse_hex_bytes(&args.text("hex").unwrap_or_default())?;
            client.write_memory(address, &bytes)?;
            Ok(json!({"address": hex(address), "written": bytes.len()}))
        }
        "disassemble" => {
            let client = engine.client()?;
            set_process_argument(client, args)?;
            let address = client.evaluate(&args.text("address").unwrap_or_else(|| "@rip".into()))?;
            let count = args.integer("count").unwrap_or(32) as usize;
            let bytes = client.read_memory(address, count * 15)?;
            let mut lines = disasm::disassemble(address, &bytes, Some(&client.symbols));
            lines.truncate(count);
            let annotate_on = args.flag("annotate").unwrap_or(true);
            let (functions, loops, comments) = if annotate_on {
                let functions = annotate::functions_for_lines(client, &lines);
                let loops = annotate::loops_for(client, &functions);
                let live = if client.is_stopped() {
                    let registers: Vec<(String, u64)> = client.general_registers().unwrap_or_default().into_iter().filter_map(|value| value.value.map(|number| (value.layout.name.to_string(), number))).collect();
                    registers.iter().find(|(name, _)| name == "rip").map(|(_, rip)| Live { rip: *rip, registers: registers.clone() })
                } else {
                    None
                };
                let comments = annotate::auto_comments(client, &lines, live.as_ref());
                (functions, loops, comments)
            } else {
                Default::default()
            };
            let rows: Vec<Value> = lines
                .iter()
                .map(|line| {
                    let function = functions.iter().find(|function| function.contains(line.address));
                    let inner = loops.iter().filter(|candidate| line.address >= candidate.start && line.address < candidate.end).count();
                    json!({
                        "address": hex(line.address),
                        "bytes": line.bytes,
                        "text": line.text,
                        "label": line.label,
                        "comment": comments.get(&line.address).cloned().or_else(|| line.comment.clone()),
                        "function_start": function.is_some_and(|function| function.start == line.address),
                        "function_end": function.is_some_and(|function| line.address + (line.bytes.len() / 2) as u64 >= function.end),
                        "loop_depth": inner,
                    })
                })
                .collect();
            let functions: Vec<Value> = functions.iter().map(|function| json!({"start": hex(function.start), "end": hex(function.end), "source": function.source.name(), "name": client.symbols.describe(function.start)})).collect();
            let loops: Vec<Value> = loops.iter().map(|found| json!({"start": hex(found.start), "branch": hex(found.branch), "end": hex(found.end)})).collect();
            Ok(json!({"address": hex(address), "lines": rows, "functions": functions, "loops": loops}))
        }
        "symbol_lookup" => {
            let client = engine.client()?;
            let address = client.evaluate(&args.text("address").unwrap_or_default())?;
            let module = client.symbols.module_at(address).map(|module| (module.name.clone(), address - module.base));
            Ok(json!({"address": hex(address), "symbol": client.symbols.describe(address), "module": module.as_ref().map(|(name, _)| name.clone()), "rva": module.map(|(_, offset)| hex(offset))}))
        }
        "symbol_resolve" => {
            let client = engine.client()?;
            let name = args.text("name").unwrap_or_default();
            let address = client.evaluate(&name)?;
            Ok(json!({"name": name, "address": hex(address), "symbol": client.symbols.describe(address)}))
        }
        "modules" => {
            let client = engine.client()?;
            set_process_argument(client, args)?;
            let modules: Vec<Value> = client.symbols.modules.iter().map(|module| json!({"name": module.name, "base": hex(module.base), "end": hex(module.end), "path": module.path, "user": module.user, "symbols": module.symbols.len(), "pdb": module.pdb.is_some()})).collect();
            Ok(json!({"process": client.process().map(|context| context.name.clone()), "modules": modules}))
        }
        "processes" => {
            let client = engine.client()?;
            let list: Vec<Value> = client.processes()?.into_iter().map(|process| json!({"pid": process.pid, "eprocess": hex(process.eprocess), "cr3": hex(process.cr3), "threads": process.threads, "name": process.name})).collect();
            Ok(json!({"processes": list}))
        }
        "threads" => {
            let client = engine.client()?;
            match args.text("process") {
                Some(process) => {
                    let list: Vec<Value> = client
                        .user_threads(&process)?
                        .into_iter()
                        .map(|thread| {
                            json!({"tid": thread.tid, "ethread": hex(thread.ethread), "teb": hex(thread.teb), "start": hex(thread.start), "start_symbol": client.symbols.describe(thread.start), "context": hex(thread.context), "rip": hex(thread.rip), "rsp": hex(thread.rsp), "state": thread.state, "wait_reason": thread.wait_reason, "last_error": thread.last_error.map(hex), "priority": thread.priority, "suspend_count": thread.suspend_count, "kernel_time": thread.kernel_time, "user_time": thread.user_time, "cycles": thread.cycles.map(hex)})
                        })
                        .collect();
                    Ok(json!({"process": process, "threads": list}))
                }
                None => {
                    let list: Vec<Value> = client.threads(None)?.into_iter().map(|thread| json!({"pid": thread.pid, "tid": thread.tid, "ethread": hex(thread.ethread), "state": thread.state, "start": hex(thread.start), "start_symbol": client.symbols.describe(thread.start), "process": thread.process})).collect();
                    Ok(json!({"threads": list}))
                }
            }
        }
        "set_process" => {
            let client = engine.client()?;
            let context = client.set_process(args.text("process").as_deref())?;
            Ok(json!({"process": context.map(|context| json!({"name": context.name, "pid": context.pid, "eprocess": hex(context.eprocess), "cr3": hex(context.cr3), "peb": hex(context.peb)}))}))
        }
        "breakpoint_set" => {
            let client = engine.client()?;
            set_process_argument(client, args)?;
            let kind = kind_of(&args.text("kind").unwrap_or_else(|| "software".into()));
            let mut request = BreakpointRequest::new(kind, &args.text("address").unwrap_or_default());
            if let Some(length) = args.integer("length") {
                request.length = length;
            }
            request.condition = args.text("condition").unwrap_or_default();
            request.log = args.text("log").unwrap_or_default();
            request.command = args.text("command").unwrap_or_default();
            request.pass_count = args.integer("pass_count").unwrap_or(0);
            request.deferred = args.flag("deferred").unwrap_or(false);
            request.options = BreakpointOptions {
                name: args.text("name").unwrap_or_default(),
                log_condition: args.text("log_condition").unwrap_or_default(),
                command_condition: args.text("command_condition").unwrap_or_default(),
                single_shot: args.flag("single_shot").unwrap_or(false),
                silent: args.flag("silent").unwrap_or(false),
                fast_resume: args.flag("fast_resume").unwrap_or(false),
            };
            let breakpoint = client.add_breakpoint_with(&request)?;
            Ok(breakpoint_value(client, &breakpoint))
        }
        "breakpoint_clear" => {
            let client = engine.client()?;
            let breakpoint = client.remove_breakpoint(args.integer("id").unwrap_or(0) as u32)?;
            Ok(json!({"removed": breakpoint_value(client, &breakpoint)}))
        }
        "breakpoint_enable" => {
            let client = engine.client()?;
            let id = args.integer("id").unwrap_or(0) as u32;
            client.set_breakpoint_enabled(id, args.flag("enabled").unwrap_or(true))?;
            let breakpoint = client.breakpoints().iter().find(|breakpoint| breakpoint.id == id).cloned().ok_or("breakpoint sumiu")?;
            Ok(breakpoint_value(client, &breakpoint))
        }
        "breakpoint_list" => {
            let client = engine.client()?;
            let list: Vec<Value> = client.breakpoints().iter().map(|breakpoint| breakpoint_value(client, breakpoint)).collect();
            Ok(json!({"breakpoints": list, "log": client.log_lines().iter().rev().take(50).rev().cloned().collect::<Vec<_>>()}))
        }
        "backtrace" => {
            let client = engine.client()?;
            let frames = client.backtrace(args.integer("limit").unwrap_or(32) as usize)?;
            let list: Vec<Value> = frames
                .iter()
                .enumerate()
                .map(|(depth, frame)| {
                    json!({"depth": depth, "address": hex(frame.address), "symbol": client.frame_name(frame), "stack": hex(frame.stack), "method": format!("{:?}", frame.method)})
                })
                .collect();
            Ok(json!({"frames": list}))
        }
        "search_strings" | "search_pattern" | "xrefs" => search_tool(engine, name, args),
        "nt_view" => {
            let client = engine.client()?;
            let argument = args.text("argument").unwrap_or_default();
            let command = match args.text("kind").as_deref().unwrap_or("") {
                "process" => format!("!process {argument}"),
                "thread" => format!("!thread {argument}"),
                "irp" => format!("!irp {argument}"),
                "devobj" => format!("!devobj {argument}"),
                "drvobj" => format!("!drvobj {argument}"),
                "object" => format!("!object {argument}"),
                "handle" => format!("!handle {argument}"),
                "analyze" => "!analyze".to_string(),
                "lmv" => format!("lmv {argument}"),
                _ => format!("dt {argument}"),
            };
            let output = client.execute(command.trim())?;
            Ok(json!({"command": command.trim(), "text": output}))
        }
        "trace_start" => {
            let client = engine.client()?;
            let options = TraceOptions {
                count: args.integer("count").unwrap_or(2000),
                until: args.text("until").unwrap_or_default(),
                until_return: args.flag("until_return").unwrap_or(false),
                over_calls: args.flag("over_calls").unwrap_or(false),
                enter_module: args.text("enter_module").unwrap_or_default(),
                leave_module: args.text("leave_module").unwrap_or_default(),
                skip_modules: args.list("skip_modules"),
                ..TraceOptions::default()
            };
            let summary = client.run_trace(&options)?;
            let records = client.trace.as_ref().map_or(0, |trace| trace.len());
            let mut value = stop_value(client, &summary);
            value["summary"] = json!(summary);
            value["records"] = json!(records);
            Ok(value)
        }
        "trace_fetch" => {
            let client = engine.client()?;
            let trace = client.trace.clone().ok_or("nenhum rastro (use trace_start)")?;
            let offset = args.integer("offset").unwrap_or(0) as usize;
            let limit = args.integer("limit").unwrap_or(500) as usize;
            let records: Vec<Value> = trace.records.iter().enumerate().skip(offset).take(limit).map(|(index, record)| json!({"index": index, "rip": hex(record.rip), "symbol": client.symbols.describe(record.rip), "depth": record.depth, "cpu": record.cpu, "class": format!("{:?}", record.class)})).collect();
            Ok(json!({"total": trace.len(), "offset": offset, "records": records}))
        }
        "trace_stop" => {
            let client = engine.client()?;
            let had = client.trace.take().is_some();
            Ok(json!({"cleared": had}))
        }
        "wait_for_serial" => wait_for_serial(engine, args),
        "read_serial_log" => {
            let path = engine.serial_log().ok_or("log da COM1 desconhecido (use launch, ou connect com o build)")?;
            let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
            let max = args.integer("max_bytes").unwrap_or(16384) as usize;
            let start = match args.integer("offset") {
                Some(offset) => (offset as usize).min(bytes.len()),
                None => bytes.len().saturating_sub(max),
            };
            let end = (start + max).min(bytes.len());
            Ok(json!({"path": path.display().to_string(), "offset": start, "end": end, "size": bytes.len(), "text": String::from_utf8_lossy(&bytes[start..end])}))
        }
        "run_script" => {
            let client = engine.client()?;
            let parsed = script::parse(&args.text("script").unwrap_or_default())?;
            let mut host = ScriptHost { client, output: Vec::new() };
            let result = script::run(&parsed, &mut host, args.integer("max_steps").unwrap_or(100_000) as usize);
            let output = std::mem::take(&mut host.output);
            match result {
                Ok(run) => Ok(json!({"output": output, "commands": run.commands, "steps": run.steps, "variables": run.variables.iter().map(|(name, value)| (name.clone(), json!(hex(*value)))).collect::<Map<String, Value>>()})),
                Err(error) => Err(ToolError::Failed(format!("{error}\n{}", output.join("\n")))),
            }
        }
        "command" => {
            let client = engine.client()?;
            let text = args.text("text").unwrap_or_default();
            let output = client.execute(&text)?;
            Ok(json!({"command": text, "output": output, "stopped": client.is_stopped()}))
        }
        "screenshot" => {
            let monitor = engine.monitor_address().ok_or("a captura precisa do QEMU aberto pelo launch (o monitor HMP)")?;
            let path = args.text("path").map(PathBuf::from).unwrap_or_else(|| engine.build_dir().unwrap_or_else(|| engine.root().join("build")).join("mcp-tela.png"));
            let path = if path.is_absolute() { path } else { engine.root().join(path) };
            let (width, height) = screenshot::capture(&monitor, &path)?;
            Ok(json!({"path": path.display().to_string(), "width": width, "height": height, "format": "png"}))
        }
        _ => extra::run(engine, name, args).unwrap_or_else(|| Err(ToolError::InvalidParams(format!("ferramenta desconhecida: {name}")))),
    }
}

/// As buscas sobre as imagens dos módulos (com o cache do engine).
fn search_tool(engine: &mut dyn Engine, name: &str, args: &Arguments) -> ToolResult {
    let elf = elf_path(engine);
    let started = Instant::now();
    match name {
        "search_strings" => {
            let base = module_base(engine.client()?, &args.text("module").unwrap_or_default())?;
            let filter = args.text("filter").unwrap_or_default().to_ascii_lowercase();
            let limit = args.integer("limit").unwrap_or(500) as usize;
            let (client, cache) = engine.parts()?;
            let image = cache.image(client, &elf, base).ok_or("modulo sem imagem")?;
            let instructions = image.instructions();
            let mut memory = |address: u64, length: usize| image.read(address, length).or_else(|| client.read_memory(address, length).ok().filter(|bytes| !bytes.is_empty()));
            let found = kd_client::analysis::refs::string_references(&instructions, &mut memory, 4);
            let rows: Vec<Value> = found
                .into_iter()
                .filter(|reference| filter.is_empty() || reference.text.to_ascii_lowercase().contains(&filter))
                .take(limit)
                .map(|reference| json!({"address": hex(reference.address), "location": client.symbols.describe(reference.address), "target": hex(reference.target), "text": reference.text, "wide": reference.wide}))
                .collect();
            Ok(json!({"module": image.name, "results": rows, "milliseconds": started.elapsed().as_millis() as u64}))
        }
        "search_pattern" => {
            let pattern = search::parse_pattern(&args.text("pattern").unwrap_or_default())?;
            let module = match args.text("module") {
                Some(module) => module,
                None => format!("{:#x}", engine.client()?.register("rip")?),
            };
            let base = module_base(engine.client()?, &module)?;
            let limit = args.integer("limit").unwrap_or(200) as usize;
            let (client, cache) = engine.parts()?;
            let image = cache.image(client, &elf, base).ok_or("modulo sem imagem")?;
            let hits: Vec<Value> = pattern.find_all(&image.bytes, image.base, limit).into_iter().map(|address| json!({"address": hex(address), "location": client.symbols.describe(address)})).collect();
            Ok(json!({"module": image.name, "results": hits}))
        }
        _ => {
            let client = engine.client()?;
            let address = client.evaluate(&args.text("address").unwrap_or_default())?;
            let base = match args.text("module") {
                Some(module) => module_base(client, &module)?,
                None => address,
            };
            let (client, cache) = engine.parts()?;
            let index = cache.xrefs(client, &elf, base).ok_or("modulo sem imagem")?;
            let rows: Vec<Value> = index.get(&address).map(|list| list.iter().map(|(from, kind)| json!({"from": hex(*from), "location": client.symbols.describe(*from), "kind": format!("{kind:?}")})).collect()).unwrap_or_default();
            Ok(json!({"address": hex(address), "symbol": client.symbols.describe(address), "references": rows, "milliseconds": started.elapsed().as_millis() as u64}))
        }
    }
}

/// Espera um texto no log da COM1, recolhendo as paradas da máquina.
fn wait_for_serial(engine: &mut dyn Engine, args: &Arguments) -> ToolResult {
    let path = engine.serial_log().ok_or("log da COM1 desconhecido (use launch, ou connect com o build)")?;
    let marker = args.text("marker").unwrap_or_default();
    let after = args.integer("after_offset").unwrap_or(0) as usize;
    let deadline = Instant::now() + args.timeout(300_000);
    loop {
        if let Ok(bytes) = std::fs::read(&path) {
            let start = after.min(bytes.len());
            if let Some(position) = bytes[start..].windows(marker.len().max(1)).position(|window| window == marker.as_bytes()) {
                let at = start + position;
                let line_start = bytes[..at].iter().rposition(|&byte| byte == b'\n').map_or(0, |index| index + 1);
                let line_end = bytes[at..].iter().position(|&byte| byte == b'\n').map_or(bytes.len(), |index| at + index);
                return Ok(json!({"found": true, "offset": at + marker.len(), "line": String::from_utf8_lossy(&bytes[line_start..line_end]).trim_end().to_string()}));
            }
        }
        if let Ok(client) = engine.client() {
            if !client.is_stopped() {
                if let Some(stop) = client.poll(Duration::from_millis(100))? {
                    let mut value = stop_value(client, &stop);
                    value["found"] = json!(false);
                    value["note"] = json!("a maquina parou antes do texto aparecer");
                    return Ok(value);
                }
            } else {
                std::thread::sleep(Duration::from_millis(100));
            }
        } else {
            std::thread::sleep(Duration::from_millis(100));
        }
        if Instant::now() >= deadline {
            return Err(ToolError::Failed(format!("tempo esgotado esperando \"{marker}\" em {}", path.display())));
        }
    }
}

/// Os recursos: o log da COM1, o DbgPrint, os breakpoints e os módulos.
pub fn resources() -> Vec<Value> {
    vec![
        json!({"uri": "opennt://serial-log", "name": "serial-log", "title": "Log da COM1", "description": "O log do kernel na COM1 (os ultimos 64 KB)", "mimeType": "text/plain"}),
        json!({"uri": "opennt://dbgprint", "name": "dbgprint", "title": "DbgPrint", "description": "A saida do DbgPrint e dos breakpoints de log na sessao", "mimeType": "text/plain"}),
        json!({"uri": "opennt://breakpoints", "name": "breakpoints", "title": "Breakpoints", "description": "Os breakpoints da sessao", "mimeType": "application/json"}),
        json!({"uri": "opennt://modules", "name": "modules", "title": "Modulos", "description": "Os modulos carregados (kernel e o processo escolhido)", "mimeType": "application/json"}),
    ]
}

/// O `resources/read`.
pub fn read_resource(engine: &mut dyn Engine, uri: &str) -> Result<Value, String> {
    let (mime, text) = match uri {
        "opennt://serial-log" => {
            let path = engine.serial_log().ok_or("log da COM1 desconhecido")?;
            let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
            ("text/plain", String::from_utf8_lossy(&bytes[bytes.len().saturating_sub(64 << 10)..]).into_owned())
        }
        "opennt://dbgprint" => {
            let client = engine.client()?;
            let console = client.console();
            ("text/plain", console[console.len().saturating_sub(64 << 10)..].to_string())
        }
        "opennt://breakpoints" => {
            let client = engine.client()?;
            let list: Vec<Value> = client.breakpoints().iter().map(|breakpoint| breakpoint_value(client, breakpoint)).collect();
            ("application/json", serde_json::to_string_pretty(&list).unwrap_or_default())
        }
        "opennt://modules" => {
            let client = engine.client()?;
            let list: Vec<Value> = client.symbols.modules.iter().map(|module| json!({"name": module.name, "base": hex(module.base), "end": hex(module.end), "user": module.user})).collect();
            ("application/json", serde_json::to_string_pretty(&list).unwrap_or_default())
        }
        _ => return Err(format!("recurso desconhecido: {uri}")),
    };
    Ok(json!({"uri": uri, "mimeType": mime, "text": text}))
}

/// O anfitrião dos roteiros: comandos do depurador, expressões e a saída.
/// `g`/`run` esperam a próxima parada.
struct ScriptHost<'a> {
    client: &'a mut Client,
    output: Vec<String>,
}

impl script::Host for ScriptHost<'_> {
    fn execute(&mut self, command: &str) -> Result<String, String> {
        let word = command.split_whitespace().next().unwrap_or("");
        let output = match word {
            "g" | "c" | "run" | "continue" => {
                self.client.go()?;
                self.client.wait_stop(Duration::from_secs(300))
            }
            _ => self.client.execute(command),
        };
        match &output {
            Ok(text) if !text.trim().is_empty() => self.output.push(format!("> {command}\n{}", text.trim_end())),
            Ok(_) => {}
            Err(error) => self.output.push(format!("> {command}\nerro: {error}")),
        }
        output
    }

    fn evaluate(&mut self, expression: &str) -> Result<u64, String> {
        self.client.evaluate(expression)
    }

    fn output(&mut self, text: &str) {
        self.output.push(text.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schemas_are_valid_objects() {
        let mut names = std::collections::HashSet::new();
        for (name, description, schema) in definitions() {
            assert!(names.insert(name), "{name} repetida");
            assert!(!description.is_empty());
            assert_eq!(schema["type"], "object", "{name}");
            let properties = schema["properties"].as_object().unwrap();
            for required in schema["required"].as_array().unwrap() {
                assert!(properties.contains_key(required.as_str().unwrap()), "{name}: {required} fora das propriedades");
            }
            for (key, property) in properties {
                assert!(property.get("type").is_some(), "{name}.{key} sem tipo");
            }
        }
        assert!(names.len() >= 35);
    }

    #[test]
    fn validates_arguments() {
        let schema = definitions().into_iter().find(|(name, _, _)| *name == "memory_read").unwrap().2;
        assert!(validate(&schema, &json!({"address": "@rsp", "length": 16})).is_ok());
        assert_eq!(validate(&schema, &json!({"address": "@rsp"})), Err("falta o argumento length".into()));
        assert_eq!(validate(&schema, &json!({"address": 5, "length": 16})), Err("address precisa ser string".into()));
        assert!(validate(&schema, &json!({"address": "@rsp", "length": 0})).is_err());
        assert!(validate(&schema, &json!({"address": "@rsp", "length": 16, "outro": 1})).is_err());
        let schema = definitions().into_iter().find(|(name, _, _)| *name == "breakpoint_set").unwrap().2;
        assert!(validate(&schema, &json!({"address": "x", "kind": "voador"})).is_err());
        assert!(validate(&schema, &json!({"address": "x", "kind": "memory_write", "single_shot": true})).is_ok());
        assert_eq!(parse_hex_bytes("90 cc"), Ok(vec![0x90, 0xCC]));
        assert!(parse_hex_bytes("9").is_err());
    }
}
