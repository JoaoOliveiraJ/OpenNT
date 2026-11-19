//! O Model Context Protocol sobre JSON-RPC 2.0: a negociação
//! (`initialize`), `ping`, `tools/list`, `tools/call`, `resources/list` e
//! `resources/read`. O transporte (stdio ou HTTP) entrega cada mensagem em
//! texto e manda a resposta que voltar.
//!
//! Erros:
//! - JSON inválido: `-32700`; mensagem que não é pedido JSON-RPC: `-32600`;
//! - método desconhecido: `-32601`; ferramenta desconhecida ou argumentos
//!   que não seguem o esquema: `-32602`;
//! - falha da ferramenta (alvo sem sessão, expressão inválida, tempo
//!   esgotado): o resultado com `isError: true` e o texto do erro, como o
//!   protocolo pede, para o modelo ler.

use serde_json::{json, Value};

use crate::engine::Engine;
use crate::session::Session;
use crate::tools::{self, ToolError};

/// As versões do protocolo aceitas (a primeira é a preferida).
pub const PROTOCOL_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;

/// O estado de uma conexão MCP: a versão negociada e o estado das
/// ferramentas (`Session`: os breakpoints de usuário adiados, o que já foi
/// entregue dos logs, o log da COM1 do `connect`).
#[derive(Default)]
pub struct Server {
    pub version: Option<String>,
    pub client_name: String,
    pub session: Session,
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn result(id: Value, value: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": value})
}

impl Server {
    pub fn new() -> Server {
        Server::default()
    }

    /// Uma mensagem em texto (um objeto ou um lote): a resposta em texto, ou
    /// `None` quando só havia notificações.
    pub fn handle_text(&mut self, text: &str, engine: &mut dyn Engine) -> Option<String> {
        let message: Value = match serde_json::from_str(text) {
            Ok(message) => message,
            Err(problem) => return Some(error(Value::Null, PARSE_ERROR, &format!("JSON invalido: {problem}")).to_string()),
        };
        match message {
            Value::Array(batch) => {
                if batch.is_empty() {
                    return Some(error(Value::Null, INVALID_REQUEST, "lote vazio").to_string());
                }
                let replies: Vec<Value> = batch.into_iter().filter_map(|item| self.handle(item, engine)).collect();
                (!replies.is_empty()).then(|| Value::Array(replies).to_string())
            }
            single => self.handle(single, engine).map(|reply| reply.to_string()),
        }
    }

    /// Uma mensagem JSON-RPC; `None` para notificações e respostas.
    pub fn handle(&mut self, message: Value, engine: &mut dyn Engine) -> Option<Value> {
        let Some(object) = message.as_object() else { return Some(error(Value::Null, INVALID_REQUEST, "a mensagem precisa ser um objeto")) };
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Some(error(object.get("id").cloned().unwrap_or(Value::Null), INVALID_REQUEST, "jsonrpc precisa ser \"2.0\""));
        }
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            // Uma resposta do cliente (o servidor não faz pedidos): ignorada.
            return None;
        };
        let Some(id) = object.get("id").cloned() else {
            // Notificação (`notifications/initialized`, `notifications/cancelled`).
            return None;
        };
        let params = object.get("params").cloned().unwrap_or(Value::Object(Default::default()));
        Some(match method {
            "initialize" => result(id, self.initialize(&params)),
            "ping" => result(id, json!({})),
            "tools/list" => result(id, json!({"tools": tools::list()})),
            "tools/call" => self.call(id, &params, engine),
            "resources/list" => result(id, json!({"resources": tools::resources()})),
            "resources/templates/list" => result(id, json!({"resourceTemplates": []})),
            "resources/read" => match params.get("uri").and_then(Value::as_str) {
                Some(uri) => match tools::read_resource(engine, &self.session, uri) {
                    Ok(contents) => result(id, json!({"contents": [contents]})),
                    Err(message) => error(id, INVALID_PARAMS, &message),
                },
                None => error(id, INVALID_PARAMS, "resources/read precisa de uri"),
            },
            "prompts/list" => result(id, json!({"prompts": []})),
            _ => error(id, METHOD_NOT_FOUND, &format!("metodo desconhecido: {method}")),
        })
    }

    fn initialize(&mut self, params: &Value) -> Value {
        let wanted = params.get("protocolVersion").and_then(Value::as_str).unwrap_or(PROTOCOL_VERSIONS[0]);
        let version = PROTOCOL_VERSIONS.iter().find(|candidate| **candidate == wanted).copied().unwrap_or(PROTOCOL_VERSIONS[0]);
        self.version = Some(version.to_string());
        self.client_name = params.pointer("/clientInfo/name").and_then(Value::as_str).unwrap_or("").to_string();
        json!({
            "protocolVersion": version,
            "capabilities": {
                "tools": {"listChanged": false},
                "resources": {"subscribe": false, "listChanged": false}
            },
            "serverInfo": {"name": "opennt-mcp", "title": "Depurador do OpenNT", "version": env!("CARGO_PKG_VERSION")},
            "instructions": "Depurador do kernel do OpenNT (e dos processos de usuario dentro dele). Comece por launch (compila, abre o QEMU e anexa; until_marker continua o boot ate um texto da COM1) ou connect (um QEMU ja aberto com --kd=com2, com serial_log). Fluxo comum: breakpoint_user (por nome de processo, dwm.exe; adiado ate a DLL carregar) ou breakpoint_set, continue_until (ate uma parada ou um texto da COM1, com as linhas novas dos breakpoints de log), stack, registers_get, memory_view, disassemble. kd_script roda os roteiros do test-boot --kd=com2 e devolve o log. Sem sessao: status_decode (NTSTATUS, HRESULT, Win32), serial_summary, crash_analyze e wdlog sobre um serial.log, annotations_list. Enderecos sao expressoes em texto: 0x..., simbolos (ntdll!LdrLoadDll, kernel::ntos::ke::run_kernel_tasks), @rip, poi(@rsp); process aceita o nome (dwm.exe, svchost.exe#2), o PID ou o EPROCESS."
        })
    }

    fn call(&mut self, id: Value, params: &Value, engine: &mut dyn Engine) -> Value {
        let Some(name) = params.get("name").and_then(Value::as_str) else { return error(id, INVALID_PARAMS, "tools/call precisa de name") };
        let arguments = params.get("arguments").cloned().unwrap_or(Value::Object(Default::default()));
        match tools::call(engine, &mut self.session, name, &arguments) {
            Ok(value) => {
                let text = serde_json::to_string_pretty(&value).unwrap_or_default();
                result(id, json!({"content": [{"type": "text", "text": text}], "structuredContent": value, "isError": false}))
            }
            Err(ToolError::InvalidParams(message)) => error(id, INVALID_PARAMS, &message),
            Err(ToolError::Failed(message)) => result(id, json!({"content": [{"type": "text", "text": message.clone()}], "structuredContent": {"error": message}, "isError": true})),
        }
    }
}
