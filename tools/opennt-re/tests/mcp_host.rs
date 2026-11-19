//! O servidor MCP hospedado pela janela, sem janela e sem QEMU: o backend
//! liga o ponto de acesso HTTP em 127.0.0.1 e responde à negociação, à
//! lista de ferramentas e ao `status` com a sessão dele (ainda sem alvo).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use opennt_re::backend::{Backend, Config, Request};
use serde_json::{json, Value};

fn post(address: &str, body: &Value) -> (u16, String) {
    let mut stream = TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let text = body.to_string();
    write!(stream, "POST /mcp HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\n\r\n{text}", text.len()).unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    let status = reply.split_whitespace().nth(1).and_then(|code| code.parse().ok()).unwrap_or(0);
    let body = reply.split_once("\r\n\r\n").map(|(_, body)| body.to_string()).unwrap_or_default();
    (status, body)
}

#[test]
fn hosted_mcp_endpoint_answers() {
    let config = Config { root: opennt_re::workspace_root(), elf: "inexistente/kernel.elf".into(), serial_log: None, session: None, script: None };
    let backend = Backend::start(config, None, Arc::new(|| {}));
    backend.send(Request::SetMcp(Some(0)));
    assert!(backend.wait_for(Duration::from_secs(10), |shared| shared.mcp.is_some()), "o servidor nao ligou");
    let address = backend.shared().mcp.clone().unwrap();
    let (status, body) = post(&address, &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "teste", "version": "1"}}}));
    assert_eq!(status, 200, "{body}");
    let reply: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(reply["result"]["serverInfo"]["name"], "opennt-mcp");
    let (status, _) = post(&address, &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    assert_eq!(status, 202);
    let (_, body) = post(&address, &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let reply: Value = serde_json::from_str(&body).unwrap();
    assert!(reply["result"]["tools"].as_array().unwrap().len() >= 35);
    let (_, body) = post(&address, &json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "status", "arguments": {}}}));
    let reply: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(reply["result"]["structuredContent"]["connected"], false, "{reply}");
    // Sem alvo, uma ferramenta que precisa da sessão falha no resultado.
    let (_, body) = post(&address, &json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "registers_get", "arguments": {}}}));
    let reply: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(reply["result"]["isError"], true);
    backend.send(Request::SetMcp(None));
    assert!(backend.wait_for(Duration::from_secs(10), |shared| shared.mcp.is_none()));
}
