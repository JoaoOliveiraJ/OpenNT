//! Ponta a ponta, sem janela: o `opennt-mcp` em stdio abre o OpenNT pelo
//! `launch` (o build com --kd=com2 e o QEMU sem tela), para a máquina, lê os
//! registradores, arma um breakpoint no laço principal do kernel, continua
//! até ele, tira o breakpoint, continua e espera um marcador da COM1.
//!
//! ```text
//! cargo test -p kd-mcp --release -- --ignored
//! ```
//!
//! `OPENNT_MCP_BUILD_DIR` troca o diretório de build (padrão build/mcp-e2e).

use std::io::{BufRead, BufReader, Write};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{json, Value};

struct Session {
    input: ChildStdin,
    replies: mpsc::Receiver<String>,
    next: u64,
}

impl Session {
    fn call(&mut self, name: &str, arguments: Value, wait: Duration) -> Value {
        self.next += 1;
        let message = json!({"jsonrpc": "2.0", "id": self.next, "method": "tools/call", "params": {"name": name, "arguments": arguments}});
        writeln!(self.input, "{message}").unwrap();
        self.input.flush().unwrap();
        let line = self.replies.recv_timeout(wait).unwrap_or_else(|_| panic!("{name}: sem resposta em {wait:?}"));
        let reply: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(reply["id"], self.next);
        assert_eq!(reply["result"]["isError"], false, "{name}: {reply}");
        eprintln!("[e2e] {name}: {}", reply["result"]["structuredContent"].to_string().chars().take(300).collect::<String>());
        reply["result"]["structuredContent"].clone()
    }
}

#[test]
#[ignore = "abre o QEMU (minutos): cargo test -p kd-mcp --release -- --ignored"]
fn launch_break_registers_breakpoint_and_serial_marker() {
    let root = kd_mcp::workspace_root();
    let build_dir = std::env::var("OPENNT_MCP_BUILD_DIR").unwrap_or_else(|_| "build/mcp-e2e".into());
    let mut child = Command::new(env!("CARGO_BIN_EXE_opennt-mcp")).arg(format!("--root={}", root.display())).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap();
    let input = child.stdin.take().unwrap();
    let output = child.stdout.take().unwrap();
    let (sender, replies) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(output).lines() {
            let Ok(line) = line else { break };
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let mut session = Session { input, replies, next: 0 };
    writeln!(session.input, "{}", json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "e2e", "version": "1"}}})).unwrap();
    session.input.flush().unwrap();
    let reply: Value = serde_json::from_str(&session.replies.recv_timeout(Duration::from_secs(30)).unwrap()).unwrap();
    assert_eq!(reply["result"]["serverInfo"]["name"], "opennt-mcp");
    writeln!(session.input, "{}", json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).unwrap();

    // O build e o boot até o attach.
    let launched = session.call("launch", json!({"build_dir": build_dir, "headless": true, "smp": 2, "timeout_ms": 1_800_000}), Duration::from_secs(3600));
    assert_eq!(launched["stopped"], true);
    let status = session.call("status", json!({}), Duration::from_secs(60));
    assert_eq!(status["connected"], true);
    // Os registradores da parada do attach.
    let registers = session.call("registers_get", json!({"extended": true}), Duration::from_secs(60));
    let rip = registers["registers"]["rip"].as_str().unwrap().to_string();
    assert!(rip.starts_with("0xfffff8"), "{rip}");
    assert!(registers["extended"]["xmm"].as_array().unwrap().len() == 16);
    // O breakpoint no laço principal do kernel e a parada nele.
    let breakpoint = session.call("breakpoint_set", json!({"address": "kernel::ntos::ke::run_kernel_tasks", "name": "laco"}), Duration::from_secs(60));
    let id = breakpoint["id"].as_u64().unwrap();
    session.call("go", json!({}), Duration::from_secs(60));
    let stop = session.call("wait_for_stop", json!({"timeout_ms": 600_000}), Duration::from_secs(700));
    assert!(stop["symbol"].as_str().unwrap().contains("run_kernel_tasks"), "{stop}");
    assert!(stop["stop"].as_str().unwrap().contains("breakpoint #"), "{stop}");
    let listing = session.call("disassemble", json!({"count": 8}), Duration::from_secs(60));
    assert_eq!(listing["lines"][0]["function_start"], true, "{listing}");
    let frames = session.call("backtrace", json!({"limit": 16}), Duration::from_secs(60));
    assert!(frames["frames"].as_array().unwrap().iter().any(|frame| frame["symbol"].as_str().unwrap_or("").contains("kmain")), "{frames}");
    // Sem o breakpoint, a máquina segue até o marcador da COM1.
    session.call("breakpoint_clear", json!({"id": id}), Duration::from_secs(60));
    session.call("go", json!({}), Duration::from_secs(60));
    let marker = session.call("wait_for_serial", json!({"marker": "[shell] pronto", "timeout_ms": 600_000}), Duration::from_secs(700));
    assert_eq!(marker["found"], true, "{marker}");
    let log = session.call("read_serial_log", json!({"max_bytes": 2048}), Duration::from_secs(60));
    assert!(log["size"].as_u64().unwrap() > 0);
    session.call("detach", json!({}), Duration::from_secs(120));
    drop(session);
    let _ = child.wait();
}
