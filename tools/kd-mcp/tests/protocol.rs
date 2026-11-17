//! O protocolo MCP do `opennt-mcp`: a negociação, a lista de ferramentas
//! (esquemas válidos), os erros e as chamadas contra o alvo de mentira do
//! `kd-client` (`tools/kd-client/tests/support/fake_stub.rs`), pela
//! biblioteca e pelo binário em stdio.

#[path = "../../kd-client/tests/support/fake_stub.rs"]
mod fake_stub;

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use fake_stub::{start, Stop, CODE, STACK};
use kd_mcp::{Server, Standalone};
use serde_json::{json, Value};

fn request(server: &mut Server, engine: &mut Standalone, id: u64, method: &str, params: Value) -> Value {
    let message = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string();
    let reply = server.handle_text(&message, engine).expect("resposta");
    serde_json::from_str(&reply).unwrap()
}

fn call(server: &mut Server, engine: &mut Standalone, id: u64, name: &str, arguments: Value) -> Value {
    let reply = request(server, engine, id, "tools/call", json!({"name": name, "arguments": arguments}));
    assert!(reply.get("error").is_none(), "{name}: {reply}");
    let result = reply["result"].clone();
    assert_eq!(result["isError"], false, "{name}: {result}");
    // O texto é o mesmo objeto estruturado.
    let text: Value = serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text, result["structuredContent"]);
    result["structuredContent"].clone()
}

#[test]
fn initialize_and_list_tools() {
    let mut server = Server::new();
    let mut engine = Standalone::new(std::path::PathBuf::from("."));
    let reply = request(&mut server, &mut engine, 1, "initialize", json!({"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "teste", "version": "1"}}));
    assert_eq!(reply["jsonrpc"], "2.0");
    assert_eq!(reply["id"], 1);
    let result = &reply["result"];
    assert_eq!(result["protocolVersion"], "2025-03-26");
    assert_eq!(result["serverInfo"]["name"], "opennt-mcp");
    assert!(result["capabilities"]["tools"].is_object());
    assert!(result["capabilities"]["resources"].is_object());
    // Uma versão desconhecida recebe a preferida do servidor.
    let reply = request(&mut server, &mut engine, 2, "initialize", json!({"protocolVersion": "1999-01-01"}));
    assert_eq!(reply["result"]["protocolVersion"], "2025-06-18");
    // A notificação não tem resposta.
    assert!(server.handle_text(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#, &mut engine).is_none());
    assert_eq!(request(&mut server, &mut engine, 3, "ping", json!({}))["result"], json!({}));
    let tools = request(&mut server, &mut engine, 4, "tools/list", json!({}))["result"]["tools"].as_array().unwrap().clone();
    let names: Vec<&str> = tools.iter().map(|tool| tool["name"].as_str().unwrap()).collect();
    for wanted in [
        "launch", "connect", "detach", "status", "break", "go", "step_into", "step_over", "step_out", "run_to", "registers_get", "register_set", "memory_read", "memory_write", "disassemble", "symbol_lookup", "symbol_resolve", "modules", "processes", "threads", "breakpoint_set", "breakpoint_clear", "breakpoint_list", "backtrace", "search_strings",
        "search_pattern", "xrefs", "nt_view", "trace_start", "trace_stop", "trace_fetch", "wait_for_serial", "read_serial_log", "run_script", "screenshot",
    ] {
        assert!(names.contains(&wanted), "falta {wanted}");
    }
    for tool in &tools {
        let schema = &tool["inputSchema"];
        assert_eq!(schema["type"], "object", "{}", tool["name"]);
        assert!(tool["description"].as_str().is_some_and(|text| text.len() > 10));
        let properties = schema["properties"].as_object().unwrap();
        for required in schema["required"].as_array().unwrap() {
            assert!(properties.contains_key(required.as_str().unwrap()));
        }
        for property in properties.values() {
            assert!(["string", "integer", "boolean", "array", "object"].contains(&property["type"].as_str().unwrap()));
        }
    }
    let resources = request(&mut server, &mut engine, 5, "resources/list", json!({}))["result"]["resources"].as_array().unwrap().len();
    assert_eq!(resources, 4);
}

#[test]
fn protocol_errors() {
    let mut server = Server::new();
    let mut engine = Standalone::new(std::path::PathBuf::from("."));
    let reply: Value = serde_json::from_str(&server.handle_text("{nao e json", &mut engine).unwrap()).unwrap();
    assert_eq!(reply["error"]["code"], -32700);
    assert_eq!(request(&mut server, &mut engine, 1, "metodo/inexistente", json!({}))["error"]["code"], -32601);
    let reply = request(&mut server, &mut engine, 2, "tools/call", json!({"name": "voar", "arguments": {}}));
    assert_eq!(reply["error"]["code"], -32602);
    let reply = request(&mut server, &mut engine, 3, "tools/call", json!({"name": "memory_read", "arguments": {"address": "@rsp"}}));
    assert_eq!(reply["error"]["code"], -32602);
    assert!(reply["error"]["message"].as_str().unwrap().contains("length"));
    // Sem sessão, a ferramenta falha no resultado (isError).
    let reply = request(&mut server, &mut engine, 4, "tools/call", json!({"name": "registers_get", "arguments": {}}));
    assert_eq!(reply["result"]["isError"], true);
    assert!(reply["result"]["content"][0]["text"].as_str().unwrap().contains("sem sessao"));
    // Um lote com um pedido e uma notificação: uma resposta.
    let batch = r#"[{"jsonrpc":"2.0","id":9,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"}]"#;
    let reply: Value = serde_json::from_str(&server.handle_text(batch, &mut engine).unwrap()).unwrap();
    assert_eq!(reply.as_array().unwrap().len(), 1);
    // A ferramenta status sem sessão funciona.
    let reply = request(&mut server, &mut engine, 5, "tools/call", json!({"name": "status", "arguments": {}}));
    assert_eq!(reply["result"]["structuredContent"]["connected"], false);
}

#[test]
fn tools_against_the_fake_stub() {
    // O alvo para em CODE + 0x100 (o preparo da chamada ao IoCreateDevice)
    // depois do `go`.
    let stops = vec![Stop { rip: CODE + 0x108, rsp: STACK, packet: "T05thread:1;swbreak:;", rax: 0, load: None }];
    let (address, log) = start(stops);
    let mut server = Server::new();
    let mut engine = Standalone::new(std::path::PathBuf::from("."));
    request(&mut server, &mut engine, 1, "initialize", json!({"protocolVersion": "2025-06-18"}));
    let attached = call(&mut server, &mut engine, 2, "connect", json!({"address": address, "elf": "inexistente/kernel.elf"}));
    assert_eq!(attached["stopped"], true);
    engine.client.as_mut().unwrap().symbols.set_kernel(fake_stub::kernel_module());
    let registers = call(&mut server, &mut engine, 3, "registers_get", json!({"extended": true}));
    assert_eq!(registers["registers"]["rip"], format!("{CODE:#x}"));
    assert_eq!(registers["rip_symbol"], "kernel::alvo::corrente");
    assert_eq!(registers["extended"]["mxcsr"]["value"], "0x1f80");
    assert_eq!(registers["extended"]["debug"]["dr7"], "0x401");
    let memory = call(&mut server, &mut engine, 4, "memory_read", json!({"address": "@rip", "length": 4}));
    assert_eq!(memory["hex"], "48 83 ec 20");
    // A desmontagem com o comentário automático da chamada (os argumentos
    // pelo preparo: mov edx, 0x40; xor r8d, r8d).
    let listing = call(&mut server, &mut engine, 5, "disassemble", json!({"address": format!("{:#x}", CODE + 0x100), "count": 3}));
    let lines = listing["lines"].as_array().unwrap();
    let comment = lines[2]["comment"].as_str().unwrap();
    assert!(comment.starts_with("IoCreateDevice(DriverObject=?, DeviceExtensionSize=0x40, DeviceName=NULL, DeviceType=?"), "{comment}");
    assert_eq!(listing["functions"].as_array().unwrap().len(), 0);
    let breakpoint = call(&mut server, &mut engine, 6, "breakpoint_set", json!({"address": format!("{:#x}", CODE + 0x108), "name": "chamada", "single_shot": true}));
    assert_eq!(breakpoint["name"], "chamada");
    assert!(log.lock().unwrap().iter().any(|packet| packet == &format!("Z0,{:x},1", CODE + 0x108)));
    assert_eq!(call(&mut server, &mut engine, 7, "go", json!({}))["running"], true);
    let stop = call(&mut server, &mut engine, 8, "wait_for_stop", json!({"timeout_ms": 10000}));
    assert_eq!(stop["rip"], format!("{:#x}", CODE + 0x108));
    assert!(stop["stop"].as_str().unwrap().contains("breakpoint #0 chamada"), "{stop}");
    // A parada no `call`: os argumentos de verdade (os registradores).
    let listing = call(&mut server, &mut engine, 9, "disassemble", json!({"count": 1}));
    assert!(listing["lines"][0]["comment"].as_str().unwrap().starts_with("IoCreateDevice(DriverObject=NULL"), "{listing}");
    // Uma vez só: o breakpoint saiu.
    assert_eq!(call(&mut server, &mut engine, 10, "breakpoint_list", json!({}))["breakpoints"].as_array().unwrap().len(), 0);
    let frames = call(&mut server, &mut engine, 11, "backtrace", json!({"limit": 4}));
    assert!(!frames["frames"].as_array().unwrap().is_empty());
    let symbol = call(&mut server, &mut engine, 12, "symbol_resolve", json!({"name": "IoCreateDevice"}));
    assert_eq!(symbol["address"], format!("{:#x}", CODE + 0x3800));
    let output = call(&mut server, &mut engine, 13, "command", json!({"text": "? 1+2*3"}));
    assert!(output["output"].as_str().unwrap().contains("0x7"));
    let resource = request(&mut server, &mut engine, 14, "resources/read", json!({"uri": "opennt://breakpoints"}));
    assert_eq!(resource["result"]["contents"][0]["mimeType"], "application/json");
    assert_eq!(call(&mut server, &mut engine, 15, "detach", json!({}))["detached"].as_str().unwrap().contains("desligado"), true);
}

#[test]
fn reverse_engineering_tools_against_the_fake_stub() {
    let (address, log) = start(Vec::new());
    let mut server = Server::new();
    let mut engine = Standalone::new(std::path::PathBuf::from("."));
    request(&mut server, &mut engine, 1, "initialize", json!({"protocolVersion": "2025-06-18"}));
    call(&mut server, &mut engine, 2, "connect", json!({"address": address, "elf": "inexistente/kernel.elf"}));
    engine.client.as_mut().unwrap().symbols.set_kernel(fake_stub::kernel_module());
    // O monitor de APIs: as especificações dos protótipos e a chamada lida.
    let started = call(&mut server, &mut engine, 3, "api_monitor_start", json!({}));
    assert_eq!(started["enabled"], true);
    assert!(log.lock().unwrap().iter().any(|packet| packet.starts_with("qRcmd,") && String::from_utf8(kd_client::rsp::unhex(&packet[6..])).unwrap().starts_with("api spec 40:7:3:1:7:6")));
    let fetched = call(&mut server, &mut engine, 4, "api_monitor_fetch", json!({"export": "createdevice"}));
    assert_eq!(fetched["matching"], 1, "{fetched}");
    let row = &fetched["rows"][0];
    assert_eq!(row["export"], "IoCreateDevice");
    assert_eq!(row["status"]["name"], "STATUS_SUCCESS");
    assert!(row["arguments"].as_str().unwrap().contains("DeviceName=\"\\Device\\Falso\""), "{row}");
    assert_eq!(row["return_address"], format!("{:#x}", CODE + 0x10D));
    assert_eq!(call(&mut server, &mut engine, 5, "api_monitor_fetch", json!({"failures_only": true}))["matching"], 0);
    // O rastreador de IRPs: o CREATE pelos dois dispositivos, concluído.
    assert_eq!(call(&mut server, &mut engine, 6, "irp_trace_start", json!({}))["enabled"], true);
    let irps = call(&mut server, &mut engine, 7, "irp_trace_fetch", json!({"major": "create"}));
    assert_eq!(irps["matching"], 1, "{irps}");
    assert_eq!(irps["irps"][0]["hops"], 2);
    assert_eq!(irps["irps"][0]["completed"], true);
    let detail = call(&mut server, &mut engine, 8, "irp_trace_fetch", json!({"irp": "0"}));
    assert_eq!(detail["final_status"]["name"], "STATUS_SUCCESS");
    assert_eq!(detail["steps"].as_array().unwrap().len(), 3);
    // Os exploradores.
    let key = call(&mut server, &mut engine, 9, "registry_list", json!({"path": "\\Registry\\Machine\\SYSTEM\\Select"}));
    assert_eq!(key["values"][0]["name"], "Current");
    assert_eq!(key["values"][0]["type"], "REG_DWORD");
    let value = call(&mut server, &mut engine, 10, "registry_read", json!({"path": "\\Registry\\Machine\\SYSTEM\\Select", "name": "Current"}));
    assert_eq!(value["text"], "0x00000001 (1)");
    let objects = call(&mut server, &mut engine, 11, "object_list", json!({"path": "\\Device"}));
    assert_eq!(objects["objects"][1]["target"], "\\Device\\Harddisk0\\Partition1");
    let files = call(&mut server, &mut engine, 12, "file_list", json!({}));
    assert_eq!(files["entries"][1]["name"], "teste.txt");
    let data = call(&mut server, &mut engine, 13, "file_read", json!({"path": "/teste.txt"}));
    assert_eq!(data["text"], "ola!!");
    // Sem reprodução e sem o monitor do QEMU: erros claros.
    let reverse = request(&mut server, &mut engine, 14, "tools/call", json!({"name": "reverse_step", "arguments": {}}));
    assert_eq!(reverse["result"]["isError"], true);
    assert!(reverse["result"]["content"][0]["text"].as_str().unwrap().contains("reproducao"), "{reverse}");
    let snapshots = request(&mut server, &mut engine, 15, "tools/call", json!({"name": "snapshot_list", "arguments": {}}));
    assert_eq!(snapshots["result"]["isError"], true);
    // A vista como tipo: um tipo que não existe no PDB (ou o PDB ausente).
    let typed = request(&mut server, &mut engine, 16, "tools/call", json!({"name": "view_struct", "arguments": {"type": "_TIPO_QUE_NAO_EXISTE", "address": "@rip"}}));
    assert_eq!(typed["result"]["isError"], true);
    assert_eq!(call(&mut server, &mut engine, 17, "api_monitor_stop", json!({}))["enabled"], false);
}

#[test]
fn stdio_binary_round_trip() {
    let (address, _) = start(Vec::new());
    let mut child = Command::new(env!("CARGO_BIN_EXE_opennt-mcp")).arg("--root=.").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let send = |input: &mut std::process::ChildStdin, message: Value| {
        writeln!(input, "{message}").unwrap();
        input.flush().unwrap();
    };
    let mut receive = || -> Value {
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    };
    send(&mut input, json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "teste", "version": "1"}}}));
    assert_eq!(receive()["result"]["serverInfo"]["name"], "opennt-mcp");
    send(&mut input, json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    send(&mut input, json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "connect", "arguments": {"address": address, "elf": "inexistente/kernel.elf"}}}));
    let reply = receive();
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    send(&mut input, json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "registers_get", "arguments": {}}}));
    assert_eq!(receive()["result"]["structuredContent"]["registers"]["rsp"], format!("{STACK:#x}"));
    drop(input);
    let status = child.wait().unwrap();
    assert!(status.success());
}
