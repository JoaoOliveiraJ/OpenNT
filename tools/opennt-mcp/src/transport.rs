//! Os transportes do MCP:
//!
//! - stdio: uma mensagem JSON-RPC por linha na entrada padrão e cada
//!   resposta numa linha da saída padrão (o log vai para a saída de erro);
//! - HTTP local (o "streamable HTTP" sem fluxo SSE): `POST /mcp` com a
//!   mensagem no corpo devolve a resposta em `application/json` (ou `202`
//!   para notificações); `GET` devolve `405` (o servidor não abre fluxo);
//!   `DELETE` encerra a sessão. Só escuta em 127.0.0.1 e recusa um `Origin`
//!   que não seja local (proteção contra páginas da web).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Lê mensagens da entrada padrão até ela fechar.
pub fn serve_stdio(handler: &mut dyn FnMut(&str) -> Option<String>) {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        if let Some(reply) = handler(&line) {
            let mut output = stdout.lock();
            let _ = writeln!(output, "{reply}");
            let _ = output.flush();
        }
    }
}

/// Um pedido HTTP lido.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl HttpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }
}

/// Lê um pedido (linha, cabeçalhos e o corpo pelo Content-Length).
pub fn read_request(stream: &mut dyn Read) -> Result<HttpRequest, String> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|error| error.to_string())?;
    let mut parts = line.split_whitespace();
    let mut request = HttpRequest { method: parts.next().unwrap_or("").to_string(), path: parts.next().unwrap_or("").to_string(), ..Default::default() };
    if request.method.is_empty() {
        return Err("pedido vazio".into());
    }
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).map_err(|error| error.to_string())?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((key, value)) = header.split_once(':') {
            request.headers.push((key.trim().to_string(), value.trim().to_string()));
        }
        if request.headers.len() > 100 {
            return Err("cabecalhos demais".into());
        }
    }
    let length: usize = request.header("content-length").and_then(|value| value.parse().ok()).unwrap_or(0);
    if length > 16 << 20 {
        return Err("corpo grande demais".into());
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).map_err(|error| error.to_string())?;
    request.body = String::from_utf8_lossy(&body).into_owned();
    Ok(request)
}

/// O `Origin` é local (ou ausente, como nos clientes que não são páginas).
pub fn local_origin(origin: Option<&str>) -> bool {
    match origin {
        None => true,
        Some(origin) => {
            let rest = origin.strip_prefix("http://").or_else(|| origin.strip_prefix("https://")).unwrap_or(origin);
            let host = rest.split(['/', ':']).next().unwrap_or("");
            host == "127.0.0.1" || host == "localhost" || host == "[::1]"
        }
    }
}

/// A resposta HTTP de um pedido: status, cabeçalhos extras e corpo.
pub fn respond(request: &HttpRequest, session: &str, handler: &mut dyn FnMut(&str) -> Option<String>) -> (u16, Vec<(String, String)>, String) {
    if !local_origin(request.header("origin")) {
        return (403, Vec::new(), "origem nao local".into());
    }
    let path = request.path.split('?').next().unwrap_or("");
    if path != "/mcp" && path != "/" {
        return (404, Vec::new(), "use /mcp".into());
    }
    match request.method.as_str() {
        "POST" => match handler(&request.body) {
            Some(reply) => (200, vec![("Content-Type".into(), "application/json".into()), ("Mcp-Session-Id".into(), session.to_string())], reply),
            None => (202, vec![("Mcp-Session-Id".into(), session.to_string())], String::new()),
        },
        "GET" => (405, vec![("Allow".into(), "POST, DELETE".into())], String::new()),
        "DELETE" => (200, Vec::new(), String::new()),
        _ => (405, vec![("Allow".into(), "POST, DELETE".into())], String::new()),
    }
}

fn write_response(stream: &mut TcpStream, status: u16, headers: &[(String, String)], body: &str) {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Bad Request",
    };
    let mut text = format!("HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
    for (key, value) in headers {
        text.push_str(&format!("{key}: {value}\r\n"));
    }
    text.push_str("\r\n");
    text.push_str(body);
    let _ = stream.write_all(text.as_bytes());
    let _ = stream.flush();
}

/// Uma identificação de sessão (o relógio e o PID, em hexadecimal).
pub fn session_id() -> String {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|elapsed| elapsed.as_nanos()).unwrap_or(0);
    format!("opennt-{:x}-{:x}", nanos, std::process::id())
}

/// Atende HTTP em `listener` (que deve estar em 127.0.0.1) até `stop`
/// ligar; um pedido por conexão.
pub fn serve_http(listener: TcpListener, stop: Arc<AtomicBool>, handler: &mut dyn FnMut(&str) -> Option<String>) {
    let session = session_id();
    let _ = listener.set_nonblocking(true);
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, peer)) => {
                if !peer.ip().is_loopback() {
                    continue;
                }
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
                let request = match read_request(&mut stream) {
                    Ok(request) => request,
                    Err(error) => {
                        write_response(&mut stream, 400, &[], &error);
                        continue;
                    }
                };
                let (status, headers, body) = respond(&request, &session, handler);
                write_response(&mut stream, status, &headers, &body);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_requests_and_checks_origin() {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        let text = format!("POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let request = read_request(&mut text.as_bytes()).unwrap();
        assert_eq!((request.method.as_str(), request.path.as_str(), request.body.as_str()), ("POST", "/mcp", body));
        assert_eq!(request.header("content-type"), Some("application/json"));
        let mut handler = |message: &str| Some(format!("eco {message}"));
        let (status, headers, reply) = respond(&request, "s1", &mut handler);
        assert_eq!(status, 200);
        assert!(headers.iter().any(|(key, value)| key == "Mcp-Session-Id" && value == "s1"));
        assert_eq!(reply, format!("eco {body}"));
        assert!(local_origin(Some("http://localhost:3000")));
        assert!(local_origin(Some("http://127.0.0.1")));
        assert!(!local_origin(Some("https://exemplo.com")));
        let hostile = HttpRequest { method: "POST".into(), path: "/mcp".into(), headers: vec![("Origin".into(), "https://exemplo.com".into())], body: body.into() };
        assert_eq!(respond(&hostile, "s1", &mut handler).0, 403);
        let get = HttpRequest { method: "GET".into(), path: "/mcp".into(), ..Default::default() };
        assert_eq!(respond(&get, "s1", &mut handler).0, 405);
        let mut silent = |_: &str| None;
        assert_eq!(respond(&request, "s1", &mut silent).0, 202);
    }
}
