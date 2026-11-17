//! `opennt-mcp`: o servidor MCP do depurador do OpenNT.
//!
//! ```text
//! opennt-mcp                       stdio (uma mensagem JSON-RPC por linha)
//! opennt-mcp --http=7000           HTTP em 127.0.0.1:7000, caminho /mcp
//! opennt-mcp --root=C:/OpenNT      outra raiz do repositorio
//! ```

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use kd_mcp::{transport, Server, Standalone};

const USAGE: &str = "uso: opennt-mcp [--http=PORTA] [--root=DIR]
  sem opcoes          MCP pela entrada e saida padrao (uma mensagem JSON-RPC por linha)
  --http=PORTA        MCP por HTTP em 127.0.0.1:PORTA/mcp (POST; so conexoes locais)
  --root=DIR          raiz do repositorio do OpenNT (padrao: a deste checkout)
as ferramentas launch/connect abrem a sessao; o log vai para a saida de erro";

fn main() -> ExitCode {
    let mut http: Option<u16> = None;
    let mut root = kd_mcp::workspace_root();
    for argument in std::env::args().skip(1) {
        match argument.split_once('=') {
            Some(("--http", port)) => match port.parse() {
                Ok(port) => http = Some(port),
                Err(_) => {
                    eprintln!("--http: porta invalida\n{USAGE}");
                    return ExitCode::FAILURE;
                }
            },
            Some(("--root", directory)) => root = PathBuf::from(directory),
            _ => {
                eprintln!("{USAGE}");
                return if argument == "--help" || argument == "-h" { ExitCode::SUCCESS } else { ExitCode::FAILURE };
            }
        }
    }
    let mut engine = Standalone::new(root);
    let mut server = Server::new();
    let mut handler = |message: &str| server.handle_text(message, &mut engine);
    match http {
        Some(port) => {
            let listener = match TcpListener::bind(("127.0.0.1", port)) {
                Ok(listener) => listener,
                Err(error) => {
                    eprintln!("127.0.0.1:{port}: {error}");
                    return ExitCode::FAILURE;
                }
            };
            eprintln!("[opennt-mcp] HTTP em http://127.0.0.1:{port}/mcp");
            transport::serve_http(listener, Arc::new(AtomicBool::new(false)), &mut handler);
        }
        None => transport::serve_stdio(&mut handler),
    }
    ExitCode::SUCCESS
}
