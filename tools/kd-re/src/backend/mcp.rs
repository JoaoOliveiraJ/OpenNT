//! O servidor MCP hospedado pela janela: o mesmo `kd_mcp::Server` do
//! `opennt-mcp`, com a sessão do backend como `Engine`. Uma thread atende
//! HTTP em 127.0.0.1 e manda cada mensagem ao backend (`Request::Mcp`);
//! a IA e o usuário mexem no mesmo alvo, e a janela relê a parada depois
//! de cada ferramenta.

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::time::Duration;

use kd_client::launcher::LaunchOptions;
use kd_client::Client;
use kd_mcp::{Engine, ImageCache};

use super::{Request, Status, Target, Worker};

/// O backend visto pelas ferramentas MCP.
struct WorkerEngine<'a> {
    worker: &'a mut Worker,
    changed: bool,
}

impl Engine for WorkerEngine<'_> {
    fn client(&mut self) -> Result<&mut Client, String> {
        self.worker.client.as_mut().ok_or_else(|| "sem sessao com o alvo (use launch ou connect, ou abra pela janela)".to_string())
    }

    fn launch(&mut self, options: LaunchOptions, _timeout: Duration) -> Result<String, String> {
        self.worker.start(Target::Launch(options));
        self.worker.client.as_ref().map(|client| client.last_stop().to_string()).ok_or_else(|| self.worker.status_text())
    }

    fn connect(&mut self, address: &str, elf: Option<PathBuf>) -> Result<String, String> {
        if let Some(elf) = elf {
            self.worker.config.elf = elf;
        }
        self.worker.start(Target::Connect(address.to_string()));
        self.worker.client.as_ref().map(|client| client.last_stop().to_string()).ok_or_else(|| self.worker.status_text())
    }

    fn detach(&mut self) -> Result<String, String> {
        self.worker.disconnect("desligado pelo servidor MCP");
        Ok("sessao encerrada".into())
    }

    fn root(&self) -> PathBuf {
        self.worker.config.root.clone()
    }

    fn serial_log(&self) -> Option<PathBuf> {
        self.worker.config.serial_log.clone()
    }

    fn monitor_address(&self) -> Option<String> {
        self.worker.launch.as_ref().and_then(|launch| launch.monitor.clone())
    }

    fn build_dir(&self) -> Option<PathBuf> {
        match &self.worker.target {
            Some(Target::Launch(options)) => Some(options.build_path()),
            _ => self.worker.config.elf.parent().map(std::path::Path::to_path_buf),
        }
    }

    fn parts(&mut self) -> Result<(&mut Client, &mut ImageCache), String> {
        let client = self.worker.client.as_mut().ok_or_else(|| "sem sessao com o alvo".to_string())?;
        Ok((client, &mut self.worker.mcp_cache))
    }

    fn changed(&mut self) {
        self.changed = true;
    }
}

impl Worker {
    /// O estado em texto (o erro de um launch/connect pelo MCP).
    fn status_text(&self) -> String {
        match self.shared.lock().map(|shared| shared.status.clone()) {
            Ok(Status::Disconnected(reason)) => reason,
            Ok(other) => format!("{other:?}"),
            Err(_) => "estado indisponivel".into(),
        }
    }

    /// Uma mensagem do servidor hospedado.
    pub(super) fn mcp_message(&mut self, message: &str, reply: Sender<Option<String>>) {
        self.set_activity("ferramenta do servidor MCP");
        let mut server = std::mem::take(&mut self.mcp_server);
        let mut engine = WorkerEngine { worker: self, changed: false };
        let answer = server.handle_text(message, &mut engine);
        let changed = engine.changed;
        self.mcp_server = server;
        let _ = reply.send(answer);
        self.set_activity("");
        if !changed {
            return;
        }
        match self.client.as_ref().map(Client::is_stopped) {
            Some(true) => {
                self.view = super::View::Owner;
                self.selected_frame = 0;
                self.focus = super::Focus::Frame;
                self.refresh();
            }
            Some(false) => self.set_status(Status::Running),
            None => {}
        }
    }

    /// Liga o servidor em 127.0.0.1:`port` (ou desliga com `None`).
    pub(super) fn set_mcp(&mut self, port: Option<u16>) {
        if let Some(stop) = self.mcp_stop.take() {
            stop.store(true, Ordering::Release);
        }
        let Some(port) = port else {
            self.publish(|shared| shared.mcp = None);
            return;
        };
        let Some(requests) = self.requests.clone() else { return };
        let listener = match TcpListener::bind(("127.0.0.1", port)) {
            Ok(listener) => listener,
            Err(error) => {
                self.transcript("(servidor MCP)", Err(format!("127.0.0.1:{port}: {error}")));
                self.publish(|shared| shared.mcp = None);
                return;
            }
        };
        let address = listener.local_addr().map(|address| address.to_string()).unwrap_or_else(|_| format!("127.0.0.1:{port}"));
        let stop = Arc::new(AtomicBool::new(false));
        self.mcp_stop = Some(Arc::clone(&stop));
        std::thread::Builder::new()
            .name("opennt-re-mcp".into())
            .spawn(move || {
                let mut handler = |message: &str| -> Option<String> {
                    let (sender, receiver) = mpsc::channel();
                    requests.send(Request::Mcp { message: message.to_string(), reply: sender }).ok()?;
                    receiver.recv().ok().flatten()
                };
                kd_mcp::transport::serve_http(listener, stop, &mut handler);
            })
            .ok();
        self.transcript("(servidor MCP)", Ok(format!("ouvindo em http://{address}/mcp")));
        self.publish(|shared| shared.mcp = Some(address));
    }
}
