//! `--launch`: o build e o QEMU pelo próprio `xtask`, o mesmo comando do
//! `cargo xtask debug --launch`, sem o prompt de texto (`--no-client`). O
//! `xtask` imprime `KD_READY 127.0.0.1:PORTA` quando o socket da COM2
//! existe e fecha o QEMU quando a entrada padrão dele fecha: parar (ou
//! reiniciar) é fechar essa entrada, e o QEMU não fica para trás nem se o
//! depurador cair.

use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct LaunchOptions {
    /// A raiz do repositório (onde o `cargo xtask` roda).
    pub root: PathBuf,
    /// `--build-dir` do `xtask` (relativo à raiz ou absoluto).
    pub build_dir: PathBuf,
    /// O QEMU sem janela (os testes e a captura de tela).
    pub headless: bool,
    /// Opções repassadas ao `xtask` (`--accel=whpx`, `--smp=2`,
    /// `--start-driver=...`).
    pub extra: Vec<String>,
}

impl LaunchOptions {
    /// O diretório de build absoluto.
    pub fn build_path(&self) -> PathBuf {
        if self.build_dir.is_absolute() {
            self.build_dir.clone()
        } else {
            self.root.join(&self.build_dir)
        }
    }

    /// Os argumentos do `cargo` (depois do executável).
    pub fn arguments(&self, port: u16, monitor: u16) -> Vec<String> {
        let mut arguments = vec!["xtask".to_string(), "debug".into(), "--launch".into(), "--no-client".into(), format!("--kd-port={port}"), format!("--monitor-port={monitor}"), format!("--build-dir={}", self.build_dir.display())];
        if self.headless {
            arguments.push("--headless".into());
        }
        arguments.extend(self.extra.iter().cloned());
        arguments
    }
}

/// Uma porta TCP livre agora (o QEMU abre o servidor nela).
pub fn free_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    listener.local_addr().map(|address| address.port()).map_err(|error| error.to_string())
}

/// O `xtask` rodando (build e depois o QEMU).
pub struct Launch {
    child: Child,
    stdin: Option<ChildStdin>,
    pub address: String,
    /// O monitor HMP do QEMU (o rastro rápido).
    pub monitor: Option<String>,
    /// Linhas do `xtask` (build e QEMU) que chegam depois do `KD_READY`.
    pub output: mpsc::Receiver<String>,
}

impl Launch {
    /// Roda o comando e espera o `KD_READY`; `progress` recebe cada linha
    /// do build. Erro se o processo terminar antes (o build falhou).
    pub fn start(options: &LaunchOptions, mut progress: impl FnMut(&str)) -> Result<Launch, String> {
        let port = free_port()?;
        let monitor = free_port()?;
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        let arguments = options.arguments(port, monitor);
        progress(&format!("{cargo} {}", arguments.join(" ")));
        let mut child = Command::new(&cargo)
            .args(&arguments)
            .current_dir(&options.root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("{cargo}: {error}"))?;
        let stdin = child.stdin.take();
        let (sender, receiver) = mpsc::channel::<String>();
        for stream in [child.stdout.take().map(|stream| Box::new(stream) as Box<dyn Read + Send>), child.stderr.take().map(|stream| Box::new(stream) as Box<dyn Read + Send>)].into_iter().flatten() {
            let sender = sender.clone();
            thread::spawn(move || {
                for line in BufReader::new(stream).lines() {
                    let Ok(line) = line else { break };
                    if sender.send(line).is_err() {
                        break;
                    }
                }
            });
        }
        drop(sender);
        let mut launch = Launch { child, stdin, address: String::new(), monitor: None, output: receiver };
        let mut tail: Vec<String> = Vec::new();
        loop {
            match launch.output.recv_timeout(Duration::from_millis(200)) {
                Ok(line) => {
                    progress(&line);
                    if let Some(address) = line.strip_prefix("KD_MONITOR ") {
                        launch.monitor = Some(address.trim().to_string());
                    }
                    if let Some(address) = line.strip_prefix("KD_READY ") {
                        launch.address = address.trim().to_string();
                        return Ok(launch);
                    }
                    tail.push(line);
                    if tail.len() > 20 {
                        tail.remove(0);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let status = launch.child.wait().map(|status| status.to_string()).unwrap_or_default();
                    return Err(format!("o xtask terminou antes do QEMU ({status}):\n{}", tail.join("\n")));
                }
            }
        }
    }

    /// Fecha o QEMU (pela entrada do `xtask`) e espera o processo.
    pub fn stop(&mut self) {
        self.stdin.take();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// O `xtask` ainda roda (o QEMU não terminou).
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for Launch {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xtask_arguments() {
        let options = LaunchOptions { root: PathBuf::from("."), build_dir: PathBuf::from("build/kd-gui"), headless: true, extra: vec!["--accel=whpx".into()] };
        assert_eq!(options.arguments(4321, 4322), vec!["xtask", "debug", "--launch", "--no-client", "--kd-port=4321", "--monitor-port=4322", "--build-dir=build/kd-gui", "--headless", "--accel=whpx"]);
        assert_eq!(options.build_path(), PathBuf::from("./build/kd-gui"));
    }
}
