//! `--launch`: o build e o QEMU pelo próprio `xtask`, o mesmo comando do
//! `cargo xtask debug --launch`, sem o prompt de texto (`--no-client`). O
//! `xtask` imprime `KD_READY 127.0.0.1:PORTA` quando o socket da COM2
//! existe e fecha o QEMU quando a entrada padrão dele fecha: parar (ou
//! reiniciar) é fechar essa entrada, e o QEMU não fica para trás nem se o
//! depurador cair.
//!
//! Também o que a janela de abertura usa: as opções do `xtask` digitadas
//! (`--initial-process=smss --display=basic`) e o endereço de um QEMU já
//! aberto (`HOST:PORTA`, só a porta ou a linha `KD_READY` colada).

use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// A mensagem de quando o usuário cancela a abertura.
pub const CANCELLED: &str = "abertura cancelada";

/// As opções que o próprio depurador passa ao `xtask` (ou que trocariam o
/// modo do `cargo xtask debug`): ficam fora do campo de opções.
const RESERVED: [&str; 8] = ["--launch", "--no-client", "--kd-port", "--monitor-port", "--build-dir", "--headless", "--connect", "--script"];

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

    /// O comando equivalente num terminal (a dica da janela de abertura).
    pub fn command_line(&self) -> String {
        let mut words = vec!["cargo xtask debug --launch --no-client".to_string(), format!("--build-dir={}", self.build_dir.display())];
        if self.headless {
            words.push("--headless".into());
        }
        words.extend(self.extra.iter().cloned());
        words.join(" ")
    }
}

/// As opções do `xtask` digitadas na janela (`--initial-process=smss
/// --display=basic --accel=whpx`): cada palavra começa com `--`, e as que
/// o depurador já passa ficam de fora.
pub fn parse_xtask_options(text: &str) -> Result<Vec<String>, String> {
    let mut options = Vec::new();
    for word in text.split_whitespace() {
        if !word.starts_with("--") || word.len() < 3 {
            return Err(format!("{word}: as opcoes do xtask comecam com -- (--initial-process=smss, --display=basic)"));
        }
        let name = word.split_once('=').map_or(word, |(name, _)| name);
        if RESERVED.contains(&name) {
            return Err(format!("{name}: o depurador ja passa esta opcao (o diretorio de build e o QEMU sem janela tem campos proprios)"));
        }
        if !options.iter().any(|known: &String| known == word) {
            options.push(word.to_string());
        }
    }
    Ok(options)
}

/// Põe ou tira uma opção do texto das opções (os botões de opção comum da
/// janela). Uma opção `--nome=valor` troca outra `--nome=...` que já esteja
/// lá.
pub fn toggle_option(text: &str, option: &str) -> String {
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.contains(&option) {
        return words.into_iter().filter(|word| *word != option).collect::<Vec<_>>().join(" ");
    }
    let name = option.split_once('=').map(|(name, _)| name);
    let mut kept: Vec<&str> = words.into_iter().filter(|word| name.is_none_or(|name| word.split_once('=').map(|(other, _)| other) != Some(name))).collect();
    kept.push(option);
    kept.join(" ")
}

/// O texto tem a opção (os botões de opção comum mostram o estado).
pub fn has_option(text: &str, option: &str) -> bool {
    text.split_whitespace().any(|word| word == option)
}

/// O endereço do depurador digitado ou colado: `HOST:PORTA`, só a porta
/// (em 127.0.0.1) ou a linha `KD_READY 127.0.0.1:PORTA` que o `cargo xtask
/// debug --launch --no-client` imprime.
pub fn parse_connect_address(text: &str) -> Result<String, String> {
    const USAGE: &str = "HOST:PORTA, a porta ou a linha KD_READY do xtask";
    let text = text.trim();
    let text = match text.find("KD_READY") {
        Some(index) => text[index + "KD_READY".len()..].trim(),
        None => text,
    };
    let word = text.split_whitespace().next().unwrap_or("");
    if word.is_empty() {
        return Err(format!("endereco vazio ({USAGE})"));
    }
    if let Ok(port) = word.parse::<u16>() {
        return if port == 0 { Err(format!("porta 0 ({USAGE})")) } else { Ok(format!("127.0.0.1:{port}")) };
    }
    match word.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok_and(|port| port != 0) => Ok(word.to_string()),
        _ => Err(format!("{word}: endereco invalido ({USAGE})")),
    }
}

/// A linha que explica a falha do `xtask`: o primeiro erro do build (ou do
/// próprio `xtask`), senão a última linha.
pub fn failure_headline(lines: &[String]) -> String {
    let error = lines.iter().find(|line| {
        let lower = line.trim_start().to_ascii_lowercase();
        lower.starts_with("error") || lower.starts_with("erro") || lower.contains("error:") || lower.contains("erro:")
    });
    error.or(lines.iter().rev().find(|line| !line.trim().is_empty())).map(|line| line.trim().to_string()).unwrap_or_default()
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
    /// do build. Erro se o processo terminar antes (o build falhou) ou se
    /// `cancel` ligar (o botão Cancelar da janela): o `cargo` morre e leva
    /// junto o `xtask`, o `rustc` e o QEMU (o objeto de job do `cargo` no
    /// Windows).
    pub fn start(options: &LaunchOptions, cancel: &AtomicBool, mut progress: impl FnMut(&str)) -> Result<Launch, String> {
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
            if cancel.load(Ordering::SeqCst) {
                launch.stdin.take();
                let _ = launch.child.kill();
                let _ = launch.child.wait();
                return Err(CANCELLED.into());
            }
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
                    if tail.len() > 40 {
                        tail.remove(0);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let status = launch.child.wait().map(|status| status.to_string()).unwrap_or_default();
                    return Err(format!("o xtask terminou antes do QEMU ({status}): {}\n{}", failure_headline(&tail), tail.join("\n")));
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

    /// Como o `xtask` terminou (`None` enquanto roda).
    pub fn exit_status(&mut self) -> Option<String> {
        self.child.try_wait().ok().flatten().map(|status| status.to_string())
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
        let options = LaunchOptions { root: PathBuf::from("."), build_dir: PathBuf::from("build/opennt-dbg"), headless: true, extra: vec!["--accel=whpx".into()] };
        assert_eq!(options.arguments(4321, 4322), vec!["xtask", "debug", "--launch", "--no-client", "--kd-port=4321", "--monitor-port=4322", "--build-dir=build/opennt-dbg", "--headless", "--accel=whpx"]);
        assert_eq!(options.build_path(), PathBuf::from("./build/opennt-dbg"));
        assert_eq!(options.command_line(), "cargo xtask debug --launch --no-client --build-dir=build/opennt-dbg --headless --accel=whpx");
    }

    #[test]
    fn xtask_options_from_text() {
        assert_eq!(parse_xtask_options("  --initial-process=smss   --display=basic "), Ok(vec!["--initial-process=smss".to_string(), "--display=basic".to_string()]));
        assert_eq!(parse_xtask_options(""), Ok(Vec::new()));
        assert_eq!(parse_xtask_options("--smp=2 --smp=2"), Ok(vec!["--smp=2".to_string()]));
        assert!(parse_xtask_options("smss").is_err());
        assert!(parse_xtask_options("--").is_err());
        assert!(parse_xtask_options("--kd-port=1234").is_err());
        assert!(parse_xtask_options("--build-dir=build/x").is_err());
        assert!(parse_xtask_options("--script=a.kd").is_err());
    }

    #[test]
    fn toggles_common_options() {
        assert_eq!(toggle_option("", "--display=basic"), "--display=basic");
        assert_eq!(toggle_option("--initial-process=smss --display=basic", "--display=basic"), "--initial-process=smss");
        assert_eq!(toggle_option("--accel=tcg --smp=2", "--accel=whpx"), "--smp=2 --accel=whpx");
        assert_eq!(toggle_option("--usb", "--net"), "--usb --net");
        assert!(has_option("--usb --net", "--net"));
        assert!(!has_option("--usb --network", "--net"));
    }

    #[test]
    fn connect_addresses() {
        assert_eq!(parse_connect_address("127.0.0.1:1234"), Ok("127.0.0.1:1234".to_string()));
        assert_eq!(parse_connect_address(" 50123 "), Ok("127.0.0.1:50123".to_string()));
        assert_eq!(parse_connect_address("KD_READY 127.0.0.1:61000"), Ok("127.0.0.1:61000".to_string()));
        assert_eq!(parse_connect_address("[xtask] KD_READY 127.0.0.1:61000\r"), Ok("127.0.0.1:61000".to_string()));
        assert_eq!(parse_connect_address("localhost:9"), Ok("localhost:9".to_string()));
        assert!(parse_connect_address("").is_err());
        assert!(parse_connect_address("0").is_err());
        assert!(parse_connect_address("127.0.0.1").is_err());
        assert!(parse_connect_address(":1234").is_err());
        assert!(parse_connect_address("127.0.0.1:99999").is_err());
    }

    #[test]
    fn failure_headlines() {
        let lines: Vec<String> = ["   Compiling kernel v0.1.0", "error[E0308]: mismatched types", "  --> kernel/src/lib.rs:1:1", "error: could not compile `kernel`"].iter().map(|line| line.to_string()).collect();
        assert_eq!(failure_headline(&lines), "error[E0308]: mismatched types");
        let lines: Vec<String> = ["qemu: nao achei o QEMU", ""].iter().map(|line| line.to_string()).collect();
        assert_eq!(failure_headline(&lines), "qemu: nao achei o QEMU");
        assert_eq!(failure_headline(&[]), "");
    }
}
