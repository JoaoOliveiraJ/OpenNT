//! `cargo xtask debug`: o cliente do depurador do kernel do OpenNT.
//!
//! O kernel com `--kd=com2` atende o protocolo remoto do GDB na COM2, que o
//! QEMU expõe como um socket TCP (`-serial tcp:...`, a segunda porta serial;
//! a primeira continua sendo o log do kernel). Modos:
//!
//! - `cargo xtask debug [opções de build e de máquina]`: compila com o
//!   depurador, abre o QEMU (log da COM1 em `<build>/serial.log`) e um
//!   prompt de comandos;
//! - `cargo xtask debug --connect=HOST:PORTA`: só o cliente, contra um QEMU
//!   já aberto (`cargo xtask run --kd=com2`, porta 1234 por padrão; o GDB
//!   também entra por ali: `target remote HOST:PORTA`);
//! - `cargo xtask test-boot [MARCADOR] [TIMEOUT_MS] --kd=com2 --script=ARQ`
//!   (ou `cargo xtask debug ... --script=ARQ`): o teste automático, QEMU sem
//!   tela e marcadores na COM1, com o roteiro rodando contra a COM2 em
//!   paralelo; o roteiro falhando derruba o teste. Com `--connect`, o
//!   roteiro roda contra um QEMU já aberto.
//!
//! Os símbolos vêm do `<build>/kernel.elf` e dos PEs desta máquina
//! (`symbols`); os comandos estão em `client`.

pub mod client;
pub mod demangle;
pub mod rsp;
pub mod symbols;

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use client::Client;
use rsp::Connection;

/// Abre a sessão: conecta e negocia.
fn open(address: &str, root: &Path, elf: &Path, echo: bool, deadline: Instant) -> Result<Client, String> {
    let connection = Connection::connect(address, deadline)?;
    Ok(Client::new(connection, root.to_path_buf(), elf.to_path_buf(), echo))
}

/// Roteiro contra o socket da COM2 (o lado do teste); `serial` é a saída
/// da COM1, quando o QEMU é do próprio teste.
pub fn run_script(address: &str, root: &Path, elf: &Path, script: &str, serial: Option<Arc<Mutex<String>>>) -> Result<(), String> {
    let mut client = open(address, root, elf, false, Instant::now() + Duration::from_secs(60))?;
    if let Some(serial) = serial {
        client.set_serial(serial);
    }
    client.run_script(script)
}

/// Prompt interativo.
pub fn interactive(address: &str, root: &Path, elf: &Path) -> Result<(), String> {
    let mut client = open(address, root, elf, true, Instant::now() + Duration::from_secs(60))?;
    println!("depurador do kernel em {address}; anexando (a maquina para)...");
    match client.attach(Duration::from_secs(120)) {
        Ok(text) => println!("{text}"),
        Err(error) => println!("erro: {error}"),
    }
    let (sender, receiver) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let prompt = |client: &Client| {
        use std::io::Write;
        print!("{}", if client.is_stopped() { "kd> " } else { "kd (rodando)> " });
        let _ = std::io::stdout().flush();
    };
    prompt(&client);
    loop {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                let line = line.trim().to_string();
                if line == "quit" || line == "q" {
                    // Sair desliga a sessão (parando antes, se preciso): a
                    // máquina segue sem host anexado.
                    if let Err(error) = client.execute("detach") {
                        println!("erro: {error}");
                    }
                    return Ok(());
                }
                match client.execute(&line) {
                    Ok(text) if !text.is_empty() => println!("{}", text.trim_end()),
                    Ok(_) => {}
                    Err(error) => println!("erro: {error}"),
                }
                prompt(&client);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if let Some(stop) = client.poll_console(Duration::from_millis(10))? {
                    println!("\n{stop}");
                    prompt(&client);
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        }
    }
}

/// O `kernel.elf` do diretório de build.
pub fn kernel_elf(build_dir: &Path) -> PathBuf {
    build_dir.join("kernel.elf")
}
