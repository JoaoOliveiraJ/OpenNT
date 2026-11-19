//! `cargo xtask debug`: o cliente de texto do depurador do kernel do OpenNT.
//!
//! O kernel com `--kd=com2` atende o protocolo remoto do GDB na COM2, que o
//! QEMU expõe como um socket TCP (`-serial tcp:...`, a segunda porta serial;
//! a primeira continua sendo o log do kernel). Modos:
//!
//! - `cargo xtask debug [--launch] [opções de build e de máquina]`: compila
//!   com o depurador, abre o QEMU (log da COM1 em `<build>/serial.log`) e um
//!   prompt de comandos;
//! - `cargo xtask debug --launch --no-client [--headless]`: só o build e o
//!   QEMU, para outro cliente (o `opennt-dbg --launch` roda este comando):
//!   imprime `KD_READY 127.0.0.1:PORTA` quando o socket existe (antes,
//!   `KD_MONITOR 127.0.0.1:PORTA` com `--monitor-port`) e fecha o
//!   QEMU quando a entrada padrão fecha (o cliente saiu);
//! - `cargo xtask debug --connect=HOST:PORTA`: só o cliente, contra um QEMU
//!   já aberto (`cargo xtask run --kd=com2`, porta 1234 por padrão; o GDB
//!   também entra por ali: `target remote HOST:PORTA`);
//! - `cargo xtask test-boot [MARCADOR] [TIMEOUT_MS] --kd=com2 --script=ARQ`
//!   (ou `cargo xtask debug ... --script=ARQ`): o teste automático, QEMU sem
//!   tela e marcadores na COM1, com o roteiro rodando contra a COM2 em
//!   paralelo; o roteiro falhando derruba o teste. Com `--connect`, o
//!   roteiro roda contra um QEMU já aberto. A linguagem dos roteiros é a
//!   de `opennt_kd::kd_script`; a transcrição da sessão fica em
//!   `kd-sessao.log`, ao lado do `serial.log`.
//!
//! O protocolo, os símbolos (`<build>/kernel.elf` e os PEs desta máquina),
//! a pilha e os comandos são do crate `opennt-kd` (`tools/opennt-kd`), o
//! mesmo do depurador gráfico.

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use opennt_kd::kd_script::ScriptOptions;
use opennt_kd::rsp::Connection;
use opennt_kd::Client;

/// Abre a sessão: conecta e negocia.
fn open(address: &str, root: &Path, elf: &Path, deadline: Instant) -> Result<Client, String> {
    let connection = Connection::connect(address, deadline)?;
    Ok(Client::new(connection, root.to_path_buf(), elf.to_path_buf()))
}

/// Roteiro contra o socket da COM2 (o lado do teste); `serial` é a saída
/// da COM1, quando o QEMU é do próprio teste. `options` traz o nome do
/// roteiro (nas mensagens de erro) e a transcrição da sessão
/// (`kd-sessao.log`), gravada à medida que o roteiro imprime.
pub fn run_script(address: &str, root: &Path, elf: &Path, script: &str, serial: Option<Arc<Mutex<String>>>, options: &ScriptOptions) -> Result<(), String> {
    let mut client = open(address, root, elf, Instant::now() + Duration::from_secs(60))?;
    if let Some(serial) = serial {
        client.set_serial(serial);
    }
    client.run_script_with(script, options)
}

/// A transcrição da sessão de um roteiro: ao lado do `serial.log`.
pub fn transcript_path(log: &Path) -> PathBuf {
    log.with_file_name("kd-sessao.log")
}

/// A saída do DbgPrint que chegou, no terminal.
fn print_console(client: &mut Client) {
    let text = client.take_console();
    if !text.is_empty() {
        print!("{text}");
    }
}

/// Prompt interativo. `monitor` é o monitor do QEMU (os snapshots);
/// `replay`, a gravação reproduzida (o cliente fala com o gdbstub do QEMU,
/// com os módulos guardados ao lado dela).
pub fn interactive(address: &str, root: &Path, elf: &Path, monitor: Option<String>, replay: Option<PathBuf>) -> Result<(), String> {
    let mut client = open(address, root, elf, Instant::now() + Duration::from_secs(60))?;
    client.set_qemu_monitor(monitor);
    if let Some(recording) = &replay {
        let modules = std::fs::read_to_string(opennt_kd::monitoring::modules_file(recording)).map(|text| opennt_kd::monitoring::parse_modules(&text)).unwrap_or_default();
        client.set_replay(modules);
        println!("reproducao de {} (rstep e rcont andam para tras)", recording.display());
    }
    println!("depurador do kernel em {address}; anexando (a maquina para)...");
    match client.attach(Duration::from_secs(120)) {
        Ok(text) => println!("{text}"),
        Err(error) => println!("erro: {error}"),
    }
    print_console(&mut client);
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
                let result = client.execute(&line);
                print_console(&mut client);
                match result {
                    Ok(text) if !text.is_empty() => println!("{}", text.trim_end()),
                    Ok(_) => {}
                    Err(error) => println!("erro: {error}"),
                }
                prompt(&client);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let stop = client.poll(Duration::from_millis(10))?;
                // Os módulos de uma gravação ficam ao lado dela (a reprodução os usa).
                if stop.is_some() {
                    save_recording_modules(&client);
                }
                print_console(&mut client);
                if let Some(stop) = stop {
                    println!("\n{stop}");
                    prompt(&client);
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        }
    }
}

/// Numa gravação (`--record=ARQ`, pela variável que o `debug` põe), os
/// módulos de agora vão para `ARQ.modulos`.
fn save_recording_modules(client: &Client) {
    if let Some(recording) = std::env::var_os("OPENNT_KD_RECORDING") {
        let path = opennt_kd::monitoring::modules_file(Path::new(&recording));
        let _ = std::fs::write(path, opennt_kd::monitoring::modules_text(&client.module_list()));
    }
}

/// `--no-client`: o QEMU já aberto, para outro cliente. Anuncia o socket e
/// espera o QEMU terminar ou a entrada padrão fechar (quem rodou o comando
/// saiu ou pediu o reinício); nos dois casos o QEMU não fica para trás.
pub fn serve(mut qemu: Child, address: &str, monitor: Option<&str>) -> Result<(), String> {
    use std::io::Write;
    if let Some(monitor) = monitor {
        println!("KD_MONITOR {monitor}");
    }
    println!("KD_READY {address}");
    let _ = std::io::stdout().flush();
    let closed = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&closed);
    std::thread::spawn(move || {
        let mut sink = String::new();
        let stdin = std::io::stdin();
        let mut lock = stdin.lock();
        while matches!(lock.read_line(&mut sink), Ok(count) if count > 0) {
            sink.clear();
        }
        flag.store(true, Ordering::Release);
    });
    loop {
        if let Ok(Some(status)) = qemu.try_wait() {
            println!("KD_QEMU_EXITED {status}");
            return Ok(());
        }
        if closed.load(Ordering::Acquire) {
            stop_qemu(&mut qemu, monitor);
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Fecha o QEMU: primeiro o `quit` pelo monitor (uma gravação só fica
/// válida quando o QEMU sai sozinho e fecha o arquivo), depois à força.
pub fn stop_qemu(qemu: &mut Child, monitor: Option<&str>) {
    if let Some(monitor) = monitor {
        if opennt_kd::hmp::command(monitor, "quit", Duration::from_secs(5)).is_ok() {
            let deadline = Instant::now() + Duration::from_secs(60);
            while Instant::now() < deadline {
                if let Ok(Some(_)) = qemu.try_wait() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    let _ = qemu.kill();
    let _ = qemu.wait();
}

/// O `kernel.elf` do diretório de build.
pub fn kernel_elf(build_dir: &Path) -> PathBuf {
    build_dir.join("kernel.elf")
}
