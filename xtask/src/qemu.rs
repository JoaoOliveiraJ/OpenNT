//! Execução no QEMU — o papel de `tools/run-kbd.mjs` e `tools/test-boot.mjs`.
//!
//! `run` abre a janela do QEMU com a serial no terminal. `test-boot` roda
//! sem tela, espera um marcador na serial, opcionalmente digita comandos no
//! shell pelo monitor HMP (`sendkey`) e confere a saída esperada.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct MachineOptions {
    pub accelerator: String,
    pub memory_mb: u32,
    pub smp: u32,
}

/// Localiza o QEMU: variável `QEMU`, PATH, ou a instalação padrão.
pub fn find_qemu() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("QEMU") {
        return Ok(PathBuf::from(path));
    }
    let executable = if cfg!(windows) { "qemu-system-x86_64.exe" } else { "qemu-system-x86_64" };
    if let Some(paths) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&paths) {
            let candidate = directory.join(executable);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    let default = PathBuf::from("C:/Program Files/qemu/qemu-system-x86_64.exe");
    if default.exists() {
        return Ok(default);
    }
    Err("QEMU nao encontrado: defina a variavel QEMU com o caminho de qemu-system-x86_64".into())
}

fn machine_arguments(image: &Path, machine: &MachineOptions) -> Vec<String> {
    let mut arguments = vec![
        "-accel".to_string(),
        // No WHPX, um RDMSR/WRMSR de MSR não suportado precisa gerar #GP (como
        // o hardware real) em vez de ler 0: drivers que leem MSRs opcionais e
        // tratam a exceção dependem disso. Requer QEMU 11.1+.
        if machine.accelerator == "whpx" { "whpx,ignore-unknown-msr=off".to_string() } else { machine.accelerator.clone() },
        "-machine".to_string(),
        if machine.accelerator == "whpx" { "pc,kernel-irqchip=off" } else { "pc" }.to_string(),
    ];
    // TCG emula o modelo mais completo; em WHPX o modelo padrão (qemu64)
    // esconde RDRAND, que o boot exige, então a CPU do host é repassada.
    match machine.accelerator.as_str() {
        "tcg" => arguments.extend(["-cpu".to_string(), "max".to_string()]),
        "whpx" => arguments.extend(["-cpu".to_string(), "host".to_string()]),
        _ => {}
    }
    arguments.extend([
        "-m".to_string(),
        machine.memory_mb.to_string(),
        "-smp".to_string(),
        machine.smp.to_string(),
        // Placa std-VGA (Bochs DISPI, PCI 1234:1111) fixada: o framebuffer de
        // `--graphics` faz o mode-set por ela e lê a base linear do BAR0.
        "-vga".to_string(),
        "std".to_string(),
        "-drive".to_string(),
        format!("format=raw,file={}", image.display()),
        "-no-reboot".to_string(),
    ]);
    // Volume NTFS de dados no mestre-escravo primário, quando gerado.
    let ntfs = image.with_file_name("ntfs.img");
    if ntfs.exists() {
        arguments.extend(["-drive".to_string(), format!("format=raw,if=ide,index=1,media=disk,file={}", ntfs.display())]);
    }
    arguments
}

/// Shell interativo numa janela do QEMU; a serial fica neste terminal.
pub fn run(image: &Path, machine: &MachineOptions) -> Result<(), String> {
    let qemu = find_qemu()?;
    let mut arguments = machine_arguments(image, machine);
    arguments.extend(["-serial".to_string(), "stdio".to_string()]);
    let status = Command::new(&qemu)
        .args(&arguments)
        .status()
        .map_err(|error| format!("{}: {error}", qemu.display()))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("QEMU terminou com {status}"))
    }
}

#[derive(Clone, Debug)]
pub struct TestOptions {
    pub marker: String,
    pub timeout: Duration,
    pub keys: Option<String>,
    pub expect: Vec<String>,
}

/// Nome do `sendkey` do HMP para um caractere.
fn key_name(character: char) -> Option<String> {
    let plain = |name: &str| Some(name.to_string());
    let shifted = |name: &str| Some(format!("shift-{name}"));
    match character {
        'a'..='z' | '0'..='9' => plain(&character.to_string()),
        'A'..='Z' => shifted(&character.to_ascii_lowercase().to_string()),
        ' ' => plain("spc"),
        '\n' => plain("ret"),
        '\t' => plain("tab"),
        '\u{8}' => plain("backspace"),
        '-' => plain("minus"),
        '=' => plain("equal"),
        '/' => plain("slash"),
        '\\' => plain("backslash"),
        '.' => plain("dot"),
        ',' => plain("comma"),
        ';' => plain("semicolon"),
        '\'' => plain("apostrophe"),
        '[' => plain("bracket_left"),
        ']' => plain("bracket_right"),
        '`' => plain("grave_accent"),
        '!' => shifted("1"),
        '@' => shifted("2"),
        '#' => shifted("3"),
        '$' => shifted("4"),
        '%' => shifted("5"),
        '^' => shifted("6"),
        '&' => shifted("7"),
        '*' => shifted("8"),
        '(' => shifted("9"),
        ')' => shifted("0"),
        '_' => shifted("minus"),
        '+' => shifted("equal"),
        ':' => shifted("semicolon"),
        '"' => shifted("apostrophe"),
        '<' => shifted("comma"),
        '>' => shifted("dot"),
        '?' => shifted("slash"),
        '{' => shifted("bracket_left"),
        '}' => shifted("bracket_right"),
        '|' => shifted("backslash"),
        '~' => shifted("grave_accent"),
        _ => None,
    }
}

fn free_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    Ok(listener.local_addr().map_err(|error| error.to_string())?.port())
}

fn connect_monitor(port: u16, deadline: Instant) -> Result<TcpStream, String> {
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => {
                // Descarta as respostas do monitor em segundo plano.
                let mut reader = stream.try_clone().map_err(|error| error.to_string())?;
                thread::spawn(move || {
                    let mut buffer = [0u8; 1024];
                    while matches!(reader.read(&mut buffer), Ok(count) if count > 0) {}
                });
                return Ok(stream);
            }
            Err(error) if Instant::now() > deadline => return Err(format!("monitor HMP: {error}")),
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn type_keys(monitor: &mut TcpStream, text: &str) -> Result<(), String> {
    for character in text.chars() {
        let name = key_name(character).ok_or_else(|| format!("tecla sem mapa no sendkey: {character:?}"))?;
        monitor
            .write_all(format!("sendkey {name} 30\n").as_bytes())
            .map_err(|error| format!("monitor HMP: {error}"))?;
        thread::sleep(Duration::from_millis(70));
    }
    Ok(())
}

struct QemuProcess(Child);

impl Drop for QemuProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

const FAILURE_MARKERS: &[&str] = &["*** PANIC", "*** EXCECAO", "SELFTEST FALHOU"];

/// Boot sem tela: sucesso quando o marcador (e as saídas esperadas depois
/// das teclas) aparecem na serial antes do prazo.
pub fn test_boot(image: &Path, machine: &MachineOptions, test: &TestOptions, log: &Path) -> Result<(), String> {
    let qemu = find_qemu()?;
    let port = free_port()?;
    let mut arguments = machine_arguments(image, machine);
    arguments.extend([
        "-display".to_string(),
        "none".to_string(),
        "-serial".to_string(),
        "stdio".to_string(),
        "-monitor".to_string(),
        format!("tcp:127.0.0.1:{port},server=on,wait=off"),
    ]);
    let mut child = Command::new(&qemu)
        .args(&arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("{}: {error}", qemu.display()))?;
    let mut stdout = child.stdout.take().unwrap();
    let process = QemuProcess(child);

    let output = Arc::new(Mutex::new(String::new()));
    let sink = Arc::clone(&output);
    thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        while let Ok(count) = stdout.read(&mut buffer) {
            if count == 0 {
                break;
            }
            let text = String::from_utf8_lossy(&buffer[..count]).replace('\r', "");
            print!("{text}");
            let _ = std::io::stdout().flush();
            sink.lock().unwrap().push_str(&text);
        }
    });

    let deadline = Instant::now() + test.timeout;
    let wait_for = |needle: &str, from: usize| -> Result<usize, String> {
        loop {
            {
                let text = output.lock().unwrap();
                if let Some(failure) = FAILURE_MARKERS.iter().find(|marker| text[from.min(text.len())..].contains(*marker)) {
                    return Err(format!("falha detectada na serial: {failure}"));
                }
                if let Some(position) = text[from.min(text.len())..].find(needle) {
                    return Ok(from + position + needle.len());
                }
            }
            if Instant::now() > deadline {
                return Err(format!("tempo esgotado esperando {needle:?}"));
            }
            thread::sleep(Duration::from_millis(50));
        }
    };

    let result = (|| -> Result<(), String> {
        let mut cursor = wait_for(&test.marker, 0)?;
        if let Some(keys) = &test.keys {
            cursor = wait_for("[shell] pronto", 0)?;
            let mut monitor = connect_monitor(port, deadline)?;
            type_keys(&mut monitor, keys)?;
        }
        for expected in &test.expect {
            cursor = wait_for(expected, cursor)?;
        }
        Ok(())
    })();

    drop(process);
    let text = output.lock().unwrap().clone();
    std::fs::write(log, &text).map_err(|error| format!("{}: {error}", log.display()))?;
    println!();
    match result {
        Ok(()) => {
            println!("TEST-BOOT OK: {:?} encontrado (serial em {})", test.marker, log.display());
            Ok(())
        }
        Err(error) => Err(format!("TEST-BOOT FALHOU: {error} (serial em {})", log.display())),
    }
}
