//! Execução no QEMU.
//!
//! `run` abre a janela do QEMU com a serial no terminal. `test-boot` roda
//! sem tela, espera um marcador na serial, opcionalmente digita comandos no
//! shell pelo monitor HMP (`sendkey`) e confere a saída esperada. Com o
//! depurador do kernel (`--kd`), a segunda porta serial (COM2) vira um
//! socket TCP em 127.0.0.1 (`kd_port`), onde o cliente (`cargo xtask
//! debug`) ou o GDB se conectam; uma sessão de roteiro roda em paralelo ao
//! `test-boot` e a falha dela derruba o teste. Com `--capture=ARQ.png`, o
//! QEMU ganha um socket QMP e, no fim do teste, a tela vai para o PNG.

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
    /// Porta TCP da COM2 (o depurador do kernel), se houver.
    pub kd_port: Option<u16>,
}

/// A COM2 como servidor TCP local, depois da COM1 (a ordem dos `-serial`
/// é a das portas).
fn kd_serial(machine: &MachineOptions) -> Vec<String> {
    match machine.kd_port {
        Some(port) => vec!["-serial".to_string(), format!("tcp:127.0.0.1:{port},server=on,wait=off")],
        None => Vec::new(),
    }
}

/// Sessão paralela ao teste (o roteiro do depurador): recebe a saída da
/// COM1 acumulada.
pub type Session = Box<dyn FnOnce(Arc<Mutex<String>>) -> Result<(), String> + Send>;

/// Espera a thread terminar, até o prazo.
fn wait_finished<T>(handle: &thread::JoinHandle<T>, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while !handle.is_finished() {
        if Instant::now() > deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(50));
    }
    true
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

/// Os discos da máquina: o de boot (`os.img`) e o volume NTFS de dados.
pub struct Disks {
    pub boot: PathBuf,
    pub data: Option<PathBuf>,
    /// O volume com `snapshot=on`: as escritas do convidado vão para um
    /// arquivo temporário do QEMU, e a imagem fica como o build a deixou
    /// (várias execuções dividem a mesma).
    pub data_snapshot: bool,
}

impl Disks {
    /// Os discos de uma pasta de build: o `ntfs.img` ao lado da imagem de
    /// boot, quando gerado, gravável.
    pub fn beside(image: &Path) -> Disks {
        let ntfs = image.with_file_name("ntfs.img");
        Disks { boot: image.to_path_buf(), data: ntfs.exists().then_some(ntfs), data_snapshot: false }
    }
}

fn machine_arguments(disks: &Disks, machine: &MachineOptions) -> Vec<String> {
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
        "-drive".to_string(),
        format!("format=raw,file={}", disks.boot.display()),
        "-no-reboot".to_string(),
    ]);
    // Volume NTFS de dados no mestre-escravo primário, quando gerado.
    if let Some(ntfs) = &disks.data {
        let snapshot = if disks.data_snapshot { ",snapshot=on" } else { "" };
        arguments.extend(["-drive".to_string(), format!("format=raw,if=ide,index=1,media=disk{snapshot},file={}", ntfs.display())]);
    }
    arguments
}

/// QEMU em segundo plano (com janela, ou sem tela com `window` falso), a
/// COM1 num arquivo (o terminal fica para o prompt do depurador) e a COM2
/// no socket do depurador.
pub fn spawn(disks: &Disks, machine: &MachineOptions, log: &Path, window: bool) -> Result<Child, String> {
    let qemu = find_qemu()?;
    let mut arguments = machine_arguments(disks, machine);
    if !window {
        arguments.extend(["-display".to_string(), "none".to_string()]);
    }
    arguments.extend(["-serial".to_string(), format!("file:{}", log.display())]);
    arguments.extend(kd_serial(machine));
    println!("QEMU com o log do kernel em {}", log.display());
    Command::new(&qemu).args(&arguments).stdin(Stdio::null()).spawn().map_err(|error| format!("{}: {error}", qemu.display()))
}

/// Shell interativo numa janela do QEMU; a serial fica neste terminal.
pub fn run(disks: &Disks, machine: &MachineOptions) -> Result<(), String> {
    let qemu = find_qemu()?;
    let mut arguments = machine_arguments(disks, machine);
    arguments.extend(["-serial".to_string(), "stdio".to_string()]);
    arguments.extend(kd_serial(machine));
    if let Some(port) = machine.kd_port {
        eprintln!("depurador do kernel: COM2 em 127.0.0.1:{port} (cargo xtask debug --connect=127.0.0.1:{port}, ou target remote no GDB)");
    }
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
    /// Depois da última saída esperada, o sistema segue rodando por este
    /// tempo sem nenhuma falha na serial (`--hold=MS`).
    pub hold: Duration,
    /// `--capture=ARQ.png`: no fim do teste (passando ou não), a tela do
    /// QEMU vai para este PNG, pelo `screendump` do QMP.
    pub capture: Option<PathBuf>,
}

/// Limite de tamanho de uma captura (a tela gráfica é reduzida até caber).
const CAPTURE_LIMIT: usize = 60 * 1024;

/// Uma linha de resposta do QMP que não é evento: `return` ou `error`.
fn qmp_reply(reader: &mut impl std::io::BufRead) -> Result<String, String> {
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).map_err(|error| format!("QMP: {error}"))? == 0 {
            return Err("QMP: conexao fechada".into());
        }
        if line.contains("\"return\"") {
            return Ok(line);
        }
        if line.contains("\"error\"") {
            return Err(format!("QMP: {}", line.trim()));
        }
    }
}

/// Grava a tela do QEMU em PPM pelo `screendump` do QMP (o QEMU desta
/// máquina não grava PNG: falta a libpng).
fn qmp_screendump(port: u16, path: &Path) -> Result<(), String> {
    let stream = TcpStream::connect(("127.0.0.1", port)).map_err(|error| format!("QMP: {error}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(30))).map_err(|error| error.to_string())?;
    let mut writer = stream.try_clone().map_err(|error| error.to_string())?;
    let mut reader = std::io::BufReader::new(stream);
    let mut greeting = String::new();
    std::io::BufRead::read_line(&mut reader, &mut greeting).map_err(|error| format!("QMP: {error}"))?;
    if !greeting.contains("\"QMP\"") {
        return Err(format!("QMP: saudacao inesperada: {}", greeting.trim()));
    }
    writer.write_all(b"{\"execute\":\"qmp_capabilities\"}\n").map_err(|error| format!("QMP: {error}"))?;
    qmp_reply(&mut reader)?;
    let file = path.display().to_string().replace('\\', "/").replace('"', "\\\"");
    writer
        .write_all(format!("{{\"execute\":\"screendump\",\"arguments\":{{\"filename\":\"{file}\"}}}}\n").as_bytes())
        .map_err(|error| format!("QMP: {error}"))?;
    qmp_reply(&mut reader).map(|_| ())
}

/// As linhas da serial que provam o teste: a de cada saída esperada (na
/// ordem em que o test-boot as procura) e as últimas, sem linhas vazias nem
/// os despejos em hexa das caixas pretas; `...` marca o que ficou de fora.
fn serial_proof(serial: &str, needles: &[&str]) -> String {
    const TAIL: usize = 6;
    const WIDTH: usize = 160;
    let lines: Vec<&str> = serial
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.trim().is_empty() && !line.starts_with("KERNEL_BLACKBOX_BYTES"))
        .collect();
    let mut chosen = Vec::new();
    let mut from = 0;
    for needle in needles {
        let found = lines[from..].iter().position(|line| line.contains(needle)).map(|offset| from + offset);
        if let Some(index) = found.or_else(|| lines.iter().position(|line| line.contains(needle))) {
            chosen.push(index);
            from = index;
        }
    }
    chosen.extend(lines.len().saturating_sub(TAIL)..lines.len());
    chosen.sort_unstable();
    chosen.dedup();
    let mut text = String::new();
    let mut previous: Option<usize> = None;
    for index in chosen {
        if previous.map_or(index > 0, |previous| previous + 1 != index) {
            text.push_str("...\n");
        }
        let line = lines[index];
        text.extend(line.chars().take(WIDTH));
        if line.chars().count() > WIDTH {
            text.push_str("...");
        }
        text.push('\n');
        previous = Some(index);
    }
    text
}

/// A captura do fim do teste: PPM do QEMU -> PNG pequeno, com a data, o
/// resultado e as linhas da serial que provam o teste nos textos do PNG (o
/// `cargo xtask status` os mostra).
fn capture_screen(port: u16, target: &Path, result: &Result<(), String>, serial: &str) -> Result<(), String> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    let ppm = target.with_extension("ppm");
    qmp_screendump(port, &ppm)?;
    let bytes = std::fs::read(&ppm).map_err(|error| format!("{}: {error}", ppm.display()))?;
    let _ = std::fs::remove_file(&ppm);
    let image = crate::png::read_ppm(&bytes)?;
    let outcome = match result {
        Ok(()) => "passou".to_string(),
        Err(error) => format!("falhou: {error}"),
    };
    let date = crate::png::today();
    let texts = [("opennt-data", date.as_str()), ("opennt-resultado", outcome.as_str()), ("opennt-serial", serial)];
    let png = crate::png::encode_capture(&image, &texts, CAPTURE_LIMIT);
    std::fs::write(target, &png).map_err(|error| format!("{}: {error}", target.display()))?;
    let info = crate::png::read_info(&png).ok_or("PNG gerado ilegivel")?;
    println!(
        "captura: {} ({}x{} de {}x{}, {} bytes)",
        target.display(),
        info.width,
        info.height,
        image.width,
        image.height,
        png.len()
    );
    Ok(())
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

pub fn free_port() -> Result<u16, String> {
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

/// Falhas na serial: pânico do Rust, exceção de kernel, autoteste e a parada
/// fatal do KeBugCheckEx (`*** STOP`, que sempre para a máquina).
pub const FAILURE_MARKERS: &[&str] = &["*** PANIC", "*** EXCECAO", "SELFTEST FALHOU", "*** STOP"];

/// Boot sem tela: sucesso quando o marcador (e as saídas esperadas depois
/// das teclas) aparecem na serial antes do prazo.
/// Com `session` (o roteiro do depurador), ela roda em paralelo ao teste.
pub fn test_boot(disks: &Disks, machine: &MachineOptions, test: &TestOptions, log: &Path, session: Option<Session>) -> Result<(), String> {
    let qemu = find_qemu()?;
    let port = free_port()?;
    let mut arguments = machine_arguments(disks, machine);
    arguments.extend([
        "-display".to_string(),
        "none".to_string(),
        "-serial".to_string(),
        "stdio".to_string(),
        "-monitor".to_string(),
        format!("tcp:127.0.0.1:{port},server=on,wait=off"),
    ]);
    // O QMP só entra com a captura: o `screendump` sai por ele.
    let qmp_port = match test.capture {
        Some(_) => {
            let qmp = free_port()?;
            arguments.extend(["-qmp".to_string(), format!("tcp:127.0.0.1:{qmp},server=on,wait=off")]);
            Some(qmp)
        }
        None => None,
    };
    arguments.extend(kd_serial(machine));
    let mut child = Command::new(&qemu)
        .args(&arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("{}: {error}", qemu.display()))?;
    let mut stdout = child.stdout.take().unwrap();
    let mut process = QemuProcess(child);

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
    // A sessão roda numa thread; o erro dela encerra as esperas.
    let session_failure: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let session_thread = session.map(|session| {
        let serial = Arc::clone(&output);
        let failure = Arc::clone(&session_failure);
        thread::spawn(move || {
            let result = session(serial);
            if let Err(error) = &result {
                *failure.lock().unwrap() = Some(error.clone());
            }
            result
        })
    });
    let wait_for = |needle: &str, from: usize| -> Result<usize, String> {
        loop {
            if let Some(error) = session_failure.lock().unwrap().clone() {
                return Err(format!("sessao do depurador: {error}"));
            }
            {
                let text = output.lock().unwrap();
                if let Some(failure) = FAILURE_MARKERS.iter().find(|marker| text[from.min(text.len())..].contains(*marker)) {
                    // O relatório que segue o marcador (registradores, pilha)
                    // ainda está chegando: um instante para ele entrar no log.
                    drop(text);
                    thread::sleep(Duration::from_millis(1500));
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
        // O prazo do teste não vale durante a espera: ela tem duração própria.
        let hold_end = Instant::now() + test.hold;
        while Instant::now() < hold_end {
            {
                let text = output.lock().unwrap();
                if let Some(failure) = FAILURE_MARKERS.iter().find(|marker| text[cursor.min(text.len())..].contains(*marker)) {
                    return Err(format!("falha detectada na serial durante os {} ms de espera: {failure}", test.hold.as_millis()));
                }
            }
            // Um triplo fault com -no-reboot encerra o QEMU sem marcador.
            if let Ok(Some(status)) = process.0.try_wait() {
                return Err(format!("QEMU terminou durante os {} ms de espera ({status})", test.hold.as_millis()));
            }
            thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    })();

    // A sessão termina antes do veredito (ela é parte do teste).
    let result = match (result, session_thread) {
        (Ok(()), Some(handle)) if !wait_finished(&handle, Duration::from_secs(30)) => Err("sessao do depurador nao terminou".to_string()),
        (Ok(()), Some(handle)) => match handle.join() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(format!("sessao do depurador: {error}")),
            Err(_) => Err("sessao do depurador: a thread entrou em panico".to_string()),
        },
        (result, _) => result,
    };
    // A captura sai com o QEMU ainda vivo, passe o teste ou não; se ela
    // falhar, o resultado do teste não muda.
    if let (Some(target), Some(qmp)) = (&test.capture, qmp_port) {
        let alive = matches!(process.0.try_wait(), Ok(None));
        let mut needles = vec![test.marker.as_str()];
        needles.extend(test.expect.iter().map(String::as_str));
        let serial = serial_proof(&output.lock().unwrap(), &needles);
        let captured = if alive { capture_screen(qmp, target, &result, &serial) } else { Err("o QEMU ja tinha terminado".into()) };
        if let Err(error) = captured {
            eprintln!("aviso: sem captura de tela ({}): {error}", target.display());
        }
    }
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
