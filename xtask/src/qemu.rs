//! Execução no QEMU.
//!
//! `run` abre a janela do QEMU com a serial no terminal. `test-boot` roda
//! sem tela, espera um marcador na serial, opcionalmente digita comandos no
//! shell pelo monitor HMP (`sendkey`) e confere a saída esperada. Com o
//! depurador do kernel (`--kd`), a segunda porta serial (COM2) vira um
//! socket TCP em 127.0.0.1 (`kd_port`), onde o cliente (`cargo xtask
//! debug`) ou o GDB se conectam; uma sessão de roteiro roda em paralelo ao
//! `test-boot` e a falha dela derruba o teste. Com `--capture=ARQ.png`, o
//! QEMU ganha um socket QMP e, no fim do teste, a tela vai para o PNG. Os
//! testes do desligamento (`--expect-poweroff`, `--power-cycles=N`,
//! `--allow-reboot`) recebem os eventos SHUTDOWN por um segundo QMP; o
//! reinício do convidado fica no mesmo QEMU (e no mesmo snapshot do volume)
//! e o religamento depois do desligamento ACPI sobe outro QEMU sobre uma
//! cópia gravável do volume NTFS.

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
    /// `--usb`: a controladora xHCI do QEMU (qemu-xhci, PCI 1B36:000D) com um
    /// teclado e um tablet USB nas portas dela.
    pub usb: bool,
    /// Porta TCP do monitor HMP (o rastro rápido do depurador gráfico liga
    /// o log de execução do QEMU por ele), se houver.
    pub monitor_port: Option<u16>,
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

/// A pasta temporária de cada QEMU, dentro da pasta de build. Um disco com
/// `snapshot=on` grava as escritas do convidado num arquivo `vl.XXXXXX` na
/// pasta temporária do processo, e o QEMU só o apaga quando sai sozinho; o
/// QEMU morto no fim de um teste o deixaria na pasta temporária do usuário.
/// Com TMP/TEMP/TMPDIR apontando para esta pasta, o arquivo fica junto da
/// execução e sai com ela.
pub const QEMU_TEMP_DIR: &str = "qemu-tmp";

/// Variáveis de ambiente da pasta temporária: o GLib do QEMU lê a TEMP no
/// Windows e a TMPDIR fora dele; a TMP é a do GetTempPath.
const TEMP_VARIABLES: [&str; 3] = ["TMP", "TEMP", "TMPDIR"];

/// Apaga uma pasta temporária de QEMU. O Windows só libera os arquivos
/// abertos um instante depois do fim do processo, então a remoção tenta de
/// novo por até um segundo.
pub fn remove_temp_dir(directory: &Path) {
    for attempt in 0..10 {
        if !directory.exists() || std::fs::remove_dir_all(directory).is_ok() {
            return;
        }
        if attempt < 9 {
            thread::sleep(Duration::from_millis(100));
        }
    }
    eprintln!("aviso: {} ficou para tras", directory.display());
}

/// A pasta temporária de um QEMU, vazia ao criar e apagada no `drop`. Quem
/// a guarda precisa soltá-la depois do processo do QEMU (a ordem inversa da
/// declaração faz isso numa função).
pub struct QemuTemp(PathBuf);

impl QemuTemp {
    /// A pasta [`QEMU_TEMP_DIR`] ao lado de `beside` (o log da serial).
    pub fn beside(beside: &Path) -> Result<QemuTemp, String> {
        let directory = temp_dir_beside(beside);
        remove_temp_dir(&directory);
        std::fs::create_dir_all(&directory).map_err(|error| format!("{}: {error}", directory.display()))?;
        Ok(QemuTemp(directory))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Deixa a pasta no disco (o QEMU segue rodando depois da função que a
    /// criou); [`temp_dir_beside`] dá o caminho para apagá-la depois.
    fn keep(self) {
        std::mem::forget(self);
    }
}

/// A pasta temporária do QEMU cujo log da serial é `log`.
pub fn temp_dir_beside(log: &Path) -> PathBuf {
    log.with_file_name(QEMU_TEMP_DIR)
}

impl Drop for QemuTemp {
    fn drop(&mut self) {
        remove_temp_dir(&self.0);
    }
}

/// O comando do QEMU com a pasta temporária dada.
fn qemu_command(qemu: &Path, temp: &Path) -> Command {
    let mut command = Command::new(qemu);
    for variable in TEMP_VARIABLES {
        command.env(variable, temp);
    }
    command
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

/// Os aceleradores que o `--accel` aceita; `auto` é o padrão do test-boot.
pub const ACCELERATORS: &[&str] = &["auto", "tcg", "whpx"];

/// O dispositivo inexistente da sondagem do WHPX.
const PROBE_DEVICE: &str = "opennt-sonda";

/// O acelerador de `--accel=auto`: o WHPX quando o QEMU o lista no
/// `-accel help` e a partição dele sobe nesta máquina, senão o TCG. A
/// sondagem sobe o QEMU com o WHPX e um dispositivo que não existe: o QEMU
/// cria a partição antes dos dispositivos, então o erro do dispositivo
/// prova que o WHPX iniciou (uns 100 ms), e qualquer outro erro é o do
/// acelerador (sem o recurso Windows Hypervisor Platform, por exemplo).
pub fn detect_accelerator() -> Result<&'static str, String> {
    let qemu = find_qemu()?;
    let help = Command::new(&qemu).args(["-accel", "help"]).output().map_err(|error| format!("{}: {error}", qemu.display()))?;
    if !String::from_utf8_lossy(&help.stdout).lines().any(|line| line.trim() == "whpx") {
        return Ok("tcg");
    }
    let probe = Command::new(&qemu)
        .args(["-accel", "whpx", "-machine", "pc", "-cpu", "host", "-m", "64", "-display", "none", "-nodefaults", "-device", PROBE_DEVICE])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("{}: {error}", qemu.display()))?;
    let errors = String::from_utf8_lossy(&probe.stderr);
    Ok(if errors.contains(PROBE_DEVICE) { "whpx" } else { "tcg" })
}

/// Resolve o `auto` de `--accel`; `tcg` e `whpx` ficam como estão.
pub fn resolve_accelerator(requested: &str) -> Result<String, String> {
    match requested {
        "auto" => detect_accelerator().map(String::from),
        other => Ok(other.to_string()),
    }
}

/// Os discos da máquina: o de boot (`os.img`), o volume NTFS de dados e o
/// disco do controlador NVMe (`--storage=nvme`).
pub struct Disks {
    pub boot: PathBuf,
    pub data: Option<PathBuf>,
    /// O volume com `snapshot=on`: as escritas do convidado vão para um
    /// arquivo temporário do QEMU, e a imagem fica como o build a deixou
    /// (várias execuções dividem a mesma).
    pub data_snapshot: bool,
    pub nvme: Option<PathBuf>,
    /// O disco NVMe com `snapshot=on`, pelo mesmo motivo; a cópia gravável
    /// do volume num religamento não muda o disco NVMe.
    pub nvme_snapshot: bool,
}

impl Disks {
    /// Os discos de uma pasta de build: o `ntfs.img` ao lado da imagem de
    /// boot, quando gerado, gravável; o `nvme.img` com `--storage=nvme`.
    pub fn beside(image: &Path, storage: &str) -> Disks {
        let ntfs = image.with_file_name("ntfs.img");
        Disks { boot: image.to_path_buf(), data: ntfs.exists().then_some(ntfs), data_snapshot: false, nvme: nvme_disk(image, storage), nvme_snapshot: false }
    }
}

/// O `nvme.img` ao lado da imagem de boot, para uma máquina com
/// `--storage=nvme`.
pub fn nvme_disk(image: &Path, storage: &str) -> Option<PathBuf> {
    let nvme = image.with_file_name(crate::build::NVME_IMAGE);
    (storage == "nvme" && nvme.exists()).then_some(nvme)
}

/// Milissegundos Unix do relógio do hospedeiro.
fn host_unix_milliseconds() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |duration| duration.as_millis() as u64)
}

/// `AAAA-MM-DDTHH:MM:SS` da hora local de um fuso com viés `bias_minutes`
/// (UTC − local), para o `-rtc base=` do QEMU.
fn local_rtc_base(bias_minutes: i32) -> String {
    let seconds = (host_unix_milliseconds() / 1000) as i64 - bias_minutes as i64 * 60;
    let (days, of_day) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    // Calendário civil a partir dos dias desde 1970 (algoritmo de Hinnant).
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 { month_prime + 3 } else { month_prime - 9 };
    let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}", of_day / 3600, of_day % 3600 / 60, of_day % 60)
}

/// A linha `UTC=<ms Unix>` que o kernel imprime quando o fuso entra em
/// vigor: a distância, em ms, entre a hora do convidado e a do hospedeiro.
fn guest_clock_offset(line: &str) -> Option<i64> {
    let digits: String = line.split("UTC=").nth(1)?.chars().take_while(char::is_ascii_digit).collect();
    let guest = digits.parse::<u64>().ok()?;
    Some(guest as i64 - host_unix_milliseconds() as i64)
}

/// Maior distância aceita entre a hora do convidado e a do hospedeiro: o
/// relógio da CMOS conta segundos inteiros e a base do `-rtc` é tomada um
/// instante antes de o QEMU subir.
const CLOCK_TOLERANCE_MS: i64 = 5_000;

/// `base=<hora local>,clock=host` do `-rtc`: o relógio da CMOS com a hora
/// local do fuso da hive (o ActiveTimeBias), andando com o do hospedeiro.
fn rtc_argument() -> String {
    format!("base={},clock=host", local_rtc_base(crate::hive_image::active_time_bias_minutes()))
}

/// O `-machine` de uma máquina. No WHPX, o LAPIC fica no QEMU
/// (`kernel-irqchip=off`), como o IOAPIC e o 8259. O OpenNT recebe as
/// interrupções de dispositivo pelo 8259, e com o LAPIC no hipervisor
/// (`kernel-irqchip=on`, o modo x2APIC do WHPX) o QEMU só entrega uma
/// interrupção do 8259 numa saída posterior da CPU virtual: medido com ele,
/// o win32k levou 66 s até o WIN32K_LOADED (19 s com o LAPIC no QEMU), 33 s
/// só na criação do arquivo de paginação. O que o LAPIC no hipervisor ganha
/// são os IPIs: o suite-smp4 chega ao KBDTEST_OK em 40 s com ele e em 59 s
/// sem.
fn whpx_machine(machine: &MachineOptions) -> String {
    if machine.accelerator == "whpx" { "pc,kernel-irqchip=off" } else { "pc" }.to_string()
}

/// Os argumentos da máquina; `no_reboot` faz o reinício do convidado
/// encerrar o QEMU.
fn machine_arguments(disks: &Disks, machine: &MachineOptions, no_reboot: bool) -> Vec<String> {
    let mut arguments = vec![
        "-accel".to_string(),
        // No WHPX, um RDMSR/WRMSR de MSR não suportado precisa gerar #GP (como
        // o hardware real) em vez de ler 0: drivers que leem MSRs opcionais e
        // tratam a exceção dependem disso. Requer QEMU 11.1+.
        if machine.accelerator == "whpx" { "whpx,ignore-unknown-msr=off".to_string() } else { machine.accelerator.clone() },
        "-machine".to_string(),
        whpx_machine(machine),
    ];
    // TCG emula o modelo mais completo; em WHPX o modelo padrão (qemu64)
    // esconde RDRAND, que o boot exige, então a CPU do host é repassada.
    match machine.accelerator.as_str() {
        "tcg" => arguments.extend(["-cpu".to_string(), "max".to_string()]),
        "whpx" => arguments.extend(["-cpu".to_string(), "host".to_string()]),
        _ => {}
    }
    // O relógio da CMOS com a hora local do fuso da hive (o que um PC com o
    // Windows guarda), andando com o relógio do hospedeiro.
    arguments.extend(["-rtc".to_string(), rtc_argument()]);
    arguments.extend([
        "-m".to_string(),
        machine.memory_mb.to_string(),
        "-smp".to_string(),
        machine.smp.to_string(),
        "-drive".to_string(),
        format!("format=raw,file={}", disks.boot.display()),
    ]);
    if no_reboot {
        arguments.push("-no-reboot".to_string());
    }
    // Volume NTFS de dados no mestre-escravo primário, quando gerado.
    if let Some(ntfs) = &disks.data {
        let snapshot = if disks.data_snapshot { ",snapshot=on" } else { "" };
        arguments.extend(["-drive".to_string(), format!("format=raw,if=ide,index=1,media=disk{snapshot},file={}", ntfs.display())]);
    }
    // Controlador NVMe (PCI\VEN_1B36&DEV_0010, classe 01.08.02) com o disco
    // particionado, com `--storage=nvme`.
    if let Some(nvme) = &disks.nvme {
        let snapshot = if disks.nvme_snapshot { ",snapshot=on" } else { "" };
        arguments.extend([
            "-drive".to_string(),
            format!("if=none,id=nvm,format=raw{snapshot},file={}", nvme.display()),
            "-device".to_string(),
            "nvme,serial=opennt,drive=nvm".to_string(),
        ]);
    }
    if machine.usb {
        arguments.extend(["-device", "qemu-xhci,id=xhci", "-device", "usb-kbd,bus=xhci.0", "-device", "usb-tablet,bus=xhci.0"].map(String::from));
    }
    arguments
}

/// QEMU em segundo plano (com janela, ou sem tela com `window` falso), a
/// COM1 num arquivo (o terminal fica para o prompt do depurador) e a COM2
/// no socket do depurador. A pasta temporária dele é a [`QEMU_TEMP_DIR`]
/// ao lado do log: quem para o QEMU a apaga com [`remove_temp_dir`].
pub fn spawn(disks: &Disks, machine: &MachineOptions, log: &Path, window: bool) -> Result<Child, String> {
    spawn_adjusted(disks, machine, log, window, Ok)
}

/// O `spawn` com os argumentos da máquina ajustados por `adjust` (os
/// discos e o relógio do `debug --vm-snapshots | --record | --replay`).
pub fn spawn_adjusted(disks: &Disks, machine: &MachineOptions, log: &Path, window: bool, adjust: impl FnOnce(Vec<String>) -> Result<Vec<String>, String>) -> Result<Child, String> {
    let qemu = find_qemu()?;
    let temp = QemuTemp::beside(log)?;
    let mut arguments = adjust(machine_arguments(disks, machine, true))?;
    if !window {
        arguments.extend(["-display".to_string(), "none".to_string()]);
    }
    arguments.extend(["-serial".to_string(), format!("file:{}", log.display())]);
    arguments.extend(kd_serial(machine));
    if let Some(port) = machine.monitor_port {
        arguments.extend(["-monitor".to_string(), format!("tcp:127.0.0.1:{port},server=on,wait=off")]);
    }
    println!("QEMU com o log do kernel em {}", log.display());
    let child = qemu_command(&qemu, temp.path()).args(&arguments).stdin(Stdio::null()).spawn().map_err(|error| format!("{}: {error}", qemu.display()))?;
    // A pasta fica enquanto o QEMU roda.
    temp.keep();
    Ok(child)
}

/// Shell interativo numa janela do QEMU; a serial fica neste terminal.
pub fn run(disks: &Disks, machine: &MachineOptions) -> Result<(), String> {
    let qemu = find_qemu()?;
    let temp = QemuTemp::beside(&disks.boot)?;
    let mut arguments = machine_arguments(disks, machine, true);
    arguments.extend(["-serial".to_string(), "stdio".to_string()]);
    arguments.extend(kd_serial(machine));
    if let Some(port) = machine.kd_port {
        eprintln!("depurador do kernel: COM2 em 127.0.0.1:{port} (cargo xtask debug --connect=127.0.0.1:{port}, ou target remote no GDB)");
    }
    let status = qemu_command(&qemu, temp.path())
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
    /// `--expect-stop`: o bugcheck faz parte do teste, e o `*** STOP` na
    /// serial deixa de ser falha.
    pub expect_stop: bool,
    /// `--power-cycles=N`: o QEMU que o convidado desliga é religado sobre o
    /// mesmo disco, até N vezes.
    pub power_cycles: u32,
    /// `--allow-reboot`: o reinício do convidado reinicia a máquina (sem
    /// `-no-reboot`).
    pub allow_reboot: bool,
    /// `--expect-poweroff`: depois das saídas esperadas, o QEMU precisa sair
    /// sozinho pelo desligamento ACPI.
    pub expect_poweroff: bool,
    /// `--watch-screen`: o xtask lê a tela do QEMU durante o teste e põe o
    /// marcador `FIRST_PIXEL_OK` no log da serial quando a tela gráfica
    /// mostra pixels desenhados ([`drawn_pixels`]).
    pub watch_screen: bool,
}

/// O marcador do `--watch-screen`.
pub const FIRST_PIXEL_MARKER: &str = "FIRST_PIXEL_OK";
/// Intervalo entre duas leituras da tela.
const SCREEN_POLL: Duration = Duration::from_secs(2);
/// Pixels não pretos que uma tela gráfica precisa ter.
const DRAWN_MINIMUM: usize = 64;
/// Um canal acima disto não é preto.
const BLACK_LEVEL: u8 = 0x20;
/// O fundo da tela de bugcheck (`bgk/bugcheck_screen.rs`).
const BUGCHECK_BACKGROUND: [u8; 3] = [0x00, 0x77, 0xD6];

/// Os pixels desenhados numa tela do QEMU, ou None. Só conta uma tela
/// gráfica de pelo menos 800x600, como o vídeo de boot (1024x768): a de
/// texto da VGA (720x400) mostra o console do carregador, e o aviso do
/// QEMU antes da VGA iniciar ocupa 640x480. O vídeo de boot do OpenNT é
/// todo preto e o kernel só desenha nele a tela de bugcheck, então pixels
/// não pretos que não são o fundo azul dela vêm de quem desenha na tela
/// depois do boot.
pub fn drawn_pixels(image: &crate::png::Image) -> Option<String> {
    if image.height < 600 || image.width < 800 {
        return None;
    }
    let mut drawn = 0usize;
    let mut bugcheck = 0usize;
    let mut colors: std::collections::HashMap<[u8; 3], usize> = std::collections::HashMap::new();
    let (mut left, mut top, mut right, mut bottom) = (usize::MAX, usize::MAX, 0usize, 0usize);
    for (index, pixel) in image.rgb.chunks_exact(3).enumerate() {
        let rgb = [pixel[0], pixel[1], pixel[2]];
        if rgb == BUGCHECK_BACKGROUND {
            bugcheck += 1;
        }
        if rgb.iter().all(|&channel| channel <= BLACK_LEVEL) {
            continue;
        }
        drawn += 1;
        *colors.entry(rgb).or_default() += 1;
        let (x, y) = (index % image.width, index / image.width);
        left = left.min(x);
        right = right.max(x);
        top = top.min(y);
        bottom = bottom.max(y);
    }
    if drawn < DRAWN_MINIMUM || bugcheck * 2 > image.width * image.height {
        return None;
    }
    let mut common: Vec<([u8; 3], usize)> = colors.into_iter().collect();
    common.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let palette: Vec<String> = common.iter().take(4).map(|(rgb, count)| format!("#{:02x}{:02x}{:02x} x{count}", rgb[0], rgb[1], rgb[2])).collect();
    Some(format!(
        "{drawn} pixels desenhados na tela {}x{}, de ({left},{top}) a ({right},{bottom}); cores: {}",
        image.width,
        image.height,
        palette.join(", ")
    ))
}

/// O marcador da tela de logon do `--watch-screen`.
pub const LOGON_SCREEN_MARKER: &str = "LOGON_SCREEN_OK";
/// A tela de logon cobre pelo menos um quarto da tela com pixels não pretos.
const LOGON_AREA_DIVISOR: usize = 4;
/// E tem pelo menos tantas cores, cada uma com pelo menos tantos pixels: uma
/// imagem ou um fundo com texto, não um retângulo de cor única nem o ponteiro.
const LOGON_COLORS: usize = 8;
const LOGON_COLOR_PIXELS: usize = 500;

/// A tela de logon numa tela do QEMU, ou None: uma tela gráfica de pelo
/// menos 800x600 que não é a de bugcheck, com um quarto ou mais dela fora do
/// preto e [`LOGON_COLORS`] cores de pelo menos [`LOGON_COLOR_PIXELS`]
/// pixels cada. O primeiro pixel (o ponteiro do mouse, [`drawn_pixels`])
/// não basta.
pub fn logon_screen(image: &crate::png::Image) -> Option<String> {
    if image.height < 600 || image.width < 800 {
        return None;
    }
    let total = image.width * image.height;
    let mut drawn = 0usize;
    let mut bugcheck = 0usize;
    let mut colors: std::collections::HashMap<[u8; 3], usize> = std::collections::HashMap::new();
    for pixel in image.rgb.chunks_exact(3) {
        let rgb = [pixel[0], pixel[1], pixel[2]];
        if rgb == BUGCHECK_BACKGROUND {
            bugcheck += 1;
        }
        if rgb.iter().all(|&channel| channel <= BLACK_LEVEL) {
            continue;
        }
        drawn += 1;
        *colors.entry(rgb).or_default() += 1;
    }
    if bugcheck * 2 > total || drawn * LOGON_AREA_DIVISOR < total {
        return None;
    }
    let mut common: Vec<([u8; 3], usize)> = colors.into_iter().filter(|(_, count)| *count >= LOGON_COLOR_PIXELS).collect();
    if common.len() < LOGON_COLORS {
        return None;
    }
    common.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let palette: Vec<String> = common.iter().take(4).map(|(rgb, count)| format!("#{:02x}{:02x}{:02x} x{count}", rgb[0], rgb[1], rgb[2])).collect();
    Some(format!("{drawn} de {total} pixels desenhados, {} cores com {LOGON_COLOR_PIXELS} pixels ou mais; cores: {}", common.len(), palette.join(", ")))
}

/// Grava uma captura da tela em `target`, com a descrição nos metadados.
fn save_capture(image: &crate::png::Image, target: &std::path::Path, result: &str, description: &str) {
    let png = crate::png::encode_capture(image, &[("opennt-data", crate::png::today().as_str()), ("opennt-resultado", result), ("opennt-serial", description)], CAPTURE_LIMIT);
    if std::fs::write(target, &png).is_ok() {
        println!("[xtask] {result}: {}", target.display());
    }
}

/// A vigia da tela (`--watch-screen`): a cada [`SCREEN_POLL`] lê a tela
/// pelo QMP. Na primeira com pixels desenhados escreve a descrição e o
/// `FIRST_PIXEL_OK` no log da serial e grava o PNG em `first` (se houver);
/// depois segue lendo até a tela de logon ([`logon_screen`]), que sai com o
/// `LOGON_SCREEN_OK` e vai para `tela-de-logon.png`, ao lado.
fn watch_screen(port: u16, scratch: PathBuf, first: Option<PathBuf>, output: Arc<Mutex<String>>, stop: Arc<std::sync::atomic::AtomicBool>) {
    use std::sync::atomic::Ordering;
    let mut first_seen = false;
    while !stop.load(Ordering::Acquire) {
        thread::sleep(SCREEN_POLL);
        if stop.load(Ordering::Acquire) || qmp_screendump(port, &scratch).is_err() {
            continue;
        }
        let Ok(bytes) = std::fs::read(&scratch) else { continue };
        let Ok(image) = crate::png::read_ppm(&bytes) else { continue };
        if !first_seen {
            let Some(description) = drawn_pixels(&image) else { continue };
            first_seen = true;
            let line = format!("\n[xtask] tela: {description}\n{FIRST_PIXEL_MARKER}\n");
            print!("{line}");
            output.lock().unwrap().push_str(&line);
            if let Some(target) = &first {
                save_capture(&image, target, "primeira tela desenhada", &description);
            }
        }
        let Some(description) = logon_screen(&image) else { continue };
        let line = format!("\n[xtask] tela de logon: {description}\n{LOGON_SCREEN_MARKER}\n");
        print!("{line}");
        output.lock().unwrap().push_str(&line);
        if let Some(target) = &first {
            save_capture(&image, &target.with_file_name("tela-de-logon.png"), "tela de logon", &description);
        }
        break;
    }
    let _ = std::fs::remove_file(&scratch);
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

/// Digita `text`; `{combo}` manda o combo cru ao `sendkey` (nomes de tecla
/// do QEMU separados por `-`, pressionados em ordem e soltos ao contrário,
/// como `{ctrl_r-scroll_lock-scroll_lock}`).
fn type_keys(monitor: &mut TcpStream, text: &str) -> Result<(), String> {
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        let name = if character == '{' {
            let combo: String = characters.by_ref().take_while(|&next| next != '}').collect();
            if combo.is_empty() || !combo.chars().all(|next| next.is_ascii_alphanumeric() || next == '_' || next == '-') {
                return Err(format!("combo de teclas invalido: {{{combo}}}"));
            }
            combo
        } else {
            key_name(character).ok_or_else(|| format!("tecla sem mapa no sendkey: {character:?}"))?
        };
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

/// Falhas na serial: pânico do Rust, exceção de kernel, autoteste (também o
/// da pressão de memória, `MEMORY_PRESSURE FALHOU`, que antes só aparecia
/// quando o prazo de 30 min do teste vencia), a parada fatal do KeBugCheckEx
/// (`*** STOP`, que sempre para a máquina) e a hora do convidado longe da do
/// hospedeiro (`*** RELOGIO`, que o test-boot acrescenta).
pub const FAILURE_MARKERS: &[&str] = &["*** PANIC", "*** EXCECAO", "SELFTEST FALHOU", "MEMORY_PRESSURE FALHOU", "*** STOP", "*** RELOGIO"];

/// O começo do motivo de um QEMU que saiu com erro sem evento SHUTDOWN do
/// QMP: morto de fora (o dono da máquina fecha os QEMUs quando o PC fica
/// lento) ou um erro fatal do próprio QEMU. O convidado nunca causa isso: o
/// desligamento e o reinício com -no-reboot fazem o QEMU sair com sucesso.
/// O test-all repete a execução ([`crate::test_all`]).
pub const QEMU_KILLED: &str = "QEMU encerrado de fora";

/// Como um QEMU terminou: o status e o motivo do evento SHUTDOWN do QMP.
fn ended(status: std::process::ExitStatus, reason: Option<&str>) -> String {
    match reason {
        None if !status.success() => format!("{QEMU_KILLED} ({status})"),
        _ => format!("{status}, evento SHUTDOWN do QMP: {}", reason.unwrap_or("nenhum")),
    }
}

/// O motivo de fim da máquina que o QMP anuncia quando o convidado se
/// desliga pelo ACPI (S5).
const GUEST_SHUTDOWN: &str = "guest-shutdown";

/// Um QEMU do teste: o processo, a thread que copia a serial e o motivo do
/// último evento SHUTDOWN do QMP (com `--expect-poweroff`/`--power-cycles`).
struct Machine {
    process: QemuProcess,
    reader: Option<thread::JoinHandle<()>>,
    shutdown_reason: Arc<Mutex<Option<String>>>,
}

impl Machine {
    /// Termina de ler a serial de um QEMU que já saiu.
    fn drain(&mut self) {
        if let Some(reader) = self.reader.take() {
            let _ = wait_finished(&reader, Duration::from_secs(5));
        }
    }
}

/// O motivo de um evento `SHUTDOWN` do QMP (`"reason": "..."`).
fn shutdown_reason(line: &str) -> Option<String> {
    if !line.contains("\"SHUTDOWN\"") {
        return None;
    }
    let after = &line[line.find("\"reason\"")? + "\"reason\"".len()..];
    let start = after.find('"')? + 1;
    let end = after[start..].find('"')? + start;
    Some(after[start..end].to_string())
}

/// Conecta ao QMP de eventos e anota o motivo de cada `SHUTDOWN`.
fn watch_shutdown_events(port: u16, reason: Arc<Mutex<Option<String>>>) {
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(60);
        let stream = loop {
            match TcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => break stream,
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(100)),
                Err(_) => return,
            }
        };
        let Ok(mut writer) = stream.try_clone() else { return };
        let mut reader = std::io::BufReader::new(stream);
        let mut line = String::new();
        if std::io::BufRead::read_line(&mut reader, &mut line).is_err() || writer.write_all(b"{\"execute\":\"qmp_capabilities\"}\n").is_err() {
            return;
        }
        loop {
            line.clear();
            match std::io::BufRead::read_line(&mut reader, &mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {
                    if let Some(found) = shutdown_reason(&line) {
                        *reason.lock().unwrap() = Some(found);
                    }
                }
            }
        }
    });
}

/// Sobe um QEMU com os argumentos dados; a serial vai para `output`.
/// Os argumentos com o `-rtc` refeito na hora corrente.
fn with_current_rtc(arguments: &[String]) -> Vec<String> {
    let mut fresh = arguments.to_vec();
    for index in 1..fresh.len() {
        if fresh[index - 1] == "-rtc" {
            fresh[index] = rtc_argument();
        }
    }
    fresh
}

fn launch(qemu: &Path, temp: &Path, arguments: &[String], output: &Arc<Mutex<String>>, events_port: Option<u16>) -> Result<Machine, String> {
    // Cada QEMU (também o religado de um ciclo de energia) começa com o
    // relógio da CMOS na hora local corrente.
    let arguments = with_current_rtc(arguments);
    let mut child = qemu_command(qemu, temp)
        .args(&arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("{}: {error}", qemu.display()))?;
    let mut stdout = child.stdout.take().unwrap();
    let process = QemuProcess(child);
    let sink = Arc::clone(output);
    let reader = thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        let mut line = String::new();
        while let Ok(count) = stdout.read(&mut buffer) {
            if count == 0 {
                break;
            }
            let text = String::from_utf8_lossy(&buffer[..count]).replace('\r', "");
            print!("{text}");
            let _ = std::io::stdout().flush();
            sink.lock().unwrap().push_str(&text);
            // A hora do convidado contra a do hospedeiro, no instante em que
            // a linha chega.
            for character in text.chars() {
                if character != '\n' {
                    line.push(character);
                    continue;
                }
                if line.starts_with("[time]") {
                    if let Some(offset) = guest_clock_offset(&line) {
                        let verdict = if offset.abs() > CLOCK_TOLERANCE_MS { "*** RELOGIO fora da hora do hospedeiro" } else { "relogio de acordo com o hospedeiro" };
                        let report = format!("[xtask] {verdict}: hora do convidado a {offset} ms\n");
                        print!("{report}");
                        sink.lock().unwrap().push_str(&report);
                    }
                }
                line.clear();
            }
        }
    });
    let shutdown_reason = Arc::new(Mutex::new(None));
    if let Some(port) = events_port {
        watch_shutdown_events(port, Arc::clone(&shutdown_reason));
    }
    Ok(Machine { process, reader: Some(reader), shutdown_reason })
}

/// O volume de dados de um teste que religa o QEMU (`--power-cycles`): uma
/// cópia gravável do volume, ao lado do log, para o segundo QEMU ver o que o
/// primeiro gravou.
fn private_data_disk(disks: &Disks, log: &Path) -> Result<Option<PathBuf>, String> {
    let Some(original) = &disks.data else { return Ok(None) };
    let copy = log.with_file_name("ntfs-execucao.img");
    std::fs::copy(original, &copy).map_err(|error| format!("{} -> {}: {error}", original.display(), copy.display()))?;
    Ok(Some(copy))
}

/// Boot sem tela: sucesso quando o marcador (e as saídas esperadas depois
/// das teclas) aparecem na serial antes do prazo.
/// Com `session` (o roteiro do depurador), ela roda em paralelo ao teste.
/// Com `power_cycles`, um QEMU que o convidado desliga pelo ACPI é religado
/// sobre o mesmo disco (até N vezes) e a serial continua no mesmo log; com
/// `allow_reboot`, o reinício do convidado reinicia a máquina em vez de
/// encerrar o QEMU; com `expect_poweroff`, depois das saídas esperadas o
/// QEMU precisa sair sozinho pelo desligamento ACPI (o evento SHUTDOWN do
/// QMP com o motivo `guest-shutdown`).
pub fn test_boot(disks: &Disks, machine: &MachineOptions, test: &TestOptions, log: &Path, session: Option<Session>) -> Result<(), String> {
    let qemu = find_qemu()?;
    let port = free_port()?;
    // O snapshot=on do volume dura um QEMU: o religamento precisa de uma
    // cópia gravável dele.
    let data_copy = if test.power_cycles > 0 { private_data_disk(disks, log)? } else { None };
    let disks = match &data_copy {
        Some(copy) => Disks { boot: disks.boot.clone(), data: Some(copy.clone()), data_snapshot: false, nvme: disks.nvme.clone(), nvme_snapshot: disks.nvme_snapshot },
        None => Disks { boot: disks.boot.clone(), data: disks.data.clone(), data_snapshot: disks.data_snapshot, nvme: disks.nvme.clone(), nvme_snapshot: disks.nvme_snapshot },
    };
    let mut arguments = machine_arguments(&disks, machine, !test.allow_reboot);
    arguments.extend([
        "-display".to_string(),
        "none".to_string(),
        "-serial".to_string(),
        "stdio".to_string(),
        "-monitor".to_string(),
        format!("tcp:127.0.0.1:{port},server=on,wait=off"),
    ]);
    // O QMP só entra com a captura ou a vigia da tela: o `screendump` sai
    // por ele.
    let qmp_port = if test.capture.is_some() || test.watch_screen {
        let qmp = free_port()?;
        arguments.extend(["-qmp".to_string(), format!("tcp:127.0.0.1:{qmp},server=on,wait=off")]);
        Some(qmp)
    } else {
        None
    };
    // Um segundo QMP só para os eventos de fim da máquina.
    let events_port = if test.expect_poweroff || test.power_cycles > 0 {
        let events = free_port()?;
        arguments.extend(["-qmp".to_string(), format!("tcp:127.0.0.1:{events},server=on,wait=off")]);
        Some(events)
    } else {
        None
    };
    arguments.extend(kd_serial(machine));
    // A pasta temporária sai depois do QEMU: declarada antes da máquina, ela
    // é solta depois dela também nos retornos de erro.
    let temp = QemuTemp::beside(log)?;
    let output = Arc::new(Mutex::new(String::new()));
    let current = std::cell::RefCell::new(launch(&qemu, temp.path(), &arguments, &output, events_port)?);
    let cycles_left = std::cell::Cell::new(test.power_cycles);
    // A vigia da tela roda durante o teste; o QMP atende um cliente por vez,
    // então ela para antes da captura do fim.
    let screen_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let screen_watcher = match (test.watch_screen, qmp_port) {
        (true, Some(qmp)) => {
            let (scratch, first) = (log.with_file_name("tela.ppm"), Some(log.with_file_name("primeira-tela.png")));
            let (serial, stop) = (Arc::clone(&output), Arc::clone(&screen_stop));
            Some(thread::spawn(move || watch_screen(qmp, scratch, first, serial, stop)))
        }
        _ => None,
    };

    let deadline = Instant::now() + test.timeout;
    // Com `--expect-stop`, o STOP do bugcheck é o próprio teste.
    let failure_markers: Vec<&str> = FAILURE_MARKERS.iter().copied().filter(|marker| !(test.expect_stop && *marker == "*** STOP")).collect();
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
    // O QEMU saiu: religa quando o convidado se desligou e ainda há ciclos;
    // senão devolve o motivo do fim (None = segue rodando).
    let supervise = || -> Result<Option<String>, String> {
        let mut machine = current.borrow_mut();
        let Ok(Some(status)) = machine.process.0.try_wait() else { return Ok(None) };
        machine.drain();
        let reason = machine.shutdown_reason.lock().unwrap().clone();
        if reason.as_deref() == Some(GUEST_SHUTDOWN) && cycles_left.get() > 0 {
            cycles_left.set(cycles_left.get() - 1);
            output.lock().unwrap().push_str("\n[xtask] o convidado desligou a maquina; QEMU religado sobre o mesmo disco\n");
            println!("\n[xtask] QEMU religado sobre o mesmo disco");
            *machine = launch(&qemu, temp.path(), &arguments, &output, events_port)?;
            return Ok(None);
        }
        Ok(Some(ended(status, reason.as_deref())))
    };
    let wait_for = |needle: &str, from: usize| -> Result<usize, String> {
        loop {
            if let Some(error) = session_failure.lock().unwrap().clone() {
                // A conexão do depurador cai quando o QEMU morre: o motivo
                // é o fim do QEMU (um instante para o processo sair).
                for _ in 0..20 {
                    if let Some(ended) = supervise()? {
                        if ended.starts_with(QEMU_KILLED) {
                            return Err(format!("QEMU terminou ({ended}) antes de {needle:?}"));
                        }
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                return Err(format!("sessao do depurador: {error}"));
            }
            {
                let text = output.lock().unwrap();
                if let Some(failure) = failure_markers.iter().find(|marker| text[from.min(text.len())..].contains(*marker)) {
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
            // O QEMU que saiu antes da saída esperada encerra a espera (sem
            // religamento a fazer); a serial dele já foi lida inteira.
            if let Some(ended) = supervise()? {
                let text = output.lock().unwrap();
                if let Some(failure) = failure_markers.iter().find(|marker| text[from.min(text.len())..].contains(*marker)) {
                    return Err(format!("falha detectada na serial: {failure}"));
                }
                if let Some(position) = text[from.min(text.len())..].find(needle) {
                    return Ok(from + position + needle.len());
                }
                return Err(format!("QEMU terminou ({ended}) antes de {needle:?}"));
            }
            if Instant::now() > deadline {
                return Err(format!("tempo esgotado esperando {needle:?}"));
            }
            thread::sleep(Duration::from_millis(50));
        }
    };

    // Quando cada saída esperada chegou, contado da subida do QEMU (o
    // tempo de cada fase do boot no test-boot.log).
    let started = Instant::now();
    let arrived = |needle: &str| println!("\n[xtask] {needle:?} aos {:.1} s", started.elapsed().as_secs_f64());
    let result = (|| -> Result<(), String> {
        let mut cursor = wait_for(&test.marker, 0)?;
        arrived(&test.marker);
        if let Some(keys) = &test.keys {
            cursor = wait_for("[shell] pronto", 0)?;
            let mut monitor = connect_monitor(port, deadline)?;
            type_keys(&mut monitor, keys)?;
        }
        for expected in &test.expect {
            cursor = wait_for(expected, cursor)?;
            arrived(expected);
        }
        if test.expect_poweroff {
            // O convidado precisa desligar a máquina sozinho, pelo ACPI.
            loop {
                if let Some(ended) = supervise()? {
                    let reason = current.borrow().shutdown_reason.lock().unwrap().clone();
                    if reason.as_deref() != Some(GUEST_SHUTDOWN) {
                        return Err(format!("o QEMU terminou sem o desligamento ACPI ({ended})"));
                    }
                    if cycles_left.get() > 0 {
                        return Err(format!("o QEMU terminou com {} religamento(s) por fazer", cycles_left.get()));
                    }
                    let text = output.lock().unwrap();
                    if let Some(failure) = failure_markers.iter().find(|marker| text[cursor.min(text.len())..].contains(*marker)) {
                        return Err(format!("falha detectada na serial antes do desligamento: {failure}"));
                    }
                    println!("\n[xtask] o QEMU saiu sozinho: {ended}");
                    return Ok(());
                }
                if Instant::now() > deadline {
                    return Err("tempo esgotado esperando o convidado desligar a maquina".into());
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
        // O prazo do teste não vale durante a espera: ela tem duração própria.
        let hold_end = Instant::now() + test.hold;
        while Instant::now() < hold_end {
            {
                let text = output.lock().unwrap();
                if let Some(failure) = failure_markers.iter().find(|marker| text[cursor.min(text.len())..].contains(*marker)) {
                    return Err(format!("falha detectada na serial durante os {} ms de espera: {failure}", test.hold.as_millis()));
                }
            }
            // Um triplo fault com -no-reboot encerra o QEMU sem marcador.
            let exited = current.borrow_mut().process.0.try_wait();
            if let Ok(Some(status)) = exited {
                let reason = current.borrow().shutdown_reason.lock().unwrap().clone();
                return Err(format!("QEMU terminou durante os {} ms de espera ({})", test.hold.as_millis(), ended(status, reason.as_deref())));
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
    screen_stop.store(true, std::sync::atomic::Ordering::Release);
    if let Some(watcher) = screen_watcher {
        let _ = watcher.join();
    }
    let mut machine = current.into_inner();
    // A captura sai com o QEMU ainda vivo, passe o teste ou não; se ela
    // falhar, o resultado do teste não muda.
    if let (Some(target), Some(qmp)) = (&test.capture, qmp_port) {
        let alive = matches!(machine.process.0.try_wait(), Ok(None));
        let mut needles = vec![test.marker.as_str()];
        needles.extend(test.expect.iter().map(String::as_str));
        let serial = serial_proof(&output.lock().unwrap(), &needles);
        let captured = if alive { capture_screen(qmp, target, &result, &serial) } else { Err("o QEMU ja tinha terminado".into()) };
        if let Err(error) = captured {
            eprintln!("aviso: sem captura de tela ({}): {error}", target.display());
        }
    }
    drop(machine.process);
    machine.reader.take();
    drop(temp);
    if let Some(copy) = &data_copy {
        let _ = std::fs::remove_file(copy);
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::png::Image;

    /// O QEMU recebe a pasta temporária da execução nas três variáveis, e a
    /// pasta sai inteira no fim, com o que o processo deixou nela (o arquivo
    /// `vl.XXXXXX` de um disco com snapshot=on de um QEMU morto).
    #[test]
    fn qemu_temporary_files_stay_in_the_run_directory() {
        let root = std::env::temp_dir().join(format!("opennt-qemu-tmp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let log = root.join("serial.log");
        let directory = temp_dir_beside(&log);
        // Uma sobra de uma execução anterior sai ao criar.
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("vl.antigo"), b"x").unwrap();
        let temp = QemuTemp::beside(&log).unwrap();
        assert_eq!(temp.path(), directory);
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
        let command = qemu_command(Path::new("qemu"), temp.path());
        for variable in TEMP_VARIABLES {
            let value = command.get_envs().find(|(name, _)| *name == variable).and_then(|(_, value)| value);
            assert_eq!(value, Some(directory.as_os_str()), "{variable}");
        }
        // Um processo filho grava na pasta temporária que recebeu.
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            let mut child = qemu_command(Path::new("cmd"), temp.path());
            let status = child.raw_arg("/C echo x> \"%TEMP%\\vl.ABC123\"").status().unwrap();
            assert!(status.success());
            assert!(directory.join("vl.ABC123").is_file());
        }
        drop(temp);
        assert!(!directory.exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    fn screen(width: usize, height: usize, fill: [u8; 3]) -> Image {
        Image { width, height, rgb: fill.iter().copied().cycle().take(width * height * 3).collect() }
    }

    #[test]
    fn drawn_pixels_needs_a_graphics_screen_with_drawing() {
        // Preto: o vídeo de boot.
        assert!(drawn_pixels(&screen(1024, 768, [0, 0, 0])).is_none());
        // A tela de texto da VGA (720x400) e o aviso do QEMU (640x480) não
        // contam.
        assert!(drawn_pixels(&screen(720, 400, [0xAA, 0xAA, 0xAA])).is_none());
        assert!(drawn_pixels(&screen(640, 480, [0xFF, 0xFF, 0xFF])).is_none());
        // A tela de bugcheck não conta.
        assert!(drawn_pixels(&screen(1024, 768, BUGCHECK_BACKGROUND)).is_none());
        // Um retângulo branco de 16x16 conta, com a caixa e a cor.
        let mut image = screen(1024, 768, [0, 0, 0]);
        for y in 100..116 {
            for x in 200..216 {
                let at = (y * 1024 + x) * 3;
                image.rgb[at..at + 3].copy_from_slice(&[0xFF, 0xFF, 0xFF]);
            }
        }
        let description = drawn_pixels(&image).expect("16x16 desenhados");
        assert!(description.starts_with("256 pixels desenhados na tela 1024x768, de (200,100) a (215,115)"), "{description}");
        assert!(description.contains("#ffffff x256"), "{description}");
        // Menos que o mínimo: ruído, não desenho.
        let mut few = screen(1024, 768, [0, 0, 0]);
        few.rgb[0..3].copy_from_slice(&[0xFF, 0, 0]);
        assert!(drawn_pixels(&few).is_none());
    }

    #[test]
    fn logon_screen_needs_a_large_area_with_several_colors() {
        // O ponteiro sobre o preto e uma tela de cor única não são a tela de
        // logon; a de bugcheck também não.
        let mut pointer = screen(1024, 768, [0, 0, 0]);
        pointer.rgb[0..3 * 73].fill(0xFF);
        assert!(logon_screen(&pointer).is_none());
        assert!(logon_screen(&screen(1024, 768, [0x10, 0x60, 0xA0])).is_none());
        assert!(logon_screen(&screen(1024, 768, BUGCHECK_BACKGROUND)).is_none());
        // Faixas de 16 cores cobrindo a tela inteira contam.
        let mut bands = screen(1024, 768, [0, 0, 0]);
        for (index, pixel) in bands.rgb.chunks_exact_mut(3).enumerate() {
            let band = ((index % 1024) / 64) as u8;
            pixel.copy_from_slice(&[0x40 + band * 8, 0x80, 0xC0 - band * 4]);
        }
        let description = logon_screen(&bands).expect("faixas coloridas");
        assert!(description.starts_with("786432 de 786432 pixels desenhados, 16 cores"), "{description}");
        // Metade da tela de cores, mas com só 4 cores: não basta.
        let mut four = screen(1024, 768, [0, 0, 0]);
        for (index, pixel) in four.rgb.chunks_exact_mut(3).enumerate().filter(|(index, _)| index % 1024 < 512) {
            pixel.copy_from_slice(&[0x80, (index % 4) as u8 * 0x30 + 0x40, 0x80]);
        }
        assert!(logon_screen(&four).is_none());
    }
}
