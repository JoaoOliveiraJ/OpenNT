//! Execução no QEMU.
//!
//! `run` abre a janela do QEMU com a serial no terminal. `test-boot` roda
//! sem tela, espera um marcador na serial, opcionalmente digita comandos no
//! shell pelo monitor HMP (`sendkey`), manda teclas e move o mouse pelo
//! mesmo monitor depois de um marcador (`--send` e `--mouse`, como uma
//! pessoa na frente da máquina: [`InputSend`]) e confere a saída esperada. Com o
//! depurador do kernel (`--kd`), a segunda porta serial (COM2) vira um
//! socket TCP em 127.0.0.1 (`kd_port`), onde o cliente (`cargo xtask
//! debug`) ou o GDB se conectam; uma sessão de roteiro roda em paralelo ao
//! `test-boot` e a falha dela derruba o teste. Com `--capture=ARQ.png`, o
//! QEMU ganha um socket QMP e, no fim do teste, a tela vai para o PNG (a
//! tela de logon ou a área de trabalho que a vigia do `--watch-screen`
//! confirmou, quando o teste passou com ela); com
//! `--capture-every=SEGUNDOS`, a tela vai para `tela-NNNN.png` durante o
//! teste e para `tela-final.png` no fim ([`FrameSeries`]). Com
//! `--manual-crash`, o fim do teste manda a parada manual pelo teclado
//! ([`manual_crash`]) para os dados secundários do bugcheck saírem na serial;
//! a parada (essa ou a do teste que falhou) sai resumida
//! ([`crate::crash::summarize`]). Os testes do
//! desligamento (`--expect-poweroff`, `--power-cycles=N`, `--allow-reboot`)
//! recebem os eventos SHUTDOWN por um segundo QMP; o reinício do convidado
//! fica no mesmo QEMU (e no mesmo snapshot do volume) e o religamento depois
//! do desligamento ACPI sobe outro QEMU sobre uma cópia gravável do volume
//! NTFS.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::screen_check::{self, COMMAND_OUTPUT_MARKER, CONTEXT_MENU_MARKER, TEXT_TYPED_MARKER, WINDOW_OPENED_MARKER, CURSOR_MOVED_MARKER, DESKTOP_AFTER, DESKTOP_MARKER, FIRST_PIXEL_MARKER, LOGON_DISMISS_MARKER, LOGON_SCREEN_MARKER, RESTART_AFTER, START_MENU_MARKER, TASKBAR_AFTER, TASKBAR_MARKER};

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
    /// `--net`: a placa de rede Intel PRO/1000 do QEMU (e1000, PCI
    /// 8086:100E) com a rede de modo usuário (slirp: a rede 10.0.2.0/24, o
    /// gateway 10.0.2.2 e o DHCP do QEMU).
    pub net: bool,
    /// `--tpm`: um TPM 2.0 com interface CRB (tpm-crb, ACPI MSFT0101 e a
    /// tabela TPM2) sobre o simulador de TPM ([`TpmSimulator`]).
    pub tpm: bool,
    /// Porta TCP do monitor HMP (o rastro rápido do depurador gráfico liga
    /// o log de execução do QEMU por ele), se houver.
    pub monitor_port: Option<u16>,
    /// `--ata-fault=read`: o volume NTFS de dados (o drive 1 do canal IDE
    /// primário) atrás do filtro blkdebug do QEMU, que devolve um erro de
    /// E/S a uma leitura do convidado ([`data_drive_file`]); vazio = o
    /// arquivo direto.
    pub ata_fault: String,
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

/// O acelerador de uma máquina. Com `--tpm` é o TCG: o WHPX do QEMU não
/// mapeia as regiões de memória do tpm-crb (o buffer de comando de 0xF80
/// bytes e a página do PPI de 0x400, menores que uma página), e o QEMU para
/// no realize do dispositivo ("WHPX: failed to unmap GPA range").
pub fn machine_accelerator(machine: &MachineOptions) -> Result<String, String> {
    match (machine.tpm, machine.accelerator.as_str()) {
        (true, "whpx") => Err("--tpm roda no TCG: o WHPX do QEMU nao mapeia as regioes do tpm-crb (use --accel=tcg)".into()),
        (true, _) => Ok("tcg".into()),
        (false, requested) => resolve_accelerator(requested),
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

/// O simulador de TPM 2.0 do `--tpm`: o `tpm_server.exe` (variável
/// `TPM_SIMULATOR`, ou ao lado do QEMU), que atende o protocolo TCP do
/// simulador de referência numa porta de comandos e na seguinte, de
/// plataforma (energia e NV). O backend `mssim` do QEMU fala com ele e o
/// `tpm-crb` o expõe ao convidado. O estado NV (o arquivo `NVChip`) e o log
/// do simulador ficam na pasta temporária do QEMU ([`QEMU_TEMP_DIR`]), que
/// sai com a execução; o `-rm` começa de um TPM recém-fabricado. O processo
/// morre no `drop`, antes da pasta.
pub struct TpmSimulator {
    process: Child,
    pub port: u16,
}

/// Localiza o simulador de TPM 2.0.
pub fn find_tpm_simulator() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("TPM_SIMULATOR") {
        return Ok(PathBuf::from(path));
    }
    let beside = find_qemu()?.with_file_name("tpm_server.exe");
    if beside.exists() {
        return Ok(beside);
    }
    Err(format!("simulador de TPM nao encontrado: {} ausente (defina TPM_SIMULATOR)", beside.display()))
}

/// Uma porta local livre cuja seguinte também está livre (comandos e
/// plataforma do simulador).
fn free_port_pair() -> Result<u16, String> {
    for _ in 0..64 {
        let port = free_port()?;
        if port < u16::MAX && TcpListener::bind(("127.0.0.1", port)).is_ok() && TcpListener::bind(("127.0.0.1", port + 1)).is_ok() {
            return Ok(port);
        }
    }
    Err("sem duas portas TCP seguidas livres para o simulador de TPM".into())
}

impl TpmSimulator {
    /// Sobe o simulador com o estado em `directory` e espera as duas portas.
    pub fn start(directory: &Path) -> Result<TpmSimulator, String> {
        let program = find_tpm_simulator()?;
        let port = free_port_pair()?;
        let log = std::fs::File::create(directory.join("tpm_server.log")).map_err(|error| format!("{}: {error}", directory.display()))?;
        let errors = log.try_clone().map_err(|error| error.to_string())?;
        let process = Command::new(&program)
            .args(["-port", &port.to_string(), "-rm"])
            .current_dir(directory)
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(errors)
            .spawn()
            .map_err(|error| format!("{}: {error}", program.display()))?;
        let mut simulator = TpmSimulator { process, port };
        let deadline = Instant::now() + Duration::from_secs(10);
        for listening in [port + 1, port] {
            loop {
                if TcpStream::connect(("127.0.0.1", listening)).is_ok() {
                    break;
                }
                if let Ok(Some(status)) = simulator.process.try_wait() {
                    return Err(format!("o simulador de TPM saiu ({status}); log em {}", directory.join("tpm_server.log").display()));
                }
                if Instant::now() > deadline {
                    return Err(format!("o simulador de TPM nao abriu a porta {listening}"));
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
        println!("simulador de TPM 2.0 nas portas {port} e {}", port + 1);
        Ok(simulator)
    }
}

impl Drop for TpmSimulator {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// O backend e o dispositivo do TPM: o `mssim` ligado ao simulador e o
/// `tpm-crb` (start method 7 na tabela TPM2, o dispositivo MSFT0101 no
/// \_SB da DSDT).
fn tpm_arguments(port: u16) -> Vec<String> {
    vec![
        "-tpmdev".to_string(),
        format!("mssim,id=tpm0,host=127.0.0.1,port={port}"),
        "-device".to_string(),
        "tpm-crb,tpmdev=tpm0".to_string(),
    ]
}

/// Valores aceitos por `--ata-fault`.
pub const ATA_FAULTS: &[&str] = &["read"];

/// O arquivo do volume de dados no `-drive`: direto, ou, com
/// `--ata-fault=read`, atrás do filtro blkdebug do QEMU. A primeira leitura
/// do disco passa e muda o estado do filtro de 1 para 2 (é a do próprio
/// QEMU, que lê o setor 0 para adivinhar a geometria CHS do disco IDE; sem
/// ela, a primeira leitura do convidado); a leitura seguinte, já do
/// convidado, volta uma vez com EIO. O IDE do QEMU relata o erro de leitura
/// (rerror=report, o padrão) com ERR no status e ABRT no registrador de
/// erro, e o driver ATA do kernel manda o comando de novo.
fn data_drive_file(image: &Path, fault: &str) -> String {
    match fault {
        "read" => format!(
            "file.driver=blkdebug,file.image.driver=file,file.image.filename={},\
             file.set-state.0.event=read_aio,file.set-state.0.state=1,file.set-state.0.new_state=2,\
             file.inject-error.0.event=read_aio,file.inject-error.0.state=2,file.inject-error.0.errno=5,file.inject-error.0.once=on",
            image.display()
        ),
        _ => format!("file={}", image.display()),
    }
}

/// Os argumentos da máquina; `no_reboot` faz o reinício do convidado
/// encerrar o QEMU; `tpm` é a porta do simulador de TPM (`--tpm`).
fn machine_arguments(disks: &Disks, machine: &MachineOptions, no_reboot: bool, tpm: Option<u16>) -> Vec<String> {
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
        arguments.extend(["-drive".to_string(), format!("format=raw,if=ide,index=1,media=disk{snapshot},{}", data_drive_file(ntfs, &machine.ata_fault))]);
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
    // A placa e1000 com a rede de modo usuário, explícita: o endereço MAC
    // fixo é o padrão do QEMU (52:54:00:12:34:56).
    if machine.net {
        arguments.extend(["-netdev", "user,id=net0", "-device", "e1000,netdev=net0,mac=52:54:00:12:34:56"].map(String::from));
    }
    if let Some(port) = tpm {
        arguments.extend(tpm_arguments(port));
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
    if machine.tpm {
        return Err("--tpm vale no run e no test-boot".into());
    }
    let qemu = find_qemu()?;
    let temp = QemuTemp::beside(log)?;
    let mut arguments = adjust(machine_arguments(disks, machine, true, None))?;
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
    let simulator = if machine.tpm { Some(TpmSimulator::start(temp.path())?) } else { None };
    let mut arguments = machine_arguments(disks, machine, true, simulator.as_ref().map(|simulator| simulator.port));
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
    /// Saídas esperadas em qualquer ordem (`--expect-any`): cada uma é
    /// procurada desde o começo da serial, depois das de `expect`, com o
    /// mesmo marcador de falha encerrando a espera.
    pub expect_any: Vec<String>,
    /// Depois da última saída esperada, o sistema segue rodando por este
    /// tempo sem nenhuma falha na serial (`--hold=MS`).
    pub hold: Duration,
    /// `--capture=ARQ.png`: no fim do teste (passando ou não), a tela do
    /// QEMU vai para este PNG, pelo `screendump` do QMP.
    pub capture: Option<PathBuf>,
    /// `--expect-stop`: o bugcheck faz parte do teste, e o `*** STOP` na
    /// serial deixa de ser falha.
    pub expect_stop: bool,
    /// `--manual-crash`: no fim do teste (passando ou não), com o QEMU vivo
    /// e sem STOP na serial, a parada manual pelo teclado ([`manual_crash`])
    /// para os dados secundários do bugcheck saírem na serial.
    pub manual_crash: bool,
    /// `--power-cycles=N`: o QEMU que o convidado desliga é religado sobre o
    /// mesmo disco, até N vezes.
    pub power_cycles: u32,
    /// `--allow-reboot`: o reinício do convidado reinicia a máquina (sem
    /// `-no-reboot`).
    pub allow_reboot: bool,
    /// `--expect-poweroff`: depois das saídas esperadas, o QEMU precisa sair
    /// sozinho pelo desligamento ACPI.
    pub expect_poweroff: bool,
    /// `--watch-screen`: o xtask lê a tela do QEMU durante o teste e põe no
    /// log da serial o marcador `FIRST_PIXEL_OK` quando a tela gráfica
    /// mostra pixels desenhados ([`screen_check::drawn_pixels`]) e o
    /// `LOGON_SCREEN_OK` quando mostra a tela de logon em duas leituras
    /// seguidas iguais ([`screen_check::logon_screen`]); num teste que espera
    /// o `DESKTOP_OK` (o marcador ou um `--expect`), procura em vez da tela de
    /// logon a área de trabalho ([`screen_check::desktop_screen`]), só depois
    /// do `EXPLORER_STARTED` na serial; num que espera o `TASKBAR_OK`, depois
    /// da área de trabalho e do `SHELL_TRAY_CREATED`, o relógio da barra de
    /// tarefas passando de minuto ([`taskbar_step`]).
    pub watch_screen: bool,
    /// `--capture-every=SEGUNDOS`: a tela do QEMU vai para `tela-NNNN.png`
    /// na pasta do log a cada intervalo (só quando mudou) e, no fim do teste
    /// (passando ou não), para `tela-final.png` ([`FrameSeries`]).
    pub capture_every: Option<Duration>,
    /// `--send`, `--dismiss` e `--mouse` (repetíveis, na ordem da linha de
    /// comando): a entrada pelo monitor HMP depois de um marcador
    /// ([`InputSend`]).
    pub inputs: Vec<InputSend>,
    /// `--perfil=nmi`: um QMP só para o perfil por amostragem, por onde uma
    /// thread injeta NMIs no convidado durante o teste ([`nmi_pump`]).
    pub nmi_samples: bool,
}

/// Intervalo entre duas leituras da tela.
const SCREEN_POLL: Duration = Duration::from_secs(2);

/// O que o test-boot faz pelo monitor HMP depois de um marcador.
#[derive(Clone, Debug, PartialEq)]
pub enum InputAction {
    /// Teclas na sintaxe do `--keys` ([`key_names`]): `{spc}` é a barra de
    /// espaço; `{combo}` vai cru ao `sendkey`; `{clique}` é o clique do mouse.
    Keys(String),
    /// O mouse PS/2 anda (`dx`, `dy`) pelo `mouse_move`; o test-boot lê a
    /// tela antes e depois e confere que o ponteiro andou
    /// ([`screen_check::cursor_moved`], o `CURSOR_MOVED_OK`).
    Mouse { dx: i32, dy: i32 },
    /// Espera a tela de bloqueio parada, digita as teclas e confere que ela
    /// saiu ([`screen_check::lock_dismissed`], o `LOGON_DISMISS_OK`).
    Dismiss(String),
    /// Espera a área de trabalho com a barra parada, digita as teclas (a
    /// tecla do Windows), confere o menu Iniciar aberto
    /// ([`screen_check::start_menu_open`]) e que o Esc o fecha (o
    /// `START_MENU_OK`).
    StartMenu(String),
    /// Espera a área de trabalho com a barra parada, leva o ponteiro ao
    /// ponto (`x`, `y`) do botão Iniciar ([`point_at`]), aperta o botão
    /// esquerdo, confere o menu Iniciar aberto e que o Esc o fecha (o
    /// `START_MENU_OK`).
    StartClick { x: usize, y: usize },
    /// Leva o ponteiro ao ponto (`x`, `y`) da tela ([`point_at`]), aperta o
    /// botão direito, confere o menu de contexto aberto
    /// ([`screen_check::context_menu_open`]) e que o Esc o fecha (o
    /// `CONTEXT_MENU_OK`).
    ContextMenu { x: usize, y: usize },
    /// Leva o ponteiro a (`x`, `y`) ([`point_at`]), aperta duas vezes o
    /// botão esquerdo e confere a janela nova ([`screen_check::window_opened`],
    /// o `WINDOW_OPENED_OK`).
    DoubleClick { x: usize, y: usize },
    /// Aperta Win+R, espera a caixa Executar, digita o comando e o Enter e
    /// confere a janela do programa sobre a tela de antes do Win+R (o
    /// `WINDOW_OPENED_OK`).
    Run(String),
    /// Digita as teclas (um atalho que abre um programa) e confere a janela
    /// nova (o `WINDOW_OPENED_OK`).
    Open(String),
    /// Digita o texto na janela que tem o foco e confere que ele apareceu
    /// ([`screen_check::text_typed`], o `TEXT_TYPED_OK`).
    Type(String),
    /// Digita o comando no console que tem o foco, confere a linha dele,
    /// aperta Enter e confere a saída ([`screen_check::command_output`], o
    /// `COMMAND_OUTPUT_OK`).
    Command(String),
    /// Espera o disco de dados do convidado parar de gravar
    /// ([`wait_disk_quiet`]), aperta Win+R, espera a caixa Executar, digita o
    /// comando (o shutdown.exe) e o Enter. Não confere janela: o teste espera
    /// o desligamento (o gerador do primeiro logon feito,
    /// `crate::first_logon`).
    Shutdown(String),
}

/// `--send=MARCADOR[+MS]:TECLAS`, `--dismiss=MARCADOR[+MS]:TECLAS` e
/// `--mouse=MARCADOR[+MS]:DX,DY`: a entrada que o test-boot manda pelo
/// monitor HMP `delay` depois de `after`
/// aparecer na serial (o MARCADOR ou um `--expect`), como uma pessoa na
/// frente da máquina: a tecla que dispensa a tela de bloqueio, o mouse que
/// move o ponteiro.
#[derive(Clone, Debug, PartialEq)]
pub struct InputSend {
    pub after: String,
    pub delay: Duration,
    pub action: InputAction,
}

impl InputSend {
    /// O `MARCADOR[+MS]` e o resto de `text`, depois do primeiro `:`.
    fn when<'a>(option: &str, text: &'a str) -> Result<(String, Duration, &'a str), String> {
        let (when, rest) = text.split_once(':').ok_or_else(|| format!("{option}={text}: falta o ':' depois do marcador"))?;
        let (after, delay) = match when.split_once('+') {
            Some((after, ms)) => (after, ms.parse::<u64>().map_err(|_| format!("{option}={text}: atraso invalido ({ms})"))?),
            None => (when, 0),
        };
        if after.is_empty() || rest.is_empty() {
            return Err(format!("{option}={text}: o marcador e o que mandar nao podem ser vazios"));
        }
        Ok((after.to_string(), Duration::from_millis(delay), rest))
    }

    /// `--send=MARCADOR[+MS]:TECLAS`; as teclas são conferidas aqui.
    pub fn keys(text: &str) -> Result<InputSend, String> {
        let (after, delay, keys) = Self::when("--send", text)?;
        key_names(keys)?;
        Ok(InputSend { after, delay, action: InputAction::Keys(keys.to_string()) })
    }

    /// `--dismiss=MARCADOR[+MS]:TECLAS`.
    pub fn dismiss(text: &str) -> Result<InputSend, String> {
        let (after, delay, keys) = Self::when("--dismiss", text)?;
        key_names(keys)?;
        Ok(InputSend { after, delay, action: InputAction::Dismiss(keys.to_string()) })
    }

    /// `--start-menu=MARCADOR[+MS]:TECLAS`.
    pub fn start_menu(text: &str) -> Result<InputSend, String> {
        let (after, delay, keys) = Self::when("--start-menu", text)?;
        key_names(keys)?;
        Ok(InputSend { after, delay, action: InputAction::StartMenu(keys.to_string()) })
    }

    /// `--start-click=MARCADOR[+MS]:X,Y`, o ponto do botão Iniciar na tela
    /// de 1024x768.
    pub fn start_click(text: &str) -> Result<InputSend, String> {
        let (after, delay, point) = Self::when("--start-click", text)?;
        match screen_point(point) {
            Some((x, y)) => Ok(InputSend { after, delay, action: InputAction::StartClick { x, y } }),
            None => Err(format!("--start-click={text}: o ponto e X,Y inteiros dentro da tela de 1024x768")),
        }
    }

    /// `--context-menu=MARCADOR[+MS]:X,Y`, um ponto da tela de 1024x768.
    pub fn context_menu(text: &str) -> Result<InputSend, String> {
        let (after, delay, point) = Self::when("--context-menu", text)?;
        match screen_point(point) {
            Some((x, y)) => Ok(InputSend { after, delay, action: InputAction::ContextMenu { x, y } }),
            None => Err(format!("--context-menu={text}: o ponto e X,Y inteiros dentro da tela de 1024x768")),
        }
    }

    /// `--double-click=MARCADOR[+MS]:X,Y`, um ponto da tela de 1024x768.
    pub fn double_click(text: &str) -> Result<InputSend, String> {
        let (after, delay, point) = Self::when("--double-click", text)?;
        match screen_point(point) {
            Some((x, y)) => Ok(InputSend { after, delay, action: InputAction::DoubleClick { x, y } }),
            None => Err(format!("--double-click={text}: o ponto e X,Y inteiros dentro da tela de 1024x768")),
        }
    }

    /// `--run=MARCADOR[+MS]:COMANDO`; o comando vai na sintaxe do `--keys`.
    pub fn run(text: &str) -> Result<InputSend, String> {
        let (after, delay, command) = Self::when("--run", text)?;
        key_names(command)?;
        Ok(InputSend { after, delay, action: InputAction::Run(command.to_string()) })
    }

    /// `--open=MARCADOR[+MS]:TECLAS`.
    pub fn open(text: &str) -> Result<InputSend, String> {
        let (after, delay, keys) = Self::when("--open", text)?;
        key_names(keys)?;
        Ok(InputSend { after, delay, action: InputAction::Open(keys.to_string()) })
    }

    /// `--type=MARCADOR[+MS]:TEXTO`: letras, algarismos e espaço (o texto que
    /// a conferência conta).
    pub fn type_text(text: &str) -> Result<InputSend, String> {
        let (after, delay, typed) = Self::when("--type", text)?;
        if !typed.chars().all(|character| character.is_ascii_alphanumeric() || character == ' ') {
            return Err(format!("--type={text}: o texto e de letras, algarismos e espacos"));
        }
        Ok(InputSend { after, delay, action: InputAction::Type(typed.to_string()) })
    }

    /// `--command=MARCADOR[+MS]:COMANDO`: letras, algarismos e espaço, como
    /// o `--type`; o Enter vem depois.
    pub fn command(text: &str) -> Result<InputSend, String> {
        let (after, delay, command) = Self::when("--command", text)?;
        if !command.chars().all(|character| character.is_ascii_alphanumeric() || character == ' ') {
            return Err(format!("--command={text}: o comando e de letras, algarismos e espacos"));
        }
        Ok(InputSend { after, delay, action: InputAction::Command(command.to_string()) })
    }

    /// O desligamento pela caixa Executar ([`InputAction::Shutdown`]) logo
    /// depois de `after`.
    pub fn shutdown(after: &str, command: &str) -> InputSend {
        InputSend { after: after.to_string(), delay: Duration::ZERO, action: InputAction::Shutdown(command.to_string()) }
    }

    /// `--mouse=MARCADOR[+MS]:DX,DY`.
    pub fn mouse(text: &str) -> Result<InputSend, String> {
        let (after, delay, motion) = Self::when("--mouse", text)?;
        let parsed = motion.split_once(',').and_then(|(dx, dy)| Some((dx.trim().parse::<i32>().ok()?, dy.trim().parse::<i32>().ok()?)));
        match parsed {
            Some((dx, dy)) if (dx, dy) != (0, 0) && dx.abs() <= 1000 && dy.abs() <= 1000 => Ok(InputSend { after, delay, action: InputAction::Mouse { dx, dy } }),
            _ => Err(format!("--mouse={text}: o movimento e DX,DY inteiros, nao os dois zero, ate 1000 em cada eixo")),
        }
    }
}

/// `X,Y` dentro da tela de 1024x768 do vídeo dos testes.
fn screen_point(text: &str) -> Option<(usize, usize)> {
    let (x, y) = text.split_once(',')?;
    let (x, y) = (x.trim().parse::<usize>().ok()?, y.trim().parse::<usize>().ok()?);
    (x < 1024 && y < 768).then_some((x, y))
}

/// O começo da linha que o test-boot põe na serial depois de mandar as
/// teclas de um `--send`.
pub const KEYS_SENT: &str = "[xtask] teclas enviadas pelo monitor";

/// O tamanho da tela do QEMU (`LARGURAxALTURA`) no texto `opennt-tela` de
/// cada PNG: o PNG pode sair reduzido ([`crate::png::encode_within`]), e as
/// conferências de [`screen_check`] valem na tela inteira; quem confere um PNG
/// de novo o amplia antes, pelo vizinho mais próximo, para este tamanho.
fn native_size(image: &crate::png::Image) -> String {
    format!("{}x{}", image.width, image.height)
}

/// Grava uma captura da tela em `target`, com a descrição nos metadados.
fn save_capture(image: &crate::png::Image, target: &std::path::Path, result: &str, description: &str) {
    let screen = native_size(image);
    let png = crate::png::encode_capture(image, &[("opennt-data", crate::png::today().as_str()), ("opennt-tela", screen.as_str()), ("opennt-resultado", result), ("opennt-serial", description)], CAPTURE_LIMIT);
    if std::fs::write(target, &png).is_ok() {
        println!("[xtask] {result}: {}", target.display());
    }
}

/// O estado da vigia da tela (`--watch-screen`).
#[derive(Default)]
struct Watch {
    /// A primeira tela desenhada já apareceu (`FIRST_PIXEL_OK`).
    first_seen: bool,
    /// A leitura anterior, quando ela passou na conferência da tela de
    /// logon: a tela de logon só conta em duas leituras seguidas iguais
    /// ([`screen_check::same_screen`]).
    candidate: Option<crate::png::Image>,
    /// A tela de logon confirmada (`LOGON_SCREEN_OK`).
    logon: Option<crate::png::Image>,
    /// O `LOGONUI_STARTED` já apareceu na serial: antes dele nenhuma tela é
    /// a de logon.
    logonui_seen: bool,
    /// O teste espera o `DESKTOP_OK`: a vigia procura a área de trabalho
    /// em vez da tela de logon.
    wants_desktop: bool,
    /// O `EXPLORER_STARTED` já apareceu na serial.
    explorer_seen: bool,
    /// A leitura anterior, quando ela passou na conferência da área de
    /// trabalho.
    desktop_candidate: Option<crate::png::Image>,
    /// A área de trabalho confirmada (`DESKTOP_OK`).
    desktop: Option<crate::png::Image>,
    /// O teste espera o `TASKBAR_OK`: depois da área de trabalho, a vigia
    /// procura o relógio da barra de tarefas passando de minuto.
    wants_taskbar: bool,
    /// O `SHELL_TRAY_CREATED` já apareceu na serial.
    tray_seen: bool,
    /// A leitura de referência da barra (com a disposição achada nela) e a
    /// leitura com o relógio no minuto seguinte, à espera da confirmação.
    taskbar_reference: Option<(crate::png::Image, screen_check::TaskbarLayout)>,
    taskbar_candidate: Option<crate::png::Image>,
    /// A barra de tarefas confirmada (`TASKBAR_OK`).
    taskbar: Option<crate::png::Image>,
    /// O teste espera o `SHELL_RESTARTED`: depois da área de trabalho (e da
    /// barra, se o teste a espera), a vigia confirma de novo a área de
    /// trabalho, com o shell recriado ([`restart_step`]).
    wants_restart: bool,
    /// O `SHELL_RESTARTED` já apareceu na serial.
    restart_seen: bool,
    /// A leitura anterior, quando ela passou na conferência da área de
    /// trabalho depois do `SHELL_RESTARTED`.
    restart_candidate: Option<crate::png::Image>,
    /// A área de trabalho de volta, confirmada (o segundo `DESKTOP_OK`).
    restarted: Option<crate::png::Image>,
}

/// Um passo da vigia da tela (`--watch-screen`) sobre `image`. Na primeira
/// tela com pixels desenhados escreve a descrição e o `FIRST_PIXEL_OK` no
/// log da serial e grava o PNG em `first`; depois, só com o
/// `LOGONUI_STARTED` na serial ([`screen_check::LOGON_AFTER`]), procura a
/// tela de logon ([`screen_check::logon_screen`]). Quando duas leituras seguidas passam e
/// são a mesma tela, a segunda sai com o `LOGON_SCREEN_OK`, vai para
/// `tela-de-logon.png`, ao lado, e fica em `watch.logon`. Devolve true
/// quando a vigia acabou (a tela de logon apareceu). Num teste da área de
/// trabalho ([`Watch::wants_desktop`]), depois do primeiro pixel vai a
/// [`desktop_step`] em vez da tela de logon; com o `SHELL_RESTARTED`
/// esperado ([`Watch::wants_restart`]), a vigia só acaba com a área de
/// trabalho de volta ([`restart_step`]).
fn watch_step(image: &crate::png::Image, first: &Path, watch: &mut Watch, output: &Mutex<String>) -> bool {
    if !watch.first_seen {
        let Some(description) = screen_check::drawn_pixels(image) else { return false };
        watch.first_seen = true;
        let line = format!("\n[xtask] tela: {description}\n{FIRST_PIXEL_MARKER}\n");
        print!("{line}");
        output.lock().unwrap().push_str(&line);
        save_capture(image, first, "primeira tela desenhada", &description);
    }
    if watch.wants_restart && watch.desktop.is_some() && (!watch.wants_taskbar || watch.taskbar.is_some()) {
        return restart_step(image, first, watch, output);
    }
    if watch.wants_taskbar && watch.desktop.is_some() {
        return taskbar_step(image, first, watch, output) && !watch.wants_restart;
    }
    if watch.wants_desktop {
        return desktop_step(image, first, watch, output);
    }
    if !watch.logonui_seen {
        watch.logonui_seen = output.lock().unwrap().contains(screen_check::LOGON_AFTER);
        if !watch.logonui_seen {
            return false;
        }
    }
    let Ok(description) = screen_check::logon_screen(image) else {
        watch.candidate = None;
        return false;
    };
    if !watch.candidate.as_ref().is_some_and(|previous| screen_check::same_screen(previous, image)) {
        watch.candidate = Some(image.clone());
        return false;
    }
    let line = format!("\n[xtask] tela de logon (igual em duas leituras seguidas): {description}\n{LOGON_SCREEN_MARKER}\n");
    print!("{line}");
    output.lock().unwrap().push_str(&line);
    save_capture(image, &first.with_file_name("tela-de-logon.png"), "tela de logon", &description);
    watch.candidate = None;
    watch.logon = Some(image.clone());
    true
}

/// A área de trabalho na vigia de um teste que espera o `DESKTOP_OK`
/// ([`screen_check::desktop_screen`]), só depois do `EXPLORER_STARTED` na
/// serial: duas leituras seguidas que passam e são a mesma tela põem no
/// log a descrição e o `DESKTOP_OK`, e a segunda vai para
/// `area-de-trabalho.png`, ao lado de `first`, e fica em `watch.desktop`.
/// Devolve true quando a área de trabalho apareceu e o teste não espera
/// também a barra de tarefas ([`taskbar_step`]).
fn desktop_step(image: &crate::png::Image, first: &Path, watch: &mut Watch, output: &Mutex<String>) -> bool {
    if !watch.explorer_seen {
        watch.explorer_seen = output.lock().unwrap().contains(DESKTOP_AFTER);
        if !watch.explorer_seen {
            return false;
        }
    }
    let Ok(description) = screen_check::desktop_screen(image) else {
        watch.desktop_candidate = None;
        return false;
    };
    if !watch.desktop_candidate.as_ref().is_some_and(|previous| screen_check::same_screen(previous, image)) {
        watch.desktop_candidate = Some(image.clone());
        return false;
    }
    let line = format!("\n[xtask] area de trabalho (igual em duas leituras seguidas): {description}\n{DESKTOP_MARKER}\n");
    print!("{line}");
    output.lock().unwrap().push_str(&line);
    save_capture(image, &first.with_file_name("area-de-trabalho.png"), "area de trabalho", &description);
    watch.desktop_candidate = None;
    watch.desktop = Some(image.clone());
    !watch.wants_taskbar && !watch.wants_restart
}

/// A área de trabalho de volta, num teste que espera o `SHELL_RESTARTED`
/// ([`RESTART_AFTER`]): depois da área de trabalho confirmada (e da barra,
/// se o teste a espera), o explorer.exe sai e o winlogon.exe o recria. A
/// vigia espera o marcador na serial (a barra de tarefas do explorer novo
/// já existe); a leitura em que ele aparece pode ser de antes dele e não
/// conta. Depois, a mesma conferência da primeira
/// ([`screen_check::desktop_screen`]): duas leituras seguidas que passam e
/// são a mesma tela põem no log a descrição e o `DESKTOP_OK` de novo, e a
/// segunda vai para `area-de-trabalho-reiniciada.png`, ao lado de `first`,
/// e fica em `watch.restarted`. A barra do explorer que saiu já foi
/// destruída quando o novo cria a dele, então ela não passa por esta.
/// Devolve true quando a área de trabalho voltou.
fn restart_step(image: &crate::png::Image, first: &Path, watch: &mut Watch, output: &Mutex<String>) -> bool {
    if !watch.restart_seen {
        watch.restart_seen = output.lock().unwrap().contains(RESTART_AFTER);
        watch.restart_candidate = None;
        return false;
    }
    let Ok(description) = screen_check::desktop_screen(image) else {
        watch.restart_candidate = None;
        return false;
    };
    if !watch.restart_candidate.as_ref().is_some_and(|previous| screen_check::same_screen(previous, image)) {
        watch.restart_candidate = Some(image.clone());
        return false;
    }
    let line = format!("\n[xtask] area de trabalho de volta depois do {RESTART_AFTER} (igual em duas leituras seguidas): {description}\n{DESKTOP_MARKER}\n");
    print!("{line}");
    output.lock().unwrap().push_str(&line);
    save_capture(image, &first.with_file_name("area-de-trabalho-reiniciada.png"), "area de trabalho de volta", &description);
    watch.restart_candidate = None;
    watch.restarted = Some(image.clone());
    true
}

/// A barra de tarefas na vigia de um teste que espera o `TASKBAR_OK`, depois
/// do `DESKTOP_OK` e do `SHELL_TRAY_CREATED` na serial: uma leitura com a
/// barra ([`screen_check::taskbar_layout`]) vira a referência; o
/// `TASKBAR_OK` sai quando uma leitura seguinte mostra o relógio no minuto
/// seguinte com o resto parado ([`screen_check::clock_ticked`]) e a leitura
/// depois dela é igual. Uma leitura sem a barra recomeça; uma que mudou sem
/// ser o minuto vira a referência nova. A tela vai para
/// `barra-de-tarefas.png`, ao lado de `first`. Devolve true quando a barra
/// foi confirmada.
fn taskbar_step(image: &crate::png::Image, first: &Path, watch: &mut Watch, output: &Mutex<String>) -> bool {
    if !watch.tray_seen {
        watch.tray_seen = output.lock().unwrap().contains(TASKBAR_AFTER);
        if !watch.tray_seen {
            return false;
        }
    }
    let Ok(layout) = screen_check::taskbar_layout(image) else {
        (watch.taskbar_reference, watch.taskbar_candidate) = (None, None);
        return false;
    };
    let Some((reference, reference_layout)) = &watch.taskbar_reference else {
        watch.taskbar_reference = Some((image.clone(), layout));
        return false;
    };
    match screen_check::clock_ticked(reference, image, reference_layout) {
        Ok(tick) => {
            if !watch.taskbar_candidate.as_ref().is_some_and(|previous| screen_check::same_screen(previous, image)) {
                watch.taskbar_candidate = Some(image.clone());
                return false;
            }
            let description = layout.describe();
            let line = format!("\n[xtask] barra de tarefas (igual em duas leituras seguidas): {description}; {tick}\n{TASKBAR_MARKER}\n");
            print!("{line}");
            output.lock().unwrap().push_str(&line);
            save_capture(image, &first.with_file_name("barra-de-tarefas.png"), "barra de tarefas", &format!("{description}; {tick}"));
            watch.taskbar = Some(image.clone());
            true
        }
        Err(_) if !screen_check::same_screen(reference, image) => {
            (watch.taskbar_reference, watch.taskbar_candidate) = (Some((image.clone(), layout)), None);
            false
        }
        Err(_) => false,
    }
}

/// O que a thread da tela devolve no fim.
#[derive(Default)]
struct ScreenOutcome {
    /// A última tela lida.
    last: Option<crate::png::Image>,
    /// A série do `--capture-every`.
    frames: Option<FrameSeries>,
    /// A tela de logon que a vigia confirmou.
    logon: Option<crate::png::Image>,
    /// A área de trabalho que a vigia confirmou.
    desktop: Option<crate::png::Image>,
    /// A barra de tarefas que a vigia confirmou.
    taskbar: Option<crate::png::Image>,
    /// A área de trabalho de volta depois do `SHELL_RESTARTED`.
    restarted: Option<crate::png::Image>,
}

/// O passo da espera da thread da tela: o fim do teste a encontra em até
/// tanto.
const SCREEN_STEP: Duration = Duration::from_millis(100);

/// A thread da tela. O QMP atende um cliente por vez, então uma thread só
/// faz as duas leituras periódicas: a vigia (`watch`, o PNG da primeira
/// tela desenhada e se o teste espera a área de trabalho, a barra de
/// tarefas ou a área de trabalho de volta depois do shell recriado, a cada
/// [`SCREEN_POLL`]) e a série do `--capture-every`
/// (`frames`); quando as duas vencem juntas, uma leitura serve às duas. Os
/// prazos contam de `launched` (a subida do QEMU). Devolve a última tela
/// lida, a série e a tela de logon confirmada.
fn screen_thread(
    port: u16,
    scratch: PathBuf,
    launched: Instant,
    watch: Option<(PathBuf, bool, bool, bool)>,
    mut frames: Option<FrameSeries>,
    output: Arc<Mutex<String>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> ScreenOutcome {
    use std::sync::atomic::Ordering;
    let (wants_desktop, wants_taskbar, wants_restart) = watch.as_ref().map_or((false, false, false), |(_, desktop, taskbar, restart)| (*desktop || *taskbar || *restart, *taskbar, *restart));
    let mut state = Watch { wants_desktop, wants_taskbar, wants_restart, ..Watch::default() };
    let mut watch_at = watch.is_some().then_some(SCREEN_POLL);
    let mut frame = frames.as_ref().map(|series| series.next_index(Duration::ZERO));
    let mut last = None;
    'screen: loop {
        let frame_at = frame.zip(frames.as_ref()).map(|(index, series)| series.due(index));
        let Some(due) = [watch_at, frame_at].into_iter().flatten().min() else { break };
        loop {
            if stop.load(Ordering::Acquire) {
                break 'screen;
            }
            let remaining = due.saturating_sub(launched.elapsed());
            if remaining.is_zero() {
                break;
            }
            thread::sleep(remaining.min(SCREEN_STEP));
        }
        let screen = read_screen(port, &scratch);
        let elapsed = launched.elapsed();
        if watch_at.is_some_and(|at| at <= elapsed) {
            watch_at = Some(elapsed + SCREEN_POLL);
            if let (Ok(image), Some((first, _, _, _))) = (&screen, &watch) {
                if watch_step(image, first, &mut state, &output) {
                    watch_at = None;
                }
            }
        }
        if let (Some(index), Some(series)) = (frame, frames.as_mut()) {
            if series.due(index) <= elapsed {
                if let Ok(image) = &screen {
                    match series.offer(index, elapsed, image, &serial_tail(&output)) {
                        Ok(Some(path)) => println!("\n[xtask] tela aos {:.1} s: {}", elapsed.as_secs_f64(), path.display()),
                        Ok(None) => {}
                        Err(error) => eprintln!("aviso: tela {index} nao gravada: {error}"),
                    }
                }
                frame = Some(series.next_index(launched.elapsed()));
            }
        }
        if let Ok(image) = screen {
            last = Some(image);
        }
    }
    ScreenOutcome { last, frames, logon: state.logon, desktop: state.desktop, taskbar: state.taskbar, restarted: state.restarted }
}

/// Limite de tamanho de uma captura (a tela gráfica é reduzida até caber).
const CAPTURE_LIMIT: usize = 60 * 1024;

/// Limite de tamanho de uma tela do `--capture-every`. A tela vai inteira,
/// sem cortar a moldura (as telas da série se comparam lado a lado); só a
/// que passa disto (uma foto de fundo) é reduzida pela metade.
const FRAME_LIMIT: usize = 256 * 1024;
/// A tela do fim do teste com `--capture-every`.
pub const FINAL_FRAME: &str = "tela-final.png";

/// As telas do `--capture-every`: `tela-NNNN.png` na pasta do log, onde
/// NNNN conta os intervalos desde a subida do QEMU (com
/// `--capture-every=5`, a `tela-0003.png` é a dos 15 s). Uma tela igual à
/// última gravada não é gravada de novo: o número que falta na sequência é
/// uma tela que não mudou (ou uma leitura que não coube no intervalo). Cada
/// PNG leva nos textos a hora da leitura (`opennt-tempo`) e as últimas
/// linhas da serial naquele instante (`opennt-serial`).
pub struct FrameSeries {
    directory: PathBuf,
    every: Duration,
    previous: Option<crate::png::Image>,
    saved: u64,
    repeated: u64,
}

impl FrameSeries {
    /// A série em `directory`, sem as telas de uma execução anterior.
    pub fn new(directory: &Path, every: Duration) -> Self {
        remove_frames(directory);
        FrameSeries { directory: directory.to_path_buf(), every, previous: None, saved: 0, repeated: 0 }
    }

    /// O nome do PNG da tela `index`.
    pub fn name(index: u64) -> String {
        format!("tela-{index:04}.png")
    }

    /// A próxima tela depois de `elapsed` desde a subida do QEMU.
    pub fn next_index(&self, elapsed: Duration) -> u64 {
        (elapsed.as_nanos() / self.every.as_nanos().max(1)) as u64 + 1
    }

    /// Quando a tela `index` vence, contado da subida do QEMU.
    pub fn due(&self, index: u64) -> Duration {
        u32::try_from(index).ok().and_then(|index| self.every.checked_mul(index)).unwrap_or(Duration::MAX)
    }

    /// Grava a tela `index`, lida `elapsed` depois da subida do QEMU, a não
    /// ser que seja igual à última gravada; `serial` vai nos textos do PNG.
    /// Devolve o PNG gravado.
    pub fn offer(&mut self, index: u64, elapsed: Duration, image: &crate::png::Image, serial: &str) -> Result<Option<PathBuf>, String> {
        if self.previous.as_ref() == Some(image) {
            self.repeated += 1;
            return Ok(None);
        }
        let target = self.directory.join(Self::name(index));
        let (date, time, screen) = (crate::png::today(), seconds(elapsed), native_size(image));
        let png = crate::png::encode_within(image, &[("opennt-data", date.as_str()), ("opennt-tela", screen.as_str()), ("opennt-tempo", time.as_str()), ("opennt-serial", serial)], FRAME_LIMIT);
        std::fs::write(&target, &png).map_err(|error| format!("{}: {error}", target.display()))?;
        self.previous = Some(image.clone());
        self.saved += 1;
        Ok(Some(target))
    }

    /// A linha do resumo do fim do teste.
    pub fn summary(&self) -> String {
        format!("{} tela(s) gravada(s) em {} ({} igual(is) a anterior nao gravada(s))", self.saved, self.directory.display(), self.repeated)
    }
}

/// Um nome de arquivo de uma série do `--capture-every`: `tela-NNNN.png`
/// (quatro dígitos ou mais) ou `tela-final.png`.
fn is_frame(name: &str) -> bool {
    let Some(middle) = name.strip_prefix("tela-").and_then(|rest| rest.strip_suffix(".png")) else { return false };
    middle == "final" || (middle.len() >= 4 && middle.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Apaga de `directory` as telas de uma série anterior, para a nova não se
/// misturar com ela.
fn remove_frames(directory: &Path) {
    let Ok(entries) = std::fs::read_dir(directory) else { return };
    for entry in entries.flatten() {
        if entry.file_name().to_str().is_some_and(is_frame) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// `12.3 s`.
fn seconds(elapsed: Duration) -> String {
    format!("{:.1} s", elapsed.as_secs_f64())
}

/// As últimas linhas da serial ([`serial_proof`] sem saídas esperadas),
/// tiradas só do fim do log.
fn serial_tail(output: &Mutex<String>) -> String {
    const WINDOW: usize = 16 * 1024;
    let text = output.lock().unwrap();
    let mut start = text.len().saturating_sub(WINDOW);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    serial_proof(&text[start..], &[])
}

/// O resultado do teste nos textos de uma captura.
fn outcome(result: &Result<(), String>) -> String {
    match result {
        Ok(()) => "passou".to_string(),
        Err(error) => format!("falhou: {error}"),
    }
}

/// A tela do fim do `--capture-every` em `target`: lida agora se o QEMU
/// ainda roda, senão (ou se a leitura falhar) a última que a thread da tela
/// leu; com o resultado do teste, a hora e as linhas da serial que provam o
/// teste nos textos.
fn final_frame(
    port: u16,
    target: &Path,
    alive: bool,
    last: Option<crate::png::Image>,
    result: &Result<(), String>,
    serial: &str,
    elapsed: Duration,
) -> Result<(), String> {
    let fresh = if alive { read_screen(port, &target.with_extension("ppm")) } else { Err("o QEMU ja tinha terminado".to_string()) };
    let (image, origin) = match (fresh, last) {
        (Ok(image), _) => (image, "lida no fim do teste"),
        (Err(_), Some(image)) => (image, "a ultima lida durante o teste"),
        (Err(error), None) => return Err(error),
    };
    let (date, outcome, time, screen) = (crate::png::today(), outcome(result), seconds(elapsed), native_size(&image));
    let texts = [("opennt-data", date.as_str()), ("opennt-tela", screen.as_str()), ("opennt-resultado", outcome.as_str()), ("opennt-tempo", time.as_str()), ("opennt-origem", origin), ("opennt-serial", serial)];
    let png = crate::png::encode_within(&image, &texts, FRAME_LIMIT);
    std::fs::write(target, &png).map_err(|error| format!("{}: {error}", target.display()))?;
    println!("[xtask] tela final ({origin}, {}x{}, {} bytes): {}", image.width, image.height, png.len(), target.display());
    Ok(())
}

/// A tela do QEMU agora: o `screendump` do QMP em `ppm`, apagado depois da
/// leitura.
fn read_screen(port: u16, ppm: &Path) -> Result<crate::png::Image, String> {
    qmp_screendump(port, ppm)?;
    let bytes = std::fs::read(ppm).map_err(|error| format!("{}: {error}", ppm.display()));
    let _ = std::fs::remove_file(ppm);
    crate::png::read_ppm(&bytes?)
}

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

/// Intervalo entre duas NMIs do perfil por amostragem.
const NMI_PERIOD: Duration = Duration::from_millis(2);

/// A linha do kernel que liga a NMI do perfil (`kd/sampler.rs`): antes dela
/// uma NMI cai no caminho das exceções do kernel (ou, antes da IDT, numa
/// falta tripla).
const NMI_READY: &str = "[perfil] amostragem pela NMI";

/// As NMIs do `--perfil=nmi`: o `inject-nmi` pelo QMP dedicado a cada
/// [`NMI_PERIOD`] (sem relação com o relógio do convidado), da linha
/// [`NMI_READY`] na serial até `stop`.
fn nmi_pump(port: u16, serial: Arc<Mutex<String>>, stop: Arc<std::sync::atomic::AtomicBool>) {
    let running = || !stop.load(std::sync::atomic::Ordering::Acquire);
    while !serial.lock().unwrap().contains(NMI_READY) {
        if !running() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let stream = loop {
        if !running() {
            return;
        }
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => break stream,
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let Ok(mut writer) = stream.try_clone() else { return };
    let mut reader = std::io::BufReader::new(stream);
    let mut greeting = String::new();
    if std::io::BufRead::read_line(&mut reader, &mut greeting).is_err() || writer.write_all(b"{\"execute\":\"qmp_capabilities\"}\n").is_err() || qmp_reply(&mut reader).is_err() {
        return;
    }
    let mut sent = 0u64;
    while running() {
        if writer.write_all(b"{\"execute\":\"inject-nmi\"}\n").is_err() || qmp_reply(&mut reader).is_err() {
            break;
        }
        sent += 1;
        thread::sleep(NMI_PERIOD);
    }
    println!("\n[xtask] perfil: {sent} NMIs injetadas");
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

/// A captura do fim do teste: PPM do QEMU -> PNG pequeno ([`write_capture`]).
fn capture_screen(port: u16, target: &Path, result: &Result<(), String>, serial: &str) -> Result<(), String> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    let image = read_screen(port, &target.with_extension("ppm"))?;
    write_capture(&image, target, result, serial)
}

/// A captura de um teste em `target`: PNG pequeno, com a data, o resultado
/// e as linhas da serial que provam o teste nos textos do PNG (o `cargo
/// xtask status` os mostra).
fn write_capture(image: &crate::png::Image, target: &Path, result: &Result<(), String>, serial: &str) -> Result<(), String> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    let outcome = outcome(result);
    let (date, screen) = (crate::png::today(), native_size(image));
    let texts = [("opennt-data", date.as_str()), ("opennt-tela", screen.as_str()), ("opennt-resultado", outcome.as_str()), ("opennt-serial", serial)];
    let png = crate::png::encode_capture(image, &texts, CAPTURE_LIMIT);
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

/// Os nomes de tecla (o QKeyCode) que o `sendkey` do HMP do QEMU 11 aceita
/// num `{combo}`: o monitor responde `invalid parameter` a qualquer outro, e
/// essa resposta é descartada ([`connect_monitor`]), então um nome errado
/// (`{win}`; a tecla do Windows é `meta_l`) não faria nada e o teste só
/// esgotaria o prazo. Conferidos um a um no `sendkey` do QEMU desta máquina
/// (`altgr` não existe nele: o AltGr é o `alt_r`).
const QEMU_KEYS: &[&str] = &[
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1",
    "2", "3", "4", "5", "6", "7", "8", "9", "shift", "shift_r", "alt", "alt_r", "ctrl", "ctrl_r", "meta_l", "meta_r", "menu", "compose", "esc",
    "ret", "spc", "tab", "backspace", "delete", "insert", "home", "end", "pgup", "pgdn", "up", "down", "left", "right", "f1", "f2", "f3", "f4",
    "f5", "f6", "f7", "f8", "f9", "f10", "f11", "f12", "print", "sysrq", "scroll_lock", "pause", "caps_lock", "num_lock", "minus", "equal",
    "bracket_left", "bracket_right", "semicolon", "apostrophe", "grave_accent", "backslash", "comma", "dot", "slash", "less", "asterisk",
    "kp_0", "kp_1", "kp_2", "kp_3", "kp_4", "kp_5", "kp_6", "kp_7", "kp_8", "kp_9", "kp_enter", "kp_add", "kp_subtract", "kp_multiply",
    "kp_divide", "kp_decimal",
];

/// Confere as teclas de `text` na sintaxe do `--keys` ([`key_names`]).
pub fn check_keys(text: &str) -> Result<(), String> {
    key_names(text).map(|_| ())
}

/// Os nomes do `sendkey` de `text`: cada caractere pelo [`key_name`];
/// `{combo}` vai cru (nomes de tecla do QEMU, [`QEMU_KEYS`], separados por
/// `-`, pressionados em ordem e soltos ao contrário, como
/// `{ctrl_r-scroll_lock-scroll_lock}` ou `{spc}`). `{clique}` ([`CLICK`]) é o
/// clique do botão esquerdo do mouse onde o ponteiro estiver.
fn key_names(text: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        names.push(if character == '{' {
            let combo: String = characters.by_ref().take_while(|&next| next != '}').collect();
            if combo.is_empty() || !combo.chars().all(|next| next.is_ascii_alphanumeric() || next == '_' || next == '-') {
                return Err(format!("combo de teclas invalido: {{{combo}}}"));
            }
            if combo != CLICK {
                if let Some(part) = combo.split('-').find(|part| !QEMU_KEYS.contains(part)) {
                    return Err(format!("tecla desconhecida do QEMU: {part} em {{{combo}}} (a tecla do Windows e meta_l)"));
                }
            }
            combo
        } else {
            key_name(character).ok_or_else(|| format!("tecla sem mapa no sendkey: {character:?}"))?
        });
    }
    Ok(names)
}

/// O nome que [`type_keys`] manda como clique do mouse (o `mouse_button 1`
/// e o `mouse_button 0` do HMP), não como tecla: o QEMU não tem tecla com
/// esse nome.
const CLICK: &str = "clique";

/// Digita `text` ([`key_names`]): cada tecla presa 30 ms, 70 ms entre elas;
/// o [`CLICK`] aperta e solta o botão esquerdo do mouse.
fn type_keys(monitor: &mut TcpStream, text: &str) -> Result<(), String> {
    let mut send = |command: String| monitor.write_all(command.as_bytes()).map_err(|error| format!("monitor HMP: {error}"));
    for name in key_names(text)? {
        if name == CLICK {
            send("mouse_button 1\n".into())?;
            thread::sleep(Duration::from_millis(50));
            send("mouse_button 0\n".into())?;
        } else {
            send(format!("sendkey {name} 30\n"))?;
        }
        thread::sleep(Duration::from_millis(70));
    }
    Ok(())
}

/// Quantos `mouse_move` um movimento do `--mouse` leva: o mouse anda aos
/// poucos, como a mão, em vez de um salto num pacote só.
const MOUSE_STEPS: i32 = 10;
/// Quanto o `--mouse` espera o ponteiro andar na tela.
const MOUSE_WAIT: Duration = Duration::from_secs(15);

/// A tela do QEMU pelo `screendump` do monitor HMP (a vigia da tela ocupa o
/// QMP): espera o arquivo ficar inteiro e o lê.
fn hmp_screen(monitor: &mut TcpStream, ppm: &Path) -> Result<crate::png::Image, String> {
    let _ = std::fs::remove_file(ppm);
    let file = ppm.display().to_string().replace('\\', "/");
    monitor.write_all(format!("screendump {file}\n").as_bytes()).map_err(|error| format!("monitor HMP: {error}"))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        thread::sleep(Duration::from_millis(100));
        if let Ok(image) = std::fs::read(ppm).map_err(|error| error.to_string()).and_then(|bytes| crate::png::read_ppm(&bytes)) {
            let _ = std::fs::remove_file(ppm);
            return Ok(image);
        }
        if Instant::now() > deadline {
            return Err(format!("screendump do monitor HMP nao gravou {}", ppm.display()));
        }
    }
}

/// Quanto a entrada espera uma tela parada antes de agir.
const STILL_WAIT: Duration = Duration::from_secs(180);

/// A tela parada que passa em `check`: duas leituras seguidas, a
/// [`SCREEN_POLL`] uma da outra, iguais ([`screen_check::same_screen`]) e
/// aprovadas, por até `wait`. Devolve a segunda, ou o que faltou na última.
fn still_screen(monitor: &mut TcpStream, ppm: &Path, wait: Duration, check: impl Fn(&crate::png::Image) -> Result<String, String>) -> Result<crate::png::Image, String> {
    let deadline = Instant::now() + wait;
    let mut previous: Option<crate::png::Image> = None;
    loop {
        let image = hmp_screen(monitor, ppm)?;
        let verdict = check(&image);
        if verdict.is_ok() && previous.as_ref().is_some_and(|previous| screen_check::same_screen(previous, &image)) {
            return Ok(image);
        }
        if Instant::now() > deadline {
            return Err(verdict.err().unwrap_or_else(|| "a tela nao parou em duas leituras seguidas".into()));
        }
        previous = verdict.is_ok().then_some(image);
        thread::sleep(SCREEN_POLL);
    }
}

/// O `--dismiss`: espera a tela de bloqueio parada
/// ([`screen_check::lock_screen_shown`], por até [`STILL_WAIT`]), digita as
/// teclas (a hora vai para `sent`) e lê a tela até ela sair e a seguinte parar
/// ([`screen_check::lock_dismissed`] em duas leituras seguidas iguais), por
/// até [`DISMISS_WAIT`]. Devolve o que mudou, ou o que faltou.
fn dismiss_lock(monitor: &mut TcpStream, ppm: &Path, keys: &str, sent: &mut Option<Instant>) -> Result<String, String> {
    let before = still_screen(monitor, ppm, STILL_WAIT, screen_check::lock_screen_shown).map_err(|missing| format!("a tela de bloqueio nao apareceu: {missing}"))?;
    *sent = Some(Instant::now());
    type_keys(monitor, keys)?;
    let after = still_screen(monitor, ppm, DISMISS_WAIT, |image| screen_check::lock_dismissed(&before, image))?;
    screen_check::lock_dismissed(&before, &after)
}

/// Quanto o `--dismiss` espera a tela de bloqueio sair depois da tecla (ela
/// sobe numa animação).
const DISMISS_WAIT: Duration = Duration::from_secs(60);

/// Quanto o `--start-menu` espera o menu abrir e fechar (o pacote sai do
/// congelamento e desenha a primeira vez no WARP).
const START_MENU_WAIT: Duration = Duration::from_secs(60);

/// O `--start-menu`: espera a área de trabalho com a barra parada
/// ([`screen_check::taskbar_screen`], por até [`STILL_WAIT`]), digita as
/// teclas (a tecla do Windows, `{meta_l}`; a hora vai para `sent`) e confere
/// o menu aberto e fechado ([`start_menu_shown`]). Devolve o menu achado, ou
/// o que faltou.
fn open_start_menu(monitor: &mut TcpStream, ppm: &Path, keys: &str, sent: &mut Option<Instant>) -> Result<String, String> {
    let before = still_screen(monitor, ppm, STILL_WAIT, screen_check::taskbar_screen).map_err(|missing| format!("a area de trabalho com a barra nao parou: {missing}"))?;
    *sent = Some(Instant::now());
    type_keys(monitor, keys)?;
    let rows = screen_check::taskbar_layout(&before)?.rows;
    start_menu_shown(monitor, ppm, &before, rows, "da tecla")
}

/// O `--start-click`: espera a área de trabalho com a barra parada, leva o
/// ponteiro a (`x`, `y`) ([`point_at`]), o botão Iniciar, espera a tela
/// parada com ele lá (a tela de antes, com o botão sob o ponteiro), aperta e
/// solta o botão esquerdo (a hora vai para `sent`) e confere o menu aberto e
/// fechado ([`start_menu_shown`]). Devolve o menu achado, ou o que faltou.
fn click_start_menu(monitor: &mut TcpStream, ppm: &Path, x: usize, y: usize, sent: &mut Option<Instant>) -> Result<String, String> {
    let bar = still_screen(monitor, ppm, STILL_WAIT, screen_check::taskbar_screen).map_err(|missing| format!("a area de trabalho com a barra nao parou: {missing}"))?;
    let rows = screen_check::taskbar_layout(&bar)?.rows;
    let (px, py) = point_at(monitor, ppm, x, y)?;
    // Com o ponteiro sobre o logotipo, a leitura da barra o mediria junto:
    // a barra fica medida de antes, e basta a tela desenhada e parada (o
    // botão já com o realce do mouse).
    let before = still_screen(monitor, ppm, STILL_WAIT, screen_check::drawn_screen).map_err(|missing| format!("a area de trabalho com o ponteiro no botao Iniciar nao parou: {missing}"))?;
    *sent = Some(Instant::now());
    monitor.write_all(b"mouse_button 1\n").map_err(|error| format!("monitor HMP: {error}"))?;
    thread::sleep(Duration::from_millis(60));
    monitor.write_all(b"mouse_button 0\n").map_err(|error| format!("monitor HMP: {error}"))?;
    let shown = start_menu_shown(monitor, ppm, &before, rows, "do clique")?;
    Ok(format!("clique em ({px},{py}): {shown}"))
}

/// Depois da tecla ou do clique sobre `before`, com a barra de `rows`
/// linhas: espera o menu aberto e parado
/// ([`screen_check::start_menu_open_over`]), aperta o Esc e espera a tela
/// de antes de volta ([`screen_check::same_screen`]), cada espera por até
/// [`START_MENU_WAIT`]. Devolve o menu achado, ou o que faltou.
fn start_menu_shown(monitor: &mut TcpStream, ppm: &Path, before: &crate::png::Image, rows: usize, what: &str) -> Result<String, String> {
    let open = still_screen(monitor, ppm, START_MENU_WAIT, |image| screen_check::start_menu_open_over(rows, before, image)).map_err(|missing| format!("o menu Iniciar nao abriu: {missing}"))?;
    let opened = screen_check::start_menu_open_over(rows, before, &open)?;
    type_keys(monitor, "{esc}")?;
    let back = |image: &crate::png::Image| if screen_check::same_screen(before, image) { Ok(String::new()) } else { Err(format!("a tela nao voltou a de antes {what}")) };
    still_screen(monitor, ppm, START_MENU_WAIT, back).map_err(|missing| format!("o menu Iniciar abriu ({opened}), mas nao fechou com o Esc: {missing}"))?;
    Ok(format!("{opened}; fechou com o Esc"))
}

/// O `--mouse`: espera a tela desenhada parada
/// ([`screen_check::drawn_screen`], por até [`STILL_WAIT`]), anda o mouse
/// PS/2 (`dx`, `dy`) em [`MOUSE_STEPS`] `mouse_move` (a hora vai para
/// `sent`) e lê a tela de novo até o ponteiro ter andado
/// ([`screen_check::cursor_moved`]), por até [`MOUSE_WAIT`]. Devolve de onde para onde ele foi, ou o que faltou na
/// última leitura.
fn move_mouse(monitor: &mut TcpStream, ppm: &Path, dx: i32, dy: i32, sent: &mut Option<Instant>) -> Result<String, String> {
    let before = still_screen(monitor, ppm, STILL_WAIT, screen_check::drawn_screen)?;
    *sent = Some(Instant::now());
    for step in 0..MOUSE_STEPS {
        // Os passos somam o movimento inteiro, com o resto da divisão
        // distribuído.
        let part = |total: i32| total * (step + 1) / MOUSE_STEPS - total * step / MOUSE_STEPS;
        monitor.write_all(format!("mouse_move {} {}\n", part(dx), part(dy)).as_bytes()).map_err(|error| format!("monitor HMP: {error}"))?;
        thread::sleep(Duration::from_millis(20));
    }
    let deadline = Instant::now() + MOUSE_WAIT;
    loop {
        thread::sleep(Duration::from_millis(500));
        let after = hmp_screen(monitor, ppm)?;
        match screen_check::cursor_moved(&before, &after, dx, dy) {
            Ok(description) => return Ok(description),
            Err(missing) if Instant::now() > deadline => return Err(missing),
            Err(_) => {}
        }
    }
}

/// Quanto o ponteiro pode ficar do ponto pedido, em pixels em cada eixo.
const POINT_TOLERANCE: i64 = 2;
/// Quantas correções o [`point_at`] faz até desistir.
const POINT_ROUNDS: usize = 24;
/// O maior pacote do mouse nas correções do [`point_at`], em mickeys em cada
/// eixo, um a cada 15 ms: a mão devagar, na parte baixa da curva de
/// aceleração.
const POINT_PACKET: i64 = 2;
/// O maior movimento de uma correção, em mickeys em cada eixo: perto do
/// previsto, a seta é achada e o ganho medido vale para a próxima.
const POINT_STEP: i64 = 120;
/// Quanto o [`settled_pointer`] espera a seta parar.
const POINTER_SETTLE: Duration = Duration::from_secs(5);

/// Leva o ponteiro do mouse PS/2 relativo ao ponto (`x`, `y`) da tela, como
/// a mão olhando a tela: primeiro ao canto de cima à esquerda (o movimento
/// grande para no canto), depois em correções de até [`POINT_STEP`]
/// mickeys, em pacotes de até [`POINT_PACKET`], achando para onde a seta foi
/// ([`settled_pointer`]) e acertando o ganho de cada eixo pelo que ela andou
/// (a aceleração do Windows muda o ganho com a velocidade). Devolve onde a
/// ponta ficou, a até [`POINT_TOLERANCE`] pixels do ponto.
fn point_at(monitor: &mut TcpStream, ppm: &Path, x: usize, y: usize) -> Result<(usize, usize), String> {
    let send = |monitor: &mut TcpStream, dx: i64, dy: i64| monitor.write_all(format!("mouse_move {dx} {dy}
").as_bytes()).map_err(|error| format!("monitor HMP: {error}"));
    for _ in 0..8 {
        send(monitor, -250, -250)?;
        thread::sleep(Duration::from_millis(15));
    }
    // No canto, a seta é a que está lá (a de antes pode ter saído de
    // qualquer lugar).
    let mut screen = hmp_screen(monitor, ppm)?;
    let mut current = None;
    let deadline = Instant::now() + POINTER_SETTLE;
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(250));
        let image = hmp_screen(monitor, ppm)?;
        let found = screen_check::pointer_near(&image, 0, 0, 40);
        let still = found.is_some() && screen_check::pointer_near(&screen, 0, 0, 40) == found;
        screen = image;
        if still {
            current = found;
            break;
        }
    }
    let mut current = current.ok_or("a seta do ponteiro nao parou no canto de cima a esquerda")?;
    let (mut gain_x, mut gain_y) = (1.0f64, 1.0f64);
    for _ in 0..POINT_ROUNDS {
        let (error_x, error_y) = (x as i64 - current.0 as i64, y as i64 - current.1 as i64);
        if error_x.abs() <= POINT_TOLERANCE && error_y.abs() <= POINT_TOLERANCE {
            return Ok(current);
        }
        // O mickey que falta, pelo ganho medido; ao menos um no eixo que
        // ainda está longe.
        let mickeys = |error: i64, gain: f64| match ((error as f64 / gain).round() as i64).clamp(-POINT_STEP, POINT_STEP) {
            0 if error.abs() > POINT_TOLERANCE => error.signum(),
            value => value,
        };
        let (move_x, move_y) = (mickeys(error_x, gain_x), mickeys(error_y, gain_y));
        let packets = (move_x.abs().max(move_y.abs()) + POINT_PACKET - 1) / POINT_PACKET;
        for step in 0..packets {
            let part = |total: i64| total * (step + 1) / packets - total * step / packets;
            send(monitor, part(move_x), part(move_y))?;
            thread::sleep(Duration::from_millis(15));
        }
        let predicted = ((current.0 as f64 + move_x as f64 * gain_x).clamp(0.0, 1023.0) as usize, (current.1 as f64 + move_y as f64 * gain_y).clamp(0.0, 767.0) as usize);
        let (found, image) = settled_pointer(monitor, ppm, &screen, current, predicted)?;
        let found = found.ok_or_else(|| format!("a seta do ponteiro nao apareceu parada depois de andar ({move_x},{move_y}) de ({},{})", current.0, current.1))?;
        let measure = |moved: i64, sent: i64, gain: f64| if sent.abs() >= 3 && moved != 0 && moved.signum() == sent.signum() { (moved as f64 / sent as f64).clamp(0.3, 4.0) } else { gain };
        gain_x = measure(found.0 as i64 - current.0 as i64, move_x, gain_x);
        gain_y = measure(found.1 as i64 - current.1 as i64, move_y, gain_y);
        (current, screen) = (found, image);
    }
    Err(format!("o ponteiro ficou em ({},{}), longe de ({x},{y}) depois de {POINT_ROUNDS} correcoes", current.0, current.1))
}

/// Onde a seta do ponteiro parou depois de um movimento a partir de
/// `before` (a tela com ela em `current`): o ponteiro desenhado pelo vídeo
/// anda depois do mouse, então vale a seta que chegou
/// ([`screen_check::pointer_moved`], a mais perto de `predicted`) quando
/// duas leituras seguidas (250 ms uma da outra) a acham no mesmo lugar; a
/// seta que não saiu do lugar (um movimento pequeno demais para a tela)
/// fica em `current`. Espera por até [`POINTER_SETTLE`] e devolve a ponta e
/// a última tela lida.
fn settled_pointer(monitor: &mut TcpStream, ppm: &Path, before: &crate::png::Image, current: (usize, usize), predicted: (usize, usize)) -> Result<(Option<(usize, usize)>, crate::png::Image), String> {
    let deadline = Instant::now() + POINTER_SETTLE;
    let mut previous = None;
    loop {
        thread::sleep(Duration::from_millis(250));
        let image = hmp_screen(monitor, ppm)?;
        let found = screen_check::pointer_moved(before, &image, predicted.0, predicted.1).or_else(|| (screen_check::pointer_near(&image, current.0, current.1, 2) == Some(current)).then_some(current));
        if found.is_some() && found == previous {
            return Ok((found, image));
        }
        if Instant::now() > deadline {
            return Ok((None, image));
        }
        previous = found;
    }
}

/// Quanto o `--context-menu` espera o menu abrir e fechar.
const CONTEXT_MENU_WAIT: Duration = Duration::from_secs(30);

/// O `--context-menu`: espera a tela desenhada parada
/// ([`screen_check::drawn_screen`], por até [`STILL_WAIT`]), leva o ponteiro
/// a (`x`, `y`) ([`point_at`]), espera a tela parada de novo, aperta e solta
/// o botão direito (a hora vai para `sent`), espera o menu aberto e parado
/// ([`screen_check::context_menu_open`]), aperta o Esc e espera a tela de
/// antes de volta, cada espera por até [`CONTEXT_MENU_WAIT`]. Devolve o menu
/// achado, ou o que faltou.
fn open_context_menu(monitor: &mut TcpStream, ppm: &Path, x: usize, y: usize, sent: &mut Option<Instant>) -> Result<String, String> {
    still_screen(monitor, ppm, STILL_WAIT, screen_check::drawn_screen)?;
    let (px, py) = point_at(monitor, ppm, x, y)?;
    let before = still_screen(monitor, ppm, CONTEXT_MENU_WAIT, screen_check::drawn_screen)?;
    *sent = Some(Instant::now());
    monitor.write_all(b"mouse_button 2\n").map_err(|error| format!("monitor HMP: {error}"))?;
    thread::sleep(Duration::from_millis(60));
    monitor.write_all(b"mouse_button 0\n").map_err(|error| format!("monitor HMP: {error}"))?;
    let open = still_screen(monitor, ppm, CONTEXT_MENU_WAIT, |image| screen_check::context_menu_open(&before, image, px, py)).map_err(|missing| format!("o menu de contexto nao abriu no clique em ({px},{py}): {missing}"))?;
    let opened = screen_check::context_menu_open(&before, &open, px, py)?;
    type_keys(monitor, "{esc}")?;
    let back = |image: &crate::png::Image| if screen_check::same_screen(&before, image) { Ok(String::new()) } else { Err("a tela nao voltou a de antes do clique".to_string()) };
    still_screen(monitor, ppm, CONTEXT_MENU_WAIT, back).map_err(|missing| format!("o menu de contexto abriu ({opened}), mas nao fechou com o Esc: {missing}"))?;
    Ok(format!("{opened}; fechou com o Esc"))
}

/// Quanto o `--double-click`, o `--run` e o `--open` esperam a janela nova
/// aparecer e parar (o primeiro desenho de um programa pode esperar o
/// carregamento das DLLs dele).
const WINDOW_WAIT: Duration = Duration::from_secs(90);

/// Espera a janela nova sobre `before` aparecer e parar
/// ([`screen_check::window_opened`] em duas leituras seguidas iguais), por
/// até [`WINDOW_WAIT`]. Devolve a janela achada, ou o que faltou.
fn new_window(monitor: &mut TcpStream, ppm: &Path, before: &crate::png::Image, what: &str) -> Result<String, String> {
    let opened = still_screen(monitor, ppm, WINDOW_WAIT, |image| screen_check::window_opened(before, image)).map_err(|missing| format!("a janela nao abriu {what}: {missing}"))?;
    screen_check::window_opened(before, &opened)
}

/// O `--double-click`: espera a tela desenhada parada, leva o ponteiro a
/// (`x`, `y`) ([`point_at`]), espera a tela parada de novo, aperta duas
/// vezes o botão esquerdo (a hora vai para `sent`), dentro do tempo do
/// clique duplo do Windows (500 ms), e espera a janela nova ([`new_window`]).
fn double_click(monitor: &mut TcpStream, ppm: &Path, x: usize, y: usize, sent: &mut Option<Instant>) -> Result<String, String> {
    still_screen(monitor, ppm, STILL_WAIT, screen_check::drawn_screen)?;
    let (px, py) = point_at(monitor, ppm, x, y)?;
    let before = still_screen(monitor, ppm, WINDOW_WAIT, screen_check::drawn_screen)?;
    *sent = Some(Instant::now());
    for press in ["mouse_button 1\n", "mouse_button 0\n", "mouse_button 1\n", "mouse_button 0\n"] {
        monitor.write_all(press.as_bytes()).map_err(|error| format!("monitor HMP: {error}"))?;
        thread::sleep(Duration::from_millis(40));
    }
    new_window(monitor, ppm, &before, &format!("com o clique duplo em ({px},{py})"))
}

/// O `--run`: espera a tela desenhada parada, aperta Win+R (a hora vai para
/// `sent`), espera a caixa Executar ([`new_window`]), digita o comando,
/// espera a tela parada com ele e, depois do Enter, a janela do programa
/// sobre a tela de antes do Win+R, numa tela diferente da do comando
/// digitado (a caixa Executar fechou: parada, ela seria a janela nova).
fn run_command(monitor: &mut TcpStream, ppm: &Path, command: &str, sent: &mut Option<Instant>) -> Result<String, String> {
    let before = still_screen(monitor, ppm, STILL_WAIT, screen_check::drawn_screen)?;
    *sent = Some(Instant::now());
    type_keys(monitor, "{meta_l-r}")?;
    let dialog = new_window(monitor, ppm, &before, "com o Win+R (a caixa Executar)")?;
    type_keys(monitor, command)?;
    let typed = still_screen(monitor, ppm, WINDOW_WAIT, screen_check::drawn_screen)?;
    type_keys(monitor, "{ret}")?;
    let opened = still_screen(monitor, ppm, WINDOW_WAIT, |image| {
        if screen_check::same_screen(&typed, image) {
            return Err("a tela e a do comando digitado: a caixa Executar nao fechou".to_string());
        }
        screen_check::window_opened(&before, image)
    })
    .map_err(|missing| format!("a janela nao abriu com o comando {command}: {missing}"))?;
    let program = screen_check::window_opened(&before, &opened)?;
    Ok(format!("caixa Executar ({dialog}); {command}: {program}"))
}

/// O desligamento do gerador do primeiro logon feito: como o `--run` até o
/// comando digitado parado na caixa Executar, e o Enter. O shutdown.exe não
/// abre janela; o teste segue pelo desligamento.
fn shutdown_command(monitor: &mut TcpStream, ppm: &Path, command: &str, sent: &mut Option<Instant>) -> Result<String, String> {
    let before = still_screen(monitor, ppm, STILL_WAIT, screen_check::drawn_screen)?;
    *sent = Some(Instant::now());
    type_keys(monitor, "{meta_l-r}")?;
    let dialog = new_window(monitor, ppm, &before, "com o Win+R (a caixa Executar)")?;
    type_keys(monitor, command)?;
    still_screen(monitor, ppm, WINDOW_WAIT, screen_check::drawn_screen)?;
    type_keys(monitor, "{ret}")?;
    Ok(format!("caixa Executar ({dialog})"))
}

/// O disco de dados no `info blockstats` do HMP: o `-drive if=ide,index=1`
/// (o canal primário, unidade 1), que o QEMU chama `ide0-hd1`.
const DATA_DRIVE: &str = "ide0-hd1";
/// A espera do disco parado: no mínimo [`QUIET_MIN`] desde o começo, até
/// [`QUIET_FOR`] seguidos sem escrita, lendo a cada [`QUIET_POLL`]; depois
/// de [`QUIET_MAX`] ela segue mesmo com o disco gravando.
const QUIET_MIN: Duration = Duration::from_secs(30);
const QUIET_FOR: Duration = Duration::from_secs(20);
const QUIET_POLL: Duration = Duration::from_secs(5);
const QUIET_MAX: Duration = Duration::from_secs(300);

/// Uma conexão do monitor HMP que lê as respostas (o [`connect_monitor`]
/// as descarta), pronta para um comando: o banner e o primeiro prompt já
/// lidos.
fn hmp_session(port: u16, deadline: Instant) -> Result<TcpStream, String> {
    let mut stream = loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => break stream,
            Err(error) if Instant::now() > deadline => return Err(format!("monitor HMP: {error}")),
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    };
    stream.set_read_timeout(Some(Duration::from_secs(10))).map_err(|error| format!("monitor HMP: {error}"))?;
    hmp_until_prompt(&mut stream)?;
    Ok(stream)
}

/// Lê o monitor até o prompt `(qemu) ` e devolve o texto antes dele.
fn hmp_until_prompt(stream: &mut TcpStream) -> Result<String, String> {
    let mut text = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let count = stream.read(&mut buffer).map_err(|error| format!("monitor HMP: {error}"))?;
        if count == 0 {
            return Err("monitor HMP: conexao fechada".into());
        }
        text.extend_from_slice(&buffer[..count]);
        if text.ends_with(b"(qemu) ") {
            text.truncate(text.len() - b"(qemu) ".len());
            return Ok(String::from_utf8_lossy(&text).into_owned());
        }
    }
}

/// As escritas que o disco de dados recebeu desde a subida do QEMU (o
/// `wr_operations` do `info blockstats`).
fn data_disk_writes(stream: &mut TcpStream) -> Result<u64, String> {
    stream.write_all(b"info blockstats\n").map_err(|error| format!("monitor HMP: {error}"))?;
    let text = hmp_until_prompt(stream)?;
    blockstats_writes(&text, DATA_DRIVE).ok_or_else(|| format!("o info blockstats nao tem o {DATA_DRIVE}: {:?}", text.trim()))
}

/// As operações de escrita do disco `drive` na saída do `info blockstats`
/// do QEMU 11: uma tabela por disco, depois da linha `nome: idle_time_ns=`,
/// com a linha `Write:` (bytes, operações, tempo, fundidas).
fn blockstats_writes(text: &str, drive: &str) -> Option<u64> {
    let mut lines = text.lines().skip_while(|line| !line.starts_with(&format!("{drive}:")));
    lines.next()?;
    let write = lines.take_while(|line| !line.trim().is_empty()).find(|line| line.starts_with("Write:"))?;
    write.split_whitespace().nth(2)?.parse().ok()
}

/// Espera o disco de dados do convidado parar de gravar: [`QUIET_FOR`]
/// seguidos sem escrita, depois de pelo menos [`QUIET_MIN`], por até
/// [`QUIET_MAX`]. Devolve quantas escritas houve e quanto durou.
fn wait_disk_quiet(port: u16, deadline: Instant) -> Result<String, String> {
    let mut monitor = hmp_session(port, deadline)?;
    let started = Instant::now();
    let first = data_disk_writes(&mut monitor)?;
    let (mut last, mut changed) = (first, started);
    loop {
        thread::sleep(QUIET_POLL);
        let writes = data_disk_writes(&mut monitor)?;
        if writes != last {
            (last, changed) = (writes, Instant::now());
        }
        let elapsed = started.elapsed().as_secs_f64();
        if started.elapsed() >= QUIET_MIN && changed.elapsed() >= QUIET_FOR {
            return Ok(format!("{} escritas em {elapsed:.0} s, nenhuma nos ultimos {} s", last - first, QUIET_FOR.as_secs()));
        }
        if started.elapsed() >= QUIET_MAX {
            return Ok(format!("{} escritas em {elapsed:.0} s, ainda gravando (a espera acabou)", last - first));
        }
    }
}

/// O `--open`: espera a tela desenhada parada, digita as teclas (a hora vai
/// para `sent`) e espera a janela nova ([`new_window`]).
fn open_with_keys(monitor: &mut TcpStream, ppm: &Path, keys: &str, sent: &mut Option<Instant>) -> Result<String, String> {
    let before = still_screen(monitor, ppm, STILL_WAIT, screen_check::drawn_screen)?;
    *sent = Some(Instant::now());
    type_keys(monitor, keys)?;
    new_window(monitor, ppm, &before, &format!("com as teclas {keys}"))
}

/// Quanto o `--type` espera o texto aparecer.
const TYPE_WAIT: Duration = Duration::from_secs(30);

/// O `--type`: espera a tela desenhada parada, digita o texto (a hora vai
/// para `sent`) e espera a tela parada com ele ([`screen_check::text_typed`]).
fn type_text(monitor: &mut TcpStream, ppm: &Path, text: &str, sent: &mut Option<Instant>) -> Result<String, String> {
    let before = still_screen(monitor, ppm, STILL_WAIT, screen_check::drawn_screen)?;
    *sent = Some(Instant::now());
    type_keys(monitor, text)?;
    let typed = text.chars().count();
    let after = still_screen(monitor, ppm, TYPE_WAIT, |image| screen_check::text_typed(&before, image, typed)).map_err(|missing| format!("o texto {text:?} nao apareceu: {missing}"))?;
    screen_check::text_typed(&before, &after, typed)
}

/// O `--command`: o comando como no `--type` ([`type_text`]); com a linha
/// dele na tela, o Enter e a tela parada com a saída
/// ([`screen_check::command_output`]).
fn run_console_command(monitor: &mut TcpStream, ppm: &Path, command: &str, sent: &mut Option<Instant>) -> Result<String, String> {
    let before = still_screen(monitor, ppm, STILL_WAIT, screen_check::drawn_screen)?;
    *sent = Some(Instant::now());
    type_keys(monitor, command)?;
    let length = command.chars().count();
    let typed = still_screen(monitor, ppm, TYPE_WAIT, |image| screen_check::text_typed(&before, image, length)).map_err(|missing| format!("o comando {command:?} nao apareceu: {missing}"))?;
    let line = screen_check::text_typed(&before, &typed, length)?;
    let below = screen_check::lowest_change(&before, &typed).unwrap_or(0);
    type_keys(monitor, "{ret}")?;
    let after = still_screen(monitor, ppm, TYPE_WAIT, |image| screen_check::command_output(&typed, image, length, below)).map_err(|missing| format!("o comando {command:?} nao escreveu a saida: {missing}"))?;
    let output = screen_check::command_output(&typed, &after, length, below)?;
    Ok(format!("comando: {line}; saida: {output}"))
}

/// O `sendkey` da parada manual: Ctrl direito segurado e Scroll Lock duas
/// vezes. O i8042prt.sys real (CrashOnCtrlScroll=1 na semente do Registro)
/// chama o KeBugCheckEx(0xE2) na ISR do teclado; com CrashDumpEnabled o
/// kernel publica na serial os dados secundários dos callbacks de motivo,
/// entre eles o WdLog do dxgkrnl.
const MANUAL_CRASH_KEYS: &str = "sendkey ctrl_r-scroll_lock-scroll_lock 30\n";

/// As linhas que fecham a parada manual: o fim da coleta dos dados e o
/// reinício ou a parada da máquina.
const MANUAL_CRASH_DONE: &[&str] = &["[bugcheck] coleta de dados do erro: 100%", "[bugcheck] callbacks:", "[bugcheck] reiniciando", "[bugcheck] maquina parada"];

/// Quanto a parada manual espera os dados secundários.
const MANUAL_CRASH_WAIT: Duration = Duration::from_secs(120);

/// `--manual-crash`: com o QEMU vivo e sem STOP na serial, manda a parada
/// manual pelo monitor HMP e espera os dados secundários chegarem (ou o QEMU
/// sair). A linha `[xtask]` que a anuncia fica no log.
fn manual_crash(port: u16, machine: &mut Machine, output: &Arc<Mutex<String>>) {
    if !matches!(machine.process.0.try_wait(), Ok(None)) {
        println!("\n[xtask] --manual-crash: o QEMU ja tinha terminado");
        return;
    }
    if output.lock().unwrap().contains("*** STOP") {
        println!("\n[xtask] --manual-crash: a serial ja tem um STOP; nada a provocar");
        return;
    }
    let start = {
        let mut text = output.lock().unwrap();
        let note = "\n[xtask] parada manual pelo teclado (Ctrl direito + Scroll Lock duas vezes) pelo monitor do QEMU\n";
        print!("{note}");
        text.push_str(note);
        text.len()
    };
    let mut monitor = match connect_monitor(port, Instant::now() + Duration::from_secs(5)) {
        Ok(monitor) => monitor,
        Err(error) => {
            eprintln!("aviso: --manual-crash: {error}");
            return;
        }
    };
    if let Err(error) = monitor.write_all(MANUAL_CRASH_KEYS.as_bytes()) {
        eprintln!("aviso: --manual-crash: monitor HMP: {error}");
        return;
    }
    let deadline = Instant::now() + MANUAL_CRASH_WAIT;
    loop {
        {
            let text = output.lock().unwrap();
            let tail = &text[start.min(text.len())..];
            if MANUAL_CRASH_DONE.iter().any(|marker| tail.contains(marker)) {
                break;
            }
        }
        if !matches!(machine.process.0.try_wait(), Ok(None)) {
            machine.drain();
            break;
        }
        if Instant::now() > deadline {
            eprintln!("aviso: --manual-crash: os dados do bugcheck nao terminaram em {} s", MANUAL_CRASH_WAIT.as_secs());
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    // As últimas linhas (o reinício) ainda estão chegando.
    thread::sleep(Duration::from_millis(500));
    drop(monitor);
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
    // A entrada é um pipe fechado logo depois da criação, não o NUL: com o
    // `-serial stdio`, a thread de leitura da entrada do QEMU no Windows
    // (`win_stdio_thread`, chardev/char-win-stdio.c) só sai num erro do
    // ReadFile e repete a leitura que volta com 0 bytes, o que o NUL faz
    // sempre: um núcleo do hospedeiro girando o teste inteiro. No pipe
    // fechado o ReadFile falha (ERROR_BROKEN_PIPE) e a thread termina.
    let mut child = qemu_command(qemu, temp)
        .args(&arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("{}: {error}", qemu.display()))?;
    drop(child.stdin.take());
    let mut stdout = child.stdout.take().unwrap();
    let process = QemuProcess(child);
    let sink = Arc::clone(output);
    let launched = Instant::now();
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
                // Os contadores do despachante com a hora do hospedeiro: a
                // linha do convidado só tem o uptime dele.
                if line.starts_with("[perf]") {
                    let report = format!("[xtask] [perf] aos {:.1} s\n", launched.elapsed().as_secs_f64());
                    print!("{report}");
                    sink.lock().unwrap().push_str(&report);
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
    // A pasta temporária sai depois do QEMU e do simulador de TPM: declarada
    // antes dos dois, ela é solta depois deles também nos retornos de erro.
    let temp = QemuTemp::beside(log)?;
    // O simulador de TPM dura o teste inteiro: um religamento do QEMU o
    // encontra com o estado NV que o boot anterior deixou.
    let simulator = if machine.tpm { Some(TpmSimulator::start(temp.path())?) } else { None };
    let mut arguments = machine_arguments(&disks, machine, !test.allow_reboot, simulator.as_ref().map(|simulator| simulator.port));
    arguments.extend([
        "-display".to_string(),
        "none".to_string(),
        "-serial".to_string(),
        "stdio".to_string(),
        "-monitor".to_string(),
        format!("tcp:127.0.0.1:{port},server=on,wait=off"),
    ]);
    // O QMP só entra com as capturas ou a vigia da tela: o `screendump` sai
    // por ele.
    let qmp_port = if test.capture.is_some() || test.watch_screen || test.capture_every.is_some() {
        let qmp = free_port()?;
        arguments.extend(["-qmp".to_string(), format!("tcp:127.0.0.1:{qmp},server=on,wait=off")]);
        Some(qmp)
    } else {
        None
    };
    // Um QMP só para as NMIs do perfil por amostragem.
    let nmi_port = if test.nmi_samples {
        let nmi = free_port()?;
        arguments.extend(["-qmp".to_string(), format!("tcp:127.0.0.1:{nmi},server=on,wait=off")]);
        Some(nmi)
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
    let output = Arc::new(Mutex::new(String::new()));
    let current = std::cell::RefCell::new(launch(&qemu, temp.path(), &arguments, &output, events_port)?);
    let launched = Instant::now();
    let cycles_left = std::cell::Cell::new(test.power_cycles);
    // A vigia da tela e as telas do `--capture-every` rodam durante o teste;
    // o QMP atende um cliente por vez, então a thread delas para antes das
    // capturas do fim.
    let screen_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // O teste da área de trabalho (o DESKTOP_OK no marcador ou num
    // --expect): a vigia procura a área de trabalho em vez da tela de logon.
    let expects = |marker: &str| test.marker == marker || test.expect.iter().chain(&test.expect_any).any(|expected| expected == marker);
    let desktop_test = expects(DESKTOP_MARKER);
    // O teste da barra de tarefas: depois da área de trabalho, a vigia
    // procura o relógio da barra passando de minuto.
    let taskbar_test = expects(TASKBAR_MARKER);
    // O teste do shell recriado: depois da área de trabalho, a vigia a
    // confirma de novo com o explorer.exe que o winlogon recriou.
    let restart_test = expects(RESTART_AFTER) && desktop_test;
    let nmi_pumper = nmi_port.map(|port| {
        let (serial, stop) = (Arc::clone(&output), Arc::clone(&screen_stop));
        thread::spawn(move || nmi_pump(port, serial, stop))
    });
    let screen_watcher = match (test.watch_screen || test.capture_every.is_some(), qmp_port) {
        (true, Some(qmp)) => {
            let scratch = log.with_file_name("tela.ppm");
            let first = test.watch_screen.then(|| (log.with_file_name("primeira-tela.png"), desktop_test, taskbar_test, restart_test));
            let frames = test.capture_every.map(|every| FrameSeries::new(log.parent().unwrap_or(Path::new(".")), every));
            let (serial, stop) = (Arc::clone(&output), Arc::clone(&screen_stop));
            Some(thread::spawn(move || screen_thread(qmp, scratch, launched, first, frames, serial, stop)))
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
    // As teclas do `--keys` e cada entrada do `--send`, do `--dismiss` e do
    // `--mouse` abrem uma conexão do monitor HMP e a fecham no fim: o
    // servidor do QEMU atende um cliente por vez, e a parada manual do fim
    // (ou um depurador) abre outra.
    let with_monitor = |action: &mut dyn FnMut(&mut TcpStream) -> Result<String, String>| -> Result<String, String> {
        let mut monitor = connect_monitor(port, deadline)?;
        let result = action(&mut monitor);
        // A cópia da conexão que descarta as respostas segura o socket: o
        // shutdown o fecha de verdade e libera o monitor para a próxima.
        let _ = monitor.shutdown(std::net::Shutdown::Both);
        result
    };
    let note = |line: String| {
        let line = format!("\n{line}\n");
        print!("{line}");
        output.lock().unwrap().push_str(&line);
    };
    // A entrada que espera `marker`, cada uma depois do atraso dela e uma vez
    // só (o mesmo texto esperado de novo mais adiante não a repete); a linha
    // de cada uma vai para a serial (sem repetir o nome do marcador, que um
    // `--expect` seguinte não pode casar). O `--dismiss` ou o `--mouse` que
    // não vê a tela mudar encerra o teste.
    let sent = std::cell::RefCell::new(vec![false; test.inputs.len()]);
    let send_after = |marker: &str| -> Result<(), String> {
        for (index, input) in test.inputs.iter().enumerate() {
            if input.after != marker || std::mem::replace(&mut sent.borrow_mut()[index], true) {
                continue;
            }
            thread::sleep(input.delay);
            let at = launched.elapsed().as_secs_f64();
            match &input.action {
                InputAction::Keys(keys) => {
                    with_monitor(&mut |monitor| type_keys(monitor, keys).map(|()| String::new()))?;
                    note(format!("{KEYS_SENT}: {keys} (aos {at:.1} s)"));
                }
                InputAction::Dismiss(keys) => {
                    let ppm = log.with_file_name("tela-monitor.ppm");
                    let mut sent = None;
                    let outcome = with_monitor(&mut |monitor| dismiss_lock(monitor, &ppm, keys, &mut sent));
                    let at = sent.map_or(at, |sent| sent.duration_since(launched).as_secs_f64());
                    match outcome {
                        Ok(description) => note(format!("{KEYS_SENT}: {keys} (aos {at:.1} s)\n[xtask] tela de bloqueio dispensada: {description}\n{LOGON_DISMISS_MARKER}")),
                        Err(missing) => {
                            note(format!("[xtask] a tela de bloqueio nao saiu com {keys} (aos {at:.1} s): {missing}"));
                            return Err(format!("a tela de bloqueio nao saiu com {keys}: {missing}"));
                        }
                    }
                }
                InputAction::StartMenu(keys) => {
                    let ppm = log.with_file_name("tela-monitor.ppm");
                    let mut sent = None;
                    let outcome = with_monitor(&mut |monitor| open_start_menu(monitor, &ppm, keys, &mut sent));
                    let at = sent.map_or(at, |sent| sent.duration_since(launched).as_secs_f64());
                    match outcome {
                        Ok(description) => note(format!("{KEYS_SENT}: {keys} (aos {at:.1} s)\n[xtask] menu Iniciar: {description}\n{START_MENU_MARKER}")),
                        Err(missing) => {
                            note(format!("[xtask] o menu Iniciar nao abriu e fechou com {keys} (aos {at:.1} s): {missing}"));
                            return Err(format!("o menu Iniciar nao abriu e fechou com {keys}: {missing}"));
                        }
                    }
                }
                InputAction::StartClick { x, y } => {
                    let ppm = log.with_file_name("tela-monitor.ppm");
                    let mut sent = None;
                    let outcome = with_monitor(&mut |monitor| click_start_menu(monitor, &ppm, *x, *y, &mut sent));
                    let at = sent.map_or(at, |sent| sent.duration_since(launched).as_secs_f64());
                    match outcome {
                        Ok(description) => note(format!("[xtask] botao esquerdo no botao Iniciar em ({x},{y}) pelo monitor (aos {at:.1} s)\n[xtask] menu Iniciar: {description}\n{START_MENU_MARKER}")),
                        Err(missing) => {
                            note(format!("[xtask] o menu Iniciar nao abriu e fechou com o clique em ({x},{y}) (aos {at:.1} s): {missing}"));
                            return Err(format!("o menu Iniciar nao abriu e fechou com o clique em ({x},{y}): {missing}"));
                        }
                    }
                }
                InputAction::ContextMenu { x, y } => {
                    let ppm = log.with_file_name("tela-monitor.ppm");
                    let mut sent = None;
                    let outcome = with_monitor(&mut |monitor| open_context_menu(monitor, &ppm, *x, *y, &mut sent));
                    let at = sent.map_or(at, |sent| sent.duration_since(launched).as_secs_f64());
                    match outcome {
                        Ok(description) => note(format!("[xtask] botao direito em ({x},{y}) pelo monitor (aos {at:.1} s): {description}\n{CONTEXT_MENU_MARKER}")),
                        Err(missing) => {
                            note(format!("[xtask] botao direito em ({x},{y}) pelo monitor (aos {at:.1} s), sem o menu de contexto: {missing}"));
                            return Err(format!("o menu de contexto nao abriu e fechou com o botao direito em ({x},{y}): {missing}"));
                        }
                    }
                }
                InputAction::DoubleClick { x, y } => {
                    let ppm = log.with_file_name("tela-monitor.ppm");
                    let mut sent = None;
                    let outcome = with_monitor(&mut |monitor| double_click(monitor, &ppm, *x, *y, &mut sent));
                    let at = sent.map_or(at, |sent| sent.duration_since(launched).as_secs_f64());
                    match outcome {
                        Ok(description) => note(format!("[xtask] clique duplo em ({x},{y}) pelo monitor (aos {at:.1} s): {description}\n{WINDOW_OPENED_MARKER}")),
                        Err(missing) => {
                            note(format!("[xtask] clique duplo em ({x},{y}) pelo monitor (aos {at:.1} s), sem janela nova: {missing}"));
                            return Err(format!("o clique duplo em ({x},{y}) nao abriu janela: {missing}"));
                        }
                    }
                }
                InputAction::Run(command) => {
                    let ppm = log.with_file_name("tela-monitor.ppm");
                    let mut sent = None;
                    let outcome = with_monitor(&mut |monitor| run_command(monitor, &ppm, command, &mut sent));
                    let at = sent.map_or(at, |sent| sent.duration_since(launched).as_secs_f64());
                    match outcome {
                        Ok(description) => note(format!("[xtask] Win+R e {command} pelo monitor (aos {at:.1} s): {description}\n{WINDOW_OPENED_MARKER}")),
                        Err(missing) => {
                            note(format!("[xtask] Win+R e {command} pelo monitor (aos {at:.1} s), sem a janela: {missing}"));
                            return Err(format!("o comando {command} da caixa Executar nao abriu janela: {missing}"));
                        }
                    }
                }
                InputAction::Open(keys) => {
                    let ppm = log.with_file_name("tela-monitor.ppm");
                    let mut sent = None;
                    let outcome = with_monitor(&mut |monitor| open_with_keys(monitor, &ppm, keys, &mut sent));
                    let at = sent.map_or(at, |sent| sent.duration_since(launched).as_secs_f64());
                    match outcome {
                        Ok(description) => note(format!("{KEYS_SENT}: {keys} (aos {at:.1} s)\n[xtask] janela nova: {description}\n{WINDOW_OPENED_MARKER}")),
                        Err(missing) => {
                            note(format!("[xtask] teclas {keys} pelo monitor (aos {at:.1} s), sem janela nova: {missing}"));
                            return Err(format!("as teclas {keys} nao abriram janela: {missing}"));
                        }
                    }
                }
                InputAction::Shutdown(command) => {
                    let quiet = wait_disk_quiet(port, deadline)?;
                    note(format!("[xtask] disco do convidado parado (aos {:.1} s): {quiet}", launched.elapsed().as_secs_f64()));
                    let ppm = log.with_file_name("tela-monitor.ppm");
                    let mut sent = None;
                    let outcome = with_monitor(&mut |monitor| shutdown_command(monitor, &ppm, command, &mut sent));
                    let at = sent.map_or(at, |sent| sent.duration_since(launched).as_secs_f64());
                    match outcome {
                        Ok(description) => note(format!("[xtask] Win+R e {command} pelo monitor (aos {at:.1} s): {description}")),
                        Err(missing) => {
                            note(format!("[xtask] Win+R e {command} pelo monitor (aos {at:.1} s), sem a caixa Executar: {missing}"));
                            return Err(format!("o desligamento pela caixa Executar nao foi digitado: {missing}"));
                        }
                    }
                }
                InputAction::Type(text) => {
                    let ppm = log.with_file_name("tela-monitor.ppm");
                    let mut sent = None;
                    let outcome = with_monitor(&mut |monitor| type_text(monitor, &ppm, text, &mut sent));
                    let at = sent.map_or(at, |sent| sent.duration_since(launched).as_secs_f64());
                    match outcome {
                        Ok(description) => note(format!("[xtask] texto digitado pelo monitor (aos {at:.1} s): {description}\n{TEXT_TYPED_MARKER}")),
                        Err(missing) => {
                            note(format!("[xtask] texto digitado pelo monitor (aos {at:.1} s), sem aparecer: {missing}"));
                            return Err(format!("o texto {text:?} nao apareceu na janela: {missing}"));
                        }
                    }
                }
                InputAction::Command(command) => {
                    let ppm = log.with_file_name("tela-monitor.ppm");
                    let mut sent = None;
                    let outcome = with_monitor(&mut |monitor| run_console_command(monitor, &ppm, command, &mut sent));
                    let at = sent.map_or(at, |sent| sent.duration_since(launched).as_secs_f64());
                    match outcome {
                        Ok(description) => note(format!("[xtask] comando {command} e Enter pelo monitor (aos {at:.1} s): {description}\n{COMMAND_OUTPUT_MARKER}")),
                        Err(missing) => {
                            note(format!("[xtask] comando {command} e Enter pelo monitor (aos {at:.1} s), sem a saida: {missing}"));
                            return Err(format!("o comando {command:?} nao escreveu a saida no console: {missing}"));
                        }
                    }
                }
                InputAction::Mouse { dx, dy } => {
                    let ppm = log.with_file_name("tela-monitor.ppm");
                    let mut sent = None;
                    let outcome = with_monitor(&mut |monitor| move_mouse(monitor, &ppm, *dx, *dy, &mut sent));
                    let at = sent.map_or(at, |sent| sent.duration_since(launched).as_secs_f64());
                    match outcome {
                        Ok(description) => note(format!("[xtask] mouse movido pelo monitor (aos {at:.1} s): {description}\n{CURSOR_MOVED_MARKER}")),
                        Err(missing) => {
                            note(format!("[xtask] mouse movido pelo monitor (aos {at:.1} s), mas o ponteiro nao andou: {missing}"));
                            return Err(format!("o ponteiro nao andou depois do mouse ({dx},{dy}): {missing}"));
                        }
                    }
                }
            }
        }
        Ok(())
    };
    let result = (|| -> Result<(), String> {
        let mut cursor = wait_for(&test.marker, 0)?;
        arrived(&test.marker);
        send_after(&test.marker)?;
        if let Some(keys) = &test.keys {
            cursor = wait_for("[shell] pronto", 0)?;
            with_monitor(&mut |monitor| type_keys(monitor, keys).map(|()| String::new()))?;
        }
        for expected in &test.expect {
            cursor = wait_for(expected, cursor)?;
            arrived(expected);
            send_after(expected)?;
        }
        // As de qualquer ordem: desde o começo da serial (um marcador de
        // falha em qualquer ponto dela reprova, como na cadeia acima). A
        // espera do fim conta da última achada.
        for expected in &test.expect_any {
            cursor = cursor.max(wait_for(expected, 0)?);
            arrived(expected);
            send_after(expected)?;
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
    if let Some(pumper) = nmi_pumper {
        let _ = pumper.join();
    }
    let ScreenOutcome { last: last_screen, frames, logon, desktop, taskbar, restarted } = screen_watcher.and_then(|watcher| watcher.join().ok()).unwrap_or_default();
    // O teste da tela de logon que falhou diz no log o que faltou na última
    // tela lida.
    let logon_test = test.marker == LOGON_SCREEN_MARKER || test.expect.iter().chain(&test.expect_any).any(|expected| expected == LOGON_SCREEN_MARKER);
    if let (true, Err(_), None, Some(last)) = (logon_test, &result, &logon, &last_screen) {
        let verdict = match screen_check::logon_screen(last) {
            Ok(description) => format!("passou numa leitura, mas nao em duas seguidas iguais: {description}"),
            Err(missing) => missing,
        };
        // No QEMU a tela desligada continua com o último quadro: a serial diz
        // se a política de energia a desligou antes da captura.
        let switched_off = output.lock().unwrap().contains("[po] tela do console: desligada");
        let verdict = if switched_off { format!("{verdict} (a politica de energia desligou a tela do console antes da captura)") } else { verdict };
        let line = format!("\n[xtask] a ultima tela lida nao e a tela de logon: {verdict}\n");
        print!("{line}");
        output.lock().unwrap().push_str(&line);
    }
    // O teste da área de trabalho que falhou também.
    if let (true, Err(_), None, Some(last)) = (desktop_test, &result, &desktop, &last_screen) {
        let verdict = match screen_check::desktop_screen(last) {
            Ok(description) => format!("passou numa leitura, mas nao em duas seguidas iguais depois do {DESKTOP_AFTER}: {description}"),
            Err(missing) => missing,
        };
        let line = format!("\n[xtask] a ultima tela lida nao e a area de trabalho: {verdict}\n");
        print!("{line}");
        output.lock().unwrap().push_str(&line);
    }
    // A tela que a vigia confirmou: a área de trabalho no teste dela,
    // senão a tela de logon.
    // O teste da barra de tarefas que falhou depois da área de trabalho diz
    // o que faltou na barra da última tela lida.
    if let (true, Err(_), Some(_), None, Some(last)) = (taskbar_test, &result, &desktop, &taskbar, &last_screen) {
        let verdict = match screen_check::taskbar_layout(last) {
            Ok(layout) => format!("{}, mas o relogio nao passou de minuto com o resto parado em duas leituras seguidas depois do {TASKBAR_AFTER}", layout.describe()),
            Err(missing) => missing,
        };
        let line = format!("\n[xtask] a ultima tela lida nao confirma a barra de tarefas: {verdict}\n");
        print!("{line}");
        output.lock().unwrap().push_str(&line);
    }
    // O teste do shell recriado que falhou depois da primeira área de
    // trabalho diz o que faltou na última tela lida.
    if let (true, Err(_), Some(_), None, Some(last)) = (restart_test, &result, &desktop, &restarted, &last_screen) {
        let seen = output.lock().unwrap().contains(RESTART_AFTER);
        let verdict = match (seen, screen_check::desktop_screen(last)) {
            (false, _) => format!("o {RESTART_AFTER} nao apareceu na serial"),
            (true, Ok(description)) => format!("passou numa leitura, mas nao em duas seguidas iguais depois do {RESTART_AFTER}: {description}"),
            (true, Err(missing)) => missing,
        };
        let line = format!("\n[xtask] a ultima tela lida nao mostra a area de trabalho de volta: {verdict}\n");
        print!("{line}");
        output.lock().unwrap().push_str(&line);
    }
    let confirmed = if restart_test { restarted.or(desktop) } else if taskbar_test { taskbar.or(desktop) } else if desktop_test { desktop } else { logon };
    let mut machine = current.into_inner();
    // As capturas do fim saem com o QEMU ainda vivo, passe o teste ou não
    // (prazo esgotado, STOP); se elas falharem, o resultado do teste não
    // muda.
    if let Some(qmp) = qmp_port.filter(|_| test.capture.is_some() || frames.is_some()) {
        let alive = matches!(machine.process.0.try_wait(), Ok(None));
        let mut needles = vec![test.marker.as_str()];
        needles.extend(test.expect.iter().chain(&test.expect_any).map(String::as_str));
        let serial = serial_proof(&output.lock().unwrap(), &needles);
        if let Some(series) = &frames {
            let target = log.with_file_name(FINAL_FRAME);
            if let Err(error) = final_frame(qmp, &target, alive, last_screen, &result, &serial, launched.elapsed()) {
                eprintln!("aviso: sem tela final ({}): {error}", target.display());
            }
            println!("[xtask] {}", series.summary());
        }
        if let Some(target) = &test.capture {
            // O teste que passou com a tela confirmada pela vigia (a de
            // logon ou a área de trabalho) grava a tela que o provou, mesmo
            // com o QEMU já terminado; os outros, a tela do fim.
            let captured = match (&result, &confirmed) {
                (Ok(()), Some(image)) => write_capture(image, target, &result, &serial),
                _ if alive => capture_screen(qmp, target, &result, &serial),
                _ => Err("o QEMU ja tinha terminado".into()),
            };
            if let Err(error) = captured {
                eprintln!("aviso: sem captura de tela ({}): {error}", target.display());
            }
        }
    }
    if test.manual_crash {
        manual_crash(port, &mut machine, &output);
    }
    drop(machine.process);
    machine.reader.take();
    drop(simulator);
    drop(temp);
    if let Some(copy) = &data_copy {
        let _ = std::fs::remove_file(copy);
    }
    let text = output.lock().unwrap().clone();
    std::fs::write(log, &text).map_err(|error| format!("{}: {error}", log.display()))?;
    println!();
    // A parada (a do teste que falhou ou a manual) sai resumida, com a pilha
    // do [kcrash] e o WdLog do dxgkrnl.
    let stopped = text.contains("*** STOP") || text.contains("*** EXCECAO DE KERNEL");
    match result {
        Ok(()) => {
            if test.manual_crash && stopped {
                crate::crash::summarize(log, &text);
            }
            println!("TEST-BOOT OK: {:?} encontrado (serial em {})", test.marker, log.display());
            Ok(())
        }
        Err(error) => {
            crate::heap_census::summarize_failure(log, &text);
            if stopped {
                crate::crash::summarize(log, &text);
            }
            Err(format!("TEST-BOOT FALHOU: {error} (serial em {})", log.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::png::Image;

    /// As escritas do disco de dados na tabela do `info blockstats` do QEMU
    /// 11.1 (a resposta do monitor, com o eco do comando antes).
    #[test]
    fn blockstats_writes_of_the_data_disk() {
        let text = "info blockstats\x1b[K\r\n\
            ide0-hd0: idle_time_ns=374276685300\r\n                          bytes       operations            total_time_ns     merged\r\n\
            Read:                  20460032              221                420443200          0\r\n\
            Write:                        0                0                        0          0\r\n\
            Flush:                                         0                        0\r\n\r\n\
            ide0-hd1: idle_time_ns=36504323300\r\n                          bytes       operations            total_time_ns     merged\r\n\
            Read:                1030619648            35338              16576149700          0\r\n\
            Write:                 62763520            19908               5592494400          0\r\n\
            Flush:                                      6443              36810944400\r\n\r\n";
        assert_eq!(blockstats_writes(text, "ide0-hd1"), Some(19908));
        assert_eq!(blockstats_writes(text, "ide0-hd0"), Some(0));
        assert_eq!(blockstats_writes(text, "ide1-cd0"), None);
    }

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

    /// Com `--tpm` a máquina ganha o backend `mssim` na porta do simulador e
    /// o `tpm-crb`; sem ele, nenhum dos dois. As duas portas do simulador
    /// (comandos e a seguinte, de plataforma) estão livres.
    #[test]
    fn tpm_machine_has_the_simulator_backend_and_the_crb_device() {
        let disks = Disks { boot: PathBuf::from("os.img"), data: None, data_snapshot: false, nvme: None, nvme_snapshot: false };
        let machine = MachineOptions { accelerator: "tcg".into(), memory_mb: 512, smp: 1, kd_port: None, usb: false, net: false, tpm: true, monitor_port: None, ata_fault: String::new() };
        let arguments = machine_arguments(&disks, &machine, true, Some(40_000));
        let at = arguments.iter().position(|argument| argument == "-tpmdev").expect("-tpmdev");
        assert_eq!(arguments[at + 1], "mssim,id=tpm0,host=127.0.0.1,port=40000");
        assert_eq!(arguments[at + 2..at + 4], ["-device".to_string(), "tpm-crb,tpmdev=tpm0".to_string()]);
        let plain = machine_arguments(&disks, &MachineOptions { tpm: false, ..machine.clone() }, true, None);
        assert!(!plain.iter().any(|argument| argument.contains("tpm")));
        let port = free_port_pair().unwrap();
        assert!(TcpListener::bind(("127.0.0.1", port)).is_ok() && TcpListener::bind(("127.0.0.1", port + 1)).is_ok());
        // Com o TPM a máquina fica no TCG: o `auto` vira TCG e o WHPX é recusado.
        assert_eq!(machine_accelerator(&MachineOptions { accelerator: "auto".into(), ..machine.clone() }), Ok("tcg".to_string()));
        assert!(machine_accelerator(&MachineOptions { accelerator: "whpx".into(), ..machine.clone() }).is_err());
        assert_eq!(machine_accelerator(&MachineOptions { accelerator: "whpx".into(), tpm: false, ..machine }), Ok("whpx".to_string()));
    }

    /// Com `--ata-fault=read` o volume de dados vai ao QEMU atrás do
    /// blkdebug, com a regra que deixa passar a primeira leitura e falha a
    /// seguinte uma vez; sem a opção, o arquivo vai direto.
    #[test]
    fn ata_fault_puts_the_data_disk_behind_blkdebug() {
        let disks = Disks { boot: PathBuf::from("os.img"), data: Some(PathBuf::from("ntfs.img")), data_snapshot: true, nvme: None, nvme_snapshot: false };
        let machine = MachineOptions { accelerator: "tcg".into(), memory_mb: 512, smp: 1, kd_port: None, usb: false, net: false, tpm: false, monitor_port: None, ata_fault: "read".into() };
        let arguments = machine_arguments(&disks, &machine, true, None);
        let data = arguments.iter().find(|argument| argument.contains("index=1")).expect("drive 1");
        assert_eq!(
            data,
            "format=raw,if=ide,index=1,media=disk,snapshot=on,file.driver=blkdebug,file.image.driver=file,file.image.filename=ntfs.img,\
             file.set-state.0.event=read_aio,file.set-state.0.state=1,file.set-state.0.new_state=2,\
             file.inject-error.0.event=read_aio,file.inject-error.0.state=2,file.inject-error.0.errno=5,file.inject-error.0.once=on"
        );
        let plain = machine_arguments(&disks, &MachineOptions { ata_fault: String::new(), ..machine }, true, None);
        assert!(plain.iter().any(|argument| argument == "format=raw,if=ide,index=1,media=disk,snapshot=on,file=ntfs.img"));
        assert!(!plain.iter().any(|argument| argument.contains("blkdebug")));
    }

    fn screen(width: usize, height: usize, fill: [u8; 3]) -> Image {
        Image { width, height, rgb: fill.iter().copied().cycle().take(width * height * 3).collect() }
    }

    /// Uma pasta vazia só do teste.
    fn scratch_dir(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!("opennt-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    fn names_in(directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(directory).unwrap().map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        names
    }

    #[test]
    fn frame_names_and_schedule() {
        assert_eq!(FrameSeries::name(1), "tela-0001.png");
        assert_eq!(FrameSeries::name(12_345), "tela-12345.png");
        assert!(is_frame("tela-0001.png") && is_frame("tela-12345.png") && is_frame(FINAL_FRAME));
        // As outras capturas da pasta do build não são da série.
        for other in ["tela-de-logon.png", "primeira-tela.png", "tela-12.png", "tela-0001.ppm", "tela.ppm", "serial.log"] {
            assert!(!is_frame(other), "{other}");
        }
        // A tela N vence aos N intervalos; a próxima depois de um instante é
        // a do intervalo seguinte.
        let series = FrameSeries { directory: PathBuf::new(), every: Duration::from_secs(5), previous: None, saved: 0, repeated: 0 };
        assert_eq!(series.next_index(Duration::ZERO), 1);
        assert_eq!(series.next_index(Duration::from_millis(4_999)), 1);
        assert_eq!(series.next_index(Duration::from_secs(5)), 2);
        assert_eq!(series.next_index(Duration::from_millis(17_200)), 4);
        assert_eq!(series.due(3), Duration::from_secs(15));
        assert_eq!(series.due(u64::MAX), Duration::MAX);
    }

    #[test]
    fn frame_series_skips_a_frame_equal_to_the_previous_one() {
        let directory = scratch_dir("frames");
        // As telas de uma série anterior saem; as outras capturas ficam.
        for stale in ["tela-0007.png", FINAL_FRAME, "tela-de-logon.png", "primeira-tela.png", "serial.log"] {
            std::fs::write(directory.join(stale), b"x").unwrap();
        }
        let mut series = FrameSeries::new(&directory, Duration::from_secs(5));
        assert_eq!(names_in(&directory), ["primeira-tela.png", "serial.log", "tela-de-logon.png"]);
        let black = screen(64, 48, [0, 0, 0]);
        let mut dot = black.clone();
        dot.rgb[0..3].copy_from_slice(&[0xFF, 0xFF, 0xFF]);
        let offered: Vec<Option<PathBuf>> = [&black, &black, &dot, &dot, &black]
            .iter()
            .enumerate()
            .map(|(at, image)| series.offer(at as u64 + 1, Duration::from_secs(5 * (at as u64 + 1)), image, "linha da serial").unwrap())
            .collect();
        // A tela igual à anterior gravada não sai; a que volta a ser como uma
        // mais antiga sai (a comparação é com a anterior).
        assert_eq!(offered, [Some(directory.join("tela-0001.png")), None, Some(directory.join("tela-0003.png")), None, Some(directory.join("tela-0005.png"))]);
        assert_eq!((series.saved, series.repeated), (3, 2));
        assert_eq!(names_in(&directory), ["primeira-tela.png", "serial.log", "tela-0001.png", "tela-0003.png", "tela-0005.png", "tela-de-logon.png"]);
        // A tela inteira, com a hora e a serial nos textos.
        let info = crate::png::read_info(&std::fs::read(directory.join("tela-0003.png")).unwrap()).unwrap();
        assert_eq!((info.width, info.height), (64, 48));
        assert_eq!(info.text("opennt-tempo"), Some("15.0 s"));
        assert_eq!(info.text("opennt-tela"), Some("64x48"));
        assert_eq!(info.text("opennt-serial"), Some("linha da serial"));
        assert!(series.summary().starts_with("3 tela(s) gravada(s) em "), "{}", series.summary());
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn final_frame_uses_the_last_screen_when_qemu_is_gone() {
        let directory = scratch_dir("final-frame");
        let target = directory.join(FINAL_FRAME);
        let result = Err("tempo esgotado esperando \"X\"".to_string());
        // Sem QEMU e sem tela lida, não há tela final.
        assert!(final_frame(0, &target, false, None, &result, "serial", Duration::from_secs(9)).is_err());
        assert!(!target.exists());
        // Com o QEMU terminado, a última tela que a thread leu.
        final_frame(0, &target, false, Some(screen(32, 24, [0x00, 0x77, 0xD6])), &result, "*** STOP", Duration::from_secs(9)).unwrap();
        let info = crate::png::read_info(&std::fs::read(&target).unwrap()).unwrap();
        assert_eq!((info.width, info.height), (32, 24));
        assert_eq!(info.text("opennt-resultado"), Some("falhou: tempo esgotado esperando \"X\""));
        assert_eq!(info.text("opennt-origem"), Some("a ultima lida durante o teste"));
        assert_eq!(info.text("opennt-tempo"), Some("9.0 s"));
        assert_eq!(info.text("opennt-tela"), Some("32x24"));
        assert_eq!(info.text("opennt-serial"), Some("*** STOP"));
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// Um QMP falso: cada conexão recebe a saudação, aceita o
    /// `qmp_capabilities` e responde ao `screendump` gravando a próxima de
    /// `screens` em PPM no arquivo pedido. Na última, liga `stop` antes de
    /// responder: a thread da tela trata aquela tela e sai.
    fn fake_qmp(screens: Vec<Image>, stop: Arc<std::sync::atomic::AtomicBool>) -> (u16, thread::JoinHandle<usize>) {
        use std::io::BufRead;
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            for (at, image) in screens.iter().enumerate() {
                let (stream, _) = listener.accept().unwrap();
                let mut writer = stream.try_clone().unwrap();
                let mut reader = std::io::BufReader::new(stream);
                writer.write_all(b"{\"QMP\": {\"version\": {}, \"capabilities\": []}}\n").unwrap();
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert!(line.contains("qmp_capabilities"), "{line}");
                writer.write_all(b"{\"return\": {}}\n").unwrap();
                line.clear();
                reader.read_line(&mut line).unwrap();
                let file = line.split("\"filename\":\"").nth(1).and_then(|rest| rest.split('"').next()).unwrap_or_else(|| panic!("{line}"));
                let header = format!("P6\n{} {}\n255\n", image.width, image.height);
                std::fs::write(file, [header.as_bytes(), &image.rgb].concat()).unwrap();
                if at + 1 == screens.len() {
                    stop.store(true, std::sync::atomic::Ordering::Release);
                }
                // Um evento antes da resposta, como o QEMU pode mandar.
                writer.write_all(b"{\"event\": \"RESUME\"}\n{\"return\": {}}\n").unwrap();
            }
            screens.len()
        });
        (port, server)
    }

    /// A thread da tela com só o `--capture-every`, contra o QMP falso: cada
    /// leitura vira uma tela da série, as iguais à anterior não são
    /// gravadas, e a última lida volta para a tela final.
    #[test]
    fn screen_thread_saves_only_the_frames_that_changed() {
        let directory = scratch_dir("screen-thread");
        let (a, b) = (screen(40, 30, [0x10, 0x20, 0x30]), screen(40, 30, [0xF0, 0xE0, 0xD0]));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (port, server) = fake_qmp(vec![a.clone(), a.clone(), b.clone(), b.clone(), b, a.clone()], Arc::clone(&stop));
        let output = Arc::new(Mutex::new("primeira linha\nultima linha\n".to_string()));
        let frames = FrameSeries::new(&directory, Duration::from_millis(30));
        let ScreenOutcome { last, frames, logon, desktop, taskbar, restarted } = screen_thread(port, directory.join("tela.ppm"), Instant::now(), None, Some(frames), output, stop);
        assert!(logon.is_none() && desktop.is_none() && taskbar.is_none() && restarted.is_none(), "sem a vigia, nada de tela de logon, area de trabalho ou barra");
        assert_eq!(server.join().unwrap(), 6);
        let frames = frames.unwrap();
        assert_eq!((frames.saved, frames.repeated), (3, 3));
        assert!(last == Some(a), "a ultima tela lida volta da thread");
        // Três PNGs em ordem, nenhum PPM de sobra.
        let names = names_in(&directory);
        assert_eq!(names.len(), 3, "{names:?}");
        assert!(names.iter().all(|name| is_frame(name) && name != FINAL_FRAME), "{names:?}");
        let info = crate::png::read_info(&std::fs::read(directory.join(&names[0])).unwrap()).unwrap();
        assert_eq!(info.text("opennt-serial"), Some("primeira linha\nultima linha\n"));
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// A vigia: o ponteiro dá o primeiro pixel; a tela de logon só sai na
    /// segunda leitura seguida igual. O quadro rasgado (que passa sozinho na
    /// conferência) e a imagem surgindo do preto antes dela não contam, e o
    /// relógio que muda de minuto entre as duas leituras não atrapalha.
    #[test]
    fn watch_confirms_the_logon_screen_on_two_equal_reads() {
        use crate::screen_check::samples::*;
        let directory = scratch_dir("watch");
        let first = directory.join("primeira-tela.png");
        let output = Mutex::new(String::new());
        let mut watch = Watch::default();
        let mut pointer = filled(WIDTH, HEIGHT, [0, 0, 0]);
        paint(&mut pointer, 512..522, 386..404, |_, _| [0xFF, 0xFF, 0xFF]);
        let lock = lock_screen(true);
        let torn = only_rows(&lock, 0..HEIGHT * 3 / 4);
        assert!(screen_check::logon_screen(&torn).is_ok(), "o quadro rasgado em 3/4 passa sozinho");
        let mut faded = lock.clone();
        faded.rgb.iter_mut().for_each(|channel| *channel /= 2);
        let mut next_minute = lock_screen(false);
        clock(&mut next_minute, 1);

        assert!(!watch_step(&pointer, &first, &mut watch, &output));
        assert!(watch.first_seen && first.is_file());
        // Antes do LOGONUI_STARTED na serial, nem a tela de bloqueio parada é
        // a tela de logon.
        for _ in 0..3 {
            assert!(!watch_step(&lock, &first, &mut watch, &output));
        }
        assert!(!output.lock().unwrap().contains(LOGON_SCREEN_MARKER));
        output.lock().unwrap().push_str("\nLOGONUI_STARTED\n");
        for image in [&torn, &faded, &lock] {
            assert!(!watch_step(image, &first, &mut watch, &output));
        }
        assert!(!output.lock().unwrap().contains(LOGON_SCREEN_MARKER));
        assert!(watch_step(&next_minute, &first, &mut watch, &output));
        assert!(watch.logon.as_ref() == Some(&next_minute), "a segunda leitura e a tela de logon");
        let text = output.lock().unwrap().clone();
        assert_eq!((text.matches(FIRST_PIXEL_MARKER).count(), text.matches(LOGON_SCREEN_MARKER).count()), (1, 1), "{text}");
        let saved = crate::png::read_info(&std::fs::read(directory.join("tela-de-logon.png")).unwrap()).unwrap();
        assert_eq!(saved.text("opennt-resultado"), Some("tela de logon"));
        // O PNG pode sair reduzido; o tamanho da tela conferida vai junto.
        assert_eq!(saved.text("opennt-tela"), Some("1024x768"));

        // Uma leitura que não é a tela de logon entre duas que são recomeça
        // a contagem.
        let mut watch = Watch::default();
        for image in [&lock, &pointer, &lock] {
            assert!(!watch_step(image, &first, &mut watch, &output));
        }
        assert!(watch_step(&lock, &first, &mut watch, &output));
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// A vigia de um teste da área de trabalho: nada conta antes do
    /// EXPLORER_STARTED na serial, a tela de logon no caminho não encerra a
    /// vigia nem põe o LOGON_SCREEN_OK, e a área de trabalho sai na segunda
    /// leitura seguida igual.
    #[test]
    fn watch_finds_the_desktop_only_after_explorer_started() {
        use crate::screen_check::samples::*;
        let directory = scratch_dir("watch-desktop");
        let first = directory.join("primeira-tela.png");
        let output = Mutex::new(String::new());
        let mut watch = Watch { wants_desktop: true, ..Watch::default() };
        let area = desktop(40, 256, true);
        for _ in 0..3 {
            assert!(!watch_step(&area, &first, &mut watch, &output));
        }
        assert!(watch.first_seen && !output.lock().unwrap().contains(DESKTOP_MARKER));
        output.lock().unwrap().push_str("\nEXPLORER_STARTED\n");
        let lock = lock_screen(true);
        for image in [&lock, &lock, &area] {
            assert!(!watch_step(image, &first, &mut watch, &output));
        }
        assert!(watch_step(&area, &first, &mut watch, &output));
        assert!(watch.desktop.as_ref() == Some(&area) && watch.logon.is_none());
        let text = output.lock().unwrap().clone();
        assert_eq!((text.matches(DESKTOP_MARKER).count(), text.matches(LOGON_SCREEN_MARKER).count()), (1, 0), "{text}");
        assert!(text.find(DESKTOP_AFTER).unwrap() < text.find(DESKTOP_MARKER).unwrap(), "{text}");
        let saved = crate::png::read_info(&std::fs::read(directory.join("area-de-trabalho.png")).unwrap()).unwrap();
        assert_eq!(saved.text("opennt-resultado"), Some("area de trabalho"));
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// A vigia de um teste do shell recriado: o primeiro DESKTOP_OK não
    /// encerra a vigia; o segundo só conta depois do SHELL_RESTARTED, com
    /// duas leituras seguidas iguais feitas depois dele (a leitura em que ele
    /// aparece não conta, e a tela sem a barra recomeça), e a tela vai para
    /// area-de-trabalho-reiniciada.png.
    #[test]
    fn watch_confirms_the_desktop_again_after_the_shell_restart() {
        use crate::screen_check::samples::*;
        let directory = scratch_dir("watch-restart");
        let first = directory.join("primeira-tela.png");
        let output = Mutex::new(String::from("EXPLORER_STARTED\n"));
        let mut watch = Watch { wants_desktop: true, wants_restart: true, ..Watch::default() };
        let area = desktop(40, 256, true);
        for _ in 0..2 {
            assert!(!watch_step(&area, &first, &mut watch, &output), "o primeiro DESKTOP_OK nao encerra a vigia");
        }
        assert!(watch.desktop.is_some());
        for _ in 0..3 {
            assert!(!watch_step(&area, &first, &mut watch, &output), "sem o SHELL_RESTARTED a area de trabalho nao conta de novo");
        }
        assert_eq!(output.lock().unwrap().matches(DESKTOP_MARKER).count(), 1);
        output.lock().unwrap().push_str("\nSHELL_RESTARTED\n");
        let bare = wallpaper();
        for (image, why) in [(&area, "a leitura do marcador"), (&area, "a candidata"), (&bare, "sem a barra"), (&area, "a candidata de novo")] {
            assert!(!watch_step(image, &first, &mut watch, &output), "{why}");
        }
        assert!(watch_step(&area, &first, &mut watch, &output));
        assert!(watch.restarted.as_ref() == Some(&area));
        let text = output.lock().unwrap().clone();
        assert_eq!(text.matches(DESKTOP_MARKER).count(), 2, "{text}");
        assert!(text.find(RESTART_AFTER).unwrap() < text.rfind(DESKTOP_MARKER).unwrap(), "{text}");
        let saved = crate::png::read_info(&std::fs::read(directory.join("area-de-trabalho-reiniciada.png")).unwrap()).unwrap();
        assert_eq!(saved.text("opennt-resultado"), Some("area de trabalho de volta"));
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// A vigia de um teste da barra de tarefas: a área de trabalho dá o
    /// DESKTOP_OK sem encerrar a vigia; a barra só conta depois do
    /// SHELL_TRAY_CREATED, com o relógio no minuto seguinte (a leitura com o
    /// minuto novo fica de candidata e a igual a ela dá o TASKBAR_OK).
    #[test]
    fn watch_finds_the_taskbar_after_the_desktop_and_a_clock_tick() {
        use crate::screen_check::samples::*;
        let directory = scratch_dir("watch-taskbar");
        let first = directory.join("primeira-tela.png");
        let area = desktop(40, 256, true);
        let mut ticked = area.clone();
        next_minute(&mut ticked, 40);
        // Sem o SHELL_TRAY_CREATED, a barra nunca conta.
        let output = Mutex::new(String::from("EXPLORER_STARTED\n"));
        let mut watch = Watch { wants_desktop: true, wants_taskbar: true, ..Watch::default() };
        for image in [&area, &area, &area, &ticked, &ticked, &ticked] {
            assert!(!watch_step(image, &first, &mut watch, &output));
        }
        assert!(watch.desktop.is_some() && !output.lock().unwrap().contains(TASKBAR_MARKER));
        // Com ele, a referência, o minuto novo e a confirmação.
        let output = Mutex::new(String::from("EXPLORER_STARTED\nSHELL_TRAY_CREATED\n"));
        let mut watch = Watch { wants_desktop: true, wants_taskbar: true, ..Watch::default() };
        for image in [&area, &area] {
            assert!(!watch_step(image, &first, &mut watch, &output), "o DESKTOP_OK nao encerra a vigia");
        }
        assert!(output.lock().unwrap().contains(DESKTOP_MARKER));
        assert!(!watch_step(&area, &first, &mut watch, &output), "a referencia");
        assert!(!watch_step(&ticked, &first, &mut watch, &output), "o minuto novo fica de candidato");
        assert!(watch_step(&ticked, &first, &mut watch, &output));
        assert!(watch.taskbar.as_ref() == Some(&ticked));
        let text = output.lock().unwrap().clone();
        assert_eq!(text.matches(TASKBAR_MARKER).count(), 1, "{text}");
        assert!(text.find(DESKTOP_MARKER).unwrap() < text.find(TASKBAR_MARKER).unwrap(), "{text}");
        let saved = crate::png::read_info(&std::fs::read(directory.join("barra-de-tarefas.png")).unwrap()).unwrap();
        assert_eq!(saved.text("opennt-resultado"), Some("barra de tarefas"));
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// A captura do `capturas` de uma tela já lida (a tela de logon
    /// confirmada) leva o resultado e a serial nos textos, como a do fim.
    #[test]
    fn write_capture_keeps_the_result_and_the_serial() {
        let directory = scratch_dir("write-capture");
        let target = directory.join("capturas").join("tela-de-logon.png");
        let image = crate::screen_check::samples::lock_screen(true);
        write_capture(&image, &target, &Ok(()), "LOGON_SCREEN_OK\n").unwrap();
        let info = crate::png::read_info(&std::fs::read(&target).unwrap()).unwrap();
        assert_eq!(info.text("opennt-resultado"), Some("passou"));
        assert_eq!(info.text("opennt-tela"), Some("1024x768"));
        assert_eq!(info.text("opennt-serial"), Some("LOGON_SCREEN_OK\n"));
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
