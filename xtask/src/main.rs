//! `cargo xtask` — build, imagem de disco e execução do OpenNT no QEMU.
//!
//! ```text
//! cargo xtask build      [opções de build]
//! cargo xtask run        [opções de build] [opções de máquina]
//! cargo xtask test-boot  [MARCADOR] [TIMEOUT_MS] [opções] [--keys=TEXTO] [--expect=TEXTO]... [--hold=MS]
//!                        [--build-only|--no-build [--image-dir=DIR]] [--kd=com2 --script=ARQ] [--capture=ARQ.png]
//!                        [--expect-stop] [--watch-screen]
//!                        [--expect-poweroff] [--power-cycles=N] [--allow-reboot]
//! cargo xtask test-all   [--jobs=N] [--only=ID,...] [--skip=ID,...] [--repeat=N] [--keep] [--cpu-friendly]
//! cargo xtask capturas   [--jobs=N] [--only=ID,...] [--skip=ID,...] [--keep] [--cpu-friendly]
//! cargo xtask debug      [opções] [--launch [--no-client [--headless]]] [--connect=HOST:PORTA]
//! cargo xtask status     [--reference=NTOSKRNL.EXE]
//! cargo xtask nt-types   [--check] [--pdb=ARQ]
//! ```
//!
//! Opções de build: `--release`, `--build-dir=DIR` (padrão `build`),
//! `--user-program=shell`, `--kernel-test-scope=none|all|disk-stress`, `--console-mirror`,
//! `--start-driver=NOME[,NOME...]`, `--trace-driver-api`, `--initial-process=smss`, `--storage=real|nvme`,
//! `--display=basic`, `--windows-dir=DIR`, `--pnp-root=acpi|internal` (a raiz da árvore de
//! dispositivos: o acpi.sys real, o padrão, ou o barramento PCI interno), `--kd=com2` (o
//! depurador do kernel na COM2), `--shutdown-test=poweroff|reboot` (o teste do desligamento),
//! `--usb` (também opção de máquina: a controladora xHCI com teclado e tablet USB),
//! `--memory-pressure` (o teste de pressão de memória sobre o arquivo de paginação do boot do
//! smss).
//! Fora `--release` e `--windows-dir`, elas não recompilam o kernel: vão no bloco de opções de
//! carga da imagem de boot (`build.rs`), e o `--initial-process=smss` também troca o volume
//! NTFS.
//! Opções de máquina: `--accel=auto|tcg|whpx` (o test-boot usa `auto`, o WHPX quando a máquina
//! o tem; o `run` e o `debug` usam o TCG), `--memory-mb=N`, `--smp=N`, `--kd-port=N`,
//! `--monitor-port=N` (o monitor HMP do QEMU num socket local, no `debug`)
//! (a porta TCP da COM2; `run` usa 1234 por padrão).
//! Em `--keys`, `\n` digita Enter.

// As tabelas de semente do kernel (`hive_image`) usam `alloc::`.
extern crate alloc;

mod build;
mod debug;
mod fonts;
mod hive_image;
mod host_language;
mod kernel_pe;
mod logon_screen;
mod nt_types;
mod ntfs_image;
mod png;
mod qemu;
mod service_chain;
mod side_by_side;
mod user_services;
mod windows_binaries;
mod status;
mod test_all;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

// O leitor de ELF é o do cliente do depurador (símbolos e linhas).
use kd_client::elf;
use std::time::Duration;

use build::BuildOptions;
use qemu::{MachineOptions, TestOptions};

const USAGE: &str = "uso: cargo xtask <build|run|test-boot|test-all|capturas|debug|status|nt-types> [opcoes]
  build      compila boot + kernel e monta build/os.img
  run        build + QEMU com janela (serial neste terminal)
  test-boot  build + QEMU sem tela; espera MARCADOR [TIMEOUT_MS]
  test-all   suites e todos os [[teste]] do components.toml em paralelo (cargo xtask test-all --help)
  capturas   roda cada [[teste]] e grava a tela do fim em docs/site/capturas/<id>.png (cargo xtask capturas --help)
  debug      depurador do kernel: build com --kd=com2, QEMU e o prompt do cliente
             (--connect=HOST:PORTA so conecta; --script=ARQ roda o roteiro como teste;
             --launch --no-client so compila e abre o QEMU para outro cliente, com
             --headless sem janela; o opennt-dbg --launch usa este modo)
  status     gera docs/site/*.html e docs/status/*.svg (cargo xtask status --help)
  nt-types   gera kernel/src/ntos/inc/types do PDB do ntoskrnl (cargo xtask nt-types --help)
opcoes de build:   --release --build-dir=DIR --user-program=shell
                   --kernel-test-scope=none|all|disk-stress --console-mirror --start-driver=NOME[,NOME...]
                   --trace-driver-api --initial-process=smss --storage=real|nvme --display=basic
                   --windows-dir=DIR (binarios do Windows do bundle; padrao build/windows)
                   --pnp-root=acpi|internal (raiz da arvore de dispositivos; padrao acpi)
                   --usb (controladora xHCI com teclado e tablet USB)
                   --kd=com2 (depurador do kernel na COM2)
                   --shutdown-test=poweroff|reboot (com --start-driver=ntfs: grava e desliga)
                   --memory-pressure (com --initial-process=smss: teste de pressao de memoria
                   sobre o arquivo de paginacao)
opcoes de maquina: --accel=auto|tcg|whpx (test-boot: auto = whpx quando a maquina tem; run e debug: tcg)
                   --memory-mb=N --smp=N --kd-port=N --monitor-port=N
test-boot:         --keys=TEXTO (\\n = Enter) --expect=TEXTO (repetivel)
                   --hold=MS (segue rodando MS ms sem falha depois da ultima saida)
                   --build-only (so monta a imagem do teste) --no-build (usa a imagem ja montada)
                   --image-dir=DIR (com --no-build: as imagens de DIR, com as opcoes de carga
                   deste teste numa copia do os.img em --build-dir, onde tambem ficam os logs)
                   --script=ARQ (com --kd: roteiro do cliente do depurador em paralelo)
                   --capture=ARQ.png (no fim do teste, a tela do QEMU pelo screendump do QMP)
                   --watch-screen (le a tela durante o teste; FIRST_PIXEL_OK na serial quando
                   a tela grafica mostra pixels desenhados)
                   --expect-poweroff (no fim o QEMU sai sozinho pelo desligamento ACPI)
                   --power-cycles=N (religa ate N vezes o QEMU que o convidado desligou)
                   --allow-reboot (o reinicio do convidado reinicia a maquina)
                   --expect-stop (o *** STOP do bugcheck faz parte do teste, nao e falha)
                   no --keys, {combo} vai cru ao sendkey: {ctrl_r-scroll_lock-scroll_lock}";

struct Arguments {
    command: String,
    build: BuildOptions,
    machine: MachineOptions,
    positional: Vec<String>,
    keys: Option<String>,
    expect: Vec<String>,
    hold_ms: u64,
    console_mirror_set: bool,
    /// `--build-only`: o test-boot monta a imagem e para antes do QEMU.
    build_only: bool,
    /// `--no-build`: o test-boot usa a imagem já montada em `--build-dir`.
    no_build: bool,
    /// `--image-dir=DIR` (com `--no-build`): as imagens montadas vêm de DIR;
    /// a `--build-dir` recebe a cópia do `os.img` com as opções de carga
    /// deste teste e os logs. Várias execuções dividem as mesmas imagens.
    image_dir: Option<PathBuf>,
    script: Option<String>,
    connect: Option<String>,
    /// `debug --no-client`: só o build e o QEMU (o cliente é outro).
    no_client: bool,
    /// `debug --no-client --headless`: o QEMU sem janela.
    headless: bool,
    /// `--capture=ARQ.png`: a tela do fim do test-boot.
    capture: Option<PathBuf>,
    /// `--expect-stop`: o STOP do bugcheck faz parte do teste.
    expect_stop: bool,
    /// `--watch-screen`: a vigia da tela do test-boot.
    watch_screen: bool,
    /// `--expect-poweroff`, `--power-cycles=N` e `--allow-reboot`.
    expect_poweroff: bool,
    power_cycles: u32,
    allow_reboot: bool,
}

fn parse(arguments: Vec<String>) -> Result<Arguments, String> {
    let mut iterator = arguments.into_iter();
    let command = iterator.next().ok_or_else(|| USAGE.to_string())?;
    let mut parsed = Arguments {
        command: command.clone(),
        build: BuildOptions {
            release: false,
            build_dir: PathBuf::from("build"),
            user_program: "shell".into(),
            kernel_test_scope: "none".into(),
            console_mirror: false,
            start_driver: String::new(),
            trace_driver_api: false,
            initial_process: String::new(),
            storage: String::new(),
            display: String::new(),
            windows_dir: None,
            pnp_root: String::new(),
            kd: String::new(),
            shutdown_test: String::new(),
            usb: false,
            memory_pressure: false,
        },
        // O test-boot roda no WHPX quando a máquina o tem (`auto`); o `run`
        // e o `debug` ficam no TCG, que o rastro de instruções do depurador
        // gráfico exige.
        machine: MachineOptions {
            accelerator: if command == "test-boot" { "auto" } else { "tcg" }.into(),
            memory_mb: 4096,
            smp: 4,
            kd_port: None,
            usb: false,
            monitor_port: None,
        },
        positional: Vec::new(),
        keys: None,
        expect: Vec::new(),
        hold_ms: 0,
        console_mirror_set: false,
        build_only: false,
        no_build: false,
        image_dir: None,
        script: None,
        connect: None,
        no_client: false,
        headless: false,
        capture: None,
        expect_stop: false,
        watch_screen: false,
        expect_poweroff: false,
        power_cycles: 0,
        allow_reboot: false,
    };
    for argument in iterator {
        let (name, value) = match argument.split_once('=') {
            Some((name, value)) => (name.to_string(), Some(value.to_string())),
            None => (argument.clone(), None),
        };
        let required = || value.clone().ok_or_else(|| format!("{name} exige um valor ({name}=...)"));
        match name.as_str() {
            "--release" => parsed.build.release = true,
            "--console-mirror" => {
                parsed.build.console_mirror = true;
                parsed.console_mirror_set = true;
            }
            "--build-dir" => parsed.build.build_dir = PathBuf::from(required()?),
            "--user-program" => parsed.build.user_program = required()?,
            "--kernel-test-scope" => parsed.build.kernel_test_scope = required()?,
            "--start-driver" => parsed.build.start_driver = required()?,
            "--trace-driver-api" => parsed.build.trace_driver_api = true,
            "--memory-pressure" => parsed.build.memory_pressure = true,
            "--initial-process" => parsed.build.initial_process = required()?,
            "--storage" => parsed.build.storage = required()?,
            "--display" => parsed.build.display = required()?,
            "--windows-dir" => parsed.build.windows_dir = Some(PathBuf::from(required()?)),
            "--pnp-root" => parsed.build.pnp_root = required()?,
            "--kd" => parsed.build.kd = required()?,
            "--shutdown-test" => parsed.build.shutdown_test = required()?,
            "--expect-poweroff" => parsed.expect_poweroff = true,
            "--power-cycles" => parsed.power_cycles = required()?.parse().map_err(|_| "--power-cycles invalido")?,
            "--allow-reboot" => parsed.allow_reboot = true,
            "--usb" => {
                parsed.build.usb = true;
                parsed.machine.usb = true;
            }
            "--kd-port" => parsed.machine.kd_port = Some(required()?.parse().map_err(|_| "--kd-port invalido")?),
            "--monitor-port" => parsed.machine.monitor_port = Some(required()?.parse().map_err(|_| "--monitor-port invalido")?),
            "--script" => parsed.script = Some(required()?),
            "--connect" => parsed.connect = Some(required()?),
            // O padrão do `debug`; explícito no comando que o opennt-dbg roda.
            "--launch" if parsed.command == "debug" => {}
            "--no-client" if parsed.command == "debug" => parsed.no_client = true,
            "--headless" if parsed.command == "debug" => parsed.headless = true,
            "--capture" => parsed.capture = Some(PathBuf::from(required()?)),
            "--expect-stop" => parsed.expect_stop = true,
            "--watch-screen" => parsed.watch_screen = true,
            "--accel" => parsed.machine.accelerator = required()?,
            "--memory-mb" => {
                parsed.machine.memory_mb = required()?.parse().map_err(|_| "--memory-mb invalido")?
            }
            "--smp" => parsed.machine.smp = required()?.parse().map_err(|_| "--smp invalido")?,
            "--keys" => parsed.keys = Some(required()?.replace("\\n", "\n")),
            "--expect" => parsed.expect.push(required()?),
            "--hold" => parsed.hold_ms = required()?.parse().map_err(|_| "--hold invalido")?,
            "--build-only" => parsed.build_only = true,
            "--no-build" => parsed.no_build = true,
            "--image-dir" => parsed.image_dir = Some(PathBuf::from(required()?)),
            "--help" | "-h" => return Err(USAGE.to_string()),
            _ if name.starts_with("--") => return Err(format!("opcao desconhecida: {name}\n{USAGE}")),
            _ => parsed.positional.push(argument),
        }
    }
    if !matches!(parsed.build.initial_process.as_str(), "" | "smss") {
        return Err(format!("--initial-process aceita apenas smss ({} recebido)", parsed.build.initial_process));
    }
    if !matches!(parsed.build.storage.as_str(), "" | "real" | "nvme") {
        return Err(format!("--storage aceita real ou nvme ({} recebido)", parsed.build.storage));
    }
    if !matches!(parsed.build.pnp_root.as_str(), "" | "acpi" | "internal") {
        return Err(format!("--pnp-root aceita acpi ou internal ({} recebido)", parsed.build.pnp_root));
    }
    if !matches!(parsed.build.shutdown_test.as_str(), "" | "poweroff" | "reboot") {
        return Err(format!("--shutdown-test aceita poweroff ou reboot ({} recebido)", parsed.build.shutdown_test));
    }
    if (parsed.expect_poweroff || parsed.power_cycles > 0 || parsed.allow_reboot) && parsed.command != "test-boot" {
        return Err("--expect-poweroff, --power-cycles e --allow-reboot sao opcoes do test-boot".into());
    }
    if parsed.expect_poweroff && parsed.hold_ms > 0 {
        return Err("--expect-poweroff e --hold se excluem (a maquina desliga)".into());
    }
    if !qemu::ACCELERATORS.contains(&parsed.machine.accelerator.as_str()) {
        return Err(format!("--accel aceita {} ({} recebido)", qemu::ACCELERATORS.join(", "), parsed.machine.accelerator));
    }
    if !matches!(parsed.build.kd.as_str(), "" | "com2" | "com3" | "com4") {
        return Err(format!("--kd aceita com2, com3 ou com4 ({} recebido; a COM1 e o log do kernel)", parsed.build.kd));
    }
    if parsed.machine.memory_mb < 128 {
        return Err("--memory-mb deve cobrir o heap do kernel (minimo 128)".into());
    }
    if (parsed.build_only || parsed.no_build) && parsed.command != "test-boot" {
        return Err("--build-only e --no-build sao opcoes do test-boot".into());
    }
    if parsed.capture.is_some() && (parsed.command != "test-boot" || parsed.build_only) {
        return Err("--capture e opcao do test-boot que roda o QEMU".into());
    }
    if parsed.watch_screen && (parsed.command != "test-boot" || parsed.build_only) {
        return Err("--watch-screen e opcao do test-boot que roda o QEMU".into());
    }
    if parsed.build_only && parsed.no_build {
        return Err("--build-only e --no-build se excluem".into());
    }
    if parsed.image_dir.is_some() && !parsed.no_build {
        return Err("--image-dir e opcao do test-boot --no-build".into());
    }
    if parsed.headless && !parsed.no_client {
        return Err("--headless e opcao do debug --no-client (o prompt precisa da janela do QEMU)".into());
    }
    if parsed.no_client && (parsed.connect.is_some() || parsed.script.is_some()) {
        return Err("--no-client so abre o QEMU (sem --connect nem --script)".into());
    }
    Ok(parsed)
}

/// Opções de build de um test-boot: os testes conferem a saída do console
/// pela serial, então o espelho do console vem ligado.
fn test_build_options(arguments: &Arguments) -> BuildOptions {
    let mut options = arguments.build.clone();
    if !arguments.console_mirror_set {
        options.console_mirror = true;
    }
    options
}

/// Marcador e prazo do test-boot (posicionais; padrão `KERNEL_RS_OK` em 60 s).
fn marker_and_timeout(arguments: &Arguments) -> Result<(String, u64), String> {
    let marker = arguments.positional.first().cloned().unwrap_or_else(|| "KERNEL_RS_OK".into());
    let timeout_ms = match arguments.positional.get(1) {
        Some(text) => text.parse().map_err(|_| format!("TIMEOUT_MS invalido: {text}"))?,
        None => 60_000,
    };
    Ok((marker, timeout_ms))
}

fn execute(arguments: Arguments) -> Result<(), String> {
    match arguments.command.as_str() {
        "build" => build::build(&arguments.build).map(|_| ()),
        "run" => {
            let output = build::build(&arguments.build)?;
            let mut machine = arguments.machine.clone();
            machine.accelerator = qemu::resolve_accelerator(&machine.accelerator)?;
            if !arguments.build.kd.is_empty() && machine.kd_port.is_none() {
                machine.kd_port = Some(1234);
            }
            qemu::run(&qemu::Disks::beside(&output.image, &arguments.build.storage), &machine)
        }
        "debug" => debug_command(arguments),
        "test-boot" => {
            let options = test_build_options(&arguments);
            let (marker, timeout_ms) = marker_and_timeout(&arguments)?;
            let build_dir = build::in_workspace(&options.build_dir);
            // A pasta das imagens montadas (o kernel, o volume NTFS e o
            // kernel.elf dos símbolos).
            let images = arguments.image_dir.as_deref().map_or_else(|| build_dir.clone(), build::in_workspace);
            let image = if arguments.no_build {
                let source = images.join("os.img");
                if !source.is_file() {
                    return Err(format!(
                        "--no-build: {} nao existe (monte antes com o mesmo test-boot e --build-only)",
                        source.display()
                    ));
                }
                let image = build_dir.join("os.img");
                if images != build_dir {
                    std::fs::create_dir_all(&build_dir).map_err(|error| format!("{}: {error}", build_dir.display()))?;
                    std::fs::copy(&source, &image).map_err(|error| format!("{}: {error}", image.display()))?;
                }
                // As opções de carga deste teste, sobre as do build.
                build::stamp_load_options(&image, &options)?;
                image
            } else {
                build::build(&options)?.image
            };
            if arguments.build_only {
                return Ok(());
            }
            let log = build_dir.join("serial.log");
            let mut machine = arguments.machine.clone();
            machine.accelerator = qemu::resolve_accelerator(&machine.accelerator)?;
            if !options.kd.is_empty() && machine.kd_port.is_none() {
                machine.kd_port = Some(qemu::free_port()?);
            }
            let session = script_session(&arguments, &options, &machine, &images)?;
            // O volume de dados fica como o build o deixou: cada teste começa
            // dele, e execuções paralelas dividem o mesmo arquivo.
            let ntfs = images.join("ntfs.img");
            let nvme = qemu::nvme_disk(&images.join("os.img"), &options.storage);
            let disks = qemu::Disks { boot: image, data: ntfs.exists().then_some(ntfs), data_snapshot: true, nvme, nvme_snapshot: true };
            qemu::test_boot(
                &disks,
                &machine,
                &TestOptions {
                    marker,
                    timeout: Duration::from_millis(timeout_ms),
                    keys: arguments.keys,
                    expect: arguments.expect,
                    hold: Duration::from_millis(arguments.hold_ms),
                    capture: arguments.capture.map(|path| if path.is_absolute() { path } else { build::workspace_root().join(path) }),
                    expect_stop: arguments.expect_stop,
                    power_cycles: arguments.power_cycles,
                    allow_reboot: arguments.allow_reboot,
                    expect_poweroff: arguments.expect_poweroff,
                    watch_screen: arguments.watch_screen,
                },
                &log,
                session,
            )
        }
        other => Err(format!("comando desconhecido: {other}\n{USAGE}")),
    }
}

/// `test-boot --kd=com2 --script=ARQ`: o roteiro do cliente do depurador
/// roda contra a COM2 em paralelo ao teste (a falha dele derruba o teste).
fn script_session(arguments: &Arguments, options: &BuildOptions, machine: &MachineOptions, images: &Path) -> Result<Option<qemu::Session>, String> {
    let Some(script) = &arguments.script else { return Ok(None) };
    let (Some(port), false) = (machine.kd_port, options.kd.is_empty()) else {
        return Err("--script exige --kd=com2 (o depurador do kernel)".into());
    };
    let root = build::workspace_root();
    let path = if Path::new(script).is_absolute() { PathBuf::from(script) } else { root.join(script) };
    let text = std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let elf = debug::kernel_elf(images);
    let address = format!("127.0.0.1:{port}");
    Ok(Some(Box::new(move |serial| debug::run_script(&address, &root, &elf, &text, Some(serial)))))
}

/// `cargo xtask debug`: conecta a um QEMU aberto (`--connect`), roda um
/// roteiro como teste (`--script`, o mesmo do `test-boot --kd=com2
/// --script`) ou abre o QEMU e o prompt do cliente.
fn debug_command(arguments: Arguments) -> Result<(), String> {
    let root = build::workspace_root();
    let build_dir = if arguments.build.build_dir.is_absolute() { arguments.build.build_dir.clone() } else { root.join(&arguments.build.build_dir) };
    let elf = debug::kernel_elf(&build_dir);
    if let Some(address) = &arguments.connect {
        return match &arguments.script {
            Some(script) => {
                let text = std::fs::read_to_string(script).map_err(|error| format!("{script}: {error}"))?;
                debug::run_script(address, &root, &elf, &text, None)
            }
            None => debug::interactive(address, &root, &elf),
        };
    }
    let mut options = arguments.build.clone();
    if options.kd.is_empty() {
        options.kd = "com2".into();
    }
    let mut machine = arguments.machine.clone();
    machine.accelerator = qemu::resolve_accelerator(&machine.accelerator)?;
    let port = match machine.kd_port {
        Some(port) => port,
        None => qemu::free_port()?,
    };
    machine.kd_port = Some(port);
    let address = format!("127.0.0.1:{port}");
    if arguments.script.is_some() {
        // O teste com roteiro é o test-boot com o depurador.
        let mut arguments = arguments;
        arguments.command = "test-boot".into();
        arguments.build.kd = options.kd;
        arguments.machine.kd_port = Some(port);
        return execute(arguments);
    }
    let output = build::build(&options)?;
    let log = output.image.with_file_name("serial.log");
    if arguments.no_client {
        let qemu = qemu::spawn(&qemu::Disks::beside(&output.image, &options.storage), &machine, &log, !arguments.headless)?;
        let monitor = machine.monitor_port.map(|port| format!("127.0.0.1:{port}"));
        let result = debug::serve(qemu, &address, monitor.as_deref());
        qemu::remove_temp_dir(&qemu::temp_dir_beside(&log));
        return result;
    }
    let mut qemu = qemu::spawn(&qemu::Disks::beside(&output.image, &options.storage), &machine, &log, true)?;
    let result = debug::interactive(&address, &root, &elf);
    let _ = qemu.kill();
    let _ = qemu.wait();
    qemu::remove_temp_dir(&qemu::temp_dir_beside(&log));
    result
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    // `status`, `nt-types`, `test-all` e `capturas` têm opções próprias; os dois
    // primeiros não compilam o kernel.
    let result = match arguments.first().map(String::as_str) {
        Some("status") => status::run(&arguments[1..]),
        Some("nt-types") => nt_types::run(&arguments[1..]),
        Some("test-all") => test_all::run(&arguments[1..]),
        Some("capturas") => test_all::capture(&arguments[1..]),
        _ => parse(arguments).and_then(execute),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
