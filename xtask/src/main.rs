//! `cargo xtask` — build, imagem de disco e execução do OpenNT no QEMU.
//!
//! ```text
//! cargo xtask build      [opções de build]
//! cargo xtask run        [opções de build] [opções de máquina]
//! cargo xtask test-boot  [MARCADOR] [TIMEOUT_MS] [opções] [--keys=TEXTO] [--expect=TEXTO]... [--hold=MS]
//!                        [--build-only|--no-build] [--kd=com2 --script=ARQ]
//! cargo xtask test-all   [--jobs=N] [--only=ID,...] [--skip=ID,...] [--repeat=N] [--keep] [--cpu-friendly]
//! cargo xtask debug      [opções] [--connect=HOST:PORTA]
//! cargo xtask status     [--reference=NTOSKRNL.EXE]
//! cargo xtask nt-types   [--check] [--pdb=ARQ]
//! ```
//!
//! Opções de build: `--release`, `--build-dir=DIR` (padrão `build`),
//! `--user-program=shell`, `--kernel-test-scope=none|all|disk-stress`, `--console-mirror`,
//! `--start-driver=NOME[,NOME...]`, `--trace-driver-api`, `--initial-process=smss`, `--storage=real`,
//! `--display=basic`, `--windows-dir=DIR`, `--pnp-root=acpi`, `--kd=com2` (o depurador do
//! kernel na COM2).
//! Opções de máquina: `--accel=tcg|whpx`, `--memory-mb=N`, `--smp=N`, `--kd-port=N`
//! (a porta TCP da COM2; `run` usa 1234 por padrão).
//! Em `--keys`, `\n` digita Enter.

// As tabelas de semente do kernel (`hive_image`) usam `alloc::`.
extern crate alloc;

mod build;
mod debug;
mod elf;
mod hive_image;
mod kernel_pe;
mod nt_types;
mod ntfs_image;
mod qemu;
mod windows_binaries;
mod status;
mod test_all;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use build::BuildOptions;
use qemu::{MachineOptions, TestOptions};

const USAGE: &str = "uso: cargo xtask <build|run|test-boot|test-all|debug|status|nt-types> [opcoes]
  build      compila boot + kernel e monta build/os.img
  run        build + QEMU com janela (serial neste terminal)
  test-boot  build + QEMU sem tela; espera MARCADOR [TIMEOUT_MS]
  test-all   suites e todos os [[teste]] do components.toml em paralelo (cargo xtask test-all --help)
  debug      depurador do kernel: build com --kd=com2, QEMU e o prompt do cliente
             (--connect=HOST:PORTA so conecta; --script=ARQ roda o roteiro como teste)
  status     gera docs/site/*.html e docs/status/*.svg (cargo xtask status --help)
  nt-types   gera kernel/src/ntos/inc/types do PDB do ntoskrnl (cargo xtask nt-types --help)
opcoes de build:   --release --build-dir=DIR --user-program=shell
                   --kernel-test-scope=none|all|disk-stress --console-mirror --start-driver=NOME[,NOME...]
                   --trace-driver-api --initial-process=smss --storage=real --display=basic
                   --windows-dir=DIR (binarios do Windows do bundle; padrao <build-dir>/windows)
                   --pnp-root=acpi
                   --kd=com2 (depurador do kernel na COM2)
opcoes de maquina: --accel=tcg|whpx --memory-mb=N --smp=N --kd-port=N
test-boot:         --keys=TEXTO (\\n = Enter) --expect=TEXTO (repetivel)
                   --hold=MS (segue rodando MS ms sem falha depois da ultima saida)
                   --build-only (so monta a imagem do teste) --no-build (usa a imagem ja montada)
                   --script=ARQ (com --kd: roteiro do cliente do depurador em paralelo)";

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
    script: Option<String>,
    connect: Option<String>,
}

fn parse(arguments: Vec<String>) -> Result<Arguments, String> {
    let mut iterator = arguments.into_iter();
    let command = iterator.next().ok_or_else(|| USAGE.to_string())?;
    let mut parsed = Arguments {
        command,
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
        },
        machine: MachineOptions { accelerator: "tcg".into(), memory_mb: 4096, smp: 4, kd_port: None },
        positional: Vec::new(),
        keys: None,
        expect: Vec::new(),
        hold_ms: 0,
        console_mirror_set: false,
        build_only: false,
        no_build: false,
        script: None,
        connect: None,
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
            "--initial-process" => parsed.build.initial_process = required()?,
            "--storage" => parsed.build.storage = required()?,
            "--display" => parsed.build.display = required()?,
            "--windows-dir" => parsed.build.windows_dir = Some(PathBuf::from(required()?)),
            "--pnp-root" => parsed.build.pnp_root = required()?,
            "--kd" => parsed.build.kd = required()?,
            "--kd-port" => parsed.machine.kd_port = Some(required()?.parse().map_err(|_| "--kd-port invalido")?),
            "--script" => parsed.script = Some(required()?),
            "--connect" => parsed.connect = Some(required()?),
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
            "--help" | "-h" => return Err(USAGE.to_string()),
            _ if name.starts_with("--") => return Err(format!("opcao desconhecida: {name}\n{USAGE}")),
            _ => parsed.positional.push(argument),
        }
    }
    if !matches!(parsed.build.initial_process.as_str(), "" | "smss") {
        return Err(format!("--initial-process aceita apenas smss ({} recebido)", parsed.build.initial_process));
    }
    if !matches!(parsed.build.pnp_root.as_str(), "" | "acpi") {
        return Err(format!("--pnp-root aceita apenas acpi ({} recebido)", parsed.build.pnp_root));
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
    if parsed.build_only && parsed.no_build {
        return Err("--build-only e --no-build se excluem".into());
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
            if !arguments.build.kd.is_empty() && machine.kd_port.is_none() {
                machine.kd_port = Some(1234);
            }
            qemu::run(&output.image, &machine)
        }
        "debug" => debug_command(arguments),
        "test-boot" => {
            let options = test_build_options(&arguments);
            let (marker, timeout_ms) = marker_and_timeout(&arguments)?;
            let image = if arguments.no_build {
                let image = build::in_workspace(&options.build_dir).join("os.img");
                if !image.is_file() {
                    return Err(format!(
                        "--no-build: {} nao existe (monte antes com o mesmo test-boot e --build-only)",
                        image.display()
                    ));
                }
                image
            } else {
                build::build(&options)?.image
            };
            if arguments.build_only {
                return Ok(());
            }
            let log = image.with_file_name("serial.log");
            let mut machine = arguments.machine.clone();
            if !options.kd.is_empty() && machine.kd_port.is_none() {
                machine.kd_port = Some(qemu::free_port()?);
            }
            let session = script_session(&arguments, &options, &machine)?;
            qemu::test_boot(
                &image,
                &machine,
                &TestOptions {
                    marker,
                    timeout: Duration::from_millis(timeout_ms),
                    keys: arguments.keys,
                    expect: arguments.expect,
                    hold: Duration::from_millis(arguments.hold_ms),
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
fn script_session(arguments: &Arguments, options: &BuildOptions, machine: &MachineOptions) -> Result<Option<qemu::Session>, String> {
    let Some(script) = &arguments.script else { return Ok(None) };
    let (Some(port), false) = (machine.kd_port, options.kd.is_empty()) else {
        return Err("--script exige --kd=com2 (o depurador do kernel)".into());
    };
    let root = build::workspace_root();
    let path = if Path::new(script).is_absolute() { PathBuf::from(script) } else { root.join(script) };
    let text = std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let elf = debug::kernel_elf(&build::in_workspace(&options.build_dir));
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
    let mut qemu = qemu::spawn_window(&output.image, &machine, &log)?;
    let result = debug::interactive(&address, &root, &elf);
    let _ = qemu.kill();
    let _ = qemu.wait();
    result
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    // `status`, `nt-types` e `test-all` têm opções próprias; os dois
    // primeiros não compilam o kernel.
    let result = match arguments.first().map(String::as_str) {
        Some("status") => status::run(&arguments[1..]),
        Some("nt-types") => nt_types::run(&arguments[1..]),
        Some("test-all") => test_all::run(&arguments[1..]),
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
