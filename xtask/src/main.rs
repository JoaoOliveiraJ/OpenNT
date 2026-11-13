//! `cargo xtask` — build, imagem de disco e execução do OpenNT no QEMU.
//!
//! ```text
//! cargo xtask build      [opções de build]
//! cargo xtask run        [opções de build] [opções de máquina]
//! cargo xtask test-boot  [MARCADOR] [TIMEOUT_MS] [opções] [--keys=TEXTO] [--expect=TEXTO]...
//! cargo xtask status     [--reference=NTOSKRNL.EXE]
//! ```
//!
//! Opções de build: `--release`, `--build-dir=DIR` (padrão `build`),
//! `--user-program=shell`, `--kernel-test-scope=none|all`, `--console-mirror`,
//! `--start-driver=NOME`.
//! Opções de máquina: `--accel=tcg|whpx`, `--memory-mb=N`, `--smp=N`.
//! Em `--keys`, `\n` digita Enter.

mod build;
mod elf;
mod kernel_pe;
mod ntfs_image;
mod qemu;
mod windows_binaries;
mod status;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use build::BuildOptions;
use qemu::{MachineOptions, TestOptions};

const USAGE: &str = "uso: cargo xtask <build|run|test-boot|status> [opcoes]
  build      compila boot + kernel e monta build/os.img
  run        build + QEMU com janela (serial neste terminal)
  test-boot  build + QEMU sem tela; espera MARCADOR [TIMEOUT_MS]
  status     gera docs/site/*.html e docs/status/*.svg (cargo xtask status --help)
opcoes de build:   --release --build-dir=DIR --user-program=shell
                   --kernel-test-scope=none|all --console-mirror --start-driver=NOME
                   --trace-driver-api
opcoes de maquina: --accel=tcg|whpx --memory-mb=N --smp=N
test-boot:         --keys=TEXTO (\\n = Enter) --expect=TEXTO (repetivel)";

struct Arguments {
    command: String,
    build: BuildOptions,
    machine: MachineOptions,
    positional: Vec<String>,
    keys: Option<String>,
    expect: Vec<String>,
    console_mirror_set: bool,
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
        },
        machine: MachineOptions { accelerator: "tcg".into(), memory_mb: 4096, smp: 4 },
        positional: Vec::new(),
        keys: None,
        expect: Vec::new(),
        console_mirror_set: false,
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
            "--accel" => parsed.machine.accelerator = required()?,
            "--memory-mb" => {
                parsed.machine.memory_mb = required()?.parse().map_err(|_| "--memory-mb invalido")?
            }
            "--smp" => parsed.machine.smp = required()?.parse().map_err(|_| "--smp invalido")?,
            "--keys" => parsed.keys = Some(required()?.replace("\\n", "\n")),
            "--expect" => parsed.expect.push(required()?),
            "--help" | "-h" => return Err(USAGE.to_string()),
            _ if name.starts_with("--") => return Err(format!("opcao desconhecida: {name}\n{USAGE}")),
            _ => parsed.positional.push(argument),
        }
    }
    if parsed.machine.memory_mb < 128 {
        return Err("--memory-mb deve cobrir o heap do kernel (minimo 128)".into());
    }
    Ok(parsed)
}

fn execute(arguments: Arguments) -> Result<(), String> {
    match arguments.command.as_str() {
        "build" => build::build(&arguments.build).map(|_| ()),
        "run" => {
            let output = build::build(&arguments.build)?;
            qemu::run(&output.image, &arguments.machine)
        }
        "test-boot" => {
            let mut options = arguments.build.clone();
            // Os testes conferem a saída do console pela serial.
            if !arguments.console_mirror_set {
                options.console_mirror = true;
            }
            let marker = arguments.positional.first().cloned().unwrap_or_else(|| "KERNEL_RS_OK".into());
            let timeout_ms: u64 = match arguments.positional.get(1) {
                Some(text) => text.parse().map_err(|_| format!("TIMEOUT_MS invalido: {text}"))?,
                None => 60_000,
            };
            let output = build::build(&options)?;
            let log = output.image.with_file_name("serial.log");
            qemu::test_boot(
                &output.image,
                &arguments.machine,
                &TestOptions {
                    marker,
                    timeout: Duration::from_millis(timeout_ms),
                    keys: arguments.keys,
                    expect: arguments.expect,
                },
                &log,
            )
        }
        other => Err(format!("comando desconhecido: {other}\n{USAGE}")),
    }
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    // `status` tem opções próprias e não compila o kernel.
    let result = match arguments.first().map(String::as_str) {
        Some("status") => status::run(&arguments[1..]),
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
