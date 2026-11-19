//! `cargo xtask` — build, imagem de disco e execução do OpenNT no QEMU.
//!
//! ```text
//! cargo xtask build      [opções de build]
//! cargo xtask run        [opções de build] [opções de máquina]
//! cargo xtask test-boot  [MARCADOR] [TIMEOUT_MS] [opções] [--keys=TEXTO] [--expect=TEXTO]... [--hold=MS]
//!                        [--build-only|--no-build [--image-dir=DIR]] [--kd=com2 --script=ARQ] [--capture=ARQ.png]
//!                        [--expect-stop] [--watch-screen] [--capture-every=SEGUNDOS]
//!                        [--expect-poweroff] [--power-cycles=N] [--allow-reboot]
//! cargo xtask test-all   [--jobs=N] [--only=ID,...] [--skip=ID,...] [--repeat=N] [--keep] [--cpu-friendly]
//! cargo xtask capturas   [--jobs=N] [--only=ID,...] [--skip=ID,...] [--keep] [--cpu-friendly]
//! cargo xtask debug      [opções] [--launch [--no-client [--headless]]] [--connect=HOST:PORTA]
//!                        [--vm-snapshots | --record=ARQ | --replay=ARQ [--gdb-port=N]]
//! cargo xtask status     [--reference=NTOSKRNL.EXE]
//! cargo xtask heap-census [--build-dir=DIR] [--all] [SERIAL.LOG]
//! cargo xtask nt-types   [--check] [--pdb=ARQ]
//! ```
//!
//! Opções de build: `--release`, `--build-dir=DIR` (padrão `build`),
//! `--user-program=shell`, `--kernel-test-scope=none|all|disk-stress`, `--console-mirror`,
//! `--start-driver=NOME[,NOME...]`, `--trace-driver-api`, `--trace-rpc` (cada mensagem ALPC das
//! portas de servidor na serial, com a interface e o opnum dos pedidos LRPC), `--heap-census`
//! (o censo do heap do kernel na serial a cada 4 MB a mais de uso),
//! `--initial-process=smss`, `--storage=real|nvme`,
//! `--display=basic`, `--windows-dir=DIR`, `--pnp-root=acpi|internal` (a raiz da árvore de
//! dispositivos: o acpi.sys real, o padrão, ou o barramento PCI interno), `--kd=com2` (o
//! depurador do kernel na COM2), `--shutdown-test=poweroff|reboot` (o teste do desligamento),
//! `--usb` (também opção de máquina: a controladora xHCI com teclado e tablet USB),
//! `--net` (também opção de máquina: a placa de rede e1000 com a rede de modo usuário do QEMU),
//! `--tpm` (também opção de máquina: um TPM 2.0 tpm-crb sobre o simulador de TPM, em
//! `run` e `test-boot`),
//! `--memory-pressure` (o teste de pressão de memória sobre o arquivo de paginação do boot do
//! smss).
//! O kernel dos builds comuns leva só as tabelas de linha do DWARF; o `debug` compila o perfil
//! `depuracao`, com o DWARF completo (as variáveis locais dos depuradores gráficos).
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
mod heap_census;
mod hive_image;
mod host_language;
mod kernel_pe;
mod logon_screen;
mod nt_types;
mod ntfs_image;
mod png;
mod qcow2;
mod qemu;
mod screen_check;
mod service_chain;
mod side_by_side;
mod theme;
mod user_services;
mod window_manager;
mod windows_binaries;
mod status;
mod test_all;
mod time_travel;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

// O leitor de ELF é o do cliente do depurador (símbolos e linhas).
use kd_client::elf;
use std::time::Duration;

use build::BuildOptions;
use qemu::{MachineOptions, TestOptions};

const USAGE: &str = "uso: cargo xtask <build|run|test-boot|test-all|capturas|debug|status|nt-types|heap-census> [opcoes]
  build      compila boot + kernel e monta build/os.img
  run        build + QEMU com janela (serial neste terminal)
  test-boot  build + QEMU sem tela; espera MARCADOR [TIMEOUT_MS]
  test-all   suites e todos os [[teste]] do components.toml em paralelo (cargo xtask test-all --help)
  capturas   roda cada [[teste]] e grava a tela do fim em docs/site/capturas/<id>.png (cargo xtask capturas --help)
  debug      depurador do kernel: build com --kd=com2, QEMU e o prompt do cliente
             (--connect=HOST:PORTA so conecta; --script=ARQ roda o roteiro como teste;
             --launch --no-client so compila e abre o QEMU para outro cliente, com
             --headless sem janela; o opennt-dbg --launch usa este modo;
             --vm-snapshots discos em overlays qcow2 para o savevm/loadvm;
             --record=ARQ grava a execucao (TCG) e --replay=ARQ a reproduz com o
             gdbstub do QEMU (--gdb-port=N) e os passos para tras)
  status     gera docs/site/*.html e docs/status/*.svg (cargo xtask status --help)
  nt-types   gera kernel/src/ntos/inc/types do PDB do ntoskrnl (cargo xtask nt-types --help)
  heap-census  da nomes ao censo do heap do kernel de uma serial (cargo xtask heap-census --help)
opcoes de build:   --release --build-dir=DIR --user-program=shell
                   --kernel-test-scope=none|all|disk-stress --console-mirror --start-driver=NOME[,NOME...]
                   --trace-driver-api --initial-process=smss --storage=real|nvme --display=basic
                   --trace-rpc (cada mensagem ALPC das portas de servidor na serial, com a
                   interface e o opnum dos pedidos LRPC e o status das respostas)
                   --heap-census (censo do heap do kernel na serial a cada 4 MB a mais de uso)
                   --windows-dir=DIR (binarios do Windows do bundle; padrao build/windows)
                   --pnp-root=acpi|internal (raiz da arvore de dispositivos; padrao acpi)
                   --usb (controladora xHCI com teclado e tablet USB)
                   --net (placa de rede e1000 com a rede de modo usuario do QEMU)
                   --tpm (TPM 2.0 tpm-crb sobre o simulador de TPM; run e test-boot)
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
                   --script=ARQ (com --kd: roteiro do cliente do depurador em paralelo; a
                   transcricao da sessao fica em kd-sessao.log, ao lado do serial.log)
                   --capture=ARQ.png (no fim do teste, a tela do QEMU pelo screendump do QMP)
                   --watch-screen (le a tela durante o teste; FIRST_PIXEL_OK na serial quando
                   a tela grafica mostra pixels desenhados e LOGON_SCREEN_OK quando um quarto
                   ou mais dela esta desenhado com 8 cores ou mais)
                   --capture-every=SEGUNDOS (durante o teste, a tela do QEMU em tela-NNNN.png na
                   --build-dir: a NNNN e a dos NNNN*SEGUNDOS s desde a subida do QEMU, gravada
                   so quando mudou; no fim do teste, passando ou nao, tela-final.png)
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
    /// `--capture-every=SEGUNDOS`: as telas periódicas do test-boot.
    capture_every: Option<u64>,
    /// `--expect-poweroff`, `--power-cycles=N` e `--allow-reboot`.
    expect_poweroff: bool,
    power_cycles: u32,
    allow_reboot: bool,
    /// `debug --vm-snapshots | --record=ARQ | --replay=ARQ`.
    time_travel: Option<time_travel::Mode>,
    /// `debug --replay --gdb-port=N`: a porta do gdbstub do QEMU.
    gdb_port: Option<u16>,
}

fn parse(arguments: Vec<String>) -> Result<Arguments, String> {
    let mut iterator = arguments.into_iter();
    let command = iterator.next().ok_or_else(|| USAGE.to_string())?;
    let mut parsed = Arguments {
        command: command.clone(),
        build: BuildOptions {
            release: false,
            full_debuginfo: false,
            build_dir: PathBuf::from("build"),
            user_program: "shell".into(),
            kernel_test_scope: "none".into(),
            console_mirror: false,
            start_driver: String::new(),
            trace_driver_api: false,
            trace_rpc: false,
            heap_census: false,
            initial_process: String::new(),
            storage: String::new(),
            display: String::new(),
            windows_dir: None,
            pnp_root: String::new(),
            kd: String::new(),
            shutdown_test: String::new(),
            usb: false,
            net: false,
            memory_pressure: false,
            tpm: false,
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
            net: false,
            tpm: false,
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
        capture_every: None,
        expect_poweroff: false,
        power_cycles: 0,
        allow_reboot: false,
        time_travel: None,
        gdb_port: None,
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
            "--trace-rpc" => parsed.build.trace_rpc = true,
            "--heap-census" => parsed.build.heap_census = true,
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
            "--net" => {
                parsed.build.net = true;
                parsed.machine.net = true;
            }
            "--tpm" => {
                parsed.build.tpm = true;
                parsed.machine.tpm = true;
            }
            "--kd-port" => parsed.machine.kd_port = Some(required()?.parse().map_err(|_| "--kd-port invalido")?),
            "--monitor-port" => parsed.machine.monitor_port = Some(required()?.parse().map_err(|_| "--monitor-port invalido")?),
            "--script" => parsed.script = Some(required()?),
            "--connect" => parsed.connect = Some(required()?),
            // O padrão do `debug`; explícito no comando que o opennt-dbg roda.
            "--launch" if parsed.command == "debug" => {}
            "--no-client" if parsed.command == "debug" => parsed.no_client = true,
            "--headless" if parsed.command == "debug" => parsed.headless = true,
            "--vm-snapshots" if parsed.command == "debug" => parsed.time_travel = Some(time_travel::Mode::Snapshots),
            "--record" if parsed.command == "debug" => parsed.time_travel = Some(time_travel::Mode::Record(PathBuf::from(required()?))),
            "--replay" if parsed.command == "debug" => parsed.time_travel = Some(time_travel::Mode::Replay(PathBuf::from(required()?))),
            "--gdb-port" if parsed.command == "debug" => parsed.gdb_port = Some(required()?.parse().map_err(|_| "--gdb-port invalido")?),
            "--capture" => parsed.capture = Some(PathBuf::from(required()?)),
            "--expect-stop" => parsed.expect_stop = true,
            "--watch-screen" => parsed.watch_screen = true,
            "--capture-every" => match required()?.parse::<u64>() {
                Ok(seconds) if seconds > 0 => parsed.capture_every = Some(seconds),
                _ => return Err("--capture-every aceita um numero inteiro de segundos maior que zero".into()),
            },
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
    // Com `--build-only` a vigia não tem efeito: o test-all monta as imagens
    // com o comando inteiro do teste, e o `--watch-screen` só vale na execução.
    if parsed.watch_screen && parsed.command != "test-boot" {
        return Err("--watch-screen e opcao do test-boot".into());
    }
    if parsed.capture_every.is_some() && parsed.command != "test-boot" {
        return Err("--capture-every e opcao do test-boot".into());
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
            machine.accelerator = qemu::machine_accelerator(&machine)?;
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
            machine.accelerator = qemu::machine_accelerator(&machine)?;
            if !options.kd.is_empty() && machine.kd_port.is_none() {
                machine.kd_port = Some(qemu::free_port()?);
            }
            let session = script_session(&arguments, &options, &machine, &images, &log)?;
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
                    capture_every: arguments.capture_every.map(Duration::from_secs),
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
/// A transcrição da sessão fica ao lado do `log` (a serial).
fn script_session(arguments: &Arguments, options: &BuildOptions, machine: &MachineOptions, images: &Path, log: &Path) -> Result<Option<qemu::Session>, String> {
    let Some(script) = &arguments.script else { return Ok(None) };
    let (Some(port), false) = (machine.kd_port, options.kd.is_empty()) else {
        return Err("--script exige --kd=com2 (o depurador do kernel)".into());
    };
    let root = build::workspace_root();
    let path = if Path::new(script).is_absolute() { PathBuf::from(script) } else { root.join(script) };
    let text = std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let elf = debug::kernel_elf(images);
    let address = format!("127.0.0.1:{port}");
    let script_options = kd_client::kd_script::ScriptOptions { name: script.clone(), transcript: Some(debug::transcript_path(log)) };
    Ok(Some(Box::new(move |serial| debug::run_script(&address, &root, &elf, &text, Some(serial), &script_options))))
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
                let script_options = kd_client::kd_script::ScriptOptions { name: script.clone(), transcript: Some(debug::transcript_path(&build_dir.join("serial.log"))) };
                debug::run_script(address, &root, &elf, &text, None, &script_options)
            }
            None => debug::interactive(address, &root, &elf, arguments.machine.monitor_port.map(|port| format!("127.0.0.1:{port}")), None),
        };
    }
    let mut options = arguments.build.clone();
    if options.kd.is_empty() {
        options.kd = "com2".into();
    }
    // O depurador mostra as variáveis locais e os tipos: o DWARF completo.
    options.full_debuginfo = true;
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
    // Snapshots e gravação: os arquivos relativos ficam a partir da raiz.
    let mode = arguments.time_travel.clone().map(|mode| match mode {
        time_travel::Mode::Record(file) if file.is_relative() => time_travel::Mode::Record(root.join(file)),
        time_travel::Mode::Replay(file) if file.is_relative() => time_travel::Mode::Replay(root.join(file)),
        other => other,
    });
    let gdb_port = match (&mode, arguments.gdb_port) {
        (Some(time_travel::Mode::Replay(_)), None) => Some(qemu::free_port()?),
        (_, port) => port,
    };
    if machine.monitor_port.is_none() {
        // O prompt usa o monitor do QEMU nos snapshots (`snap`).
        machine.monitor_port = Some(qemu::free_port()?);
    }
    if let Some(time_travel::Mode::Record(file)) = &mode {
        // O prompt guarda os módulos ao lado da gravação.
        std::env::set_var("OPENNT_KD_RECORDING", file);
    }
    let disks = qemu::Disks::beside(&output.image, &options.storage);
    let spawn = |window: bool| match &mode {
        None => qemu::spawn(&disks, &machine, &log, window),
        Some(mode) => {
            let effective = time_travel::machine(&machine, mode);
            qemu::spawn_adjusted(&disks, &effective, &log, window, |base| time_travel::arguments(base, &disks, &effective, mode, gdb_port))
        }
    };
    // Na reprodução o cliente fala com o gdbstub do QEMU.
    let address = match (&mode, gdb_port) {
        (Some(time_travel::Mode::Replay(_)), Some(port)) => format!("127.0.0.1:{port}"),
        _ => address,
    };
    let monitor = machine.monitor_port.map(|port| format!("127.0.0.1:{port}"));
    if arguments.no_client {
        let qemu = spawn(!arguments.headless)?;
        if let Some(time_travel::Mode::Replay(file)) = &mode {
            println!("KD_REPLAY {}", file.display());
        }
        let result = debug::serve(qemu, &address, monitor.as_deref());
        qemu::remove_temp_dir(&qemu::temp_dir_beside(&log));
        return result;
    }
    let mut qemu = spawn(true)?;
    let replay = match &mode {
        Some(time_travel::Mode::Replay(file)) => Some(file.clone()),
        _ => None,
    };
    let result = debug::interactive(&address, &root, &elf, monitor.clone(), replay);
    debug::stop_qemu(&mut qemu, monitor.as_deref());
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
        Some("heap-census") => heap_census::run(&arguments[1..]),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_words(words: &[&str]) -> Result<Arguments, String> {
        parse(words.iter().map(|word| word.to_string()).collect())
    }

    #[test]
    fn capture_every_takes_whole_seconds_on_test_boot() {
        assert_eq!(parse_words(&["test-boot", "--capture-every=5"]).unwrap().capture_every, Some(5));
        assert_eq!(parse_words(&["test-boot"]).unwrap().capture_every, None);
        // O test-all monta as imagens com o comando inteiro do teste.
        assert_eq!(parse_words(&["test-boot", "--build-only", "--capture-every=2"]).unwrap().capture_every, Some(2));
        for bad in ["--capture-every=0", "--capture-every=-1", "--capture-every=2.5", "--capture-every=x", "--capture-every"] {
            assert!(parse_words(&["test-boot", bad]).is_err(), "{bad}");
        }
        assert!(parse_words(&["run", "--capture-every=5"]).is_err());
    }
}
