//! `opennt-re`: o depurador de engenharia reversa do OpenNT.
//!
//! ```text
//! cargo run -p kd-re --release -- --launch                 build com --kd=com2, QEMU e a janela
//! cargo run -p kd-re --release -- --launch --initial-process=smss   com o csrss.exe real (modo usuario)
//! cargo run -p kd-re --release -- --connect=127.0.0.1:1234  a um `cargo xtask run --kd=com2`
//! cargo run -p kd-re --release -- --launch --screenshot-dir=docs/screenshots --scenario=kernel
//! cargo run -p kd-re --release -- --launch --screenshot-dir=docs/screenshots --scenario=usuario
//! ```

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use eframe::egui;
use kd_re::app::{DebuggerApp, Tab};
use kd_re::backend::{Backend, Config, Request, SearchKind, SearchScope, Status, Target};
use kd_re::launcher::LaunchOptions;
use kd_re::{offscreen, scenario};

const USAGE: &str = "uso: opennt-re [opcoes] [opcoes do xtask]
  --launch               compila com --kd=com2 e abre o QEMU (cargo xtask debug --launch --no-client)
  --connect=HOST:PORTA   conecta a um QEMU aberto (cargo xtask run --kd=com2: 127.0.0.1:1234)
  --build-dir=DIR        diretorio de build (padrao build): kernel.elf, serial.log, opennt-re/
  --headless-qemu        com --launch: o QEMU sem janela
  --root=DIR             raiz do repositorio (padrao: a deste checkout)
  --script=ARQ           roteiro para rodar depois do attach (a linguagem da aba Script)
  --screenshot-dir=DIR   sem janela: roda o cenario e grava as capturas kd-re-*.png em DIR
  --scenario=NOME        com --screenshot-dir: kernel (cpu, grafo, referencias) ou usuario (usuario, memoria)
  --size=LxA             tamanho da captura (padrao 1600x1000)
  outras --opcoes vao para o xtask (--accel=whpx, --smp=1, --initial-process=smss...)";

struct Options {
    launch: bool,
    connect: Option<String>,
    build_dir: PathBuf,
    headless: bool,
    root: PathBuf,
    script: Option<PathBuf>,
    screenshot_dir: Option<PathBuf>,
    scenario: String,
    size: [u32; 2],
    extra: Vec<String>,
}

fn parse(arguments: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut options = Options { launch: false, connect: None, build_dir: PathBuf::from("build"), headless: false, root: kd_re::workspace_root(), script: None, screenshot_dir: None, scenario: "kernel".into(), size: [1600, 1000], extra: Vec::new() };
    for argument in arguments {
        let (name, value) = match argument.split_once('=') {
            Some((name, value)) => (name.to_string(), Some(value.to_string())),
            None => (argument.clone(), None),
        };
        let required = || value.clone().ok_or_else(|| format!("{name} exige um valor ({name}=...)"));
        match name.as_str() {
            "--launch" => options.launch = true,
            "--connect" => options.connect = Some(required()?),
            "--build-dir" => options.build_dir = PathBuf::from(required()?),
            "--headless-qemu" => options.headless = true,
            "--root" => options.root = PathBuf::from(required()?),
            "--script" => options.script = Some(PathBuf::from(required()?)),
            "--screenshot-dir" => options.screenshot_dir = Some(PathBuf::from(required()?)),
            "--scenario" => options.scenario = required()?,
            "--size" => {
                let text = required()?;
                let (width, height) = text.split_once('x').ok_or("--size=LARGURAxALTURA")?;
                options.size = [width.parse().map_err(|_| "--size invalido")?, height.parse().map_err(|_| "--size invalido")?];
            }
            "--help" | "-h" => return Err(USAGE.to_string()),
            _ if name.starts_with("--") => options.extra.push(argument),
            _ => return Err(format!("argumento inesperado: {argument}\n{USAGE}")),
        }
    }
    if options.launch && options.connect.is_some() {
        return Err("--launch e --connect se excluem".into());
    }
    if options.screenshot_dir.is_some() && !options.launch && options.connect.is_none() {
        return Err("--screenshot-dir precisa de --launch ou --connect".into());
    }
    if !["kernel", "usuario"].contains(&options.scenario.as_str()) {
        return Err(format!("--scenario desconhecido: {}\n{USAGE}", options.scenario));
    }
    // O cenário de usuário precisa do csrss.exe real.
    if options.scenario == "usuario" && options.screenshot_dir.is_some() && !options.extra.iter().any(|argument| argument.starts_with("--initial-process")) {
        options.extra.push("--initial-process=smss".into());
    }
    Ok(options)
}

fn main() -> ExitCode {
    let options = match parse(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::FAILURE;
        }
    };
    let launch = LaunchOptions { root: options.root.clone(), build_dir: options.build_dir.clone(), headless: options.headless || options.screenshot_dir.is_some(), extra: options.extra.clone() };
    // A sessão (breakpoints e notas) só na janela: a captura começa limpa.
    let session_dir = launch.build_path().join("opennt-re");
    let session = options.screenshot_dir.is_none().then(|| session_dir.join("breakpoints.txt"));
    let config = Config { root: options.root.clone(), elf: launch.build_path().join("kernel.elf"), serial_log: None, session, script: options.script.clone() };
    let target = if options.launch {
        Some(Target::Launch(launch.clone()))
    } else {
        options.connect.clone().map(Target::Connect)
    };
    let result = match &options.screenshot_dir {
        Some(directory) => screenshots(config, target, &options, directory),
        None => window(config, target, launch, &options, session_dir),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn window(config: Config, target: Option<Target>, launch: LaunchOptions, options: &Options, session_dir: PathBuf) -> Result<(), String> {
    let connect = options.connect.clone().unwrap_or_else(|| "127.0.0.1:1234".to_string());
    let native = eframe::NativeOptions { viewport: egui::ViewportBuilder::default().with_title("opennt-re - depurador de engenharia reversa do OpenNT").with_inner_size([1600.0, 1000.0]), ..Default::default() };
    eframe::run_native(
        "opennt-re",
        native,
        Box::new(move |creation| {
            kd_re::configure(&creation.egui_ctx);
            let context = creation.egui_ctx.clone();
            let backend = Backend::start(config, target, Arc::new(move || context.request_repaint()));
            let mut app = DebuggerApp::new(backend, Some(launch), connect).with_notes(session_dir);
            if let Some(path) = kd_re::app::state_path() {
                app = app.with_persistence(path);
            }
            Ok(Box::new(app))
        }),
    )
    .map_err(|error| format!("janela: {error}"))
}

/// Desenha a janela fora da tela e grava o PNG.
fn capture(backend: Backend, options: &Options, path: &Path, prepare: impl FnOnce(&mut DebuggerApp)) -> Result<Backend, String> {
    let mut app = DebuggerApp::new(backend, None, String::new());
    prepare(&mut app);
    let image = offscreen::render(&mut app, options.size, 8);
    offscreen::save_png(&image, path)?;
    eprintln!("[opennt-re] captura em {}", path.display());
    Ok(app.backend)
}

/// Espera o snapshot da parada com todas as vistas.
fn refresh(backend: &Backend, log: &dyn Fn(&str)) -> Result<(), String> {
    let before = backend.shared().snapshot.generation;
    backend.send(Request::Refresh);
    scenario::wait(backend, "os paineis", Duration::from_secs(300), log, |shared| shared.snapshot.generation > before && shared.activity.is_empty())
}

/// `--screenshot-dir`: sem janela, os cenários e as capturas.
fn screenshots(config: Config, target: Option<Target>, options: &Options, directory: &Path) -> Result<(), String> {
    std::fs::create_dir_all(directory).map_err(|error| format!("{}: {error}", directory.display()))?;
    let mut backend = Backend::start(config, target, Arc::new(|| {}));
    let log = |text: &str| eprintln!("[opennt-re] {text}");
    scenario::wait(&backend, "a primeira parada (attach)", Duration::from_secs(1800), &log, |shared| shared.status == Status::Stopped && shared.activity.is_empty())?;
    match options.scenario.as_str() {
        "usuario" => {
            scenario::stop_in_csrss(&backend, &log)?;
            backend.send(Request::ShowDump(0, "@rsp".into()));
            backend.send(Request::ShowDump(1, "@rcx".into()));
            refresh(&backend, &log)?;
            let rip = backend.shared().snapshot.registers.iter().find(|row| row.name == "rip").and_then(|row| row.value).unwrap_or(0);
            backend = capture(backend, options, &directory.join("kd-re-usuario.png"), |app| {
                app.annotate(rip, "o csrsrv carrega a DLL de servidor seguinte", "");
                app.focus(Tab::Cpu);
            })?;
            scenario::memory_map(&backend, &log)?;
            backend = capture(backend, options, &directory.join("kd-re-memoria.png"), |app| app.focus(Tab::MemoryMap))?;
            let base = scenario::module_base(&backend.shared(), "CSRSRV").unwrap_or(rip);
            scenario::search(&backend, SearchKind::StringReferences, SearchScope::Module(base), &log)?;
            capture(backend, options, &directory.join("kd-re-referencias-usuario.png"), |app| {
                app.set_reference_filter("Sessions", false);
                app.focus(Tab::References);
            })?;
        }
        _ => {
            let module = scenario::stop_inside_driver(&backend, &log)?;
            scenario::wait_for_driver_symbols(&backend, &module, &log);
            backend.send(Request::ShowDump(0, "@rsp".into()));
            backend.send(Request::ShowDump(1, "@rcx".into()));
            refresh(&backend, &log)?;
            let (rip, call) = {
                let shared = backend.shared();
                let rip = shared.snapshot.registers.iter().find(|row| row.name == "rip").and_then(|row| row.value).unwrap_or(0);
                let call = shared.snapshot.code.lines.iter().rev().find(|line| line.address < rip && line.text.starts_with("call")).map(|line| line.address);
                (rip, call)
            };
            backend = capture(backend, options, &directory.join("kd-re-cpu.png"), |app| {
                app.annotate(rip, "volta do IoCreateDevice", "");
                if let Some(call) = call {
                    app.annotate(call, "cria o dispositivo do driver", "");
                    app.select_code(call);
                }
                app.focus(Tab::Cpu);
            })?;
            scenario::show_graph(&backend, "", &log)?;
            backend = capture(backend, options, &directory.join("kd-re-grafo.png"), |app| app.focus(Tab::Graph))?;
            let base = scenario::module_base(&backend.shared(), &module).unwrap_or(rip);
            scenario::search(&backend, SearchKind::StringReferences, SearchScope::Module(base), &log)?;
            capture(backend, options, &directory.join("kd-re-referencias.png"), |app| {
                app.set_reference_filter("PNP|Thermal|Windows 20", true);
                app.focus(Tab::References);
            })?;
        }
    }
    Ok(())
}
