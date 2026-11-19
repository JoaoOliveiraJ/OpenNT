//! `opennt-dbg`: o depurador gráfico do kernel do OpenNT.
//!
//! ```text
//! cargo run -p kd-gui --release -- --launch              build com --kd=com2, QEMU e a janela
//! cargo run -p kd-gui --release -- --connect=127.0.0.1:1234   a um `cargo xtask run --kd=com2`
//! cargo run -p kd-gui --release -- --launch --initial-process=smss --display=basic
//! cargo run -p kd-gui --release -- --launch --screenshot=docs/screenshots/kd-gui.png --scenario=driver
//! ```

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use eframe::egui;
use egui_dock::{DockState, NodeIndex};
use kd_client::commands::TraceOptions;
use kd_gui::app::{DebuggerApp, Tab};
use kd_gui::backend::{Backend, Config, Request, Status, Target};
use kd_gui::launcher::{self, LaunchOptions};
use kd_gui::session::SessionFile;
use kd_gui::{offscreen, scenario};

const USAGE: &str = "uso: opennt-dbg [opcoes] [opcoes do xtask]
  --launch               compila com --kd=com2 e abre o QEMU (cargo xtask debug --launch --no-client)
  --connect=HOST:PORTA   conecta a um QEMU aberto (cargo xtask run --kd=com2: 127.0.0.1:1234;
                         aceita so a porta ou a linha \"KD_READY 127.0.0.1:PORTA\" do xtask)
  --build-dir=DIR        diretorio de build (padrao build): kernel.elf, serial.log
  --serial-log=ARQ       o log da COM1 a acompanhar (padrao DIR/serial.log; o --launch usa o do build)
  --headless-qemu        com --launch: o QEMU sem janela
  --root=DIR             raiz do repositorio (padrao: a deste checkout)
  --script=ARQ           roteiro do kd para rodar depois do attach (a linguagem do --script do
                         cargo xtask test-boot --kd=com2; menu Roteiro)
  --session=ARQ          sessao salva (menu Sessao): breakpoints, expressoes, memoria e as opcoes
                         de abertura; com --launch, abre com as opcoes do xtask dela (as da linha
                         de comando, quando houver, valem no lugar)
  --screenshot=ARQ.png   sem janela: espera a parada, desenha a janela fora da tela e sai
  --scenario=NOME        com --screenshot: breakpoint (padrao), driver, trace ou bugcheck
  --break-at=EXPR        com --screenshot: breakpoint e continuar antes da captura
  --size=LxA             tamanho da captura (padrao 1600x1000)
  outras --opcoes vao para o xtask (--accel=whpx, --smp=2, --start-driver=NOME...)";

struct Options {
    launch: bool,
    connect: Option<String>,
    build_dir: PathBuf,
    /// O `--build-dir` veio da linha de comando (senão vale o da sessão).
    build_dir_given: bool,
    serial_log: Option<PathBuf>,
    session: Option<PathBuf>,
    /// O roteiro do kd que roda depois do attach (`--script`).
    script: Option<PathBuf>,
    /// O endereço de um QEMU de fora salvo na sessão (vai ao campo Conectar).
    session_connect: Option<String>,
    headless: bool,
    root: PathBuf,
    screenshot: Option<PathBuf>,
    scenario: String,
    break_at: Option<String>,
    size: [u32; 2],
    extra: Vec<String>,
}

fn parse(arguments: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut options = Options { launch: false, connect: None, build_dir: PathBuf::from("build"), build_dir_given: false, serial_log: None, session: None, script: None, session_connect: None, headless: false, root: kd_gui::workspace_root(), screenshot: None, scenario: "breakpoint".into(), break_at: None, size: [1600, 1000], extra: Vec::new() };
    for argument in arguments {
        let (name, value) = match argument.split_once('=') {
            Some((name, value)) => (name.to_string(), Some(value.to_string())),
            None => (argument.clone(), None),
        };
        let required = || value.clone().ok_or_else(|| format!("{name} exige um valor ({name}=...)"));
        match name.as_str() {
            "--launch" => options.launch = true,
            "--connect" => options.connect = Some(launcher::parse_connect_address(&required()?)?),
            "--build-dir" => {
                options.build_dir = PathBuf::from(required()?);
                options.build_dir_given = true;
            }
            "--serial-log" => options.serial_log = Some(PathBuf::from(required()?)),
            "--session" => options.session = Some(PathBuf::from(required()?)),
            "--script" => options.script = Some(PathBuf::from(required()?)),
            "--headless-qemu" => options.headless = true,
            "--root" => options.root = PathBuf::from(required()?),
            "--screenshot" => options.screenshot = Some(PathBuf::from(required()?)),
            "--scenario" => options.scenario = required()?,
            "--break-at" => options.break_at = Some(required()?),
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
    if options.screenshot.is_some() && !options.launch && options.connect.is_none() {
        return Err("--screenshot precisa de --launch ou --connect".into());
    }
    if !["breakpoint", "driver", "trace", "bugcheck"].contains(&options.scenario.as_str()) {
        return Err(format!("--scenario desconhecido: {}\n{USAGE}", options.scenario));
    }
    Ok(options)
}

fn main() -> ExitCode {
    let mut options = match parse(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::FAILURE;
        }
    };
    // A sessão salva só na janela (a captura começa limpa).
    let saved_session = match options.session.as_ref().filter(|_| options.screenshot.is_none()) {
        Some(path) => {
            let path = if path.is_absolute() { path.clone() } else { options.root.join(path) };
            match SessionFile::load(&path) {
                Ok(session) => Some(session),
                Err(message) => {
                    eprintln!("{message}");
                    return ExitCode::FAILURE;
                }
            }
        }
        None => None,
    };
    if let Some(session) = &saved_session {
        if options.extra.is_empty() {
            options.extra = session.xtask.clone();
        }
        if !options.build_dir_given && !session.build_dir.is_empty() {
            options.build_dir = PathBuf::from(&session.build_dir);
        }
        options.headless |= session.headless;
        if options.connect.is_none() && !session.connect.is_empty() && !options.launch {
            // O endereço da sessão fica no campo Conectar (sem conectar sozinho).
            options.session_connect = Some(session.connect.clone());
        }
    }
    let launch = LaunchOptions { root: options.root.clone(), build_dir: options.build_dir.clone(), headless: options.headless || options.screenshot.is_some(), extra: options.extra.clone() };
    // A sessão (os breakpoints) só na janela: a captura começa limpa.
    let session = options.screenshot.is_none().then(|| launch.build_path().join("opennt-dbg").join("breakpoints.txt"));
    // O log da COM1: o pedido (relativo à raiz) ou o do diretório de build,
    // o de um QEMU de fora (o backend troca pelo do build no --launch e numa
    // conexão aberta pela janela).
    let serial_log = Some(options.serial_log.clone().map(|path| if path.is_absolute() { path } else { options.root.join(path) }).unwrap_or_else(|| launch.build_path().join("serial.log")));
    let config = Config { root: options.root.clone(), elf: launch.build_path().join("kernel.elf"), serial_log, session };
    let target = if options.launch {
        Some(Target::Launch(launch.clone()))
    } else {
        options.connect.clone().map(Target::Connect)
    };
    let result = match &options.screenshot {
        Some(path) => screenshot(config, target, &options, path),
        None => window(config, target, launch, &options, saved_session),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn window(config: Config, target: Option<Target>, launch: LaunchOptions, options: &Options, session: Option<SessionFile>) -> Result<(), String> {
    let connect = options.connect.clone().or_else(|| options.session_connect.clone()).unwrap_or_else(|| "127.0.0.1:1234".to_string());
    let script = options.script.clone();
    let native = eframe::NativeOptions { viewport: egui::ViewportBuilder::default().with_title("opennt-dbg - depurador do kernel do OpenNT").with_inner_size([1600.0, 1000.0]), ..Default::default() };
    eframe::run_native(
        "opennt-dbg",
        native,
        Box::new(move |creation| {
            kd_gui::configure(&creation.egui_ctx);
            let context = creation.egui_ctx.clone();
            let backend = Backend::start(config, target, Arc::new(move || context.request_repaint()));
            let mut app = DebuggerApp::new(backend, Some(launch), connect);
            if let Some(path) = kd_gui::app::state_path() {
                app = app.with_persistence(path);
            }
            // Depois do estado salvo: as expressões da sessão valem no lugar
            // das da última execução.
            if let Some(session) = &session {
                app.apply_session(session);
            }
            // O roteiro vai na fila depois dos breakpoints da sessão: roda
            // depois do attach (sem alvo, a mensagem pede para abrir ou
            // conectar).
            if let Some(path) = script {
                app.queue(Request::RunScriptFile(path));
            }
            Ok(Box::new(app))
        }),
    )
    .map_err(|error| format!("janela: {error}"))
}

/// `--screenshot`: sem janela, até a parada do cenário pedido, e a janela
/// desenhada fora da tela num PNG.
fn screenshot(config: Config, target: Option<Target>, options: &Options, path: &std::path::Path) -> Result<(), String> {
    let backend = Backend::start(config, target, Arc::new(|| {}));
    let log = |text: &str| eprintln!("[opennt-dbg] {text}");
    scenario::wait(&backend, "a primeira parada (attach)", Duration::from_secs(1800), &log, |shared| shared.status == Status::Stopped && shared.activity.is_empty())?;
    let mut watches = Vec::new();
    let mut focus = None;
    match options.scenario.as_str() {
        "driver" => {
            let module = scenario::stop_inside_driver(&backend, &log)?;
            scenario::wait_for_driver_symbols(&backend, &module, &log);
            watches.push("@rcx".to_string());
            watches.push("(_KPCR*)@gs_base".to_string());
            backend.send(Request::ShowMemory("@rsp".into()));
            backend.send(Request::Command("k 10".into()));
        }
        "trace" => {
            scenario::stop_at(&backend, options.break_at.as_deref().unwrap_or("kernel::ntos::ke::run_kernel_tasks"), &log)?;
            let generation = backend.shared().trace_generation;
            backend.send(Request::Trace(TraceOptions { count: 4000, ..Default::default() }));
            scenario::wait(&backend, "o rastro", Duration::from_secs(900), &log, |shared| shared.trace_generation > generation && shared.activity.is_empty())?;
            focus = Some(Tab::Trace);
        }
        "bugcheck" => {
            scenario::trigger_bugcheck(&backend, &log)?;
            focus = Some(Tab::Bugcheck);
        }
        _ => {
            if let Some(expression) = &options.break_at {
                scenario::stop_at(&backend, expression, &log)?;
            }
            backend.send(Request::ShowMemory("%rsp".into()));
            backend.send(Request::Command("bt 6".into()));
            backend.send(Request::Command("cpus".into()));
        }
    }
    let before = backend.shared().snapshot.generation;
    backend.send(Request::SetWatches(watches.clone()));
    backend.send(Request::Refresh);
    scenario::wait(&backend, "os paineis", Duration::from_secs(300), &log, |shared| shared.snapshot.generation > before && shared.activity.is_empty())?;
    let mut app = DebuggerApp::new(backend, None, String::new());
    app.set_watches(watches);
    if let Some(tab) = focus {
        app.focus(tab);
    }
    if focus == Some(Tab::Trace) {
        // O rastro no centro, com a desmontagem e a pilha ao lado.
        let mut dock = DockState::new(vec![Tab::Trace, Tab::Command]);
        let surface = dock.main_surface_mut();
        let [_, right] = surface.split_right(NodeIndex::root(), 0.70, vec![Tab::Disassembly, Tab::Source]);
        surface.split_below(right, 0.55, vec![Tab::CallStack, Tab::Registers]);
        app.set_layout(dock);
        // Um registro com operando de memória (o detalhe mostra o valor).
        let index = app.backend.shared().trace.as_ref().and_then(|trace| {
            trace.trace.records.iter().position(|record| trace.info(record.rip).is_some_and(|info| info.text.contains('[') && !info.text.starts_with("lea") && !info.text.starts_with("nop")))
        });
        app.select_trace_record(index.unwrap_or(0));
    }
    let image = offscreen::render(&mut app, options.size, 8);
    offscreen::save_png(&image, path)?;
    log(&format!("captura em {}", path.display()));
    Ok(())
}
