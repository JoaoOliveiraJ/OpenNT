//! `opennt-dbg`: o depurador gráfico do kernel do OpenNT.
//!
//! ```text
//! cargo run -p kd-gui --release -- --launch              build com --kd=com2, QEMU e a janela
//! cargo run -p kd-gui --release -- --connect=127.0.0.1:1234   a um `cargo xtask run --kd=com2`
//! cargo run -p kd-gui --release -- --launch --headless-qemu \
//!     --break-at=kernel::ntos::ke::run_kernel_tasks --screenshot=docs/screenshots/kd-gui.png
//! ```

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use eframe::egui;
use kd_gui::app::DebuggerApp;
use kd_gui::backend::{Backend, Config, Request, Status, Target};
use kd_gui::launcher::LaunchOptions;
use kd_gui::offscreen;

const USAGE: &str = "uso: opennt-dbg [opcoes] [opcoes do xtask]
  --launch               compila com --kd=com2 e abre o QEMU (cargo xtask debug --launch --no-client)
  --connect=HOST:PORTA   conecta a um QEMU aberto (cargo xtask run --kd=com2: 127.0.0.1:1234)
  --build-dir=DIR        diretorio de build (padrao build): kernel.elf, serial.log
  --headless-qemu        com --launch: o QEMU sem janela
  --root=DIR             raiz do repositorio (padrao: a deste checkout)
  --screenshot=ARQ.png   sem janela: espera a parada, desenha a janela fora da tela e sai
  --break-at=EXPR        com --screenshot: breakpoint e continuar antes da captura
  --size=LxA             tamanho da captura (padrao 1600x1000)
  outras --opcoes vao para o xtask (--accel=whpx, --smp=2, --start-driver=NOME...)";

struct Options {
    launch: bool,
    connect: Option<String>,
    build_dir: PathBuf,
    headless: bool,
    root: PathBuf,
    screenshot: Option<PathBuf>,
    break_at: Option<String>,
    size: [u32; 2],
    extra: Vec<String>,
}

fn parse(arguments: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut options = Options { launch: false, connect: None, build_dir: PathBuf::from("build"), headless: false, root: kd_gui::workspace_root(), screenshot: None, break_at: None, size: [1600, 1000], extra: Vec::new() };
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
            "--screenshot" => options.screenshot = Some(PathBuf::from(required()?)),
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
    let launch = LaunchOptions { root: options.root.clone(), build_dir: options.build_dir.clone(), headless: options.headless || options.screenshot.is_some(), extra: options.extra.clone() };
    let config = Config { root: options.root.clone(), elf: launch.build_path().join("kernel.elf"), serial_log: None };
    let target = if options.launch {
        Some(Target::Launch(launch.clone()))
    } else {
        options.connect.clone().map(Target::Connect)
    };
    let result = match &options.screenshot {
        Some(path) => screenshot(config, target, &options, path),
        None => window(config, target, launch, &options),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn window(config: Config, target: Option<Target>, launch: LaunchOptions, options: &Options) -> Result<(), String> {
    let connect = options.connect.clone().unwrap_or_else(|| "127.0.0.1:1234".to_string());
    let native = eframe::NativeOptions { viewport: egui::ViewportBuilder::default().with_title("opennt-dbg - depurador do kernel do OpenNT").with_inner_size([1500.0, 950.0]), ..Default::default() };
    eframe::run_native(
        "opennt-dbg",
        native,
        Box::new(move |creation| {
            kd_gui::configure(&creation.egui_ctx);
            let context = creation.egui_ctx.clone();
            let backend = Backend::start(config, target, Arc::new(move || context.request_repaint()));
            Ok(Box::new(DebuggerApp::new(backend, Some(launch), connect)))
        }),
    )
    .map_err(|error| format!("janela: {error}"))
}

/// Espera o estado satisfazer `predicate`, mostrando o andamento.
fn wait(backend: &Backend, what: &str, timeout: Duration, predicate: impl Fn(&kd_gui::backend::Shared) -> bool) -> Result<(), String> {
    eprintln!("[opennt-dbg] esperando: {what}");
    if backend.wait_for(timeout, |shared| predicate(shared) || matches!(shared.status, Status::Disconnected(_))) {
        let shared = backend.shared();
        if let Status::Disconnected(reason) = &shared.status {
            return Err(format!("{what}: desconectado: {reason}"));
        }
        return Ok(());
    }
    Err(format!("{what}: tempo esgotado"))
}

/// `--screenshot`: sem janela, até a parada (no breakpoint pedido), e a
/// janela desenhada fora da tela num PNG.
fn screenshot(config: Config, target: Option<Target>, options: &Options, path: &std::path::Path) -> Result<(), String> {
    let backend = Backend::start(config, target, Arc::new(|| {}));
    wait(&backend, "a primeira parada (attach)", Duration::from_secs(1800), |shared| shared.status == Status::Stopped)?;
    if let Some(expression) = &options.break_at {
        backend.send(Request::AddBreakpoint(kd_client::BreakpointKind::Software, expression.clone()));
        wait(&backend, "o breakpoint armado", Duration::from_secs(60), |shared| !shared.snapshot.breakpoints.is_empty())?;
        let before = backend.shared().snapshot.generation;
        backend.send(Request::Go);
        wait(&backend, "a parada no breakpoint", Duration::from_secs(900), |shared| shared.status == Status::Stopped && shared.snapshot.generation > before && shared.snapshot.stop.contains("swbreak"))?;
    }
    // Painéis com conteúdo: a memória na pilha e dois comandos.
    let before = backend.shared().snapshot.generation;
    backend.send(Request::ShowMemory("%rsp".into()));
    backend.send(Request::Command("bt 6".into()));
    backend.send(Request::Command("cpus".into()));
    wait(&backend, "os paineis", Duration::from_secs(120), |shared| shared.snapshot.generation > before + 1 && shared.transcript.len() >= 3 && shared.activity.is_empty())?;
    let mut app = DebuggerApp::new(backend, None, String::new());
    let image = offscreen::render(&mut app, options.size, 6);
    offscreen::save_png(&image, path)?;
    eprintln!("[opennt-dbg] captura em {}", path.display());
    Ok(())
}
