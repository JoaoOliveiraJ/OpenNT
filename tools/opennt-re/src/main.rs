//! `opennt-re`: o depurador de engenharia reversa do OpenNT.
//!
//! ```text
//! cargo run -p opennt-re --release -- --launch                 build com --kd=com2, QEMU e a janela
//! cargo run -p opennt-re --release -- --launch --initial-process=smss   com o csrss.exe real (modo usuario)
//! cargo run -p opennt-re --release -- --connect=127.0.0.1:1234  a um `cargo xtask run --kd=com2`
//! cargo run -p opennt-re --release -- --launch --screenshot-dir=docs/screenshots --scenario=kernel
//! cargo run -p opennt-re --release -- --launch --screenshot-dir=docs/screenshots --scenario=usuario
//! cargo run -p opennt-re --release -- --launch --screenshot-dir=docs/screenshots --scenario=ferramentas
//! cargo run -p opennt-re --release -- --launch --screenshot-dir=docs/screenshots --scenario=voltar
//! ```

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use eframe::egui;
use opennt_re::app::{DebuggerApp, Tab};
use opennt_re::backend::{Backend, Config, ExtraRequest, Request, SearchKind, SearchScope, Status, Target};
use opennt_re::launcher::LaunchOptions;
use opennt_re::{offscreen, scenario};

const USAGE: &str = "uso: opennt-re [opcoes] [opcoes do xtask]
  --launch               compila com --kd=com2 e abre o QEMU (cargo xtask debug --launch --no-client)
  --connect=HOST:PORTA   conecta a um QEMU aberto (cargo xtask run --kd=com2: 127.0.0.1:1234)
  --build-dir=DIR        diretorio de build (padrao build): kernel.elf, serial.log, opennt-re/
  --headless-qemu        com --launch: o QEMU sem janela
  --root=DIR             raiz do repositorio (padrao: a deste checkout)
  --script=ARQ           roteiro para rodar depois do attach (a linguagem dos roteiros do kd, a do test-boot)
  --screenshot-dir=DIR   sem janela: roda o cenario e grava as capturas kd-re-*.png em DIR
  --scenario=NOME        com --screenshot-dir: kernel (cpu, registradores, breakpoint, observacao, grafo, referencias), usuario (usuario, memoria),
                         ferramentas (api, irp, tipos, registro; com --start-driver=ntfs) ou voltar (snapshots; com --vm-snapshots)
  --size=LxA             tamanho da captura (padrao 1600x1000)
  outras --opcoes vao para o xtask (--accel=whpx, --smp=1, --initial-process=smss...)";

#[derive(Clone)]
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
    let mut options = Options { launch: false, connect: None, build_dir: PathBuf::from("build"), headless: false, root: opennt_re::workspace_root(), script: None, screenshot_dir: None, scenario: "kernel".into(), size: [1600, 1000], extra: Vec::new() };
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
    if !["kernel", "usuario", "ferramentas", "voltar"].contains(&options.scenario.as_str()) {
        return Err(format!("--scenario desconhecido: {}\n{USAGE}", options.scenario));
    }
    // O cenário de usuário precisa do csrss.exe real.
    if options.scenario == "usuario" && options.screenshot_dir.is_some() && !options.extra.iter().any(|argument| argument.starts_with("--initial-process")) {
        options.extra.push("--initial-process=smss".into());
    }
    // As ferramentas mostram o ntfs.sys real montando o volume.
    if options.scenario == "ferramentas" && options.screenshot_dir.is_some() && !options.extra.iter().any(|argument| argument.starts_with("--start-driver")) {
        options.extra.push("--start-driver=ntfs".into());
    }
    // Os snapshots precisam dos discos em qcow2.
    if options.scenario == "voltar" && options.screenshot_dir.is_some() && !options.extra.iter().any(|argument| argument == "--vm-snapshots" || argument.starts_with("--replay=") || argument.starts_with("--record=")) {
        options.extra.push("--vm-snapshots".into());
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
    // A janela volta com o tamanho, a posição e o maximizado da última vez.
    let mut viewport = egui::ViewportBuilder::default().with_title("opennt-re - depurador de engenharia reversa do OpenNT").with_inner_size([1600.0, 1000.0]);
    if let Some(geometry) = opennt_re::app::state_path().and_then(|path| opennt_re::app::saved_window(&path)) {
        let (size, position) = geometry.logical();
        viewport = viewport.with_inner_size(size).with_position(position).with_maximized(geometry.maximized);
    }
    let native = eframe::NativeOptions { viewport, ..Default::default() };
    eframe::run_native(
        "opennt-re",
        native,
        Box::new(move |creation| {
            opennt_re::configure(&creation.egui_ctx);
            let context = creation.egui_ctx.clone();
            let backend = Backend::start(config, target, Arc::new(move || context.request_repaint()));
            let mut app = DebuggerApp::new(backend, Some(launch), connect).with_notes(session_dir);
            if let Some(path) = opennt_re::app::state_path() {
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
        "ferramentas" => tools_screenshots(backend, options, directory, &log)?,
        "voltar" => time_screenshots(backend, options, directory, &log)?,
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
            // A caixa de informação da chamada escolhida.
            if call.is_some() {
                let before = backend.shared().snapshot.generation;
                backend.send(Request::SelectInstruction(call));
                scenario::wait(&backend, "a caixa de informacao", Duration::from_secs(120), &log, |shared| shared.snapshot.generation > before && shared.activity.is_empty())?;
            }
            // A desmontagem com os colchetes das funções e dos laços, os
            // comentários automáticos (a chamada com os argumentos) e o
            // destaque de um registrador.
            backend = capture(backend, options, &directory.join("kd-re-cpu.png"), |app| {
                app.annotate(rip, "volta do IoCreateDevice", "");
                if let Some(call) = call {
                    app.select_code(call);
                }
                app.highlight("rcx");
                app.focus(Tab::Cpu);
            })?;
            // Os registradores com SSE e a caixa dos argumentos x64 (mais
            // alta, para os painéis da direita caberem).
            let tall = Options { size: [options.size[0], options.size[1] + 520], ..options.clone() };
            backend = capture(backend, &tall, &directory.join("kd-re-registradores.png"), |app| {
                app.set_xmm_format(0);
                app.focus(Tab::Cpu);
            })?;
            // O editor de breakpoints na chamada.
            let target = call.unwrap_or(rip);
            backend = capture(backend, options, &directory.join("kd-re-breakpoint.png"), |app| {
                let mut form = opennt_re::editor::BreakpointForm::new(opennt_kd::BreakpointKind::Software, &format!("{target:#x}"));
                form.name = "criacao do dispositivo".into();
                form.break_condition = "@rdx != 0".into();
                form.log_text = "IoCreateDevice extensao={@rdx} nome={@r8:s}".into();
                form.log_condition = "1".into();
                form.command_text = "k 5; r rcx".into();
                form.hit_count = "2".into();
                form.single_shot = true;
                app.open_breakpoint_editor(form);
                app.select_code(target);
                app.focus(Tab::Cpu);
            })?;
            // A observação: as expressões antes e depois de um passo (o que
            // mudou em vermelho).
            let watches: Vec<String> = ["@rax", "@rcx", "@rdi", "@rsp", "poi(@rsp)", "@rip", "@eflags", "by(@rip)"].iter().map(|text| text.to_string()).collect();
            backend.send(Request::SetWatches(watches.clone()));
            refresh(&backend, &log)?;
            // Dois passos: o segundo (o `mov edi, eax` depois do retorno)
            // muda o RDI e o RIP.
            for _ in 0..2 {
                let before = backend.shared().snapshot.generation;
                backend.send(Request::StepInto);
                scenario::wait(&backend, "o passo da observacao", Duration::from_secs(120), &log, |shared| shared.snapshot.generation > before && shared.status == Status::Stopped && shared.activity.is_empty())?;
            }
            backend = capture(backend, options, &directory.join("kd-re-observacao.png"), |app| {
                app.set_watches(watches);
                app.focus(Tab::Watch);
            })?;
            scenario::show_graph(&backend, "", &log)?;
            backend = capture(backend, options, &directory.join("kd-re-grafo.png"), |app| app.focus(Tab::Graph))?;
            let base = scenario::module_base(&backend.shared(), &module).unwrap_or(rip);
            scenario::search(&backend, SearchKind::StringReferences, SearchScope::Module(base), &log)?;
            // Um filtro que tem a ver com o driver da parada.
            let filter = match module.to_ascii_lowercase().as_str() {
                "dxgkrnl" => "EDID|Monitor|GraphicsDrivers",
                "acpi" => "PNP0A0|Thermal|Windows 20",
                _ => "Registry|Device",
            };
            capture(backend, options, &directory.join("kd-re-referencias.png"), |app| {
                app.set_reference_filter(filter, true);
                app.focus(Tab::References);
            })?;
        }
    }
    Ok(())
}

/// As capturas das abas APIs, IRPs, Tipos e Registro: os monitores ligados
/// no começo do boot, a máquina até o ntfs.sys real abrir um arquivo e a
/// parada pedida.
fn tools_screenshots(backend: Backend, options: &Options, directory: &Path, log: &dyn Fn(&str)) -> Result<(), String> {
    // Na carga do ntfs.sys: o monitor só para os chamadores dele.
    let before = backend.shared().snapshot.generation;
    backend.send(Request::AddBreakpointWith(opennt_kd::client::BreakpointRequest::new(opennt_kd::BreakpointKind::Module, "ntfs.sys")));
    scenario::wait(&backend, "a parada por carga armada", Duration::from_secs(60), log, |shared| shared.snapshot.generation > before)?;
    let before = backend.shared().snapshot.generation;
    backend.send(Request::Go);
    scenario::wait(&backend, "a carga do ntfs.sys", Duration::from_secs(1800), log, |shared| shared.status == Status::Stopped && shared.snapshot.generation > before && shared.snapshot.stop.contains("modulo carregado") && shared.activity.is_empty())?;
    backend.send(Request::Extra(ExtraRequest::ApiMonitor { enable: true, modules: vec!["ntfs".into()] }));
    backend.send(Request::Extra(ExtraRequest::IrpTrace(true)));
    scenario::wait(&backend, "os monitores ligados", Duration::from_secs(300), log, |_| backend.store.lock().map(|store| store.api_enabled && store.irp_enabled).unwrap_or(false))?;
    backend.send(Request::Go);
    scenario::wait(&backend, "a maquina rodando", Duration::from_secs(60), log, |shared| shared.status == Status::Running)?;
    scenario::wait(&backend, "o arquivo aberto pelo ntfs.sys", Duration::from_secs(1800), log, |shared| shared.serial.contains("FILE_SYSTEM_MOUNT_OK"))?;
    let before = backend.shared().snapshot.generation;
    backend.send(Request::Break);
    scenario::wait(&backend, "a parada pedida", Duration::from_secs(300), log, |shared| shared.status == Status::Stopped && shared.snapshot.generation > before && shared.activity.is_empty())?;
    let (api_row, irp) = {
        let store = backend.store.lock().map_err(|_| "deposito travado")?;
        let row = store.api_rows.iter().position(|row| row.module.eq_ignore_ascii_case("ntfs") && row.name.as_ref() == "IoCreateDevice");
        let ntfs: Vec<u64> = store.driver_names.iter().filter(|(_, name)| name.to_ascii_lowercase().contains("ntfs")).map(|(&driver, _)| driver).collect();
        let irp = store.irps.iter().position(|life| life.major == 0 && life.completed && life.hops().count() >= 1 && life.drivers().iter().any(|driver| ntfs.contains(driver)));
        (row, irp)
    };
    let mut backend = capture(backend, options, &directory.join("kd-re-api.png"), |app| {
        app.set_api_filter("ntfs", "");
        if let Some(index) = api_row {
            app.select_api_row(index);
        }
        app.focus(Tab::ApiMonitor);
    })?;
    backend = capture(backend, options, &directory.join("kd-re-irp.png"), |app| {
        if let Some(index) = irp {
            app.select_irp(index);
        }
        app.focus(Tab::Irps);
    })?;
    let system = backend.shared().snapshot.processes.iter().find(|process| process.pid == 4).map(|process| process.eprocess).ok_or("sem o processo System")?;
    let expanded = ["ThreadListHead", "ThreadListHead/#0"];
    backend.send(Request::Extra(ExtraRequest::StructView { type_name: "_EPROCESS".into(), address: format!("{system:#x}"), expanded: expanded.iter().map(|key| key.to_string()).collect(), lists: Vec::new() }));
    scenario::wait(&backend, "a vista _EPROCESS", Duration::from_secs(300), log, |shared| shared.extras.struct_tree.is_some() && shared.activity.is_empty())?;
    backend = capture(backend, options, &directory.join("kd-re-tipos.png"), |app| {
        app.view_type("_EPROCESS", system, &expanded);
        app.focus(Tab::Types);
    })?;
    let path = "\\Registry\\Machine\\SYSTEM\\Select";
    let mut current = String::new();
    let mut paths = Vec::new();
    for part in path.trim_start_matches('\\').split('\\') {
        current.push('\\');
        current.push_str(part);
        paths.push(current.clone());
    }
    for path in &paths {
        backend.send(Request::Extra(ExtraRequest::RegistryKey(path.clone())));
    }
    scenario::wait(&backend, "as chaves do Registro", Duration::from_secs(300), log, |shared| paths.iter().all(|path| shared.extras.registry.contains_key(path)) && shared.activity.is_empty())?;
    backend.send(Request::Extra(ExtraRequest::RegistryValue(path.into(), "Current".into())));
    scenario::wait(&backend, "o valor Current", Duration::from_secs(120), log, |shared| shared.extras.registry_value.is_some())?;
    capture(backend, options, &directory.join("kd-re-registro.png"), |app| {
        app.set_registry_path(path);
        app.focus(Tab::Registry);
    })?;
    Ok(())
}

/// A captura da aba Snapshots: dois snapshots gravados na parada (antes e
/// depois de uns passos) e a volta ao primeiro.
fn time_screenshots(backend: Backend, options: &Options, directory: &Path, log: &dyn Fn(&str)) -> Result<(), String> {
    let snapshot = |backend: &Backend, name: &str| -> Result<(), String> {
        backend.send(Request::Extra(ExtraRequest::SnapshotSave(name.into())));
        scenario::wait(backend, &format!("o snapshot {name}"), Duration::from_secs(600), log, |shared| shared.extras.snapshots.as_ref().is_some_and(|list| list.as_ref().as_ref().is_ok_and(|list| list.iter().any(|item| item.tag == name))) && shared.activity.is_empty())
    };
    snapshot(&backend, "inicio-do-boot")?;
    for _ in 0..3 {
        let before = backend.shared().snapshot.generation;
        backend.send(Request::StepInto);
        scenario::wait_stop(&backend, "um passo", before, Duration::from_secs(120), log)?;
    }
    snapshot(&backend, "tres-passos-depois")?;
    let before = backend.shared().snapshot.generation;
    backend.send(Request::Extra(ExtraRequest::SnapshotLoad("inicio-do-boot".into())));
    scenario::wait_stop(&backend, "a volta ao snapshot", before, Duration::from_secs(600), log)?;
    backend.send(Request::Extra(ExtraRequest::SnapshotList));
    scenario::wait(&backend, "a lista de snapshots", Duration::from_secs(120), log, |shared| shared.activity.is_empty())?;
    capture(backend, options, &directory.join("kd-re-voltar.png"), |app| app.focus(Tab::Snapshots))?;
    Ok(())
}
