//! Teste de fumaça do depurador gráfico, sem janela: o backend abre o
//! OpenNT com `--kd=com2` pelo `xtask` (o mesmo `cargo xtask debug --launch
//! --no-client` do `--launch`, com o QEMU sem tela), anexa, confere
//! registradores, módulos, pilha, desmontagem e a linha de código, pede a
//! parada com a máquina rodando, arma um breakpoint no laço principal do
//! kernel, continua até ele, dá um passo por cima e um para fora, desenha a
//! janela fora da tela e fecha o QEMU.
//!
//! Abre o QEMU e leva minutos, então só roda pedido:
//! `cargo test -p kd-gui --release -- --ignored --nocapture`. Variáveis:
//! `QEMU` (o executável), `OPENNT_KD_GUI_ARGS` (opções a mais para o
//! `xtask`, como `--accel=whpx`) e `OPENNT_KD_GUI_SHOT` (onde gravar a
//! captura; padrão `target/kd-gui-smoke.png`).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kd_client::BreakpointKind;
use kd_gui::app::DebuggerApp;
use kd_gui::backend::{Backend, Config, Request, Shared, Status, Target};
use kd_gui::launcher::LaunchOptions;
use kd_gui::offscreen;

const BREAKPOINT: &str = "kernel::ntos::ke::run_kernel_tasks";

fn wait(backend: &Backend, what: &str, timeout: Duration, predicate: impl Fn(&Shared) -> bool) {
    println!("[smoke] esperando: {what}");
    let ok = backend.wait_for(timeout, |shared| predicate(shared) || matches!(shared.status, Status::Disconnected(_)));
    let shared = backend.shared();
    let transcript: Vec<String> = shared.transcript.iter().map(|entry| format!("kd> {}\n{}", entry.input, entry.output)).collect();
    assert!(ok && !matches!(shared.status, Status::Disconnected(_)), "{what}: estado {:?}\n{}\n--- xtask ---\n{}", shared.status, transcript.join("\n"), shared.launch_log);
}

/// Espera uma parada nova (snapshot mais novo que `before`).
fn wait_stop(backend: &Backend, what: &str, before: u64, timeout: Duration) {
    wait(backend, what, timeout, |shared| shared.status == Status::Stopped && shared.snapshot.generation > before && shared.activity.is_empty());
}

fn generation(backend: &Backend) -> u64 {
    backend.shared().snapshot.generation
}

fn rip(backend: &Backend) -> u64 {
    backend.shared().snapshot.registers.iter().find(|row| row.name == "rip").and_then(|row| row.value).expect("rip")
}

#[test]
#[ignore = "abre o OpenNT no QEMU (minutos): cargo test -p kd-gui --release -- --ignored"]
fn launches_breaks_and_stops_at_a_breakpoint() {
    let root = kd_gui::workspace_root();
    let extra: Vec<String> = std::env::var("OPENNT_KD_GUI_ARGS").map(|text| text.split_whitespace().map(String::from).collect()).unwrap_or_default();
    let options = LaunchOptions { root: root.clone(), build_dir: PathBuf::from("build/kd-gui"), headless: true, extra };
    let config = Config { root: root.clone(), elf: options.build_path().join("kernel.elf"), serial_log: None };
    let backend = Backend::start(config, Some(Target::Launch(options)), Arc::new(|| {}));

    // Anexar: a máquina para e o snapshot traz o estado inteiro.
    wait(&backend, "a primeira parada (build, QEMU e attach)", Duration::from_secs(1800), |shared| shared.status == Status::Stopped && shared.activity.is_empty());
    {
        let shared = backend.shared();
        let snapshot = &shared.snapshot;
        assert!(snapshot.stop.contains("SIGINT"), "{}", snapshot.stop);
        assert!(snapshot.registers.len() >= 24, "{:?}", snapshot.registers);
        assert!(snapshot.registers_editable);
        assert!(snapshot.stopped_threads.len() >= 1);
        assert!(!snapshot.processors.is_empty());
        assert!(snapshot.modules.iter().any(|module| module.symbols > 1000), "sem os simbolos do kernel: {:?}", snapshot.modules);
        assert!(!snapshot.frames.is_empty());
        assert!(!snapshot.code.lines.is_empty(), "{:?}", snapshot.code.error);
        assert!(shared.can_restart);
    }
    assert_ne!(rip(&backend), 0);

    // Parada pedida com a máquina rodando.
    backend.send(Request::Go);
    wait(&backend, "a maquina rodando", Duration::from_secs(60), |shared| shared.status == Status::Running);
    std::thread::sleep(Duration::from_millis(1500));
    let before = generation(&backend);
    backend.send(Request::Break);
    wait_stop(&backend, "a parada pedida", before, Duration::from_secs(120));
    assert!(backend.shared().snapshot.stop.contains("SIGINT"));

    // Breakpoint de software no laço principal e continuar até ele.
    backend.send(Request::AddBreakpoint(BreakpointKind::Software, BREAKPOINT.into()));
    wait(&backend, "o breakpoint armado", Duration::from_secs(60), |shared| shared.snapshot.breakpoints.len() == 1);
    let address = backend.shared().snapshot.breakpoints[0].address;
    let before = generation(&backend);
    backend.send(Request::Go);
    wait_stop(&backend, "a parada no breakpoint", before, Duration::from_secs(900));
    {
        let shared = backend.shared();
        let snapshot = &shared.snapshot;
        assert!(snapshot.stop.contains("swbreak"), "{}", snapshot.stop);
        assert!(snapshot.frames[0].name.contains("run_kernel_tasks"), "{:?}", snapshot.frames);
        assert!(snapshot.frames.iter().any(|frame| frame.name.contains("kmain")), "{:?}", snapshot.frames);
        assert!(snapshot.code.lines.iter().any(|line| line.address == address && line.label.as_deref() == Some(BREAKPOINT)), "{:?}", snapshot.code.lines.first());
        let source = snapshot.source.as_ref().unwrap_or_else(|| panic!("sem a linha de codigo: {:?}", snapshot.source_error));
        assert!(source.file.replace('\\', "/").ends_with(".rs"), "{}", source.file);
        assert!(source.text.len() >= source.line as usize);
    }
    assert_eq!(rip(&backend), address);

    // Desliga o breakpoint (fica na lista) e passa por cima / sai da função.
    let id = backend.shared().snapshot.breakpoints[0].id;
    let before = generation(&backend);
    backend.send(Request::EnableBreakpoint(id, false));
    wait(&backend, "o breakpoint desligado", Duration::from_secs(60), |shared| shared.snapshot.generation > before && !shared.snapshot.breakpoints[0].enabled);
    let before = generation(&backend);
    backend.send(Request::StepOver);
    wait_stop(&backend, "o passo por cima", before, Duration::from_secs(120));
    assert_ne!(rip(&backend), address);
    let before = generation(&backend);
    backend.send(Request::StepOut);
    wait_stop(&backend, "o passo para fora", before, Duration::from_secs(600));
    // O retorno é no laço do kmain, logo depois do `call`.
    assert!(backend.shared().snapshot.frames[0].name.starts_with("kernel::ntos::init::main::kmain+"), "{:?}", backend.shared().snapshot.frames.first());

    // Um comando do painel, a memória e a captura da janela fora da tela.
    let before = generation(&backend);
    backend.send(Request::ShowMemory("%rsp".into()));
    backend.send(Request::Command("lm".into()));
    wait(&backend, "o comando lm", Duration::from_secs(60), |shared| shared.snapshot.generation > before && shared.transcript.iter().any(|entry| entry.input == "lm" && entry.output.contains("ntoskrnl")));
    assert_eq!(backend.shared().snapshot.memory.bytes.len(), 0x200);
    let mut app = DebuggerApp::new(backend, None, String::new());
    let image = offscreen::render(&mut app, [1280, 800], 5);
    let distinct: std::collections::HashSet<_> = image.pixels.iter().step_by(97).collect();
    assert!(distinct.len() > 20, "captura sem conteudo ({} cores)", distinct.len());
    let path = std::env::var("OPENNT_KD_GUI_SHOT").map(PathBuf::from).unwrap_or_else(|_| root.join("target").join("kd-gui-smoke.png"));
    offscreen::save_png(&image, &path).unwrap();
    println!("[smoke] captura em {}", path.display());
    // Soltar a janela solta o backend: o QEMU fecha junto.
    drop(app);
}
