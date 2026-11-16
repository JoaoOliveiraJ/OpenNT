//! Teste de fumaça do opennt-re, sem janela: o backend abre o OpenNT com
//! `--kd=com2 --initial-process=smss` pelo `xtask` (o QEMU sem tela),
//! anexa e confere:
//!
//! - o processo csrss.exe real: a parada na carga do basesrv.dll (o evento
//!   de imagem), o contexto dele (PEB, módulos da PEB.Ldr com os símbolos
//!   da ntdll), um breakpoint de usuário no ntdll!LdrLoadDll que só o
//!   csrss acerta, a pilha de usuário até o CSRSRV, as threads de usuário,
//!   os handles e o mapa de memória (VAD);
//! - o grafo de fluxo de uma função do kernel e de uma da ntdll;
//! - as referências a strings conhecidas no ACPI.sys real (ASCII e UTF-16)
//!   e no CSRSRV.dll;
//! - um roteiro;
//! - a janela desenhada fora da tela.
//!
//! Abre o QEMU e leva minutos, então só roda pedido:
//! `cargo test -p kd-re --release -- --ignored --nocapture`. Variáveis:
//! `QEMU` (o executável), `OPENNT_KD_RE_ARGS` (opções a mais para o `xtask`,
//! como `--accel=whpx`) e `OPENNT_KD_RE_SHOT` (onde gravar a captura;
//! padrão `target/kd-re-smoke.png`).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kd_re::app::{DebuggerApp, Tab};
use kd_re::backend::{Backend, Config, Request, SearchKind, SearchScope, Shared, Status, Target};
use kd_re::launcher::LaunchOptions;
use kd_re::{offscreen, scenario};

fn log(text: &str) {
    println!("[smoke] {text}");
}

fn wait(backend: &Backend, what: &str, timeout: Duration, predicate: impl Fn(&Shared) -> bool) {
    if let Err(error) = scenario::wait(backend, what, timeout, &log, predicate) {
        panic!("{error}");
    }
}

fn generation(backend: &Backend) -> u64 {
    backend.shared().snapshot.generation
}

fn ok(result: Result<(), String>) {
    if let Err(error) = result {
        panic!("{error}");
    }
}

#[test]
#[ignore = "abre o OpenNT no QEMU (minutos): cargo test -p kd-re --release -- --ignored"]
fn debugs_csrss_and_the_kernel() {
    let root = kd_re::workspace_root();
    let mut extra: Vec<String> = std::env::var("OPENNT_KD_RE_ARGS").map(|text| text.split_whitespace().map(String::from).collect()).unwrap_or_default();
    if !extra.iter().any(|argument| argument.starts_with("--initial-process")) {
        extra.push("--initial-process=smss".into());
    }
    if !extra.iter().any(|argument| argument.starts_with("--smp")) {
        extra.push("--smp=1".into());
    }
    let options = LaunchOptions { root: root.clone(), build_dir: PathBuf::from("build/kd-re"), headless: true, extra };
    let config = Config { root: root.clone(), elf: options.build_path().join("kernel.elf"), serial_log: None, session: None, script: None };
    let backend = Backend::start(config, Some(Target::Launch(options)), Arc::new(|| {}));

    // Anexar.
    wait(&backend, "a primeira parada (build, QEMU e attach)", Duration::from_secs(1800), |shared| shared.status == Status::Stopped && shared.activity.is_empty());
    {
        let shared = backend.shared();
        assert!(shared.snapshot.stop.contains("SIGINT"), "{}", shared.snapshot.stop);
        assert!(shared.snapshot.registers.len() >= 24);
        assert!(!shared.snapshot.code.lines.is_empty());
        assert_eq!(shared.snapshot.dumps.len(), 5);
        assert!(!shared.snapshot.user_mode);
    }

    // O csrss.exe real: o evento de carga, o contexto e o breakpoint de
    // usuário.
    ok(scenario::stop_in_csrss(&backend, &log));
    {
        let shared = backend.shared();
        let snapshot = &shared.snapshot;
        let process = snapshot.process.as_ref().expect("o processo da parada");
        assert_eq!(process.name.to_ascii_lowercase(), "csrss.exe", "{process:?}");
        assert_ne!(process.peb, 0, "{process:?}");
        assert!(snapshot.user_mode);
        let ntdll = snapshot.modules.iter().find(|module| module.user && module.name.eq_ignore_ascii_case("ntdll")).unwrap_or_else(|| panic!("sem a ntdll do csrss: {:?}", snapshot.modules.iter().filter(|module| module.user).collect::<Vec<_>>()));
        assert!(ntdll.symbols > 1000, "{ntdll:?}");
        assert!(snapshot.modules.iter().any(|module| module.user && module.name.eq_ignore_ascii_case("csrsrv")));
        assert!(snapshot.stop.contains("ntdll!LdrLoadDll"), "{}", snapshot.stop);
        assert!(snapshot.frames.iter().any(|frame| frame.name.to_ascii_lowercase().starts_with("csrsrv!")), "{:?}", snapshot.frames);
        assert!(snapshot.registers.iter().any(|row| row.name == "cs" && row.value == Some(0x33)));
        assert!(!snapshot.stack.is_empty());
        assert!(!snapshot.info_box.is_empty());
    }
    let before = generation(&backend);
    backend.send(Request::LoadUserThreads);
    backend.send(Request::LoadHandles);
    wait(&backend, "threads e handles do csrss", Duration::from_secs(300), |shared| shared.snapshot.generation > before && shared.snapshot.handles.is_some() && shared.snapshot.user_threads.is_some() && shared.activity.is_empty());
    {
        let shared = backend.shared();
        let threads = shared.snapshot.user_threads.as_deref().expect("threads").as_ref().expect("threads de usuario");
        assert!(threads.iter().any(|thread| thread.teb != 0 && thread.context != 0), "{threads:?}");
        let handles = shared.snapshot.handles.as_deref().expect("handles").as_ref().expect("tabela de handles");
        assert!(!handles.is_empty());
        assert!(handles.iter().any(|handle| handle.kind != "?"), "{handles:?}");
    }
    ok(scenario::memory_map(&backend, &log));
    {
        let shared = backend.shared();
        let map = shared.snapshot.memory_map.as_ref().expect("mapa");
        assert!(map.rows.iter().any(|row| row.kind == "Image" && row.name.to_ascii_lowercase().contains("csrss.exe")), "{:?}", map.rows);
        assert!(map.rows.iter().any(|row| row.kind == "Seção" && row.section == ".text"), "sem as secoes das imagens");
    }
    let csrsrv = scenario::module_base(&backend.shared(), "CSRSRV").expect("CSRSRV");
    ok(scenario::search(&backend, SearchKind::StringReferences, SearchScope::Module(csrsrv), &log));
    {
        let shared = backend.shared();
        let references = shared.snapshot.references.as_ref().expect("referencias");
        assert!(references.rows.iter().any(|row| row.text.contains("\\Sessions")), "{:?}", references.rows.iter().take(20).collect::<Vec<_>>());
    }

    // Grafos: uma função do kernel e uma da ntdll.
    ok(scenario::show_graph(&backend, "kernel::ntos::ke::run_kernel_tasks", &log));
    {
        let shared = backend.shared();
        let graph = shared.snapshot.graph.as_ref().expect("grafo");
        assert!(graph.blocks.len() >= 3, "{} blocos", graph.blocks.len());
        assert!(graph.blocks.iter().any(|block| block.edges.len() == 2), "sem desvio condicional");
        assert!(graph.layout.layers >= 2);
        assert!(graph.name.contains("run_kernel_tasks"), "{}", graph.name);
    }
    ok(scenario::show_graph(&backend, "ntdll!LdrLoadDll", &log));
    {
        let shared = backend.shared();
        let graph = shared.snapshot.graph.as_ref().expect("grafo");
        assert!(graph.blocks.len() >= 2, "{} blocos", graph.blocks.len());
        assert!(graph.current.is_some());
    }

    // Referências a strings no ACPI.sys real: ASCII e UTF-16.
    let acpi = scenario::module_base(&backend.shared(), "ACPI").expect("o ACPI.sys carregado");
    ok(scenario::search(&backend, SearchKind::StringReferences, SearchScope::Module(acpi), &log));
    {
        let shared = backend.shared();
        let references = shared.snapshot.references.as_ref().expect("referencias");
        assert!(references.rows.len() > 100, "{} referencias", references.rows.len());
        assert!(references.rows.iter().any(|row| row.text == "\"PNP0A03\"" && row.disassembly.starts_with("lea")), "sem PNP0A03");
        assert!(references.rows.iter().any(|row| row.text.starts_with("L\"") && row.text.contains("Thermal")), "sem a string UTF-16");
        assert!(references.rows.iter().all(|row| row.location.to_ascii_lowercase().starts_with("acpi")));
    }
    // A mesma busca vem do cache.
    ok(scenario::search(&backend, SearchKind::StringReferences, SearchScope::Module(acpi), &log));
    assert_eq!(backend.shared().snapshot.references.as_ref().map(|view| view.cached), Some(1));

    // Um roteiro.
    let before = backend.shared().transcript.len();
    backend.send(Request::RunScript("var n = 0\nwhile n < 2\n  n = n + 1\nend\nlog \"voltas {n}\"\n".into()));
    wait(&backend, "o roteiro", Duration::from_secs(120), |shared| shared.transcript.len() > before && shared.activity.is_empty());
    {
        let shared = backend.shared();
        let entry = shared.transcript.last().expect("saida do roteiro");
        assert!(entry.output.contains("voltas 0x2"), "{}", entry.output);
    }

    // A janela fora da tela.
    let path = std::env::var("OPENNT_KD_RE_SHOT").map(PathBuf::from).unwrap_or_else(|_| root.join("target").join("kd-re-smoke.png"));
    let mut app = DebuggerApp::new(backend, None, String::new());
    app.focus(Tab::Cpu);
    let image = offscreen::render(&mut app, [1400, 900], 6);
    assert!(image.pixels.iter().any(|pixel| pixel.r() != pixel.g()), "a captura saiu sem cor");
    offscreen::save_png(&image, &path).unwrap_or_else(|error| panic!("{error}"));
    log(&format!("captura em {}", path.display()));
}
