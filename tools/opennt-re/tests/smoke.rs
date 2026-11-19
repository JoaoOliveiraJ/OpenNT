//! Teste de fumaça do opennt-re, sem janela: o backend abre o OpenNT com
//! `--kd=com2 --initial-process=smss` pelo `xtask` (o QEMU sem tela),
//! anexa e confere:
//!
//! - o processo csrss.exe real: a parada na carga do basesrv.dll (o evento
//!   de imagem), o contexto dele (PEB, módulos da PEB.Ldr com os símbolos
//!   da ntdll), um breakpoint de usuário no ntdll!LdrLoadDll que só o
//!   csrss acerta, a pilha de usuário até o CSRSRV, as threads de usuário,
//!   os handles e o mapa de memória (VAD);
//! - a aba Processos: a sessão do csrss, o PDB da ntdll, as pilhas de
//!   usuário e de kernel de uma thread, e um plano de seguir (a carga do
//!   winsrv.dll no csrss arma o ponto de entrada dele e a máquina segue até
//!   lá);
//! - o grafo de fluxo de uma função do kernel e de uma da ntdll;
//! - as referências a strings conhecidas no ACPI.sys real (ASCII e UTF-16)
//!   e no CSRSRV.dll;
//! - um roteiro;
//! - a janela desenhada fora da tela.
//!
//! Abre o QEMU e leva minutos, então só roda pedido:
//! `cargo test -p opennt-re --release -- --ignored --nocapture`. Variáveis:
//! `QEMU` (o executável), `OPENNT_KD_RE_ARGS` (opções a mais para o `xtask`,
//! como `--accel=whpx`) e `OPENNT_KD_RE_SHOT` (onde gravar a captura;
//! padrão `target/kd-re-smoke.png`).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use opennt_re::app::{DebuggerApp, Tab};
use opennt_re::backend::{Backend, Config, PdbState, Request, SearchKind, SearchScope, Shared, Status, Target, UserRequest};
use opennt_re::follow::FollowPlan;
use opennt_re::launcher::LaunchOptions;
use opennt_re::{offscreen, scenario};

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
#[ignore = "abre o OpenNT no QEMU (minutos): cargo test -p opennt-re --release -- --ignored"]
fn debugs_csrss_and_the_kernel() {
    let root = opennt_re::workspace_root();
    let mut extra: Vec<String> = std::env::var("OPENNT_KD_RE_ARGS").map(|text| text.split_whitespace().map(String::from).collect()).unwrap_or_default();
    if !extra.iter().any(|argument| argument.starts_with("--initial-process")) {
        extra.push("--initial-process=smss".into());
    }
    if !extra.iter().any(|argument| argument.starts_with("--smp")) {
        extra.push("--smp=1".into());
    }
    let options = LaunchOptions { root: root.clone(), build_dir: PathBuf::from("build/opennt-re"), headless: true, extra };
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
    // A aba Processos: a imagem do csrss (com os tipos do ntoskrnl), os
    // módulos com o PDB da ntdll, as threads e as duas pilhas de uma delas.
    let tid = {
        let shared = backend.shared();
        let user = &shared.snapshot.user;
        let csrss: Vec<_> = user.processes.iter().filter(|row| row.name.eq_ignore_ascii_case("csrss.exe")).collect();
        assert!(!csrss.is_empty(), "{:?}", user.processes);
        log(&format!("csrss na aba Processos: {csrss:?}"));
        if user.types_note.is_empty() {
            assert!(csrss.iter().all(|row| row.image.to_ascii_lowercase().ends_with("csrss.exe")), "sem a imagem do csrss: {csrss:?}");
        }
        assert!(user.modules.iter().any(|module| module.name.eq_ignore_ascii_case("ntdll") && matches!(module.pdb, PdbState::Loaded(_))), "{:?}", user.modules);
        let threads = user.threads.as_deref().expect("as threads de usuario").as_ref().expect("uthreads");
        threads.iter().find(|row| row.thread.context != 0).map(|row| row.thread.tid).unwrap_or_else(|| panic!("nenhuma thread com CONTEXT: {threads:?}"))
    };
    let before = generation(&backend);
    backend.send(Request::User(UserRequest::ThreadStacks(Some(tid))));
    wait(&backend, "as pilhas da thread", Duration::from_secs(300), |shared| shared.snapshot.generation > before && shared.snapshot.user.stacks.is_some() && shared.activity.is_empty());
    {
        let shared = backend.shared();
        let stacks = shared.snapshot.user.stacks.as_ref().expect("pilhas");
        assert_eq!(stacks.tid, tid);
        assert!(stacks.kernel.as_ref().is_ok_and(|frames| !frames.is_empty()), "{stacks:?}");
        assert!(stacks.user.is_ok(), "{stacks:?}");
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

    // Seguir: quando o csrss carregar o winsrv.dll (a carga do LdrLoadDll
    // parado), o plano arma o ponto de entrada dele só no csrss e segue; a
    // parada seguinte é lá.
    let ldr = backend.shared().snapshot.breakpoints.iter().find(|breakpoint| breakpoint.expression.contains("LdrLoadDll")).map(|breakpoint| breakpoint.id);
    if let Some(id) = ldr {
        backend.send(Request::RemoveBreakpoint(id));
    }
    let before = generation(&backend);
    backend.send(Request::User(UserRequest::Follow(FollowPlan { process: "csrss.exe".into(), module: "winsrv.dll".into(), symbols: vec!["$iment(winsrv)".into()], ..Default::default() })));
    wait(&backend, "o plano de seguir armado", Duration::from_secs(60), |shared| shared.snapshot.generation > before && shared.snapshot.user.plans.iter().any(|plan| plan.trigger_armed));
    let before = generation(&backend);
    backend.send(Request::Go);
    wait(&backend, "a parada no ponto de entrada do winsrv.dll", Duration::from_secs(900), |shared| shared.status == Status::Stopped && shared.snapshot.generation > before && shared.snapshot.stop.contains("swbreak") && shared.snapshot.user_mode && shared.activity.is_empty());
    {
        let shared = backend.shared();
        assert!(shared.snapshot.stop.to_ascii_lowercase().contains("winsrv"), "{}", shared.snapshot.stop);
        assert!(shared.transcript.iter().any(|entry| entry.input == "(seguir)" && entry.output.contains("armado")), "sem o plano armado no log");
        let plan = shared.snapshot.user.plans.first().expect("o plano");
        assert!(plan.instances.iter().any(|line| line.contains("armados")), "{plan:?}");
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

    // Um roteiro, na linguagem dos roteiros do kd (a do test-boot).
    let before = backend.shared().transcript.len();
    backend.send(Request::RunScript("save n 0\nwhile $n < 2 {\n  save n $n+1\n}\nprint voltas {$n}\n".into()));
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
