//! Teste de fumaça do depurador gráfico, sem janela: o backend abre o
//! OpenNT com `--kd=com2` pelo `xtask` (o mesmo `cargo xtask debug --launch
//! --no-client` do `--launch`, com o QEMU sem tela), anexa e confere:
//!
//! - registradores, módulos, pilha, desmontagem e a linha de código;
//! - a parada pela carga de um módulo (`sxe ld:ACPI.sys`);
//! - a parada dentro do acpi.sys real (no retorno de uma chamada ao
//!   IoCreateDevice) e a pilha através dele pela `.pdata`, com os nomes do
//!   PDB público;
//! - as vistas: o módulo e a linha de cada quadro, o estado do PDB de cada
//!   módulo, o estado estendido do processador (SSE, DR7) e a espera e a
//!   prioridade das threads pelo KTHREAD;
//! - um rastro curto dentro do driver, com os símbolos e a árvore;
//! - o objeto de driver, um IRP de PnP e o objeto de dispositivo dele (na
//!   rotina de despacho IRP_MJ_PNP do driver);
//! - a parada pedida com a máquina rodando, o breakpoint no laço principal
//!   do kernel, o rastro da função até o retorno, o rastro rápido pelo log
//!   de execução do QEMU, o passo por cima e para fora;
//! - o bugcheck pelo despejo manual do teclado e a análise dele;
//! - a janela desenhada fora da tela.
//!
//! Abre o QEMU e leva minutos, então só roda pedido:
//! `cargo test -p kd-gui --release -- --ignored --nocapture`. Variáveis:
//! `QEMU` (o executável), `OPENNT_KD_GUI_ARGS` (opções a mais para o
//! `xtask`, como `--accel=whpx`) e `OPENNT_KD_GUI_SHOT` (onde gravar a
//! captura; padrão `target/kd-gui-smoke.png`).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kd_client::client::BreakpointRequest;
use kd_client::commands::TraceOptions;
use kd_client::BreakpointKind;
use kd_gui::app::{DebuggerApp, Tab};
use kd_gui::backend::{Backend, Config, QueryKind, Request, Shared, Status, Target, Wanted};
use kd_gui::details::PdbStatus;
use kd_gui::launcher::LaunchOptions;
use kd_gui::{offscreen, scenario};

const BREAKPOINT: &str = "kernel::ntos::ke::run_kernel_tasks";

fn log(text: &str) {
    println!("[smoke] {text}");
}

fn wait(backend: &Backend, what: &str, timeout: Duration, predicate: impl Fn(&Shared) -> bool) {
    if let Err(error) = scenario::wait(backend, what, timeout, &log, predicate) {
        panic!("{error}");
    }
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

/// Uma consulta do painel Objetos do NT; devolve o texto.
fn query(backend: &Backend, kind: QueryKind, argument: &str) -> String {
    let before = generation(backend);
    backend.send(Request::Query(kind, argument.into()));
    wait(backend, &format!("a consulta {}", kind.command(argument)), Duration::from_secs(120), |shared| shared.snapshot.generation > before && shared.snapshot.query.as_ref().is_some_and(|query| query.kind == kind));
    let shared = backend.shared();
    match &shared.snapshot.query.as_ref().unwrap().text {
        Ok(text) => text.clone(),
        Err(error) => panic!("{}: {error}", kind.command(argument)),
    }
}

#[test]
#[ignore = "abre o OpenNT no QEMU (minutos): cargo test -p kd-gui --release -- --ignored"]
fn launches_breaks_and_stops_at_a_breakpoint() {
    let root = kd_gui::workspace_root();
    let extra: Vec<String> = std::env::var("OPENNT_KD_GUI_ARGS").map(|text| text.split_whitespace().map(String::from).collect()).unwrap_or_default();
    let options = LaunchOptions { root: root.clone(), build_dir: PathBuf::from("build/kd-gui"), headless: true, extra };
    let config = Config { root: root.clone(), elf: options.build_path().join("kernel.elf"), serial_log: None, session: None };
    let backend = Backend::start(config, Some(Target::Launch(options)), Arc::new(|| {}));

    // Anexar: a máquina para e o snapshot traz o estado inteiro.
    wait(&backend, "a primeira parada (build, QEMU e attach)", Duration::from_secs(1800), |shared| shared.status == Status::Stopped && shared.activity.is_empty());
    {
        let shared = backend.shared();
        let snapshot = &shared.snapshot;
        assert!(snapshot.stop.contains("SIGINT"), "{}", snapshot.stop);
        assert!(snapshot.registers.len() >= 24, "{:?}", snapshot.registers);
        assert!(snapshot.registers_editable);
        assert!(!snapshot.stopped_threads.is_empty());
        assert!(!snapshot.processors.is_empty());
        assert!(snapshot.modules.iter().any(|module| module.symbols > 1000), "sem os simbolos do kernel: {:?}", snapshot.modules);
        assert!(!snapshot.frames.is_empty());
        assert!(!snapshot.code.lines.is_empty(), "{:?}", snapshot.code.error);
        assert!(shared.can_restart);
    }
    assert_ne!(rip(&backend), 0);

    // Parada pela carga do acpi.sys real (o attach é no começo do boot).
    let before = generation(&backend);
    backend.send(Request::AddBreakpointWith(BreakpointRequest::new(BreakpointKind::Module, "ACPI.sys")));
    wait(&backend, "a parada por carga armada", Duration::from_secs(60), |shared| shared.snapshot.generation > before && shared.snapshot.breakpoints.iter().any(|breakpoint| breakpoint.kind == BreakpointKind::Module));
    let before = generation(&backend);
    backend.send(Request::Go);
    wait_stop(&backend, "a carga do ACPI.sys", before, Duration::from_secs(900));
    {
        let shared = backend.shared();
        assert!(shared.snapshot.stop.contains("modulo carregado: ACPI.sys"), "{}", shared.snapshot.stop);
        assert!(shared.snapshot.modules.iter().any(|module| module.name == "ACPI"), "{:?}", shared.snapshot.modules);
    }
    let module_breakpoint = backend.shared().snapshot.breakpoints.iter().find(|breakpoint| breakpoint.kind == BreakpointKind::Module).map(|breakpoint| breakpoint.id).unwrap();
    backend.send(Request::RemoveBreakpoint(module_breakpoint));

    // Dentro do driver: a pilha passa pelo acpi.sys (.pdata) até o kernel.
    let module = scenario::stop_inside_driver(&backend, &log).unwrap_or_else(|error| panic!("{error}"));
    let named = scenario::wait_for_driver_symbols(&backend, &module, &log);
    {
        let shared = backend.shared();
        let snapshot = &shared.snapshot;
        let frames = &snapshot.frames;
        assert!(scenario::driver_module(&shared, frames[0].address).as_deref() == Some(module.as_str()), "{frames:?}");
        assert!(frames[0].name.starts_with(&format!("{module}!")) || frames[0].name.starts_with(&format!("{module}+")), "{frames:?}");
        if named {
            assert!(frames[0].name.starts_with(&format!("{module}!")), "sem o nome do PDB: {frames:?}");
        }
        // Depois dos quadros do driver vem o kernel do OpenNT (o carregador
        // do PnP), achado pela `.pdata` do driver.
        let first_kernel = frames.iter().position(|frame| scenario::driver_module(&shared, frame.address).is_none()).unwrap_or_else(|| panic!("a pilha nao sai do driver: {frames:?}"));
        assert!(first_kernel >= 1, "{frames:?}");
        assert_eq!(frames[first_kernel].method, ".pdata", "{frames:?}");
        assert!(frames[first_kernel..].iter().any(|frame| frame.name.starts_with("kernel::ntos::io::")), "a pilha nao volta ao kernel: {frames:?}");
        // As vistas: o módulo de cada quadro, a linha do DWARF nos quadros do
        // kernel do OpenNT e o estado do PDB de cada módulo.
        assert_eq!(frames[0].module, module, "{frames:?}");
        assert!(frames[first_kernel..].iter().any(|frame| frame.line.is_some()), "sem arquivo:linha nos quadros do kernel: {frames:?}");
        assert!(snapshot.modules.iter().any(|row| row.status == PdbStatus::Elf), "{:?}", snapshot.modules);
        let row = snapshot.modules.iter().find(|row| row.name == module).expect("o modulo do driver");
        assert!(!matches!(row.status, PdbStatus::Elf | PdbStatus::NoFile), "{row:?}");
    }

    // As leituras extras das vistas: o resto do estado do processador e a
    // espera e a prioridade das threads pelo KTHREAD (os offsets do PDB).
    let before = generation(&backend);
    backend.send(Request::SetWanted(Wanted { extended: true, thread_details: true, thread_filter: None, user_stack: true }));
    wait(&backend, "as leituras extras", Duration::from_secs(300), |shared| shared.snapshot.generation > before && shared.activity.is_empty());
    {
        let shared = backend.shared();
        let snapshot = &shared.snapshot;
        let extended = snapshot.extended.as_ref().expect("o estado estendido pedido").as_ref().unwrap_or_else(|error| panic!("{error}"));
        assert!(extended.xmm.iter().all(Option::is_some), "{extended:?}");
        assert!(extended.debug[5].is_some(), "sem o DR7: {extended:?}");
        // O mesmo campo State do KTHREAD que a tabela do alvo mostra (sem o
        // PDB do ntoskrnl ainda, a nota diz por quê).
        let detailed: Vec<_> = snapshot.threads.iter().filter_map(|row| row.detail.as_ref().map(|detail| (row, detail))).collect();
        if snapshot.threads_note.is_empty() || !detailed.is_empty() {
            assert!(!detailed.is_empty(), "nenhuma thread com detalhes: {}", snapshot.threads_note);
            for (row, detail) in &detailed {
                assert!(detail.state == row.thread.state || detail.state.starts_with("GateWait"), "{row:?} {detail:?}");
            }
        }
    }
    let before = generation(&backend);
    backend.send(Request::SetWanted(Wanted::default()));
    wait(&backend, "sem as leituras extras", Duration::from_secs(120), |shared| shared.snapshot.generation > before && shared.activity.is_empty());

    // Um rastro curto dentro do driver.
    let traces = backend.shared().trace_generation;
    backend.send(Request::Trace(TraceOptions { count: 200, ..Default::default() }));
    wait(&backend, "o rastro no driver", Duration::from_secs(600), |shared| shared.trace_generation > traces && shared.activity.is_empty());
    {
        let shared = backend.shared();
        let trace = shared.trace.as_ref().expect("rastro");
        assert!(trace.trace.len() >= 2, "{}", trace.summary);
        let first = trace.info(trace.trace.records[0].rip).expect("simbolo do primeiro registro");
        assert_eq!(first.module, module, "{first:?}");
        assert!(first.symbol.starts_with(&format!("{module}!")) || first.symbol.starts_with(&format!("{module}+")), "{first:?}");
        assert!(!trace.trace.call_tree().is_empty());
        assert!(trace.trace.records.iter().all(|record| record.cpu == trace.trace.records[0].cpu));
    }

    // O objeto de driver, um IRP de PnP e o dispositivo dele, na rotina de
    // despacho IRP_MJ_PNP do driver (DeviceObject em RCX, Irp em RDX).
    let driver = query(&backend, QueryKind::Driver, &format!("\\Driver\\{module}"));
    assert!(driver.contains("DRIVER_OBJECT") && driver.contains("IRP_MJ_PNP"), "{driver}");
    let dispatch = driver.lines().find(|line| line.contains("IRP_MJ_PNP")).and_then(|line| line.split_whitespace().find_map(|word| word.strip_prefix("0x").and_then(|hex| u64::from_str_radix(hex, 16).ok()))).expect("rotina de PnP");
    scenario::stop_at(&backend, &format!("{dispatch:#x}"), &log).unwrap_or_else(|error| panic!("{error}"));
    let irp = query(&backend, QueryKind::Irp, "@rdx");
    assert!(irp.contains("IRP_MJ_PNP") && irp.contains("pilha de E/S"), "{irp}");
    let device = query(&backend, QueryKind::Device, "@rcx");
    assert!(device.contains("DEVICE_OBJECT") && device.contains("pilha de dispositivos"), "{device}");
    let dispatch_breakpoint = backend.shared().snapshot.breakpoints.iter().find(|breakpoint| breakpoint.address == dispatch).map(|breakpoint| breakpoint.id).unwrap();
    backend.send(Request::RemoveBreakpoint(dispatch_breakpoint));

    // Parada pedida com a máquina rodando.
    backend.send(Request::Go);
    wait(&backend, "a maquina rodando", Duration::from_secs(60), |shared| shared.status == Status::Running);
    std::thread::sleep(Duration::from_millis(1500));
    let before = generation(&backend);
    backend.send(Request::Break);
    wait_stop(&backend, "a parada pedida", before, Duration::from_secs(120));
    assert!(backend.shared().snapshot.stop.contains("SIGINT"));

    // Breakpoint de software no laço principal e continuar até ele.
    scenario::stop_at(&backend, BREAKPOINT, &log).unwrap_or_else(|error| panic!("{error}"));
    let address = backend.shared().snapshot.breakpoints.iter().find(|breakpoint| breakpoint.expression == BREAKPOINT).unwrap().address;
    {
        let shared = backend.shared();
        let snapshot = &shared.snapshot;
        assert!(snapshot.frames[0].name.contains("run_kernel_tasks"), "{:?}", snapshot.frames);
        assert!(snapshot.frames.iter().any(|frame| frame.name.contains("kmain")), "{:?}", snapshot.frames);
        assert!(snapshot.code.lines.iter().any(|line| line.address == address && line.label.as_deref() == Some(BREAKPOINT)), "{:?}", snapshot.code.lines.first());
        let source = snapshot.source.as_ref().unwrap_or_else(|| panic!("sem a linha de codigo: {:?}", snapshot.source_error));
        assert!(source.file.replace('\\', "/").ends_with(".rs"), "{}", source.file);
        assert!(source.text.len() >= source.line as usize);
    }
    assert_eq!(rip(&backend), address);

    // O rastro de uma função conhecida do kernel até o retorno.
    let traces = backend.shared().trace_generation;
    backend.send(Request::Trace(TraceOptions { count: 400_000, until_return: true, ..Default::default() }));
    wait(&backend, "o rastro de run_kernel_tasks", Duration::from_secs(900), |shared| shared.trace_generation > traces && shared.activity.is_empty());
    {
        let shared = backend.shared();
        let trace = shared.trace.as_ref().expect("rastro");
        let first = trace.info(trace.trace.records[0].rip).expect("simbolo");
        assert_eq!(first.symbol, BREAKPOINT, "{first:?}");
        assert_eq!(trace.trace.reason, kd_client::trace::Reason::Return, "{}", trace.summary);
        let nodes = trace.trace.call_tree();
        let root_children: Vec<String> = nodes[0].children.iter().flat_map(|&child| nodes[child].children.iter().copied().chain([child])).filter_map(|node| trace.info(nodes[node].address).map(|info| info.symbol.clone())).collect();
        assert!(root_children.iter().any(|name| name.starts_with(BREAKPOINT)), "{root_children:?}");
        // Chamadas do run_kernel_tasks viram filhos na árvore.
        assert!(nodes.iter().any(|node| node.depth == 1), "sem chamadas no rastro");
        let last = trace.trace.records.last().unwrap();
        assert!(trace.info(last.rip).is_some_and(|info| info.symbol.starts_with("kernel::ntos::init::main::kmain")), "{:?}", trace.info(last.rip));
    }

    // O rastro rápido pelo log de execução do QEMU (TCG): 300 ms da máquina
    // rodando, só os RIPs.
    let traces = backend.shared().trace_generation;
    backend.send(Request::QemuTrace { milliseconds: 300, until: String::new() });
    wait(&backend, "o rastro rapido do QEMU", Duration::from_secs(900), |shared| shared.trace_generation > traces && shared.activity.is_empty() && shared.status == Status::Stopped);
    {
        let shared = backend.shared();
        let trace = shared.trace.as_ref().expect("rastro do QEMU");
        assert_eq!(trace.trace.source, kd_client::trace::Source::Qemu, "{}", trace.title);
        assert!(trace.trace.len() > 1000, "{}", trace.summary);
        assert!(trace.trace.records.iter().any(|record| trace.info(record.rip).is_some_and(|info| info.symbol.starts_with("kernel::"))), "{}", trace.summary);
    }

    // De volta ao breakpoint: desliga (fica na lista) e passa por cima / sai.
    let before = generation(&backend);
    backend.send(Request::Go);
    wait_stop(&backend, "a parada no breakpoint de novo", before, Duration::from_secs(900));
    assert_eq!(rip(&backend), address);
    let id = backend.shared().snapshot.breakpoints.iter().find(|breakpoint| breakpoint.expression == BREAKPOINT).unwrap().id;
    let before = generation(&backend);
    backend.send(Request::EnableBreakpoint(id, false));
    wait(&backend, "o breakpoint desligado", Duration::from_secs(60), |shared| shared.snapshot.generation > before && shared.snapshot.breakpoints.iter().any(|breakpoint| breakpoint.id == id && !breakpoint.enabled));
    let before = generation(&backend);
    backend.send(Request::StepOver);
    wait_stop(&backend, "o passo por cima", before, Duration::from_secs(120));
    assert_ne!(rip(&backend), address);
    let before = generation(&backend);
    backend.send(Request::StepOut);
    wait_stop(&backend, "o passo para fora", before, Duration::from_secs(600));
    // O retorno é no laço do kmain, logo depois do `call`.
    assert!(backend.shared().snapshot.frames[0].name.starts_with("kernel::ntos::init::main::kmain+"), "{:?}", backend.shared().snapshot.frames.first());

    // Um comando do painel e a memória.
    let before = generation(&backend);
    backend.send(Request::ShowMemory("%rsp".into()));
    backend.send(Request::Command("lm".into()));
    wait(&backend, "o comando lm", Duration::from_secs(60), |shared| shared.snapshot.generation > before && shared.transcript.iter().any(|entry| entry.input == "lm" && entry.output.contains("ntoskrnl")));
    assert_eq!(backend.shared().snapshot.memory.bytes.len(), 0x200);

    // O bugcheck pelo despejo manual do teclado e a análise dele.
    scenario::trigger_bugcheck(&backend, &log).unwrap_or_else(|error| panic!("{error}"));
    {
        let shared = backend.shared();
        let analysis = shared.snapshot.bugcheck.as_ref().unwrap();
        assert_eq!(analysis.code, 0xE2);
        assert_eq!(analysis.name, "MANUALLY_INITIATED_CRASH");
        assert!(!analysis.stack.is_empty());
        assert!(analysis.blamed.as_ref().is_some_and(|(module, _)| module.eq_ignore_ascii_case("i8042prt")), "{:?}", analysis.blamed);
    }

    // A janela fora da tela, com a análise do bugcheck aberta.
    let mut app = DebuggerApp::new(backend, None, String::new());
    app.focus(Tab::Bugcheck);
    let image = offscreen::render(&mut app, [1280, 800], 5);
    let distinct: std::collections::HashSet<_> = image.pixels.iter().step_by(97).collect();
    assert!(distinct.len() > 20, "captura sem conteudo ({} cores)", distinct.len());
    let path = std::env::var("OPENNT_KD_GUI_SHOT").map(PathBuf::from).unwrap_or_else(|_| root.join("target").join("kd-gui-smoke.png"));
    offscreen::save_png(&image, &path).unwrap();
    println!("[smoke] captura em {}", path.display());
    // Soltar a janela solta o backend: o QEMU fecha junto.
    drop(app);
}
