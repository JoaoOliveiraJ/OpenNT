//! Teste de fumaça das ferramentas novas do opennt-re, sem janela: o
//! backend abre o OpenNT com `--kd=com2 --start-driver=ntfs` (o ntfs.sys
//! real monta o volume e abre um arquivo), anexa no começo do boot e
//! confere:
//!
//! - o monitor de APIs: as chamadas do ntfs.sys aos exports do kernel, com
//!   o nome do export, os argumentos e o NTSTATUS (o IoCreateDevice do
//!   \Ntfs com sucesso);
//! - o rastreador de IRPs: um IRP_MJ_CREATE que passa pelo \FileSystem\Ntfs
//!   e é concluído;
//! - o Registro vivo: o valor `Current` de `SYSTEM\Select`;
//! - a vista como tipo: o EPROCESS do System com o ImageFileName;
//! - o namespace (`\Driver` com o Ntfs) e os arquivos do volume;
//! - as abas desenhadas fora da tela.
//!
//! Abre o QEMU e leva minutos, então só roda pedido:
//! `cargo test -p opennt-re --release --test smoke_tools -- --ignored --nocapture`.
//! `OPENNT_KD_RE_ARGS` passa opções a mais ao `xtask` (`--accel=whpx`).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use opennt_kd::client::BreakpointRequest;
use opennt_kd::struct_view::RowKind;
use opennt_kd::BreakpointKind;
use opennt_re::app::{DebuggerApp, Tab};
use opennt_re::backend::{Backend, Config, ExtraRequest, Request, Shared, Status, Target};
use opennt_re::launcher::LaunchOptions;
use opennt_re::{offscreen, scenario};

fn log(text: &str) {
    println!("[smoke-ferramentas] {text}");
}

fn wait(backend: &Backend, what: &str, timeout: Duration, predicate: impl Fn(&Shared) -> bool) {
    if let Err(error) = scenario::wait(backend, what, timeout, &log, predicate) {
        panic!("{error}");
    }
}

fn idle(shared: &Shared) -> bool {
    shared.status == Status::Stopped && shared.activity.is_empty()
}

#[test]
#[ignore = "abre o OpenNT no QEMU (minutos): cargo test -p opennt-re --release --test smoke_tools -- --ignored"]
fn api_monitor_irps_registry_types_and_explorers() {
    let root = opennt_re::workspace_root();
    let mut extra: Vec<String> = std::env::var("OPENNT_KD_RE_ARGS").map(|text| text.split_whitespace().map(String::from).collect()).unwrap_or_default();
    if !extra.iter().any(|argument| argument.starts_with("--start-driver")) {
        extra.push("--start-driver=ntfs".into());
    }
    let options = LaunchOptions { root: root.clone(), build_dir: PathBuf::from("build/kd-re-ferramentas"), headless: true, extra };
    let config = Config { root: root.clone(), elf: options.build_path().join("kernel.elf"), serial_log: None, session: None, script: None };
    let backend = Backend::start(config, Some(Target::Launch(options)), Arc::new(|| {}));
    wait(&backend, "a primeira parada (build, QEMU e attach)", Duration::from_secs(1800), idle);

    // A parada na carga do ntfs.sys (antes do DriverEntry): o monitor de
    // APIs só para os chamadores do ntfs e o rastreador de IRPs.
    let before = backend.shared().snapshot.generation;
    backend.send(Request::AddBreakpointWith(BreakpointRequest::new(BreakpointKind::Module, "ntfs.sys")));
    wait(&backend, "a parada por carga armada", Duration::from_secs(60), |shared| shared.snapshot.generation > before);
    let before = backend.shared().snapshot.generation;
    backend.send(Request::Go);
    wait(&backend, "a carga do ntfs.sys", Duration::from_secs(1800), |shared| idle(shared) && shared.snapshot.generation > before && shared.snapshot.stop.contains("modulo carregado"));
    backend.send(Request::Extra(ExtraRequest::ApiMonitor { enable: true, modules: vec!["ntfs".into()] }));
    backend.send(Request::Extra(ExtraRequest::IrpTrace(true)));
    wait(&backend, "os dois monitores ligados", Duration::from_secs(300), |_| {
        let store = backend.store.lock().unwrap();
        store.api_enabled && store.irp_enabled
    });
    backend.send(Request::Go);
    wait(&backend, "a maquina rodando", Duration::from_secs(60), |shared| shared.status == Status::Running);
    wait(&backend, "o arquivo aberto pelo ntfs.sys (FILE_SYSTEM_MOUNT_OK)", Duration::from_secs(1800), |shared| shared.serial.contains("FILE_SYSTEM_MOUNT_OK"));
    // Registros chegam com a máquina rodando (os pacotes O do fluxo).
    let streamed = backend.store.lock().unwrap().api_rows.len();
    log(&format!("{streamed} chamadas recebidas com a maquina rodando"));
    let before = backend.shared().snapshot.generation;
    backend.send(Request::Break);
    wait(&backend, "a parada pedida", Duration::from_secs(300), |shared| idle(shared) && shared.snapshot.generation > before);
    {
        let store = backend.store.lock().unwrap();
        assert!(streamed > 0, "nenhuma chamada chegou com a maquina rodando");
        let ntfs: Vec<_> = store.api_rows.iter().filter(|row| row.module.eq_ignore_ascii_case("ntfs")).collect();
        assert!(!ntfs.is_empty(), "nenhuma chamada do ntfs.sys entre {} chamadas", store.api_rows.len());
        let create = ntfs.iter().find(|row| row.name.as_ref() == "IoCreateDevice").unwrap_or_else(|| panic!("sem o IoCreateDevice do ntfs: {:?}", ntfs.iter().take(20).map(|row| row.name.to_string()).collect::<Vec<_>>()));
        assert_eq!(create.status, Some(0), "{create:?}");
        assert!(create.result.contains("STATUS_SUCCESS"), "{}", create.result);
        assert!(create.arguments.contains("DeviceName="), "{}", create.arguments);
        assert!(create.caller.to_ascii_lowercase().starts_with("ntfs"), "{}", create.caller);
        // O IRP de CREATE pelo \FileSystem\Ntfs, concluído.
        let ntfs_driver: Vec<u64> = store.driver_names.iter().filter(|(_, name)| name.to_ascii_lowercase().contains("ntfs")).map(|(&driver, _)| driver).collect();
        assert!(!ntfs_driver.is_empty(), "sem o nome do driver do ntfs: {:?}", store.driver_names);
        let creates: Vec<_> = store.irps.iter().filter(|life| life.major == 0 && life.drivers().iter().any(|driver| ntfs_driver.contains(driver))).collect();
        assert!(!creates.is_empty(), "nenhum IRP_MJ_CREATE pelo ntfs entre {} IRPs", store.irps.len());
        assert!(creates.iter().any(|life| life.final_status.is_some() && life.completed), "nenhum CREATE concluido: {:?}", creates.iter().take(3).collect::<Vec<_>>());
    }

    // O Registro: SYSTEM\Select\Current.
    let path = "\\Registry\\Machine\\SYSTEM\\Select".to_string();
    backend.send(Request::Extra(ExtraRequest::RegistryKey(path.clone())));
    wait(&backend, "a chave SYSTEM\\Select", Duration::from_secs(120), |shared| shared.extras.registry.contains_key(&path));
    {
        let shared = backend.shared();
        let view = shared.extras.registry[&path].as_ref().as_ref().unwrap_or_else(|error| panic!("{error}"));
        let current = view.values.iter().find(|value| value.name == "Current").unwrap_or_else(|| panic!("sem o valor Current: {:?}", view.values));
        assert_eq!(current.kind_name(), "REG_DWORD");
        assert_eq!(current.data.len(), 4);
        assert!(u32::from_le_bytes(current.data[..4].try_into().unwrap()) >= 1);
    }

    // A vista como tipo: o EPROCESS do System.
    let system = backend.shared().snapshot.processes.iter().find(|process| process.pid == 4).map(|process| process.eprocess).expect("o processo System");
    backend.send(Request::Extra(ExtraRequest::StructView { type_name: "_EPROCESS".into(), address: format!("{system:#x}"), expanded: vec!["ThreadListHead".into()], lists: Vec::new() }));
    wait(&backend, "a vista _EPROCESS", Duration::from_secs(300), |shared| shared.extras.struct_tree.is_some());
    {
        let shared = backend.shared();
        let tree = shared.extras.struct_tree.as_ref().unwrap().as_ref().as_ref().unwrap_or_else(|error| panic!("{error}"));
        let name = tree.rows.iter().find(|row| row.name == "ImageFileName").expect("o campo ImageFileName");
        assert!(name.value.contains("System"), "{}", name.value);
        assert!(tree.rows.iter().any(|row| row.kind == RowKind::ListEntry), "a lista de threads aberta sem entradas");
    }

    // O namespace e os arquivos.
    backend.send(Request::Extra(ExtraRequest::ObjectDirectory("\\Driver".into())));
    backend.send(Request::Extra(ExtraRequest::FileList("/".into())));
    wait(&backend, "\\Driver e a raiz do volume", Duration::from_secs(300), |shared| shared.extras.objects.contains_key("\\Driver") && shared.extras.files.contains_key("/"));
    {
        let shared = backend.shared();
        let drivers = shared.extras.objects["\\Driver"].as_ref().as_ref().unwrap_or_else(|error| panic!("{error}"));
        assert!(drivers.entries.iter().any(|entry| entry.kind == "Driver"), "{:?}", drivers.entries.iter().take(10).collect::<Vec<_>>());
        let files = shared.extras.files["/"].as_ref().as_ref().unwrap_or_else(|error| panic!("{error}"));
        assert!(!files.is_empty());
    }

    // As abas desenhadas fora da tela.
    let path = std::env::var("OPENNT_KD_RE_SHOT").map(PathBuf::from).unwrap_or_else(|_| root.join("target").join("kd-re-ferramentas.png"));
    let mut app = DebuggerApp::new(backend, None, String::new());
    app.focus(Tab::ApiMonitor);
    let image = offscreen::render(&mut app, [1400, 900], 6);
    assert!(image.pixels.iter().any(|pixel| pixel.r() != pixel.g()), "a captura saiu sem cor");
    offscreen::save_png(&image, &path).unwrap_or_else(|error| panic!("{error}"));
    log(&format!("captura em {}", path.display()));
}

/// Os snapshots da máquina (`--vm-snapshots`): gravar na parada, andar uns
/// passos e voltar ao snapshot, com o RIP de antes.
#[test]
#[ignore = "abre o OpenNT no QEMU (minutos): cargo test -p opennt-re --release --test smoke_tools -- --ignored"]
fn snapshot_returns_to_an_earlier_stop() {
    let root = opennt_re::workspace_root();
    let mut extra: Vec<String> = std::env::var("OPENNT_KD_RE_ARGS").map(|text| text.split_whitespace().map(String::from).collect()).unwrap_or_default();
    extra.push("--vm-snapshots".into());
    let options = LaunchOptions { root: root.clone(), build_dir: PathBuf::from("build/kd-re-snapshots"), headless: true, extra };
    let config = Config { root: root.clone(), elf: options.build_path().join("kernel.elf"), serial_log: None, session: None, script: None };
    let backend = Backend::start(config, Some(Target::Launch(options)), Arc::new(|| {}));
    wait(&backend, "a primeira parada (build, QEMU e attach)", Duration::from_secs(1800), idle);
    assert_eq!(backend.shared().extras.mode, opennt_re::backend::TimeMode::Snapshots);
    let rip = |backend: &Backend| backend.shared().snapshot.registers.iter().find(|row| row.name == "rip").and_then(|row| row.value).expect("rip");
    let start = rip(&backend);
    backend.send(Request::Extra(ExtraRequest::SnapshotSave("antes".into())));
    wait(&backend, "o snapshot antes", Duration::from_secs(600), |shared| shared.extras.snapshots.as_ref().is_some_and(|list| list.as_ref().as_ref().is_ok_and(|list| list.iter().any(|item| item.tag == "antes"))) && shared.activity.is_empty());
    for _ in 0..3 {
        let before = backend.shared().snapshot.generation;
        backend.send(Request::StepInto);
        wait(&backend, "um passo", Duration::from_secs(120), |shared| idle(shared) && shared.snapshot.generation > before);
    }
    assert_ne!(rip(&backend), start, "os passos nao mudaram o RIP");
    let before = backend.shared().snapshot.generation;
    backend.send(Request::Extra(ExtraRequest::SnapshotLoad("antes".into())));
    wait(&backend, "a volta ao snapshot", Duration::from_secs(600), |shared| idle(shared) && shared.snapshot.generation > before);
    assert_eq!(rip(&backend), start, "a volta ao snapshot nao trouxe o RIP de antes");
    log(&format!("de volta a {start:#x}"));
}
