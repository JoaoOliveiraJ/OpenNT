//! O lado do depurador que fala com o alvo, numa thread própria: a
//! interface manda pedidos (`Request`) e lê o estado publicado (`Shared`),
//! sem nunca esperar o socket. Sem janela nenhuma, o mesmo backend roda nos
//! testes (`tests/smoke.rs`) e na captura de tela.
//!
//! A cada parada o backend monta um `Snapshot` inteiro: registradores do
//! processador (ou da thread) escolhido, a pilha, a desmontagem em volta do
//! quadro escolhido com a linha de código quando o DWARF a tem, a memória
//! pedida, módulos, processadores, processos, threads e breakpoints.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use kd_client::client::Resumed;
use kd_client::monitor::{Process, Processor, Thread};
use kd_client::rsp::Connection;
use kd_client::{registers, Breakpoint, BreakpointKind, Client};

use crate::disasm::{self, Line};
use crate::launcher::{Launch, LaunchOptions};
use crate::source::LineTable;

/// Onde está o alvo.
#[derive(Clone, Debug)]
pub enum Target {
    /// Build e QEMU pelo `xtask` (`--launch`).
    Launch(LaunchOptions),
    /// Um QEMU já aberto (`--connect=HOST:PORTA`).
    Connect(String),
}

#[derive(Clone, Debug)]
pub struct Config {
    pub root: PathBuf,
    /// O `kernel.elf` (símbolos e linhas).
    pub elf: PathBuf,
    /// O log da COM1 (o `serial.log` do build), quando conhecido.
    pub serial_log: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub enum Request {
    Start(Target),
    Restart,
    Disconnect,
    Break,
    Go,
    StepInto,
    StepOver,
    StepOut,
    /// Uma linha do painel de comandos (os comandos do `cargo xtask debug`).
    Command(String),
    /// Processador das leituras (thread do protocolo = processador + 1).
    SelectCpu(u64),
    /// Uma ETHREAD da lista de threads (registradores e pilha dela).
    SelectThread(u64),
    SelectFrame(usize),
    ToggleBreakpoint(u64),
    AddBreakpoint(BreakpointKind, String),
    RemoveBreakpoint(u32),
    EnableBreakpoint(u32, bool),
    /// Desmontagem num endereço ou símbolo (vazio: volta a seguir o RIP).
    ShowCode(String),
    ShowMemory(String),
    WriteMemory(u64, Vec<u8>),
    WriteRegister(String, u64),
    Refresh,
    Shutdown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Status {
    #[default]
    Idle,
    Launching(String),
    Connecting(String),
    Running,
    Stopped,
    Disconnected(String),
}

/// De quem são os registradores e a pilha mostrados.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum View {
    /// O processador da parada.
    #[default]
    Owner,
    /// Uma thread do protocolo escolhida.
    Cpu(u64),
    /// Uma ETHREAD fora da CPU (o quadro de troca).
    Thread(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterRow {
    pub name: String,
    pub value: Option<u64>,
    /// Mudou desde a parada anterior.
    pub changed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameRow {
    pub address: u64,
    pub name: String,
}

#[derive(Clone, Debug, Default)]
pub struct CodeView {
    /// O endereço destacado (o RIP do quadro, ou o pedido).
    pub focus: u64,
    pub lines: Vec<Line>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct SourceView {
    pub file: String,
    pub line: u32,
    pub text: Arc<Vec<String>>,
}

#[derive(Clone, Debug, Default)]
pub struct MemoryView {
    pub expression: String,
    pub address: u64,
    pub bytes: Vec<u8>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadRow {
    pub thread: Thread,
    /// O símbolo do endereço de início.
    pub start: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleRow {
    pub base: u64,
    pub end: u64,
    pub name: String,
    pub symbols: usize,
    pub source: String,
}

/// O estado do alvo numa parada.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    /// Cresce a cada snapshot novo.
    pub generation: u64,
    pub stop: String,
    /// O processador da parada.
    pub stop_processor: Option<u64>,
    pub view: View,
    /// Cabeçalho da thread escolhida (`context`).
    pub view_header: String,
    pub registers: Vec<RegisterRow>,
    pub registers_editable: bool,
    pub frames: Vec<FrameRow>,
    pub selected_frame: usize,
    pub code: CodeView,
    pub source: Option<SourceView>,
    pub source_error: Option<String>,
    pub memory: MemoryView,
    pub modules: Vec<ModuleRow>,
    pub processors: Vec<Processor>,
    pub stopped_threads: Vec<u64>,
    pub processes: Vec<Process>,
    pub threads: Vec<ThreadRow>,
    pub breakpoints: Vec<Breakpoint>,
}

/// Uma entrada do painel de comandos.
#[derive(Clone, Debug)]
pub struct Entry {
    pub input: String,
    pub output: String,
    pub error: bool,
}

/// O que a interface lê.
#[derive(Default)]
pub struct Shared {
    pub status: Status,
    pub snapshot: Arc<Snapshot>,
    /// Saída do DbgPrint da sessão.
    pub console: String,
    /// O log da COM1.
    pub serial: String,
    pub transcript: Vec<Entry>,
    /// O que o backend está fazendo agora (vazio = nada).
    pub activity: String,
    /// Saída do `xtask` (build e QEMU).
    pub launch_log: String,
    /// Pode reiniciar (o alvo é do próprio depurador).
    pub can_restart: bool,
}

pub struct Backend {
    requests: Sender<Request>,
    pub shared: Arc<Mutex<Shared>>,
    thread: Option<JoinHandle<()>>,
}

/// Chamado quando o estado publicado muda (o `request_repaint` da janela).
pub type Notify = Arc<dyn Fn() + Send + Sync>;

impl Backend {
    pub fn start(config: Config, target: Option<Target>, notify: Notify) -> Backend {
        let (requests, receiver) = mpsc::channel();
        let shared = Arc::new(Mutex::new(Shared::default()));
        let worker = Worker::new(config, Arc::clone(&shared), notify);
        let thread = thread::Builder::new()
            .name("kd-backend".into())
            .spawn(move || worker.run(receiver, target))
            .expect("thread do backend");
        Backend { requests, shared, thread: Some(thread) }
    }

    pub fn send(&self, request: Request) {
        let _ = self.requests.send(request);
    }

    pub fn shared(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Espera o estado satisfazer `predicate` (os testes).
    pub fn wait_for(&self, timeout: Duration, predicate: impl Fn(&Shared) -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if predicate(&self.shared()) {
                return true;
            }
            thread::sleep(Duration::from_millis(50));
        }
        false
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        let _ = self.requests.send(Request::Shutdown);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Seguir o RIP do quadro escolhido, ou mostrar um endereço fixo.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Frame,
    Fixed(u64),
}

struct Worker {
    config: Config,
    shared: Arc<Mutex<Shared>>,
    notify: Notify,
    target: Option<Target>,
    client: Option<Client>,
    launch: Option<Launch>,
    lines: Option<Result<LineTable, String>>,
    view: View,
    selected_frame: usize,
    focus: Focus,
    memory_expression: String,
    previous_registers: HashMap<String, u64>,
    serial_offset: u64,
    generation: u64,
}

impl Worker {
    fn new(config: Config, shared: Arc<Mutex<Shared>>, notify: Notify) -> Worker {
        Worker {
            config,
            shared,
            notify,
            target: None,
            client: None,
            launch: None,
            lines: None,
            view: View::Owner,
            selected_frame: 0,
            focus: Focus::Frame,
            memory_expression: String::new(),
            previous_registers: HashMap::new(),
            serial_offset: 0,
            generation: 0,
        }
    }

    fn publish(&self, update: impl FnOnce(&mut Shared)) {
        {
            let mut shared = self.shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            update(&mut shared);
        }
        (self.notify)();
    }

    fn set_status(&self, status: Status) {
        self.publish(|shared| shared.status = status);
    }

    fn set_activity(&self, activity: &str) {
        let activity = activity.to_string();
        self.publish(|shared| shared.activity = activity);
    }

    fn run(mut self, receiver: Receiver<Request>, target: Option<Target>) {
        if let Some(target) = target {
            self.start(target);
        }
        loop {
            let running = self.client.as_ref().is_some_and(|client| !client.is_stopped());
            match receiver.recv_timeout(Duration::from_millis(if running { 20 } else { 150 })) {
                Ok(Request::Shutdown) | Err(RecvTimeoutError::Disconnected) => {
                    self.disconnect("encerrado");
                    return;
                }
                Ok(request) => self.handle(request),
                Err(RecvTimeoutError::Timeout) => {}
            }
            if self.client.as_ref().is_some_and(|client| !client.is_stopped()) {
                self.poll_target();
            }
            self.forward_console();
            self.tail_serial();
            if let Some(launch) = self.launch.as_mut() {
                let mut text = String::new();
                while let Ok(line) = launch.output.try_recv() {
                    text.push_str(&line);
                    text.push('\n');
                }
                if !text.is_empty() {
                    self.publish(|shared| shared.launch_log.push_str(&text));
                }
            }
            // A janela do QEMU fechada com a máquina parada (rodando, o
            // socket fechado já avisa).
            if self.launch.as_mut().is_some_and(|launch| !launch.alive()) {
                self.lost("o QEMU terminou".into());
            }
        }
    }

    /// Conecta (abrindo o QEMU antes, no `--launch`) e anexa.
    fn start(&mut self, target: Target) {
        self.disconnect("reiniciando");
        self.target = Some(target.clone());
        self.view = View::Owner;
        self.selected_frame = 0;
        self.focus = Focus::Frame;
        self.previous_registers.clear();
        self.serial_offset = 0;
        let address = match &target {
            Target::Connect(address) => {
                self.publish(|shared| {
                    shared.can_restart = false;
                    shared.serial.clear();
                    shared.console.clear();
                });
                address.clone()
            }
            Target::Launch(options) => {
                self.config.elf = options.build_path().join("kernel.elf");
                self.config.serial_log = Some(options.build_path().join("serial.log"));
                self.publish(|shared| {
                    shared.can_restart = true;
                    shared.launch_log.clear();
                    shared.serial.clear();
                    shared.console.clear();
                });
                self.set_status(Status::Launching("compilando com --kd=com2 e abrindo o QEMU".into()));
                let shared = Arc::clone(&self.shared);
                let notify = Arc::clone(&self.notify);
                let launched = Launch::start(options, |line| {
                    {
                        let mut shared = shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                        shared.launch_log.push_str(line);
                        shared.launch_log.push('\n');
                        shared.status = Status::Launching(line.chars().take(120).collect());
                    }
                    notify();
                });
                match launched {
                    Ok(launch) => {
                        let address = launch.address.clone();
                        self.launch = Some(launch);
                        address
                    }
                    Err(error) => {
                        self.set_status(Status::Disconnected(error));
                        return;
                    }
                }
            }
        };
        self.set_status(Status::Connecting(address.clone()));
        let connection = match Connection::connect(&address, Instant::now() + Duration::from_secs(60)) {
            Ok(connection) => connection,
            Err(error) => {
                self.set_status(Status::Disconnected(error));
                return;
            }
        };
        let mut client = Client::new(connection, self.config.root.clone(), self.config.elf.clone());
        self.set_activity("anexando (a maquina para no proximo tique)");
        match client.attach(Duration::from_secs(180)) {
            Ok(text) => {
                self.transcript("attach", Ok(text));
                self.client = Some(client);
                self.lines = None;
                self.refresh();
            }
            Err(error) => self.set_status(Status::Disconnected(format!("attach: {error}"))),
        }
        self.set_activity("");
    }

    fn disconnect(&mut self, reason: &str) {
        if let Some(mut client) = self.client.take() {
            if self.launch.is_none() {
                // Um QEMU de fora segue rodando sem o host.
                let _ = client.detach();
            }
        }
        if let Some(mut launch) = self.launch.take() {
            launch.stop();
        }
        if self.target.is_some() {
            self.set_status(Status::Disconnected(reason.to_string()));
        }
    }

    fn transcript(&self, input: &str, result: Result<String, String>) {
        let (output, error) = match result {
            Ok(text) => (text, false),
            Err(text) => (text, true),
        };
        let entry = Entry { input: input.to_string(), output, error };
        self.publish(|shared| shared.transcript.push(entry));
    }

    fn forward_console(&mut self) {
        let Some(client) = self.client.as_mut() else { return };
        let text = client.take_console();
        if !text.is_empty() {
            self.publish(|shared| shared.console.push_str(&text));
        }
    }

    fn tail_serial(&mut self) {
        let Some(path) = self.config.serial_log.clone() else { return };
        let Ok(mut file) = std::fs::File::open(&path) else { return };
        let Ok(length) = file.metadata().map(|metadata| metadata.len()) else { return };
        if length < self.serial_offset {
            self.serial_offset = 0;
        }
        if length == self.serial_offset || file.seek(SeekFrom::Start(self.serial_offset)).is_err() {
            return;
        }
        let mut bytes = Vec::new();
        if file.take(1 << 20).read_to_end(&mut bytes).is_ok() && !bytes.is_empty() {
            self.serial_offset += bytes.len() as u64;
            let text = String::from_utf8_lossy(&bytes).into_owned();
            self.publish(|shared| {
                shared.serial.push_str(&text);
                if shared.serial.len() > 4 << 20 {
                    let cut = shared.serial.len() - (2 << 20);
                    let cut = (cut..shared.serial.len()).find(|&index| shared.serial.is_char_boundary(index)).unwrap_or(0);
                    shared.serial.drain(..cut);
                }
            });
        }
    }

    /// Com a máquina rodando: DbgPrint e a parada.
    fn poll_target(&mut self) {
        let Some(client) = self.client.as_mut() else { return };
        match client.poll(Duration::from_millis(30)) {
            Ok(Some(_)) => {
                self.view = View::Owner;
                self.selected_frame = 0;
                self.focus = Focus::Frame;
                self.refresh();
            }
            Ok(None) => {}
            Err(error) => self.lost(error),
        }
    }

    /// A conexão caiu (o QEMU fechou).
    fn lost(&mut self, error: String) {
        self.client = None;
        if let Some(mut launch) = self.launch.take() {
            launch.stop();
        }
        self.set_status(Status::Disconnected(error));
    }

    fn handle(&mut self, request: Request) {
        match request {
            Request::Start(target) => return self.start(target),
            Request::Restart => {
                if let Some(target) = self.target.clone() {
                    self.start(target);
                }
                return;
            }
            Request::Disconnect => {
                self.disconnect("desconectado");
                return;
            }
            Request::Shutdown => return,
            _ => {}
        }
        if self.client.is_none() {
            return;
        }
        let stopped = self.client.as_ref().is_some_and(Client::is_stopped);
        let result: Result<bool, String> = match request {
            Request::Break => self.with_client(|client| client.interrupt()).map(|_| false),
            Request::Go => self.resume(|client| client.go().map(|_| Resumed::Running)),
            Request::StepInto => self.resume(|client| client.step().map(Resumed::Stopped)),
            Request::StepOver => self.resume(Client::step_over),
            Request::StepOut => self.resume(Client::step_out),
            Request::Command(line) => self.command(&line),
            Request::SelectCpu(thread) => self.with_client(|client| client.select_thread(thread)).map(|_| {
                self.view = View::Cpu(thread);
                self.selected_frame = 0;
                self.focus = Focus::Frame;
                true
            }),
            Request::SelectThread(ethread) => self.select_thread(ethread),
            Request::SelectFrame(index) => {
                self.selected_frame = index;
                self.focus = Focus::Frame;
                Ok(true)
            }
            Request::ToggleBreakpoint(address) => self.with_client(|client| client.toggle_breakpoint(address)).map(|_| true),
            Request::AddBreakpoint(kind, expression) => {
                let length = if matches!(kind, BreakpointKind::Write | BreakpointKind::Access) { 8 } else { 1 };
                self.with_client(|client| client.add_breakpoint(kind, &expression, length)).map(|_| true)
            }
            Request::RemoveBreakpoint(id) => self.with_client(|client| client.remove_breakpoint(id)).map(|_| true),
            Request::EnableBreakpoint(id, enabled) => self.with_client(|client| client.set_breakpoint_enabled(id, enabled)).map(|_| true),
            Request::ShowCode(expression) => {
                if expression.trim().is_empty() {
                    self.focus = Focus::Frame;
                    Ok(true)
                } else {
                    self.with_client(|client| client.evaluate(&expression)).map(|address| {
                        self.focus = Focus::Fixed(address);
                        true
                    })
                }
            }
            Request::ShowMemory(expression) => {
                self.memory_expression = expression;
                Ok(true)
            }
            Request::WriteMemory(address, bytes) => self.with_client(|client| client.write_memory(address, &bytes)).map(|_| true),
            Request::WriteRegister(name, value) => self.with_client(|client| client.write_register(&name, value)).map(|_| true),
            Request::Refresh => Ok(true),
            Request::Start(_) | Request::Restart | Request::Disconnect | Request::Shutdown => Ok(false),
        };
        match result {
            Ok(true) if stopped || self.client.as_ref().is_some_and(Client::is_stopped) => self.refresh(),
            Ok(_) => {}
            Err(error) => {
                if is_connection_error(&error) {
                    self.lost(error);
                } else {
                    self.transcript("(interface)", Err(error));
                    if self.client.as_ref().is_some_and(Client::is_stopped) {
                        self.refresh();
                    }
                }
            }
        }
    }

    fn with_client<T>(&mut self, action: impl FnOnce(&mut Client) -> Result<T, String>) -> Result<T, String> {
        match self.client.as_mut() {
            Some(client) => action(client),
            None => Err("sem conexao com o alvo".into()),
        }
    }

    /// Continua ou dá um passo; a parada (quando a máquina segue) chega
    /// pelo `poll_target`.
    fn resume(&mut self, action: impl FnOnce(&mut Client) -> Result<Resumed, String>) -> Result<bool, String> {
        self.set_activity("executando");
        let result = self.with_client(action);
        self.set_activity("");
        self.view = View::Owner;
        self.selected_frame = 0;
        self.focus = Focus::Frame;
        match result? {
            Resumed::Stopped(_) => Ok(true),
            Resumed::Running => {
                self.set_status(Status::Running);
                Ok(false)
            }
        }
    }

    /// Os comandos que mudam o estado da máquina viram as ações dos botões
    /// (a interface não espera a parada); os outros vão ao cliente.
    fn command(&mut self, line: &str) -> Result<bool, String> {
        let trimmed = line.trim();
        let word = trimmed.split_whitespace().next().unwrap_or("");
        let action = match word {
            "c" | "g" | "continue" if trimmed == word => Some(Request::Go),
            "p" if trimmed == word => Some(Request::StepOver),
            "gu" => Some(Request::StepOut),
            "break" | "halt" => Some(Request::Break),
            _ => None,
        };
        if let Some(action) = action {
            self.transcript(trimmed, Ok(String::new()));
            self.handle(action);
            return Ok(false);
        }
        self.set_activity(trimmed);
        let result = self.with_client(|client| client.execute(trimmed));
        self.set_activity("");
        let refresh = result.is_ok();
        self.forward_console();
        let connection = result.as_ref().err().is_some_and(|error| is_connection_error(error));
        self.transcript(trimmed, result.clone());
        if connection {
            return Err(result.err().unwrap_or_default());
        }
        if !self.client.as_ref().is_some_and(Client::is_stopped) {
            self.set_status(Status::Running);
            return Ok(false);
        }
        Ok(refresh)
    }

    fn select_thread(&mut self, ethread: u64) -> Result<bool, String> {
        let context = self.with_client(|client| client.thread_context(ethread))?;
        match context.processor {
            Some(processor) => {
                self.with_client(|client| client.select_thread(processor + 1))?;
                self.view = View::Cpu(processor + 1);
            }
            None => self.view = View::Thread(ethread),
        }
        self.selected_frame = 0;
        self.focus = Focus::Frame;
        Ok(true)
    }

    /// Monta e publica o snapshot da parada.
    fn refresh(&mut self) {
        self.set_activity("lendo o estado da maquina");
        let snapshot = self.build_snapshot();
        self.set_activity("");
        match snapshot {
            Ok(snapshot) => {
                self.publish(|shared| {
                    shared.snapshot = Arc::new(snapshot);
                    shared.status = Status::Stopped;
                });
            }
            Err(error) if is_connection_error(&error) => self.lost(error),
            Err(error) => self.transcript("(interface)", Err(error)),
        }
    }

    fn build_snapshot(&mut self) -> Result<Snapshot, String> {
        self.generation += 1;
        let mut snapshot = Snapshot { generation: self.generation, view: self.view, selected_frame: self.selected_frame, memory: MemoryView { expression: self.memory_expression.clone(), ..Default::default() }, ..Default::default() };
        let view = self.view;
        let elf = self.config.elf.clone();
        let Some(client) = self.client.as_mut() else { return Err("sem conexao com o alvo".into()) };
        snapshot.stop = client.last_stop().to_string();
        snapshot.stop_processor = client.stop_reply().and_then(|stop| stop.processor());
        snapshot.stopped_threads = client.stopped_threads()?;
        snapshot.processors = client.processors().unwrap_or_default();
        // Registradores e pilha da visão escolhida.
        let frames = match view {
            View::Thread(ethread) => {
                let (context, frames) = client.thread_backtrace(ethread, 64)?;
                snapshot.view_header = context.header.clone();
                snapshot.registers = context.registers.iter().map(|(name, value)| RegisterRow { name: name.clone(), value: Some(*value), changed: false }).collect();
                snapshot.registers_editable = false;
                frames
            }
            View::Owner | View::Cpu(_) => {
                let mut rows: Vec<RegisterRow> = client.general_registers()?.into_iter().map(|value| RegisterRow { name: value.layout.name.to_string(), value: value.value, changed: false }).collect();
                for layout in registers::EXTRA {
                    rows.push(RegisterRow { name: layout.name.to_string(), value: client.register(layout.name).ok(), changed: false });
                }
                let key = |row: &RegisterRow| format!("{:?}:{}", view, row.name);
                for row in &mut rows {
                    if let (Some(value), Some(previous)) = (row.value, self.previous_registers.get(&key(row))) {
                        row.changed = value != *previous;
                    }
                }
                for row in &rows {
                    if let Some(value) = row.value {
                        self.previous_registers.insert(key(row), value);
                    }
                }
                snapshot.view_header = match view {
                    View::Cpu(thread) => format!("CPU {} (thread {thread} do protocolo)", thread.saturating_sub(1)),
                    _ => snapshot.stop_processor.map(|number| format!("CPU {number} (a da parada)")).unwrap_or_default(),
                };
                snapshot.registers = rows;
                snapshot.registers_editable = true;
                client.backtrace(64)?
            }
        };
        snapshot.frames = frames.iter().map(|frame| FrameRow { address: frame.address, name: client.frame_name(frame) }).collect();
        if snapshot.selected_frame >= frames.len() {
            snapshot.selected_frame = 0;
        }
        // Código em volta do quadro escolhido (ou do endereço pedido).
        let focus = match self.focus {
            Focus::Fixed(address) => address,
            // O quadro de cima mostra o endereço de retorno (depois do `call`).
            Focus::Frame => frames.get(snapshot.selected_frame).map_or(0, |frame| frame.address),
        };
        snapshot.code = code_view(client, focus);
        // Memória pedida.
        if !snapshot.memory.expression.trim().is_empty() {
            match client.evaluate(&snapshot.memory.expression) {
                Ok(address) => {
                    snapshot.memory.address = address;
                    match client.read_memory(address, 0x200) {
                        Ok(bytes) => snapshot.memory.bytes = bytes,
                        Err(error) => snapshot.memory.error = Some(error),
                    }
                }
                Err(error) => snapshot.memory.error = Some(error),
            }
        }
        snapshot.modules = client.symbols.modules.iter().map(|module| ModuleRow { base: module.base, end: module.end, name: module.name.clone(), symbols: module.symbols.len(), source: module.source.clone() }).collect();
        snapshot.processes = client.processes().unwrap_or_default();
        snapshot.threads = client.threads(None).unwrap_or_default().into_iter().map(|thread| ThreadRow { start: client.symbols.describe(thread.start), thread }).collect();
        snapshot.breakpoints = client.breakpoints().to_vec();
        // Linha de código (só o kernel do OpenNT tem DWARF).
        if self.lines.is_none() {
            self.set_activity("lendo o DWARF do kernel.elf");
            self.lines = Some(LineTable::load(&elf));
        }
        match self.lines.as_mut() {
            Some(Ok(table)) => match table.locate(focus) {
                Some(position) => match table.file(&position.file) {
                    Some(text) => snapshot.source = Some(SourceView { file: position.file, line: position.line, text }),
                    None => snapshot.source_error = Some(format!("{}:{} (arquivo indisponivel)", position.file, position.line)),
                },
                None => snapshot.source_error = Some(format!("sem linha de codigo para {focus:#x} (so o kernel do OpenNT tem DWARF)")),
            },
            Some(Err(error)) => snapshot.source_error = Some(error.clone()),
            None => {}
        }
        Ok(snapshot)
    }
}

/// A desmontagem em volta de `focus`.
fn code_view(client: &mut Client, focus: u64) -> CodeView {
    const BEFORE: u64 = 0x120;
    const AFTER: u64 = 0x180;
    let mut view = CodeView { focus, ..Default::default() };
    if focus == 0 {
        return view;
    }
    let start = disasm::window_start(focus, &client.symbols, BEFORE);
    let attempt = |client: &mut Client, start: u64| -> Result<Option<Vec<Line>>, String> {
        let bytes = client.read_memory(start, (focus - start + AFTER) as usize)?;
        Ok(disasm::clip(disasm::disassemble(start, &bytes, Some(&client.symbols)), focus, BEFORE, AFTER))
    };
    match attempt(client, start) {
        Ok(Some(lines)) => view.lines = lines,
        Ok(None) => match attempt(client, focus) {
            Ok(Some(lines)) => view.lines = lines,
            Ok(None) => view.error = Some(format!("{focus:#x}: desmontagem desalinhada")),
            Err(error) => view.error = Some(error),
        },
        Err(_) => match attempt(client, focus) {
            Ok(Some(lines)) => view.lines = lines,
            Ok(None) => view.error = Some(format!("{focus:#x}: desmontagem desalinhada")),
            Err(error) => view.error = Some(error),
        },
    }
    view
}

/// O erro é de conexão (o alvo sumiu), não de um comando.
fn is_connection_error(error: &str) -> bool {
    error.contains("fechou a conexao") || error.contains("depurador:") || error.contains("os error") || error.contains("nao confirmou")
}
