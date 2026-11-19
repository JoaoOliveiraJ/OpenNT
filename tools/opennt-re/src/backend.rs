//! O lado do depurador que fala com o alvo, numa thread própria: a
//! interface manda pedidos (`Request`) e lê o estado publicado (`Shared`),
//! sem nunca esperar o socket. Sem janela nenhuma, o mesmo backend roda nos
//! testes (`tests/smoke.rs`) e na captura de tela.
//!
//! A cada parada o backend monta um `Snapshot` inteiro: registradores do
//! processador (ou da thread) escolhido, a pilha, a desmontagem em volta do
//! quadro escolhido com a linha de código e as variáveis locais quando o
//! DWARF as tem, a memória pedida, as expressões observadas, as vistas
//! tipadas abertas, a última consulta do NT, a análise do bugcheck, módulos,
//! processadores, processos, threads e breakpoints. Os rastros ficam fora
//! do snapshot (`Shared::trace`), com o símbolo e a instrução de cada RIP.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use opennt_kd::analysis::functions::{Function, Loop};
use opennt_kd::bugcheck::Analysis;
use opennt_kd::client::{BreakpointRequest, Resumed};
use opennt_kd::commands::TraceOptions;
use opennt_kd::monitor::{Process, Processor, Thread};
use opennt_kd::rsp::Connection;
use opennt_kd::trace::{self, Class, Source, Trace};
use opennt_kd::types::Field;
use opennt_kd::registers::ExtendedState;
use opennt_kd::{registers, Breakpoint, BreakpointKind, Client};
use opennt_mcp::annotate::{self, Live};

use crate::annotations::{self, ImportCache};
use crate::disasm::{self, Line};
use crate::launcher::{Launch, LaunchOptions};
use crate::source::{Local, LineTable};

#[path = "backend/extras.rs"]
mod extras;
#[path = "backend/mcp.rs"]
mod mcp;
#[path = "backend/usermode.rs"]
mod usermode;
#[path = "backend/views.rs"]
mod views;
pub use extras::{ExtraRequest, ExtrasView, FilePreview, MonitorStore, RegistryKeyView, SharedStore, StructTree, TimeMode};
pub use usermode::{FileSymbols, PdbState, PlanRow, ProcessRow, ThreadStacks, UserThreadRow, UserModuleRow, UserRequest, UserView};
pub use views::{GraphBlock, GraphView, MapRow, MemoryMapView, ReferenceRow, ReferenceView, SearchKind, SearchQuery, SearchScope, SehRow, StackRow, SymbolView, XrefRow, XrefView};
use opennt_kd::analysis::notes::Patch;
use opennt_kd::user::{Handle, ProcessContext, UserThread};

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
    /// Onde gravar e de onde recriar os breakpoints (`None` = sem sessão).
    pub session: Option<PathBuf>,
    /// Um roteiro para rodar depois do attach (`--script`).
    pub script: Option<PathBuf>,
}

/// As consultas da janela Objetos do NT.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QueryKind {
    Process,
    Thread,
    Irp,
    Device,
    Driver,
    Object,
    Handle,
    Module,
    Type,
    Analyze,
}

impl QueryKind {
    pub const ALL: [QueryKind; 10] = [QueryKind::Process, QueryKind::Thread, QueryKind::Irp, QueryKind::Device, QueryKind::Driver, QueryKind::Object, QueryKind::Handle, QueryKind::Module, QueryKind::Type, QueryKind::Analyze];

    pub fn label(self) -> &'static str {
        match self {
            QueryKind::Process => "Processo (EPROCESS)",
            QueryKind::Thread => "Thread (ETHREAD)",
            QueryKind::Irp => "IRP",
            QueryKind::Device => "Dispositivo (DEVICE_OBJECT)",
            QueryKind::Driver => "Driver (DRIVER_OBJECT)",
            QueryKind::Object => "Objeto por nome",
            QueryKind::Handle => "Handle (processo handle)",
            QueryKind::Module => "Modulo carregado",
            QueryKind::Type => "Struct do NT (tipo endereco)",
            QueryKind::Analyze => "Analise do bugcheck",
        }
    }

    /// O comando de texto equivalente.
    pub fn command(self, argument: &str) -> String {
        match self {
            QueryKind::Process => format!("!process {argument}"),
            QueryKind::Thread => format!("!thread {argument}"),
            QueryKind::Irp => format!("!irp {argument}"),
            QueryKind::Device => format!("!devobj {argument}"),
            QueryKind::Driver => format!("!drvobj {argument}"),
            QueryKind::Object => format!("!object {argument}"),
            QueryKind::Handle => format!("!handle {argument}"),
            QueryKind::Module => format!("lmv {argument}"),
            QueryKind::Type => format!("dt {argument}"),
            QueryKind::Analyze => "!analyze".into(),
        }
    }
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
    AddBreakpointWith(BreakpointRequest),
    RemoveBreakpoint(u32),
    EnableBreakpoint(u32, bool),
    /// Condição e contagem de um breakpoint.
    SetBreakpointCondition(u32, String, u64),
    /// Desmontagem num endereço ou símbolo (vazio: volta a seguir o RIP).
    ShowCode(String),
    ShowMemory(String),
    WriteMemory(u64, Vec<u8>),
    WriteRegister(String, u64),
    /// As expressões da janela de observação.
    SetWatches(Vec<String>),
    /// As vistas tipadas abertas (endereço, tipo).
    SetExpanded(Vec<(u64, u32)>),
    Query(QueryKind, String),
    /// Procura bytes (hexadecimal, `"texto"` ou `u"texto"`) a partir de uma
    /// expressão.
    SearchMemory { start: String, length: u64, pattern: String },
    /// Rastro passo a passo no convidado.
    Trace(TraceOptions),
    /// Rastro pelo log de execução do QEMU (TCG): até o endereço, ou pelo
    /// tempo.
    QemuTrace { milliseconds: u64, until: String },
    SaveTrace(PathBuf),
    LoadReference(PathBuf),
    TraceAsReference,
    ReloadSymbols,
    /// Teclas pelo monitor HMP do QEMU (`sendkey`, como
    /// `ctrl_r-scroll_lock-scroll_lock`, o despejo manual do teclado).
    SendKeys(String),
    Refresh,
    Shutdown,
    /// O processo das leituras (EPROCESS; `None` = o kernel).
    SelectProcess(Option<u64>),
    /// Uma das janelas Dump 1-5 numa expressão.
    ShowDump(usize, String),
    /// A instrução da caixa de informação.
    SelectInstruction(Option<u64>),
    RunToCursor(u64),
    RunToUserCode,
    /// O grafo da função que contém a expressão (vazia = o RIP).
    Graph(String),
    Search(SearchQuery),
    /// Monta uma linha em assembly no endereço (patch).
    Assemble { address: u64, text: String },
    /// Grava bytes como patch.
    Patch { address: u64, bytes: Vec<u8> },
    RevertPatch(u64),
    RevertAllPatches,
    ExportPatches(PathBuf),
    LoadMemoryMap,
    LoadHandles,
    LoadUserThreads,
    /// Uma thread de usuário do processo escolhido (o CONTEXT salvo).
    SelectUserThread(u64),
    /// Símbolos, exports e imports do módulo nesta base.
    LoadSymbols(u64),
    RunScript(String),
    SetUserExceptions(bool),
    SetGroupEnabled(String, bool),
    /// Log, comandos de parada e grupo de um breakpoint.
    SetBreakpointActions(u32, String, String, String),
    /// Vigia uma faixa (escrita ou acesso) com até quatro comparadores.
    AddRangeWatch(BreakpointKind, String, u64),
    /// Todas as opções de um breakpoint (o editor).
    EditBreakpoint(u32, BreakpointRequest),
    /// Quem referencia o endereço (a análise do módulo, feita aos poucos
    /// numa thread) e o que sai da função dele.
    Xrefs(u64),
    /// O tipo de um registrador a partir de uma instrução (`type_name`
    /// vazio tira): os operandos `[reg+deslocamento]` ganham o nome do campo.
    RegisterType { address: u64, register: String, type_name: String },
    /// Grava uma faixa de memória num arquivo.
    DumpToFile { address: u64, size: u64, path: PathBuf },
    /// Quantos argumentos a caixa da convenção de chamada mostra.
    SetArgumentCount(usize),
    /// A janela de pilha numa expressão (vazia = presa ao RSP).
    ShowStack(String),
    /// O deslocamento no arquivo do endereço vai à área de transferência.
    CopyFileOffset(u64),
    /// Uma mensagem do servidor MCP hospedado (a resposta volta pelo canal).
    Mcp { message: String, reply: Sender<Option<String>> },
    /// Liga (na porta) ou desliga o servidor MCP da janela.
    SetMcp(Option<u16>),
    /// As abas do monitor de APIs, dos IRPs, dos tipos, dos exploradores,
    /// dos snapshots e da reprodução (`backend/extras.rs`).
    Extra(ExtraRequest),
    /// As abas Processos e Exceção (`backend/usermode.rs`).
    User(UserRequest),
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
    /// Uma thread de usuário do processo escolhido (TID; o CONTEXT salvo).
    UserThread(u64),
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
    /// O RSP do quadro.
    pub stack: u64,
    /// Como o quadro foi achado (`.pdata`, frame pointer...).
    pub method: &'static str,
    /// O espaço de home (rcx, rdx, r8, r9 guardados) e os primeiros
    /// argumentos da pilha, no RSP do quadro de quem chamou.
    pub arguments: Vec<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct CodeView {
    /// O endereço destacado (o RIP do quadro, ou o pedido).
    pub focus: u64,
    pub lines: Vec<Line>,
    pub error: Option<String>,
    /// As funções que cobrem as linhas (os colchetes da margem).
    pub functions: Vec<Function>,
    /// Os laços dessas funções.
    pub loops: Vec<Loop>,
    /// Os comentários automáticos (chamadas com argumentos, strings).
    pub auto_comments: HashMap<u64, String>,
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
    pub file_name: String,
    pub symbols: usize,
    pub source: String,
    pub pdb: bool,
    pub pending: bool,
    /// Módulo de usuário do processo escolhido.
    pub user: bool,
}

/// Uma expressão observada.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchRow {
    pub expression: String,
    pub value: Result<String, String>,
    /// Valor tipado que abre (endereço, tipo) e o nome do tipo.
    pub typed: Option<(u64, u32)>,
    pub type_name: String,
    /// O valor mudou desde a parada anterior.
    pub changed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryResult {
    pub kind: QueryKind,
    pub argument: String,
    pub text: Result<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SearchResult {
    pub pattern: String,
    pub start: u64,
    pub hits: Vec<u64>,
    pub error: Option<String>,
}

/// O estado do alvo numa parada.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    /// Cresce a cada snapshot novo.
    pub generation: u64,
    pub stop: String,
    /// O processador da parada.
    pub stop_processor: Option<u64>,
    /// O sinal da parada (6 = bugcheck ou pânico).
    pub stop_signal: u8,
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
    pub locals: Vec<Local>,
    pub locals_note: String,
    pub memory: MemoryView,
    pub modules: Vec<ModuleRow>,
    pub processors: Vec<Processor>,
    pub stopped_threads: Vec<u64>,
    pub processes: Vec<Process>,
    pub threads: Vec<ThreadRow>,
    pub breakpoints: Vec<Breakpoint>,
    pub watches: Vec<WatchRow>,
    /// Os campos das vistas tipadas abertas.
    pub typed: HashMap<(u64, u32), Result<Vec<Field>, String>>,
    pub query: Option<QueryResult>,
    pub bugcheck: Option<Analysis>,
    pub search: Option<SearchResult>,
    pub types_note: String,
    /// O processo das leituras.
    pub process: Option<ProcessContext>,
    /// A parada é numa thread de usuário.
    pub user_mode: bool,
    /// Dump 1-5.
    pub dumps: Vec<MemoryView>,
    /// A pilha em qwords.
    pub stack: Vec<StackRow>,
    /// A caixa de informação da instrução escolhida.
    pub info_box: Vec<String>,
    pub seh: Vec<SehRow>,
    /// A parada em palavras (breakpoint, exceção, modo).
    pub exception: Option<String>,
    pub memory_map: Option<Arc<MemoryMapView>>,
    pub handles: Option<Arc<Result<Vec<Handle>, String>>>,
    pub user_threads: Option<Arc<Result<Vec<UserThread>, String>>>,
    pub graph: Option<Arc<GraphView>>,
    pub references: Option<Arc<ReferenceView>>,
    /// A busca de strings soltas (a aba Strings).
    pub strings: Option<Arc<ReferenceView>>,
    pub symbol_view: Option<Arc<SymbolView>>,
    pub patches: Vec<Patch>,
    /// LastErrorValue e LastStatusValue da TEB numa parada de usuário.
    pub last_error: Option<(u64, u64)>,
    /// O símbolo do valor de cada registrador que aponta para um módulo.
    pub register_notes: HashMap<String, String>,
    /// x87, MMX, SSE, AVX e os registradores de depuração do processador.
    pub extended: Option<ExtendedState>,
    /// A caixa da convenção x64: (n.º, onde, valor).
    pub arguments: Vec<(String, String, Option<u64>)>,
    /// A janela de referências cruzadas (tecla X).
    pub xrefs: Option<Arc<XrefView>>,
    /// A janela de pilha segue o RSP (senão, a expressão pedida).
    pub stack_locked: bool,
    /// Os processos de usuário, os módulos e as threads do escolhido, a
    /// exceção da parada e os planos de seguir (`backend/usermode.rs`).
    pub user: UserView,
}

/// Uma entrada do painel de comandos.
#[derive(Clone, Debug)]
pub struct Entry {
    pub input: String,
    pub output: String,
    pub error: bool,
}

/// O que um RIP do rastro é: símbolo, módulo, bytes e instrução.
#[derive(Clone, Debug, Default)]
pub struct RipInfo {
    pub symbol: String,
    pub module: String,
    pub bytes: Vec<u8>,
    pub text: String,
}

/// Um rastro pronto para a janela.
pub struct TraceView {
    pub trace: Trace,
    pub info: HashMap<u64, RipInfo>,
    pub title: String,
    pub summary: String,
}

impl TraceView {
    pub fn info(&self, rip: u64) -> Option<&RipInfo> {
        self.info.get(&rip)
    }
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
    pub trace: Option<Arc<TraceView>>,
    pub reference: Option<Arc<TraceView>>,
    /// Muda a cada rastro novo.
    pub trace_generation: u64,
    /// Os nomes de símbolo (o autocompletar), por geração dos símbolos.
    pub completions: Arc<Vec<String>>,
    /// Todos os símbolos de todos os módulos carregados, com o endereço (a
    /// busca aproximada da janela Ir para), por geração dos símbolos.
    pub symbol_index: Arc<Vec<crate::navigation::SymbolEntry>>,
    pub type_names: Arc<Vec<String>>,
    /// Texto para a área de transferência (a janela copia e limpa).
    pub clipboard: Option<String>,
    /// O servidor MCP hospedado (`127.0.0.1:porta`), quando ligado.
    pub mcp: Option<String>,
    /// O estado das abas novas (tipos, exploradores, snapshots, modo).
    pub extras: ExtrasView,
}

pub struct Backend {
    requests: Sender<Request>,
    pub shared: Arc<Mutex<Shared>>,
    /// O monitor de APIs e os IRPs (a janela lê sob a trava).
    pub store: SharedStore,
    thread: Option<JoinHandle<()>>,
}

/// Chamado quando o estado publicado muda (o `request_repaint` da janela).
pub type Notify = Arc<dyn Fn() + Send + Sync>;

impl Backend {
    pub fn start(config: Config, target: Option<Target>, notify: Notify) -> Backend {
        let (requests, receiver) = mpsc::channel();
        let shared = Arc::new(Mutex::new(Shared::default()));
        let store: SharedStore = Arc::new(Mutex::new(MonitorStore::default()));
        let mut worker = Worker::new(config, Arc::clone(&shared), notify);
        worker.store = Arc::clone(&store);
        worker.requests = Some(requests.clone());
        let thread = thread::Builder::new()
            .name("kd-backend".into())
            .spawn(move || worker.run(receiver, target))
            .expect("thread do backend");
        Backend { requests, shared, store, thread: Some(thread) }
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
    watches: Vec<String>,
    expanded: Vec<(u64, u32)>,
    query: Option<(QueryKind, String)>,
    search: Option<SearchResult>,
    symbols_generation: u64,
    types_published: bool,
    re: views::ReState,
    /// O canal dos pedidos (o servidor MCP hospedado manda por ele).
    requests: Option<Sender<Request>>,
    argument_count: usize,
    previous_watches: HashMap<String, String>,
    /// A expressão da janela de pilha (vazia = o RSP).
    stack_expression: String,
    mcp_server: opennt_mcp::Server,
    mcp_cache: opennt_mcp::ImageCache,
    mcp_stop: Option<Arc<std::sync::atomic::AtomicBool>>,
    store: SharedStore,
    /// Os processos de usuário, as exceções e os planos de seguir.
    user: usermode::UserState,
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
            watches: Vec::new(),
            expanded: Vec::new(),
            query: None,
            search: None,
            symbols_generation: u64::MAX,
            types_published: false,
            re: views::ReState::default(),
            requests: None,
            argument_count: 5,
            previous_watches: HashMap::new(),
            stack_expression: String::new(),
            mcp_server: opennt_mcp::Server::new(),
            mcp_cache: opennt_mcp::ImageCache::default(),
            mcp_stop: None,
            store: SharedStore::default(),
            user: usermode::UserState::default(),
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
                    self.set_mcp(None);
                    self.disconnect("encerrado");
                    return;
                }
                Ok(request) => self.handle(request),
                Err(RecvTimeoutError::Timeout) => {}
            }
            if self.client.as_ref().is_some_and(|client| !client.is_stopped()) {
                self.poll_target();
                self.sync_monitors();
            }
            // Um PDB que chegou: os nomes trocam sem esperar outra parada.
            if self.client.as_ref().is_some_and(|client| client.is_stopped() && client.symbols.pending() && !client.symbols.store.as_ref().is_some_and(|store| store.busy())) {
                let _ = self.with_client(|client| client.reload_modules());
                // Os de usuário também (o reload_modules só refaz os do kernel).
                let root = self.config.root.clone();
                let _ = self.with_client(|client| {
                    usermode::swap_user_pdbs(client, &root);
                    Ok(())
                });
                self.refresh();
            }
            // A janela Xrefs esperando lotes da análise de um módulo.
            self.poll_analysis();
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
        self.symbols_generation = u64::MAX;
        self.types_published = false;
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
        self.prepare_client(&mut client);
        self.set_activity("anexando (a maquina para no proximo tique)");
        match client.attach(Duration::from_secs(180)) {
            Ok(text) => {
                self.transcript("attach", Ok(text));
                // Os breakpoints da sessão anterior (os de módulos que ainda
                // não carregaram ficam adiados).
                if let Some(path) = &self.config.session {
                    if let Ok(text) = std::fs::read_to_string(path) {
                        let errors = client.restore_breakpoints(&text);
                        let restored = format!("{} breakpoints da sessao anterior ({})", client.breakpoints().len(), path.display());
                        self.transcript("(sessao)", if errors.is_empty() { Ok(restored) } else { Err(format!("{restored}\n{}", errors.join("\n"))) });
                    }
                }
                self.client = Some(client);
                self.after_attach();
                self.lines = None;
                self.re = views::ReState::default();
                self.user_after_attach();
                if let Some(path) = self.config.script.clone() {
                    match std::fs::read_to_string(&path) {
                        Ok(text) => {
                            let _ = self.run_script(&text);
                        }
                        Err(error) => self.transcript("(roteiro)", Err(format!("{}: {error}", path.display()))),
                    }
                }
                if self.client.as_ref().is_some_and(Client::is_stopped) {
                    self.refresh();
                }
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
                // Os planos de seguir: um evento do processo seguido arma os
                // breakpoints nele e a máquina segue sozinha.
                if self.follow_after_stop() {
                    return;
                }
                // Os comandos de parada do breakpoint (o "command on hit").
                let commands = self.client.as_ref().and_then(Client::stop_commands);
                if let Some((id, commands)) = commands {
                    for command in commands.split(';').map(str::trim).filter(|command| !command.is_empty()) {
                        let result = self.with_client(|client| client.execute(command));
                        self.transcript(&format!("(bp #{id}) {command}"), result);
                        if !self.client.as_ref().is_some_and(Client::is_stopped) {
                            self.set_status(Status::Running);
                            return;
                        }
                    }
                }
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

    /// Grava os breakpoints no arquivo da sessão.
    fn save_session(&self) {
        let (Some(path), Some(client)) = (&self.config.session, &self.client) else { return };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(path, client.breakpoint_specs());
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
            Request::SetWatches(watches) => {
                self.watches = watches;
                if self.client.as_ref().is_some_and(Client::is_stopped) {
                    self.refresh();
                }
                return;
            }
            Request::SetExpanded(expanded) => {
                self.expanded = expanded;
                if self.client.as_ref().is_some_and(Client::is_stopped) {
                    self.refresh();
                }
                return;
            }
            Request::Mcp { message, reply } => {
                self.mcp_message(&message, reply);
                return;
            }
            Request::SetMcp(port) => {
                self.set_mcp(port);
                return;
            }
            Request::SetArgumentCount(count) => {
                self.argument_count = count.min(16);
                if self.client.as_ref().is_some_and(Client::is_stopped) {
                    self.refresh();
                }
                return;
            }
            _ => {}
        }
        if self.client.is_none() {
            return;
        }
        let stopped = self.client.as_ref().is_some_and(Client::is_stopped);
        let mut breakpoints_changed = false;
        let result: Result<bool, String> = match request {
            Request::Break => self.with_client(|client| client.interrupt()).map(|_| false),
            Request::Go => self.resume(|client| client.go().map(|_| Resumed::Running)),
            Request::StepInto => self.resume(|client| client.step().map(Resumed::Stopped)),
            Request::StepOver => self.resume(Client::step_over),
            Request::StepOut => self.resume(Client::step_out),
            Request::Command(line) => {
                breakpoints_changed = matches!(line.split_whitespace().next(), Some("bp" | "bu" | "bc" | "bd" | "be" | "ba" | "hbp" | "hbc" | "watch" | "unwatch" | "sxe" | "sxd" | ".bpload"));
                self.command(&line)
            }
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
            Request::ToggleBreakpoint(address) => {
                breakpoints_changed = true;
                self.with_client(|client| client.toggle_breakpoint(address)).map(|_| true)
            }
            Request::AddBreakpoint(kind, expression) => {
                breakpoints_changed = true;
                let request = BreakpointRequest::new(kind, &expression);
                self.with_client(|client| client.add_breakpoint_with(&request)).map(|_| true)
            }
            Request::AddBreakpointWith(request) => {
                breakpoints_changed = true;
                self.with_client(|client| client.add_breakpoint_with(&request)).map(|_| true)
            }
            Request::RemoveBreakpoint(id) => {
                breakpoints_changed = true;
                self.with_client(|client| client.remove_breakpoint(id)).map(|_| true)
            }
            Request::EnableBreakpoint(id, enabled) => {
                breakpoints_changed = true;
                self.with_client(|client| client.set_breakpoint_enabled(id, enabled)).map(|_| true)
            }
            Request::SetBreakpointCondition(id, condition, pass_count) => {
                breakpoints_changed = true;
                self.with_client(|client| client.set_breakpoint_condition(id, &condition, pass_count)).map(|_| true)
            }
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
            Request::Query(kind, argument) => {
                self.query = Some((kind, argument));
                Ok(true)
            }
            Request::SearchMemory { start, length, pattern } => {
                self.set_activity("procurando na memoria");
                let result = self.search_memory(&start, length, &pattern);
                self.set_activity("");
                self.search = Some(result);
                Ok(true)
            }
            Request::Trace(options) => self.trace(&options),
            Request::QemuTrace { milliseconds, until } => self.qemu_trace(milliseconds, &until),
            Request::SaveTrace(path) => self.save_trace(&path),
            Request::LoadReference(path) => self.load_reference(&path),
            Request::TraceAsReference => {
                let current = self.shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).trace.clone();
                match current {
                    Some(trace) => {
                        self.publish(|shared| {
                            shared.reference = Some(trace);
                            shared.trace_generation += 1;
                        });
                        Ok(false)
                    }
                    None => Err("nenhum rastro para guardar como referencia".into()),
                }
            }
            Request::ReloadSymbols => self.with_client(|client| client.reload_modules()).map(|_| true),
            Request::SelectProcess(process) => self.select_process(process),
            Request::ShowDump(index, expression) => {
                if let Some(slot) = self.re.dumps.get_mut(index) {
                    *slot = expression;
                }
                self.update_quick_views()
            }
            Request::SelectInstruction(address) => {
                self.re.selected_instruction = address;
                self.update_quick_views()
            }
            Request::RunToCursor(address) => self.resume(|client| client.run_until(address, None).map(|_| Resumed::Running)),
            Request::RunToUserCode => {
                self.set_activity("executando ate o codigo de usuario");
                let result = self.run_to_user_code();
                self.set_activity("");
                self.view = View::Owner;
                self.selected_frame = 0;
                self.focus = Focus::Frame;
                result.map(|_| {
                    self.set_status(Status::Running);
                    false
                })
            }
            Request::Graph(expression) => {
                self.set_activity("montando o grafo da funcao");
                let result = self.build_graph(&expression);
                self.set_activity("");
                result
            }
            Request::Search(query) => {
                self.set_activity(&format!("procurando: {}", query.kind.title()));
                let result = self.search(&query);
                self.set_activity("");
                result
            }
            Request::Assemble { address, text } => self.assemble(address, &text),
            Request::Patch { address, bytes } => self.write_patch(address, &bytes),
            Request::RevertPatch(address) => self.revert_patch(address),
            Request::RevertAllPatches => self.revert_all_patches(),
            Request::ExportPatches(path) => self.export_patches(&path),
            Request::LoadMemoryMap => {
                self.set_activity("lendo o mapa de memoria");
                let result = self.load_memory_map();
                self.set_activity("");
                result
            }
            Request::LoadHandles => {
                self.set_activity("lendo a tabela de handles");
                let result = self.load_handles();
                self.set_activity("");
                result
            }
            Request::LoadUserThreads => self.load_user_threads(),
            Request::SelectUserThread(tid) => {
                self.view = View::UserThread(tid);
                self.selected_frame = 0;
                self.focus = Focus::Frame;
                Ok(true)
            }
            Request::LoadSymbols(base) => self.load_symbols(base),
            Request::RunScript(text) => {
                self.set_activity("rodando o roteiro");
                let result = self.run_script(&text);
                self.set_activity("");
                result
            }
            Request::SetUserExceptions(enabled) => self.with_client(|client| client.set_user_exceptions(enabled)).map(|text| {
                self.transcript("uex", Ok(text));
                false
            }),
            Request::SetGroupEnabled(group, enabled) => {
                breakpoints_changed = true;
                self.with_client(|client| client.set_group_enabled(&group, enabled)).map(|_| true)
            }
            Request::SetBreakpointActions(id, log, command, group) => {
                breakpoints_changed = true;
                self.with_client(|client| client.set_breakpoint_actions(id, &log, &command, &group)).map(|_| true)
            }
            Request::AddRangeWatch(kind, start, length) => {
                breakpoints_changed = true;
                self.with_client(|client| {
                    let address = client.evaluate(&start)?;
                    client.add_range_watch(kind, address, length)
                })
                .map(|_| true)
            }
            Request::SendKeys(keys) => self.send_keys(&keys).map(|_| false),
            Request::Refresh => Ok(true),
            Request::EditBreakpoint(id, request) => {
                breakpoints_changed = true;
                self.with_client(|client| client.edit_breakpoint(id, &request)).map(|_| true)
            }
            Request::Xrefs(address) => {
                self.set_activity("referencias cruzadas (analise do modulo)");
                let result = self.xrefs(address);
                self.set_activity("");
                result
            }
            Request::RegisterType { address, register, type_name } => self.set_register_type(address, &register, &type_name),
            Request::DumpToFile { address, size, path } => self.dump_to_file(address, size, &path),
            Request::ShowStack(expression) => {
                self.stack_expression = expression;
                Ok(true)
            }
            Request::CopyFileOffset(address) => self.copy_file_offset(address),
            Request::Extra(request) => {
                let result = self.extra(request);
                if let Err(error) = &result {
                    self.extras_message(error.clone());
                }
                result
            }
            Request::User(request) => self.user_request(request),
            Request::Start(_) | Request::Restart | Request::Disconnect | Request::Shutdown | Request::SetWatches(_) | Request::SetExpanded(_) | Request::Mcp { .. } | Request::SetMcp(_) | Request::SetArgumentCount(_) => Ok(false),
        };
        if breakpoints_changed && result.is_ok() {
            self.save_session();
        }
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
        // Os planos de seguir (`backend/usermode.rs`).
        if word == "seguir" {
            return self.follow_command(trimmed);
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
        if word == "trace" && refresh && trimmed.split_whitespace().nth(1).is_none_or(|second| !matches!(second, "show" | "tree" | "save" | "diff" | "status")) {
            self.publish_client_trace("rastro (comando)");
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
        self.extras_after_stop();
        self.set_activity("lendo o estado da maquina");
        let snapshot = self.build_snapshot();
        self.set_activity("");
        match snapshot {
            Ok(snapshot) => {
                // A parada vai para a janela antes dos nomes: refazer o
                // índice de todos os símbolos leva um tempo quando os
                // módulos mudam.
                self.publish(|shared| {
                    shared.snapshot = Arc::new(snapshot);
                    shared.status = Status::Stopped;
                });
                if let Some((symbols, types)) = self.completions() {
                    self.publish(|shared| {
                        if let Some((names, index)) = symbols {
                            shared.completions = Arc::new(names);
                            shared.symbol_index = Arc::new(index);
                        }
                        if let Some(types) = types {
                            shared.type_names = Arc::new(types);
                        }
                    });
                }
            }
            Err(error) if is_connection_error(&error) => self.lost(error),
            Err(error) => self.transcript("(interface)", Err(error)),
        }
    }

    /// Os nomes do autocompletar (só as funções) e o índice de todos os
    /// símbolos com o endereço, quando os símbolos mudaram; os tipos, na
    /// primeira vez que existem.
    #[allow(clippy::type_complexity)]
    fn completions(&mut self) -> Option<(Option<(Vec<String>, Vec<crate::navigation::SymbolEntry>)>, Option<Vec<String>>)> {
        let client = self.client.as_mut()?;
        let symbols = (client.symbols.generation != self.symbols_generation).then(|| {
            self.symbols_generation = client.symbols.generation;
            let mut names: Vec<String> = Vec::new();
            let mut index: Vec<crate::navigation::SymbolEntry> = Vec::new();
            for module in &client.symbols.modules {
                let prefix = if client.symbols.is_kernel(module) { String::new() } else { format!("{}!", module.name) };
                for symbol in &module.symbols {
                    let name = format!("{prefix}{}", symbol.name);
                    if symbol.function {
                        names.push(name.clone());
                    }
                    index.push(crate::navigation::SymbolEntry { name, address: symbol.address, function: symbol.function });
                }
            }
            names.sort();
            names.dedup();
            index.sort();
            index.dedup();
            (names, index)
        });
        let types = if self.types_published {
            None
        } else {
            // Só quando os tipos já foram carregados por alguma expressão.
            client.type_database_loaded().map(|database| {
                self.types_published = true;
                database.names_starting_with("_", 50_000)
            })
        };
        (symbols.is_some() || types.is_some()).then_some((symbols, types))
    }

    fn build_snapshot(&mut self) -> Result<Snapshot, String> {
        self.generation += 1;
        let mut snapshot = Snapshot { generation: self.generation, view: self.view, selected_frame: self.selected_frame, memory: MemoryView { expression: self.memory_expression.clone(), ..Default::default() }, ..Default::default() };
        let view = self.view;
        let elf = self.config.elf.clone();
        let Some(client) = self.client.as_mut() else { return Err("sem conexao com o alvo".into()) };
        snapshot.stop = client.last_stop().to_string();
        snapshot.stop_processor = client.stop_reply().and_then(|stop| stop.processor());
        snapshot.stop_signal = client.stop_reply().map_or(0, |stop| stop.signal);
        snapshot.stopped_threads = client.stopped_threads()?;
        snapshot.processors = client.processors().unwrap_or_default();
        // Registradores e pilha da visão escolhida.
        let frames = match view {
            View::UserThread(tid) => {
                let process = client.process().map(|context| format!("{:#x}", context.eprocess)).ok_or("nenhum processo escolhido")?;
                let thread = client.user_threads(&process)?.into_iter().find(|thread| thread.tid == tid).ok_or_else(|| format!("thread {tid} nao e do processo"))?;
                let (registers, frames) = client.user_thread_backtrace(&thread, 64)?;
                snapshot.view_header = format!("thread de usuario {tid} (TEB {:#x}, CONTEXT {:#x})", thread.teb, thread.context);
                snapshot.registers = registers.iter().map(|(name, value)| RegisterRow { name: name.clone(), value: Some(*value), changed: false }).collect();
                snapshot.registers_editable = false;
                frames
            }
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
                snapshot.extended = client.extended_registers().ok();
                client.backtrace(64)?
            }
        };
        // A caixa da convenção de chamada (RCX, RDX, R8, R9 e a pilha).
        let named: Vec<(String, u64)> = snapshot.registers.iter().filter_map(|row| row.value.map(|value| (row.name.clone(), value))).collect();
        snapshot.arguments = annotate::calling_convention_arguments(client, &named, self.argument_count);
        snapshot.frames = frames
            .iter()
            .map(|frame| FrameRow {
                address: frame.address,
                name: client.frame_name(frame),
                stack: frame.stack,
                method: match frame.method {
                    opennt_kd::unwind::Method::Context => "registradores",
                    opennt_kd::unwind::Method::Table => ".pdata",
                    opennt_kd::unwind::Method::Leaf => "folha",
                    opennt_kd::unwind::Method::Epilog => "epilogo",
                    opennt_kd::unwind::Method::FramePointer => "frame pointer",
                },
                arguments: Vec::new(),
            })
            .collect();
        if snapshot.selected_frame >= frames.len() {
            snapshot.selected_frame = 0;
        }
        // Código em volta do quadro escolhido (ou do endereço pedido).
        let focus = match self.focus {
            Focus::Fixed(address) => address,
            // O quadro de cima mostra o endereço de retorno (depois do `call`).
            Focus::Frame => frames.get(snapshot.selected_frame).map_or(0, |frame| frame.address),
        };
        let live = named.iter().find(|(name, _)| name == "rip").map(|(_, rip)| Live { rip: *rip, registers: named.clone() });
        snapshot.code = code_view(client, focus, live.as_ref(), &mut self.re);
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
        snapshot.modules = client
            .symbols
            .modules
            .iter()
            .map(|module| ModuleRow { base: module.base, end: module.end, name: module.name.clone(), file_name: module.file_name.clone(), symbols: module.symbols.len(), source: module.source.clone(), pdb: module.pdb.is_some(), pending: module.pdb_pending, user: module.user })
            .collect();
        snapshot.processes = client.processes().unwrap_or_default();
        snapshot.threads = client.threads(None).unwrap_or_default().into_iter().map(|thread| ThreadRow { start: client.symbols.describe(thread.start), thread }).collect();
        snapshot.breakpoints = client.breakpoints().to_vec();
        // Expressões observadas e as vistas tipadas abertas.
        for expression in &self.watches {
            let row = match client.evaluate_value(expression) {
                Ok(value) => {
                    let (typed, type_name) = match value.ty {
                        Some(ty) => {
                            let database = client.type_database();
                            let name = database.as_ref().map(|database| format!("{}{}", database.name(ty.index), "*".repeat(ty.pointers as usize))).unwrap_or_default();
                            // Abre o que aponta para uma struct ou é uma.
                            let openable = database.as_ref().and_then(|database| {
                                if ty.pointers == 1 {
                                    Some((value.number, ty.index))
                                } else if ty.pointers == 0 {
                                    match database.kind(ty.index) {
                                        opennt_kd::types::Kind::Struct { .. } | opennt_kd::types::Kind::Array { .. } => Some((value.address.unwrap_or(value.number), ty.index)),
                                        opennt_kd::types::Kind::Pointer { target } if matches!(database.kind(target), opennt_kd::types::Kind::Struct { .. }) => Some((value.number, target)),
                                        _ => None,
                                    }
                                } else {
                                    None
                                }
                            });
                            (openable, name)
                        }
                        None => (None, String::new()),
                    };
                    let symbol = client.symbols.name_at(value.number).map(|name| format!(" {name}")).unwrap_or_default();
                    WatchRow { expression: expression.clone(), value: Ok(format!("{:#x} ({}){symbol}", value.number, value.number as i64)), typed, type_name, changed: false }
                }
                Err(error) => WatchRow { expression: expression.clone(), value: Err(error), typed: None, type_name: String::new(), changed: false },
            };
            // O destaque do que mudou desde a parada anterior.
            let mut row = row;
            if let Ok(text) = &row.value {
                row.changed = self.previous_watches.get(expression).is_some_and(|previous| previous != text);
                self.previous_watches.insert(expression.clone(), text.clone());
            }
            snapshot.watches.push(row);
        }
        let mut wanted: Vec<(u64, u32)> = self.expanded.clone();
        wanted.extend(snapshot.watches.iter().filter_map(|row| row.typed));
        let mut seen = HashSet::new();
        for (address, ty) in wanted {
            if seen.insert((address, ty)) {
                snapshot.typed.insert((address, ty), client.typed_fields(ty, address));
            }
        }
        snapshot.types_note = client.types_note.clone();
        // A consulta do NT pedida.
        if let Some((kind, argument)) = self.query.clone() {
            let text = client.execute(&kind.command(&argument));
            snapshot.query = Some(QueryResult { kind, argument, text });
        }
        // Parada por bugcheck: a análise vem junto (o sinal 6 do anel 3 é
        // uma exceção de usuário, como o int 0x29 do __fastfail).
        if snapshot.stop_signal == 6 && !client.stopped_in_user_mode() {
            snapshot.bugcheck = client.analyze().ok();
        }
        snapshot.search = self.search.clone();
        self.add_re_views(&mut snapshot);
        self.add_user_views(&mut snapshot);
        // Linha de código e variáveis locais (só o kernel do OpenNT tem DWARF).
        if self.lines.is_none() {
            self.set_activity("lendo o DWARF do kernel.elf");
            self.lines = Some(LineTable::load(&elf));
        }
        let Some(client) = self.client.as_mut() else { return Err("sem conexao com o alvo".into()) };
        match self.lines.as_mut() {
            Some(Ok(table)) => {
                match table.locate(focus) {
                    Some(position) => match table.file(&position.file) {
                        Some(text) => snapshot.source = Some(SourceView { file: position.file, line: position.line, text }),
                        None => snapshot.source_error = Some(format!("{}:{} (arquivo indisponivel)", position.file, position.line)),
                    },
                    None => snapshot.source_error = Some(format!("sem linha de codigo para {focus:#x} (so o kernel do OpenNT tem DWARF)")),
                }
                // As locais do quadro de cima (os registradores são os dele).
                if snapshot.selected_frame == 0 && matches!(self.focus, Focus::Frame) && !matches!(view, View::Thread(_)) {
                    let registers: Vec<(String, u64)> = snapshot.registers.iter().filter_map(|row| row.value.map(|value| (row.name.clone(), value))).collect();
                    match table.locals(focus, &registers, client) {
                        Ok(locals) => snapshot.locals = locals,
                        Err(note) => snapshot.locals_note = note,
                    }
                } else {
                    snapshot.locals_note = "variaveis locais so no quadro de cima".into();
                }
            }
            Some(Err(error)) => snapshot.source_error = Some(error.clone()),
            None => {}
        }
        Ok(snapshot)
    }

    /// Procura um padrão na memória (em blocos de 64 KB).
    fn search_memory(&mut self, start: &str, length: u64, pattern: &str) -> SearchResult {
        let mut result = SearchResult { pattern: pattern.to_string(), ..Default::default() };
        let needle = match parse_pattern(pattern) {
            Ok(needle) if !needle.is_empty() => needle,
            Ok(_) => {
                result.error = Some("padrao vazio".into());
                return result;
            }
            Err(error) => {
                result.error = Some(error);
                return result;
            }
        };
        let Some(client) = self.client.as_mut() else { return result };
        let base = match client.evaluate(start) {
            Ok(base) => base,
            Err(error) => {
                result.error = Some(error);
                return result;
            }
        };
        result.start = base;
        let length = length.clamp(1, 64 << 20);
        let chunk = 0x10000u64;
        let mut offset = 0u64;
        let mut tail: Vec<u8> = Vec::new();
        while offset < length && result.hits.len() < 256 {
            let size = chunk.min(length - offset) as usize;
            let bytes = match client.read_memory(base + offset, size) {
                Ok(bytes) => bytes,
                Err(_) => {
                    // Página sem mapa: pula para a próxima.
                    offset = ((base + offset + 0x1000) & !0xFFF) - base;
                    tail.clear();
                    continue;
                }
            };
            let mut window = std::mem::take(&mut tail);
            let window_start = base + offset - window.len() as u64;
            window.extend_from_slice(&bytes);
            for position in 0..window.len().saturating_sub(needle.len() - 1) {
                if window[position..position + needle.len()] == needle[..] {
                    let address = window_start + position as u64;
                    if result.hits.last() != Some(&address) {
                        result.hits.push(address);
                    }
                }
            }
            tail = window[window.len().saturating_sub(needle.len() - 1)..].to_vec();
            offset += bytes.len().max(1) as u64;
            if bytes.len() < size {
                offset = ((base + offset + 0xFFF) & !0xFFF) - base;
                tail.clear();
            }
        }
        result
    }

    /// O rastro do cliente vira um `TraceView` (símbolo e instrução de cada
    /// RIP, pelo código lido do alvo).
    fn publish_client_trace(&mut self, title: &str) {
        let Some(client) = self.client.as_mut() else { return };
        let Some(trace) = client.trace.clone() else { return };
        let view = build_trace_view(client, trace, title);
        self.publish(|shared| {
            shared.trace = Some(Arc::new(view));
            shared.trace_generation += 1;
        });
    }

    fn trace(&mut self, options: &TraceOptions) -> Result<bool, String> {
        self.set_activity("rastreando passo a passo no convidado");
        let result = self.with_client(|client| client.run_trace(options));
        self.set_activity("");
        let summary = result?;
        self.transcript("(rastro)", Ok(summary));
        self.set_activity("lendo as instrucoes do rastro");
        self.publish_client_trace("rastro passo a passo");
        self.set_activity("");
        Ok(true)
    }

    /// O caminho rápido: o log de execução do QEMU (`log exec,nochain` pelo
    /// monitor HMP) enquanto a máquina roda, até o endereço pedido ou pelo
    /// tempo; cada bloco executado vira as instruções dele.
    fn qemu_trace(&mut self, milliseconds: u64, until: &str) -> Result<bool, String> {
        let monitor = self.launch.as_ref().and_then(|launch| launch.monitor.clone()).ok_or("o rastro rapido precisa do QEMU aberto pelo depurador (--launch), com o monitor HMP")?;
        let log = match &self.target {
            Some(Target::Launch(options)) => options.build_path().join("qemu-exec.log"),
            _ => return Err("o rastro rapido precisa do --launch".into()),
        };
        let _ = std::fs::remove_file(&log);
        let mut hmp = TcpStream::connect(&monitor).map_err(|error| format!("monitor HMP {monitor}: {error}"))?;
        hmp.set_read_timeout(Some(Duration::from_millis(300))).ok();
        let command = |stream: &mut TcpStream, text: &str| -> Result<(), String> {
            stream.write_all(format!("{text}\n").as_bytes()).map_err(|error| format!("monitor HMP: {error}"))?;
            let mut sink = [0u8; 4096];
            let deadline = Instant::now() + Duration::from_millis(400);
            while Instant::now() < deadline {
                match stream.read(&mut sink) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            Ok(())
        };
        command(&mut hmp, &format!("logfile {}", log.display()))?;
        command(&mut hmp, "log exec,nochain")?;
        // Até o endereço (um breakpoint temporário) ou pelo tempo.
        let temporary = if until.trim().is_empty() { None } else { Some(self.with_client(|client| client.add_breakpoint(BreakpointKind::Software, until, 1))?) };
        self.set_status(Status::Running);
        self.set_activity("rastro rapido: a maquina roda com o log do QEMU");
        let run = (|| -> Result<(), String> {
            self.with_client(|client| client.go())?;
            match temporary {
                Some(_) => {
                    self.with_client(|client| client.wait_stop(Duration::from_millis(milliseconds.max(1000))))?;
                }
                None => {
                    thread::sleep(Duration::from_millis(milliseconds.clamp(10, 60_000)));
                    self.with_client(|client| client.break_in(Duration::from_secs(60)))?;
                }
            }
            Ok(())
        })();
        let _ = command(&mut hmp, "log none");
        if !self.client.as_ref().is_some_and(Client::is_stopped) {
            let _ = self.with_client(|client| client.break_in(Duration::from_secs(60)));
        }
        if let Some(breakpoint) = temporary {
            let _ = self.with_client(|client| client.remove_breakpoint(breakpoint.id));
        }
        self.set_activity("");
        run?;
        self.set_activity("lendo o log do QEMU");
        let text = std::fs::read(&log).map(|bytes| String::from_utf8_lossy(&bytes[..bytes.len().min(256 << 20)]).into_owned()).unwrap_or_default();
        let blocks = trace::parse_qemu_exec(&text);
        if blocks.is_empty() {
            self.set_activity("");
            return Err("o log do QEMU veio vazio: o rastro rapido precisa do TCG (--accel=tcg)".into());
        }
        let Some(client) = self.client.as_mut() else { return Err("sem conexao com o alvo".into()) };
        let trace = expand_qemu_blocks(client, &blocks, 2_000_000);
        let view = build_trace_view(client, trace, &format!("rastro rapido do QEMU ({} blocos)", blocks.len()));
        self.publish(|shared| {
            shared.trace = Some(Arc::new(view));
            shared.trace_generation += 1;
        });
        self.set_activity("");
        Ok(true)
    }

    fn send_keys(&mut self, keys: &str) -> Result<(), String> {
        let monitor = self.launch.as_ref().and_then(|launch| launch.monitor.clone()).ok_or("teclas pelo monitor HMP: so com o QEMU aberto pelo depurador (--launch)")?;
        let mut hmp = TcpStream::connect(&monitor).map_err(|error| format!("monitor HMP {monitor}: {error}"))?;
        hmp.write_all(format!("sendkey {keys} 30
").as_bytes()).map_err(|error| format!("monitor HMP: {error}"))?;
        thread::sleep(Duration::from_millis(300));
        Ok(())
    }

    fn save_trace(&mut self, path: &std::path::Path) -> Result<bool, String> {
        let trace = self.shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).trace.clone().ok_or("nenhum rastro para exportar")?;
        let csv = trace.trace.to_csv(&|rip| trace.info(rip).map(|info| info.symbol.clone()).unwrap_or_else(|| format!("{rip:#x}")), &|rip| trace.info(rip).map(|info| info.text.clone()).unwrap_or_default());
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(path, csv).map_err(|error| format!("{}: {error}", path.display()))?;
        self.transcript("(rastro)", Ok(format!("{} registros em {}", trace.trace.len(), path.display())));
        Ok(false)
    }

    fn load_reference(&mut self, path: &std::path::Path) -> Result<bool, String> {
        let text = std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
        let trace = Trace::from_csv(&text)?;
        // Símbolos e instruções do próprio arquivo.
        let mut info = HashMap::new();
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split(';').collect();
            if let (Some(rip), Some(symbol), Some(instruction)) = (fields.get(3).and_then(|text| opennt_kd::parse_number(text)), fields.get(4), fields.get(5)) {
                info.entry(rip).or_insert_with(|| RipInfo { symbol: symbol.to_string(), module: symbol.split_once('!').map_or("kernel".to_string(), |(module, _)| module.to_string()), bytes: Vec::new(), text: instruction.to_string() });
            }
        }
        let view = TraceView { summary: format!("{} registros de {}", trace.len(), path.display()), title: path.display().to_string(), trace, info };
        self.publish(|shared| {
            shared.reference = Some(Arc::new(view));
            shared.trace_generation += 1;
        });
        Ok(false)
    }
}

/// Um padrão de busca: bytes em hexadecimal (`48 8b 05`), `"texto"` ou
/// `u"texto"` (UTF-16).
pub fn parse_pattern(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if let Some(inner) = text.strip_prefix("u\"").and_then(|rest| rest.strip_suffix('"')) {
        return Ok(inner.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect());
    }
    if let Some(inner) = text.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')) {
        return Ok(inner.as_bytes().to_vec());
    }
    let digits: String = text.chars().filter(|character| !character.is_whitespace()).collect();
    if digits.len() % 2 != 0 || !digits.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err("padrao: bytes em hexadecimal (48 8b 05), \"texto\" ou u\"texto\"".into());
    }
    Ok((0..digits.len() / 2).map(|index| u8::from_str_radix(&digits[index * 2..index * 2 + 2], 16).unwrap_or(0)).collect())
}

/// Páginas de código lidas do alvo (o rastro desmonta cada RIP uma vez).
struct CodePages<'a> {
    client: &'a mut Client,
    pages: HashMap<u64, Option<Vec<u8>>>,
}

impl CodePages<'_> {
    fn bytes(&mut self, address: u64, length: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(length);
        let mut position = address;
        while output.len() < length {
            let page = position & !0xFFF;
            let entry = self.pages.entry(page).or_insert_with(|| self.client.read_memory(page, 0x1000).ok().filter(|bytes| bytes.len() == 0x1000));
            let Some(bytes) = entry else { break };
            let start = (position - page) as usize;
            let take = (length - output.len()).min(0x1000 - start);
            output.extend_from_slice(&bytes[start..start + take]);
            position += take as u64;
        }
        output
    }
}

/// Símbolo, módulo, bytes e instrução de cada RIP distinto do rastro.
fn build_trace_view(client: &mut Client, trace: Trace, title: &str) -> TraceView {
    let mut unique: Vec<u64> = trace.records.iter().map(|record| record.rip).collect();
    unique.sort_unstable();
    unique.dedup();
    let mut info = HashMap::with_capacity(unique.len());
    let names: Vec<(u64, String, String)> = unique.iter().map(|&rip| (rip, client.symbols.describe(rip), client.symbols.module_at(rip).map_or(String::new(), |module| module.name.clone()))).collect();
    let mut pages = CodePages { client, pages: HashMap::new() };
    for (rip, symbol, module) in names {
        let bytes = pages.bytes(rip, 16);
        let text = disasm::disassemble(rip, &bytes, None).into_iter().next().map(|line| line.text).unwrap_or_else(|| "(codigo ilegivel)".into());
        let length = disasm::instruction_length(rip, &bytes).unwrap_or(bytes.len().min(1));
        info.insert(rip, RipInfo { symbol, module, bytes: bytes[..length.min(bytes.len())].to_vec(), text });
    }
    let symbols = &pages.client.symbols;
    let mut summary = format!("{} registros, {} instrucoes executadas, {} lote(s); fim: {}\n", trace.len(), trace.steps.max(trace.len() as u64), trace.batches, trace.reason.text());
    for (name, count) in trace::histogram(&trace, &|rip| symbols.describe(rip)).into_iter().take(5) {
        summary.push_str(&format!("{count:>8}  {name}\n"));
    }
    TraceView { trace, info, title: title.to_string(), summary }
}

/// Os blocos do log do QEMU em instruções: cada bloco vai até o primeiro
/// desvio ou até o começo do bloco seguinte.
fn expand_qemu_blocks(client: &mut Client, blocks: &[(u8, u64)], limit: usize) -> Trace {
    let mut trace = Trace::new(Source::Qemu);
    let mut pages = CodePages { client, pages: HashMap::new() };
    let mut depth: HashMap<u8, i32> = HashMap::new();
    for (index, &(cpu, start)) in blocks.iter().enumerate() {
        let next = blocks[index + 1..].iter().find(|(other, _)| *other == cpu).map(|(_, pc)| *pc);
        let code = pages.bytes(start, 512);
        for (address, flow) in disasm::block(start, &code, next) {
            let level = depth.entry(cpu).or_insert(0);
            let class = match flow {
                opennt_kd::x86::Flow::Call(_) => Class::Call,
                opennt_kd::x86::Flow::Return => Class::Return,
                opennt_kd::x86::Flow::Other => Class::Other,
            };
            trace.push_rip(cpu, address, class, *level);
            match class {
                Class::Call => *level += 1,
                Class::Return => *level -= 1,
                Class::Other => {}
            }
            if trace.len() >= limit {
                return trace;
            }
        }
    }
    trace.steps = trace.len() as u64;
    trace.reason = trace::Reason::Interrupted;
    trace.batches = 1;
    trace
}

/// A desmontagem em volta de `focus`, com a análise automática: as
/// funções, os laços (do cache por função), os comentários das chamadas e
/// os do opennt-re (imports, CFG, strings, códigos de erro e os campos dos
/// tipos).
fn code_view(client: &mut Client, focus: u64, live: Option<&Live>, re: &mut views::ReState) -> CodeView {
    let mut view = code_lines(client, focus, &mut re.imports);
    if view.lines.is_empty() {
        return view;
    }
    view.functions = annotate::functions_for_lines(client, &view.lines);
    for function in &view.functions {
        let key = (function.start, function.end);
        if !re.loops.contains_key(&key) {
            let found = annotate::loops_for(client, std::slice::from_ref(function));
            re.loops.insert(key, found);
        }
        view.loops.extend(re.loops[&key].iter().copied());
    }
    view.auto_comments = annotate::auto_comments(client, &view.lines, live);
    let context = annotations::Context { imports: &re.imports, register_types: &re.register_types, live, read_target: true };
    annotations::enrich(client, &mut view.lines, &context);
    view
}

/// As linhas da desmontagem em volta de `focus` (com os nomes nos
/// operandos).
fn code_lines(client: &mut Client, focus: u64, imports: &mut ImportCache) -> CodeView {
    const BEFORE: u64 = 0x120;
    const AFTER: u64 = 0x180;
    let mut view = CodeView { focus, ..Default::default() };
    if focus == 0 {
        return view;
    }
    let start = disasm::window_start(focus, &client.symbols, BEFORE);
    imports.load(&client.symbols, focus);
    let imports: &ImportCache = imports;
    let attempt = |client: &mut Client, start: u64| -> Result<Option<Vec<Line>>, String> {
        let bytes = client.read_memory(start, (focus - start + AFTER) as usize)?;
        Ok(disasm::clip(disasm::disassemble_named(start, &bytes, &client.symbols, Some(imports)), focus, BEFORE, AFTER))
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

#[cfg(test)]
mod tests {
    use super::parse_pattern;

    #[test]
    fn search_patterns() {
        assert_eq!(parse_pattern("48 8b 05"), Ok(vec![0x48, 0x8b, 0x05]));
        assert_eq!(parse_pattern("\"MZ\""), Ok(vec![b'M', b'Z']));
        assert_eq!(parse_pattern("u\"Nt\""), Ok(vec![b'N', 0, b't', 0]));
        assert!(parse_pattern("4").is_err());
        assert!(parse_pattern("zz").is_err());
    }
}
