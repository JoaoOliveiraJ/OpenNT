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
//!
//! As leituras caras (o resto do estado do processador, o KTHREAD de cada
//! thread e a parte de usuário da pilha) só entram quando a janela as pede
//! (`Wanted`, pelos painéis abertos).

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use opennt_kd::bugcheck::Analysis;
use opennt_kd::client::{BreakpointRequest, Resumed};
use opennt_kd::commands::TraceOptions;
use opennt_kd::kd_script::{self, ScriptHost, ScriptOptions, ScriptOutcome};
use opennt_kd::monitor::{Process, Processor, Thread};
use opennt_kd::rsp::Connection;
use opennt_kd::trace::{self, Class, Source, Trace};
use opennt_kd::types::Field;
use opennt_kd::unwind::Method;
use opennt_kd::user::ProcessContext;
use opennt_kd::{parse_number, registers, Breakpoint, BreakpointKind, Client};

use crate::details::{self, KthreadLayout, PdbStatus, ThreadDetail};
use crate::disasm::{self, Line};
use crate::launcher::{Launch, LaunchOptions, CANCELLED};
use crate::script::{self, PanelLine};
use crate::session::{self, SessionFile};
use crate::source::{Local, LineTable};

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
    /// Troca os breakpoints pelos de uma sessão (o texto do `.bpsave`):
    /// na hora com a máquina parada, senão na próxima parada ou no
    /// próximo attach.
    LoadBreakpoints(String),
    /// Grava uma sessão com nome; o backend põe os breakpoints de agora.
    SaveSession { path: PathBuf, session: SessionFile },
    /// Roda um roteiro do kd (a linguagem do `--script` do test-boot);
    /// `name` aparece nas mensagens.
    RunScript { name: String, text: String },
    /// Roda o roteiro de um arquivo (relativo à raiz do repositório).
    RunScriptFile(PathBuf),
    /// Grava os comandos da janela num roteiro (o arquivo é recriado); as
    /// opções do xtask vão no cabeçalho, na linha de como rodar de novo.
    StartRecording { path: PathBuf, xtask: Vec<String> },
    StopRecording,
    /// Teclas pelo monitor HMP do QEMU (`sendkey`, como
    /// `ctrl_r-scroll_lock-scroll_lock`, o despejo manual do teclado).
    SendKeys(String),
    /// As leituras extras que os painéis abertos querem.
    SetWanted(Wanted),
    /// O processo das leituras (`.process`): PID ou EPROCESS; `None` volta
    /// ao espaço do processador.
    SetProcess(Option<String>),
    /// Continua até o endereço (breakpoint temporário, qualquer RSP).
    RunTo(u64),
    /// Troca as opções de um breakpoint (condição, contagem, log,
    /// comandos, grupo, uma vez só...).
    EditBreakpoint(u32, BreakpointRequest),
    SetGroupEnabled(String, bool),
    /// A janela de memória também como um tipo do PDB do ntoskrnl (vazio:
    /// só os bytes).
    ShowMemoryAs(String),
    /// O log da COM1 a acompanhar (o `serial.log` de um `xtask` aberto à
    /// parte, no `--connect`).
    SetSerialLog(Option<PathBuf>),
    Refresh,
    Shutdown,
}

/// As leituras caras que a janela quer em cada parada (os painéis que as
/// mostram estão abertos e ligados).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Wanted {
    /// x87, SSE, a metade alta dos YMM e os registradores de depuração.
    pub extended: bool,
    /// Espera e prioridade de cada thread (uma leitura do KTHREAD por
    /// thread).
    pub thread_details: bool,
    /// Só as threads deste processo (PID) ganham os detalhes.
    pub thread_filter: Option<u64>,
    /// A parte de usuário da pilha de uma thread que entrou no kernel.
    pub user_stack: bool,
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
    /// O símbolo do valor, quando ele cai num módulo.
    pub symbol: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameRow {
    pub address: u64,
    pub name: String,
    /// O RSP do quadro.
    pub stack: u64,
    /// Como o quadro foi achado (`.pdata`, frame pointer...).
    pub method: &'static str,
    /// O módulo do quadro (vazio fora dos módulos).
    pub module: String,
    /// O nome sem o módulo (`função+0x10`).
    pub symbol: String,
    /// O endereço é da metade de usuário.
    pub user: bool,
    /// O primeiro quadro da parte de usuário (do CONTEXT salvo da thread).
    pub user_start: bool,
    /// Arquivo e linha (o DWARF do kernel do OpenNT).
    pub line: Option<(String, u32)>,
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
    /// O símbolo de cada qword da janela (os que caem num módulo).
    pub pointers: Vec<Option<String>>,
    /// A janela como tipo do PDB: o nome pedido, a vista tipada (endereço,
    /// tipo) e o erro da busca do tipo.
    pub type_name: String,
    pub typed: Option<(u64, u32)>,
    pub type_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadRow {
    pub thread: Thread,
    /// O símbolo do endereço de início.
    pub start: String,
    /// Espera e prioridade pelo KTHREAD (quando pedidas).
    pub detail: Option<ThreadDetail>,
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
    /// O caminho no alvo.
    pub path: String,
    /// Módulo de usuário do processo das leituras.
    pub user: bool,
    pub status: PdbStatus,
    /// O PDB citado pelo RSDS e a identidade dele (GUID e idade).
    pub pdb_name: String,
    pub pdb_id: String,
}

/// Uma expressão observada.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchRow {
    pub expression: String,
    pub value: Result<String, String>,
    /// Valor tipado que abre (endereço, tipo) e o nome do tipo.
    pub typed: Option<(u64, u32)>,
    pub type_name: String,
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
    /// O resto do estado do processador (quando pedido; só no processador,
    /// não numa thread fora da CPU).
    pub extended: Option<Result<registers::ExtendedState, String>>,
    /// O símbolo de DR0-DR3.
    pub debug_symbols: [Option<String>; 4],
    pub frames: Vec<FrameRow>,
    /// De onde veio a parte de usuário da pilha, ou por que ela falta.
    pub user_stack_note: String,
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
    /// Por que os detalhes das threads faltam (sem o PDB do ntoskrnl...).
    pub threads_note: String,
    /// O processo das leituras (`.process`), se escolhido.
    pub process_context: Option<ProcessContext>,
    pub breakpoints: Vec<Breakpoint>,
    pub watches: Vec<WatchRow>,
    /// Os campos das vistas tipadas abertas.
    pub typed: HashMap<(u64, u32), Result<Vec<Field>, String>>,
    pub query: Option<QueryResult>,
    pub bugcheck: Option<Analysis>,
    pub search: Option<SearchResult>,
    pub types_note: String,
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

/// O erro de quando o `xtask` termina com a máquina parada (rodando, o
/// socket fechado avisa antes).
pub const QEMU_ENDED: &str = "o QEMU terminou";

/// O roteiro rodando (a barra de estado e o painel de comandos).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScriptProgress {
    pub name: String,
    /// O número da linha no arquivo.
    pub line: usize,
    /// Quantas linhas de comando já foram (com a de agora) e o total.
    pub index: usize,
    pub total: usize,
    pub text: String,
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
    /// O alvo da sessão (o último pedido), para reabrir ou reconectar.
    pub target: Option<Target>,
    /// O roteiro rodando agora.
    pub script: Option<ScriptProgress>,
    /// A gravação ligada: o arquivo e quantas linhas já foram.
    pub recording: Option<(PathBuf, usize)>,
    /// A última falha da sessão (a conexão caiu, o QEMU terminou, a
    /// abertura falhou): a primeira linha diz o que foi, o resto o que se
    /// sabe e como continuar. Some num início novo.
    pub failure: Option<String>,
    /// Cresce a cada falha nova (a janela fecha o aviso de uma só).
    pub failure_generation: u64,
    pub trace: Option<Arc<TraceView>>,
    pub reference: Option<Arc<TraceView>>,
    /// Muda a cada rastro novo.
    pub trace_generation: u64,
    /// Os nomes de símbolo (o autocompletar), por geração dos símbolos.
    pub completions: Arc<Vec<String>>,
    pub type_names: Arc<Vec<String>>,
}

pub struct Backend {
    requests: Sender<Request>,
    pub shared: Arc<Mutex<Shared>>,
    /// Cancela a abertura ou o roteiro em andamento: a janela liga direto,
    /// sem passar pela fila (o backend está ocupado justamente nisso).
    cancel: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

/// Chamado quando o estado publicado muda (o `request_repaint` da janela).
pub type Notify = Arc<dyn Fn() + Send + Sync>;

impl Backend {
    pub fn start(config: Config, target: Option<Target>, notify: Notify) -> Backend {
        let (requests, receiver) = mpsc::channel();
        let shared = Arc::new(Mutex::new(Shared::default()));
        let cancel = Arc::new(AtomicBool::new(false));
        let worker = Worker::new(config, Arc::clone(&shared), notify, Arc::clone(&cancel));
        let thread = thread::Builder::new()
            .name("kd-backend".into())
            .spawn(move || worker.run(receiver, target))
            .expect("thread do backend");
        Backend { requests, shared, cancel, thread: Some(thread) }
    }

    pub fn send(&self, request: Request) {
        let _ = self.requests.send(request);
    }

    /// Cancela a abertura (build, QEMU, conexão) ou o roteiro em andamento.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
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

/// A gravação dos comandos num roteiro: cada linha vai ao disco na hora
/// (uma queda do depurador não perde o que já foi gravado).
struct Recording {
    path: PathBuf,
    file: std::fs::File,
    lines: usize,
    /// Um `c` gravado espera a parada: quando ela chega, entra o
    /// `wait-stop` com o tempo que a máquina levou.
    resumed_at: Option<Instant>,
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
    cancel: Arc<AtomicBool>,
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
    wanted: Wanted,
    memory_type: String,
    /// Os offsets do KTHREAD (do PDB, uma vez por sessão).
    kthread: Option<KthreadLayout>,
    /// Os detalhes das threads lidos nesta parada, com o filtro de processo
    /// deles: valem até a máquina andar ou algo mudar o alvo (os pedidos que
    /// só trocam a vista os reaproveitam).
    thread_cache: Option<(Option<u64>, HashMap<u64, ThreadDetail>)>,
    /// O processo das leituras que a pilha de usuário escolheu sozinha (um
    /// `.process` diferente foi escolhido à mão e fica).
    auto_process: Option<u64>,
    /// Os breakpoints de uma sessão aberta que ainda esperam a máquina
    /// parar (ou o attach).
    pending_breakpoints: Option<String>,
    /// As variáveis `$nome` dos roteiros (`save`, `save-word`,
    /// `save-thread`); valem também nos comandos digitados depois.
    variables: HashMap<String, u64>,
    recording: Option<Recording>,
    /// Como o QEMU saiu (a linha `KD_QEMU_EXITED` do xtask).
    qemu_exit: Option<String>,
}

/// Quantas threads ganham os detalhes do KTHREAD por parada (sem filtro de
/// processo).
const THREAD_DETAIL_LIMIT: usize = 512;

/// A partir daqui o endereço é do kernel.
const KERNEL_START: u64 = 0xFFFF_8000_0000_0000;

impl Worker {
    fn new(config: Config, shared: Arc<Mutex<Shared>>, notify: Notify, cancel: Arc<AtomicBool>) -> Worker {
        Worker {
            config,
            shared,
            notify,
            cancel,
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
            wanted: Wanted::default(),
            memory_type: String::new(),
            kthread: None,
            thread_cache: None,
            auto_process: None,
            pending_breakpoints: None,
            variables: HashMap::new(),
            recording: None,
            qemu_exit: None,
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
            // Um PDB que chegou: os nomes trocam sem esperar outra parada.
            if self.client.as_ref().is_some_and(|client| client.is_stopped() && client.symbols.pending() && !client.symbols.store.as_ref().is_some_and(|store| store.busy())) {
                let _ = self.with_client(|client| client.reload_modules());
                self.refresh();
            }
            self.forward_console();
            self.tail_serial();
            if let Some(launch) = self.launch.as_mut() {
                let mut text = String::new();
                let mut exited = None;
                while let Ok(line) = launch.output.try_recv() {
                    if let Some(status) = line.strip_prefix("KD_QEMU_EXITED ") {
                        exited = Some(status.trim().to_string());
                    }
                    text.push_str(&line);
                    text.push('\n');
                }
                if exited.is_some() {
                    self.qemu_exit = exited;
                }
                if !text.is_empty() {
                    self.publish(|shared| shared.launch_log.push_str(&text));
                }
            }
            // A janela do QEMU fechada com a máquina parada (rodando, o
            // socket fechado já avisa).
            if self.launch.as_mut().is_some_and(|launch| !launch.alive()) {
                self.lost(QEMU_ENDED.into());
            }
        }
    }

    /// Conecta (abrindo o QEMU antes, no `--launch`) e anexa.
    fn start(&mut self, target: Target) {
        self.disconnect("reiniciando");
        self.cancel.store(false, Ordering::SeqCst);
        self.target = Some(target.clone());
        self.qemu_exit = None;
        let published = target.clone();
        self.publish(|shared| {
            shared.target = Some(published);
            shared.failure = None;
        });
        self.view = View::Owner;
        self.selected_frame = 0;
        self.focus = Focus::Frame;
        self.previous_registers.clear();
        self.serial_offset = 0;
        self.symbols_generation = u64::MAX;
        self.types_published = false;
        self.auto_process = None;
        self.thread_cache = None;
        // As variáveis dos roteiros são deste boot (endereços).
        self.variables.clear();
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
                // Os breakpoints da sessão seguem o diretório de build da
                // abertura (a janela de abertura pode trocá-lo).
                if self.config.session.is_some() {
                    self.config.session = Some(options.build_path().join("opennt-dbg").join("breakpoints.txt"));
                }
                self.publish(|shared| {
                    shared.can_restart = true;
                    shared.launch_log.clear();
                    shared.serial.clear();
                    shared.console.clear();
                });
                self.set_status(Status::Launching("compilando com --kd=com2 e abrindo o QEMU".into()));
                let shared = Arc::clone(&self.shared);
                let notify = Arc::clone(&self.notify);
                let launched = Launch::start(options, &self.cancel, |line| {
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
                    Err(error) if error == CANCELLED => {
                        self.set_status(Status::Disconnected(error));
                        return;
                    }
                    Err(error) => {
                        self.fail(format!("A abertura falhou: {error}\n\nO comando: {}\nPara continuar: Ctrl+O para conferir as opções do xtask e abrir de novo.", options.command_line()));
                        return;
                    }
                }
            }
        };
        self.set_status(Status::Connecting(address.clone()));
        // Tentativas de um segundo até o prazo, para o Cancelar valer logo.
        let deadline = Instant::now() + Duration::from_secs(60);
        let connection = loop {
            match Connection::connect(&address, (Instant::now() + Duration::from_secs(1)).min(deadline)) {
                Ok(connection) => break connection,
                Err(error) => {
                    let cancelled = self.cancel.swap(false, Ordering::SeqCst);
                    if cancelled || Instant::now() >= deadline {
                        // O QEMU aberto pela sessão não fica para trás.
                        if let Some(mut launch) = self.launch.take() {
                            launch.stop();
                        }
                        if cancelled {
                            self.set_status(Status::Disconnected(CANCELLED.to_string()));
                        } else {
                            self.fail(format!("Sem conexão com o depurador em {address}: {error}\n\nO QEMU precisa estar aberto com o kernel de --kd=com2: o cargo xtask debug --launch --no-client imprime KD_READY 127.0.0.1:PORTA (cole a linha em Ctrl+O), e o cargo xtask run --kd=com2 escuta em 127.0.0.1:1234."));
                        }
                        return;
                    }
                }
            }
        };
        let mut client = Client::new(connection, self.config.root.clone(), self.config.elf.clone());
        self.set_activity("anexando (a maquina para no proximo tique)");
        match client.attach(Duration::from_secs(180)) {
            Ok(text) => {
                self.transcript("attach", Ok(text));
                // Num QEMU de fora, o log da COM1 é o do diretório de build
                // (ou o do --serial-log): a janela diz qual arquivo segue.
                if let (Some(Target::Connect(_)), Some(path)) = (&self.target, &self.config.serial_log) {
                    let note = if path.exists() { format!("log da COM1 lido de {} (--serial-log=ARQ troca o arquivo)", path.display()) } else { format!("sem o log da COM1: {} nao existe (--serial-log=ARQ indica o arquivo)", path.display()) };
                    self.transcript("(sessao)", Ok(note));
                }
                // Os breakpoints de uma sessão aberta antes do attach; senão,
                // os da sessão anterior deste diretório de build (os de
                // módulos que ainda não carregaram ficam adiados).
                let opened = self.pending_breakpoints.take();
                let restore = match &opened {
                    Some(text) => Some((text.clone(), "da sessao aberta".to_string())),
                    None => self.config.session.as_ref().and_then(|path| std::fs::read_to_string(path).ok().map(|text| (text, format!("da sessao anterior ({})", path.display())))),
                };
                if let Some((text, origin)) = restore {
                    let errors = client.restore_breakpoints(&text);
                    let restored = format!("{} breakpoints {origin}", client.breakpoints().len());
                    self.transcript("(sessao)", if errors.is_empty() { Ok(restored) } else { Err(format!("{restored}\n{}", errors.join("\n"))) });
                }
                self.client = Some(client);
                if opened.is_some() {
                    self.save_session();
                }
                self.lines = None;
                self.refresh();
            }
            Err(error) => {
                if let Some(mut launch) = self.launch.take() {
                    launch.stop();
                }
                self.fail(format!("O attach falhou: {error}\n\nO socket abriu, mas o depurador do kernel não respondeu: o kernel precisa do --kd=com2 (o cargo xtask debug já o liga) e de ter chegado ao ponto em que o kd atende. Num QEMU de fora, confira se outro cliente (outro opennt-dbg, o opennt-re ou o cargo xtask debug) já está conectado."));
            }
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
        self.publish_console(text);
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
                self.thread_cache = None;
                self.record_stop();
                self.view = View::Owner;
                self.selected_frame = 0;
                self.focus = Focus::Frame;
                // Os breakpoints de uma sessão aberta com a máquina rodando.
                if let Some(text) = self.pending_breakpoints.take() {
                    if let Err(error) = self.apply_breakpoints(&text) {
                        if is_connection_error(&error) {
                            return self.lost(error);
                        }
                        self.transcript("(sessao)", Err(error));
                    }
                }
                self.refresh();
            }
            Ok(None) => {}
            Err(error) => self.lost(error),
        }
    }

    /// Uma falha da sessão: a barra de estado e o aviso da janela mostram a
    /// mensagem (a primeira linha diz o que foi).
    fn fail(&self, message: String) {
        self.publish(|shared| {
            shared.status = Status::Disconnected(message.clone());
            shared.failure = Some(message);
            shared.failure_generation += 1;
        });
    }

    /// A conexão caiu ou o QEMU terminou: a mensagem diz como o QEMU saiu
    /// (a linha `KD_QEMU_EXITED` do xtask ou o código de saída dele), se a
    /// COM1 mostra um bugcheck ou pânico, as últimas linhas da COM1 e do
    /// xtask, e como continuar.
    fn lost(&mut self, error: String) {
        self.client = None;
        self.cancel.store(false, Ordering::SeqCst);
        if self.recording.is_some() {
            self.record(&[format!("# a sessao caiu: {error}")]);
        }
        let launched = self.launch.is_some();
        let mut qemu_status = self.qemu_exit.clone();
        let mut xtask_status = None;
        if let Some(mut launch) = self.launch.take() {
            // O xtask sai logo depois do QEMU: um instante para a linha
            // KD_QEMU_EXITED e o código de saída.
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                let mut text = String::new();
                while let Ok(line) = launch.output.try_recv() {
                    if let Some(status) = line.strip_prefix("KD_QEMU_EXITED ") {
                        qemu_status = Some(status.trim().to_string());
                    }
                    text.push_str(&line);
                    text.push('\n');
                }
                if !text.is_empty() {
                    self.publish(|shared| shared.launch_log.push_str(&text));
                }
                if let Some(status) = launch.exit_status() {
                    xtask_status = Some(status);
                    break;
                }
                if Instant::now() >= deadline {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
            launch.stop();
        }
        self.tail_serial();
        let (serial, xtask) = {
            let shared = self.shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            (tail_lines(&shared.serial, 12), if launched { tail_lines(&shared.launch_log, 8) } else { Vec::new() })
        };
        self.fail(loss_message(&error, launched, qemu_status.as_deref(), xtask_status.as_deref(), &serial, &xtask));
    }

    /// Grava os breakpoints no arquivo da sessão.
    fn save_session(&self) {
        let (Some(path), Some(client)) = (&self.config.session, &self.client) else { return };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(path, client.breakpoint_specs());
    }

    /// Troca os breakpoints de agora pelos de uma sessão (com a máquina
    /// parada; os de módulos que ainda não carregaram ficam adiados).
    fn apply_breakpoints(&mut self, text: &str) -> Result<(), String> {
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        let ids: Vec<u32> = client.breakpoints().iter().map(|breakpoint| breakpoint.id).collect();
        for id in ids {
            client.remove_breakpoint(id)?;
        }
        let errors = client.restore_breakpoints(text);
        let restored = format!("{} breakpoints da sessao aberta", client.breakpoints().len());
        self.transcript("(sessao)", if errors.is_empty() { Ok(restored) } else { Err(format!("{restored}\n{}", errors.join("\n"))) });
        self.save_session();
        Ok(())
    }

    /// Grava uma sessão com nome: os breakpoints são os do cliente (ou os
    /// que esperam o attach, ou os do `breakpoints.txt` sem conexão).
    fn save_named_session(&mut self, path: &std::path::Path, mut session: SessionFile) {
        session.version = session::VERSION;
        session.breakpoints = match (&self.pending_breakpoints, &self.client) {
            (Some(text), _) => text.clone(),
            (None, Some(client)) => client.breakpoint_specs(),
            (None, None) => self.config.session.as_ref().and_then(|file| std::fs::read_to_string(file).ok()).unwrap_or_default(),
        };
        let result = session.save(path).map(|_| format!("sessao salva em {} ({} breakpoints, {} expressoes observadas)", path.display(), session.breakpoint_count(), session.watches.len()));
        self.transcript("(sessao)", result);
    }

    /// Um pedido da janela: vai para a gravação (quando ligada) e é feito.
    fn handle(&mut self, request: Request) {
        if self.recording.is_some() {
            let lines = self.recorded_lines(&request);
            if !lines.is_empty() {
                self.record(&lines);
            }
        }
        self.process(request);
        // Nenhum pedido deixa a atividade presa: com ela, a janela desliga
        // os botões de execução.
        let stale = !self.shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).activity.is_empty();
        if stale {
            self.set_activity("");
        }
    }

    fn process(&mut self, request: Request) {
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
            Request::SetWanted(wanted) => {
                let changed = wanted != self.wanted;
                self.wanted = wanted;
                if changed && self.client.as_ref().is_some_and(Client::is_stopped) {
                    self.refresh();
                }
                return;
            }
            Request::SetSerialLog(path) => {
                self.config.serial_log = path;
                self.serial_offset = 0;
                self.publish(|shared| shared.serial.clear());
                self.tail_serial();
                return;
            }
            Request::LoadBreakpoints(text) => {
                if self.client.as_ref().is_some_and(Client::is_stopped) {
                    if let Err(error) = self.apply_breakpoints(&text) {
                        if is_connection_error(&error) {
                            return self.lost(error);
                        }
                        self.transcript("(sessao)", Err(error));
                    }
                    self.refresh();
                } else {
                    let note = if self.client.is_some() { "os breakpoints da sessao entram na proxima parada (Ctrl+B para agora)" } else { "os breakpoints da sessao entram no proximo attach" };
                    self.pending_breakpoints = Some(text);
                    self.transcript("(sessao)", Ok(note.to_string()));
                }
                return;
            }
            Request::SaveSession { path, session } => {
                self.save_named_session(&path, session);
                return;
            }
            Request::StartRecording { path, xtask } => {
                self.start_recording(path, &xtask);
                return;
            }
            Request::StopRecording => {
                self.stop_recording();
                return;
            }
            Request::RunScriptFile(path) => {
                let path = if path.is_absolute() { path } else { self.config.root.join(path) };
                match std::fs::read_to_string(&path) {
                    Ok(text) => self.process(Request::RunScript { name: path.display().to_string(), text }),
                    Err(error) => self.transcript("(roteiro)", Err(format!("{}: {error}", path.display()))),
                }
                return;
            }
            Request::RunScript { .. } if self.client.is_none() => {
                self.transcript("(roteiro)", Err("o roteiro precisa da conexao com o alvo: abra o OpenNT ou conecte antes (Ctrl+O)".into()));
                return;
            }
            _ => {}
        }
        if self.client.is_none() {
            return;
        }
        // Os pedidos que só trocam a vista guardam os detalhes das threads
        // desta parada; os outros podem mudar o alvo.
        if !matches!(request, Request::SelectCpu(_) | Request::SelectThread(_) | Request::SelectFrame(_) | Request::ShowCode(_) | Request::ShowMemory(_) | Request::ShowMemoryAs(_) | Request::Query(..) | Request::SearchMemory { .. } | Request::SetProcess(_)) {
            self.thread_cache = None;
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
            Request::RunScript { name, text } => {
                breakpoints_changed = true;
                self.run_script(&name, &text)
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
            Request::SendKeys(keys) => self.send_keys(&keys).map(|_| false),
            Request::SetProcess(process) => self.with_client(|client| client.set_process(process.as_deref())).map(|_| true),
            Request::RunTo(address) => self.resume(|client| client.run_until(address, None).map(|_| Resumed::Running)),
            Request::EditBreakpoint(id, request) => {
                breakpoints_changed = true;
                self.with_client(|client| client.edit_breakpoint(id, &request)).map(|_| true)
            }
            Request::SetGroupEnabled(group, enabled) => {
                breakpoints_changed = true;
                self.with_client(|client| client.set_group_enabled(&group, enabled)).map(|_| true)
            }
            Request::ShowMemoryAs(type_name) => {
                self.memory_type = type_name.trim().to_string();
                Ok(true)
            }
            Request::Refresh => Ok(true),
            Request::Start(_)
            | Request::Restart
            | Request::Disconnect
            | Request::Shutdown
            | Request::SetWatches(_)
            | Request::SetExpanded(_)
            | Request::SetWanted(_)
            | Request::SetSerialLog(_)
            | Request::LoadBreakpoints(_)
            | Request::SaveSession { .. }
            | Request::RunScriptFile(_)
            | Request::StartRecording { .. }
            | Request::StopRecording => Ok(false),
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
            // A linha digitada já foi para a gravação.
            self.process(action);
            return Ok(false);
        }
        self.set_activity(trimmed);
        // As variáveis dos roteiros (`$nome`) valem nos comandos digitados.
        let substituted = script::substitute(trimmed, &self.variables);
        let result = self.with_client(|client| client.execute(&substituted));
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

    /// O estado do alvo (rodando ou parado) durante um roteiro, sem montar o
    /// snapshot (ele fica para o fim do roteiro).
    fn publish_run_state(&self, client: &Client) {
        let status = if client.is_stopped() { Status::Stopped } else { Status::Running };
        let changed = self.shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).status != status;
        if changed {
            self.set_status(status);
        }
    }

    /// O DbgPrint novo no painel.
    fn publish_console(&self, text: String) {
        if !text.is_empty() {
            self.publish(|shared| shared.console.push_str(&text));
        }
    }

    /// Roda um roteiro do kd pelo executor do opennt-kd (a linguagem do
    /// `--script` do test-boot, com blocos, laços e tratadores): o roteiro
    /// é conferido inteiro antes (um erro de sintaxe não deixa a máquina
    /// andar), cada comando vai ao painel de comandos na hora, o Cancelar
    /// para entre um comando e outro e dentro das esperas, e a primeira
    /// conferência ou comando que falha encerra, como no test-boot.
    fn run_script(&mut self, name: &str, text: &str) -> Result<bool, String> {
        if let Err((line, error)) = kd_script::check_script(text) {
            self.transcript("(roteiro)", Err(format!("{name}: o roteiro nao rodou:\nlinha {line}: {error}")));
            return Ok(false);
        }
        let Some(mut client) = self.client.take() else { return Err("sem conexao com o alvo".into()) };
        self.cancel.store(false, Ordering::SeqCst);
        let started = Instant::now();
        let (order, total) = script::command_lines(text);
        self.transcript("(roteiro)", Ok(format!("{name}: {total} linhas de comando")));
        let options = ScriptOptions { name: name.to_string(), ..ScriptOptions::default() };
        let mut host = WindowScript { worker: self, name: name.to_string(), order, total, line: 0, entry: None };
        let outcome = client.run_script_hosted(text, &options, &mut host);
        host.finish(&outcome);
        self.client = Some(client);
        // As variáveis numéricas do roteiro valem nos comandos digitados
        // depois.
        for (variable, value) in &outcome.variables {
            if let Some(number) = parse_number(value) {
                self.variables.insert(variable.clone(), number);
            }
        }
        self.cancel.store(false, Ordering::SeqCst);
        self.set_activity("");
        self.publish(|shared| shared.script = None);
        let seconds = started.elapsed().as_secs_f64();
        match &outcome.result {
            Ok(()) => self.transcript("(roteiro)", Ok(format!("{name}: fim, {total} linhas em {seconds:.1} s"))),
            Err(error) if is_connection_error(error) => return Err(error.clone()),
            Err(_) => {
                let line = outcome.failed_line.map_or(String::new(), |line| format!(" na linha {line}"));
                self.transcript("(roteiro)", Err(format!("{name}: parou{line}")));
            }
        }
        if self.client.as_ref().is_some_and(Client::is_stopped) {
            Ok(true)
        } else {
            self.set_status(Status::Running);
            Ok(false)
        }
    }

    /// Liga a gravação dos comandos num roteiro (o arquivo é recriado, com
    /// o cabeçalho de como rodar de novo e o `attach`).
    fn start_recording(&mut self, path: PathBuf, xtask: &[String]) {
        self.stop_recording();
        let path = if path.is_absolute() { path } else { self.config.root.join(path) };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::File::create(&path) {
            Ok(file) => {
                let shown = path.strip_prefix(&self.config.root).unwrap_or(&path).display().to_string().replace('\\', "/");
                self.recording = Some(Recording { path: path.clone(), file, lines: 0, resumed_at: None });
                self.record(&script::recording_header(xtask, &shown));
                self.transcript("(gravacao)", Ok(format!("gravando os comandos em {} (Roteiro > Parar a gravacao)", path.display())));
            }
            Err(error) => self.transcript("(gravacao)", Err(format!("{}: {error}", path.display()))),
        }
    }

    fn stop_recording(&mut self) {
        if let Some(recording) = self.recording.take() {
            let message = format!("{} linhas gravadas em {}", recording.lines, recording.path.display());
            drop(recording);
            self.publish(|shared| shared.recording = None);
            self.transcript("(gravacao)", Ok(message));
        }
    }

    /// Escreve linhas na gravação; um erro de disco desliga a gravação com
    /// a mensagem.
    fn record(&mut self, lines: &[String]) {
        let Some(recording) = self.recording.as_mut() else { return };
        let mut failed = None;
        for line in lines {
            if let Err(error) = writeln!(recording.file, "{line}") {
                failed = Some(error.to_string());
                break;
            }
            recording.lines += 1;
        }
        let _ = recording.file.flush();
        let published = (recording.path.clone(), recording.lines);
        if let Some(error) = failed {
            self.recording = None;
            self.publish(|shared| shared.recording = None);
            self.transcript("(gravacao)", Err(format!("{}: {error}; a gravacao parou", published.0.display())));
            return;
        }
        self.publish(|shared| shared.recording = Some(published));
    }

    /// A parada que um `c` gravado esperava: o `wait-stop` com o prazo e a
    /// parada num comentário.
    fn record_stop(&mut self) {
        let Some(started) = self.recording.as_mut().and_then(|recording| recording.resumed_at.take()) else { return };
        let stop = self.client.as_ref().map(|client| client.last_stop().lines().next().unwrap_or("").to_string()).unwrap_or_default();
        self.record(&[script::wait_stop_line(started.elapsed()), format!("# parou: {stop}")]);
    }

    /// O que um pedido da janela vira no roteiro gravado (nada para o que
    /// só muda a vista).
    fn recorded_lines(&mut self, request: &Request) -> Vec<String> {
        let mut resumed = None;
        let lines = match request {
            Request::Command(line) => {
                let line = line.trim();
                match line.split_whitespace().next() {
                    None => return Vec::new(),
                    Some("c" | "g" | "continue") => resumed = Some(true),
                    Some("break" | "halt" | "wait-stop") => resumed = Some(false),
                    _ => {}
                }
                vec![line.to_string()]
            }
            Request::Go => {
                resumed = Some(true);
                vec!["c".to_string()]
            }
            Request::Break => {
                resumed = Some(false);
                vec!["break".to_string()]
            }
            Request::StepInto => vec!["t".to_string()],
            Request::StepOver => vec!["p".to_string()],
            Request::StepOut => vec!["gu".to_string()],
            Request::SelectCpu(thread) => vec![format!("thread {thread}")],
            Request::ToggleBreakpoint(address) => {
                let Some(client) = self.client.as_ref() else { return Vec::new() };
                match client.breakpoints().iter().find(|breakpoint| breakpoint.kind == BreakpointKind::Software && breakpoint.address == *address && !breakpoint.pending) {
                    Some(existing) => vec![script::clear_command(existing)],
                    None => vec![format!("bp {}", client.symbols.name_at(*address).unwrap_or_else(|| format!("{address:#x}")))],
                }
            }
            Request::AddBreakpoint(kind, expression) => vec![script::breakpoint_command(&BreakpointRequest::new(*kind, expression))],
            Request::AddBreakpointWith(breakpoint) => vec![script::breakpoint_command(breakpoint)],
            Request::RemoveBreakpoint(id) => self.client.as_ref().and_then(|client| client.breakpoints().iter().find(|breakpoint| breakpoint.id == *id).map(script::clear_command)).into_iter().collect(),
            Request::EnableBreakpoint(id, enabled) => vec![format!("{} {id}", if *enabled { "be" } else { "bd" })],
            Request::SetBreakpointCondition(id, condition, pass_count) => vec![format!("# o breakpoint #{id} passou a ter a condicao {condition:?} e a contagem {pass_count} (sem comando de texto)")],
            Request::WriteMemory(address, bytes) => vec![script::write_command(*address, bytes)],
            Request::WriteRegister(name, value) => vec![format!("r {name}={value:#x}")],
            Request::Query(kind, argument) => vec![kind.command(argument)],
            Request::ReloadSymbols => vec![".reload".to_string()],
            Request::Trace(_) | Request::QemuTrace { .. } => vec!["# (um rastro pelo painel Rastro)".to_string()],
            Request::SendKeys(keys) => vec![format!("# teclas pelo monitor do QEMU: {keys} (no test-boot: --keys={{{keys}}})")],
            Request::LoadBreakpoints(_) => vec!["# (os breakpoints de uma sessao aberta pelo menu Sessao)".to_string()],
            Request::RunScript { name, .. } => vec![format!("# (rodou o roteiro {name})")],
            Request::RunScriptFile(path) => vec![format!("# (rodou o roteiro {})", path.display())],
            _ => Vec::new(),
        };
        if let (Some(resumed), Some(recording)) = (resumed, self.recording.as_mut()) {
            recording.resumed_at = resumed.then(Instant::now);
        }
        lines
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
        // O log da COM1 até a parada chega antes do snapshot (a janela marca
        // a parada na linha certa).
        self.tail_serial();
        self.set_activity("lendo o estado da maquina");
        let snapshot = self.build_snapshot();
        self.set_activity("");
        match snapshot {
            Ok(snapshot) => {
                let completions = self.completions();
                self.publish(|shared| {
                    shared.snapshot = Arc::new(snapshot);
                    shared.status = Status::Stopped;
                    if let Some((symbols, types)) = completions {
                        if let Some(symbols) = symbols {
                            shared.completions = Arc::new(symbols);
                        }
                        if let Some(types) = types {
                            shared.type_names = Arc::new(types);
                        }
                    }
                });
            }
            Err(error) if is_connection_error(&error) => self.lost(error),
            Err(error) => self.transcript("(interface)", Err(error)),
        }
    }

    /// Os nomes do autocompletar, quando os símbolos ou os tipos mudaram.
    #[allow(clippy::type_complexity)]
    fn completions(&mut self) -> Option<(Option<Vec<String>>, Option<Vec<String>>)> {
        let client = self.client.as_mut()?;
        let symbols = (client.symbols.generation != self.symbols_generation).then(|| {
            self.symbols_generation = client.symbols.generation;
            let mut names: Vec<String> = Vec::new();
            for module in &client.symbols.modules {
                let prefix = if client.symbols.is_kernel(module) { String::new() } else { format!("{}!", module.name) };
                names.extend(module.symbols.iter().filter(|symbol| symbol.function).map(|symbol| format!("{prefix}{}", symbol.name)));
            }
            names.sort();
            names.dedup();
            names
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
        let mut snapshot = Snapshot { generation: self.generation, view: self.view, selected_frame: self.selected_frame, memory: MemoryView { expression: self.memory_expression.clone(), type_name: self.memory_type.clone(), ..Default::default() }, ..Default::default() };
        let view = self.view;
        let wanted = self.wanted;
        let elf = self.config.elf.clone();
        let Some(client) = self.client.as_mut() else { return Err("sem conexao com o alvo".into()) };
        snapshot.stop = client.last_stop().to_string();
        snapshot.stop_processor = client.stop_reply().and_then(|stop| stop.processor());
        snapshot.stop_signal = client.stop_reply().map_or(0, |stop| stop.signal);
        snapshot.stopped_threads = client.stopped_threads()?;
        snapshot.processors = client.processors().unwrap_or_default();
        // Processos e threads antes da pilha: a parte de usuário dela precisa
        // do processo dono da thread.
        snapshot.processes = client.processes().unwrap_or_default();
        let threads = client.threads(None).unwrap_or_default();
        // Registradores e pilha da visão escolhida.
        let mut frames = match view {
            View::Thread(ethread) => {
                let (context, frames) = client.thread_backtrace(ethread, 64)?;
                snapshot.view_header = context.header.clone();
                snapshot.registers = context.registers.iter().map(|(name, value)| RegisterRow { name: name.clone(), value: Some(*value), changed: false, symbol: None }).collect();
                snapshot.registers_editable = false;
                frames
            }
            View::Owner | View::Cpu(_) => {
                let mut rows: Vec<RegisterRow> = client.general_registers()?.into_iter().map(|value| RegisterRow { name: value.layout.name.to_string(), value: value.value, changed: false, symbol: None }).collect();
                for layout in registers::EXTRA {
                    rows.push(RegisterRow { name: layout.name.to_string(), value: client.register(layout.name).ok(), changed: false, symbol: None });
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
                if wanted.extended {
                    let extended = client.extended_registers();
                    if let Ok(state) = &extended {
                        for (index, value) in state.debug.iter().copied().take(4).enumerate() {
                            snapshot.debug_symbols[index] = value.and_then(|address| client.symbols.name_at(address));
                        }
                    }
                    snapshot.extended = Some(extended);
                }
                client.backtrace(64)?
            }
        };
        // O símbolo de cada registrador que aponta para um módulo.
        for row in &mut snapshot.registers {
            row.symbol = row.value.and_then(|value| client.symbols.name_at(value));
        }
        // A parte de usuário: uma thread de um processo de usuário parada no
        // kernel continua pelo CONTEXT de usuário salvo dela, com os módulos
        // do processo (o processo das leituras passa a ser o dela, a não ser
        // que outro tenha sido escolhido à mão).
        let mut user_from = None;
        let kernel_top = frames.first().is_some_and(|frame| frame.address >= KERNEL_START);
        if wanted.user_stack && kernel_top {
            let ethread = match view {
                View::Thread(ethread) => Some(ethread),
                View::Cpu(thread) => snapshot.processors.iter().find(|processor| processor.number + 1 == thread).map(|processor| processor.thread),
                View::Owner => snapshot.stop_processor.and_then(|number| snapshot.processors.iter().find(|processor| processor.number == number)).map(|processor| processor.thread),
            }
            .filter(|&ethread| ethread != 0);
            let owner = ethread
                .and_then(|ethread| threads.iter().find(|thread| thread.ethread == ethread))
                .and_then(|thread| snapshot.processes.iter().find(|process| process.pid == thread.pid))
                .filter(|process| process.pid > 4)
                .map(|process| process.eprocess);
            if let (Some(ethread), Some(eprocess)) = (ethread, owner) {
                let current = client.process().map(|context| context.eprocess);
                let chosen_by_hand = current.is_some() && current != self.auto_process;
                if chosen_by_hand && current != Some(eprocess) {
                    snapshot.user_stack_note = format!("sem a parte de usuario: o processo das leituras foi escolhido a mao (.process); a thread e do EPROCESS {eprocess:#x}");
                } else {
                    let mut switched: Result<(), String> = Ok(());
                    if current != Some(eprocess) {
                        switched = client.set_process(Some(format!("{eprocess:#x}").as_str())).map(|_| ());
                        if switched.is_ok() {
                            self.auto_process = Some(eprocess);
                        }
                    }
                    match switched.and_then(|()| details::user_frames(client, ethread, eprocess, 48)) {
                        Ok((thread, user)) => {
                            snapshot.user_stack_note = format!("CONTEXT de usuario salvo da thread {} (TEB {:#x})", thread.tid, thread.teb);
                            if !user.is_empty() {
                                user_from = Some(frames.len());
                                frames.extend(user);
                            }
                        }
                        Err(error) => snapshot.user_stack_note = format!("sem a parte de usuario: {error}"),
                    }
                }
            }
        }
        snapshot.frames = frames
            .iter()
            .enumerate()
            .map(|(index, frame)| {
                let name = client.frame_name(frame);
                // O módulo de um endereço de retorno é o do `call`.
                let lookup = if frame.is_return { frame.address.wrapping_sub(1) } else { frame.address };
                let module = client.symbols.module_at(lookup).map(|module| module.name.clone()).unwrap_or_default();
                let user_start = user_from == Some(index);
                FrameRow {
                    address: frame.address,
                    symbol: details::strip_module(&name, &module).to_string(),
                    name,
                    stack: frame.stack,
                    method: if user_start { "CONTEXT de usuario" } else { method_text(frame.method) },
                    module,
                    user: frame.address < KERNEL_START,
                    user_start,
                    line: None,
                }
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
        // Os ponteiros da janela e a vista como tipo do PDB.
        snapshot.memory.pointers = details::pointer_names(&client.symbols, &snapshot.memory.bytes);
        if !snapshot.memory.type_name.is_empty() && !snapshot.memory.bytes.is_empty() {
            match client.type_database() {
                Some(database) => match database.find(&snapshot.memory.type_name) {
                    Some(ty) => snapshot.memory.typed = Some((snapshot.memory.address, ty)),
                    None => snapshot.memory.type_error = Some(format!("o tipo {} nao existe no PDB do ntoskrnl", snapshot.memory.type_name)),
                },
                None => snapshot.memory.type_error = Some(client.types_note.clone()),
            }
        }
        let symbols = &client.symbols;
        snapshot.modules = symbols.modules.iter().map(|module| module_row(symbols, module)).collect();
        snapshot.threads = threads.into_iter().map(|thread| ThreadRow { start: client.symbols.describe(thread.start), detail: None, thread }).collect();
        // Espera e prioridade pelo KTHREAD (os offsets do PDB do ntoskrnl).
        if wanted.thread_details {
            let cached = self.thread_cache.as_ref().filter(|(filter, _)| *filter == wanted.thread_filter).map(|(_, found)| found.clone());
            let layout = match &self.kthread {
                Some(layout) => Some(layout.clone()),
                None => client.type_database().and_then(|database| KthreadLayout::from_types(&database)),
            };
            match layout {
                Some(layout) => {
                    let chosen: Vec<u64> = snapshot.threads.iter().filter(|row| wanted.thread_filter.is_none_or(|pid| pid == row.thread.pid)).take(THREAD_DETAIL_LIMIT).map(|row| row.thread.ethread).collect();
                    let found = match cached {
                        Some(found) => found,
                        None => details::thread_details(client, &layout, &chosen),
                    };
                    for row in &mut snapshot.threads {
                        row.detail = found.get(&row.thread.ethread).cloned();
                    }
                    if chosen.len() == THREAD_DETAIL_LIMIT {
                        snapshot.threads_note = format!("espera e prioridade so das primeiras {THREAD_DETAIL_LIMIT} threads (escolha um processo para ver as dele)");
                    }
                    self.thread_cache = Some((wanted.thread_filter, found));
                    self.kthread = Some(layout);
                }
                None => snapshot.threads_note = if client.types_note.is_empty() { "sem o _KTHREAD no PDB do ntoskrnl".into() } else { client.types_note.clone() },
            }
        }
        snapshot.process_context = client.process().cloned();
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
                    WatchRow { expression: expression.clone(), value: Ok(format!("{:#x} ({}){symbol}", value.number, value.number as i64)), typed, type_name }
                }
                Err(error) => WatchRow { expression: expression.clone(), value: Err(error), typed: None, type_name: String::new() },
            };
            snapshot.watches.push(row);
        }
        let mut typed_keys: Vec<(u64, u32)> = self.expanded.clone();
        typed_keys.extend(snapshot.watches.iter().filter_map(|row| row.typed));
        typed_keys.extend(snapshot.memory.typed);
        let mut seen = HashSet::new();
        for (address, ty) in typed_keys {
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
        // Parada por bugcheck: a análise vem junto.
        if snapshot.stop_signal == 6 {
            snapshot.bugcheck = client.analyze().ok();
        }
        snapshot.search = self.search.clone();
        // Linha de código e variáveis locais (só o kernel do OpenNT tem DWARF).
        if self.lines.is_none() {
            self.set_activity("lendo o DWARF do kernel.elf");
            self.lines = Some(LineTable::load(&elf));
        }
        let Some(client) = self.client.as_mut() else { return Err("sem conexao com o alvo".into()) };
        match self.lines.as_mut() {
            Some(Ok(table)) => {
                // O arquivo e a linha de cada quadro do kernel do OpenNT.
                for (row, frame) in snapshot.frames.iter_mut().zip(&frames) {
                    let pc = if frame.is_return { frame.address.wrapping_sub(1) } else { frame.address };
                    row.line = table.locate(pc).map(|position| (position.file, position.line));
                }
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

/// Como o desenrolar achou o quadro.
fn method_text(method: Method) -> &'static str {
    match method {
        Method::Context => "registradores",
        Method::Table => ".pdata",
        Method::Leaf => "folha",
        Method::Epilog => "epilogo",
        Method::FramePointer => "frame pointer",
    }
}

/// Uma linha da lista de módulos, com o estado do PDB.
fn module_row(symbols: &opennt_kd::Symbols, module: &opennt_kd::symbols::Module) -> ModuleRow {
    let (pdb_name, pdb_id) = details::pdb_identity(module);
    ModuleRow {
        base: module.base,
        end: module.end,
        name: module.name.clone(),
        file_name: module.file_name.clone(),
        symbols: module.symbols.len(),
        source: module.source.clone(),
        pdb: module.pdb.is_some(),
        pending: module.pdb_pending,
        path: module.path.clone(),
        user: module.user,
        status: PdbStatus::of(symbols, module),
        pdb_name,
        pdb_id,
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

/// As últimas `count` linhas não vazias de um texto (as da COM1 e do xtask
/// na mensagem de queda).
pub fn tail_lines(text: &str, count: usize) -> Vec<String> {
    let mut lines: Vec<String> = text.lines().rev().map(|line| line.trim_end().to_string()).filter(|line| !line.is_empty()).take(count).collect();
    lines.reverse();
    lines
}

/// Como o QEMU saiu, em texto (o `ExitStatus` do Rust: "exit code: 0").
fn describe_qemu_exit(status: &str) -> String {
    let code = status.rsplit(':').next().map(str::trim).unwrap_or(status);
    if code == "0" {
        "O QEMU saiu normalmente (a janela dele foi fechada ou o sistema desligou).".to_string()
    } else {
        format!("O QEMU saiu com {status}.")
    }
}

/// A mensagem de quando a sessão cai: o que aconteceu na primeira linha (a
/// barra de estado), depois como o QEMU saiu, um bugcheck ou pânico na
/// COM1, as últimas linhas da COM1 e do xtask, e como continuar.
pub fn loss_message(error: &str, launched: bool, qemu_status: Option<&str>, xtask_status: Option<&str>, serial_tail: &[String], xtask_tail: &[String]) -> String {
    let mut lines = vec![if error == QEMU_ENDED { "O QEMU terminou e a sessão acabou.".to_string() } else { format!("A conexão com o alvo caiu: {error}") }];
    match (qemu_status, xtask_status) {
        (Some(status), _) => lines.push(describe_qemu_exit(status)),
        (None, Some(status)) => lines.push(format!("O xtask saiu com {status}, sem a linha KD_QEMU_EXITED (o QEMU pode ter caído junto ou sido morto).")),
        (None, None) if launched => lines.push("O QEMU aberto pelo depurador foi fechado.".to_string()),
        (None, None) => lines.push("O QEMU de fora fechou o socket da COM2 ou terminou.".to_string()),
    }
    let serial = serial_tail.join("\n");
    if serial.contains("*** STOP") {
        lines.push("A COM1 mostra um bugcheck (*** STOP) que não chegou como parada ao depurador.".to_string());
    } else if serial.to_ascii_lowercase().contains("panic") {
        lines.push("A COM1 mostra um pânico do kernel.".to_string());
    }
    if !serial_tail.is_empty() {
        lines.push(String::new());
        lines.push("Últimas linhas da COM1:".to_string());
        lines.extend(serial_tail.iter().map(|line| format!("  {line}")));
    }
    if !xtask_tail.is_empty() {
        lines.push(String::new());
        lines.push("Últimas linhas do xtask:".to_string());
        lines.extend(xtask_tail.iter().map(|line| format!("  {line}")));
    }
    lines.push(String::new());
    lines.push(if launched { "Para continuar: Reiniciar (Ctrl+Shift+F5) recompila e abre o OpenNT com as mesmas opções; Ctrl+O troca as opções." } else { "Para continuar: Conectar de novo ao mesmo endereço, ou Ctrl+O para outro." }.to_string());
    lines.join("\n")
}

/// O erro é de conexão (o alvo sumiu), não de um comando.
/// A janela como anfitriã de um roteiro do opennt-kd: cada comando vira
/// uma entrada do painel de comandos (a saída dele junta até o próximo), a
/// barra de estado mostra a linha, e as esperas põem o DbgPrint, a COM1 e o
/// estado do alvo em dia.
struct WindowScript<'w> {
    worker: &'w mut Worker,
    name: String,
    /// O número de ordem de cada linha de comando do arquivo e o total.
    order: HashMap<usize, usize>,
    total: usize,
    /// A linha do arquivo que está rodando.
    line: usize,
    /// A entrada aberta: a linha do arquivo, o comando e a saída até agora.
    entry: Option<(usize, String, String)>,
}

impl WindowScript<'_> {
    fn flush(&mut self) {
        if let Some((_, input, output)) = self.entry.take() {
            self.worker.transcript(&input, Ok(output));
        }
    }

    /// O fim: a entrada aberta sai; a do comando que falhou sai com o erro.
    fn finish(&mut self, outcome: &ScriptOutcome) {
        let Err(error) = &outcome.result else { return self.flush() };
        match self.entry.take() {
            Some((line, input, output)) if outcome.failed_line == Some(line) => {
                let text = if output.is_empty() { error.clone() } else { format!("{output}\n{error}") };
                self.worker.transcript(&input, Err(text));
            }
            entry => {
                self.entry = entry;
                self.flush();
                self.worker.transcript("(roteiro)", Err(error.clone()));
            }
        }
    }
}

impl ScriptHost for WindowScript<'_> {
    fn output(&mut self, line: &str) {
        match script::panel_line(line) {
            PanelLine::Skip => {}
            PanelLine::Command(command) => {
                self.flush();
                self.entry = Some((self.line, format!("{command}    # roteiro, linha {}", self.line), String::new()));
            }
            PanelLine::Item(text) => {
                self.flush();
                self.entry = Some((self.line, text, String::new()));
            }
            PanelLine::Output(text) => match &mut self.entry {
                Some((_, _, output)) => {
                    if !output.is_empty() {
                        output.push('\n');
                    }
                    output.push_str(&text);
                }
                None => self.entry = Some((self.line, "(roteiro)".to_string(), text)),
            },
        }
    }

    fn progress(&mut self, line: usize, text: &str) {
        self.line = line;
        let index = self.order.get(&line).copied().unwrap_or(0);
        let progress = ScriptProgress { name: self.name.clone(), line, index, total: self.total, text: text.to_string() };
        self.worker.publish(|shared| shared.script = Some(progress));
        self.worker.set_activity(&format!("roteiro {index}/{}: {text}", self.total));
    }

    fn tick(&mut self, client: &mut Client) {
        self.worker.publish_console(client.take_console());
        self.worker.tail_serial();
        self.worker.publish_run_state(client);
    }

    fn cancelled(&self) -> bool {
        self.worker.cancel.load(Ordering::SeqCst)
    }

    fn serial_log(&self) -> Option<PathBuf> {
        self.worker.config.serial_log.clone()
    }

    fn intercept(&mut self, _client: &mut Client, word: &str, _text: &str) -> Option<Result<String, String>> {
        (word == "attach").then(|| Ok("a janela ja esta anexada".to_string()))
    }
}

fn is_connection_error(error: &str) -> bool {
    error.contains("fechou a conexao") || error.contains("depurador:") || error.contains("os error") || error.contains("nao confirmou")
}

#[cfg(test)]
mod tests {
    use super::{loss_message, parse_pattern, tail_lines, QEMU_ENDED};

    #[test]
    fn loss_messages() {
        let serial = tail_lines("a\n\nb\r\n*** STOP: 0x000000E2\n", 2);
        assert_eq!(serial, vec!["b".to_string(), "*** STOP: 0x000000E2".to_string()]);
        let message = loss_message(QEMU_ENDED, true, Some("exit code: 0"), None, &serial, &["KD_QEMU_EXITED exit code: 0".to_string()]);
        let first = message.lines().next().unwrap();
        assert_eq!(first, "O QEMU terminou e a sessão acabou.");
        assert!(message.contains("saiu normalmente"));
        assert!(message.contains("bugcheck (*** STOP)"));
        assert!(message.contains("Últimas linhas do xtask:"));
        assert!(message.contains("Reiniciar (Ctrl+Shift+F5)"));
        let message = loss_message("o alvo fechou a conexao", false, None, None, &[], &[]);
        assert!(message.starts_with("A conexão com o alvo caiu: o alvo fechou a conexao"));
        assert!(message.contains("QEMU de fora"));
        assert!(message.contains("Conectar de novo"));
        assert!(!message.contains("COM1"));
        let message = loss_message("o alvo fechou a conexao", true, None, Some("exit code: 101"), &[], &[]);
        assert!(message.contains("O xtask saiu com exit code: 101"));
        assert!(loss_message(QEMU_ENDED, true, Some("exit code: 1"), None, &[], &[]).contains("O QEMU saiu com exit code: 1."));
    }

    #[test]
    fn search_patterns() {
        assert_eq!(parse_pattern("48 8b 05"), Ok(vec![0x48, 0x8b, 0x05]));
        assert_eq!(parse_pattern("\"MZ\""), Ok(vec![b'M', b'Z']));
        assert_eq!(parse_pattern("u\"Nt\""), Ok(vec![b'N', 0, b't', 0]));
        assert!(parse_pattern("4").is_err());
        assert!(parse_pattern("zz").is_err());
    }
}
