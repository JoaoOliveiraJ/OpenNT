//! Os processos de usuário no backend do opennt-re: a lista de processos
//! com sessão, pai e imagem (os campos do `_EPROCESS` pelos tipos do PDB do
//! ntoskrnl, lidos uma vez por processo), os módulos do processo escolhido
//! com o estado do PDB, as threads de usuário dele com as pilhas de usuário
//! (o CONTEXT salvo) e de kernel (o quadro de troca), a exceção da parada
//! (`crate::exception`), os planos de seguir (`crate::follow`), os
//! breakpoints prontos de exceção, o registro de eventos e os símbolos de
//! uma DLL pelo arquivo, sem o processo.
//!
//! O que precisa do motor e ainda não está no opennt-kd fica descrito nos
//! comentários (os breakpoints de usuário adiados e o mesmo endereço em
//! dois processos são da área de breakpoints de usuário do opennt-kd).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use opennt_kd::client::{BreakpointRequest, Resumed};
use opennt_kd::pdb::SymbolStore;
use opennt_kd::pe::PeImage;
use opennt_kd::types::TypeDb;
use opennt_kd::unwind::{self, Context as UnwindContext, Frame, Method};
use opennt_kd::user::UserThread;
use opennt_kd::{Breakpoint, BreakpointKind, Client};

use super::{FrameRow, Notify, Shared, Snapshot, Status, Worker};
use crate::exception::{self, Preset, Report};
use crate::follow::{self, Event, EventKind, FollowPlan};

/// O STATUS_PENDING do ExitStatus de um processo vivo.
const STATUS_PENDING: u32 = 0x103;
/// Quanto esperar o PDB de um módulo antes de armar os símbolos dele.
const PDB_WAIT: Duration = Duration::from_secs(90);

/// Os pedidos das abas Processos e Exceção.
#[derive(Clone, Debug)]
pub enum UserRequest {
    /// Relê sessão, pai, imagem e estado de saída de todos os processos.
    RefreshProcesses,
    /// O processo do CR3 do processador parado vira o das leituras.
    StopContext,
    /// Relê os módulos do processo escolhido (PEB.Ldr e imagens do VAD).
    ReloadModules,
    /// As pilhas de usuário e de kernel de uma thread (TID) do processo
    /// escolhido; `None` fecha.
    ThreadStacks(Option<u64>),
    /// Um EXCEPTION_RECORD (ou EXCEPTION_POINTERS) numa expressão; vazio
    /// volta à exceção lida pela parada.
    DecodeException { expression: String, pointers: bool },
    /// Arma um breakpoint de uma vez só no ntdll!KiUserExceptionDispatcher
    /// do processo e continua (a entrega da exceção de primeira chance).
    RunToDispatcher,
    /// Um breakpoint de usuário num processo (EPROCESS; o contexto troca
    /// para ele). Um módulo que ainda não carregou vira um plano de seguir.
    Breakpoint { process: u64, request: BreakpointRequest },
    /// Os breakpoints prontos de exceção no processo escolhido.
    Preset(Preset),
    Follow(FollowPlan),
    Unfollow(u32),
    /// O registro (sem parar) da criação e saída de processos e das cargas
    /// de DLL.
    EventLog { processes: bool, images: bool },
    /// Os nomes (exports e públicos do PDB) de uma DLL pelo arquivo desta
    /// máquina.
    FileSymbols(String),
}

/// Uma linha da lista de processos.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessRow {
    pub pid: u64,
    pub eprocess: u64,
    pub cr3: u64,
    pub threads: u64,
    pub name: String,
    /// `_MM_SESSION_SPACE.SessionId` pelo `_EPROCESS.Session` (`None`: sem
    /// sessão, como o System e o smss, ou sem os tipos).
    pub session: Option<u32>,
    /// InheritedFromUniqueProcessId.
    pub parent: Option<u64>,
    /// O caminho do NT da imagem (SeAuditProcessCreationInfo.ImageFileName).
    pub image: String,
    /// ExitStatus (STATUS_PENDING enquanto vivo).
    pub exit_status: Option<u32>,
}

impl ProcessRow {
    /// O processo já está saindo (ExitStatus diferente de STATUS_PENDING).
    pub fn exiting(&self) -> bool {
        self.exit_status.is_some_and(|status| status != STATUS_PENDING)
    }
}

/// O estado do PDB de um módulo de usuário.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PdbState {
    /// O PDB carregado (o caminho).
    Loaded(String),
    Downloading,
    /// Só os exports do arquivo (o motivo).
    ExportsOnly(String),
    /// A DLL não está nesta máquina.
    NoFile,
}

/// Um módulo do processo escolhido.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserModuleRow {
    pub base: u64,
    pub end: u64,
    pub name: String,
    pub path: String,
    pub entry: Option<u64>,
    pub symbols: usize,
    pub pdb: PdbState,
}

/// Uma thread de usuário com os símbolos do início e do RIP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserThreadRow {
    pub start: String,
    pub rip: String,
    pub thread: UserThread,
}

/// As duas pilhas de uma thread.
#[derive(Clone, Debug)]
pub struct ThreadStacks {
    pub tid: u64,
    pub ethread: u64,
    pub teb: u64,
    /// A primeira linha do `context` do kernel (estado, onde estão os
    /// registradores).
    pub kernel_header: String,
    pub user: Result<Vec<FrameRow>, String>,
    pub kernel: Result<Vec<FrameRow>, String>,
}

/// Um plano de seguir com o estado.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanRow {
    pub id: u32,
    pub plan: FollowPlan,
    /// O breakpoint de evento do gatilho está ligado.
    pub trigger_armed: bool,
    pub finished: bool,
    /// Uma linha por processo seguido.
    pub instances: Vec<String>,
}

/// Os nomes de uma DLL pelo arquivo.
#[derive(Clone, Debug)]
pub struct FileSymbols {
    /// O nome curto (`dwmcore`), o prefixo dos símbolos.
    pub module: String,
    pub source: String,
    pub names: Result<Vec<String>, String>,
}

/// O que as abas Processos e Exceção mostram.
#[derive(Clone, Debug, Default)]
pub struct UserView {
    pub processes: Vec<ProcessRow>,
    pub modules: Vec<UserModuleRow>,
    pub threads: Option<Arc<Result<Vec<UserThreadRow>, String>>>,
    pub stacks: Option<Arc<ThreadStacks>>,
    pub exception: Option<Arc<Report>>,
    pub plans: Vec<PlanRow>,
    pub file_symbols: Option<Arc<FileSymbols>>,
    /// A última mensagem das ações desta área.
    pub message: String,
    /// Os tipos do ntoskrnl ainda não chegaram (sessão, pai e imagem vazios).
    pub types_note: String,
}

/// O que um processo tem de fixo (lido uma vez).
#[derive(Clone, Debug, Default)]
struct Facts {
    session: Option<u32>,
    parent: Option<u64>,
    image: String,
    exit_status: Option<u32>,
}

/// Um processo seguido por um plano.
#[derive(Clone, Debug)]
struct Instance {
    pid: u64,
    eprocess: u64,
    /// (símbolo, breakpoint).
    armed: Vec<(String, u32)>,
    /// Os símbolos de módulos que ainda não carregaram.
    waiting: Vec<String>,
    errors: Vec<String>,
}

impl Instance {
    fn describe(&self) -> String {
        let mut parts = vec![format!("PID {} (EPROCESS {:#x})", self.pid, self.eprocess)];
        if !self.armed.is_empty() {
            parts.push(format!("armados: {}", self.armed.iter().map(|(symbol, id)| format!("#{id} {symbol}")).collect::<Vec<_>>().join(", ")));
        }
        if !self.waiting.is_empty() {
            parts.push(format!("esperando a carga: {}", self.waiting.join(", ")));
        }
        if !self.errors.is_empty() {
            parts.push(format!("erros: {}", self.errors.join("; ")));
        }
        parts.join("; ")
    }
}

#[derive(Clone, Debug)]
struct PlanState {
    plan: FollowPlan,
    instances: Vec<Instance>,
    finished: bool,
}

/// O resultado de um evento para os planos.
#[derive(Default)]
struct Outcome {
    /// Algum plano pede a parada no evento.
    stop: bool,
    messages: Vec<String>,
}

/// O estado desta área dentro do backend.
#[derive(Default)]
pub struct UserState {
    facts: HashMap<(u64, u64), Facts>,
    threads: Option<Arc<Result<Vec<UserThreadRow>, String>>>,
    stacks_tid: Option<u64>,
    stacks: Option<Arc<ThreadStacks>>,
    /// A exceção pedida na aba (expressão, é um EXCEPTION_POINTERS).
    manual: Option<(String, bool)>,
    plans: Vec<PlanState>,
    next_plan: u32,
    /// Os eventos auxiliares (`ld:processo!`) que os planos armaram.
    helpers: Vec<String>,
    file_symbols: Option<Arc<FileSymbols>>,
    message: String,
}

impl Worker {
    /// A vista da parada (chamada ao montar o snapshot).
    pub(super) fn add_user_views(&mut self, snapshot: &mut Snapshot) {
        let Some(client) = self.client.as_mut() else { return };
        let mut view = UserView::default();
        // Os processos com o que eles têm de fixo.
        let types = client.type_database();
        if types.is_none() {
            view.types_note = client.types_note.clone();
        }
        for process in &snapshot.processes {
            let key = (process.eprocess, process.pid);
            if !self.user.facts.contains_key(&key) {
                if let Some(types) = &types {
                    let facts = read_facts(client, types, process.eprocess);
                    self.user.facts.insert(key, facts);
                }
            }
            let facts = self.user.facts.get(&key).cloned().unwrap_or_default();
            view.processes.push(ProcessRow { pid: process.pid, eprocess: process.eprocess, cr3: process.cr3, threads: process.threads, name: process.name.clone(), session: facts.session, parent: facts.parent, image: facts.image, exit_status: facts.exit_status });
        }
        if !snapshot.processes.is_empty() {
            self.user.facts.retain(|key, _| snapshot.processes.iter().any(|process| (process.eprocess, process.pid) == *key));
        }
        // Os módulos, as threads e as pilhas do processo escolhido.
        match client.process().cloned() {
            Some(context) => {
                if client.symbols.user_process == context.eprocess {
                    view.modules = client.symbols.user_modules().map(module_row).collect();
                }
                let threads = client.user_threads(&format!("{:#x}", context.eprocess)).map(|list| list.into_iter().map(|thread| UserThreadRow { start: client.symbols.describe(thread.start), rip: client.symbols.describe(thread.rip), thread }).collect::<Vec<_>>());
                let threads = Arc::new(threads);
                self.user.stacks = match (self.user.stacks_tid, &*threads) {
                    (Some(tid), Ok(list)) => match list.iter().find(|row| row.thread.tid == tid) {
                        Some(row) => Some(Arc::new(thread_stacks(client, &row.thread))),
                        None => None,
                    },
                    _ => None,
                };
                self.user.threads = Some(threads);
            }
            None => {
                self.user.threads = None;
                self.user.stacks = None;
            }
        }
        view.threads = self.user.threads.clone();
        view.stacks = self.user.stacks.clone();
        // A exceção: a pedida na aba ou a da parada.
        let registers: Vec<(String, u64)> = snapshot.registers.iter().filter_map(|row| row.value.map(|value| (row.name.clone(), value))).collect();
        let report = match self.user.manual.clone() {
            Some((expression, pointers)) => Some(match client.evaluate(&expression) {
                Ok(address) => exception::report_from_address(client, address, pointers, &format!("pedido na aba: {expression} = {address:#x}")),
                Err(error) => {
                    let mut report = Report::new(format!("pedido na aba: {expression}"));
                    report.record = Err(error);
                    report
                }
            }),
            None => automatic_report(client, &registers, snapshot.stop_signal, snapshot.user_mode),
        };
        if let Some(mut report) = report {
            if report.first_chance {
                report.notes.extend(snapshot.info_box.iter().cloned());
            }
            if let Some(context) = report.context {
                report.context_stack = context_stack(client, context);
            }
            report.symbolize(&|address| client.symbols.describe(address));
            view.exception = Some(Arc::new(report));
        }
        // Os planos.
        let breakpoints = client.breakpoints();
        for state in &self.user.plans {
            let trigger = state.plan.trigger();
            let trigger_armed = breakpoints.iter().any(|breakpoint| breakpoint.kind == BreakpointKind::Event && breakpoint.enabled && breakpoint.expression.eq_ignore_ascii_case(&trigger));
            view.plans.push(PlanRow { id: state.plan.id, plan: state.plan.clone(), trigger_armed, finished: state.finished, instances: state.instances.iter().map(Instance::describe).collect() });
        }
        view.file_symbols = self.user.file_symbols.clone();
        view.message = self.user.message.clone();
        snapshot.user = view;
    }

    /// Um pedido das abas Processos e Exceção; devolve se a parada precisa
    /// ser relida.
    pub(super) fn user_request(&mut self, request: UserRequest) -> Result<bool, String> {
        let result = match request {
            UserRequest::RefreshProcesses => {
                self.user.facts.clear();
                Ok(true)
            }
            UserRequest::StopContext => self.stop_context(),
            UserRequest::ReloadModules => {
                let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
                let count = client.reload_user_modules()?;
                self.user.message = format!("{count} modulos de usuario relidos");
                Ok(true)
            }
            UserRequest::ThreadStacks(tid) => {
                self.user.stacks_tid = tid;
                if tid.is_none() {
                    self.user.stacks = None;
                }
                Ok(true)
            }
            UserRequest::DecodeException { expression, pointers } => {
                let expression = expression.trim().to_string();
                self.user.manual = if expression.is_empty() { None } else { Some((expression, pointers)) };
                Ok(true)
            }
            UserRequest::RunToDispatcher => self.run_to_dispatcher(),
            UserRequest::Breakpoint { process, request } => self.user_breakpoint(process, request),
            UserRequest::Preset(preset) => self.arm_preset(preset),
            UserRequest::Follow(plan) => self.add_plan(plan),
            UserRequest::Unfollow(id) => self.remove_plan(id),
            UserRequest::EventLog { processes, images } => self.event_log(processes, images),
            UserRequest::FileSymbols(module) => self.file_symbols(&module),
        };
        if let Err(error) = &result {
            self.user.message = error.clone();
        }
        result
    }

    /// O processo do CR3 do processador parado vira o das leituras.
    fn stop_context(&mut self) -> Result<bool, String> {
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        let text = client.monitor(".process")?;
        let (eprocess, pid) = opennt_kd::user::parse_current_process(&text).ok_or_else(|| text.trim().to_string())?;
        client.set_process(Some(&format!("{eprocess:#x}")))?;
        self.re.handles = None;
        self.re.user_threads = None;
        self.re.memory_map = None;
        self.user.stacks_tid = None;
        self.user.message = format!("contexto: o processo da parada (PID {pid})");
        Ok(true)
    }

    fn run_to_dispatcher(&mut self) -> Result<bool, String> {
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        let process = client.process().map(|context| context.eprocess).ok_or("escolha o processo da exceção (aba Processos)")?;
        let mut request = BreakpointRequest::new(BreakpointKind::Software, "ntdll!KiUserExceptionDispatcher");
        request.process = process;
        request.options.single_shot = true;
        request.options.name = "entrega da exceção".into();
        client.add_breakpoint_with(&request)?;
        self.user.message = "continuando até a entrega da exceção".into();
        self.resume(|client| client.go().map(|_| Resumed::Running))
    }

    /// Um breakpoint de usuário num processo. Um símbolo de um módulo que
    /// ainda não carregou nele vira um plano de seguir de uma vez só (o
    /// opennt-kd ainda não arma breakpoints de usuário adiados: o `bu` só é
    /// resolvido na notificação de carga do kernel, sem o processo dono).
    fn user_breakpoint(&mut self, process: u64, mut request: BreakpointRequest) -> Result<bool, String> {
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        if process != 0 && client.process().map(|context| context.eprocess) != Some(process) {
            client.set_process(Some(&format!("{process:#x}")))?;
            self.re.handles = None;
            self.re.user_threads = None;
            self.re.memory_map = None;
        }
        request.process = process;
        request.deferred = false;
        let module = request.expression.split_once('!').map(|(module, _)| module.trim().to_string());
        // O PDB do módulo ainda chegando: espera antes de procurar o nome.
        if let Some(module) = &module {
            wait_for_pdb(client, module, &self.config.root, &self.shared, &self.notify);
        }
        match client.add_breakpoint_with(&request) {
            Ok(breakpoint) => {
                if process != 0 && breakpoint.process != process {
                    self.user.message = format!("breakpoint #{} em {:#x}: o endereço já tinha um breakpoint de outro processo ({:#x})", breakpoint.id, breakpoint.address, breakpoint.process);
                } else {
                    self.user.message = format!("breakpoint #{} em {:#x} {}", breakpoint.id, breakpoint.address, client.symbols.describe(breakpoint.address));
                }
                self.save_session();
                Ok(true)
            }
            Err(error) => {
                let loaded = module.as_deref().is_some_and(|module| client.symbols.module_named(module).is_some());
                let name = client.process().map(|context| context.name.clone()).unwrap_or_default();
                match module {
                    Some(module) if !loaded && !name.is_empty() && process != 0 => {
                        let plan = FollowPlan { id: 0, process: name, module, symbols: vec![request.expression.clone()], condition: request.condition.clone(), log: request.log.clone(), stop_at_trigger: false, once: true };
                        self.add_plan(plan)
                    }
                    _ => Err(error),
                }
            }
        }
    }

    fn arm_preset(&mut self, preset: Preset) -> Result<bool, String> {
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        let process = client.process().map(|context| context.eprocess).ok_or("escolha um processo (aba Processos) antes")?;
        let mut armed = Vec::new();
        let mut errors = Vec::new();
        for spec in preset.breakpoints() {
            let mut request = BreakpointRequest::new(BreakpointKind::Software, spec.expression);
            request.condition = spec.condition.to_string();
            request.log = spec.log.to_string();
            request.process = process;
            request.group = "excecoes".into();
            request.options.name = spec.name.to_string();
            match client.add_breakpoint_with(&request) {
                Ok(breakpoint) => armed.push(format!("#{} {}", breakpoint.id, spec.expression)),
                Err(error) => errors.push(format!("{}: {error}", spec.expression)),
            }
        }
        if armed.is_empty() {
            return Err(errors.join("; "));
        }
        self.save_session();
        let mut text = format!("{}: {}", preset.label(), armed.join(", "));
        if !errors.is_empty() {
            text.push_str(&format!(" (falharam: {})", errors.join("; ")));
        }
        self.transcript("(excecoes)", Ok(text.clone()));
        self.user.message = text;
        Ok(true)
    }

    fn event_log(&mut self, processes: bool, images: bool) -> Result<bool, String> {
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        set_log_event(client, follow::LOG_CREATE, processes)?;
        set_log_event(client, follow::LOG_EXIT, processes)?;
        set_log_event(client, follow::LOG_IMAGES, images)?;
        self.save_session();
        self.user.message = format!("registro de eventos: processos {}, cargas de DLL {}", if processes { "ligado" } else { "desligado" }, if images { "ligado" } else { "desligado" });
        Ok(true)
    }

    /// Os nomes de uma DLL pelo arquivo desta máquina (exports e públicos
    /// do PDB do cache), para escolher onde parar antes de o processo
    /// existir.
    fn file_symbols(&mut self, module: &str) -> Result<bool, String> {
        let module = module.trim();
        if module.is_empty() {
            return Err("qual DLL? (dwmcore.dll)".into());
        }
        let file_name = if module.contains('.') { module.to_string() } else { format!("{module}.dll") };
        let store = self.client.as_ref().and_then(|client| client.symbols.store.clone()).unwrap_or_else(|| SymbolStore::new(&self.config.root));
        let mut source = String::new();
        let names = (|| -> Result<Vec<String>, String> {
            let path = opennt_kd::symbols::host_file(&file_name).ok_or_else(|| format!("{file_name}: arquivo nao achado em C:\\Windows (System32, drivers)"))?;
            let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
            let image = PeImage::parse(bytes).ok_or_else(|| format!("{}: PE invalido", path.display()))?;
            let mut names: Vec<String> = image.exports().into_iter().map(|(_, name)| name).collect();
            source = format!("exports de {}", path.display());
            let id = opennt_kd::pdb::PdbId::of_image(&image);
            match id.as_ref().and_then(|id| store.request(id).map(|pdb| (id, pdb))) {
                Some((id, pdb)) => match opennt_kd::pdb::load(&pdb, id, &opennt_kd::pdb::PdbSection::of_image(&image)) {
                    Some(data) => {
                        names.extend(data.symbols.into_iter().map(|symbol| symbol.name));
                        source = format!("PDB {} + exports", pdb.display());
                    }
                    None => source.push_str(" (o PDB do cache nao confere)"),
                },
                None if id.is_none() => source.push_str(" (a imagem nao cita PDB)"),
                None => source.push_str(" (o PDB esta baixando ou indisponivel: carregue de novo em alguns segundos)"),
            }
            names.sort();
            names.dedup();
            Ok(names)
        })();
        let stem = opennt_kd::symbols::display_name(&file_name);
        self.user.message = match &names {
            Ok(list) => format!("{}: {} nomes", stem, list.len()),
            Err(error) => error.clone(),
        };
        self.user.file_symbols = Some(Arc::new(FileSymbols { module: stem, source, names }));
        self.publish_user_view();
        Ok(false)
    }

    /// Só a parte desta área no snapshot publicado (sem reler a parada).
    fn publish_user_view(&mut self) {
        let current = self.shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).snapshot.clone();
        let mut copy = (*current).clone();
        copy.user.file_symbols = self.user.file_symbols.clone();
        copy.user.message = self.user.message.clone();
        self.generation += 1;
        copy.generation = self.generation;
        self.publish(|shared| shared.snapshot = Arc::new(copy));
    }

    // ---- os planos de seguir -------------------------------------------------

    fn plans_path(&self) -> Option<PathBuf> {
        self.config.session.as_ref().map(|path| path.with_file_name("seguir.txt"))
    }

    fn save_plans(&self) {
        let Some(path) = self.plans_path() else { return };
        let plans: Vec<FollowPlan> = self.user.plans.iter().filter(|state| !state.finished).map(|state| state.plan.clone()).collect();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&path, follow::plans_to_text(&plans));
    }

    /// Arma o gatilho do plano e o guarda; o texto do plano.
    fn register_plan(&mut self, mut plan: FollowPlan) -> Result<String, String> {
        plan.validate()?;
        plan.symbols = plan.qualified_symbols();
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        client.add_breakpoint_with(&BreakpointRequest::new(BreakpointKind::Event, &plan.trigger()))?;
        self.user.next_plan += 1;
        plan.id = self.user.next_plan;
        let text = format!("#{} {} (gatilho: sxe {})", plan.id, plan.describe(), plan.trigger());
        self.user.plans.push(PlanState { plan, instances: Vec::new(), finished: false });
        Ok(text)
    }

    fn add_plan(&mut self, plan: FollowPlan) -> Result<bool, String> {
        let text = self.register_plan(plan)?;
        self.user.message = format!("seguir {text}");
        self.save_plans();
        self.save_session();
        self.transcript("(seguir)", Ok(text));
        Ok(true)
    }

    fn remove_plan(&mut self, id: u32) -> Result<bool, String> {
        let index = self.user.plans.iter().position(|state| state.plan.id == id).ok_or_else(|| format!("plano #{id} nao existe"))?;
        let state = self.user.plans.remove(index);
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        let trigger = state.plan.trigger();
        if !self.user.plans.iter().any(|other| !other.finished && other.plan.trigger().eq_ignore_ascii_case(&trigger)) {
            let found = client.breakpoints().iter().find(|breakpoint| breakpoint.kind == BreakpointKind::Event && breakpoint.expression.eq_ignore_ascii_case(&trigger)).map(|breakpoint| breakpoint.id);
            if let Some(found) = found {
                let _ = client.remove_breakpoint(found);
            }
        }
        for instance in &state.instances {
            for (_, breakpoint) in &instance.armed {
                let _ = client.remove_breakpoint(*breakpoint);
            }
        }
        sync_helpers(client, &self.user.plans, &mut self.user.helpers);
        self.save_plans();
        self.save_session();
        let text = format!("plano #{id} tirado ({})", state.plan.describe());
        self.user.message = text.clone();
        self.transcript("(seguir)", Ok(text));
        Ok(true)
    }

    /// Os planos da sessão anterior (`seguir.txt`), com os gatilhos de novo;
    /// os eventos auxiliares que voltaram do arquivo de breakpoints saem.
    pub(super) fn user_after_attach(&mut self) {
        let plans: Vec<FollowPlan> = self.plans_path().and_then(|path| std::fs::read_to_string(path).ok()).map(|text| follow::plans_from_text(&text)).unwrap_or_default();
        self.user = UserState::default();
        if plans.is_empty() {
            return;
        }
        let helpers: Vec<String> = plans.iter().map(|plan| plan.helper().to_ascii_lowercase()).collect();
        let triggers: Vec<String> = plans.iter().map(|plan| plan.trigger().to_ascii_lowercase()).collect();
        if let Some(client) = self.client.as_mut() {
            let stale: Vec<u32> = client.breakpoints().iter().filter(|breakpoint| breakpoint.kind == BreakpointKind::Event && breakpoint.log.trim().is_empty()).filter(|breakpoint| {
                let expression = breakpoint.expression.to_ascii_lowercase();
                helpers.contains(&expression) && !triggers.contains(&expression)
            }).map(|breakpoint| breakpoint.id).collect();
            for id in stale {
                let _ = client.remove_breakpoint(id);
            }
        }
        let mut lines = Vec::new();
        for plan in plans {
            match self.register_plan(plan) {
                Ok(text) => lines.push(text),
                Err(error) => lines.push(format!("erro: {error}")),
            }
        }
        self.save_session();
        self.transcript("(seguir)", Ok(format!("planos da sessao anterior:\n{}", lines.join("\n"))));
    }

    /// O comando `seguir` da barra de comando: sem argumentos lista os
    /// planos, `seguir -N` tira o plano N, senão
    /// `processo[!dll] [símbolo...] [/parar] [/uma]`.
    pub(super) fn follow_command(&mut self, line: &str) -> Result<bool, String> {
        let rest = line.trim().strip_prefix("seguir").unwrap_or("").trim();
        if rest.is_empty() {
            let text = if self.user.plans.is_empty() {
                format!("nenhum plano\n{}", follow::USAGE)
            } else {
                self.user.plans.iter().map(|state| format!("#{} {}{}", state.plan.id, state.plan.describe(), if state.finished { " (concluido)" } else { "" })).collect::<Vec<_>>().join("\n")
            };
            self.transcript(line.trim(), Ok(text));
            return Ok(false);
        }
        if let Some(number) = rest.strip_prefix('-') {
            let id = number.trim().trim_start_matches('#').parse().map_err(|_| follow::USAGE.to_string())?;
            return self.remove_plan(id);
        }
        let plan = FollowPlan::parse(rest)?;
        self.add_plan(plan)
    }

    /// Depois de uma parada com a máquina rodando: um evento que dispara um
    /// plano arma os breakpoints dele no processo e, se ninguém pede a
    /// parada, a máquina segue sozinha. Devolve se seguiu.
    pub(super) fn follow_after_stop(&mut self) -> bool {
        if self.user.plans.is_empty() {
            return false;
        }
        let Some(event) = self.client.as_ref().and_then(|client| follow::parse_stop(client.last_stop())).map(|(_, event)| event) else { return false };
        let outcome = {
            let Some(client) = self.client.as_mut() else { return false };
            follow_event(client, &mut self.user.plans, &mut self.user.helpers, &event, &self.config.root, &self.shared, &self.notify)
        };
        let Some(mut outcome) = outcome else { return false };
        let owned: Vec<String> = self.user.plans.iter().flat_map(|state| [state.plan.trigger().to_ascii_lowercase(), state.plan.helper().to_ascii_lowercase()]).collect();
        let (foreign, resumed) = {
            let Some(client) = self.client.as_mut() else { return false };
            // Um breakpoint de evento do usuário que também casa pede a parada.
            let foreign = client.breakpoints().iter().any(|breakpoint| breakpoint.enabled && breakpoint.kind == BreakpointKind::Event && breakpoint.log.trim().is_empty() && !owned.contains(&breakpoint.expression.to_ascii_lowercase()) && follow::event_matches(&breakpoint.expression, &event));
            let resume = !outcome.stop && !foreign;
            let resumed = resume
                && match client.go() {
                    Ok(()) => true,
                    Err(error) => {
                        outcome.messages.push(format!("seguir: {error}"));
                        false
                    }
                };
            (foreign, resumed)
        };
        let mut text = outcome.messages.join("\n");
        text.push_str(if resumed {
            "\n(segue sozinho)"
        } else if foreign {
            "\n(parado: outro breakpoint de evento pede esta parada)"
        } else {
            "\n(parado no evento)"
        });
        self.user.message = outcome.messages.last().cloned().unwrap_or_default();
        self.save_plans();
        self.save_session();
        self.transcript("(seguir)", Ok(text));
        if resumed {
            self.set_status(Status::Running);
        }
        resumed
    }
}

/// Uma linha da lista de módulos.
fn module_row(module: &opennt_kd::symbols::Module) -> UserModuleRow {
    let pdb = match (&module.pdb, module.pdb_pending, &module.image) {
        (Some(path), _, _) => PdbState::Loaded(path.display().to_string()),
        (None, true, _) => PdbState::Downloading,
        (None, false, None) => PdbState::NoFile,
        (None, false, Some(_)) => PdbState::ExportsOnly(pdb_reason(&module.source)),
    };
    let entry = module.image.as_ref().map(|image| module.base + image.header.entry_point as u64).filter(|&entry| entry != module.base);
    UserModuleRow { base: module.base, end: module.end, name: module.name.clone(), path: module.path.clone(), entry, symbols: module.symbols.len(), pdb }
}

/// O motivo de um módulo sem PDB (o texto da origem dos símbolos).
fn pdb_reason(source: &str) -> String {
    match source.find("(PDB indisponivel: ") {
        Some(start) => source[start + "(PDB indisponivel: ".len()..].trim_end_matches(')').to_string(),
        None if source.contains("baixando") => "baixando".into(),
        None => "sem PDB no cache nem no servidor".into(),
    }
}

/// Sessão, pai, imagem e estado de saída de um processo, pelos campos do
/// `_EPROCESS` nos tipos do PDB do ntoskrnl.
fn read_facts(client: &mut Client, types: &TypeDb, eprocess: u64) -> Facts {
    let offset = |structure: &str, field: &str| types.field_offset(structure, field);
    let mut facts = Facts::default();
    if let (Some(session), Some(id)) = (offset("_EPROCESS", "Session"), offset("_MM_SESSION_SPACE", "SessionId")) {
        if let Ok(pointer) = client.read_integer(eprocess + session, 8) {
            if pointer != 0 {
                facts.session = client.read_integer(pointer + id, 4).ok().map(|value| value as u32);
            }
        }
    }
    if let Some(parent) = offset("_EPROCESS", "InheritedFromUniqueProcessId") {
        facts.parent = client.read_integer(eprocess + parent, 8).ok().filter(|&pid| pid != 0);
    }
    if let (Some(audit), Some(name)) = (offset("_EPROCESS", "SeAuditProcessCreationInfo"), offset("_SE_AUDIT_PROCESS_CREATION_INFO", "ImageFileName")) {
        if let Ok(pointer) = client.read_integer(eprocess + audit + name, 8) {
            if pointer != 0 {
                facts.image = opennt_kd::types::read_unicode_string(client, pointer).unwrap_or_default();
            }
        }
    }
    if let Some(exit) = offset("_EPROCESS", "ExitStatus") {
        facts.exit_status = client.read_integer(eprocess + exit, 4).ok().map(|value| value as u32);
    }
    facts
}

fn method_text(method: Method) -> &'static str {
    match method {
        Method::Context => "registradores",
        Method::Table => ".pdata",
        Method::Leaf => "folha",
        Method::Epilog => "epilogo",
        Method::FramePointer => "frame pointer",
    }
}

fn frame_rows(client: &Client, frames: &[Frame]) -> Vec<FrameRow> {
    frames.iter().map(|frame| FrameRow { address: frame.address, name: client.frame_name(frame), stack: frame.stack, method: method_text(frame.method), arguments: Vec::new() }).collect()
}

/// A pilha de usuário (o CONTEXT salvo, pela `.pdata` dos módulos do
/// processo escolhido) e a de kernel (o `context` do alvo) de uma thread.
fn thread_stacks(client: &mut Client, thread: &UserThread) -> ThreadStacks {
    let user = client.user_thread_backtrace(thread, 64).map(|(_, frames)| frame_rows(client, &frames));
    let (kernel_header, kernel) = match client.thread_backtrace(thread.ethread, 64) {
        Ok((context, frames)) => (context.header.clone(), Ok(frame_rows(client, &frames))),
        Err(error) => (String::new(), Err(error)),
    };
    ThreadStacks { tid: thread.tid, ethread: thread.ethread, teb: thread.teb, kernel_header, user, kernel }
}

/// A exceção lida pela parada: a entrada de uma das funções conhecidas, ou
/// uma parada de primeira chance do anel 3.
fn automatic_report(client: &mut Client, registers: &[(String, u64)], signal: u8, user_mode: bool) -> Option<Report> {
    let register = |name: &str| registers.iter().find(|(key, _)| key == name).map(|(_, value)| *value);
    let rip = register("rip")?;
    if rip >= 0x8000_0000_0000 {
        return None;
    }
    let module = client.symbols.module_at(rip).map(|module| module.name.to_ascii_lowercase()).unwrap_or_default();
    for locator in exception::LOCATORS.iter().filter(|locator| locator.module().eq_ignore_ascii_case(&module)) {
        if client.symbols.lookup(locator.symbol).ok() == Some(rip) {
            return Some(exception::report_at(locator, &register, client));
        }
    }
    if user_mode && matches!(signal, 4 | 6 | 8 | 11) {
        return Some(exception::first_chance(client, signal, rip, register("rcx").unwrap_or(0)));
    }
    None
}

/// A pilha desenrolada de um CONTEXT (o ponto da exceção).
fn context_stack(client: &mut Client, context: u64) -> Vec<(u64, String)> {
    let Ok(bytes) = client.read_memory(context, 0x100) else { return Vec::new() };
    if bytes.len() < 0x100 {
        return Vec::new();
    }
    let registers = opennt_kd::user::context_registers(&bytes);
    let rip = registers.iter().find(|(name, _)| *name == "rip").map_or(0, |(_, value)| *value);
    if rip == 0 {
        return Vec::new();
    }
    let frames = unwind::walk(client, UnwindContext::from_named(rip, &registers), false, 48);
    frames.iter().map(|frame| (frame.address, client.frame_name(frame))).collect()
}

/// A atividade da barra de estado, sem passar pelo `Worker` (o cliente
/// está emprestado).
fn set_activity(shared: &Arc<Mutex<Shared>>, notify: &Notify, text: &str) {
    shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).activity = text.to_string();
    notify();
}

/// Espera o PDB de um módulo de usuário que ainda está chegando (os
/// símbolos dele só existem depois); no fim, os PDBs que chegaram entram.
fn wait_for_pdb(client: &mut Client, module: &str, root: &Path, shared: &Arc<Mutex<Shared>>, notify: &Notify) {
    let deadline = Instant::now() + PDB_WAIT;
    let mut waited = false;
    while client.symbols.module_named(module).is_some_and(|found| found.pdb_pending) && Instant::now() < deadline {
        if !client.symbols.store.as_ref().is_some_and(SymbolStore::busy) {
            swap_user_pdbs(client, root);
            break;
        }
        if !waited {
            set_activity(shared, notify, &format!("seguir: esperando o PDB de {module}"));
            waited = true;
        }
        thread::sleep(Duration::from_millis(250));
    }
    if waited {
        set_activity(shared, notify, "");
    }
}

/// Troca os PDBs que chegaram nos módulos de usuário (o `reload_modules` do
/// opennt-kd só refaz os do kernel; sem isto um módulo de usuário fica
/// "baixando" para sempre e o laço do backend relê a parada sem parar).
pub(super) fn swap_user_pdbs(client: &mut Client, root: &Path) {
    if !client.symbols.user_modules().any(|module| module.pdb_pending) {
        return;
    }
    let list: Vec<(u64, u64, String)> = client.symbols.user_modules().map(|module| (module.base, module.end, module.path.clone())).collect();
    let process = client.symbols.user_process;
    client.symbols.set_user_modules(process, &list, root);
}

/// Liga (com o texto de registro, sem parar) ou tira um breakpoint de
/// evento do registro.
fn set_log_event(client: &mut Client, expression: &str, on: bool) -> Result<(), String> {
    let existing = client.breakpoints().iter().find(|breakpoint| breakpoint.kind == BreakpointKind::Event && breakpoint.expression.eq_ignore_ascii_case(expression)).map(|breakpoint| breakpoint.id);
    match (on, existing) {
        (true, None) => {
            let mut request = BreakpointRequest::new(BreakpointKind::Event, expression);
            request.log = follow::LOG_MARK.into();
            client.add_breakpoint_with(&request)?;
        }
        (false, Some(id)) => {
            client.remove_breakpoint(id)?;
        }
        _ => {}
    }
    Ok(())
}

/// Arma um símbolo de um plano no processo; `Ok(None)` quando o módulo
/// dele ainda não carregou.
fn arm_symbol(client: &mut Client, plan: &FollowPlan, symbol: &str, eprocess: u64) -> Result<Option<Breakpoint>, String> {
    if let Some((module, _)) = symbol.split_once('!') {
        if client.symbols.module_named(module.trim()).is_none() {
            return Ok(None);
        }
    }
    let mut request = BreakpointRequest::new(BreakpointKind::Software, symbol);
    request.process = eprocess;
    request.condition = plan.condition.clone();
    request.log = plan.log.clone();
    request.group = format!("seguir #{}", plan.id);
    request.options.name = format!("seguir #{} {}", plan.id, plan.process);
    match client.add_breakpoint_with(&request) {
        Ok(breakpoint) => Ok(Some(breakpoint)),
        Err(error) if error.contains("nao carregado") => Ok(None),
        Err(error) => Err(error),
    }
}

/// Os eventos auxiliares (`ld:processo!`) dos planos com símbolos
/// esperando: arma os que faltam e tira os que este backend armou e não
/// servem mais.
fn sync_helpers(client: &mut Client, plans: &[PlanState], helpers: &mut Vec<String>) {
    let needed: Vec<String> = plans.iter().filter(|state| state.instances.iter().any(|instance| !instance.waiting.is_empty())).map(|state| state.plan.helper().to_ascii_lowercase()).collect();
    let triggers: Vec<String> = plans.iter().filter(|state| !state.finished).map(|state| state.plan.trigger().to_ascii_lowercase()).collect();
    helpers.retain(|expression| {
        if needed.contains(expression) || triggers.contains(expression) {
            return true;
        }
        let found = client.breakpoints().iter().find(|breakpoint| breakpoint.kind == BreakpointKind::Event && breakpoint.expression.eq_ignore_ascii_case(expression)).map(|breakpoint| breakpoint.id);
        if let Some(found) = found {
            let _ = client.remove_breakpoint(found);
        }
        false
    });
    for expression in needed {
        if helpers.contains(&expression) {
            continue;
        }
        let exists = client.breakpoints().iter().any(|breakpoint| breakpoint.kind == BreakpointKind::Event && breakpoint.expression.eq_ignore_ascii_case(&expression));
        if !exists && client.add_breakpoint_with(&BreakpointRequest::new(BreakpointKind::Event, &expression)).is_ok() {
            helpers.push(expression);
        }
    }
}

/// Um evento para os planos: os gatilhos criam os processos seguidos, os
/// símbolos esperando são armados. `None` quando o evento não é de nenhum
/// plano.
fn follow_event(client: &mut Client, plans: &mut [PlanState], helpers: &mut Vec<String>, event: &Event, root: &Path, shared: &Arc<Mutex<Shared>>, notify: &Notify) -> Option<Outcome> {
    let mut outcome = Outcome::default();
    if event.kind == EventKind::ProcessExiting {
        // Os símbolos esperando num processo que sai não vão carregar.
        for state in plans.iter_mut() {
            for instance in state.instances.iter_mut().filter(|instance| instance.pid == event.pid) {
                instance.waiting.clear();
            }
        }
        sync_helpers(client, plans, helpers);
        return None;
    }
    if !matches!(event.kind, EventKind::ProcessCreated | EventKind::Image) {
        return None;
    }
    let processes = client.processes().unwrap_or_default();
    let eprocess = event.eprocess.or_else(|| processes.iter().find(|process| process.pid == event.pid).map(|process| process.eprocess))?;
    let mut ours = false;
    // Os gatilhos.
    let mut finished = Vec::new();
    for state in plans.iter_mut() {
        if state.finished || !state.plan.triggered_by(event) {
            continue;
        }
        ours = true;
        outcome.stop |= state.plan.stop_at_trigger;
        // As instâncias deste PID (de novo) e as de processos que acabaram
        // saem com os breakpoints delas.
        let mut kept = Vec::new();
        for instance in state.instances.drain(..) {
            let alive = processes.iter().any(|process| process.pid == instance.pid && process.eprocess == instance.eprocess);
            if instance.pid == event.pid || !alive {
                for (_, id) in &instance.armed {
                    let _ = client.remove_breakpoint(*id);
                }
            } else {
                kept.push(instance);
            }
        }
        kept.push(Instance { pid: event.pid, eprocess, armed: Vec::new(), waiting: state.plan.symbols.clone(), errors: Vec::new() });
        state.instances = kept;
        outcome.messages.push(format!("#{} {}: {} {} (PID {})", state.plan.id, state.plan.process, event.kind.label(), if event.kind == EventKind::Image { event.dll() } else { event.process.as_str() }, event.pid));
        if state.plan.once {
            state.finished = true;
            finished.push(state.plan.trigger());
        }
    }
    for trigger in finished {
        if !plans.iter().any(|state| !state.finished && state.plan.trigger().eq_ignore_ascii_case(&trigger)) {
            let found = client.breakpoints().iter().find(|breakpoint| breakpoint.kind == BreakpointKind::Event && breakpoint.expression.eq_ignore_ascii_case(&trigger)).map(|breakpoint| breakpoint.id);
            if let Some(found) = found {
                let _ = client.remove_breakpoint(found);
            }
        }
    }
    // Os símbolos esperando neste processo.
    let waiting = plans.iter().any(|state| state.instances.iter().any(|instance| instance.pid == event.pid && !instance.waiting.is_empty()));
    ours |= waiting && plans.iter().any(|state| state.instances.iter().any(|instance| instance.pid == event.pid && !instance.waiting.is_empty()) && follow::event_matches(&state.plan.helper(), event));
    if waiting {
        if client.process().map(|context| context.eprocess) != Some(eprocess) {
            if let Err(error) = client.set_process(Some(&format!("{eprocess:#x}"))) {
                outcome.messages.push(format!("contexto do PID {}: {error}", event.pid));
            }
        } else {
            let _ = client.reload_user_modules();
        }
        let mut modules: Vec<String> = plans.iter().flat_map(|state| state.instances.iter().filter(|instance| instance.pid == event.pid).flat_map(|instance| instance.waiting.iter())).filter_map(|symbol| symbol.split_once('!').map(|(module, _)| module.trim().to_string())).collect();
        modules.sort();
        modules.dedup();
        for module in &modules {
            wait_for_pdb(client, module, root, shared, notify);
        }
        for state in plans.iter_mut() {
            let plan = state.plan.clone();
            for instance in state.instances.iter_mut().filter(|instance| instance.pid == event.pid) {
                let mut still = Vec::new();
                for symbol in std::mem::take(&mut instance.waiting) {
                    match arm_symbol(client, &plan, &symbol, eprocess) {
                        Ok(Some(breakpoint)) => {
                            if breakpoint.process != eprocess {
                                instance.errors.push(format!("{symbol}: o endereço {:#x} já tinha um breakpoint de outro processo ({:#x})", breakpoint.address, breakpoint.process));
                            }
                            outcome.messages.push(format!("#{} armado no PID {}: {symbol} em {:#x} (breakpoint #{})", plan.id, event.pid, breakpoint.address, breakpoint.id));
                            instance.armed.push((symbol, breakpoint.id));
                            ours = true;
                        }
                        Ok(None) => still.push(symbol),
                        Err(error) => {
                            // Um símbolo que não arma (nome errado, sem PDB):
                            // a máquina fica parada no evento para corrigir.
                            outcome.messages.push(format!("#{} {symbol}: {error}", plan.id));
                            instance.errors.push(format!("{symbol}: {error}"));
                            outcome.stop = true;
                            ours = true;
                        }
                    }
                }
                instance.waiting = still;
            }
        }
    }
    if !ours {
        return None;
    }
    sync_helpers(client, plans, helpers);
    Some(outcome)
}
