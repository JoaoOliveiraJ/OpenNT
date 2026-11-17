//! A sessão do depurador: o protocolo, os breakpoints, a pilha, as
//! expressões e as consultas do OpenNT, com a API tipada que a interface
//! gráfica usa. Os comandos de texto (o prompt do `cargo xtask debug`, o
//! painel de comandos do `opennt-dbg` e os roteiros de teste) ficam em
//! `commands`.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::bugcheck::{self, Analysis};
use super::expr::{self, Environment};
use super::monitor::{self, LoadedModule, Process, Processor, Thread, ThreadContext};
use super::pdb::SymbolStore;
use super::pe::PeImage;
use super::registers::{self, Value};
use super::rsp::{hex, is_timeout, unhex, Connection};
use super::stop::{Reason, StopReply};
use super::symbols::Symbols;
use super::trace::Trace;
use super::types::{self, TypeDb};
use super::unwind::{self, Context, Frame, FunctionTable, ReadMemory, Target};
use super::user::{self, Handle, KernelRange, ProcessContext, Region, UserModule, UserThread};
use super::x86;

/// Quanto o `p` e o `gu` do prompt esperam a chamada voltar.
pub(crate) const RUN_TO_WAIT: Duration = Duration::from_secs(120);

/// Onde o kernel avisa que uma imagem foi carregada (já na lista de
/// módulos): o breakpoint interno das paradas por carga de módulo.
const LOAD_HOOKS: [&str; 3] = ["kernel::ntos::ps::notify::image::notify", "kernel::ntos::mm::pe_loader::notify_loaded", "kernel::ntos::mm::loaded_images::register"];

/// Os pontos de evento do kernel (`kd/events.rs`): criação e saída de
/// processo, de thread e carga de imagem, com os argumentos nos
/// registradores da convenção sysv64.
const PROCESS_EVENT: &str = "opennt_kd_process_event";
const THREAD_EVENT: &str = "opennt_kd_thread_event";
const IMAGE_EVENT: &str = "opennt_kd_image_event";

/// CS do anel 3: a parada foi numa thread de usuário.
const USER_CODE_SELECTOR: u64 = 0x33;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BreakpointKind {
    /// `int 3` gravado no código (Z0).
    Software,
    /// Comparador de execução DR0-DR3 (Z1).
    Hardware,
    /// Vigia de escrita (Z2).
    Write,
    /// Vigia de acesso (Z4).
    Access,
    /// Parada quando um módulo é carregado (`sxe ld:ntfs.sys`).
    Module,
    /// Parada num evento de processo, thread ou imagem de usuário: `cpr`,
    /// `epr` (criação e saída de processo, com `:nome` opcional), `ct`, `et`
    /// (thread, com `:pid` opcional) e `ld:processo!dll` (carga de uma DLL
    /// num processo; `*` vale qualquer processo).
    Event,
    /// Breakpoint de memória por página (`monitor membp`): qualquer acesso,
    /// escrita ou execução numa página do processo, pelo bit reservado da
    /// entrada da tabela de páginas (a proteção que o processo consulta não
    /// muda).
    MemoryAccess,
    MemoryWrite,
    MemoryExecute,
}

impl BreakpointKind {
    fn packet_type(self) -> u8 {
        match self {
            Self::Software | Self::Module | Self::Event | Self::MemoryAccess | Self::MemoryWrite | Self::MemoryExecute => 0,
            Self::Hardware => 1,
            Self::Write => 2,
            Self::Access => 4,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::Hardware => "hardware",
            Self::Write => "escrita",
            Self::Access => "acesso",
            Self::Module => "carga de modulo",
            Self::Event => "evento",
            Self::MemoryAccess => "memoria-acesso",
            Self::MemoryWrite => "memoria-escrita",
            Self::MemoryExecute => "memoria-execucao",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "software" => Self::Software,
            "hardware" => Self::Hardware,
            "escrita" => Self::Write,
            "acesso" => Self::Access,
            "modulo" | "carga de modulo" => Self::Module,
            "evento" => Self::Event,
            "memoria-acesso" => Self::MemoryAccess,
            "memoria-escrita" => Self::MemoryWrite,
            "memoria-execucao" => Self::MemoryExecute,
            _ => return None,
        })
    }

    /// O breakpoint de memória por página (o `membp` do alvo).
    pub fn is_memory(self) -> bool {
        matches!(self, Self::MemoryAccess | Self::MemoryWrite | Self::MemoryExecute)
    }

    /// A letra do `membp` (a, w, x).
    fn memory_letter(self) -> &'static str {
        match self {
            Self::MemoryWrite => "w",
            Self::MemoryExecute => "x",
            _ => "a",
        }
    }

    /// O nome curto do arquivo de sessão.
    fn key(self) -> &'static str {
        match self {
            Self::Module => "modulo",
            other => other.name(),
        }
    }
}

/// O que um breakpoint faz num acerto, além de parar: as opções do editor
/// de breakpoints (nome, condições de log e de comando, uma vez só, sem
/// a linha de acerto no log e o retorno rápido).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BreakpointOptions {
    pub name: String,
    /// O log só sai quando esta condição der diferente de zero (vazia =
    /// sempre).
    pub log_condition: String,
    /// Os comandos só rodam quando esta condição der diferente de zero
    /// (vazia = quando o breakpoint para).
    pub command_condition: String,
    /// Some depois da primeira parada.
    pub single_shot: bool,
    /// Sem a linha `[bp #n] acerto` no log.
    pub silent: bool,
    /// Quando não para, segue na hora: sem reler os módulos nem a linha de
    /// acerto.
    pub fast_resume: bool,
}

/// Um breakpoint do cliente: desligado, continua na lista mas sai do alvo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Breakpoint {
    pub id: u32,
    pub kind: BreakpointKind,
    pub address: u64,
    pub length: u64,
    pub enabled: bool,
    /// Como o usuário o pediu (símbolo, expressão ou nome do módulo).
    pub expression: String,
    /// Só para quando a condição der diferente de zero (vazia = sempre).
    pub condition: String,
    /// Para a partir do N-ésimo acerto (0 e 1 = no primeiro).
    pub pass_count: u64,
    pub hits: u64,
    /// O símbolo é de um módulo ainda não carregado: é armado quando ele
    /// aparecer (o `bu` do WinDbg).
    pub pending: bool,
    /// Breakpoint de log: o texto (com `{expr}`) vai ao console e a máquina
    /// segue sem parar.
    pub log: String,
    /// Comandos (separados por `;`) executados quando ele para.
    pub command: String,
    /// O grupo (ligar e desligar juntos).
    pub group: String,
    /// O EPROCESS do processo dono de um breakpoint de usuário (0 = o espaço
    /// do processador).
    pub process: u64,
    pub options: BreakpointOptions,
}

/// O que pedir num breakpoint novo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BreakpointRequest {
    pub kind: BreakpointKind,
    pub expression: String,
    pub length: u64,
    pub condition: String,
    pub pass_count: u64,
    /// Aceita um símbolo que ainda não existe.
    pub deferred: bool,
    pub enabled: bool,
    pub log: String,
    pub command: String,
    pub group: String,
    /// O EPROCESS dono (0 = o processo escolhido no momento, se houver).
    pub process: u64,
    pub options: BreakpointOptions,
}

impl BreakpointRequest {
    pub fn new(kind: BreakpointKind, expression: &str) -> Self {
        // Um breakpoint de memória cobre as páginas de [endereço, endereço +
        // tamanho): com 1, a página do endereço.
        let length = match kind {
            BreakpointKind::Write | BreakpointKind::Access => 8,
            _ => 1,
        };
        Self { kind, expression: expression.trim().to_string(), length, condition: String::new(), pass_count: 0, deferred: false, enabled: true, log: String::new(), command: String::new(), group: String::new(), process: 0, options: BreakpointOptions::default() }
    }
}

/// O passo por cima ou para fora em andamento: o breakpoint temporário no
/// retorno e o RSP que o processador terá ao voltar (uma parada no mesmo
/// endereço com outro RSP é de uma recursão mais funda ou de outra thread,
/// e a máquina segue).
struct RunTo {
    address: u64,
    /// O breakpoint é só deste passo (não havia um do usuário ali).
    inserted: bool,
    /// `None`: qualquer RSP serve (o "rodar até aqui").
    expected_rsp: Option<u64>,
}

/// Como a máquina ficou depois de um passo por cima ou para fora.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resumed {
    /// O passo terminou na hora (a instrução não era um `call`).
    Stopped(String),
    /// A máquina roda até o retorno; a parada chega por `wait_stop`/`poll`.
    Running,
}

/// O que fazer com uma parada num breakpoint.
enum Hit {
    None,
    Continue,
    Stop(String),
}

pub struct Client {
    connection: Connection,
    pub symbols: Symbols,
    pub(crate) root: PathBuf,
    elf: PathBuf,
    stopped: bool,
    pub(crate) last_stop: String,
    stop: Option<StopReply>,
    pub(crate) variables: HashMap<String, u64>,
    /// Saída do DbgPrint recebida na sessão inteira.
    pub(crate) console: String,
    /// A parte que a interface ainda não pegou (`take_console`).
    unread_console: String,
    pub(crate) timeout: Duration,
    /// Saída da COM1 (o log do kernel), quando o cliente roda junto com o
    /// teste.
    pub(crate) serial: Option<Arc<Mutex<String>>>,
    pub(crate) breakpoints: Vec<Breakpoint>,
    next_breakpoint: u32,
    run_to: Option<RunTo>,
    /// O pacote `g` da parada corrente, do processador escolhido.
    registers: Option<String>,
    /// Thread do protocolo escolhida por `Hg` (`None` = o dono da parada).
    selected: Option<u64>,
    /// Os tipos do PDB do ntoskrnl (carregados na primeira vista tipada).
    types: Option<Arc<TypeDb>>,
    pub types_note: String,
    /// Tabelas de funções lidas da memória do alvo (módulos sem arquivo
    /// nesta máquina), pela geração dos símbolos.
    function_tables: HashMap<u64, Option<Arc<FunctionTable>>>,
    tables_generation: u64,
    /// O breakpoint interno na notificação de carga de imagem e se foi o
    /// cliente que o gravou.
    load_hook: Option<(u64, bool)>,
    /// Os módulos já vistos (as paradas por carga de módulo só valem para os
    /// novos).
    known_modules: HashSet<String>,
    /// Um rastro em andamento: as paradas não seguem sozinhas.
    pub(crate) tracing: bool,
    /// O último rastro e o de referência (a comparação).
    pub trace: Option<Trace>,
    pub reference: Option<Trace>,
    /// O processo das leituras (`.process`), reaplicado a cada parada.
    pub(crate) process_context: Option<ProcessContext>,
    /// Os breakpoints internos nos pontos de evento: (endereço, símbolo, o
    /// cliente o gravou).
    event_hooks: Vec<(u64, &'static str, bool)>,
    /// Saída dos breakpoints de log e dos comandos de parada.
    pub(crate) log_lines: Vec<String>,
    /// Os comandos do breakpoint que parou a máquina (a condição de comando
    /// já conferida).
    pending_commands: Option<(u32, String)>,
    /// O breakpoint de uma vez só que acabou de parar (sai no fim da
    /// parada).
    single_shot: Option<u32>,
}

impl ReadMemory for Client {
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
        self.read_memory(address, length)
    }
}

impl Target for Client {
    fn function_table(&mut self, address: u64) -> Option<Arc<FunctionTable>> {
        if self.tables_generation != self.symbols.generation {
            self.function_tables.clear();
            self.tables_generation = self.symbols.generation;
        }
        let module = self.symbols.module_at(address)?;
        if self.symbols.is_kernel(module) {
            return None;
        }
        if let Some(table) = &module.unwind {
            return Some(Arc::clone(table));
        }
        let base = module.base;
        if let Some(cached) = self.function_tables.get(&base) {
            return cached.clone();
        }
        let table = self.read_function_table(base);
        self.function_tables.insert(base, table.clone());
        table
    }
}

impl Environment for Client {
    fn register(&mut self, name: &str) -> Result<u64, String> {
        Client::register(self, name)
    }

    fn read_memory(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
        Client::read_memory(self, address, length)
    }

    fn symbol(&mut self, name: &str) -> Result<u64, String> {
        self.symbols.lookup(name)
    }

    fn variable(&mut self, name: &str) -> Option<u64> {
        self.variables.get(name).copied()
    }

    fn is_register(&self, name: &str) -> bool {
        registers::find(name).is_some()
    }

    fn types(&mut self) -> Option<Arc<TypeDb>> {
        self.type_database()
    }

    fn image_entry(&mut self, module: &str) -> Result<u64, String> {
        let base = match super::parse_number(module) {
            Some(address) => self.symbols.module_at(address).map(|module| module.base).ok_or_else(|| format!("{address:#x} fora dos modulos"))?,
            None => self.symbols.module_named(module).map(|module| module.base).ok_or_else(|| format!("modulo {module} nao carregado"))?,
        };
        if let Some(image) = self.symbols.module_at(base).and_then(|module| module.image.clone()) {
            return Ok(base + image.header.entry_point as u64);
        }
        let header = self.read_memory(base, 0x400)?;
        let image = PeImage::parse_mapped(header).ok_or_else(|| format!("{base:#x}: cabecalho PE ilegivel"))?;
        Ok(base + image.header.entry_point as u64)
    }
}

impl Client {
    pub fn new(connection: Connection, root: PathBuf, elf: PathBuf) -> Self {
        Self {
            connection,
            symbols: Symbols::default(),
            root,
            elf,
            stopped: false,
            last_stop: String::new(),
            stop: None,
            variables: HashMap::new(),
            console: String::new(),
            unread_console: String::new(),
            timeout: Duration::from_secs(20),
            serial: None,
            breakpoints: Vec::new(),
            next_breakpoint: 0,
            run_to: None,
            registers: None,
            selected: None,
            types: None,
            types_note: String::new(),
            function_tables: HashMap::new(),
            tables_generation: 0,
            load_hook: None,
            known_modules: HashSet::new(),
            tracing: false,
            trace: None,
            reference: None,
            process_context: None,
            event_hooks: Vec::new(),
            log_lines: Vec::new(),
            pending_commands: None,
            single_shot: None,
        }
    }

    /// A saída da COM1 para o `wait-serial` do roteiro.
    pub fn set_serial(&mut self, serial: Arc<Mutex<String>>) {
        self.serial = Some(serial);
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// A descrição da última parada.
    pub fn last_stop(&self) -> &str {
        &self.last_stop
    }

    pub fn stop_reply(&self) -> Option<&StopReply> {
        self.stop.as_ref()
    }

    /// A thread do protocolo escolhida (`None` = o dono da parada).
    pub fn selected_thread(&self) -> Option<u64> {
        self.selected
    }

    /// Toda a saída do DbgPrint da sessão.
    pub fn console(&self) -> &str {
        &self.console
    }

    /// A saída do DbgPrint que chegou desde a última chamada.
    pub fn take_console(&mut self) -> String {
        self.collect_console();
        std::mem::take(&mut self.unread_console)
    }

    pub fn breakpoints(&self) -> &[Breakpoint] {
        &self.breakpoints
    }

    pub(crate) fn collect_console(&mut self) {
        let text = self.connection.take_console();
        if !text.is_empty() {
            self.console.push_str(&text);
            self.unread_console.push_str(&text);
        }
    }

    pub(crate) fn request(&mut self, payload: &str) -> Result<String, String> {
        let reply = self.connection.request(payload, self.timeout);
        self.collect_console();
        reply
    }

    fn describe_stop(&mut self, stop: &StopReply) -> String {
        let rip = self.register("rip").ok();
        let location = rip.map(|rip| format!(" em {:#x} {}", rip, self.symbols.describe(rip))).unwrap_or_default();
        let processor = stop.processor().map(|number| format!(" (CPU {number})")).unwrap_or_default();
        format!("parado: {} {}{processor}{location}", stop.signal_name(), stop.reason_text())
    }

    /// Uma resposta de parada chegou. `None` quando o próprio cliente
    /// mandou a máquina seguir (o breakpoint do passo por cima atingido numa
    /// recursão mais funda ou por outra thread, um breakpoint condicional
    /// falso, a carga de um módulo que ninguém pediu).
    fn on_stop(&mut self, packet: String) -> Result<Option<String>, String> {
        let stop = StopReply::parse(&packet).ok_or_else(|| format!("resposta de parada inesperada: {packet:?}"))?;
        self.stopped = true;
        self.registers = None;
        // Uma parada nova é do dono dela: as leituras voltam para ele.
        if self.selected.take().is_some() {
            let _ = self.request("Hg0");
        }
        // Parada numa thread de usuário: o processo dela passa a ser o das
        // leituras; senão o escolhido antes volta (o alvo o esquece a cada
        // continuação).
        if self.register("cs").ok() == Some(USER_CODE_SELECTOR) {
            if let Ok(text) = self.monitor(".process") {
                if let Some((eprocess, _)) = user::parse_current_process(&text) {
                    let _ = self.set_process(Some(&format!("{eprocess:#x}")));
                }
            }
        } else if let Some(context) = self.process_context.clone() {
            let _ = self.monitor(&format!(".process {:#x}", context.eprocess));
        }
        if let Some(run_to) = self.run_to.take() {
            let at_target = self.register("rip").ok() == Some(run_to.address) && stop.reasons.contains(&Reason::SoftwareBreak);
            if at_target && run_to.expected_rsp.is_some() && self.register("rsp").ok() != run_to.expected_rsp {
                self.run_to = Some(run_to);
                self.resume("c")?;
                return Ok(None);
            }
            if run_to.inserted && !self.hook_at(run_to.address) {
                let _ = self.request(&format!("z0,{:x},1", run_to.address));
            }
        }
        self.pending_commands = None;
        // Módulos carregados desde a última parada entram nos símbolos (a
        // primeira parada, a do attach, ainda não tem o ELF carregado). Um
        // breakpoint de retorno rápido não espera essa releitura.
        let fast = stop.reasons.contains(&Reason::SoftwareBreak) && self.register("rip").is_ok_and(|rip| self.fast_resume_at(rip));
        if !self.symbols.modules.is_empty() && !fast {
            let _ = self.reload_modules();
        }
        let mut note = String::new();
        if !self.tracing {
            match self.check_hit(&stop) {
                Hit::Continue => {
                    self.resume("c")?;
                    return Ok(None);
                }
                Hit::Stop(text) => note = text,
                Hit::None => {}
            }
        }
        if let Some(id) = self.single_shot.take() {
            if self.remove_breakpoint(id).is_ok() {
                note.push_str(" (breakpoint de uma vez so removido)");
            }
        }
        self.last_stop = format!("{}{note} [{}]", self.describe_stop(&stop), packet);
        self.stop = Some(stop);
        Ok(Some(self.last_stop.clone()))
    }

    /// O breakpoint interno de carga está neste endereço.
    fn hook_at(&self, address: u64) -> bool {
        self.load_hook.is_some_and(|(hook, _)| hook == address)
    }

    /// Os módulos novos desde a última consulta (nomes de arquivo).
    fn new_modules(&mut self) -> Vec<String> {
        let mut fresh = Vec::new();
        for module in &self.symbols.modules {
            let key = module.file_name.to_ascii_lowercase();
            if self.known_modules.insert(key) {
                fresh.push(module.file_name.clone());
            }
        }
        fresh
    }

    /// Uma parada num breakpoint: contagem, condição, carga de módulo.
    fn check_hit(&mut self, stop: &StopReply) -> Hit {
        let Ok(rip) = self.register("rip") else { return Hit::None };
        let software = stop.reasons.contains(&Reason::SoftwareBreak);
        if software {
            if let Some(&(_, symbol, _)) = self.event_hooks.iter().find(|(address, _, _)| *address == rip) {
                let user_here = self.breakpoints.iter().any(|breakpoint| breakpoint.enabled && breakpoint.kind == BreakpointKind::Software && breakpoint.address == rip);
                return match self.check_event(symbol) {
                    Some(text) => Hit::Stop(text),
                    None if user_here => Hit::None,
                    None => Hit::Continue,
                };
            }
        }
        if software && self.hook_at(rip) {
            let fresh = self.new_modules();
            self.resolve_pending();
            let matches = |wanted: &str, file: &str| {
                let (wanted, file) = (wanted.to_ascii_lowercase(), file.to_ascii_lowercase());
                file == wanted || file.rsplit_once('.').is_some_and(|(stem, _)| stem == wanted)
            };
            let mut loaded = Vec::new();
            for breakpoint in self.breakpoints.iter_mut().filter(|breakpoint| breakpoint.enabled && breakpoint.kind == BreakpointKind::Module) {
                if let Some(file) = fresh.iter().find(|file| matches(&breakpoint.expression, file)) {
                    breakpoint.hits += 1;
                    loaded.push((breakpoint.id, file.clone()));
                }
            }
            let _ = self.update_load_hook();
            if let Some((id, file)) = loaded.first() {
                let base = self.symbols.module_named(file).map(|module| module.base).unwrap_or(0);
                return Hit::Stop(format!(" (modulo carregado: {file} em {base:#x}, breakpoint #{id})"));
            }
            let user_here = self.breakpoints.iter().any(|breakpoint| breakpoint.enabled && breakpoint.kind == BreakpointKind::Software && breakpoint.address == rip);
            if !user_here {
                return Hit::Continue;
            }
        }
        let watched = stop.reasons.iter().find_map(|reason| match reason {
            Reason::Watch { address, .. } => Some(*address),
            _ => None,
        });
        let memory = stop.reasons.iter().find_map(|reason| match reason {
            Reason::Memory { address } => Some(*address),
            _ => None,
        });
        let hardware = stop.reasons.contains(&Reason::HardwareBreak);
        let index = self.breakpoints.iter().position(|breakpoint| {
            breakpoint.enabled
                && !breakpoint.pending
                && match breakpoint.kind {
                    BreakpointKind::Software => software && breakpoint.address == rip,
                    BreakpointKind::Hardware => hardware && memory.is_none() && breakpoint.address == rip,
                    BreakpointKind::Write | BreakpointKind::Access => memory.is_none() && watched == Some(breakpoint.address),
                    BreakpointKind::MemoryAccess | BreakpointKind::MemoryWrite | BreakpointKind::MemoryExecute => memory.is_some_and(|address| address >= breakpoint.address && address < breakpoint.address + breakpoint.length.max(1)),
                    BreakpointKind::Module | BreakpointKind::Event => false,
                }
        });
        let Some(index) = index else {
            // Um acesso à página vigiada fora da faixa pedida: segue.
            if memory.is_some() && self.breakpoints.iter().any(|breakpoint| breakpoint.enabled && breakpoint.kind.is_memory()) {
                return Hit::Continue;
            }
            return Hit::None;
        };
        self.breakpoints[index].hits += 1;
        let breakpoint = self.breakpoints[index].clone();
        if breakpoint.pass_count > 1 && breakpoint.hits < breakpoint.pass_count {
            return Hit::Continue;
        }
        let options = breakpoint.options.clone();
        let label = if options.name.is_empty() { format!("#{}", breakpoint.id) } else { format!("#{} {}", breakpoint.id, options.name) };
        let mut text = format!(" (breakpoint {label}, acerto {})", breakpoint.hits);
        // A condição de parada; sem ela, um breakpoint com log só registra
        // (o `/log` do prompt).
        let stop_now = if breakpoint.condition.trim().is_empty() {
            breakpoint.log.trim().is_empty()
        } else {
            match self.evaluate(&breakpoint.condition) {
                Ok(0) => false,
                Ok(_) => {
                    text = format!(" (breakpoint {label}, condicao verdadeira, acerto {})", breakpoint.hits);
                    true
                }
                Err(error) => return Hit::Stop(format!(" (breakpoint {label}: erro na condicao: {error})")),
            }
        };
        let condition_true = |client: &mut Client, condition: &str, default: bool| if condition.trim().is_empty() { default } else { client.evaluate(condition).map(|value| value != 0).unwrap_or(true) };
        if !breakpoint.log.trim().is_empty() && condition_true(self, &options.log_condition, true) {
            let line = format!("[bp {label}] {}", self.format_log(&breakpoint.log));
            self.push_log(line);
        }
        let run_commands = !breakpoint.command.trim().is_empty() && condition_true(self, &options.command_condition, stop_now);
        if !stop_now {
            if run_commands {
                self.run_hit_commands(breakpoint.id, &breakpoint.command);
            }
            if !options.silent && !options.fast_resume && breakpoint.log.trim().is_empty() {
                let line = format!("[bp {label}] acerto {} em {:#x} {} (segue)", breakpoint.hits, rip, self.symbols.describe(rip));
                self.push_log(line);
            }
            return Hit::Continue;
        }
        if !options.silent {
            let line = format!("[bp {label}] acerto {} em {:#x} {}", breakpoint.hits, rip, self.symbols.describe(rip));
            self.push_log(line);
        }
        if run_commands {
            self.pending_commands = Some((breakpoint.id, breakpoint.command.clone()));
        }
        if options.single_shot {
            self.single_shot = Some(breakpoint.id);
        }
        Hit::Stop(text)
    }

    /// Os comandos de um acerto que não para: rodam aqui mesmo (os que
    /// fariam a máquina seguir ficam de fora), com a saída no log.
    fn run_hit_commands(&mut self, id: u32, commands: &str) {
        for command in commands.split(';').map(str::trim).filter(|command| !command.is_empty()) {
            let word = command.split_whitespace().next().unwrap_or("");
            if matches!(word, "g" | "c" | "continue" | "p" | "t" | "s" | "step" | "gu" | "trace" | "detach" | "q" | "quit") {
                continue;
            }
            let output = match self.execute(command) {
                Ok(text) => text,
                Err(error) => format!("erro: {error}"),
            };
            self.push_log(format!("[bp #{id}] > {command}\n{}", output.trim_end()));
        }
    }

    /// Um breakpoint de software ligado em `address` com o retorno rápido.
    fn fast_resume_at(&self, address: u64) -> bool {
        !self.hook_at(address) && !self.event_hooks.iter().any(|(hook, _, _)| *hook == address) && self.breakpoints.iter().any(|breakpoint| breakpoint.enabled && breakpoint.kind == BreakpointKind::Software && breakpoint.address == address && breakpoint.options.fast_resume)
    }

    /// Um texto de breakpoint de log: cada `{expr}` vira o valor (`{expr:d}`
    /// em decimal, `{expr:s}` o símbolo).
    pub fn format_log(&mut self, format: &str) -> String {
        let mut output = String::new();
        let mut rest = format;
        while let Some(open) = rest.find('{') {
            output.push_str(&rest[..open]);
            let Some(close) = rest[open..].find('}') else {
                output.push_str(&rest[open..]);
                return output;
            };
            let inner = &rest[open + 1..open + close];
            let (expression, style) = match inner.rsplit_once(':') {
                Some((expression, style)) if matches!(style, "x" | "d" | "s") => (expression, style),
                _ => (inner, "x"),
            };
            match self.evaluate(expression) {
                Ok(value) => match style {
                    "d" => output.push_str(&(value as i64).to_string()),
                    "s" => output.push_str(&self.symbols.describe(value)),
                    _ => output.push_str(&format!("{value:#x}")),
                },
                Err(error) => output.push_str(&format!("<{error}>")),
            }
            rest = &rest[open + close + 1..];
        }
        output.push_str(rest);
        output
    }

    /// Uma linha de log (breakpoint de log, comando de parada) no console.
    pub(crate) fn push_log(&mut self, line: String) {
        self.console.push_str(&line);
        self.console.push('\n');
        self.unread_console.push_str(&line);
        self.unread_console.push('\n');
        self.log_lines.push(line);
    }

    /// As linhas dos breakpoints de log da sessão.
    pub fn log_lines(&self) -> &[String] {
        &self.log_lines
    }

    /// Um evento de processo, thread ou imagem: o texto da parada se algum
    /// breakpoint de evento o pede.
    fn check_event(&mut self, symbol: &str) -> Option<String> {
        let read = |client: &mut Client, name: &str| client.register(name).unwrap_or(0);
        let (rdi, rsi, rdx, rcx, r8) = (read(self, "rdi"), read(self, "rsi"), read(self, "rdx"), read(self, "rcx"), read(self, "r8"));
        let processes = self.processes().unwrap_or_default();
        let name_of_pid = |pid: u64| processes.iter().find(|process| process.pid == pid).map(|process| process.name.clone()).unwrap_or_default();
        let same_process = |wanted: &str, name: &str| {
            let (wanted, name) = (wanted.to_ascii_lowercase(), name.to_ascii_lowercase());
            wanted.is_empty() || wanted == "*" || wanted == name || name.strip_suffix(".exe") == Some(wanted.as_str())
        };
        let ((code, subject), description) = match symbol {
            PROCESS_EVENT => {
                let name = processes.iter().find(|process| process.eprocess == rdi).map(|process| process.name.clone()).unwrap_or_else(|| name_of_pid(rsi));
                let created = rdx != 0;
                ((if created { "cpr" } else { "epr" }, name.clone()), format!("processo {} {name} (PID {rsi}, EPROCESS {rdi:#x})", if created { "criado" } else { "saindo" }))
            }
            THREAD_EVENT => {
                let exiting = rdx == 2;
                ((if exiting { "et" } else { "ct" }, rdi.to_string()), format!("thread {} TID {rsi} no PID {rdi} ({})", if exiting { "saindo" } else { "criada" }, name_of_pid(rdi)))
            }
            _ => {
                let bytes = if rcx != 0 && r8 > 0 && r8 < 0x1000 { self.read_memory(rcx, r8 as usize).unwrap_or_default() } else { Vec::new() };
                let path = String::from_utf8_lossy(&bytes).to_string();
                let process = if rdx == 0 { "System".to_string() } else { name_of_pid(rdx) };
                (("ld", format!("{process}!{}", super::symbols::base_name(&path))), format!("imagem {path} em {rdi:#x} (tamanho {rsi:#x}) no processo {process} (PID {rdx})"))
            }
        };
        let mut matched = None;
        for breakpoint in self.breakpoints.iter_mut().filter(|breakpoint| breakpoint.enabled && breakpoint.kind == BreakpointKind::Event) {
            let (wanted_code, wanted) = breakpoint.expression.split_once(':').map_or((breakpoint.expression.as_str(), ""), |(code, rest)| (code, rest));
            if !wanted_code.eq_ignore_ascii_case(code) {
                continue;
            }
            let hit = match code {
                "ld" => {
                    let (wanted_process, wanted_dll) = wanted.split_once('!').unwrap_or(("*", wanted));
                    let (process, dll) = subject.split_once('!').unwrap_or(("", subject.as_str()));
                    let dll = dll.to_ascii_lowercase();
                    let wanted_dll = wanted_dll.to_ascii_lowercase();
                    same_process(wanted_process, process) && (wanted_dll.is_empty() || dll == wanted_dll || dll.strip_suffix(".dll") == Some(wanted_dll.as_str()))
                }
                "cpr" | "epr" => same_process(wanted, &subject),
                _ => wanted.is_empty() || wanted == subject,
            };
            if hit {
                breakpoint.hits += 1;
                matched.get_or_insert((breakpoint.id, breakpoint.log.clone()));
            }
        }
        let (id, log) = matched?;
        if !log.trim().is_empty() {
            let line = format!("[evento #{id}] {description} {}", self.format_log(&log));
            self.push_log(line);
            return None;
        }
        // Uma DLL nova num processo: os módulos dele entram nos símbolos.
        if code == "ld" && rdx != 0 {
            if let Some(process) = processes.iter().find(|process| process.pid == rdx) {
                let _ = self.set_process(Some(&format!("{:#x}", process.eprocess)));
            }
        }
        Some(format!(" (evento #{id}: {description})"))
    }

    /// Negocia a sessão: o primeiro pacote para a máquina (o depurador do
    /// alvo para quando um pacote chega com ela rodando).
    pub fn attach(&mut self, timeout: Duration) -> Result<String, String> {
        let supported = self.connection.request("qSupported:swbreak+;hwbreak+;vContSupported+", timeout)?;
        self.collect_console();
        if supported.contains("QStartNoAckMode+") && self.request("QStartNoAckMode")? == "OK" {
            self.connection.set_no_ack();
        }
        let stop = self.request("?")?;
        let mut output = format!("sessao: {supported}\n");
        let shown = self.elf.strip_prefix(&self.root).unwrap_or(&self.elf).display().to_string();
        match self.symbols.load_kernel(&self.elf) {
            Ok(count) => output.push_str(&format!("simbolos do kernel: {count} ({shown})\n")),
            Err(error) => output.push_str(&format!("sem os simbolos do kernel: {error}\n")),
        }
        let description = self.on_stop(stop)?.unwrap_or_default();
        output.push_str(&description);
        self.reload_modules()?;
        self.new_modules();
        Ok(output)
    }

    /// Lê a lista de módulos do alvo e os símbolos de cada um.
    pub fn reload_modules(&mut self) -> Result<(), String> {
        let list: Vec<(u64, u64, String)> = self.loaded_modules()?.into_iter().map(|module| (module.base, module.end, module.path)).collect();
        self.symbols.set_modules(&list, &self.root);
        Ok(())
    }

    pub(crate) fn require_stopped(&self) -> Result<(), String> {
        if self.stopped {
            Ok(())
        } else {
            Err("a maquina esta rodando (use break)".into())
        }
    }

    /// Comando do OpenNT no alvo: a resposta chega em pacotes `O` antes do
    /// `OK` (com a máquina parada não há DbgPrint misturado).
    pub fn monitor(&mut self, command: &str) -> Result<String, String> {
        self.require_stopped()?;
        self.collect_console();
        let reply = self.connection.request(&format!("qRcmd,{}", hex(command.as_bytes())), self.timeout)?;
        let text = self.connection.take_console();
        if reply != "OK" {
            return Err(format!("monitor {command}: {reply}"));
        }
        Ok(text)
    }

    pub fn processes(&mut self) -> Result<Vec<Process>, String> {
        Ok(monitor::processes(&self.monitor("ps")?))
    }

    pub fn threads(&mut self, pid: Option<u64>) -> Result<Vec<Thread>, String> {
        let command = pid.map_or("threads".to_string(), |pid| format!("threads {pid}"));
        Ok(monitor::threads(&self.monitor(&command)?))
    }

    pub fn loaded_modules(&mut self) -> Result<Vec<LoadedModule>, String> {
        Ok(monitor::modules(&self.monitor("lm")?))
    }

    pub fn processors(&mut self) -> Result<Vec<Processor>, String> {
        Ok(monitor::processors(&self.monitor("cpus")?))
    }

    /// Os registradores de uma thread (`monitor context`).
    pub fn thread_context(&mut self, thread: u64) -> Result<ThreadContext, String> {
        let text = self.monitor(&format!("context {thread:x}"))?;
        monitor::thread_context(&text).ok_or_else(|| format!("contexto de {thread:#x}: {}", text.trim()))
    }

    /// Os registradores gerais do processador escolhido.
    pub fn general_registers(&mut self) -> Result<Vec<Value>, String> {
        self.require_stopped()?;
        if self.registers.is_none() {
            let reply = self.request("g")?;
            if reply.starts_with('E') {
                return Err(format!("registradores: {reply}"));
            }
            self.registers = Some(reply);
        }
        registers::parse_general(self.registers.as_deref().unwrap_or(""))
    }

    /// Um registrador pelo nome (os gerais pelo `g`, FS_BASE e GS_BASE pelo
    /// `p`).
    pub fn register(&mut self, name: &str) -> Result<u64, String> {
        let layout = registers::find(name).ok_or_else(|| format!("registrador desconhecido: {name}"))?;
        if layout.number < registers::GENERAL.len() {
            return self.general_registers()?[layout.number].value.ok_or_else(|| format!("{name} indisponivel"));
        }
        self.require_stopped()?;
        let reply = self.request(&format!("p{:x}", layout.number))?;
        if reply.starts_with('E') || reply.is_empty() {
            return Err(format!("{name}: {reply}"));
        }
        registers::parse_little_endian(&reply).ok_or_else(|| format!("{name} indisponivel"))
    }

    /// O x87, o SSE, a metade alta dos YMM e os registradores de depuração
    /// do processador escolhido (os do `g` e as extensões do OpenNT por
    /// `p`; o que o alvo não tem fica `None`).
    pub fn extended_registers(&mut self) -> Result<registers::ExtendedState, String> {
        self.general_registers()?;
        let mut state = registers::parse_extended(self.registers.as_deref().unwrap_or(""));
        let read = |client: &mut Client, number: usize| -> Option<Vec<u8>> {
            let reply = client.request(&format!("p{number:x}")).ok()?;
            (!reply.is_empty() && !reply.starts_with('E') && !reply.contains('x')).then(|| unhex(&reply))
        };
        // Sem resposta ao primeiro YMM (alvo sem a extensão ou sem AVX), os
        // outros nem são pedidos.
        if let Some(first) = read(self, registers::YMM_HIGH_FIRST) {
            state.ymm_high[0] = first.try_into().ok();
            for index in 1..16 {
                state.ymm_high[index] = read(self, registers::YMM_HIGH_FIRST + index).and_then(|bytes| bytes.try_into().ok());
            }
        }
        for (index, layout) in registers::DEBUG.iter().enumerate() {
            state.debug[index] = read(self, layout.number).map(|bytes| {
                let mut value = [0u8; 8];
                value[..bytes.len().min(8)].copy_from_slice(&bytes[..bytes.len().min(8)]);
                u64::from_le_bytes(value)
            });
        }
        Ok(state)
    }

    /// Grava bytes num registrador pelo número do protocolo (XMM, ST).
    pub fn write_register_bytes(&mut self, number: usize, bytes: &[u8]) -> Result<(), String> {
        self.require_stopped()?;
        let reply = self.request(&format!("P{number:x}={}", hex(bytes)))?;
        self.registers = None;
        if reply == "OK" {
            Ok(())
        } else {
            Err(format!("registrador {number}: {reply}"))
        }
    }

    /// Grava um registrador do processador escolhido.
    pub fn write_register(&mut self, name: &str, value: u64) -> Result<(), String> {
        self.require_stopped()?;
        let layout = registers::find(name).ok_or_else(|| format!("registrador desconhecido: {name}"))?;
        let reply = self.request(&registers::write_packet(layout, value))?;
        self.registers = None;
        if reply == "OK" {
            Ok(())
        } else {
            Err(format!("{name}: {reply}"))
        }
    }

    pub fn read_memory(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
        self.require_stopped()?;
        let mut bytes = Vec::with_capacity(length);
        while bytes.len() < length {
            let chunk = (length - bytes.len()).min(0x400);
            let reply = self.request(&format!("m{:x},{:x}", address + bytes.len() as u64, chunk))?;
            if reply.starts_with('E') || reply.is_empty() {
                if bytes.is_empty() {
                    return Err(format!("memoria em {address:#x} inacessivel ({reply})"));
                }
                break;
            }
            let data = unhex(&reply);
            let short = data.len() < chunk;
            bytes.extend_from_slice(&data);
            if short {
                break;
            }
        }
        Ok(bytes)
    }

    pub fn write_memory(&mut self, address: u64, bytes: &[u8]) -> Result<(), String> {
        self.require_stopped()?;
        let reply = self.request(&format!("M{:x},{:x}:{}", address, bytes.len(), hex(bytes)))?;
        if reply == "OK" {
            Ok(())
        } else {
            Err(format!("escrita em {address:#x}: {reply}"))
        }
    }

    pub fn read_integer(&mut self, address: u64, size: usize) -> Result<u64, String> {
        let bytes = self.read_memory(address, size)?;
        if bytes.len() < size {
            return Err(format!("memoria em {address:#x} inacessivel"));
        }
        let mut value = [0u8; 8];
        value[..size].copy_from_slice(&bytes[..size]);
        Ok(u64::from_le_bytes(value))
    }

    /// Avalia uma expressão (`expr`): o número.
    pub fn evaluate(&mut self, expression: &str) -> Result<u64, String> {
        expr::evaluate_number(self, expression)
    }

    /// Avalia uma expressão com o tipo (a janela de observação).
    pub fn evaluate_value(&mut self, expression: &str) -> Result<expr::Value, String> {
        expr::evaluate(self, expression)
    }

    /// Os tipos, se já carregados (sem tentar carregar).
    pub fn type_database_loaded(&self) -> Option<Arc<TypeDb>> {
        self.types.clone()
    }

    /// Os tipos do PDB do ntoskrnl: do cache (`build/symbols/ntkrnlmp.pdb`);
    /// ausente, o download começa e a próxima tentativa os acha.
    pub fn type_database(&mut self) -> Option<Arc<TypeDb>> {
        if let Some(types) = &self.types {
            return Some(Arc::clone(types));
        }
        let store = self.symbols.store.clone().unwrap_or_else(|| SymbolStore::new(&self.root));
        let path = store.path("ntkrnlmp.pdb");
        if path.is_file() {
            match TypeDb::load(&path) {
                Ok(types) => {
                    self.types_note = format!("tipos de {}", path.display());
                    self.types = Some(Arc::new(types));
                }
                Err(error) => self.types_note = format!("tipos: {error}"),
            }
            return self.types.clone();
        }
        // O GUID e a idade do PDB de onde as estruturas do kernel saem.
        let config = std::fs::read_to_string(self.root.join("kernel/src/ntos/inc/types/nt_types.toml")).unwrap_or_default();
        let field = |key: &str| config.lines().find_map(|line| line.trim().strip_prefix(key).and_then(|rest| rest.trim().strip_prefix('=')).map(|value| value.trim().trim_matches('"').to_string()));
        match (field("pdb_guid"), field("pdb_age").and_then(|age| age.parse::<u32>().ok())) {
            (Some(guid), Some(age)) if store.download => {
                if store.fetch_state("ntkrnlmp.pdb").is_none() {
                    let destination = path.clone();
                    let server = store.server.clone();
                    std::thread::spawn(move || {
                        let _ = super::pdb::download(&server, "ntkrnlmp.pdb", &guid, age, &destination);
                    });
                }
                self.types_note = "baixando o PDB do ntoskrnl (tente de novo em alguns segundos)".into();
            }
            _ => self.types_note = format!("sem os tipos: {} ausente", path.display()),
        }
        None
    }

    /// Os campos de um tipo em `address` (com o símbolo dos ponteiros).
    pub fn typed_fields(&mut self, ty: u32, address: u64) -> Result<Vec<types::Field>, String> {
        let database = self.type_database().ok_or_else(|| self.types_note.clone())?;
        let mut fields = database.fields(self, ty, address, &|_| None);
        for field in &mut fields {
            if let (Some(number), types::Kind::Pointer { .. }) = (field.number, database.kind(field.ty)) {
                if let Some(name) = self.symbols.name_at(number) {
                    field.value = format!("{} {name}", field.value);
                }
            }
        }
        Ok(fields)
    }

    /// Espera a próxima parada (o passo por cima que segue sozinho não
    /// conta).
    pub fn wait_stop(&mut self, timeout: Duration) -> Result<String, String> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("tempo esgotado esperando a parada (a maquina segue rodando; use break)".into());
            }
            if let Some(stop) = self.poll(remaining.min(Duration::from_millis(500)))? {
                return Ok(stop);
            }
        }
    }

    /// Com a máquina rodando, recolhe a saída do DbgPrint e uma parada que
    /// tenha chegado dentro do prazo.
    pub fn poll(&mut self, timeout: Duration) -> Result<Option<String>, String> {
        if self.stopped {
            return Ok(None);
        }
        match self.connection.receive(timeout) {
            Ok(packet) => {
                self.collect_console();
                self.on_stop(packet)
            }
            Err(error) if is_timeout(&error) => {
                self.collect_console();
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn resume(&mut self, packet: &str) -> Result<(), String> {
        self.require_stopped()?;
        self.connection.send(packet, self.timeout)?;
        self.stopped = false;
        self.registers = None;
        Ok(())
    }

    /// Continua.
    pub fn go(&mut self) -> Result<(), String> {
        self.resume("c")
    }

    /// Pede a parada (0x03) sem esperar a resposta.
    pub fn interrupt(&mut self) -> Result<(), String> {
        if self.stopped {
            return Ok(());
        }
        self.connection.interrupt()
    }

    /// Pede a parada e espera.
    pub fn break_in(&mut self, timeout: Duration) -> Result<String, String> {
        if self.stopped {
            return Ok(self.last_stop.clone());
        }
        self.connection.interrupt()?;
        self.wait_stop(timeout)
    }

    /// Um passo no processador da parada.
    pub fn step(&mut self) -> Result<String, String> {
        self.resume("s")?;
        self.wait_stop(self.timeout)
    }

    /// Passo por cima: num `call`, um breakpoint temporário na instrução
    /// seguinte e a máquina segue; em qualquer outra instrução, um passo.
    pub fn step_over(&mut self) -> Result<Resumed, String> {
        let rip = self.register("rip")?;
        let rsp = self.register("rsp")?;
        let code = self.read_memory(rip, 16).unwrap_or_default();
        match x86::call_length(&code) {
            Some(length) => {
                self.run_to(rip + length as u64, rsp)?;
                Ok(Resumed::Running)
            }
            None => self.step().map(Resumed::Stopped),
        }
    }

    /// Passo para fora: até o endereço de retorno da função corrente (pela
    /// `.pdata` num binário da Microsoft, pelo prólogo ou pelo frame pointer
    /// no código do OpenNT).
    pub fn step_out(&mut self) -> Result<Resumed, String> {
        let frames = self.backtrace(2)?;
        let caller = frames.get(1).copied().ok_or("sem endereco de retorno (a pilha nao desenrola)")?;
        if caller.address == 0 {
            return Err("sem endereco de retorno".into());
        }
        self.run_to(caller.address, caller.stack)?;
        Ok(Resumed::Running)
    }

    /// Roda até `address` (um breakpoint temporário); com `expected_rsp`,
    /// só para quando o RSP for esse (o mesmo quadro).
    pub fn run_until(&mut self, address: u64, expected_rsp: Option<u64>) -> Result<(), String> {
        self.require_stopped()?;
        self.run_to_inner(address, expected_rsp)
    }

    fn run_to(&mut self, address: u64, expected_rsp: u64) -> Result<(), String> {
        self.run_to_inner(address, Some(expected_rsp))
    }

    fn run_to_inner(&mut self, address: u64, expected_rsp: Option<u64>) -> Result<(), String> {
        let existing = self.hook_at(address) || self.breakpoints.iter().any(|breakpoint| breakpoint.enabled && breakpoint.kind == BreakpointKind::Software && breakpoint.address == address);
        if !existing {
            let reply = self.request(&format!("Z0,{address:x},1"))?;
            if reply != "OK" {
                return Err(format!("breakpoint temporario em {address:#x}: {reply}"));
            }
        }
        self.run_to = Some(RunTo { address, inserted: !existing, expected_rsp });
        if let Err(error) = self.resume("c") {
            if let Some(run_to) = self.run_to.take() {
                if run_to.inserted {
                    let _ = self.request(&format!("z0,{address:x},1"));
                }
            }
            return Err(error);
        }
        Ok(())
    }

    fn insert(&mut self, kind: BreakpointKind, address: u64, length: u64, insert: bool) -> Result<(), String> {
        self.insert_in(kind, address, length, insert, 0)
    }

    /// Grava ou tira um breakpoint; `process` (EPROCESS, 0 = o escolhido)
    /// dá a raiz de um endereço de usuário.
    fn insert_in(&mut self, kind: BreakpointKind, address: u64, length: u64, insert: bool, process: u64) -> Result<(), String> {
        // O breakpoint interno de carga divide o endereço com um do usuário.
        if kind == BreakpointKind::Software && (self.hook_at(address) || self.event_hooks.iter().any(|(hook, _, _)| *hook == address)) {
            return Ok(());
        }
        let switch = process != 0 && address < 0x8000_0000_0000 && self.process_context.as_ref().is_none_or(|context| context.eprocess != process);
        if switch {
            self.monitor(&format!(".process {process:#x}"))?;
        }
        if kind.is_memory() {
            // O breakpoint de memória por página vai pelo `monitor membp`.
            let command = if insert { format!("membp set {address:#x} {length:#x} {}", kind.memory_letter()) } else { format!("membp clear {address:#x}") };
            let result = self.monitor(&command);
            if switch {
                let restore = self.process_context.as_ref().map_or("0".to_string(), |context| format!("{:#x}", context.eprocess));
                let _ = self.monitor(&format!(".process {restore}"));
            }
            let text = result?;
            return if text.contains("membp ok") { Ok(()) } else { Err(format!("breakpoint de memoria em {address:#x}: {}", text.trim())) };
        }
        let reply = self.request(&format!("{}{},{:x},{:x}", if insert { 'Z' } else { 'z' }, kind.packet_type(), address, length));
        if switch {
            let restore = self.process_context.as_ref().map_or("0".to_string(), |context| format!("{:#x}", context.eprocess));
            let _ = self.monitor(&format!(".process {restore}"));
        }
        match reply?.as_str() {
            "OK" => Ok(()),
            "" => Err("tipo de breakpoint sem suporte no alvo".into()),
            other => Err(format!("breakpoint em {address:#x}: {other}")),
        }
    }

    /// Arma um breakpoint (ou religa o mesmo, se já existe).
    pub fn add_breakpoint(&mut self, kind: BreakpointKind, expression: &str, length: u64) -> Result<Breakpoint, String> {
        let mut request = BreakpointRequest::new(kind, expression);
        request.length = length;
        self.add_breakpoint_with(&request)
    }

    /// Arma um breakpoint com condição, contagem e adiamento.
    pub fn add_breakpoint_with(&mut self, request: &BreakpointRequest) -> Result<Breakpoint, String> {
        self.require_stopped()?;
        let kind = request.kind;
        if kind == BreakpointKind::Event {
            let expression = request.expression.trim().to_string();
            let code = expression.split(':').next().unwrap_or("").to_ascii_lowercase();
            if !["cpr", "epr", "ct", "et", "ld"].contains(&code.as_str()) {
                return Err("uso: sxe cpr[:nome] | epr[:nome] | ct[:pid] | et[:pid] | ld:processo!dll".into());
            }
            if let Some(existing) = self.breakpoints.iter_mut().find(|breakpoint| breakpoint.kind == kind && breakpoint.expression.eq_ignore_ascii_case(&expression)) {
                existing.enabled = request.enabled;
                existing.log = request.log.clone();
                let copy = existing.clone();
                self.update_event_hooks()?;
                return Ok(copy);
            }
            let breakpoint = self.push_breakpoint(request, 0, false);
            self.update_event_hooks()?;
            return Ok(breakpoint);
        }
        if kind == BreakpointKind::Module {
            let name = request.expression.trim().to_string();
            if name.is_empty() {
                return Err("uso: sxe ld:<modulo>".into());
            }
            if let Some(existing) = self.breakpoints.iter_mut().find(|breakpoint| breakpoint.kind == kind && breakpoint.expression.eq_ignore_ascii_case(&name)) {
                existing.enabled = request.enabled;
                let copy = existing.clone();
                self.update_load_hook()?;
                return Ok(copy);
            }
            let breakpoint = self.push_breakpoint(request, 0, false);
            self.update_load_hook()?;
            return Ok(breakpoint);
        }
        let address = match self.evaluate(&request.expression) {
            Ok(address) => address,
            Err(error) if request.deferred && (error.contains("nao carregado") || error.contains("nao encontrado")) => {
                let breakpoint = self.push_breakpoint(request, 0, true);
                self.update_load_hook()?;
                return Ok(breakpoint);
            }
            Err(error) => return Err(error),
        };
        // O breakpoint de memória vale por página inteira.
        let (address, length) = if kind.is_memory() {
            let start = address & !0xFFF;
            let end = (address + request.length.max(1) + 0xFFF) & !0xFFF;
            (start, end - start)
        } else {
            (address, request.length)
        };
        if let Some(index) = self.breakpoints.iter().position(|breakpoint| breakpoint.kind == kind && breakpoint.address == address && !breakpoint.pending) {
            if !self.breakpoints[index].enabled && request.enabled {
                let (length, process) = (self.breakpoints[index].length, self.breakpoints[index].process);
                self.insert_in(kind, address, length, true, process)?;
                self.breakpoints[index].enabled = true;
            }
            self.breakpoints[index].condition = request.condition.clone();
            self.breakpoints[index].pass_count = request.pass_count;
            self.breakpoints[index].log = request.log.clone();
            self.breakpoints[index].command = request.command.clone();
            self.breakpoints[index].group = request.group.clone();
            self.breakpoints[index].options = request.options.clone();
            return Ok(self.breakpoints[index].clone());
        }
        let process = if request.process != 0 {
            request.process
        } else if address < 0x8000_0000_0000 {
            self.process_context.as_ref().map_or(0, |context| context.eprocess)
        } else {
            0
        };
        if request.enabled {
            self.insert_in(kind, address, length, true, process)?;
        }
        let mut breakpoint = self.push_breakpoint(request, address, false);
        if let Some(entry) = self.breakpoints.iter_mut().find(|entry| entry.id == breakpoint.id) {
            entry.process = process;
            entry.length = length;
            breakpoint.process = process;
            breakpoint.length = length;
        }
        Ok(breakpoint)
    }

    /// Troca todas as opções de um breakpoint (o editor): condição,
    /// contagem, log, comandos, grupo e as opções de acerto. Zera os
    /// acertos.
    pub fn edit_breakpoint(&mut self, id: u32, request: &BreakpointRequest) -> Result<Breakpoint, String> {
        let breakpoint = self.breakpoints.iter_mut().find(|breakpoint| breakpoint.id == id).ok_or_else(|| format!("breakpoint {id} nao existe"))?;
        breakpoint.condition = request.condition.trim().to_string();
        breakpoint.pass_count = request.pass_count;
        breakpoint.log = request.log.trim().to_string();
        breakpoint.command = request.command.trim().to_string();
        breakpoint.group = request.group.trim().to_string();
        breakpoint.options = request.options.clone();
        breakpoint.hits = 0;
        let copy = breakpoint.clone();
        if copy.enabled != request.enabled {
            self.set_breakpoint_enabled(id, request.enabled)?;
        }
        Ok(self.breakpoints.iter().find(|breakpoint| breakpoint.id == id).cloned().unwrap_or(copy))
    }

    fn push_breakpoint(&mut self, request: &BreakpointRequest, address: u64, pending: bool) -> Breakpoint {
        let breakpoint = Breakpoint {
            id: self.next_breakpoint,
            kind: request.kind,
            address,
            length: request.length,
            enabled: request.enabled,
            expression: request.expression.trim().to_string(),
            condition: request.condition.trim().to_string(),
            pass_count: request.pass_count,
            hits: 0,
            pending,
            log: request.log.trim().to_string(),
            command: request.command.trim().to_string(),
            group: request.group.trim().to_string(),
            process: request.process,
            options: request.options.clone(),
        };
        self.next_breakpoint += 1;
        self.breakpoints.push(breakpoint.clone());
        breakpoint
    }

    /// Troca a condição e a contagem de um breakpoint.
    pub fn set_breakpoint_condition(&mut self, id: u32, condition: &str, pass_count: u64) -> Result<(), String> {
        let breakpoint = self.breakpoints.iter_mut().find(|breakpoint| breakpoint.id == id).ok_or_else(|| format!("breakpoint {id} nao existe"))?;
        breakpoint.condition = condition.trim().to_string();
        breakpoint.pass_count = pass_count;
        breakpoint.hits = 0;
        Ok(())
    }

    /// Arma os breakpoints adiados cujo símbolo já existe.
    fn resolve_pending(&mut self) {
        for index in 0..self.breakpoints.len() {
            let breakpoint = self.breakpoints[index].clone();
            if !breakpoint.pending {
                continue;
            }
            let Ok(address) = self.evaluate(&breakpoint.expression) else { continue };
            if breakpoint.enabled && self.insert(breakpoint.kind, address, breakpoint.length, true).is_err() {
                continue;
            }
            self.breakpoints[index].address = address;
            self.breakpoints[index].pending = false;
        }
    }

    /// Liga ou tira o breakpoint interno da notificação de carga de imagem,
    /// conforme haja paradas por carga de módulo ou breakpoints adiados.
    fn update_load_hook(&mut self) -> Result<(), String> {
        let needed = self.breakpoints.iter().any(|breakpoint| breakpoint.enabled && (breakpoint.kind == BreakpointKind::Module || breakpoint.pending));
        match (needed, self.load_hook) {
            (true, None) => {
                let address = LOAD_HOOKS.iter().find_map(|name| self.symbols.lookup(name).ok()).ok_or("o kernel nao tem a funcao de notificacao de carga de imagem (sem simbolos do kernel?)")?;
                let user = self.breakpoints.iter().any(|breakpoint| breakpoint.enabled && breakpoint.kind == BreakpointKind::Software && breakpoint.address == address);
                if !user {
                    let reply = self.request(&format!("Z0,{address:x},1"))?;
                    if reply != "OK" {
                        return Err(format!("breakpoint de carga em {address:#x}: {reply}"));
                    }
                }
                self.load_hook = Some((address, !user));
            }
            (false, Some((address, _))) => {
                let user = self.breakpoints.iter().any(|breakpoint| breakpoint.enabled && breakpoint.kind == BreakpointKind::Software && breakpoint.address == address);
                if !user {
                    let _ = self.request(&format!("z0,{address:x},1"));
                }
                self.load_hook = None;
            }
            _ => {}
        }
        Ok(())
    }

    /// Tira um breakpoint do alvo e da lista.
    pub fn remove_breakpoint(&mut self, id: u32) -> Result<Breakpoint, String> {
        self.require_stopped()?;
        let index = self.breakpoints.iter().position(|breakpoint| breakpoint.id == id).ok_or_else(|| format!("breakpoint {id} nao existe"))?;
        let breakpoint = self.breakpoints[index].clone();
        if breakpoint.enabled && !breakpoint.pending && !matches!(breakpoint.kind, BreakpointKind::Module | BreakpointKind::Event) {
            self.insert_in(breakpoint.kind, breakpoint.address, breakpoint.length, false, breakpoint.process)?;
        }
        self.breakpoints.remove(index);
        self.update_load_hook()?;
        self.update_event_hooks()?;
        Ok(breakpoint)
    }

    /// Desliga (tira do alvo, fica na lista) ou religa.
    pub fn set_breakpoint_enabled(&mut self, id: u32, enabled: bool) -> Result<(), String> {
        self.require_stopped()?;
        let index = self.breakpoints.iter().position(|breakpoint| breakpoint.id == id).ok_or_else(|| format!("breakpoint {id} nao existe"))?;
        let breakpoint = self.breakpoints[index].clone();
        if breakpoint.enabled != enabled {
            if !breakpoint.pending && !matches!(breakpoint.kind, BreakpointKind::Module | BreakpointKind::Event) {
                self.insert_in(breakpoint.kind, breakpoint.address, breakpoint.length, enabled, breakpoint.process)?;
            }
            self.breakpoints[index].enabled = enabled;
        }
        self.update_load_hook()?;
        self.update_event_hooks()
    }

    /// Liga ou desliga todos os breakpoints de um grupo; devolve quantos.
    pub fn set_group_enabled(&mut self, group: &str, enabled: bool) -> Result<usize, String> {
        let ids: Vec<u32> = self.breakpoints.iter().filter(|breakpoint| breakpoint.group == group).map(|breakpoint| breakpoint.id).collect();
        for id in &ids {
            self.set_breakpoint_enabled(*id, enabled)?;
        }
        Ok(ids.len())
    }

    /// Troca o log, os comandos de parada e o grupo de um breakpoint.
    pub fn set_breakpoint_actions(&mut self, id: u32, log: &str, command: &str, group: &str) -> Result<(), String> {
        let breakpoint = self.breakpoints.iter_mut().find(|breakpoint| breakpoint.id == id).ok_or_else(|| format!("breakpoint {id} nao existe"))?;
        breakpoint.log = log.trim().to_string();
        breakpoint.command = command.trim().to_string();
        breakpoint.group = group.trim().to_string();
        Ok(())
    }

    /// Vigia uma faixa de bytes com os comparadores de hardware (escrita ou
    /// acesso): a faixa vira pedaços alinhados de 8, 4, 2 e 1 bytes, no
    /// máximo quatro, num grupo próprio.
    pub fn add_range_watch(&mut self, kind: BreakpointKind, start: u64, length: u64) -> Result<Vec<Breakpoint>, String> {
        if !matches!(kind, BreakpointKind::Write | BreakpointKind::Access) {
            return Err("faixa: so escrita ou acesso".into());
        }
        let chunks = range_chunks(start, length);
        if chunks.is_empty() || chunks.len() > 4 {
            return Err(format!("a faixa {start:#x}+{length:#x} precisa de {} comparadores (o x86 tem 4)", chunks.len()));
        }
        let group = format!("faixa {start:#x}+{length:#x}");
        let mut created = Vec::new();
        for (address, size) in chunks {
            let mut request = BreakpointRequest::new(kind, &format!("{address:#x}"));
            request.length = size;
            request.group = group.clone();
            created.push(self.add_breakpoint_with(&request)?);
        }
        Ok(created)
    }

    /// Os comandos de parada do breakpoint que parou a máquina por último
    /// (o número dele e o texto).
    pub fn stop_commands(&self) -> Option<(u32, String)> {
        self.pending_commands.clone()
    }

    /// Arma ou tira os breakpoints internos nos pontos de evento conforme os
    /// breakpoints de evento ligados.
    fn update_event_hooks(&mut self) -> Result<(), String> {
        let wanted: Vec<&'static str> = [PROCESS_EVENT, THREAD_EVENT, IMAGE_EVENT]
            .into_iter()
            .filter(|symbol| {
                let codes: &[&str] = match *symbol {
                    PROCESS_EVENT => &["cpr", "epr"],
                    THREAD_EVENT => &["ct", "et"],
                    _ => &["ld"],
                };
                self.breakpoints.iter().any(|breakpoint| breakpoint.enabled && breakpoint.kind == BreakpointKind::Event && codes.iter().any(|code| breakpoint.expression.to_ascii_lowercase().starts_with(code)))
            })
            .collect();
        let mut keep = Vec::new();
        for (address, symbol, inserted) in std::mem::take(&mut self.event_hooks) {
            if wanted.contains(&symbol) {
                keep.push((address, symbol, inserted));
            } else if inserted && !self.breakpoints.iter().any(|breakpoint| breakpoint.enabled && breakpoint.kind == BreakpointKind::Software && breakpoint.address == address) {
                let _ = self.request(&format!("z0,{address:x},1"));
            }
        }
        self.event_hooks = keep;
        for symbol in wanted {
            if self.event_hooks.iter().any(|(_, existing, _)| *existing == symbol) {
                continue;
            }
            let address = self.symbols.lookup(symbol).map_err(|_| format!("o kernel nao tem o ponto de evento {symbol} (kernel antigo?)"))?;
            let user = self.breakpoints.iter().any(|breakpoint| breakpoint.enabled && breakpoint.kind == BreakpointKind::Software && breakpoint.address == address);
            if !user {
                let reply = self.request(&format!("Z0,{address:x},1"))?;
                if reply != "OK" {
                    return Err(format!("breakpoint de evento em {address:#x}: {reply}"));
                }
            }
            self.event_hooks.push((address, symbol, !user));
        }
        Ok(())
    }

    // ---- processos de usuário ------------------------------------------------

    /// Escolhe o processo das leituras (`.process`): PID, EPROCESS ou
    /// `None` (o espaço do processador). Os módulos de usuário dele (a
    /// PEB.Ldr e as imagens do VAD) entram nos símbolos.
    pub fn set_process(&mut self, process: Option<&str>) -> Result<Option<ProcessContext>, String> {
        let Some(process) = process.map(str::trim).filter(|text| !text.is_empty() && *text != "0") else {
            self.monitor(".process 0")?;
            self.process_context = None;
            return Ok(None);
        };
        let text = self.monitor(&format!(".process {process}"))?;
        let mut context = user::parse_process_context(&text).ok_or_else(|| text.trim().to_string())?;
        context.name = self.processes().unwrap_or_default().into_iter().find(|entry| entry.eprocess == context.eprocess).map(|entry| entry.name).unwrap_or_default();
        let changed = self.symbols.user_process != context.eprocess;
        self.process_context = Some(context.clone());
        if changed {
            let _ = self.reload_user_modules();
        }
        Ok(Some(context))
    }

    /// O processo das leituras, se escolhido.
    pub fn process(&self) -> Option<&ProcessContext> {
        self.process_context.as_ref()
    }

    /// A parada é numa thread de usuário (CS do anel 3).
    pub fn stopped_in_user_mode(&mut self) -> bool {
        self.register("cs").ok() == Some(USER_CODE_SELECTOR)
    }

    /// Os módulos do processo escolhido: a PEB.Ldr e, para as imagens que
    /// ainda não estão nela (uma DLL recém-mapeada), o VAD.
    pub fn user_modules(&mut self) -> Result<Vec<UserModule>, String> {
        let context = self.process_context.clone().ok_or("nenhum processo escolhido (.process <pid>)")?;
        let mut modules = if context.peb != 0 { user::read_loader_list(self, context.peb).unwrap_or_default() } else { Vec::new() };
        if let Ok(regions) = self.regions(&format!("{:#x}", context.eprocess)) {
            for region in regions.into_iter().filter(|region| region.kind == "Image" && !region.name.is_empty()) {
                if !modules.iter().any(|module| module.base == region.base) {
                    let name = super::symbols::base_name(&region.name).to_string();
                    modules.push(UserModule { base: region.base, size: region.size, entry: 0, name, path: region.name.clone() });
                }
            }
        }
        modules.sort_by_key(|module| module.base);
        Ok(modules)
    }

    /// Recarrega os módulos de usuário do processo escolhido nos símbolos;
    /// devolve quantos.
    pub fn reload_user_modules(&mut self) -> Result<usize, String> {
        let context = self.process_context.clone().ok_or("nenhum processo escolhido (.process <pid>)")?;
        let modules = self.user_modules()?;
        let list: Vec<(u64, u64, String)> = modules.iter().map(|module| (module.base, module.base + module.size.max(0x1000), if module.path.is_empty() { module.name.clone() } else { module.path.clone() })).collect();
        self.symbols.set_user_modules(context.eprocess, &list, &self.root);
        Ok(list.len())
    }

    /// A tabela de handles de um processo (todas as páginas).
    pub fn handles(&mut self, process: &str) -> Result<Vec<Handle>, String> {
        let mut handles = Vec::new();
        let mut start = 0u64;
        loop {
            let text = self.monitor(&format!("handles {process} {start}"))?;
            if handles.is_empty() && !text.contains("HANDLE_TABLE") {
                return Err(text.trim().to_string());
            }
            handles.extend(user::parse_handles(&text));
            match user::next_page(&text) {
                Some(next) if next > start && handles.len() < 65536 => start = next,
                _ => break,
            }
        }
        Ok(handles)
    }

    /// As regiões de usuário de um processo (todas as páginas).
    pub fn regions(&mut self, process: &str) -> Result<Vec<Region>, String> {
        let mut regions = Vec::new();
        let mut start = 0u64;
        loop {
            let text = self.monitor(&format!("vad {process} {start}"))?;
            if regions.is_empty() && !text.contains("regioes") {
                return Err(text.trim().to_string());
            }
            regions.extend(user::parse_regions(&text));
            match user::next_page(&text) {
                Some(next) if next > start && regions.len() < 65536 => start = next,
                _ => break,
            }
        }
        Ok(regions)
    }

    /// As threads de usuário de um processo.
    pub fn user_threads(&mut self, process: &str) -> Result<Vec<UserThread>, String> {
        let text = self.monitor(&format!("uthreads {process}"))?;
        if !text.contains("CR3") {
            return Err(text.trim().to_string());
        }
        Ok(user::parse_user_threads(&text))
    }

    /// As faixas fixas do espaço de sistema.
    pub fn kernel_ranges(&mut self) -> Result<Vec<KernelRange>, String> {
        Ok(user::parse_kernel_map(&self.monitor("kmap")?))
    }

    /// Os registradores de usuário de uma thread pelo CONTEXT salvo dela.
    pub fn user_thread_registers(&mut self, thread: &UserThread) -> Result<Vec<(String, u64)>, String> {
        if thread.context == 0 {
            return Err(format!("thread {}: sem CONTEXT salvo", thread.tid));
        }
        let bytes = self.read_memory(thread.context, 0x100)?;
        Ok(user::context_registers(&bytes).into_iter().map(|(name, value)| (name.to_string(), value)).collect())
    }

    /// A pilha de usuário de uma thread (o CONTEXT salvo, desenrolado pela
    /// `.pdata` dos módulos do processo escolhido).
    pub fn user_thread_backtrace(&mut self, thread: &UserThread, limit: usize) -> Result<(Vec<(String, u64)>, Vec<Frame>), String> {
        let registers = self.user_thread_registers(thread)?;
        let rip = registers.iter().find(|(name, _)| name == "rip").map(|(_, value)| *value).unwrap_or(0);
        let named: Vec<(&str, u64)> = registers.iter().map(|(name, value)| (name.as_str(), *value)).collect();
        let frames = unwind::walk(self, Context::from_named(rip, &named), false, limit);
        Ok((registers, frames))
    }

    /// Parar ou não nas exceções de primeira chance do anel 3.
    pub fn set_user_exceptions(&mut self, enabled: bool) -> Result<String, String> {
        self.monitor(if enabled { "uex on" } else { "uex off" })
    }

    /// Liga ou tira o breakpoint de software num endereço (o clique na
    /// margem da desmontagem, o F9); `true` se ficou armado.
    pub fn toggle_breakpoint(&mut self, address: u64) -> Result<bool, String> {
        if let Some(breakpoint) = self.breakpoints.iter().find(|breakpoint| breakpoint.kind == BreakpointKind::Software && breakpoint.address == address && !breakpoint.pending) {
            let id = breakpoint.id;
            self.remove_breakpoint(id)?;
            return Ok(false);
        }
        let expression = self.symbols.name_at(address).unwrap_or_else(|| format!("{address:#x}"));
        let breakpoint = self.add_breakpoint(BreakpointKind::Software, &format!("{address:#x}"), 1)?;
        if let Some(entry) = self.breakpoints.iter_mut().find(|entry| entry.id == breakpoint.id) {
            entry.expression = expression;
        }
        Ok(true)
    }

    /// Os breakpoints em texto (o arquivo de sessão): tipo, ligado, tamanho,
    /// contagem, expressão e condição, separados por tabulação.
    pub fn breakpoint_specs(&self) -> String {
        self.breakpoints
            .iter()
            .map(|breakpoint| {
                let mut line = format!("{}\t{}\t{}\t{}\t{}\t{}", breakpoint.kind.key(), breakpoint.enabled as u8, breakpoint.length, breakpoint.pass_count, breakpoint.expression, breakpoint.condition);
                let options = &breakpoint.options;
                let flags: String = [(options.single_shot, 's'), (options.silent, 'q'), (options.fast_resume, 'f')].iter().filter(|(on, _)| *on).map(|(_, letter)| *letter).collect();
                let extended = !options.name.is_empty() || !options.log_condition.is_empty() || !options.command_condition.is_empty() || !flags.is_empty();
                if extended || !breakpoint.log.is_empty() || !breakpoint.command.is_empty() || !breakpoint.group.is_empty() {
                    line.push_str(&format!("\t{}\t{}\t{}", breakpoint.log, breakpoint.command, breakpoint.group));
                }
                if extended {
                    line.push_str(&format!("\t{}\t{}\t{}\t{flags}", options.name, options.log_condition, options.command_condition));
                }
                line.push('\n');
                line
            })
            .collect()
    }

    /// Recria os breakpoints de um arquivo de sessão (adiados quando o
    /// símbolo ainda não existe); devolve os que falharam.
    pub fn restore_breakpoints(&mut self, text: &str) -> Vec<String> {
        let mut errors = Vec::new();
        for line in text.lines().filter(|line| !line.trim().is_empty() && !line.starts_with('#')) {
            let fields: Vec<&str> = line.split('\t').collect();
            let Some(kind) = fields.first().and_then(|kind| BreakpointKind::parse(kind)) else {
                errors.push(format!("linha invalida: {line}"));
                continue;
            };
            let mut request = BreakpointRequest::new(kind, fields.get(4).copied().unwrap_or(""));
            request.enabled = fields.get(1) != Some(&"0");
            request.length = fields.get(2).and_then(|text| text.parse().ok()).unwrap_or(request.length);
            request.pass_count = fields.get(3).and_then(|text| text.parse().ok()).unwrap_or(0);
            request.condition = fields.get(5).copied().unwrap_or("").to_string();
            request.log = fields.get(6).copied().unwrap_or("").to_string();
            request.command = fields.get(7).copied().unwrap_or("").to_string();
            request.group = fields.get(8).copied().unwrap_or("").to_string();
            request.options.name = fields.get(9).copied().unwrap_or("").to_string();
            request.options.log_condition = fields.get(10).copied().unwrap_or("").to_string();
            request.options.command_condition = fields.get(11).copied().unwrap_or("").to_string();
            let flags = fields.get(12).copied().unwrap_or("");
            request.options.single_shot = flags.contains('s');
            request.options.silent = flags.contains('q');
            request.options.fast_resume = flags.contains('f');
            request.deferred = true;
            if let Err(error) = self.add_breakpoint_with(&request) {
                errors.push(format!("{}: {error}", request.expression));
            }
        }
        errors
    }

    /// A pilha do processador escolhido: `.pdata` nos binários da
    /// Microsoft, frame pointers no código do OpenNT.
    pub fn backtrace(&mut self, limit: usize) -> Result<Vec<Frame>, String> {
        let values = self.general_registers()?;
        let rip = self.register("rip")?;
        let named: Vec<(&str, u64)> = values.iter().filter_map(|value| value.value.map(|number| (value.layout.name, number))).collect();
        let context = Context::from_named(rip, &named);
        Ok(unwind::walk(self, context, false, limit))
    }

    /// A pilha de uma thread pelo `monitor context` (a de uma thread fora
    /// da CPU começa no quadro de troca: o RIP já é um retorno).
    pub fn thread_backtrace(&mut self, thread: u64, limit: usize) -> Result<(ThreadContext, Vec<Frame>), String> {
        let context = self.thread_context(thread)?;
        let Some(rip) = context.register("rip") else { return Err(format!("contexto de {thread:#x}: {}", context.header)) };
        let named: Vec<(&str, u64)> = context.registers.iter().map(|(name, value)| (name.as_str(), *value)).collect();
        let start = Context::from_named(rip, &named);
        let frames = unwind::walk(self, start, context.processor.is_none(), limit);
        Ok((context, frames))
    }

    /// `#n endereço símbolo` por quadro.
    pub fn format_frames(&self, frames: &[Frame]) -> String {
        let mut output = String::new();
        for (depth, frame) in frames.iter().enumerate() {
            output.push_str(&format!("#{depth:<2} {:#018x} {}\n", frame.address, self.frame_name(frame)));
        }
        output
    }

    /// A pilha como o `k` do WinDbg: RSP do quadro, endereço e símbolo.
    pub fn format_frames_with_stack(&self, frames: &[Frame]) -> String {
        let mut output = String::from(" #  Child-SP           RetAddr            Call Site\n");
        for (depth, frame) in frames.iter().enumerate() {
            let next = frames.get(depth + 1).map_or(0, |frame| frame.address);
            output.push_str(&format!("{depth:02} {:#018x} {next:#018x} {}\n", frame.stack, self.frame_name(frame)));
        }
        output
    }

    /// O símbolo de um quadro: um endereço de retorno pode cair logo depois
    /// do fim da função chamadora (chamada que não volta), então o símbolo é
    /// o do byte de antes.
    pub fn frame_name(&self, frame: &Frame) -> String {
        if frame.is_return {
            self.symbols.describe_return(frame.address)
        } else {
            self.symbols.describe(frame.address)
        }
    }

    /// Escolhe o processador das leituras e gravações (thread do protocolo
    /// = processador + 1).
    pub fn select_thread(&mut self, thread: u64) -> Result<(), String> {
        self.require_stopped()?;
        let reply = self.request(&format!("Hg{thread:x}"))?;
        if reply != "OK" {
            return Err(format!("thread {thread}: {reply}"));
        }
        self.registers = None;
        self.selected = Some(thread);
        Ok(())
    }

    /// Os processadores parados (as threads do protocolo).
    pub fn stopped_threads(&mut self) -> Result<Vec<u64>, String> {
        self.require_stopped()?;
        let mut threads = Vec::new();
        let mut reply = self.request("qfThreadInfo")?;
        while let Some(list) = reply.strip_prefix('m') {
            threads.extend(list.split(',').filter_map(|thread| u64::from_str_radix(thread, 16).ok()));
            reply = self.request("qsThreadInfo")?;
        }
        Ok(threads)
    }

    /// Desliga a sessão (parando antes, se preciso): a máquina segue sem
    /// host anexado e o alvo tira os breakpoints.
    pub fn detach(&mut self) -> Result<String, String> {
        if !self.stopped {
            self.connection.interrupt()?;
            self.wait_stop(Duration::from_secs(60))?;
        }
        let reply = self.request("D")?;
        self.stopped = false;
        self.breakpoints.clear();
        self.load_hook = None;
        self.event_hooks.clear();
        self.process_context = None;
        Ok(format!("desligado ({reply})"))
    }

    /// A análise do bugcheck que parou a máquina (`!analyze`).
    pub fn analyze(&mut self) -> Result<Analysis, String> {
        let text = self.monitor("bugcheck")?;
        let (code, parameters) = bugcheck::parse_monitor(&text).ok_or("nenhum bugcheck parou a maquina")?;
        let frames = self.backtrace(32).unwrap_or_default();
        let stack: Vec<(u64, String)> = frames.iter().map(|frame| (frame.address, self.frame_name(frame))).collect();
        let symbols = &self.symbols;
        let mut analysis = bugcheck::analyze(code, parameters, stack, &|address| symbols.module_at(address).map(|module| module.name.clone()), &|address| symbols.describe(address));
        // O culpado que o próprio kernel apontou (KiBugCheckDriver).
        if let Some(driver) = text.lines().find_map(|line| line.trim().strip_prefix("driver: ")) {
            if !driver.trim().is_empty() {
                analysis.blamed = Some((super::symbols::display_name(driver.trim()), "KiBugCheckDriver do kernel".into()));
            }
        }
        if let Some(name) = text.lines().find_map(|line| line.trim().strip_prefix("nome: ")) {
            if analysis.name.starts_with("BUGCHECK_") && !name.trim().is_empty() {
                analysis.name = name.trim().to_string();
            }
        }
        Ok(analysis)
    }

    /// A tabela de funções de uma imagem lida da memória do alvo.
    fn read_function_table(&mut self, base: u64) -> Option<Arc<FunctionTable>> {
        let header = self.read_memory(base, 0x1000).ok()?;
        let image = PeImage::parse_mapped(header)?;
        let (rva, size) = image.directory(3)?;
        if size == 0 || size > 0x40_0000 {
            return None;
        }
        let table = self.read_memory(base + rva as u64, size as usize).ok()?;
        let mut functions: Vec<super::pe::RuntimeFunction> = table
            .chunks_exact(12)
            .map(|entry| super::pe::RuntimeFunction { begin: u32::from_le_bytes(entry[0..4].try_into().unwrap()), end: u32::from_le_bytes(entry[4..8].try_into().unwrap()), unwind: u32::from_le_bytes(entry[8..12].try_into().unwrap()) })
            .filter(|function| function.end > function.begin)
            .collect();
        functions.sort_by_key(|function| function.begin);
        Some(Arc::new(FunctionTable { base, functions, image: None }))
    }

    /// Lê bytes do buffer do rastro do alvo (`qOpenNTTrace:offset,tamanho`).
    pub(crate) fn trace_bytes(&mut self, offset: usize, length: usize) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::with_capacity(length);
        while bytes.len() < length {
            let chunk = (length - bytes.len()).min(0x7C0);
            let reply = self.request(&format!("qOpenNTTrace:{:x},{:x}", offset + bytes.len(), chunk))?;
            if reply.starts_with('E') || reply.is_empty() {
                return Err(format!("rastro: leitura em {:#x}: {reply}", offset + bytes.len()));
            }
            let data = unhex(&reply);
            if data.is_empty() {
                break;
            }
            bytes.extend_from_slice(&data);
        }
        Ok(bytes)
    }
}

/// Uma faixa em pedaços alinhados de 8, 4, 2 e 1 bytes (os tamanhos que um
/// comparador de hardware aceita).
pub fn range_chunks(start: u64, length: u64) -> Vec<(u64, u64)> {
    let mut chunks = Vec::new();
    let mut address = start;
    let end = start.saturating_add(length);
    while address < end && chunks.len() <= 4 {
        let size = [8u64, 4, 2, 1].into_iter().find(|size| address % size == 0 && address + size <= end).unwrap_or(1);
        chunks.push((address, size));
        address += size;
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::range_chunks;

    #[test]
    fn splits_ranges_for_the_comparators() {
        assert_eq!(range_chunks(0x1000, 16), vec![(0x1000, 8), (0x1008, 8)]);
        assert_eq!(range_chunks(0x1003, 6), vec![(0x1003, 1), (0x1004, 4), (0x1008, 1)]);
        assert_eq!(range_chunks(0x1000, 0), vec![]);
        assert!(range_chunks(0x1001, 64).len() > 4);
    }
}
