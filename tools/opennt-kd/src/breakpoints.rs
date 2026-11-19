//! Os breakpoints adiados e os breakpoints por processo.
//!
//! - Adiado (`bu`): o símbolo é de um módulo que ainda não carregou. O
//!   cliente arma o ponto de evento de imagem do kernel
//!   (`opennt_kd_image_event`, `kernel/src/ntos/kd/events.rs`) e, a cada
//!   imagem nova (driver ou DLL de um processo), resolve o nome só no módulo
//!   novo: exports e públicos do PDB (baixado na hora, com a máquina parada)
//!   e, sem eles, `módulo+0xRVA`. Um breakpoint de usuário é armado no
//!   processo que carregou a imagem (`.process` + `Z0`), não no processo
//!   escolhido na sessão.
//! - Por processo (`/p`): um PID ou EPROCESS (aquela instância), um nome de
//!   imagem (`dwm.exe`: cada processo com esse nome, também os que ainda vão
//!   nascer) ou `*` (todos os processos). Com nome ou `*`, o breakpoint
//!   pedido vira um modelo, sempre adiado, e cada processo ganha uma
//!   instância: um breakpoint comum com o EPROCESS dele. Num endereço de
//!   sistema, o filtro vale na hora do acerto: a máquina segue quando o
//!   processo corrente não é o pedido.
//! - Saída de processo (`opennt_kd_process_event`): o stub já devolveu os
//!   bytes do processo; as instâncias dele somem da lista e os outros
//!   breakpoints dele voltam a adiados. Um `bu` armado no processo escolhido
//!   segue para o próximo processo com o mesmo nome (o dwm que reinicia).
//! - Limite de acertos (`/max N`): depois de N acertos que pararam ou
//!   registraram, o breakpoint se desliga (num modelo, a contagem é a de
//!   todas as instâncias).
//!
//! O que não cabe em `Breakpoint` (o filtro, o modelo de uma instância, o
//! limite) fica numa tabela à parte, pelo número do breakpoint, para não
//! mudar a estrutura que as interfaces montam.

use std::sync::Arc;

use super::client::{Breakpoint, BreakpointKind, BreakpointRequest, Client};
use super::expr::{self, Environment};
use super::registers;
use super::symbols::{self, Symbols};
use super::types::TypeDb;
use super::user;

/// Abaixo daqui, a metade de usuário.
pub const USER_LIMIT: u64 = 0x8000_0000_0000;

/// Imagens guardadas no máximo (as que armaram breakpoints adiados).
const IMAGE_CACHE_LIMIT: usize = 64;

/// Para quais processos um breakpoint vale.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ProcessFilter {
    /// Sem `/p`: o processo escolhido na criação (o campo `process` do
    /// breakpoint) ou, sem nenhum, o primeiro que carregar o módulo.
    #[default]
    Unset,
    /// Todos os processos (`/p *`).
    Any,
    /// Os processos com este nome de imagem (`/p dwm.exe`).
    Name(String),
    /// Este EPROCESS (`/p <pid|eprocess>`).
    Process(u64),
}

impl ProcessFilter {
    /// O texto do `/p` (o `bl` e o arquivo de sessão).
    pub fn text(&self) -> String {
        match self {
            Self::Unset => String::new(),
            Self::Any => "*".into(),
            Self::Name(name) => name.clone(),
            Self::Process(eprocess) => format!("{eprocess:#x}"),
        }
    }

    /// Vale para o processo `eprocess` de nome `name`.
    pub fn matches(&self, eprocess: u64, name: &str) -> bool {
        match self {
            Self::Unset | Self::Any => true,
            Self::Name(wanted) => same_process_name(wanted, name),
            Self::Process(wanted) => *wanted == eprocess,
        }
    }

    /// Com nome ou `*`: o breakpoint pedido vira modelo.
    pub fn makes_template(&self) -> bool {
        matches!(self, Self::Any | Self::Name(_))
    }
}

/// O que um breakpoint tem além de `Breakpoint`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scope {
    pub filter: ProcessFilter,
    /// Modelo: nunca é armado; cada processo que o filtro aceita ganha uma
    /// instância.
    pub template: bool,
    /// A instância de um modelo: o número dele.
    pub parent: Option<u32>,
    /// Desliga depois de tantos acertos que pararam ou registraram (0 = sem
    /// limite).
    pub max_hits: u64,
    /// Os acertos que pararam ou registraram.
    pub counted: u64,
    /// O módulo do símbolo (o que a carga de imagem procura).
    pub module: String,
}

/// O breakpoint escolhido para um acerto.
pub(crate) enum Pick {
    Found(usize),
    /// Todos os candidatos são de outros processos: a máquina segue.
    Other,
    Nothing,
}

/// O mesmo processo pelo nome da imagem (sem diferença de caixa; `dwm` vale
/// `dwm.exe`).
pub fn same_process_name(wanted: &str, name: &str) -> bool {
    let (wanted, name) = (wanted.trim().to_ascii_lowercase(), name.trim().to_ascii_lowercase());
    !wanted.is_empty() && !name.is_empty() && (wanted == name || name.strip_suffix(".exe") == Some(wanted.as_str()) || wanted.strip_suffix(".exe") == Some(name.as_str()))
}

/// O arquivo de uma imagem (caminho ou nome) é o módulo pedido (`dwmcore`
/// ou `dwmcore.dll`).
pub fn module_matches(wanted: &str, path: &str) -> bool {
    let file = symbols::base_name(path.trim()).to_ascii_lowercase();
    let wanted = wanted.trim().to_ascii_lowercase();
    !wanted.is_empty() && (file == wanted || file.rsplit_once('.').is_some_and(|(stem, _)| stem == wanted))
}

/// O módulo de que uma expressão depende: o de `módulo!nome` ou o nome solto
/// do começo seguido de `+`/`-` (`dwmcore+0x5d7e8`).
pub fn expression_module(expression: &str) -> Option<String> {
    let characters: Vec<char> = expression.chars().collect();
    let module_character = |character: char| character.is_ascii_alphanumeric() || character == '_' || character == '.';
    for (index, &character) in characters.iter().enumerate() {
        // O `!` de `módulo!nome`, não o de `!=` nem o `!` unário.
        if character != '!' || characters.get(index + 1) == Some(&'=') {
            continue;
        }
        let mut start = index;
        while start > 0 && module_character(characters[start - 1]) {
            start -= 1;
        }
        if start < index && characters[start].is_ascii_alphabetic() {
            return Some(characters[start..index].iter().collect());
        }
    }
    let trimmed = expression.trim_start();
    let name: String = trimmed.chars().take_while(|&character| module_character(character)).collect();
    let next = trimmed[name.len()..].trim_start().chars().next();
    (name.chars().next().is_some_and(|first| first.is_ascii_alphabetic()) && matches!(next, None | Some('+') | Some('-'))).then_some(name)
}

/// Os tipos que viram bytes ou comparadores num endereço (os adiáveis).
fn addressable(kind: BreakpointKind) -> bool {
    !matches!(kind, BreakpointKind::Module | BreakpointKind::Event)
}

/// O lugar armado de um tipo: o breakpoint de memória vale por páginas
/// inteiras.
pub(crate) fn placement(kind: BreakpointKind, address: u64, length: u64) -> (u64, u64) {
    if kind.is_memory() {
        let start = address & !0xFFF;
        let end = (address + length.max(1) + 0xFFF) & !0xFFF;
        (start, end - start)
    } else {
        (address, length)
    }
}

/// O pedido que recria um breakpoint (as instâncias de um modelo).
fn request_from(breakpoint: &Breakpoint) -> BreakpointRequest {
    let mut request = BreakpointRequest::new(breakpoint.kind, &breakpoint.expression);
    request.length = breakpoint.length;
    request.condition = breakpoint.condition.clone();
    request.pass_count = breakpoint.pass_count;
    request.enabled = breakpoint.enabled;
    request.log = breakpoint.log.clone();
    request.command = breakpoint.command.clone();
    request.group = breakpoint.group.clone();
    request.options = breakpoint.options.clone();
    request
}

/// A imagem de um conjunto de símbolos de um módulo só cita um PDB que
/// ainda não está nos símbolos dela.
fn missing_pdb(image: &Symbols) -> bool {
    image.modules.first().is_some_and(|module| module.pdb.is_none() && module.pdb_id.is_some())
}

/// O PDB citado pela imagem de um conjunto de símbolos de um módulo só.
fn pdb_name(image: &Symbols) -> Option<String> {
    let module = image.modules.first()?;
    let (_, _, name) = module.image.as_ref()?.rsds()?;
    Some(symbols::base_name(&name).to_string())
}

/// As expressões com uma imagem recém-carregada na frente dos símbolos da
/// sessão: o processo dela pode não ser o escolhido, e a mesma DLL pode
/// estar em outra base nos símbolos de outro processo.
struct ImageEnvironment<'a> {
    client: &'a mut Client,
    image: &'a Symbols,
}

impl Environment for ImageEnvironment<'_> {
    fn register(&mut self, name: &str) -> Result<u64, String> {
        self.client.register(name)
    }

    fn read_memory(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
        self.client.read_memory(address, length)
    }

    fn symbol(&mut self, name: &str) -> Result<u64, String> {
        if let Ok(address) = self.image.lookup(name) {
            return Ok(address);
        }
        // `dwmcore+0x5d7e8`: o módulo sozinho é a base.
        if let Some(module) = self.image.module_named(name) {
            return Ok(module.base);
        }
        if let Some((module, _)) = name.split_once('!') {
            if self.image.module_named(module).is_some() {
                return Err(format!("{name}: simbolo nao encontrado (nem nos exports nem no PDB; use {module}+0xRVA)"));
            }
        }
        Environment::symbol(&mut *self.client, name)
    }

    fn variable(&mut self, name: &str) -> Option<u64> {
        self.client.variables.get(name).copied()
    }

    fn is_register(&self, name: &str) -> bool {
        registers::find(name).is_some()
    }

    fn types(&mut self) -> Option<Arc<TypeDb>> {
        self.client.type_database()
    }

    fn image_entry(&mut self, module: &str) -> Result<u64, String> {
        match self.image.module_named(module) {
            Some(found) => found.image.as_ref().map(|image| found.base + image.header.entry_point as u64).ok_or_else(|| format!("$iment({module}): sem o arquivo do modulo nesta maquina")),
            None => Environment::image_entry(&mut *self.client, module),
        }
    }
}

impl Client {
    /// O escopo de um breakpoint: filtro de processo, modelo ou instância,
    /// limite de acertos.
    pub fn breakpoint_scope(&self, id: u32) -> Option<&Scope> {
        self.scopes.get(&id)
    }

    /// O escopo em texto para as listas: o `/p`, modelo ou instância e o
    /// limite de acertos (vazio sem nada disso).
    pub fn breakpoint_scope_text(&self, id: u32) -> String {
        let Some(scope) = self.scopes.get(&id) else { return String::new() };
        let mut text = String::new();
        if let Some(parent) = scope.parent {
            text.push_str(&format!(" instancia de #{parent}"));
        } else if scope.filter != ProcessFilter::Unset {
            text.push_str(&format!(" /p {}", scope.filter.text()));
        }
        if scope.template {
            text.push_str(&format!(" modelo ({} instancias)", self.breakpoint_instances(id).len()));
        }
        if scope.max_hits != 0 {
            text.push_str(&format!(" max {} ({} contados)", scope.max_hits, scope.counted));
        }
        text
    }

    /// As instâncias de um modelo.
    pub fn breakpoint_instances(&self, template: u32) -> Vec<u32> {
        self.breakpoints.iter().filter(|breakpoint| self.scopes.get(&breakpoint.id).is_some_and(|scope| scope.parent == Some(template))).map(|breakpoint| breakpoint.id).collect()
    }

    /// As linhas dos breakpoints de log também vão à saída padrão na hora em
    /// que saem (o prompt e os roteiros, que não leem o console).
    pub fn set_log_echo(&mut self, on: bool) {
        self.log_echo = on;
    }

    /// O filtro do texto de um `/p`: vazio, `*`, PID ou EPROCESS (número,
    /// `$nome`, `@reg`) ou nome de imagem.
    pub fn parse_process_filter(&mut self, text: &str) -> Result<ProcessFilter, String> {
        let text = text.trim();
        if text.is_empty() {
            return Ok(ProcessFilter::Unset);
        }
        if text == "*" {
            return Ok(ProcessFilter::Any);
        }
        let number = if text.starts_with(['$', '@']) { Some(self.evaluate(text)?) } else { super::parse_number(text) };
        let Some(value) = number else { return Ok(ProcessFilter::Name(text.to_string())) };
        let processes = self.processes()?;
        let process = processes.iter().find(|process| process.eprocess == value || process.pid == value).ok_or_else(|| format!("/p {text}: processo nao encontrado (ps)"))?;
        self.process_names.insert(process.eprocess, process.name.clone());
        Ok(ProcessFilter::Process(process.eprocess))
    }

    /// O nome de imagem de um processo (pelo `ps`, guardado).
    fn process_name(&mut self, eprocess: u64) -> String {
        if let Some(name) = self.process_names.get(&eprocess) {
            return name.clone();
        }
        if let Ok(list) = self.processes() {
            for process in list {
                self.process_names.insert(process.eprocess, process.name);
            }
        }
        self.process_names.get(&eprocess).cloned().unwrap_or_default()
    }

    /// O processo corrente da parada (EPROCESS): o da thread de usuário ou o
    /// do CR3 do processador.
    fn stop_process(&mut self) -> Option<u64> {
        if self.stopped_in_user_mode() {
            if let Some(context) = &self.process_context {
                return Some(context.eprocess);
            }
        }
        let text = self.monitor(".process").ok()?;
        user::parse_current_process(&text).map(|(eprocess, _)| eprocess)
    }

    /// Entre os breakpoints que batem com a parada (índices), o que vale
    /// para o processo corrente.
    pub(crate) fn pick_for_process(&mut self, candidates: &[usize]) -> Pick {
        let Some(&first) = candidates.first() else { return Pick::Nothing };
        let filtered = candidates.iter().any(|&index| {
            let breakpoint = &self.breakpoints[index];
            breakpoint.process != 0 || self.scopes.get(&breakpoint.id).is_some_and(|scope| matches!(scope.filter, ProcessFilter::Name(_) | ProcessFilter::Process(_)))
        });
        if !filtered {
            return Pick::Found(first);
        }
        // Sem saber o processo corrente, vale o primeiro (o stub só para nos
        // processos donos de um breakpoint de usuário).
        let Some(current) = self.stop_process() else { return Pick::Found(first) };
        for &index in candidates {
            let (id, process) = (self.breakpoints[index].id, self.breakpoints[index].process);
            let fits = if process != 0 {
                process == current
            } else {
                match self.scopes.get(&id).map(|scope| scope.filter.clone()) {
                    Some(ProcessFilter::Name(wanted)) => {
                        let name = self.process_name(current);
                        same_process_name(&wanted, &name)
                    }
                    Some(ProcessFilter::Process(wanted)) => wanted == current,
                    _ => true,
                }
            };
            if fits {
                return Pick::Found(index);
            }
        }
        Pick::Other
    }

    /// Conta um acerto que parou ou registrou; com o limite (`/max`)
    /// alcançado, desliga o breakpoint (o modelo, numa instância) e devolve
    /// `true`.
    pub(crate) fn count_hit(&mut self, id: u32) -> bool {
        let target = self.scopes.get(&id).and_then(|scope| scope.parent).unwrap_or(id);
        let Some(scope) = self.scopes.get_mut(&target) else { return false };
        scope.counted += 1;
        if scope.max_hits == 0 || scope.counted < scope.max_hits {
            return false;
        }
        let max = scope.max_hits;
        match self.set_breakpoint_enabled(target, false) {
            Ok(()) => self.push_log(format!("[bp #{target}] limite de {max} acertos: desligado")),
            Err(error) => self.push_log(format!("[bp #{target}] limite de {max} acertos, mas nao desligou: {error}")),
        }
        true
    }

    /// Um breakpoint adiado que só pode ser de usuário (com processo, filtro
    /// ou modelo): a notificação de carga do kernel não precisa parar por ele.
    pub(crate) fn user_only_pending(&self, breakpoint: &Breakpoint) -> bool {
        breakpoint.process != 0 || self.scopes.get(&breakpoint.id).is_some_and(|scope| scope.template || scope.filter != ProcessFilter::Unset)
    }

    /// Os pontos de evento que os breakpoints adiados e os de processo
    /// precisam: (carga de imagem, saída de processo).
    pub(crate) fn internal_event_needs(&self) -> (bool, bool) {
        let image = self.breakpoints.iter().any(|breakpoint| breakpoint.enabled && breakpoint.pending && addressable(breakpoint.kind));
        let process = self.breakpoints.iter().any(|breakpoint| breakpoint.process != 0 && addressable(breakpoint.kind));
        (image, process)
    }

    /// Avalia com uma imagem na frente dos símbolos da sessão.
    pub(crate) fn evaluate_with_image(&mut self, expression: &str, image: &Symbols) -> Result<u64, String> {
        let mut environment = ImageEnvironment { client: self, image };
        expr::evaluate_number(&mut environment, expression)
    }

    fn load_image_symbols(&self, path: &str, base: u64, end: u64, eprocess: u64) -> Symbols {
        let mut image = Symbols::default();
        image.store = self.symbols.store.clone();
        image.set_user_modules(eprocess, &[(base, end, path.to_string())], &self.root);
        image
    }

    /// Os símbolos de uma imagem, só ela: exports e públicos do PDB. Um PDB
    /// que falta é baixado agora, com pressa, e a máquina espera parada (até
    /// o prazo do cache de símbolos, `OPENNT_SYMBOL_WAIT`); sem ele, ficam os
    /// exports e o `módulo+0xRVA`.
    pub(crate) fn image_symbols(&mut self, path: &str, base: u64, end: u64, eprocess: u64) -> Symbols {
        if let Some(cached) = self.image_cache.remove(&(path.to_ascii_lowercase(), base)) {
            if !missing_pdb(&cached) {
                return cached;
            }
        }
        let mut image = self.load_image_symbols(path, base, end, eprocess);
        if !missing_pdb(&image) {
            return image;
        }
        let pdb = pdb_name(&image).unwrap_or_default();
        self.push_log(format!("[bu] baixando o PDB {pdb} de {} (a maquina espera parada)", symbols::base_name(path)));
        image.wait_pdb_at(base);
        if missing_pdb(&image) {
            self.push_log(format!("[bu] o PDB {pdb} nao chegou a tempo: so os exports de {}", symbols::base_name(path)));
        }
        image
    }

    pub(crate) fn cache_image(&mut self, path: &str, base: u64, image: Symbols) {
        if self.image_cache.len() >= IMAGE_CACHE_LIMIT {
            self.image_cache.clear();
        }
        self.image_cache.insert((path.to_ascii_lowercase(), base), image);
    }

    /// Um módulo de usuário de um processo pelo nome (a PEB.Ldr e, para uma
    /// imagem ainda fora dela, o VAD): base, fim e caminho. O processo das
    /// leituras da sessão volta no fim.
    pub(crate) fn locate_module(&mut self, eprocess: u64, module: &str) -> Result<Option<(u64, u64, String)>, String> {
        let text = self.monitor(&format!(".process {eprocess:#x}"))?;
        let mut found = None;
        if let Some(context) = user::parse_process_context(&text) {
            if context.peb != 0 {
                if let Ok(modules) = user::read_loader_list(self, context.peb) {
                    found = modules.into_iter().find(|entry| module_matches(module, &entry.name) || module_matches(module, &entry.path)).map(|entry| (entry.base, entry.base + entry.size.max(0x1000), if entry.path.is_empty() { entry.name } else { entry.path }));
                }
            }
        }
        if found.is_none() {
            if let Ok(regions) = self.regions(&format!("{eprocess:#x}")) {
                found = regions.into_iter().find(|region| region.kind == "Image" && module_matches(module, &region.name)).map(|region| (region.base, region.base + region.size, region.name));
            }
        }
        let restore = self.process_context.as_ref().map_or("0".to_string(), |context| format!("{:#x}", context.eprocess));
        let _ = self.monitor(&format!(".process {restore}"));
        Ok(found)
    }

    /// Avalia uma expressão de usuário em outro processo: o módulo dela pelos
    /// módulos daquele processo.
    pub(crate) fn evaluate_in_process(&mut self, expression: &str, module: &str, eprocess: u64) -> Result<u64, String> {
        match self.evaluate(expression) {
            // Um endereço de sistema (ou sem módulo) vale em qualquer processo.
            Ok(address) if address >= USER_LIMIT || module.is_empty() => return Ok(address),
            Err(error) if module.is_empty() => return Err(error),
            _ => {}
        }
        let (base, end, path) = self.locate_module(eprocess, module)?.ok_or_else(|| format!("modulo {module} nao carregado no processo {eprocess:#x}"))?;
        let image = self.image_symbols(&path, base, end, eprocess);
        let result = self.evaluate_with_image(expression, &image);
        self.cache_image(&path, base, image);
        result
    }

    /// Cria a instância de um modelo no processo `eprocess` (o breakpoint é
    /// armado pela raiz dele).
    pub(crate) fn add_instance(&mut self, template: u32, address: u64, eprocess: u64, process_name: &str) -> Result<Breakpoint, String> {
        let model = self.breakpoints.iter().find(|breakpoint| breakpoint.id == template).cloned().ok_or_else(|| format!("breakpoint {template} nao existe"))?;
        let module = self.scopes.get(&template).map(|scope| scope.module.clone()).unwrap_or_default();
        let (address, length) = placement(model.kind, address, model.length);
        self.insert_in(model.kind, address, length, true, eprocess)?;
        let mut request = request_from(&model);
        request.length = length;
        request.process = eprocess;
        let breakpoint = self.push_breakpoint(&request, address, false);
        self.scopes.insert(breakpoint.id, Scope { filter: ProcessFilter::Process(eprocess), parent: Some(template), module, ..Scope::default() });
        if !model.options.silent {
            self.push_log(format!("[bp #{template}] instancia #{} em {address:#x} no processo {process_name} (EPROCESS {eprocess:#x})", breakpoint.id));
        }
        Ok(breakpoint)
    }

    /// Cria as instâncias de um modelo nos processos que já existem e têm o
    /// módulo; devolve quantas.
    pub(crate) fn instantiate_existing(&mut self, template: u32) -> usize {
        let Some(scope) = self.scopes.get(&template).cloned() else { return 0 };
        let Some(model) = self.breakpoints.iter().find(|breakpoint| breakpoint.id == template).cloned() else { return 0 };
        let mut created = 0;
        for process in self.processes().unwrap_or_default() {
            // O Idle e o System não têm metade de usuário.
            if process.pid == 0 || process.pid == 4 || !scope.filter.matches(process.eprocess, &process.name) {
                continue;
            }
            if self.breakpoints.iter().any(|breakpoint| breakpoint.process == process.eprocess && self.scopes.get(&breakpoint.id).is_some_and(|entry| entry.parent == Some(template))) {
                continue;
            }
            let Ok(Some((base, end, path))) = self.locate_module(process.eprocess, &scope.module) else { continue };
            let image = self.image_symbols(&path, base, end, process.eprocess);
            let result = self.evaluate_with_image(&model.expression, &image);
            self.cache_image(&path, base, image);
            match result {
                Ok(address) if address < USER_LIMIT => match self.add_instance(template, address, process.eprocess, &process.name) {
                    Ok(_) => created += 1,
                    Err(error) => self.push_log(format!("[bp #{template}] {} (PID {}): {error}", process.name, process.pid)),
                },
                Ok(_) => {}
                Err(error) => self.push_log(format!("[bp #{template}] {} (PID {}): {error}", process.name, process.pid)),
            }
        }
        created
    }

    /// Cria um modelo (`/p nome` ou `/p *`): sempre adiado, com as
    /// instâncias dos processos que já têm o módulo.
    pub(crate) fn add_template(&mut self, request: &BreakpointRequest, filter: ProcessFilter, module: String) -> Result<Breakpoint, String> {
        if module.is_empty() {
            return Err("um breakpoint por nome de processo (ou /p *) precisa de um simbolo com modulo: modulo!nome ou modulo+0xRVA".into());
        }
        let template = self.push_breakpoint(request, 0, true);
        self.scopes.insert(template.id, Scope { filter, template: true, max_hits: request.max_hits, module, ..Scope::default() });
        if request.enabled {
            self.instantiate_existing(template.id);
        }
        self.refresh_hooks()?;
        Ok(template)
    }

    /// A parada no ponto de evento de imagem (base em RDI, tamanho em RSI,
    /// PID em RDX, nome UTF-8 em RCX/R8): arma os breakpoints adiados cujo
    /// módulo é a imagem nova, no processo dela (PID 0 = imagem de sistema).
    pub(crate) fn on_image_event(&mut self) {
        let read = |client: &mut Client, name: &str| client.register(name).unwrap_or(0);
        let (base, size, pid, name_pointer, name_length) = (read(self, "rdi"), read(self, "rsi"), read(self, "rdx"), read(self, "rcx"), read(self, "r8"));
        if size == 0 || name_pointer == 0 || name_length == 0 || name_length >= 0x1000 {
            return;
        }
        let waiting: Vec<u32> = self.breakpoints.iter().filter(|breakpoint| breakpoint.enabled && breakpoint.pending && addressable(breakpoint.kind)).map(|breakpoint| breakpoint.id).collect();
        if waiting.is_empty() {
            return;
        }
        let Ok(bytes) = self.read_memory(name_pointer, name_length as usize) else { return };
        let path = String::from_utf8_lossy(&bytes).to_string();
        let matching: Vec<u32> = waiting.into_iter().filter(|id| self.scopes.get(id).is_some_and(|scope| module_matches(&scope.module, &path))).collect();
        if matching.is_empty() {
            return;
        }
        let system = pid == 0;
        // O processo da imagem; ainda fora da lista (o executável e a ntdll
        // de um processo que nasce), o breakpoint vai pela raiz da parada.
        let (eprocess, process_name) = if system {
            (0, String::from("System"))
        } else {
            match self.processes().unwrap_or_default().into_iter().find(|process| process.pid == pid) {
                Some(process) => {
                    self.process_names.insert(process.eprocess, process.name.clone());
                    (process.eprocess, process.name)
                }
                None => (0, format!("PID {pid}")),
            }
        };
        let mut image: Option<Symbols> = None;
        for id in matching {
            let Some(breakpoint) = self.breakpoints.iter().find(|breakpoint| breakpoint.id == id).cloned() else { continue };
            let scope = self.scopes.get(&id).cloned().unwrap_or_default();
            if !system {
                let fits = match &scope.filter {
                    ProcessFilter::Unset => breakpoint.process == 0 || breakpoint.process == eprocess,
                    filter => filter.matches(eprocess, &process_name),
                };
                let duplicate = scope.template && eprocess != 0 && self.breakpoints.iter().any(|other| other.process == eprocess && self.scopes.get(&other.id).is_some_and(|entry| entry.parent == Some(id)));
                if !fits || duplicate {
                    continue;
                }
            }
            if image.is_none() {
                image = Some(self.image_symbols(&path, base, base + size, eprocess));
            }
            let Some(symbols_of_image) = image.as_ref() else { continue };
            let resolved = self.evaluate_with_image(&breakpoint.expression, symbols_of_image);
            let described = resolved.as_ref().map(|address| symbols_of_image.describe(*address)).unwrap_or_default();
            let address = match resolved {
                // Um símbolo de usuário numa imagem de sistema (ou o contrário)
                // não é desta carga.
                Ok(address) if system == (address >= USER_LIMIT) => address,
                Ok(_) => continue,
                Err(error) => {
                    self.push_log(format!("[bp #{id}] {}: {error}", symbols::base_name(&path)));
                    continue;
                }
            };
            if scope.template && !system {
                // Sem o EPROCESS, a instância não teria como sair com o
                // processo.
                if eprocess == 0 {
                    self.push_log(format!("[bp #{id}] {process_name} fora da lista de processos: sem instancia nesta carga"));
                    continue;
                }
                if let Err(error) = self.add_instance(id, address, eprocess, &process_name) {
                    self.push_log(format!("[bp #{id}] {process_name}: {error}"));
                }
                continue;
            }
            // Um breakpoint comum (ou um modelo cujo módulo é um driver: vira
            // breakpoint de sistema, com o filtro valendo no acerto).
            let target = if system { 0 } else { eprocess };
            let (address, length) = placement(breakpoint.kind, address, breakpoint.length);
            if let Err(error) = self.insert_in(breakpoint.kind, address, length, true, target) {
                self.push_log(format!("[bp #{id}] {}: {error}", symbols::base_name(&path)));
                continue;
            }
            // Num driver, um `/p <pid>` continua filtrando pelo processo no
            // acerto; o processo escolhido na criação não vale mais.
            let process = match (system, &scope.filter) {
                (true, ProcessFilter::Process(wanted)) => *wanted,
                (true, _) => 0,
                (false, _) => target,
            };
            if let Some(entry) = self.breakpoints.iter_mut().find(|entry| entry.id == id) {
                entry.address = address;
                entry.length = length;
                entry.pending = false;
                entry.process = process;
            }
            if let Some(entry) = self.scopes.get_mut(&id) {
                entry.template = false;
            }
            if !breakpoint.options.silent {
                self.push_log(format!("[bp #{id}] armado em {address:#x} {described} ({process_name})"));
            }
        }
        if let Some(symbols_of_image) = image {
            self.cache_image(&path, base, symbols_of_image);
        }
        let _ = self.refresh_hooks();
    }

    /// A parada no evento de processo saindo: o stub já tirou os bytes do
    /// processo. As instâncias dele somem; os outros breakpoints dele voltam
    /// a adiados, e um `bu` sem `/p` segue para o próximo processo com o
    /// mesmo nome.
    pub(crate) fn on_process_exit(&mut self, eprocess: u64) {
        if eprocess == 0 || !self.breakpoints.iter().any(|breakpoint| breakpoint.process == eprocess) {
            self.process_names.remove(&eprocess);
            return;
        }
        let name = self.process_name(eprocess);
        let affected: Vec<u32> = self.breakpoints.iter().filter(|breakpoint| breakpoint.process == eprocess && addressable(breakpoint.kind)).map(|breakpoint| breakpoint.id).collect();
        for id in affected {
            let scope = self.scopes.get(&id).cloned().unwrap_or_default();
            if scope.parent.is_some() {
                self.breakpoints.retain(|breakpoint| breakpoint.id != id);
                self.scopes.remove(&id);
                continue;
            }
            let Some(breakpoint) = self.breakpoints.iter().find(|entry| entry.id == id).cloned() else { continue };
            if !breakpoint.pending && breakpoint.address >= USER_LIMIT {
                // Um breakpoint de sistema filtrado por este processo nunca
                // mais vale: sai do alvo e fica desligado.
                if breakpoint.enabled && self.set_breakpoint_enabled(id, false).is_ok() && !breakpoint.options.silent {
                    self.push_log(format!("[bp #{id}] o processo {name} ({eprocess:#x}) saiu: desligado"));
                }
                continue;
            }
            // Um `bu`/`bp` sem `/p` segue o nome do processo; um `/p <pid>`
            // fica adiado e desligado (aquela instância não volta).
            let follow = matches!(scope.filter, ProcessFilter::Unset | ProcessFilter::Name(_)) && !name.is_empty();
            let module = if scope.module.is_empty() { expression_module(&breakpoint.expression).unwrap_or_default() } else { scope.module.clone() };
            if let Some(entry) = self.breakpoints.iter_mut().find(|entry| entry.id == id) {
                entry.pending = true;
                if follow {
                    entry.process = 0;
                } else {
                    entry.enabled = false;
                }
            }
            let record = self.scopes.entry(id).or_default();
            record.module = module;
            if follow && record.filter == ProcessFilter::Unset {
                record.filter = ProcessFilter::Name(name.clone());
            }
            if !breakpoint.options.silent {
                let line = if follow { format!("[bp #{id}] o processo {name} saiu: adiado ate o proximo {name}") } else { format!("[bp #{id}] o processo {eprocess:#x} saiu: adiado e desligado") };
                self.push_log(line);
            }
        }
        self.process_names.remove(&eprocess);
        let _ = self.refresh_hooks();
    }

    /// Arma (ou tira) os pontos de evento e a notificação de carga conforme
    /// os breakpoints: primeiro os eventos, que dizem se a notificação ainda
    /// precisa parar pelos adiados.
    pub(crate) fn refresh_hooks(&mut self) -> Result<(), String> {
        self.update_event_hooks()?;
        self.update_load_hook()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_of_an_expression() {
        assert_eq!(expression_module("dwmcore!CD2DContext::PopulateEffectTable+0x96").as_deref(), Some("dwmcore"));
        assert_eq!(expression_module("d3d10warp.dll!UMDevice::MSCB_SetError").as_deref(), Some("d3d10warp.dll"));
        assert_eq!(expression_module("poi(@rsp)-d2d1!DoStackCapture+0x261a74").as_deref(), Some("d2d1"));
        assert_eq!(expression_module("dwmcore+0x5d7e8").as_deref(), Some("dwmcore"));
        assert_eq!(expression_module("Windows.UI.Logon+0x10").as_deref(), Some("Windows.UI.Logon"));
        assert_eq!(expression_module("@rax != 0"), None);
        assert_eq!(expression_module("kernel::ntos::ke::run_kernel_tasks"), None);
        assert_eq!(expression_module("0x7ff600001000"), None);
        assert_eq!(expression_module("poi(@rsp+8)"), None);
    }

    #[test]
    fn names_of_modules_and_processes() {
        assert!(module_matches("dwmcore", r"\Windows\System32\dwmcore.dll"));
        assert!(module_matches("DWMCORE.DLL", "dwmcore.dll"));
        assert!(!module_matches("dwm", r"\Windows\System32\dwmcore.dll"));
        assert!(!module_matches("", "dwmcore.dll"));
        assert!(same_process_name("dwm.exe", "dwm.exe"));
        assert!(same_process_name("dwm", "DWM.EXE"));
        assert!(same_process_name("dwm.exe", "dwm"));
        assert!(!same_process_name("dwm.exe", "LogonUI.exe"));
        assert!(!same_process_name("", "dwm.exe"));
    }

    #[test]
    fn process_filters() {
        let name = ProcessFilter::Name("dwm.exe".into());
        assert!(name.matches(0x10, "dwm.exe") && !name.matches(0x10, "csrss.exe"));
        assert!(name.makes_template() && ProcessFilter::Any.makes_template());
        assert!(!ProcessFilter::Process(0x10).makes_template() && !ProcessFilter::Unset.makes_template());
        assert!(ProcessFilter::Process(0x10).matches(0x10, "") && !ProcessFilter::Process(0x10).matches(0x20, ""));
        assert_eq!(ProcessFilter::Any.text(), "*");
        assert_eq!(name.text(), "dwm.exe");
        assert_eq!(ProcessFilter::Unset.text(), "");
    }

    #[test]
    fn memory_breakpoints_cover_whole_pages() {
        assert_eq!(placement(BreakpointKind::MemoryWrite, 0x7ff6_0000_1010, 0x20), (0x7ff6_0000_1000, 0x1000));
        assert_eq!(placement(BreakpointKind::Software, 0x7ff6_0000_1010, 1), (0x7ff6_0000_1010, 1));
    }
}
