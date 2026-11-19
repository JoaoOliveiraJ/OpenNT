//! A navegação do opennt-re: o histórico de idas da desmontagem (voltar e
//! avançar, Alt+Esquerda e Alt+Direita ou os botões laterais do mouse), a
//! janela Ir para com a busca aproximada sobre todos os símbolos
//! carregados e os marcadores (ligar, próximo, anterior, a lista).
//!
//! A busca aproximada roda numa thread própria: com todos os PDBs
//! carregados o índice tem centenas de milhares de nomes, e filtrar isso a
//! cada tecla na thread da janela trava a interface. A janela manda a busca
//! a cada mudança do texto e lê o último resultado pronto; uma busca nova
//! cancela a que ainda está rodando.
//!
//! O histórico guarda módulo + RVA (como os comentários e os marcadores),
//! então continua valendo depois que um módulo muda de base.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use eframe::egui::{self, Key, Modifiers, RichText, TextStyle, Ui, Vec2};
use opennt_kd::analysis::notes::Location;

use crate::app::{current_rip, hex, hint, mono, palette, Tab, UiState};
use crate::backend::{Request, Status};
use crate::preferences::Action;

/// Quantas linhas a busca devolve.
pub const RESULT_LIMIT: usize = 200;

// ---- histórico ----

/// O histórico de idas: cada ida guarda de onde se saiu; voltar e avançar
/// andam pelas duas pilhas.
#[derive(Clone, Debug)]
pub struct History<T> {
    back: Vec<T>,
    forward: Vec<T>,
    limit: usize,
}

impl<T: Clone + PartialEq> History<T> {
    pub fn new(limit: usize) -> Self {
        History { back: Vec::new(), forward: Vec::new(), limit: limit.max(1) }
    }

    /// Uma ida nova saindo de `from` (para `to`, quando já se sabe): o
    /// caminho à frente some. Sem origem, ou indo para o mesmo lugar, nada
    /// muda.
    pub fn visit(&mut self, from: Option<T>, to: Option<&T>) {
        let Some(from) = from else { return };
        if to == Some(&from) {
            return;
        }
        if self.back.last() != Some(&from) {
            self.back.push(from);
            if self.back.len() > self.limit {
                let excess = self.back.len() - self.limit;
                self.back.drain(..excess);
            }
        }
        self.forward.clear();
    }

    /// Volta: o lugar anterior (pulando os iguais a `current`); `current`
    /// vai para a pilha da frente.
    pub fn back(&mut self, current: Option<T>) -> Option<T> {
        Self::step(&mut self.back, &mut self.forward, current, self.limit)
    }

    /// Avança: o contrário de `back`.
    pub fn forward(&mut self, current: Option<T>) -> Option<T> {
        Self::step(&mut self.forward, &mut self.back, current, self.limit)
    }

    fn step(from: &mut Vec<T>, to: &mut Vec<T>, current: Option<T>, limit: usize) -> Option<T> {
        while current.is_some() && from.last() == current.as_ref() {
            from.pop();
        }
        let target = from.pop()?;
        if let Some(current) = current {
            if to.last() != Some(&current) {
                to.push(current);
                if to.len() > limit {
                    to.remove(0);
                }
            }
        }
        Some(target)
    }

    /// Para onde `back` iria.
    pub fn peek_back(&self) -> Option<&T> {
        self.back.last()
    }

    /// Para onde `forward` iria.
    pub fn peek_forward(&self) -> Option<&T> {
        self.forward.last()
    }

    /// Os lugares de trás, do mais recente ao mais antigo.
    pub fn recent(&self) -> impl Iterator<Item = &T> {
        self.back.iter().rev()
    }

    pub fn clear(&mut self) {
        self.back.clear();
        self.forward.clear();
    }
}

impl<T: Clone + PartialEq> Default for History<T> {
    fn default() -> Self {
        History::new(200)
    }
}

// ---- busca aproximada ----

/// Um nome do índice de símbolos que o backend publica a cada troca de
/// módulos (todos os símbolos de todos os módulos carregados).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SymbolEntry {
    /// `modulo!nome` (os do kernel sem o módulo, como no autocompletar).
    pub name: String,
    pub address: u64,
    /// Função (senão, dado).
    pub function: bool,
}

/// De onde veio uma linha da janela Ir para.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoundKind {
    Function,
    Data,
    Label,
    Bookmark,
    Recent,
}

impl FoundKind {
    pub fn tag(self) -> &'static str {
        match self {
            FoundKind::Function => "função",
            FoundKind::Data => "dado",
            FoundKind::Label => "rótulo",
            FoundKind::Bookmark => "marcador",
            FoundKind::Recent => "recente",
        }
    }
}

/// Uma linha da janela Ir para.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub name: String,
    pub address: u64,
    pub kind: FoundKind,
    pub score: i32,
}

/// Começo de palavra num nome de símbolo: o início, depois de um
/// separador, a maiúscula depois de minúscula e a letra depois de dígito.
fn word_start(name: &[u8], index: usize) -> bool {
    if index == 0 {
        return true;
    }
    let (previous, current) = (name[index - 1], name[index]);
    matches!(previous, b'!' | b'_' | b':' | b'.' | b'@' | b'?' | b'$' | b' ' | b'<' | b'>' | b'-' | b'+' | b'`')
        || (previous.is_ascii_lowercase() && current.is_ascii_uppercase())
        || (previous.is_ascii_digit() && current.is_ascii_alphabetic())
}

/// Onde `needle` (em minúsculas) aparece em `haystack`, sem diferença de
/// caixa.
fn find_ignoring_case(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&start| haystack[start..start + needle.len()].iter().zip(needle).all(|(byte, wanted)| byte.to_ascii_lowercase() == *wanted))
}

fn equal_ignoring_case(name: &[u8], lower: &[u8]) -> bool {
    name.len() == lower.len() && name.iter().zip(lower).all(|(byte, wanted)| byte.to_ascii_lowercase() == *wanted)
}

/// As letras de `word` (em minúsculas) aparecem em `name` nesta ordem.
fn is_subsequence(word: &[u8], name: &[u8]) -> bool {
    let mut letters = word.iter().peekable();
    for byte in name {
        if letters.peek().is_some_and(|wanted| byte.to_ascii_lowercase() == **wanted) {
            letters.next();
        }
    }
    letters.peek().is_none()
}

/// Onde cada letra de `word` cai em `name`: a primeira ocorrência, ou
/// (com `prefer_starts`) a próxima que começa uma palavra, quando a letra
/// não segue a anterior.
fn align(word: &[u8], name: &[u8], prefer_starts: bool) -> Option<Vec<usize>> {
    let mut positions: Vec<usize> = Vec::with_capacity(word.len());
    let mut from = 0;
    for &wanted in word {
        let hits = |offset: &usize| name[*offset].to_ascii_lowercase() == wanted;
        let next = (from..name.len()).find(hits)?;
        let follows = positions.last().is_some_and(|&last| next == last + 1);
        let chosen = if prefer_starts && !follows { (next..name.len()).find(|offset| hits(offset) && word_start(name, *offset)).unwrap_or(next) } else { next };
        positions.push(chosen);
        from = chosen + 1;
    }
    Some(positions)
}

/// A nota de um alinhamento: letras seguidas e começos de palavra valem
/// mais; buracos entre as letras custam.
fn alignment_score(name: &[u8], positions: &[usize]) -> i32 {
    let mut score = 0;
    for (index, &position) in positions.iter().enumerate() {
        score += 1;
        if word_start(name, position) {
            score += 8;
        }
        match index.checked_sub(1).map(|previous| positions[previous]) {
            Some(previous) if position == previous + 1 => score += 6,
            Some(previous) => score -= (position - previous - 1).min(8) as i32,
            None => score -= (position.min(12) / 2) as i32,
        }
    }
    score
}

/// A nota de um nome para uma palavra da busca (em minúsculas), ou `None`
/// quando as letras não aparecem na ordem. O pedaço inteiro vale mais que
/// as letras espalhadas.
fn word_score(word: &[u8], name: &[u8]) -> Option<i32> {
    if word.is_empty() {
        return Some(0);
    }
    // A conferência barata primeiro: quase todos os nomes caem aqui.
    if !is_subsequence(word, name) {
        return None;
    }
    if let Some(position) = find_ignoring_case(name, word) {
        let start = if word_start(name, position) { 30 } else { 0 };
        return Some(20 + 9 * word.len() as i32 + start - (position.min(40) / 4) as i32);
    }
    let greedy = align(word, name, false)?;
    let mut best = alignment_score(name, &greedy);
    if let Some(starts) = align(word, name, true) {
        best = best.max(alignment_score(name, &starts));
    }
    Some(best)
}

/// A busca já preparada: as palavras em minúsculas (todas têm de casar) e
/// o texto inteiro sem espaços (o nome exato ganha na frente de todos).
#[derive(Clone, Debug, Default)]
pub struct Query {
    words: Vec<Vec<u8>>,
    whole: Vec<u8>,
}

impl Query {
    pub fn new(text: &str) -> Query {
        let words: Vec<Vec<u8>> = text.split_whitespace().map(|word| word.to_ascii_lowercase().into_bytes()).collect();
        let whole = words.concat();
        Query { words, whole }
    }

    pub fn is_empty(&self) -> bool {
        self.whole.is_empty()
    }

    /// A nota de um nome (maior é melhor), ou `None` quando não casa.
    pub fn score(&self, name: &str) -> Option<i32> {
        if self.is_empty() {
            return None;
        }
        let bytes = name.as_bytes();
        let mut total = 0;
        for word in &self.words {
            total += word_score(word, bytes)?;
        }
        // O nome sem o módulo: `ntdll!LdrLoadDll` casa exato com `ldrloaddll`.
        let short = name.rsplit('!').next().unwrap_or(name).as_bytes();
        if equal_ignoring_case(short, &self.whole) || equal_ignoring_case(bytes, &self.whole) {
            total += 1000;
        } else if short.len() > self.whole.len() && equal_ignoring_case(&short[..self.whole.len()], &self.whole) {
            total += 150;
        }
        Some(total - (bytes.len() / 8) as i32)
    }
}

/// As melhores `limit` linhas para a busca: as do usuário (rótulos e
/// marcadores, um pouco na frente) e as do índice. `cancel` é consultado de
/// tempos em tempos (uma busca mais nova chegou): `None` quando cancelou.
/// Também devolve quantos nomes casaram ao todo.
pub fn best_matches(query: &Query, extra: &[Found], symbols: &[SymbolEntry], limit: usize, cancel: &dyn Fn() -> bool) -> Option<(Vec<Found>, usize)> {
    let mut scored: Vec<(i32, usize)> = Vec::new();
    for (index, entry) in extra.iter().enumerate() {
        if let Some(score) = query.score(&entry.name) {
            scored.push((score + 50, index));
        }
    }
    for (index, symbol) in symbols.iter().enumerate() {
        if index % 4096 == 0 && cancel() {
            return None;
        }
        if let Some(score) = query.score(&symbol.name) {
            scored.push((score, extra.len() + index));
        }
    }
    let total = scored.len();
    let name_of = |index: usize| if index < extra.len() { extra[index].name.as_str() } else { symbols[index - extra.len()].name.as_str() };
    let order = |a: &(i32, usize), b: &(i32, usize)| b.0.cmp(&a.0).then_with(|| name_of(a.1).len().cmp(&name_of(b.1).len())).then_with(|| name_of(a.1).cmp(name_of(b.1)));
    if scored.len() > limit {
        scored.select_nth_unstable_by(limit, |a, b| order(a, b));
        scored.truncate(limit);
    }
    scored.sort_by(|a, b| order(a, b));
    let found = scored
        .into_iter()
        .map(|(score, index)| {
            if index < extra.len() {
                Found { score, ..extra[index].clone() }
            } else {
                let symbol = &symbols[index - extra.len()];
                Found { name: symbol.name.clone(), address: symbol.address, kind: if symbol.function { FoundKind::Function } else { FoundKind::Data }, score }
            }
        })
        .collect();
    Some((found, total))
}

/// O resultado de uma busca da thread.
#[derive(Clone, Debug, Default)]
pub struct SearchOutcome {
    pub id: u64,
    pub query: String,
    pub found: Vec<Found>,
    /// Quantos nomes casaram (a lista mostra os `RESULT_LIMIT` melhores).
    pub total: usize,
    pub milliseconds: u128,
    /// O tamanho do índice procurado.
    pub symbols: usize,
}

struct Job {
    id: u64,
    query: String,
    extra: Vec<Found>,
    symbols: Arc<Vec<SymbolEntry>>,
}

/// A busca aproximada numa thread: a janela manda a busca a cada tecla e
/// lê o último resultado pronto.
pub struct SymbolSearch {
    jobs: Sender<Job>,
    latest: Arc<AtomicU64>,
    outcome: Arc<Mutex<Option<SearchOutcome>>>,
    next: u64,
}

impl SymbolSearch {
    /// Abre a thread; `notify` é chamado quando um resultado fica pronto
    /// (o `request_repaint` da janela). A thread acaba quando a busca é
    /// largada.
    pub fn start(notify: Arc<dyn Fn() + Send + Sync>) -> SymbolSearch {
        let (jobs, receiver) = mpsc::channel::<Job>();
        let latest = Arc::new(AtomicU64::new(0));
        let outcome = Arc::new(Mutex::new(None));
        let (thread_latest, thread_outcome) = (Arc::clone(&latest), Arc::clone(&outcome));
        let _ = std::thread::Builder::new().name("kd-re-busca".into()).spawn(move || search_thread(receiver, thread_latest, thread_outcome, notify));
        SymbolSearch { jobs, latest, outcome, next: 0 }
    }

    /// Manda uma busca; devolve o número dela.
    pub fn submit(&mut self, query: &str, extra: Vec<Found>, symbols: Arc<Vec<SymbolEntry>>) -> u64 {
        self.next += 1;
        self.latest.store(self.next, Ordering::SeqCst);
        let _ = self.jobs.send(Job { id: self.next, query: query.to_string(), extra, symbols });
        self.next
    }

    /// O último resultado pronto, se é mais novo que `seen`.
    pub fn newer_than(&self, seen: u64) -> Option<SearchOutcome> {
        let outcome = self.outcome.lock().ok()?;
        outcome.as_ref().filter(|outcome| outcome.id > seen).cloned()
    }

    /// O número da última busca mandada.
    pub fn last_submitted(&self) -> u64 {
        self.next
    }
}

fn search_thread(receiver: Receiver<Job>, latest: Arc<AtomicU64>, outcome: Arc<Mutex<Option<SearchOutcome>>>, notify: Arc<dyn Fn() + Send + Sync>) {
    while let Ok(mut job) = receiver.recv() {
        // Só a busca mais nova interessa.
        while let Ok(newer) = receiver.try_recv() {
            job = newer;
        }
        let started = Instant::now();
        let query = Query::new(&job.query);
        let id = job.id;
        let cancel = || latest.load(Ordering::SeqCst) != id;
        let Some((found, total)) = best_matches(&query, &job.extra, &job.symbols, RESULT_LIMIT, &cancel) else { continue };
        let result = SearchOutcome { id, query: job.query.clone(), found, total, milliseconds: started.elapsed().as_millis(), symbols: job.symbols.len() };
        if let Ok(mut slot) = outcome.lock() {
            *slot = Some(result);
        }
        notify();
    }
}

/// O texto parece uma expressão do avaliador (endereço, registrador,
/// aritmética, deslocamento), não um nome para a busca aproximada.
pub fn looks_like_expression(text: &str) -> bool {
    let text = text.trim();
    if text.is_empty() {
        return false;
    }
    if text.starts_with("0x") || text.starts_with("0X") || text.starts_with('@') || text.starts_with("poi(") || text.contains('`') {
        return true;
    }
    if text.chars().any(|character| matches!(character, '+' | '*' | '/' | '(' | ')' | '[' | ']' | '&' | '|' | '^' | '~')) {
        return true;
    }
    // Um número em hexadecimal comprido (nomes como `add` também são hex).
    text.len() >= 8 && text.chars().all(|character| character.is_ascii_hexdigit())
}

/// O marcador depois (ou antes) de `current` na lista ordenada, dando a
/// volta no fim.
pub fn next_bookmark(sorted: &[u64], current: u64, forward: bool) -> Option<u64> {
    if forward {
        sorted.iter().copied().find(|&address| address > current).or_else(|| sorted.first().copied())
    } else {
        sorted.iter().rev().copied().find(|&address| address < current).or_else(|| sorted.last().copied())
    }
}

// ---- idas da janela ----

impl UiState {
    /// O lugar da desmontagem agora: a linha escolhida, o foco ou o RIP.
    pub(crate) fn code_location(&self) -> Option<u64> {
        self.selected_code.or_else(|| (self.snapshot.code.focus != 0).then_some(self.snapshot.code.focus)).or_else(|| current_rip(&self.snapshot))
    }

    /// Guarda no histórico a saída do lugar de agora (para `to`, quando já
    /// se sabe).
    pub(crate) fn record_visit(&mut self, to: Option<u64>) {
        let from = self.code_location().map(|address| self.location(address));
        let to = to.map(|address| self.location(address));
        self.navigation.visit(from, to.as_ref());
    }

    /// A desmontagem num endereço, sem mexer no histórico.
    pub(crate) fn show_code_at(&mut self, address: u64) {
        self.selected_code = Some(address);
        self.selection_end = None;
        self.pending_goto = None;
        self.requests.push(Request::ShowCode(format!("{address:#x}")));
        self.requests.push(Request::SelectInstruction(Some(address)));
        self.focus_tab.push(Tab::Cpu);
    }

    /// Uma expressão na desmontagem (o avaliador do backend resolve); a
    /// linha escolhida passa a ser a do resultado quando o snapshot chegar.
    pub(crate) fn go_to_expression(&mut self, text: &str) {
        let text = text.trim();
        if text.is_empty() {
            return;
        }
        self.record_visit(None);
        self.requests.push(Request::ShowCode(text.to_string()));
        self.focus_tab.push(Tab::Cpu);
        self.pending_goto = Some(PendingGoTo { generation: self.snapshot.generation, focus: self.snapshot.code.focus, selected: self.selected_code });
    }

    /// Volta no histórico (os lugares de módulos que saíram ficam para
    /// trás).
    pub(crate) fn navigate_back(&mut self) -> bool {
        let current = self.code_location().map(|address| self.location(address));
        while let Some(location) = self.navigation.back(current.clone()) {
            if let Some(address) = self.address_of(&location) {
                self.show_code_at(address);
                return true;
            }
        }
        self.last_message = "nada para voltar".into();
        false
    }

    /// Avança no histórico.
    pub(crate) fn navigate_forward(&mut self) -> bool {
        let current = self.code_location().map(|address| self.location(address));
        while let Some(location) = self.navigation.forward(current.clone()) {
            if let Some(address) = self.address_of(&location) {
                self.show_code_at(address);
                return true;
            }
        }
        self.last_message = "nada para avançar".into();
        false
    }

    /// Os marcadores com o endereço de agora (os de módulos ausentes ficam
    /// de fora), em ordem de endereço.
    pub(crate) fn bookmark_addresses(&self) -> Vec<(u64, Location)> {
        let mut list: Vec<(u64, Location)> = self.notes.bookmarks.iter().filter_map(|location| self.address_of(location).map(|address| (address, location.clone()))).collect();
        list.sort();
        list
    }

    /// Liga ou tira o marcador do endereço; devolve se ficou ligado.
    pub(crate) fn toggle_bookmark_at(&mut self, address: u64) -> bool {
        let location = self.location(address);
        let on = self.notes.toggle_bookmark(location.clone());
        self.last_message = if on { format!("marcador em {}", location.display()) } else { format!("marcador tirado de {}", location.display()) };
        on
    }

    /// Vai ao marcador seguinte (ou ao anterior), dando a volta.
    pub(crate) fn jump_to_bookmark(&mut self, forward: bool) {
        let addresses: Vec<u64> = self.bookmark_addresses().into_iter().map(|(address, _)| address).collect();
        let current = self.code_location().unwrap_or(0);
        match next_bookmark(&addresses, current, forward) {
            Some(address) => self.go_to_code(address),
            None => self.last_message = "nenhum marcador num módulo carregado".into(),
        }
    }

    /// O nome de um marcador: o rótulo, o comentário ou só módulo + RVA.
    pub(crate) fn bookmark_name(&self, location: &Location) -> String {
        match (self.notes.labels.get(location), self.notes.comments.get(location)) {
            (Some(label), _) => format!("{label} ({})", location.display()),
            (None, Some(comment)) => format!("{} ; {comment}", location.display()),
            _ => location.display(),
        }
    }
}

/// Uma ida por expressão esperando o snapshot com o resultado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingGoTo {
    /// A geração do snapshot quando a ida foi pedida.
    pub(crate) generation: u64,
    /// O foco da desmontagem naquela hora.
    pub(crate) focus: u64,
    /// A linha escolhida naquela hora.
    pub(crate) selected: Option<u64>,
}

/// Depois da ida por expressão: a linha escolhida vira a do resultado. Um
/// snapshot que chegou antes do pedido (o foco ainda é o de antes) espera o
/// seguinte; um clique em outra linha no meio cancela.
pub(crate) fn resolve_pending_goto(state: &mut UiState) {
    let Some(pending) = state.pending_goto else { return };
    if state.selected_code != pending.selected {
        state.pending_goto = None;
        return;
    }
    let generation = state.snapshot.generation;
    if generation <= pending.generation {
        return;
    }
    if state.snapshot.code.focus != pending.focus || generation > pending.generation + 1 {
        state.pending_goto = None;
        if state.snapshot.code.focus != 0 {
            state.selected_code = Some(state.snapshot.code.focus);
        }
    }
}

// ---- janela Ir para ----

/// O estado da janela Ir para.
#[derive(Default)]
pub(crate) struct GoToPalette {
    /// A janela está aberta (o texto inicial já entrou).
    active: bool,
    pub(crate) text: String,
    /// A linha escolhida na lista.
    pub(crate) selected: usize,
    /// A linha foi escolhida (setas ou clique) depois da última mudança do
    /// texto: com uma expressão escrita, o Enter vai à linha e não avalia.
    navigated: bool,
    /// A última busca mandada: texto, índice (o endereço do `Arc`) e
    /// quantos rótulos e marcadores havia.
    sent: Option<(String, usize, usize)>,
    shown: Option<SearchOutcome>,
    search: Option<SymbolSearch>,
}

impl GoToPalette {
    fn open(&mut self, initial: &str) {
        self.active = true;
        self.text = initial.to_string();
        self.selected = 0;
        self.navigated = false;
        self.sent = None;
        self.shown = None;
    }

    fn close(&mut self) {
        self.active = false;
        self.text.clear();
        self.sent = None;
        self.shown = None;
    }
}

/// Os rótulos e os marcadores do usuário como linhas da busca.
fn user_entries(state: &UiState) -> Vec<Found> {
    let mut entries = Vec::new();
    for (location, name) in &state.notes.labels {
        if let Some(address) = state.address_of(location) {
            entries.push(Found { name: name.clone(), address, kind: FoundKind::Label, score: 0 });
        }
    }
    for location in &state.notes.bookmarks {
        if let Some(address) = state.address_of(location) {
            entries.push(Found { name: state.bookmark_name(location), address, kind: FoundKind::Bookmark, score: 0 });
        }
    }
    entries
}

/// Sem texto: os lugares recentes do histórico e os marcadores.
fn empty_rows(state: &UiState) -> Vec<Found> {
    let mut rows = Vec::new();
    for location in state.navigation.recent().take(15) {
        if let Some(address) = state.address_of(location) {
            let name = state.notes.labels.get(location).map(|label| format!("{label} ({})", location.display())).unwrap_or_else(|| location.display());
            rows.push(Found { name, address, kind: FoundKind::Recent, score: 0 });
        }
    }
    for (address, location) in state.bookmark_addresses() {
        rows.push(Found { name: state.bookmark_name(&location), address, kind: FoundKind::Bookmark, score: 0 });
    }
    rows
}

/// A janela Ir para (Ctrl+G): o campo, a lista dos nomes parecidos (a
/// busca roda na thread de busca) e, quando o texto parece uma expressão
/// ou nada casa, o texto vai ao avaliador (`@rax+8`,
/// `ntdll!LdrLoadDll+0x10`). Devolve se a janela continua aberta.
pub(crate) fn goto_window(ui: &mut Ui, state: &mut UiState, initial: &str) -> bool {
    if !state.goto.active {
        state.goto.open(initial);
    }
    if state.goto.search.is_none() {
        let context = ui.ctx().clone();
        state.goto.search = Some(SymbolSearch::start(Arc::new(move || context.request_repaint())));
    }
    let colors = palette(ui);
    // A busca nova, quando o texto, o índice ou as notas mudaram.
    let query = state.goto.text.trim().to_string();
    let key = (query.clone(), Arc::as_ptr(&state.symbol_index) as usize, state.notes.labels.len() + state.notes.bookmarks.len());
    if !query.is_empty() && state.goto.sent.as_ref() != Some(&key) {
        let extra = user_entries(state);
        let symbols = Arc::clone(&state.symbol_index);
        if let Some(search) = state.goto.search.as_mut() {
            search.submit(&query, extra, symbols);
        }
        state.goto.sent = Some(key);
    }
    let seen = state.goto.shown.as_ref().map_or(0, |shown| shown.id);
    if let Some(newer) = state.goto.search.as_ref().and_then(|search| search.newer_than(seen)) {
        state.goto.shown = Some(newer);
    }
    let waiting = !query.is_empty() && state.goto.search.as_ref().is_some_and(|search| state.goto.shown.as_ref().is_none_or(|shown| shown.id < search.last_submitted()));
    let rows: Vec<Found> = if query.is_empty() { empty_rows(state) } else { state.goto.shown.as_ref().map(|shown| shown.found.clone()).unwrap_or_default() };
    // As setas antes do campo (o campo de uma linha não usa as setas).
    let (down, up, page_down, page_up) = ui.input_mut(|input| {
        (input.consume_key(Modifiers::NONE, Key::ArrowDown), input.consume_key(Modifiers::NONE, Key::ArrowUp), input.consume_key(Modifiers::NONE, Key::PageDown), input.consume_key(Modifiers::NONE, Key::PageUp))
    });
    let last = rows.len().saturating_sub(1);
    let mut moved = false;
    if down {
        state.goto.selected = (state.goto.selected + 1).min(last);
        moved = true;
    }
    if up {
        state.goto.selected = state.goto.selected.saturating_sub(1);
        moved = true;
    }
    if page_down {
        state.goto.selected = (state.goto.selected + 10).min(last);
        moved = true;
    }
    if page_up {
        state.goto.selected = state.goto.selected.saturating_sub(10);
        moved = true;
    }
    state.goto.selected = state.goto.selected.min(last);
    if moved {
        state.goto.navigated = true;
    }
    let escape = ui.input(|input| input.key_pressed(Key::Escape));
    let mut open = true;
    let mut close = false;
    let mut submit = false;
    let mut chosen: Option<u64> = None;
    let mut expression: Option<String> = None;
    let index_size = state.symbol_index.len();
    egui::Window::new("Ir para").id(egui::Id::new("re-goto")).collapsible(false).resizable(true).default_width(680.0).anchor(egui::Align2::CENTER_TOP, Vec2::new(0.0, 80.0)).open(&mut open).show(ui.ctx(), |ui| {
        let response = ui.add(egui::TextEdit::singleline(&mut state.goto.text).id(egui::Id::new("re-goto-text")).font(TextStyle::Monospace).desired_width(f32::INFINITY).hint_text("nome (busca aproximada), endereço, @rax+8, ntdll!LdrLoadDll+0x10"));
        response.request_focus();
        if response.changed() {
            state.goto.selected = 0;
            state.goto.navigated = false;
        }
        if response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter)) {
            submit = true;
        }
        ui.horizontal(|ui| {
            if query.is_empty() {
                hint(ui, "sem texto: os lugares recentes e os marcadores; setas escolhem, Enter vai");
            } else if waiting {
                ui.spinner();
                hint(ui, &format!("procurando em {index_size} símbolos..."));
            } else if let Some(shown) = &state.goto.shown {
                hint(ui, &format!("{} parecidos em {} símbolos ({} ms){}", shown.total, shown.symbols, shown.milliseconds, if shown.total > shown.found.len() { format!("; os {} melhores", shown.found.len()) } else { String::new() }));
            }
            if index_size == 0 {
                ui.label(RichText::new("sem símbolos ainda: o índice enche na primeira parada").color(colors.yellow));
            }
        });
        if !query.is_empty() && looks_like_expression(&query) {
            hint(ui, "Enter avalia o texto como expressão (escolha uma linha com as setas para ir ao nome)");
        }
        ui.separator();
        let mut clicked = None;
        egui::ScrollArea::vertical().id_salt("re-goto-list").max_height(380.0).auto_shrink([false, true]).show(ui, |ui| {
            if rows.is_empty() && !query.is_empty() && !waiting {
                hint(ui, "nada parecido; Enter avalia o texto como expressão");
            }
            for (index, row) in rows.iter().enumerate() {
                let selected = index == state.goto.selected;
                let location = state.location(row.address).display();
                let text = format!("{:<9}{}  {}  {}", row.kind.tag(), row.name, location, hex(row.address));
                let response = ui.add(egui::Button::selectable(selected, mono(text)));
                if selected && moved {
                    response.scroll_to_me(Some(egui::Align::Center));
                }
                if response.clicked() {
                    clicked = Some(index);
                }
                if response.double_clicked() {
                    chosen = Some(row.address);
                }
            }
        });
        if let Some(index) = clicked {
            state.goto.selected = index;
            state.goto.navigated = true;
        }
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("Ir").clicked() {
                submit = true;
            }
            if ui.add_enabled(!query.is_empty(), egui::Button::new("Avaliar como expressão")).on_hover_text("manda o texto ao avaliador do depurador: registradores, aritmética, módulo!símbolo+deslocamento").clicked() {
                expression = Some(query.clone());
            }
            if ui.button("Cancelar").clicked() {
                close = true;
            }
        });
    });
    if submit && chosen.is_none() && expression.is_none() {
        let pick = rows.get(state.goto.selected).map(|row| row.address);
        // Uma expressão escrita só vai à lista quando a linha foi escolhida
        // (setas ou clique) depois de escrever.
        let typed_expression = looks_like_expression(&query) && !state.goto.navigated;
        match pick {
            Some(address) if !typed_expression || query.is_empty() => chosen = Some(address),
            _ if !query.is_empty() => expression = Some(query.clone()),
            _ => {}
        }
    }
    if let Some(address) = chosen {
        state.go_to_code(address);
        close = true;
    } else if let Some(text) = expression {
        state.go_to_expression(&text);
        close = true;
    }
    if !open || close || escape {
        state.goto.close();
        return false;
    }
    true
}

/// O menu Navegar: voltar, avançar, ir para, os marcadores.
pub(crate) fn navigate_menu(ui: &mut Ui, state: &mut UiState) {
    let stopped = state.status == Status::Stopped;
    let key = |action: Action| state.prefs.binding(action).text();
    let (back_key, forward_key, goto_key, mark_key, next_key, previous_key) = (key(Action::NavigateBack), key(Action::NavigateForward), key(Action::GoTo), key(Action::ToggleBookmark), key(Action::NextBookmark), key(Action::PreviousBookmark));
    let back = state.navigation.peek_back().map(Location::display);
    let forward = state.navigation.peek_forward().map(Location::display);
    let back_text = back.as_ref().map_or("Voltar".to_string(), |place| format!("Voltar para {place}"));
    let forward_text = forward.as_ref().map_or("Avançar".to_string(), |place| format!("Avançar para {place}"));
    if ui.add_enabled(stopped && back.is_some(), egui::Button::new(back_text).shortcut_text(back_key)).clicked() {
        state.navigate_back();
        ui.close();
    }
    if ui.add_enabled(stopped && forward.is_some(), egui::Button::new(forward_text).shortcut_text(forward_key)).clicked() {
        state.navigate_forward();
        ui.close();
    }
    if ui.add_enabled(stopped, egui::Button::new("Ir para...").shortcut_text(goto_key)).clicked() {
        state.dialog = Some(crate::app::Dialog::GoTo(String::new()));
        ui.close();
    }
    if ui.add_enabled(stopped, egui::Button::new("Voltar ao RIP").shortcut_text("*")).clicked() {
        state.record_visit(None);
        state.selected_code = None;
        state.selection_end = None;
        state.requests.push(Request::ShowCode(String::new()));
        state.requests.push(Request::SelectInstruction(None));
        state.focus_tab.push(Tab::Cpu);
        ui.close();
    }
    if ui.button("Limpar o histórico").clicked() {
        state.navigation.clear();
        ui.close();
    }
    ui.separator();
    let target = state.selected_code.or_else(|| current_rip(&state.snapshot));
    let marked = target.is_some_and(|address| state.bookmarked(address));
    if ui.add_enabled(target.is_some(), egui::Button::new(if marked { "Tirar o marcador da linha" } else { "Marcador na linha" }).shortcut_text(mark_key)).clicked() {
        if let Some(address) = target {
            state.toggle_bookmark_at(address);
        }
        ui.close();
    }
    let bookmarks = state.bookmark_addresses();
    if ui.add_enabled(stopped && !bookmarks.is_empty(), egui::Button::new("Próximo marcador").shortcut_text(next_key)).clicked() {
        state.jump_to_bookmark(true);
        ui.close();
    }
    if ui.add_enabled(stopped && !bookmarks.is_empty(), egui::Button::new("Marcador anterior").shortcut_text(previous_key)).clicked() {
        state.jump_to_bookmark(false);
        ui.close();
    }
    ui.menu_button(format!("Marcadores ({})", bookmarks.len()), |ui| {
        if bookmarks.is_empty() {
            hint(ui, "nenhum marcador num módulo carregado (menu de contexto da desmontagem, ou a tecla do marcador)");
        }
        for (address, location) in &bookmarks {
            if ui.add_enabled(stopped, egui::Button::new(mono(format!("{}  {}", hex(*address), state.bookmark_name(location))))).clicked() {
                state.go_to_code(*address);
                ui.close();
            }
        }
        ui.separator();
        if ui.button("Todos na aba Comentários/Rótulos").clicked() {
            state.focus_tab.push(Tab::Comments);
            ui.close();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn history_goes_back_and_forward() {
        let mut history: History<u64> = History::new(3);
        history.visit(Some(1), Some(&2));
        history.visit(Some(2), Some(&3));
        assert_eq!(history.peek_back(), Some(&2));
        assert_eq!(history.back(Some(3)), Some(2));
        assert_eq!(history.back(Some(2)), Some(1));
        assert_eq!(history.back(Some(1)), None);
        assert_eq!(history.forward(Some(1)), Some(2));
        assert_eq!(history.forward(Some(2)), Some(3));
        assert_eq!(history.forward(Some(3)), None);
        // Uma ida nova apaga o caminho à frente.
        assert_eq!(history.back(Some(3)), Some(2));
        history.visit(Some(2), Some(&9));
        assert_eq!(history.peek_forward(), None);
        assert_eq!(history.recent().copied().collect::<Vec<_>>(), vec![2, 1]);
        // Sem origem ou para o mesmo lugar: nada muda.
        history.visit(None, Some(&5));
        history.visit(Some(9), Some(&9));
        assert_eq!(history.recent().count(), 2);
        // O mesmo lugar duas vezes seguidas entra uma vez só.
        history.visit(Some(2), None);
        assert_eq!(history.recent().count(), 2);
        // O limite corta os mais antigos.
        for place in 10..20 {
            history.visit(Some(place), None);
        }
        assert_eq!(history.recent().copied().collect::<Vec<_>>(), vec![19, 18, 17]);
        // Voltar pula o lugar onde já se está.
        assert_eq!(history.back(Some(19)), Some(18));
        history.clear();
        assert_eq!(history.peek_back(), None);
    }

    #[test]
    fn fuzzy_scores_prefer_exact_names_and_word_starts() {
        let query = Query::new("create");
        assert!(query.score("ntfs!NtfsFsdCreate").is_some());
        assert!(Query::new("xyz").score("ntfs!NtfsFsdCreate").is_none());
        assert!(Query::new("").score("qualquer").is_none());
        // As letras espalhadas casam (as iniciais das palavras).
        let initials = Query::new("nfc");
        assert!(initials.score("NtfsFsdCreate").is_some());
        let starts = Query::new("fc");
        assert!(starts.score("FsdCreate") > starts.score("xfxxxxcx"));
        // O nome exato vem antes dos mais compridos, com ou sem o módulo.
        let close = Query::new("ntclose");
        assert!(close.score("NtClose") > close.score("NtCloseObjectAuditAlarm"));
        assert!(Query::new("ldrloaddll").score("ntdll!LdrLoadDll") > Query::new("ldrloaddll").score("ntdll!LdrLoadDllInternal"));
        // Várias palavras: todas têm de casar.
        let words = Query::new("ntfs create");
        assert!(words.score("ntfs!NtfsFsdCreate").is_some());
        assert!(words.score("acpi!AcpiCreate").is_none());
        // O pedaço inteiro vale mais que as letras espalhadas.
        let piece = Query::new("fsd");
        assert!(piece.score("ntfs!NtfsFsdRead") > piece.score("ntfs!FooSomethingDone"));
        // O alinhamento que prefere começos de palavra não perde um casamento.
        assert!(Query::new("ab").score("xa_b_a").is_some());
    }

    #[test]
    fn best_matches_rank_and_limit() {
        let symbols: Vec<SymbolEntry> = ["NtCloseObjectAuditAlarm", "NtClose", "ZwClose", "ntdll!NtClose", "NtCreateFile"].iter().enumerate().map(|(index, name)| SymbolEntry { name: name.to_string(), address: 0x1000 * (index as u64 + 1), function: true }).collect();
        let extra = vec![Found { name: "fecha_tudo".into(), address: 0x9000, kind: FoundKind::Label, score: 0 }];
        let (found, total) = best_matches(&Query::new("ntclose"), &extra, &symbols, 10, &|| false).expect("busca");
        assert_eq!(total, 3);
        assert_eq!(found[0].name, "NtClose");
        assert_eq!(found[0].address, 0x2000);
        assert_eq!(found[0].kind, FoundKind::Function);
        assert_eq!(found[1].name, "ntdll!NtClose");
        // O limite fica com os melhores, em ordem.
        let (found, total) = best_matches(&Query::new("close"), &extra, &symbols, 2, &|| false).expect("busca");
        assert_eq!(total, 4);
        assert_eq!(found.len(), 2);
        assert!(found[0].score >= found[1].score);
        // Os rótulos do usuário entram na busca.
        let (found, _) = best_matches(&Query::new("fecha"), &extra, &symbols, 10, &|| false).expect("busca");
        assert_eq!(found[0].kind, FoundKind::Label);
        // Cancelada, não devolve nada.
        assert!(best_matches(&Query::new("close"), &extra, &symbols, 10, &|| true).is_none());
    }

    #[test]
    fn search_runs_in_its_own_thread() {
        let symbols: Arc<Vec<SymbolEntry>> = Arc::new((0..20_000).map(|index| SymbolEntry { name: format!("modulo!Funcao{index}"), address: index, function: index % 2 == 0 }).chain(std::iter::once(SymbolEntry { name: "ntoskrnl!KeBugCheckEx".into(), address: 0xdead, function: true })).collect());
        let mut search = SymbolSearch::start(Arc::new(|| {}));
        // A primeira é cancelada pela segunda (ou termina antes: o resultado que vale é o da segunda).
        search.submit("funcao1", Vec::new(), Arc::clone(&symbols));
        let id = search.submit("kebugcheck", Vec::new(), Arc::clone(&symbols));
        let deadline = Instant::now() + Duration::from_secs(20);
        let outcome = loop {
            if let Some(outcome) = search.newer_than(id - 1).filter(|outcome| outcome.id == id) {
                break outcome;
            }
            assert!(Instant::now() < deadline, "a busca não terminou");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(outcome.query, "kebugcheck");
        assert_eq!(outcome.found.first().map(|found| found.address), Some(0xdead));
        assert_eq!(outcome.symbols, 20_001);
    }

    #[test]
    fn expressions_and_bookmarks() {
        assert!(looks_like_expression("@rax+8"));
        assert!(looks_like_expression("ntdll!LdrLoadDll+0x10"));
        assert!(looks_like_expression("0xfffff80000001000"));
        assert!(looks_like_expression("fffff800`00001000"));
        assert!(looks_like_expression("fffff80000001000"));
        assert!(looks_like_expression("poi(@rsp)"));
        assert!(!looks_like_expression("add"));
        assert!(!looks_like_expression("NtCreateFile"));
        assert!(!looks_like_expression("ntfs create"));
        assert!(!looks_like_expression("ntdll!LdrLoadDll"));
        let marks = [0x100, 0x200, 0x300];
        assert_eq!(next_bookmark(&marks, 0x150, true), Some(0x200));
        assert_eq!(next_bookmark(&marks, 0x300, true), Some(0x100));
        assert_eq!(next_bookmark(&marks, 0x150, false), Some(0x100));
        assert_eq!(next_bookmark(&marks, 0x100, false), Some(0x300));
        assert_eq!(next_bookmark(&[], 0x100, true), None);
    }
}
