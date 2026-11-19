//! Copiar uma aba como texto (Ctrl+Shift+C copia a aba ativa; o botão
//! direito no título de qualquer aba também tem "Copiar a aba como texto").
//! O texto é o que a aba mostra: as tabelas em colunas separadas por
//! tabulação (cola direto numa planilha ou num relatório), os filtros de
//! agora valendo.

use eframe::egui;

use crate::app::{current_rip, hex, LogLines, Tab, UiState};
use crate::backend::Status;
use crate::console::Level;
use crate::views::Filter;

/// Quantas linhas uma cópia leva no máximo (o rastro e o monitor crescem
/// sem fim).
const LINE_LIMIT: usize = 200_000;

/// Uma tabela: o cabeçalho e as linhas, separados por tabulação.
fn table(headers: &[&str], rows: impl IntoIterator<Item = Vec<String>>) -> String {
    let mut text = headers.join("\t");
    text.push('\n');
    for row in rows.into_iter().take(LINE_LIMIT) {
        text.push_str(&row.join("\t"));
        text.push('\n');
    }
    text
}

fn log_text(log: &LogLines) -> String {
    let mut text = String::new();
    for index in 0..log.count().min(LINE_LIMIT) {
        text.push_str(log.line(index));
        text.push('\n');
    }
    text
}

fn bytes_text(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(" ")
}

/// A aba CPU: a desmontagem (com rótulos, comentários e a marca do RIP),
/// os registradores e a pilha.
fn cpu_text(state: &UiState) -> String {
    let snapshot = &state.snapshot;
    let rip = current_rip(snapshot);
    let mut text = String::from("; desmontagem\n");
    for line in &snapshot.code.lines {
        if let Some(label) = state.label_at(line.address).or(line.label.as_ref()) {
            text.push_str(&format!("{label}:\n"));
        }
        let marker = if Some(line.address) == rip { ">" } else if state.bookmarked(line.address) { "#" } else { " " };
        let comment = state.comment_at(line.address).map(|comment| format!("  ; {comment}")).or_else(|| snapshot.code.auto_comments.get(&line.address).map(|comment| format!("  {comment}"))).or_else(|| line.comment.as_ref().map(|comment| format!("  {comment}"))).unwrap_or_default();
        text.push_str(&format!("{marker} {}  {:<20}  {}{comment}\n", hex(line.address), line.bytes, line.text));
    }
    text.push_str("\n; registradores\n");
    for row in &snapshot.registers {
        let value = row.value.map_or("?".to_string(), hex);
        let note = snapshot.register_notes.get(&row.name).map(|note| format!("  {note}")).unwrap_or_default();
        text.push_str(&format!("{:<8} {value}{note}\n", row.name));
    }
    text.push_str("\n; pilha\n");
    for row in &snapshot.stack {
        text.push_str(&format!("{}  {}  {}\n", hex(row.address), hex(row.value), row.note));
    }
    text
}

/// O texto de uma aba, ou por que não há.
pub(crate) fn tab_text(state: &UiState, tab: Tab) -> Result<String, String> {
    let snapshot = &state.snapshot;
    let empty = |what: &str| Err(format!("{what}: nada para copiar ainda"));
    let text = match tab {
        Tab::Cpu => {
            if snapshot.code.lines.is_empty() && snapshot.registers.is_empty() {
                return empty("CPU");
            }
            cpu_text(state)
        }
        Tab::Log => match state.log_mode {
            1 => log_text(&state.console),
            2 => log_text(&state.serial),
            crate::console::EVENTS_MODE => state.events.text(),
            _ if state.transcript_lines.is_empty() => log_text(&state.launch_log),
            _ => state.transcript_lines.text(),
        },
        Tab::Notes => state.session_notes.clone(),
        Tab::Script => state.script_text.clone(),
        Tab::Breakpoints => table(
            &["#", "tipo", "endereço", "expressão", "nome", "ligado", "acertos", "condição", "log", "comandos", "grupo", "processo"],
            snapshot.breakpoints.iter().map(|breakpoint| {
                vec![
                    breakpoint.id.to_string(),
                    breakpoint.kind.name().to_string(),
                    if breakpoint.pending { "adiado".into() } else { hex(breakpoint.address) },
                    breakpoint.expression.clone(),
                    breakpoint.options.name.clone(),
                    if breakpoint.enabled { "sim".into() } else { "não".into() },
                    breakpoint.hits.to_string(),
                    breakpoint.condition.clone(),
                    breakpoint.log.clone(),
                    breakpoint.command.clone(),
                    breakpoint.group.clone(),
                    if breakpoint.process != 0 { format!("{:#x}", breakpoint.process) } else { String::new() },
                ]
            }),
        ),
        Tab::MemoryMap => {
            let Some(map) = &snapshot.memory_map else { return empty("Mapa de memória") };
            let filter = Filter::new(&state.map_filter, false);
            table(
                &["endereço", "tamanho", "parte", "informação", "conteúdo", "tipo", "proteção", "proteção inicial"],
                map.rows.iter().filter(|row| filter.matches(&[&row.name, &row.kind, &row.section, &row.protection, &row.content, &row.party])).map(|row| {
                    let info = if row.section.is_empty() { row.name.clone() } else { format!("{} {}", row.name, row.section) };
                    vec![hex(row.base), format!("{:x}", row.size), row.party.clone(), info, row.content.clone(), row.kind.clone(), row.protection.clone(), row.initial_protection.clone()]
                }),
            )
        }
        Tab::CallStack => {
            if snapshot.frames.is_empty() {
                return empty("Pilha de chamadas");
            }
            table(
                &["#", "pilha", "endereço", "função", "argumentos", "como"],
                snapshot.frames.iter().enumerate().map(|(index, frame)| vec![format!("{index:02}"), hex(frame.stack), hex(frame.address), frame.name.clone(), frame.arguments.iter().map(|value| format!("{value:x}")).collect::<Vec<_>>().join(" "), frame.method.to_string()]),
            )
        }
        Tab::Seh => {
            let mut text = String::new();
            if let Some(exception) = &snapshot.exception {
                text.push_str(&format!("parada: {exception}\n"));
            }
            for row in &snapshot.seh {
                text.push_str(&format!("#{:02} {} {}\n    tratador: {}\n", row.frame, hex(row.address), row.function, row.handler));
                for scope in &row.scopes {
                    text.push_str(&format!("    {scope}\n"));
                }
            }
            if text.is_empty() {
                return empty("SEH");
            }
            text
        }
        Tab::Symbols => {
            let Some(view) = &snapshot.symbol_view else { return empty("Símbolos") };
            let filter = Filter::new(&state.symbols_filter, false);
            match state.symbols_mode {
                1 => table(&["endereço", "export"], view.exports.iter().filter(|(_, name)| filter.matches(&[name])).map(|(address, name)| vec![hex(*address), name.clone()])),
                2 => table(&["slot", "import", "valor"], view.imports.iter().filter(|(_, dll, name, _)| filter.matches(&[dll, name])).map(|(slot, dll, name, value)| vec![hex(*slot), format!("{dll}!{name}"), format!("{value:#x}")])),
                _ => table(&["endereço", "símbolo"], view.symbols.iter().filter(|(_, name)| filter.matches(&[name])).map(|(address, name)| vec![hex(*address), name.clone()])),
            }
        }
        Tab::Source => {
            let Some(source) = &snapshot.source else { return empty("Código-fonte") };
            let mut text = format!("; {}:{}\n", source.file, source.line);
            for (index, line) in source.text.iter().enumerate() {
                let number = index as u32 + 1;
                text.push_str(&format!("{} {number:>5}  {line}\n", if number == source.line { ">" } else { " " }));
            }
            text
        }
        Tab::References | Tab::Strings => {
            let strings = tab == Tab::Strings;
            let view = if strings { &snapshot.strings } else { &snapshot.references };
            let Some(view) = view else { return empty(tab.title()) };
            let filter = Filter::new(if strings { &state.strings_filter } else { &state.reference_filter }, state.reference_regex);
            let mut text = format!("; {} em {}\n", view.title, view.scope);
            text.push_str(&table(&["endereço", "local", if strings { "bytes" } else { "desmontagem" }, "string / destino"], view.rows.iter().filter(|row| filter.matches(&[&row.text, &row.disassembly, &row.location])).map(|row| vec![hex(row.address), row.location.clone(), row.disassembly.clone(), row.text.clone()])));
            text
        }
        Tab::Threads => {
            let mut text = table(&["PID", "TID", "ETHREAD", "estado", "início", "processo"], snapshot.threads.iter().map(|row| vec![format!("{:#x}", row.thread.pid), format!("{:#x}", row.thread.tid), hex(row.thread.ethread), row.thread.state.clone(), row.start.clone(), row.thread.process.clone()]));
            if let Some(Ok(threads)) = snapshot.user_threads.as_deref() {
                text.push_str("\n; threads de usuário\n");
                text.push_str(&table(&["TID", "TEB", "RIP", "RSP", "estado", "espera", "LastError"], threads.iter().map(|thread| vec![thread.tid.to_string(), format!("{:x}", thread.teb), format!("{:x}", thread.rip), format!("{:x}", thread.rsp), thread.state.clone(), thread.wait_reason.clone(), thread.last_error.map_or("-".into(), |value| format!("{value:#x}"))])));
            }
            text
        }
        Tab::Handles => match snapshot.handles.as_deref() {
            Some(Ok(handles)) => {
                let filter = Filter::new(&state.handles_filter, false);
                table(&["handle", "objeto", "acesso", "tipo", "nome"], handles.iter().filter(|handle| filter.matches(&[&handle.kind, &handle.name])).map(|handle| vec![format!("{:#x}", handle.handle), hex(handle.object), format!("{:#x}", handle.access), handle.kind.clone(), handle.name.clone()]))
            }
            Some(Err(error)) => return Err(error.clone()),
            None => return empty("Handles"),
        },
        Tab::Trace => {
            let Some(trace) = &state.trace else { return empty("Rastro") };
            let mut text = format!("; {}\n; {}\n", trace.title, trace.summary);
            text.push_str(&table(
                &["#", "rip", "símbolo", "instrução", "profundidade", "thread", "cpu"],
                trace.trace.records.iter().enumerate().map(|(index, record)| {
                    let info = trace.info(record.rip);
                    vec![index.to_string(), hex(record.rip), info.map(|info| info.symbol.clone()).unwrap_or_default(), info.map(|info| info.text.clone()).unwrap_or_default(), record.depth.to_string(), format!("{:#x}", record.thread), record.cpu.to_string()]
                }),
            ));
            text
        }
        Tab::Patches => table(&["endereço", "módulo + RVA", "original", "novo"], snapshot.patches.iter().map(|patch| vec![hex(patch.address), patch.location.display(), bytes_text(&patch.original), bytes_text(&patch.patched)])),
        Tab::Comments => {
            let filter = Filter::new(&state.comments_filter, false);
            let mut rows = Vec::new();
            for (location, text) in &state.notes.labels {
                rows.push(("rótulo", location, text.clone()));
            }
            for (location, text) in &state.notes.comments {
                rows.push(("comentário", location, text.clone()));
            }
            for location in &state.notes.bookmarks {
                rows.push(("marcador", location, String::new()));
            }
            table(&["tipo", "módulo + RVA", "endereço agora", "texto"], rows.into_iter().filter(|(kind, location, text)| filter.matches(&[kind, &location.display(), text])).map(|(kind, location, text)| vec![kind.to_string(), location.display(), state.address_of(location).map(hex).unwrap_or_else(|| "(módulo ausente)".into()), text]))
        }
        Tab::Processes => table(&["PID", "EPROCESS", "CR3", "threads", "nome"], snapshot.processes.iter().map(|process| vec![process.pid.to_string(), hex(process.eprocess), format!("{:#x}", process.cr3), process.threads.to_string(), process.name.clone()])),
        Tab::Watch => {
            let mut text = table(&["expressão", "valor", "tipo"], snapshot.watches.iter().map(|watch| vec![watch.expression.clone(), match &watch.value { Ok(value) => value.clone(), Err(error) => format!("erro: {error}") }, watch.type_name.clone()]));
            if !snapshot.locals.is_empty() {
                text.push_str("\n; variáveis locais\n");
                text.push_str(&table(&["nome", "tipo", "onde", "valor"], snapshot.locals.iter().map(|local| vec![local.name.clone(), local.type_name.clone(), local.location.clone(), local.value.clone()])));
            }
            text
        }
        Tab::NtObjects => {
            let mut text = String::new();
            if let Some(query) = &snapshot.query {
                text.push_str(&format!("> {}\n", query.kind.command(&query.argument)));
                match &query.text {
                    Ok(output) => text.push_str(output),
                    Err(error) => text.push_str(&format!("erro: {error}")),
                }
                text.push_str("\n\n");
            }
            text.push_str(&table(&["base", "fim", "módulo", "arquivo", "símbolos", "origem"], snapshot.modules.iter().map(|module| vec![hex(module.base), hex(module.end), module.name.clone(), module.file_name.clone(), module.symbols.to_string(), module.source.clone()])));
            text
        }
        Tab::Bugcheck => match &snapshot.bugcheck {
            Some(analysis) => analysis.text(),
            None => return empty("Bugcheck"),
        },
        Tab::Graph => {
            let Some(graph) = &snapshot.graph else { return empty("Grafo") };
            let mut text = format!("; {} ({:#x}), {} blocos\n", graph.name, graph.function, graph.blocks.len());
            for (index, block) in graph.blocks.iter().enumerate() {
                text.push_str(&format!("\n; bloco {index}: {}..{}\n", hex(block.start), hex(block.end)));
                for line in &block.lines {
                    text.push_str(&format!("  {}  {}\n", hex(line.address), line.text));
                }
                for (target, kind) in &block.edges {
                    text.push_str(&format!("  -> bloco {target} ({kind:?})\n"));
                }
            }
            text
        }
        Tab::ApiMonitor => {
            let Ok(store) = state.store.lock() else { return Err("o depósito do monitor está travado".into()) };
            if store.api_rows.is_empty() {
                return empty("APIs");
            }
            let mut text = String::new();
            for row in store.api_rows.iter().take(LINE_LIMIT) {
                text.push_str(&kd_client::api_monitor::format_row(row));
                text.push('\n');
            }
            text
        }
        Tab::Irps => {
            let Ok(store) = state.store.lock() else { return Err("o depósito do monitor está travado".into()) };
            if store.irps.is_empty() {
                return empty("IRPs");
            }
            table(
                &["#", "IRP", "major", "minor", "PID", "thread", "saltos", "status", "concluído"],
                store.irps.iter().map(|life| vec![life.number.to_string(), hex(life.address), format!("{:#x}", life.major), format!("{:#x}", life.minor), life.pid.to_string(), format!("{:#x}", life.thread), life.steps.len().to_string(), life.final_status.map_or("-".into(), |status| format!("{status:#010x}")), if life.completed { "sim".into() } else { "não".into() }]),
            )
        }
        Tab::Snapshots => match state.extras.snapshots.as_deref() {
            Some(Ok(list)) => table(&["id", "nome", "tamanho", "data", "relógio da VM", "icount"], list.iter().map(|item| vec![item.id.clone(), item.tag.clone(), item.vm_size.clone(), item.date.clone(), item.vm_clock.clone(), item.icount.clone()])),
            Some(Err(error)) => return Err(error.clone()),
            None => return empty("Snapshots"),
        },
        Tab::Types | Tab::Registry | Tab::Objects | Tab::Files => return Err(format!("{}: sem cópia em texto (use o menu de contexto das linhas)", tab.title())),
    };
    Ok(text)
}

/// Copia a aba para a área de transferência e conta na barra de estado e no
/// log de eventos.
pub(crate) fn copy_tab(context: &egui::Context, state: &mut UiState, tab: Tab) {
    match tab_text(state, tab) {
        Ok(text) => {
            let lines = text.lines().count();
            context.copy_text(text);
            state.last_message = format!("copiada a aba {} ({lines} linhas)", tab.title());
            state.events.push(Level::Info, state.last_message.clone());
        }
        Err(reason) => {
            state.last_message = reason.clone();
            state.events.push(Level::Warning, reason);
        }
    }
}

/// O texto do estado para quem não tem a aba aberta (a barra de estado
/// copiada pelo menu).
pub(crate) fn status_text(state: &UiState) -> String {
    let line = crate::status::target_line(&state.snapshot);
    let status = match &state.status {
        Status::Stopped => "pausado".to_string(),
        Status::Running => "rodando".to_string(),
        Status::Launching(line) => format!("abrindo: {line}"),
        Status::Connecting(address) => format!("conectando a {address}"),
        Status::Idle => "sem alvo".to_string(),
        Status::Disconnected(reason) => format!("desconectado: {reason}"),
    };
    [status, line.cpu, line.irql, line.process, line.thread, line.mode, line.context, state.snapshot.exception.clone().unwrap_or_default()].into_iter().filter(|part| !part.is_empty()).collect::<Vec<_>>().join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_are_tab_separated() {
        let text = table(&["a", "b"], vec![vec!["1".to_string(), "2".to_string()], vec!["3".to_string(), String::new()]]);
        assert_eq!(text, "a\tb\n1\t2\n3\t\n");
        assert_eq!(bytes_text(&[0x90, 0xCC]), "90 CC");
    }
}
