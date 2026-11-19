//! A barra de estado: o estado do alvo (rodando há quanto tempo, pausado,
//! abrindo, conectando, sem alvo, desconectado), o processador, o processo
//! e a thread da visão, o modo (kernel ou usuário), os PDBs que ainda estão
//! chegando, o que o backend está fazendo (com o tempo), a última mensagem
//! e, à direita, as teclas principais (as das preferências).

use std::time::Duration;

use eframe::egui::{self, Color32, RichText, Sense, Ui, Vec2};

use crate::app::{current_rip, mono, palette, shown_processor, UiState};
use crate::backend::{Snapshot, Status, TimeMode, View};
use crate::preferences::Action;

/// Um tempo em palavras curtas: `12 s`, `3 min 05 s`, `1 h 02 min`.
pub fn elapsed_text(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs();
    if seconds < 60 {
        format!("{seconds} s")
    } else if seconds < 3600 {
        format!("{} min {:02} s", seconds / 60, seconds % 60)
    } else {
        format!("{} h {:02} min", seconds / 3600, (seconds % 3600) / 60)
    }
}

/// O que a barra mostra da visão parada.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TargetLine {
    /// `CPU 1 de 4`.
    pub cpu: String,
    pub irql: String,
    /// O processo da thread mostrada (nome e PID quando a lista os tem).
    pub process: String,
    /// `thread 0x1c (ETHREAD ...)`, `thread de usuário 12`.
    pub thread: String,
    /// `modo kernel` ou `modo usuário`.
    pub mode: String,
    /// O processo das leituras, quando não é o da thread.
    pub context: String,
}

fn find_thread(snapshot: &Snapshot, ethread: u64) -> Option<&kd_client::monitor::Thread> {
    if ethread == 0 {
        return None;
    }
    snapshot.threads.iter().map(|row| &row.thread).find(|thread| thread.ethread == ethread)
}

/// Os campos da visão de um snapshot: o processador mostrado (o da parada
/// ou o escolhido), a thread dele (ou a escolhida), o processo e o modo.
pub fn target_line(snapshot: &Snapshot) -> TargetLine {
    let mut line = TargetLine::default();
    let processor = shown_processor(snapshot);
    if let Some(processor) = processor {
        let total = snapshot.processors.len();
        line.cpu = if total > 1 { format!("CPU {} de {total}", processor.number) } else { format!("CPU {}", processor.number) };
        line.irql = format!("IRQL {}", processor.irql);
    }
    let ethread = match snapshot.view {
        View::Thread(ethread) => Some(ethread),
        View::UserThread(_) => None,
        View::Owner | View::Cpu(_) => processor.map(|processor| processor.thread),
    };
    let thread = ethread.and_then(|ethread| find_thread(snapshot, ethread));
    line.thread = match (snapshot.view, thread, ethread) {
        (View::UserThread(tid), _, _) => format!("thread de usuário {tid}"),
        (_, Some(thread), _) => format!("thread {} ({:#x})", thread.tid, thread.ethread),
        (_, None, Some(ethread)) if ethread != 0 => format!("ETHREAD {ethread:#x}"),
        _ => String::new(),
    };
    line.process = match (thread, processor) {
        (Some(thread), _) if !thread.process.is_empty() => format!("{} (PID {})", thread.process, thread.pid),
        (_, Some(processor)) if !processor.process.is_empty() && !matches!(snapshot.view, View::Thread(_) | View::UserThread(_)) => {
            match snapshot.processes.iter().find(|process| process.name.eq_ignore_ascii_case(&processor.process)) {
                Some(process) => format!("{} (PID {})", process.name, process.pid),
                None => processor.process.clone(),
            }
        }
        _ => String::new(),
    };
    if let View::UserThread(_) = snapshot.view {
        if let Some(process) = &snapshot.process {
            line.process = format!("{} (PID {})", process.name, process.pid);
        }
    }
    // O processo das leituras (aba Processos), quando é outro.
    if let Some(process) = &snapshot.process {
        let shown = format!("{} (PID {})", process.name, process.pid);
        if shown != line.process {
            line.context = format!("leituras em {shown}");
        }
    }
    line.mode = match current_rip(snapshot) {
        Some(rip) if snapshot.user_mode || rip < 0x8000_0000_0000 => "modo usuário".into(),
        Some(_) => "modo kernel".into(),
        None => String::new(),
    };
    line
}

/// O estado em uma palavra, a cor do selo e o texto ao lado.
fn badge(status: &Status, since: Duration) -> (Color32, String) {
    match status {
        Status::Stopped => (Color32::from_rgb(0xC0, 0x30, 0x30), "Pausado".to_string()),
        Status::Running => (Color32::from_rgb(0x20, 0x90, 0x40), format!("Rodando há {}", elapsed_text(since))),
        Status::Launching(_) => (Color32::from_rgb(0xB0, 0x80, 0x10), format!("Abrindo há {}", elapsed_text(since))),
        Status::Connecting(_) => (Color32::from_rgb(0xB0, 0x80, 0x10), "Conectando".to_string()),
        Status::Idle => (Color32::GRAY, "Sem alvo".to_string()),
        Status::Disconnected(_) => (Color32::GRAY, "Desconectado".to_string()),
    }
}

/// As teclas principais para o estado de agora.
pub fn key_hints(state: &UiState) -> String {
    let key = |action: Action| state.prefs.binding(action).text();
    match state.status {
        Status::Stopped => format!("{} executar · {} entrar · {} passar · {} breakpoint · {} ir para · {} atalhos", key(Action::Go), key(Action::StepInto), key(Action::StepOver), key(Action::ToggleBreakpoint), key(Action::GoTo), key(Action::ShowShortcuts)),
        Status::Running => format!("{} pausar · {} atalhos", key(Action::Break), key(Action::ShowShortcuts)),
        _ => format!("{} atalhos", key(Action::ShowShortcuts)),
    }
}

/// A barra de estado inteira.
pub(crate) fn status_bar(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    // Os relógios da barra andam sozinhos com a máquina rodando ou com uma
    // tarefa no backend.
    if matches!(state.status, Status::Running | Status::Launching(_)) || !state.activity.is_empty() {
        ui.ctx().request_repaint_after(Duration::from_millis(500));
    }
    let hints = key_hints(state);
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        ui.label(RichText::new(hints).color(colors.dim).small());
        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
            let (fill, text) = badge(&state.status, state.status_since.elapsed());
            let galley = ui.painter().layout_no_wrap(text, egui::FontId::proportional(13.0), Color32::WHITE);
            let (rect, response) = ui.allocate_exact_size(Vec2::new(galley.size().x + 16.0, 18.0), Sense::click());
            ui.painter().rect_filled(rect, 2.0, fill);
            ui.painter().galley(rect.center() - galley.size() / 2.0, galley, Color32::WHITE);
            let tooltip = match &state.status {
                Status::Disconnected(reason) => format!("{reason}\n\nbotão direito: copiar o estado"),
                _ => "botão direito: copiar o estado (CPU, processo, thread, parada)".to_string(),
            };
            response.on_hover_text(tooltip).context_menu(|ui| {
                if ui.button("Copiar o estado").clicked() {
                    let text = crate::copy_text::status_text(state);
                    ui.ctx().copy_text(text);
                    ui.close();
                }
            });
            match &state.status {
                Status::Stopped => {
                    let line = target_line(&state.snapshot);
                    for (text, tooltip) in [(&line.cpu, "o processador mostrado (o da parada ou o escolhido na aba Threads)"), (&line.irql, "o IRQL desse processador"), (&line.process, "o processo da thread mostrada"), (&line.thread, "a thread mostrada (TID e ETHREAD)"), (&line.mode, "onde estava o RIP")] {
                        if !text.is_empty() {
                            ui.label(mono(text.as_str()).color(colors.blue)).on_hover_text(tooltip);
                            ui.separator();
                        }
                    }
                    if !line.context.is_empty() {
                        ui.label(mono(line.context.as_str()).color(colors.dim)).on_hover_text("as leituras de memória de usuário vão para este processo (aba Processos)");
                        ui.separator();
                    }
                    if let Some(exception) = &state.snapshot.exception {
                        ui.label(RichText::new(exception).color(colors.red)).on_hover_text("o motivo da parada");
                        ui.separator();
                    }
                }
                Status::Launching(line) => {
                    ui.add(egui::Label::new(mono(line.as_str()).color(colors.dim)).truncate());
                    ui.separator();
                }
                Status::Connecting(address) => {
                    ui.label(mono(format!("conectando a {address}")).color(colors.dim));
                    ui.separator();
                }
                Status::Disconnected(reason) => {
                    ui.label(mono(reason.lines().next().unwrap_or("")).color(colors.red));
                    ui.separator();
                }
                Status::Running | Status::Idle => {}
            }
            match &state.extras.mode {
                TimeMode::Normal => {}
                TimeMode::Snapshots => {
                    ui.label(mono("snapshots").color(colors.green)).on_hover_text("discos em qcow2: savevm/loadvm na aba Snapshots");
                    ui.separator();
                }
                mode @ TimeMode::Recording(_) => {
                    ui.label(mono(format!("● {}", mode.label())).color(colors.red)).on_hover_text("gravação do QEMU (icount): Arquivo > Reproduzir a gravação");
                    ui.separator();
                }
                mode @ TimeMode::Replay(..) => {
                    ui.label(mono(format!("⟲ {}", mode.label())).color(colors.yellow)).on_hover_text("reprodução: o gdbstub do QEMU, com os passos para trás");
                    ui.separator();
                }
            }
            // Os PDBs que ainda estão chegando (os nomes trocam sozinhos quando chegam).
            let pending: Vec<&str> = state.snapshot.modules.iter().filter(|module| module.pending).map(|module| module.name.as_str()).collect();
            if !pending.is_empty() {
                let names = pending.iter().take(20).copied().collect::<Vec<_>>().join(", ");
                ui.label(mono(format!("símbolos: {} PDB{} chegando", pending.len(), if pending.len() == 1 { "" } else { "s" })).color(colors.yellow)).on_hover_text(format!("baixando ou lendo: {names}; a janela segue respondendo e os nomes trocam quando chegam"));
                ui.separator();
            }
            if let Some(address) = &state.mcp_address {
                ui.label(mono(format!("MCP {address}")).color(colors.green)).on_hover_text(format!("servidor MCP desta janela: http://{address}/mcp"));
                ui.separator();
            }
            if state.highlight_mode {
                ui.label(mono("destaque (H)").color(colors.yellow));
                ui.separator();
            }
            if !state.activity.is_empty() {
                ui.spinner();
                let elapsed = state.activity_since.elapsed();
                let text = if elapsed >= Duration::from_secs(1) { format!("{} ({})", state.activity, elapsed_text(elapsed)) } else { state.activity.clone() };
                ui.label(RichText::new(text).color(colors.yellow)).on_hover_text("o backend está nesta tarefa; a janela segue respondendo, e os pedidos novos esperam a vez");
                ui.separator();
            }
            // A última mensagem: clique abre o log de eventos.
            let message = state.last_message.clone();
            if !message.is_empty() {
                let response = ui.add(egui::Label::new(mono(message).color(colors.dim)).truncate().sense(Sense::click()));
                if response.on_hover_text("clique: o log de eventos (aba Log)").clicked() {
                    state.log_mode = crate::console::EVENTS_MODE;
                    state.focus_tab.push(crate::app::Tab::Log);
                }
            }
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{RegisterRow, ThreadRow};
    use kd_client::monitor::{Process, Processor, Thread};

    fn processor(number: u64, thread: u64, process: &str) -> Processor {
        Processor { number, owner: number == 1, irql: 2, pcr: 0, thread, rip: 0, process: process.into() }
    }

    #[test]
    fn elapsed_in_words() {
        assert_eq!(elapsed_text(Duration::from_secs(7)), "7 s");
        assert_eq!(elapsed_text(Duration::from_secs(65)), "1 min 05 s");
        assert_eq!(elapsed_text(Duration::from_secs(3720)), "1 h 02 min");
    }

    #[test]
    fn target_line_of_a_stop() {
        let mut snapshot = Snapshot { stop_processor: Some(1), ..Default::default() };
        snapshot.processors = vec![processor(0, 0xA0, "Idle"), processor(1, 0xB0, "csrss.exe")];
        snapshot.threads = vec![ThreadRow { thread: Thread { pid: 0x1c4, tid: 0x1d0, ethread: 0xB0, state: "Running".into(), start: 0, process: "csrss.exe".into() }, start: String::new() }];
        snapshot.registers = vec![RegisterRow { name: "rip".into(), value: Some(0xFFFF_F800_0000_1000), changed: false }];
        let line = target_line(&snapshot);
        assert_eq!(line.cpu, "CPU 1 de 2");
        assert_eq!(line.irql, "IRQL 2");
        assert_eq!(line.thread, "thread 464 (0xb0)");
        assert_eq!(line.process, "csrss.exe (PID 452)");
        assert_eq!(line.mode, "modo kernel");
        assert!(line.context.is_empty());
        // A CPU escolhida (thread do protocolo = processador + 1), sem a thread na lista.
        snapshot.view = View::Cpu(1);
        snapshot.processes = vec![Process { pid: 0, eprocess: 0, cr3: 0, threads: 1, name: "Idle".into() }];
        snapshot.registers[0].value = Some(0x7FF0_0000_1000);
        let line = target_line(&snapshot);
        assert_eq!(line.cpu, "CPU 0 de 2");
        assert_eq!(line.thread, "ETHREAD 0xa0");
        assert_eq!(line.process, "Idle (PID 0)");
        assert_eq!(line.mode, "modo usuário");
        // Uma thread de usuário escolhida.
        snapshot.view = View::UserThread(12);
        assert_eq!(target_line(&snapshot).thread, "thread de usuário 12");
        // Sem parada nenhuma: tudo vazio.
        assert_eq!(target_line(&Snapshot::default()), TargetLine::default());
    }
}
