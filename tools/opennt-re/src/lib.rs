//! `opennt-re`: o depurador de engenharia reversa do OpenNT, para o kernel
//! e para os processos de usuário que rodam nele, sobre o depurador do
//! próprio OpenNT (`kernel/src/ntos/kd`, o protocolo remoto do GDB na COM2
//! com as extensões do OpenNT). O layout é o dos depuradores de engenharia
//! reversa: abas no alto e a aba CPU com quatro painéis.
//!
//! - `backend`: a sessão com o alvo numa thread (o `opennt_kd::Client`),
//!   publicando um `Snapshot` por parada, com as vistas de engenharia
//!   reversa (`backend/views.rs`);
//! - `launcher`: o `--launch` (build e QEMU pelo `cargo xtask debug
//!   --launch --no-client`);
//! - `app`: a janela (abas, barra de ferramentas, atalhos, diálogos, barra
//!   de comando e de estado); `cpu`, `graph`, `views` e `panels`: as abas;
//! - `disasm`: a desmontagem (iced-x86) com os símbolos do cliente (o
//!   módulo do `opennt-mcp`, com a análise automática em `opennt_mcp::annotate`) e
//!   os nomes dentro dos operandos;
//! - `annotations`: os comentários a mais das linhas (imports, trampolins,
//!   o alvo do CFG, strings, NTSTATUS/HRESULT/Win32 e os campos dos tipos
//!   do PDB nos operandos de memória);
//! - `analysis`: a análise de um módulo inteiro aos poucos (as funções da
//!   `.pdata` com os pedaços juntos, as referências cruzadas e os ponteiros
//!   dos dados pela `.reloc`);
//! - `imports`: os imports de um PE (comuns e de carga adiada);
//! - `codes`: os nomes e os textos de NTSTATUS, HRESULT e erros do Win32;
//! - `highlight`: os pedaços de uma instrução para o modo de destaque (H);
//! - `dump`: os formatos das janelas Dump;
//! - `editor`: o modelo do editor de breakpoints;
//! - `asm`: o montador de uma linha (patch de instrução);
//! - `scan`: a imagem de um módulo para as buscas e o grafo;
//! - `source`: as linhas de código e as variáveis locais pelo DWARF do
//!   `kernel.elf`;
//! - `scenario`: roteiros sem janela (o teste de fumaça e as capturas);
//! - `offscreen`: a janela desenhada sem GPU (a captura de tela);
//! - `monitors`: as abas APIs (o monitor de APIs) e IRPs (o rastreador);
//! - `explorers`: as abas Tipos (ver como tipo), Registro, Objetos,
//!   Arquivos e Snapshots (com os passos para trás da reprodução);
//! - `preferences`: as preferências (aparência, atalhos, eventos), a lista
//!   dos atalhos (F1) e o banco por módulo;
//! - `navigation`: o histórico de idas (voltar e avançar), a janela Ir para
//!   com a busca aproximada sobre todos os símbolos (numa thread própria) e
//!   os marcadores;
//! - `status`: a barra de estado (o alvo, a CPU, o processo, a thread, os
//!   PDBs chegando, as tarefas do backend e as teclas principais);
//! - `console`: o painel do console, o transcrito em rolagem virtual e o log
//!   de eventos da janela;
//! - `copy_text`: copiar qualquer aba como texto;
//! - `layout`: a janela, os painéis e o arranjo das abas entre execuções;
//! - `processes`: as abas Processos (processos com sessão, contexto,
//!   módulos com o PDB, threads com as pilhas de usuário e de kernel,
//!   breakpoints de usuário, seguir um processo desde a criação) e Exceção;
//! - `exception`: o EXCEPTION_RECORD em palavras (fail-fast, exceções
//!   guardadas do WinRT, violação de acesso, C++) e onde achá-lo numa
//!   parada;
//! - `follow`: os planos de seguir e o texto dos eventos do opennt-kd.

pub mod analysis;
pub mod annotations;
pub mod app;
pub mod asm;
pub mod backend;
pub mod codes;
pub mod console;
pub mod copy_text;
pub mod cpu;
pub mod disasm;
pub mod dump;
pub mod editor;
pub mod exception;
pub mod explorers;
pub mod follow;
pub mod graph;
pub mod highlight;
pub mod imports;
pub mod launcher;
pub mod layout;
pub mod monitors;
pub mod navigation;
pub mod offscreen;
pub mod panels;
pub mod preferences;
pub mod processes;
pub mod scan;
pub mod scenario;
pub mod source;
pub mod status;
pub mod views;

use eframe::egui;

/// A raiz do repositório deste checkout (o crate fica em `tools/opennt-re`).
pub fn workspace_root() -> std::path::PathBuf {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.ancestors().nth(2).map(std::path::Path::to_path_buf).unwrap_or_else(|| manifest.to_path_buf())
}

/// O visual da janela (o mesmo na tela e na captura): tema claro, fontes
/// um pouco maiores que as do egui e espaçamento compacto.
pub fn configure(context: &egui::Context) {
    apply_theme(context, false);
    context.all_styles_mut(|style| {
        for (text_style, font) in style.text_styles.iter_mut() {
            font.size = match text_style {
                egui::TextStyle::Monospace => 12.5,
                egui::TextStyle::Heading => 16.0,
                egui::TextStyle::Small => 10.0,
                _ => 13.0,
            };
        }
        style.spacing.item_spacing = egui::vec2(6.0, 2.0);
        style.spacing.button_padding = egui::vec2(5.0, 1.0);
    });
}

/// O tema escuro ou o claro.
pub fn apply_theme(context: &egui::Context, dark: bool) {
    context.set_theme(if dark { egui::Theme::Dark } else { egui::Theme::Light });
}
