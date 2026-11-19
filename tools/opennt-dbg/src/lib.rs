//! `opennt-dbg`: o depurador gráfico do kernel do OpenNT, no espírito do
//! WinDbg, para o depurador do próprio OpenNT (`kernel/src/ntos/kd`, o
//! protocolo remoto do GDB na COM2 com as extensões do OpenNT).
//!
//! - `backend`: a sessão com o alvo numa thread (o `opennt_kd::Client`, o
//!   mesmo do `cargo xtask debug`), publicando um `Snapshot` por parada;
//! - `launcher`: o `--launch` (build e QEMU pelo `cargo xtask debug
//!   --launch --no-client`), as opções do `xtask` e o endereço de um QEMU
//!   aberto digitados na janela;
//! - `session`: as sessões com nome (breakpoints, expressões, memória e
//!   opções de abertura);
//! - `script`: os roteiros do kd (a linguagem do `--script` do test-boot)
//!   e o texto da gravação dos comandos;
//! - `app`: a janela (egui/eframe com painéis encaixáveis do `egui_dock`);
//!   as vistas do estado da máquina ficam em `app/views.rs`;
//! - `details`: as leituras extras das vistas (espera e prioridade das
//!   threads pelo KTHREAD, a parte de usuário da pilha, o estado do PDB de
//!   cada módulo) e os textos dos registradores;
//! - `disasm`: a desmontagem (iced-x86) com os símbolos do cliente;
//! - `source`: as linhas de código e as variáveis locais pelo DWARF do
//!   `kernel.elf`;
//! - `scenario`: roteiros sem janela (o teste de fumaça e as capturas);
//! - `offscreen`: a janela desenhada sem GPU (a captura de tela).

pub mod app;
pub mod backend;
pub mod details;
pub mod disasm;
pub mod launcher;
pub mod offscreen;
pub mod scenario;
pub mod script;
pub mod session;
pub mod source;

use eframe::egui;

/// A raiz do repositório deste checkout (o crate fica em `tools/opennt-dbg`).
pub fn workspace_root() -> std::path::PathBuf {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.ancestors().nth(2).map(std::path::Path::to_path_buf).unwrap_or_else(|| manifest.to_path_buf())
}

/// O visual da janela (o mesmo na tela e na captura): tema escuro, fontes
/// um pouco maiores que as do egui e espaçamento uniforme.
pub fn configure(context: &egui::Context) {
    apply_theme(context, true);
    context.all_styles_mut(|style| {
        for (text_style, font) in style.text_styles.iter_mut() {
            font.size = match text_style {
                egui::TextStyle::Monospace => 13.0,
                egui::TextStyle::Heading => 17.0,
                egui::TextStyle::Small => 10.5,
                _ => 13.5,
            };
        }
        style.spacing.item_spacing = egui::vec2(8.0, 3.0);
        style.spacing.button_padding = egui::vec2(6.0, 2.0);
    });
}

/// O tema escuro ou o claro.
pub fn apply_theme(context: &egui::Context, dark: bool) {
    context.set_theme(if dark { egui::Theme::Dark } else { egui::Theme::Light });
}
