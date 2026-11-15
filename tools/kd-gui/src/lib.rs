//! `opennt-dbg`: o depurador gráfico do kernel do OpenNT, no espírito do
//! WinDbg, para o depurador do próprio OpenNT (`kernel/src/ntos/kd`, o
//! protocolo remoto do GDB na COM2 com as extensões do OpenNT).
//!
//! - `backend`: a sessão com o alvo numa thread (o `kd_client::Client`, o
//!   mesmo do `cargo xtask debug`), publicando um `Snapshot` por parada;
//! - `launcher`: o `--launch` (build e QEMU pelo `cargo xtask debug
//!   --launch --no-client`);
//! - `app`: a janela (egui/eframe com painéis encaixáveis do `egui_dock`);
//! - `disasm`: a desmontagem (iced-x86) com os símbolos do cliente;
//! - `source`: as linhas de código pelo DWARF do `kernel.elf`;
//! - `offscreen`: a janela desenhada sem GPU (a captura de tela).

pub mod app;
pub mod backend;
pub mod disasm;
pub mod launcher;
pub mod offscreen;
pub mod source;

use eframe::egui;

/// A raiz do repositório deste checkout (o crate fica em `tools/kd-gui`).
pub fn workspace_root() -> std::path::PathBuf {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.ancestors().nth(2).map(std::path::Path::to_path_buf).unwrap_or_else(|| manifest.to_path_buf())
}

/// O visual da janela (o mesmo na tela e na captura): tema escuro e as
/// fontes um pouco maiores que as do egui.
pub fn configure(context: &egui::Context) {
    context.set_theme(egui::Theme::Dark);
    context.all_styles_mut(|style| {
        for (text_style, font) in style.text_styles.iter_mut() {
            font.size = match text_style {
                egui::TextStyle::Monospace => 13.0,
                egui::TextStyle::Heading => 17.0,
                egui::TextStyle::Small => 10.0,
                _ => 13.5,
            };
        }
    });
}
