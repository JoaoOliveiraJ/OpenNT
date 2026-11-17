//! `opennt-mcp`: um servidor do Model Context Protocol para agentes de IA
//! dirigirem o depurador do OpenNT, sobre o mesmo cliente do `cargo xtask
//! debug` e do opennt-re (`kd-client`). O protocolo (JSON-RPC 2.0, a
//! negociação, ferramentas e recursos) é implementado aqui.
//!
//! - `server`: as mensagens do MCP (`initialize`, `tools/list`,
//!   `tools/call`, `resources/*`, `ping`);
//! - `tools`: as ferramentas (esquemas, conferência dos argumentos e a
//!   execução) e os recursos;
//! - `engine`: o dono da sessão (`Engine`): o `Standalone` do binário, ou o
//!   backend da janela do opennt-re;
//! - `transport`: stdio e HTTP local (127.0.0.1);
//! - `screenshot`: a tela do convidado em PNG pelo monitor do QEMU;
//! - `disasm`, `annotate`: a desmontagem e a análise automática (limites de
//!   função, laços, comentários das chamadas), compartilhadas com a janela
//!   CPU do opennt-re.

pub mod annotate;
pub mod disasm;
pub mod engine;
pub mod screenshot;
pub mod server;
pub mod tools;
pub mod transport;

pub use engine::{Engine, ImageCache, Standalone};
pub use server::Server;

/// A raiz do repositório deste checkout (o crate fica em `tools/kd-mcp`).
pub fn workspace_root() -> std::path::PathBuf {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.ancestors().nth(2).map(std::path::Path::to_path_buf).unwrap_or_else(|| manifest.to_path_buf())
}
