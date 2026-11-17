//! `--launch`: o build e o QEMU pelo `cargo xtask debug --launch
//! --no-client`, o módulo do `kd-client` (`kd_client::launcher`),
//! compartilhado com o servidor MCP.

pub use kd_client::launcher::*;
