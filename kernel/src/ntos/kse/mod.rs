//! Kernel Shim Engine (KSE) — o motor de shims de drivers do ntoskrnl. O
//! OpenNT não tem banco de shims; `shim_engine` reproduz o motor não
//! inicializado.
pub mod shim_engine;
pub mod exports;
