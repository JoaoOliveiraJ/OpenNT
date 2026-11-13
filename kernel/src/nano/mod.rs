//! Nanokernel.
//!
//! Filosofia nanokernel: o núcleo faz o mínimo (interrupções, IPC,
//! escalonamento). Todo o resto — drivers, FS, console, win32 — são serviços.

pub mod interrupts;
pub mod kernel;
pub mod message_channels;
