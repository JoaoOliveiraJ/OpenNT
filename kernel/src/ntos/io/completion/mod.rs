//! Portas de conclusão de I/O (o iocomp do NT): criação, remoção,
//! IoSetIoCompletionEx e a porta de um FILE_OBJECT.

pub mod create;
pub mod file_port;
pub mod remove;
pub mod set;
