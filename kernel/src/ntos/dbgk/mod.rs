//! Dbgk: o subsistema de depuração do executive (relatórios ao vivo do
//! Windows Error Reporting e o evento SystemErrorPortReady do estado de
//! silo).

pub mod wer;
pub mod silo_state;
pub mod live_dump;
pub mod exports;
