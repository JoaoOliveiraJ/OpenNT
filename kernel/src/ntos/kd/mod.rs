//! kd: o depurador do kernel.
//!
//! O estado que os drivers veem (KdDebuggerEnabled e afins) mora em
//! `debugger`; com `--kd=comN` o depurador do próprio OpenNT atende um host
//! pelo protocolo remoto do GDB numa porta serial (`transport`, `packet`,
//! `session`), com as paradas, o congelamento dos outros processadores e
//! os passos em `stop`, os breakpoints em `breakpoints`, o acesso à memória
//! em `memory`, os registradores em `registers`, as consultas do OpenNT em
//! `monitor` e `inspect` (objetos do NT), o rastro de instruções em `trace`
//! e a saída do DbgPrint em `print_log`.
pub mod breakpoints;
pub mod debug_filter;
pub mod debugger;
pub mod exports;
pub mod inspect;
pub mod memory;
pub mod monitor;
pub mod packet;
pub mod power;
pub mod print_log;
pub mod registers;
pub mod session;
pub mod stop;
pub mod trace;
pub mod transport;

use crate::ntos::init::boot_config;

/// Inicia o depurador pedido no boot (`--kd=comN`), como o KdInitSystem da
/// fase 0 com o transporte: sem a opção, nada muda. Um pedido de parada do
/// host que já esteja na porta para a máquina aqui mesmo.
pub fn initialize() {
    let name = boot_config::kernel_debugger();
    if name.is_empty() {
        return;
    }
    let Some(base) = transport::port_base(name) else {
        debug_print!("[kd] porta de depurador desconhecida: {} (use com2, com3 ou com4)", name);
        return;
    };
    if !transport::initialize(base) {
        debug_print!("[kd] {} ausente (porta {:#x}): depurador desligado", name, base);
        return;
    }
    if let Err(error) = debugger::enable_at_boot(base) {
        debug_print!("[kd] estado do depurador nao publicado: {}", error);
        return;
    }
    trace::reserve();
    stop::activate(transport::line_status_port());
    debug_print!("[kd] depurador do kernel na {} (porta {:#x}, protocolo remoto do GDB)", name, base);
    if transport::byte_pending() {
        stop::break_in_now();
    }
}
