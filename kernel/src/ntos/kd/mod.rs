//! kd: o depurador do kernel.
//!
//! O estado que os drivers veem (KdDebuggerEnabled e afins) mora em
//! `debugger`; com `--kd=comN` o depurador do próprio OpenNT atende um host
//! pelo protocolo remoto do GDB numa porta serial (`transport`, `packet`,
//! `session`), com as paradas, o congelamento dos outros processadores e
//! os passos em `stop`, os breakpoints em `breakpoints`, o acesso à memória
//! em `memory`, os registradores em `registers`, as consultas do OpenNT em
//! `monitor` e `inspect` (objetos do NT), o rastro de instruções em `trace`,
//! a saída do DbgPrint em `print_log` e o serviço de depuração (`int 0x2D`)
//! do modo usuário em `debug_service`. Para os processos de usuário: o
//! processo das leituras em `process_context`, as paradas do anel 3 em
//! `user_debug`, os pontos de evento (processo, thread, imagem) em `events`,
//! a tabela de handles em `handles` e as regiões e threads de usuário em
//! `regions`. Extensões do OpenNT: a metade alta dos YMM e os registradores
//! de depuração por `p` em `extended_state`, os breakpoints de hardware do
//! modo usuário por processo em `user_hardware` e os breakpoints de memória
//! por página em `page_breakpoints`. Para as ferramentas de engenharia
//! reversa: o fluxo de registros com a máquina rodando em `stream`, o
//! monitor de APIs em `api_monitor`, o rastreador de IRPs em `irp_trace` e
//! os exploradores do Registro, do namespace e dos arquivos em `explore`.
pub mod api_monitor;
pub mod breakpoints;
pub mod debug_filter;
pub mod debug_service;
pub mod debugger;
pub mod events;
pub mod explore;
pub mod exports;
pub mod extended_state;
pub mod handles;
pub mod inspect;
pub mod irp_trace;
pub mod memory;
pub mod monitor;
pub mod objects;
pub mod packet;
pub mod page_breakpoints;
pub mod power;
pub mod print_log;
pub mod process_context;
pub mod regions;
pub mod registers;
pub mod session;
pub mod stop;
pub mod stream;
pub mod trace;
pub mod transport;
pub mod user_debug;
pub mod user_hardware;

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
    stream::reserve();
    stop::activate(transport::line_status_port());
    debug_print!("[kd] depurador do kernel na {} (porta {:#x}, protocolo remoto do GDB)", name, base);
    if transport::byte_pending() {
        stop::break_in_now();
    }
}
