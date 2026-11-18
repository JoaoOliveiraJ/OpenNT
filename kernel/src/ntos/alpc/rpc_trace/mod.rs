//! Rastro do tráfego ALPC na serial (`--trace-rpc`, a opção de carga
//! TRACERPC), para achar a chamada RPC que falha: uma linha `[rpc]` por
//! mensagem que passa por uma porta de servidor (`alpc/server.rs`).
//!
//! Cada linha traz o nome da porta de conexão do servidor, o pid do cliente e
//! o do servidor (`->` quando o cliente envia, `<-` quando o servidor
//! responde ou manda), o Type que a mensagem leva (com os bits altos), o
//! MessageId, o ValidAttributes do ALPC_MESSAGE_ATTRIBUTES de envio e quais
//! atributos chegaram ao destino com conteúdo (`leva`: o contexto de
//! segurança, a vista de dados, os handles). Nas portas do `\RPC Control`,
//! onde o rpcrt4 cria os endpoints LRPC, os dados de LPC_REQUEST, LPC_REPLY
//! e LPC_DATAGRAM são decodificados ([`lrpc`]):
//!
//! - o bind mostra a interface (UUID e versão) e os contextos de
//!   apresentação oferecidos, que ficam guardados pela porta do cliente;
//! - o pedido mostra a interface do contexto que ele leva e o opnum;
//! - a resposta, a falha (o código de falha do RPC) e a resposta do bind
//!   mostram o pedido a que respondem (pelo MessageId na porta de conexão).
//!
//! O formato, com valores ilustrativos (o cliente de pid 612 faz o bind de
//! uma interface na porta do servidor de pid 640, chama o opnum 7 dela e
//! recebe a falha 5):
//!
//! ```text
//! [rpc] \RPC Control\exemplo pid 612 -> 640 LPC_REQUEST(0x6001) id 3 atrib 0x20000000 lrpc bind 01234567-89ab-cdef-0123-456789abcdef v1.0 sintaxes 0x3 ctx 0,1
//! [rpc] \RPC Control\exemplo pid 612 <- 640 LPC_REPLY(0x2) id 3 atrib 0x0 lrpc bind aceito sintaxe 0x1 (01234567-89ab-cdef-0123-456789abcdef v1.0)
//! [rpc] \RPC Control\exemplo pid 612 -> 640 LPC_REQUEST(0x2001) id 4 atrib 0xa2000000 leva seg lrpc pedido 01234567-89ab-cdef-0123-456789abcdef v1.0 opnum 7
//! [rpc] \RPC Control\exemplo pid 612 <- 640 LPC_REPLY(0x2) id 4 atrib 0x0 lrpc falha 0x5 (01234567-89ab-cdef-0123-456789abcdef v1.0 opnum 7)
//! ```
//!
//! Cada mensagem que uma thread do servidor tira da fila também sai numa
//! linha com o `pid:tid` de quem a recebeu ([`received`]):
//!
//! ```text
//! [rpc] \RPC Control\exemplo id 4 recebido por 640:652
//! ```
//!
//! O rastro só observa: não muda mensagem, status nem estado do ALPC. Sem a
//! opção, cada ponto de envio só lê [`enabled`]; o estado daqui (os nomes das
//! portas, os binds e os pedidos à espera de resposta) só existe com ela.

pub mod lrpc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use core::fmt::Write;

use crate::rtl::SpinLock;
use lrpc::{Interface, Message};

/// O diretório dos endpoints LRPC.
const RPC_CONTROL: &str = "\\RPC Control\\";
/// Pedidos guardados à espera da resposta; os mais antigos saem primeiro (um
/// pedido cujo cliente saiu nunca é respondido).
const MAX_CALLS: usize = 512;
/// Binds guardados; acima disso o mais antigo pela chave sai.
const MAX_BINDINGS: usize = 4096;

/// Tipos de PORT_MESSAGE (o byte baixo de Type) que levam dados LRPC.
const LPC_REQUEST: u16 = 1;
const LPC_REPLY: u16 = 2;
const LPC_DATAGRAM: u16 = 3;

/// Atributos de mensagem (ALPC_MESSAGE_*_ATTRIBUTE) com conteúdo que o
/// destino recebe.
pub const CARRIED_SECURITY: u32 = 0x8000_0000;
pub const CARRIED_VIEW: u32 = 0x4000_0000;
pub const CARRIED_HANDLES: u32 = 0x1000_0000;

/// O rastro está ligado (`--trace-rpc`).
#[inline]
pub fn enabled() -> bool {
    crate::ntos::init::boot_config::trace_rpc()
}

/// Quem envia a mensagem rastreada.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Direction {
    /// O cliente (ou o kernel, por ele) envia ao servidor.
    #[default]
    ToServer,
    /// O servidor responde ou manda ao cliente.
    ToClient,
}

/// Uma mensagem rastreada.
#[derive(Default)]
pub struct Record<'a> {
    /// A porta de conexão do servidor (o nome e os pedidos à espera).
    pub listener: u64,
    /// A porta do cliente (os binds dele); 0 quando não há.
    pub client_port: u64,
    pub client: u64,
    pub server: u64,
    pub direction: Direction,
    /// O Type que a mensagem leva.
    pub message_type: u16,
    pub id: u32,
    /// O ValidAttributes do envio.
    pub attributes: u32,
    /// Os atributos com conteúdo que chegam ao destino (`CARRIED_*`).
    pub carried: u32,
    /// Os dados que seguem o PORT_MESSAGE.
    pub data: &'a [u8],
    /// O status de um envio recusado.
    pub status: Option<u32>,
}

/// O pedido LRPC a que uma resposta responde.
#[derive(Clone, Copy)]
enum Called {
    Bind(Interface),
    Request { interface: Option<Interface>, context: u32, opnum: u32 },
}

struct Pending {
    listener: u64,
    id: u32,
    called: Called,
}

struct State {
    /// O nome de cada porta de conexão, pelo ponteiro dela.
    names: BTreeMap<u64, String>,
    /// A interface de cada contexto de apresentação, por (porta do cliente,
    /// contexto).
    bindings: BTreeMap<(u64, u32), Interface>,
    calls: VecDeque<Pending>,
}

static STATE: SpinLock<State> = SpinLock::new(State { names: BTreeMap::new(), bindings: BTreeMap::new(), calls: VecDeque::new() });

/// O servidor criou a porta de conexão `listener` com esse nome.
pub fn port_created(listener: u64, name: Option<&str>) {
    let mut state = STATE.lock();
    match name {
        Some(name) => {
            state.names.insert(listener, String::from(name));
        }
        None => {
            state.names.remove(&listener);
        }
    }
}

/// A porta de conexão saiu: o nome e os pedidos à espera dela também.
pub fn port_closed(listener: u64) {
    let mut state = STATE.lock();
    state.names.remove(&listener);
    state.calls.retain(|pending| pending.listener != listener);
}

/// O cliente da porta `client_port` saiu: os binds dele também.
pub fn client_closed(client_port: u64) {
    let mut state = STATE.lock();
    state.bindings.retain(|&(port, _), _| port != client_port);
}

/// A linha de uma mensagem na serial.
pub fn message(record: &Record<'_>) {
    let line = line(record);
    crate::debug_print!("{}", line);
}

/// O texto da linha de uma mensagem; guarda os binds e os pedidos LRPC que
/// esperam resposta e solta o pedido que a resposta conclui.
pub fn line(record: &Record<'_>) -> String {
    let mut line = String::with_capacity(192);
    let mut state = STATE.lock();
    let name = state.names.get(&record.listener).map_or("(sem nome)", String::as_str);
    let lrpc_port = name.len() > RPC_CONTROL.len() && name.as_bytes()[..RPC_CONTROL.len()].eq_ignore_ascii_case(RPC_CONTROL.as_bytes());
    let arrow = if record.direction == Direction::ToServer { "->" } else { "<-" };
    let _ = write!(line, "[rpc] {} pid {} {} {} {}({:#x}) id {} atrib {:#x}", name, record.client, arrow, record.server, type_name(record.message_type), record.message_type, record.id, record.attributes);
    if record.carried != 0 {
        line.push_str(" leva");
        let mut separator = ' ';
        for (bit, label) in [(CARRIED_SECURITY, "seg"), (CARRIED_VIEW, "vista"), (CARRIED_HANDLES, "handles")] {
            if record.carried & bit != 0 {
                line.push(separator);
                line.push_str(label);
                separator = '+';
            }
        }
    }
    if let Some(status) = record.status {
        let _ = write!(line, " recusada {:#x}", status);
    }
    if lrpc_port && matches!(record.message_type & 0xFF, LPC_REQUEST | LPC_REPLY | LPC_DATAGRAM) {
        if let Some(message) = lrpc::decode(record.data) {
            describe(&mut state, record, &message, &mut line);
        }
    }
    line
}

/// A decisão do servidor sobre uma conexão (o NtAlpcAcceptConnectPort que
/// aceita ou recusa), para o cliente que esperava por ela.
pub fn connection_decided(listener: u64, client: u64, server: u64, id: u32, status: u32) {
    let name = STATE.lock().names.get(&listener).cloned().unwrap_or_else(|| String::from("(sem nome)"));
    let verdict = if status == 0 { "aceita" } else { "recusada" };
    crate::debug_print!("[rpc] {} pid {} <- {} conexao {} id {} status {:#x}", name, client, server, verdict, id, status);
}

/// O servidor tirou da fila da porta de conexão `listener` a mensagem `id`:
/// o `pid:tid` da thread do servidor que a recebeu. Separa a mensagem que
/// nunca chegou ao servidor da que chegou a uma thread dele e ficou sem
/// resposta.
pub fn received(listener: u64, id: u32, pid: u64, tid: u64) {
    let name = STATE.lock().names.get(&listener).cloned().unwrap_or_else(|| String::from("(sem nome)"));
    crate::debug_print!("[rpc] {} id {} recebido por {}:{}", name, id, pid, tid);
}

/// O nome do Type de um PORT_MESSAGE (o byte baixo).
fn type_name(message_type: u16) -> &'static str {
    match message_type & 0xFF {
        1 => "LPC_REQUEST",
        2 => "LPC_REPLY",
        3 => "LPC_DATAGRAM",
        4 => "LPC_LOST_REPLY",
        5 => "LPC_PORT_CLOSED",
        6 => "LPC_CLIENT_DIED",
        7 => "LPC_EXCEPTION",
        8 => "LPC_DEBUG_EVENT",
        9 => "LPC_ERROR_EVENT",
        10 => "LPC_CONNECTION_REQUEST",
        _ => "tipo",
    }
}

/// A parte LRPC da linha; guarda os binds e os pedidos que esperam resposta
/// e acha o pedido de uma resposta.
fn describe(state: &mut State, record: &Record<'_>, message: &Message, line: &mut String) {
    let to_server = record.direction == Direction::ToServer;
    // Só um envio do cliente que espera resposta e que chegou ao servidor.
    let awaits_reply = to_server && record.message_type & 0xFF == LPC_REQUEST && record.status.is_none();
    match *message {
        Message::Request { context, opnum, flags, object, .. } => {
            let interface = if to_server { state.bindings.get(&(record.client_port, context)).copied() } else { None };
            line.push_str(" lrpc pedido ");
            push_call(line, interface, context, opnum);
            if let Some(object) = object {
                let _ = write!(line, " objeto {}", object);
            }
            if flags & lrpc::FLAG_VIEW != 0 {
                line.push_str(" vista");
            }
            if awaits_reply {
                remember(state, record, Called::Request { interface, context, opnum });
            }
        }
        Message::Bind { interface, syntaxes, contexts, status } if to_server => {
            let _ = write!(line, " lrpc bind {} sintaxes {:#x} ctx", interface, syntaxes);
            let mut separator = ' ';
            for context in contexts.iter().flatten() {
                let _ = write!(line, "{}{}", separator, context);
                separator = ',';
                if record.client_port != 0 {
                    if state.bindings.len() >= MAX_BINDINGS {
                        state.bindings.pop_first();
                    }
                    state.bindings.insert((record.client_port, *context as u32), interface);
                }
            }
            if status != 0 {
                let _ = write!(line, " status {:#x}", status);
            }
            if awaits_reply {
                remember(state, record, Called::Bind(interface));
            }
        }
        Message::Bind { syntaxes, status, .. } => {
            if status == 0 {
                let _ = write!(line, " lrpc bind aceito sintaxe {:#x}", syntaxes);
            } else {
                let _ = write!(line, " lrpc bind status {:#x} sintaxe {:#x}", status, syntaxes);
            }
            push_answered(state, record, line);
        }
        Message::Fault { status } => {
            let _ = write!(line, " lrpc falha {:#x}", status);
            push_answered(state, record, line);
        }
        Message::Response { flags, .. } => {
            line.push_str(" lrpc resposta");
            if flags & lrpc::FLAG_VIEW != 0 {
                line.push_str(" vista");
            }
            push_answered(state, record, line);
        }
        Message::Other(kind) => {
            let _ = write!(line, " lrpc {} {}", lrpc::kind_name(kind), kind);
        }
    }
}

/// A interface e o opnum de um pedido (o contexto quando o bind não foi
/// visto).
fn push_call(line: &mut String, interface: Option<Interface>, context: u32, opnum: u32) {
    match interface {
        Some(interface) => {
            let _ = write!(line, "{} opnum {}", interface, opnum);
        }
        None => {
            let _ = write!(line, "ctx {} opnum {}", context, opnum);
        }
    }
}

/// Guarda o pedido até a resposta do servidor pelo mesmo MessageId.
fn remember(state: &mut State, record: &Record<'_>, called: Called) {
    if state.calls.len() >= MAX_CALLS {
        state.calls.pop_front();
    }
    state.calls.push_back(Pending { listener: record.listener, id: record.id, called });
}

/// O pedido a que a resposta do servidor responde, entre parênteses.
fn push_answered(state: &mut State, record: &Record<'_>, line: &mut String) {
    if record.direction != Direction::ToClient || record.status.is_some() {
        return;
    }
    let Some(index) = state.calls.iter().position(|pending| pending.listener == record.listener && pending.id == record.id) else { return };
    let Some(pending) = state.calls.remove(index) else { return };
    line.push_str(" (");
    match pending.called {
        Called::Bind(interface) => {
            let _ = write!(line, "{}", interface);
        }
        Called::Request { interface, context, opnum } => push_call(line, interface, context, opnum),
    }
    line.push(')');
}
