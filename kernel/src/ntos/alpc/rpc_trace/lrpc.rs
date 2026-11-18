//! As mensagens LRPC do rpcrt4 (o RPC local sobre ALPC) que o rastro
//! `--trace-rpc` decodifica. O LRPC põe um cabeçalho próprio logo depois do
//! PORT_MESSAGE de 0x28 bytes; os offsets abaixo são relativos aos dados que
//! seguem o PORT_MESSAGE (o offset na mensagem inteira menos 0x28), como o
//! rpcrt4 19041 os escreve e lê:
//!
//! - o tipo LRPC fica nos primeiros oito bytes. O LRPC_ADDRESS::ProcessIO
//!   despacha os LPC_REQUEST que o servidor recebe por ele (0 o pedido, 1 o
//!   bind, 5 a mensagem reservada, 7 e 8 o HandleAckOrNackCallback, 9 o
//!   callback, 12 e 13 o HandlePipeAck; os outros são recusados), e o
//!   LRPC_BASE_CCALL::UnpackResponse separa a resposta (3) da falha (2);
//! - o pedido (o `_LRPC_REQUEST_MESSAGE` que o
//!   LRPC_BASE_CCALL::InitializeRequestAndAttributes monta; o
//!   LRPC_ADDRESS::HandleRequest exige 0x40 bytes) leva as flags em 0x08 (1:
//!   o UUID de objeto em 0x30; 4: os dados numa vista, com o tamanho em
//!   0x40), o id da chamada em 0x0C, o contexto de apresentação em 0x10 (o
//!   LRPC_SCALL::HandleRequest procura nele a interface entre as do bind da
//!   associação, RPC_S_UNKNOWN_IF sem ela) e o número do procedimento em 0x14
//!   (o ProcNum do RPC_MESSAGE). Os dados do stub começam em 0x40;
//! - o bind (o `_LRPC_BIND_MESSAGE` do LRPC_CASSOCIATION::Bind, 0x48 bytes)
//!   leva o RPC_SYNTAX_IDENTIFIER da interface em 0x0C (o UUID e as versões
//!   maior e menor), as sintaxes de transferência oferecidas em 0x20 (1 a
//!   NDR, 2 a NDR64, 4 a terceira) e o contexto de apresentação que o cliente
//!   escolheu para cada uma em 0x24, 0x26 e 0x28. O
//!   LRPC_ADDRESS::HandleBindRequest responde com a mesma mensagem, com o
//!   status do LRPC_SASSOCIATION::AddBinding em 0x08 e a sintaxe aceita em
//!   0x20; o pedido seguinte leva em 0x10 o contexto dessa sintaxe;
//! - a falha (o `_LRPC_FAULT_MESSAGE` do SetFaultPacket) leva o status em
//!   0x08;
//! - a resposta leva as flags em 0x08 (4: os dados numa vista) e o id da
//!   chamada em 0x0C; os dados começam em 0x18.

use core::fmt;

/// Tipos LRPC decodificados (os oito primeiros bytes dos dados).
pub const REQUEST: u32 = 0;
pub const BIND: u32 = 1;
pub const FAULT: u32 = 2;
pub const RESPONSE: u32 = 3;

/// Flags do pedido e da resposta (0x08): o UUID de objeto presente e os
/// dados numa vista.
pub const FLAG_OBJECT: u32 = 1;
pub const FLAG_VIEW: u32 = 4;

/// O menor pedido e o menor bind que o servidor aceita, e o que a resposta e
/// a falha precisam ter para os campos lidos aqui.
const REQUEST_SIZE: usize = 0x40;
const BIND_SIZE: usize = 0x48;
const RESPONSE_SIZE: usize = 0x10;
const FAULT_SIZE: usize = 0x0C;

/// Um UUID no formato do GUID (Data1, Data2 e Data3 little-endian).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Uuid(pub [u8; 16]);

impl fmt::Display for Uuid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            formatter,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u16::from_le_bytes([b[4], b[5]]),
            u16::from_le_bytes([b[6], b[7]]),
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}

/// A interface de um bind (o RPC_SYNTAX_IDENTIFIER): o UUID e a versão.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Interface {
    pub uuid: Uuid,
    pub major: u16,
    pub minor: u16,
}

impl fmt::Display for Interface {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} v{}.{}", self.uuid, self.major, self.minor)
    }
}

/// Uma mensagem LRPC decodificada.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Message {
    /// O pedido: o contexto de apresentação do bind, o número do
    /// procedimento, o id da chamada, as flags e o UUID de objeto.
    Request { context: u32, opnum: u32, call: u32, flags: u32, object: Option<Uuid> },
    /// O bind e a resposta a ele: a interface, as sintaxes (as oferecidas no
    /// pedido, a aceita na resposta), o contexto de apresentação de cada
    /// sintaxe oferecida e o status (o da resposta).
    Bind { interface: Interface, syntaxes: u32, contexts: [Option<u16>; 3], status: u32 },
    /// A falha: o status que o servidor devolve no lugar da resposta.
    Fault { status: u32 },
    /// A resposta: o id da chamada e as flags.
    Response { call: u32, flags: u32 },
    /// Os outros tipos, pelo número.
    Other(u32),
}

fn read16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn uuid_at(data: &[u8], offset: usize) -> Uuid {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&data[offset..offset + 16]);
    Uuid(bytes)
}

/// Decodifica os dados que seguem o PORT_MESSAGE; `None` quando não cabem o
/// tipo ou os campos que ele exige.
pub fn decode(data: &[u8]) -> Option<Message> {
    if data.len() < 8 {
        return None;
    }
    let kind = read32(data, 0);
    match kind {
        REQUEST if data.len() >= REQUEST_SIZE => {
            let flags = read32(data, 0x08);
            Some(Message::Request { context: read32(data, 0x10), opnum: read32(data, 0x14), call: read32(data, 0x0C), flags, object: (flags & FLAG_OBJECT != 0).then(|| uuid_at(data, 0x30)) })
        }
        BIND if data.len() >= BIND_SIZE => {
            let syntaxes = read32(data, 0x20);
            let mut contexts = [None; 3];
            for (index, context) in contexts.iter_mut().enumerate() {
                if syntaxes & (1 << index) != 0 {
                    *context = Some(read16(data, 0x24 + 2 * index));
                }
            }
            let interface = Interface { uuid: uuid_at(data, 0x0C), major: read16(data, 0x1C), minor: read16(data, 0x1E) };
            Some(Message::Bind { interface, syntaxes, contexts, status: read32(data, 0x08) })
        }
        FAULT if data.len() >= FAULT_SIZE => Some(Message::Fault { status: read32(data, 0x08) }),
        RESPONSE if data.len() >= RESPONSE_SIZE => Some(Message::Response { call: read32(data, 0x0C), flags: read32(data, 0x08) }),
        REQUEST | BIND | FAULT | RESPONSE => None,
        other => Some(Message::Other(other)),
    }
}

/// O nome de um tipo LRPC que o rastro não decodifica, pela rotina do
/// LRPC_ADDRESS::ProcessIO que o trata.
pub fn kind_name(kind: u32) -> &'static str {
    match kind {
        5 => "reservada",
        7 | 8 => "ack de callback",
        9 => "callback",
        12 | 13 => "ack de pipe",
        _ => "tipo desconhecido",
    }
}
