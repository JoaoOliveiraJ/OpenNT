//! A resposta de parada do alvo: `S05` ou `T05thread:1;swbreak:;` (o sinal,
//! a thread do protocolo, que é o processador + 1, e a razão).
//!
//! O depurador do OpenNT põe mais na resposta para o cliente decidir a
//! parada sem idas e voltas: os registradores adiantados (`n:valor;`, os 24
//! primeiros do `g`), a impressão digital da lista de módulos (`modgen:`),
//! o EPROCESS corrente do processador (`process:`) e, numa carga de imagem
//! do filtro de carga, `library:;load:base,tamanho,pid,nome;` (o nome em
//! hexadecimal). Numa parada pedida por NMI vem `nmi:`; numa exceção do
//! anel 3 que o filtro por código parou, `exception:código;chance:n;` (e
//! `term:` quando é o fim do processo com o código). Um alvo sem eles (o
//! gdbstub do QEMU, um kernel antigo) deixa os campos vazios e o cliente
//! pergunta como antes.

/// Nomes dos sinais que o depurador do OpenNT usa.
pub const SIGNALS: &[(u8, &str)] = &[(2, "SIGINT (pedido de parada)"), (4, "SIGILL"), (5, "SIGTRAP"), (6, "SIGABRT (bugcheck/panico)"), (8, "SIGFPE"), (11, "SIGSEGV")];

/// Por que a máquina parou, além do sinal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    SoftwareBreak,
    HardwareBreak,
    /// Vigia de escrita (`watch`) ou de acesso (`awatch`/`rwatch`), com o
    /// endereço.
    Watch { kind: String, address: u64 },
    /// Breakpoint de memória por página do OpenNT (`membp:endereço`): o
    /// endereço que a instrução acessou.
    Memory { address: u64 },
    /// Carga de imagem pedida pelo filtro de carga (`library:` com o
    /// `load:` do OpenNT): base, tamanho, PID (0 = imagem de sistema) e o
    /// nome-base. Sem o `load:` (um GDB comum), tudo zero e nome vazio.
    Library { base: u64, size: u64, pid: u64, name: String },
    /// Parada pedida por NMI (`nmi:`).
    Nmi,
    /// Exceção do anel 3 parada pelo filtro por código (`exception:`,
    /// `chance:`, `term:`): o código, a chance (1 ou 2) e se é o fim do
    /// processo com o código.
    Exception { code: u32, chance: u8, termination: bool },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopReply {
    pub signal: u8,
    /// Thread do protocolo (processador + 1), quando informada.
    pub thread: Option<u64>,
    pub reasons: Vec<Reason>,
    /// Os registradores adiantados: número do protocolo e os dígitos (na
    /// ordem dos bytes do alvo, como no `g`).
    pub registers: Vec<(usize, String)>,
    /// A impressão digital da lista de módulos do alvo.
    pub module_generation: Option<u64>,
    /// O EPROCESS corrente do processador da parada.
    pub process: Option<u64>,
    /// O pacote como chegou.
    pub packet: String,
}

/// O `load:base,tamanho,pid,nome` de uma carga do filtro.
fn parse_load(value: &str) -> Option<Reason> {
    let mut fields = value.splitn(4, ',');
    let mut number = || fields.next().and_then(|field| u64::from_str_radix(field, 16).ok());
    let (base, size, pid) = (number()?, number()?, number()?);
    let name = super::rsp::decode_hex_text(fields.next().unwrap_or(""));
    Some(Reason::Library { base, size, pid, name })
}

impl StopReply {
    /// `None` se o pacote não é uma resposta de parada.
    pub fn parse(packet: &str) -> Option<Self> {
        if !packet.starts_with('T') && !packet.starts_with('S') {
            return None;
        }
        let signal = u8::from_str_radix(packet.get(1..3)?, 16).ok()?;
        let mut reply = StopReply { signal, thread: None, reasons: Vec::new(), registers: Vec::new(), module_generation: None, process: None, packet: packet.to_string() };
        let mut load = None;
        let mut library = false;
        let mut exception: Option<u32> = None;
        let mut chance = 0u8;
        let mut termination = false;
        for field in packet.get(3..).unwrap_or("").split(';').filter(|field| !field.is_empty()) {
            let (key, value) = field.split_once(':').unwrap_or((field, ""));
            match key {
                "thread" => reply.thread = u64::from_str_radix(value, 16).ok(),
                "swbreak" => reply.reasons.push(Reason::SoftwareBreak),
                "hwbreak" => reply.reasons.push(Reason::HardwareBreak),
                "watch" | "awatch" | "rwatch" => reply.reasons.push(Reason::Watch { kind: key.to_string(), address: u64::from_str_radix(value, 16).unwrap_or(0) }),
                "membp" => reply.reasons.push(Reason::Memory { address: u64::from_str_radix(value, 16).unwrap_or(0) }),
                "library" => library = true,
                "load" => load = parse_load(value),
                "modgen" => reply.module_generation = u64::from_str_radix(value, 16).ok(),
                "process" => reply.process = u64::from_str_radix(value, 16).ok().filter(|&process| process != 0),
                "nmi" => reply.reasons.push(Reason::Nmi),
                "exception" => exception = u32::from_str_radix(value, 16).ok(),
                "chance" => chance = value.parse().unwrap_or(0),
                "term" => termination = true,
                // Só dígitos hexadecimais: um registrador adiantado.
                _ if !key.is_empty() && key.len() <= 4 && key.bytes().all(|byte| byte.is_ascii_hexdigit()) => {
                    if let Ok(number) = usize::from_str_radix(key, 16) {
                        reply.registers.push((number, value.to_string()));
                    }
                }
                _ => {}
            }
        }
        if library || load.is_some() {
            reply.reasons.push(load.unwrap_or(Reason::Library { base: 0, size: 0, pid: 0, name: String::new() }));
        }
        if let Some(code) = exception {
            reply.reasons.push(Reason::Exception { code, chance, termination });
        }
        Some(reply)
    }

    /// O pacote sem os registradores adiantados, a impressão digital e o
    /// processo (o que a linha da parada mostra).
    pub fn brief(&self) -> String {
        let Some(fields) = self.packet.get(3..) else { return self.packet.clone() };
        let mut text = self.packet[..3].to_string();
        for field in fields.split(';').filter(|field| !field.is_empty()) {
            let key = field.split_once(':').map_or(field, |(key, _)| key);
            let register = !key.is_empty() && key.len() <= 4 && key.bytes().all(|byte| byte.is_ascii_hexdigit());
            if !register && key != "modgen" && key != "process" {
                text.push_str(field);
                text.push(';');
            }
        }
        text
    }

    /// Os dígitos de um registrador adiantado.
    pub fn register(&self, number: usize) -> Option<&str> {
        self.registers.iter().find(|(register, _)| *register == number).map(|(_, digits)| digits.as_str())
    }

    /// A carga de imagem da parada, se for uma.
    pub fn library(&self) -> Option<(u64, u64, u64, &str)> {
        self.reasons.iter().find_map(|reason| match reason {
            Reason::Library { base, size, pid, name } => Some((*base, *size, *pid, name.as_str())),
            _ => None,
        })
    }

    pub fn signal_name(&self) -> &'static str {
        SIGNALS.iter().find(|(number, _)| *number == self.signal).map_or("sinal", |(_, name)| name)
    }

    /// O processador da parada.
    pub fn processor(&self) -> Option<u64> {
        self.thread.map(|thread| thread.saturating_sub(1))
    }

    /// `swbreak`, `hwbreak`, `watch 0x...`.
    pub fn reason_text(&self) -> String {
        self.reasons
            .iter()
            .map(|reason| match reason {
                Reason::SoftwareBreak => "swbreak".to_string(),
                Reason::HardwareBreak => "hwbreak".to_string(),
                Reason::Watch { kind, address } => format!("{kind} {address:x}"),
                Reason::Memory { address } => format!("membp {address:x}"),
                Reason::Library { name, .. } if name.is_empty() => "library".to_string(),
                Reason::Library { name, pid, .. } => format!("library {name} (PID {pid})"),
                Reason::Nmi => "nmi".to_string(),
                Reason::Exception { code, chance, termination } => {
                    let which = match chance {
                        1 => "primeira chance",
                        2 => "segunda chance",
                        _ => "chance ?",
                    };
                    let end = if *termination { ", fim do processo" } else { "" };
                    format!("excecao {code:#010x} ({which}{end})")
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_breakpoint_stop() {
        let stop = StopReply::parse("T05thread:3;swbreak:;").unwrap();
        assert_eq!(stop.signal, 5);
        assert_eq!(stop.thread, Some(3));
        assert_eq!(stop.processor(), Some(2));
        assert_eq!(stop.reasons, vec![Reason::SoftwareBreak]);
        assert_eq!(stop.signal_name(), "SIGTRAP");
        assert_eq!(stop.reason_text(), "swbreak");
    }

    #[test]
    fn parses_watch_and_plain_signal() {
        let stop = StopReply::parse("T05thread:1;watch:fffff80040001000;").unwrap();
        assert_eq!(stop.reasons, vec![Reason::Watch { kind: "watch".into(), address: 0xfffff80040001000 }]);
        let stop = StopReply::parse("S02").unwrap();
        assert_eq!(stop.signal, 2);
        assert_eq!(stop.thread, None);
        let stop = StopReply::parse("T05thread:1;watch:7ff600001000;membp:7ff600001008;").unwrap();
        assert_eq!(stop.reasons[1], Reason::Memory { address: 0x7ff600001008 });
        assert_eq!(stop.reason_text(), "watch 7ff600001000 membp 7ff600001008");
        assert!(StopReply::parse("OK").is_none());
        assert!(StopReply::parse("E01").is_none());
    }

    /// A resposta do OpenNT com os registradores adiantados, a impressão da
    /// lista de módulos, o processo corrente e uma carga do filtro.
    #[test]
    fn parses_expedited_registers_generation_and_library() {
        let packet = "T05thread:2;library:;load:7ffb10000000,1a000,4d0,64776d636f72652e646c6c;00:0100000000000000;10:3412000000000000;12:33000000;modgen:9f3a;process:ffffa00000123080;";
        let stop = StopReply::parse(packet).unwrap();
        assert_eq!(stop.thread, Some(2));
        assert_eq!(stop.register(0), Some("0100000000000000"));
        assert_eq!(stop.register(16), Some("3412000000000000"));
        assert_eq!(stop.register(18), Some("33000000"));
        assert_eq!(stop.register(5), None);
        assert_eq!(stop.module_generation, Some(0x9f3a));
        assert_eq!(stop.process, Some(0xffff_a000_0012_3080));
        assert_eq!(stop.library(), Some((0x7ffb_1000_0000, 0x1a000, 0x4d0, "dwmcore.dll")));
        assert_eq!(stop.reason_text(), "library dwmcore.dll (PID 1232)");
        assert_eq!(stop.brief(), "T05thread:2;library:;load:7ffb10000000,1a000,4d0,64776d636f72652e646c6c;");
        assert_eq!(StopReply::parse("S05").unwrap().brief(), "S05");
        // `library` sem o `load:` (um stub comum) e as chaves conhecidas não
        // viram registradores.
        let plain = StopReply::parse("T05thread:1;library:;swbreak:;").unwrap();
        assert_eq!(plain.library(), Some((0, 0, 0, "")));
        assert!(plain.registers.is_empty());
        assert_eq!(plain.module_generation, None);
        assert!(StopReply::parse("T05thread:1;").unwrap().library().is_none());
    }

    /// A parada por NMI e a exceção do anel 3 do filtro por código.
    #[test]
    fn parses_nmi_and_ring3_exception() {
        let stop = StopReply::parse("T02thread:1;nmi:;").unwrap();
        assert_eq!(stop.reasons, vec![Reason::Nmi]);
        assert_eq!(stop.reason_text(), "nmi");
        let stop = StopReply::parse("T0bthread:1;exception:c0000409;chance:2;term:;process:ffffa00000123080;").unwrap();
        assert_eq!(stop.reasons, vec![Reason::Exception { code: 0xC000_0409, chance: 2, termination: true }]);
        assert_eq!(stop.reason_text(), "excecao 0xc0000409 (segunda chance, fim do processo)");
        assert!(stop.registers.is_empty());
        assert_eq!(stop.brief(), "T0bthread:1;exception:c0000409;chance:2;term:;");
    }
}
