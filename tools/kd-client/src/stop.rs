//! A resposta de parada do alvo: `S05` ou `T05thread:1;swbreak:;` (o sinal,
//! a thread do protocolo, que é o processador + 1, e a razão).

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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopReply {
    pub signal: u8,
    /// Thread do protocolo (processador + 1), quando informada.
    pub thread: Option<u64>,
    pub reasons: Vec<Reason>,
    /// O pacote como chegou.
    pub packet: String,
}

impl StopReply {
    /// `None` se o pacote não é uma resposta de parada.
    pub fn parse(packet: &str) -> Option<Self> {
        if !packet.starts_with('T') && !packet.starts_with('S') {
            return None;
        }
        let signal = u8::from_str_radix(packet.get(1..3)?, 16).ok()?;
        let mut reply = StopReply { signal, thread: None, reasons: Vec::new(), packet: packet.to_string() };
        for field in packet.get(3..).unwrap_or("").split(';').filter(|field| !field.is_empty()) {
            let (key, value) = field.split_once(':').unwrap_or((field, ""));
            match key {
                "thread" => reply.thread = u64::from_str_radix(value, 16).ok(),
                "swbreak" => reply.reasons.push(Reason::SoftwareBreak),
                "hwbreak" => reply.reasons.push(Reason::HardwareBreak),
                "watch" | "awatch" | "rwatch" => reply.reasons.push(Reason::Watch { kind: key.to_string(), address: u64::from_str_radix(value, 16).unwrap_or(0) }),
                "membp" => reply.reasons.push(Reason::Memory { address: u64::from_str_radix(value, 16).unwrap_or(0) }),
                _ => {}
            }
        }
        Some(reply)
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
}
