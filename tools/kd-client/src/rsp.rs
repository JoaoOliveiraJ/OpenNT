//! Lado do host do protocolo serial remoto do GDB (RSP), sobre o socket TCP
//! em que o QEMU expõe a porta serial do depurador.
//!
//! Pacotes `$dados#cs`; confirmação `+`/`-` até o modo sem confirmação
//! (`QStartNoAckMode`); `O` com texto em hexadecimal é saída do alvo
//! (DbgPrint e respostas do `monitor`), entregue a quem pediu; 0x03 avulso
//! pede a parada.
//!
//! O enquadramento (`encode`, `Decoder`) não depende do socket: os testes
//! o exercitam com bytes prontos.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// Soma dos bytes do conteúdo, módulo 256.
pub fn checksum(payload: &[u8]) -> u8 {
    payload.iter().fold(0u8, |sum, &byte| sum.wrapping_add(byte))
}

/// O quadro de um pacote: `$conteúdo#cs`. Os pacotes do cliente são texto
/// (os dados binários vão em hexadecimal), sem `$`, `#` nem `}`.
pub fn encode(payload: &str) -> Vec<u8> {
    format!("${payload}#{:02x}", checksum(payload.as_bytes())).into_bytes()
}

/// Texto de um `O` (hexadecimal).
pub fn decode_hex_text(hex: &str) -> String {
    String::from_utf8_lossy(&unhex(hex)).into_owned()
}

/// Saída do alvo num pacote `O` (o `OK` não é saída).
pub fn console_text(packet: &str) -> Option<String> {
    let hex = packet.strip_prefix('O')?;
    (!hex.is_empty() && hex.len() % 2 == 0 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())).then(|| decode_hex_text(hex))
}

/// O conteúdo de um `O` do fluxo de registros (começa com o marcador).
pub fn stream_bytes(packet: &str) -> Option<Vec<u8>> {
    let hex = packet.strip_prefix('O')?;
    let marker: String = super::stream::MARKER.iter().map(|byte| format!("{byte:02x}")).collect();
    hex.starts_with(&marker).then(|| unhex(hex))
}

/// Desfaz a compressão `x*n` (repetição) de uma resposta.
pub fn expand_run_length(payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(payload.len());
    let mut index = 0;
    while index < payload.len() {
        let byte = payload[index];
        if byte == b'*' && index + 1 < payload.len() && !output.is_empty() {
            let count = payload[index + 1].wrapping_sub(29) as usize;
            let last = *output.last().unwrap();
            output.extend(std::iter::repeat_n(last, count));
            index += 2;
            continue;
        }
        output.push(byte);
        index += 1;
    }
    output
}

/// Um pacote completo recebido.
#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    /// Conteúdo já sem a compressão.
    Packet(String),
    /// Soma de verificação errada (o lado com confirmação manda `-`).
    Corrupt,
}

/// Os bytes recebidos e ainda não consumidos.
#[derive(Default)]
pub struct Decoder {
    buffer: Vec<u8>,
}

impl Decoder {
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// A confirmação do último pacote enviado: `+`, `-`, ou `$` quando um
    /// pacote do alvo chegou antes dela (o `$` fica no buffer). Outros bytes
    /// são descartados.
    pub fn next_ack(&mut self) -> Option<u8> {
        while let Some(&byte) = self.buffer.first() {
            match byte {
                b'$' => return Some(b'$'),
                b'+' | b'-' => {
                    self.buffer.remove(0);
                    return Some(byte);
                }
                _ => {
                    self.buffer.remove(0);
                }
            }
        }
        None
    }

    /// O próximo pacote completo. Um pacote só sai do buffer inteiro: bytes
    /// de um pacote pela metade ficam para a próxima leitura.
    pub fn next_frame(&mut self) -> Option<Frame> {
        match self.buffer.iter().position(|&byte| byte == b'$') {
            Some(start) => {
                self.buffer.drain(..start);
            }
            None => {
                self.buffer.clear();
                return None;
            }
        }
        let hash = self.buffer.iter().position(|&byte| byte == b'#')?;
        if self.buffer.len() < hash + 3 {
            return None;
        }
        let packet: Vec<u8> = self.buffer.drain(..hash + 3).collect();
        // Um `$` no meio recomeça o pacote.
        let begin = packet[..hash].iter().rposition(|&byte| byte == b'$').unwrap_or(0);
        let payload = &packet[begin + 1..hash];
        let expected = std::str::from_utf8(&packet[hash + 1..hash + 3]).ok().and_then(|text| u8::from_str_radix(text, 16).ok());
        if expected == Some(checksum(payload)) {
            Some(Frame::Packet(String::from_utf8_lossy(&expand_run_length(payload)).into_owned()))
        } else {
            Some(Frame::Corrupt)
        }
    }
}

/// Erro de tempo esgotado (a máquina segue rodando, nada se perdeu).
pub const TIMEOUT: &str = "tempo esgotado esperando o alvo";

/// Se o erro é só o prazo vencido.
pub fn is_timeout(error: &str) -> bool {
    error.contains("tempo esgotado")
}

pub struct Connection {
    stream: TcpStream,
    decoder: Decoder,
    no_ack: bool,
    /// Saída `O` recebida e ainda não consumida.
    console: String,
    /// Os `O` do fluxo de registros (`stream::MARKER`), crus.
    records: Vec<Vec<u8>>,
}

impl Connection {
    /// Conecta ao socket da porta serial do depurador, tentando até o prazo
    /// (o QEMU pode ainda não ter aberto o socket).
    pub fn connect(address: &str, deadline: Instant) -> Result<Self, String> {
        loop {
            match TcpStream::connect(address) {
                Ok(stream) => {
                    stream.set_nodelay(true).map_err(|error| error.to_string())?;
                    return Ok(Self { stream, decoder: Decoder::default(), no_ack: false, console: String::new(), records: Vec::new() });
                }
                Err(error) if Instant::now() > deadline => return Err(format!("depurador em {address}: {error}")),
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    fn fill(&mut self, deadline: Instant) -> Result<(), String> {
        let now = Instant::now();
        if now >= deadline {
            return Err(TIMEOUT.into());
        }
        self.stream.set_read_timeout(Some((deadline - now).max(Duration::from_millis(1)))).map_err(|error| error.to_string())?;
        let mut chunk = [0u8; 4096];
        match self.stream.read(&mut chunk) {
            Ok(0) => Err("o alvo fechou a conexao".into()),
            Ok(count) => {
                self.decoder.push(&chunk[..count]);
                Ok(())
            }
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted) => Err(TIMEOUT.into()),
            // ERROR_IO_PENDING (997): no Windows, um recv com prazo curto que
            // venceu durante a operação; os bytes chegam na próxima leitura.
            Err(error) if error.raw_os_error() == Some(997) => Err(TIMEOUT.into()),
            Err(error) => Err(error.to_string()),
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.stream.write_all(bytes).map_err(|error| format!("depurador: {error}"))
    }

    /// Pede a parada (0x03).
    pub fn interrupt(&mut self) -> Result<(), String> {
        self.write(&[0x03])
    }

    /// Envia um pacote; no modo com confirmação espera o `+`.
    pub fn send(&mut self, payload: &str, timeout: Duration) -> Result<(), String> {
        let frame = encode(payload);
        let deadline = Instant::now() + timeout;
        for _ in 0..5 {
            self.write(&frame)?;
            if self.no_ack {
                return Ok(());
            }
            loop {
                match self.decoder.next_ack() {
                    Some(b'+') => return Ok(()),
                    Some(b'-') => break,
                    // Um pacote do alvo antes da confirmação: fica para depois.
                    Some(_) => return Ok(()),
                    None => self.fill(deadline)?,
                }
            }
        }
        Err(format!("o alvo nao confirmou o pacote {payload:?}"))
    }

    /// Recebe o próximo pacote (confirmando-o).
    fn receive_raw(&mut self, deadline: Instant) -> Result<String, String> {
        loop {
            match self.decoder.next_frame() {
                Some(Frame::Packet(packet)) => {
                    if !self.no_ack {
                        self.write(b"+")?;
                    }
                    return Ok(packet);
                }
                Some(Frame::Corrupt) => {
                    if !self.no_ack {
                        self.write(b"-")?;
                    }
                }
                None => self.fill(deadline)?,
            }
        }
    }

    /// Próximo pacote que não é saída `O` (a saída acumula no console; os
    /// registros do fluxo ficam à parte).
    pub fn receive(&mut self, timeout: Duration) -> Result<String, String> {
        let deadline = Instant::now() + timeout;
        loop {
            let packet = self.receive_raw(deadline)?;
            if let Some(bytes) = stream_bytes(&packet) {
                self.records.push(bytes);
                continue;
            }
            match console_text(&packet) {
                Some(text) => self.console.push_str(&text),
                None => return Ok(packet),
            }
        }
    }

    /// Consome os `O` do fluxo de registros recebidos.
    pub fn take_records(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.records)
    }

    /// Pacote e resposta.
    pub fn request(&mut self, payload: &str, timeout: Duration) -> Result<String, String> {
        self.send(payload, timeout)?;
        self.receive(timeout)
    }

    pub fn set_no_ack(&mut self) {
        self.no_ack = true;
    }

    /// Consome a saída `O` acumulada.
    pub fn take_console(&mut self) -> String {
        std::mem::take(&mut self.console)
    }
}

/// Bytes em hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Hexadecimal em bytes (`x` = indisponível vira 0).
pub fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|index| text.get(index * 2..index * 2 + 2).and_then(|pair| u8::from_str_radix(pair, 16).ok()).unwrap_or(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_with_checksum() {
        assert_eq!(encode("g"), b"$g#67".to_vec());
        assert_eq!(encode("qSupported:swbreak+"), format!("$qSupported:swbreak+#{:02x}", checksum(b"qSupported:swbreak+")).into_bytes());
        assert_eq!(encode(""), b"$#00".to_vec());
    }

    #[test]
    fn decodes_packets_split_across_reads() {
        let mut decoder = Decoder::default();
        decoder.push(b"+$T05thre");
        assert_eq!(decoder.next_ack(), Some(b'+'));
        assert_eq!(decoder.next_frame(), None);
        decoder.push(b"ad:1;#");
        assert_eq!(decoder.next_frame(), None);
        let tail = format!("{:02x}", checksum(b"T05thread:1;"));
        decoder.push(tail.as_bytes());
        assert_eq!(decoder.next_frame(), Some(Frame::Packet("T05thread:1;".into())));
        assert_eq!(decoder.next_frame(), None);
    }

    #[test]
    fn rejects_bad_checksum_and_restarts_on_dollar() {
        let mut decoder = Decoder::default();
        decoder.push(b"$OK#00");
        assert_eq!(decoder.next_frame(), Some(Frame::Corrupt));
        // Lixo e um pacote recomeçado no meio.
        decoder.push(b"xx$garb$OK#9a");
        assert_eq!(decoder.next_frame(), Some(Frame::Packet("OK".into())));
    }

    #[test]
    fn ack_leaves_an_early_packet_in_place() {
        let mut decoder = Decoder::default();
        decoder.push(b"$OK#9a");
        assert_eq!(decoder.next_ack(), Some(b'$'));
        assert_eq!(decoder.next_frame(), Some(Frame::Packet("OK".into())));
    }

    #[test]
    fn expands_run_length() {
        // `0* ` = '0' mais 3 repetições (' ' = 32, 32 - 29 = 3).
        assert_eq!(expand_run_length(b"0* "), b"0000".to_vec());
        assert_eq!(expand_run_length(b"ab*!c"), b"abbbbbc".to_vec());
        // `*` no começo não repete nada.
        assert_eq!(expand_run_length(b"*a"), b"*a".to_vec());
        let mut decoder = Decoder::default();
        decoder.push(&encode_raw(b"00* 11"));
        assert_eq!(decoder.next_frame(), Some(Frame::Packet("0000011".into())));
    }

    fn encode_raw(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![b'$'];
        frame.extend_from_slice(payload);
        frame.extend_from_slice(format!("#{:02x}", checksum(payload)).as_bytes());
        frame
    }

    #[test]
    fn console_output() {
        assert_eq!(console_text("O48690a").as_deref(), Some("Hi\n"));
        assert_eq!(console_text("OK"), None);
        assert_eq!(console_text("O"), None);
        assert_eq!(console_text("T05"), None);
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!(hex(&[0, 0xab, 0x7f]), "00ab7f");
        assert_eq!(unhex("00ab7f"), vec![0, 0xab, 0x7f]);
        assert_eq!(unhex("xx01"), vec![0, 1]);
    }
}
