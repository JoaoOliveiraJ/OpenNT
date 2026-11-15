//! Lado do host do protocolo serial remoto do GDB (RSP), sobre o socket TCP
//! em que o QEMU expõe a porta serial do depurador.
//!
//! Pacotes `$dados#cs`; confirmação `+`/`-` até o modo sem confirmação
//! (`QStartNoAckMode`); `O` com texto em hexadecimal é saída do alvo
//! (DbgPrint e respostas do `monitor`), entregue a quem pediu; 0x03 avulso
//! pede a parada.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub struct Connection {
    stream: TcpStream,
    buffer: Vec<u8>,
    no_ack: bool,
    /// Saída `O` recebida e ainda não consumida.
    console: String,
}

fn checksum(payload: &[u8]) -> u8 {
    payload.iter().fold(0u8, |sum, &byte| sum.wrapping_add(byte))
}

/// Texto de um `O` (hexadecimal).
fn decode_hex_text(hex: &str) -> String {
    let bytes: Vec<u8> = (0..hex.len() / 2).filter_map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Desfaz a compressão `x*n` (repetição) de uma resposta.
fn expand_run_length(payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(payload.len());
    let mut index = 0;
    while index < payload.len() {
        let byte = payload[index];
        if byte == b'*' && index + 1 < payload.len() && !output.is_empty() {
            let count = payload[index + 1].wrapping_sub(29) as usize;
            let last = *output.last().unwrap();
            output.extend(std::iter::repeat(last).take(count));
            index += 2;
            continue;
        }
        output.push(byte);
        index += 1;
    }
    output
}

impl Connection {
    /// Conecta ao socket da porta serial do depurador, tentando até o prazo
    /// (o QEMU pode ainda não ter aberto o socket).
    pub fn connect(address: &str, deadline: Instant) -> Result<Self, String> {
        loop {
            match TcpStream::connect(address) {
                Ok(stream) => {
                    stream.set_nodelay(true).map_err(|error| error.to_string())?;
                    return Ok(Self { stream, buffer: Vec::new(), no_ack: false, console: String::new() });
                }
                Err(error) if Instant::now() > deadline => return Err(format!("depurador em {address}: {error}")),
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    fn fill(&mut self, deadline: Instant) -> Result<(), String> {
        let now = Instant::now();
        if now >= deadline {
            return Err("tempo esgotado esperando o alvo".into());
        }
        self.stream.set_read_timeout(Some((deadline - now).max(Duration::from_millis(1)))).map_err(|error| error.to_string())?;
        let mut chunk = [0u8; 4096];
        match self.stream.read(&mut chunk) {
            Ok(0) => Err("o alvo fechou a conexao".into()),
            Ok(count) => {
                self.buffer.extend_from_slice(&chunk[..count]);
                Ok(())
            }
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => Err("tempo esgotado esperando o alvo".into()),
            Err(error) => Err(error.to_string()),
        }
    }

    fn next_byte(&mut self, deadline: Instant) -> Result<u8, String> {
        while self.buffer.is_empty() {
            self.fill(deadline)?;
        }
        Ok(self.buffer.remove(0))
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
        let frame = format!("${payload}#{:02x}", checksum(payload.as_bytes()));
        let deadline = Instant::now() + timeout;
        for _ in 0..5 {
            self.write(frame.as_bytes())?;
            if self.no_ack {
                return Ok(());
            }
            loop {
                match self.next_byte(deadline)? {
                    b'+' => return Ok(()),
                    b'-' => break,
                    // Um pacote do alvo antes da confirmação: fica para depois.
                    b'$' => {
                        self.buffer.insert(0, b'$');
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }
        Err(format!("o alvo nao confirmou o pacote {payload:?}"))
    }

    /// Recebe o próximo pacote (confirmando-o); `O` vai para o console.
    /// Um pacote só sai do buffer inteiro: um prazo vencido no meio dele não
    /// perde os bytes já recebidos.
    fn receive_raw(&mut self, deadline: Instant) -> Result<String, String> {
        loop {
            match self.buffer.iter().position(|&byte| byte == b'$') {
                Some(start) => {
                    self.buffer.drain(..start);
                }
                None => self.buffer.clear(),
            }
            if let Some(hash) = self.buffer.iter().position(|&byte| byte == b'#') {
                if self.buffer.len() >= hash + 3 {
                    let packet: Vec<u8> = self.buffer.drain(..hash + 3).collect();
                    // Um `$` no meio recomeça o pacote.
                    let begin = packet[..hash].iter().rposition(|&byte| byte == b'$').unwrap_or(0);
                    let payload = &packet[begin + 1..hash];
                    let expected = u8::from_str_radix(std::str::from_utf8(&packet[hash + 1..hash + 3]).unwrap_or("zz"), 16).ok();
                    let valid = expected == Some(checksum(payload));
                    if !self.no_ack {
                        self.write(if valid { b"+" } else { b"-" })?;
                    }
                    if valid {
                        return Ok(String::from_utf8_lossy(&expand_run_length(payload)).into_owned());
                    }
                    continue;
                }
            }
            self.fill(deadline)?;
        }
    }

    /// Próximo pacote que não é saída `O` (a saída acumula no console).
    pub fn receive(&mut self, timeout: Duration) -> Result<String, String> {
        let deadline = Instant::now() + timeout;
        loop {
            let packet = self.receive_raw(deadline)?;
            if let Some(hex) = packet.strip_prefix('O') {
                if !hex.is_empty() && hex.len() % 2 == 0 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    self.console.push_str(&decode_hex_text(hex));
                    continue;
                }
            }
            return Ok(packet);
        }
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
    (0..text.len() / 2).map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap_or(0)).collect()
}
