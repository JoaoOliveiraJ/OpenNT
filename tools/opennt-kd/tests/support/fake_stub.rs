//! Um alvo de mentira: um stub do protocolo remoto do GDB num socket
//! local, com registradores (os gerais, x87/SSE no `g` e as extensões do
//! OpenNT por `p`), uma pilha capturada, código, módulos e as paradas
//! roteirizadas. Os testes do `opennt-kd` (`fake_target.rs`) e os do
//! servidor MCP (`tools/opennt-mcp/tests`) usam o mesmo stub.
//!
//! `start_opennt` liga o que o depurador do OpenNT anuncia além do GDB:
//! pacote de 16 KB, leitura binária (`x`), o filtro de carga
//! (`QOpenNTLoadBreak`: uma parada roteirizada com `load` que não casa com
//! o filtro não chega ao cliente, como no alvo) e as respostas de parada
//! com os registradores adiantados e a impressão digital dos módulos.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use opennt_kd::rsp::{checksum, encode, hex, unhex, Connection, Decoder, Frame};
use opennt_kd::symbols::{Module, Symbol};
use opennt_kd::Client;

pub const STACK: u64 = 0xffff_8000_0010_0f00;
pub const CODE: u64 = 0xfffff800_4010_0000;
/// Uma página de dados de usuário (os breakpoints de memória).
pub const USER_DATA: u64 = 0x7ff6_0000_1000;

/// O que o alvo faz no próximo `c`: os novos RIP e RSP e a resposta.
pub struct Stop {
    pub rip: u64,
    pub rsp: u64,
    pub packet: &'static str,
    /// O RAX da parada (as condições dos breakpoints).
    pub rax: u64,
    /// Um módulo que aparece no `lm` a partir desta parada.
    pub load: Option<&'static str>,
}

impl Stop {
    pub fn at(rip: u64, packet: &'static str) -> Stop {
        Stop { rip, rsp: STACK, packet, rax: 0, load: None }
    }
}

struct Target {
    registers: [u64; 24],
    memory: Vec<(u64, Vec<u8>)>,
    stops: VecDeque<Stop>,
    log: Arc<Mutex<Vec<String>>>,
    modules: Vec<String>,
    /// Os breakpoints de memória armados (`membp`).
    memory_breakpoints: Vec<(u64, u64, String)>,
    /// O monitor de APIs ou o rastreador ligado: o fluxo tem registros.
    stream_enabled: bool,
    /// Registradores (índice do `g`, valor) postos a cada parada, na ordem
    /// das paradas (os argumentos dos pontos de evento).
    register_sets: VecDeque<Vec<(usize, u64)>>,
    /// A resposta do `ps` (vazia = a resposta padrão).
    processes: String,
    /// As extensões do depurador do OpenNT (`start_opennt`).
    opennt: bool,
    /// O filtro de carga pedido pelo cliente (minúsculas; `*` = qualquer).
    load_filter: Vec<String>,
}

/// O quadro de um pacote com conteúdo binário.
fn frame_bytes(payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![b'$'];
    frame.extend_from_slice(payload);
    frame.extend_from_slice(format!("#{:02x}", checksum(payload)).as_bytes());
    frame
}

/// Os registros do fluxo do alvo de mentira: uma chamada ao IoCreateDevice
/// vinda do código (sucesso, com o nome copiado) e um IRP de CREATE que
/// passa por dois dispositivos e é concluído.
pub fn stream_records() -> Vec<u8> {
    let mut bytes = Vec::new();
    let header = |kind: u8, sequence: u64, time: u64| {
        let mut record = vec![0u8; 24];
        record[2] = kind;
        record[8..16].copy_from_slice(&sequence.to_le_bytes());
        record[16..24].copy_from_slice(&time.to_le_bytes());
        record
    };
    let finish = |mut record: Vec<u8>, bytes: &mut Vec<u8>| {
        let length = record.len() as u16;
        record[0..2].copy_from_slice(&length.to_le_bytes());
        bytes.extend(record);
    };
    // IoCreateDevice(DriverObject, 0x40, "\Device\Falso", 0x22, 0, FALSE, &DeviceObject) = 0.
    let mut call = header(1, 0, 1000);
    call.extend_from_slice(&40u32.to_le_bytes());
    call.push(7);
    call.push(1);
    call.extend_from_slice(&[0, 0]);
    call.extend_from_slice(&4u32.to_le_bytes());
    call.extend_from_slice(&8u32.to_le_bytes());
    call.extend_from_slice(&0xffff_a000_0000_0100u64.to_le_bytes());
    call.extend_from_slice(&(CODE + 0x10D).to_le_bytes());
    call.extend_from_slice(&30u64.to_le_bytes());
    call.extend_from_slice(&0u64.to_le_bytes());
    for argument in [0xffff_a000_0000_1000u64, 0x40, 0xffff_a000_0000_2000, 0x22, 0, 0, 0xffff_a000_0000_3000] {
        call.extend_from_slice(&argument.to_le_bytes());
    }
    let name = b"\\Device\\Falso";
    call.push(3);
    call.push(1);
    call.extend_from_slice(&(name.len() as u16).to_le_bytes());
    call.extend_from_slice(name);
    finish(call, &mut bytes);
    let irp = |kind: u8, sequence: u64, time: u64, device: u64, driver: u64, value: u64, location: u8, bytes: &mut Vec<u8>| {
        let mut record = header(kind, sequence, time);
        for field in [0xffff_a000_0000_9000u64, device, driver, 0xffff_a000_0000_0100, CODE + 0x10D, CODE + 0x2000, value, 0x5] {
            record.extend_from_slice(&field.to_le_bytes());
        }
        record.extend_from_slice(&[0, 0, location, 2]);
        record.extend_from_slice(&4u32.to_le_bytes());
        finish(record, bytes);
    };
    irp(0x11, 1, 2000, 0xffff_a000_0000_d100, 0xffff_a000_0000_5100, 0, 2, &mut bytes);
    irp(0x11, 2, 2100, 0xffff_a000_0000_d200, 0xffff_a000_0000_5200, 0, 1, &mut bytes);
    irp(0x13, 3, 2200, 0, 0, 0, 1, &mut bytes);
    irp(0x12, 4, 2300, 0xffff_a000_0000_d200, 0xffff_a000_0000_5200, 0, 0, &mut bytes);
    irp(0x12, 5, 2400, 0xffff_a000_0000_d100, 0xffff_a000_0000_5100, 0, 0, &mut bytes);
    bytes
}

/// Os registradores além dos gerais: x87 e SSE (no `g`) e as extensões
/// do OpenNT (por `p`). XMMn = bytes n..n+16, MXCSR 0x1F80, YMMnh = 0xA0+n,
/// DRn = 0xD0+n, DR7 = 0x401.
fn extended_register(number: usize) -> Option<Vec<u8>> {
    let size = opennt_kd::registers::packet_size(number);
    Some(match number {
        24..=31 => vec![0; size],
        33 => (0u32).to_le_bytes().to_vec(),
        32 | 34..=39 => vec![0; size],
        40..=55 => (0..16).map(|index| (number - 40 + index) as u8).collect(),
        56 => 0x1F80u32.to_le_bytes().to_vec(),
        59..=74 => vec![0xA0 + (number - 59) as u8; 16],
        75..=78 => (0xD0 + (number - 75) as u64).to_le_bytes().to_vec(),
        79 => 0xFFFF_0FF0u64.to_le_bytes().to_vec(),
        80 => 0x401u64.to_le_bytes().to_vec(),
        _ => return None,
    })
}

impl Target {
    fn read(&self, address: u64, length: usize) -> Option<Vec<u8>> {
        self.memory.iter().find(|(base, bytes)| address >= *base && address < base + bytes.len() as u64).map(|(base, bytes)| {
            let start = (address - base) as usize;
            bytes[start..(start + length).min(bytes.len())].to_vec()
        })
    }

    fn registers_packet(&self) -> String {
        let mut reply = String::new();
        for (index, value) in self.registers.iter().enumerate() {
            let size = if index <= 16 { 8 } else { 4 };
            reply.push_str(&hex(&value.to_le_bytes()[..size]));
        }
        for number in 24..57 {
            reply.push_str(&hex(&extended_register(number).unwrap_or_default()));
        }
        reply
    }

    /// Os 24 registradores gerais como na resposta de parada do OpenNT, e a
    /// impressão digital da lista de módulos (muda a cada módulo novo).
    fn opennt_stop_fields(&self) -> String {
        let mut fields = String::new();
        for (index, value) in self.registers.iter().enumerate() {
            let size = if index <= 16 { 8 } else { 4 };
            fields.push_str(&format!("{index:02x}:{};", hex(&value.to_le_bytes()[..size])));
        }
        fields.push_str(&format!("modgen:{:x};", self.modules.len() + 1));
        fields
    }

    /// Uma imagem passa pelo filtro de carga (nome ou nome sem extensão).
    fn load_filter_matches(&self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        let stem = name.rsplit_once('.').map_or(name.as_str(), |(stem, _)| stem).to_string();
        self.load_filter.iter().any(|wanted| wanted == "*" || *wanted == name || *wanted == stem)
    }

    /// `x endereço,tamanho`: `b` e os bytes escapados.
    fn binary_read(&mut self, packet: &str) -> Vec<u8> {
        self.log.lock().unwrap().push(packet.to_string());
        let (address, length) = packet[1..].split_once(',').unwrap();
        match self.read(u64::from_str_radix(address, 16).unwrap(), usize::from_str_radix(length, 16).unwrap()) {
            Some(bytes) => {
                let mut reply = vec![b'b'];
                for byte in bytes {
                    if matches!(byte, b'#' | b'$' | b'}' | b'*') {
                        reply.push(b'}');
                        reply.push(byte ^ 0x20);
                    } else {
                        reply.push(byte);
                    }
                }
                reply
            }
            None => b"E14".to_vec(),
        }
    }

    fn monitor(&mut self, text: &str) -> String {
        let words: Vec<&str> = text.split_whitespace().collect();
        match words.as_slice() {
            ["lm"] => format!("              base                fim  nome             caminho\n{}", self.modules.join("")),
            ["ps"] if !self.processes.is_empty() => self.processes.clone(),
            // Os processos e as threads (os laços dos roteiros).
            ["ps"] => "   PID           EPROCESS                CR3 threads  nome\n     4 0xffffe00000001000           0x1ab000       2  System\n   100 0xffffe00000042000           0x2cd000       1  smss.exe\n   500 0xffffc00000500000           0x2bb000       5  csrss.exe\n".to_string(),
            ["threads"] => "   PID    TID            ETHREAD estado                    inicio  processo\n     4      8 0xffffe00000003000 Waiting       0xfffff80040100000  System\n     4     12 0xffffe00000004000 Waiting       0xfffff80040102000  System\n   100    104 0xffffe00000043000 Running       0xfffff80040103000  smss.exe\n".to_string(),
            ["bl"] => "nenhum breakpoint\n".to_string(),
            ["membp", "set", address, length, kind] => {
                let address = opennt_kd::parse_number(address).unwrap_or(0);
                let length = opennt_kd::parse_number(length).unwrap_or(0x1000);
                self.memory_breakpoints.push((address, length, kind.to_string()));
                format!("membp ok {address:#x} {length:#x} {kind}\n")
            }
            ["membp", "clear", address] => {
                let address = opennt_kd::parse_number(address).unwrap_or(0);
                self.memory_breakpoints.retain(|(start, _, _)| *start != address);
                format!("membp ok removido {address:#x}\n")
            }
            ["membp"] if self.memory_breakpoints.is_empty() => "nenhum breakpoint de memoria\n".to_string(),
            ["membp"] => self.memory_breakpoints.iter().map(|(address, length, kind)| format!("{address:#x} {length:#x} {kind}\n")).collect(),
            // O monitor de APIs, o rastreador de IRPs e o fluxo.
            ["api", "names", "0"] => "40 IoCreateDevice\n41 ExAllocatePoolWithTag\nmais: 2\n".to_string(),
            ["api", "names", _] => "42 IofCallDriver\n43 IofCompleteRequest\n".to_string(),
            ["api", "clear"] => "api: faixas e especificacoes limpas\n".to_string(),
            ["api", "spec", specs @ ..] => format!("api: {} especificacoes ({} no total)\n", specs.len(), specs.len()),
            ["api", "on", ..] => {
                self.stream_enabled = true;
                "api: monitor ligado (todos os chamadores)\n".to_string()
            }
            ["api", "off"] => "api: monitor desligado\n".to_string(),
            ["irptrace", "on"] => {
                self.stream_enabled = true;
                "irptrace: rastreador ligado\n".to_string()
            }
            ["irptrace", "off"] => "irptrace: rastreador desligado\n".to_string(),
            ["stream", _] => "fluxo: ok\n".to_string(),
            // Os exploradores.
            ["reg", "keys", "\\Registry\\Machine\\SYSTEM\\Select", ..] => "chave\t\\REGISTRY\\MACHINE\\SYSTEM\\Select\t0\t2\t0x1d9a0b0c0d0e0f0\t0\t0\t\\SystemRoot\\System32\\Config\\SYSTEM\n".to_string(),
            ["reg", "values", "\\Registry\\Machine\\SYSTEM\\Select", ..] => "v\tCurrent\t4\t4\t01000000\nv\tDefault\t4\t4\t01000000\n".to_string(),
            ["reg", "value", "\\Registry\\Machine\\SYSTEM\\Select", "Current", ..] => "valor\tCurrent\t4\t4\t0\t01000000\n".to_string(),
            ["reg", ..] => "chave nao encontrada\n".to_string(),
            ["objdir", ..] => "diretorio\t\\Device\tDirectory\t0xffff800000001000\t2\no\tNull\tDevice\t0xffff800000002000\t0\t\no\tHarddiskVolume1\tSymbolicLink\t0x0\t0\t\\Device\\Harddisk0\\Partition1\n".to_string(),
            ["fs", "ls", ..] => "pasta\t/\t2\nf\tWindows\t1\t0\t0x10\t0x0\nf\tteste.txt\t0\t5\t0x20\t0x1d9a0b0c0d0e0f0\n".to_string(),
            ["fs", "read", _, offset, ..] if *offset == "0" => "dados\t/teste.txt\t5\t0\t6f6c612121\n".to_string(),
            ["fs", "read", ..] => "dados\t/teste.txt\t5\t5\t\n".to_string(),
            // Os objetos do NT (`nt_objects`): processos, handles e as
            // consultas do `kd/objects.rs`.
            ["handles", "0xffffc00000500000", "0"] => "EPROCESS 0xffffc00000500000 HANDLE_TABLE 0xffffc00000600000 TableCode 0xffffc00000610000 entradas 4\n  handle             objeto     acesso tipo             nome\n     0x4 0xffffc00000700000   0x1f0003 Event            \\BaseNamedObjects\\x\n     0x8 0xffffc00000800000   0x1f0001 ALPC Port        \\Windows\\ApiPort\n     0xc 0xffffc00000900000   0x1f0003 IoCompletion     \n".to_string(),
            ["obtypes"] => "ObHeaderCookie 0x5a\nINDICE        OBJECT_TYPE  OBJETOS  HANDLES NOME\n     7 0xffffc00000100000       12        3 Process\n    46 0xffffc00000200000        2        1 ALPC Port\n".to_string(),
            ["alpc", port] => format!("ALPC {port} tipo alpc fechada 0 handles 1 PID 500 TID 504 processo 0xffffc00000500000\npapel Listener conexao 0\nfila-do-servidor 2\n"),
            ["iocp", port] => format!("IOCP {port} fechada 0 concorrencia 1 processo-exclusivo - nome -\npacotes 0 ativas 0 esperando 0 associadas 0\n"),
            _ => "comandos do OpenNT\n".to_string(),
        }
    }

    fn answer(&mut self, packet: &str, stream: &mut TcpStream) -> Option<String> {
        self.log.lock().unwrap().push(packet.to_string());
        let reply = if packet.starts_with("qSupported") && self.opennt {
            "PacketSize=4000;swbreak+;hwbreak+;QStartNoAckMode+;vContSupported+;qXfer:libraries:read+;binary-upload+;QOpenNTLoadBreak+".to_string()
        } else if packet.starts_with("qSupported") {
            "PacketSize=1000;swbreak+;hwbreak+;QStartNoAckMode+;ReverseStep+;ReverseContinue+".to_string()
        } else if let Some(list) = packet.strip_prefix("QOpenNTLoadBreak:").filter(|_| self.opennt) {
            self.load_filter = list.split(';').filter(|name| !name.is_empty()).map(str::to_ascii_lowercase).collect();
            "OK".to_string()
        } else if packet == "QStartNoAckMode" || packet.starts_with('Z') || packet.starts_with('z') || packet.starts_with("Hg") || packet.starts_with('M') || packet.starts_with('P') {
            if let Some(rest) = packet.strip_prefix('P') {
                let (number, value) = rest.split_once('=').unwrap();
                let number = usize::from_str_radix(number, 16).unwrap();
                if number < self.registers.len() {
                    let mut bytes = unhex(value);
                    bytes.resize(8, 0);
                    self.registers[number] = u64::from_le_bytes(bytes.try_into().unwrap());
                }
            }
            if let Some(rest) = packet.strip_prefix('M') {
                let (head, data) = rest.split_once(':').unwrap();
                let address = u64::from_str_radix(head.split(',').next().unwrap(), 16).unwrap();
                let bytes = unhex(data);
                if let Some((base, memory)) = self.memory.iter_mut().find(|(base, memory)| address >= *base && address < base + memory.len() as u64) {
                    let start = (address - *base) as usize;
                    let end = (start + bytes.len()).min(memory.len());
                    memory[start..end].copy_from_slice(&bytes[..end - start]);
                }
            }
            "OK".to_string()
        } else if packet == "?" && self.opennt {
            format!("T02thread:1;{}", self.opennt_stop_fields())
        } else if packet == "?" {
            "T02thread:1;".to_string()
        } else if packet == "g" {
            self.registers_packet()
        } else if let Some(number) = packet.strip_prefix('p') {
            let number = usize::from_str_radix(number, 16).unwrap_or(usize::MAX);
            if number < self.registers.len() {
                let size = if number <= 16 { 8 } else { 4 };
                hex(&self.registers[number].to_le_bytes()[..size])
            } else if number == 57 || number == 58 {
                hex(&0u64.to_le_bytes())
            } else {
                extended_register(number).map(|bytes| hex(&bytes)).unwrap_or_else(|| "E00".into())
            }
        } else if let Some(rest) = packet.strip_prefix('m') {
            let (address, length) = rest.split_once(',').unwrap();
            match self.read(u64::from_str_radix(address, 16).unwrap(), usize::from_str_radix(length, 16).unwrap()) {
                Some(bytes) => hex(&bytes),
                None => "E14".to_string(),
            }
        } else if let Some(command) = packet.strip_prefix("qRcmd,") {
            let text = String::from_utf8(unhex(command)).unwrap();
            let output = self.monitor(&text);
            stream.write_all(&encode(&format!("O{}", hex(output.as_bytes())))).unwrap();
            "OK".to_string()
        } else if let Some(sequence) = packet.strip_prefix("qOpenNTStream:") {
            let from = u64::from_str_radix(sequence, 16).unwrap_or(0);
            let records = if self.stream_enabled { stream_records() } else { Vec::new() };
            let count = if self.stream_enabled { 6u64 } else { 0 };
            let mut reply = Vec::new();
            reply.extend_from_slice(&count.to_le_bytes());
            reply.extend_from_slice(&0u64.to_le_bytes());
            reply.extend_from_slice(&0u64.to_le_bytes());
            reply.extend_from_slice(&(self.stream_enabled as u32 | 4).to_le_bytes());
            reply.extend_from_slice(&[0; 4]);
            // Só os registros a partir do pedido (o cliente lê de novo até o fim).
            if from == 0 {
                reply.extend(records);
            }
            hex(&reply)
        } else if packet == "c" || packet == "s" || packet == "bs" || packet == "bc" {
            loop {
                let stop = self.stops.pop_front().expect("parada roteirizada");
                self.registers[16] = stop.rip;
                self.registers[7] = stop.rsp;
                self.registers[0] = stop.rax;
                for (index, value) in self.register_sets.pop_front().unwrap_or_default() {
                    self.registers[index] = value;
                }
                let mut loaded = None;
                if let Some(name) = stop.load {
                    let base = 0xfffff800_4300_0000u64 + self.modules.len() as u64 * 0x10000;
                    self.modules.push(format!("{base:#x} {:#x}  {name}   \\SystemRoot\\System32\\drivers\\{name}\n", base + 0x10000));
                    loaded = Some((name, base));
                }
                if !self.opennt {
                    break stop.packet.to_string();
                }
                // O alvo do OpenNT: a carga só para com o filtro casando,
                // como uma parada de biblioteca com os argumentos.
                match loaded {
                    Some((name, _)) if !self.load_filter_matches(name) => continue,
                    Some((name, base)) => break format!("T05thread:1;library:;load:{base:x},10000,0,{};{}", hex(name.as_bytes()), self.opennt_stop_fields()),
                    None => break format!("{}{}", stop.packet, self.opennt_stop_fields()),
                }
            }
        } else if packet == "D" {
            "OK".to_string()
        } else {
            String::new()
        };
        Some(reply)
    }
}

/// Sobe o alvo; devolve o endereço e o registro dos pacotes recebidos.
pub fn start(stops: Vec<Stop>) -> (String, Arc<Mutex<Vec<String>>>) {
    start_target(stops, Vec::new(), Vec::new(), "", false)
}

/// Sobe o alvo com as extensões do depurador do OpenNT.
pub fn start_opennt(stops: Vec<Stop>) -> (String, Arc<Mutex<Vec<String>>>) {
    start_target(stops, Vec::new(), Vec::new(), "", true)
}

/// Sobe o alvo com registradores por parada (`registers[n]` vale na
/// parada `n`), memória a mais e a resposta do `ps`.
pub fn start_with(stops: Vec<Stop>, registers: Vec<Vec<(usize, u64)>>, memory: Vec<(u64, Vec<u8>)>, processes: &str) -> (String, Arc<Mutex<Vec<String>>>) {
    start_target(stops, registers, memory, processes, false)
}

fn start_target(stops: Vec<Stop>, registers: Vec<Vec<(usize, u64)>>, memory: Vec<(u64, Vec<u8>)>, processes: &str, opennt: bool) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let log = Arc::new(Mutex::new(Vec::new()));
    // Um driver que não existe nesta máquina (sem símbolos).
    let modules = vec!["0xfffff80042000000 0xfffff80042010000  alvo-falso.sys   \\SystemRoot\\System32\\drivers\\alvo-falso.sys\n".to_string()];
    let mut target = Target { registers: [0; 24], memory, stops: stops.into(), log: Arc::clone(&log), modules, memory_breakpoints: Vec::new(), stream_enabled: false, register_sets: registers.into(), processes: processes.to_string(), opennt, load_filter: Vec::new() };
    // Pilha: o quadro corrente em STACK + 0x20 com dois chamadores.
    let mut stack = vec![0u8; 0x100];
    let mut put = |offset: usize, value: u64| stack[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    put(0x20, STACK + 0x60);
    put(0x28, CODE + 0x2010);
    put(0x60, 0);
    put(0x68, CODE + 0x3020);
    target.memory.push((STACK, stack));
    // Código: `sub rsp, 0x20`, `call rel32`, `nop`; em CODE + 0x100, o
    // preparo de uma chamada ao IoCreateDevice.
    let mut code = vec![0x48, 0x83, 0xEC, 0x20, 0xE8, 0, 0, 0, 0, 0x90];
    code.resize(0x4000, 0x90);
    // mov edx, 0x40; xor r8d, r8d; call CODE + 0x3800 (IoCreateDevice).
    let setup = [0xBA, 0x40, 0, 0, 0, 0x45, 0x33, 0xC0, 0xE8];
    code[0x100..0x109].copy_from_slice(&setup);
    let relative = (0x3800i64 - 0x10D) as i32;
    code[0x109..0x10D].copy_from_slice(&relative.to_le_bytes());
    code[0x3800] = 0xC3;
    target.memory.push((CODE, code));
    target.memory.push((USER_DATA, vec![0x11; 0x1000]));
    target.registers[16] = CODE;
    target.registers[7] = STACK;
    target.registers[6] = STACK + 0x20;
    target.registers[17] = 0x246;
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut decoder = Decoder::default();
        let mut no_ack = false;
        let mut chunk = [0u8; 4096];
        loop {
            while let Some(frame) = decoder.next_frame() {
                let Frame::Packet(packet) = frame else { continue };
                if !no_ack {
                    stream.write_all(b"+").unwrap();
                }
                if target.opennt && packet.starts_with('x') {
                    let reply = target.binary_read(&packet);
                    stream.write_all(&frame_bytes(&reply)).unwrap();
                    continue;
                }
                if let Some(reply) = target.answer(&packet, &mut stream) {
                    stream.write_all(&encode(&reply)).unwrap();
                }
                if packet == "QStartNoAckMode" {
                    no_ack = true;
                }
            }
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(count) => decoder.push(&chunk[..count]),
            }
        }
    });
    (address, log)
}

/// Os símbolos de mentira do kernel (as funções do roteiro dos testes).
pub fn kernel_module() -> Module {
    Module::new(
        "kernel",
        "kernel.elf",
        0xfffff800_40000000,
        0xfffff800_41000000,
        vec![
            Symbol { address: CODE, size: 0x100, name: "kernel::alvo::corrente".into(), function: true },
            Symbol { address: CODE + 0x1000, size: 0x100, name: "kernel::ntos::ps::notify::image::notify".into(), function: true },
            Symbol { address: CODE + 0x2000, size: 0x100, name: "kernel::alvo::chamador".into(), function: true },
            Symbol { address: CODE + 0x3000, size: 0x100, name: "kernel::alvo::kmain".into(), function: true },
            Symbol { address: CODE + 0x3800, size: 0x10, name: "IoCreateDevice".into(), function: true },
        ],
        "teste",
    )
}

/// Conecta, anexa e põe os símbolos de mentira.
/// Uma sessão de reprodução (o gdbstub do QEMU): os módulos vêm da
/// gravação e as consultas do OpenNT não vão ao alvo.
pub fn connect_replay(address: &str, modules: Vec<(u64, u64, String)>) -> Client {
    let connection = Connection::connect(address, Instant::now() + Duration::from_secs(10)).unwrap();
    let mut client = Client::new(connection, PathBuf::from("."), PathBuf::from("inexistente/kernel.elf"));
    client.set_replay(modules);
    client.attach(Duration::from_secs(10)).unwrap();
    client.symbols.set_kernel(kernel_module());
    client
}

pub fn connect(address: &str) -> Client {
    let connection = Connection::connect(address, Instant::now() + Duration::from_secs(10)).unwrap();
    let mut client = Client::new(connection, PathBuf::from("."), PathBuf::from("inexistente/kernel.elf"));
    let text = client.attach(Duration::from_secs(10)).unwrap();
    assert!(text.contains("sem os simbolos do kernel"), "{text}");
    assert!(client.is_stopped());
    assert!(client.last_stop().contains("SIGINT"), "{}", client.last_stop());
    client.symbols.set_kernel(kernel_module());
    client
}
