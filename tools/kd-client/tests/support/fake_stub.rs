//! Um alvo de mentira: um stub do protocolo remoto do GDB num socket
//! local, com registradores (os gerais, x87/SSE no `g` e as extensões do
//! OpenNT por `p`), uma pilha capturada, código, módulos e as paradas
//! roteirizadas. Os testes do `kd-client` (`fake_target.rs`) e os do
//! servidor MCP (`tools/kd-mcp/tests`) usam o mesmo stub.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use kd_client::rsp::{encode, hex, unhex, Connection, Decoder, Frame};
use kd_client::symbols::{Module, Symbol};
use kd_client::Client;

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
}

/// Os registradores além dos gerais: x87 e SSE (no `g`) e as extensões
/// do OpenNT (por `p`). XMMn = bytes n..n+16, MXCSR 0x1F80, YMMnh = 0xA0+n,
/// DRn = 0xD0+n, DR7 = 0x401.
fn extended_register(number: usize) -> Option<Vec<u8>> {
    let size = kd_client::registers::packet_size(number);
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

    fn monitor(&mut self, text: &str) -> String {
        let words: Vec<&str> = text.split_whitespace().collect();
        match words.as_slice() {
            ["lm"] => format!("              base                fim  nome             caminho\n{}", self.modules.join("")),
            ["bl"] => "nenhum breakpoint\n".to_string(),
            ["membp", "set", address, length, kind] => {
                let address = kd_client::parse_number(address).unwrap_or(0);
                let length = kd_client::parse_number(length).unwrap_or(0x1000);
                self.memory_breakpoints.push((address, length, kind.to_string()));
                format!("membp ok {address:#x} {length:#x} {kind}\n")
            }
            ["membp", "clear", address] => {
                let address = kd_client::parse_number(address).unwrap_or(0);
                self.memory_breakpoints.retain(|(start, _, _)| *start != address);
                format!("membp ok removido {address:#x}\n")
            }
            ["membp"] if self.memory_breakpoints.is_empty() => "nenhum breakpoint de memoria\n".to_string(),
            ["membp"] => self.memory_breakpoints.iter().map(|(address, length, kind)| format!("{address:#x} {length:#x} {kind}\n")).collect(),
            _ => "comandos do OpenNT\n".to_string(),
        }
    }

    fn answer(&mut self, packet: &str, stream: &mut TcpStream) -> Option<String> {
        self.log.lock().unwrap().push(packet.to_string());
        let reply = if packet.starts_with("qSupported") {
            "PacketSize=1000;swbreak+;hwbreak+;QStartNoAckMode+".to_string()
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
        } else if packet == "c" || packet == "s" {
            let stop = self.stops.pop_front().expect("parada roteirizada");
            self.registers[16] = stop.rip;
            self.registers[7] = stop.rsp;
            self.registers[0] = stop.rax;
            if let Some(name) = stop.load {
                let base = 0xfffff800_4300_0000u64 + self.modules.len() as u64 * 0x10000;
                self.modules.push(format!("{base:#x} {:#x}  {name}   \\SystemRoot\\System32\\drivers\\{name}\n", base + 0x10000));
            }
            stop.packet.to_string()
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
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let log = Arc::new(Mutex::new(Vec::new()));
    // Um driver que não existe nesta máquina (sem símbolos).
    let modules = vec!["0xfffff80042000000 0xfffff80042010000  alvo-falso.sys   \\SystemRoot\\System32\\drivers\\alvo-falso.sys\n".to_string()];
    let mut target = Target { registers: [0; 24], memory: Vec::new(), stops: stops.into(), log: Arc::clone(&log), modules, memory_breakpoints: Vec::new() };
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
