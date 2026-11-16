//! A sessão inteira contra um alvo de mentira: um stub do protocolo remoto
//! do GDB num socket local, com registradores, uma pilha capturada e as
//! paradas roteirizadas. Confere a negociação, a pilha pelos frame
//! pointers, os breakpoints (ligar, desligar, religar, tirar) e o passo por
//! cima de um `call`, inclusive o retorno numa recursão mais funda (o
//! cliente segue sozinho até o RSP certo), o breakpoint condicional e a
//! parada pela carga de um módulo.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use kd_client::client::Resumed;
use kd_client::rsp::{encode, hex, unhex, Connection, Decoder, Frame};
use kd_client::symbols::{Module, Symbol};
use kd_client::{BreakpointKind, Client};

const STACK: u64 = 0xffff_8000_0010_0f00;
const CODE: u64 = 0xfffff800_4010_0000;

/// O que o alvo faz no próximo `c`: os novos RIP e RSP e a resposta.
struct Stop {
    rip: u64,
    rsp: u64,
    packet: &'static str,
    /// O RAX da parada (as condições dos breakpoints).
    rax: u64,
    /// Um módulo que aparece no `lm` a partir desta parada.
    load: Option<&'static str>,
}

struct Target {
    registers: [u64; 24],
    memory: Vec<(u64, Vec<u8>)>,
    stops: VecDeque<Stop>,
    log: Arc<Mutex<Vec<String>>>,
    modules: Vec<String>,
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
        reply
    }

    fn answer(&mut self, packet: &str, stream: &mut TcpStream) -> Option<String> {
        self.log.lock().unwrap().push(packet.to_string());
        let reply = if packet.starts_with("qSupported") {
            "PacketSize=1000;swbreak+;hwbreak+;QStartNoAckMode+".to_string()
        } else if packet == "QStartNoAckMode" || packet.starts_with('Z') || packet.starts_with('z') || packet.starts_with("Hg") || packet.starts_with('M') || packet.starts_with('P') {
            if let Some(rest) = packet.strip_prefix('P') {
                let (number, value) = rest.split_once('=').unwrap();
                let mut bytes = unhex(value);
                bytes.resize(8, 0);
                self.registers[usize::from_str_radix(number, 16).unwrap()] = u64::from_le_bytes(bytes.try_into().unwrap());
            }
            "OK".to_string()
        } else if packet == "?" {
            "T02thread:1;".to_string()
        } else if packet == "g" {
            self.registers_packet()
        } else if let Some(rest) = packet.strip_prefix('m') {
            let (address, length) = rest.split_once(',').unwrap();
            match self.read(u64::from_str_radix(address, 16).unwrap(), usize::from_str_radix(length, 16).unwrap()) {
                Some(bytes) => hex(&bytes),
                None => "E14".to_string(),
            }
        } else if let Some(command) = packet.strip_prefix("qRcmd,") {
            let text = String::from_utf8(unhex(command)).unwrap();
            let output = match text.as_str() {
                "lm" => format!("              base                fim  nome             caminho\n{}", self.modules.join("")),
                "bl" => "nenhum breakpoint\n".to_string(),
                _ => "comandos do OpenNT\n".to_string(),
            };
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
fn start(stops: Vec<Stop>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let log = Arc::new(Mutex::new(Vec::new()));
    // Um driver que não existe nesta máquina (sem símbolos).
    let modules = vec!["0xfffff80042000000 0xfffff80042010000  alvo-falso.sys   \\SystemRoot\\System32\\drivers\\alvo-falso.sys\n".to_string()];
    let mut target = Target { registers: [0; 24], memory: Vec::new(), stops: stops.into(), log: Arc::clone(&log), modules };
    // Pilha: o quadro corrente em STACK + 0x20 com dois chamadores.
    let mut stack = vec![0u8; 0x100];
    let mut put = |offset: usize, value: u64| stack[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    put(0x20, STACK + 0x60);
    put(0x28, CODE + 0x2010);
    put(0x60, 0);
    put(0x68, CODE + 0x3020);
    target.memory.push((STACK, stack));
    // Código: `sub rsp, 0x20`, `call rel32`, `nop`.
    let mut code = vec![0x48, 0x83, 0xEC, 0x20, 0xE8, 0, 0, 0, 0, 0x90];
    code.resize(0x4000, 0x90);
    target.memory.push((CODE, code));
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

fn connect(address: &str) -> Client {
    let connection = Connection::connect(address, Instant::now() + Duration::from_secs(10)).unwrap();
    let mut client = Client::new(connection, PathBuf::from("."), PathBuf::from("inexistente/kernel.elf"));
    let text = client.attach(Duration::from_secs(10)).unwrap();
    assert!(text.contains("sem os simbolos do kernel"), "{text}");
    assert!(client.is_stopped());
    assert!(client.last_stop().contains("SIGINT"), "{}", client.last_stop());
    client.symbols.set_kernel(Module::new(
        "kernel",
        "kernel.elf",
        0xfffff800_40000000,
        0xfffff800_41000000,
        vec![
            Symbol { address: CODE, size: 0x100, name: "kernel::alvo::corrente".into(), function: true },
            Symbol { address: CODE + 0x1000, size: 0x100, name: "kernel::ntos::ps::notify::image::notify".into(), function: true },
            Symbol { address: CODE + 0x2000, size: 0x100, name: "kernel::alvo::chamador".into(), function: true },
            Symbol { address: CODE + 0x3000, size: 0x100, name: "kernel::alvo::kmain".into(), function: true },
        ],
        "teste",
    ));
    client
}

#[test]
fn backtrace_registers_and_memory() {
    let (address, log) = start(Vec::new());
    let mut client = connect(&address);
    assert_eq!(client.register("rip").unwrap(), CODE);
    assert_eq!(client.evaluate("%rbp+8").unwrap(), STACK + 0x28);
    assert_eq!(client.evaluate("[%rbp+8]").unwrap(), CODE + 0x2010);
    let frames = client.backtrace(16).unwrap();
    let text = client.format_frames(&frames);
    assert_eq!(frames.len(), 3, "{text}");
    assert!(text.contains("kernel::alvo::corrente"), "{text}");
    assert!(text.contains("kernel::alvo::chamador+0x10"), "{text}");
    assert!(text.contains("kernel::alvo::kmain+0x20"), "{text}");
    // Gravar um registrador refaz o `g` (o cache da parada é descartado).
    client.write_register("rax", 0x1234).unwrap();
    assert_eq!(client.register("rax").unwrap(), 0x1234);
    assert!(log.lock().unwrap().iter().any(|packet| packet == "P0=3412000000000000"));
    let output = client.execute("x %rsp 16").unwrap();
    assert!(output.contains("ffff800000100f00"), "{output}");
}

#[test]
fn breakpoints_enable_disable_remove() {
    let (address, log) = start(Vec::new());
    let mut client = connect(&address);
    let breakpoint = client.add_breakpoint(BreakpointKind::Software, "kernel::alvo::chamador", 1).unwrap();
    assert_eq!(breakpoint.address, CODE + 0x2000);
    client.set_breakpoint_enabled(breakpoint.id, false).unwrap();
    assert!(!client.breakpoints()[0].enabled);
    client.set_breakpoint_enabled(breakpoint.id, true).unwrap();
    let hardware = client.add_breakpoint(BreakpointKind::Hardware, "kernel::alvo::kmain", 1).unwrap();
    assert!(!client.toggle_breakpoint(CODE + 0x2000).unwrap());
    assert!(client.toggle_breakpoint(CODE + 0x10).unwrap());
    client.remove_breakpoint(hardware.id).unwrap();
    assert_eq!(client.breakpoints().len(), 1);
    assert_eq!(client.breakpoints()[0].expression, "kernel::alvo::corrente+0x10");
    let sent: Vec<String> = log.lock().unwrap().iter().filter(|packet| packet.starts_with('Z') || packet.starts_with('z')).cloned().collect();
    assert_eq!(sent, vec!["Z0,fffff80040102000,1", "z0,fffff80040102000,1", "Z0,fffff80040102000,1", "Z1,fffff80040103000,1", "z0,fffff80040102000,1", "Z0,fffff80040100010,1", "z1,fffff80040103000,1"]);
}

#[test]
fn step_over_skips_deeper_recursion() {
    // O `call` está em CODE + 4 (RSP = STACK - 0x20 depois do `sub`). A
    // primeira parada no retorno vem com outro RSP (uma recursão mais
    // funda): o cliente segue sozinho; a segunda é a certa.
    let stops = vec![
        Stop { rip: CODE + 4, rsp: STACK - 0x20, packet: "T05thread:1;", rax: 0, load: None },
        Stop { rip: CODE + 9, rsp: STACK - 0x80, packet: "T05thread:1;swbreak:;", rax: 0, load: None },
        Stop { rip: CODE + 9, rsp: STACK - 0x20, packet: "T05thread:1;swbreak:;", rax: 0, load: None },
    ];
    let (address, log) = start(stops);
    let mut client = connect(&address);
    // O `sub rsp, 0x20` não é chamada: passo simples.
    match client.step_over().unwrap() {
        Resumed::Stopped(text) => assert!(text.contains("SIGTRAP"), "{text}"),
        Resumed::Running => panic!("um passo simples terminaria na hora"),
    }
    assert_eq!(client.register("rip").unwrap(), CODE + 4);
    assert_eq!(client.step_over().unwrap(), Resumed::Running);
    let stop = client.wait_stop(Duration::from_secs(10)).unwrap();
    assert!(stop.contains("kernel::alvo::corrente+0x9"), "{stop}");
    assert_eq!(client.register("rsp").unwrap(), STACK - 0x20);
    let sent: Vec<String> = log.lock().unwrap().iter().filter(|packet| matches!(packet.as_bytes().first(), Some(b'Z' | b'z' | b'c' | b's'))).cloned().collect();
    assert_eq!(sent, vec!["s", "Z0,fffff80040100009,1", "c", "c", "z0,fffff80040100009,1"]);
    assert!(client.breakpoints().is_empty());
}

#[test]
fn conditional_breakpoint_and_pass_count() {
    // Três acertos em CODE + 0x10: RAX 1, 7 e 7. Com a condição `@rax == 7`
    // e a contagem 3, só o terceiro para; os outros seguem sozinhos.
    let stops = vec![
        Stop { rip: CODE + 0x10, rsp: STACK, packet: "T05thread:1;swbreak:;", rax: 1, load: None },
        Stop { rip: CODE + 0x10, rsp: STACK, packet: "T05thread:1;swbreak:;", rax: 7, load: None },
        Stop { rip: CODE + 0x10, rsp: STACK, packet: "T05thread:1;swbreak:;", rax: 7, load: None },
    ];
    let (address, log) = start(stops);
    let mut client = connect(&address);
    let text = client.execute("bp kernel::alvo::corrente+0x10 3 /w \"@rax == 7\"").unwrap();
    assert!(text.contains("a partir do acerto 3") && text.contains("se @rax == 7"), "{text}");
    client.go().unwrap();
    let stop = client.wait_stop(Duration::from_secs(10)).unwrap();
    assert!(stop.contains("breakpoint #0, condicao verdadeira, acerto 3"), "{stop}");
    assert_eq!(client.register("rax").unwrap(), 7);
    assert_eq!(client.breakpoints()[0].hits, 3);
    let continues = log.lock().unwrap().iter().filter(|packet| *packet == "c").count();
    assert_eq!(continues, 3);
    // A sessão gravada recria o breakpoint com a condição.
    let specs = client.breakpoint_specs();
    assert!(specs.starts_with("software\t1\t1\t3\tkernel::alvo::corrente+0x10\t@rax == 7"), "{specs}");
}

#[test]
fn stops_when_a_module_loads() {
    // A notificação de carga para duas vezes: primeiro outro módulo (segue
    // sozinho), depois o pedido.
    let hook = CODE + 0x1000;
    let stops = vec![
        Stop { rip: hook, rsp: STACK, packet: "T05thread:1;swbreak:;", rax: 0, load: Some("outro.sys") },
        Stop { rip: hook, rsp: STACK, packet: "T05thread:1;swbreak:;", rax: 0, load: Some("novo.sys") },
    ];
    let (address, log) = start(stops);
    let mut client = connect(&address);
    let text = client.execute("sxe ld:novo").unwrap();
    assert!(text.contains("para quando novo carregar"), "{text}");
    // Um breakpoint adiado num módulo que ainda não existe.
    let text = client.execute("bu novo!Entrada").unwrap();
    assert!(text.contains("adiado"), "{text}");
    client.go().unwrap();
    let stop = client.wait_stop(Duration::from_secs(10)).unwrap();
    assert!(stop.contains("modulo carregado: novo.sys"), "{stop}");
    assert!(client.symbols.module_named("novo").is_some());
    let sent: Vec<String> = log.lock().unwrap().iter().filter(|packet| matches!(packet.as_bytes().first(), Some(b'Z' | b'z' | b'c'))).cloned().collect();
    assert_eq!(sent, vec!["Z0,fffff80040101000,1", "c", "c"]);
    let list = client.execute("bl").unwrap();
    assert!(list.contains("ld:novo") && list.contains("(adiado)"), "{list}");
}
