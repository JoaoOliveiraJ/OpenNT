//! Comandos do cliente do depurador (interativo e em roteiro).
//!
//! ```text
//! attach                     conecta a sessao (o alvo para) e carrega os simbolos
//! break                      pede a parada (0x03) e espera
//! c | continue               continua (no roteiro, volta sem esperar; use wait-stop)
//! wait-stop [ms]             espera a proxima parada
//! s | step [n]               um passo (n passos) no processador da parada
//! regs                       registradores do processador escolhido
//! x <expr> [bytes]           memoria em hexadecimal
//! write <expr> <hex>         grava bytes
//! poke <1|2|4|8> <expr> <valor>   grava um inteiro
//! bp | bc <expr|all>         breakpoint de software (por endereco ou simbolo)
//! hbp | hbc <expr>           breakpoint de hardware (DR0-DR3)
//! watch | unwatch <expr> <bytes> [w|a]   vigia de escrita ou de acesso
//! bt [n]                     pilha pelos frame pointers
//! sym <expr>                 endereco -> simbolo; addr <nome>: nome -> endereco
//! thread <n>                 processador das leituras (thread n = CPU n-1)
//! context <ethread>          registradores de uma thread (fora da CPU: quadro de troca)
//! btt <ethread> [n]          pilha de uma thread pelo quadro de troca
//! cpulist                    processadores parados (threads do protocolo)
//! ps | threads [pid] | lm | cpus | irql | obj <caminho> | log [bytes] | bl | bugcheck | kd
//! monitor <texto>            comando do OpenNT no alvo
//! detach | quit
//! ```
//!
//! Roteiro (`--script`): uma linha por comando, `#` comenta, e as
//! conferências `expect <texto>` (a saída do comando anterior contém o
//! texto), `expect-stop <texto>` (a última parada), `expect-console
//! <texto>` (a saída do DbgPrint recebida), `expect-eq <expr> <expr>`,
//! `save <nome> <expr>` (vira `$nome`), `save-word <nome> <texto> <coluna>`
//! (um número da saída anterior), `wait-serial <texto>` (o texto no log da
//! COM1), `echo <texto>` e `sleep <ms>`.
//! Expressões: números (`0x...` ou decimais), `$nome`, `%reg`, símbolos,
//! `[expr]` / `byte[expr]` / `word[expr]` / `dword[expr]` (memória), com
//! `+` e `-`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::rsp::{hex, unhex, Connection};
use super::symbols::Symbols;

/// Registradores do pacote `g` (ordem do GDB para x86-64).
const REGISTERS: &[(&str, usize)] = &[
    ("rax", 8), ("rbx", 8), ("rcx", 8), ("rdx", 8), ("rsi", 8), ("rdi", 8), ("rbp", 8), ("rsp", 8),
    ("r8", 8), ("r9", 8), ("r10", 8), ("r11", 8), ("r12", 8), ("r13", 8), ("r14", 8), ("r15", 8),
    ("rip", 8), ("eflags", 4), ("cs", 4), ("ss", 4), ("ds", 4), ("es", 4), ("fs", 4), ("gs", 4),
];

const HELP: &str = "attach | break | c | wait-stop [ms] | s [n] | regs | x <expr> [bytes] | write <expr> <hex>
poke <1|2|4|8> <expr> <valor> | bp/bc <expr|all> | hbp/hbc <expr> | watch/unwatch <expr> <bytes> [w|a]
bt [n] | btt <ethread> [n] | context <ethread> | sym <expr> | addr <nome> | thread <n> | cpulist | modules
ps | threads [pid] | lm | cpus | irql | obj <caminho> | log [bytes] | bl | bugcheck | kd | monitor <texto>
detach | quit
expressoes: 0x.., decimais, $nome, %reg, simbolos, [expr] byte[..] word[..] dword[..], + e -
";

const SIGNALS: &[(u8, &str)] = &[(2, "SIGINT (pedido de parada)"), (4, "SIGILL"), (5, "SIGTRAP"), (6, "SIGABRT (bugcheck/panico)"), (8, "SIGFPE"), (11, "SIGSEGV")];

pub struct Client {
    connection: Connection,
    pub symbols: Symbols,
    root: PathBuf,
    elf: PathBuf,
    stopped: bool,
    last_stop: String,
    variables: HashMap<String, u64>,
    /// Saída do DbgPrint recebida na sessão inteira.
    console: String,
    /// Imprime a saída do DbgPrint assim que chega (modo interativo).
    echo_console: bool,
    timeout: Duration,
    /// Saída da COM1 (o log do kernel), quando o cliente roda junto com o
    /// teste.
    serial: Option<Arc<Mutex<String>>>,
}

fn parse_number(text: &str) -> Option<u64> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(&hex.replace('`', "").replace('_', ""), 16).ok()
    } else if text.chars().all(|character| character.is_ascii_digit()) && !text.is_empty() {
        text.parse().ok()
    } else {
        None
    }
}

impl Client {
    pub fn new(connection: Connection, root: PathBuf, elf: PathBuf, echo_console: bool) -> Self {
        Self { connection, symbols: Symbols::default(), root, elf, stopped: false, last_stop: String::new(), variables: HashMap::new(), console: String::new(), echo_console, timeout: Duration::from_secs(20), serial: None }
    }

    /// A saída da COM1 para o `wait-serial` do roteiro.
    pub fn set_serial(&mut self, serial: Arc<Mutex<String>>) {
        self.serial = Some(serial);
    }

    fn collect_console(&mut self) {
        let text = self.connection.take_console();
        if !text.is_empty() {
            if self.echo_console {
                print!("{text}");
            }
            self.console.push_str(&text);
        }
    }

    fn request(&mut self, payload: &str) -> Result<String, String> {
        let reply = self.connection.request(payload, self.timeout);
        self.collect_console();
        reply
    }

    fn describe_stop(&mut self, packet: &str) -> String {
        let signal = u8::from_str_radix(packet.get(1..3).unwrap_or("00"), 16).unwrap_or(0);
        let name = SIGNALS.iter().find(|(number, _)| *number == signal).map_or("sinal", |(_, name)| name);
        let mut reasons = Vec::new();
        let mut thread = String::new();
        for field in packet.get(3..).unwrap_or("").split(';').filter(|field| !field.is_empty()) {
            let (key, value) = field.split_once(':').unwrap_or((field, ""));
            match key {
                "thread" => thread = value.to_string(),
                "swbreak" => reasons.push("swbreak".to_string()),
                "hwbreak" => reasons.push("hwbreak".to_string()),
                "watch" | "awatch" | "rwatch" => reasons.push(format!("{key} {value}")),
                _ => {}
            }
        }
        let rip = self.register("rip").ok();
        let location = rip.map(|rip| format!(" em {:#x} {}", rip, self.symbols.describe(rip))).unwrap_or_default();
        let processor = u64::from_str_radix(&thread, 16).map(|thread| format!(" (CPU {})", thread.saturating_sub(1))).unwrap_or_default();
        format!("parado: {name} {}{processor}{location}", reasons.join(" "))
    }

    fn stopped_with(&mut self, packet: String) -> Result<String, String> {
        if !packet.starts_with('T') && !packet.starts_with('S') {
            return Err(format!("resposta de parada inesperada: {packet:?}"));
        }
        self.stopped = true;
        // Módulos carregados desde a última parada entram nos símbolos (a
        // primeira parada, a do attach, ainda não tem o ELF carregado).
        if !self.symbols.modules.is_empty() {
            let _ = self.reload_modules();
        }
        self.last_stop = self.describe_stop(&packet);
        self.last_stop = format!("{} [{}]", self.last_stop, packet);
        Ok(self.last_stop.clone())
    }

    /// Negocia a sessão: o primeiro pacote para a máquina (o depurador do
    /// alvo para quando um pacote chega com ela rodando).
    pub fn attach(&mut self, timeout: Duration) -> Result<String, String> {
        let supported = self.connection.request("qSupported:swbreak+;hwbreak+;vContSupported+", timeout)?;
        self.collect_console();
        if supported.contains("QStartNoAckMode+") && self.request("QStartNoAckMode")? == "OK" {
            self.connection.set_no_ack();
        }
        let stop = self.request("?")?;
        let mut output = format!("sessao: {supported}\n");
        let count = self.symbols.load_kernel(&self.elf)?;
        output.push_str(&format!("simbolos do kernel: {count} ({})\n", self.elf.display()));
        output.push_str(&self.stopped_with(stop)?);
        self.reload_modules()?;
        Ok(output)
    }

    /// Lê a lista de módulos do alvo e os símbolos de cada um.
    fn reload_modules(&mut self) -> Result<(), String> {
        let text = self.monitor("lm")?;
        let mut list = Vec::new();
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 4 {
                if let (Some(base), Some(end)) = (parse_number(fields[0]), parse_number(fields[1])) {
                    list.push((base, end, fields[3..].join(" ")));
                }
            }
        }
        self.symbols.set_modules(&list, &self.root);
        Ok(())
    }

    fn require_stopped(&self) -> Result<(), String> {
        if self.stopped { Ok(()) } else { Err("a maquina esta rodando (use break)".into()) }
    }

    /// Comando do OpenNT no alvo: a resposta chega em pacotes `O` antes do
    /// `OK` (com a máquina parada não há DbgPrint misturado).
    pub fn monitor(&mut self, command: &str) -> Result<String, String> {
        self.require_stopped()?;
        self.collect_console();
        let reply = self.connection.request(&format!("qRcmd,{}", hex(command.as_bytes())), self.timeout)?;
        let text = self.connection.take_console();
        if reply != "OK" {
            return Err(format!("monitor {command}: {reply}"));
        }
        Ok(text)
    }

    fn registers(&mut self) -> Result<Vec<u8>, String> {
        self.require_stopped()?;
        let reply = self.request("g")?;
        if reply.starts_with('E') {
            return Err(format!("registradores: {reply}"));
        }
        Ok(unhex(&reply.replace('x', "0")))
    }

    fn register(&mut self, name: &str) -> Result<u64, String> {
        let bytes = self.registers()?;
        let mut offset = 0;
        for &(register, size) in REGISTERS {
            if register == name {
                let mut value = [0u8; 8];
                value[..size].copy_from_slice(bytes.get(offset..offset + size).ok_or("pacote g curto")?);
                return Ok(u64::from_le_bytes(value));
            }
            offset += size;
        }
        Err(format!("registrador desconhecido: {name}"))
    }

    fn read_memory(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
        self.require_stopped()?;
        let mut bytes = Vec::with_capacity(length);
        while bytes.len() < length {
            let chunk = (length - bytes.len()).min(0x400);
            let reply = self.request(&format!("m{:x},{:x}", address + bytes.len() as u64, chunk))?;
            if reply.starts_with('E') || reply.is_empty() {
                if bytes.is_empty() {
                    return Err(format!("memoria em {address:#x} inacessivel ({reply})"));
                }
                break;
            }
            let data = unhex(&reply);
            let short = data.len() < chunk;
            bytes.extend_from_slice(&data);
            if short {
                break;
            }
        }
        Ok(bytes)
    }

    fn write_memory(&mut self, address: u64, bytes: &[u8]) -> Result<(), String> {
        self.require_stopped()?;
        let reply = self.request(&format!("M{:x},{:x}:{}", address, bytes.len(), hex(bytes)))?;
        if reply == "OK" { Ok(()) } else { Err(format!("escrita em {address:#x}: {reply}")) }
    }

    fn read_integer(&mut self, address: u64, size: usize) -> Result<u64, String> {
        let bytes = self.read_memory(address, size)?;
        if bytes.len() < size {
            return Err(format!("memoria em {address:#x} inacessivel"));
        }
        let mut value = [0u8; 8];
        value[..size].copy_from_slice(&bytes[..size]);
        Ok(u64::from_le_bytes(value))
    }

    /// Avalia uma expressão (termos somados ou subtraídos).
    pub fn evaluate(&mut self, expression: &str) -> Result<u64, String> {
        let text = expression.trim();
        // Divide no último `+`/`-` fora de colchetes e de nomes com `::<...>`.
        let mut depth = 0i32;
        let mut split = None;
        for (index, character) in text.char_indices() {
            match character {
                '[' | '<' => depth += 1,
                ']' | '>' => depth -= 1,
                '+' | '-' if depth == 0 && index > 0 => split = Some((index, character)),
                _ => {}
            }
        }
        if let Some((index, operator)) = split {
            let left = self.evaluate(&text[..index])?;
            let right = self.evaluate(&text[index + 1..])?;
            return Ok(if operator == '+' { left.wrapping_add(right) } else { left.wrapping_sub(right) });
        }
        for (prefix, size) in [("byte[", 1), ("word[", 2), ("dword[", 4), ("qword[", 8), ("[", 8)] {
            if let Some(inner) = text.strip_prefix(prefix).and_then(|rest| rest.strip_suffix(']')) {
                let address = self.evaluate(inner)?;
                return self.read_integer(address, size);
            }
        }
        if let Some(name) = text.strip_prefix('$') {
            return self.variables.get(name).copied().ok_or_else(|| format!("variavel ${name} nao definida"));
        }
        if let Some(name) = text.strip_prefix('%') {
            return self.register(name);
        }
        if let Some(value) = parse_number(text) {
            return Ok(value);
        }
        self.symbols.lookup(text)
    }

    fn wait_stop(&mut self, timeout: Duration) -> Result<String, String> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("tempo esgotado esperando a parada".into());
            }
            match self.connection.receive(remaining.min(Duration::from_millis(500))) {
                Ok(packet) => {
                    self.collect_console();
                    return self.stopped_with(packet);
                }
                Err(error) if error.contains("tempo esgotado") => {
                    self.collect_console();
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn resume(&mut self, packet: &str) -> Result<(), String> {
        self.require_stopped()?;
        self.connection.send(packet, self.timeout)?;
        self.stopped = false;
        Ok(())
    }

    fn breakpoint(&mut self, insert: bool, kind: u8, target: &str, length: u64) -> Result<String, String> {
        self.require_stopped()?;
        let address = self.evaluate(target)?;
        let reply = self.request(&format!("{}{},{:x},{:x}", if insert { 'Z' } else { 'z' }, kind, address, length))?;
        match reply.as_str() {
            "OK" => Ok(format!("{} {:#x} {}", if insert { "armado" } else { "removido" }, address, self.symbols.describe(address))),
            "" => Err("tipo de breakpoint sem suporte no alvo".into()),
            other => Err(format!("breakpoint em {address:#x}: {other}")),
        }
    }

    /// Pilha pelos frame pointers (o kernel é compilado com eles). No
    /// prólogo (`push rbp` ou `mov rbp, rsp` ainda por executar) o endereço
    /// de retorno está no topo da pilha e o RBP ainda é o do chamador.
    fn backtrace(&mut self, limit: usize) -> Result<String, String> {
        let rip = self.register("rip")?;
        let rsp = self.register("rsp")?;
        let rbp = self.register("rbp")?;
        let mut frames = vec![rip];
        let code = self.read_memory(rip, 3).unwrap_or_default();
        let pending = if code.first() == Some(&0x55) {
            Some(rsp)
        } else if code.starts_with(&[0x48, 0x89, 0xE5]) {
            Some(rsp + 8)
        } else {
            None
        };
        if let Some(slot) = pending {
            if let Ok(address) = self.read_integer(slot, 8) {
                frames.push(address);
            }
        }
        self.unwind(frames, rbp, limit, 0)
    }

    /// Segue a cadeia de RBP a partir de `frames` (os primeiros endereços já
    /// conhecidos); `first_return` é o índice do primeiro endereço que já é
    /// de retorno.
    fn unwind(&mut self, mut frames: Vec<u64>, mut rbp: u64, limit: usize, first_return: usize) -> Result<String, String> {
        while frames.len() < limit && rbp != 0 && rbp & 7 == 0 {
            let Ok(frame) = self.read_memory(rbp, 16) else { break };
            if frame.len() < 16 {
                break;
            }
            let next = u64::from_le_bytes(frame[..8].try_into().unwrap());
            let address = u64::from_le_bytes(frame[8..16].try_into().unwrap());
            if address == 0 {
                break;
            }
            frames.push(address);
            if next <= rbp {
                break;
            }
            rbp = next;
        }
        let mut output = String::new();
        for (depth, &address) in frames.iter().enumerate() {
            // Um endereço de retorno pode cair logo depois do fim da função
            // chamadora (chamada que não volta): o símbolo é o de antes dele.
            let name = if depth == 0 && first_return == 0 { self.symbols.describe(address) } else { self.symbols.describe_return(address) };
            output.push_str(&format!("#{depth:<2} {address:#018x} {name}\n"));
        }
        Ok(output)
    }

    /// Pilha de uma thread pelo `monitor context` (o quadro de troca da
    /// pilha de kernel de uma thread fora da CPU: o RIP já é um retorno).
    fn thread_backtrace(&mut self, thread: u64, limit: usize) -> Result<String, String> {
        let text = self.monitor(&format!("context {thread:x}"))?;
        let field = |name: &str| text.split_whitespace().find_map(|word| word.strip_prefix(name).and_then(parse_number));
        let (Some(rip), Some(rbp)) = (field("rip="), field("rbp=")) else { return Err(format!("contexto de {thread:#x}: {}", text.trim())) };
        let running = text.contains("roda na CPU");
        let mut output = format!("{}\n", text.lines().next().unwrap_or(""));
        output.push_str(&self.unwind(vec![rip], rbp, limit, if running { 0 } else { 1 })?);
        Ok(output)
    }

    fn format_registers(&mut self) -> Result<String, String> {
        let bytes = self.registers()?;
        let mut output = String::new();
        let mut offset = 0;
        for (index, &(name, size)) in REGISTERS.iter().enumerate() {
            let mut value = [0u8; 8];
            value[..size].copy_from_slice(&bytes[offset..offset + size]);
            offset += size;
            output.push_str(&format!("{name:>6}={:#018x}", u64::from_le_bytes(value)));
            output.push(if index % 4 == 3 { '\n' } else { ' ' });
        }
        Ok(output)
    }

    fn dump(&mut self, address: u64, length: usize) -> Result<String, String> {
        let bytes = self.read_memory(address, length)?;
        let mut output = String::new();
        for (row, chunk) in bytes.chunks(16).enumerate() {
            let text: String = chunk.iter().map(|&byte| if (0x20..0x7F).contains(&byte) { byte as char } else { '.' }).collect();
            output.push_str(&format!("{:#018x}  {:<48} {}\n", address + row as u64 * 16, chunk.iter().map(|byte| format!("{byte:02x} ")).collect::<String>(), text));
        }
        Ok(output)
    }

    /// Executa um comando; devolve a saída.
    pub fn execute(&mut self, line: &str) -> Result<String, String> {
        let line = line.trim();
        let (command, rest) = line.split_once(char::is_whitespace).map_or((line, ""), |(command, rest)| (command, rest.trim()));
        let words: Vec<&str> = rest.split_whitespace().collect();
        match command {
            "" => Ok(String::new()),
            "attach" => self.attach(Duration::from_secs(120)),
            "break" | "halt" => {
                if self.stopped {
                    return Ok(self.last_stop.clone());
                }
                self.connection.interrupt()?;
                self.wait_stop(Duration::from_secs(60))
            }
            "c" | "continue" => {
                self.resume("c")?;
                Ok("rodando".into())
            }
            "wait-stop" => {
                let milliseconds = words.first().and_then(|text| parse_number(text)).unwrap_or(120_000);
                self.wait_stop(Duration::from_millis(milliseconds))
            }
            "s" | "step" => {
                let count = words.first().and_then(|text| parse_number(text)).unwrap_or(1);
                let mut output = String::new();
                for _ in 0..count {
                    self.resume("s")?;
                    output = self.wait_stop(self.timeout)?;
                }
                Ok(output)
            }
            "regs" | "r" => self.format_registers(),
            "x" | "mem" => {
                let address = self.evaluate(words.first().ok_or("uso: x <endereco> [bytes]")?)?;
                let length = words.get(1).and_then(|text| parse_number(text)).unwrap_or(64) as usize;
                self.dump(address, length)
            }
            "write" => {
                let address = self.evaluate(words.first().ok_or("uso: write <endereco> <hex>")?)?;
                let bytes = unhex(words.get(1).ok_or("uso: write <endereco> <hex>")?);
                self.write_memory(address, &bytes)?;
                Ok(format!("{} bytes em {address:#x}", bytes.len()))
            }
            "poke" => {
                let size = words.first().and_then(|text| parse_number(text)).filter(|size| matches!(size, 1 | 2 | 4 | 8)).ok_or("uso: poke <1|2|4|8> <endereco> <valor>")? as usize;
                let address = self.evaluate(words.get(1).ok_or("uso: poke <1|2|4|8> <endereco> <valor>")?)?;
                let value = self.evaluate(words.get(2).ok_or("uso: poke <1|2|4|8> <endereco> <valor>")?)?;
                self.write_memory(address, &value.to_le_bytes()[..size])?;
                Ok(format!("{value:#x} em {address:#x}"))
            }
            "bp" => self.breakpoint(true, 0, rest, 1),
            "bc" if rest == "all" => {
                let list = self.monitor("bl")?;
                for line in list.lines() {
                    if let Some(address) = line.strip_prefix("software").and_then(|rest| parse_number(rest.trim())) {
                        self.request(&format!("z0,{address:x},1"))?;
                    }
                }
                Ok("breakpoints de software removidos".into())
            }
            "bc" => self.breakpoint(false, 0, rest, 1),
            "hbp" => self.breakpoint(true, 1, rest, 1),
            "hbc" => self.breakpoint(false, 1, rest, 1),
            "watch" | "unwatch" => {
                let target = words.first().ok_or("uso: watch <endereco> <bytes> [w|a]")?;
                let length = words.get(1).and_then(|text| parse_number(text)).unwrap_or(8);
                let kind = if words.get(2) == Some(&"a") { 4 } else { 2 };
                self.breakpoint(command == "watch", kind, target, length)
            }
            "bt" => {
                let limit = words.first().and_then(|text| parse_number(text)).unwrap_or(32) as usize;
                self.backtrace(limit)
            }
            "context" => {
                let thread = self.evaluate(rest)?;
                self.monitor(&format!("context {thread:x}"))
            }
            "btt" => {
                let thread = self.evaluate(words.first().ok_or("uso: btt <ethread> [n]")?)?;
                let limit = words.get(1).and_then(|text| parse_number(text)).unwrap_or(32) as usize;
                self.thread_backtrace(thread, limit)
            }
            "sym" => {
                let address = self.evaluate(rest)?;
                Ok(format!("{address:#x} {}", self.symbols.describe(address)))
            }
            "addr" => {
                let address = self.symbols.lookup(rest)?;
                Ok(format!("{address:#x} {}", self.symbols.describe(address)))
            }
            "thread" => {
                let thread = parse_number(rest).ok_or("uso: thread <n>")?;
                let reply = self.request(&format!("Hg{thread:x}"))?;
                if reply == "OK" { Ok(format!("thread {thread} (CPU {})", thread.saturating_sub(1))) } else { Err(format!("thread {thread}: {reply}")) }
            }
            "cpulist" => {
                self.require_stopped()?;
                let mut threads = Vec::new();
                let mut reply = self.request("qfThreadInfo")?;
                while let Some(list) = reply.strip_prefix('m') {
                    threads.extend(list.split(',').filter_map(|thread| u64::from_str_radix(thread, 16).ok()));
                    reply = self.request("qsThreadInfo")?;
                }
                Ok(format!("processadores parados: {}", threads.iter().map(|thread| thread.to_string()).collect::<Vec<_>>().join(",")))
            }
            "ps" | "threads" | "lm" | "cpus" | "irql" | "obj" | "log" | "bl" | "bugcheck" | "kd" => {
                let text = self.monitor(line)?;
                if command == "lm" {
                    self.reload_modules()?;
                }
                Ok(text)
            }
            "monitor" => self.monitor(rest),
            "modules" => Ok(self.symbols.modules.iter().map(|module| format!("{:#018x} {:#018x} {:<16} {} simbolos ({})\n", module.base, module.end, module.name, module.symbols.len(), module.source)).collect()),
            "detach" => {
                if !self.stopped {
                    self.connection.interrupt()?;
                    self.wait_stop(Duration::from_secs(60))?;
                }
                let reply = self.request("D")?;
                self.stopped = false;
                Ok(format!("desligado ({reply})"))
            }
            "help" => Ok(HELP.to_string()),
            other => Err(format!("comando desconhecido: {other} (help)")),
        }
    }

    /// Roda um roteiro; a primeira conferência que falha encerra.
    pub fn run_script(&mut self, script: &str) -> Result<(), String> {
        let mut last_output = String::new();
        for (number, raw) in script.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            println!("[kd-script] > {line}");
            let fail = |message: String| format!("roteiro, linha {}: {line}: {message}", number + 1);
            let (command, rest) = line.split_once(char::is_whitespace).map_or((line, ""), |(command, rest)| (command, rest.trim()));
            match command {
                "expect" => {
                    if !last_output.contains(rest) {
                        return Err(fail(format!("saida sem {rest:?}:\n{last_output}")));
                    }
                }
                "expect-stop" => {
                    if !self.last_stop.contains(rest) {
                        return Err(fail(format!("ultima parada sem {rest:?}: {}", self.last_stop)));
                    }
                }
                "expect-console" => {
                    self.collect_console();
                    if !self.console.contains(rest) {
                        return Err(fail(format!("saida do DbgPrint sem {rest:?}:\n{}", self.console)));
                    }
                }
                "expect-eq" => {
                    let (left, right) = split_two(rest).ok_or_else(|| fail("uso: expect-eq <expr> <expr>".into()))?;
                    let (a, b) = (self.evaluate(left).map_err(&fail)?, self.evaluate(right).map_err(&fail)?);
                    if a != b {
                        return Err(fail(format!("{left} = {a:#x}, {right} = {b:#x}")));
                    }
                    println!("[kd-script]   {a:#x} == {b:#x}");
                }
                "save" => {
                    let (name, expression) = split_two(rest).ok_or_else(|| fail("uso: save <nome> <expr>".into()))?;
                    let value = self.evaluate(expression).map_err(&fail)?;
                    self.variables.insert(name.to_string(), value);
                    println!("[kd-script]   ${name} = {value:#x}");
                }
                "save-word" => {
                    // save-word <nome> <texto da linha> <coluna>: um número da
                    // primeira linha da saída anterior que contém o texto.
                    let mut parts = rest.split_whitespace();
                    let (Some(name), Some(needle), Some(column)) = (parts.next(), parts.next(), parts.next().and_then(|text| text.parse::<usize>().ok())) else {
                        return Err(fail("uso: save-word <nome> <texto> <coluna>".into()));
                    };
                    let value = last_output.lines().find(|line| line.contains(needle)).and_then(|line| line.split_whitespace().nth(column)).and_then(parse_number).ok_or_else(|| fail(format!("nenhuma linha com {needle:?} e numero na coluna {column}")))?;
                    self.variables.insert(name.to_string(), value);
                    println!("[kd-script]   ${name} = {value:#x}");
                }
                "wait-serial" => {
                    // O texto em qualquer ponto do log da COM1 (a ordem entre as
                    // tarefas do kernel não importa).
                    let serial = self.serial.clone().ok_or_else(|| fail("sem o log da COM1 neste modo".into()))?;
                    let deadline = Instant::now() + Duration::from_secs(300);
                    while !serial.lock().unwrap().contains(rest) {
                        if Instant::now() > deadline {
                            return Err(fail("tempo esgotado esperando o texto na COM1".into()));
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
                "echo" => println!("[kd-script] {rest}"),
                "sleep" => std::thread::sleep(Duration::from_millis(parse_number(rest).unwrap_or(1000))),
                _ => {
                    last_output = self.execute(line).map_err(&fail)?;
                    for output_line in last_output.lines() {
                        println!("[kd-script]   {output_line}");
                    }
                }
            }
        }
        Ok(())
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// Recolhe a saída do DbgPrint que chegou com a máquina rodando.
    pub fn poll_console(&mut self, timeout: Duration) -> Result<Option<String>, String> {
        if self.stopped {
            return Ok(None);
        }
        match self.connection.receive(timeout) {
            Ok(packet) => {
                self.collect_console();
                self.stopped_with(packet).map(Some)
            }
            Err(error) if error.contains("tempo esgotado") => {
                self.collect_console();
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}

/// Divide em duas expressões no primeiro espaço fora de colchetes.
fn split_two(text: &str) -> Option<(&str, &str)> {
    let mut depth = 0;
    for (index, character) in text.char_indices() {
        match character {
            '[' => depth += 1,
            ']' => depth -= 1,
            ' ' if depth == 0 => return Some((&text[..index], text[index + 1..].trim())),
            _ => {}
        }
    }
    None
}
