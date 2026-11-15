//! A sessão do depurador: os comandos de texto (o prompt do `cargo xtask
//! debug` e o painel de comandos do `opennt-dbg`), os roteiros de teste e a
//! API tipada que a interface gráfica usa.
//!
//! ```text
//! attach                     conecta a sessao (o alvo para) e carrega os simbolos
//! break                      pede a parada (0x03) e espera
//! c | g | continue           continua (no roteiro, volta sem esperar; use wait-stop)
//! wait-stop [ms]             espera a proxima parada
//! s | t | step [n]           um passo (n passos) no processador da parada
//! p [n]                      passo por cima de um call (breakpoint temporario no retorno)
//! gu                         ate o retorno da funcao corrente (pelo frame pointer)
//! regs | r                   registradores do processador escolhido; r <reg>=<expr> grava
//! x <expr> [bytes]           memoria em hexadecimal
//! write <expr> <hex>         grava bytes
//! poke <1|2|4|8> <expr> <valor>   grava um inteiro
//! bp | bc <expr|#n|all>      breakpoint de software (por endereco ou simbolo)
//! hbp | hbc <expr>           breakpoint de hardware (DR0-DR3)
//! watch | unwatch <expr> <bytes> [w|a]   vigia de escrita ou de acesso
//! bd | be <n>                desliga / religa o breakpoint n (sem esquece-lo)
//! bl                         breakpoints do cliente e os armados no alvo
//! bt [n]                     pilha pelos frame pointers
//! sym <expr>                 endereco -> simbolo; addr <nome>: nome -> endereco
//! thread <n>                 processador das leituras (thread n = CPU n-1)
//! context <ethread>          registradores de uma thread (fora da CPU: quadro de troca)
//! btt <ethread> [n]          pilha de uma thread pelo quadro de troca
//! cpulist                    processadores parados (threads do protocolo)
//! ps | threads [pid] | lm | cpus | irql | obj <caminho> | log [bytes] | bugcheck | kd
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

use super::monitor::{self, LoadedModule, Process, Processor, Thread, ThreadContext};
use super::registers::{self, Value};
use super::rsp::{hex, is_timeout, unhex, Connection};
use super::stop::{Reason, StopReply};
use super::symbols::Symbols;
use super::unwind::{self, Frame, ReadMemory};
use super::{parse_number, x86};

const HELP: &str = "attach | break | c | wait-stop [ms] | s [n] | p [n] | gu | regs | r <reg>=<expr> | x <expr> [bytes]
write <expr> <hex> | poke <1|2|4|8> <expr> <valor> | bp/bc <expr|#n|all> | hbp/hbc <expr>
watch/unwatch <expr> <bytes> [w|a] | bd/be <n> | bl | bt [n] | btt <ethread> [n] | context <ethread>
sym <expr> | addr <nome> | thread <n> | cpulist | modules
ps | threads [pid] | lm | cpus | irql | obj <caminho> | log [bytes] | bugcheck | kd | monitor <texto>
detach | quit
expressoes: 0x.., decimais, $nome, %reg, simbolos, [expr] byte[..] word[..] dword[..], + e -
";

/// Quanto o `p` e o `gu` do prompt esperam a chamada voltar.
const RUN_TO_WAIT: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakpointKind {
    /// `int 3` gravado no código (Z0).
    Software,
    /// Comparador de execução DR0-DR3 (Z1).
    Hardware,
    /// Vigia de escrita (Z2).
    Write,
    /// Vigia de acesso (Z4).
    Access,
}

impl BreakpointKind {
    fn packet_type(self) -> u8 {
        match self {
            Self::Software => 0,
            Self::Hardware => 1,
            Self::Write => 2,
            Self::Access => 4,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::Hardware => "hardware",
            Self::Write => "escrita",
            Self::Access => "acesso",
        }
    }
}

/// Um breakpoint do cliente: desligado, continua na lista mas sai do alvo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Breakpoint {
    pub id: u32,
    pub kind: BreakpointKind,
    pub address: u64,
    pub length: u64,
    pub enabled: bool,
    /// Como o usuário o pediu (símbolo ou expressão).
    pub expression: String,
}

/// O passo por cima ou para fora em andamento: o breakpoint temporário no
/// retorno e o RSP que o processador terá ao voltar (uma parada no mesmo
/// endereço com outro RSP é de uma recursão mais funda ou de outra thread,
/// e a máquina segue).
struct RunTo {
    address: u64,
    /// O breakpoint é só deste passo (não havia um do usuário ali).
    inserted: bool,
    expected_rsp: u64,
}

/// Como a máquina ficou depois de um passo por cima ou para fora.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resumed {
    /// O passo terminou na hora (a instrução não era um `call`).
    Stopped(String),
    /// A máquina roda até o retorno; a parada chega por `wait_stop`/`poll`.
    Running,
}

pub struct Client {
    connection: Connection,
    pub symbols: Symbols,
    root: PathBuf,
    elf: PathBuf,
    stopped: bool,
    last_stop: String,
    stop: Option<StopReply>,
    variables: HashMap<String, u64>,
    /// Saída do DbgPrint recebida na sessão inteira.
    console: String,
    /// A parte que a interface ainda não pegou (`take_console`).
    unread_console: String,
    timeout: Duration,
    /// Saída da COM1 (o log do kernel), quando o cliente roda junto com o
    /// teste.
    serial: Option<Arc<Mutex<String>>>,
    breakpoints: Vec<Breakpoint>,
    next_breakpoint: u32,
    run_to: Option<RunTo>,
    /// O pacote `g` da parada corrente, do processador escolhido.
    registers: Option<String>,
    /// Thread do protocolo escolhida por `Hg` (`None` = o dono da parada).
    selected: Option<u64>,
}

impl ReadMemory for Client {
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
        self.read_memory(address, length)
    }
}

impl Client {
    pub fn new(connection: Connection, root: PathBuf, elf: PathBuf) -> Self {
        Self {
            connection,
            symbols: Symbols::default(),
            root,
            elf,
            stopped: false,
            last_stop: String::new(),
            stop: None,
            variables: HashMap::new(),
            console: String::new(),
            unread_console: String::new(),
            timeout: Duration::from_secs(20),
            serial: None,
            breakpoints: Vec::new(),
            next_breakpoint: 0,
            run_to: None,
            registers: None,
            selected: None,
        }
    }

    /// A saída da COM1 para o `wait-serial` do roteiro.
    pub fn set_serial(&mut self, serial: Arc<Mutex<String>>) {
        self.serial = Some(serial);
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// A descrição da última parada.
    pub fn last_stop(&self) -> &str {
        &self.last_stop
    }

    pub fn stop_reply(&self) -> Option<&StopReply> {
        self.stop.as_ref()
    }

    /// A thread do protocolo escolhida (`None` = o dono da parada).
    pub fn selected_thread(&self) -> Option<u64> {
        self.selected
    }

    /// Toda a saída do DbgPrint da sessão.
    pub fn console(&self) -> &str {
        &self.console
    }

    /// A saída do DbgPrint que chegou desde a última chamada.
    pub fn take_console(&mut self) -> String {
        self.collect_console();
        std::mem::take(&mut self.unread_console)
    }

    pub fn breakpoints(&self) -> &[Breakpoint] {
        &self.breakpoints
    }

    fn collect_console(&mut self) {
        let text = self.connection.take_console();
        if !text.is_empty() {
            self.console.push_str(&text);
            self.unread_console.push_str(&text);
        }
    }

    fn request(&mut self, payload: &str) -> Result<String, String> {
        let reply = self.connection.request(payload, self.timeout);
        self.collect_console();
        reply
    }

    fn describe_stop(&mut self, stop: &StopReply) -> String {
        let rip = self.register("rip").ok();
        let location = rip.map(|rip| format!(" em {:#x} {}", rip, self.symbols.describe(rip))).unwrap_or_default();
        let processor = stop.processor().map(|number| format!(" (CPU {number})")).unwrap_or_default();
        format!("parado: {} {}{processor}{location}", stop.signal_name(), stop.reason_text())
    }

    /// Uma resposta de parada chegou. `None` quando o próprio cliente
    /// mandou a máquina seguir (o breakpoint do passo por cima atingido numa
    /// recursão mais funda ou por outra thread).
    fn on_stop(&mut self, packet: String) -> Result<Option<String>, String> {
        let stop = StopReply::parse(&packet).ok_or_else(|| format!("resposta de parada inesperada: {packet:?}"))?;
        self.stopped = true;
        self.registers = None;
        // Uma parada nova é do dono dela: as leituras voltam para ele.
        if self.selected.take().is_some() {
            let _ = self.request("Hg0");
        }
        if let Some(run_to) = self.run_to.take() {
            let at_target = self.register("rip").ok() == Some(run_to.address) && stop.reasons.contains(&Reason::SoftwareBreak);
            if at_target && self.register("rsp").ok() != Some(run_to.expected_rsp) {
                self.run_to = Some(run_to);
                self.resume("c")?;
                return Ok(None);
            }
            if run_to.inserted {
                let _ = self.request(&format!("z0,{:x},1", run_to.address));
            }
        }
        // Módulos carregados desde a última parada entram nos símbolos (a
        // primeira parada, a do attach, ainda não tem o ELF carregado).
        if !self.symbols.modules.is_empty() {
            let _ = self.reload_modules();
        }
        self.last_stop = format!("{} [{}]", self.describe_stop(&stop), packet);
        self.stop = Some(stop);
        Ok(Some(self.last_stop.clone()))
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
        let shown = self.elf.strip_prefix(&self.root).unwrap_or(&self.elf).display().to_string();
        match self.symbols.load_kernel(&self.elf) {
            Ok(count) => output.push_str(&format!("simbolos do kernel: {count} ({shown})\n")),
            Err(error) => output.push_str(&format!("sem os simbolos do kernel: {error}\n")),
        }
        let description = self.on_stop(stop)?.unwrap_or_default();
        output.push_str(&description);
        self.reload_modules()?;
        Ok(output)
    }

    /// Lê a lista de módulos do alvo e os símbolos de cada um.
    fn reload_modules(&mut self) -> Result<(), String> {
        let list: Vec<(u64, u64, String)> = self.loaded_modules()?.into_iter().map(|module| (module.base, module.end, module.path)).collect();
        self.symbols.set_modules(&list, &self.root);
        Ok(())
    }

    fn require_stopped(&self) -> Result<(), String> {
        if self.stopped {
            Ok(())
        } else {
            Err("a maquina esta rodando (use break)".into())
        }
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

    pub fn processes(&mut self) -> Result<Vec<Process>, String> {
        Ok(monitor::processes(&self.monitor("ps")?))
    }

    pub fn threads(&mut self, pid: Option<u64>) -> Result<Vec<Thread>, String> {
        let command = pid.map_or("threads".to_string(), |pid| format!("threads {pid}"));
        Ok(monitor::threads(&self.monitor(&command)?))
    }

    pub fn loaded_modules(&mut self) -> Result<Vec<LoadedModule>, String> {
        Ok(monitor::modules(&self.monitor("lm")?))
    }

    pub fn processors(&mut self) -> Result<Vec<Processor>, String> {
        Ok(monitor::processors(&self.monitor("cpus")?))
    }

    /// Os registradores de uma thread (`monitor context`).
    pub fn thread_context(&mut self, thread: u64) -> Result<ThreadContext, String> {
        let text = self.monitor(&format!("context {thread:x}"))?;
        monitor::thread_context(&text).ok_or_else(|| format!("contexto de {thread:#x}: {}", text.trim()))
    }

    /// Os registradores gerais do processador escolhido.
    pub fn general_registers(&mut self) -> Result<Vec<Value>, String> {
        self.require_stopped()?;
        if self.registers.is_none() {
            let reply = self.request("g")?;
            if reply.starts_with('E') {
                return Err(format!("registradores: {reply}"));
            }
            self.registers = Some(reply);
        }
        registers::parse_general(self.registers.as_deref().unwrap_or(""))
    }

    /// Um registrador pelo nome (os gerais pelo `g`, FS_BASE e GS_BASE pelo
    /// `p`).
    pub fn register(&mut self, name: &str) -> Result<u64, String> {
        let layout = registers::find(name).ok_or_else(|| format!("registrador desconhecido: {name}"))?;
        if layout.number < registers::GENERAL.len() {
            return self.general_registers()?[layout.number].value.ok_or_else(|| format!("{name} indisponivel"));
        }
        self.require_stopped()?;
        let reply = self.request(&format!("p{:x}", layout.number))?;
        if reply.starts_with('E') || reply.is_empty() {
            return Err(format!("{name}: {reply}"));
        }
        registers::parse_little_endian(&reply).ok_or_else(|| format!("{name} indisponivel"))
    }

    /// Grava um registrador do processador escolhido.
    pub fn write_register(&mut self, name: &str, value: u64) -> Result<(), String> {
        self.require_stopped()?;
        let layout = registers::find(name).ok_or_else(|| format!("registrador desconhecido: {name}"))?;
        let reply = self.request(&registers::write_packet(layout, value))?;
        self.registers = None;
        if reply == "OK" {
            Ok(())
        } else {
            Err(format!("{name}: {reply}"))
        }
    }

    pub fn read_memory(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
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

    pub fn write_memory(&mut self, address: u64, bytes: &[u8]) -> Result<(), String> {
        self.require_stopped()?;
        let reply = self.request(&format!("M{:x},{:x}:{}", address, bytes.len(), hex(bytes)))?;
        if reply == "OK" {
            Ok(())
        } else {
            Err(format!("escrita em {address:#x}: {reply}"))
        }
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
        if let Some(name) = text.strip_prefix('%').or_else(|| text.strip_prefix('@')) {
            return self.register(name);
        }
        if let Some(value) = parse_number(text) {
            return Ok(value);
        }
        self.symbols.lookup(text)
    }

    /// Espera a próxima parada (o passo por cima que segue sozinho não
    /// conta).
    pub fn wait_stop(&mut self, timeout: Duration) -> Result<String, String> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("tempo esgotado esperando a parada (a maquina segue rodando; use break)".into());
            }
            if let Some(stop) = self.poll(remaining.min(Duration::from_millis(500)))? {
                return Ok(stop);
            }
        }
    }

    /// Com a máquina rodando, recolhe a saída do DbgPrint e uma parada que
    /// tenha chegado dentro do prazo.
    pub fn poll(&mut self, timeout: Duration) -> Result<Option<String>, String> {
        if self.stopped {
            return Ok(None);
        }
        match self.connection.receive(timeout) {
            Ok(packet) => {
                self.collect_console();
                self.on_stop(packet)
            }
            Err(error) if is_timeout(&error) => {
                self.collect_console();
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn resume(&mut self, packet: &str) -> Result<(), String> {
        self.require_stopped()?;
        self.connection.send(packet, self.timeout)?;
        self.stopped = false;
        self.registers = None;
        Ok(())
    }

    /// Continua.
    pub fn go(&mut self) -> Result<(), String> {
        self.resume("c")
    }

    /// Pede a parada (0x03) sem esperar a resposta.
    pub fn interrupt(&mut self) -> Result<(), String> {
        if self.stopped {
            return Ok(());
        }
        self.connection.interrupt()
    }

    /// Pede a parada e espera.
    pub fn break_in(&mut self, timeout: Duration) -> Result<String, String> {
        if self.stopped {
            return Ok(self.last_stop.clone());
        }
        self.connection.interrupt()?;
        self.wait_stop(timeout)
    }

    /// Um passo no processador da parada.
    pub fn step(&mut self) -> Result<String, String> {
        self.resume("s")?;
        self.wait_stop(self.timeout)
    }

    /// Passo por cima: num `call`, um breakpoint temporário na instrução
    /// seguinte e a máquina segue; em qualquer outra instrução, um passo.
    pub fn step_over(&mut self) -> Result<Resumed, String> {
        let rip = self.register("rip")?;
        let rsp = self.register("rsp")?;
        let code = self.read_memory(rip, 16).unwrap_or_default();
        match x86::call_length(&code) {
            Some(length) => {
                self.run_to(rip + length as u64, rsp)?;
                Ok(Resumed::Running)
            }
            None => self.step().map(Resumed::Stopped),
        }
    }

    /// Passo para fora: até o endereço de retorno da função corrente (pelo
    /// prólogo ou pelo frame pointer).
    pub fn step_out(&mut self) -> Result<Resumed, String> {
        let rip = self.register("rip")?;
        let rsp = self.register("rsp")?;
        let rbp = self.register("rbp")?;
        let slot = unwind::return_slot(self, rip, rsp, rbp);
        let address = self.read_integer(slot, 8)?;
        if address == 0 {
            return Err(format!("sem endereco de retorno em {slot:#x}"));
        }
        self.run_to(address, slot + 8)?;
        Ok(Resumed::Running)
    }

    fn run_to(&mut self, address: u64, expected_rsp: u64) -> Result<(), String> {
        let existing = self.breakpoints.iter().any(|breakpoint| breakpoint.enabled && breakpoint.kind == BreakpointKind::Software && breakpoint.address == address);
        if !existing {
            let reply = self.request(&format!("Z0,{address:x},1"))?;
            if reply != "OK" {
                return Err(format!("breakpoint temporario em {address:#x}: {reply}"));
            }
        }
        self.run_to = Some(RunTo { address, inserted: !existing, expected_rsp });
        if let Err(error) = self.resume("c") {
            if let Some(run_to) = self.run_to.take() {
                if run_to.inserted {
                    let _ = self.request(&format!("z0,{address:x},1"));
                }
            }
            return Err(error);
        }
        Ok(())
    }

    fn insert(&mut self, kind: BreakpointKind, address: u64, length: u64, insert: bool) -> Result<(), String> {
        let reply = self.request(&format!("{}{},{:x},{:x}", if insert { 'Z' } else { 'z' }, kind.packet_type(), address, length))?;
        match reply.as_str() {
            "OK" => Ok(()),
            "" => Err("tipo de breakpoint sem suporte no alvo".into()),
            other => Err(format!("breakpoint em {address:#x}: {other}")),
        }
    }

    /// Arma um breakpoint (ou religa o mesmo, se já existe).
    pub fn add_breakpoint(&mut self, kind: BreakpointKind, expression: &str, length: u64) -> Result<Breakpoint, String> {
        self.require_stopped()?;
        let address = self.evaluate(expression)?;
        if let Some(index) = self.breakpoints.iter().position(|breakpoint| breakpoint.kind == kind && breakpoint.address == address) {
            if !self.breakpoints[index].enabled {
                self.insert(kind, address, self.breakpoints[index].length, true)?;
                self.breakpoints[index].enabled = true;
            }
            return Ok(self.breakpoints[index].clone());
        }
        self.insert(kind, address, length, true)?;
        let breakpoint = Breakpoint { id: self.next_breakpoint, kind, address, length, enabled: true, expression: expression.trim().to_string() };
        self.next_breakpoint += 1;
        self.breakpoints.push(breakpoint.clone());
        Ok(breakpoint)
    }

    /// Tira um breakpoint do alvo e da lista.
    pub fn remove_breakpoint(&mut self, id: u32) -> Result<Breakpoint, String> {
        self.require_stopped()?;
        let index = self.breakpoints.iter().position(|breakpoint| breakpoint.id == id).ok_or_else(|| format!("breakpoint {id} nao existe"))?;
        let breakpoint = self.breakpoints[index].clone();
        if breakpoint.enabled {
            self.insert(breakpoint.kind, breakpoint.address, breakpoint.length, false)?;
        }
        self.breakpoints.remove(index);
        Ok(breakpoint)
    }

    /// Desliga (tira do alvo, fica na lista) ou religa.
    pub fn set_breakpoint_enabled(&mut self, id: u32, enabled: bool) -> Result<(), String> {
        self.require_stopped()?;
        let index = self.breakpoints.iter().position(|breakpoint| breakpoint.id == id).ok_or_else(|| format!("breakpoint {id} nao existe"))?;
        let breakpoint = self.breakpoints[index].clone();
        if breakpoint.enabled != enabled {
            self.insert(breakpoint.kind, breakpoint.address, breakpoint.length, enabled)?;
            self.breakpoints[index].enabled = enabled;
        }
        Ok(())
    }

    /// Liga ou tira o breakpoint de software num endereço (o clique na
    /// margem da desmontagem); `true` se ficou armado.
    pub fn toggle_breakpoint(&mut self, address: u64) -> Result<bool, String> {
        if let Some(breakpoint) = self.breakpoints.iter().find(|breakpoint| breakpoint.kind == BreakpointKind::Software && breakpoint.address == address) {
            let id = breakpoint.id;
            self.remove_breakpoint(id)?;
            return Ok(false);
        }
        let expression = self.symbols.name_at(address).unwrap_or_else(|| format!("{address:#x}"));
        let breakpoint = self.add_breakpoint(BreakpointKind::Software, &format!("{address:#x}"), 1)?;
        if let Some(entry) = self.breakpoints.iter_mut().find(|entry| entry.id == breakpoint.id) {
            entry.expression = expression;
        }
        Ok(true)
    }

    /// `bp`/`hbp`/`watch` do prompt.
    fn breakpoint_command(&mut self, kind: BreakpointKind, target: &str, length: u64) -> Result<String, String> {
        let breakpoint = self.add_breakpoint(kind, target, length)?;
        Ok(format!("armado {:#x} {} (#{})", breakpoint.address, self.symbols.describe(breakpoint.address), breakpoint.id))
    }

    /// `bc`/`hbc`/`unwatch` do prompt: pelo número (`#n`) ou pelo endereço;
    /// um endereço que só o alvo conhece (armado por outro host) também sai.
    fn clear_command(&mut self, kind: BreakpointKind, target: &str, length: u64) -> Result<String, String> {
        self.require_stopped()?;
        let id = match target.strip_prefix('#').and_then(parse_number) {
            Some(id) => id as u32,
            None => {
                let address = self.evaluate(target)?;
                match self.breakpoints.iter().find(|breakpoint| breakpoint.kind == kind && breakpoint.address == address) {
                    Some(breakpoint) => breakpoint.id,
                    None => {
                        self.insert(kind, address, length, false)?;
                        return Ok(format!("removido {:#x} {}", address, self.symbols.describe(address)));
                    }
                }
            }
        };
        let breakpoint = self.remove_breakpoint(id)?;
        Ok(format!("removido {:#x} {}", breakpoint.address, self.symbols.describe(breakpoint.address)))
    }

    fn breakpoint_list(&mut self) -> Result<String, String> {
        let mut output = String::new();
        for breakpoint in &self.breakpoints {
            output.push_str(&format!(
                "#{:<3} {} {:<8} {:#018x} {} ({})\n",
                breakpoint.id,
                if breakpoint.enabled { "ligado   " } else { "desligado" },
                breakpoint.kind.name(),
                breakpoint.address,
                self.symbols.describe(breakpoint.address),
                breakpoint.expression
            ));
        }
        output.push_str("armados no alvo:\n");
        output.push_str(&self.monitor("bl")?);
        Ok(output)
    }

    /// A pilha do processador escolhido pelos frame pointers.
    pub fn backtrace(&mut self, limit: usize) -> Result<Vec<Frame>, String> {
        let rip = self.register("rip")?;
        let rsp = self.register("rsp")?;
        let rbp = self.register("rbp")?;
        Ok(unwind::unwind(self, rip, rsp, rbp, limit))
    }

    /// A pilha de uma thread pelo `monitor context` (a de uma thread fora
    /// da CPU começa no quadro de troca: o RIP já é um retorno).
    pub fn thread_backtrace(&mut self, thread: u64, limit: usize) -> Result<(ThreadContext, Vec<Frame>), String> {
        let context = self.thread_context(thread)?;
        let (Some(rip), Some(rbp)) = (context.register("rip"), context.register("rbp")) else { return Err(format!("contexto de {thread:#x}: {}", context.header)) };
        let frames = match (context.processor, context.register("rsp")) {
            (Some(_), Some(rsp)) => unwind::unwind(self, rip, rsp, rbp, limit),
            _ => unwind::follow_chain(self, vec![Frame { address: rip, is_return: true }], rbp, limit),
        };
        Ok((context, frames))
    }

    /// `#n endereço símbolo` por quadro.
    pub fn format_frames(&self, frames: &[Frame]) -> String {
        let mut output = String::new();
        for (depth, frame) in frames.iter().enumerate() {
            output.push_str(&format!("#{depth:<2} {:#018x} {}\n", frame.address, self.frame_name(frame)));
        }
        output
    }

    /// O símbolo de um quadro: um endereço de retorno pode cair logo depois
    /// do fim da função chamadora (chamada que não volta), então o símbolo é
    /// o do byte de antes.
    pub fn frame_name(&self, frame: &Frame) -> String {
        if frame.is_return {
            self.symbols.describe_return(frame.address)
        } else {
            self.symbols.describe(frame.address)
        }
    }

    fn format_registers(&mut self) -> Result<String, String> {
        let values = self.general_registers()?;
        let mut output = String::new();
        for (index, value) in values.iter().enumerate() {
            output.push_str(&format!("{:>6}={:#018x}", value.layout.name, value.value.unwrap_or(0)));
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

    /// Escolhe o processador das leituras e gravações (thread do protocolo
    /// = processador + 1).
    pub fn select_thread(&mut self, thread: u64) -> Result<(), String> {
        self.require_stopped()?;
        let reply = self.request(&format!("Hg{thread:x}"))?;
        if reply != "OK" {
            return Err(format!("thread {thread}: {reply}"));
        }
        self.registers = None;
        self.selected = Some(thread);
        Ok(())
    }

    /// Os processadores parados (as threads do protocolo).
    pub fn stopped_threads(&mut self) -> Result<Vec<u64>, String> {
        self.require_stopped()?;
        let mut threads = Vec::new();
        let mut reply = self.request("qfThreadInfo")?;
        while let Some(list) = reply.strip_prefix('m') {
            threads.extend(list.split(',').filter_map(|thread| u64::from_str_radix(thread, 16).ok()));
            reply = self.request("qsThreadInfo")?;
        }
        Ok(threads)
    }

    /// Desliga a sessão (parando antes, se preciso): a máquina segue sem
    /// host anexado e o alvo tira os breakpoints.
    pub fn detach(&mut self) -> Result<String, String> {
        if !self.stopped {
            self.connection.interrupt()?;
            self.wait_stop(Duration::from_secs(60))?;
        }
        let reply = self.request("D")?;
        self.stopped = false;
        self.breakpoints.clear();
        Ok(format!("desligado ({reply})"))
    }

    /// Executa um comando; devolve a saída.
    pub fn execute(&mut self, line: &str) -> Result<String, String> {
        let line = line.trim();
        let (command, rest) = line.split_once(char::is_whitespace).map_or((line, ""), |(command, rest)| (command, rest.trim()));
        let words: Vec<&str> = rest.split_whitespace().collect();
        let count = || words.first().and_then(|text| parse_number(text)).unwrap_or(1);
        match command {
            "" => Ok(String::new()),
            "attach" => self.attach(Duration::from_secs(120)),
            "break" | "halt" => self.break_in(Duration::from_secs(60)),
            "c" | "g" | "continue" => {
                self.go()?;
                Ok("rodando".into())
            }
            "wait-stop" => {
                let milliseconds = words.first().and_then(|text| parse_number(text)).unwrap_or(120_000);
                self.wait_stop(Duration::from_millis(milliseconds))
            }
            "s" | "t" | "step" => {
                let mut output = String::new();
                for _ in 0..count() {
                    output = self.step()?;
                }
                Ok(output)
            }
            "p" => {
                let mut output = String::new();
                for _ in 0..count() {
                    output = match self.step_over()? {
                        Resumed::Stopped(text) => text,
                        Resumed::Running => self.wait_stop(RUN_TO_WAIT)?,
                    };
                }
                Ok(output)
            }
            "gu" => match self.step_out()? {
                Resumed::Stopped(text) => Ok(text),
                Resumed::Running => self.wait_stop(RUN_TO_WAIT),
            },
            "regs" => self.format_registers(),
            "r" if rest.contains('=') => {
                let (name, expression) = rest.split_once('=').unwrap_or_default();
                let value = self.evaluate(expression)?;
                self.write_register(name.trim(), value)?;
                Ok(format!("{}={value:#x}", name.trim()))
            }
            "r" if !rest.is_empty() => {
                let value = self.register(rest)?;
                Ok(format!("{rest}={value:#x}"))
            }
            "r" => self.format_registers(),
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
            "bp" => self.breakpoint_command(BreakpointKind::Software, rest, 1),
            "bc" if rest == "all" => {
                let list = self.monitor("bl")?;
                for line in list.lines() {
                    if let Some(address) = line.strip_prefix("software").and_then(|rest| parse_number(rest.trim())) {
                        self.request(&format!("z0,{address:x},1"))?;
                    }
                }
                self.breakpoints.retain(|breakpoint| breakpoint.kind != BreakpointKind::Software);
                Ok("breakpoints de software removidos".into())
            }
            "bc" => self.clear_command(BreakpointKind::Software, rest, 1),
            "hbp" => self.breakpoint_command(BreakpointKind::Hardware, rest, 1),
            "hbc" => self.clear_command(BreakpointKind::Hardware, rest, 1),
            "watch" | "unwatch" => {
                let target = words.first().ok_or("uso: watch <endereco> <bytes> [w|a]")?;
                let length = words.get(1).and_then(|text| parse_number(text)).unwrap_or(8);
                let kind = if words.get(2) == Some(&"a") { BreakpointKind::Access } else { BreakpointKind::Write };
                if command == "watch" {
                    self.breakpoint_command(kind, target, length)
                } else {
                    self.clear_command(kind, target, length)
                }
            }
            "bd" | "be" => {
                let id = parse_number(rest.trim_start_matches('#')).ok_or("uso: bd|be <n>")? as u32;
                self.set_breakpoint_enabled(id, command == "be")?;
                Ok(format!("breakpoint {id} {}", if command == "be" { "ligado" } else { "desligado" }))
            }
            "bl" => self.breakpoint_list(),
            "bt" => {
                let limit = words.first().and_then(|text| parse_number(text)).unwrap_or(32) as usize;
                let frames = self.backtrace(limit)?;
                Ok(self.format_frames(&frames))
            }
            "context" => {
                let thread = self.evaluate(rest)?;
                self.monitor(&format!("context {thread:x}"))
            }
            "btt" => {
                let thread = self.evaluate(words.first().ok_or("uso: btt <ethread> [n]")?)?;
                let limit = words.get(1).and_then(|text| parse_number(text)).unwrap_or(32) as usize;
                let (context, frames) = self.thread_backtrace(thread, limit)?;
                Ok(format!("{}\n{}", context.header, self.format_frames(&frames)))
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
                self.select_thread(thread)?;
                Ok(format!("thread {thread} (CPU {})", thread.saturating_sub(1)))
            }
            "cpulist" => {
                let threads = self.stopped_threads()?;
                Ok(format!("processadores parados: {}", threads.iter().map(|thread| thread.to_string()).collect::<Vec<_>>().join(",")))
            }
            "ps" | "threads" | "lm" | "cpus" | "irql" | "obj" | "log" | "bugcheck" | "kd" => {
                let text = self.monitor(line)?;
                if command == "lm" {
                    self.reload_modules()?;
                }
                Ok(text)
            }
            "monitor" => self.monitor(rest),
            "modules" => Ok(self.symbols.modules.iter().map(|module| format!("{:#018x} {:#018x} {:<16} {} simbolos ({})\n", module.base, module.end, module.name, module.symbols.len(), module.source)).collect()),
            "detach" => self.detach(),
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
