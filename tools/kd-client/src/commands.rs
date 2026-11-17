//! Os comandos de texto da sessão: o prompt do `cargo xtask debug`, o
//! painel de comandos do `opennt-dbg` e os roteiros de teste.
//!
//! ```text
//! attach                     conecta a sessao (o alvo para) e carrega os simbolos
//! break                      pede a parada (0x03) e espera
//! c | g | continue           continua (no roteiro, volta sem esperar; use wait-stop)
//! wait-stop [ms]             espera a proxima parada
//! s | t | step [n]           um passo (n passos) no processador da parada
//! p [n]                      passo por cima de um call (breakpoint temporario no retorno)
//! gu                         ate o retorno da funcao corrente
//! regs | r                   registradores do processador escolhido; r <reg>=<expr> grava
//! x <expr> [bytes]           memoria em hexadecimal
//! db|dw|dd|dq <expr> [L<n>]  memoria em bytes, words, dwords ou qwords
//! da|du <expr>               cadeia ASCII ou UTF-16
//! write <expr> <hex>         grava bytes
//! poke <1|2|4|8> <expr> <valor>   grava um inteiro
//! bp <expr> [N] [/w "cond"]  breakpoint de software, a partir do N-esimo acerto, condicional
//! bu <expr>                  breakpoint adiado (o simbolo de um modulo que ainda vai carregar)
//! bc <expr|#n|all>           tira breakpoints
//! hbp | hbc <expr>           breakpoint de hardware (DR0-DR3)
//! ba <e|w|r><1|2|4|8> <expr> breakpoint de hardware de execucao, escrita ou acesso
//! watch | unwatch <expr> <bytes> [w|a]   vigia de escrita ou de acesso
//! sxe | sxd ld:<modulo>      para (ou nao) quando o modulo carregar
//! bd | be <n>                desliga / religa o breakpoint n (sem esquece-lo)
//! bl                         breakpoints do cliente e os armados no alvo
//! .bpsave | .bpload <arq>    grava ou recria os breakpoints
//! bt [n] | k [n]             pilha (.pdata nos binarios da Microsoft, frame pointers no OpenNT)
//! ? <expr> | sym <expr> | ln <expr>   valor, simbolo e simbolo mais proximo
//! addr <nome>                nome -> endereco
//! dt <tipo> [expr]           struct do NT campo a campo (tipos do PDB do ntoskrnl)
//! thread <n>                 processador das leituras (thread n = CPU n-1)
//! context <ethread>          registradores de uma thread (fora da CPU: quadro de troca)
//! btt <ethread> [n]          pilha de uma thread pelo quadro de troca
//! cpulist                    processadores parados (threads do protocolo)
//! modules | lmv <modulo> | .reload    modulos com simbolos, detalhe de um, recarregar
//! ps | threads [pid] | lm | cpus | irql | obj <caminho> | log [bytes] | bugcheck | kd
//! !process [pid|eprocess] | !thread [ethread] | !irp <expr> | !devobj <expr|caminho>
//! !drvobj <expr|caminho|nome> | !object <caminho> | !handle <pid> <handle> | !analyze
//! trace [n] [ate <expr>] [ret] [over] [entra|sai <mod>] [pula <mod>] [vigia <expr> [bytes]]
//! trace show [de] [n] | trace tree [n] | trace save <arq> | trace diff <arq> | trace ref | trace status
//! monitor <texto>            comando do OpenNT no alvo
//! .process [pid|eprocess|0]  processo das leituras e dos breakpoints de usuario
//! lmu                        modulos de usuario do processo escolhido (PEB.Ldr e VAD)
//! handles | vad | uthreads <pid> [i]   handles, regioes e threads de usuario de um processo
//! ustack <tid> [n]           pilha de usuario de uma thread do processo escolhido
//! kmap | events | uex [on|off]   faixas do sistema, ultimos eventos, excecoes do anel 3
//! sxe | sxd cpr[:nome] | epr[:nome] | ct[:pid] | et[:pid] | ld:processo!dll   eventos
//! bp <expr> /log "texto {expr}" | /cmd "r; k" | /g grupo   log, comandos de parada, grupo
//! bgd | bge <grupo>          desliga / religa um grupo de breakpoints
//! bar <w|a> <expr> <bytes>   vigia uma faixa com ate quatro comparadores
//! detach | quit
//! ```
//!
//! Roteiro (`--script`): uma linha por comando, `#` comenta, e as
//! conferências `expect <texto>` (a saída do comando anterior contém o
//! texto), `expect-stop <texto>` (a última parada), `expect-console
//! <texto>` (a saída do DbgPrint recebida), `expect-eq <expr> <expr>`,
//! `save <nome> <expr>` (vira `$nome`), `save-word <nome> <texto> <coluna> [ocorrência]`
//! (um número da saída anterior), `wait-serial <texto>` (o texto no log da
//! COM1), `echo <texto>` e `sleep <ms>`.

use std::time::{Duration, Instant};

use super::client::{BreakpointKind, BreakpointRequest, Client, Resumed, RUN_TO_WAIT};
use super::registers;
use super::rsp::unhex;
use super::trace::{self, Source, Trace};
use super::types::{self, Kind};
use super::parse_number;

const HELP: &str = "attach | break | c/g | wait-stop [ms] | s/t [n] | p [n] | gu | regs | r [<reg>[=<expr>]] | rx (x87, SSE, YMM, DR)
x <expr> [bytes] | db/dw/dd/dq <expr> [L<n>] | da/du <expr> | write <expr> <hex> | poke <1|2|4|8> <expr> <valor>
bp <expr> [N] [/w \"cond\"] | bu <expr> | bc <expr|#n|all> | bd/be <n> | bl | hbp/hbc <expr>
ba <e|w|r><1|2|4|8> <expr> | watch/unwatch <expr> <bytes> [w|a] | sxe/sxd ld:<modulo> | .bpsave/.bpload <arq>
bpm <a|w|x> <expr> [bytes] | bpmc <expr> (breakpoint de memoria por pagina, no processo escolhido)
bt [n] | k [n] | btt <ethread> [n] | context <ethread> | ? <expr> | sym <expr> | ln <expr> | addr <nome>
dt <tipo> [expr] | thread <n> | cpulist | modules | lmv <modulo> | .reload
ps | threads [pid] | lm | cpus | irql | obj <caminho> | log [bytes] | bugcheck | kd | monitor <texto>
!process [pid|eprocess] | !thread [ethread] | !irp <expr> | !devobj <expr|caminho> | !drvobj <expr|caminho>
!object <caminho> | !handle <pid> <handle> | !analyze
.process [pid|eprocess|0] | lmu | handles/vad/uthreads <pid> [i] | ustack <tid> [n] | kmap | events | uex [on|off]
sxe cpr[:nome]|epr[:nome]|ct[:pid]|et[:pid]|ld:proc!dll | bp <expr> /log \"txt {expr}\" /cmd \"r\" /g grupo | bgd/bge <grupo> | bar <w|a> <expr> <bytes>
trace [n] [ate <expr>] [ret] [over] [entra|sai <mod>] [pula <mod>] [vigia <expr> [bytes]]
trace show [de] [n] | trace tree [n] | trace save <arq> | trace diff <arq> | trace ref | trace status
detach | quit
expressoes: 0x.., decimais, $nome, @reg, simbolos, poi() by() wo() dwo() [..], operadores do C, ((_IRP*)x)->Campo
";

/// O pedido de um rastro (o `trace` do prompt e o painel Rastro).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceOptions {
    /// Instruções no máximo.
    pub count: u64,
    /// Até este endereço ou símbolo (vazio = sem).
    pub until: String,
    /// Até a função corrente retornar.
    pub until_return: bool,
    /// Só o nível da função corrente (as chamadas executam sem gravar).
    pub over_calls: bool,
    /// Para quando entrar neste módulo.
    pub enter_module: String,
    /// Para quando sair deste módulo.
    pub leave_module: String,
    /// Módulos que executam sem gravar.
    pub skip_modules: Vec<String>,
    /// Uma expressão de memória lida a cada passo (o endereço) e o tamanho.
    pub watch: String,
    pub watch_size: u64,
    /// Registros no máximo (para de pedir lotes).
    pub max_records: usize,
}

impl Default for TraceOptions {
    fn default() -> Self {
        Self { count: 1000, until: String::new(), until_return: false, over_calls: false, enter_module: String::new(), leave_module: String::new(), skip_modules: Vec::new(), watch: String::new(), watch_size: 8, max_records: 2_000_000 }
    }
}

impl TraceOptions {
    /// Lê as palavras do `trace` do prompt.
    pub fn parse(words: &[&str]) -> Result<Self, String> {
        let mut options = TraceOptions::default();
        let mut index = 0;
        let next = |index: &mut usize, what: &str| -> Result<String, String> {
            *index += 1;
            words.get(*index).map(|word| word.to_string()).ok_or_else(|| format!("trace: falta {what}"))
        };
        while index < words.len() {
            match words[index] {
                "ate" | "until" => options.until = next(&mut index, "o endereco")?,
                "ret" | "retorno" => options.until_return = true,
                "over" | "por-cima" => options.over_calls = true,
                "entra" | "enter" => options.enter_module = next(&mut index, "o modulo")?,
                "sai" | "leave" => options.leave_module = next(&mut index, "o modulo")?,
                "pula" | "skip" => options.skip_modules.push(next(&mut index, "o modulo")?),
                "vigia" | "watch" => {
                    options.watch = next(&mut index, "a expressao")?;
                    if let Some(size) = words.get(index + 1).and_then(|word| parse_number(word)).filter(|size| matches!(size, 1 | 2 | 4 | 8)) {
                        options.watch_size = size;
                        index += 1;
                    }
                }
                word => options.count = parse_number(word).ok_or_else(|| format!("trace: palavra inesperada {word:?}"))?,
            }
            index += 1;
        }
        if options.until_return || !options.until.is_empty() || !options.enter_module.is_empty() || !options.leave_module.is_empty() {
            // Com uma condição de fim, o número vira só o limite de segurança.
            if !words.iter().any(|word| parse_number(word).is_some()) {
                options.count = 1_000_000;
            }
        }
        Ok(options)
    }
}

/// Divide em duas expressões no primeiro espaço fora de colchetes.
fn split_two(text: &str) -> Option<(&str, &str)> {
    let mut depth = 0;
    for (index, character) in text.char_indices() {
        match character {
            '[' | '(' => depth += 1,
            ']' | ')' => depth -= 1,
            ' ' if depth == 0 => return Some((&text[..index], text[index + 1..].trim())),
            _ => {}
        }
    }
    None
}

/// `L<n>` de um comando de memória.
/// As opções de texto de um `bp`: `/log "..."`, `/cmd "..."` e `/g nome`.
#[derive(Default)]
struct BreakpointOptions {
    log: String,
    command: String,
    group: String,
}

/// Tira as opções `/log`, `/cmd` e `/g` do texto de um `bp` (o resto volta).
fn breakpoint_options(text: &str) -> (String, BreakpointOptions) {
    let mut options = BreakpointOptions::default();
    let mut rest = text.to_string();
    for (key, slot) in [("/log", 0), ("/cmd", 1), ("/g", 2)] {
        let Some(start) = rest.find(&format!("{key} ")) else { continue };
        let after = rest[start + key.len()..].trim_start();
        let (value, consumed) = if let Some(quoted) = after.strip_prefix('"') {
            match quoted.find('"') {
                Some(end) => (quoted[..end].to_string(), rest.len() - after.len() + end + 2),
                None => (quoted.to_string(), rest.len()),
            }
        } else {
            let end = after.find(char::is_whitespace).unwrap_or(after.len());
            (after[..end].to_string(), rest.len() - after.len() + end)
        };
        match slot {
            0 => options.log = value,
            1 => options.command = value,
            _ => options.group = value,
        }
        rest = format!("{} {}", rest[..start].trim_end(), rest[consumed.min(rest.len())..].trim_start()).trim().to_string();
    }
    (rest, options)
}

/// `sxe` de evento (processo, thread ou DLL de usuário), não de módulo do
/// kernel.
fn is_event_filter(text: &str) -> bool {
    let code = text.trim().split(':').next().unwrap_or("").to_ascii_lowercase();
    matches!(code.as_str(), "cpr" | "epr" | "ct" | "et") || (code == "ld" && text.contains('!'))
}

fn length_argument(words: &[&str]) -> Option<u64> {
    words.iter().find_map(|word| word.strip_prefix('L').or_else(|| word.strip_prefix('l')).and_then(|count| parse_number(count).or_else(|| u64::from_str_radix(count, 16).ok())))
}

impl Client {
    fn breakpoint_command(&mut self, request: BreakpointRequest) -> Result<String, String> {
        let breakpoint = self.add_breakpoint_with(&request)?;
        if breakpoint.kind == BreakpointKind::Module {
            return Ok(format!("para quando {} carregar (#{})", breakpoint.expression, breakpoint.id));
        }
        if breakpoint.kind == BreakpointKind::Event {
            return Ok(format!("para no evento {} (#{})", breakpoint.expression, breakpoint.id));
        }
        if breakpoint.pending {
            return Ok(format!("adiado: {} (#{}), armado quando o modulo carregar", breakpoint.expression, breakpoint.id));
        }
        let mut text = format!("armado {:#x} {} (#{})", breakpoint.address, self.symbols.describe(breakpoint.address), breakpoint.id);
        if breakpoint.pass_count > 1 {
            text.push_str(&format!(" a partir do acerto {}", breakpoint.pass_count));
        }
        if !breakpoint.condition.is_empty() {
            text.push_str(&format!(" se {}", breakpoint.condition));
        }
        if !breakpoint.log.is_empty() {
            text.push_str(&format!(" log \"{}\"", breakpoint.log));
        }
        if !breakpoint.command.is_empty() {
            text.push_str(&format!(" comandos \"{}\"", breakpoint.command));
        }
        if !breakpoint.group.is_empty() {
            text.push_str(&format!(" grupo {}", breakpoint.group));
        }
        if breakpoint.process != 0 {
            text.push_str(&format!(" processo {:#x}", breakpoint.process));
        }
        Ok(text)
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
                        let reply = self.request(&format!("z{},{:x},{:x}", match kind {
                            BreakpointKind::Hardware => 1,
                            BreakpointKind::Write => 2,
                            BreakpointKind::Access => 4,
                            _ => 0,
                        }, address, length))?;
                        if reply != "OK" {
                            return Err(format!("breakpoint em {address:#x}: {reply}"));
                        }
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
            let place = if breakpoint.kind == BreakpointKind::Module {
                format!("ld:{}", breakpoint.expression)
            } else if breakpoint.kind == BreakpointKind::Event {
                format!("evento {}", breakpoint.expression)
            } else if breakpoint.pending {
                "(adiado)".to_string()
            } else {
                format!("{:#018x} {}", breakpoint.address, self.symbols.describe(breakpoint.address))
            };
            output.push_str(&format!("#{:<3} {} {:<8} {} ({})", breakpoint.id, if breakpoint.enabled { "ligado   " } else { "desligado" }, breakpoint.kind.name(), place, breakpoint.expression));
            if breakpoint.pass_count > 1 {
                output.push_str(&format!(" a partir do acerto {}", breakpoint.pass_count));
            }
            if !breakpoint.condition.is_empty() {
                output.push_str(&format!(" se {}", breakpoint.condition));
            }
            if !breakpoint.log.is_empty() {
                output.push_str(&format!(" log \"{}\"", breakpoint.log));
            }
            if !breakpoint.command.is_empty() {
                output.push_str(&format!(" comandos \"{}\"", breakpoint.command));
            }
            if !breakpoint.group.is_empty() {
                output.push_str(&format!(" grupo {}", breakpoint.group));
            }
            if breakpoint.process != 0 {
                output.push_str(&format!(" processo {:#x}", breakpoint.process));
            }
            output.push_str(&format!(" acertos {}\n", breakpoint.hits));
        }
        output.push_str("armados no alvo:\n");
        output.push_str(&self.monitor("bl")?);
        Ok(output)
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

    /// `dw`/`dd`/`dq`: unidades de `size` bytes, 16 bytes por linha.
    fn dump_units(&mut self, address: u64, size: usize, count: usize) -> Result<String, String> {
        let bytes = self.read_memory(address, size * count)?;
        let mut output = String::new();
        for (row, chunk) in bytes.chunks(16).enumerate() {
            output.push_str(&format!("{:#018x} ", address + row as u64 * 16));
            for unit in chunk.chunks(size) {
                let mut raw = [0u8; 8];
                raw[..unit.len()].copy_from_slice(unit);
                output.push_str(&format!(" {:0width$x}", u64::from_le_bytes(raw), width = size * 2));
            }
            output.push('\n');
        }
        Ok(output)
    }

    fn module_detail(&mut self, name: &str) -> Result<String, String> {
        let module = self.symbols.module_named(name).cloned().ok_or_else(|| format!("modulo {name} nao carregado"))?;
        let mut output = format!("{} ({})\n  caminho   {}\n  base      {:#018x}\n  fim       {:#018x}\n  tamanho   {:#x}\n  simbolos  {} ({})\n", module.name, module.file_name, module.path, module.base, module.end, module.end - module.base, module.symbols.len(), module.source);
        if let Some(image) = &module.image {
            output.push_str(&format!("  data      {:#010x}\n  checksum  {:#010x}\n  entrada   {:#018x}\n", image.header.time_date_stamp, image.header.checksum, module.base + image.header.entry_point as u64));
            if let Some((guid, age, pdb)) = image.rsds() {
                output.push_str(&format!("  PDB       {pdb} {}{age:X}\n", super::pe::guid_text(&guid)));
            }
            output.push_str(&format!("  secoes    {}\n", image.sections.iter().map(|section| section.name.as_str()).collect::<Vec<_>>().join(" ")));
        }
        if let Some(table) = &module.unwind {
            output.push_str(&format!("  .pdata    {} funcoes\n", table.functions.len()));
        }
        Ok(output)
    }

    /// `dt <tipo> [expr]`.
    fn display_type(&mut self, rest: &str) -> Result<String, String> {
        let (type_name, address) = match rest.split_once(char::is_whitespace) {
            Some((type_name, expression)) => (type_name, Some(self.evaluate(expression.trim())?)),
            None => (rest, None),
        };
        if type_name.is_empty() {
            return Err("uso: dt <tipo> [expr]".into());
        }
        let database = self.type_database().ok_or_else(|| self.types_note.clone())?;
        let index = database.find(type_name).ok_or_else(|| format!("tipo {type_name} nao encontrado no PDB do ntoskrnl"))?;
        let mut output = format!("{} ({:#x} bytes)", database.name(index), database.size(index));
        match address {
            Some(address) => {
                output.push_str(&format!(" em {address:#x}\n"));
                for field in self.typed_fields(index, address)? {
                    output.push_str(&format!("   +{:#05x} {:<28} : {:<24} {}\n", field.offset, field.name, field.type_name, field.value));
                }
            }
            None => {
                output.push('\n');
                for member in database.members(index) {
                    output.push_str(&format!("   +{:#05x} {:<28} : {}\n", member.offset, member.name, database.name(member.ty)));
                }
            }
        }
        Ok(output)
    }

    /// Endereço ou caminho de objeto para uma consulta do NT.
    fn object_argument(&mut self, argument: &str, directory: &str) -> Result<String, String> {
        let argument = argument.trim();
        if argument.starts_with('\\') {
            return Ok(argument.to_string());
        }
        match self.evaluate(argument) {
            Ok(address) => Ok(format!("{address:#x}")),
            Err(error) if !directory.is_empty() && argument.chars().all(|character| character.is_ascii_alphanumeric() || character == '_') => {
                let _ = error;
                Ok(format!("{directory}{argument}"))
            }
            Err(error) => Err(error),
        }
    }

    /// As consultas do NT pelo depurador do alvo (`!process`, `!irp`...).
    pub fn nt_view(&mut self, command: &str, argument: &str) -> Result<String, String> {
        let argument = argument.trim();
        let query = match command {
            "process" => {
                if argument.is_empty() {
                    "process".to_string()
                } else {
                    format!("process {:#x}", self.evaluate(argument)?)
                }
            }
            "thread" => {
                if argument.is_empty() {
                    "thread".to_string()
                } else {
                    format!("thread {:#x}", self.evaluate(argument)?)
                }
            }
            "irp" => format!("irp {:#x}", self.evaluate(argument)?),
            "devobj" => format!("devobj {}", self.object_argument(argument, "\\Device\\")?),
            "drvobj" => format!("drvobj {}", self.object_argument(argument, "\\Driver\\")?),
            "handle" => {
                let (process, handle) = split_two(argument).ok_or("uso: !handle <pid|eprocess> <handle>")?;
                format!("handle {:#x} {:#x}", self.evaluate(process)?, self.evaluate(handle)?)
            }
            "object" | "obj" => format!("obj {argument}"),
            other => return Err(format!("consulta desconhecida: {other}")),
        };
        let text = self.monitor(&query)?;
        // Os endereços de código ganham o símbolo.
        Ok(text
            .lines()
            .map(|line| {
                let symbol = line.split_whitespace().filter_map(|word| parse_number(word.trim_end_matches(','))).filter(|&value| self.symbols.kernel().is_some_and(|_| value > 0xffff_0000_0000_0000)).find_map(|value| self.symbols.name_at(value));
                match symbol {
                    Some(name) if !line.contains(&name) => format!("{line}  {name}\n"),
                    _ => format!("{line}\n"),
                }
            })
            .collect())
    }

    /// Roda um rastro pedido (vários lotes até o fim) e o guarda em
    /// `self.trace`; devolve o resumo.
    pub fn run_trace(&mut self, options: &TraceOptions) -> Result<String, String> {
        self.require_stopped()?;
        let mut command = format!("trace start count={}", options.count.max(1));
        if !options.until.trim().is_empty() {
            command.push_str(&format!(" until={:x}", self.evaluate(&options.until)?));
        }
        if options.until_return {
            command.push_str(" ret");
        }
        if options.over_calls {
            command.push_str(" depth=0");
        }
        let range = |client: &Client, name: &str| -> Result<String, String> {
            let module = client.symbols.module_named(name.trim()).ok_or_else(|| format!("modulo {name} nao carregado"))?;
            Ok(format!("{:x}-{:x}", module.base, module.end))
        };
        if !options.enter_module.trim().is_empty() {
            command.push_str(&format!(" enter={}", range(self, &options.enter_module)?));
        }
        if !options.leave_module.trim().is_empty() {
            command.push_str(&format!(" leave={}", range(self, &options.leave_module)?));
        }
        for module in &options.skip_modules {
            command.push_str(&format!(" skip={}", range(self, module)?));
        }
        if !options.watch.trim().is_empty() {
            command.push_str(&format!(" watch={:x}:{}", self.evaluate(&options.watch)?, options.watch_size));
        }
        let reply = self.monitor(&command)?;
        if !reply.contains("armado") {
            return Err(reply.trim().to_string());
        }
        self.tracing = true;
        let result = self.collect_trace(options.max_records);
        self.tracing = false;
        let trace = result?;
        let summary = self.trace_summary(&trace);
        self.trace = Some(trace);
        Ok(summary)
    }

    fn collect_trace(&mut self, max_records: usize) -> Result<Trace, String> {
        let mut trace = Trace::new(Source::Stub);
        let started = Instant::now();
        loop {
            self.resume("c")?;
            self.wait_stop(Duration::from_secs(900))?;
            let header = trace::Header::parse(&self.trace_bytes(0, trace::HEADER_SIZE)?)?;
            let bytes = self.trace_bytes(0, trace::HEADER_SIZE + header.bytes as usize)?;
            let header = trace.append_batch(&bytes)?;
            if header.reason != trace::Reason::BufferFull || trace.len() >= max_records {
                break;
            }
            let reply = self.monitor("trace resume")?;
            if !reply.contains("armado") {
                return Err(reply.trim().to_string());
            }
        }
        let _ = started;
        Ok(trace)
    }

    fn trace_summary(&self, trace: &Trace) -> String {
        let symbols = &self.symbols;
        let symbol = |address: u64| symbols.describe(address);
        let mut output = format!("rastro: {} registros, {} instrucoes executadas, {} lote(s); fim: {}\n", trace.len(), trace.steps, trace.batches, trace.reason.text());
        output.push_str("mais executados:\n");
        for (name, count) in trace::histogram(trace, &symbol).into_iter().take(8) {
            output.push_str(&format!("  {count:>8}  {name}\n"));
        }
        let first = trace.len().saturating_sub(4);
        output.push_str("ultimos registros:\n");
        for index in first..trace.len() {
            output.push_str(&trace::format_record(trace, index, &symbol));
            output.push('\n');
        }
        output
    }

    fn trace_command(&mut self, words: &[&str]) -> Result<String, String> {
        match words.first().copied() {
            Some("show") => {
                let trace = self.trace.as_ref().ok_or("nenhum rastro (trace [n])")?;
                let from = words.get(1).and_then(|word| parse_number(word)).unwrap_or(0) as usize;
                let count = words.get(2).and_then(|word| parse_number(word)).unwrap_or(40) as usize;
                let symbols = &self.symbols;
                let mut output = String::new();
                for index in from..(from + count).min(trace.len()) {
                    output.push_str(&trace::format_record(trace, index, &|address| symbols.describe(address)));
                    output.push('\n');
                }
                Ok(output)
            }
            Some("tree") => {
                let trace = self.trace.as_ref().ok_or("nenhum rastro (trace [n])")?;
                let limit = words.get(1).and_then(|word| parse_number(word)).unwrap_or(200) as usize;
                let symbols = &self.symbols;
                Ok(trace::format_tree(trace, &|address| symbols.describe(address), limit))
            }
            Some("save") => {
                let path = words.get(1).ok_or("uso: trace save <arquivo.csv>")?;
                let trace = self.trace.as_ref().ok_or("nenhum rastro (trace [n])")?;
                let symbols = &self.symbols;
                let csv = trace.to_csv(&|address| symbols.describe(address), &|_| String::new());
                std::fs::write(path, csv).map_err(|error| format!("{path}: {error}"))?;
                Ok(format!("{} registros em {path}", trace.len()))
            }
            Some("ref") => {
                let trace = self.trace.take().ok_or("nenhum rastro (trace [n])")?;
                let count = trace.len();
                self.reference = Some(trace);
                Ok(format!("rastro de {count} registros guardado como referencia"))
            }
            Some("diff") => {
                if let Some(path) = words.get(1) {
                    let text = std::fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?;
                    self.reference = Some(Trace::from_csv(&text)?);
                }
                let (Some(current), Some(reference)) = (self.trace.as_ref(), self.reference.as_ref()) else { return Err("precisa de um rastro e de uma referencia (trace ref ou trace diff <arq.csv>)".into()) };
                let a: Vec<u64> = current.records.iter().map(|record| record.rip).collect();
                let b: Vec<u64> = reference.records.iter().map(|record| record.rip).collect();
                let symbols = &self.symbols;
                Ok(match trace::first_divergence(&a, &b) {
                    None => format!("rastros iguais ({} registros)", a.len()),
                    Some((x, y)) => {
                        let describe = |list: &[u64], index: usize| list.get(index).map_or("(fim)".to_string(), |&rip| format!("{rip:#x} {}", symbols.describe(rip)));
                        format!("primeira divergencia: registro {x} deste rastro e {y} da referencia\n  este:       {}\n  referencia: {}\n  antes:      {}\n", describe(&a, x), describe(&b, y), x.checked_sub(1).map_or("(inicio)".to_string(), |index| describe(&a, index)))
                    }
                })
            }
            Some("status") => self.monitor("trace status"),
            _ => {
                let options = TraceOptions::parse(words)?;
                self.run_trace(&options)
            }
        }
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
            "rx" => {
                // x87, SSE, a metade alta dos YMM e os registradores de
                // depuração.
                let state = self.extended_registers()?;
                let hex_bytes = |bytes: &[u8]| bytes.iter().rev().map(|byte| format!("{byte:02x}")).collect::<String>();
                let mut output = String::new();
                for (index, value) in state.xmm.iter().enumerate() {
                    output.push_str(&format!("xmm{index:<2} {}\n", value.map_or("indisponivel".into(), |bytes| hex_bytes(&bytes))));
                }
                if let Some(mxcsr) = state.mxcsr {
                    output.push_str(&format!("mxcsr {mxcsr:08x} {}\n", registers::mxcsr_text(mxcsr)));
                }
                for (index, value) in state.st.iter().enumerate() {
                    if let Some(bytes) = value {
                        output.push_str(&format!("st{index} {} ({})\n", hex_bytes(bytes), registers::extended_to_f64(bytes)));
                    }
                }
                let ymm: Vec<String> = state.ymm_high.iter().enumerate().filter_map(|(index, value)| value.map(|bytes| format!("ymm{index}h {}", hex_bytes(&bytes)))).collect();
                if ymm.is_empty() {
                    output.push_str("ymm: indisponivel (o sistema nao liga o AVX)\n");
                } else {
                    output.push_str(&(ymm.join("\n") + "\n"));
                }
                for (name, value) in ["dr0", "dr1", "dr2", "dr3", "dr6", "dr7"].iter().zip(state.debug.iter()) {
                    output.push_str(&format!("{name} {}\n", value.map_or("indisponivel".into(), |value| format!("{value:#x}"))));
                }
                if let Some(control) = state.debug[5] {
                    output.push_str(&format!("dr7: {}\n", registers::dr7_text(control)));
                }
                Ok(output)
            }
            "r" if rest.contains('=') && !rest.contains("==") => {
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
            "db" | "dw" | "dd" | "dq" => {
                let expression: Vec<&str> = words.iter().copied().filter(|word| !(word.starts_with('L') || word.starts_with('l')) || parse_number(&word[1..]).is_none()).collect();
                let address = self.evaluate(&expression.join(" ")).map_err(|error| if expression.is_empty() { format!("uso: {command} <expr> [L<n>]") } else { error })?;
                let size = match command {
                    "db" => 1,
                    "dw" => 2,
                    "dd" => 4,
                    _ => 8,
                };
                let count = length_argument(&words).unwrap_or(128 / size as u64) as usize;
                if size == 1 {
                    self.dump(address, count)
                } else {
                    self.dump_units(address, size, count)
                }
            }
            "da" | "du" => {
                let address = self.evaluate(rest)?;
                let text = if command == "da" { types::read_narrow(self, address, 256) } else { types::read_wide(self, address, 512) };
                Ok(format!("{address:#018x}  {}", text.unwrap_or_else(|| "(ilegivel)".into())))
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
            "bp" | "bu" => {
                // bp <expr> [N] [/w "condição"] [/log "texto"] [/cmd "comandos"] [/g grupo]
                let (rest, options) = breakpoint_options(rest);
                let rest = rest.as_str();
                let (main, condition) = match rest.split_once("/w") {
                    Some((main, condition)) => (main.trim(), condition.trim().trim_matches('"').to_string()),
                    None => (rest, String::new()),
                };
                let parts: Vec<&str> = main.split_whitespace().collect();
                let (expression, pass_count) = match parts.split_last() {
                    Some((last, init)) if parts.len() > 1 && parse_number(last).is_some() => (init.join(" "), parse_number(last).unwrap_or(0)),
                    _ => (main.to_string(), 0),
                };
                let mut request = BreakpointRequest::new(BreakpointKind::Software, &expression);
                request.condition = condition;
                request.pass_count = pass_count;
                request.deferred = command == "bu";
                request.log = options.log;
                request.command = options.command;
                request.group = options.group;
                self.breakpoint_command(request)
            }
            "bc" if rest == "all" || rest == "*" => {
                let list = self.monitor("bl")?;
                for line in list.lines() {
                    if let Some(address) = line.strip_prefix("software").and_then(|rest| parse_number(rest.trim())) {
                        self.request(&format!("z0,{address:x},1"))?;
                    }
                }
                let ids: Vec<u32> = self.breakpoints.iter().filter(|breakpoint| breakpoint.kind == BreakpointKind::Software).map(|breakpoint| breakpoint.id).collect();
                for id in ids {
                    if let Some(index) = self.breakpoints.iter().position(|breakpoint| breakpoint.id == id) {
                        self.breakpoints.remove(index);
                    }
                }
                Ok("breakpoints de software removidos".into())
            }
            "bc" => self.clear_command(BreakpointKind::Software, rest, 1),
            "hbp" => self.breakpoint_command(BreakpointRequest::new(BreakpointKind::Hardware, rest)),
            "hbc" => self.clear_command(BreakpointKind::Hardware, rest, 1),
            "ba" => {
                // ba e1 <expr> | ba w4 <expr> | ba r8 <expr>
                let access = words.first().ok_or("uso: ba <e|w|r><1|2|4|8> <expr>")?;
                let (kind, size) = access.split_at(1);
                let kind = match kind {
                    "e" => BreakpointKind::Hardware,
                    "w" => BreakpointKind::Write,
                    "r" | "a" => BreakpointKind::Access,
                    _ => return Err("uso: ba <e|w|r><1|2|4|8> <expr>".into()),
                };
                let mut request = BreakpointRequest::new(kind, &words[1..].join(" "));
                request.length = parse_number(size).filter(|size| matches!(size, 1 | 2 | 4 | 8)).unwrap_or(1);
                self.breakpoint_command(request)
            }
            "bpm" | "bpmc" => {
                // bpm <a|w|x> <expr> [bytes]: breakpoint de memória por página.
                let usage = "uso: bpm <a|w|x> <expr> [bytes] | bpmc <expr>";
                if command == "bpmc" {
                    let address = self.evaluate(words.first().ok_or(usage)?)? & !0xFFF;
                    let id = self.breakpoints.iter().find(|breakpoint| breakpoint.kind.is_memory() && breakpoint.address == address).map(|breakpoint| breakpoint.id).ok_or_else(|| format!("nenhum breakpoint de memoria em {address:#x}"))?;
                    let breakpoint = self.remove_breakpoint(id)?;
                    return Ok(format!("removido o breakpoint de memoria em {:#x}", breakpoint.address));
                }
                let kind = match words.first().copied() {
                    Some("a" | "r") => BreakpointKind::MemoryAccess,
                    Some("w") => BreakpointKind::MemoryWrite,
                    Some("x" | "e") => BreakpointKind::MemoryExecute,
                    _ => return Err(usage.into()),
                };
                let mut request = BreakpointRequest::new(kind, words.get(1).ok_or(usage)?);
                if let Some(length) = words.get(2).and_then(|text| parse_number(text)) {
                    request.length = length;
                }
                let breakpoint = self.add_breakpoint_with(&request)?;
                Ok(format!("breakpoint de memoria ({}) em {:#x}+{:#x} (#{})", kind.name(), breakpoint.address, breakpoint.length, breakpoint.id))
            }
            "watch" | "unwatch" => {
                let target = words.first().ok_or("uso: watch <endereco> <bytes> [w|a]")?;
                let length = words.get(1).and_then(|text| parse_number(text)).unwrap_or(8);
                let kind = if words.get(2) == Some(&"a") { BreakpointKind::Access } else { BreakpointKind::Write };
                if command == "watch" {
                    let mut request = BreakpointRequest::new(kind, target);
                    request.length = length;
                    self.breakpoint_command(request)
                } else {
                    self.clear_command(kind, target, length)
                }
            }
            "sxe" | "sxd" if is_event_filter(rest) => {
                let expression = rest.trim().to_string();
                if command == "sxe" {
                    self.breakpoint_command(BreakpointRequest::new(BreakpointKind::Event, &expression))
                } else {
                    let id = self.breakpoints.iter().find(|breakpoint| breakpoint.kind == BreakpointKind::Event && breakpoint.expression.eq_ignore_ascii_case(&expression)).map(|breakpoint| breakpoint.id).ok_or_else(|| format!("nenhuma parada no evento {expression}"))?;
                    self.remove_breakpoint(id)?;
                    Ok(format!("sem parada no evento {expression}"))
                }
            }
            "sxe" | "sxd" => {
                let module = rest.strip_prefix("ld:").or_else(|| rest.strip_prefix("ld ")).ok_or("uso: sxe ld:<modulo> | cpr | epr | ct | et | ld:processo!dll")?.trim();
                if command == "sxe" {
                    self.breakpoint_command(BreakpointRequest::new(BreakpointKind::Module, module))
                } else {
                    let id = self.breakpoints.iter().find(|breakpoint| breakpoint.kind == BreakpointKind::Module && breakpoint.expression.eq_ignore_ascii_case(module)).map(|breakpoint| breakpoint.id).ok_or_else(|| format!("nenhuma parada por carga de {module}"))?;
                    self.remove_breakpoint(id)?;
                    Ok(format!("sem parada quando {module} carregar"))
                }
            }
            "bd" | "be" => {
                let id = parse_number(rest.trim_start_matches('#')).ok_or("uso: bd|be <n>")? as u32;
                self.set_breakpoint_enabled(id, command == "be")?;
                Ok(format!("breakpoint {id} {}", if command == "be" { "ligado" } else { "desligado" }))
            }
            "bl" => self.breakpoint_list(),
            ".bpsave" => {
                let path = words.first().ok_or("uso: .bpsave <arquivo>")?;
                std::fs::write(path, self.breakpoint_specs()).map_err(|error| format!("{path}: {error}"))?;
                Ok(format!("{} breakpoints em {path}", self.breakpoints.len()))
            }
            ".bpload" => {
                let path = words.first().ok_or("uso: .bpload <arquivo>")?;
                let text = std::fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?;
                let errors = self.restore_breakpoints(&text);
                Ok(if errors.is_empty() { format!("{} breakpoints", self.breakpoints.len()) } else { errors.join("\n") })
            }
            "bt" => {
                let limit = words.first().and_then(|text| parse_number(text)).unwrap_or(32) as usize;
                let frames = self.backtrace(limit)?;
                Ok(self.format_frames(&frames))
            }
            "k" | "kb" | "kn" | "kp" => {
                let limit = words.first().and_then(|text| parse_number(text)).unwrap_or(32) as usize;
                let frames = self.backtrace(limit)?;
                Ok(self.format_frames_with_stack(&frames))
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
            "?" => {
                let value = self.evaluate(rest)?;
                let symbol = self.symbols.name_at(value).map(|name| format!(" {name}")).unwrap_or_default();
                Ok(format!("= {value:#x} ({value}){symbol}"))
            }
            "sym" => {
                let address = self.evaluate(rest)?;
                Ok(format!("{address:#x} {}", self.symbols.describe(address)))
            }
            "ln" => {
                let address = self.evaluate(rest)?;
                let module = self.symbols.module_at(address).map(|module| format!(" (modulo {} {:#x}-{:#x})", module.name, module.base, module.end)).unwrap_or_default();
                Ok(format!("{address:#x} {}{module}", self.symbols.describe(address)))
            }
            "addr" => {
                let address = self.symbols.lookup(rest)?;
                Ok(format!("{address:#x} {}", self.symbols.describe(address)))
            }
            "dt" => self.display_type(rest),
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
            "lmv" => self.module_detail(rest),
            ".reload" => {
                self.reload_modules()?;
                let pending: Vec<String> = self.symbols.modules.iter().filter(|module| module.pdb_pending).map(|module| module.name.clone()).collect();
                let with_pdb = self.symbols.modules.iter().filter(|module| module.pdb.is_some()).count();
                Ok(format!("{} modulos, {with_pdb} com PDB{}", self.symbols.modules.len(), if pending.is_empty() { String::new() } else { format!(", baixando: {}", pending.join(" ")) }))
            }
            "!process" => self.nt_view("process", rest),
            "!thread" => self.nt_view("thread", rest),
            "!irp" => self.nt_view("irp", rest),
            "!devobj" => self.nt_view("devobj", rest),
            "!drvobj" => self.nt_view("drvobj", rest),
            "!object" => self.nt_view("object", rest),
            "!handle" => self.nt_view("handle", rest),
            "!analyze" => Ok(self.analyze()?.text()),
            "trace" => self.trace_command(&words),
            "monitor" => self.monitor(rest),
            ".process" => {
                if rest.is_empty() {
                    return self.monitor(".process");
                }
                match self.set_process(Some(rest))? {
                    Some(context) => {
                        let modules = self.symbols.user_modules().count();
                        Ok(format!("processo {} (PID {}) EPROCESS {:#x} CR3 {:#x} PEB {:#x}; {modules} modulos de usuario", context.name, context.pid, context.eprocess, context.cr3, context.peb))
                    }
                    None => Ok("processo das leituras: o do processador".into()),
                }
            }
            "lmu" => {
                let modules = self.user_modules()?;
                self.reload_user_modules()?;
                let mut output = String::new();
                for module in &modules {
                    let symbols = self.symbols.module_at(module.base).map(|loaded| format!("{} simbolos ({})", loaded.symbols.len(), loaded.source)).unwrap_or_default();
                    output.push_str(&format!("{:#018x} {:#018x} {:<20} {symbols}\n", module.base, module.base + module.size, module.name));
                }
                Ok(output)
            }
            "handles" | "vad" | "uthreads" => {
                // O processo pode vir de uma expressão ($nome, @reg, módulo!símbolo).
                let process = match words.first() {
                    Some(first) if first.starts_with(['$', '@']) || first.contains(['!', '(']) => format!("{:#x}", self.evaluate(first)?),
                    Some(first) => first.to_string(),
                    None => return Err(format!("uso: {command} <pid|eprocess> [indice]")),
                };
                let tail = words.get(1).map(|start| format!(" {start}")).unwrap_or_default();
                self.monitor(&format!("{command} {process}{tail}"))
            }
            "kmap" | "events" | "uex" => self.monitor(line),
            "ustack" => {
                let tid = words.first().and_then(|text| parse_number(text)).ok_or("uso: ustack <tid> [n] (processo escolhido com .process)")?;
                let limit = words.get(1).and_then(|text| parse_number(text)).unwrap_or(32) as usize;
                let process = self.process().map(|context| format!("{:#x}", context.eprocess)).ok_or("nenhum processo escolhido (.process <pid>)")?;
                let thread = self.user_threads(&process)?.into_iter().find(|thread| thread.tid == tid).ok_or_else(|| format!("thread {tid} nao e deste processo"))?;
                let (_, frames) = self.user_thread_backtrace(&thread, limit)?;
                Ok(self.format_frames_with_stack(&frames))
            }
            "bgd" | "bge" => {
                let count = self.set_group_enabled(rest, command == "bge")?;
                Ok(format!("grupo {rest}: {count} breakpoints {}", if command == "bge" { "ligados" } else { "desligados" }))
            }
            "bar" => {
                let usage = "uso: bar <w|a> <expr> <bytes>";
                let kind = match words.first().copied() {
                    Some("w") => BreakpointKind::Write,
                    Some("a" | "r") => BreakpointKind::Access,
                    _ => return Err(usage.into()),
                };
                let start = self.evaluate(words.get(1).ok_or(usage)?)?;
                let length = self.evaluate(words.get(2).ok_or(usage)?)?;
                let created = self.add_range_watch(kind, start, length)?;
                Ok(created.iter().map(|breakpoint| format!("#{} {:#x} ({} bytes)", breakpoint.id, breakpoint.address, breakpoint.length)).collect::<Vec<_>>().join("\n"))
            }
            "modules" => Ok(self.symbols.modules.iter().map(|module| format!("{:#018x} {:#018x} {:<16} {} simbolos ({})\n", module.base, module.end, module.name, module.symbols.len(), module.source)).collect()),
            "detach" => self.detach(),
            "help" => Ok(HELP.to_string()),
            other => Err(format!("comando desconhecido: {other} (help)")),
        }
    }

    /// Os comandos e aliases conhecidos (o autocompletar).
    pub fn command_names() -> &'static [&'static str] {
        &[
            "attach", "break", "c", "g", "continue", "wait-stop", "s", "t", "step", "p", "gu", "regs", "r", "rx", "x", "db", "dw", "dd", "dq", "da", "du", "write", "poke", "bp", "bu", "bc", "hbp", "hbc", "ba", "bpm", "bpmc", "watch", "unwatch", "sxe", "sxd", "bd", "be", "bl", ".bpsave", ".bpload", "bt", "k", "context", "btt", "?", "sym", "ln", "addr", "dt", "thread", "cpulist", "ps",
            "threads", "lm", "lmv", "cpus", "irql", "obj", "log", "bugcheck", "kd", ".reload", "!process", "!thread", "!irp", "!devobj", "!drvobj", "!object", "!handle", "!analyze", "trace", "monitor", "modules", "detach", "help",
            ".process", "lmu", "handles", "vad", "uthreads", "ustack", "kmap", "events", "uex", "bgd", "bge", "bar",
        ]
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
                    // save-word <nome> <texto da linha> <coluna> [ocorrência]:
                    // um número da linha da saída anterior que contém o texto
                    // (a primeira, ou a N-ésima delas).
                    let mut parts = rest.split_whitespace();
                    let (Some(name), Some(needle), Some(column)) = (parts.next(), parts.next(), parts.next().and_then(|text| text.parse::<usize>().ok())) else {
                        return Err(fail("uso: save-word <nome> <texto> <coluna> [ocorrencia]".into()));
                    };
                    let occurrence = match parts.next() {
                        Some(text) => text.parse::<usize>().ok().filter(|&value| value >= 1).ok_or_else(|| fail("uso: save-word <nome> <texto> <coluna> [ocorrencia]".into()))?,
                        None => 1,
                    };
                    let value = last_output.lines().filter(|line| line.contains(needle)).nth(occurrence - 1).and_then(|line| line.split_whitespace().nth(column)).and_then(parse_number).ok_or_else(|| fail(format!("nenhuma linha {occurrence} com {needle:?} e numero na coluna {column}")))?;
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

/// O tipo de um campo é ponteiro para struct (a vista tipada abre).
pub fn is_struct_pointer(database: &types::TypeDb, ty: u32) -> bool {
    matches!(database.kind(ty), Kind::Pointer { target } if matches!(database.kind(target), Kind::Struct { .. }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_trace_options() {
        let options = TraceOptions::parse(&["500", "over", "pula", "ntfs", "vigia", "@rsp", "4"]).unwrap();
        assert_eq!(options.count, 500);
        assert!(options.over_calls);
        assert_eq!(options.skip_modules, vec!["ntfs".to_string()]);
        assert_eq!(options.watch, "@rsp");
        assert_eq!(options.watch_size, 4);
        let options = TraceOptions::parse(&["ret"]).unwrap();
        assert!(options.until_return);
        assert_eq!(options.count, 1_000_000);
        let options = TraceOptions::parse(&["ate", "kernel::ntos::ke::run_kernel_tasks", "entra", "ACPI"]).unwrap();
        assert_eq!(options.until, "kernel::ntos::ke::run_kernel_tasks");
        assert_eq!(options.enter_module, "ACPI");
        assert!(TraceOptions::parse(&["xyz"]).is_err());
        assert!(TraceOptions::parse(&["ate"]).is_err());
    }

    #[test]
    fn breakpoint_text_options() {
        let (rest, options) = breakpoint_options("ntdll!NtClose /log \"fechou {@rcx}\" /g fechar");
        assert_eq!(rest, "ntdll!NtClose");
        assert_eq!(options.log, "fechou {@rcx}");
        assert_eq!(options.group, "fechar");
        let (rest, options) = breakpoint_options("x 3 /w \"@rax == 1\" /cmd \"r; k 4\"");
        assert_eq!(rest, "x 3 /w \"@rax == 1\"");
        assert_eq!(options.command, "r; k 4");
        assert!(is_event_filter("ld:csrss!winsrv.dll"));
        assert!(is_event_filter("cpr:winlogon.exe"));
        assert!(!is_event_filter("ld:ntfs.sys"));
    }

    #[test]
    fn memory_length_argument() {
        assert_eq!(length_argument(&["@rsp", "L8"]), Some(8));
        assert_eq!(length_argument(&["@rsp", "L0x10"]), Some(16));
        assert_eq!(length_argument(&["@rsp"]), None);
        assert_eq!(split_two("poi(@rsp + 8) 4"), Some(("poi(@rsp + 8)", "4")));
    }
}
