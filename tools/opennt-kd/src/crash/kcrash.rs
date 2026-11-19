//! A parada no log: a linha `*** STOP` (ou a `*** EXCECAO DE KERNEL` da
//! HAL), o bloco `[kcrash]` que o kernel imprime logo depois
//! (`kernel/src/ntos/ke/bugcheck_trace.rs`) e o resumo: o código, os
//! parâmetros com o sentido que têm no Windows 10 19041, onde parou
//! (módulo+deslocamento), o módulo culpado, o componente provável e a pilha
//! com os nomes dos PDBs públicos.
//!
//! O bloco escreve cada endereço como `módulo+0xRVA`, com o export mais
//! próximo entre parênteses; aqui o nome vem do [`ModuleSymbols`] (PDB do
//! módulo ou o `kernel.elf` para o `ntoskrnl.exe`, que é o kernel do
//! OpenNT) e o export do bloco fica só quando não há nada melhor.

use super::serial::{self, LoadedImage};
use super::symbolizer::{is_opennt_kernel, ModuleSymbols};
use crate::bugcheck;

/// Linhas depois da parada em que o bloco e as linhas `[bugcheck]` são
/// procurados.
const BLOCK_WINDOW: usize = 80;
/// O nome de um quadro na pilha é cortado neste tamanho.
const NAME_WIDTH: usize = 140;

/// MANUALLY_INITIATED_CRASH.
const MANUAL_CRASH: u32 = 0xE2;

/// O tipo da linha de parada.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StopKind {
    /// `*** STOP (KeBugCheckEx): ...`
    BugCheck,
    /// `*** STOP (KeBugCheckEx aninhado): ...`
    Nested,
    /// `*** STOP: ...`, antes de o bugcheck completo estar pronto.
    Early,
    /// `*** EXCECAO DE KERNEL: vetor ...`: a exceção que não passou pelo
    /// despacho, com os registradores que a HAL imprimiu.
    KernelException { description: String, registers: Vec<(String, u64)> },
}

/// A linha de parada.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stop {
    pub line: usize,
    pub kind: StopKind,
    pub code: u32,
    pub parameters: [u64; 4],
}

/// Um endereço como o bloco o escreve: `módulo+0xRVA` (com o export mais
/// próximo entre parênteses) ou só `0xVA` fora de qualquer módulo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Location {
    pub module: Option<String>,
    /// A RVA no módulo, ou a VA quando não há módulo.
    pub offset: u64,
    pub export: Option<String>,
}

/// A origem que o bloco aponta.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    /// A exceção de kernel sem tratamento que virou o bugcheck.
    Exception { code: u32, address: u64, location: Option<Location>, access: Option<String> },
    /// A parada dentro de uma chamada nativa ao kernel: a rotina chamada e
    /// quem a chamou (o endereço de retorno).
    Call { callee: String, caller: Location },
    /// A exceção que não passou pelo despacho: o RIP.
    Trap { location: Location },
    /// Uma parada do próprio kernel fora de uma chamada nativa.
    Kernel,
    /// Uma linha que o bloco escreve quando não consegue ler o estado.
    Other(String),
}

/// O bloco `[kcrash]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub origin: Origin,
    /// As linhas de registradores, sem o prefixo.
    pub registers: Vec<String>,
    /// `pilha (rsp 0x...)` ou `pilha do kernel (rbp 0x...)`.
    pub stack: String,
    pub frames: Vec<Location>,
    /// O primeiro quadro é o RIP da falha, não um endereço de retorno.
    pub first_frame_exact: bool,
}

/// A parada do log com o que veio junto.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Crash {
    pub stop: Stop,
    pub block: Option<Block>,
    /// `[bugcheck] codigo de parada: NOME`.
    pub stop_name: Option<String>,
    /// `[bugcheck] o que falhou: DRIVER`.
    pub failed_driver: Option<String>,
    /// Quantas linhas de parada o log tem.
    pub stops: usize,
}

/// Uma linha `*** STOP`.
pub fn parse_stop(line: &str) -> Option<(StopKind, u32, [u64; 4])> {
    let rest = line.trim_end().strip_prefix("*** STOP")?;
    let (kind, body) = if let Some(rest) = rest.strip_prefix(" (") {
        let (inner, after) = rest.split_once(')')?;
        let kind = if inner.contains("aninhado") { StopKind::Nested } else { StopKind::BugCheck };
        (kind, after.strip_prefix(": ")?)
    } else {
        (StopKind::Early, rest.strip_prefix(": ")?)
    };
    let (code, parameters) = body.split_once(" (")?;
    let code = u32::try_from(serial::hex(code)?).ok()?;
    let values: Vec<u64> = parameters.trim_end_matches(')').split(',').filter_map(serial::hex).collect();
    Some((kind, code, values.get(..4)?.try_into().ok()?))
}

/// `NOME=0x...` numa linha de registradores (também `R8 =0x...` da HAL).
fn registers_of(line: &str) -> Vec<(String, u64)> {
    line.replace(" =", "=").split_whitespace().filter_map(|word| word.split_once('=')).filter_map(|(name, value)| Some((name.to_ascii_lowercase(), serial::hex(value)?))).collect()
}

/// Um endereço do bloco.
pub fn parse_location(text: &str) -> Option<Location> {
    let text = text.trim();
    let (head, export) = match text.split_once(" (") {
        Some((head, rest)) => (head, Some(rest.strip_suffix(')').unwrap_or(rest).to_string())),
        None => (text, None),
    };
    if let Some((module, offset)) = head.rsplit_once("+0x") {
        if module.is_empty() || module.contains(char::is_whitespace) {
            return None;
        }
        return Some(Location { module: Some(module.to_string()), offset: u64::from_str_radix(offset, 16).ok()?, export });
    }
    let address = serial::hex(head.strip_prefix("0x")?)?;
    Some(Location { module: None, offset: address, export })
}

/// O tipo de acesso no fim da linha da exceção (`, leitura de 0x40`).
fn split_access(text: &str) -> (&str, Option<String>) {
    for word in [", leitura de ", ", escrita em ", ", execucao em ", ", acesso a "] {
        if let Some(position) = text.find(word) {
            return (&text[..position], Some(text[position + 2..].to_string()));
        }
    }
    (text, None)
}

fn exception_origin(rest: &str) -> Origin {
    let parsed = (|| {
        let (code, rest) = rest.split_once(" em ")?;
        let (address, rest) = rest.split_once(" = ").unwrap_or((rest, ""));
        let (location, access) = split_access(rest);
        Some(Origin::Exception { code: u32::try_from(serial::hex(code)?).ok()?, address: serial::hex(address)?, location: parse_location(location), access })
    })();
    parsed.unwrap_or_else(|| Origin::Other(format!("excecao {rest}")))
}

fn frames_of(text: &str) -> Vec<Location> {
    text.split(" | ").filter_map(parse_location).collect()
}

/// O bloco `[kcrash]` nas linhas depois da parada (`start` é a primeira
/// linha depois dela).
pub fn parse_block(lines: &[String], start: usize) -> Option<Block> {
    let mut origin = None;
    let mut registers = Vec::new();
    let mut stack = String::new();
    let mut frames = Vec::new();
    let end = (start + BLOCK_WINDOW).min(lines.len());
    for line in &lines[start.min(end)..end] {
        if line.starts_with("*** ") || line.contains(serial::BOOT_MARKER) {
            break;
        }
        let Some(body) = line.strip_prefix("[kcrash]") else { continue };
        if body.starts_with("  ") {
            frames.extend(frames_of(body));
            continue;
        }
        let body = body.trim_start();
        if let Some(rest) = body.strip_prefix("excecao ") {
            origin = Some(exception_origin(rest));
        } else if let Some(rest) = body.strip_prefix("parada dentro de ") {
            origin = Some(match rest.rsplit_once(", chamada de ").and_then(|(callee, caller)| Some((callee, parse_location(caller)?))) {
                Some((callee, caller)) => Origin::Call { callee: callee.to_string(), caller },
                None => Origin::Other(body.to_string()),
            });
        } else if body.starts_with("parada do proprio kernel") {
            origin = Some(Origin::Kernel);
        } else if let Some(rest) = body.strip_prefix("rip = ") {
            origin = Some(parse_location(rest).map_or_else(|| Origin::Other(body.to_string()), |location| Origin::Trap { location }));
        } else if body.starts_with("rip=") || body.starts_with("rbx=") {
            registers.push(body.to_string());
        } else if body.starts_with("pilha") {
            let (header, rest) = body.split_once("):").unwrap_or((body, ""));
            stack = format!("{header})");
            frames.extend(frames_of(rest));
        } else if origin.is_none() {
            origin = Some(Origin::Other(body.to_string()));
        }
    }
    let origin = origin?;
    let first_frame_exact = matches!(origin, Origin::Exception { .. } | Origin::Trap { .. });
    Some(Block { origin, registers, stack, frames, first_frame_exact })
}

fn is_stop_line(line: &str) -> bool {
    line.starts_with("*** STOP") || line.starts_with("*** EXCECAO DE KERNEL")
}

/// A parada a analisar: a primeira do boot da última parada do log (as
/// seguintes do mesmo boot são aninhadas ou consequências dela).
pub fn find_last(lines: &[String]) -> Option<Crash> {
    let stops: Vec<usize> = lines.iter().enumerate().filter(|(_, line)| is_stop_line(line)).map(|(index, _)| index).collect();
    let last = *stops.last()?;
    let boot = serial::boot_start(lines, last);
    let index = stops.iter().copied().find(|&index| index >= boot).unwrap_or(last);
    let line = lines[index].as_str();
    let stop = if let Some(description) = line.strip_prefix("*** EXCECAO DE KERNEL: ") {
        let registers = lines[index + 1..(index + 10).min(lines.len())].iter().take_while(|line| line.starts_with("    ")).flat_map(|line| registers_of(line)).collect();
        Stop { line: index, kind: StopKind::KernelException { description: description.trim().to_string(), registers }, code: 0, parameters: [0; 4] }
    } else {
        let (kind, code, parameters) = parse_stop(line).unwrap_or((StopKind::BugCheck, 0, [0; 4]));
        Stop { line: index, kind, code, parameters }
    };
    let end = (index + 1 + BLOCK_WINDOW).min(lines.len());
    let window = &lines[index + 1..end];
    let after = |prefix: &str| window.iter().find_map(|line| line.strip_prefix(prefix)).map(|rest| rest.trim().to_string());
    Some(Crash { block: parse_block(lines, index + 1), stop_name: after("[bugcheck] codigo de parada: "), failed_driver: after("[bugcheck] o que falhou: "), stop, stops: stops.len() })
}

/// O componente provável de um módulo (pelo nome do arquivo); no kernel do
/// OpenNT, a pasta do código pelo nome do símbolo.
pub fn component(module: &str, symbol: Option<&str>) -> String {
    const COMPONENTS: &[(&[&str], &str)] = &[
        (&["win32k.sys", "win32kbase.sys", "win32kfull.sys"], "subsistema Win32 de kernel (win32k: janelas, entrada e GDI)"),
        (&["cdd.dll"], "Canonical Display Driver (cdd.dll: o desenho da sessao sobre o dxgkrnl)"),
        (&["dxgkrnl.sys"], "nucleo grafico DirectX (dxgkrnl: adaptadores, VidPn e apresentacao)"),
        (&["dxgmms1.sys", "dxgmms2.sys"], "memoria e escalonador de video (dxgmms)"),
        (&["basicdisplay.sys"], "driver de video basico (BasicDisplay, so exibicao)"),
        (&["basicrender.sys"], "renderizador basico (BasicRender)"),
        (&["watchdog.sys"], "watchdog de video e WdLog"),
        (&["i8042prt.sys", "kbdclass.sys", "kbdhid.sys", "mouclass.sys", "mouhid.sys"], "entrada (teclado e mouse)"),
        (&["hidclass.sys", "hidparse.sys", "hidusb.sys"], "HID"),
        (&["usbxhci.sys", "ucx01000.sys", "usbhub3.sys", "usbd.sys"], "USB"),
        (&["ntfs.sys"], "sistema de arquivos NTFS"),
        (&["npfs.sys"], "pipes nomeados (npfs)"),
        (&["msfs.sys"], "mailslots (msfs)"),
        (&["ataport.sys", "atapi.sys", "disk.sys", "classpnp.sys", "storport.sys", "stornvme.sys", "mountmgr.sys"], "armazenamento"),
        (&["acpi.sys", "pci.sys", "msisadrv.sys"], "barramento (ACPI e PCI)"),
        (&["wdf01000.sys", "wdfldr.sys"], "framework de drivers KMDF"),
        (&["cng.sys", "ksecdd.sys", "ci.dll", "msrpc.sys"], "seguranca, criptografia e integridade de codigo"),
        (&["tpm.sys", "tbs.sys"], "TPM"),
        (&["wpprecorder.sys"], "rastro WPP"),
        (&["hal.dll"], "HAL"),
    ];
    if is_opennt_kernel(module) {
        return match symbol.and_then(kernel_area) {
            Some(area) => format!("kernel do OpenNT ({area})"),
            None => "kernel do OpenNT".to_string(),
        };
    }
    let lower = module.to_ascii_lowercase();
    COMPONENTS.iter().find(|(names, _)| names.contains(&lower.as_str())).map_or_else(|| format!("driver {module}"), |(_, text)| (*text).to_string())
}

/// A pasta do código do kernel pelo caminho Rust do símbolo
/// (`kernel::ntos::mm::...` vira `kernel/src/ntos/mm`).
fn kernel_area(symbol: &str) -> Option<String> {
    let start = symbol.find("kernel::")?;
    let parts: Vec<&str> = symbol[start..].split("::").take(3).map(|part| part.split(['<', ' ', '>', '{']).next().unwrap_or(part)).collect();
    match parts.as_slice() {
        [_, group, area] if !area.is_empty() && (*group == "ntos" || *group == "hal") => Some(format!("kernel/src/{group}/{area}")),
        [_, area, ..] if !area.is_empty() => Some(format!("kernel/src/{area}")),
        _ => None,
    }
}

fn is_kernel_side(module: &str) -> bool {
    is_opennt_kernel(module) || module.eq_ignore_ascii_case("hal.dll")
}

fn shorten(name: String) -> String {
    if name.chars().count() <= NAME_WIDTH {
        return name;
    }
    let head: String = name.chars().take(NAME_WIDTH - 3).collect();
    format!("{head}...")
}

/// O nome de um endereço do bloco: o do [`ModuleSymbols`], senão o export
/// que o kernel escreveu.
fn location_name(location: &Location, symbols: &dyn ModuleSymbols, return_address: bool) -> Option<String> {
    let module = location.module.as_deref()?;
    symbols.name(module, location.offset, return_address).or_else(|| location.export.clone()).map(shorten)
}

/// `módulo+0xRVA (nome)` ou `0xVA`.
pub fn describe_location(location: &Location, symbols: &dyn ModuleSymbols, return_address: bool) -> String {
    match &location.module {
        Some(module) => match location_name(location, symbols, return_address) {
            Some(name) => format!("{module}+{:#x} ({name})", location.offset),
            None => format!("{module}+{:#x}", location.offset),
        },
        None => format!("{:#x}", location.offset),
    }
}

/// Um endereço pelas imagens do log: `módulo+0xRVA (nome)` ou `0xVA`.
pub fn describe_address(address: u64, images: &[LoadedImage], symbols: &dyn ModuleSymbols, return_address: bool) -> String {
    match serial::image_at(images, address).filter(|image| !image.name.is_empty()) {
        Some(image) => describe_location(&Location { module: Some(image.name.clone()), offset: address - image.base, export: None }, symbols, return_address),
        None => format!("{address:#x}"),
    }
}

impl Block {
    /// O quadro `index` é um endereço de retorno.
    pub fn is_return(&self, index: usize) -> bool {
        index != 0 || !self.first_frame_exact
    }

    /// O ponto de partida da culpa: o RIP da falha, ou quem chamou o kernel,
    /// ou o primeiro quadro.
    fn start(&self) -> Option<(Location, bool)> {
        match &self.origin {
            Origin::Exception { location: Some(location), .. } | Origin::Trap { location } => Some((location.clone(), false)),
            Origin::Call { caller, .. } => Some((caller.clone(), true)),
            _ => self.frames.first().map(|frame| (frame.clone(), self.is_return(0))),
        }
    }

    /// O módulo culpado: o do ponto de partida, ou, quando ele é do kernel
    /// ou da HAL, o do primeiro quadro fora deles.
    pub fn culprit(&self) -> Option<(Location, bool, &'static str)> {
        let (start, return_address) = self.start()?;
        let module = start.module.clone().unwrap_or_default();
        if !is_kernel_side(&module) && !module.is_empty() {
            return Some((start, return_address, "onde parou"));
        }
        let outside = self.frames.iter().enumerate().find(|(_, frame)| frame.module.as_deref().is_some_and(|module| !is_kernel_side(module)));
        match outside {
            Some((index, frame)) => Some((frame.clone(), self.is_return(index), "primeiro quadro fora do kernel")),
            None => Some((start, return_address, "onde parou")),
        }
    }

    /// Os módulos que o bloco cita.
    pub fn modules(&self) -> Vec<String> {
        let mut modules: Vec<String> = Vec::new();
        let origin = match &self.origin {
            Origin::Exception { location, .. } => location.as_ref(),
            Origin::Call { caller, .. } => Some(caller),
            Origin::Trap { location } => Some(location),
            _ => None,
        };
        for location in origin.into_iter().chain(self.frames.iter()) {
            if let Some(module) = &location.module {
                if !modules.iter().any(|known| known.eq_ignore_ascii_case(module)) {
                    modules.push(module.clone());
                }
            }
        }
        modules
    }
}

/// O nome de exceção de um código, se conhecido.
fn exception_text(code: u32) -> String {
    match bugcheck::exception_name(code).or_else(|| crate::ntstatus::name(code)) {
        Some(name) => format!("{code:#x} ({name})"),
        None => format!("{code:#x}"),
    }
}

impl Crash {
    /// O resumo da parada.
    pub fn summary(&self, images: &[LoadedImage], symbols: &dyn ModuleSymbols) -> String {
        let mut output = String::new();
        let stop = &self.stop;
        let ordinal = if self.stops > 1 { format!(" ({} linhas de parada no log; esta e a primeira do ultimo boot com parada)", self.stops) } else { String::new() };
        output.push_str(&format!("parada na linha {}{ordinal}\n", stop.line + 1));
        if let StopKind::KernelException { description, registers } = &stop.kind {
            output.push_str(&format!("excecao de kernel fora do despacho: {description}\n"));
            for name in ["rip", "cr2", "rsp"] {
                if let Some((_, value)) = registers.iter().find(|(register, _)| register == name) {
                    let note = if name == "rip" && serial::image_at(images, *value).is_some() { format!("  {}", describe_address(*value, images, symbols, false)) } else { String::new() };
                    output.push_str(&format!("  {name} {value:#018x}{note}\n"));
                }
            }
        } else {
            let known = bugcheck::code(stop.code);
            let name = known.map_or_else(|| self.stop_name.clone().unwrap_or_else(|| format!("BUGCHECK_{:X}", stop.code)), |entry| entry.name.to_string());
            output.push_str(&format!("codigo {:#010x} {name}", stop.code));
            if stop.kind == StopKind::Nested {
                output.push_str(" (aninhado)");
            }
            output.push('\n');
            if let Some(entry) = known {
                output.push_str(&format!("  {}\n", entry.summary));
            }
            output.push_str("parametros (sentido no Windows 10 19041):\n");
            for index in 0..4 {
                let value = stop.parameters[index];
                let label = known.map_or_else(|| format!("parametro {}", index + 1), |entry| entry.parameters[index].to_string());
                let note = bugcheck::parameter_note(stop.code, index, &stop.parameters).or_else(|| (serial::system_address(value) && serial::image_at(images, value).is_some()).then(|| describe_address(value, images, symbols, false)));
                match note {
                    Some(note) => output.push_str(&format!("  {} {value:#018x}  {label}: {note}\n", index + 1)),
                    None => output.push_str(&format!("  {} {value:#018x}  {label}\n", index + 1)),
                }
            }
        }
        let Some(block) = &self.block else {
            output.push_str("sem bloco [kcrash] depois da parada\n");
            if let Some(driver) = &self.failed_driver {
                output.push_str(&format!("o kernel aponta: {driver}\n"));
            }
            return output;
        };
        let place = match &block.origin {
            Origin::Exception { code, address, location, access } => {
                let place = location.as_ref().map_or_else(|| format!("{address:#x}"), |location| describe_location(location, symbols, false));
                let access = access.as_ref().map_or_else(String::new, |access| format!(", {access}"));
                format!("excecao {} em {place}{access}", exception_text(*code))
            }
            Origin::Call { callee, caller } => format!("{callee}, chamada de {}", describe_location(caller, symbols, true)),
            Origin::Trap { location } => format!("rip em {}", describe_location(location, symbols, false)),
            Origin::Kernel => "parada do proprio kernel, fora de uma chamada nativa".to_string(),
            Origin::Other(text) => text.clone(),
        };
        output.push_str(&format!("onde parou: {place}\n"));
        let culprit = block.culprit();
        if let Some((location, return_address, reason)) = &culprit {
            let module = location.module.clone().unwrap_or_else(|| "?".into());
            let mut line = format!("modulo culpado: {module} ({reason}: {})", describe_location(location, symbols, *return_address));
            if let Some(driver) = self.failed_driver.as_ref().filter(|driver| !driver.eq_ignore_ascii_case(&module)) {
                line.push_str(&format!("; o kernel aponta {driver}"));
            }
            output.push_str(&line);
            output.push('\n');
        } else if let Some(driver) = &self.failed_driver {
            output.push_str(&format!("o kernel aponta: {driver}\n"));
        }
        let component = if stop.code == MANUAL_CRASH && !matches!(stop.kind, StopKind::KernelException { .. }) {
            "parada manual (CrashOnCtrlScroll do teclado ou pedido do depurador): nao e uma falha; os dados secundarios mostram o estado do sistema".to_string()
        } else {
            match &culprit {
                Some((location, return_address, _)) => {
                    let module = location.module.clone().unwrap_or_default();
                    component(&module, location_name(location, symbols, *return_address).as_deref())
                }
                None => "desconhecido (o bloco nao tem enderecos)".to_string(),
            }
        };
        output.push_str(&format!("componente provavel: {component}\n"));
        output
    }

    /// A pilha do bloco com os nomes e os registradores.
    pub fn stack(&self, symbols: &dyn ModuleSymbols) -> String {
        let Some(block) = &self.block else { return String::new() };
        let mut output = String::new();
        if block.frames.is_empty() {
            output.push_str(&format!("{}: ilegivel\n", if block.stack.is_empty() { "pilha" } else { block.stack.as_str() }));
        } else {
            output.push_str(&format!("{}:\n", block.stack));
            for (index, frame) in block.frames.iter().enumerate() {
                output.push_str(&format!("  #{index:<2} {}\n", describe_location(frame, symbols, block.is_return(index))));
            }
        }
        if !block.registers.is_empty() {
            output.push_str("registradores:\n");
            for line in &block.registers {
                output.push_str(&format!("  {line}\n"));
            }
        }
        output
    }

    /// Os módulos que a parada cita (o bloco e os parâmetros que caem numa
    /// imagem do log).
    pub fn modules(&self, images: &[LoadedImage]) -> Vec<String> {
        let mut modules = self.block.as_ref().map(Block::modules).unwrap_or_default();
        let mut addresses: Vec<u64> = self.stop.parameters.to_vec();
        if let StopKind::KernelException { registers, .. } = &self.stop.kind {
            addresses.extend(registers.iter().filter(|(name, _)| name == "rip").map(|(_, value)| *value));
        }
        for address in addresses {
            if let Some(image) = serial::image_at(images, address).filter(|image| !image.name.is_empty()) {
                if !modules.iter().any(|known| known.eq_ignore_ascii_case(&image.name)) {
                    modules.push(image.name.clone());
                }
            }
        }
        modules
    }
}

#[cfg(test)]
mod tests {
    use super::super::symbolizer::{NoSymbols, Table};
    use super::*;

    const KMODE: &str = include_str!("../../tests/fixtures/crash/c19-kmode.txt");
    const MANUAL: &str = include_str!("../../tests/fixtures/crash/c29-manual.txt");

    fn pdb() -> Table {
        Table::new(&[
            ("win32kfull.sys", 0xe9620, "xxxDwmStopRedirection"),
            ("win32kbase.sys", 0x760a0, "tagDomLock::LockUnInitialize"),
            ("win32kbase.sys", 0x41000, "UserThreadCallout_inner"),
            ("ntoskrnl.exe", 0x47af00, "kernel::ntos::ps::win32k_callout::thread_callout"),
            ("i8042prt.sys", 0x7200, "I8xProcessCrashDump"),
            ("i8042prt.sys", 0x6b00, "I8042KeyboardInterruptService"),
        ])
    }

    #[test]
    fn parses_stop_lines() {
        assert_eq!(parse_stop("*** STOP (KeBugCheckEx): 0x0000001e (0xc0000005, 0xfffff92040469655, 0x0, 0x0)"), Some((StopKind::BugCheck, 0x1e, [0xc0000005, 0xfffff92040469655, 0, 0])));
        assert_eq!(parse_stop("*** STOP (KeBugCheckEx aninhado): 0x0000007f (0x8, 0x0, 0x0, 0x0)").map(|stop| stop.0), Some(StopKind::Nested));
        assert_eq!(parse_stop("*** STOP: 0x000000e2 (0x0000000000000000, 0x0000000000000001, 0x0000000000000002, 0x0000000000000003)"), Some((StopKind::Early, 0xe2, [0, 1, 2, 3])));
        assert_eq!(parse_stop("*** STOP 0x1e"), None);
    }

    #[test]
    fn parses_locations() {
        assert_eq!(parse_location("win32kfull.sys+0xe9655 (xxxDwmStopRedirection+0x35)"), Some(Location { module: Some("win32kfull.sys".into()), offset: 0xe9655, export: Some("xxxDwmStopRedirection+0x35".into()) }));
        assert_eq!(parse_location(" ntoskrnl.exe+0x47afc3 "), Some(Location { module: Some("ntoskrnl.exe".into()), offset: 0x47afc3, export: None }));
        assert_eq!(parse_location("0xfffff80100001000"), Some(Location { module: None, offset: 0xfffff80100001000, export: None }));
        assert_eq!(parse_location("ilegivel"), None);
    }

    #[test]
    fn reads_the_exception_block() {
        let lines = serial::split(KMODE);
        let crash = find_last(&lines).expect("parada");
        assert_eq!((crash.stop.code, crash.stop.kind.clone(), crash.stops), (0x1e, StopKind::BugCheck, 1));
        assert_eq!(crash.stop_name.as_deref(), Some("KMODE_EXCEPTION_NOT_HANDLED"));
        assert_eq!(crash.failed_driver.as_deref(), Some("win32kfull.sys"));
        let block = crash.block.as_ref().expect("bloco");
        match &block.origin {
            Origin::Exception { code, address, location, access } => {
                assert_eq!((*code, *address), (0xc0000005, 0xfffff92040469655));
                assert_eq!(location.as_ref().and_then(|location| location.module.as_deref()), Some("win32kfull.sys"));
                assert_eq!(access.as_deref(), Some("leitura de 0x40"));
            }
            other => panic!("origem {other:?}"),
        }
        assert_eq!(block.frames.len(), 15);
        assert_eq!(block.frames[14], Location { module: Some("ntoskrnl.exe".into()), offset: 0x853430, export: None });
        assert_eq!(block.registers.len(), 2);
        assert_eq!(block.stack, "pilha (rsp 0xffffa00701cff0d0)");
        assert!(block.first_frame_exact && !block.is_return(0) && block.is_return(1));
        assert_eq!(block.modules(), ["win32kfull.sys", "win32kbase.sys", "win32k.sys", "ntoskrnl.exe"]);
    }

    #[test]
    fn summarizes_the_exception_with_the_pdb_names() {
        let lines = serial::split(KMODE);
        let images = serial::loaded_images(&lines, 0..lines.len());
        let crash = find_last(&lines).unwrap();
        let text = crash.summary(&images, &pdb());
        assert!(text.contains("codigo 0x0000001e KMODE_EXCEPTION_NOT_HANDLED"), "{text}");
        assert!(text.contains("  1 0x00000000c0000005  codigo da excecao: STATUS_ACCESS_VIOLATION"), "{text}");
        assert!(text.contains("  2 0xfffff92040469655  endereco da excecao: win32kfull.sys+0xe9655 (xxxDwmStopRedirection+0x35)"), "{text}");
        assert!(text.contains("onde parou: excecao 0xc0000005 (STATUS_ACCESS_VIOLATION) em win32kfull.sys+0xe9655 (xxxDwmStopRedirection+0x35), leitura de 0x40"), "{text}");
        assert!(text.contains("modulo culpado: win32kfull.sys (onde parou: "), "{text}");
        assert!(text.contains("componente provavel: subsistema Win32 de kernel"), "{text}");
        let stack = crash.stack(&pdb());
        // O nome do PDB troca o export do bloco; o retorno usa o byte da chamada.
        assert!(stack.contains("  #1  win32kbase.sys+0x7627e (tagDomLock::LockUnInitialize+0x1de)"), "{stack}");
        assert!(stack.contains("  #2  win32kbase.sys+0x4113a (UserThreadCallout_inner+0x13a)"), "{stack}");
        assert!(stack.contains("  #7  ntoskrnl.exe+0x47afc3 (kernel::ntos::ps::win32k_callout::thread_callout+0xc3)"), "{stack}");
        assert!(stack.contains("  #8  ntoskrnl.exe+0x4b59e4\n"), "{stack}");
        assert!(stack.contains("registradores:\n  rip=fffff92040469655"), "{stack}");
        // Sem símbolos ficam os exports que o kernel escreveu.
        let stack = crash.stack(&NoSymbols);
        assert!(stack.contains("  #1  win32kbase.sys+0x7627e (?LockUnInitialize@tagDomLock@@QEBAXXZ+0x1de)"), "{stack}");
    }

    #[test]
    fn the_manual_crash_points_at_the_keyboard_and_says_it_is_not_a_failure() {
        let lines = serial::split(MANUAL);
        let images = serial::loaded_images(&lines, 0..lines.len());
        let crash = find_last(&lines).unwrap();
        let block = crash.block.as_ref().unwrap();
        assert_eq!(block.origin, Origin::Call { callee: "KeBugCheckEx".into(), caller: Location { module: Some("i8042prt.sys".into()), offset: 0x72f0, export: None } });
        assert!(!block.first_frame_exact);
        let text = crash.summary(&images, &pdb());
        assert!(text.contains("codigo 0x000000e2 MANUALLY_INITIATED_CRASH"), "{text}");
        assert!(text.contains("onde parou: KeBugCheckEx, chamada de i8042prt.sys+0x72f0 (I8xProcessCrashDump+0xf0)"), "{text}");
        assert!(text.contains("modulo culpado: i8042prt.sys"), "{text}");
        assert!(text.contains("componente provavel: parada manual"), "{text}");
        assert_eq!(crash.modules(&images), ["i8042prt.sys", "ntoskrnl.exe"]);
    }

    #[test]
    fn a_kernel_fault_blames_the_first_frame_outside_the_kernel() {
        let lines = serial::split(
            "*** STOP (KeBugCheckEx): 0x0000003b (0xc0000005, 0xfffff80040123456, 0xffffa00701bbe000, 0x0)\n\
             [kcrash] excecao 0xc0000005 em 0xfffff80040123456 = ntoskrnl.exe+0x123456, escrita em 0x8\n\
             [kcrash] pilha (rsp 0xffffa00701bbf0b0): ntoskrnl.exe+0x123456 | hal.dll+0x1010 | Ntfs.sys+0x2000 | ntoskrnl.exe+0x10b5\n",
        );
        let crash = find_last(&lines).unwrap();
        let (location, return_address, reason) = crash.block.as_ref().unwrap().culprit().unwrap();
        assert_eq!((location.module.as_deref(), location.offset, return_address, reason), (Some("Ntfs.sys"), 0x2000, true, "primeiro quadro fora do kernel"));
        let text = crash.summary(&[], &NoSymbols);
        assert!(text.contains("componente provavel: sistema de arquivos NTFS"), "{text}");
        assert!(text.contains("SYSTEM_SERVICE_EXCEPTION"), "{text}");
    }

    #[test]
    fn a_kernel_exception_outside_the_dispatcher() {
        let lines = serial::split(
            "[OpenNT] kernel 64-bit vivo\n\
             \n\
             *** EXCECAO DE KERNEL: vetor 0x0e (falta de pagina) erro=0x2\n    RIP=0xfffff80040001234 CS=0x0010 RFLAGS=0x10246 RSP=0xffffa00000001000\n    CR2=0x0000000000000008\n    R8 =0x0000000000000001 R9 =0x0000000000000002\n\
             [kcrash] rip = ntoskrnl.exe+0x1234\n\
             [kcrash] pilha (rsp 0xffffa00000001000): ntoskrnl.exe+0x1234 | ntoskrnl.exe+0x5678\n\
             *** sistema parado ***\n",
        );
        let crash = find_last(&lines).unwrap();
        let StopKind::KernelException { description, registers } = &crash.stop.kind else { panic!("{:?}", crash.stop.kind) };
        assert_eq!(description, "vetor 0x0e (falta de pagina) erro=0x2");
        assert!(registers.contains(&("cr2".to_string(), 8)) && registers.contains(&("r8".to_string(), 1)));
        let symbols = Table::new(&[("ntoskrnl.exe", 0x1200, "kernel::ntos::mm::fault::resolve")]);
        let text = crash.summary(&[], &symbols);
        assert!(text.contains("excecao de kernel fora do despacho: vetor 0x0e"), "{text}");
        assert!(text.contains("  cr2 0x0000000000000008"), "{text}");
        assert!(text.contains("onde parou: rip em ntoskrnl.exe+0x1234 (kernel::ntos::mm::fault::resolve+0x34)"), "{text}");
        assert!(text.contains("componente provavel: kernel do OpenNT (kernel/src/ntos/mm)"), "{text}");
    }

    #[test]
    fn components() {
        assert_eq!(component("dxgkrnl.sys", None), "nucleo grafico DirectX (dxgkrnl: adaptadores, VidPn e apresentacao)");
        assert_eq!(component("ntoskrnl.exe", Some("<kernel::ntos::ob::Object as core::ops::Drop>::drop+0x10")), "kernel do OpenNT (kernel/src/ntos/ob)");
        assert_eq!(component("ntoskrnl.exe", Some("kernel::hal::amd64::irqstubs::entry")), "kernel do OpenNT (kernel/src/hal/amd64)");
        assert_eq!(component("ntoskrnl.exe", None), "kernel do OpenNT");
        assert_eq!(component("foo.sys", None), "driver foo.sys");
    }
}
