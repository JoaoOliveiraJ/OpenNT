//! Os processos de usuário no depurador do kernel: as tabelas das
//! consultas `.process`, `handles`, `vad`, `uthreads` e `kmap` do alvo em
//! estruturas, a lista de módulos da PEB (PEB.Ldr, InLoadOrderModuleList),
//! os registradores de um CONTEXT salvo e o texto das proteções de página.
//!
//! Layouts do x64 (19041): PEB.Ldr em 0x18; PEB_LDR_DATA.InLoadOrderModuleList
//! em 0x10; LDR_DATA_TABLE_ENTRY com InLoadOrderLinks em 0, DllBase em
//! 0x30, EntryPoint em 0x38, SizeOfImage em 0x40, FullDllName em 0x48 e
//! BaseDllName em 0x58; CONTEXT com os inteiros de 0x78 a 0xF0, RIP em
//! 0xF8, RSP em 0x98 e EFlags em 0x44.

use super::parse_number;
use super::unwind::ReadMemory;

/// O processo das leituras (`.process`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessContext {
    pub eprocess: u64,
    pub pid: u64,
    pub cr3: u64,
    pub peb: u64,
    pub name: String,
}

/// Um módulo da PEB.Ldr de um processo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserModule {
    pub base: u64,
    pub size: u64,
    pub entry: u64,
    /// O BaseDllName (`ntdll.dll`).
    pub name: String,
    /// O FullDllName (`C:\Windows\System32\ntdll.dll`).
    pub path: String,
}

/// Uma thread de usuário (`uthreads`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserThread {
    pub tid: u64,
    pub ethread: u64,
    pub teb: u64,
    pub start: u64,
    /// O CONTEXT salvo da thread (memória do kernel).
    pub context: u64,
    pub rip: u64,
    pub rsp: u64,
    pub state: String,
    pub wait_reason: String,
    pub last_error: Option<u64>,
}

/// Uma entrada da tabela de handles (`handles`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handle {
    pub handle: u64,
    pub object: u64,
    pub access: u64,
    pub kind: String,
    pub name: String,
}

/// Uma região de usuário (`vad`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Region {
    pub base: u64,
    pub size: u64,
    /// Private, Mapped ou Image.
    pub kind: String,
    pub protect: u32,
    pub allocation_protect: u32,
    pub name: String,
}

/// Uma faixa do espaço de sistema (`kmap`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelRange {
    pub start: u64,
    pub end: u64,
    pub name: String,
}

fn rest_after(line: &str, fields: usize) -> String {
    let mut rest = line.trim_start();
    for _ in 0..fields {
        rest = rest.trim_start();
        rest = rest.find(char::is_whitespace).map_or("", |index| &rest[index..]);
    }
    rest.trim().to_string()
}

/// A resposta do `.process`: o processo escolhido.
pub fn parse_process_context(text: &str) -> Option<ProcessContext> {
    let line = text.lines().find(|line| line.contains("EPROCESS") && line.contains("CR3"))?;
    let words: Vec<&str> = line.split_whitespace().collect();
    let after = |key: &str| words.iter().position(|word| *word == key).and_then(|index| words.get(index + 1)).and_then(|value| parse_number(value));
    Some(ProcessContext { eprocess: after("EPROCESS")?, pid: after("PID").unwrap_or(0), cr3: after("CR3")?, peb: after("PEB").unwrap_or(0), name: String::new() })
}

/// O processo do CR3 do processador (`.process` sem argumento).
pub fn parse_current_process(text: &str) -> Option<(u64, u64)> {
    let line = text.lines().find(|line| line.starts_with("processo do CR3 do processador: EPROCESS"))?;
    let words: Vec<&str> = line.split_whitespace().collect();
    let after = |key: &str| words.iter().position(|word| *word == key).and_then(|index| words.get(index + 1)).and_then(|value| parse_number(value));
    Some((after("EPROCESS")?, after("PID")?))
}

/// A continuação de uma tabela paginada (`mais: N`).
pub fn next_page(text: &str) -> Option<u64> {
    text.lines().find_map(|line| line.trim().strip_prefix("mais: ")).and_then(parse_number)
}

pub fn parse_handles(text: &str) -> Vec<Handle> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 || !fields[0].starts_with("0x") || !fields[1].starts_with("0x") {
                return None;
            }
            Some(Handle { handle: parse_number(fields[0])?, object: parse_number(fields[1])?, access: parse_number(fields[2])?, kind: fields[3].to_string(), name: rest_after(line, 4) })
        })
        .collect()
}

pub fn parse_regions(text: &str) -> Vec<Region> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 5 || !fields[0].starts_with("0x") || !fields[1].starts_with("0x") {
                return None;
            }
            Some(Region {
                base: parse_number(fields[0])?,
                size: parse_number(fields[1])?,
                kind: fields[2].to_string(),
                protect: parse_number(fields[3])? as u32,
                allocation_protect: parse_number(fields[4])? as u32,
                name: rest_after(line, 5),
            })
        })
        .collect()
}

pub fn parse_user_threads(text: &str) -> Vec<UserThread> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 || !fields[1].starts_with("0x") {
                return None;
            }
            Some(UserThread {
                tid: parse_number(fields[0])?,
                ethread: parse_number(fields[1])?,
                teb: parse_number(fields[2])?,
                start: parse_number(fields[3])?,
                context: parse_number(fields[4])?,
                rip: parse_number(fields[5])?,
                rsp: parse_number(fields[6])?,
                state: fields[7].to_string(),
                wait_reason: fields[8].to_string(),
                last_error: parse_number(fields[9]),
            })
        })
        .collect()
}

pub fn parse_kernel_map(text: &str) -> Vec<KernelRange> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 3 || !fields[0].starts_with("0x") {
                return None;
            }
            Some(KernelRange { start: parse_number(fields[0])?, end: parse_number(fields[1])?, name: rest_after(line, 2) })
        })
        .collect()
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes.get(offset..offset + 8).map(|slice| u64::from_le_bytes(slice.try_into().unwrap_or([0; 8])))
}

/// Uma UNICODE_STRING (`bytes` = os 16 bytes dela) lida pela memória.
pub fn read_unicode(memory: &mut dyn ReadMemory, bytes: &[u8]) -> Option<String> {
    let length = u16::from_le_bytes(bytes.get(0..2)?.try_into().ok()?) as usize;
    let buffer = u64_at(bytes, 8)?;
    if length == 0 || buffer == 0 || length > 0x1000 {
        return Some(String::new());
    }
    let data = memory.read(buffer, length).ok()?;
    let units: Vec<u16> = data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    Some(String::from_utf16_lossy(&units))
}

/// A lista de módulos da PEB (InLoadOrderModuleList), pela memória do
/// processo (o `.process` escolhido).
pub fn read_loader_list(memory: &mut dyn ReadMemory, peb: u64) -> Result<Vec<UserModule>, String> {
    let ldr = memory.read(peb + 0x18, 8).ok().and_then(|bytes| u64_at(&bytes, 0)).ok_or_else(|| format!("PEB {peb:#x} ilegivel"))?;
    if ldr == 0 {
        return Err(format!("PEB {peb:#x} sem Ldr (o loader ainda nao rodou)"));
    }
    let head = ldr + 0x10;
    let mut entry = memory.read(head, 8).ok().and_then(|bytes| u64_at(&bytes, 0)).ok_or_else(|| format!("PEB_LDR_DATA {ldr:#x} ilegivel"))?;
    let mut modules = Vec::new();
    while entry != head && entry != 0 && modules.len() < 512 {
        let Ok(bytes) = memory.read(entry, 0x68) else { break };
        if bytes.len() < 0x68 {
            break;
        }
        let base = u64_at(&bytes, 0x30).unwrap_or(0);
        if base != 0 {
            let path = read_unicode(memory, &bytes[0x48..0x58]).unwrap_or_default();
            let mut name = read_unicode(memory, &bytes[0x58..0x68]).unwrap_or_default();
            if name.is_empty() {
                name = super::symbols::base_name(&path).to_string();
            }
            modules.push(UserModule { base, size: u64_at(&bytes, 0x40).unwrap_or(0) & 0xFFFF_FFFF, entry: u64_at(&bytes, 0x38).unwrap_or(0), name, path });
        }
        entry = u64_at(&bytes, 0).unwrap_or(0);
    }
    Ok(modules)
}

/// Os registradores de um CONTEXT do x64 (0x4D0 bytes).
pub fn context_registers(bytes: &[u8]) -> Vec<(&'static str, u64)> {
    const INTEGER: [(&str, usize); 18] = [
        ("rax", 0x78),
        ("rcx", 0x80),
        ("rdx", 0x88),
        ("rbx", 0x90),
        ("rsp", 0x98),
        ("rbp", 0xA0),
        ("rsi", 0xA8),
        ("rdi", 0xB0),
        ("r8", 0xB8),
        ("r9", 0xC0),
        ("r10", 0xC8),
        ("r11", 0xD0),
        ("r12", 0xD8),
        ("r13", 0xE0),
        ("r14", 0xE8),
        ("r15", 0xF0),
        ("rip", 0xF8),
        ("eflags", 0x44),
    ];
    INTEGER
        .iter()
        .filter_map(|(name, offset)| {
            let value = if *name == "eflags" { bytes.get(*offset..*offset + 4).map(|slice| u32::from_le_bytes(slice.try_into().unwrap_or([0; 4])) as u64) } else { u64_at(bytes, *offset) };
            value.map(|value| (*name, value))
        })
        .collect()
}

/// O texto de uma proteção de página do NT (PAGE_*): `RWX`, `R-X`, com
/// `G` (guarda) e `NC` (sem cache).
pub fn protection_text(protect: u32) -> String {
    let base = match protect & 0xFF {
        0x01 => "---",
        0x02 => "R--",
        0x04 => "RW-",
        0x08 => "RW- (CoW)",
        0x10 => "--X",
        0x20 => "R-X",
        0x40 => "RWX",
        0x80 => "RWX (CoW)",
        0 => "",
        _ => "?",
    };
    let mut text = base.to_string();
    if protect & 0x100 != 0 {
        text.push_str(" G");
    }
    if protect & 0x200 != 0 {
        text.push_str(" NC");
    }
    text
}

/// O texto das características de uma seção de PE (leitura, escrita,
/// execução).
pub fn section_protection(characteristics: u32) -> String {
    let read = characteristics & 0x4000_0000 != 0;
    let write = characteristics & 0x8000_0000 != 0;
    let execute = characteristics & 0x2000_0000 != 0;
    format!("{}{}{}", if read { 'R' } else { '-' }, if write { 'W' } else { '-' }, if execute { 'X' } else { '-' })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Memory(HashMap<u64, u8>);

    impl Memory {
        fn put(&mut self, address: u64, bytes: &[u8]) {
            for (index, byte) in bytes.iter().enumerate() {
                self.0.insert(address + index as u64, *byte);
            }
        }

        fn put_unicode(&mut self, at: u64, buffer: u64, text: &str) {
            let units: Vec<u8> = text.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
            let mut string = vec![0u8; 16];
            string[0..2].copy_from_slice(&(units.len() as u16).to_le_bytes());
            string[2..4].copy_from_slice(&(units.len() as u16 + 2).to_le_bytes());
            string[8..16].copy_from_slice(&buffer.to_le_bytes());
            self.put(at, &string);
            self.put(buffer, &units);
        }
    }

    impl ReadMemory for Memory {
        fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
            (0..length as u64).map(|offset| self.0.get(&(address + offset)).copied().ok_or_else(|| format!("{address:#x}"))).collect()
        }
    }

    #[test]
    fn walks_the_loader_list() {
        let mut memory = Memory(HashMap::new());
        let peb = 0x7ff0_0000u64;
        let ldr = 0x7ff1_0000u64;
        let first = 0x7ff2_0000u64;
        let second = 0x7ff2_1000u64;
        memory.put(peb + 0x18, &ldr.to_le_bytes());
        memory.put(ldr + 0x10, &first.to_le_bytes());
        for (entry, next, base, size, name, path) in [(first, second, 0x7ff6_0000_0000u64, 0x1f0000u64, "csrss.exe", "C:\\Windows\\system32\\csrss.exe"), (second, ldr + 0x10, 0x7ffd_0000_0000, 0x1f5000, "ntdll.dll", "C:\\Windows\\SYSTEM32\\ntdll.dll")] {
            let mut bytes = vec![0u8; 0x68];
            bytes[0..8].copy_from_slice(&next.to_le_bytes());
            bytes[0x30..0x38].copy_from_slice(&base.to_le_bytes());
            bytes[0x38..0x40].copy_from_slice(&(base + 0x1000).to_le_bytes());
            bytes[0x40..0x48].copy_from_slice(&size.to_le_bytes());
            memory.put(entry, &bytes);
            memory.put_unicode(entry + 0x48, entry + 0x200, path);
            memory.put_unicode(entry + 0x58, entry + 0x400, name);
        }
        let modules = read_loader_list(&mut memory, peb).unwrap();
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].name, "csrss.exe");
        assert_eq!(modules[1], UserModule { base: 0x7ffd_0000_0000, size: 0x1f5000, entry: 0x7ffd_0000_1000, name: "ntdll.dll".into(), path: "C:\\Windows\\SYSTEM32\\ntdll.dll".into() });
        assert!(read_loader_list(&mut memory, 0x1234).is_err());
    }

    #[test]
    fn parses_tables() {
        let process = "processo das leituras: EPROCESS 0xffffa00000123000 PID 412 CR3 0x1b2000 PEB 0x3a1000\n";
        assert_eq!(parse_process_context(process), Some(ProcessContext { eprocess: 0xffffa00000123000, pid: 412, cr3: 0x1b2000, peb: 0x3a1000, name: String::new() }));
        let current = "processo das leituras: o do processador (CR3 0x1b2000)\nprocesso do CR3 do processador: EPROCESS 0xffffa00000123000 PID 412\n";
        assert_eq!(parse_current_process(current), Some((0xffffa00000123000, 412)));
        assert_eq!(parse_process_context(current), None);
        let handles = "EPROCESS 0xffffa00000123000 HANDLE_TABLE 0xffffa00000200000 TableCode 0xffffa00000300000 entradas 40\n  handle             objeto     acesso tipo             nome\n     0x4 0xffffa00000400030   0x1f0003 Event            \\KernelObjects\\X\n     0x8 0xffffa00000500030   0x100020 File             \\Windows\\System32\nmais: 120\n";
        let list = parse_handles(handles);
        assert_eq!(list.len(), 2);
        assert_eq!(list[1], Handle { handle: 8, object: 0xffffa00000500030, access: 0x100020, kind: "File".into(), name: "\\Windows\\System32".into() });
        assert_eq!(next_page(handles), Some(120));
        let regions = "EPROCESS 0x1 regioes 2\n              base      tamanho tipo     protecao alocacao  nome\n    0x7ff600000000     0x1f0000 Image        0x0     0x80  \\Windows\\System32\\csrss.exe\n          0x200000      0x10000 Private      0x4      0x4  \n";
        let list = parse_regions(regions);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].kind, "Image");
        assert_eq!(list[1].protect, 4);
        assert_eq!(list[1].name, "");
        let threads = "EPROCESS 0x1 CR3 0x2\n   TID ETHREAD TEB inicio CONTEXT rip rsp estado espera LastError\n   416 0xffffa00000600000 0x3a3000 0x7ffd00001000 0xffffa00000700000 0x7ffd00002000 0x8fe00 Waiting UserRequest 0x0\n";
        let list = parse_user_threads(threads);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].wait_reason, "UserRequest");
        assert_eq!(list[0].last_error, Some(0));
        let map = "            inicio                fim  faixa\n           0x10000     0x7fffffff0000  metade de usuario\n";
        assert_eq!(parse_kernel_map(map), vec![KernelRange { start: 0x10000, end: 0x7fffffff0000, name: "metade de usuario".into() }]);
    }

    #[test]
    fn registers_and_protections() {
        let mut context = vec![0u8; 0x4D0];
        context[0xF8..0x100].copy_from_slice(&0x7ffd_1234u64.to_le_bytes());
        context[0x98..0xA0].copy_from_slice(&0x8f000u64.to_le_bytes());
        context[0x44..0x48].copy_from_slice(&0x246u32.to_le_bytes());
        let registers = context_registers(&context);
        assert!(registers.contains(&("rip", 0x7ffd_1234)));
        assert!(registers.contains(&("rsp", 0x8f000)));
        assert!(registers.contains(&("eflags", 0x246)));
        assert_eq!(protection_text(0x20), "R-X");
        assert_eq!(protection_text(0x104), "RW- G");
        assert_eq!(section_protection(0x6000_0020), "R-X");
        assert_eq!(section_protection(0xC000_0040), "RW-");
    }
}
