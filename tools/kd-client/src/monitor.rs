//! As tabelas das consultas do OpenNT (`qRcmd`, `kernel/src/ntos/kd/
//! monitor.rs`) em estruturas: `ps`, `threads`, `lm`, `cpus` e `context`.
//! Linhas que não seguem o formato (cabeçalho, avisos de lista ocupada)
//! ficam de fora.

use super::parse_number;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Process {
    pub pid: u64,
    pub eprocess: u64,
    pub cr3: u64,
    pub threads: u64,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Thread {
    pub pid: u64,
    pub tid: u64,
    pub ethread: u64,
    pub state: String,
    pub start: u64,
    pub process: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedModule {
    pub base: u64,
    pub end: u64,
    pub name: String,
    pub path: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Processor {
    pub number: u64,
    /// O dono da parada (`*` na tabela).
    pub owner: bool,
    pub irql: u64,
    pub pcr: u64,
    pub thread: u64,
    pub rip: u64,
    pub process: String,
}

/// Registradores de uma thread pelo `context`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadContext {
    /// A primeira linha (ETHREAD, estado, onde estão os registradores).
    pub header: String,
    /// A thread roda num processador parado: os registradores completos são
    /// os da thread do protocolo dele.
    pub processor: Option<u64>,
    /// `nome=valor` na ordem do texto (rip, rsp, rflags, r15...).
    pub registers: Vec<(String, u64)>,
}

impl ThreadContext {
    pub fn register(&self, name: &str) -> Option<u64> {
        self.registers.iter().find(|(register, _)| register == name).map(|(_, value)| *value)
    }
}

fn rest_after(line: &str, fields: usize) -> String {
    let mut rest = line.trim_start();
    for _ in 0..fields {
        rest = rest.trim_start();
        rest = rest.find(char::is_whitespace).map_or("", |index| &rest[index..]);
    }
    rest.trim().to_string()
}

pub fn processes(text: &str) -> Vec<Process> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 || !fields[1].starts_with("0x") {
                return None;
            }
            Some(Process { pid: parse_number(fields[0])?, eprocess: parse_number(fields[1])?, cr3: parse_number(fields[2])?, threads: parse_number(fields[3])?, name: rest_after(line, 4) })
        })
        .collect()
}

pub fn threads(text: &str) -> Vec<Thread> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 5 || !fields[2].starts_with("0x") {
                return None;
            }
            Some(Thread { pid: parse_number(fields[0])?, tid: parse_number(fields[1])?, ethread: parse_number(fields[2])?, state: fields[3].to_string(), start: parse_number(fields[4])?, process: rest_after(line, 5) })
        })
        .collect()
}

pub fn modules(text: &str) -> Vec<LoadedModule> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                return None;
            }
            Some(LoadedModule { base: parse_number(fields[0])?, end: parse_number(fields[1])?, name: fields[2].to_string(), path: rest_after(line, 3) })
        })
        .collect()
}

pub fn processors(text: &str) -> Vec<Processor> {
    text.lines()
        .filter_map(|line| {
            let owner = line.trim_start().starts_with('*');
            let line = line.trim_start().trim_start_matches('*');
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 5 || !fields[2].starts_with("0x") {
                return None;
            }
            Some(Processor { number: parse_number(fields[0])?, owner, irql: parse_number(fields[1])?, pcr: parse_number(fields[2])?, thread: parse_number(fields[3])?, rip: parse_number(fields[4])?, process: rest_after(line, 5) })
        })
        .collect()
}

pub fn thread_context(text: &str) -> Option<ThreadContext> {
    let header = text.lines().next()?.trim().to_string();
    let processor = header.split_once("roda na CPU ").and_then(|(_, rest)| rest.split(|character: char| !character.is_ascii_digit()).next()).and_then(parse_number);
    let registers: Vec<(String, u64)> = text
        .split_whitespace()
        .filter_map(|word| {
            let (name, value) = word.split_once('=')?;
            Some((name.to_string(), parse_number(value)?))
        })
        .collect();
    registers.iter().any(|(name, _)| name == "rip").then_some(ThreadContext { header, processor, registers })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ps_and_threads() {
        let ps = "   PID           EPROCESS                CR3 threads  nome\n     4 0xffffe00000001000           0x1ab000      12  System\n   100 0xffffe00000042000           0x2cd000       3  smss.exe\n";
        let list = processes(ps);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0], Process { pid: 4, eprocess: 0xffffe00000001000, cr3: 0x1ab000, threads: 12, name: "System".into() });
        assert_eq!(list[1].name, "smss.exe");
        let threads_text = "   PID    TID            ETHREAD estado                    inicio  processo\n     4      8 0xffffe00000003000 Waiting       0xfffff80040123456  System\n";
        let list = threads(threads_text);
        assert_eq!(list, vec![Thread { pid: 4, tid: 8, ethread: 0xffffe00000003000, state: "Waiting".into(), start: 0xfffff80040123456, process: "System".into() }]);
        assert!(processes("lista de processos ocupada (trava tomada no codigo interrompido)\n").is_empty());
    }

    #[test]
    fn parses_lm_and_cpus() {
        let lm = "              base                fim  nome             caminho\n0xfffff80040000000 0xfffff80041000000  ntoskrnl.exe     \\SystemRoot\\System32\\ntoskrnl.exe\n0xfffff80042000000 0xfffff80042010000  ksecdd.sys       \\SystemRoot\\System32\\Drivers\\ksecdd.sys\n";
        let list = modules(lm);
        assert_eq!(list.len(), 2);
        assert_eq!(list[1], LoadedModule { base: 0xfffff80042000000, end: 0xfffff80042010000, name: "ksecdd.sys".into(), path: "\\SystemRoot\\System32\\Drivers\\ksecdd.sys".into() });
        let cpus = "CPU IRQL               KPCR             thread                RIP  processo\n* 0    0 0xfffff80040500000 0xffffe00000003000 0xfffff80040101000  System\n  1    2 0xfffff80040600000                0x0 0xfffff80040102000  \n";
        let list = processors(cpus);
        assert_eq!(list.len(), 2);
        assert!(list[0].owner);
        assert_eq!(list[0].number, 0);
        assert_eq!(list[0].process, "System");
        assert!(!list[1].owner);
        assert_eq!(list[1].irql, 2);
        assert_eq!(list[1].thread, 0);
        assert_eq!(list[1].process, "");
    }

    #[test]
    fn parses_context() {
        let off_cpu = "ETHREAD 0xffffe00000003000 estado Waiting quadro de troca em 0xffff800000101e00\nrip=0xfffff80040111111 rsp=0xffff800000101f00 rflags=0x246 r15=0x0 r14=0x1 r13=0x2 r12=0x3 rsi=0x4 rdi=0x5 rbx=0x6 rbp=0xffff800000101f40\n";
        let context = thread_context(off_cpu).unwrap();
        assert_eq!(context.processor, None);
        assert_eq!(context.register("rip"), Some(0xfffff80040111111));
        assert_eq!(context.register("rbp"), Some(0xffff800000101f40));
        assert_eq!(context.registers.len(), 11);
        let running = "ETHREAD 0xffffe00000003000 roda na CPU 2: registradores da thread 3 do protocolo\nrip=0x1 rsp=0x2 rbp=0x3\n";
        assert_eq!(thread_context(running).unwrap().processor, Some(2));
        assert!(thread_context("uso: context <ETHREAD em hexadecimal>\n").is_none());
    }
}
