//! Filtro das exceções do anel 3 por código (`monitor sx`): para cada
//! código, se a primeira chance e a segunda chance param a máquina.
//!
//! O ntoskrnl 19041 decide a primeira chance no KdpReport (0x511924): sem
//! FLG_STOP_ON_EXCEPTION no NtGlobalFlag só STATUS_BREAKPOINT,
//! STATUS_SINGLE_STEP, STATUS_ASSERTION_FAILURE e os dois do WX86 chegam ao
//! host; com a flag, qualquer código chega, menos os informativos até
//! 0x4000001D, o STATUS_PORT_DISCONNECTED e os positivos a partir de
//! 0x40000020 (o DBG_PRINTEXCEPTION_C 0x40010006 do OutputDebugString e o
//! 0x406D1388 do nome de thread do MSVC). A segunda chance de uma exceção
//! de usuário vai ao DbgkForwardException (0x732460), à porta de depuração
//! do processo e depois à de exceção; o KdTrap não a vê. O host do NT
//! escolhe por código o que de fato para (o `sxe`/`sxd`/`sxi` do WinDbg).
//!
//! No OpenNT a escolha fica no alvo, para não trocar pacotes por exceção: o
//! `monitor uex on` é o FLG_STOP_ON_EXCEPTION (com a regra de exclusão do
//! KdpReport), e uma entrada da tabela vale por cima dele para o seu código.
//! A segunda chance para quando a entrada pede; sem entrada, não para (o
//! processo termina como antes). Os breakpoints e passos do próprio
//! depurador não passam por aqui. Sem host anexado nada para.
//!
//! A tabela tem 32 entradas e só o dono da parada a muda.

use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

/// Escolha de uma chance para um código.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Choice {
    /// Sem escolha: vale a regra geral.
    Default,
    /// Para a máquina.
    Break,
    /// Segue sem parar.
    Ignore,
}

impl Choice {
    fn code(self) -> u8 {
        match self {
            Choice::Default => 0,
            Choice::Break => 1,
            Choice::Ignore => 2,
        }
    }

    fn from_code(code: u8) -> Self {
        match code {
            1 => Choice::Break,
            2 => Choice::Ignore,
            _ => Choice::Default,
        }
    }

    fn text(self) -> &'static str {
        match self {
            Choice::Default => "padrao",
            Choice::Break => "para",
            Choice::Ignore => "segue",
        }
    }
}

/// Os códigos de fim imediato do processo: o `__fastfail` (int 0x29), o
/// RaiseFailFastException e a exceção guardada (stowed) do WinRT.
pub const FAIL_FAST_CODES: [u32; 3] = [STATUS_STACK_BUFFER_OVERRUN, STATUS_FAIL_FAST_EXCEPTION, STATUS_STOWED_EXCEPTION];

pub const STATUS_STACK_BUFFER_OVERRUN: u32 = 0xC000_0409;
pub const STATUS_FAIL_FAST_EXCEPTION: u32 = 0xC000_0602;
pub const STATUS_STOWED_EXCEPTION: u32 = 0xC000_027B;
/// STATUS_PORT_DISCONNECTED, que o KdpReport não relata.
const STATUS_PORT_DISCONNECTED: u32 = 0xC000_0037;

const SLOTS: usize = 32;

struct Entry {
    /// 0 = livre (o código 0 é STATUS_SUCCESS, nunca uma exceção).
    code: AtomicU32,
    first: AtomicU8,
    second: AtomicU8,
    /// Paradas e passagens deste código desde a entrada.
    stops: AtomicU32,
    passed: AtomicU32,
}

impl Entry {
    const fn new() -> Self {
        Self { code: AtomicU32::new(0), first: AtomicU8::new(0), second: AtomicU8::new(0), stops: AtomicU32::new(0), passed: AtomicU32::new(0) }
    }
}

static ENTRIES: [Entry; SLOTS] = [const { Entry::new() }; SLOTS];
/// Exceções de usuário vistas sem entrada e sem parada.
static OTHERS_PASSED: AtomicU32 = AtomicU32::new(0);

fn find(code: u32) -> Option<&'static Entry> {
    if code == 0 {
        return None;
    }
    ENTRIES.iter().find(|entry| entry.code.load(Ordering::Acquire) == code)
}

/// Grava a escolha das duas chances de `code`; `false` sem entrada livre.
pub fn set(code: u32, first: Choice, second: Choice) -> bool {
    if code == 0 {
        return false;
    }
    let entry = match find(code) {
        Some(entry) => entry,
        None => {
            let Some(free) = ENTRIES.iter().find(|entry| entry.code.load(Ordering::Acquire) == 0) else { return false };
            free.stops.store(0, Ordering::Relaxed);
            free.passed.store(0, Ordering::Relaxed);
            free
        }
    };
    entry.first.store(first.code(), Ordering::Relaxed);
    entry.second.store(second.code(), Ordering::Relaxed);
    entry.code.store(code, Ordering::Release);
    true
}

/// Tira a entrada de `code`.
pub fn remove(code: u32) -> bool {
    match find(code) {
        Some(entry) => {
            entry.code.store(0, Ordering::Release);
            true
        }
        None => false,
    }
}

/// Tira todas as entradas (o host se desligou ou pediu `sx clear`).
pub fn clear() {
    for entry in ENTRIES.iter() {
        entry.code.store(0, Ordering::Release);
    }
    OTHERS_PASSED.store(0, Ordering::Relaxed);
}

/// A escolha de cada chance para `code`.
pub fn choices(code: u32) -> (Choice, Choice) {
    find(code).map_or((Choice::Default, Choice::Default), |entry| (Choice::from_code(entry.first.load(Ordering::Relaxed)), Choice::from_code(entry.second.load(Ordering::Relaxed))))
}

/// O KdpReport com FLG_STOP_ON_EXCEPTION: o código chega ao host na
/// primeira chance.
pub fn reportable_first_chance(code: u32) -> bool {
    code > 0x4000_001D && code != STATUS_PORT_DISCONNECTED && (code as i32) < 0x4000_0020
}

/// A primeira chance de `code` para a máquina? `stop_on_all` é o `uex on`.
pub fn first_chance(code: u32, stop_on_all: bool) -> bool {
    match choices(code).0 {
        Choice::Break => true,
        Choice::Ignore => false,
        Choice::Default => stop_on_all && reportable_first_chance(code),
    }
}

/// A segunda chance (ou o fim do processo com o código) para a máquina?
pub fn second_chance(code: u32) -> bool {
    choices(code).1 == Choice::Break
}

/// Conta a decisão tomada para `code` (o `monitor sx` mostra).
pub fn count(code: u32, stopped: bool) {
    match find(code) {
        Some(entry) => {
            let counter = if stopped { &entry.stops } else { &entry.passed };
            counter.fetch_add(1, Ordering::Relaxed);
        }
        None if !stopped => {
            OTHERS_PASSED.fetch_add(1, Ordering::Relaxed);
        }
        None => {}
    }
}

/// O nome de um código conhecido.
pub fn name(code: u32) -> Option<&'static str> {
    Some(match code {
        0x4000_0015 => "STATUS_FATAL_APP_EXIT",
        0x4001_0006 => "DBG_PRINTEXCEPTION_C",
        0x406D_1388 => "MS_VC_EXCEPTION (nome de thread)",
        0x8000_0001 => "STATUS_GUARD_PAGE_VIOLATION",
        0x8000_0002 => "STATUS_DATATYPE_MISALIGNMENT",
        0x8000_0003 => "STATUS_BREAKPOINT",
        0x8000_0004 => "STATUS_SINGLE_STEP",
        0xC000_0005 => "STATUS_ACCESS_VIOLATION",
        0xC000_0006 => "STATUS_IN_PAGE_ERROR",
        0xC000_0008 => "STATUS_INVALID_HANDLE",
        0xC000_001D => "STATUS_ILLEGAL_INSTRUCTION",
        0xC000_0025 => "STATUS_NONCONTINUABLE_EXCEPTION",
        0xC000_0026 => "STATUS_INVALID_DISPOSITION",
        0xC000_008C => "STATUS_ARRAY_BOUNDS_EXCEEDED",
        0xC000_008E => "STATUS_FLOAT_DIVIDE_BY_ZERO",
        0xC000_0094 => "STATUS_INTEGER_DIVIDE_BY_ZERO",
        0xC000_0095 => "STATUS_INTEGER_OVERFLOW",
        0xC000_0096 => "STATUS_PRIVILEGED_INSTRUCTION",
        0xC000_00FD => "STATUS_STACK_OVERFLOW",
        0xC000_0135 => "STATUS_DLL_NOT_FOUND",
        0xC000_0139 => "STATUS_ENTRYPOINT_NOT_FOUND",
        0xC000_0142 => "STATUS_DLL_INIT_FAILED",
        0xC000_0194 => "STATUS_POSSIBLE_DEADLOCK",
        STATUS_STOWED_EXCEPTION => "STATUS_STOWED_EXCEPTION",
        0xC000_0374 => "STATUS_HEAP_CORRUPTION",
        STATUS_STACK_BUFFER_OVERRUN => "STATUS_STACK_BUFFER_OVERRUN (fast fail)",
        0xC000_0417 => "STATUS_INVALID_CRUNTIME_PARAMETER",
        0xC000_041D => "STATUS_FATAL_USER_CALLBACK_EXCEPTION",
        0xC000_0420 => "STATUS_ASSERTION_FAILURE",
        STATUS_FAIL_FAST_EXCEPTION => "STATUS_FAIL_FAST_EXCEPTION",
        0xE06D_7363 => "excecao C++ do MSVC",
        0xC06D_007E => "VcppException (modulo nao encontrado)",
        0xC06D_007F => "VcppException (procedimento nao encontrado)",
        _ => return None,
    })
}

/// O código de uma palavra do `monitor sx` (hexadecimal, com ou sem 0x).
pub fn parse_code(word: &str) -> Option<u32> {
    let text = word.trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(text, 16).ok().filter(|&code| code != 0)
}

/// `sx [e|d|i|r] <código|failfast> | sx clear`: `e` para nas duas chances,
/// `d` só na segunda (e no fim do processo com o código), `i` segue nas
/// duas, `r` tira a entrada; sem argumento, a tabela.
pub fn command(argument: &str, out: &mut super::packet::Payload) {
    use core::fmt::Write;
    const USAGE: &str = "uso: sx [e|d|i|r] <codigo em hexadecimal|failfast> | sx clear\n";
    let mut words = argument.split_whitespace();
    let verb = words.next().unwrap_or("");
    let target = words.next().unwrap_or("");
    if verb == "clear" {
        clear();
    } else if !verb.is_empty() {
        let single;
        let codes: &[u32] = if target.eq_ignore_ascii_case("failfast") {
            &FAIL_FAST_CODES
        } else if let Some(code) = parse_code(target) {
            single = [code];
            &single
        } else {
            out.push_str(USAGE);
            return;
        };
        for &code in codes {
            let done = match verb {
                "e" => set(code, Choice::Break, Choice::Break),
                "d" => set(code, Choice::Default, Choice::Break),
                "i" => set(code, Choice::Ignore, Choice::Ignore),
                "r" => {
                    remove(code);
                    true
                }
                _ => {
                    out.push_str(USAGE);
                    return;
                }
            };
            if !done {
                let _ = writeln!(out, "{:#010x}: tabela cheia ({} entradas)", code, SLOTS);
            }
        }
    }
    let mut any = false;
    for entry in ENTRIES.iter() {
        let code = entry.code.load(Ordering::Acquire);
        if code == 0 {
            continue;
        }
        any = true;
        let (first, second) = choices(code);
        let _ = writeln!(
            out,
            "{:08x}  primeira chance: {:<6} segunda chance: {:<6} paradas {} ignoradas {}  {}",
            code,
            first.text(),
            second.text(),
            entry.stops.load(Ordering::Relaxed),
            entry.passed.load(Ordering::Relaxed),
            name(code).unwrap_or("")
        );
    }
    if !any {
        out.push_str("nenhuma entrada (a primeira chance segue o uex; a segunda chance nao para)\n");
    }
    let _ = writeln!(out, "outras excecoes passadas sem parar: {}", OTHERS_PASSED.load(Ordering::Relaxed));
}
