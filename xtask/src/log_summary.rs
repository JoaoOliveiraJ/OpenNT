//! `cargo xtask logsum`: o resumo compacto de um log da serial (COM1).
//!
//! ```text
//! cargo xtask logsum SERIAL.LOG [--since=MARCADOR] [--until=MARCADOR] [--boot=N|all] [--last=N]
//!                    [--tail=N] [--top=K] [--loop-min=R] [--width=W] [--all] [--only=LISTA]
//! ```
//!
//! O que ele lê (as linhas que o kernel imprime):
//! - marcadores: as linhas que começam com um TOKEN_EM_MAIUSCULAS
//!   (`HELLO_KERNEL_OK`, `LSASS_STARTED`, `*_FALHOU`...), `X FALHOU` e
//!   `REBOOT`. A serial não tem relógio: as posições são números de linha e
//!   % da faixa;
//! - processos: `[init] processo inicial`, `A (pid a) criou B (pid b)`,
//!   `[ps] NtCreateUserProcess: NOME pid=0x.. tid=0x..`, as falhas de
//!   criação, `[ps] fim do processo <EPROCESS> pedido: codigo X` (com o
//!   `NtTerminateProcess` ou a `[exception] unhandled` antes), `[usermode]
//!   NOME saiu`, as linhas de autópsia (`[exit-stack]`, `FAST_FAIL`, `CR2`) e
//!   `[thread] exit tid=.. status=..`. A linha do fim cita o EPROCESS, não o
//!   pid: o pid é deduzido da atividade (o processo que não aparece mais) e
//!   marcado com `~` (`~?` quando mais de um serve);
//! - falhas: `[usermode] PID:TID NtX FALHOU com S (rip R, chamador C)`
//!   (formato novo), `[usermode] NtX FALHOU com S (rip R)` (antigo) e as
//!   outras linhas FALHOU;
//! - fim: `*** STOP`, `*** PANIC`, `[bugcheck] codigo de parada / o que
//!   falhou`, `[kernel-seh]`, `[kd] bugcheck/excecao`, `[sched] .. morreu`;
//! - laços: blocos de até 8 linhas repetidos em sequência, as linhas mais
//!   repetidas e o log que termina dentro de um laço (travamento);
//! - memória: as linhas `[mm] memoria` e as de falta de memória.

use std::collections::{BTreeMap, HashMap, HashSet};

const USAGE: &str = "uso: cargo xtask logsum SERIAL.LOG [opcoes]
  resumo compacto de um log da serial: marcadores, fim (STOP, PANIC), memoria, arvore de
  processos com o fim de cada um, falhas de syscall (FALHOU) por processo, syscalls sem
  implementacao, lacos e as ultimas linhas por processo
  --since=MARCADOR  comeca na primeira linha com esse marcador (ou que contem o texto)
  --until=MARCADOR  para antes dessa linha (mesma busca)
  --boot=N|all      qual boot de um log com varios (a partir de 1; padrao: o ultimo, ou o do --since)
  --last=N          ultimas N linhas por processo (padrao 4)
  --tail=N          ultimas N linhas relevantes antes do STOP ou do fim (padrao 10)
  --top=K           grupos de FALHOU por processo (padrao 6)
  --loop-min=R      repeticoes minimas para chamar de laco (padrao 10)
  --width=W         corta as linhas do log em W caracteres (padrao 150; 0 = sem corte)
  --all             sem agrupar: todos os marcadores, grupos e lacos
  --only=LISTA      secoes separadas por virgula: head,markers,end,mem,procs,fails,noimpl,loops,last";

const SECTIONS: &str = "head,markers,end,mem,procs,fails,noimpl,loops,last";

// ---- nomes de NTSTATUS (só os que aparecem nestes logs) ---------------------------

const STATUS: &[(u32, &str)] = &[
    (0x0000_0000, "SUCCESS"),
    (0x0000_0102, "TIMEOUT"),
    (0x0000_0103, "PENDING"),
    (0x8000_0002, "DATATYPE_MISALIGNMENT"),
    (0x8000_0003, "BREAKPOINT"),
    (0x8000_0004, "SINGLE_STEP"),
    (0x8000_0005, "BUFFER_OVERFLOW"),
    (0x8000_0006, "NO_MORE_FILES"),
    (0x8000_001a, "NO_MORE_ENTRIES"),
    (0xc000_0001, "UNSUCCESSFUL"),
    (0xc000_0002, "NOT_IMPLEMENTED"),
    (0xc000_0003, "INVALID_INFO_CLASS"),
    (0xc000_0004, "INFO_LENGTH_MISMATCH"),
    (0xc000_0005, "ACCESS_VIOLATION"),
    (0xc000_0006, "IN_PAGE_ERROR"),
    (0xc000_0008, "INVALID_HANDLE"),
    (0xc000_000d, "INVALID_PARAMETER"),
    (0xc000_000f, "NO_SUCH_FILE"),
    (0xc000_0010, "INVALID_DEVICE_REQUEST"),
    (0xc000_0017, "NO_MEMORY"),
    (0xc000_0018, "CONFLICTING_ADDRESSES"),
    (0xc000_001d, "ILLEGAL_INSTRUCTION"),
    (0xc000_0022, "ACCESS_DENIED"),
    (0xc000_0023, "BUFFER_TOO_SMALL"),
    (0xc000_0024, "OBJECT_TYPE_MISMATCH"),
    (0xc000_0033, "OBJECT_NAME_INVALID"),
    (0xc000_0034, "OBJECT_NAME_NOT_FOUND"),
    (0xc000_0035, "OBJECT_NAME_COLLISION"),
    (0xc000_0037, "PORT_DISCONNECTED"),
    (0xc000_003a, "OBJECT_PATH_NOT_FOUND"),
    (0xc000_0041, "PORT_CONNECTION_REFUSED"),
    (0xc000_0043, "SHARING_VIOLATION"),
    (0xc000_0045, "INVALID_PAGE_PROTECTION"),
    (0xc000_0048, "PORT_ALREADY_SET"),
    (0xc000_0056, "DELETE_PENDING"),
    (0xc000_0061, "PRIVILEGE_NOT_HELD"),
    (0xc000_0073, "NONE_MAPPED"),
    (0xc000_0078, "INVALID_SID"),
    (0xc000_007a, "PROCEDURE_NOT_FOUND"),
    (0xc000_007b, "INVALID_IMAGE_FORMAT"),
    (0xc000_007c, "NO_TOKEN"),
    (0xc000_0094, "INTEGER_DIVIDE_BY_ZERO"),
    (0xc000_0096, "PRIVILEGED_INSTRUCTION"),
    (0xc000_009a, "INSUFFICIENT_RESOURCES"),
    (0xc000_00a0, "MEMORY_NOT_ALLOCATED"),
    (0xc000_00a2, "MEDIA_WRITE_PROTECTED"),
    (0xc000_00a5, "BAD_IMPERSONATION_LEVEL"),
    (0xc000_00b5, "IO_TIMEOUT"),
    (0xc000_00ba, "FILE_IS_A_DIRECTORY"),
    (0xc000_00bb, "NOT_SUPPORTED"),
    (0xc000_00e5, "INTERNAL_ERROR"),
    (0xc000_00fd, "STACK_OVERFLOW"),
    (0xc000_0100, "VARIABLE_NOT_FOUND"),
    (0xc000_0103, "NOT_A_DIRECTORY"),
    (0xc000_010a, "PROCESS_IS_TERMINATING"),
    (0xc000_010e, "IMAGE_ALREADY_LOADED"),
    (0xc000_0120, "CANCELLED"),
    (0xc000_0128, "FILE_CLOSED"),
    (0xc000_0135, "DLL_NOT_FOUND"),
    (0xc000_0139, "ENTRYPOINT_NOT_FOUND"),
    (0xc000_0141, "INVALID_ADDRESS"),
    (0xc000_0142, "DLL_INIT_FAILED"),
    (0xc000_0184, "INVALID_DEVICE_STATE"),
    (0xc000_0225, "NOT_FOUND"),
    (0xc000_0240, "REQUEST_ABORTED"),
    (0xc000_0353, "PORT_NOT_SET"),
    (0xc000_0374, "HEAP_CORRUPTION"),
    (0xc000_0409, "STACK_BUFFER_OVERRUN"),
    (0xc000_0428, "INVALID_IMAGE_HASH"),
    (0xc002_0017, "RPC_NT_SERVER_UNAVAILABLE"),
    (0xe06d_7363, "C++_EH"),
    (0x406d_1388, "SET_THREAD_NAME"),
    (0x4001_0006, "DBG_PRINTEXCEPTION_C"),
    (0x4001_000a, "DBG_PRINTEXCEPTION_WIDE_C"),
];

fn hex_value(text: &str) -> Option<u64> {
    let digits = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text);
    u64::from_str_radix(digits, 16).ok()
}

fn status_name(text: &str) -> Option<&'static str> {
    let code = u32::try_from(hex_value(text)?).ok()?;
    STATUS.iter().find(|(value, _)| *value == code).map(|(_, name)| *name)
}

/// `0xc0000034` vira `0xc0000034 OBJECT_NAME_NOT_FOUND`.
fn st(code: &str) -> String {
    match status_name(code) {
        Some(name) => format!("{code} {name}"),
        None => code.to_string(),
    }
}

// ---- leitura das linhas -----------------------------------------------------------

/// Um leitor da frente de um texto, para os formatos fixos das linhas.
struct Scan<'a>(&'a str);

impl<'a> Scan<'a> {
    fn lit(&mut self, text: &str) -> Option<()> {
        self.0 = self.0.strip_prefix(text)?;
        Some(())
    }

    fn span(&mut self, accept: impl Fn(char) -> bool) -> Option<&'a str> {
        let end = self.0.find(|character: char| !accept(character)).unwrap_or(self.0.len());
        if end == 0 {
            return None;
        }
        let (head, tail) = self.0.split_at(end);
        self.0 = tail;
        Some(head)
    }

    /// `0x` seguido de dígitos hexadecimais.
    fn hex(&mut self) -> Option<&'a str> {
        let digits = self.0.strip_prefix("0x")?;
        let count = digits.find(|character: char| !character.is_ascii_hexdigit()).unwrap_or(digits.len());
        if count == 0 {
            return None;
        }
        let (head, tail) = self.0.split_at(2 + count);
        self.0 = tail;
        Some(head)
    }

    fn decimal(&mut self) -> Option<u64> {
        self.span(|character| character.is_ascii_digit())?.parse().ok()
    }

    fn word(&mut self) -> Option<&'a str> {
        self.span(|character| character.is_alphanumeric() || character == '_')
    }

    /// Uma sequência sem espaços.
    fn token(&mut self) -> Option<&'a str> {
        self.span(|character| !character.is_whitespace())
    }
}

fn is_word(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// `PID:TID ` no começo do texto.
fn pid_tid(text: &str) -> Option<(u64, u64, &str)> {
    let mut scan = Scan(text);
    let pid = scan.decimal()?;
    scan.lit(":")?;
    let tid = scan.decimal()?;
    scan.lit(" ")?;
    Some((pid, tid, scan.0))
}

/// `[usermode] [PID:TID ]NtX FALHOU com S (rip R[, chamador C])[ resto]`, C
/// em hexadecimal ou `módulo+deslocamento`.
struct Fail<'a> {
    pid: Option<u64>,
    tid: Option<u64>,
    name: &'a str,
    status: &'a str,
    rip: &'a str,
    caller: Option<&'a str>,
    detail: &'a str,
}

fn parse_fail(line: &str) -> Option<Fail<'_>> {
    let rest = line.strip_prefix("[usermode] ")?;
    let (pid, tid, rest) = match pid_tid(rest) {
        Some((pid, tid, rest)) => (Some(pid), Some(tid), rest),
        None => (None, None, rest),
    };
    let mut scan = Scan(rest);
    let name = scan.word()?;
    scan.lit(" FALHOU com ")?;
    let status = scan.hex()?;
    scan.lit(" (rip ")?;
    let rip = scan.hex()?;
    // O chamador: `módulo+deslocamento` ou o endereço cru em hexadecimal.
    let caller = if scan.lit(", chamador ").is_some() { Some(scan.span(|character| character != ')' && !character.is_whitespace())?) } else { None };
    scan.lit(")")?;
    Some(Fail { pid, tid, name, status, rip, caller, detail: scan.0.trim_start() })
}

/// `[sys] PID:TID NtX(`.
fn parse_sys(line: &str) -> Option<(u64, u64)> {
    let (pid, tid, rest) = pid_tid(line.strip_prefix("[sys] ")?)?;
    let mut scan = Scan(rest);
    scan.word()?;
    scan.lit("(")?;
    Some((pid, tid))
}

/// As linhas de dados do bugcheck e do black box: só contadas.
const NOISY_MARKERS: &[&str] = &["KERNEL_BUGCHECK_SECONDARY_BYTES", "KERNEL_BUGCHECK_SECONDARY_RECORD", "KERNEL_BLACKBOX_BYTES", "KERNEL_BLACKBOX_RECORD"];

/// O marcador de uma linha: `TOKEN_EM_MAIUSCULAS` (com `_`, seguido do fim,
/// de espaço ou de `:{(=,`), `NOME FALHOU` ou `REBOOT`.
fn marker_token(line: &str) -> Option<&str> {
    let run = line.find(|character: char| !(character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_')).unwrap_or(line.len());
    let token = &line[..run];
    let after = &line[run..];
    let starts_with_letter = token.starts_with(|character: char| character.is_ascii_uppercase());
    let structured = starts_with_letter && token.contains('_') && !token.ends_with('_') && !token.contains("__");
    if structured && after.chars().next().map_or(true, |character| character.is_whitespace() || ":{(=,".contains(character)) {
        return Some(token);
    }
    if starts_with_letter && after.strip_prefix(" FALHOU").is_some_and(|rest| !rest.starts_with(is_word)) {
        return Some(token);
    }
    if line.strip_prefix("REBOOT").is_some_and(|rest| !rest.starts_with(is_word)) {
        return Some("REBOOT");
    }
    None
}

/// `NOME FALHOU` no começo da linha.
fn is_marker_failure(line: &str) -> bool {
    let run = line.find(|character: char| !(character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_')).unwrap_or(line.len());
    line.starts_with(|character: char| character.is_ascii_uppercase()) && line[run..].strip_prefix(" FALHOU").is_some_and(|rest| !rest.starts_with(is_word))
}

fn parse_initial(line: &str) -> Option<(&str, u64)> {
    let mut scan = Scan(line.strip_prefix("[init] processo inicial ")?);
    let name = scan.token()?;
    scan.lit(" (pid ")?;
    let pid = scan.decimal()?;
    scan.lit(")")?;
    Some((name, pid))
}

fn parse_created(line: &str) -> Option<(&str, u64, &str, u64)> {
    let mut scan = Scan(line.strip_prefix("[init] ")?);
    let creator = scan.token()?;
    scan.lit(" (pid ")?;
    let creator_pid = scan.decimal()?;
    scan.lit(") criou ")?;
    let child = scan.token()?;
    scan.lit(" (pid ")?;
    let child_pid = scan.decimal()?;
    scan.lit(")")?;
    Some((creator, creator_pid, child, child_pid))
}

fn parse_process_created(line: &str) -> Option<(&str, u64, u64)> {
    let mut scan = Scan(line.strip_prefix("[ps] NtCreateUserProcess: ")?);
    let name = scan.token()?;
    scan.lit(" pid=")?;
    let pid = hex_value(scan.hex()?)?;
    scan.lit(" tid=")?;
    let tid = hex_value(scan.hex()?)?;
    Some((name, pid, tid))
}

/// `[ps] NtCreateUserProcess de NOME: motivo` ou `[ps] criacao de NOME falhou: motivo`.
fn parse_create_failure(line: &str) -> Option<(&str, &str)> {
    if let Some(rest) = line.strip_prefix("[ps] NtCreateUserProcess de ") {
        let space = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let name = rest[..space].strip_suffix(':').filter(|name| !name.is_empty())?;
        return Some((name, rest[space..].strip_prefix(' ')?));
    }
    let mut scan = Scan(line.strip_prefix("[ps] criacao de ")?);
    let name = scan.token()?;
    scan.lit(" falhou: ")?;
    Some((name, scan.0))
}

/// `[ps] fim do processo PTR pedido: codigo X resto`.
fn parse_exit_request(line: &str) -> Option<(&str, &str, &str)> {
    let mut scan = Scan(line.strip_prefix("[ps] fim do processo ")?);
    let pointer = scan.hex()?;
    scan.lit(" pedido: codigo ")?;
    let code = scan.hex()?;
    Some((pointer, code, scan.0))
}

fn parse_terminate_self(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("[usermode] NtTerminateProcess(")?;
    let rest = rest.strip_prefix("NULL, ").unwrap_or(rest);
    let mut scan = Scan(rest.strip_prefix("exit=")?);
    let code = scan.hex()?;
    scan.lit(")")?;
    Some(code)
}

fn parse_terminate_other(line: &str) -> Option<(&str, &str)> {
    let mut scan = Scan(line.strip_prefix("[usermode] NtTerminateProcess(processo ")?);
    let pointer = scan.hex()?;
    scan.lit(", exit=")?;
    let code = scan.hex()?;
    scan.lit(")")?;
    Some((pointer, code))
}

fn parse_exited(line: &str) -> Option<(&str, &str)> {
    let mut scan = Scan(line.strip_prefix("[usermode] ")?);
    let name = scan.token()?;
    scan.lit(" saiu: codigo ")?;
    Some((name, scan.hex()?))
}

fn parse_unhandled(line: &str) -> Option<(&str, &str)> {
    let mut scan = Scan(line.strip_prefix("[exception] unhandled ")?);
    let code = scan.hex()?;
    scan.lit(" @")?;
    Some((code, scan.hex()?))
}

fn parse_first_chance(line: &str) -> Option<(&str, Option<&str>)> {
    let mut scan = Scan(line.strip_prefix("[exception] first chance ")?);
    let code = scan.hex()?;
    let address = if scan.lit(" em ").is_some() { scan.hex() } else { None };
    Some((code, address))
}

fn is_postmortem(line: &str) -> bool {
    line.starts_with("[exit-stack] ") || line.starts_with("[usermode] FAST_FAIL ") || line.starts_with("[usermode] CR2=")
}

/// As threads que ficaram bloqueadas no fim de um processo: (quantas, EPROCESS).
fn parse_blocked(line: &str) -> Option<(Option<u64>, &str)> {
    let rest = line.strip_prefix("[thread] ")?;
    if let Some(rest) = rest.strip_prefix("processo ") {
        let mut scan = Scan(rest);
        let pointer = scan.hex()?;
        scan.lit(" terminado com thread ainda bloqueada no kernel")?;
        return Some((None, pointer));
    }
    let mut scan = Scan(rest);
    let count = scan.decimal()?;
    scan.lit(" thread(s) ainda bloqueada(s) no kernel no fim do processo ")?;
    Some((Some(count), scan.hex()?))
}

fn parse_thread(line: &str) -> Option<u64> {
    let rest = line.strip_prefix("[thread] ")?;
    let rest = rest.strip_prefix("created tid=").or_else(|| rest.strip_prefix("exit tid="))?;
    Scan(rest).decimal()
}

fn parse_thread_exit(line: &str) -> Option<(u64, &str)> {
    let mut scan = Scan(line.strip_prefix("[thread] exit tid=")?);
    let tid = scan.decimal()?;
    scan.lit(" status=")?;
    Some((tid, scan.hex()?))
}

fn parse_unimplemented(line: &str) -> Option<(&str, &str)> {
    let mut scan = Scan(line.strip_prefix("[usermode] syscall ")?);
    let name = scan.token()?;
    scan.lit(" sem implementacao")?;
    Some((name, scan.0))
}

fn is_hard_error(line: &str) -> bool {
    line.starts_with("[usermode] HARDERROR: ") || line.starts_with("[hard-error] 0x")
}

/// `PREFIXO <número> resto` no começo da linha.
fn number_then(line: &str, prefix: &str, rest: &str) -> bool {
    let Some(after) = line.strip_prefix(prefix) else { return false };
    let mut scan = Scan(after);
    scan.decimal().is_some() && scan.0.starts_with(rest)
}

/// As linhas do fim: STOP, PANIC, o bugcheck e as exceções de kernel.
fn is_end(line: &str) -> bool {
    line.strip_prefix("*** STOP").is_some_and(|rest| !rest.starts_with(is_word))
        || line.contains("*** PANIC: ")
        || ["[bugcheck] codigo de parada", "[bugcheck] o que falhou", "[bugcheck] reiniciando", "[bugcheck] maquina parada", "[kernel-seh] ", "[ke] BUGCHECK", "[kd] bugcheck", "[kd] excecao de kernel", "[kd] DbgBreakPointWithStatus", "[kd] maquina parada"].iter().any(|prefix| line.starts_with(prefix))
        || number_then(line, "[sched] processo ", " morreu")
        || number_then(line, "[thread] tid=", " despacho falhou")
}

fn is_stop(line: &str) -> bool {
    ["*** STOP", "*** PANIC"].iter().any(|prefix| line.strip_prefix(prefix).is_some_and(|rest| !rest.starts_with(is_word)))
}

/// Os pids `pid N` / `pid=N` (palavra inteira) da linha, na ordem.
fn pids(line: &str) -> Vec<u64> {
    let mut found = Vec::new();
    for (at, _) in line.match_indices("pid") {
        if line[..at].chars().next_back().is_some_and(is_word) {
            continue;
        }
        let rest = &line[at + 3..];
        let Some(rest) = rest.strip_prefix(' ').or_else(|| rest.strip_prefix('=')) else { continue };
        let digits = rest.find(|character: char| !character.is_ascii_digit()).unwrap_or(rest.len());
        if digits == 0 || rest[digits..].starts_with(is_word) {
            continue;
        }
        if let Ok(pid) = rest[..digits].parse() {
            found.push(pid);
        }
    }
    found
}

fn first_pid(line: &str) -> Option<u64> {
    pids(line).first().copied()
}

/// Os ponteiros de kernel (`0xffff` + 12 dígitos minúsculos) da linha.
fn kernel_pointers(line: &str) -> HashSet<&str> {
    let mut found = HashSet::new();
    let mut from = 0;
    while let Some(offset) = line[from..].find("0xffff") {
        let at = from + offset;
        let digits = line.get(at + 6..at + 18);
        if digits.is_some_and(|digits| digits.chars().all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))) {
            found.insert(&line[at..at + 18]);
            from = at + 18;
        } else {
            from = at + 6;
        }
    }
    found
}

fn is_boot(line: &str) -> bool {
    line.contains("kernel 64-bit vivo")
}

/// Linhas sem informação para o fim e as últimas linhas por processo.
fn meaningful(line: &str) -> bool {
    let noise = ["[pe] ", "[rtl] ", "[zw] ", "[atapio] ", "[bugcheck] callback ", "KERNEL_BUGCHECK_SECONDARY", "KERNEL_BLACKBOX_BYTES", "[usermode] primeiro: ", "[mm] NAO ACHOU"];
    !(line.trim().is_empty() || noise.iter().any(|prefix| line.starts_with(prefix)))
}

/// `[mm] memoria (TIPO N): PFN livres A/B paginas, commit C/D paginas (maximo E, pico F), nao residentes G, heap H/I KB`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Memory {
    free: u64,
    total: u64,
    commit: u64,
    commit_limit: u64,
    maximum: u64,
    peak: u64,
    nonresident: u64,
    heap: u64,
    heap_total: u64,
}

fn parse_memory(line: &str) -> Option<Memory> {
    let at = line.find("[mm] memoria (")?;
    let mut scan = Scan(&line[at + "[mm] memoria (".len()..]);
    scan.word()?;
    scan.lit(" ")?;
    scan.decimal()?;
    scan.lit("): PFN livres ")?;
    let free = scan.decimal()?;
    scan.lit("/")?;
    let total = scan.decimal()?;
    scan.lit(" paginas, commit ")?;
    let commit = scan.decimal()?;
    scan.lit("/")?;
    let commit_limit = scan.decimal()?;
    scan.lit(" paginas (maximo ")?;
    let maximum = scan.decimal()?;
    scan.lit(", pico ")?;
    let peak = scan.decimal()?;
    scan.lit("), nao residentes ")?;
    let nonresident = scan.decimal()?;
    scan.lit(", heap ")?;
    let heap = scan.decimal()?;
    scan.lit("/")?;
    let heap_total = scan.decimal()?;
    scan.lit(" KB")?;
    Some(Memory { free, total, commit, commit_limit, maximum, peak, nonresident, heap, heap_total })
}

fn is_memory_failure(line: &str) -> bool {
    ["kernel-heap-failure", "PFN exhausted", "commit acima do limite", "reclaim failed", "PFN esgotado", "sem frame livre"].iter().any(|text| line.contains(text))
        || line.find("[section] ").is_some_and(|at| line[at + "[section] ".len()..].contains("STATUS_NO_MEMORY"))
}

/// As linhas do arquivo: sem bytes nulos e com `\r\n` e `\r` como fim de linha.
fn load(bytes: &[u8]) -> Vec<String> {
    let bytes: Vec<u8> = bytes.iter().copied().filter(|&byte| byte != 0).collect();
    let text = String::from_utf8_lossy(&bytes).replace("\r\n", "\n").replace('\r', "\n");
    let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    if lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    lines
}

/// Os boots: cada um começa na linha `kernel 64-bit vivo` (o que vem antes
/// do primeiro entra nele).
fn boots(lines: &[String]) -> Vec<(usize, usize)> {
    let mut starts: Vec<usize> = lines.iter().enumerate().filter(|(_, line)| is_boot(line)).map(|(index, _)| index).collect();
    if starts.is_empty() {
        starts = lines.iter().enumerate().filter(|(_, line)| line.trim() == "HELLO_KERNEL_OK").map(|(index, _)| index).collect();
    }
    if starts.is_empty() {
        starts.push(0);
    }
    starts[0] = 0;
    (0..starts.len()).map(|index| (starts[index], starts.get(index + 1).copied().unwrap_or(lines.len()))).collect()
}

fn find_marker(lines: &[String], low: usize, high: usize, marker: &str) -> Option<usize> {
    (low..high).find(|&index| marker_token(&lines[index]) == Some(marker)).or_else(|| (low..high).find(|&index| lines[index].contains(marker)))
}

/// Contagem na ordem da primeira aparição.
struct Counter<K> {
    items: Vec<(K, usize)>,
    index: HashMap<K, usize>,
}

impl<K: std::hash::Hash + Eq + Clone> Counter<K> {
    fn new() -> Self {
        Counter { items: Vec::new(), index: HashMap::new() }
    }

    fn add(&mut self, key: K) {
        match self.index.get(&key) {
            Some(&position) => self.items[position].1 += 1,
            None => {
                self.index.insert(key.clone(), self.items.len());
                self.items.push((key, 1));
            }
        }
    }

    /// Por contagem decrescente; empates na ordem da primeira aparição.
    fn most_common(&self) -> Vec<(K, usize)> {
        let mut items = self.items.clone();
        items.sort_by(|a, b| b.1.cmp(&a.1));
        items
    }
}

// ---- o modelo dos processos --------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum How {
    Unknown,
    Unhandled,
    Killed,
    SelfTerminated,
    CreationFailed,
    Kernel,
}

impl How {
    fn text(self) -> &'static str {
        match self {
            How::Unknown => "?",
            How::Unhandled => "excecao sem tratamento",
            How::Killed => "morto (NtTerminateProcess de outro)",
            How::SelfTerminated => "proprio (NtTerminateProcess)",
            How::CreationFailed => "criacao falhou",
            How::Kernel => "kernel (despacho/criacao)",
        }
    }
}

struct Proc {
    pid: u64,
    name: String,
    parent: Option<u64>,
    /// A linha da criação.
    line: Option<usize>,
    initial: bool,
    /// O fim (índice em `exits`).
    exit: Option<usize>,
    children: Vec<u64>,
    /// (linha, nome, motivo).
    create_fails: Vec<(usize, String, String)>,
    /// (tid, status, linha).
    thread_bad: Vec<(u64, String, usize)>,
}

impl Proc {
    fn new(pid: u64) -> Self {
        Proc { pid, name: "?".into(), parent: None, line: None, initial: false, exit: None, children: Vec::new(), create_fails: Vec::new(), thread_bad: Vec::new() }
    }
}

struct Exit {
    line: usize,
    pointer: String,
    code: String,
    how: How,
    /// A exceção sem tratamento (índice em `unhandled`).
    exception: Option<usize>,
    pid: Option<u64>,
    /// `` explícito, `~` deduzido, `~?` ambíguo.
    conf: &'static str,
    candidates: Vec<u64>,
    /// As linhas de autópsia.
    post: Vec<usize>,
    blocked: Option<String>,
    /// O nome, da falha de criação ou do `saiu`.
    name: Option<String>,
    /// O pid que pediu o NtTerminateProcess, quando se sabe.
    by: Option<u64>,
}

struct Unhandled {
    code: String,
    address: String,
    line: usize,
}

struct Attempt {
    line: usize,
    pointer: String,
    code: String,
    status: String,
    by: Option<u64>,
    fail_line: usize,
}

struct CreateFail {
    line: usize,
    name: String,
    reason: String,
    creator: Option<u64>,
}

/// Um NtTerminateProcess(processo ...) ainda sem desfecho: (EPROCESS, código, linha, quem pediu).
type PendingOther = (String, String, usize, Option<u64>);

struct Log<'a> {
    lines: &'a [String],
    low: usize,
    high: usize,
    range_low: usize,
    range_high: usize,
    procs: Vec<Proc>,
    index: HashMap<u64, usize>,
    tid_to_pid: HashMap<u64, u64>,
    exits: Vec<Exit>,
    attempts: Vec<Attempt>,
    create_fails: Vec<CreateFail>,
    /// (linha, nome, código) dos `saiu` sem fim de processo perto.
    exited: Vec<(usize, String, String)>,
    /// Linha -> pid.
    attributed: BTreeMap<usize, u64>,
    activity: HashMap<u64, Vec<usize>>,
    first_chance: Vec<(usize, String)>,
    unhandled: Vec<Unhandled>,
    /// EPROCESS -> [(linha, pid)] das linhas que citam os dois.
    pointer_pid: HashMap<String, Vec<(usize, u64)>>,
}

impl<'a> Log<'a> {
    fn new(lines: &'a [String], low: usize, high: usize) -> Self {
        let mut log = Log {
            lines,
            low,
            high,
            range_low: low,
            range_high: high,
            procs: Vec::new(),
            index: HashMap::new(),
            tid_to_pid: HashMap::new(),
            exits: Vec::new(),
            attempts: Vec::new(),
            create_fails: Vec::new(),
            exited: Vec::new(),
            attributed: BTreeMap::new(),
            activity: HashMap::new(),
            first_chance: Vec::new(),
            unhandled: Vec::new(),
            pointer_pid: HashMap::new(),
        };
        log.parse();
        log
    }

    fn proc_index(&mut self, pid: u64) -> usize {
        if let Some(&index) = self.index.get(&pid) {
            return index;
        }
        self.procs.push(Proc::new(pid));
        self.index.insert(pid, self.procs.len() - 1);
        self.procs.len() - 1
    }

    fn get(&self, pid: u64) -> Option<&Proc> {
        self.index.get(&pid).map(|&index| &self.procs[index])
    }

    fn parse(&mut self) {
        let lines = self.lines;
        let mut pending_self: Option<(String, usize)> = None;
        let mut pending_other: Option<PendingOther> = None;
        let mut pending_exception: Option<usize> = None;
        let mut last_exit: Option<usize> = None;
        for i in self.low..self.high {
            let line = lines[i].as_str();
            let mut pid: Option<u64> = None;
            let fail = parse_fail(line);
            let pair = match &fail {
                Some(fail) => fail.pid.zip(fail.tid),
                None => parse_sys(line),
            };
            if let Some((owner, tid)) = pair {
                pid = Some(owner);
                self.tid_to_pid.insert(tid, owner);
            }
            if let Some((name, child, tid)) = parse_process_created(line) {
                let index = self.proc_index(child);
                self.procs[index].name = name.to_string();
                if self.procs[index].line.is_none() {
                    self.procs[index].line = Some(i);
                }
                self.tid_to_pid.insert(tid, child);
                pid = Some(child);
            }
            if let Some((name, initial)) = parse_initial(line) {
                let index = self.proc_index(initial);
                let proc = &mut self.procs[index];
                proc.name = name.rsplit('\\').next().unwrap_or(name).to_string();
                proc.initial = true;
                proc.line = Some(i);
            }
            if let Some((creator_name, creator, child_name, child)) = parse_created(line) {
                let creator_index = self.proc_index(creator);
                let child_index = self.proc_index(child);
                if self.procs[creator_index].name == "?" {
                    self.procs[creator_index].name = creator_name.to_string();
                }
                self.procs[child_index].name = child_name.to_string();
                if self.procs[child_index].parent.is_none() {
                    self.procs[child_index].parent = Some(creator);
                    self.procs[creator_index].children.push(child);
                }
                if self.procs[child_index].line.is_none() {
                    self.procs[child_index].line = Some(i);
                }
            }
            if pid.is_none() && !line.starts_with("[ps] NtCreateUserProcess") {
                pid = first_pid(line);
            }
            if let Some(pid) = pid {
                self.attributed.insert(i, pid);
            }
            // Os fins de processo e as causas.
            if let Some(code) = parse_terminate_self(line) {
                pending_self = Some((code.to_string(), i));
            }
            if let Some((pointer, code)) = parse_terminate_other(line) {
                // O NtTerminateProcess anterior que falhou na mesma thread diz quem pediu.
                let killer = self.attempts.last().filter(|attempt| i - attempt.fail_line <= 2).and_then(|attempt| attempt.by);
                pending_other = Some((pointer.to_string(), code.to_string(), i, killer));
            }
            if let Some((code, address)) = parse_unhandled(line) {
                self.unhandled.push(Unhandled { code: code.to_string(), address: address.to_string(), line: i });
                pending_exception = Some(self.unhandled.len() - 1);
            }
            if let Some((code, _)) = parse_first_chance(line) {
                self.first_chance.push((i, code.to_string()));
            }
            if let Some(fail) = &fail {
                let attempt = match &pending_other {
                    Some((pointer, code, at, _)) if fail.name == "NtTerminateProcess" && i - at <= 3 => Some(Attempt { line: *at, pointer: pointer.clone(), code: code.clone(), status: fail.status.to_string(), by: fail.pid, fail_line: i }),
                    _ => None,
                };
                if let Some(attempt) = attempt {
                    self.attempts.push(attempt);
                    pending_other = None;
                }
                if fail.name == "NtCreateUserProcess" && fail.pid.is_some() {
                    if let Some(last) = self.create_fails.last_mut() {
                        if i - last.line <= 6 && last.creator.is_none() {
                            last.creator = fail.pid;
                        }
                    }
                }
            }
            if let Some((name, reason)) = parse_create_failure(line) {
                self.create_fails.push(CreateFail { line: i, name: name.to_string(), reason: reason.to_string(), creator: None });
            }
            if let Some((pointer, code, rest)) = parse_exit_request(line) {
                let code_value = hex_value(code);
                let same = |other: &str| hex_value(other) == code_value;
                let mut exit = Exit { line: i, pointer: pointer.to_string(), code: code.to_string(), how: How::Unknown, exception: None, pid: None, conf: "", candidates: Vec::new(), post: Vec::new(), blocked: None, name: None, by: None };
                if let Some(index) = pending_exception.filter(|&index| i - self.unhandled[index].line <= 10 && same(self.unhandled[index].code.as_str())) {
                    exit.how = How::Unhandled;
                    exit.exception = Some(index);
                } else if let Some((_, _, _, killer)) = pending_other.as_ref().filter(|(other, _, at, _)| i - at <= 3 && other == pointer) {
                    exit.how = How::Killed;
                    exit.by = *killer;
                } else if pending_self.as_ref().is_some_and(|(self_code, at)| i - at <= 3 && same(self_code.as_str())) {
                    exit.how = How::SelfTerminated;
                } else if let Some(last) = self.create_fails.last().filter(|last| i - last.line <= 6) {
                    exit.how = How::CreationFailed;
                    exit.name = Some(last.name.clone());
                } else {
                    exit.how = How::Kernel;
                }
                if let Some(pid) = first_pid(rest) {
                    exit.pid = Some(pid);
                }
                pending_self = None;
                pending_other = None;
                pending_exception = None;
                self.exits.push(exit);
                last_exit = Some(self.exits.len() - 1);
                continue;
            }
            if let Some(index) = last_exit {
                if i - self.exits[index].line <= 80 && is_postmortem(line) {
                    self.exits[index].post.push(i);
                }
            }
            if let Some((count, pointer)) = parse_blocked(line) {
                if let Some(exit) = self.exits.iter_mut().rev().find(|exit| exit.pointer == pointer) {
                    exit.blocked = Some(format!("{} thread(s) ainda bloqueada(s) no kernel", count.map_or_else(|| "alguma".to_string(), |count| count.to_string())));
                }
            }
            if let Some((name, code)) = parse_exited(line) {
                let code_value = hex_value(code);
                let start = self.exits.len().saturating_sub(4);
                let near = self.exits[start..].iter_mut().filter(|exit| i - exit.line <= 6 && hex_value(&exit.code) == code_value && exit.name.is_none()).last();
                match near {
                    Some(exit) => exit.name = Some(name.to_string()),
                    None => self.exited.push((i, name.to_string(), code.to_string())),
                }
            }
            // Um EPROCESS e um pid na mesma linha (diagnósticos que citam os dois).
            if line.contains("processo") {
                let pointers = kernel_pointers(line);
                let mut found = pids(line);
                found.sort_unstable();
                found.dedup();
                if pointers.len() == 1 && found.len() == 1 {
                    let pointer = pointers.into_iter().next().unwrap_or_default().to_string();
                    self.pointer_pid.entry(pointer).or_default().push((i, found[0]));
                }
            }
        }
        // As linhas de thread pelo tid -> pid (os tids aprendidos depois também valem).
        for i in self.low..self.high {
            if self.attributed.contains_key(&i) {
                continue;
            }
            let line = lines[i].as_str();
            if let Some(&pid) = parse_thread(line).and_then(|tid| self.tid_to_pid.get(&tid)) {
                self.attributed.insert(i, pid);
            }
            if let Some((tid, status)) = parse_thread_exit(line) {
                if hex_value(status).unwrap_or(0) != 0 {
                    if let Some(&pid) = self.tid_to_pid.get(&tid) {
                        let index = self.proc_index(pid);
                        self.procs[index].thread_bad.push((tid, status.to_string(), i));
                    }
                }
            }
        }
        let attributed: Vec<(usize, u64)> = self.attributed.iter().map(|(&line, &pid)| (line, pid)).collect();
        for (line, pid) in attributed {
            self.activity.entry(pid).or_default().push(line);
            self.proc_index(pid);
        }
        if let Some(&index) = self.index.get(&4) {
            if self.procs[index].name == "?" {
                self.procs[index].name = "System".into();
            }
        }
        for list in self.activity.values_mut() {
            list.sort_unstable();
        }
        for proc in &mut self.procs {
            if proc.line.is_none() {
                proc.line = self.activity.get(&proc.pid).and_then(|list| list.first()).copied();
            }
        }
        self.resolve_exits();
        let fails: Vec<(u64, usize, String, String)> = self.create_fails.iter().filter_map(|fail| fail.creator.map(|creator| (creator, fail.line, fail.name.clone(), fail.reason.clone()))).collect();
        for (creator, line, name, reason) in fails {
            let index = self.proc_index(creator);
            self.procs[index].create_fails.push((line, name, reason));
        }
    }

    /// EPROCESS -> pid. Explícito quando uma linha liga os dois; senão o
    /// processo com atividade antes do fim e nenhuma depois.
    fn resolve_exits(&mut self) {
        // O endereço de um EPROCESS volta a ser usado depois que o processo
        // some, e cada `fim do processo` é um processo diferente.
        let mut taken: HashSet<u64> = HashSet::new();
        let attributed: Vec<usize> = self.attributed.keys().copied().collect();
        let mut previous: HashMap<String, usize> = HashMap::new();
        for e in 0..self.exits.len() {
            let line = self.exits[e].line;
            let pointer = self.exits[e].pointer.clone();
            let since = previous.get(&pointer).copied();
            previous.insert(pointer.clone(), line);
            let explicit: Vec<u64> = self.pointer_pid.get(&pointer).map(|list| list.iter().filter(|(at, _)| since.map_or(true, |since| *at > since) && *at <= line + 3).map(|(_, pid)| *pid).collect()).unwrap_or_default();
            if self.exits[e].pid.is_none() {
                if let Some(&pid) = explicit.last() {
                    self.exits[e].pid = Some(pid);
                    self.exits[e].conf = "";
                }
            }
            if let Some(pid) = self.exits[e].pid {
                taken.insert(pid);
                continue;
            }
            if self.exits[e].how == How::CreationFailed {
                continue;
            }
            let later = attributed.iter().filter(|&&at| at > line + 2).count();
            let name = self.exits[e].name.clone();
            let by = self.exits[e].by;
            let mut candidates: Vec<(usize, u64)> = Vec::new();
            for proc in &self.procs {
                let pid = proc.pid;
                if taken.contains(&pid) || proc.exit.is_some() || pid <= 4 || Some(pid) == by {
                    continue;
                }
                if name.as_ref().is_some_and(|name| !proc.name.eq_ignore_ascii_case(name)) {
                    continue;
                }
                let Some(created) = proc.line.filter(|&created| created < line) else { continue };
                let acts = self.activity.get(&pid).map_or(&[][..], Vec::as_slice);
                if acts.iter().any(|&at| at > line + 2) {
                    continue;
                }
                let last = acts.iter().copied().filter(|&at| at < line).last().unwrap_or(created);
                candidates.push((last, pid));
            }
            candidates.sort_unstable_by(|a, b| b.cmp(a));
            let named: Vec<u64> = candidates.iter().filter(|(_, pid)| name.as_ref().is_some_and(|name| self.get(*pid).is_some_and(|proc| proc.name.eq_ignore_ascii_case(name)))).map(|&(_, pid)| pid).collect();
            let how = self.exits[e].how;
            let mut conf = self.exits[e].conf;
            let mut chosen = None;
            self.exits[e].candidates = candidates.iter().map(|&(_, pid)| pid).collect();
            if named.len() == 1 {
                chosen = Some(named[0]);
                conf = "~";
            } else if candidates.is_empty() {
                continue;
            } else if later < 20 {
                conf = "~?";
                if candidates.len() == 1 {
                    chosen = Some(candidates[0].1);
                }
            } else if candidates.len() == 1 {
                chosen = Some(candidates[0].1);
                conf = "~";
            } else if matches!(how, How::SelfTerminated | How::Unhandled) {
                chosen = Some(candidates[0].1);
                conf = "~?";
            }
            self.exits[e].conf = conf;
            self.exits[e].pid = chosen;
            if let Some(pid) = chosen {
                taken.insert(pid);
                let index = self.proc_index(pid);
                self.procs[index].exit = Some(e);
            }
        }
        for e in 0..self.exits.len() {
            if let Some(pid) = self.exits[e].pid {
                let index = self.proc_index(pid);
                if self.procs[index].exit.is_none() {
                    self.procs[index].exit = Some(e);
                }
            }
        }
    }

    /// O pid do último fim do EPROCESS `pointer` até a linha.
    fn pointer_at(&self, pointer: &str, line: usize) -> Option<u64> {
        self.exits.iter().rev().find(|exit| exit.pointer == pointer && exit.line <= line + 3 && exit.pid.is_some()).and_then(|exit| exit.pid)
    }

    fn pname(&self, pid: Option<u64>) -> String {
        match pid {
            None => "?".into(),
            Some(pid) => format!("{} {pid}", self.get(pid).map_or("?", |proc| proc.name.as_str())),
        }
    }

    fn in_range(&self, line: usize) -> bool {
        self.range_low <= line && line < self.range_high
    }
}

// ---- a saída ---------------------------------------------------------------------

struct Out {
    width: usize,
    text: String,
}

impl Out {
    fn line(&mut self, text: &str) {
        if !text.starts_with("==") && self.width != 0 && text.chars().count() > self.width {
            let head: String = text.chars().take(self.width.saturating_sub(3)).collect();
            self.text.push_str(&head);
            self.text.push_str("...");
        } else {
            self.text.push_str(text);
        }
        self.text.push('\n');
    }
}

fn span(first: usize, last: usize) -> String {
    if first == last {
        format!("L{}", first + 1)
    } else {
        format!("L{}-L{}", first + 1, last + 1)
    }
}

fn section_head(out: &mut Out, log: &Log, path: &str, boots: usize, boot: usize, format: &str) {
    let range = if (log.range_low, log.range_high) != (log.low, log.high) { format!(", faixa L{}-L{}", log.range_low + 1, log.range_high) } else { String::new() };
    out.line(&format!("== {path}: {} linhas, {boots} boot(s); resumo do boot {boot}, linhas {}-{}{range}", log.lines.len(), log.low + 1, log.high));
    out.line(&format!("   formato do FALHOU: {format}; a serial nao tem relogio: as posicoes sao numeros de linha (L) e % da faixa"));
}

fn section_markers(out: &mut Out, log: &Log, all: bool) {
    let total = (log.range_high - log.range_low).max(1);
    let mut seen: HashMap<&str, (usize, usize)> = HashMap::new();
    let mut order: Vec<(usize, &str)> = Vec::new();
    let mut noisy: Counter<&str> = Counter::new();
    for i in log.range_low..log.range_high {
        let Some(token) = marker_token(&log.lines[i]) else { continue };
        if NOISY_MARKERS.contains(&token) {
            noisy.add(token);
            continue;
        }
        if let Some(entry) = seen.get_mut(token).filter(|_| !all) {
            entry.0 += 1;
            entry.1 = i;
            continue;
        }
        seen.insert(token, (1, i));
        order.push((i, token));
    }
    out.line(&format!("== marcadores ({})", order.len()));
    for (i, token) in &order {
        let line = &log.lines[*i];
        let (count, last) = seen[token];
        let head: String = line.chars().take(60).collect();
        let bad = if token.contains("FALHOU") || head.contains("FALHOU") { "!! " } else { "   " };
        let extra = if count > 1 { format!("  (x{count}, ultima L{})", last + 1) } else { String::new() };
        let percent = 100 * (i - log.range_low) / total;
        out.line(&format!("{bad}L{:<6} {percent:>3}%  {}{extra}", i + 1, line.trim()));
    }
    if !noisy.items.is_empty() {
        let items: Vec<String> = noisy.items.iter().map(|(token, count)| format!("{token} x{count}")).collect();
        out.line(&format!("   (linhas de dados do bugcheck e do black box: {})", items.join(", ")));
    }
}

fn section_end(out: &mut Out, log: &Log, tail_count: usize) {
    let lines = log.lines;
    let ends: Vec<usize> = (log.range_low..log.range_high).filter(|&i| is_end(&lines[i])).collect();
    let stop = ends.iter().copied().find(|&i| is_stop(&lines[i]));
    out.line("== fim");
    if ends.is_empty() {
        out.line("   nenhum STOP, PANIC ou excecao de kernel na faixa: o log so termina (prazo, travamento ou fim do teste)");
    }
    let failed: Vec<usize> = (log.range_low..log.range_high).filter(|&i| marker_token(&lines[i]).is_some_and(|token| token.ends_with("FALHOU")) || is_marker_failure(&lines[i])).collect();
    if let Some(&first) = failed.first() {
        out.line(&format!("   !! {} marcador(es) de falha, o primeiro na L{}: {}", failed.len(), first + 1, lines[first].trim()));
    }
    let mut shown = 0;
    for &i in &ends {
        let line = &lines[i];
        if line.starts_with("[bugcheck] reiniciando") || line.starts_with("[bugcheck] maquina parada") || shown < 8 {
            out.line(&format!("   L{:<6} {}", i + 1, line.trim()));
            shown += 1;
        }
    }
    let hard: Vec<usize> = (log.range_low..log.range_high).filter(|&i| is_hard_error(&lines[i])).collect();
    for &i in hard.iter().take(4) {
        out.line(&format!("   L{:<6} {}", i + 1, lines[i].trim()));
    }
    if hard.len() > 4 {
        out.line(&format!("   ... mais {} erros graves (hard errors)", hard.len() - 4));
    }
    let mut first_chance: Counter<String> = Counter::new();
    for (i, code) in &log.first_chance {
        if log.in_range(*i) {
            first_chance.add(code.clone());
        }
    }
    if !first_chance.items.is_empty() {
        let items: Vec<String> = first_chance.most_common().into_iter().take(5).map(|(code, count)| format!("{} x{count}", st(&code))).collect();
        out.line(&format!("   excecoes de usuario de primeira chance: {}", items.join(", ")));
    }
    // As últimas linhas relevantes antes do ponto final.
    let end_at = stop.or_else(|| ends.first().copied()).unwrap_or(log.range_high);
    let mut tail = Vec::new();
    let mut i = end_at;
    while i > log.range_low && tail.len() < tail_count {
        i -= 1;
        if meaningful(&lines[i]) && !is_end(&lines[i]) {
            tail.push(i);
        }
    }
    let what = if stop.is_some() { "o STOP" } else if !ends.is_empty() { "o primeiro erro do kernel" } else { "o fim" };
    out.line(&format!("   ultimas {} linhas relevantes antes de {what}:", tail.len()));
    for &i in tail.iter().rev() {
        out.line(&format!("     L{:<6} {}", i + 1, lines[i].trim()));
    }
}

fn exit_text(log: &Log, exit: &Exit) -> String {
    let mut how = exit.how.text().to_string();
    if exit.by.is_some() {
        how.push_str(&format!(" {}", log.pname(exit.by)));
    }
    let mut text = format!("fim{} L{} codigo {} [{how}]", exit.conf, exit.line + 1, st(&exit.code));
    if let Some(exception) = exit.exception.map(|index| &log.unhandled[index]) {
        text.push_str(&format!(" SEM TRATAMENTO {} @{} (L{})", st(&exception.code), exception.address, exception.line + 1));
    }
    if let Some(blocked) = &exit.blocked {
        text.push_str(&format!("; {blocked}"));
    }
    text
}

/// O processo aparece na faixa: criado antes do fim dela e não terminado
/// antes do começo.
fn visible(log: &Log, proc: &Proc) -> bool {
    if proc.line.is_some_and(|line| line >= log.range_high) {
        return false;
    }
    !proc.exit.is_some_and(|exit| log.exits[exit].line < log.range_low)
}

fn by_creation(log: &Log, pids: &[u64]) -> Vec<u64> {
    let mut sorted: Vec<u64> = pids.to_vec();
    sorted.sort_by_key(|&pid| log.get(pid).and_then(|proc| proc.line).unwrap_or(usize::MAX));
    sorted
}

fn show_proc(out: &mut Out, log: &Log, pid: u64, depth: usize, printed: &mut HashSet<u64>, all: bool) {
    if !printed.insert(pid) {
        return;
    }
    let Some(proc) = log.get(pid) else { return };
    let kids = by_creation(log, &proc.children);
    let any_visible_kid = kids.iter().any(|&kid| log.get(kid).is_some_and(|kid| visible(log, kid)));
    if visible(log, proc) || any_visible_kid {
        let pad = format!("   {}{}", "  ".repeat(depth), if depth > 0 { "+- " } else { "" });
        let flags = if proc.initial { " [inicial]" } else { "" };
        let created = proc.line.map_or_else(String::new, |line| format!(" L{}", line + 1));
        let mut text = format!("{pad}{} {}{flags}{created}", proc.name, proc.pid);
        if let Some(exit) = proc.exit.map(|index| &log.exits[index]) {
            text.push_str("  ");
            text.push_str(&exit_text(log, exit));
        }
        out.line(&text);
        let sub = format!("   {}   ", "  ".repeat(depth + 1));
        if let Some(exit) = proc.exit.map(|index| &log.exits[index]) {
            let limit = if all { exit.post.len() } else { exit.post.len().min(4) };
            for &i in &exit.post[..limit] {
                out.line(&format!("{sub}L{} {}", i + 1, log.lines[i].trim()));
            }
        }
        for (line, name, reason) in &proc.create_fails {
            if log.in_range(*line) {
                out.line(&format!("{sub}x L{} nao criou {name}: {reason}", line + 1));
            }
        }
        let bad: Vec<String> = proc.thread_bad.iter().filter(|(_, _, line)| log.in_range(*line)).take(6).map(|(tid, status, line)| format!("tid {tid}={status} L{}", line + 1)).collect();
        if !bad.is_empty() {
            out.line(&format!("{sub}threads que sairam com status != 0: {}", bad.join(", ")));
        }
    }
    for kid in kids {
        show_proc(out, log, kid, depth + 1, printed, all);
    }
}

fn section_procs(out: &mut Out, log: &Log, all: bool) {
    out.line(&format!("== processos ({}; pid decimal; '~' = pid deduzido da atividade, '~?' = ambiguo)", log.procs.len()));
    let roots: Vec<u64> = log.procs.iter().filter(|proc| proc.parent.map_or(true, |parent| log.get(parent).is_none())).map(|proc| proc.pid).collect();
    let mut printed = HashSet::new();
    for pid in by_creation(log, &roots) {
        let Some(proc) = log.get(pid) else { continue };
        if proc.parent.is_none() && (proc.name != "?" || !proc.children.is_empty() || proc.line.is_some()) {
            show_proc(out, log, pid, 0, &mut printed, all);
        }
    }
    let mut others: Vec<&Proc> = log.procs.iter().filter(|proc| !printed.contains(&proc.pid) && visible(log, proc) && proc.name != "?").collect();
    others.sort_by_key(|proc| proc.line.unwrap_or(0));
    let others: Vec<u64> = others.iter().map(|proc| proc.pid).collect();
    for pid in others {
        show_proc(out, log, pid, 0, &mut printed, all);
    }
    let mut anonymous: Vec<u64> = log.procs.iter().filter(|proc| !printed.contains(&proc.pid) && proc.name == "?" && visible(log, proc)).map(|proc| proc.pid).collect();
    anonymous.sort_unstable();
    if !anonymous.is_empty() {
        let list: Vec<String> = anonymous.iter().take(20).map(u64::to_string).collect();
        out.line(&format!("   pids vistos so em linhas (sem registro de criacao): {}", list.join(", ")));
    }
    // Os fins que não ficaram ligados a um processo da árvore.
    let loose: Vec<usize> = (0..log.exits.len()).filter(|&e| log.in_range(log.exits[e].line) && log.exits[e].pid.map_or(true, |pid| log.get(pid).map_or(true, |proc| proc.exit != Some(e)))).collect();
    if !loose.is_empty() {
        out.line(&format!("   fins de processo fora da arvore ({}):", loose.len()));
    }
    let limit = if all { loose.len() } else { loose.len().min(12) };
    for &e in &loose[..limit] {
        let exit = &log.exits[e];
        let mut who = exit.name.as_ref().map_or_else(String::new, |name| format!("{name} "));
        let mut candidates = String::new();
        if exit.pid.is_some() {
            who = format!("{}{} ", log.pname(exit.pid), exit.conf);
        } else if !exit.candidates.is_empty() && exit.name.is_none() {
            let names: Vec<String> = exit.candidates.iter().take(5).map(|&pid| log.pname(Some(pid))).collect();
            candidates = format!("candidatos: {}{}", names.join(", "), if exit.candidates.len() > 5 { " ..." } else { "" });
        }
        out.line(&format!("     {who}EPROCESS {}: {}", exit.pointer, exit_text(log, exit)));
        if !candidates.is_empty() {
            out.line(&format!("        {candidates}"));
        }
        for &i in exit.post.iter().take(4) {
            out.line(&format!("        L{} {}", i + 1, log.lines[i].trim()));
        }
    }
    if loose.len() > 12 && !all {
        out.line(&format!("     ... mais {} fins (--all)", loose.len() - 12));
    }
    let linked: HashSet<usize> = log.exits.iter().filter_map(|exit| exit.exception).collect();
    for (index, exception) in log.unhandled.iter().enumerate() {
        if !linked.contains(&index) && log.in_range(exception.line) {
            out.line(&format!("   !! L{} excecao sem tratamento {} @{} sem fim de processo logo depois", exception.line + 1, st(&exception.code), exception.address));
        }
    }
    for attempt in &log.attempts {
        if log.in_range(attempt.line) {
            let target = log.pointer_at(&attempt.pointer, attempt.line).map_or_else(|| attempt.pointer.clone(), |pid| log.pname(Some(pid)));
            let caller = if attempt.by.is_some() { log.pname(attempt.by) } else { "(chamador desconhecido)".into() };
            out.line(&format!("   L{} {caller} tentou NtTerminateProcess({target}, {}) -> {}", attempt.line + 1, attempt.code, st(&attempt.status)));
        }
    }
    for fail in &log.create_fails {
        if fail.creator.is_none() && log.in_range(fail.line) {
            out.line(&format!("   x L{} nao criou {}: {}", fail.line + 1, fail.name, fail.reason));
        }
    }
    for (i, name, code) in &log.exited {
        if log.in_range(*i) {
            out.line(&format!("   L{} {name} saiu (rodado pelo kernel): codigo {}", i + 1, st(code)));
        }
    }
}

/// Um grupo de falhas iguais: (pid, syscall, status, resto).
struct FailGroup {
    key: (Option<u64>, String, String, String),
    count: usize,
    first: usize,
    last: usize,
    callers: Counter<String>,
    rips: Counter<String>,
    tids: Counter<u64>,
}

/// Troca os números hexadecimais por `#` (o agrupamento das outras linhas FALHOU).
fn without_numbers(line: &str) -> String {
    let mut output = String::new();
    let mut rest = line;
    while let Some(at) = rest.find("0x") {
        let digits = rest[at + 2..].find(|character: char| !character.is_ascii_hexdigit()).unwrap_or(rest.len() - at - 2);
        if digits == 0 {
            output.push_str(&rest[..at + 2]);
            rest = &rest[at + 2..];
            continue;
        }
        output.push_str(&rest[..at]);
        output.push('#');
        rest = &rest[at + 2 + digits..];
    }
    output.push_str(rest);
    output
}

fn section_fails(out: &mut Out, log: &Log, top: usize, all: bool, format: &str) {
    let mut groups: Vec<FailGroup> = Vec::new();
    let mut group_index: HashMap<(Option<u64>, String, String, String), usize> = HashMap::new();
    let mut other: Vec<(String, usize, usize, usize, String)> = Vec::new();
    let mut other_index: HashMap<String, usize> = HashMap::new();
    for i in log.range_low..log.range_high {
        let line = &log.lines[i];
        if let Some(fail) = parse_fail(line) {
            let key = (fail.pid, fail.name.to_string(), fail.status.to_ascii_lowercase(), fail.detail.trim().to_string());
            let index = *group_index.entry(key.clone()).or_insert_with(|| {
                groups.push(FailGroup { key, count: 0, first: i, last: i, callers: Counter::new(), rips: Counter::new(), tids: Counter::new() });
                groups.len() - 1
            });
            let group = &mut groups[index];
            group.count += 1;
            group.last = i;
            if let Some(caller) = fail.caller {
                group.callers.add(caller.to_string());
            }
            group.rips.add(fail.rip.to_string());
            if let Some(tid) = fail.tid {
                group.tids.add(tid);
            }
            continue;
        }
        if line.contains("FALHOU") && marker_token(line).is_none() {
            let key = without_numbers(line.trim());
            let index = *other_index.entry(key.clone()).or_insert_with(|| {
                other.push((key, 0, i, i, line.trim().to_string()));
                other.len() - 1
            });
            other[index].1 += 1;
            other[index].3 = i;
        }
    }
    let total: usize = groups.iter().map(|group| group.count).sum();
    out.line(&format!("== FALHOU: {total} falhas de syscall em {} grupos ({format})", groups.len()));
    // Por pid, na ordem da primeira aparição de cada pid.
    let mut by_pid: Vec<(Option<u64>, Vec<usize>)> = Vec::new();
    for (index, group) in groups.iter().enumerate() {
        match by_pid.iter_mut().find(|(pid, _)| *pid == group.key.0) {
            Some((_, list)) => list.push(index),
            None => by_pid.push((group.key.0, vec![index])),
        }
    }
    // (syscall, status) que falha em pelo menos metade dos processos (>= 3): uma vez só.
    let mut spread: Vec<((String, String), HashSet<u64>, usize)> = Vec::new();
    for group in &groups {
        let Some(pid) = group.key.0 else { continue };
        let key = (group.key.1.clone(), group.key.2.clone());
        match spread.iter_mut().find(|(known, _, _)| *known == key) {
            Some((_, pids, count)) => {
                pids.insert(pid);
                *count += group.count;
            }
            None => spread.push((key, HashSet::from([pid]), group.count)),
        }
    }
    let processes = by_pid.iter().filter(|(pid, _)| pid.is_some()).count();
    let mut common: Vec<&((String, String), HashSet<u64>, usize)> = if all { Vec::new() } else { spread.iter().filter(|(_, pids, _)| processes >= 3 && pids.len() * 2 >= processes).collect() };
    common.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
    if !common.is_empty() {
        out.line("   falham em >= metade dos processos (fora das listas por processo abaixo):");
        for ((name, status), pids, count) in &common {
            out.line(&format!("     {count:>5}x {name} {}  ({} procs)", st(status), pids.len()));
        }
    }
    let is_common = |name: &str, status: &str| common.iter().any(|((known_name, known_status), _, _)| known_name == name && known_status == status);
    out.line("   avisos (0x8...) por processo ficam numa linha '~'; erros listados por contagem");
    by_pid.sort_by_key(|(_, list)| list.iter().map(|&index| groups[index].first).min().unwrap_or(0));
    for (pid, list) in &by_pid {
        let mut items: Vec<usize> = list.clone();
        items.sort_by(|a, b| groups[*b].count.cmp(&groups[*a].count));
        let count: usize = items.iter().map(|&index| groups[index].count).sum();
        let label = if pid.is_some() { log.pname(*pid) } else { "(sem pid: formato antigo)".to_string() };
        out.line(&format!("   {label}: {count} falhas, {} grupos", items.len()));
        let warning = |index: &usize| !all && hex_value(&groups[*index].key.2).is_some_and(|status| status & 0xC000_0000 == 0x8000_0000);
        let warnings: Vec<usize> = items.iter().filter(|&&index| warning(&index)).copied().collect();
        let errors: Vec<usize> = items.iter().filter(|&&index| !warning(&index) && !is_common(groups[index].key.1.as_str(), groups[index].key.2.as_str())).copied().collect();
        if !warnings.is_empty() {
            let shown: Vec<String> = warnings.iter().take(5).map(|&index| {
                let group = &groups[index];
                format!("{} {} {}x", group.key.1, status_name(&group.key.2).unwrap_or(group.key.2.as_str()), group.count)
            }).collect();
            let more = if warnings.len() > 5 { format!(" +{}", warnings.len() - 5) } else { String::new() };
            out.line(&format!("     ~ {}{more}", shown.join(", ")));
        }
        let limit = if all { errors.len() } else { errors.len().min(top) };
        for &index in &errors[..limit] {
            let group = &groups[index];
            let mut extra = Vec::new();
            if !group.key.3.is_empty() {
                extra.push(group.key.3.clone());
            }
            let callers: Vec<&String> = group.callers.items.iter().map(|(caller, _)| caller).filter(|caller| caller.as_str() != "0x0").collect();
            if !callers.is_empty() {
                let names: Vec<&str> = callers.iter().take(3).map(|caller| caller.as_str()).collect();
                extra.push(format!("chamador {}{}", names.join(","), if callers.len() > 3 { "..." } else { "" }));
            }
            if pid.is_none() && group.rips.items.len() > 1 {
                let rips: Vec<&str> = group.rips.items.iter().take(3).map(|(rip, _)| rip.as_str()).collect();
                extra.push(format!("rips {}", rips.join(",")));
            }
            if group.tids.items.len() > 1 {
                extra.push(format!("{} threads", group.tids.items.len()));
            }
            out.line(&format!("     {:>5}x {} {}  {}  {}", group.count, group.key.1, st(&group.key.2), span(group.first, group.last), extra.join("  ")));
        }
        if errors.len() > limit {
            let rest: usize = errors[limit..].iter().map(|&index| groups[index].count).sum();
            out.line(&format!("     ... mais {} grupos ({rest} falhas)", errors.len() - limit));
        }
    }
    if !other.is_empty() {
        out.line(&format!("   outras linhas FALHOU ({}):", other.iter().map(|item| item.1).sum::<usize>()));
        let mut items: Vec<&(String, usize, usize, usize, String)> = other.iter().collect();
        items.sort_by(|a, b| b.1.cmp(&a.1));
        let limit = if all { items.len() } else { items.len().min(top) };
        for (_, count, first, last, text) in &items[..limit] {
            out.line(&format!("     {count:>5}x {}  {text}", span(*first, *last)));
        }
    }
}

fn section_unimplemented(out: &mut Out, log: &Log) {
    let mut counter: Counter<String> = Counter::new();
    let mut first: HashMap<String, usize> = HashMap::new();
    for i in log.range_low..log.range_high {
        if let Some((name, _)) = parse_unimplemented(&log.lines[i]) {
            counter.add(name.to_string());
            first.entry(name.to_string()).or_insert(i);
        }
    }
    if counter.items.is_empty() {
        return;
    }
    out.line(&format!("== syscalls sem implementacao ({})", counter.items.len()));
    let items: Vec<String> = counter.most_common().into_iter().map(|(name, count)| format!("{name} x{count} (L{})", first[&name] + 1)).collect();
    out.line(&format!("   {}", items.join(", ")));
}

/// O bloco não é a repetição de um bloco menor.
fn primitive(block: &[String]) -> bool {
    let length = block.len();
    !(1..length).any(|period| length % period == 0 && block[period..].iter().chain(block[..period].iter()).eq(block.iter()))
}

/// Um laço: (primeira linha, última linha, período, repetições).
type Loop = (usize, usize, usize, usize);

fn find_loops(lines: &[String], low: usize, high: usize, minimum: usize) -> Vec<Loop> {
    let mut loops = Vec::new();
    let mut covered = vec![false; high.saturating_sub(low)];
    for period in 1..9 {
        let mut start: Option<usize> = None;
        for i in low + period..=high {
            let same = i < high && lines[i] == lines[i - period];
            if same {
                start.get_or_insert(i - period);
                continue;
            }
            let Some(first) = start.take() else { continue };
            let repetitions = (i - first) / period;
            let block = &lines[first..first + period];
            let length = repetitions * period;
            if repetitions >= minimum && block.iter().any(|line| !line.trim().is_empty()) && primitive(block) {
                let already = covered[first - low..first - low + length].iter().filter(|&&flag| flag).count();
                if (already as f64) < length as f64 / 2.0 {
                    loops.push((first, first + length - 1, period, repetitions));
                    for flag in &mut covered[first - low..first - low + length] {
                        *flag = true;
                    }
                }
            }
        }
    }
    loops.sort_by(|a, b| (b.1 - b.0).cmp(&(a.1 - a.0)));
    loops
}

fn section_loops(out: &mut Out, log: &Log, minimum: usize, all: bool) {
    let lines = log.lines;
    let loops = find_loops(lines, log.range_low, log.range_high, minimum);
    // As sequências do mesmo bloco (em qualquer fase) vão juntas.
    let mut folded: Vec<(Vec<&str>, usize, Vec<(usize, usize, usize)>)> = Vec::new();
    for &(first, last, period, repetitions) in &loops {
        let block: Vec<&str> = lines[first..first + period].iter().map(String::as_str).collect();
        let key = (0..period).map(|phase| block[phase..].iter().chain(block[..phase].iter()).copied().collect::<Vec<&str>>()).min().unwrap_or_default();
        match folded.iter_mut().find(|(known, _, _)| *known == key) {
            Some((_, _, runs)) => runs.push((first, last, repetitions)),
            None => folded.push((key, period, vec![(first, last, repetitions)])),
        }
    }
    let longest = |runs: &[(usize, usize, usize)]| runs.iter().map(|(first, last, _)| last - first).max().unwrap_or(0);
    let mut items: Vec<usize> = (0..folded.len()).collect();
    items.sort_by(|a, b| longest(folded[*b].2.as_slice()).cmp(&longest(folded[*a].2.as_slice())));
    out.line(&format!("== lacos (>= {minimum} repeticoes seguidas): {} sequencias de {} linhas ou blocos distintos", loops.len(), folded.len()));
    let mut shown: Vec<usize> = if all { items.clone() } else { items.iter().take(8).copied().collect() };
    shown.sort_by_key(|&index| folded[index].2.iter().map(|(first, _, _)| *first).min().unwrap_or(0));
    for &index in &shown {
        let (_, period, runs) = &folded[index];
        let mut runs = runs.clone();
        runs.sort_unstable();
        let &(first, last, repetitions) = runs.iter().max_by(|a, b| (a.1 - a.0).cmp(&(b.1 - b.0)).then(b.0.cmp(&a.0))).unwrap_or(&(0, 0, 0));
        let more = if runs.len() > 1 {
            let total: usize = runs.iter().map(|run| run.2).sum();
            format!(" (+{} sequencias, {total} repeticoes ao todo, L{}-L{})", runs.len() - 1, runs[0].0 + 1, runs[runs.len() - 1].1 + 1)
        } else {
            String::new()
        };
        if *period == 1 {
            out.line(&format!("   L{}-L{} x{repetitions}{more}  {}", first + 1, last + 1, lines[first].trim()));
        } else {
            out.line(&format!("   L{}-L{} x{repetitions}{more} bloco de {period} linhas:", first + 1, last + 1));
            for line in &lines[first..first + period] {
                out.line(&format!("        | {}", line.trim()));
            }
        }
    }
    if items.len() > shown.len() {
        out.line(&format!("   ... mais {} lacos (mais curtos); --all lista todos", items.len() - shown.len()));
    }
    // As linhas mais repetidas (fora de sequência); FALHOU e ruído ficam de fora.
    let mut hot: Counter<&str> = Counter::new();
    for line in &lines[log.range_low..log.range_high] {
        if meaningful(line) && parse_fail(line).is_none() {
            hot.add(line.as_str());
        }
    }
    let floor = (3 * minimum).max(30);
    let hot_items: Vec<(&str, usize)> = hot.most_common().into_iter().take(12).filter(|(_, count)| *count >= floor).collect();
    if !hot_items.is_empty() {
        out.line("   linhas mais repetidas no todo:");
        for (line, count) in hot_items.iter().take(6) {
            out.line(&format!("     {count:>5}x {}", line.trim()));
        }
    }
    // A faixa termina dentro de um laço (travamento)?
    let stop = (log.range_low..log.range_high).find(|&i| is_stop(&lines[i]));
    if stop.is_none() && log.range_high > log.range_low {
        let mut last_end = log.range_high - 1;
        while last_end > log.range_low && lines[last_end].trim().is_empty() {
            last_end -= 1;
        }
        let window: Vec<&str> = lines[log.range_high.saturating_sub(150).max(log.range_low)..log.range_high].iter().map(String::as_str).filter(|line| !line.trim().is_empty()).collect();
        let mut distinct: Counter<&str> = Counter::new();
        for line in &window {
            distinct.add(*line);
        }
        if let Some(&(first, last, period, repetitions)) = loops.iter().find(|lp| lp.1 + 1 >= last_end) {
            out.line(&format!("   !! a faixa TERMINA DENTRO DE UM LACO: L{}-L{} x{repetitions} (bloco de {period}) ate a ultima linha", first + 1, last + 1));
        }
        if window.len() >= 60 && distinct.items.len() <= 12 {
            out.line(&format!("   !! as ultimas {} linhas tem so {} linhas distintas (travamento ou espera ativa?):", window.len(), distinct.items.len()));
            for (line, count) in distinct.most_common().into_iter().take(5) {
                out.line(&format!("     {count:>5}x {}", line.trim()));
            }
        }
    }
}

fn section_last(out: &mut Out, log: &Log, count: usize) {
    let mut per: Vec<(u64, Vec<usize>)> = Vec::new();
    for (&i, &pid) in &log.attributed {
        if log.in_range(i) && meaningful(&log.lines[i]) {
            match per.iter_mut().find(|(known, _)| *known == pid) {
                Some((_, list)) => list.push(i),
                None => per.push((pid, vec![i])),
            }
        }
    }
    if per.is_empty() {
        return;
    }
    out.line(&format!("== ultimas {count} linhas por processo (as linhas com o pid; as FALHOU do formato antigo nao tem)"));
    per.sort_by_key(|(_, list)| list.last().copied().unwrap_or(0));
    for (pid, list) in &per {
        out.line(&format!("   {} ({} linhas, ultima L{}):", log.pname(Some(*pid)), list.len(), list.last().map_or(0, |line| line + 1)));
        for &i in &list[list.len().saturating_sub(count)..] {
            out.line(&format!("     L{:<6} {}", i + 1, log.lines[i].trim()));
        }
    }
}

fn section_memory(out: &mut Out, log: &Log) {
    let mut rows: Vec<(usize, Memory)> = Vec::new();
    let mut fails: Vec<usize> = Vec::new();
    for i in log.range_low..log.range_high {
        let line = &log.lines[i];
        if let Some(memory) = parse_memory(line) {
            rows.push((i, memory));
        } else if is_memory_failure(line) {
            fails.push(i);
        }
    }
    if rows.is_empty() && fails.is_empty() {
        return;
    }
    out.line(&format!("== memoria ({} linhas [mm] memoria, {} linhas de falha)", rows.len(), fails.len()));
    if let (Some(&(first_line, first)), Some(&(_, last))) = (rows.first(), rows.last()) {
        let megabytes = |pages: u64| pages * 4 / 1024;
        let (low, low_at) = rows.iter().map(|(i, memory)| (memory.free, *i)).min().unwrap_or((0, 0));
        let (high_heap, high_heap_at) = rows.iter().map(|(i, memory)| (memory.heap, *i)).max().unwrap_or((0, 0));
        out.line(&format!(
            "   PFN livres: primeira {} ({} MB) L{}, menor {low} ({} MB) L{}, ultima {} ({} MB) de {} ({} MB)",
            first.free,
            megabytes(first.free),
            first_line + 1,
            megabytes(low),
            low_at + 1,
            last.free,
            megabytes(last.free),
            last.total,
            megabytes(last.total)
        ));
        out.line(&format!("   commit: ultimo {}/{} paginas (maximo {}, pico {}); nao residentes por ultimo {}", last.commit, last.commit_limit, last.maximum, last.peak, last.nonresident));
        out.line(&format!("   heap do kernel: maior {high_heap} KB L{} de {} KB; ultimo {} KB", high_heap_at + 1, last.heap_total, last.heap));
    }
    for &i in fails.iter().take(8) {
        out.line(&format!("!! L{:<6} {}", i + 1, log.lines[i].trim()));
    }
    if fails.len() > 8 {
        out.line(&format!("   ... mais {} linhas de falha", fails.len() - 8));
    }
}

// ---- opções e o resumo ------------------------------------------------------------

#[derive(Debug)]
struct Options {
    log: String,
    since: Option<String>,
    until: Option<String>,
    boot: Option<String>,
    last: usize,
    tail: usize,
    top: usize,
    loop_minimum: usize,
    width: usize,
    all: bool,
    only: Option<String>,
}

fn parse_options(arguments: &[String]) -> Result<Options, String> {
    let mut options = Options { log: String::new(), since: None, until: None, boot: None, last: 4, tail: 10, top: 6, loop_minimum: 10, width: 150, all: false, only: None };
    let mut iterator = arguments.iter();
    while let Some(argument) = iterator.next() {
        if argument == "--help" || argument == "-h" {
            return Err(USAGE.to_string());
        }
        if argument == "--all" {
            options.all = true;
            continue;
        }
        if !argument.starts_with("--") {
            if !options.log.is_empty() {
                return Err(format!("logsum: um log so ({argument} sobrando)\n{USAGE}"));
            }
            options.log = argument.clone();
            continue;
        }
        // `--opcao=valor` ou `--opcao valor`.
        let (name, value) = match argument.split_once('=') {
            Some((name, value)) => (name.to_string(), value.to_string()),
            None => (argument.clone(), iterator.next().cloned().ok_or_else(|| format!("logsum: {argument} exige um valor"))?),
        };
        let number = |value: &str| value.parse::<usize>().map_err(|_| format!("logsum: {name} aceita um numero ({value} recebido)"));
        match name.as_str() {
            "--since" => options.since = Some(value),
            "--until" => options.until = Some(value),
            "--boot" => options.boot = Some(value),
            "--last" => options.last = number(&value)?,
            "--tail" => options.tail = number(&value)?,
            "--top" => options.top = number(&value)?,
            "--loop-min" => options.loop_minimum = number(&value)?,
            "--width" => options.width = number(&value)?,
            "--only" => options.only = Some(value),
            _ => return Err(format!("logsum: opcao desconhecida: {name}\n{USAGE}")),
        }
    }
    if options.log.is_empty() {
        return Err(USAGE.to_string());
    }
    Ok(options)
}

/// O resumo do texto de um log.
fn summarize(path: &str, lines: &[String], options: &Options) -> Result<String, String> {
    let segments = boots(lines);
    let chosen: Vec<usize> = match (&options.boot, &options.since) {
        (Some(boot), _) if boot == "all" => (0..segments.len()).collect(),
        (Some(boot), _) => {
            let number: usize = boot.parse().map_err(|_| format!("logsum: --boot aceita um numero ou all ({boot} recebido)"))?;
            if number == 0 || number > segments.len() {
                return Err(format!("logsum: --boot {boot}: o log tem {} boot(s)", segments.len()));
            }
            vec![number - 1]
        }
        (None, Some(since)) => {
            let Some(at) = find_marker(lines, 0, lines.len(), since) else {
                let mut tokens: Vec<&str> = Vec::new();
                for line in lines {
                    if let Some(token) = marker_token(line).filter(|token| !NOISY_MARKERS.contains(token)) {
                        if !tokens.contains(&token) {
                            tokens.push(token);
                        }
                    }
                }
                return Err(format!("logsum: marcador {since:?} nao encontrado; marcadores no log: {}", tokens.join(" ")));
            };
            vec![segments.iter().position(|&(start, end)| start <= at && at < end).unwrap_or(segments.len() - 1)]
        }
        (None, None) => vec![segments.len() - 1],
    };
    let sections: Vec<&str> = options.only.as_deref().unwrap_or(SECTIONS).split(',').map(str::trim).collect();
    let wants = |name: &str| sections.contains(&name);
    let mut out = Out { width: options.width, text: String::new() };
    for boot in chosen {
        let (low, high) = segments[boot];
        let mut log = Log::new(lines, low, high);
        if let Some(since) = &options.since {
            log.range_low = find_marker(lines, low, high, since).ok_or_else(|| format!("logsum: marcador {since:?} nao esta no boot {}", boot + 1))?;
        }
        if let Some(until) = &options.until {
            log.range_high = find_marker(lines, log.range_low, high, until).ok_or_else(|| format!("logsum: marcador {until:?} nao encontrado depois do inicio"))?;
        }
        let (mut new, mut old) = (0, 0);
        for i in log.range_low..log.range_high {
            if let Some(fail) = parse_fail(&lines[i]) {
                if fail.pid.is_some() {
                    new += 1;
                } else {
                    old += 1;
                }
            }
        }
        let format = match (new, old) {
            (0, 0) => "nenhuma linha FALHOU".to_string(),
            (_, 0) => "novo (pid:tid + chamador)".to_string(),
            (0, _) => "antigo (sem pid)".to_string(),
            _ => format!("misto ({new} novos, {old} antigos)"),
        };
        if wants("head") {
            section_head(&mut out, &log, path, segments.len(), boot + 1, &format);
        }
        if wants("markers") {
            section_markers(&mut out, &log, options.all);
        }
        if wants("end") {
            section_end(&mut out, &log, options.tail);
        }
        if wants("mem") {
            section_memory(&mut out, &log);
        }
        if wants("procs") {
            section_procs(&mut out, &log, options.all);
        }
        if wants("fails") {
            section_fails(&mut out, &log, options.top, options.all, &format);
        }
        if wants("noimpl") {
            section_unimplemented(&mut out, &log);
        }
        if wants("loops") {
            section_loops(&mut out, &log, options.loop_minimum, options.all);
        }
        if wants("last") {
            section_last(&mut out, &log, options.last);
        }
    }
    Ok(out.text)
}

pub fn run(arguments: &[String]) -> Result<(), String> {
    let options = match parse_options(arguments) {
        Err(message) if message == USAGE => {
            println!("{USAGE}");
            return if arguments.iter().any(|argument| argument == "--help" || argument == "-h") { Ok(()) } else { Err("logsum: falta o arquivo do log".into()) };
        }
        other => other?,
    };
    let bytes = std::fs::read(&options.log).map_err(|error| format!("{}: {error}", options.log))?;
    let lines = load(&bytes);
    print!("{}", summarize(&options.log, &lines, &options)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/fixtures/logsum-c21.txt");

    fn options(extra: &[&str]) -> Options {
        let mut arguments = vec!["serial.log".to_string()];
        arguments.extend(extra.iter().map(|argument| argument.to_string()));
        parse_options(&arguments).unwrap()
    }

    #[test]
    fn line_formats() {
        let fail = parse_fail("[usermode] 60:64 NtOpenKey FALHOU com 0xc0000034 (rip 0x18009d7e4, chamador 0x0) [diag-arquivo] \"\\Registry\"").unwrap();
        assert_eq!((fail.pid, fail.tid, fail.name, fail.status, fail.rip, fail.caller), (Some(60), Some(64), "NtOpenKey", "0xc0000034", "0x18009d7e4", Some("0x0")));
        assert_eq!(fail.detail, "[diag-arquivo] \"\\Registry\"");
        let named = parse_fail("[usermode] 424:800 NtDuplicateObject FALHOU com 0xc0000022 (rip 0x7ffe0a0b14, chamador rpcss.dll+0x9c5ff) negado: dup-upgrade tipo=process").unwrap();
        assert_eq!((named.caller, named.detail), (Some("rpcss.dll+0x9c5ff"), "negado: dup-upgrade tipo=process"));
        let old = parse_fail("[usermode] NtClose FALHOU com 0xc0000008 (rip 0x1800a0b14)").unwrap();
        assert_eq!((old.pid, old.caller, old.detail), (None, None, ""));
        assert_eq!(marker_token("HELLO_KERNEL_OK"), Some("HELLO_KERNEL_OK"));
        assert_eq!(marker_token("CI_KERNEL_POLICY status=0x0"), Some("CI_KERNEL_POLICY"));
        assert_eq!(marker_token("SELFTEST FALHOU: x"), Some("SELFTEST"));
        assert_eq!(marker_token("REBOOT RESET_REG=None"), Some("REBOOT"));
        assert_eq!(marker_token("HELLO_Kernel"), None);
        assert_eq!(marker_token("ABC_ x"), None);
        assert_eq!(marker_token("[boot] fase 1"), None);
        assert_eq!(pids("[usermode] HARDERROR: status=0x1 (pid 508, retorno 0x0) pid=12 rapid 7 pid 9x"), [508, 12]);
        assert_eq!(kernel_pointers("processo 0xffffc000c012b1d0 e 0xffffc000c012b1d0 0xffff1234").len(), 1);
        assert_eq!(parse_create_failure("[ps] NtCreateUserProcess de foo.exe: STATUS_X"), Some(("foo.exe", "STATUS_X")));
        assert_eq!(parse_create_failure("[ps] criacao de bar.exe falhou: sem imagem"), Some(("bar.exe", "sem imagem")));
        assert_eq!(parse_blocked("[thread] 1 thread(s) ainda bloqueada(s) no kernel no fim do processo 0xffffc000c012b1d0"), Some((Some(1), "0xffffc000c012b1d0")));
        assert!(is_end("*** STOP (KeBugCheckEx): 0x1e") && is_end("[sched] processo 12 morreu de fome") && !is_end("*** STOPPED"));
        assert_eq!(without_numbers("[services] FALHOU 0x1f em 0xabc."), "[services] FALHOU # em #.");
        let memory = parse_memory("[mm] memoria (criado 76): PFN livres 328528/352256 paginas, commit 10630/352256 paginas (maximo 352256, pico 10630), nao residentes 0, heap 26480/65535 KB").unwrap();
        assert_eq!((memory.free, memory.total, memory.heap, memory.heap_total), (328528, 352256, 26480, 65535));
    }

    #[test]
    fn loops_and_primitive_blocks() {
        let lines: Vec<String> = ["a", "b", "x", "x", "x", "x", "y", "z", "y", "z", "y", "z", "fim"].iter().map(|line| line.to_string()).collect();
        let loops = find_loops(&lines, 0, lines.len(), 3);
        assert_eq!(loops, [(6, 11, 2, 3), (2, 5, 1, 4)]);
        assert!(primitive(&lines[6..8]));
        assert!(!primitive(&["q".to_string(), "q".to_string()]));
    }

    #[test]
    fn boots_and_load() {
        let lines = load(b"pre\r\n[OpenNT] kernel 64-bit vivo\r\na\0\rb\n[OpenNT] kernel 64-bit vivo\nc\n");
        assert_eq!(lines, ["pre", "[OpenNT] kernel 64-bit vivo", "a", "b", "[OpenNT] kernel 64-bit vivo", "c"]);
        assert_eq!(boots(&lines), [(0, 4), (4, 6)]);
    }

    #[test]
    fn summarizes_the_fixture() {
        let lines = load(FIXTURE.as_bytes());
        let text = summarize("c21.txt", &lines, &options(&[])).unwrap();
        // A árvore: o smss inicial cria o smss da sessão, que cria o csrss.
        assert!(text.contains("   smss.exe 60 [inicial]"), "{text}");
        assert!(text.contains("     +- smss.exe 76 L"), "{text}");
        assert!(text.contains("proprio (NtTerminateProcess)"), "{text}");
        assert!(text.contains("== FALHOU: "), "{text}");
        assert!(text.contains("NtOpenKey 0xc0000034 OBJECT_NAME_NOT_FOUND"), "{text}");
        assert!(text.contains("== syscalls sem implementacao (1)\n   NtGetMUIRegistryInfo x1 (L"), "{text}");
        assert!(text.contains("== fim\n"), "{text}");
        assert!(text.contains("*** STOP (KeBugCheckEx): 0x0000001e"), "{text}");
        assert!(text.contains("== lacos (>= 10 repeticoes seguidas): 1 sequencias"), "{text}");
        assert!(text.contains("== memoria (") && text.contains("   heap do kernel: maior "), "{text}");
        assert!(text.contains("~ NtEnumerateValueKey NO_MORE_ENTRIES 4x"), "{text}");
        let only = summarize("c21.txt", &lines, &options(&["--only=noimpl"])).unwrap();
        assert!(only.starts_with("== syscalls sem implementacao (1)"), "{only}");
        assert!(summarize("c21.txt", &lines, &options(&["--since=NAO_EXISTE_MARCADOR"])).unwrap_err().contains("marcadores no log: HELLO_KERNEL_OK"));
        let since = summarize("c21.txt", &lines, &options(&["--since", "SMSS_CSRSS_OK", "--only=head"])).unwrap();
        assert!(since.contains(", faixa L20-L77"), "{since}");
        // Os dois fins de processo ficam fora da árvore, com os candidatos.
        assert!(text.contains("   fins de processo fora da arvore (2):\n     EPROCESS 0xffffc000c0082bb0: fim~? L32 codigo 0x0 SUCCESS [proprio (NtTerminateProcess)]\n        candidatos: smss.exe 76, smss.exe 60, csrss.exe 96\n"), "{text}");
        assert!(text.contains("== lacos (>= 10 repeticoes seguidas): 1 sequencias de 1 linhas ou blocos distintos\n   L53-L64 x12  C2=00000000048A0FF8 SP=00000000048A1000\n"), "{text}");
    }

    #[test]
    fn options_parse() {
        let parsed = options(&["--top=3", "--width", "0", "--all", "--boot=all"]);
        assert_eq!((parsed.top, parsed.width, parsed.all, parsed.boot.as_deref()), (3, 0, true, Some("all")));
        assert!(parse_options(&["--top=x".to_string(), "a.log".to_string()]).is_err());
        assert!(parse_options(&["--nada".to_string(), "a.log".to_string()]).unwrap_err().contains("opcao desconhecida"));
        assert!(parse_options(&[]).is_err());
    }
}
