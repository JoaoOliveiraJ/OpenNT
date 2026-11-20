//! A pilha inteira de uma thread do OpenNT: as passagens que o desenrolar
//! comum (`unwind`) não vê, nos trampolins do kernel do OpenNT, e o processo
//! das leituras da parte de usuário.
//!
//! As passagens (o lado do kernel fica em `kernel/src/hal/amd64`):
//! - a entrada de syscall (`usermode.rs`, `user_syscall_entry`): empilha os
//!   registradores do anel 3 no topo da pilha de kernel (RAX, RCX = o RIP
//!   do usuário, RDX, RSI, RDI, R8, R9, R10, R11 = RFLAGS, RBX, RBP,
//!   R12-R15), reserva 0x208 bytes para o FXSAVE e chama
//!   `opennt_user_syscall`. É o papel do KTRAP_FRAME do KiSystemCall64: o
//!   quadro com o retorno desse `call` passa para o anel 3. O RSP do
//!   usuário não fica no quadro (fica na KPCR.UserRsp); o
//!   `opennt_user_syscall` o copia, com o RIP, no CONTEXT do intervalo da
//!   thread (o do `uthreads`). Vale o RSP desse CONTEXT quando o RIP dele é
//!   o do quadro; senão, o KPCR.UserRsp do processador em que a thread roda;
//! - o trampolim dos exports (`win32_thunk.rs`, `opennt_win32_common`):
//!   monta um quadro de RBP, salva o CONTEXT AMD64 do código nativo que
//!   chamou o export em RBP - 0x500 e chama `opennt_ntoskrnl_dispatch`: o
//!   quadro com o retorno desse `call` passa para o código nativo, com os
//!   registradores não voláteis dele;
//! - o começo de uma pilha: `opennt_kernel_thread_start` (o `call` da
//!   rotina de uma thread de kernel) e `opennt_kernel_thread_return` (o
//!   retorno da rotina de um contexto nativo).
//!
//! Os pontos saem dos símbolos do `kernel.elf`, e cada `call` é conferido
//! no código do alvo (`E8 rel32` para a rotina certa).
//!
//! A parte de usuário é lida no espaço do processo da thread: o processo
//! das leituras passa a ser o dela enquanto a pilha é lida (os módulos de
//! usuário dele entram nos símbolos). Sem processo escolhido antes, as
//! leituras voltam ao processador depois; os módulos ficam para os nomes
//! dos quadros. Com outro processo escolhido, a troca fica (como o
//! `.thread` do WinDbg com o processo).

use std::sync::Arc;

use super::client::Client;
use super::monitor::ThreadContext;
use super::symbols::Symbols;
use super::unwind::{self, Context, Crossing, FunctionTable, ReadMemory, Target, Transition, Walk};
use super::user::{self, UserThread};

/// Bytes entre o RSP do quadro com o retorno do `call opennt_user_syscall`
/// e os registradores empilhados pela entrada de syscall (o `sub rsp,
/// 0x208` do FXSAVE).
pub const SYSCALL_SAVE_AREA: u64 = 0x208;
/// A ordem dos registradores no quadro da entrada de syscall.
const SYSCALL_FRAME: [&str; 15] = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "rbx", "rbp", "r12", "r13", "r14", "r15"];
/// Onde o trampolim dos exports salva o CONTEXT do chamador (RBP - 0x500).
pub const EXPORT_CONTEXT_BELOW_RBP: u64 = 0x500;
/// Os registradores que valem no chamador depois de uma chamada (os não
/// voláteis e o RSP).
const NONVOLATILE: [&str; 9] = ["rbx", "rsp", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15"];
/// KPCR.UserRsp (gs:[10h]): a pilha do usuário na entrada de syscall.
const KPCR_USER_RSP: u64 = 0x10;
/// O `mov rdi, r13; call r12` do `opennt_kernel_thread_start` cabe aqui.
const THREAD_START_SIZE: u64 = 0x10;
/// O `call` de um trampolim fica até aqui depois do começo dele (o da
/// entrada de syscall em +0x60, o do trampolim dos exports em +0x110).
const CALL_WINDOW: u64 = 0x400;
const USER_LIMIT: u64 = 0x0000_8000_0000_0000;
const SYSTEM_HALF: u64 = 0xFFFF_8000_0000_0000;

/// Os símbolos do kernel do OpenNT que marcam as passagens.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KernelLabels {
    /// `user_syscall_entry`, a entrada de syscall (o alvo do LSTAR).
    pub syscall_entry: Option<u64>,
    /// `opennt_user_syscall`, chamada pela entrada de syscall.
    pub syscall_service: Option<u64>,
    /// `opennt_win32_common`, o trampolim comum dos exports.
    pub export_common: Option<u64>,
    /// `opennt_ntoskrnl_dispatch`, chamada pelo trampolim dos exports.
    pub export_dispatch: Option<u64>,
    /// `opennt_kernel_thread_start`.
    pub thread_start: Option<u64>,
    /// `opennt_kernel_thread_return`.
    pub thread_return: Option<u64>,
}

impl KernelLabels {
    pub fn from_symbols(symbols: &Symbols) -> Self {
        let find = |name: &str| symbols.kernel().and_then(|kernel| kernel.symbols.iter().find(|symbol| symbol.name == name)).map(|symbol| symbol.address);
        Self {
            syscall_entry: find("user_syscall_entry"),
            syscall_service: find("opennt_user_syscall"),
            export_common: find("opennt_win32_common"),
            export_dispatch: find("opennt_ntoskrnl_dispatch"),
            thread_start: find("opennt_kernel_thread_start"),
            thread_return: find("opennt_kernel_thread_return"),
        }
    }
}

/// Uma passagem do kernel do OpenNT num endereço de retorno.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Site {
    /// O retorno do `call opennt_user_syscall` da entrada de syscall.
    Syscall,
    /// O retorno do `call opennt_ntoskrnl_dispatch` do trampolim.
    Export,
    /// O retorno do `call r12` do começo de uma thread de kernel.
    ThreadStart,
    /// A sentinela de retorno de um contexto nativo.
    ThreadReturn,
}

/// O destino do `call rel32` que volta em `address`.
fn call_target(memory: &mut dyn ReadMemory, address: u64) -> Option<u64> {
    let bytes = memory.read(address.wrapping_sub(5), 5).ok()?;
    (bytes.len() == 5 && bytes[0] == 0xE8).then(|| address.wrapping_add(i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as i64 as u64))
}

/// `address` pode ser o retorno do `call` do trampolim que começa em
/// `start` (sem o símbolo do começo, qualquer endereço pode).
fn near(start: Option<u64>, address: u64) -> bool {
    start.is_none_or(|start| address > start && address - start <= CALL_WINDOW)
}

/// A passagem cujo endereço de retorno é `address`, se há uma.
pub fn site(labels: &KernelLabels, memory: &mut dyn ReadMemory, address: u64) -> Option<Site> {
    if labels.thread_return == Some(address) {
        return Some(Site::ThreadReturn);
    }
    if labels.thread_start.is_some_and(|start| address > start && address - start <= THREAD_START_SIZE) {
        return Some(Site::ThreadStart);
    }
    // Só o código perto de um trampolim é lido (um retorno por quadro).
    let syscall = labels.syscall_service.filter(|_| near(labels.syscall_entry, address));
    let export = labels.export_dispatch.filter(|_| near(labels.export_common, address));
    if syscall.is_none() && export.is_none() {
        return None;
    }
    let routine = call_target(memory, address)?;
    if syscall == Some(routine) {
        return Some(Site::Syscall);
    }
    (export == Some(routine)).then_some(Site::Export)
}

fn named(values: &[(&str, u64)], name: &str) -> Option<u64> {
    values.iter().find(|(register, _)| *register == name).map(|(_, value)| *value)
}

/// Os registradores do anel 3 no quadro da entrada de syscall, a partir do
/// RSP do quadro com o retorno do `call opennt_user_syscall` (o RSP do
/// usuário fica de fora). Erro quando o quadro não é um: ilegível, RIP fora
/// do anel 3 ou RFLAGS impossível.
pub fn syscall_context(memory: &mut dyn ReadMemory, rsp: u64) -> Result<Context, String> {
    let frame = rsp.wrapping_add(SYSCALL_SAVE_AREA);
    let length = SYSCALL_FRAME.len() * 8;
    let bytes = memory.read(frame, length).map_err(|_| format!("quadro da syscall ilegivel em {frame:#x}"))?;
    if bytes.len() < length {
        return Err(format!("quadro da syscall ilegivel em {:#x}", frame.wrapping_add(bytes.len() as u64)));
    }
    let values: Vec<(&str, u64)> = SYSCALL_FRAME.iter().enumerate().map(|(index, name)| (*name, u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap()))).collect();
    let (rip, flags) = (named(&values, "rcx").unwrap_or(0), named(&values, "r11").unwrap_or(0));
    // RFLAGS tem o bit 1 sempre ligado e nada acima do bit 21.
    if rip == 0 || rip >= USER_LIMIT || flags & 2 == 0 || flags >> 22 != 0 {
        return Err(format!("quadro da syscall em {frame:#x} sem o anel 3 (rip {rip:#x}, rflags {flags:#x})"));
    }
    let kept: Vec<(&str, u64)> = values.into_iter().filter(|(name, _)| NONVOLATILE.contains(name)).collect();
    Ok(Context::from_named(rip, &kept))
}

/// Os registradores do código nativo que chamou um export, do CONTEXT que o
/// trampolim salvou abaixo do RBP do quadro dele; `None` quando o CONTEXT
/// não confere com o quadro (RSP = RBP + 16).
pub fn export_context(memory: &mut dyn ReadMemory, rbp: u64) -> Option<Context> {
    let bytes = memory.read(rbp.wrapping_sub(EXPORT_CONTEXT_BELOW_RBP), 0x100).ok()?;
    let registers = user::context_registers(&bytes);
    if named(&registers, "rsp")? != rbp.wrapping_add(16) {
        return None;
    }
    let rip = named(&registers, "rip")?;
    let kept: Vec<(&str, u64)> = registers.into_iter().filter(|(name, _)| NONVOLATILE.contains(name)).collect();
    Some(Context::from_named(rip, &kept))
}

/// O alvo do desenrolar de uma thread: a sessão, os pontos do kernel e o
/// que se sabe da thread para a parte de usuário.
struct StackTarget<'a> {
    client: &'a mut Client,
    labels: KernelLabels,
    /// A thread (ETHREAD) da pilha, quando conhecida.
    thread: Option<u64>,
    /// O processador parado em que ela roda.
    processor: Option<u64>,
    /// Atravessar a syscall para a pilha do anel 3.
    user: bool,
    /// O processo da thread (EPROCESS, PID), depois de achado.
    process: Option<(u64, u64)>,
    /// O processo das leituras antes da troca para a parte de usuário
    /// (`Some(None)`: o do processador).
    switched_from: Option<Option<u64>>,
}

impl ReadMemory for StackTarget<'_> {
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
        self.client.read_memory(address, length)
    }
}

impl Target for StackTarget<'_> {
    fn function_table(&mut self, address: u64) -> Option<Arc<FunctionTable>> {
        Target::function_table(&mut *self.client, address)
    }

    fn crossing(&mut self, context: &Context) -> Option<Crossing> {
        if context.rip < SYSTEM_HALF {
            return None;
        }
        let symbols = &self.client.symbols;
        if !symbols.module_at(context.rip).is_some_and(|module| symbols.is_kernel(module)) {
            return None;
        }
        let labels = self.labels;
        match site(&labels, &mut *self, context.rip)? {
            Site::ThreadStart => Some(Crossing::End("comeco da thread do kernel (opennt_kernel_thread_start)".into())),
            Site::ThreadReturn => Some(Crossing::End("comeco do contexto nativo (opennt_kernel_thread_return)".into())),
            Site::Export => export_context(&mut *self, context.rbp()?).map(|caller| Crossing::Enter(caller, Transition::NativeCall)),
            Site::Syscall => Some(self.enter_user(context)),
        }
    }
}

impl StackTarget<'_> {
    /// A passagem da entrada de syscall: os registradores do anel 3, o RSP
    /// do usuário e o processo da thread nas leituras.
    fn enter_user(&mut self, context: &Context) -> Crossing {
        let mut user = match syscall_context(&mut *self, context.rsp()) {
            Ok(user) => user,
            Err(reason) => return Crossing::End(reason),
        };
        if !self.user {
            return Crossing::End(format!("entrada de syscall (anel 3 em {:#x}; a pilha de usuario nao foi pedida)", user.rip));
        }
        if let Err(reason) = self.enter_process() {
            return Crossing::End(format!("entrada de syscall (anel 3 em {:#x}): {reason}", user.rip));
        }
        // Sem o RSP do usuário, o quadro do anel 3 ainda sai e o desenrolar
        // para nele (rsp desconhecido).
        if let Some(rsp) = self.user_rsp(user.rip) {
            user.set("rsp", rsp);
        }
        Crossing::Enter(user, Transition::Syscall)
    }

    /// A thread da pilha: a dada, ou a do processador parado.
    fn thread(&mut self) -> Option<u64> {
        if self.thread.is_none() {
            let processor = self.processor?;
            self.thread = self.client.processors().ok()?.into_iter().find(|entry| entry.number == processor).map(|entry| entry.thread).filter(|&thread| thread != 0);
        }
        self.thread
    }

    /// O processo da thread (EPROCESS e PID), pelas listas do alvo.
    fn thread_process(&mut self) -> Option<(u64, u64)> {
        if self.process.is_none() {
            let thread = self.thread()?;
            let pid = self.client.threads(None).ok()?.into_iter().find(|entry| entry.ethread == thread)?.pid;
            let eprocess = self.client.processes().ok()?.into_iter().find(|entry| entry.pid == pid)?.eprocess;
            self.process = Some((eprocess, pid));
        }
        self.process
    }

    /// O processo das leituras passa a ser o da thread (os módulos de
    /// usuário dele entram nos símbolos).
    fn enter_process(&mut self) -> Result<(), String> {
        let (eprocess, _) = self.thread_process().ok_or("processo da thread desconhecido")?;
        let current = self.client.process().map(|context| context.eprocess);
        if current != Some(eprocess) {
            self.client.set_process(Some(&format!("{eprocess:#x}")))?;
            if self.switched_from.is_none() {
                self.switched_from = Some(current);
            }
        } else if self.client.symbols.user_process != eprocess {
            self.client.reload_user_modules()?;
        }
        Ok(())
    }

    /// O RSP do anel 3 na syscall que entrou em `user_rip`: o do CONTEXT do
    /// intervalo da thread quando o RIP dele confere; senão o KPCR.UserRsp
    /// do processador em que ela roda.
    fn user_rsp(&mut self, user_rip: u64) -> Option<u64> {
        if let Some(rsp) = self.context_rsp(user_rip) {
            return Some(rsp);
        }
        let processor = self.processor?;
        let pcr = self.client.processors().ok()?.into_iter().find(|entry| entry.number == processor)?.pcr;
        self.client.read_integer(pcr.wrapping_add(KPCR_USER_RSP), 8).ok().filter(|&rsp| rsp != 0 && rsp < USER_LIMIT)
    }

    fn context_rsp(&mut self, user_rip: u64) -> Option<u64> {
        let thread = self.thread()?;
        let (eprocess, _) = self.thread_process()?;
        let entry = self.client.user_threads(&format!("{eprocess:#x}")).ok()?.into_iter().find(|entry| entry.ethread == thread)?;
        if entry.context == 0 {
            return None;
        }
        let bytes = self.client.read_memory(entry.context, 0x100).ok()?;
        let registers = user::context_registers(&bytes);
        if named(&registers, "rip")? != user_rip {
            return None;
        }
        named(&registers, "rsp").filter(|&rsp| rsp != 0 && rsp < USER_LIMIT)
    }
}

/// Por onde começa a pilha de uma thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Start {
    /// No RIP exato do processador ou da passagem.
    Exact,
    /// No retorno do quadro de troca (uma thread fora da CPU bloqueada num
    /// serviço).
    SwitchFrame,
    /// No anel 3, pelo CONTEXT do intervalo (uma thread fora da CPU sem
    /// serviço suspenso): as leituras passam ao processo dela antes.
    UserContext,
}

/// Uma thread fora da CPU, pelo `monitor context`: o RIP no anel 3 vem do
/// CONTEXT do intervalo (nenhum quadro de troca na pilha de kernel); senão,
/// do retorno do quadro de troca.
fn thread_start(context: &ThreadContext, rip: u64) -> Start {
    if context.processor.is_some() {
        Start::Exact
    } else if rip != 0 && rip < USER_LIMIT {
        Start::UserContext
    } else {
        Start::SwitchFrame
    }
}

/// A faixa da pilha de usuário que o `monitor context` dá de uma thread no
/// anel 3 (NT_TIB.StackLimit e StackBase da TEB dela).
pub fn user_stack_range(header: &str) -> Option<(u64, u64)> {
    let range = header.split_once("pilha de usuario ")?.1.split_whitespace().next()?;
    let (limit, base) = range.split_once('-')?;
    let (limit, base) = (super::parse_number(limit)?, super::parse_number(base)?);
    (limit != 0 && limit < base).then_some((limit, base))
}

impl Client {
    /// Desenrola com as passagens do OpenNT. `thread`/`processor`: a thread
    /// da pilha (para a parte de usuário); `user`: atravessar a syscall.
    fn walk_thread(&mut self, context: Context, start: Start, limit: usize, user: bool, thread: Option<u64>, processor: Option<u64>) -> Walk {
        let labels = KernelLabels::from_symbols(&self.symbols);
        let mut target = StackTarget { client: &mut *self, labels, thread, processor, user, process: None, switched_from: None };
        let walk = match start {
            Start::UserContext => match target.enter_process() {
                Ok(()) => unwind::walk_stack(&mut target, context, false, limit),
                Err(reason) => Walk { frames: Vec::new(), stop: unwind::Stop::End(format!("anel 3 em {:#x}: {reason}", context.rip)) },
            },
            _ => unwind::walk_stack(&mut target, context, start == Start::SwitchFrame, limit),
        };
        let switched_from = target.switched_from;
        // Sem processo escolhido antes, as leituras voltam ao processador;
        // os módulos de usuário da thread ficam nos símbolos (os nomes dos
        // quadros).
        if switched_from == Some(None) {
            let _ = self.set_process(None);
        }
        walk
    }

    /// A pilha do processador escolhido, com o motivo do fim: `.pdata` nos
    /// binários da Microsoft, frame pointers no código do OpenNT e as
    /// passagens dos trampolins. `user`: seguir pela pilha do anel 3 depois
    /// da entrada de syscall.
    pub fn stack(&mut self, limit: usize, user: bool) -> Result<Walk, String> {
        let values = self.general_registers()?;
        let rip = self.register("rip")?;
        let named: Vec<(&str, u64)> = values.iter().filter_map(|value| value.value.map(|number| (value.layout.name, number))).collect();
        let context = Context::from_named(rip, &named);
        let processor = self.selected_thread().map(|thread| thread.saturating_sub(1)).or_else(|| self.stop_reply().and_then(|stop| stop.processor()));
        Ok(self.walk_thread(context, Start::Exact, limit, user, None, processor))
    }

    /// A pilha de uma thread pelo `monitor context`, com o motivo do fim. A
    /// de uma thread fora da CPU começa no quadro de troca (o RIP já é um
    /// retorno) ou, sem serviço suspenso (uma espera adiada, o fim do
    /// intervalo), no CONTEXT do anel 3 dela, lido no processo dela.
    pub fn thread_stack(&mut self, thread: u64, limit: usize, user: bool) -> Result<(ThreadContext, Walk), String> {
        let mut context = self.thread_context(thread)?;
        let Some(rip) = context.register("rip") else { return Err(format!("contexto de {thread:#x}: {}", context.header)) };
        let named: Vec<(&str, u64)> = context.registers.iter().map(|(name, value)| (name.as_str(), *value)).collect();
        let registers = Context::from_named(rip, &named);
        let start = thread_start(&context, rip);
        // A pilha de usuário da TEB: um RSP do CONTEXT fora dela fica dito.
        if start == Start::UserContext {
            let rsp = context.register("rsp").unwrap_or(0);
            if let Some((low, high)) = user_stack_range(&context.header).filter(|(low, high)| !(*low..*high).contains(&rsp)) {
                context.header.push_str(&format!("\naviso: o rsp {rsp:#x} do CONTEXT esta fora da pilha da TEB ({low:#x}-{high:#x})"));
            }
        }
        if start == Start::UserContext && !user {
            let walk = Walk { frames: Vec::new(), stop: unwind::Stop::End(format!("a thread esta no anel 3 em {rip:#x}, sem servico suspenso (a pilha de usuario nao foi pedida)")) };
            return Ok((context, walk));
        }
        let walk = self.walk_thread(registers, start, limit, user, Some(thread), context.processor);
        Ok((context, walk))
    }

    /// A pilha de usuário de uma thread pelo CONTEXT salvo dela, nos módulos
    /// do processo escolhido, com o motivo do fim.
    pub fn user_thread_stack(&mut self, thread: &UserThread, limit: usize) -> Result<(Vec<(String, u64)>, Walk), String> {
        let registers = self.user_thread_registers(thread)?;
        let rip = registers.iter().find(|(name, _)| name == "rip").map(|(_, value)| *value).unwrap_or(0);
        let named: Vec<(&str, u64)> = registers.iter().map(|(name, value)| (name.as_str(), *value)).collect();
        let start = Context::from_named(rip, &named);
        let walk = self.walk_thread(start, Start::Exact, limit, false, Some(thread.ethread), None);
        Ok((registers, walk))
    }

    /// A pilha em texto: os quadros (`#n endereço símbolo`, ou a tabela do
    /// `k` com o RSP e o retorno de cada quadro), as passagens entre eles e
    /// onde o desenrolar parou.
    pub fn format_walk(&self, walk: &Walk, with_stack: bool) -> String {
        let mut output = if with_stack { self.format_frames_with_stack(&walk.frames) } else { self.format_frames(&walk.frames) };
        output.push_str(&format!("-- {}\n", walk.stop.text()));
        output
    }

    /// A linha que avisa que o processo das leituras mudou desde `before`
    /// (vazia quando não mudou).
    pub fn process_change_note(&self, before: Option<u64>) -> String {
        match self.process() {
            Some(context) if Some(context.eprocess) != before => format!("processo das leituras: {} (PID {}, EPROCESS {:#x})\n", context.name, context.pid, context.eprocess),
            _ => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unwind::Captured;

    fn labels() -> KernelLabels {
        KernelLabels {
            syscall_entry: Some(0xfffff800_4020_0000),
            syscall_service: Some(0xfffff800_4010_0000),
            export_common: Some(0xfffff800_4020_00c0),
            export_dispatch: Some(0xfffff800_4011_0000),
            thread_start: Some(0xfffff800_4012_0000),
            thread_return: Some(0xfffff800_4013_0000),
        }
    }

    /// Um `call rel32` em `at` para `routine` (o retorno em `at + 5`).
    fn call_to(at: u64, routine: u64) -> (u64, Vec<u8>) {
        let mut bytes = vec![0xE8];
        bytes.extend_from_slice(&((routine.wrapping_sub(at + 5)) as i32).to_le_bytes());
        bytes.push(0x90);
        (at, bytes)
    }

    #[test]
    fn finds_the_crossings_by_the_call() {
        let labels = labels();
        let syscall_call = 0xfffff800_4020_0040u64;
        let export_call = 0xfffff800_4020_0100u64;
        let mut memory = Captured { regions: vec![call_to(syscall_call, 0xfffff800_4010_0000), call_to(export_call, 0xfffff800_4011_0000)] };
        assert_eq!(site(&labels, &mut memory, syscall_call + 5), Some(Site::Syscall));
        assert_eq!(site(&labels, &mut memory, export_call + 5), Some(Site::Export));
        // Outro retorno no mesmo código (sem o `call` certo antes dele).
        assert_eq!(site(&labels, &mut memory, syscall_call + 6), None);
        assert_eq!(site(&labels, &mut memory, 0xfffff800_4012_0006), Some(Site::ThreadStart));
        assert_eq!(site(&labels, &mut memory, 0xfffff800_4012_0000), None);
        assert_eq!(site(&labels, &mut memory, 0xfffff800_4013_0000), Some(Site::ThreadReturn));
        assert_eq!(site(&KernelLabels::default(), &mut memory, syscall_call + 5), None);
    }

    fn syscall_frame(rip: u64, flags: u64) -> Vec<u8> {
        // RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11, RBX, RBP, R12-R15.
        let values = [0x1234, rip, 3, 0x5151, 0xd1d1, 5, 6, 7, flags, 0xb0b0, 0x3_0000_0040, 0xc12, 0xc13, 0xc14, 0xc15];
        values.iter().flat_map(|value: &u64| value.to_le_bytes()).collect()
    }

    #[test]
    fn reads_the_user_registers_of_a_syscall() {
        let rsp = 0xffff_a007_0000_0000u64;
        let mut memory = Captured { regions: vec![(rsp + SYSCALL_SAVE_AREA, syscall_frame(0x7ffe_1234_0014, 0x246))] };
        let user = syscall_context(&mut memory, rsp).unwrap();
        assert_eq!(user.rip, 0x7ffe_1234_0014);
        assert_eq!((user.register("rbx"), user.register("rbp"), user.register("rsi"), user.register("rdi")), (Some(0xb0b0), Some(0x3_0000_0040), Some(0x5151), Some(0xd1d1)));
        assert_eq!((user.register("r12"), user.register("r15")), (Some(0xc12), Some(0xc15)));
        // Os voláteis e o RSP do usuário não vêm do quadro.
        assert_eq!((user.register("rax"), user.register("rcx"), user.register("r11"), user.register("rsp")), (None, None, None, None));
        // Um RIP de kernel ou um RFLAGS sem o bit 1 não são de uma syscall.
        let mut memory = Captured { regions: vec![(rsp + SYSCALL_SAVE_AREA, syscall_frame(0xfffff800_4000_0000, 0x246))] };
        assert!(syscall_context(&mut memory, rsp).is_err());
        let mut memory = Captured { regions: vec![(rsp + SYSCALL_SAVE_AREA, syscall_frame(0x7ffe_1234_0014, 0x200))] };
        assert!(syscall_context(&mut memory, rsp).is_err());
        assert!(syscall_context(&mut Captured { regions: Vec::new() }, rsp).unwrap_err().contains("ilegivel"));
    }

    #[test]
    fn a_thread_off_the_cpu_starts_in_its_user_context_without_a_switch_frame() {
        // A resposta do `monitor context` de uma thread de usuário numa
        // espera adiada (sem quadro de troca), como as do dwm no b2-idle.
        let text = "ETHREAD 0xffffc000c01513b0 estado Waiting no anel 3, sem servico suspenso: CONTEXT 0xffffa00701a3f000 TEB 0x3a5000 pilha de usuario 0x2c9c000-0x2ca0000\nrip=0x7ffd0009d6e4 rsp=0x2c9fc48 rbp=0x0 rbx=0x5 rsi=0x0 rdi=0x0 r12=0x0 r13=0x0 r14=0x0 r15=0x0 rflags=0x246\n";
        let context = crate::monitor::thread_context(text).unwrap();
        assert_eq!(context.processor, None);
        assert_eq!((context.register("rip"), context.register("rsp"), context.register("rbx")), (Some(0x7ffd_0009_d6e4), Some(0x2c9_fc48), Some(5)));
        assert_eq!(thread_start(&context, 0x7ffd_0009_d6e4), Start::UserContext);
        assert_eq!(user_stack_range(&context.header), Some((0x2c9_c000, 0x2ca_0000)));
        // O quadro de troca de uma thread bloqueada num serviço.
        let text = "ETHREAD 0xffffc000c012f2c0 estado Waiting quadro de troca em 0xffffa0070173dd30\nrip=0xfffff800408cf349 rsp=0xffffa0070173de30 rflags=0x2 rbp=0xffffa0070173de80\n";
        let context = crate::monitor::thread_context(text).unwrap();
        assert_eq!(thread_start(&context, 0xffff_f800_408c_f349), Start::SwitchFrame);
        assert_eq!(user_stack_range(&context.header), None);
        // Uma thread num processador parado: os registradores do protocolo.
        let text = "ETHREAD 0xffffc000c012f2c0 roda na CPU 1: registradores da thread 2 do protocolo\nrip=0x7ffd0009d6e4 rsp=0x1000 rbp=0x0\n";
        let context = crate::monitor::thread_context(text).unwrap();
        assert_eq!(thread_start(&context, 0x7ffd_0009_d6e4), Start::Exact);
        // Faixa vazia ou invertida (TEB ilegível) não vale.
        assert_eq!(user_stack_range("x pilha de usuario 0x0-0x0"), None);
        assert_eq!(user_stack_range("x pilha de usuario 0x2000-0x1000"), None);
    }

    #[test]
    fn reads_the_native_caller_from_the_trampoline() {
        let rbp = 0xffff_a007_0000_1000u64;
        let mut context = vec![0u8; 0x100];
        let mut put = |offset: usize, value: u64| context[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        put(0x78, 0x1111); // rax
        put(0x90, 0xb0b0); // rbx
        put(0x98, rbp + 16); // rsp
        put(0xA0, 0xffff_a007_0000_2000); // rbp
        put(0xD8, 0xc12); // r12
        put(0xF8, 0xfffff960_0000_9008); // rip: o retorno no código nativo
        let mut memory = Captured { regions: vec![(rbp - EXPORT_CONTEXT_BELOW_RBP, context.clone())] };
        let caller = export_context(&mut memory, rbp).unwrap();
        assert_eq!(caller.rip, 0xfffff960_0000_9008);
        assert_eq!((caller.rsp(), caller.rbp(), caller.register("rbx"), caller.register("r12"), caller.register("rax")), (rbp + 16, Some(0xffff_a007_0000_2000), Some(0xb0b0), Some(0xc12), None));
        // Um CONTEXT que não é o deste quadro (outro RSP) não vale.
        context[0x98..0xA0].copy_from_slice(&(rbp + 0x40).to_le_bytes());
        let mut memory = Captured { regions: vec![(rbp - EXPORT_CONTEXT_BELOW_RBP, context)] };
        assert_eq!(export_context(&mut memory, rbp), None);
    }
}
