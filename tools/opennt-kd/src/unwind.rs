//! A pilha de um processador parado ou de uma thread, com dois métodos:
//!
//! - binários da Microsoft (sem frame pointer): o desenrolar virtual do x64
//!   como o RtlVirtualUnwind do 19041, pela tabela de funções do PE
//!   (`.pdata`, RUNTIME_FUNCTION, com as entradas indiretas) e pelos códigos
//!   do UNWIND_INFO de cada função: push, alocação, registrador de quadro,
//!   registradores salvos por MOV (relativos ao establisher frame), quadro
//!   de máquina e informação encadeada. No quadro de cima, os códigos do
//!   prólogo ainda não executados ficam de fora e o epílogo é reconhecido
//!   pelas instruções (`add rsp`/`lea rsp`, `pop`s e `ret` ou um `jmp` de
//!   chamada em cauda);
//! - o código do OpenNT (compilado com `force-frame-pointers`, sem
//!   `.pdata`): cada quadro guarda o RBP do chamador em [RBP] e o endereço
//!   de retorno em [RBP + 8]; no prólogo (`push rbp` ou `mov rbp, rsp` por
//!   executar) e no `ret`, o retorno está no topo da pilha.
//!
//! Os dois se misturam numa pilha: o contexto (RIP, RSP e os registradores
//! conhecidos) passa de um quadro ao outro, então um driver chamado pelo
//! kernel e o kernel chamado pelo driver desenrolam um sobre o outro. Um
//! registrador que o chamador não vê igual fica desconhecido: os voláteis
//! depois de qualquer quadro e os salvos do código sem `.pdata` (o quadro de
//! RBP não diz onde estão).
//!
//! As passagens que não seguem essas regras vêm do alvo
//! ([`Target::crossing`]): os trampolins do kernel do OpenNT que trocam de
//! pilha ou de modo e o começo de uma pilha (`stack.rs`). O desenrolar diz
//! onde parou e por quê ([`Stop`]).
//!
//! O desenrolar só lê memória por `ReadMemory`: o alvo pela sessão, ou uma
//! pilha capturada nos testes.

use std::sync::Arc;

use super::pe::{find_function, PeImage, RuntimeFunction};
use super::x86;

/// Leitor de memória do alvo.
pub trait ReadMemory {
    /// Lê até `length` bytes (menos quando a leitura para numa página
    /// inacessível); erro se nem o primeiro byte pôde ser lido.
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String>;

    fn read_u64(&mut self, address: u64) -> Option<u64> {
        let bytes = self.read(address, 8).ok()?;
        Some(u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?))
    }
}

/// A tabela de funções de uma imagem carregada.
pub struct FunctionTable {
    pub base: u64,
    pub functions: Vec<RuntimeFunction>,
    /// O arquivo desta máquina (os UNWIND_INFO saem dele); sem ele, da
    /// memória do alvo.
    pub image: Option<Arc<PeImage>>,
}

/// O alvo do desenrolar: memória, a tabela de funções do código num
/// endereço (`None` = código sem `.pdata`, desenrolado pelo RBP) e as
/// passagens que só ele conhece.
pub trait Target: ReadMemory {
    fn function_table(&mut self, address: u64) -> Option<Arc<FunctionTable>>;

    /// Uma passagem no quadro de `context`, cujo RIP é um endereço de
    /// retorno ainda não desenrolado: um trampolim que troca de modo ou de
    /// pilha (o contexto do outro lado) ou o começo da pilha. `None`: as
    /// regras comuns valem.
    fn crossing(&mut self, _context: &Context) -> Option<Crossing> {
        None
    }
}

/// Só memória: todo o código desenrola pelos frame pointers.
pub struct FramePointers<'a>(pub &'a mut dyn ReadMemory);

impl ReadMemory for FramePointers<'_> {
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
        self.0.read(address, length)
    }
}

impl Target for FramePointers<'_> {
    fn function_table(&mut self, _address: u64) -> Option<Arc<FunctionTable>> {
        None
    }
}

/// Como o quadro foi achado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// Os registradores do processador ou da thread (ou os salvos numa
    /// passagem).
    Context,
    /// `.pdata`/UNWIND_INFO do quadro de baixo.
    Table,
    /// Função folha de uma imagem com `.pdata` (retorno em [RSP]).
    Leaf,
    /// Epílogo emulado no quadro de baixo.
    Epilog,
    /// Cadeia de RBP (ou prólogo) do quadro de baixo.
    FramePointer,
}

/// Uma passagem entre dois quadros que troca de pilha, de modo ou de
/// convenção.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition {
    /// UWOP_PUSH_MACHFRAME: o quadro que a CPU empilhou numa interrupção ou
    /// exceção; o RIP do quadro alcançado é o da instrução interrompida.
    MachineFrame,
    /// A entrada de syscall do OpenNT, o papel do KTRAP_FRAME: do kernel
    /// para o anel 3, no RIP depois do `syscall`.
    Syscall,
    /// O trampolim dos exports do kernel: do código do OpenNT para o código
    /// nativo que chamou o export, pelos registradores que o trampolim
    /// salvou.
    NativeCall,
}

impl Transition {
    /// O RIP do outro lado é o de uma instrução interrompida, não um
    /// endereço de retorno.
    pub fn exact(self) -> bool {
        matches!(self, Self::MachineFrame | Self::Syscall)
    }

    pub fn text(self) -> &'static str {
        match self {
            Self::MachineFrame => "quadro de maquina (interrupcao ou excecao)",
            Self::Syscall => "syscall: pilha do anel 3",
            Self::NativeCall => "chamada nativa ao kernel (registradores do trampolim)",
        }
    }
}

/// Um quadro da pilha.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    pub address: u64,
    /// O endereço é de retorno (a instrução depois de um `call`): o símbolo
    /// certo é o do byte anterior.
    pub is_return: bool,
    /// O RSP do quadro (o do chamador logo depois do retorno).
    pub stack: u64,
    pub method: Method,
    /// O quadro foi alcançado por uma passagem.
    pub transition: Option<Transition>,
}

/// O que o alvo diz de um quadro ([`Target::crossing`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Crossing {
    /// O contexto do outro lado da passagem.
    Enter(Context, Transition),
    /// A pilha acaba neste quadro (o texto diz por quê).
    End(String),
}

/// Por que o desenrolar parou.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stop {
    /// O limite de quadros pedido.
    Limit,
    /// O fim da pilha: o começo de uma thread ou de um contexto.
    End(String),
    /// Memória que não pôde ser lida (a pilha, a tabela, o UNWIND_INFO).
    Unreadable(u64),
    /// Um endereço de retorno que não é código (abaixo de 0x1000 ou não
    /// canônico).
    BadReturn(u64),
    /// Um quadro do kernel voltaria para o anel 3 sem passagem.
    KernelToUser(u64),
    /// Um quadro do anel 3 voltaria para o kernel.
    UserToKernel(u64),
    /// O RSP do chamador não passou do quadro (a pilha não subiu).
    NoProgress(u64),
    /// UNWIND_INFO com versão ou códigos inválidos.
    BadUnwindInfo(u64),
    /// Um registrador necessário e desconhecido neste quadro: o de quadro
    /// do SET_FPREG, o RSP de uma passagem.
    UnknownRegister(&'static str),
    /// A cadeia de RBP do código sem `.pdata` não continua.
    FramePointer(u64),
    /// Passagens demais (um laço).
    Crossings,
}

impl Stop {
    pub fn text(&self) -> String {
        match self {
            Stop::Limit => "parou no limite de quadros pedido".into(),
            Stop::End(reason) => format!("fim da pilha: {reason}"),
            Stop::Unreadable(address) => format!("parou: memoria ilegivel em {address:#x}"),
            Stop::BadReturn(address) => format!("parou: retorno {address:#x} fora de codigo"),
            Stop::KernelToUser(address) => format!("parou: o kernel voltaria para o anel 3 ({address:#x}) sem quadro de syscall"),
            Stop::UserToKernel(address) => format!("parou: o anel 3 voltaria para o kernel ({address:#x})"),
            Stop::NoProgress(rsp) => format!("parou: a pilha nao subiu (rsp {rsp:#x})"),
            Stop::BadUnwindInfo(address) => format!("parou: UNWIND_INFO invalido em {address:#x}"),
            Stop::UnknownRegister(name) => format!("parou: {name} desconhecido neste quadro"),
            Stop::FramePointer(rbp) => format!("parou: cadeia de rbp interrompida (rbp {rbp:#x})"),
            Stop::Crossings => "parou: passagens demais (laco)".into(),
        }
    }
}

/// A pilha desenrolada e onde ela parou.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Walk {
    pub frames: Vec<Frame>,
    pub stop: Stop,
}

/// Os registradores na numeração do UNWIND_CODE: 0 RAX, 1 RCX, 2 RDX,
/// 3 RBX, 4 RSP, 5 RBP, 6 RSI, 7 RDI, 8-15 R8-R15.
pub const REGISTER_NAMES: [&str; 16] = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
const RSP: usize = 4;
const RBP: usize = 5;
/// RAX, RCX, RDX e R8-R11: voláteis na convenção do x64.
const VOLATILE: [usize; 7] = [0, 1, 2, 8, 9, 10, 11];
/// Entradas encadeadas e indiretas seguidas num quadro.
const MAX_CHAIN: usize = 32;
/// Passagens numa pilha (mais que isso é um laço).
const MAX_CROSSINGS: usize = 16;
/// O fim da metade de usuário e o começo da de sistema.
const USER_LIMIT: u64 = 0x0000_8000_0000_0000;
const SYSTEM_HALF: u64 = 0xFFFF_8000_0000_0000;

/// O contexto que passa de quadro em quadro.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Context {
    pub rip: u64,
    pub registers: [Option<u64>; 16],
}

impl Context {
    /// RIP, RSP e RBP (o resto desconhecido).
    pub fn new(rip: u64, rsp: u64, rbp: u64) -> Self {
        let mut context = Context { rip, registers: [None; 16] };
        context.registers[RSP] = Some(rsp);
        context.registers[RBP] = Some(rbp);
        context
    }

    /// A partir de pares nome/valor (o pacote `g` ou o `monitor context`).
    pub fn from_named(rip: u64, values: &[(&str, u64)]) -> Self {
        let mut context = Context { rip, registers: [None; 16] };
        for (name, value) in values {
            context.set(name, *value);
        }
        context
    }

    /// Grava um registrador pelo nome (nomes fora de [`REGISTER_NAMES`]
    /// ficam de fora).
    pub fn set(&mut self, name: &str, value: u64) {
        if let Some(index) = REGISTER_NAMES.iter().position(|register| *register == name) {
            self.registers[index] = Some(value);
        }
    }

    /// Um registrador pelo nome, se conhecido.
    pub fn register(&self, name: &str) -> Option<u64> {
        REGISTER_NAMES.iter().position(|register| *register == name).and_then(|index| self.registers[index])
    }

    pub fn rsp(&self) -> u64 {
        self.registers[RSP].unwrap_or(0)
    }

    pub fn rbp(&self) -> Option<u64> {
        self.registers[RBP]
    }

    /// Os voláteis não sobrevivem a uma chamada: desconhecidos no chamador.
    fn forget_volatile(&mut self) {
        for index in VOLATILE {
            self.registers[index] = None;
        }
    }

    /// Depois de um quadro de RBP, só RSP e RBP são conhecidos (os salvos
    /// do código sem `.pdata` ficam em lugares que o quadro não diz).
    fn keep_frame_registers(&mut self) {
        for (index, register) in self.registers.iter_mut().enumerate() {
            if index != RSP && index != RBP {
                *register = None;
            }
        }
    }
}

/// Onde está o endereço de retorno da função em que o RIP está: no prólogo
/// e no `ret`, no topo da pilha; com o quadro montado, em RBP + 8.
pub fn return_slot(memory: &mut dyn ReadMemory, rip: u64, rsp: u64, rbp: u64) -> u64 {
    let code = memory.read(rip, 3).unwrap_or_default();
    x86::prologue_return_slot(&code, rsp).unwrap_or(rbp.wrapping_add(8))
}

/// A pilha pelos frame pointers a partir dos registradores (sem `.pdata`).
pub fn unwind(memory: &mut dyn ReadMemory, rip: u64, rsp: u64, rbp: u64, limit: usize) -> Vec<Frame> {
    walk(&mut FramePointers(memory), Context::new(rip, rsp, rbp), false, limit)
}

/// Os quadros a partir de um contexto ([`walk_stack`] sem o motivo do fim).
pub fn walk(target: &mut dyn Target, context: Context, top_is_return: bool, limit: usize) -> Vec<Frame> {
    walk_stack(target, context, top_is_return, limit).frames
}

/// A pilha a partir de um contexto, até `limit` quadros, e onde ela parou.
/// `top_is_return`: o RIP já é um endereço de retorno (o quadro de troca de
/// uma thread fora da CPU).
pub fn walk_stack(target: &mut dyn Target, mut context: Context, top_is_return: bool, limit: usize) -> Walk {
    let mut frames = vec![Frame { address: context.rip, is_return: top_is_return, stack: context.rsp(), method: Method::Context, transition: None }];
    // O RIP do quadro corrente é exato (o de cima, ou o do outro lado de uma
    // passagem exata) ou um endereço de retorno.
    let mut exact = !top_is_return;
    let mut crossings = 0;
    let stop = loop {
        if frames.len() >= limit {
            break Stop::Limit;
        }
        let before = context.clone();
        let crossing = if exact { None } else { target.crossing(&context) };
        let stepped = match crossing {
            Some(Crossing::End(reason)) => break Stop::End(reason),
            Some(Crossing::Enter(next, transition)) => {
                crossings += 1;
                if crossings > MAX_CROSSINGS {
                    break Stop::Crossings;
                }
                context = next;
                Stepped { method: Method::Context, transition: Some(transition) }
            }
            None => match step(target, &mut context, exact) {
                Ok(stepped) => stepped,
                Err(stop) => break stop,
            },
        };
        if let Err(stop) = check(&before, &context, stepped.transition) {
            break stop;
        }
        let exact_next = stepped.transition.is_some_and(Transition::exact);
        frames.push(Frame { address: context.rip, is_return: !exact_next, stack: context.rsp(), method: stepped.method, transition: stepped.transition });
        if context.registers[RSP].is_none() {
            break Stop::UnknownRegister("rsp");
        }
        exact = exact_next;
    };
    Walk { frames, stop }
}

/// O quadro novo faz sentido: código, a pilha subindo e nenhum retorno
/// entre o kernel e o anel 3 fora de uma passagem.
fn check(before: &Context, after: &Context, transition: Option<Transition>) -> Result<(), Stop> {
    let rip = after.rip;
    if rip == 0 {
        return Err(Stop::End("retorno zero (o comeco da thread)".into()));
    }
    if rip < 0x1000 || (USER_LIMIT..SYSTEM_HALF).contains(&rip) {
        return Err(Stop::BadReturn(rip));
    }
    if transition.is_none() {
        if before.rip >= SYSTEM_HALF && rip < USER_LIMIT {
            return Err(Stop::KernelToUser(rip));
        }
        if before.rip < USER_LIMIT && rip >= SYSTEM_HALF {
            return Err(Stop::UserToKernel(rip));
        }
        if after.registers[RSP].is_some() && after.rsp() <= before.rsp() {
            return Err(Stop::NoProgress(after.rsp()));
        }
    }
    Ok(())
}

/// Um quadro desfeito: como, e a passagem (o quadro de máquina) se houve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stepped {
    method: Method,
    transition: Option<Transition>,
}

/// Um quadro: o contexto vira o do chamador. `top`: o RIP é exato.
fn step(target: &mut dyn Target, context: &mut Context, top: bool) -> Result<Stepped, Stop> {
    // O símbolo (e a função) de um endereço de retorno é o do `call`.
    let lookup = if top { context.rip } else { context.rip.wrapping_sub(1) };
    let Some(table) = target.function_table(lookup) else {
        frame_pointer_step(target, context, top)?;
        return Ok(Stepped { method: Method::FramePointer, transition: None });
    };
    let rva = lookup.checked_sub(table.base).and_then(|offset| u32::try_from(offset).ok()).ok_or(Stop::BadReturn(context.rip))?;
    let Some(entry) = find_function(&table.functions, rva) else {
        // Função folha: nada na pilha além do retorno.
        pop_return(target, context)?;
        context.forget_volatile();
        return Ok(Stepped { method: Method::Leaf, transition: None });
    };
    let function = resolve_indirect(target, &table, entry)?;
    if top && unwind_epilog(target, &table, function, context) {
        return Ok(Stepped { method: Method::Epilog, transition: None });
    }
    let offset = top.then(|| context.rip.wrapping_sub(table.base.wrapping_add(function.begin as u64)) as u32);
    let machine = virtual_unwind(target, &table, function, offset, context)?;
    Ok(Stepped { method: Method::Table, transition: machine.then_some(Transition::MachineFrame) })
}

/// Um quadro do código sem `.pdata`: no prólogo e no `ret` do quadro de
/// cima, o retorno no topo da pilha; senão a cadeia de RBP.
fn frame_pointer_step(target: &mut dyn Target, context: &mut Context, top: bool) -> Result<(), Stop> {
    let rsp = context.registers[RSP].ok_or(Stop::UnknownRegister("rsp"))?;
    if top {
        let code = target.read(context.rip, 3).unwrap_or_default();
        if let Some(slot) = x86::prologue_return_slot(&code, rsp) {
            // O prólogo ainda não salvou nada: os registradores são os do
            // chamador, fora os voláteis.
            context.rip = read_u64(target, slot)?;
            context.registers[RSP] = Some(slot.wrapping_add(8));
            context.forget_volatile();
            return Ok(());
        }
    }
    let rbp = context.rbp().ok_or(Stop::UnknownRegister("rbp"))?;
    if rbp == 0 {
        return Err(Stop::End("rbp zero (o fim da cadeia de quadros)".into()));
    }
    if rbp & 7 != 0 || rbp.wrapping_add(16) <= rsp {
        return Err(Stop::FramePointer(rbp));
    }
    let frame = target.read(rbp, 16).map_err(|_| Stop::Unreadable(rbp))?;
    if frame.len() < 16 {
        return Err(Stop::Unreadable(rbp.wrapping_add(frame.len() as u64)));
    }
    context.registers[RBP] = Some(u64::from_le_bytes(frame[..8].try_into().unwrap()));
    context.rip = u64::from_le_bytes(frame[8..16].try_into().unwrap());
    context.registers[RSP] = Some(rbp.wrapping_add(16));
    context.keep_frame_registers();
    Ok(())
}

fn read_u64(target: &mut dyn Target, address: u64) -> Result<u64, Stop> {
    target.read_u64(address).ok_or(Stop::Unreadable(address))
}

/// O retorno no topo da pilha.
fn pop_return(target: &mut dyn Target, context: &mut Context) -> Result<(), Stop> {
    let rsp = context.registers[RSP].ok_or(Stop::UnknownRegister("rsp"))?;
    context.rip = read_u64(target, rsp)?;
    context.registers[RSP] = Some(rsp.wrapping_add(8));
    Ok(())
}

/// Os códigos de um UNWIND_INFO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwindInfo {
    pub version: u8,
    pub flags: u8,
    pub prolog_size: u8,
    pub frame_register: u8,
    pub frame_offset: u8,
    pub codes: Vec<u16>,
    /// UNW_FLAG_CHAININFO: a função principal desta parte.
    pub chained: Option<RuntimeFunction>,
}

pub const UNW_FLAG_CHAININFO: u8 = 4;

pub const UWOP_PUSH_NONVOL: u8 = 0;
pub const UWOP_ALLOC_LARGE: u8 = 1;
pub const UWOP_ALLOC_SMALL: u8 = 2;
pub const UWOP_SET_FPREG: u8 = 3;
pub const UWOP_SAVE_NONVOL: u8 = 4;
pub const UWOP_SAVE_NONVOL_FAR: u8 = 5;
pub const UWOP_EPILOG: u8 = 6;
pub const UWOP_SPARE_CODE: u8 = 7;
pub const UWOP_SAVE_XMM128: u8 = 8;
pub const UWOP_SAVE_XMM128_FAR: u8 = 9;
pub const UWOP_PUSH_MACHFRAME: u8 = 10;

impl UnwindInfo {
    /// O cabeçalho, os códigos e o RUNTIME_FUNCTION encadeado.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let header = bytes.get(..4)?;
        let count = header[2] as usize;
        let codes: Vec<u16> = (0..count).map(|index| bytes.get(4 + 2 * index..6 + 2 * index).map(|pair| u16::from_le_bytes([pair[0], pair[1]]))).collect::<Option<_>>()?;
        let flags = header[0] >> 3;
        let chained = if flags & UNW_FLAG_CHAININFO != 0 {
            let at = 4 + 2 * ((count + 1) & !1);
            let entry = bytes.get(at..at + 12)?;
            Some(RuntimeFunction { begin: u32::from_le_bytes(entry[0..4].try_into().ok()?), end: u32::from_le_bytes(entry[4..8].try_into().ok()?), unwind: u32::from_le_bytes(entry[8..12].try_into().ok()?) })
        } else {
            None
        };
        Some(Self { version: header[0] & 7, flags, prolog_size: header[1], frame_register: header[3] & 0xF, frame_offset: header[3] >> 4, codes, chained })
    }

    /// Quantos bytes ler para ter o UNWIND_INFO inteiro com a entrada
    /// encadeada (sem o tratador).
    pub fn size(count: usize) -> usize {
        4 + 2 * ((count + 1) & !1) + 12
    }
}

/// Quantos slots ocupa um código (o RtlpUnwindOpSlotTable do 19041);
/// `None` para um código inválido.
fn slots(code: u16) -> Option<usize> {
    let (op, info) = (((code >> 8) & 0xF) as u8, (code >> 12) as u8);
    Some(match op {
        UWOP_PUSH_NONVOL | UWOP_ALLOC_SMALL | UWOP_SET_FPREG | UWOP_PUSH_MACHFRAME => 1,
        UWOP_ALLOC_LARGE if info == 0 => 2,
        UWOP_ALLOC_LARGE if info == 1 => 3,
        UWOP_SAVE_NONVOL | UWOP_EPILOG | UWOP_SAVE_XMM128 => 2,
        UWOP_SAVE_NONVOL_FAR | UWOP_SPARE_CODE | UWOP_SAVE_XMM128_FAR => 3,
        _ => return None,
    })
}

/// Um código decodificado: onde termina a instrução no prólogo, a operação,
/// o OpInfo e os slots seguintes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Code {
    offset: u32,
    op: u8,
    info: usize,
    first: u64,
    second: u64,
}

impl Code {
    /// Os bytes que a instrução do código tirou do RSP (push e alocações).
    fn stack_bytes(&self) -> u64 {
        match self.op {
            UWOP_PUSH_NONVOL => 8,
            UWOP_ALLOC_SMALL => self.info as u64 * 8 + 8,
            UWOP_ALLOC_LARGE if self.info == 0 => self.first * 8,
            UWOP_ALLOC_LARGE => self.first | self.second << 16,
            _ => 0,
        }
    }
}

fn decode(info: &UnwindInfo, address: u64) -> Result<Vec<Code>, Stop> {
    let mut codes = Vec::with_capacity(info.codes.len());
    let mut index = 0;
    while index < info.codes.len() {
        let code = info.codes[index];
        let size = slots(code).ok_or(Stop::BadUnwindInfo(address))?;
        if index + size > info.codes.len() {
            return Err(Stop::BadUnwindInfo(address));
        }
        let word = |position: usize| if position < size { u64::from(info.codes[index + position]) } else { 0 };
        codes.push(Code { offset: (code & 0xFF) as u32, op: ((code >> 8) & 0xF) as u8, info: (code >> 12) as usize, first: word(1), second: word(2) });
        index += size;
    }
    Ok(codes)
}

/// Bytes da imagem num RVA: do arquivo desta máquina ou da memória do alvo.
fn table_bytes(target: &mut dyn Target, table: &FunctionTable, rva: u32, length: usize) -> Result<Vec<u8>, Stop> {
    let address = table.base.wrapping_add(rva as u64);
    let bytes = match &table.image {
        Some(image) => image.bytes_at(rva, length).map(<[u8]>::to_vec),
        None => target.read(address, length).ok(),
    };
    match bytes {
        Some(bytes) if bytes.len() >= length => Ok(bytes),
        Some(bytes) => Err(Stop::Unreadable(address.wrapping_add(bytes.len() as u64))),
        None => Err(Stop::Unreadable(address)),
    }
}

/// Uma entrada indireta (bit 0 do UnwindData) aponta outra RUNTIME_FUNCTION
/// da imagem, a que tem o UNWIND_INFO.
fn resolve_indirect(target: &mut dyn Target, table: &FunctionTable, mut function: RuntimeFunction) -> Result<RuntimeFunction, Stop> {
    for _ in 0..MAX_CHAIN {
        if function.unwind & 1 == 0 {
            return Ok(function);
        }
        let bytes = table_bytes(target, table, function.unwind & !1, 12)?;
        let field = |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
        function = RuntimeFunction { begin: field(0), end: field(4), unwind: field(8) };
    }
    Err(Stop::BadUnwindInfo(table.base.wrapping_add(function.unwind as u64)))
}

fn read_unwind_info(target: &mut dyn Target, table: &FunctionTable, rva: u32) -> Result<UnwindInfo, Stop> {
    let address = table.base.wrapping_add(rva as u64);
    let header = table_bytes(target, table, rva, 4)?;
    let codes = 4 + 2 * ((header[2] as usize + 1) & !1);
    // A entrada encadeada (12 bytes) só existe com UNW_FLAG_CHAININFO.
    let length = if (header[0] >> 3) & UNW_FLAG_CHAININFO != 0 { codes + 12 } else { codes };
    let bytes = table_bytes(target, table, rva, length)?;
    let info = UnwindInfo::parse(&bytes).ok_or(Stop::BadUnwindInfo(address))?;
    if !matches!(info.version, 1 | 2) {
        return Err(Stop::BadUnwindInfo(address));
    }
    Ok(info)
}

/// O valor do registrador de quadro menos o deslocamento (o RSP do
/// SET_FPREG).
fn frame_value(info: &UnwindInfo, context: &Context) -> Result<u64, Stop> {
    let register = (info.frame_register & 0xF) as usize;
    let value = context.registers[register].ok_or(Stop::UnknownRegister(REGISTER_NAMES[register]))?;
    Ok(value.wrapping_sub(info.frame_offset as u64 * 16))
}

/// O establisher frame, a base dos registradores salvos por MOV: o
/// registrador de quadro menos o deslocamento depois do SET_FPREG; sem ele,
/// o RSP depois do prólogo. No meio do prólogo, o RSP corrente menos o que
/// os códigos ainda não executados vão tirar (os MOV do prólogo gravam
/// relativos ao RSP final, mesmo os de antes da alocação).
fn establisher(info: &UnwindInfo, address: u64, offset: Option<u32>, context: &Context) -> Result<u64, Stop> {
    let rsp = context.registers[RSP].ok_or(Stop::UnknownRegister("rsp"))?;
    // Uma parte encadeada já está depois do prólogo da principal.
    let in_prolog = offset.filter(|&offset| offset < info.prolog_size as u32 && info.chained.is_none());
    let Some(offset) = in_prolog else {
        return if info.frame_register != 0 { frame_value(info, context) } else { Ok(rsp) };
    };
    let codes = decode(info, address)?;
    if info.frame_register != 0 && codes.iter().any(|code| code.op == UWOP_SET_FPREG && code.offset <= offset) {
        return frame_value(info, context);
    }
    let pending = codes.iter().filter(|code| code.offset > offset).fold(0u64, |total, code| total.wrapping_add(code.stack_bytes()));
    Ok(rsp.wrapping_sub(pending))
}

/// Desfaz o prólogo da função (e das principais encadeadas) e tira o
/// retorno da pilha, ou volta pelo quadro de máquina. `offset`: onde o RIP
/// está na função, só no quadro de cima (códigos do prólogo ainda não
/// executados ficam de fora). Devolve se houve quadro de máquina.
fn virtual_unwind(target: &mut dyn Target, table: &FunctionTable, function: RuntimeFunction, offset: Option<u32>, context: &mut Context) -> Result<bool, Stop> {
    let mut address = table.base.wrapping_add(function.unwind as u64);
    let mut info = read_unwind_info(target, table, function.unwind)?;
    let base = establisher(&info, address, offset, context)?;
    let mut first = true;
    let mut machine = false;
    for _ in 0..MAX_CHAIN {
        for code in decode(&info, address)? {
            // No meio do prólogo, só os códigos já executados; os das
            // principais encadeadas valem inteiros.
            if first && offset.is_some_and(|offset| code.offset > offset) {
                continue;
            }
            let rsp = context.registers[RSP].ok_or(Stop::UnknownRegister("rsp"))?;
            match code.op {
                UWOP_PUSH_NONVOL => {
                    context.registers[code.info] = Some(read_u64(target, rsp)?);
                    context.registers[RSP] = Some(rsp.wrapping_add(8));
                }
                UWOP_ALLOC_LARGE | UWOP_ALLOC_SMALL => context.registers[RSP] = Some(rsp.wrapping_add(code.stack_bytes())),
                UWOP_SET_FPREG => context.registers[RSP] = Some(frame_value(&info, context)?),
                UWOP_SAVE_NONVOL => context.registers[code.info] = Some(read_u64(target, base.wrapping_add(code.first * 8))?),
                UWOP_SAVE_NONVOL_FAR => context.registers[code.info] = Some(read_u64(target, base.wrapping_add(code.first | code.second << 16))?),
                UWOP_PUSH_MACHFRAME => {
                    // RIP, CS, RFLAGS, RSP e SS (com o código de erro antes,
                    // OpInfo 1): o primeiro empilhado, o último desfeito.
                    let frame = rsp.wrapping_add(code.info as u64 * 8);
                    context.rip = read_u64(target, frame)?;
                    context.registers[RSP] = Some(read_u64(target, frame.wrapping_add(0x18))?);
                    machine = true;
                    break;
                }
                // Os XMM salvos não mudam a pilha; os códigos de epílogo da
                // versão 2 não são do prólogo.
                _ => {}
            }
        }
        if machine {
            break;
        }
        let Some(chained) = info.chained else { break };
        let parent = resolve_indirect(target, table, chained)?;
        address = table.base.wrapping_add(parent.unwind as u64);
        info = read_unwind_info(target, table, parent.unwind)?;
        first = false;
    }
    if !machine {
        pop_return(target, context)?;
    }
    context.forget_volatile();
    Ok(machine)
}

/// A entrada principal de uma função (seguindo a informação encadeada).
fn primary(target: &mut dyn Target, table: &FunctionTable, mut function: RuntimeFunction) -> Option<RuntimeFunction> {
    for _ in 0..MAX_CHAIN {
        function = resolve_indirect(target, table, function).ok()?;
        match read_unwind_info(target, table, function.unwind).ok()?.chained {
            Some(parent) => function = parent,
            None => return Some(function),
        }
    }
    None
}

/// O destino de um `jmp` sai da função (uma chamada em cauda): fora da
/// entrada e de qualquer outra parte da mesma função principal (o código
/// frio das entradas encadeadas).
fn leaves_function(target: &mut dyn Target, table: &FunctionTable, function: RuntimeFunction, destination: u64) -> bool {
    let Some(rva) = destination.checked_sub(table.base).and_then(|offset| u32::try_from(offset).ok()) else { return true };
    if rva >= function.begin && rva < function.end {
        return false;
    }
    let Some(other) = find_function(&table.functions, rva) else { return true };
    primary(target, table, other) != primary(target, table, function)
}

/// Registrador de um `pop` (com ou sem REX.B), se o byte for um.
fn pop_register(code: &[u8], at: usize) -> Option<(usize, usize)> {
    match (code.get(at).copied()?, code.get(at + 1).copied()) {
        (byte @ 0x58..=0x5F, _) => Some(((byte - 0x58) as usize, 1)),
        (0x41, Some(byte @ 0x58..=0x5F)) => Some(((byte - 0x58) as usize + 8, 2)),
        _ => None,
    }
}

/// O RIP do quadro de cima está num epílogo: `add rsp, imm` ou
/// `lea rsp, [registrador + deslocamento]`, `pop`s e um `ret`, um `jmp`
/// para fora da função, um `jmp [rip+disp32]` (o import) ou um
/// `rex.w jmp registrador` (as chamadas em cauda). Emula as instruções que
/// faltam.
fn unwind_epilog(target: &mut dyn Target, table: &FunctionTable, function: RuntimeFunction, context: &mut Context) -> bool {
    let rip = context.rip;
    let Ok(code) = target.read(rip, 64) else { return false };
    let Some(mut rsp) = context.registers[RSP] else { return false };
    let byte = |index: usize| code.get(index).copied();
    let imm32 = |index: usize| code.get(index..index + 4).map(|bytes| i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64 as u64);
    let mut at = 0;
    match (byte(0), byte(1), byte(2)) {
        (Some(0x48), Some(0x83), Some(0xC4)) => {
            let Some(value) = byte(3) else { return false };
            rsp = rsp.wrapping_add(value as i8 as i64 as u64);
            at = 4;
        }
        (Some(0x48), Some(0x81), Some(0xC4)) => {
            let Some(value) = imm32(3) else { return false };
            rsp = rsp.wrapping_add(value);
            at = 7;
        }
        // lea rsp, [registrador + disp8/disp32] (sem SIB).
        (Some(prefix @ (0x48 | 0x49)), Some(0x8D), Some(modrm)) if modrm & 0x38 == 0x20 && modrm & 7 != 4 && matches!(modrm >> 6, 1 | 2) => {
            let register = (modrm & 7) as usize + if prefix == 0x49 { 8 } else { 0 };
            let Some(frame) = context.registers[register] else { return false };
            let (displacement, length) = if modrm >> 6 == 1 { (byte(3).map(|value| value as i8 as i64 as u64), 1) } else { (imm32(3), 4) };
            let Some(displacement) = displacement else { return false };
            rsp = frame.wrapping_add(displacement);
            at = 3 + length;
        }
        _ => {}
    }
    let mut pops = Vec::new();
    while let Some((register, length)) = pop_register(&code, at) {
        pops.push(register);
        at += length;
    }
    let terminator = match (byte(at), byte(at + 1), byte(at + 2)) {
        (Some(0xC3 | 0xC2), _, _) | (Some(0xF3), Some(0xC3), _) => true,
        (Some(0xE9), _, _) => match imm32(at + 1) {
            Some(relative) => leaves_function(target, table, function, rip.wrapping_add(at as u64 + 5).wrapping_add(relative)),
            None => false,
        },
        (Some(0xEB), Some(relative), _) => leaves_function(target, table, function, rip.wrapping_add(at as u64 + 2).wrapping_add(relative as i8 as i64 as u64)),
        (Some(0xFF), Some(0x25), _) | (Some(0x48), Some(0xFF), Some(0x25)) => true,
        (Some(0x48 | 0x49), Some(0xFF), Some(modrm)) => modrm & 0xF8 == 0xE0,
        _ => false,
    };
    if !terminator {
        return false;
    }
    let mut registers = context.registers;
    for register in pops {
        let Some(value) = target.read_u64(rsp) else { return false };
        registers[register] = Some(value);
        rsp = rsp.wrapping_add(8);
    }
    let Some(caller) = target.read_u64(rsp) else { return false };
    registers[RSP] = Some(rsp.wrapping_add(8));
    context.registers = registers;
    context.rip = caller;
    context.forget_volatile();
    true
}

/// Uma pilha capturada: bytes a partir de um endereço (os testes, e o
/// código em volta do RIP).
pub struct Captured {
    pub regions: Vec<(u64, Vec<u8>)>,
}

impl ReadMemory for Captured {
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
        for (base, bytes) in &self.regions {
            if address >= *base && address < base + bytes.len() as u64 {
                let start = (address - base) as usize;
                let end = (start + length).min(bytes.len());
                return Ok(bytes[start..end].to_vec());
            }
        }
        Err(format!("memoria em {address:#x} inacessivel"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Uma pilha de kernel de verdade, como o `x %rsp 0x60` a mostra num
    /// breakpoint dentro de uma função com o quadro montado: três quadros
    /// encadeados e um RBP zerado no fim.
    fn captured_stack() -> Captured {
        let base = 0xffff_8000_0010_0f00u64;
        let mut stack = vec![0u8; 0x100];
        let mut put = |offset: usize, value: u64| stack[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        // Quadro 1 (RBP = base + 0x20): RBP salvo -> base + 0x60, retorno.
        put(0x20, base + 0x60);
        put(0x28, 0xfffff800_4012_3456);
        // Quadro 2 (base + 0x60) -> base + 0xa0.
        put(0x60, base + 0xa0);
        put(0x68, 0xfffff800_4000_2222);
        // Quadro 3 (base + 0xa0): fim da cadeia.
        put(0xa0, 0);
        put(0xa8, 0xfffff800_4000_1111);
        let code_base = 0xfffff800_4010_0000u64;
        // O RIP aponta para `sub rsp, 0x20` (depois do prólogo) e, num
        // segundo cenário, para o `push rbp`.
        let code = vec![0x48, 0x83, 0xEC, 0x20, 0x55, 0x48, 0x89, 0xE5];
        Captured { regions: vec![(base, stack), (code_base, code)] }
    }

    fn addresses(frames: &[Frame]) -> Vec<u64> {
        frames.iter().map(|frame| frame.address).collect()
    }

    /// Uma região de memória com valores de 64 bits nos deslocamentos.
    fn region(base: u64, size: usize, values: &[(u64, u64)]) -> (u64, Vec<u8>) {
        let mut bytes = vec![0u8; size];
        for &(offset, value) in values {
            bytes[offset as usize..offset as usize + 8].copy_from_slice(&value.to_le_bytes());
        }
        (base, bytes)
    }

    /// A tabela de um driver montado (`pe::tests::tiny_pe`): a `.pdata` em
    /// 0x2000 e os UNWIND_INFO logo depois dela.
    fn driver_table(base: u64, pdata: &[RuntimeFunction], rdata: &[u8]) -> Arc<FunctionTable> {
        let image = PeImage::parse(crate::pe::tests::tiny_pe(pdata, rdata, false)).unwrap();
        Arc::new(FunctionTable { base, functions: image.runtime_functions(), image: Some(Arc::new(image)) })
    }

    #[test]
    fn unwinds_framed_function() {
        let mut memory = captured_stack();
        let base = 0xffff_8000_0010_0f00u64;
        let frames = unwind(&mut memory, 0xfffff800_4010_0000, base, base + 0x20, 32);
        assert_eq!(addresses(&frames), vec![0xfffff800_4010_0000, 0xfffff800_4012_3456, 0xfffff800_4000_2222, 0xfffff800_4000_1111]);
        assert!(!frames[0].is_return);
        assert!(frames[1..].iter().all(|frame| frame.is_return && frame.method == Method::FramePointer && frame.transition.is_none()));
        assert_eq!(frames[1].stack, base + 0x30);
        assert_eq!(return_slot(&mut memory, 0xfffff800_4010_0000, base, base + 0x20), base + 0x28);
    }

    #[test]
    fn unwinds_at_push_rbp() {
        // No `push rbp`, o retorno está em [RSP] (base + 0x18 aqui) e o RBP
        // ainda é o do chamador (o quadro 1).
        let mut memory = captured_stack();
        let base = 0xffff_8000_0010_0f00u64;
        if let Some((_, stack)) = memory.regions.first_mut() {
            stack[0x18..0x20].copy_from_slice(&0xfffff800_4013_0000u64.to_le_bytes());
        }
        let frames = unwind(&mut memory, 0xfffff800_4010_0004, base + 0x18, base + 0x20, 32);
        assert_eq!(addresses(&frames), vec![0xfffff800_4010_0004, 0xfffff800_4013_0000, 0xfffff800_4012_3456, 0xfffff800_4000_2222, 0xfffff800_4000_1111]);
        assert_eq!(return_slot(&mut memory, 0xfffff800_4010_0004, base + 0x18, base + 0x20), base + 0x18);
    }

    #[test]
    fn stops_on_limit_and_bad_frames() {
        let mut memory = captured_stack();
        let base = 0xffff_8000_0010_0f00u64;
        assert_eq!(unwind(&mut memory, 0xfffff800_4010_0000, base, base + 0x20, 2).len(), 2);
        // RBP desalinhado ou fora da memória: só o RIP.
        assert_eq!(unwind(&mut memory, 0xfffff800_4010_0000, base, base + 0x21, 32).len(), 1);
        assert_eq!(unwind(&mut memory, 0xfffff800_4010_0000, base, 0x1000, 32).len(), 1);
    }

    #[test]
    fn says_why_the_walk_stopped() {
        let base = 0xffff_8000_0010_0f00u64;
        let rip = 0xfffff800_4010_0000u64;
        let walk_with = |rbp: u64, limit: usize| {
            let mut memory = captured_stack();
            walk_stack(&mut FramePointers(&mut memory), Context::new(rip, base, rbp), false, limit)
        };
        let full = walk_with(base + 0x20, 32);
        assert_eq!(full.frames.len(), 4);
        assert!(matches!(full.stop, Stop::End(ref reason) if reason.contains("rbp zero")), "{:?}", full.stop);
        assert_eq!(walk_with(base + 0x20, 2).stop, Stop::Limit);
        assert_eq!(walk_with(base + 0x21, 32).stop, Stop::FramePointer(base + 0x21));
        assert_eq!(walk_with(base + 0x200, 32).stop, Stop::Unreadable(base + 0x200));
        assert_eq!(walk_with(0x1000, 32).stop, Stop::FramePointer(0x1000));
        assert!(Stop::Unreadable(0x1234).text().contains("0x1234"));
        assert!(Stop::End("x".into()).text().starts_with("fim da pilha"));
    }

    #[test]
    fn parses_unwind_info() {
        // Versão 1, prólogo de 0x0e bytes, 5 slots, quadro RBP+0x20, e uma
        // função encadeada.
        let bytes = [
            0x21, 0x0e, 0x05, 0x25, //
            0x0e, 0x53, // SET_FPREG (offset 0x0e)
            0x0a, 0x01, 0x08, 0x00, // ALLOC_LARGE 8*8 (offset 0x0a)
            0x06, 0x30, // PUSH_NONVOL rbx
            0x02, 0x50, // PUSH_NONVOL rbp
            0x00, 0x00, // alinhamento
            0x00, 0x10, 0x00, 0x00, 0x40, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
        ];
        let info = UnwindInfo::parse(&bytes).unwrap();
        assert_eq!(info.version, 1);
        assert_eq!(info.flags, UNW_FLAG_CHAININFO);
        assert_eq!(info.prolog_size, 0x0e);
        assert_eq!(info.frame_register, 5);
        assert_eq!(info.frame_offset, 2);
        assert_eq!(info.codes.len(), 5);
        assert_eq!(slots(info.codes[1]), Some(2));
        assert_eq!(info.chained, Some(RuntimeFunction { begin: 0x1000, end: 0x1040, unwind: 0x2000 }));
        // A tabela dos slots do 19041: SPARE_CODE ocupa 3, códigos 11-15
        // são inválidos.
        assert_eq!(slots(0x0700), Some(3));
        assert_eq!(slots(0x0600), Some(2));
        assert_eq!(slots(0x0B00), None);
        assert_eq!(slots(0x2100), None);
        let codes = decode(&info, 0).unwrap();
        assert_eq!(codes.len(), 4);
        assert_eq!(codes[1], Code { offset: 0x0a, op: UWOP_ALLOC_LARGE, info: 0, first: 8, second: 0 });
        assert_eq!(codes[1].stack_bytes(), 0x40);
    }

    /// Um driver (com `.pdata`) entre código do kernel (frame pointers).
    struct Mixed {
        memory: Captured,
        table: Arc<FunctionTable>,
    }

    impl ReadMemory for Mixed {
        fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
            self.memory.read(address, length)
        }
    }

    impl Target for Mixed {
        fn function_table(&mut self, address: u64) -> Option<Arc<FunctionTable>> {
            (address >= self.table.base && address < self.table.base + 0x3000).then(|| Arc::clone(&self.table))
        }
    }

    #[test]
    fn unwinds_through_a_driver_without_frame_pointers() {
        let driver = 0xfffff800_5000_0000u64;
        // Interna (0x1000-0x1100): push rbx; sub rsp, 0x20 -> PUSH_NONVOL
        // rbx (offset 1), ALLOC_SMALL 0x20 (offset 5).
        let interna = [0x01, 0x05, 0x02, 0x00, 0x05, 0x32, 0x01, 0x30];
        // Externa (0x1200-0x1300): push rbp; push rsi; sub rsp, 0x30; lea
        // rbp, [rsp+0x20] -> SET_FPREG rbp+0x20, ALLOC_SMALL 0x30, PUSH rsi,
        // PUSH rbp.
        let externa = [0x01, 0x0b, 0x04, 0x25, 0x0b, 0x53, 0x06, 0x52, 0x02, 0x60, 0x01, 0x50];
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&interna);
        rdata.extend_from_slice(&externa);
        let table = driver_table(driver, &[RuntimeFunction { begin: 0x1000, end: 0x1100, unwind: 0x2018 }, RuntimeFunction { begin: 0x1200, end: 0x1300, unwind: 0x2020 }], &rdata);

        // A pilha, de baixo para cima (endereços crescentes).
        let stack_base = 0xffff_8000_0020_0000u64;
        let stack = region(
            stack_base,
            0x200,
            &[
                // Quadro do kernel (frame pointer) chamado pela Interna: o
                // RBP salvo (o da Externa, stack_base + 0x70) e o retorno na
                // Interna.
                (0x10, stack_base + 0x70),
                (0x18, driver + 0x1050),
                // Interna: sub rsp, 0x20 (0x20..0x40), push rbx (0x40),
                // retorno (0x48).
                (0x40, 0x1111),
                (0x48, driver + 0x1280),
                // Externa: RSP depois do prólogo = 0x50; sub rsp, 0x30
                // (0x50..0x80), push rsi (0x80), push rbp (0x88), retorno
                // (0x90). RBP = 0x50 + 0x20.
                (0x80, 0x2222),
                (0x88, stack_base + 0xc0),
                (0x90, 0xfffff800_4000_7000),
                // Kernel (frame pointer) em 0xc0: RBP salvo 0 e retorno no
                // kmain.
                (0xc0, 0),
                (0xc8, 0xfffff800_4000_1000),
            ],
        );
        let mut target = Mixed { memory: Captured { regions: vec![stack] }, table };
        let mut context = Context::new(0xfffff800_4000_9000, stack_base, stack_base + 0x10);
        context.registers[3] = Some(0x9999);
        let walk = walk_stack(&mut target, context, false, 16);
        let frames = &walk.frames;
        assert_eq!(addresses(frames), vec![0xfffff800_4000_9000, driver + 0x1050, driver + 0x1280, 0xfffff800_4000_7000, 0xfffff800_4000_1000]);
        assert_eq!(frames[1].method, Method::FramePointer);
        assert_eq!(frames[2].method, Method::Table);
        assert_eq!(frames[3].method, Method::Table);
        assert_eq!(frames[4].method, Method::FramePointer);
        assert_eq!(frames[3].stack, stack_base + 0x98);
        assert!(matches!(walk.stop, Stop::End(_)), "{:?}", walk.stop);
    }

    #[test]
    fn emulates_an_epilog_and_a_leaf() {
        let driver = 0xfffff800_5000_0000u64;
        let table = driver_table(driver, &[RuntimeFunction { begin: 0x1000, end: 0x1100, unwind: 0x200c }], &[0x01, 0x05, 0x02, 0x00, 0x05, 0x32, 0x01, 0x30]);
        let stack_base = 0xffff_8000_0030_0000u64;
        let stack = region(stack_base, 0x100, &[(0x20, 0x7777), (0x28, 0xfffff800_4000_2000)]);
        // Código do epílogo em driver+0x1080: add rsp, 0x20; pop rbx; ret.
        let code = vec![0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3];
        let mut target = Mixed { memory: Captured { regions: vec![stack, (driver + 0x1080, code)] }, table };
        let frames = walk(&mut target, Context::new(driver + 0x1080, stack_base, 0), false, 2);
        assert_eq!(addresses(&frames), vec![driver + 0x1080, 0xfffff800_4000_2000]);
        assert_eq!(frames[1].method, Method::Epilog);
        // Fora de qualquer função da `.pdata`: folha, retorno em [RSP].
        let mut context = Context::new(driver + 0x1180, stack_base + 0x28, 0);
        assert_eq!(step(&mut target, &mut context, true).map(|stepped| stepped.method), Ok(Method::Leaf));
        assert_eq!(context.rip, 0xfffff800_4000_2000);
        assert_eq!(context.rsp(), stack_base + 0x30);
    }

    #[test]
    fn saved_registers_are_relative_to_the_establisher_frame() {
        let driver = 0xfffff800_5000_0000u64;
        // mov [rsp+8], rbx (termina em 5); push rdi (6); sub rsp, 0x20
        // (0x0a): ALLOC_SMALL 0x20 em 0x0a, PUSH_NONVOL rdi em 6 e
        // SAVE_NONVOL rbx em 5, deslocamento 0x30 (relativo ao RSP final).
        let info = [0x01, 0x0a, 0x04, 0x00, 0x0a, 0x32, 0x06, 0x70, 0x05, 0x34, 0x06, 0x00];
        let table = driver_table(driver, &[RuntimeFunction { begin: 0x1000, end: 0x1100, unwind: 0x200c }], &info);
        // O RSP final em `base`: locais (0..0x20), rdi (0x20), retorno
        // (0x28) e o rbx na área de casa do chamador (0x30). Em 0x58, o que o
        // deslocamento leria a partir do RSP depois dos pushes.
        let base = 0xffff_8000_0040_0000u64;
        let stack = region(base, 0x100, &[(0x20, 0x7d7d), (0x28, 0xfffff800_4000_3000), (0x30, 0xb0b0), (0x58, 0xbad)]);
        let mut target = Mixed { memory: Captured { regions: vec![stack] }, table };
        let state = |context: &Context| (context.rip, context.rsp(), context.registers[3], context.registers[7]);
        // No corpo (um retorno de quem ela chamou).
        let mut context = Context::new(driver + 0x1050, base, 0);
        assert_eq!(step(&mut target, &mut context, false).map(|stepped| stepped.method), Ok(Method::Table));
        assert_eq!(state(&context), (0xfffff800_4000_3000, base + 0x30, Some(0xb0b0), Some(0x7d7d)));
        // No meio do prólogo: depois do push rdi, antes do sub (RSP final +
        // 0x20).
        let mut context = Context::new(driver + 0x1006, base + 0x20, 0);
        step(&mut target, &mut context, true).unwrap();
        assert_eq!(state(&context), (0xfffff800_4000_3000, base + 0x30, Some(0xb0b0), Some(0x7d7d)));
        // Na primeira instrução: só o retorno.
        let mut context = Context::new(driver + 0x1000, base + 0x28, 0);
        step(&mut target, &mut context, true).unwrap();
        assert_eq!(state(&context), (0xfffff800_4000_3000, base + 0x30, None, None));
    }

    #[test]
    fn follows_indirect_and_chained_entries() {
        let driver = 0xfffff800_5000_0000u64;
        // A (0x1000-0x1040): push rbx. B (0x1100-0x1120): código frio de A,
        // sub rsp, 0x10, encadeado a A. C (0x1120-0x1140): entrada indireta
        // para a de B (o RVA da entrada de B na `.pdata` com o bit 0).
        let a = RuntimeFunction { begin: 0x1000, end: 0x1040, unwind: 0x2024 };
        let b = RuntimeFunction { begin: 0x1100, end: 0x1120, unwind: 0x202c };
        let c = RuntimeFunction { begin: 0x1120, end: 0x1140, unwind: 0x200c | 1 };
        let mut rdata = vec![0x01, 0x01, 0x01, 0x00, 0x01, 0x30, 0x00, 0x00];
        rdata.extend_from_slice(&[0x21, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00, 0x00]);
        for value in [a.begin, a.end, a.unwind] {
            rdata.extend_from_slice(&value.to_le_bytes());
        }
        let table = driver_table(driver, &[a, b, c], &rdata);
        let base = 0xffff_8000_0050_0000u64;
        let stack = region(base, 0x100, &[(0x10, 0x5151), (0x18, 0xfffff800_4000_4000)]);
        let mut target = Mixed { memory: Captured { regions: vec![stack] }, table: Arc::clone(&table) };
        let mut context = Context::new(driver + 0x1130, base, 0);
        assert_eq!(step(&mut target, &mut context, false).map(|stepped| stepped.method), Ok(Method::Table));
        assert_eq!((context.rip, context.rsp(), context.registers[3]), (0xfffff800_4000_4000, base + 0x20, Some(0x5151)));
        // A principal de C e de B é A: um `jmp` de A para B não sai da
        // função; um para fora da `.pdata`, sim.
        assert_eq!(primary(&mut target, &table, c), Some(a));
        assert!(!leaves_function(&mut target, &table, a, driver + 0x1110));
        assert!(leaves_function(&mut target, &table, a, driver + 0x1500));
    }

    #[test]
    fn crosses_a_machine_frame() {
        let driver = 0xfffff800_5000_0000u64;
        // Tratador de interrupção (0x1000-0x1100): o quadro de máquina com
        // código de erro (offset 0) e push rbp (offset 1).
        let table = driver_table(driver, &[RuntimeFunction { begin: 0x1000, end: 0x1100, unwind: 0x200c }], &[0x01, 0x01, 0x02, 0x00, 0x01, 0x50, 0x00, 0x1A]);
        let interrupt = 0xffff_8000_0060_0000u64;
        let interrupted = 0xffff_8000_0070_0000u64;
        // A pilha da interrupção: rbp salvo, código de erro, RIP, CS,
        // RFLAGS, RSP e SS do código interrompido.
        let handler_stack = region(interrupt, 0x40, &[(0x00, interrupted + 0x40), (0x08, 0x10), (0x10, 0xfffff800_4000_5000), (0x18, 0x10), (0x20, 0x246), (0x28, interrupted + 0x20), (0x30, 0x18)]);
        // O código interrompido (kernel, frame pointers): o quadro em +0x40.
        let interrupted_stack = region(interrupted, 0x80, &[(0x40, 0), (0x48, 0xfffff800_4000_6000)]);
        let mut target = Mixed { memory: Captured { regions: vec![handler_stack, interrupted_stack] }, table };
        let walk = walk_stack(&mut target, Context::new(driver + 0x1010, interrupt, 0), false, 16);
        assert_eq!(addresses(&walk.frames), vec![driver + 0x1010, 0xfffff800_4000_5000, 0xfffff800_4000_6000]);
        assert_eq!(walk.frames[1].transition, Some(Transition::MachineFrame));
        assert_eq!(walk.frames[1].method, Method::Table);
        assert!(!walk.frames[1].is_return);
        assert_eq!(walk.frames[1].stack, interrupted + 0x20);
        assert_eq!(walk.frames[2].method, Method::FramePointer);
        assert!(matches!(walk.stop, Stop::End(_)), "{:?}", walk.stop);
    }

    /// Um kernel com uma passagem para o anel 3 num endereço de retorno e o
    /// começo da pilha em outro.
    struct WithCrossings {
        memory: Captured,
        syscall_return: u64,
        user: Context,
        start_return: u64,
    }

    impl ReadMemory for WithCrossings {
        fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
            self.memory.read(address, length)
        }
    }

    impl Target for WithCrossings {
        fn function_table(&mut self, _address: u64) -> Option<Arc<FunctionTable>> {
            None
        }

        fn crossing(&mut self, context: &Context) -> Option<Crossing> {
            if context.rip == self.syscall_return {
                return Some(Crossing::Enter(self.user.clone(), Transition::Syscall));
            }
            (context.rip == self.start_return).then(|| Crossing::End("comeco da thread".into()))
        }
    }

    #[test]
    fn crosses_into_user_mode_and_marks_the_end() {
        let kernel = 0xffff_8000_0080_0000u64;
        let user = 0x0000_0000_0300_0000u64;
        let syscall_return = 0xfffff800_4000_8100u64;
        let start_return = 0xfffff800_4000_8200u64;
        let run = |kernel_return: u64| {
            let kernel_stack = region(kernel, 0x80, &[(0x20, kernel + 0x60), (0x28, kernel_return)]);
            let user_stack = region(user, 0x80, &[(0x40, 0), (0x48, 0x7ff6_0000_2000)]);
            let mut target = WithCrossings {
                memory: Captured { regions: vec![kernel_stack, user_stack] },
                syscall_return,
                user: Context::new(0x7ff6_0000_1000, user, user + 0x40),
                start_return,
            };
            walk_stack(&mut target, Context::new(0xfffff800_4000_9000, kernel, kernel + 0x20), false, 16)
        };
        // O quadro da entrada de syscall passa para o anel 3, com o RIP
        // exato do outro lado.
        let walk = run(syscall_return);
        assert_eq!(addresses(&walk.frames), vec![0xfffff800_4000_9000, syscall_return, 0x7ff6_0000_1000, 0x7ff6_0000_2000]);
        assert_eq!(walk.frames[2].transition, Some(Transition::Syscall));
        assert_eq!(walk.frames[2].method, Method::Context);
        assert!(!walk.frames[2].is_return);
        assert_eq!(walk.frames[2].stack, user);
        assert!(walk.frames[3].is_return);
        assert!(matches!(walk.stop, Stop::End(_)), "{:?}", walk.stop);
        // O começo da pilha: o quadro sai e o motivo é o do alvo.
        let walk = run(start_return);
        assert_eq!(addresses(&walk.frames), vec![0xfffff800_4000_9000, start_return]);
        assert_eq!(walk.stop, Stop::End("comeco da thread".into()));
        // Um retorno do kernel direto para o anel 3, sem passagem, para.
        let walk = run(0x7ff6_0000_3000);
        assert_eq!(walk.frames.len(), 1);
        assert_eq!(walk.stop, Stop::KernelToUser(0x7ff6_0000_3000));
        // E o anel 3 nunca volta para o kernel.
        let user_stack = region(user, 0x80, &[(0x40, 0), (0x48, 0xfffff800_4000_1000)]);
        let mut memory = Captured { regions: vec![user_stack] };
        let walk = walk_stack(&mut FramePointers(&mut memory), Context::new(0x7ff6_0000_1000, user, user + 0x40), false, 16);
        assert_eq!(walk.frames.len(), 1);
        assert_eq!(walk.stop, Stop::UserToKernel(0xfffff800_4000_1000));
    }

    #[test]
    fn recognizes_epilog_forms() {
        let driver = 0xfffff800_5000_0000u64;
        let function = RuntimeFunction { begin: 0x1000, end: 0x1100, unwind: 0x200c };
        let table = driver_table(driver, &[function], &[0x01, 0x00, 0x00, 0x00]);
        let mut code = vec![0x90u8; 0x100];
        // +0x80: lea rsp, [rbp+0x10]; pop rbp; ret.
        code[0x80..0x86].copy_from_slice(&[0x48, 0x8D, 0x65, 0x10, 0x5D, 0xC3]);
        // +0x90: add rsp, 0x28; jmp para driver+0x2000 (fora da função).
        code[0x90..0x99].copy_from_slice(&[0x48, 0x83, 0xC4, 0x28, 0xE9, 0x67, 0x0F, 0x00, 0x00]);
        // +0xa0: add rsp, 0x28; jmp para driver+0x1010 (dentro dela).
        code[0xa0..0xa9].copy_from_slice(&[0x48, 0x83, 0xC4, 0x28, 0xE9, 0x67, 0xFF, 0xFF, 0xFF]);
        // +0xb0: rex.w jmp rax (chamada em cauda por registrador).
        code[0xb0..0xb3].copy_from_slice(&[0x48, 0xFF, 0xE0]);
        let base = 0xffff_8000_0090_0000u64;
        let stack = region(base, 0x100, &[(0x00, 0xfffff800_4000_a000), (0x20, base + 0x80), (0x28, 0xfffff800_4000_b000)]);
        let mut target = Mixed { memory: Captured { regions: vec![stack, (driver + 0x1000, code)] }, table: Arc::clone(&table) };
        let mut context = Context::new(driver + 0x1080, base, base + 0x10);
        assert!(unwind_epilog(&mut target, &table, function, &mut context));
        assert_eq!((context.rip, context.rsp(), context.rbp()), (0xfffff800_4000_b000, base + 0x30, Some(base + 0x80)));
        let mut context = Context::new(driver + 0x1090, base, 0);
        assert!(unwind_epilog(&mut target, &table, function, &mut context));
        assert_eq!((context.rip, context.rsp()), (0xfffff800_4000_b000, base + 0x30));
        let mut context = Context::new(driver + 0x10a0, base, 0);
        assert!(!unwind_epilog(&mut target, &table, function, &mut context));
        assert_eq!(context.rip, driver + 0x10a0);
        let mut context = Context::new(driver + 0x10b0, base, 0);
        assert!(unwind_epilog(&mut target, &table, function, &mut context));
        assert_eq!((context.rip, context.rsp()), (0xfffff800_4000_a000, base + 0x8));
    }

    #[test]
    fn stops_on_an_unknown_frame_register_and_bad_unwind_info() {
        let driver = 0xfffff800_5000_0000u64;
        // F (0x1000-0x1100): quadro em r13 (SET_FPREG em 4). G
        // (0x1200-0x1300): versão 3.
        let rdata = [0x01, 0x04, 0x01, 0x0D, 0x04, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00];
        let table = driver_table(driver, &[RuntimeFunction { begin: 0x1000, end: 0x1100, unwind: 0x2018 }, RuntimeFunction { begin: 0x1200, end: 0x1300, unwind: 0x2020 }], &rdata);
        let base = 0xffff_8000_00a0_0000u64;
        let mut target = Mixed { memory: Captured { regions: vec![region(base, 0x40, &[])] }, table };
        let mut context = Context::new(driver + 0x1050, base, base);
        assert_eq!(step(&mut target, &mut context, false), Err(Stop::UnknownRegister("r13")));
        let mut context = Context::new(driver + 0x1250, base, base);
        assert_eq!(step(&mut target, &mut context, false), Err(Stop::BadUnwindInfo(driver + 0x2020)));
    }
}
