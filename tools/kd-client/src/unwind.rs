//! A pilha de um processador parado ou de uma thread, com dois métodos:
//!
//! - binários da Microsoft (sem frame pointer): o desenrolar virtual do x64
//!   pela tabela de funções do PE (`.pdata`, RUNTIME_FUNCTION) e pelos
//!   códigos do UNWIND_INFO de cada função (push, alocação, registrador de
//!   quadro, registradores salvos, quadro de máquina e informação
//!   encadeada), com o epílogo reconhecido no quadro de cima, como o
//!   RtlVirtualUnwind;
//! - o código do OpenNT (compilado com `force-frame-pointers`, sem
//!   `.pdata`): cada quadro guarda o RBP do chamador em [RBP] e o endereço
//!   de retorno em [RBP + 8]; no prólogo (`push rbp` ou `mov rbp, rsp` por
//!   executar) e no `ret`, o retorno está no topo da pilha.
//!
//! Os dois se misturam numa pilha: o contexto (RIP, RSP e os registradores
//! conhecidos) passa de um quadro ao outro, então um driver chamado pelo
//! kernel e o kernel chamado pelo driver desenrolam um sobre o outro.
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

/// O alvo do desenrolar: memória e a tabela de funções do código num
/// endereço (`None` = código sem `.pdata`, desenrolado pelo RBP).
pub trait Target: ReadMemory {
    fn function_table(&mut self, address: u64) -> Option<Arc<FunctionTable>>;
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
    /// Os registradores do processador ou da thread.
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
}

/// Os registradores na numeração do UNWIND_CODE: 0 RAX, 1 RCX, 2 RDX,
/// 3 RBX, 4 RSP, 5 RBP, 6 RSI, 7 RDI, 8-15 R8-R15.
pub const REGISTER_NAMES: [&str; 16] = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
const RSP: usize = 4;
const RBP: usize = 5;

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
            if let Some(index) = REGISTER_NAMES.iter().position(|register| register == name) {
                context.registers[index] = Some(*value);
            }
        }
        context
    }

    pub fn rsp(&self) -> u64 {
        self.registers[RSP].unwrap_or(0)
    }

    pub fn rbp(&self) -> Option<u64> {
        self.registers[RBP]
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

/// A pilha a partir de um contexto. `top_is_return`: o RIP já é um
/// endereço de retorno (o quadro de troca de uma thread fora da CPU).
pub fn walk(target: &mut dyn Target, mut context: Context, top_is_return: bool, limit: usize) -> Vec<Frame> {
    let mut frames = vec![Frame { address: context.rip, is_return: top_is_return, stack: context.rsp(), method: Method::Context }];
    let mut top = !top_is_return;
    while frames.len() < limit {
        let before = context.rsp();
        let Some(method) = step(target, &mut context, top) else { break };
        if context.rip == 0 || context.rip < 0x1000 {
            break;
        }
        // Sem progresso na pilha (fora o quadro de máquina, que troca de
        // pilha), o desenrolar se perdeu.
        if context.rsp() <= before && method != Method::Table {
            break;
        }
        frames.push(Frame { address: context.rip, is_return: true, stack: context.rsp(), method });
        top = false;
    }
    frames
}

/// Um quadro: o contexto vira o do chamador.
fn step(target: &mut dyn Target, context: &mut Context, top: bool) -> Option<Method> {
    // O símbolo (e a função) de um endereço de retorno é o do `call`.
    let lookup = if top { context.rip } else { context.rip.wrapping_sub(1) };
    match target.function_table(lookup) {
        Some(table) => {
            let rva = u32::try_from(lookup.checked_sub(table.base)?).ok()?;
            match find_function(&table.functions, rva) {
                None => {
                    // Função folha: nada na pilha além do retorno.
                    let rsp = context.rsp();
                    context.rip = target.read_u64(rsp)?;
                    context.registers[RSP] = Some(rsp + 8);
                    Some(Method::Leaf)
                }
                Some(function) => {
                    if top && unwind_epilog(target, context) {
                        return Some(Method::Epilog);
                    }
                    let offset = if top { (context.rip - table.base) as u32 - function.begin } else { u32::MAX };
                    virtual_unwind(target, &table, function, offset, context)?;
                    Some(Method::Table)
                }
            }
        }
        None => {
            let rsp = context.rsp();
            if top {
                let code = target.read(context.rip, 3).unwrap_or_default();
                if let Some(slot) = x86::prologue_return_slot(&code, rsp) {
                    context.rip = target.read_u64(slot)?;
                    context.registers[RSP] = Some(slot + 8);
                    return Some(Method::FramePointer);
                }
            }
            let rbp = context.rbp()?;
            if rbp == 0 || rbp & 7 != 0 || rbp.wrapping_add(16) <= rsp {
                return None;
            }
            let frame = target.read(rbp, 16).ok()?;
            if frame.len() < 16 {
                return None;
            }
            context.registers[RBP] = Some(u64::from_le_bytes(frame[..8].try_into().unwrap()));
            context.rip = u64::from_le_bytes(frame[8..16].try_into().unwrap());
            context.registers[RSP] = Some(rbp + 16);
            Some(Method::FramePointer)
        }
    }
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

    /// Quantos bytes ler para ter o UNWIND_INFO inteiro (sem o tratador).
    pub fn size(count: usize) -> usize {
        4 + 2 * ((count + 1) & !1) + 12
    }
}

/// Quantos slots ocupa um código.
fn slots(code: u16) -> usize {
    let (op, info) = (((code >> 8) & 0xF) as u8, (code >> 12) as u8);
    match op {
        UWOP_ALLOC_LARGE if info == 0 => 2,
        UWOP_ALLOC_LARGE => 3,
        UWOP_SAVE_NONVOL | UWOP_SAVE_XMM128 | UWOP_SPARE_CODE => 2,
        UWOP_SAVE_NONVOL_FAR | UWOP_SAVE_XMM128_FAR => 3,
        UWOP_EPILOG => 2,
        _ => 1,
    }
}

fn read_unwind_info(target: &mut dyn Target, table: &FunctionTable, rva: u32) -> Option<UnwindInfo> {
    let bytes = match &table.image {
        Some(image) => {
            let header = image.bytes_at(rva, 4)?.to_vec();
            image.bytes_at(rva, UnwindInfo::size(*header.get(2)? as usize))?.to_vec()
        }
        None => {
            let header = target.read(table.base + rva as u64, 4).ok()?;
            target.read(table.base + rva as u64, UnwindInfo::size(*header.get(2)? as usize)).ok()?
        }
    };
    UnwindInfo::parse(&bytes)
}

/// Desfaz o prólogo da função (e das principais encadeadas) e tira o
/// retorno da pilha. `offset`: onde o RIP está na função (só no quadro de
/// cima: códigos do prólogo ainda não executados ficam de fora).
fn virtual_unwind(target: &mut dyn Target, table: &FunctionTable, function: RuntimeFunction, offset: u32, context: &mut Context) -> Option<()> {
    let mut info = read_unwind_info(target, table, function.unwind)?;
    let mut first = true;
    for _ in 0..32 {
        let mut index = 0;
        if first {
            while index < info.codes.len() && (info.codes[index] & 0xFF) as u32 > offset {
                index += slots(info.codes[index]);
            }
        }
        while index < info.codes.len() {
            let code = info.codes[index];
            let (op, register) = (((code >> 8) & 0xF) as u8, (code >> 12) as usize);
            let slot = |position: usize| info.codes.get(index + position).copied().map(u64::from);
            let rsp = context.rsp();
            match op {
                UWOP_PUSH_NONVOL => {
                    context.registers[register] = Some(target.read_u64(rsp)?);
                    context.registers[RSP] = Some(rsp + 8);
                }
                UWOP_ALLOC_LARGE => {
                    let size = if register == 0 { slot(1)? * 8 } else { slot(1)? | slot(2)? << 16 };
                    context.registers[RSP] = Some(rsp + size);
                }
                UWOP_ALLOC_SMALL => context.registers[RSP] = Some(rsp + register as u64 * 8 + 8),
                UWOP_SET_FPREG => {
                    let frame = context.registers[info.frame_register as usize]?;
                    context.registers[RSP] = Some(frame - info.frame_offset as u64 * 16);
                }
                UWOP_SAVE_NONVOL => context.registers[register] = Some(target.read_u64(rsp + slot(1)? * 8)?),
                UWOP_SAVE_NONVOL_FAR => context.registers[register] = Some(target.read_u64(rsp + (slot(1)? | slot(2)? << 16))?),
                UWOP_PUSH_MACHFRAME => {
                    let base = rsp + register as u64 * 8;
                    context.rip = target.read_u64(base)?;
                    context.registers[RSP] = Some(target.read_u64(base + 0x18)?);
                    return Some(());
                }
                _ => {}
            }
            index += slots(code);
        }
        let Some(chained) = info.chained else { break };
        info = read_unwind_info(target, table, chained.unwind)?;
        first = false;
    }
    let rsp = context.rsp();
    context.rip = target.read_u64(rsp)?;
    context.registers[RSP] = Some(rsp + 8);
    Some(())
}

/// Registrador de um `pop` (com ou sem REX.B), se o byte for um.
fn pop_register(code: &[u8], at: usize) -> Option<(usize, usize)> {
    match (code.get(at).copied()?, code.get(at + 1).copied()) {
        (byte @ 0x58..=0x5F, _) => Some(((byte - 0x58) as usize, 1)),
        (0x41, Some(byte @ 0x58..=0x5F)) => Some(((byte - 0x58) as usize + 8, 2)),
        _ => None,
    }
}

/// O RIP está num epílogo (`add rsp`/`lea rsp`, `pop`s e `ret` ou um `jmp`
/// de chamada em cauda): emula as instruções que faltam.
fn unwind_epilog(target: &mut dyn Target, context: &mut Context) -> bool {
    let Ok(code) = target.read(context.rip, 64) else { return false };
    let mut at = 0;
    let mut rsp = context.rsp();
    let mut adjusted = false;
    // add rsp, imm8 / imm32; lea rsp, [rbp + disp8/disp32].
    match code.get(..3) {
        Some([0x48, 0x83, 0xC4]) => {
            rsp = rsp.wrapping_add(code.get(3).copied().unwrap_or(0) as i8 as i64 as u64);
            at = 4;
            adjusted = true;
        }
        Some([0x48, 0x81, 0xC4]) => {
            let Some(bytes) = code.get(3..7) else { return false };
            rsp = rsp.wrapping_add(i32::from_le_bytes(bytes.try_into().unwrap()) as i64 as u64);
            at = 7;
            adjusted = true;
        }
        Some([0x48, 0x8D, 0x65]) => {
            let Some(rbp) = context.rbp() else { return false };
            rsp = rbp.wrapping_add(code.get(3).copied().unwrap_or(0) as i8 as i64 as u64);
            at = 4;
            adjusted = true;
        }
        Some([0x48, 0x8D, 0xA5]) => {
            let (Some(rbp), Some(bytes)) = (context.rbp(), code.get(3..7)) else { return false };
            rsp = rbp.wrapping_add(i32::from_le_bytes(bytes.try_into().unwrap()) as i64 as u64);
            at = 7;
            adjusted = true;
        }
        _ => {}
    }
    let mut pops = Vec::new();
    while let Some((register, length)) = pop_register(&code, at) {
        pops.push(register);
        at += length;
    }
    let terminator = match (code.get(at).copied(), code.get(at + 1).copied(), code.get(at + 2).copied()) {
        (Some(0xC3), _, _) | (Some(0xC2), _, _) | (Some(0xF3), Some(0xC3), _) => true,
        (Some(0xE9), _, _) | (Some(0xFF), Some(0x25), _) | (Some(0x48), Some(0xFF), Some(0x25)) => adjusted || !pops.is_empty(),
        _ => false,
    };
    if !terminator {
        return false;
    }
    let mut registers = context.registers;
    for register in pops {
        let Some(value) = target.read_u64(rsp) else { return false };
        registers[register] = Some(value);
        rsp += 8;
    }
    let Some(rip) = target.read_u64(rsp) else { return false };
    registers[RSP] = Some(rsp + 8);
    context.registers = registers;
    context.rip = rip;
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

    #[test]
    fn unwinds_framed_function() {
        let mut memory = captured_stack();
        let base = 0xffff_8000_0010_0f00u64;
        let frames = unwind(&mut memory, 0xfffff800_4010_0000, base, base + 0x20, 32);
        assert_eq!(addresses(&frames), vec![0xfffff800_4010_0000, 0xfffff800_4012_3456, 0xfffff800_4000_2222, 0xfffff800_4000_1111]);
        assert!(!frames[0].is_return);
        assert!(frames[1..].iter().all(|frame| frame.is_return && frame.method == Method::FramePointer));
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
        assert_eq!(slots(info.codes[1]), 2);
        assert_eq!(info.chained, Some(RuntimeFunction { begin: 0x1000, end: 0x1040, unwind: 0x2000 }));
    }

    /// Um driver (com `.pdata`) chamado pelo kernel (frame pointers) e que
    /// chama o kernel de volta: kernel -> driver!Externa -> driver!Interna
    /// -> kernel (o quadro de cima).
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
        let pdata = [RuntimeFunction { begin: 0x1000, end: 0x1100, unwind: 0x2018 }, RuntimeFunction { begin: 0x1200, end: 0x1300, unwind: 0x2020 }];
        let image = PeImage::parse(crate::pe::tests::tiny_pe(&pdata, &rdata, false)).unwrap();
        let table = Arc::new(FunctionTable { base: driver, functions: image.runtime_functions(), image: Some(Arc::new(image)) });

        // A pilha, de baixo para cima (endereços crescentes).
        let stack_base = 0xffff_8000_0020_0000u64;
        let mut stack = vec![0u8; 0x200];
        let mut put = |offset: u64, value: u64| stack[offset as usize..offset as usize + 8].copy_from_slice(&value.to_le_bytes());
        // Quadro do kernel (frame pointer) chamado pela Interna: RBP do
        // kernel em +0x10 aponta para o RBP salvo, retorno na Interna.
        put(0x10, 0x1234); // RBP salvo (trocado abaixo)
        put(0x18, driver + 0x1050); // retorno na Interna
        // Interna: sub rsp, 0x20 (0x20..0x40), push rbx (0x40), retorno (0x48).
        put(0x40, 0x1111); // rbx salvo
        put(0x48, driver + 0x1280); // retorno na Externa
        // Externa: RSP depois do prólogo = 0x50; sub rsp, 0x30 (0x50..0x80),
        // push rsi (0x80), push rbp (0x88), retorno (0x90). RBP = 0x50+0x20.
        put(0x80, 0x2222); // rsi salvo
        put(0x88, stack_base + 0xc0); // rbp do kernel que chamou
        put(0x90, 0xfffff800_4000_7000); // retorno no kernel
        // Kernel (frame pointer) em 0xc0: RBP salvo 0 e retorno no kmain.
        put(0xc0, 0);
        put(0xc8, 0xfffff800_4000_1000);
        let memory = Captured { regions: vec![(stack_base, stack)] };
        let mut target = Mixed { memory, table };
        // O quadro de cima: kernel, RBP = stack_base + 0x10 (quadro
        // montado), mas o RBP real do kernel... o RSP no kernel.
        let mut context = Context::new(0xfffff800_4000_9000, stack_base, stack_base + 0x10);
        // A Externa usa RBP como registrador de quadro: o valor dela é o RBP
        // do kernel antes de entrar na Interna; o kernel o salvou em [RBP].
        put_rbp(&mut target, stack_base + 0x10, stack_base + 0x70);
        context.registers[3] = Some(0x9999);
        let frames = walk(&mut target, context, false, 16);
        assert_eq!(addresses(&frames), vec![0xfffff800_4000_9000, driver + 0x1050, driver + 0x1280, 0xfffff800_4000_7000, 0xfffff800_4000_1000]);
        assert_eq!(frames[1].method, Method::FramePointer);
        assert_eq!(frames[2].method, Method::Table);
        assert_eq!(frames[3].method, Method::Table);
        assert_eq!(frames[4].method, Method::FramePointer);
        assert_eq!(frames[3].stack, stack_base + 0x98);
    }

    fn put_rbp(target: &mut Mixed, address: u64, value: u64) {
        let (base, stack) = &mut target.memory.regions[0];
        let offset = (address - *base) as usize;
        stack[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn emulates_an_epilog_and_a_leaf() {
        let driver = 0xfffff800_5000_0000u64;
        let pdata = [RuntimeFunction { begin: 0x1000, end: 0x1100, unwind: 0x200c }];
        let image = PeImage::parse(crate::pe::tests::tiny_pe(&pdata, &[0x01, 0x05, 0x02, 0x00, 0x05, 0x32, 0x01, 0x30], false)).unwrap();
        let table = Arc::new(FunctionTable { base: driver, functions: image.runtime_functions(), image: Some(Arc::new(image)) });
        let stack_base = 0xffff_8000_0030_0000u64;
        let mut stack = vec![0u8; 0x100];
        stack[0x20..0x28].copy_from_slice(&0x7777u64.to_le_bytes());
        stack[0x28..0x30].copy_from_slice(&0xfffff800_4000_2000u64.to_le_bytes());
        // Código do epílogo em driver+0x1080: add rsp, 0x20; pop rbx; ret.
        let code = vec![0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3];
        let memory = Captured { regions: vec![(stack_base, stack), (driver + 0x1080, code)] };
        let mut target = Mixed { memory, table };
        let frames = walk(&mut target, Context::new(driver + 0x1080, stack_base, 0), false, 2);
        assert_eq!(addresses(&frames), vec![driver + 0x1080, 0xfffff800_4000_2000]);
        assert_eq!(frames[1].method, Method::Epilog);
        // Fora de qualquer função da `.pdata`: folha, retorno em [RSP].
        let mut context = Context::new(driver + 0x1180, stack_base + 0x28, 0);
        let mut target_leaf = target;
        assert_eq!(step(&mut target_leaf, &mut context, true), Some(Method::Leaf));
        assert_eq!(context.rip, 0xfffff800_4000_2000);
        assert_eq!(context.rsp(), stack_base + 0x30);
    }
}
