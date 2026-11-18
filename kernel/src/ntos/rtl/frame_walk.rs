//! Desenrolamento de diagnóstico da pilha x64.
//!
//! Cada quadro sai da .pdata (RUNTIME_FUNCTION/UNWIND_INFO) da imagem que
//! contém o RIP, como no RtlVirtualUnwind, mas sem epílogos nem handlers; um
//! quadro sem RUNTIME_FUNCTION é o de uma função folha (o retorno no topo da
//! pilha), salvo quando quem lê a memória sabe outra regra
//! ([`Images::frameless`]). Toda leitura passa pelo leitor de quem chama
//! ([`Memory`]), que recusa em vez de faltar, e nada aqui aloca nem toma
//! trava: o diagnóstico de falhas de processos (`ps::user::crash_report`,
//! memória de usuário sondada) e o das paradas do kernel
//! (`ke::bugcheck_trace`, em qualquer IRQL) usam o mesmo desenrolamento.

use core::mem::{offset_of, size_of};

use crate::ntos::inc::types::{ImageDataDirectory, ImageDosHeader, ImageNtHeaders64, ImageRuntimeFunctionEntry, NtStruct, UnwindInfo};
use crate::ntos::mm::guest_memory::GuestScalar;

/// Leitura que devolve `None` para o que não pode ser lido sem falta.
pub trait Memory {
    fn read<T: GuestScalar>(&mut self, address: u64) -> Option<T>;
}

/// Memória com as imagens carregadas.
pub trait Images: Memory + Sized {
    /// A imagem (base, tamanho) que contém `address`.
    fn image(&mut self, address: u64) -> Option<(u64, u64)>;

    /// O quadro de `pc` não tem RUNTIME_FUNCTION: o padrão é o de função
    /// folha, com o retorno no topo da pilha.
    fn frameless(&mut self, _pc: u64, registers: &mut Registers) -> Option<()> {
        pop_return(self, registers)
    }
}

/// Rsp e Rbp no vetor de inteiros (a ordem dos números de registrador do x64).
pub const RSP: usize = 4;
pub const RBP: usize = 5;

/// Rax..R15 na ordem dos números de registrador do x64, e o Rip.
#[derive(Clone, Copy)]
pub struct Registers {
    pub integer: [u64; 16],
    pub rip: u64,
}

/// IMAGE_DIRECTORY_ENTRY_EXCEPTION.
const EXCEPTION_DIRECTORY: usize = 3;
/// UNW_FLAG_CHAININFO e os códigos UWOP_* do UNWIND_CODE.
const UNW_FLAG_CHAININFO: u8 = 4;
const UWOP_PUSH_NONVOL: u16 = 0;
const UWOP_ALLOC_LARGE: u16 = 1;
const UWOP_ALLOC_SMALL: u16 = 2;
const UWOP_SET_FPREG: u16 = 3;
const UWOP_SAVE_NONVOL: u16 = 4;
const UWOP_SAVE_NONVOL_FAR: u16 = 5;
const UWOP_EPILOG: u16 = 6;
const UWOP_SPARE_CODE: u16 = 7;
const UWOP_PUSH_MACHFRAME: u16 = 10;
/// Entradas encadeadas e indiretas seguidas por quadro.
const MAX_CHAIN: usize = 8;

// ---- cabeçalhos da imagem --------------------------------------------------------

/// Os cabeçalhos NT de uma imagem mapeada (MZ e PE conferidos).
pub fn nt_headers(memory: &mut impl Memory, base: u64) -> Option<u64> {
    if memory.read::<u16>(base + offset_of!(ImageDosHeader, e_magic) as u64)? != 0x5A4D {
        return None;
    }
    let header = base + memory.read::<u32>(base + offset_of!(ImageDosHeader, e_lfanew) as u64)? as u64;
    (memory.read::<u32>(header + offset_of!(ImageNtHeaders64, signature) as u64)? == 0x4550).then_some(header)
}

/// Um IMAGE_DATA_DIRECTORY (RVA, tamanho) dos cabeçalhos NT.
pub fn data_directory(memory: &mut impl Memory, header: u64, index: usize) -> Option<(u32, u32)> {
    if memory.read::<u32>(header + offset_of!(ImageNtHeaders64, optional_header.number_of_rva_and_sizes) as u64)? as usize <= index {
        return None;
    }
    let entry = header + (offset_of!(ImageNtHeaders64, optional_header.data_directory) + index * size_of::<ImageDataDirectory>()) as u64;
    Some((memory.read::<u32>(entry + offset_of!(ImageDataDirectory, virtual_address) as u64)?, memory.read::<u32>(entry + offset_of!(ImageDataDirectory, size) as u64)?))
}

// ---- RUNTIME_FUNCTION e UNWIND_INFO ------------------------------------------------

/// Uma RUNTIME_FUNCTION da imagem em `base` (RVAs).
#[derive(Clone, Copy)]
struct FunctionEntry {
    begin: u32,
    end: u32,
    unwind: u32,
}

fn read_function(memory: &mut impl Memory, address: u64) -> Option<FunctionEntry> {
    Some(FunctionEntry {
        begin: memory.read::<u32>(address + offset_of!(ImageRuntimeFunctionEntry, begin_address) as u64)?,
        end: memory.read::<u32>(address + offset_of!(ImageRuntimeFunctionEntry, end_address) as u64)?,
        unwind: memory.read::<u32>(address + offset_of!(ImageRuntimeFunctionEntry, unwind_info_address) as u64)?,
    })
}

/// Busca binária na .pdata da imagem, seguindo as entradas indiretas.
fn function_entry(memory: &mut impl Memory, base: u64, size: u64, pc: u64) -> Option<FunctionEntry> {
    let header = nt_headers(memory, base)?;
    let (table, length) = data_directory(memory, header, EXCEPTION_DIRECTORY)?;
    let entry_size = ImageRuntimeFunctionEntry::SIZE;
    if table == 0 || length as u64 % entry_size != 0 || table as u64 + length as u64 > size {
        return None;
    }
    let relative = pc - base;
    let (mut lower, mut upper) = (0i64, (length as u64 / entry_size) as i64 - 1);
    while lower <= upper {
        let index = (lower + upper) / 2;
        let mut function = read_function(memory, base + table as u64 + index as u64 * entry_size)?;
        if relative < function.begin as u64 {
            upper = index - 1;
        } else if relative >= function.end as u64 {
            lower = index + 1;
        } else {
            for _ in 0..MAX_CHAIN {
                if function.unwind & 1 == 0 {
                    return Some(function);
                }
                function = read_function(memory, base + (function.unwind - 1) as u64)?;
            }
            return None;
        }
    }
    None
}

/// Um UNWIND_INFO lido da imagem (CountOfCodes cabe num byte).
struct UnwindData {
    flags: u8,
    prolog: u8,
    frame: usize,
    frame_offset: u64,
    count: usize,
    codes: [u16; 256],
    /// Depois dos códigos (em número par): a RUNTIME_FUNCTION encadeada.
    tail: u64,
}

/// Slots de 16 bits de cada código (o RtlpUnwindOpSlotTable).
fn slot_count(operation: u16, information: u16) -> Option<usize> {
    Some(match operation {
        UWOP_PUSH_NONVOL | UWOP_ALLOC_SMALL | UWOP_SET_FPREG | UWOP_PUSH_MACHFRAME => 1,
        UWOP_ALLOC_LARGE => {
            if information == 0 {
                2
            } else {
                3
            }
        }
        UWOP_SAVE_NONVOL | UWOP_EPILOG | 8 => 2,
        UWOP_SAVE_NONVOL_FAR | UWOP_SPARE_CODE | 9 => 3,
        _ => return None,
    })
}

impl UnwindData {
    fn read(memory: &mut impl Memory, address: u64) -> Option<Self> {
        let header = memory.read::<u8>(address + offset_of!(UnwindInfo, bitfield_0) as u64)?;
        let version = (header & UnwindInfo::VERSION_MASK) >> UnwindInfo::VERSION_SHIFT;
        if version != 1 && version != 2 {
            return None;
        }
        let prolog = memory.read::<u8>(address + offset_of!(UnwindInfo, size_of_prolog) as u64)?;
        let count = memory.read::<u8>(address + offset_of!(UnwindInfo, count_of_codes) as u64)? as usize;
        let frame = memory.read::<u8>(address + offset_of!(UnwindInfo, bitfield_3) as u64)?;
        let first = address + offset_of!(UnwindInfo, unwind_code) as u64;
        let mut codes = [0u16; 256];
        for (index, code) in codes.iter_mut().take(count).enumerate() {
            *code = memory.read::<u16>(first + index as u64 * 2)?;
        }
        Some(Self {
            flags: (header & UnwindInfo::FLAGS_MASK) >> UnwindInfo::FLAGS_SHIFT,
            prolog,
            frame: ((frame & UnwindInfo::FRAME_REGISTER_MASK) >> UnwindInfo::FRAME_REGISTER_SHIFT) as usize,
            frame_offset: ((frame & UnwindInfo::FRAME_OFFSET_MASK) >> UnwindInfo::FRAME_OFFSET_SHIFT) as u64 * 16,
            count,
            codes,
            tail: first + (((count + 1) & !1) * 2) as u64,
        })
    }

    fn codes(&self) -> &[u16] {
        &self.codes[..self.count]
    }

    /// O establisher frame: RSP antes do SET_FPREG, depois o registrador de
    /// frame menos o deslocamento.
    fn establisher(&self, registers: &Registers, relative: u64) -> u64 {
        if self.frame == 0 {
            return registers.integer[RSP];
        }
        let codes = self.codes();
        let mut established = relative >= self.prolog as u64 || self.flags & UNW_FLAG_CHAININFO != 0;
        let mut slot = 0;
        while !established && slot < codes.len() {
            let code = codes[slot];
            let operation = (code >> 8) & 0xF;
            established = operation == UWOP_SET_FPREG && (code & 0xFF) as u64 <= relative;
            let Some(slots) = slot_count(operation, code >> 12) else { break };
            slot += slots;
        }
        if established { registers.integer[self.frame].wrapping_sub(self.frame_offset) } else { registers.integer[RSP] }
    }
}

// ---- desenrolamento ------------------------------------------------------------

/// O retorno no topo da pilha (função folha ou fim do desenrolamento).
pub fn pop_return(memory: &mut impl Memory, registers: &mut Registers) -> Option<()> {
    let rsp = registers.integer[RSP];
    registers.rip = memory.read::<u64>(rsp)?;
    registers.integer[RSP] = rsp.wrapping_add(8);
    Some(())
}

/// Desfaz um quadro pelos códigos de unwind (sem epílogos nem handlers): os
/// inteiros e o RIP do chamador. `first`: o RIP é o da falha, não um retorno.
pub fn unwind_frame<M: Images>(memory: &mut M, registers: &mut Registers, first: bool) -> Option<()> {
    let pc = if first { registers.rip } else { registers.rip.wrapping_sub(1) };
    let image = memory.image(pc);
    let Some((base, mut entry)) = image.and_then(|(base, size)| function_entry(memory, base, size, pc).map(|entry| (base, entry))) else {
        return memory.frameless(pc, registers);
    };
    let mut machine_frame = false;
    let mut establisher_frame = None;
    for _ in 0..MAX_CHAIN {
        let info = UnwindData::read(memory, base + entry.unwind as u64)?;
        let relative = pc.wrapping_sub(base + entry.begin as u64);
        let establisher = *establisher_frame.get_or_insert_with(|| info.establisher(registers, relative));
        let inside_prolog = relative < info.prolog as u64;
        let codes = info.codes();
        let mut slot = 0;
        while slot < codes.len() {
            let code = codes[slot];
            let operation = (code >> 8) & 0xF;
            let register = (code >> 12) as usize;
            let slots = slot_count(operation, code >> 12)?;
            if slot + slots > codes.len() {
                return None;
            }
            let word = |offset: usize| codes.get(slot + offset).copied().unwrap_or(0) as u64;
            let (first_word, second_word) = (word(1), word(2));
            slot += slots;
            // No meio do prólogo só as operações já executadas são desfeitas.
            if operation == UWOP_EPILOG || operation == UWOP_SPARE_CODE || (inside_prolog && (code & 0xFF) as u64 > relative) {
                continue;
            }
            let rsp = registers.integer[RSP];
            match operation {
                UWOP_PUSH_NONVOL => {
                    registers.integer[register] = memory.read::<u64>(rsp)?;
                    registers.integer[RSP] = rsp.wrapping_add(8);
                }
                UWOP_ALLOC_LARGE => registers.integer[RSP] = rsp.wrapping_add(if register != 0 { first_word | second_word << 16 } else { first_word * 8 }),
                UWOP_ALLOC_SMALL => registers.integer[RSP] = rsp.wrapping_add(register as u64 * 8 + 8),
                UWOP_SET_FPREG => registers.integer[RSP] = registers.integer[info.frame].wrapping_sub(info.frame_offset),
                UWOP_SAVE_NONVOL => registers.integer[register] = memory.read::<u64>(establisher.wrapping_add(first_word * 8))?,
                UWOP_SAVE_NONVOL_FAR => registers.integer[register] = memory.read::<u64>(establisher.wrapping_add(first_word | second_word << 16))?,
                UWOP_PUSH_MACHFRAME => {
                    let frame = rsp.wrapping_add(register as u64 * 8);
                    registers.rip = memory.read::<u64>(frame)?;
                    registers.integer[RSP] = memory.read::<u64>(frame + 24)?;
                    machine_frame = true;
                }
                // Os XMM salvos não mudam a pilha.
                _ => {}
            }
        }
        if info.flags & UNW_FLAG_CHAININFO == 0 {
            break;
        }
        entry = read_function(memory, info.tail)?;
    }
    if machine_frame { Some(()) } else { pop_return(memory, registers) }
}
