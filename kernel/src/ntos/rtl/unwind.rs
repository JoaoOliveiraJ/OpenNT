//! Unwind AMD64.
//!
//! Localiza RUNTIME_FUNCTION e interpreta UNWIND_INFO versões 1 e 2,
//! reconstruindo o CONTEXT do chamador sem executar handlers de exceção ou de
//! término. Registradores inteiros usam valores exatos de 64 bits.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::ntos::mm::loaded_images;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

/// Tabela dinâmica (RtlAddFunctionTable): ponteiro, quantidade e base.
#[derive(Clone, Copy)]
struct DynamicTable {
    pointer: u64,
    count: u32,
    base: u64,
}

static DYNAMIC_TABLES: SpinLock<BTreeMap<u64, DynamicTable>> = SpinLock::new(BTreeMap::new());

fn invalid(message: &str) -> KernelError {
    KernelError::new(message)
}

/// RUNTIME_FUNCTION resolvida.
#[derive(Clone, Copy, Debug)]
pub struct FunctionEntry {
    pub base: u64,
    pub address: u64,
    pub begin: u32,
    pub end: u32,
    pub unwind: u32,
}

/// Três DWORDs: início, fim e metadados; intervalo vazio/invertido ou
/// unwind nulo são recusados.
fn read_function_entry(base: u64, address: u64) -> Result<FunctionEntry, KernelError> {
    let begin = guest::read32(address);
    let end = guest::read32(address + 4);
    let unwind = guest::read32(address + 8);
    if begin >= end || unwind == 0 {
        return Err(invalid("invalid RUNTIME_FUNCTION"));
    }
    Ok(FunctionEntry { base, address, begin, end, unwind })
}

/// Entradas indiretas (bit baixo do RVA de unwind), com detecção de ciclos.
fn follow_indirect_entry(base: u64, mut address: u64) -> Result<FunctionEntry, KernelError> {
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(address) {
            return Err(invalid("cyclic indirect function entry"));
        }
        let entry = read_function_entry(base, address)?;
        if entry.unwind & 1 == 0 {
            return Ok(entry);
        }
        address = base + (entry.unwind - 1) as u64;
    }
}

/// Busca binária nas entradas ordenadas de 12 bytes.
fn search_function_table(base: u64, table: u64, count: u32, instruction: u64) -> Result<Option<FunctionEntry>, KernelError> {
    let Some(relative) = instruction.checked_sub(base).filter(|relative| *relative <= 0xFFFF_FFFF) else { return Ok(None) };
    let (mut lower, mut upper) = (0i64, count as i64 - 1);
    while lower <= upper {
        let index = (lower + upper) / 2;
        let entry = table + index as u64 * 12;
        let begin = guest::read32(entry) as u64;
        let end = guest::read32(entry + 4) as u64;
        if relative < begin {
            upper = index - 1;
        } else if relative >= end {
            lower = index + 1;
        } else {
            return follow_indirect_entry(base, entry).map(Some);
        }
    }
    Ok(None)
}

/// A imagem carregada e seu diretório de exceções, depois as tabelas
/// dinâmicas. Sem entrada: endereço zero com a base encontrada.
pub fn lookup(instruction: u64) -> Result<(u64, Option<FunctionEntry>), KernelError> {
    let mut image_base = 0;
    if let Some(image) = loaded_images::find(instruction) {
        image_base = image.image_base;
        let header_offset = guest::read32(image_base + 0x3C) as u64;
        let header = image_base + header_offset;
        if header_offset > image.size_of_image.saturating_sub(0xA8) || guest::read16(image_base) != 0x5A4D || guest::read32(header) != 0x4550 || guest::read16(header + 24) != 0x20B {
            return Err(invalid("invalid loaded image unwind header"));
        }
        if guest::read32(header + 24 + 108) > 3 {
            let table = guest::read32(header + 24 + 112 + 24) as u64;
            let length = guest::read32(header + 24 + 112 + 28) as u64;
            if table != 0 && length != 0 {
                if length % 12 != 0 || table + length > image.size_of_image {
                    return Err(invalid("invalid loaded image function table"));
                }
                if let Some(entry) = search_function_table(image_base, image_base + table, (length / 12) as u32, instruction)? {
                    return Ok((image_base, Some(entry)));
                }
            }
        }
    }
    let tables: Vec<DynamicTable> = DYNAMIC_TABLES.lock().values().copied().collect();
    for table in tables {
        if let Some(entry) = search_function_table(table.base, table.pointer, table.count, instruction)? {
            return Ok((entry.base, Some(entry)));
        }
    }
    Ok((image_base, None))
}

/// RtlLookupFunctionEntry: publica a base e devolve a entrada (o histórico não é usado).
pub fn lookup_function_entry(instruction: u64, output_image_base: u64, _history: u64) -> Result<u64, KernelError> {
    let (base, entry) = lookup(instruction)?;
    guest::write64(output_image_base, base);
    Ok(entry.map_or(0, |entry| entry.address))
}

/// RtlAddFunctionTable: alinhamento, quantidade, intervalos ordenados e
/// limites validados; o chamador continua dono da memória.
pub fn add_function_table(table: u64, count: u32, base: u64) -> Result<u64, KernelError> {
    if table == 0 || table & 3 != 0 || count == 0 || count > 0x100_0000 || DYNAMIC_TABLES.lock().contains_key(&table) {
        return Ok(0);
    }
    let mut previous_end = 0u32;
    for index in 0..count as u64 {
        let entry = read_function_entry(base, table + index * 12)?;
        if entry.begin < previous_end || base.checked_add(entry.end as u64).is_none() {
            return Ok(0);
        }
        previous_end = entry.end;
    }
    DYNAMIC_TABLES.lock().insert(table, DynamicTable { pointer: table, count, base });
    Ok(1)
}

/// RtlDeleteFunctionTable: remove pelo endereço exato (a memória é do chamador).
pub fn delete_function_table(table: u64) -> u64 {
    DYNAMIC_TABLES.lock().remove(&table).is_some() as u64
}

struct RegisterContext {
    regs: [u64; 16],
    rip: u64,
    xmm: BTreeMap<u64, [u64; 2]>,
    pointers: Vec<(u64, u64)>,
    pointer: u64,
}

fn read_context(pointer: u64) -> RegisterContext {
    let mut regs = [0u64; 16];
    for (index, slot) in regs.iter_mut().enumerate() {
        *slot = guest::read64(pointer + 0x78 + index as u64 * 8);
    }
    RegisterContext { regs, rip: guest::read64(pointer + 0xF8), xmm: BTreeMap::new(), pointers: Vec::new(), pointer }
}

/// Publica inteiros, RIP e só os XMM restaurados.
fn write_context(context: &RegisterContext) {
    for (index, value) in context.regs.iter().enumerate() {
        guest::write64(context.pointer + 0x78 + index as u64 * 8, *value);
    }
    guest::write64(context.pointer + 0xF8, context.rip);
    for (index, value) in &context.xmm {
        guest::write64(context.pointer + 0x1A0 + index * 16, value[0]);
        guest::write64(context.pointer + 0x1A8 + index * 16, value[1]);
    }
}

struct UnwindInformation {
    address: u64,
    version: u8,
    flags: u8,
    prolog: u8,
    count: usize,
    frame: usize,
    frame_offset: u64,
    codes: Vec<u16>,
    tail: u64,
}

/// Versão, flags, prólogo, registrador de frame, slots e a cauda alinhada.
fn read_unwind_information(entry: &FunctionEntry) -> Result<UnwindInformation, KernelError> {
    let address = entry.base + entry.unwind as u64;
    let header = guest::read8(address);
    let version = header & 7;
    let flags = header >> 3;
    if version != 1 && version != 2 {
        return Err(KernelError::new(alloc::format!("unsupported AMD64 unwind version {version}")));
    }
    if flags & 4 != 0 && flags & 3 != 0 {
        return Err(invalid("chained unwind info cannot have a handler"));
    }
    let prolog = guest::read8(address + 1);
    let count = guest::read8(address + 2) as usize;
    let frame_register = guest::read8(address + 3);
    let codes = (0..count as u64).map(|slot| guest::read16(address + 4 + slot * 2)).collect();
    Ok(UnwindInformation { address, version, flags, prolog, count, frame: (frame_register & 15) as usize, frame_offset: (frame_register >> 4) as u64 * 16, codes, tail: address + 4 + (((count + 1) & !1) * 2) as u64 })
}

/// Palavras de 16 bits ocupadas por cada opcode.
fn operation_slot_count(code: u16, information: u16) -> Result<usize, KernelError> {
    Ok(match code {
        0 | 2 | 3 | 10 => 1,
        6 => 2,
        1 => {
            if information > 1 {
                return Err(invalid("invalid large unwind allocation"));
            }
            if information != 0 {
                3
            } else {
                2
            }
        }
        4 | 8 => 2,
        5 | 9 => 3,
        _ => return Err(KernelError::new(alloc::format!("invalid AMD64 unwind operation {code}"))),
    })
}

/// RSP enquanto o frame não foi estabelecido; depois do SET_FPREG (ou fora
/// do prólogo), o registrador de frame menos o offset.
fn find_establisher_frame(context: &RegisterContext, entry: &FunctionEntry, information: &UnwindInformation, instruction: u64) -> Result<u64, KernelError> {
    if information.frame == 0 {
        return Ok(context.regs[4]);
    }
    let relative = instruction.wrapping_sub(entry.base).wrapping_sub(entry.begin as u64);
    let mut established = relative >= information.prolog as u64 || information.flags & 4 != 0;
    if !established {
        let mut slot = 0;
        while slot < information.count {
            let code = information.codes[slot];
            let operation = (code >> 8) & 15;
            if operation == 3 && (code & 255) as u64 <= relative {
                established = true;
                break;
            }
            slot += operation_slot_count(operation, code >> 12)?;
        }
    }
    Ok(if established { context.regs[information.frame].wrapping_sub(information.frame_offset) } else { context.regs[4] })
}

/// v1 admite testar o código; v2 exige um epílogo descrito pelos slots.
fn allows_epilog_decoding(entry: &FunctionEntry, information: &UnwindInformation, instruction: u64) -> bool {
    if information.version == 1 {
        return true;
    }
    let codes = &information.codes;
    if codes.is_empty() || (codes[0] >> 8) & 15 != 6 {
        return false;
    }
    let length = (codes[0] & 255) as u64;
    let end = entry.base + entry.end as u64;
    if (codes[0] >> 12) & 1 != 0 && instruction >= end - length && instruction < end {
        return true;
    }
    let mut index = 1;
    while index < codes.len() && (codes[index] >> 8) & 15 == 6 {
        let distance = ((codes[index] & 255) | ((codes[index] >> 12) << 8)) as u64;
        if distance != 0 && instruction >= end - distance && instruction < end - distance + length {
            return true;
        }
        index += 1;
    }
    false
}

/// Ajuste de pilha, POPs e instrução terminal reconhecidos antes de mudar o
/// contexto; sequência incompleta devolve false (usa os códigos do prólogo).
fn unwind_epilog(context: &mut RegisterContext, entry: &FunctionEntry, information: &UnwindInformation, instruction: u64) -> bool {
    if !allows_epilog_decoding(entry, information, instruction) {
        return false;
    }
    let mut cursor = instruction;
    let mut stack = context.regs[4];
    let mut restored: Vec<(usize, u64)> = Vec::new();
    let end = entry.base + entry.end as u64;
    let start = entry.base + entry.begin as u64;
    let byte = |cursor: u64, offset: u64| -> i32 { if cursor + offset < end { guest::read8(cursor + offset) as i32 } else { -1 } };
    if byte(cursor, 0) == 0x48 && byte(cursor, 1) == 0x83 && byte(cursor, 2) == 0xC4 {
        stack = stack.wrapping_add(byte(cursor, 3) as u8 as i8 as i64 as u64);
        cursor += 4;
    } else if byte(cursor, 0) == 0x48 && byte(cursor, 1) == 0x81 && byte(cursor, 2) == 0xC4 && cursor + 7 <= end {
        stack = stack.wrapping_add(guest::read32(cursor + 3) as i32 as i64 as u64);
        cursor += 7;
    } else if byte(cursor, 0) & 0xF8 == 0x48 && byte(cursor, 1) == 0x8D && byte(cursor, 2) & 0x38 == 0x20 {
        // LEA RSP: REX estende o registrador; ModR/M e SIB dão base e deslocamento.
        let rex = byte(cursor, 0);
        let modrm = byte(cursor, 2);
        let mode = modrm >> 6;
        let mut register = ((modrm & 7) | ((rex & 1) << 3)) as usize;
        let mut length = 3u64;
        if modrm & 7 == 4 {
            if byte(cursor, 3) != 0x24 {
                return false;
            }
            length += 1;
            register = (4 | ((rex & 1) << 3)) as usize;
        }
        if information.frame == 0 || register != information.frame || (mode != 1 && mode != 2) {
            return false;
        }
        let displacement_length = if mode == 1 { 1 } else { 4 };
        if cursor + length + displacement_length > end {
            return false;
        }
        let displacement = if mode == 1 { byte(cursor, length) as u8 as i8 as i64 } else { guest::read32(cursor + length) as i32 as i64 };
        stack = context.regs[register].wrapping_add(displacement as u64);
        cursor += length + displacement_length;
    }
    // Até 16 POPs; POP RSP invalida o caminho.
    for _ in 0..16 {
        let mut rex = 0;
        let mut opcode = byte(cursor, 0);
        let mut length = 1;
        if (0x40..=0x4F).contains(&opcode) {
            rex = opcode;
            opcode = byte(cursor, 1);
            length += 1;
        }
        if !(0x58..=0x5F).contains(&opcode) {
            break;
        }
        let register = (opcode - 0x58 + ((rex & 1) << 3)) as usize;
        if register == 4 {
            return false;
        }
        restored.push((register, stack));
        stack = stack.wrapping_add(8);
        cursor += length;
    }
    // RET, RET n e saltos permitidos encerram o epílogo (v1: salto para fora).
    let mut valid = byte(cursor, 0) == 0xC3 || (byte(cursor, 0) == 0xF3 && byte(cursor, 1) == 0xC3);
    let mut cleanup = 0u64;
    if byte(cursor, 0) == 0xC2 && cursor + 3 <= end {
        valid = true;
        cleanup = guest::read16(cursor + 1) as u64;
    }
    if byte(cursor, 0) == 0xE9 && cursor + 5 <= end {
        let target = (cursor + 5).wrapping_add(guest::read32(cursor + 1) as i32 as i64 as u64);
        valid = information.version == 2 || target < start || target >= end;
    } else if byte(cursor, 0) == 0xEB && cursor + 2 <= end {
        let target = (cursor + 2).wrapping_add(byte(cursor, 1) as u8 as i8 as i64 as u64);
        valid = information.version == 2 || target < start || target >= end;
    } else {
        let prefix = if (0x40..=0x4F).contains(&byte(cursor, 0)) { 1 } else { 0 };
        let modrm = byte(cursor, prefix + 1);
        if byte(cursor, prefix) == 0xFF && modrm & 0x38 == 0x20 && (modrm >> 6 == 0 || (prefix != 0 && byte(cursor, 0) & 8 != 0 && modrm >> 6 == 3)) {
            valid = true;
        }
    }
    if !valid {
        return false;
    }
    for (register, saved) in restored {
        context.regs[register] = guest::read64(saved);
        context.pointers.push((128 + register as u64 * 8, saved));
    }
    context.rip = guest::read64(stack);
    context.regs[4] = stack.wrapping_add(8).wrapping_add(cleanup);
    true
}

/// RtlVirtualUnwind: epílogo ou códigos e encadeamentos; publica CONTEXT,
/// establisher frame e ponteiros opcionais e devolve o handler elegível
/// (sem executá-lo).
#[allow(clippy::too_many_arguments)]
pub fn unwind(handler_type: u32, image_base: u64, instruction: u64, function_entry: u64, context_pointer: u64, output_handler_data: u64, output_frame: u64, output_context_pointers: u64) -> Result<u64, KernelError> {
    let mut entry = follow_indirect_entry(image_base, function_entry)?;
    let mut information = read_unwind_information(&entry)?;
    let mut context = read_context(context_pointer);
    let establisher = find_establisher_frame(&context, &entry, &information, instruction)?;
    let mut handler = 0u64;
    let mut handler_data = 0u64;
    let mut machine_frame = false;
    if !unwind_epilog(&mut context, &entry, &information, instruction) {
        let mut visited = BTreeSet::new();
        loop {
            if !visited.insert(information.address) {
                return Err(invalid("cyclic chained unwind data"));
            }
            let relative = instruction.wrapping_sub(entry.base).wrapping_sub(entry.begin as u64);
            let inside_prolog = relative < information.prolog as u64;
            let mut slot = 0;
            while slot < information.count {
                let code = information.codes[slot];
                let operation = (code >> 8) & 15;
                let operation_information = code >> 12;
                let consumed = operation_slot_count(operation, operation_information)?;
                if slot + consumed > information.count {
                    return Err(invalid("truncated AMD64 unwind code"));
                }
                let first = information.codes.get(slot + 1).copied().unwrap_or(0) as u64;
                let second = information.codes.get(slot + 2).copied().unwrap_or(0) as u64;
                slot += consumed;
                if operation == 6 {
                    if information.version != 2 {
                        return Err(invalid("v1 epilog opcode"));
                    }
                    continue;
                }
                // No meio do prólogo só as operações já executadas são desfeitas.
                if inside_prolog && (code & 255) as u64 > relative {
                    continue;
                }
                let register = operation_information as usize;
                match operation {
                    0 => {
                        let saved = context.regs[4];
                        context.regs[register] = guest::read64(saved);
                        context.regs[4] = saved.wrapping_add(8);
                        context.pointers.push((128 + register as u64 * 8, saved));
                    }
                    1 => context.regs[4] = context.regs[4].wrapping_add(if operation_information != 0 { first + second * 65536 } else { first * 8 }),
                    2 => context.regs[4] = context.regs[4].wrapping_add(operation_information as u64 * 8 + 8),
                    3 => context.regs[4] = context.regs[information.frame].wrapping_sub(information.frame_offset),
                    4 | 5 => {
                        let saved = establisher.wrapping_add(if operation == 4 { first * 8 } else { first + second * 65536 });
                        context.regs[register] = guest::read64(saved);
                        // O FAR restaura sem publicar o ponteiro opcional (como na 19041).
                        if operation == 4 {
                            context.pointers.push((128 + register as u64 * 8, saved));
                        }
                    }
                    8 | 9 => {
                        let saved = establisher.wrapping_add(if operation == 8 { first * 16 } else { first + second * 65536 });
                        context.xmm.insert(register as u64, [guest::read64(saved), guest::read64(saved + 8)]);
                        context.pointers.push((register as u64 * 8, saved));
                    }
                    10 => {
                        if operation_information > 1 {
                            return Err(invalid("invalid machine-frame unwind"));
                        }
                        let saved = context.regs[4] + operation_information as u64 * 8;
                        context.rip = guest::read64(saved);
                        context.regs[4] = guest::read64(saved + 24);
                        machine_frame = true;
                    }
                    _ => {}
                }
            }
            if information.flags & 4 != 0 {
                entry = read_function_entry(image_base, information.tail)?;
                information = read_unwind_information(&entry)?;
                continue;
            }
            if !inside_prolog && (information.flags as u32) & handler_type & 3 != 0 {
                handler = image_base + guest::read32(information.tail) as u64;
                handler_data = information.tail + 4;
            }
            break;
        }
        // Sem machine frame o retorno vem do topo reconstruído.
        if !machine_frame {
            context.rip = guest::read64(context.regs[4]);
            context.regs[4] = context.regs[4].wrapping_add(8);
        }
    }
    write_context(&context);
    guest::write64(output_frame, establisher);
    if handler != 0 {
        guest::write64(output_handler_data, handler_data);
    }
    if output_context_pointers != 0 {
        for (offset, saved) in &context.pointers {
            guest::write64(output_context_pointers + offset, *saved);
        }
    }
    Ok(handler)
}
