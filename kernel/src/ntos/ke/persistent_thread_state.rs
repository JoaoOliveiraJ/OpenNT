//! KeCapturePersistentThreadState — `system32/ntos/ke/persistent-thread-state.js`.
//!
//! Triage dump x64 de 256 KiB com o layout, o tamanho devolvido e a ordem de
//! cópia do ntoskrnl 19041. A captura não causa bugcheck nem executa
//! callbacks de crash.

use super::{debugger_data, dump_memory, irql, pcr, smp};
use crate::ntos::mm::loaded_images;
use crate::ntos::ps::process;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{eprocess, kthread};

pub const DUMP_BYTE_LENGTH: usize = 0x40000;
const TRAILER_OFFSET: usize = DUMP_BYTE_LENGTH - 4;
const CONTEXT_OFFSET: usize = 0x348;
const CONTEXT_BYTE_LENGTH: usize = 0x4D0;
const SHARED_DATA: u64 = 0xFFFF_F780_0000_0000;
const PROCESSOR_BYTE_LENGTH: usize = 0xAF00;
const MODULE_ENTRY_BYTE_LENGTH: usize = 0x90;

/// Montado no boot, antes de consumidores em IRQL alto: o dump usa o
/// armazenamento já reservado e a lista nativa mantida pelo loader.
pub fn init() -> Result<(), KernelError> {
    debugger_data::initialize()?;
    loaded_images::native_list()?;
    Ok(())
}

/// High1/Low/High2 rejeitam uma atualização interrompida entre as metades.
fn shared_time(offset: u64) -> u64 {
    let address = SHARED_DATA + offset;
    loop {
        let high = guest::read32(address + 4);
        let low = guest::read32(address);
        if high == guest::read32(address + 8) {
            return (high as u64) << 32 | low as u64;
        }
    }
}

fn align8(value: usize) -> usize {
    value.div_ceil(8) * 8
}

struct Dump(alloc::vec::Vec<u8>);

impl Dump {
    fn u16(&mut self, at: usize, value: u64) {
        self.0[at..at + 2].copy_from_slice(&(value as u16).to_le_bytes());
    }
    fn u32(&mut self, at: usize, value: u64) {
        self.0[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
    }
    fn u64(&mut self, at: usize, value: u64) {
        self.0[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn get32(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.0[at..at + 4].try_into().unwrap())
    }
    fn get64(&self, at: usize) -> u64 {
        u64::from_le_bytes(self.0[at..at + 8].try_into().unwrap())
    }
    fn set(&mut self, at: usize, bytes: &[u8]) {
        self.0[at..at + bytes.len()].copy_from_slice(bytes);
    }
}

/// Saída NULL é a recusa explícita do contrato nativo (devolve 0).
#[allow(clippy::too_many_arguments)]
pub fn capture(context: u64, thread: u64, bugcheck_code: u32, first: u64, second: u64, third: u64, fourth: u64, output: u64) -> Result<u64, KernelError> {
    if output == 0 {
        return Ok(0);
    }
    let thread = if thread != 0 { thread } else { process::get_current_thread() };
    let process_address = guest::read64(thread + kthread::APC_STATE_PROCESS);
    let processor = guest::read64(pcr::get_pcr_address() + pcr::layout::CURRENT_PRCB);
    // A saída é limpa antes de ler o CONTEXT (que pode estar no próprio buffer).
    let mut dump = Dump(alloc::vec![0u8; DUMP_BYTE_LENGTH]);
    for offset in (0..0x2000).step_by(4) {
        dump.u32(offset, 0x4547_4150);
    }
    dump.u32(4, 0x3436_5544);
    dump_memory::write(output, &dump.0)?;
    let (module_head, modules) = loaded_images::native_list()?;
    let debugger = debugger_data::snapshot(module_head)?;
    dump.u32(8, 0xF);
    dump.u32(0xC, (guest::read32(SHARED_DATA + 0x260) & 0xFFFF) as u64);
    dump.u64(0x10, guest::read64(process_address + eprocess::DIRECTORY_TABLE_BASE) & !0xFFF);
    dump.u64(0x18, debugger.pfn_database);
    dump.u64(0x20, module_head);
    dump.u64(0x28, process::get_active_process_head());
    dump.u32(0x30, 0x8664);
    dump.u32(0x34, smp::online_cpu_count() as u64);
    dump.u32(0x38, bugcheck_code as u64);
    for (index, value) in [first, second, third, fourth].into_iter().enumerate() {
        dump.u64(0x40 + index * 8, value);
    }
    dump.u32(0xF00, 0x8000_0003);
    dump.u32(0xF04, 1);
    dump.u64(0xF08, 0);
    dump.u64(0xF10, guest::read64(context + 0xF8));
    dump.u32(0xF18, 0);
    dump.u32(0xF98, 4);
    dump.u64(0xFA0, DUMP_BYTE_LENGTH as u64);
    dump.u64(0xFA8, shared_time(0x14));
    dump.u64(0x1030, shared_time(8));
    dump.u32(0x1040, guest::read32(SHARED_DATA + 0x264) as u64);
    dump.u32(0x1044, guest::read32(SHARED_DATA + 0x2D0) as u64);
    dump.u32(0x1050, 0x18);
    dump.u32(0x1054, guest::read32(SHARED_DATA + 0x2C4) as u64);
    dump.u32(0x2000, 0);
    dump.u32(0x2004, DUMP_BYTE_LENGTH as u64);
    dump.u32(0x2008, TRAILER_OFFSET as u64);
    dump.u32(0x200C, CONTEXT_OFFSET as u64);
    dump.u32(0x2010, 0xF00);
    let mut flags = 0x83u64;
    // Publica o cabeçalho primeiro: aliases do contexto enxergam as gravações.
    dump.u32(0x1038, flags);
    dump_memory::write(output, &dump.0[..0x2080])?;
    for offset in (0..CONTEXT_BYTE_LENGTH).step_by(16) {
        let chunk = dump_memory::read(context + offset as u64, 16)?;
        dump.set(CONTEXT_OFFSET + offset, &chunk);
        dump_memory::write(output + (CONTEXT_OFFSET + offset) as u64, &chunk)?;
    }
    dump.set(0x2080, &debugger.bytes);
    dump.u64(0x80, debugger.address);
    dump.u32(0x2070, 0x2080);
    dump.u32(0x2074, debugger.bytes.len() as u64);
    flags |= 0x400;
    // Registros reais da CPU, processo e thread.
    let mut cursor = 0x2080 + debugger.bytes.len();
    for (source, length, header, flag) in [(processor, PROCESSOR_BYTE_LENGTH, 0x201C, 4u64), (process_address, eprocess::SIZE as usize, 0x2020, 8), (thread, kthread::SIZE as usize, 0x2024, 16)] {
        cursor = align8(cursor);
        if cursor + length >= TRAILER_OFFSET {
            return Err(KernelError::new("fixed triage records exceed dump"));
        }
        let bytes = dump_memory::read(source, length)?;
        dump.set(cursor, &bytes);
        dump.u32(header, cursor as u64);
        flags |= flag;
        cursor += length;
    }
    // StackResident controla a cópia do prefixo mapeado da pilha.
    if guest::read32(thread + 0x78) & 0x2_0000 != 0 {
        let limit = guest::read64(thread + 0x30);
        let base = guest::read64(thread + 0x38);
        let mut stack = dump.get64(CONTEXT_OFFSET + 0x98);
        if stack < limit || stack >= base {
            stack = limit;
        }
        let requested = if base > stack { (base - stack).min(0x7FFF) } else { 0 };
        let readable = dump_memory::readable_length(stack, requested, false) as usize;
        let copied = readable.min(TRAILER_OFFSET - cursor);
        if copied != 0 {
            let bytes = dump_memory::read(stack, copied)?;
            dump.set(cursor, &bytes);
            dump.u32(0x2028, cursor as u64);
            dump.u32(0x202C, copied as u64);
            dump.u64(0x2048, stack);
            flags |= 0x20;
            if copied < readable {
                dump.u32(0x2044, 0x100);
            }
            cursor += copied;
        }
    }
    // Em DISPATCH_LEVEL ou acima a rotina nativa não percorre os módulos.
    if irql::get_irql() < 2 && !modules.is_empty() {
        let module_offset = align8(cursor);
        let names_offset = module_offset + modules.len() * MODULE_ENTRY_BYTE_LENGTH;
        let names_length = align8(modules.iter().map(|(image, _)| image.name.encode_utf16().count() * 2 + 15).sum());
        if names_offset + names_length < TRAILER_OFFSET {
            let mut name_cursor = names_offset;
            for (index, (image, pointer)) in modules.iter().enumerate() {
                let record = module_offset + index * MODULE_ENTRY_BYTE_LENGTH;
                dump.u32(record, name_cursor as u64);
                let entry = dump_memory::read(*pointer, 0x88)?;
                dump.set(record + 8, &entry);
                dump.u32(record + 0x48, image.size_of_image);
                dump.u32(record + 0x88, image.time_date_stamp as u64);
                let units: alloc::vec::Vec<u16> = image.name.encode_utf16().collect();
                dump.u32(name_cursor, units.len() as u64);
                for (unit_index, unit) in units.iter().enumerate() {
                    dump.u16(name_cursor + 4 + unit_index * 2, *unit as u64);
                }
                name_cursor = align8(name_cursor + 6 + units.len() * 2);
            }
            dump.u32(0x2030, module_offset as u64);
            dump.u32(0x2034, modules.len() as u64);
            dump.u32(0x2038, names_offset as u64);
            dump.u32(0x203C, names_length as u64);
            flags |= 0x40;
            cursor = names_offset + names_length;
        } else {
            let previous = dump.get32(0x2044) as u64;
            dump.u32(0x2044, previous | 0x100);
        }
    }
    // Até uma página de código ao redor de RIP, sem ler páginas ausentes.
    cursor = align8(cursor);
    let capacity = 0x1010.min(TRAILER_OFFSET - cursor) as i64 - 16;
    if capacity > 0 {
        let instruction = dump.get64(CONTEXT_OFFSET + 0xF8);
        let previous = dump_memory::readable_length(instruction, ((capacity / 2) as u64).min(instruction.min(2048)), true);
        if previous != 0 {
            let code = instruction - previous + 1;
            let length = dump_memory::readable_length(code, capacity as u64, false) as usize;
            if length != 0 {
                let code_offset = align8(cursor + 16);
                dump.u64(cursor, code);
                dump.u32(cursor + 8, code_offset as u64);
                dump.u32(cursor + 12, length as u64);
                let bytes = dump_memory::read(code, length)?;
                dump.set(code_offset, &bytes);
                dump.u32(0x2078, cursor as u64);
                dump.u32(0x207C, 1);
                flags |= 0x800;
            }
        }
    }
    dump.u32(0x1038, flags);
    dump.u32(TRAILER_OFFSET, 0x4447_5254);
    dump_memory::write(output, &dump.0)?;
    Ok(DUMP_BYTE_LENGTH as u64)
}
