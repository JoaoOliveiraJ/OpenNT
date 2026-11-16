//! Vetores de dados do triage dump: KeInitializeTriageDumpDataArray e
//! KeAddTriageDumpDataBlock.
//!
//! O KTRIAGE_DUMP_DATA_ARRAY é memória do chamador (um callback
//! KbCallbackTriageDumpData monta o vetor e o bugcheck copia os blocos para o
//! triage dump). Como no ntoskrnl 19041:
//! - a inicialização exige 0x40 bytes (cabeçalho e um bloco), calcula
//!   NumBlocksTotal = (Size - 0x30) / 16, liga a lista a si mesma, zera os
//!   contadores e o nome do componente e limita os dados a 32 MiB
//!   (MaxDataSize 0x2000000);
//! - acrescentar valida o vetor inteiro (o KiValidateTriageDumpDataArray:
//!   cabeçalho e blocos residentes, lista íntegra, NumBlocksUsed dentro do
//!   total, a soma dos tamanhos igual a DataSize e dentro do máximo) e a faixa
//!   pedida (o IopIsAddressRangeValid: toda página residente e acima dos
//!   primeiros 64 KiB); um bloco vazio é aceito sem mudar nada; a faixa nova é
//!   aparada contra os blocos que ela sobrepõe pela ponta (contida num bloco,
//!   não acrescenta nada); sem bloco livre é STATUS_BUFFER_TOO_SMALL e sem
//!   espaço no limite de dados, STATUS_INSUFFICIENT_RESOURCES.

use crate::ntos::inc::types::extra_ke_misc::{KaddressRange, KtriageDumpDataArray};
use crate::ntos::inc::types::{ListEntry, NtStruct};
use crate::ntos::mm::small;
use crate::rtl::KernelError;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// Cabeçalho até Blocks e o limite de dados de um vetor novo.
const HEADER_SIZE: u32 = 0x30;
const MAXIMUM_DATA_SIZE: u32 = 0x200_0000;

/// IopIsAddressRangeValid: cada página da faixa residente e fora dos
/// primeiros 64 KiB; faixa vazia é válida.
fn range_valid(address: u64, size: u64) -> Result<bool, KernelError> {
    let pages = ((address & 0xFFF).wrapping_add(size).wrapping_add(0xFFF)) >> 12;
    let mut page = address & !0xFFF;
    for _ in 0..pages {
        if page < 0x1_0000 || !small::is_address_valid(page)? {
            return Ok(false);
        }
        page = page.wrapping_add(0x1000);
    }
    Ok(true)
}

fn blocks(array: &KtriageDumpDataArray, count: u32) -> &'static [KaddressRange] {
    // SAFETY: o vetor do chamador tem NumBlocksTotal entradas, conferidas
    // residentes por `validate`.
    unsafe { KaddressRange::array_at(array.blocks[0].address(), count as usize) }
}

/// KiValidateTriageDumpDataArray(Array, 0).
fn validate(array: u64) -> Result<bool, KernelError> {
    if !range_valid(array, HEADER_SIZE as u64)? {
        return Ok(false);
    }
    // SAFETY: cabeçalho residente conferido acima.
    let header = unsafe { KtriageDumpDataArray::at(array) };
    let (used, total) = (header.num_blocks_used.get(), header.num_blocks_total.get());
    if used > total {
        return Ok(false);
    }
    let bytes = (total as u64) << 4;
    if bytes > u32::MAX as u64 || (bytes as u32).checked_add(HEADER_SIZE).is_none() || !range_valid(array + HEADER_SIZE as u64, bytes)? {
        return Ok(false);
    }
    let (flink, blink) = (header.list.flink.get(), header.list.blink.get());
    if !range_valid(flink, ListEntry::SIZE)? || !range_valid(blink, ListEntry::SIZE)? {
        return Ok(false);
    }
    // SAFETY: os vizinhos da lista, residentes conferidos acima.
    if unsafe { ListEntry::at(flink) }.blink.get() != array || unsafe { ListEntry::at(blink) }.flink.get() != array {
        return Ok(false);
    }
    let mut sum = 0u32;
    for block in blocks(header, used) {
        let size = block.size.get();
        if size > u32::MAX as u64 {
            return Ok(false);
        }
        match sum.checked_add(size as u32) {
            Some(total) => sum = total,
            None => return Ok(false),
        }
    }
    Ok(header.data_size.get() == sum && sum <= header.max_data_size.get())
}

/// KeInitializeTriageDumpDataArray(Array, Size): devolve o NTSTATUS.
pub fn initialize(array: u64, size: u32) -> u32 {
    if array == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if size < KtriageDumpDataArray::SIZE as u32 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    // SAFETY: o vetor do chamador de kernel, com pelo menos `size` bytes.
    let header = unsafe { KtriageDumpDataArray::at(array) };
    header.list.blink.set(array);
    header.num_blocks_total.set((size - HEADER_SIZE) >> 4);
    header.list.flink.set(array);
    header.num_blocks_used.set(0);
    header.data_size.set(0);
    header.max_data_size.set(MAXIMUM_DATA_SIZE);
    header.component_name_buffer_length.set(0);
    header.component_name.set(0);
    0
}

/// KeAddTriageDumpDataBlock(Array, Address, Size): devolve o NTSTATUS.
pub fn add_block(array: u64, address: u64, size: u64) -> Result<u32, KernelError> {
    if array == 0 || !validate(array)? || !range_valid(address, size)? {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if size == 0 {
        return Ok(0);
    }
    // SAFETY: vetor validado acima.
    let header = unsafe { KtriageDumpDataArray::at(array) };
    let used = header.num_blocks_used.get();
    let (mut start, mut end) = (address, address.wrapping_add(size));
    for block in blocks(header, used) {
        let block_start = block.address.get();
        let block_end = block_start.wrapping_add(block.size.get());
        if start >= block_end || end <= block_start {
            continue;
        }
        if start >= block_start {
            if end <= block_end {
                return Ok(0);
            }
            start = block_end;
        } else if end <= block_end {
            end = block_start;
        }
    }
    if used == header.num_blocks_total.get() {
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    let length = end.wrapping_sub(start);
    if length > header.max_data_size.get().wrapping_sub(header.data_size.get()) as u64 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    // SAFETY: a entrada `used` (< NumBlocksTotal) do vetor validado.
    let slot = unsafe { KaddressRange::at(array + HEADER_SIZE as u64 + used as u64 * KaddressRange::SIZE) };
    slot.size.set(length);
    slot.address.set(start);
    header.num_blocks_used.set(used + 1);
    header.data_size.set(header.data_size.get().wrapping_add(length as u32));
    Ok(0)
}
