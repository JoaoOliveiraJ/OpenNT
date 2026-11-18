//! As tabelas de funções dinâmicas de modo usuário que o kernel guarda por
//! processo. O RtlAddGrowableFunctionTable e o RtlDeleteGrowableFunctionTable
//! da ntdll registram e retiram o DYNAMIC_FUNCTION_TABLE de cada faixa de
//! código gerado pelo NtSetInformationProcess(NtCurrentProcess(),
//! ProcessDynamicFunctionTableInformation) (`ps/set_process_information`); o
//! JIT do d3d10warp registra assim o unwind de cada bloco que compila.
//!
//! O registro é o INVERTED_FUNCTION_TABLE apontado por
//! EPROCESS.InvertedFunctionTable: um bloco de pool 'RtDF' com quota do
//! processo, mudado sob o push lock EPROCESS.InvertedFunctionTableLock numa
//! região guardada. As CurrentSize entradas ficam ordenadas pela base da
//! faixa a partir da 1 (a 0 é zerada e só abre o vetor); cada uma guarda o
//! ponteiro de usuário da tabela (DynamicTable), a base (ImageBase), o
//! tamanho da faixa (SizeOfImage) e EntryCount * 12 do registro
//! (SizeOfTable). Como no ntoskrnl 19041:
//!
//! - RtlInsertDynamicFunctionTable (rva 0x2ffee8): a tabela fora do
//!   alinhamento 4 é STATUS_DATATYPE_MISALIGNMENT; do usuário saem
//!   BaseAddress, MaximumAddress e EntryCount (uma falha de leitura devolve o
//!   código da exceção). MaximumAddress abaixo da base, faixa acima de
//!   0xFFFFFFFF ou EntryCount acima de 0x15555555 dão
//!   STATUS_INTEGER_OVERFLOW. Sob a trava, o vetor cheio cresce 10 entradas
//!   (sem pool ou sem quota, STATUS_INSUFFICIENT_RESOURCES; o bloco anterior
//!   é liberado depois da trava) e a faixa que se sobrepõe à anterior ou à
//!   seguinte dá STATUS_CONFLICTING_ADDRESSES.
//! - RtlRemoveDynamicFunctionTable (rva 0x30479c): as mesmas leituras, sem o
//!   EntryCount; uma faixa de 0xFFFFFFFF ou mais (MaximumAddress abaixo da
//!   base também) dá STATUS_INTEGER_OVERFLOW. A entrada com a mesma base e o
//!   mesmo tamanho sai do vetor, senão STATUS_BAD_FUNCTION_TABLE; o vetor
//!   fica, mesmo vazio.
//! - A busca do RtlpLookupUserFunctionTable (rva 0x2f15c4), que o
//!   desenrolamento de pilhas de usuário do kernel faz depois da tabela
//!   invertida da ntdll: busca binária pela faixa sob a trava compartilhada e,
//!   fora dela, o FunctionTable e o EntryCount correntes da tabela de
//!   usuário (uma tabela que cresceu depois do registro aparece inteira).
//! - O PspExitThread da última thread (rva 0x6c3bf6) libera o vetor.

use core::mem::offset_of;

use crate::ntos::ex::{pool_allocation, pool_quota, push_lock};
use crate::ntos::inc::types::{DynamicFunctionTable, Eprocess, InvertedFunctionTable, InvertedFunctionTableEntry, Kthread, NtStruct};
use crate::ntos::ke::critical_region;
use crate::ntos::mm::guest_memory::{self as guest, GuestScalar};
use crate::ntos::ps::{process, user_probe};
use crate::rtl::KernelError;

const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
const STATUS_INTEGER_OVERFLOW: u32 = 0xC000_0095;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_BAD_FUNCTION_TABLE: u32 = 0xC000_00FF;
/// 'RtDF'.
const TAG: u32 = 0x4644_7452;
/// PagedPool | POOL_QUOTA_FAIL_INSTEAD_OF_RAISE.
const POOL_TYPE: u32 = 9;
/// Entradas acrescentadas a cada crescimento do vetor.
const GROWTH: u32 = 10;
/// O maior EntryCount (EntryCount * 12 cabe num ULONG).
const MAXIMUM_ENTRY_COUNT: u32 = 0x1555_5555;
/// Bytes de um RUNTIME_FUNCTION.
const RUNTIME_FUNCTION_SIZE: u32 = 12;
/// O cabeçalho do vetor, antes das entradas.
const HEADER_SIZE: u64 = offset_of!(InvertedFunctionTable, table_entry) as u64;
/// O fim do espaço de usuário que o ProbeForRead aceita (MmUserProbeAddress).
const USER_PROBE_ADDRESS: u64 = 0x7FFF_FFFF_0000;

/// O que a busca devolve de uma faixa registrada (os quatro campos que o
/// RtlpLookupUserFunctionTable grava): a FunctionTable e o tamanho dela
/// (EntryCount * 12), lidos da tabela de usuário na hora, e a base e o
/// tamanho da faixa. Uma tabela de usuário ilegível dá tudo zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserFunctionTable {
    pub function_table: u64,
    pub image_base: u64,
    pub size_of_image: u32,
    pub size_of_table: u32,
}

/// Uma faixa capturada da tabela de usuário.
struct Captured {
    base: u64,
    maximum: u64,
    entry_count: u32,
}

/// Leitura de um campo da tabela de usuário pelo layout do
/// DYNAMIC_FUNCTION_TABLE. O 19041 só exige alinhamento 4 da tabela, abaixo
/// do alinhamento do tipo; por isso a leitura é pelo endereço do campo, sem
/// referência ao tipo. A falha devolve o código da exceção.
fn read_user<T: GuestScalar>(table: u64, offset: usize) -> Result<T, u32> {
    let address = table + offset as u64;
    if !user_probe::probe_user_read(address, T::SIZE) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    guest::try_read::<T>(address).map_err(|error| if error.status != 0 { error.status } else { STATUS_ACCESS_VIOLATION })
}

/// A captura do começo das duas rotinas: alinhamento, BaseAddress e
/// MaximumAddress; com `entry_count`, também o EntryCount, lido depois da
/// conferência da faixa como no RtlInsertDynamicFunctionTable.
fn capture(table: u64, entry_count: bool) -> Result<Captured, u32> {
    if table & 3 != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    let base = read_user::<u64>(table, offset_of!(DynamicFunctionTable, base_address))?;
    let maximum = read_user::<u64>(table, offset_of!(DynamicFunctionTable, maximum_address))?;
    if !entry_count {
        return Ok(Captured { base, maximum, entry_count: 0 });
    }
    if maximum < base || maximum - base > 0xFFFF_FFFF {
        return Err(STATUS_INTEGER_OVERFLOW);
    }
    let count = read_user::<u32>(table, offset_of!(DynamicFunctionTable, entry_count))?;
    if count > MAXIMUM_ENTRY_COUNT {
        return Err(STATUS_INTEGER_OVERFLOW);
    }
    Ok(Captured { base, maximum, entry_count: count })
}

/// O EPROCESS dono da thread corrente (KTHREAD.Process, não o anexado), o
/// que as três rotinas usam.
fn current_process() -> &'static Eprocess {
    // SAFETY: a KTHREAD corrente e o processo dono dela estão vivos durante o
    // serviço.
    unsafe { Eprocess::at(Kthread::at(process::get_current_thread()).process.get()) }
}

fn header(vector: u64) -> &'static InvertedFunctionTable {
    // SAFETY: o vetor do EPROCESS.InvertedFunctionTable, retido pela trava;
    // só o cabeçalho e as entradas até MaximumSize são tocados.
    unsafe { InvertedFunctionTable::at(vector) }
}

/// As `capacity` entradas do vetor (MaximumSize).
fn entries(vector: u64, capacity: u32) -> &'static [InvertedFunctionTableEntry] {
    // SAFETY: o bloco foi alocado com espaço para MaximumSize entradas depois
    // do cabeçalho.
    unsafe { InvertedFunctionTableEntry::array_at(vector + HEADER_SIZE, capacity as usize) }
}

fn copy_entry(target: &InvertedFunctionTableEntry, source: &InvertedFunctionTableEntry) {
    target.function_table.set(source.function_table.get());
    target.image_base.set(source.image_base.get());
    target.size_of_image.set(source.size_of_image.get());
    target.size_of_table.set(source.size_of_table.get());
}

/// Região guardada e push lock exclusivo do processo em volta de `body`.
fn with_exclusive<T>(eprocess: &Eprocess, body: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
    let lock = eprocess.inverted_function_table_lock.address();
    critical_region::with_guarded(|| {
        push_lock::acquire_exclusive(lock, 0)?;
        let result = body();
        push_lock::release_exclusive(lock, 0)?;
        result
    })
}

/// RtlInsertDynamicFunctionTable(Table): devolve o NTSTATUS.
pub fn insert(table: u64) -> Result<u32, KernelError> {
    let captured = match capture(table, true) {
        Ok(captured) => captured,
        Err(status) => return Ok(status),
    };
    let eprocess = current_process();
    let mut replaced = 0u64;
    let status = with_exclusive(eprocess, || insert_locked(eprocess, table, &captured, &mut replaced))?;
    // O bloco anterior a um crescimento sai depois da trava.
    if replaced != 0 {
        pool_allocation::free(replaced, TAG as u64)?;
    }
    Ok(status)
}

fn insert_locked(eprocess: &Eprocess, table: u64, captured: &Captured, replaced: &mut u64) -> Result<u32, KernelError> {
    let mut vector = eprocess.inverted_function_table.get();
    let (mut current, mut capacity) = if vector == 0 { (0, 0) } else { (header(vector).current_size.get(), header(vector).maximum_size.get()) };
    if current.wrapping_add(1) > capacity {
        let Some(grown) = capacity.checked_add(GROWTH) else { return Ok(STATUS_INTEGER_OVERFLOW) };
        let bytes = grown as u64 * InvertedFunctionTableEntry::SIZE + HEADER_SIZE;
        if bytes >= 0xFFFF_FFFF {
            return Ok(STATUS_INTEGER_OVERFLOW);
        }
        let block = pool_quota::allocate(POOL_TYPE, bytes, TAG)?;
        if block == 0 {
            return Ok(STATUS_INSUFFICIENT_RESOURCES);
        }
        let target = entries(block, grown);
        if current != 0 {
            for (target, source) in target.iter().zip(entries(vector, current)) {
                copy_entry(target, source);
            }
        } else {
            // A entrada 0 zerada abre o vetor novo.
            target[0].function_table.set(0);
            target[0].image_base.set(0);
            target[0].size_of_image.set(0);
            target[0].size_of_table.set(0);
            current = 1;
        }
        let grown_header = header(block);
        grown_header.current_size.set(current);
        grown_header.maximum_size.set(grown);
        grown_header.overflow.set(0);
        eprocess.inverted_function_table.set(block);
        *replaced = vector;
        vector = block;
        capacity = grown;
    }
    let list = entries(vector, capacity);
    let current = current as usize;
    // A primeira entrada, a partir da 1, com base acima da nova.
    let mut index = 1usize;
    while index < current && captured.base >= list[index].image_base.get() {
        index += 1;
    }
    let previous = &list[index - 1];
    if previous.image_base.get().wrapping_add(previous.size_of_image.get() as u64) > captured.base {
        return Ok(STATUS_CONFLICTING_ADDRESSES);
    }
    if index < current && list[index].image_base.get() < captured.maximum {
        return Ok(STATUS_CONFLICTING_ADDRESSES);
    }
    for slot in (index..current).rev() {
        copy_entry(&list[slot + 1], &list[slot]);
    }
    let entry = &list[index];
    entry.function_table.set(table);
    entry.image_base.set(captured.base);
    entry.size_of_image.set((captured.maximum - captured.base) as u32);
    entry.size_of_table.set(captured.entry_count * RUNTIME_FUNCTION_SIZE);
    header(vector).current_size.set(current as u32 + 1);
    Ok(0)
}

/// RtlRemoveDynamicFunctionTable(Table): devolve o NTSTATUS.
pub fn remove(table: u64) -> Result<u32, KernelError> {
    let captured = match capture(table, false) {
        Ok(captured) => captured,
        Err(status) => return Ok(status),
    };
    let size = captured.maximum.wrapping_sub(captured.base);
    if size >= 0xFFFF_FFFF {
        return Ok(STATUS_INTEGER_OVERFLOW);
    }
    let eprocess = current_process();
    with_exclusive(eprocess, || {
        let vector = eprocess.inverted_function_table.get();
        if vector == 0 {
            return Ok(STATUS_BAD_FUNCTION_TABLE);
        }
        let current = header(vector).current_size.get() as usize;
        if current <= 1 {
            return Ok(STATUS_BAD_FUNCTION_TABLE);
        }
        let list = entries(vector, current as u32);
        let mut index = 1usize;
        while index < current && list[index].image_base.get() < captured.base {
            index += 1;
        }
        if index == current || list[index].image_base.get() != captured.base || list[index].size_of_image.get() != size as u32 {
            return Ok(STATUS_BAD_FUNCTION_TABLE);
        }
        for slot in index..current - 1 {
            copy_entry(&list[slot], &list[slot + 1]);
        }
        header(vector).current_size.set(current as u32 - 1);
        Ok(0)
    })
}

/// A parte das faixas registradas do RtlpLookupUserFunctionTable(ControlPc):
/// `None` quando nenhuma faixa do processo corrente contém `control_pc` (o
/// NT segue então para a tabela de exceções da imagem do endereço).
pub fn lookup(control_pc: u64) -> Result<Option<UserFunctionTable>, KernelError> {
    let eprocess = current_process();
    if eprocess.inverted_function_table.get() == 0 {
        return Ok(None);
    }
    let lock = eprocess.inverted_function_table_lock.address();
    let found = critical_region::with_guarded(|| {
        push_lock::acquire_shared(lock, 0)?;
        let found = search_locked(eprocess, control_pc);
        push_lock::release_shared(lock, 0)?;
        Ok(found)
    })?;
    let Some((table, base, size)) = found else { return Ok(None) };
    // Fora da trava, a tabela de usuário como está agora.
    let read = || -> Result<(u64, u32), u32> {
        let function_table = read_user::<u64>(table, offset_of!(DynamicFunctionTable, function_table))?;
        let size_of_table = read_user::<u32>(table, offset_of!(DynamicFunctionTable, entry_count))?.wrapping_mul(RUNTIME_FUNCTION_SIZE);
        if size_of_table != 0 {
            if function_table & 3 != 0 {
                return Err(STATUS_DATATYPE_MISALIGNMENT);
            }
            let end = function_table.wrapping_add(size_of_table as u64);
            if end > USER_PROBE_ADDRESS || end < function_table {
                return Err(STATUS_ACCESS_VIOLATION);
            }
        }
        Ok((function_table, size_of_table))
    };
    Ok(Some(match read() {
        Ok((function_table, size_of_table)) => UserFunctionTable { function_table, image_base: base, size_of_image: size, size_of_table },
        Err(_) => UserFunctionTable::default(),
    }))
}

/// Busca binária nas entradas 1..CurrentSize: (tabela, base, tamanho) da
/// faixa que contém `control_pc`.
fn search_locked(eprocess: &Eprocess, control_pc: u64) -> Option<(u64, u64, u32)> {
    let vector = eprocess.inverted_function_table.get();
    if vector == 0 {
        return None;
    }
    let current = header(vector).current_size.get();
    let list = entries(vector, current);
    let (mut low, mut high) = (1i64, current as i64 - 1);
    while low <= high {
        let middle = (low + high) >> 1;
        let entry = &list[middle as usize];
        let base = entry.image_base.get();
        if control_pc < base {
            if middle == 0 {
                return None;
            }
            high = middle - 1;
        } else if control_pc < base.wrapping_add(entry.size_of_image.get() as u64) {
            return Some((entry.dynamic_table.get(), base, entry.size_of_image.get()));
        } else {
            low = middle + 1;
        }
    }
    None
}

/// O fim do processo libera o vetor (o PspExitThread da última thread).
pub fn release(process: u64) {
    // SAFETY: o EPROCESS que termina, vivo durante as rotinas de término.
    let vector = unsafe { Eprocess::at(process) }.inverted_function_table.atomic().swap(0, core::sync::atomic::Ordering::SeqCst);
    if vector != 0 {
        let _ = pool_allocation::free(vector, 0);
    }
}
