//! Heap do Rtl em modo kernel (RtlCreateHeap, RtlAllocateHeap, RtlFreeHeap,
//! RtlDestroyHeap), com a semântica de criação do ntoskrnl 19041.
//!
//! O RtlCreateHeap real tem dois caminhos, e os dois existem aqui:
//!
//! - **Heap fixo** (Flags com HEAP_CREATE_SEGMENT_HEAP, 0x100; o
//!   RtlpHpFixedHeapCreate): sobre memória do chamador. Exige HeapBase, Lock
//!   nulo e nada de HEAP_GROWABLE; com a CommitRoutine de
//!   RTL_HEAP_PARAMETERS, o tamanho vem de InitialReserve/InitialCommit
//!   (ambos não nulos, commit <= reserve); sem ela, da região consultada no
//!   processo corrente. O cabeçalho ocupa as primeiras páginas (0x100 bytes
//!   mais o bitmap de páginas, arredondado à página); se o commit inicial
//!   não cobre o cabeçalho, a CommitRoutine é chamada para ele. Depois, toda
//!   página nova é confirmada pela CommitRoutine(HeapBase, &Endereço,
//!   &Tamanho) antes de ser usada. Pedidos acima de 128 KB devolvem NULL e
//!   uma falha nunca levanta exceção. O RtlDestroyHeap não libera nada (a
//!   memória é do chamador).
//! - **Heap NT** (sem 0x100): HEAP_CREATE_HARDENED sozinho devolve NULL;
//!   flags fora de 0x7F3FF caem (a menos de 0x10000000); os parâmetros só
//!   valem com Length = 0x60; commit em múltiplos de 8 KB (8 KB se 0),
//!   reserva em 8 KB (ou o commit arredondado a 64 KB se 0), commit <=
//!   reserva; HEAP_NO_SERIALIZE com Lock dá NULL. Sem HeapBase, a reserva e
//!   o commit vêm do espaço do processo corrente (ZwAllocateVirtualMemory);
//!   com HeapBase e CommitRoutine, valem InitialCommit/InitialReserve (sem
//!   HEAP_GROWABLE) e o commit inicial é zerado; com HeapBase sem rotina, a
//!   região é consultada (confirmada: o tamanho confirmado; só reservada:
//!   confirma o commit pedido, ao menos 8 KB). Um heap serializado usa o
//!   ERESOURCE do chamador (Lock) ou um próprio no cabeçalho (+0x2C0) em cada
//!   operação. HEAP_GROWABLE sem base ganha segmentos novos (SegmentReserve,
//!   1 MB por padrão) e blocos acima do VirtualMemoryThreshold em reservas
//!   próprias. Com HEAP_GENERATE_EXCEPTIONS (no Flags da chamada ou no
//!   ForceFlags), uma falha levanta STATUS_NO_MEMORY com o tamanho em
//!   ExceptionInformation[0], como o RtlpAllocateHeapRaiseException.
//!
//! Comum aos dois: o handle é o HeapBase, com o cabeçalho real no início
//! (assinaturas e flags nos offsets do NT); blocos de 16 em 16 bytes com 16
//! de cabeçalho, ponteiros alinhados a 16; HEAP_ZERO_MEMORY (na chamada ou
//! na criação) zera o pedido. A contabilidade dos blocos (livres e em uso) é
//! do OpenNT, fora da memória do heap: nenhum chamador lê o formato interno
//! dos blocos.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::hal::amd64::native_call;
use crate::ntos::ex::resource;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::extra_rtl::RtlHeapParameters;
use crate::ntos::inc::types::{MemoryBasicInformation, MemoryRegionInformation};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::{query_virtual, virtual_memory_services};
use crate::ntos::rtl::{exceptions, shared_data};
use crate::rtl::{KernelError, SpinLock};

const HEAP_NO_SERIALIZE: u32 = 0x1;
const HEAP_GROWABLE: u32 = 0x2;
const HEAP_GENERATE_EXCEPTIONS: u32 = 0x4;
const HEAP_ZERO_MEMORY: u32 = 0x8;
const HEAP_TAIL_CHECKING_ENABLED: u32 = 0x20;
const HEAP_FREE_CHECKING_ENABLED: u32 = 0x40;
const HEAP_DISABLE_COALESCE_ON_FREE: u32 = 0x80;
const HEAP_CREATE_SEGMENT_HEAP: u32 = 0x100;
const HEAP_CREATE_HARDENED: u32 = 0x200;
const HEAP_CREATE_ENABLE_EXECUTE: u32 = 0x4_0000;
const HEAP_SKIP_VALIDATION_CHECKS: u32 = 0x1000_0000;
/// HEAP_LOCK_USER_ALLOCATED: o Lock veio do chamador.
const HEAP_LOCK_USER_ALLOCATED: u32 = 0x8000_0000;
/// Flags inválidas do RtlCreateHeap e a máscara que sobra sem elas.
const INVALID_CREATE_FLAGS: u32 = 0xFFF8_0C00;
const VALID_CREATE_FLAGS: u32 = 0x7_F3FF;
/// Bits do Flags de criação que vão para o ForceFlags.
const FORCE_FLAGS_MASK: u32 = 0x6001_007D;

/// NtGlobalFlag: FLG_HEAP_ENABLE_TAIL_CHECK, FLG_HEAP_ENABLE_FREE_CHECK e
/// FLG_HEAP_DISABLE_COALESCING.
const FLG_HEAP_ENABLE_TAIL_CHECK: u32 = 0x10;
const FLG_HEAP_ENABLE_FREE_CHECK: u32 = 0x20;
const FLG_HEAP_DISABLE_COALESCING: u32 = 0x20_0000;

const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const MEM_FREE: u32 = 0x1_0000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const CURRENT_PROCESS: u64 = u64::MAX;
/// Classes do ZwQueryVirtualMemory.
const MEMORY_BASIC_INFORMATION: u32 = 0;
const MEMORY_REGION_INFORMATION: u32 = 3;

const PAGE: u64 = 0x1000;
const GRANULARITY: u64 = 16;
const BLOCK_HEADER: u64 = 16;
/// Maior pedido de um heap fixo (o contexto VS).
const FIXED_MAXIMUM_ALLOCATION: u64 = 0x2_0000;
/// sizeof(HEAP), o ERESOURCE interno e a área de listas que o segmento
/// reserva depois do cabeçalho.
const HEAP_HEADER: u64 = 0x2C0;
const LOCK_SIZE: u64 = 0x68;
const LIST_AREA: u64 = 0x450;
/// Cabeçalho de um bloco em reserva própria (HEAP_VIRTUAL_ALLOC_ENTRY).
const LARGE_BLOCK_HEADER: u64 = 0x40;
/// MmHeapSegmentReserve/MmHeapSegmentCommit (os padrões do 19041).
const DEFAULT_SEGMENT_RESERVE: u64 = 0x10_0000;
const DEFAULT_SEGMENT_COMMIT: u64 = 0x2000;
const DEFAULT_VIRTUAL_MEMORY_THRESHOLD: u64 = 0xF_F000;
/// MaximumAllocationSize padrão: MmHighestUserAddress - 64 KB - 4 KB.
const DEFAULT_MAXIMUM_ALLOCATION: u64 = 0x7FFF_FFFE_FFFF - 0x1_0000 - PAGE;

const SEGMENT_SIGNATURE: u32 = 0xFFEE_FFEE;
const HEAP_SIGNATURE: u32 = 0xEEFF_EEFF;
const FIXED_HEAP_SIGNATURE: u32 = 0xCCDD_CCDD;

/// O começo do HEAP do NT (os campos que o OpenNT publica).
#[repr(C)]
struct HeapHeader {
    _reserved_0: Reserved<0x10>,
    segment_signature: Field<u32>,
    segment_flags: Field<u32>,
    _reserved_18: Reserved<0x58>,
    flags: Field<u32>,
    force_flags: Field<u32>,
    _reserved_78: Reserved<0x20>,
    signature: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for HeapHeader {}

/// O começo do heap fixo: assinatura e flags convertidas.
#[repr(C)]
struct FixedHeapHeader {
    _reserved_0: Reserved<0x10>,
    signature: Field<u32>,
    flags: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for FixedHeapHeader {}

const _: () = {
    assert!(core::mem::offset_of!(HeapHeader, segment_signature) == 0x10);
    assert!(core::mem::offset_of!(HeapHeader, flags) == 0x70);
    assert!(core::mem::offset_of!(HeapHeader, force_flags) == 0x74);
    assert!(core::mem::offset_of!(HeapHeader, signature) == 0x98);
    assert!(core::mem::offset_of!(FixedHeapHeader, signature) == 0x10);
};

/// De onde vêm as páginas novas.
#[derive(Clone, Copy)]
enum Commit {
    /// RTL_HEAP_PARAMETERS.CommitRoutine.
    Routine(u64),
    /// ZwAllocateVirtualMemory(MEM_COMMIT) no processo corrente.
    Process,
}

struct Segment {
    base: u64,
    end: u64,
    committed: u64,
    /// Reservado pelo heap (liberado no RtlDestroyHeap).
    owned: bool,
}

struct Heap {
    base: u64,
    fixed: bool,
    force_flags: u32,
    /// ERESOURCE de serialização (0 = nenhum).
    lock: u64,
    internal_lock: bool,
    commit: Commit,
    growable: bool,
    segment_reserve: u64,
    segment_commit: u64,
    virtual_threshold: u64,
    maximum_allocation: u64,
    segments: Vec<Segment>,
    /// Bloco livre -> tamanho.
    free: BTreeMap<u64, u64>,
    /// Ponteiro em uso -> tamanho do bloco.
    busy: BTreeMap<u64, u64>,
    /// Ponteiro de bloco em reserva própria -> base da reserva.
    large: BTreeMap<u64, u64>,
}

static HEAPS: SpinLock<BTreeMap<u64, Arc<SpinLock<Heap>>>> = SpinLock::new(BTreeMap::new());

fn round_up(value: u64, alignment: u64) -> Option<u64> {
    Some(value.checked_add(alignment - 1)? & !(alignment - 1))
}

fn zero(address: u64, length: u64) {
    if length != 0 {
        guest::write_bytes(address, &alloc::vec![0u8; length as usize]);
    }
}

/// ZwAllocateVirtualMemory(NtCurrentProcess(), ...): (base, tamanho) ou
/// None na falha.
fn zw_allocate(address: u64, size: u64, kind: u32) -> Result<Option<(u64, u64)>, KernelError> {
    let cells = guest::alloc_bytes(16);
    if cells == 0 {
        return Ok(None);
    }
    guest::write64(cells, address);
    guest::write64(cells + 8, size);
    let status = virtual_memory_services::allocate(CURRENT_PROCESS, cells, 0, cells + 8, kind, PAGE_READWRITE);
    let result = status.map(|status| ((status as i32) >= 0).then(|| (guest::read64(cells), guest::read64(cells + 8))));
    guest::free_bytes(cells);
    result
}

/// ZwFreeVirtualMemory(NtCurrentProcess(), base, 0, MEM_RELEASE).
fn zw_release(address: u64) -> Result<(), KernelError> {
    let cells = guest::alloc_bytes(16);
    if cells == 0 {
        return Ok(());
    }
    guest::write64(cells, address);
    guest::write64(cells + 8, 0);
    let result = virtual_memory_services::free(CURRENT_PROCESS, cells, cells + 8, MEM_RELEASE).map(|_| ());
    guest::free_bytes(cells);
    result
}

/// ZwQueryVirtualMemory no processo corrente; None se a consulta falha.
fn query<T: NtStruct + 'static, R>(address: u64, class: u32, read: impl FnOnce(&T) -> R) -> Result<Option<R>, KernelError> {
    let buffer = guest::alloc_bytes(T::SIZE);
    if buffer == 0 {
        return Ok(None);
    }
    let status = query_virtual::query(CURRENT_PROCESS, address, class, buffer, T::SIZE, 0);
    // SAFETY: a estrutura recém-preenchida no bloco alocado acima.
    let result = status.map(|status| (status == 0).then(|| read(unsafe { T::at(buffer) })));
    guest::free_bytes(buffer);
    result
}

/// CommitRoutine(Base, &CommitAddress, &CommitSize): a faixa confirmada.
fn call_commit_routine(routine: u64, heap_base: u64, address: u64, size: u64) -> Option<(u64, u64)> {
    let cells = guest::alloc_bytes(16);
    if cells == 0 {
        return None;
    }
    guest::write64(cells, address);
    guest::write64(cells + 8, size);
    let status = native_call::call(routine, &[heap_base, cells, cells + 8]) as u32;
    let result = ((status as i32) >= 0).then(|| (guest::read64(cells), guest::read64(cells + 8)));
    guest::free_bytes(cells);
    result
}

fn commit_pages(commit: Commit, heap_base: u64, address: u64, size: u64) -> Result<Option<(u64, u64)>, KernelError> {
    match commit {
        Commit::Routine(routine) => Ok(call_commit_routine(routine, heap_base, address, size)),
        Commit::Process => zw_allocate(address, size, MEM_COMMIT),
    }
}

/// Parâmetros de criação lidos do RTL_HEAP_PARAMETERS.
#[derive(Default, Clone, Copy)]
struct Parameters {
    segment_reserve: u64,
    segment_commit: u64,
    maximum_allocation: u64,
    virtual_threshold: u64,
    initial_commit: u64,
    initial_reserve: u64,
    commit_routine: u64,
}

fn read_parameters(parameters: u64) -> Parameters {
    // SAFETY: PRTL_HEAP_PARAMETERS opcional do chamador de kernel.
    let fields = unsafe { RtlHeapParameters::at(parameters) };
    Parameters {
        segment_reserve: fields.segment_reserve.get(),
        segment_commit: fields.segment_commit.get(),
        maximum_allocation: fields.maximum_allocation_size.get(),
        virtual_threshold: fields.virtual_memory_threshold.get(),
        initial_commit: fields.initial_commit.get(),
        initial_reserve: fields.initial_reserve.get(),
        commit_routine: fields.commit_routine.get(),
    }
}

fn register(heap: Heap) -> u64 {
    let base = heap.base;
    HEAPS.lock().insert(base, Arc::new(SpinLock::new(heap)));
    base
}

fn heap_of(handle: u64) -> Option<Arc<SpinLock<Heap>>> {
    HEAPS.lock().get(&handle).cloned()
}

/// RtlCreateHeap(Flags, HeapBase, ReserveSize, CommitSize, Lock,
/// Parameters): o handle ou NULL.
pub fn create(flags: u32, base: u64, reserve: u64, commit: u64, lock: u64, parameters: u64) -> Result<u64, KernelError> {
    if flags & HEAP_CREATE_SEGMENT_HEAP != 0 {
        create_fixed(flags, base, commit, lock, parameters)
    } else {
        create_nt(flags, base, reserve, commit, lock, parameters)
    }
}

/// RtlpHpFixedHeapCreate. O ReserveSize do chamador não entra: com rotina
/// vale o InitialReserve, sem ela a região consultada.
fn create_fixed(flags: u32, base: u64, commit: u64, lock: u64, parameters: u64) -> Result<u64, KernelError> {
    if base == 0 || lock != 0 || flags & HEAP_GROWABLE != 0 || parameters == 0 {
        return Ok(0);
    }
    let supplied = read_parameters(parameters);
    let reserve;
    let mut commit = commit;
    let routine = supplied.commit_routine;
    if routine != 0 {
        (reserve, commit) = (supplied.initial_reserve, supplied.initial_commit);
        if commit == 0 || reserve == 0 || commit > reserve {
            return Ok(0);
        }
    } else {
        // Sem rotina: a alocação e o trecho confirmado vêm da consulta.
        let Some(region) = query::<MemoryRegionInformation, u64>(base, MEMORY_REGION_INFORMATION, |info| info.region_size.get())? else { return Ok(0) };
        let Some((start, state, size)) = query::<MemoryBasicInformation, (u64, u32, u64)>(base, MEMORY_BASIC_INFORMATION, |info| (info.base_address.get(), info.state.get(), info.region_size.get()))? else { return Ok(0) };
        if start != base || state == MEM_FREE {
            return Ok(0);
        }
        reserve = region;
        if state == MEM_COMMIT {
            commit = size;
        }
        if commit == 0 || reserve == 0 || commit > reserve {
            return Ok(0);
        }
    }
    let commit_source = if routine != 0 { Commit::Routine(routine) } else { Commit::Process };
    // Cabeçalho: 0x100 bytes e o bitmap de páginas, arredondados à página.
    let bitmap = ((reserve >> 12 >> 3) + 7) & !7;
    let Some(header) = round_up(bitmap + 0x100, PAGE) else { return Ok(0) };
    if header > reserve {
        return Ok(0);
    }
    if commit < header && commit_pages(commit_source, base, base, header)?.is_none() {
        return Ok(0);
    }
    zero(base, bitmap + 0x100);
    // SAFETY: as primeiras páginas da memória do heap, confirmadas acima.
    let fixed = unsafe { FixedHeapHeader::at(base) };
    fixed.signature.set(FIXED_HEAP_SIGNATURE);
    // RtlpHpConvertCreationFlags: HEAP_NO_SERIALIZE -> bit 0, HEAP_ZERO_MEMORY -> bit 1.
    fixed.flags.set((flags & HEAP_NO_SERIALIZE) | (((flags & HEAP_ZERO_MEMORY) != 0) as u32) << 1);
    Ok(register(Heap {
        base,
        fixed: true,
        force_flags: flags & (HEAP_NO_SERIALIZE | HEAP_ZERO_MEMORY),
        lock: 0,
        internal_lock: false,
        commit: commit_source,
        growable: false,
        segment_reserve: 0,
        segment_commit: PAGE,
        virtual_threshold: u64::MAX,
        maximum_allocation: FIXED_MAXIMUM_ALLOCATION,
        segments: alloc::vec![Segment { base, end: base + reserve, committed: base + header, owned: false }],
        free: BTreeMap::new(),
        busy: BTreeMap::new(),
        large: BTreeMap::new(),
    }))
}

/// O caminho do heap NT do RtlCreateHeap.
fn create_nt(flags: u32, base: u64, reserve: u64, commit: u64, lock: u64, parameters: u64) -> Result<u64, KernelError> {
    if flags & HEAP_CREATE_HARDENED != 0 {
        return Ok(0);
    }
    let mut flags = flags;
    if flags & HEAP_SKIP_VALIDATION_CHECKS == 0 && flags & INVALID_CREATE_FLAGS != 0 {
        flags &= VALID_CREATE_FLAGS;
    }
    let supplied = if parameters != 0 && guest::read32(parameters) == RtlHeapParameters::SIZE as u32 { read_parameters(parameters) } else { Parameters::default() };
    let global = shared_data::nt_global_flag();
    if global & FLG_HEAP_ENABLE_TAIL_CHECK != 0 {
        flags |= HEAP_TAIL_CHECKING_ENABLED;
    }
    if global & FLG_HEAP_ENABLE_FREE_CHECK != 0 {
        flags |= HEAP_FREE_CHECKING_ENABLED;
    }
    if global & FLG_HEAP_DISABLE_COALESCING != 0 {
        flags |= HEAP_DISABLE_COALESCE_ON_FREE;
    }
    let segment_reserve = if supplied.segment_reserve != 0 { supplied.segment_reserve } else { DEFAULT_SEGMENT_RESERVE };
    let segment_commit = if supplied.segment_commit != 0 { supplied.segment_commit } else { DEFAULT_SEGMENT_COMMIT };
    let maximum_allocation = if supplied.maximum_allocation != 0 { supplied.maximum_allocation } else { DEFAULT_MAXIMUM_ALLOCATION };
    let virtual_threshold = if (1..=DEFAULT_VIRTUAL_MEMORY_THRESHOLD).contains(&supplied.virtual_threshold) { supplied.virtual_threshold } else { DEFAULT_VIRTUAL_MEMORY_THRESHOLD };
    let Some(mut commit) = (if commit == 0 { Some(0x2000) } else { round_up(commit, 0x2000) }) else { return Ok(0) };
    let Some(mut reserve) = (if reserve == 0 { round_up(commit, 0x1_0000) } else { round_up(reserve, 0x2000) }) else { return Ok(0) };
    commit = commit.min(reserve);
    let growable = flags & HEAP_GROWABLE != 0;
    let guard_page = growable && base == 0;
    if guard_page && reserve - PAGE < commit {
        let Some(grown) = round_up(reserve + 0x1_0000, 0x1_0000) else { return Ok(0) };
        reserve = grown;
    }
    if commit == 0 || reserve == 0 {
        return Ok(0);
    }
    let serialized = flags & HEAP_NO_SERIALIZE == 0;
    if !serialized && lock != 0 {
        return Ok(0);
    }
    if lock != 0 {
        flags |= HEAP_LOCK_USER_ALLOCATED;
    }
    let header = if serialized && lock == 0 { HEAP_HEADER + LOCK_SIZE } else { HEAP_HEADER };
    let first_block = header.next_multiple_of(GRANULARITY) + LIST_AREA;
    let (heap_base, committed, commit_source, owned) = if base != 0 {
        if supplied.commit_routine != 0 {
            let (initial_commit, initial_reserve) = (supplied.initial_commit, supplied.initial_reserve);
            if initial_commit == 0 || initial_reserve == 0 || initial_commit > initial_reserve || growable {
                return Ok(0);
            }
            zero(base, initial_commit);
            reserve = initial_reserve;
            (base, base + initial_commit, Commit::Routine(supplied.commit_routine), false)
        } else {
            let Some((start, state, protect, size)) = query::<MemoryBasicInformation, (u64, u32, u32, u64)>(base, MEMORY_BASIC_INFORMATION, |info| (info.base_address.get(), info.state.get(), info.protect.get(), info.region_size.get()))? else { return Ok(0) };
            if start != base || state == MEM_FREE {
                return Ok(0);
            }
            if state == MEM_COMMIT {
                if flags & HEAP_CREATE_ENABLE_EXECUTE != 0 && protect & PAGE_EXECUTE_READWRITE == 0 {
                    return Ok(0);
                }
                zero(base, PAGE);
                let Some(region) = query::<MemoryRegionInformation, u64>(base, MEMORY_REGION_INFORMATION, |info| info.region_size.get())? else { return Ok(0) };
                reserve = region;
                (base, base + size, Commit::Process, false)
            } else {
                reserve = size;
                commit = commit.min(size);
                if commit < 0x2000 {
                    return Ok(0);
                }
                let Some((start, length)) = zw_allocate(base, commit, MEM_COMMIT)? else { return Ok(0) };
                (base, start + length, Commit::Process, false)
            }
        }
    } else {
        if supplied.commit_routine != 0 {
            return Ok(0);
        }
        let Some((start, length)) = zw_allocate(0, reserve, MEM_RESERVE)? else { return Ok(0) };
        reserve = length;
        let Some((committed_start, committed_length)) = zw_allocate(start, commit, MEM_COMMIT)? else {
            zw_release(start)?;
            return Ok(0);
        };
        (start, committed_start + committed_length, Commit::Process, true)
    };
    if committed < heap_base + first_block {
        if owned {
            zw_release(heap_base)?;
        }
        return Ok(0);
    }
    zero(heap_base, first_block);
    let mut heap_lock = lock;
    let internal_lock = serialized && lock == 0;
    if internal_lock {
        heap_lock = heap_base + HEAP_HEADER;
        if (resource::initialize(heap_lock)? as i32) < 0 {
            if owned {
                zw_release(heap_base)?;
            }
            return Ok(0);
        }
    }
    // SAFETY: o início da memória do heap, confirmado e zerado acima.
    let fields = unsafe { HeapHeader::at(heap_base) };
    fields.segment_signature.set(SEGMENT_SIGNATURE);
    fields.flags.set(flags & !HEAP_SKIP_VALIDATION_CHECKS);
    fields.force_flags.set(flags & FORCE_FLAGS_MASK);
    fields.signature.set(HEAP_SIGNATURE);
    let end = heap_base + reserve - if guard_page { PAGE } else { 0 };
    let mut free = BTreeMap::new();
    let start = heap_base + first_block;
    let committed = committed.min(end);
    if committed > start {
        free.insert(start, (committed - start) & !(GRANULARITY - 1));
    }
    Ok(register(Heap {
        base: heap_base,
        fixed: false,
        force_flags: flags & FORCE_FLAGS_MASK,
        lock: heap_lock,
        internal_lock,
        commit: commit_source,
        growable,
        segment_reserve,
        segment_commit,
        virtual_threshold,
        maximum_allocation,
        segments: alloc::vec![Segment { base: heap_base, end, committed, owned }],
        free,
        busy: BTreeMap::new(),
        large: BTreeMap::new(),
    }))
}

impl Heap {
    /// Primeiro bloco livre que cabe (por endereço), dividido se sobra.
    fn take_free(&mut self, block: u64) -> Option<u64> {
        let (&address, &size) = self.free.iter().find(|(_, &size)| size >= block)?;
        self.free.remove(&address);
        let used = if size - block >= BLOCK_HEADER + GRANULARITY {
            self.free.insert(address + block, size - block);
            block
        } else {
            size
        };
        self.busy.insert(address + BLOCK_HEADER, used);
        Some(address + BLOCK_HEADER)
    }

    /// Devolve um bloco à lista livre, unido aos vizinhos livres.
    fn release(&mut self, mut address: u64, mut size: u64) {
        if let Some(next) = self.free.remove(&(address + size)) {
            size += next;
        }
        if let Some((&previous, &length)) = self.free.range(..address).next_back() {
            if previous + length == address {
                self.free.remove(&previous);
                address = previous;
                size += length;
            }
        }
        self.free.insert(address, size);
    }

    /// Onde confirmar páginas para um bloco: (segmento, endereço, tamanho).
    fn commit_plan(&self, block: u64) -> Option<(usize, u64, u64)> {
        for (index, segment) in self.segments.iter().enumerate() {
            let tail = self.free.range(..segment.committed).next_back().filter(|(&address, &size)| address + size == segment.committed).map_or(0, |(_, &size)| size);
            let needed = block.saturating_sub(tail);
            let available = segment.end - segment.committed;
            if needed == 0 || needed > available {
                continue;
            }
            let minimum = if matches!(self.commit, Commit::Process) { self.segment_commit } else { PAGE };
            let size = round_up(needed.max(minimum), PAGE)?.min(available & !(PAGE - 1));
            if size >= needed {
                return Some((index, segment.committed, size));
            }
        }
        None
    }

    /// Acrescenta o que foi confirmado ao fim do segmento.
    fn add_committed(&mut self, index: usize, address: u64, size: u64) -> bool {
        let segment = &mut self.segments[index];
        let end = address.saturating_add(size).min(segment.end);
        if address > segment.committed || end <= segment.committed {
            return false;
        }
        let start = segment.committed;
        segment.committed = end;
        self.release(start, (end - start) & !(GRANULARITY - 1));
        true
    }
}

enum Growth {
    Commit(usize, u64, u64),
    Segment(u64),
    Large(u64),
    None,
}

/// Bloco de `size` bytes, confirmando páginas (fora da trava do heap) ou
/// criando segmento quando preciso; 0 se não há como.
fn allocate_block(heap: &Arc<SpinLock<Heap>>, size: u64) -> Result<u64, KernelError> {
    let Some(block) = round_up(size.max(1), GRANULARITY).and_then(|rounded| rounded.checked_add(BLOCK_HEADER)) else { return Ok(0) };
    loop {
        let (growth, commit, base) = {
            let mut state = heap.lock();
            if !state.fixed && state.growable && matches!(state.commit, Commit::Process) && block > state.virtual_threshold {
                (Growth::Large(block), state.commit, state.base)
            } else if let Some(pointer) = state.take_free(block) {
                return Ok(pointer);
            } else if let Some((index, address, length)) = state.commit_plan(block) {
                (Growth::Commit(index, address, length), state.commit, state.base)
            } else if state.growable && matches!(state.commit, Commit::Process) {
                let reserve = state.segment_reserve.max(round_up(block + PAGE, 0x1_0000).unwrap_or(u64::MAX));
                (Growth::Segment(reserve), state.commit, state.base)
            } else {
                (Growth::None, state.commit, state.base)
            }
        };
        match growth {
            Growth::None => return Ok(0),
            Growth::Large(block) => {
                let Some(length) = round_up(block - BLOCK_HEADER + LARGE_BLOCK_HEADER, PAGE) else { return Ok(0) };
                let Some((start, _)) = zw_allocate(0, length, MEM_RESERVE | MEM_COMMIT)? else { return Ok(0) };
                heap.lock().large.insert(start + LARGE_BLOCK_HEADER, start);
                return Ok(start + LARGE_BLOCK_HEADER);
            }
            Growth::Commit(index, address, length) => {
                let Some((start, committed)) = commit_pages(commit, base, address, length)? else { return Ok(0) };
                if !heap.lock().add_committed(index, start, committed) {
                    return Ok(0);
                }
            }
            Growth::Segment(reserve) => {
                let Some((start, length)) = zw_allocate(0, reserve, MEM_RESERVE)? else { return Ok(0) };
                let mut state = heap.lock();
                state.segments.push(Segment { base: start, end: start + length, committed: start, owned: true });
                let plan = state.commit_plan(block);
                drop(state);
                let Some((index, address, size)) = plan else { return Ok(0) };
                let Some((committed_start, committed)) = zw_allocate(address, size, MEM_COMMIT)? else { return Ok(0) };
                if !heap.lock().add_committed(index, committed_start, committed) {
                    return Ok(0);
                }
            }
        }
    }
}

/// O ERESOURCE de uma operação: o do heap, salvo HEAP_NO_SERIALIZE.
fn operation_lock(heap: &Heap, flags: u32) -> u64 {
    if (flags | heap.force_flags) & HEAP_NO_SERIALIZE != 0 { 0 } else { heap.lock }
}

fn serialized<T>(lock: u64, body: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
    if lock != 0 {
        resource::enter_exclusive(lock)?;
    }
    let result = body();
    if lock != 0 {
        resource::release_and_leave(lock)?;
    }
    result
}

/// RtlAllocateHeap(HeapHandle, Flags, Size).
pub fn allocate(handle: u64, flags: u32, size: u64) -> Result<u64, KernelError> {
    let Some(heap) = heap_of(handle) else { return Ok(0) };
    let (fixed, force, lock, maximum) = {
        let state = heap.lock();
        (state.fixed, state.force_flags, operation_lock(&state, flags), state.maximum_allocation)
    };
    let flags = flags | force;
    let pointer = if size > maximum || size > i64::MAX as u64 { 0 } else { serialized(lock, || allocate_block(&heap, size))? };
    if pointer == 0 {
        if !fixed && flags & HEAP_GENERATE_EXCEPTIONS != 0 {
            return exceptions::raise_software_exception(STATUS_NO_MEMORY, &[size], 0);
        }
        return Ok(0);
    }
    if flags & HEAP_ZERO_MEMORY != 0 {
        zero(pointer, size);
    }
    Ok(pointer)
}

/// RtlFreeHeap(HeapHandle, Flags, BaseAddress): NULL é sucesso; um ponteiro
/// que não é bloco em uso do heap dá FALSE.
pub fn free(handle: u64, flags: u32, pointer: u64) -> Result<bool, KernelError> {
    if pointer == 0 {
        return Ok(true);
    }
    let Some(heap) = heap_of(handle) else { return Ok(false) };
    let lock = operation_lock(&heap.lock(), flags);
    serialized(lock, || {
        let mut state = heap.lock();
        if let Some(size) = state.busy.remove(&pointer) {
            state.release(pointer - BLOCK_HEADER, size);
            return Ok(true);
        }
        let Some(start) = state.large.remove(&pointer) else { return Ok(false) };
        drop(state);
        zw_release(start)?;
        Ok(true)
    })
}

/// RtlDestroyHeap(HeapHandle): NULL no sucesso. O heap fixo não libera
/// memória; o NT devolve as reservas próprias, os blocos grandes e o lock
/// interno.
pub fn destroy(handle: u64) -> Result<u64, KernelError> {
    if handle == 0 {
        return Ok(0);
    }
    let Some(heap) = HEAPS.lock().remove(&handle) else { return Ok(handle) };
    let (fixed, internal_lock, lock, large, owned): (bool, bool, u64, Vec<u64>, Vec<u64>) = {
        let state = heap.lock();
        (state.fixed, state.internal_lock, state.lock, state.large.values().copied().collect(), state.segments.iter().filter(|segment| segment.owned).map(|segment| segment.base).collect())
    };
    if fixed {
        return Ok(0);
    }
    for start in large {
        zw_release(start)?;
    }
    if internal_lock {
        resource::delete(lock)?;
    }
    for base in owned.into_iter().rev() {
        zw_release(base)?;
    }
    Ok(0)
}

/// Para os autotestes: (fixo, ForceFlags, faixa confirmada do primeiro
/// segmento, número de segmentos).
pub fn describe(handle: u64) -> Option<(bool, u32, u64, usize)> {
    let heap = heap_of(handle)?;
    let state = heap.lock();
    Some((state.fixed, state.force_flags, state.segments[0].committed - state.segments[0].base, state.segments.len()))
}
