//! As classes do NtQuerySystemInformation que o Mm responde sobre a
//! memória virtual do sistema, como o ExpQuerySystemInformation do ntoskrnl
//! 19041:
//!
//! - SystemPerformanceInformation (2, o ExpQuerySystemPerformanceInformation
//!   em rva 0x6bf5c0): a estrutura de 0x158 bytes; um buffer menor que 0x138
//!   (a versão antiga) é STATUS_INFO_LENGTH_MISMATCH com ReturnLength 0x158,
//!   senão vão min(Length, 0x158) bytes e esse é o ReturnLength. Do Mm saem
//!   AvailablePages, CommittedPages, CommitLimit e PeakCommitment (o pico
//!   nunca abaixo do commit), as contagens de faltas, de leituras e de
//!   escritas do arquivo de paginação e ResidentAvailablePages; os
//!   contadores que o OpenNT não mantém (E/S de arquivo, pool, Cc, trocas
//!   de contexto) ficam zerados.
//! - SystemPageFileInformation (18) e SystemPageFileInformationEx (144), o
//!   MmGetPageFileInformation (rva 0x6a1644): uma entrada por arquivo de
//!   paginação (0x20 bytes, 0x28 na Ex com MinimumSize e MaximumSize), em
//!   páginas, com TotalInUse = Size - FreeSpace - 2, o nome logo depois da
//!   entrada (MaximumLength = Length + 2, terminado em NUL) e
//!   NextEntryOffset até a próxima entrada alinhada a 8 (0 na última).
//!   Sem espaço para a próxima entrada ou para o nome, ReturnLength diz até
//!   onde ia e o status é STATUS_INFO_LENGTH_MISMATCH. Sem arquivos, a
//!   primeira entrada fica com NextEntryOffset e TotalSize zero e
//!   ReturnLength 0.
//! - SystemMemoryUsageInformation (182): a memória física e o commit em
//!   bytes ([`memory_usage_information`]); é a primeira consulta do
//!   GlobalMemoryStatusEx.

use core::sync::atomic::{AtomicU64, Ordering};

use super::{commit, paging_file, pfn, working_set};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

pub const PERFORMANCE_INFORMATION_SIZE: u32 = 0x158;
const PERFORMANCE_INFORMATION_MINIMUM: u32 = 0x138;
pub const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;

/// Deslocamentos da SYSTEM_PERFORMANCE_INFORMATION.
mod performance {
    pub const AVAILABLE_PAGES: u64 = 0x2C;
    pub const COMMITTED_PAGES: u64 = 0x30;
    pub const COMMIT_LIMIT: u64 = 0x34;
    pub const PEAK_COMMITMENT: u64 = 0x38;
    pub const PAGE_FAULT_COUNT: u64 = 0x3C;
    pub const TRANSITION_COUNT: u64 = 0x44;
    pub const PAGE_READ_COUNT: u64 = 0x50;
    pub const PAGE_READ_IO_COUNT: u64 = 0x54;
    pub const DIRTY_PAGES_WRITE_COUNT: u64 = 0x60;
    pub const DIRTY_WRITE_IO_COUNT: u64 = 0x64;
    pub const RESIDENT_AVAILABLE_PAGES: u64 = 0x148;
}

fn clamp32(value: u64) -> u32 {
    value.min(u32::MAX as u64) as u32
}

/// SystemPerformanceInformation em `buffer` (sondado pelo chamador):
/// (NTSTATUS, ReturnLength).
pub fn performance_information(buffer: u64, length: u32) -> Result<(u32, u32), KernelError> {
    if length < PERFORMANCE_INFORMATION_MINIMUM {
        return Ok((STATUS_INFO_LENGTH_MISMATCH, PERFORMANCE_INFORMATION_SIZE));
    }
    let mut image = [0u8; PERFORMANCE_INFORMATION_SIZE as usize];
    let mut put = |offset: u64, value: u32| image[offset as usize..offset as usize + 4].copy_from_slice(&value.to_le_bytes());
    let commitment = commit::snapshot();
    let available = pfn::free_count();
    put(performance::AVAILABLE_PAGES, clamp32(available));
    put(performance::COMMITTED_PAGES, clamp32(commitment.committed));
    put(performance::COMMIT_LIMIT, clamp32(commitment.limit));
    put(performance::PEAK_COMMITMENT, clamp32(commitment.peak.max(commitment.committed)));
    let counters = &working_set::COUNTERS;
    put(performance::PAGE_FAULT_COUNT, clamp32(counters.page_faults.load(Ordering::Relaxed)));
    put(performance::TRANSITION_COUNT, clamp32(counters.transition_faults.load(Ordering::Relaxed)));
    put(performance::PAGE_READ_COUNT, clamp32(counters.page_reads.load(Ordering::Relaxed)));
    put(performance::PAGE_READ_IO_COUNT, clamp32(counters.page_read_ios.load(Ordering::Relaxed)));
    put(performance::DIRTY_PAGES_WRITE_COUNT, clamp32(counters.dirty_pages_written.load(Ordering::Relaxed)));
    put(performance::DIRTY_WRITE_IO_COUNT, clamp32(counters.dirty_write_ios.load(Ordering::Relaxed)));
    image[performance::RESIDENT_AVAILABLE_PAGES as usize..performance::RESIDENT_AVAILABLE_PAGES as usize + 8].copy_from_slice(&available.to_le_bytes());
    let copied = length.min(PERFORMANCE_INFORMATION_SIZE);
    guest::try_write_bytes(buffer, &image[..copied as usize])?;
    Ok((0, copied))
}

/// SystemMemoryUsageInformation (182, o ramo da classe no
/// ExpQuerySystemInformation 19041, rva 0x6ca289): os contadores da
/// partição do processo corrente em bytes, na ordem do
/// SYSTEM_MEMORY_USAGE_INFORMATION. TotalPhysicalBytes é o
/// MmGetNumberOfPhysicalPages (o banco de frames, nunca abaixo das páginas
/// disponíveis); AvailableBytes o MmGetAvailablePages; ResidentAvailableBytes
/// o MmGetResidentAvailablePages (no OpenNT, as mesmas páginas livres); o
/// commit (MmGetTotalCommittedPages, MmGetTotalCommitLimit e
/// MmGetPeakCommitment, os dois últimos nunca abaixo do commit) vem de
/// `mm/commit`; SharedCommittedBytes é o MmGetSharedCommit, o commit das
/// seções de paginação, que o OpenNT ainda não cobra (zero). O tamanho é
/// exatamente 0x38 bytes (o chamador confere).
pub fn memory_usage_information() -> Result<alloc::vec::Vec<u8>, KernelError> {
    use crate::ntos::inc::field::NtStruct;
    use crate::ntos::inc::types::extra_ps_user::SystemMemoryUsageInformation;
    let size = SystemMemoryUsageInformation::SIZE;
    let scratch = guest::alloc_bytes(size);
    if scratch == 0 {
        return Err(KernelError::with_status("SystemMemoryUsageInformation", 0xC000_009A));
    }
    guest::write_bytes(scratch, &[0u8; SystemMemoryUsageInformation::SIZE as usize]);
    // SAFETY: a moldura própria recém-alocada, com o tamanho da estrutura.
    let usage = unsafe { SystemMemoryUsageInformation::at(scratch) };
    let available = pfn::free_count();
    let commitment = commit::snapshot();
    usage.total_physical_bytes.set(pfn::total_count().max(available) << 12);
    usage.available_bytes.set(available << 12);
    usage.resident_available_bytes.set(available << 12);
    usage.committed_bytes.set(commitment.committed << 12);
    usage.shared_committed_bytes.set(0);
    usage.commit_limit_bytes.set(commitment.limit.max(commitment.committed) << 12);
    usage.peak_commitment_bytes.set(commitment.peak.max(commitment.committed) << 12);
    let bytes = guest::read_bytes(scratch, size as usize);
    guest::free_bytes(scratch);
    Ok(bytes)
}

/// SystemMemoryTopologyInformation (138, o ExpQueryMemoryTopologyInformation
/// do ntoskrnl 19041, rva 0x7c8270, sobre o MmGetNodeChannelRanges): o
/// cabeçalho com NumberOfRuns, NumberOfNodes (KeNumberNodes) e
/// NumberOfChannels (MmNumberOfChannels, 1 sem topologia de canais do
/// firmware) e uma entrada por faixa de RAM da partição (as mesmas do
/// MmGetPhysicalMemoryRanges, `mm/physical_layout`), com o nó e o canal da
/// faixa (0 e 0 numa máquina de um nó e um canal), a primeira página, a
/// contagem e as flags (1 com o canal desligado pelo gerenciamento de
/// energia de memória, que o OpenNT não tem: 0). O tamanho, 0x10 + 0x20 por
/// faixa, vai sempre para `reported`; um buffer menor dá
/// STATUS_BUFFER_TOO_SMALL sem cópia. O buffer foi sondado pelo chamador.
pub fn memory_topology_information(output: u64, length: u32, reported: &mut u32) -> Result<u32, KernelError> {
    use crate::ntos::inc::field::NtStruct;
    use crate::ntos::inc::types::extra_ps_user::{MemoryTopologyRun, SystemMemoryTopologyInformation};
    let runs = super::physical_layout::ranges();
    let size = SystemMemoryTopologyInformation::SIZE + runs.len() as u64 * MemoryTopologyRun::SIZE;
    *reported = size as u32;
    if size > u32::MAX as u64 {
        return Ok(0xC000_009A);
    }
    if size > length as u64 {
        return Ok(0xC000_0023);
    }
    let scratch = guest::alloc_bytes(size);
    if scratch == 0 {
        return Ok(0xC000_009A);
    }
    guest::write_bytes(scratch, &alloc::vec![0u8; size as usize]);
    // SAFETY: a moldura própria recém-alocada, com o cabeçalho e as faixas.
    let header = unsafe { SystemMemoryTopologyInformation::at(scratch) };
    header.number_of_runs.set(runs.len() as u64);
    header.number_of_nodes.set(crate::ntos::ke::processor_group::number_nodes() as u32);
    header.number_of_channels.set(1);
    // SAFETY: as faixas logo depois do cabeçalho, dentro da moldura.
    let entries = unsafe { MemoryTopologyRun::array_at(scratch + SystemMemoryTopologyInformation::SIZE, runs.len()) };
    for (entry, &(base, top)) in entries.iter().zip(runs.iter()) {
        entry.base_page.set(base >> 12);
        entry.page_count.set((top - base) >> 12);
    }
    let bytes = guest::read_bytes(scratch, size as usize);
    guest::free_bytes(scratch);
    guest::try_write_bytes(output, &bytes)?;
    Ok(0)
}

/// O intervalo mínimo entre duas tabelas de processos do diagnóstico, em
/// unidades de 100 ns (5 s).
const PROCESS_TABLE_INTERVAL: u64 = 50_000_000;
/// O KeQueryInterruptTime da última tabela de processos (0: nenhuma).
static LAST_PROCESS_TABLE: AtomicU64 = AtomicU64::new(0);

/// Linha de diagnóstico da memória do sistema na serial (`[mm] memoria`):
/// frames livres do banco, commit do sistema (cobrado, limite, limite
/// máximo e pico), páginas privadas fora do working set e o heap do
/// kernel (os bytes usados, o total e o ocupado com os cabeçalhos dos
/// blocos) e a arena dos convidados (os bytes dos blocos vivos, o tamanho
/// e os blocos). Sai a cada processo criado e terminado, para a pressão de
/// memória aparecer no log da cadeia de boot sem depurador. Logo depois
/// sai a divisão dos frames em uso por dono ([`print_frame_owners`]) e, no
/// máximo a cada 5 s, a tabela dos processos ([`print_processes`]).
pub fn print_status(event: &str, process_id: u64) {
    print_memory_line(event, process_id);
    print_frame_owners();
    let now = crate::ntos::ke::clock::interrupt_time();
    let last = LAST_PROCESS_TABLE.load(Ordering::Acquire);
    if (last == 0 || now.wrapping_sub(last) >= PROCESS_TABLE_INTERVAL) && LAST_PROCESS_TABLE.compare_exchange(last, now.max(1), Ordering::AcqRel, Ordering::Acquire).is_ok() {
        print_processes();
    }
}

/// `[mm] frames por dono`: os frames em uso do alocador (o total da
/// partição menos os disponíveis, com a memória do kernel) e quantos são de
/// cada dono (`pfn::FrameUse`).
pub fn print_frame_owners() {
    let partition = pfn::partition();
    let usage = pfn::usage();
    let mut line = alloc::format!("[mm] frames por dono: em uso {} de {}", partition.total.saturating_sub(partition.available), partition.total);
    for owner in pfn::FrameUse::ALL {
        line.push_str(&alloc::format!(", {} {}", owner.label(), usage[owner as usize]));
    }
    crate::debug_print!("{}", line);
}

/// `[mm] processo`: uma linha por processo com raiz própria, com o working
/// set (`process_usage`, em páginas, e a parte privada), o commit privado
/// (EPROCESS.CommitCharge) e as cópias de sistema; depois a soma.
pub fn print_processes() {
    use crate::ntos::inc::field::NtStruct;
    use crate::ntos::inc::types::Eprocess;
    let (mut working_set, mut private, mut commit, mut copies, mut count) = (0u64, 0u64, 0u64, 0u64, 0u64);
    for state in crate::ntos::ps::user::process_state::all() {
        let root = state.directory_table_base.load(Ordering::Acquire);
        if root == 0 || root == super::process_address_space::SYSTEM_ROOT {
            continue;
        }
        let usage = super::process_usage::query_working_set(state.process);
        // SAFETY: o EPROCESS do estado registrado, vivo enquanto o estado está
        // na lista (o término tira o estado antes do último dereference).
        let process = unsafe { Eprocess::at(state.process) };
        let name: alloc::string::String = process.image_file_name.iter().map(|byte| byte.get()).take_while(|&byte| byte != 0).map(char::from).collect();
        let (pages, private_pages, charge, system) = (usage.current / 0x1000, usage.private / 0x1000, process.commit_charge.get(), state.system_page_count() as u64);
        crate::debug_print!("[mm] processo {} {}: working set {} paginas (privado {}), commit {}, copias de sistema {}", state.process_id, name, pages, private_pages, charge, system);
        working_set += pages;
        private += private_pages;
        commit += charge;
        copies += system;
        count += 1;
    }
    crate::debug_print!("[mm] processos: {} com raiz propria, working set {} paginas (privado {}), commit {}, copias de sistema {}", count, working_set, private, commit, copies);
}

fn print_memory_line(event: &str, process_id: u64) {
    let partition = pfn::partition();
    let commitment = commit::snapshot();
    let (heap_total, heap_used) = crate::hal::kmalloc::info();
    let heap_occupied = crate::hal::kmalloc::occupied();
    let (arena_blocks, arena_used) = crate::ntos::mm::guest_memory::usage();
    crate::debug_print!(
        "[mm] memoria ({} {}): PFN livres {}/{} paginas, commit {}/{} paginas (maximo {}, pico {}), nao residentes {}, heap {}/{} KB (ocupado {} KB), arena {}/{} KB ({} blocos)",
        event,
        process_id,
        partition.available,
        partition.total,
        commitment.committed,
        commitment.limit,
        commitment.limit_maximum,
        commitment.peak,
        working_set::nonresident_pages(),
        heap_used / 1024,
        heap_total / 1024,
        heap_occupied / 1024,
        arena_used / 1024,
        crate::ntos::mm::guest_memory::ARENA_SIZE / 1024,
        arena_blocks
    );
}

/// O tamanho mínimo do buffer da SystemPageFileInformation(Ex).
pub fn page_file_entry_size(extended: bool) -> u32 {
    if extended {
        0x28
    } else {
        0x20
    }
}

/// MmGetPageFileInformation em `buffer` (sondado pelo chamador, com pelo
/// menos uma entrada): (NTSTATUS, ReturnLength).
pub fn page_file_information(buffer: u64, length: u32, extended: bool) -> Result<(u32, u32), KernelError> {
    let entry_size = page_file_entry_size(extended);
    guest::try_write::<u32>(buffer + 4, 0)?;
    let mut used = 0u32;
    let mut last = buffer;
    for file in paging_file::information() {
        let entry = buffer + used as u64;
        let after_entry = used.checked_add(entry_size).filter(|&end| end <= length);
        let Some(after_entry) = after_entry else { return Ok((STATUS_INFO_LENGTH_MISMATCH, used + entry_size)) };
        last = entry;
        guest::try_write::<u32>(entry + 4, clamp32(file.total_size))?;
        guest::try_write::<u32>(entry + 8, clamp32(file.total_in_use))?;
        guest::try_write::<u32>(entry + 0xC, clamp32(file.peak_usage))?;
        if extended {
            guest::try_write::<u32>(entry + 0x20, clamp32(file.minimum))?;
            guest::try_write::<u32>(entry + 0x24, clamp32(file.maximum))?;
        }
        let units: alloc::vec::Vec<u16> = file.name.encode_utf16().collect();
        let name_length = units.len() as u32 * 2;
        guest::try_write::<u16>(entry + 0x10, name_length as u16)?;
        guest::try_write::<u16>(entry + 0x12, name_length as u16 + 2)?;
        guest::try_write::<u64>(entry + 0x18, entry + entry_size as u64)?;
        let aligned = (name_length + 2 + 7) & !7;
        let Some(after_name) = after_entry.checked_add(aligned).filter(|&end| end <= length) else { return Ok((STATUS_INFO_LENGTH_MISMATCH, after_entry + aligned)) };
        let mut bytes: alloc::vec::Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        bytes.extend_from_slice(&[0, 0]);
        guest::try_write_bytes(entry + entry_size as u64, &bytes)?;
        guest::try_write::<u32>(entry, aligned + entry_size)?;
        used = after_name;
    }
    guest::try_write::<u32>(last, 0)?;
    Ok((0, used))
}
