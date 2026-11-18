//! Extensão dos arquivos de paginação do ntoskrnl 19041: o pedido
//! MMPAGE_FILE_EXPANSION, a thread que o atende e as rotinas que crescem um
//! arquivo de paginação do Size até o MaximumSize, com o limite de commit.
//!
//! - MiIssuePageExtendRequest (rva 0x543884): com o flag 2, o pedido é o
//!   estático da partição (Modwriter.AttemptForCantExtend: PageFileNumber
//!   0xFF e AttemptForCantExtend desde o MiInitializeCommitment), um só em
//!   curso (InProgress), com o tamanho arredondado a 4096 páginas e
//!   ninguém esperando; o flag 4 liga IgnoreCurrentCommit. Sem o flag 2, o
//!   pedido é do chamador (o flag 1 liga IncreaseMinimumSize), que espera
//!   o evento dele: sem prazo para um arquivo escolhido e um segundo
//!   (MiOneSecond) para qualquer arquivo (PageFileNumber 0xFF), e só se
//!   algum arquivo comum ainda não chegou ao máximo. Não pede quem é a
//!   própria thread de extensão nem quem não pode esperar. Vencido o prazo,
//!   o pedido sai da fila, ou, se a thread já trabalha nele, a cópia dela
//!   deixa de responder (ActiveEntry) e o resultado é zero. NoWait fica
//!   ligado em todo pedido que não espera com o prazo de um segundo.
//! - MiQueuePageFileExtension (rva 0x543d3c): o pedido entra na fila de
//!   extensões (PagefileExtensionListHead) e o semáforo do
//!   MMDEREFERENCE_SEGMENT_HEADER acorda a thread.
//! - A thread (no NT, a MiDereferenceSegmentThread, prioridade 19) tira o
//!   pedido da fila, trabalha numa cópia (as ActiveEntry ligam as duas),
//!   chama o MiExtendPagingFiles e, no MiProcessingPageExtendComplete (rva
//!   0x52a17c), devolve o ActualExpansion e sinaliza o evento do pedido; o
//!   estático só volta a InProgress 0.
//! - MiExtendPagingFiles (rva 0x8d05a0): com um arquivo escolhido, só ele,
//!   se o que falta até o máximo cobre o pedido (e IncreaseMinimumSize soma
//!   a extensão ao mínimo). Com qualquer arquivo, sem IgnoreCurrentCommit, o
//!   pedido vira o que passa do limite de commit (cobrado + a reserva do
//!   sistema + o pedido - o limite; se nada passa, ActualExpansion = 1 e
//!   nada cresce); os arquivos comuns, juntos, têm de cobrir o pedido, e
//!   crescem na ordem da lista até cobri-lo. O que cresceu sobe o limite de
//!   commit (MiIncreaseCommitLimits, sem mexer no limite máximo), menos o
//!   do arquivo de troca de working sets.
//! - MiAttemptPageFileExtension (rva 0x8d0274): o FileFsSizeInformation do
//!   volume; a extensão é o pedido, ou 16384 páginas (64 MB) se o pedido é
//!   menor, sem passar do máximo nem deixar menos de 256 MB livres no
//!   volume; o novo fim vai ao file system pelo IoSetInformation
//!   (FileEndOfFileInformation, na forma FILE_END_OF_FILE_INFORMATION_EX
//!   de 0x20 bytes, Flags 1, mais 4 sem NoWait). Recusado, tenta de novo
//!   com 4096 páginas (16 MB) no lugar das 16384. Aceito, o
//!   MiFinishPageFileExtension (`paging_file::finish_extension`).
//! - MiPageFileNoFreeSpace (rva 0x543b74): o modified page writer achou os
//!   arquivos cheios (AdriftMdls). Com o commit acima de 80% do limite e o
//!   limite abaixo do máximo (o MiCauseOverCommitPopup não existe aqui), o
//!   pedido estático é de uma página; senão, com 4096 páginas ou mais
//!   esperando o arquivo de paginação (TotalPagesForPagingFile, a lista de
//!   modificadas), do que passa do espaço livre. Os dois com
//!   IgnoreCurrentCommit, e só com o limite abaixo do máximo.
//!
//! Diferenças declaradas: a fila de pedidos de remoção de segmentos sem uso
//! (UnusedSegmentDeletion, o flag 8) não existe, nem o MiCauseOverCommitPopup;
//! a thread nasce com o primeiro arquivo de paginação, não no boot do Mm.
//! O OpenNT comita as páginas na hora da alocação e não tem a espera por
//! página livre do MiWaitForFreePage: quem grava páginas para conseguir
//! memória espera o pedido estático em curso terminar ([`wait_for_attempt`]),
//! e por isso o fim do pedido estático também sinaliza o evento dele.
//! Enquanto isso o corte do working set continua, com os arquivos cheios,
//! como o MmWorkingSetManager faria (`working_set::reclaim`), e a lista de
//! modificadas chega às 4096 páginas que o MiPageFileNoFreeSpace pede.

use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::ExtensionView;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{FileEndOfFileInformationEx, FileFsSizeInformation, Ksemaphore, LargeInteger, MmpageFileExpansion};
use crate::ntos::init::exports::invoke_handler;
use crate::ntos::ke::{dispatcher, irql};
use crate::ntos::mm::commit;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::process;
use crate::rtl::{sync, SpinLock};

/// PageFileNumber de qualquer arquivo.
pub const ANY_PAGE_FILE: u8 = 0xFF;
/// Flags do MiIssuePageExtendRequest.
pub const INCREASE_MINIMUM_SIZE: u32 = 1;
pub const STATIC_REQUEST: u32 = 2;
pub const IGNORE_CURRENT_COMMIT: u32 = 4;
const UNUSED_SEGMENT_DELETION: u32 = 8;
/// O pedido estático cresce em múltiplos de 4096 páginas.
const STATIC_GRANULARITY: u64 = 0x1000;
/// A extensão mínima da primeira tentativa (64 MB) e da segunda (16 MB).
const FIRST_MINIMUM: u64 = 0x4000;
const SECOND_MINIMUM: u64 = 0x1000;
/// O espaço que o volume guarda livre (256 MB).
const VOLUME_RESERVE: u64 = 0x1000_0000;
/// O TotalPagesForPagingFile a partir do qual o writer sem espaço pede.
const WAITING_PAGES_TO_REQUEST: u64 = 0x1000;
/// MiOneSecond.
const ONE_SECOND: i64 = -10_000_000;
/// A prioridade da MiDereferenceSegmentThread.
const THREAD_PRIORITY: u64 = 19;
const PAGE_SHIFT: u32 = 12;
const FILE_END_OF_FILE_INFORMATION: u64 = 0x14;
const FILE_FS_SIZE_INFORMATION: u64 = 3;
const STATUS_TIMEOUT: u32 = 0x102;
/// DISPATCHER_HEADER.Type de NotificationEvent.
const NOTIFICATION_EVENT: u8 = 0;

/// Os pedidos na fila (PagefileExtensionListHead). O lock é o
/// SegmentListLock da partição: guarda a fila, as ActiveEntry e o fim de
/// cada pedido.
static QUEUE: SpinLock<VecDeque<u64>> = SpinLock::new(VecDeque::new());
/// O semáforo do MMDEREFERENCE_SEGMENT_HEADER.
static SEMAPHORE: AtomicU64 = AtomicU64::new(0);
/// Modwriter.AttemptForCantExtend.
static STATIC: AtomicU64 = AtomicU64::new(0);
/// A cópia em que a thread trabalha.
static ACTIVE: AtomicU64 = AtomicU64::new(0);
/// O LARGE_INTEGER do MiOneSecond.
static TIMEOUT: AtomicU64 = AtomicU64::new(0);
/// O ETHREAD da thread de extensão.
static THREAD: AtomicU64 = AtomicU64::new(0);
static STARTED: AtomicBool = AtomicBool::new(false);

fn expansion(address: u64) -> &'static MmpageFileExpansion {
    // SAFETY: um MMPAGE_FILE_EXPANSION do pool deste módulo (o estático, a
    // cópia da thread ou o de quem espera, vivo enquanto ele espera).
    unsafe { MmpageFileExpansion::at(address) }
}

/// Um MMPAGE_FILE_EXPANSION zerado no pool, com o evento de notificação; 0
/// sem memória. O OpenNT não tem MI_PARTITION: Partition fica zero.
fn new_expansion() -> u64 {
    let address = guest::alloc_bytes(MmpageFileExpansion::SIZE);
    if address != 0 {
        guest::write_bytes(address, &[0u8; MmpageFileExpansion::SIZE as usize]);
        dispatcher::initialize_event(expansion(address).event.address(), NOTIFICATION_EVENT, false);
    }
    address
}

/// Os objetos e a thread, uma vez (com o primeiro arquivo de paginação).
pub fn start() {
    if STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let semaphore = guest::alloc_bytes(Ksemaphore::SIZE);
    let timeout = guest::alloc_bytes(LargeInteger::SIZE);
    let (fixed, active) = (new_expansion(), new_expansion());
    if semaphore == 0 || timeout == 0 || fixed == 0 || active == 0 {
        crate::debug_print!("[mm] extensao de arquivos de paginacao sem memoria");
        return;
    }
    dispatcher::initialize_semaphore(semaphore, 0, i32::MAX as u32);
    // SAFETY: LARGE_INTEGER recém-alocado.
    unsafe { LargeInteger::at(timeout) }.quad_part.set(ONE_SECOND);
    // MiInitializeCommitment: qualquer arquivo, AttemptForCantExtend, um
    // pedido de uma página.
    let request = expansion(fixed);
    request.requested_expansion_size.set(1);
    request.u1.flags.set_page_file_number(ANY_PAGE_FILE);
    request.u1.flags.set_attempt_for_cant_extend(1);
    SEMAPHORE.store(semaphore, Ordering::Release);
    TIMEOUT.store(timeout, Ordering::Release);
    STATIC.store(fixed, Ordering::Release);
    ACTIVE.store(active, Ordering::Release);
    let entry: extern "win64" fn(u64) = extension_thread;
    let started = crate::ntos::mm::kernel_address::image_address(entry as usize as u64).and_then(|start| crate::ntos::ps::kernel_threads::create_system_thread(0, start, 0, 0x1F_FFFF, 0, None));
    match started {
        Ok(handle) => {
            THREAD.store(crate::ntos::ps::kernel_threads::of_handle(handle).unwrap_or(0), Ordering::Release);
            let _ = crate::ntos::ob::object_manager::close(handle as u32);
        }
        Err(error) => crate::debug_print!("[mm] thread de extensao de arquivos de paginacao nao criada: {}", error),
    }
}

/// Quem pode esperar um pedido: não a própria thread de extensão, e só
/// abaixo de DISPATCH_LEVEL, sem spin lock retido.
fn may_wait() -> bool {
    process::get_current_thread() != THREAD.load(Ordering::Acquire) && irql::get_irql() < irql::DISPATCH_LEVEL && sync::spin_locks_held() == 0
}

/// MiQueuePageFileExtension: o pedido entra na fila e o semáforo acorda a
/// thread.
fn queue(request: u64) {
    QUEUE.lock().push_back(request);
    let _ = dispatcher::release_semaphore(SEMAPHORE.load(Ordering::Acquire), 1);
}

/// Quantos pedidos estáticos entraram na fila e quantos a thread terminou
/// (o OpenNT acompanha para [`wait_for_attempt`]; mudam com o lock da fila).
static STATIC_ISSUED: AtomicU64 = AtomicU64::new(0);
static STATIC_COMPLETED: AtomicU64 = AtomicU64::new(0);

/// O pedido estático (o caminho com o flag 2 do MiIssuePageExtendRequest):
/// nada se já há um em curso.
fn issue_static(pages: u64, flags: u32) {
    let fixed = STATIC.load(Ordering::Acquire);
    let request = expansion(fixed);
    {
        let mut queued = QUEUE.lock();
        if request.in_progress.atomic().compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return;
        }
        request.requested_expansion_size.set(pages.div_ceil(STATIC_GRANULARITY) * STATIC_GRANULARITY);
        request.u1.flags.set_ignore_current_commit((flags & IGNORE_CURRENT_COMMIT != 0) as u8);
        request.u1.flags.set_unused_segment_deletion(0);
        request.u1.flags.set_no_wait(1);
        request.actual_expansion.set(0);
        request.active_entry.set(0);
        dispatcher::reset_event(request.event.address());
        STATIC_ISSUED.fetch_add(1, Ordering::AcqRel);
        queued.push_back(fixed);
    }
    let _ = dispatcher::release_semaphore(SEMAPHORE.load(Ordering::Acquire), 1);
}

/// MiIssuePageExtendRequest(Partition, Pages, Flags, PageFileNumber):
/// `true` se o pedido esperado cresceu algum arquivo (ActualExpansion
/// diferente de zero). O pedido estático nunca é esperado aqui e dá `false`.
pub fn issue_request(pages: u64, flags: u32, page_file_number: u8) -> bool {
    let semaphore = SEMAPHORE.load(Ordering::Acquire);
    let thread = THREAD.load(Ordering::Acquire);
    if semaphore == 0 || thread == 0 || flags & UNUSED_SEGMENT_DELETION != 0 {
        return false;
    }
    if flags & STATIC_REQUEST != 0 {
        issue_static(pages, flags);
        return false;
    }
    if !may_wait() {
        return false;
    }
    let files = super::extension_views();
    let timed = page_file_number as usize >= files.len();
    if timed && !files.iter().any(|file| !file.working_set_swap && file.size < file.maximum) {
        return false;
    }
    let address = new_expansion();
    if address == 0 {
        return false;
    }
    let request = expansion(address);
    request.requested_expansion_size.set(pages);
    request.in_progress.set(1);
    request.u1.flags.set_page_file_number(page_file_number);
    request.u1.flags.set_increase_minimum_size((flags & INCREASE_MINIMUM_SIZE != 0) as u8);
    request.u1.flags.set_no_wait((!timed) as u8);
    queue(address);
    let timeout = if timed { TIMEOUT.load(Ordering::Acquire) } else { 0 };
    if dispatcher::wait_for_single_object(request.event.address(), timeout, 0, false) == STATUS_TIMEOUT {
        let mut queued = QUEUE.lock();
        if dispatcher::read_state(request.event.address()) == 0 {
            match request.active_entry.get() {
                0 => queued.retain(|&candidate| candidate != address),
                // A cópia em curso não responde mais a este pedido.
                copy => expansion(copy).active_entry.set(0),
            }
            request.actual_expansion.set(0);
        }
    }
    let grew = request.actual_expansion.get() != 0;
    guest::free_bytes(address);
    grew
}

/// Quem grava páginas para conseguir memória espera o pedido estático em
/// curso terminar (o papel da espera por página livre do NT); `true` se
/// algum arquivo comum tem espaço livre depois disso.
pub fn wait_for_attempt() -> bool {
    let fixed = STATIC.load(Ordering::Acquire);
    if fixed == 0 || !may_wait() {
        return false;
    }
    let request = expansion(fixed);
    let target = {
        let _queued = QUEUE.lock();
        (request.in_progress.get() != 0).then(|| STATIC_ISSUED.load(Ordering::Acquire))
    };
    if let Some(target) = target {
        while STATIC_COMPLETED.load(Ordering::Acquire) < target {
            dispatcher::wait_for_single_object(request.event.address(), 0, 0, false);
        }
    }
    super::free_pages() > 0
}

/// Algum arquivo comum ainda pode crescer: abaixo do máximo, com o limite
/// de commit abaixo do limite máximo.
pub fn can_grow() -> bool {
    let commitment = commit::snapshot();
    commitment.limit < commitment.limit_maximum && super::extension_views().iter().any(|file| !file.working_set_swap && file.size < file.maximum)
}

/// A thread de extensão: espera o semáforo, atende um pedido por vez.
extern "win64" fn extension_thread(_context: u64) {
    let _ = crate::ntos::ke::thread_priority::set_priority(process::get_current_thread(), THREAD_PRIORITY);
    loop {
        dispatcher::wait_for_single_object(SEMAPHORE.load(Ordering::Acquire), 0, 0, false);
        process_one();
    }
}

/// Um pedido da fila: a cópia, o MiExtendPagingFiles e o
/// MiProcessingPageExtendComplete.
fn process_one() {
    let active = ACTIVE.load(Ordering::Acquire);
    let local = expansion(active);
    let request = {
        let mut queued = QUEUE.lock();
        let Some(address) = queued.pop_front() else { return };
        let request = expansion(address);
        local.requested_expansion_size.set(request.requested_expansion_size.get());
        local.actual_expansion.set(0);
        local.u1.long_flags.set(request.u1.long_flags.get());
        local.active_entry.set(address);
        request.active_entry.set(active);
        address
    };
    extend_paging_files(local);
    let original = expansion(request);
    let _queued = QUEUE.lock();
    if local.u1.flags.attempt_for_cant_extend() != 0 {
        original.in_progress.atomic().swap(0, Ordering::AcqRel);
        STATIC_COMPLETED.fetch_add(1, Ordering::AcqRel);
        dispatcher::set_event(original.event.address());
    } else if local.active_entry.get() != 0 {
        original.actual_expansion.set(local.actual_expansion.get());
        dispatcher::set_event(original.event.address());
    }
    local.active_entry.set(0);
}

/// MiExtendPagingFiles(PageExpand).
fn extend_paging_files(request: &MmpageFileExpansion) {
    let files = super::extension_views();
    if files.is_empty() {
        return;
    }
    let mut wanted = request.requested_expansion_size.get();
    let number = request.u1.flags.page_file_number() as usize;
    let (extended, raises_limit) = if let Some(file) = files.get(number) {
        if file.maximum - file.size < wanted {
            return;
        }
        let extended = attempt_extension(request, file, wanted);
        if extended != 0 && request.u1.flags.increase_minimum_size() != 0 {
            super::update_minimum(file.number, extended);
        }
        (extended, !file.working_set_swap)
    } else {
        if request.u1.flags.ignore_current_commit() == 0 {
            let commitment = commit::snapshot();
            let Some(needed) = commitment.committed.checked_add(commit::system_commit_reserve()).and_then(|total| total.checked_add(wanted)) else { return };
            if needed <= commitment.limit {
                request.actual_expansion.set(1);
                return;
            }
            wanted = needed - commitment.limit;
        }
        let ordinary = || files.iter().filter(|file| !file.working_set_swap);
        if ordinary().map(|file| file.maximum - file.size).sum::<u64>() < wanted {
            return;
        }
        let mut extended = 0;
        for file in ordinary() {
            extended += attempt_extension(request, file, wanted - extended);
            if extended >= wanted {
                break;
            }
        }
        (extended, true)
    };
    if extended == 0 {
        return;
    }
    request.actual_expansion.set(extended);
    if raises_limit {
        commit::increase_limits(extended, 0);
    }
}

/// Os blocos do MiAttemptPageFileExtension: o FileFsSizeInformation, o
/// tamanho devolvido e o FILE_END_OF_FILE_INFORMATION_EX.
struct Buffers {
    block: u64,
}

const SIZE_INFORMATION: u64 = 0;
const RETURNED: u64 = 0x18;
const END_OF_FILE: u64 = 0x20;
const BUFFERS_SIZE: u64 = 0x40;

impl Buffers {
    fn new() -> Option<Self> {
        let block = guest::alloc_bytes(BUFFERS_SIZE);
        (block != 0).then_some(Self { block })
    }

    fn size_information(&self) -> &FileFsSizeInformation {
        // SAFETY: dentro do bloco, do tamanho da estrutura.
        unsafe { FileFsSizeInformation::at(self.block + SIZE_INFORMATION) }
    }

    fn end_of_file(&self) -> &FileEndOfFileInformationEx {
        // SAFETY: dentro do bloco, do tamanho da estrutura.
        unsafe { FileEndOfFileInformationEx::at(self.block + END_OF_FILE) }
    }
}

impl Drop for Buffers {
    fn drop(&mut self) {
        guest::free_bytes(self.block);
    }
}

fn status_of(name: &str, arguments: &[u64]) -> u32 {
    match invoke_handler(name, arguments) {
        Ok(value) => value as u32,
        Err(error) if error.status != 0 => error.status,
        Err(_) => 0xC000_0001,
    }
}

/// MiAttemptPageFileExtension(PageExpand, PagingFile, SizeNeeded): as
/// páginas que o arquivo cresceu.
fn attempt_extension(request: &MmpageFileExpansion, file: &ExtensionView, needed: u64) -> u64 {
    // O tamanho de agora: a extensão anterior do mesmo pedido já pode ter
    // mudado a lista.
    let Some(file) = super::extension_views().into_iter().find(|candidate| candidate.number == file.number) else { return 0 };
    if file.size == file.maximum {
        return 0;
    }
    let Some(buffers) = Buffers::new() else { return 0 };
    let information = buffers.size_information();
    if status_of("IoQueryVolumeInformation", &[file.file_object, FILE_FS_SIZE_INFORMATION, FileFsSizeInformation::SIZE, information.address(), buffers.block + RETURNED]) & 0x8000_0000 != 0 {
        return 0;
    }
    let cluster = information.bytes_per_sector.get().wrapping_mul(information.sectors_per_allocation_unit.get()) as u64;
    let free = cluster.wrapping_mul(information.available_allocation_units.quad_part.get() as u64);
    let mut minimum = FIRST_MINIMUM;
    loop {
        let (wanted, pass_minimum) = if needed >= minimum { (needed, SECOND_MINIMUM) } else { (minimum, minimum) };
        let mut extension = wanted.min(file.maximum - file.size);
        if free <= VOLUME_RESERVE {
            return 0;
        }
        extension = extension.min((free - VOLUME_RESERVE) >> PAGE_SHIFT);
        if file.working_set_swap && extension < needed {
            return 0;
        }
        let end_of_file = buffers.end_of_file();
        end_of_file.end_of_file.quad_part.set(((file.size + extension) << PAGE_SHIFT) as i64);
        end_of_file.paging_file_size_in_mm.quad_part.set((file.size << PAGE_SHIFT) as i64);
        end_of_file.paging_file_max_size.quad_part.set((file.maximum << PAGE_SHIFT) as i64);
        end_of_file.flags.set(if request.u1.flags.no_wait() != 0 { 1 } else { 5 });
        if status_of("IoSetInformation", &[file.file_object, FILE_END_OF_FILE_INFORMATION, FileEndOfFileInformationEx::SIZE, end_of_file.address()]) == 0 {
            if super::finish_extension(file.number, extension) {
                // RescanPageFilesEvent.
                crate::ntos::mm::modified_writer::wake();
            }
            crate::debug_print!("[mm] arquivo de paginacao {} cresceu {} paginas ({} de {})", file.number, extension, file.size + extension, file.maximum);
            return extension;
        }
        if pass_minimum == SECOND_MINIMUM {
            return 0;
        }
        minimum = SECOND_MINIMUM;
    }
}

/// MiPageFileNoFreeSpace: o modified page writer não achou espaço em
/// nenhum arquivo, com `waiting` páginas na lista de modificadas
/// (TotalPagesForPagingFile).
pub fn page_file_no_free_space(waiting: u64) {
    if !super::mark_full_files_adrift() {
        return;
    }
    let commitment = commit::snapshot();
    let committed = commitment.committed.min(commitment.limit);
    let pages = if committed > commitment.limit / 10 * 8 && commitment.limit < commitment.limit_maximum {
        1
    } else {
        if waiting < WAITING_PAGES_TO_REQUEST {
            return;
        }
        let free = super::free_pages();
        if waiting <= free {
            return;
        }
        waiting - free
    };
    if commitment.limit < commitment.limit_maximum {
        issue_request(pages, STATIC_REQUEST | IGNORE_CURRENT_COMMIT, 0);
    }
}
