//! EOF lock e mutex do cabeçalho de FCB — FsRtl do NT (ntoskrnl 19045:
//! FsRtlInitializeEofLock 0x302e10, FsRtlAcquireEofLock 0x2ee090,
//! FsRtlReleaseEofLock 0x26f300, FsRtlGetIoAtEof 0x2ee000,
//! FsRtlpWaitForIoAtEof 0x2ee2cc, FsRtlAcquireHeaderMutex 0x2c9760,
//! FsRtlReleaseHeaderMutex 0x2c9230, FsRtlTryToAcquireHeaderMutex 0x2e0ed0).
//!
//! O EOF lock serializa as E/S que estendem o arquivo (escrita em
//! FILE_WRITE_TO_END_OF_FILE ou além de FileSize). É uma estrutura de 0x28
//! bytes que o file system embute no seu SCB/FCB e liga a um
//! FSRTL_ADVANCED_FCB_HEADER; todo o estado é protegido pelo FAST_MUTEX do
//! cabeçalho (`Header->FastMutex`). O layout ([`EofLock`], [`EofWaitBlock`])
//! não está nos cabeçalhos públicos: veio da desmontagem e é privado do
//! FsRtl.
//!
//! O contador opcional (`PULONG`, 2º argumento de todas as rotinas) é
//! incrementado atomicamente a cada aquisição e a cada liberação do mutex do
//! cabeçalho, exatamente como no NT.
//!
//! Diferença declarada: o NT eleva a prioridade do dono (KeSetPriorityBoost,
//! PsBoostThreadIoEx/IoBoostThreadIoPriority). O OpenNT não tem impulso
//! temporário de prioridade nem de E/S; as prioridades são registradas nos
//! mesmos campos, mas nenhuma elevação é aplicada e `owner_io_boosted` nunca
//! é ligado aqui. A ordem de posse e o despertar são os do NT.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::extra_fsrtl::FsrtlAdvancedFcbHeader;
use crate::ntos::inc::types::{Eprocess, Ethread, Kevent, ListEntry};
use crate::ntos::ke::{dispatcher, fast_mutex, thread_priority};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::process;
use crate::rtl::KernelError;

/// EOF lock do FsRtl (0x28 bytes, embutido no SCB/FCB do file system).
#[repr(C)]
pub struct EofLock {
    /// -> `_KTHREAD` com a E/S no fim do arquivo.
    pub owner: Field<u64>,
    /// Blocos [`EofWaitBlock`] em FIFO.
    pub wait_list: ListEntry,
    /// -> `_FSRTL_ADVANCED_FCB_HEADER`
    pub header: Field<u64>,
    /// Prioridade herdada pelo dono.
    pub owner_priority: Field<u32>,
    pub owner_io_boosted: Field<u8>,
    _pad_25: Reserved<0x1>,
    pub recursion: Field<u16>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for EofLock {}

/// Bloco de espera (na pilha do aguardante no NT, 0x40 bytes).
#[repr(C)]
pub struct EofWaitBlock {
    pub links: ListEntry,
    /// Evento de sincronização sinalizado na liberação.
    pub event: Kevent,
    pub ending_offset: Field<i64>,
    /// -> `_KTHREAD`
    pub thread: Field<u64>,
    pub priority: Field<u32>,
    pub io_priority: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for EofWaitBlock {}

const _: () = {
    assert!(core::mem::size_of::<EofLock>() == 0x28);
    assert!(core::mem::offset_of!(EofLock, wait_list) == 0x8);
    assert!(core::mem::offset_of!(EofLock, header) == 0x18);
    assert!(core::mem::offset_of!(EofLock, owner_priority) == 0x20);
    assert!(core::mem::offset_of!(EofLock, owner_io_boosted) == 0x24);
    assert!(core::mem::offset_of!(EofLock, recursion) == 0x26);
    assert!(core::mem::size_of::<EofWaitBlock>() == 0x40);
    assert!(core::mem::offset_of!(EofWaitBlock, event) == 0x10);
    assert!(core::mem::offset_of!(EofWaitBlock, ending_offset) == 0x28);
    assert!(core::mem::offset_of!(EofWaitBlock, thread) == 0x30);
    assert!(core::mem::offset_of!(EofWaitBlock, priority) == 0x38);
    assert!(core::mem::offset_of!(EofWaitBlock, io_priority) == 0x3c);
};

const SYNCHRONIZATION_EVENT: u8 = 1;
const STATUS_FILE_LOCK_CONFLICT: u32 = 0xC000_0054;
/// IoPriorityNormal e o teto de prioridade usado pelo NT.
const IO_PRIORITY_NORMAL: u32 = 2;
const PRIORITY_CEILING: i32 = 15;

/// O `PULONG Counter` opcional dos exports (NULL = sem contador).
///
/// # Safety
/// `address` é NULL ou aponta para um ULONG do file system.
pub unsafe fn optional_counter(address: u64) -> Option<&'static Field<u32>> {
    // SAFETY: garantido pelo chamador.
    (address != 0).then(|| unsafe { Field::<u32>::at(address) })
}

impl EofLock {
    fn header(&self) -> &FsrtlAdvancedFcbHeader {
        // SAFETY: ligado por FsRtlInitializeEofLock ao cabeçalho do mesmo FCB.
        unsafe { FsrtlAdvancedFcbHeader::at(self.header.get()) }
    }

    fn fast_mutex(&self) -> u64 {
        self.header().fast_mutex.get()
    }

    fn file_size(&self) -> i64 {
        self.header().file_size.quad_part.get()
    }

    fn waiters(&self) -> u64 {
        self.wait_list.address()
    }
}

fn wait_block(links: u64) -> &'static EofWaitBlock {
    // SAFETY: entradas da lista do EOF lock são blocos de espera (links em +0).
    unsafe { EofWaitBlock::at(links) }
}

fn list_entry(address: u64) -> &'static ListEntry {
    // SAFETY: nós de LIST_ENTRY da lista do EOF lock.
    unsafe { ListEntry::at(address) }
}

/// `lock inc dword ptr [Counter]` quando o contador foi fornecido.
fn bump(counter: Option<&Field<u32>>) {
    if let Some(counter) = counter {
        counter.atomic().fetch_add(1, Ordering::SeqCst);
    }
}

fn remove_entry(entry: &ListEntry) {
    list_entry(entry.blink.get()).flink.set(entry.flink.get());
    list_entry(entry.flink.get()).blink.set(entry.blink.get());
}

fn insert_tail(head: &ListEntry, entry: &ListEntry) {
    let tail = head.blink.get();
    entry.flink.set(head.address());
    entry.blink.set(tail);
    list_entry(tail).flink.set(entry.address());
    head.blink.set(entry.address());
}

/// PsGetIoPriorityThread (0x242180): CrossThreadFlags.ThreadIoPriority, zero
/// para processo em segundo plano, e Normal para a thread corrente com
/// IoBoostCount pendente.
fn io_priority(thread: &Ethread) -> u32 {
    let mut priority = thread.thread_io_priority();
    let owner = thread.tcb.process.get();
    // SAFETY: KTHREAD.Process de uma thread viva.
    if owner != 0 && unsafe { Eprocess::at(owner) }.background() != 0 {
        priority = 0;
    }
    if priority < IO_PRIORITY_NORMAL && thread.address() == process::get_current_thread() && thread.io_boost_count.get() != 0 {
        return IO_PRIORITY_NORMAL;
    }
    priority
}

/// FsRtlInitializeEofLock(EofLock, AdvancedHeader): dono nulo, lista vazia,
/// cabeçalho e os campos de prioridade/recursão zerados.
pub fn initialize(eof_lock: &EofLock, header: &FsrtlAdvancedFcbHeader) {
    eof_lock.owner.set(0);
    eof_lock.wait_list.flink.set(eof_lock.waiters());
    eof_lock.wait_list.blink.set(eof_lock.waiters());
    eof_lock.header.set(header.address());
    eof_lock.owner_priority.set(0);
    eof_lock.owner_io_boosted.set(0);
    eof_lock.recursion.set(0);
}

/// FsRtlAcquireHeaderMutex: ExAcquireFastMutex(Header->FastMutex) e conta.
pub fn acquire_header_mutex(eof_lock: &EofLock, counter: Option<&Field<u32>>) -> Result<(), KernelError> {
    fast_mutex::acquire(eof_lock.fast_mutex())?;
    bump(counter);
    Ok(())
}

/// FsRtlReleaseHeaderMutex: conta antes de liberar o FAST_MUTEX.
pub fn release_header_mutex(eof_lock: &EofLock, counter: Option<&Field<u32>>) -> Result<(), KernelError> {
    bump(counter);
    fast_mutex::release(eof_lock.fast_mutex())?;
    Ok(())
}

/// FsRtlTryToAcquireHeaderMutex: só conta quando a tentativa vence.
pub fn try_to_acquire_header_mutex(eof_lock: &EofLock, counter: Option<&Field<u32>>) -> Result<bool, KernelError> {
    let acquired = fast_mutex::try_acquire(eof_lock.fast_mutex())? != 0;
    if acquired {
        bump(counter);
    }
    Ok(acquired)
}

/// FsRtlpWaitForIoAtEof, chamado com o mutex do cabeçalho na mão: registra a
/// prioridade, enfileira um bloco no fim da lista, solta o mutex, espera o
/// evento e o readquire. TRUE quando a thread recebeu a posse (E/S ainda
/// além do fim do arquivo); FALSE quando a E/S deixou de estender o arquivo.
fn wait_for_io_at_eof(eof_lock: &EofLock, counter: Option<&Field<u32>>, ending_offset: i64) -> Result<bool, KernelError> {
    let current = process::get_current_thread();
    // SAFETY: a thread corrente.
    let io_priority = io_priority(unsafe { Ethread::at(current) }).min(IO_PRIORITY_NORMAL);
    let priority = thread_priority::query_priority(current).min(PRIORITY_CEILING);
    if priority > eof_lock.owner_priority.get() as i32 {
        eof_lock.owner_priority.set(priority as u32);
    }
    // Herança para os aguardantes à frente, do fim para o começo, até achar
    // um que já tenha prioridades iguais ou maiores.
    let head = eof_lock.waiters();
    let mut links = eof_lock.wait_list.blink.get();
    while links != head {
        let waiter = wait_block(links);
        let (waiting_priority, waiting_io) = (waiter.priority.get() as i32, waiter.io_priority.get());
        if waiting_priority >= priority && waiting_io >= io_priority {
            break;
        }
        waiter.priority.set(waiting_priority.max(priority) as u32);
        waiter.io_priority.set(waiting_io.max(io_priority));
        links = waiter.links.blink.get();
    }
    let address = guest::alloc_bytes(core::mem::size_of::<EofWaitBlock>() as u64);
    let block = wait_block(address);
    dispatcher::initialize_event(block.event.address(), SYNCHRONIZATION_EVENT, false);
    block.ending_offset.set(ending_offset);
    block.thread.set(current);
    block.priority.set(priority as u32);
    block.io_priority.set(io_priority);
    insert_tail(&eof_lock.wait_list, &block.links);
    release_header_mutex(eof_lock, counter)?;
    dispatcher::wait_for_single_object(block.event.address(), 0, 0, false);
    guest::free_bytes(address);
    acquire_header_mutex(eof_lock, counter)?;
    Ok(ending_offset < 0 || ending_offset > eof_lock.file_size())
}

/// FsRtlGetIoAtEof(EofLock, Counter, StartingOffset, Length, Wait, *IoAtEof),
/// com o mutex do cabeçalho já adquirido: recursão do dono soma; lock livre
/// passa ao chamador; ocupado espera (Wait) ou devolve
/// STATUS_FILE_LOCK_CONFLICT. `*IoAtEof` diz se o chamador ficou com a posse.
pub fn get_io_at_eof(eof_lock: &EofLock, counter: Option<&Field<u32>>, starting_offset: i64, length: u64, wait: bool, io_at_eof: &Field<u8>) -> Result<u32, KernelError> {
    let current = process::get_current_thread();
    let owner = eof_lock.owner.get();
    if owner == current {
        eof_lock.recursion.set(eof_lock.recursion.get().wrapping_add(1));
        io_at_eof.set(1);
        return Ok(0);
    }
    let ending_offset = if starting_offset < 0 { starting_offset } else { starting_offset.wrapping_add(length as i64) };
    if owner == 0 {
        eof_lock.owner.set(current);
        eof_lock.recursion.set(1);
        io_at_eof.set(1);
        return Ok(0);
    }
    if !wait {
        return Ok(STATUS_FILE_LOCK_CONFLICT);
    }
    let granted = wait_for_io_at_eof(eof_lock, counter, ending_offset)?;
    io_at_eof.set(granted as u8);
    Ok(0)
}

/// FsRtlAcquireEofLock(EofLock, Counter): posse incondicional (EndingOffset
/// -1) sob o mutex do cabeçalho; recursão do dono soma.
pub fn acquire(eof_lock: &EofLock, counter: Option<&Field<u32>>) -> Result<(), KernelError> {
    acquire_header_mutex(eof_lock, counter)?;
    let current = process::get_current_thread();
    let owner = eof_lock.owner.get();
    if owner == current {
        eof_lock.recursion.set(eof_lock.recursion.get().wrapping_add(1));
    } else if owner == 0 {
        eof_lock.owner.set(current);
        eof_lock.recursion.set(1);
    } else {
        wait_for_io_at_eof(eof_lock, counter, -1)?;
    }
    release_header_mutex(eof_lock, counter)
}

/// FsRtlReleaseEofLock(EofLock, Counter). Na última liberação percorre a
/// lista em ordem: o primeiro aguardante cuja E/S ainda passa do FileSize
/// atual (ou é escrita no fim) vira o dono; os que agora ficam dentro do
/// arquivo são despertados sem posse; os demais continuam na fila. Os
/// eventos são sinalizados depois de soltar o mutex do cabeçalho, o novo
/// dono primeiro.
pub fn release(eof_lock: &EofLock, counter: Option<&Field<u32>>) -> Result<(), KernelError> {
    acquire_header_mutex(eof_lock, counter)?;
    let remaining = eof_lock.recursion.get().wrapping_sub(1);
    eof_lock.recursion.set(remaining);
    if remaining != 0 {
        return release_header_mutex(eof_lock, counter);
    }
    let size = eof_lock.file_size();
    // Sem impulso de E/S aplicado (ver cabeçalho): apenas desliga a marca.
    eof_lock.owner_io_boosted.set(0);
    let head = eof_lock.waiters();
    let mut next_owner: Option<&EofWaitBlock> = None;
    let mut wake: Vec<&EofWaitBlock> = Vec::new();
    let mut links = eof_lock.wait_list.flink.get();
    while links != head {
        let waiter = wait_block(links);
        links = waiter.links.flink.get();
        let ending = waiter.ending_offset.get();
        if ending >= 0 && ending <= size {
            remove_entry(&waiter.links);
            wake.push(waiter);
        } else if next_owner.is_none() {
            remove_entry(&waiter.links);
            next_owner = Some(waiter);
        }
    }
    match next_owner {
        Some(waiter) => {
            eof_lock.owner.set(waiter.thread.get());
            eof_lock.recursion.set(1);
            eof_lock.owner_priority.set(waiter.priority.get());
            wake.insert(0, waiter);
        }
        None => {
            eof_lock.owner.set(0);
            eof_lock.recursion.set(0);
            eof_lock.owner_priority.set(0);
        }
    }
    release_header_mutex(eof_lock, counter)?;
    for waiter in wake {
        dispatcher::set_event(waiter.event.address());
    }
    Ok(())
}
