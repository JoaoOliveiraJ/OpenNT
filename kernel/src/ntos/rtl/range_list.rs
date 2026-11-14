//! Listas de faixas (RTL_RANGE_LIST): o pacote que os árbitros de recursos
//! dos drivers de barramento usam para portas, memória e números de
//! barramento.
//!
//! Mesmo formato e algoritmo do ntoskrnl 19041 (as instruções de cada
//! rotina): a lista é ordenada por início, e faixas de topo nunca se
//! sobrepõem; uma faixa nova que cruza outras transforma a primeira numa
//! faixa **fundida** (`RTLP_RANGE_LIST_ENTRY_MERGED`), cuja sublista guarda
//! as faixas originais ordenadas por início e cujo intervalo cobre todas
//! elas. As entradas (`_RTLP_RANGE_LIST_ENTRY`, 0x38 bytes) vêm do pool
//! paginado com a tag 'RRle' (a lookaside do RtlInitializeRangeListPackage);
//! os iteradores entregam o `RTL_RANGE` no início de cada entrada, nunca a
//! cabeça de uma fundida. O chamador sincroniza a lista, como no NT.
//!
//! A bandeira 0x10 do RtlAddRange marca uma faixa cujo `UserData` aponta
//! para um contador ULONG de referências em pool: cada cópia da entrada o
//! incrementa e cada liberação o decrementa, devolvendo o bloco ao pool no
//! zero.

use core::cell::UnsafeCell;
use core::mem::offset_of;

use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::extra_rtl::{RtlRangeList, RtlRangeListIterator, RtlpRangeListEntry};
use crate::ntos::inc::types::ListEntry;
use crate::ntos::ke::bugcheck;

/// RtlAddRange: aceita a faixa mesmo em conflito (marcando os dois lados).
pub const RTL_RANGE_LIST_ADD_IF_CONFLICT: u32 = 1;
/// RtlAddRange: a faixa pode ser dividida com outras compartilhadas.
pub const RTL_RANGE_LIST_ADD_SHARED: u32 = 2;
/// RtlFindRange/RtlIsRangeAvailable: faixas compartilhadas não conflitam.
pub const RTL_RANGE_LIST_SHARED_OK: u32 = 1;
/// RtlFindRange/RtlIsRangeAvailable: faixas sem dono não conflitam.
pub const RTL_RANGE_LIST_NULL_CONFLICT_OK: u32 = 2;

/// `RTL_RANGE.Flags`.
const RTL_RANGE_SHARED: u8 = 1;
const RTL_RANGE_CONFLICT: u8 = 2;
/// Bandeira privada de `PublicFlags`: `UserData` é um contador de referências.
const RANGE_USER_DATA_COUNTED: u8 = 0x10;
/// `PrivateFlags`: a entrada é a cabeça de uma faixa fundida.
const RTLP_RANGE_LIST_ENTRY_MERGED: u16 = 1;

const ENTRY_TAG: u32 = u32::from_le_bytes(*b"RRle");
const PAGED_POOL: u32 = 1;
const LINK: u64 = offset_of!(RtlpRangeListEntry, list_entry) as u64;

const STATUS_SUCCESS: u32 = 0;
const STATUS_NO_MORE_ENTRIES: u32 = 0x8000_001A;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_RANGE_LIST_CONFLICT: u32 = 0xC000_0282;
const STATUS_RANGE_NOT_FOUND: u32 = 0xC000_028C;

/// KERNEL_SECURITY_CHECK_FAILURE / FAST_FAIL_CORRUPT_LIST_ENTRY (o `int 0x29`).
fn corrupt_list() -> ! {
    bugcheck::bug_check_ex(0x139, 3, 0, 0, 0)
}

fn failed(status: u32) -> bool {
    (status as i32) < 0
}

fn entry(address: u64) -> &'static RtlpRangeListEntry {
    // SAFETY: entradas vivas de uma lista do chamador ou recém-alocadas.
    unsafe { RtlpRangeListEntry::at(address) }
}

fn entry_of_link(link: u64) -> &'static RtlpRangeListEntry {
    entry(link - LINK)
}

fn link(address: u64) -> &'static ListEntry {
    // SAFETY: os vínculos de uma lista viva apontam para LIST_ENTRYs vivas.
    unsafe { ListEntry::at(address) }
}

fn counter(address: u64) -> &'static Field<u32> {
    // SAFETY: o UserData de uma faixa com RANGE_USER_DATA_COUNTED é o ULONG
    // de referências que o chamador alocou.
    unsafe { Field::<u32>::at(address) }
}

fn is_merged(range: &RtlpRangeListEntry) -> bool {
    range.private_flags.get() & RTLP_RANGE_LIST_ENTRY_MERGED != 0
}

fn shared(range: &RtlpRangeListEntry) -> bool {
    range.public_flags.get() & RTL_RANGE_SHARED != 0
}

fn initialize_head(head: &ListEntry) {
    head.flink.set(head.address());
    head.blink.set(head.address());
}

/// RemoveEntryList com a checagem de integridade.
fn remove(entry: &ListEntry) {
    let (flink, blink) = (entry.flink.get(), entry.blink.get());
    if link(flink).blink.get() != entry.address() || link(blink).flink.get() != entry.address() {
        corrupt_list();
    }
    link(blink).flink.set(flink);
    link(flink).blink.set(blink);
}

/// InsertTailList com a checagem de integridade.
fn insert_tail(head: &ListEntry, entry: &ListEntry) {
    let last = head.blink.get();
    if link(last).flink.get() != head.address() {
        corrupt_list();
    }
    entry.flink.set(head.address());
    entry.blink.set(last);
    link(last).flink.set(entry.address());
    head.blink.set(entry.address());
}

/// Insere `entry` logo depois de `previous` (sem checagem, como o original).
fn insert_after(previous: &ListEntry, entry: &ListEntry) {
    let next = previous.flink.get();
    entry.flink.set(next);
    entry.blink.set(previous.address());
    link(next).blink.set(entry.address());
    previous.flink.set(entry.address());
}

/// Interseção de intervalos fechados.
fn overlaps(range: &RtlpRangeListEntry, other: &RtlpRangeListEntry) -> bool {
    range.start.get() <= other.end.get() && other.start.get() <= range.end.get()
}

fn allocate_entry() -> Option<&'static RtlpRangeListEntry> {
    let block = pool_allocation::allocate_tagged(PAGED_POOL, RtlpRangeListEntry::SIZE, ENTRY_TAG).unwrap_or(0);
    (block != 0).then(|| entry(block))
}

/// A cópia rasa dos 0x38 bytes da entrada.
fn copy_fields(source: &RtlpRangeListEntry, target: &RtlpRangeListEntry) {
    target.start.set(source.start.get());
    target.end.set(source.end.get());
    target.user_data.set(source.user_data.get());
    target.owner.set(source.owner.get());
    target.attributes.set(source.attributes.get());
    target.public_flags.set(source.public_flags.get());
    target.private_flags.set(source.private_flags.get());
    target.list_entry.flink.set(source.list_entry.flink.get());
    target.list_entry.blink.set(source.list_entry.blink.get());
}

fn reference_user_data(range: &RtlpRangeListEntry) {
    if range.public_flags.get() & RANGE_USER_DATA_COUNTED != 0 {
        counter(range.user_data.get()).atomic().fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    }
}

/// RtlpCreateRangeListEntry.
fn create_entry(start: u64, end: u64, attributes: u8, user_data: u64, owner: u64) -> Option<&'static RtlpRangeListEntry> {
    let range = allocate_entry()?;
    range.public_flags.set(0);
    range.private_flags.set(0);
    range.owner.set(owner);
    range.start.set(start);
    range.end.set(end);
    range.attributes.set(attributes);
    range.user_data.set(user_data);
    Some(range)
}

/// RtlpCopyRangeListEntry: a entrada e, numa fundida, a sublista inteira.
fn copy_entry(source: &RtlpRangeListEntry) -> Option<&'static RtlpRangeListEntry> {
    let copy = allocate_entry()?;
    copy_fields(source, copy);
    reference_user_data(copy);
    if is_merged(source) {
        let head = copy.merged_list_head();
        initialize_head(head);
        let source_head = source.merged_list_head().address();
        let mut current = link(source_head).flink.get();
        while current != source_head {
            let original = entry_of_link(current);
            let Some(sub) = allocate_entry() else {
                delete_entry(copy);
                return None;
            };
            copy_fields(original, sub);
            reference_user_data(sub);
            insert_tail(head, &sub.list_entry);
            current = original.list_entry.flink.get();
        }
    }
    Some(copy)
}

/// RtlpFreeRangeListEntry.
fn free_entry(range: &RtlpRangeListEntry) {
    if !is_merged(range) && range.public_flags.get() & RANGE_USER_DATA_COUNTED != 0 {
        let user_data = range.user_data.get();
        if counter(user_data).atomic().fetch_sub(1, core::sync::atomic::Ordering::SeqCst) == 1 {
            let _ = pool_allocation::free(user_data, 0);
        }
    }
    let _ = pool_allocation::free(range.address(), 0);
}

/// RtlpDeleteRangeListEntry: a entrada e, numa fundida, as da sublista.
fn delete_entry(range: &RtlpRangeListEntry) {
    if is_merged(range) {
        let head = range.merged_list_head().address();
        let mut current = link(head).flink.get();
        while current != head {
            let sub = entry_of_link(current);
            current = sub.list_entry.flink.get();
            free_entry(sub);
        }
    }
    free_entry(range);
}

/// RtlpAddToMergedRange: põe `range` na sublista de `merged` (ordem de
/// início; empates depois das existentes), conferindo conflitos.
fn add_to_merged(merged: &RtlpRangeListEntry, range: &RtlpRangeListEntry, flags: u32) -> u32 {
    let range_shared = shared(range);
    let head = merged.merged_list_head();
    let mut previous = 0u64;
    let mut current = head.flink.get();
    while current != head.address() {
        let sub = entry_of_link(current);
        if overlaps(range, sub) && !(range_shared && shared(sub)) {
            if flags & RTL_RANGE_LIST_ADD_IF_CONFLICT == 0 {
                return STATUS_RANGE_LIST_CONFLICT;
            }
            sub.public_flags.set(sub.public_flags.get() | RTL_RANGE_CONFLICT);
            range.public_flags.set(range.public_flags.get() | RTL_RANGE_CONFLICT);
        }
        if previous == 0 && sub.start.get() > range.start.get() {
            previous = sub.list_entry.blink.get();
        }
        current = sub.list_entry.flink.get();
    }
    if previous == 0 {
        insert_tail(head, &range.list_entry);
    } else {
        insert_after(link(previous), &range.list_entry);
    }
    if range.start.get() < merged.start.get() {
        merged.start.set(range.start.get());
    }
    if range.end.get() > merged.end.get() {
        merged.end.set(range.end.get());
    }
    if shared(merged) && !range_shared {
        merged.public_flags.set(merged.public_flags.get() & !RTL_RANGE_SHARED);
    }
    STATUS_SUCCESS
}

/// RtlpAddIntersectingRanges: `first` é a primeira faixa de topo que cruza
/// `range`; ela vira (ou já é) a fundida que absorve as seguintes.
fn add_intersecting(list: &ListEntry, first: &RtlpRangeListEntry, range: &RtlpRangeListEntry, flags: u32) -> u32 {
    let head = list.address();
    let range_shared = shared(range);
    if flags & RTL_RANGE_LIST_ADD_IF_CONFLICT == 0 {
        let mut current_link = first.list_entry.address();
        while current_link != head {
            let current = entry_of_link(current_link);
            if range.end.get() < current.start.get() {
                break;
            }
            if is_merged(current) {
                let sub_head = current.merged_list_head().address();
                let mut sub_link = link(sub_head).flink.get();
                while sub_link != sub_head {
                    let sub = entry_of_link(sub_link);
                    if overlaps(range, sub) && !(range_shared && shared(sub)) {
                        return STATUS_RANGE_LIST_CONFLICT;
                    }
                    sub_link = sub.list_entry.flink.get();
                }
            } else if !(range_shared && shared(current)) {
                return STATUS_RANGE_LIST_CONFLICT;
            }
            current_link = current.list_entry.flink.get();
        }
    }
    if !is_merged(first) {
        let Some(copy) = copy_entry(first) else { return STATUS_INSUFFICIENT_RESOURCES };
        if first.public_flags.get() & RANGE_USER_DATA_COUNTED != 0 {
            counter(first.user_data.get()).atomic().fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
            first.public_flags.set(first.public_flags.get() & !RANGE_USER_DATA_COUNTED);
        }
        first.private_flags.set(RTLP_RANGE_LIST_ENTRY_MERGED);
        let merged_head = first.merged_list_head();
        copy.list_entry.flink.set(merged_head.address());
        copy.list_entry.blink.set(merged_head.address());
        merged_head.blink.set(copy.list_entry.address());
        merged_head.flink.set(copy.list_entry.address());
    }
    let mut current = first.list_entry.flink.get();
    while current != head {
        let next_range = entry_of_link(current);
        let next = next_range.list_entry.flink.get();
        if range.end.get() < next_range.start.get() {
            break;
        }
        if is_merged(next_range) {
            let sub_head = next_range.merged_list_head().address();
            let mut sub_link = link(sub_head).flink.get();
            while sub_link != sub_head {
                let sub = entry_of_link(sub_link);
                sub_link = sub.list_entry.flink.get();
                remove(&sub.list_entry);
                add_to_merged(first, sub, flags);
            }
            remove(&next_range.list_entry);
            free_entry(next_range);
        } else {
            remove(&next_range.list_entry);
            add_to_merged(first, next_range, flags);
        }
        current = next;
    }
    add_to_merged(first, range, flags)
}

/// RtlpAddRange: insere `range` na lista de topo `list`.
fn add_range(list: &ListEntry, range: &RtlpRangeListEntry, flags: u32) -> u32 {
    range.public_flags.set(range.public_flags.get() & !RTL_RANGE_CONFLICT);
    let (start, end) = (range.start.get(), range.end.get());
    let head = list.address();
    let first = list.flink.get();
    if first != head && start <= entry_of_link(list.blink.get()).end.get() {
        let mut current = first;
        while current != head {
            let existing = entry_of_link(current);
            if end < existing.start.get() {
                insert_after(link(existing.list_entry.blink.get()), &range.list_entry);
                return STATUS_SUCCESS;
            }
            if existing.start.get() >= start || existing.end.get() >= start {
                return add_intersecting(list, existing, range, flags);
            }
            current = existing.list_entry.flink.get();
        }
    }
    insert_tail(list, &range.list_entry);
    STATUS_SUCCESS
}

/// RtlInitializeRangeList.
pub fn initialize(list: &RtlRangeList) {
    initialize_head(&list.list_head);
    list.flags.set(0);
    list.count.set(0);
    list.stamp.set(0);
}

/// RtlFreeRangeList: devolve todas as entradas; o carimbo fica.
pub fn free(list: &RtlRangeList) {
    list.flags.set(0);
    list.count.set(0);
    let head = list.list_head.address();
    let mut current = list.list_head.flink.get();
    while current != head {
        let range = entry_of_link(current);
        current = range.list_entry.flink.get();
        remove(&range.list_entry);
        delete_entry(range);
    }
}

/// RtlCopyRangeList: `copy` precisa estar vazia (Count 0).
pub fn copy(copy: &RtlRangeList, source: &RtlRangeList) -> u32 {
    if copy.count.get() != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    copy.flags.set(source.flags.get());
    copy.count.set(source.count.get());
    copy.stamp.set(source.stamp.get());
    let head = source.list_head.address();
    let mut current = source.list_head.flink.get();
    while current != head {
        let range = entry_of_link(current);
        let Some(duplicate) = copy_entry(range) else {
            free(copy);
            return STATUS_INSUFFICIENT_RESOURCES;
        };
        insert_tail(&copy.list_head, &duplicate.list_entry);
        current = range.list_entry.flink.get();
    }
    STATUS_SUCCESS
}

/// Os argumentos de uma faixa nova do RtlAddRange.
pub struct NewRange {
    pub start: u64,
    pub end: u64,
    pub attributes: u8,
    pub flags: u32,
    pub user_data: u64,
    pub owner: u64,
}

/// RtlAddRange.
pub fn add(list: &RtlRangeList, request: &NewRange) -> u32 {
    if request.end < request.start {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(range) = create_entry(request.start, request.end, request.attributes, request.user_data, request.owner) else {
        return STATUS_UNSUCCESSFUL;
    };
    if request.flags & RTL_RANGE_LIST_ADD_SHARED != 0 {
        range.public_flags.set(range.public_flags.get() | RTL_RANGE_SHARED);
    }
    if request.flags & RANGE_USER_DATA_COUNTED as u32 != 0 {
        range.public_flags.set(range.public_flags.get() | RANGE_USER_DATA_COUNTED);
    }
    let status = add_range(&list.list_head, range, request.flags);
    if failed(status) {
        free_entry(range);
        return status;
    }
    list.count.set(list.count.get().wrapping_add(1));
    list.stamp.set(list.stamp.get().wrapping_add(1));
    status
}

/// RtlpDeleteFromMergedRange: tira `range` da fundida `merged` e reinsere as
/// que sobram numa lista nova, que toma o lugar da fundida (ou nada, se a
/// sublista ficou vazia).
fn delete_from_merged(range: &RtlpRangeListEntry, merged: &RtlpRangeListEntry) -> u32 {
    remove(&range.list_entry);
    let storage = UnsafeCell::new([0u64; 2]);
    let temporary = link(storage.get() as u64);
    initialize_head(temporary);
    let merged_head = merged.merged_list_head();
    let mut status = STATUS_SUCCESS;
    let mut current = merged_head.flink.get();
    while current != merged_head.address() {
        let sub = entry_of_link(current);
        current = sub.list_entry.flink.get();
        remove(&sub.list_entry);
        sub.public_flags.set(sub.public_flags.get() & !RTL_RANGE_CONFLICT);
        status = add_range(temporary, sub, RTL_RANGE_LIST_ADD_IF_CONFLICT);
        if failed(status) {
            // Devolve o que já saiu e a própria faixa à fundida.
            let mut moved = temporary.flink.get();
            while moved != temporary.address() {
                let back = entry_of_link(moved);
                moved = back.list_entry.flink.get();
                add_to_merged(merged, back, RTL_RANGE_LIST_ADD_IF_CONFLICT);
            }
            add_to_merged(merged, range, RTL_RANGE_LIST_ADD_IF_CONFLICT);
            return status;
        }
    }
    if temporary.flink.get() == temporary.address() {
        remove(&merged.list_entry);
    } else {
        let (previous, next) = (merged.list_entry.blink.get(), merged.list_entry.flink.get());
        let (first, last) = (temporary.flink.get(), temporary.blink.get());
        link(previous).flink.set(first);
        link(first).blink.set(previous);
        link(next).blink.set(last);
        link(last).flink.set(next);
    }
    free_entry(range);
    free_entry(merged);
    status
}

/// A faixa da sublista de `merged` com o predicado, se houver.
fn find_sub(merged: &RtlpRangeListEntry, matches: impl Fn(&RtlpRangeListEntry) -> bool) -> Option<&'static RtlpRangeListEntry> {
    let head = merged.merged_list_head().address();
    let mut current = link(head).flink.get();
    while current != head {
        let sub = entry_of_link(current);
        if matches(sub) {
            return Some(sub);
        }
        current = sub.list_entry.flink.get();
    }
    None
}

fn note_removed(list: &RtlRangeList) {
    list.count.set(list.count.get().wrapping_sub(1));
    list.stamp.set(list.stamp.get().wrapping_add(1));
}

/// RtlDeleteRange: a faixa exata (início, fim e dono).
pub fn delete(list: &RtlRangeList, start: u64, end: u64, owner: u64) -> u32 {
    let head = list.list_head.address();
    let mut current = list.list_head.flink.get();
    while current != head {
        let range = entry_of_link(current);
        current = range.list_entry.flink.get();
        if end < range.start.get() {
            break;
        }
        let status = if is_merged(range) {
            if start < range.start.get() || end > range.end.get() {
                continue;
            }
            let Some(sub) = find_sub(range, |sub| sub.start.get() == start && sub.end.get() == end && sub.owner.get() == owner) else { continue };
            delete_from_merged(sub, range)
        } else if range.start.get() == start && range.end.get() == end && range.owner.get() == owner {
            remove(&range.list_entry);
            free_entry(range);
            STATUS_SUCCESS
        } else {
            continue;
        };
        if !failed(status) {
            note_removed(list);
        }
        return status;
    }
    STATUS_RANGE_NOT_FOUND
}

/// RtlDeleteOwnersRanges: todas as faixas do dono.
pub fn delete_owners(list: &RtlRangeList, owner: u64) -> u32 {
    let head = list.list_head.address();
    let mut status = STATUS_SUCCESS;
    'restart: loop {
        let mut current = list.list_head.flink.get();
        while current != head {
            let range = entry_of_link(current);
            current = range.list_entry.flink.get();
            if is_merged(range) {
                if let Some(sub) = find_sub(range, |sub| sub.owner.get() == owner) {
                    status = delete_from_merged(sub, range);
                    if failed(status) {
                        return status;
                    }
                    note_removed(list);
                    continue 'restart;
                }
            } else if range.owner.get() == owner {
                remove(&range.list_entry);
                free_entry(range);
                note_removed(list);
                status = STATUS_SUCCESS;
            }
        }
        return status;
    }
}

fn iterator_at(address: u64) -> &'static RtlRangeListIterator {
    // SAFETY: o RTL_RANGE_LIST_ITERATOR do chamador (ou o local da busca).
    unsafe { RtlRangeListIterator::at(address) }
}

/// RtlGetFirstRange/RtlGetLastRange: posiciona o iterador numa ponta.
fn get_edge(list: &RtlRangeList, iterator: &RtlRangeListIterator, range: &Field<u64>, forward: bool) -> u32 {
    iterator.range_list_head.set(list.address());
    iterator.stamp.set(list.stamp.get());
    let head = list.list_head.address();
    let edge = if forward { list.list_head.flink.get() } else { list.list_head.blink.get() };
    if edge == head {
        iterator.merged_head.set(0);
        iterator.current.set(0);
        range.set(0);
        return STATUS_NO_MORE_ENTRIES;
    }
    let mut target = entry_of_link(edge);
    if is_merged(target) {
        let merged_head = target.merged_list_head();
        iterator.merged_head.set(merged_head.address());
        target = entry_of_link(if forward { merged_head.flink.get() } else { merged_head.blink.get() });
    } else {
        iterator.merged_head.set(0);
    }
    iterator.current.set(target.address());
    range.set(target.address());
    STATUS_SUCCESS
}

/// RtlGetFirstRange.
pub fn get_first(list: &RtlRangeList, iterator: &RtlRangeListIterator, range: &Field<u64>) -> u32 {
    get_edge(list, iterator, range, true)
}

/// RtlGetNextRange: a faixa seguinte (ou anterior), atravessando as
/// sublistas das fundidas; um carimbo diferente do da lista recusa.
pub fn get_next(iterator: &RtlRangeListIterator, range: &Field<u64>, forward: bool) -> u32 {
    // SAFETY: a RTL_RANGE_LIST que o RtlGetFirstRange gravou no iterador.
    let list = unsafe { RtlRangeList::at(iterator.range_list_head.get()) };
    if list.stamp.get() != iterator.stamp.get() {
        return STATUS_INVALID_PARAMETER;
    }
    let current = iterator.current.get();
    if current == 0 {
        range.set(0);
        return STATUS_NO_MORE_ENTRIES;
    }
    let step = |entry: &ListEntry| if forward { entry.flink.get() } else { entry.blink.get() };
    let mut next_link = step(&entry(current).list_entry);
    let merged = iterator.merged_head.get();
    if merged != 0 {
        if next_link != merged {
            iterator.current.set(next_link - LINK);
            range.set(next_link - LINK);
            return STATUS_SUCCESS;
        }
        // Fim da sublista: segue a lista de topo a partir da fundida.
        let merged_entry = entry(merged - offset_of!(RtlpRangeListEntry, user_data) as u64);
        next_link = step(&merged_entry.list_entry);
        iterator.merged_head.set(0);
    }
    if next_link == list.list_head.address() {
        iterator.current.set(0);
        range.set(0);
        return STATUS_NO_MORE_ENTRIES;
    }
    let mut target = entry_of_link(next_link);
    if is_merged(target) {
        let merged_head = target.merged_list_head();
        iterator.merged_head.set(merged_head.address());
        target = entry_of_link(step(merged_head));
    }
    iterator.current.set(target.address());
    range.set(target.address());
    STATUS_SUCCESS
}

/// Critérios de disponibilidade (RtlpIsRangeAvailable).
pub struct Availability {
    pub attribute_mask: u8,
    pub shared_ok: bool,
    pub null_conflict_ok: bool,
    pub context: u64,
    /// `PRTL_CONFLICT_RANGE_CALLBACK`: TRUE = a faixa não conflita.
    pub callback: u64,
}

impl Availability {
    pub fn new(flags: u32, attribute_mask: u8, context: u64, callback: u64) -> Self {
        Self { attribute_mask, shared_ok: flags & RTL_RANGE_LIST_SHARED_OK != 0, null_conflict_ok: flags & RTL_RANGE_LIST_NULL_CONFLICT_OK != 0, context, callback }
    }

    /// A faixa sobreposta ainda deixa o intervalo livre?
    fn tolerates(&self, range: &RtlpRangeListEntry) -> bool {
        (self.shared_ok && shared(range))
            || range.attributes.get() & self.attribute_mask != 0
            || (self.null_conflict_ok && range.owner.get() == 0)
            || (self.callback != 0 && crate::hal::amd64::native_call::call(self.callback, &[self.context, range.address()]) as u8 != 0)
    }
}

/// A sobreposição do intervalo pedido com `range`, na ordem de comparações
/// do original (um início igual cruza sempre).
fn touches(range: &RtlpRangeListEntry, start: u64, end: u64) -> bool {
    let range_start = range.start.get();
    if range_start > start {
        end >= range_start
    } else if range_start == start {
        true
    } else {
        range.end.get() >= start
    }
}

/// RtlpIsRangeAvailable: anda a partir do corrente do iterador; num
/// conflito, o iterador fica na faixa que conflitou.
fn is_available(iterator: &RtlRangeListIterator, start: u64, end: u64, criteria: &Availability, forward: bool) -> bool {
    let cell = UnsafeCell::new(iterator.current.get());
    // SAFETY: a célula local recebe a faixa seguinte do RtlGetNextRange.
    let next = unsafe { Field::<u64>::at(cell.get() as u64) };
    let mut current = iterator.current.get();
    while current != 0 {
        let range = entry(current);
        let past = if forward { end < range.start.get() } else { start > range.end.get() };
        if iterator.merged_head.get() == 0 && past {
            return true;
        }
        if touches(range, start, end) && !criteria.tolerates(range) {
            return false;
        }
        get_next(iterator, next, forward);
        current = next.get();
    }
    true
}

/// RtlIsRangeAvailable.
pub fn is_range_available(list: &RtlRangeList, start: u64, end: u64, criteria: &Availability, available: &Field<u8>) -> u32 {
    let storage = UnsafeCell::new([0u64; 5]);
    let iterator = iterator_at(storage.get() as u64);
    // SAFETY: a última palavra do bloco local guarda o RTL_RANGE devolvido.
    let first = unsafe { Field::<u64>::at(storage.get() as u64 + RtlRangeListIterator::SIZE) };
    match get_first(list, iterator, first) {
        STATUS_NO_MORE_ENTRIES => {
            available.set(1);
            STATUS_SUCCESS
        }
        status if failed(status) => status,
        _ => {
            available.set(is_available(iterator, start, end, criteria, true) as u8);
            STATUS_SUCCESS
        }
    }
}

/// Pedido do RtlFindRange.
pub struct FindRequest {
    pub minimum: u64,
    pub maximum: u64,
    pub length: u64,
    pub alignment: u64,
}

/// RtlFindRange: o intervalo livre alinhado mais alto em [mínimo, máximo],
/// procurado de cima para baixo.
pub fn find(list: &RtlRangeList, request: &FindRequest, criteria: &Availability, start_out: &Field<u64>) -> u32 {
    let FindRequest { minimum, maximum, length, alignment } = *request;
    // (O original divide antes de conferir o alinhamento; zero é recusado aqui.)
    if alignment == 0 || length == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let mut start = maximum.wrapping_sub(length).wrapping_add(1);
    start -= start % alignment;
    if minimum > maximum || maximum - minimum < length - 1 || minimum.checked_add(alignment).is_none() || start < minimum {
        return STATUS_INVALID_PARAMETER;
    }
    let storage = UnsafeCell::new([0u64; 5]);
    let iterator = iterator_at(storage.get() as u64);
    // SAFETY: a última palavra do bloco local guarda o RTL_RANGE devolvido.
    let last = unsafe { Field::<u64>::at(storage.get() as u64 + RtlRangeListIterator::SIZE) };
    get_edge(list, iterator, last, false);
    loop {
        if is_available(iterator, start, start.wrapping_add(length - 1), criteria, false) {
            start_out.set(start);
            return STATUS_SUCCESS;
        }
        let conflict = entry(iterator.current.get()).start.get();
        start = conflict.wrapping_sub(length);
        if start > conflict {
            return STATUS_UNSUCCESSFUL;
        }
        start -= start % alignment;
        if start < minimum {
            return STATUS_UNSUCCESSFUL;
        }
    }
}

/// Atributos das faixas que o RtlInvertRangeListEx cria.
pub struct InvertedRange {
    pub attributes: u8,
    pub user_data: u64,
    pub owner: u64,
}

/// RtlInvertRangeListEx: os buracos de `source` entram em `inverted`.
pub fn invert(inverted: &RtlRangeList, source: &RtlRangeList, fill: &InvertedRange) -> u32 {
    let gap = |start: u64, end: u64| add(inverted, &NewRange { start, end, attributes: fill.attributes, flags: 0, user_data: fill.user_data, owner: fill.owner });
    if source.count.get() == 0 {
        return gap(0, u64::MAX);
    }
    let head = source.list_head.address();
    let mut cursor = 0u64;
    let mut current = source.list_head.flink.get();
    while current != head {
        let range = entry_of_link(current);
        if range.start.get() > cursor {
            let status = gap(cursor, range.start.get() - 1);
            if failed(status) {
                return status;
            }
        }
        cursor = range.end.get().wrapping_add(1);
        current = range.list_entry.flink.get();
    }
    if cursor != 0 {
        let status = gap(cursor, u64::MAX);
        if failed(status) {
            return status;
        }
    }
    STATUS_SUCCESS
}
