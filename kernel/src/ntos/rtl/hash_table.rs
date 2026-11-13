//! Tabelas de hash dinâmicas do Rtl (RTL_DYNAMIC_HASH_TABLE) —
//! RtlCreateHashTable[Ex], RtlDeleteHashTable, Rtl{Insert,Remove,Lookup,
//! GetNext}EntryHashTable, as enumerações normal/fraca/forte e
//! Rtl{Expand,Contract}HashTable. A pilha de rede real (ndis.sys, tcpip.sys)
//! guarda conexões e vizinhos nelas.
//!
//! Comportamento do ntoskrnl: diretório de dois níveis (até 16 diretórios
//! secundários de `128 << i` cabeças LIST_ENTRY; com TableSize <= 128 o
//! Directory aponta direto para as cabeças), espalhamento linear
//! (Pivot/DivisorMask), cadeias ordenadas por Signature crescente e
//! enumeradores normais/fracos que se inserem na cadeia como marcador de
//! Signature 0. Os acessores inline do WDK (RtlTotalBucketsHashTable,
//! RtlInitHashTableContext, ...) leem os campos direto, então o layout é o
//! do PDB. Os contadores são `++`/`--` simples, como no NT: o chamador
//! serializa o acesso à tabela. Listas corrompidas disparam
//! FAST_FAIL_CORRUPT_LIST_ENTRY (bugcheck 0x139, código 3), como o `int 0x29`
//! original. A memória vem do NonPagedPoolNx com a tag 'HTab' e volta pelo
//! ExFreePool.

use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::types::{
    Field, ListEntry, NtStruct, RtlDynamicHashTable, RtlDynamicHashTableContext, RtlDynamicHashTableEntry, RtlDynamicHashTableEnumerator,
};
use crate::ntos::ke::bugcheck;
use crate::rtl::KernelError;

/// RTL_HASH_ALLOCATED_HEADER: o cabeçalho foi alocado pelo Create.
const ALLOCATED_HEADER: u32 = 1;
/// HT_FIRST_LEVEL_DIR_SIZE: entradas do diretório de primeiro nível.
const FIRST_LEVEL_ENTRIES: usize = 16;
/// Cabeças do nível 0 e tamanho inicial do RtlCreateHashTable.
const SECOND_LEVEL_BASE: u32 = 0x80;
/// TableSize máximo aceito pelo RtlExpandHashTable.
const MAXIMUM_TABLE_SIZE: u32 = 0x7F_FF80;
const NON_PAGED_POOL_NX: u32 = 0x200;
/// 'HTab'.
const HASH_TABLE_TAG: u32 = 0x6261_5448;

// SAFETY (todas as conversões abaixo): os endereços são as estruturas do
// chamador (tabela, entradas, contexto, enumerador) ou as cabeças de lista
// dos diretórios desta tabela, vivas e alinhadas como no NT.
fn table_at(address: u64) -> &'static RtlDynamicHashTable {
    unsafe { RtlDynamicHashTable::at(address) }
}
fn context_at(address: u64) -> &'static RtlDynamicHashTableContext {
    unsafe { RtlDynamicHashTableContext::at(address) }
}
fn enumerator_at(address: u64) -> &'static RtlDynamicHashTableEnumerator {
    unsafe { RtlDynamicHashTableEnumerator::at(address) }
}
fn links(entry: u64) -> &'static ListEntry {
    unsafe { ListEntry::at(entry) }
}
/// Diretório de primeiro nível: PVOID[16] com as cabeças de cada nível.
fn directory_slots(directory: u64) -> &'static [Field<u64>] {
    unsafe { Field::<u64>::array_at(directory, FIRST_LEVEL_ENTRIES) }
}

/// `Counter += delta` sem interlocked (o NT faz o mesmo sob o lock do chamador).
fn add(counter: &Field<u32>, delta: i32) {
    counter.set(counter.get().wrapping_add(delta as u32));
}
fn flink(entry: u64) -> u64 {
    links(entry).flink.get()
}
fn blink(entry: u64) -> u64 {
    links(entry).blink.get()
}
fn is_empty(head: u64) -> bool {
    flink(head) == head
}
fn signature(entry: u64) -> u64 {
    // SAFETY: entrada (ou marcador de enumerador, mesmo layout no início).
    unsafe { RtlDynamicHashTableEntry::at(entry) }.signature.get()
}

/// `int 0x29` com FAST_FAIL_CORRUPT_LIST_ENTRY.
fn corrupt_list() -> ! {
    bugcheck::bug_check_ex(0x139, 3, 0, 0, 0)
}

/// InsertHeadList relativo a `previous`, conferindo previous->Flink->Blink.
fn insert_after(previous: u64, entry: u64) {
    let next = flink(previous);
    if blink(next) != previous {
        corrupt_list();
    }
    links(entry).blink.set(previous);
    links(entry).flink.set(next);
    links(next).blink.set(entry);
    links(previous).flink.set(entry);
}

/// InsertTailList conferindo head->Blink->Flink (laço do Expand).
fn insert_tail(head: u64, entry: u64) {
    let last = blink(head);
    if flink(last) != head {
        corrupt_list();
    }
    links(entry).flink.set(head);
    links(entry).blink.set(last);
    links(last).flink.set(entry);
    links(head).blink.set(entry);
}

/// RemoveEntryList com as duas checagens do original.
fn unlink(entry: u64) {
    let next = flink(entry);
    let previous = blink(entry);
    if blink(next) != entry || flink(previous) != entry {
        corrupt_list();
    }
    links(previous).flink.set(next);
    links(next).blink.set(previous);
}

/// InitializeListHead em `count` cabeças consecutivas.
fn initialize_heads(base: u64, count: u32) {
    // SAFETY: vetor de cabeças recém-alocado por esta tabela.
    for head in unsafe { ListEntry::array_at(base, count as usize) } {
        head.blink.set(head.address());
        head.flink.set(head.address());
    }
}

fn allocate(bytes: u64) -> Result<u64, KernelError> {
    pool_allocation::allocate_tagged(NON_PAGED_POOL_NX, bytes, HASH_TABLE_TAG)
}

/// RtlpAllocateSecondLevelDir: `0x10 << (level + 7)` bytes, sem inicializar.
fn allocate_second_level(level: u32) -> Result<u64, KernelError> {
    allocate(ListEntry::SIZE << (level + 7))
}

/// O espalhamento de RtlpPopulateContext sobre os 32 bits baixos.
fn hash(signature: u64, shift: u32) -> u32 {
    let value = (signature as u32) >> (shift & 31);
    let low = value.wrapping_mul(0x41C6_4E6D).wrapping_add(0x3039) >> 16;
    let high = value.wrapping_mul(0x10DCD).wrapping_add(1) & 0xFFFF_0000;
    low | high
}

fn expanded_mask(mask: u32) -> u32 {
    mask.wrapping_add(mask) | 1
}

/// Balde linear: abaixo do Pivot o balde já foi dividido.
fn bucket_of(table: &RtlDynamicHashTable, signature: u64) -> u32 {
    let hashed = hash(signature, table.shift.get());
    let mask = table.divisor_mask.get();
    let bucket = hashed & mask;
    if bucket < table.pivot.get() { hashed & expanded_mask(mask) } else { bucket }
}

/// RtlpGetChainHead: direto com TableSize <= 128; senão (balde + 128) indexa
/// o nível pelo bit mais alto e o deslocamento pelo restante.
fn chain_head(table: &RtlDynamicHashTable, bucket: u32) -> u64 {
    let directory = table.directory.get();
    if table.table_size.get() <= SECOND_LEVEL_BASE {
        return directory + bucket as u64 * ListEntry::SIZE;
    }
    let biased = bucket.wrapping_add(SECOND_LEVEL_BASE);
    let bit = 31 - biased.leading_zeros();
    let offset = biased ^ (1 << bit);
    directory_slots(directory)[(bit - 7) as usize].get() + offset as u64 * ListEntry::SIZE
}

/// RtlpPopulateContext: a cabeça e a ligação após a qual a assinatura entra
/// (antes do primeiro não-marcador com Signature >= a pedida).
fn locate(table: &RtlDynamicHashTable, wanted: u64) -> (u64, u64) {
    let head = chain_head(table, bucket_of(table, wanted));
    let mut previous = head;
    let mut current = flink(head);
    while current != head {
        let found = signature(current);
        if found != 0 && found >= wanted {
            break;
        }
        previous = current;
        current = flink(current);
    }
    (head, previous)
}

fn write_context(context: &RtlDynamicHashTableContext, head: u64, previous: u64, wanted: u64) {
    context.chain_head.set(head);
    context.prev_linkage.set(previous);
    context.signature.set(wanted);
}

/// RtlpCreateHashTable(Table**, InitialSize, Shift, Flags): InitialSize é
/// potência de dois entre 128 e 0x7FFF80; *Table nulo aloca o cabeçalho.
fn create_sized(holder: u64, initial: u32, shift: u32, flags: u32) -> Result<bool, KernelError> {
    let mask = initial.wrapping_sub(1);
    if initial & mask != 0 || initial.wrapping_sub(SECOND_LEVEL_BASE) > 0x7F_FF00 {
        return Ok(false);
    }
    // SAFETY: PRTL_DYNAMIC_HASH_TABLE* do chamador.
    let holder = unsafe { Field::<u64>::at(holder) };
    let mut address = holder.get();
    let mut header = 0;
    if address == 0 {
        address = allocate(RtlDynamicHashTable::SIZE)?;
        if address == 0 {
            return Ok(false);
        }
        header = ALLOCATED_HEADER;
    }
    let table = table_at(address);
    table.num_entries.set(0);
    table.non_empty_buckets.set(0);
    table.num_enumerators.set(0);
    table.directory.set(0);
    table.pivot.set(0);
    table.flags.set(header | flags);
    table.table_size.set(initial);
    table.divisor_mask.set(mask);
    table.shift.set(shift);
    if initial <= SECOND_LEVEL_BASE {
        let heads = allocate_second_level(0)?;
        if heads == 0 {
            delete(address)?;
            return Ok(false);
        }
        initialize_heads(heads, table.table_size.get());
        table.directory.set(heads);
    } else {
        // Último balde + 128: o bit alto é o último nível e o resto, o índice
        // da última cabeça dele.
        let biased = initial + 0x7F;
        let bit = 31 - biased.leading_zeros();
        let tail = (1u32 << bit) ^ biased;
        let last_level = bit - 7;
        let first = allocate((FIRST_LEVEL_ENTRIES * 8) as u64)?;
        if first == 0 {
            delete(address)?;
            return Ok(false);
        }
        let slots = directory_slots(first);
        for slot in slots {
            slot.set(0);
        }
        table.directory.set(first);
        for level in 0..=last_level {
            let heads = allocate_second_level(level)?;
            if heads == 0 {
                delete(address)?;
                return Ok(false);
            }
            initialize_heads(heads, if level < last_level { 1 << (level + 7) } else { tail + 1 });
            slots[level as usize].set(heads);
        }
    }
    holder.set(address);
    Ok(true)
}

/// RtlCreateHashTable(Table**, Shift, Flags): 128 baldes iniciais.
pub fn create(holder: u64, shift: u32, flags: u32) -> Result<bool, KernelError> {
    create_sized(holder, SECOND_LEVEL_BASE, shift, flags)
}

/// RtlCreateHashTableEx(Table**, InitialSize, Shift, Flags).
pub fn create_ex(holder: u64, initial: u32, shift: u32, flags: u32) -> Result<bool, KernelError> {
    create_sized(holder, initial, shift, flags)
}

/// RtlDeleteHashTable: diretórios e, se alocado pelo Create, o cabeçalho.
pub fn delete(address: u64) -> Result<(), KernelError> {
    let table = table_at(address);
    let directory = table.directory.get();
    if table.table_size.get() > SECOND_LEVEL_BASE {
        if directory != 0 {
            for slot in directory_slots(directory) {
                let heads = slot.get();
                if heads == 0 {
                    break;
                }
                pool_allocation::free(heads, 0)?;
            }
            pool_allocation::free(directory, 0)?;
        }
    } else if directory != 0 {
        pool_allocation::free(directory, 0)?;
    }
    if table.flags.get() & ALLOCATED_HEADER != 0 {
        pool_allocation::free(address, 0)?;
    }
    Ok(())
}

/// RtlInsertEntryHashTable(Table, Entry, Signature, Context): contexto nulo
/// ou sem ChainHead é recalculado; com ChainHead, usado como veio.
pub fn insert(table: u64, entry: u64, wanted: u64, context: u64) -> bool {
    let table = table_at(table);
    // SAFETY: PRTL_DYNAMIC_HASH_TABLE_ENTRY do chamador.
    unsafe { RtlDynamicHashTableEntry::at(entry) }.signature.set(wanted);
    add(&table.num_entries, 1);
    let (head, previous) = if context == 0 {
        locate(table, wanted)
    } else {
        let context = context_at(context);
        if context.chain_head.get() == 0 {
            let (head, previous) = locate(table, wanted);
            write_context(context, head, previous, wanted);
            (head, previous)
        } else {
            (context.chain_head.get(), context.prev_linkage.get())
        }
    };
    if is_empty(head) {
        add(&table.non_empty_buckets, 1);
    }
    insert_after(previous, entry);
    true
}

/// RtlRemoveEntryHashTable(Table, Entry, Context): Flink == Blink marca o
/// último da cadeia; o contexto sem ChainHead recebe a posição da entrada.
pub fn remove(table: u64, entry: u64, context: u64) -> bool {
    let table = table_at(table);
    let wanted = signature(entry);
    add(&table.num_entries, -1);
    if flink(entry) == blink(entry) {
        add(&table.non_empty_buckets, -1);
    }
    unlink(entry);
    if context != 0 {
        let context = context_at(context);
        if context.chain_head.get() == 0 {
            let (head, previous) = locate(table, wanted);
            write_context(context, head, previous, wanted);
        }
    }
    true
}

/// RtlLookupEntryHashTable(Table, Signature, Context): a primeira entrada
/// com a assinatura exata; o contexto (opcional) guarda a posição.
pub fn lookup(table: u64, wanted: u64, context: u64) -> u64 {
    let (head, previous) = locate(table_at(table), wanted);
    if context != 0 {
        write_context(context_at(context), head, previous, wanted);
    }
    let candidate = flink(previous);
    if candidate == head || signature(candidate) != wanted { 0 } else { candidate }
}

/// RtlGetNextEntryHashTable(Table, Context): a próxima com a mesma
/// assinatura; com enumeradores ativos, pula os marcadores (Signature 0).
pub fn get_next(table: u64, context: u64) -> u64 {
    let (table, context) = (table_at(table), context_at(context));
    let head = context.chain_head.get();
    let mut previous = flink(context.prev_linkage.get());
    let mut next = flink(previous);
    if next == head {
        return 0;
    }
    if table.num_enumerators.get() != 0 {
        let mut cursor = next;
        loop {
            next = cursor;
            if signature(cursor) != 0 {
                break;
            }
            let after = flink(cursor);
            previous = cursor;
            cursor = after;
            if after == head {
                break;
            }
        }
    }
    if signature(next) != context.signature.get() {
        return 0;
    }
    context.prev_linkage.set(previous);
    next
}

/// RtlInitEnumerationHashTable (a variante Weak encaminha para esta): o
/// marcador entra na cabeça do balde da assinatura 0 (balde 0).
pub fn init_enumeration(table: u64, enumerator: u64) -> bool {
    let table = table_at(table);
    let (head, _) = locate(table, 0);
    add(&table.num_enumerators, 1);
    if is_empty(head) {
        add(&table.non_empty_buckets, 1);
    }
    insert_after(head, enumerator);
    let marker = enumerator_at(enumerator);
    marker.bucket_index.set(0);
    marker.hash_entry.signature.set(0);
    marker.chain_head.set(head);
    true
}

/// RtlEnumerateEntryHashTable (e Weakly...): retoma do marcador, devolve a
/// próxima entrada real e reinsere o marcador logo após ela.
pub fn enumerate(table: u64, enumerator: u64) -> u64 {
    let table = table_at(table);
    let marker = enumerator_at(enumerator);
    let start = marker.bucket_index.get();
    let size = table.table_size.get();
    let mut bucket = start;
    while bucket < size {
        let (head, mut cursor) = if bucket == start {
            (marker.chain_head.get(), enumerator)
        } else {
            let head = chain_head(table, bucket);
            (head, head)
        };
        cursor = flink(cursor);
        while cursor != head {
            if signature(cursor) != 0 {
                unlink(enumerator);
                let old_head = marker.chain_head.get();
                if old_head != head {
                    if is_empty(old_head) {
                        add(&table.non_empty_buckets, -1);
                    }
                    if is_empty(head) {
                        add(&table.non_empty_buckets, 1);
                    }
                }
                marker.bucket_index.set(bucket);
                marker.chain_head.set(head);
                insert_after(cursor, enumerator);
                return cursor;
            }
            cursor = flink(cursor);
        }
        bucket += 1;
    }
    0
}

/// RtlEndEnumerationHashTable (e EndWeak...): retira o marcador se ligado.
pub fn end_enumeration(table: u64, enumerator: u64) {
    let table = table_at(table);
    let marker = enumerator_at(enumerator);
    add(&table.num_enumerators, -1);
    if flink(enumerator) != enumerator {
        unlink(enumerator);
        if is_empty(marker.chain_head.get()) {
            add(&table.non_empty_buckets, -1);
        }
    }
    marker.chain_head.set(0);
}

/// RtlInitStrongEnumerationHashTable: sem marcador nem NumEnumerators;
/// CurEntry começa na cabeça do balde 0.
pub fn init_strong_enumeration(table: u64, enumerator: u64) -> bool {
    let (head, _) = locate(table_at(table), 0);
    let marker = enumerator_at(enumerator);
    marker.hash_entry.linkage.blink.set(0);
    marker.hash_entry.signature.set(0);
    marker.bucket_index.set(0);
    marker.chain_head.set(head);
    marker.cur_entry.set(head);
    true
}

/// RtlStronglyEnumerateEntryHashTable: avança CurEntry (o chamador garante
/// que a tabela não muda durante a enumeração forte).
pub fn strongly_enumerate(table: u64, enumerator: u64) -> u64 {
    let table = table_at(table);
    let marker = enumerator_at(enumerator);
    let start = marker.bucket_index.get();
    let size = table.table_size.get();
    let mut bucket = start;
    while bucket < size {
        let (head, mut cursor) = if bucket == start {
            (marker.chain_head.get(), marker.cur_entry.get())
        } else {
            let head = chain_head(table, bucket);
            (head, head)
        };
        cursor = flink(cursor);
        while cursor != head {
            if signature(cursor) != 0 {
                marker.chain_head.set(head);
                marker.bucket_index.set(bucket);
                marker.cur_entry.set(cursor);
                return cursor;
            }
            cursor = flink(cursor);
        }
        bucket += 1;
    }
    0
}

/// RtlEndStrongEnumerationHashTable: `ret` no original.
pub fn end_strong_enumeration(_table: u64, _enumerator: u64) {}

/// RtlExpandHashTable: divide o balde do Pivot no novo balde TableSize;
/// recusa com enumeradores ativos ou no tamanho máximo.
pub fn expand(address: u64) -> Result<bool, KernelError> {
    let table = table_at(address);
    let size = table.table_size.get();
    if size == MAXIMUM_TABLE_SIZE || table.num_enumerators.get() > 0 {
        return Ok(false);
    }
    let biased = size + SECOND_LEVEL_BASE;
    let bit = 31 - biased.leading_zeros();
    let offset = biased ^ (1 << bit);
    let level = (bit - 7) as usize;
    if size == SECOND_LEVEL_BASE {
        // Passa ao diretório de dois níveis: o antigo vira o nível 0.
        let single = table.directory.get();
        let first = allocate((FIRST_LEVEL_ENTRIES * 8) as u64)?;
        if first == 0 {
            return Ok(false);
        }
        let slots = directory_slots(first);
        for slot in &slots[1..] {
            slot.set(0);
        }
        slots[0].set(single);
        table.directory.set(first);
    }
    let directory = table.directory.get();
    let slots = directory_slots(directory);
    let mut heads = slots[level].get();
    if heads == 0 {
        heads = allocate_second_level(level as u32)?;
        if heads == 0 {
            if table.table_size.get() == SECOND_LEVEL_BASE {
                table.directory.set(slots[0].get());
                pool_allocation::free(directory, 0)?;
            }
            return Ok(false);
        }
        slots[level].set(heads);
    }
    let pivot = table.pivot.get();
    table.table_size.set(size + 1);
    let old_head = chain_head(table, pivot);
    table.pivot.set(pivot + 1);
    let new_head = heads + offset as u64 * ListEntry::SIZE;
    initialize_heads(new_head, 1);
    if !is_empty(old_head) {
        let mut previous = old_head;
        let mut current = flink(old_head);
        loop {
            let target = hash(signature(current), table.shift.get()) & expanded_mask(table.divisor_mask.get());
            if target != table.table_size.get() - 1 {
                previous = current;
            } else {
                unlink(current);
                insert_tail(new_head, current);
            }
            current = flink(previous);
            if current == old_head {
                break;
            }
        }
        if !is_empty(new_head) {
            add(&table.non_empty_buckets, 1);
        }
        if is_empty(old_head) {
            add(&table.non_empty_buckets, -1);
        }
    }
    let mask = table.divisor_mask.get();
    if table.pivot.get() == mask.wrapping_add(1) {
        table.pivot.set(0);
        table.divisor_mask.set(expanded_mask(mask));
    }
    Ok(true)
}

/// RtlContractHashTable: funde o último balde no seu par (mantendo a ordem
/// por assinatura) e libera o nível secundário que esvazia.
pub fn contract(address: u64) -> Result<bool, KernelError> {
    let table = table_at(address);
    let size = table.table_size.get();
    if size == SECOND_LEVEL_BASE || table.num_enumerators.get() > 0 {
        return Ok(false);
    }
    let pivot = match table.pivot.get() {
        0 => {
            let mask = table.divisor_mask.get() >> 1;
            table.divisor_mask.set(mask);
            mask
        }
        pivot => pivot - 1,
    };
    table.pivot.set(pivot);
    let last = chain_head(table, size - 1);
    let target = chain_head(table, table.pivot.get());
    table.table_size.set(size - 1);
    if !is_empty(last) && !is_empty(target) {
        add(&table.non_empty_buckets, -1);
    }
    let mut cursor = target;
    loop {
        let moved = flink(last);
        if moved == last {
            break;
        }
        let after = flink(moved);
        if blink(moved) != last || blink(after) != moved {
            corrupt_list();
        }
        links(last).flink.set(after);
        links(after).blink.set(last);
        let mut next = flink(cursor);
        if next != target {
            let key = signature(moved);
            while signature(next) < key {
                cursor = next;
                next = flink(next);
                if next == target {
                    break;
                }
            }
        }
        insert_after(cursor, moved);
    }
    let biased = table.table_size.get() + SECOND_LEVEL_BASE;
    let bit = 31 - biased.leading_zeros();
    if 1u32 << bit == biased {
        let directory = table.directory.get();
        let slots = directory_slots(directory);
        let slot = &slots[(bit - 7) as usize];
        pool_allocation::free(slot.get(), 0)?;
        slot.set(0);
        if table.table_size.get() == SECOND_LEVEL_BASE {
            table.directory.set(slots[0].get());
            pool_allocation::free(directory, 0)?;
        }
    }
    Ok(true)
}
