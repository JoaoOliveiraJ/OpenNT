//! Tabelas de hash dinâmicas do Rtl (RTL_DYNAMIC_HASH_TABLE) —
//! RtlCreateHashTable[Ex], RtlDeleteHashTable, Rtl{Insert,Remove,Lookup,
//! GetNext}EntryHashTable, as enumerações normal/fraca/forte e
//! Rtl{Expand,Contract}HashTable. A pilha de rede real (ndis.sys, tcpip.sys)
//! guarda conexões e vizinhos nelas.
//!
//! Transcrição do ntoskrnl: diretório de dois níveis (até 16 diretórios
//! secundários de `128 << i` cabeças LIST_ENTRY; com TableSize <= 128 o
//! Directory aponta direto para as cabeças), espalhamento linear
//! (Pivot/DivisorMask), cadeias ordenadas por Signature crescente e
//! enumeradores normais/fracos que se inserem na cadeia como marcador de
//! Signature 0. Os acessores inline do WDK (RtlTotalBucketsHashTable,
//! RtlInitHashTableContext, ...) leem os campos direto, então o layout é o
//! do PDB. Listas corrompidas disparam FAST_FAIL_CORRUPT_LIST_ENTRY
//! (bugcheck 0x139, código 3), como o `int 0x29` original. A memória vem do
//! NonPagedPoolNx com a tag 'HTab' e volta pelo ExFreePool.

use crate::ntos::ex::pool_allocation;
use crate::ntos::ke::bugcheck;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

// RTL_DYNAMIC_HASH_TABLE (0x28).
const FLAGS: u64 = 0x00;
const SHIFT: u64 = 0x04;
const TABLE_SIZE: u64 = 0x08;
const PIVOT: u64 = 0x0C;
const DIVISOR_MASK: u64 = 0x10;
const NUM_ENTRIES: u64 = 0x14;
const NON_EMPTY_BUCKETS: u64 = 0x18;
const NUM_ENUMERATORS: u64 = 0x1C;
const DIRECTORY: u64 = 0x20;
// RTL_DYNAMIC_HASH_TABLE_ENTRY (0x18): Linkage@0, Signature@0x10.
const SIGNATURE: u64 = 0x10;
// RTL_DYNAMIC_HASH_TABLE_CONTEXT (0x18).
const CONTEXT_CHAIN_HEAD: u64 = 0x00;
const CONTEXT_PREV_LINKAGE: u64 = 0x08;
const CONTEXT_SIGNATURE: u64 = 0x10;
// RTL_DYNAMIC_HASH_TABLE_ENUMERATOR (0x28): HashEntry/CurEntry@0,
// ChainHead@0x18, BucketIndex@0x20.
const ENUMERATOR_CHAIN_HEAD: u64 = 0x18;
const ENUMERATOR_BUCKET_INDEX: u64 = 0x20;

/// RTL_HASH_ALLOCATED_HEADER: o cabeçalho foi alocado pelo Create.
const ALLOCATED_HEADER: u32 = 1;
/// HT_FIRST_LEVEL_DIR_SIZE * sizeof(PVOID).
const FIRST_LEVEL_BYTES: u64 = 0x80;
/// Cabeças do nível 0 e tamanho inicial do RtlCreateHashTable.
const SECOND_LEVEL_BASE: u32 = 0x80;
/// TableSize máximo aceito pelo RtlExpandHashTable.
const MAXIMUM_TABLE_SIZE: u32 = 0x7F_FF80;
const NON_PAGED_POOL_NX: u32 = 0x200;
/// 'HTab'.
const HASH_TABLE_TAG: u32 = 0x6261_5448;

fn read32(address: u64) -> u32 {
    guest::read32(address)
}
fn write32(address: u64, value: u32) {
    guest::write32(address, value)
}
fn add32(address: u64, delta: i32) {
    write32(address, read32(address).wrapping_add(delta as u32));
}
fn flink(entry: u64) -> u64 {
    guest::read64(entry)
}
fn blink(entry: u64) -> u64 {
    guest::read64(entry + 8)
}
fn is_empty(head: u64) -> bool {
    flink(head) == head
}
fn signature(entry: u64) -> u64 {
    guest::read64(entry + SIGNATURE)
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
    guest::write64(entry + 8, previous);
    guest::write64(entry, next);
    guest::write64(next + 8, entry);
    guest::write64(previous, entry);
}

/// InsertTailList conferindo head->Blink->Flink (laço do Expand).
fn insert_tail(head: u64, entry: u64) {
    let last = blink(head);
    if flink(last) != head {
        corrupt_list();
    }
    guest::write64(entry, head);
    guest::write64(entry + 8, last);
    guest::write64(last, entry);
    guest::write64(head + 8, entry);
}

/// RemoveEntryList com as duas checagens do original.
fn unlink(entry: u64) {
    let next = flink(entry);
    let previous = blink(entry);
    if blink(next) != entry || flink(previous) != entry {
        corrupt_list();
    }
    guest::write64(previous, next);
    guest::write64(next + 8, previous);
}

fn initialize_heads(base: u64, count: u32) {
    for index in 0..count as u64 {
        let head = base + index * 16;
        guest::write64(head + 8, head);
        guest::write64(head, head);
    }
}

fn allocate(bytes: u64) -> Result<u64, KernelError> {
    pool_allocation::allocate_tagged(NON_PAGED_POOL_NX, bytes, HASH_TABLE_TAG)
}

/// RtlpAllocateSecondLevelDir: `0x10 << (level + 7)` bytes, sem inicializar.
fn allocate_second_level(level: u32) -> Result<u64, KernelError> {
    allocate(0x10u64 << (level + 7))
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
fn bucket_of(table: u64, signature: u64) -> u32 {
    let hashed = hash(signature, read32(table + SHIFT));
    let mask = read32(table + DIVISOR_MASK);
    let bucket = hashed & mask;
    if bucket < read32(table + PIVOT) { hashed & expanded_mask(mask) } else { bucket }
}

/// RtlpGetChainHead: direto com TableSize <= 128; senão (balde + 128) indexa
/// o nível pelo bit mais alto e o deslocamento pelo restante.
fn chain_head(table: u64, bucket: u32) -> u64 {
    let directory = guest::read64(table + DIRECTORY);
    if read32(table + TABLE_SIZE) <= SECOND_LEVEL_BASE {
        return directory + bucket as u64 * 16;
    }
    let biased = bucket.wrapping_add(SECOND_LEVEL_BASE);
    let bit = 31 - biased.leading_zeros();
    let offset = biased ^ (1 << bit);
    guest::read64(directory + (bit - 7) as u64 * 8) + offset as u64 * 16
}

/// RtlpPopulateContext: a cabeça e a ligação após a qual a assinatura entra
/// (antes do primeiro não-marcador com Signature >= a pedida).
fn locate(table: u64, wanted: u64) -> (u64, u64) {
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

fn write_context(context: u64, head: u64, previous: u64, wanted: u64) {
    guest::write64(context + CONTEXT_CHAIN_HEAD, head);
    guest::write64(context + CONTEXT_PREV_LINKAGE, previous);
    guest::write64(context + CONTEXT_SIGNATURE, wanted);
}

/// RtlpCreateHashTable(Table**, InitialSize, Shift, Flags): InitialSize é
/// potência de dois entre 128 e 0x7FFF80; *Table nulo aloca o cabeçalho.
fn create_sized(holder: u64, initial: u32, shift: u32, flags: u32) -> Result<bool, KernelError> {
    let mask = initial.wrapping_sub(1);
    if initial & mask != 0 || initial.wrapping_sub(SECOND_LEVEL_BASE) > 0x7F_FF00 {
        return Ok(false);
    }
    let mut table = guest::read64(holder);
    let mut header = 0;
    if table == 0 {
        table = allocate(0x28)?;
        if table == 0 {
            return Ok(false);
        }
        header = ALLOCATED_HEADER;
    }
    guest::write64(table + NUM_ENTRIES, 0);
    guest::write64(table + NUM_ENUMERATORS, 0);
    write32(table + DIRECTORY + 4, 0);
    write32(table + PIVOT, 0);
    write32(table + FLAGS, header | flags);
    write32(table + TABLE_SIZE, initial);
    write32(table + DIVISOR_MASK, mask);
    write32(table + SHIFT, shift);
    if initial <= SECOND_LEVEL_BASE {
        let heads = allocate_second_level(0)?;
        if heads == 0 {
            delete(table)?;
            return Ok(false);
        }
        initialize_heads(heads, read32(table + TABLE_SIZE));
        guest::write64(table + DIRECTORY, heads);
    } else {
        // Último balde + 128: o bit alto é o último nível e o resto, o índice
        // da última cabeça dele.
        let biased = initial + 0x7F;
        let bit = 31 - biased.leading_zeros();
        let tail = (1u32 << bit) ^ biased;
        let last_level = bit - 7;
        let first = allocate(FIRST_LEVEL_BYTES)?;
        if first == 0 {
            delete(table)?;
            return Ok(false);
        }
        guest::write_bytes(first, &[0u8; FIRST_LEVEL_BYTES as usize]);
        guest::write64(table + DIRECTORY, first);
        for level in 0..=last_level {
            let heads = allocate_second_level(level)?;
            if heads == 0 {
                delete(table)?;
                return Ok(false);
            }
            initialize_heads(heads, if level < last_level { 1 << (level + 7) } else { tail + 1 });
            guest::write64(first + level as u64 * 8, heads);
        }
    }
    guest::write64(holder, table);
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
pub fn delete(table: u64) -> Result<(), KernelError> {
    let directory = guest::read64(table + DIRECTORY);
    if read32(table + TABLE_SIZE) > SECOND_LEVEL_BASE {
        if directory != 0 {
            for level in 0..16u64 {
                let heads = guest::read64(directory + level * 8);
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
    if read32(table + FLAGS) & ALLOCATED_HEADER != 0 {
        pool_allocation::free(table, 0)?;
    }
    Ok(())
}

/// RtlInsertEntryHashTable(Table, Entry, Signature, Context): contexto nulo
/// ou sem ChainHead é recalculado; com ChainHead, usado como veio.
pub fn insert(table: u64, entry: u64, wanted: u64, context: u64) -> bool {
    guest::write64(entry + SIGNATURE, wanted);
    add32(table + NUM_ENTRIES, 1);
    let (head, previous) = if context == 0 {
        locate(table, wanted)
    } else if guest::read64(context + CONTEXT_CHAIN_HEAD) == 0 {
        let (head, previous) = locate(table, wanted);
        write_context(context, head, previous, wanted);
        (head, previous)
    } else {
        (guest::read64(context + CONTEXT_CHAIN_HEAD), guest::read64(context + CONTEXT_PREV_LINKAGE))
    };
    if is_empty(head) {
        add32(table + NON_EMPTY_BUCKETS, 1);
    }
    insert_after(previous, entry);
    true
}

/// RtlRemoveEntryHashTable(Table, Entry, Context): Flink == Blink marca o
/// último da cadeia; o contexto sem ChainHead recebe a posição da entrada.
pub fn remove(table: u64, entry: u64, context: u64) -> bool {
    let wanted = signature(entry);
    add32(table + NUM_ENTRIES, -1);
    if flink(entry) == blink(entry) {
        add32(table + NON_EMPTY_BUCKETS, -1);
    }
    unlink(entry);
    if context != 0 && guest::read64(context + CONTEXT_CHAIN_HEAD) == 0 {
        let (head, previous) = locate(table, wanted);
        write_context(context, head, previous, wanted);
    }
    true
}

/// RtlLookupEntryHashTable(Table, Signature, Context): a primeira entrada
/// com a assinatura exata; o contexto (opcional) guarda a posição.
pub fn lookup(table: u64, wanted: u64, context: u64) -> u64 {
    let (head, previous) = locate(table, wanted);
    if context != 0 {
        write_context(context, head, previous, wanted);
    }
    let candidate = flink(previous);
    if candidate == head || signature(candidate) != wanted { 0 } else { candidate }
}

/// RtlGetNextEntryHashTable(Table, Context): a próxima com a mesma
/// assinatura; com enumeradores ativos, pula os marcadores (Signature 0).
pub fn get_next(table: u64, context: u64) -> u64 {
    let head = guest::read64(context + CONTEXT_CHAIN_HEAD);
    let mut previous = flink(guest::read64(context + CONTEXT_PREV_LINKAGE));
    let mut next = flink(previous);
    if next == head {
        return 0;
    }
    if read32(table + NUM_ENUMERATORS) != 0 {
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
    if signature(next) != guest::read64(context + CONTEXT_SIGNATURE) {
        return 0;
    }
    guest::write64(context + CONTEXT_PREV_LINKAGE, previous);
    next
}

/// RtlInitEnumerationHashTable (a variante Weak encaminha para esta): o
/// marcador entra na cabeça do balde da assinatura 0 (balde 0).
pub fn init_enumeration(table: u64, enumerator: u64) -> bool {
    let (head, _) = locate(table, 0);
    add32(table + NUM_ENUMERATORS, 1);
    if is_empty(head) {
        add32(table + NON_EMPTY_BUCKETS, 1);
    }
    insert_after(head, enumerator);
    write32(enumerator + ENUMERATOR_BUCKET_INDEX, 0);
    guest::write64(enumerator + SIGNATURE, 0);
    guest::write64(enumerator + ENUMERATOR_CHAIN_HEAD, head);
    true
}

/// RtlEnumerateEntryHashTable (e Weakly...): retoma do marcador, devolve a
/// próxima entrada real e reinsere o marcador logo após ela.
pub fn enumerate(table: u64, enumerator: u64) -> u64 {
    let start = read32(enumerator + ENUMERATOR_BUCKET_INDEX);
    let size = read32(table + TABLE_SIZE);
    let mut bucket = start;
    while bucket < size {
        let (head, mut cursor) = if bucket == start {
            (guest::read64(enumerator + ENUMERATOR_CHAIN_HEAD), enumerator)
        } else {
            let head = chain_head(table, bucket);
            (head, head)
        };
        cursor = flink(cursor);
        while cursor != head {
            if signature(cursor) != 0 {
                unlink(enumerator);
                let old_head = guest::read64(enumerator + ENUMERATOR_CHAIN_HEAD);
                if old_head != head {
                    if is_empty(old_head) {
                        add32(table + NON_EMPTY_BUCKETS, -1);
                    }
                    if is_empty(head) {
                        add32(table + NON_EMPTY_BUCKETS, 1);
                    }
                }
                write32(enumerator + ENUMERATOR_BUCKET_INDEX, bucket);
                guest::write64(enumerator + ENUMERATOR_CHAIN_HEAD, head);
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
    add32(table + NUM_ENUMERATORS, -1);
    if flink(enumerator) != enumerator {
        unlink(enumerator);
        if is_empty(guest::read64(enumerator + ENUMERATOR_CHAIN_HEAD)) {
            add32(table + NON_EMPTY_BUCKETS, -1);
        }
    }
    guest::write64(enumerator + ENUMERATOR_CHAIN_HEAD, 0);
}

/// RtlInitStrongEnumerationHashTable: sem marcador nem NumEnumerators;
/// CurEntry começa na cabeça do balde 0.
pub fn init_strong_enumeration(table: u64, enumerator: u64) -> bool {
    let (head, _) = locate(table, 0);
    guest::write64(enumerator + 0x08, 0);
    guest::write64(enumerator + 0x10, 0);
    guest::write64(enumerator + ENUMERATOR_BUCKET_INDEX, 0);
    guest::write64(enumerator + ENUMERATOR_CHAIN_HEAD, head);
    guest::write64(enumerator, head);
    true
}

/// RtlStronglyEnumerateEntryHashTable: avança CurEntry (o chamador garante
/// que a tabela não muda durante a enumeração forte).
pub fn strongly_enumerate(table: u64, enumerator: u64) -> u64 {
    let start = read32(enumerator + ENUMERATOR_BUCKET_INDEX);
    let size = read32(table + TABLE_SIZE);
    let mut bucket = start;
    while bucket < size {
        let (head, mut cursor) = if bucket == start {
            (guest::read64(enumerator + ENUMERATOR_CHAIN_HEAD), guest::read64(enumerator))
        } else {
            let head = chain_head(table, bucket);
            (head, head)
        };
        cursor = flink(cursor);
        while cursor != head {
            if signature(cursor) != 0 {
                guest::write64(enumerator + ENUMERATOR_CHAIN_HEAD, head);
                write32(enumerator + ENUMERATOR_BUCKET_INDEX, bucket);
                guest::write64(enumerator, cursor);
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
pub fn expand(table: u64) -> Result<bool, KernelError> {
    let size = read32(table + TABLE_SIZE);
    if size == MAXIMUM_TABLE_SIZE || read32(table + NUM_ENUMERATORS) > 0 {
        return Ok(false);
    }
    let biased = size + SECOND_LEVEL_BASE;
    let bit = 31 - biased.leading_zeros();
    let offset = biased ^ (1 << bit);
    let level = bit - 7;
    if size == SECOND_LEVEL_BASE {
        // Passa ao diretório de dois níveis: o antigo vira o nível 0.
        let single = guest::read64(table + DIRECTORY);
        let first = allocate(FIRST_LEVEL_BYTES)?;
        if first == 0 {
            return Ok(false);
        }
        guest::write_bytes(first + 8, &[0u8; FIRST_LEVEL_BYTES as usize - 8]);
        guest::write64(first, single);
        guest::write64(table + DIRECTORY, first);
    }
    let directory = guest::read64(table + DIRECTORY);
    let mut heads = guest::read64(directory + level as u64 * 8);
    if heads == 0 {
        heads = allocate_second_level(level)?;
        if heads == 0 {
            if read32(table + TABLE_SIZE) == SECOND_LEVEL_BASE {
                guest::write64(table + DIRECTORY, guest::read64(directory));
                pool_allocation::free(directory, 0)?;
            }
            return Ok(false);
        }
        guest::write64(directory + level as u64 * 8, heads);
    }
    let pivot = read32(table + PIVOT);
    write32(table + TABLE_SIZE, size + 1);
    let old_head = chain_head(table, pivot);
    write32(table + PIVOT, pivot + 1);
    let new_head = heads + offset as u64 * 16;
    guest::write64(new_head + 8, new_head);
    guest::write64(new_head, new_head);
    if !is_empty(old_head) {
        let mut previous = old_head;
        let mut current = flink(old_head);
        loop {
            let target = hash(signature(current), read32(table + SHIFT)) & expanded_mask(read32(table + DIVISOR_MASK));
            if target != read32(table + TABLE_SIZE) - 1 {
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
            add32(table + NON_EMPTY_BUCKETS, 1);
        }
        if is_empty(old_head) {
            add32(table + NON_EMPTY_BUCKETS, -1);
        }
    }
    let mask = read32(table + DIVISOR_MASK);
    if read32(table + PIVOT) == mask.wrapping_add(1) {
        write32(table + PIVOT, 0);
        write32(table + DIVISOR_MASK, expanded_mask(mask));
    }
    Ok(true)
}

/// RtlContractHashTable: funde o último balde no seu par (mantendo a ordem
/// por assinatura) e libera o nível secundário que esvazia.
pub fn contract(table: u64) -> Result<bool, KernelError> {
    let size = read32(table + TABLE_SIZE);
    if size == SECOND_LEVEL_BASE || read32(table + NUM_ENUMERATORS) > 0 {
        return Ok(false);
    }
    let pivot = match read32(table + PIVOT) {
        0 => {
            let mask = read32(table + DIVISOR_MASK) >> 1;
            write32(table + DIVISOR_MASK, mask);
            mask
        }
        pivot => pivot - 1,
    };
    write32(table + PIVOT, pivot);
    let last = chain_head(table, size - 1);
    let target = chain_head(table, read32(table + PIVOT));
    write32(table + TABLE_SIZE, size - 1);
    if !is_empty(last) && !is_empty(target) {
        add32(table + NON_EMPTY_BUCKETS, -1);
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
        guest::write64(last, after);
        guest::write64(after + 8, last);
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
    let biased = read32(table + TABLE_SIZE) + SECOND_LEVEL_BASE;
    let bit = 31 - biased.leading_zeros();
    if 1u32 << bit == biased {
        let directory = guest::read64(table + DIRECTORY);
        let slot = directory + (bit - 7) as u64 * 8;
        pool_allocation::free(guest::read64(slot), 0)?;
        guest::write64(slot, 0);
        if read32(table + TABLE_SIZE) == SECOND_LEVEL_BASE {
            guest::write64(table + DIRECTORY, guest::read64(directory));
            pool_allocation::free(directory, 0)?;
        }
    }
    Ok(true)
}
