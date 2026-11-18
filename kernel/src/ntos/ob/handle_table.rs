//! HANDLE_TABLE consumida pela enumeração nativa.
//!
//! O dono do objeto mantém suas referências; a entrada codifica corpo - 0x30,
//! sem escrever um OBJECT_HEADER antes de uma alocação de outro subsistema.
//! Leituras e compare-exchange operam sobre a memória vista pelo driver.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::ntos::ex::push_lock;
use crate::ntos::ke::{critical_region, dispatcher};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::status::STATUS_INSUFFICIENT_RESOURCES;
use crate::ntos::inc::types::{HandleTable, HandleTableEntry, ListEntry, ObjectHeader};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

pub const MAXIMUM_HANDLE_VALUE: u32 = 0x7FFF_FFFC;

/// Distância do corpo ao início do OBJECT_HEADER (`Body` em +0x30).
const OBJECT_HEADER_BODY: u64 = core::mem::offset_of!(ObjectHeader, body) as u64;

/// Linha publicada: identidade, atributos e direitos de um handle.
#[derive(Clone, Debug)]
pub struct Row {
    pub pointer: u64,
    pub type_name: alloc::string::String,
    /// Identidade do dono (nó do Object Manager, registro de arquivo...).
    pub identity: u64,
    /// Corpo nativo alternativo (namespace, abertura nativa), se houver.
    pub native_body: u64,
    pub attributes: u32,
    pub access: u32,
    pub entry: u64,
    pub handle: u32,
    /// Identidade da publicação.
    pub serial: u64,
}

/// Descrição de um handle a publicar.
#[derive(Clone, Debug)]
pub struct HandleDescription {
    pub pointer: u64,
    pub type_name: alloc::string::String,
    pub identity: u64,
    pub native_body: u64,
    pub attributes: u32,
    pub access: u32,
}

/// O índice da lista livre (predecessor e sucessor de cada slot, dois ULONGs
/// por slot, posição `handle / 2`) em frames do PFN, fora do heap: os
/// identificadores de handle são globais e crescentes, então toda tabela
/// cobre até o maior em uso no sistema.
#[derive(Default)]
struct FreeLinks {
    frames: Vec<u64>,
    /// ULONGs em uso (os frames cobrem pelo menos isso).
    length: usize,
}

const LINKS_PER_FRAME: usize = 1024;

impl FreeLinks {
    fn len(&self) -> usize {
        self.length
    }

    /// Cresce até `length` ULONGs zerados.
    fn reserve(&mut self, length: usize) -> Result<(), KernelError> {
        while self.frames.len() * LINKS_PER_FRAME < length {
            let frame = crate::ntos::mm::pfn::alloc_page();
            if frame == 0 {
                return Err(KernelError::with_status("handle table free index: PFN esgotado", STATUS_INSUFFICIENT_RESOURCES));
            }
            crate::hal::physical::zero(frame, 4096);
            self.frames.push(frame);
        }
        self.length = self.length.max(length);
        Ok(())
    }

    fn cell(&self, index: usize) -> u64 {
        self.frames[index / LINKS_PER_FRAME] + (index % LINKS_PER_FRAME) as u64 * 4
    }

    fn get(&self, index: usize) -> u32 {
        crate::hal::physical::read32(self.cell(index))
    }

    fn set(&self, index: usize, value: u32) {
        crate::hal::physical::write32(self.cell(index), value);
    }
}

impl Drop for FreeLinks {
    fn drop(&mut self) {
        for &frame in &self.frames {
            crate::ntos::mm::pfn::free_page(frame);
        }
    }
}

/// As páginas da tabela (folhas, diretórios e a de topo): VirtualAlloc de
/// kernel (frames do PFN numa VA de sistema), como o pool paginado de que o
/// NT tira as tabelas de handles, fora da arena dos convidados. O `Drop`
/// devolve as páginas.
#[derive(Default)]
struct TablePages {
    pages: Vec<u64>,
}

impl TablePages {
    /// Uma página zerada.
    fn allocate() -> Result<u64, KernelError> {
        let page = crate::ntos::mm::virtual_memory::alloc(4096);
        if page == 0 {
            return Err(KernelError::with_status("native handle table allocation failed", STATUS_INSUFFICIENT_RESOURCES));
        }
        // SAFETY: página recém-mapeada, só desta tabela.
        unsafe { core::ptr::write_bytes(page as *mut u8, 0, 4096) };
        Ok(page)
    }

    fn release(pages: &[u64]) {
        for &page in pages.iter().rev() {
            crate::ntos::mm::virtual_memory::free(page, 4096);
        }
        // Outra CPU pode guardar a tradução: a VA só volta a ser usada
        // depois da invalidação em todas.
        if !pages.is_empty() {
            if let Err(error) = crate::ntos::ke::smp::flush_remote_tlb(false) {
                crate::debug_print!("[ob] paginas de tabela de handles: {}", error);
            }
        }
    }
}

impl Drop for TablePages {
    fn drop(&mut self) {
        TablePages::release(&self.pages);
    }
}

struct Table {
    pointer: u64,
    process: u64,
    leaves: Vec<u64>,
    directories: Vec<u64>,
    top: u64,
    allocations: Vec<u64>,
    pages: TablePages,
    rows: BTreeMap<u32, Row>,
    free_links: FreeLinks,
    free_count: u32,
    first_free: u32,
    last_free: u32,
}

struct Registry {
    tables: BTreeMap<u64, Table>,
    list_head: u64,
}

static NEXT_SERIAL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

static REGISTRY: SpinLock<Registry> = SpinLock::new(Registry { tables: BTreeMap::new(), list_head: 0 });

/// A HANDLE_TABLE de `address` (alocada por `create`, viva no registro).
fn table_at(address: u64) -> &'static HandleTable {
    // SAFETY: só endereços de tabelas criadas por `create`.
    unsafe { HandleTable::at(address) }
}

/// A entrada de `address` (folhas alocadas por `grow`, nunca liberadas
/// antes da tabela).
fn entry_at(address: u64) -> &'static HandleTableEntry {
    // SAFETY: endereço de slot calculado por `slot_entry`.
    unsafe { HandleTableEntry::at(address) }
}

/// Palavra baixa da entrada (LowValue), lida de forma atômica.
fn read_entry_word(entry: &HandleTableEntry) -> u64 {
    entry.volatile_low_value.atomic().load(Ordering::SeqCst) as u64
}

/// Troca atômica da palavra baixa da entrada.
fn store_entry_word(entry: &HandleTableEntry, value: u64) {
    entry.volatile_low_value.atomic().swap(value as i64, Ordering::SeqCst);
}

/// LOCK CMPXCHG na palavra baixa; devolve o valor anterior.
fn cas_entry_word(entry: &HandleTableEntry, expected: u64, replacement: u64) -> u64 {
    match entry.volatile_low_value.atomic().compare_exchange(expected as i64, replacement as i64, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(previous) | Err(previous) => previous as u64,
    }
}

/// A HANDLE_TABLE e a cabeça da lista global, na arena dos convidados.
fn allocate_storage(size: u64) -> Result<u64, KernelError> {
    let address = guest::alloc_bytes(size);
    if address == 0 {
        return Err(KernelError::with_status("native handle table allocation failed", STATUS_INSUFFICIENT_RESOURCES));
    }
    Ok(address)
}

/// A entrada zero de cada folha é reservada; os dois bits baixos não são índice.
pub fn handle_value(value: u64) -> Result<u32, KernelError> {
    if value < 4 || value > MAXIMUM_HANDLE_VALUE as u64 || value & 3 != 0 || value & 1023 == 0 {
        return Err(KernelError::new("invalid native handle table slot"));
    }
    Ok(value as u32)
}

impl Table {
    fn slot_entry(&self, handle: u32) -> u64 {
        self.leaves[(handle / 1024) as usize] + ((handle & 1023) * 4) as u64
    }

    /// Acrescenta à lista livre nativa e ao índice de predecessores.
    fn append_free(&mut self, handle: u32, entry: u64) {
        let index = (handle / 2) as usize;
        self.free_links.set(index, self.last_free);
        self.free_links.set(index + 1, 0);
        let free_list = &table_at(self.pointer).free_lists[0];
        if self.last_free != 0 {
            self.free_links.set((self.last_free / 2 + 1) as usize, handle);
            entry_at(self.slot_entry(self.last_free)).next_free_handle_entry.set(entry);
        } else {
            self.first_free = handle;
            free_list.first_free_handle_entry.set(entry);
        }
        self.last_free = handle;
        self.free_count += 1;
        entry_at(entry).next_free_handle_entry.set(0);
        free_list.last_free_handle_entry.set(entry);
    }

    /// Retira um slot da lista livre, validando os dois vizinhos.
    fn take_free(&mut self, handle: u32) -> Result<u64, KernelError> {
        let index = (handle / 2) as usize;
        if index + 1 >= self.free_links.len() {
            return Err(KernelError::new("handle slot is not free"));
        }
        let previous = self.free_links.get(index);
        let next = self.free_links.get(index + 1);
        let linked = if previous != 0 { self.free_links.get((previous / 2 + 1) as usize) == handle } else { self.first_free == handle };
        let linked_next = if next != 0 { self.free_links.get((next / 2) as usize) == handle } else { self.last_free == handle };
        if self.free_count == 0 || !linked || !linked_next {
            return Err(KernelError::new("handle slot is not free"));
        }
        let free_list = &table_at(self.pointer).free_lists[0];
        let next_entry = if next != 0 { self.slot_entry(next) } else { 0 };
        if previous != 0 {
            self.free_links.set((previous / 2 + 1) as usize, next);
            entry_at(self.slot_entry(previous)).next_free_handle_entry.set(next_entry);
        } else {
            self.first_free = next;
            free_list.first_free_handle_entry.set(next_entry);
        }
        if next != 0 {
            self.free_links.set((next / 2) as usize, previous);
        } else {
            self.last_free = previous;
            free_list.last_free_handle_entry.set(if previous != 0 { self.slot_entry(previous) } else { 0 });
        }
        self.free_links.set(index, 0);
        self.free_links.set(index + 1, 0);
        self.free_count -= 1;
        Ok(self.slot_entry(handle))
    }

    /// Expande folhas e diretórios sem invalidar endereços já entregues.
    fn grow(&mut self, needed: usize) -> Result<(), KernelError> {
        if needed <= self.leaves.len() {
            return Ok(());
        }
        let mut allocated = Vec::new();
        let mut leaves = self.leaves.clone();
        let mut directories = self.directories.clone();
        let mut top = self.top;
        let result = (|| -> Result<(), KernelError> {
            while leaves.len() < needed {
                let page = TablePages::allocate()?;
                allocated.push(page);
                leaves.push(page);
            }
            if needed > 1 {
                while directories.len() < needed.div_ceil(512) {
                    let page = TablePages::allocate()?;
                    allocated.push(page);
                    directories.push(page);
                }
            }
            if needed > 512 && top == 0 {
                let page = TablePages::allocate()?;
                allocated.push(page);
                top = page;
            }
            // O índice livre cresce antes de qualquer página ser ligada.
            self.free_links.reserve(needed * 512)
        })();
        if let Err(error) = result {
            TablePages::release(&allocated);
            return Err(error);
        }
        // Páginas intermediária e de topo: vetores de 512 ponteiros.
        // SAFETY: páginas recém-alocadas por `TablePages::allocate` (4 KiB cada).
        let pointers = |page: u64| unsafe { Field::<u64>::array_at(page, 512) };
        if needed > 1 {
            for index in self.leaves.len()..needed {
                pointers(directories[index / 512])[index % 512].set(leaves[index]);
            }
        }
        if needed > 1 && self.directories.is_empty() {
            pointers(directories[0])[0].set(leaves[0]);
        }
        if top != 0 {
            for (index, &directory) in directories.iter().enumerate() {
                pointers(top)[index].set(directory);
            }
        }
        let old_count = self.leaves.len();
        self.leaves = leaves;
        self.directories = directories;
        self.top = top;
        self.pages.pages.extend(allocated);
        for page in old_count..needed {
            for slot in 1..256u32 {
                let handle = page as u32 * 1024 + slot * 4;
                self.append_free(handle, self.leaves[page] + slot as u64 * HandleTableEntry::SIZE);
            }
        }
        let code = if top != 0 { top + 2 } else if needed > 1 { self.directories[0] + 1 } else { self.leaves[0] };
        let table = table_at(self.pointer);
        table.table_code.atomic().swap(code, Ordering::SeqCst);
        table.next_handle_needing_pool.set(needed as u32 * 1024);
        Ok(())
    }
}

/// Cria a tabela vazia de um processo e a insere na lista global.
pub fn create(process: u64, process_id: u64) -> Result<u64, KernelError> {
    let pointer = allocate_storage(HandleTable::SIZE)?;
    let mut table = Table {
        pointer,
        process,
        leaves: Vec::new(),
        directories: Vec::new(),
        top: 0,
        allocations: vec![pointer],
        pages: TablePages::default(),
        rows: BTreeMap::new(),
        free_links: FreeLinks::default(),
        free_count: 0,
        first_free: 0,
        last_free: 0,
    };
    let mut registry = REGISTRY.lock();
    let mut new_head = 0;
    let result = table.grow(1).and_then(|_| {
        if registry.list_head == 0 {
            new_head = allocate_storage(ListEntry::SIZE)?;
            // SAFETY: alocação nova do tamanho de um LIST_ENTRY.
            let head = unsafe { ListEntry::at(new_head) };
            head.flink.set(new_head);
            head.blink.set(new_head);
        }
        Ok(())
    });
    if let Err(error) = result {
        for &allocation in table.allocations.iter().rev() {
            guest::free_bytes(allocation);
        }
        if new_head != 0 {
            guest::free_bytes(new_head);
        }
        return Err(error);
    }
    if new_head != 0 {
        registry.list_head = new_head;
    }
    let native = table_at(pointer);
    native.quota_process.set(process);
    native.unique_process_id.set(process_id as u32);
    // InsertTailList na lista global de tabelas (sob o registro).
    // SAFETY: cabeça alocada acima e entradas de tabelas vivas.
    let head = unsafe { ListEntry::at(registry.list_head) };
    let entry = &native.handle_table_list;
    let tail = head.blink.get();
    entry.flink.set(head.address());
    entry.blink.set(tail);
    unsafe { ListEntry::at(tail) }.flink.set(entry.address());
    head.blink.set(entry.address());
    registry.tables.insert(pointer, table);
    Ok(pointer)
}

fn assert_live(table: u64) -> Result<(), KernelError> {
    if REGISTRY.lock().tables.contains_key(&table) {
        Ok(())
    } else {
        Err(KernelError::new("dead native handle table"))
    }
}

/// Serializa mudanças estruturais (HandleTableLock) com APCs adiadas.
fn with_table_mutation<T>(table: u64, action: impl FnOnce(&mut Table) -> Result<T, KernelError>) -> Result<T, KernelError> {
    assert_live(table)?;
    let lock = table_at(table).handle_table_lock.address();
    critical_region::with_critical(|| {
        push_lock::acquire_exclusive(lock, 0)?;
        let result = {
            let mut registry = REGISTRY.lock();
            match registry.tables.get_mut(&table) {
                Some(owner) => action(owner),
                None => Err(KernelError::new("dead native handle table")),
            }
        };
        push_lock::release_exclusive(lock, 0)?;
        result
    })
}

/// Codifica o corpo conforme a decodificação nativa de HANDLE_TABLE_ENTRY.
pub fn encode_object_pointer(pointer: u64, attributes: u32) -> Result<u64, KernelError> {
    let header = pointer.wrapping_sub(OBJECT_HEADER_BODY);
    let canonical = (((header << 16) as i64) >> 16) as u64;
    if pointer < OBJECT_HEADER_BODY || pointer & 15 != 0 || canonical != header {
        return Err(KernelError::new("object body cannot be encoded in a native handle entry"));
    }
    // Bit 0 = entrada destravada; os três atributos ocupam seus bits nativos.
    Ok((header << 16) | ((attributes & 7) as u64) << 17 | 1)
}

/// Publica um objeto já referenciado pelo dono numa entrada livre.
pub fn insert(table: u64, handle: u64, description: &HandleDescription) -> Result<Row, KernelError> {
    let handle = handle_value(handle)?;
    let low = encode_object_pointer(description.pointer, description.attributes)?;
    with_table_mutation(table, |owner| {
        if owner.rows.contains_key(&handle) {
            return Err(KernelError::new("duplicate native handle table entry"));
        }
        owner.grow((handle / 1024) as usize + 1)?;
        let entry = owner.slot_entry(handle);
        let native = entry_at(entry);
        if read_entry_word(native) != 0 {
            return Err(KernelError::new("free native handle entry was modified externally"));
        }
        owner.take_free(handle)?;
        native.high_value.set(description.access as i64);
        let row = Row {
            pointer: description.pointer,
            type_name: description.type_name.clone(),
            identity: description.identity,
            native_body: description.native_body,
            attributes: description.attributes,
            access: description.access,
            entry,
            handle,
            serial: NEXT_SERIAL.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
        };
        owner.rows.insert(handle, row.clone());
        store_entry_word(native, low);
        table_at(owner.pointer).free_lists[0].handle_count.set(owner.rows.len() as i32);
        Ok(row)
    })
}

/// Adquire o bit de trava sem devolver uma identidade substituída.
fn acquire_entry(table: u64, handle: u32) -> Result<Option<Row>, KernelError> {
    assert_live(table)?;
    let Some(row) = REGISTRY.lock().tables.get(&table).and_then(|owner| owner.rows.get(&handle).cloned()) else {
        return Ok(None);
    };
    loop {
        let current = REGISTRY.lock().tables.get(&table).and_then(|owner| owner.rows.get(&handle).map(|current| current.serial));
        if current != Some(row.serial) {
            return Ok(None);
        }
        let entry = entry_at(row.entry);
        let low = read_entry_word(entry);
        if low == 0 {
            return Err(KernelError::new("live native handle entry was deleted externally"));
        }
        if low & 1 == 0 {
            dispatcher::pump_kernel();
            continue;
        }
        if cas_entry_word(entry, low, low - 1) == low {
            return Ok(Some(row));
        }
    }
}

fn unlock_entry(entry: u64) -> Result<(), KernelError> {
    let entry = entry_at(entry);
    let mut value = read_entry_word(entry);
    loop {
        if value == 0 || value & 1 != 0 {
            return Err(KernelError::new("native handle entry lock ownership lost"));
        }
        let observed = cas_entry_word(entry, value, value + 1);
        if observed == value {
            return Ok(());
        }
        value = observed;
    }
}

/// Consulta/mudança sob a trava da entrada. `action` devolve (resultado,
/// removida).
fn entry_operation<T>(table: u64, handle: u32, empty: T, action: impl FnOnce(&Row) -> Result<(T, bool), KernelError>) -> Result<T, KernelError> {
    critical_region::with_critical(|| {
        let Some(row) = acquire_entry(table, handle)? else { return Ok(empty) };
        let result = action(&row);
        let removed = matches!(result, Ok((_, true)));
        if !removed {
            unlock_entry(row.entry)?;
        }
        result.map(|(value, _)| value)
    })
}

/// Atualiza atributos e direitos sob a mesma trava.
pub fn change(table: u64, handle: u64, attributes: u32, access: u32) -> Result<bool, KernelError> {
    let handle = handle_value(handle)?;
    entry_operation(table, handle, false, |row| {
        let entry = entry_at(row.entry);
        entry.high_value.set(access as i64);
        // CAS nos bits Attributes (17..=19); a entrada continua travada.
        entry.set_attributes((attributes & 7) as u64);
        if let Some(stored) = REGISTRY.lock().tables.get_mut(&table).and_then(|owner| owner.rows.get_mut(&handle)) {
            stored.attributes = attributes;
            stored.access = access;
        }
        Ok((true, false))
    })
}

/// O chamador retém o rundown da tabela; uma referência obtida em `action`
/// sobrevive à liberação desta trava.
pub fn with_entry<T>(table: u64, handle: u32, action: impl FnOnce(&Row) -> Result<T, KernelError>) -> Result<Option<T>, KernelError> {
    entry_operation(table, handle, None, |row| action(row).map(|value| (Some(value), false)))
}

/// Remove uma entrada protegida e devolve sua identidade ao dono.
pub fn remove(table: u64, handle: u64) -> Result<Option<Row>, KernelError> {
    let handle = handle_value(handle)?;
    entry_operation(table, handle, None, |row| {
        let row = row.clone();
        with_table_mutation(table, |owner| {
            store_entry_word(entry_at(row.entry), 0);
            owner.rows.remove(&handle);
            owner.append_free(handle, row.entry);
            table_at(owner.pointer).free_lists[0].handle_count.set(owner.rows.len() as i32);
            Ok(())
        })?;
        Ok((Some(row), true))
    })
}

/// Destrói uma tabela sem handles, rundown ou donos de trava.
pub fn destroy(table: u64) -> Result<(), KernelError> {
    let mut registry = REGISTRY.lock();
    let Some(owner) = registry.tables.get(&table) else {
        return Err(KernelError::new("dead native handle table"));
    };
    let native = table_at(table);
    if !owner.rows.is_empty() || native.handle_table_lock.value.atomic().load(Ordering::SeqCst) != 0 || native.handle_contention_event.value.atomic().load(Ordering::SeqCst) != 0 {
        return Err(KernelError::new("native handle table is still owned"));
    }
    // Flags.Rundown por CAS: outros bits de Flags não se perdem.
    native.set_rundown(1);
    // RemoveEntryList da lista global (sob o registro).
    let entry = &native.handle_table_list;
    let next = entry.flink.get();
    let previous = entry.blink.get();
    // SAFETY: vizinhos são a cabeça global ou entradas de tabelas vivas.
    unsafe {
        ListEntry::at(previous).flink.set(next);
        ListEntry::at(next).blink.set(previous);
    }
    let owner = registry.tables.remove(&table).unwrap();
    for &allocation in owner.allocations.iter().rev() {
        guest::free_bytes(allocation);
    }
    if registry.tables.is_empty() {
        guest::free_bytes(registry.list_head);
        registry.list_head = 0;
    }
    Ok(())
}

pub fn exists(table: u64) -> bool {
    REGISTRY.lock().tables.contains_key(&table)
}

pub fn process_of(table: u64) -> Option<u64> {
    REGISTRY.lock().tables.get(&table).map(|owner| owner.process)
}

pub fn rows(table: u64) -> Vec<Row> {
    REGISTRY.lock().tables.get(&table).map(|owner| owner.rows.values().cloned().collect()).unwrap_or_default()
}

pub fn row(table: u64, handle: u32) -> Option<Row> {
    REGISTRY.lock().tables.get(&table).and_then(|owner| owner.rows.get(&handle).cloned())
}

pub fn list_head() -> u64 {
    REGISTRY.lock().list_head
}

/// Armazenamento do dono: (folhas, slots livres, ULONGs do índice livre).
pub fn storage(table: u64) -> Option<(usize, u32, usize)> {
    REGISTRY.lock().tables.get(&table).map(|owner| (owner.leaves.len(), owner.free_count, owner.free_links.len()))
}

// ---- Handles inválidos de modo usuário (verificação estrita) -----------------
//
// No ntoskrnl 19041, um handle que não está na tabela passa por aqui:
// - o ObpReferenceObjectByHandleWithTag (handle não nulo) chama
//   ExHandleLogBadReference(tabela, handle, KTHREAD.PreviousMode);
// - o NtClose (handle fora de -6..0) consulta o ExQueryHandleExceptionsPermanency
//   e, com RaiseUMExceptionOnInvalidHandleClose e as exceções permanentes,
//   chama o mesmo ExHandleLogBadReference; depois, em UserMode, levanta
//   STATUS_INVALID_HANDLE por conta própria com FLG_ENABLE_CLOSE_EXCEPTIONS,
//   EPROCESS.DebugPort ou HANDLE_TABLE.DebugInfo.
// O ExHandleLogBadReference só levanta com EnableHandleExceptions (o
// ProcessHandleCheckingMode, a verificação estrita do dwm.exe), PreviousMode
// UserMode, a thread sem anexação e a tabela do processo corrente dela. O
// KeRaiseUserException desvia o retorno do serviço para o
// KiRaiseUserExceptionDispatcher da NTDLL, que levanta o código no anel 3. O
// OpenNT não tem o rastreio de handles (DebugInfo fica 0, mas é lido).

const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
/// NtGlobalFlag: FLG_APPLICATION_VERIFIER (a linha "AVRF:" do log).
const FLG_APPLICATION_VERIFIER: u32 = 0x100;
/// NtGlobalFlag: FLG_ENABLE_CLOSE_EXCEPTIONS.
const FLG_ENABLE_CLOSE_EXCEPTIONS: u32 = 0x40_0000;

/// ExQueryHandleExceptionsPermanency (rva 0x380800), sob o HandleTableLock:
/// (ligadas, permanentes). Com DebugInfo, ligadas e o bit 3 dos flags dele;
/// senão EnableHandleExceptions liga as duas.
pub fn handle_exceptions_permanency(table: u64) -> Result<(bool, bool), KernelError> {
    let handle_table = table_at(table);
    let lock = handle_table.handle_table_lock.address();
    critical_region::with_critical(|| {
        push_lock::acquire_exclusive(lock, 0)?;
        let debug_info = handle_table.debug_info.get();
        let result = if debug_info != 0 {
            (true, guest::read::<u32>(debug_info + 8) >> 3 & 1 != 0)
        } else {
            let enabled = handle_table.enable_handle_exceptions() != 0;
            (enabled, enabled)
        };
        push_lock::release_exclusive(lock, 0)?;
        Ok(result)
    })
}

/// A thread corrente e o processo corrente dela (ApcState.Process), com a
/// anexação (KTHREAD.ApcStateIndex 1).
fn current_context() -> Option<(u64, u64, bool)> {
    use crate::ntos::inc::types::Kthread;
    let thread = crate::ntos::ps::process::get_current_thread();
    if thread == 0 {
        return None;
    }
    // SAFETY: a KTHREAD corrente.
    let kthread = unsafe { Kthread::at(thread) };
    Some((thread, kthread.apc_state.process.get(), kthread.apc_state_index.get() == 1))
}

/// EPROCESS.ObjectTable de `process`.
fn object_table_of(process: u64) -> u64 {
    // SAFETY: o processo corrente da thread corrente, vivo enquanto ela roda.
    (process != 0).then(|| unsafe { crate::ntos::inc::types::Eprocess::at(process) }.object_table.get()).unwrap_or(0)
}

/// KeRaiseUserException(STATUS_INVALID_HANDLE), com a linha na serial.
fn raise_invalid_handle(handle: u64, process: u64) -> u32 {
    debug_print!("[ob] handle {:#x} invalido no processo {:#x}: STATUS_INVALID_HANDLE levantado no anel 3", handle, process);
    crate::ntos::ke::kernel_exception::raise_user_exception(STATUS_INVALID_HANDLE)
}

/// ExHandleLogBadReference(HandleTable, Handle, PreviousMode) do ntoskrnl
/// 19041 (rva 0x2011c8, corpo frio 0x41f1fa).
pub fn log_bad_reference(table: u64, handle: u64, previous_mode: u8) {
    if table == 0 || table_at(table).enable_handle_exceptions() == 0 || previous_mode != 1 {
        return;
    }
    let Some((_, process, attached)) = current_context() else { return };
    if attached || object_table_of(process) != table {
        return;
    }
    if crate::ntos::rtl::shared_data::nt_global_flag() & FLG_APPLICATION_VERIFIER != 0 {
        debug_print!("AVRF: Invalid handle {:#x} in process {:#x}", handle, process);
    }
    raise_invalid_handle(handle, process);
}

/// O ObpReferenceObjectByHandleWithTag de um handle que não resolveu: um
/// handle de kernel em KernelMode é da tabela de kernel (nunca levanta); os
/// demais, da tabela do processo corrente, com o PreviousMode da thread.
pub fn bad_reference(handle: u64, access_mode: u8) {
    if handle == 0 || (access_mode == 0 && handle & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000) {
        return;
    }
    let Some((thread, process, _)) = current_context() else { return };
    // SAFETY: a KTHREAD corrente.
    let previous_mode = unsafe { crate::ntos::inc::types::Kthread::at(thread) }.previous_mode.get() as u8;
    log_bad_reference(object_table_of(process), handle, previous_mode);
}

/// O NtClose de modo usuário de um handle que não está na tabela do
/// processo corrente (ntoskrnl 19041, NtClose 0x63e1cf..0x63e26d): o handle
/// 0 só devolve STATUS_INVALID_HANDLE; os demais passam pelo
/// ExHandleLogBadReference quando a tabela tem
/// RaiseUMExceptionOnInvalidHandleClose e as exceções permanentes, e
/// levantam STATUS_INVALID_HANDLE fora de uma anexação com
/// FLG_ENABLE_CLOSE_EXCEPTIONS, EPROCESS.DebugPort ou HANDLE_TABLE.DebugInfo.
pub fn bad_user_close(handle: u64) -> u32 {
    // -6..-1 já fecharam com sucesso.
    if handle.wrapping_add(6) <= 6 {
        return STATUS_INVALID_HANDLE;
    }
    let Some((_, process, attached)) = current_context() else { return STATUS_INVALID_HANDLE };
    let table = object_table_of(process);
    if table == 0 {
        return STATUS_INVALID_HANDLE;
    }
    let handle_table = table_at(table);
    let permanent = handle_exceptions_permanency(table).is_ok_and(|(_, permanent)| permanent);
    if handle_table.raise_um_exception_on_invalid_handle_close() != 0 && permanent {
        log_bad_reference(table, handle, 1);
    }
    // SAFETY: o processo corrente da thread corrente.
    let debugged = unsafe { crate::ntos::inc::types::Eprocess::at(process) }.debug_port.get() != 0;
    let close_exceptions = crate::ntos::rtl::shared_data::nt_global_flag() & FLG_ENABLE_CLOSE_EXCEPTIONS != 0;
    if (close_exceptions || debugged || handle_table.debug_info.get() != 0) && !attached {
        return raise_invalid_handle(handle, process);
    }
    STATUS_INVALID_HANDLE
}
