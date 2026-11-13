//! HANDLE_TABLE consumida pela enumeração nativa — `ntos/ob/handle-table.js`.
//!
//! O dono do objeto mantém suas referências; a entrada codifica corpo - 0x30,
//! sem escrever um OBJECT_HEADER antes de uma alocação de outro subsistema.
//! Leituras e compare-exchange operam sobre a memória vista pelo driver.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::ntos::ex::push_lock;
use crate::ntos::ke::{critical_region, dispatcher};
use crate::ntos::inc::status::STATUS_INSUFFICIENT_RESOURCES;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const HANDLE_TABLE_SIZE: u64 = 0x80;
pub const MAXIMUM_HANDLE_VALUE: u32 = 0x7FFF_FFFC;

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
    /// Identidade da publicação (o `===` de linha do original).
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

struct Table {
    pointer: u64,
    process: u64,
    leaves: Vec<u64>,
    directories: Vec<u64>,
    top: u64,
    allocations: Vec<u64>,
    rows: BTreeMap<u32, Row>,
    free_links: Vec<u32>,
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

fn cas64(pointer: u64, expected: u64, replacement: u64) -> u64 {
    guest::compare_exchange64(pointer, expected, replacement).unwrap_or_else(|error| panic!("{error}"))
}

fn read_entry_word(address: u64) -> u64 {
    cas64(address, 0, 0)
}

fn store_entry_word(address: u64, value: u64) {
    let mut previous = read_entry_word(address);
    loop {
        let observed = cas64(address, previous, value);
        if observed == previous {
            return;
        }
        previous = observed;
    }
}

fn allocate_storage(size: u64, page_aligned: bool) -> Result<u64, KernelError> {
    let address = if page_aligned { guest::alloc_page() } else { guest::alloc_bytes(size) };
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
        self.free_links[index] = self.last_free;
        self.free_links[index + 1] = 0;
        if self.last_free != 0 {
            self.free_links[(self.last_free / 2 + 1) as usize] = handle;
            guest::write64(self.slot_entry(self.last_free) + 8, entry);
        } else {
            self.first_free = handle;
            guest::write64(self.pointer + 0x48, entry);
        }
        self.last_free = handle;
        self.free_count += 1;
        guest::write64(entry + 8, 0);
        guest::write64(self.pointer + 0x50, entry);
    }

    /// Retira um slot da lista livre, validando os dois vizinhos.
    fn take_free(&mut self, handle: u32) -> Result<u64, KernelError> {
        let index = (handle / 2) as usize;
        let previous = self.free_links[index];
        let next = self.free_links[index + 1];
        let linked = if previous != 0 { self.free_links[(previous / 2 + 1) as usize] == handle } else { self.first_free == handle };
        let linked_next = if next != 0 { self.free_links[(next / 2) as usize] == handle } else { self.last_free == handle };
        if self.free_count == 0 || !linked || !linked_next {
            return Err(KernelError::new("handle slot is not free"));
        }
        let next_entry = if next != 0 { self.slot_entry(next) } else { 0 };
        if previous != 0 {
            self.free_links[(previous / 2 + 1) as usize] = next;
            guest::write64(self.slot_entry(previous) + 8, next_entry);
        } else {
            self.first_free = next;
            guest::write64(self.pointer + 0x48, next_entry);
        }
        if next != 0 {
            self.free_links[(next / 2) as usize] = previous;
        } else {
            self.last_free = previous;
            guest::write64(self.pointer + 0x50, if previous != 0 { self.slot_entry(previous) } else { 0 });
        }
        self.free_links[index] = 0;
        self.free_links[index + 1] = 0;
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
                let page = allocate_storage(4096, true)?;
                allocated.push(page);
                leaves.push(page);
            }
            if needed > 1 {
                while directories.len() < needed.div_ceil(512) {
                    let page = allocate_storage(4096, true)?;
                    allocated.push(page);
                    directories.push(page);
                }
            }
            if needed > 512 && top == 0 {
                let page = allocate_storage(4096, true)?;
                allocated.push(page);
                top = page;
            }
            Ok(())
        })();
        if let Err(error) = result {
            for &page in allocated.iter().rev() {
                guest::free_bytes(page);
            }
            return Err(error);
        }
        if needed > 1 {
            for index in self.leaves.len()..needed {
                guest::write64(directories[index / 512] + ((index % 512) * 8) as u64, leaves[index]);
            }
        }
        if needed > 1 && self.directories.is_empty() {
            guest::write64(directories[0], leaves[0]);
        }
        if top != 0 {
            for (index, &directory) in directories.iter().enumerate() {
                guest::write64(top + index as u64 * 8, directory);
            }
        }
        let old_count = self.leaves.len();
        if self.free_links.len() < needed * 512 {
            self.free_links.resize((needed * 512).max(self.free_links.len() * 2), 0);
        }
        self.leaves = leaves;
        self.directories = directories;
        self.top = top;
        self.allocations.extend(allocated);
        for page in old_count..needed {
            for slot in 1..256u32 {
                let handle = page as u32 * 1024 + slot * 4;
                self.append_free(handle, self.leaves[page] + slot as u64 * 16);
            }
        }
        let code = if top != 0 { top + 2 } else if needed > 1 { self.directories[0] + 1 } else { self.leaves[0] };
        store_entry_word(self.pointer + 8, code);
        guest::write32(self.pointer, needed as u32 * 1024);
        Ok(())
    }
}

/// Cria a tabela vazia de um processo e a insere na lista global.
pub fn create(process: u64, process_id: u64) -> Result<u64, KernelError> {
    let pointer = allocate_storage(HANDLE_TABLE_SIZE, false)?;
    let mut table = Table {
        pointer,
        process,
        leaves: Vec::new(),
        directories: Vec::new(),
        top: 0,
        allocations: vec![pointer],
        rows: BTreeMap::new(),
        free_links: Vec::new(),
        free_count: 0,
        first_free: 0,
        last_free: 0,
    };
    let mut registry = REGISTRY.lock();
    let mut new_head = 0;
    let result = table.grow(1).and_then(|_| {
        if registry.list_head == 0 {
            new_head = allocate_storage(16, false)?;
            guest::write64(new_head, new_head);
            guest::write64(new_head + 8, new_head);
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
    guest::write64(pointer + 0x10, process);
    guest::write32(pointer + 0x28, process_id as u32);
    let head = registry.list_head;
    let entry = pointer + 0x18;
    let tail = guest::read64(head + 8);
    guest::write64(entry, head);
    guest::write64(entry + 8, tail);
    guest::write64(tail, entry);
    guest::write64(head + 8, entry);
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

/// Serializa mudanças estruturais (push lock em +0x38) com APCs adiadas.
fn with_table_mutation<T>(table: u64, action: impl FnOnce(&mut Table) -> Result<T, KernelError>) -> Result<T, KernelError> {
    assert_live(table)?;
    critical_region::with_critical(|| {
        push_lock::acquire_exclusive(table + 0x38, 0)?;
        let result = {
            let mut registry = REGISTRY.lock();
            match registry.tables.get_mut(&table) {
                Some(owner) => action(owner),
                None => Err(KernelError::new("dead native handle table")),
            }
        };
        push_lock::release_exclusive(table + 0x38, 0)?;
        result
    })
}

/// Codifica o corpo conforme a decodificação nativa de HANDLE_TABLE_ENTRY.
pub fn encode_object_pointer(pointer: u64, attributes: u32) -> Result<u64, KernelError> {
    let header = pointer.wrapping_sub(0x30);
    let canonical = (((header << 16) as i64) >> 16) as u64;
    if pointer < 0x30 || pointer & 15 != 0 || canonical != header {
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
        if read_entry_word(entry) != 0 {
            return Err(KernelError::new("free native handle entry was modified externally"));
        }
        owner.take_free(handle)?;
        guest::write64(entry + 8, description.access as u64);
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
        store_entry_word(entry, low);
        guest::write32(owner.pointer + 0x58, owner.rows.len() as u32);
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
        let low = read_entry_word(row.entry);
        if low == 0 {
            return Err(KernelError::new("live native handle entry was deleted externally"));
        }
        if low & 1 == 0 {
            dispatcher::pump_kernel();
            continue;
        }
        if cas64(row.entry, low, low - 1) == low {
            return Ok(Some(row));
        }
    }
}

fn unlock_entry(entry: u64) -> Result<(), KernelError> {
    let mut value = read_entry_word(entry);
    loop {
        if value == 0 || value & 1 != 0 {
            return Err(KernelError::new("native handle entry lock ownership lost"));
        }
        let observed = cas64(entry, value, value + 1);
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
        guest::write64(row.entry + 8, access as u64);
        store_entry_word(row.entry, (read_entry_word(row.entry) & !(7 << 17)) | ((attributes & 7) as u64) << 17);
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
            store_entry_word(row.entry, 0);
            owner.rows.remove(&handle);
            owner.append_free(handle, row.entry);
            guest::write32(owner.pointer + 0x58, owner.rows.len() as u32);
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
    if !owner.rows.is_empty() || read_entry_word(table + 0x38) != 0 || read_entry_word(table + 0x30) != 0 {
        return Err(KernelError::new("native handle table is still owned"));
    }
    guest::write32(table + 0x2C, guest::read32(table + 0x2C) | 4);
    let entry = table + 0x18;
    let next = guest::read64(entry);
    let previous = guest::read64(entry + 8);
    guest::write64(previous, next);
    guest::write64(next + 8, previous);
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
