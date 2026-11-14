//! O banco do Errata Manager e a trava dele (o EmpDatabaseLock).
//!
//! As listas indexadas por GUID dos tipos de entrada (EmpEntryListHead) e
//! dos callbacks (EmpCallbackListHead). O OpenNT não recebe o INF de
//! errata do carregador, então nada é inserido e as buscas devolvem `None`,
//! como as Emp*Search*Database do ntoskrnl sobre listas vazias; as regras
//! (EmpRuleListHead) também só viriam do INF, e o banco do OpenNT não as
//! tem.

use alloc::vec::Vec;

use crate::ntos::inc::types::Guid;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::sync::SpinLockGuard;
use crate::rtl::SpinLock;

/// Uma entrada do banco: o GUID e o registro dela.
pub struct Record {
    pub guid: [u8; 16],
}

/// O banco interpretado do INF de errata.
pub struct Database {
    pub entries: Vec<Record>,
    pub callbacks: Vec<Record>,
}

static DATABASE: SpinLock<Database> = SpinLock::new(Database { entries: Vec::new(), callbacks: Vec::new() });

/// O EmpDatabaseLock exclusivo.
pub fn lock() -> SpinLockGuard<'static, Database> {
    DATABASE.lock()
}

/// Os 16 bytes do GUID em `address`.
pub fn guid_at(address: u64) -> [u8; 16] {
    let mut guid = [0u8; 16];
    guid.copy_from_slice(&guest::read_bytes(address, core::mem::size_of::<Guid>()));
    guid
}

fn search(records: &[Record], guid: &[u8; 16]) -> Option<usize> {
    records.iter().position(|record| record.guid == *guid)
}

impl Database {
    /// EmpSearchEntryDatabase.
    pub fn search_entry(&self, guid: &[u8; 16]) -> Option<usize> {
        search(&self.entries, guid)
    }

    /// EmpSearchCallbackDatabase.
    pub fn search_callback(&self, guid: &[u8; 16]) -> Option<usize> {
        search(&self.callbacks, guid)
    }
}
