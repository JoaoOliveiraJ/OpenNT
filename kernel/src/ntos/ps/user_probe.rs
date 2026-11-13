//! Sondagem de buffers de usuário (ProbeForRead/ProbeForWrite).
//!
//! O kernel só escreve em buffer de usuário mapeado; se não estiver, a
//! resposta real do NT é STATUS_ACCESS_VIOLATION (nunca uma exceção no
//! handler). Memória supervisora nunca passa.

use crate::ntos::mm::memory_map::USER_ADDRESS_LIMIT;
use crate::ntos::mm::paging;
use crate::rtl::SpinLock;

/// Materializa a página privada de uma seção numa sondagem de escrita
/// (`ntos/ps/user/sections.fault`), instalado com o modo usuário.
static SECTION_FAULT: SpinLock<Option<fn(u64, u32) -> bool>> = SpinLock::new(None);

pub fn set_section_fault_handler(handler: Option<fn(u64, u32) -> bool>) {
    *SECTION_FAULT.lock() = handler;
}

pub fn probe_user_access(va: u64, size: u64, write: bool) -> bool {
    let Some(end) = va.checked_add(size) else { return false };
    if end > USER_ADDRESS_LIMIT {
        return false;
    }
    if size == 0 {
        return true;
    }
    if va == 0 {
        return false;
    }
    let first = va / 0x1000 * 0x1000;
    let last = (va + size - 1) / 0x1000 * 0x1000;
    let required = paging::PAGE_PRESENT | paging::PAGE_USER | if write { paging::PAGE_RW } else { 0 };
    let mut page = first;
    while page <= last {
        if paging::access_flags(page) & required != required {
            // Escritas de convidado usam o alias físico e não geram #PF.
            let fault = *SECTION_FAULT.lock();
            let materialized = write && fault.is_some_and(|fault| fault(page, 7));
            if !materialized || paging::access_flags(page) & required != required {
                return false;
            }
        }
        page += 0x1000;
    }
    true
}

pub fn probe_user_write(va: u64, size: u64) -> bool {
    probe_user_access(va, size, true)
}

pub fn probe_user_read(va: u64, size: u64) -> bool {
    probe_user_access(va, size, false)
}
