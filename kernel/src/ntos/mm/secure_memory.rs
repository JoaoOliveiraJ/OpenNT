//! Faixas de usuário protegidas por MmSecureVirtualMemory (as entradas de
//! segurança dos VADs do NT: MiSecureVad / MiAddSecureEntry / MiRemoveSecureEntry).
//!
//! Contrato do ntoskrnl 19041:
//! - MmSecureVirtualMemory(Address, Size, ProbeMode) =
//!   MmSecureVirtualMemoryEx(Address, Size, ProbeMode == PAGE_READONLY ? 2 : 4, 0).
//! - Ex: fim <= início ou > MmUserProbeAddress (0x7FFFFFFF0000) -> NULL;
//!   ProbeMode fora de {1, 2, 4} -> NULL; nenhum VAD com a primeira página ->
//!   NULL; última página além do VAD -> NULL; salvo ProbeMode bit 0,
//!   MiComparePteProtections exige em toda página acesso de leitura
//!   (PAGE_READONLY) ou escrita -> NULL na divergência; o handle é a entrada
//!   combinada com o processo e um cookie (opaco, não nulo).
//! - MmUnsecureVirtualMemory(Handle): a busca combina o processo corrente, então
//!   um handle de outro contexto é ignorado; VOID.
//!
//! Os "VADs" são as regiões do `ps::user` (privadas do processo ativo ou de
//! outros processos e as vistas de seção do processo), com os mesmos conjuntos
//! de páginas confirmadas e proteções por página que o ZwQueryVirtualMemory
//! relata.
//!
//! Lacuna: a entrada é só registro. No NT uma faixa protegida faz
//! NtFreeVirtualMemory/NtProtectVirtualMemory falharem enquanto existe; isso
//! exige um gancho em `ps/user/memory.rs` (free_in/protect_in).

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::mm::section::views as section_views;
use crate::ntos::ps::process;
use crate::ntos::ps::user::memory::{self, Space};
use crate::ntos::ps::user::state::Region;
use crate::rtl::SpinLock;

const PAGE: u64 = 0x1000;
/// MmUserProbeAddress.
const USER_PROBE_ADDRESS: u64 = crate::ntos::mm::memory_map::USER_PROBE_ADDRESS;
const PAGE_READONLY: u32 = 2;
const PAGE_READWRITE: u32 = 4;
const PAGE_GUARD: u32 = 0x100;

struct Secured {
    process: u64,
    _base: u64,
    _size: u64,
    _probe_mode: u32,
}

static SECURED: SpinLock<BTreeMap<u64, Secured>> = SpinLock::new(BTreeMap::new());
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

/// O "VAD" que contém o endereço: vista de seção do processo ou região
/// privada do espaço dele.
fn region_of(process: u64, address: u64) -> Option<Region> {
    if let Some(view) = section_views::find(process, address) {
        return Some(view.region());
    }
    match Space::of(process) {
        Space::Active => memory::find_region(address),
        Space::Foreign(owner) => memory::foreign_regions(owner).into_iter().find(|region| address >= region.base() && address < region.base() + region.size()),
    }
}

/// MiComparePteProtections: leitura aceita tudo que não seja NOACCESS ou
/// GUARD; escrita exige READWRITE/WRITECOPY (executável ou não). Região sem
/// proteção registrada é RW, como o ZwQueryVirtualMemory a reporta.
fn allows(protect: u32, write: bool) -> bool {
    if protect == 0 {
        return true;
    }
    if protect & PAGE_GUARD != 0 {
        return false;
    }
    match protect & 0xFF {
        0x04 | 0x08 | 0x40 | 0x80 => true,
        0x02 | 0x10 | 0x20 => !write,
        _ => false,
    }
}

/// Páginas [first, end) confirmadas e com o acesso pedido.
fn pages_accessible(region: &Region, first: u64, end: u64, write: bool) -> bool {
    let committed = region.committed_pages();
    let mut page = first;
    while page < end {
        let index = (page - region.base()) / PAGE;
        if committed.as_ref().is_some_and(|pages| !pages.contains(&index)) {
            return false;
        }
        let protect = region.page_protect(index).filter(|&protect| protect != 0).unwrap_or_else(|| region.protect());
        if !allows(protect, write) {
            return false;
        }
        page += PAGE;
    }
    true
}

/// MmSecureVirtualMemoryEx com Flags = 0; 0 = NULL.
fn secure_range(address: u64, size: u64, probe_mode: u32) -> u64 {
    let end = address.wrapping_add(size);
    if end <= address || end > USER_PROBE_ADDRESS {
        return 0;
    }
    if !matches!(probe_mode, 1 | 2 | 4) {
        return 0;
    }
    let process = process::get_current_process();
    let first = address & !(PAGE - 1);
    let Some(region) = region_of(process, first) else { return 0 };
    if (end - 1) >> 12 > (region.base() + region.size() - 1) >> 12 {
        return 0;
    }
    if probe_mode & 1 == 0 && !pages_accessible(&region, first, (end - 1) | (PAGE - 1), probe_mode != PAGE_READONLY) {
        return 0;
    }
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    SECURED.lock().insert(handle, Secured { process, _base: address, _size: size, _probe_mode: probe_mode });
    handle
}

/// MmSecureVirtualMemory(Address, Size, ProbeMode): o handle ou 0.
pub fn secure(address: u64, size: u64, probe_mode: u32) -> u64 {
    secure_range(address, size, if probe_mode == PAGE_READONLY { PAGE_READONLY } else { PAGE_READWRITE })
}

/// MmUnsecureVirtualMemory(Handle): só a entrada do processo corrente sai.
pub fn unsecure(handle: u64) {
    let process = process::get_current_process();
    let mut secured = SECURED.lock();
    if secured.get(&handle).is_some_and(|entry| entry.process == process) {
        secured.remove(&handle);
    }
}
