//! Faixas de usuário protegidas por MmSecureVirtualMemory (as entradas de
//! segurança dos VADs do NT: MiSecureVad / MiAddSecureEntry /
//! MiRemoveSecureEntry / MiCheckSecuredVad).
//!
//! Contrato do ntoskrnl 19041:
//! - MmSecureVirtualMemory(Address, Size, ProbeMode) =
//!   MmSecureVirtualMemoryEx(Address, Size, ProbeMode == PAGE_READONLY ? 2 : 4, 0)
//!   (rva 0x6201b0).
//! - MmSecureVirtualMemoryEx(Address, Size, ProbeMode, Flags) (rva 0x620040):
//!   Flags fora de 0xF -> NULL; fim <= início ou > MmUserProbeAddress
//!   (0x7FFFFFFF0000) -> NULL; ProbeMode fora de {1, 2, 4} -> NULL; nenhum
//!   VAD com a primeira página -> NULL; última página além do VAD -> NULL; VAD
//!   AWE ou privado de página grande -> NULL (o OpenNT não cria nenhum dos
//!   dois: MEM_PHYSICAL e MEM_LARGE_PAGES são recusados na alocação). Flags
//!   bit 1 vira o bit 31 do ProbeMode passado ao MiSecureVad.
//! - MiSecureVad (rva 0x61fad0): a faixa em páginas inteiras; sem o bit 0 do
//!   ProbeMode, o MiComparePteProtections exige em toda página acesso de
//!   leitura (ProbeMode == 2, comparado com o bit 31 incluso) ou de escrita.
//! - MiAddSecureEntry (rva 0x61fbe0): num VAD já NoChange, Flags bit 0
//!   (exclusiva) -> NULL, e uma entrada exclusiva do VAD recusa qualquer outra
//!   (MiLocateExclusiveSecure). As flags da entrada (os bits baixos do
//!   MMADDRESS_LIST.StartVa): ProbeMode bit 0 -> 0x8; senão bit 2 -> 0x8|0x2;
//!   senão bit 1 -> 0x8|0x1; Flags bit 0 -> 0x20, bit 2 -> 0x40, bit 3 -> 0x80;
//!   ProbeMode bit 31 -> 0x4, bit 30 -> 0x10, bit 29 -> 0x100. O VAD ganha
//!   NoChange (MiSetVadFlags).
//! - MmUnsecureVirtualMemory(Handle) (rva 0x61fb80): o handle combina o
//!   processo corrente, então o de outro contexto é ignorado; VOID. O
//!   MiRemoveSecureEntry (rva 0x25ae40) tira a entrada e, se era a única do
//!   VAD, limpa o NoChange.
//! - MiCheckSecuredVad(Vad, StartVa, Size, ProbeMode, PreviousMode)
//!   (rva 0x6db108), por entrada do VAD que cruza [StartVa, StartVa + Size - 1]
//!   ([`check_vad`]): a flag 0x40 só vale com PreviousMode UserMode; na
//!   remoção (ProbeMode >= 0x55) a flag 0x8 recusa; a flag 0x4 compara (fora
//!   da remoção) a proteção pedida com a de cada página, exata; senão uma
//!   proteção de guarda recusa e o MiReadWrite da proteção (0 na remoção)
//!   precisa de leitura (flag 0x1) ou escrita (flag 0x2). Toda recusa é
//!   STATUS_INVALID_PAGE_PROTECTION.
//!
//! Quem consulta, sempre num VAD NoChange:
//! - MiUnmapViewOfSection (rva 0x61e510): o VAD inteiro, 0x55, sem
//!   VmDeleted no processo (`mm/section/unmap_view.rs`).
//! - MmFreeVirtualMemory (rva 0x63ad20): MEM_RELEASE, o VAD inteiro e 0x55
//!   (sem VmDeleted); MEM_DECOMMIT, da base pedida (sem arredondar) pelo
//!   número de páginas da faixa, 0x55 (`ps/user/memory.rs`, `free_in`).
//! - MmProtectVirtualMemory (rva 0x5fa060): a base e o tamanho pedidos, com a
//!   máscara da proteção nova (`protect_in`).
//! - MiAllocateVirtualMemory (rva 0x5f8650): o MEM_COMMIT sobre o VAD
//!   existente, a faixa em páginas, com a máscara da proteção pedida.
//!
//! Os VADs são as regiões de cada processo (`ps::user::memory`: privadas,
//! vistas de seção e imagens), com as mesmas páginas confirmadas e proteções
//! por página que o ZwQueryVirtualMemory relata. A entrada guarda a
//! identidade da região: uma região que sai do VAD por outro caminho leva as
//! entradas dela (nenhuma região nova tem a mesma identidade), como o
//! MiDeleteVad libera a lista de eventos. O NoChange de um VAD é ter entradas
//! ou ser uma vista SEC_NO_CHANGE. A entrada que o MiMapViewOfDataSection põe
//! numa vista SEC_NO_CHANGE (só a flag 0x4) não entra aqui: ela não recusa a
//! remoção, e a troca de proteção da vista já é recusada em
//! `ps/user/sections.rs` (`protection_status`).

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::Eprocess;
use crate::ntos::mm::protection;
use crate::ntos::mm::section::views as section_views;
use crate::ntos::ps::user::memory::Space;
use crate::ntos::ps::user::sections::View;
use crate::ntos::ps::user::state::{Region, UserRegion};
use crate::ntos::ps::{previous_mode, process};
use crate::rtl::SpinLock;

const PAGE: u64 = 0x1000;
/// MmUserProbeAddress.
const USER_PROBE_ADDRESS: u64 = crate::ntos::mm::memory_map::USER_PROBE_ADDRESS;
const PAGE_READONLY: u32 = 2;
const PAGE_READWRITE: u32 = 4;
const PAGE_GUARD: u32 = 0x100;

/// O ProbeMode da remoção (MiUnmapViewOfSection e MmFreeVirtualMemory).
pub const PROBE_DELETE: u32 = 0x55;

/// STATUS_INVALID_PAGE_PROTECTION.
const STATUS_INVALID_PAGE_PROTECTION: u32 = 0xC000_0045;

/// Flags da entrada (os bits baixos do MMADDRESS_LIST.StartVa).
const SECURE_READ: u32 = 0x1;
const SECURE_WRITE: u32 = 0x2;
/// Troca de proteção só para a proteção exata das páginas.
const SECURE_COMPARE: u32 = 0x4;
/// Recusa a remoção.
const SECURE_NO_DELETE: u32 = 0x8;
const SECURE_AGAINST_WRITES: u32 = 0x10;
const SECURE_EXCLUSIVE: u32 = 0x20;
/// Só vale para PreviousMode UserMode.
const SECURE_USER_ONLY: u32 = 0x40;
/// Flags bit 3 do MmSecureVirtualMemoryEx; o MiCheckSecuredVad não a lê.
const SECURE_FLAGS_BIT3: u32 = 0x80;
/// A regra de pilha de sombra do MiCheckSecuredVad (VAD privado com
/// ShadowStack); o OpenNT não tem esses VADs, e fora deles a flag não muda
/// nada.
const SECURE_SHADOW_STACK: u32 = 0x100;

/// MiReadWrite (rva 0x128c8) pelos 3 bits baixos da máscara de proteção:
/// 1 sem acesso, 10 leitura, 11 escrita.
const READ_WRITE: [u8; 8] = [1, 10, 10, 10, 11, 11, 11, 11];
/// MM_GUARD_PAGE nos bits 3-4 da máscara.
const MASK_GUARD: u32 = protection::MASK_GUARD;

/// Uma entrada de segurança: a faixa [start, end] em páginas inteiras do VAD
/// `vad` de `process`.
struct Secured {
    process: u64,
    /// A identidade da região dona (o endereço do objeto); o `Weak` segura a
    /// alocação, então o endereço não passa a outra região enquanto a
    /// entrada existe.
    vad: usize,
    _owner: Weak<dyn UserRegion>,
    start: u64,
    end: u64,
    flags: u32,
}

static SECURED: SpinLock<BTreeMap<u64, Secured>> = SpinLock::new(BTreeMap::new());
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

/// A identidade de uma região (o objeto, sem a vtable).
fn identity(region: &Region) -> usize {
    Arc::as_ptr(region) as *const u8 as usize
}

/// O "VAD" que contém o endereço: vista de seção do processo ou região do
/// VAD dele.
fn region_of(process: u64, address: u64) -> Option<Region> {
    if let Some(view) = section_views::find(process, address) {
        return Some(view.region());
    }
    Space::of(process).find(address)
}

/// As entradas (início, fim, flags) do VAD `region` de `process`.
fn entries_of(process: u64, region: &Region) -> Vec<(u64, u64, u32)> {
    let vad = identity(region);
    SECURED.lock().values().filter(|entry| entry.process == process && entry.vad == vad).map(|entry| (entry.start, entry.end, entry.flags)).collect()
}

/// Vista SEC_NO_CHANGE: o VAD nasce NoChange (MiMapViewOfDataSection).
fn sec_no_change(region: &Region) -> bool {
    region.as_any().downcast_ref::<View>().is_some_and(|view| view.no_change)
}

/// EPROCESS.Flags.VmDeleted: o espaço já foi desmontado e as checagens de
/// remoção não valem mais.
pub fn vm_deleted(process: u64) -> bool {
    // SAFETY: o EPROCESS do espaço, retido por quem pede a operação.
    unsafe { Eprocess::at(process) }.vm_deleted() != 0
}

/// MiComparePteProtections fora do modo exato: leitura aceita tudo que não
/// seja NOACCESS ou GUARD; escrita exige READWRITE/WRITECOPY (executável ou
/// não). Região sem proteção registrada é RW, como o ZwQueryVirtualMemory a
/// reporta.
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

/// A proteção Win32 da página `index` da região (a própria ou a da região).
fn page_protection(region: &Region, index: u64) -> u32 {
    region.page_protect(index).filter(|&protect| protect != 0).unwrap_or_else(|| region.protect())
}

/// MiComparePteProtections(Vad, first, last, Protection, ExactMatch) sobre as
/// páginas [first, last] da região: toda página confirmada e com a proteção
/// aceita por `test` (a máscara exata, ou o acesso pedido).
fn compare_pages(region: &Region, first: u64, last: u64, test: impl Fn(u32) -> bool) -> bool {
    let committed = region.committed_pages();
    let mut page = first & !(PAGE - 1);
    while page <= last {
        if page < region.base() || page >= region.base() + region.size() {
            return false;
        }
        let index = (page - region.base()) / PAGE;
        if committed.as_ref().is_some_and(|pages| !pages.contains(&index)) || !test(page_protection(region, index)) {
            return false;
        }
        page += PAGE;
    }
    true
}

/// MmSecureVirtualMemoryEx(Address, Size, ProbeMode, Flags): o handle ou 0
/// (NULL).
pub fn secure_ex(address: u64, size: u64, probe_mode: u32, flags: u32) -> u64 {
    if flags & !0xF != 0 {
        return 0;
    }
    let end = address.wrapping_add(size);
    if end <= address || end > USER_PROBE_ADDRESS {
        return 0;
    }
    // 0x80000001 passa no primeiro teste do 19041 e cai no do sinal.
    if !matches!(probe_mode, 1 | 2 | 4) {
        return 0;
    }
    let process = process::get_current_process();
    let Some(region) = region_of(process, address & !(PAGE - 1)) else { return 0 };
    if (end - 1) >> 12 > (region.base() + region.size() - 1) >> 12 {
        return 0;
    }
    let probe = if flags & 2 != 0 { probe_mode | 0x8000_0000 } else { probe_mode };
    secure_vad(process, &region, address, size, probe, flags)
}

/// MiSecureVad: a faixa em páginas inteiras, o MiComparePteProtections das
/// páginas (sem o bit 0 do ProbeMode) e a entrada nova.
fn secure_vad(process: u64, region: &Region, address: u64, size: u64, probe: u32, flags: u32) -> u64 {
    let first = address & !(PAGE - 1);
    let last = (address + size - 1) | (PAGE - 1);
    if probe & 1 == 0 {
        let write = probe != PAGE_READONLY;
        if !compare_pages(region, first, last, |protect| allows(protect, write)) {
            return 0;
        }
    }
    add_entry(process, region, first, last, probe, flags)
}

/// MiAddSecureEntry: a exclusividade num VAD NoChange (entradas de
/// segurança ou SEC_NO_CHANGE), as flags da entrada e o NoChange do VAD
/// (implícito nas entradas). A conferência e a inserção ficam sob a mesma
/// trava, como sob a trava do VAD no NT.
fn add_entry(process: u64, region: &Region, start: u64, end: u64, probe: u32, flags: u32) -> u64 {
    let mut entry = if probe & 1 != 0 {
        SECURE_NO_DELETE
    } else if probe & 4 != 0 {
        SECURE_NO_DELETE | SECURE_WRITE
    } else if probe & 2 != 0 {
        SECURE_NO_DELETE | SECURE_READ
    } else {
        0
    };
    for (bit, flag) in [(1, SECURE_EXCLUSIVE), (4, SECURE_USER_ONLY), (8, SECURE_FLAGS_BIT3)] {
        if flags & bit != 0 {
            entry |= flag;
        }
    }
    for (bit, flag) in [(0x8000_0000, SECURE_COMPARE), (0x4000_0000, SECURE_AGAINST_WRITES), (0x2000_0000, SECURE_SHADOW_STACK)] {
        if probe & bit != 0 {
            entry |= flag;
        }
    }
    // As entradas vivem nos VADs do processo e somem com o espaço dele.
    process::register_process_exit_routine(release_process);
    let vad = identity(region);
    let view_no_change = sec_no_change(region);
    let mut secured = SECURED.lock();
    let mut in_vad = secured.values().filter(|other| other.process == process && other.vad == vad).peekable();
    let no_change = view_no_change || in_vad.peek().is_some();
    // MiLocateExclusiveSecure: uma exclusiva só existe sozinha no VAD.
    if no_change && (flags & 1 != 0 || in_vad.any(|other| other.flags & SECURE_EXCLUSIVE != 0)) {
        return 0;
    }
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    secured.insert(handle, Secured { process, vad, _owner: Arc::downgrade(region), start, end, flags: entry });
    handle
}

/// O fim do processo leva os VADs e as entradas deles.
fn release_process(process: u64) {
    SECURED.lock().retain(|_, entry| entry.process != process);
}

/// MiCheckSecuredVad(Vad, StartVa, Size, ProbeMode, PreviousMode) sobre as
/// entradas do VAD `region` de `process`, com o PreviousMode da thread
/// corrente: 0 ou STATUS_INVALID_PAGE_PROTECTION. `probe` é a máscara de
/// proteção pedida (MiMakeProtectionMask) ou [`PROBE_DELETE`].
pub fn check_vad(process: u64, region: &Region, start: u64, size: u64, probe: u32) -> u32 {
    let entries = entries_of(process, region);
    if entries.is_empty() {
        return 0;
    }
    let user_mode = previous_mode::get().unwrap_or(0) == 1;
    let last = start.wrapping_add(size).wrapping_sub(1);
    for (entry_start, entry_end, flags) in entries {
        if flags & SECURE_USER_ONLY != 0 && !user_mode {
            continue;
        }
        if start > entry_end || last < entry_start {
            continue;
        }
        if probe >= PROBE_DELETE && flags & SECURE_NO_DELETE != 0 {
            return STATUS_INVALID_PAGE_PROTECTION;
        }
        if flags & SECURE_COMPARE != 0 {
            if probe >= PROBE_DELETE {
                continue;
            }
            if !compare_pages(region, start, last, |protect| protection::make_mask(protect) == Some(probe)) {
                return STATUS_INVALID_PAGE_PROTECTION;
            }
            continue;
        }
        let mask = if probe < PROBE_DELETE { probe } else { 0 };
        if mask & !7 == MASK_GUARD {
            return STATUS_INVALID_PAGE_PROTECTION;
        }
        let access = READ_WRITE[(mask & 7) as usize];
        let needed = if flags & SECURE_READ != 0 {
            10
        } else if flags & SECURE_WRITE != 0 {
            11
        } else {
            0
        };
        if access < needed {
            return STATUS_INVALID_PAGE_PROTECTION;
        }
    }
    0
}

/// MmSecureVirtualMemory(Address, Size, ProbeMode): o handle ou 0.
pub fn secure(address: u64, size: u64, probe_mode: u32) -> u64 {
    secure_ex(address, size, if probe_mode == PAGE_READONLY { PAGE_READONLY } else { PAGE_READWRITE }, 0)
}

/// MmUnsecureVirtualMemory(Handle): só a entrada do processo corrente sai;
/// sem outra entrada, o VAD perde o NoChange (implícito).
pub fn unsecure(handle: u64) {
    let process = process::get_current_process();
    let mut secured = SECURED.lock();
    if secured.get(&handle).is_some_and(|entry| entry.process == process) {
        secured.remove(&handle);
    }
}
