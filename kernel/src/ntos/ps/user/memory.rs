//! Memória virtual do processo de usuário.
//!
//! O "VAD" (regiões de usuário e imagens do estado), o alocador de VA
//! (reserva, commit e top-down), o mapeamento de pilha, estruturas e regiões
//! compartilhadas (frames do PFN com U/S=1) e os handlers Nt*VirtualMemory.
//!
//! A VA segue o NT (Windows 10 19041 x64): nada abaixo de
//! MM_LOWEST_USER_ADDRESS (64 KB) e nada acima de MM_HIGHEST_VAD_ADDRESS; sem
//! base, a primeira faixa livre de baixo para cima com granularidade de
//! 64 KB (MEM_TOP_DOWN: a primeira de cima para baixo); com base, a reserva
//! desce aos 64 KB e uma base abaixo do piso falha com
//! STATUS_CONFLICTING_ADDRESSES. Pilhas, PEB/TEB e as demais estruturas que
//! o kernel monta para o processo também saem do alocador: não há janela
//! fixa na metade de usuário além da KUSER_SHARED_DATA em 0x7FFE0000.
//!
//! O processo de usuário ativo usa os VADs do runtime (`state`); os demais
//! processos (o System, onde rodam os DriverEntry) têm as próprias regiões
//! privadas aqui, alocadas por ZwAllocateVirtualMemory de kernel. Como a
//! tabela de páginas é uma só, a escolha de endereço considera as regiões de
//! todos os espaços (`occupied`).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use super::memory_query::{self, Context};
use super::sections::{self, View};
use super::state::{self, Region, UserRegion, STATUS_CONFLICTING_ADDRESSES, STATUS_INVALID_PARAMETER, USER_STACK_SIZE};
use crate::hal::physical;
use crate::ntos::mm::memory_map::{self as map, USER_ADDRESS_LIMIT};
use crate::ntos::mm::paging::{self, MapOptions};
use crate::ntos::mm::pfn;
use crate::ntos::mm::section::{address as section_address, views as section_views};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{Eprocess, MemAddressRequirements, MemExtendedParameter, NtStruct};

const PAGE: u64 = 0x1000;
const MAX_SAFE: u64 = (1 << 53) - 1;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_TOP_DOWN: u32 = 0x10_0000;
/// Limite exclusivo das alocações de usuário (MM_HIGHEST_VAD_ADDRESS + 1).
pub const USER_ALLOCATION_TOP: u64 = map::HIGHEST_VAD_ADDRESS + 1;

pub struct PrivateMut {
    pub frames: BTreeMap<u64, u64>,
    pub committed_pages: BTreeSet<u64>,
    pub page_protects: BTreeMap<u64, u32>,
    pub protected_frames: BTreeMap<u64, u64>,
}

/// Região privada (NtAllocateVirtualMemory, pilha e estruturas): commit
/// real por página.
pub struct PrivateRegion {
    pub base: u64,
    pub size: u64,
    pub protect: u32,
    pub allocation_protect: u32,
    pub allocation_type: u32,
    pub state: SpinLock<PrivateMut>,
}

impl PrivateRegion {
    fn new(base: u64, size: u64, protect: u32, allocation_type: u32) -> Arc<Self> {
        Arc::new(Self { base, size, protect, allocation_protect: protect, allocation_type, state: SpinLock::new(PrivateMut { frames: BTreeMap::new(), committed_pages: BTreeSet::new(), page_protects: BTreeMap::new(), protected_frames: BTreeMap::new() }) })
    }
}

impl UserRegion for PrivateRegion {
    fn base(&self) -> u64 {
        self.base
    }
    fn size(&self) -> u64 {
        self.size
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn committed_pages(&self) -> Option<BTreeSet<u64>> {
        Some(self.state.lock().committed_pages.clone())
    }
    fn page_protect(&self, index: u64) -> Option<u32> {
        self.state.lock().page_protects.get(&index).copied().filter(|&protect| protect != 0)
    }
    fn protect(&self) -> u32 {
        self.protect
    }
    fn allocation_protect(&self) -> u32 {
        self.allocation_protect
    }
    fn frame(&self, index: u64) -> Option<u64> {
        let state = self.state.lock();
        state.frames.get(&index).copied().or_else(|| state.protected_frames.get(&index).copied())
    }
    fn record_protect(&self, index: u64, protect: u32, physical: u64) -> bool {
        let mut state = self.state.lock();
        state.page_protects.insert(index, protect);
        state.protected_frames.insert(index, physical);
        true
    }
}

/// Mapeamento compartilhado (NLS, schemas) que sobrevive entre processos.
pub struct SharedRegion {
    pub base: u64,
    pub size: u64,
}

impl UserRegion for SharedRegion {
    fn base(&self) -> u64 {
        self.base
    }
    fn size(&self) -> u64 {
        self.size
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn contains(region: &Region, va: u64) -> bool {
    va >= region.base() && va < region.base() + region.size()
}

/// Regiões privadas dos processos sem runtime de usuário, por EPROCESS.
static FOREIGN: SpinLock<BTreeMap<u64, Vec<Region>>> = SpinLock::new(BTreeMap::new());

/// O espaço de endereçamento de usuário de um processo.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Space {
    /// O processo de usuário em execução (VADs do runtime).
    Active,
    /// Outro processo, pelo EPROCESS.
    Foreign(u64),
}

impl Space {
    pub fn of(process: u64) -> Space {
        // SAFETY: EPROCESS vivo, referenciado pelo chamador.
        if unsafe { Eprocess::at(process) }.unique_process_id.get() == state::with(|state| state.current_process_id) {
            Space::Active
        } else {
            Space::Foreign(process)
        }
    }

    fn find(self, va: u64) -> Option<Region> {
        match self {
            Space::Active => find_region(va),
            Space::Foreign(process) => FOREIGN.lock().get(&process).and_then(|regions| regions.iter().find(|region| contains(region, va)).cloned()),
        }
    }

    fn insert(self, region: Region) {
        match self {
            Space::Active => state::with(|state| state.user_regions.push(region)),
            Space::Foreign(process) => FOREIGN.lock().entry(process).or_default().push(region),
        }
    }

    fn remove(self, region: &Region) {
        match self {
            Space::Active => state::with(|state| state.remove_region(state::RegionKind::User, region)),
            Space::Foreign(process) => {
                if let Some(regions) = FOREIGN.lock().get_mut(&process) {
                    regions.retain(|candidate| !state::same_region(candidate, region));
                }
            }
        }
    }
}

/// As regiões privadas de um processo sem runtime de usuário.
pub fn foreign_regions(process: u64) -> Vec<Region> {
    FOREIGN.lock().get(&process).cloned().unwrap_or_default()
}

/// Libera as regiões privadas de um processo que saiu.
pub fn release_foreign(process: u64) {
    let regions = FOREIGN.lock().remove(&process).unwrap_or_default();
    for region in regions {
        if let Some(owner) = private(&region) {
            free_region_pages(owner);
        }
    }
}

/// Tudo o que ocupa VA de usuário na tabela de páginas única: regiões e
/// imagens do processo ativo, regiões compartilhadas, vistas de seção de
/// qualquer dono (inclusive reservas ainda sem página) e as regiões
/// privadas dos outros processos. O que só existe nas PTEs (a
/// KUSER_SHARED_DATA, imagens mapeadas sem região) o `mm/section/address`
/// acha pela própria árvore de páginas.
pub fn occupied() -> Vec<section_address::Region> {
    let span = |region: &Region| section_address::Region { base: region.base(), size: region.size() };
    let mut occupied: Vec<section_address::Region> = state::with(|state| state.user_regions.iter().chain(state.process_images.iter()).chain(state.shared_user_regions.iter()).chain(state.section_kernel_views.iter()).map(span).collect());
    occupied.extend(sections::views().iter().map(|view| section_address::Region { base: view.base, size: view.size }));
    occupied.extend(section_views::all().iter().map(|view| section_address::Region { base: view.base(), size: view.size() }));
    for regions in FOREIGN.lock().values() {
        occupied.extend(regions.iter().map(span));
    }
    occupied.retain(|region| region.base < USER_ADDRESS_LIMIT);
    occupied
}

/// A primeira faixa livre de `size` bytes na metade de usuário, de baixo
/// para cima ou (`top_down`) de cima para baixo, alinhada a `alignment`.
pub fn find_free(size: u64, alignment: u64, top_down: bool) -> Result<u64, u32> {
    section_address::find(&section_address::FindOptions { size, alignment, top_down, ..section_address::FindOptions::default() }, &occupied())
}

/// Região de usuário ou imagem que contém o endereço.
pub fn find_region(va: u64) -> Option<Region> {
    state::with(|state| state.user_regions.iter().find(|region| contains(region, va)).cloned().or_else(|| state.process_images.iter().find(|region| contains(region, va)).cloned()))
}

fn private(region: &Region) -> Option<&PrivateRegion> {
    region.as_any().downcast_ref::<PrivateRegion>()
}

fn view_of(region: &Region) -> Option<Arc<View>> {
    region.as_any().downcast_ref::<View>()?;
    sections::views().into_iter().find(|view| {
        let candidate: Region = view.clone();
        state::same_region(&candidate, region)
    })
}

/// Mapeia uma faixa com frames do PFN (commit inicial e commit sobre
/// reserva); qualquer falha desfaz as páginas desta chamada.
pub fn map_user_page_range(base: u64, size: u64, region: Option<&PrivateRegion>, protect: u32) -> bool {
    let protect = if protect != 0 { protect } else { region.map_or(4, |region| if region.protect != 0 { region.protect } else { 4 }) };
    let mut added: Vec<(u64, u64, u64)> = Vec::new();
    let rollback = |added: &[(u64, u64, u64)]| {
        for &(va, frame, index) in added {
            paging::unmap_page(va, MapOptions::default());
            pfn::free_page(frame);
            if let Some(region) = region {
                let mut state = region.state.lock();
                state.frames.remove(&index);
                state.committed_pages.remove(&index);
                state.page_protects.remove(&index);
            }
        }
        false
    };
    let mut offset = 0;
    while offset < size {
        let index = match region {
            Some(region) => (base + offset - region.base) / PAGE,
            None => offset / PAGE,
        };
        if region.is_some_and(|region| region.state.lock().committed_pages.contains(&index)) {
            offset += PAGE;
            continue;
        }
        let frame = pfn::alloc_page();
        if frame == 0 {
            debug_print!("[mm] PFN exhausted: request={}, mapped={}, total={}", size, added.len() as u64 * PAGE, pfn::total_count());
            return rollback(&added);
        }
        physical::zero(frame, PAGE as usize);
        let writable = protect & (4 | 8 | 0x40 | 0x80) != 0;
        let flags = paging::PAGE_USER | if protect != 1 { paging::PAGE_PRESENT } else { 0 } | if writable { paging::PAGE_RW } else { 0 };
        if !paging::map_page(base + offset, frame, flags, MapOptions::default()) {
            pfn::free_page(frame);
            return rollback(&added);
        }
        added.push((base + offset, frame, index));
        if let Some(region) = region {
            let mut state = region.state.lock();
            state.frames.insert(index, frame);
            state.committed_pages.insert(index);
            state.page_protects.insert(index, protect);
        }
        offset += PAGE;
    }
    true
}

pub fn map_region_pages(region: &PrivateRegion) -> bool {
    map_user_page_range(region.base, region.size, Some(region), 0)
}

/// O alocador de VA: commit sobre reserva própria, base fixa ou escolha
/// pelo `mm/section/address` (primeira faixa livre; MEM_TOP_DOWN de cima).
#[allow(clippy::too_many_arguments)]
pub fn do_user_allocate(base_pointer: u64, size_pointer: u64, allocation_type: u32, protect: u32, lowest: u64, highest: u64, align: u64) -> Result<u32, KernelError> {
    allocate_in(Space::Active, base_pointer, size_pointer, allocation_type, protect, lowest, highest, align)
}

/// Reserva/commit no espaço dado. `lowest` é o piso pedido (nunca abaixo
/// de MM_LOWEST_USER_ADDRESS) e `highest` o limite exclusivo (0, ou acima do
/// topo, = MM_HIGHEST_VAD_ADDRESS + 1).
#[allow(clippy::too_many_arguments)]
pub fn allocate_in(space: Space, base_pointer: u64, size_pointer: u64, allocation_type: u32, protect: u32, lowest: u64, highest: u64, align: u64) -> Result<u32, KernelError> {
    let highest = if highest == 0 { USER_ALLOCATION_TOP } else { highest.min(USER_ALLOCATION_TOP) };
    let lowest = lowest.max(map::LOWEST_USER_ADDRESS);
    // PVOID *BaseAddress e SIZE_T *RegionSize: de usuário (sondados pelo
    // handler) ou do kernel (Zw); os acessos são sondados nos dois casos.
    let requested_base = guest::try_read::<u64>(base_pointer)?;
    let requested = guest::try_read::<u64>(size_pointer)?;
    // Como o MiAllocateVirtualMemoryPrepare: base até MmHighestUserAddress e
    // a faixa inteira abaixo de MmUserProbeAddress.
    if requested_base > map::HIGHEST_USER_ADDRESS || requested == 0 || requested > MAX_SAFE || requested > USER_ADDRESS_LIMIT - requested_base {
        debug_print!("[usermode] alloc invalida: base=0x{:x} size=0x{:x} type=0x{:x}", requested_base, requested, allocation_type);
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if ![1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80].contains(&(protect & 0xFF)) {
        return Ok(0xC000_0045);
    }
    if protect & !0xFF != 0 {
        return Ok(0xC000_00BB);
    }
    let fixed = requested_base != 0;
    let reserve = allocation_type & MEM_RESERVE != 0;
    // Uma reserva com base desce à granularidade de alocação (64 KB); o
    // commit sobre uma reserva fica em páginas. O tamanho cobre até o fim
    // pedido, arredondado à página.
    let base = if !fixed {
        0
    } else if reserve {
        requested_base & !(map::ALLOCATION_GRANULARITY - 1)
    } else {
        requested_base & !(PAGE - 1)
    };
    let size = if fixed { (requested_base + requested).div_ceil(PAGE) * PAGE - base } else { requested.div_ceil(PAGE) * PAGE };
    if fixed {
        if let Some(existing) = space.find(base) {
            // COMMIT sem RESERVE dentro de uma região já reservada: comita a
            // subfaixa (só em regiões próprias; imagens nunca).
            let commit_only = !reserve && allocation_type & MEM_COMMIT != 0;
            let view = view_of(&existing);
            let ours = private(&existing).is_some() || view.is_some();
            if commit_only && ours && base >= existing.base() && base + size <= existing.base() + existing.size() {
                if let Some(view) = view {
                    let status = sections::commit_view(&view, base, size, protect)?;
                    if status != 0 {
                        return Ok(status);
                    }
                } else if !map_user_page_range(base, size, private(&existing), protect) {
                    return Ok(0xC000_0017);
                }
                guest::try_write::<u64>(base_pointer, base)?;
                guest::try_write::<u64>(size_pointer, size)?;
                return Ok(0);
            }
            debug_print!("[usermode] alloc CONFLITO: base 0x{:x} size 0x{:x} tipo 0x{:x} - regiao em 0x{:x}", base, size, allocation_type, existing.base());
            return Ok(STATUS_CONFLICTING_ADDRESSES);
        }
        // Os primeiros 64 KB nunca são mapeáveis (MiIsVaRangeAvailable).
        if base < lowest || base + size > highest {
            return Ok(STATUS_CONFLICTING_ADDRESSES);
        }
    }
    let top_down = allocation_type & MEM_TOP_DOWN != 0;
    let find = section_address::FindOptions { base, size, minimum: Some(lowest), upper: Some(highest - 1), alignment: align, top_down, ..section_address::FindOptions::default() };
    let base = match section_address::find(&find, &occupied()) {
        Ok(base) => base,
        Err(status) => return Ok(status),
    };
    let region = PrivateRegion::new(base, size, protect, allocation_type);
    if allocation_type & MEM_COMMIT != 0 && !map_region_pages(&region) {
        return Ok(0xC000_0017);
    }
    space.insert(region);
    guest::try_write::<u64>(base_pointer, base)?;
    guest::try_write::<u64>(size_pointer, size)?;
    Ok(0)
}

/// Região privada comitada que o kernel monta para o processo ativo, na
/// primeira faixa livre (`top_down`: a primeira de cima para baixo).
fn register_user_region(size: u64, alignment: u64, top_down: bool) -> Result<Arc<PrivateRegion>, KernelError> {
    let size = size.div_ceil(PAGE) * PAGE;
    if size == 0 {
        return Err(KernelError::new("Regiao de usuario vazia"));
    }
    let base = find_free(size, alignment, top_down).map_err(|status| KernelError::with_status("sem VA livre na metade de usuario", status))?;
    let region = PrivateRegion::new(base, size, 4, MEM_COMMIT | MEM_RESERVE);
    if !map_region_pages(&region) {
        return Err(KernelError::new("PFN esgotado na regiao de usuario"));
    }
    let entry: Region = region.clone();
    state::with(|state| state.user_regions.push(entry));
    Ok(region)
}

/// Pilha da primeira thread, uma alocação comum de baixo para cima (como a
/// reserva da pilha inicial no NT): devolve a base (StackLimit e
/// DeallocationStack) e o topo (StackBase) da pilha.
pub fn map_user_stack() -> Result<(u64, u64), KernelError> {
    let region = register_user_region(USER_STACK_SIZE, map::ALLOCATION_GRANULARITY, false)?;
    Ok((region.base, region.base + region.size))
}

/// Estruturas que o kernel monta para o processo (PEB, TEB, parâmetros,
/// entradas do Ldr): páginas comitadas de cima para baixo, como o
/// MiCreatePebOrTeb, sem janela fixa.
pub fn map_user_region(size: u64) -> Result<u64, KernelError> {
    Ok(register_user_region(size, PAGE, true)?.base)
}

/// Igual, na área compartilhada (NLS etc.), que sobrevive entre processos.
pub fn map_shared_user_region(size: u64) -> Result<u64, KernelError> {
    let rounded = size.div_ceil(PAGE) * PAGE;
    if rounded == 0 {
        return Err(KernelError::new("Regiao compartilhada vazia"));
    }
    let va = find_free(rounded, PAGE, true).map_err(|status| KernelError::with_status("sem VA livre para a regiao compartilhada", status))?;
    // A faixa entra na lista antes das páginas: nenhuma escolha de VA no
    // meio do mapeamento a reutiliza.
    let entry: Region = Arc::new(SharedRegion { base: va, size: rounded });
    state::with(|state| state.shared_user_regions.push(entry));
    let mut offset = 0;
    while offset < size {
        let frame = pfn::alloc_page();
        if frame == 0 {
            return Err(KernelError::new("PFN esgotado nas regioes compartilhadas"));
        }
        physical::zero(frame, PAGE as usize);
        if !paging::map_page(va + offset, frame, paging::PAGE_PRESENT | paging::PAGE_RW | paging::PAGE_USER, MapOptions::default()) {
            return Err(KernelError::new("mapPage falhou nas regioes compartilhadas"));
        }
        offset += PAGE;
    }
    Ok(va)
}

/// NtAllocateVirtualMemory(process, base*, zeroBits, size*, type, protect).
pub fn nt_allocate_virtual_memory(_process: u64, base_pointer: u64, _zero_bits: u64, size_pointer: u64, user_rsp: u64) -> Result<u32, KernelError> {
    let allocation_type = state::stack_arg32(user_rsp, 5);
    let protect = state::stack_arg32(user_rsp, 6);
    // Os ponteiros de saída são acessados por cópias sondadas.
    state::guarded(|| do_user_allocate(base_pointer, size_pointer, allocation_type, protect, 0, 0, map::ALLOCATION_GRANULARITY))
}

/// NtAllocateVirtualMemoryEx(process, base*, size*, type, protect, params*,
/// count): sem ZeroBits; MEM_ADDRESS_REQUIREMENTS honrado; PartitionHandle
/// recusado pelo syscall nativo mesmo válido.
pub fn nt_allocate_virtual_memory_ex(_process: u64, base_pointer: u64, size_pointer: u64, allocation_type: u64, user_rsp: u64) -> Result<u32, KernelError> {
    let (parameters, count) = (state::stack_arg(user_rsp, 6), state::stack_arg32(user_rsp, 7) as u64);
    // BaseAddress, RegionSize e o vetor de MEM_EXTENDED_PARAMETER são
    // acessados por cópias sondadas.
    if guest::try_read::<u64>(size_pointer).is_ok_and(|size| size == 0) {
        // Diagnóstico: endereços de retorno na pilha de usuário.
        debug_print!("[usermode] allocEx tamanho zero chamado de 0x{:x} caller2=0x{:x} sizePtr=0x{:x}", guest::try_read::<u64>(user_rsp).unwrap_or(0), guest::try_read::<u64>(user_rsp + 0x90).unwrap_or(0), size_pointer);
    }
    state::guarded(|| allocate_ex_in(Space::Active, base_pointer, size_pointer, allocation_type as u32, state::stack_arg32(user_rsp, 5), parameters, count))
}

/// NtAllocateVirtualMemoryEx no espaço dado: MEM_ADDRESS_REQUIREMENTS
/// honrado; PartitionHandle recusado.
#[allow(clippy::too_many_arguments)]
pub fn allocate_ex_in(space: Space, base_pointer: u64, size_pointer: u64, allocation_type: u32, protect: u32, parameters: u64, count: u64) -> Result<u32, KernelError> {
    let mut count = count;
    if parameters == 0 || count > 16 {
        count = 0;
    }
    // `highest` exclusivo; 0 = o topo das alocações de usuário.
    let (mut lowest, mut highest, mut align) = (0u64, 0u64, map::ALLOCATION_GRANULARITY);
    for index in 0..count {
        let entry = state::user_struct::<MemExtendedParameter>(parameters + index * MemExtendedParameter::SIZE)?;
        // Header inteiro (Type nos 8 bits baixos, Reserved zero).
        match entry.header.probe_get()? {
            // MemExtendedParameterAddressRequirements.
            1 => {
                let requirements = state::user_struct::<MemAddressRequirements>(entry.pointer.probe_get()?)?;
                lowest = requirements.lowest_starting_address.probe_get()?;
                // HighestEndingAddress é inclusivo; 0 = sem limite superior.
                let ending = requirements.highest_ending_address.probe_get()?;
                highest = if ending == 0 { 0 } else { ending.saturating_add(1) };
                let alignment = requirements.alignment.probe_get()?;
                if alignment != 0 {
                    align = alignment;
                }
            }
            3 => return Ok(STATUS_INVALID_PARAMETER),
            other => debug_print!("[usermode] allocEx: param tipo {} ignorado", other),
        }
    }
    allocate_in(space, base_pointer, size_pointer, allocation_type, protect, lowest, highest, align)
}

/// NtFreeVirtualMemory: MEM_DECOMMIT desmapeia a subfaixa (a região fica
/// reservada); MEM_RELEASE libera a região privada inteira; seções usam
/// UnmapView.
pub fn nt_free_virtual_memory(_process: u64, base_pointer: u64, size_pointer: u64, free_type: u64, _user_rsp: u64) -> Result<u32, KernelError> {
    state::guarded(|| free_in(Space::Active, base_pointer, size_pointer, free_type as u32))
}

/// MEM_RESET: a faixa (arredondada a páginas) tem de estar comitada numa
/// região privada do espaço; o conteúdo pode ser preservado.
pub fn validate_committed(space: Space, base_pointer: u64, size_pointer: u64) -> Result<u32, KernelError> {
    let (base, size) = (guest::try_read::<u64>(base_pointer)?, guest::try_read::<u64>(size_pointer)?);
    if base == 0 || size == 0 || base > MAX_SAFE || size > MAX_SAFE || base + size > USER_ADDRESS_LIMIT {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let first = base & !(PAGE - 1);
    let end = (base + size).div_ceil(PAGE) * PAGE;
    let Some(region) = space.find(first) else { return Ok(STATUS_CONFLICTING_ADDRESSES) };
    let Some(owner) = private(&region) else { return Ok(STATUS_CONFLICTING_ADDRESSES) };
    if end > owner.base + owner.size {
        return Ok(STATUS_CONFLICTING_ADDRESSES);
    }
    let committed = owner.state.lock().committed_pages.clone();
    if (first..end).step_by(PAGE as usize).any(|va| !committed.contains(&((va - owner.base) / PAGE))) {
        return Ok(0xC000_002D);
    }
    guest::try_write::<u64>(base_pointer, first)?;
    guest::try_write::<u64>(size_pointer, end - first)?;
    Ok(0)
}

/// MEM_DECOMMIT/MEM_RELEASE no espaço dado.
pub fn free_in(space: Space, base_pointer: u64, size_pointer: u64, free_type: u32) -> Result<u32, KernelError> {
    let base = guest::try_read::<u64>(base_pointer)?;
    let size = guest::try_read::<u64>(size_pointer)?;
    let Some(region) = space.find(base) else {
        debug_print!("[usermode] NtFreeVirtualMemory: base 0x{:x} size 0x{:x} tipo 0x{:x} - NAO MAPEADO", base, size, free_type);
        return Ok(STATUS_INVALID_PARAMETER);
    };
    if region.section().is_some() {
        return Ok(0xC000_001B);
    }
    let Some(owner) = private(&region) else { return Ok(STATUS_INVALID_PARAMETER) };
    let release = free_type == 0x8000;
    let decommit = free_type == 0x4000;
    if (!release && !decommit) || (release && (base != owner.base || size != 0)) {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let first = if release || size == 0 { owner.base } else { base & !(PAGE - 1) };
    let end = if release || size == 0 { owner.base + owner.size } else { (base + size).div_ceil(PAGE) * PAGE };
    if first < owner.base || end > owner.base + owner.size || (size == 0 && base != owner.base) {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let mut va = first;
    while va < end {
        let index = (va - owner.base) / PAGE;
        let frame = {
            let mut state = owner.state.lock();
            if state.committed_pages.remove(&index) {
                state.page_protects.remove(&index);
                state.protected_frames.remove(&index);
                state.frames.remove(&index)
            } else {
                None
            }
        };
        if let Some(frame) = frame {
            paging::unmap_page(va, MapOptions::default());
            pfn::free_page(frame);
        }
        va += PAGE;
    }
    if release {
        space.remove(&region);
    }
    guest::try_write::<u64>(base_pointer, first)?;
    guest::try_write::<u64>(size_pointer, end - first)?;
    Ok(0)
}

/// NtProtectVirtualMemory(process, base*, size*, newProtect, oldProtect*):
/// cobre qualquer VA de usuário mapeada (a ntdll protege as próprias seções
/// da imagem); falha de política devolve PAGE_NOACCESS no OldProtect sem
/// tocar base, tamanho ou PTEs.
pub fn nt_protect_virtual_memory(_process: u64, base_pointer: u64, size_pointer: u64, new_protect: u64, user_rsp: u64) -> Result<u32, KernelError> {
    state::guarded(|| protect_in(Space::Active, base_pointer, size_pointer, new_protect as u32, state::stack_arg(user_rsp, 5), true))
}

/// Troca a proteção no espaço dado; ponteiros de modo usuário são sondados.
pub fn protect_in(space: Space, base_pointer: u64, size_pointer: u64, new_protect: u32, old_pointer: u64, from_user: bool) -> Result<u32, KernelError> {
    let new_protect = new_protect as u64;
    if from_user && (!state::probe_user_write(base_pointer, 8) || !state::probe_user_write(size_pointer, 8) || !state::probe_user_write(old_pointer, 4)) {
        return Ok(0xC000_0005);
    }
    let requested_base = guest::try_read::<u64>(base_pointer)?;
    let requested_size = guest::try_read::<u64>(size_pointer)?;
    if requested_base == 0 || requested_base > MAX_SAFE || requested_size == 0 || requested_size > MAX_SAFE || requested_base + requested_size > USER_ADDRESS_LIMIT {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let base = requested_base & !(PAGE - 1);
    let end = (requested_base + requested_size).div_ceil(PAGE) * PAGE;
    let size = end - base;
    let region = space.find(base);
    let protect = new_protect as u32;
    if ![1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80].contains(&(protect & 0xFF)) {
        return Ok(0xC000_0045);
    }
    let Some(region) = region.filter(|region| end <= region.base() + region.size()) else { return Ok(0xC000_0018) };
    // ULONG *OldProtect = PAGE_NOACCESS até a troca dar certo.
    guest::try_write::<u32>(old_pointer, 1)?;
    let section = region.section();
    let view = view_of(&region);
    if let Some(view) = &view {
        let status = sections::protection_status(view, protect);
        if status != 0 {
            return Ok(status);
        }
    }
    if protect & !0xFF != 0 {
        return Ok(0xC000_00BB);
    }
    if let Some(section) = &section {
        if !sections::compatible(section.is_image, section.page_protect(), protect) {
            return Ok(0xC000_004E);
        }
    }
    let context = Context::current();
    if let (Some(section), Some(view)) = (&section, &view) {
        if !section.is_image {
            let old = memory_query::page_protection(&region, (base - region.base()) / PAGE, &context);
            let status = sections::protect_view(view, base, size, protect);
            if status != 0 {
                return Ok(status);
            }
            guest::try_write::<u32>(old_pointer, old)?;
            guest::try_write::<u64>(base_pointer, base)?;
            guest::try_write::<u64>(size_pointer, size)?;
            return Ok(0);
        }
    }
    let committed = region.committed_pages();
    let mut changes = Vec::new();
    let mut va = base;
    while va < end {
        let index = (va - region.base()) / PAGE;
        let physical = region.frame(index).unwrap_or_else(|| paging::translate(va));
        if committed.as_ref().is_some_and(|pages| !pages.contains(&index)) || physical == 0 {
            return Ok(0xC000_002D);
        }
        changes.push((va, index, physical));
        va += PAGE;
    }
    let old = memory_query::page_protection(&region, (base - region.base()) / PAGE, &context);
    let writable = protect & (4 | 8 | 0x40 | 0x80) != 0;
    for (va, index, physical) in changes {
        let flags = paging::PAGE_USER | if protect != 1 { paging::PAGE_PRESENT } else { 0 } | if writable { paging::PAGE_RW } else { 0 };
        paging::map_page(va, physical, flags, MapOptions { nx: protect & 0xF0 == 0, ..MapOptions::default() });
        region.record_protect(index, protect, physical);
    }
    guest::try_write::<u32>(old_pointer, old)?;
    guest::try_write::<u64>(base_pointer, base)?;
    guest::try_write::<u64>(size_pointer, size)?;
    Ok(0)
}

/// Transferências nativas obedecem às PTEs de usuário: nenhuma identidade de
/// supervisor contorna uma página inacessível; cópia por blocos que não
/// cruzam páginas, preservando faixas sobrepostas.
fn transfer_virtual_memory(process: u64, address: u64, buffer: u64, size: u64, rsp: u64, write: bool) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 8) {
        return Ok(0xC000_0005);
    }
    let transferred = state::stack_arg(rsp, 5);
    if transferred != 0 && !state::probe_user_write(transferred, 8) {
        return Ok(0xC000_0005);
    }
    if size > MAX_SAFE || address > MAX_SAFE || address + size > USER_ADDRESS_LIMIT || buffer > MAX_SAFE || buffer + size > USER_ADDRESS_LIMIT {
        return Ok(0xC000_0005);
    }
    if process != u64::MAX {
        let Some(entry) = state::get_user_handle(process) else { return Ok(0xC000_0008) };
        if entry.kind() != "process" {
            return Ok(0xC000_0024);
        }
        if entry.access() & if write { 0x20 } else { 0x10 } == 0 {
            return Ok(0xC000_0022);
        }
        if entry.object.callback_data().process_id != Some(state::with(|state| state.current_process_id)) {
            return Ok(0xC000_00BB);
        }
    }
    if !(if write { state::probe_user_read(buffer, size) } else { state::probe_user_write(buffer, size) }) {
        return Ok(0xC000_0005);
    }
    let (source, target) = if write { (buffer, address) } else { (address, buffer) };
    let mut accessible = 0u64;
    while accessible < size {
        let at = address + accessible;
        let count = (size - accessible).min(PAGE - at % PAGE);
        if !(if write { state::probe_user_write(at, count) } else { state::probe_user_read(at, count) }) {
            break;
        }
        accessible += count;
    }
    let backwards = target > source && target < source + accessible;
    let mut done = 0u64;
    while done < accessible {
        let source_edge = source + if backwards { accessible - done } else { done };
        let target_edge = target + if backwards { accessible - done } else { done };
        let source_span = if backwards { match source_edge % PAGE { 0 => PAGE, rest => rest } } else { PAGE - source_edge % PAGE };
        let target_span = if backwards { match target_edge % PAGE { 0 => PAGE, rest => rest } } else { PAGE - target_edge % PAGE };
        let count = (accessible - done).min(source_span).min(target_span);
        let offset = if backwards { accessible - done - count } else { done };
        let block = physical::read_bytes(paging::translate(source + offset), count as usize);
        physical::write_bytes(paging::translate(target + offset), &block);
        done += count;
    }
    // SIZE_T *NumberOfBytesTransferred (sondado acima).
    if transferred != 0 && guest::try_write::<u64>(transferred, done).is_err() {
        return Ok(0xC000_0005);
    }
    Ok(if done == size { 0 } else { 0x8000_000D })
}

pub fn nt_read_virtual_memory(process: u64, address: u64, buffer: u64, size: u64, rsp: u64) -> Result<u32, KernelError> {
    transfer_virtual_memory(process, address, buffer, size, rsp, false)
}

pub fn nt_write_virtual_memory(process: u64, address: u64, buffer: u64, size: u64, rsp: u64) -> Result<u32, KernelError> {
    transfer_virtual_memory(process, address, buffer, size, rsp, true)
}

/// Buracos reservados não têm PFN; páginas NOACCESS ainda são donas do frame.
pub fn release_private_region(region: &Region) {
    let Some(owner) = private(region) else { return };
    if !state::with(|state| state.user_regions.iter().any(|candidate| state::same_region(candidate, region))) {
        return;
    }
    free_region_pages(owner);
    state::with(|state| state.remove_region(state::RegionKind::User, region));
}

/// Desmapeia e devolve ao PFN as páginas comitadas de uma região privada.
fn free_region_pages(owner: &PrivateRegion) {
    let pages: Vec<(u64, u64)> = {
        let mut state = owner.state.lock();
        let pages = state.committed_pages.iter().filter_map(|&index| state.frames.get(&index).map(|&frame| (index, frame))).collect();
        state.committed_pages.clear();
        state.frames.clear();
        pages
    };
    for (index, frame) in pages {
        paging::unmap_page(owner.base + index * PAGE, MapOptions::default());
        pfn::free_page(frame);
    }
}

pub fn release_private_regions() {
    let regions = state::with(|state| state.user_regions.clone());
    for region in regions {
        release_private_region(&region);
    }
}

fn query(process: u64, base: u64, class: u64, buffer: u64, rsp: u64) -> Result<u32, KernelError> {
    memory_query::query_virtual_memory(process, base, class, buffer, rsp)
}

/// Registra os handlers Nt*VirtualMemory.
pub fn init() {
    state::register_handler("NtAllocateVirtualMemory", nt_allocate_virtual_memory);
    state::register_handler("NtAllocateVirtualMemoryEx", nt_allocate_virtual_memory_ex);
    state::register_handler("NtFreeVirtualMemory", nt_free_virtual_memory);
    state::register_handler("NtProtectVirtualMemory", nt_protect_virtual_memory);
    state::register_handler("NtQueryVirtualMemory", query);
    state::register_handler("NtReadVirtualMemory", nt_read_virtual_memory);
    state::register_handler("NtWriteVirtualMemory", nt_write_virtual_memory);
}
