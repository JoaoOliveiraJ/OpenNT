//! Memória virtual do processo de usuário.
//!
//! O VAD de cada processo, o alocador de VA (reserva, commit e top-down), o
//! mapeamento de pilha, estruturas e regiões compartilhadas (frames do PFN
//! com U/S=1) e os handlers Nt*VirtualMemory.
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
//! Posse: cada EPROCESS tem o seu VAD (`Vad`, no `ProcessState` dele), com as
//! alocações privadas, as vistas de seção e as imagens que ele mapeou. Os
//! serviços agem sobre um `Space`: os Nt* de usuário e os Zw* sobre o
//! processo do handle (o pseudo-handle é o corrente, o anexado quando há
//! attach), com o acesso que o NT exige do handle de usuário
//! (`with_process_handle`: PROCESS_VM_OPERATION para alocar, liberar e
//! reproteger, PROCESS_QUERY_INFORMATION para consultar, PROCESS_VM_READ e
//! PROCESS_VM_WRITE para as cópias de `mm/copy_virtual`); o System guarda o
//! que o kernel aloca no próprio contexto (DriverEntry, threads de sistema) e
//! as cópias de sistema da ntdll, do apiset e do NLS. Sobre outro processo,
//! os ponteiros do chamador (base, tamanho, proteção anterior) são lidos e
//! escritos no contexto dele, e o espaço alvo é editado pela raiz dele, sem
//! anexar: o efeito do "captura, anexa, opera, desanexa" do NT.
//! Consultas, liberações e trocas de proteção só enxergam o VAD do
//! espaço; o término do processo devolve o VAD inteiro (`release_vad`), como
//! o MmCleanProcessAddressSpace. O VAD também decide a posse no modo
//! estrito de `guest_memory` (`check_user_access`): uma sonda só alcança
//! páginas do processo corrente ou das faixas de sistema compartilhadas.
//!
//! Raiz: as páginas de um espaço vivem na raiz dele (`Space::root`, o
//! KPROCESS.DirectoryTableBase): a própria de cada processo de usuário, ou a
//! do System para ele e para os processos que ficam nela. Mapear, desfazer e
//! reproteger editam essa raiz explicitamente (`paging::*_in`), esteja ela
//! carregada ou não: um Zw* sobre outro processo e o término (que roda no
//! contexto de quem termina) mexem nas tabelas do dono, nunca nas do CR3.
//!
//! Escolha de endereço: por raiz (`occupied`). A faixa nova evita o VAD dos
//! processos que dividem a raiz do espaço (só ele, quando a raiz é própria),
//! as vistas mapeadas nessa raiz, as PTEs dela e as faixas de sistema que
//! todo processo vê na mesma VA (a KUSER_SHARED_DATA, a ntdll, o apiset e o
//! NLS). Dois processos com raiz própria podem usar a mesma VA.
//!
//! Cópias de sistema: a ntdll, o apiset e o NLS são mapeados uma vez na raiz
//! do System; logo depois o loader fotografa as páginas
//! (`snapshot_system_range`), e cada processo com raiz própria recebe cópias
//! privadas delas nas mesmas VAs (`map_private_copies`), devolvidas no
//! término dele. Nenhum frame de usuário com escrita é dividido entre
//! processos.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use super::memory_query::{self, Context};
use super::process_state::{self, ProcessState};
use super::sections::{self, View};
use super::state::{self, Region, RegionKind, UserRegion, STATUS_CONFLICTING_ADDRESSES, STATUS_INVALID_PARAMETER, USER_STACK_SIZE};
use crate::hal::physical;
use crate::ntos::mm::memory_map::{self as map, USER_ADDRESS_LIMIT};
use crate::ntos::mm::paging::{self, MapOptions};
use crate::ntos::mm::pfn;
use crate::ntos::mm::copy_virtual;
use crate::ntos::mm::process_address_space::SYSTEM_ROOT;
use crate::ntos::mm::process_commit;
use crate::ntos::mm::paging_file::Slot as PageFileSlot;
use crate::ntos::mm::{control_flow_guard, protection, write_watch};
use crate::ntos::mm::working_set;
use crate::ntos::mm::virtual_lock;
use crate::ntos::mm::section::handles::{self as section_handles, Kind};
use crate::ntos::mm::section::{address as section_address, views as section_views};
use crate::ntos::ke::context_switch;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{MemAddressRequirements, MemExtendedParameter, NtStruct};

const PAGE: u64 = 0x1000;
const MAX_SAFE: u64 = (1 << 53) - 1;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_TOP_DOWN: u32 = 0x10_0000;
/// PAGE_GUARD: a página fica comitada com a PTE ausente (`mm/guard_page`).
pub const PAGE_GUARD: u32 = 0x100;
/// PAGE_TARGETS_INVALID (alocação) e PAGE_TARGETS_NO_UPDATE (proteção):
/// alvos de CFG, sem efeito com o CFG ausente (`mm/control_flow_guard`).
const PAGE_TARGETS: u32 = 0x4000_0000;
/// O processo do espaço já passou pelo término (sem VAD).
const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
/// Direitos de acesso do handle de processo que os serviços exigem.
const PROCESS_VM_OPERATION: u32 = 0x8;
/// SeLockMemoryPrivilege.
const SE_LOCK_MEMORY_PRIVILEGE: u64 = 4;
const PROCESS_VM_READ: u32 = 0x10;
const PROCESS_VM_WRITE: u32 = 0x20;
pub const PROCESS_QUERY_INFORMATION: u32 = 0x400;
/// PreviousMode dos serviços de usuário.
const USER_MODE: u8 = 1;
/// Limite exclusivo das alocações de usuário (MM_HIGHEST_VAD_ADDRESS + 1).
pub const USER_ALLOCATION_TOP: u64 = map::HIGHEST_VAD_ADDRESS + 1;

pub struct PrivateMut {
    /// O frame de cada página residente ou em transição.
    pub frames: BTreeMap<u64, u64>,
    pub committed_pages: BTreeSet<u64>,
    pub page_protects: BTreeMap<u64, u32>,
    pub protected_frames: BTreeMap<u64, u64>,
    /// Páginas que o corte do working set tirou do working set
    /// (`mm/working_set`): em transição (o frame segue em `frames`, numa
    /// lista de páginas modificadas ou de reserva) ou só no arquivo de
    /// paginação (sem frame).
    pub paging: BTreeMap<u64, PagedPage>,
    /// Páginas residentes cuja cópia no arquivo de paginação ainda vale (a
    /// página voltou de lá e não foi escrita desde então).
    pub clean: BTreeMap<u64, PageFileSlot>,
    /// Operações em curso que trabalham com os frames da região (proteção,
    /// liberação): o corte do working set não toca a região enquanto há
    /// alguma.
    pub busy: u32,
    /// As páginas travadas pelo NtLockVirtualMemory (`mm/virtual_lock`):
    /// MAP_PROCESS e MAP_SYSTEM em bits; o corte do working set não as leva.
    pub locked: BTreeMap<u64, u8>,
    /// O bitmap de write watch de uma alocação MEM_WRITE_WATCH
    /// (`mm/write_watch`): as páginas escritas cujo bit Dirty saiu da PTE.
    pub written: BTreeSet<u64>,
}

/// Uma página fora do working set (o estado que a PTE de transição ou de
/// arquivo de paginação descreve no NT).
#[derive(Clone, Copy, Debug)]
pub struct PagedPage {
    /// A cópia no arquivo de paginação, quando há.
    pub slot: Option<PageFileSlot>,
    /// Os bits da PTE válida para a volta (U/S, R/W, NX).
    pub template: u64,
    /// Em transição (com frame) ou só no arquivo de paginação.
    pub transition: bool,
}

/// Região privada (NtAllocateVirtualMemory, pilha e estruturas): commit
/// real por página.
pub struct PrivateRegion {
    pub base: u64,
    pub size: u64,
    pub protect: u32,
    pub allocation_protect: u32,
    pub allocation_type: u32,
    /// Alocação do NtAllocateVirtualMemory, cujas páginas o corte do working
    /// set pode levar ao arquivo de paginação. As estruturas que o kernel
    /// monta para o processo (pilha inicial, PEB, TEB, parâmetros) ficam
    /// residentes: o kernel as lê também com spin locks retidos, onde uma
    /// falta de página com E/S não pode ser atendida.
    pub pageable: bool,
    pub state: SpinLock<PrivateMut>,
}

impl PrivateRegion {
    fn new(base: u64, size: u64, protect: u32, allocation_type: u32, pageable: bool) -> Arc<Self> {
        let state = PrivateMut { frames: BTreeMap::new(), committed_pages: BTreeSet::new(), page_protects: BTreeMap::new(), protected_frames: BTreeMap::new(), paging: BTreeMap::new(), clean: BTreeMap::new(), busy: 0, locked: BTreeMap::new(), written: BTreeSet::new() };
        Arc::new(Self { base, size, protect, allocation_protect: protect, allocation_type, pageable, state: SpinLock::new(state) })
    }

    /// Retém a região contra o corte do working set enquanto o guard vive.
    pub fn hold(&self) -> RegionHold<'_> {
        self.state.lock().busy += 1;
        RegionHold { region: self }
    }
}

/// A retenção de [`PrivateRegion::hold`].
pub struct RegionHold<'a> {
    region: &'a PrivateRegion,
}

impl Drop for RegionHold<'_> {
    fn drop(&mut self) {
        let mut state = self.region.state.lock();
        state.busy = state.busy.saturating_sub(1);
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

/// O VAD de um processo: o que ele possui na metade de usuário. No NT é a
/// árvore de EPROCESS.VadRoot; aqui são listas (o EPROCESS.VadRoot fica
/// vazio).
#[derive(Default)]
pub struct Vad {
    /// Alocações privadas e vistas de seção de dados.
    pub regions: Vec<Region>,
    /// Imagens: o executável, a ntdll, as DLLs do loader e as vistas de
    /// seção de imagem.
    pub images: Vec<Region>,
    /// Área de strings das entradas LDR montadas pelo kernel: (próxima VA,
    /// fim da região).
    pub ldr_strings: (u64, u64),
}

impl Vad {
    fn find(&self, va: u64) -> Option<Region> {
        self.regions.iter().find(|region| contains(region, va)).or_else(|| self.images.iter().find(|region| contains(region, va))).cloned()
    }

    fn list(&mut self, kind: RegionKind) -> Option<&mut Vec<Region>> {
        match kind {
            RegionKind::User => Some(&mut self.regions),
            RegionKind::ProcessImages => Some(&mut self.images),
            _ => None,
        }
    }

    /// Retira a região (pela identidade) da lista do tipo; devolve se estava lá.
    fn remove(&mut self, kind: RegionKind, region: &Region) -> bool {
        let Some(list) = self.list(kind) else { return false };
        let Some(index) = list.iter().position(|candidate| state::same_region(candidate, region)) else { return false };
        list.remove(index);
        true
    }
}

/// O espaço de endereçamento de usuário de um processo, pelo EPROCESS: o VAD
/// do `ProcessState` dele.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Space {
    Process(u64),
}

impl Space {
    pub fn of(process: u64) -> Space {
        Space::Process(process)
    }

    /// O processo corrente (KTHREAD.ApcState.Process: o anexado, quando há
    /// attach).
    pub fn current() -> Space {
        Space::Process(process::get_current_process())
    }

    /// O System: o que o kernel aloca no próprio contexto e as imagens de
    /// sistema mapeadas uma vez.
    pub fn system() -> Space {
        Space::Process(process::get_system_process())
    }

    pub fn process(self) -> u64 {
        match self {
            Space::Process(process) => process,
        }
    }

    /// A raiz das tabelas de páginas do espaço (KPROCESS.DirectoryTableBase):
    /// a própria do processo, ou a do System.
    pub fn root(self) -> u64 {
        context_switch::directory_table_base(self.process())
    }

    /// O estado do processo; `None` depois do término.
    fn state(self) -> Option<Arc<ProcessState>> {
        process_state::get(self.process())
    }

    /// `body` sobre o VAD do processo; `None` se ele já saiu. A trava do VAD
    /// não atravessa chamadas que voltem a um VAD.
    pub fn with_vad<R>(self, body: impl FnOnce(&mut Vad) -> R) -> Option<R> {
        self.state().map(|state| body(&mut state.vad.lock()))
    }

    /// Região privada, vista ou imagem do processo que contém o endereço.
    pub fn find(self, va: u64) -> Option<Region> {
        self.with_vad(|vad| vad.find(va)).flatten()
    }

    /// Alocações privadas e vistas de dados do processo.
    pub fn regions(self) -> Vec<Region> {
        self.with_vad(|vad| vad.regions.clone()).unwrap_or_default()
    }

    /// Imagens do processo.
    pub fn images(self) -> Vec<Region> {
        self.with_vad(|vad| vad.images.clone()).unwrap_or_default()
    }

    /// Registra a região no VAD; `false` se o processo já saiu.
    fn insert(self, kind: RegionKind, region: Region) -> bool {
        self.with_vad(|vad| vad.list(kind).map(|list| list.push(region)).is_some()).unwrap_or(false)
    }

    /// Retira uma alocação privada do VAD (pela identidade).
    fn remove(self, region: &Region) {
        self.with_vad(|vad| vad.remove(RegionKind::User, region));
    }
}

/// Registra a região na lista do tipo: `User`/`ProcessImages` no VAD do
/// espaço, `Shared`/`KernelViews` nas listas de sistema, `Detached` em
/// nenhuma. Devolve se a região entrou numa lista.
pub fn insert_region(space: Space, kind: RegionKind, region: Region) -> bool {
    match kind {
        RegionKind::User | RegionKind::ProcessImages => space.insert(kind, region),
        RegionKind::Shared | RegionKind::KernelViews => state::with(|state| state.regions(kind).map(|list| list.push(region)).is_some()),
        RegionKind::Detached => false,
    }
}

/// Retira a região da lista do tipo: das listas de sistema ou do VAD do
/// processo que a possui (uma região está num VAD só).
pub fn remove_region(kind: RegionKind, region: &Region) {
    match kind {
        RegionKind::User | RegionKind::ProcessImages => {
            for state in process_state::all() {
                if state.vad.lock().remove(kind, region) {
                    return;
                }
            }
        }
        RegionKind::Shared | RegionKind::KernelViews => state::with(|state| state.remove_region(kind, region)),
        RegionKind::Detached => {}
    }
}

/// Tudo o que ocupa VA de usuário na raiz do espaço: as faixas de sistema
/// que todo processo vê na mesma VA (a KUSER_SHARED_DATA, a ntdll, o apiset,
/// o NLS e as vistas de sistema), os VADs dos processos que usam essa raiz
/// (só o do processo, quando a raiz é própria) e as vistas de seção
/// mapeadas nela (inclusive reservas ainda sem página). O que só existe nas
/// PTEs o `mm/section/address` acha pela árvore da mesma raiz
/// (`FindOptions::root`).
pub fn occupied(space: Space) -> Vec<section_address::Region> {
    let root = space.root();
    let span = |region: &Region| section_address::Region { base: region.base(), size: region.size() };
    let mut occupied: Vec<section_address::Region> = state::with(|state| state.shared_user_regions.iter().chain(state.section_kernel_views.iter()).map(span).collect());
    occupied.extend(crate::ntos::mm::shared_user_data::shared_user_pages().into_iter().filter(|&page| page != 0).map(|base| section_address::Region { base, size: PAGE }));
    occupied.extend(super::loader::system_image_ranges().into_iter().map(|(base, size)| section_address::Region { base, size }));
    for state in process_state::all() {
        if state.directory_table_base.load(core::sync::atomic::Ordering::Acquire) != root {
            continue;
        }
        let vad = state.vad.lock();
        occupied.extend(vad.regions.iter().chain(vad.images.iter()).map(span));
    }
    occupied.extend(sections::views().iter().filter(|view| view.root == root).map(|view| section_address::Region { base: view.base, size: view.size }));
    occupied.extend(section_views::all().iter().filter(|view| view.root() == root).map(|view| section_address::Region { base: view.base(), size: view.size() }));
    occupied.retain(|region| region.base < USER_ADDRESS_LIMIT);
    occupied
}

/// A primeira faixa livre de `size` bytes na metade de usuário do espaço, de
/// baixo para cima ou (`top_down`) de cima para baixo, alinhada a
/// `alignment`.
pub fn find_free(space: Space, size: u64, alignment: u64, top_down: bool) -> Result<u64, u32> {
    section_address::find(&section_address::FindOptions { size, alignment, top_down, root: space.root(), ..section_address::FindOptions::default() }, &occupied(space))
}

/// Região de usuário ou imagem do processo corrente que contém o endereço.
pub fn find_region(va: u64) -> Option<Region> {
    Space::current().find(va)
}

/// A VA cai numa faixa de sistema que todo processo vê na mesma VA: a visão
/// de usuário da KUSER_SHARED_DATA, as regiões compartilhadas (NLS), as
/// vistas de sistema e as imagens de sistema mapeadas uma vez (ntdll e
/// apiset).
pub fn shared_system_range(va: u64) -> bool {
    crate::ntos::mm::shared_user_data::is_shared_user_page(va)
        || super::loader::system_image(va)
        || state::with(|state| state.shared_user_regions.iter().chain(state.section_kernel_views.iter()).any(|region| contains(region, va)))
}

/// O verificador do modo estrito de posse (`guest_memory::set_ownership_check`):
/// uma página de usuário presente no espaço carregado tem de estar no VAD do
/// processo corrente (o anexado, quando há attach) ou numa faixa de sistema
/// compartilhada. A recusa nomeia o processo cujo VAD a contém (0 se
/// nenhum). Sem página, nada a recusar: a sonda devolve ACCESS_VIOLATION,
/// que é o que a VA de outro processo dá num espaço próprio.
pub fn check_user_access(va: u64) -> Result<(), guest::OwnershipFault> {
    let current = process::get_current_process();
    if Space::of(current).find(va).is_some() || shared_system_range(va) || paging::query_page(va & !(PAGE - 1), false).is_none() {
        return Ok(());
    }
    let owner = process_state::all().iter().find(|state| state.process != current && state.vad.lock().find(va).is_some()).map_or(0, |state| state.process);
    Err(guest::OwnershipFault { owner, current, thread: process::get_current_thread() })
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

/// Os bits da PTE de uma página privada com a proteção do Win32: U/S, R/W
/// nas proteções com escrita e P menos em PAGE_NOACCESS e PAGE_GUARD (a PTE
/// ausente guarda o frame). PAGE_NOCACHE e PAGE_WRITECOMBINE ficam só na
/// proteção registrada: a página privada segue em cache, como o mapa direto
/// que zera e copia o frame.
pub fn private_pte(protect: u32) -> u64 {
    let present = protect & 0xFF != 1 && protect & PAGE_GUARD == 0;
    let writable = protect & (4 | 8 | 0x40 | 0x80) != 0;
    paging::PAGE_USER | if present { paging::PAGE_PRESENT } else { 0 } | if writable { paging::PAGE_RW } else { 0 }
}

/// Mapeia uma faixa com frames do PFN na raiz `root` (commit inicial e
/// commit sobre reserva); qualquer falha desfaz as páginas desta chamada.
pub fn map_user_page_range(root: u64, base: u64, size: u64, region: Option<&PrivateRegion>, protect: u32) -> bool {
    let protect = if protect != 0 { protect } else { region.map_or(4, |region| if region.protect != 0 { region.protect } else { 4 }) };
    let mut added: Vec<(u64, u64, u64)> = Vec::new();
    let rollback = |added: &[(u64, u64, u64)]| {
        for &(va, frame, index) in added {
            paging::unmap_page_in(root, va, MapOptions::default());
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
        if !paging::map_page_in(root, base + offset, frame, private_pte(protect), MapOptions::default()) {
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

/// As páginas de `[base, base + size)` ainda sem commit na região.
fn uncommitted_pages(owner: &PrivateRegion, base: u64, size: u64) -> u64 {
    let state = owner.state.lock();
    (base..base + size).step_by(PAGE as usize).filter(|&va| !state.committed_pages.contains(&((va - owner.base) / PAGE))).count() as u64
}

pub fn map_region_pages(root: u64, region: &PrivateRegion) -> bool {
    map_user_page_range(root, region.base, region.size, Some(region), 0)
}

/// O alocador de VA: commit sobre reserva própria, base fixa ou escolha
/// pelo `mm/section/address` (primeira faixa livre; MEM_TOP_DOWN de cima).
#[allow(clippy::too_many_arguments)]
pub fn do_user_allocate(base_pointer: u64, size_pointer: u64, allocation_type: u32, protect: u32, lowest: u64, highest: u64, align: u64) -> Result<u32, KernelError> {
    allocate_in(Space::current(), base_pointer, size_pointer, allocation_type, protect, lowest, highest, align)
}

/// Reserva/commit no espaço dado. `lowest` é o piso pedido (nunca abaixo
/// de MM_LOWEST_USER_ADDRESS) e `highest` o limite exclusivo (0, ou acima do
/// topo, = MM_HIGHEST_VAD_ADDRESS + 1).
#[allow(clippy::too_many_arguments)]
pub fn allocate_in(space: Space, base_pointer: u64, size_pointer: u64, allocation_type: u32, protect: u32, lowest: u64, highest: u64, align: u64) -> Result<u32, KernelError> {
    if space.state().is_none() {
        return Ok(STATUS_PROCESS_IS_TERMINATING);
    }
    if !write_watch::valid_allocation_type(allocation_type) {
        return Ok(STATUS_INVALID_PARAMETER);
    }
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
    let protect = match allocation_protection(protect) {
        Ok(protect) => protect,
        Err(status) => return Ok(status),
    };
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
    let commit_only = !reserve && allocation_type & MEM_COMMIT != 0;
    if fixed {
        if let Some(existing) = space.find(base) {
            // COMMIT sem RESERVE dentro de uma região já reservada: comita a
            // subfaixa (só em regiões próprias; imagens nunca).
            let view = view_of(&existing);
            let ours = private(&existing).is_some() || view.is_some();
            if commit_only && ours && base >= existing.base() && base + size <= existing.base() + existing.size() {
                if let Some(view) = view {
                    let status = sections::commit_view(&view, base, size, protect)?;
                    if status != 0 {
                        return Ok(status);
                    }
                } else if let Some(owner) = private(&existing) {
                    let pages = uncommitted_pages(owner, base, size);
                    let reprotect = protection_differs(owner, base, size, protect);
                    let charged = process_commit::charge(space.process(), pages);
                    if charged != 0 {
                        return Ok(charged);
                    }
                    if !map_user_page_range(space.root(), base, size, Some(owner), protect) {
                        process_commit::release(space.process(), pages);
                        return Ok(0xC000_0017);
                    }
                    if reprotect {
                        reprotect_committed(space, base, size, protect)?;
                    }
                }
                guest::try_write::<u64>(base_pointer, base)?;
                guest::try_write::<u64>(size_pointer, size)?;
                return Ok(0);
            }
            debug_print!("[usermode] alloc CONFLITO: base 0x{:x} size 0x{:x} tipo 0x{:x} - regiao em 0x{:x}", base, size, allocation_type, existing.base());
            return Ok(STATUS_CONFLICTING_ADDRESSES);
        }
        // COMMIT sem RESERVE só comita o que já está reservado: sem VAD na
        // base, STATUS_CONFLICTING_ADDRESSES, como no MiAllocateVirtualMemory
        // do 19041 (o STATUS_MEMORY_NOT_ALLOCATED do MiObtainReferencedVadEx
        // vira CONFLICTING_ADDRESSES). Sem base, o commit reserva uma faixa
        // nova (abaixo).
        if commit_only {
            return Ok(STATUS_CONFLICTING_ADDRESSES);
        }
        // Os primeiros 64 KB nunca são mapeáveis (MiIsVaRangeAvailable).
        if base < lowest || base + size > highest {
            return Ok(STATUS_CONFLICTING_ADDRESSES);
        }
    }
    let top_down = allocation_type & MEM_TOP_DOWN != 0;
    let find = section_address::FindOptions { base, size, minimum: Some(lowest), upper: Some(highest - 1), alignment: align, top_down, root: space.root(), ..section_address::FindOptions::default() };
    let base = match section_address::find(&find, &occupied(space)) {
        Ok(base) => base,
        Err(status) => return Ok(status),
    };
    let region = PrivateRegion::new(base, size, protect, allocation_type, true);
    if allocation_type & MEM_COMMIT != 0 {
        // O commit da região inteira é cobrado do processo (e dos jobs dele)
        // antes das páginas.
        let charged = process_commit::charge(space.process(), size / PAGE);
        if charged != 0 {
            return Ok(charged);
        }
        if !map_region_pages(space.root(), &region) {
            process_commit::release(space.process(), size / PAGE);
            return Ok(0xC000_0017);
        }
    }
    let entry: Region = region.clone();
    if !space.insert(RegionKind::User, entry) {
        // O processo saiu no meio da alocação: as páginas voltam ao PFN.
        free_region_pages(space.process(), space.root(), &region);
        return Ok(STATUS_PROCESS_IS_TERMINATING);
    }
    guest::try_write::<u64>(base_pointer, base)?;
    guest::try_write::<u64>(size_pointer, size)?;
    Ok(0)
}

/// A proteção de uma alocação privada, como o MiAllocateVirtualMemory do
/// 19041: PAGE_TARGETS_INVALID só com uma proteção executável (senão
/// STATUS_INVALID_PAGE_PROTECTION) e sai da proteção, sem efeito com o CFG
/// ausente; o resto passa pelo MiMakeProtectionMask, que aceita PAGE_GUARD,
/// PAGE_NOCACHE e PAGE_WRITECOMBINE nas combinações válidas.
fn allocation_protection(protect: u32) -> Result<u32, u32> {
    let mut protect = protect;
    if protect & PAGE_TARGETS != 0 {
        if protect & 0xF0 == 0 {
            return Err(0xC000_0045);
        }
        protect &= !PAGE_TARGETS;
    }
    if protection::make_mask(protect).is_none() {
        return Err(0xC000_0045);
    }
    Ok(protect)
}

/// Alguma página já comitada de `[base, base + size)` tem outra proteção (o
/// MiCommitExistingVad compara cada uma com a pedida).
fn protection_differs(owner: &PrivateRegion, base: u64, size: u64, protect: u32) -> bool {
    let state = owner.state.lock();
    let (first, end) = ((base - owner.base) / PAGE, (base + size - owner.base) / PAGE);
    state.committed_pages.range(first..end).any(|index| state.page_protects.get(index).copied().filter(|&value| value != 0).unwrap_or(owner.protect) != protect)
}

/// O commit sobre páginas já comitadas com outra proteção troca a proteção
/// da faixa inteira depois do commit, como o MiAllocateVirtualMemory chama o
/// MmProtectVirtualMemory (o resultado não muda o do commit). É o RW→RX de um
/// JIT por VirtualAlloc(MEM_COMMIT): o d3d10warp exige a faixa em
/// PAGE_READWRITE e a recomita PAGE_EXECUTE_READ.
fn reprotect_committed(space: Space, base: u64, size: u64, protect: u32) -> Result<(), KernelError> {
    let cells = guest::alloc_bytes(0x18);
    if cells == 0 {
        return Err(KernelError::with_status("sem pool para a troca de protecao do commit", 0xC000_009A));
    }
    guest::write64(cells, base);
    guest::write64(cells + 8, size);
    let result = protect_in(space, cells, cells + 8, protect, cells + 0x10, false);
    guest::free_bytes(cells);
    result.map(|_| ())
}

/// Região privada comitada que o kernel monta para o processo do espaço, na
/// primeira faixa livre (`top_down`: a primeira de cima para baixo).
fn register_user_region(space: Space, size: u64, alignment: u64, top_down: bool) -> Result<Arc<PrivateRegion>, KernelError> {
    let size = size.div_ceil(PAGE) * PAGE;
    if size == 0 {
        return Err(KernelError::new("Regiao de usuario vazia"));
    }
    if space.state().is_none() {
        return Err(KernelError::with_status("regiao de usuario num processo sem VAD", STATUS_PROCESS_IS_TERMINATING));
    }
    let base = find_free(space, size, alignment, top_down).map_err(|status| KernelError::with_status("sem VA livre na metade de usuario", status))?;
    let region = PrivateRegion::new(base, size, 4, MEM_COMMIT | MEM_RESERVE, false);
    let charged = process_commit::charge(space.process(), size / PAGE);
    if charged != 0 {
        return Err(KernelError::with_status("commit da regiao de usuario acima do limite", charged));
    }
    if !map_region_pages(space.root(), &region) {
        process_commit::release(space.process(), size / PAGE);
        return Err(KernelError::new("PFN esgotado na regiao de usuario"));
    }
    let entry: Region = region.clone();
    if !space.insert(RegionKind::User, entry) {
        free_region_pages(space.process(), space.root(), &region);
        return Err(KernelError::with_status("processo saiu durante a regiao de usuario", STATUS_PROCESS_IS_TERMINATING));
    }
    Ok(region)
}

/// Pilha da primeira thread do processo corrente, uma alocação comum de
/// baixo para cima (como a reserva da pilha inicial no NT): devolve a base
/// (StackLimit e DeallocationStack) e o topo (StackBase) da pilha.
pub fn map_user_stack() -> Result<(u64, u64), KernelError> {
    let region = register_user_region(Space::current(), USER_STACK_SIZE, map::ALLOCATION_GRANULARITY, false)?;
    Ok((region.base, region.base + region.size))
}

/// Estruturas que o kernel monta para o processo corrente (PEB, TEB,
/// parâmetros, entradas do Ldr): páginas comitadas de cima para baixo, como
/// o MiCreatePebOrTeb, sem janela fixa.
pub fn map_user_region(size: u64) -> Result<u64, KernelError> {
    Ok(register_user_region(Space::current(), size, PAGE, true)?.base)
}

/// Igual, numa faixa de sistema (a cópia de sistema do NLS) mapeada na raiz
/// do System, na mesma VA que todo processo reserva; cada processo com raiz
/// própria recebe uma cópia privada dela (`map_private_copies`).
pub fn map_shared_user_region(size: u64) -> Result<u64, KernelError> {
    let rounded = size.div_ceil(PAGE) * PAGE;
    if rounded == 0 {
        return Err(KernelError::new("Regiao compartilhada vazia"));
    }
    let va = find_free(Space::system(), rounded, PAGE, true).map_err(|status| KernelError::with_status("sem VA livre para a regiao compartilhada", status))?;
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
        if !paging::map_page_in(SYSTEM_ROOT, va + offset, frame, paging::PAGE_PRESENT | paging::PAGE_RW | paging::PAGE_USER, MapOptions::default()) {
            return Err(KernelError::new("mapPage falhou nas regioes compartilhadas"));
        }
        offset += PAGE;
    }
    Ok(va)
}

/// Uma página de uma faixa de sistema fotografada logo depois do mapeamento
/// na raiz do System: a VA, o frame com a cópia (do Mm, fora de toda tabela
/// de páginas) e as permissões da PTE de origem.
pub struct TemplatePage {
    pub va: u64,
    pub frame: u64,
    pub flags: u64,
    pub nx: bool,
}

/// Bits da PTE de origem que a cópia repete.
const TEMPLATE_FLAGS: u64 = paging::PAGE_PRESENT | paging::PAGE_RW | paging::PAGE_USER | paging::PAGE_PWT | paging::PAGE_PCD;

/// Fotografa em frames próprios as páginas presentes de `[base, base +
/// size)` na raiz do System: a origem das cópias por processo, que não muda
/// com o que rodar depois na raiz do System. Uma falha devolve os frames já
/// tirados.
pub fn snapshot_system_range(base: u64, size: u64) -> Result<Vec<TemplatePage>, KernelError> {
    let mut pages = Vec::new();
    let mut va = base & !(PAGE - 1);
    while va < base + size {
        if let Some(page) = paging::query_page_in(SYSTEM_ROOT, va, false).filter(|page| page.page_size == PAGE) {
            let frame = pfn::alloc_page();
            if frame == 0 {
                release_template(pages);
                return Err(KernelError::new("PFN esgotado na fotografia de uma faixa de sistema"));
            }
            physical::write_bytes(frame, &physical::read_bytes(page.physical_address & !(PAGE - 1), PAGE as usize));
            pages.push(TemplatePage { va, frame, flags: page.flags & TEMPLATE_FLAGS, nx: page.nx });
        }
        va += PAGE;
    }
    Ok(pages)
}

/// Devolve ao PFN os frames de uma fotografia.
pub fn release_template(pages: Vec<TemplatePage>) {
    for page in pages {
        pfn::free_page(page.frame);
    }
}

/// Cópias privadas das páginas fotografadas na raiz `root`, nas mesmas VAs
/// e com as mesmas permissões (o PspMapSystemDll e as vistas de sistema de
/// um processo novo, sem frame dividido). Cada página mapeada entra em
/// `mapped` (VA, frame) na hora: o dono a devolve no término, mesmo depois
/// de uma falha no meio.
pub fn map_private_copies(root: u64, pages: &[TemplatePage], mapped: &mut Vec<(u64, u64)>) -> Result<(), KernelError> {
    for page in pages {
        let frame = pfn::alloc_page();
        if frame == 0 {
            return Err(KernelError::with_status("PFN esgotado na copia de sistema do processo", 0xC000_0017));
        }
        physical::write_bytes(frame, &physical::read_bytes(page.frame, PAGE as usize));
        if !paging::map_page_in(root, page.va, frame, page.flags, MapOptions { nx: page.nx, ..MapOptions::default() }) {
            pfn::free_page(frame);
            return Err(KernelError::new(alloc::format!("mapPage falhou na copia de sistema em {:#x}", page.va)));
        }
        mapped.push((page.va, frame));
    }
    Ok(())
}

/// Desfaz na raiz `root` as cópias privadas de [`map_private_copies`] e
/// devolve os frames.
pub fn release_private_copies(root: u64, pages: Vec<(u64, u64)>) {
    for (va, frame) in pages {
        paging::unmap_page_in(root, va, MapOptions::default());
        pfn::free_page(frame);
    }
}

/// O processo do handle de um serviço de usuário com o acesso pedido (o
/// ObReferenceObjectByHandle(PsProcessType) em UserMode: o pseudo-handle é o
/// processo corrente, um handle precisa ser da tabela do corrente e ter
/// `desired`, senão STATUS_ACCESS_DENIED), retido enquanto `body` age sobre
/// ele. Um processo terminado ou saindo dá STATUS_PROCESS_IS_TERMINATING.
pub fn with_process_handle(handle: u64, desired: u32, body: impl FnOnce(u64) -> Result<u32, KernelError>) -> Result<u32, KernelError> {
    let process = match section_handles::reference(handle, Kind::Process, desired, USER_MODE) {
        Ok(process) => process,
        Err(status) => return Ok(status),
    };
    let result = if process.process_terminating() { Ok(STATUS_PROCESS_IS_TERMINATING) } else { body(process.pointer) };
    process.release()?;
    result
}

/// NtAllocateVirtualMemory(process, base*, zeroBits, size*, type, protect),
/// no processo do handle (PROCESS_VM_OPERATION).
pub fn nt_allocate_virtual_memory(process: u64, base_pointer: u64, _zero_bits: u64, size_pointer: u64, user_rsp: u64) -> Result<u32, KernelError> {
    let allocation_type = state::stack_arg32(user_rsp, 5);
    let protect = state::stack_arg32(user_rsp, 6);
    // Os ponteiros de saída são acessados por cópias sondadas.
    with_process_handle(process, PROCESS_VM_OPERATION, |target| state::guarded(|| allocate_in(Space::of(target), base_pointer, size_pointer, allocation_type, protect, 0, 0, map::ALLOCATION_GRANULARITY)))
}

/// NtAllocateVirtualMemoryEx(process, base*, size*, type, protect, params*,
/// count), no processo do handle (PROCESS_VM_OPERATION): sem ZeroBits;
/// MEM_ADDRESS_REQUIREMENTS honrado; PartitionHandle recusado pelo syscall
/// nativo mesmo válido.
pub fn nt_allocate_virtual_memory_ex(process: u64, base_pointer: u64, size_pointer: u64, allocation_type: u64, user_rsp: u64) -> Result<u32, KernelError> {
    let (parameters, count) = (state::stack_arg(user_rsp, 6), state::stack_arg32(user_rsp, 7) as u64);
    // BaseAddress, RegionSize e o vetor de MEM_EXTENDED_PARAMETER são
    // acessados por cópias sondadas.
    if guest::try_read::<u64>(size_pointer).is_ok_and(|size| size == 0) {
        // Diagnóstico: endereços de retorno na pilha de usuário.
        debug_print!("[usermode] allocEx tamanho zero chamado de 0x{:x} caller2=0x{:x} sizePtr=0x{:x}", guest::try_read::<u64>(user_rsp).unwrap_or(0), guest::try_read::<u64>(user_rsp + 0x90).unwrap_or(0), size_pointer);
    }
    let protect = state::stack_arg32(user_rsp, 5);
    with_process_handle(process, PROCESS_VM_OPERATION, |target| state::guarded(|| allocate_ex_in(Space::of(target), base_pointer, size_pointer, allocation_type as u32, protect, parameters, count)))
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

/// NtFreeVirtualMemory, no processo do handle (PROCESS_VM_OPERATION), como
/// o MmFreeVirtualMemory do 19041 (`free_in`): o FreeType e a faixa são
/// conferidos antes do handle.
pub fn nt_free_virtual_memory(process: u64, base_pointer: u64, size_pointer: u64, free_type: u64, _user_rsp: u64) -> Result<u32, KernelError> {
    let free_type = free_type as u32;
    state::guarded(|| {
        let (base, size) = (guest::try_read::<u64>(base_pointer)?, guest::try_read::<u64>(size_pointer)?);
        if let Err(status) = free_range_request(base, size, free_type) {
            return Ok(status);
        }
        with_process_handle(process, PROCESS_VM_OPERATION, |target| state::guarded(|| free_in(Space::of(target), base_pointer, size_pointer, free_type)))
    })
}

/// NtSetInformationVirtualMemory(process, class, NumberOfEntries,
/// VirtualAddresses, VmInformation, VmInformationLength) do modo usuário:
/// as validações iniciais do serviço (`mm/prefetch`), o ProbeForRead com
/// alinhamento 4 do vetor de MEMORY_RANGE_ENTRY e do ULONG de VmInformation,
/// o processo do handle com PROCESS_VM_OPERATION, as faixas capturadas e
/// conferidas (STATUS_INVALID_PARAMETER_4) e a pré-busca da
/// VmPrefetchInformation (flags diferentes de zero são
/// STATUS_INVALID_PARAMETER_5). Os alvos de CFG (classe 2) seguem o
/// processo sem CFG (`mm/control_flow_guard`). Prioridade de página e as
/// classes de estado de página ainda não existem no OpenNT
/// (STATUS_NOT_SUPPORTED). A ntdll pede VmImageHotPatchInformation a cada
/// DLL inicializada e ignora o resultado.
pub fn nt_set_information_virtual_memory(process: u64, class: u64, count: u64, entries: u64, user_rsp: u64) -> Result<u32, KernelError> {
    use crate::ntos::mm::prefetch;
    let information = state::stack_arg(user_rsp, 5);
    let length = state::stack_arg32(user_rsp, 6);
    let class = class as u32;
    if let Err(status) = prefetch::validate_information_request(class, count, information, length) {
        return Ok(status);
    }
    let bytes = count * 16;
    if entries & 3 != 0 || (class != 2 && information & 3 != 0) {
        return Ok(0x8000_0002);
    }
    if !state::probe_user_read(entries, bytes) || (class != 2 && !state::probe_user_read(information, 4)) {
        return Ok(0xC000_0005);
    }
    let targets = if class == control_flow_guard::VM_CFG_CALL_TARGET_INFORMATION {
        match control_flow_guard::capture_list(information) {
            Ok(list) => Some(list),
            Err(status) => return Ok(status),
        }
    } else {
        None
    };
    let flags = if class != 2 {
        match guest::try_read::<u32>(information) {
            Ok(flags) => flags,
            Err(_) => return Ok(0xC000_0005),
        }
    } else {
        0
    };
    let captured = match guest::try_read_bytes(entries, bytes as usize) {
        Ok(captured) => captured,
        Err(_) => return Ok(0xC000_0005),
    };
    let ranges: Vec<(u64, u64)> = captured.chunks_exact(16).map(|entry| (u64::from_le_bytes(entry[..8].try_into().unwrap_or([0; 8])), u64::from_le_bytes(entry[8..].try_into().unwrap_or([0; 8])))).collect();
    with_process_handle(process, PROCESS_VM_OPERATION, |target| {
        if let Some(list) = &targets {
            return state::guarded(|| control_flow_guard::set_call_targets(target, &ranges, list, USER_MODE));
        }
        if !prefetch::valid_user_ranges(&ranges) {
            return Ok(prefetch::STATUS_INVALID_PARAMETER_4);
        }
        if class != prefetch::VM_PREFETCH_INFORMATION {
            return Ok(prefetch::STATUS_NOT_SUPPORTED);
        }
        if flags != 0 {
            return Ok(prefetch::STATUS_INVALID_PARAMETER_5);
        }
        prefetch::prefetch_ranges(target, &ranges).map(|_| 0)
    })
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

const MEM_DECOMMIT: u32 = 0x4000;
const MEM_RELEASE: u32 = 0x8000;
const MEM_COALESCE_PLACEHOLDERS: u32 = 0x1;
const MEM_PRESERVE_PLACEHOLDER: u32 = 0x2;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;
const STATUS_UNABLE_TO_FREE_VM: u32 = 0xC000_001A;
const STATUS_UNABLE_TO_DELETE_SECTION: u32 = 0xC000_001B;
const STATUS_FREE_VM_NOT_AT_BASE: u32 = 0xC000_009F;
const STATUS_MEMORY_NOT_ALLOCATED: u32 = 0xC000_00A0;

/// O FreeType conferido pelo MmFreeVirtualMemory.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FreeKind {
    Decommit,
    Release,
    /// MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER.
    PreservePlaceholder,
    /// MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS.
    CoalescePlaceholders,
}

/// As conferências do MmFreeVirtualMemory (ntoskrnl 19041, rva 0x63ad20)
/// antes do handle: exatamente um de MEM_DECOMMIT e MEM_RELEASE
/// (STATUS_INVALID_PARAMETER_4), a base até MM_HIGHEST_USER_ADDRESS
/// (STATUS_INVALID_PARAMETER_2) e a faixa abaixo de MmUserProbeAddress
/// (STATUS_INVALID_PARAMETER_3); os dois bits de placeholder juntos dão
/// STATUS_INVALID_PARAMETER, e um deles só vale com MEM_RELEASE e a faixa em
/// páginas inteiras. Devolve o FreeType sem os bits de placeholder.
fn free_range_request(base: u64, size: u64, free_type: u32) -> Result<(u32, Option<FreeKind>), u32> {
    if matches!(free_type & (MEM_DECOMMIT | MEM_RELEASE), 0 | 0xC000) {
        return Err(STATUS_INVALID_PARAMETER_4);
    }
    if base > map::HIGHEST_USER_ADDRESS {
        return Err(STATUS_INVALID_PARAMETER_2);
    }
    if USER_ADDRESS_LIMIT - base < size {
        return Err(STATUS_INVALID_PARAMETER_3);
    }
    let mut remaining = free_type;
    let placeholder = if remaining & MEM_PRESERVE_PLACEHOLDER != 0 {
        if remaining & MEM_COALESCE_PLACEHOLDERS != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        remaining &= !MEM_PRESERVE_PLACEHOLDER;
        Some(FreeKind::PreservePlaceholder)
    } else if remaining & MEM_COALESCE_PLACEHOLDERS != 0 {
        remaining &= !MEM_COALESCE_PLACEHOLDERS;
        Some(FreeKind::CoalescePlaceholders)
    } else {
        None
    };
    if placeholder.is_some() {
        if remaining != MEM_RELEASE {
            return Err(STATUS_INVALID_PARAMETER_4);
        }
        if size == 0 || size & (PAGE - 1) != 0 {
            return Err(STATUS_INVALID_PARAMETER_3);
        }
        if base & (PAGE - 1) != 0 {
            return Err(STATUS_INVALID_PARAMETER_2);
        }
    }
    Ok((remaining, placeholder))
}

/// O FreeType inteiro: depois do handle, nenhum bit além de MEM_DECOMMIT e
/// MEM_RELEASE (os internos do kernel não vêm deste caminho).
fn free_request(base: u64, size: u64, free_type: u32) -> Result<FreeKind, u32> {
    let (remaining, placeholder) = free_range_request(base, size, free_type)?;
    if remaining & !(MEM_DECOMMIT | MEM_RELEASE) != 0 {
        return Err(STATUS_INVALID_PARAMETER_4);
    }
    Ok(placeholder.unwrap_or(if remaining == MEM_RELEASE { FreeKind::Release } else { FreeKind::Decommit }))
}

/// MEM_DECOMMIT/MEM_RELEASE no espaço dado, como o MmFreeVirtualMemory do
/// 19041. A região é a que contém a página da base (sem região,
/// STATUS_MEMORY_NOT_ALLOCATED); a faixa é a pedida, arredondada a páginas,
/// ou, com RegionSize 0, da base ao fim da região (o MEM_RELEASE exige a base
/// na primeira página dela: STATUS_FREE_VM_NOT_AT_BASE). Uma faixa que passa
/// do fim da região dá STATUS_UNABLE_TO_FREE_VM e uma vista ou imagem
/// STATUS_UNABLE_TO_DELETE_SECTION. MEM_DECOMMIT devolve as páginas e deixa
/// a reserva (com RegionSize 0 devolve RegionSize 0, como o 19041);
/// MEM_RELEASE devolve a faixa e tira do VAD a região inteira ou só a parte
/// liberada (o MiFreeVadRange: o RtlCreateHeap reserva a pilha do heap com
/// uma folga aleatória e libera o começo dela). O OpenNT não cria reservas
/// de placeholder: MEM_COALESCE_PLACEHOLDERS e MEM_PRESERVE_PLACEHOLDER dão
/// STATUS_CONFLICTING_ADDRESSES, a resposta do 19041 para VADs comuns.
pub fn free_in(space: Space, base_pointer: u64, size_pointer: u64, free_type: u32) -> Result<u32, KernelError> {
    let base = guest::try_read::<u64>(base_pointer)?;
    let size = guest::try_read::<u64>(size_pointer)?;
    let kind = match free_request(base, size, free_type) {
        Ok(kind) => kind,
        Err(status) => return Ok(status),
    };
    if kind == FreeKind::CoalescePlaceholders {
        return Ok(STATUS_CONFLICTING_ADDRESSES);
    }
    let start = base & !(PAGE - 1);
    let Some(region) = space.find(start) else {
        return Ok(if space.state().is_none() { STATUS_PROCESS_IS_TERMINATING } else { STATUS_MEMORY_NOT_ALLOCATED });
    };
    let release = kind != FreeKind::Decommit;
    let (region_start, region_end) = (region.base(), region.base() + region.size());
    if size == 0 && release && start != region_start {
        return Ok(STATUS_FREE_VM_NOT_AT_BASE);
    }
    let (first, end) = if size == 0 { (if release { region_start } else { start }, region_end) } else { (start, (base + size).div_ceil(PAGE) * PAGE) };
    if end > region_end {
        return Ok(STATUS_UNABLE_TO_FREE_VM);
    }
    let Some(owner) = private(&region) else { return Ok(STATUS_UNABLE_TO_DELETE_SECTION) };
    if kind == FreeKind::PreservePlaceholder {
        return Ok(STATUS_CONFLICTING_ADDRESSES);
    }
    if !release && size == 0 && start != region_start {
        return Ok(STATUS_FREE_VM_NOT_AT_BASE);
    }
    let whole = (first, end) == (region_start, region_end);
    // SAFETY: o EPROCESS do espaço, retido por quem pediu a liberação.
    if release && !whole && unsafe { crate::ntos::inc::types::Eprocess::at(space.process()) }.relinquished_commit() != 0 {
        return Ok(STATUS_PROCESS_IS_TERMINATING);
    }
    decommit_private_pages(space, owner, first, end);
    if release {
        if whole {
            space.remove(&region);
        } else {
            split_private_region(space, &region, owner, first, end);
        }
    }
    guest::try_write::<u64>(base_pointer, first)?;
    guest::try_write::<u64>(size_pointer, if !release && size == 0 { 0 } else { end - first })?;
    Ok(0)
}

/// O MiDecommitRegion de uma região privada: as páginas confirmadas de
/// [first, end) saem (frame, cópia no arquivo de paginação, proteção e
/// trava) e o commit volta ao processo.
fn decommit_private_pages(space: Space, owner: &PrivateRegion, first: u64, end: u64) {
    let mut va = first;
    let mut decommitted = 0;
    while va < end {
        let index = (va - owner.base) / PAGE;
        let (frame, paged, clean) = {
            let mut state = owner.state.lock();
            if state.committed_pages.remove(&index) {
                decommitted += 1;
                state.locked.remove(&index);
                state.page_protects.remove(&index);
                state.protected_frames.remove(&index);
                (state.frames.remove(&index), state.paging.remove(&index), state.clean.remove(&index))
            } else {
                (None, None, None)
            }
        };
        // Uma página fora do working set devolve a cópia no arquivo de
        // paginação e a PTE de software.
        working_set::discard(space.root(), va, paged, clean);
        if let Some(frame) = frame {
            paging::unmap_page_in(space.root(), va, MapOptions::default());
            pfn::free_page(frame);
        }
        va += PAGE;
    }
    process_commit::release(space.process(), decommitted);
}

/// As entradas de `[from, to)` saem do mapa e voltam reindexadas a partir de 0.
fn take_pages<V>(map: &mut BTreeMap<u64, V>, from: u64, to: u64) -> BTreeMap<u64, V> {
    let mut taken = map.split_off(&from);
    let mut after = taken.split_off(&to);
    map.append(&mut after);
    taken.into_iter().map(|(index, value)| (index - from, value)).collect()
}

/// O mesmo para um conjunto de índices.
fn take_indices(set: &mut BTreeSet<u64>, from: u64, to: u64) -> BTreeSet<u64> {
    let mut taken = set.split_off(&from);
    let mut after = taken.split_off(&to);
    set.append(&mut after);
    taken.into_iter().map(|index| index - from).collect()
}

/// O MiFreeVadRange de uma faixa interna (já sem páginas): a parte da região
/// antes de [first, end) e a parte depois viram regiões novas no VAD, no
/// lugar da original e com a mesma proteção, cada uma com as páginas dela
/// reindexadas (frames, commit, proteções, cópias no arquivo de paginação,
/// travas e o bitmap de write watch). As páginas em transição voltam às listas de modificadas e de
/// reserva pela região nova; as entradas pela região antiga deixam de valer
/// (o frame já não é dela).
fn split_private_region(space: Space, region: &Region, owner: &PrivateRegion, first: u64, end: u64) {
    let root = space.root();
    let mut relisted: Vec<(working_set::ListedPage, bool)> = Vec::new();
    space.with_vad(|vad| {
        let Some(position) = vad.regions.iter().position(|candidate| state::same_region(candidate, region)) else { return };
        let mut old = owner.state.lock();
        vad.regions.remove(position);
        for (start, stop) in [(owner.base, first), (end, owner.base + owner.size)] {
            if stop <= start {
                continue;
            }
            let piece = PrivateRegion::new(start, stop - start, owner.protect, owner.allocation_type, owner.pageable);
            let entry: Region = piece.clone();
            let (from, to) = ((start - owner.base) / PAGE, (stop - owner.base) / PAGE);
            {
                let mut moved = piece.state.lock();
                moved.frames = take_pages(&mut old.frames, from, to);
                moved.committed_pages = take_indices(&mut old.committed_pages, from, to);
                moved.page_protects = take_pages(&mut old.page_protects, from, to);
                moved.protected_frames = take_pages(&mut old.protected_frames, from, to);
                moved.paging = take_pages(&mut old.paging, from, to);
                moved.clean = take_pages(&mut old.clean, from, to);
                moved.locked = take_pages(&mut old.locked, from, to);
                moved.written = take_indices(&mut old.written, from, to);
                for (&index, paged) in moved.paging.iter().filter(|(_, paged)| paged.transition) {
                    if let Some(&frame) = moved.frames.get(&index) {
                        relisted.push((working_set::ListedPage { region: entry.clone(), root, index, frame }, paged.slot.is_none()));
                    }
                }
            }
            vad.regions.push(entry);
        }
    });
    for (page, modified) in relisted {
        if modified {
            crate::ntos::mm::modified_writer::insert_modified(page);
        } else {
            crate::ntos::mm::modified_writer::insert_standby(page);
        }
    }
}

/// NtProtectVirtualMemory(process, base*, size*, newProtect, oldProtect*),
/// no processo do handle (PROCESS_VM_OPERATION): cobre qualquer VA de
/// usuário mapeada (a ntdll protege as próprias seções da imagem); falha de
/// política devolve PAGE_NOACCESS no OldProtect sem tocar base, tamanho ou
/// PTEs.
pub fn nt_protect_virtual_memory(process: u64, base_pointer: u64, size_pointer: u64, new_protect: u64, user_rsp: u64) -> Result<u32, KernelError> {
    let old_pointer = state::stack_arg(user_rsp, 5);
    with_process_handle(process, PROCESS_VM_OPERATION, |target| state::guarded(|| protect_in(Space::of(target), base_pointer, size_pointer, new_protect as u32, old_pointer, true)))
}

/// A proteção nova do NtProtectVirtualMemory 19041: o MiMakeProtectionMask
/// sobre os bits que ele confere (0x0FF807FF; inválida dá
/// STATUS_INVALID_PAGE_PROTECTION) e o PAGE_TARGETS_NO_UPDATE, que o
/// MmProtectVirtualMemory tira e só aceita com uma proteção executável sem
/// modificadores (senão STATUS_INVALID_PARAMETER_4); com o CFG ausente ele
/// não tem outro efeito.
fn protection_change(protect: u32) -> Result<u32, u32> {
    if protection::make_mask(protect & 0x0FF8_07FF).is_none() {
        return Err(0xC000_0045);
    }
    if protect & PAGE_TARGETS == 0 {
        return Ok(protect);
    }
    let protect = protect & !PAGE_TARGETS;
    if protect & 0xFFFF_FF0F != 0 {
        return Err(0xC000_00F2);
    }
    Ok(protect)
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
    let protect = match protection_change(new_protect as u32) {
        Ok(protect) => protect,
        Err(status) => return Ok(status),
    };
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
    // PAGE_GUARD, PAGE_NOCACHE e PAGE_WRITECOMBINE valem nas alocações
    // privadas; vistas e imagens ainda não têm guarda nem cache próprio.
    if protect & !0x7FF != 0 || (protect & 0x700 != 0 && private(&region).is_none()) {
        return Ok(0xC000_00BB);
    }
    if let Some(section) = &section {
        if !sections::compatible(section.is_image, section.page_protect(), protect) {
            return Ok(0xC000_004E);
        }
    }
    let context = Context::of(space);
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
    let root = space.root();
    // As páginas de uma alocação privada voltam ao working set antes da
    // troca, e a região fica retida contra o corte enquanto ela dura.
    let owner = private(&region);
    let _hold = owner.map(|owner| owner.hold());
    if let Some(owner) = owner {
        let status = working_set::make_resident(root, owner, (base - owner.base) / PAGE, (end - owner.base) / PAGE);
        if status != 0 {
            return Ok(status);
        }
    }
    let committed = region.committed_pages();
    let mut changes = Vec::new();
    let mut va = base;
    while va < end {
        let index = (va - region.base()) / PAGE;
        let physical = region.frame(index).unwrap_or_else(|| paging::translate_in(root, va));
        if committed.as_ref().is_some_and(|pages| !pages.contains(&index)) || physical == 0 {
            return Ok(0xC000_002D);
        }
        changes.push((va, index, physical));
        va += PAGE;
    }
    let old = memory_query::page_protection(&region, (base - region.base()) / PAGE, &context);
    let writable = protect & (4 | 8 | 0x40 | 0x80) != 0;
    // Uma página compartilhada de imagem que fica gravável ganha antes a
    // cópia privada do processo (o PAGE_WRITECOPY resolvido).
    let mut changes = changes;
    if writable {
        for (_, index, physical) in changes.iter_mut() {
            match region.write_copy(*index) {
                Some(Ok(copy)) => *physical = copy,
                Some(Err(status)) => return Ok(status),
                None => {}
            }
        }
    }
    for (va, index, physical) in changes {
        // A PTE reescrita perde o bit Dirty: numa alocação MEM_WRITE_WATCH
        // ele passa antes ao bitmap da região.
        if let Some(owner) = owner.filter(|owner| write_watch::watched(owner)) {
            if let Some(pte) = paging::read_leaf_in(root, va) {
                write_watch::capture(owner, &mut owner.state.lock(), index, pte);
            }
        }
        paging::map_page_in(root, va, physical, private_pte(protect), MapOptions { nx: protect & 0xF0 == 0, ..MapOptions::default() });
        region.record_protect(index, protect, physical);
    }
    guest::try_write::<u32>(old_pointer, old)?;
    guest::try_write::<u64>(base_pointer, base)?;
    guest::try_write::<u64>(size_pointer, size)?;
    Ok(0)
}

/// NtReadVirtualMemory/NtWriteVirtualMemory(process, address, buffer, size,
/// transferred*): a cópia entre `address` no processo do handle
/// (PROCESS_VM_READ na leitura, PROCESS_VM_WRITE na gravação) e `buffer` no
/// processo corrente, por `mm/copy_virtual` em UserMode. As duas faixas
/// precisam caber até MmHighestUserAddress, sem dar a volta
/// (STATUS_ACCESS_VIOLATION); tamanho zero devolve sucesso sem olhar o
/// handle, como no NT. O buffer do chamador é sondado inteiro antes, no
/// espaço dele; as páginas do alvo obedecem às PTEs dele, e a primeira
/// inacessível dá STATUS_PARTIAL_COPY com a contagem exata. A contagem vai
/// para `transferred` mesmo na falha; uma saída que falha não muda o status.
fn transfer_virtual_memory(process: u64, address: u64, buffer: u64, size: u64, rsp: u64, write: bool) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 8) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let fits = |start: u64| start.checked_add(size).is_some_and(|end| end <= map::HIGHEST_USER_ADDRESS);
    if !fits(address) || !fits(buffer) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let transferred = state::stack_arg(rsp, 5);
    if transferred != 0 && !state::probe_user_write(transferred, 8) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let mut copied = 0;
    let status = if size == 0 {
        0
    } else {
        with_process_handle(process, if write { PROCESS_VM_WRITE } else { PROCESS_VM_READ }, |target| {
            if !(if write { state::probe_user_read(buffer, size) } else { state::probe_user_write(buffer, size) }) {
                return Ok(STATUS_ACCESS_VIOLATION);
            }
            let current = process::get_current_process();
            let (status, bytes) = if write { copy_virtual::copy_virtual_memory(current, buffer, target, address, size, USER_MODE)? } else { copy_virtual::copy_virtual_memory(target, address, current, buffer, size, USER_MODE)? };
            copied = bytes;
            Ok(status)
        })?
    };
    // SIZE_T *NumberOfBytesTransferred (sondado acima).
    if transferred != 0 {
        let _ = guest::try_write::<u64>(transferred, copied);
    }
    Ok(status)
}

pub fn nt_read_virtual_memory(process: u64, address: u64, buffer: u64, size: u64, rsp: u64) -> Result<u32, KernelError> {
    transfer_virtual_memory(process, address, buffer, size, rsp, false)
}

pub fn nt_write_virtual_memory(process: u64, address: u64, buffer: u64, size: u64, rsp: u64) -> Result<u32, KernelError> {
    transfer_virtual_memory(process, address, buffer, size, rsp, true)
}

/// Libera uma região privada do VAD que a possui (a pilha e a TEB de uma
/// thread, por exemplo); uma região que já saiu do VAD (liberada ou
/// devolvida no término do processo) não é tocada. Buracos reservados não
/// têm PFN; páginas NOACCESS ainda são donas do frame.
pub fn release_private_region(region: &Region) {
    let Some(owner) = private(region) else { return };
    let holder = process_state::all().into_iter().find(|state| state.vad.lock().remove(RegionKind::User, region));
    if let Some(holder) = holder {
        free_region_pages(holder.process, holder.directory_table_base.load(core::sync::atomic::Ordering::Acquire), owner);
    }
}

/// Desmapeia da raiz `root` e devolve ao PFN as páginas comitadas de uma
/// região privada de `process`, devolvendo o commit delas.
fn free_region_pages(process: u64, root: u64, owner: &PrivateRegion) {
    let (pages, committed, paged, clean) = {
        let mut state = owner.state.lock();
        let pages: Vec<(u64, u64)> = state.committed_pages.iter().filter_map(|&index| state.frames.get(&index).map(|&frame| (index, frame))).collect();
        let committed = state.committed_pages.len() as u64;
        state.committed_pages.clear();
        state.frames.clear();
        (pages, committed, core::mem::take(&mut state.paging), core::mem::take(&mut state.clean))
    };
    for (index, page) in paged {
        working_set::discard(root, owner.base + index * PAGE, Some(page), None);
    }
    for (index, slot) in clean {
        working_set::discard(root, owner.base + index * PAGE, None, Some(slot));
    }
    process_commit::release(process, committed);
    for (index, frame) in pages {
        paging::unmap_page_in(root, owner.base + index * PAGE, MapOptions::default());
        pfn::free_page(frame);
    }
}

/// Devolve o VAD inteiro do processo (o MmCleanProcessAddressSpace do
/// término): as listas saem do VAD primeiro, então nada mais as encontra; as
/// vistas de dados e de imagem voltam ao Mm e as páginas privadas ao PFN,
/// todas desfeitas na raiz do processo (o término roda no contexto de quem
/// termina). As imagens do loader não têm páginas próprias (são do
/// `pe_loader`, que as desfaz na raiz em que as mapeou).
pub fn release_vad(state: &ProcessState) {
    let root = state.directory_table_base.load(core::sync::atomic::Ordering::Acquire);
    let (regions, images) = {
        let mut vad = state.vad.lock();
        vad.ldr_strings = (0, 0);
        (core::mem::take(&mut vad.regions), core::mem::take(&mut vad.images))
    };
    for region in &regions {
        if let Some(owner) = private(region) {
            free_region_pages(state.process, root, owner);
        } else if let Some(view) = view_of(region) {
            if let Err(error) = sections::unmap(&view, None) {
                debug_print!("[usermode] vista em 0x{:x} retida no termino do processo: {}", view.base, error);
            }
        }
    }
    for image in &images {
        let view = section_views::all().into_iter().find(|view| matches!(view, section_views::OwnedView::Image(registered) if registered.section.is_some()) && state::same_region(&view.region(), image));
        if let Some(view) = view {
            if let Err(error) = section_views::unmap(&view) {
                debug_print!("[usermode] imagem em 0x{:x} retida no termino do processo: {}", image.base(), error);
            }
        }
    }
}

fn query(process: u64, base: u64, class: u64, buffer: u64, rsp: u64) -> Result<u32, KernelError> {
    memory_query::query_virtual_memory(process, base, class, buffer, rsp)
}

/// NtCreatePagingFile(PageFileName, MinimumSize, MaximumSize, Priority):
/// `mm/paging_file/create`.
fn nt_create_paging_file(name: u64, minimum: u64, maximum: u64, priority: u64, _rsp: u64) -> Result<u32, KernelError> {
    crate::ntos::mm::paging_file::create::nt_create_paging_file(name, minimum, maximum, priority as u32)
}

/// NtLockVirtualMemory(process, base*, size*, MapType) e
/// NtUnlockVirtualMemory: o processo do handle com PROCESS_VM_OPERATION, o
/// SeLockMemoryPrivilege para MAP_SYSTEM e a trava de `mm/virtual_lock`;
/// BaseAddress e RegionSize voltam arredondados a páginas no sucesso.
fn lock_or_unlock(process: u64, base_pointer: u64, size_pointer: u64, map_type: u64, lock: bool) -> Result<u32, KernelError> {
    let map_type = map_type as u32;
    let (base, size) = match (guest::try_read::<u64>(base_pointer), guest::try_read::<u64>(size_pointer)) {
        (Ok(base), Ok(size)) if state::probe_user_write(base_pointer, 8) && state::probe_user_write(size_pointer, 8) => (base, size),
        _ => return Ok(STATUS_ACCESS_VIOLATION),
    };
    let (first, end) = match virtual_lock::validate(map_type, base, size) {
        Ok(range) => range,
        Err(status) => return Ok(status),
    };
    with_process_handle(process, PROCESS_VM_OPERATION, |target| {
        if map_type & virtual_lock::MAP_SYSTEM != 0 && !crate::ntos::se::privilege::single_privilege_check(SE_LOCK_MEMORY_PRIVILEGE, USER_MODE as u32) {
            return Ok(0xC000_0061);
        }
        let space = Space::of(target);
        let status = if lock { virtual_lock::lock(space, first, end, map_type) } else { virtual_lock::unlock(space, first, end, map_type) };
        if status & 0x8000_0000 == 0 && (guest::try_write::<u64>(base_pointer, first).is_err() || guest::try_write::<u64>(size_pointer, end - first).is_err()) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        Ok(status)
    })
}

fn nt_lock_virtual_memory(process: u64, base_pointer: u64, size_pointer: u64, map_type: u64, _user_rsp: u64) -> Result<u32, KernelError> {
    lock_or_unlock(process, base_pointer, size_pointer, map_type, true)
}

fn nt_unlock_virtual_memory(process: u64, base_pointer: u64, size_pointer: u64, map_type: u64, _user_rsp: u64) -> Result<u32, KernelError> {
    lock_or_unlock(process, base_pointer, size_pointer, map_type, false)
}

/// NtGetWriteWatch: `mm/write_watch`.
fn nt_get_write_watch(process: u64, flags: u64, base: u64, size: u64, user_rsp: u64) -> Result<u32, KernelError> {
    write_watch::nt_get_write_watch(process, flags, base, size, user_rsp)
}

/// NtResetWriteWatch: `mm/write_watch`.
fn nt_reset_write_watch(process: u64, base: u64, size: u64, _unused: u64, _user_rsp: u64) -> Result<u32, KernelError> {
    write_watch::nt_reset_write_watch(process, base, size)
}

/// Registra os handlers Nt*VirtualMemory e o NtCreatePagingFile.
pub fn init() {
    state::register_handler("NtLockVirtualMemory", nt_lock_virtual_memory);
    state::register_handler("NtUnlockVirtualMemory", nt_unlock_virtual_memory);
    state::register_handler("NtCreatePagingFile", nt_create_paging_file);
    state::register_handler("NtAllocateVirtualMemory", nt_allocate_virtual_memory);
    state::register_handler("NtAllocateVirtualMemoryEx", nt_allocate_virtual_memory_ex);
    state::register_handler("NtFreeVirtualMemory", nt_free_virtual_memory);
    state::register_handler("NtSetInformationVirtualMemory", nt_set_information_virtual_memory);
    state::register_handler("NtProtectVirtualMemory", nt_protect_virtual_memory);
    state::register_handler("NtQueryVirtualMemory", query);
    state::register_handler("NtReadVirtualMemory", nt_read_virtual_memory);
    state::register_handler("NtWriteVirtualMemory", nt_write_virtual_memory);
    state::register_handler("NtGetWriteWatch", nt_get_write_watch);
    state::register_handler("NtResetWriteWatch", nt_reset_write_watch);
}
