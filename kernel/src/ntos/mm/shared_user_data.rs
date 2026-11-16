//! A página KUSER_SHARED_DATA e a página de referência do QPC.
//!
//! O Windows mapeia 0xFFFFF78000000000 em todo espaço de endereço; o kernel
//! atualiza SystemTime, InterruptTime e TickCount (o tick de `ke::clock`).
//! Drivers do WDK leem ali direto (KeQuerySystemTime/KeQueryTickCount são
//! macros inline). O modo usuário lê o mesmo frame pela visão de usuário em
//! 0x7FFE0000 (MM_SHARED_USER_DATA_VA), somente leitura e sem execução, que
//! cada espaço de endereçamento recebe por [`map_user_view_in`].
//!
//! A página de referência do TSC (o HalpTimerReferencePage do
//! HalpTimerCreateReferencePage 19041: TscSequence 'HalT', TscScale e
//! TscOffset zero) vai junto, no endereço de usuário que o
//! MiInitializeSharedUserData sorteia logo acima da KUSER_SHARED_DATA
//! ((0x7FFE0 + n) << 12, n de 1 a 15) e que o
//! NtQuerySystemInformation(SystemHypervisorSharedPageInformation) devolve:
//! é por ela que o RtlQueryPerformanceCounter da ntdll lê o QPC sem syscall.

use core::sync::atomic::{AtomicU64, Ordering};

use super::paging::{self, MapOptions};
use super::pfn;
use crate::hal::{cpu, kmalloc, physical};
use crate::ntos::cm::state_separation;
use crate::ntos::ke::{clock, processor_identity, smp};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{KsystemTime, KuserSharedData, NtProductType};

pub const SHARED_USER_DATA_VA: u64 = 0xFFFF_F780_0000_0000;
/// MM_SHARED_USER_DATA_VA: a visão de usuário da página, na mesma VA em todo
/// espaço de endereçamento.
pub const MM_SHARED_USER_DATA_VA: u64 = 0x7FFE_0000;
/// Célula lida pela atualização preemptiva no caminho nativo do timer.
const SHARED_FRAME_CELL: u64 = 0x81530;
/// SharedDataFlags.DbgStateSeparationEnabled.
const DBG_STATE_SEPARATION_ENABLED_SHIFT: u32 = 10;

static SHARED_FRAME: AtomicU64 = AtomicU64::new(0);
/// O frame da página de referência e a VA de usuário dela.
static REFERENCE_FRAME: AtomicU64 = AtomicU64::new(0);
static REFERENCE_USER_VA: AtomicU64 = AtomicU64::new(0);

pub fn frame() -> u64 {
    SHARED_FRAME.load(Ordering::Relaxed)
}

/// A KUSER_SHARED_DATA pelo frame, na VA do mapa direto.
fn shared(frame: u64) -> &'static KuserSharedData {
    // SAFETY: frame próprio da página compartilhada, alcançado pelo mapa
    // direto (que nunca é desfeito).
    unsafe { KuserSharedData::at(physical::range_to_virtual(frame, 0x1000)) }
}

/// A página publicada (`None` antes de [`init`]).
pub fn data() -> Option<&'static KuserSharedData> {
    let frame = frame();
    (frame != 0).then(|| shared(frame))
}

/// O HypervisorSharedUserVa: a VA de usuário da página de referência (zero
/// antes de [`init`]).
pub fn hypervisor_shared_user_va() -> u64 {
    REFERENCE_USER_VA.load(Ordering::Relaxed)
}

/// O frame da página de referência.
pub fn reference_frame() -> u64 {
    REFERENCE_FRAME.load(Ordering::Relaxed)
}

/// As páginas de usuário que todo espaço de endereçamento tem na mesma VA
/// (a KUSER_SHARED_DATA e a página de referência): nunca saem com a metade
/// de usuário de um processo.
pub fn shared_user_pages() -> [u64; 2] {
    [MM_SHARED_USER_DATA_VA, hypervisor_shared_user_va()]
}

/// A VA cai numa das páginas de [`shared_user_pages`].
pub fn is_shared_user_page(va: u64) -> bool {
    let page = va & !0xFFF;
    page == MM_SHARED_USER_DATA_VA || (page != 0 && page == hypervisor_shared_user_va())
}

/// A metade de usuário da raiz não tem nada mapeado além das páginas de
/// [`shared_user_pages`], e a KUSER_SHARED_DATA está lá.
pub fn only_shared_user_pages(root: u64) -> bool {
    let reference = hypervisor_shared_user_va();
    let mut pages = [MM_SHARED_USER_DATA_VA, if reference != 0 { reference } else { MM_SHARED_USER_DATA_VA }];
    pages.sort_unstable();
    let mut start = super::memory_map::LOWEST_USER_ADDRESS;
    for page in pages {
        if page > start && paging::find_mapping_in(root, start, page - start).is_some() {
            return false;
        }
        start = start.max(page + 0x1000);
    }
    root != 0 && paging::find_mapping_in(root, start, super::memory_map::USER_ADDRESS_LIMIT - start).is_none() && paging::translate_in(root, MM_SHARED_USER_DATA_VA) != 0
}

/// Mapeia as visões de usuário na raiz `root`: o frame da visão de kernel
/// em [`MM_SHARED_USER_DATA_VA`] e a página de referência na VA dela, as
/// duas acessíveis ao anel 3, somente leitura e sem execução. As folhas são
/// do espaço de endereçamento, não de uma região do VAD.
pub fn map_user_view_in(root: u64) -> bool {
    let frame = frame();
    let options = || MapOptions { nx: true, ..MapOptions::default() };
    let shared = frame != 0 && paging::map_page_in(root, MM_SHARED_USER_DATA_VA, frame, paging::PAGE_PRESENT | paging::PAGE_USER, options());
    let (reference, user_va) = (reference_frame(), hypervisor_shared_user_va());
    shared && (reference == 0 || paging::map_page_in(root, user_va, reference, paging::PAGE_PRESENT | paging::PAGE_USER, options()))
}

/// Leitura do KSYSTEM_TIME (High1Time, LowPart, High2Time, repetida
/// enquanto as metades altas diferem).
pub fn read_shared_time(time: &KsystemTime) -> u64 {
    clock::read_shared_time(time)
}

/// A página de referência do HalpTimerCreateReferencePage: TscSequence,
/// TscScale (10^7 × 2^64 / frequência do TSC) e TscOffset zero, e a VA de
/// usuário sorteada como o MiInitializeSharedUserData.
fn init_reference_page() -> bool {
    let frame = pfn::alloc_page();
    if frame == 0 {
        return false;
    }
    physical::zero(frame, 0x1000);
    physical::write32(frame, clock::REFERENCE_PAGE_SEQUENCE);
    physical::write64(frame + 8, clock::tsc_scale());
    physical::write64(frame + 0x10, 0);
    let random = cpu::hardware_random_u64().unwrap_or_else(|| cpu::rdtsc().rotate_left(13)) & 0xF;
    let slot = if random != 0 { random } else { 15 };
    REFERENCE_FRAME.store(frame, Ordering::Relaxed);
    REFERENCE_USER_VA.store((0x7FFE0 + slot) << 12, Ordering::Relaxed);
    true
}

pub fn init() -> bool {
    let frame = pfn::alloc_page();
    if frame == 0 {
        debug_print!("[mm] FALHA: sem frame p/ shared user data");
        return false;
    }
    physical::zero(frame, 0x1000);
    SHARED_FRAME.store(frame, Ordering::Relaxed);
    if !paging::map_page(SHARED_USER_DATA_VA, frame, paging::PAGE_PRESENT | paging::PAGE_RW, MapOptions::default()) {
        debug_print!("[mm] FALHA: map shared user data");
        return false;
    }
    physical::write32(SHARED_FRAME_CELL, frame as u32);
    if !init_reference_page() {
        debug_print!("[mm] FALHA: sem frame p/ a pagina de referencia do QPC");
        return false;
    }
    let data = shared(frame);
    // O Ldr da ntdll forma caminhos a partir de NtSystemRoot.
    for (character, unit) in data.nt_system_root.iter().zip("C:\\Windows".encode_utf16()) {
        character.set(unit);
    }
    // Versão compatível com o Windows 10 que o kernel implementa.
    data.nt_build_number.set(26100);
    data.nt_major_version.set(10);
    data.nt_minor_version.set(0);
    data.nt_product_type.set(NtProductType::NT_PRODUCT_WIN_NT);
    data.product_type_is_valid.set(1);
    data.native_processor_architecture.set(9); // PROCESSOR_ARCHITECTURE_AMD64
    // Nível e revisão do processador não fazem parte desta página no 19041
    // (vêm de SystemProcessorInformation); os recursos (PF_*) saem de
    // KeFeatureBits, como no KiInitializeKernel.
    processor_identity::publish_processor_features(data);
    data.suite_mask.set(0x110);
    data.number_of_physical_pages.set((kmalloc::ram_top() / 0x1000) as u32);
    data.active_processor_count.set(smp::online_cpu_count() as u32);
    data.active_group_count.set(1); // um grupo de processadores
    data.kd_debugger_enabled.set(0);
    data.safe_boot_mode.set(0); // boot normal
    // A ntdll consulta este bit pelo alias somente leitura em 0x7FFE0000.
    let separation = state_separation::is_enabled().unwrap_or(false) as u32;
    data.shared_data_flags.set(separation << DBG_STATE_SEPARATION_ENABLED_SHIFT);
    // QpcFrequency, os incrementos QPC, TickCountMultiplier, QpcBias, o
    // atalho do QPC em modo usuário e o primeiro tick.
    clock::publish_shared_constants(data);
    debug_print!("[mm] KUSER_SHARED_DATA mapeada (frame {:#x}); pagina de referencia do QPC em {:#x}", frame, hypervisor_shared_user_va());
    true
}

/// ActiveProcessorCount: os processadores online, atualizado quando um AP
/// sobe (o KiUpdateProcessorCount do NT).
pub fn update_active_processor_count() {
    if let Some(data) = data() {
        data.active_processor_count.set(smp::online_cpu_count() as u32);
    }
}

/// Chamado a cada volta do kernel: o tick do relógio (`ke::clock`).
pub fn update_system_times() {
    clock::update_shared_times();
}
