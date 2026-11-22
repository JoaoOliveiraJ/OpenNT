//! PEB e TEB de um processo de usuário.
//!
//! O papel do MmCreatePeb e do MmCreateTeb: as páginas saem do VAD do
//! processo em montagem, que é o corrente (a criação roda anexada a ele),
//! comprometidas de cima para baixo como o MiCreatePebOrTeb, e pertencem ao
//! processo até o término dele. A PEB recebe o que o loader da ntdll lê na
//! inicialização (LdrInitializeThunk): a imagem, o apiset, as tabelas NLS,
//! os parâmetros de heap, o prazo das seções críticas, a versão do sistema e
//! o subsistema da imagem. Os
//! offsets da PEB foram conferidos na ntdll 24H2 (NLS em +0xA0/+0xA8/+0xB0,
//! ApiSetMap em +0x68). PEB.Ldr nasce NULL: a ntdll publica a dela.
//!
//! Num processo WoW64 x86 a PEB de 32 bits vem do MiInitializeWowPeb
//! (19041 0x670754, chamado pelo MmCreatePeb): uma página própria abaixo do
//! limite de VA do processo, com a versão do sistema, os parâmetros de heap,
//! o prazo das seções críticas, o NtGlobalFlag, o MinimumStackCommit, a
//! sessão, o subsistema da imagem, a imagem, o Mutant e as tabelas NLS da
//! PEB nativa, e o EWOW64PROCESS.Peb aponta para ela. Os ponteiros dela são
//! de 32 bits: as vistas do NLS e do apiset que o MmCreatePeb e o
//! MmMapApiSetView mapeiam num processo WoW64 ficam abaixo do limite, e aqui
//! a PEB de 32 bits recebe cópias das cópias de sistema numa VA baixa
//! (`ps::wow64::system_dll::map_low_copy`). A TEB de uma thread WoW64 é a
//! do MmCreateTeb com a de 32 bits 0x2000 bytes depois (três páginas): a de
//! 32 bits recebe NT_TIB (ExceptionList -1, a pilha de 32 bits, Version
//! 0x1E00 e Self), ClientId e RealClientId, a PEB de 32 bits, TxFsContext
//! 0xFFFE, a StaticUnicodeString sobre o StaticUnicodeBuffer, o
//! DeallocationStack de 32 bits, o Vdm da nativa e, no GdiBatchCount, a TEB
//! nativa; TEB.WowTebOffset = 0x2000 e TEB32.WowTebOffset = -0x2000, e o
//! NtTib.ExceptionList da nativa aponta para a de 32 bits (o que o
//! LdrpInitializeProcess da ntdll nativa lê para ligar o UseWOW64).

use core::sync::atomic::{AtomicI64, Ordering};

use crate::ntos::cm::registry;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Eprocess, ImageDosHeader, ImageNtHeaders64, Peb, Peb32, Teb, Teb32};
use crate::ntos::ke::smp;
use crate::ntos::ps::user::{memory, state};
use crate::ntos::ps::{process, session};
use crate::rtl::KernelError;

/// Páginas da PEB: a estrutura e, logo depois dela na mesma página, o vetor
/// de heaps do processo.
const PEB_REGION: u64 = 0x1000;
/// Onde começa o vetor de heaps, dentro da página da PEB.
const PROCESS_HEAPS_OFFSET: u64 = 0x800;
/// A TEB x64 passa de uma página (TLS, FLS e SameTebFlags vão até +0x1838).
const TEB_REGION: u64 = 0x2000;
/// A TEB de uma thread WoW64: a nativa e a de 32 bits (uma página) depois.
pub const WOW64_TEB_REGION: u64 = TEB_REGION + 0x1000;
/// NT_TIB.Version (OS2_VERSION) e o TxFsContext inicial do MmCreateTeb.
const NT_TIB_VERSION: u32 = 0x1E00;
const TX_FS_CONTEXT: u32 = 0xFFFE;
/// O tamanho do StaticUnicodeBuffer (STATIC_UNICODE_BUFFER_LENGTH + 1
/// WCHARs).
const STATIC_UNICODE_MAXIMUM: u16 = 0x20A;

/// O `CriticalSectionTimeout` do Session Manager, em segundos: o padrão da
/// imagem em MmRegistryState+0x24 (0x278D00, 30 dias), que o CmControlVector
/// sobrepõe com até quatro bytes do valor.
const SESSION_MANAGER: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager";
const DEFAULT_CRITICAL_SECTION_TIMEOUT: u32 = 0x278D00;
/// MmCriticalSectionTimeout em 100 ns (negativo, relativo); 0 enquanto não
/// foi calculado.
static CRITICAL_SECTION_TIMEOUT: AtomicI64 = AtomicI64::new(0);

/// MmCriticalSectionTimeout (MiState+0x1560), que o MmCreatePeb copia para
/// PEB.CriticalSectionTimeout: os segundos do registro lidos como LONG vezes
/// -10.000.000 (o MiInitializeBootDefaults). A ntdll copia o valor para o
/// RtlpTimeout e desliga o prazo das seções críticas quando ele passa de uma
/// hora (RtlpTimeoutDisable); com 0, toda espera numa seção crítica disputada
/// voltava na hora com STATUS_TIMEOUT e o aviso "RTL: Enter CriticalSection
/// Timeout" no DbgPrint.
pub fn critical_section_timeout() -> i64 {
    let cached = CRITICAL_SECTION_TIMEOUT.load(Ordering::Acquire);
    if cached != 0 {
        return cached;
    }
    let mut seconds = DEFAULT_CRITICAL_SECTION_TIMEOUT.to_le_bytes();
    if let Some(value) = registry::read_value_by_path(SESSION_MANAGER, "CriticalSectionTimeout") {
        for (byte, &data) in seconds.iter_mut().zip(value.data.iter()) {
            *byte = data;
        }
    }
    let timeout = i32::from_le_bytes(seconds) as i64 * -10_000_000;
    CRITICAL_SECTION_TIMEOUT.store(timeout, Ordering::Release);
    timeout
}

/// A primeira thread (ou uma thread nova) do processo, como a TEB a descreve.
pub struct TebDescription {
    pub process_id: u64,
    pub thread_id: u64,
    pub peb: u64,
    /// Topo da pilha de usuário (NT_TIB.StackBase).
    pub stack_base: u64,
    /// A página comitada mais baixa da pilha (NT_TIB.StackLimit).
    pub stack_limit: u64,
    /// Base da reserva da pilha (DeallocationStack, o StackAllocationBase do
    /// INITIAL_TEB).
    pub deallocation_stack: u64,
    /// TEB.CurrentLocale (`ps::locale::thread_locale_of`).
    pub current_locale: u32,
    /// A TEB de 32 bits de uma thread de processo WoW64 x86.
    pub wow64: Option<Wow64Teb>,
}

/// O que a TEB de 32 bits recebe (o INITIAL_TEB de 32 bits do
/// PspWow64SetupUserStack e a PEB de 32 bits).
#[derive(Clone, Copy)]
pub struct Wow64Teb {
    pub peb32: u64,
    pub stack_base: u64,
    pub stack_limit: u64,
    pub deallocation_stack: u64,
}

/// Subsistema e versão do subsistema da imagem mapeada em `image_base`, lidos
/// dos cabeçalhos no processo corrente (cada passo sondado).
fn image_subsystem(image_base: u64) -> Result<(u32, u32, u32), KernelError> {
    let dos = state::user_struct::<ImageDosHeader>(image_base)?;
    let headers = state::user_struct::<ImageNtHeaders64>(image_base + dos.e_lfanew.probe_get()? as u32 as u64)?;
    let optional = &headers.optional_header;
    Ok((optional.subsystem.probe_get()? as u32, optional.major_subsystem_version.probe_get()? as u32, optional.minor_subsystem_version.probe_get()? as u32))
}

/// MmCreatePeb: a PEB do processo `process`, que tem de ser o corrente (a
/// criação anexada a ele), com a imagem principal já mapeada em `image_base`.
/// Publica a PEB em EPROCESS.Peb e a devolve. PEB.ProcessParameters fica para
/// quem grava os parâmetros (`ps::process_parameters`).
pub fn create_peb(process: u64, image_base: u64) -> Result<u64, KernelError> {
    if process == 0 || process != process::get_current_process() {
        return Err(KernelError::new("PEB fora do processo em montagem"));
    }
    let (subsystem, major, minor) = image_subsystem(image_base)?;
    let peb = memory::map_user_region(PEB_REGION)?;
    // SAFETY: a página acabou de ser comprometida no processo corrente e
    // nenhum código de usuário roda nele ainda.
    let block = unsafe { Peb::at(peb) };
    let (api_set_map, nls) = state::with(|state| (state.api_set_map_va, state.nls_vas.unwrap_or_default()));
    let processors = smp::online_cpu_count() as u64;
    block.being_debugged.set(0);
    block.image_base_address.set(image_base);
    block.ldr.set(0);
    block.api_set_map.set(api_set_map);
    block.ansi_code_page_data.set(nls.ansi);
    block.oem_code_page_data.set(nls.oem);
    block.unicode_case_table_data.set(nls.unicode);
    block.number_of_processors.set(processors as u32);
    block.critical_section_timeout.quad_part.set(critical_section_timeout());
    block.heap_segment_reserve.set(0x10_0000); // reserva do heap
    block.heap_segment_commit.set(0x2000); // commit inicial dos segmentos
    block.heap_de_commit_total_free_threshold.set(0x10000); // decommit total livre
    block.heap_de_commit_free_block_threshold.set(0x1000); // decommit de bloco livre
    // O vetor de heaps ocupa o resto da página da PEB.
    block.maximum_number_of_heaps.set(((PEB_REGION - PROCESS_HEAPS_OFFSET) / 8) as u32);
    block.process_heaps.set(peb + PROCESS_HEAPS_OFFSET);
    block.active_process_affinity_mask.set((1u64 << processors) - 1);
    block.os_major_version.set(10);
    block.os_minor_version.set(0);
    block.os_build_number.set(26100);
    block.os_platform_id.set(2); // VER_PLATFORM_WIN32_NT
    block.image_subsystem.set(subsystem);
    block.image_subsystem_major_version.set(major);
    block.image_subsystem_minor_version.set(minor);
    block.session_id.set(session::query(process));
    // As marcas do PspAllocateProcess no INITIAL_PEB: IsProtectedProcess
    // (PsIsProtectedProcess: Protection.Type != 0) e IsProtectedProcessLight
    // (Type == PsProtectedTypeProtectedLight).
    // SAFETY: o EPROCESS em montagem, retido pelo chamador.
    let protection = unsafe { Eprocess::at(process) }.protection.type_();
    block.set_is_protected_process(u8::from(protection != 0));
    block.set_is_protected_process_light(u8::from(protection == 1));
    // SAFETY: o EPROCESS em montagem, retido pelo chamador.
    unsafe { Eprocess::at(process) }.peb.set(peb);
    Ok(peb)
}

/// O MiInitializeWowPeb: a PEB de 32 bits do processo `process` (o
/// corrente, anexado), com a PEB nativa `peb` já montada. Publica a PEB em
/// EWOW64PROCESS.Peb e a devolve. O PEB32.ProcessParameters fica para o
/// PspWow64ThunkProcessParameters (`ps::wow64::process`).
pub fn create_wow64_peb(process: u64, peb: u64) -> Result<u64, KernelError> {
    let Some(wow64) = crate::ntos::ps::wow64::ewow64(process) else { return Err(KernelError::new("PEB de 32 bits num processo nativo")) };
    // As cópias baixas do apiset e do NLS (os ponteiros de 32 bits da PEB).
    let low = |name: &str, pointer: u64| -> Result<u32, KernelError> {
        if pointer == 0 {
            return Ok(0);
        }
        let pages = crate::ntos::ps::user::loader::system_template(name).ok_or_else(|| KernelError::new(alloc::format!("sem a copia de sistema {name}")))?;
        let (base, copy) = crate::ntos::ps::wow64::system_dll::map_low_copy(&pages.pages)?;
        Ok((pointer - base + copy) as u32)
    };
    // SAFETY: a PEB nativa montada agora no processo corrente.
    let native = unsafe { Peb::at(peb) };
    let api_set_map = low("apiset", native.api_set_map.get())?;
    let ansi = low("nls-ansi", native.ansi_code_page_data.get())?;
    let oem = low("nls-oem", native.oem_code_page_data.get())?;
    let unicode = low("nls-unicode", native.unicode_case_table_data.get())?;
    let peb32 = memory::map_user_region(Peb32::SIZE)?;
    // SAFETY: a página acabou de ser comprometida no processo corrente e
    // nenhum código de usuário roda nele ainda.
    let block = unsafe { Peb32::at(peb32) };
    block.inherited_address_space.set(native.inherited_address_space.get());
    block.bit_field.set(native.bit_field.get());
    block.mutant.set(native.mutant.get() as u32);
    block.image_base_address.set(native.image_base_address.get() as u32);
    block.api_set_map.set(api_set_map);
    block.ansi_code_page_data.set(ansi);
    block.oem_code_page_data.set(oem);
    block.unicode_case_table_data.set(unicode);
    block.number_of_processors.set(native.number_of_processors.get());
    block.nt_global_flag.set(native.nt_global_flag.get());
    block.nt_global_flag2.set(native.nt_global_flag2.get());
    block.critical_section_timeout.quad_part.set(native.critical_section_timeout.quad_part.get());
    block.heap_segment_reserve.set(native.heap_segment_reserve.get() as u32);
    block.heap_segment_commit.set(native.heap_segment_commit.get() as u32);
    block.heap_de_commit_total_free_threshold.set(native.heap_de_commit_total_free_threshold.get() as u32);
    block.heap_de_commit_free_block_threshold.set(native.heap_de_commit_free_block_threshold.get() as u32);
    block.minimum_stack_commit.set(native.minimum_stack_commit.get() as u32);
    block.os_major_version.set(native.os_major_version.get());
    block.os_minor_version.set(native.os_minor_version.get());
    block.os_build_number.set(native.os_build_number.get());
    block.oscsd_version.set(native.oscsd_version.get());
    block.os_platform_id.set(native.os_platform_id.get());
    block.image_subsystem.set(native.image_subsystem.get());
    block.image_subsystem_major_version.set(native.image_subsystem_major_version.get());
    block.image_subsystem_minor_version.set(native.image_subsystem_minor_version.get());
    block.session_id.set(native.session_id.get());
    block.leap_second_data.set(native.leap_second_data.get() as u32);
    block.leap_second_flags.set(native.leap_second_flags.get());
    wow64.peb.set(peb32);
    Ok(peb32)
}

/// Os campos da TEB de 32 bits (a terceira página de uma TEB WoW64), como o
/// MmCreateTeb os grava para uma thread x86.
fn initialize_teb32(teb: u64, thread: &TebDescription, wow64: &Wow64Teb) {
    let teb32 = teb + crate::ntos::ps::wow64::TEB32_OFFSET;
    // SAFETY: a TEB recém-comprometida (as três páginas) no processo
    // corrente; a thread ainda não roda.
    let (native, block) = unsafe { (Teb::at(teb), Teb32::at(teb32)) };
    block.nt_tib.exception_list.set(u32::MAX);
    block.nt_tib.stack_base.set(wow64.stack_base as u32);
    block.nt_tib.stack_limit.set(wow64.stack_limit as u32);
    block.nt_tib.version.set(NT_TIB_VERSION);
    block.nt_tib.self_.set(teb32 as u32);
    block.client_id.unique_process.set(thread.process_id as u32);
    block.client_id.unique_thread.set(thread.thread_id as u32);
    block.real_client_id.unique_process.set(thread.process_id as u32);
    block.real_client_id.unique_thread.set(thread.thread_id as u32);
    block.process_environment_block.set(wow64.peb32 as u32);
    block.tx_fs_context.set(TX_FS_CONTEXT);
    block.static_unicode_string.maximum_length.set(STATIC_UNICODE_MAXIMUM);
    block.static_unicode_string.buffer.set(block.static_unicode_buffer.as_ptr() as u32);
    block.deallocation_stack.set(wow64.deallocation_stack as u32);
    block.vdm.set(native.vdm.get() as u32);
    block.gdi_batch_count.set(teb as u32);
    block.current_locale.set(thread.current_locale);
    let offset = crate::ntos::ps::wow64::TEB32_OFFSET as i32;
    native.wow_teb_offset.set(offset);
    block.wow_teb_offset.set(-offset);
    native.nt_tib.exception_list.set(teb32);
}

/// Os campos da TEB que o kernel preenche numa TEB recém-comprometida:
/// NT_TIB (pilha e Self), ClientId, a PEB e a DeallocationStack; numa
/// thread WoW64, também a TEB de 32 bits.
pub fn initialize_teb(teb: u64, thread: &TebDescription) {
    // SAFETY: TEB recém-comprometida no processo corrente; a thread ainda
    // não roda.
    let block = unsafe { Teb::at(teb) };
    block.nt_tib.stack_base.set(thread.stack_base);
    block.nt_tib.stack_limit.set(thread.stack_limit);
    block.nt_tib.self_.set(teb);
    block.client_id.unique_process.set(thread.process_id);
    block.client_id.unique_thread.set(thread.thread_id);
    block.process_environment_block.set(thread.peb);
    block.deallocation_stack.set(thread.deallocation_stack);
    block.current_locale.set(thread.current_locale);
    if let Some(wow64) = &thread.wow64 {
        initialize_teb32(teb, thread, wow64);
    }
}

/// As páginas da TEB de uma thread: três numa thread WoW64 (a de 32 bits
/// depois da nativa), duas nas outras.
pub fn teb_region(thread: &TebDescription) -> u64 {
    if thread.wow64.is_some() { WOW64_TEB_REGION } else { TEB_REGION }
}

/// MmCreateTeb: a TEB de uma thread do processo corrente, na própria região
/// (nunca dividida com a PEB). Devolve a VA; KTHREAD.Teb fica com quem cria a
/// thread de usuário.
pub fn create_teb(thread: &TebDescription) -> Result<u64, KernelError> {
    let teb = memory::map_user_region(teb_region(thread))?;
    initialize_teb(teb, thread);
    Ok(teb)
}
