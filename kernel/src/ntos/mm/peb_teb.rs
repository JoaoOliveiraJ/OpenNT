//! PEB e TEB de um processo de usuário.
//!
//! O papel do MmCreatePeb e do MmCreateTeb: as páginas saem do VAD do
//! processo em montagem, que é o corrente (a criação roda anexada a ele),
//! comprometidas de cima para baixo como o MiCreatePebOrTeb, e pertencem ao
//! processo até o término dele. A PEB recebe o que o loader da ntdll lê na
//! inicialização (LdrInitializeThunk): a imagem, o apiset, as tabelas NLS,
//! os parâmetros de heap, a versão do sistema e o subsistema da imagem. Os
//! offsets da PEB foram conferidos na ntdll 24H2 (NLS em +0xA0/+0xA8/+0xB0,
//! ApiSetMap em +0x68). PEB.Ldr nasce NULL: a ntdll publica a dela.

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Eprocess, ImageDosHeader, ImageNtHeaders64, Peb, Teb};
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

/// A primeira thread (ou uma thread nova) do processo, como a TEB a descreve.
pub struct TebDescription {
    pub process_id: u64,
    pub thread_id: u64,
    pub peb: u64,
    /// Topo da pilha de usuário (NT_TIB.StackBase).
    pub stack_base: u64,
    /// Base da reserva da pilha (NT_TIB.StackLimit e DeallocationStack).
    pub stack_limit: u64,
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

/// Os campos da TEB que o kernel preenche numa TEB recém-comprometida:
/// NT_TIB (pilha e Self), ClientId, a PEB e a DeallocationStack.
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
    block.deallocation_stack.set(thread.stack_limit);
}

/// MmCreateTeb: a TEB de uma thread do processo corrente, na própria região
/// (nunca dividida com a PEB). Devolve a VA; KTHREAD.Teb fica com quem cria a
/// thread de usuário.
pub fn create_teb(thread: &TebDescription) -> Result<u64, KernelError> {
    let teb = memory::map_user_region(TEB_REGION)?;
    initialize_teb(teb, thread);
    Ok(teb)
}
