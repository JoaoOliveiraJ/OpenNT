//! Estado do subsistema de modo usuário.
//!
//! Constantes, o estado mutável único `S` visto por todos os módulos de
//! `ntos/ps/user`, a tabela de handles do processo e os auxiliares de leitura
//! e escrita de memória de usuário. Os módulos de área registram seus
//! handlers de syscall por nome; o despacho usa o mapa SSN→nome lido dos
//! stubs reais da ntdll carregada.
//!
//! Modelo: cada objeto de usuário é um `Arc<dyn UserObject>` (tipo, corpo
//! nativo, ganchos e estado próprio recuperado por downcast) e cada handle um
//! `Arc<UserHandle>` com acesso, atributos e referências de espera próprios;
//! as duplicatas compartilham o resto do objeto. A tabela de handles é por
//! processo (`ProcessState.handles`) e as operações sem processo explícito
//! agem sobre a do processo corrente, o anexado quando há attach, como o
//! ObReferenceObjectByHandle do NT. Os campos do estado que
//! pertencem a módulos ainda não implementados (regiões, threads, imagens e
//! módulos carregados) entram junto com eles.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use core::cell::Cell;

use crate::hal::physical;
use crate::ntos::mm::memory_map::USER_ADDRESS_LIMIT;
use crate::ntos::mm::paging;
use crate::ntos::ob::close;
use crate::ntos::ob::handle_table::HandleDescription;
use crate::ntos::ob::object_manager::ObjectData;
use crate::ntos::ob::handles::process::{self as process_handles, Binding};
use crate::ntos::ob::{callbacks, handle_ids};
use crate::ntos::ps::user::process_state::{self, ProcessState};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::status::STATUS_ACCESS_VIOLATION;
use crate::ntos::inc::types::{Field, IoStatusBlock, NtStruct, UnicodeString};

/// O ProbeForRead/ProbeForWrite de um endereço desalinhado.
pub const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;

/// 64 KiB de pilha de kernel para o ring 3.
pub const SYSCALL_STACK_PAGES: u64 = 16;
/// Pilha de usuário da primeira thread (VA escolhida pelo alocador).
pub const USER_STACK_SIZE: u64 = 0x10_0000;
/// O endereço real de usuário da KUSER_SHARED_DATA.
pub const KUSER_SHARED_DATA_USER_VA: u64 = crate::ntos::mm::shared_user_data::MM_SHARED_USER_DATA_VA;

/// Contrato com o retorno ao modo usuário: NtTerminateProcess devolve este
/// valor e grava o código de saída no bloco de execução da CPU; o retorno faz
/// o salto de volta ao executor em vez do sysretq.
pub const TERMINATE_MAGIC: u32 = 0x5452_4D49; // "TRMI"

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub const STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
pub const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
pub const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
pub const STATUS_HANDLE_NOT_CLOSABLE: u32 = 0xC000_0235;

/// Dados NLS reais mapeados.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NlsVas {
    pub ansi: u64,
    pub oem: u64,
    pub unicode: u64,
}

/// Pilha de argumentos sondada pelo despachante nativo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceStack {
    pub rsp: u64,
    pub bytes: u64,
}

/// Região do espaço de usuário (alocação privada, imagem ou vista de seção).
pub trait UserRegion: Send + Sync {
    fn base(&self) -> u64;
    fn size(&self) -> u64;
    fn as_any(&self) -> &dyn Any;
    /// Páginas confirmadas, quando a região as rastreia (vistas de seção).
    fn committed_pages(&self) -> Option<alloc::collections::BTreeSet<u64>> {
        None
    }
    /// Proteção própria da página.
    fn page_protect(&self, _index: u64) -> Option<u32> {
        None
    }
    fn protect(&self) -> u32 {
        0
    }
    fn allocation_protect(&self) -> u32 {
        0
    }
    /// Alocação privada inteiramente confirmada.
    fn committed(&self) -> bool {
        false
    }
    fn section(&self) -> Option<Arc<crate::ntos::ps::user::sections::Section>> {
        None
    }
    /// Nome nativo.
    fn name(&self) -> Option<alloc::string::String> {
        None
    }
    /// Frame da página (`frames`, `pages` ou `protected_frames`).
    fn frame(&self, _index: u64) -> Option<u64> {
        None
    }
    /// Registra a proteção e o frame de uma página reprotegida
    /// (`page_protects`/`protected_frames`); `false` = região sem esse registro.
    fn record_protect(&self, _index: u64, _protect: u32, _physical: u64) -> bool {
        false
    }
}

pub type Region = Arc<dyn UserRegion>;

/// Listas de regiões: `User` (alocações privadas e vistas de dados) e
/// `ProcessImages` no VAD do processo (`memory::Vad`); `Shared` e
/// `KernelViews` nas listas de sistema daqui (`shared_user_regions`,
/// `section_kernel_views`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionKind {
    User,
    ProcessImages,
    Shared,
    KernelViews,
    /// A região não entra em lista alguma (vista avulsa de teste).
    Detached,
}

/// Mesma região (identidade do objeto).
pub fn same_region(left: &Region, right: &Region) -> bool {
    Arc::as_ptr(left) as *const u8 == Arc::as_ptr(right) as *const u8
}

/// Estado global de modo usuário.
pub struct State {
    /// Mapeamentos NLS permanentes e vistas de seção de kernel, os mesmos em
    /// todo processo; as regiões de cada processo moram no VAD dele.
    pub shared_user_regions: alloc::vec::Vec<Region>,
    pub section_kernel_views: alloc::vec::Vec<Region>,
    /// SSN → nome (preenchido pelo loader a partir dos stubs reais).
    pub name_by_number: BTreeMap<u32, String>,
    /// Topo da pilha de syscall (o frame fica no topo).
    pub syscall_stack_top: u64,
    pub current_peb_va: u64,
    pub current_process_id: u64,
    pub current_process_cookie: u32,
    pub current_image_path: String,
    pub current_thread_hidden_from_debugger: bool,
    /// Diagnóstico: primeiras ocorrências.
    pub seen_syscalls: BTreeSet<String>,
    /// Exports da ntdll mapeada (nome → VA de usuário).
    pub ntdll_exports: Option<BTreeMap<String, u64>>,
    /// Base da imagem da ntdll mapeada.
    pub ntdll_image_base: u64,
    /// Imagens nativas mapeadas por NtMapViewOfSection (nome minúsculo →
    /// exports), registradas pela vista de imagem.
    pub mapped_image_exports: BTreeMap<String, BTreeMap<String, u64>>,
    /// PIDs no estilo NT (múltiplos de 4, depois do System).
    pub next_process_id: u64,
    pub nls_vas: Option<NlsVas>,
    /// Captura opcional de uma chamada de export nativo.
    pub capture_export: String,
    pub capture_limit: u32,
    pub instrumentation_callback: u64,
    /// Instantâneo diagnóstico da saída explícita do processo.
    pub termination_rsp: u64,
    /// O apiset schema real, mapeado como dado.
    pub api_set_map_va: u64,
    /// contrato → DLL hospedeira (minúsculas).
    pub api_set_hosts: Option<BTreeMap<String, String>>,
    /// A PEB_LDR_DATA do processo corrente.
    pub current_ldr_va: u64,
    pub service_stack: Option<ServiceStack>,
    pub service_raw_arguments: u64,
}

impl State {
    /// A lista de sistema do tipo (`Shared`, `KernelViews`); as demais ficam
    /// no VAD do processo (`memory::insert_region`).
    pub fn regions(&mut self, kind: RegionKind) -> Option<&mut alloc::vec::Vec<Region>> {
        match kind {
            RegionKind::Shared => Some(&mut self.shared_user_regions),
            RegionKind::KernelViews => Some(&mut self.section_kernel_views),
            RegionKind::User | RegionKind::ProcessImages | RegionKind::Detached => None,
        }
    }

    /// Remove a região da lista de sistema, se estiver nela.
    pub fn remove_region(&mut self, kind: RegionKind, region: &Region) {
        let Some(list) = self.regions(kind) else { return };
        if let Some(index) = list.iter().position(|candidate| same_region(candidate, region)) {
            list.remove(index);
        }
    }

    const fn new() -> Self {
        Self {
            shared_user_regions: alloc::vec::Vec::new(),
            section_kernel_views: alloc::vec::Vec::new(),
            name_by_number: BTreeMap::new(),
            syscall_stack_top: 0,
            current_peb_va: 0,
            current_process_id: 0,
            current_process_cookie: 0,
            current_image_path: String::new(),
            current_thread_hidden_from_debugger: false,
            seen_syscalls: BTreeSet::new(),
            ntdll_exports: None,
            mapped_image_exports: BTreeMap::new(),
            ntdll_image_base: 0,
            next_process_id: 300,
            nls_vas: None,
            capture_export: String::new(),
            capture_limit: 1,
            instrumentation_callback: 0,
            termination_rsp: 0,
            api_set_map_va: 0,
            api_set_hosts: None,
            current_ldr_va: 0,
            service_stack: None,
            service_raw_arguments: 0,
        }
    }
}

static S: SpinLock<State> = SpinLock::new(State::new());

/// Acesso ao estado; o lock não pode atravessar chamadas que voltem aqui.
pub fn with<R>(body: impl FnOnce(&mut State) -> R) -> R {
    body(&mut S.lock())
}

// ---- handlers de syscall por nome ----------------------------------------

/// (a1, a2, a3, a4, userRsp) → NTSTATUS.
pub type SyscallHandler = fn(u64, u64, u64, u64, u64) -> Result<u32, KernelError>;

static HANDLERS: SpinLock<BTreeMap<&'static str, SyscallHandler>> = SpinLock::new(BTreeMap::new());

/// Registro feito pelos módulos de área.
pub fn register_handler(name: &'static str, handler: SyscallHandler) {
    HANDLERS.lock().insert(name, handler);
}

pub fn handler(name: &str) -> Option<SyscallHandler> {
    HANDLERS.lock().get(name).copied()
}

// ---- memória de usuário (VA → físico pelas tabelas) ----------------------

/// Escreve numa VA de usuário traduzindo página a página.
pub fn write_user_bytes(va: u64, bytes: &[u8]) -> Result<(), KernelError> {
    let mut done = 0usize;
    while done < bytes.len() {
        let offset = va + done as u64;
        let physical_address = paging::translate(offset);
        if physical_address == 0 {
            return Err(KernelError::new(format!("writeUserBytes: VA nao mapeada 0x{offset:x}")));
        }
        let length = ((0x1000 - offset % 0x1000) as usize).min(bytes.len() - done);
        physical::write_bytes(physical_address, &bytes[done..done + length]);
        done += length;
    }
    Ok(())
}

/// `count` WCHARs de um buffer de usuário (já sondado pelo chamador), numa
/// cópia sondada: uma página desmapeada no meio devolve ACCESS_VIOLATION.
pub fn try_read_user_wide_string(buffer_va: u64, count: u64) -> Result<String, KernelError> {
    let bytes = guest::try_read_bytes(buffer_va, (count * 2) as usize)?;
    let units: alloc::vec::Vec<u16> = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    Ok(String::from_utf16_lossy(&units))
}

/// Como [`try_read_user_wide_string`]; uma falha de sonda devolve o texto vazio.
pub fn read_user_wide_string(buffer_va: u64, count: u64) -> String {
    try_read_user_wide_string(buffer_va, count).unwrap_or_default()
}

fn wide_with_nul(text: &str) -> alloc::vec::Vec<u8> {
    text.encode_utf16().chain(core::iter::once(0)).flat_map(u16::to_le_bytes).collect()
}

/// Grava o texto com NUL numa estrutura de usuário montada pelo kernel;
/// devolve o comprimento em bytes sem o NUL.
pub fn write_user_wide(va: u64, text: &str) -> u64 {
    let bytes = wide_with_nul(text);
    guest::write_bytes(va, &bytes);
    bytes.len() as u64 - 2
}

/// [`write_user_wide`] num buffer de usuário (cópia sondada).
pub fn try_write_user_wide(va: u64, text: &str) -> Result<u64, KernelError> {
    let bytes = wide_with_nul(text);
    guest::try_write_bytes(va, &bytes)?;
    Ok(bytes.len() as u64 - 2)
}

/// UNICODE_STRING com MaximumLength incluindo o NUL, numa estrutura de
/// usuário montada pelo kernel.
pub fn write_unicode_string(struct_va: u64, buffer_va: u64, text: &str) {
    let bytes = text.encode_utf16().count() as u16 * 2;
    // SAFETY: estrutura do processo criada e comprometida pelo próprio kernel.
    let string = unsafe { UnicodeString::at(struct_va) };
    string.length.set(bytes);
    string.maximum_length.set(bytes + 2);
    string.buffer.set(buffer_va);
}

/// [`write_unicode_string`] num buffer de usuário (escritas sondadas).
pub fn try_write_unicode_string(struct_va: u64, buffer_va: u64, text: &str) -> Result<(), KernelError> {
    let bytes = text.encode_utf16().count() as u16 * 2;
    let string = UnicodeString::try_at(struct_va)?;
    string.length.probe_set(bytes)?;
    string.maximum_length.probe_set(bytes + 2)?;
    string.buffer.probe_set(buffer_va)
}

/// IO_STATUS_BLOCK de modo usuário: Status estendido aos 64 bits do slot
/// (Status/Pointer), como a cópia da estrutura na conclusão, e Information.
pub fn set_user_iosb(iosb: u64, status: u32, information: u64) -> Result<(), KernelError> {
    let block = IoStatusBlock::try_at(iosb)?;
    block.pointer.probe_set(status as u64)?;
    block.information.probe_set(information)
}

/// Estrutura de modo usuário cuja faixa útil o chamador já sondou com
/// `probe_user_read`/`probe_user_write` (classes de informação de tamanho
/// variável cabem num prefixo do tipo): aqui só nulo e alinhamento, como no
/// ProbeForWrite do NT. Cada acesso segue sondado (`probe_get`/`probe_set`).
pub fn user_struct<T: NtStruct>(address: u64) -> Result<&'static T, KernelError> {
    if address == 0 {
        return Err(guest::address_fault(address));
    }
    if address % core::mem::align_of::<T>() as u64 != 0 {
        return Err(KernelError::with_status(format!("datatype misalignment at {address:#x}"), STATUS_DATATYPE_MISALIGNMENT));
    }
    // SAFETY: não nulo e alinhado; a faixa foi sondada pelo chamador e os
    // acessos seguintes são sondados de novo.
    Ok(unsafe { T::at(address) })
}

/// Falha de sonda: o `__except` do NT em volta dos acessos a memória de
/// usuário devolve o código da exceção ao chamador.
pub fn probe_fault(error: &KernelError) -> bool {
    matches!(error.status, STATUS_ACCESS_VIOLATION | STATUS_DATATYPE_MISALIGNMENT)
}

/// Corpo de serviço com acessos sondados: ACCESS_VIOLATION e
/// DATATYPE_MISALIGNMENT viram o status devolvido; os demais erros sobem.
pub fn guarded(body: impl FnOnce() -> Result<u32, KernelError>) -> Result<u32, KernelError> {
    match body() {
        Err(error) if probe_fault(&error) => Ok(error.status),
        other => other,
    }
}

/// Argumento de pilha do syscall (1-based, a partir do 5): o stub da ntdll
/// não ajusta a pilha; o chamador pôs o arg5 em [rsp+0x20] e o `call`
/// empurrou o retorno. O despachante sonda a área de argumentos; uma pilha
/// desmapeada lê zero, nunca uma falha de kernel.
pub fn stack_arg(user_rsp: u64, index: u64) -> u64 {
    guest::try_read::<u64>(user_rsp + 0x28 + (index - 5) * 8).unwrap_or(0)
}

pub fn stack_arg32(user_rsp: u64, index: u64) -> u32 {
    guest::try_read::<u32>(user_rsp + 0x28 + (index - 5) * 8).unwrap_or(0)
}

/// O despachante nativo sonda a pilha antes de copiá-la; os handlers
/// validam aqui a extensão de argumentos de que precisam.
pub fn probe_syscall_stack(rsp: u64, bytes: u64) -> bool {
    let captured = S.lock().service_stack;
    if let Some(captured) = captured.filter(|captured| captured.rsp == rsp) {
        return bytes <= captured.bytes;
    }
    probe_user_read(rsp + 0x28, bytes)
}

/// Frame que o stub de syscall da HAL de modo usuário salva no topo da pilha
/// de syscall (layout do OpenNT, não do NT): os registradores devolvidos ao
/// anel 3 no retorno; R10/RDX/R8/R9 são também os quatro primeiros argumentos.
#[repr(C)]
pub struct SyscallFrame {
    pub rax: Field<u64>,
    pub rip: Field<u64>,
    pub rdx: Field<u64>,
    pub rsi: Field<u64>,
    pub rdi: Field<u64>,
    pub r8: Field<u64>,
    pub r9: Field<u64>,
    pub r10: Field<u64>,
    pub rflags: Field<u64>,
    pub rbx: Field<u64>,
    pub rbp: Field<u64>,
    pub r12: Field<u64>,
    pub r13: Field<u64>,
    pub r14: Field<u64>,
    pub r15: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for SyscallFrame {}

const _: () = assert!(core::mem::size_of::<SyscallFrame>() == 0x78);

/// O frame do syscall corrente, logo abaixo do topo da pilha de syscall.
pub fn syscall_frame() -> &'static SyscallFrame {
    let top = S.lock().syscall_stack_top;
    // SAFETY: a pilha de syscall é do kernel e o stub sempre salva o frame.
    unsafe { SyscallFrame::at(top - SyscallFrame::SIZE) }
}

/// ULONG_PTR opaco em duas palavras (os quatro primeiros vêm dos argumentos
/// brutos ou do frame salvo; os demais da pilha de usuário).
pub fn syscall_arg_words(user_rsp: u64, index: u64) -> [u32; 2] {
    let raw = S.lock().service_raw_arguments;
    // Uma carga de qword: o argumento nunca é observado pela metade.
    let value = if index <= 4 {
        // Vetor bruto do despacho ou frame do syscall: memória do kernel.
        if raw != 0 {
            guest::read::<u64>(raw + index * 8)
        } else {
            let frame = syscall_frame();
            [&frame.r10, &frame.rdx, &frame.r8, &frame.r9][index as usize - 1].get()
        }
    } else {
        guest::try_read::<u64>(user_rsp + 0x28 + (index - 5) * 8).unwrap_or(0)
    };
    [value as u32, (value >> 32) as u32]
}

/// Falha de página de seção (`ps/user/sections.fault`), instalada pelo
/// módulo de seções.
static SECTION_FAULT: SpinLock<Option<fn(u64, u32) -> bool>> = SpinLock::new(None);

pub fn set_section_fault(fault: fn(u64, u32) -> bool) {
    *SECTION_FAULT.lock() = Some(fault);
}

/// ProbeForRead/Write: o kernel só toca buffer de usuário mapeado; fora
/// disso a resposta é ACCESS_VIOLATION, nunca uma exceção no handler. Uma
/// sonda de escrita primeiro materializa a página privada de uma seção (as
/// escritas do kernel usam o alias físico e não geram #PF).
fn probe_user_access(va: u64, size: u64, write: bool) -> bool {
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
    let first = va & !0xFFF;
    let last = (va + size - 1) & !0xFFF;
    let required = paging::PAGE_PRESENT | paging::PAGE_USER | if write { paging::PAGE_RW } else { 0 };
    let mut page = first;
    while page <= last {
        if paging::access_flags(page) & required != required {
            let fault = *SECTION_FAULT.lock();
            if !write || !fault.is_some_and(|fault| fault(page, 7)) || paging::access_flags(page) & required != required {
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

// ---- tabela de handles do processo ---------------------------------------

/// Corpo nativo de um objeto.
#[derive(Clone)]
pub struct NativeBody {
    pub pointer: u64,
    pub type_name: String,
    /// Identidade publicada na HANDLE_TABLE.
    pub record: u64,
    pub reference: Arc<dyn Fn() + Send + Sync>,
    pub dereference: Arc<dyn Fn() + Send + Sync>,
}

/// Objeto de usuário: os objetos vivem no kernel; o usuário só vê HANDLEs
/// opacos.
pub trait UserObject: Send + Sync {
    /// Tipo do objeto.
    fn kind(&self) -> &'static str;
    fn native_body(&self) -> Option<NativeBody> {
        None
    }
    /// A abertura por ponteiro já passou pelos callbacks.
    fn opened_natively(&self) -> bool {
        false
    }
    fn owner_process(&self) -> Option<u64> {
        None
    }
    /// Dados entregues aos callbacks de processo e thread.
    fn callback_data(&self) -> ObjectData {
        ObjectData { native_pointer: self.native_body().map_or(0, |body| body.pointer), ..ObjectData::default() }
    }
    /// A cada handle aberto; `Ok(true)` quando o gancho existe e reteve algo.
    fn on_each_handle_open(&self) -> Result<bool, KernelError> {
        Ok(false)
    }
    fn on_each_handle_close(&self) {}
    /// O último handle da descrição foi fechado.
    fn on_handle_closed(&self) {}
    /// Liberação no NtClose (chave, dispositivo ou `close`).
    fn release(&self) {}
    /// Caminho usado como raiz de OBJECT_ATTRIBUTES (chave, diretório ou
    /// diretório aberto como arquivo).
    fn object_path(&self) -> Option<alloc::string::String> {
        None
    }
    /// Seção de um handle de seção do processo.
    fn section(&self) -> Option<Arc<crate::ntos::ps::user::sections::Section>> {
        None
    }
    /// Nó do namespace de um diretório de objetos aberto pelo processo.
    fn namespace_node(&self) -> Option<crate::ntos::ob::object_manager::NodeId> {
        None
    }
    /// Objeto esperável (o ponteiro das esperas Nt).
    fn wait_pointer(&self) -> Option<u64> {
        None
    }
    /// Política do objeto.
    fn security(&self) -> Option<crate::ntos::se::model::SecurityPolicy> {
        None
    }
    fn as_any(&self) -> &dyn Any;
}

struct Group {
    handles: u32,
    references: u32,
}

struct Local {
    access: u32,
    attributes: u32,
    wait_references: u32,
    on_references_released: Option<Box<dyn FnOnce() + Send>>,
}

/// Um handle: a descrição aberta compartilhada (posição, cursor, estado do
/// dispositivo ou seção) e o acesso/atributos/referências deste handle.
pub struct UserHandle {
    pub object: Arc<dyn UserObject>,
    group: Arc<SpinLock<Group>>,
    local: SpinLock<Local>,
}

impl UserHandle {
    pub fn kind(&self) -> &'static str {
        self.object.kind()
    }

    pub fn access(&self) -> u32 {
        self.local.lock().access
    }

    pub fn set_access(&self, access: u32) {
        self.local.lock().access = access;
    }

    pub fn attributes(&self) -> u32 {
        self.local.lock().attributes
    }

    pub fn wait_references(&self) -> u32 {
        self.local.lock().wait_references
    }

    pub fn downcast<T: 'static>(&self) -> Option<&T> {
        self.object.as_any().downcast_ref::<T>()
    }
}

/// A tabela de handles de usuário de um processo (`ProcessState.handles`),
/// o papel da ObjectTable do NT para os objetos do runtime: o handle, o
/// vínculo com a linha publicada na HANDLE_TABLE nativa do mesmo processo e o
/// piso dos valores novos. Os valores vêm do espaço global de `handle_ids`,
/// então um valor nunca existe em duas tabelas.
pub struct UserHandleTable {
    entries: BTreeMap<u32, Arc<UserHandle>>,
    bindings: BTreeMap<u32, Binding>,
    floor: u32,
}

impl UserHandleTable {
    pub const fn new() -> Self {
        Self { entries: BTreeMap::new(), bindings: BTreeMap::new(), floor: 0x100 }
    }
}

/// STATUS_PROCESS_IS_TERMINATING: o processo corrente já passou pelo
/// término e não tem mais tabela.
fn table_closed() -> KernelError {
    KernelError::with_status("process handle table is closing", 0xC000_010A)
}

/// Abre um handle na tabela do processo corrente (o anexado, quando há
/// attach); processos e threads sem abertura nativa passam pelos callbacks
/// de objeto.
pub fn alloc_user_handle(object: Arc<dyn UserObject>, access: u32, attributes: u32) -> Result<u32, KernelError> {
    let table = process_state::current().ok_or_else(table_closed)?;
    let entry = Arc::new(UserHandle {
        object,
        group: Arc::new(SpinLock::new(Group { handles: 1, references: 1 })),
        local: SpinLock::new(Local { access, attributes, wait_references: 0, on_references_released: None }),
    });
    alloc_entry(&table, entry, false)
}

fn alloc_entry(table: &ProcessState, entry: Arc<UserHandle>, duplicate: bool) -> Result<u32, KernelError> {
    let kind = entry.object.kind();
    if (kind == "process" || kind == "thread") && (!entry.object.opened_natively() || duplicate) {
        let mut data = entry.object.callback_data();
        data.access = Some(entry.access());
        let route_kind = if kind == "process" { "Process" } else { "Thread" };
        return callbacks::route(route_kind, &data, if duplicate { 2 } else { 1 }, true, &mut |access| {
            entry.set_access(access);
            insert_user_handle(table, &entry)
        });
    }
    insert_user_handle(table, &entry)
}

/// Fechamento pedido pela HANDLE_TABLE do processo dono, que pode não ser o
/// corrente (o rundown de handles no término).
fn close_from_table(process: u64, handle: u32) {
    if let Some(table) = process_state::get(process) {
        let _ = close_user_handle_in(&table, handle as u64, true, true);
    }
}

/// Provedores de kernel e de usuário podem habitar a mesma tabela do
/// EPROCESS: os ids são únicos ali, incluindo o slot reservado de cada folha.
/// A linha nativa vai para a HANDLE_TABLE do processo dono da tabela.
fn insert_user_handle(table: &ProcessState, entry: &Arc<UserHandle>) -> Result<u32, KernelError> {
    let minimum = table.handles.lock().floor;
    let handle = handle_ids::allocate(minimum)?;
    table.handles.lock().floor = handle + 4;
    let retained = match entry.object.on_each_handle_open() {
        Ok(retained) => retained,
        Err(error) => return Err(error),
    };
    let published = match entry.object.native_body() {
        Some(body) => {
            let description = HandleDescription { pointer: body.pointer, type_name: body.type_name.clone(), identity: body.record, native_body: body.record, attributes: entry.attributes(), access: entry.access() };
            process_handles::publish(
                table.process,
                handle as u64,
                &description,
                close_from_table,
                Some(&mut |binding: &Binding| {
                    let mut handles = table.handles.lock();
                    handles.bindings.insert(handle, *binding);
                    handles.entries.insert(handle, entry.clone());
                    Ok(())
                }),
            )
            .map(|_| ())
        }
        None => {
            table.handles.lock().entries.insert(handle, entry.clone());
            Ok(())
        }
    };
    if let Err(error) = published {
        {
            let mut handles = table.handles.lock();
            handles.bindings.remove(&handle);
            handles.entries.remove(&handle);
        }
        if retained {
            entry.object.on_each_handle_close();
        }
        return Err(error);
    }
    Ok(handle)
}

/// Os valores de todos os handles do processo corrente.
pub fn user_handle_values() -> alloc::vec::Vec<u32> {
    process_state::current().map(|table| table.handles.lock().entries.keys().copied().collect()).unwrap_or_default()
}

/// Os handles de usuário de todos os processos (a contagem de handles de um
/// objeto é global, como o HandleCount do OBJECT_HEADER).
pub fn all_user_handles() -> alloc::vec::Vec<Arc<UserHandle>> {
    process_state::all().iter().flat_map(|table| table.handles.lock().entries.values().cloned().collect::<alloc::vec::Vec<_>>()).collect()
}

/// HANDLEs do processo corrente são baixos.
pub fn get_user_handle(value: u64) -> Option<Arc<UserHandle>> {
    process_state::current().and_then(|table| table.handles.lock().entries.get(&(value as u32)).cloned())
}

/// O rundown da tabela de um processo que terminou: fecha o que a drenagem
/// da HANDLE_TABLE nativa não fechou (handles sem linha nativa), como o
/// ExSweepHandleTable do ObKillProcess.
pub fn sweep_user_handles(table: &ProcessState) {
    loop {
        let next = table.handles.lock().entries.keys().next().copied();
        let Some(handle) = next else { break };
        if !matches!(close_user_handle_in(table, handle as u64, true, true), Ok(0)) {
            table.handles.lock().entries.remove(&handle);
        }
    }
}

/// A descrição aberta compartilhada.
pub fn user_handle_object(entry: &UserHandle) -> Arc<dyn UserObject> {
    entry.object.clone()
}

/// Dois handles da mesma descrição aberta.
pub fn same_object(left: &UserHandle, right: &UserHandle) -> bool {
    Arc::as_ptr(&left.object) as *const u8 == Arc::as_ptr(&right.object) as *const u8
}

/// Duplica com acesso e atributos próprios; posição, cursor e estado do
/// objeto continuam compartilhados. Esperas de kernel podem sobreviver ao
/// último handle.
pub fn duplicate_user_handle(entry: &UserHandle, access: u32, attributes: u32) -> Result<u32, KernelError> {
    {
        let mut group = entry.group.lock();
        group.handles += 1;
        group.references += 1;
    }
    let duplicate = Arc::new(UserHandle {
        object: entry.object.clone(),
        group: entry.group.clone(),
        local: SpinLock::new(Local { access, attributes, wait_references: 0, on_references_released: None }),
    });
    let target = process_state::current().ok_or_else(table_closed);
    target.and_then(|table| alloc_entry(&table, duplicate, true)).inspect_err(|_| {
        let mut group = entry.group.lock();
        group.handles -= 1;
        group.references -= 1;
    })
}

/// Fecha o handle do processo corrente; `release` libera o objeto na última
/// referência, `force` ignora a proteção individual.
pub fn close_user_handle(value: u64, release: bool, force: bool) -> Result<u32, KernelError> {
    match process_state::current() {
        Some(table) => close_user_handle_in(&table, value, release, force),
        None => Ok(STATUS_INVALID_HANDLE),
    }
}

/// [`close_user_handle`] na tabela de `table`.
pub fn close_user_handle_in(table: &ProcessState, value: u64, release: bool, force: bool) -> Result<u32, KernelError> {
    let handle = value as u32;
    let Some(entry) = table.handles.lock().entries.get(&handle).cloned() else { return Ok(STATUS_INVALID_HANDLE) };
    if !force && entry.attributes() & 1 != 0 {
        return Ok(STATUS_HANDLE_NOT_CLOSABLE);
    }
    let binding = table.handles.lock().bindings.get(&handle).copied();
    let last = Cell::new(false);
    let mut detach = || {
        {
            let mut handles = table.handles.lock();
            handles.entries.remove(&handle);
            handles.bindings.remove(&handle);
        }
        let mut group = entry.group.lock();
        group.handles -= 1;
        last.set(group.handles == 0);
    };
    match binding {
        Some(binding) => {
            if !process_handles::remove(&binding, Some(&mut detach))? {
                return Ok(STATUS_INVALID_HANDLE);
            }
        }
        None => detach(),
    }
    entry.object.on_each_handle_close();
    if last.get() {
        entry.object.on_handle_closed();
    }
    let owner = entry.clone();
    let finish = move || {
        let released = {
            let mut group = owner.group.lock();
            group.references -= 1;
            group.references == 0
        };
        if released && release {
            owner.object.release();
        }
    };
    let mut local = entry.local.lock();
    if local.wait_references != 0 {
        local.on_references_released = Some(Box::new(finish));
    } else {
        drop(local);
        finish();
    }
    Ok(0)
}

pub fn change_user_handle_attributes(handle: u64, attributes: u32) -> Result<u32, KernelError> {
    let handle = handle as u32;
    let Some(table) = process_state::current() else { return Ok(STATUS_INVALID_HANDLE) };
    let Some(entry) = table.handles.lock().entries.get(&handle).cloned() else { return Ok(STATUS_INVALID_HANDLE) };
    let mut commit = || entry.local.lock().attributes = attributes;
    let binding = table.handles.lock().bindings.get(&handle).copied();
    match binding {
        Some(binding) => {
            if !process_handles::change(&binding, attributes, entry.access(), Some(&mut commit))? {
                return Ok(STATUS_INVALID_HANDLE);
            }
        }
        None => commit(),
    }
    Ok(0)
}

/// Referências nativas por handle somem no fechamento: uma espera em curso
/// retém o corpo por conta própria, mesmo depois do último handle.
pub fn retain_user_handle_reference(entry: &UserHandle) {
    if let Some(body) = entry.object.native_body() {
        (body.reference)();
    }
    entry.local.lock().wait_references += 1;
}

pub fn release_user_handle_reference(entry: &UserHandle) -> Result<(), KernelError> {
    let close = {
        let mut local = entry.local.lock();
        if local.wait_references == 0 {
            return Err(KernelError::new("Unbalanced user handle reference"));
        }
        local.wait_references -= 1;
        if local.wait_references == 0 {
            local.on_references_released.take()
        } else {
            None
        }
    };
    if let Some(close) = close {
        close();
    }
    if let Some(body) = entry.object.native_body() {
        (body.dereference)();
    }
    Ok(())
}

// ---- provedor do NtClose -------------------------------------------------

/// Todo processo vivo (o System inclusive) tem a sua tabela.
fn owns(process: u64) -> bool {
    process_state::get(process).is_some()
}

fn handle_attributes(handle: u64) -> Option<u32> {
    get_user_handle(handle).map(|entry| entry.attributes())
}

/// Uma falha interna devolve o status dela (ou STATUS_UNSUCCESSFUL).
fn table_close(handle: u64, force: bool) -> u32 {
    close_user_handle(handle, true, force).unwrap_or_else(|error| if error.status != 0 { error.status } else { 0xC000_0001 })
}

/// Instala a tabela de usuário como dona dos handles baixos no NtClose.
pub fn init() {
    close::set_user_handle_table(close::UserHandleTable { owns, attributes: handle_attributes, close: table_close });
}
