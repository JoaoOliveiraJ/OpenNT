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
//! as duplicatas compartilham o resto do objeto. Os campos do estado que
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
use crate::ntos::ob::close::{self, UserHandleTable};
use crate::ntos::ob::handle_table::HandleDescription;
use crate::ntos::ob::object_manager::ObjectData;
use crate::ntos::ob::handles::process::{self as process_handles, Binding};
use crate::ntos::ob::{callbacks, handle_ids};
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::eprocess;

/// 64 KiB de pilha de kernel para o ring 3.
pub const SYSCALL_STACK_PAGES: u64 = 16;
/// PML4[1], fora da identidade baixa.
pub const USER_STACK_TOP: u64 = 0x80_0000_0000;
pub const USER_STACK_SIZE: u64 = 0x10_0000;
/// O endereço real de usuário da KUSER_SHARED_DATA.
pub const KUSER_SHARED_DATA_USER_VA: u64 = 0x7FFE_0000;

/// Contrato com o retorno ao modo usuário: NtTerminateProcess devolve este
/// valor e grava o código de saída na célula; o retorno faz o salto de volta
/// ao executor em vez do sysretq.
pub const TERMINATE_MAGIC: u32 = 0x5452_4D49; // "TRMI"
pub const EXIT_CODE_CELL: u64 = 0x8_F078;
pub const USER_RSP_CELL_ADDR: u64 = 0x8_F060;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub const STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
pub const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
pub const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
pub const STATUS_HANDLE_NOT_CLOSABLE: u32 = 0xC000_0235;

/// 8 GiB: heap e regiões do processo.
pub const USER_ALLOC_BASE: u64 = 0x2_0000_0000;
/// Estruturas do processo (PML4[1], junto da pilha).
pub const USER_STRUCT_BASE: u64 = 0x7F_F000_0000;
/// Regiões compartilhadas entre processos (NLS, schemas); nunca reiniciam.
pub const USER_SHARED_BASE: u64 = 0x7F_F100_0000;

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

/// Listas de regiões do estado (`user_regions`, `process_images`,
/// `shared_user_regions`, `section_kernel_views`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionKind {
    User,
    ProcessImages,
    Shared,
    KernelViews,
    /// Lista temporária para processos fora de execução:
    /// a região não entra em lista alguma do estado.
    Detached,
}

/// Mesma região (identidade do objeto).
pub fn same_region(left: &Region, right: &Region) -> bool {
    Arc::as_ptr(left) as *const u8 == Arc::as_ptr(right) as *const u8
}

/// Estado global de modo usuário.
pub struct State {
    /// Regiões do processo, imagens mapeadas, mapeamentos NLS/schema
    /// permanentes e vistas de seção de kernel.
    pub user_regions: alloc::vec::Vec<Region>,
    pub process_images: alloc::vec::Vec<Region>,
    pub shared_user_regions: alloc::vec::Vec<Region>,
    pub section_kernel_views: alloc::vec::Vec<Region>,
    /// Sempre vazia (ver `RegionKind::Detached`).
    detached_regions: alloc::vec::Vec<Region>,
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
    pub next_user_handle: u32,
    pub next_user_alloc_va: u64,
    pub next_user_alloc_high: u64,
    pub next_struct_va: u64,
    pub next_shared_va: u64,
    /// Área de strings das entradas LDR (bump próprio).
    pub next_ldr_string_va: u64,
    pub ldr_string_region_end: u64,
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
    pub fn regions(&mut self, kind: RegionKind) -> &mut alloc::vec::Vec<Region> {
        match kind {
            RegionKind::User => &mut self.user_regions,
            RegionKind::ProcessImages => &mut self.process_images,
            RegionKind::Shared => &mut self.shared_user_regions,
            RegionKind::KernelViews => &mut self.section_kernel_views,
            RegionKind::Detached => &mut self.detached_regions,
        }
    }

    /// Remove a região da lista, se estiver nela.
    pub fn remove_region(&mut self, kind: RegionKind, region: &Region) {
        if kind == RegionKind::Detached {
            return;
        }
        let list = self.regions(kind);
        if let Some(index) = list.iter().position(|candidate| same_region(candidate, region)) {
            list.remove(index);
        }
    }

    const fn new() -> Self {
        Self {
            user_regions: alloc::vec::Vec::new(),
            process_images: alloc::vec::Vec::new(),
            shared_user_regions: alloc::vec::Vec::new(),
            section_kernel_views: alloc::vec::Vec::new(),
            detached_regions: alloc::vec::Vec::new(),
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
            next_user_handle: 0x100,
            next_user_alloc_va: USER_ALLOC_BASE,
            next_user_alloc_high: 0x7F_EFF0_0000,
            next_struct_va: USER_STRUCT_BASE,
            next_shared_va: USER_SHARED_BASE,
            next_ldr_string_va: 0,
            ldr_string_region_end: 0,
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

pub fn read_user_wide_string(buffer_va: u64, count: u64) -> String {
    let units: alloc::vec::Vec<u16> = (0..count).map(|index| guest::read16(buffer_va + index * 2)).collect();
    String::from_utf16_lossy(&units)
}

/// Grava o texto com NUL; devolve o comprimento em bytes sem o NUL.
pub fn write_user_wide(va: u64, text: &str) -> u64 {
    let mut count = 0u64;
    for unit in text.encode_utf16() {
        guest::write16(va + count * 2, unit);
        count += 1;
    }
    guest::write16(va + count * 2, 0);
    count * 2
}

/// UNICODE_STRING com MaximumLength incluindo o NUL.
pub fn write_unicode_string(struct_va: u64, buffer_va: u64, text: &str) {
    let bytes = text.encode_utf16().count() as u64 * 2;
    guest::write16(struct_va, bytes as u16);
    guest::write16(struct_va + 2, bytes as u16 + 2);
    guest::write32(struct_va + 4, 0);
    guest::write64(struct_va + 8, buffer_va);
}

/// Argumento de pilha do syscall (1-based, a partir do 5): o stub da ntdll
/// não ajusta a pilha; o chamador pôs o arg5 em [rsp+0x20] e o `call`
/// empurrou o retorno.
pub fn stack_arg(user_rsp: u64, index: u64) -> u64 {
    guest::read64(user_rsp + 0x28 + (index - 5) * 8)
}

pub fn stack_arg32(user_rsp: u64, index: u64) -> u32 {
    guest::read32(user_rsp + 0x28 + (index - 5) * 8)
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

/// ULONG_PTR opaco em duas palavras (os quatro primeiros vêm dos argumentos
/// brutos ou do frame salvo; os demais da pilha de usuário).
pub fn syscall_arg_words(user_rsp: u64, index: u64) -> [u32; 2] {
    const OFFSETS: [u64; 4] = [0x38, 0x10, 0x28, 0x30];
    let (raw, top) = {
        let state = S.lock();
        (state.service_raw_arguments, state.syscall_stack_top)
    };
    let address = if index <= 4 {
        if raw != 0 {
            raw + index * 8
        } else {
            top - 0x78 + OFFSETS[index as usize - 1]
        }
    } else {
        user_rsp + 0x28 + (index - 5) * 8
    };
    [guest::read32(address), guest::read32(address + 4)]
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

static HANDLES: SpinLock<BTreeMap<u32, Arc<UserHandle>>> = SpinLock::new(BTreeMap::new());
static NATIVE_BINDINGS: SpinLock<BTreeMap<u32, Binding>> = SpinLock::new(BTreeMap::new());

/// Abre um handle; processos e threads sem abertura nativa passam pelos
/// callbacks de objeto.
pub fn alloc_user_handle(object: Arc<dyn UserObject>, access: u32, attributes: u32) -> Result<u32, KernelError> {
    let entry = Arc::new(UserHandle {
        object,
        group: Arc::new(SpinLock::new(Group { handles: 1, references: 1 })),
        local: SpinLock::new(Local { access, attributes, wait_references: 0, on_references_released: None }),
    });
    alloc_entry(entry, false)
}

fn alloc_entry(entry: Arc<UserHandle>, duplicate: bool) -> Result<u32, KernelError> {
    let kind = entry.object.kind();
    if (kind == "process" || kind == "thread") && (!entry.object.opened_natively() || duplicate) {
        let mut data = entry.object.callback_data();
        data.access = Some(entry.access());
        let route_kind = if kind == "process" { "Process" } else { "Thread" };
        return callbacks::route(route_kind, &data, if duplicate { 2 } else { 1 }, true, &mut |access| {
            entry.set_access(access);
            insert_user_handle(&entry)
        });
    }
    insert_user_handle(&entry)
}

/// Fechamento pedido pela HANDLE_TABLE do processo.
fn close_from_table(_process: u64, handle: u32) {
    close::close_user(handle as u64, true);
}

/// Provedores de kernel e de usuário podem habitar a mesma tabela do
/// EPROCESS: os ids são únicos ali, incluindo o slot reservado de cada folha.
fn insert_user_handle(entry: &Arc<UserHandle>) -> Result<u32, KernelError> {
    let minimum = S.lock().next_user_handle;
    let handle = handle_ids::allocate(minimum)?;
    S.lock().next_user_handle = handle + 4;
    let retained = match entry.object.on_each_handle_open() {
        Ok(retained) => retained,
        Err(error) => return Err(error),
    };
    let published = match entry.object.native_body() {
        Some(body) => {
            let owner = entry.object.owner_process().unwrap_or_else(process::get_current_process);
            let description = HandleDescription { pointer: body.pointer, type_name: body.type_name.clone(), identity: body.record, native_body: body.record, attributes: entry.attributes(), access: entry.access() };
            process_handles::publish(
                owner,
                handle as u64,
                &description,
                close_from_table,
                Some(&mut |binding: &Binding| {
                    NATIVE_BINDINGS.lock().insert(handle, *binding);
                    HANDLES.lock().insert(handle, entry.clone());
                    Ok(())
                }),
            )
            .map(|_| ())
        }
        None => {
            HANDLES.lock().insert(handle, entry.clone());
            Ok(())
        }
    };
    if let Err(error) = published {
        NATIVE_BINDINGS.lock().remove(&handle);
        HANDLES.lock().remove(&handle);
        if retained {
            entry.object.on_each_handle_close();
        }
        return Err(error);
    }
    Ok(handle)
}

/// Os valores de todos os handles do processo.
/// Reinício da tabela por processo (os handles já foram fechados pela
/// liberação dos recursos).
pub fn clear_user_handles() {
    HANDLES.lock().clear();
}

pub fn user_handle_values() -> alloc::vec::Vec<u32> {
    HANDLES.lock().keys().copied().collect()
}

/// HANDLEs do processo são baixos.
pub fn get_user_handle(value: u64) -> Option<Arc<UserHandle>> {
    HANDLES.lock().get(&(value as u32)).cloned()
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
    alloc_entry(duplicate, true).inspect_err(|_| {
        let mut group = entry.group.lock();
        group.handles -= 1;
        group.references -= 1;
    })
}

/// Fecha o handle; `release` libera o objeto na última referência,
/// `force` ignora a proteção individual.
pub fn close_user_handle(value: u64, release: bool, force: bool) -> Result<u32, KernelError> {
    let handle = value as u32;
    let Some(entry) = HANDLES.lock().get(&handle).cloned() else { return Ok(STATUS_INVALID_HANDLE) };
    if !force && entry.attributes() & 1 != 0 {
        return Ok(STATUS_HANDLE_NOT_CLOSABLE);
    }
    let binding = NATIVE_BINDINGS.lock().get(&handle).copied();
    let last = Cell::new(false);
    let mut detach = || {
        HANDLES.lock().remove(&handle);
        NATIVE_BINDINGS.lock().remove(&handle);
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
    let Some(entry) = HANDLES.lock().get(&handle).cloned() else { return Ok(STATUS_INVALID_HANDLE) };
    let mut commit = || entry.local.lock().attributes = attributes;
    match NATIVE_BINDINGS.lock().get(&handle).copied() {
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

/// O processo corrente é o processo de usuário em execução.
fn owns(process: u64) -> bool {
    S.lock().current_process_id == guest::read64(process + eprocess::UNIQUE_PROCESS_ID)
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
    close::set_user_handle_table(UserHandleTable { owns, attributes: handle_attributes, close: table_close });
}
