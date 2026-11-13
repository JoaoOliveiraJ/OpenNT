//! ObOpenObjectByPointer / ObReferenceObjectByHandle / ObCloseHandle.
//!
//! `describe` identifica o dono do corpo, na ordem do original (processo,
//! thread, token, callback, driver, seção, arquivo, dispatcher, namespace,
//! silo), e entrega suas operações reais de retenção, liberação e handle.
//! Os donos ainda não transcritos registram seu slot quando chegam.
//!
//! O caminho da tabela de handles de usuário (`ps/user/state`) entra na
//! fase 7; até lá toda abertura segue pelo Object Manager.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::callbacks::{self, Outcome, PerformOptions};
use super::object_manager::{self, NativeOpen, ObjectData, ObjectHooks};
use super::object_types::{self, ObjectType};
use crate::ntos::ob::objects::namespace as namespace_objects;
use super::object_access;
use crate::ntos::ke::irql;
use crate::ntos::ps::process;
use crate::ntos::se::model::SecurityPolicy;
use crate::ntos::se::token::{thread as thread_tokens, tokens};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

/// Operações de um dono de corpos nativos.
/// Metadados de ZwQueryObject vindos do registro do dono (`item.record`).
/// `handles: None` faz a consulta contar os handles das tabelas.
#[derive(Clone, Debug, Default)]
pub struct QueryRecord {
    pub handles: Option<u32>,
    pub references: u32,
    pub permanent: bool,
    pub name: alloc::string::String,
}

/// Caminho do nó do namespace cujo corpo é `pointer` (`namespaceNode`).
pub fn namespace_path_of(pointer: u64) -> Option<alloc::string::String> {
    if pointer == 0 {
        return None;
    }
    object_manager::namespace_entries().into_iter().find(|(node, _)| object_manager::node(*node).and_then(|node| node.data).is_some_and(|data| data.native_pointer == pointer)).map(|(_, path)| path)
}

pub trait ObjectOwner: Send + Sync {
    fn object_type(&self, pointer: u64) -> ObjectType;
    fn reference(&self, pointer: u64);
    fn dereference(&self, pointer: u64);
    /// Abertura própria de handle (`item.open`); `None` = referência + conta.
    fn open_handle(&self, _pointer: u64) -> Option<Result<(), KernelError>> {
        None
    }
    fn close_handle(&self, _pointer: u64) -> Option<Result<(), KernelError>> {
        None
    }
    /// Segurança capturada na criação do corpo.
    fn security(&self, pointer: u64) -> SecurityPolicy;
    /// Processo dono de um objeto exclusivo (0 = compartilhado).
    fn exclusive_process(&self, _pointer: u64) -> u64 {
        0
    }
    /// Arquivo aberto, não limpo e não fechando.
    fn file_usable(&self, _pointer: u64) -> bool {
        true
    }
    /// Dados de abertura do dono (`item.data`).
    fn data(&self, pointer: u64) -> ObjectData;
    /// Nó do namespace dono (diretórios e links).
    fn node(&self, _pointer: u64) -> Option<object_manager::NodeId> {
        None
    }
    /// Contagens, permanência e nome vigente do corpo.
    fn query_record(&self, _pointer: u64) -> QueryRecord {
        QueryRecord::default()
    }
}

/// Objeto descrito por ponteiro.
#[derive(Clone)]
pub struct Described {
    pub pointer: u64,
    pub object_type: ObjectType,
    pub owner: &'static dyn ObjectOwner,
}

impl Described {
    pub fn reference(&self) {
        self.owner.reference(self.pointer);
    }

    pub fn dereference(&self) {
        self.owner.dereference(self.pointer);
    }

    pub fn data(&self) -> ObjectData {
        self.owner.data(self.pointer)
    }
}

/// Slots de dono, na ordem de busca do original.
#[derive(Clone, Copy)]
pub enum Slot {
    Process,
    Thread,
    Token,
    Callback,
    Driver,
    Section,
    File,
    Dispatcher,
    Namespace,
    Silo,
}

type Recognizer = fn(u64) -> bool;

static OWNERS: SpinLock<[Option<(Recognizer, &'static dyn ObjectOwner)>; 10]> = SpinLock::new([None; 10]);

/// Registra o dono de um slot (os módulos de objetos, ao inicializar).
pub fn register_owner(slot: Slot, recognizes: Recognizer, owner: &'static dyn ObjectOwner) {
    OWNERS.lock()[slot as usize] = Some((recognizes, owner));
}

struct ProcessOwner;
struct ThreadOwner;
struct TokenOwner;
struct NamespaceOwner;

impl ObjectOwner for ProcessOwner {
    fn object_type(&self, _pointer: u64) -> ObjectType {
        object_types::process_type()
    }
    fn reference(&self, pointer: u64) {
        process::reference(pointer);
    }
    fn dereference(&self, pointer: u64) {
        let _ = process::dereference(pointer);
    }
    fn security(&self, pointer: u64) -> SecurityPolicy {
        process::with_record(pointer, |record| record.security.clone()).unwrap_or_default()
    }
    fn data(&self, pointer: u64) -> ObjectData {
        ObjectData { native_pointer: pointer, process_id: Some(guest::read64(pointer + 0x440)), ..ObjectData::default() }
    }
}

/// Threads executadas pelo kernel também passam pela coleta do escalonador
/// (`KernelThreads.dereference`, instalado com `ps/kernel-threads`).
static THREAD_DEREFERENCE: SpinLock<Option<fn(u64) -> bool>> = SpinLock::new(None);

pub fn set_thread_dereference(routine: fn(u64) -> bool) {
    *THREAD_DEREFERENCE.lock() = Some(routine);
}

impl ObjectOwner for ThreadOwner {
    fn object_type(&self, _pointer: u64) -> ObjectType {
        object_types::thread_type()
    }
    fn reference(&self, pointer: u64) {
        process::reference_thread(pointer);
    }
    fn dereference(&self, pointer: u64) {
        let handled = (*THREAD_DEREFERENCE.lock()).is_some_and(|routine| routine(pointer));
        if !handled {
            let _ = process::dereference_thread(pointer);
        }
    }
    fn security(&self, pointer: u64) -> SecurityPolicy {
        process::thread_record(pointer).map(|record| record.security).unwrap_or_default()
    }
    fn data(&self, pointer: u64) -> ObjectData {
        ObjectData::pointer(pointer)
    }
}

impl ObjectOwner for TokenOwner {
    fn object_type(&self, _pointer: u64) -> ObjectType {
        object_types::token_type()
    }
    fn reference(&self, pointer: u64) {
        let _ = tokens::retain(pointer);
    }
    fn dereference(&self, pointer: u64) {
        let _ = tokens::release(pointer);
    }
    fn security(&self, pointer: u64) -> SecurityPolicy {
        tokens::with(pointer, |token| token.security.clone()).unwrap_or_default()
    }
    fn exclusive_process(&self, pointer: u64) -> u64 {
        tokens::with(pointer, |token| token.exclusive_process).unwrap_or(0)
    }
    fn query_record(&self, pointer: u64) -> QueryRecord {
        QueryRecord { references: tokens::with(pointer, |token| token.refs as u32).unwrap_or(0), permanent: tokens::with(pointer, |token| token.permanent).unwrap_or(false), ..QueryRecord::default() }
    }
    fn data(&self, pointer: u64) -> ObjectData {
        ObjectData::pointer(pointer)
    }
}

impl ObjectOwner for NamespaceOwner {
    fn object_type(&self, pointer: u64) -> ObjectType {
        match namespace_objects::get(pointer) {
            Some((_, true)) => object_types::directory_type(),
            _ => object_types::symbolic_link_type(),
        }
    }
    fn reference(&self, pointer: u64) {
        let _ = namespace_objects::reference(pointer);
    }
    fn dereference(&self, pointer: u64) {
        let _ = namespace_objects::dereference(pointer);
    }
    /// O corpo conta seus handles e remove o nome temporário no último.
    fn open_handle(&self, pointer: u64) -> Option<Result<(), KernelError>> {
        Some(namespace_objects::open(pointer))
    }
    fn close_handle(&self, pointer: u64) -> Option<Result<(), KernelError>> {
        Some(namespace_objects::close(pointer))
    }
    fn security(&self, pointer: u64) -> SecurityPolicy {
        namespace_objects::security(pointer).unwrap_or_default()
    }
    fn data(&self, pointer: u64) -> ObjectData {
        ObjectData::pointer(pointer)
    }
    fn node(&self, pointer: u64) -> Option<object_manager::NodeId> {
        namespace_objects::get(pointer).map(|(node, _)| node)
    }
}

static PROCESS_OWNER: ProcessOwner = ProcessOwner;
static THREAD_OWNER: ThreadOwner = ThreadOwner;
static TOKEN_OWNER: TokenOwner = TokenOwner;
static NAMESPACE_OWNER: NamespaceOwner = NamespaceOwner;

fn built_in(slot: usize, pointer: u64) -> Option<&'static dyn ObjectOwner> {
    match slot {
        0 if process::is_process(pointer) => Some(&PROCESS_OWNER),
        1 if process::is_thread(pointer) => Some(&THREAD_OWNER),
        2 if tokens::exists(pointer) => Some(&TOKEN_OWNER),
        8 if namespace_objects::get(pointer).is_some() => Some(&NAMESPACE_OWNER),
        _ => None,
    }
}

/// Identifica o dono do corpo; `None` quando nenhum dono conhece o endereço.
pub fn describe(pointer: u64) -> Option<Described> {
    let owners = *OWNERS.lock();
    for (slot, registered) in owners.iter().enumerate() {
        let owner = built_in(slot, pointer).or_else(|| registered.filter(|(recognizes, _)| recognizes(pointer)).map(|(_, owner)| owner));
        if let Some(owner) = owner {
            return Some(Described { pointer, object_type: owner.object_type(pointer), owner });
        }
    }
    None
}

/// Registro privado de cada handle (32 bytes) e a retenção do dono.
struct HandleBodies {
    item: Described,
    granted: u32,
    flags: u32,
    bodies: SpinLock<Vec<u64>>,
}

impl ObjectHooks for HandleBodies {
    fn on_handle_open(&self) -> Result<(), KernelError> {
        let body = guest::alloc_bytes(32);
        if body == 0 {
            return Err(KernelError::with_status("object handle allocation failed", 0xC000_009A));
        }
        let opened = match self.item.owner.open_handle(self.item.pointer) {
            Some(result) => result,
            None => {
                self.item.reference();
                object_types::account(&self.item.object_type.name, 0, 1)
            }
        };
        if let Err(error) = opened {
            guest::free_bytes(body);
            return Err(error);
        }
        guest::write64(body, self.item.pointer);
        guest::write32(body + 8, self.granted);
        guest::write32(body + 12, self.flags);
        self.bodies.lock().push(body);
        Ok(())
    }

    fn on_handle_close(&self) {
        let Some(body) = self.bodies.lock().pop() else { return };
        match self.item.owner.close_handle(self.item.pointer) {
            Some(result) => {
                let _ = result;
            }
            None => {
                let _ = object_types::account(&self.item.object_type.name, 0, -1);
                self.item.dereference();
            }
        }
        guest::free_bytes(body);
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

/// ObOpenObjectByPointer: valida tipo, atributos, exclusividade e acesso e
/// publica o handle no processo correto. A saída é zerada antes da
/// validação (RVA 653F8E na referência 19041).
#[allow(clippy::too_many_arguments)]
pub fn open(pointer: u64, attributes: u32, access_state: u64, desired_access: u32, object_type: u64, access_mode: u8, output_handle: u64) -> Result<u32, KernelError> {
    if irql::get_irql() > 1 {
        return Err(KernelError::new("ObOpenObjectByPointer above APC_LEVEL"));
    }
    guest::try_write64(output_handle, 0)?;
    let Some(item) = describe(pointer) else {
        return Err(KernelError::new(alloc::format!("ObOpenObjectByPointer: invalid native object {pointer:#x}")));
    };
    if if object_type != 0 { object_type != item.object_type.pointer } else { access_mode != 0 } {
        return Ok(0xC000_0024);
    }
    // OBJ_EXCLUSIVE não transforma uma instância compartilhada já criada.
    let exclusive = item.owner.exclusive_process(pointer);
    if attributes & !0x1FF2 != 0 || (attributes & 0x20 != 0 && exclusive == 0) {
        return Ok(0xC000_000D);
    }
    if exclusive != 0 && exclusive != process::get_current_process() {
        return Ok(0xC000_0022);
    }
    if item.object_type.name == "File" && !item.owner.file_usable(pointer) {
        return Ok(0xC000_0128);
    }
    let enforce = access_mode != 0 || attributes & 0x400 != 0;
    // Um ACCESS_STATE capturado pode substituir o token e as máscaras.
    let mut subject = object_access::subject();
    let mut remaining = desired_access;
    let mut previously_granted = 0;
    if access_state != 0 {
        remaining = guest::read32(access_state + 0x10);
        previously_granted = guest::read32(access_state + 0x14);
        if enforce {
            let client = guest::read64(access_state + 0x20);
            let primary = guest::read64(access_state + 0x30);
            if client != 0 && guest::read32(access_state + 0x28) < 2 {
                return Ok(0xC000_00A5);
            }
            let token = if client != 0 { client } else { primary };
            subject = tokens::exists(token).then_some(token);
        }
    } else if enforce && thread_tokens::get(process::get_current_thread()).is_some_and(|impersonation| impersonation.level < 2) {
        return Ok(0xC000_00A5);
    }
    let rights = match object_access::check(&item.owner.security(pointer), subject, remaining, &item.object_type, !enforce) {
        Ok(access) => access,
        Err(status) => return Ok(status),
    };
    let options = PerformOptions { operation: 1, enforce, kernel_handle: attributes & 0x200 != 0, source_process: 0, target_process: 0 };
    let outcome = callbacks::perform(&item, rights | previously_granted, &options, &mut |granted| create(&item, attributes, granted, access_state, remaining, output_handle))?;
    Ok(outcome.status)
}

/// Publica `item` na tabela de `owner` com os direitos concedidos; o bit
/// 0x200 dos atributos marca um handle de kernel. Cada handle conserva a
/// própria retenção do corpo.
pub fn insert(item: &Described, granted: u32, attributes: u32, owner: u64) -> Result<u32, KernelError> {
    let handle_flags = attributes & 2; // OB_HANDLE_FLAG_INHERIT
    let mut data = item.data();
    data.native_pointer = item.pointer;
    data.native_open = Some(NativeOpen { record: item.pointer, node: item.owner.node(item.pointer) });
    data.access = Some(granted);
    data.owner_process = Some(owner);
    data.attributes = handle_flags;
    data.open_attributes = Some(attributes);
    data.hooks = Some(Arc::new(HandleBodies { item: item.clone(), granted, flags: handle_flags, bodies: SpinLock::new(Vec::new()) }));
    let node = object_manager::new_node("", &item.object_type.name, Some(data));
    object_manager::open_object(node, None)
}

fn create(item: &Described, attributes: u32, granted: u32, access_state: u64, remaining: u32, output_handle: u64) -> Outcome {
    let failure = |error: KernelError| Outcome { status: if error.status != 0 { error.status } else { 0xC000_0001 }, granted: None, value: 0, error: Some(error) };
    let owner = if attributes & 0x200 != 0 { process::get_system_process() } else { process::get_current_process() };
    let identifier = match insert(item, granted, attributes, owner) {
        Ok(identifier) => identifier,
        Err(error) => return failure(error),
    };
    let handle = if attributes & 0x200 != 0 { 0xFFFF_FFFF_8000_0000 | identifier as u64 } else { identifier as u64 };
    if let Err(error) = guest::try_write64(output_handle, handle) {
        let _ = close(handle);
        return failure(error);
    }
    if access_state != 0 {
        guest::write32(access_state + 0x14, granted);
        guest::write32(access_state + 0x10, remaining & !(granted | 0x0200_0000));
        guest::write8(access_state + 8, 1);
    }
    Outcome { status: 0, granted: Some(granted), value: identifier, error: None }
}

/// Resultado de `resolve`: dados atuais da linha nativa e o dono do corpo.
#[derive(Clone)]
pub struct Resolved {
    pub item: Described,
    pub data: ObjectData,
    pub owner_process: u64,
    pub open_attributes: u32,
    pub attributes: u32,
    pub access: u32,
}

/// Normaliza o handle e verifica tabela, modo e dono. `None` = handle
/// desconhecido; `Some(Err(status))` = handle de outro dono.
pub fn resolve(handle: u64, from_user_mode: bool) -> Option<Result<Resolved, u32>> {
    let value = handle & !3;
    let kernel_handle = value & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000;
    if !kernel_handle && value > 0x7FFF_FFFF {
        return None;
    }
    let entry = object_manager::handle_record((value & 0x7FFF_FFFF) as u32)?;
    if entry.pointer == 0 {
        return None;
    }
    let owner = entry.options.owner_process.unwrap_or(0);
    let mismatch = if kernel_handle { !entry.options.kernel_handle || from_user_mode } else { entry.options.kernel_handle || owner != process::get_current_process() };
    if mismatch {
        return Some(Err(0xC000_0008));
    }
    let item = describe(entry.pointer)?;
    let node_data = object_manager::node(entry.node).and_then(|node| node.data).unwrap_or_default();
    let mut data = item.data();
    data.native_pointer = item.pointer;
    data.native_open = node_data.native_open.or(Some(NativeOpen { record: item.pointer, node: item.owner.node(item.pointer) }));
    data.hooks = node_data.hooks;
    data.owner_process = Some(owner);
    data.open_attributes = entry.options.open_attributes;
    data.attributes = entry.attributes;
    data.access = Some(entry.access);
    Some(Ok(Resolved { item, data, owner_process: owner, open_attributes: entry.options.open_attributes.unwrap_or(0), attributes: entry.attributes, access: entry.access }))
}

/// ObReferenceObjectByHandle: resolve e retém o corpo, com verificações de
/// tipo e acesso. `None` = handle desconhecido.
pub fn reference_handle(handle: u64, desired_access: u32, object_type: u64, access_mode: u8, output_object: u64, output_information: u64) -> Result<Option<u32>, KernelError> {
    let (item, access, attributes) = match resolve(handle, access_mode != 0) {
        Some(Err(status)) => return Ok(Some(status)),
        Some(Ok(resolved)) => (resolved.item, resolved.access, resolved.attributes),
        // Handle da tabela de usuário do processo corrente: o corpo nativo
        // publicado pelo handle, com o acesso e os atributos do handle.
        None => match user_handle_body(handle) {
            Some(found) => found,
            None => return Ok(None),
        },
    };
    if object_type != 0 && object_type != item.object_type.pointer {
        return Ok(Some(0xC000_0024));
    }
    if access_mode != 0 && desired_access & !access != 0 {
        return Ok(Some(0xC000_0022));
    }
    item.reference();
    let written = guest::try_write64(output_object, item.pointer).and_then(|_| {
        if output_information != 0 {
            guest::try_write32(output_information, attributes)?;
            guest::try_write32(output_information + 4, access)?;
        }
        Ok(())
    });
    if let Err(error) = written {
        item.dereference();
        return Err(error);
    }
    Ok(Some(0))
}

/// Só quando o PID do runtime de usuário é o do processo corrente.
fn user_handle_body(handle: u64) -> Option<(Described, u32, u32)> {
    if handle > 0x7FFF_FFFF {
        return None;
    }
    let current = crate::ntos::ps::user::state::with(|state| state.current_process_id);
    if current != guest::read64(process::get_current_process() + 0x440) {
        return None;
    }
    let entry = crate::ntos::ps::user::state::get_user_handle(handle)?;
    let body = entry.object.native_body()?;
    let item = describe(body.pointer)?;
    Some((item, entry.access(), entry.attributes()))
}

/// Fecha pelo mesmo dono selecionado na resolução, isolando processos.
/// `None` = handle desconhecido.
pub fn close(handle: u64) -> Option<u32> {
    match resolve(handle, false)? {
        Err(status) => Some(status),
        Ok(_) => Some(if matches!(object_manager::close((handle & 0x7FFF_FFFF) as u32), Ok(true)) { 0 } else { 0xC000_0008 }),
    }
}

/// Nome do tipo de um corpo conhecido (diagnóstico).
pub fn type_name(pointer: u64) -> Option<String> {
    describe(pointer).map(|item| item.object_type.name)
}
