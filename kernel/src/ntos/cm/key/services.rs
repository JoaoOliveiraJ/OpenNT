//! Serviços de chave do registro.
//!
//! NtCreateKey/NtOpenKey, consulta, enumeração, alteração, exclusão,
//! fechamento e segurança, com captura de buffers, direitos por operação e
//! as notificações REG_* dos filtros. A tabela de handles de usuário
//! (`ps/user/state`) entra por [`set_user_handles`]; sem ela, o caminho de
//! PreviousMode usuário não resolve nem publica handles.
//!
//! A observação diagnóstica da árvore `HARDWARE\RESOURCEMAP` pertence ao
//! coletor externo e não faz parte do kernel.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::ntos::cm::callbacks::{self, Operation, Outcome as CallbackOutcome};
use crate::ntos::cm::registry::{self, NativeHooks, NodeId, Value};
use crate::ntos::cm::key::{access as key_access, information as key_information, objects as key_objects, security as key_security};
use crate::ntos::cm::value_information;
use crate::ntos::ke::critical_region;
use crate::ntos::mm::section::create as create_section;
use crate::ntos::ob::close;
use crate::ntos::ob::handle_table::HandleDescription;
use crate::ntos::ob::object_types;
use crate::ntos::ob::handles::process::{self as process_handles, Binding};
use crate::ntos::ps::{process, user_probe};
use crate::ntos::se::query_descriptor::QueryResult;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

/// Campos nomeados de uma estrutura REG_* (ou argumentos de uma operação).
pub type Fields = BTreeMap<&'static str, u64>;

pub fn fields(pairs: &[(&'static str, u64)]) -> Fields {
    pairs.iter().copied().collect()
}

/// Registro de handle de usuário do tipo key (`ps/user/state`).
#[derive(Clone, Copy, Debug)]
pub struct UserKeyRecord {
    pub khandle: u32,
    pub access: u32,
}

/// Tabela de handles de usuário do processo corrente.
#[derive(Clone, Copy)]
pub struct UserHandles {
    /// Registro do handle quando existe e é do tipo key.
    pub get: fn(u64) -> Option<UserKeyRecord>,
    /// Aloca o handle de usuário para o handle interno, direitos, atributos
    /// (só OBJ_INHERIT) e o corpo Key (retido/solto por `key_objects`).
    pub allocate: fn(u32, u32, u32, u64) -> Result<u64, KernelError>,
    pub close: fn(u64),
}

#[derive(Clone, Debug)]
struct NativeRecord {
    owner_process: u64,
    kernel_handle: bool,
    attributes: u32,
    access: u32,
    binding: Option<Binding>,
    handle_tags: u32,
    closing: bool,
}

#[derive(Default)]
struct State {
    records: BTreeMap<u32, NativeRecord>,
    user_tags: BTreeMap<u64, u32>,
    user: Option<UserHandles>,
}

static STATE: SpinLock<Option<State>> = SpinLock::new(None);
static HOOKS_INSTALLED: AtomicBool = AtomicBool::new(false);

fn with<T>(body: impl FnOnce(&mut State) -> T) -> T {
    let mut state = STATE.lock();
    body(state.get_or_insert_with(State::default))
}

pub fn set_user_handles(provider: Option<UserHandles>) {
    with(|state| state.user = provider);
}

/// Falha de contrato por NTSTATUS, distinta dos erros do kernel.
enum Fail {
    Status(u32),
    Kernel(KernelError),
}

impl From<KernelError> for Fail {
    fn from(error: KernelError) -> Self {
        Fail::Kernel(error)
    }
}

type Flow<T> = Result<T, Fail>;

fn status<T>(value: u32) -> Flow<T> {
    Err(Fail::Status(value))
}

/// Resultado de uma operação de chave (o objeto é o corpo Key).
#[derive(Clone, Copy, Debug, Default)]
struct Outcome {
    status: u32,
    object: u64,
    granted: Option<u32>,
    flags: Option<u32>,
    disposition: Option<u32>,
}

impl CallbackOutcome for Outcome {
    fn status(&self) -> u32 {
        self.status
    }
    fn object(&self) -> u64 {
        self.object
    }
    fn set_status(&mut self, status: u32) {
        self.status = status;
    }
    fn set_object(&mut self, object: u64) {
        self.object = object;
    }
    fn from_status(status: u32) -> Self {
        Self { status, ..Default::default() }
    }
}

/// Para PreviousMode usuário, sonda leitura ou escrita do intervalo inteiro.
fn probe(pointer: u64, length: u64, previous_mode: bool, write: bool) -> Flow<u64> {
    if previous_mode && !(if write { user_probe::probe_user_write(pointer, length) } else { user_probe::probe_user_read(pointer, length) }) {
        return status(0xC000_0005);
    }
    Ok(pointer)
}

/// UNICODE_STRING de 16 bytes; comprimento ímpar recusado; exatamente
/// Length bytes, sem depender de terminador.
fn read_unicode_string(pointer: u64, previous_mode: bool) -> Flow<String> {
    let pointer = probe(pointer, 16, previous_mode, false)?;
    let length = guest::read16(pointer) as u64;
    let buffer = guest::read64(pointer + 8);
    if length & 1 != 0 {
        return status(0xC000_0033);
    }
    if length != 0 {
        probe(buffer, length, previous_mode, false)?;
    }
    let units: Vec<u16> = (0..length / 2).map(|index| guest::read16(buffer + index * 2)).collect();
    Ok(String::from_utf16_lossy(&units))
}

/// Dono dos buffers e corpos temporários da solicitação: corpos retidos são
/// soltos antes dos buffers, liberados em ordem inversa, em qualquer saída.
struct Request {
    allocations: RefCell<Vec<u64>>,
    bodies: RefCell<Vec<u64>>,
}

impl Request {
    fn allocate(&self, length: u64) -> Flow<u64> {
        let pointer = guest::alloc_bytes(length);
        if pointer == 0 {
            return status(0xC000_009A);
        }
        self.allocations.borrow_mut().push(pointer);
        Ok(pointer)
    }

    /// Estrutura e texto na mesma alocação: cabeçalho, UTF-16 e terminador.
    fn create_unicode_string(&self, name: &str) -> Flow<u64> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let pointer = self.allocate(18 + units.len() as u64 * 2)?;
        guest::write16(pointer, units.len() as u16 * 2);
        guest::write16(pointer + 2, units.len() as u16 * 2 + 2);
        guest::write64(pointer + 8, pointer + 16);
        for (index, unit) in units.iter().enumerate() {
            guest::write16(pointer + 16 + index as u64 * 2, *unit);
        }
        Ok(pointer)
    }

    fn retain_key_body(&self, body: Option<u64>) -> Flow<u64> {
        let Some(body) = body else { return status(0xC000_009A) };
        self.bodies.borrow_mut().push(key_objects::hold(body));
        Ok(body)
    }

    fn create_temporary_key_body(&self, node: Option<NodeId>, path: &str) -> Flow<u64> {
        let Some(body) = node.and_then(|node| key_objects::temporary(node, path)) else { return status(0xC000_009A) };
        self.bodies.borrow_mut().push(body);
        Ok(body)
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        for body in self.bodies.borrow().iter() {
            let _ = key_objects::release(*body);
        }
        for pointer in self.allocations.borrow().iter().rev() {
            guest::free_bytes(*pointer);
        }
    }
}

/// Converte só falhas de NTSTATUS em retorno; erros do kernel continuam.
fn with_request(body: impl FnOnce(&Request) -> Flow<u32>) -> Result<u32, KernelError> {
    let request = Request { allocations: RefCell::new(Vec::new()), bodies: RefCell::new(Vec::new()) };
    match body(&request) {
        Ok(value) => Ok(value),
        Err(Fail::Status(value)) => Ok(value),
        Err(Fail::Kernel(error)) => Err(error),
    }
}

type Layout = &'static [(&'static str, u64, u8)];

fn write_fields(pointer: u64, layout: Layout, values: &Fields) {
    for &(name, offset, width) in layout {
        let value = values.get(name).copied().unwrap_or(0);
        match width {
            8 => guest::write8(pointer + offset, value as u8),
            32 => guest::write32(pointer + offset, value as u32),
            _ => guest::write64(pointer + offset, value),
        }
    }
}

fn read_fields(pointer: u64, layout: Layout, initial: &Fields) -> Fields {
    let mut result = initial.clone();
    for &(name, offset, width) in layout {
        let value = match width {
            8 => guest::read8(pointer + offset) as u64,
            32 => guest::read32(pointer + offset) as u64,
            _ => guest::read64(pointer + offset),
        };
        result.insert(name, value);
    }
    result
}

/// Serializa os campos no layout REG_* quando há filtros e relê os campos
/// modificáveis antes da operação; sem filtros, chama a ação diretamente.
#[allow(clippy::too_many_arguments)]
fn notify_and_perform(
    request: &Request,
    pre: u32,
    post: u32,
    size: u64,
    call_offset: u64,
    initial: &Fields,
    layout: Layout,
    action: impl FnOnce(&Fields) -> Flow<Outcome>,
    unblockable: bool,
    bypass: Option<&dyn Fn(&Fields) -> Outcome>,
) -> Flow<Outcome> {
    if !callbacks::has() {
        return action(initial);
    }
    let information = request.allocate(size)?;
    write_fields(information, layout, initial);
    let bypassing = || match bypass {
        Some(bypass) => bypass(&read_fields(information, layout, initial)),
        None => Outcome::from_status(0),
    };
    let operation = Operation { pre, post, info: information, call_offset, object: initial.get("object").copied().unwrap_or(0), unblockable, bypass: Some(&bypassing) };
    callbacks::perform_fallible(&operation, || action(&read_fields(information, layout, initial)))?
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Entry {
    None,
    Native(u32),
    User(u64),
}

struct Resolved {
    khandle: u32,
    node: NodeId,
    entry: Entry,
    path: String,
}

/// Resolve handles de usuário ou nativos, confere direitos de usuário e o
/// processo dono, e distingue chave excluída de handle inválido.
fn resolve_key_handle(handle: u64, previous_mode: bool, required: u32) -> Flow<Resolved> {
    if handle > 0x7FFF_FFFF {
        return status(0xC000_0008);
    }
    let mut khandle = handle as u32;
    let entry;
    if previous_mode {
        let provider = with(|state| state.user);
        let Some(record) = provider.and_then(|provider| (provider.get)(handle)) else { return status(0xC000_0008) };
        if required & !record.access != 0 {
            return status(0xC000_0022);
        }
        khandle = record.khandle;
        entry = Entry::User(handle);
    } else {
        let record = with(|state| state.records.get(&khandle).map(|record| (record.kernel_handle, record.owner_process)));
        if let Some((kernel_handle, owner)) = record {
            if !kernel_handle && owner != process::get_current_process() {
                return status(0xC000_0008);
            }
            entry = Entry::Native(khandle);
        } else {
            entry = Entry::None;
        }
    }
    let Some(node) = registry::get_node(khandle) else {
        return status(if registry::handle_entry(khandle).is_some() { 0xC000_017C } else { 0xC000_0008 });
    };
    Ok(Resolved { khandle, node, entry, path: registry::get_path(khandle).unwrap_or_default() })
}

fn close_from_table(_process: u64, handle: u32) {
    registry::close_handle(handle);
}

/// Associa a identidade à tabela apropriada e só então grava o handle de
/// saída; falha nessa escrita desfaz a publicação.
fn publish_key_handle(output: u64, khandle: u32, attributes: u32, granted: u32, previous_mode: bool) -> Flow<()> {
    let Some(body) = key_objects::for_handle(khandle) else { return status(0xC000_009A) };
    let mut handle = khandle as u64;
    if previous_mode {
        let Some(provider) = with(|state| state.user) else { return Err(KernelError::new("user handle table unavailable").into()) };
        handle = (provider.allocate)(khandle, granted, attributes & 2, body)?;
    } else {
        // OBJ_KERNEL_HANDLE vincula ao processo do sistema.
        let kernel_handle = attributes & 0x200 != 0;
        let owner = if kernel_handle { process::get_system_process() } else { process::get_current_process() };
        let description = HandleDescription { pointer: body, type_name: object_types::key_type().name, identity: body, native_body: body, attributes: attributes & 2, access: granted };
        process_handles::publish(
            owner,
            handle,
            &description,
            close_from_table,
            Some(&mut |binding: &Binding| {
                with(|state| state.records.insert(khandle, NativeRecord { owner_process: owner, kernel_handle, attributes: attributes & 2, access: granted, binding: Some(*binding), handle_tags: 0, closing: false }));
                Ok(())
            }),
        )?;
    }
    if let Err(error) = guest::try_write64(output, handle) {
        if previous_mode {
            if let Some(provider) = with(|state| state.user) {
                (provider.close)(handle);
            }
        } else {
            registry::close_raw(khandle);
        }
        return Err(error.into());
    }
    Ok(())
}

/// O caminho de usuário aplica a política compartilhada; o de kernel
/// conserva a máscara recebida.
fn resolve_access_mask(desired: u32, options: u32, previous_mode: bool) -> Result<u32, u32> {
    if previous_mode { key_access::key_access(desired, options) } else { Ok(desired) }
}

fn starts_with_registry(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower == "\\registry" || lower.starts_with("\\registry\\")
}

fn strip_registry(path: &str) -> &str {
    if path.len() >= 9 && path[..9].eq_ignore_ascii_case("\\registry") {
        let rest = &path[9..];
        rest.strip_prefix('\\').unwrap_or(rest)
    } else {
        path
    }
}

const CREATE_LAYOUT: Layout = &[
    ("name", 0, 64),
    ("root", 8, 64),
    ("type", 16, 64),
    ("options", 24, 32),
    ("className", 32, 64),
    ("sd", 40, 64),
    ("qos", 48, 64),
    ("desired", 56, 32),
    ("granted", 60, 32),
    ("disposition", 64, 64),
    ("resultObject", 72, 64),
    ("version", 104, 64),
    ("remaining", 112, 64),
    ("wow64", 120, 32),
    ("flags", 124, 32),
    ("mode", 128, 8),
];

/// Captura OBJECT_ATTRIBUTES e o nome, valida raiz e opções, notifica os
/// filtros, abre ou cria a chave e publica o handle. Uma abertura não
/// transferida ao chamador é fechada em qualquer saída.
#[allow(clippy::too_many_arguments)]
fn open_or_create_key(create: bool, output: u64, desired: u32, attributes_pointer: u64, _title_index: u32, class_name: u64, options: u32, output_disposition: u64, previous_mode: bool) -> Result<u32, KernelError> {
    install_hooks();
    with_request(|request| {
        let output = probe(output, 8, previous_mode, true)?;
        let attributes_pointer = probe(attributes_pointer, 48, previous_mode, false)?;
        if guest::read32(attributes_pointer) != 48 {
            return Ok(0xC000_000D);
        }
        if options & !(if create { 1 } else { 12 }) != 0 {
            return Ok(if create { 0xC000_000D } else { 0xC000_00F2 });
        }
        if class_name != 0 && !read_unicode_string(class_name, previous_mode)?.is_empty() {
            return Ok(0xC000_00BB);
        }
        let output_disposition = if output_disposition != 0 { probe(output_disposition, 4, previous_mode, true)? } else { 0 };
        let mut attribute_flags = guest::read32(attributes_pointer + 24);
        if previous_mode {
            attribute_flags &= !0x200;
        }
        let name_pointer = guest::read64(attributes_pointer + 16);
        let mut key_name = read_unicode_string(name_pointer, previous_mode)?;
        let root_handle = guest::read64(attributes_pointer + 8);
        let parent = if root_handle != 0 { Some(resolve_key_handle(root_handle, previous_mode, 0)?) } else { None };
        if (parent.is_some() && key_name.starts_with('\\')) || (parent.is_none() && !starts_with_registry(&key_name)) {
            return Ok(0xC000_003B);
        }
        let mut absolute_path = match &parent {
            Some(parent) => parent.path.clone() + if key_name.is_empty() { "" } else { "\\" } + &key_name,
            None => key_name.clone(),
        };
        let access = match resolve_access_mask(desired, options, previous_mode) {
            Ok(access) => access,
            Err(value) => return Ok(value),
        };
        // Descritor e QoS capturados de OBJECT_ATTRIBUTES; o descritor é
        // sondado para usuário e capturado ao criar a política do nó.
        let descriptor = guest::read64(attributes_pointer + 32);
        let qos = guest::read64(attributes_pointer + 40);
        if previous_mode && descriptor != 0 && !create_section::descriptor_probe(descriptor) {
            return Ok(0xC000_0005);
        }
        if qos != 0 {
            probe(qos, 12, previous_mode, false)?;
        }
        let filtered = callbacks::has();
        let root_body = if filtered {
            match &parent {
                Some(parent) => request.retain_key_body(key_objects::for_handle(parent.khandle))?,
                None => request.create_temporary_key_body(registry::node_by_path("\\Registry"), "\\Registry")?,
            }
        } else {
            0
        };
        let output_object = if filtered { request.allocate(8)? } else { 0 };
        let callback_disposition = if filtered { request.allocate(4)? } else { 0 };
        let remaining = if filtered { request.create_unicode_string(if parent.is_some() { &key_name } else { strip_registry(&key_name) })? } else { 0 };
        let initial = fields(&[
            ("name", if filtered { request.create_unicode_string(&key_name)? } else { name_pointer }),
            ("root", root_body),
            ("type", if filtered { object_types::key_type().pointer } else { 0 }),
            ("options", options as u64),
            ("className", class_name),
            ("sd", descriptor),
            ("qos", qos),
            ("desired", desired as u64),
            ("granted", 0),
            ("disposition", callback_disposition),
            ("resultObject", output_object),
            ("version", 1),
            ("remaining", remaining),
            ("wow64", (desired & 0x300) as u64),
            ("flags", attribute_flags as u64),
            ("mode", (previous_mode || attribute_flags & 0x400 != 0) as u64),
        ]);
        let mut opened: u32 = 0;
        let mut created_disposition = 0u32;
        let bypass = |fields: &Fields| Outcome {
            status: 0,
            object: if fields["resultObject"] != 0 { guest::read64(fields["resultObject"]) } else { 0 },
            granted: Some(fields["granted"] as u32),
            flags: Some(fields["flags"] as u32),
            disposition: Some(if fields["disposition"] != 0 { guest::read32(fields["disposition"]) } else { 0 }),
        };
        let result = notify_and_perform(
            request,
            if create { 26 } else { 28 },
            if create { 27 } else { 29 },
            144,
            80,
            &initial,
            CREATE_LAYOUT,
            |operation: &Fields| -> Flow<Outcome> {
                if callbacks::has() {
                    key_name = read_unicode_string(operation["name"], false)?;
                    // Um filtro pode trocar raiz e nome; a raiz precisa ser
                    // uma identidade real.
                    let Some(root) = key_objects::get(operation["root"]) else { return Ok(Outcome::from_status(0xC000_0008)) };
                    absolute_path = if key_name.starts_with('\\') { key_name.clone() } else { root.path + if key_name.is_empty() { "" } else { "\\" } + &key_name };
                }
                if !starts_with_registry(&absolute_path) {
                    return Ok(Outcome::from_status(0xC000_003B));
                }
                let options = operation["options"] as u32;
                if options & !(if create { 1 } else { 12 }) != 0 {
                    return Ok(Outcome::from_status(0xC000_000D));
                }
                let enforce = previous_mode || operation["flags"] & 0x400 != 0;
                let required = match resolve_access_mask(operation["desired"] as u32, options, enforce) {
                    Ok(required) => required,
                    Err(value) => return Ok(Outcome::from_status(value)),
                };
                let existing = registry::node_by_path(&absolute_path);
                let existed = existing.is_some();
                let parent_node = registry::node_by_path(&absolute_path[..absolute_path.rfind('\\').unwrap_or(0)]);
                if create && !existed && parent_node.is_none() {
                    return Ok(Outcome::from_status(0xC000_003A));
                }
                let mut assigned = None;
                if create && !existed {
                    let parent_security = registry::with_node(parent_node.unwrap_or(0), |key| key.security.clone()).ok_or(Fail::Status(0xC000_003A))?;
                    if let Err(value) = key_security::access(&parent_security, 4, enforce) {
                        return Ok(Outcome::from_status(value));
                    }
                    match key_security::create(&parent_security, operation["sd"], enforce)? {
                        Ok(descriptor) => assigned = Some(descriptor),
                        Err(value) => return Ok(Outcome::from_status(value)),
                    }
                }
                let Some(existing_or_assigned) = (match (&assigned, existing) {
                    (Some(descriptor), _) => Some(descriptor.clone()),
                    (None, Some(node)) => registry::with_node(node, |key| key.security.clone()),
                    (None, None) => None,
                }) else {
                    return Ok(Outcome::from_status(0xC000_0034));
                };
                let granted = if options & 4 != 0 { Ok(required) } else { key_security::access(&existing_or_assigned, required, enforce && existed) };
                let granted = match granted {
                    Ok(granted) => granted,
                    Err(value) => return Ok(Outcome::from_status(value)),
                };
                opened = if create { registry::open_or_create(&absolute_path, assigned)? } else { registry::open(&absolute_path)? };
                if opened == 0 {
                    return Ok(Outcome::from_status(0xC000_0034));
                }
                created_disposition = if existed { 2 } else { 1 };
                let body = if callbacks::has() { request.retain_key_body(key_objects::for_handle(opened))? } else { 0 };
                if operation["resultObject"] != 0 {
                    guest::write64(operation["resultObject"], body);
                }
                if operation["disposition"] != 0 {
                    guest::write32(operation["disposition"], created_disposition);
                }
                Ok(Outcome { status: 0, object: body, granted: Some(granted), flags: Some(operation["flags"] as u32), disposition: None })
            },
            false,
            Some(&bypass),
        );
        let published = (|| -> Flow<u32> {
            let result = result?;
            if result.status != 0 {
                return Ok(result.status);
            }
            if callbacks::has() {
                // Um BYPASS de abertura precisa fornecer identidade viva; um
                // sucesso isolado não cria objeto nem handle.
                let object = if result.object != 0 { result.object } else { guest::read64(output_object) };
                let Some(body) = key_objects::get(object) else { return Ok(0xC000_0008) };
                if opened == 0 || key_objects::for_handle(opened) != Some(body.pointer) {
                    if opened != 0 {
                        registry::close_raw(opened);
                        opened = 0;
                    }
                    opened = registry::open_node(body.node, &body.path)?;
                    key_objects::attach(opened, body.pointer)?;
                }
            }
            publish_key_handle(output, opened, result.flags.unwrap_or(attribute_flags), result.granted.unwrap_or(access), previous_mode)?;
            if output_disposition != 0 {
                guest::write32(output_disposition, result.disposition.unwrap_or(created_disposition));
            }
            opened = 0;
            Ok(0)
        })();
        if opened != 0 {
            registry::close_raw(opened);
        }
        published
    })
}

/// Operações sobre um handle de chave aberto.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Set,
    DeleteValue,
    DeleteKey,
    EnumerateKey,
    EnumerateValue,
    QueryValue,
    QueryKey,
    SetInfo,
}

/// (classe pré, classe pós, tamanho, offset do CallContext, campos).
fn notification_layout(kind: Kind) -> (u32, u32, u64, u64, Layout) {
    match kind {
        Kind::DeleteKey => (0, 15, 32, 8, &[("object", 0, 64)]),
        Kind::DeleteValue => (2, 17, 40, 16, &[("object", 0, 64), ("name", 8, 64)]),
        Kind::Set => (1, 16, 64, 40, &[("object", 0, 64), ("name", 8, 64), ("title", 16, 32), ("type", 20, 32), ("data", 24, 64), ("length", 32, 32)]),
        Kind::SetInfo => (3, 18, 56, 32, &[("object", 0, 64), ("klass", 8, 32), ("data", 16, 64), ("length", 24, 32)]),
        Kind::QueryKey => (7, 22, 64, 40, &[("object", 0, 64), ("klass", 8, 32), ("out", 16, 64), ("length", 24, 32), ("returned", 32, 64)]),
        Kind::QueryValue => (8, 23, 72, 48, &[("object", 0, 64), ("name", 8, 64), ("klass", 16, 32), ("out", 24, 64), ("length", 32, 32), ("returned", 40, 64)]),
        Kind::EnumerateKey => (5, 20, 64, 40, &[("object", 0, 64), ("index", 8, 32), ("klass", 12, 32), ("out", 16, 64), ("length", 24, 32), ("returned", 32, 64)]),
        Kind::EnumerateValue => (6, 21, 64, 40, &[("object", 0, 64), ("index", 8, 32), ("klass", 12, 32), ("out", 16, 64), ("length", 24, 32), ("returned", 32, 64)]),
    }
}

fn handle_tags(entry: Entry) -> u32 {
    with(|state| match entry {
        Entry::Native(handle) => state.records.get(&handle).map_or(0, |record| record.handle_tags),
        Entry::User(handle) => state.user_tags.get(&handle).copied().unwrap_or(0),
        Entry::None => 0,
    })
}

/// Consulta, enumeração, alteração ou exclusão com captura de buffers,
/// direitos por operação e notificações; o objeto redirecionado por filtros
/// precisa continuar sendo uma chave viva.
pub fn key_operation(kind: Kind, handle: u64, arguments: &Fields, previous_mode: bool) -> Result<u32, KernelError> {
    install_hooks();
    with_request(|request| {
        let required = match kind {
            Kind::Set | Kind::DeleteValue => 2,
            Kind::DeleteKey => 0x10000,
            Kind::EnumerateKey => 8,
            Kind::EnumerateValue | Kind::QueryValue => 1,
            Kind::QueryKey => if arguments.get("klass").copied() == Some(3) { 0 } else { 1 },
            Kind::SetInfo => 0,
        };
        let resolved = resolve_key_handle(handle, previous_mode, required)?;
        let body = if callbacks::has() { request.retain_key_body(key_objects::for_handle(resolved.khandle))? } else { 0 };
        let mut operation = arguments.clone();
        operation.insert("object", body);
        if let Some(&name) = arguments.get("name") {
            let captured = read_unicode_string(name, previous_mode)?;
            if callbacks::has() {
                operation.insert("name", request.create_unicode_string(&captured)?);
            }
        }
        // Captura limitada a 1 MiB; com filtros, uma cópia privada desliga a
        // operação do buffer de entrada original.
        if kind == Kind::Set || kind == Kind::SetInfo {
            let length = operation.get("length").copied().unwrap_or(0) as u32 as u64;
            operation.insert("length", length);
            if length > 0x10_0000 {
                return Ok(0xC000_009A);
            }
            let data = operation.get("data").copied().unwrap_or(0);
            if length != 0 {
                probe(data, length, previous_mode, false)?;
            }
            if callbacks::has() && length != 0 {
                let captured = request.allocate(length)?;
                guest::write_bytes(captured, &guest::read_bytes(data, length as usize));
                operation.insert("data", captured);
            }
        }
        if let Some(&out) = arguments.get("out") {
            let length = operation.get("length").copied().unwrap_or(0) as u32 as u64;
            operation.insert("length", length);
            probe(operation.get("returned").copied().unwrap_or(0), 4, previous_mode, true)?;
            if length != 0 {
                probe(out, length, previous_mode, true)?;
            }
        }
        let (pre, post, size, call_offset, layout) = notification_layout(kind);
        let result = notify_and_perform(
            request,
            pre,
            post,
            size,
            call_offset,
            &operation,
            layout,
            |updated: &Fields| -> Flow<Outcome> {
                let field = |name: &str| updated.get(name).copied().unwrap_or(0);
                let target = if callbacks::has() { key_objects::get(field("object")) } else { None };
                if callbacks::has() && target.is_none() {
                    return Ok(Outcome::from_status(0xC000_0008));
                }
                let node = target.as_ref().map_or(resolved.node, |target| target.node);
                let path = target.as_ref().map_or(resolved.path.clone(), |target| target.path.clone());
                if registry::is_deleted(node) {
                    return Ok(Outcome::from_status(0xC000_017C));
                }
                let status = match kind {
                    Kind::Set => {
                        let length = field("length");
                        if length > 0x10_0000 {
                            return Ok(Outcome::from_status(0xC000_009A));
                        }
                        let bytes = guest::read_bytes(field("data"), length as usize);
                        let name = read_unicode_string(field("name"), false)?;
                        if registry::set_node_value(node, &path, &name, field("type") as u32, bytes) { 0 } else { 0xC000_017C }
                    }
                    Kind::DeleteValue => {
                        let name = read_unicode_string(field("name"), false)?;
                        if registry::delete_node_value(node, &path, &name) { 0 } else { 0xC000_0034 }
                    }
                    Kind::DeleteKey => {
                        if registry::delete_node(node, &path) { 0 } else { 0xC000_0121 }
                    }
                    Kind::SetInfo => {
                        if field("klass") != 5 {
                            0xC000_0003
                        } else if field("length") != 4 {
                            0xC000_0004
                        } else {
                            let tags = guest::read32(field("data"));
                            with(|state| match resolved.entry {
                                Entry::Native(handle) => {
                                    if let Some(record) = state.records.get_mut(&handle) {
                                        record.handle_tags = tags;
                                    }
                                }
                                Entry::User(handle) => {
                                    state.user_tags.insert(handle, tags);
                                }
                                Entry::None => {}
                            });
                            0
                        }
                    }
                    Kind::QueryValue | Kind::EnumerateValue => {
                        let value: Option<Value> = if kind == Kind::QueryValue {
                            let name = read_unicode_string(field("name"), false)?.to_lowercase();
                            registry::with_node(node, |key| key.value(&name).cloned()).flatten()
                        } else {
                            let index = field("index") as u32 as usize;
                            registry::with_node(node, |key| key.values.get(index).map(|(_, value)| value.clone())).flatten()
                        };
                        match value {
                            Some(value) => value_information::write(&value, field("klass") as u32, field("out"), field("length") as u32, field("returned")),
                            None if kind == Kind::QueryValue => 0xC000_0034,
                            None => 0x8000_001A,
                        }
                    }
                    Kind::EnumerateKey | Kind::QueryKey => {
                        let child = if kind == Kind::EnumerateKey { registry::children(node).get(field("index") as u32 as usize).copied() } else { Some(node) };
                        if kind == Kind::EnumerateKey && field("klass") > 2 {
                            0xC000_0003
                        } else {
                            match child {
                                None => 0x8000_001A,
                                Some(child) => key_information::write(child, if kind == Kind::QueryKey { &path } else { "" }, field("klass") as u32, field("out"), field("length") as u32, field("returned"), handle_tags(resolved.entry)),
                            }
                        }
                    }
                };
                Ok(Outcome { status, object: field("object"), ..Default::default() })
            },
            false,
            None,
        )?;
        Ok(result.status)
    })
}

/// Notifica o fechamento sem veto dos filtros. O processo dono fica retido
/// durante a transição e o fechamento reentrante do registro é recusado.
pub fn close(handle: u32, action: fn(u32) -> bool) -> bool {
    let record = with(|state| state.records.get(&handle).map(|record| (record.closing, record.owner_process)));
    let mut retained = 0;
    let mut owner = 0;
    if let Some((closing, owner_process)) = record {
        if closing {
            return false;
        }
        owner = owner_process;
        retained = process_handles::reference(owner).unwrap_or(0);
        if retained == 0 && !process_handles::draining(owner) {
            return false;
        }
        with(|state| {
            if let Some(record) = state.records.get_mut(&handle) {
                record.closing = true;
            }
        });
    }
    let result = if !callbacks::has() {
        action(handle)
    } else {
        let mut closed = false;
        let mut attempted = false;
        let notified = with_request(|request| {
            let body = request.retain_key_body(key_objects::for_handle(handle))?;
            notify_and_perform(
                request,
                14,
                25,
                32,
                8,
                &fields(&[("object", body)]),
                &[("object", 0, 64)],
                |_| {
                    attempted = true;
                    closed = action(handle);
                    Ok(Outcome { status: if closed { 0 } else { 0xC000_0008 }, object: body, ..Default::default() })
                },
                true,
                None,
            )?;
            Ok(0)
        });
        match notified {
            Ok(_) if attempted => closed,
            Ok(_) => action(handle),
            Err(_) => false,
        }
    };
    with(|state| {
        if let Some(record) = state.records.get_mut(&handle) {
            record.closing = false;
        }
    });
    if retained != 0 {
        let _ = process_handles::release(owner);
    }
    result
}

/// Metadados de um handle nativo ainda presente na hive.
#[derive(Clone, Copy, Debug)]
pub struct NativeHandleInfo {
    pub owner_process: u64,
    pub kernel_handle: bool,
    pub attributes: u32,
    pub access: u32,
}

pub fn close_record(handle: u32) -> Option<NativeHandleInfo> {
    let record = with(|state| state.records.get(&handle).cloned())?;
    registry::handle_entry(handle)?;
    Some(NativeHandleInfo { owner_process: record.owner_process, kernel_handle: record.kernel_handle, attributes: record.attributes, access: record.access })
}

/// Fechamento do registro devolvido por [`close_record`].
pub fn close_native(handle: u32) -> u32 {
    if registry::close_handle(handle) { 0 } else { 0xC000_0008 }
}

/// Registro Zw de um handle de chave, para o provedor Zw do NtClose.
pub fn zw_record(handle: u32) -> Option<close::ZwRecord> {
    let record = close_record(handle)?;
    Some(close::ZwRecord { kernel_handle: record.kernel_handle, owner_process: record.owner_process, attributes: record.attributes, close: alloc::boxed::Box::new(move || close_native(handle)) })
}

/// Abertura interna com OBJECT_ATTRIBUTES temporários, handle de kernel e
/// nome sem diferença de caixa. Devolve (status, handle).
pub fn open_path(path: &str, create: bool) -> Result<(u32, u64), KernelError> {
    let mut handle = 0;
    let status = with_request(|request| {
        let attributes = request.allocate(48)?;
        let output = request.allocate(8)?;
        guest::write32(attributes, 48);
        guest::write64(attributes + 16, request.create_unicode_string(path)?);
        guest::write32(attributes + 24, 0x240);
        let status = open_or_create_key(create, output, 0xF003F, attributes, 0, 0, 0, 0, false)?;
        if status == 0 {
            handle = guest::read64(output);
        }
        Ok(status)
    })?;
    Ok((status, handle))
}

/// Operações de valor por nome: a consulta obtém o tamanho, lê a resposta e
/// copia só o dado efetivamente devolvido.
pub fn named_value(kind: Kind, handle: u64, name: &str, value_type: u32, bytes: &[u8]) -> Result<(u32, Option<Value>), KernelError> {
    let mut value = None;
    let status = with_request(|request| {
        let name_pointer = request.create_unicode_string(name)?;
        if kind == Kind::DeleteValue {
            return Ok(key_operation(kind, handle, &fields(&[("name", name_pointer)]), false)?);
        }
        if kind == Kind::Set {
            let data = request.allocate((bytes.len() as u64).max(1))?;
            guest::write_bytes(data, bytes);
            return Ok(key_operation(kind, handle, &fields(&[("name", name_pointer), ("title", 0), ("type", value_type as u64), ("data", data), ("length", bytes.len() as u64)]), false)?);
        }
        let returned = request.allocate(4)?;
        let status = key_operation(Kind::QueryValue, handle, &fields(&[("name", name_pointer), ("klass", 2), ("out", 0), ("length", 0), ("returned", returned)]), false)?;
        if status != 0xC000_0023 {
            return Ok(status);
        }
        let length = guest::read32(returned) as u64;
        let buffer = request.allocate(length)?;
        let status = key_operation(Kind::QueryValue, handle, &fields(&[("name", name_pointer), ("klass", 2), ("out", buffer), ("length", length), ("returned", returned)]), false)?;
        if status != 0 {
            return Ok(status);
        }
        let data_length = guest::read32(buffer + 8) as u64;
        if data_length > length.saturating_sub(12) {
            return Ok(0xC000_0023);
        }
        value = Some(Value { name: String::from(name), value_type: guest::read32(buffer + 4), data: guest::read_bytes(buffer + 12, data_length as usize) });
        Ok(0)
    })?;
    Ok((status, value))
}

/// CmpSecurityMethod: filtros editam Information/Length, mas trocar os
/// ponteiros da notificação não redireciona a consulta. A região crítica
/// cobre também o caminho sem filtros. O chamador retém o corpo.
pub fn query_security(body: u64, information: u32, buffer: u64, capacity: u32) -> Result<QueryResult, KernelError> {
    critical_region::enter_critical()?;
    let result = (|| -> Result<QueryResult, KernelError> {
        if !callbacks::has() {
            return key_security::query(body, information, buffer, capacity);
        }
        let mut selected = information;
        let mut needed = capacity;
        let status = with_request(|request| {
            let information_pointer = request.allocate(8)?;
            let length_pointer = information_pointer + 4;
            guest::write32(information_pointer, selected);
            guest::write32(length_pointer, needed);
            let result = notify_and_perform(
                request,
                36,
                37,
                56,
                32,
                &fields(&[("object", body), ("information", information_pointer), ("buffer", buffer), ("length", length_pointer)]),
                &[("object", 0, 64), ("information", 8, 64), ("buffer", 16, 64), ("length", 24, 64)],
                |_| {
                    let queried = key_security::query(body, guest::read32(information_pointer), buffer, guest::read32(length_pointer))?;
                    guest::write32(information_pointer, queried.information);
                    guest::write32(length_pointer, queried.needed as u32);
                    Ok(Outcome { status: queried.status, object: body, ..Default::default() })
                },
                false,
                None,
            );
            // O pós ainda pode mudar o tamanho pelo ponteiro original; só
            // depois dele o serviço publica LengthNeeded.
            selected = guest::read32(information_pointer);
            needed = guest::read32(length_pointer);
            Ok(result?.status)
        })?;
        Ok(QueryResult { status, needed: needed as usize, information: selected })
    })();
    let left = critical_region::leave_critical();
    let result = result?;
    left?;
    Ok(result)
}

fn remove_hook(handle: u32, detach: &dyn Fn() -> bool) -> bool {
    let binding = with(|state| state.records.get(&handle).and_then(|record| record.binding));
    match binding {
        Some(binding) => process_handles::remove(&binding, Some(&mut || {
            detach();
        }))
        .unwrap_or(false),
        None => detach(),
    }
}

fn detach_hook(handle: u32) {
    with(|state| state.records.remove(&handle));
    key_objects::detach(handle);
}

/// Conecta fechamento, remoção da tabela do processo e liberação da
/// identidade nativa à hive, num único caminho de limpeza.
pub fn install_hooks() {
    if HOOKS_INSTALLED.swap(true, Ordering::AcqRel) {
        return;
    }
    registry::set_native_hooks(Some(NativeHooks { close, remove: Some(remove_hook), detach: detach_hook }));
    close::set_zw_provider_if_absent(zw_record);
}

/// NtOpenKey(Ex).
pub fn open(output: u64, desired: u32, attributes: u64, previous_mode: bool, options: u32) -> Result<u32, KernelError> {
    open_or_create_key(false, output, desired, attributes, 0, 0, options, 0, previous_mode)
}

/// NtCreateKey.
#[allow(clippy::too_many_arguments)]
pub fn create(output: u64, desired: u32, attributes: u64, title_index: u32, class_name: u64, options: u32, disposition: u64, previous_mode: bool) -> Result<u32, KernelError> {
    open_or_create_key(true, output, desired, attributes, title_index, class_name, options, disposition, previous_mode)
}
