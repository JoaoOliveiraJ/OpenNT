//! Identidade e vida dos objetos de espera e conclusão.
//!
//! Handles e ponteiros retêm o mesmo corpo dono. O dono entrega `dispose`
//! (libera os recursos reais) e, opcionalmente, `busy` (impede a coleta
//! enquanto houver trabalho externo) e os ganchos de handle.
//!
//! `publish` entrega o corpo como handle do processo pela tabela de
//! handles de usuário.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;

use crate::ntos::ob::object_manager::{ObjectData, ObjectHooks};
use crate::ntos::ob::object_types::{self, ObjectType};
use crate::ntos::ob::open_pointer::{self, ObjectOwner, Slot};
use crate::ntos::ob::object_access;
use crate::ntos::ex::callback_security;
use crate::ntos::mm::section::create as create_section;
use crate::ntos::se::model::SecurityPolicy;
use crate::ntos::se::token::tokens;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

/// Ganchos do dono do objeto.
#[derive(Clone, Copy, Default)]
pub struct DispatcherHooks {
    /// Verificação antes de cada handle (`beforeHandleOpen`).
    pub before_handle_open: Option<fn(u64) -> Result<(), KernelError>>,
    /// Último handle fechado (`onLastHandleClose`).
    pub on_last_handle_close: Option<fn(u64)>,
}

struct Body {
    kind: String,
    object_type: ObjectType,
    security: SecurityPolicy,
    refs: u32,
    handles: u32,
    /// Contagens espelhadas no próprio corpo (+0 referências, +8 handles).
    mirror: bool,
    dispose: fn(u64),
    busy: Option<fn(u64) -> bool>,
    hooks: DispatcherHooks,
}

static BODIES: SpinLock<BTreeMap<u64, Body>> = SpinLock::new(BTreeMap::new());

fn status(code: u32) -> KernelError {
    KernelError::with_status(alloc::format!("dispatcher object status {code:x}"), code)
}

struct DispatcherOwner;

static OWNER: DispatcherOwner = DispatcherOwner;

impl ObjectOwner for DispatcherOwner {
    fn object_type(&self, pointer: u64) -> ObjectType {
        BODIES.lock().get(&pointer).map(|body| body.object_type.clone()).unwrap_or_else(object_types::event_type)
    }
    fn reference(&self, pointer: u64) {
        let _ = reference(pointer);
    }
    fn dereference(&self, pointer: u64) {
        let _ = dereference(pointer);
    }
    fn open_handle(&self, pointer: u64) -> Option<Result<(), KernelError>> {
        Some(open(pointer))
    }
    fn close_handle(&self, pointer: u64) -> Option<Result<(), KernelError>> {
        Some(close(pointer))
    }
    fn security(&self, pointer: u64) -> SecurityPolicy {
        security(pointer).unwrap_or_default()
    }
    fn data(&self, pointer: u64) -> ObjectData {
        data(pointer)
    }
    fn query_record(&self, pointer: u64) -> crate::ntos::ob::open_pointer::QueryRecord {
        let (handles, references) = BODIES.lock().get(&pointer).map_or((0, 0), |body| (body.handles, body.refs));
        crate::ntos::ob::open_pointer::QueryRecord { handles: Some(handles), references, permanent: false, name: crate::ntos::ob::open_pointer::namespace_path_of(pointer).unwrap_or_default() }
    }
}

/// Captura a política de segurança e registra o corpo. `attributes` é o
/// OBJECT_ATTRIBUTES (SecurityDescriptor em +32; zero = política do sujeito).
pub fn create(pointer: u64, kind: &str, dispose: fn(u64), busy: Option<fn(u64) -> bool>, attributes: u64, from_user_mode: bool, hooks: DispatcherHooks) -> Result<u64, KernelError> {
    let object_type = if kind == "event" { Some(object_types::event_type()) } else { object_types::user_type(kind) };
    let Some(object_type) = object_type.filter(|_| !BODIES.lock().contains_key(&pointer)) else {
        return Err(KernelError::new("invalid dispatcher object registration"));
    };
    let subject = object_access::subject();
    let descriptor = if attributes != 0 { guest::read64(attributes + 32) } else { 0 };
    if descriptor != 0 && from_user_mode && !create_section::descriptor_probe(descriptor) {
        return Err(status(0xC000_0005));
    }
    let policy = if descriptor != 0 { callback_security::capture(descriptor).map_err(status)? } else { object_access::capture(subject) };
    if from_user_mode && policy.sacl.is_some() {
        let privileged = subject.and_then(|token| tokens::with(token, |token| token.privileges.iter().any(|privilege| privilege.id == 8 && privilege.attributes & 2 != 0))).unwrap_or(false);
        if !privileged {
            return Err(status(0xC000_0061));
        }
    }
    object_types::bind_native(pointer, &object_type.name)?;
    BODIES.lock().insert(pointer, Body { kind: String::from(kind), object_type, security: policy, refs: 0, handles: 0, mirror: false, dispose, busy, hooks });
    open_pointer::register_owner(Slot::Dispatcher, |pointer| BODIES.lock().contains_key(&pointer), &OWNER);
    Ok(pointer)
}

fn assert_live(pointer: u64) -> Result<(), KernelError> {
    if BODIES.lock().contains_key(&pointer) { Ok(()) } else { Err(KernelError::new("dispatcher object has been released")) }
}

/// Libera o corpo só sem referências, handles e ocupação externa.
pub fn collect(pointer: u64) {
    let dispose = {
        let bodies = BODIES.lock();
        let Some(body) = bodies.get(&pointer) else { return };
        if body.refs != 0 || body.handles != 0 {
            return;
        }
        (body.busy, body.dispose)
    };
    if dispose.0.is_some_and(|busy| busy(pointer)) {
        return;
    }
    if BODIES.lock().remove(&pointer).is_none() {
        return;
    }
    object_types::unbind_native(pointer);
    (dispose.1)(pointer);
}

/// Escreve as contagens no corpo quando o registro as mantém nele.
fn mirror(pointer: u64, body: &Body) {
    if body.mirror {
        guest::write64(pointer, body.refs as u64);
        guest::write32(pointer + 8, body.handles);
    }
}

/// O registro passa a manter referências e handles no corpo (+0/+8).
pub fn mirror_counts(pointer: u64) {
    if let Some(body) = BODIES.lock().get_mut(&pointer) {
        body.mirror = true;
        mirror(pointer, body);
    }
}

pub fn reference(pointer: u64) -> Result<u32, KernelError> {
    let mut bodies = BODIES.lock();
    let body = bodies.get_mut(&pointer).ok_or_else(|| KernelError::new("dispatcher object has been released"))?;
    body.refs += 1;
    mirror(pointer, body);
    Ok(body.refs)
}

/// O último ponteiro não pode sumir enquanto um handle possui o corpo.
pub fn dereference(pointer: u64) -> Result<u32, KernelError> {
    let remaining = {
        let mut bodies = BODIES.lock();
        let body = bodies.get_mut(&pointer).ok_or_else(|| KernelError::new("dispatcher object has been released"))?;
        if body.refs == 0 {
            return Err(KernelError::new("dispatcher object reference underflow"));
        }
        if body.refs == 1 && body.handles != 0 {
            return Err(KernelError::new("dispatcher object last reference still owned by handle"));
        }
        body.refs -= 1;
        mirror(pointer, body);
        body.refs
    };
    collect(pointer);
    Ok(remaining)
}

/// Verificação do dono, retenção e mais um handle.
pub fn open(pointer: u64) -> Result<(), KernelError> {
    assert_live(pointer)?;
    let (hooks, type_name) = BODIES.lock().get(&pointer).map(|body| (body.hooks, body.object_type.name.clone())).unwrap();
    if let Some(before) = hooks.before_handle_open {
        before(pointer)?;
    }
    reference(pointer)?;
    if let Some(body) = BODIES.lock().get_mut(&pointer) {
        body.handles += 1;
        mirror(pointer, body);
    }
    object_types::account(&type_name, 0, 1)
}

/// Conta o fechamento, notifica o último handle e solta a referência.
pub fn close(pointer: u64) -> Result<(), KernelError> {
    let (last, hooks, type_name) = {
        let mut bodies = BODIES.lock();
        let body = bodies.get_mut(&pointer).ok_or_else(|| KernelError::new("dispatcher object has been released"))?;
        if body.handles == 0 {
            return Err(KernelError::new("dispatcher object handle underflow"));
        }
        body.handles -= 1;
        mirror(pointer, body);
        (body.handles == 0, body.hooks, body.object_type.name.clone())
    };
    let _ = object_types::account(&type_name, 0, -1);
    if last {
        if let Some(notify) = hooks.on_last_handle_close {
            notify(pointer);
        }
    }
    dereference(pointer).map(|_| ())
}

/// Ganchos de handle para aberturas pelo namespace (o `onHandleOpen` do original).
struct DispatcherHandle {
    pointer: u64,
}

impl ObjectHooks for DispatcherHandle {
    fn on_handle_open(&self) -> Result<(), KernelError> {
        open(self.pointer)
    }
    fn on_handle_close(&self) {
        let _ = close(self.pointer);
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

/// Dados públicos do corpo, com os ganchos que retêm o mesmo objeto.
pub fn data(pointer: u64) -> ObjectData {
    ObjectData { native_pointer: pointer, hooks: Some(Arc::new(DispatcherHandle { pointer })), ..ObjectData::default() }
}

/// Política definida pelo criador (`port.security = policy`).
pub fn set_security(pointer: u64, policy: SecurityPolicy) {
    if let Some(body) = BODIES.lock().get_mut(&pointer) {
        body.security = policy;
    }
}

pub fn security(pointer: u64) -> Option<SecurityPolicy> {
    BODIES.lock().get(&pointer).map(|body| body.security.clone())
}

/// (tipo do objeto, referências, handles) de um corpo vivo.
pub fn get(pointer: u64) -> Option<(String, u32, u32)> {
    BODIES.lock().get(&pointer).map(|body| (body.kind.clone(), body.refs, body.handles))
}

/// Handle de usuário de um corpo de despacho (`{ ...body.data, type: kind }`),
/// com o objeto do dono (evento, semáforo...) como carga.
pub struct UserDispatcher {
    pub pointer: u64,
    pub kind: &'static str,
    pub payload: Option<Arc<dyn core::any::Any + Send + Sync>>,
}

impl crate::ntos::ps::user::state::UserObject for UserDispatcher {
    fn kind(&self) -> &'static str {
        self.kind
    }
    fn native_body(&self) -> Option<crate::ntos::ps::user::state::NativeBody> {
        let pointer = self.pointer;
        let type_name = BODIES.lock().get(&pointer).map(|body| body.object_type.name.clone())?;
        Some(crate::ntos::ps::user::state::NativeBody {
            pointer,
            type_name,
            record: pointer,
            reference: Arc::new(move || {
                let _ = reference(pointer);
            }),
            dereference: Arc::new(move || {
                let _ = dereference(pointer);
            }),
        })
    }
    fn on_each_handle_open(&self) -> Result<bool, KernelError> {
        open(self.pointer)?;
        Ok(true)
    }
    /// Portas, pacotes de espera e fábricas não expõem o campo de espera.
    fn wait_pointer(&self) -> Option<u64> {
        (!matches!(self.kind, "completion" | "waitpacket" | "workerfactory")).then_some(self.pointer)
    }
    fn security(&self) -> Option<SecurityPolicy> {
        security(self.pointer)
    }
    fn on_each_handle_close(&self) {
        let _ = close(self.pointer);
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

fn static_kind(kind: &str) -> &'static str {
    match kind {
        "event" => "event",
        "semaphore" => "semaphore",
        "mutant" => "mutant",
        "timer" => "timer",
        "keyedevent" => "keyedevent",
        "completion" => "completion",
        "partition" => "partition",
        "waitpacket" => "waitpacket",
        "workerfactory" => "workerfactory",
        "alpc" => "alpc",
        "port" => "port",
        _ => "dispatcher",
    }
}

/// Verifica os direitos e publica um handle de usuário com os ganchos do
/// corpo; recusa coleta o corpo e uma falha ao gravar a saída desfaz o handle.
pub fn publish(pointer: u64, output: u64, desired: u32, attributes: u32, success: u32, creating: bool, payload: Option<Arc<dyn core::any::Any + Send + Sync>>) -> Result<u32, KernelError> {
    let Some((kind, object_type, policy)) = BODIES.lock().get(&pointer).map(|body| (body.kind.clone(), body.object_type.clone(), body.security.clone())) else { return Err(KernelError::new("dispatcher object has been released")) };
    let access = match object_access::check(&policy, object_access::subject(), desired, &object_type, creating) {
        Ok(access) => access,
        Err(status) => {
            collect(pointer);
            return Ok(status);
        }
    };
    let object = Arc::new(UserDispatcher { pointer, kind: static_kind(&kind), payload });
    let handle = match crate::ntos::ps::user::state::alloc_user_handle(object, access, attributes & 2) {
        Ok(handle) => handle,
        Err(error) => {
            collect(pointer);
            return if error.status != 0 { Ok(error.status) } else { Err(error) };
        }
    };
    if let Err(error) = guest::try_write64(output, handle as u64) {
        let _ = crate::ntos::ps::user::state::close_user_handle(handle as u64, false, true);
        return if error.status != 0 { Ok(error.status) } else { Err(error) };
    }
    Ok(success)
}
