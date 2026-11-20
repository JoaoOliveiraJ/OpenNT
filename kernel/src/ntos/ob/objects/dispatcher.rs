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
use crate::ntos::ob::shared_policy::{self, SharedPolicy};
use crate::ntos::mm::section::create as create_section;
use crate::ntos::se::model::SecurityPolicy;
use crate::ntos::se::token::tokens;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::ObjectAttributes;
use crate::ntos::mm::guest_memory as guest;

/// Início comum dos corpos privados que espelham as contagens do registro:
/// referências em +0 e handles em +8 (o resto é do corpo de cada tipo).
#[repr(C)]
pub struct MirroredCounts {
    pub references: Field<u64>,
    pub handles: Field<u32>,
    _body: Reserved<4>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for MirroredCounts {}

const _: () = assert!(core::mem::size_of::<MirroredCounts>() == 0x10);

/// Ganchos do dono do objeto.
#[derive(Clone, Copy, Default)]
pub struct DispatcherHooks {
    /// Verificação antes de cada handle.
    pub before_handle_open: Option<fn(u64) -> Result<(), KernelError>>,
    /// Último handle fechado.
    pub on_last_handle_close: Option<fn(u64)>,
}

struct Body {
    kind: &'static str,
    /// O tipo, dividido por todos os corpos dele.
    object_type: Arc<ObjectType>,
    /// O descritor, dividido entre corpos com a mesma política
    /// (`ob/shared_policy.rs`, o ObLogSecurityDescriptor). `None` é o
    /// SecurityDescriptor nulo do NT: objeto sem nome, criado sem descritor,
    /// num tipo sem SecurityRequired; nada é guardado, a abertura por
    /// ponteiro e o ObCheckObjectAccess concedem o pedido sem SeAccessCheck,
    /// a consulta devolve o descritor vazio e o NtSetSecurityObject dá
    /// STATUS_NO_SECURITY_ON_OBJECT.
    security: Option<SharedPolicy>,
    refs: u32,
    handles: u32,
    /// Contagens espelhadas no próprio corpo (+0 referências, +8 handles).
    mirror: bool,
    dispose: fn(u64),
    busy: Option<fn(u64) -> bool>,
    hooks: DispatcherHooks,
}

static BODIES: SpinLock<BTreeMap<u64, Body>> = SpinLock::new(BTreeMap::new());

/// Os tipos dos corpos, um registro por OBJECT_TYPE.
static TYPES: SpinLock<alloc::vec::Vec<Arc<ObjectType>>> = SpinLock::new(alloc::vec::Vec::new());

/// O registro dividido do tipo `object_type`.
fn shared_type(object_type: ObjectType) -> Arc<ObjectType> {
    let mut types = TYPES.lock();
    if let Some(known) = types.iter().find(|known| known.pointer == object_type.pointer) {
        return known.clone();
    }
    let known = Arc::new(object_type);
    types.push(known.clone());
    known
}

fn status(code: u32) -> KernelError {
    KernelError::with_status(alloc::format!("dispatcher object status {code:x}"), code)
}

struct DispatcherOwner;

static OWNER: DispatcherOwner = DispatcherOwner;

impl ObjectOwner for DispatcherOwner {
    fn object_type(&self, pointer: u64) -> ObjectType {
        BODIES.lock().get(&pointer).map(|body| ObjectType::clone(&body.object_type)).unwrap_or_else(object_types::event_type)
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
    fn set_security(&self, pointer: u64, security: SecurityPolicy) -> bool {
        replace_security(pointer, security)
    }
    fn has_descriptor(&self, pointer: u64) -> bool {
        has_descriptor(pointer)
    }
    fn data(&self, pointer: u64) -> ObjectData {
        data(pointer)
    }
    fn query_record(&self, pointer: u64) -> crate::ntos::ob::open_pointer::QueryRecord {
        let (handles, references) = BODIES.lock().get(&pointer).map_or((0, 0), |body| (body.handles, body.refs));
        crate::ntos::ob::open_pointer::QueryRecord { handles: Some(handles), references, permanent: false, name: crate::ntos::ob::open_pointer::namespace_path_of(pointer).unwrap_or_default() }
    }
}

/// Um campo do OBJECT_ATTRIBUTES (ou do UNICODE_STRING do nome) do
/// chamador: de modo usuário vem sondado.
fn caller_read<T: guest::GuestScalar>(address: u64, from_user_mode: bool) -> Result<T, KernelError> {
    if from_user_mode { guest::try_read::<T>(address).map_err(|_| status(0xC000_0005)) } else { Ok(guest::read::<T>(address)) }
}

/// Atribui o descritor e registra o corpo. `attributes` é o
/// OBJECT_ATTRIBUTES (SecurityDescriptor em +32; zero = política do sujeito).
///
/// Como o ObInsertObjectEx do 19041 (0x652192..0x6521b7 confere o
/// SecurityRequired do TypeInfo, o nome e o SecurityDescriptor do
/// ObjectCreateInfo; sem os três, 0x6521bd..0x652201 vai direto ao
/// ObpCreateHandle, sem SeAssignSecurity), um objeto sem nome (ObjectName
/// ausente ou vazio), sem descritor explícito e de um tipo sem
/// SecurityRequired fica sem descritor e nada da política do sujeito é
/// guardado. Os outros recebem o descritor do SeAssignSecurity, dividido
/// entre corpos iguais.
pub fn create(pointer: u64, kind: &'static str, dispose: fn(u64), busy: Option<fn(u64) -> bool>, attributes: u64, from_user_mode: bool, hooks: DispatcherHooks) -> Result<u64, KernelError> {
    let object_type = if kind == "event" { Some(object_types::event_type()) } else { object_types::user_type(kind) };
    let Some(object_type) = object_type.filter(|_| !BODIES.lock().contains_key(&pointer)) else {
        return Err(KernelError::new("invalid dispatcher object registration"));
    };
    let subject = object_access::subject();
    let (descriptor, named) = if attributes != 0 {
        let descriptor = caller_read::<u64>(attributes + core::mem::offset_of!(ObjectAttributes, security_descriptor) as u64, from_user_mode)?;
        let name = caller_read::<u64>(attributes + core::mem::offset_of!(ObjectAttributes, object_name) as u64, from_user_mode)?;
        // UNICODE_STRING.Length em +0.
        let named = name != 0 && caller_read::<u16>(name, from_user_mode)? != 0;
        (descriptor, named)
    } else {
        (0, false)
    };
    let no_descriptor = descriptor == 0 && !named && !object_types::security_required(&object_type);
    if descriptor != 0 && from_user_mode && !create_section::descriptor_probe(descriptor) {
        return Err(status(0xC000_0005));
    }
    // O SeAssignSecurity do objeto novo: o descritor explícito sobre o dono,
    // o grupo e a DACL padrão do token efetivo (a herança do diretório entra
    // quando o nome é publicado).
    let policy = if descriptor != 0 {
        Some(crate::ntos::ob::object_security::assign_new(&object_type, None, descriptor, from_user_mode).map_err(status)?)
    } else if no_descriptor {
        None
    } else {
        Some(object_access::capture(subject))
    };
    if from_user_mode && policy.as_ref().and_then(|policy| policy.sacl.as_deref()).is_some_and(crate::ntos::se::model::sacl_requires_security_privilege) {
        let privileged = subject.and_then(|token| tokens::with(token, |token| token.privileges.iter().any(|privilege| privilege.id == 8 && privilege.attributes & 2 != 0))).unwrap_or(false);
        if !privileged {
            return Err(status(0xC000_0061));
        }
    }
    object_types::bind_native(pointer, &object_type.name)?;
    let (object_type, security) = (shared_type(object_type), policy.map(shared_policy::share));
    BODIES.lock().insert(pointer, Body { kind, object_type, security, refs: 0, handles: 0, mirror: false, dispose, busy, hooks });
    open_pointer::register_owner(Slot::Dispatcher, |pointer| BODIES.lock().contains_key(&pointer), &OWNER);
    Ok(pointer)
}

/// O objeto vai ganhar um nome que não veio no OBJECT_ATTRIBUTES (os
/// objetos nomeados do próprio kernel, logo depois do [`create`] e no mesmo
/// contexto): como no ObInsertObjectEx de um objeto nomeado, ele passa a ter
/// o descritor do sujeito (a herança do diretório entra com o nome).
pub fn mark_named(pointer: u64) {
    if BODIES.lock().get(&pointer).is_none_or(|body| body.security.is_some()) {
        return;
    }
    let policy = shared_policy::share(object_access::capture(object_access::subject()));
    let previous = BODIES.lock().get_mut(&pointer).and_then(|body| body.security.replace(policy));
    drop(previous);
}

/// O corpo tem descritor de segurança (falso para o SecurityDescriptor nulo
/// do NT).
pub fn has_descriptor(pointer: u64) -> bool {
    BODIES.lock().get(&pointer).is_none_or(|body| body.security.is_some())
}

/// Troca o descritor de um corpo vivo pela cópia dividida de `policy`;
/// `false` sem o corpo. A cópia anterior cai fora da trava dos corpos.
fn replace_security(pointer: u64, policy: SecurityPolicy) -> bool {
    let policy = shared_policy::share(policy);
    let previous = BODIES.lock().get_mut(&pointer).map(|body| body.security.replace(policy));
    previous.is_some()
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
        // SAFETY: corpo vivo registrado pelo dono, com as contagens no início.
        let counts = unsafe { MirroredCounts::at(pointer) };
        counts.references.set(body.refs as u64);
        counts.handles.set(body.handles);
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
    let (hooks, object_type) = BODIES.lock().get(&pointer).map(|body| (body.hooks, body.object_type.clone())).unwrap();
    if let Some(before) = hooks.before_handle_open {
        before(pointer)?;
    }
    reference(pointer)?;
    if let Some(body) = BODIES.lock().get_mut(&pointer) {
        body.handles += 1;
        mirror(pointer, body);
    }
    object_types::account(&object_type.name, 0, 1)
}

/// Conta o fechamento, notifica o último handle e solta a referência.
pub fn close(pointer: u64) -> Result<(), KernelError> {
    let (last, hooks, object_type) = {
        let mut bodies = BODIES.lock();
        let body = bodies.get_mut(&pointer).ok_or_else(|| KernelError::new("dispatcher object has been released"))?;
        if body.handles == 0 {
            return Err(KernelError::new("dispatcher object handle underflow"));
        }
        body.handles -= 1;
        mirror(pointer, body);
        (body.handles == 0, body.hooks, body.object_type.clone())
    };
    let _ = object_types::account(&object_type.name, 0, -1);
    if last {
        if let Some(notify) = hooks.on_last_handle_close {
            notify(pointer);
        }
    }
    dereference(pointer).map(|_| ())
}

/// Ganchos de handle para aberturas pelo namespace.
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

/// Política definida pelo criador (o objeto passa a ter descritor).
pub fn set_security(pointer: u64, policy: SecurityPolicy) {
    replace_security(pointer, policy);
}

/// Os dois corpos têm a mesma cópia dividida do descritor.
pub fn same_security(left: u64, right: u64) -> bool {
    let bodies = BODIES.lock();
    match (bodies.get(&left).and_then(|body| body.security.as_ref()), bodies.get(&right).and_then(|body| body.security.as_ref())) {
        (Some(left), Some(right)) => left.same(right),
        _ => false,
    }
}

/// O descritor do corpo como política; `None` sem o corpo ou sem descritor.
pub fn security(pointer: u64) -> Option<SecurityPolicy> {
    let shared = BODIES.lock().get(&pointer).and_then(|body| body.security.clone())?;
    Some(SecurityPolicy::clone(&shared))
}

/// O censo dos corpos vivos (o diagnóstico do `--heap-census`): por tipo,
/// quantos, quantos sem handle e as referências somadas.
pub fn census() -> alloc::vec::Vec<(&'static str, u32, u32, u32)> {
    let mut groups: BTreeMap<&'static str, (u32, u32, u32)> = BTreeMap::new();
    for body in BODIES.lock().values() {
        let group = groups.entry(body.kind).or_default();
        group.0 += 1;
        group.1 += (body.handles == 0) as u32;
        group.2 += body.refs;
    }
    groups.into_iter().map(|(kind, (count, unhandled, refs))| (kind, count, unhandled, refs)).collect()
}

/// (tipo do objeto, referências, handles) de um corpo vivo.
pub fn get(pointer: u64) -> Option<(String, u32, u32)> {
    BODIES.lock().get(&pointer).map(|body| (String::from(body.kind), body.refs, body.handles))
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

/// Verifica os direitos e publica um handle de usuário com os ganchos do
/// corpo; recusa coleta o corpo e uma falha ao gravar a saída desfaz o handle.
pub fn publish(pointer: u64, output: u64, desired: u32, attributes: u32, success: u32, creating: bool, payload: Option<Arc<dyn core::any::Any + Send + Sync>>) -> Result<u32, KernelError> {
    let Some((kind, object_type, security)) = BODIES.lock().get(&pointer).map(|body| (body.kind, body.object_type.clone(), body.security.clone())) else { return Err(KernelError::new("dispatcher object has been released")) };
    // Sem descritor, o ObpCreateHandle não passa pelo SeAccessCheck.
    let unchecked = SecurityPolicy::default();
    let access = match object_access::check(security.as_deref().unwrap_or(&unchecked), object_access::subject(), desired, &object_type, creating || security.is_none()) {
        Ok(access) => access,
        Err(status) => {
            collect(pointer);
            return Ok(status);
        }
    };
    let object = Arc::new(UserDispatcher { pointer, kind, payload });
    let handle = match crate::ntos::ps::user::state::alloc_user_handle(object, access, attributes & 2) {
        Ok(handle) => handle,
        Err(error) => {
            collect(pointer);
            return if error.status != 0 { Ok(error.status) } else { Err(error) };
        }
    };
    if let Err(error) = guest::try_write::<u64>(output, handle as u64) {
        let _ = crate::ntos::ps::user::state::close_user_handle(handle as u64, false, true);
        return if error.status != 0 { Ok(error.status) } else { Err(error) };
    }
    Ok(success)
}
