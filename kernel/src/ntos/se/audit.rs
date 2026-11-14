//! Auditoria de segurança: os eventos que os drivers reportam ao Security
//! Reference Monitor.
//!
//! Não há serviço de eventlog em modo usuário: os eventos ficam num anel do
//! kernel (os mais antigos saem) e são ecoados na serial.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::mem::offset_of;

use crate::ntos::inc::types::{AccessAllowedAce, AccessState, AceHeader, Acl, AuxAccessData, Guid, NtStruct, PrivilegeSet, SecuritySubjectContext};
use crate::ntos::ke::clock;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{get_object_type, object_types};
use crate::ntos::rtl::guest_strings;
use crate::ntos::se::token::tokens;
use crate::ntos::se::{descriptor, out, sid};
use crate::rtl::SpinLock;

/// Evento de auditoria gravado no anel.
#[derive(Clone, Debug)]
pub struct AuditEvent {
    pub kind: &'static str,
    pub detail: String,
    pub at_ms: u64,
}

const AUDIT_RING_LIMIT: usize = 256;
static AUDIT_RING: SpinLock<VecDeque<AuditEvent>> = SpinLock::new(VecDeque::new());

/// Consulta interna (eventlog/depuração futuros): os eventos gravados.
pub fn events() -> Vec<AuditEvent> {
    AUDIT_RING.lock().iter().cloned().collect()
}

fn record_audit_event(kind: &'static str, detail: String) {
    let line = if detail.is_empty() { format!("[se-audit] {kind}") } else { format!("[se-audit] {kind}: {detail}") };
    let mut ring = AUDIT_RING.lock();
    ring.push_back(AuditEvent { kind, detail, at_ms: clock::now_ms() });
    if ring.len() > AUDIT_RING_LIMIT {
        ring.pop_front();
    }
    drop(ring);
    debug_print!("{}", line);
}

/// SeSetAuditParameter: registra tipo, categoria e endereço; não copia o
/// conteúdo apontado.
pub fn set_audit_parameter(kind: u32, category: u32, parameters: u32) {
    record_audit_event("SetAuditParameter", format!("type={} category={} params={:#x}", kind, category, parameters));
}

/// SeReportSecurityEventWithSubCategory: registra a categoria.
pub fn report_security_event(category: u32) {
    record_audit_event("SecurityEvent", format!("category={}", category));
}

/// SeAuditFipsCryptoSelftests: o cng audita o resultado dos selftests FIPS
/// por aqui.
pub fn fips_crypto_selftests(general: u32, causing: u32, extra: u32) {
    record_audit_event("FipsCryptoSelftest", format!("general={} causing={} extra={:#x}", general, causing, extra));
}

// ---- Política de auditoria e alarmes de auditoria de objeto ------------------
//
// Como na auditoria do Se do NT. Contrato, conferido contra o
// ntoskrnl 19041:
// - A política vive em `SeAuditingState` (rva 0xc1d5a0: 64 subcategorias a
//   partir do id 100, um byte de sucesso e um de falha cada) e em
//   `SeAuditingStateByCategory` (rva 0xc1d560: máscara por categoria, 0x03 =
//   sucesso, 0x30 = falha). No NT o LSA empurra a política pelo
//   `SeRmCommandPort`; o OpenNT não tem LSA nem esse comando, então a tabela
//   fica no estado de boot anterior ao push — toda zerada — e os portões
//   abaixo respondem como o NT responde nesse estado.
// - A política por usuário (`SepTokenPolicyCounter*`) só é consultada quando
//   algum token carrega política própria; os tokens do OpenNT não carregam,
//   então os contadores são zero e esse ramo do NT nunca é tomado.
// - Quando um portão abre, o registro vai para o anel de auditoria acima, que
//   faz o papel do `SepAdtLogAuditRecord` sem LSA/event log.
// - ACCESS_STATE, AUX_ACCESS_DATA, descritores e GUIDs vêm de chamadores de
//   kernel (o ntfs), então não são sondados.

const FIRST_SUBCATEGORY: u32 = 100;
const SUBCATEGORY_COUNT: usize = 64;
const CATEGORY_COUNT: usize = 16;
const CATEGORY_OBJECT_ACCESS: usize = 2;

const SUBCATEGORY_FILE_SYSTEM: u32 = 0x75;
const SUBCATEGORY_REGISTRY: u32 = 0x76;
const SUBCATEGORY_KERNEL_OBJECT: u32 = 0x77;
const SUBCATEGORY_SAM: u32 = 0x78;
const SUBCATEGORY_OTHER_OBJECT_ACCESS: u32 = 0x79;
const SUBCATEGORY_STAGING: u32 = 0x82;
const SUBCATEGORY_SENSITIVE_PRIVILEGE_USE: u32 = 0x83;
const SUBCATEGORY_NON_SENSITIVE_PRIVILEGE_USE: u32 = 0x84;

const SYSTEM_AUDIT_ACE_TYPE: u8 = 2;
const SYSTEM_ALARM_ACE_TYPE: u8 = 3;
const INHERIT_ONLY_ACE: u8 = 0x08;
const SUCCESSFUL_ACCESS_ACE_FLAG: u8 = 0x40;
const FAILED_ACCESS_ACE_FLAG: u8 = 0x80;
const SE_GROUP_ENABLED: u32 = 0x04;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// SeAuditingState + SeAuditingStateByCategory.
struct AuditPolicy {
    by_subcategory: [[bool; 2]; SUBCATEGORY_COUNT],
    by_category: [u32; CATEGORY_COUNT],
}

static POLICY: SpinLock<AuditPolicy> = SpinLock::new(AuditPolicy { by_subcategory: [[false; 2]; SUBCATEGORY_COUNT], by_category: [0; CATEGORY_COUNT] });

/// SepAuditingEnabledForSubcategory.
fn enabled_for_subcategory(subcategory: u32, success: bool, failure: bool) -> bool {
    let policy = POLICY.lock();
    let Some(state) = policy.by_subcategory.get(subcategory.wrapping_sub(FIRST_SUBCATEGORY) as usize) else { return false };
    (state[0] && success) || (state[1] && failure)
}

/// SepAdtAuditThisEventByCategoryWithContext (sem política por usuário).
fn audit_by_category(category: usize, mask: u32) -> bool {
    let state = POLICY.lock().by_category[category];
    state != 0 && state & mask != 0
}

/// Máscara de categoria do acesso a objetos: 0x03 sucesso, 0x30 falha.
fn object_access_mask(success: bool, failure: bool) -> u32 {
    (if success { 0x03 } else { 0 }) | if failure { 0x30 } else { 0 }
}

/// SepAdtAuditThisEventWithContext: ids até 8 são categorias inteiras.
fn audit_this_event(subcategory: u32, success: bool, failure: bool) -> bool {
    if subcategory <= 8 {
        return audit_by_category(subcategory as usize, success as u32 | if failure { 0x10 } else { 0 });
    }
    enabled_for_subcategory(subcategory, success, failure)
}

/// SepAdtClassifyObjectIntoSubCategory. Armazenamento removível (0x81) só é
/// distinguido com essa subcategoria ligada e SepIsRemovableStorageDevice;
/// o OpenNT não marca volumes removíveis para a auditoria, então esses
/// objetos ficam na classe comum (0x75 para File).
fn classify(object: u64, type_name: u64) -> u32 {
    let name = if object != 0 {
        get_object_type::get(object).ok().and_then(object_types::find).map(|object_type| object_type.name)
    } else if type_name != 0 {
        guest_strings::try_read_unicode_string(type_name).ok()
    } else {
        None
    };
    match name.as_deref() {
        Some("File") => SUBCATEGORY_FILE_SYSTEM,
        Some("Key") => SUBCATEGORY_REGISTRY,
        _ => SUBCATEGORY_KERNEL_OBJECT,
    }
}

/// SepAdtAuditObjectAccessWithContext: portão da categoria de acesso a
/// objetos e, aberto, o da subcategoria do objeto.
fn audit_object_access(object: u64, type_name: u64, success: bool, failure: bool, kernel_object: bool) -> Option<u32> {
    if !audit_by_category(CATEGORY_OBJECT_ACCESS, object_access_mask(success, failure)) {
        return None;
    }
    let subcategory = if object == 0 && !kernel_object {
        let sam = type_name != 0 && guest_strings::try_read_unicode_string(type_name).is_ok_and(|name| name.starts_with("SAM"));
        if sam { SUBCATEGORY_SAM } else { SUBCATEGORY_OTHER_OBJECT_ACCESS }
    } else {
        classify(object, type_name)
    };
    audit_this_event(subcategory, success, failure).then_some(subcategory)
}

/// SepAdtAuditPrivilegeUseWithContext: subcategorias de uso de privilégio.
fn audit_privilege_use(success: bool, failure: bool) -> bool {
    enabled_for_subcategory(SUBCATEGORY_SENSITIVE_PRIVILEGE_USE, success, failure) || enabled_for_subcategory(SUBCATEGORY_NON_SENSITIVE_PRIVILEGE_USE, success, failure)
}

/// Token efetivo do sujeito: ClientToken, senão PrimaryToken.
fn subject_token(subject: &SecuritySubjectContext) -> u64 {
    let client = subject.client_token.get();
    if client != 0 { client } else { subject.primary_token.get() }
}

/// SACL de um SECURITY_DESCRIPTOR (absoluto ou self-relative), se houver.
fn sacl_of(descriptor: u64) -> u64 {
    descriptor::component(descriptor, descriptor::control(descriptor), 2)
}

fn ace_count(acl: u64) -> u16 {
    // SAFETY: componente SACL de um descritor de kernel (PACL alinhada a WORD).
    unsafe { Acl::at(acl) }.ace_count.get()
}

/// SeExamineSacl: ACEs de auditoria/alarme que casam com o token, com os
/// acessos pedidos e com o resultado (sucesso/falha). As ACEs podem ficar
/// desalinhadas, então são lidas pelo offset do layout (KNOWN_ACE).
fn examine_sacl(sacl: u64, token: u64, accesses: u32, granted: bool) -> (bool, bool) {
    if sacl == 0 {
        return (false, false);
    }
    let Some((user, groups)) = tokens::with(token, |token| (token.user.clone(), token.groups.iter().map(|group| (group.sid.clone(), group.attributes)).collect::<Vec<_>>())) else {
        return (false, false);
    };
    let wanted = if granted { SUCCESSFUL_ACCESS_ACE_FLAG } else { FAILED_ACCESS_ACE_FLAG };
    let (mut audit, mut alarm) = (false, false);
    let mut cursor = sacl + Acl::SIZE;
    for _ in 0..ace_count(sacl) {
        let ace_type = guest::read::<u8>(cursor + offset_of!(AceHeader, ace_type) as u64);
        let flags = guest::read::<u8>(cursor + offset_of!(AceHeader, ace_flags) as u64);
        let size = guest::read::<u16>(cursor + offset_of!(AceHeader, ace_size) as u64) as u64;
        if size == 0 {
            break;
        }
        let mask = guest::read::<u32>(cursor + offset_of!(AccessAllowedAce, mask) as u64);
        if (ace_type == SYSTEM_AUDIT_ACE_TYPE || ace_type == SYSTEM_ALARM_ACE_TYPE) && flags & INHERIT_ONLY_ACE == 0 && flags & wanted != 0 && mask & accesses != 0 {
            let ace_sid = sid::read(cursor + offset_of!(AccessAllowedAce, sid_start) as u64);
            let member = ace_sid == user || groups.iter().any(|(group, attributes)| *group == ace_sid && attributes & (SE_GROUP_ENABLED | SE_GROUP_USE_FOR_DENY_ONLY) != 0);
            if member {
                audit |= ace_type == SYSTEM_AUDIT_ACE_TYPE;
                alarm |= ace_type == SYSTEM_ALARM_ACE_TYPE;
            }
        }
        cursor += size;
    }
    (audit, alarm)
}

fn name_of(pointer: u64) -> String {
    if pointer == 0 { String::new() } else { guest_strings::try_read_unicode_string(pointer).unwrap_or_default() }
}

fn guid_of(pointer: u64) -> String {
    if pointer == 0 {
        return String::from("{none}");
    }
    // SAFETY: GUID* de um chamador de kernel (TransactionId / RM id).
    let guid = unsafe { Guid::at(pointer) };
    let tail: String = guid.data4.iter().map(|byte| format!("{:02x}", byte.get())).collect();
    format!("{{{:08x}-{:04x}-{:04x}-{}}}", guid.data1.get(), guid.data2.get(), guid.data3.get(), tail)
}

/// SeAuditingAnyFileEventsWithContextEx(Sd, Subject, *StagingEnabled): o
/// descritor não é consultado e o Subject só serviria à política por
/// usuário; sucesso e falha juntos.
pub fn auditing_any_file_events(staging_enabled: u64) -> bool {
    if staging_enabled != 0 {
        out::<u8>(staging_enabled).set(audit_this_event(SUBCATEGORY_STAGING, true, true) as u8);
    }
    audit_this_event(SUBCATEGORY_FILE_SYSTEM, true, true) || audit_by_category(CATEGORY_OBJECT_ACCESS, object_access_mask(true, true))
}

/// SeAuditingFileEventsWithContextEx(AccessGranted, Sd, Subject, *StagingEnabled).
pub fn auditing_file_events(granted: bool, staging_enabled: u64) -> bool {
    if staging_enabled != 0 {
        out::<u8>(staging_enabled).set(audit_this_event(SUBCATEGORY_STAGING, granted, !granted) as u8);
    }
    audit_this_event(SUBCATEGORY_FILE_SYSTEM, granted, !granted) || audit_by_category(CATEGORY_OBJECT_ACCESS, object_access_mask(granted, !granted))
}

/// SeAuditingHardLinkEventsWithContext(AccessGranted, Sd, Subject): só com
/// SACL presente e não vazia, e a subcategoria de sistema de arquivos ligada.
pub fn auditing_hard_link_events(granted: bool, descriptor: u64) -> bool {
    let sacl = sacl_of(descriptor);
    sacl != 0 && ace_count(sacl) != 0 && audit_this_event(SUBCATEGORY_FILE_SYSTEM, granted, !granted)
}

/// SeAuditHardLinkCreationWithTransaction: o NT grava o evento 4664 sem
/// consultar a política (o chamador já perguntou com
/// SeAuditingHardLinkEventsWithContext).
pub fn audit_hard_link_creation(file_name: u64, link_name: u64, success: bool, transaction: u64) {
    record_audit_event("HardLinkCreation", format!("event=4664 file={} link={} success={} transaction={}", name_of(file_name), name_of(link_name), success, guid_of(transaction)));
}

/// SeAuditTransactionStateChange: evento 4985, gravado sem portão.
pub fn audit_transaction_state_change(transaction: u64, resource_manager: u64, new_state: u32) {
    record_audit_event("TransactionStateChange", format!("event=4985 transaction={} rm={} state={}", guid_of(transaction), guid_of(resource_manager), new_state));
}

/// SeDeleteObjectAuditAlarmWithTransaction(Object, Handle, TransactionId).
pub fn delete_object_audit_alarm(object: u64, handle: u64, transaction: u64) {
    if audit_object_access(object, 0, true, false, true).is_some() {
        record_audit_event("DeleteObject", format!("event=4660 object={object:#x} handle={handle:#x} transaction={}", guid_of(transaction)));
    }
}

/// AUX_ACCESS_DATA do ACCESS_STATE (SeCreateAccessState sempre o liga).
fn aux_data(access_state: &AccessState) -> &'static AuxAccessData {
    // SAFETY: AccessState->AuxData aponta para o AUX_ACCESS_DATA do mesmo pedido.
    unsafe { AuxAccessData::at(access_state.aux_data.get()) }
}

/// Algum AccessReasons marcado para staging (bit 31).
fn staged_reasons(aux: &AuxAccessData) -> bool {
    aux.access_reasons.data.iter().any(|reason| (reason.get() as i32) < 0)
}

/// Uso de privilégio auditável: PrivilegesUsed com PrivilegeCount > 0.
fn privileges_used(aux: &AuxAccessData) -> bool {
    let used = aux.privileges_used.get();
    // SAFETY: PPRIVILEGE_SET do AUX_ACCESS_DATA.
    used != 0 && unsafe { PrivilegeSet::at(used) }.privilege_count.get() != 0
}

/// Acessos examinados na SACL: Remaining | PreviouslyGranted.
fn audited_accesses(access_state: &AccessState) -> u32 {
    access_state.remaining_desired_access.get() | access_state.previously_granted_access.get()
}

/// SeOpenObjectAuditAlarmWithTransaction(TypeName, Object, AbsoluteName, Sd,
/// AccessState, ObjectCreated, AccessGranted, AccessMode, TransactionId,
/// *GenerateOnClose); ObjectCreated não muda a decisão. KernelMode não
/// audita. Com a política zerada só escreve GenerateStagingEvents (havendo
/// Sd) e GenerateAudit = FALSE.
#[allow(clippy::too_many_arguments)]
pub fn open_object_audit_alarm(type_name: u64, object: u64, object_name: u64, descriptor: u64, access_state: &AccessState, granted: bool, mode: u8, transaction: u64, generate_on_close: u64) {
    if mode == 0 {
        return;
    }
    let aux = aux_data(access_state);
    let (mut generate_audit, mut generate_alarm) = (false, false);
    if descriptor != 0 {
        if audit_by_category(CATEGORY_OBJECT_ACCESS, object_access_mask(granted, !granted)) && audit_this_event(classify(object, type_name), granted, !granted) {
            (generate_audit, generate_alarm) = examine_sacl(sacl_of(descriptor), subject_token(&access_state.subject_security_context), audited_accesses(access_state), granted);
            if generate_audit && generate_on_close != 0 {
                out::<u8>(generate_on_close).set(1);
            }
        }
        let maximum_allowed = access_state.original_desired_access.get() & MAXIMUM_ALLOWED != 0;
        let staging = staged_reasons(aux) && audit_this_event(SUBCATEGORY_STAGING, !maximum_allowed && granted, maximum_allowed || !granted);
        aux.generate_staging_events.set(staging as u8);
    }
    if granted && privileges_used(aux) && audit_privilege_use(true, false) {
        access_state.audit_privileges.set(1);
        generate_audit = true;
    }
    let generate = generate_audit || generate_alarm;
    access_state.generate_audit.set(generate as u8);
    if generate || aux.generate_staging_events.get() != 0 {
        record_audit_event("OpenObject", format!("event=4656 type={} name={} granted={} transaction={}", name_of(type_name), name_of(object_name), granted, guid_of(transaction)));
    }
}

/// SeOpenObjectForDeleteAuditAlarmWithTransaction: mesmos parâmetros; com o
/// portão fechado não escreve nada (nem GenerateAudit).
#[allow(clippy::too_many_arguments)]
pub fn open_object_for_delete_audit_alarm(type_name: u64, object: u64, object_name: u64, descriptor: u64, access_state: &AccessState, granted: bool, mode: u8, transaction: u64, generate_on_close: u64) {
    if mode == 0 {
        return;
    }
    let aux = aux_data(access_state);
    let (mut generate_audit, mut generate_alarm) = (false, false);
    if descriptor != 0 && audit_object_access(object, type_name, granted, !granted, true).is_some() {
        (generate_audit, generate_alarm) = examine_sacl(sacl_of(descriptor), subject_token(&access_state.subject_security_context), audited_accesses(access_state), granted);
    }
    if granted && privileges_used(aux) && audit_privilege_use(true, false) {
        access_state.audit_privileges.set(1);
        generate_audit = true;
    }
    if generate_audit || generate_alarm {
        access_state.generate_audit.set(1);
        if generate_audit && generate_on_close != 0 {
            out::<u8>(generate_on_close).set(1);
        }
        record_audit_event("OpenObjectForDelete", format!("event=4656 type={} name={} granted={} transaction={}", name_of(type_name), name_of(object_name), granted, guid_of(transaction)));
    }
}

/// SePrivilegeObjectAuditAlarm(Handle, SubjectSecurityContext,
/// DesiredAccess, Privileges, AccessGranted, AccessMode): como no NT, só um
/// pedido vindo do modo usuário gera o evento (o
/// SepAdtPrivilegeObjectAuditAlarm com o subsistema "Security"): o handle, o
/// acesso pedido, a quantidade de privilégios usados e se foi concedido.
/// Devolve se o evento foi gerado.
pub fn privilege_object_audit_alarm(handle: u64, desired_access: u32, privileges: u64, granted: bool, mode: u8) -> bool {
    if mode == 0 {
        return false;
    }
    let count = if privileges != 0 {
        // SAFETY: o PPRIVILEGE_SET do chamador de kernel.
        unsafe { PrivilegeSet::at(privileges) }.privilege_count.get()
    } else {
        0
    };
    record_audit_event("privileged object operation", format!("handle={handle:#x} access={desired_access:#x} privileges={count} granted={granted}"));
    true
}

/// SeOpenObjectAuditAlarmForNonObObject(SubsystemName, HandleId,
/// ObjectTypeName, ObjectName, Sd, SubjectContext, DesiredAccess,
/// GrantedAccess, Privileges, AccessGranted, *GenerateOnClose): o alarme de
/// abertura de um objeto que não é do Object Manager (uma reserva de portas
/// do TCP/IP, por exemplo). Como no ntoskrnl 19041 (rva 0x7d2580): com a
/// subcategoria de objeto do kernel aberta para o resultado, examina a SACL
/// do descritor com os acessos pedidos e concedidos (a SACL global não
/// existe no OpenNT); uma auditoria gerada grava o evento 4656 e liga
/// *GenerateOnClose. Com o portão fechado, um acesso concedido com
/// privilégios usados gera o alarme de uso de privilégio sobre o objeto
/// (evento 4674), se essa auditoria estiver ligada.
#[allow(clippy::too_many_arguments)]
pub fn open_object_audit_alarm_for_non_ob_object(subsystem: u64, handle_id: u64, type_name: u64, object_name: u64, descriptor: u64, subject: &SecuritySubjectContext, desired: u32, granted_access: u32, privileges: u64, granted: bool, generate_on_close: u64) {
    if audit_this_event(SUBCATEGORY_KERNEL_OBJECT, granted, !granted) {
        let sacl = if descriptor != 0 { sacl_of(descriptor) } else { 0 };
        let (generate_audit, _) = examine_sacl(sacl, subject_token(subject), desired | granted_access, granted);
        if generate_audit {
            record_audit_event("OpenObject", format!("event=4656 subsystem={} handle={:#x} type={} name={} desired={:#x} granted={}", name_of(subsystem), handle_id, name_of(type_name), name_of(object_name), desired, granted));
            out::<u8>(generate_on_close).set(1);
        }
        return;
    }
    if privileges != 0 && granted && audit_privilege_use(true, false) {
        record_audit_event("PrivilegeObject", format!("event=4674 subsystem={} handle={:#x} type={} name={} desired={:#x}", name_of(subsystem), handle_id, name_of(type_name), name_of(object_name), desired));
    }
}
