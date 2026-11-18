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

use crate::ntos::inc::types::{AccessAllowedAce, AccessState, AceHeader, Acl, AuxAccessData, Guid, NtStruct, ObjectAttributes, PrivilegeSet, SecuritySubjectContext};
use crate::ntos::ke::clock;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{get_object_type, object_types};
use crate::ntos::rtl::guest_strings;
use crate::ntos::se::token::tokens;
use crate::ntos::se::{descriptor, out, sid};
use crate::rtl::{KernelError, SpinLock};

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
//   sucesso, 0x30 = falha). O LSA empurra a política pelo RmAuditSetCommand
//   da `SeRmCommandPort` ([`set_policy_from_lsa`]); antes disso a tabela fica
//   no estado de boot, toda zerada, e os portões abaixo respondem como o NT
//   responde nesse estado.
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

/// AdtpPerCategoryCount (ntoskrnl 19041 rva 0xd2d1a0): as subcategorias de
/// cada uma das nove categorias, na ordem do SeAuditingState.
const SUBCATEGORIES_PER_CATEGORY: [usize; 9] = [5, 12, 14, 3, 6, 6, 6, 4, 4];
/// As palavras de política que o RmAuditSetCommand traz, uma por
/// subcategoria.
pub const LSA_POLICY_SUBCATEGORIES: usize = 60;

/// SepRmSetAuditEventWrkr (rva 0x7c5270), o RmAuditSetCommand que o LSA manda
/// pela `\SeRmCommandPort` (`se/reference_monitor.rs`): cada palavra liga o
/// sucesso (bit 0) e a falha (bit 1) da subcategoria; cada categoria recebe
/// o código de sucesso (1 todas, 2 algumas, 4 nenhuma) no nibble baixo e o de
/// falha no alto. No fim liga o SepRmAuditingEnabled (rva 0x7c5319), que
/// abre o envio das filas do SepRmCallLsa ao LSA (`se/lsa_call.rs`).
pub fn set_policy_from_lsa(policy: &[u16; LSA_POLICY_SUBCATEGORIES]) {
    let code = |count: usize, total: usize| if count == 0 { 4 } else if count == total { 1 } else { 2 };
    let mut state = POLICY.lock();
    let mut index = 0;
    for (category, &total) in SUBCATEGORIES_PER_CATEGORY.iter().enumerate() {
        let (mut successes, mut failures) = (0, 0);
        for flags in &policy[index..index + total] {
            let entry = [flags & 1 != 0, flags & 2 != 0];
            successes += entry[0] as usize;
            failures += entry[1] as usize;
            state.by_subcategory[index] = entry;
            index += 1;
        }
        state.by_category[category] = code(successes, total) | code(failures, total) << 4;
    }
    drop(state);
    AUDITING_ENABLED.store(true, core::sync::atomic::Ordering::Release);
}

/// Uma entrada da SepRmGlobalSaclHead: o nome do tipo de objeto e a SACL
/// global dele (os bytes do valor padrão da chave).
struct GlobalSacl {
    type_name: Vec<u16>,
    sacl: Vec<u8>,
}

/// SepRmGlobalSaclHead, sob a SepRmGlobalSaclLock.
static GLOBAL_SACLS: SpinLock<Vec<GlobalSacl>> = SpinLock::new(Vec::new());

/// GlobalSaclKeyPrefix: a chave da SACL global de um tipo é este prefixo
/// seguido do nome do tipo.
const GLOBAL_SACL_KEY_PREFIX: &str = "\\Registry\\Machine\\SECURITY\\Policy\\GlobalSaclName";
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
/// O maior ResultLength de KEY_VALUE_PARTIAL_INFORMATION aceito (0xC de
/// cabeçalho mais 0xFFFF bytes de SACL).
const GLOBAL_SACL_MAXIMUM_RESULT: usize = 0x1_000B;

/// SepRmGlobalSaclSetWrkr (rva 0x7c5390), o comando 5 que o LSA manda pela
/// `\SeRmCommandPort` (`se/reference_monitor.rs`) para cada tipo com SACL
/// global ("File" e "Key" no LsapAdtInitialize). O SepRmFetchGlobalSacl abre
/// a chave do tipo (o ZwOpenKey de kernel) e lê o valor padrão; a falha da
/// abertura ou da leitura é o ReturnedStatus (sem chave,
/// STATUS_OBJECT_NAME_NOT_FOUND, que o LsapAdtApplyGlobalSaclUpdate do
/// lsasrv aceita). Uma SACL lida troca ou cria a entrada do tipo; um valor
/// sem dados tira a entrada.
pub fn set_global_sacl_from_lsa(type_name: &[u16]) -> u32 {
    let name = String::from_utf16_lossy(type_name);
    let path = format!("{GLOBAL_SACL_KEY_PREFIX}{name}");
    let Some(node) = crate::ntos::cm::registry::node_by_path(&path) else { return STATUS_OBJECT_NAME_NOT_FOUND };
    let Some(value) = crate::ntos::cm::registry::with_node(node, |key| key.value("").map(|value| value.data.clone())) else { return STATUS_OBJECT_NAME_NOT_FOUND };
    let Some(data) = value else { return STATUS_OBJECT_NAME_NOT_FOUND };
    // O ResultLength da primeira leitura (KEY_VALUE_PARTIAL_INFORMATION):
    // acima do limite, o STATUS_BUFFER_TOO_SMALL dela volta ao LSA.
    if 0xC + data.len() > GLOBAL_SACL_MAXIMUM_RESULT {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let mut list = GLOBAL_SACLS.lock();
    let position = list.iter().position(|entry| entry.type_name == type_name);
    match (position, data.is_empty()) {
        (Some(index), false) => list[index].sacl = data,
        (Some(index), true) => {
            list.remove(index);
        }
        (None, false) => list.insert(0, GlobalSacl { type_name: type_name.to_vec(), sacl: data }),
        (None, true) => {}
    }
    0
}

/// A SACL global de um tipo de objeto (os bytes da ACL), se o LSA a
/// instalou.
pub fn global_sacl(type_name: &str) -> Option<Vec<u8>> {
    let wanted: Vec<u16> = type_name.encode_utf16().collect();
    GLOBAL_SACLS.lock().iter().find(|entry| entry.type_name == wanted).map(|entry| entry.sacl.clone())
}

/// SepRmAuditProcessCommandLine e SepRmAuditingEnabled (rva 0xc1d534; o
/// SepRmDbInitialization o zera no boot).
static AUDIT_PROCESS_COMMAND_LINE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static AUDITING_ENABLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// SepRmProcessCreationCommandLineAuditSettingsWrkr (rva 0x365650), o
/// comando 7 do LSA: a auditoria da linha de comando na criação de
/// processos e o SepRmAuditingEnabled ligado. Sempre STATUS_SUCCESS.
pub fn set_process_command_line_audit(enabled: bool) -> u32 {
    AUDIT_PROCESS_COMMAND_LINE.store(enabled, core::sync::atomic::Ordering::Release);
    AUDITING_ENABLED.store(true, core::sync::atomic::Ordering::Release);
    0
}

/// SepRmAuditingEnabled: o LSA já mandou a política (RmAuditSetCommand) ou a
/// auditoria da linha de comando. Sem ele, o SepRmCallLsa
/// (`se/lsa_call.rs`) esvazia as filas sem mandar nada ao LSA.
pub fn auditing_enabled() -> bool {
    AUDITING_ENABLED.load(core::sync::atomic::Ordering::Acquire)
}

/// O SepRmAuditingEnabled zerado quando a conexão do LSA fecha no silo
/// hospedeiro (o LPC_PORT_CLOSED do SepRmCommandServerThread).
pub fn disable_auditing() {
    AUDITING_ENABLED.store(false, core::sync::atomic::Ordering::Release);
}

// ---- O registro da auditoria no ETW -----------------------------------------
//
// O SeRmInitPhase1 do 19041 chama o SepAdtInitializeAuditingOptions (rva
// 0xa4bb0c) logo depois de criar a `\SeRmCommandPort`: o
// AdtpInitializeAuditingCommon (rva 0x79e7d0) liga o AdtpRegisteredWithEtw e,
// com ele pronto, o evento `\ADT_ETW_CHANNEL_INIT` é criado ou aberto
// (SepAdtOpenEtwReadyEvent), sinalizado (NtSetEvent) e fechado. O SepRmCallLsa
// que roda antes disso espera esse evento. O resto do
// SepAdtInitializeAuditingOptions (as letras de unidade e os objetos do
// AdtpInitializeAuditingCommon, a notificação do Registro das opções de
// auditoria, o CrashOnAuditFail, a auditoria de privilégios e os limites)
// não existe no OpenNT.

/// AdtpRegisteredWithEtw.
static REGISTERED_WITH_ETW: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// O evento que sinaliza o registro da auditoria no ETW.
pub const ETW_READY_EVENT_NAME: &str = "\\ADT_ETW_CHANNEL_INIT";
/// SYNCHRONIZE | EVENT_QUERY_STATE | EVENT_MODIFY_STATE.
const ETW_READY_EVENT_ACCESS: u32 = 0x10_0003;
/// OBJ_OPENIF | OBJ_KERNEL_HANDLE.
const ETW_READY_EVENT_ATTRIBUTES: u32 = 0x280;
const STATUS_OBJECT_NAME_EXISTS: u32 = 0x4000_0000;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// AdtpRegisteredWithEtw: o SepAdtInitializeAuditingOptions já rodou.
pub fn registered_with_etw() -> bool {
    REGISTERED_WITH_ETW.load(core::sync::atomic::Ordering::Acquire)
}

/// SepAdtOpenEtwReadyEvent (rva 0x79e744): o NtCreateEvent do
/// `\ADT_ETW_CHANNEL_INIT` (SYNCHRONIZE | EVENT_QUERY_STATE |
/// EVENT_MODIFY_STATE, OBJ_OPENIF | OBJ_KERNEL_HANDLE, evento de notificação
/// não sinalizado). STATUS_OBJECT_NAME_EXISTS e STATUS_OBJECT_NAME_COLLISION
/// viram STATUS_SUCCESS. Devolve (NTSTATUS, handle; 0 sem handle).
pub fn open_etw_ready_event() -> Result<(u32, u64), KernelError> {
    let units = ETW_READY_EVENT_NAME.encode_utf16().count() as u64;
    let block = guest::alloc_bytes(ObjectAttributes::SIZE + 8 + 16 + units * 2 + 2);
    if block == 0 {
        return Ok((STATUS_INSUFFICIENT_RESOURCES, 0));
    }
    let (attributes_address, handle_cell, name) = (block, block + ObjectAttributes::SIZE, block + ObjectAttributes::SIZE + 8);
    guest::write_bytes(block, &alloc::vec![0u8; (ObjectAttributes::SIZE + 8) as usize]);
    guest_strings::write_wide_string(name + 16, ETW_READY_EVENT_NAME);
    guest_strings::write_string_fields(name, (units * 2) as u16, (units * 2 + 2) as u16, name + 16);
    // SAFETY: bloco recém-alocado com o tamanho do OBJECT_ATTRIBUTES.
    let attributes = unsafe { ObjectAttributes::at(attributes_address) };
    attributes.length.set(ObjectAttributes::SIZE as u32);
    attributes.object_name.set(name);
    attributes.attributes.set(ETW_READY_EVENT_ATTRIBUTES);
    let created = crate::ntos::ex::event::create(handle_cell, ETW_READY_EVENT_ACCESS, attributes_address, 0, false);
    let handle = guest::read64(handle_cell);
    guest::free_bytes(block);
    Ok(match created? {
        STATUS_OBJECT_NAME_EXISTS | STATUS_OBJECT_NAME_COLLISION => (0, handle),
        status => (status, handle),
    })
}

/// SepAdtInitializeAuditingOptions, a parte do registro no ETW: o
/// AdtpRegisteredWithEtw ligado e o `\ADT_ETW_CHANNEL_INIT` sinalizado e
/// fechado. Devolve o NTSTATUS.
pub fn initialize_auditing_options() -> Result<u32, KernelError> {
    REGISTERED_WITH_ETW.store(true, core::sync::atomic::Ordering::Release);
    let (status, handle) = open_etw_ready_event()?;
    if status & 0x8000_0000 != 0 {
        return Ok(status);
    }
    let set = crate::ntos::ex::event::set(handle, 0)?;
    let _ = crate::ntos::ob::close::close(handle, Some(0));
    Ok(set)
}

/// SepRmAuditProcessCommandLine.
pub fn audit_process_command_line() -> bool {
    AUDIT_PROCESS_COMMAND_LINE.load(core::sync::atomic::Ordering::Acquire)
}

/// O SeAuditingStateByCategory da categoria (0 fora da tabela).
pub fn category_policy(category: usize) -> u32 {
    POLICY.lock().by_category.get(category).copied().unwrap_or(0)
}

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

/// SeExamineSacl(Sacl, ResourceSacl, Token, DesiredAccess, AccessGranted,
/// GenerateAudit*, GenerateAlarm*) do ntoskrnl 19041 (rva 0x921390): o
/// GenerateAudit. O GenerateAlarm sai sempre FALSE (o 19041 só zera).
///
/// Percorre as ACEs da SACL até a primeira que pede auditoria, pulando as
/// inherit-only. Uma SYSTEM_AUDIT_ACE vale para o token quando o SID está
/// nele pelo SepSidInToken (com as entradas só de negação) ou, num token
/// anônimo (o usuário é S-1-5-7), quando o SID é World. Com algum bit pedido
/// na máscara da ACE, audita a ACE SUCCESSFUL_ACCESS no acesso concedido e
/// a FAILED_ACCESS no negado; sem bit em comum, só um pedido com
/// MAXIMUM_ALLOWED audita, pela flag do resultado (SUCCESSFUL no concedido,
/// FAILED no negado). As SYSTEM_AUDIT_CALLBACK_ACE sem dados de aplicação
/// depois do SID são puladas, como no NT; as com expressão condicional
/// também, porque o OpenNT ainda não avalia expressões condicionais
/// (AuthzBasepEvaluateAceCondition), o mesmo que o SeSrpAccessCheck faz. O
/// ResourceSacl só serve às expressões condicionais.
pub fn examine_sacl_for_audit(sacl: u64, token: u64, desired: u32, granted: bool) -> bool {
    if sacl == 0 || ace_count(sacl) == 0 {
        return false;
    }
    let Some(subject) = tokens::with(token, crate::ntos::se::access_evaluation::Subject::from_token) else { return false };
    let maximum_flag = if desired & MAXIMUM_ALLOWED == 0 {
        0
    } else if granted {
        SUCCESSFUL_ACCESS_ACE_FLAG
    } else {
        FAILED_ACCESS_ACE_FLAG
    };
    let world = crate::ntos::se::model::sid(1, &[0]);
    let anonymous = subject.user == crate::ntos::se::model::sid(5, &[7]);
    let mut cursor = sacl + Acl::SIZE;
    for _ in 0..ace_count(sacl) {
        let ace_type = guest::read::<u8>(cursor + offset_of!(AceHeader, ace_type) as u64);
        let flags = guest::read::<u8>(cursor + offset_of!(AceHeader, ace_flags) as u64);
        let size = guest::read::<u16>(cursor + offset_of!(AceHeader, ace_size) as u64) as u64;
        let sid_address = cursor + offset_of!(AccessAllowedAce, sid_start) as u64;
        // SYSTEM_AUDIT_CALLBACK_ACE (0xD): pulada, veja acima.
        if flags & INHERIT_ONLY_ACE == 0 && ace_type == SYSTEM_AUDIT_ACE_TYPE {
            let ace_sid = sid::read(sid_address);
            let applies = crate::ntos::se::access_evaluation::sid_in_token(&subject, &ace_sid, true) || (anonymous && ace_sid == world);
            if applies {
                let mask = guest::read::<u32>(cursor + offset_of!(AccessAllowedAce, mask) as u64);
                let audit = if desired & mask != 0 {
                    (flags & SUCCESSFUL_ACCESS_ACE_FLAG != 0 && granted) || (flags & FAILED_ACCESS_ACE_FLAG != 0 && !granted)
                } else {
                    flags & maximum_flag != 0
                };
                if audit {
                    return true;
                }
            }
        }
        cursor += size;
    }
    false
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

/// NtPrivilegedServiceAuditAlarm(SubsystemName, ServiceName, ClientToken,
/// Privileges, AccessGranted) sobre o token do cliente já referenciado
/// (TOKEN_QUERY): como no ntoskrnl 19041, um token de impersonação abaixo de
/// SecurityIdentification é STATUS_BAD_IMPERSONATION_LEVEL; o PRIVILEGE_SET
/// é capturado (STATUS_ACCESS_VIOLATION fora da faixa) e, com a auditoria de
/// uso de privilégio ligada para o resultado, o evento 4673 vai ao anel.
/// Devolve o NTSTATUS (STATUS_SUCCESS mesmo sem evento).
pub fn privileged_service_audit_alarm(service: &str, token_kind: u32, impersonation_level: u32, privilege_count: u32, granted: bool) -> u32 {
    if token_kind == 2 && impersonation_level < 1 {
        return 0xC000_00A5;
    }
    if audit_this_event(SUBCATEGORY_SENSITIVE_PRIVILEGE_USE, granted, !granted) {
        record_audit_event("privileged service", format!("event=4673 service={service} privileges={privilege_count} granted={granted}"));
    }
    0
}

/// O maior PrivilegeCount que o NtPrivilegeObjectAuditAlarm captura (0x43 ou
/// mais é STATUS_INVALID_PARAMETER).
pub const MAX_ALARM_PRIVILEGES: u32 = 0x42;

/// NtPrivilegeObjectAuditAlarm(SubsystemName, HandleId, ClientToken,
/// DesiredAccess, Privileges, AccessGranted) depois das verificações e
/// capturas do adaptador, como no ntoskrnl 19041 (rva 0x78b840): o
/// SeCheckAuditPrivilege de quem chama (STATUS_PRIVILEGE_NOT_HELD), o token
/// do cliente com TOKEN_QUERY (um token de impersonação abaixo de
/// SecurityIdentification é STATUS_BAD_IMPERSONATION_LEVEL), o
/// SubsystemName e o PRIVILEGE_SET (alinhado a ULONG, até
/// [`MAX_ALARM_PRIVILEGES`] entradas). O SepAdtPrivilegeObjectAuditAlarm
/// (rva 0x627d4c) gera o evento 4674 quando a auditoria de uso de
/// privilégio, sensível ou não (SepAdtAuditPrivilegeUseWithContext), está
/// ligada para o resultado. Devolve STATUS_SUCCESS mesmo sem evento; o
/// lsass (LsapAdtCheckPrivilege) ignora o status.
pub fn privilege_object_audit_alarm_service(subsystem: &str, handle_id: u64, desired_access: u32, privilege_count: u32, granted: bool) -> u32 {
    if audit_privilege_use(granted, !granted) {
        record_audit_event("PrivilegeObject", format!("event=4674 subsystem={subsystem} handle={handle_id:#x} desired={desired_access:#x} privileges={privilege_count} granted={granted}"));
    }
    0
}

/// NtCloseObjectAuditAlarm e NtDeleteObjectAuditAlarm(SubsystemName,
/// HandleId, GenerateOnClose), como no ntoskrnl 19041 (NtCloseObjectAuditAlarm
/// 0x684fd0): sem GenerateOnClose, STATUS_SUCCESS sem mais nada; com ele, o
/// SeAuditPrivilege do chamador (STATUS_PRIVILEGE_NOT_HELD) e o evento de
/// fechamento (4658) ou de exclusão (4660) do handle. `privileged` é o
/// SeCheckAuditPrivilege já feito pelo adaptador.
pub fn close_object_audit_alarm(subsystem: &str, handle_id: u64, generate_on_close: bool, privileged: bool, delete: bool) -> u32 {
    if !generate_on_close {
        return 0;
    }
    if !privileged {
        return 0xC000_0061;
    }
    let (kind, event) = if delete { ("delete object", 4660) } else { ("close object", 4658) };
    record_audit_event(kind, format!("event={event} subsystem={subsystem} handle={handle_id:#x}"));
    0
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
