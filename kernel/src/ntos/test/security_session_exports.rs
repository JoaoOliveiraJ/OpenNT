//! Autoteste dos exports de Se, Kse e Ps que eram os últimos imports de
//! drivers reais: as rotinas de término de sessão de logon (com a sessão
//! saindo junto com o último token e o aviso aos file systems pela fila de
//! work items), o token de sessão, os atributos de segurança de tokens, o
//! ZwCompareTokens, o SeQueryServerSiloToken, o SeExamineSacl, o
//! SeGetCachedSigningLevel, o SePublicDefaultDacl, o KseRegisterShimEx com o
//! KseUnregisterShim e o PsChargePoolQuota.
//!
//! Cada export é chamado pelo trampolim nativo (ABI MS x64). Os valores
//! esperados seguem o ntoskrnl 19041 (as rotinas e os RVAs citados nos
//! arquivos de lógica), no estado do OpenNT: sem silos de servidor, sem o
//! motor de shims inicializado.

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::types::{Eprocess, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::se::logon_session;
use crate::ntos::se::token::{handles, reference as token_reference, tokens};

type Assert = fn(bool, &str);

const SENTINEL: u64 = 0xDEAD_DEAD_DEAD_DEAD;

fn call(name: &str, arguments: &[u64]) -> u64 {
    super::phase6::call_export(name, arguments).unwrap_or(SENTINEL)
}

fn status(value: u32) -> u64 {
    crate::ntos::init::exports::signed_status(value)
}

fn zeroed(size: u64) -> u64 {
    let block = guest::alloc_bytes(size);
    guest::write_bytes(block, &vec![0u8; size as usize]);
    block
}

/// Espera ~10 ms (KeDelayExecutionThread relativo): a fila de work items
/// anda enquanto a thread espera.
fn sleep_10ms() {
    let interval = zeroed(8);
    guest::write64(interval, (-100_000i64) as u64);
    call("KeDelayExecutionThread", &[0, 0, interval]);
    guest::free_bytes(interval);
}

/// SID S-<revisão 1>-<autoridade>-<subautoridades>.
fn sid_bytes(authority: u8, sub_authorities: &[u32]) -> Vec<u8> {
    let mut bytes = vec![1, sub_authorities.len() as u8, 0, 0, 0, 0, 0, authority];
    for value in sub_authorities {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn system_token() -> u64 {
    crate::ntos::ps::process::get_primary_token(crate::ntos::ps::process::get_system_process()).unwrap_or(0)
}

/// Um token primário novo, cópia do System com o AuthenticationId pedido.
fn token_for_logon(logon_id: u64) -> u64 {
    tokens::create(Some(system_token()), Some(&|token: &mut tokens::Token| token.authentication_id = logon_id)).unwrap_or(0)
}

/// Handle de kernel (TOKEN_ALL_ACCESS) ligado ao token.
fn kernel_handle(token: u64) -> u64 {
    handles::create(token, 0xF_01FF, 0x200, false).unwrap_or(0)
}

/// O token de um handle (a referência é solta na hora).
fn token_of(handle: u64) -> u64 {
    match token_reference::reference(handle, 0, 0, false) {
        Ok(Ok(mut reference)) => {
            let token = reference.token;
            let _ = reference.release();
            token
        }
        _ => 0,
    }
}

pub fn run(assert: Assert) {
    logon_session_termination(assert);
    logon_session_token(assert);
    compare_tokens(assert);
    security_attributes(assert);
    server_silo(assert);
    examine_sacl(assert);
    cached_signing_level(assert);
    public_default_dacl(assert);
    shim_registration(assert);
    charge_pool_quota(assert);
}

// ---- SeRegister/Unregister/MarkLogonSessionTermination ----------------------

static TERMINATED: AtomicU64 = AtomicU64::new(0);
static TERMINATED_LOGON: AtomicU64 = AtomicU64::new(0);
static TERMINATED_SILO: AtomicU64 = AtomicU64::new(0);
static TERMINATED_CONTEXT: AtomicU64 = AtomicU64::new(0);

/// PSE_LOGON_SESSION_TERMINATED_ROUTINE_EX(LogonId*, Silo, Context).
extern "win64" fn logon_terminated(logon_id: u64, silo: u64, context: u64) -> u32 {
    TERMINATED_LOGON.store(guest::read64(logon_id), Ordering::SeqCst);
    TERMINATED_SILO.store(silo, Ordering::SeqCst);
    TERMINATED_CONTEXT.store(context, Ordering::SeqCst);
    TERMINATED.fetch_add(1, Ordering::SeqCst);
    0
}

/// Espera até ~2 s o contador de avisos passar de `before`.
fn wait_terminated(before: u64) -> bool {
    for _ in 0..200 {
        if TERMINATED.load(Ordering::SeqCst) > before {
            return true;
        }
        sleep_10ms();
    }
    false
}

fn logon_session_termination(assert: Assert) {
    let routine = logon_terminated as extern "win64" fn(u64, u64, u64) -> u32 as usize as u64;
    let context = 0x5E55_10E0u64;
    let logon = tokens::allocate_luid();
    let luid = zeroed(8);
    guest::write64(luid, logon);
    let created = logon_session::create_track(logon);
    let registered = call("SeRegisterLogonSessionTerminatedRoutineEx", &[routine, context]);
    let null_routine = call("SeRegisterLogonSessionTerminatedRoutineEx", &[0, context]);
    let listed = logon_session::terminated_routines().first() == Some(&(routine, context));
    // Dois tokens: o primeiro herda a referência do LSA, o segundo soma 1.
    let first = token_for_logon(logon);
    let after_first = logon_session::reference_state(logon, 0);
    let second = token_for_logon(logon);
    let after_second = logon_session::reference_state(logon, 0);
    let in_use = logon_session::delete_track(logon);
    let missing = zeroed(8);
    guest::write64(missing, logon + 0x10_0000);
    let marked = call("SeMarkLogonSessionForTerminationNotificationEx", &[luid, 0]);
    let unknown = call("SeMarkLogonSessionForTerminationNotificationEx", &[missing, 0]);
    let after_mark = logon_session::reference_state(logon, 0);
    assert(
        created == 0 && registered == 0 && null_routine == status(0xC000_000D) && listed && first != 0 && second != 0 && after_first == Some((1, 8)) && after_second == Some((2, 8)) && in_use == 0xC000_0104 && marked == 0 && unknown == status(0xC000_0225) && after_mark == Some((2, 9)),
        "se-logon-session-notify: registro, referencias dos tokens (bit 8), sessao em uso recusada e marca de termino",
    );
    let before = TERMINATED.load(Ordering::SeqCst);
    let _ = tokens::release(second);
    let still = logon_session::reference_state(logon, 0) == Some((1, 9)) && TERMINATED.load(Ordering::SeqCst) == before;
    let _ = tokens::release(first);
    let gone = !logon_session::exists(logon, 0);
    let notified = wait_terminated(before);
    assert(
        still && gone && notified && TERMINATED_LOGON.load(Ordering::SeqCst) == logon && TERMINATED_SILO.load(Ordering::SeqCst) == 0 && TERMINATED_CONTEXT.load(Ordering::SeqCst) == context && logon_session::delete_track(logon) == 0xC000_005F,
        "se-logon-session-notify: a sessao marcada sai com o ultimo token e a rotina recebe LogonId, silo e contexto pela fila",
    );
    // Sem a marca, a sessão sai com o último token sem aviso.
    let quiet = tokens::allocate_luid();
    let quiet_created = logon_session::create_track(quiet);
    let quiet_token = token_for_logon(quiet);
    let before_quiet = TERMINATED.load(Ordering::SeqCst);
    let _ = tokens::release(quiet_token);
    for _ in 0..20 {
        sleep_10ms();
    }
    assert(quiet_created == 0 && quiet_token != 0 && !logon_session::exists(quiet, 0) && TERMINATED.load(Ordering::SeqCst) == before_quiet, "se-logon-session-notify: sessao sem marca sai sem aviso");
    let unregistered = call("SeUnregisterLogonSessionTerminatedRoutineEx", &[routine, context]);
    let again = call("SeUnregisterLogonSessionTerminatedRoutineEx", &[routine, context]);
    let null_unregister = call("SeUnregisterLogonSessionTerminatedRoutineEx", &[0, 0]);
    assert(unregistered == 0 && again == status(0xC000_0225) && null_unregister == status(0xC000_000D) && !logon_session::terminated_routines().contains(&(routine, context)), "se-logon-session-notify: remocao do par exato, ausente = STATUS_NOT_FOUND");
    guest::free_bytes(luid);
    guest::free_bytes(missing);
}

// ---- SeGetLogonSessionToken ---------------------------------------------------

fn logon_session_token(assert: Assert) {
    let logon = tokens::allocate_luid();
    let created = logon_session::create_track(logon);
    let token = token_for_logon(logon);
    let handle = kernel_handle(token);
    let output = zeroed(8);
    let without = call("SeGetLogonSessionToken", &[handle, 0, output]);
    // Um token filtrado restrito liga o token de sessão (SepSetLogonSessionToken).
    let restricted = zeroed(0x40);
    let everyone = restricted + 0x20;
    guest::write_bytes(everyone, &sid_bytes(1, &[0]));
    guest::write32(restricted, 1);
    guest::write64(restricted + 8, everyone);
    let filtered_out = zeroed(8);
    let filtered = call("SeFilterToken", &[token, 0, 0, 0, restricted, filtered_out]);
    let filtered_token = guest::read64(filtered_out);
    // O token, o filtrado e a cópia de sessão (que não referencia a sessão).
    let state = logon_session::reference_state(logon, 0);
    let got = call("SeGetLogonSessionToken", &[handle, 0, output]);
    let new_handle = guest::read64(output);
    let copy = token_of(new_handle);
    let copy_shape = tokens::with(copy, |record| (record.kind, record.user.clone(), record.authentication_id));
    let original_user = tokens::with(token, |record| record.user.clone());
    let bad = call("SeGetLogonSessionToken", &[0x7FFF_FFF8, 0, output]);
    assert(
        created == 0 && token != 0 && handle != 0 && without == status(0xC000_007C) && filtered == 0 && filtered_token != 0 && state == Some((2, 8)) && got == 0 && new_handle & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000 && copy != 0 && copy != token && copy_shape == original_user.map(|user| (1, user, logon)) && bad == status(0xC000_0008),
        "se-token-session-queries: sem token de sessao STATUS_NO_TOKEN; o filtro restrito liga a copia e o SeGetLogonSessionToken devolve handle de kernel para uma copia primaria",
    );
    call("ZwClose", &[new_handle]);
    call("ZwClose", &[handle]);
    let _ = tokens::release(filtered_token);
    let _ = tokens::release(token);
    assert(!logon_session::exists(logon, 0), "se-token-session-queries: a sessao sai com o ultimo token, levando o token de sessao");
    for block in [output, restricted, filtered_out] {
        guest::free_bytes(block);
    }
}

// ---- ZwCompareTokens ----------------------------------------------------------

fn compare_tokens(assert: Assert) {
    let (first, second) = (tokens::create(Some(system_token()), None).unwrap_or(0), tokens::create(Some(system_token()), None).unwrap_or(0));
    let (first_handle, second_handle) = (kernel_handle(first), kernel_handle(second));
    let equal = zeroed(8);
    let compare = |left: u64, right: u64| {
        guest::write8(equal, 0xCC);
        let result = call("ZwCompareTokens", &[left, right, equal]);
        (result, guest::read8(equal))
    };
    let same_handle = compare(first_handle, first_handle);
    let copies = compare(first_handle, second_handle);
    // Um privilégio desligado no segundo.
    let flipped = tokens::update(second, |record| record.privileges.iter_mut().find(|privilege| privilege.attributes & 2 != 0).map(|privilege| privilege.attributes &= !2)).flatten().is_some();
    let privilege_differs = compare(first_handle, second_handle);
    let original = tokens::with(first, |source| source.privileges.clone()).unwrap_or_default();
    let _ = tokens::update(second, |record| record.privileges = original);
    // Um grupo com SE_GROUP_ENABLED trocado.
    let _ = tokens::update(second, |record| record.groups[0].attributes ^= 0x4);
    let group_differs = compare(first_handle, second_handle);
    let _ = tokens::update(second, |record| record.groups[0].attributes ^= 0x4);
    // Um atributo de segurança só no segundo; com COMPARE_IGNORE ele não conta.
    let attribute = |flags: u32| crate::ntos::se::security_attributes::SecurityAttribute { name: alloc::string::String::from("TST://CMP"), kind: 1, flags, values: vec![crate::ntos::se::security_attributes::AttributeValue::Integer(5)] };
    let _ = tokens::update(second, |record| record.security_attributes.push(attribute(0)));
    let attribute_differs = compare(first_handle, second_handle);
    let _ = tokens::update(second, |record| record.security_attributes = vec![attribute(0x40)]);
    let ignored = compare(first_handle, second_handle);
    let invalid = compare(0x7FFF_FFF8, second_handle);
    assert(
        same_handle == (0, 1) && copies == (0, 1) && flipped && privilege_differs == (0, 0) && group_differs == (0, 0) && attribute_differs == (0, 0) && ignored == (0, 1) && invalid == (status(0xC000_0008), 0),
        "zw-compare-tokens: mesmo handle e copias iguais; privilegio, grupo habilitado e atributo relevante diferem; COMPARE_IGNORE nao conta; handle invalido grava FALSE",
    );
    call("ZwClose", &[first_handle]);
    call("ZwClose", &[second_handle]);
    let _ = tokens::release(first);
    let _ = tokens::release(second);
    guest::free_bytes(equal);
}

// ---- SeSetSecurityAttributesToken(Ex) ------------------------------------------

/// TOKEN_SECURITY_ATTRIBUTES_INFORMATION v1 com um atributo INT64.
fn attributes_information(block: u64, name: &str, value: u64) {
    let name_units: Vec<u8> = name.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
    let (entry, text, values) = (block + 0x10, block + 0x40, block + 0x80);
    guest::write_bytes(text, &name_units);
    guest::write64(values, value);
    guest::write16(block, 1);
    guest::write16(block + 2, 0);
    guest::write32(block + 4, 1);
    guest::write64(block + 8, entry);
    guest::write16(entry, name_units.len() as u16);
    guest::write16(entry + 2, name_units.len() as u16);
    guest::write64(entry + 8, text);
    guest::write16(entry + 16, 1);
    guest::write16(entry + 18, 0);
    guest::write32(entry + 20, 0);
    guest::write32(entry + 24, 1);
    guest::write64(entry + 32, values);
}

fn security_attributes(assert: Assert) {
    let token = tokens::create(Some(system_token()), None).unwrap_or(0);
    let handle = kernel_handle(token);
    let (information, operations, singleton) = (zeroed(0x100), zeroed(8), zeroed(8));
    let values = |token: u64| tokens::with(token, |record| record.security_attributes.iter().filter(|attribute| attribute.name == "TST://TESTE").map(|attribute| attribute.values.clone()).collect::<Vec<_>>()).unwrap_or_default();
    let delinked = || tokens::body(token).token_flags.get() & 0x2_0000 != 0;
    let modified = || tokens::with(token, |record| record.modified_id).unwrap_or(0);
    attributes_information(information, "TST://TESTE", 42);
    guest::write32(operations, 2);
    let before = modified();
    let added = call("SeSetSecurityAttributesToken", &[handle, 0, operations, information]);
    let after_add = (values(token), delinked(), modified() != before);
    let collision = call("SeSetSecurityAttributesToken", &[handle, 0, operations, information]);
    let no_operations = call("SeSetSecurityAttributesToken", &[handle, 0, 0, information]);
    assert(
        added == 0 && after_add == (vec![vec![crate::ntos::se::security_attributes::AttributeValue::Integer(42)]], false, true) && collision == status(0xC000_0035) && no_operations == status(0xC000_000D),
        "se-token-attributes-set: ADD grava o atributo e um ModifiedId novo, nome repetido = colisao, sem Operations = STATUS_INVALID_PARAMETER",
    );
    attributes_information(information, "TST://TESTE", 7);
    guest::write32(operations, 4);
    guest::write8(singleton, 0xCC);
    let reserved = call("SeSetSecurityAttributesTokenEx", &[handle, 0, 1, 0, operations, information, singleton]);
    let replaced = call("SeSetSecurityAttributesTokenEx", &[handle, 0, 0, 0, operations, information, singleton]);
    let after_replace = (values(token), delinked(), guest::read8(singleton));
    guest::write32(operations, 3);
    let deleted = call("SeSetSecurityAttributesToken", &[handle, 0, operations, information]);
    let missing = call("SeSetSecurityAttributesToken", &[handle, 0, operations, information]);
    guest::write32(operations, 2);
    call("SeSetSecurityAttributesToken", &[handle, 0, operations, information]);
    guest::write32(operations, 1);
    let cleared = call("SeSetSecurityAttributesToken", &[handle, 0, operations, 0]);
    let empty = tokens::with(token, |record| record.security_attributes.is_empty()).unwrap_or(false);
    assert(
        reserved == status(0xC000_000D) && replaced == 0 && after_replace == (vec![vec![crate::ntos::se::security_attributes::AttributeValue::Integer(7)]], true, 0) && deleted == 0 && missing == status(0xC000_0225) && cleared == 0 && empty,
        "se-token-attributes-set: Ex recusa Reserved, troca com delink e SingletonSet FALSE; DELETE e REPLACE_ALL sem atributos",
    );
    call("ZwClose", &[handle]);
    let _ = tokens::release(token);
    for block in [information, operations, singleton] {
        guest::free_bytes(block);
    }
}

// ---- SeQueryServerSiloToken -------------------------------------------------

fn server_silo(assert: Assert) {
    let token = tokens::create(Some(system_token()), None).unwrap_or(0);
    let silo = zeroed(8);
    let expected = |session_id: u32| {
        let process = crate::ntos::mm::session::by_id(session_id);
        if process == 0 {
            return (status(0xC000_0455), 0xAAAA_AAAA_AAAA_AAAA);
        }
        // SAFETY: o processo referenciado mantém a sessão viva.
        let value = unsafe { crate::ntos::inc::types::MmSessionSpace::at(crate::ntos::mm::session::of_process(process)) }.server_silo.get();
        let _ = crate::ntos::ps::process::dereference(process);
        (0, value)
    };
    let mut results = Vec::new();
    for session_id in [0u32, 0x7777] {
        let _ = tokens::update(token, |record| record.session_id = session_id);
        guest::write64(silo, 0xAAAA_AAAA_AAAA_AAAA);
        let result = call("SeQueryServerSiloToken", &[token, silo]);
        results.push(((result, guest::read64(silo)), expected(session_id)));
    }
    assert(results.iter().all(|(got, wanted)| got == wanted) && results[1].0 == (status(0xC000_0455), 0xAAAA_AAAA_AAAA_AAAA), "se-token-session-queries: SeQueryServerSiloToken pela sessao do token; sessao inexistente = STATUS_INVALID_SESSION sem gravar");
    let _ = tokens::release(token);
    guest::free_bytes(silo);
}

// ---- SeExamineSacl -------------------------------------------------------------

/// SACL revisão 2 com ACEs (tipo, flags, máscara, SID).
fn sacl(block: u64, aces: &[(u8, u8, u32, Vec<u8>)]) -> u64 {
    let mut bytes = vec![2u8, 0, 0, 0, 0, 0, 0, 0];
    for (kind, flags, mask, identifier) in aces {
        let size = 8 + identifier.len();
        bytes.extend_from_slice(&[*kind, *flags]);
        bytes.extend_from_slice(&(size as u16).to_le_bytes());
        bytes.extend_from_slice(&mask.to_le_bytes());
        bytes.extend_from_slice(identifier);
    }
    let total = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&total.to_le_bytes());
    bytes[4..6].copy_from_slice(&(aces.len() as u16).to_le_bytes());
    guest::write_bytes(block, &bytes);
    block
}

fn examine_sacl(assert: Assert) {
    const AUDIT: u8 = 2;
    const ALARM: u8 = 3;
    const SUCCESS: u8 = 0x40;
    const FAILURE: u8 = 0x80;
    const INHERIT_ONLY: u8 = 0x08;
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    let system = system_token();
    let world = sid_bytes(1, &[0]);
    let users = sid_bytes(5, &[32, 545]);
    let (block, outputs) = (zeroed(0x200), zeroed(8));
    let examine = |acl: u64, token: u64, desired: u32, granted: bool| {
        guest::write64(outputs, 0xCCCC);
        let result = call("SeExamineSacl", &[acl, 0, token, desired as u64, granted as u64, outputs, outputs + 1]);
        (result != SENTINEL, guest::read8(outputs), guest::read8(outputs + 1))
    };
    let failure_world = sacl(block, &[(AUDIT, FAILURE, 1, world.clone())]);
    let failure = [examine(failure_world, system, 1, false), examine(failure_world, system, 1, true), examine(failure_world, system, 2, false), examine(failure_world, system, MAXIMUM_ALLOWED | 2, false), examine(failure_world, system, MAXIMUM_ALLOWED | 2, true)];
    assert(failure == [(true, 1, 0), (true, 0, 0), (true, 0, 0), (true, 1, 0), (true, 0, 0)], "se-examine-sacl: ACE FAILED audita o acesso negado com bit em comum, ou sem bit com MAXIMUM_ALLOWED");
    let success_world = sacl(block, &[(AUDIT, SUCCESS, 1, world.clone())]);
    let success = [examine(success_world, system, 1, true), examine(success_world, system, 1, false)];
    let inherit_only = sacl(block, &[(AUDIT, SUCCESS | FAILURE | INHERIT_ONLY, 1, world.clone())]);
    let skipped = examine(inherit_only, system, 1, false);
    let other_sid = sacl(block, &[(AUDIT, FAILURE, 1, users.clone())]);
    let not_member = examine(other_sid, system, 1, false);
    let alarm = sacl(block, &[(ALARM, SUCCESS | FAILURE, 1, world.clone())]);
    let no_alarm = examine(alarm, system, 1, false);
    let null = examine(0, system, 1, false);
    assert(success == [(true, 1, 0), (true, 0, 0)] && skipped == (true, 0, 0) && not_member == (true, 0, 0) && no_alarm == (true, 0, 0) && null == (true, 0, 0), "se-examine-sacl: SUCCESS no concedido; inherit-only, SID fora do token e ACE de alarme nao auditam; GenerateAlarm sempre FALSE");
    // Token anônimo (usuário S-1-5-7, sem grupos): World vale pela regra do anônimo.
    let anonymous = tokens::create(Some(system), Some(&|token: &mut tokens::Token| {
        token.user = sid_bytes(5, &[7]);
        token.groups = Vec::new();
    }))
    .unwrap_or(0);
    let lonely = tokens::create(Some(system), Some(&|token: &mut tokens::Token| {
        token.user = sid_bytes(5, &[21, 1, 2, 3, 1001]);
        token.groups = Vec::new();
    }))
    .unwrap_or(0);
    let failure_world = sacl(block, &[(AUDIT, FAILURE, 1, world)]);
    let anonymous_audit = examine(failure_world, anonymous, 1, false);
    let lonely_audit = examine(failure_world, lonely, 1, false);
    assert(anonymous != 0 && lonely != 0 && anonymous_audit == (true, 1, 0) && lonely_audit == (true, 0, 0), "se-examine-sacl: o token anonimo casa World sem o grupo; outro token sem grupos nao");
    let _ = tokens::release(anonymous);
    let _ = tokens::release(lonely);
    guest::free_bytes(block);
    guest::free_bytes(outputs);
}

// ---- SeGetCachedSigningLevel ---------------------------------------------------

fn cached_signing_level(assert: Assert) {
    use crate::ntos::se::code_integrity::{self, SigningCallback};
    let present = code_integrity::signing_callback(SigningCallback::GetFileCache) != 0;
    let (flags, level) = (zeroed(8), zeroed(8));
    let null_file = call("SeGetCachedSigningLevel", &[0, flags, level, 0, 0, 0]);
    let null_level = call("SeGetCachedSigningLevel", &[0x1000, flags, 0, 0, 0, 0]);
    let expected = if present { status(0xC000_000D) } else { status(0xC000_0001) };
    assert(null_file == expected && null_level == expected, "se-cached-signing-level: sem a CI STATUS_UNSUCCESSFUL antes dos argumentos; com ela, FileObject/SigningLevel nulos = STATUS_INVALID_PARAMETER");
    guest::free_bytes(flags);
    guest::free_bytes(level);
}

// ---- SePublicDefaultDacl --------------------------------------------------------

fn public_default_dacl(assert: Assert) {
    use crate::ntos::mm::pe_loader::ResolvedImport;
    let cell = match crate::ntos::init::exports::lookup("ntoskrnl.exe", "SePublicDefaultDacl") {
        Some(ResolvedImport::Address { address, .. }) => address,
        _ => 0,
    };
    let acl = if cell != 0 { guest::read64(cell) } else { 0 };
    let bytes = if acl != 0 { guest::read_bytes(acl, 0x54) } else { Vec::new() };
    let mut expected = vec![2u8, 0, 0x54, 0, 3, 0, 0, 0];
    for (mask, identifier) in [(0x2000_0000u32, sid_bytes(1, &[0])), (0x1000_0000, sid_bytes(5, &[18])), (0x1000_0000, sid_bytes(5, &[32, 544]))] {
        expected.extend_from_slice(&[0, 0]);
        expected.extend_from_slice(&((8 + identifier.len()) as u16).to_le_bytes());
        expected.extend_from_slice(&mask.to_le_bytes());
        expected.extend_from_slice(&identifier);
    }
    expected.resize(0x54, 0);
    assert(cell != 0 && acl == cell + 8 && bytes == expected, "se-public-default-dacl: World GENERIC_EXECUTE, SYSTEM e Administrators GENERIC_ALL numa ACL de 0x54 bytes");
}

// ---- KseRegisterShimEx / KseUnregisterShim --------------------------------------

fn shim_registration(assert: Assert) {
    let shim = zeroed(0x30);
    guest::write_bytes(shim, &[0x5A; 0x30]);
    let null_register = call("KseRegisterShimEx", &[0, 0, 0, 0]);
    let register = call("KseRegisterShimEx", &[shim, 0, 0, 0x1234]);
    let null_unregister = call("KseUnregisterShim", &[0, 0, 0]);
    let unregister = call("KseUnregisterShim", &[shim, 0, 0]);
    let untouched = guest::read_bytes(shim, 0x30).iter().all(|&byte| byte == 0x5A);
    assert(
        null_register == status(0xC000_000D) && register == status(0xC000_0001) && null_unregister == status(0xC000_000D) && unregister == status(0xC000_0001) && untouched,
        "kse-shim-registration-ex: shim nulo = STATUS_INVALID_PARAMETER; motor nao inicializado = STATUS_UNSUCCESSFUL sem tocar no KSE_SHIM",
    );
    guest::free_bytes(shim);
}

// ---- PsChargePoolQuota ----------------------------------------------------------

fn charge_pool_quota(assert: Assert) {
    let system = crate::ntos::ps::process::get_system_process();
    let charged_system = call("PsChargePoolQuota", &[system, 0, 0x1000]);
    let measured = super::multiprocess::identity::with_test_process("cota-pool-raise.exe", None, |test| {
        let process = test.process;
        // SAFETY: EPROCESS vivo do processo de teste.
        let usage = |index: usize| unsafe { Eprocess::at(process) }.process_quota_usage[index].get();
        let (non_paged, paged) = (usage(0), usage(1));
        let charged = [call("PsChargePoolQuota", &[process, 1, 0x3000]), call("PsChargePoolQuota", &[process, 0x200, 0x2000])];
        let delta = (usage(0) - non_paged, usage(1) - paged);
        call("PsReturnPoolQuota", &[process, 1, 0x3000]);
        call("PsReturnPoolQuota", &[process, 0x200, 0x2000]);
        (charged, delta, (usage(0) - non_paged, usage(1) - paged))
    });
    assert(charged_system == 0 && measured == Some(([0, 0], (0x2000, 0x3000), (0, 0))), "ps-charge-pool-quota: PsChargePoolQuota cobra pelo tipo de pool (o System nao) e o PsReturnPoolQuota devolve");
}
