//! Autoteste do par de tokens do UAC e das classes de token em volta dele:
//! TokenElevation (20) e TokenElevationType (18) calculados como no
//! ntoskrnl 19041, as classes de TokenFlags do NtSetInformationToken (23,
//! 24, 26 e 42), o TokenLinkedToken (19) de ida (o SepLinkLogonSessions,
//! com as sessões de logon ligadas e as referências entre elas) e de volta
//! (a cópia do token da sessão irmã num handle novo), o TokenLogonSid (28),
//! o rótulo de integridade no seu lugar entre os grupos e os bits de UAC
//! do PsBootPhaseComplete.
//!
//! Roda numa thread do System em modo kernel: o PreviousMode KernelMode
//! passa em todo privilégio, e o UserMode confere o token do System, que
//! tem o SeCreateTokenPrivilege desligado e o SeTcbPrivilege ligado.

use alloc::vec;
use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::se::logon_session;
use crate::ntos::se::model::{sid, Group, Privilege};
use crate::ntos::se::token::{handles, query, reference as token_reference, set_information, tokens};

type Assert = fn(bool, &str);

const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_NO_SUCH_LOGON_SESSION: u32 = 0xC000_005F;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_TOKEN_ALREADY_IN_USE: u32 = 0xC000_012B;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const KERNEL_MODE: u8 = 0;
const USER_MODE: u8 = 1;

fn system_token() -> u64 {
    crate::ntos::ps::process::get_primary_token(crate::ntos::ps::process::get_system_process()).unwrap_or(0)
}

/// Um token primário novo, cópia do System, com o AuthenticationId pedido.
fn token_for_logon(logon_id: u64) -> u64 {
    tokens::create(Some(system_token()), Some(&|token: &mut tokens::Token| token.authentication_id = logon_id)).unwrap_or(0)
}

/// Um token de usuário comum: S-1-5-21-1-2-3-1001, os grupos e os
/// privilégios pedidos e o rótulo Medium.
fn user_token(groups: Vec<Group>, privileges: Vec<Privilege>) -> u64 {
    tokens::create(
        Some(system_token()),
        Some(&|token: &mut tokens::Token| {
            token.user = sid(5, &[21, 1, 2, 3, 1001]);
            token.owner = token.user.clone();
            token.primary_group = token.user.clone();
            token.groups = groups.clone();
            token.privileges = privileges.clone();
            token.integrity = sid(16, &[0x2000]);
        }),
    )
    .unwrap_or(0)
}

/// Handle de kernel (TOKEN_ALL_ACCESS) ligado ao token.
fn kernel_handle(token: u64) -> u64 {
    handles::create(token, 0xF_01FF, 0x200, false).unwrap_or(0)
}

fn close(handle: u64) {
    let _ = handles::close_native(handle);
}

/// O token de um handle (a referência é solta na hora).
fn token_of(handle: u64) -> u64 {
    match token_reference::reference(handle, 0, KERNEL_MODE, false) {
        Ok(Ok(mut reference)) => {
            let token = reference.token;
            let _ = reference.release();
            token
        }
        _ => 0,
    }
}

/// O ULONG de uma classe pelo serializador.
fn scalar(token: u64, class: u32) -> Option<u32> {
    query::encode(token, class, 0).ok().filter(|bytes| bytes.len() == 4).map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// NtSetInformationToken de um ULONG.
fn set_ulong(token: u64, class: u32, value: u32, length: u32, mode: u8) -> u32 {
    let buffer = guest::alloc_bytes(8);
    guest::write64(buffer, value as u64);
    let status = set_information::set(token, class, buffer, length, mode).unwrap_or(u32::MAX);
    guest::free_bytes(buffer);
    status
}

pub fn run(assert: Assert) {
    elevation(assert);
    flag_classes(assert);
    linked_tokens(assert);
    logon_sid_and_label(assert);
    boot_phase_bits(assert);
}

// ---- TokenElevation (20) --------------------------------------------------

fn elevation(assert: Assert) {
    let everyone = Group { sid: sid(1, &[0]), attributes: 7 };
    let users = Group { sid: sid(5, &[32, 545]), attributes: 7 };
    let change_notify = || Privilege { id: 23, attributes: 3 };
    let plain = user_token(vec![everyone.clone(), users.clone()], vec![change_notify()]);
    let admin = user_token(vec![everyone.clone(), Group { sid: sid(5, &[32, 544]), attributes: 7 }], vec![change_notify()]);
    let deny_admin = user_token(vec![everyone.clone(), Group { sid: sid(5, &[32, 544]), attributes: 0x10 }], vec![change_notify()]);
    // Primeira subautoridade de 80 a 111 (conta virtual): o RID 544 não conta.
    let virtual_rid = user_token(vec![everyone.clone(), Group { sid: sid(5, &[90, 544]), attributes: 7 }], vec![change_notify()]);
    // SeBackupPrivilege presente, mesmo desligado.
    let backup = user_token(vec![everyone.clone(), users], vec![change_notify(), Privilege { id: 17, attributes: 0 }]);
    let values = [system_token(), plain, admin, deny_admin, virtual_rid, backup].map(|token| scalar(token, 20));
    assert(
        values == [Some(1), Some(0), Some(1), Some(0), Some(0), Some(1)],
        "uac-tokens: TokenElevation pelos privilegios elevados presentes e pelo RtlIsElevatedRid (deny-only e conta virtual nao contam)",
    );
    // O tamanho é conferido antes do handle, com o ReturnLength já gravado.
    let (output, returned) = (guest::alloc_bytes(8), guest::alloc_bytes(8));
    guest::write32(returned, 0);
    let mismatch = query::query(0x7FFF_FFF8, 20, output, 8, returned, KERNEL_MODE).unwrap_or(u32::MAX) == STATUS_INFO_LENGTH_MISMATCH && guest::read32(returned) == 4;
    let bad_handle = query::query(0x7FFF_FFF8, 20, output, 4, returned, KERNEL_MODE).unwrap_or(u32::MAX) == STATUS_INVALID_HANDLE;
    let handle = kernel_handle(plain);
    guest::write32(output, 0xEEEE);
    let queried = query::query(handle, 20, output, 4, returned, KERNEL_MODE).unwrap_or(u32::MAX) == 0 && guest::read32(output) == 0 && guest::read32(returned) == 4;
    close(handle);
    assert(mismatch && bad_handle && queried, "uac-tokens: TokenElevation pede 4 bytes antes do handle e grava o ULONG");
    guest::free_bytes(output);
    guest::free_bytes(returned);
    for token in [plain, admin, deny_admin, virtual_rid, backup] {
        let _ = tokens::release(token);
    }
}

// ---- TokenVirtualizationAllowed/Enabled, TokenUIAccess, TokenPrivateNameSpace

fn flag_classes(assert: Assert) {
    let token = tokens::create(Some(system_token()), None).unwrap_or(0);
    let flags = || tokens::token_flags(token);
    let modified = || tokens::with(token, |record| record.modified_id).unwrap_or(0);
    tokens::body(token).token_flags.set(flags() & !0x1_1600);
    // 24 sem VIRTUALIZE_ALLOWED não liga nada, mas o ModifiedId muda.
    let before = modified();
    let enable_without = set_ulong(token, 24, 1, 4, KERNEL_MODE) == 0 && flags() & 0x400 == 0 && modified() != before;
    // 23 pede o SeCreateTokenPrivilege (desligado no token do System).
    let refused = set_ulong(token, 23, 1, 4, USER_MODE) == STATUS_PRIVILEGE_NOT_HELD && flags() & 0x200 == 0;
    let short = set_ulong(token, 23, 1, 8, KERNEL_MODE) == STATUS_INFO_LENGTH_MISMATCH && set_ulong(token, 24, 1, 2, KERNEL_MODE) == STATUS_INFO_LENGTH_MISMATCH;
    let allowed = set_ulong(token, 23, 1, 4, KERNEL_MODE) == 0 && flags() & 0x200 != 0 && scalar(token, 23) == Some(1);
    let enabled = set_ulong(token, 24, 7, 4, KERNEL_MODE) == 0 && flags() & 0x400 != 0 && scalar(token, 24) == Some(1);
    let disabled = set_ulong(token, 24, 0, 4, KERNEL_MODE) == 0 && flags() & 0x400 == 0 && set_ulong(token, 23, 0, 4, KERNEL_MODE) == 0 && flags() & 0x200 == 0;
    assert(enable_without && refused && short && allowed && enabled && disabled, "uac-tokens: TokenVirtualizationAllowed com SeCreateToken; TokenVirtualizationEnabled so com VIRTUALIZE_ALLOWED; ModifiedId novo");
    // 26: ligar pede o SeTcbPrivilege (ligado no System), desligar não.
    let ui_on = set_ulong(token, 26, 1, 4, USER_MODE) == 0 && flags() & 0x1000 != 0 && scalar(token, 26) == Some(1);
    let ui_off = set_ulong(token, 26, 0, 4, USER_MODE) == 0 && flags() & 0x1000 == 0;
    assert(ui_on && ui_off && set_ulong(token, 26, 1, 3, KERNEL_MODE) == STATUS_INFO_LENGTH_MISMATCH, "uac-tokens: TokenUIAccess liga e desliga TOKEN_UIACCESS");
    // 42: TOKEN_PRIVATE_NAMESPACE; o primário de um processo vivo é
    // recusado, com ModifiedId novo do mesmo jeito.
    let namespace_on = set_ulong(token, 42, 1, 4, KERNEL_MODE) == 0 && flags() & 0x1_0000 != 0 && scalar(token, 42) == Some(1);
    let namespace_off = set_ulong(token, 42, 0, 4, KERNEL_MODE) == 0 && flags() & 0x1_0000 == 0;
    let primary = system_token();
    let (primary_flags, primary_modified) = (tokens::token_flags(primary), tokens::with(primary, |record| record.modified_id).unwrap_or(0));
    let in_use = set_ulong(primary, 42, 1, 4, KERNEL_MODE) == STATUS_TOKEN_ALREADY_IN_USE && tokens::token_flags(primary) == primary_flags && tokens::with(primary, |record| record.modified_id) != Some(primary_modified);
    assert(namespace_on && namespace_off && in_use, "uac-tokens: TokenPrivateNameSpace com SeTcb; token primario em uso recusado");
    let _ = tokens::release(token);
}

// ---- TokenLinkedToken (19) e TokenElevationType (18) ------------------------

fn linked_tokens(assert: Assert) {
    let (full_logon, limited_logon) = (tokens::allocate_luid(), tokens::allocate_luid());
    let created = logon_session::create_track(full_logon) == 0 && logon_session::create_track(limited_logon) == 0;
    let full = token_for_logon(full_logon);
    let limited = token_for_logon(limited_logon);
    let (output, returned) = (guest::alloc_bytes(8), guest::alloc_bytes(8));
    let full_handle = kernel_handle(full);
    let limited_handle = kernel_handle(limited);
    let link = |token: u64, handle: u64, mode: u8| {
        guest::write64(output, handle);
        set_information::set(token, 19, output, 8, mode).unwrap_or(u32::MAX)
    };
    let linked_query = |handle: u64, length: u32| query::query(handle, 19, output, length, returned, KERNEL_MODE).unwrap_or(u32::MAX);
    let unlinked = scalar(full, 18) == Some(1) && linked_query(full_handle, 8) == STATUS_NO_SUCH_LOGON_SESSION;
    // O SeCreateTokenPrivilege no modo anterior; o token ligado precisa ser
    // primário.
    let refused = link(full, limited_handle, USER_MODE) == STATUS_PRIVILEGE_NOT_HELD;
    let impersonation = tokens::duplicate(limited, 2, false, 2).unwrap_or(0);
    let impersonation_handle = kernel_handle(impersonation);
    let not_primary = link(full, impersonation_handle, KERNEL_MODE) == STATUS_INVALID_PARAMETER;
    close(impersonation_handle);
    let _ = tokens::release(impersonation);
    let short = set_information::set(full, 19, output, 4, KERNEL_MODE).unwrap_or(u32::MAX) == STATUS_INFO_LENGTH_MISMATCH;
    assert(created && full != 0 && limited != 0 && unlinked && refused && not_primary && short, "uac-tokens: TokenLinkedToken sem par = STATUS_NO_SUCH_LOGON_SESSION; vinculo pede SeCreateToken, token primario e 8 bytes");
    let modified = tokens::with(full, |record| record.modified_id);
    let linked = link(full, limited_handle, KERNEL_MODE) == 0;
    // A sessão completa: o token dela, a cópia (que solta a sessão) e a
    // referência que a filtrada segura; Flags 8 | 2. A filtrada: 8 | 4.
    let sessions = logon_session::reference_state(full_logon, 0) == Some((2, 0xA)) && logon_session::reference_state(limited_logon, 0) == Some((1, 0xC));
    let buddies = logon_session::buddy_logon_id(full_logon, 0) == limited_logon && logon_session::buddy_logon_id(limited_logon, 0) == full_logon;
    let types = scalar(full, 18) == Some(2) && scalar(limited, 18) == Some(3) && scalar(system_token(), 18) == Some(1);
    assert(linked && sessions && buddies && types && tokens::with(full, |record| record.modified_id) == modified, "uac-tokens: SepLinkLogonSessions liga as sessoes (Flags 2 e 4, BuddyLogonId, referencia da filtrada na completa) e da os tipos Full e Limited");
    // A volta: um handle novo para uma cópia primária do token da sessão
    // irmã (KernelMode passa no SeTcbPrivilege).
    guest::write32(returned, 0);
    let mismatch = linked_query(full_handle, 4) == STATUS_INFO_LENGTH_MISMATCH && guest::read32(returned) == 8;
    let to_limited = linked_query(full_handle, 8) == 0 && guest::read32(returned) == 8;
    let limited_copy_handle = guest::read64(output);
    let limited_copy = token_of(limited_copy_handle);
    let limited_ok = to_limited && limited_copy != 0 && limited_copy != limited && tokens::with(limited_copy, |record| (record.authentication_id, record.kind)) == Some((limited_logon, 1));
    let to_full = linked_query(limited_handle, 8) == 0;
    let full_copy_handle = guest::read64(output);
    let full_ok = to_full && tokens::with(token_of(full_copy_handle), |record| (record.authentication_id, record.kind)) == Some((full_logon, 1));
    close(limited_copy_handle);
    close(full_copy_handle);
    // A sessão completa já guarda um token de sessão.
    let again = link(full, limited_handle, KERNEL_MODE) == STATUS_INVALID_PARAMETER;
    assert(mismatch && limited_ok && full_ok && again, "uac-tokens: TokenLinkedToken devolve a copia primaria do token da sessao irma; segundo vinculo recusado");
    // A filtrada sai com o último token dela e solta a completa, que sai
    // junto se ninguém mais a segura.
    close(full_handle);
    close(limited_handle);
    let _ = tokens::release(full);
    let held = logon_session::reference_state(full_logon, 0) == Some((1, 0xA));
    let _ = tokens::release(limited);
    let gone = !logon_session::exists(limited_logon, 0) && !logon_session::exists(full_logon, 0);
    assert(held && gone, "uac-tokens: a sessao filtrada segura a completa ate sair, e as duas saem");
    // Os dois tokens na mesma sessão: só o Flags 4, sem irmã.
    let same_logon = tokens::allocate_luid();
    let same_created = logon_session::create_track(same_logon) == 0;
    let (first, second) = (token_for_logon(same_logon), token_for_logon(same_logon));
    let second_handle = kernel_handle(second);
    let same = link(first, second_handle, KERNEL_MODE) == 0 && logon_session::reference_state(same_logon, 0).is_some_and(|(_, flags)| flags & 6 == 4) && scalar(first, 18) == Some(3);
    let first_handle = kernel_handle(first);
    let no_buddy = linked_query(first_handle, 8) == STATUS_NO_SUCH_LOGON_SESSION;
    close(first_handle);
    close(second_handle);
    let _ = tokens::release(first);
    let _ = tokens::release(second);
    assert(same_created && same && no_buddy && !logon_session::exists(same_logon, 0), "uac-tokens: vincular na mesma sessao so a marca como filtrada");
    guest::free_bytes(output);
    guest::free_bytes(returned);
}

// ---- TokenLogonSid (28) e o rótulo de integridade nos grupos -----------------

fn logon_sid_and_label(assert: Assert) {
    let logon_sid = sid(5, &[5, 0, 0x1234]);
    let token = user_token(vec![Group { sid: sid(1, &[0]), attributes: 7 }, Group { sid: logon_sid.clone(), attributes: 0xC000_0007 }], vec![]);
    let handle = kernel_handle(token);
    let (output, returned) = (guest::alloc_bytes(0x100), guest::alloc_bytes(8));
    let expected = 0x20 + 4 * 3;
    let found = query::query(handle, 28, output, 0x100, returned, KERNEL_MODE).unwrap_or(u32::MAX) == 0 && guest::read32(returned) == expected;
    let entry_ok = guest::read32(output) == 1 && guest::read64(output + 8) == output + 0x18 && guest::read32(output + 16) == 0xC000_0007 && guest::read_bytes(output + 0x18, logon_sid.len()) == logon_sid;
    let short = query::query(handle, 28, output, expected - 1, returned, KERNEL_MODE).unwrap_or(u32::MAX) == STATUS_BUFFER_TOO_SMALL && guest::read32(returned) == expected;
    close(handle);
    // Sem SE_GROUP_LOGON_ID: STATUS_NOT_FOUND, sem ReturnLength.
    let system = kernel_handle(system_token());
    guest::write32(returned, 0x5A5A);
    let missing = query::query(system, 28, output, 0x100, returned, KERNEL_MODE).unwrap_or(u32::MAX) == STATUS_NOT_FOUND && guest::read32(returned) == 0x5A5A;
    close(system);
    assert(found && entry_ok && short && missing, "uac-tokens: TokenLogonSid devolve o grupo SE_GROUP_LOGON_ID, ou STATUS_NOT_FOUND");
    // TokenGroups: o rótulo no seu lugar (depois do último grupo no token
    // do System), com 0x60; o GroupCount do TOKEN_STATISTICS o conta.
    let system_groups = tokens::with(system_token(), |record| record.groups.len()).unwrap_or(0);
    let groups = query::encode(system_token(), 2, 0).unwrap_or_default();
    let read32 = |bytes: &[u8], at: usize| bytes.get(at..at + 4).map_or(0, |word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]));
    let count = read32(&groups, 0) as usize;
    let label_last = count == system_groups + 1 && read32(&groups, 16 + system_groups * 16) == 0x60;
    let statistics = query::encode(system_token(), 10, 0).unwrap_or_default();
    let statistics_ok = read32(&statistics, core::mem::offset_of!(crate::ntos::inc::types::TokenStatistics, group_count)) as usize == system_groups + 1;
    assert(label_last && statistics_ok, "uac-tokens: TokenGroups e TOKEN_STATISTICS contam o rotulo de integridade (0x60)");
    // Uma cópia só com o efetivo: o rótulo é uma das entradas que as trocas
    // movem (A desligado sai e o rótulo, último, toma o lugar dele).
    let mixed = user_token(vec![Group { sid: sid(5, &[32, 546]), attributes: 0 }, Group { sid: sid(1, &[0]), attributes: 7 }], vec![]);
    let effective = tokens::duplicate(mixed, 2, true, 2).unwrap_or(0);
    let moved = query::encode(effective, 2, 0).unwrap_or_default();
    let moved_ok = read32(&moved, 0) == 2 && read32(&moved, 16) == 0x60 && read32(&moved, 32) == 7 && tokens::with(effective, |record| record.label_index) == Some(0);
    assert(moved_ok, "uac-tokens: SepMakeTokenEffectiveOnly move o rotulo com as outras entradas");
    for token in [token, mixed, effective] {
        let _ = tokens::release(token);
    }
    guest::free_bytes(output);
    guest::free_bytes(returned);
}

// ---- PsBootPhaseComplete ---------------------------------------------------

fn boot_phase_bits(assert: Assert) {
    use crate::ntos::cm::registry;
    use crate::ntos::ps::boot_phase;
    const REG_DWORD: u32 = 4;
    const REG_BINARY: u32 = 3;
    let base = "\\Registry\\Machine\\Software\\OpenNTSelfTest\\Uac";
    let lsa_path = "\\Registry\\Machine\\Software\\OpenNTSelfTest\\Uac\\Lsa";
    let policies_path = "\\Registry\\Machine\\Software\\OpenNTSelfTest\\Uac\\Policies";
    let missing_path = "\\Registry\\Machine\\Software\\OpenNTSelfTest\\Uac\\Ausente";
    let lsa = registry::open_or_create(lsa_path, None).unwrap_or(0);
    let not_installed = boot_phase::elevation_bits(lsa_path, missing_path) == 0;
    let dword = |value: u32| value.to_le_bytes().to_vec();
    let installed = registry::set_value(lsa, "UACInstalled", REG_DWORD, dword(1));
    // Sem a chave de política, os três bits.
    let all = boot_phase::elevation_bits(lsa_path, missing_path) == 0xE;
    // Só um REG_DWORD 0 desliga o bit; outro tipo ou um valor ausente, não.
    let policies = registry::open_or_create(policies_path, None).unwrap_or(0);
    let written = registry::set_value(policies, "EnableLUA", REG_DWORD, dword(1)) && registry::set_value(policies, "EnableVirtualization", REG_BINARY, vec![0; 4]) && registry::set_value(policies, "EnableInstallerDetection", REG_DWORD, dword(0));
    let mixed = boot_phase::elevation_bits(lsa_path, policies_path) == 0x6;
    let lua_off = registry::set_value(policies, "EnableLUA", REG_DWORD, dword(0)) && boot_phase::elevation_bits(lsa_path, policies_path) == 0x4;
    let uninstalled = registry::set_value(lsa, "UACInstalled", REG_DWORD, dword(0)) && boot_phase::elevation_bits(lsa_path, missing_path) == 0;
    assert(lsa != 0 && policies != 0 && not_installed && installed && all && written && mixed && lua_off && uninstalled, "uac-tokens: PsBootPhaseComplete liga os bits de UAC com UACInstalled, menos os REG_DWORD 0");
    for handle in [policies, lsa] {
        registry::delete_key(handle);
        registry::close_handle(handle);
    }
    if let Ok(parent) = registry::open_or_create(base, None) {
        registry::delete_key(parent);
        registry::close_handle(parent);
    }
}
