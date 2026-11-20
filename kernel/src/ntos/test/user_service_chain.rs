//! Autotestes dos serviços de modo usuário que os serviços do início
//! automático do services.exe pedem e que não tinham provedor:
//! NtCompareObjects (`ob/compare_objects`), NtCompareTokens
//! (`se/token/compare`), NtSetUuidSeed e NtAllocateUuids (`ex/uuid`) e
//! NtIsSystemResumeAutomatic (`po/system_state`).

use crate::ntos::ex::uuid;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::ObjectAttributes;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::po::system_state;
use crate::ntos::ps::process;
use crate::ntos::ps::user::{memory, state};
use crate::ntos::se::model::{sid, Group};
use crate::ntos::se::token::{handles as token_handles, thread as thread_tokens, tokens};

type Assert = fn(bool, &str);
type Call<'a> = &'a dyn Fn(&str, u64, u64, u64, u64) -> u32;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_NOT_SAME_OBJECT: u32 = 0xC000_01AC;
/// NtCurrentProcess e NtCurrentProcessToken.
const CURRENT_PROCESS: u64 = u64::MAX;
const CURRENT_PROCESS_TOKEN: u64 = u64::MAX - 3;
/// Um valor de handle muito acima dos que o boot dos autotestes abre.
const INVALID_HANDLE: u64 = 0x00FF_FFFC;

pub fn run(assert: Assert) {
    let Ok(block) = memory::map_user_region(0x3000) else {
        assert(false, "servicechain: memoria de usuario");
        return;
    };
    let rsp = block + 0x2000;
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map_or(u32::MAX, |handler| handler(a1, a2, a3, a4, rsp).unwrap_or(u32::MAX));
    resume_automatic(assert, &call);
    compare_objects(assert, block, rsp, &call);
    compare_tokens(assert, block, &call);
    uuid_seed(assert, block, &call);
    allocate_uuids(assert, block, &call);
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

/// PopFullWake = 1 desde o PoInitSystem: AL = 0 e o resto de EAX também.
/// A presença do usuário não muda um PopFullWake com o bit 0 ligado.
fn resume_automatic(assert: Assert, call: Call) {
    let first = call("NtIsSystemResumeAutomatic", 0, 0, 0, 0);
    system_state::set_user_present(1);
    let after_presence = call("NtIsSystemResumeAutomatic", 0, 0, 0, 0);
    assert(first == 0 && after_presence == 0 && system_state::full_wake() == 1, "servicechain: NtIsSystemResumeAutomatic devolve FALSE com PopFullWake = 1, mesmo depois da presenca do usuario");
}

/// OBJECT_ATTRIBUTES de usuário em `at` com o nome em `at + 0x100`.
fn attributes(at: u64, name: &str) -> u64 {
    state::write_user_wide(at + 0x100, name);
    state::write_unicode_string(at + 0x40, at + 0x100, name);
    // SAFETY: memória de usuário do teste, mapeada pelo kernel.
    let object = unsafe { ObjectAttributes::at(at) };
    object.length.set(ObjectAttributes::SIZE as u32);
    object.root_directory.set(0);
    object.object_name.set(at + 0x40);
    object.attributes.set(0x40);
    object.security_descriptor.set(0);
    object.security_quality_of_service.set(0);
    at
}

/// Dois handles do mesmo evento nomeado comparam iguais; eventos distintos
/// dão STATUS_NOT_SAME_OBJECT; um handle inválido volta como está.
fn compare_objects(assert: Assert, block: u64, rsp: u64, call: Call) {
    let (out, oa) = (block + 0x400, block + 0x800);
    let attributes = attributes(oa, "\\OpenNtCompararObjetos");
    guest::write32(rsp + 0x28, 0);
    let created = call("NtCreateEvent", out, 0x1F_0003, attributes, 0);
    let named = guest::read64(out);
    let opened = call("NtOpenEvent", out, 0x1F_0003, attributes, 0);
    let reopened = guest::read64(out);
    let anonymous_created = call("NtCreateEvent", out, 0x1F_0003, 0, 0);
    let anonymous = guest::read64(out);
    assert(created == 0 && opened == 0 && anonymous_created == 0 && named != reopened, "servicechain: dois handles do evento nomeado e um anonimo");
    let same = call("NtCompareObjects", named, reopened, 0, 0);
    let itself = call("NtCompareObjects", named, named, 0, 0);
    let different = call("NtCompareObjects", named, anonymous, 0, 0);
    let process_pseudo = call("NtCompareObjects", CURRENT_PROCESS, CURRENT_PROCESS, 0, 0);
    let process_and_event = call("NtCompareObjects", CURRENT_PROCESS, named, 0, 0);
    let invalid_second = call("NtCompareObjects", named, INVALID_HANDLE, 0, 0);
    let invalid_first = call("NtCompareObjects", INVALID_HANDLE, named, 0, 0);
    assert(same == 0 && itself == 0 && different == STATUS_NOT_SAME_OBJECT, "servicechain: NtCompareObjects compara os corpos dos objetos");
    assert(process_pseudo == 0 && process_and_event == STATUS_NOT_SAME_OBJECT, "servicechain: NtCompareObjects aceita o pseudo-handle do processo");
    assert(invalid_first == STATUS_INVALID_HANDLE && invalid_second == STATUS_INVALID_HANDLE, "servicechain: NtCompareObjects devolve a falha do ObReferenceObjectByHandle");
    for handle in [named, reopened, anonymous] {
        let _ = call("NtClose", handle, 0, 0, 0);
    }
}

/// Um token duplicado do primário compara igual; mudar um privilégio
/// habilitado, a ordem dos grupos ou os bits dos atributos do usuário
/// muda (ou não) o resultado como o SepCompareSidAndAttributeArrays.
fn compare_tokens(assert: Assert, block: u64, call: Call) {
    let equal = block + 0x500;
    let Some(primary) = process::get_primary_token(process::get_current_process()) else {
        assert(false, "servicechain: token primario do processo de teste");
        return;
    };
    let duplicate = |change: &dyn Fn(&mut tokens::Token)| -> Option<(u64, u64)> {
        let token = tokens::duplicate(primary, 2, false, 2).ok()?;
        tokens::update(token, |record| change(record));
        let handle = token_handles::create(token, 0x8, 0, true).ok()?;
        Some((token, handle))
    };
    let (Some(copy), Some(reordered), Some(privilege), Some(deny_only)) = (
        duplicate(&|_| {}),
        duplicate(&|record| record.groups.reverse()),
        duplicate(&|record| {
            if let Some(entry) = record.privileges.first_mut() {
                entry.attributes ^= 2;
            }
        }),
        duplicate(&|record| record.user_attributes ^= 0x10),
    ) else {
        assert(false, "servicechain: tokens duplicados para o NtCompareTokens");
        return;
    };
    let compare = |first: u64, second: u64| {
        guest::write8(equal, 0xAA);
        (call("NtCompareTokens", first, second, equal, 0), guest::read8(equal))
    };
    let has_groups = tokens::with(primary, |record| record.groups.len() > 1).unwrap_or(false);
    let has_privileges = tokens::with(primary, |record| !record.privileges.is_empty()).unwrap_or(false);
    assert(compare(CURRENT_PROCESS_TOKEN, CURRENT_PROCESS_TOKEN) == (0, 1) && compare(copy.1, copy.1) == (0, 1), "servicechain: NtCompareTokens com o mesmo handle da TRUE");
    assert(compare(CURRENT_PROCESS_TOKEN, copy.1) == (0, 1), "servicechain: NtCompareTokens iguala o primario e a copia dele");
    assert(!has_groups || compare(copy.1, reordered.1) == (0, 1), "servicechain: NtCompareTokens ignora a ordem dos grupos");
    assert(!has_privileges || compare(copy.1, privilege.1) == (0, 0), "servicechain: NtCompareTokens compara a mascara Enabled dos privilegios");
    assert(compare(copy.1, deny_only.1) == (0, 0), "servicechain: NtCompareTokens compara os bits 0x14 dos atributos do usuario");
    assert(compare(INVALID_HANDLE, copy.1) == (STATUS_INVALID_HANDLE, 0) && compare(copy.1, INVALID_HANDLE) == (STATUS_INVALID_HANDLE, 0), "servicechain: NtCompareTokens grava FALSE e devolve a falha da referencia");
    assert(call("NtCompareTokens", copy.1, copy.1, 0, 0) == STATUS_ACCESS_VIOLATION, "servicechain: NtCompareTokens sonda o Equal antes dos handles");
    for (token, handle) in [copy, reordered, privilege, deny_only] {
        let _ = call("NtClose", handle, 0, 0, 0);
        let _ = tokens::release(token);
    }
}

/// NtAllocateUuids (ExpAllocateUuids 0x69cdd4): uma faixa de até 10000
/// intervalos de 100 ns no máximo 1 s atrás, a sequência lida e gravada na
/// chave do Executive, o NodeId corrente e RPC_NT_UUID_LOCAL_ONLY sem
/// ExpUuidCacheValid; o pedido seguinte começa no fim da faixa (ou repete o
/// tick com a marca nos bits 23..27 da parte alta); alinhamento e ponteiro
/// inválido recusados.
fn allocate_uuids(assert: Assert, block: u64, call: Call) {
    let (time, range, sequence, seed) = (block + 0x700, block + 0x708, block + 0x70C, block + 0x710);
    let now = crate::ntos::ke::clock::system_time_100ns();
    let (node, valid) = uuid::node_seed();
    let expected = if valid { 0 } else { 0x4002_0056 };
    let first = call("NtAllocateUuids", time, range, sequence, seed);
    let (first_time, first_range, first_sequence) = (guest::read64(time), guest::read32(range), guest::read32(sequence));
    let first_node = guest::read_bytes(seed, 6);
    let saved = crate::ntos::cm::registry::read_value_by_path(uuid::SEQUENCE_KEY, uuid::SEQUENCE_VALUE).map(|value| value.data);
    assert(first == expected && first_node == node && (1..=10_000).contains(&first_range) && first_time <= now + 10_000_000 && saved.as_deref() == Some(&first_sequence.to_le_bytes()[..]), "servicechain: NtAllocateUuids devolve a faixa, a sequencia gravada na chave do Executive e o NodeId");
    let second = call("NtAllocateUuids", time, range, sequence, seed);
    let (second_time, second_sequence) = (guest::read64(time), guest::read32(sequence));
    let repeated = (second_time >> 32) & 0x0F80_0000 != 0;
    assert(second == expected && second_sequence == first_sequence && (second_time >= first_time + first_range as u64 || repeated), "servicechain: o NtAllocateUuids seguinte comeca no fim da faixa anterior com a mesma sequencia");
    assert(call("NtAllocateUuids", time + 1, range, sequence, seed) == 0x8000_0002 && call("NtAllocateUuids", 0, range, sequence, seed) == STATUS_ACCESS_VIOLATION, "servicechain: NtAllocateUuids recusa Time desalinhado e ponteiro invalido");
}

/// Sem o SID de serviço do RpcEptMapper, STATUS_ACCESS_DENIED e o nó
/// intacto; impersonando um token com ele, o nó muda e o bit de multicast
/// decide o ExpUuidCacheValid.
fn uuid_seed(assert: Assert, block: u64, call: Call) {
    let seed = block + 0x600;
    let initial = ([0x80, b'n', b'o', b'n', b'i', b'c'], false);
    for (index, byte) in [0x00u8, 0x15, 0x5D, 0x01, 0x02, 0x03].iter().enumerate() {
        guest::write8(seed + index as u64, *byte);
    }
    let denied = call("NtSetUuidSeed", seed, 0, 0, 0);
    assert(denied == STATUS_ACCESS_DENIED && uuid::node_seed() == initial, "servicechain: NtSetUuidSeed recusa o chamador sem o SID de servico do RpcEptMapper");
    let Some(primary) = process::get_primary_token(process::get_current_process()) else {
        assert(false, "servicechain: token primario para o NtSetUuidSeed");
        return;
    };
    let service = sid(5, &[80, 0x1F12_C0C6, 0x3601_1346, 0xE65A_CE03, 0x5AE7_EA38, 0xCDB5_8062]);
    let Ok(token) = tokens::duplicate(primary, 2, false, 2) else {
        assert(false, "servicechain: token de impersonacao do RpcEptMapper");
        return;
    };
    tokens::update(token, |record| record.groups.push(Group { sid: service.clone(), attributes: 7 }));
    let thread = process::get_current_thread();
    let previous = thread_tokens::get(thread);
    let identification = thread_tokens::assign(thread, Some(token), 1, false, false).is_ok() && call("NtSetUuidSeed", seed, 0, 0, 0) == STATUS_ACCESS_DENIED;
    let impersonating = thread_tokens::assign(thread, Some(token), 2, false, false).is_ok();
    let accepted = call("NtSetUuidSeed", seed, 0, 0, 0);
    let after_seed = uuid::node_seed();
    let bad_pointer = call("NtSetUuidSeed", 0, 0, 0, 0);
    guest::write8(seed, 0x81);
    let multicast = call("NtSetUuidSeed", seed, 0, 0, 0);
    let after_multicast = uuid::node_seed();
    for (index, byte) in initial.0.iter().enumerate() {
        guest::write8(seed + index as u64, *byte);
    }
    let restored = call("NtSetUuidSeed", seed, 0, 0, 0) == 0 && uuid::node_seed() == initial;
    let _ = match previous {
        Some(state) => thread_tokens::assign(thread, Some(state.token), state.level, state.copy_on_open, state.effective_only),
        None => thread_tokens::release(thread),
    };
    let _ = tokens::release(token);
    assert(identification, "servicechain: NtSetUuidSeed recusa a impersonacao abaixo de SecurityImpersonation");
    assert(impersonating && accepted == 0 && after_seed == ([0x00, 0x15, 0x5D, 0x01, 0x02, 0x03], true), "servicechain: NtSetUuidSeed grava o no e liga o ExpUuidCacheValid");
    assert(bad_pointer == STATUS_ACCESS_VIOLATION, "servicechain: NtSetUuidSeed sonda a semente depois do acesso");
    assert(multicast == 0 && after_multicast == ([0x81, 0x15, 0x5D, 0x01, 0x02, 0x03], false) && restored, "servicechain: o bit de multicast desliga o ExpUuidCacheValid");
}
