//! Self-test da fase 5 — Registro e serviços.
//!
//! Exercita a hive em memória, os objetos de chave, a serialização das
//! classes KEY_* e os provedores e serviços construídos sobre o registro.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{
    CmKeyBody, Eprocess, KeyBasicInformation, KeyCachedInformation, KeyFullInformation, KeyHandleTagsInformation, KeyNameInformation,
    KeyValueFullInformation, KeyValuePartialInformation, KeyValuePartialInformationAlign64, LargeInteger, NtStruct, ObjectAttributes,
    RegPostOperationInformation, RtlFeatureUsageReport, SecurityDescriptorRelative, UnicodeString, WnfDataScope, WnfNameInstance,
    WnfProcessContext, WnfScopeInstance, WnfStateData, WnfStateName, WnfSubscription, WnfSubscriptionState,
};

type Assert = fn(bool, &str);

/// WNF_STATE_NAME (dois ULONGs) como o valor de 64 bits.
fn read_state_name(address: u64) -> u64 {
    let name = unsafe { WnfStateName::at(address) };
    (name.data[1].get() as u64) << 32 | name.data[0].get() as u64
}

fn write_state_name(address: u64, value: u64) {
    let name = unsafe { WnfStateName::at(address) };
    name.data[0].set(value as u32);
    name.data[1].set((value >> 32) as u32);
}

static NOTIFICATIONS: AtomicU32 = AtomicU32::new(0);

fn registry_hive(assert: Assert) {
    use crate::ntos::cm::registry;
    let base = "\\Registry\\Machine\\Software\\OpenNTSelfTest";
    let watch = registry::watch(base, Arc::new(|_path: &str| {
        NOTIFICATIONS.fetch_add(1, Ordering::SeqCst);
    }));
    NOTIFICATIONS.store(0, Ordering::SeqCst);
    let statistics = registry::object_stats();
    let child = registry::open_or_create("\\Registry\\Machine\\Software\\OpenNTSelfTest\\Filho", None).unwrap_or(0);
    assert(child != 0 && NOTIFICATIONS.load(Ordering::SeqCst) == 1, "registry: criacao de caminho notifica o observador");
    let again = registry::open_or_create("\\REGISTRY\\machine\\software\\openntselftest\\opennttest", None).unwrap_or(0);
    assert(again != 0 && NOTIFICATIONS.load(Ordering::SeqCst) == 2, "registry: nome novo noutra caixa cria outra subchave");
    let reopened = registry::open("\\registry\\MACHINE\\Software\\OPENNTSELFTEST\\FILHO").unwrap_or(0);
    assert(reopened != 0 && registry::get_node(reopened) == registry::get_node(child) && registry::open("\\Registry\\Machine\\Software\\Ausente").ok() == Some(0), "registry: travessia sem diferenca de caixa; ausencia devolve zero");
    assert(registry::object_stats().handles == statistics.handles + 3 && registry::object_stats().objects >= statistics.objects + 2, "registry: estatisticas de objetos e handles");
    let names = registry::list_keys(base);
    assert(names.len() == 2 && names[0] == "Filho" && names[1] == "opennttest", "registry: subchaves em ordem de insercao com nome preservado");
    // Valores sem diferença de caixa; regravar mantém a posição.
    let before = registry::with_node(registry::get_node(child).unwrap_or(0), |key| key.last_write_time).unwrap_or(0);
    assert(registry::set_value(child, "Primeiro", 4, alloc::vec![1, 0, 0, 0]) && registry::set_value(child, "Segundo", 1, alloc::vec![b'a', 0]) && registry::set_value(reopened, "PRIMEIRO", 4, alloc::vec![2, 0, 0, 0]), "registry: valores gravados");
    let value = registry::get_value(child, "primeiro");
    let order = registry::with_node(registry::get_node(child).unwrap_or(0), |key| key.values.iter().map(|(_, value)| value.name.clone()).collect::<alloc::vec::Vec<_>>()).unwrap_or_default();
    assert(value.is_some_and(|value| value.name == "PRIMEIRO" && value.data == [2, 0, 0, 0]) && order.len() == 2 && order[0] == "PRIMEIRO", "registry: regravar substitui no lugar");
    assert(registry::read_value_by_path("\\registry\\machine\\software\\openntselftest\\opennttest", "segundo").is_none() && registry::read_value_by_path(&(alloc::string::String::from(base) + "\\Filho"), "segundo").is_some_and(|value| value.value_type == 1), "registry: consulta interna por caminho");
    let after = registry::with_node(registry::get_node(child).unwrap_or(0), |key| key.last_write_time).unwrap_or(0);
    assert(after >= before && NOTIFICATIONS.load(Ordering::SeqCst) == 5, "registry: LastWriteTime e notificacao a cada gravacao");
    assert(registry::delete_value(child, "SEGUNDO") && !registry::delete_value(child, "segundo") && NOTIFICATIONS.load(Ordering::SeqCst) == 6, "registry: exclusao de valor so notifica quando remove");
    // Exclusão: só folhas; handles antigos deixam de resolver a identidade.
    let parent = registry::open(base).unwrap_or(0);
    assert(!registry::delete_key(parent), "registry: chave com filhos nao e excluida");
    let node = registry::get_node(child).unwrap_or(0);
    assert(registry::delete_key(child) && registry::get_node(reopened).is_none() && registry::get_path(child).is_none() && registry::is_deleted(node) && !registry::set_value(reopened, "x", 4, alloc::vec![0; 4]), "registry: chave excluida invalida os handles antigos");
    assert(!registry::delete_key(reopened) && registry::list_keys(base).len() == 1, "registry: exclusao repetida recusada");
    let extra = registry::open(&(alloc::string::String::from(base) + "\\opennttest")).unwrap_or(0);
    assert(registry::delete_key(extra) && registry::delete_key(parent), "registry: folhas e depois o pai");
    for handle in [child, again, reopened, parent, extra] {
        assert(registry::close_handle(handle), "registry: fechamento do handle");
    }
    assert(!registry::close_handle(child) && registry::object_stats().handles == statistics.handles, "registry: handle fechado nao existe mais");
    assert(registry::unwatch(watch) && !registry::unwatch(watch), "registry: inscricao removida");
}

fn key_information_classes(assert: Assert) {
    use crate::ntos::cm::key::information as key_information;
    use crate::ntos::cm::{registry, value_information};
    let path = "\\Registry\\Machine\\Software\\OpenNTInfo";
    let handle = registry::open_or_create(path, None).unwrap_or(0);
    let child = registry::open_or_create("\\Registry\\Machine\\Software\\OpenNTInfo\\Subchave", None).unwrap_or(0);
    registry::set_value(handle, "Valor", 4, alloc::vec![0x78, 0x56, 0x34, 0x12]);
    registry::set_value(handle, "Texto", 1, alloc::vec![b'o', 0, b'k', 0, 0, 0]);
    let node = registry::get_node(handle).unwrap_or(0);
    let buffer = guest::alloc_bytes(0x200);
    let length = guest::alloc_bytes(8);
    // KeyBasicInformation: 16 + nome em UTF-16.
    let basic = unsafe { KeyBasicInformation::at(buffer) };
    assert(key_information::write(node, path, 0, buffer, 0x200, length, 0) == 0 && guest::read32(length) == 16 + 20 && basic.name_length.get() == 20 && basic.name[0].get() == b'O' as u16, "keyinfo: Basic com nome do no");
    assert(key_information::write(node, path, 0, buffer, 8, length, 0) == 0xC000_0023 && guest::read32(length) == 36, "keyinfo: buffer menor que o cabecalho");
    guest::write_bytes(buffer, &[0xEE; 40]);
    assert(key_information::write(node, path, 0, buffer, 20, length, 0) == 0x8000_0005 && basic.name[0].get() == b'O' as u16 && guest::read_bytes(basic.name[0].address() + 4, 1) == [0xEE], "keyinfo: nome truncado devolve BUFFER_OVERFLOW");
    // KeyFullInformation: contagens e máximos.
    let full = unsafe { KeyFullInformation::at(buffer) };
    assert(key_information::write(node, path, 2, buffer, 0x200, length, 0) == 0 && guest::read32(length) == 44 && full.class_offset.get() == 0xFFFF_FFFF && full.sub_keys.get() == 1 && full.max_name_len.get() == 16 && full.values.get() == 2 && full.max_value_name_len.get() == 10 && full.max_value_data_len.get() == 6, "keyinfo: Full com subchaves, valores e maximos");
    let cached = unsafe { KeyCachedInformation::at(buffer) };
    assert(key_information::write(node, path, 4, buffer, 0x200, length, 0) == 0 && cached.sub_keys.get() == 1 && cached.values.get() == 2 && cached.name_length.get() == 20, "keyinfo: Cached com o nome do no");
    let name = unsafe { KeyNameInformation::at(buffer) };
    assert(key_information::write(node, path, 3, buffer, 0x200, length, 0) == 0 && name.name_length.get() == path.len() as u32 * 2 && name.name[0].get() == b'\\' as u16, "keyinfo: Name com caminho absoluto");
    assert(key_information::write(node, path, 7, buffer, 0x200, length, 0x5) == 0 && unsafe { KeyHandleTagsInformation::at(buffer) }.handle_tags.get() == 5 && key_information::write(node, path, 5, buffer, 0x200, length, 0) == 0xC000_0003, "keyinfo: HandleTags e classe invalida");
    // KEY_VALUE_*.
    let value = registry::get_value(handle, "valor").unwrap_or(registry::Value { name: alloc::string::String::new(), value_type: 0, data: alloc::vec::Vec::new() });
    let partial = unsafe { KeyValuePartialInformation::at(buffer) };
    assert(value_information::write(&value, 2, buffer, 0x200, length) == 0 && guest::read32(length) == 16 && partial.type_.get() == 4 && partial.data_length.get() == 4 && guest::read32(partial.data[0].address()) == 0x1234_5678, "valueinfo: Partial");
    let full_value = unsafe { KeyValueFullInformation::at(buffer) };
    assert(value_information::write(&value, 1, buffer, 0x200, length) == 0 && guest::read32(length) == 36 && full_value.data_offset.get() == 32 && full_value.data_length.get() == 4 && full_value.name_length.get() == 10 && guest::read32(buffer + full_value.data_offset.get() as u64) == 0x1234_5678, "valueinfo: Full com dados alinhados depois do nome");
    assert(value_information::write(&value, 3, buffer + 4, 0x200, length) == 0x8000_0002 && value_information::write(&value, 3, buffer, 0x200, length) == 0 && full_value.data_offset.get() == 32, "valueinfo: Align64 exige saida alinhada");
    let aligned = unsafe { KeyValuePartialInformationAlign64::at(buffer) };
    assert(value_information::write(&value, 4, buffer, 0x200, length) == 0 && aligned.type_.get() == 4 && aligned.data_length.get() == 4 && guest::read32(aligned.data[0].address()) == 0x1234_5678, "valueinfo: PartialAlign64");
    assert(value_information::write(&value, 0, buffer, 14, length) == 0x8000_0005 && guest::read32(length) == 22 && value_information::write(&value, 2, buffer, 11, length) == 0xC000_0023 && value_information::write(&value, 9, buffer, 0x200, length) == 0xC000_0003, "valueinfo: truncado, curto e classe invalida");
    registry::delete_key(child);
    registry::delete_key(handle);
    registry::close_handle(child);
    registry::close_handle(handle);
    guest::free_bytes(buffer);
    guest::free_bytes(length);
}

fn key_objects_and_security(assert: Assert) {
    use crate::ntos::cm::key::{access as key_access, objects as key_objects, policy as key_policy, security as key_security};
    use crate::ntos::cm::registry;
    use crate::ntos::se::inherit_descriptor::Captured;
    let handle = registry::open_or_create("\\Registry\\Machine\\Software\\OpenNTBody", None).unwrap_or(0);
    let body = key_objects::for_handle(handle).unwrap_or(0);
    assert(body != 0 && key_objects::for_handle(handle) == Some(body) && key_objects::get(body).is_some_and(|record| record.handles == 1 && record.references == 0 && record.path.ends_with("OpenNTBody")), "keyobjects: corpo materializado uma vez por handle");
    assert(unsafe { CmKeyBody::at(body) }.process_id.get() == crate::ntos::ps::process::get_current_process_id(), "keyobjects: processo criador no CM_KEY_BODY");
    key_objects::hold(body);
    key_objects::detach(handle);
    assert(key_objects::get(body).is_some_and(|record| record.handles == 0 && record.references == 1), "keyobjects: retencao mantem o corpo sem handles");
    assert(key_objects::release(body).is_ok() && key_objects::get(body).is_none() && key_objects::release(body).is_err(), "keyobjects: ultima referencia libera; underflow recusado");
    let node = registry::get_node(handle).unwrap_or(0);
    let temporary = key_objects::temporary(node, "\\Registry\\Machine\\Software\\OpenNTBody").unwrap_or(0);
    assert(temporary != 0 && key_objects::attach(handle, temporary).is_ok() && key_objects::attach(handle, temporary).is_err(), "keyobjects: corpo temporario associado a um handle");
    key_objects::detach(handle);
    assert(key_objects::get(temporary).is_some() && key_objects::release(temporary).is_ok() && key_objects::get(temporary).is_none(), "keyobjects: corpo temporario liberado");
    // Direitos de chave.
    assert(key_access::key_access(0x300, 0) == Err(0xC000_000D) && key_access::key_access(0x200, 0) == Err(0xC000_00BB), "keyaccess: visoes WOW64");
    assert(key_access::key_access(0x8000_0000, 0) == Ok(0x20019) && key_access::key_access(0x1000_0000 | 0x100, 0) == Ok(0xF003F) && key_access::key_access(0x200_0000, 0) == Ok(0x200_0000), "keyaccess: genericos mapeados e MAXIMUM_ALLOWED preservado");
    assert(key_access::key_access(0x40, 0) == Err(0xC000_0022), "keyaccess: bit invalido");
    // Política da hive: raiz administrada por SYSTEM, filhos herdam.
    let root = key_policy::boot_root();
    let child = key_policy::boot_child(&root);
    assert(child.as_ref().is_ok_and(|child| child.control & 4 != 0 && child.dacl.as_ref().is_some_and(|dacl| u16::from_le_bytes([dacl[4], dacl[5]]) == 3) && child.owner == root.owner), "keypolicy: filho herda as tres ACEs da raiz");
    assert(registry::with_node(node, |key| key.security.dacl.is_some()).unwrap_or(false), "keypolicy: no da hive com descritor herdado");
    assert(key_security::access(&root, 0, true) == Err(0xC000_0022) && key_security::access(&root, 0x20019, false) == Ok(0x20019), "keysecurity: acesso vazio negado; modo kernel concede o explicito");
    let null_dacl = Captured { control: 4, owner: root.owner.clone(), group: root.group.clone(), dacl: None, sacl: None };
    assert(key_security::access(&null_dacl, 0x200_0000, true) == Ok(0xF003F), "keysecurity: MAXIMUM_ALLOWED numa DACL nula");
    assert(matches!(key_security::create(&root, 0, true), Ok(Ok(ref created)) if created.dacl.is_some() && created.control & 4 != 0), "keysecurity: criacao herda a DACL do pai");
    let policy = key_security::access_policy(&root);
    assert(policy.dacl.as_ref().is_some_and(|dacl| dacl.len() == 3 && dacl[2].mask == 0x20019 && !dacl[0].deny) && policy.dacl_bytes.is_some(), "keysecurity: politica de acesso a partir do descritor");
    let output = guest::alloc_bytes(0x100);
    let body = key_objects::for_handle(handle).unwrap_or(0);
    let result = key_security::query(body, 4, output, 0x100);
    assert(result.as_ref().is_ok_and(|result| result.status == 0 && result.needed > 20) && unsafe { SecurityDescriptorRelative::at(output) }.control.get() & 0x8004 == 0x8004, "keysecurity: consulta da DACL autocontida");
    registry::delete_key(handle);
    assert(key_security::query(body, 4, output, 0x100).is_ok_and(|result| result.status == 0xC000_017C && result.needed == 0x100), "keysecurity: chave excluida");
    registry::close_handle(handle);
    key_objects::detach(handle);
    guest::free_bytes(output);
}

static CALLBACK_LOG: crate::rtl::SpinLock<alloc::vec::Vec<u64>> = crate::rtl::SpinLock::new(alloc::vec::Vec::new());
/// (contexto, classe) que devolve o status configurado.
static CALLBACK_RULE: [core::sync::atomic::AtomicU64; 3] = [const { core::sync::atomic::AtomicU64::new(0) }; 3];

extern "win64" fn test_registry_callback(context: u64, class: u64, information: u64) -> u64 {
    CALLBACK_LOG.lock().push(context * 100 + class);
    // CallContext próprio da inscrição, conferido na notificação posterior.
    if class == 1 {
        guest::write64(information + 0x20, 0xC000 + context);
    } else if class == 2 && unsafe { RegPostOperationInformation::at(information) }.call_context.get() != 0xC000 + context {
        return 0xC000_0001;
    }
    if CALLBACK_RULE[0].load(Ordering::SeqCst) == context && CALLBACK_RULE[1].load(Ordering::SeqCst) == class {
        return CALLBACK_RULE[2].load(Ordering::SeqCst);
    }
    0
}

struct TestOutcome {
    status: u32,
    object: u64,
}

impl crate::ntos::cm::callbacks::Outcome for TestOutcome {
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
        Self { status, object: 0 }
    }
}

fn registry_callbacks(assert: Assert) {
    use crate::ntos::cm::callbacks::{self, Operation, CALLBACK_BYPASS};
    let storage = guest::alloc_bytes(0x200);
    let altitude = storage;
    let cookie = storage + 0x80;
    let information = storage + 0x100;
    let write_altitude = |value: &str| license_unicode(altitude, value);
    let cookie_value = || unsafe { LargeInteger::at(cookie) }.quad_part.get() as u64;
    let routine = test_registry_callback as extern "win64" fn(u64, u64, u64) -> u64 as usize as u64;
    write_altitude("380000");
    assert(matches!(callbacks::register(routine, altitude, 0, 1, cookie, 0), Ok(0xC000_00F1)) && matches!(callbacks::register(routine, altitude, 1, 1, cookie, 8), Ok(0xC000_00F4)), "cmcallbacks: Driver nulo e Reserved recusados");
    assert(matches!(callbacks::register(routine, altitude, 1, 1, cookie, 0), Ok(0)), "cmcallbacks: CmRegisterCallbackEx");
    let high = cookie_value();
    write_altitude("0380000.000");
    assert(matches!(callbacks::register(routine, altitude, 1, 9, cookie, 0), Ok(0xC01C_0011)) && cookie_value() == high + 1 && callbacks::get(high + 1).is_none(), "cmcallbacks: altitude equivalente recusada com cookie publicado");
    write_altitude("370000");
    assert(matches!(callbacks::register(routine, altitude, 1, 2, cookie, 0), Ok(0)), "cmcallbacks: segunda altitude");
    let low = cookie_value();
    assert(callbacks::get(high).is_some_and(|(pointer, text, active, removing)| text == "380000" && active == 0 && !removing && guest::read64(pointer + 24) == high && guest::read64(pointer + 40) == routine), "cmcallbacks: registro de 80 bytes com cookie e rotina");
    // Pré em altitude decrescente, ação, pós em ordem inversa.
    let operation = Operation::<TestOutcome> { pre: 1, post: 2, info: information, call_offset: 0x20, object: 0x55, unblockable: false, bypass: None };
    CALLBACK_LOG.lock().clear();
    let mut executed = false;
    let result = callbacks::perform(&operation, || {
        executed = true;
        TestOutcome { status: 0, object: 0x1234 }
    });
    let log = CALLBACK_LOG.lock().clone();
    assert(executed && result.as_ref().is_ok_and(|result| result.status == 0 && result.object == 0x1234) && log == [101, 201, 202, 102], "cmcallbacks: ordem pre/pos e CallContext por inscricao");
    // Erro no pré bloqueia a operação e pula filtros mais baixos.
    CALLBACK_RULE[0].store(1, Ordering::SeqCst);
    CALLBACK_RULE[1].store(1, Ordering::SeqCst);
    CALLBACK_RULE[2].store(0xC000_0022, Ordering::SeqCst);
    CALLBACK_LOG.lock().clear();
    let mut executed = false;
    let result = callbacks::perform(&operation, || {
        executed = true;
        TestOutcome { status: 0, object: 0 }
    });
    assert(!executed && result.is_ok_and(|result| result.status == 0xC000_0022) && *CALLBACK_LOG.lock() == [101], "cmcallbacks: pre com erro bloqueia");
    // Bypass no pré do filtro baixo: a operação é concluída pelo filtro.
    CALLBACK_RULE[0].store(2, Ordering::SeqCst);
    CALLBACK_RULE[2].store(CALLBACK_BYPASS as u64, Ordering::SeqCst);
    CALLBACK_LOG.lock().clear();
    let bypass = || TestOutcome { status: 0, object: 0x77 };
    let bypassing = Operation::<TestOutcome> { bypass: Some(&bypass), ..operation };
    let result = callbacks::perform(&bypassing, || TestOutcome { status: 0xC000_0001, object: 0 });
    assert(result.is_ok_and(|result| result.status == 0 && result.object == 0x77) && *CALLBACK_LOG.lock() == [101, 201, 102], "cmcallbacks: bypass no pre conclui pelo filtro e notifica os anteriores");
    // Bypass no pós substitui Status e Object pelo REG_POST_OPERATION_INFORMATION.
    CALLBACK_RULE[1].store(2, Ordering::SeqCst);
    let result = callbacks::perform(&operation, || TestOutcome { status: 0, object: 0 });
    assert(result.is_ok_and(|result| result.status == 0 && result.object == 0x55), "cmcallbacks: bypass no pos relê o objeto efetivo");
    // Operação não bloqueável ignora erros dos filtros.
    CALLBACK_RULE[1].store(1, Ordering::SeqCst);
    CALLBACK_RULE[2].store(0xC000_0022, Ordering::SeqCst);
    let unblockable = Operation::<TestOutcome> { unblockable: true, ..operation };
    assert(callbacks::perform(&unblockable, || TestOutcome { status: 0, object: 0 }).is_ok_and(|result| result.status == 0), "cmcallbacks: operacao nao bloqueavel");
    CALLBACK_RULE[0].store(0, Ordering::SeqCst);
    assert(matches!(callbacks::remove(high), Ok(0)) && matches!(callbacks::remove(high), Ok(0xC000_000D)) && callbacks::get(high).is_none(), "cmcallbacks: CmUnRegisterCallback");
    assert(matches!(callbacks::remove(low), Ok(0)) && !callbacks::has(), "cmcallbacks: ultima inscricao removida");
    guest::free_bytes(storage);
}

static KEY_LOG: crate::rtl::SpinLock<alloc::vec::Vec<u64>> = crate::rtl::SpinLock::new(alloc::vec::Vec::new());

extern "win64" fn test_key_logger(_context: u64, class: u64, _information: u64) -> u64 {
    KEY_LOG.lock().push(class);
    0
}

/// OBJECT_ATTRIBUTES com o UNICODE_STRING logo depois (e o texto depois dele).
fn object_attributes(pointer: u64, root: u64, name: &str, attributes: u32) {
    let name_address = pointer + ObjectAttributes::SIZE;
    guest::write_bytes(pointer, &[0; (ObjectAttributes::SIZE + UnicodeString::SIZE) as usize]);
    let object_attributes = unsafe { ObjectAttributes::at(pointer) };
    object_attributes.length.set(ObjectAttributes::SIZE as u32);
    object_attributes.root_directory.set(root);
    object_attributes.object_name.set(name_address);
    object_attributes.attributes.set(attributes);
    license_unicode(name_address, name);
}

fn key_services_kernel_mode(assert: Assert) {
    use crate::ntos::cm::key::services::{self as keys, fields, Kind};
    use crate::ntos::cm::{callbacks, registry};
    let (status, parent) = keys::open_path("\\Registry\\Machine\\Software\\OpenNTKeys", true).unwrap_or((1, 0));
    assert(status == 0 && parent != 0 && keys::close_record(parent as u32).is_some_and(|record| record.kernel_handle && record.access == 0xF003F), "keyservices: abertura interna com handle de kernel");
    assert(matches!(keys::named_value(Kind::Set, parent, "Versao", 4, &[7, 0, 0, 0]), Ok((0, None))), "keyservices: NtSetValueKey por nome");
    let queried = keys::named_value(Kind::QueryValue, parent, "VERSAO", 0, &[]);
    assert(matches!(queried, Ok((0, Some(ref value))) if value.value_type == 4 && value.data == [7, 0, 0, 0]), "keyservices: NtQueryValueKey em duas etapas");
    assert(matches!(keys::named_value(Kind::QueryValue, parent, "Ausente", 0, &[]), Ok((0xC000_0034, None))), "keyservices: valor ausente");
    // NtCreateKey relativo à raiz, com disposição.
    let storage = guest::alloc_bytes(0x400);
    let attributes = storage;
    let output = storage + 0x100;
    let disposition = storage + 0x108;
    let buffer = storage + 0x200;
    let returned = storage + 0x110;
    object_attributes(attributes, parent, "Filho", 0x240);
    assert(matches!(keys::create(output, 0xF003F, attributes, 0, 0, 0, disposition, false), Ok(0)) && guest::read32(disposition) == 1, "keyservices: NtCreateKey cria (REG_CREATED_NEW_KEY)");
    let child = guest::read64(output);
    assert(matches!(keys::create(output, 0xF003F, attributes, 0, 0, 0, disposition, false), Ok(0)) && guest::read32(disposition) == 2 && guest::read64(output) != child, "keyservices: NtCreateKey abre existente (REG_OPENED_EXISTING_KEY)");
    let second = guest::read64(output);
    object_attributes(attributes, 0, "\\Registry\\Machine\\Software\\OpenNTKeys\\Ausente", 0x240);
    assert(matches!(keys::open(output, 0x20019, attributes, false, 0), Ok(0xC000_0034)), "keyservices: NtOpenKey de chave ausente");
    object_attributes(attributes, 0, "\\Machine\\Software", 0x240);
    assert(matches!(keys::open(output, 0x20019, attributes, false, 0), Ok(0xC000_003B)), "keyservices: caminho fora de Registry");
    object_attributes(attributes, parent, "\\Registry", 0x240);
    assert(matches!(keys::open(output, 0x20019, attributes, false, 0), Ok(0xC000_003B)), "keyservices: nome absoluto com raiz");
    object_attributes(attributes, parent, "Filho", 0x240);
    assert(matches!(keys::open(output, 0x20019, attributes, false, 2), Ok(0xC000_00F2)) && matches!(keys::create(output, 0x20019, attributes, 0, 0, 4, 0, false), Ok(0xC000_000D)), "keyservices: opcoes invalidas");
    unsafe { ObjectAttributes::at(attributes) }.length.set(40);
    assert(matches!(keys::open(output, 0x20019, attributes, false, 0), Ok(0xC000_000D)), "keyservices: OBJECT_ATTRIBUTES com tamanho errado");
    object_attributes(attributes, 0x7FFF_FFF0, "Filho", 0x240);
    assert(matches!(keys::open(output, 0x20019, attributes, false, 0), Ok(0xC000_0008)), "keyservices: raiz invalida");
    // Enumeração e consulta.
    let enumerate = |index: u64, class: u64| keys::key_operation(Kind::EnumerateKey, parent, &fields(&[("index", index), ("klass", class), ("out", buffer), ("length", 0x100), ("returned", returned)]), false);
    let basic = unsafe { KeyBasicInformation::at(buffer) };
    assert(matches!(enumerate(0, 0), Ok(0)) && basic.name_length.get() == 10 && basic.name[0].get() == 0x46, "keyservices: NtEnumerateKey");
    assert(matches!(enumerate(1, 0), Ok(0x8000_001A)) && matches!(enumerate(0, 3), Ok(0xC000_0003)), "keyservices: fim da enumeracao e classe invalida");
    assert(matches!(keys::key_operation(Kind::EnumerateValue, parent, &fields(&[("index", 0), ("klass", 2), ("out", buffer), ("length", 0x100), ("returned", returned)]), false), Ok(0)) && guest::read32(unsafe { KeyValuePartialInformation::at(buffer) }.data[0].address()) == 7, "keyservices: NtEnumerateValueKey");
    let child_path_length = "\\Registry\\Machine\\Software\\OpenNTKeys\\Filho".len() as u32 * 2;
    assert(matches!(keys::key_operation(Kind::QueryKey, child, &fields(&[("klass", 3), ("out", buffer), ("length", 0x100), ("returned", returned)]), false), Ok(0)) && unsafe { KeyNameInformation::at(buffer) }.name_length.get() == child_path_length, "keyservices: KeyNameInformation pelo caminho do handle");
    // Tags do handle (KeySetHandleTagsInformation).
    let tags = &unsafe { KeyHandleTagsInformation::at(buffer) }.handle_tags;
    tags.set(0x5A);
    assert(matches!(keys::key_operation(Kind::SetInfo, child, &fields(&[("klass", 5), ("data", buffer), ("length", 4)]), false), Ok(0)), "keyservices: NtSetInformationKey de tags");
    assert(matches!(keys::key_operation(Kind::SetInfo, child, &fields(&[("klass", 5), ("data", buffer), ("length", 8)]), false), Ok(0xC000_0004)) && matches!(keys::key_operation(Kind::SetInfo, child, &fields(&[("klass", 1), ("data", buffer), ("length", 4)]), false), Ok(0xC000_0003)), "keyservices: classe e tamanho de SetInformation");
    assert(matches!(keys::key_operation(Kind::QueryKey, child, &fields(&[("klass", 7), ("out", buffer), ("length", 4), ("returned", returned)]), false), Ok(0)) && tags.get() == 0x5A, "keyservices: tags por handle");
    assert(matches!(keys::key_operation(Kind::QueryKey, second, &fields(&[("klass", 7), ("out", buffer), ("length", 4), ("returned", returned)]), false), Ok(0)) && tags.get() == 0, "keyservices: tags independentes por handle");
    // Filtros veem as operações e o fechamento.
    license_unicode(storage + 0x300, "320000");
    let logger = test_key_logger as extern "win64" fn(u64, u64, u64) -> u64 as usize as u64;
    assert(matches!(callbacks::register(logger, storage + 0x300, 1, 0, storage + 0x340, 0), Ok(0)), "keyservices: filtro registrado");
    let cookie = unsafe { LargeInteger::at(storage + 0x340) }.quad_part.get() as u64;
    KEY_LOG.lock().clear();
    let (status, filtered) = keys::open_path("\\Registry\\Machine\\Software\\OpenNTKeys\\Filho", false).unwrap_or((1, 0));
    assert(status == 0 && filtered != 0 && *KEY_LOG.lock() == [28, 29], "keyservices: RegNtPreOpenKeyEx/PostOpenKeyEx");
    KEY_LOG.lock().clear();
    assert(matches!(keys::named_value(Kind::QueryValue, parent, "Versao", 0, &[]), Ok((0, Some(_)))) && *KEY_LOG.lock() == [8, 23, 8, 23], "keyservices: notificacoes de consulta de valor");
    KEY_LOG.lock().clear();
    assert(registry::close_handle(filtered as u32) && *KEY_LOG.lock() == [14, 25] && keys::close_record(filtered as u32).is_none(), "keyservices: fechamento notificado sem veto");
    assert(matches!(callbacks::remove(cookie), Ok(0)), "keyservices: filtro removido");
    // Exclusão.
    assert(matches!(keys::key_operation(Kind::DeleteKey, parent, &fields(&[]), false), Ok(0xC000_0121)), "keyservices: chave com subchaves nao e excluida");
    assert(matches!(keys::key_operation(Kind::DeleteKey, child, &fields(&[]), false), Ok(0)) && matches!(keys::key_operation(Kind::QueryKey, second, &fields(&[("klass", 0), ("out", buffer), ("length", 0x100), ("returned", returned)]), false), Ok(0xC000_017C)), "keyservices: chave excluida invalida os outros handles");
    assert(matches!(keys::named_value(Kind::DeleteValue, parent, "Versao", 0, &[]), Ok((0, None))) && matches!(keys::named_value(Kind::DeleteValue, parent, "Versao", 0, &[]), Ok((0xC000_0034, None))), "keyservices: NtDeleteValueKey");
    // Segurança pelo corpo do handle.
    let body = crate::ntos::cm::key::objects::for_handle(parent as u32).unwrap_or(0);
    assert(keys::query_security(body, 4, buffer, 0x100).is_ok_and(|result| result.status == 0 && result.needed > 20), "keyservices: NtQuerySecurityObject da chave");
    // Fechamento pelos hooks: tabela do processo, registro e identidade.
    for handle in [child, second, parent] {
        assert(registry::close_handle(handle as u32) && keys::close_record(handle as u32).is_none(), "keyservices: fechamento pelos hooks");
    }
    assert(matches!(keys::key_operation(Kind::QueryKey, parent, &fields(&[("klass", 0), ("out", buffer), ("length", 0x100), ("returned", returned)]), false), Ok(0xC000_0008)), "keyservices: handle fechado e invalido");
    let (status, cleanup) = keys::open_path("\\Registry\\Machine\\Software\\OpenNTKeys", false).unwrap_or((1, 0));
    assert(status == 0 && matches!(keys::key_operation(Kind::DeleteKey, cleanup, &fields(&[]), false), Ok(0)) && registry::close_handle(cleanup as u32), "keyservices: limpeza da chave de teste");
    guest::free_bytes(storage);
}

fn wide_text(value: &crate::ntos::cm::registry::Value) -> alloc::string::String {
    let units: alloc::vec::Vec<u16> = value.data.chunks(2).map(|pair| u16::from_le_bytes([pair[0], *pair.get(1).unwrap_or(&0)])).take_while(|&unit| unit != 0).collect();
    alloc::string::String::from_utf16_lossy(&units)
}

fn registry_boot_providers(assert: Assert) {
    use crate::ntos::cm::{check_registry_key, cng_defaults, computer_name, crypto_defaults, persisted_state, physical_memory_resources, registry, wnf_defaults};
    use crate::ntos::cm::key::native as native_keys;
    let storage = guest::alloc_bytes(0x400);
    let write_wide = |pointer: u64, text: &str| crate::ntos::rtl::guest_strings::write_wide_string(pointer, text);
    // ZwOpenKey/ZwCreateKey pelo adaptador de kernel.
    object_attributes(storage, 0, "\\Registry\\Machine\\Software\\OpenNTNative", 0x240);
    assert(matches!(native_keys::create(storage + 0x100, 0xF003F, storage, 0, 0, 0, storage + 0x108), Ok(0)) && guest::read32(storage + 0x108) == 1, "nativekeys: ZwCreateKey");
    let created = guest::read64(storage + 0x100);
    assert(matches!(native_keys::open(storage + 0x100, 0x20019, storage), Ok(0)) && native_keys::close_record(guest::read64(storage + 0x100) as u32).is_some(), "nativekeys: ZwOpenKey");
    let opened = guest::read64(storage + 0x100);
    // NtClose do handle de chave pelo provedor Zw.
    let handles = registry::object_stats().handles;
    assert(matches!(crate::ntos::ob::close::close(opened, Some(0)), Ok(0)) && registry::object_stats().handles == handles - 1, "nativekeys: NtClose fecha o handle de chave");
    let key = crate::ntos::cm::key::services::fields(&[]);
    assert(matches!(crate::ntos::cm::key::services::key_operation(crate::ntos::cm::key::services::Kind::DeleteKey, created, &key, false), Ok(0)) && matches!(crate::ntos::ob::close::close(created, Some(0)), Ok(0)), "nativekeys: limpeza");
    // RtlCheckRegistryKey.
    let handles = registry::object_stats().handles;
    write_wide(storage + 0x200, "Notifications");
    assert(matches!(check_registry_key::check(2, storage + 0x200), Ok(0)), "checkregistrykey: RTL_REGISTRY_CONTROL existente");
    write_wide(storage + 0x200, "Ausente");
    assert(matches!(check_registry_key::check(2, storage + 0x200), Ok(0xC000_0034)), "checkregistrykey: chave ausente");
    write_wide(storage + 0x200, "\\Registry\\Machine\\Hardware\\ResourceMap\\System Resources\\Physical Memory");
    assert(matches!(check_registry_key::check(0, storage + 0x200), Ok(0)), "checkregistrykey: RTL_REGISTRY_ABSOLUTE");
    assert(matches!(check_registry_key::check(6, storage + 0x200), Ok(0xC000_000D)) && matches!(check_registry_key::check(0x4000_0000 | 77, 0), Ok(0)), "checkregistrykey: indice invalido e RTL_REGISTRY_HANDLE");
    write_wide(storage + 0x200, "Volatile Environment");
    assert(matches!(check_registry_key::check(5, storage + 0x200), Ok(0xC000_0034)), "checkregistrykey: RTL_REGISTRY_USER pelo SID do token");
    assert(registry::object_stats().handles == handles, "checkregistrykey: handle temporario fechado");
    // Nome do computador e parâmetros de rede.
    assert(computer_name::initialize().is_ok(), "computername: inicializacao");
    let active = registry::read_value_by_path("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName", "ComputerName");
    let hostname = registry::read_value_by_path("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters", "Hostname");
    assert(active.as_ref().is_some_and(|value| value.value_type == 1 && wide_text(value) == "OPENNT") && hostname.as_ref().is_some_and(|value| wide_text(value) == "opennt"), "computername: nome ativo copiado do configurado");
    // CSPs e catálogo CNG.
    assert(crypto_defaults::initialize().is_ok() && registry::read_value_by_path("\\Registry\\Machine\\Software\\Microsoft\\Cryptography\\Defaults\\Provider Types\\Type 012", "Name").is_some_and(|value| wide_text(&value) == "Microsoft RSA SChannel Cryptographic Provider"), "cryptodefaults: tipos de provedor");
    assert(registry::read_value_by_path("\\Registry\\Machine\\Software\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Strong Cryptographic Provider", "Type").is_some_and(|value| value.value_type == 4 && value.data == [1, 0, 0, 0]), "cryptodefaults: provedor RSA Full");
    let image = registry::read_value_by_path("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Cryptography\\Providers\\Microsoft Primitive Provider\\KM", "Image");
    let providers = registry::read_value_by_path("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Cryptography\\Configuration\\Local\\Default\\00000002\\SHA256", "Providers");
    let expected: alloc::vec::Vec<u8> = "Microsoft Primitive Provider\0\0".encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
    assert(cng_defaults::initialize().is_ok() && image.is_some_and(|value| wide_text(&value) == "cng.sys") && providers.is_some_and(|value| value.value_type == 7 && value.data == expected), "cngdefaults: catalogo de kernel e contexto padrao de usuario");
    assert(registry::node_by_path("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Cryptography\\Configuration\\Local\\Default\\00000005\\DSA").is_some() && registry::node_by_path("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Cryptography\\Providers\\Microsoft Primitive Provider\\KM\\00000005").is_some(), "cngdefaults: so algoritmos de usuario entram nos contextos");
    // Definições WNF instaladas no boot.
    let lengths: alloc::vec::Vec<usize> = wnf_defaults::DEFINITIONS.iter().filter_map(|(name, _)| registry::read_value_by_path("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Notifications", name)).map(|value| value.data.len()).collect();
    assert(lengths == [412, 364, 364] && matches!(wnf_defaults::initialize(), Ok(0)), "wnfdefaults: tres definicoes; reinstalacao preserva");
    // RtlGetPersistedStateLocation.
    let source = storage + 0x200;
    let output = storage + 0x300;
    let length = storage + 0x3F0;
    write_wide(source, "OpenNTSource");
    write_wide(storage + 0x280, "C:\\Padrao");
    assert(persisted_state::query(source, 0, storage + 0x280, 0, output, 0x80, length) == 0 && guest::read32(length) == 20 && guest::read16(output) == b'C' as u16, "persistedstate: chave ausente usa o caminho padrao");
    let handle = registry::open_or_create(&(alloc::string::String::from(persisted_state::ROOT) + "Keys\\OpenNTSource"), None).unwrap_or(0);
    registry::set_value(handle, "", 1, "D:\\Novo".encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect());
    assert(persisted_state::query(source, 0, storage + 0x280, 0, output, 0x80, length) == 0 && guest::read32(length) == 16 && guest::read16(output) == b'D' as u16 && guest::read16(output + 14) == 0, "persistedstate: redirecionamento com terminador acrescentado");
    guest::write16(output, 0x55);
    assert(persisted_state::query(source, 0, 0, 0, output, 8, length) == 0x8000_0005 && guest::read16(output) == 0x55, "persistedstate: BUFFER_OVERFLOW sem copia parcial");
    write_wide(storage + 0x380, "Outro");
    assert(persisted_state::query(source, storage + 0x380, 0, 0, output, 0x80, length) == 0xC000_0034 && persisted_state::query(source, 0, 0, 2, output, 0x80, length) == 0xC000_00F1 && persisted_state::query(0, 0, 0, 0, output, 0x80, length) == 0xC000_000D, "persistedstate: valor ausente, tipo e origem invalidos");
    registry::set_value(handle, "", 4, alloc::vec![1, 0, 0, 0]);
    assert(persisted_state::query(source, 0, 0, 0, output, 0x80, length) == 0xC000_0024, "persistedstate: valor que nao e REG_SZ");
    registry::delete_key(handle);
    registry::close_handle(handle);
    // Mapa de RAM em CM_RESOURCE_LIST.
    let translated = registry::read_value_by_path(physical_memory_resources::PHYSICAL_MEMORY_KEY, ".Translated");
    let ranges = crate::ntos::mm::physical_layout::ranges();
    assert(translated.as_ref().is_some_and(|value| value.value_type == 8 && value.data.len() == 20 + ranges.len() * 20 && u32::from_le_bytes([value.data[16], value.data[17], value.data[18], value.data[19]]) == ranges.len() as u32), "physicalmemory: .Translated com uma entrada por faixa admitida");
    let encoded = physical_memory_resources::encode_ranges(&[(0x1000, 0x9F000), (0x1_0000_0000, 0x1_0000_0000 + 0x2_0000_0000)]).unwrap_or_default();
    assert(encoded.len() == 60 && encoded[20] == 3 && encoded[40] == 7 && u16::from_le_bytes([encoded[42], encoded[43]]) == 0x200 && u32::from_le_bytes([encoded[52], encoded[53], encoded[54], encoded[55]]) == 0x0200_0000, "physicalmemory: Memory e MemoryLarge com escala de 256");
    assert(physical_memory_resources::encode_ranges(&[(0x2000, 0x3000), (0x1000, 0x4000)]).is_err() && physical_memory_resources::encode_ranges(&[(0x1001, 0x3000)]).is_err(), "physicalmemory: faixas sobrepostas ou desalinhadas recusadas");
    guest::free_bytes(storage);
}

/// Argumentos do último callout de IoQueryDeviceDescription (11) e o status devolvido.
static CALLOUT_ARGS: crate::rtl::SpinLock<[u64; 11]> = crate::rtl::SpinLock::new([0; 11]);
static CALLOUT_STATUS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static CALLOUT_CALLS: AtomicU32 = AtomicU32::new(0);

#[allow(clippy::too_many_arguments)]
extern "win64" fn test_device_callout(context: u64, path: u64, bus_type: u64, bus_number: u64, bus_information: u64, controller_type: u64, controller_number: u64, controller_information: u64, peripheral_type: u64, peripheral_number: u64, peripheral_information: u64) -> u64 {
    *CALLOUT_ARGS.lock() = [context, path, bus_type, bus_number, bus_information, controller_type, controller_number, controller_information, peripheral_type, peripheral_number, peripheral_information];
    CALLOUT_CALLS.fetch_add(1, Ordering::SeqCst);
    CALLOUT_STATUS.load(Ordering::SeqCst)
}

fn hardware_description_and_feature_usage(assert: Assert) {
    use crate::ntos::cm::{feature_usage, feature_usage_buffer as bank, hw_description, registry};
    use crate::ntos::cm::feature_usage_delivery::Subscription;
    use crate::ntos::ex::wnf::state_data as wnf;
    // Árvore legada do 8042 semeada no boot.
    let leaf = "\\Registry\\Machine\\Hardware\\Description\\System\\MultifunctionAdapter\\0\\OtherController\\0\\OtherPeripheral\\0";
    let identifier = registry::read_value_by_path(leaf, "Identifier");
    let configuration = registry::read_value_by_path(leaf, "Configuration Data");
    assert(identifier.is_some_and(|value| value.value_type == 1 && value.data == b"AT-Compatible 8042 Keyboard\0") && configuration.is_some_and(|value| value.value_type == 3 && value.data == hw_description::configuration_bytes()), "hwdesc: teclado 8042 na hive de hardware");
    let bytes = hw_description::configuration_bytes();
    assert(bytes.len() == 84 && bytes[24] == 2 && bytes[28] == 0x60 && bytes[32] == 0x60 && bytes[64] == 3 && bytes[68] == 1 && bytes[72] == 0x21 && bytes[76..84] == [0xFF, 0, 0, 0, 0xFF, 0, 0, 0], "hwdesc: descritores legados de portas e IRQ");
    // IoQueryDeviceDescription com callout nativo de onze argumentos.
    let types = guest::alloc_bytes(16);
    guest::write32(types, hw_description::OTHER_CONTROLLER);
    guest::write32(types + 4, hw_description::OTHER_PERIPHERAL);
    let callout = test_device_callout as extern "win64" fn(u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) -> u64 as usize as u64;
    CALLOUT_STATUS.store(0, Ordering::SeqCst);
    CALLOUT_CALLS.store(0, Ordering::SeqCst);
    assert(hw_description::query_device_description(0, 0, types, 0, types + 4, 0, callout, 0xC0FFEE) == 0 && CALLOUT_CALLS.load(Ordering::SeqCst) == 1, "hwdesc: IoQueryDeviceDescription chama o callout");
    let arguments = *CALLOUT_ARGS.lock();
    let path = crate::ntos::rtl::guest_strings::read_unicode_string(arguments[1]);
    let peripheral_identifier = guest::read64(arguments[10]);
    let data_offset = unsafe { KeyValueFullInformation::at(peripheral_identifier) }.data_offset.get() as u64;
    assert(arguments[0] == 0xC0FFEE && path == leaf && arguments[2] == 1 && arguments[3] == 0 && arguments[5] == 22 && arguments[8] == 32 && guest::read_bytes(peripheral_identifier + data_offset, 4) == b"AT-C", "hwdesc: caminho, tipos e informacao do periferico");
    CALLOUT_STATUS.store(0xC000_0001, Ordering::SeqCst);
    assert(hw_description::query_device_description(0, 0, types, 0, types + 4, 0, callout, 0) == 0xC000_0034, "hwdesc: callout recusa e a busca termina sem sucesso");
    guest::write32(types + 4, 7);
    assert(hw_description::query_device_description(0, 0, types, 0, types + 4, 0, callout, 0) == 0xC000_0034 && hw_description::query_device_description(0, 0, 0, 0, types + 4, 0, callout, 0) == 0xC000_0034, "hwdesc: tipo nao tratado");
    guest::free_bytes(types);
    // Dados de estado WNF internos.
    let name = 0x4F50_454E_4E54_0001u64;
    let buffer = guest::alloc_bytes(0x40);
    assert(wnf::register(name, 16) == 0 && wnf::register(name, 16) == 0xC000_0035 && wnf::register(0, 16) == 0xC000_000D && wnf::register(name + 1, 5000) == 0xC000_000D, "wnfstate: registro de nome");
    assert(wnf::query(name, buffer, 0x40) == wnf::QueryResult { status: 0, size: 0, stamp: 0 }, "wnfstate: estado vazio");
    guest::write64(buffer, 0x1122_3344_5566_7788);
    assert(wnf::update(name, buffer, 8, 0, false) == 0 && wnf::query(name, buffer + 0x20, 4) == wnf::QueryResult { status: 0xC000_0023, size: 8, stamp: 1 }, "wnfstate: atualizacao e buffer curto");
    assert(wnf::update(name, buffer, 8, 0, true) == 0xC000_0001 && wnf::update(name, buffer, 32, 1, true) == 0xC000_000D && wnf::update(name, buffer, 4, 1, true) == 0 && wnf::query(name, buffer + 0x20, 8).stamp == 2, "wnfstate: carimbo condicional e limite");
    assert(wnf::remove(name) == 0 && wnf::query(name, buffer, 0x40).status == 0xC000_0034, "wnfstate: remocao");
    // Banco de relatos: capacidade, descarte, retenção.
    let storage = guest::alloc_bytes(bank::SIZE);
    let report = guest::alloc_bytes(16);
    let usage_report = unsafe { RtlFeatureUsageReport::at(report) };
    usage_report.feature_id.set(0x1234);
    usage_report.reporting_kind.set(1);
    let mut accepted = 0;
    for _ in 0..64 {
        if matches!(bank::enqueue(storage, report), Ok(0)) {
            accepted += 1;
        }
    }
    assert(accepted == 64 && matches!(bank::enqueue(storage, report), Ok(0xC000_009A)) && bank::dropped(storage) == 1 && bank::count(storage) == 64, "featureusage: banco de 64 relatos e descarte");
    assert(bank::drain(storage, |_| 0xC000_0001, false) == 0 && bank::count(storage) == 0, "featureusage: falha com menos de cinco tentativas libera o slot");
    let _ = bank::enqueue(storage, report);
    let slot = (0..64u64).find(|&slot| guest::read64(storage + 8) & (1 << slot) != 0).unwrap_or(0);
    guest::write32(storage + 0x10 + slot * 12, 4);
    assert(bank::drain(storage, |_| 0xC000_0001, false) == 0 && bank::count(storage) == 1, "featureusage: slot com tentativas so e repetido no retry");
    assert(bank::drain(storage, |_| 0xC000_0001, true) == 1 && bank::count(storage) == 1 && guest::read32(storage + 0x10 + slot * 12) == 5, "featureusage: cinco tentativas retêm o relato");
    assert(bank::drain(storage, |_| 0xC000_0225, true) == 0 && bank::count(storage) == 0, "featureusage: NOT_FOUND descarta");
    guest::free_bytes(storage);
    // Entrega pelo work item até o estado WNF inscrito, com deduplicação.
    let target = 0x4F50_454E_4E54_0002u64;
    assert(feature_usage::init() && wnf::register(target, 4096) == 0, "featureusage: bancos, work items, DPCs e timer");
    assert(feature_usage::set_subscriptions(&[Subscription { feature_id: 0x1234, reporting_kind: 1, reporting_options: 0, target_name: target }]).is_ok(), "featureusage: inscricao interna");
    let deliver = || crate::ntos::io::work_items::run_queue();
    assert(matches!(feature_usage::notify(report, None), Ok(0)), "featureusage: relato produzido");
    deliver();
    let state = wnf::query(target, buffer, 0x40);
    let delivered = unsafe { RtlFeatureUsageReport::at(buffer) };
    assert(state.status == 0 && state.size == 8 && delivered.feature_id.get() == 0x1234 && delivered.reporting_kind.get() == 1 && feature_usage::snapshot().counts == [0, 0], "featureusage: relato entregue ao estado WNF");
    assert(matches!(feature_usage::notify(report, None), Ok(0)), "featureusage: relato repetido");
    deliver();
    assert(wnf::query(target, buffer, 0x40).size == 8, "featureusage: par recurso/tipo deduplicado");
    usage_report.feature_id.set(0x9999);
    assert(matches!(feature_usage::notify(report, Some(2)), Ok(0)), "featureusage: produção em DISPATCH_LEVEL usa DPC");
    let _ = crate::ntos::ke::dpc::run_queue();
    deliver();
    let snapshot = feature_usage::snapshot();
    assert(snapshot.counts == [0, 0] && !snapshot.retry_armed && wnf::query(target, buffer, 0x40).size == 8, "featureusage: relato sem inscricao descartado");
    let _ = feature_usage::set_subscriptions(&[]);
    let _ = wnf::remove(target);
    guest::free_bytes(report);
    guest::free_bytes(buffer);
}

static SERVICE_STOPS: AtomicU32 = AtomicU32::new(0);

fn running_driver(_configuration: &crate::ntos::cm::service::database::Configuration, status: &mut crate::ntos::cm::service::database::ServiceStatus) {
    status.current_state = 4;
}

fn service_code<T>(result: &crate::ntos::cm::service::database::ServiceResult<T>) -> u32 {
    match result {
        Err(error) => error.win32().unwrap_or(0),
        Ok(_) => 0,
    }
}

fn service_database(assert: Assert) {
    use crate::ntos::cm::service::database::{self as services, ConfigurationInput, ReportedStatus, RUNNING, STOPPED, START_PENDING};
    let input = |name: &str, image: &str| ConfigurationInput { name: alloc::string::String::from(name), image_path: Some(alloc::string::String::from(image)), ..Default::default() };
    // Instalação com os padrões do gerenciador.
    let installed = services::install(&input("OpenNTSvc", "\"C:\\Program Files\\svc.exe\" -x"), false);
    assert(installed.as_ref().is_ok_and(|configuration| configuration.service_type == 16 && configuration.start == 3 && configuration.error_control == 1 && configuration.display_name == "OpenNTSvc" && configuration.object_name == "LocalSystem" && configuration.dependencies.is_empty()), "services: instalacao com padroes");
    assert(services::list().iter().any(|name| name == "OpenNTSvc") && !services::list().iter().any(|name| name == "Tcpip"), "services: lista so chaves com Type");
    assert(service_code(&services::install(&input("OpenNTSvc", "x.exe"), false)) == 1073 && services::install(&input("OpenNTSvc", "x.exe"), true).is_ok_and(|configuration| configuration.image_path.starts_with('"')), "services: duplicado recusado ou preservado");
    assert(service_code(&services::install(&input("a/b", "x.exe"), false)) == 123 && service_code(&services::install(&input("", "x.exe"), false)) == 123, "services: nome invalido");
    let mut account = input("OpenNTAccount", "x.exe");
    account.object_name = Some(alloc::string::String::from("NT AUTHORITY\\LocalService"));
    let mut boot = input("OpenNTBoot", "x.exe");
    boot.start = Some(1);
    let mut itself = input("OpenNTSelf", "x.exe");
    itself.dependencies = Some(alloc::vec![alloc::string::String::from("opennTself")]);
    let mut twice = input("OpenNTTwice", "x.exe");
    twice.dependencies = Some(alloc::vec![alloc::string::String::from("A"), alloc::string::String::from("a")]);
    assert(service_code(&services::install(&account, false)) == 50 && service_code(&services::install(&boot, false)) == 87 && service_code(&services::install(&itself, false)) == 1059 && service_code(&services::install(&twice, false)) == 87 && service_code(&services::install(&input("OpenNTEmpty", ""), false)) == 87, "services: conta, inicio, dependencias e caminho invalidos");
    // Dependências e ciclos.
    let mut dependent = input("OpenNTDep", "dep.exe");
    dependent.dependencies = Some(alloc::vec![alloc::string::String::from("OpenNTSvc")]);
    assert(services::install(&dependent, false).is_ok_and(|configuration| configuration.dependencies == ["OpenNTSvc"]), "services: dependencia gravada em REG_MULTI_SZ");
    let cycle = ConfigurationInput { name: alloc::string::String::from("OpenNTSvc"), dependencies: Some(alloc::vec![alloc::string::String::from("OpenNTDep")]), ..Default::default() };
    assert(service_code(&services::configure("OpenNTSvc", &cycle)) == 1059 && service_code(&services::configure("OpenNTAusente", &cycle)) == 1060, "services: ciclo e servico ausente na configuracao");
    assert(services::status("OpenNTSvc").is_ok_and(|status| status.current_state == STOPPED && status.process_id == 0) && service_code(&services::status("OpenNTAusente")) == 1060, "services: estado parado por padrao");
    // Lançamento: anexo do processo, relatos autenticados e parada.
    assert(service_code(&services::launch("OpenNTDep", |_| Some((0u32, false)), |_, _, _| Ok(0))) == 1068, "services: dependencia fora de execucao");
    SERVICE_STOPS.store(0, Ordering::SeqCst);
    services::on_stopped(Arc::new(|name: &str| {
        if name == "OpenNTSvc" {
            SERVICE_STOPS.fetch_add(1, Ordering::SeqCst);
        }
    }));
    let mut observed = (0u32, 0u32, 0u32, 0u32, false);
    let launched = services::launch("OpenNTSvc", |path| (path == "C:\\Program Files\\svc.exe").then_some((42u32, false)), |image, command_line, attach| {
        observed.0 = services::status("OpenNTSvc").map(|status| status.current_state).unwrap_or(0);
        let attached = attach(7).is_ok() && attach(8).is_err();
        let running = ReportedStatus { current_state: RUNNING, controls_accepted: 1, ..Default::default() };
        observed.1 = services::report_status("OpenNTSvc", 9, &running).err().and_then(|error| error.win32()).unwrap_or(0);
        observed.2 = services::report_status("OpenNTSvc", 7, &ReportedStatus { current_state: 9, ..Default::default() }).err().and_then(|error| error.win32()).unwrap_or(0);
        let reported = services::report_status("OpenNTSvc", 7, &running).is_ok();
        observed.3 = services::status("OpenNTSvc").map(|status| status.current_state).unwrap_or(0);
        observed.4 = attached && reported && image == 42 && command_line.arguments == "-x" && services::active_for_process(7).len() == 1 && services::active_dependents("OpenNTSvc").is_empty();
        Ok(0)
    });
    assert(matches!(launched, Ok(0)) && observed == (START_PENDING, 6, 13, RUNNING, true), "services: START_PENDING, anexo unico, relatos autenticados e RUNNING");
    assert(services::status("OpenNTSvc").is_ok_and(|status| status.current_state == STOPPED && status.process_exit_code == Some(0) && status.win32_exit_code == 0 && status.process_id == 0) && SERVICE_STOPS.load(Ordering::SeqCst) == 1, "services: saida publica STOPPED e avisa os ouvintes");
    assert(services::launch("OpenNTSvc", |_| Some((0u32, false)), |_, _, _| Ok(3)).is_ok() && services::status("OpenNTSvc").is_ok_and(|status| status.win32_exit_code == 1067 && status.process_exit_code == Some(3)), "services: saida com erro vira ERROR_PROCESS_ABORTED");
    assert(service_code(&services::launch("OpenNTSvc", |_| None::<(u32, bool)>, |_, _, _| Ok(0))) == 2 && service_code(&services::launch("OpenNTSvc", |_| Some((0u32, true)), |_, _, _| Ok(0))) == 2, "services: imagem ausente ou diretorio");
    let disabled = ConfigurationInput { name: alloc::string::String::from("OpenNTSvc"), start: Some(4), ..Default::default() };
    assert(services::configure("OpenNTSvc", &disabled).is_ok_and(|configuration| configuration.start == 4 && configuration.image_path.starts_with('"')) && service_code(&services::launch("OpenNTSvc", |_| Some((0u32, false)), |_, _, _| Ok(0))) == 1058, "services: configuracao mesclada e servico desabilitado");
    assert(services::parse_command_line("\"C:\\a b\\c.exe\"  -k  netsvcs ").is_ok_and(|line| line.path == "C:\\a b\\c.exe" && line.arguments == "-k  netsvcs") && services::parse_command_line("svc.exe").is_ok_and(|line| line.arguments.is_empty()) && service_code(&services::parse_command_line("\"\"x")) == 123, "services: linha de comando");
    // Drivers recebem o estado do objeto nativo.
    let mut driver = input("OpenNTDriver", "\\SystemRoot\\System32\\drivers\\x.sys");
    driver.service_type = Some(1);
    assert(services::install(&driver, false).is_ok() && services::status("OpenNTDriver").is_ok_and(|status| status.current_state == STOPPED), "services: driver parado sem provedor");
    services::set_driver_status_provider(Some(running_driver));
    assert(services::status("OpenNTDriver").is_ok_and(|status| status.current_state == RUNNING) && service_code(&services::remove("OpenNTDriver")) == 1061, "services: provedor do ciclo do driver");
    services::set_driver_status_provider(None);
    // Remoção.
    let child = crate::ntos::cm::registry::open_or_create(&(alloc::string::String::from(services::ROOT) + "\\OpenNTDep\\Parameters"), None).unwrap_or(0);
    assert(service_code(&services::remove("OpenNTDep")) == 5, "services: chave com subchaves nao e removida");
    crate::ntos::cm::registry::delete_key(child);
    crate::ntos::cm::registry::close_handle(child);
    for name in ["OpenNTDep", "OpenNTSvc", "OpenNTDriver"] {
        assert(services::remove(name).is_ok() && matches!(services::read(name), Ok(None)), "services: remocao");
    }
}

fn test_physical_push(request: u32, _name: u64, stamp: u32, _buffer: u64, length: u32) -> u32 {
    request + stamp + length
}

fn test_physical_populate(_state: u64) -> u32 {
    0x77
}

fn wnf_names_definitions_and_stores(assert: Assert) {
    use crate::ntos::ex::wnf::{name as name, physical as physical, registry as stores};
    use crate::ntos::ob::close;
    // WNF_STATE_NAME.
    let encoded = 0x0280_032E_A3BC_0875u64;
    let decoded = name::decode(encoded);
    assert(decoded.status == 0 && decoded.version == 1 && decoded.lifetime == 0 && decoded.scope == 0 && !decoded.permanent_data && name::value_name(decoded.decoded_name) == "0280032EA3BC0875", "wnfname: nome bem conhecido decodificado");
    assert(name::decode(encoded ^ 3).status == 0xC000_000D && name::decode(name::NAME_MASK | 1 | 6 << 6).status == 0xC000_000D && name::decode(name::NAME_MASK ^ (1 | 1 << 10 | 1 << 6)).status == 0xC000_000D, "wnfname: versao, escopo e dados permanentes invalidos");
    let guid = guest::alloc_bytes(0x40);
    guest::write_bytes(guid, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    guest::write_bytes(guid + 0x10, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    let description = name::Description { security_descriptor: 0x1234, type_identifier: guid, maximum_size: 8 };
    let allow = |_: u64, _: u32| 0u32;
    let deny = |descriptor: u64, desired: u32| if descriptor == 0x1234 && desired == 2 { 0xC000_0022 } else { 0 };
    assert(name::validate(&description, 8, name::SuppliedType::Pointer(guid + 0x10), false, Some(&allow), 2) == 0 && name::validate(&description, 4, name::SuppliedType::Captured([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]), true, None, 2) == 0, "wnfname: GUID por ponteiro ou capturado");
    assert(name::validate(&description, 8, name::SuppliedType::None, true, None, 2) == 0xC000_000D && name::validate(&description, 8, name::SuppliedType::Captured([0; 16]), true, None, 2) == 0xC000_000D && name::validate(&description, 9, name::SuppliedType::Pointer(guid), true, None, 2) == 0xC000_000D, "wnfname: GUID ausente, diferente e limite");
    assert(name::validate(&description, 99, name::SuppliedType::None, false, Some(&deny), 2) == 0xC000_0022, "wnfname: acesso avaliado antes do GUID e do limite");
    let untyped = name::Description { type_identifier: 0, ..description };
    assert(name::validate(&untyped, 8, name::SuppliedType::Pointer(0xDEAD_0000), true, None, 2) == 0, "wnfname: estado sem GUID nao le o ponteiro");
    // Definições instaladas no boot, lidas pelo store com cache.
    let slot = guest::alloc_bytes(0x80);
    let definition = stores::lookup_definition(decoded.decoded_name, slot);
    let handle = guest::read64(slot);
    assert(matches!(definition, Ok(Ok(ref definition)) if definition.maximum_size == 8 && definition.type_identifier != 0 && guest::read_bytes(definition.type_identifier, 4) == [0x63, 0x64, 0xF9, 0x48] && crate::ntos::se::descriptor::valid(definition.security_descriptor)) && handle != 0, "wnfdefinition: definicao com GUID e limite lida da hive");
    drop(definition);
    let kernelbase = name::decode(0x418A_073A_A3BC_7C75);
    let second = stores::lookup_definition(kernelbase.decoded_name, slot);
    assert(matches!(second, Ok(Ok(ref definition)) if definition.maximum_size == 4096 && definition.type_identifier == 0) && guest::read64(slot) == handle, "wnfdefinition: definicao sem GUID; store reaproveitado do cache");
    drop(second);
    let absent = name::decode(name::NAME_MASK ^ 0x0000_0042_0000_0001);
    assert(matches!(stores::lookup_definition(absent.decoded_name, slot), Ok(Err(0xC000_0034))) && stores::get_definition_store(3, slot).is_err(), "wnfdefinition: nome ausente e nome temporario sem store");
    // Stores permanentes.
    let definitions = guest::alloc_bytes(8);
    assert(matches!(stores::open_permanent_store(1, 1, 0, 0, 1, definitions), Ok(Err(0xC000_0002))) && matches!(stores::open_permanent_store(1, 1, 0, 0, 0, definitions), Ok(Err(0xC000_0034))) && matches!(stores::open_permanent_store(4, 1, 0, 1, 0, definitions), Ok(Err(0xC000_0034))), "wnfregistry: combinacoes sem store");
    let instance = guest::alloc_bytes(0x60);
    let scope_instance = unsafe { WnfScopeInstance::at(instance) };
    scope_instance.data_scope.set(WnfDataScope::WNF_DATA_SCOPE_MACHINE);
    // Sem a semeadura do registro de usuário, a raiz Windows NT\CurrentVersion
    // ainda não existe e o CM devolve OBJECT_PATH_NOT_FOUND.
    let seeded = crate::ntos::cm::registry::node_by_path(r"\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion").is_some();
    assert(seeded || (matches!(stores::get_permanent_store(instance, 1, 1, definitions), Ok(Err(0xC000_003A))) && scope_instance.permanent_data_store.get() == 0), "wnfregistry: raiz de definicoes permanentes ausente antes da semeadura");
    let parent = crate::ntos::cm::registry::open_or_create(r"\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion", None).unwrap_or(0);
    crate::ntos::cm::registry::close_handle(parent);
    let opened = stores::get_permanent_store(instance, 1, 1, definitions);
    let permanent = scope_instance.permanent_data_store.get();
    assert(matches!(opened, Ok(Ok(store)) if store.handle == permanent && permanent != 0) && crate::ntos::cm::registry::node_by_path("\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Notifications\\Data").is_some() && guest::read64(definitions) != 0, "wnfregistry: store permanente da maquina em Notifications\\Data");
    assert(matches!(stores::get_permanent_store(instance, 1, 1, definitions), Ok(Ok(store)) if store.handle == permanent), "wnfregistry: store permanente do cache");
    let system = crate::ntos::mm::kernel_pool::allocate(16, crate::ntos::mm::kernel_pool::AllocateOptions { zero: true, ..Default::default() }).unwrap_or(0);
    guest::write_bytes(system, &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
    let user_store = stores::open_permanent_store(2, 0, system, 0, 1, definitions);
    assert(matches!(user_store, Ok(Err(0xC000_003A))),"wnfregistry: store de usuario exige a hive do usuario carregada");
    for handle in [handle, permanent, guest::read64(definitions)] {
        let _ = close::close(handle, Some(0));
    }
    // Transporte PhysicalMachine.
    assert(physical::push(1, encoded, 2, 0, 3) == 0xC000_0002 && physical::populate(0) == 0xC000_0002, "wnfphysical: sem extensao devolve NOT_IMPLEMENTED");
    let transport = physical::Transport { push: test_physical_push, populate: test_physical_populate };
    let token = physical::register(transport).unwrap_or(0);
    assert(token != 0 && physical::register(transport).is_err() && physical::push(1, encoded, 2, 0, 3) == 6 && physical::populate(0) == 0x77, "wnfphysical: extensao registrada recebe push e populate");
    assert(physical::unregister(token + 1).is_err() && physical::unregister(token).is_ok() && physical::push(1, encoded, 2, 0, 3) == 0xC000_0002, "wnfphysical: remocao pelo token");
    let _ = crate::ntos::mm::kernel_pool::free(system, None);
    for pointer in [guid, slot, definitions, instance] {
        guest::free_bytes(pointer);
    }
}

/// SECURITY_DESCRIPTOR_RELATIVE com owner SYSTEM e as ACLs dadas.
fn relative_descriptor(pointer: u64, dacl: Option<&[u8]>, sacl: Option<&[u8]>) {
    let owner: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let mut bytes = alloc::vec![0u8; 20];
    bytes[0] = 1;
    let mut control = 0x8000u16;
    bytes.extend_from_slice(&owner);
    bytes[4..8].copy_from_slice(&20u32.to_le_bytes());
    if let Some(dacl) = dacl {
        control |= 4;
        let offset = bytes.len() as u32;
        bytes[16..20].copy_from_slice(&offset.to_le_bytes());
        bytes.extend_from_slice(dacl);
    }
    if let Some(sacl) = sacl {
        control |= 16;
        let offset = bytes.len() as u32;
        bytes[12..16].copy_from_slice(&offset.to_le_bytes());
        bytes.extend_from_slice(sacl);
    }
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    guest::write_bytes(pointer, &bytes);
}

/// ACL com ACEs de 20 bytes (tipo, máscara, SID de 12 bytes).
fn acl(entries: &[(u8, u32, [u8; 12])]) -> alloc::vec::Vec<u8> {
    let size = 8 + entries.len() * 20;
    let mut bytes = alloc::vec![2u8, 0];
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&[0, 0]);
    for (entry_type, mask, sid) in entries {
        bytes.extend_from_slice(&[*entry_type, 0, 20, 0]);
        bytes.extend_from_slice(&mask.to_le_bytes());
        bytes.extend_from_slice(sid);
    }
    bytes
}

fn wnf_identity_security_and_data(assert: Assert) {
    use crate::ntos::ex::wnf::data_block::{self as data, NameState};
    use crate::ntos::ex::wnf::{name as wnf_name, scope_identity as identity, security as security};
    use crate::ntos::ps::process;
    let storage = guest::alloc_bytes(0x400);
    let buffer = storage;
    let length = storage + 0x40;
    let cache = storage + 0x48;
    // Identidade corrente por escopo.
    let current = process::get_current_process();
    guest::write32(cache, 7);
    assert(matches!(identity::query_current(current, 0, 0, buffer, length, cache), Ok(0)) && guest::read32(length) == 0 && guest::read32(cache) == 1, "wnfscope: sistema sem identificador");
    assert(matches!(identity::query_current(current, 0, 3, buffer, length, cache), Ok(0)) && guest::read32(length) == 8 && guest::read64(buffer) == current, "wnfscope: processo pelo EPROCESS selecionado");
    assert(matches!(identity::query_current(current, 0, 1, buffer, length, cache), Ok(0)) && guest::read32(length) == 4 && guest::read32(buffer) == crate::ntos::ps::session::query(current), "wnfscope: sessao do processo");
    guest::write32(length, 64);
    guest::write32(cache, 7);
    let user = crate::ntos::se::token::tokens::with(process::get_primary_token(current).unwrap_or(0), |token| token.user.clone()).unwrap_or_default();
    assert(matches!(identity::query_current(current, 0, 2, buffer, length, cache), Ok(0)) && guest::read32(length) as usize == user.len() && guest::read_bytes(buffer, user.len()) == user && guest::read32(cache) == 1, "wnfscope: SID do token primario");
    guest::write32(length, 4);
    guest::write32(cache, 7);
    assert(matches!(identity::query_current(current, 0, 2, buffer, length, cache), Ok(0xC000_0023)) && guest::read32(length) as usize == user.len() && guest::read32(cache) == 7, "wnfscope: buffer curto publica o tamanho sem autorizar o cache");
    // Acesso WNF pelo descritor do estado.
    let descriptor = storage + 0x100;
    let everyone = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    let system = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    relative_descriptor(descriptor, None, None);
    assert(matches!(security::check(descriptor, 0), Ok(0)) && matches!(security::check(descriptor, 1), Ok(0)), "wnfsecurity: DACL ausente concede o acesso");
    relative_descriptor(descriptor, Some(&acl(&[(1, 1, everyone), (0, 0x1F_0013, system)])), None);
    assert(matches!(security::check(descriptor, 1), Ok(0xC000_0022)) && matches!(security::check(descriptor, 2), Ok(0)), "wnfsecurity: negacao de consulta para Everyone; atualizacao permitida ao SYSTEM");
    relative_descriptor(descriptor, Some(&acl(&[(0, 3, system)])), Some(&acl(&[(17, 2, [1, 1, 0, 0, 0, 0, 0, 16, 0, 0x50, 0, 0])])));
    assert(matches!(security::check(descriptor, 1), Ok(0xC000_0022)) && matches!(security::check(descriptor, 2), Ok(0)), "wnfsecurity: rotulo protegido impede a leitura (no-read-up)");
    relative_descriptor(descriptor, Some(&acl(&[(0, 3, system)])), Some(&acl(&[(17, 3, [1, 1, 0, 0, 0, 0, 0, 16, 0, 0x10, 0, 0])])));
    assert(matches!(security::check(descriptor, 3), Ok(0)), "wnfsecurity: rotulo baixo nao restringe");
    let physical = wnf_name::decode(wnf_name::NAME_MASK ^ (1 | 3 << 6));
    let session = wnf_name::decode(wnf_name::NAME_MASK ^ (1 | 1 << 6));
    assert(matches!(security::check_cross_scope(&physical, |_| Ok(Err(0xC000_0001))), Ok(0)) && matches!(security::check_cross_scope(&session, |_| Ok(Err(0xC000_0034))), Ok(0xC000_0034)), "wnfsecurity: escopo fisico livre; definicao ausente propagada");
    // Bloco de dados sem persistência.
    let name_instance = |pointer: u64| unsafe { WnfNameInstance::at(pointer) };
    let instance = guest::alloc_bytes(WnfNameInstance::SIZE);
    let state = NameState { pointer: instance };
    let decoded = wnf_name::NAME_MASK ^ 0x0000_0099_0000_0011;
    name_instance(instance).state_name.bitfield_0.set(decoded);
    name_instance(instance).state_name_info.max_state_size.set(16);
    let stamp = storage + 0x50;
    let returned = storage + 0x58;
    guest::write32(stamp, 9);
    assert(matches!(data::read(&state, stamp, buffer, 16, returned), Ok(0)) && guest::read32(stamp) == 0 && guest::read32(returned) == 0, "wnfdata: sem dados publicados");
    guest::write_bytes(storage + 0x60, b"dadosWNF");
    assert(matches!(data::write(&state, storage + 0x60, 8, 0, false), Ok(0)) && state.data_pointer() > 1 && state.change_stamp() == 1, "wnfdata: primeira atualizacao aloca o bloco");
    assert(matches!(data::read(&state, stamp, buffer, 16, returned), Ok(0)) && guest::read32(stamp) == 1 && guest::read32(returned) == 8 && guest::read_bytes(buffer, 8) == b"dadosWNF", "wnfdata: leitura do bloco publicado");
    assert(matches!(data::read(&state, stamp, buffer, 4, returned), Ok(0xC000_0023)) && guest::read32(returned) == 8, "wnfdata: buffer curto informa o tamanho");
    let block = state.data_pointer();
    assert(matches!(data::write(&state, storage + 0x60, 4, 7, true), Ok(0xC000_0001)) && matches!(data::write(&state, storage + 0x64, 4, 1, true), Ok(0)) && state.data_pointer() == block && state.change_stamp() == 2, "wnfdata: carimbo condicional e reaproveitamento do bloco");
    let empty_instance = guest::alloc_bytes(WnfNameInstance::SIZE);
    let empty = NameState { pointer: empty_instance };
    name_instance(empty_instance).state_name.bitfield_0.set(decoded);
    assert(matches!(data::write(&empty, 0, 0, 0, false), Ok(0)) && empty.data_pointer() == 1 && empty.change_stamp() == 1 && matches!(data::read(&empty, stamp, buffer, 16, returned), Ok(0)) && guest::read32(stamp) == 1 && guest::read32(returned) == 0, "wnfdata: marcador de dados vazios com carimbo valido");
    let temporary_instance = guest::alloc_bytes(WnfNameInstance::SIZE);
    let temporary = NameState { pointer: temporary_instance };
    name_instance(temporary_instance).state_name.bitfield_0.set(decoded | 0x30);
    assert(matches!(data::write(&temporary, storage + 0x60, 4, 0, false), Ok(0xC000_0034)), "wnfdata: estado temporario sem processo criador");
    // Persistência na hive e recarga.
    let (status, key) = crate::ntos::cm::key::services::open_path("\\Registry\\Machine\\Software\\OpenNTWnfData", true).unwrap_or((1, 0));
    let persistent_instance = guest::alloc_bytes(WnfNameInstance::SIZE);
    let persistent = NameState { pointer: persistent_instance };
    name_instance(persistent_instance).state_name.bitfield_0.set(decoded);
    name_instance(persistent_instance).state_name_info.max_state_size.set(16);
    name_instance(persistent_instance).permanent_data_store.set(key);
    assert(status == 0 && matches!(data::write(&persistent, storage + 0x60, 8, 0, false), Ok(0)), "wnfdata: atualizacao persistida");
    let stored = crate::ntos::cm::registry::read_value_by_path("\\Registry\\Machine\\Software\\OpenNTWnfData", &wnf_name::value_name(decoded));
    assert(stored.is_some_and(|value| value.value_type == 3 && value.data.len() == 12 && value.data[0..4] == [1, 0, 0, 0] && value.data[4..] == *b"dadosWNF"), "wnfdata: REG_BINARY com carimbo e dados");
    let loaded_instance = guest::alloc_bytes(WnfNameInstance::SIZE);
    let loaded = NameState { pointer: loaded_instance };
    name_instance(loaded_instance).state_name.bitfield_0.set(decoded);
    name_instance(loaded_instance).state_name_info.max_state_size.set(4);
    name_instance(loaded_instance).permanent_data_store.set(key);
    // Máximo menor que o valor: o CM devolve BUFFER_OVERFLOW (cópia parcial),
    // que a carga propaga sem publicar o bloco.
    assert(matches!(data::load_local(&loaded), Ok(0x8000_0005)) && loaded.data_pointer() == 0, "wnfdata: valor maior que o maximo da definicao");
    name_instance(loaded_instance).state_name_info.max_state_size.set(16);
    assert(matches!(data::load_local(&loaded), Ok(0)) && loaded.change_stamp() == 1 && matches!(data::read(&loaded, stamp, buffer, 16, returned), Ok(0)) && guest::read32(returned) == 8 && guest::read_bytes(buffer, 8) == b"dadosWNF", "wnfdata: recarga da hive");
    let absent_instance = guest::alloc_bytes(WnfNameInstance::SIZE);
    let absent = NameState { pointer: absent_instance };
    name_instance(absent_instance).state_name.bitfield_0.set(decoded ^ 0x100_0000);
    name_instance(absent_instance).state_name_info.max_state_size.set(16);
    name_instance(absent_instance).permanent_data_store.set(key);
    assert(matches!(data::load_local(&absent), Ok(0)) && absent.data_pointer() > 1 && absent.change_stamp() == 0 && unsafe { WnfStateData::at(absent.data_pointer()) }.data_size.get() == 0, "wnfdata: valor ausente vira estado inicial vazio");
    for state in [state, persistent, loaded, absent] {
        if state.data_pointer() > 1 {
            let _ = crate::ntos::mm::kernel_pool::free(state.data_pointer(), Some(data::DATA_TAG));
        }
    }
    let _ = crate::ntos::cm::key::services::key_operation(crate::ntos::cm::key::services::Kind::DeleteKey, key, &crate::ntos::cm::key::services::fields(&[]), false);
    let _ = crate::ntos::ob::close::close(key, Some(0));
    for pointer in [storage, instance, empty_instance, temporary_instance, persistent_instance, loaded_instance, absent_instance] {
        guest::free_bytes(pointer);
    }
}

static NAME_TEARDOWNS: AtomicU32 = AtomicU32::new(0);
static PROCESS_TEARDOWNS: AtomicU32 = AtomicU32::new(0);

fn test_delete_name_subscriptions(_name: u64) {
    NAME_TEARDOWNS.fetch_add(1, Ordering::SeqCst);
}

fn test_delete_process_subscriptions(_process: u64, _context: u64) {
    PROCESS_TEARDOWNS.fetch_add(1, Ordering::SeqCst);
}

fn wnf_namespace(assert: Assert) {
    use crate::ntos::ex::wnf::data_block as data;
    use crate::ntos::ex::wnf::name as wnf_name;
    use crate::ntos::ex::wnf::namespace::{self, Lifecycle, NameDefinition};
    use crate::ntos::ps::process;
    let lifecycle = Lifecycle { delete_name_subscriptions: test_delete_name_subscriptions, delete_process_subscriptions: test_delete_process_subscriptions };
    NAME_TEARDOWNS.store(0, Ordering::SeqCst);
    PROCESS_TEARDOWNS.store(0, Ordering::SeqCst);
    assert(namespace::create(lifecycle).is_ok() && namespace::create(lifecycle).is_err(), "wnfnamespace: um namespace por vez");
    let current = process::get_current_process();
    // Escopos: cache do mapa, contexto do processo e identidade explícita.
    let system = namespace::resolve_kernel_scope(current, 0, 0);
    let system_again = namespace::resolve_kernel_scope(current, 0, 0);
    let machine = namespace::resolve_kernel_scope(current, 4, 0);
    let system_scope = match system { Ok(Ok(pointer)) => pointer, _ => 0 };
    assert(system_scope != 0 && matches!(system_again, Ok(Ok(pointer)) if pointer == system_scope) && matches!(machine, Ok(Ok(pointer)) if pointer != system_scope && pointer != 0), "wnfnamespace: escopos de sistema (cache) e maquina");
    let machine_scope = match machine { Ok(Ok(pointer)) => pointer, _ => 0 };
    let process_scope = match namespace::resolve_kernel_scope(current, 3, 0) { Ok(Ok(pointer)) => pointer, _ => 0 };
    let wnf_context = &unsafe { Eprocess::at(current) }.wnf_context;
    let context = wnf_context.get();
    assert(process_scope != 0 && context != 0, "wnfnamespace: escopo de processo e contexto WnfContext publicados");
    let process_context = unsafe { WnfProcessContext::at(context) };
    let process_instance = unsafe { WnfScopeInstance::at(process_scope) };
    // A identidade do escopo fica logo depois da instância (InstanceIdData aponta para lá).
    assert(process_context.process.get() == current && process_context.implicit_scope_instances[2].get() == process_scope && process_instance.instance_id_size.get() == 8 && guest::read64(process_scope + WnfScopeInstance::SIZE) == current, "wnfnamespace: escopo de processo pelo EPROCESS e contexto WnfContext");
    let session_identity = guest::alloc_bytes(8);
    guest::write32(session_identity, 5);
    let session = namespace::resolve_kernel_scope(current, 1, session_identity);
    let session_again = namespace::resolve_kernel_scope(current, 1, session_identity);
    let session_scope = match session { Ok(Ok(pointer)) => pointer, _ => 0 };
    assert(session_scope != 0 && matches!(session_again, Ok(Ok(pointer)) if pointer == session_scope), "wnfnamespace: escopo de sessao pela identidade explicita");
    let session_instance = unsafe { WnfScopeInstance::at(session_scope) };
    assert(session_instance.instance_id_size.get() == 4 && guest::read32(session_instance.instance_id_data.get()) == 5 && process_context.implicit_scope_instances[0].get() == 0, "wnfnamespace: identidade explicita encontrada na lista, sem cache");
    assert(namespace::resolve_kernel_scope(current, 6, 0).is_err(), "wnfnamespace: escopo nao capturado");
    // Nomes: definição bem conhecida, criação, consulta e dados.
    let well_known = wnf_name::decode(0x0280_032E_A3BC_0875).decoded_name;
    let definition = namespace::lookup_definition(well_known);
    let Ok(Ok(definition)) = definition else {
        assert(false, "wnfnamespace: definicao bem conhecida pelo namespace");
        return;
    };
    let created = namespace::create_name(system_scope, well_known, NameDefinition::from(&definition), current);
    let state = match created { Ok(Ok(state)) => state, _ => data::NameState { pointer: 0 } };
    assert(state.pointer != 0 && state.decoded_name() == well_known && state.maximum_size() == 8 && state.type_identifier() == state.pointer + 0xA8 && guest::read_bytes(state.type_identifier(), 4) == [0x63, 0x64, 0xF9, 0x48] && state.data_pointer() == 0, "wnfnamespace: nome criado com GUID copiado e sem dados");
    let found = namespace::lookup_name(system_scope, well_known);
    assert(matches!(found, Ok(Ok(found)) if found.pointer == state.pointer) && matches!(namespace::lookup_name(system_scope, well_known ^ 0x1000_0000), Ok(Err(0xC000_0034))), "wnfnamespace: consulta na arvore AVL");
    let buffer = guest::alloc_bytes(0x40);
    guest::write64(buffer, 0x0102_0304_0506_0708);
    assert(matches!(data::write(&state, buffer, 8, 0, false), Ok(0)) && matches!(data::read(&state, buffer + 0x10, buffer + 0x20, 8, buffer + 0x18), Ok(0)) && guest::read64(buffer + 0x20) == 0x0102_0304_0506_0708, "wnfnamespace: dados do nome publicado");
    let other = well_known ^ 0x0000_0001_0000_0000;
    let second = namespace::create_name(system_scope, other, NameDefinition::from(&definition), current);
    let second_state = match second { Ok(Ok(state)) => state, _ => data::NameState { pointer: 0 } };
    assert(second_state.pointer != 0 && second_state.security_descriptor() == state.security_descriptor() && guest::read64(state.security_descriptor() - 0x20 + 8) == 2, "wnfnamespace: descritor compartilhado pelo cache com contagem");
    // Nome temporário na lista do processo criador.
    let temporary = (wnf_name::NAME_MASK ^ 0x0000_00AB_0000_00F1) & !0x3C0 | 0x30;
    let temporary_state = match namespace::create_name(process_scope, temporary, NameDefinition { maximum_size: 16, type_identifier: 0, security_descriptor: definition.security_descriptor }, current) { Ok(Ok(state)) => state, _ => data::NameState { pointer: 0 } };
    let temporary_names = &process_context.temporary_names_list_head;
    assert(temporary_state.pointer != 0 && temporary_state.creator_process() == current && temporary_names.flink.get() == unsafe { WnfNameInstance::at(temporary_state.pointer) }.temporary_name_list_entry.address(), "wnfnamespace: nome temporario ligado ao contexto do criador");
    drop(definition);
    // Exclusão depois de devolver as referências de rundown.
    for state in [state, state, second_state, temporary_state] {
        let _ = namespace::release_name(&state);
    }
    assert(namespace::delete_name(temporary_state.pointer).is_ok() && temporary_names.flink.get() == temporary_names.address() && namespace::delete_name(second_state.pointer).is_ok() && NAME_TEARDOWNS.load(Ordering::SeqCst) == 2, "wnfnamespace: exclusao desmonta os assinantes");
    assert(namespace::delete_name(second_state.pointer).is_err(), "wnfnamespace: nome excluido nao tem dono");
    for scope in [system_scope, system_scope, machine_scope, process_scope, session_scope, session_scope] {
        let _ = namespace::release_scope(scope);
    }
    assert(namespace::dispose().is_ok() && !namespace::exists() && NAME_TEARDOWNS.load(Ordering::SeqCst) == 3 && PROCESS_TEARDOWNS.load(Ordering::SeqCst) == 1 && wnf_context.get() == 0, "wnfnamespace: dispose libera nomes, escopos e o contexto do processo");
    guest::free_bytes(session_identity);
    guest::free_bytes(buffer);
}

/// (chamadas, máscara, carimbo, nome codificado, contexto) do callback WNF.
static WNF_CALLBACK: [core::sync::atomic::AtomicU64; 5] = [const { core::sync::atomic::AtomicU64::new(0) }; 5];

extern "win64" fn test_wnf_callback(_subscription: u64, name: u64, mask: u64, stamp: u64, _type_identifier: u64, context: u64) -> u64 {
    WNF_CALLBACK[0].fetch_add(1, Ordering::SeqCst);
    WNF_CALLBACK[1].store(mask, Ordering::SeqCst);
    WNF_CALLBACK[2].store(stamp, Ordering::SeqCst);
    WNF_CALLBACK[3].store(read_state_name(name), Ordering::SeqCst);
    WNF_CALLBACK[4].store(context, Ordering::SeqCst);
    0
}

fn wnf_notifications_and_subscriptions(assert: Assert) {
    use crate::ntos::ex::wnf::data_block as data;
    use crate::ntos::ex::wnf::namespace::{self, Lifecycle, NameDefinition};
    use crate::ntos::ex::wnf::{name as wnf_name, notifications as notifications, subscriptions as subscriptions};
    use crate::ntos::ps::process;
    for slot in &WNF_CALLBACK {
        slot.store(0, Ordering::SeqCst);
    }
    assert(matches!(notifications::create(), Ok(true)) && notifications::create().is_err(), "wnfnotify: work item do dispatcher de kernel");
    assert(namespace::create(Lifecycle { delete_name_subscriptions: notifications::detach_name_hook, delete_process_subscriptions: notifications::delete_process_subscriptions_hook }).is_ok(), "wnfnotify: namespace ligado as notificacoes");
    let system = process::get_system_process();
    let scope = match namespace::resolve_kernel_scope(system, 0, 0) { Ok(Ok(pointer)) => pointer, _ => 0 };
    let descriptor = guest::alloc_bytes(0x80);
    relative_descriptor(descriptor, None, None);
    let decoded = 0x0000_00CD_0000_0001u64;
    let state = match namespace::create_name(scope, decoded, NameDefinition { maximum_size: 16, type_identifier: 0, security_descriptor: descriptor }, system) { Ok(Ok(state)) => state, _ => data::NameState { pointer: 0 } };
    assert(scope != 0 && state.pointer != 0, "wnfnotify: escopo e nome");
    // Inscrição de kernel só de dados: a transição de leitor (máscara 2) não é aceita.
    let subscribed = subscriptions::subscribe_name(state.pointer, system, 0, 1);
    let subscription = match subscribed { Ok(Ok(subscribed)) => subscribed, _ => subscriptions::Subscribed::default() };
    let wnf_context = &unsafe { Eprocess::at(system) }.wnf_context;
    assert(subscription.pointer != 0 && subscription.identifier != 0 && subscription.reader_transition == 1 && subscription.notification_performed && wnf_context.get() != 0, "wnfsubscribe: inscricao criada com contexto do processo");
    let process_context = unsafe { WnfProcessContext::at(wnf_context.get()) };
    let name_instance = unsafe { WnfNameInstance::at(state.pointer) };
    let subscriber = unsafe { WnfSubscription::at(subscription.pointer) };
    assert(name_instance.data_subscribers_count.get() == 1 && subscriber.process.get() == system && subscriber.name_instance.get() == state.pointer && process_context.process_subscription_list_head.flink.get() == subscriber.process_subscription_list_entry.address() && name_instance.state_subscription_list_head.flink.get() == subscriber.state_subscription_list_entry.address(), "wnfsubscribe: inscricao publicada nas listas do processo e do nome");
    let _ = crate::ntos::ex::rundown::release(subscriber.run_ref.address());
    let callback = test_wnf_callback as extern "win64" fn(u64, u64, u64, u64, u64, u64) -> u64 as usize as u64;
    subscriber.callback_routine.set(callback);
    subscriber.callback_context.set(0xC0DE);
    // Dados publicados e notificação pelo work item do dispatcher.
    let buffer = guest::alloc_bytes(0x20);
    guest::write32(buffer, 0x1234_5678);
    assert(matches!(data::write(&state, buffer, 4, 0, false), Ok(0)) && state.change_stamp() == 1, "wnfnotify: dados publicados");
    assert(notifications::notify_name(state.pointer, 1, true, false).is_ok() && subscriber.subscription_state.get() == WnfSubscriptionState::WNF_SUB_STATE_READY_TO_DELIVER && name_instance.current_delivery_count.get() == 1 && WNF_CALLBACK[0].load(Ordering::SeqCst) == 0, "wnfnotify: pendente na fila do processo do sistema");
    crate::ntos::io::work_items::run_queue();
    assert(WNF_CALLBACK[0].load(Ordering::SeqCst) == 1 && WNF_CALLBACK[1].load(Ordering::SeqCst) == 1 && WNF_CALLBACK[2].load(Ordering::SeqCst) == 1 && WNF_CALLBACK[3].load(Ordering::SeqCst) == decoded ^ wnf_name::NAME_MASK && WNF_CALLBACK[4].load(Ordering::SeqCst) == 0xC0DE, "wnfnotify: callback com mascara, carimbo, nome codificado e contexto");
    assert(subscriber.subscription_state.get() == WnfSubscriptionState::WNF_SUB_STATE_QUIESCENT && subscriber.current_change_stamp.get() == 1 && name_instance.current_delivery_count.get() == 0, "wnfnotify: entrega concluida e carimbo da inscricao atualizado");
    assert(notifications::notify_name(state.pointer, 1, true, true).is_ok() && WNF_CALLBACK[0].load(Ordering::SeqCst) == 1, "wnfnotify: carimbo repetido nao reentrega dados");
    // Atualização da inscrição existente: mesmo identificador, callback zerado.
    let updated = subscriptions::subscribe_name(state.pointer, system, 0, 1 | 8);
    assert(matches!(updated, Ok(Ok(ref again)) if again.pointer == subscription.pointer && again.identifier == subscription.identifier && again.reader_transition == 0) && subscriber.callback_routine.get() == 0 && subscriber.subscribed_event_set.get() == 9, "wnfsubscribe: inscricao existente atualizada");
    let _ = crate::ntos::ex::rundown::release(subscriber.run_ref.address());
    subscriber.callback_routine.set(callback);
    assert(notifications::notify_name(state.pointer, 8, true, true).is_ok() && WNF_CALLBACK[0].load(Ordering::SeqCst) == 2 && WNF_CALLBACK[1].load(Ordering::SeqCst) == 8, "wnfnotify: conclusao entregue inline");
    // NtSubscribeWnfStateChange com o nome capturado.
    let captured = subscriptions::subscribe_captured(&wnf_name::decode(decoded ^ wnf_name::NAME_MASK), 1, 1 | 8);
    assert(matches!(captured, Ok(Ok(identifier)) if identifier == subscription.identifier) && WNF_CALLBACK[0].load(Ordering::SeqCst) == 2, "wnfsubscribe: inscricao capturada reaproveita a existente");
    subscriber.callback_routine.set(callback);
    // Exclusão do nome desliga o assinante; o dispose libera a inscrição.
    let _ = namespace::release_name(&state);
    assert(namespace::delete_name(state.pointer).is_ok() && subscriber.name_instance.get() == 0, "wnfnotify: exclusao do nome desliga o assinante");
    let _ = namespace::release_scope(scope);
    assert(namespace::dispose().is_ok() && wnf_context.get() == 0 && notifications::dispose().is_ok() && notifications::dispose().is_err(), "wnfnotify: dispose libera inscricoes, contexto e work item");
    guest::free_bytes(descriptor);
    guest::free_bytes(buffer);
}

fn wnf_service_update_and_query(assert: Assert) {
    use crate::ntos::ex::wnf::{name as wnf_name, scope_capture as capture, service as service};
    let storage = guest::alloc_bytes(0x200);
    let name = storage;
    let guid = storage + 0x10;
    let data = storage + 0x20;
    let stamp = storage + 0x40;
    let length = storage + 0x48;
    let output = storage + 0x60;
    write_state_name(name, 0x0280_032E_A3BC_0875);
    guest::write_bytes(guid, &[0x63, 0x64, 0xF9, 0x48, 0xD6, 0x52, 0x85, 0x4E, 0x9C, 0x02, 0xF2, 0xC1, 0x4E, 0x17, 0x26, 0x4E]);
    guest::write32(data, 0xCAFE_F00D);
    // Consulta antes da primeira atualização: vazio, sem criar a instância.
    guest::write32(length, 8);
    guest::write32(stamp, 7);
    assert(matches!(service::query(name, guid, 0, stamp, output, length), Ok(0)) && guest::read32(stamp) == 0 && guest::read32(length) == 0 && service::exists(), "wnfservice: definicao sem instancia devolve vazio");
    guest::write32(length, 8);
    assert(matches!(service::query(name, 0, 0, stamp, output, length), Ok(0xC000_000D)), "wnfservice: consulta exige o TypeId da definicao");
    // Atualização validada pela definição bem conhecida.
    assert(matches!(service::update(name, data, 4, 0, 0, 0, false), Ok(0xC000_000D)) && matches!(service::update(name, data, 9, guid, 0, 0, false), Ok(0xC000_000D)), "wnfservice: TypeId ausente e limite da definicao");
    assert(matches!(service::update(name, data, 4, guid, 0, 0, false), Ok(0)), "wnfservice: ZwUpdateWnfStateData");
    guest::write32(length, 8);
    assert(matches!(service::query(name, guid, 0, stamp, output, length), Ok(0)) && guest::read32(stamp) == 1 && guest::read32(length) == 4 && guest::read32(output) == 0xCAFE_F00D, "wnfservice: ZwQueryWnfStateData le os dados publicados");
    guest::write32(length, 2);
    assert(matches!(service::query(name, guid, 0, stamp, output, length), Ok(0xC000_0023)) && guest::read32(length) == 4, "wnfservice: buffer curto informa o tamanho");
    assert(matches!(service::update(name, data, 4, guid, 0, 9, true), Ok(0xC000_0001)) && matches!(service::update(name, data, 2, guid, 0, 1, true), Ok(0)), "wnfservice: carimbo condicional");
    guest::write32(length, 8);
    assert(matches!(service::query(name, guid, 0, stamp, output, length), Ok(0)) && guest::read32(stamp) == 2 && guest::read32(length) == 2, "wnfservice: segunda versao publicada");
    // Nomes inválidos, escopo explícito recusado e temporário inexistente.
    write_state_name(name + WnfStateName::SIZE, 0x0280_032E_A3BC_0876);
    assert(matches!(service::update(name + 8, data, 4, guid, 0, 0, false), Ok(0xC000_000D)), "wnfservice: versao invalida do nome");
    assert(matches!(service::update(name, data, 4, guid, 0x1234, 0, false), Ok(0xC000_000D)), "wnfservice: escopo de sistema nao aceita ExplicitScope");
    write_state_name(name + WnfStateName::SIZE, wnf_name::NAME_MASK ^ 0x0000_00EE_0000_0031);
    assert(matches!(service::update(name + 8, data, 4, 0, 0, 0, false), Ok(0xC000_0034)), "wnfservice: nome temporario sem instancia");
    // Captura de ExplicitScope.
    let sid = storage + 0x100;
    guest::write32(storage + 0x120, 0);
    assert(matches!(capture::capture_kernel(2, sid), Ok(Ok(ref captured)) if captured.identity == sid) && matches!(capture::capture_kernel(1, 0), Ok(Ok(ref captured)) if captured.identity == 0), "wnfcapture: SID emprestado em KernelMode e escopo ausente");
    assert(matches!(capture::capture_kernel(4, sid), Ok(Err(0xC000_000D))) && matches!(capture::capture_kernel(1, storage + 0x120), Ok(Err(0xC000_000D))) && capture::capture_kernel(3, 4).is_err(), "wnfcapture: maquina recusada, sessao sem espaco de sessao, handle sem ObReferenceObjectByHandle");
    assert(service::shutdown().is_ok() && !service::exists(), "wnfservice: encerramento");
    guest::free_bytes(storage);
}

static LICENSE_CORRUPTIONS: AtomicU32 = AtomicU32::new(0);

fn test_license_corruption(_context: u64) {
    LICENSE_CORRUPTIONS.fetch_add(1, Ordering::SeqCst);
}

/// Entrada de ProductPolicy: tamanho, nome, tipo, dados, flags e reservado.
fn license_entry(name: &str, value_type: u16, data: &[u8], flags: u32) -> alloc::vec::Vec<u8> {
    let units: alloc::vec::Vec<u8> = name.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
    let size = (16 + units.len() + data.len()).div_ceil(4) * 4;
    let mut bytes = alloc::vec::Vec::new();
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&(units.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&value_type.to_le_bytes());
    bytes.extend_from_slice(&(data.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(&units);
    bytes.extend_from_slice(data);
    bytes.resize(size, 0);
    bytes
}

/// Cabeçalho de 20 bytes, entradas e rodapé de 4 bytes.
fn license_blob(entries: &[alloc::vec::Vec<u8>], header_flags: u32) -> alloc::vec::Vec<u8> {
    let body: alloc::vec::Vec<u8> = entries.iter().flatten().copied().collect();
    let total = 20 + body.len() + 4;
    let mut bytes = alloc::vec::Vec::new();
    for value in [total as u32, body.len() as u32, 4, header_flags, 0] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(&0x45u32.to_le_bytes());
    bytes
}

/// UNICODE_STRING em `pointer` com o texto UTF-16 logo depois do descritor.
fn license_unicode(pointer: u64, text: &str) {
    let bytes: alloc::vec::Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let buffer = pointer + UnicodeString::SIZE;
    guest::write_bytes(buffer, &bytes);
    let string = unsafe { UnicodeString::at(pointer) };
    string.length.set(bytes.len() as u16);
    string.maximum_length.set(bytes.len() as u16);
    string.buffer.set(buffer);
}

fn license_cache_index_and_state(assert: Assert) {
    use crate::ntos::ex::license::{cache as cache, data as data, index as index, state as state};
    // Doze entradas fora de ordem: a ordenação passa pela partição do qsort.
    let entries: alloc::vec::Vec<alloc::vec::Vec<u8>> = (0..12u32).rev().map(|value| license_entry(&alloc::format!("Name-{value:02}"), 4, &value.to_le_bytes(), 0)).collect();
    let blob_bytes = license_blob(&entries, 1);
    let blob = guest::alloc_bytes(blob_bytes.len() as u64 + 16);
    guest::write_bytes(blob, &blob_bytes);
    let context_size = 0xB7C0u64;
    let context = guest::alloc_bytes(context_size);
    let count = guest::alloc_bytes(8);
    assert(index::build(blob, 1, context + 24, cache::DESCRIPTOR_CAPACITY, count) == 0 && guest::read32(count) == 12 && guest::read8(context + 24) == 2 && guest::read64(context + 32) == blob + 20, "licenseindex: indice com doze descritores");
    assert(index::build(blob, 1, context + 24, 2, count) == 0xC000_0023 && guest::read32(count) == 12 && guest::read64(context + 24 + 8) == blob + 20 && guest::read64(context + 24 + 2 * 16 + 8) != 0, "licenseindex: capacidade curta limpa so a capacidade e publica a contagem");
    let invalid_bytes = license_blob(&[license_entry("Bad", 4, &[1, 0, 0, 0], 4)], 0);
    let invalid = guest::alloc_bytes(invalid_bytes.len() as u64);
    guest::write_bytes(invalid, &invalid_bytes);
    assert(index::build(invalid, 1, 0, 0, 0) == 0xC000_003E && index::build(invalid, 0, 0, 4, count) == 0 && guest::read32(count) == 1, "licenseindex: flags invalidas recusadas; sem validacao conta a entrada");
    // Cabeçalho do blob primário (comprimento e tipo capturados pelo loader).
    let primary = guest::alloc_bytes(0x14010);
    guest::write_bytes(primary, &blob_bytes);
    guest::write32(primary + 0x14000, blob_bytes.len() as u32);
    guest::write32(primary + 0x14004, 3);
    let header_context = guest::alloc_bytes(16);
    guest::write64(header_context, primary);
    assert(index::validate_header(header_context) == 0, "licenseindex: cabecalho primario valido");
    guest::write32(primary + 0x14004, 1);
    assert(index::validate_header(header_context) == 0xC000_003E, "licenseindex: tipo capturado diferente de REG_BINARY");
    // Preparação pelo blob secundário, com ordenação e estado do contexto.
    guest::write_bytes(context, &alloc::vec![0u8; context_size as usize]);
    guest::write64(context + 0xB6F0, blob);
    LICENSE_CORRUPTIONS.store(0, Ordering::SeqCst);
    assert(matches!(cache::prepare(context, Some(test_license_corruption)), Ok(0)) && guest::read8(context + 0xB6EC) == 1 && guest::read32(context + 0xB6E8) == 12, "licensecache: contexto preparado");
    assert((0..11u64).all(|slot| index::compare(context + 24 + slot * 16, context + 24 + (slot + 1) * 16) <= 0), "licensecache: descritores ordenados pelo qsort do kernel");
    assert(matches!(cache::prepare(context, None), Ok(0)), "licensecache: preparacao repetida");
    let name = guest::alloc_bytes(0x60);
    let output = guest::alloc_bytes(0x40);
    let value_type = output + 8;
    let length = output + 12;
    license_unicode(name, "Name-05");
    assert(matches!(cache::query(context, name, value_type, output, 4, length), Ok(0)) && guest::read32(output) == 5 && guest::read32(value_type) == 4 && guest::read32(length) == 4, "licensecache: busca binaria pelo nome");
    assert(matches!(cache::query(context, name, 0, output, 2, length), Ok(0xC000_0023)) && guest::read32(length) == 4, "licensecache: buffer curto informa o tamanho");
    license_unicode(name, "Name-5");
    assert(matches!(cache::query(context, name, 0, output, 4, length), Ok(0xC000_0034)), "licensecache: nome ausente");
    // Estado: a flag 1 do cabeçalho publica o estado 2.
    let snapshot = state::snapshot(context);
    assert(guest::read32(context + 0xB78C) == 2 && matches!(snapshot, Ok(Some(ref bytes)) if bytes[8] == 2 && bytes[40] == 1), "licensestate: estado do contexto publicado pela flag do blob");
    let source = guest::alloc_bytes(48);
    guest::write64(source, 0xAABB_CCDD_0011_2233);
    assert(matches!(state::update(context, source, 1, 0), Ok(0)) && matches!(state::query(context, output), Ok(0)) && guest::read64(output) == 0xAABB_CCDD_0011_2233 && guest::read32(output + 8) == 2, "licensestate: mascara seleciona o campo atualizado");
    assert(matches!(state::update(context, 0, 1, 0), Ok(0xC000_000D)), "licensestate: origem nula");
    let carrier = guest::read64(context + 0xB7A8);
    guest::write64(carrier, guest::read64(carrier) ^ 1);
    assert(state::query(context, output).is_err(), "licensestate: portador corrompido recusado");
    guest::write64(carrier, guest::read64(carrier) ^ 1);
    assert(state::release(context).is_ok() && guest::read64(context + 0xB7A8) == 0 && matches!(state::query(context, output), Ok(0xC000_0225)), "licensestate: liberacao do registro");
    // Mais entradas que a capacidade: contexto marcado corrompido e telemetria.
    let many: alloc::vec::Vec<alloc::vec::Vec<u8>> = (0..cache::DESCRIPTOR_CAPACITY + 1).map(|_| license_entry("A", 0, &[], 0)).collect();
    let big_bytes = license_blob(&many, 0);
    let big = guest::alloc_bytes(big_bytes.len() as u64);
    guest::write_bytes(big, &big_bytes);
    guest::write_bytes(context, &alloc::vec![0u8; context_size as usize]);
    guest::write64(context + 0xB6F0, big);
    assert(matches!(cache::prepare(context, Some(test_license_corruption)), Ok(0xC000_003E)) && guest::read8(context + 0xB790) == 1 && LICENSE_CORRUPTIONS.load(Ordering::SeqCst) == 1, "licensecache: indice estourado marca corrupcao e avisa");
    assert(matches!(cache::prepare(context, Some(test_license_corruption)), Ok(0xC000_003E)) && LICENSE_CORRUPTIONS.load(Ordering::SeqCst) == 1, "licensecache: corrupcao ja marcada nao avisa de novo");
    // Valores do cache do boot (cópia própria).
    let owned = data::OwnedValues { status: 0, entries: alloc::vec![data::OwnedEntry { name: "Alpha".encode_utf16().collect(), value_type: 4, data: alloc::vec![7, 0, 0, 0] }, data::OwnedEntry { name: "Beta".encode_utf16().collect(), value_type: 1, data: alloc::vec![b'x', 0] }] };
    license_unicode(name, "Beta");
    assert(data::query_owned(&owned, name, value_type, output, 8, length) == 0 && guest::read32(value_type) == 1 && guest::read32(length) == 2 && guest::read16(output) == b'x' as u16, "licensedata: consulta no cache do boot");
    assert(data::query_owned(&data::OwnedValues { status: 0xC000_003E, entries: alloc::vec::Vec::new() }, name, 0, output, 8, length) == 0xC000_003E, "licensedata: status da carga propagado");
    for pointer in [blob, context, count, invalid, primary, header_context, name, output, source, big] {
        guest::free_bytes(pointer);
    }
}

fn test_cloudbook_information(class: u32, buffer: u64, _length: u32, _returned: u64) -> u32 {
    if class != 0xBE {
        return 0xC000_0003;
    }
    guest::write32(buffer, 5);
    guest::write_bytes(buffer + 4, &[0xAB; 32]);
    0
}

fn test_expiration() -> (u32, u64) {
    (0, 132_223_104_000_000_000) // 2020-01-01 00:00:00
}

fn license_service_queries(assert: Assert) {
    use crate::ntos::ex::license::special::{self, Providers};
    use crate::ntos::ex::license::{registry as registry, service as service};
    let entries = alloc::vec![
        license_entry("Kernel-ProductInfo", 4, &0x30u32.to_le_bytes(), 0),
        license_entry("ConsumeAddonPolicySet", 4, &0u32.to_le_bytes(), 0),
        license_entry("Security-SPP-IgnoreDeferredActivation", 4, &1u32.to_le_bytes(), 0),
    ];
    let blob_bytes = license_blob(&entries, 0);
    let blob = guest::alloc_bytes(blob_bytes.len() as u64);
    guest::write_bytes(blob, &blob_bytes);
    let context = guest::alloc_bytes(0xB7C0);
    guest::write64(context + 0xB6F0, blob);
    guest::write32(context + 8, 0x77);
    guest::write_bytes(context + 0xB791, &[0x5A; 16]);
    let name = guest::alloc_bytes(0x100);
    let output = guest::alloc_bytes(0x80);
    let value_type = guest::alloc_bytes(8);
    let length = guest::alloc_bytes(8);
    let providers = Providers::default();
    let ask = |text: &str, capacity: u32, providers: &Providers| {
        license_unicode(name, text);
        guest::write_bytes(output, &[0; 0x40]);
        service::query(context, name, value_type, output, capacity, length, providers).unwrap_or(0xDEAD)
    };
    assert(ask("Kernel-ProductInfo", 4, &providers) == 0 && guest::read32(output) == 0x30 && guest::read32(value_type) == 4, "licenseservice: valor do ProductPolicy pelo cache");
    assert(ask("Kernel-ProductInfo", 2, &providers) == 0xC000_0023 && guest::read32(length) == 4, "licenseservice: buffer curto");
    assert(ask("Ausente-Value", 4, &providers) == 0xC000_0034, "licenseservice: nome ausente");
    assert(ask("Kernel-Session-Machine-Identifier", 16, &providers) == 0 && guest::read_bytes(output, 16) == [0x5A; 16] && guest::read32(value_type) == 3, "licenseservice: identificador de sessao do contexto");
    assert(ask("9882750d-0aa7-4801-bb9b-90ae56b7c2ab", 4, &providers) == 0 && guest::read32(output) == 0x77, "licenseservice: valor DWORD do contexto");
    assert(ask("Security-SPP-Reserved-LocalHardwareId", 4, &providers) == 0xC000_0034, "licenseservice: hardware local sem suporte segue para o cache");
    assert(ask("Security-SPP-Reserved-TBLState", 4, &providers) == 0 && guest::read32(output) == 4, "licenseservice: estado local padrao 4");
    assert(ask("Security-SPP-GenuineLocalStatus", 4, &providers) == 0 && guest::read32(output) == 0, "licenseservice: status genuino pelo estado local");
    let refreshed = crate::ntos::ex::license::state::snapshot(context);
    assert(matches!(refreshed, Ok(Some(ref bytes)) if u64::from_le_bytes(bytes[16..24].try_into().unwrap_or([0; 8])) != 0), "licenseservice: verificacao genuina registra o instante");
    // Data de expiração: FILETIME zero sem provedor, data real com provedor.
    assert(ask("Kernel-ExpirationDate", 16, &providers) == 0 && guest::read_bytes(output, 6) == [0x41, 0x06, 1, 0, 1, 0], "licenseservice: expiracao sem provedor e 1601-01-01");
    let dated = Providers { query_expiration: Some(test_expiration), ..Providers::default() };
    assert(ask("Kernel-ExpirationDate", 16, &dated) == 0 && guest::read_bytes(output, 12) == [0xE4, 0x07, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0], "licenseservice: expiracao 2020-01-01 pelo provedor");
    assert(special::expiration_bytes(132_539_328_000_000_000 + 36_000_000_000 + 1_234_0000) == [0xE5, 0x07, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0], "licensespecial: campos civis com hora, minuto e segundo");
    // ProductOptions na hive.
    assert(ask("Kernel-OsProduct-PFN", 64, &providers) == 0xC000_0034, "licenseregistry: ProductOptions ausente");
    let options = crate::ntos::cm::registry::open_or_create("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ProductOptions", None).unwrap_or(0);
    crate::ntos::cm::registry::set_value(options, "OSProductPfn", 1, crate::ntos::cm::registry::encode_wide("OpenNT.Pfn"));
    assert(ask("Kernel-OsProduct-PFN", 64, &providers) == 0 && guest::read32(value_type) == 1 && guest::read32(length) == 22 && guest::read16(output) == b'O' as u16, "licenseregistry: OSProductPfn lido de ProductOptions");
    assert(ask("Kernel-OsProduct-PFN", 4, &providers) == 0xC000_0023 && guest::read32(length) == 22, "licenseregistry: buffer curto");
    // Cloudbook pela classe 0xBE quando ProductOptions não tem o valor.
    registry::set_system_information(Some(test_cloudbook_information));
    assert(ask("FDE6DEB3-F790-48FF-8F27-43461944FD3E", 32, &providers) == 0 && guest::read32(value_type) == 3 && guest::read_bytes(output, 32) == [0xAB; 32], "licenseregistry: identificador Cloudbook pelo provedor do sistema");
    assert(ask("CE163B38-1AEC-47AF-854D-FC90ABD6951C", 4, &providers) == 0 && guest::read32(value_type) == 4 && guest::read32(output) == 1, "licenseregistry: Cloudbook bloqueado (flags 5)");
    assert(ask("FDE6DEB3-F790-48FF-8F27-43461944FD3E", 16, &providers) == 0xC000_0023, "licenseregistry: capacidade do identificador");
    registry::set_system_information(None);
    crate::ntos::cm::registry::delete_key(options);
    crate::ntos::cm::registry::close_handle(options);
    // Guardas da entrada Nt.
    license_unicode(name, "Kernel-ProductInfo");
    assert(matches!(service::query_kernel(|| context, 0, 0, output, 4, length, &providers), Ok(0xC000_000D)) && matches!(service::query_kernel(|| context, name, 0, 0, 4, length, &providers), Ok(0xC000_000D)) && matches!(service::query_kernel(|| context, name, 0, output, 0x80_0001, length, &providers), Ok(0xC000_0017)), "licenseservice: guardas da entrada Nt");
    assert(matches!(service::query_kernel(|| context, name, value_type, output, 4, length, &providers), Ok(0)) && guest::read32(output) == 0x30, "licenseservice: entrada Nt sem provedor externo");
    assert(matches!(service::query_by_name(context, "Kernel-ProductInfo", 0, output, 4, length, &providers), Ok(0)), "licenseservice: consulta por nome interno");
    let _ = crate::ntos::ex::license::state::release(context);
    for pointer in [blob, context, name, output, value_type, length] {
        guest::free_bytes(pointer);
    }
}

static SECTION_REFERENCES: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);
static SECTION_VIEWS: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);

fn fake_create_section(handle: u64, _access: u32, _attributes: u64, _size: u64, _protect: u32, _flags: u32, _file: u64) -> u32 {
    guest::write64(handle, 0x1234);
    0
}

fn fake_reference_handle(handle: u64, object: u64) -> Option<u32> {
    (handle == 0x1234).then(|| {
        guest::write64(object, 0x5EC7_0000);
        SECTION_REFERENCES.fetch_add(1, Ordering::SeqCst);
        0
    })
}

fn fake_close_handle(_handle: u64) {}

fn fake_map_system_view(_section: u64, base: u64, size: u64, _view_size: u64, _unused: u64) -> u32 {
    let view = guest::alloc_bytes(0x14000);
    guest::write64(base, view);
    guest::write64(size, 0x14000);
    SECTION_VIEWS.fetch_add(1, Ordering::SeqCst);
    0
}

fn fake_unmap_system_view(view: u64) {
    guest::free_bytes(view);
    SECTION_VIEWS.fetch_sub(1, Ordering::SeqCst);
}

fn fake_reference_section(_section: u64) {
    SECTION_REFERENCES.fetch_add(1, Ordering::SeqCst);
}

fn fake_dereference_section(_section: u64) {
    SECTION_REFERENCES.fetch_sub(1, Ordering::SeqCst);
}

fn license_boot_values_and_anonymous(assert: Assert) {
    use crate::ntos::ex::license::boot::{self, BootProviders, SectionBackend};
    use crate::ntos::ex::license::{service as service, values as values};
    use crate::ntos::ex::license::special::Providers;
    // Política publicável: cabeçalho com +16 = 1, rodapé 0x45 e flag 1 (estado 2).
    let mut policy = license_blob(&[license_entry("Kernel-ProductInfo", 4, &0x30u32.to_le_bytes(), 0), license_entry("Kernel-Brand", 1, &[b'O', 0, b'N', 0], 0)], 1);
    policy[16..20].copy_from_slice(&1u32.to_le_bytes());
    let blob = guest::alloc_bytes(policy.len() as u64);
    guest::write_bytes(blob, &policy);
    assert(boot::validate_publication(blob, policy.len() as u32) == 0 && boot::validate_publication(blob, policy.len() as u32 + 4) == 0xC000_000D && boot::validate_publication(blob + 1, policy.len() as u32) == 0xC000_000D && boot::validate_publication(blob, 24) == 0xC000_000D, "licenseboot: validacao da publicacao");
    // Sem backend de seção a publicação não acontece.
    boot::set_section_backend(None);
    let without = boot::create(Some((3, &policy)), &BootProviders::default());
    assert(without.is_err(), "licenseboot: publicacao exige o backend de SECTION");
    boot::set_section_backend(Some(SectionBackend {
        create_section: fake_create_section,
        reference_handle: fake_reference_handle,
        close_handle: fake_close_handle,
        map_system_view: fake_map_system_view,
        unmap_system_view: fake_unmap_system_view,
        reference_section: fake_reference_section,
        dereference_section: fake_dereference_section,
    }));
    SECTION_REFERENCES.store(0, Ordering::SeqCst);
    SECTION_VIEWS.store(0, Ordering::SeqCst);
    let created = boot::create(Some((3, &policy)), &BootProviders::default());
    let (context, diagnostics) = match created { Ok(Ok(created)) => created, _ => (0, boot::Diagnostics::default()) };
    assert(context != 0 && diagnostics.header_status == Some(0) && diagnostics.publication_status == Some(0) && guest::read64(context) == 0 && guest::read64(context + 0xB6F0) != 0 && guest::read64(context + 16) == 0x5EC7_0000 && guest::read32(context + 0xB6E8) == 2 && guest::read8(context + 0xB6EC) == 1, "licenseboot: politica publicada numa SECTION com indice ordenado");
    assert(SECTION_REFERENCES.load(Ordering::SeqCst) == 1 && SECTION_VIEWS.load(Ordering::SeqCst) == 1 && guest::read32(context + 0xB78C) == 2, "licenseboot: referencia e vista retidas pelo contexto; estado 2 pela flag");
    let name = guest::alloc_bytes(0x80);
    let output = guest::alloc_bytes(0x40);
    let length = guest::alloc_bytes(8);
    license_unicode(name, "Kernel-ProductInfo");
    assert(matches!(service::query(context, name, 0, output, 4, length, &Providers::default()), Ok(0)) && guest::read32(output) == 0x30, "licenseboot: consulta pela politica publicada");
    assert(boot::destroy(context).is_ok() && SECTION_REFERENCES.load(Ordering::SeqCst) == 0 && SECTION_VIEWS.load(Ordering::SeqCst) == 0 && boot::destroy(context).is_err(), "licenseboot: destruicao devolve SECTION e vista");
    // Rodapé errado: formato inválido marca o estado local 5.
    let mut broken = policy.clone();
    let footer = broken.len() - 4;
    broken[footer] = 0x44;
    let invalid = boot::create(Some((3, &broken)), &BootProviders::default());
    let (invalid_context, invalid_diagnostics) = match invalid { Ok(Ok(created)) => created, _ => (0, boot::Diagnostics::default()) };
    assert(invalid_context != 0 && invalid_diagnostics.publication_status == Some(0xC000_003F) && guest::read32(invalid_context + 0xB78C) == 5 && SECTION_VIEWS.load(Ordering::SeqCst) == 0, "licenseboot: rodape invalido recusado e vista desfeita");
    let _ = boot::destroy(invalid_context);
    boot::set_section_backend(None);
    // Contexto do boot real: sem ProductPolicy na hive, cabeçalho recusado.
    let host = values::host_context();
    assert(host != 0 && matches!(values::current_context(), Ok(context) if context == host) && guest::read8(host + 0xB790) == 1, "licensevalues: contexto do boot sem politica marcado corrompido");
    assert(matches!(values::query(name, 0, output, 4, length), Ok(0xC000_003E)), "licensevalues: consulta comum devolve DATA_ERROR");
    license_unicode(name, "Kernel-Session-Machine-Identifier");
    assert(matches!(values::query(name, 0, output, 16, length), Ok(0)) && guest::read32(length) == 16, "licensevalues: identificador de sessao do boot");
    // ImpersonateAnonymousToken na thread corrente.
    let thread = crate::ntos::ps::process::get_current_thread();
    assert(crate::ntos::se::token::thread::get(thread).is_none() && matches!(crate::ntos::se::token::impersonate_anonymous::impersonate(u64::MAX - 1, 0), Ok(0)), "impersonateanonymous: NtImpersonateAnonymousToken");
    let impersonation = crate::ntos::se::token::thread::get(thread);
    let anonymous = impersonation.and_then(|impersonation| crate::ntos::se::token::tokens::with(impersonation.token, |token| token.user.clone()));
    assert(impersonation.is_some_and(|impersonation| impersonation.level == 2) && anonymous.is_some_and(|user| user == [1, 1, 0, 0, 0, 0, 0, 5, 7, 0, 0, 0]), "impersonateanonymous: thread impersona S-1-5-7 em nivel de impersonacao");
    let _ = crate::ntos::se::token::thread::assign(thread, None, 0, false, false);
    assert(crate::ntos::se::token::thread::get(thread).is_none() && matches!(crate::ntos::se::token::impersonate_anonymous::impersonate(u64::MAX, 0), Ok(0xC000_0024)), "impersonateanonymous: impersonacao revertida; processo nao e thread");
    for pointer in [blob, name, output, length] {
        guest::free_bytes(pointer);
    }
}

fn capability_policy_and_check(assert: Assert) {
    use crate::ntos::se::capability::{check as capability, policy as policy};
    let name = guest::alloc_bytes(0x80);
    let output = guest::alloc_bytes(0x20);
    license_unicode(name, "internetClient");
    let multi = policy::is_multi_session();
    assert(multi <= 1, "capabilitypolicy: SKU multissessao pelo KUSER_SHARED_DATA");
    // Sem ProductPolicy no boot, o contexto de licenças está corrompido.
    guest::write_bytes(output, &[0; 16]);
    let policy_string = unsafe { UnicodeString::at(output) };
    assert(matches!(policy::query_system_policy(name, output), Ok(0xC000_003E)) && policy_string.buffer.get() == 0 && policy_string.length.get() == 0, "capabilitypolicy: politica do sistema sem ProductPolicy");
    assert(matches!(policy::query_system_policy(0, output), Ok(0xC000_000D)), "capabilitypolicy: nome nulo");
    // RtlCapabilityCheck em modo kernel chega à política do sistema.
    guest::write8(output, 0x55);
    assert(matches!(capability::check(0, name, output), Ok(0xC000_003E)) && guest::read8(output) == 0, "capabilitycheck: politica do sistema invalida zera o resultado");
    assert(matches!(capability::check(0, 0, output), Ok(0xC000_000D)) && capability::check(0, name, 0).is_err(), "capabilitycheck: argumentos nulos (saida nula e falha terminal)");
    guest::free_bytes(name);
    guest::free_bytes(output);
}

pub fn run(assert: Assert) {
    registry_hive(assert);
    key_information_classes(assert);
    key_objects_and_security(assert);
    registry_callbacks(assert);
    key_services_kernel_mode(assert);
    registry_boot_providers(assert);
    hardware_description_and_feature_usage(assert);
    service_database(assert);
    wnf_names_definitions_and_stores(assert);
    wnf_identity_security_and_data(assert);
    wnf_namespace(assert);
    wnf_notifications_and_subscriptions(assert);
    wnf_service_update_and_query(assert);
    license_cache_index_and_state(assert);
    license_service_queries(assert);
    license_boot_values_and_anonymous(assert);
    capability_policy_and_check(assert);
    debug_print!("PHASE5_SELFTEST_OK");
}
