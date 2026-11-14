//! Autotestes do OBJECT_HEADER do NT (`ob/object_header.rs`): o layout que o
//! ObCreateObject monta na frente do corpo, a vida do objeto pelo
//! PointerCount e pelo HandleCount do cabeçalho, o nome do NameInfo no
//! namespace e o ObCreateObjectTypeEx. Na fase 6 (contexto do System) e
//! num processo de usuário de teste (fase 7, com QuotaInfo e a cota cobrada
//! do processo). Os valores esperados seguem o ObpAllocateObject, o
//! ObpFreeObject e o ObInsertObjectEx do ntoskrnl 19041.

use alloc::vec::Vec;

use crate::ntos::inc::types::extra_ob_header::ObjectHeaderQuotaInfo;
use crate::ntos::inc::types::{self as nt, NtStruct};
use crate::ntos::mm::{guest_memory as guest, kernel_data, kernel_pool};
use crate::ntos::ob::{object_header, object_manager, object_types};
use crate::ntos::ps::process;
use crate::ntos::test::phase6::call_export;

type Assert = fn(bool, &str);

fn at<T: NtStruct>(address: u64) -> &'static T {
    // SAFETY: blocos alocados pelo teste com o tamanho do tipo ou objetos
    // vivos do kernel.
    unsafe { T::at(address) }
}

/// O NTSTATUS de 32 bits como o export devolve.
fn status(value: Option<u64>) -> u32 {
    value.map_or(0xDEAD_BEEF, |value| value as u32)
}

/// UNICODE_STRING com `text` em `block` (texto em +0x20).
fn unicode(block: u64, text: &str) -> u64 {
    let units: Vec<u16> = text.encode_utf16().collect();
    guest::write_bytes(block + 0x20, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    let string = at::<nt::UnicodeString>(block);
    string.length.set(units.len() as u16 * 2);
    string.maximum_length.set(units.len() as u16 * 2);
    string.buffer.set(block + 0x20);
    block
}

/// OBJECT_ATTRIBUTES em `block` (nome em `block + 0x40`, se houver).
fn attributes(block: u64, name: Option<&str>, flags: u32) -> u64 {
    let object = at::<nt::ObjectAttributes>(block);
    object.length.set(nt::ObjectAttributes::SIZE as u32);
    object.root_directory.set(0);
    object.object_name.set(name.map_or(0, |name| unicode(block + 0x40, name)));
    object.attributes.set(flags);
    object.security_descriptor.set(0);
    object.security_quality_of_service.set(0);
    block
}

/// Um OBJECT_TYPE_INITIALIZER em `block` com o mapeamento de teste.
fn initializer(block: u64, flags: u16, pool_type: u32, non_paged_charge: u32) -> u64 {
    guest::write_bytes(block, &[0; nt::ObjectTypeInitializer::SIZE as usize]);
    let init = at::<nt::ObjectTypeInitializer>(block);
    init.length.set(nt::ObjectTypeInitializer::SIZE as u16);
    init.object_type_flags.set(flags);
    init.invalid_attributes.set(0x100);
    init.generic_mapping.generic_read.set(0x2_0001);
    init.generic_mapping.generic_write.set(0x2_0002);
    init.generic_mapping.generic_execute.set(0x2_0004);
    init.generic_mapping.generic_all.set(0x1F_0007);
    init.valid_access_mask.set(0x1F_0007);
    init.pool_type.set(nt::PoolType(pool_type as i32));
    init.default_non_paged_pool_charge.set(non_paged_charge);
    block
}

/// O tipo de teste pelo ObCreateObjectTypeEx (DefaultObject NULL).
fn create_type(block: u64, name: &str, init: u64) -> (u32, u64) {
    let name = unicode(block, name);
    let output = block + 0x1F8;
    guest::write64(output, 0);
    let created = status(call_export("ObCreateObjectTypeEx", &[name, init, 0, 0, output]));
    (created, guest::read64(output))
}

/// O cabeçalho de um corpo, pelo OBJECT_TO_OBJECT_HEADER do NT.
fn header_of(body: u64) -> &'static nt::ObjectHeader {
    at::<nt::ObjectHeader>(body - 0x30)
}

/// O tipo pelo TypeIndex do cabeçalho, decodificado à mão.
fn decoded_type(body: u64) -> u64 {
    let header = body - 0x30;
    object_types::type_at_index(header_of(body).type_index.get() ^ object_types::header_cookie() ^ (header >> 8) as u8)
}

fn objects_of(object_type: u64) -> u32 {
    at::<nt::ObjectType>(object_type).total_number_of_objects.get()
}

/// O ObCreateObjectTypeEx: validação, cópia do inicializador, Key, índice e
/// a cobrança padrão acrescida de 0x58.
fn object_type_ex(assert: Assert, block: u64) -> u64 {
    let init = initializer(block + 0x200, 0, 0x200, 0x40);
    let (created, object_type) = create_type(block, "OpenNTTesteOb", init);
    let native = (object_type != 0).then(|| at::<nt::ObjectType>(object_type));
    let copied = native.is_some_and(|native| {
        let info = &native.type_info;
        info.length.get() == 0x78 && info.invalid_attributes.get() == 0x100 && info.valid_access_mask.get() == 0x1F_0007 && info.pool_type.get().0 == 0x200 && info.default_non_paged_pool_charge.get() == 0x98 && info.generic_mapping.generic_all.get() == 0x1F_0007
    });
    let indexed = native.is_some_and(|native| native.key.get() == u32::from_le_bytes(*b"Open") && native.index.get() >= 3 && object_types::type_at_index(native.index.get()) == object_type);
    assert(created == 0 && copied && indexed, "ob: ObCreateObjectTypeEx copia o OBJECT_TYPE_INITIALIZER (cobranca + 0x58), Key 'Open' e o indice na ObTypeIndexTable");
    let (collision, _) = create_type(block, "OpenNTTesteOb", init);
    let (backslash, _) = create_type(block, "Open\\NT", init);
    let bad = initializer(block + 0x280, 0x10, 0x200, 0);
    let (no_procedure, _) = create_type(block, "OpenNTTesteSemRotina", bad);
    let paged = initializer(block + 0x300, 0, 1, 0);
    let (paged_waitable, _) = create_type(block, "OpenNTTestePaginado", paged);
    assert(collision == 0xC000_0035 && backslash == 0xC000_0033 && no_procedure == 0xC000_000D && paged_waitable == 0xC000_000D, "ob: ObCreateObjectTypeEx recusa nome repetido, barra no nome, MaintainHandleCount sem rotina e pool paginavel sem UseDefaultObject");
    object_type
}

/// ObCreateObject com nome: o cabeçalho real na frente do corpo, no pool do
/// tipo; ObInsertObject publica o nome e o handle; o último handle tira o
/// nome e o último dereference libera o bloco.
fn named_object(assert: Assert, block: u64, object_type: u64) {
    let before = objects_of(object_type);
    let object_attributes = attributes(block + 0x400, Some("\\OpenNTTesteObNomeado"), 0x240);
    let output = block + 0x380;
    let created = status(call_export("ObCreateObject", &[0, object_type, object_attributes, 0, 0, 0x40, 0, 0, output]));
    let body = guest::read64(output);
    let header = header_of(body);
    let system = process::get_current_process() == process::get_system_process();
    let expected_mask = 0x02 | if system { 0 } else { 0x08 };
    let name_info = body - 0x30 - 0x20;
    let laid_out = created == 0
        && header.pointer_count.get() == 1
        && header.handle_count.get() == 0
        && header.flags.get() == 0x03
        && header.info_mask.get() == expected_mask
        && header.object_create_info.get() != 0
        && header.security_descriptor.get() == 0
        && decoded_type(body) == object_type
        && call_export("ObGetObjectType", &[body]) == Some(object_type)
        && call_export("ObQueryNameInfo", &[body]) == Some(name_info)
        && crate::ntos::rtl::guest_strings::read_unicode_string(at::<nt::ObjectHeaderNameInfo>(name_info).name.address()) == "\\OpenNTTesteObNomeado"
        && at::<nt::ObjectHeaderNameInfo>(name_info).directory.get() == 0
        && objects_of(object_type) == before + 1;
    let base = body - 0x30 - object_header::INFO_MASK_TO_OFFSET[expected_mask as usize] as u64;
    let pooled = kernel_pool::info(base).is_some_and(|info| info.tag == u32::from_le_bytes(*b"Open") && !info.paged && info.nx && info.bytes == 0x30 + object_header::INFO_MASK_TO_OFFSET[expected_mask as usize] as u64 + 0x40);
    assert(laid_out && pooled, "ob: ObCreateObject monta o OBJECT_HEADER (PointerCount 1, Flags NewObject|KernelObject, NameInfo com o nome capturado, TypeIndex pelo ObHeaderCookie) no pool NonPagedPoolNx do tipo com a tag Key");

    let (new_object, handle) = (block + 0x388, block + 0x390);
    let inserted = status(call_export("ObInsertObject", &[body, 0, 0x1F_0007, 0, new_object, handle]));
    let kernel_handle = guest::read64(handle);
    let root = object_manager::node(object_manager::ROOT).and_then(|node| node.data).map_or(0, |data| data.native_body);
    let published = object_manager::lookup("\\OpenNTTesteObNomeado").and_then(object_manager::node).and_then(|node| node.data).is_some_and(|data| data.native_pointer == body);
    let after_insert = inserted == 0
        && guest::read64(new_object) == body
        && kernel_handle & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000
        && header.flags.get() & 1 == 0
        && header.object_create_info.get() == 1
        && header.handle_count.get() == 1
        && header.pointer_count.get() == 2
        && at::<nt::ObjectHeaderNameInfo>(name_info).directory.get() == root
        && crate::ntos::rtl::guest_strings::read_unicode_string(at::<nt::ObjectHeaderNameInfo>(name_info).name.address()) == "OpenNTTesteObNomeado"
        && published;
    assert(after_insert, "ob: ObInsertObject com nome tira NewObject, cobra no System (QuotaBlockCharged 1), conta o handle e a entrada do diretorio (PointerCount 2) e publica o nome com o diretorio no NameInfo");

    let referenced = block + 0x398;
    let by_handle = status(call_export("ObReferenceObjectByHandle", &[kernel_handle, 0, object_type, 0, referenced, 0])) == 0 && guest::read64(referenced) == body && header.pointer_count.get() == 3;
    let _ = call_export("ObfDereferenceObject", &[body]);
    let mismatch = status(call_export("ObReferenceObjectByPointer", &[body, 0, object_types::event_type().pointer, 1])) == 0xC000_0024;
    let by_pointer = status(call_export("ObReferenceObjectByPointer", &[body, 0, object_type, 0])) == 0 && header.pointer_count.get() == 3;
    let _ = call_export("ObfDereferenceObject", &[body]);
    let open_attributes = attributes(block + 0x500, Some("\\OpenNTTesteObNomeado"), 0x240);
    let second = block + 0x3A0;
    let by_name = status(call_export("ObOpenObjectByName", &[open_attributes, object_type, 0, 0, 0x1F_0007, 0, second])) == 0 && header.handle_count.get() == 2;
    let closed_second = status(call_export("ZwClose", &[guest::read64(second)])) == 0 && header.handle_count.get() == 1 && header.pointer_count.get() == 2;
    assert(by_handle && mismatch && by_pointer && by_name && closed_second, "ob: ObReferenceObjectByHandle/ByPointer e ObOpenObjectByName contam no PointerCount e no HandleCount do cabecalho");

    let closed = status(call_export("ZwClose", &[kernel_handle])) == 0;
    let gone = object_manager::lookup("\\OpenNTTesteObNomeado").is_none() && objects_of(object_type) == before && kernel_pool::info(base).is_none() && !object_header::is_object(body);
    assert(closed && gone, "ob: o ultimo handle tira o nome temporario do namespace (ObpDeleteNameCheck) e o ultimo dereference devolve o bloco ao pool (ObpFreeObject)");
}

/// Objetos sem nome: ObDeleteCapturedInsertInfo e ObInsertObject sem handle.
fn unnamed_objects(assert: Assert, block: u64, object_type: u64) {
    let before = objects_of(object_type);
    let output = block + 0x380;
    let created = status(call_export("ObCreateObject", &[0, object_type, 0, 0, 0, 0x20, 0, 0, output])) == 0;
    let body = guest::read64(output);
    let header = header_of(body);
    let system = process::get_current_process() == process::get_system_process();
    let mask_ok = header.info_mask.get() == if system { 0 } else { 0x08 } && call_export("ObQueryNameInfo", &[body]) == Some(0);
    let _ = call_export("ObDeleteCapturedInsertInfo", &[body]);
    let deleted_info = header.object_create_info.get() == 0 && header.flags.get() & 1 == 1;
    let _ = call_export("ObfDereferenceObject", &[body]);
    let freed = objects_of(object_type) == before && !object_header::is_object(body);
    assert(created && mask_ok && deleted_info && freed, "ob: objeto sem nome sem NameInfo; ObDeleteCapturedInsertInfo libera a informacao de criacao e o ultimo dereference libera o objeto");
    let created = status(call_export("ObCreateObject", &[0, object_type, 0, 0, 0, 0x20, 0, 0, output])) == 0;
    let body = guest::read64(output);
    let inserted = status(call_export("ObInsertObject", &[body, 0, 0, 0, 0, 0])) == 0;
    assert(created && inserted && objects_of(object_type) == before && !object_header::is_object(body), "ob: ObInsertObject sem handle de um objeto sem nome nem seguranca solta a referencia de criacao");
    let invalid = attributes(block + 0x400, None, 0x100);
    assert(status(call_export("ObCreateObject", &[0, object_type, invalid, 0, 0, 0x20, 0, 0, output])) == 0xC000_000D, "ob: atributo proibido pelo InvalidAttributes do tipo e STATUS_INVALID_PARAMETER");
}

/// O DEVICE_OBJECT pelo ObOpenObjectByPointer, ObReferenceObjectByHandle e
/// ObReferenceObjectByPointer (o dono dos dispositivos no Object Manager).
fn device_objects(assert: Assert, block: u64) {
    let address = guest::alloc_bytes(nt::DeviceObject::SIZE);
    let device = at::<nt::DeviceObject>(address);
    device.type_.set(3);
    device.size.set(nt::DeviceObject::SIZE as u16);
    device.stack_size.set(1);
    let registered = crate::ntos::ob::objects::device::register(address, None, None).is_ok();
    let device_type = guest::read64(kernel_data::address("IoDeviceObjectType").unwrap_or(0));
    let handle = block + 0x380;
    let opened = status(call_export("ObOpenObjectByPointer", &[address, 0x200, 0, 0, device_type, 0, handle])) == 0;
    let referenced = block + 0x388;
    let by_handle = status(call_export("ObReferenceObjectByHandle", &[guest::read64(handle), 0, device_type, 0, referenced, 0])) == 0 && guest::read64(referenced) == address;
    let _ = call_export("ObfDereferenceObject", &[address]);
    let closed = status(call_export("ZwClose", &[guest::read64(handle)])) == 0;
    let by_pointer = status(call_export("ObReferenceObjectByPointer", &[address, 0, device_type, 0])) == 0;
    let _ = call_export("ObfDereferenceObject", &[address]);
    assert(registered && opened && by_handle && closed && by_pointer && call_export("ObGetObjectType", &[address]) == Some(device_type), "ob: DEVICE_OBJECT abre pelo ObOpenObjectByPointer, resolve pelo ObReferenceObjectByHandle e retem pelo ObReferenceObjectByPointer");
}

pub fn run(assert: Assert) {
    let block = guest::alloc_bytes(0x1000);
    let object_type = object_type_ex(assert, block);
    if object_type != 0 {
        named_object(assert, block, object_type);
        unnamed_objects(assert, block, object_type);
    }
    device_objects(assert, block);
    guest::free_bytes(block);
}

/// Num processo de usuário de teste: QuotaInfo no cabeçalho, a cota cobrada
/// do EPROCESS no handle de criação e devolvida no ObpFreeObject, o handle
/// na tabela do processo fechado pelo NtClose de UserMode, e um objeto
/// exclusivo (OBJ_EXCLUSIVE) que outro processo não abre.
pub fn run_user(assert: Assert) {
    use crate::ntos::ob::close;
    use crate::ntos::test::multiprocess::identity::with_test_process;
    let object_type = object_types::all().into_iter().find(|info| info.name == "OpenNTTesteOb").map_or(0, |info| info.pointer);
    if object_type == 0 {
        assert(false, "ob: tipo de teste criado na fase 6");
        return;
    }
    let block = guest::alloc_bytes(0x1000);
    let outcome = with_test_process("cabecalho-ob.exe", None, |test| {
        let usage = |paged: bool| at::<nt::Eprocess>(test.process).process_quota_usage[paged as usize].get();
        let (paged_before, non_paged_before) = (usage(true), usage(false));
        let output = block + 0x380;
        let exclusive = attributes(block + 0x400, None, 0x20);
        let created = status(call_export("ObCreateObject", &[0, object_type, exclusive, 1, 0, 0x40, 0x30, 0x50, output])) == 0;
        let body = guest::read64(output);
        let header = header_of(body);
        let quota_info = body - 0x30 - 0x20;
        let quota = at::<ObjectHeaderQuotaInfo>(quota_info);
        let laid_out = header.info_mask.get() == 0x18 && header.flags.get() == 0x09 && quota.paged_pool_charge.get() == 0x30 && quota.non_paged_pool_charge.get() == 0x50;
        let handle = block + 0x388;
        let inserted = status(call_export("ObInsertObject", &[body, 0, 0x1F_0007, 0, 0, handle])) == 0;
        let user_handle = guest::read64(handle);
        let charged = header.object_create_info.get() == 1 && usage(true) == paged_before + 0x30 && usage(false) == non_paged_before + 0x50;
        let exclusive_process = at::<nt::Field<u64>>(body - 0x30 - 0x30).get() == test.process;
        let in_table = user_handle != 0 && user_handle < 0x8000_0000 && crate::ntos::ob::open_pointer::resolve(user_handle, true).is_some_and(|resolved| resolved.is_ok_and(|resolved| resolved.item.pointer == body));
        let closed = matches!(close::close(user_handle, Some(1)), Ok(0));
        let returned = usage(true) == paged_before && usage(false) == non_paged_before && !object_header::is_object(body);
        Some((created && laid_out, inserted && charged && exclusive_process && in_table, closed && returned))
    })
    .flatten();
    guest::free_bytes(block);
    let Some((laid_out, inserted, closed)) = outcome else {
        assert(false, "ob: processo de teste do cabecalho");
        return;
    };
    assert(laid_out, "ob: num processo de usuario o cabecalho leva QuotaInfo (cobrancas pedidas) e ProcessInfo (OBJ_EXCLUSIVE), Flags NewObject|ExclusiveObject");
    assert(inserted, "ob: o handle de criacao cobra a cota do processo, prende o ExclusiveProcess e entra na tabela do processo");
    assert(closed, "ob: o NtClose de UserMode fecha o ultimo handle, o objeto sai e a cota volta ao processo");
}
