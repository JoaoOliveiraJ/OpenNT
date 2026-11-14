//! Autotestes do OBJECT_HEADER do NT (`ob/object_header.rs`): o layout que o
//! ObCreateObject monta na frente do corpo, a vida do objeto pelo
//! PointerCount e pelo HandleCount do cabeçalho, o nome do NameInfo no
//! namespace, o ObCreateObjectTypeEx e as rotinas do tipo (Open, Close,
//! OkayToClose, Delete, Security e QueryName, com a remoção adiada). Na fase 6 (contexto do System) e
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

// ---- Rotinas de tipo ------------------------------------------------------------

/// Uma chamada registrada por uma rotina do tipo de teste.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    /// (razão, modo, processo, objeto, acesso, contagem do processo)
    Open(u32, u8, u64, u64, u32, u32),
    /// (processo, objeto, contagem do processo, contagem do sistema)
    Close(u64, u64, u64, u64),
    /// (processo, objeto, handle, modo)
    OkayToClose(u64, u64, u64, u8),
    /// (objeto, IRQL, DeletedInline)
    Delete(u64, u8, bool),
    /// (objeto, operação)
    Security(u64, u32),
    /// (objeto, HasObjectName)
    QueryName(u64, bool),
}

static CALLS: crate::rtl::SpinLock<Vec<Call>> = crate::rtl::SpinLock::new(Vec::new());
static REFUSE_CLOSE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static FAIL_OPEN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn record(call: Call) {
    CALLS.lock().push(call);
}

/// As chamadas registradas sobre `object`, na ordem, esvaziando o registro
/// delas.
fn take_calls(object: u64) -> Vec<Call> {
    let mut calls = CALLS.lock();
    let mine: Vec<Call> = calls.iter().copied().filter(|call| match *call {
        Call::Open(_, _, _, target, _, _) | Call::Close(_, target, _, _) | Call::OkayToClose(_, target, _, _) | Call::Delete(target, _, _) | Call::Security(target, _) | Call::QueryName(target, _) => target == object,
    }).collect();
    calls.retain(|call| !mine.contains(call));
    mine
}

extern "win64" fn open_procedure(reason: u32, mode: u8, process: u64, object: u64, granted: u64, handle_count: u32) -> u32 {
    record(Call::Open(reason, mode, process, object, guest::read32(granted), handle_count));
    if FAIL_OPEN.load(core::sync::atomic::Ordering::SeqCst) { 0xC000_0022 } else { 0 }
}

extern "win64" fn close_procedure(process: u64, object: u64, process_count: u64, system_count: u64) {
    record(Call::Close(process, object, process_count, system_count));
}

extern "win64" fn okay_to_close_procedure(process: u64, object: u64, handle: u64, mode: u8) -> u8 {
    record(Call::OkayToClose(process, object, handle, mode));
    !REFUSE_CLOSE.load(core::sync::atomic::Ordering::SeqCst) as u8
}

extern "win64" fn delete_procedure(object: u64) {
    let inline = guest::read8(object - 0x30 + 0x1B) & 0x80 != 0;
    record(Call::Delete(object, crate::ntos::ke::irql::get_irql(), inline));
}

/// O SecurityProcedure de teste guarda o descritor atribuído no cabeçalho e
/// o libera na remoção.
#[allow(clippy::too_many_arguments)]
extern "win64" fn security_procedure(object: u64, operation: u32, _information: u64, descriptor: u64, _length: u64, objects: u64, _pool: u32, _mapping: u64, _mode: u8) -> u32 {
    record(Call::Security(object, operation));
    match operation {
        3 => guest::write64(object - 0x30 + 0x28, descriptor),
        2 => {
            let current = guest::read64(objects);
            guest::write64(objects, 0);
            if current != 0 {
                guest::free_bytes(current);
            }
        }
        _ => {}
    }
    0
}

extern "win64" fn query_name_procedure(object: u64, has_name: u8, buffer: u64, _length: u32, returned: u64, _mode: u8) -> u32 {
    record(Call::QueryName(object, has_name != 0));
    let name = at::<nt::ObjectNameInformation>(buffer);
    let text = buffer + nt::ObjectNameInformation::SIZE;
    guest::write_bytes(text, &[b'\\', 0, b'R', 0]);
    name.name.length.set(4);
    name.name.maximum_length.set(4);
    name.name.buffer.set(text);
    if returned != 0 {
        guest::write32(returned, nt::ObjectNameInformation::SIZE as u32 + 4);
    }
    0
}

/// O tipo com as seis rotinas, MaintainHandleCount e SecurityRequired.
fn procedure_type(block: u64) -> u64 {
    let init = initializer(block + 0x200, 0x18, 0x200, 0);
    let info = at::<nt::ObjectTypeInitializer>(init);
    info.open_procedure.set(open_procedure as extern "win64" fn(u32, u8, u64, u64, u64, u32) -> u32 as usize as u64);
    info.close_procedure.set(close_procedure as extern "win64" fn(u64, u64, u64, u64) as usize as u64);
    info.okay_to_close_procedure.set(okay_to_close_procedure as extern "win64" fn(u64, u64, u64, u8) -> u8 as usize as u64);
    info.delete_procedure.set(delete_procedure as extern "win64" fn(u64) as usize as u64);
    info.security_procedure.set(security_procedure as extern "win64" fn(u64, u32, u64, u64, u64, u64, u32, u64, u8) -> u32 as usize as u64);
    info.query_name_procedure.set(query_name_procedure as extern "win64" fn(u64, u8, u64, u32, u64, u8) -> u32 as usize as u64);
    create_type(block, "OpenNTTesteRotinas", init).1
}

/// Criação, abertura, duplicação, OkayToClose recusando e aceitando,
/// fechamentos com as contagens, QueryNameProcedure e a remoção em
/// PASSIVE_LEVEL (com o DeleteSecurityDescriptor antes do DeleteProcedure).
fn type_procedures(assert: Assert, block: u64) {
    let object_type = procedure_type(block);
    let system = process::get_system_process();
    let output = block + 0x380;
    let named = attributes(block + 0x400, Some("\\OpenNTTesteRotinas"), 0x240);
    let created = status(call_export("ObCreateObject", &[0, object_type, named, 0, 0, 0x40, 0, 0, output])) == 0;
    let body = guest::read64(output);
    let first = block + 0x388;
    let inserted = status(call_export("ObInsertObject", &[body, 0, 0x1F_0007, 0, 0, first])) == 0;
    let calls = take_calls(body);
    let create_calls = created && inserted && calls == [Call::Open(0, 0, system, body, 0x1F_0007, 1), Call::Security(body, 3)];
    assert(create_calls, "ob: ObInsertObject com nome chama a OpenProcedure (ObCreateHandle, KernelMode, o System, o acesso e a contagem 1) e, com o nome no diretorio, o SecurityProcedure (AssignSecurityDescriptor)");

    let second = block + 0x390;
    let opened = status(call_export("ObOpenObjectByPointer", &[body, 0x200, 0, 0x2_0001, object_type, 0, second])) == 0;
    let third = block + 0x398;
    let duplicated = status(call_export("ZwDuplicateObject", &[u64::MAX, guest::read64(second), u64::MAX, third, 0, 0x200, 2])) == 0;
    let calls = take_calls(body);
    assert(opened && duplicated && calls == [Call::Open(1, 0, system, body, 0x2_0001, 2), Call::Open(2, 0, system, body, 0x2_0001, 3)], "ob: ObOpenObjectByPointer e ZwDuplicateObject chamam a OpenProcedure com ObOpenHandle e ObDuplicateHandle e a contagem do processo");

    let handle = guest::read64(third);
    REFUSE_CLOSE.store(true, core::sync::atomic::Ordering::SeqCst);
    let refused = status(call_export("ZwClose", &[handle])) == 0xC000_0235 && header_of(body).handle_count.get() == 3;
    REFUSE_CLOSE.store(false, core::sync::atomic::Ordering::SeqCst);
    let stripped = handle ^ 0xFFFF_FFFF_8000_0000;
    let refused_calls = take_calls(body) == [Call::OkayToClose(system, body, stripped, 0)];
    let closed = status(call_export("ZwClose", &[handle])) == 0;
    let close_calls = take_calls(body) == [Call::OkayToClose(system, body, stripped, 0), Call::Close(system, body, 3, 3)];
    assert(refused && refused_calls, "ob: a OkayToCloseProcedure que devolve FALSE recusa o ZwClose com STATUS_HANDLE_NOT_CLOSABLE e o handle continua aberto");
    assert(closed && close_calls, "ob: o ZwClose passa pela OkayToCloseProcedure e chama a CloseProcedure com as contagens anteriores (processo e sistema)");

    let name_buffer = block + 0x600;
    let returned = block + 0x3A0;
    let queried = status(call_export("ObQueryNameString", &[body, name_buffer, 0x100, returned])) == 0 && take_calls(body) == [Call::QueryName(body, true)];
    assert(queried && crate::ntos::rtl::guest_strings::read_unicode_string(name_buffer) == "\\R", "ob: ObQueryNameString chama a QueryNameProcedure do tipo");

    let _ = call_export("ZwClose", &[guest::read64(second)]);
    let _ = call_export("ZwClose", &[guest::read64(first)]);
    let calls = take_calls(body);
    let removed = calls == [Call::OkayToClose(system, body, guest::read64(second) ^ 0xFFFF_FFFF_8000_0000, 0), Call::Close(system, body, 2, 2), Call::OkayToClose(system, body, guest::read64(first) ^ 0xFFFF_FFFF_8000_0000, 0), Call::Close(system, body, 1, 1), Call::Security(body, 2), Call::Delete(body, 0, true)];
    assert(removed && !object_header::is_object(body), "ob: o ultimo fechamento remove o objeto em PASSIVE_LEVEL: DeleteSecurityDescriptor e DeleteProcedure (DeletedInline)");

    // Remoção adiada: o último dereference em DISPATCH_LEVEL vai para a fila.
    let created = status(call_export("ObCreateObject", &[0, object_type, 0, 0, 0, 0x20, 0, 0, output])) == 0;
    let body = guest::read64(output);
    let _ = call_export("ObDeleteCapturedInsertInfo", &[body]);
    let previous = crate::ntos::ke::irql::raise_irql(2);
    let _ = call_export("ObfDereferenceObject", &[body]);
    let pending = take_calls(body).is_empty();
    crate::ntos::ke::irql::lower_irql(previous as u64);
    crate::ntos::io::work_items::run_queue();
    let deferred = take_calls(body) == [Call::Delete(body, 0, false)] && !object_header::is_object(body);
    assert(created && pending && deferred, "ob: o ultimo dereference em DISPATCH_LEVEL adia a remocao; o trabalhador chama a DeleteProcedure em PASSIVE_LEVEL");
    let created = status(call_export("ObCreateObject", &[0, object_type, 0, 0, 0, 0x20, 0, 0, output])) == 0;
    let body = guest::read64(output);
    let _ = call_export("ObDeleteCapturedInsertInfo", &[body]);
    let _ = call_export("ObDereferenceObjectDeferDelete", &[body]);
    let queued = take_calls(body).is_empty();
    crate::ntos::io::work_items::run_queue();
    assert(created && queued && take_calls(body) == [Call::Delete(body, 0, false)], "ob: ObDereferenceObjectDeferDelete sempre adia a remocao para o trabalhador");

    // A OpenProcedure que falha desfaz a abertura sem CloseProcedure.
    let created = status(call_export("ObCreateObject", &[0, object_type, 0, 0, 0, 0x20, 0, 0, output])) == 0;
    let body = guest::read64(output);
    FAIL_OPEN.store(true, core::sync::atomic::Ordering::SeqCst);
    let failed = status(call_export("ObInsertObject", &[body, 0, 0x1F_0007, 0, 0, first])) == 0xC000_0022;
    FAIL_OPEN.store(false, core::sync::atomic::Ordering::SeqCst);
    let calls = take_calls(body);
    assert(created && failed && calls == [Call::Security(body, 3), Call::Open(0, 0, system, body, 0x1F_0007, 1), Call::Security(body, 2), Call::Delete(body, 0, true)] && !object_header::is_object(body), "ob: OpenProcedure com falha faz o ObInsertObject devolver o status, sem CloseProcedure, e o objeto sai");
}

/// As rotinas num processo de usuário de teste: a OpenProcedure com o
/// processo e o modo da thread, a duplicata para a tabela do System
/// (ObDuplicateHandle, contagem por processo), a OkayToCloseProcedure que
/// recusa o NtClose de UserMode e a CloseProcedure no fechamento e no fim do
/// processo, com as contagens por processo e do sistema.
fn user_procedures(assert: Assert, block: u64) {
    use crate::ntos::ob::close;
    use crate::ntos::test::multiprocess::identity::with_test_process;
    let object_type = object_types::all().into_iter().find(|info| info.name == "OpenNTTesteRotinas").map_or(0, |info| info.pointer);
    if object_type == 0 {
        assert(false, "ob: tipo com rotinas criado na fase 6");
        return;
    }
    let system = process::get_system_process();
    let outcome = with_test_process("rotinas-ob.exe", None, |test| {
        let mode = at::<nt::Kthread>(test.thread).previous_mode.get() as u8;
        let output = block + 0x380;
        let created = status(call_export("ObCreateObject", &[0, object_type, 0, mode as u64, 0, 0x40, 0, 0, output])) == 0;
        let body = guest::read64(output);
        let handle = block + 0x388;
        let inserted = status(call_export("ObInsertObject", &[body, 0, 0x2_0001, 0, 0, handle])) == 0;
        let user_handle = guest::read64(handle);
        let create_calls = take_calls(body) == [Call::Security(body, 3), Call::Open(0, mode, test.process, body, 0x2_0001, 1)];
        let kernel = block + 0x390;
        let duplicated = status(call_export("ObDuplicateObject", &[test.process, user_handle, system, kernel, 0, 0x200, 2, 0])) == 0;
        let duplicate_calls = take_calls(body) == [Call::Open(2, 0, system, body, 0x2_0001, 1)];
        REFUSE_CLOSE.store(true, core::sync::atomic::Ordering::SeqCst);
        let refused = close::close(user_handle, Some(1)).ok() == Some(0xC000_0235);
        REFUSE_CLOSE.store(false, core::sync::atomic::Ordering::SeqCst);
        let refused_calls = take_calls(body) == [Call::OkayToClose(test.process, body, user_handle, 1)];
        let closed = close::close(user_handle, Some(1)).ok() == Some(0);
        let close_calls = take_calls(body) == [Call::OkayToClose(test.process, body, user_handle, 1), Call::Close(test.process, body, 1, 2)];
        let reopened = block + 0x398;
        let opened = status(call_export("ObOpenObjectByPointer", &[body, 0, 0, 0x2_0001, object_type, 0, reopened])) == 0 && take_calls(body) == [Call::Open(1, 0, test.process, body, 0x2_0001, 1)];
        Some((body, guest::read64(kernel), [created && inserted && create_calls, duplicated && duplicate_calls, refused && refused_calls, closed && close_calls, opened]))
    })
    .flatten();
    let Some((body, kernel_handle, checks)) = outcome else {
        assert(false, "ob: processo de teste das rotinas");
        return;
    };
    let rundown = take_calls(body).iter().any(|call| matches!(call, Call::Close(_, target, 1, 2) if *target == body));
    let _ = call_export("ZwClose", &[kernel_handle]);
    let final_calls = take_calls(body) == [Call::OkayToClose(system, body, kernel_handle ^ 0xFFFF_FFFF_8000_0000, 0), Call::Close(system, body, 1, 1), Call::Security(body, 2), Call::Delete(body, 0, true)];
    assert(checks[0], "ob: num processo de usuario o ObInsertObject chama o SecurityProcedure e a OpenProcedure com o processo, o modo da thread e a contagem do processo");
    assert(checks[1], "ob: ObDuplicateObject para a tabela do System chama a OpenProcedure com ObDuplicateHandle e a contagem do System");
    assert(checks[2] && checks[3], "ob: a OkayToCloseProcedure recebe o processo, o handle e UserMode e recusa o NtClose; aceito, a CloseProcedure recebe as contagens do processo e do sistema");
    assert(checks[4] && rundown, "ob: o handle deixado aberto fecha no fim do processo com a CloseProcedure do processo");
    assert(final_calls, "ob: o ultimo handle (o do System) fecha com OkayToClose e CloseProcedure e o objeto sai com DeleteSecurityDescriptor e DeleteProcedure");
}

pub fn run(assert: Assert) {
    let block = guest::alloc_bytes(0x1000);
    let object_type = object_type_ex(assert, block);
    if object_type != 0 {
        named_object(assert, block, object_type);
        unnamed_objects(assert, block, object_type);
    }
    device_objects(assert, block);
    type_procedures(assert, block);
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
    let block = guest::alloc_bytes(0x1000);
    user_procedures(assert, block);
    guest::free_bytes(block);
}
