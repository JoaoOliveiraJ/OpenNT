//! Autotestes da interface MOUNTDEV do volume do kernel
//! (`drivers/fs/volume_device.rs::mount_control`), da abertura que o
//! mountmgr.sys faz dele (`io/device.rs::get_device_object_pointer`) e da
//! FILE_NORMALIZED_NAME_INFORMATION (48), contra o volmgr.sys, o
//! IoGetDeviceObjectPointer e o ntfs.sys do 19041:
//!
//! - IoGetDeviceObjectPointer(`\Device\KernelVolume1`, FILE_READ_ATTRIBUTES),
//!   o OpenDevice do mountmgr.sys (0x15244), é a abertura direta: o
//!   dispositivo real, FILE_OBJECT sem VPB, sem nome e com
//!   FO_DIRECT_DEVICE_OPEN; o IoGetAttachedDeviceReference dele é ele mesmo;
//!   `\DosDevices\D:` dá o mesmo dispositivo;
//! - QUERY_DEVICE_NAME, QUERY_UNIQUE_ID ("DMIO:ID:" e o GUID estável),
//!   QUERY_STABLE_GUID, QUERY_SUGGESTED_LINK_NAME (STATUS_NOT_FOUND),
//!   LINK_CREATED/DELETED, GPT_ATTRIBUTES e VOLUME_ONLINE com os status e o
//!   Information do volmgr.sys, inclusive a saída curta
//!   (STATUS_BUFFER_OVERFLOW com Information 2);
//! - o volume em memória (`\Device\KernelVolume0`, sem disco) dá
//!   STATUS_NO_SUCH_DEVICE na letra sugerida e nos atributos GPT, e outro
//!   identificador único;
//! - o ObDereferenceObject do FILE_OBJECT manda o CLOSE e devolve o
//!   ReferenceCount do dispositivo;
//! - em modo usuário, o NtDeviceIoControlFile de QUERY_DEVICE_NAME na
//!   abertura direta de `\??\D:`, o LINK_CREATED recusado pelo acesso do
//!   handle e o QUERY_UNIQUE_ID na abertura do volume;
//! - a classe 48 devolve o caminho com os nomes longos gravados, e as classes
//!   9 e 48 pedem 8 bytes (IopQueryOperationLength);
//! - o boot dos autotestes não entrega os volumes ao mountmgr.sys
//!   (`io/boot_partition.rs` é só do boot do smss).

use alloc::vec::Vec;

use crate::drivers::fs::volume::FileSystem;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types as nt;
use crate::ntos::inc::types::extra_fs_fat::{MountdevName, MountdevUniqueId};
use crate::ntos::io::io_manager::{self, RequestContext};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager;
use crate::ntos::ob::objects::{device as device_objects, file as file_objects};
use crate::ntos::ps::process;
use crate::ntos::ps::user::{memory, state};

type Assert = fn(bool, &str);

const FO_DIRECT_DEVICE_OPEN: u32 = 0x800;
const QUERY_UNIQUE_ID: u32 = 0x004D_0000;
const QUERY_DEVICE_NAME: u32 = 0x004D_0008;
const QUERY_SUGGESTED_LINK_NAME: u32 = 0x004D_000C;
const LINK_CREATED_LEGACY: u32 = 0x004D_0010;
const QUERY_STABLE_GUID: u32 = 0x004D_0018;
const LINK_CREATED: u32 = 0x004D_C010;
const LINK_DELETED: u32 = 0x004D_C014;
const GET_GPT_ATTRIBUTES: u32 = 0x0056_0038;
const VOLUME_ONLINE: u32 = 0x0056_C008;

/// Grava uma UNICODE_STRING de kernel em `string` com o texto em `text`.
fn kernel_unicode(string: u64, text: u64, value: &str) {
    let units: Vec<u16> = value.encode_utf16().collect();
    guest::write_bytes(text, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    // SAFETY: a UNICODE_STRING no bloco de rascunho do teste.
    let unicode = unsafe { nt::UnicodeString::at(string) };
    unicode.length.set(units.len() as u16 * 2);
    unicode.maximum_length.set(units.len() as u16 * 2);
    unicode.buffer.set(text);
}

/// IoGetDeviceObjectPointer pelo export: (status, FILE_OBJECT, DEVICE_OBJECT).
fn device_object_pointer(block: u64, name: &str, access: u32) -> (u32, u64, u64) {
    let (unicode, text, outputs) = (block, block + 0x10, block + 0x80);
    kernel_unicode(unicode, text, name);
    // SAFETY: as duas células de saída no bloco de rascunho do teste.
    let (file, device) = unsafe { (Field::<u64>::at(outputs), Field::<u64>::at(outputs + 8)) };
    file.set(0);
    device.set(0);
    let status = super::phase6::call_export("IoGetDeviceObjectPointer", &[unicode, access as u64, outputs, outputs + 8]).map_or(0xFFFF_FFFF, |status| status as u32);
    (status, file.get(), device.get())
}

/// Um IOCTL METHOD_BUFFERED de modo kernel ao dispositivo, com o
/// FILE_OBJECT na stack location (o MountMgrSendDeviceControl): entrada e
/// saída em `buffer`; devolve (status, Information).
fn control(device: u64, file: u64, code: u32, buffer: u64, input_length: u32, output_length: u32) -> (u32, u64) {
    let scratch = guest::alloc_bytes(0x40);
    if scratch == 0 {
        return (0xC000_009A, 0);
    }
    let (event, iosb) = (scratch, scratch + 0x18);
    dispatcher::initialize_event(event, 0, false);
    // SAFETY: o IO_STATUS_BLOCK de rascunho.
    let io_status = unsafe { nt::IoStatusBlock::at(iosb) };
    io_status.status.set(-1);
    io_status.information.set(0);
    let context = RequestContext { file_object: file, thread: process::get_current_thread(), ..Default::default() };
    let request = io_manager::build_device_io_control_request(code, device, if input_length != 0 { buffer } else { 0 }, input_length, buffer, output_length, 0, event, iosb, Some(context));
    if request == 0 {
        guest::free_bytes(scratch);
        return (0xC000_009A, 0);
    }
    let mut status = io_manager::iof_call_driver(device, request) as u32;
    if status == 0x103 {
        dispatcher::wait_for_single_object(event, 0, 0, false);
        status = io_status.status.get() as u32;
    }
    let information = io_status.information.get();
    // A conclusão já soltou o SystemBuffer (IRP_DEALLOCATE_BUFFER); uma
    // recusa sem IoCompleteRequest o deixa no IRP.
    // SAFETY: o IRP construído acima, ainda não liberado.
    let system_buffer = unsafe { nt::Irp::at(request) }.associated_irp.system_buffer.get();
    if system_buffer != 0 {
        guest::free_bytes(system_buffer);
    }
    guest::free_bytes(request);
    guest::free_bytes(scratch);
    (status, information)
}

/// O MOUNTDEV_NAME em `buffer`: (NameLength, texto que cabe em `limit`).
fn mountdev_name(buffer: u64, limit: usize) -> (u16, Vec<u16>) {
    // SAFETY: o MOUNTDEV_NAME devolvido no buffer do teste.
    let reply = unsafe { MountdevName::at(buffer) };
    let length = reply.name_length.get();
    let bytes = guest::read_bytes(reply.name[0].address(), (length as usize).min(limit));
    (length, bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect())
}

/// Grava um MOUNTDEV_NAME de entrada em `buffer`; devolve o tamanho.
fn write_mountdev_name(buffer: u64, value: &str) -> u32 {
    let units: Vec<u16> = value.encode_utf16().collect();
    // SAFETY: o buffer do teste, maior que o MOUNTDEV_NAME.
    let name = unsafe { MountdevName::at(buffer) };
    name.name_length.set(units.len() as u16 * 2);
    guest::write_bytes(name.name[0].address(), &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    2 + units.len() as u32 * 2
}

/// O MOUNTDEV_UNIQUE_ID em `buffer`: (UniqueIdLength, bytes que cabem em `limit`).
fn unique_id(buffer: u64, limit: usize) -> (u16, Vec<u8>) {
    // SAFETY: o MOUNTDEV_UNIQUE_ID devolvido no buffer do teste.
    let reply = unsafe { MountdevUniqueId::at(buffer) };
    let length = reply.unique_id_length.get();
    (length, guest::read_bytes(reply.unique_id[0].address(), (length as usize).min(limit)))
}

pub fn run(assert: Assert) {
    let Some(volume) = crate::drivers::fs::ntfs::fixed() else {
        assert(false, "mountdev: volume NTFS do kernel");
        return;
    };
    let Some(real) = crate::drivers::fs::volume_device::real_device(volume) else {
        assert(false, "mountdev: dispositivo do volume NTFS");
        return;
    };
    let block = guest::alloc_bytes(0x400);
    if block == 0 {
        assert(false, "mountdev: memoria de rascunho");
        return;
    }
    kernel_part(assert, volume, real, block);
    guest::free_bytes(block);
    user_part(assert);
}

fn kernel_part(assert: Assert, volume: &'static crate::drivers::fs::ntfs::Ntfs, real: u64, block: u64) {
    let buffer = block + 0x200;
    // SAFETY: o DEVICE_OBJECT permanente do volume.
    let device = unsafe { nt::DeviceObject::at(real) };
    let references = device.reference_count.get();

    // 1. A abertura do OpenDevice do mountmgr.sys.
    let (status, file, related) = device_object_pointer(block, "\\Device\\KernelVolume1", 0x80);
    // SAFETY: o FILE_OBJECT retido pela abertura.
    let object = (status == 0 && file != 0).then(|| unsafe { nt::FileObject::at(file) });
    let attached = object.and_then(|_| device_objects::attached_reference(real, false).ok());
    if let Some(attached) = attached {
        let _ = device_objects::dereference(attached);
    }
    assert(
        status == 0 && related == real && attached == Some(real) && object.is_some_and(|object| object.device_object.get() == real && object.vpb.get() == 0 && object.file_name.length.get() == 0 && object.flags.get() & FO_DIRECT_DEVICE_OPEN != 0),
        "mountdev: IoGetDeviceObjectPointer(\\Device\\KernelVolume1, FILE_READ_ATTRIBUTES) abre o dispositivo do volume direto",
    );
    let (dos_status, dos_file, dos_related) = device_object_pointer(block, "\\DosDevices\\D:", 0x80);
    if dos_status == 0 && dos_file != 0 {
        let _ = file_objects::dereference(dos_file);
    }
    assert(dos_status == 0 && dos_related == real, "mountdev: IoGetDeviceObjectPointer(\\DosDevices\\D:) da o mesmo dispositivo");
    if object.is_none() {
        return;
    }

    // 2. QUERY_DEVICE_NAME (VmpQueryDeviceName).
    let expected: Vec<u16> = "\\Device\\KernelVolume1".encode_utf16().collect();
    let full = control(real, file, QUERY_DEVICE_NAME, buffer, 0, 0x102);
    let (length, text) = mountdev_name(buffer, 0x100);
    let named = full == (0, 44) && length == 42 && text == expected;
    // SAFETY: o MOUNTDEV_NAME no buffer do teste.
    unsafe { MountdevName::at(buffer) }.name_length.set(0);
    let short = control(real, file, QUERY_DEVICE_NAME, buffer, 0, 4);
    let short_length = mountdev_name(buffer, 0).0;
    let tiny = control(real, file, QUERY_DEVICE_NAME, buffer, 0, 2);
    assert(named && short == (0x8000_0005, 2) && short_length == 42 && tiny.0 == 0xC000_000D, "mountdev: QUERY_DEVICE_NAME com o nome, a saida curta e a minima");

    // 3. QUERY_UNIQUE_ID (VmpQueryUniqueId).
    let full = control(real, file, QUERY_UNIQUE_ID, buffer, 0, 0x82);
    let (length, identifier) = unique_id(buffer, 0x80);
    let identified = full == (0, 26) && length == 24 && identifier.starts_with(b"DMIO:ID:");
    // SAFETY: o MOUNTDEV_UNIQUE_ID no buffer do teste.
    unsafe { MountdevUniqueId::at(buffer) }.unique_id_length.set(0);
    let short = control(real, file, QUERY_UNIQUE_ID, buffer, 0, 4);
    let short_length = unique_id(buffer, 0).0;
    assert(identified && short == (0x8000_0005, 2) && short_length == 24, "mountdev: QUERY_UNIQUE_ID DMIO:ID: com o GUID estavel e a saida curta");

    // 4. QUERY_STABLE_GUID (VmpQueryStableGuid).
    let guid_status = control(real, file, QUERY_STABLE_GUID, buffer, 0, 16);
    let guid = guest::read_bytes(buffer, 16);
    let serial = volume.volume_serial().unwrap_or(0);
    let stable = guid_status == (0, 16) && identifier.len() == 24 && guid[..] == identifier[8..] && u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]) == 0x4F50_454E && guid[8..] == serial.to_le_bytes();
    assert(stable && control(real, file, QUERY_STABLE_GUID, buffer, 0, 8).0 == 0xC000_000D, "mountdev: QUERY_STABLE_GUID com OPEN, KV e o numero de serie do volume");

    // 5. QUERY_SUGGESTED_LINK_NAME: o volmgr.sys nunca sugere letra.
    let suggested = control(real, file, QUERY_SUGGESTED_LINK_NAME, buffer, 0, 0x20).0;
    let suggested_short = control(real, file, QUERY_SUGGESTED_LINK_NAME, buffer, 0, 4).0;
    assert(suggested == 0xC000_0225 && suggested_short == 0xC000_000D, "mountdev: QUERY_SUGGESTED_LINK_NAME sem letra sugerida");

    // 6. LINK_CREATED e os outros avisos.
    let input = write_mountdev_name(buffer, "\\DosDevices\\Q:");
    let created = control(real, file, LINK_CREATED, buffer, input, 0).0;
    let created_short = control(real, file, LINK_CREATED, buffer, 2, 0).0;
    let input = write_mountdev_name(buffer, "\\DosDevices\\Q:");
    let legacy = control(real, file, LINK_CREATED_LEGACY, buffer, input, 0).0;
    let input = write_mountdev_name(buffer, "\\DosDevices\\Q:");
    let deleted = control(real, file, LINK_DELETED, buffer, input, 0).0;
    let gpt = control(real, file, GET_GPT_ATTRIBUTES, buffer, 0, 8).0;
    let online = control(real, file, VOLUME_ONLINE, buffer, 0, 0).0;
    assert(created == 0 && created_short == 0xC000_000D && legacy == 0 && deleted == 0 && gpt == 0xC000_000D && online == 0, "mountdev: LINK_CREATED/DELETED, GPT_ATTRIBUTES e VOLUME_ONLINE como no volmgr.sys");

    // 7. O volume em memória, sem disco.
    let (memory_status, memory_file, memory_device) = device_object_pointer(block, "\\Device\\KernelVolume0", 0x80);
    if memory_status == 0 && memory_file != 0 {
        let memory_name: Vec<u16> = "\\Device\\KernelVolume0".encode_utf16().collect();
        let name_status = control(memory_device, memory_file, QUERY_DEVICE_NAME, buffer, 0, 0x102);
        let memory_named = name_status.0 == 0 && mountdev_name(buffer, 0x100).1 == memory_name;
        let memory_suggested = control(memory_device, memory_file, QUERY_SUGGESTED_LINK_NAME, buffer, 0, 0x20).0;
        let memory_gpt = control(memory_device, memory_file, GET_GPT_ATTRIBUTES, buffer, 0, 8).0;
        let memory_id = control(memory_device, memory_file, QUERY_UNIQUE_ID, buffer, 0, 0x82);
        let other_id = memory_id.0 == 0 && unique_id(buffer, 0x80).1 != identifier;
        assert(memory_named && memory_suggested == 0xC000_000E && memory_gpt == 0xC000_000E && other_id, "mountdev: \\Device\\KernelVolume0 sem disco: sem letra, sem GPT e outro identificador");
        let _ = file_objects::dereference(memory_file);
    } else {
        assert(false, "mountdev: IoGetDeviceObjectPointer(\\Device\\KernelVolume0)");
    }

    // 8. O ObDereferenceObject manda o CLOSE e solta o dispositivo.
    let released = file_objects::dereference(file).is_ok_and(|remaining| remaining == Some(0));
    assert(released && device.reference_count.get() == references, "mountdev: o ObDereferenceObject fecha a abertura e devolve o ReferenceCount do dispositivo");

    // 12. Sem o boot do smss, nenhum volume do kernel chega ao mountmgr.sys.
    if object_manager::lookup("\\Device\\MountPointManager").is_some() {
        let status = crate::ntos::io::volume_dos_name::volume_device_to_dos_name(real, block).unwrap_or(0xFFFF_FFFF);
        assert(status == 0xC000_0034, "mountdev: o boot dos autotestes nao entrega o volume ao mountmgr.sys");
    }
}

/// O caminho de modo usuário: NtDeviceIoControlFile nas aberturas de
/// `\??\D:` e a classe 48 do NtQueryInformationFile.
fn user_part(assert: Assert) {
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "mountdev: memoria de usuario");
        return;
    };
    let (out, iosb, buffer, rsp) = (block + 0x200, block + 0x210, block + 0x300, block + 0x800);
    // SAFETY: o IO_STATUS_BLOCK na região de usuário mapeada acima.
    let io_status = unsafe { nt::IoStatusBlock::at(iosb) };
    let create = |name: &str, access: u32, share: u32, disposition: u32, options: u32| -> (u32, u64) {
        let text = block + 0x80;
        state::write_user_wide(text, name);
        state::write_unicode_string(block + 0x40, text, name);
        // SAFETY: o OBJECT_ATTRIBUTES no início da região de usuário.
        let attributes = unsafe { nt::ObjectAttributes::at(block) };
        attributes.length.set(nt::ObjectAttributes::SIZE as u32);
        attributes.root_directory.set(0);
        attributes.object_name.set(block + 0x40);
        attributes.attributes.set(0x40);
        attributes.security_descriptor.set(0);
        attributes.security_quality_of_service.set(0);
        guest::write64(out, 0);
        for (index, value) in [0u64, 0, share as u64, disposition as u64, options as u64, 0, 0].into_iter().enumerate() {
            guest::write64(rsp + 0x28 + index as u64 * 8, value);
        }
        let status = state::handler("NtCreateFile").map(|handler| handler(out, access as u64, block, iosb, rsp).unwrap_or(1)).unwrap_or(1);
        (status, guest::read64(out))
    };
    let device_control = |handle: u64, code: u32, input_length: u32, output_length: u32| -> u32 {
        for (index, value) in [iosb, code as u64, buffer, input_length as u64, buffer, output_length as u64].into_iter().enumerate() {
            guest::write64(rsp + 0x28 + index as u64 * 8, value);
        }
        state::handler("NtDeviceIoControlFile").map(|handler| handler(handle, 0, 0, 0, rsp).unwrap_or(1)).unwrap_or(1)
    };
    let query = |handle: u64, class: u32, length: u64| -> u32 {
        guest::write64(rsp + 0x28, class as u64);
        state::handler("NtQueryInformationFile").map(|handler| handler(handle, iosb, buffer, length, rsp).unwrap_or(1)).unwrap_or(1)
    };

    // 10. A abertura direta responde o QUERY_DEVICE_NAME; o LINK_CREATED
    // (FILE_READ_ACCESS | FILE_WRITE_ACCESS) passa do acesso do handle.
    let expected: Vec<u16> = "\\Device\\KernelVolume1".encode_utf16().collect();
    let (status, direct) = create("\\??\\D:", 0x0010_0080, 3, 1, 0x60);
    if status == 0 {
        let named = device_control(direct, QUERY_DEVICE_NAME, 0, 0x102) == 0 && io_status.information.get() == 44 && mountdev_name(buffer, 0x100).1 == expected;
        let input = write_mountdev_name(buffer, "\\DosDevices\\Q:");
        let denied = device_control(direct, LINK_CREATED, input, 0);
        assert(named && denied == 0xC000_0022, "mountdev: NtDeviceIoControlFile de QUERY_DEVICE_NAME na abertura direta e LINK_CREATED pelo acesso do handle");
        let _ = state::close_user_handle(direct, true, false);
    } else {
        assert(false, "mountdev: abertura direta de \\??\\D:");
    }
    let (status, whole) = create("\\??\\D:", 0x8010_0000, 3, 1, 0x20);
    if status == 0 {
        let identified = device_control(whole, QUERY_UNIQUE_ID, 0, 0x82) == 0 && io_status.information.get() == 26 && unique_id(buffer, 0x80).1.starts_with(b"DMIO:ID:");
        assert(identified, "mountdev: QUERY_UNIQUE_ID na abertura do volume, passado ao dispositivo alvo");
        let _ = state::close_user_handle(whole, true, false);
    } else {
        assert(false, "mountdev: abertura do volume \\??\\D:");
    }

    // 11. FILE_NORMALIZED_NAME_INFORMATION: os nomes longos gravados.
    let (status, directory) = create("\\??\\D:\\WINDOWS\\system32", 0x0010_0001, 3, 1, 0x21);
    if status == 0 {
        let normalized: Vec<u16> = "\\Windows\\System32".encode_utf16().collect();
        let full = query(directory, 48, 0x100) == 0;
        let name_length = guest::read32(buffer);
        let name: Vec<u16> = guest::read_bytes(buffer + 4, (name_length as usize).min(0xFC)).chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        let short_normalized = query(directory, 48, 7);
        let short_name = query(directory, 9, 4);
        assert(full && name_length == 34 && name == normalized && short_normalized == 0xC000_0004 && short_name == 0xC000_0004, "mountdev: classe 48 com os nomes longos gravados e o minimo de 8 bytes das classes 9 e 48");
        let _ = state::close_user_handle(directory, true, false);
    } else {
        assert(false, "mountdev: abertura de D:\\WINDOWS\\system32");
    }
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}
