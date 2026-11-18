//! Autotestes da abertura do volume inteiro de um volume do kernel pelo
//! nome do volume, sem nome restante (`io/parse.rs::open_volume`,
//! `drivers/fs/volume_device.rs`), pelos serviços de modo usuário, contra o
//! IopParseDevice, o IopXxxControlFile e o NtQueryVolumeInformationFile do
//! ntoskrnl 19041:
//!
//! - `\??\D:` com SYNCHRONIZE | FILE_READ_ATTRIBUTES (o CreateFileW de
//!   `\\.\C:` do PsmServiceExtHost.dll, com FILE_NON_DIRECTORY_FILE) é a
//!   abertura direta do dispositivo: handle `device` com o acesso pedido,
//!   FILE_OBJECT com FO_DIRECT_DEVICE_OPEN, sem nome, sem VPB e com o
//!   DeviceObject = `\Device\KernelVolume1` (antes, a raiz do volume e
//!   STATUS_FILE_IS_A_DIRECTORY);
//! - nela, o IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS devolve a extensão do
//!   volume no disco (com saída curta, STATUS_BUFFER_TOO_SMALL), o
//!   IOCTL_DISK_GET_LENGTH_INFO (FILE_READ_ACCESS) é STATUS_ACCESS_DENIED
//!   pelo acesso do handle, um IOCTL sem resposta é
//!   STATUS_INVALID_DEVICE_REQUEST, o NtQueryVolumeInformationFile só
//!   responde FileFsDeviceInformation (FILE_DEVICE_DISK com
//!   FILE_DEVICE_IS_MOUNTED) e um FSCTL é STATUS_INVALID_DEVICE_REQUEST;
//! - `\??\D:\` (com a barra) continua a raiz, um diretório do volume;
//! - `\??\D:` com GENERIC_READ é a abertura do volume pelo file system:
//!   FO_VOLUME_OPEN, com o VPB; FileFsVolumeInformation com o número de
//!   série do volume, IOCTL_DISK_GET_LENGTH_INFO com o tamanho,
//!   FSCTL_GET_NTFS_VOLUME_DATA, FSCTL_LOCK_VOLUME e FSCTL_DISMOUNT_VOLUME
//!   recusados (STATUS_ACCESS_DENIED), FSCTL_UNLOCK_VOLUME sem trava
//!   (STATUS_NOT_LOCKED); outra abertura só com FILE_SHARE_READ pede a trava
//!   (STATUS_SHARING_VIOLATION), uma compatível abre, FILE_DIRECTORY_FILE é
//!   STATUS_NOT_A_DIRECTORY e FILE_CREATE é STATUS_ACCESS_DENIED.

use crate::drivers::fs::volume::FileSystem;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types as nt;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user::files::UserDevice;
use crate::ntos::ps::user::{memory, state};

type Assert = fn(bool, &str);

const FO_DIRECT_DEVICE_OPEN: u32 = 0x800;
const FO_VOLUME_OPEN: u32 = 0x40_0000;

pub fn run(assert: Assert) {
    let Some(volume) = crate::drivers::fs::ntfs::fixed() else {
        assert(false, "volumeopen: volume NTFS do kernel");
        return;
    };
    let Some(device) = crate::drivers::fs::volume_device::real_device(volume) else {
        assert(false, "volumeopen: dispositivo do volume NTFS");
        return;
    };
    let Some(extent) = volume.disk_extent() else {
        assert(false, "volumeopen: extensao do volume no disco");
        return;
    };
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "volumeopen: memoria de usuario");
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
        // AllocationSize, FileAttributes, ShareAccess, Disposition,
        // CreateOptions, EaBuffer e EaLength.
        for (index, value) in [0u64, 0, share as u64, disposition as u64, options as u64, 0, 0].into_iter().enumerate() {
            guest::write64(rsp + 0x28 + index as u64 * 8, value);
        }
        let status = state::handler("NtCreateFile").map(|handler| handler(out, access as u64, block, iosb, rsp).unwrap_or(1)).unwrap_or(1);
        (status, guest::read64(out))
    };
    // NtDeviceIoControlFile/NtFsControlFile com entrada e saída no buffer.
    let control = |service: &str, handle: u64, code: u32, input_length: u32, output_length: u32| -> u32 {
        for (index, value) in [iosb, code as u64, buffer, input_length as u64, buffer, output_length as u64].into_iter().enumerate() {
            guest::write64(rsp + 0x28 + index as u64 * 8, value);
        }
        state::handler(service).map(|handler| handler(handle, 0, 0, 0, rsp).unwrap_or(1)).unwrap_or(1)
    };
    let query_volume = |handle: u64, class: u32, length: u64| -> u32 {
        guest::write64(rsp + 0x28, class as u64);
        state::handler("NtQueryVolumeInformationFile").map(|handler| handler(handle, iosb, buffer, length, rsp).unwrap_or(1)).unwrap_or(1)
    };
    let file_object_of = |handle: u64| -> u64 { state::get_user_handle(handle).and_then(|entry| entry.downcast::<UserDevice>().map(|device| device.file_object)).unwrap_or(0) };

    // A abertura direta: SYNCHRONIZE | FILE_READ_ATTRIBUTES, FILE_OPEN,
    // FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE.
    let (status, direct) = create("\\??\\D:", 0x0010_0080, 3, 1, 0x60);
    let information = io_status.information.get();
    let entry = state::get_user_handle(direct);
    let file = file_object_of(direct);
    // SAFETY: o FILE_OBJECT retido pelo handle aberto.
    let object = (file != 0).then(|| unsafe { nt::FileObject::at(file) });
    assert(
        status == 0 && information == 1 && entry.as_ref().is_some_and(|entry| entry.kind() == "device" && entry.access() == 0x0010_0080) && object.is_some_and(|object| object.flags.get() & (FO_DIRECT_DEVICE_OPEN | FO_VOLUME_OPEN) == FO_DIRECT_DEVICE_OPEN && object.file_name.length.get() == 0 && object.vpb.get() == 0 && object.device_object.get() == device),
        "volumeopen: \\??\\D: com SYNCHRONIZE|FILE_READ_ATTRIBUTES abre o dispositivo do volume direto",
    );
    if status == 0 {
        let extents = control("NtDeviceIoControlFile", direct, 0x0056_0000, 0, 0x20);
        let extents_ok = extents == 0 && io_status.information.get() == 0x20 && guest::read32(buffer) == 1 && guest::read32(buffer + 8) == extent.disk_number && guest::read64(buffer + 0x10) == extent.starting_offset && guest::read64(buffer + 0x18) == extent.length;
        let short = control("NtDeviceIoControlFile", direct, 0x0056_0000, 0, 0x10);
        assert(extents_ok && short == 0xC000_0023, "volumeopen: IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS com a extensao do volume e a saida curta");
        assert(control("NtDeviceIoControlFile", direct, 0x0007_405C, 0, 8) == 0xC000_0022, "volumeopen: IOCTL_DISK_GET_LENGTH_INFO sem FILE_READ_DATA no handle");
        assert(control("NtDeviceIoControlFile", direct, 0x0022_096C, 0, 0x10) == 0xC000_0010, "volumeopen: IOCTL sem resposta no volume");
        let device_information = query_volume(direct, 4, 8) == 0 && guest::read32(buffer) == 7 && guest::read32(buffer + 4) & 0x20 != 0;
        assert(device_information && query_volume(direct, 1, 0x80) == 0xC000_0010, "volumeopen: a abertura direta so responde FileFsDeviceInformation");
        assert(control("NtFsControlFile", direct, 0x0009_0028, 0, 0) == 0xC000_0010, "volumeopen: FSCTL na abertura direta");
        assert(state::close_user_handle(direct, true, false).is_ok_and(|status| status == 0), "volumeopen: handle da abertura direta fechado");
    }

    // A barra final é a raiz do volume, um diretório.
    let (root_status, root) = create("\\??\\D:\\", 0x0010_0001, 3, 1, 0x21);
    let root_is_file = state::get_user_handle(root).is_some_and(|entry| entry.kind() == "file");
    assert(root_status == 0 && root_is_file, "volumeopen: \\??\\D:\\ continua a raiz do volume");
    if root_status == 0 {
        let _ = state::close_user_handle(root, true, false);
    }

    // A abertura do volume pelo file system: GENERIC_READ | SYNCHRONIZE.
    let (status, whole) = create("\\??\\D:", 0x8010_0000, 3, 1, 0x20);
    let entry = state::get_user_handle(whole);
    let file = file_object_of(whole);
    // SAFETY: o FILE_OBJECT retido pelo handle aberto.
    let object = (file != 0).then(|| unsafe { nt::FileObject::at(file) });
    assert(
        status == 0 && entry.as_ref().is_some_and(|entry| entry.kind() == "device" && entry.access() == 0x0012_0089) && object.is_some_and(|object| object.flags.get() & (FO_DIRECT_DEVICE_OPEN | FO_VOLUME_OPEN) == FO_VOLUME_OPEN && object.vpb.get() != 0 && object.device_object.get() == device),
        "volumeopen: \\??\\D: com GENERIC_READ abre o volume pelo file system",
    );
    if status != 0 {
        return;
    }
    let serial = volume.volume_information().map(|information| information.serial).unwrap_or(0);
    let volume_status = query_volume(whole, 1, 0x80);
    assert((volume_status == 0 || volume_status == 0x8000_0005) && guest::read32(buffer + 8) == serial, "volumeopen: FileFsVolumeInformation da abertura do volume");
    assert(control("NtDeviceIoControlFile", whole, 0x0007_405C, 0, 8) == 0 && guest::read64(buffer) == extent.length, "volumeopen: IOCTL_DISK_GET_LENGTH_INFO com FILE_READ_DATA");
    let ntfs_data = control("NtFsControlFile", whole, 0x0009_0064, 0, 96);
    assert(ntfs_data == 0 && io_status.information.get() == 96 && guest::read64(buffer) == volume.geometry.serial && guest::read32(buffer + 40) == 512, "volumeopen: FSCTL_GET_NTFS_VOLUME_DATA no volume");
    let locked = control("NtFsControlFile", whole, 0x0009_0018, 0, 0);
    let dismounted = control("NtFsControlFile", whole, 0x0009_0020, 0, 0);
    let unlocked = control("NtFsControlFile", whole, 0x0009_001C, 0, 0);
    assert(locked == 0xC000_0022 && dismounted == 0xC000_0022 && unlocked == 0xC000_002A, "volumeopen: trava e desmontagem recusadas no volume do kernel");
    let (exclusive, _) = create("\\??\\D:", 0x8010_0000, 1, 1, 0x20);
    assert(exclusive == 0xC000_0043, "volumeopen: abertura sem FILE_SHARE_WRITE pede a trava do volume");
    let (shared, second) = create("\\??\\D:", 0x8010_0000, 3, 1, 0x20);
    assert(shared == 0, "volumeopen: segunda abertura compativel do volume");
    if shared == 0 {
        let _ = state::close_user_handle(second, true, false);
    }
    let (as_directory, _) = create("\\??\\D:", 0x8010_0000, 3, 1, 0x21);
    let (created, _) = create("\\??\\D:", 0x8010_0000, 3, 2, 0x20);
    assert(as_directory == 0xC000_0103 && created == 0xC000_0022, "volumeopen: FILE_DIRECTORY_FILE e FILE_CREATE no volume");
    assert(state::close_user_handle(whole, true, false).is_ok_and(|status| status == 0), "volumeopen: handle do volume fechado");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}
