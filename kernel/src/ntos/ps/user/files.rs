//! Arquivos, dispositivos e seções de modo usuário.
//!
//! NtOpenFile/NtCreateFile abrem um arquivo do volume (pelo `file_io`) ou um
//! dispositivo do NT (`\Device\X`, `\DosDevices\X`, `\GLOBAL??\X`, `\\.\X`,
//! `\??\X`): o dispositivo vai ao I/O manager de verdade e o IRP_MJ_CREATE
//! chega ao driver. NtCreateNamedPipeFile e NtCreateMailslotFile abrem pelo
//! mesmo caminho, com IRP_MJ_CREATE_NAMED_PIPE/CREATE_MAILSLOT e os
//! parâmetros capturados por `io/file/pipe_mailslot.rs`; NtFsControlFile é o
//! do I/O Manager (`io/file/irp_service.rs`). Também NtDeviceIoControlFile
//! (driver gerenciado ou pilha nativa), NtClose e as syscalls de seção sobre
//! os serviços do Mm.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use super::file_io::{self, OpenRequest};
use super::registry::{parse_user_object_attributes, user_object_attributes};
use super::state::{self, NativeBody, UserObject, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER};
use crate::ntos::io::device_control::{self, FastControl};
use crate::ntos::io::file::{irp_service, pipe_mailslot};
use crate::ntos::io::io_manager::{self, IoParams, IoResult, RequestContext};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::section::{create as create_section, map_view, open as open_section, unmap_view};
use crate::ntos::ob::{close, object_types};
use crate::ntos::ob::objects::file as file_objects;
use crate::ntos::ps::process;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{Eprocess, IoStatusBlock, NtStruct, SectionBasicInformation};

/// Handle `device` do processo: o caminho, o handle do I/O manager e o
/// FILE_OBJECT aberto pelo IRP_MJ_CREATE.
pub struct UserDevice {
    pub device_path: String,
    pub options: u32,
    /// O handle do I/O manager; 0 numa abertura do IopParseDevice
    /// (`io/parse.rs`, o volume inteiro), cuja descrição retém só a
    /// referência do CREATE no FILE_OBJECT.
    pub device_handle: u64,
    pub file_object: u64,
    /// Posição do I/O síncrono (FILE_SYNCHRONOUS_IO_*).
    pub position: crate::rtl::SpinLock<u64>,
}

impl UserObject for UserDevice {
    fn kind(&self) -> &'static str {
        "device"
    }
    fn native_body(&self) -> Option<NativeBody> {
        let pointer = self.file_object;
        (pointer != 0).then(|| NativeBody {
            pointer,
            type_name: object_types::file_type().name.clone(),
            record: pointer,
            reference: Arc::new(move || {
                let _ = file_objects::reference(pointer);
            }),
            dereference: Arc::new(move || {
                let _ = file_objects::dereference(pointer);
            }),
        })
    }
    fn on_each_handle_open(&self) -> Result<bool, KernelError> {
        file_objects::open_handle(self.file_object)?;
        Ok(true)
    }
    fn on_each_handle_close(&self) {
        let _ = file_objects::close_handle(self.file_object);
    }
    /// O último handle cancela as requisições pendentes do objeto.
    fn on_handle_closed(&self) {
        super::device_io::cancel_entry(self, 0, false);
    }
    /// Liberação do objeto: fecha o handle do I/O manager, ou solta a
    /// referência do CREATE de uma abertura do IopParseDevice.
    fn release(&self) {
        if self.device_handle == 0 {
            let _ = file_objects::dereference(self.file_object);
        } else {
            let _ = io_manager::close_device(self.device_handle);
        }
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl UserDevice {
    /// O handle `device` de um FILE_OBJECT que já existe: o
    /// ObOpenObjectByPointer de UserMode com que o CdpLaunchServerProcess do
    /// condrv.sys põe o servidor do console no conhost.exe
    /// (`ob/open_pointer.rs`). Sem handle do I/O manager (o I/O vai por IRP
    /// ao dispositivo relacionado do FILE_OBJECT, como numa abertura do
    /// IopParseDevice), com uma referência própria no FILE_OBJECT, solta no
    /// `release`. O caminho é o do DEVICE_OBJECT do FILE_OBJECT.
    pub fn existing(file_object: u64) -> Result<Self, KernelError> {
        // SAFETY: FILE_OBJECT vivo, retido por quem abre o handle.
        let device = unsafe { crate::ntos::inc::types::FileObject::at(file_object) }.device_object.get();
        let device_path = crate::ntos::io::device::find_device_node_by_pointer(device).and_then(crate::ntos::ob::object_manager::path_of).unwrap_or_default();
        file_objects::reference(file_object)?;
        Ok(Self { device_path, options: 0, device_handle: 0, file_object, position: crate::rtl::SpinLock::new(0) })
    }
}

fn is_separator(character: Option<char>) -> bool {
    matches!(character, Some('\\') | Some('/'))
}

/// O caminho de dispositivo do nome, quando é um (sem regex: prefixos sem
/// caixa). Um nome DOS sem unidade é um link real do Object Manager.
fn device_path_of(path: &str) -> Option<String> {
    let lower = path.to_lowercase();
    let mut device = None;
    if lower.starts_with("\\device\\") && path.len() > 8 {
        device = Some(String::from(path));
    }
    if lower.starts_with("\\dosdevices\\") || lower.starts_with("\\global??\\") {
        device = Some(String::from(path));
    }
    let characters: Vec<char> = path.chars().collect();
    let mut link_rest: Option<String> = None;
    if is_separator(characters.first().copied()) && is_separator(characters.get(1).copied()) {
        let mut index = 2;
        if characters.get(index) == Some(&'?') {
            index += 1;
        }
        if characters.get(index) == Some(&'.') {
            index += 1;
        }
        if characters.get(index) == Some(&'\\') && characters.len() > index + 1 {
            link_rest = Some(characters[index + 1..].iter().collect());
        }
    }
    if link_rest.is_none() && is_separator(characters.first().copied()) && characters.get(1) == Some(&'?') && characters.get(2) == Some(&'?') && characters.get(3) == Some(&'\\') && characters.len() > 4 {
        link_rest = Some(characters[4..].iter().collect());
    }
    if let Some(rest) = link_rest {
        let drive = rest.chars().nth(1) == Some(':');
        if !drive {
            device = Some(alloc::format!("\\DosDevices\\{rest}"));
        }
    }
    device
}

/// IO_STATUS_BLOCK (sondado) com o status e Information zero.
fn fail_iosb(iosb: u64, status: u32) -> u32 {
    match state::set_user_iosb(iosb, status, 0) {
        Ok(()) => status,
        Err(_) => 0xC000_0005,
    }
}

/// NtOpenFile/NtCreateFile: dispositivo pelo I/O manager ou arquivo do
/// volume pelo `file_io`.
pub fn open_nt_file(handle_pointer: u64, attributes: u64, iosb: u64, disposition: u32, request: &OpenRequest) -> Result<u32, KernelError> {
    open_file(handle_pointer, attributes, iosb, disposition, request, None)
}

/// A abertura do IoCreateFile, com o tipo de criação do file system
/// (`special`: os parâmetros de pipe nomeado ou de mailslot capturados).
fn open_file(handle_pointer: u64, attributes: u64, iosb: u64, disposition: u32, request: &OpenRequest, special: Option<&pipe_mailslot::Captured>) -> Result<u32, KernelError> {
    if !state::probe_user_write(handle_pointer, 8) || !state::probe_user_write(iosb, 16) || !state::probe_user_read(attributes, 48) {
        return Ok(0xC000_0005);
    }
    // O EXTENDED_CREATE_INFORMATION sai antes da abertura, como no
    // IopCreateFile (`file_io::extended_create`).
    let request = &match file_io::extended_create(request) {
        Ok(request) => request,
        Err(status) => return Ok(status),
    };
    // FILE_OPEN_BY_FILE_ID relativo a um arquivo do volume: o nome binário
    // vira o caminho do registro, aberto como os demais.
    if request.options & FILE_OPEN_BY_FILE_ID != 0 && special.is_none() {
        match volume_name_by_file_id(attributes) {
            Ok(Some(name)) => {
                let object_flags = match user_object_attributes(attributes) {
                    Ok(flags) => flags,
                    Err(error) => return Ok(error.status),
                };
                let explicit = match capture_explicit_descriptor(attributes) {
                    Ok(descriptor) => descriptor,
                    Err(status) => return Ok(status),
                };
                return open_by_name(handle_pointer, &name, object_flags, iosb, disposition, &OpenRequest { explicit, options: request.options & !FILE_OPEN_BY_FILE_ID, ..request.clone() }, None);
            }
            Ok(None) => {}
            Err(status) => return Ok(fail_iosb(iosb, status)),
        }
    }
    let Some(parsed) = parse_user_object_attributes(attributes) else { return Ok(STATUS_INVALID_PARAMETER) };
    // OBJ_* do OA, lido uma vez.
    let object_flags = match user_object_attributes(attributes) {
        Ok(flags) => flags,
        Err(error) => return Ok(error.status),
    };
    // RootDirectory que é um arquivo de dispositivo (o `\Reference` do
    // servidor do condrv, o `\Connect` da referência, o `\Input` e o
    // `\Output` da conexão): o IopParseFile, que vai ao IopParseDevice com
    // RelatedFileObject = a raiz.
    if parsed.root_directory != 0 && special.is_none() {
        if let Some(root) = state::get_user_handle(parsed.root_directory).filter(|entry| entry.kind() == "device") {
            return open_relative_to_device(handle_pointer, &root, &parsed.path, object_flags, iosb, disposition, request);
        }
    }
    // [Q-FILESEC hook 1, step 1+] O AccessState->SecurityDescriptor dos OA.
    let explicit = match capture_explicit_descriptor(attributes) {
        Ok(descriptor) => descriptor,
        Err(status) => return Ok(status),
    };
    open_by_name(handle_pointer, &parsed.path, object_flags, iosb, disposition, &OpenRequest { explicit, ..request.clone() }, special)
}

/// FILE_OPEN_BY_FILE_ID.
const FILE_OPEN_BY_FILE_ID: u32 = 0x2000;

/// FILE_OPEN_BY_FILE_ID relativo a um handle do volume de boot (o
/// OpenFileById do Win32: RootDirectory é qualquer arquivo do volume e o
/// ObjectName traz os 8 bytes do FILE_REFERENCE): o NTFS abre o registro
/// pela referência, e aqui ela vira o caminho dele no volume, na letra da
/// raiz. `Ok(None)` quando a raiz não é um arquivo do volume (o caminho
/// comum segue); um ObjectName que não tem 8 bytes, ou uma referência fora
/// de uso ou de outra sequência, é STATUS_INVALID_PARAMETER (o
/// ERROR_INVALID_PARAMETER do OpenFileById de um id apagado).
fn volume_name_by_file_id(attributes: u64) -> Result<Option<String>, u32> {
    use crate::ntos::inc::types::{ObjectAttributes, UnicodeString};
    let status = |error: KernelError| if error.status != 0 { error.status } else { 0xC000_0005 };
    let object = state::user_struct::<ObjectAttributes>(attributes).map_err(status)?;
    let root = object.root_directory.probe_get().map_err(status)?;
    let Some(root_entry) = state::get_user_handle(root).filter(|entry| entry.kind() == "file") else { return Ok(None) };
    let Some(root_file) = root_entry.downcast::<super::file_objects::UserFile>() else { return Ok(None) };
    let name = object.object_name.probe_get().map_err(status)?;
    if name == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let string = state::user_struct::<UnicodeString>(name).map_err(status)?;
    let (length, buffer) = (string.length.probe_get().map_err(status)?, string.buffer.probe_get().map_err(status)?);
    if length != 8 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if !state::probe_user_read(buffer, 8) {
        return Err(0xC000_0005);
    }
    let reference = guest::try_read::<u64>(buffer).map_err(status)?;
    let volume = crate::drivers::fs::volume_files::volume().ok_or(0xC000_000Eu32)?;
    let Some(path) = volume.path_of_reference(reference).map_err(|_| STATUS_INVALID_PARAMETER)? else { return Err(STATUS_INVALID_PARAMETER) };
    let root_name = root_file.nt_path.lock().clone();
    let drive = if root_name.len() >= 6 && root_name.starts_with("\\??\\") && root_name.as_bytes()[5] == b':' { String::from(&root_name[..6]) } else { String::from("\\??\\C:") };
    Ok(Some(alloc::format!("{drive}{}", path.replace('/', "\\"))))
}

/// O SeCaptureSecurityDescriptor do OBJECT_ATTRIBUTES.SecurityDescriptor de
/// modo usuário (o ObpCaptureObjectCreateInformation do ObOpenObjectByName),
/// que o IopParseDevice põe no AccessState->SecurityDescriptor: `None` sem
/// descritor, ou o NTSTATUS de um descritor inválido ou ilegível.
fn capture_explicit_descriptor(attributes: u64) -> Result<Option<crate::ntos::se::policy_descriptor::OwnedDescriptor>, u32> {
    let pointer = state::user_struct::<crate::ntos::inc::types::ObjectAttributes>(attributes).and_then(|object| object.security_descriptor.probe_get()).map_err(|error| if error.status != 0 { error.status } else { 0xC000_0005 })?;
    crate::ntos::ob::object_security::capture_descriptor(pointer, true)
}

/// O EaBuffer de um IRP_MJ_CREATE de dispositivo, sondado para leitura
/// (o ProbeForRead do IopCreateFile): (buffer, comprimento), (0, 0) sem EA,
/// ou STATUS_ACCESS_VIOLATION.
fn user_ea(request: &OpenRequest) -> Result<(u64, u32), u32> {
    if request.ea_buffer == 0 || request.ea_length == 0 {
        return Ok((0, 0));
    }
    if !state::probe_user_read(request.ea_buffer, request.ea_length as u64) {
        return Err(0xC000_0005);
    }
    Ok((request.ea_buffer, request.ea_length))
}

/// O NtCreateFile relativo a um handle `device`: o FILE_OBJECT novo, no
/// dispositivo da raiz, aponta o FILE_OBJECT dela (RelatedFileObject) e o
/// nome vai como veio, com o IRP_MJ_CREATE completo e o EA (a mesma
/// abertura de kernel de `io/file/zw.rs`).
fn open_relative_to_device(handle_pointer: u64, root: &state::UserHandle, name: &str, object_flags: u32, iosb: u64, disposition: u32, request: &OpenRequest) -> Result<u32, KernelError> {
    let Some(device) = root.downcast::<UserDevice>() else { return Ok(fail_iosb(iosb, STATUS_INVALID_HANDLE)) };
    let (ea_buffer, ea_length) = match user_ea(request) {
        Ok(ea) => ea,
        Err(status) => return Ok(fail_iosb(iosb, status)),
    };
    debug_print!("[usermode] abre device relativo: {}{} (raiz {:#x})", device.device_path, name, device.file_object);
    let create = device_create_parameters(request, disposition, object_flags, None);
    let opened = match io_manager::open_related_device_file_with_ea(&device.device_path, name, device.file_object, create, ea_buffer, ea_length, true) {
        Ok(opened) => opened,
        Err(error) if error.status != 0 => return Ok(fail_iosb(iosb, error.status)),
        Err(error) => return Err(error),
    };
    publish_device(handle_pointer, iosb, device.device_path.clone(), request, object_flags, opened)
}

/// O IRP_MJ_CREATE de uma abertura de dispositivo de modo usuário:
/// acesso, compartilhamento, disposição, opções, atributos e o tipo de
/// criação do file system (`special`).
fn device_create_parameters(request: &OpenRequest, disposition: u32, object_flags: u32, special: Option<&pipe_mailslot::Captured>) -> io_manager::CreateParameters {
    io_manager::CreateParameters {
        access: request.access,
        share: request.share,
        disposition,
        options: request.options,
        file_attributes: request.attributes,
        case_sensitive: object_flags & 0x40 == 0,
        file_type: special.map_or(0, |captured| captured.file_type()),
        extra_parameters: special.map_or(0, |captured| captured.pointer()),
        user_mode: true,
        ..Default::default()
    }
}

/// O handle `device` de uma abertura de dispositivo concluída, na tabela
/// do processo, ou a falha do IRP_MJ_CREATE no IO_STATUS_BLOCK (um EA
/// inconsistente leva o deslocamento da entrada ruim no Information).
fn publish_device(handle_pointer: u64, iosb: u64, device_path: String, request: &OpenRequest, object_flags: u32, opened: io_manager::Opened) -> Result<u32, KernelError> {
    if opened.status != 0 {
        let status = if opened.status == io_manager::status::NOT_FOUND { 0xC000_0034 } else { opened.status as u32 };
        if status == crate::ntos::io::buffer_validation::STATUS_EA_LIST_INCONSISTENT {
            return Ok(if state::set_user_iosb(iosb, status, opened.information).is_err() { 0xC000_0005 } else { status });
        }
        return Ok(fail_iosb(iosb, status));
    }
    let information = if opened.information != 0 { opened.information } else { 1 };
    let object = Arc::new(UserDevice { device_path, options: request.options, device_handle: opened.handle, file_object: opened.file_object, position: crate::rtl::SpinLock::new(0) });
    let access = file_objects::access(request.access);
    match state::alloc_user_handle(object, access, object_flags & 2) {
        Ok(handle) => {
            if guest::try_write::<u64>(handle_pointer, handle as u64).is_err() {
                close::close_user(handle as u64, true);
                return Ok(0xC000_0005);
            }
            // O Information do IRP_MJ_CREATE (FILE_OPENED quando o driver
            // não informa).
            Ok(if state::set_user_iosb(iosb, 0, information).is_err() { 0xC000_0005 } else { 0 })
        }
        Err(error) => {
            let _ = io_manager::close_device(opened.handle);
            if error.status != 0 {
                Ok(fail_iosb(iosb, error.status))
            } else {
                Err(error)
            }
        }
    }
}

/// O DeviceType do DEVICE_OBJECT de `device_path` (0 sem um nativo).
fn device_type_of(device_path: &str) -> u32 {
    let (Some(node), None) = crate::ntos::ob::object_manager::resolve(device_path) else { return 0 };
    let Some(device) = io_manager::device(node).map(|entry| entry.native_device).filter(|&device| device != 0) else { return 0 };
    // SAFETY: DEVICE_OBJECT vivo do namespace.
    unsafe { crate::ntos::inc::types::DeviceObject::at(device) }.device_type.get()
}

/// Um nome dentro do dispositivo do volume de boot
/// (`\Device\KernelVolume1\...`): o IopParseDevice desse dispositivo é a
/// abertura no volume (`file_io`), como a por `C:`.
fn on_boot_volume_device(name: &str) -> bool {
    let device = crate::drivers::fs::volume_device::device_path(crate::drivers::fs::ntfs::DEVICE_INDEX);
    name.len() > device.len() + 1 && name[..device.len()].eq_ignore_ascii_case(&device) && name.as_bytes()[device.len()] == b'\\'
}

/// O ObOpenObjectByName de uma abertura de arquivo por nome: cada volta
/// abre `name` no dispositivo (o IopParseDevice) ou no volume de boot
/// (`file_io::create`); o STATUS_REPARSE de um reparse point no caminho dá
/// o nome novo (`io/reparse.rs`), que recomeça a busca, até as 0x40 voltas
/// do ObpLookupObjectName. `object_flags` são os OBJ_* da abertura.
#[allow(clippy::too_many_arguments)]
pub fn open_by_name(handle_pointer: u64, name: &str, object_flags: u32, iosb: u64, disposition: u32, request: &OpenRequest, special: Option<&pipe_mailslot::Captured>) -> Result<u32, KernelError> {
    let mut walk = crate::ntos::io::reparse::NameWalk::new(object_flags);
    let mut name = String::from(name);
    let mut options = request.options;
    loop {
        let request = &OpenRequest { options, ..request.clone() };
        // Um volume do kernel pelo nome do volume, sem nome restante
        // (`\??\C:`, o `\\.\C:` do Win32): o IopParseDevice abre o volume
        // inteiro (`io/parse.rs`), não a raiz (`\??\C:\`).
        if special.is_none() {
            if let Some(device) = crate::ntos::io::parse::kernel_volume_device(&name) {
                if let Err(status) = walk.arrive(crate::ntos::io::reparse::FILE_DEVICE_DISK) {
                    return Ok(fail_iosb(iosb, status));
                }
                return open_volume(handle_pointer, iosb, device, disposition, request, object_flags);
            }
        }
        let device_path = if on_boot_volume_device(&name) { None } else { device_path_of(&name) };
        if let Some((device_path, _)) = device_path.as_deref().and_then(io_manager::split_device_path) {
            if let Err(status) = walk.arrive(device_type_of(&device_path)) {
                return Ok(fail_iosb(iosb, status));
            }
            return open_device_name(handle_pointer, device_path_of(&name), object_flags, iosb, disposition, request, special);
        }
        if device_path.is_some() || special.is_some() {
            return open_device_name(handle_pointer, device_path, object_flags, iosb, disposition, request, special);
        }
        if let Err(status) = walk.arrive(crate::ntos::io::reparse::FILE_DEVICE_DISK) {
            return Ok(fail_iosb(iosb, status));
        }
        match file_io::create(handle_pointer, &name, iosb, disposition, &OpenRequest { handle_attributes: object_flags, ..request.clone() })? {
            file_io::Created::Done(status) => return Ok(status),
            file_io::Created::Reparse(found) => {
                let reparsed = match found.graft(&mut walk, &name).and_then(|reparsed| walk.restart(&reparsed.name).map(|()| reparsed)) {
                    Ok(reparsed) => reparsed,
                    Err(status) => return Ok(fail_iosb(iosb, status)),
                };
                debug_print!("[usermode] reparse 0x{:x}: {} -> {}", reparsed.tag, name, reparsed.name);
                options = reparsed.create_options(options);
                name = reparsed.name;
            }
        }
    }
}

/// A abertura de um nome de dispositivo (`device_path_of`): o dispositivo
/// e o resto do nome pelo I/O Manager, NOT_FOUND quando o dispositivo não
/// existe, e o pipe ou mailslot fora de um dispositivo.
#[allow(clippy::too_many_arguments)]
fn open_device_name(handle_pointer: u64, device_path: Option<String>, object_flags: u32, iosb: u64, disposition: u32, request: &OpenRequest, special: Option<&pipe_mailslot::Captured>) -> Result<u32, KernelError> {
    // O dispositivo e o resto do nome (um arquivo no sistema de arquivos do
    // dispositivo, como `\Device\NamedPipe\ProtectedPrefix`), com o
    // IRP_MJ_CREATE completo: acesso, compartilhamento, disposição e opções.
    if let Some((device_path, rest)) = device_path.as_deref().and_then(io_manager::split_device_path) {
        debug_print!("[usermode] abre device: {}{}", device_path, rest);
        // O EA vai só no IRP_MJ_CREATE de arquivo (o dos pipes e mailslots
        // leva os parâmetros do file system no lugar do EaLength).
        let (ea_buffer, ea_length) = if special.is_none() {
            match user_ea(request) {
                Ok(ea) => ea,
                Err(status) => return Ok(fail_iosb(iosb, status)),
            }
        } else {
            (0, 0)
        };
        let create = device_create_parameters(request, disposition, object_flags, special);
        let opened = match io_manager::open_related_device_file_with_ea(&device_path, &rest, 0, create, ea_buffer, ea_length, true) {
            Ok(opened) => opened,
            Err(error) if error.status != 0 => return Ok(fail_iosb(iosb, error.status)),
            Err(error) => return Err(error),
        };
        return publish_device(handle_pointer, iosb, device_path, request, object_flags, opened);
    }
    if let Some(device_path) = device_path {
        // Dispositivo que ainda não existe: NOT_FOUND real; o processo repete.
        debug_print!("[usermode] device NAO EXISTE: {}", device_path);
        return Ok(fail_iosb(iosb, 0xC000_0034));
    }
    // Pipe ou mailslot fora de um file system de dispositivo: o
    // IRP_MJ_CREATE_NAMED_PIPE/CREATE_MAILSLOT não tem quem o atenda.
    Ok(fail_iosb(iosb, 0xC000_0010))
}

/// A abertura de modo usuário do volume inteiro de um volume do kernel
/// (`io/parse.rs::open_volume`): as recusas de parâmetros do IopCreateFile
/// (opções fora de FILE_VALID_OPTION_FLAGS também), o IopParseDevice e o
/// handle `device` com o FILE_OBJECT aberto (FO_DIRECT_DEVICE_OPEN ou
/// FO_VOLUME_OPEN) e o acesso concedido pelo SeAccessCheck do dispositivo.
/// Os IOCTLs, FSCTLs e consultas de volume do handle vão por IRP ao
/// dispositivo relacionado (`io/file/irp_service.rs`).
fn open_volume(handle_pointer: u64, iosb: u64, device: u64, disposition: u32, request: &OpenRequest, object_flags: u32) -> Result<u32, KernelError> {
    if request.options & !0x00FF_FFFF != 0 {
        return Ok(fail_iosb(iosb, STATUS_INVALID_PARAMETER));
    }
    if let Err(status) = file_io::validate_create(disposition, request) {
        return Ok(fail_iosb(iosb, status));
    }
    let volume_request = crate::ntos::io::parse::OpenRequest {
        desired_access: request.access,
        file_attributes: request.attributes,
        share_access: request.share,
        disposition,
        create_options: request.options,
        case_insensitive: object_flags & 0x40 != 0,
        driver_context: crate::ntos::io::parse::DriverCreateContext::default(),
    };
    let (opened, granted) = match crate::ntos::io::parse::open_volume(device, &volume_request) {
        Ok(result) => result,
        Err(error) if error.status != 0 => return Ok(fail_iosb(iosb, error.status)),
        Err(error) => return Err(error),
    };
    if opened.status & 0x8000_0000 != 0 || opened.file_object == 0 {
        return Ok(fail_iosb(iosb, if opened.status & 0x8000_0000 != 0 { opened.status } else { 0xC000_0001 }));
    }
    // O provedor de usuário é dono de cada handle publicado; a descrição
    // retém só a referência do CREATE (solta no `release`).
    if let Err(error) = file_objects::mark_opened(opened.file_object) {
        let _ = file_objects::dereference(opened.file_object);
        return Err(error);
    }
    let device_path = crate::drivers::fs::volume_device::real_device_path(device).unwrap_or_default();
    debug_print!("[usermode] abre volume: {} (acesso 0x{:x}, {})", device_path, granted, if crate::ntos::io::parse::is_volume_open(granted) { "pelo file system" } else { "direto no dispositivo" });
    let object = Arc::new(UserDevice { device_path, options: request.options, device_handle: 0, file_object: opened.file_object, position: crate::rtl::SpinLock::new(0) });
    match state::alloc_user_handle(object, granted, object_flags & 2) {
        Ok(handle) => {
            if guest::try_write::<u64>(handle_pointer, handle as u64).is_err() {
                close::close_user(handle as u64, true);
                return Ok(0xC000_0005);
            }
            let information = if opened.information != 0 { opened.information } else { 1 };
            Ok(if state::set_user_iosb(iosb, 0, information).is_err() { 0xC000_0005 } else { 0 })
        }
        Err(error) => {
            let _ = file_objects::dereference(opened.file_object);
            if error.status != 0 {
                Ok(fail_iosb(iosb, error.status))
            } else {
                Err(error)
            }
        }
    }
}

/// NtOpenFile(handle*, access, oa, ioStatus*, share, options).
fn nt_open_file(handle_pointer: u64, access: u64, attributes: u64, iosb: u64, rsp: u64) -> Result<u32, KernelError> {
    open_nt_file(handle_pointer, attributes, iosb, 1, &OpenRequest { access: access as u32, share: state::stack_arg32(rsp, 5), options: state::stack_arg32(rsp, 6), ..OpenRequest::default() })
}

/// NtDeleteFile(ObjectAttributes) de modo usuário (ntoskrnl 19041,
/// 0x77ca70): o ObOpenObjectByNameEx com o OPEN_PACKET DeleteOnly do
/// IopParseDevice, DesiredAccess DELETE, FILE_DELETE_ON_CLOSE, ShareAccess 7
/// e FILE_OPEN, cujo FILE_OBJECT é fechado logo (o file system retira o nome
/// no fechamento); o status é o da abertura. O NT não cria handle; aqui a
/// abertura de modo usuário pede uma página de rascunho do processo para o
/// handle e o IO_STATUS_BLOCK, solta antes da volta.
fn nt_delete_file(attributes: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    const DELETE: u32 = 0x1_0000;
    const FILE_DELETE_ON_CLOSE: u32 = 0x1000;
    const FILE_SHARE_ALL: u32 = 7;
    const FILE_OPEN: u32 = 1;
    let Ok(scratch) = super::memory::map_user_region(0x1000) else { return Ok(0xC000_009A) };
    let status = open_file(scratch, attributes, scratch + 0x10, FILE_OPEN, &OpenRequest { access: DELETE, share: FILE_SHARE_ALL, options: FILE_DELETE_ON_CLOSE, ..OpenRequest::default() }, None);
    if matches!(status, Ok(status) if status & 0x8000_0000 == 0) {
        // O fechamento do NtClose: a tabela de usuário, senão a nativa.
        let handle = guest::read64(scratch);
        if close::close_user(handle, false) == STATUS_INVALID_HANDLE {
            let _ = close::close(handle, Some(1));
        }
    }
    if let Some(region) = super::memory::find_region(scratch) {
        super::memory::release_private_region(&region);
    }
    status
}

/// NtCreateFile(handle*, access, oa, ioStatus*, allocSize*, fileAttrs, share,
/// disposition, options, ea*, eaLength).
fn nt_create_file(handle_pointer: u64, access: u64, attributes: u64, iosb: u64, rsp: u64) -> Result<u32, KernelError> {
    let disposition = state::stack_arg32(rsp, 8);
    open_nt_file(
        handle_pointer,
        attributes,
        iosb,
        disposition,
        &OpenRequest { access: access as u32, allocation_pointer: state::stack_arg(rsp, 5), attributes: state::stack_arg32(rsp, 6), share: state::stack_arg32(rsp, 7), options: state::stack_arg32(rsp, 9), ea_buffer: state::stack_arg(rsp, 10), ea_length: state::stack_arg32(rsp, 11), handle_attributes: 0, explicit: None },
    )
}

/// NtCreateNamedPipeFile(handle*, access, oa, ioStatus*, share, disposition,
/// options, pipeType, readMode, completionMode, maxInstances, inboundQuota,
/// outboundQuota, defaultTimeout*).
fn nt_create_named_pipe_file(handle_pointer: u64, access: u64, attributes: u64, iosb: u64, rsp: u64) -> Result<u32, KernelError> {
    let create = pipe_mailslot::CreateArguments { desired_access: access as u32, share_access: state::stack_arg32(rsp, 5), disposition: state::stack_arg32(rsp, 6), create_options: state::stack_arg32(rsp, 7) };
    let pipe = pipe_mailslot::NamedPipeArguments {
        named_pipe_type: state::stack_arg32(rsp, 8),
        read_mode: state::stack_arg32(rsp, 9),
        completion_mode: state::stack_arg32(rsp, 10),
        maximum_instances: state::stack_arg32(rsp, 11),
        inbound_quota: state::stack_arg32(rsp, 12),
        outbound_quota: state::stack_arg32(rsp, 13),
        default_timeout: state::stack_arg(rsp, 14),
    };
    let captured = match pipe_mailslot::capture_named_pipe(&create, &pipe) {
        Ok(captured) => captured,
        Err(status) => return Ok(status),
    };
    open_file(handle_pointer, attributes, iosb, create.disposition, &OpenRequest { access: create.desired_access, share: create.share_access, options: create.create_options, ..OpenRequest::default() }, Some(&captured))
}

/// NtCreateMailslotFile(handle*, access, oa, ioStatus*, options, quota,
/// maxMessageSize, readTimeout*).
fn nt_create_mailslot_file(handle_pointer: u64, access: u64, attributes: u64, iosb: u64, rsp: u64) -> Result<u32, KernelError> {
    let mailslot = pipe_mailslot::MailslotArguments { create_options: state::stack_arg32(rsp, 5), mailslot_quota: state::stack_arg32(rsp, 6), maximum_message_size: state::stack_arg32(rsp, 7), read_timeout: state::stack_arg(rsp, 8) };
    let create = pipe_mailslot::mailslot_create_arguments(access as u32, &mailslot);
    let captured = match pipe_mailslot::capture_mailslot(&create, &mailslot) {
        Ok(captured) => captured,
        Err(status) => return Ok(status),
    };
    open_file(handle_pointer, attributes, iosb, create.disposition, &OpenRequest { access: create.desired_access, share: create.share_access, options: create.create_options, ..OpenRequest::default() }, Some(&captured))
}

/// NtFsControlFile(handle, event, apcRoutine, apcContext, ioStatus*, code,
/// input*, inputLength, output*, outputLength): o IRP_MJ_FILE_SYSTEM_CONTROL
/// do I/O Manager (`io/file/irp_service.rs`) ao driver do arquivo.
fn nt_fs_control_file(handle: u64, event: u64, apc_routine: u64, apc_context: u64, rsp: u64) -> Result<u32, KernelError> {
    // Um arquivo do volume de boot: o FSCTL vai ao NTFS do kernel (`file_io`).
    if state::get_user_handle(handle).is_some_and(|entry| entry.kind() == "file") {
        return file_io::fs_control(handle, event, apc_routine, rsp);
    }
    if state::get_user_handle(handle).is_some_and(|entry| entry.kind() != "device") {
        return Ok(0xC000_0010);
    }
    Ok(irp_service::fs_control(&irp_service::Control {
        handle,
        event,
        apc_routine,
        apc_context,
        io_status: state::stack_arg(rsp, 5),
        code: state::stack_arg32(rsp, 6),
        input: state::stack_arg(rsp, 7),
        input_length: state::stack_arg32(rsp, 8),
        output: state::stack_arg(rsp, 9),
        output_length: state::stack_arg32(rsp, 10),
    }))
}

/// NtDeviceIoControlFile: IRP gerenciado (resultado copiado para a saída)
/// ou, num driver nativo, o FastIoDeviceControl e depois o IRP: METHOD_BUFFERED
/// e METHOD_NEITHER sem evento na pilha; METHOD_IN_DIRECT, METHOD_OUT_DIRECT
/// e os pedidos com evento pelo IopXxxControlFile de `io/file/irp_service.rs`
/// (MDL das páginas de usuário, conclusão assíncrona e porta do arquivo).
fn nt_device_io_control_file(handle: u64, event: u64, apc: u64, context: u64, rsp: u64) -> Result<u32, KernelError> {
    let Some(entry) = state::get_user_handle(handle).filter(|entry| entry.kind() == "device") else { return Ok(STATUS_INVALID_HANDLE) };
    let Some(device) = entry.downcast::<UserDevice>() else { return Ok(STATUS_INVALID_HANDLE) };
    let iosb = state::stack_arg(rsp, 5);
    let code = state::stack_arg32(rsp, 6);
    let input = state::stack_arg(rsp, 7);
    let input_length = state::stack_arg32(rsp, 8);
    let output = state::stack_arg(rsp, 9);
    let output_length = state::stack_arg32(rsp, 10);
    // Uma abertura do IopParseDevice (o volume inteiro) ou do
    // ObOpenObjectByPointer de um FILE_OBJECT (o servidor do console que o
    // condrv.sys põe no conhost.exe), sem handle do I/O manager: o
    // IopXxxControlFile completo, com o acesso que o código pede
    // (FILE_READ_ACCESS/FILE_WRITE_ACCESS contra o do handle), o dispositivo
    // relacionado do FILE_OBJECT e o FastIoDeviceControl do driver antes do
    // IRP (o CdpServerFastIoctl do condrv atende os IOCTLs do servidor).
    if device.device_handle == 0 {
        return Ok(irp_service::device_control(&irp_service::Control { handle, event, apc_routine: apc, apc_context: context, io_status: iosb, code, input, input_length, output, output_length }, true));
    }
    if apc != 0 {
        return Ok(0xC000_00BB);
    }
    if !state::probe_user_write(iosb, 16) || !state::probe_user_read(input, input_length as u64) || !state::probe_user_write(output, output_length as u64) {
        return Ok(0xC000_0005);
    }
    if input_length > 1_048_576 || output_length > 1_048_576 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let Some((managed, top)) = io_manager::device_route(&device.device_path) else { return Ok(STATUS_INVALID_HANDLE) };
    if managed {
        let completion = if event != 0 { state::get_user_handle(event) } else { None };
        if event != 0 && completion.as_ref().is_none_or(|completion| completion.kind() != "event") {
            return Ok(STATUS_INVALID_HANDLE);
        }
        let Ok(data) = guest::try_read_bytes(input, input_length as usize) else { return Ok(0xC000_0005) };
        let mut request = io_manager::make_io_request(0x0E, IoParams { control_code: code, data: Some(data), binary: true, output_length: Some(output_length), ..IoParams::default() });
        request.file_object = device.file_object;
        io_manager::call_driver(&device.device_path, &mut request)?;
        let status = request.status as u32;
        let result = match &request.result {
            IoResult::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        };
        if request.info > output_length as u64 || (request.info != 0 && result.as_ref().is_none_or(|bytes| (bytes.len() as u64) < request.info)) {
            return Ok(0xC000_0001);
        }
        if status >> 30 != 3 && request.info != 0 {
            if let Some(bytes) = &result {
                state::write_user_bytes(output, &bytes[..request.info as usize])?;
            }
        }
        if state::set_user_iosb(iosb, status, request.info).is_err() {
            return Ok(0xC000_0005);
        }
        if let Some(body) = completion.and_then(|completion| completion.object.native_body()) {
            dispatcher::set_event(body.pointer);
        }
        return Ok(status);
    }
    // O evento do pedido (EVENT_MODIFY_STATE), zerado antes da operação.
    let event_object = if event != 0 {
        match super::events::reference(event, 2) {
            Ok(object) => {
                dispatcher::reset_event(object.pointer);
                Some(object)
            }
            Err(status) => return Ok(status),
        }
    } else {
        None
    };
    // O FastIoDeviceControl do driver antes de qualquer IRP, como o
    // IopXxxControlFile: atendido, o IoStatus vai ao IOSB e o evento é
    // sinalizado.
    let fast = device_control::fast_device_control(device.file_object, top, input, input_length, output, output_length, code);
    if let FastControl::Handled { status, information } = fast {
        let _ = state::set_user_iosb(iosb, status, information);
        if let Some(object) = &event_object {
            dispatcher::set_event(object.pointer);
        }
    }
    if let Some(object) = &event_object {
        super::events::release(object);
    }
    match fast {
        FastControl::NoMemory => return Ok(0xC000_009A),
        FastControl::Handled { status, .. } => return Ok(status),
        FastControl::NotHandled => {}
    }
    // Direct I/O (o MDL das páginas travadas) e o evento do pedido: o
    // IopXxxControlFile completo. O lsass.exe deixa assim pendente no
    // \Device\KsecDD o pedido METHOD_OUT_DIRECT 0x39006a, concluído na
    // porta de conclusão do arquivo.
    if code & 3 == 1 || code & 3 == 2 || event != 0 {
        return Ok(irp_service::device_control(&irp_service::Control { handle, event, apc_routine: apc, apc_context: context, io_status: iosb, code, input, input_length, output, output_length }, false));
    }
    let packet = io_manager::build_device_io_control_request(code, top, input, input_length, output, output_length, 0, 0, iosb, Some(RequestContext { file_object: device.file_object, requestor_mode: 1, thread: process::get_current_thread() }));
    if packet == 0 {
        return Ok(0xC000_009A);
    }
    // O IOSB fica STATUS_PENDING até a conclusão copiar o IoStatus para ele:
    // um driver que conclui e devolve STATUS_PENDING (IoStartPacket) vale
    // pelo IoStatus; sem conclusão, vale o retorno do despacho.
    let _ = state::set_user_iosb(iosb, 0x103, 0);
    let guest_status = io_manager::iof_call_driver(top, packet) as u32;
    let mut status = match state::user_struct::<IoStatusBlock>(iosb).and_then(|block| block.status.probe_get()) {
        Ok(value) => value as u32,
        Err(error) => error.status,
    };
    if status == 0x103 && guest_status != 0x103 {
        status = guest_status;
        if state::set_user_iosb(iosb, status, 0).is_err() {
            status = 0xC000_0005;
        }
    }
    if guest_status != 0x103 {
        guest::free_bytes(packet);
    }
    Ok(status)
}

/// NtClose: o objeto sai da tabela e do kernel.
fn nt_close(handle: u64, force: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    let status = close::close_user(handle, force == 1);
    if status != STATUS_INVALID_HANDLE {
        return Ok(status);
    }
    // Os handles nativos do processo (diretórios e links do namespace,
    // objetos abertos por ponteiro) ficam fora da tabela de usuário.
    close::close(handle, Some(1))
}

/// NtCreateSection(handle*, access, oa?, maxSize*, pageProt, secProt, file).
fn nt_create_section(handle_pointer: u64, access: u64, attributes: u64, size_pointer: u64, rsp: u64) -> Result<u32, KernelError> {
    create_section::create(handle_pointer, access as u32, attributes, size_pointer, state::stack_arg32(rsp, 5), state::stack_arg32(rsp, 6), state::stack_arg(rsp, 7), 1, None)
}

/// NtCreateSectionEx(handle*, access, oa?, maxSize*, pageProt, secProt,
/// file, ExtendedParameters, ExtendedParameterCount).
fn nt_create_section_ex(handle_pointer: u64, access: u64, attributes: u64, size_pointer: u64, rsp: u64) -> Result<u32, KernelError> {
    create_section::create_ex(handle_pointer, access as u32, attributes, size_pointer, state::stack_arg32(rsp, 5), state::stack_arg32(rsp, 6), state::stack_arg(rsp, 7), state::stack_arg(rsp, 8), state::stack_arg32(rsp, 9), 1)
}

/// NtExtendSection(SectionHandle, NewSectionSize*): `mm/section/extend`.
fn nt_extend_section(section: u64, size_pointer: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    crate::ntos::mm::section::extend::nt_extend_section(section, size_pointer, 1)
}

fn nt_open_section(handle_pointer: u64, access: u64, attributes: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    open_section::open(handle_pointer, access as u32, attributes, 1)
}

/// NtMapViewOfSection(section, process, base*, zeroBits, commit, offset*,
/// viewSize*, inherit, allocType, protect).
fn nt_map_view_of_section(section: u64, process_handle: u64, base_pointer: u64, zero_bits: u64, rsp: u64) -> Result<u32, KernelError> {
    map_view::map(section, process_handle, base_pointer, zero_bits, state::stack_arg(rsp, 5), state::stack_arg(rsp, 6), state::stack_arg(rsp, 7), state::stack_arg32(rsp, 8), state::stack_arg32(rsp, 9), state::stack_arg32(rsp, 10), 1)
}

/// NtMapViewOfSectionEx(section, process, base*, offset*, viewSize*,
/// allocType, protect, ExtendedParameters, ExtendedParameterCount).
fn nt_map_view_of_section_ex(section: u64, process_handle: u64, base_pointer: u64, offset_pointer: u64, rsp: u64) -> Result<u32, KernelError> {
    map_view::map_ex(section, process_handle, base_pointer, offset_pointer, state::stack_arg(rsp, 5), state::stack_arg32(rsp, 6), state::stack_arg32(rsp, 7), state::stack_arg(rsp, 8), state::stack_arg32(rsp, 9), 1)
}

fn nt_unmap_view_of_section(process_handle: u64, base: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    unmap_view::unmap(process_handle, base, 1)
}

/// NtUnmapViewOfSectionEx(process, base, Flags): MEM_UNMAP_WITH_TRANSIENT_BOOST
/// e MEM_PRESERVE_PLACEHOLDER como o MiUnmapViewOfSection
/// (`mm/section/unmap_view.rs`).
fn nt_unmap_view_of_section_ex(process_handle: u64, base: u64, flags: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    unmap_view::unmap_ex(process_handle, base, 1, flags as u32)
}

/// NtQuerySection(SectionBasicInformation) de um handle `section` do processo.
fn nt_query_section(handle: u64, class: u64, out: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    let Some(entry) = state::get_user_handle(handle).filter(|entry| entry.kind() == "section") else { return Ok(STATUS_INVALID_HANDLE) };
    let Some(section) = entry.object.section() else { return Ok(STATUS_INVALID_HANDLE) };
    if section.is_image || class != 0 {
        return Ok(0xC000_0003);
    }
    if entry.access() & 1 == 0 {
        return Ok(0xC000_0022);
    }
    let returned = state::stack_arg(rsp, 5);
    if returned != 0 && !state::probe_user_write(returned, 8) {
        return Ok(0xC000_0005);
    }
    state::guarded(|| {
        // SIZE_T *ReturnLength.
        if returned != 0 {
            guest::try_write::<u64>(returned, SectionBasicInformation::SIZE)?;
        }
        if length < SectionBasicInformation::SIZE {
            return Ok(0xC000_0004);
        }
        if !state::probe_user_write(out, SectionBasicInformation::SIZE) {
            return Ok(0xC000_0005);
        }
        guest::try_write_bytes(out, &[0; SectionBasicInformation::SIZE as usize])?;
        let information = state::user_struct::<SectionBasicInformation>(out)?;
        information.allocation_attributes.probe_set(section.attributes)?;
        information.maximum_size.quad_part.probe_set(section.maximum_size() as i64)?;
        Ok(0)
    })
}

/// Fim do processo `process` (EPROCESS): a rotina de saída de processo do
/// término (`ps::process::terminate_process`), chamada depois da saída das
/// threads nativas e das notificações e antes do rundown de handles e do
/// VAD. Libera o que o processo possui, e só o dele: as requisições de
/// `device_io`, as fábricas de workers, a cópia do callback de
/// instrumentação, os mutantes e as threads de usuário, os canais de
/// `cm::service::rpc` e os picos de `system_process_information`, nesta
/// ordem. Os handles, o VAD e os módulos do loader saem logo depois, em
/// `process_state::destroy`. Nada é reiniciado entre processos: um processo
/// vivo não perde nada quando outro termina.
pub fn release_user_resources(process: u64) {
    // SAFETY: o EPROCESS em término, retido pelo próprio término.
    let process_id = unsafe { Eprocess::at(process) }.unique_process_id.get();
    super::device_io::release_process(process_id);
    super::worker_factory::release_process(process_id);
    super::instrumentation::release_process(process);
    super::mutants::release_process(process);
    super::threads::release_process(process);
    crate::ntos::cm::service::rpc::release_process(process_id);
    crate::ntos::ps::system_process_information::release_process(process_id);
}

/// Registra os handlers de arquivos, dispositivos e seções, e a liberação
/// por processo no término.
pub fn init() {
    process::register_process_exit_routine(release_user_resources);
    state::register_handler("NtOpenFile", nt_open_file);
    state::register_handler("NtDeleteFile", nt_delete_file);
    state::register_handler("NtCreateFile", nt_create_file);
    state::register_handler("NtDeviceIoControlFile", nt_device_io_control_file);
    state::register_handler("NtCreateNamedPipeFile", nt_create_named_pipe_file);
    state::register_handler("NtCreateMailslotFile", nt_create_mailslot_file);
    state::register_handler("NtFsControlFile", nt_fs_control_file);
    state::register_handler("NtClose", nt_close);
    state::register_handler("NtCreateSection", nt_create_section);
    state::register_handler("NtCreateSectionEx", nt_create_section_ex);
    state::register_handler("NtExtendSection", nt_extend_section);
    state::register_handler("NtMapViewOfSectionEx", nt_map_view_of_section_ex);
    state::register_handler("NtOpenSection", nt_open_section);
    state::register_handler("NtMapViewOfSection", nt_map_view_of_section);
    state::register_handler("NtUnmapViewOfSection", nt_unmap_view_of_section);
    state::register_handler("NtUnmapViewOfSectionEx", nt_unmap_view_of_section_ex);
    state::register_handler("NtQuerySection", nt_query_section);
}
