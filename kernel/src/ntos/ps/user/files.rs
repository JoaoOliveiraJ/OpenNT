//! Arquivos, dispositivos e seções de modo usuário.
//!
//! NtOpenFile/NtCreateFile abrem um arquivo do volume (pelo `file_io`) ou um
//! dispositivo do NT (`\Device\X`, `\DosDevices\X`, `\GLOBAL??\X`, `\\.\X`,
//! `\??\X`): o dispositivo vai ao I/O manager de verdade e o IRP_MJ_CREATE
//! chega ao driver. Também NtDeviceIoControlFile (driver gerenciado ou pilha
//! nativa), NtClose e as syscalls de seção sobre os serviços do Mm.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use super::file_io::{self, OpenRequest};
use super::registry::{parse_user_object_attributes, user_object_attributes};
use super::state::{self, NativeBody, UserObject, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER};
use crate::ntos::io::io_manager::{self, IoParams, IoResult, RequestContext};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::section::{create as create_section, map_view, open as open_section, unmap_view};
use crate::ntos::ob::{close, object_manager, object_types};
use crate::ntos::ob::objects::file as file_objects;
use crate::ntos::ps::process;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{IoStatusBlock, NtStruct, SectionBasicInformation};

/// Handle `device` do processo: o caminho, o handle do I/O manager e o
/// FILE_OBJECT aberto pelo IRP_MJ_CREATE.
pub struct UserDevice {
    pub device_path: String,
    pub options: u32,
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
    /// Liberação do objeto: fecha o handle do I/O manager.
    fn release(&self) {
        let _ = io_manager::close_device(self.device_handle);
    }
    fn as_any(&self) -> &dyn Any {
        self
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
    if !state::probe_user_write(handle_pointer, 8) || !state::probe_user_write(iosb, 16) || !state::probe_user_read(attributes, 48) {
        return Ok(0xC000_0005);
    }
    let Some(parsed) = parse_user_object_attributes(attributes) else { return Ok(STATUS_INVALID_PARAMETER) };
    // OBJ_* do OA, lido uma vez.
    let object_flags = match user_object_attributes(attributes) {
        Ok(flags) => flags,
        Err(error) => return Ok(error.status),
    };
    let device_path = device_path_of(&parsed.path);
    if let Some(device_path) = device_path.as_ref().filter(|path| object_manager::lookup(path).is_some()) {
        debug_print!("[usermode] abre device: {}", device_path);
        let opened = match io_manager::open_device(device_path, true) {
            Ok(opened) => opened,
            Err(error) if error.status != 0 => return Ok(fail_iosb(iosb, error.status)),
            Err(error) => return Err(error),
        };
        if opened.status != 0 {
            return Ok(fail_iosb(iosb, opened.status as u32));
        }
        let object = Arc::new(UserDevice { device_path: device_path.clone(), options: request.options, device_handle: opened.handle, file_object: opened.file_object, position: crate::rtl::SpinLock::new(0) });
        let access = file_objects::access(request.access);
        return match state::alloc_user_handle(object, access, object_flags & 2) {
            Ok(handle) => {
                if guest::try_write::<u64>(handle_pointer, handle as u64).is_err() {
                    close::close_user(handle as u64, true);
                    return Ok(0xC000_0005);
                }
                // FILE_OPENED.
                Ok(if state::set_user_iosb(iosb, 0, 1).is_err() { 0xC000_0005 } else { 0 })
            }
            Err(error) => {
                let _ = io_manager::close_device(opened.handle);
                if error.status != 0 {
                    Ok(fail_iosb(iosb, error.status))
                } else {
                    Err(error)
                }
            }
        };
    }
    if let Some(device_path) = device_path {
        // Dispositivo que ainda não existe: NOT_FOUND real; o processo repete.
        debug_print!("[usermode] device NAO EXISTE: {}", device_path);
        return Ok(fail_iosb(iosb, 0xC000_0034));
    }
    file_io::open(handle_pointer, &parsed.path, iosb, disposition, &OpenRequest { handle_attributes: object_flags, ..*request })
}

/// NtOpenFile(handle*, access, oa, ioStatus*, share, options).
fn nt_open_file(handle_pointer: u64, access: u64, attributes: u64, iosb: u64, rsp: u64) -> Result<u32, KernelError> {
    open_nt_file(handle_pointer, attributes, iosb, 1, &OpenRequest { access: access as u32, share: state::stack_arg32(rsp, 5), options: state::stack_arg32(rsp, 6), ..OpenRequest::default() })
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
        &OpenRequest { access: access as u32, allocation_pointer: state::stack_arg(rsp, 5), attributes: state::stack_arg32(rsp, 6), share: state::stack_arg32(rsp, 7), options: state::stack_arg32(rsp, 9), ea_length: state::stack_arg32(rsp, 11), handle_attributes: 0 },
    )
}

/// NtDeviceIoControlFile: IRP gerenciado (resultado copiado para a saída)
/// ou IRP nativo METHOD_BUFFERED/NEITHER na pilha (Direct I/O e eventos
/// assíncronos nativos ainda recusados).
fn nt_device_io_control_file(handle: u64, event: u64, apc: u64, _context: u64, rsp: u64) -> Result<u32, KernelError> {
    let Some(entry) = state::get_user_handle(handle).filter(|entry| entry.kind() == "device") else { return Ok(STATUS_INVALID_HANDLE) };
    let Some(device) = entry.downcast::<UserDevice>() else { return Ok(STATUS_INVALID_HANDLE) };
    let iosb = state::stack_arg(rsp, 5);
    let code = state::stack_arg32(rsp, 6);
    let input = state::stack_arg(rsp, 7);
    let input_length = state::stack_arg32(rsp, 8);
    let output = state::stack_arg(rsp, 9);
    let output_length = state::stack_arg32(rsp, 10);
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
    // Direct I/O exige MDLs fixadas: nunca descrito como METHOD_BUFFERED.
    if code & 3 == 1 || code & 3 == 2 {
        return Ok(0xC000_00BB);
    }
    if event != 0 {
        return Ok(0xC000_00BB);
    }
    let packet = io_manager::build_device_io_control_request(code, top, input, input_length, output, output_length, 0, 0, iosb, Some(RequestContext { file_object: device.file_object, requestor_mode: 1, thread: process::get_current_thread() }));
    if packet == 0 {
        return Ok(0xC000_009A);
    }
    let guest_status = io_manager::iof_call_driver(top, packet) as u32;
    // A conclusão já copiou o IoStatus para o IOSB do usuário; o retorno do
    // dispatch vale quando o IoStatus ficou zerado.
    let mut status = match state::user_struct::<IoStatusBlock>(iosb).and_then(|block| block.status.probe_get()) {
        Ok(value) => value as u32,
        Err(error) => error.status,
    };
    if status == 0 && guest_status != 0 {
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
    Ok(close::close_user(handle, force == 1))
}

/// NtCreateSection(handle*, access, oa?, maxSize*, pageProt, secProt, file).
fn nt_create_section(handle_pointer: u64, access: u64, attributes: u64, size_pointer: u64, rsp: u64) -> Result<u32, KernelError> {
    create_section::create(handle_pointer, access as u32, attributes, size_pointer, state::stack_arg32(rsp, 5), state::stack_arg32(rsp, 6), state::stack_arg(rsp, 7), 1, None)
}

fn nt_open_section(handle_pointer: u64, access: u64, attributes: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    open_section::open(handle_pointer, access as u32, attributes, 1)
}

/// NtMapViewOfSection(section, process, base*, zeroBits, commit, offset*,
/// viewSize*, inherit, allocType, protect).
fn nt_map_view_of_section(section: u64, process_handle: u64, base_pointer: u64, zero_bits: u64, rsp: u64) -> Result<u32, KernelError> {
    map_view::map(section, process_handle, base_pointer, zero_bits, state::stack_arg(rsp, 5), state::stack_arg(rsp, 6), state::stack_arg(rsp, 7), state::stack_arg32(rsp, 8), state::stack_arg32(rsp, 9), state::stack_arg32(rsp, 10), 1)
}

fn nt_unmap_view_of_section(process_handle: u64, base: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    unmap_view::unmap(process_handle, base, 1)
}

/// MEM_PRESERVE_PLACEHOLDER exige VADs de placeholder.
fn nt_unmap_view_of_section_ex(process_handle: u64, base: u64, flags: u64, _a4: u64, rsp: u64) -> Result<u32, KernelError> {
    if flags != 0 {
        return Ok(0xC000_00BB);
    }
    nt_unmap_view_of_section(process_handle, base, 0, 0, rsp)
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
        information.maximum_size.quad_part.probe_set(section.maximum_size as i64)?;
        Ok(0)
    })
}

/// Fim do processo de usuário: desmonta as vistas de seção e de imagem e
/// libera as regiões privadas. As liberações de `device_io`,
/// `worker_factory`, instrumentação, mutantes, threads, win32k,
/// `cm::service::rpc` e `system_process_information`, nesta ordem. Os
/// handles não passam por aqui: a tabela é do processo e o término dele a
/// esvazia (`process_state::destroy`).
pub fn release_user_resources() {
    super::device_io::release_process(state::with(|state| state.current_process_id));
    super::worker_factory::release_process();
    super::instrumentation::release_process();
    super::mutants::release_process();
    super::threads::release_process();
    crate::ntos::cm::service::rpc::release_process(state::with(|state| state.current_process_id));
    crate::ntos::ps::system_process_information::release_process(state::with(|state| state.current_process_id));
    let regions = state::with(|state| state.user_regions.clone());
    for region in regions {
        if region.section().is_some() {
            if let Some(view) = crate::ntos::ps::user::sections::views().into_iter().find(|view| {
                let candidate: state::Region = view.clone();
                state::same_region(&candidate, &region)
            }) {
                let _ = crate::ntos::ps::user::sections::unmap(&view, None);
            }
        }
    }
    let images: Vec<crate::ntos::mm::section::views::OwnedView> = crate::ntos::mm::section::views::all().into_iter().filter(|view| matches!(view, crate::ntos::mm::section::views::OwnedView::Image(image) if image.section.is_some() && state::with(|state| state.process_images.iter().any(|region| region.base() == image.base)))).collect();
    for image in images {
        if let crate::ntos::mm::section::views::OwnedView::Image(view) = &image {
            *view.regions.lock() = Some(state::RegionKind::ProcessImages);
        }
        let _ = crate::ntos::mm::section::views::unmap(&image);
    }
    super::memory::release_private_regions();
}

/// Registra os handlers de arquivos, dispositivos e seções.
pub fn init() {
    state::register_handler("NtOpenFile", nt_open_file);
    state::register_handler("NtCreateFile", nt_create_file);
    state::register_handler("NtDeviceIoControlFile", nt_device_io_control_file);
    state::register_handler("NtClose", nt_close);
    state::register_handler("NtCreateSection", nt_create_section);
    state::register_handler("NtOpenSection", nt_open_section);
    state::register_handler("NtMapViewOfSection", nt_map_view_of_section);
    state::register_handler("NtUnmapViewOfSection", nt_unmap_view_of_section);
    state::register_handler("NtUnmapViewOfSectionEx", nt_unmap_view_of_section_ex);
    state::register_handler("NtQuerySection", nt_query_section);
}
