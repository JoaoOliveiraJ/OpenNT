//! Abertura de um arquivo de volume pelo dispositivo: o ramo de arquivo do
//! IopParseDevice (RVA 0x6ab6a0 no ntoskrnl 19041).
//!
//! Um nome `\Device\<volume>\<resto>` cujo prefixo é um DEVICE_OBJECT com VPB
//! é aberto como no NT: `file_system::check_vpb_mounted` (IopCheckVpbMounted)
//! devolve o VPB montado, montando o volume pelo IopMountVolume se preciso; o
//! FILE_OBJECT nasce com DeviceObject = o dispositivo real, Vpb = o VPB,
//! FileName = o nome restante e as flags das opções de criação; o
//! IRP_MJ_CREATE (IRP_CREATE_OPERATION | IRP_SYNCHRONOUS_API) vai ao topo da
//! pilha do dispositivo de volume do file system, com o IO_SECURITY_CONTEXT
//! (o ACCESS_STATE do SeCreateAccessState com o mapeamento genérico de
//! arquivo), Options = (Disposition << 24) | CreateOptions, atributos e
//! compartilhamento. O file system preenche FsContext, a
//! SECTION_OBJECT_POINTERS e o resto do FILE_OBJECT; a abertura guarda a
//! referência do VPB e do dispositivo até o IRP_MJ_CLOSE, que vai ao mesmo
//! dispositivo relacionado (IoGetRelatedDeviceObject), depois do
//! IRP_MJ_CLEANUP do último handle.
//!
//! O IO_DRIVER_CREATE_CONTEXT de um IoCreateFileEx chega aqui como
//! [`DriverCreateContext`]: a lista de ECPs vai no Irp->UserBuffer do
//! IRP_MJ_CREATE (o FsRtlGetEcpListFromIrp a lê, e a lista ganha a flag de
//! "dentro de um IRP"), e o DeviceObjectHint, que precisa estar na pilha do
//! volume montado (senão STATUS_INVALID_DEVICE_OBJECT_PARAMETER), recebe o
//! IRP no lugar do topo e fica como a dica do FILE_OBJECT (o
//! IoGetRelatedDeviceObject para nele). É o caminho do FltCreateFileEx de um
//! minifiltro, que manda a abertura começar abaixo da sua instância.
//!
//! Sem nome restante, a abertura é do volume (o file system abre o volume
//! inteiro) quando o acesso pede mais que uma abertura direta do dispositivo
//! ([`is_volume_open`]): o FILE_OBJECT que o file system aceitou fica com
//! FO_VOLUME_OPEN (rva 0x650234). A abertura direta, sem montagem, segue
//! por `io_manager::open_device` no ZwCreateFile; a de modo usuário de um
//! volume do kernel ([`open_volume`], o `\??\C:` do `\\.\C:` do Win32) faz
//! o caminho inteiro do IopParseDevice: o IopCheckDeviceAndDriver, o
//! SeAccessCheck do descritor do dispositivo com o acesso pedido e, sem
//! montagem, o IRP_MJ_CREATE ao topo da pilha do próprio dispositivo com
//! FO_DIRECT_DEVICE_OPEN ([`open_direct`]). STATUS_REPARSE, EAs e arquivo
//! relacionado ainda não são tratados.

use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{AccessState, AuxAccessData, DeviceObject, DevobjExtension, FileObject, GenericMapping, IoStackLocation, IoStatusBlock, Irp};
use crate::ntos::io::irp_builder::{self, BuildOptions};
use crate::ntos::io::threads::thread_requests;
use crate::ntos::io::{file::information, file_system, io_manager};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_types::{self, ObjectType};
use crate::ntos::ob::{object_access, object_manager, object_security};
use crate::ntos::ob::objects::device as device_objects;
use crate::ntos::ob::objects::file::{self as file_objects, FileCallbacks};
use crate::ntos::ps::process;
use crate::ntos::se::access_state;
use crate::rtl::KernelError;

const STATUS_PENDING: u32 = 0x103;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const IRP_MJ_CREATE: u8 = 0x00;
const IRP_MJ_CLEANUP: u8 = 0x12;
const IRP_MJ_CLOSE: u8 = 0x02;
const IRP_SYNCHRONOUS_API: u32 = 0x04;
const IRP_CREATE_OPERATION: u32 = 0x80;
const IRP_CLOSE_OPERATION: u32 = 0x400;
const SL_CASE_SENSITIVE: u8 = 0x80;
/// Opções de criação (wdm.h) e as flags de FILE_OBJECT que o parse deriva delas.
const FILE_WRITE_THROUGH: u32 = 0x02;
const FILE_SEQUENTIAL_ONLY: u32 = 0x04;
const FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x08;
const FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x10;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const FILE_RANDOM_ACCESS: u32 = 0x800;
const FO_SYNCHRONOUS_IO: u32 = 0x02;
const FO_ALERTABLE_IO: u32 = 0x04;
const FO_NO_INTERMEDIATE_BUFFERING: u32 = 0x08;
const FO_WRITE_THROUGH: u32 = 0x10;
const FO_SEQUENTIAL_ONLY: u32 = 0x20;
const FO_RANDOM_ACCESS: u32 = 0x10_0000;
/// IoFileObjectType->TypeInfo.GenericMapping: FILE_GENERIC_READ/WRITE/EXECUTE
/// e FILE_ALL_ACCESS.
const FILE_GENERIC_MAPPING: [u32; 4] = [0x0012_0089, 0x0012_0116, 0x0012_00A0, 0x001F_01FF];

const STATUS_INVALID_DEVICE_OBJECT_PARAMETER: u32 = 0xC000_0369;
const STATUS_NO_SUCH_DEVICE: u32 = 0xC000_000E;
const VPB_MOUNTED: u16 = 0x01;
/// FILE_OBJECT.Flags: FO_DIRECT_DEVICE_OPEN e FO_VOLUME_OPEN.
const FO_DIRECT_DEVICE_OPEN: u32 = 0x800;
const FO_VOLUME_OPEN: u32 = 0x40_0000;
/// DEVICE_OBJECT.Flags: DO_DEVICE_INITIALIZING.
const DO_DEVICE_INITIALIZING: u32 = 0x80;
/// DEVOBJ_EXTENSION.ExtensionFlags: DOE_UNLOAD_PENDING, DOE_DELETE_PENDING,
/// DOE_REMOVE_PENDING, DOE_REMOVE_PROCESSED e DOE_START_PENDING.
const DOE_PENDING: u32 = 0x1F;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
/// O acesso de uma abertura direta do dispositivo (IopParseDevice, ntoskrnl
/// 19041): FILE_READ_ATTRIBUTES, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
/// SYNCHRONIZE e ACCESS_SYSTEM_SECURITY. Pedir qualquer outro bit sem nome
/// restante é abrir o volume.
const DIRECT_DEVICE_OPEN_ACCESS: u32 = !0xFEE1_FF7F;

/// IO_DRIVER_CREATE_CONTEXT de um IoCreateFileEx (ou o DeviceObject do
/// IoCreateFileSpecifyDeviceObjectHint): a lista de ECPs e a dica de
/// dispositivo (0 quando ausentes).
#[derive(Clone, Copy, Default)]
pub struct DriverCreateContext {
    pub extra_create_parameter: u64,
    pub device_object_hint: u64,
}

/// Os parâmetros do ZwCreateFile que chegam ao file system.
#[derive(Clone, Copy, Default)]
pub struct OpenRequest {
    pub desired_access: u32,
    pub file_attributes: u32,
    pub share_access: u32,
    pub disposition: u32,
    pub create_options: u32,
    pub case_insensitive: bool,
    pub driver_context: DriverCreateContext,
}

/// Uma abertura sem nome restante de um dispositivo com VPB é a do volume
/// quando o acesso passa do de uma abertura direta (e não há arquivo
/// relacionado, que o chamador já excluiu).
pub fn is_volume_open(desired_access: u32) -> bool {
    desired_access & !DIRECT_DEVICE_OPEN_ACCESS != 0
}

/// O dispositivo `\Device\X` cujo volume já está montado por um file
/// system com pilha de IRP (o da abertura do volume). Os volumes do kernel,
/// servidos pelo file system embutido, ficam de fora; um volume ainda não
/// montado segue aberto direto no dispositivo, porque sem o RAW a montagem
/// pela abertura do volume não tem para onde cair quando nenhum file system
/// o reconhece.
pub fn volume_device_for_open(path: &str) -> Option<u64> {
    let (Some(node), None) = object_manager::resolve(path) else { return None };
    let device = io_manager::device(node)?.native_device;
    if device == 0 || device_at(device).vpb.get() == 0 {
        return None;
    }
    // SAFETY: o VPB do dispositivo.
    let vpb = unsafe { crate::ntos::inc::types::Vpb::at(device_at(device).vpb.get()) };
    let mounted = vpb.device_object.get();
    if vpb.flags.get() & VPB_MOUNTED == 0 || mounted == 0 || crate::drivers::fs::volume_device::is_volume_device(mounted) {
        return None;
    }
    Some(device)
}

/// O dispositivo está na pilha que começa em `base` (ele ou um acima).
fn on_stack(base: u64, device: u64) -> bool {
    let mut current = base;
    let mut steps = 0;
    while current != 0 && steps < 64 {
        if current == device {
            return true;
        }
        current = device_at(current).attached_device.get();
        steps += 1;
    }
    false
}

/// Resultado do IRP_MJ_CREATE: status, Information (FILE_OPENED...) e o
/// FILE_OBJECT aberto (0 na falha).
pub struct Opened {
    pub status: u32,
    pub information: u64,
    pub file_object: u64,
}

/// IO_SECURITY_CONTEXT (wdm.h): SecurityQos, AccessState, DesiredAccess e
/// FullCreateOptions.
#[repr(C)]
struct IoSecurityContext {
    security_qos: crate::ntos::inc::field::Field<u64>,
    access_state: crate::ntos::inc::field::Field<u64>,
    desired_access: crate::ntos::inc::field::Field<u32>,
    full_create_options: crate::ntos::inc::field::Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for IoSecurityContext {}

const _: () = {
    assert!(core::mem::size_of::<IoSecurityContext>() == 0x18);
    assert!(core::mem::offset_of!(IoSecurityContext, full_create_options) == 0x14);
};

fn device_at(address: u64) -> &'static DeviceObject {
    // SAFETY: DEVICE_OBJECTs vivos do namespace ou de um VPB montado.
    unsafe { DeviceObject::at(address) }
}

/// Divide `\Device\X\resto` no DEVICE_OBJECT mais longo do prefixo (links do
/// namespace seguidos) que tem VPB e no nome restante, com a barra inicial.
pub fn split_volume_path(path: &str) -> Option<(u64, String)> {
    let parts: alloc::vec::Vec<&str> = path.split('\\').filter(|part| !part.is_empty()).collect();
    for split in (1..parts.len()).rev() {
        let prefix = alloc::format!("\\{}", parts[..split].join("\\"));
        let (Some(node), None) = object_manager::resolve(&prefix) else { continue };
        let Some(entry) = io_manager::device(node) else { continue };
        let device = entry.native_device;
        if device == 0 || device_at(device).vpb.get() == 0 {
            continue;
        }
        return Some((device, alloc::format!("\\{}", parts[split..].join("\\"))));
    }
    None
}

/// Flags do FILE_OBJECT pelas opções de criação.
fn file_object_flags(options: u32) -> u32 {
    let mut flags = 0;
    if options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) != 0 {
        flags |= FO_SYNCHRONOUS_IO;
        if options & FILE_SYNCHRONOUS_IO_ALERT != 0 {
            flags |= FO_ALERTABLE_IO;
        }
    }
    if options & FILE_NO_INTERMEDIATE_BUFFERING != 0 {
        flags |= FO_NO_INTERMEDIATE_BUFFERING;
    }
    if options & FILE_WRITE_THROUGH != 0 {
        flags |= FO_WRITE_THROUGH;
    }
    if options & FILE_SEQUENTIAL_ONLY != 0 {
        flags |= FO_SEQUENTIAL_ONLY;
    }
    if options & FILE_RANDOM_ACCESS != 0 {
        flags |= FO_RANDOM_ACCESS;
    }
    flags
}

/// IRP síncrono de modo kernel a `target` com o FILE_OBJECT; espera o
/// STATUS_PENDING no evento do pedido. Devolve (status, Information).
fn call_file_irp(target: u64, file: u64, major: u8, irp_flags: u32, configure: impl FnOnce(&Irp, &IoStackLocation)) -> Result<(u32, u64), KernelError> {
    let count = (device_at(target).stack_size.get() as u8 as u32).max(1);
    let scratch = guest::alloc_bytes(0x30);
    let packet = guest::alloc_bytes(irp_builder::size_for(count));
    if scratch == 0 || packet == 0 {
        for block in [scratch, packet] {
            if block != 0 {
                guest::free_bytes(block);
            }
        }
        return Ok((STATUS_INSUFFICIENT_RESOURCES, 0));
    }
    let (event, io_status) = (scratch, scratch + 0x18);
    dispatcher::initialize_event(event, 0, false);
    let thread = process::get_current_thread();
    irp_builder::build(packet, &BuildOptions { major, device_object: target, stack_count: count, file_object: file, user_event: event, user_iosb: io_status, thread, requestor_mode: 0, ..Default::default() });
    // SAFETY: o IRP e o slot acabaram de ser montados pelo irp_builder.
    let (irp, stack) = unsafe { (Irp::at(packet), IoStackLocation::at(irp_builder::first_stack_location(packet, count))) };
    irp.flags.set(irp_flags);
    irp.tail.overlay.original_file_object.set(file);
    stack.file_object.set(file);
    configure(irp, stack);
    let queued = thread != 0 && thread_requests::insert(packet, thread).is_ok();
    let mut status = io_manager::iof_call_driver(target, packet) as u32;
    // SAFETY: o IO_STATUS_BLOCK do scratch.
    let iosb = unsafe { IoStatusBlock::at(io_status) };
    if status == STATUS_PENDING {
        dispatcher::wait_for_single_object(event, 0, 0, false);
        status = iosb.status.get() as u32;
    }
    let information = if (status as i32) >= 0 { iosb.information.get() } else { 0 };
    if queued && irp.thread_list_entry.flink.get() != 0 {
        thread_requests::remove(packet, thread)?;
    }
    guest::free_bytes(packet);
    guest::free_bytes(scratch);
    Ok((status, information))
}

/// CLEANUP/CLOSE de um arquivo de volume ao dispositivo relacionado.
fn send_close(file: u64, major: u8) -> u32 {
    let target = information::related_device(file).unwrap_or(0);
    if target == 0 {
        return 0;
    }
    call_file_irp(target, file, major, IRP_CLOSE_OPERATION | IRP_SYNCHRONOUS_API, |_, stack| stack.major_function.set(major)).map_or(0, |(status, _)| status)
}

/// ACCESS_STATE e AUX_ACCESS_DATA de uma abertura (SeCreateAccessState com o
/// mapeamento genérico de arquivo); devolve o bloco (estado, aux, mapa).
fn create_access_state(desired: u32) -> Result<u64, KernelError> {
    let size = AccessState::SIZE + AuxAccessData::SIZE + GenericMapping::SIZE;
    let block = guest::alloc_bytes(size);
    if block == 0 {
        return Err(KernelError::with_status("ACCESS_STATE allocation failed", STATUS_INSUFFICIENT_RESOURCES));
    }
    let (state_address, aux_address, mapping_address) = (block, block + AccessState::SIZE, block + AccessState::SIZE + AuxAccessData::SIZE);
    // SAFETY: as três regiões do bloco recém-alocado.
    let (state, aux, mapping) = unsafe { (AccessState::at(state_address), AuxAccessData::at(aux_address), GenericMapping::at(mapping_address)) };
    mapping.generic_read.set(FILE_GENERIC_MAPPING[0]);
    mapping.generic_write.set(FILE_GENERIC_MAPPING[1]);
    mapping.generic_execute.set(FILE_GENERIC_MAPPING[2]);
    mapping.generic_all.set(FILE_GENERIC_MAPPING[3]);
    let thread = process::get_current_thread();
    access_state::create(thread, process::get_current_process(), state, aux, desired, Some(mapping))?;
    Ok(block)
}

fn release_access_state(block: u64) {
    // SAFETY: o ACCESS_STATE no início do bloco de create_access_state.
    let _ = access_state::delete(unsafe { AccessState::at(block) });
    guest::free_bytes(block);
}

/// O IRP_MJ_CREATE de `file` a `target`: o ACCESS_STATE, o
/// IO_SECURITY_CONTEXT, Options = (Disposition << 24) | CreateOptions, os
/// atributos, o compartilhamento e a lista de ECPs. Devolve (status,
/// Information).
fn send_create(target: u64, file: u64, request: &OpenRequest) -> Result<(u32, u64), KernelError> {
    let access = create_access_state(request.desired_access)?;
    let context = guest::alloc_bytes(IoSecurityContext::SIZE);
    if context == 0 {
        release_access_state(access);
        return Ok((STATUS_INSUFFICIENT_RESOURCES, 0));
    }
    // SAFETY: bloco recém-alocado do tamanho do IO_SECURITY_CONTEXT.
    let security = unsafe { IoSecurityContext::at(context) };
    security.access_state.set(access);
    security.desired_access.set(request.desired_access);
    security.full_create_options.set(request.create_options);
    let ecp_list = request.driver_context.extra_create_parameter;
    let result = call_file_irp(target, file, IRP_MJ_CREATE, IRP_CREATE_OPERATION | IRP_SYNCHRONOUS_API, |irp, stack| {
        if ecp_list != 0 {
            // SAFETY: a _ECP_LIST do IO_DRIVER_CREATE_CONTEXT do chamador.
            crate::ntos::fsrtl::ecp::set_list_into_irp(irp, unsafe { crate::ntos::inc::types::extra_fsrtl::EcpList::at(ecp_list) });
        }
        stack.major_function.set(IRP_MJ_CREATE);
        stack.flags.set(if request.case_insensitive { 0 } else { SL_CASE_SENSITIVE });
        let create = &stack.parameters.create;
        create.security_context.set(context);
        create.options.set((request.disposition << 24) | (request.create_options & 0x00FF_FFFF));
        create.file_attributes.set(request.file_attributes as u16);
        create.share_access.set(request.share_access as u16);
        create.ea_length.set(0);
    });
    guest::free_bytes(context);
    release_access_state(access);
    result
}

/// Abre `remaining` no volume montado em `device` (montando-o se preciso).
pub fn open_file(device: u64, remaining: &str, request: &OpenRequest) -> Result<Opened, KernelError> {
    let real = device_at(device);
    // IopIncrementDeviceObjectRefCount: a abertura retém o dispositivo real.
    real.reference_count.atomic().fetch_add(1, Ordering::SeqCst);
    let release_device = || {
        real.reference_count.atomic().fetch_sub(1, Ordering::SeqCst);
        device_objects::changed(device);
    };
    let vpb = match file_system::check_vpb_mounted(real, remaining.is_empty(), false) {
        Ok(Ok(vpb)) => vpb,
        Ok(Err(status)) => {
            release_device();
            return Ok(Opened { status, information: 0, file_object: 0 });
        }
        Err(error) => {
            release_device();
            return Err(error);
        }
    };
    // SAFETY: o VPB montado e referenciado acima.
    let volume = unsafe { crate::ntos::inc::types::Vpb::at(vpb) }.device_object.get();
    let hint = request.driver_context.device_object_hint;
    if hint != 0 && !on_stack(volume, hint) {
        let _ = file_system::dereference_vpb(vpb);
        release_device();
        return Ok(Opened { status: STATUS_INVALID_DEVICE_OBJECT_PARAMETER, information: 0, file_object: 0 });
    }
    let target = if hint != 0 { hint } else { device_objects::top(volume) };
    let file = match file_objects::create(device, remaining) {
        Ok(file) => file,
        Err(error) => {
            let _ = file_system::dereference_vpb(vpb);
            release_device();
            return Err(error);
        }
    };
    // SAFETY: o FILE_OBJECT recém-criado.
    let object = unsafe { FileObject::at(file) };
    object.vpb.set(vpb);
    object.flags.set(file_object_flags(request.create_options));
    let (status, information) = match send_create(target, file, request) {
        Ok(result) => result,
        Err(error) => {
            let _ = file_objects::dereference(file);
            let _ = file_system::dereference_vpb(vpb);
            release_device();
            return Err(error);
        }
    };
    if (status as i32) < 0 || status == STATUS_PENDING {
        // A falha não chega ao file system como CLOSE: só as referências voltam.
        let _ = file_objects::dereference(file);
        let _ = file_system::dereference_vpb(vpb);
        release_device();
        return Ok(Opened { status, information: 0, file_object: 0 });
    }
    // Sem nome e sem arquivo relacionado, a abertura que um file system
    // atendeu (FILE_DEVICE_CD_ROM_FILE_SYSTEM, DISK_FILE_SYSTEM, FILE_SYSTEM
    // ou TAPE_FILE_SYSTEM no dispositivo que recebeu o IRP) é a do volume
    // (IopParseDevice, rva 0x650214..0x650234).
    if remaining.is_empty() && matches!(device_at(target).device_type.get(), 3 | 8 | 9 | 0x20) {
        object.flags.atomic().fetch_or(FO_VOLUME_OPEN, Ordering::SeqCst);
    }
    if hint != 0 {
        // A dica fica no FILE_OBJECT: os IRPs seguintes param nela.
        crate::ntos::io::extensions::set_device_object_hint(object, hint)?;
    }
    file_objects::set_callbacks(file, FileCallbacks {
        cleanup: Some(Arc::new(move || send_close(file, IRP_MJ_CLEANUP))),
        close: Some(Arc::new(move || {
            send_close(file, IRP_MJ_CLOSE);
            // SAFETY: o FILE_OBJECT ainda vive durante o CLOSE.
            let _ = file_system::dereference_vpb(unsafe { FileObject::at(file) }.vpb.get());
            device_at(device).reference_count.atomic().fetch_sub(1, Ordering::SeqCst);
            device_objects::changed(device);
        })),
        destroy: None,
    })?;
    Ok(Opened { status, information, file_object: file })
}

/// A abertura direta do IopParseDevice (sem nome restante, sem arquivo
/// relacionado e só com os direitos de DIRECT_DEVICE_OPEN_ACCESS): sem
/// montagem, o FILE_OBJECT fica com DeviceObject = o dispositivo do nome,
/// sem VPB e com FO_DIRECT_DEVICE_OPEN (rva 0x64f548), e o IRP_MJ_CREATE
/// vai ao topo da pilha do próprio dispositivo (IoGetAttachedDevice,
/// 0x64f010). Os IRPs seguintes do arquivo vão ao mesmo topo
/// (IopXxxControlFile 0x64bd0e).
pub fn open_direct(device: u64, request: &OpenRequest) -> Result<Opened, KernelError> {
    // IopIncrementDeviceObjectRefCount: a abertura retém o dispositivo.
    device_at(device).reference_count.atomic().fetch_add(1, Ordering::SeqCst);
    let release_device = move || {
        device_at(device).reference_count.atomic().fetch_sub(1, Ordering::SeqCst);
        device_objects::changed(device);
    };
    let target = device_objects::top(device);
    let file = match file_objects::create(device, "") {
        Ok(file) => file,
        Err(error) => {
            release_device();
            return Err(error);
        }
    };
    // SAFETY: o FILE_OBJECT recém-criado.
    let object = unsafe { FileObject::at(file) };
    object.flags.set(file_object_flags(request.create_options) | FO_DIRECT_DEVICE_OPEN);
    let (status, information) = match send_create(target, file, request) {
        Ok(result) => result,
        Err(error) => {
            let _ = file_objects::dereference(file);
            release_device();
            return Err(error);
        }
    };
    if (status as i32) < 0 || status == STATUS_PENDING {
        let _ = file_objects::dereference(file);
        release_device();
        return Ok(Opened { status, information: 0, file_object: 0 });
    }
    file_objects::set_callbacks(file, FileCallbacks {
        cleanup: Some(Arc::new(move || send_close(file, IRP_MJ_CLEANUP))),
        close: Some(Arc::new(move || {
            send_close(file, IRP_MJ_CLOSE);
            release_device();
        })),
        destroy: None,
    })?;
    Ok(Opened { status, information, file_object: file })
}

/// O SeAccessCheck do IopParseDevice para um chamador de modo usuário sem
/// nome restante (rva 0x64eb07): o descritor do dispositivo, o sujeito da
/// thread (com a impersonação), o acesso pedido e o mapeamento genérico do
/// IoFileObjectType. Sem descritor, o pedido é concedido.
fn device_access(device: u64, desired: u32, file_type: &ObjectType) -> Result<u32, u32> {
    match object_security::object_policy(device) {
        Some(policy) => object_access::check(&policy, object_access::subject(), desired, file_type, false),
        None => Ok((desired & !MAXIMUM_ALLOWED) | if desired & MAXIMUM_ALLOWED != 0 { file_type.valid_access } else { 0 }),
    }
}

/// O IopParseDevice de uma abertura de modo usuário sem nome restante num
/// volume do kernel: o IopCheckDeviceAndDriver (0x2d3af0: o dispositivo
/// com remoção, descarga ou início pendente, ou ainda inicializando, dá
/// STATUS_NO_SUCH_DEVICE), o acesso pedido com o mapeamento genérico de
/// arquivo (RtlMapGenericMask, 0x64e90b), o SeAccessCheck do descritor do
/// dispositivo ([`device_access`]) e a escolha (0x64eda1..0x64edc0): só os
/// direitos da abertura direta (o pedido antes da checagem, com
/// MAXIMUM_ALLOWED contando como mais) abrem o dispositivo direto
/// ([`open_direct`]); senão o volume é aberto pelo file system
/// ([`open_file`] sem nome, com FO_VOLUME_OPEN). O file system recebe no
/// IO_SECURITY_CONTEXT o acesso concedido. Devolve a abertura e o acesso
/// concedido, que é o do handle.
pub fn open_volume(device: u64, request: &OpenRequest) -> Result<(Opened, u32), KernelError> {
    let failed = |status: u32| -> Result<(Opened, u32), KernelError> { Ok((Opened { status, information: 0, file_object: 0 }, 0)) };
    let object = device_at(device);
    let extension = object.device_object_extension.get();
    // SAFETY: a DEVOBJ_EXTENSION de um dispositivo vivo.
    let pending = extension != 0 && unsafe { DevobjExtension::at(extension) }.extension_flags.get() & DOE_PENDING != 0;
    if pending || object.flags.get() & DO_DEVICE_INITIALIZING != 0 {
        return failed(STATUS_NO_SUCH_DEVICE);
    }
    let file_type = object_types::file_type();
    let desired = object_access::map_generic_access(request.desired_access, &file_type);
    let granted = match device_access(device, desired, &file_type) {
        Ok(granted) => granted,
        Err(status) => return failed(status),
    };
    let request = OpenRequest { desired_access: granted, ..*request };
    let opened = if is_volume_open(desired) { open_file(device, "", &request)? } else { open_direct(device, &request)? };
    Ok((opened, granted))
}

/// O dispositivo real do volume do kernel em que `path` termina, sem nome
/// restante: `\??\C:` (o `\\.\C:` do Win32), `\GLOBAL??\D:`,
/// `\Device\KernelVolume1`. `\??\C:\` (com a barra) é a raiz do volume, um
/// diretório do file system, e não entra aqui.
pub fn kernel_volume_device(path: &str) -> Option<u64> {
    if path.is_empty() || path.ends_with(['\\', '/']) {
        return None;
    }
    let (Some(node), Some(rest)) = object_manager::resolve(path) else { return None };
    if !rest.is_empty() {
        return None;
    }
    let device = object_manager::node(node)?.data?.native_pointer;
    crate::drivers::fs::volume_device::is_real_device(device).then_some(device)
}
