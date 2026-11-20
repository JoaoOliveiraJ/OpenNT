//! A API do configuration manager do PnP (`\Device\DeviceApi\CMApi`).
//!
//! É por ela que o cfgmgr32.dll (CM_Locate_DevNode, CM_Get_DevNode_Status,
//! CM_Get_Device_ID_List, CM_Get_Device_Interface_List...) consulta e
//! altera a árvore de dispositivos. Como no ntoskrnl 19041:
//!   * PiCMDispatch (rva 0x69e0b0): IRP_MJ_CREATE, CLOSE e CLEANUP concluem
//!     com sucesso; IRP_MJ_DEVICE_CONTROL com STATUS_NOT_SUPPORTED (os
//!     IOCTLs só chegam pelo Fast I/O); um IRP que já traz falha no
//!     IoStatus conclui com ela;
//!   * PiCMFastIoDeviceDispatch (rva 0x6ad5c0): todo IOCTL é atendido pelo
//!     FastIoDeviceControl, com IoIs32bitProcess, e devolve TRUE com o
//!     NTSTATUS do PiCMHandleIoctl no IoStatus;
//!   * PiCMHandleIoctl (rva 0x6ad630): IOCTLs CTL_CODE(0x47, 0x200 + n,
//!     METHOD_NEITHER, FILE_ANY_ACCESS), buffers de usuário capturados pelo
//!     tratador; código desconhecido: STATUS_NOT_SUPPORTED.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::inc::types::{IoStackLocation, IoStatusBlock, Irp, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::previous_mode;
use crate::ntos::ps::user_probe::{probe_user_read, probe_user_write};
use crate::rtl::KernelError;

use super::device_api::{self, FastIoRequest};
use super::devnode;

const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

const IRP_MJ_CREATE: u8 = 0x00;
const IRP_MJ_CLOSE: u8 = 0x02;
const IRP_MJ_DEVICE_CONTROL: u8 = 0x0E;
const IRP_MJ_CLEANUP: u8 = 0x12;

/// CTL_CODE(0x47, 0x200 + função, METHOD_NEITHER, FILE_ANY_ACCESS).
const fn ioctl(function: u32) -> u32 {
    (0x47 << 16) | ((0x200 + function) << 2) | 3
}

/// Os IOCTLs do PiCMHandleIoctl, na ordem das funções.
pub mod code {
    use super::ioctl;
    pub const GET_DEVICE_ID_LIST: u32 = ioctl(0x00);
    pub const GET_DEVICE_INTERFACE_LIST: u32 = ioctl(0x01);
    pub const ENUMERATE_SUB_KEYS: u32 = ioctl(0x02);
    pub const GET_OBJECT_PROPERTY_KEYS: u32 = ioctl(0x03);
    pub const GET_OBJECT_PROPERTY: u32 = ioctl(0x04);
    pub const SET_OBJECT_PROPERTY: u32 = ioctl(0x05);
    pub const GET_REGISTRY_PROPERTY: u32 = ioctl(0x06);
    pub const SET_REGISTRY_PROPERTY: u32 = ioctl(0x07);
    pub const GET_RELATED_DEVICE_INSTANCE: u32 = ioctl(0x08);
    pub const GET_DEVICE_STATUS: u32 = ioctl(0x09);
    pub const GET_DEVICE_DEPTH: u32 = ioctl(0x0A);
    pub const SET_DEVICE_PROBLEM: u32 = ioctl(0x0B);
    pub const QUERY_REMOVE: u32 = ioctl(0x0C);
    pub const REGISTER_DEVICE_INTERFACE: u32 = ioctl(0x0D);
    pub const UNREGISTER_DEVICE_INTERFACE: u32 = ioctl(0x0E);
    pub const GET_DEVICE_INTERFACE_ALIAS: u32 = ioctl(0x0F);
    pub const VALIDATE_DEVICE_INSTANCE: u32 = ioctl(0x10);
    pub const CREATE_DEVICE: u32 = ioctl(0x11);
    pub const DELETE_DEVICE: u32 = ioctl(0x12);
    pub const DEVICE_ACTION: u32 = ioctl(0x13);
    pub const OPEN_DEVICE_INTERFACE_KEY: u32 = ioctl(0x14);
    pub const DELETE_DEVICE_INTERFACE_KEY: u32 = ioctl(0x15);
    pub const OPEN_DEVICE_KEY: u32 = ioctl(0x16);
    pub const DELETE_DEVICE_KEY: u32 = ioctl(0x17);
    pub const OPEN_CLASS_KEY: u32 = ioctl(0x18);
    pub const DELETE_CLASS_KEY: u32 = ioctl(0x19);
    pub const OPEN_OBJECT_KEY: u32 = ioctl(0x1A);
    pub const CREATE_OBJECT: u32 = ioctl(0x1B);
    pub const DELETE_OBJECT: u32 = ioctl(0x1C);
    pub const GET_OBJECT_LIST: u32 = ioctl(0x1D);
}

/// O nome do tratador do ntoskrnl para um IOCTL (None: desconhecido).
pub fn handler_name(code: u32) -> Option<&'static str> {
    const NAMES: [&str; 30] = [
        "PiCMGetDeviceIdList",
        "PiCMGetDeviceInterfaceList",
        "PiCMEnumerateSubKeys",
        "PiCMGetObjectPropertyKeys",
        "PiCMGetObjectProperty",
        "PiCMSetObjectProperty",
        "PiCMGetRegistryProperty",
        "PiCMSetRegistryProperty",
        "PiCMGetRelatedDeviceInstance",
        "PiCMGetDeviceStatus",
        "PiCMGetDeviceDepth",
        "PiCMSetDeviceProblem",
        "PiCMQueryRemove",
        "PiCMRegisterDeviceInterface",
        "PiCMUnregisterDeviceInterface",
        "PiCMGetDeviceInterfaceAlias",
        "PiCMValidateDeviceInstance",
        "PiCMCreateDevice",
        "PiCMDeleteDevice",
        "PiCMDeviceAction",
        "PiCMOpenDeviceInterfaceKey",
        "PiCMDeleteDeviceInterfaceKey",
        "PiCMOpenDeviceKey",
        "PiCMDeleteDeviceKey",
        "PiCMOpenClassKey",
        "PiCMDeleteClassKey",
        "PiCMOpenObjectKey",
        "PiCMCreateObject",
        "PiCMDeleteObject",
        "PiCMGetObjectList",
    ];
    if code & 0xFFFF_0003 != 0x0047_0003 {
        return None;
    }
    let function = (code >> 2) & 0xFFF;
    function.checked_sub(0x200).and_then(|index| NAMES.get(index as usize)).copied()
}

/// Os buffers de um IOCTL (METHOD_NEITHER: ponteiros de quem chamou).
pub struct Buffers {
    pub input: u64,
    pub input_length: u32,
    pub output: u64,
    pub output_length: u32,
    pub is_32bit: bool,
}

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_SUCH_DEVICE: u32 = 0xC000_000E;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
/// CM_GET_DEVICE_INTERFACE_LIST_PRESENT / CM_GETIDLIST_FILTER_PRESENT no
/// formato do kernel.
const LIST_PRESENT: u32 = 0x1_0000;

/// O pedido de objeto do cfgmgr32 depois do PiCMCaptureObjectInputData
/// (64 bits: 0x28 bytes, Size em +0): +4 os flags da operação, +8 o tipo
/// do objeto (1 = dispositivo), +0x10/+0x18 o nome (o caminho da instância,
/// com o NUL, copiado e terminado), +0x1C o parâmetro da operação e +0x20 o
/// tamanho do resultado que quem chama espera.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectInput {
    pub flags: u32,
    pub object_type: u32,
    pub name: Option<String>,
    pub parameter: u32,
    pub result_size: u32,
}

/// Leitura do buffer de quem pediu: sondada quando ele veio do modo usuário.
fn read_caller(address: u64, length: u64, user: bool) -> Result<Vec<u8>, u32> {
    if user && !probe_user_read(address, length) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    guest::try_read_bytes(address, length as usize).map_err(|_| STATUS_ACCESS_VIOLATION)
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

/// PiCMCaptureObjectInputData (ntoskrnl 19041 rva 0x6b1954): Err é o
/// NTSTATUS do próprio IOCTL.
pub fn capture_object_input(buffers: &Buffers) -> Result<ObjectInput, u32> {
    let user = previous_mode::get().unwrap_or(0) != 0;
    if buffers.input == 0 || buffers.input_length == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if user && buffers.input & 7 != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    if buffers.input_length < 0x28 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let bytes = read_caller(buffers.input, 0x28, user)?;
    if u32_at(&bytes, 0) != 0x28 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let pointer = u64::from_le_bytes(bytes[0x10..0x18].try_into().unwrap_or([0; 8]));
    let name = capture_name(pointer, u32_at(&bytes, 0x18), user)?;
    Ok(ObjectInput { flags: u32_at(&bytes, 4), object_type: u32_at(&bytes, 8), name, parameter: u32_at(&bytes, 0x1C), result_size: u32_at(&bytes, 0x20) })
}

/// O texto de um PiCMCapture*InputData: ponteiro NULL exige tamanho 0;
/// senão ao menos 2 bytes, cópia com alinhamento 2
/// (PiControlMakeUserModeCallersCopy) e o último WCHAR zerado.
fn capture_name(pointer: u64, length: u32, user: bool) -> Result<Option<String>, u32> {
    if pointer == 0 {
        return if length != 0 { Err(STATUS_INVALID_PARAMETER) } else { Ok(None) };
    }
    if length < 2 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if user && pointer & 1 != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    let raw = read_caller(pointer, length as u64, user)?;
    let mut units: Vec<u16> = raw.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    if let Some(last) = units.last_mut() {
        *last = 0;
    }
    let end = units.iter().position(|&unit| unit == 0).unwrap_or(units.len());
    Ok(Some(String::from_utf16_lossy(&units[..end])))
}

/// Grava o resultado (os DWORDs do cabeçalho e os bytes extras) no buffer de
/// saída sondado: `(NTSTATUS do IOCTL, Information)`.
fn write_result(buffers: &Buffers, header: &[u32], extra: &[u8], expected: u32) -> (u32, u64) {
    let size = header.len() as u32 * 4 + extra.len() as u32;
    if buffers.output_length < size || header.first() != Some(&expected) {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let user = previous_mode::get().unwrap_or(0) != 0;
    if buffers.output & 3 != 0 && user {
        return (STATUS_DATATYPE_MISALIGNMENT, 0);
    }
    if user && !probe_user_write(buffers.output, buffers.output_length as u64) {
        return (STATUS_ACCESS_VIOLATION, 0);
    }
    let mut bytes: Vec<u8> = header.iter().flat_map(|value| value.to_le_bytes()).collect();
    bytes.extend_from_slice(extra);
    match guest::try_write_bytes(buffers.output, &bytes) {
        Ok(()) => (0, size as u64),
        Err(_) => (STATUS_ACCESS_VIOLATION, 0),
    }
}

/// PiCMReturnBasicResultData: {8, Status}, se o resultado esperado é de 8 bytes.
fn return_basic(buffers: &Buffers, status: u32, expected: u32) -> (u32, u64) {
    if expected != 8 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    write_result(buffers, &[8, status], &[], 8)
}

/// PiCMReturnStatusResultData: {0x14, Status, DevNodeStatus, Problem, ProblemStatus}.
fn return_status(buffers: &Buffers, status: u32, device: (u32, u32, u32), expected: u32) -> (u32, u64) {
    if expected != 0x14 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    write_result(buffers, &[0x14, status, device.0, device.1, device.2], &[], 0x14)
}

/// PiCMReturnDepthResultData: {0xC, Status, Depth}.
fn return_depth(buffers: &Buffers, status: u32, depth: u32, expected: u32) -> (u32, u64) {
    if expected != 0xC {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    write_result(buffers, &[0xC, status, depth], &[], 0xC)
}

/// PiCMReturnBufferResultData (19041 0x6b0564): {0x14, Status, Required,
/// Extra} em +0, um DWORD zerado em +0x10 e os dados a partir de +0x10;
/// Information = 0x14 + dados. Resultado esperado diferente de 0x14 ou saída
/// menor que 0x14 + dados recusam o próprio IOCTL (0x810bd6).
fn return_buffer(buffers: &Buffers, status: u32, required: u32, extra: u32, data: &[u8], expected: u32) -> (u32, u64) {
    let total = 0x14u32.saturating_add(data.len() as u32);
    if expected != 0x14 || buffers.output == 0 || buffers.output_length < total {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let user = previous_mode::get().unwrap_or(0) != 0;
    if user && buffers.output & 3 != 0 {
        return (STATUS_DATATYPE_MISALIGNMENT, 0);
    }
    if user && !probe_user_write(buffers.output, buffers.output_length as u64) {
        return (STATUS_ACCESS_VIOLATION, 0);
    }
    let mut bytes: Vec<u8> = [0x14, status, required, extra].iter().flat_map(|value| value.to_le_bytes()).collect();
    bytes.extend_from_slice(data);
    bytes.resize(bytes.len().max(0x14), 0);
    match guest::try_write_bytes(buffers.output, &bytes) {
        Ok(()) => (0, total as u64),
        Err(_) => (STATUS_ACCESS_VIOLATION, 0),
    }
}

/// MULTI_SZ: cada texto com o NUL e mais um NUL; vazia = um NUL
/// (IopGetDeviceInterfaces 0x6b36b3, PiCMGetDeviceIdList 0x689ef4).
fn multi_sz_bytes(items: &[String]) -> Vec<u8> {
    let mut units: Vec<u16> = Vec::new();
    for item in items {
        units.extend(item.encode_utf16());
        units.push(0);
    }
    units.push(0);
    units.iter().flat_map(|unit| unit.to_le_bytes()).collect()
}

/// PiCMCaptureInterfaceListInputData (0x68ff1c; 0x28 bytes): +4 flags, +8 o
/// GUID da classe, +0x18/+0x20 a instância opcional, +0x24 o resultado (0x14).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InterfaceListInput {
    pub flags: u32,
    pub class: [u8; 16],
    pub device: Option<String>,
    pub result_size: u32,
}

/// PiCMCaptureDeviceListInputData (0x68a104; 0x18 bytes): +4 flags, +8/+0x10
/// o filtro, +0x14 o resultado (0x14).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceListInput {
    pub flags: u32,
    pub filter: Option<String>,
    pub result_size: u32,
}

/// O cabeçalho comum dos PiCMCapture*InputData de 64 bits: ponteiro e
/// tamanho, alinhamento 8, sondagem e o Size exato em +0.
fn capture_fixed(buffers: &Buffers, size: u32) -> Result<(Vec<u8>, bool), u32> {
    let user = previous_mode::get().unwrap_or(0) != 0;
    if buffers.input == 0 || buffers.input_length == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if user && buffers.input & 7 != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    if user && !probe_user_read(buffers.input, buffers.input_length as u64) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    if buffers.input_length < size {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let bytes = read_caller(buffers.input, size as u64, user)?;
    if u32_at(&bytes, 0) != size {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok((bytes, user))
}

pub fn capture_interface_list_input(buffers: &Buffers) -> Result<InterfaceListInput, u32> {
    let (bytes, user) = capture_fixed(buffers, 0x28)?;
    let pointer = u64::from_le_bytes(bytes[0x18..0x20].try_into().unwrap_or([0; 8]));
    let device = capture_name(pointer, u32_at(&bytes, 0x20), user)?;
    let mut class = [0u8; 16];
    class.copy_from_slice(&bytes[8..0x18]);
    Ok(InterfaceListInput { flags: u32_at(&bytes, 4), class, device, result_size: u32_at(&bytes, 0x24) })
}

pub fn capture_device_list_input(buffers: &Buffers) -> Result<DeviceListInput, u32> {
    let (bytes, user) = capture_fixed(buffers, 0x18)?;
    let pointer = u64::from_le_bytes(bytes[8..0x10].try_into().unwrap_or([0; 8]));
    let filter = capture_name(pointer, u32_at(&bytes, 0x10), user)?;
    Ok(DeviceListInput { flags: u32_at(&bytes, 4), filter, result_size: u32_at(&bytes, 0x14) })
}

/// PiCMGetDeviceInterfaceList (0x201; 19041 0x68fd38): só o flag 0x10000
/// (só as habilitadas) é válido; a lista do IopGetDeviceInterfaces no formato
/// do modo usuário (classe sem interfaces: `L"\0"`); saída curta =
/// STATUS_BUFFER_TOO_SMALL com o tamanho no resultado.
fn get_device_interface_list(buffers: &Buffers) -> (u32, u64) {
    let input = match capture_interface_list_input(buffers) {
        Ok(input) => input,
        Err(status) => return (status, 0),
    };
    let (status, required, data) = if buffers.output == 0 || buffers.output_length < 0x14 || input.flags & !LIST_PRESENT != 0 {
        (STATUS_INVALID_PARAMETER, 0, Vec::new())
    } else {
        let device = input.device.as_deref().filter(|name| !name.is_empty());
        let links = crate::ntos::io::device_interface::user_interface_links(&input.class, device, input.flags & LIST_PRESENT == 0);
        let bytes = multi_sz_bytes(&links);
        let required = bytes.len() as u32;
        if buffers.output_length - 0x14 < required { (STATUS_BUFFER_TOO_SMALL, required, Vec::new()) } else { (0, required, bytes) }
    };
    return_buffer(buffers, status, required, 0, &data, input.result_size)
}

/// _CmGetMatchingDeviceListForSubkey/_CmEnumSubkeyCallback (0x7b02fc/0x7b1070):
/// `Enum\a\b\c` na ordem das subchaves, válidos pelo CmValidateDeviceName,
/// com `present` só os que têm nó (_CmIsDevicePresent 0x684b78).
fn enum_instances(base: Option<&str>, present: bool, keep: &dyn Fn(&str) -> bool) -> Result<Vec<String>, u32> {
    let root = alloc::format!("{}\\Enum", super::install::CONTROL_SET);
    let sorted = |path: &str| {
        let mut keys = crate::ntos::cm::registry::list_keys(path);
        keys.sort_by_key(|key| key.to_uppercase());
        keys
    };
    let mut prefixes: Vec<String> = match base {
        None => sorted(&root),
        Some(filter) => {
            let parts: Vec<&str> = filter.split('\\').collect();
            if parts.len() > 2 || parts.iter().any(|part| part.is_empty()) {
                return Err(STATUS_INVALID_PARAMETER);
            }
            if crate::ntos::cm::registry::node_by_path(&alloc::format!("{root}\\{filter}")).is_none() {
                return Err(STATUS_OBJECT_NAME_NOT_FOUND);
            }
            alloc::vec![String::from(filter)]
        }
    };
    let mut depth = base.map_or(1, |filter| filter.split('\\').count());
    while depth < 3 {
        prefixes = prefixes.iter().flat_map(|prefix| sorted(&alloc::format!("{root}\\{prefix}")).into_iter().map(move |child| alloc::format!("{prefix}\\{child}"))).collect();
        depth += 1;
    }
    Ok(prefixes.into_iter().filter(|id| validate_device_name(id) == 0 && (!present || devnode::by_instance_path(id).is_some()) && keep(id)).collect())
}

/// _CmServiceFilterCallback (0x9771b0): o Service, ou um dos filtros do
/// dispositivo ou da classe de instalação.
fn service_matches(id: &str, service: &str) -> bool {
    use super::install::{read_multi, read_text, CONTROL_SET};
    let key = alloc::format!("{CONTROL_SET}\\Enum\\{id}");
    let same = |name: &String| name.eq_ignore_ascii_case(service);
    if read_text(&key, "Service").is_some_and(|name| same(&name)) {
        return true;
    }
    let filters = |path: &str| read_multi(path, "UpperFilters").into_iter().chain(read_multi(path, "LowerFilters"));
    if filters(&key).any(|name| same(&name)) {
        return true;
    }
    read_text(&key, "ClassGUID").is_some_and(|class| filters(&alloc::format!("{CONTROL_SET}\\Control\\Class\\{class}")).any(|name| same(&name)))
}

/// _CmClassFilterCallback (0x976e20): ClassGUID igual ao texto, sem caixa.
fn class_matches(id: &str, class: &str) -> bool {
    let key = alloc::format!("{}\\Enum\\{id}", super::install::CONTROL_SET);
    super::install::read_text(&key, "ClassGUID").is_some_and(|value| value.eq_ignore_ascii_case(class))
}

/// PiQueryDeviceRelations (0x8b3fec): o nó tem de existir; BusRelations são
/// os filhos. As outras relações o NT pede à pilha (PnpQueryDeviceRelations);
/// aqui ficam vazias.
fn device_relations(relation: u32, device: &str) -> Result<Vec<String>, u32> {
    let node = node_of(device).ok_or(STATUS_NO_SUCH_DEVICE)?;
    Ok(if relation == 0x20 { node.children.iter().filter_map(|&pdo| devnode::get(pdo).map(|child| child.instance_path)).collect() } else { Vec::new() })
}

/// O chamador é o SYSTEM ou administrador (a aproximação do
/// PiAuDoesClientHaveAccess(2) no PiAuSecurityObject).
fn caller_is_system_or_admin() -> bool {
    let process = crate::ntos::ps::process::get_current_process();
    let Some(token) = crate::ntos::ps::process::get_primary_token(process) else { return false };
    let system = crate::ntos::se::token::tokens::with(token, |token| token.user == crate::ntos::se::model::sid(5, &[18])).unwrap_or(false);
    system || crate::ntos::se::token::information::is_admin(token)
}

/// PiCMGetDeviceIdList (0x200; 19041 0x689bd4).
fn get_device_id_list(buffers: &Buffers) -> (u32, u64) {
    let input = match capture_device_list_input(buffers) {
        Ok(input) => input,
        Err(status) => return (status, 0),
    };
    if buffers.output == 0 || buffers.output_length < 0x14 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    // 0x20000 (sem o filtro obrigatório) exige o acesso ao objeto de
    // segurança do PnP: aqui, SYSTEM ou administrador.
    if input.flags & 0x2_0000 != 0 && !caller_is_system_or_admin() {
        return return_buffer(buffers, STATUS_ACCESS_DENIED, 0, 0, &[], input.result_size);
    }
    let capacity = match buffers.output_length - 0x14 {
        room if room >= 2 => room,
        _ => 0,
    };
    let kind = input.flags & 0xFFFF;
    let present = input.flags & LIST_PRESENT != 0;
    let result = if !matches!(kind, 0 | 1 | 2 | 4 | 8 | 0x10 | 0x20 | 0x40 | 0x80) || input.flags & 0xFFFC_0000 != 0 {
        Err(STATUS_INVALID_PARAMETER)
    } else {
        match (kind, input.filter.as_deref()) {
            (0, _) => enum_instances(None, present, &|_| true),
            (_, None) => Err(STATUS_INVALID_PARAMETER),
            (1, Some(enumerator)) => enum_instances(Some(enumerator), present, &|_| true),
            (2, Some(service)) => enum_instances(None, present, &|id| service_matches(id, service)),
            (0x80, Some(class)) => enum_instances(None, present, &|id| class_matches(id, class)),
            (relation, Some(device)) => device_relations(relation, device),
        }
    };
    let (status, required, data) = match result {
        Err(status) => (status, 0, Vec::new()),
        Ok(ids) => {
            let bytes = multi_sz_bytes(&ids);
            let required = bytes.len() as u32;
            if required > capacity { (STATUS_BUFFER_TOO_SMALL, required, Vec::new()) } else { (0, required, bytes) }
        }
    };
    return_buffer(buffers, status, required, 0, &data, input.result_size)
}

/// CmValidateDeviceName: até 200 WCHARs, só de 0x21 a 0x7F e sem vírgula,
/// em exatamente três componentes não vazios separados por `\`.
pub fn validate_device_name(name: &str) -> u32 {
    let units: Vec<u16> = name.encode_utf16().collect();
    if units.is_empty() || units.len() >= 200 || units.iter().any(|&unit| !(0x21..=0x7F).contains(&unit) || unit == u16::from(b',')) {
        return STATUS_OBJECT_NAME_INVALID;
    }
    let components: Vec<&str> = name.split('\\').collect();
    if components.len() != 3 || components.iter().any(|component| component.is_empty()) {
        return STATUS_OBJECT_NAME_INVALID;
    }
    0
}

/// DN_* do PiControlGetUserFlagsFromDeviceNode, pelo estado do nó: sempre
/// DN_NT_ENUMERATOR|DN_NT_DRIVER; DN_DRIVER_LOADED com os recursos
/// atribuídos ou iniciado; DN_STARTED; DN_ROOT_ENUMERATED pelo prefixo
/// `Root\`; DN_REMOVABLE pela capacidade; DN_HAS_PROBLEM com um problema; e
/// DN_DISABLEABLE (nenhum dependente impede desabilitar).
pub fn device_node_status(node: &devnode::DeviceNode) -> (u32, u32, u32) {
    const DN_ROOT_ENUMERATED: u32 = 0x1;
    const DN_DRIVER_LOADED: u32 = 0x2;
    const DN_STARTED: u32 = 0x8;
    const DN_HAS_PROBLEM: u32 = 0x400;
    const DN_DISABLEABLE: u32 = 0x2000;
    const DN_REMOVABLE: u32 = 0x4000;
    const DN_NT_ENUMERATOR: u32 = 0x80_0000;
    const DN_NT_DRIVER: u32 = 0x100_0000;
    let mut status = DN_NT_ENUMERATOR | DN_NT_DRIVER | DN_DISABLEABLE;
    if matches!(node.state, devnode::State::ResourcesAssigned | devnode::State::Started) {
        status |= DN_DRIVER_LOADED;
    }
    if node.state == devnode::State::Started {
        status |= DN_STARTED;
    }
    if node.instance_path.get(..5).is_some_and(|prefix| prefix.eq_ignore_ascii_case("Root\\")) {
        status |= DN_ROOT_ENUMERATED;
    }
    if node.capability_bit(devnode::capability::REMOVABLE) {
        status |= DN_REMOVABLE;
    }
    let problem = if node.state == devnode::State::Failed { node.problem } else { 0 };
    if problem != 0 {
        status |= DN_HAS_PROBLEM;
    }
    (status, problem, 0)
}

/// O nó de um caminho de instância.
fn node_of(name: &str) -> Option<devnode::DeviceNode> {
    devnode::by_instance_path(name).and_then(devnode::get)
}

/// PiCMGetDeviceStatus (0x209): nome, flags 0, tipo dispositivo, parâmetro
/// 0 e saída de 0x14 bytes; o CmGetDeviceStatus do nó (sem nó:
/// STATUS_NO_SUCH_DEVICE).
fn get_device_status(buffers: &Buffers) -> (u32, u64) {
    let input = match capture_object_input(buffers) {
        Ok(input) => input,
        Err(status) => return (status, 0),
    };
    let valid = input.name.is_some() && input.flags == 0 && input.object_type == 1 && input.parameter == 0 && buffers.output != 0 && buffers.output_length >= 0x14;
    let (status, device) = match (valid, input.name.as_deref().and_then(node_of)) {
        (false, _) => (STATUS_INVALID_PARAMETER, (0, 0, 0)),
        (true, None) => (STATUS_NO_SUCH_DEVICE, (0, 0, 0)),
        (true, Some(node)) => (0, device_node_status(&node)),
    };
    return_status(buffers, status, device, input.result_size)
}

/// PiCMValidateDeviceInstance (0x210, o CM_Locate_DevNode): flags 1 (só
/// presentes) ou 2 (também fantasmas), tipo dispositivo, parâmetro 0 e
/// saída de 8 bytes. A chave `Enum\<instância>` tem de existir; com flags 1
/// o nó também (senão STATUS_NO_SUCH_DEVICE); com flags 2 basta a chave não
/// ter o valor `Phantom` diferente de zero.
fn validate_device_instance(buffers: &Buffers) -> (u32, u64) {
    let input = match capture_object_input(buffers) {
        Ok(input) => input,
        Err(status) => return (status, 0),
    };
    let valid = input.name.is_some() && (1..=2).contains(&input.flags) && input.object_type == 1 && input.parameter == 0 && buffers.output != 0 && buffers.output_length >= 8;
    let status = match input.name.as_deref() {
        Some(name) if valid => {
            let key = alloc::format!("{}\\Enum\\{}", super::install::CONTROL_SET, name);
            if crate::ntos::cm::registry::node_by_path(&key).is_none() {
                STATUS_NO_SUCH_DEVICE
            } else if input.flags == 2 {
                let phantom = crate::ntos::cm::registry::read_value_by_path(&key, "Phantom").filter(|value| value.value_type == 4 && value.data.len() == 4).is_some_and(|value| value.data != [0; 4]);
                if phantom { STATUS_NO_SUCH_DEVICE } else { 0 }
            } else if node_of(name).is_some() {
                0
            } else {
                STATUS_NO_SUCH_DEVICE
            }
        }
        _ => STATUS_INVALID_PARAMETER,
    };
    return_basic(buffers, status, input.result_size)
}

/// PiCMGetDeviceDepth (0x20A): o Level do nó (PiGetDeviceDepth), depois do
/// CmValidateDeviceName.
fn get_device_depth(buffers: &Buffers) -> (u32, u64) {
    let input = match capture_object_input(buffers) {
        Ok(input) => input,
        Err(status) => return (status, 0),
    };
    let valid = input.name.is_some() && input.flags == 0 && input.object_type == 1 && input.parameter == 0 && buffers.output != 0 && buffers.output_length >= 0xC;
    let (status, depth) = match input.name.as_deref() {
        Some(name) if valid => match validate_device_name(name) {
            0 => node_of(name).map_or((STATUS_NO_SUCH_DEVICE, 0), |node| (0, node.level)),
            invalid => (invalid, 0),
        },
        _ => (STATUS_INVALID_PARAMETER, 0),
    };
    return_depth(buffers, status, depth, input.result_size)
}

/// PiCMGetRelatedDeviceInstance (0x208): o parâmetro escolhe o pai (1), o
/// primeiro filho (2) ou o próximo irmão (3; a raiz não tem irmão); o
/// resultado é o caminho da instância com o NUL. Um caminho que não cabe no
/// que sobra da saída depois do cabeçalho (STATUS_BUFFER_TOO_SMALL com o
/// tamanho pedido) faz o PiCMReturnBufferResultData recusar o próprio IOCTL
/// (STATUS_INVALID_PARAMETER).
fn get_related_device_instance(buffers: &Buffers) -> (u32, u64) {
    let input = match capture_object_input(buffers) {
        Ok(input) => input,
        Err(status) => return (status, 0),
    };
    let valid = input.name.is_some() && input.flags == 0 && input.object_type == 1 && buffers.output != 0 && buffers.output_length >= 0x14;
    let capacity = buffers.output_length.saturating_sub(0x14) as usize;
    let related = |name: &str| -> Result<String, u32> {
        match validate_device_name(name) {
            0 => {}
            invalid => return Err(invalid),
        }
        let node = node_of(name).ok_or(STATUS_NO_SUCH_DEVICE)?;
        let target = match input.parameter {
            1 => node.parent,
            2 => node.children.first().copied().unwrap_or(0),
            3 => {
                if node.pdo == devnode::root() {
                    return Err(STATUS_NO_SUCH_DEVICE);
                }
                let siblings = devnode::get(node.parent).map(|parent| parent.children).unwrap_or_default();
                siblings.iter().position(|&pdo| pdo == node.pdo).and_then(|index| siblings.get(index + 1).copied()).unwrap_or(0)
            }
            _ => return Err(STATUS_INVALID_PARAMETER),
        };
        devnode::get(target).map(|node| node.instance_path).ok_or(STATUS_NO_SUCH_DEVICE)
    };
    let (status, data) = match input.name.as_deref() {
        Some(name) if valid => match related(name) {
            Ok(path) => {
                let bytes: Vec<u8> = path.encode_utf16().chain(core::iter::once(0)).flat_map(|unit| unit.to_le_bytes()).collect();
                if bytes.len() > capacity {
                    return (STATUS_INVALID_PARAMETER, 0);
                }
                (0, bytes)
            }
            Err(status) => (status, Vec::new()),
        },
        _ => (STATUS_INVALID_PARAMETER, Vec::new()),
    };
    return_buffer(buffers, status, data.len() as u32, 0, &data, input.result_size)
}

/// O pedido de propriedade do cfgmgr32 depois do
/// PiCMCapturePropertyInputData (19041 0x6adbb4; 64 bits: 0x48 bytes, Size
/// em +0): +4 os flags, +8 o tipo do objeto, +0x10/+0x18 o nome, +0x1C o
/// DEVPROPKEY (FMTID e PID), +0x30 e +0x38/+0x40 (um segundo texto) que a
/// leitura exige zerados, e +0x44 o tamanho do resultado esperado.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PropertyInput {
    pub flags: u32,
    pub object_type: u32,
    pub name: Option<String>,
    pub fmtid: [u8; 16],
    pub pid: u32,
    pub reserved: u32,
    pub second: Option<String>,
    pub result_size: u32,
}

pub fn capture_property_input(buffers: &Buffers) -> Result<PropertyInput, u32> {
    let (bytes, user) = capture_fixed(buffers, 0x48)?;
    let pointer = |offset: usize| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap_or([0; 8]));
    let name = capture_name(pointer(0x10), u32_at(&bytes, 0x18), user)?;
    let second = capture_name(pointer(0x38), u32_at(&bytes, 0x40), user)?;
    let mut fmtid = [0u8; 16];
    fmtid.copy_from_slice(&bytes[0x1C..0x2C]);
    Ok(PropertyInput { flags: u32_at(&bytes, 4), object_type: u32_at(&bytes, 8), name, fmtid, pid: u32_at(&bytes, 0x2C), reserved: u32_at(&bytes, 0x30), second, result_size: u32_at(&bytes, 0x44) })
}

/// PiCMGetObjectProperty (0x204; 19041 0x6ad91c): o nome é obrigatório e os
/// flags, +0x30 e o segundo texto têm de vir zerados, com saída de ao menos
/// 0x14 bytes (senão STATUS_INVALID_PARAMETER no resultado). O tipo do
/// objeto vira o do PnP: dispositivo (1) e interface (2) pelo armazenamento
/// de propriedades (`io/device_property.rs`); contêiner (3), classe de
/// interface (4), classe de instalação (5), 6 e os objetos do banco de
/// drivers (0x10001..0x10005) não têm armazenamento no OpenNT e respondem
/// STATUS_NOT_FOUND; outro tipo é STATUS_INVALID_PARAMETER. O resultado é o
/// do PiCMReturnBufferResultData: Required = o tamanho da propriedade e
/// Extra = o DEVPROPTYPE, com os dados só no sucesso; buffer curto é
/// STATUS_BUFFER_TOO_SMALL com o tamanho e o tipo.
fn get_object_property(buffers: &Buffers) -> (u32, u64) {
    use crate::ntos::io::device_property::{named_object_property, NamedObject};
    let input = match capture_property_input(buffers) {
        Ok(input) => input,
        Err(status) => return (status, 0),
    };
    let valid = input.name.is_some() && input.flags == 0 && input.reserved == 0 && input.second.is_none() && buffers.output != 0 && buffers.output_length >= 0x14;
    let name = input.name.as_deref().unwrap_or("");
    let found = match input.object_type {
        _ if !valid => Err(STATUS_INVALID_PARAMETER),
        1 => named_object_property(NamedObject::Device(name), input.fmtid, input.pid),
        2 => named_object_property(NamedObject::Interface(name), input.fmtid, input.pid),
        3..=6 | 0x1_0001..=0x1_0005 => Err(STATUS_NOT_FOUND),
        _ => Err(STATUS_INVALID_PARAMETER),
    };
    let (status, required, property_type, data) = match found {
        Ok((property_type, bytes)) if (bytes.len() as u64) > (buffers.output_length - 0x14) as u64 => (STATUS_BUFFER_TOO_SMALL, bytes.len() as u32, property_type, Vec::new()),
        Ok((property_type, bytes)) => (0, bytes.len() as u32, property_type, bytes),
        Err(status) => (status, 0, 0, Vec::new()),
    };
    return_buffer(buffers, status, required, property_type, &data, input.result_size)
}

/// PiCMHandleIoctl: NTSTATUS e o Information.
pub fn handle_ioctl(code: u32, buffers: &Buffers) -> (u32, u64) {
    match code {
        code::GET_OBJECT_PROPERTY => get_object_property(buffers),
        code::GET_DEVICE_STATUS => get_device_status(buffers),
        code::VALIDATE_DEVICE_INSTANCE => validate_device_instance(buffers),
        code::GET_DEVICE_DEPTH => get_device_depth(buffers),
        code::GET_RELATED_DEVICE_INSTANCE => get_related_device_instance(buffers),
        code::GET_DEVICE_ID_LIST => get_device_id_list(buffers),
        code::GET_DEVICE_INTERFACE_LIST => get_device_interface_list(buffers),
        _ => match handler_name(code) {
            Some(name) => {
                debug_print!("[pnp] CMApi: {} ({:#x}) sem suporte no kernel", name, code);
                (STATUS_NOT_IMPLEMENTED, 0)
            }
            None => (STATUS_NOT_SUPPORTED, 0),
        },
    }
}

/// PiCMDispatch(DeviceObject, Irp).
pub fn dispatch(irp: &Irp, location: &IoStackLocation) -> u32 {
    let current = irp.io_status.status.get() as u32;
    if current & 0x8000_0000 != 0 {
        return device_api::complete(irp, current);
    }
    let status = match location.major_function.get() {
        IRP_MJ_CREATE | IRP_MJ_CLOSE | IRP_MJ_CLEANUP => 0,
        IRP_MJ_DEVICE_CONTROL => STATUS_NOT_SUPPORTED,
        _ => current,
    };
    device_api::complete(irp, status)
}

/// PiCMFastIoDeviceDispatch: sempre TRUE, com o resultado no IoStatus.
pub fn fast_io_device_control(request: &FastIoRequest) -> Result<bool, KernelError> {
    // IoIs32bitProcess(NULL): os processos do OpenNT são todos de 64 bits.
    let buffers = Buffers { input: request.input, input_length: request.input_length, output: request.output, output_length: request.output_length, is_32bit: false };
    let (status, information) = handle_ioctl(request.code, &buffers);
    // SAFETY: o IO_STATUS_BLOCK que o I/O Manager passa ao Fast I/O.
    let io_status = unsafe { IoStatusBlock::at(request.io_status) };
    io_status.information.set(information);
    io_status.status.set(status as i32);
    Ok(true)
}
