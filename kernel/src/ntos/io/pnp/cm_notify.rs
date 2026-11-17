//! As notificações de eventos de dispositivo para o modo usuário
//! (`\Device\DeviceApi\CMNotify`), por onde o CM_Register_Notification do
//! cfgmgr32 recebe chegada e remoção de interfaces e de dispositivos.
//!
//! PiUEventDispatch (ntoskrnl 19041, rva 0x715380): IRP_MJ_CREATE zera o
//! FsContext2 do FILE_OBJECT (o contexto de registro do cliente); CLOSE
//! libera o contexto que estiver nele; CLEANUP conclui com sucesso;
//! DEVICE_CONTROL vai ao PiUEventHandleIoctl; os demais concluem com
//! STATUS_NOT_SUPPORTED. Um IRP que chega com falha no IoStatus volta com
//! ela, sem conclusão.
//!
//! PiUEventHandleIoctl (rva 0x71541c) despacha quatro IOCTLs, todos
//! METHOD_BUFFERED, e conclui o IRP com o status:
//!
//! - 0x470800, o registro (PiUEventHandleRegistration, rva 0x715870). A
//!   entrada tem exatamente 0x3A8 bytes (o nome do módulo, WCHAR[0x104], e o
//!   CM_NOTIFY_FILTER de 0x1A0 bytes em +0x208) e a saída exatamente 8;
//!   senão STATUS_INVALID_PARAMETER. O PiUEventInitClientRegistrationContext
//!   cria o contexto e um nome WNF temporário de escopo de máquina
//!   (ZwCreateWnfStateName, MaximumStateSize 4) cujo descritor tem o SYSTEM
//!   como dono e a DACL SYSTEM GENERIC_ALL, Everyone, ALL APPLICATION
//!   PACKAGES, Low Mandatory Level e a capability `lpacPnpNotifications`
//!   com o bit 1, todas com CONTAINER_INHERIT_ACE. O nome do módulo precisa
//!   de um NUL nos 0x104 caracteres; o filtro, cbSize 0x1A0, Flags só com os
//!   bits 0 e 1 e FilterType menor que 4. O bit 0
//!   (CM_NOTIFY_FILTER_FLAG_ALL_INTERFACE_CLASSES) só vale com FilterType 0
//!   (interface); o bit 1 (ALL_DEVICE_INSTANCES), com FilterType 2 ou 3. O
//!   FilterType 1 (handle de dispositivo) recusa os handles 0 e -1; o 2 e o
//!   3 levam um texto de até 200 caracteres. A saída recebe o nome WNF, o
//!   Information é 8 e o contexto fica no FsContext2. Qualquer recusa depois
//!   do contexto o libera e zera o FsContext2.
//! - 0x47080C, o fim do registro (PiUEventHandleUnregisterClient): desliga o
//!   contexto do FsContext2 (STATUS_INVALID_PARAMETER sem contexto).
//! - 0x470804 (GetEvent) e 0x470808 (Veto): a entrega de eventos. O OpenNT
//!   ainda não publica eventos de dispositivo para o modo usuário; os dois
//!   devolvem STATUS_NOT_IMPLEMENTED.
//! - Qualquer outro código: STATUS_NOT_SUPPORTED.
//!
//! O PiUEventFreeClientRegistrationContext (o CLOSE e as recusas) tira o
//! contexto das listas, apaga o nome WNF (ZwDeleteWnfStateName) e o libera.
//! O FilterType 1 (o PiUEventGetDeviceInstanceIdFromUserHandle, que acha a
//! instância do dispositivo a partir do handle) ainda não tem suporte e
//! devolve STATUS_NOT_IMPLEMENTED.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::inc::types::{FileObject, IoStackLocation, Irp};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::se::model::sid;
use crate::rtl::{KernelError, SpinLock};

use super::device_api;

const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

const IRP_MJ_CREATE: u8 = 0x00;
const IRP_MJ_CLOSE: u8 = 0x02;
const IRP_MJ_DEVICE_CONTROL: u8 = 0x0E;
const IRP_MJ_CLEANUP: u8 = 0x12;

const IOCTL_REGISTER: u32 = 0x47_0800;
const IOCTL_GET_EVENT: u32 = 0x47_0804;
const IOCTL_VETO: u32 = 0x47_0808;
const IOCTL_UNREGISTER: u32 = 0x47_080C;

/// O pedido de registro: WCHAR ModuleName[0x104] e o CM_NOTIFY_FILTER.
const REGISTRATION_INPUT: u32 = 0x3A8;
const MODULE_NAME_CHARACTERS: usize = 0x104;
const FILTER_OFFSET: usize = 0x208;
const FILTER_SIZE: u32 = 0x1A0;
/// O texto de um filtro por instância (MAX_DEVICE_ID_LEN).
const INSTANCE_CHARACTERS: usize = 200;
const FLAG_ALL_INTERFACE_CLASSES: u32 = 1;
const FLAG_ALL_DEVICE_INSTANCES: u32 = 2;
const FILTER_DEVICE_INTERFACE: u32 = 0;
const FILTER_DEVICE_HANDLE: u32 = 1;

/// WnfTemporaryStateName e WnfDataScopeMachine.
const WNF_TEMPORARY_STATE_NAME: u32 = 3;
const WNF_DATA_SCOPE_MACHINE: u32 = 4;
/// O tamanho do contexto de registro (ExAllocatePoolWithTag 0x90, 'PnpY').
const CONTEXT_SIZE: u64 = 0x90;

/// O alvo de um registro.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// Uma classe de interface (None = todas as classes).
    Interface(Option<[u8; 16]>),
    /// Uma instância de dispositivo pelo texto (None = todas).
    Instance(u32, Option<String>),
}

/// Um contexto de registro (o bloco do FsContext2).
#[derive(Clone, Debug)]
pub struct Registration {
    pub state_name: u64,
    pub process_id: u64,
    pub target: Option<Target>,
    pub active: bool,
}

/// PiUEventDevInterfaceClientList e PiUEventDevInstanceClientList, sob o
/// PiUEventClientRegistrationListLock: o contexto e o registro.
static REGISTRATIONS: SpinLock<BTreeMap<u64, Registration>> = SpinLock::new(BTreeMap::new());

/// Os registros vivos (para os autotestes e o diagnóstico).
pub fn registrations() -> Vec<(u64, Registration)> {
    REGISTRATIONS.lock().iter().map(|(&context, registration)| (context, registration.clone())).collect()
}

/// O descritor absoluto do nome WNF de um registro, num bloco de kernel.
fn state_name_descriptor() -> Result<u64, KernelError> {
    let sids: [Vec<u8>; 5] = [sid(5, &[18]), sid(1, &[0]), sid(15, &[2, 1]), sid(16, &[0x1000]), crate::ntos::se::capability::identifiers::capability_sid("lpacPnpNotifications")];
    let sid_bytes: usize = sids.iter().map(Vec::len).sum();
    let acl_size = 0x30 + sid_bytes as u32;
    let block = guest::alloc_bytes(0x28 + acl_size as u64 + sid_bytes as u64);
    if block == 0 {
        return Err(KernelError::with_status("CMNotify: sem memoria para o descritor", STATUS_INSUFFICIENT_RESOURCES));
    }
    let (descriptor, acl) = (block, block + 0x28);
    let mut cursor = acl + acl_size as u64;
    let mut addresses = [0u64; 5];
    for (address, bytes) in addresses.iter_mut().zip(&sids) {
        guest::write_bytes(cursor, bytes);
        *address = cursor;
        cursor += bytes.len() as u64;
    }
    use crate::ntos::se::{acl as acls, descriptor as descriptors};
    const CONTAINER_INHERIT_ACE: u32 = 2;
    let mut status = descriptors::create(descriptor, 1);
    if status == 0 {
        status = descriptors::set_owner(descriptor, addresses[0], true);
    }
    if status == 0 {
        status = acls::create(acl, acl_size, 2);
    }
    for (index, &address) in addresses.iter().enumerate() {
        if status == 0 {
            status = acls::add_known_ace(acl, 2, CONTAINER_INHERIT_ACE, if index == 0 { 0x1000_0000 } else { 1 }, address, 0);
        }
    }
    if status == 0 {
        status = descriptors::set_dacl(descriptor, true, acl, false);
    }
    if status != 0 {
        guest::free_bytes(block);
        return Err(KernelError::with_status("CMNotify: descritor do nome WNF", status));
    }
    Ok(block)
}

/// PiUEventInitClientRegistrationContext: o contexto e o nome WNF.
fn create_context() -> Result<Option<u64>, KernelError> {
    let descriptor = state_name_descriptor()?;
    let cell = guest::alloc_bytes(8);
    if cell == 0 {
        guest::free_bytes(descriptor);
        return Ok(None);
    }
    guest::write64(cell, 0);
    let request = crate::ntos::ex::wnf::service::CreateName {
        output: cell,
        lifetime: WNF_TEMPORARY_STATE_NAME,
        scope: WNF_DATA_SCOPE_MACHINE,
        persist: false,
        type_identifier: 0,
        maximum_size: 4,
        security_descriptor: descriptor,
    };
    let status = crate::ntos::ex::wnf::service::create_state_name(&request);
    let state_name = guest::read64(cell);
    guest::free_bytes(cell);
    guest::free_bytes(descriptor);
    if status? != 0 {
        return Ok(None);
    }
    let context = guest::alloc_bytes(CONTEXT_SIZE);
    if context == 0 {
        let _ = crate::ntos::ex::wnf::service::delete_state_name_kernel(state_name);
        return Ok(None);
    }
    guest::write_bytes(context, &[0u8; CONTEXT_SIZE as usize]);
    let registration = Registration { state_name, process_id: crate::ntos::ps::process::get_current_process_id(), target: None, active: true };
    REGISTRATIONS.lock().insert(context, registration);
    Ok(Some(context))
}

/// PiUEventFreeClientRegistrationContext.
fn free_context(context: u64) {
    let Some(registration) = REGISTRATIONS.lock().remove(&context) else { return };
    let _ = crate::ntos::ex::wnf::service::delete_state_name_kernel(registration.state_name);
    guest::free_bytes(context);
}

/// Os caracteres antes do NUL, se houver um NUL nos primeiros `limit`
/// (RtlStringCchLengthW).
fn wide_string(bytes: &[u8], limit: usize) -> Option<String> {
    let units: Vec<u16> = bytes.chunks_exact(2).take(limit).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    let length = units.iter().position(|&unit| unit == 0)?;
    Some(String::from_utf16_lossy(&units[..length]))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

/// O filtro validado: o alvo do registro ou o status da recusa.
fn parse_filter(input: &[u8]) -> Result<Target, u32> {
    wide_string(input, MODULE_NAME_CHARACTERS).ok_or(STATUS_INVALID_PARAMETER)?;
    let filter = &input[FILTER_OFFSET..];
    let (size, flags, filter_type) = (read_u32(filter, 0), read_u32(filter, 4), read_u32(filter, 8));
    if size != FILTER_SIZE || filter_type as i32 >= 4 || flags & !3 != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if flags & FLAG_ALL_INTERFACE_CLASSES != 0 && filter_type != FILTER_DEVICE_INTERFACE {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if flags & FLAG_ALL_DEVICE_INSTANCES != 0 && !(2..=3).contains(&filter_type) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // O union do filtro, em +0x10 do CM_NOTIFY_FILTER.
    let union = &filter[0x10..];
    match filter_type {
        FILTER_DEVICE_INTERFACE => {
            let mut guid = [0u8; 16];
            guid.copy_from_slice(&union[..16]);
            Ok(Target::Interface((flags & FLAG_ALL_INTERFACE_CLASSES == 0).then_some(guid)))
        }
        FILTER_DEVICE_HANDLE => {
            let handle = u64::from_le_bytes(union[..8].try_into().unwrap_or([0; 8]));
            if handle.wrapping_add(1) & !1 == 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            crate::debug_print!("[pnp] CMNotify: registro por handle de dispositivo sem suporte");
            Err(STATUS_NOT_IMPLEMENTED)
        }
        _ => {
            let text = wide_string(union, INSTANCE_CHARACTERS).ok_or(STATUS_INVALID_PARAMETER)?;
            Ok(Target::Instance(filter_type, (flags & FLAG_ALL_DEVICE_INSTANCES == 0).then_some(text)))
        }
    }
}

/// PiUEventHandleRegistration(FileObject, SystemBuffer, InputLength,
/// OutputLength, IoStatus): o status e o Information.
pub fn register(file: &FileObject, buffer: u64, input_length: u32, output_length: u32) -> Result<(u32, u64), KernelError> {
    if buffer == 0 || input_length != REGISTRATION_INPUT || output_length != 8 {
        return Ok((STATUS_INVALID_PARAMETER, 0));
    }
    let Some(context) = create_context()? else { return Ok((STATUS_INSUFFICIENT_RESOURCES, 0)) };
    let input = guest::read_bytes(buffer, REGISTRATION_INPUT as usize);
    let target = match parse_filter(&input) {
        Ok(target) => target,
        Err(status) => {
            free_context(context);
            file.fs_context2.set(0);
            return Ok((status, 0));
        }
    };
    let state_name = {
        let mut registrations = REGISTRATIONS.lock();
        let Some(registration) = registrations.get_mut(&context) else { return Ok((STATUS_INVALID_PARAMETER, 0)) };
        registration.target = Some(target);
        registration.state_name
    };
    guest::write64(buffer, state_name);
    file.fs_context2.set(context);
    Ok((0, 8))
}

/// PiUEventHandleUnregisterClient(FileObject).
pub fn unregister(file: &FileObject) -> u32 {
    let context = file.fs_context2.get();
    match REGISTRATIONS.lock().get_mut(&context) {
        Some(registration) if context != 0 => {
            registration.active = false;
            0
        }
        _ => STATUS_INVALID_PARAMETER,
    }
}

/// PiUEventDispatch(DeviceObject, Irp).
pub fn dispatch(_device: u64, irp: &Irp, location: &IoStackLocation, file: &FileObject) -> Result<u32, KernelError> {
    let current = irp.io_status.status.get() as u32;
    if current & 0x8000_0000 != 0 {
        return Ok(current);
    }
    Ok(match location.major_function.get() {
        IRP_MJ_CREATE => {
            file.fs_context2.set(0);
            device_api::complete(irp, 0)
        }
        IRP_MJ_CLOSE => {
            let context = file.fs_context2.get();
            if context != 0 {
                free_context(context);
            }
            file.fs_context2.set(0);
            device_api::complete(irp, 0)
        }
        IRP_MJ_CLEANUP => device_api::complete(irp, 0),
        IRP_MJ_DEVICE_CONTROL => {
            let control = &location.parameters.device_io_control;
            let (status, information) = match control.io_control_code.get() {
                IOCTL_REGISTER => register(file, irp.associated_irp.system_buffer.get(), control.input_buffer_length.get(), control.output_buffer_length.get())?,
                IOCTL_UNREGISTER => (unregister(file), 0),
                code @ (IOCTL_GET_EVENT | IOCTL_VETO) => {
                    crate::debug_print!("[pnp] CMNotify: IOCTL {:#x} (entrega de eventos) sem suporte no kernel", code);
                    (STATUS_NOT_IMPLEMENTED, 0)
                }
                _ => (STATUS_NOT_SUPPORTED, 0),
            };
            irp.io_status.information.set(information);
            device_api::complete(irp, status)
        }
        _ => device_api::complete(irp, STATUS_NOT_SUPPORTED),
    })
}
