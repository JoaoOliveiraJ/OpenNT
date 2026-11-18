//! Notificações PnP — IoRegisterPlugPlayNotification,
//! IoUnregisterPlugPlayNotification[Ex], IoReportTargetDeviceChange e
//! IoReportTargetDeviceChangeAsynchronous.
//!
//! O handle devolvido é o registro nativo. Mudanças de interface de
//! dispositivo chegam aos registros da classe (DEVICE_INTERFACE_CHANGE_
//! NOTIFICATION); mudanças de dispositivo chegam aos registros de
//! EventCategoryTargetDeviceChange daquele dispositivo, as agendadas por um
//! work item.
//!
//! Como no ntoskrnl 19041:
//!
//! - um registro de EventCategoryTargetDeviceChange fica ligado ao PDO por
//!   trás do FILE_OBJECT (o PnpGetRelatedTargetDevice do
//!   IoRegisterPlugPlayNotification 0x69bfe0, que guarda o PDO referenciado
//!   e o FILE_OBJECT no registro); o PnpNotifyTargetDeviceChange 0x71ac58 só
//!   percorre os registros do devnode do PDO do evento e grava em
//!   NotificationStructure->FileObject o FILE_OBJECT de cada registro antes
//!   de chamá-lo;
//! - um callback em espaço de sessão (o RIMDeviceClassNotify do win32kbase,
//!   o DeviceClassCDROMNotify do win32kfull) guarda a sessão de quem
//!   registrou (o PnpInitializeNotifyEntry 0x69c4b4: MmGetSessionIdEx do
//!   processo corrente, -1 dá STATUS_INVALID_PARAMETER, e o objeto
//!   `\KernelObjects\Session<id>` retido no registro, sem ele também
//!   STATUS_INVALID_PARAMETER). O PnpNotifyDriverCallback 0x71b5b4 chama
//!   direto quando o processo corrente está nessa sessão; senão (0x84a88c)
//!   pega um processo dela (MmGetSessionById; nenhum dá STATUS_UNSUCCESSFUL
//!   e o callback não roda), anexa (MmAttachSession), chama e desanexa. As
//!   imagens de sessão de todas as sessões ficam na mesma VA: sem a anexação
//!   a chamada vinda de um work item do System (sem o slot de sessão) ou de
//!   outra sessão cairia em página ausente ou na cópia de outra sessão.
//!
//! Lacuna: o PnpNotifyTargetDeviceChange também restringe os registros de
//! sessão à sessão do PDO (IopGetSessionIdFromPDO); o OpenNT não tem
//! dispositivos por sessão, e esse id é sempre -1 (todos recebem).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::hal::amd64::native_call;
use crate::ntos::io::{device_interface, work_items};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::{session, session_object};
use crate::ntos::ob::{object_header, object_reference, reference_trace};
use crate::ntos::ps::process;
use crate::ntos::rtl::guest_strings;
use crate::ntos::inc::field::{Field, Reserved};
use crate::ntos::inc::types::{DeviceInterfaceChangeNotification, Eprocess, Guid, KapcState, NtStruct, UnicodeString};
use crate::rtl::SpinLock;

const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;

/// Registro de notificação PnP (o handle é o registro nativo).
#[derive(Clone, Copy)]
struct PlugPlayRegistration {
    category: u32,
    /// GUID da classe de interface (EventCategoryDeviceInterfaceChange).
    class: [u8; 16],
    callback: u64,
    context: u64,
    record: u64,
    /// EventCategoryTargetDeviceChange: o FILE_OBJECT registrado e o PDO
    /// por trás dele (referenciado enquanto o registro vive).
    file_object: u64,
    device: u64,
    /// Callback em espaço de sessão: a sessão de quem registrou e o objeto
    /// Session dela, referenciado enquanto o registro vive.
    session: Option<RegistrationSession>,
}

#[derive(Clone, Copy)]
struct RegistrationSession {
    id: u32,
    object: u64,
}

const EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE: u32 = 2;
const EVENT_CATEGORY_TARGET_DEVICE_CHANGE: u32 = 3;
/// GUID_DEVICE_INTERFACE_ARRIVAL / _REMOVAL (wdmguid.h).
const INTERFACE_ARRIVAL: [u8; 16] = [0x04, 0x40, 0x3A, 0xCB, 0xF0, 0x46, 0xD0, 0x11, 0xB0, 0x8F, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3F];
const INTERFACE_REMOVAL: [u8; 16] = [0x05, 0x40, 0x3A, 0xCB, 0xF0, 0x46, 0xD0, 0x11, 0xB0, 0x8F, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3F];

/// Registro devolvido como NotificationEntry (privado do OpenNT; o driver
/// só o devolve ao IoUnregisterPlugPlayNotification).
#[repr(C)]
struct RegistrationRecord {
    callback: Field<u64>,
    context: Field<u64>,
    _reserved: Reserved<0x10>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for RegistrationRecord {}

const _: () = assert!(core::mem::size_of::<RegistrationRecord>() == 0x20);

/// O cabeçalho comum das notificações de dispositivo
/// (TARGET_DEVICE_CUSTOM_NOTIFICATION e TARGET_DEVICE_REMOVAL_NOTIFICATION
/// do wdm.h): Version, Size, Event e o FileObject que o PnP preenche com o
/// do registro.
#[repr(C)]
struct TargetDeviceNotificationHeader {
    version: Field<u16>,
    size: Field<u16>,
    _event: Reserved<0x10>,
    _pad: Reserved<0x4>,
    file_object: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for TargetDeviceNotificationHeader {}

const _: () = assert!(core::mem::offset_of!(TargetDeviceNotificationHeader, file_object) == 0x18);

static PLUG_PLAY_REGISTRATIONS: SpinLock<Vec<PlugPlayRegistration>> = SpinLock::new(Vec::new());
/// Mudanças de dispositivo agendadas: work item → (PDO, cópia da estrutura,
/// callback de conclusão, contexto).
static TARGET_CHANGES: SpinLock<BTreeMap<u64, (u64, u64, u64, u64)>> = SpinLock::new(BTreeMap::new());

fn eprocess(process: u64) -> &'static Eprocess {
    // SAFETY: o processo corrente, vivo enquanto a thread dele executa.
    unsafe { Eprocess::at(process) }
}

/// PnpNotifyDriverCallback: chama `callback(notification, context)` do
/// registro; um callback de sessão roda na sessão de quem registrou. Devolve
/// o status da entrega (não o do callback, que o PnP só usa nas consultas
/// de remoção).
fn notify_driver_callback(registration: &PlugPlayRegistration, notification: u64) -> u32 {
    if !session::is_session_address(registration.callback) {
        native_call::call(registration.callback, &[notification, registration.context]);
        return 0;
    }
    let Some(owner) = registration.session else { return STATUS_INVALID_PARAMETER };
    let current = process::get_current_process();
    if eprocess(current).process_in_session() != 0 && crate::ntos::ps::session::current_process_session_id() == owner.id {
        native_call::call(registration.callback, &[notification, registration.context]);
        return 0;
    }
    let target = session::by_id(owner.id);
    if target == 0 {
        return STATUS_UNSUCCESSFUL;
    }
    let apc_state = guest::alloc_bytes(KapcState::SIZE);
    let status = if apc_state == 0 {
        STATUS_UNSUCCESSFUL
    } else {
        let status = match session::attach(target, apc_state) {
            Ok(0) => {
                native_call::call(registration.callback, &[notification, registration.context]);
                session::detach(target, apc_state).unwrap_or(STATUS_UNSUCCESSFUL)
            }
            Ok(status) => status,
            Err(_) => STATUS_UNSUCCESSFUL,
        };
        guest::free_bytes(apc_state);
        status
    };
    let _ = process::dereference(target);
    status
}

/// DEVICE_INTERFACE_CHANGE_NOTIFICATION (Version, Size, Event,
/// InterfaceClassGuid, SymbolicLinkName) entregue a callback(estrutura,
/// contexto) de cada registro da classe.
fn notify_interface(registrations: &[PlugPlayRegistration], event: &[u8; 16], class: &[u8; 16], link: &str) {
    for registration in registrations.iter().filter(|registration| registration.category == EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE && registration.class == *class) {
        let units = link.encode_utf16().count() as u64;
        // DEVICE_INTERFACE_CHANGE_NOTIFICATION, o UNICODE_STRING do link e o texto.
        let notification = guest::alloc_bytes(DeviceInterfaceChangeNotification::SIZE + UnicodeString::SIZE + (units + 1) * 2);
        if notification == 0 {
            continue;
        }
        let string = notification + DeviceInterfaceChangeNotification::SIZE;
        let buffer = string + UnicodeString::SIZE;
        // SAFETY: estruturas dentro do bloco zerado recém-alocado.
        let (body, name) = unsafe { (DeviceInterfaceChangeNotification::at(notification), UnicodeString::at(string)) };
        body.version.set(1);
        body.size.set(DeviceInterfaceChangeNotification::SIZE as u16);
        guest::write_bytes(body.event.address(), event);
        guest::write_bytes(body.interface_class_guid.address(), class);
        body.symbolic_link_name.set(string);
        guest_strings::write_wide_string(buffer, link);
        name.length.set(units as u16 * 2);
        name.maximum_length.set(units as u16 * 2 + 2);
        name.buffer.set(buffer);
        notify_driver_callback(registration, notification);
        guest::free_bytes(notification);
    }
}

/// Chegada (`arrival`) ou remoção de uma interface para os registros da classe.
pub fn notify_interface_change(arrival: bool, class: &[u8; 16], link: &str) {
    let registrations = PLUG_PLAY_REGISTRATIONS.lock().clone();
    notify_interface(&registrations, if arrival { &INTERFACE_ARRIVAL } else { &INTERFACE_REMOVAL }, class, link);
}

/// Solta as referências de um registro que sai (ou que não chegou a entrar).
fn release_references(device: u64, session_object: u64) {
    if device != 0 {
        let _ = object_reference::dereference_with_tag(device, reference_trace::DEFAULT_TAG, true);
    }
    if session_object != 0 {
        object_header::dereference(session_object, false);
    }
}

/// IoRegisterPlugPlayNotification(EventCategory, EventCategoryFlags,
/// EventCategoryData, DriverObject, CallbackRoutine, Context,
/// NotificationEntry): assinatura do WDK; o handle é o registro.
/// PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES entrega as
/// interfaces já habilitadas da classe. Para EventCategoryTargetDeviceChange
/// o EventCategoryData é o FILE_OBJECT, e a falha do IoGetRelatedTargetDevice
/// dele é o status.
pub fn register(category: u32, flags: u32, data: u64, callback: u64, context: u64, output: u64) -> u32 {
    if callback == 0 || output == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let mut class = [0u8; 16];
    if category == EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE {
        if data == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        class.copy_from_slice(&guest::read_bytes(data, Guid::SIZE as usize));
    }
    let (file_object, device) = if category == EVENT_CATEGORY_TARGET_DEVICE_CHANGE {
        if data == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        match crate::ntos::io::pnp::related_target_device(data) {
            Ok((status, _)) if (status as i32) < 0 => return status,
            Ok((_, device)) => (data, device),
            Err(_) => return STATUS_UNSUCCESSFUL,
        }
    } else {
        (0, 0)
    };
    // PnpInitializeNotifyEntry: a sessão de um callback de sessão.
    let owner = if session::is_session_address(callback) {
        let id = session::session_id_ex(process::get_current_process());
        let object = if id == u32::MAX { 0 } else { session_object::by_id(id) };
        if object == 0 {
            release_references(device, 0);
            return STATUS_INVALID_PARAMETER;
        }
        Some(RegistrationSession { id, object })
    } else {
        None
    };
    let record = guest::alloc_bytes(RegistrationRecord::SIZE);
    if record == 0 {
        release_references(device, owner.map_or(0, |owner| owner.object));
        return 0xC000_009A;
    }
    // SAFETY: registro recém-alocado.
    let body = unsafe { RegistrationRecord::at(record) };
    body.callback.set(callback);
    body.context.set(context);
    let registration = PlugPlayRegistration { category, class, callback, context, record, file_object, device, session: owner };
    PLUG_PLAY_REGISTRATIONS.lock().push(registration);
    // SAFETY: PVOID* NotificationEntry do chamador de modo kernel.
    unsafe { Field::<u64>::at(output) }.set(record);
    if category == EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE && flags & 1 != 0 {
        let existing = device_interface::enabled_links(&class);
        // Diagnóstico dos registros de sessão (o RIT do win32k com as
        // classes de mouse, teclado e HID): quantas interfaces já
        // habilitadas ele recebeu.
        if let Some(owner) = owner {
            let data1 = u32::from_le_bytes([class[0], class[1], class[2], class[3]]);
            debug_print!("[pnp] notificacao de interface {:08x}-... da sessao {}: {} interface(s) existente(s)", data1, owner.id, existing.len());
        }
        for link in existing {
            notify_interface(&[registration], &INTERFACE_ARRIVAL, &class, &link);
        }
    }
    0
}

/// IoUnregisterPlugPlayNotification[Ex]: handle desconhecido =
/// STATUS_OBJECT_NAME_NOT_FOUND. O PDO e o objeto Session retidos voltam.
pub fn unregister(record: u64) -> u32 {
    let removed = {
        let mut registrations = PLUG_PLAY_REGISTRATIONS.lock();
        let Some(index) = registrations.iter().position(|registration| registration.record == record) else { return STATUS_OBJECT_NAME_NOT_FOUND };
        registrations.remove(index)
    };
    release_references(removed.device, removed.session.map_or(0, |owner| owner.object));
    guest::free_bytes(removed.record);
    0
}

/// PnpNotifyTargetDeviceChange: entrega a notificação aos registros de
/// EventCategoryTargetDeviceChange do PDO `device`, cada um com o próprio
/// FILE_OBJECT em NotificationStructure->FileObject.
fn notify_target_change(device: u64, notification: u64) {
    let registrations: Vec<PlugPlayRegistration> = PLUG_PLAY_REGISTRATIONS.lock().iter().filter(|registration| registration.category == EVENT_CATEGORY_TARGET_DEVICE_CHANGE && device != 0 && registration.device == device).copied().collect();
    // SAFETY: a cópia da notificação, memória do kernel com ao menos o
    // cabeçalho (`notification_size`).
    let header = unsafe { TargetDeviceNotificationHeader::at(notification) };
    for registration in &registrations {
        header.file_object.set(registration.file_object);
        notify_driver_callback(registration, notification);
    }
}

/// TARGET_DEVICE_CUSTOM_NOTIFICATION.Size (USHORT em +2), com o mínimo do
/// cabeçalho (até CustomDataBuffer, 0x24).
fn notification_size(notification: u64) -> u64 {
    // SAFETY: estrutura de notificação do chamador de modo kernel.
    (unsafe { TargetDeviceNotificationHeader::at(notification) }.size.get() as u64).max(0x24)
}

/// Uma cópia de Size bytes da estrutura do chamador (o evento PnP do NT leva
/// uma cópia; a do chamador pode morar na pilha dele e não é tocada).
fn copy_notification(notification: u64) -> u64 {
    let size = notification_size(notification);
    let copy = guest::alloc_bytes(size);
    if copy != 0 {
        guest::write_bytes(copy, &guest::read_bytes(notification, size as usize));
    }
    copy
}

/// Work item do IoReportTargetDeviceChangeAsynchronous: entrega a cópia da
/// estrutura, chama o callback de conclusão do chamador e libera a cópia.
fn deliver_target_change(_device: u64, item: u64) {
    let Some((device, notification, callback, context)) = TARGET_CHANGES.lock().remove(&item) else { return };
    notify_target_change(device, notification);
    if callback != 0 {
        native_call::call(callback, &[context, 0]);
    }
    guest::free_bytes(notification);
}

/// IoReportTargetDeviceChangeAsynchronous(PhysicalDeviceObject,
/// NotificationStructure, Callback, Context): o work item entrega uma cópia
/// aos registros do PDO.
pub fn report_target_device_change_asynchronous(device: u64, notification: u64, callback: u64, context: u64) {
    let copy = copy_notification(notification);
    if copy == 0 {
        return;
    }
    let item = guest::alloc_bytes(work_items::work_item_size());
    TARGET_CHANGES.lock().insert(item, (device, copy, callback, context));
    work_items::queue_kernel_work_item(item, deliver_target_change, item, None);
}

/// IoReportTargetDeviceChange(PhysicalDeviceObject, NotificationStructure):
/// a entrega síncrona de uma cópia aos registros do PDO antes de voltar.
pub fn report_target_device_change(device: u64, notification: u64) -> u32 {
    let copy = copy_notification(notification);
    if copy == 0 {
        return 0xC000_009A;
    }
    notify_target_change(device, copy);
    guest::free_bytes(copy);
    0
}
