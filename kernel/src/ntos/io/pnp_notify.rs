//! Notificações PnP — IoRegisterPlugPlayNotification,
//! IoUnregisterPlugPlayNotification[Ex] e
//! IoReportTargetDeviceChangeAsynchronous.
//!
//! O handle devolvido é o registro nativo. Mudanças de interface de
//! dispositivo chegam aos registros da classe (DEVICE_INTERFACE_CHANGE_
//! NOTIFICATION); mudanças de dispositivo agendadas são entregues por um
//! work item aos registros de EventCategoryTargetDeviceChange.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::hal::amd64::native_call;
use crate::ntos::io::{device_interface, work_items};
use crate::rtl::SpinLock;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::ntos::inc::field::{Field, Reserved};
use crate::ntos::inc::types::{DeviceInterfaceChangeNotification, Guid, NtStruct, UnicodeString};

/// Registro de notificação PnP (o handle é o registro nativo).
#[derive(Clone, Copy)]
struct PlugPlayRegistration {
    category: u32,
    /// GUID da classe de interface (EventCategoryDeviceInterfaceChange).
    class: [u8; 16],
    callback: u64,
    context: u64,
    record: u64,
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

static PLUG_PLAY_REGISTRATIONS: SpinLock<Vec<PlugPlayRegistration>> = SpinLock::new(Vec::new());
/// Mudanças de dispositivo agendadas: work item → (GUID, contexto, callback).
static TARGET_CHANGES: SpinLock<BTreeMap<u64, (u64, u64, u64)>> = SpinLock::new(BTreeMap::new());

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
        native_call::call(registration.callback, &[notification, registration.context]);
        guest::free_bytes(notification);
    }
}

/// Chegada (`arrival`) ou remoção de uma interface para os registros da classe.
pub fn notify_interface_change(arrival: bool, class: &[u8; 16], link: &str) {
    let registrations = PLUG_PLAY_REGISTRATIONS.lock().clone();
    notify_interface(&registrations, if arrival { &INTERFACE_ARRIVAL } else { &INTERFACE_REMOVAL }, class, link);
}

/// IoRegisterPlugPlayNotification(EventCategory, EventCategoryFlags,
/// EventCategoryData, DriverObject, CallbackRoutine, Context,
/// NotificationEntry): assinatura do WDK; o handle é o registro.
/// PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES entrega as
/// interfaces já habilitadas da classe.
pub fn register(category: u32, flags: u32, data: u64, callback: u64, context: u64, output: u64) -> u32 {
    if callback == 0 || output == 0 {
        return 0xC000_000D;
    }
    let mut class = [0u8; 16];
    if category == EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE {
        if data == 0 {
            return 0xC000_000D;
        }
        class.copy_from_slice(&guest::read_bytes(data, Guid::SIZE as usize));
    }
    let record = guest::alloc_bytes(RegistrationRecord::SIZE);
    // SAFETY: registro recém-alocado.
    let body = unsafe { RegistrationRecord::at(record) };
    body.callback.set(callback);
    body.context.set(context);
    let registration = PlugPlayRegistration { category, class, callback, context, record };
    PLUG_PLAY_REGISTRATIONS.lock().push(registration);
    // SAFETY: PVOID* NotificationEntry do chamador de modo kernel.
    unsafe { Field::<u64>::at(output) }.set(record);
    if category == EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE && flags & 1 != 0 {
        let existing = device_interface::enabled_links(&class);
        for link in existing {
            notify_interface(&[registration], &INTERFACE_ARRIVAL, &class, &link);
        }
    }
    0
}

/// IoUnregisterPlugPlayNotification[Ex]: handle desconhecido =
/// STATUS_OBJECT_NAME_NOT_FOUND.
pub fn unregister(record: u64) -> u32 {
    let removed = {
        let mut registrations = PLUG_PLAY_REGISTRATIONS.lock();
        let Some(index) = registrations.iter().position(|registration| registration.record == record) else { return 0xC000_0034 };
        registrations.remove(index)
    };
    guest::free_bytes(removed.record);
    0
}

/// Entrega uma TARGET_DEVICE_CUSTOM_NOTIFICATION aos registros de
/// EventCategoryTargetDeviceChange.
fn notify_target_change(notification: u64) {
    let registrations = PLUG_PLAY_REGISTRATIONS.lock().clone();
    for registration in registrations.iter().filter(|registration| registration.category == EVENT_CATEGORY_TARGET_DEVICE_CHANGE) {
        native_call::call(registration.callback, &[notification, registration.context]);
    }
}

/// Work item do IoReportTargetDeviceChangeAsynchronous: entrega a cópia da
/// estrutura, chama o callback de conclusão do chamador e libera a cópia.
fn deliver_target_change(_device: u64, item: u64) {
    let Some((notification, callback, context)) = TARGET_CHANGES.lock().remove(&item) else { return };
    notify_target_change(notification);
    if callback != 0 {
        native_call::call(callback, &[context, 0]);
    }
    guest::free_bytes(notification);
}

/// TARGET_DEVICE_CUSTOM_NOTIFICATION.Size (USHORT em +2), com o mínimo do
/// cabeçalho (até CustomDataBuffer, 0x24).
fn notification_size(notification: u64) -> u64 {
    // SAFETY: estrutura de notificação do chamador de modo kernel.
    (unsafe { Field::<u16>::at(notification + 2) }.get() as u64).max(0x24)
}

/// IoReportTargetDeviceChangeAsynchronous(PhysicalDeviceObject,
/// NotificationStructure, Callback, Context). Como no NT (o evento PnP leva
/// uma cópia de Size bytes), a estrutura do chamador pode morar na pilha
/// dele: o work item entrega uma cópia.
pub fn report_target_device_change_asynchronous(notification: u64, callback: u64, context: u64) {
    let size = notification_size(notification);
    let copy = guest::alloc_bytes(size);
    guest::write_bytes(copy, &guest::read_bytes(notification, size as usize));
    let item = guest::alloc_bytes(work_items::work_item_size());
    TARGET_CHANGES.lock().insert(item, (copy, callback, context));
    work_items::queue_kernel_work_item(item, deliver_target_change, item, None);
}

/// IoReportTargetDeviceChange(PhysicalDeviceObject, NotificationStructure):
/// a entrega síncrona aos registros antes de voltar.
pub fn report_target_device_change(notification: u64) -> u32 {
    notify_target_change(notification);
    0
}
