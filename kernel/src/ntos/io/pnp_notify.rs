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
use crate::ntos::inc::nt_abi::io_workitem;

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

static PLUG_PLAY_REGISTRATIONS: SpinLock<Vec<PlugPlayRegistration>> = SpinLock::new(Vec::new());
/// Mudanças de dispositivo agendadas: work item → (GUID, contexto, callback).
static TARGET_CHANGES: SpinLock<BTreeMap<u64, (u64, u64, u64)>> = SpinLock::new(BTreeMap::new());

/// DEVICE_INTERFACE_CHANGE_NOTIFICATION (Version, Size, Event,
/// InterfaceClassGuid, SymbolicLinkName) entregue a callback(estrutura,
/// contexto) de cada registro da classe.
fn notify_interface(registrations: &[PlugPlayRegistration], event: &[u8; 16], class: &[u8; 16], link: &str) {
    for registration in registrations.iter().filter(|registration| registration.category == EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE && registration.class == *class) {
        let units = link.encode_utf16().count() as u64;
        let notification = guest::alloc_bytes(0x30 + 16 + (units + 1) * 2);
        if notification == 0 {
            continue;
        }
        let string = notification + 0x30;
        let buffer = string + 16;
        guest::write16(notification, 1);
        guest::write16(notification + 2, 0x30);
        guest::write_bytes(notification + 4, event);
        guest::write_bytes(notification + 20, class);
        guest::write32(notification + 36, 0);
        guest::write64(notification + 40, string);
        guest_strings::write_wide_string(buffer, link);
        guest::write16(string, units as u16 * 2);
        guest::write16(string + 2, units as u16 * 2 + 2);
        guest::write64(string + 8, buffer);
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
        class.copy_from_slice(&guest::read_bytes(data, 16));
    }
    let record = guest::alloc_bytes(0x20);
    guest::write64(record, callback);
    guest::write64(record + 8, context);
    let registration = PlugPlayRegistration { category, class, callback, context, record };
    PLUG_PLAY_REGISTRATIONS.lock().push(registration);
    guest::write64(output, record);
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

/// Work item do IoReportTargetDeviceChangeAsynchronous: entrega a estrutura
/// aos registros de EventCategoryTargetDeviceChange e chama o callback de
/// conclusão do chamador.
fn deliver_target_change(_device: u64, item: u64) {
    let Some((notification, callback, context)) = TARGET_CHANGES.lock().remove(&item) else { return };
    let registrations = PLUG_PLAY_REGISTRATIONS.lock().clone();
    for registration in registrations.iter().filter(|registration| registration.category == EVENT_CATEGORY_TARGET_DEVICE_CHANGE) {
        native_call::call(registration.callback, &[notification, registration.context]);
    }
    if callback != 0 {
        native_call::call(callback, &[context, 0]);
    }
}

/// IoReportTargetDeviceChangeAsynchronous(PhysicalDeviceObject,
/// NotificationStructure, Callback, Context).
pub fn report_target_device_change_asynchronous(notification: u64, callback: u64, context: u64) {
    let item = guest::alloc_bytes(io_workitem::SIZE);
    TARGET_CHANGES.lock().insert(item, (notification, callback, context));
    work_items::queue_kernel_work_item(item, deliver_target_change, item, None);
}
