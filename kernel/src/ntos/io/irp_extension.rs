//! Extensões de IRP criadas sob demanda — a extensão genérica propagável
//! (IoGet/SetGenericIrpExtension, IoPropagateIrpExtensionEx), o activity id
//! (IoGet/SetActivityIdIrp, IoPropagateActivityIdToThread) e o dispositivo de
//! hard error/verify (IoSetHardErrorOrVerifyDevice).
//!
//! A extensão pertence ao IRP: IoFreeIrp a descarta e ela não sobrevive ao
//! reuso do endereço.

use alloc::collections::BTreeMap;

use crate::ntos::io::threads::thread_activity;
use crate::rtl::SpinLock;
use crate::ntos::mm::guest_memory as guest;

/// Extensão de um IRP criada sob demanda (activity id zerado).
#[derive(Clone, Copy, Default)]
struct RequestExtension {
    generic: u64,
    propagate: u32,
    activity_id_pointer: u64,
    activity_id_present: bool,
    hard_error_device: u64,
}

static REQUEST_EXTENSIONS: SpinLock<BTreeMap<u64, RequestExtension>> = SpinLock::new(BTreeMap::new());

fn request_extension(packet: u64) -> RequestExtension {
    let mut extensions = REQUEST_EXTENSIONS.lock();
    *extensions.entry(packet).or_insert_with(|| RequestExtension { activity_id_pointer: guest::alloc_bytes(16), ..Default::default() })
}

fn update_extension(packet: u64, change: impl FnOnce(&mut RequestExtension)) {
    request_extension(packet);
    if let Some(extension) = REQUEST_EXTENSIONS.lock().get_mut(&packet) {
        change(extension);
    }
}

/// Descarta a extensão do IRP liberado.
pub fn release(packet: u64) {
    if let Some(extension) = REQUEST_EXTENSIONS.lock().remove(&packet) {
        guest::free_bytes(extension.activity_id_pointer);
    }
}

/// IoGetGenericIrpExtension.
pub fn generic(packet: u64) -> u64 {
    request_extension(packet).generic
}

/// IoSetGenericIrpExtension.
pub fn set_generic(packet: u64, generic: u64, propagate: bool) {
    let propagate = propagate as u32;
    update_extension(packet, |extension| {
        extension.generic = generic;
        extension.propagate = propagate;
    });
}

/// IoPropagateIrpExtensionEx: copia a extensão propagável para o IRP
/// associado; sem extensão, STATUS_NOT_FOUND.
pub fn propagate(source: u64, target: u64) -> u32 {
    let source = request_extension(source);
    if source.generic == 0 {
        return 0xC000_0225;
    }
    update_extension(target, |target| {
        target.generic = source.generic;
        target.propagate = source.propagate;
    });
    0
}

/// IoGetActivityIdIrp: copia o GUID presente; ausente, STATUS_NOT_FOUND.
pub fn activity_id(packet: u64, output: u64) -> u32 {
    let extension = REQUEST_EXTENSIONS.lock().get(&packet).copied();
    let Some(extension) = extension.filter(|extension| extension.activity_id_present) else { return 0xC000_0225 };
    guest::write_bytes(output, &guest::read_bytes(extension.activity_id_pointer, 16));
    0
}

/// IoSetActivityIdIrp.
pub fn set_activity_id(packet: u64, guid: u64) {
    let extension = request_extension(packet);
    guest::write_bytes(extension.activity_id_pointer, &guest::read_bytes(guid, 16));
    update_extension(packet, |extension| extension.activity_id_present = true);
}

/// IoPropagateActivityIdToThread: o activity id do IRP (ou nenhum) vira o
/// da thread.
pub fn propagate_activity_id_to_thread(packet: u64, propagated: u64, previous_output: u64) -> u32 {
    let extension = REQUEST_EXTENSIONS.lock().get(&packet).copied();
    let source = extension.filter(|extension| extension.activity_id_present).map_or(0, |extension| extension.activity_id_pointer);
    thread_activity::propagate(source, propagated, previous_output)
}

/// IoSetHardErrorOrVerifyDevice.
pub fn set_hard_error_device(packet: u64, device: u64) {
    update_extension(packet, |extension| extension.hard_error_device = device);
}
