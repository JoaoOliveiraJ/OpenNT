//! Callbacks de coalescência de I/O do Power Manager.
//!
//! PoRegisterCoalescingCallback (ntoskrnl 19041 rva 0x7998d0)
//!   (Callback, ClientOnly, Handle*, Context): registro de 0x48 bytes em
//!   NonPagedPool ('PoCb'): rotina interna PopCoalescingCallback em +8, o
//!   próprio registro em +0x10, Callback em +0x18, ClientOnly em +0x20,
//!   Context em +0x28, LIST_ENTRY em +0x30 (PopCoalRegistrationList) e o
//!   EX_CALLBACK em +0x40; *Handle = registro; STATUS_INSUFFICIENT_RESOURCES
//!   sem pool. PoUnregisterCoalescingCallback rva 0x8e6680: desfaz o
//!   EX_CALLBACK, espera a rundown, tira da lista e libera.
//! O Power Manager chama os registrados quando o sistema entra/sai de um
//! período de coalescência (tela desligada, idle resiliency). O OpenNT não
//! tem esses períodos: os registros ficam guardados e nunca são chamados,
//! que é o que acontece no NT enquanto o sistema não entra em coalescência.

use alloc::vec::Vec;

use crate::ntos::inc::types::{Field, ListEntry, NtStruct, Reserved};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

/// Registro do PoRegisterCoalescingCallback (POP_COALESCING_CALLBACK_BLOCK do
/// 19041: layout do Power Manager, não visto pelos drivers).
#[repr(C)]
pub struct CoalescingRegistration {
    _reserved_0: Reserved<0x8>,
    /// Rotina interna (PopCoalescingCallback).
    pub internal_callback: Field<u64>,
    /// O próprio registro (contexto da rotina interna).
    pub self_pointer: Field<u64>,
    pub callback: Field<u64>,
    pub client_only: Field<u8>,
    _pad_21: Reserved<0x7>,
    pub context: Field<u64>,
    /// Entrada na PopCoalRegistrationList.
    pub link: ListEntry,
    /// EX_CALLBACK do registro.
    pub callback_block: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for CoalescingRegistration {}

const _: () = {
    assert!(core::mem::size_of::<CoalescingRegistration>() == 0x48);
    assert!(core::mem::offset_of!(CoalescingRegistration, self_pointer) == 0x10);
    assert!(core::mem::offset_of!(CoalescingRegistration, callback) == 0x18);
    assert!(core::mem::offset_of!(CoalescingRegistration, client_only) == 0x20);
    assert!(core::mem::offset_of!(CoalescingRegistration, context) == 0x28);
    assert!(core::mem::offset_of!(CoalescingRegistration, link) == 0x30);
    assert!(core::mem::offset_of!(CoalescingRegistration, callback_block) == 0x40);
};

const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// PopCoalRegistrationList, na ordem de inserção (cauda).
static REGISTRATIONS: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());

/// PoRegisterCoalescingCallback.
pub fn register(callback: u64, client_only: bool, handle: &Field<u64>, context: u64) -> u32 {
    let address = guest::alloc_bytes(CoalescingRegistration::SIZE);
    if address == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: bloco recém-alocado (zerado) do tamanho do registro.
    let registration = unsafe { CoalescingRegistration::at(address) };
    registration.self_pointer.set(address);
    registration.callback.set(callback);
    registration.client_only.set(client_only as u8);
    registration.context.set(context);
    let link = registration.link.flink.address();
    registration.link.flink.set(link);
    registration.link.blink.set(link);
    REGISTRATIONS.lock().push(address);
    handle.set(address);
    0
}

/// PoUnregisterCoalescingCallback(Handle): registro desconhecido não muda nada.
pub fn unregister(handle: u64) {
    let removed = {
        let mut registrations = REGISTRATIONS.lock();
        registrations.iter().position(|&registration| registration == handle).map(|index| registrations.remove(index))
    };
    if let Some(registration) = removed {
        guest::free_bytes(registration);
    }
}

/// Registros vivos (diagnóstico e autoteste).
pub fn registered(handle: u64) -> bool {
    REGISTRATIONS.lock().contains(&handle)
}
