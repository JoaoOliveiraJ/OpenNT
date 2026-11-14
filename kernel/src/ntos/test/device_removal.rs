//! Autoteste (fase 6) dos pedidos de ejeção, chamados pelo nome sobre um
//! PDO com devnode (dos barramentos internos): IoRequestDeviceEjectEx devolve
//! STATUS_SUCCESS e enfileira o worker, que entrega (Status, Context) ao
//! callback com o status do PnP do OpenNT (STATUS_TOO_LATE: sem
//! processamento de eventos de dispositivo-alvo) e solta a referência do
//! DRIVER_OBJECT depois dele; IoRequestDeviceEject enfileira o mesmo
//! worker sem callback.

use core::sync::atomic::{AtomicU64, Ordering};

use super::phase6::call_export;
use crate::ntos::io::{device_removal, io_manager, work_items};
use crate::ntos::mm::guest_memory as guest;

type Assert = fn(bool, &str);

const STATUS_TOO_LATE: u64 = 0xC000_0189;

/// (status, contexto) recebidos pelo callback do teste.
static DELIVERED: AtomicU64 = AtomicU64::new(0);
static DELIVERED_CONTEXT: AtomicU64 = AtomicU64::new(0);

/// PIO_DEVICE_EJECT_CALLBACK(Status, Context).
extern "win64" fn eject_completed(status: u32, context: u64) {
    DELIVERED.store(0x1_0000_0000 | status as u64, Ordering::SeqCst);
    DELIVERED_CONTEXT.store(context, Ordering::SeqCst);
}

pub fn run(assert: Assert) {
    let Some(pdo) = io_manager::devices().into_iter().map(|(_, entry)| entry.native_device).find(|&device| device_removal::has_device_node(device)) else {
        assert(false, "eject: nenhum PDO com devnode");
        return;
    };
    let context = guest::alloc_bytes(16);
    let callback = eject_completed as extern "win64" fn(u32, u64) as usize as u64;
    DELIVERED.store(0, Ordering::SeqCst);
    let pending = work_items::pending();
    // O DRIVER_OBJECT do PDO fica referenciado até depois do callback.
    let driver = guest::read64(pdo + 8);
    let queued = call_export("IoRequestDeviceEjectEx", &[pdo, callback, context, driver]);
    let after_queue = work_items::pending();
    let before_run = DELIVERED.load(Ordering::SeqCst);
    work_items::run_queue();
    assert(queued == Some(0) && after_queue == pending + 1 && before_run == 0 && DELIVERED.load(Ordering::SeqCst) == 0x1_0000_0000 | STATUS_TOO_LATE && DELIVERED_CONTEXT.load(Ordering::SeqCst) == context, "eject: IoRequestDeviceEjectEx enfileira o worker, que chama o callback com o status e o contexto");
    let plain = call_export("IoRequestDeviceEject", &[pdo]);
    let plain_queued = work_items::pending();
    work_items::run_queue();
    assert(plain == Some(0) && plain_queued == work_items::pending() + 1, "eject: IoRequestDeviceEject enfileira o pedido sem callback");
    guest::free_bytes(context);
}
