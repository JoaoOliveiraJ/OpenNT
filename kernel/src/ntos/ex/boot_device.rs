//! Dispositivos de boot removíveis: ExRegisterBootDevice e
//! ExNotifyBootDeviceRemoval (ntoskrnl 19041, ex/bootdev).
//!
//! Um driver de barramento (o usbhub.sys, por exemplo) registra o
//! dispositivo de que o boot depende com um BOOT_DEVICE_REGISTRATION de
//! 0x28 bytes: Version = 1, um ULONG reservado (zero), o objeto retido
//! obrigatório (o usbhub passa o DRIVER_OBJECT), o objeto opcional que a
//! rotina recebe (o DEVICE_OBJECT), a rotina `BOOLEAN Callback(Object,
//! Context)` que diz se o dispositivo voltou, e o Context. O handle
//! devolvido é a entrada de 0x40 bytes do pool não paginado (tag 'BDNP'):
//! assinatura, contador de remoções pendentes, o LIST_ENTRY da
//! ExBootDeviceList e a cópia do registro.
//!
//! O primeiro registro cria, sob o ExExternalBootSupportInitializationEvent
//! (evento de sincronização sinalizado, usado como trava), a thread de
//! sistema ExpWaitForBootDevices com prioridade 31. Ela espera o
//! ExBootDevicesRemovedEvent; a cada sinal percorre a lista do fim para o
//! começo chamando a rotina de cada entrada com remoção pendente, e uma
//! resposta TRUE desconta a entrada e o ExNumMissingBootDevices. Enquanto
//! faltar algum dispositivo, espera 1 s ocupada (KeStallExecutionProcessor)
//! e tenta de novo; depois de 60 tentativas para o sistema com
//! INACCESSIBLE_BOOT_DEVICE (0x7B, 0, 0, 3, 0). No NT os outros
//! processadores ficam congelados (KeFreezeExecution) durante cada espera;
//! o OpenNT não tem o congelamento fora do depurador do kernel e eles
//! seguem rodando.
//!
//! ExNotifyBootDeviceRemoval(Handle) confere a assinatura (FALSE sem ela),
//! incrementa o contador da entrada e, na primeira remoção dela, o
//! ExNumMissingBootDevices; quando este passa de 0 para 1 sinaliza o
//! ExBootDevicesRemovedEvent. Devolve TRUE.

use core::sync::atomic::{AtomicU32, Ordering};

use super::{list_entry, pool_allocation};
use crate::hal::amd64::native_call;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{Kevent, ListEntry};
use crate::ntos::ke::{bugcheck, clock, dispatcher, thread_priority};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{object_manager, object_reference, reference_trace};
use crate::ntos::ps::kernel_threads;
use crate::rtl::{KernelError, SpinLock};

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// 'BDNP': assinatura da entrada e tag do pool.
const BOOT_DEVICE_SIGNATURE: u32 = 0x504E_4442;
/// NonPagedPoolNx.
const NON_PAGED_POOL_NX: u32 = 0x200;
/// THREAD_ALL_ACCESS.
const THREAD_ALL_ACCESS: u32 = 0x1F_FFFF;
/// Prioridade da thread de espera (KeSetPriorityThread).
const REMOVAL_HANDLER_PRIORITY: u64 = 31;
/// Tentativas de 1 s antes do INACCESSIBLE_BOOT_DEVICE.
const RETRIES: u32 = 60;
const RETRY_STALL_MICROSECONDS: u32 = 1_000_000;
const INACCESSIBLE_BOOT_DEVICE: u32 = 0x7B;
const KERNEL_SECURITY_CHECK_FAILURE: u32 = 0x139;
const FAST_FAIL_CORRUPT_LIST_ENTRY: u64 = 3;

/// O registro do chamador (0x28 bytes), copiado para a entrada.
#[repr(C)]
pub struct BootDeviceRegistration {
    pub version: Field<u32>,
    pub reserved: Field<u32>,
    /// Objeto retido obrigatório.
    pub object: Field<u64>,
    /// Objeto opcional, retido e passado à rotina.
    pub callback_object: Field<u64>,
    /// BOOLEAN Callback(CallbackObject, Context): TRUE = o dispositivo voltou.
    pub callback: Field<u64>,
    pub context: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for BootDeviceRegistration {}

/// A entrada (o handle), 0x40 bytes.
#[repr(C)]
struct BootDeviceEntry {
    signature: Field<u32>,
    /// Remoções ainda não resolvidas pela rotina.
    missing: Field<u32>,
    links: ListEntry,
    registration: BootDeviceRegistration,
}

// SAFETY: #[repr(C)] só de células e estruturas do NT.
unsafe impl NtStruct for BootDeviceEntry {}

const _: () = {
    assert!(core::mem::size_of::<BootDeviceRegistration>() == 0x28);
    assert!(core::mem::size_of::<BootDeviceEntry>() == 0x40);
    assert!(core::mem::offset_of!(BootDeviceEntry, links) == 0x08);
    assert!(core::mem::offset_of!(BootDeviceEntry, registration) == 0x18);
};

fn entry(address: u64) -> &'static BootDeviceEntry {
    // SAFETY: entrada alocada por `register` (o handle do chamador).
    unsafe { BootDeviceEntry::at(address) }
}

struct State {
    /// ExExternalBootSupportInitializationEvent.
    initialization_event: u64,
    /// ExBootDevicesRemovedEvent.
    removed_event: u64,
    /// ExBootDeviceList (cabeça LIST_ENTRY).
    list_head: u64,
    /// ExBootDeviceRemovalHandler (ETHREAD).
    removal_handler: u64,
}

/// O estado e a ExBootDeviceListSpinLock: a trava protege a cadeia.
static STATE: SpinLock<State> = SpinLock::new(State { initialization_event: 0, removed_event: 0, list_head: 0, removal_handler: 0 });
/// ExNumMissingBootDevices.
static MISSING_BOOT_DEVICES: AtomicU32 = AtomicU32::new(0);

/// Os eventos e a cabeça da lista, criados uma vez (os globais estáticos
/// do NT, inicializados antes do primeiro uso).
fn objects() -> Result<(u64, u64, u64), KernelError> {
    {
        let state = STATE.lock();
        if state.initialization_event != 0 {
            return Ok((state.initialization_event, state.removed_event, state.list_head));
        }
    }
    let initialization = guest::alloc_bytes(Kevent::SIZE);
    let removed = guest::alloc_bytes(Kevent::SIZE);
    let head = guest::alloc_bytes(ListEntry::SIZE);
    if initialization == 0 || removed == 0 || head == 0 {
        return Err(KernelError::new("boot device objects allocation failed"));
    }
    // SynchronizationEvent sinalizado: a trava da criação da thread.
    dispatcher::initialize_event(initialization, 1, true);
    dispatcher::initialize_event(removed, 1, false);
    // SAFETY: LIST_ENTRY recém-alocada.
    list_entry::initialize(unsafe { ListEntry::at(head) });
    let mut state = STATE.lock();
    if state.initialization_event != 0 {
        drop(state);
        for block in [initialization, removed, head] {
            guest::free_bytes(block);
        }
        return objects();
    }
    state.initialization_event = initialization;
    state.removed_event = removed;
    state.list_head = head;
    Ok((initialization, removed, head))
}

/// Cria a ExpWaitForBootDevices na primeira chamada; devolve o NTSTATUS.
fn ensure_removal_handler(initialization_event: u64) -> Result<u32, KernelError> {
    dispatcher::wait_for_single_object(initialization_event, 0, 0, false);
    let status = (|| -> Result<u32, KernelError> {
        if STATE.lock().removal_handler != 0 {
            return Ok(0);
        }
        let routine: extern "win64" fn(u64) = wait_for_boot_devices;
        let start = crate::ntos::mm::kernel_address::image_address(routine as usize as u64)?;
        let handle = match kernel_threads::create_system_thread(0, start, 0, THREAD_ALL_ACCESS, 0, None) {
            Ok(handle) => handle,
            Err(error) => return Ok(if error.status != 0 { error.status } else { STATUS_INSUFFICIENT_RESOURCES }),
        };
        let thread = kernel_threads::of_handle(handle).unwrap_or(0);
        let _ = object_manager::close(handle as u32);
        STATE.lock().removal_handler = thread;
        if thread != 0 {
            thread_priority::set_priority(thread, REMOVAL_HANDLER_PRIORITY)?;
        }
        Ok(0)
    })();
    dispatcher::set_event(initialization_event);
    status
}

/// ExRegisterBootDevice(Registration, Handle).
pub fn register(registration: u64, handle_output: u64) -> Result<u32, KernelError> {
    let (initialization_event, _, list_head) = objects()?;
    let status = ensure_removal_handler(initialization_event)?;
    if status & 0x8000_0000 != 0 {
        return Ok(status);
    }
    // SAFETY: BOOT_DEVICE_REGISTRATION do chamador de modo kernel.
    let source = unsafe { BootDeviceRegistration::at(registration) };
    if source.version.get() != 1 || source.object.get() == 0 || source.reserved.get() != 0 || source.callback.get() == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let address = pool_allocation::allocate_tagged(NON_PAGED_POOL_NX, BootDeviceEntry::SIZE, BOOT_DEVICE_SIGNATURE)?;
    if address == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    object_reference::reference_with_tag(source.object.get(), reference_trace::DEFAULT_TAG, true)?;
    if source.callback_object.get() != 0 {
        object_reference::reference_with_tag(source.callback_object.get(), reference_trace::DEFAULT_TAG, true)?;
    }
    guest::write_bytes(address, &[0u8; BootDeviceEntry::SIZE as usize]);
    let created = entry(address);
    created.signature.set(BOOT_DEVICE_SIGNATURE);
    created.registration.version.set(source.version.get());
    created.registration.reserved.set(source.reserved.get());
    created.registration.object.set(source.object.get());
    created.registration.callback_object.set(source.callback_object.get());
    created.registration.callback.set(source.callback.get());
    created.registration.context.set(source.context.get());
    {
        let _list = STATE.lock();
        // SAFETY: a cabeça permanente da ExBootDeviceList.
        let head = unsafe { ListEntry::at(list_head) };
        if !list_entry::tail_consistent(head) {
            // A checagem do InsertTailList (int 29h, FAST_FAIL_CORRUPT_LIST_ENTRY).
            bugcheck::bug_check_ex(KERNEL_SECURITY_CHECK_FAILURE, FAST_FAIL_CORRUPT_LIST_ENTRY, 0, 0, 0);
        }
        list_entry::insert_tail(head, &created.links);
    }
    // SAFETY: PVOID *Handle do chamador.
    unsafe { Field::<u64>::at(handle_output) }.set(address);
    Ok(0)
}

/// ExNotifyBootDeviceRemoval(Handle).
pub fn notify_removal(handle: u64) -> bool {
    let removed = entry(handle);
    if removed.signature.get() != BOOT_DEVICE_SIGNATURE {
        return false;
    }
    if removed.missing.atomic().fetch_add(1, Ordering::SeqCst) + 1 == 1 && MISSING_BOOT_DEVICES.fetch_add(1, Ordering::SeqCst) + 1 == 1 {
        let event = STATE.lock().removed_event;
        if event != 0 {
            dispatcher::set_event(event);
        }
    }
    true
}

/// Remoções pendentes da entrada e o ExNumMissingBootDevices (autotestes).
pub fn missing(handle: u64) -> (u32, u32) {
    (entry(handle).missing.get(), MISSING_BOOT_DEVICES.load(Ordering::SeqCst))
}

/// A thread de espera já existe (autotestes).
pub fn removal_handler() -> u64 {
    STATE.lock().removal_handler
}

/// Uma passada pela lista, do fim para o começo, com a trava solta durante
/// cada rotina. Devolve `true` se o último dispositivo que faltava voltou.
fn poll_entries(list_head: u64) -> bool {
    let mut cursor = list_head;
    loop {
        cursor = {
            let _list = STATE.lock();
            // SAFETY: LIST_ENTRY viva da cadeia (as entradas não saem dela).
            unsafe { ListEntry::at(cursor) }.blink.get()
        };
        if cursor == list_head {
            return false;
        }
        let current = entry(cursor - core::mem::offset_of!(BootDeviceEntry, links) as u64);
        if current.missing.get() == 0 {
            continue;
        }
        let registration = &current.registration;
        let back = native_call::call(registration.callback.get(), &[registration.callback_object.get(), registration.context.get()]) & 0xFF != 0;
        if back && current.missing.atomic().fetch_sub(1, Ordering::SeqCst) == 1 && MISSING_BOOT_DEVICES.fetch_sub(1, Ordering::SeqCst) == 1 {
            return true;
        }
    }
}

/// ExpWaitForBootDevices.
extern "win64" fn wait_for_boot_devices(_context: u64) {
    loop {
        let (removed_event, list_head) = {
            let state = STATE.lock();
            (state.removed_event, state.list_head)
        };
        dispatcher::wait_for_single_object(removed_event, 0, 0, false);
        let mut retries = RETRIES;
        loop {
            if poll_entries(list_head) || MISSING_BOOT_DEVICES.load(Ordering::SeqCst) == 0 {
                break;
            }
            clock::stall_execution_processor(RETRY_STALL_MICROSECONDS);
            retries -= 1;
            if retries == 0 {
                bugcheck::bug_check_ex(INACCESSIBLE_BOOT_DEVICE, 0, 0, 3, 0);
            }
        }
    }
}
