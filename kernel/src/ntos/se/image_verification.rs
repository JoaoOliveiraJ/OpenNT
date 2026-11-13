//! Verificação de imagens de drivers.
//!
//! Inscrições e entrega dos pacotes BDCB_IMAGE_INFORMATION de uma
//! verificação; carregar um PE por si só não produz o evento nem atribui
//! confiança à imagem. A entrega roda numa requisição de thread de sistema.

use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::ntos::ex::callbacks::{self as executive_callbacks, NotifyRequest};
use crate::ntos::ke::{dispatcher, irql};
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ps::kernel_threads::{self, KernelWait, WaitPoll};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const VERIFICATION_POOL_TAG: u32 = 0x6373_4943;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;

/// Inscrições válidas para remoção.
static HANDLES: SpinLock<BTreeSet<u64>> = SpinLock::new(BTreeSet::new());
/// Objeto de callbacks compartilhado, criado no primeiro uso.
static CALLBACK_OBJECT: AtomicU64 = AtomicU64::new(0);
/// Pacotes na fila que ainda não terminaram nem foram cancelados.
static QUEUED: AtomicUsize = AtomicUsize::new(0);

fn require_passive_level() -> Result<(), KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("image verification callback requires PASSIVE_LEVEL"));
    }
    Ok(())
}

pub fn initialize() -> Result<u64, KernelError> {
    let current = CALLBACK_OBJECT.load(Ordering::Acquire);
    if current != 0 {
        return Ok(current);
    }
    let object = executive_callbacks::create_internal(true)?;
    if object == 0 {
        return Err(KernelError::new("image verification callback object allocation failed"));
    }
    CALLBACK_OBJECT.store(object, Ordering::Release);
    Ok(object)
}

/// SeRegisterImageVerificationCallback: só imagens de driver (1), callback de
/// verificação (0) e token NULL.
pub fn register(image_type: u32, callback_type: u32, callback: u64, context: u64, token: u64, output: u64) -> Result<u32, KernelError> {
    require_passive_level()?;
    if image_type != 1 {
        return Ok(0xC000_00EF);
    }
    if callback_type != 0 {
        return Ok(0xC000_00F0);
    }
    if token != 0 {
        return Ok(0xC000_00F3);
    }
    let object = initialize()?;
    let handle = executive_callbacks::register(object, callback, context)?;
    if handle == 0 {
        return Ok(STATUS_NO_MEMORY);
    }
    HANDLES.lock().insert(handle);
    guest::write64(output, handle);
    Ok(0)
}

/// Remoção interna; a espera pelas notificações ativas é do provedor executivo.
pub fn begin_remove(handle: u64) -> Result<executive_callbacks::UnregisterRequest, KernelError> {
    require_passive_level()?;
    if !HANDLES.lock().contains(&handle) {
        return Err(KernelError::new("invalid image verification registration"));
    }
    let request = executive_callbacks::begin_unregister(handle)?;
    HANDLES.lock().remove(&handle);
    Ok(request)
}

/// SeUnregisterImageVerificationCallback: conclui cooperativamente.
pub fn remove(handle: u64) -> Result<(), KernelError> {
    let mut request = begin_remove(handle)?;
    while request.poll()?.is_none() {
        dispatcher::pump_kernel();
    }
    Ok(())
}

/// Copia o pacote e ajusta à base da cópia os cinco ponteiros empacotados
/// (RegistryPath.Buffer fica com o valor original, como na rotina NT).
pub fn copy_information(source: u64, destination: u64, size: u64) {
    guest::write_bytes(destination, &guest::read_bytes(source, size as usize));
    for offset in [0x10u64, 0x30, 0x40, 0x48, 0x50] {
        guest::write64(destination + offset, guest::read64(source + offset).wrapping_sub(source).wrapping_add(destination));
    }
}

/// Entrega de um pacote: cada chamada recebe uma cópia com os ponteiros
/// ajustados; o fim ou o cancelamento liberam o pacote e a área de trabalho.
struct Delivery {
    notification: NotifyRequest,
    packet: u64,
    work: u64,
    size: u64,
    completed: bool,
}

impl Delivery {
    fn release(&mut self) {
        if self.completed {
            return;
        }
        self.completed = true;
        QUEUED.fetch_sub(1, Ordering::AcqRel);
        let _ = kernel_pool::free(self.packet, None);
        let _ = kernel_pool::free(self.work, None);
    }
}

impl KernelWait for Delivery {
    fn poll(&mut self) -> Result<WaitPoll, KernelError> {
        match self.notification.poll()? {
            Some(call) => {
                copy_information(self.packet, self.work + 0x30, self.size);
                Ok(WaitPoll::Callback { routine: call.callback, arguments: call.arguments.to_vec() })
            }
            None => {
                self.release();
                Ok(WaitPoll::Done(0))
            }
        }
    }
    fn resume(&mut self, _value: u64) -> Result<(), KernelError> {
        self.notification.resume()
    }
    fn cancel(&mut self) {
        let _ = self.notification.cancel();
        self.release();
    }
}

/// Passa um pacote do pool a uma requisição de thread de sistema; no
/// sucesso a fila assume a propriedade, na falha ele fica com o produtor.
pub fn queue_owned_information(packet: u64, size: u64) -> Result<u32, KernelError> {
    require_passive_level()?;
    let allocation = kernel_pool::info(packet);
    if !(0x68..=0xFFFF_FFFF).contains(&size) || allocation.is_none_or(|allocation| (allocation.bytes as u64) < size) {
        return Err(KernelError::new("image verification packet must own a complete BDCB image-information allocation"));
    }
    let object = initialize()?;
    let work = kernel_pool::allocate(size + 0x30, AllocateOptions { tag: VERIFICATION_POOL_TAG, ..Default::default() }).unwrap_or(0);
    if work == 0 {
        return Ok(STATUS_NO_MEMORY);
    }
    let notification = match executive_callbacks::begin_notify(object, 1, work + 0x30) {
        Ok(notification) => notification,
        Err(error) => {
            let _ = kernel_pool::free(work, None);
            return Err(error);
        }
    };
    QUEUED.fetch_add(1, Ordering::AcqRel);
    let delivery = Delivery { notification, packet, work, size, completed: false };
    match kernel_threads::create_system_request(Box::new(delivery)) {
        Ok(_) => Ok(0),
        Err(error) => {
            // Sem recursos para a thread o pacote continua com o produtor; a
            // requisição não criada é descartada sem liberar o pacote.
            QUEUED.fetch_sub(1, Ordering::AcqRel);
            let _ = kernel_pool::free(work, None);
            let message = error.message.as_str();
            if ["no thread context", "no kernel stack", "no thread object", "allocation failed"].iter().any(|pattern| message.contains(pattern)) {
                return Ok(STATUS_NO_MEMORY);
            }
            Err(error)
        }
    }
}

/// Inscrições ativas.
pub fn count() -> usize {
    HANDLES.lock().len()
}

/// Pacotes cuja entrega ainda não terminou.
pub fn pending() -> usize {
    QUEUED.load(Ordering::Acquire)
}
