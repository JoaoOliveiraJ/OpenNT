//! O nanokernel — registro de serviços.
//!
//! Drivers, FS, console e win32 podem ser serviços registrados aqui e
//! acessados por chamada de serviço (mensagem). Requisições e respostas são
//! valores dinâmicos.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::any::Any;

use crate::rtl::{KernelError, SpinLock};

pub type Message = Box<dyn Any + Send>;
pub type ServiceHandler = fn(Message) -> Message;

static SERVICES: SpinLock<BTreeMap<String, ServiceHandler>> = SpinLock::new(BTreeMap::new());

pub fn register_service(name: &str, handler: ServiceHandler) -> Result<(), KernelError> {
    let mut services = SERVICES.lock();
    if services.contains_key(name) {
        return Err(KernelError::new(alloc::format!("servico duplicado: {name}")));
    }
    services.insert(String::from(name), handler);
    Ok(())
}

pub fn call_service(name: &str, request: Message) -> Result<Message, KernelError> {
    // O handler roda sem o lock: pode chamar outros serviços.
    let handler = SERVICES.lock().get(name).copied();
    match handler {
        Some(handler) => Ok(handler(request)),
        None => Err(KernelError::new(alloc::format!("servico desconhecido: {name}"))),
    }
}

pub fn has_service(name: &str) -> bool {
    SERVICES.lock().contains_key(name)
}

pub fn list_services() -> Vec<String> {
    SERVICES.lock().keys().cloned().collect()
}
