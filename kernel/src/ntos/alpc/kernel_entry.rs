//! Ligação do escalonador ao transporte.
//!
//! O transporte de `ps/user/alpc` instala as entradas depois da carga dos
//! módulos, evitando o ciclo entre threads de kernel, transporte ALPC e
//! escalonamento de usuário. As entradas Zw de troca de mensagens e conexão
//! bombeiam a operação retomável pelo escalonador de kernel até concluir.

use alloc::boxed::Box;

use crate::ntos::ke::dispatcher;
use crate::rtl::{KernelError, SpinLock};

/// Operação retomável devolvida pelo transporte.
pub trait Pending {
    fn poll(&mut self) -> Option<u32>;
    fn cancel(&mut self);
}

impl Pending for super::kernel_wait::Request {
    fn poll(&mut self) -> Option<u32> {
        super::kernel_wait::Request::poll(self)
    }
    fn cancel(&mut self) {
        super::kernel_wait::Request::cancel(self)
    }
}

/// Resultado já decidido.
pub struct Completed(pub u32);

impl Pending for Completed {
    fn poll(&mut self) -> Option<u32> {
        Some(self.0)
    }
    fn cancel(&mut self) {}
}

/// Troca de mensagens: handle, flags, entrada, atributos de envio, saída,
/// comprimento, atributos de recepção e timeout.
pub type TransportEntry = fn(&[u64; 8]) -> Result<Box<dyn Pending>, KernelError>;
/// Conexão (Ex ou não): os onze argumentos x64 da entrada Zw.
pub type ConnectionEntry = fn(&[u64; 11]) -> Result<Box<dyn Pending>, KernelError>;

static TRANSPORT: SpinLock<Option<TransportEntry>> = SpinLock::new(None);
static CONNECTION: SpinLock<Option<ConnectionEntry>> = SpinLock::new(None);
static CONNECTION_EX: SpinLock<Option<ConnectionEntry>> = SpinLock::new(None);

fn install_into<T: Copy>(slot: &SpinLock<Option<T>>, entry: T, same: impl Fn(T, T) -> bool, what: &str) -> Result<(), KernelError> {
    let mut slot = slot.lock();
    if slot.is_some_and(|existing| !same(existing, entry)) {
        return Err(KernelError::new(alloc::format!("invalid ALPC {what} registration")));
    }
    *slot = Some(entry);
    Ok(())
}

pub fn install(entry: TransportEntry) -> Result<(), KernelError> {
    install_into(&TRANSPORT, entry, |left, right| left as usize == right as usize, "kernel transport")
}

pub fn begin(arguments: &[u64; 8]) -> Result<Box<dyn Pending>, KernelError> {
    let Some(entry) = *TRANSPORT.lock() else { return Err(KernelError::new("ALPC kernel transport is not initialized")) };
    entry(arguments)
}

pub fn install_connection(entry: ConnectionEntry) -> Result<(), KernelError> {
    install_into(&CONNECTION, entry, |left, right| left as usize == right as usize, "kernel connection")
}

pub fn begin_connection(arguments: &[u64; 11]) -> Result<Box<dyn Pending>, KernelError> {
    let Some(entry) = *CONNECTION.lock() else { return Err(KernelError::new("ALPC kernel connection is not initialized")) };
    entry(arguments)
}

pub fn install_connection_ex(entry: ConnectionEntry) -> Result<(), KernelError> {
    install_into(&CONNECTION_EX, entry, |left, right| left as usize == right as usize, "extended connection")
}

pub fn begin_connection_ex(arguments: &[u64; 11]) -> Result<Box<dyn Pending>, KernelError> {
    let Some(entry) = *CONNECTION_EX.lock() else { return Err(KernelError::new("ALPC extended connection is not initialized")) };
    entry(arguments)
}

/// Bombeia a operação retomável até concluir; o cancelamento final é
/// inócuo depois da conclusão.
fn drive(mut operation: Box<dyn Pending>) -> u32 {
    let status = loop {
        if let Some(status) = operation.poll() {
            break status;
        }
        dispatcher::pump_kernel();
    };
    operation.cancel();
    status
}

/// ZwAlpcSendWaitReceivePort até a conclusão; devolve o NTSTATUS.
pub fn send_wait_receive(arguments: &[u64; 8]) -> Result<u32, KernelError> {
    begin(arguments).map(drive)
}

/// ZwAlpcConnectPort até a conclusão: onze argumentos x64, incluindo timeout
/// e atributos depois do quarto slot.
pub fn connect(arguments: &[u64; 11]) -> Result<u32, KernelError> {
    begin_connection(arguments).map(drive)
}

/// ZwAlpcConnectPortEx até a conclusão.
pub fn connect_ex(arguments: &[u64; 11]) -> Result<u32, KernelError> {
    begin_connection_ex(arguments).map(drive)
}
