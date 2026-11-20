//! Ligação do escalonador ao transporte.
//!
//! O transporte de `ps/user/alpc` instala as entradas depois da carga dos
//! módulos, evitando o ciclo entre threads de kernel, transporte ALPC e
//! escalonamento de usuário. As entradas Zw de troca de mensagens e conexão
//! conduzem a operação retomável até concluir: uma thread de kernel sai das
//! prontas (WrLpcReceive) e volta quando o transporte muda (uma mensagem na
//! fila de uma porta, um pedido, uma resposta, a decisão de uma conexão, o
//! fecho de uma porta: [`notify_waiters`]), pelo prazo ou por um alerta, e
//! sonda a operação de novo; o contexto de boot gira o pump do kernel.

use alloc::boxed::Box;
use alloc::collections::BTreeSet;

use crate::ntos::ke::{context_switch, dispatcher, wait};
use crate::rtl::{KernelError, SpinLock};

/// Operação retomável devolvida pelo transporte.
pub trait Pending {
    fn poll(&mut self) -> Option<u32>;
    fn cancel(&mut self);
    /// O prazo, o modo e se a espera é alertável.
    fn wait_parameters(&self) -> (wait::Deadline, u8, bool) {
        (wait::Deadline::Infinite, 0, false)
    }
}

impl Pending for super::kernel_wait::Request {
    fn poll(&mut self) -> Option<u32> {
        super::kernel_wait::Request::poll(self)
    }
    fn cancel(&mut self) {
        super::kernel_wait::Request::cancel(self)
    }
    fn wait_parameters(&self) -> (wait::Deadline, u8, bool) {
        super::kernel_wait::Request::wait_parameters(self)
    }
}

/// As threads de kernel paradas numa espera do ALPC.
static WAITERS: SpinLock<BTreeSet<u64>> = SpinLock::new(BTreeSet::new());

/// O transporte mudou: as threads de kernel paradas numa espera do ALPC
/// voltam à fila e sondam a operação delas de novo.
pub fn notify_waiters() {
    crate::ntos::ke::dispatcher::note_wake();
    let waiters: alloc::vec::Vec<u64> = WAITERS.lock().iter().copied().collect();
    for thread in waiters {
        wait::wake(thread);
    }
}

/// Uma espera do ALPC: numa thread de kernel, a saída das prontas até
/// [`notify_waiters`], o prazo ou um alerta (`ke::wait`); fora dela, a
/// espera sondada do `context_switch`.
pub fn wait_transport(poll: &mut dyn FnMut() -> Option<u32>, deadline: wait::Deadline, mode: u8, alertable: bool) -> u32 {
    let Some(thread) = context_switch::on_kernel_thread_stack().filter(|_| context_switch::kernel_thread_can_block()) else {
        return context_switch::wait_until(poll, dispatcher::pump_kernel);
    };
    WAITERS.lock().insert(thread);
    let status = wait::wait_woken(poll, None, deadline, mode, alertable, wait::reason::WR_LPC_RECEIVE);
    WAITERS.lock().remove(&thread);
    status
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

/// Conduz a operação retomável até concluir; o cancelamento final é inócuo
/// depois da conclusão (e desfaz a que a espera deixou pela metade). Fora de
/// uma thread de kernel, a espera é a do `context_switch::wait_until`: uma
/// thread de usuário num serviço (o win32k chamando o msrpc.sys, que manda o
/// pedido síncrono a um servidor RPC de modo usuário) bloqueia e deixa o
/// servidor rodar, em vez de girar o pump do kernel.
pub fn drive(mut operation: Box<dyn Pending>) -> u32 {
    let (deadline, mode, alertable) = operation.wait_parameters();
    let status = wait_transport(&mut || operation.poll(), deadline, mode, alertable);
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
