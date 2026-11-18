//! As portas de término de thread (ETHREAD.TerminationPort).
//!
//! NtRegisterThreadTerminatePort(PortHandle) referencia a porta (PORT_CONNECT,
//! LpcPortObjectType) e a põe na lista da thread corrente, como o 19041 (o
//! TERMINATION_PORT de ExAllocatePoolWithQuotaTag, sem memória
//! STATUS_INSUFFICIENT_RESOURCES). Quando a thread termina, o PspExitThread
//! manda a cada porta da lista, da última registrada para a primeira, a
//! mensagem LPC_CLIENT_DIED com o CreateTime da thread (o CLIENTDIED_MSG, um
//! datagrama do LpcRequestPort) e solta a referência. O csrss registra a
//! própria \Windows\ApiPort para as threads que cria (CsrCreateThread) e
//! trata o LPC_CLIENT_DIED na CsrApiRequestThread.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::ntos::alpc::port_reference;
use crate::ntos::alpc::server;
use crate::ntos::alpc::transport::Sender;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::Ethread;
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::ob::objects::port as port_objects;
use crate::ntos::ps::{previous_mode, process};
use crate::rtl::{KernelError, SpinLock};

/// PORT_CONNECT.
const PORT_CONNECT: u32 = 1;

/// As portas registradas por thread (ETHREAD), na ordem do registro; cada uma
/// retém o corpo da porta.
static PORTS: SpinLock<BTreeMap<u64, Vec<u64>>> = SpinLock::new(BTreeMap::new());

/// NtRegisterThreadTerminatePort(PortHandle). Devolve o NTSTATUS.
pub fn register(handle: u64) -> Result<u32, KernelError> {
    let mode = previous_mode::get().unwrap_or(1);
    let reference = match port_reference::reference(handle, PORT_CONNECT, mode)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    // A referência fica com a lista da thread até o término.
    let pointer = reference.port.pointer;
    PORTS.lock().entry(process::get_current_thread()).or_default().push(pointer);
    Ok(0)
}

/// O PspExitThread: LPC_CLIENT_DIED a cada porta registrada pela thread,
/// antes do callout de saída de thread do win32k (`ps::process::exit_thread`).
pub fn thread_exit(thread: u64) {
    let Some(ports) = PORTS.lock().remove(&thread) else { return };
    // SAFETY: a ETHREAD que termina, viva durante as rotinas de término.
    let object = unsafe { Ethread::at(thread) };
    let create_time = (object.create_time.high_part.get() as u32 as u64) << 32 | object.create_time.low_part.get() as u64;
    let sender = Sender { process: object.cid.unique_process.get(), thread: object.cid.unique_thread.get(), thread_pointer: thread };
    for pointer in ports.into_iter().rev() {
        if let Some(port) = port_objects::port_of(pointer) {
            server::post_client_died(&port, sender, create_time);
        }
        let _ = dispatcher_objects::dereference(pointer);
    }
}
