//! O serviço de depuração (`int 0x2D`) vindo do modo usuário, com a lógica
//! do ntoskrnl 19041.
//!
//! O DebugPrint da ntdll faz `int 0x2D` seguido de `int3` com o serviço no
//! RAX: 1 é BREAKPOINT_PRINT (RCX = texto, DX = tamanho, R8 = componente,
//! R9 = nível), 2 o prompt, 3 e 4 os símbolos, 5 a linha de comando. A
//! ntdll só usa esse caminho com um host anexado (bits 0 e 1 do
//! KUSER_SHARED_DATA.KdDebuggerEnabled) ou antes da FastPebLock existir;
//! senão ela levanta DBG_PRINTEXCEPTION_C e trata no próprio processo.
//!
//! No NT o portão 0x2D da IDT tem DPL 3 (KiDebugServiceTrap). O trap avança
//! o RIP para depois do `int3` e despacha STATUS_BREAKPOINT com esse
//! endereço e o serviço em ExceptionInformation[0]; o KiDispatchException
//! recua o RIP do CONTEXT para o `int3` e, como o KdIsThisAKdTrap reconhece
//! o serviço, chama o KdTrap antes de qualquer entrega ao processo:
//!
//! - sem depurador (KdpStub): os serviços 1, 3, 4 e 5 só pulam o `int3`
//!   (RIP + 1) e a exceção fica tratada; os outros seguem para o processo;
//! - com o depurador (KdpTrap): o serviço 1 é o KdpPrint e o RAX recebe o
//!   status dele; 3, 4 e 5 ficam tratados; o RIP pula o `int3` se ninguém o
//!   mudou, também num serviço acima de 5, que segue não tratado.
//!
//! KdpPrint (0x9b96c8): o filtro de `debug_filter` decide; filtrado, a
//! exceção fica tratada com STATUS_SUCCESS e nada sai. O texto vai até 512
//! bytes e a faixa tem de estar abaixo de MmUserProbeAddress; uma falha na
//! cópia devolve STATUS_ACCESS_VIOLATION sem tratar a exceção. O texto
//! entra no anel do DbgPrint e vai ao host (`print_log`); sem host,
//! STATUS_DEVICE_NOT_CONNECTED. O transporte do OpenNT não atende o prompt
//! (serviço 2) nem os avisos de símbolos: o prompt segue como no KdpStub.

use super::{debug_filter, debugger, print_log, stop};
use crate::ntos::inc::types::Context;
use crate::ntos::mm::guest_memory as guest;

/// Serviços do `int 0x2D`.
const BREAKPOINT_PRINT: u64 = 1;
const BREAKPOINT_PROMPT: u64 = 2;
const BREAKPOINT_COMMAND_STRING: u64 = 5;
/// Maior texto que o KdpPrint copia.
const PRINT_LIMIT: u64 = 0x200;
/// MmUserProbeAddress.
const USER_PROBE_ADDRESS: u64 = 0x7FFF_FFFF_0000;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_DEVICE_NOT_CONNECTED: u32 = 0xC000_009D;

/// O KdTrap de um serviço de depuração de modo usuário. `context` é o
/// CONTEXT da thread com o RIP já no `int3` (o recuo do KiDispatchException)
/// e o serviço no RAX. Devolve se a exceção ficou tratada; tratada, a thread
/// continua do CONTEXT, que o serviço pode ter mudado (RIP e RAX).
pub fn user_trap(context: &Context) -> bool {
    service_trap(context, stop::active())
}

/// O KdTrap do serviço com a rotina escolhida: o KdpTrap com o depurador
/// ligado (`debugger`), senão o KdpStub.
pub fn service_trap(context: &Context, debugger: bool) -> bool {
    let service = context.rax.get();
    let breakpoint = context.rip.get();
    if !debugger {
        // KdpStub.
        let handled = service == BREAKPOINT_PRINT || (3..=BREAKPOINT_COMMAND_STRING).contains(&service);
        if handled {
            context.rip.set(breakpoint + 1);
        }
        return handled;
    }
    // KdpTrap.
    let handled = match service {
        BREAKPOINT_PRINT => {
            let (status, handled) = print(context.r8.get() as u32, context.r9.get() as u32, context.rcx.get(), context.rdx.get() as u16);
            context.rax.set(status as i32 as i64 as u64);
            handled
        }
        BREAKPOINT_PROMPT => return false,
        3..=BREAKPOINT_COMMAND_STRING => true,
        _ => false,
    };
    if context.rip.get() == breakpoint {
        context.rip.set(breakpoint + 1);
    }
    handled
}

/// KdpPrint de modo usuário: (status, exceção tratada).
fn print(component: u32, level: u32, message: u64, length: u16) -> (u32, bool) {
    if !debug_filter::print_enabled(component, level) {
        return (0, true);
    }
    let length = (length as u64).min(PRINT_LIMIT);
    let bytes = if length == 0 {
        alloc::vec::Vec::new()
    } else {
        let end = message.checked_add(length);
        match end.filter(|&end| end <= USER_PROBE_ADDRESS).and_then(|_| guest::try_read_bytes(message, length as usize).ok()) {
            Some(bytes) => bytes,
            None => return (STATUS_ACCESS_VIOLATION, false),
        }
    };
    let text = alloc::string::String::from_utf8_lossy(&bytes);
    let line = text.strip_suffix('\n').map(|rest| rest.strip_suffix('\r').unwrap_or(rest)).unwrap_or(&text);
    debug_print!("[usermode] DbgPrint: {}", line);
    print_log::output(line);
    if debugger::debugger_not_present() {
        return (STATUS_DEVICE_NOT_CONNECTED, true);
    }
    (0, true)
}
