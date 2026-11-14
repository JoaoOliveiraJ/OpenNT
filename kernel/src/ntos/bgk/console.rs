//! Console do vídeo de boot (BgkDisplayCharacter, BgkGetConsoleState,
//! BgkSetCursor).
//!
//! Como no ntoskrnl 19041: a interface do console (a tabela que o
//! BgConsoleGetInterface devolve e o BgkInitialize guarda) tem
//! DisplayCharacter em +0x20, GetConsoleState em +0x28, GetCursorState em
//! +0x30 e SetCursor em +0x38. Cada export (BgkDisplayCharacter rva
//! 0x9f6340, BgkGetConsoleState 0x9f6410, BgkSetCursor 0x9f64f0) entra no
//! rundown do console (BgkpAcquireConsole), chama a função da interface e
//! sai (BgkpReleaseConsole); sem o rundown devolve STATUS_UNSUCCESSFUL. O
//! rundown nasce encerrado (o valor estático da imagem é 1) e só o
//! BgkpTryEnableConsole o reabre, quando há interface e o display pertence
//! ao Bgk.
//!
//! O OpenNT não tem a biblioteca gráfica de boot (o vídeo de boot é o modo
//! texto VGA do console do kernel): a interface nunca é publicada, o rundown
//! continua encerrado e os três exports devolvem STATUS_UNSUCCESSFUL, como o
//! NT sem console gráfico de boot.

use core::sync::atomic::{AtomicU64, Ordering::SeqCst};

use crate::hal::amd64::native_call;
use crate::ntos::ex::rundown;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;

/// Posições das funções na interface do console.
const DISPLAY_CHARACTER: u64 = 0x20;
const GET_CONSOLE_STATE: u64 = 0x28;
const SET_CURSOR: u64 = 0x38;

/// O EX_RUNDOWN_REF do console (BgkpConsoleRundown): encerrado (1) até o
/// console ser habilitado.
static CONSOLE_RUNDOWN: AtomicU64 = AtomicU64::new(1);
/// A interface do console (BgkpConsoleInterface); 0 sem biblioteca gráfica.
static CONSOLE_INTERFACE: AtomicU64 = AtomicU64::new(0);

fn rundown_pointer() -> u64 {
    CONSOLE_RUNDOWN.as_ptr() as u64
}

/// BgkpAcquireConsole + a função da interface + BgkpReleaseConsole.
fn call_console(slot: u64, arguments: &[u64]) -> Result<u32, KernelError> {
    if !rundown::acquire(rundown_pointer())? {
        return Ok(STATUS_UNSUCCESSFUL);
    }
    let routine = guest::read64(CONSOLE_INTERFACE.load(SeqCst) + slot);
    let status = native_call::call(routine, arguments) as u32;
    rundown::release(rundown_pointer())?;
    Ok(status)
}

/// O console de boot está habilitado (o rundown aberto).
pub fn enabled() -> bool {
    CONSOLE_RUNDOWN.load(SeqCst) & 1 == 0
}

/// BgkDisplayCharacter(Character, X, Y, Color, Flags?): os cinco
/// argumentos seguem para o DisplayCharacter da interface.
pub fn display_character(character: u16, x: u32, y: u32, color: u32, fifth: u32) -> Result<u32, KernelError> {
    call_console(DISPLAY_CHARACTER, &[character as u64, x as u64, y as u64, color as u64, fifth as u64])
}

/// BgkGetConsoleState(State*).
pub fn get_console_state(state: u64) -> Result<u32, KernelError> {
    call_console(GET_CONSOLE_STATE, &[state])
}

/// BgkSetCursor(X, Y, Visible?).
pub fn set_cursor(x: u32, y: u32, third: u32) -> Result<u32, KernelError> {
    call_console(SET_CURSOR, &[x as u64, y as u64, third as u64])
}
