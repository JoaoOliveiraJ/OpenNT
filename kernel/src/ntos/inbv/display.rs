//! Posse do vídeo de boot (o Inbv do NT) sobre o driver de vídeo de texto do
//! OpenNT.
//!
//! No ntoskrnl 19041 as rotinas Inbv* despacham por uma tabela escolhida no
//! boot: a da BGFX (Bgk*, vídeo gráfico do firmware) ou a do driver de vídeo
//! de boot legado (Bvga*, o bootvid). O OpenNT sobe em modo texto VGA pelo
//! BIOS, sem BGFX: vale a tabela Bvga, e o "driver de boot" é o
//! `drivers/video/vga` que o console usa. O estado é o BvgaDisplayState
//! (INBV_DISPLAY_STATE): 0 = do kernel, 1 = desligado, 2 = perdido para o
//! driver de vídeo.
//!
//! - InbvNotifyDisplayOwnershipChange(Owned, Context) = o
//!   BvgaNotifyDisplayOwnershipChange: reaver a posse (Owned) com o estado
//!   diferente de 0 chama o BvgaAcquireDisplayOwnership (o
//!   ResetDisplayParameters guardado roda com 80 colunas e 50 linhas quando o
//!   estado era "perdido"; o estado volta a 0); ceder a posse com o estado
//!   diferente de 2 chama o BvgaNotifyDisplayOwnershipLost(NULL) (o VidCleanUp
//!   solta o vídeo, o estado vira 2 e a rotina de reset guardada vira NULL).
//!   A parte da BGFX não existe sem BGFX. Devolve STATUS_SUCCESS.
//! - InbvSetVirtualFrameBuffer = o BvgaSetVirtualFrameBuffer:
//!   STATUS_NOT_IMPLEMENTED (só a BGFX tem framebuffer virtual).
//!
//! Com o vídeo perdido, o console deixa de escrever na memória de texto (o
//! hardware é do driver de vídeo) e continua no espelho serial.

use crate::drivers::video::vga;
use crate::hal::amd64::native_call;
use crate::rtl::SpinLock;

/// INBV_DISPLAY_STATE.
pub const DISPLAY_STATE_OWNED: u32 = 0;
pub const DISPLAY_STATE_DISABLED: u32 = 1;
pub const DISPLAY_STATE_LOST: u32 = 2;

const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

struct Display {
    /// BvgaDisplayState.
    state: u32,
    /// BvgaResetDisplayParameters (INBV_RESET_DISPLAY_PARAMETERS).
    reset_display_parameters: u64,
}

static DISPLAY: SpinLock<Display> = SpinLock::new(Display { state: DISPLAY_STATE_OWNED, reset_display_parameters: 0 });

/// BvgaGetDisplayState.
pub fn display_state() -> u32 {
    DISPLAY.lock().state
}

/// BvgaAcquireDisplayOwnership.
fn acquire_display_ownership() {
    let reset = {
        let display = DISPLAY.lock();
        if display.state == DISPLAY_STATE_LOST { display.reset_display_parameters } else { 0 }
    };
    if reset != 0 {
        // BOOLEAN ResetDisplayParameters(ULONG Cols, ULONG Rows).
        native_call::call(reset, &[80, 50]);
    }
    vga::set_owned(true);
    DISPLAY.lock().state = DISPLAY_STATE_OWNED;
}

/// BvgaNotifyDisplayOwnershipLost(ResetDisplayParameters).
fn notify_display_ownership_lost(reset_display_parameters: u64) {
    let mut display = DISPLAY.lock();
    if display.state != DISPLAY_STATE_LOST {
        // VidCleanUp: o driver de boot solta o hardware.
        vga::set_owned(false);
    }
    display.state = DISPLAY_STATE_LOST;
    display.reset_display_parameters = reset_display_parameters;
}

/// InbvNotifyDisplayOwnershipChange(Owned, Context).
pub fn notify_display_ownership_change(owned: bool, _context: u64) -> u32 {
    let state = display_state();
    if owned {
        if state != DISPLAY_STATE_OWNED {
            acquire_display_ownership();
        }
    } else if state != DISPLAY_STATE_LOST {
        notify_display_ownership_lost(0);
    }
    0
}

/// InbvSetVirtualFrameBuffer(FrameBuffer, Context).
pub fn set_virtual_frame_buffer(_frame_buffer: u64, _context: u64) -> u32 {
    STATUS_NOT_IMPLEMENTED
}
