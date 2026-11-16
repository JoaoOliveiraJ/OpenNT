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
//! - InbvCheckDisplayOwnership = o BvgaCheckDisplayOwnership (o vídeo não
//!   foi perdido) e InbvEnableBootDriver = o BvgaEnableBootDriver (liga ou
//!   desliga o desenho do kernel sem ceder o vídeo).
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

/// BvgaAcquireDisplayOwnership (o InbvAcquireDisplayOwnership do
/// KiDisplayBlueScreen).
pub fn acquire_display_ownership() {
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

/// InbvCheckDisplayOwnership = o BvgaCheckDisplayOwnership: TRUE enquanto
/// o vídeo não foi perdido para o driver de vídeo (estado diferente de 2).
pub fn check_display_ownership() -> bool {
    display_state() != DISPLAY_STATE_LOST
}

/// VidCleanUp do driver de boot: devolve a Bit Mask do Graphics Controller
/// (índice 8 em 0x3CE) a 0xFF.
fn video_clean_up() {
    crate::hal::port::write8(0x3CE, 8);
    crate::hal::port::write8(0x3CF, 0xFF);
}

/// InbvEnableBootDriver(Enable) = o BvgaEnableBootDriver. O driver de boot
/// do OpenNT (o vídeo de texto do console) está inicializado desde o boot,
/// então vale o caminho do BvgaBootDriverFullyInitialized: com o vídeo
/// perdido nada muda; senão, sob a trava do driver de boot, o estado "do
/// kernel" passa pelo VidCleanUp e o estado vira 0 (Enable) ou 1
/// (desligado). O console só escreve na memória de texto no estado 0.
pub fn enable_boot_driver(enable: bool) {
    let mut display = DISPLAY.lock();
    if display.state >= DISPLAY_STATE_LOST {
        return;
    }
    if display.state == DISPLAY_STATE_OWNED {
        video_clean_up();
    }
    display.state = if enable { DISPLAY_STATE_OWNED } else { DISPLAY_STATE_DISABLED };
    vga::set_owned(display.state == DISPLAY_STATE_OWNED);
}

/// InbvSetVirtualFrameBuffer(FrameBuffer, Context).
pub fn set_virtual_frame_buffer(_frame_buffer: u64, _context: u64) -> u32 {
    STATUS_NOT_IMPLEMENTED
}

/// Colunas e linhas da tela de texto do vídeo de boot.
pub fn text_size() -> (usize, usize) {
    (vga::COLUMNS, vga::ROWS)
}

/// InbvSolidColorFill da tela inteira no modo texto: espaços com o
/// atributo (fundo nos 4 bits altos, texto nos baixos).
pub fn solid_color_fill(attribute: u8) {
    if display_state() == DISPLAY_STATE_OWNED {
        vga::fill_screen(attribute);
    }
}

/// InbvDisplayString numa posição: bytes da página de código 437 a partir
/// de (coluna, linha), cortados na borda direita.
pub fn display_string_at(column: usize, row: usize, text: &[u8], attribute: u8) {
    if display_state() != DISPLAY_STATE_OWNED {
        return;
    }
    for (offset, &byte) in text.iter().enumerate() {
        vga::put_cell(column + offset, row, byte, attribute);
    }
}
