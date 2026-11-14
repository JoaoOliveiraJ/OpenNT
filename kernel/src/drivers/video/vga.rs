//! Driver VGA modo texto 80x25.
//!
//! Escreve direto na memória de vídeo 0xB8000 e move o cursor de hardware
//! pelas portas 0x3D4/0x3D5. É o driver de vídeo de boot do Inbv
//! (`ntos/inbv/display`): quando o vídeo passa a um driver de vídeo, a posse
//! sai daqui e as escritas param de tocar o hardware até a posse voltar.

use crate::hal::{physical, port};
use crate::rtl::SpinLock;

const MEMORY: u64 = 0xB8000;
const WIDTH: usize = 80;
const HEIGHT: usize = 25;

struct Screen {
    cx: usize,
    cy: usize,
    attribute: u8, // cinza claro / preto
    /// O vídeo de texto é do kernel (o VidCleanUp do Inbv o solta).
    owned: bool,
}

static SCREEN: SpinLock<Screen> = SpinLock::new(Screen { cx: 0, cy: 0, attribute: 0x07, owned: true });

fn cell(x: usize, y: usize) -> u64 {
    MEMORY + ((y * WIDTH + x) * 2) as u64
}

impl Screen {
    fn hardware_cursor(&self) {
        let position = self.cy * WIDTH + self.cx;
        port::write8(0x3D4, 0x0F);
        port::write8(0x3D5, (position & 0xFF) as u8);
        port::write8(0x3D4, 0x0E);
        port::write8(0x3D5, ((position >> 8) & 0xFF) as u8);
    }

    fn blank(&self) -> u16 {
        (self.attribute as u16) << 8 | 0x20
    }

    fn clear_line(&self, y: usize) {
        for x in 0..WIDTH {
            physical::write16(cell(x, y), self.blank());
        }
    }

    fn scroll(&mut self) {
        for y in 1..HEIGHT {
            for x in 0..WIDTH {
                physical::write16(cell(x, y - 1), physical::read16(cell(x, y)));
            }
        }
        self.clear_line(HEIGHT - 1);
        self.cy = HEIGHT - 1;
    }

    fn putc(&mut self, character: char) {
        match character {
            '\n' => {
                self.cx = 0;
                self.cy += 1;
            }
            '\r' => self.cx = 0,
            '\u{8}' => {
                if self.cx > 0 {
                    self.cx -= 1;
                    physical::write16(cell(self.cx, self.cy), self.blank());
                }
            }
            '\t' => {
                self.cx = (self.cx + 8) & !7;
                if self.cx >= WIDTH {
                    self.cx = 0;
                    self.cy += 1;
                }
            }
            _ => {
                // A memória de texto guarda um byte por célula (code page 437);
                // só o byte baixo do código é escrito.
                let byte = (character as u32 & 0xFF) as u16;
                physical::write16(cell(self.cx, self.cy), (self.attribute as u16) << 8 | byte);
                self.cx += 1;
                if self.cx >= WIDTH {
                    self.cx = 0;
                    self.cy += 1;
                }
            }
        }
        if self.cy >= HEIGHT {
            self.scroll();
        }
    }
}

pub fn write(text: &str) {
    let mut screen = SCREEN.lock();
    if !screen.owned {
        return;
    }
    for character in text.chars() {
        screen.putc(character);
    }
    screen.hardware_cursor();
}

pub fn putc(character: char) {
    let mut screen = SCREEN.lock();
    if screen.owned {
        screen.putc(character);
    }
}

pub fn clear() {
    let mut screen = SCREEN.lock();
    if !screen.owned {
        return;
    }
    for y in 0..HEIGHT {
        screen.clear_line(y);
    }
    screen.cx = 0;
    screen.cy = 0;
    screen.hardware_cursor();
}

pub fn set_attribute(attribute: u8) {
    SCREEN.lock().attribute = attribute;
}

/// Posse do vídeo de texto: `false` quando um driver de vídeo assume o
/// hardware (o VidCleanUp do Inbv), `true` quando ela volta ao kernel.
pub fn set_owned(owned: bool) {
    SCREEN.lock().owned = owned;
}

pub fn owned() -> bool {
    SCREEN.lock().owned
}
