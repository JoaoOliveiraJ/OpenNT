//! Framebuffer linear via Bochs DISPI (a placa de `-vga std` do QEMU).
//!
//! O OpenNT faz o mode-set de dentro do modo longo, sem BIOS (`int 10h`): o
//! DISPI/BGA é programável por duas portas de 16 bits. A base linear vem do
//! BAR0 da função PCI `1234:1111` que `drivers/bus/pci.rs` já enumera na fase
//! 1; ela cai no buraco PCI de 32 bits, abaixo de 4 GB, dentro do mapa de
//! identidade do boot, então `hal::physical` escreve direto na VRAM.
//!
//! Este é o Stage 1 do caminho gráfico: um framebuffer que o kernel desenha.
//! Os estágios seguintes (present de modo usuário, compositor) desenham sobre
//! ele. Fica atrás do flag `--graphics`; o boot normal segue em modo texto.

use crate::drivers::bus::pci;
use crate::hal::{physical, port};

/// Porta de índice e de dado do DISPI (`VBE_DISPI_IOPORT_INDEX`/`_DATA`).
const DISPI_INDEX: u16 = 0x01CE;
const DISPI_DATA: u16 = 0x01CF;

// Índices de registrador do DISPI.
const REG_ID: u16 = 0;
const REG_XRES: u16 = 1;
const REG_YRES: u16 = 2;
const REG_BPP: u16 = 3;
const REG_ENABLE: u16 = 4;
const REG_VIRT_WIDTH: u16 = 6;
const REG_VIRT_HEIGHT: u16 = 7;
const REG_X_OFFSET: u16 = 8;
const REG_Y_OFFSET: u16 = 9;

// Bits do registrador ENABLE.
const ENABLE_DISABLED: u16 = 0x00;
const ENABLE_ENABLED: u16 = 0x01;
const ENABLE_LFB: u16 = 0x40;

fn write_register(index: u16, value: u16) {
    port::write16(DISPI_INDEX, index);
    port::write16(DISPI_DATA, value);
}

fn read_register(index: u16) -> u16 {
    port::write16(DISPI_INDEX, index);
    port::read16(DISPI_DATA)
}

/// Um framebuffer linear já configurado: base física, dimensões e passo em
/// bytes. Pixels são `0x00RRGGBB` (XRGB8888) em little-endian.
pub struct Framebuffer {
    pub base: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
}

impl Framebuffer {
    /// Escreve um pixel, ignorando coordenadas fora da tela.
    pub fn put_pixel(&self, x: u32, y: u32, color: u32) {
        if x < self.width && y < self.height {
            physical::write32(self.base + y as u64 * self.stride as u64 + x as u64 * 4, color);
        }
    }

    /// Preenche o retângulo `[x0,x1) x [y0,y1)`, recortado à tela.
    pub fn fill_rect(&self, x0: u32, y0: u32, x1: u32, y1: u32, color: u32) {
        for y in y0..y1.min(self.height) {
            for x in x0..x1.min(self.width) {
                self.put_pixel(x, y, color);
            }
        }
    }

    /// Pinta a tela inteira de uma cor.
    pub fn clear(&self, color: u32) {
        self.fill_rect(0, 0, self.width, self.height, color);
    }
}

/// Faz o mode-set `width`x`height`x32 via DISPI e devolve o framebuffer, ou
/// `None` quando a placa std-VGA/Bochs não está presente (outro `-vga`): aí o
/// chamador mantém o modo texto.
pub fn init(width: u32, height: u32) -> Option<Framebuffer> {
    // O ID do DISPI (índice 0) é 0xB0C0..0xB0C5 no QEMU; ausência => sem BGA.
    let id = read_register(REG_ID);
    if !(0xB0C0..=0xB0CF).contains(&id) {
        return None;
    }
    let device = pci::find_by_id(0x1234, 0x1111)?;
    let bar0 = device.bars.iter().find(|bar| bar.index == 0)?;
    let base = (bar0.value & 0xFFFF_FFF0) as u64;
    if base == 0 {
        return None;
    }
    // Reprograma com o LFB desligado e religa com o framebuffer linear ativo.
    write_register(REG_ENABLE, ENABLE_DISABLED);
    write_register(REG_XRES, width as u16);
    write_register(REG_YRES, height as u16);
    write_register(REG_BPP, 32);
    write_register(REG_VIRT_WIDTH, width as u16);
    write_register(REG_VIRT_HEIGHT, height as u16);
    write_register(REG_X_OFFSET, 0);
    write_register(REG_Y_OFFSET, 0);
    write_register(REG_ENABLE, ENABLE_ENABLED | ENABLE_LFB);
    Some(Framebuffer { base, width, height, stride: width * 4 })
}

/// Stage 1 (sob `--graphics`): mode-set 640x480x32, tela azul com um retângulo
/// branco, confirma a leitura de volta do LFB e imprime `FRAMEBUFFER_OK`.
pub fn selftest() {
    let Some(framebuffer) = init(640, 480) else {
        crate::debug_print!("[video] DISPI/std-VGA ausente; mantendo modo texto");
        return;
    };
    const BLUE: u32 = 0x0000_00FF;
    const WHITE: u32 = 0x00FF_FFFF;
    framebuffer.clear(BLUE);
    framebuffer.fill_rect(160, 120, 480, 360, WHITE);
    // (0,0) está fora do retângulo: a leitura confirma que o LFB está vivo.
    let probe = physical::read32(framebuffer.base);
    if probe == BLUE {
        crate::debug_print!("FRAMEBUFFER_OK {}x{} base={:#x}", framebuffer.width, framebuffer.height, framebuffer.base);
    } else {
        crate::debug_print!("[video] framebuffer leu {:#010x} (esperado {:#010x})", probe, BLUE);
    }
}
