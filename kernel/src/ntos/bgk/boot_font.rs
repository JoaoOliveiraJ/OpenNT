//! A fonte do vídeo de boot e o desenho de texto no framebuffer.
//!
//! A biblioteca gráfica de boot do Windows desenha a tela de bugcheck com
//! uma fonte TrueType que o carregador entrega ao kernel. O OpenNT não usa
//! as fontes da Microsoft: a fonte é a de 8x16 pixels do BIOS de vídeo
//! (INT 10h, AX=1130h, BH=06h devolve em ES:BP a tabela de 256 glifos da
//! página de código 437), copiada quando o carregador liga o modo gráfico.
//! Cada caractere ocupa uma célula da altura de linha pedida, com a largura
//! de 2/5 dessa altura; o glifo é ampliado por interpolação bilinear do
//! bitmap e a borda é suavizada contra o fundo (a cobertura em torno de
//! meio pixel do bitmap vira a mistura das cores), o que mantém as curvas
//! legíveis também nos 200 pixels do ":(".
//!
//! Os caracteres fora da página 437 que os textos em português usam (ã, õ)
//! são compostos: a letra base com o til do glifo `~` sobre ela. As
//! maiúsculas acentuadas sem glifo próprio caem na letra base.

use core::sync::atomic::{AtomicBool, Ordering};

use super::graphics_information::BootFrameBuffer;
use crate::hal::{physical, x86bios};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_hal::X86BiosRegisters;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

const GLYPH_ROWS: usize = 16;
const GLYPH_COLUMNS: u32 = 8;

static FONT: SpinLock<[u8; 256 * GLYPH_ROWS]> = SpinLock::new([0; 256 * GLYPH_ROWS]);
static LOADED: AtomicBool = AtomicBool::new(false);

/// Lê `length` bytes da memória do BIOS emulado.
fn read_bios(segment: u16, offset: u16, length: usize) -> Option<alloc::vec::Vec<u8>> {
    let buffer = guest::alloc_bytes(length as u64);
    if buffer == 0 {
        return None;
    }
    let status = x86bios::read_memory(segment, offset, buffer, length as u32);
    let bytes = guest::read_bytes(buffer, length);
    guest::free_bytes(buffer);
    (status == 0).then_some(bytes)
}

/// Copia a fonte de 8x16 do BIOS de vídeo (INT 10h, AX=1130h, BH=06h).
/// O x86BiosCall devolve só os registradores gerais (o BP com o
/// deslocamento da tabela); o segmento é o do próprio BIOS de vídeo, o do
/// vetor do INT 10h, onde o BIOS guarda as tabelas de fonte. A tabela é
/// conferida pelos glifos de forma conhecida da página 437: o espaço vazio
/// e o bloco cheio (0xDB) com as 16 linhas acesas.
pub fn load_firmware_font() -> bool {
    let block = guest::alloc_bytes(X86BiosRegisters::SIZE);
    if block == 0 {
        return false;
    }
    // SAFETY: bloco zerado do tamanho de X86_BIOS_REGISTERS.
    let registers = unsafe { X86BiosRegisters::at(block) };
    registers.eax.set(0x1130);
    registers.ebx.set(0x0600);
    let ok = x86bios::call(0x10, registers);
    let offset = registers.ebp.get() as u16;
    guest::free_bytes(block);
    let Some(vector) = read_bios(0, 0x10 * 4, 4) else { return false };
    let segment = u16::from_le_bytes([vector[2], vector[3]]);
    if !ok || segment == 0 {
        return false;
    }
    let Some(bytes) = read_bios(segment, offset, 256 * GLYPH_ROWS) else { return false };
    let rows = |code: usize| &bytes[code * GLYPH_ROWS..(code + 1) * GLYPH_ROWS];
    if !rows(b' ' as usize).iter().all(|&row| row == 0) || !rows(0xDB).iter().all(|&row| row == 0xFF) {
        return false;
    }
    FONT.lock().copy_from_slice(&bytes);
    LOADED.store(true, Ordering::Release);
    true
}

pub fn loaded() -> bool {
    LOADED.load(Ordering::Acquire)
}

/// O caractere na página de código 437 e se leva o til composto por cima.
pub fn code_page_437(character: char) -> (u8, bool) {
    let plain = |byte: u8| (byte, false);
    match character {
        ' '..='~' => plain(character as u8),
        'Ç' => plain(0x80),
        'ü' => plain(0x81),
        'é' => plain(0x82),
        'â' => plain(0x83),
        'ä' => plain(0x84),
        'à' => plain(0x85),
        'å' => plain(0x86),
        'ç' => plain(0x87),
        'ê' => plain(0x88),
        'ë' => plain(0x89),
        'è' => plain(0x8A),
        'ï' => plain(0x8B),
        'î' => plain(0x8C),
        'ì' => plain(0x8D),
        'Ä' => plain(0x8E),
        'Å' => plain(0x8F),
        'É' => plain(0x90),
        'ô' => plain(0x93),
        'ö' => plain(0x94),
        'ò' => plain(0x95),
        'û' => plain(0x96),
        'ù' => plain(0x97),
        'Ö' => plain(0x99),
        'Ü' => plain(0x9A),
        'á' => plain(0xA0),
        'í' => plain(0xA1),
        'ó' => plain(0xA2),
        'ú' => plain(0xA3),
        'ñ' => plain(0xA4),
        'Ñ' => plain(0xA5),
        'ª' => plain(0xA6),
        'º' => plain(0xA7),
        '¿' => plain(0xA8),
        '¡' => plain(0xAD),
        '«' => plain(0xAE),
        '»' => plain(0xAF),
        '°' => plain(0xF8),
        'ã' => (b'a', true),
        'õ' => (b'o', true),
        'Á' | 'À' | 'Â' | 'Ã' => plain(b'A'),
        'Ê' | 'È' | 'Ë' => plain(b'E'),
        'Í' | 'Ì' | 'Î' | 'Ï' => plain(b'I'),
        'Ó' | 'Ò' | 'Ô' | 'Õ' => plain(b'O'),
        'Ú' | 'Ù' | 'Û' => plain(b'U'),
        '\u{2018}' | '\u{2019}' => plain(b'\''),
        '\u{201C}' | '\u{201D}' => plain(b'"'),
        '\u{2013}' | '\u{2014}' => plain(b'-'),
        '\u{00A0}' => plain(b' '),
        _ => plain(b'?'),
    }
}

/// O bitmap de 16 linhas do caractere (com o til composto).
fn glyph(font: &[u8; 256 * GLYPH_ROWS], character: char) -> [u8; GLYPH_ROWS] {
    let (code, tilde) = code_page_437(character);
    let mut rows = [0u8; GLYPH_ROWS];
    rows.copy_from_slice(&font[code as usize * GLYPH_ROWS..(code as usize + 1) * GLYPH_ROWS]);
    if tilde {
        // O til do glifo `~` fica nas linhas de cima, livres na minúscula.
        let accent = &font[b'~' as usize * GLYPH_ROWS..(b'~' as usize + 1) * GLYPH_ROWS];
        for (row, &bits) in rows.iter_mut().zip(accent).take(5) {
            *row |= bits;
        }
    }
    rows
}

/// Largura da célula de um caractere para a altura de linha `height`.
pub fn advance(height: u32) -> u32 {
    (height * 2 / 5).max(1)
}

/// Mistura canal a canal (`alpha` em 0..=256).
fn blend(background: u32, foreground: u32, alpha: i32) -> u32 {
    let mut color = 0;
    for shift in [0, 8, 16] {
        let low = ((background >> shift) & 0xFF) as i32;
        let high = ((foreground >> shift) & 0xFF) as i32;
        color |= ((low + (high - low) * alpha / 256) as u32 & 0xFF) << shift;
    }
    color
}

/// Pinta o retângulo com a cor (recortado na tela).
pub fn fill(screen: &BootFrameBuffer, x: u32, y: u32, width: u32, height: u32, color: u32) {
    let right = (x + width).min(screen.width);
    let bottom = (y + height).min(screen.height);
    for row in y..bottom {
        let line = screen.frame_buffer + row as u64 * screen.pixel_stride as u64 * 4;
        for column in x..right {
            physical::write32(line + column as u64 * 4, color);
        }
    }
}

/// Desenha o caractere na célula de canto (x, y) com a altura de linha
/// `height`; devolve a largura avançada. A célula inteira é pintada (o
/// fundo também), então o texto novo cobre o antigo.
pub fn draw_character(screen: &BootFrameBuffer, character: char, x: u32, y: u32, height: u32, foreground: u32, background: u32) -> u32 {
    let width = advance(height);
    if !loaded() {
        fill(screen, x, y, width, height, background);
        return width;
    }
    let rows = glyph(&FONT.lock(), character);
    let bit = |column: i32, row: i32| -> i32 {
        if column < 0 || row < 0 || column >= GLYPH_COLUMNS as i32 || row >= GLYPH_ROWS as i32 {
            return 0;
        }
        if rows[row as usize] & (0x80 >> column) != 0 { 256 } else { 0 }
    };
    // O ganho da borda acompanha a ampliação: a transição do bitmap ocupa
    // cerca de um pixel da tela.
    let gain = (height as i32 * 16).max(512);
    for dy in 0..height {
        if y + dy >= screen.height {
            break;
        }
        // Centro do pixel no espaço do bitmap, em 1/256 de pixel.
        let source_y = ((2 * dy + 1) as i32 * GLYPH_ROWS as i32 * 256) / (2 * height) as i32 - 128;
        let (row, fraction_y) = (source_y.div_euclid(256), source_y.rem_euclid(256));
        let line = screen.frame_buffer + (y + dy) as u64 * screen.pixel_stride as u64 * 4;
        for dx in 0..width {
            if x + dx >= screen.width {
                break;
            }
            let source_x = ((2 * dx + 1) as i32 * GLYPH_COLUMNS as i32 * 256) / (2 * width) as i32 - 128;
            let (column, fraction_x) = (source_x.div_euclid(256), source_x.rem_euclid(256));
            let top = bit(column, row) * (256 - fraction_x) + bit(column + 1, row) * fraction_x;
            let bottom = bit(column, row + 1) * (256 - fraction_x) + bit(column + 1, row + 1) * fraction_x;
            let coverage = (top * (256 - fraction_y) + bottom * fraction_y) >> 16;
            let alpha = ((coverage - 128) * gain / 256 + 128).clamp(0, 256);
            physical::write32(line + (x + dx) as u64 * 4, blend(background, foreground, alpha));
        }
    }
    width
}
